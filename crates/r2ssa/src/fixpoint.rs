//! One fixpoint driver for the passes that iterate (doc/adr-fixpoint.md).
//!
//! A forward dataflow over a function's blocks, with a state that says
//! whether a join moved it:
//!
//! - an unreached block is bottom: it has no state, and contributes nothing
//!   to the join at a merge. It never stands for "entry" or "unknown", which
//!   would be a value the program does not have on that path;
//! - work is the set of blocks whose input may have moved, taken in reverse
//!   postorder, so the order is deterministic and a round visits only what
//!   changed;
//! - the caller states the height of its lattice, and no state may move more
//!   times than that: a move past it is a transfer that is not monotone or a
//!   height that is wrong, reported as [`Exhausted`] with evidence, which the
//!   caller refuses on. No result is partial and silent. Work stays within
//!   `blocks + edges × (height + 1)`, or `values + edges × height` over values.

use std::collections::{BTreeMap, BTreeSet};

use crate::SSAFunction;
use crate::dense::{Csr, DenseId, IdMap};

/// A state that joins: `join` moves `self` up to cover `other` and says
/// whether it moved.
pub trait Join: Clone + PartialEq {
    fn join(&mut self, other: &Self) -> bool;
}

/// A pass that moved one state more times than its stated lattice height allows: a transfer that
/// is not monotone, or a height that is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exhausted {
    pub pass: &'static str,
    pub height: usize,
}

impl std::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} moved a state more than the {} times its stated lattice height allows",
            self.pass, self.height
        )
    }
}

/// The settled state at entry to and exit from each reached block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solution<S> {
    pub entry: BTreeMap<u64, S>,
    pub exit: BTreeMap<u64, S>,
}

/// Solve a forward dataflow over `function`'s blocks.
///
/// `initial` is the state control enters the function with; `transfer`
/// takes a block's entry state to its exit state, and must be monotone.
/// `height` bounds how many times any block's entry state can move.
pub fn forward<S: Join>(
    function: &SSAFunction,
    pass: &'static str,
    height: usize,
    initial: S,
    transfer: impl FnMut(u64, &S) -> S,
) -> Result<Solution<S>, Exhausted> {
    forward_on_edges(
        function,
        pass,
        height,
        initial,
        |state: &mut S, other: &S| {
            state.join(other);
        },
        |_, _, state: &S| state.clone(),
        transfer,
    )
}

/// The same, where an edge says something of its own -- the condition a
/// branch holds on it -- and the join needs the pass's context: `edge` takes
/// a predecessor's exit state to what it contributes along one edge, and
/// `join` folds one contribution into another.
pub fn forward_on_edges<S: Clone + PartialEq>(
    function: &SSAFunction,
    pass: &'static str,
    height: usize,
    initial: S,
    join: impl Fn(&mut S, &S),
    mut edge: impl FnMut(u64, u64, &S) -> S,
    mut transfer: impl FnMut(u64, &S) -> S,
) -> Result<Solution<S>, Exhausted> {
    let order = function.block_addrs();
    let rank = order
        .iter()
        .enumerate()
        .map(|(index, addr)| (*addr, index))
        .collect::<BTreeMap<_, _>>();
    let root = function.root();
    // Each entry moves at most `height` times past its first value, so a block is taken at most
    // once more per move of a predecessor's exit: `B + E · (height + 1)` visits, checked per move.
    let mut moves = vec![0usize; order.len()];
    let mut entry = BTreeMap::<u64, S>::new();
    let mut exit = BTreeMap::<u64, S>::new();
    let mut work = rank
        .get(&root)
        .copied()
        .into_iter()
        .collect::<BTreeSet<_>>();
    while let Some(index) = work.pop_first() {
        let block = order[index];
        // The join of what reached it; the function's own entry is reached
        // with the initial state as well as from any edge back to it.
        let mut state = (block == root).then(|| initial.clone());
        for pred in function.predecessors(block) {
            let Some(reached) = exit.get(&pred) else {
                continue;
            };
            let along = edge(pred, block, reached);
            match &mut state {
                Some(state) => join(state, &along),
                None => state = Some(along),
            }
        }
        let Some(state) = state else {
            continue;
        };
        let out = transfer(block, &state);
        if entry
            .insert(block, state.clone())
            .is_some_and(|held| held != state)
        {
            moves[index] += 1;
            if moves[index] > height {
                r2il::refusal_evidence!("fixpoint", "{pass}: block {block:#x} moved past {height}");
                return Err(Exhausted { pass, height });
            }
        }
        if exit.get(&block) == Some(&out) {
            continue;
        }
        exit.insert(block, out);
        work.extend(
            function
                .successors(block)
                .into_iter()
                .filter_map(|succ| rank.get(&succ).copied()),
        );
    }
    Ok(Solution { entry, exit })
}

/// Solve a sparse dataflow over values: each value's cell is computed from
/// the cells of the values it reads, and recomputed only when one of those
/// moves.
///
/// `order` lists every value in definition order, which is the order work
/// is taken in; `readers` names, for each value, the values computed from
/// it. Every cell starts at `start` -- the optimistic top of a descending
/// lattice -- and `eval` must only move a cell down. `height` bounds how
/// many times one cell can move. The cells are a dense map over the values
/// in `order`; a value outside it has no cell.
///
/// Work is a min-heap of definition ranks with a flag per rank, so a value
/// is queued at most once at a time and taken in definition order:
/// `O((V + E) · height · log V)` in all.
pub fn sparse<I: DenseId, L: Clone + PartialEq>(
    pass: &'static str,
    height: usize,
    order: &[I],
    readers: &Csr<I, I>,
    start: L,
    mut eval: impl FnMut(I, &IdMap<I, L>) -> L,
) -> Result<IdMap<I, L>, Exhausted> {
    let bound = order
        .iter()
        .map(|id| id.index() + 1)
        .max()
        .unwrap_or(0)
        .max(readers.len());
    let mut rank = IdMap::new(bound);
    let mut cells = IdMap::new(bound);
    for (index, id) in order.iter().enumerate() {
        rank.insert(*id, index);
        cells.insert(*id, start.clone());
    }
    // A cell moves at most `height` times, so a value is taken at most once more per move of a
    // value it reads: `V + E · height` visits, checked per move.
    let mut moves = vec![0usize; order.len()];
    let mut queued = vec![true; order.len()];
    let mut work = (0..order.len())
        .map(std::cmp::Reverse)
        .collect::<std::collections::BinaryHeap<_>>();
    while let Some(std::cmp::Reverse(index)) = work.pop() {
        queued[index] = false;
        let id = order[index];
        let next = eval(id, &cells);
        if cells.get(id) == Some(&next) {
            continue;
        }
        moves[index] += 1;
        if moves[index] > height {
            r2il::refusal_evidence!("fixpoint", "{pass}: a cell moved past {height}");
            return Err(Exhausted { pass, height });
        }
        cells.insert(id, next);
        for reader in readers.get(id) {
            if let Some(&at) = rank.get(*reader)
                && !std::mem::replace(&mut queued[at], true)
            {
                work.push(std::cmp::Reverse(at));
            }
        }
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cell read by three that each move twice is taken after each move: 16 visits, more than
    /// `V · (height + 1)` = 12. A visit budget refused this monotone pass; no cell moves past 2.
    #[test]
    fn a_merge_read_by_many_settles() {
        use crate::ValueId;
        let order = [ValueId(0), ValueId(1), ValueId(2), ValueId(3)];
        // 0 merges 1, 2 and 3; each of those reads itself, moving one step per visit up to 2.
        let pairs = (1..4).flat_map(|at| [(ValueId(at), ValueId(0)), (ValueId(at), ValueId(at))]);
        let readers = Csr::from_pairs(4, pairs);
        let mut visits = 0;
        let solved = sparse("fan-in", 2, &order, &readers, 0u8, |id, cells| {
            visits += 1;
            let at = |id: ValueId| cells.get(id).copied().unwrap_or(0);
            match id.0 {
                0 => (1..4).map(|from| at(ValueId(from))).max().unwrap_or(0),
                _ => (at(id) + 1).min(2),
            }
        })
        .expect("a monotone pass settles");
        assert!(
            visits > 12,
            "{visits} visits: the case the old budget refused"
        );
        assert_eq!(solved.get(ValueId(0)), Some(&2));
    }
    use r2il::{R2ILBlock, R2ILOp, Varnode};

    /// The set of block addresses a path has passed, joined by union.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Passed(BTreeSet<u64>);

    impl Join for Passed {
        fn join(&mut self, other: &Self) -> bool {
            let before = self.0.len();
            self.0.extend(other.0.iter().copied());
            self.0.len() != before
        }
    }

    /// `0x1000` loops on itself until it falls to `0x1004`.
    fn looping() -> SSAFunction {
        let mut head = R2ILBlock::new(0x1000, 4);
        head.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1000, 8),
            cond: Varnode::register(0x200, 1),
        });
        let mut tail = R2ILBlock::new(0x1004, 4);
        tail.push(R2ILOp::Return {
            target: Varnode::register(0x10, 8),
        });
        SSAFunction::from_blocks_raw(&[head, tail], None).expect("a function")
    }

    #[test]
    fn a_loop_settles_and_an_unreached_edge_adds_nothing() {
        let function = looping();
        let solved = forward(
            &function,
            "test",
            2,
            Passed(BTreeSet::new()),
            |block, state| {
                let mut out = state.clone();
                out.0.insert(block);
                out
            },
        )
        .expect("settles");
        // The head is entered from where control enters the function and
        // from itself, and the tail has passed the head but not itself.
        assert!(solved.entry[&0x1000].0.contains(&0x1000));
        assert!(solved.entry[&0x1004].0.contains(&0x1000));
        assert!(!solved.entry[&0x1004].0.contains(&0x1004));
    }

    /// A transfer that never settles is refused at its budget, not stopped
    /// quietly with whatever it had.
    #[test]
    fn a_pass_that_does_not_settle_is_refused() {
        let function = looping();
        let mut count = 0u64;
        let solved = forward(
            &function,
            "runaway",
            1,
            Passed(BTreeSet::new()),
            |_, state| {
                count += 1;
                let mut out = state.clone();
                out.0.insert(count);
                out
            },
        );
        // A height of one allows each entry one move past its first value.
        assert_eq!(
            solved,
            Err(Exhausted {
                pass: "runaway",
                height: 1
            })
        );
    }
}
