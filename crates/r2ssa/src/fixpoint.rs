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
//! - the caller states the height of its lattice, and the budget is
//!   `blocks × (height + 1)` visits. A monotone transfer over a lattice of
//!   that height cannot exceed it, so exceeding it is a defect in the pass,
//!   reported as [`Exhausted`] with evidence, which the caller refuses on. No
//!   result is partial and silent.

use std::collections::{BTreeMap, BTreeSet};

use crate::SSAFunction;

/// A state that joins: `join` moves `self` up to cover `other` and says
/// whether it moved.
pub trait Join: Clone + PartialEq {
    fn join(&mut self, other: &Self) -> bool;
}

/// A pass that ran past the visits its stated height allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exhausted {
    pub pass: &'static str,
    pub budget: usize,
}

impl std::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} did not settle within {} block visits, which its stated lattice height allows",
            self.pass, self.budget
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
    let budget = order.len().saturating_mul(height.saturating_add(1)).max(1);
    let mut entry = BTreeMap::<u64, S>::new();
    let mut exit = BTreeMap::<u64, S>::new();
    let mut work = rank
        .get(&root)
        .copied()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut visits = 0usize;
    while let Some(index) = work.pop_first() {
        visits += 1;
        if visits > budget {
            r2il::refusal_evidence!("fixpoint", "{pass}: {budget} block visits were not enough");
            return Err(Exhausted { pass, budget });
        }
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
        entry.insert(block, state);
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
/// many times one cell can move.
pub fn sparse<K: Ord + Clone, L: Clone + PartialEq>(
    pass: &'static str,
    height: usize,
    order: &[K],
    readers: &BTreeMap<K, Vec<K>>,
    start: L,
    mut eval: impl FnMut(&K, &BTreeMap<K, L>) -> L,
) -> Result<BTreeMap<K, L>, Exhausted> {
    let rank = order
        .iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let budget = order.len().saturating_mul(height.saturating_add(1)).max(1);
    let mut cells = order
        .iter()
        .map(|key| (key.clone(), start.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut work = (0..order.len()).collect::<BTreeSet<_>>();
    let mut visits = 0usize;
    while let Some(index) = work.pop_first() {
        visits += 1;
        if visits > budget {
            r2il::refusal_evidence!("fixpoint", "{pass}: {budget} value visits were not enough");
            return Err(Exhausted { pass, budget });
        }
        let key = &order[index];
        let next = eval(key, &cells);
        if cells.get(key) == Some(&next) {
            continue;
        }
        cells.insert(key.clone(), next);
        work.extend(
            readers
                .get(key)
                .into_iter()
                .flatten()
                .filter_map(|reader| rank.get(reader).copied()),
        );
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // A height of one allows two visits per block.
        let budget = function.block_addrs().len() * 2;
        assert_eq!(
            solved,
            Err(Exhausted {
                pass: "runaway",
                budget
            })
        );
    }
}
