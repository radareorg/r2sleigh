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
use crate::dense::{Csr, DenseId, IdMap, IdSet, IdVec};

/// A state that joins: `join` moves `self` up to cover `other` and says
/// whether it moved.
pub trait Join: Clone + PartialEq {
    fn join(&mut self, other: &Self) -> bool;
}

/// A pass that moved one state more times than its stated lattice height allows: a transfer that
/// is not monotone, or a height that is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    // A transfer moves its exit only when its entry moved, so at most `height + 1` times.
    let mut exits = vec![0usize; order.len()];
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
        exits[index] += 1;
        if exits[index] > height + 1 {
            r2il::refusal_evidence!(
                "fixpoint",
                "{pass}: block {block:#x}'s exit moved past its entry"
            );
            return Err(Exhausted { pass, height });
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

/// Not placed by the order: a node the entry does not reach.
const UNPLACED: u32 = u32::MAX;

/// Bourdoncle's weak topological order of what an entry reaches: each strongly connected component
/// a nested run led by its head (doc/adr-fixpoint.md, "Weak topological order").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wto<I> {
    order: Vec<I>,
    position: IdVec<I, u32>,
    /// One past the last position of the component a head leads; else the node's next position.
    end: IdVec<I, u32>,
    head: IdSet<I>,
    visits: u64,
}

/// One step of building the order.
enum Build<I> {
    /// Order a node set, its search entering at `starts` first.
    Decompose {
        nodes: Vec<I>,
        starts: Vec<I>,
    },
    Place(I),
    /// Close the component a placed node leads.
    Close(I),
}

impl<I: DenseId> Wto<I> {
    /// The order of what `entry` reaches, numbered and searched by ascending `key` alone; one
    /// condensation per nesting level, `O(d · (V + E))` for depth `d`.
    pub fn of(successors: &Csr<I, I>, entry: I, key: impl Fn(I) -> u64) -> Self {
        use crate::dense::Node;
        let count = successors.len();
        let mut wto = Self {
            order: Vec::new(),
            position: IdVec::filled(count, UNPLACED),
            end: IdVec::filled(count, UNPLACED),
            head: IdSet::new(count),
            visits: 0,
        };
        let by_key = |nodes: &mut Vec<I>| nodes.sort_unstable_by_key(|node| (key(*node), *node));
        let mut reached = IdSet::new(count);
        reached.insert(entry);
        let mut pending = vec![entry];
        while let Some(node) = pending.pop() {
            for successor in successors.get(node) {
                wto.visits += 1;
                if reached.insert(*successor) {
                    pending.push(*successor);
                }
            }
        }
        let mut nodes = reached.iter().collect::<Vec<_>>();
        by_key(&mut nodes);
        // A decomposition places at least one node or removes a head from what it hands on,
        // so the tasks end.
        let mut tasks = vec![Build::Decompose {
            nodes,
            starts: vec![entry],
        }];
        let mut local = IdVec::filled(count, UNPLACED);
        while let Some(task) = tasks.pop() {
            let (nodes, starts) = match task {
                Build::Place(node) => {
                    wto.position[node] = wto.order.len() as u32;
                    wto.order.push(node);
                    continue;
                }
                Build::Close(node) => {
                    wto.end[node] = wto.order.len() as u32;
                    continue;
                }
                Build::Decompose { nodes, starts } => (nodes, starts),
            };
            for (at, node) in nodes.iter().enumerate() {
                local[*node] = at as u32;
            }
            let member = |node: I| {
                let at = local[node];
                (nodes.get(at as usize) == Some(&node)).then_some(Node(at))
            };
            let mut rows = Csr::<Node, Node>::with_capacity(nodes.len(), nodes.len());
            for node in &nodes {
                let mut row = (successors.get(*node).iter())
                    .filter_map(|successor| member(*successor))
                    .collect::<Vec<_>>();
                wto.visits += row.len() as u64 + 1;
                row.sort_unstable();
                row.dedup();
                rows.push_row(row);
            }
            let condensation =
                crate::dense::Condensation::of(&rows, starts.iter().filter_map(|s| member(*s)));
            wto.visits += condensation.visits();
            let mut steps = Vec::new();
            // Components close sinks first; the order wants sources first.
            for (component, members) in condensation
                .components()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let members = members
                    .iter()
                    .map(|at| nodes[at.index()])
                    .collect::<Vec<_>>();
                if !condensation.is_cyclic(component) {
                    steps.extend([Build::Place(members[0]), Build::Close(members[0])]);
                    continue;
                }
                // The member the search entered first finishes last: the component's head.
                let head = *(members.iter())
                    .max_by_key(|member| condensation.finish(Node(local[**member])))
                    .expect("a component has a member");
                wto.head.insert(head);
                let mut starts = successors.get(head).to_vec();
                by_key(&mut starts);
                let rest = members.into_iter().filter(|other| *other != head).collect();
                steps.extend([
                    Build::Place(head),
                    Build::Decompose {
                        nodes: rest,
                        starts,
                    },
                    Build::Close(head),
                ]);
            }
            tasks.extend(steps.into_iter().rev());
        }
        wto
    }

    /// The reached nodes, in order.
    pub fn order(&self) -> &[I] {
        &self.order
    }

    /// Where `node` stands in the order; `None` for a node the entry does not reach.
    pub fn position(&self, node: I) -> Option<u32> {
        Some(self.position[node]).filter(|at| *at != UNPLACED)
    }

    /// Whether `node` leads a component: a cycle passes through it.
    pub fn is_head(&self, node: I) -> bool {
        self.head.contains(node)
    }

    /// One past the last position of the component `node` leads, or its own next position.
    pub fn end(&self, node: I) -> u32 {
        self.end[node]
    }

    /// Nodes and edges the searches touched: the `O(d · (V + E))` bound, metered.
    pub fn visits(&self) -> u64 {
        self.visits
    }
}

/// How [`wto_sparse`] asks for one cell: in the ascent (join, widen at a head) or the descent
/// (meet, refine at a head), and whether the cell lies in a component's head block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Ascend { head: bool },
    Descend { head: bool },
}

/// What one [`wto_sparse`] run spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Meter {
    /// Cells evaluated.
    pub evaluations: u64,
    /// The most times one head-block cell moved in one phase.
    pub head_moves: usize,
    /// Bitmap words the waiting search read: `O(cells / 64 + evaluations)` per phase.
    pub probes: u64,
}

/// Solve cells placed in blocks over a weak topological order, ascending then descending; `height`
/// bounds a head-block cell's moves per phase (doc/adr-fixpoint.md, "Weak topological order").
pub fn wto_sparse<B: DenseId, C: DenseId>(
    pass: &'static str,
    height: (usize, usize),
    wto: &Wto<B>,
    cells: &Csr<B, C>,
    readers: &Csr<C, C>,
    mut eval: impl FnMut(C, Step) -> bool,
) -> Result<Meter, Exhausted> {
    // Each cell's rank: blocks in order, a block's cells in its order.
    let mut rank = IdVec::filled(readers.len(), UNPLACED);
    let mut first = Vec::with_capacity(wto.order().len() + 1);
    let mut ranked = Vec::new();
    for block in wto.order() {
        first.push(ranked.len() as u32);
        for cell in cells.get(*block) {
            rank[*cell] = ranked.len() as u32;
            ranked.push(*cell);
        }
    }
    first.push(ranked.len() as u32);
    let mut meter = Meter::default();
    let mut moves = vec![0usize; ranked.len()];
    for (phase, height) in [(false, height.0), (true, height.1)] {
        let mut waiting = Waiting::all(ranked.len());
        moves.iter_mut().for_each(|count| *count = 0);
        let mut evaluate = |at: usize, head: bool, waiting: &mut Waiting, meter: &mut Meter| {
            let (lo, hi) = (first[at] as usize, first[at + 1] as usize);
            // The search resumes past each taken cell; a reader requeued below it moves it back.
            let mut from = lo;
            while let Some(index) = waiting.next(from, hi, &mut meter.probes) {
                waiting.clear(index);
                from = index + 1;
                meter.evaluations += 1;
                let step = match phase {
                    false => Step::Ascend { head },
                    true => Step::Descend { head },
                };
                if !eval(ranked[index], step) {
                    continue;
                }
                if head {
                    moves[index] += 1;
                    meter.head_moves = meter.head_moves.max(moves[index]);
                }
                for reader in readers.get(ranked[index]) {
                    if let Some(at) = Some(rank[*reader]).filter(|at| *at != UNPLACED) {
                        waiting.set(at as usize);
                        if (lo..from).contains(&(at as usize)) {
                            from = at as usize;
                        }
                    }
                }
            }
        };
        // The open components: each head's position and how often it has run.
        let mut open = Vec::<(usize, usize)>::new();
        let mut at = 0usize;
        loop {
            while let Some(&(head, runs)) = open.last()
                && at == wto.end(wto.order()[head]) as usize
            {
                let (lo, hi) = (first[head] as usize, first[head + 1] as usize);
                if waiting.next(lo, hi, &mut meter.probes).is_none() {
                    open.pop();
                    continue;
                }
                let limit = 2 + 2 * height * (hi - lo);
                if runs >= limit {
                    r2il::refusal_evidence!("fixpoint", "{pass}: a component ran past {limit}");
                    return Err(Exhausted { pass, height });
                }
                if let Some(last) = open.last_mut() {
                    last.1 += 1;
                }
                evaluate(head, true, &mut waiting, &mut meter);
                at = head + 1;
            }
            let Some(block) = wto.order().get(at) else {
                break;
            };
            let head = wto.is_head(*block);
            if head {
                open.push((at, 1));
            }
            evaluate(at, head, &mut waiting, &mut meter);
            at += 1;
        }
        if waiting.next(0, ranked.len(), &mut meter.probes).is_some() {
            r2il::refusal_evidence!("fixpoint", "{pass}: a cell was read before its writer");
            return Err(Exhausted { pass, height });
        }
    }
    Ok(meter)
}

/// The cells waiting to be evaluated, by rank: a bitset searched a word at a time.
struct Waiting {
    words: Vec<u64>,
}

impl Waiting {
    fn all(count: usize) -> Self {
        let mut words = vec![u64::MAX; count.div_ceil(64)];
        if let Some(last) = words.last_mut()
            && !count.is_multiple_of(64)
        {
            *last = (1u64 << (count % 64)) - 1;
        }
        Self { words }
    }

    fn set(&mut self, at: usize) {
        self.words[at / 64] |= 1 << (at % 64);
    }

    fn clear(&mut self, at: usize) {
        self.words[at / 64] &= !(1 << (at % 64));
    }

    /// The first waiting rank in `lo..hi`, each word read counted in `probes`.
    fn next(&self, lo: usize, hi: usize, probes: &mut u64) -> Option<usize> {
        let mut word = lo / 64;
        let mut bits = self.words.get(word)? & (u64::MAX << (lo % 64));
        loop {
            *probes += 1;
            if bits != 0 {
                let at = word * 64 + bits.trailing_zeros() as usize;
                return (at < hi).then_some(at);
            }
            word += 1;
            if word * 64 >= hi {
                return None;
            }
            bits = *self.words.get(word)?;
        }
    }
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

    /// The order of `edges` over `count` nodes from node 0, each node keyed by `keys`.
    fn order_of(count: usize, edges: &[(u32, u32)], keys: &[u64]) -> Wto<crate::dense::Node> {
        use crate::dense::Node;
        let pairs = edges.iter().map(|(from, to)| (Node(*from), Node(*to)));
        let successors = Csr::from_pairs(count, pairs);
        Wto::of(&successors, Node(0), |node| keys[node.index()])
    }

    /// The keys in order, a head marked `(` with its component closed by `)`.
    fn spelled(wto: &Wto<crate::dense::Node>, keys: &[u64]) -> String {
        let mut text = String::new();
        let mut open = Vec::new();
        for (at, node) in wto.order().iter().enumerate() {
            while open.last() == Some(&(at as u32)) {
                open.pop();
                text.push(')');
            }
            if wto.is_head(*node) {
                text.push('(');
                open.push(wto.end(*node));
            }
            text.push_str(&format!("{:x} ", keys[node.index()]));
        }
        text + &")".repeat(open.len())
    }

    /// `entry -> A | B`, `A <-> B`: the head is the lower-keyed of the two, whatever the numbering.
    #[test]
    fn an_irreducible_loops_head_is_its_least_key_whatever_the_numbering() {
        let keys = [0x1000, 0x1010, 0x1020];
        let given = order_of(3, &[(0, 1), (0, 2), (1, 2), (2, 1)], &keys);
        let swapped = order_of(3, &[(0, 2), (0, 1), (2, 1), (1, 2)], &keys);
        let renumbered = order_of(
            3,
            &[(0, 2), (0, 1), (1, 2), (2, 1)],
            &[0x1000, 0x1020, 0x1010],
        );
        assert_eq!(spelled(&given, &keys), "1000 (1010 1020 )");
        assert_eq!(spelled(&swapped, &keys), "1000 (1010 1020 )");
        assert_eq!(
            spelled(&renumbered, &[0x1000, 0x1020, 0x1010]),
            "1000 (1010 1020 )"
        );
    }

    /// Two nested loops, a block after them and one nothing reaches.
    #[test]
    fn nested_loops_nest_and_an_unreached_block_is_unplaced() {
        // 0 -> 1 (outer head) -> 2 (inner head) -> 3 -> 2 | 4 -> 1 | 5; 6 unreached.
        let keys = [0, 1, 2, 3, 4, 5, 6];
        let edges = [
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 2),
            (3, 4),
            (4, 1),
            (4, 5),
            (6, 5),
        ];
        let wto = order_of(7, &edges, &keys);
        assert_eq!(spelled(&wto, &keys), "0 (1 (2 3 )4 )5 ");
        assert_eq!(wto.position(crate::dense::Node(6)), None);
        assert!(
            wto.visits() <= 3 * (7 + edges.len() as u64) * 3,
            "{}",
            wto.visits()
        );
    }

    /// One block of `n` cells, each read by the next and moving once: the waiting search reads
    /// `O(n / 64 + evaluations)` words, where restarting at the block's first word read `n² / 128`.
    #[test]
    fn a_straight_block_searches_its_waiting_cells_once() {
        use crate::{ValueId, dense::Node};
        for n in [4096u32, 8192] {
            let wto = order_of(1, &[], &[0]);
            let cells = Csr::from_pairs(1, (0..n).map(|cell| (Node(0), ValueId(cell))));
            let readers =
                Csr::from_pairs(n as usize, (1..n).map(|at| (ValueId(at - 1), ValueId(at))));
            let mut moved = IdSet::new(n as usize);
            let meter = wto_sparse("straight", (1, 1), &wto, &cells, &readers, |cell, _| {
                moved.insert(cell)
            })
            .expect("a straight block settles");
            assert!(
                meter.probes <= 2 * meter.evaluations + 4 * u64::from(n) / 64,
                "{meter:?}"
            );
        }
    }

    /// A self-loop is its own component.
    #[test]
    fn a_self_loop_heads_a_component_of_one() {
        let keys = [0, 1, 2];
        let wto = order_of(3, &[(0, 1), (1, 1), (1, 2)], &keys);
        assert_eq!(spelled(&wto, &keys), "0 (1 )2 ");
    }

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

    /// A transfer whose exit moves while its entry does not is no function of its entry, refused.
    #[test]
    fn an_exit_that_moves_while_its_entry_holds_is_refused() {
        let function = looping();
        let mut count = 0u64;
        let solved = forward_on_edges(
            &function,
            "churn",
            1,
            Passed(BTreeSet::new()),
            |_, _| {},
            |_, _, state: &Passed| state.clone(),
            |_, _| {
                count += 1;
                Passed(BTreeSet::from([count]))
            },
        );
        assert_eq!(
            solved,
            Err(Exhausted {
                pass: "churn",
                height: 1
            })
        );
    }
}
