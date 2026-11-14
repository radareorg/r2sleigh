//! What each value can be: a fixpoint over the SSA graph.
//!
//! Abstract interpretation with strided intervals. Where the function has
//! nine or so hand-written answers to "how large can this get" -- one per
//! question, none of them joining at a merge and none of them following a phi
//! -- this is the one answer they were all approximating.
//!
//! The solve runs on `fixpoint::wto_sparse`, with branch environments in the ascent (doc/ssa.md,
//! "Termination" and "Branch assumptions").
//!
//! Top wider than sixty-four bits is unknown, never read as a value below `2^64`.

use std::collections::BTreeMap;

use crate::dense::{Csr, DenseId};
use crate::fixpoint::{Step, Wto};
use crate::graph::{BlockId, GraphInst, SsaGraph};
use crate::op::SSAOp;
use crate::strided::StridedInterval;
use crate::{InstPayload, ValueId};

/// What every value in one function can be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueRanges {
    by_value: Vec<StridedInterval>,
    /// Each value's copy class, which a guard environment is keyed by.
    class: Vec<ValueId>,
    /// Each block's guard environment, by [`BlockId`]; `u32::MAX` where no branch proves anything.
    env_of: Vec<u32>,
    /// What each environment holds once solved; `None` for one the entry never reached.
    envs: Vec<Option<Held>>,
}

impl ValueRanges {
    /// What this value can be, where the analysis reached it.
    pub fn get(&self, value: ValueId) -> Option<StridedInterval> {
        self.by_value.get(value.0 as usize).copied()
    }

    /// The largest value this can take, where that is bounded.
    ///
    /// The question the object model asks, answered once here instead of by
    /// a walk per caller.
    pub fn upper_bound(&self, value: ValueId) -> Option<u64> {
        let range = self.get(value)?;
        match range.is_top() || range.is_bottom() {
            true => None,
            false => range.bounds().map(|(_, high)| high),
        }
    }

    /// The smallest value this can take, where that is bounded.
    pub fn lower_bound(&self, value: ValueId) -> Option<u64> {
        let range = self.get(value)?;
        match range.is_top() || range.is_bottom() {
            true => None,
            false => range.bounds().map(|(low, _)| low),
        }
    }

    /// The step between the values this can take, where it takes several.
    ///
    /// An index into an array of four-byte elements steps by four, and that
    /// is the element size the aggregate recovery is otherwise guessing.
    pub fn stride(&self, value: ValueId) -> Option<u64> {
        self.get(value).filter(|range| !range.is_top())?.stride()
    }

    /// What this value can be where it is read in `block`: its range, under what the branches
    /// dominating `block` prove of its copy class. `O(log k)` in the classes they prove things of.
    pub fn range_at(&self, value: ValueId, block: BlockId) -> Option<StridedInterval> {
        let range = self.get(value)?;
        let held = (self.env_of.get(block.0 as usize))
            .and_then(|env| self.envs.get(*env as usize)?.as_ref());
        Some(meet_held(range, held, class_of(&self.class, value)))
    }

    /// The largest value this can take where it is read in `block`, where that is bounded.
    pub fn upper_bound_at(&self, value: ValueId, block: BlockId) -> Option<u64> {
        let range = self.range_at(value, block)?;
        match range.is_top() || range.is_bottom() {
            true => None,
            false => range.bounds().map(|(_, high)| high),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty()
    }

    /// How many values the analysis bounded, out of how many there are.
    ///
    /// The number that says whether this is answering anything: a solver that
    /// reaches top everywhere costs the same as one that works.
    pub fn bounded(&self) -> (usize, usize) {
        let bounded = self
            .by_value
            .iter()
            .filter(|range| !range.is_top() && !range.is_bottom())
            .count();
        (bounded, self.by_value.len())
    }
}

/// Solve for every value.
pub fn solve_value_ranges(
    graph: &SsaGraph,
    function: crate::semantic::BuildFacts<'_>,
    prep: Option<&crate::DecompilePrepFacts>,
    predicates: &crate::semantic::PredicateFacts,
) -> ValueRanges {
    solve_counted(graph, function, prep, predicates).0
}

/// What one instruction alone makes of the value it leaves in a storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionBound {
    /// The range its own operations give the value, with every value from before it at top.
    pub range: StridedInterval,
    /// Whether that is only the width the instruction wrote, before it was zero-extended.
    pub spans_width_written: bool,
}

/// The instruction's own operations transferred in `O(k)`, earlier values at top, over a graph no pass folded constants into.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "per-block interval environments; P5 rebuilds the value domain as an index over value ids (ROADMAP P5)"
    )
)]
pub fn instruction_bound(
    graph: &SsaGraph,
    instruction: u64,
    storage: crate::CanonicalStorageId,
) -> Option<InstructionBound> {
    let left = graph.left_by_instruction(instruction, storage)?;
    let mut local = BTreeMap::new();
    for inst in graph
        .insts_for_instruction(instruction)
        .filter_map(|inst| graph.inst(inst))
    {
        let Some(output) = inst.output else {
            continue;
        };
        let range = transfer(graph, inst, &|value: ValueId| {
            local
                .get(&value)
                .copied()
                .unwrap_or_else(|| literal_or_top(graph, value))
        });
        local.insert(output, range);
    }
    Some(InstructionBound {
        range: *local.get(&left)?,
        spans_width_written: spans_width_written(graph, &local, left),
    })
}

/// Whether the instruction alone leaves a value unbounded at the width it wrote, following its zero extensions back.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "per-block interval environments; P5 rebuilds the value domain as an index over value ids (ROADMAP P5)"
    )
)]
fn spans_width_written(
    graph: &SsaGraph,
    local: &BTreeMap<ValueId, StridedInterval>,
    mut value: ValueId,
) -> bool {
    loop {
        let known = local
            .get(&value)
            .copied()
            .unwrap_or_else(|| literal_or_top(graph, value));
        if known.is_top() {
            return true;
        }
        let extended = graph
            .def_inst(value)
            .filter(|_| local.contains_key(&value))
            .and_then(|inst| graph.inst(inst))
            .filter(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::IntZExt { .. })))
            .and_then(|inst| graph.inputs(inst.id).first().copied());
        let Some(extended) = extended else {
            return false;
        };
        value = extended;
    }
}

/// What a value is before anything in the function is known: a literal is itself, anything else is top.
fn literal_or_top(graph: &SsaGraph, value: ValueId) -> StridedInterval {
    let Some(value) = graph.value(value) else {
        return StridedInterval::top(64);
    };
    let width = width_of(value.var.size);
    match value.var.constant_bits() {
        Some(bits) => StridedInterval::constant(width, bits),
        None => StridedInterval::top(width),
    }
}

/// A head phi's widening moves: off bottom, each bound once, the stride through at most 64 divisors.
const WIDENING_MOVES: usize = 67;

/// A head phi's refinement moves: each bound widening sent to the extreme, once.
const REFINING_MOVES: usize = 2;

/// One cell of the solve: an instruction's output (`InstId` below the instruction count), or a
/// guard environment past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cell(u32);

impl DenseId for Cell {
    fn index(self) -> usize {
        self.0 as usize
    }
    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 cells"))
    }
}

/// No environment: no branch on the way proves anything.
const NO_ENV: u32 = u32::MAX;

/// What one environment holds: a narrowed range per copy class, sorted by class; a class absent is
/// not narrowed. A sparse row of the environments' dense index (doc/ssa.md, "Branch assumptions").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Held(Vec<(ValueId, StridedInterval)>);

impl Held {
    fn get(&self, class: ValueId) -> Option<&StridedInterval> {
        let at = self
            .0
            .binary_search_by_key(&class, |(class, _)| *class)
            .ok()?;
        Some(&self.0[at].1)
    }

    fn insert(&mut self, class: ValueId, range: StridedInterval) {
        match self.0.binary_search_by_key(&class, |(class, _)| *class) {
            Ok(at) => self.0[at].1 = range,
            Err(at) => self.0.insert(at, (class, range)),
        }
    }

    /// What both hold of a class each holds; a class one leaves unnarrowed is unnarrowed.
    fn join(&self, other: &Self) -> Self {
        let both = self.0.iter().filter_map(|(class, range)| {
            let theirs = other.get(*class)?;
            (theirs.width_bits() == range.width_bits()).then(|| (*class, range.join(theirs)))
        });
        Self(both.collect())
    }

    /// What either holds, met where both do.
    fn meet(&self, other: &Self) -> Self {
        let mut met = self.clone();
        for (class, theirs) in &other.0 {
            let range = match met.get(*class) {
                Some(ours) if ours.width_bits() == theirs.width_bits() => ours.meet(theirs),
                Some(ours) => *ours,
                None => *theirs,
            };
            met.insert(*class, range);
        }
        met
    }
}

/// A range under what an environment holds of its class.
fn meet_held(range: StridedInterval, held: Option<&Held>, class: ValueId) -> StridedInterval {
    match held.and_then(|held| held.get(class)) {
        Some(narrowed) if narrowed.width_bits() == range.width_bits() => range.meet(narrowed),
        _ => range,
    }
}

/// One guard environment: what holds at a block's start, or along one edge into a merge.
#[derive(Debug, Clone)]
struct Env {
    parent: u32,
    /// The block its cell is evaluated at the start of.
    block: BlockId,
    tests: Vec<(crate::semantic::CompareProvenance, bool)>,
}

/// The guard environments and where they hold.
struct Guards {
    envs: Vec<Env>,
    /// Each block's environment, by [`BlockId`].
    env_of: Vec<u32>,
    /// Each tested edge into a block with phis, `(to, from)` ascending, with its environment.
    edges: Vec<((BlockId, BlockId), u32)>,
}

impl Guards {
    /// Down the dominator tree, a new environment only where a dominating edge tests something:
    /// `O(B + A log A)` for `A` assumptions.
    fn of(
        graph: &SsaGraph,
        function: crate::semantic::BuildFacts<'_>,
        predicates: &crate::semantic::PredicateFacts,
    ) -> Self {
        let mut guards = Self {
            envs: Vec::new(),
            env_of: vec![NO_ENV; graph.blocks.len()],
            edges: Vec::new(),
        };
        if predicates.block_assumptions.is_empty() {
            return guards;
        }
        let block = |addr: u64| graph.block_by_addr.get(&addr).copied();
        let tests_from = |addr: u64, from: u64| {
            (predicates
                .block_assumptions
                .get(&addr)
                .into_iter()
                .flatten())
            .filter(|assumption| assumption.predecessor == from)
            .filter_map(|assumption| {
                Some((tested(predicates, assumption)?.clone(), assumption.truth))
            })
            .collect::<Vec<_>>()
        };
        let domtree = function.domtree();
        let mut ready = vec![domtree.entry];
        while let Some(addr) = ready.pop() {
            ready.extend(domtree.children(addr).iter().copied());
            let Some(at) = block(addr) else {
                continue;
            };
            let inherited = (domtree.idom(addr).and_then(block))
                .map_or(NO_ENV, |idom| guards.env_of[idom.0 as usize]);
            let dominating = (graph.blocks[at.0 as usize].predecessors.iter())
                .filter_map(|from| Some(graph.blocks.get(from.0 as usize)?.addr))
                .find(|from| edge_dominates((function.cfg(), function.domtree()), *from, addr));
            let tests = dominating
                .map(|from| tests_from(addr, from))
                .unwrap_or_default();
            guards.env_of[at.0 as usize] = match tests.is_empty() {
                true => inherited,
                false => guards.push(inherited, at, tests),
            };
        }
        for target in graph.blocks.iter() {
            let has_phis = (target.insts.iter())
                .filter_map(|inst| graph.inst(*inst))
                .any(|inst| matches!(inst.payload, InstPayload::Phi { .. }));
            if !has_phis || !predicates.block_assumptions.contains_key(&target.addr) {
                continue;
            }
            let mut sources = target.predecessors.clone();
            sources.sort_unstable();
            sources.dedup();
            for from in sources {
                let Some(from_addr) = graph.blocks.get(from.0 as usize).map(|b| b.addr) else {
                    continue;
                };
                let tests = tests_from(target.addr, from_addr);
                if tests.is_empty() {
                    continue;
                }
                let dominates =
                    edge_dominates((function.cfg(), function.domtree()), from_addr, target.addr);
                let env = match dominates {
                    true => guards.env_of[target.id.0 as usize],
                    false => {
                        let parent = guards.env_of[from.0 as usize];
                        guards.push(parent, target.id, tests)
                    }
                };
                guards.edges.push(((target.id, from), env));
            }
        }
        guards.edges.sort_unstable();
        guards
    }

    fn push(
        &mut self,
        parent: u32,
        block: BlockId,
        tests: Vec<(crate::semantic::CompareProvenance, bool)>,
    ) -> u32 {
        self.envs.push(Env {
            parent,
            block,
            tests,
        });
        (self.envs.len() - 1) as u32
    }

    /// What holds along `from -> to`: the edge's own environment, or `from`'s.
    fn along(&self, from: BlockId, to: BlockId) -> u32 {
        match self
            .edges
            .binary_search_by_key(&(to, from), |(edge, _)| *edge)
        {
            Ok(at) => self.edges[at].1,
            Err(_) => self.env_of.get(from.0 as usize).copied().unwrap_or(NO_ENV),
        }
    }
}

/// The values a guard environment's own tests read, and the copy classes they narrow.
fn guard_reads(graph: &SsaGraph, solved: Solved<'_>, env: &Env) -> (Vec<ValueId>, Vec<ValueId>) {
    let (mut reads, mut narrows) = (Vec::new(), Vec::new());
    for (compare, _) in &env.tests {
        for side in [compare.lhs, compare.rhs] {
            reads.push(side);
            if wide(graph, side) {
                continue;
            }
            narrows.push(solved.class_of(side));
            if let Some(whole) = lane_source(graph, side) {
                reads.push(whole);
                narrows.push(solved.class_of(whole));
            }
            narrows.extend(
                solved
                    .zero_extensions(side)
                    .into_iter()
                    .map(|w| solved.class_of(w)),
            );
        }
    }
    (reads, narrows)
}

/// The solution, and what the solve spent.
fn solve_counted(
    graph: &SsaGraph,
    function: crate::semantic::BuildFacts<'_>,
    prep: Option<&crate::DecompilePrepFacts>,
    predicates: &crate::semantic::PredicateFacts,
) -> (ValueRanges, crate::fixpoint::Meter) {
    // Environments are keyed by copy class: what a branch proves of a value it proves of its copies.
    let mut class = crate::view::class_values(graph, prep.map(|facts| &facts.views));
    let reloads = crate::reload::reloads(graph, prep);
    crate::reload::unite_classes(&mut class, &reloads);
    let extended = zero_extended(graph, &class);
    let guards = Guards::of(graph, function, predicates);
    let inst_count = graph.insts.len();
    let pi = |env: u32| Cell((inst_count + env as usize) as u32);
    let cell_count = inst_count + guards.envs.len();

    let mut state = graph
        .values
        .iter()
        .map(|value| {
            let width = width_of(value.var.size);
            match (value.var.constant_bits(), graph.def_inst(value.id)) {
                (Some(bits), _) => StridedInterval::constant(width, bits),
                (None, Some(_)) => StridedInterval::bottom(width),
                (None, None) => StridedInterval::top(width),
            }
        })
        .collect::<Vec<_>>();
    let mut held: Vec<Option<Held>> = vec![None; guards.envs.len()];
    let solved_classes = Solved {
        class: &class,
        state: &state,
        extended: &extended,
    };

    // Each environment's cell first in its block, then the block's instructions.
    let mut cells = Csr::<BlockId, Cell>::with_capacity(graph.blocks.len(), cell_count);
    let mut by_block = vec![Vec::new(); graph.blocks.len()];
    for (env, Env { block, .. }) in guards.envs.iter().enumerate() {
        by_block[block.0 as usize].push(pi(env as u32));
    }
    for (block, row) in graph.blocks.iter().zip(&mut by_block) {
        let defining = block
            .insts
            .iter()
            .filter(|inst| graph.inst(**inst).is_some_and(|inst| inst.output.is_some()));
        row.extend(defining.map(|inst| Cell(inst.0)));
        cells.push_row(std::mem::take(row));
    }

    // Operands, a select's comparison, a reload's first load, an environment's tests and parent:
    // every source dominates its reader (doc/adr-fixpoint.md, "Weak topological order").
    let mut pairs = Vec::new();
    let defined = |value: ValueId| graph.def_inst(value).map(|inst| Cell(inst.0));
    let mut narrows_of = Vec::with_capacity(guards.envs.len());
    for (at, env) in guards.envs.iter().enumerate() {
        let (reads, mut narrows) = guard_reads(graph, solved_classes, env);
        pairs.extend(
            reads
                .into_iter()
                .filter_map(defined)
                .map(|from| (from, pi(at as u32))),
        );
        if env.parent != NO_ENV {
            pairs.push((pi(env.parent), pi(at as u32)));
            narrows.extend(
                narrows_of
                    .get(env.parent as usize)
                    .into_iter()
                    .flat_map(|n: &Vec<ValueId>| n.iter().copied()),
            );
        }
        narrows.sort_unstable();
        narrows.dedup();
        narrows_of.push(narrows);
    }
    let narrowed = |env: u32, value: ValueId| {
        (narrows_of.get(env as usize)).is_some_and(|narrows: &Vec<ValueId>| {
            narrows.binary_search(&class_of(&class, value)).is_ok()
        })
    };
    for inst in graph.insts.iter() {
        let Some(output) = inst.output else {
            continue;
        };
        let reader = Cell(inst.id.0);
        let inputs = graph.inputs(inst.id);
        let tested = match &inst.payload {
            InstPayload::Op(SSAOp::Select(_)) => inputs
                .first()
                .and_then(|condition| comparison_of(graph, *condition)),
            _ => None,
        };
        let compared = tested.iter().flat_map(|compare| [compare.lhs, compare.rhs]);
        let first = reloads.get(output).copied();
        for value in inputs.iter().copied().chain(compared).chain(first) {
            pairs.extend(defined(value).map(|from| (from, reader)));
        }
        match &inst.payload {
            InstPayload::Phi { predecessors } => {
                for (value, from) in inputs.iter().zip(predecessors) {
                    let env = guards.along(*from, inst.block);
                    if env != NO_ENV && narrowed(env, *value) {
                        pairs.push((pi(env), reader));
                    }
                }
            }
            InstPayload::Op(_) => {
                let env = guards.env_of[inst.block.0 as usize];
                let compared = tested.iter().flat_map(|compare| [compare.lhs, compare.rhs]);
                let read = inputs.iter().copied().chain(compared).chain(first);
                if env != NO_ENV && read.into_iter().any(|value| narrowed(env, value)) {
                    pairs.push((pi(env), reader));
                }
            }
        }
    }
    let readers = Csr::<Cell, Cell>::from_pairs(cell_count, pairs);
    let successors = Csr::<BlockId, BlockId>::from_pairs(
        graph.blocks.len(),
        graph
            .blocks
            .iter()
            .flat_map(|block| block.successors.iter().map(move |to| (block.id, *to))),
    );
    let wto = Wto::of(&successors, graph.entry, |block| {
        graph.blocks[block.0 as usize].addr
    });

    let solve = crate::fixpoint::wto_sparse(
        "value ranges",
        (WIDENING_MOVES, REFINING_MOVES),
        &wto,
        &cells,
        &readers,
        |cell, step| {
            let solved = Solved {
                class: &class,
                state: &state,
                extended: &extended,
            };
            if cell.index() >= inst_count {
                let at = cell.index() - inst_count;
                let env = &guards.envs[at];
                let parent = match env.parent {
                    NO_ENV => Some(Held::default()),
                    parent => held[parent as usize].clone(),
                };
                let Some(mut now) = parent else {
                    return false;
                };
                for (compare, truth) in &env.tests {
                    assume(&mut now, graph, solved, compare, *truth);
                }
                let next = match (&held[at], step) {
                    (None, _) => now,
                    (Some(was), Step::Ascend { .. }) => was.join(&now),
                    (Some(was), Step::Descend { .. }) => was.meet(&now),
                };
                let moved = held[at].as_ref() != Some(&next);
                held[at] = Some(next);
                return moved;
            }
            let Some(inst) = graph.inst(crate::InstId(cell.0)) else {
                return false;
            };
            let Some(output) = inst.output else {
                return false;
            };
            let Some(slot) = state.get(output.0 as usize).copied() else {
                return false;
            };
            let read_under = |env: u32, value: ValueId| {
                let range = (state.get(value.0 as usize).copied())
                    .unwrap_or_else(|| StridedInterval::top(64));
                let held = (env != NO_ENV)
                    .then(|| held[env as usize].as_ref())
                    .flatten();
                meet_held(range, held, class_of(&class, value))
            };
            let env = guards.env_of[inst.block.0 as usize];
            let read = |value: ValueId| read_under(env, value);
            let phi = matches!(inst.payload, InstPayload::Phi { .. });
            let mut computed = match &inst.payload {
                // A merge is the join of what reaches it, each input under what its own edge proves.
                InstPayload::Phi { predecessors } => {
                    let width = slot.width_bits();
                    (graph.inputs(inst.id).iter().zip(predecessors))
                        .map(|(value, from)| {
                            read_at(read_under(guards.along(*from, inst.block), *value), width)
                        })
                        .reduce(|left, right| left.join(&right))
                        .unwrap_or_else(|| StridedInterval::bottom(width))
                }
                InstPayload::Op(_) => transfer(graph, inst, &read),
            };
            // A reload of an unwritten slot is the earlier load's bits.
            if let Some(first) = reloads.get(output) {
                let reread = read(*first);
                if reread.width_bits() == computed.width_bits() {
                    computed = computed.meet(&reread);
                }
            }
            let next = match step {
                Step::Ascend { head: true } if phi => slot.widen(&slot.join(&computed)),
                Step::Ascend { .. } => slot.join(&computed),
                Step::Descend { head: true } if phi => slot.refine(&slot.meet(&computed)),
                Step::Descend { .. } => slot.meet(&computed),
            };
            if next == slot {
                return false;
            }
            state[output.0 as usize] = next;
            true
        },
    );
    let meter = match solve {
        Ok(meter) => meter,
        // A solve that broke its bound states nothing: every value is unknown.
        Err(_) => {
            let top =
                (graph.values.iter()).map(|value| StridedInterval::top(width_of(value.var.size)));
            let ranges = ValueRanges {
                by_value: top.collect(),
                class,
                env_of: Vec::new(),
                envs: Vec::new(),
            };
            return (ranges, crate::fixpoint::Meter::default());
        }
    };
    let ranges = ValueRanges {
        by_value: state,
        class,
        env_of: guards.env_of,
        envs: held,
    };
    (ranges, meter)
}

/// Whether a value is wider than the domain describes.
fn wide(graph: &SsaGraph, value: ValueId) -> bool {
    graph
        .value(value)
        .is_some_and(|value| value.var.size > StridedInterval::MAX_WIDTH_BITS / 8)
}

/// The width a value is read at, in the widest the domain can describe.
///
/// A vector register is wider than the domain's `u64`, and a value described
/// at sixty-four bits is top there, which is the honest answer rather than a
/// shift by a distance that does not exist.
const fn width_of(size_bytes: u32) -> u32 {
    let bits = match size_bytes {
        0 => StridedInterval::MAX_WIDTH_BITS,
        size => size.saturating_mul(8),
    };
    match bits > StridedInterval::MAX_WIDTH_BITS {
        true => StridedInterval::MAX_WIDTH_BITS,
        false => bits,
    }
}

/// What this instruction makes of what its inputs can be.
fn transfer(
    graph: &SsaGraph,
    inst: &GraphInst,
    lookup: &dyn Fn(ValueId) -> StridedInterval,
) -> StridedInterval {
    let width = inst
        .output
        .and_then(|value| graph.value(value))
        .map(|value| width_of(value.var.size))
        .unwrap_or(64);
    let input = |index: usize| -> StridedInterval {
        graph
            .inputs(inst.id)
            .get(index)
            .map(|value| lookup(*value))
            .unwrap_or_else(|| StridedInterval::top(width))
    };
    let at_width = |range: StridedInterval| read_at(range, width);

    let InstPayload::Op(op) = &inst.payload else {
        // A merge is the join of what reaches it, which is the whole reason
        // this is a fixpoint and not a walk.
        return graph
            .inputs(inst.id)
            .iter()
            .map(|value| lookup(*value))
            .map(at_width)
            .reduce(|left, right| left.join(&right))
            .unwrap_or_else(|| StridedInterval::bottom(width));
    };
    if bounds_unknown_as_known(graph, inst, op) {
        return StridedInterval::top(width);
    }
    if let Some(bits) = exact(graph, inst, op, lookup) {
        return StridedInterval::constant(width, bits);
    }
    // A shift by more than `u32` holds is still past every width.
    let places = |index: usize| {
        input(index)
            .as_constant()
            .map(|places| u32::try_from(places).unwrap_or(u32::MAX))
    };

    match op {
        SSAOp::Copy { .. } | SSAOp::CallRestore { .. } => at_width(input(0)),
        SSAOp::IntAdd { .. } => at_width(input(0)).add(&at_width(input(1))),
        SSAOp::IntSub { .. } => {
            let difference = at_width(input(0)).sub(&at_width(input(1)));
            // `x - d * (x / d)` with an exact quotient is `x % d` (`crate::division`).
            match (graph.inputs(inst.id).first(), graph.inputs(inst.id).get(1)) {
                (Some(x), Some(t)) => match crate::division::remainder_divisor(graph, *x, *t) {
                    Some(divisor) => {
                        difference.meet(&StridedInterval::interval(width, 0, divisor - 1))
                    }
                    None => difference,
                },
                _ => difference,
            }
        }
        SSAOp::IntMult { .. } => at_width(input(0)).mul(&at_width(input(1))),
        SSAOp::IntLeft { .. } => match places(1) {
            Some(places) => at_width(input(0)).shl(places),
            None => StridedInterval::top(width),
        },
        SSAOp::IntRight { .. } => match places(1) {
            Some(places) => at_width(input(0)).shr(places),
            None => StridedInterval::top(width),
        },
        SSAOp::IntAnd { .. } => match input(1).as_constant() {
            Some(mask) => at_width(input(0)).and_mask(mask),
            None => match input(0).as_constant() {
                Some(mask) => at_width(input(1)).and_mask(mask),
                None => StridedInterval::top(width),
            },
        },
        SSAOp::IntRem { .. } => at_width(input(0)).rem(&at_width(input(1))),
        SSAOp::IntDiv { .. } => at_width(input(0)).div(&at_width(input(1))),
        // Zero extension keeps the value and changes only the width it is
        // read at, which the bounds already say.
        SSAOp::IntZExt { .. } => at_width(input(0)),
        // A piece is the source shifted down past `offset` bytes, then read at the narrower width.
        SSAOp::Subpiece { offset, .. } => {
            let source = input(0);
            let unknown = source.is_top()
                && graph
                    .inputs(inst.id)
                    .first()
                    .is_some_and(|v| wide(graph, *v));
            match unknown {
                true => StridedInterval::top(width),
                false => at_width(source.shr(offset.saturating_mul(8))),
            }
        }
        // A selection is one arm or the other, and its condition says which.
        //
        // `csel x16, x16, xzr, ls` after `cmp x16, 0x5b` is how a compiler
        // clamps a switch index, and without reading the condition the arm it
        // keeps stays unbounded -- which made a jump table run to the end of
        // the address space rather than over its cases.
        SSAOp::Select(_) => {
            let arm =
                |index: usize| selected_arm(graph, inst, index, at_width(input(index)), lookup);
            arm(1).join(&arm(2))
        }
        // A comparison is nought or one, whatever it compares.
        op if comparison_kind(op).is_some() || is_flag(op) => {
            StridedInterval::interval(width, 0, 1)
        }
        _ => StridedInterval::top(width),
    }
}

/// The one value an operation computes whatever its inputs hold, where its inputs fix it.
fn exact(
    graph: &SsaGraph,
    inst: &GraphInst,
    op: &SSAOp<ValueId>,
    lookup: &dyn Fn(ValueId) -> StridedInterval,
) -> Option<u64> {
    // A number less itself, or exclusive-or itself, is nought whatever it is: `xor eax, eax`.
    let (first, second) = (graph.inputs(inst.id).first(), graph.inputs(inst.id).get(1));
    if matches!(op, SSAOp::IntXor { .. } | SSAOp::IntSub { .. })
        && first.is_some()
        && first == second
    {
        return Some(0);
    }
    // An operation over literals is the one value it computes: `mvn r3, 0` leaves exactly `!0`.
    let narrow = |value: &ValueId| !wide(graph, *value);
    if !inst.output.iter().chain(graph.inputs(inst.id)).all(narrow) {
        return None;
    }
    crate::constant::fold_inst(graph, inst, |value| lookup(value).as_constant())
}

/// A value read at a width other than its own keeps its bounds where they fit and is otherwise unknown.
fn read_at(range: StridedInterval, width: u32) -> StridedInterval {
    match range.bounds() {
        _ if range.width_bits() == width => range,
        Some((low, high)) if high <= mask_of(width) => {
            StridedInterval::strided(width, range.stride().unwrap_or(1), low, high)
        }
        _ => StridedInterval::top(width),
    }
}

/// Whether an operation's transfer would read an unknown value past sixty-four bits as below `2^64`.
fn bounds_unknown_as_known(graph: &SsaGraph, inst: &GraphInst, op: &SSAOp<ValueId>) -> bool {
    inst.output.is_some_and(|output| wide(graph, output))
        && matches!(
            op,
            SSAOp::IntLeft { .. }
                | SSAOp::IntRight { .. }
                | SSAOp::IntDiv { .. }
                | SSAOp::Select(_)
        )
}

/// A carry, borrow or boolean operation, which yields a flag.
fn is_flag<V>(op: &SSAOp<V>) -> bool {
    matches!(
        op,
        SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::BoolNot { .. }
    )
}

const fn mask_of(width_bits: u32) -> u64 {
    match width_bits >= 64 {
        true => u64::MAX,
        false => (1u64 << width_bits) - 1,
    }
}

/// The comparison an edge's branch tests, where its two ways out differ.
fn tested<'a>(
    predicates: &'a crate::semantic::PredicateFacts,
    assumption: &crate::semantic::BlockAssumption,
) -> Option<&'a crate::semantic::CompareProvenance> {
    let fact = predicates.predicates.get(&assumption.predicate)?;
    (fact.true_target != fact.false_target)
        .then(|| {
            fact.comparison
                .as_ref()
                .or(fact.evaluated_comparison.as_ref())
        })
        .flatten()
}

/// Whether every arrival at `block` first takes `predecessor -> block`, so what that edge tests holds there (doc/ssa.md, "Branch assumptions").
pub(crate) fn edge_dominates(
    (cfg, domtree): (&crate::cfg::CFG, &crate::domtree::DomTree),
    predecessor: u64,
    block: u64,
) -> bool {
    let reachable = |other: u64| other == domtree.entry || domtree.idom(other).is_some();
    block != domtree.entry
        && cfg
            .predecessors(block)
            .into_iter()
            .filter(|other| *other != predecessor && reachable(*other))
            .all(|other| domtree.dominates(block, other))
}

/// The ranges solved so far, and the copy class (the view's) each value is
/// held under: what a comparison proves of one side it proves of every value
/// with that side's bits.
#[derive(Clone, Copy)]
struct Solved<'a> {
    class: &'a [ValueId],
    state: &'a [StridedInterval],
    /// Each zero extension, by the copy class it extends, ascending: the class and the wider value.
    extended: &'a [(ValueId, ValueId)],
}

impl Solved<'_> {
    fn class_of(self, value: ValueId) -> ValueId {
        class_of(self.class, value)
    }

    /// Every value that zero-extends one of `value`'s copy class, through any number of extensions:
    /// the same number at a wider width. Each copy class is visited once: `O(found log found)`.
    fn zero_extensions(self, value: ValueId) -> Vec<ValueId> {
        let of = |class: ValueId| {
            let start = self.extended.partition_point(|(from, _)| *from < class);
            let run = self.extended[start..].iter();
            run.take_while(move |(from, _)| *from == class)
                .map(|(_, wider)| *wider)
        };
        // The classes visited, ascending, and the ones whose extensions are still to read.
        let mut visited = vec![self.class_of(value)];
        let mut pending = visited.clone();
        let mut found = Vec::new();
        while let Some(class) = pending.pop() {
            let from = found.len();
            found.extend(of(class));
            let reached = found[from..].iter().map(|wider| self.class_of(*wider));
            pending.extend(reached.filter(|class| first_visit(&mut visited, *class)));
        }
        found
    }
}

/// Whether `class` is new to `visited`, which holds it afterwards, ascending.
fn first_visit(visited: &mut Vec<ValueId>, class: ValueId) -> bool {
    match visited.binary_search(&class) {
        Ok(_) => false,
        Err(at) => {
            visited.insert(at, class);
            true
        }
    }
}

/// Every zero extension in the graph, by the copy class of what it extends: `O(I log I)`.
fn zero_extended(graph: &SsaGraph, class: &[ValueId]) -> Vec<(ValueId, ValueId)> {
    let mut extended = (graph.insts.iter())
        .filter(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::IntZExt { .. })))
        .filter_map(|inst| {
            let from = graph.inputs(inst.id).first()?;
            Some((class_of(class, *from), inst.output?))
        })
        .collect::<Vec<_>>();
    extended.sort_unstable();
    extended
}

/// The copy class a value belongs to, where the table knows it.
fn class_of(class: &[ValueId], value: ValueId) -> ValueId {
    class.get(value.0 as usize).copied().unwrap_or(value)
}

/// Narrow what a block holds by one comparison, taken the way `truth` says.
///
/// `held` is keyed by copy class.
fn assume(
    held: &mut Held,
    graph: &SsaGraph,
    solved: Solved<'_>,
    compare: &crate::semantic::CompareProvenance,
    truth: bool,
) {
    for side in [compare.lhs, compare.rhs] {
        let now = (!wide(graph, side))
            .then(|| narrowed_side(held, solved, compare, truth, side))
            .flatten();
        if let Some(now) = now {
            held.insert(solved.class_of(side), now);
            // `add eax, 0x83; cmp eax, 0x114; ja` writes rax as the zero extension of the compared bits.
            // `cmp $0xe, %ax` tests the low lane of a value that fits the lane: the value is the lane.
            if let Some(whole) = fitting_source(graph, solved, side) {
                let width = (graph.value(whole)).map_or(64, |value| width_of(value.var.size));
                let was = (held.get(solved.class_of(whole)).copied())
                    .or_else(|| solved.state.get(whole.0 as usize).copied())
                    .unwrap_or_else(|| StridedInterval::top(width));
                held.insert(solved.class_of(whole), was.meet(&read_at(now, width)));
            }
            // An extension may be written after the guard: a reader meets its own range with this.
            for widened in solved.zero_extensions(side) {
                let width = graph
                    .value(widened)
                    .map_or(64, |value| width_of(value.var.size));
                let was = (held.get(solved.class_of(widened)).copied())
                    .unwrap_or_else(|| StridedInterval::top(width));
                held.insert(solved.class_of(widened), was.meet(&read_at(now, width)));
            }
        }
    }
}

/// The value `lane` is the low bytes of, where the ascent bounds that value inside the lane's
/// width; a value with no values yet fits, so the environment only grows as the source does.
fn fitting_source(graph: &SsaGraph, solved: Solved<'_>, lane: ValueId) -> Option<ValueId> {
    let src = lane_source(graph, lane)?;
    let width = width_of(graph.value(lane)?.var.size);
    let range = solved.state.get(src.0 as usize)?;
    let fits = range.is_bottom()
        || range
            .bounds()
            .is_some_and(|(_, high)| high <= mask_of(width));
    fits.then_some(src)
}

/// The value a lane narrower than sixty-four bits is the low bytes of, where the domain describes it.
fn lane_source(graph: &SsaGraph, lane: ValueId) -> Option<ValueId> {
    let inst = graph.inst(graph.def_inst(lane)?)?;
    let InstPayload::Op(SSAOp::Subpiece { src, offset: 0, .. }) = &inst.payload else {
        return None;
    };
    let width = width_of(graph.value(lane)?.var.size);
    (!wide(graph, *src) && width < 64).then_some(*src)
}

/// One arm of a select, under what its condition proves on that arm.
///
/// A select is the one place a condition bounds a value with no path
/// sensitivity needed: both arms are taken, and each satisfies the condition
/// it is guarded by, so the join of the two narrowed arms is sound.
fn selected_arm(
    graph: &SsaGraph,
    inst: &GraphInst,
    index: usize,
    range: StridedInterval,
    lookup: &dyn Fn(ValueId) -> StridedInterval,
) -> StridedInterval {
    // The first input is the condition and the second is the arm taken when it
    // holds, so which arm this is says which way the condition ran; passing
    // that separately would let the two disagree.
    let truth = index == 1;
    let compare = graph
        .inputs(inst.id)
        .first()
        .and_then(|condition| comparison_of(graph, *condition));
    match (compare, graph.inputs(inst.id).get(index).copied()) {
        (Some(compare), Some(value)) => {
            narrow(&|value| Some(lookup(value)), range, &compare, truth, value)
        }
        _ => range,
    }
}

/// What a comparison proves about one of its sides, where it proves anything.
///
/// `None` where the side has no range yet or where the comparison leaves it
/// exactly as it was, so the caller inserts only what it has learned.
fn narrowed_side(
    held: &Held,
    solved: Solved<'_>,
    compare: &crate::semantic::CompareProvenance,
    truth: bool,
    side: ValueId,
) -> Option<StridedInterval> {
    let known = |value: ValueId| {
        held.get(solved.class_of(value))
            .copied()
            .or_else(|| solved.state.get(value.0 as usize).copied())
    };
    let was = known(side)?;
    let now = narrow(&known, was, compare, truth, side);
    (now != was).then_some(now)
}

/// One comparison's effect on one side of it; a false one is its mirror, `!(a < b)` being `b <= a`.
fn narrow(
    known: &dyn Fn(ValueId) -> Option<StridedInterval>,
    range: StridedInterval,
    compare: &crate::semantic::CompareProvenance,
    truth: bool,
    value: ValueId,
) -> StridedInterval {
    use crate::semantic::CompareKind;
    let (other, mirrored) = match (compare.lhs == value, compare.rhs == value) {
        (true, _) => (compare.rhs, false),
        (_, true) => (compare.lhs, true),
        _ => return range,
    };
    let (kind, mirrored) = match truth {
        true => (compare.kind, mirrored),
        false => (
            match compare.kind {
                CompareKind::Less => CompareKind::LessEqual,
                CompareKind::LessEqual => CompareKind::Less,
                CompareKind::Equal => CompareKind::NotEqual,
                CompareKind::NotEqual => CompareKind::Equal,
                kind => kind,
            },
            !mirrored,
        ),
    };
    let Some(bound) = known(other) else {
        return range;
    };
    // A side with no values yet admits nothing, so what it bounds only grows as it does.
    if bound.is_bottom() {
        return StridedInterval::bottom(range.width_bits());
    }
    let Some((low, high)) = bound.bounds() else {
        return range;
    };
    let width = range.width_bits();
    let ceiling = StridedInterval::top(width)
        .bounds()
        .map_or(u64::MAX, |(_, high)| high);
    let below = |limit: Option<u64>| match limit {
        Some(limit) => range.meet(&StridedInterval::interval(width, 0, limit)),
        None => StridedInterval::bottom(width),
    };
    // A limit past the width's end admits nothing, where masking it would admit everything.
    let above = |limit: Option<u64>| match limit.filter(|limit| *limit <= ceiling) {
        Some(limit) => range.meet(&StridedInterval::interval(width, limit, ceiling)),
        None => StridedInterval::bottom(width),
    };
    // Only what the unsigned comparisons prove is taken: a signed one says
    // nothing about an unsigned range without knowing the sign.
    match (kind, mirrored) {
        (CompareKind::Equal, _) => range.meet(&bound),
        (CompareKind::Less, false) => below(high.checked_sub(1)),
        (CompareKind::LessEqual, false) => below(Some(high)),
        (CompareKind::Less, true) => above(low.checked_add(1)),
        (CompareKind::LessEqual, true) => above(Some(low)),
        _ => range,
    }
}

/// The comparison a condition is, read off the operation that defines it.
fn comparison_of(
    graph: &SsaGraph,
    condition: ValueId,
) -> Option<crate::semantic::CompareProvenance> {
    let inst = graph.inst(graph.def_inst(condition)?)?;
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    Some(crate::semantic::CompareProvenance {
        kind: comparison_kind(op)?,
        lhs: *graph.inputs(inst.id).first()?,
        rhs: *graph.inputs(inst.id).get(1)?,
    })
}

/// Which comparison an operation is, where it is one.
fn comparison_kind<V>(op: &SSAOp<V>) -> Option<crate::semantic::CompareKind> {
    use crate::semantic::CompareKind;
    Some(match op {
        SSAOp::IntEqual { .. } => CompareKind::Equal,
        SSAOp::IntNotEqual { .. } => CompareKind::NotEqual,
        SSAOp::IntLess { .. } => CompareKind::Less,
        SSAOp::IntLessEqual { .. } => CompareKind::LessEqual,
        SSAOp::IntSLess { .. } => CompareKind::SignedLess,
        SSAOp::IntSLessEqual { .. } => CompareKind::SignedLessEqual,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SSAVar;
    use crate::cfg::{BasicBlock, BlockTerminator, CFG};
    use crate::function::{PhiNode, SSABlock, SSAFunction};

    fn var(name: &str, version: u32, size: u32) -> SSAVar {
        SSAVar::new(name, version, size)
    }

    fn constant(value: u64, size: u32) -> SSAVar {
        SSAVar::constant(value, size)
    }

    fn solve_over(blocks: &[SSABlock], cfg: CFG) -> (ValueRanges, SsaGraph) {
        let (ranges, graph, _) = solve_counting(blocks, cfg);
        (ranges, graph)
    }

    fn solve_counting(
        blocks: &[SSABlock],
        cfg: CFG,
    ) -> (ValueRanges, SsaGraph, crate::fixpoint::Meter) {
        let function = SSAFunction::from_exact_test_blocks(blocks, cfg);
        let graph = SsaGraph::from_function(&function);
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let (ranges, meter) = solve_counted(
            &graph,
            crate::semantic::BuildFacts::bare(&function),
            None,
            &predicates,
        );
        (ranges, graph, meter)
    }

    /// A graph from each block's terminator.
    fn cfg_of(entry: u64, shape: &[(u64, BlockTerminator)]) -> CFG {
        let mut cfg = CFG::new(entry);
        for (addr, terminator) in shape {
            let mut basic = BasicBlock::new(*addr);
            basic.size = 16;
            basic.terminator = terminator.clone();
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();
        cfg
    }

    fn straight_line(block: SSABlock) -> CFG {
        let mut cfg = CFG::new(block.addr);
        let mut basic = BasicBlock::new(block.addr);
        basic.size = block.size;
        basic.terminator = BlockTerminator::Return;
        cfg.add_block(basic);
        cfg.rebuild_edges();
        cfg
    }

    fn range_of(ranges: &ValueRanges, graph: &SsaGraph, name: &SSAVar) -> StridedInterval {
        let id = graph.value_id_for_var(name).expect("value in graph");
        ranges.get(id).expect("a range for it")
    }

    #[test]
    fn constants_travel_through_arithmetic() {
        let sum = var("sum", 1, 4);
        let mut block = SSABlock::new(0x1000, 8);
        block.push(crate::op::SSAOp::IntAdd {
            dst: sum.clone(),
            a: constant(4, 4),
            b: constant(6, 4),
        });
        let cfg = straight_line(block.clone());
        let (ranges, graph) = solve_over(&[block], cfg);
        assert_eq!(range_of(&ranges, &graph, &sum).as_constant(), Some(10));
    }

    #[test]
    fn an_index_scaled_by_an_element_size_keeps_the_stride() {
        // What an array subscript is: a bounded index times the element size.
        let index = var("index", 1, 4);
        let offset = var("offset", 1, 4);
        let mut block = SSABlock::new(0x1000, 12);
        block.push(crate::op::SSAOp::IntAnd {
            dst: index.clone(),
            a: var("raw", 0, 4),
            b: constant(7, 4),
        });
        block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: index.clone(),
            b: constant(4, 4),
        });
        let cfg = straight_line(block.clone());
        let (ranges, graph) = solve_over(&[block], cfg);

        let index_range = range_of(&ranges, &graph, &index);
        assert_eq!(index_range.bounds(), Some((0, 7)));
        let offset_range = range_of(&ranges, &graph, &offset);
        assert_eq!(offset_range.stride(), Some(4));
        assert_eq!(offset_range.bounds(), Some((0, 28)));
    }

    #[test]
    fn a_merge_joins_what_reaches_it_rather_than_giving_up() {
        let entry = 0x1000;
        let (left, right, merge) = (0x1010, 0x1020, 0x1030);
        let taken = var("value", 1, 4);
        let other = var("value", 2, 4);
        let merged = var("value", 3, 4);

        let head = SSABlock::new(entry, 16);
        let mut left_block = SSABlock::new(left, 16);
        left_block.push(crate::op::SSAOp::Copy {
            dst: taken.clone(),
            src: constant(3, 4),
        });
        let mut right_block = SSABlock::new(right, 16);
        right_block.push(crate::op::SSAOp::Copy {
            dst: other.clone(),
            src: constant(7, 4),
        });
        let mut merge_block = SSABlock::new(merge, 16);
        merge_block.push_phi(PhiNode {
            dst: merged.clone(),
            sources: vec![(left, taken), (right, other)],
            canonical_storage: None,
        });

        let mut cfg = CFG::new(entry);
        for (addr, terminator) in [
            (
                entry,
                BlockTerminator::ConditionalBranch {
                    true_target: left,
                    false_target: right,
                },
            ),
            (left, BlockTerminator::Branch { target: merge }),
            (right, BlockTerminator::Branch { target: merge }),
            (merge, BlockTerminator::Return),
        ] {
            let mut basic = BasicBlock::new(addr);
            basic.size = 16;
            basic.terminator = terminator;
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();

        let blocks = [head, left_block, right_block, merge_block];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let joined = range_of(&ranges, &graph, &merged);
        assert!(joined.contains(3), "{joined:?}");
        assert!(joined.contains(7), "{joined:?}");
        assert_eq!(joined.bounds(), Some((3, 7)));
    }

    #[test]
    fn a_counter_in_a_loop_reaches_a_fixpoint() {
        // Without widening this climbs one iteration at a time and never
        // settles; the test is that it settles at all.
        let entry = 0x1000;
        let header = 0x1010;
        let counter = var("i", 1, 4);
        let stepped = var("i", 2, 4);

        let head = SSABlock::new(entry, 16);
        let mut header_block = SSABlock::new(header, 16);
        header_block.push_phi(PhiNode {
            dst: counter.clone(),
            sources: vec![(entry, constant(0, 4)), (header, stepped.clone())],
            canonical_storage: None,
        });
        header_block.push(crate::op::SSAOp::IntAdd {
            dst: stepped,
            a: counter.clone(),
            b: constant(1, 4),
        });

        let mut cfg = CFG::new(entry);
        for (addr, terminator) in [
            (entry, BlockTerminator::Branch { target: header }),
            (
                header,
                BlockTerminator::ConditionalBranch {
                    true_target: header,
                    false_target: entry,
                },
            ),
        ] {
            let mut basic = BasicBlock::new(addr);
            basic.size = 16;
            basic.terminator = terminator;
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();

        let blocks = [head, header_block];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let range = range_of(&ranges, &graph, &counter);
        assert!(range.contains(0), "the counter starts at nought: {range:?}");
        assert!(range.contains(1), "and is stepped: {range:?}");
    }

    #[test]
    fn a_value_wider_than_the_domain_is_never_read_as_below_its_edge() {
        // `div rcx` divides rdx:rax, a 128-bit dividend nothing bounds, so its quotient is not below 2^63.
        let dividend = var("tmp", 0, 16);
        let (divisor, quotient) = (var("divisor", 1, 16), var("quotient", 1, 16));
        let (low, high) = (var("low", 1, 8), var("high", 1, 8));
        let mut block = SSABlock::new(0x1000, 8);
        block.push(crate::op::SSAOp::IntZExt {
            dst: divisor.clone(),
            src: constant(2, 8),
        });
        block.push(crate::op::SSAOp::IntDiv {
            dst: quotient.clone(),
            a: dividend.clone(),
            b: divisor,
        });
        block.push(crate::op::SSAOp::Subpiece {
            dst: low.clone(),
            src: quotient,
            offset: 0,
        });
        // The high half of an unknown value is unknown, not the nought a shift past sixty-four bits gives.
        block.push(crate::op::SSAOp::Subpiece {
            dst: high.clone(),
            src: dividend,
            offset: 8,
        });
        let cfg = straight_line(block.clone());
        let (ranges, graph) = solve_over(&[block], cfg);
        assert!(range_of(&ranges, &graph, &low).contains(1 << 63));
        assert!(range_of(&ranges, &graph, &high).contains(5));
    }

    #[test]
    fn an_edge_into_a_merge_narrows_nothing_there() {
        // c = x <u 10; if c goto T else M; T: goto M; M: y = x -- T enters M with x < 10.
        let (entry, taken, merge) = (0x1000, 0x1010, 0x1020);
        let (x, below, y) = (var("x", 0, 4), var("below", 1, 1), var("y", 1, 4));
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntLess {
            dst: below.clone(),
            a: x.clone(),
            b: constant(10, 4),
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(taken, 8),
            cond: below,
        });
        let mut merge_block = SSABlock::new(merge, 16);
        merge_block.push(crate::op::SSAOp::Copy {
            dst: y.clone(),
            src: x,
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: taken,
                        false_target: merge,
                    },
                ),
                (taken, BlockTerminator::Branch { target: merge }),
                (merge, BlockTerminator::Return),
            ],
        );
        let blocks = [head, SSABlock::new(taken, 16), merge_block];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let copied = range_of(&ranges, &graph, &y);
        assert!(copied.contains(5), "{copied:?}");
    }

    /// `entry: if x <u 10 goto M; other: if z <u 20 goto M else exit; M: m = phi(x, z); y = m * 4`,
    /// or `other` entering `M` untested.
    fn merged_index(second_guarded: bool) -> StridedInterval {
        let (entry, other, merge, exit) = (0x1000, 0x1010, 0x1020, 0x1030);
        let (x, z, m, y) = (
            var("x", 0, 4),
            var("z", 0, 4),
            var("m", 1, 4),
            var("y", 1, 4),
        );
        let guard = |block: &mut SSABlock, flag: &str, value: &SSAVar, limit: u64| {
            let below = var(flag, 1, 1);
            block.push(crate::op::SSAOp::IntLess {
                dst: below.clone(),
                a: value.clone(),
                b: constant(limit, 4),
            });
            block.push(crate::op::SSAOp::CBranch {
                target: constant(merge, 8),
                cond: below,
            });
        };
        let mut head = SSABlock::new(entry, 16);
        guard(&mut head, "first", &x, 10);
        let mut other_block = SSABlock::new(other, 16);
        let leaves = match second_guarded {
            true => {
                guard(&mut other_block, "second", &z, 20);
                BlockTerminator::ConditionalBranch {
                    true_target: merge,
                    false_target: exit,
                }
            }
            false => BlockTerminator::Branch { target: merge },
        };
        let mut merge_block = SSABlock::new(merge, 16);
        merge_block.push_phi(PhiNode {
            dst: m.clone(),
            sources: vec![(entry, x), (other, z)],
            canonical_storage: None,
        });
        merge_block.push(crate::op::SSAOp::IntMult {
            dst: y.clone(),
            a: m,
            b: constant(4, 4),
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: merge,
                        false_target: other,
                    },
                ),
                (other, leaves),
                (merge, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let blocks = [head, other_block, merge_block, SSABlock::new(exit, 16)];
        let (ranges, graph) = solve_over(&blocks, cfg);
        range_of(&ranges, &graph, &y)
    }

    /// gzip `main` `0x3b9a`: a table index reached from two tests, neither of whose edges dominates the dispatch.
    #[test]
    fn a_merge_reads_each_input_under_its_own_edges_test() {
        assert_eq!(merged_index(true).bounds(), Some((0, 76)));
    }

    #[test]
    fn a_merge_with_an_untested_edge_keeps_what_that_edge_carries() {
        let scaled = merged_index(false);
        assert!(scaled.contains(1 << 20), "{scaled:?}");
    }

    #[test]
    fn an_irreducible_counter_widens_and_settles() {
        // entry -> A | B, A -> B, B -> A: neither A nor B dominates the other, so neither is a natural loop header.
        let (entry, a, b) = (0x1000, 0x1010, 0x1020);
        let (at_a, from_a) = (var("i", 1, 4), var("i", 2, 4));
        let (at_b, from_b) = (var("i", 3, 4), var("i", 4, 4));
        let choice = var("choice", 1, 1);
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntLess {
            dst: choice.clone(),
            a: var("arg", 0, 4),
            b: constant(5, 4),
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(a, 8),
            cond: choice,
        });
        let counted = |addr: u64, phi: &SSAVar, stepped: &SSAVar, back: (u64, &SSAVar)| {
            let mut block = SSABlock::new(addr, 16);
            block.push_phi(PhiNode {
                dst: phi.clone(),
                sources: vec![(entry, constant(0, 4)), (back.0, back.1.clone())],
                canonical_storage: None,
            });
            block.push(crate::op::SSAOp::IntAdd {
                dst: stepped.clone(),
                a: phi.clone(),
                b: constant(1, 4),
            });
            block
        };
        let blocks = [
            head,
            counted(a, &at_a, &from_a, (b, &from_b)),
            counted(b, &at_b, &from_b, (a, &from_a)),
        ];
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: a,
                        false_target: b,
                    },
                ),
                (a, BlockTerminator::Branch { target: b }),
                (b, BlockTerminator::Branch { target: a }),
            ],
        );
        let (ranges, graph, meter) = solve_counting(&blocks, cfg);
        // One component of two head cells: at most `2 + 2 * 67 * 2` runs per phase.
        assert!(meter.head_moves <= WIDENING_MOVES, "{meter:?}");
        let cells = graph.insts.len() as u64;
        let runs = 2 + 2 * WIDENING_MOVES as u64 * 2;
        assert!(
            meter.evaluations <= 2 * cells * runs,
            "{meter:?} over {cells} cells"
        );
        assert!(
            meter.evaluations <= 4 * cells,
            "{meter:?}: two passes per phase settle it"
        );
        for counter in [&at_a, &at_b] {
            let range = range_of(&ranges, &graph, counter);
            assert!(range.contains(0) && range.contains(7), "{range:?}");
        }
    }

    #[test]
    fn a_guarded_body_reads_the_bound_its_header_leaves_on() {
        // `for (i = 0; i < 8; i++) a[i] = ...`. Widening leaves the counter
        // describing every value of its width, which is what makes the loop
        // terminate; the header's test is what says the body only ever sees
        // nought to seven, so the offset it scales reaches 28 and the array
        // is 32 bytes rather than the whole address space.
        let (entry, header, body, latch, exit) = (0x1000, 0x1010, 0x1020, 0x1030, 0x1040);
        let counter = var("i", 1, 4);
        let stepped = var("i", 2, 4);
        let guard = var("guard", 1, 1);
        let offset = var("offset", 1, 4);

        let head = SSABlock::new(entry, 16);
        let mut header_block = SSABlock::new(header, 16);
        header_block.push_phi(PhiNode {
            dst: counter.clone(),
            sources: vec![(entry, constant(0, 4)), (latch, stepped.clone())],
            canonical_storage: None,
        });
        header_block.push(crate::op::SSAOp::IntLess {
            dst: guard.clone(),
            a: counter.clone(),
            b: constant(8, 4),
        });
        header_block.push(crate::op::SSAOp::CBranch {
            target: constant(body, 8),
            cond: guard,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: counter.clone(),
            b: constant(4, 4),
        });
        let mut latch_block = SSABlock::new(latch, 16);
        latch_block.push(crate::op::SSAOp::IntAdd {
            dst: stepped,
            a: counter,
            b: constant(1, 4),
        });
        let exit_block = SSABlock::new(exit, 16);

        let mut cfg = CFG::new(entry);
        for (addr, terminator) in [
            (entry, BlockTerminator::Branch { target: header }),
            (
                header,
                BlockTerminator::ConditionalBranch {
                    true_target: body,
                    false_target: exit,
                },
            ),
            (body, BlockTerminator::Branch { target: latch }),
            (latch, BlockTerminator::Branch { target: header }),
            (exit, BlockTerminator::Return),
        ] {
            let mut basic = BasicBlock::new(addr);
            basic.size = 16;
            basic.terminator = terminator;
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();

        let blocks = [head, header_block, body_block, latch_block, exit_block];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let scaled = range_of(&ranges, &graph, &offset);
        assert_eq!(scaled.bounds(), Some((0, 28)), "{scaled:?}");
        assert_eq!(scaled.stride(), Some(4), "{scaled:?}");
    }

    /// `cmp eax, 7; ja default; mov eax, eax; ... [rax*8]` with EAX loaded:
    /// the comparison reads one lane read of the register and the index
    /// another. Both are the loaded value's bits, so what the branch proves of
    /// one it proves of the other; keyed by the value the comparison happened
    /// to read, the index read further on stayed the whole of its width.
    #[test]
    fn a_branch_narrows_every_read_of_the_bits_it_compares() {
        let (entry, body, exit) = (0x1000, 0x1010, 0x1020);
        let loaded = var("tmp:load", 1, 4);
        let wide = var("rax", 1, 8);
        let compared = var("eax", 1, 4);
        let guard = var("guard", 1, 1);
        let indexed = var("eax", 2, 4);
        let index = var("rax", 2, 8);
        let offset = var("offset", 1, 8);

        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: var("rdi", 0, 8),
        });
        head.push(crate::op::SSAOp::IntZExt {
            dst: wide.clone(),
            src: loaded,
        });
        head.push(crate::op::SSAOp::Subpiece {
            dst: compared.clone(),
            src: wide.clone(),
            offset: 0,
        });
        head.push(crate::op::SSAOp::IntLess {
            dst: guard.clone(),
            a: compared,
            b: constant(8, 4),
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(body, 8),
            cond: guard,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::Subpiece {
            dst: indexed.clone(),
            src: wide,
            offset: 0,
        });
        body_block.push(crate::op::SSAOp::IntZExt {
            dst: index.clone(),
            src: indexed,
        });
        body_block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: index.clone(),
            b: constant(8, 8),
        });
        let exit_block = SSABlock::new(exit, 16);
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: body,
                        false_target: exit,
                    },
                ),
                (body, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let function = SSAFunction::from_exact_test_blocks(&[head, body_block, exit_block], cfg);
        let prep = function.prep_facts_for_test();
        let graph = SsaGraph::from_function(&function);
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let ranges = solve_value_ranges(
            &graph,
            crate::semantic::BuildFacts::bare(&function),
            Some(&prep),
            &predicates,
        );
        assert_eq!(range_of(&ranges, &graph, &index).bounds(), Some((0, 7)));
        assert_eq!(range_of(&ranges, &graph, &offset).bounds(), Some((0, 56)));
    }

    /// `add eax, 0x83; cmp eax, 0x114; ja`: rax is written before the guard, and the guard still bounds it.
    #[test]
    fn a_guard_bounds_the_zero_extension_written_before_it() {
        let (entry, body, exit) = (0x1000, 0x1010, 0x1020);
        let selector = var("tmp:sum", 1, 4);
        let wide = var("rax", 1, 8);
        let within = var("within", 1, 1);
        let beyond = var("beyond", 1, 1);
        let offset = var("offset", 1, 8);

        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntAdd {
            dst: selector.clone(),
            a: var("eax", 0, 4),
            b: constant(0x83, 4),
        });
        head.push(crate::op::SSAOp::IntZExt {
            dst: wide.clone(),
            src: selector.clone(),
        });
        head.push(crate::op::SSAOp::IntLessEqual {
            dst: within.clone(),
            a: selector,
            b: constant(0x114, 4),
        });
        head.push(crate::op::SSAOp::BoolNot {
            dst: beyond.clone(),
            src: within,
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(exit, 8),
            cond: beyond,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: wide,
            b: constant(4, 8),
        });
        let exit_block = SSABlock::new(exit, 16);
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: exit,
                        false_target: body,
                    },
                ),
                (body, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let function = SSAFunction::from_exact_test_blocks(&[head, body_block, exit_block], cfg);
        let prep = function.prep_facts_for_test();
        let graph = SsaGraph::from_function(&function);
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let ranges = solve_value_ranges(
            &graph,
            crate::semantic::BuildFacts::bare(&function),
            Some(&prep),
            &predicates,
        );
        assert_eq!(
            range_of(&ranges, &graph, &offset).bounds(),
            Some((0, 0x450))
        );
    }

    /// grep `0x9cc5`: `movzwl 0x68(%rbp), %eax` then `cmp $0xe, %ax; ja`: the guard reads a copy of the
    /// loaded word, and the index is that word extended twice.
    #[test]
    fn a_guard_on_a_copy_bounds_the_words_extensions_through_both_widths() {
        let (entry, body, exit) = (0x1000, 0x1010, 0x1020);
        let (word, low) = (var("tmp:word", 1, 2), var("ax", 1, 2));
        let (half, wide) = (var("eax", 1, 4), var("rax", 1, 8));
        let (within, beyond) = (var("within", 1, 1), var("beyond", 1, 1));
        let offset = var("offset", 1, 8);
        let extend = |dst: &SSAVar, src: &SSAVar| crate::op::SSAOp::IntZExt {
            dst: dst.clone(),
            src: src.clone(),
        };
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::Copy {
            dst: word.clone(),
            src: var("loaded", 0, 2),
        });
        head.push(extend(&half, &word));
        head.push(extend(&wide, &half));
        head.push(crate::op::SSAOp::Subpiece {
            dst: low.clone(),
            src: wide.clone(),
            offset: 0,
        });
        head.push(crate::op::SSAOp::IntLessEqual {
            dst: within.clone(),
            a: low,
            b: constant(0xe, 2),
        });
        head.push(crate::op::SSAOp::BoolNot {
            dst: beyond.clone(),
            src: within,
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(exit, 8),
            cond: beyond,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: wide,
            b: constant(4, 8),
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: exit,
                        false_target: body,
                    },
                ),
                (body, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let blocks = [head, body_block, SSABlock::new(exit, 16)];
        let function = SSAFunction::from_exact_test_blocks(&blocks, cfg);
        let prep = function.prep_facts_for_test();
        let graph = SsaGraph::from_function(&function);
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let ranges = solve_value_ranges(
            &graph,
            crate::semantic::BuildFacts::bare(&function),
            Some(&prep),
            &predicates,
        );
        assert_eq!(range_of(&ranges, &graph, &offset).bounds(), Some((0, 56)));
    }

    /// 64 extensions of one word, each extended again: every extension is found once, however many
    /// share a copy class.
    #[test]
    fn equivalent_extensions_are_each_found_once() {
        let word = var("word", 0, 2);
        let mut block = SSABlock::new(0x1000, 16);
        let mut wide = Vec::new();
        for at in 0..64u32 {
            let (half, whole) = (var("half", at + 1, 4), var("whole", at + 1, 8));
            block.push(crate::op::SSAOp::IntZExt {
                dst: half.clone(),
                src: word.clone(),
            });
            block.push(crate::op::SSAOp::IntZExt {
                dst: whole.clone(),
                src: half,
            });
            wide.push(whole);
        }
        let cfg = straight_line(block.clone());
        let function = SSAFunction::from_exact_test_blocks(&[block], cfg);
        let prep = function.prep_facts_for_test();
        let graph = SsaGraph::from_function(&function);
        let class = crate::view::class_values(&graph, Some(&prep.views));
        let extended = zero_extended(&graph, &class);
        let solved = Solved {
            class: &class,
            state: &[],
            extended: &extended,
        };
        let word = graph.value_id_for_var(&word).expect("the word");
        let mut found = solved.zero_extensions(word);
        assert_eq!(found.len(), 128, "{found:?}");
        found.sort_unstable();
        found.dedup();
        assert_eq!(found.len(), 128);
        for whole in &wide {
            let whole = graph.value_id_for_var(whole).expect("an extension");
            assert!(found.binary_search(&whole).is_ok(), "{whole:?}");
        }
    }

    /// grep `0x9d2a`: the index is a merge of 16-bit words held in `rax`, and `cmp $0xe, %ax; ja` tests its low lane.
    #[test]
    fn a_guard_on_the_low_lane_bounds_a_value_that_fits_the_lane() {
        let (entry, body, exit) = (0x1000, 0x1010, 0x1020);
        let (wide, low) = (var("rax", 1, 8), var("ax", 1, 2));
        let (within, beyond) = (var("within", 1, 1), var("beyond", 1, 1));
        let offset = var("offset", 1, 8);
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntAnd {
            dst: wide.clone(),
            a: var("loaded", 0, 8),
            b: constant(0xffff, 8),
        });
        head.push(crate::op::SSAOp::Subpiece {
            dst: low.clone(),
            src: wide.clone(),
            offset: 0,
        });
        head.push(crate::op::SSAOp::IntLessEqual {
            dst: within.clone(),
            a: low,
            b: constant(0xe, 2),
        });
        head.push(crate::op::SSAOp::BoolNot {
            dst: beyond.clone(),
            src: within,
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(exit, 8),
            cond: beyond,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: wide,
            b: constant(4, 8),
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: exit,
                        false_target: body,
                    },
                ),
                (body, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let blocks = [head, body_block, SSABlock::new(exit, 16)];
        let (ranges, graph) = solve_over(&blocks, cfg);
        assert_eq!(range_of(&ranges, &graph, &offset).bounds(), Some((0, 56)));
    }

    /// Every consumer of the solution reads an operation its inputs fix as that one value, whatever the operand holds.
    #[test]
    fn the_solver_reads_an_operation_its_inputs_fix_as_one_value() {
        let entry = 0x1000;
        let (left, right, merge) = (0x1010, 0x1020, 0x1030);
        let raw = var("eax", 0, 4);
        let cleared = var("eax", 1, 4);
        let seven = var("eax", 2, 4);
        let merged = var("eax", 3, 4);
        let inverted = var("r3", 1, 4);
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntNot {
            dst: inverted.clone(),
            src: constant(0, 4),
        });
        // `xor eax, eax` on one arm, `mov eax, 7` on the other.
        let mut left_block = SSABlock::new(left, 16);
        left_block.push(crate::op::SSAOp::IntXor {
            dst: cleared.clone(),
            a: raw.clone(),
            b: raw,
        });
        let mut right_block = SSABlock::new(right, 16);
        right_block.push(crate::op::SSAOp::Copy {
            dst: seven.clone(),
            src: constant(7, 4),
        });
        let mut merge_block = SSABlock::new(merge, 16);
        merge_block.push_phi(PhiNode {
            dst: merged.clone(),
            sources: vec![(left, cleared.clone()), (right, seven)],
            canonical_storage: None,
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: left,
                        false_target: right,
                    },
                ),
                (left, BlockTerminator::Branch { target: merge }),
                (right, BlockTerminator::Branch { target: merge }),
                (merge, BlockTerminator::Return),
            ],
        );
        let blocks = [head, left_block, right_block, merge_block];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let of = |name: &SSAVar| range_of(&ranges, &graph, name);
        assert_eq!(of(&inverted).as_constant(), Some(0xffff_ffff));
        assert_eq!(of(&cleared).as_constant(), Some(0));
        assert_eq!(of(&merged).bounds(), Some((0, 7)), "{:?}", of(&merged));
    }

    /// `mvn r3, 0` computes one value from its literal, and `xor eax, eax` is nought: each instruction alone fixes it.
    #[test]
    fn an_instruction_alone_fixes_what_it_computes_from_literals() {
        use r2il::{R2ILBlock, R2ILOp, Varnode};
        let r3 = Varnode::register(0, 4);
        let eax = Varnode::register(8, 4);
        let scratch = Varnode::unique(0x100, 4);
        let ops = [
            (
                0x1000,
                R2ILOp::IntNot {
                    dst: scratch.clone(),
                    src: Varnode::constant(0, 4),
                },
            ),
            (
                0x1000,
                R2ILOp::Copy {
                    dst: r3.clone(),
                    src: scratch,
                },
            ),
            (
                0x1004,
                R2ILOp::IntXor {
                    dst: eax.clone(),
                    a: eax.clone(),
                    b: eax.clone(),
                },
            ),
            (
                0x1006,
                R2ILOp::Return {
                    target: Varnode::constant(0, 4),
                },
            ),
        ];
        let mut block = R2ILBlock::new(0x1000, 8);
        for (addr, op) in ops {
            block.push_from(op, addr);
        }
        let graph = crate::def_use_graph(&[block], None, 0x1000).expect("it builds");
        let fixed = |at: u64, storage: &Varnode| {
            let storage = crate::CanonicalStorageId::from_varnode(storage);
            instruction_bound(&graph, at, storage).and_then(|bound| bound.range.as_constant())
        };
        assert_eq!(fixed(0x1000, &r3), Some(0xffff_ffff));
        assert_eq!(fixed(0x1004, &eax), Some(0));
    }

    /// Two counter loops meeting at a self-loop `H`; `flipped` swaps the entry branch (renumbering
    /// every InstId), `cut` drops `H`'s exit (an ancestor-closed block set of the whole).
    fn two_loops_meeting(flipped: bool, cut: bool) -> Vec<(String, StridedInterval)> {
        let (entry, l1, x1, l2, x2, head, exit) =
            (0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060);
        let (u, u2, t, m) = (
            var("u", 1, 4),
            var("u", 2, 4),
            var("t", 1, 4),
            var("m", 1, 4),
        );
        let (v, v2, c1, c2) = (
            var("v", 1, 4),
            var("v", 2, 4),
            var("c1", 1, 4),
            var("c2", 1, 4),
        );
        let (w, w2, w3) = (var("w", 1, 4), var("w", 2, 4), var("w", 3, 4));
        let (p, p2, after) = (var("p", 1, 4), var("p", 2, 4), var("after", 1, 4));
        let counter = |addr: u64, phi: &SSAVar, stepped: &SSAVar, step: u64| {
            let mut block = SSABlock::new(addr, 16);
            block.push_phi(PhiNode {
                dst: phi.clone(),
                sources: vec![(entry, constant(0, 4)), (addr, stepped.clone())],
                canonical_storage: None,
            });
            block.push(crate::op::SSAOp::IntAdd {
                dst: stepped.clone(),
                a: phi.clone(),
                b: constant(step, 4),
            });
            block
        };
        // `c1 = 10 - (u & 1) * 8` settles at `8[2,10]` one round before `c2 = 10 - (v & 5)`, two
        // copies longer, settles at `[5,10]`: the head reads `[2,10]` whichever it reads first.
        let mut x1_block = SSABlock::new(x1, 16);
        x1_block.push(crate::op::SSAOp::IntAnd {
            dst: t.clone(),
            a: u.clone(),
            b: constant(1, 4),
        });
        x1_block.push(crate::op::SSAOp::IntMult {
            dst: m.clone(),
            a: t,
            b: constant(8, 4),
        });
        x1_block.push(crate::op::SSAOp::IntSub {
            dst: c1.clone(),
            a: constant(10, 4),
            b: m,
        });
        let mut x2_block = SSABlock::new(x2, 16);
        x2_block.push(crate::op::SSAOp::IntAnd {
            dst: w.clone(),
            a: v.clone(),
            b: constant(5, 4),
        });
        x2_block.push(crate::op::SSAOp::Copy {
            dst: w2.clone(),
            src: w,
        });
        x2_block.push(crate::op::SSAOp::Copy {
            dst: w3.clone(),
            src: w2,
        });
        x2_block.push(crate::op::SSAOp::IntSub {
            dst: c2.clone(),
            a: constant(10, 4),
            b: w3,
        });
        let mut head_block = SSABlock::new(head, 16);
        head_block.push_phi(PhiNode {
            dst: p.clone(),
            sources: vec![(x1, c1), (x2, c2), (head, p2.clone())],
            canonical_storage: None,
        });
        head_block.push(crate::op::SSAOp::Copy {
            dst: p2,
            src: p.clone(),
        });
        let mut exit_block = SSABlock::new(exit, 16);
        exit_block.push(crate::op::SSAOp::IntAdd {
            dst: after,
            a: p,
            b: constant(1, 4),
        });
        let (first, second) = match flipped {
            true => (l2, l1),
            false => (l1, l2),
        };
        let looping = |addr: u64, out: u64| {
            let terminator = BlockTerminator::ConditionalBranch {
                true_target: addr,
                false_target: out,
            };
            (addr, terminator)
        };
        let mut shape = vec![
            (
                entry,
                BlockTerminator::ConditionalBranch {
                    true_target: first,
                    false_target: second,
                },
            ),
            looping(l1, x1),
            (x1, BlockTerminator::Branch { target: head }),
            looping(l2, x2),
            (x2, BlockTerminator::Branch { target: head }),
        ];
        let mut blocks = vec![
            SSABlock::new(entry, 16),
            counter(l1, &u, &u2, 16),
            x1_block,
            counter(l2, &v, &v2, 1),
            x2_block,
            head_block,
        ];
        match cut {
            true => shape.push((head, BlockTerminator::Branch { target: head })),
            false => {
                shape.push(looping(head, exit));
                shape.push((exit, BlockTerminator::Return));
                blocks.push(exit_block);
            }
        }
        let (ranges, graph) = solve_over(&blocks, cfg_of(entry, &shape));
        ["u", "t", "m", "c1", "v", "w", "c2", "p"]
            .iter()
            .flat_map(|name| [1, 2, 3].map(|version| var(name, version, 4)))
            .filter_map(|name| {
                let id = graph.value_id_for_var(&name)?;
                Some((name.to_string(), ranges.get(id)?))
            })
            .collect()
    }

    /// The ranges are a function of the program: a renumbering of its InstIds, or a cut to an
    /// ancestor-closed block set, leaves every value's range as it was (doc/adr-fixpoint.md).
    #[test]
    fn a_renumbered_function_solves_to_the_same_ranges() {
        let whole = two_loops_meeting(false, false);
        assert_eq!(whole.len(), 13, "{whole:?}");
        assert_eq!(two_loops_meeting(true, false), whole, "renumbered");
        assert_eq!(two_loops_meeting(false, true), whole, "cut");
        let (p, at) = (var("p", 1, 4), |ranges: &[(String, StridedInterval)]| {
            ranges.to_vec()
        });
        let p = whole.iter().find(|(name, _)| *name == p.to_string());
        assert_eq!(
            p.map(|(_, range)| range.bounds()),
            Some(Some((2, 10))),
            "{:?}",
            at(&whole)
        );
        assert_eq!(
            irreducible(true),
            irreducible(false),
            "an irreducible loop's head"
        );
    }

    /// `entry -> A | B`, `A <-> B` with `qa = pa + 1`, `qb = pb & 7`; `flipped` swaps the entry
    /// branch, which a search taking the true edge first follows into the other block.
    fn irreducible(flipped: bool) -> Vec<Option<StridedInterval>> {
        let (entry, a, b) = (0x1000, 0x1010, 0x1020);
        let (pa, qa, pb, qb) = (
            var("pa", 1, 4),
            var("qa", 1, 4),
            var("pb", 1, 4),
            var("qb", 1, 4),
        );
        let mut a_block = SSABlock::new(a, 16);
        a_block.push_phi(PhiNode {
            dst: pa.clone(),
            sources: vec![(entry, constant(0, 4)), (b, qb.clone())],
            canonical_storage: None,
        });
        a_block.push(crate::op::SSAOp::IntAdd {
            dst: qa.clone(),
            a: pa.clone(),
            b: constant(1, 4),
        });
        let mut b_block = SSABlock::new(b, 16);
        b_block.push_phi(PhiNode {
            dst: pb.clone(),
            sources: vec![(entry, constant(0, 4)), (a, qa.clone())],
            canonical_storage: None,
        });
        b_block.push(crate::op::SSAOp::IntAnd {
            dst: qb.clone(),
            a: pb.clone(),
            b: constant(7, 4),
        });
        let (first, second) = match flipped {
            true => (b, a),
            false => (a, b),
        };
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: first,
                        false_target: second,
                    },
                ),
                (a, BlockTerminator::Branch { target: b }),
                (b, BlockTerminator::Branch { target: a }),
            ],
        );
        let (ranges, graph) = solve_over(&[SSABlock::new(entry, 16), a_block, b_block], cfg);
        [pa, qa, pb, qb]
            .iter()
            .map(|name| ranges.get(graph.value_id_for_var(name)?))
            .collect()
    }

    /// `if (x <u 4) body; exit`: a live-in no instruction narrows is bounded where each way holds.
    #[test]
    fn a_guard_bounds_a_live_in_where_it_dominates() {
        let (entry, body, exit) = (0x1000, 0x1010, 0x1020);
        let (x, below) = (var("x", 0, 4), var("below", 1, 1));
        let mut head = SSABlock::new(entry, 16);
        head.push(crate::op::SSAOp::IntLess {
            dst: below.clone(),
            a: x.clone(),
            b: constant(4, 4),
        });
        head.push(crate::op::SSAOp::CBranch {
            target: constant(body, 8),
            cond: below,
        });
        let cfg = cfg_of(
            entry,
            &[
                (
                    entry,
                    BlockTerminator::ConditionalBranch {
                        true_target: body,
                        false_target: exit,
                    },
                ),
                (body, BlockTerminator::Return),
                (exit, BlockTerminator::Return),
            ],
        );
        let blocks = [head, SSABlock::new(body, 16), SSABlock::new(exit, 16)];
        let (ranges, graph) = solve_over(&blocks, cfg);
        let value = graph.value_id_for_var(&x).expect("x");
        let at = |addr: u64| ranges.range_at(value, graph.block_by_addr[&addr]);
        assert_eq!(at(body).and_then(|range| range.bounds()), Some((0, 3)));
        let past = at(exit).and_then(|range| range.bounds());
        assert_eq!(past, Some((4, u64::from(u32::MAX))));
        assert_eq!(ranges.upper_bound(value), None);
    }

    /// `entry: i = arg & 7`, `H: n = phi(4, 8); if i < n goto B`, `B: x = i`: the bound `n` rises
    /// after the guard first reads it, and the guard reads it again (8 admits `i = 7`).
    #[test]
    fn a_guard_reads_its_bound_again_when_the_bound_rises_in_the_loop() {
        let (entry, head, body, exit) = (0x1000, 0x1010, 0x1020, 0x1030);
        let (i, n, n2) = (var("i", 1, 4), var("n", 1, 4), var("n", 2, 4));
        let (x, below) = (var("x", 1, 4), var("below", 1, 1));
        let mut entry_block = SSABlock::new(entry, 16);
        entry_block.push(crate::op::SSAOp::IntAnd {
            dst: i.clone(),
            a: var("arg", 0, 4),
            b: constant(7, 4),
        });
        let mut head_block = SSABlock::new(head, 16);
        head_block.push_phi(PhiNode {
            dst: n.clone(),
            sources: vec![(entry, constant(4, 4)), (body, n2.clone())],
            canonical_storage: None,
        });
        head_block.push(crate::op::SSAOp::IntLess {
            dst: below.clone(),
            a: i.clone(),
            b: n,
        });
        head_block.push(crate::op::SSAOp::CBranch {
            target: constant(body, 8),
            cond: below,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.push(crate::op::SSAOp::Copy {
            dst: x.clone(),
            src: i,
        });
        body_block.push(crate::op::SSAOp::Copy {
            dst: n2,
            src: constant(8, 4),
        });
        let cfg = cfg_of(
            entry,
            &[
                (entry, BlockTerminator::Branch { target: head }),
                (
                    head,
                    BlockTerminator::ConditionalBranch {
                        true_target: body,
                        false_target: exit,
                    },
                ),
                (body, BlockTerminator::Branch { target: head }),
                (exit, BlockTerminator::Return),
            ],
        );
        let blocks = [entry_block, head_block, body_block, SSABlock::new(exit, 16)];
        let (ranges, graph) = solve_over(&blocks, cfg);
        assert_eq!(range_of(&ranges, &graph, &x).bounds(), Some((0, 7)));
    }
}
