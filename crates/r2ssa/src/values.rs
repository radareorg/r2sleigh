//! What each value can be: a fixpoint over the SSA graph.
//!
//! Abstract interpretation with strided intervals. Where the function has
//! nine or so hand-written answers to "how large can this get" -- one per
//! question, none of them joining at a merge and none of them following a phi
//! -- this is the one answer they were all approximating.
//!
//! The shape is the worklist `data_ref.rs` already uses for constants: seed
//! from the literals, transfer at each instruction, and re-queue the readers
//! of anything that moved. What is different is the domain, and that a merge
//! joins rather than giving up.
//!
//! Termination comes from widening at loop headers. The lattice has unbounded
//! ascending chains through the bounds, so a counter would otherwise be raised
//! one iteration at a time forever; at a header the bound that grew jumps to
//! the extreme of its width instead. The criterion is structural -- this phi
//! is a loop's -- rather than a count of visits, because a count would be a
//! number nothing derived.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::graph::{GraphInst, SsaGraph};
use crate::op::SSAOp;
use crate::strided::StridedInterval;
use crate::{InstPayload, ValueId};

/// What every value in one function can be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueRanges {
    by_value: Vec<StridedInterval>,
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

/// Solve for every value, widening at the phis of the given blocks.
///
/// `widen_at` is the loop headers, and any block in a cycle the structurer
/// could not name. A phi anywhere else joins, which is exact.
pub fn solve_value_ranges(
    graph: &SsaGraph,
    function: &crate::SSAFunction,
    predicates: &crate::semantic::PredicateFacts,
    widen_at: &BTreeSet<u64>,
) -> ValueRanges {
    let mut by_value = ascend(graph, widen_at);
    narrow_where_defined(graph, function, predicates, &mut by_value);
    ValueRanges { by_value }
}

/// The ascending half: raise every value until nothing moves.
fn ascend(graph: &SsaGraph, widen_at: &BTreeSet<u64>) -> Vec<StridedInterval> {
    // A literal is what it says. A value some instruction defines starts at
    // bottom, since the transfer raises it to what the instruction can
    // produce. A value nothing in the function defines -- an argument, a
    // live-in register -- is never raised by anything, so bottom would be a
    // claim that it has no values at all; it starts at top, which is the
    // truth about it.
    let mut by_value = graph
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

    let widen_insts = graph
        .insts
        .iter()
        .filter(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
        .filter(|inst| {
            graph
                .op_site_for_inst(inst.id)
                .map(|(block_addr, _)| block_addr)
                .or_else(|| block_addr(graph, inst))
                .is_some_and(|addr| widen_at.contains(&addr))
        })
        .map(|inst| inst.id)
        .collect::<BTreeSet<_>>();

    let mut queued = graph
        .insts
        .iter()
        .map(|inst| inst.id)
        .collect::<BTreeSet<_>>();
    let mut ready = queued.iter().copied().collect::<VecDeque<_>>();
    while let Some(inst_id) = ready.pop_front() {
        queued.remove(&inst_id);
        let Some(inst) = graph.inst(inst_id) else {
            continue;
        };
        let Some(output) = inst.output else {
            continue;
        };
        let Some(slot) = by_value.get(output.0 as usize).copied() else {
            continue;
        };
        let computed = transfer(graph, inst, &|value: ValueId| {
            by_value
                .get(value.0 as usize)
                .copied()
                .unwrap_or_else(|| StridedInterval::top(64))
        });
        let next = match widen_insts.contains(&inst_id) {
            true => slot.widen(&slot.join(&computed)),
            false => slot.join(&computed),
        };
        if next == slot {
            continue;
        }
        by_value[output.0 as usize] = next;
        for site in graph.use_sites(output) {
            if queued.insert(site.inst) {
                ready.push_back(site.inst);
            }
        }
    }

    by_value
}

/// The block a phi belongs to, which its operation site does not name.
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
        inst.inputs
            .get(index)
            .map(|value| lookup(*value))
            .unwrap_or_else(|| StridedInterval::top(width))
    };
    let at_width = |range: StridedInterval| -> StridedInterval {
        match range.width_bits() == width {
            true => range,
            // A value read at a different width keeps its bounds where they
            // fit and is otherwise unknown; the narrowing itself is the
            // `Subpiece` and `IntZExt` cases below.
            false => match range.bounds() {
                Some((low, high)) if high <= mask_of(width) => {
                    StridedInterval::strided(width, range.stride().unwrap_or(1), low, high)
                }
                _ => StridedInterval::top(width),
            },
        }
    };

    let InstPayload::Op(op) = &inst.payload else {
        // A merge is the join of what reaches it, which is the whole reason
        // this is a fixpoint and not a walk.
        return inst
            .inputs
            .iter()
            .map(|value| lookup(*value))
            .map(at_width)
            .reduce(|left, right| left.join(&right))
            .unwrap_or_else(|| StridedInterval::bottom(width));
    };

    match op {
        SSAOp::Copy { .. } | SSAOp::CallRestore { .. } => at_width(input(0)),
        SSAOp::IntAdd { .. } => at_width(input(0)).add(&at_width(input(1))),
        SSAOp::IntSub { .. } => at_width(input(0)).sub(&at_width(input(1))),
        SSAOp::IntMult { .. } => at_width(input(0)).mul(&at_width(input(1))),
        SSAOp::IntLeft { .. } => match input(1).as_constant() {
            Some(places) => at_width(input(0)).shl(places as u32),
            None => StridedInterval::top(width),
        },
        SSAOp::IntRight { .. } => match input(1).as_constant() {
            Some(places) => at_width(input(0)).shr(places as u32),
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
        SSAOp::IntZExt { .. } | SSAOp::Subpiece { .. } => at_width(input(0)),
        // A selection is one arm or the other, and its condition says which.
        //
        // `csel x16, x16, xzr, ls` after `cmp x16, 0x5b` is how a compiler
        // clamps a switch index, and without reading the condition the arm it
        // keeps stays unbounded -- which made a jump table run to the end of
        // the address space rather than over its cases.
        SSAOp::Select(_) => {
            let arm = |index: usize, truth: bool| match (
                inst.inputs
                    .first()
                    .and_then(|condition| comparison_of(graph, *condition)),
                inst.inputs.get(index).copied(),
            ) {
                (Some(compare), Some(value)) => narrow(
                    &|value| Some(lookup(value)),
                    at_width(input(index)),
                    &compare,
                    truth,
                    value,
                ),
                _ => at_width(input(index)),
            };
            arm(1, true).join(&arm(2, false))
        }
        // A comparison is nought or one, whatever it compares.
        SSAOp::IntEqual { .. }
        | SSAOp::IntNotEqual { .. }
        | SSAOp::IntLess { .. }
        | SSAOp::IntSLess { .. }
        | SSAOp::IntLessEqual { .. }
        | SSAOp::IntSLessEqual { .. }
        | SSAOp::IntCarry { .. }
        | SSAOp::IntSCarry { .. }
        | SSAOp::IntSBorrow { .. }
        | SSAOp::BoolAnd { .. }
        | SSAOp::BoolOr { .. }
        | SSAOp::BoolXor { .. }
        | SSAOp::BoolNot { .. } => StridedInterval::interval(width, 0, 1),
        _ => StridedInterval::top(width),
    }
}

const fn mask_of(width_bits: u32) -> u64 {
    match width_bits >= 64 {
        true => u64::MAX,
        false => (1u64 << width_bits) - 1,
    }
}

/// What each block's branches prove about the values they compare.
///
/// Walked down the dominator tree so a block starts from everything its
/// dominators proved and adds its own, which is the same set a walk up the
/// chain from each instruction would gather, gathered once.
fn assumptions_by_block(
    function: &crate::SSAFunction,
    predicates: &crate::semantic::PredicateFacts,
    state: &[StridedInterval],
) -> BTreeMap<u64, BTreeMap<ValueId, StridedInterval>> {
    if predicates.block_assumptions.is_empty() {
        return BTreeMap::new();
    }
    let domtree = function.domtree();
    let mut by_block = BTreeMap::<u64, BTreeMap<ValueId, StridedInterval>>::new();
    let mut ready = vec![domtree.entry];
    while let Some(addr) = ready.pop() {
        let mut held = domtree
            .idom(addr)
            .and_then(|idom| by_block.get(&idom))
            .cloned()
            .unwrap_or_default();
        for assumption in predicates
            .block_assumptions
            .get(&addr)
            .into_iter()
            .flatten()
        {
            let Some(fact) = predicates.predicates.get(&assumption.predicate) else {
                continue;
            };
            let Some(compare) = fact
                .comparison
                .as_ref()
                .or(fact.evaluated_comparison.as_ref())
            else {
                continue;
            };
            for side in [compare.lhs, compare.rhs] {
                let Some(was) = held
                    .get(&side)
                    .copied()
                    .or_else(|| state.get(side.0 as usize).copied())
                else {
                    continue;
                };
                let now = narrow(
                    &|value| {
                        held.get(&value)
                            .copied()
                            .or_else(|| state.get(value.0 as usize).copied())
                    },
                    was,
                    compare,
                    assumption.truth,
                    side,
                );
                if now != was {
                    held.insert(side, now);
                }
            }
        }
        if !held.is_empty() {
            by_block.insert(addr, held);
        }
        ready.extend(domtree.children(addr).iter().copied());
    }
    by_block
}

/// One comparison's effect on one side of it.
///
/// A comparison that does not hold is the mirror of the one that does --
/// `!(a < b)` is `b <= a` -- so the false case is taken by turning the
/// comparison round rather than by four more arms saying the same thing.
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
    let Some(bound) = known(other).filter(|other| !other.is_bottom()) else {
        return range;
    };
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
    let above = |limit: Option<u64>| match limit {
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
    use crate::semantic::CompareKind;
    let inst = graph.inst(graph.def_inst(condition)?)?;
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    let kind = match op {
        SSAOp::IntEqual { .. } => CompareKind::Equal,
        SSAOp::IntNotEqual { .. } => CompareKind::NotEqual,
        SSAOp::IntLess { .. } => CompareKind::Less,
        SSAOp::IntLessEqual { .. } => CompareKind::LessEqual,
        SSAOp::IntSLess { .. } => CompareKind::SignedLess,
        SSAOp::IntSLessEqual { .. } => CompareKind::SignedLessEqual,
        _ => return None,
    };
    Some(crate::semantic::CompareProvenance {
        kind,
        lhs: *inst.inputs.first()?,
        rhs: *inst.inputs.get(1)?,
    })
}

/// Where an instruction stands.
fn block_addr(graph: &SsaGraph, inst: &GraphInst) -> Option<u64> {
    graph
        .blocks
        .get(inst.block.0 as usize)
        .map(|block| block.addr)
}

/// The descending half: each instruction re-read under what dominates it.
///
/// Widening is what makes the ascending half finish, and what it costs is the
/// bound: a counter raised one iteration at a time jumps to the extreme of
/// its width instead, so a loop that plainly runs eight times leaves its
/// counter describing every value there is. The condition that stops the loop
/// is the missing fact, and it is a fact about a block rather than about the
/// whole function -- which is why it is applied here, to the instructions the
/// block dominates, rather than folded into the ascent.
///
/// A value is narrowed where it is *defined*. Every execution that defines it
/// passes through that block, so what the block assumes holds of it
/// everywhere, and one range per value stays the whole answer -- no caller
/// has to say where it is asking from. A use further on under a weaker
/// assumption still reads a range the value really has.
///
/// The carry forward stops at phis. Every cycle in an SSA graph passes
/// through one, so stopping there leaves a DAG, and a walk over a DAG
/// finishes without anything having to count its steps. Nothing true is lost:
/// a merge takes its value from several paths, and what held on one of them
/// is not a fact about the merge.
fn narrow_where_defined(
    graph: &SsaGraph,
    function: &crate::SSAFunction,
    predicates: &crate::semantic::PredicateFacts,
    state: &mut [StridedInterval],
) {
    let assumed = assumptions_by_block(function, predicates, state);
    if assumed.is_empty() {
        return;
    }
    // Only the instructions something is assumed about start on the list.
    // One under no assumption recomputes to exactly what the ascent already
    // gave it, and if an input of it narrows elsewhere the carry forward
    // brings it back.
    let mut queued = graph
        .blocks
        .iter()
        .filter(|block| assumed.contains_key(&block.addr))
        .flat_map(|block| block.insts.iter().copied())
        .filter(|inst| {
            graph
                .inst(*inst)
                .is_some_and(|inst| !matches!(inst.payload, InstPayload::Phi { .. }))
        })
        .collect::<BTreeSet<_>>();
    let mut ready = queued.iter().copied().collect::<VecDeque<_>>();
    while let Some(inst_id) = ready.pop_front() {
        queued.remove(&inst_id);
        let Some(inst) = graph.inst(inst_id) else {
            continue;
        };
        let Some(output) = inst.output else {
            continue;
        };
        let Some(was) = state.get(output.0 as usize).copied() else {
            continue;
        };
        let held = block_addr(graph, inst).and_then(|addr| assumed.get(&addr));
        let now = was.meet(&transfer(graph, inst, &|value: ValueId| {
            let range = state
                .get(value.0 as usize)
                .copied()
                .unwrap_or_else(|| StridedInterval::top(64));
            match held.and_then(|held| held.get(&value)) {
                Some(narrowed) => range.meet(narrowed),
                None => range,
            }
        }));
        if now == was {
            continue;
        }
        state[output.0 as usize] = now;
        for site in graph.use_sites(output) {
            let Some(user) = graph.inst(site.inst) else {
                continue;
            };
            if matches!(user.payload, InstPayload::Phi { .. }) {
                continue;
            }
            if queued.insert(site.inst) {
                ready.push_back(site.inst);
            }
        }
    }
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

    fn solve_over(blocks: &[SSABlock], cfg: CFG, widen_at: &[u64]) -> (ValueRanges, SsaGraph) {
        let function = SSAFunction::from_exact_test_blocks(blocks, cfg);
        let graph = SsaGraph::from_function(&function);
        let widen = widen_at.iter().copied().collect::<BTreeSet<_>>();
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let ranges = solve_value_ranges(&graph, &function, &predicates, &widen);
        (ranges, graph)
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
        block.ops.push(crate::op::SSAOp::IntAdd {
            dst: sum.clone(),
            a: constant(4, 4),
            b: constant(6, 4),
        });
        let cfg = straight_line(block.clone());
        let (ranges, graph) = solve_over(&[block], cfg, &[]);
        assert_eq!(range_of(&ranges, &graph, &sum).as_constant(), Some(10));
    }

    #[test]
    fn an_index_scaled_by_an_element_size_keeps_the_stride() {
        // What an array subscript is: a bounded index times the element size.
        let index = var("index", 1, 4);
        let offset = var("offset", 1, 4);
        let mut block = SSABlock::new(0x1000, 12);
        block.ops.push(crate::op::SSAOp::IntAnd {
            dst: index.clone(),
            a: var("raw", 0, 4),
            b: constant(7, 4),
        });
        block.ops.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: index.clone(),
            b: constant(4, 4),
        });
        let cfg = straight_line(block.clone());
        let (ranges, graph) = solve_over(&[block], cfg, &[]);

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
        left_block.ops.push(crate::op::SSAOp::Copy {
            dst: taken.clone(),
            src: constant(3, 4),
        });
        let mut right_block = SSABlock::new(right, 16);
        right_block.ops.push(crate::op::SSAOp::Copy {
            dst: other.clone(),
            src: constant(7, 4),
        });
        let mut merge_block = SSABlock::new(merge, 16);
        merge_block.phis.push(PhiNode {
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
        let (ranges, graph) = solve_over(&blocks, cfg, &[]);
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
        header_block.phis.push(PhiNode {
            dst: counter.clone(),
            sources: vec![(entry, constant(0, 4)), (header, stepped.clone())],
            canonical_storage: None,
        });
        header_block.ops.push(crate::op::SSAOp::IntAdd {
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
        let (ranges, graph) = solve_over(&blocks, cfg, &[header]);
        let range = range_of(&ranges, &graph, &counter);
        assert!(range.contains(0), "the counter starts at nought: {range:?}");
        assert!(range.contains(1), "and is stepped: {range:?}");
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
        header_block.phis.push(PhiNode {
            dst: counter.clone(),
            sources: vec![(entry, constant(0, 4)), (latch, stepped.clone())],
            canonical_storage: None,
        });
        header_block.ops.push(crate::op::SSAOp::IntLess {
            dst: guard.clone(),
            a: counter.clone(),
            b: constant(8, 4),
        });
        header_block.ops.push(crate::op::SSAOp::CBranch {
            target: constant(body, 8),
            cond: guard,
        });
        let mut body_block = SSABlock::new(body, 16);
        body_block.ops.push(crate::op::SSAOp::IntMult {
            dst: offset.clone(),
            a: counter.clone(),
            b: constant(4, 4),
        });
        let mut latch_block = SSABlock::new(latch, 16);
        latch_block.ops.push(crate::op::SSAOp::IntAdd {
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
        let (ranges, graph) = solve_over(&blocks, cfg, &[header]);
        let scaled = range_of(&ranges, &graph, &offset);
        assert_eq!(scaled.bounds(), Some((0, 28)), "{scaled:?}");
        assert_eq!(scaled.stride(), Some(4), "{scaled:?}");
    }
}
