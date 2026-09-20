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

use std::collections::{BTreeSet, VecDeque};

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
pub fn solve_value_ranges(graph: &SsaGraph, widen_at: &BTreeSet<u64>) -> ValueRanges {
    let mut by_value = graph
        .values
        .iter()
        .map(|value| match value.var.constant_bits() {
            Some(bits) => StridedInterval::constant(width_of(value.var.size), bits),
            None => StridedInterval::bottom(width_of(value.var.size)),
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
                .or_else(|| phi_block_addr(graph, inst))
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
        let computed = transfer(graph, inst, &by_value);
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

    ValueRanges { by_value }
}

/// The block a phi belongs to, which its operation site does not name.
fn phi_block_addr(graph: &SsaGraph, inst: &GraphInst) -> Option<u64> {
    graph
        .blocks
        .get(inst.block.0 as usize)
        .map(|block| block.addr)
}

const fn width_of(size_bytes: u32) -> u32 {
    match size_bytes {
        0 => 64,
        size => size.saturating_mul(8),
    }
}

/// What this instruction makes of what its inputs can be.
fn transfer(graph: &SsaGraph, inst: &GraphInst, states: &[StridedInterval]) -> StridedInterval {
    let width = inst
        .output
        .and_then(|value| graph.value(value))
        .map(|value| width_of(value.var.size))
        .unwrap_or(64);
    let input = |index: usize| -> StridedInterval {
        inst.inputs
            .get(index)
            .and_then(|value| states.get(value.0 as usize))
            .copied()
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
            .filter_map(|value| states.get(value.0 as usize).copied())
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
        // Zero extension keeps the value and changes only the width it is
        // read at, which the bounds already say.
        SSAOp::IntZExt { .. } | SSAOp::Subpiece { .. } => at_width(input(0)),
        // A selection is one arm or the other.
        SSAOp::Select(_) => at_width(input(1)).join(&at_width(input(2))),
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
        let ranges = solve_value_ranges(&graph, &widen);
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
            sources: vec![(left, taken.clone()), (right, other.clone())],
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
            dst: stepped.clone(),
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
}
