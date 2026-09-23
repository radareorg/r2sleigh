//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};
use r2ssa::{CanonicalStorageId, InstPayload, SsaGraph, ValueId};
use std::collections::BTreeSet;

use super::Support;
use super::Work;
use super::records::{Annotation, AnnotationKind, Answered, Line, Memory};

/// Say what each line's own lift says, and what the run says about it.
///
/// Two passes, because they answer different questions. What an instruction
/// transfers to or reads is a fact about the instruction. Whether the number
/// it computes is an address or a step towards one is a fact about what the
/// next instruction does with it: `adrp x17, 0x100008000` computes a page
/// base, and only the `add` after it says the address is fifty bytes further
/// on.
pub(super) fn over_run(
    answered: &Answered<'_>,
    work: Work,
    lifts: &[Option<r2il::R2ILBlock>],
    lines: &mut [Line],
) {
    if work == Work::Decode {
        return;
    }
    let memory = &answered.memory;
    for (index, line) in lines.iter_mut().enumerate() {
        let (Some(lift), Some(syntax)) = (lifts.get(index).and_then(Option::as_ref), &line.syntax)
        else {
            continue;
        };
        let mut kinds = touched_by(lift);
        if work >= Work::BlockLocal {
            let graph = (work >= Work::Function)
                .then_some(answered.facts)
                .flatten()
                .map(r2ssa::SsaArtifact::graph);
            kinds.extend(computed_by(lift, &lifts[index + 1..], graph, line.address));
        }
        kinds.extend(held_at(memory, &kinds));
        if work >= Work::Function {
            kinds.extend(proved_about(answered.facts, line.address));
        }
        line.annotations = kinds
            .into_iter()
            .map(|kind| Annotation {
                support: support_for(kind),
                operand: sole_operand(syntax, kind.address()),
                kind,
            })
            .collect();
    }
}

/// What this revision holds wherever the instruction reads.
///
/// Said beside the read rather than folded into it: the bytes there are a fact
/// about this revision, and the load is a fact about the instruction.
fn held_at(memory: &Memory<'_>, kinds: &[AnnotationKind]) -> Vec<AnnotationKind> {
    kinds
        .iter()
        .filter_map(|kind| match kind {
            AnnotationKind::Reads { address, width } => Some(AnnotationKind::Holds {
                address: *address,
                width: *width,
                value: memory.word(*address, *width)?,
            }),
            _ => None,
        })
        .collect()
}

/// What the analysis proved about the values one instruction defines.
///
/// One range per value, and the range is the value's own: it is narrowed where
/// the value is defined, so it holds wherever the value is live rather than at
/// this instruction in particular.
fn proved_about(facts: Option<&r2ssa::SsaArtifact>, address: u64) -> Vec<AnnotationKind> {
    let Some(facts) = facts else {
        return Vec::new();
    };
    let graph = facts.graph();
    graph
        .insts_for_instruction(address)
        .iter()
        .filter_map(|inst| {
            let instruction = graph.inst(*inst)?;
            let value = instruction.output?;
            let range = facts.values().get(value)?;
            // A range that spans the storage proves nothing about it, and a
            // line that said `cf in [0x0, 0x1]` of a one-bit flag was saying
            // only that the flag is a flag.
            if range.is_top() {
                return None;
            }
            let (low, high) = range.bounds()?;
            Some(AnnotationKind::Bounds {
                storage: instruction.canonical_storage?,
                low,
                high,
                stride: range.stride().unwrap_or(0),
            })
        })
        .collect()
}

/// How well supported a claim of this shape is.
fn support_for(kind: AnnotationKind) -> Support {
    match kind {
        // The instruction's own operands say it transfers there or reads it.
        AnnotationKind::Target { .. }
        | AnnotationKind::Reads { .. }
        | AnnotationKind::Writes { .. } => Support::Decoded,
        // Folded, either within the instruction or across the run.
        AnnotationKind::Computes { .. } | AnnotationKind::Holds { .. } => Support::Folded,
        // An over-approximation an analysis over the function established.
        AnnotationKind::Bounds { .. } => Support::Solved,
    }
}

/// Every address one instruction's operations name.
fn touched_by(lift: &r2il::R2ILBlock) -> Vec<AnnotationKind> {
    let mut origins = BlockOrigins::default();
    let mut kinds: Vec<AnnotationKind> = Vec::new();
    for op in &lift.ops {
        for kind in touched(&origins, op) {
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        origins.step(op);
    }
    kinds
}

/// The number this instruction produces, where nothing reads it back.
///
/// A value a later instruction reads back is a step towards an address rather
/// than one: spelling `adrp x17, reloc.humanize_number` named the page base
/// the `add` after it was about to move fifty bytes past.
fn computed_by(
    lift: &r2il::R2ILBlock,
    rest: &[Option<r2il::R2ILBlock>],
    graph: Option<&SsaGraph>,
    address: u64,
) -> Option<AnnotationKind> {
    let mut origins = BlockOrigins::default();
    for op in &lift.ops {
        origins.step(op);
    }
    let output = lift.ops.iter().rev().find_map(r2il::R2ILOp::output)?;
    let value = origins.of(output)?.constant()?;
    let fate = match straight_line_fate(lift, rest, output) {
        Fate::Unknown => graph.map_or(Fate::Unknown, |graph| defined_fate(graph, address, output)),
        settled => settled,
    };
    (fate == Fate::Result).then_some(AnnotationKind::Computes { value })
}

/// Whether a number an instruction leaves is read back, and who can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Something reads a byte of it: a step towards what that reader computes.
    Step,
    /// Nothing reads it before all of it is overwritten or it leaves the function unread.
    Result,
    /// The evidence at hand does not reach far enough to say.
    Unknown,
}

/// What the run after an instruction says, as far as it is one straight line.
fn straight_line_fate(
    lift: &r2il::R2ILBlock,
    rest: &[Option<r2il::R2ILBlock>],
    output: &Varnode,
) -> Fate {
    // Comparing the starting offset alone missed `ah` read out of an `rax` just written.
    let covers = |varnode: &Varnode| {
        varnode.space == output.space
            && varnode.offset <= output.offset
            && output.offset + u64::from(output.size) <= varnode.offset + u64::from(varnode.size)
    };
    let overlaps = |varnode: &Varnode| {
        varnode.space == output.space
            && varnode.offset < output.offset + u64::from(output.size)
            && output.offset < varnode.offset + u64::from(varnode.size)
    };
    // Past a transfer the run is no longer every path the value takes, so it settles nothing.
    if lift.ops.iter().any(R2ILOp::is_control_flow) {
        return Fate::Unknown;
    }
    for block in rest {
        let Some(block) = block else {
            return Fate::Unknown;
        };
        for op in &block.ops {
            if op.inputs().into_iter().any(&overlaps) {
                return Fate::Step;
            }
            if op.is_control_flow() {
                return Fate::Unknown;
            }
            if op.output().is_some_and(&covers) {
                return Fate::Result;
            }
        }
    }
    Fate::Unknown
}

/// What the function's def-use says of the value this instruction leaves in `output`.
fn defined_fate(graph: &SsaGraph, address: u64, output: &Varnode) -> Fate {
    let storage = CanonicalStorageId::from_varnode(output);
    let defined = graph
        .insts_for_instruction(address)
        .iter()
        .rev()
        .filter_map(|inst| graph.inst(*inst))
        .find(|inst| inst.canonical_storage == Some(storage))
        .and_then(|inst| inst.output);
    match defined {
        Some(defined) if read_through_merges(graph, defined) => Fate::Step,
        Some(_) => Fate::Result,
        None => Fate::Unknown,
    }
}

/// Whether an operation reads this value, directly or through the merges it flows into.
fn read_through_merges(graph: &SsaGraph, defined: ValueId) -> bool {
    let mut seen = BTreeSet::from([defined]);
    let mut pending = vec![defined];
    while let Some(value) = pending.pop() {
        let users = graph
            .use_sites(value)
            .iter()
            .filter_map(|site| graph.inst(site.inst));
        for user in users {
            // A merge only passes the value on; any other operation reads it.
            let InstPayload::Phi { .. } = user.payload else {
                return true;
            };
            pending.extend(user.output.filter(|merged| seen.insert(*merged)));
        }
    }
    false
}

/// The addresses one operation names, as far as the block so far shows.
fn touched(origins: &BlockOrigins, op: &R2ILOp) -> Vec<AnnotationKind> {
    let folded = |addr: &Varnode| origins.of(addr).and_then(ValueOrigin::constant);
    let mut found = Vec::new();
    match op {
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => found.extend(
            encoded_target(target).map(|address| AnnotationKind::Target {
                address,
                call: false,
            }),
        ),
        R2ILOp::Call { target } => {
            found.extend(
                encoded_target(target).map(|address| AnnotationKind::Target {
                    address,
                    call: true,
                }),
            )
        }
        R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr,
        } => found.extend(folded(addr).map(|address| AnnotationKind::Reads {
            address,
            width: dst.size,
        })),
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val,
        } => found.extend(folded(addr).map(|address| AnnotationKind::Writes {
            address,
            width: val.size,
        })),
        _ => {}
    }
    found
}

/// The one number in the operands that spells this address, where there is one.
fn sole_operand(syntax: &Syntax, address: u64) -> Option<NumberSpan> {
    let mut spelling = syntax
        .numbers
        .iter()
        .filter(|number| number.value == i128::from(address));
    let found = spelling.next()?;
    spelling.next().is_none().then_some(*found)
}
