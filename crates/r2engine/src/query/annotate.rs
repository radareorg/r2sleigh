//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::ValueUse;
use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};
use r2ssa::{CanonicalStorageId, CanonicalStorageSpace, InstPayload, SsaGraph, ValueId};
use std::collections::BTreeSet;

use super::Support;
use super::Work;
use super::decode::Lookahead;
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
    beyond: &mut Lookahead<'_, '_>,
    lines: &mut [Line],
) {
    if work == Work::Decode {
        return;
    }
    let memory = &answered.memory;
    // One convention per run: ARM and Thumb decode apart but call alike.
    let clobbered = lines
        .first()
        .and_then(|line| answered.decoders.at(line.address))
        .map(|machine| r2ssa::call_clobbered_storages(&machine.arch))
        .unwrap_or_default();
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
            let mut after = After {
                rest: &lifts[index + 1..],
                beyond: &mut *beyond,
                clobbered: &clobbered,
                graph,
            };
            kinds.extend(computed_by(lift, &mut after, line.address));
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

/// What can be known of the program after one instruction.
struct After<'a, 'r, 'b> {
    /// The lifts of the lines that follow it in the run.
    rest: &'a [Option<r2il::R2ILBlock>],
    /// The instructions past the run, read as far as a question needs them.
    beyond: &'a mut Lookahead<'r, 'b>,
    /// The registers the convention says a call leaves undefined.
    clobbered: &'a [CanonicalStorageId],
    /// The function's def-use, where the request paid for it.
    graph: Option<&'a SsaGraph>,
}

/// The number this instruction produces, where nothing derives another from it.
///
/// A value a later instruction builds a number on is a step towards an address
/// rather than one: spelling `adrp x17, reloc.humanize_number` named the page
/// base the `add` after it was about to move fifty bytes past. Copying, storing,
/// comparing, loading through or passing the number is using it as it stands.
fn computed_by(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    address: u64,
) -> Option<AnnotationKind> {
    let mut origins = BlockOrigins::default();
    for op in &lift.ops {
        origins.step(op);
    }
    let output = lift.ops.iter().rev().find_map(r2il::R2ILOp::output)?;
    let value = origins.of(output)?.constant()?;
    let fate = match straight_line_fate(lift, after, output) {
        Fate::Unknown => after
            .graph
            .map_or(Fate::Unknown, |graph| defined_fate(graph, address, output)),
        settled => settled,
    };
    (fate == Fate::Result).then_some(AnnotationKind::Computes { value })
}

/// Whether a number an instruction leaves is a step, and who can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Something derives another number from it.
    Step,
    /// Every copy of it is gone before anything derives from it.
    Result,
    /// The evidence at hand does not reach far enough to say.
    Unknown,
}

/// Whether a storage is a temporary one instruction's operations share.
fn scratch(space: SpaceId) -> bool {
    space == SpaceId::Unique
}

/// What the run after an instruction says, as far as it is one straight line.
///
/// The number is followed through every storage a copy puts it in; a number
/// derived from it is followed only through temporaries, because a flag is
/// computed that way and a flag is a test rather than a step.
fn straight_line_fate(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    output: &Varnode,
) -> Fate {
    // Past a branch the run is no longer every path the value takes, so it settles nothing.
    if lift.ops.iter().any(R2ILOp::is_control_flow) {
        return Fate::Unknown;
    }
    let mut holders = vec![output.clone()];
    // A callee may have left a register as it found it, so a read after a call proves no step.
    let mut called = false;
    let listed = after.rest.len();
    for index in 0.. {
        let block = match after.rest.get(index) {
            Some(block) => block.as_ref(),
            None => after.beyond.at(index - listed).flatten(),
        };
        let Some(block) = block else {
            return Fate::Unknown;
        };
        let mut derived: Vec<Varnode> = Vec::new();
        for op in &block.ops {
            match op_fate(op, &mut holders, &mut derived, after.clobbered) {
                Some(Fate::Step) if called => return Fate::Unknown,
                Some(fate) => return fate,
                None => {}
            }
            called |= matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. });
            if holders.is_empty() && derived.is_empty() {
                return Fate::Result;
            }
        }
        holders.retain(|held| !scratch(held.space));
        if holders.is_empty() {
            return Fate::Result;
        }
    }
    Fate::Unknown
}

/// What one operation does to the storages holding the number, where it decides.
fn op_fate(
    op: &R2ILOp,
    holders: &mut Vec<Varnode>,
    derived: &mut Vec<Varnode>,
    clobbered: &[CanonicalStorageId],
) -> Option<Fate> {
    let inputs = op.inputs();
    let reads = |set: &[Varnode]| {
        inputs
            .iter()
            .any(|input| set.iter().any(|held| overlaps(held, input)))
    };
    let (held, built) = (reads(holders), reads(derived));
    match op {
        R2ILOp::Call { .. } | R2ILOp::CallInd { .. } => {
            holders.retain(|held| {
                !clobbered
                    .iter()
                    .any(|storage| covers(&storage_varnode(*storage), held))
            });
            return built.then_some(Fate::Step);
        }
        _ if op.is_control_flow() => return Some(Fate::Unknown),
        _ => {}
    }
    let carried = match op.value_use() {
        ValueUse::Derives if held || built => Some(true),
        ValueUse::Carries if built => Some(true),
        ValueUse::Carries if held => Some(false),
        ValueUse::Consumes if built => return Some(Fate::Step),
        _ => None,
    };
    let written = op.output()?;
    holders.retain(|held| !covers(written, held));
    derived.retain(|held| !covers(written, held));
    match carried {
        Some(true) if !scratch(written.space) => return Some(Fate::Step),
        Some(true) => derived.push(written.clone()),
        Some(false) => holders.push(written.clone()),
        None => {}
    }
    None
}

/// Whether two storages share a byte.
fn overlaps(left: &Varnode, right: &Varnode) -> bool {
    left.space == right.space
        && left.offset < right.offset + u64::from(right.size)
        && right.offset < left.offset + u64::from(left.size)
}

/// Whether a write to `outer` replaces every byte of `inner`.
fn covers(outer: &Varnode, inner: &Varnode) -> bool {
    outer.space == inner.space
        && outer.offset <= inner.offset
        && inner.offset + u64::from(inner.size) <= outer.offset + u64::from(outer.size)
}

/// A register storage, as the lift spells it.
fn storage_varnode(storage: CanonicalStorageId) -> Varnode {
    Varnode::new(SpaceId::Register, storage.offset, storage.size)
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
        Some(defined) if derived_from(graph, defined) => Fate::Step,
        Some(_) => Fate::Result,
        None => Fate::Unknown,
    }
}

/// Whether an operation builds a number on this value, through the copies and merges it flows into.
fn derived_from(graph: &SsaGraph, defined: ValueId) -> bool {
    let mut seen = BTreeSet::from([(defined, false)]);
    let mut pending = vec![(defined, false)];
    while let Some((value, built)) = pending.pop() {
        let users = graph
            .use_sites(value)
            .iter()
            .filter_map(|site| graph.inst(site.inst));
        for user in users {
            let carried = match &user.payload {
                InstPayload::Phi { .. } => built,
                InstPayload::Op(op) => match op.value_use() {
                    ValueUse::Carries => built,
                    ValueUse::Derives => true,
                    ValueUse::Consumes if built => return true,
                    ValueUse::Consumes | ValueUse::Tests => continue,
                },
            };
            let Some(next) = user.output else {
                continue;
            };
            let temporary = graph
                .value(next)
                .and_then(|value| value.canonical_storage)
                .is_some_and(|storage| storage.space == CanonicalStorageSpace::Unique);
            if carried && !temporary {
                return true;
            }
            if seen.insert((next, carried)) {
                pending.push((next, carried));
            }
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
