//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};

use super::Support;
use super::Work;
use super::records::{Annotation, AnnotationKind, Line, Memory};

/// Say what each line's own lift says, and what the run says about it.
///
/// Two passes, because they answer different questions. What an instruction
/// transfers to or reads is a fact about the instruction. Whether the number
/// it computes is an address or a step towards one is a fact about what the
/// next instruction does with it: `adrp x17, 0x100008000` computes a page
/// base, and only the `add` after it says the address is fifty bytes further
/// on.
pub(super) fn over_run(
    memory: &Memory<'_>,
    work: Work,
    lifts: &[Option<r2il::R2ILBlock>],
    lines: &mut [Line],
) {
    if work == Work::Decode {
        return;
    }
    for (index, line) in lines.iter_mut().enumerate() {
        let (Some(lift), Some(syntax)) = (lifts.get(index).and_then(Option::as_ref), &line.syntax)
        else {
            continue;
        };
        let mut kinds = touched_by(lift);
        if work >= Work::BlockLocal {
            kinds.extend(computed_by(lift, &lifts[index + 1..]));
        }
        // What a read finds there is a fact about this revision, so it is said
        // beside the read rather than folded into it.
        for index in 0..kinds.len() {
            let AnnotationKind::Reads { address, width } = kinds[index] else {
                continue;
            };
            let Some(value) = memory.word(address, width) else {
                continue;
            };
            kinds.push(AnnotationKind::Holds {
                address,
                width,
                value,
            });
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

/// How well supported a claim of this shape is.
fn support_for(kind: AnnotationKind) -> Support {
    match kind {
        // The instruction's own operands say it transfers there or reads it.
        AnnotationKind::Target { .. }
        | AnnotationKind::Reads { .. }
        | AnnotationKind::Writes { .. } => Support::Decoded,
        // Folded, either within the instruction or across the run.
        AnnotationKind::Computes { .. } | AnnotationKind::Holds { .. } => Support::Folded,
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

/// The number this instruction produces, where the run leaves it standing.
///
/// A value a later instruction reads back is a step towards an address rather
/// than one: spelling `adrp x17, reloc.humanize_number` named the page base
/// the `add` after it was about to move fifty bytes past.
fn computed_by(lift: &r2il::R2ILBlock, rest: &[Option<r2il::R2ILBlock>]) -> Option<AnnotationKind> {
    let mut origins = BlockOrigins::default();
    for op in &lift.ops {
        origins.step(op);
    }
    let output = lift.ops.iter().rev().find_map(r2il::R2ILOp::output)?;
    let value = origins.of(output)?.constant()?;
    let storage = (output.space, output.offset);
    let read_later = rest
        .iter()
        .flatten()
        .flat_map(|block| block.ops.iter())
        .any(|op| {
            op.inputs()
                .into_iter()
                .any(|input| (input.space, input.offset) == storage)
        });
    (!read_later).then_some(AnnotationKind::Computes { value })
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
