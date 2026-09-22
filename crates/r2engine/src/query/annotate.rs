//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};

use super::Support;
use super::records::{Annotation, AnnotationKind, Memory};
use r2sleigh_lift::EmbeddedMachine;

/// What one instruction's own lift says about the addresses it touches.
///
/// Lifting is the whole point: a number in the operands is an address because
/// the instruction transfers to it or reads it, not because it looks like one.
/// The window is the decoder's, not the instruction's: Sleigh reads the whole
/// of it whatever the instruction needs, and handing it only the bytes the
/// instruction occupies fails the decode it just performed.
pub(super) fn instruction_local(
    machine: &EmbeddedMachine,
    memory: &Memory<'_>,
    window: &[u8],
    address: u64,
    syntax: &Syntax,
) -> Vec<Annotation> {
    let Ok(block) = machine.disasm.lift(window, address) else {
        return Vec::new();
    };
    let mut origins = BlockOrigins::default();
    let mut kinds: Vec<AnnotationKind> = Vec::new();
    for op in &block.ops {
        for kind in touched(&origins, op) {
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        origins.step(op);
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
    kinds
        .into_iter()
        .map(|kind| Annotation {
            kind,
            support: Support::Folded,
            operand: sole_operand(syntax, kind.address()),
        })
        .collect()
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
