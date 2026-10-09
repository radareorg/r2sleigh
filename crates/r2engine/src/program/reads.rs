//! What the program's calls to a function read of its result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): each caller discovery walked is lifted, never prepared, so no answer waits on the
//! function it is about.

use std::collections::BTreeMap;
use std::sync::Arc;

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2source::{CanonicalStorageId, SourceResultReads};

use super::requests::SurveyQuery;
use super::{ProgramInputs, Source, View};
use crate::query::db::{Db, Query};

/// The reads at every call to one function, by its entry; `None` where no call reads either register.
pub(super) struct ResultReads;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ResultReads {
    type Key = u64;
    type Value = Option<SourceResultReads>;
    const NAME: &'static str = "result-reads";

    /// Work: one lift per caller discovery found, each scanned to its call's block end.
    fn compute(db: &Db<ProgramInputs<S>>, &callee: &u64) -> Self::Value {
        let survey = db.get::<SurveyQuery>(&()).ok()?;
        let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        let mut reads = SourceResultReads::default();
        for &caller in survey.callers_of(callee) {
            let Some(Ok(thumb)) = survey.walked_in(caller) else {
                continue;
            };
            let target = walker.target(thumb);
            let Ok(slots) = crate::native::convention_slots(target) else {
                continue;
            };
            let Ok(body) = crate::body::lift_body(caller, target.disasm, &view, &BTreeMap::new())
            else {
                continue;
            };
            for block in &body.blocks {
                for (index, op) in block.lifted.ops.iter().enumerate() {
                    if !matches!(op, R2ILOp::Call { target } if target.offset == callee)
                        || predicated(&block.lifted, index)
                    {
                        continue;
                    }
                    let first = first_reads(
                        &block.lifted,
                        index,
                        slots.result_slot(),
                        slots.float_result_slot(),
                    );
                    count(&mut reads, first, slots.float_result_slot());
                }
            }
        }
        (reads.integer > 0 || reads.float > 0).then_some(reads)
    }
}

/// What the code after one call reads first of each result register.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FirstReads {
    integer: bool,
    /// The bytes of the float register the first read takes.
    float: Option<u32>,
}

fn count(reads: &mut SourceResultReads, first: FirstReads, float: Option<CanonicalStorageId>) {
    reads.integer += u32::from(first.integer);
    if let Some(bytes) = first.float {
        reads.float += 1;
        // A read wider than the result lane (a whole-register move) says nothing of the width.
        if float.is_some_and(|slot| bytes <= slot.size) {
            reads.float_bytes = reads.float_bytes.max(bytes);
        }
    }
}

/// The ops after the call at `index` up to the next transfer or the block's end: a read before any
/// write of a register is a read of what the call left there; a write, a transfer or the end is not.
fn first_reads(
    block: &R2ILBlock,
    index: usize,
    integer: Option<CanonicalStorageId>,
    float: Option<CanonicalStorageId>,
) -> FirstReads {
    let mut first = FirstReads::default();
    let (mut integer, mut float) = (integer, float);
    for op in block.ops.iter().skip(index + 1) {
        if op.is_control_flow() {
            break;
        }
        // `xor eax, eax` lifts to `EAX = EAX ^ EAX`: its value is none of what the call left.
        let inputs = match op {
            R2ILOp::IntXor { a, b, .. } | R2ILOp::IntSub { a, b, .. } if a == b => Vec::new(),
            op => op.inputs(),
        };
        for input in inputs {
            if integer.is_some_and(|slot| overlaps(input, slot)) {
                first.integer = true;
                integer = None;
            }
            if float.is_some_and(|slot| overlaps(input, slot)) {
                first.float = Some(input.size);
                float = None;
            }
        }
        if let Some(output) = op.output() {
            if integer.is_some_and(|slot| overlaps(output, slot)) {
                integer = None;
            }
            if float.is_some_and(|slot| overlaps(output, slot)) {
                float = None;
            }
        }
        if integer.is_none() && float.is_none() {
            break;
        }
    }
    first
}

/// Whether the call at `index` is one its own instruction may skip (an ARM32 conditional `bl`
/// lifts to a branch around it): what follows may then read the value from before the call.
fn predicated(block: &R2ILBlock, index: usize) -> bool {
    let instruction = |at: usize| block.op_metadata(at).and_then(|meta| meta.instruction_addr);
    let Some(call) = instruction(index) else {
        return true;
    };
    (0..index)
        .rev()
        .take_while(|at| instruction(*at) == Some(call))
        .any(|at| block.ops[at].is_control_flow())
}

fn overlaps(varnode: &Varnode, slot: CanonicalStorageId) -> bool {
    let storage = CanonicalStorageId::from_varnode(varnode);
    storage.space == slot.space
        && storage.offset < slot.offset.saturating_add(u64::from(slot.size))
        && slot.offset < storage.offset.saturating_add(u64::from(storage.size))
}

#[cfg(test)]
mod tests {
    use r2il::{R2ILBlock, R2ILOp, Varnode};
    use r2source::{CanonicalStorageId, CanonicalStorageSpace};

    use super::{FirstReads, first_reads};

    const RAX: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    const XMM0: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x1200,
        size: 8,
    };

    fn block(ops: Vec<R2ILOp>) -> R2ILBlock {
        let mut block = R2ILBlock::new(0x1000, 16);
        for op in ops {
            block.push(op);
        }
        block
    }

    /// `call f; mov [rsi], eax`: the caller reads EAX as the call left it.
    #[test]
    fn a_read_of_the_result_register_after_the_call_is_evidence() {
        let ops = vec![
            R2ILOp::Call {
                target: Varnode::ram(0x2000, 8),
            },
            R2ILOp::Store {
                space: r2il::SpaceId::Ram,
                addr: Varnode::register(0x30, 8),
                val: Varnode::register(0, 4),
            },
        ];
        assert_eq!(
            first_reads(&block(ops), 0, Some(RAX), Some(XMM0)),
            FirstReads {
                integer: true,
                float: None
            }
        );
    }

    /// ARM32's `blne f` lifts to a branch around the call within its own instruction: a read after
    /// it may see the value from before the call, so the site is no evidence. A plain `bl` is.
    #[test]
    fn a_call_its_own_instruction_may_skip_is_no_evidence() {
        let at = |instruction| {
            Some(r2il::OpMetadata {
                instruction_addr: Some(instruction),
                ..r2il::OpMetadata::default()
            })
        };
        let mut conditional = R2ILBlock::new(0x1000, 4);
        conditional.push_with_metadata(
            R2ILOp::CBranch {
                target: Varnode::ram(0x1004, 4),
                cond: Varnode::register(0x100, 1),
            },
            at(0x1000),
        );
        conditional.push_with_metadata(
            R2ILOp::Call {
                target: Varnode::ram(0x2000, 4),
            },
            at(0x1000),
        );
        assert!(super::predicated(&conditional, 1));
        let mut plain = R2ILBlock::new(0x1000, 8);
        plain.push_with_metadata(
            R2ILOp::CBranch {
                target: Varnode::ram(0x1008, 4),
                cond: Varnode::register(0x100, 1),
            },
            at(0x0ffc),
        );
        plain.push_with_metadata(
            R2ILOp::Call {
                target: Varnode::ram(0x2000, 4),
            },
            at(0x1000),
        );
        assert!(!super::predicated(&plain, 1));
    }

    /// `call f; xor eax, eax; ...`: the zeroing reads EAX only in form; it is a write.
    #[test]
    fn a_self_cancelling_write_is_no_read() {
        let ops = vec![
            R2ILOp::Call {
                target: Varnode::ram(0x2000, 8),
            },
            R2ILOp::IntXor {
                dst: Varnode::register(0, 4),
                a: Varnode::register(0, 4),
                b: Varnode::register(0, 4),
            },
            R2ILOp::Store {
                space: r2il::SpaceId::Ram,
                addr: Varnode::register(0x30, 8),
                val: Varnode::register(0, 4),
            },
        ];
        assert_eq!(
            first_reads(&block(ops), 0, Some(RAX), Some(XMM0)),
            FirstReads::default()
        );
    }

    /// `call f; xor eax, eax; movsd [rsi], xmm0`: EAX is written before any read, XMM0 is read as a double.
    #[test]
    fn a_write_before_any_read_is_no_evidence() {
        let ops = vec![
            R2ILOp::Call {
                target: Varnode::ram(0x2000, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::register(0, 4),
                src: Varnode::constant(0, 4),
            },
            R2ILOp::Store {
                space: r2il::SpaceId::Ram,
                addr: Varnode::register(0x30, 8),
                val: Varnode::register(0x1200, 8),
            },
        ];
        assert_eq!(
            first_reads(&block(ops), 0, Some(RAX), Some(XMM0)),
            FirstReads {
                integer: false,
                float: Some(8)
            }
        );
    }
}
