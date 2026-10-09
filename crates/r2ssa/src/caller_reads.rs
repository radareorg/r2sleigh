//! What the code after one call reads of its callee's result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): the caller's own instructions, lifted, before any preparation.

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2source::{CanonicalStorageId, SourceResultReads};

/// The reads of the call at `index`: a read before any write of a result register is a read of
/// what the call left there; a write, a transfer or the block's end is not. A call its own
/// instruction may skip reads nothing, since what follows may see the value from before it.
pub fn reads_after_call(
    block: &R2ILBlock,
    index: usize,
    integer: Option<CanonicalStorageId>,
    float: Option<CanonicalStorageId>,
) -> SourceResultReads {
    let mut reads = SourceResultReads::default();
    if predicated(block, index) {
        return reads;
    }
    let (mut integer_open, mut float_open) = (integer, float);
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
            if integer_open.is_some_and(|slot| overlaps(input, slot)) {
                reads.integer = 1;
                integer_open = None;
            }
            if let Some(slot) = float_open.filter(|slot| overlaps(input, *slot)) {
                reads.float = 1;
                // A read wider than the result lane (a whole-register move) says nothing of the width.
                if input.size <= slot.size {
                    reads.float_bytes = input.size;
                }
                float_open = None;
            }
        }
        if let Some(output) = op.output() {
            if integer_open.is_some_and(|slot| overlaps(output, slot)) {
                integer_open = None;
            }
            if float_open.is_some_and(|slot| overlaps(output, slot)) {
                float_open = None;
            }
        }
        if integer_open.is_none() && float_open.is_none() {
            break;
        }
    }
    reads
}

/// Whether the call at `index` is one its own instruction may skip (an ARM32 conditional `bl`
/// lifts to a branch around it).
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
    use r2source::{CanonicalStorageId, CanonicalStorageSpace, SourceResultReads};

    use super::reads_after_call;

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
        let at = Some(r2il::OpMetadata {
            instruction_addr: Some(0x1000),
            ..r2il::OpMetadata::default()
        });
        let mut block = R2ILBlock::new(0x1000, 16);
        for op in ops {
            block.push_with_metadata(op, at.clone());
        }
        block
    }

    fn call() -> R2ILOp {
        R2ILOp::Call {
            target: Varnode::ram(0x2000, 8),
        }
    }

    /// `call f; mov [rsi], eax`: the caller reads EAX as the call left it.
    #[test]
    fn a_read_of_the_result_register_after_the_call_is_evidence() {
        let ops = vec![
            call(),
            R2ILOp::Store {
                space: r2il::SpaceId::Ram,
                addr: Varnode::register(0x30, 8),
                val: Varnode::register(0, 4),
            },
        ];
        assert_eq!(
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0)),
            SourceResultReads {
                integer: 1,
                float: 0,
                float_bytes: 0
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
        conditional.push_with_metadata(call(), at(0x1000));
        assert!(super::predicated(&conditional, 1));
        let mut plain = R2ILBlock::new(0x1000, 8);
        plain.push_with_metadata(
            R2ILOp::CBranch {
                target: Varnode::ram(0x1008, 4),
                cond: Varnode::register(0x100, 1),
            },
            at(0x0ffc),
        );
        plain.push_with_metadata(call(), at(0x1000));
        assert!(!super::predicated(&plain, 1));
    }

    /// `call f; xor eax, eax; ...`: the zeroing reads EAX only in form; it is a write.
    #[test]
    fn a_self_cancelling_write_is_no_read() {
        let ops = vec![
            call(),
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
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0)),
            SourceResultReads::default()
        );
    }

    /// `call f; xor eax, eax; movsd [rsi], xmm0`: EAX is written before any read, XMM0 is read as a double.
    #[test]
    fn a_write_before_any_read_is_no_evidence() {
        let ops = vec![
            call(),
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
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0)),
            SourceResultReads {
                integer: 0,
                float: 1,
                float_bytes: 8
            }
        );
    }
}
