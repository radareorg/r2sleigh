//! What the code after one call reads of its callee's result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): the caller's own instructions, lifted, before any preparation.

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2source::{CanonicalStorageId, SourceFloatReadWidth, SourceResultReads};

/// The reads after the call at `index`: a result register's byte read before a write, a transfer or
/// the block's end; none where the call's own instruction may skip it. A register is overwritten
/// where writes cover every byte of it before any is read. The second integer register's read is
/// counted apart and closes nothing the others decide.
pub fn reads_after_call(
    block: &R2ILBlock,
    index: usize,
    integer: Option<CanonicalStorageId>,
    float: Option<CanonicalStorageId>,
    second: Option<CanonicalStorageId>,
) -> SourceResultReads {
    let mut reads = SourceResultReads {
        calls: 1,
        ..SourceResultReads::default()
    };
    if predicated(block, index) {
        return reads;
    }
    let (mut integer, mut float, mut second) = (
        integer.map(Lane::new),
        float.map(Lane::new),
        second.map(Lane::new),
    );
    for op in block.ops.iter().skip(index + 1) {
        if op.is_control_flow() {
            break;
        }
        // `xor eax, eax` lifts to `EAX = EAX ^ EAX`: its value is none of what the call left.
        let inputs = match op {
            R2ILOp::IntXor { a, b, .. } | R2ILOp::IntSub { a, b, .. } if a == b => Vec::new(),
            op => op.inputs(),
        };
        for input in &inputs {
            if second.as_ref().is_some_and(|lane| lane.reads(input)) {
                reads.second = 1;
                second = None;
            }
            if integer.as_ref().is_some_and(|lane| lane.reads(input)) {
                reads.integer = 1;
                integer = None;
            }
            if let Some(lane) = float.as_ref().filter(|lane| lane.reads(input)) {
                reads.float = 1;
                // A read wider than the result lane (a whole-register move) says nothing of the width.
                if input.size <= lane.slot.size {
                    reads.float_width = SourceFloatReadWidth::Bytes(input.size);
                }
                float = None;
            }
        }
        if let Some(output) = op.output() {
            if integer.as_mut().is_some_and(|lane| lane.write(output)) {
                reads.integer_overwritten = 1;
                integer = None;
            }
            if float.as_mut().is_some_and(|lane| lane.write(output)) {
                reads.float_overwritten = 1;
                float = None;
            }
            if second.as_mut().is_some_and(|lane| lane.write(output)) {
                second = None;
            }
        }
        if integer.is_none() && float.is_none() && second.is_none() {
            break;
        }
    }
    reads
}

/// The bytes of one result register that still hold what the call left there, one bit each.
struct Lane {
    slot: CanonicalStorageId,
    open: u128,
}

impl Lane {
    fn new(slot: CanonicalStorageId) -> Self {
        Self {
            slot,
            open: Self::span(0, u64::from(slot.size)),
        }
    }

    /// Bits `from..to`; a register past 128 bytes keeps its last bit open for the rest.
    fn span(from: u64, to: u64) -> u128 {
        let (from, to) = (from.min(127), to.min(128));
        (from..to).fold(0, |mask, byte| mask | 1 << byte)
    }

    /// The bytes of this register `varnode` touches.
    fn bytes(&self, varnode: &Varnode) -> u128 {
        let storage = CanonicalStorageId::from_varnode(varnode);
        if storage.space != self.slot.space {
            return 0;
        }
        let start = self.slot.offset;
        let end = start.saturating_add(u64::from(self.slot.size));
        let from = storage.offset.max(start);
        let to = (storage.offset.saturating_add(u64::from(storage.size))).min(end);
        match from < to {
            true => Self::span(from - start, to - start),
            false => 0,
        }
    }

    fn reads(&self, input: &Varnode) -> bool {
        self.bytes(input) & self.open != 0
    }

    /// Clear the bytes `output` writes; whether none is left.
    fn write(&mut self, output: &Varnode) -> bool {
        self.open &= !self.bytes(output);
        self.open == 0
    }
}

/// Whether the call at `index` is one its own instruction may skip (an ARM32 conditional `bl`
/// lifts to a branch around it).
fn predicated(block: &R2ILBlock, index: usize) -> bool {
    let instruction = |at: usize| block.instruction_of(at);
    let Some(call) = instruction(index) else {
        return true;
    };
    (0..index)
        .rev()
        .take_while(|at| instruction(*at) == Some(call))
        .any(|at| block.ops[at].is_control_flow())
}

#[cfg(test)]
mod tests {
    use r2il::{R2ILBlock, R2ILOp, Varnode};
    use r2source::{
        CanonicalStorageId, CanonicalStorageSpace, SourceFloatReadWidth, SourceResultReads,
    };

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
        let mut block = R2ILBlock::new(0x1000, 16);
        for op in ops {
            block.push_from(op, 0x1000);
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
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0), None),
            SourceResultReads {
                integer: 1,
                float: 0,
                float_width: SourceFloatReadWidth::Unstated,
                second: 0,
                integer_overwritten: 0,
                float_overwritten: 0,
                calls: 1,
                exhaustive: false,
            }
        );
    }

    /// ARM32's `blne f` lifts to a branch around the call within its own instruction: a read after
    /// it may see the value from before the call, so the site is no evidence. A plain `bl` is.
    #[test]
    fn a_call_its_own_instruction_may_skip_is_no_evidence() {
        let mut conditional = R2ILBlock::new(0x1000, 4);
        conditional.push_from(
            R2ILOp::CBranch {
                target: Varnode::ram(0x1004, 4),
                cond: Varnode::register(0x100, 1),
            },
            0x1000,
        );
        conditional.push_from(call(), 0x1000);
        assert!(super::predicated(&conditional, 1));
        let mut plain = R2ILBlock::new(0x1000, 8);
        plain.push_from(
            R2ILOp::CBranch {
                target: Varnode::ram(0x1008, 4),
                cond: Varnode::register(0x100, 1),
            },
            0x0ffc,
        );
        plain.push_from(call(), 0x1000);
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
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0), None),
            SourceResultReads {
                calls: 1,
                ..SourceResultReads::default()
            }
        );
    }

    /// x86-64's `xor eax, eax` lifts to `EAX = EAX ^ EAX; RAX = zext(EAX)`: the extension reads only
    /// bytes the xor wrote, then covers RAX, so the call's RAX is overwritten unread.
    #[test]
    fn a_write_extended_over_the_register_overwrites_it() {
        let ops = vec![
            call(),
            R2ILOp::IntXor {
                dst: Varnode::register(0, 4),
                a: Varnode::register(0, 4),
                b: Varnode::register(0, 4),
            },
            R2ILOp::IntZExt {
                dst: Varnode::register(0, 8),
                src: Varnode::register(0, 4),
            },
        ];
        let reads = reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0), None);
        assert_eq!(
            (
                reads.integer,
                reads.integer_overwritten,
                reads.float_overwritten
            ),
            (0, 1, 0)
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
            reads_after_call(&block(ops), 0, Some(RAX), Some(XMM0), None),
            SourceResultReads {
                integer: 0,
                float: 1,
                float_width: SourceFloatReadWidth::Bytes(8),
                second: 0,
                integer_overwritten: 0,
                float_overwritten: 0,
                calls: 1,
                exhaustive: false,
            }
        );
    }

    /// `call f; mov rax, 0; mov xmm0, 0`: each result register is written before any read, which
    /// proves it unread; writing only `al` leaves the rest of RAX to read later.
    #[test]
    fn writes_covering_every_result_register_prove_it_unread() {
        let write = |offset, size| R2ILOp::Copy {
            dst: Varnode::register(offset, size),
            src: Varnode::constant(0, size),
        };
        let counts = |reads: SourceResultReads| {
            (
                reads.integer,
                reads.float,
                reads.integer_overwritten,
                reads.float_overwritten,
            )
        };
        let covered = vec![call(), write(0, 8), write(0x1200, 8)];
        let reads = reads_after_call(&block(covered), 0, Some(RAX), Some(XMM0), None);
        assert_eq!(counts(reads), (0, 0, 1, 1));
        let partial = vec![call(), write(0, 1), write(0x1200, 8)];
        let reads = reads_after_call(&block(partial), 0, Some(RAX), Some(XMM0), None);
        assert_eq!(counts(reads), (0, 0, 0, 1));
    }
}
