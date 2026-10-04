//! Where control goes after one instruction, read from what it lifts to.
//!
//! A listing colours a call apart from a jump, and a return apart from both.
//! That distinction is the instruction's semantics, so it is read from the
//! P-code the instruction lifts to, never from how its mnemonic is spelled:
//! `bl`, `call` and `jal` are one thing because each lifts to a `Call`.

use r2il::{R2ILBlock, R2ILOp};

/// What one instruction does with control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flow {
    /// Nothing: the instruction lifts to no operation at all.
    Nop,
    /// Control goes on to the next instruction and nowhere else.
    Fall,
    /// An unconditional transfer: direct or through a register.
    Jump,
    /// A transfer taken only when a condition holds.
    ConditionalJump,
    /// The instruction stops the machine or names no semantics to run.
    Trap,
    /// A call.
    Call,
    /// A return.
    Return,
}

/// The flow of one instruction's lift.
///
/// Where an instruction does several things the most significant wins, in
/// the order of [`Flow`]: a conditional return is a return, and a call that
/// first tests something is a call. A branch whose target is a constant is a
/// jump between this instruction's own P-code operations (a `rep` prefix's
/// loop) and leaves the instruction nowhere.
pub fn of(block: &R2ILBlock) -> Flow {
    if block.ops.is_empty() {
        return Flow::Nop;
    }
    block
        .ops
        .iter()
        .filter_map(|op| match op {
            R2ILOp::Return { .. } => Some(Flow::Return),
            R2ILOp::Call { .. } | R2ILOp::CallInd { .. } => Some(Flow::Call),
            R2ILOp::Unimplemented | R2ILOp::Breakpoint => Some(Flow::Trap),
            R2ILOp::CBranch { target, .. } if !target.is_const() => Some(Flow::ConditionalJump),
            R2ILOp::Branch { target } if !target.is_const() => Some(Flow::Jump),
            R2ILOp::BranchInd { .. } => Some(Flow::Jump),
            _ => None,
        })
        .max()
        .unwrap_or(Flow::Fall)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::Varnode;

    fn block(ops: Vec<R2ILOp>) -> R2ILBlock {
        let mut block = R2ILBlock::new(0x1000, 4);
        for op in ops {
            block.push(op);
        }
        block
    }

    #[test]
    fn the_most_significant_transfer_names_the_instruction() {
        let address = Varnode::constant(0x2000, 8);
        let ram = Varnode::new(r2il::SpaceId::Ram, 0x2000, 8);
        let flag = Varnode::register(0x200, 1);
        assert_eq!(of(&block(Vec::new())), Flow::Nop);
        assert_eq!(
            of(&block(vec![R2ILOp::Copy {
                dst: Varnode::register(0, 8),
                src: address,
            }])),
            Flow::Fall
        );
        assert_eq!(
            of(&block(vec![R2ILOp::Branch {
                target: ram.clone()
            }])),
            Flow::Jump
        );
        assert_eq!(
            of(&block(vec![R2ILOp::CBranch {
                target: ram.clone(),
                cond: flag.clone(),
            }])),
            Flow::ConditionalJump
        );
        assert_eq!(of(&block(vec![R2ILOp::Call { target: ram }])), Flow::Call);
        // A conditional return: the condition skips the return.
        assert_eq!(
            of(&block(vec![
                R2ILOp::CBranch {
                    target: Varnode::constant(2, 8),
                    cond: flag,
                },
                R2ILOp::Return {
                    target: Varnode::register(8, 8),
                },
            ])),
            Flow::Return
        );
        // A branch between the instruction's own operations goes nowhere.
        assert_eq!(
            of(&block(vec![R2ILOp::Branch {
                target: Varnode::constant(0, 8),
            }])),
            Flow::Fall
        );
    }
}
