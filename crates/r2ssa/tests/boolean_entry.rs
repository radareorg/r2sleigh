//! What the machine model may conclude about a value it was entered with.
//!
//! A condition flag read by a boolean operation looks like a boolean and is
//! one, and the temptation is to say so from the operation. Nothing available
//! here can tell that flag from any other one-byte register -- `AL` is a byte
//! and so is `CF` -- and the architecture record carries no flag among a
//! register's facts. So the model refuses, and the fact belongs in the
//! specification before the refusal can go.

#![cfg(feature = "sleigh-config")]

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2ssa::SsaArtifact;

#[test]
fn an_entry_value_is_not_a_boolean_for_being_one_byte_wide() {
    let carry = Varnode::register(0x20, 1);
    let other = Varnode::register(0x21, 1);
    let both = Varnode::register(0x22, 1);
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::BoolAnd {
        dst: both,
        a: carry,
        b: other,
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 4),
    });

    let artifact = SsaArtifact::raw(&[block], None).expect("the fixture builds");
    // Refused, and named: the operand that is not a boolean says which value
    // it is, so the refusal points at the thing to look at rather than at the
    // operation as a whole.
    assert!(r2ssa::MachineFunction::from_artifact(&artifact).is_err());
}
