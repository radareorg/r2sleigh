//! A condition flag the function was entered with is the boolean p-code says.

#![cfg(feature = "sleigh-config")]

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2ssa::SsaArtifact;

#[test]
fn an_entry_flag_read_by_a_boolean_operation_is_one() {
    // `CY` enters with no producer to ask, and the machine model refused the
    // operation that reads it -- which is every function entered with a
    // condition flag live. What makes it a boolean is the operation itself:
    // the specification defines `BOOL_AND` over booleans and the translator
    // emits it over nothing else.
    let carry = Varnode::register(0x20, 1);
    let other = Varnode::register(0x21, 1);
    let both = Varnode::register(0x22, 1);
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::BoolAnd {
        dst: both.clone(),
        a: carry,
        b: other,
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 4),
    });

    let artifact = SsaArtifact::raw(&[block], None).expect("the fixture builds");
    let machine = r2ssa::MachineFunction::from_artifact(&artifact);
    assert!(machine.is_ok(), "{:?}", machine.err());
}
