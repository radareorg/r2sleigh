//! ARM's exclusive-access pair, lifted to the operations it performs.

#![cfg(all(feature = "arm", feature = "sleigh-config"))]

use r2il::R2ILOp;

/// `ldrex r2, [r1, 0]` then `adds r2, 1` then `strex r3, r2, [r1, 0]`, which
/// is what an atomic increment compiles to on ARM.
const EXCLUSIVE_INCREMENT: &[u8] = &[
    0x51, 0xe8, 0x00, 0x2f, // ldrex r2, [r1, 0]
    0x01, 0x32, // adds r2, 1
    0x41, 0xe8, 0x00, 0x23, // strex r3, r2, [r1, 0]
];

#[test]
fn an_exclusive_pair_lifts_to_a_linked_load_and_a_conditional_store() {
    // Sleigh writes each half as a user operation with no semantics beside
    // the ordinary load or store it guards, and the store is skipped by a
    // branch inside the instruction. Left alone the branch became
    // `Unimplemented` and the whole function refused.
    let machine = r2sleigh_lift::embedded_machine("thumb").expect("thumb machine");
    let ops = |at: u64, len: usize| {
        let mut bytes = EXCLUSIVE_INCREMENT[at as usize..].to_vec();
        bytes.resize(16, 0);
        let block = machine
            .disasm
            .lift(&bytes, 0x1000 + at)
            .expect("the instruction lifts");
        assert_eq!(block.size as usize, len, "{:?}", block.ops);
        block.ops
    };

    let linked = ops(0, 4);
    assert!(
        linked
            .iter()
            .any(|op| matches!(op, R2ILOp::LoadLinked { .. })),
        "{linked:?}"
    );
    assert!(
        !linked
            .iter()
            .any(|op| matches!(op, R2ILOp::CallOther { .. } | R2ILOp::Load { .. })),
        "the marking and the load are one operation: {linked:?}"
    );

    let conditional = ops(6, 4);
    assert!(
        conditional
            .iter()
            .any(|op| matches!(op, R2ILOp::StoreConditional { .. })),
        "{conditional:?}"
    );
    assert!(
        !conditional
            .iter()
            .any(|op| matches!(op, R2ILOp::Unimplemented | R2ILOp::Store { .. })),
        "the store happens only where the monitor held: {conditional:?}"
    );
}
