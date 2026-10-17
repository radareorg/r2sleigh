//! A body's def-use is built from where control enters, not from its lowest block.

use r2il::{R2ILBlock, R2ILOp, Varnode};
use r2ssa::{IntegrityRule, SsaPrepareError};

/// A one-block stub at 0x100 that a body entered at 0x200 jumps to (a PLT stub its walk absorbed).
fn body_below_its_entry() -> Vec<R2ILBlock> {
    let mut stub = R2ILBlock::new(0x100, 4);
    stub.push(R2ILOp::BranchInd {
        target: Varnode::register(0x10, 8),
    });
    let mut body = R2ILBlock::new(0x200, 4);
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x100, 8),
    });
    vec![stub, body]
}

#[test]
fn a_body_entered_above_its_lowest_block_builds() {
    let blocks = body_below_its_entry();
    assert!(r2ssa::def_use_graph(&blocks, None, 0x200).is_ok());
}

#[test]
fn a_refusal_names_the_invariant_the_graph_broke() {
    // Entered at the lowest block, the body's own block is cut off and its edge dangles.
    let blocks = body_below_its_entry();
    assert_eq!(
        r2ssa::def_use_graph(&blocks, None, 0x100).err(),
        Some(SsaPrepareError::Integrity(
            IntegrityRule::PredecessorOutsideBlockDomain
        ))
    );
}
