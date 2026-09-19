//! `REV64` reverses the elements inside each 64-bit half of a vector. The
//! specification models it as the user operation `NEON_rev64`, which the lift
//! expands into extracts and pieces so nothing downstream meets a `CallOther`.
#![cfg(feature = "arm")]

use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

fn ops(bytes: [u8; 4]) -> Vec<String> {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted arm64 specification");
    let mut padded = bytes.to_vec();
    padded.resize(20, 0);
    let lifted = disassembler
        .lift_genuine_block(&padded, 0x1000, 4)
        .expect("lift");
    lifted
        .block()
        .ops
        .iter()
        .map(|op| format!("{op:?}"))
        .collect()
}

#[test]
fn rev64_expands_into_one_extract_per_element_and_pieces_them_back() {
    // rev64 v0.16b, v0.16b: sixteen byte elements, eight per half.
    let ops = ops([0x00, 0x08, 0x20, 0x4e]);
    assert!(!ops.iter().any(|op| op.starts_with("CallOther")), "{ops:?}");
    assert_eq!(
        ops.iter().filter(|op| op.starts_with("Subpiece")).count(),
        16,
        "{ops:?}"
    );
    assert_eq!(
        ops.iter().filter(|op| op.starts_with("Piece")).count(),
        15,
        "{ops:?}"
    );
    // The first element of the result is the eighth of the source, and the
    // ninth is the sixteenth.
    assert!(
        ops[0].contains("offset: 7 }") || ops[0].contains("offset: 7,"),
        "{ops:?}"
    );
    assert!(
        ops[8].contains("offset: 15 }") || ops[8].contains("offset: 15,"),
        "{ops:?}"
    );
}

#[test]
fn rev64_on_a_64_bit_vector_of_words_swaps_the_two_words() {
    // rev64 v0.2s, v0.2s
    let ops = ops([0x00, 0x08, 0xa0, 0x0e]);
    assert!(!ops.iter().any(|op| op.starts_with("CallOther")), "{ops:?}");
    assert_eq!(
        ops.iter().filter(|op| op.starts_with("Subpiece")).count(),
        2,
        "{ops:?}"
    );
    assert_eq!(
        ops.iter().filter(|op| op.starts_with("Piece")).count(),
        1,
        "{ops:?}"
    );
}
