//! Per-element expansions of the NEON user operations bzip2's vectorised
//! loops use: unsigned min and max, their across-vector forms, and the
//! single-register table lookup.
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

fn count(ops: &[String], prefix: &str) -> usize {
    ops.iter().filter(|op| op.starts_with(prefix)).count()
}

#[test]
fn umax_and_umin_pick_per_element_with_a_select() {
    // umax v2.4s, v2.4s, v24.4s and umin v3.4s, v3.4s, v24.4s
    for bytes in [[0x42, 0x64, 0xb8, 0x6e], [0x63, 0x6c, 0xb8, 0x6e]] {
        let ops = ops(bytes);
        assert!(!ops.iter().any(|op| op.starts_with("CallOther")), "{ops:?}");
        assert_eq!(count(&ops, "IntLess"), 4, "{ops:?}");
        assert_eq!(count(&ops, "Select"), 4, "{ops:?}");
        assert_eq!(count(&ops, "Piece"), 3, "{ops:?}");
    }
}

#[test]
fn umaxv_and_uminv_fold_the_lanes_to_one_element() {
    // umaxv s0, v0.4s and uminv s1, v1.4s
    for bytes in [[0x00, 0xa8, 0xb0, 0x6e], [0x21, 0xa8, 0xb1, 0x6e]] {
        let ops = ops(bytes);
        assert!(!ops.iter().any(|op| op.starts_with("CallOther")), "{ops:?}");
        assert_eq!(count(&ops, "Subpiece"), 4, "{ops:?}");
        assert_eq!(count(&ops, "IntLess"), 3, "{ops:?}");
        assert_eq!(count(&ops, "Select"), 3, "{ops:?}");
        assert_eq!(count(&ops, "Piece"), 0, "{ops:?}");
    }
}

#[test]
fn tbl_with_one_table_selects_each_byte_or_zero() {
    // tbl v26.16b, {v24.16b}, v8.16b
    let ops = ops([0x1a, 0x03, 0x08, 0x4e]);
    assert!(!ops.iter().any(|op| op.starts_with("CallOther")), "{ops:?}");
    assert_eq!(count(&ops, "IntRight"), 16, "{ops:?}");
    assert_eq!(count(&ops, "Select"), 16, "{ops:?}");
    assert_eq!(count(&ops, "Piece"), 15, "{ops:?}");
}
