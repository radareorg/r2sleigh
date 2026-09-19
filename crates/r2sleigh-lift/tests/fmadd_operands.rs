//! The arm64 fused multiply-add computes `Ra + Rn * Rm` at every width. The
//! Ghidra 11.4 specification wrote the 32-bit form as `Rn + Rm * Ra`; the
//! specification crate is patched to Ghidra master's text.
#![cfg(feature = "arm")]

use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

fn float_ops(bytes: [u8; 4]) -> Vec<String> {
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
        .filter(|text| text.starts_with("Float"))
        .map(|text| {
            text.replace("Varnode { space: Register, offset: ", "r")
                .replace("Varnode { space: Unique, offset: ", "u")
                .replace(", meta: None }", "")
        })
        .collect()
}

#[test]
fn fmadd_multiplies_rn_by_rm_and_adds_ra_at_every_width() {
    // fmadd s0, s0, s2, s1 and fmadd d0, d0, d3, d1
    for (bytes, width) in [([0x00, 0x04, 0x02, 0x1f], 4), ([0x00, 0x04, 0x43, 0x1f], 8)] {
        let ops = float_ops(bytes);
        let (rn, rm, ra) = if width == 4 {
            (20480, 20544, 20512)
        } else {
            (20480, 20576, 20512)
        };
        assert!(
            ops[0].contains(&format!("a: r{rm}, size: {width}"))
                && ops[0].contains(&format!("b: r{rn}, size: {width}")),
            "{ops:?}"
        );
        assert!(
            ops[1].contains(&format!("a: r{ra}, size: {width}")),
            "{ops:?}"
        );
    }
}
