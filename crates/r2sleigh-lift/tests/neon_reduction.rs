//! `ADDV` to a B register writes the sum and zeroes the vector above it, as every scalar write to
//! a SIMD register does; the lift is run through `r2il::eval` to show the count read back is alone.
#![cfg(feature = "arm")]

use r2il::eval::{Flow, State, step};
use r2il::{Endianness, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// `fmov s0, w0; cnt v0.8b, v0.8b; addv b0, v0.8b; fmov w0, s0`: gcc's `__builtin_popcount`.
const POPCOUNT: [u8; 16] = [
    0x00, 0x00, 0x27, 0x1e, 0x00, 0x58, 0x20, 0x0e, 0x00, 0xb8, 0x31, 0x0e, 0x00, 0x00, 0x26, 0x1e,
];

fn register(disassembler: &Disassembler, name: &str) -> Varnode {
    let storage = disassembler
        .arch_spec()
        .get_register(name)
        .unwrap_or_else(|| panic!("AArch64 declares {name}"))
        .storage();
    Varnode::register(storage.offset, storage.size)
}

/// Ghidra 11.4 zeroed only the bytes above Q0, so S0 kept `cnt`'s counts of bytes 1 to 3 and
/// all ones counted 0x08080820.
#[test]
fn a_byte_reduction_zeroes_the_lanes_above_its_result() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted arm64 specification");
    let mut padded = POPCOUNT.to_vec();
    padded.resize(32, 0);
    let lifted = disassembler
        .lift_genuine_block(&padded, 0x1000, POPCOUNT.len())
        .expect("lift");
    let x0 = register(&disassembler, "x0");
    for (input, count) in [(0u32, 0u128), (1, 1), (0xf0f0, 8), (u32::MAX, 32)] {
        let mut state = State::new(Endianness::Little, |_| None, 4096).expect("machine");
        state
            .set_register(x0.offset, x0.size, u128::from(input))
            .expect("x0");
        for op in &lifted.block().ops {
            assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
        }
        assert_eq!(
            state.register(x0.offset, x0.size),
            Some(count),
            "{input:#x}"
        );
    }
}
