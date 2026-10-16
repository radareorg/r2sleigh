//! CVTTSD2SI and CVTTSS2SI truncate toward zero, and a NaN or a value outside the destination's
//! range gives the integer indefinite, 80000000H or 80000000_00000000H (Intel SDM Vol. 2A).
#![cfg(feature = "x86")]

mod x86_machine;

use x86_machine::Machine;

const INDEFINITE32: u128 = 0x8000_0000;
const INDEFINITE64: u128 = 0x8000_0000_0000_0000;

fn converts(machine: &Machine, text: &str, bytes: &[u8], source: u128, expected: u128) {
    let state = &machine.run(bytes, &[("RAX", u128::from(u64::MAX)), ("XMM1", source)]);
    assert_eq!(
        machine.read(state, "RAX"),
        expected,
        "{text} of {source:#x}"
    );
}

#[test]
fn out_of_range_and_nan_give_the_integer_indefinite() {
    let machine = Machine::x86_64();
    let double = |value: f64| u128::from(value.to_bits());
    let single = |value: f32| u128::from(value.to_bits());
    // cvttsd2si eax, xmm1: a 32-bit result zero-extends into RAX
    for (value, expected) in [
        (2_147_483_647.75, 0x7fff_ffff),
        (-2_147_483_647.5, 0x8000_0001),
        (-1.5, 0xffff_ffff),
        (2_147_483_648.0, INDEFINITE32),
        (-2_147_483_649.0, INDEFINITE32),
        (f64::INFINITY, INDEFINITE32),
        (f64::NAN, INDEFINITE32),
    ] {
        converts(
            &machine,
            "cvttsd2si eax, xmm1",
            &[0xf2, 0x0f, 0x2c, 0xc1],
            double(value),
            expected,
        );
    }
    // cvttsd2si rax, xmm1
    for (value, expected) in [
        (9.2e18, 9_200_000_000_000_000_000),
        (-9_223_372_036_854_775_808.0, INDEFINITE64),
        (9_223_372_036_854_775_808.0, INDEFINITE64),
        (f64::NEG_INFINITY, INDEFINITE64),
        (f64::NAN, INDEFINITE64),
    ] {
        let bytes = [0xf2, 0x48, 0x0f, 0x2c, 0xc1];
        converts(
            &machine,
            "cvttsd2si rax, xmm1",
            &bytes,
            double(value),
            expected,
        );
    }
    // cvttss2si eax, xmm1: 2147483520 is the largest single below 2^31
    for (value, expected) in [
        (2_147_483_520.0, 0x7fff_ff80),
        (2_147_483_648.0, INDEFINITE32),
        (-2_147_483_904.0, INDEFINITE32),
        (f32::NAN, INDEFINITE32),
    ] {
        converts(
            &machine,
            "cvttss2si eax, xmm1",
            &[0xf3, 0x0f, 0x2c, 0xc1],
            single(value),
            expected,
        );
    }
    // vcvttss2si rax, xmm1
    for (value, expected) in [(-3.75, u128::from((-3i64) as u64)), (1e19, INDEFINITE64)] {
        let bytes = [0xc4, 0xe1, 0xfa, 0x2c, 0xc1];
        converts(
            &machine,
            "vcvttss2si rax, xmm1",
            &bytes,
            single(value),
            expected,
        );
    }
}
