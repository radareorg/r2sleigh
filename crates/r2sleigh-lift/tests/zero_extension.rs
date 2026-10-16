//! In 64-bit mode a 32-bit destination zero-extends into its 64-bit register (Intel SDM Vol. 1,
//! 3.4.1.1; GP-7027, vendor/README.md), run through `r2il::eval` from registers with upper halves set.
#![cfg(feature = "x86")]

mod x86_machine;

use r2il::{R2ILOp, SpaceId};
use x86_machine::{HELD, Machine, low};

/// Every bit set, so a write that keeps the upper half shows.
const ONES: u128 = u64::MAX as u128;

#[test]
fn a_32_bit_destination_clears_the_register_above_it() {
    let machine = Machine::x86_64();
    // (instruction, bytes, the 64-bit register written, what it holds after). LODSD loads the
    // doubleword at [RSI] into EAX (SDM Vol. 2B, LODS), so RAX holds that doubleword alone.
    let forms: [(&str, &[u8], &str, u128); 8] = [
        ("lodsd", &[0xad], "RAX", low(4)),
        // GP-7027 writes MOVBE byte by byte; the doubleword at [RSI] reversed (SDM Vol. 2B, MOVBE).
        (
            "movbe eax, [rsi]",
            &[0x0f, 0x38, 0xf0, 0x06],
            "RAX",
            0x8888_7777,
        ),
        (
            "movbe rax, [rsi]",
            &[0x48, 0x0f, 0x38, 0xf0, 0x06],
            "RAX",
            0x8888_7777_6666_5555,
        ),
        (
            "pextrw eax, mm0, 1",
            &[0x0f, 0xc5, 0xc0, 0x01],
            "RAX",
            0x2222,
        ),
        // VEX 0F3A 15 /r writes ModRM r/m (SDM Vol. 2B, PEXTRW): ECX, with XMM0's word 1.
        (
            "vpextrw ecx, xmm0, 1",
            &[0xc4, 0xe3, 0x79, 0x15, 0xc1, 0x01],
            "RCX",
            0x4444,
        ),
        (
            "vmovd eax, xmm0",
            &[0xc5, 0xf9, 0x7e, 0xc0],
            "RAX",
            0x4444_5555,
        ),
        // The register keeps the cell's old value; the cell takes the sum.
        ("xadd [rsi], eax", &[0x0f, 0xc1, 0x06], "RAX", low(4)),
        // EDX:EAX differs from the cell, so it takes the cell's two halves.
        (
            "cmpxchg8b [rsi]",
            &[0x0f, 0xc7, 0x0e],
            "RDX",
            (HELD >> 32) & 0xffff_ffff,
        ),
    ];
    for (text, bytes, register, expected) in forms {
        let state = &machine.run(
            bytes,
            &[
                ("RAX", ONES),
                ("RDX", ONES),
                ("MM0", 0x4444_3333_2222_1111),
                ("XMM0", 0x4444_5555),
                ("RBX", 0),
                ("RCX", 0),
                ("DF", 0),
            ],
        );
        assert_eq!(machine.read(state, register), expected, "{text}");
    }
    let entry = [("RAX", ONES), ("RDX", ONES), ("RBX", 0), ("RCX", 0)];
    let state = &machine.run(&[0x0f, 0xc7, 0x0e], &entry);
    assert_eq!(machine.read(state, "RAX"), low(4), "cmpxchg8b [rsi]");
}

/// Where the operation is a user operation `eval` does not run, its result is still widened.
#[test]
fn a_32_bit_result_of_a_user_operation_is_zero_extended() {
    let machine = Machine::x86_64();
    for (text, bytes, register) in [
        ("movmskps eax, xmm0", &[0x0f, 0x50, 0xc0][..], "EAX"),
        ("rdrand ecx", &[0x0f, 0xc7, 0xf1], "ECX"),
        ("rdseed ecx", &[0x0f, 0xc7, 0xf9], "ECX"),
        (
            "pcmpestri xmm0, xmm1, 0",
            &[0x66, 0x0f, 0x3a, 0x61, 0xc1, 0x00],
            "ECX",
        ),
    ] {
        let (offset, size) = machine.register(register);
        let narrow = r2il::Varnode::new(SpaceId::Register, offset, size);
        let ops = machine.lift(bytes);
        let widened = ops.iter().any(|op| {
            matches!(op, R2ILOp::IntZExt { dst, src }
                if *src == narrow && dst.offset == offset && dst.size == 8)
        });
        assert!(widened, "{text}: {ops:?}");
        // No other register is widened: GP-7027's RDRAND widened the ModRM reg field's.
        let stray = ops.iter().any(|op| {
            matches!(op, R2ILOp::IntZExt { dst, src }
                if dst.space == SpaceId::Register && src.size == 4 && dst.offset != offset)
        });
        assert!(!stray, "{text}: {ops:?}");
    }
}
