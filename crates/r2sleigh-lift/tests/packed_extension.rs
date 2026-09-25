//! x86 `PMOVSX*` and `PMOVZX*` compute what the Intel SDM states.
//!
//! Every SSE4.1 form, from a register and from memory, and the VEX.128 forms,
//! is lifted and run through `r2il::eval`, the engine's one statement of what
//! each operation computes. The destination is compared lane by lane with the
//! SDM's Operation clause over source bytes whose high bits are set, which is
//! what tells a sign extension from a zero extension, and the run is repeated
//! from two different old destinations: an instruction that defined its result
//! from anything but the source would not give the same answer twice. The
//! operand an instruction does not read holds other bytes, so one that read
//! the register for a memory form, or the reverse, computes something else;
//! and the register above the result is checked too, kept by a legacy SSE
//! write and zeroed by a VEX one.
#![cfg(feature = "x86")]

use r2il::eval::{Flow, State, step};
use r2il::{Endianness, R2ILBlock, R2ILOp};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// Where `[rdi]` points in each run.
const SOURCE_ADDRESS: u64 = 0x4000;

/// Sixteen source bytes; each element width reads some with the top bit set.
const SOURCE: [u8; 16] = [
    0x01, 0x80, 0x7f, 0xfe, 0x00, 0xff, 0x81, 0x7e, 0x55, 0xaa, 0x80, 0x00, 0x7f, 0xff, 0xc3, 0x3c,
];

/// Two old destinations with nothing in common.
const OLD_DESTINATIONS: [u128; 2] = [0, u128::MAX];

#[derive(Clone, Copy)]
struct Extension {
    opcode: u8,
    from: usize,
    to: usize,
    signed: bool,
}

const EXTENSIONS: [Extension; 12] = [
    Extension {
        opcode: 0x20,
        from: 1,
        to: 2,
        signed: true,
    },
    Extension {
        opcode: 0x21,
        from: 1,
        to: 4,
        signed: true,
    },
    Extension {
        opcode: 0x22,
        from: 1,
        to: 8,
        signed: true,
    },
    Extension {
        opcode: 0x23,
        from: 2,
        to: 4,
        signed: true,
    },
    Extension {
        opcode: 0x24,
        from: 2,
        to: 8,
        signed: true,
    },
    Extension {
        opcode: 0x25,
        from: 4,
        to: 8,
        signed: true,
    },
    Extension {
        opcode: 0x30,
        from: 1,
        to: 2,
        signed: false,
    },
    Extension {
        opcode: 0x31,
        from: 1,
        to: 4,
        signed: false,
    },
    Extension {
        opcode: 0x32,
        from: 1,
        to: 8,
        signed: false,
    },
    Extension {
        opcode: 0x33,
        from: 2,
        to: 4,
        signed: false,
    },
    Extension {
        opcode: 0x34,
        from: 2,
        to: 8,
        signed: false,
    },
    Extension {
        opcode: 0x35,
        from: 4,
        to: 8,
        signed: false,
    },
];

/// The SDM result: each destination element is the matching source element,
/// extended.
fn expected(extension: Extension) -> u128 {
    let lanes = 16 / extension.to;
    let mut result = 0u128;
    for lane in 0..lanes {
        let at = lane * extension.from;
        let element = SOURCE[at..at + extension.from]
            .iter()
            .rev()
            .fold(0u128, |value, byte| (value << 8) | u128::from(*byte));
        let from_bits = 8 * extension.from as u32;
        let to_bits = 8 * extension.to as u32;
        let negative = element >> (from_bits - 1) & 1 == 1;
        let widened = if extension.signed && negative {
            element | (((1u128 << to_bits) - 1) & !((1u128 << from_bits) - 1))
        } else {
            element
        };
        result |= widened << (lane as u32 * to_bits);
    }
    result
}

fn register(disassembler: &Disassembler, name: &str) -> (u64, u32) {
    let storage = disassembler
        .arch_spec()
        .get_register(name)
        .unwrap_or_else(|| panic!("x86-64 declares {name}"))
        .storage();
    (storage.offset, storage.size)
}

/// Where an instruction takes its source from. The other place holds
/// [`DECOY`], so an instruction that read the wrong operand would not compute
/// the SDM result.
#[derive(Clone, Copy, Debug)]
enum Operand {
    Register,
    Memory,
}

/// What the bits of `ZMM1` above `XMM1` hold afterwards: a legacy SSE write
/// keeps them, and a VEX.128 write zeroes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Upper {
    Kept,
    Zeroed,
}

/// Bytes where the instruction must not read its source from.
const DECOY: [u8; 16] = [0x5a; 16];

/// What `ZMM1` holds above `XMM1` before each run.
const UPPER_BEFORE: u128 = u128::MAX;

/// Run one lifted instruction from a state holding the source in `xmm0` or
/// at `[rdi]`, the decoy in the other, and the old destination in `xmm1`;
/// answer what `xmm1` holds and each sixteen bytes of `zmm1` above it.
fn run(
    disassembler: &Disassembler,
    block: &R2ILBlock,
    operand: Operand,
    old_destination: u128,
) -> (u128, Vec<u128>) {
    let (in_register, in_memory) = match operand {
        Operand::Register => (SOURCE, DECOY),
        Operand::Memory => (DECOY, SOURCE),
    };
    let mapped = |address: u64| {
        address
            .checked_sub(SOURCE_ADDRESS)
            .and_then(|at| in_memory.get(usize::try_from(at).ok()?))
            .copied()
    };
    let mut state = State::new(Endianness::Little, mapped, 4096).expect("little-endian machine");
    let (xmm0, xmm0_size) = register(disassembler, "XMM0");
    let (xmm1, xmm1_size) = register(disassembler, "XMM1");
    let (rdi, rdi_size) = register(disassembler, "RDI");
    let (zmm1, zmm1_size) = register(disassembler, "ZMM1");
    assert_eq!(zmm1, xmm1, "XMM1 is the low sixteen bytes of ZMM1");
    let upper = (xmm1_size..zmm1_size)
        .step_by(16)
        .map(|at| zmm1 + u64::from(at));
    for at in upper.clone() {
        state
            .set_register(at, 16, UPPER_BEFORE)
            .expect("upper lanes");
    }
    state
        .set_register(xmm0, xmm0_size, u128::from_le_bytes(in_register))
        .expect("source register");
    state
        .set_register(xmm1, xmm1_size, old_destination)
        .expect("old destination");
    state
        .set_register(rdi, rdi_size, u128::from(SOURCE_ADDRESS))
        .expect("source address");
    for op in &block.ops {
        assert!(
            !matches!(op, R2ILOp::CallOther { .. }),
            "a packed extension is lifted, not left opaque: {:?}",
            block.ops
        );
        assert_eq!(
            step(op, &mut state),
            Flow::Next,
            "{op:?} in {:?}",
            block.ops
        );
    }
    let result = state.register(xmm1, xmm1_size).expect("xmm1 is written");
    let upper = upper
        .map(|at| state.register(at, 16).expect("upper lanes are defined"))
        .collect();
    (result, upper)
}

fn assert_computes(
    disassembler: &Disassembler,
    encoding: &[u8],
    operand: Operand,
    extension: Extension,
    upper: Upper,
) {
    let mut bytes = encoding.to_vec();
    bytes.resize(16, 0x90);
    let block = disassembler.lift(&bytes, 0x1000).expect("lift");
    assert_eq!(block.size as usize, encoding.len(), "{encoding:02x?}");
    let want = expected(extension);
    let want_upper = match upper {
        Upper::Kept => UPPER_BEFORE,
        Upper::Zeroed => 0,
    };
    for old_destination in OLD_DESTINATIONS {
        let (got, got_upper) = run(disassembler, &block, operand, old_destination);
        assert_eq!(
            got, want,
            "{encoding:02x?} ({operand:?}) from old destination {old_destination:#x}: got {got:#034x}, want {want:#034x}"
        );
        assert!(
            got_upper.iter().all(|lane| *lane == want_upper),
            "{encoding:02x?} ({operand:?}): the bits above the result are {got_upper:#x?}, want {upper:?}"
        );
    }
}

/// `pmov{s,z}x* xmm1, xmm0` and `pmov{s,z}x* xmm1, [rdi]`, every element
/// width. A legacy SSE write leaves the register above `XMM1` as it was.
#[test]
fn every_sse41_packed_extension_computes_the_sdm_result() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification");
    for extension in EXTENSIONS {
        let from_register = [0x66, 0x0f, 0x38, extension.opcode, 0xc8];
        let from_memory = [0x66, 0x0f, 0x38, extension.opcode, 0x0f];
        for (encoding, operand) in [
            (from_register, Operand::Register),
            (from_memory, Operand::Memory),
        ] {
            assert_computes(&disassembler, &encoding, operand, extension, Upper::Kept);
        }
    }
}

/// `vpmov{s,z}x* xmm1, xmm0` and `vpmov{s,z}x* xmm1, [rdi]` (VEX.128), which
/// also zero the register above the result.
#[test]
fn every_vex128_packed_extension_computes_the_sdm_result() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification");
    for extension in EXTENSIONS {
        let from_register = [0xc4, 0xe2, 0x79, extension.opcode, 0xc8];
        let from_memory = [0xc4, 0xe2, 0x79, extension.opcode, 0x0f];
        for (encoding, operand) in [
            (from_register, Operand::Register),
            (from_memory, Operand::Memory),
        ] {
            assert_computes(&disassembler, &encoding, operand, extension, Upper::Zeroed);
        }
    }
}
