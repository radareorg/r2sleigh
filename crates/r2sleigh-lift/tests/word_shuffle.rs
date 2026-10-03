//! x86 `PSHUFLW`, `PSHUFHW` and `PSHUFW` compute what the Intel SDM states,
//! for every immediate, in every encoding the specification declares.
//!
//! Every form is lifted with each of the 256 immediates and run from a state
//! whose source words are all different, so a word taken from the wrong place
//! shows, and from two old destinations with nothing in common, so a result
//! that read the destination shows too. The destination is compared byte for
//! byte with the SDM's Operation clause: in each 128-bit lane, word `k` of the
//! shuffled quadword is the quadword's word `imm[2k+1:2k]`, and the other
//! quadword is copied. The register above the result is checked as well: a
//! legacy SSE write keeps it and a VEX or EVEX write zeroes it.
//!
//! The 64- and 128-bit forms run through `r2il::eval`, the engine's one
//! statement of what each operation computes. The 256- and 512-bit forms hold
//! values wider than `eval` carries, and the lift gives them in data movement
//! alone -- `SUBPIECE`, `PIECE`, `COPY`, `INT_ZEXT` -- which [`Bytes`] runs a
//! byte at a time; any other operation fails the test.
#![cfg(feature = "x86")]

use std::collections::BTreeMap;

use r2il::eval::{Flow, State, step};
use r2il::{Endianness, R2ILBlock, R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// Where `[rdi]` points in the memory form.
const SOURCE_ADDRESS: u64 = 0x4000;

/// Which quadword of each lane the immediate shuffles.
#[derive(Clone, Copy, Debug)]
enum Quadword {
    Low,
    High,
}

/// What the register above the result holds afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Upper {
    Kept,
    Zeroed,
    /// An MMX register has nothing above it.
    None,
}

/// One encoding: its bytes up to the immediate, the width it writes, the
/// quadword it shuffles, the destination and source registers, and whether
/// its source is `[rdi]`.
struct Form {
    name: &'static str,
    encoding: &'static [u8],
    bytes: usize,
    quadword: Quadword,
    registers: (&'static str, &'static str),
    upper: Upper,
    from_memory: bool,
}

const fn form(
    name: &'static str,
    encoding: &'static [u8],
    bytes: usize,
    quadword: Quadword,
    upper: Upper,
) -> Form {
    let registers = match bytes {
        8 => ("MM1", "MM0"),
        _ => ("ZMM1", "ZMM0"),
    };
    Form {
        name,
        encoding,
        bytes,
        quadword,
        registers,
        upper,
        from_memory: false,
    }
}

const FORMS: [Form; 14] = [
    form(
        "pshufw mm1, mm0",
        &[0x0f, 0x70, 0xc8],
        8,
        Quadword::Low,
        Upper::None,
    ),
    form(
        "pshuflw xmm1, xmm0",
        &[0xf2, 0x0f, 0x70, 0xc8],
        16,
        Quadword::Low,
        Upper::Kept,
    ),
    form(
        "pshufhw xmm1, xmm0",
        &[0xf3, 0x0f, 0x70, 0xc8],
        16,
        Quadword::High,
        Upper::Kept,
    ),
    Form {
        from_memory: true,
        ..form(
            "pshuflw xmm1, [rdi]",
            &[0xf2, 0x0f, 0x70, 0x0f],
            16,
            Quadword::Low,
            Upper::Kept,
        )
    },
    form(
        "vpshuflw xmm1, xmm0",
        &[0xc5, 0xfb, 0x70, 0xc8],
        16,
        Quadword::Low,
        Upper::Zeroed,
    ),
    form(
        "vpshufhw xmm1, xmm0",
        &[0xc5, 0xfa, 0x70, 0xc8],
        16,
        Quadword::High,
        Upper::Zeroed,
    ),
    form(
        "vpshuflw ymm1, ymm0",
        &[0xc5, 0xff, 0x70, 0xc8],
        32,
        Quadword::Low,
        Upper::Zeroed,
    ),
    form(
        "vpshufhw ymm1, ymm0",
        &[0xc5, 0xfe, 0x70, 0xc8],
        32,
        Quadword::High,
        Upper::Zeroed,
    ),
    form(
        "vpshuflw xmm1, xmm0 (evex)",
        &[0x62, 0xf1, 0x7f, 0x08, 0x70, 0xc8],
        16,
        Quadword::Low,
        Upper::Zeroed,
    ),
    form(
        "vpshufhw xmm1, xmm0 (evex)",
        &[0x62, 0xf1, 0x7e, 0x08, 0x70, 0xc8],
        16,
        Quadword::High,
        Upper::Zeroed,
    ),
    form(
        "vpshuflw ymm1, ymm0 (evex)",
        &[0x62, 0xf1, 0x7f, 0x28, 0x70, 0xc8],
        32,
        Quadword::Low,
        Upper::Zeroed,
    ),
    form(
        "vpshufhw ymm1, ymm0 (evex)",
        &[0x62, 0xf1, 0x7e, 0x28, 0x70, 0xc8],
        32,
        Quadword::High,
        Upper::Zeroed,
    ),
    form(
        "vpshuflw zmm1, zmm0",
        &[0x62, 0xf1, 0x7f, 0x48, 0x70, 0xc8],
        64,
        Quadword::Low,
        Upper::Zeroed,
    ),
    form(
        "vpshufhw zmm1, zmm0",
        &[0x62, 0xf1, 0x7e, 0x48, 0x70, 0xc8],
        64,
        Quadword::High,
        Upper::Zeroed,
    ),
];

/// Sixty-four source bytes: every 16-bit word is different.
fn source() -> Vec<u8> {
    (0..64u8)
        .map(|at| at.wrapping_mul(7).wrapping_add(0x11))
        .collect()
}

/// Bytes where the instruction must not read its source from.
const DECOY: u8 = 0xa5;

/// Two old destinations with nothing in common.
const OLD_DESTINATIONS: [u8; 2] = [0x00, 0xff];

/// The SDM result over the first `bytes` of `source`.
fn expected(form: &Form, source: &[u8], order: u8) -> Vec<u8> {
    let mut result = source[..form.bytes].to_vec();
    let quadword = match form.quadword {
        Quadword::Low => 0,
        Quadword::High => 8,
    };
    for lane in (0..form.bytes).step_by(16) {
        let at = lane + quadword;
        for k in 0..4 {
            let chosen = usize::from((order >> (2 * k)) & 3);
            result[at + 2 * k] = source[at + 2 * chosen];
            result[at + 2 * k + 1] = source[at + 2 * chosen + 1];
        }
    }
    result
}

fn register(disassembler: &Disassembler, name: &str) -> Varnode {
    let storage = disassembler
        .arch_spec()
        .get_register(name)
        .unwrap_or_else(|| panic!("x86-64 declares {name}"))
        .storage();
    Varnode::register(storage.offset, storage.size)
}

/// A byte-at-a-time run of data movement, for values wider than `eval` carries.
#[derive(Default)]
struct Bytes {
    held: BTreeMap<(bool, u64), u8>,
}

/// A byte's place: whether it is a register's, and its offset.
fn place(varnode: &Varnode, at: u64) -> (bool, u64) {
    match varnode.space {
        SpaceId::Register | SpaceId::Unique => {
            (varnode.space == SpaceId::Register, varnode.offset + at)
        }
        other => panic!("{other:?} is not a register or a temporary"),
    }
}

impl Bytes {
    fn set(&mut self, varnode: &Varnode, bytes: &[u8]) {
        for (at, byte) in (0u64..).zip(bytes.iter().take(varnode.size as usize)) {
            self.held.insert(place(varnode, at), *byte);
        }
    }

    fn get(&self, varnode: &Varnode) -> Vec<u8> {
        (0..u64::from(varnode.size))
            .map(|at| self.held[&place(varnode, at)])
            .collect()
    }

    fn step(&mut self, op: &R2ILOp) {
        let (dst, value) = match op {
            R2ILOp::Copy { dst, src } => (dst, self.get(src)),
            R2ILOp::Subpiece { dst, src, offset } => {
                let from = *offset as usize;
                (dst, self.get(src)[from..from + dst.size as usize].to_vec())
            }
            R2ILOp::Piece { dst, hi, lo } => (dst, [self.get(lo), self.get(hi)].concat()),
            R2ILOp::IntZExt { dst, src } => {
                let mut value = self.get(src);
                value.resize(dst.size as usize, 0);
                (dst, value)
            }
            other => panic!("{other:?} is not data movement"),
        };
        self.set(dst, &value);
    }
}

/// Where each sixteen bytes of a register begin.
fn chunks(varnode: &Varnode) -> impl Iterator<Item = u64> + '_ {
    (0..varnode.size)
        .step_by(16)
        .map(|at| varnode.offset + u64::from(at))
}

/// What the destination register (its full ZMM or MM extent) holds after the
/// lifted instruction runs with `source` in the source operand.
fn run(disassembler: &Disassembler, form: &Form, block: &R2ILBlock, old: u8) -> Vec<u8> {
    let (destination, source_register) = (
        register(disassembler, form.registers.0),
        register(disassembler, form.registers.1),
    );
    let source = source();
    let in_register = match form.from_memory {
        true => vec![DECOY; 64],
        false => source.clone(),
    };
    assert!(
        !block
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::CallOther { .. })),
        "{} is lifted, not left opaque: {:?}",
        form.name,
        block.ops
    );
    if form.bytes > 16 {
        let mut machine = Bytes::default();
        machine.set(&destination, &[old; 64]);
        machine.set(&source_register, &in_register);
        for op in &block.ops {
            machine.step(op);
        }
        return machine.get(&destination);
    }
    let mapped = move |address: u64| {
        let at = usize::try_from(address.checked_sub(SOURCE_ADDRESS)?).ok()?;
        source.get(at).copied()
    };
    let mut state = State::new(Endianness::Little, mapped, 4096).expect("little-endian machine");
    let rdi = register(disassembler, "RDI");
    state
        .set_register(rdi.offset, rdi.size, u128::from(SOURCE_ADDRESS))
        .expect("source address");
    for at in chunks(&destination) {
        let width = destination.size.min(16);
        state
            .set_register(at, width, u128::from_le_bytes([old; 16]))
            .expect("old destination");
    }
    let low = u128::from_le_bytes(in_register[..16].try_into().expect("sixteen bytes"));
    state
        .set_register(source_register.offset, source_register.size.min(16), low)
        .expect("source");
    for op in &block.ops {
        assert_eq!(
            step(op, &mut state),
            Flow::Next,
            "{op:?} in {:?}",
            block.ops
        );
    }
    chunks(&destination)
        .flat_map(|at| {
            let width = destination.size.min(16);
            let value = state.register(at, width).expect("destination is defined");
            value.to_le_bytes()[..width as usize].to_vec()
        })
        .collect()
}

#[test]
fn every_word_shuffle_computes_the_sdm_result_for_every_immediate() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification");
    for form in &FORMS {
        for order in 0..=u8::MAX {
            let mut bytes = form.encoding.to_vec();
            bytes.push(order);
            let length = bytes.len();
            bytes.resize(16, 0x90);
            let block = disassembler.lift(&bytes, 0x1000).expect("lift");
            assert_eq!(block.size as usize, length, "{} decodes whole", form.name);
            let want = expected(form, &source(), order);
            for old in OLD_DESTINATIONS {
                let got = run(&disassembler, form, &block, old);
                assert_eq!(
                    &got[..form.bytes],
                    &want[..],
                    "{} with immediate {order:#04x} from old destination {old:#04x}",
                    form.name
                );
                let above = &got[form.bytes..];
                let held = match form.upper {
                    Upper::Kept => old,
                    Upper::Zeroed | Upper::None => 0,
                };
                assert!(
                    above.iter().all(|byte| *byte == held),
                    "{}: above the result {above:02x?}, want {:?}",
                    form.name,
                    form.upper
                );
            }
        }
    }
}
