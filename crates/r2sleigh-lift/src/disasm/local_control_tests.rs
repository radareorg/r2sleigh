//! Every instruction-local loop the lift rewrites computes what the
//! specification's own p-code loop computes.
//!
//! Each instruction is taken twice from the same bytes: as Sleigh's p-code,
//! with its local branches, run by an interpreter that follows them; and as
//! the lift gives it, which has none left. Both run through `r2il::eval`, the
//! engine's one statement of what each operation computes, from the same
//! state, and every register either writes and every byte either stores must
//! agree. The 16-bit scans are run on every source; the wider forms on every
//! single bit, every run of low and of high bits, and pseudo-random values.
//!
//! The one place the rewrite departs from the specification is stated and
//! checked on its own: where BSF's or BSR's source is zero, the specification
//! writes the loop's starting index, which no documentation gives, and the
//! lift keeps the destination as it was instead.
#![cfg(feature = "x86")]

use super::*;
use r2il::Endianness;
use r2il::eval::{AccessKind, Flow, Mapped, State, step};

/// Where the instruction sits in every run.
const AT: u64 = 0x1000;
/// Where `[rbp - 0x20]` points in the memory forms.
const FRAME: u64 = 0x8000;
/// What the destination holds before every run: no count any scan produces.
const OLD_DESTINATION: u128 = 0x5a5a_5a5a_5a5a_5a5a;

/// Each register either program writes, and each store, in order.
type Outcome = (Vec<Option<u128>>, Vec<(u64, u128)>);

fn x86() -> Disassembler {
    Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification")
}

/// Sleigh's p-code for `bytes`, and the lift of the same bytes.
fn both(disassembler: &Disassembler, bytes: &[u8]) -> (R2ILBlock, R2ILBlock) {
    let mut padded = [0u8; 16];
    padded[..bytes.len()].copy_from_slice(bytes);
    disassembler.clear_decode_cache().expect("fresh decode");
    let pcode = disassembler.pcode(&padded, AT).expect("p-code");
    let raw = disassembler
        .translate_pcode(pcode, AT)
        .expect("translation");
    let lifted = disassembler.lift(&padded, AT).expect("lift");
    (raw, lifted)
}

fn register(disassembler: &Disassembler, name: &str) -> Varnode {
    let storage = disassembler
        .arch_spec()
        .get_register(name)
        .unwrap_or_else(|| panic!("x86-64 declares {name}"))
        .storage();
    Varnode::register(storage.offset, storage.size)
}

/// Bytes nothing wrote read as a pattern of their address, so a load of the
/// wrong place reads something else.
fn memory(address: u64) -> u8 {
    (address as u8).wrapping_mul(0x9d) ^ (address >> 8) as u8
}

/// A machine holding `inputs`, whose memory holds `frame` at [`FRAME`] and
/// the pattern everywhere else.
fn machine(inputs: &[(Varnode, u128)], frame: u128) -> State<impl Mapped> {
    let mapped = move |address: u64| match address.checked_sub(FRAME) {
        Some(at) if at < 16 => Some((frame >> (8 * at)) as u8),
        _ => Some(memory(address)),
    };
    let mut state = State::new(Endianness::Little, mapped, 1 << 16).expect("state");
    for (register, value) in inputs {
        state
            .set_register(register.offset, register.size, *value)
            .expect("entry register");
    }
    state
}

/// Where a local branch at `at` goes when taken, or `None` for a machine one.
fn local_target(block: &R2ILBlock, at: usize, target: &Varnode) -> Option<usize> {
    if target.space == SpaceId::Const {
        let shift = 64 - 8 * target.size;
        let relative = ((target.offset << shift) as i64) >> shift;
        return at.checked_add_signed(relative as isize);
    }
    (target.offset == block.addr + u64::from(block.size)).then_some(block.ops.len())
}

/// Run one instruction's operations, following its local branches.
fn run<M: Mapped>(block: &R2ILBlock, state: &mut State<M>) {
    let mut at = 0;
    while at < block.ops.len() {
        let op = &block.ops[at];
        let branch = match op {
            R2ILOp::Branch { target } => local_target(block, at, target).map(|to| (to, true)),
            R2ILOp::CBranch { target, cond } => local_target(block, at, target)
                .map(|to| (to, state.value(cond).expect("condition") != 0)),
            _ => None,
        };
        at = match branch {
            Some((to, true)) => to,
            Some((_, false)) => at + 1,
            None => match step(op, state) {
                Flow::Next => at + 1,
                other => panic!("{op:?} at {at} of {:#x}: {other:?}", block.addr),
            },
        };
    }
}

/// Every register the operations write.
fn written(block: &R2ILBlock) -> Vec<Varnode> {
    block
        .ops
        .iter()
        .filter_map(R2ILOp::output)
        .filter(|output| output.space == SpaceId::Register)
        .cloned()
        .collect()
}

/// What a run leaves in `registers`, and what it stored where.
fn outcome<M: Mapped>(state: &mut State<M>, registers: &[Varnode]) -> Outcome {
    let values = registers
        .iter()
        .map(|register| state.register(register.offset, register.size))
        .collect();
    let stores = state
        .take_accesses()
        .into_iter()
        .filter(|access| access.kind == AccessKind::Write)
        .collect::<Vec<_>>();
    let stored = stores
        .into_iter()
        .map(|access| {
            let value = state.load(access.address, access.width).expect("stored");
            (access.address, value)
        })
        .collect();
    (values, stored)
}

/// Run the specification's p-code and the lift from one state, and answer
/// both outcomes over every register either writes.
fn compare(
    (raw, lifted): (&R2ILBlock, &R2ILBlock),
    inputs: &[(Varnode, u128)],
    frame: u128,
) -> (Vec<Varnode>, [Outcome; 2]) {
    let mut registers = written(raw);
    registers.extend(written(lifted));
    let outcomes = [raw, lifted].map(|block| {
        let mut state = machine(inputs, frame);
        run(block, &mut state);
        outcome(&mut state, &registers)
    });
    (registers, outcomes)
}

fn assert_agrees(
    name: &str,
    blocks: (&R2ILBlock, &R2ILBlock),
    inputs: &[(Varnode, u128)],
    frame: u128,
) {
    let (_, [expected, got]) = compare(blocks, inputs, frame);
    assert_eq!(got, expected, "{name} from {inputs:x?}, frame {frame:#x}");
}

/// No local branch is left, and nothing is `Unimplemented`.
fn assert_no_local_control(name: &str, lifted: &R2ILBlock) {
    let local = lifted.ops.iter().enumerate().any(|(at, op)| match op {
        R2ILOp::Unimplemented => true,
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => {
            local_target(lifted, at, target).is_some()
        }
        _ => false,
    });
    assert!(!local, "{name} kept local control: {:?}", lifted.ops);
}

/// Every single bit, every run of low bits and of high bits, and 2048
/// pseudo-random values, at `bits`.
fn samples(bits: u32) -> Vec<u128> {
    let mask = u128::MAX >> (128 - bits);
    let mut values = vec![0, mask];
    for k in 0..bits {
        let low = (1u128 << k) - 1;
        values.extend([1 << k, low, mask & !low]);
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..2048 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let wide = (u128::from(seed) << 64) | u128::from(seed.rotate_left(29));
        values.push(wide & mask);
    }
    values
}

/// One scan instruction: its bytes, the operand width, and whether it is BSF
/// or BSR, whose zero source the lift departs from the specification on.
struct Scan {
    name: &'static str,
    bytes: &'static [u8],
    bits: u32,
    zero_keeps_destination: bool,
}

/// A BSF or BSR, whose zero source keeps the destination.
const fn bit_search(name: &'static str, bytes: &'static [u8], bits: u32) -> Scan {
    Scan {
        name,
        bytes,
        bits,
        zero_keeps_destination: true,
    }
}

/// A TZCNT, whose zero source counts the width.
const fn count(name: &'static str, bytes: &'static [u8], bits: u32) -> Scan {
    Scan {
        name,
        bytes,
        bits,
        zero_keeps_destination: false,
    }
}

const SCANS: [Scan; 12] = [
    bit_search("bsr rax, rcx", &[0x48, 0x0f, 0xbd, 0xc1], 64),
    bit_search("bsr eax, ecx", &[0x0f, 0xbd, 0xc1], 32),
    bit_search("bsr ax, cx", &[0x66, 0x0f, 0xbd, 0xc1], 16),
    bit_search("bsr rax, [rbp - 0x20]", &[0x48, 0x0f, 0xbd, 0x45, 0xe0], 64),
    bit_search("bsf rax, rcx", &[0x48, 0x0f, 0xbc, 0xc1], 64),
    bit_search("bsf eax, ecx", &[0x0f, 0xbc, 0xc1], 32),
    bit_search("bsf ax, cx", &[0x66, 0x0f, 0xbc, 0xc1], 16),
    bit_search("bsf eax, [rbp - 0x20]", &[0x0f, 0xbc, 0x45, 0xe0], 32),
    count("tzcnt rax, rcx", &[0xf3, 0x48, 0x0f, 0xbc, 0xc1], 64),
    count("tzcnt eax, ecx", &[0xf3, 0x0f, 0xbc, 0xc1], 32),
    count("tzcnt ax, cx", &[0xf3, 0x66, 0x0f, 0xbc, 0xc1], 16),
    count(
        "tzcnt rax, [rbp - 0x20]",
        &[0xf3, 0x48, 0x0f, 0xbc, 0x45, 0xe0],
        64,
    ),
];

#[test]
fn bit_scans_compute_what_their_p_code_loops_compute() {
    let disassembler = x86();
    let [rax, rcx, rbp] = ["RAX", "RCX", "RBP"].map(|name| register(&disassembler, name));
    for scan in &SCANS {
        let (raw, lifted) = both(&disassembler, scan.bytes);
        assert!(
            raw.ops.iter().any(|op| matches!(op, R2ILOp::Branch { .. })),
            "{} is a loop in the specification: {:?}",
            scan.name,
            raw.ops
        );
        assert_no_local_control(scan.name, &lifted);
        let memory_form = scan.bytes.ends_with(&[0x45, 0xe0]);
        let every = match scan.bits {
            16 => (0..=0xffffu128).collect(),
            bits => samples(bits),
        };
        let mask = u128::MAX >> (128 - scan.bits);
        for source in every {
            // A memory form reads the frame, a register form RCX; the other
            // holds something else.
            let (in_register, in_frame) = match memory_form {
                true => (!source & mask, source),
                false => (source, !source & mask),
            };
            let inputs = [
                (rax.clone(), OLD_DESTINATION),
                (rcx.clone(), in_register),
                (rbp.clone(), u128::from(FRAME + 0x20)),
            ];
            let blocks = (&raw, &lifted);
            if source == 0 && scan.zero_keeps_destination {
                assert_zero_source_keeps_destination(scan.name, blocks, &inputs, in_frame);
            } else {
                assert_agrees(scan.name, blocks, &inputs, in_frame);
            }
        }
    }
}

/// Where BSF's or BSR's source is zero, every register but the destination
/// agrees with the specification, ZF among them, and the destination keeps
/// what it held.
fn assert_zero_source_keeps_destination(
    name: &str,
    blocks: (&R2ILBlock, &R2ILBlock),
    inputs: &[(Varnode, u128)],
    frame: u128,
) {
    let (registers, [expected, got]) = compare(blocks, inputs, frame);
    let destination = &inputs[0].0;
    for ((register, expected), got) in registers.iter().zip(&expected.0).zip(&got.0) {
        if register.offset == destination.offset {
            let held = OLD_DESTINATION & (u128::MAX >> (128 - 8 * register.size));
            assert_eq!(*got, Some(held), "{name}: {register:?} at a zero source");
        } else {
            assert_eq!(got, expected, "{name}: {register:?} at a zero source");
        }
    }
    assert_eq!(got.1, expected.1, "{name}: stores at a zero source");
}

#[test]
fn constant_decided_loops_run_as_many_passes_as_their_p_code() {
    let disassembler = x86();
    let names = ["RAX", "RBX", "RCX", "RSP", "RBP", "XMM0", "XMM1"];
    let [rax, rbx, rcx, rsp, rbp, xmm0, xmm1] = names.map(|name| register(&disassembler, name));
    let cases: [(&str, &[u8], u32); 10] = [
        ("pdep rax, rbx, rcx", &[0xc4, 0xe2, 0xe3, 0xf5, 0xc1], 64),
        ("pdep eax, ebx, ecx", &[0xc4, 0xe2, 0x63, 0xf5, 0xc1], 32),
        ("pext rax, rbx, rcx", &[0xc4, 0xe2, 0xe2, 0xf5, 0xc1], 64),
        ("pext eax, ebx, ecx", &[0xc4, 0xe2, 0x62, 0xf5, 0xc1], 32),
        (
            "pclmulqdq xmm0, xmm1, 0x00",
            &[0x66, 0x0f, 0x3a, 0x44, 0xc1, 0x00],
            128,
        ),
        (
            "pclmulqdq xmm0, xmm1, 0x11",
            &[0x66, 0x0f, 0x3a, 0x44, 0xc1, 0x11],
            128,
        ),
        ("enter 0x10, 2", &[0xc8, 0x10, 0x00, 0x02], 64),
        ("enter 0x10, 3", &[0xc8, 0x10, 0x00, 0x03], 64),
        ("enter 0x20, 7", &[0xc8, 0x20, 0x00, 0x07], 64),
        ("enter 0x08, 31", &[0xc8, 0x08, 0x00, 0x1f], 64),
    ];
    for (name, bytes, bits) in cases {
        let (raw, lifted) = both(&disassembler, bytes);
        assert!(
            raw.ops.iter().enumerate().any(|(at, op)| matches!(
                op,
                R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. }
                    if local_target(&raw, at, target).is_some_and(|to| to <= at)
            )),
            "{name} is a loop in the specification: {:?}",
            raw.ops
        );
        assert_no_local_control(name, &lifted);
        let values = samples(bits);
        for (index, value) in values.iter().enumerate().step_by(7) {
            let other = values[(index * 31 + 5) % values.len()];
            let inputs = [
                (rax.clone(), OLD_DESTINATION),
                (rbx.clone(), value & u128::from(u64::MAX)),
                (rcx.clone(), other & u128::from(u64::MAX)),
                (rsp.clone(), u128::from(FRAME)),
                (rbp.clone(), u128::from(FRAME + 0x100)),
                (xmm0.clone(), *value),
                (xmm1.clone(), other),
            ];
            assert_agrees(name, (&raw, &lifted), &inputs, 0);
        }
    }
}

#[test]
fn zz_debug_cmpxchg_dump() {
    let disassembler = x86();
    let cases: [(&str, &[u8]); 12] = [
        ("lock cmpxchg [rdi], esi", &[0xf0, 0x0f, 0xb1, 0x37]),
        ("cmpxchg [rdi], esi", &[0x0f, 0xb1, 0x37]),
        ("cmpxchg ecx, esi", &[0x0f, 0xb1, 0xf1]),
        ("cmpxchg cl, sil", &[0x40, 0x0f, 0xb0, 0xf1]),
        ("cmpxchg cx, si", &[0x66, 0x0f, 0xb1, 0xf1]),
        ("cmpxchg rcx, rsi", &[0x48, 0x0f, 0xb1, 0xf1]),
        ("lock cmpxchg [rdi], sil", &[0xf0, 0x40, 0x0f, 0xb0, 0x37]),
        ("lock cmpxchg [rdi], si", &[0x66, 0xf0, 0x0f, 0xb1, 0x37]),
        ("lock cmpxchg [rdi], rsi", &[0xf0, 0x48, 0x0f, 0xb1, 0x37]),
        ("lock cmpxchg8b [rdi]", &[0xf0, 0x0f, 0xc7, 0x0f]),
        ("lock cmpxchg16b [rdi]", &[0xf0, 0x48, 0x0f, 0xc7, 0x0f]),
        ("cmpxchg eax, esi", &[0x0f, 0xb1, 0xf0]),
    ];
    for (name, bytes) in cases {
        let (raw, lifted) = both(&disassembler, bytes);
        eprintln!("==== {name} size {}", raw.size);
        for (i, op) in raw.ops.iter().enumerate() {
            eprintln!("  raw {i:2}: {op:?}");
        }
        for (i, op) in lifted.ops.iter().enumerate() {
            eprintln!("  lift {i:2}: {op:?}");
        }
    }
}
