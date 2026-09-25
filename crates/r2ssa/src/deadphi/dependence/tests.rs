//! The per-operation proof harness for [`super::operand_bytes`].
//!
//! Each case is one operation at concrete operand widths, with its constant
//! operands fixed. The claim checked is the relation's own invariant: for an
//! assignment `x` of the free operands and output byte `b`, replacing every
//! operand byte outside `dep(op, {b})` by the same byte of another assignment
//! `y` leaves byte `b` of the value unchanged.
//!
//! Where the free operands span at most 16 bits the check is exhaustive with
//! `y = 0`: if every `x` agrees with its projection onto the dependence bytes,
//! any two assignments that agree there agree with each other, so byte `b` is
//! a function of the dependence bytes alone. That is every unary and binary
//! operation at eight bits, a shift by an eight-bit amount included. A case
//! with more free bits -- an insert's root and lane, a select, anything at
//! sixteen bits -- sweeps each operand's low byte exhaustively under a
//! boundary set of high bytes, against a boundary and random set of the other
//! operands, in the normal suite; the `#[ignore]`d test takes every assignment
//! up to 2^32 (`cargo test --release -p r2ssa exhaustive -- --ignored`), which
//! is every eight- and sixteen-bit case but a sixteen-bit select. Thirty-two
//! and sixty-four bits are sampled here and proven by the Kani harnesses.
//!
//! The semantics is `r2il::eval::apply`; the four operations it does not model
//! are stated in [`evaluate`].

use super::*;
use r2il::eval::{Word, apply};

/// What `op` computes from its operands in [`SSAOp::sources`] order, or `None`
/// where p-code gives it no value.
fn evaluate(op: &SSAOp, operands: &[u128]) -> Option<u128> {
    let dst = op.dst()?;
    let width_mask = mask(dst.size);
    match op {
        // The lane in place of the root's bits at the position, the root's
        // other bits kept; a lane bit past the root's width is dropped.
        SSAOp::Insert(insert) => {
            let (root, lane, position) = (operands[0], operands[1], operands[2]);
            let position = u32::try_from(position).ok().filter(|bits| *bits < 128)?;
            let lane_mask = mask(insert.value.size);
            let placed = lane_mask.checked_shl(position).unwrap_or(0);
            let lane_bits = (lane & lane_mask).checked_shl(position).unwrap_or(0);
            Some(((root & !placed) | lane_bits) & width_mask)
        }
        // The source shifted down by the position, cut to the destination.
        SSAOp::Extract { .. } => {
            let position = u32::try_from(operands[1]).unwrap_or(u32::MAX);
            Some(operands[0].checked_shr(position).unwrap_or(0) & width_mask)
        }
        // A same-width cast and a call's restore of a carrier are the value.
        SSAOp::Cast { .. } | SSAOp::CallRestore { .. } => Some(operands[0] & width_mask),
        _ => {
            let words = op
                .sources()
                .iter()
                .zip(operands)
                .map(|(source, bits)| Word::new(*bits, source.size).ok())
                .collect::<Option<Vec<_>>>()?;
            apply(op.operation()?, &words, dst.size).ok()
        }
    }
}

fn mask(bytes: u32) -> u128 {
    if bytes >= 16 {
        u128::MAX
    } else {
        (1u128 << (8 * bytes)) - 1
    }
}

/// The bits of a byte mask, as a value mask.
fn bits_of(bytes: ByteMask, width: u32) -> u128 {
    match bytes {
        ByteMask::All => mask(width),
        ByteMask::Bytes(set) => (0..width.min(16))
            .filter(|byte| (set >> byte) & 1 == 1)
            .fold(0, |bits, byte| bits | (0xff << (8 * byte))),
    }
}

/// One operation and which of its operands the harness varies.
struct Case {
    op: SSAOp,
    /// For each source: `Some(bits)` for a fixed constant, `None` for free.
    fixed: Vec<Option<u128>>,
    widths: Vec<u32>,
    /// For each output byte, the bits of each operand the relation says it reads.
    kept: Vec<Vec<u128>>,
}

impl Case {
    fn new(op: SSAOp) -> Self {
        let sources = op.sources();
        let widths = sources.iter().map(|source| source.size).collect::<Vec<_>>();
        let output = op.dst().map_or(0, |dst| dst.size).min(16);
        let kept = (0..output)
            .map(|byte| {
                operand_bytes(&op, ByteMask::byte(byte))
                    .iter()
                    .zip(&widths)
                    .map(|(dep, width)| bits_of(*dep, *width))
                    .collect()
            })
            .collect();
        Self {
            fixed: sources
                .iter()
                .map(|source| source.constant_bits().map(u128::from))
                .collect(),
            widths,
            kept,
            op,
        }
    }

    /// The widths of the free operands, in order.
    fn free_widths(&self) -> Vec<u32> {
        self.fixed
            .iter()
            .zip(&self.widths)
            .filter(|(fixed, _)| fixed.is_none())
            .map(|(_, width)| *width)
            .collect()
    }

    fn free_bits(&self) -> u32 {
        self.fixed
            .iter()
            .zip(&self.widths)
            .filter(|(fixed, _)| fixed.is_none())
            .map(|(_, width)| width * 8)
            .sum()
    }

    fn output_bytes(&self) -> u32 {
        self.op.dst().map_or(0, |dst| dst.size)
    }

    /// The operands with `free` supplying the free ones in order.
    fn operands(&self, free: &[u128]) -> Vec<u128> {
        let mut free = free.iter();
        self.fixed
            .iter()
            .zip(&self.widths)
            .map(|(fixed, width)| {
                fixed.unwrap_or_else(|| *free.next().expect("free") & mask(*width))
            })
            .collect()
    }

    /// Check the invariant at `x` against the replacement `y`; answers
    /// whether both assignments had a value.
    fn check(&self, x: &[u128], y: &[u128]) -> bool {
        let x = self.operands(x);
        let y = self.operands(y);
        let Some(value) = evaluate(&self.op, &x) else {
            return false;
        };
        let mut defined = true;
        for (byte, kept) in self.kept.iter().enumerate() {
            let merged = x
                .iter()
                .zip(&y)
                .zip(kept)
                .zip(&self.widths)
                .map(|(((x, y), keep), width)| (x & keep) | (y & !keep & mask(*width)))
                .collect::<Vec<_>>();
            if merged == x {
                continue;
            }
            let Some(other) = evaluate(&self.op, &merged) else {
                defined = false;
                continue;
            };
            let shift = 8 * byte;
            assert_eq!(
                (value >> shift) & 0xff,
                (other >> shift) & 0xff,
                "{}: byte {byte} of the value at {x:x?} changed when the bytes outside {:?} became {merged:x?}",
                self.op,
                operand_bytes(&self.op, ByteMask::byte(u32::try_from(byte).expect("byte")))
            );
        }
        defined
    }
}

fn var(name: &str, size: u32) -> SSAVar {
    SSAVar::new(name, 0, size)
}

fn constant(bits: u64, size: u32) -> SSAVar {
    SSAVar::constant(bits, size)
}

/// Every operation at operand width `width`, with the constants that decide a
/// transfer drawn from `constants`.
fn cases(width: u32, constants: &[u64]) -> Vec<Case> {
    let (a, b, dst) = (var("A", width), var("B", width), var("D", width));
    let flag = var("F", 1);
    let mut ops = vec![
        SSAOp::Copy {
            dst: dst.clone(),
            src: a.clone(),
        },
        SSAOp::IntNot {
            dst: dst.clone(),
            src: a.clone(),
        },
        SSAOp::IntNegate {
            dst: dst.clone(),
            src: a.clone(),
        },
        SSAOp::Cast {
            dst: dst.clone(),
            src: a.clone(),
        },
        SSAOp::CallRestore {
            dst: dst.clone(),
            src: a.clone(),
        },
        SSAOp::PopCount {
            dst: flag.clone(),
            src: a.clone(),
        },
        SSAOp::Lzcount {
            dst: flag.clone(),
            src: a.clone(),
        },
    ];
    macro_rules! binary {
        ($($kind:ident => $out:expr),* $(,)?) => {
            $(ops.push(SSAOp::$kind { dst: $out.clone(), a: a.clone(), b: b.clone() });)*
        };
    }
    binary!(
        IntAdd => dst, IntSub => dst, IntMult => dst, IntXor => dst, IntAnd => dst,
        IntOr => dst, IntDiv => dst, IntSDiv => dst, IntRem => dst, IntSRem => dst,
        IntLeft => dst, IntRight => dst, IntSRight => dst,
        IntEqual => flag, IntNotEqual => flag, IntLess => flag, IntSLess => flag,
        IntLessEqual => flag, IntSLessEqual => flag, IntCarry => flag, IntSCarry => flag,
        IntSBorrow => flag,
    );
    for element_size in [1, 2, 3, 4, 8] {
        ops.push(SSAOp::PtrAdd {
            dst: dst.clone(),
            base: a.clone(),
            index: b.clone(),
            element_size,
        });
        ops.push(SSAOp::PtrSub {
            dst: dst.clone(),
            base: a.clone(),
            index: b.clone(),
            element_size,
        });
    }
    for bits in constants {
        let c = constant(*bits, width);
        ops.push(SSAOp::IntAnd {
            dst: dst.clone(),
            a: a.clone(),
            b: c.clone(),
        });
        ops.push(SSAOp::IntOr {
            dst: dst.clone(),
            a: c.clone(),
            b: a.clone(),
        });
        ops.push(SSAOp::IntXor {
            dst: dst.clone(),
            a: a.clone(),
            b: c,
        });
    }
    for amount in (0..=u64::from(8 * width) + 1).chain([u64::from(8 * width) + 7, 255]) {
        let c = constant(amount, 1);
        ops.push(SSAOp::IntLeft {
            dst: dst.clone(),
            a: a.clone(),
            b: c.clone(),
        });
        ops.push(SSAOp::IntRight {
            dst: dst.clone(),
            a: a.clone(),
            b: c.clone(),
        });
        ops.push(SSAOp::IntSRight {
            dst: dst.clone(),
            a: a.clone(),
            b: c,
        });
    }
    let amount = var("S", 1);
    ops.push(SSAOp::IntLeft {
        dst: dst.clone(),
        a: a.clone(),
        b: amount.clone(),
    });
    ops.push(SSAOp::IntRight {
        dst: dst.clone(),
        a: a.clone(),
        b: amount.clone(),
    });
    ops.push(SSAOp::IntSRight {
        dst: dst.clone(),
        a: a.clone(),
        b: amount,
    });
    if width == 1 {
        ops.push(SSAOp::BoolNot {
            dst: flag.clone(),
            src: a.clone(),
        });
        binary!(BoolAnd => flag, BoolOr => flag, BoolXor => flag);
    }
    ops.push(SSAOp::Select(Box::new(crate::op::SelectOp {
        dst: dst.clone(),
        cond: flag.clone(),
        if_true: a.clone(),
        if_false: b.clone(),
    })));
    ops.extend(lane_cases(width));
    ops.into_iter().map(Case::new).collect()
}

/// The operations that move bytes between widths: extensions, slices,
/// concatenations, extractions and lane inserts, with `width` the widest.
fn lane_cases(width: u32) -> Vec<SSAOp> {
    let mut ops = Vec::new();
    let narrower = [1, 2, 4].into_iter().filter(|narrow| *narrow < width);
    for narrow in narrower {
        let (src, dst) = (var("A", narrow), var("D", width));
        ops.push(SSAOp::IntZExt {
            dst: dst.clone(),
            src: src.clone(),
        });
        ops.push(SSAOp::IntSExt {
            dst: dst.clone(),
            src: src.clone(),
        });
        ops.push(SSAOp::Piece {
            dst: dst.clone(),
            hi: var("B", width - narrow),
            lo: src.clone(),
        });
        // Every position, whole bytes and not, at which the lane fits.
        for position in 0..=u64::from(8 * (width - narrow)) {
            ops.push(SSAOp::Insert(Box::new(crate::op::InsertOp {
                dst: dst.clone(),
                src: var("R", width),
                value: src.clone(),
                position: constant(position, 4),
            })));
        }
    }
    for out in [1, 2, 4, 8].into_iter().filter(|out| *out <= width) {
        for offset in 0..width {
            ops.push(SSAOp::Subpiece {
                dst: var("D", out),
                src: var("A", width),
                offset,
            });
        }
        for position in 0..=u64::from(8 * width) {
            ops.push(SSAOp::Extract {
                dst: var("D", out),
                src: var("A", width),
                position: constant(position, 4),
            });
        }
    }
    ops
}

/// A deterministic generator, so a failure names the point it failed at.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Values that sit on every boundary a byte rule could get wrong: zero, one,
/// all ones, each sign bit, each byte alone and each byte cleared.
fn boundary_values(width: u32) -> Vec<u128> {
    let full = mask(width);
    let mut values = vec![0, 1, 2, full, full - 1, full >> 1, (full >> 1) + 1];
    for byte in 0..width {
        let at = 0xffu128 << (8 * byte);
        values.extend([at, full & !at, 1 << (8 * byte), 0x80 << (8 * byte)]);
    }
    values.sort_unstable();
    values.dedup();
    values
}

/// Every assignment of a case's free operands, when there are at most
/// `2^limit`.
fn exhaustive(case: &Case, limit: u32) -> bool {
    let bits = case.free_bits();
    if bits > limit {
        return false;
    }
    let free_widths = case.free_widths();
    let zero = vec![0; free_widths.len()];
    let mut defined = 0u64;
    for packed in 0u64..1 << bits {
        let mut rest = packed;
        let x = free_widths
            .iter()
            .map(|width| {
                let value = u128::from(rest) & mask(*width);
                rest >>= 8 * width;
                value
            })
            .collect::<Vec<_>>();
        defined += u64::from(case.check(&x, &zero));
    }
    assert!(defined > 0, "{}: no assignment has a value", case.op);
    true
}

/// How much of each operand a crossed sweep takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sweep {
    /// Every low byte under a boundary set of high bytes: what a debug build
    /// runs in the normal suite.
    Bytes,
    /// Every value of the operand's low sixteen bits.
    Whole,
}

/// The values a crossed sweep gives the varied operand.
fn swept_values(width: u32, sweep: Sweep) -> Vec<u128> {
    if width == 1 || sweep == Sweep::Whole {
        return (0..=mask(width.min(2))).collect();
    }
    [0u128, 1, 0x7f, 0x80, 0xff]
        .into_iter()
        .flat_map(|high| (0..=0xffu128).map(move |low| (high << 8) | low))
        .collect()
}

/// Each free operand swept against a boundary and random set of the others,
/// for the cases too wide to take whole.
fn crossed(case: &Case, rng: &mut SplitMix, sweep: Sweep) {
    let widths = case.free_widths();
    let zero = vec![0; widths.len()];
    for (varied, width) in widths.iter().enumerate() {
        let mut others = vec![0, 0x80, u128::MAX];
        if sweep == Sweep::Whole {
            others.extend([1, 0x7f, 0xff, 0x8000]);
        }
        others.push(u128::from(rng.next()));
        let values = swept_values(*width, sweep);
        for other in others {
            let y = widths
                .iter()
                .map(|_| u128::from(rng.next()))
                .collect::<Vec<_>>();
            for value in &values {
                let x = (0..widths.len())
                    .map(|index| if index == varied { *value } else { other })
                    .collect::<Vec<_>>();
                case.check(&x, &zero);
                case.check(&x, &y);
            }
        }
    }
}

/// Random and boundary assignments with random replacements.
fn sampled(case: &Case, rng: &mut SplitMix, samples: usize) {
    let widths = case.free_widths();
    let draw = |rng: &mut SplitMix| {
        widths
            .iter()
            .map(|_| u128::from(rng.next()))
            .collect::<Vec<_>>()
    };
    for boundary in widths.iter().flat_map(|width| boundary_values(*width)) {
        let x = widths.iter().map(|_| boundary).collect::<Vec<_>>();
        let y = draw(rng);
        case.check(&x, &y);
        case.check(&x, &vec![0; widths.len()]);
    }
    for _ in 0..samples {
        let (x, y) = (draw(rng), draw(rng));
        case.check(&x, &y);
    }
}

const EIGHT_BIT_CONSTANTS: [u64; 6] = [0, 0xff, 0x0f, 0xf0, 0x80, 0x01];
const WIDE_CONSTANTS: [u64; 8] = [
    0,
    u64::MAX,
    0xff,
    0xff00,
    0x00ff_00ff_00ff_00ff,
    0xff00_ff00_ff00_ff00,
    0x0f0f_0f0f_0f0f_0f0f,
    0x8000_0000_0000_0001,
];

/// Every case at eight-bit operands, with the lane operations that move an
/// eight-bit operand into a sixteen-bit value.
fn eight_bit_cases() -> Vec<Case> {
    let mut all = cases(1, &EIGHT_BIT_CONSTANTS);
    all.extend(lane_cases(2).into_iter().map(Case::new));
    all
}

/// Run `check` over the cases on every core, so the exhaustive sweeps finish
/// in a debug build.
fn on_every_core(all: &[Case], check: impl Fn(&Case, &mut SplitMix) + Sync) {
    let per_thread = all.len().div_ceil(4).max(1);
    std::thread::scope(|scope| {
        for (index, chunk) in all.chunks(per_thread).enumerate() {
            let check = &check;
            scope.spawn(move || {
                let mut rng = SplitMix(index as u64);
                for case in chunk {
                    check(case, &mut rng);
                }
            });
        }
    });
}

#[test]
fn every_operation_is_sound_at_eight_bits() {
    on_every_core(&eight_bit_cases(), |case, rng| {
        if !exhaustive(case, 16) {
            crossed(case, rng, Sweep::Bytes);
        }
    });
}

#[test]
fn every_operation_is_sound_at_sixteen_bits() {
    on_every_core(&cases(2, &WIDE_CONSTANTS), |case, rng| {
        crossed(case, rng, Sweep::Bytes);
    });
}

#[test]
fn every_operation_is_sound_at_thirty_two_and_sixty_four_bits() {
    let mut rng = SplitMix(64);
    for width in [4, 8] {
        for case in cases(width, &WIDE_CONSTANTS) {
            sampled(&case, &mut rng, 400);
        }
    }
}

/// Every assignment of every eight- and sixteen-bit case, up to 2^32 of them
/// for two free sixteen-bit operands. Minutes in a release build; run with
/// `--ignored` whenever a transfer changes.
#[test]
#[ignore = "exhaustive over up to 2^32 assignments per operation; run in release"]
fn every_eight_and_sixteen_bit_operation_is_exhaustively_sound() {
    let mut all = eight_bit_cases();
    all.extend(cases(2, &WIDE_CONSTANTS));
    on_every_core(&all, |case, rng| {
        if !exhaustive(case, 32) {
            crossed(case, rng, Sweep::Whole);
        }
    });
}

/// A mask asks of each operand the union of what its bytes ask, so a rule
/// checked one byte at a time is sound for every mask.
#[test]
fn a_mask_asks_at_least_what_its_bytes_ask() {
    let mut rng = SplitMix(2);
    for width in [2, 4, 8] {
        for case in cases(width, &WIDE_CONSTANTS) {
            for _ in 0..8 {
                let demanded =
                    ByteMask::Bytes(rng.next()).intersection(ByteMask::whole(case.output_bytes()));
                let whole = operand_bytes(&case.op, demanded);
                let mut union = vec![ByteMask::NONE; whole.len()];
                for byte in 0..case.output_bytes() {
                    if demanded.contains_byte(byte) {
                        for (acc, mask) in union
                            .iter_mut()
                            .zip(operand_bytes(&case.op, ByteMask::byte(byte)))
                        {
                            *acc = acc.union(mask);
                        }
                    }
                }
                for (asked, needed) in whole.iter().zip(&union) {
                    assert_eq!(
                        asked.union(*needed),
                        *asked,
                        "{}: {demanded:?} asks {asked:?}, its bytes ask {needed:?}",
                        case.op
                    );
                }
            }
        }
    }
}

/// The transfers the byte closures lean on, stated as the machine does them.
#[test]
fn the_transfers_read_what_the_machine_reads() {
    let (rax, rdi) = (var("RAX", 8), var("RDI", 8));
    let low4 = ByteMask::whole(4);
    // `neg eax`: the low four bytes of a negation read the low four bytes.
    let negate = SSAOp::IntNegate {
        dst: rax.clone(),
        src: rdi.clone(),
    };
    assert_eq!(operand_bytes(&negate, low4), vec![low4]);
    // `lea rax, [rdi + rsi]` read whole: every byte of both.
    let add = SSAOp::IntAdd {
        dst: rax.clone(),
        a: rdi.clone(),
        b: var("RSI", 8),
    };
    assert_eq!(
        operand_bytes(&add, ByteMask::whole(8)),
        vec![ByteMask::whole(8); 2]
    );
    // `sar eax, 4` read at four bytes: all four, the top one for the sign.
    let sar = SSAOp::IntSRight {
        dst: var("EAX", 4),
        a: var("EAX", 4),
        b: constant(4, 1),
    };
    assert_eq!(operand_bytes(&sar, low4)[0], low4);
    assert_eq!(operand_bytes(&sar, ByteMask::byte(3))[0], ByteMask::byte(3));
    // `mov al, dil`: the insert's lane is byte zero of the source, and the
    // root keeps every byte but that one.
    let insert = SSAOp::Insert(Box::new(crate::op::InsertOp {
        dst: rax.clone(),
        src: var("RAX", 8),
        value: var("DIL", 1),
        position: constant(0, 4),
    }));
    let [root, lane, _] = operand_bytes(&insert, ByteMask::whole(8))[..] else {
        panic!("three operands");
    };
    assert_eq!((root, lane), (ByteMask::Bytes(0xfe), ByteMask::byte(0)));
    // An unaligned lane shares its partial byte with the root.
    let unaligned = SSAOp::Insert(Box::new(crate::op::InsertOp {
        dst: var("AX", 2),
        src: var("AX", 2),
        value: var("B", 1),
        position: constant(4, 4),
    }));
    let [root, lane, _] = operand_bytes(&unaligned, ByteMask::byte(1))[..] else {
        panic!("three operands");
    };
    assert_eq!((root, lane), (ByteMask::byte(1), ByteMask::byte(0)));
    // A sign extension's upper bytes are the source's top byte.
    let sext = SSAOp::IntSExt {
        dst: var("AX", 2),
        src: var("DIL", 1),
    };
    assert_eq!(
        operand_bytes(&sext, ByteMask::byte(1)),
        vec![ByteMask::byte(0)]
    );
    // A comparison's upper bytes are zero and read nothing.
    let wide_flag = SSAOp::IntEqual {
        dst: var("F", 4),
        a: rdi.clone(),
        b: rax,
    };
    assert_eq!(
        operand_bytes(&wide_flag, ByteMask::byte(2)),
        vec![ByteMask::NONE; 2]
    );
    assert_eq!(
        operand_bytes(&wide_flag, ByteMask::byte(0)),
        vec![ByteMask::whole(8); 2]
    );
}
