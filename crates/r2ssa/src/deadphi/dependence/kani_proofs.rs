//! The byte-dependence invariant at thirty-two and sixty-four bits, proven.
//!
//! For symbolic operands `x`, a symbolic replacement `y` and a symbolic output
//! byte `b`: the value's byte `b` at `x` equals its byte `b` at `x` with every
//! operand byte outside `dep(op, {b})` taken from `y`. The semantics restated
//! here is the wrapping machine arithmetic `r2il::eval` computes, which the
//! sampled harness in `tests.rs` checks against `eval` itself.

use super::*;
use crate::name::InternedName;

static A: InternedName = InternedName::unregistered("A");
static B: InternedName = InternedName::unregistered("B");
static D: InternedName = InternedName::unregistered("D");
static C: InternedName = InternedName::unregistered("const:c");

fn var(name: &'static InternedName, size: u32) -> SSAVar {
    SSAVar::from_interned(name, 0, size)
}

fn mask(bytes: u32) -> u64 {
    if bytes >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * bytes)) - 1
    }
}

fn bits_of(bytes: ByteMask, width: u32) -> u64 {
    match bytes {
        ByteMask::All => mask(width),
        ByteMask::Bytes(set) => {
            let mut bits = 0u64;
            let mut byte = 0;
            while byte < width.min(8) {
                if (set >> byte) & 1 == 1 {
                    bits |= 0xff << (8 * byte);
                }
                byte += 1;
            }
            bits
        }
    }
}

/// A symbolic byte of a `width`-byte value.
fn any_byte(width: u32) -> u32 {
    let byte: u32 = kani::any();
    kani::assume(byte < width);
    byte
}

/// Byte `byte` of `f` agrees at `x` and at `x` with the bytes outside the
/// relation's answer taken from `y`.
fn prove_binary(op: &SSAOp, width: u32, f: fn(u64, u64) -> u64) {
    let byte = any_byte(width);
    let deps = operand_bytes(op, ByteMask::byte(byte));
    let (xa, xb, ya, yb): (u64, u64, u64, u64) =
        (kani::any(), kani::any(), kani::any(), kani::any());
    let (xa, xb) = (xa & mask(width), xb & mask(width));
    let keep_a = bits_of(deps[0], width);
    let keep_b = bits_of(deps[1], width);
    let ma = (xa & keep_a) | (ya & !keep_a & mask(width));
    let mb = (xb & keep_b) | (yb & !keep_b & mask(width));
    let shift = 8 * byte;
    assert_eq!(
        (f(xa, xb) & mask(width)) >> shift & 0xff,
        (f(ma, mb) & mask(width)) >> shift & 0xff
    );
}

fn prove_unary(op: &SSAOp, width: u32, source_width: u32, f: fn(u64) -> u64) {
    let byte = any_byte(width);
    let deps = operand_bytes(op, ByteMask::byte(byte));
    let (x, y): (u64, u64) = (kani::any(), kani::any());
    let x = x & mask(source_width);
    let keep = bits_of(deps[0], source_width);
    let merged = (x & keep) | (y & !keep & mask(source_width));
    let shift = 8 * byte;
    assert_eq!(
        (f(x) & mask(width)) >> shift & 0xff,
        (f(merged) & mask(width)) >> shift & 0xff
    );
}

macro_rules! binary_proofs {
    ($($name:ident: $kind:ident, $width:expr, $f:expr;)*) => {
        $(
            #[kani::proof]
            fn $name() {
                let op = SSAOp::$kind { dst: var(&D, $width), a: var(&A, $width), b: var(&B, $width) };
                prove_binary(&op, $width, $f);
            }
        )*
    };
}

binary_proofs! {
    add_32: IntAdd, 4, |a, b| a.wrapping_add(b);
    add_64: IntAdd, 8, |a, b| a.wrapping_add(b);
    sub_32: IntSub, 4, |a, b| a.wrapping_sub(b);
    sub_64: IntSub, 8, |a, b| a.wrapping_sub(b);
    mult_32: IntMult, 4, |a, b| a.wrapping_mul(b);
    mult_64: IntMult, 8, |a, b| a.wrapping_mul(b);
    xor_64: IntXor, 8, |a, b| a ^ b;
    and_64: IntAnd, 8, |a, b| a & b;
    or_64: IntOr, 8, |a, b| a | b;
    shl_32: IntLeft, 4, |a, b| if b < 32 { a << b } else { 0 };
    shl_64: IntLeft, 8, |a, b| if b < 64 { a << b } else { 0 };
    shr_32: IntRight, 4, |a, b| if b < 32 { a >> b } else { 0 };
    shr_64: IntRight, 8, |a, b| if b < 64 { a >> b } else { 0 };
    sar_32: IntSRight, 4, |a, b| (((a as u32) as i32) >> b.min(31)) as u32 as u64;
    sar_64: IntSRight, 8, |a, b| ((a as i64) >> b.min(63)) as u64;
}

#[kani::proof]
fn negate_64() {
    let op = SSAOp::IntNegate {
        dst: var(&D, 8),
        src: var(&A, 8),
    };
    prove_unary(&op, 8, 8, |a| a.wrapping_neg());
}

#[kani::proof]
fn zero_extend_32_to_64() {
    let op = SSAOp::IntZExt {
        dst: var(&D, 8),
        src: var(&A, 4),
    };
    prove_unary(&op, 8, 4, |a| a);
}

#[kani::proof]
fn sign_extend_16_to_64() {
    let op = SSAOp::IntSExt {
        dst: var(&D, 8),
        src: var(&A, 2),
    };
    prove_unary(&op, 8, 2, |a| (a as u16 as i16) as i64 as u64);
}

#[kani::proof]
fn slice_of_64() {
    let offset: u32 = kani::any();
    kani::assume(offset < 8);
    let op = SSAOp::Subpiece {
        dst: var(&D, 4),
        src: var(&A, 8),
        offset,
    };
    let byte = any_byte(4);
    let deps = operand_bytes(&op, ByteMask::byte(byte));
    let (x, y): (u64, u64) = (kani::any(), kani::any());
    let keep = bits_of(deps[0], 8);
    let merged = (x & keep) | (y & !keep);
    let slice = |value: u64| (value >> (8 * offset)) & mask(4);
    assert_eq!(
        slice(x) >> (8 * byte) & 0xff,
        slice(merged) >> (8 * byte) & 0xff
    );
}

/// A shift by a constant, whole bytes or not, reads the window the relation names.
#[kani::proof]
fn constant_shifts_of_64() {
    let amount: u64 = kani::any();
    kani::assume(amount <= 66);
    let c = SSAVar::constant_interned(&C, amount, 1);
    let byte = any_byte(8);
    let (x, y): (u64, u64) = (kani::any(), kani::any());
    for (op, f) in [
        (
            SSAOp::IntLeft {
                dst: var(&D, 8),
                a: var(&A, 8),
                b: c.clone(),
            },
            (|a: u64, s: u64| if s < 64 { a << s } else { 0 }) as fn(u64, u64) -> u64,
        ),
        (
            SSAOp::IntRight {
                dst: var(&D, 8),
                a: var(&A, 8),
                b: c.clone(),
            },
            |a: u64, s: u64| if s < 64 { a >> s } else { 0 },
        ),
        (
            SSAOp::IntSRight {
                dst: var(&D, 8),
                a: var(&A, 8),
                b: c,
            },
            |a: u64, s: u64| ((a as i64) >> s.min(63)) as u64,
        ),
    ] {
        let keep = bits_of(operand_bytes(&op, ByteMask::byte(byte))[0], 8);
        let merged = (x & keep) | (y & !keep);
        assert_eq!(
            f(x, amount) >> (8 * byte) & 0xff,
            f(merged, amount) >> (8 * byte) & 0xff
        );
    }
}

/// A lane written at any bit position into a sixty-four-bit root.
#[kani::proof]
#[kani::unwind(9)]
fn insert_into_64() {
    let position: u64 = kani::any();
    kani::assume(position <= 48);
    let op = SSAOp::Insert(Box::new(crate::op::InsertOp {
        dst: var(&D, 8),
        src: var(&A, 8),
        value: var(&B, 2),
        position: SSAVar::constant_interned(&C, position, 4),
    }));
    let byte = any_byte(8);
    let deps = operand_bytes(&op, ByteMask::byte(byte));
    let (root, lane, y_root, y_lane): (u64, u64, u64, u64) =
        (kani::any(), kani::any(), kani::any(), kani::any());
    let lane = lane & mask(2);
    let insert =
        |root: u64, lane: u64| (root & !(mask(2) << position)) | ((lane & mask(2)) << position);
    let (keep_root, keep_lane) = (bits_of(deps[0], 8), bits_of(deps[1], 2));
    let merged_root = (root & keep_root) | (y_root & !keep_root);
    let merged_lane = (lane & keep_lane) | (y_lane & !keep_lane & mask(2));
    assert_eq!(
        insert(root, lane) >> (8 * byte) & 0xff,
        insert(merged_root, merged_lane) >> (8 * byte) & 0xff
    );
}
