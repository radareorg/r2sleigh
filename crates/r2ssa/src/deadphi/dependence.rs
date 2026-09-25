//! Which bytes of an operation's operands each byte of its value depends on.
//!
//! One relation, `dep(op, out_byte) -> operand bytes`, answers every question
//! the byte closures ask: what an observation demands of a value's producers
//! (backward, [`super::dependency_closure`]), which bytes of a value may or
//! must carry a register the convention leaves unspecified (forward,
//! [`super::unspecified`]), and which operand of a lane write contributes no
//! observed byte ([`super::narrow`]).
//!
//! The invariant each transfer states is the one the proof harness below
//! checks, exhaustively at 8 and 16 bits and by sampling and Kani at 32 and
//! 64: for every operand assignment, changing any operand byte outside
//! `dep(op, M)` leaves every byte in `M` of the value unchanged. A transfer
//! may name more bytes than the value depends on -- that costs a formal or a
//! merge nothing needed -- but never fewer, because the elision and the
//! narrowing both delete what this calls unobserved.
//!
//! The semantics each rule is checked against is `r2il::eval`, the one owner
//! of what an operation computes; the lane operations it does not model
//! (`Insert`, `Extract`, a same-width `Cast` or `CallRestore`) are stated in
//! the harness beside the rule.
//!
//! Each transfer is O(1) on a mask word, except the two whose windows are cut
//! at a bit position (`Insert` and a constant shift), which are O(bytes named).

use super::ByteMask;
use crate::SSAOp;
use crate::var::SSAVar;

/// The bytes of each operand that the `demanded` bytes of `op`'s value may
/// depend on, one mask per operand in [`SSAOp::sources`] order, each trimmed
/// to its operand's width.
///
/// A `Phi` is not an operation here: each of its inputs is the value on one
/// edge, so each is demanded exactly as the merge is.
pub(crate) fn operand_bytes(op: &SSAOp, demanded: ByteMask) -> Vec<ByteMask> {
    let sources = op.sources();
    let demanded = match op.dst() {
        Some(dst) => demanded.intersection(ByteMask::whole(dst.size)),
        None => ByteMask::All,
    };
    if demanded.is_empty() {
        return vec![ByteMask::NONE; sources.len()];
    }
    // Wider than a mask word can name: every operand whole.
    if demanded == ByteMask::All {
        return sources.iter().map(|source| whole(source)).collect();
    }
    let masks =
        transfer(op, demanded).unwrap_or_else(|| sources.iter().map(|s| whole(s)).collect());
    masks
        .into_iter()
        .zip(sources)
        .map(|(mask, source)| mask.intersection(whole(source)))
        .collect()
}

fn whole(var: &SSAVar) -> ByteMask {
    ByteMask::whole(var.size)
}

/// The exact transfer of the operations that have one; `None` for the rest,
/// which read every byte of every operand.
fn transfer(op: &SSAOp, m: ByteMask) -> Option<Vec<ByteMask>> {
    use SSAOp::*;
    Some(match op {
        // A byte of the value is the same byte of the operand.
        Copy { .. } | IntNot { .. } => vec![m],
        Cast { dst, src } | CallRestore { dst, src } if dst.size == src.size => vec![m],
        // Two's complement arithmetic carries only upward: byte k of a sum,
        // a difference, a product or a negation is a function of bytes
        // 0..=k of its operands.
        IntNegate { .. } => vec![m.through_highest()],
        IntAdd { .. } | IntSub { .. } | IntMult { .. } | PtrAdd { .. } | PtrSub { .. } => {
            vec![m.through_highest(), m.through_highest()]
        }
        IntXor { .. } => vec![m, m],
        IntAnd { a, b, .. } => bytewise_absorbing(m, a, b, ByteMask::nonzero_bytes_of),
        IntOr { a, b, .. } => bytewise_absorbing(m, a, b, not_all_ones_bytes_of),
        IntLeft { a, b, .. } => shift_left(m, a, b),
        IntRight { a, b, .. } => shift_right(m, a, b, false),
        IntSRight { a, b, .. } => shift_right(m, a, b, true),
        // A flag is nought or one: only its least significant byte is ever
        // anything, and that one reads its operands whole.
        _ if is_flag(op) => {
            let read = if m.contains_byte(0) {
                ByteMask::All
            } else {
                ByteMask::NONE
            };
            vec![read; op.sources().len()]
        }
        // Above the operand a zero extension is zero, and a sign extension is
        // the operand's top byte.
        IntZExt { .. } => vec![m],
        IntSExt { src, .. } => vec![sign_extension(m, src.size)],
        Piece { lo, .. } => vec![m.shifted_down(lo.size), m],
        Subpiece { offset, .. } => vec![m.shifted_up(*offset)],
        Extract { position, .. } => match position.constant_bits() {
            Some(bits) => vec![read_above(m, bits), ByteMask::All],
            None => return None,
        },
        Insert(insert) => {
            let bits = insert.position.constant_bits()?;
            let (root, lane) = insert_window(m, bits, insert.value.size);
            vec![root, lane, ByteMask::All]
        }
        // The condition decides which operand is the value; the value is
        // either one, byte for byte.
        Select(_) => vec![ByteMask::All, m, m],
        _ => return None,
    })
}

/// Whether the operation's value is a p-code boolean: nought or one.
const fn is_flag(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::BoolNot { .. }
    )
}

/// A byte-wise operation with an absorbing byte value: where one operand is
/// a constant whose byte absorbs (`and` with zero, `or` with all ones), the
/// other operand's byte there is not read.
fn bytewise_absorbing(
    m: ByteMask,
    a: &SSAVar,
    b: &SSAVar,
    passes: fn(u64, u32) -> ByteMask,
) -> Vec<ByteMask> {
    let passing = |var: &SSAVar| var.constant_bits().map(|bits| passes(bits, var.size));
    match (passing(a), passing(b)) {
        (None, Some(through)) => vec![m.intersection(through), m],
        (Some(through), None) => vec![m, m.intersection(through)],
        _ => vec![m, m],
    }
}

/// The bytes of a constant `size_bytes` wide that are not all ones, which are
/// the only bytes an `or` with it lets through. A constant is zero past its
/// eighth byte, so every byte from there on lets through.
fn not_all_ones_bytes_of(bits: u64, size_bytes: u32) -> ByteMask {
    let mut mask = ByteMask::whole(size_bytes);
    for byte in 0..size_bytes.min(8) {
        if (bits >> (8 * byte)) & 0xff == 0xff {
            mask = mask.intersection(ByteMask::byte(byte).complement_within(size_bytes));
        }
    }
    mask
}

/// What a sign extension from `source_bytes` reads: each byte the operand has,
/// and its top byte for every byte above it.
fn sign_extension(m: ByteMask, source_bytes: u32) -> ByteMask {
    let own = m.intersection(ByteMask::whole(source_bytes));
    if source_bytes > 0 && !m.shifted_down(source_bytes).is_empty() {
        own.union(ByteMask::byte(source_bytes - 1))
    } else {
        own
    }
}

/// Output byte `j` of a value shifted up by `bits` reads operand bits
/// `[8j - bits, 8j + 8 - bits)`: the byte `bits / 8` below it and, for a
/// shift that is not a whole number of bytes, the one below that.
fn read_below(m: ByteMask, bits: u64) -> ByteMask {
    let whole_bytes = u32::try_from(bits / 8).unwrap_or(u32::MAX).min(64);
    let straddles = !bits.is_multiple_of(8);
    let first = m.shifted_down(whole_bytes);
    if straddles {
        first.union(m.shifted_down(whole_bytes.saturating_add(1).min(64)))
    } else {
        first
    }
}

/// Output byte `j` of a value shifted down by `bits` reads operand bits
/// `[8j + bits, 8j + 8 + bits)`.
fn read_above(m: ByteMask, bits: u64) -> ByteMask {
    let whole_bytes = u32::try_from(bits / 8).unwrap_or(u32::MAX).min(64);
    let straddles = !bits.is_multiple_of(8);
    let first = m.shifted_up(whole_bytes);
    if straddles {
        first.union(m.shifted_up(whole_bytes.saturating_add(1)))
    } else {
        first
    }
}

/// `a << b`. A shift by the width or more is zero, which reads nothing of
/// `a`; by a variable amount, byte `k` reads bytes `0..=k` of `a`, and every
/// byte of the amount decides whether the width was reached.
fn shift_left(m: ByteMask, a: &SSAVar, b: &SSAVar) -> Vec<ByteMask> {
    let width_bits = u64::from(a.size) * 8;
    match b.constant_bits() {
        Some(bits) if bits >= width_bits => vec![ByteMask::NONE, ByteMask::All],
        Some(bits) => vec![read_below(m, bits), ByteMask::All],
        None => vec![m.through_highest(), ByteMask::All],
    }
}

/// `a >> b`, logical or arithmetic. A logical shift by the width or more is
/// zero; an arithmetic one is the sign, which is the top byte. By a variable
/// amount, byte `k` reads bytes `k..` of `a`, which include the top byte.
fn shift_right(m: ByteMask, a: &SSAVar, b: &SSAVar, arithmetic: bool) -> Vec<ByteMask> {
    let width = a.size;
    let width_bits = u64::from(width) * 8;
    let top = ByteMask::byte(width.saturating_sub(1));
    let value = match b.constant_bits() {
        Some(bits) if bits >= width_bits => {
            if arithmetic {
                top
            } else {
                ByteMask::NONE
            }
        }
        Some(bits) => {
            let read = read_above(m, bits).intersection(ByteMask::whole(width));
            // A demanded byte whose window reaches past the top reads the sign.
            let reaches_past = m
                .highest()
                .is_some_and(|highest| u64::from(highest) * 8 + 7 + bits >= width_bits);
            if arithmetic && reaches_past {
                read.union(top)
            } else {
                read
            }
        }
        None => m.lowest_and_above(width),
    };
    vec![value, ByteMask::All]
}

/// What the demanded bytes of `insert(root, lane, bits)` read: a byte wholly
/// inside the lane's window is the lane's, one wholly outside is the root's,
/// and one the window only partly covers is both.
fn insert_window(m: ByteMask, position_bits: u64, lane_bytes: u32) -> (ByteMask, ByteMask) {
    let ByteMask::Bytes(mut pending) = m else {
        return (ByteMask::All, ByteMask::All);
    };
    let start = position_bits;
    let end = position_bits.saturating_add(u64::from(lane_bytes) * 8);
    let (mut root, mut lane) = (0u64, 0u64);
    while pending != 0 {
        let byte = pending.trailing_zeros();
        pending &= pending - 1;
        let low = u64::from(byte) * 8;
        let high = low + 8;
        let from = low.max(start);
        let to = high.min(end);
        if from < to {
            // The lane's bytes under this one, counted from the lane's own start.
            let first = (from - start) / 8;
            let last = (to - 1 - start) / 8;
            for lane_byte in first..=last.min(63) {
                lane |= 1 << lane_byte;
            }
        }
        if !(start <= low && high <= end) {
            root |= 1 << byte;
        }
    }
    (ByteMask::Bytes(root), ByteMask::Bytes(lane))
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod kani_proofs;
