//! Division by a constant through a multiply-high, proven exact (doc/adr-frame-model.md, extent).
//!
//! A compiler divides an `N`-bit `x` by `d` as `(zext(x) * M) >> S`, keeping the high part. That is
//! `x / d` for every `x` exactly when `2^S <= M*d <= 2^S + 2^(S-N)` (Granlund and Montgomery 1994,
//! Theorem 4.2), and then `x - d * (x / d)` is `x % d`, in `[0, d - 1]`.

use crate::graph::{InstPayload, SsaGraph, ValueId};
use crate::op::SSAOp;

/// The divisor `d` for which `x - t` is `x % d`: `t` is `d` times an exact quotient of `x` by `d`.
pub(crate) fn remainder_divisor(graph: &SsaGraph, x: ValueId, t: ValueId) -> Option<u64> {
    let (quotient, multiple) = linear_multiple(graph, t, graph.values.len())?;
    let (dividend, divisor) = exact_quotient(graph, quotient)?;
    (copied(graph, dividend) == copied(graph, x) && multiple == divisor).then_some(divisor)
}

fn op(graph: &SsaGraph, value: ValueId) -> Option<&SSAOp<ValueId>> {
    match &graph.inst(graph.def_inst(value)?)?.payload {
        InstPayload::Op(op) => Some(op),
        InstPayload::Phi { .. } => None,
    }
}

fn constant(graph: &SsaGraph, value: ValueId) -> Option<u64> {
    graph.value(value)?.var.constant_bits()
}

fn width_bits(graph: &SsaGraph, value: ValueId) -> Option<u32> {
    graph.value(value).map(|value| value.var.size * 8)
}

/// The value a run of copies forwards; each step moves to an earlier definition.
fn copied(graph: &SsaGraph, mut value: ValueId) -> ValueId {
    for _ in 0..graph.values.len() {
        match op(graph, value) {
            Some(SSAOp::Copy { src, .. }) => value = *src,
            _ => break,
        }
    }
    value
}

/// A quotient as the value shifted and the places: `h >> s`, or `(v, 0)` for any other `v`.
type Shifted = (ValueId, u64);

/// `value` as `k * q` for one `q`: `q + q + q`, `q * 3`, `(q << 1) + q`, and `h & -2^j`, which is
/// `2^j * (h >> j)`. `depth` bounds the walk.
fn linear_multiple(graph: &SsaGraph, value: ValueId, depth: usize) -> Option<(Shifted, u64)> {
    let depth = depth.checked_sub(1)?;
    let value = copied(graph, value);
    let term = |input: ValueId| linear_multiple(graph, input, depth);
    match op(graph, value) {
        Some(SSAOp::IntAdd { a, b, .. }) => {
            let ((left, j), (right, k)) = (term(*a)?, term(*b)?);
            (left == right).then_some((left, j.checked_add(k)?))
        }
        Some(SSAOp::IntMult { a, b, .. }) => match (constant(graph, *a), constant(graph, *b)) {
            (_, Some(c)) => term(*a).and_then(|(q, k)| Some((q, k.checked_mul(c)?))),
            (Some(c), _) => term(*b).and_then(|(q, k)| Some((q, k.checked_mul(c)?))),
            _ => Some(((value, 0), 1)),
        },
        Some(SSAOp::IntLeft { a, b, .. }) => {
            let places = u32::try_from(constant(graph, *b)?).ok()?;
            term(*a).and_then(|(q, k)| Some((q, k.checked_mul(1u64.checked_shl(places)?)?)))
        }
        Some(SSAOp::IntRight { a, b, .. }) => Some(((copied(graph, *a), constant(graph, *b)?), 1)),
        Some(SSAOp::IntAnd { a, b, .. }) => {
            let (h, mask) = match (constant(graph, *a), constant(graph, *b)) {
                (None, Some(mask)) => (*a, mask),
                (Some(mask), None) => (*b, mask),
                _ => return Some(((value, 0), 1)),
            };
            let places = low_clearing_places(mask, width_bits(graph, h)?)?;
            Some((
                (copied(graph, h), u64::from(places)),
                1u64.checked_shl(places)?,
            ))
        }
        _ => Some(((value, 0), 1)),
    }
}

/// The `j` for which `mask` is `-2^j` at `bits` wide: every bit from `j` up set, none below.
fn low_clearing_places(mask: u64, bits: u32) -> Option<u32> {
    let width = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let places = mask.trailing_zeros();
    (places > 0 && places < bits && mask & width == width & (u64::MAX << places)).then_some(places)
}

/// `h >> s` as `x / d`, from `h = trunc_N((zext_2N(x) * M) >> N)` with the exactness condition.
fn exact_quotient(graph: &SsaGraph, (high, shift): Shifted) -> Option<(ValueId, u64)> {
    let high = copied(graph, high);
    let (high, shift) = match (shift, op(graph, high)) {
        (0, Some(SSAOp::IntRight { a, b, .. })) => (copied(graph, *a), constant(graph, *b)?),
        _ => (high, shift),
    };
    let Some(SSAOp::Subpiece { src, offset, .. }) = op(graph, high) else {
        return None;
    };
    let n = width_bits(graph, high)?;
    let product = copied(graph, *src);
    if width_bits(graph, product)? != 2 * n || offset.checked_mul(8)? != n || n > 64 {
        return None;
    }
    let Some(SSAOp::IntMult { a, b, .. }) = op(graph, product) else {
        return None;
    };
    let (widened, magic) = match (constant(graph, *a), constant(graph, *b)) {
        (None, Some(magic)) => (*a, magic),
        (Some(magic), None) => (*b, magic),
        _ => return None,
    };
    let Some(SSAOp::IntZExt { src: x, .. }) = op(graph, copied(graph, widened)) else {
        return None;
    };
    if width_bits(graph, *x)? != n {
        return None;
    }
    let divisor = exact_divisor(magic, n, n.checked_add(u32::try_from(shift).ok()?)?)?;
    Some((*x, divisor))
}

/// The `d` for which `floor(x * magic / 2^s) = floor(x / d)` for every `n`-bit `x`, by Theorem 4.2.
pub(crate) fn exact_divisor(magic: u64, n: u32, s: u32) -> Option<u64> {
    if magic == 0 || n == 0 || n > 64 || s < n || s > 127 {
        return None;
    }
    let (magic, power) = (u128::from(magic), 1u128 << s);
    let divisor = power.div_ceil(magic);
    let product = magic.checked_mul(divisor)?;
    let slack = 1u128 << (s - n);
    (product >= power && product <= power.checked_add(slack)?)
        .then(|| u64::try_from(divisor).ok())
        .flatten()
        .filter(|divisor| *divisor > 0)
}

#[cfg(test)]
mod tests {
    use super::{exact_divisor, low_clearing_places};

    /// Every condition the rule accepts at eight bits divides every eight-bit value exactly.
    #[test]
    fn an_accepted_magic_divides_every_eight_bit_value_exactly() {
        let mut accepted = 0;
        for magic in 1u64..=255 {
            for s in 8u32..=15 {
                let Some(d) = exact_divisor(magic, 8, s) else {
                    continue;
                };
                accepted += 1;
                for x in 0u64..=255 {
                    assert_eq!((x * magic) >> s, x / d, "M={magic} s={s} d={d} x={x}");
                }
            }
        }
        assert!(accepted > 100, "{accepted}");
    }

    /// `h & -2^j` is `2^j * (h >> j)` only for a mask with every bit from `j` up.
    #[test]
    fn a_low_clearing_mask_names_its_places() {
        assert_eq!(low_clearing_places(0xffff_ffff_ffff_fffe, 64), Some(1));
        assert_eq!(low_clearing_places(0xffff_fff8, 32), Some(3));
        assert_eq!(low_clearing_places(0x7fff_ffff_ffff_fffe, 64), None);
        assert_eq!(low_clearing_places(u64::MAX, 64), None);
    }

    /// gcc's `% 3` at sixty-four bits: `M = 0xaaaaaaaaaaaaaaab`, shifted by 65.
    #[test]
    fn gcc_s_divide_by_three_is_exact() {
        assert_eq!(exact_divisor(0xaaaa_aaaa_aaaa_aaab, 64, 65), Some(3));
        assert_eq!(exact_divisor(0xaaaa_aaaa_aaaa_aaab, 64, 64), None);
    }
}
