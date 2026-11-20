//! Group F: shifts by literal counts.

use r2ssa::{
    MachineArithmeticOp, MachineBitVector, MachineBitwiseOp, MachineOvershiftBehavior,
    MachineShiftKind, MachineSignedness, MachineType,
};

use super::literal::{lit, unsigned};
use super::{DEFAULT_PROOF_WIDTHS, Measure, Rule, RuleGroup, literal_like, literal_of};
use crate::term::{TermArena, TermId, TermKind};

macro_rules! shift_rule {
    ($name:ident, $id:literal, $apply:expr, $templates:expr) => {
        pub static $name: Rule = Rule {
            id: $id,
            group: RuleGroup::Shift,
            decreases: Measure::NonLeafNodes,
            apply: $apply,
            templates: $templates,
            proof_widths: DEFAULT_PROOF_WIDTHS,
            proof_note: None,
        };
    };
}

/// `Shift(kind, Shift(kind, x, a), b)` with literal counts.
fn nested(
    arena: &TermArena,
    id: TermId,
    kind: MachineShiftKind,
) -> Option<(TermId, u64, u64, TermId)> {
    match arena.term(id).kind {
        TermKind::Shift {
            kind: outer,
            value,
            count,
            ..
        } if outer == kind => {
            let b = literal_of(arena, count)?;
            match arena.term(value).kind {
                TermKind::Shift {
                    kind: inner,
                    value: x,
                    count: inner_count,
                    ..
                } if inner == kind => {
                    let a = literal_of(arena, inner_count)?;
                    Some((x, a, b, count))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn shift(arena: &mut TermArena, kind: MachineShiftKind, value: TermId, count: TermId) -> TermId {
    let ty = arena.term(value).ty;
    let overshift = match kind {
        MachineShiftKind::ArithmeticRight => MachineOvershiftBehavior::SignFill,
        _ => MachineOvershiftBehavior::Zero,
    };
    arena.intern(
        ty,
        TermKind::Shift {
            kind,
            overshift,
            value,
            count,
        },
    )
}

fn literal_count(arena: &mut TermArena, like: TermId, value: u64) -> TermId {
    let ty = arena.term(like).ty;
    let bits = MachineBitVector::new(ty.width_bits(), value).expect("count width fits a literal");
    arena.intern(ty, TermKind::Literal(bits))
}

fn compose(arena: &mut TermArena, id: TermId, kind: MachineShiftKind) -> Option<TermId> {
    let (x, a, b, count) = nested(arena, id, kind)?;
    let width = u64::from(arena.term(id).width_bits());
    let total = a.checked_add(b)?;
    let total = match kind {
        MachineShiftKind::ArithmeticRight => total.min(width - 1),
        _ => {
            if total >= width {
                return None;
            }
            total
        }
    };
    if total >= (1u64 << arena.term(count).width_bits().min(63)) {
        return None;
    }
    let count = literal_count(arena, count, total);
    Some(shift(arena, kind, x, count))
}

fn nested_template(kind: MachineShiftKind) -> impl Fn(&mut TermArena, u32, &[TermId]) -> TermId {
    move |arena, _, l| {
        let a = lit(arena, 8, 3);
        let b = lit(arena, 8, 2);
        let inner = shift(arena, kind, l[0], a);
        shift(arena, kind, inner, b)
    }
}

shift_rule!(
    SHL_SHL,
    "shift.shl_shl",
    |arena, id| compose(arena, id, MachineShiftKind::Left),
    &[|a, w, l| nested_template(MachineShiftKind::Left)(a, w, l)]
);
shift_rule!(
    LSHR_LSHR,
    "shift.lshr_lshr",
    |arena, id| compose(arena, id, MachineShiftKind::LogicalRight),
    &[|a, w, l| nested_template(MachineShiftKind::LogicalRight)(a, w, l)]
);
shift_rule!(
    ASHR_ASHR,
    "shift.ashr_ashr",
    |arena, id| compose(arena, id, MachineShiftKind::ArithmeticRight),
    &[
        |a, w, l| nested_template(MachineShiftKind::ArithmeticRight)(a, w, l),
        // Counts that sum past the width clamp to width minus one.
        |arena, _, l| {
            let a = lit(arena, 8, 60);
            let b = lit(arena, 8, 60);
            let inner = shift(arena, MachineShiftKind::ArithmeticRight, l[0], a);
            shift(arena, MachineShiftKind::ArithmeticRight, inner, b)
        },
    ]
);

fn overwidth(arena: &mut TermArena, id: TermId, kind: MachineShiftKind) -> Option<TermId> {
    match arena.term(id).kind {
        TermKind::Shift {
            kind: actual,
            overshift: MachineOvershiftBehavior::Zero,
            count,
            ..
        } if actual == kind
            && literal_of(arena, count)? >= u64::from(arena.term(id).width_bits()) =>
        {
            Some(literal_like(arena, id, 0))
        }
        _ => None,
    }
}

fn overwidth_template(kind: MachineShiftKind) -> impl Fn(&mut TermArena, u32, &[TermId]) -> TermId {
    move |arena, w, l| {
        let count = lit(arena, 8, u64::from(w));
        let _ = unsigned(w);
        shift(arena, kind, l[0], count)
    }
}

shift_rule!(
    SHL_OVERWIDTH,
    "shift.shl_overwidth",
    |arena, id| overwidth(arena, id, MachineShiftKind::Left),
    &[|a, w, l| overwidth_template(MachineShiftKind::Left)(a, w, l)]
);
shift_rule!(
    LSHR_OVERWIDTH,
    "shift.lshr_overwidth",
    |arena, id| overwidth(arena, id, MachineShiftKind::LogicalRight),
    &[|a, w, l| overwidth_template(MachineShiftKind::LogicalRight)(a, w, l)]
);

/// `x << k` with a literal `0 < k < w`, or `x * 2^k` as the affine form spells it inside a sum.
fn shifted_left(arena: &TermArena, id: TermId, w: u32, sum: bool) -> Option<(TermId, u64)> {
    let k = match arena.term(id).kind {
        TermKind::Shift {
            kind: MachineShiftKind::Left,
            value,
            count,
            ..
        } => (value, literal_of(arena, count)?),
        TermKind::Arithmetic {
            op: MachineArithmeticOp::Multiply,
            left,
            right,
        } if sum => {
            let factor = literal_of(arena, right)?;
            (
                left,
                u64::from(factor.is_power_of_two().then(|| factor.trailing_zeros())?),
            )
        }
        _ => return None,
    };
    (0 < k.1 && k.1 < u64::from(w)).then_some(k)
}

/// `x` and `k` where `high` is `x << k` and `low` is `x >> (w - k)` over one value of `ty`; the
/// two reads are two leaves, so the value is matched by what it reads, and the left read is kept.
fn complementary(
    arena: &TermArena,
    (high, low): (TermId, TermId),
    ty: MachineType,
    sum: bool,
) -> Option<(TermId, u64)> {
    let w = ty.width_bits();
    let (x, k) = shifted_left(arena, high, w, sum)?;
    let TermKind::Shift {
        kind: MachineShiftKind::LogicalRight,
        value: y,
        count,
        ..
    } = arena.term(low).kind
    else {
        return None;
    };
    let same_type = [x, y, high, low].iter().all(|id| arena.term(*id).ty == ty);
    (same_type && literal_of(arena, count)? == u64::from(w) - k && arena.same_value(x, y))
        .then_some((x, k))
}

/// The two shifted halves share no set bit, so `|`, `^` and `+` join them alike.
fn rotate(arena: &mut TermArena, id: TermId) -> Option<TermId> {
    let term = arena.term(id);
    let (left, right, sum) = match term.kind {
        TermKind::Bitwise {
            op: MachineBitwiseOp::Or | MachineBitwiseOp::Xor,
            left,
            right,
        } => (left, right, false),
        TermKind::Arithmetic {
            op: MachineArithmeticOp::Add,
            left,
            right,
        } => (left, right, true),
        _ => return None,
    };
    let MachineType::Integer {
        width_bits: 8 | 16 | 32 | 64,
        signedness: MachineSignedness::Unsigned,
    } = term.ty
    else {
        return None;
    };
    let (value, k) = complementary(arena, (left, right), term.ty, sum)
        .or_else(|| complementary(arena, (right, left), term.ty, sum))?;
    let count = literal_like(arena, id, k);
    Some(arena.intern(term.ty, TermKind::Rotate { value, count }))
}

fn rotate_template(
    join: fn(&mut TermArena, u32, TermId, TermId) -> TermId,
    k: fn(u32) -> u64,
    swapped: bool,
) -> impl Fn(&mut TermArena, u32, &[TermId]) -> TermId {
    move |arena, w, l| {
        let (high, low) = (lit(arena, 8, k(w)), lit(arena, 8, u64::from(w) - k(w)));
        let high = shift(arena, MachineShiftKind::Left, l[0], high);
        let low = shift(arena, MachineShiftKind::LogicalRight, l[0], low);
        match swapped {
            true => join(arena, w, low, high),
            false => join(arena, w, high, low),
        }
    }
}

fn bitwise(op: MachineBitwiseOp) -> impl Fn(&mut TermArena, u32, TermId, TermId) -> TermId {
    move |arena, w, left, right| arena.intern(unsigned(w), TermKind::Bitwise { op, left, right })
}

fn add(arena: &mut TermArena, w: u32, left: TermId, right: TermId) -> TermId {
    let op = MachineArithmeticOp::Add;
    arena.intern(unsigned(w), TermKind::Arithmetic { op, left, right })
}

shift_rule!(
    ROTATE,
    "shift.rotate",
    rotate,
    &[
        |a, w, l| rotate_template(
            |a, w, x, y| bitwise(MachineBitwiseOp::Or)(a, w, x, y),
            |_| 3,
            false
        )(a, w, l),
        |a, w, l| rotate_template(
            |a, w, x, y| bitwise(MachineBitwiseOp::Or)(a, w, x, y),
            |w| u64::from(w) - 1,
            true
        )(a, w, l),
        |a, w, l| rotate_template(
            |a, w, x, y| bitwise(MachineBitwiseOp::Xor)(a, w, x, y),
            |_| 1,
            true
        )(a, w, l),
        |a, w, l| rotate_template(add, |w| u64::from(w / 2), false)(a, w, l),
        // The affine form spells `x << 5` inside a sum as `x * 32`.
        |arena, w, l| {
            let factor = lit(arena, w, 32);
            let count = lit(arena, 8, u64::from(w) - 5);
            let high = arena.intern(
                unsigned(w),
                TermKind::Arithmetic {
                    op: MachineArithmeticOp::Multiply,
                    left: l[0],
                    right: factor,
                },
            );
            let low = shift(arena, MachineShiftKind::LogicalRight, l[0], count);
            add(arena, w, high, low)
        },
    ]
);
