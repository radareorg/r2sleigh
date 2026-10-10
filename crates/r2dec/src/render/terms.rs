//! D3: a canonical term as C (doc/adr-decompiler-rewrite.md). An integer is spelled unsigned at its
//! width so the C wraps as the machine does; a node with no exact C spelling answers `None`.

use r2rewrite::{LeafRead, TermArena, TermId, TermKind};
use r2ssa::{
    MachineArithmeticFlagOp, MachineArithmeticMode, MachineArithmeticOp, MachineBitVector,
    MachineBitwiseOp, MachineBooleanOp, MachineCastKind, MachineComparisonOp, MachineExprId,
    MachineExprKind, MachineFloatOp, MachineFloatUnaryOp, MachineOvershiftBehavior,
    MachineProjection, MachineShiftKind, MachineSignedness, MachineType, ObjectId, ValueId,
};
use r2types::Signedness;

use crate::ast::{BinaryOp, CExpr, CType, UnaryOp};
use crate::prelude::{FlagOp, FloatOp, Helper, ResidualType};

/// What a term's leaves and objects read as: the variable a bound value is, an object's address.
pub(super) struct Spell<'a> {
    pub(super) projection: &'a MachineProjection,
    pub(super) arena: &'a TermArena,
    /// The variable a value is held in, where it is held at a type C reads as this one.
    pub(super) bound: &'a dyn Fn(ValueId, &MachineType) -> Option<CExpr>,
    /// Where a frame object lies in the frame array.
    pub(super) object: &'a dyn Fn(ObjectId) -> Option<Placed>,
    /// The object the program names at a literal address, read (`false`) or written as a class.
    pub(super) global: &'a dyn Fn(u64, &MachineType, bool) -> Option<super::globals::Named>,
    /// Whether memory is little-endian, so a byte copy reads a word as the machine does.
    pub(super) little_endian: bool,
    /// The slot the caller pushed the return address into, never written here, and the address width.
    pub(super) return_address: Option<(ObjectId, u32)>,
}

/// A frame object's address in the frame array and its extent.
pub(super) struct Placed {
    pub(super) base: CExpr,
    pub(super) extent: u32,
}

/// The C type a machine type is spelled in: an unsigned integer, or `float` or `double`.
pub(super) fn c_type(ty: &MachineType) -> Option<CType> {
    match ty {
        MachineType::Float {
            width_bits: 32 | 64,
        } => Some(CType::Float(ty.width_bits())),
        MachineType::Float { .. } => None,
        _ if wide(ty.width_bits()) => Some(CType::BitVector(ty.width_bits())),
        _ => integer(ty.width_bits()),
    }
}

/// Whether `bits` is a carrier no C integer holds: a struct `crate::bitvector` defines, which C
/// only assigns and selects, and its helpers take apart, compose and zero-extend.
pub(super) fn wide(bits: u32) -> bool {
    crate::bitvector::is_supported(bits)
}

/// `field_bits` of the wide `input` at bit `lsb`.
pub(super) fn wide_extract(carrier: u32, field: u32, input: CExpr, lsb: u32) -> Option<CExpr> {
    let helper = crate::bitvector::BitVectorHelper::extract(carrier, field)?;
    Some(helper.call(vec![input, CExpr::UIntLit(u64::from(lsb))]))
}

/// The integer `field`, `field_bits` wide, zero-extended to the `carrier`.
pub(super) fn wide_zero_extend(field_bits: u32, carrier: u32, field: CExpr) -> Option<CExpr> {
    let helper = crate::bitvector::BitVectorHelper::zero_extend(field_bits, carrier)?;
    Some(helper.call(vec![cast(integer(field_bits)?, field)]))
}

fn integer(bits: u32) -> Option<CType> {
    matches!(bits, 8 | 16 | 32 | 64 | 128).then_some(CType::Int {
        bits,
        signedness: Signedness::Unsigned,
    })
}

fn signed(bits: u32) -> Option<CType> {
    matches!(bits, 8 | 16 | 32 | 64 | 128).then_some(CType::Int {
        bits,
        signedness: Signedness::Signed,
    })
}

/// The width an integer operation is computed at: never narrower than `int`, so promotion cannot overflow.
fn computed(bits: u32) -> u32 {
    bits.max(32)
}

fn cast(ty: CType, expr: CExpr) -> CExpr {
    CExpr::cast(ty, expr)
}

fn binary(op: BinaryOp, left: CExpr, right: CExpr) -> CExpr {
    CExpr::binary(op, left, right)
}

/// A machine integer constant of `bits`, spelled in its own type.
pub(super) fn literal(value: MachineBitVector) -> Option<CExpr> {
    let ty = integer(value.width_bits())?;
    Some(cast(ty, CExpr::UIntLit(value.bits())))
}

/// `expr` converted to `sink` as by assignment (return, assignment, prototyped argument): an
/// integer literal under value-keeping unsigned casts becomes the plain literal.
pub(super) fn at_sink(sink: &CType, expr: CExpr) -> CExpr {
    let holds = |ty: &CType, value: u64| match ty {
        CType::Int { bits, signedness } => {
            let bits = bits - u32::from(*signedness == Signedness::Signed);
            bits >= 64 || value < 1 << bits
        }
        _ => false,
    };
    let (mut casts, mut ids) = (Vec::new(), expr.observation_ids().into_owned());
    let mut inner = expr.unobserved();
    let value = loop {
        match inner {
            CExpr::Cast { ty, expr, .. } => {
                casts.push(ty);
                ids.extend(expr.observation_ids().iter().copied());
                inner = expr.unobserved();
            }
            CExpr::UIntLit(value) => break *value,
            CExpr::IntLit(value) if *value >= 0 => break value.unsigned_abs(),
            _ => return expr,
        }
    };
    let unsigned = |ty: &CType| {
        matches!(
            ty,
            CType::Int {
                signedness: Signedness::Unsigned,
                ..
            }
        )
    };
    let kept = casts.iter().all(|ty| unsigned(ty) && holds(ty, value));
    if !kept || !holds(sink, value) || value > i32::MAX as u64 {
        return expr;
    }
    CExpr::observe_all(ids, CExpr::IntLit(value as i64))
}

/// The address the call into this function returns to, which its caller pushed (r2ssa's
/// `return_address_stack_object`).
fn return_address() -> CExpr {
    CExpr::call(
        CExpr::External {
            name: "__builtin_return_address".to_string(),
            kind: crate::symbol::ExternalKind::Intrinsic,
        },
        vec![CExpr::UIntLit(0)],
    )
}

/// A constant read as `ty`: a float's bits reinterpreted, since C would convert an integer's value.
fn literal_as(value: MachineBitVector, ty: &MachineType) -> Option<CExpr> {
    // A wide constant holds at most 64 set bits, its low ones.
    if wide(value.width_bits()) {
        return wide_zero_extend(64, value.width_bits(), CExpr::UIntLit(value.bits()));
    }
    let bits = literal(value)?;
    match ty {
        MachineType::Float { width_bits } if *width_bits == value.width_bits() => {
            Some(Helper::float_from_bits(*width_bits)?.call(vec![bits]))
        }
        MachineType::Float { .. } => None,
        _ => Some(bits),
    }
}

/// `condition ? if_true : if_false` at `ty`; a wide carrier is a struct, which C selects uncast.
fn select(ty: &MachineType, condition: CExpr, if_true: CExpr, if_false: CExpr) -> Option<CExpr> {
    let arm = |expr: CExpr| -> Option<CExpr> {
        Some(match wide(ty.width_bits()) {
            true => expr,
            false => cast(c_type(ty)?, expr),
        })
    };
    Some(CExpr::Ternary {
        cond: Box::new(condition),
        then_expr: Box::new(arm(if_true)?),
        else_expr: Box::new(arm(if_false)?),
    })
}

/// `value`'s low `bits` as an unsigned literal of that width; a 128-bit one is spelled from halves.
fn wide_literal(bits: u32, value: u128) -> Option<CExpr> {
    let ty = integer(bits)?;
    if bits <= 64 {
        return Some(cast(ty, CExpr::UIntLit(value as u64)));
    }
    let high = binary(
        BinaryOp::Shl,
        cast(ty.clone(), CExpr::UIntLit((value >> 64) as u64)),
        CExpr::UIntLit(64),
    );
    Some(cast(
        ty.clone(),
        binary(
            BinaryOp::BitOr,
            high,
            cast(ty, CExpr::UIntLit(value as u64)),
        ),
    ))
}

/// `root`, `bits` wide, with `lane` written over its bits `lsb..lsb + width`.
fn insert_lane(bits: u32, (lsb, width): (u32, u32), root: CExpr, lane: CExpr) -> Option<CExpr> {
    if wide(bits) {
        let insert = crate::bitvector::BitVectorHelper::insert(bits, width)?;
        let lane = cast(integer(width)?, lane);
        return Some(insert.call(vec![root, lane, CExpr::UIntLit(u64::from(lsb))]));
    }
    let end = lsb.checked_add(width)?;
    if width == 0 || end > bits || bits > 128 {
        return None;
    }
    let ty = integer(bits)?;
    let full = |n: u32| {
        if n >= 128 {
            u128::MAX
        } else {
            (1u128 << n) - 1
        }
    };
    let hole = full(bits) & !(full(width) << lsb);
    let kept = binary(
        BinaryOp::BitAnd,
        cast(ty.clone(), root),
        wide_literal(bits, hole)?,
    );
    let written = binary(
        BinaryOp::BitAnd,
        cast(ty.clone(), lane),
        wide_literal(bits, full(width))?,
    );
    let placed = binary(BinaryOp::Shl, written, CExpr::UIntLit(u64::from(lsb)));
    Some(cast(ty, binary(BinaryOp::BitOr, kept, placed)))
}

/// An integer as the unsigned word of `bits`, the width an address is held at.
pub(super) fn fit_integer(expr: CExpr, bits: u32) -> Option<CExpr> {
    Some(cast(integer(bits)?, expr))
}

/// One operator over two operands of `bits`: computed unsigned at least `int` wide, then narrowed.
fn wrapping(op: BinaryOp, bits: u32, left: CExpr, right: CExpr) -> Option<CExpr> {
    let wide = integer(computed(bits))?;
    let sum = binary(op, cast(wide.clone(), left), cast(wide, right));
    Some(cast(integer(bits)?, sum))
}

fn comparison(op: MachineComparisonOp) -> BinaryOp {
    match op {
        MachineComparisonOp::Equal => BinaryOp::Eq,
        MachineComparisonOp::NotEqual => BinaryOp::Ne,
        MachineComparisonOp::LessThan => BinaryOp::Lt,
        MachineComparisonOp::LessThanOrEqual => BinaryOp::Le,
    }
}

/// `0 - x` at `bits`, wrapping as the machine does.
fn negate(bits: u32, x: CExpr) -> Option<CExpr> {
    let zero = cast(integer(bits)?, CExpr::UIntLit(0));
    wrapping(BinaryOp::Sub, bits, zero, x)
}

/// `~x` at `bits`, computed no narrower than `int`.
fn bitwise_not(bits: u32, x: CExpr) -> Option<CExpr> {
    let inverted = CExpr::unary(UnaryOp::BitNot, cast(integer(computed(bits))?, x));
    Some(cast(integer(bits)?, inverted))
}

/// A boolean's negation: its low bit flipped.
fn boolean_not(bits: u32, x: CExpr) -> Option<CExpr> {
    let one = cast(integer(bits)?, CExpr::UIntLit(1));
    wrapping(BinaryOp::BitXor, bits, x, one)
}

/// `bits` of a `wide`-bit `input` from bit `lsb`.
fn extract((wide, bits): (u32, u32), input: CExpr, lsb: u32) -> Option<CExpr> {
    if self::wide(wide) {
        return wide_extract(wide, bits, input, lsb);
    }
    let shifted = binary(
        BinaryOp::Shr,
        cast(integer(wide)?, input),
        CExpr::UIntLit(u64::from(lsb)),
    );
    Some(cast(integer(bits)?, shifted))
}

/// A float comparison, as a byte holding 0 or 1.
fn float_compare(op: MachineComparisonOp, bits: u32, left: CExpr, right: CExpr) -> Option<CExpr> {
    let test = binary(comparison(op), left, right);
    Some(cast(integer(bits)?, test))
}

/// A quotient or remainder at `bits` under `interpretation`, each operand with its literal value.
fn divide(
    (op, interpretation): (BinaryOp, MachineSignedness),
    bits: u32,
    (dividend, dividend_literal): (CExpr, Option<u128>),
    (divisor, divisor_literal): (CExpr, Option<u128>),
) -> Option<CExpr> {
    let ty = integer(bits)?;
    let operand = match interpretation {
        MachineSignedness::Signed => signed(bits)?,
        MachineSignedness::Unsigned => ty.clone(),
    };
    let (minimum, all) = (1u128 << (bits - 1), u128::MAX >> (128 - bits));
    let guarded = interpretation == MachineSignedness::Signed
        && dividend_literal.is_none_or(|value| value == minimum)
        && divisor_literal.is_none_or(|value| value == all);
    let tested = (
        dividend.clone_without_render_observations(),
        divisor.clone_without_render_observations(),
    );
    let quotient = binary(op, cast(operand.clone(), dividend), cast(operand, divisor));
    let quotient = cast(ty.clone(), quotient);
    if !guarded {
        return Some(quotient);
    }
    // r2il::eval gives MIN / -1 no value and MIN % -1 the value 0; C leaves both undefined.
    let (dividend, divisor) = tested;
    let minimum = binary(
        BinaryOp::Eq,
        cast(ty.clone(), dividend),
        wide_literal(bits, minimum)?,
    );
    let minus_one = binary(
        BinaryOp::Eq,
        cast(ty.clone(), divisor),
        wide_literal(bits, all)?,
    );
    let (test, arm) = match op {
        BinaryOp::Div => (
            binary(BinaryOp::And, minimum, minus_one),
            crate::prelude::residual(&ty, crate::prelude::ResidualCause::UndefinedQuotient)?,
        ),
        _ => (minus_one, wide_literal(bits, 0)?),
    };
    Some(CExpr::Ternary {
        cond: Box::new(test),
        then_expr: Box::new(arm),
        else_expr: Box::new(quotient),
    })
}

/// A comparison of two `bits`-wide operands under `interpretation`, as a byte holding 0 or 1.
fn compare(
    (op, interpretation): (MachineComparisonOp, MachineSignedness),
    (bits, result_bits): (u32, u32),
    left: CExpr,
    right: CExpr,
) -> Option<CExpr> {
    let operand = match interpretation {
        MachineSignedness::Signed => signed(bits)?,
        MachineSignedness::Unsigned => integer(bits)?,
    };
    let test = binary(
        comparison(op),
        cast(operand.clone(), left),
        cast(operand, right),
    );
    Some(cast(integer(result_bits)?, test))
}

/// A shift of a `bits`-wide value, with the machine's answer where the count reaches the width.
fn shift(
    kind: MachineShiftKind,
    overshift: MachineOvershiftBehavior,
    (bits, count_bits): (u32, u32),
    value: CExpr,
    count: CExpr,
) -> Option<CExpr> {
    let ty = integer(bits)?;
    let wide = integer(computed(bits))?;
    // The count keeps its own width, so a count past the value's width is never truncated into it.
    let counted = integer(computed(bits.max(count_bits)))?;
    let count = cast(counted.clone(), count);
    let width = cast(counted.clone(), CExpr::UIntLit(u64::from(bits)));
    let count = match overshift {
        MachineOvershiftBehavior::MaskCount if bits.is_power_of_two() => binary(
            BinaryOp::BitAnd,
            count,
            cast(counted, CExpr::UIntLit(u64::from(bits - 1))),
        ),
        MachineOvershiftBehavior::MaskCount | MachineOvershiftBehavior::Checked => return None,
        MachineOvershiftBehavior::Zero | MachineOvershiftBehavior::SignFill => count,
    };
    let shifted = match kind {
        MachineShiftKind::Left => cast(
            ty.clone(),
            binary(BinaryOp::Shl, cast(wide, value.clone()), count.clone()),
        ),
        MachineShiftKind::LogicalRight => cast(
            ty.clone(),
            binary(BinaryOp::Shr, cast(wide, value.clone()), count.clone()),
        ),
        MachineShiftKind::ArithmeticRight => {
            let sty = signed(bits)?;
            let swide = signed(computed(bits))?;
            let value = cast(swide, cast(sty, value.clone()));
            cast(ty.clone(), binary(BinaryOp::Shr, value, count.clone()))
        }
    };
    let past = match (overshift, kind) {
        (MachineOvershiftBehavior::MaskCount, _) => return Some(shifted),
        (MachineOvershiftBehavior::SignFill, MachineShiftKind::ArithmeticRight) => {
            let negative = binary(
                BinaryOp::Lt,
                cast(signed(bits)?, value),
                cast(signed(bits)?, CExpr::UIntLit(0)),
            );
            CExpr::Ternary {
                cond: Box::new(negative),
                then_expr: Box::new(cast(ty.clone(), CExpr::UIntLit(u64::MAX))),
                else_expr: Box::new(cast(ty, CExpr::UIntLit(0))),
            }
        }
        _ => cast(ty, CExpr::UIntLit(0)),
    };
    // The count is tested before the shift runs, so C never shifts by its width or more.
    Some(CExpr::Ternary {
        cond: Box::new(binary(BinaryOp::Ge, count, width)),
        then_expr: Box::new(past),
        else_expr: Box::new(shifted),
    })
}

/// A flag of two `bits`-wide operands, as a `result_bits` integer holding 0 or 1.
fn flag_at(
    op: MachineArithmeticFlagOp,
    (bits, result_bits): (u32, u32),
    left: CExpr,
    right: CExpr,
) -> Option<CExpr> {
    Some(cast(integer(result_bits)?, flag(op, bits, left, right)?))
}

fn flag(op: MachineArithmeticFlagOp, bits: u32, left: CExpr, right: CExpr) -> Option<CExpr> {
    let op = match op {
        MachineArithmeticFlagOp::UnsignedCarry => FlagOp::Carry,
        MachineArithmeticFlagOp::SignedCarry => FlagOp::SignedCarry,
        MachineArithmeticFlagOp::SignedBorrow => FlagOp::SignedBorrow,
    };
    let ty = integer(bits)?;
    Some(Helper::flag(op, bits)?.call(vec![cast(ty.clone(), left), cast(ty, right)]))
}

/// A cast of a value of `from` to `to`.
fn convert(
    kind: MachineCastKind,
    from: &MachineType,
    to: &MachineType,
    input: CExpr,
) -> Option<CExpr> {
    let (from_bits, to_bits) = (from.width_bits(), to.width_bits());
    match kind {
        MachineCastKind::ZeroExtend if wide(to_bits) => wide_zero_extend(from_bits, to_bits, input),
        MachineCastKind::ZeroExtend
        | MachineCastKind::IntegerToAddress
        | MachineCastKind::AddressToInteger => {
            Some(cast(integer(to_bits)?, cast(integer(from_bits)?, input)))
        }
        MachineCastKind::SignExtend => Some(cast(
            integer(to_bits)?,
            cast(signed(to_bits)?, cast(signed(from_bits)?, input)),
        )),
        MachineCastKind::BitReinterpret => match (from, to) {
            (MachineType::Float { .. }, MachineType::Float { .. }) => None,
            (MachineType::Float { .. }, _) if from_bits == to_bits => {
                Some(Helper::float_to_bits(from_bits)?.call(vec![input]))
            }
            (_, MachineType::Float { .. }) if from_bits == to_bits => {
                Some(Helper::float_from_bits(to_bits)?.call(vec![cast(integer(from_bits)?, input)]))
            }
            _ if from_bits == to_bits => Some(cast(integer(to_bits)?, input)),
            _ => None,
        },
        MachineCastKind::IntegerToFloat => Some(cast(c_type(to)?, cast(signed(from_bits)?, input))),
        MachineCastKind::FloatToFloat => Some(cast(c_type(to)?, input)),
        // Out of range C leaves it undefined, so that arm is a residual; a term has no effect.
        MachineCastKind::FloatToInteger => Some(cast(
            integer(to_bits)?,
            crate::prelude::guarded_truncation(input, from_bits, to_bits)?,
        )),
    }
}

fn float_binary(op: MachineFloatOp, left: CExpr, right: CExpr) -> CExpr {
    let op = match op {
        MachineFloatOp::Add => BinaryOp::Add,
        MachineFloatOp::Subtract => BinaryOp::Sub,
        MachineFloatOp::Multiply => BinaryOp::Mul,
        MachineFloatOp::Divide => BinaryOp::Div,
    };
    binary(op, left, right)
}

fn float_unary(
    op: MachineFloatUnaryOp,
    bits: u32,
    result: &MachineType,
    input: CExpr,
) -> Option<CExpr> {
    let helper = match op {
        MachineFloatUnaryOp::Negate => return Some(CExpr::unary(UnaryOp::Neg, input)),
        MachineFloatUnaryOp::Absolute => FloatOp::Absolute,
        MachineFloatUnaryOp::SquareRoot => FloatOp::SquareRoot,
        MachineFloatUnaryOp::Ceiling => FloatOp::Ceiling,
        MachineFloatUnaryOp::Floor => FloatOp::Floor,
        MachineFloatUnaryOp::Round => FloatOp::Round,
        MachineFloatUnaryOp::IsNan => {
            let call = Helper::float(FloatOp::IsNan, bits)?.call(vec![input]);
            return Some(cast(integer(result.width_bits())?, call));
        }
    };
    Some(Helper::float(helper, bits)?.call(vec![input]))
}

fn arithmetic(op: MachineArithmeticOp) -> BinaryOp {
    match op {
        MachineArithmeticOp::Add => BinaryOp::Add,
        MachineArithmeticOp::Subtract => BinaryOp::Sub,
        MachineArithmeticOp::Multiply => BinaryOp::Mul,
    }
}

fn bitwise(op: MachineBitwiseOp) -> BinaryOp {
    match op {
        MachineBitwiseOp::And => BinaryOp::BitAnd,
        MachineBitwiseOp::Or => BinaryOp::BitOr,
        MachineBitwiseOp::Xor => BinaryOp::BitXor,
    }
}

fn boolean(op: MachineBooleanOp, bits: u32, left: CExpr, right: CExpr) -> Option<CExpr> {
    let op = match op {
        MachineBooleanOp::And => BinaryOp::BitAnd,
        MachineBooleanOp::Or => BinaryOp::BitOr,
        MachineBooleanOp::Xor => BinaryOp::BitXor,
    };
    wrapping(op, bits, left, right)
}

/// `high` above `low`, as one integer of their summed widths.
fn concat(bits: u32, low_bits: u32, high: CExpr, low: CExpr) -> Option<CExpr> {
    if wide(bits) {
        let insert = crate::bitvector::BitVectorHelper::insert(bits, bits.checked_sub(low_bits)?)?;
        let low = wide_zero_extend(low_bits, bits, low)?;
        return Some(insert.call(vec![low, high, CExpr::UIntLit(u64::from(low_bits))]));
    }
    let ty = integer(bits)?;
    let high = binary(
        BinaryOp::Shl,
        cast(ty.clone(), high),
        CExpr::UIntLit(u64::from(low_bits)),
    );
    Some(cast(
        ty.clone(),
        binary(BinaryOp::BitOr, high, cast(ty, low)),
    ))
}

/// `expr`, of machine type `from`, as `to`: the same C value, or the same bits read as the other
/// class. A C cast between a float and an integer converts the value, so it never stands for this.
pub(super) fn reclass(expr: CExpr, from: &MachineType, to: &MachineType) -> Option<CExpr> {
    if c_type(from)? == c_type(to)? {
        return Some(expr);
    }
    match (from, to) {
        (MachineType::Float { width_bits }, to) if to.width_bits() == *width_bits => {
            Some(Helper::float_to_bits(*width_bits)?.call(vec![expr]))
        }
        (from, MachineType::Float { width_bits }) if from.width_bits() == *width_bits => {
            Some(Helper::float_from_bits(*width_bits)?.call(vec![expr]))
        }
        _ => None,
    }
}

/// A literal read as signed at its own width: a frame offset or index below its base is negative.
fn signed_literal(arena: &TermArena, id: TermId) -> Option<i64> {
    match arena.term(id).kind {
        TermKind::Literal(value) => {
            let shift = 64u32.checked_sub(value.width_bits())?;
            Some(((value.bits() << shift) as i64) >> shift)
        }
        _ => None,
    }
}

/// A frame object's address plus a literal offset, as `(object, offset)`.
fn frame_offset(arena: &TermArena, id: TermId) -> Option<(ObjectId, i64)> {
    let signed = |id: TermId| signed_literal(arena, id);
    let object = |id: TermId| match arena.term(id).kind {
        TermKind::ObjectAddress(object) => Some(object),
        _ => None,
    };
    match arena.term(id).kind {
        TermKind::ObjectAddress(object) => Some((object, 0)),
        TermKind::Arithmetic {
            op: MachineArithmeticOp::Add,
            left,
            right,
        } => object(left)
            .zip(signed(right))
            .or_else(|| object(right).zip(signed(left))),
        TermKind::Arithmetic {
            op: MachineArithmeticOp::Subtract,
            left,
            right,
        } => object(left).zip(signed(right)?.checked_neg()),
        _ => None,
    }
}

/// Whether `bytes` at `offset` lie inside an object of `extent` bytes.
fn inside(offset: i64, bytes: u32, extent: u32) -> bool {
    offset >= 0
        && offset
            .checked_add(i64::from(bytes))
            .is_some_and(|end| end <= i64::from(extent))
}

impl Spell<'_> {
    /// The frame objects a term's address arithmetic starts from.
    fn objects_named(&self, root: TermId) -> Vec<ObjectId> {
        let mut named = Vec::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            match self.arena.term(id).kind {
                TermKind::ObjectAddress(object) => named.push(object),
                kind => stack.extend(kind.children()),
            }
        }
        named.sort_unstable();
        named.dedup();
        named
    }

    /// Whether an address computed into the frame may be spelled: it names no frame object, or one
    /// placed object, the access's own where it states one (ADR "D4's frame", computed indices).
    fn computed_into_frame(&self, id: TermId, object: Option<ObjectId>) -> bool {
        match self.objects_named(id).as_slice() {
            [] => true,
            [named] => {
                object.is_none_or(|object| object == *named) && (self.object)(*named).is_some()
            }
            _ => false,
        }
    }

    /// The address of element `index` of `bytes` each from `base`: a literal index into a frame
    /// object is held to its extent, a computed one to its proven layout.
    pub(super) fn subscript(
        &self,
        (base, index): (TermId, TermId),
        bytes: u32,
        object: Option<ObjectId>,
    ) -> Option<CExpr> {
        let literal_index = signed_literal(self.arena, index);
        if let (Some((named, offset)), Some(element)) =
            (frame_offset(self.arena, base), literal_index)
        {
            let at = element.checked_mul(i64::from(bytes))?.checked_add(offset)?;
            let placed = (self.object)(named)?;
            if object.is_some_and(|object| object != named) || !inside(at, bytes, placed.extent) {
                return None;
            }
            let ty = integer(self.arena.term(base).ty.width_bits())?;
            return Some(binary(
                BinaryOp::Add,
                cast(ty.clone(), placed.base),
                cast(ty, CExpr::UIntLit(at as u64)),
            ));
        }
        if !self.computed_into_frame(base, object) {
            return None;
        }
        let wide = integer(self.arena.term(base).ty.width_bits())?;
        let step = CExpr::UIntLit(u64::from(bytes));
        let offset = binary(BinaryOp::Mul, cast(wide.clone(), self.term(index)?), step);
        let base = match self.named_base(base) {
            Some(named) => named,
            None => self.term(base)?,
        };
        Some(binary(BinaryOp::Add, cast(wide, base), offset))
    }

    /// A literal base at the exact address of an object the program names: that object's address,
    /// so an index off it stays in the object wherever the program's does (ADR "D4's frame").
    fn named_base(&self, id: TermId) -> Option<CExpr> {
        let TermKind::Literal(value) = self.arena.term(id).kind else {
            return None;
        };
        let byte = MachineType::Integer {
            width_bits: 8,
            signedness: r2ssa::MachineSignedness::Unsigned,
        };
        let named = (self.global)(value.bits(), &byte, false)?;
        Some(cast(
            integer(self.arena.term(id).ty.width_bits())?,
            named.address,
        ))
    }

    /// A computed address one of whose summands is a named object's exact address, spelled off it.
    fn off_named(&self, id: TermId) -> Option<CExpr> {
        let TermKind::Arithmetic {
            op: MachineArithmeticOp::Add,
            left,
            right,
        } = self.arena.term(id).kind
        else {
            return None;
        };
        let (base, rest) = match self.named_base(right) {
            Some(base) => (base, left),
            None => (self.named_base(left)?, right),
        };
        let ty = integer(self.arena.term(id).ty.width_bits())?;
        Some(binary(BinaryOp::Add, cast(ty, self.term(rest)?), base))
    }

    /// The address `bytes` are read or written at. A frame address is spelled only inside the
    /// extent of the object the access belongs to, so the C never reaches past its array.
    pub(super) fn address(
        &self,
        id: TermId,
        bytes: u32,
        object: Option<ObjectId>,
    ) -> Option<CExpr> {
        let Some((named, offset)) = frame_offset(self.arena, id) else {
            if !self.computed_into_frame(id, object) {
                return None;
            }
            return self.off_named(id).or_else(|| self.term(id));
        };
        let placed = (self.object)(named)?;
        if object.is_some_and(|object| object != named) || !inside(offset, bytes, placed.extent) {
            return None;
        }
        let ty = integer(self.arena.term(id).ty.width_bits())?;
        let base = cast(ty.clone(), placed.base);
        Some(match offset {
            0 => base,
            offset => binary(BinaryOp::Add, base, cast(ty, CExpr::UIntLit(offset as u64))),
        })
    }

    /// A read of `ty` at the integer `address`, by a byte copy so C reads it as the machine does.
    fn load(&self, ty: &MachineType, address: CExpr) -> Option<CExpr> {
        let named = crate::literal_value(&address).and_then(|at| (self.global)(at, ty, false));
        let address = match named {
            Some(super::globals::Named {
                object: Some((object, declared)),
                ..
            }) => return super::calls::from_declared(object, &declared, ty),
            Some(named) => named.address,
            None => address,
        };
        if !self.little_endian {
            return None;
        }
        let pointer = cast(CType::Pointer(Box::new(CType::Void)), address);
        match c_type(ty)? {
            CType::BitVector(bits) => {
                Some(crate::bitvector::BitVectorHelper::load(bits)?.call(vec![pointer]))
            }
            ty => Some(Helper::Load(ResidualType::of(&ty)?).call(vec![pointer])),
        }
    }

    /// A read of `ty` from `object` at `address`; the caller's return-address slot reads as that
    /// address.
    fn load_of(&self, ty: &MachineType, object: ObjectId, address: TermId) -> Option<CExpr> {
        let bits = ty.width_bits();
        if self.return_address == Some((object, bits))
            && frame_offset(self.arena, address) == Some((object, 0))
        {
            return Some(cast(integer(bits)?, return_address()));
        }
        self.load(ty, self.address(address, bits / 8, Some(object))?)
    }

    /// A machine expression a term reads at `ty`: the projection may hold the same bits at the
    /// other class than the term reads them.
    fn leaf(&self, expr: MachineExprId, ty: &MachineType) -> Option<CExpr> {
        let held = *self.projection.expr(expr)?.ty();
        reclass(self.machine(expr)?, &held, ty)
    }

    /// The term as C of its own machine type; `None` where C has no exact spelling of it.
    pub(super) fn term(&self, id: TermId) -> Option<CExpr> {
        let node = self.arena.term(id);
        let ty = node.ty;
        let bits = ty.width_bits();
        let child = |id: TermId| self.term(id);
        let child_bits = |id: TermId| self.arena.term(id).ty.width_bits();
        match node.kind {
            TermKind::Leaf(LeafRead { expr, .. }) | TermKind::Opaque(expr) => self.leaf(expr, &ty),
            TermKind::Literal(value) => literal_as(value, &ty),
            TermKind::Variable(_) => None,
            // A frame address may be held or passed: every place it reaches is a byte of the one array.
            TermKind::ObjectAddress(object) => {
                Some(cast(integer(bits)?, (self.object)(object)?.base))
            }
            TermKind::Load { object, address } => self.load_of(&ty, object, address),
            TermKind::Subscript { base, index } => {
                self.load(&ty, self.subscript((base, index), bits / 8, None)?)
            }
            TermKind::Arithmetic { op, left, right } => {
                wrapping(arithmetic(op), bits, child(left)?, child(right)?)
            }
            TermKind::Negate(input) => negate(bits, child(input)?),
            TermKind::Bitwise { op, left, right } => {
                wrapping(bitwise(op), bits, child(left)?, child(right)?)
            }
            TermKind::BitwiseNot(input) => bitwise_not(bits, child(input)?),
            TermKind::Boolean { op, left, right } => boolean(op, bits, child(left)?, child(right)?),
            TermKind::BooleanNot(input) => boolean_not(bits, child(input)?),
            TermKind::Shift {
                kind,
                overshift,
                value,
                count,
            } => shift(
                kind,
                overshift,
                (bits, child_bits(count)),
                child(value)?,
                child(count)?,
            ),
            TermKind::Compare {
                op,
                interpretation,
                left,
                right,
            } => compare(
                (op, interpretation),
                (child_bits(left), bits),
                child(left)?,
                child(right)?,
            ),
            TermKind::Flag { op, left, right } => {
                flag_at(op, (child_bits(left), bits), child(left)?, child(right)?)
            }
            TermKind::Cast { kind, input } | TermKind::FloatCast { kind, input } => {
                convert(kind, &self.arena.term(input).ty, &ty, child(input)?)
            }
            TermKind::Extract { input, lsb_bits } => {
                extract((child_bits(input), bits), child(input)?, lsb_bits)
            }
            TermKind::Concat { high, low } => {
                concat(bits, child_bits(low), child(high)?, child(low)?)
            }
            TermKind::Select {
                condition,
                if_true,
                if_false,
            } => select(&ty, child(condition)?, child(if_true)?, child(if_false)?),
            TermKind::FloatArithmetic { op, left, right } => {
                Some(float_binary(op, child(left)?, child(right)?))
            }
            TermKind::FloatUnary { op, input } => {
                float_unary(op, child_bits(input), &ty, child(input)?)
            }
            TermKind::FloatCompare { op, left, right } => {
                float_compare(op, bits, child(left)?, child(right)?)
            }
        }
    }

    /// A machine expression as C: what an opaque term or a leaf stands for.
    /// The bits a machine expression holds where it is a constant.
    fn constant(&self, id: MachineExprId) -> Option<u128> {
        match self.projection.expr(id)?.kind() {
            MachineExprKind::Constant { value, .. } => Some(u128::from(value.bits())),
            _ => None,
        }
    }

    pub(super) fn machine(&self, id: MachineExprId) -> Option<CExpr> {
        let node = self.projection.expr(id)?;
        let ty = *node.ty();
        let bits = ty.width_bits();
        let child = |id: MachineExprId| self.machine(id);
        let child_ty = |id: MachineExprId| self.projection.expr(id).map(|node| *node.ty());
        let child_bits = |id: MachineExprId| child_ty(id).map(|ty| ty.width_bits());
        match node.kind() {
            MachineExprKind::Source { binding, .. } => (self.bound)(binding.value(), &ty),
            MachineExprKind::Constant { value, .. } => literal_as(*value, &ty),
            MachineExprKind::MemoryRead { address, .. } => self.load(&ty, child(*address)?),
            MachineExprKind::Copy { input } => child(*input),
            kind @ (MachineExprKind::Arithmetic { .. }
            | MachineExprKind::ArithmeticFlag { .. }
            | MachineExprKind::Divide { .. }
            | MachineExprKind::Remainder { .. }
            | MachineExprKind::Negate { .. }
            | MachineExprKind::Bitwise { .. }
            | MachineExprKind::BitwiseNot { .. }
            | MachineExprKind::BooleanNot { .. }
            | MachineExprKind::Boolean { .. }
            | MachineExprKind::Shift { .. }
            | MachineExprKind::Compare { .. }) => self.machine_integer(kind, ty),
            MachineExprKind::Cast { kind, input } => {
                convert(*kind, &child_ty(*input)?, &ty, child(*input)?)
            }
            MachineExprKind::Extract { input, lsb_bits } => {
                extract((child_bits(*input)?, bits), child(*input)?, *lsb_bits)
            }
            MachineExprKind::Concat { high, low } => {
                concat(bits, child_bits(*low)?, child(*high)?, child(*low)?)
            }
            MachineExprKind::FloatArithmetic { op, left, right } => {
                Some(float_binary(*op, child(*left)?, child(*right)?))
            }
            MachineExprKind::FloatUnary { op, input } => {
                float_unary(*op, child_bits(*input)?, &ty, child(*input)?)
            }
            MachineExprKind::FloatCompare { op, left, right } => {
                float_compare(*op, bits, child(*left)?, child(*right)?)
            }
            MachineExprKind::Select {
                condition,
                if_true,
                if_false,
            } => select(&ty, child(*condition)?, child(*if_true)?, child(*if_false)?),
            MachineExprKind::InsertLane {
                root,
                lane,
                lsb_bits,
                width_bits,
                ..
            } => {
                let lane_ty = child_ty(*lane)?;
                let as_bits = MachineType::Integer {
                    width_bits: lane_ty.width_bits(),
                    signedness: MachineSignedness::Unsigned,
                };
                let lane = reclass(child(*lane)?, &lane_ty, &as_bits)?;
                insert_lane(bits, (*lsb_bits, *width_bits), child(*root)?, lane)
            }
            // The builtin counts an `unsigned long long` and returns an `int`.
            MachineExprKind::PopulationCount { input } if child_bits(*input)? <= 64 => {
                let counted = CExpr::call(
                    CExpr::External {
                        name: "__builtin_popcountll".to_string(),
                        kind: crate::symbol::ExternalKind::Intrinsic,
                    },
                    vec![cast(
                        integer(64)?,
                        cast(integer(child_bits(*input)?)?, child(*input)?),
                    )],
                );
                Some(cast(integer(bits)?, counted))
            }
            // A merge is its variable, which the edges assign; the rest has no single C operator.
            MachineExprKind::Phi { .. }
            | MachineExprKind::PopulationCount { .. }
            | MachineExprKind::GuardedRead { .. }
            | MachineExprKind::ExclusiveStoreSucceeded { .. }
            | MachineExprKind::BlockAnswer { .. } => None,
        }
    }

    /// An integer operation's machine expression as C, at `ty`.
    fn machine_integer(&self, kind: &MachineExprKind, ty: MachineType) -> Option<CExpr> {
        let bits = ty.width_bits();
        let child = |id: MachineExprId| self.machine(id);
        let child_bits =
            |id: MachineExprId| self.projection.expr(id).map(|node| node.ty().width_bits());
        match kind {
            // Checked arithmetic traps on overflow, which no C operator states.
            MachineExprKind::Arithmetic {
                mode: MachineArithmeticMode::Checked,
                ..
            }
            | MachineExprKind::Negate {
                mode: MachineArithmeticMode::Checked,
                ..
            } => None,
            MachineExprKind::Arithmetic {
                op, left, right, ..
            } => wrapping(arithmetic(*op), bits, child(*left)?, child(*right)?),
            MachineExprKind::ArithmeticFlag { op, left, right } => {
                let flag = flag(*op, child_bits(*left)?, child(*left)?, child(*right)?)?;
                Some(cast(integer(bits)?, flag))
            }
            // C traps or leaves undefined what the machine does with a zero divisor alike.
            MachineExprKind::Divide {
                interpretation,
                dividend,
                divisor,
                ..
            }
            | MachineExprKind::Remainder {
                interpretation,
                dividend,
                divisor,
                ..
            } => {
                let op = match kind {
                    MachineExprKind::Divide { .. } => BinaryOp::Div,
                    _ => BinaryOp::Mod,
                };
                divide(
                    (op, *interpretation),
                    bits,
                    (child(*dividend)?, self.constant(*dividend)),
                    (child(*divisor)?, self.constant(*divisor)),
                )
            }
            MachineExprKind::Negate { input, .. } => negate(bits, child(*input)?),
            MachineExprKind::Bitwise { op, left, right } => {
                wrapping(bitwise(*op), bits, child(*left)?, child(*right)?)
            }
            MachineExprKind::BitwiseNot { input } => bitwise_not(bits, child(*input)?),
            MachineExprKind::BooleanNot { input } => boolean_not(bits, child(*input)?),
            MachineExprKind::Boolean { op, left, right } => {
                boolean(*op, bits, child(*left)?, child(*right)?)
            }
            MachineExprKind::Shift {
                kind,
                overshift,
                value,
                count,
            } => shift(
                *kind,
                *overshift,
                (bits, child_bits(*count)?),
                child(*value)?,
                child(*count)?,
            ),
            MachineExprKind::Compare {
                op,
                interpretation,
                left,
                right,
            } => compare(
                (*op, *interpretation),
                (child_bits(*left)?, bits),
                child(*left)?,
                child(*right)?,
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use r2rewrite::{TermArena, TermKind};
    use r2ssa::{MachineArithmeticOp, MachineBitVector, MachineType, ObjectId};

    use super::{frame_offset, inside};

    const ADDRESS: MachineType = MachineType::Integer {
        width_bits: 64,
        signedness: r2ssa::MachineSignedness::Unsigned,
    };

    fn displaced(arena: &mut TermArena, op: MachineArithmeticOp, by: u64) -> r2rewrite::TermId {
        let base = arena.intern(ADDRESS, TermKind::ObjectAddress(ObjectId(3)));
        let by = MachineBitVector::new(64, by).expect("a 64-bit literal");
        let by = arena.intern(ADDRESS, TermKind::Literal(by));
        arena.intern(
            ADDRESS,
            TermKind::Arithmetic {
                op,
                left: base,
                right: by,
            },
        )
    }

    #[test]
    fn a_lane_insert_keeps_the_root_s_other_bits() {
        let spelled = |expr: Option<crate::ast::CExpr>| format!("{:?}", expr.expect("spelled"));
        // `setne dl`: one byte at bit 0 of a 64-bit register.
        let low = super::insert_lane(
            64,
            (0, 8),
            crate::ast::CExpr::UIntLit(1),
            crate::ast::CExpr::UIntLit(2),
        );
        assert!(spelled(low).contains("18446744073709551360"), "~0xff kept");
        // A lane past the root's width has no C spelling.
        assert!(
            super::insert_lane(
                64,
                (60, 8),
                crate::ast::CExpr::UIntLit(1),
                crate::ast::CExpr::UIntLit(2)
            )
            .is_none()
        );
    }

    #[test]
    fn a_frame_access_is_spelled_only_inside_its_object() {
        let mut arena = TermArena::new();
        let up = displaced(&mut arena, MachineArithmeticOp::Add, 8);
        let wrapped = displaced(&mut arena, MachineArithmeticOp::Add, 8u64.wrapping_neg());
        let down = displaced(&mut arena, MachineArithmeticOp::Subtract, 8);
        assert_eq!(frame_offset(&arena, up), Some((ObjectId(3), 8)));
        assert_eq!(frame_offset(&arena, wrapped), Some((ObjectId(3), -8)));
        assert_eq!(frame_offset(&arena, down), Some((ObjectId(3), -8)));
        assert!(inside(8, 8, 16));
        // Below the object, or past its end, is another object's memory or none at all.
        assert!(!inside(-8, 8, 16));
        assert!(!inside(12, 8, 16));
    }

    /// A literal divisor other than -1 rules out MIN / -1, so that quotient is the C division alone.
    #[test]
    fn a_signed_divide_by_a_literal_other_than_minus_one_is_unguarded() {
        use crate::ast::{BinaryOp, CExpr};
        let x = || CExpr::UIntLit(9);
        let signed = (BinaryOp::Div, r2ssa::MachineSignedness::Signed);
        let by_seven = super::divide(signed, 32, (x(), None), (x(), Some(7))).expect("spelled");
        assert!(!matches!(by_seven, CExpr::Ternary { .. }), "{by_seven:?}");
        let by_minus_one =
            super::divide(signed, 32, (x(), None), (x(), Some(0xffff_ffff))).expect("spelled");
        assert!(
            matches!(by_minus_one, CExpr::Ternary { .. }),
            "{by_minus_one:?}"
        );
    }

    /// `object[-1]` with the index a 64-bit literal of all ones: element -1 lies below the object,
    /// so the literal path refuses it and no computed address reaches the bytes before it.
    #[test]
    fn a_negative_literal_index_into_a_frame_object_is_refused() {
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::Copy {
            dst: r2il::Varnode::unique(0x100, 8),
            src: r2il::Varnode::constant(0, 8),
        });
        let artifact = r2ssa::SsaArtifact::from_blocks(&[block], None).expect("an artifact");
        let projection = r2ssa::MachineProjection::from_artifact(&artifact).expect("a projection");
        let mut arena = TermArena::new();
        let base = arena.intern(ADDRESS, TermKind::ObjectAddress(ObjectId(3)));
        let index = |arena: &mut TermArena, bits: u64| {
            let bits = MachineBitVector::new(64, bits).expect("a 64-bit literal");
            arena.intern(ADDRESS, TermKind::Literal(bits))
        };
        let (below, first) = (index(&mut arena, u64::MAX), index(&mut arena, 1));
        let spell = super::Spell {
            projection: &projection,
            arena: &arena,
            bound: &|_, _| None,
            object: &|object| {
                (object == ObjectId(3)).then_some(super::Placed {
                    base: crate::ast::CExpr::UIntLit(0x40),
                    extent: 16,
                })
            },
            global: &|_, _, _| None,
            little_endian: true,
            return_address: None,
        };
        assert!(
            spell
                .subscript((base, first), 8, Some(ObjectId(3)))
                .is_some()
        );
        assert!(
            spell
                .subscript((base, below), 8, Some(ObjectId(3)))
                .is_none()
        );
    }
}
