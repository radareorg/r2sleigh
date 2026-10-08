//! D3: a canonical term as C (doc/adr-decompiler-rewrite.md). An integer is spelled unsigned at its
//! width so the C wraps as the machine does; a node with no exact C spelling answers `None`.

use r2rewrite::{TermArena, TermId, TermKind};
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
    pub(super) object: &'a dyn Fn(ObjectId) -> Option<CExpr>,
    /// Whether memory is little-endian, so a byte copy reads a word as the machine does.
    pub(super) little_endian: bool,
}

/// The C type a machine type is spelled in: an unsigned integer, or `float` or `double`.
pub(super) fn c_type(ty: &MachineType) -> Option<CType> {
    match ty {
        MachineType::Float {
            width_bits: 32 | 64,
        } => Some(CType::Float(ty.width_bits())),
        MachineType::Float { .. } => None,
        _ => integer(ty.width_bits()),
    }
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

/// A comparison of two `bits`-wide operands under `interpretation`, as a byte holding 0 or 1.
fn compare(
    op: MachineComparisonOp,
    interpretation: MachineSignedness,
    bits: u32,
    result_bits: u32,
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
            binary(
                BinaryOp::Shl,
                cast(wide.clone(), value.clone()),
                count.clone(),
            ),
        ),
        MachineShiftKind::LogicalRight => cast(
            ty.clone(),
            binary(
                BinaryOp::Shr,
                cast(wide.clone(), value.clone()),
                count.clone(),
            ),
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
                else_expr: Box::new(cast(ty.clone(), CExpr::UIntLit(0))),
            }
        }
        _ => cast(ty.clone(), CExpr::UIntLit(0)),
    };
    // The count is tested before the shift runs, so C never shifts by its width or more.
    Some(CExpr::Ternary {
        cond: Box::new(binary(BinaryOp::Ge, count, width)),
        then_expr: Box::new(past),
        else_expr: Box::new(shifted),
    })
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
        // C leaves a float outside the integer's range undefined, and the machine does not.
        MachineCastKind::FloatToInteger => None,
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

impl Spell<'_> {
    /// A read of `ty` at the integer `address`, by a byte copy so C reads it as the machine does.
    fn load(&self, ty: &MachineType, address: CExpr) -> Option<CExpr> {
        if !self.little_endian {
            return None;
        }
        let residual = ResidualType::of(&c_type(ty)?)?;
        let pointer = cast(CType::Pointer(Box::new(CType::Void)), address);
        Some(Helper::Load(residual).call(vec![pointer]))
    }

    /// The term as C of its own machine type; `None` where C has no exact spelling of it.
    pub(super) fn term(&self, id: TermId) -> Option<CExpr> {
        let node = self.arena.term(id);
        let ty = node.ty;
        let bits = ty.width_bits();
        let child = |id: TermId| self.term(id);
        let child_bits = |id: TermId| self.arena.term(id).ty.width_bits();
        match node.kind {
            TermKind::Leaf(read) => self.machine(read.expr),
            TermKind::Opaque(expr) => self.machine(expr),
            TermKind::Literal(value) => literal(value),
            TermKind::Variable(_) => None,
            TermKind::ObjectAddress(object) => Some(cast(integer(bits)?, (self.object)(object)?)),
            TermKind::Load { address, .. } => self.load(&ty, child(address)?),
            TermKind::Subscript { base, index } => {
                let step = CExpr::UIntLit(u64::from(bits / 8));
                let wide = integer(child_bits(base))?;
                let offset = binary(BinaryOp::Mul, cast(wide.clone(), child(index)?), step);
                let at = binary(BinaryOp::Add, cast(wide, child(base)?), offset);
                self.load(&ty, at)
            }
            TermKind::Arithmetic { op, left, right } => {
                wrapping(arithmetic(op), bits, child(left)?, child(right)?)
            }
            TermKind::Negate(input) => {
                let zero = cast(integer(bits)?, CExpr::UIntLit(0));
                wrapping(BinaryOp::Sub, bits, zero, child(input)?)
            }
            TermKind::Bitwise { op, left, right } => {
                wrapping(bitwise(op), bits, child(left)?, child(right)?)
            }
            TermKind::BitwiseNot(input) => Some(cast(
                integer(bits)?,
                CExpr::unary(
                    UnaryOp::BitNot,
                    cast(integer(computed(bits))?, child(input)?),
                ),
            )),
            TermKind::Boolean { op, left, right } => boolean(op, bits, child(left)?, child(right)?),
            TermKind::BooleanNot(input) => {
                let one = cast(integer(bits)?, CExpr::UIntLit(1));
                wrapping(BinaryOp::BitXor, bits, child(input)?, one)
            }
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
                op,
                interpretation,
                child_bits(left),
                bits,
                child(left)?,
                child(right)?,
            ),
            TermKind::Flag { op, left, right } => {
                let flag = flag(op, child_bits(left), child(left)?, child(right)?)?;
                Some(cast(integer(bits)?, flag))
            }
            TermKind::Cast { kind, input } => {
                convert(kind, &self.arena.term(input).ty, &ty, child(input)?)
            }
            TermKind::Extract { input, lsb_bits } => {
                let wide = integer(child_bits(input))?;
                let shifted = binary(
                    BinaryOp::Shr,
                    cast(wide, child(input)?),
                    CExpr::UIntLit(u64::from(lsb_bits)),
                );
                Some(cast(integer(bits)?, shifted))
            }
            TermKind::Concat { high, low } => {
                concat(bits, child_bits(low), child(high)?, child(low)?)
            }
            TermKind::Select {
                condition,
                if_true,
                if_false,
            } => Some(CExpr::Ternary {
                cond: Box::new(child(condition)?),
                then_expr: Box::new(cast(c_type(&ty)?, child(if_true)?)),
                else_expr: Box::new(cast(c_type(&ty)?, child(if_false)?)),
            }),
            TermKind::FloatCast { kind, input } => {
                convert(kind, &self.arena.term(input).ty, &ty, child(input)?)
            }
            TermKind::FloatArithmetic { op, left, right } => {
                Some(float_binary(op, child(left)?, child(right)?))
            }
            TermKind::FloatUnary { op, input } => {
                float_unary(op, child_bits(input), &ty, child(input)?)
            }
            TermKind::FloatCompare { op, left, right } => {
                let test = binary(comparison(op), child(left)?, child(right)?);
                Some(cast(integer(bits)?, test))
            }
        }
    }

    /// A machine expression as C: what an opaque term or a leaf stands for.
    pub(super) fn machine(&self, id: MachineExprId) -> Option<CExpr> {
        let node = self.projection.expr(id)?;
        let ty = *node.ty();
        let bits = ty.width_bits();
        let child = |id: MachineExprId| self.machine(id);
        let child_ty = |id: MachineExprId| self.projection.expr(id).map(|node| *node.ty());
        let child_bits = |id: MachineExprId| child_ty(id).map(|ty| ty.width_bits());
        match node.kind() {
            MachineExprKind::Source { binding, .. } => (self.bound)(binding.value(), &ty),
            MachineExprKind::Constant { value, .. } => literal(*value),
            MachineExprKind::MemoryRead { address, .. } => self.load(&ty, child(*address)?),
            MachineExprKind::Copy { input } => child(*input),
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
                let op = match node.kind() {
                    MachineExprKind::Divide { .. } => BinaryOp::Div,
                    _ => BinaryOp::Mod,
                };
                let operand = match interpretation {
                    MachineSignedness::Signed => signed(bits)?,
                    MachineSignedness::Unsigned => integer(bits)?,
                };
                let quotient = binary(
                    op,
                    cast(operand.clone(), child(*dividend)?),
                    cast(operand, child(*divisor)?),
                );
                Some(cast(integer(bits)?, quotient))
            }
            MachineExprKind::Negate { input, .. } => {
                let zero = cast(integer(bits)?, CExpr::UIntLit(0));
                wrapping(BinaryOp::Sub, bits, zero, child(*input)?)
            }
            MachineExprKind::Bitwise { op, left, right } => {
                wrapping(bitwise(*op), bits, child(*left)?, child(*right)?)
            }
            MachineExprKind::BitwiseNot { input } => Some(cast(
                integer(bits)?,
                CExpr::unary(
                    UnaryOp::BitNot,
                    cast(integer(computed(bits))?, child(*input)?),
                ),
            )),
            MachineExprKind::BooleanNot { input } => {
                let one = cast(integer(bits)?, CExpr::UIntLit(1));
                wrapping(BinaryOp::BitXor, bits, child(*input)?, one)
            }
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
                *op,
                *interpretation,
                child_bits(*left)?,
                bits,
                child(*left)?,
                child(*right)?,
            ),
            MachineExprKind::Cast { kind, input } => {
                convert(*kind, &child_ty(*input)?, &ty, child(*input)?)
            }
            MachineExprKind::Extract { input, lsb_bits } => {
                let wide = integer(child_bits(*input)?)?;
                let shifted = binary(
                    BinaryOp::Shr,
                    cast(wide, child(*input)?),
                    CExpr::UIntLit(u64::from(*lsb_bits)),
                );
                Some(cast(integer(bits)?, shifted))
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
                let test = binary(comparison(*op), child(*left)?, child(*right)?);
                Some(cast(integer(bits)?, test))
            }
            MachineExprKind::Select {
                condition,
                if_true,
                if_false,
            } => Some(CExpr::Ternary {
                cond: Box::new(child(*condition)?),
                then_expr: Box::new(cast(c_type(&ty)?, child(*if_true)?)),
                else_expr: Box::new(cast(c_type(&ty)?, child(*if_false)?)),
            }),
            // A merge is its variable, which the edges assign; the rest has no single C operator.
            MachineExprKind::Phi { .. }
            | MachineExprKind::PopulationCount { .. }
            | MachineExprKind::InsertLane { .. }
            | MachineExprKind::GuardedRead { .. }
            | MachineExprKind::ExclusiveStoreSucceeded { .. }
            | MachineExprKind::BlockAnswer { .. } => None,
        }
    }
}
