//! Concrete interpreter for terms, the twin of the Z3 encoding in the proof
//! harness. Widths are at most 64 bits; arithmetic is done in `u128` and
//! masked to the term's width. Memory and placed objects are leaves too: the
//! caller answers what a cell holds and where an object sits, and the
//! interpreter only computes the address.

use r2ssa::{
    MachineArithmeticFlagOp, MachineArithmeticOp, MachineBitwiseOp, MachineBooleanOp,
    MachineCastKind, MachineComparisonOp, MachineExprId, MachineFloatOp, MachineFloatUnaryOp,
    MachineOvershiftBehavior, MachineShiftKind, MachineSignedness, MachineType, ObjectId,
};

/// The floating value `bits` encodes at `width_bits`, widened to `f64`; a
/// `float` widens exactly.
fn float_of(bits: u128, width_bits: u32) -> f64 {
    if width_bits == 32 {
        f64::from(f32::from_bits(bits as u32))
    } else {
        f64::from_bits(bits as u64)
    }
}

/// The encoding of `value` at `width_bits`, rounded to nearest at 32.
fn float_bits(value: f64, width_bits: u32) -> u128 {
    if width_bits == 32 {
        u128::from((value as f32).to_bits())
    } else {
        u128::from(value.to_bits())
    }
}

/// A binary IEEE operation at `width_bits`, performed in that format so a
/// `float` result rounds once.
fn float_binary(op: MachineFloatOp, l: f64, r: f64, width_bits: u32) -> f64 {
    if width_bits == 32 {
        let (l, r) = (l as f32, r as f32);
        f64::from(match op {
            MachineFloatOp::Add => l + r,
            MachineFloatOp::Subtract => l - r,
            MachineFloatOp::Multiply => l * r,
            MachineFloatOp::Divide => l / r,
        })
    } else {
        match op {
            MachineFloatOp::Add => l + r,
            MachineFloatOp::Subtract => l - r,
            MachineFloatOp::Multiply => l * r,
            MachineFloatOp::Divide => l / r,
        }
    }
}

fn float_unary(op: MachineFloatUnaryOp, x: f64, width_bits: u32) -> f64 {
    if width_bits == 32 {
        let x = x as f32;
        f64::from(match op {
            MachineFloatUnaryOp::Negate => -x,
            MachineFloatUnaryOp::Absolute => x.abs(),
            MachineFloatUnaryOp::SquareRoot => x.sqrt(),
            MachineFloatUnaryOp::Ceiling => x.ceil(),
            MachineFloatUnaryOp::Floor => x.floor(),
            MachineFloatUnaryOp::Round => (x + 0.5).floor(),
            MachineFloatUnaryOp::IsNan => return f64::from(u8::from(x.is_nan())),
        })
    } else {
        match op {
            MachineFloatUnaryOp::Negate => -x,
            MachineFloatUnaryOp::Absolute => x.abs(),
            MachineFloatUnaryOp::SquareRoot => x.sqrt(),
            MachineFloatUnaryOp::Ceiling => x.ceil(),
            MachineFloatUnaryOp::Floor => x.floor(),
            MachineFloatUnaryOp::Round => (x + 0.5).floor(),
            MachineFloatUnaryOp::IsNan => f64::from(u8::from(x.is_nan())),
        }
    }
}

use crate::term::{TermArena, TermId, TermKind};

pub fn mask(width_bits: u32) -> u128 {
    if width_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << width_bits) - 1
    }
}

/// Interpret `bits` of `width_bits` as a signed value.
pub fn signed(bits: u128, width_bits: u32) -> i128 {
    let shift = 128 - width_bits;
    ((bits << shift) as i128) >> shift
}

/// What a term reads from outside itself: a base-arena node, a free variable
/// of a proof template, a memory cell, or the address of a placed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeafRef {
    Expr(MachineExprId),
    Variable(u32),
    /// The cell of `width_bits` at `address`, which is already masked to the
    /// address width.
    Memory {
        address: u128,
        width_bits: u32,
    },
    ObjectAddress(ObjectId),
}

/// Evaluate `root`, asking `leaf` for the value of every base-arena node or
/// variable it reads. A Bool-typed leaf must be answered with 0 or 1.
pub fn eval(
    arena: &TermArena,
    root: TermId,
    leaf: &mut dyn FnMut(LeafRef, &MachineType) -> u128,
) -> u128 {
    let term = arena.term(root);
    let width = term.width_bits();
    let m = mask(width);
    let value = match term.kind {
        TermKind::Leaf(read) => leaf(LeafRef::Expr(read.expr), &term.ty),
        TermKind::Opaque(expr) => leaf(LeafRef::Expr(expr), &term.ty),
        TermKind::Variable(index) => leaf(LeafRef::Variable(index), &term.ty),
        TermKind::Literal(bits) => u128::from(bits.bits()),
        TermKind::ObjectAddress(object) => leaf(LeafRef::ObjectAddress(object), &term.ty),
        TermKind::Load { address, .. } => {
            let address = eval(arena, address, leaf);
            leaf(
                LeafRef::Memory {
                    address,
                    width_bits: width,
                },
                &term.ty,
            )
        }
        TermKind::Subscript { base, index } => {
            let address_width = arena.term(base).width_bits();
            let b = eval(arena, base, leaf);
            let i = eval(arena, index, leaf);
            let address =
                b.wrapping_add(i.wrapping_mul(u128::from(width / 8))) & mask(address_width);
            leaf(
                LeafRef::Memory {
                    address,
                    width_bits: width,
                },
                &term.ty,
            )
        }
        TermKind::Arithmetic { op, left, right } => {
            let l = eval(arena, left, leaf);
            let r = eval(arena, right, leaf);
            match op {
                MachineArithmeticOp::Add => l.wrapping_add(r),
                MachineArithmeticOp::Subtract => l.wrapping_sub(r),
                MachineArithmeticOp::Multiply => l.wrapping_mul(r),
            }
        }
        TermKind::Negate(input) => 0u128.wrapping_sub(eval(arena, input, leaf)),
        TermKind::Bitwise { op, left, right } => {
            let l = eval(arena, left, leaf);
            let r = eval(arena, right, leaf);
            match op {
                MachineBitwiseOp::And => l & r,
                MachineBitwiseOp::Or => l | r,
                MachineBitwiseOp::Xor => l ^ r,
            }
        }
        TermKind::BitwiseNot(input) => !eval(arena, input, leaf),
        TermKind::Boolean { op, left, right } => {
            let l = eval(arena, left, leaf) != 0;
            let r = eval(arena, right, leaf) != 0;
            u128::from(match op {
                MachineBooleanOp::And => l && r,
                MachineBooleanOp::Or => l || r,
                MachineBooleanOp::Xor => l ^ r,
            })
        }
        TermKind::BooleanNot(input) => u128::from(eval(arena, input, leaf) == 0),
        TermKind::Shift {
            kind,
            overshift,
            value,
            count,
        } => {
            let v = eval(arena, value, leaf);
            let c = eval(arena, count, leaf);
            let w = u128::from(width);
            let c = match overshift {
                MachineOvershiftBehavior::MaskCount => c & (w - 1),
                _ => c,
            };
            let sign = (v >> (width - 1)) & 1 == 1;
            match kind {
                MachineShiftKind::Left => {
                    if c >= w {
                        0
                    } else {
                        v << c
                    }
                }
                MachineShiftKind::LogicalRight => {
                    if c >= w {
                        0
                    } else {
                        v >> c
                    }
                }
                MachineShiftKind::ArithmeticRight => {
                    if c >= w {
                        match overshift {
                            MachineOvershiftBehavior::Zero => 0,
                            _ => {
                                if sign {
                                    m
                                } else {
                                    0
                                }
                            }
                        }
                    } else {
                        (signed(v, width) >> c) as u128
                    }
                }
            }
        }
        TermKind::Compare {
            op,
            interpretation,
            left,
            right,
        } => {
            let l = eval(arena, left, leaf);
            let r = eval(arena, right, leaf);
            let lw = arena.term(left).width_bits();
            let result = match (op, interpretation) {
                (MachineComparisonOp::Equal, _) => l == r,
                (MachineComparisonOp::NotEqual, _) => l != r,
                (MachineComparisonOp::LessThan, MachineSignedness::Unsigned) => l < r,
                (MachineComparisonOp::LessThanOrEqual, MachineSignedness::Unsigned) => l <= r,
                (MachineComparisonOp::LessThan, MachineSignedness::Signed) => {
                    signed(l, lw) < signed(r, lw)
                }
                (MachineComparisonOp::LessThanOrEqual, MachineSignedness::Signed) => {
                    signed(l, lw) <= signed(r, lw)
                }
            };
            u128::from(result)
        }
        TermKind::Flag { op, left, right } => {
            let l = eval(arena, left, leaf);
            let r = eval(arena, right, leaf);
            let lw = arena.term(left).width_bits();
            let lm = mask(lw);
            let result = match op {
                MachineArithmeticFlagOp::UnsignedCarry => l + r > lm,
                MachineArithmeticFlagOp::SignedCarry => {
                    let sum = signed(l, lw) + signed(r, lw);
                    sum != signed((sum as u128) & lm, lw)
                }
                MachineArithmeticFlagOp::SignedBorrow => {
                    let diff = signed(l, lw) - signed(r, lw);
                    diff != signed((diff as u128) & lm, lw)
                }
            };
            u128::from(result)
        }
        TermKind::Cast { kind, input } | TermKind::FloatCast { kind, input } => {
            let x = eval(arena, input, leaf);
            let from = arena.term(input).width_bits();
            match kind {
                MachineCastKind::SignExtend => signed(x, from) as u128,
                MachineCastKind::ZeroExtend
                | MachineCastKind::BitReinterpret
                | MachineCastKind::IntegerToAddress
                | MachineCastKind::AddressToInteger => x,
                MachineCastKind::IntegerToFloat => float_bits(signed(x, from) as f64, width),
                MachineCastKind::FloatToInteger => (float_of(x, from) as i128) as u128,
                MachineCastKind::FloatToFloat => float_bits(float_of(x, from), width),
            }
        }
        TermKind::FloatArithmetic { op, left, right } => {
            let l = float_of(eval(arena, left, leaf), width);
            let r = float_of(eval(arena, right, leaf), width);
            float_bits(float_binary(op, l, r, width), width)
        }
        TermKind::FloatUnary { op, input } => {
            let from = arena.term(input).width_bits();
            let x = float_of(eval(arena, input, leaf), from);
            let result = float_unary(op, x, from);
            if op == MachineFloatUnaryOp::IsNan {
                u128::from(result != 0.0)
            } else {
                float_bits(result, from)
            }
        }
        TermKind::FloatCompare { op, left, right } => {
            let from = arena.term(left).width_bits();
            let l = float_of(eval(arena, left, leaf), from);
            let r = float_of(eval(arena, right, leaf), from);
            u128::from(match op {
                MachineComparisonOp::Equal => l == r,
                MachineComparisonOp::NotEqual => l != r,
                MachineComparisonOp::LessThan => l < r,
                MachineComparisonOp::LessThanOrEqual => l <= r,
            })
        }
        TermKind::Extract { input, lsb_bits } => eval(arena, input, leaf) >> lsb_bits,
        TermKind::Concat { high, low } => {
            let low_width = arena.term(low).width_bits();
            (eval(arena, high, leaf) << low_width) | eval(arena, low, leaf)
        }
        TermKind::Select {
            condition,
            if_true,
            if_false,
        } => {
            if eval(arena, condition, leaf) != 0 {
                eval(arena, if_true, leaf)
            } else {
                eval(arena, if_false, leaf)
            }
        }
    };
    value & m
}
