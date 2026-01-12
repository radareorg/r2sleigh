//! Symbolic values for symbolic execution.
//!
//! A `SymValue` can be:
//! - `Concrete`: A known constant value
//! - `Symbolic`: A Z3 bitvector expression
//! - `Unknown`: An uninitialized or undefined value

use std::fmt;

use z3::ast::{Ast, BV};
use z3::Context;

/// A symbolic value that can be concrete, symbolic, or unknown.
#[derive(Clone)]
pub enum SymValue<'ctx> {
    /// A concrete (known) value.
    Concrete {
        /// The value.
        value: u64,
        /// Size in bits.
        bits: u32,
    },
    /// A symbolic value represented as a Z3 bitvector.
    Symbolic {
        /// The Z3 bitvector AST.
        ast: BV<'ctx>,
        /// Size in bits.
        bits: u32,
    },
    /// An unknown/uninitialized value.
    Unknown {
        /// Size in bits.
        bits: u32,
    },
}

impl<'ctx> SymValue<'ctx> {
    /// Create a concrete value.
    pub fn concrete(value: u64, bits: u32) -> Self {
        Self::Concrete { value, bits }
    }

    /// Create a symbolic value from a Z3 bitvector.
    pub fn symbolic(ast: BV<'ctx>, bits: u32) -> Self {
        Self::Symbolic { ast, bits }
    }

    /// Create an unknown value.
    pub fn unknown(bits: u32) -> Self {
        Self::Unknown { bits }
    }

    /// Create a new symbolic variable.
    pub fn new_symbolic(ctx: &'ctx Context, name: &str, bits: u32) -> Self {
        let ast = BV::new_const(ctx, name, bits);
        Self::Symbolic { ast, bits }
    }

    /// Create a concrete value from a Z3 context.
    pub fn from_u64(_ctx: &'ctx Context, value: u64, bits: u32) -> Self {
        Self::Concrete { value, bits }
    }

    /// Get the bit width of this value.
    pub fn bits(&self) -> u32 {
        match self {
            Self::Concrete { bits, .. } => *bits,
            Self::Symbolic { bits, .. } => *bits,
            Self::Unknown { bits } => *bits,
        }
    }

    /// Normalize two values to the same bit width for binary operations.
    /// Returns (self_normalized, other_normalized, result_bits).
    /// Uses zero-extension to match the larger width.
    fn normalize_widths<'a>(
        &'a self,
        ctx: &'ctx Context,
        other: &'a Self,
    ) -> (BV<'ctx>, BV<'ctx>, u32) {
        let self_bits = self.bits();
        let other_bits = other.bits();

        if self_bits == other_bits {
            (self.to_bv(ctx), other.to_bv(ctx), self_bits)
        } else if self_bits > other_bits {
            let self_bv = self.to_bv(ctx);
            let other_bv = other.to_bv(ctx).zero_ext(self_bits - other_bits);
            (self_bv, other_bv, self_bits)
        } else {
            let self_bv = self.to_bv(ctx).zero_ext(other_bits - self_bits);
            let other_bv = other.to_bv(ctx);
            (self_bv, other_bv, other_bits)
        }
    }

    /// Normalize shift amount to match value width.
    /// Shift amounts are often smaller (e.g., 8-bit) than the value being shifted.
    fn normalize_shift_amount(&self, ctx: &'ctx Context, amount: &Self) -> BV<'ctx> {
        let value_bits = self.bits();
        let amount_bits = amount.bits();

        if amount_bits == value_bits {
            amount.to_bv(ctx)
        } else if amount_bits < value_bits {
            amount.to_bv(ctx).zero_ext(value_bits - amount_bits)
        } else {
            // Truncate if shift amount is larger (unusual but handle it)
            amount.to_bv(ctx).extract(value_bits - 1, 0)
        }
    }

    /// Check if this value is concrete.
    pub fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete { .. })
    }

    /// Check if this value is symbolic.
    pub fn is_symbolic(&self) -> bool {
        matches!(self, Self::Symbolic { .. })
    }

    /// Check if this value is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// Get the concrete value if available.
    pub fn as_concrete(&self) -> Option<u64> {
        match self {
            Self::Concrete { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Get the Z3 AST if this is symbolic.
    pub fn as_ast(&self) -> Option<&BV<'ctx>> {
        match self {
            Self::Symbolic { ast, .. } => Some(ast),
            _ => None,
        }
    }

    /// Convert to a Z3 bitvector (concretizing if needed).
    pub fn to_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            Self::Concrete { value, bits } => BV::from_u64(ctx, *value, *bits),
            Self::Symbolic { ast, .. } => ast.clone(),
            Self::Unknown { bits } => {
                // Create a fresh symbolic variable for unknown values
                BV::fresh_const(ctx, "unknown", *bits)
            }
        }
    }

    /// Zero-extend to a larger size.
    pub fn zero_extend(&self, _ctx: &'ctx Context, new_bits: u32) -> Self {
        if new_bits <= self.bits() {
            return self.clone();
        }
        let extend_by = new_bits - self.bits();
        match self {
            Self::Concrete { value, .. } => Self::Concrete {
                value: *value,
                bits: new_bits,
            },
            Self::Symbolic { ast, .. } => {
                let new_ast = ast.zero_ext(extend_by);
                Self::Symbolic {
                    ast: new_ast,
                    bits: new_bits,
                }
            }
            Self::Unknown { .. } => Self::Unknown { bits: new_bits },
        }
    }

    /// Sign-extend to a larger size.
    pub fn sign_extend(&self, _ctx: &'ctx Context, new_bits: u32) -> Self {
        if new_bits <= self.bits() {
            return self.clone();
        }
        let extend_by = new_bits - self.bits();
        match self {
            Self::Concrete { value, bits } => {
                // Sign extend the concrete value
                let sign_bit = (*value >> (*bits - 1)) & 1;
                let new_value = if sign_bit == 1 {
                    let mask = !((1u64 << *bits) - 1);
                    *value | mask
                } else {
                    *value
                };
                Self::Concrete {
                    value: new_value,
                    bits: new_bits,
                }
            }
            Self::Symbolic { ast, .. } => {
                let new_ast = ast.sign_ext(extend_by);
                Self::Symbolic {
                    ast: new_ast,
                    bits: new_bits,
                }
            }
            Self::Unknown { .. } => Self::Unknown { bits: new_bits },
        }
    }

    /// Extract bits [high:low] from this value.
    pub fn extract(&self, _ctx: &'ctx Context, high: u32, low: u32) -> Self {
        let new_bits = high - low + 1;
        match self {
            Self::Concrete { value, .. } => {
                let mask = (1u64 << new_bits) - 1;
                let new_value = (*value >> low) & mask;
                Self::Concrete {
                    value: new_value,
                    bits: new_bits,
                }
            }
            Self::Symbolic { ast, .. } => {
                let new_ast = ast.extract(high, low);
                Self::Symbolic {
                    ast: new_ast,
                    bits: new_bits,
                }
            }
            Self::Unknown { .. } => Self::Unknown { bits: new_bits },
        }
    }

    /// Concatenate two values (self is high bits, other is low bits).
    pub fn concat(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let new_bits = self.bits() + other.bits();
        match (self, other) {
            (
                Self::Concrete { value: hi, bits: _ },
                Self::Concrete {
                    value: lo,
                    bits: lo_bits,
                },
            ) => {
                let new_value = (*hi << *lo_bits) | *lo;
                Self::Concrete {
                    value: new_value,
                    bits: new_bits,
                }
            }
            _ => {
                let hi_bv = self.to_bv(ctx);
                let lo_bv = other.to_bv(ctx);
                let new_ast = hi_bv.concat(&lo_bv);
                Self::Symbolic {
                    ast: new_ast,
                    bits: new_bits,
                }
            }
        }
    }

    // ==================== Arithmetic Operations ====================

    /// Add two values.
    pub fn add(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                let result_bits = (*bits).max(*b_bits);
                let mask = if result_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << result_bits) - 1
                };
                Self::Concrete {
                    value: a.wrapping_add(*b) & mask,
                    bits: result_bits,
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvadd(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Subtract two values.
    pub fn sub(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                let result_bits = (*bits).max(*b_bits);
                let mask = if result_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << result_bits) - 1
                };
                Self::Concrete {
                    value: a.wrapping_sub(*b) & mask,
                    bits: result_bits,
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvsub(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Multiply two values.
    pub fn mul(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                let result_bits = (*bits).max(*b_bits);
                let mask = if result_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << result_bits) - 1
                };
                Self::Concrete {
                    value: a.wrapping_mul(*b) & mask,
                    bits: result_bits,
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvmul(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Unsigned division.
    pub fn udiv(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                let result_bits = (*bits).max(*b_bits);
                if *b == 0 {
                    Self::Unknown { bits: result_bits }
                } else {
                    Self::Concrete {
                        value: *a / *b,
                        bits: result_bits,
                    }
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvudiv(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Signed division.
    pub fn sdiv(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
        Self::Symbolic {
            ast: a_bv.bvsdiv(&b_bv),
            bits: result_bits,
        }
    }

    /// Unsigned remainder.
    pub fn urem(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                let result_bits = (*bits).max(*b_bits);
                if *b == 0 {
                    Self::Unknown { bits: result_bits }
                } else {
                    Self::Concrete {
                        value: *a % *b,
                        bits: result_bits,
                    }
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvurem(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Signed remainder.
    pub fn srem(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
        Self::Symbolic {
            ast: a_bv.bvsrem(&b_bv),
            bits: result_bits,
        }
    }

    /// Two's complement negation.
    pub fn neg(&self, ctx: &'ctx Context) -> Self {
        match self {
            Self::Concrete { value, bits } => {
                let mask = if *bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << *bits) - 1
                };
                Self::Concrete {
                    value: (!*value).wrapping_add(1) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let bv = self.to_bv(ctx);
                Self::Symbolic {
                    ast: bv.bvneg(),
                    bits: self.bits(),
                }
            }
        }
    }

    // ==================== Bitwise Operations ====================

    /// Bitwise AND.
    pub fn and(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                Self::Concrete {
                    value: *a & *b,
                    bits: (*bits).max(*b_bits),
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvand(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Bitwise OR.
    pub fn or(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                Self::Concrete {
                    value: *a | *b,
                    bits: (*bits).max(*b_bits),
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvor(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Bitwise XOR.
    pub fn xor(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, bits: b_bits }) => {
                Self::Concrete {
                    value: *a ^ *b,
                    bits: (*bits).max(*b_bits),
                }
            }
            _ => {
                let (a_bv, b_bv, result_bits) = self.normalize_widths(ctx, other);
                Self::Symbolic {
                    ast: a_bv.bvxor(&b_bv),
                    bits: result_bits,
                }
            }
        }
    }

    /// Bitwise NOT.
    pub fn not(&self, ctx: &'ctx Context) -> Self {
        match self {
            Self::Concrete { value, bits } => {
                let mask = if *bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << *bits) - 1
                };
                Self::Concrete {
                    value: !*value & mask,
                    bits: *bits,
                }
            }
            _ => {
                let bv = self.to_bv(ctx);
                Self::Symbolic {
                    ast: bv.bvnot(),
                    bits: self.bits(),
                }
            }
        }
    }

    // ==================== Shift Operations ====================

    /// Logical left shift.
    pub fn shl(&self, ctx: &'ctx Context, amount: &Self) -> Self {
        match (self, amount) {
            (Self::Concrete { value, bits }, Self::Concrete { value: amt, .. }) => {
                let mask = if *bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << *bits) - 1
                };
                Self::Concrete {
                    value: (*value << (*amt as u32)) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = self.normalize_shift_amount(ctx, amount);
                Self::Symbolic {
                    ast: a_bv.bvshl(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Logical right shift.
    pub fn lshr(&self, ctx: &'ctx Context, amount: &Self) -> Self {
        match (self, amount) {
            (Self::Concrete { value, bits }, Self::Concrete { value: amt, .. }) => Self::Concrete {
                value: *value >> (*amt as u32),
                bits: *bits,
            },
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = self.normalize_shift_amount(ctx, amount);
                Self::Symbolic {
                    ast: a_bv.bvlshr(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Arithmetic right shift.
    pub fn ashr(&self, ctx: &'ctx Context, amount: &Self) -> Self {
        let a_bv = self.to_bv(ctx);
        let b_bv = self.normalize_shift_amount(ctx, amount);
        Self::Symbolic {
            ast: a_bv.bvashr(&b_bv),
            bits: self.bits(),
        }
    }

    // ==================== Comparison Operations ====================

    /// Equality comparison (returns 1-bit result).
    pub fn eq(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, .. }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: if *a == *b { 1 } else { 0 },
                bits: 1,
            },
            _ => {
                let (a_bv, b_bv, _) = self.normalize_widths(ctx, other);
                let cond = a_bv._eq(&b_bv);
                let one = BV::from_u64(ctx, 1, 1);
                let zero = BV::from_u64(ctx, 0, 1);
                Self::Symbolic {
                    ast: cond.ite(&one, &zero),
                    bits: 1,
                }
            }
        }
    }

    /// Unsigned less than comparison.
    pub fn ult(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, .. }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: if *a < *b { 1 } else { 0 },
                bits: 1,
            },
            _ => {
                let (a_bv, b_bv, _) = self.normalize_widths(ctx, other);
                let cond = a_bv.bvult(&b_bv);
                let one = BV::from_u64(ctx, 1, 1);
                let zero = BV::from_u64(ctx, 0, 1);
                Self::Symbolic {
                    ast: cond.ite(&one, &zero),
                    bits: 1,
                }
            }
        }
    }

    /// Unsigned less than or equal comparison.
    pub fn ule(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, .. }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: if *a <= *b { 1 } else { 0 },
                bits: 1,
            },
            _ => {
                let (a_bv, b_bv, _) = self.normalize_widths(ctx, other);
                let cond = a_bv.bvule(&b_bv);
                let one = BV::from_u64(ctx, 1, 1);
                let zero = BV::from_u64(ctx, 0, 1);
                Self::Symbolic {
                    ast: cond.ite(&one, &zero),
                    bits: 1,
                }
            }
        }
    }

    /// Signed less than comparison.
    pub fn slt(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let (a_bv, b_bv, _) = self.normalize_widths(ctx, other);
        let cond = a_bv.bvslt(&b_bv);
        let one = BV::from_u64(ctx, 1, 1);
        let zero = BV::from_u64(ctx, 0, 1);
        Self::Symbolic {
            ast: cond.ite(&one, &zero),
            bits: 1,
        }
    }

    /// Signed less than or equal comparison.
    pub fn sle(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let (a_bv, b_bv, _) = self.normalize_widths(ctx, other);
        let cond = a_bv.bvsle(&b_bv);
        let one = BV::from_u64(ctx, 1, 1);
        let zero = BV::from_u64(ctx, 0, 1);
        Self::Symbolic {
            ast: cond.ite(&one, &zero),
            bits: 1,
        }
    }

    /// Check if value is zero (returns boolean).
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Concrete { value, .. } => *value == 0,
            _ => false,
        }
    }

    /// Check if value is non-zero (returns boolean).
    pub fn is_nonzero(&self) -> bool {
        match self {
            Self::Concrete { value, .. } => *value != 0,
            _ => false,
        }
    }
}

impl<'ctx> fmt::Debug for SymValue<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete { value, bits } => write!(f, "Concrete(0x{:x}, {})", value, bits),
            Self::Symbolic { bits, .. } => write!(f, "Symbolic({})", bits),
            Self::Unknown { bits } => write!(f, "Unknown({})", bits),
        }
    }
}

impl<'ctx> fmt::Display for SymValue<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete { value, bits } => write!(f, "0x{:x}:{}", value, bits),
            Self::Symbolic { bits, .. } => write!(f, "<sym:{}>", bits),
            Self::Unknown { bits } => write!(f, "<unk:{}>", bits),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_concrete_ops() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(10, 32);
        let b = SymValue::concrete(3, 32);

        let sum = a.add(&ctx, &b);
        assert_eq!(sum.as_concrete(), Some(13));

        let diff = a.sub(&ctx, &b);
        assert_eq!(diff.as_concrete(), Some(7));

        let prod = a.mul(&ctx, &b);
        assert_eq!(prod.as_concrete(), Some(30));

        let quot = a.udiv(&ctx, &b);
        assert_eq!(quot.as_concrete(), Some(3));

        let rem = a.urem(&ctx, &b);
        assert_eq!(rem.as_concrete(), Some(1));
    }

    #[test]
    fn test_bitwise_ops() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(0b1100, 8);
        let b = SymValue::concrete(0b1010, 8);

        assert_eq!(a.and(&ctx, &b).as_concrete(), Some(0b1000));
        assert_eq!(a.or(&ctx, &b).as_concrete(), Some(0b1110));
        assert_eq!(a.xor(&ctx, &b).as_concrete(), Some(0b0110));
        assert_eq!(a.not(&ctx).as_concrete(), Some(0b11110011));
    }

    #[test]
    fn test_shift_ops() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(0b1100, 8);
        let amt = SymValue::concrete(2, 8);

        assert_eq!(a.shl(&ctx, &amt).as_concrete(), Some(0b110000));
        assert_eq!(a.lshr(&ctx, &amt).as_concrete(), Some(0b0011));
    }

    #[test]
    fn test_comparison_ops() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(10, 32);
        let b = SymValue::concrete(20, 32);

        assert_eq!(a.eq(&ctx, &a).as_concrete(), Some(1));
        assert_eq!(a.eq(&ctx, &b).as_concrete(), Some(0));
        assert_eq!(a.ult(&ctx, &b).as_concrete(), Some(1));
        assert_eq!(b.ult(&ctx, &a).as_concrete(), Some(0));
    }

    #[test]
    fn test_symbolic_creation() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let sym = SymValue::new_symbolic(&ctx, "x", 64);
        assert!(sym.is_symbolic());
        assert_eq!(sym.bits(), 64);
    }

    #[test]
    fn test_extension() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(0xFF, 8);

        let zext = a.zero_extend(&ctx, 16);
        assert_eq!(zext.as_concrete(), Some(0xFF));
        assert_eq!(zext.bits(), 16);

        let sext = a.sign_extend(&ctx, 16);
        assert_eq!(sext.bits(), 16);
        // 0xFF sign-extended = 0xFFFF
        assert_eq!(sext.as_concrete(), Some(0xFFFFFFFFFFFFFFFF)); // Due to our sign extension logic
    }

    #[test]
    fn test_extract() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let a = SymValue::concrete(0xABCD, 16);
        let low = a.extract(&ctx, 7, 0);
        assert_eq!(low.as_concrete(), Some(0xCD));
        assert_eq!(low.bits(), 8);

        let high = a.extract(&ctx, 15, 8);
        assert_eq!(high.as_concrete(), Some(0xAB));
    }
}

#[cfg(test)]
mod bitwidth_tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_add_different_bitwidths_concrete() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Create values of different widths
        let val8 = SymValue::concrete(5, 8);
        let val64 = SymValue::concrete(10, 64);

        // This should handle the mismatch gracefully
        let result = val8.add(&ctx, &val64);
        assert_eq!(result.as_concrete(), Some(15));
        assert_eq!(result.bits(), 64); // Result should use larger width
    }

    #[test]
    fn test_shl_different_bitwidths_concrete() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Create values of different widths - this is common in real code
        // where shift amount might be 8-bit but value is 64-bit
        let val64 = SymValue::concrete(5, 64);
        let shift8 = SymValue::concrete(2, 8);

        // This should handle the mismatch gracefully
        let result = val64.shl(&ctx, &shift8);
        assert_eq!(result.as_concrete(), Some(20)); // 5 << 2 = 20
        assert_eq!(result.bits(), 64); // Result keeps value's width
    }

    #[test]
    fn test_symbolic_different_bitwidths() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Create symbolic values of different widths
        let sym8 = SymValue::new_symbolic(&ctx, "x", 8);
        let sym64 = SymValue::new_symbolic(&ctx, "y", 64);

        // This should NOT crash with Z3 assertion anymore!
        let result = sym8.add(&ctx, &sym64);
        assert!(result.is_symbolic());
        assert_eq!(result.bits(), 64); // Result should use larger width
    }

    #[test]
    fn test_symbolic_shift_different_bitwidths() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Symbolic value with smaller shift amount
        let sym64 = SymValue::new_symbolic(&ctx, "val", 64);
        let shift8 = SymValue::new_symbolic(&ctx, "shift", 8);

        // This should NOT crash with Z3 assertion anymore!
        let result = sym64.shl(&ctx, &shift8);
        assert!(result.is_symbolic());
        assert_eq!(result.bits(), 64); // Shift preserves value width
    }

    #[test]
    fn test_comparison_different_bitwidths() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Create symbolic values of different widths
        let sym8 = SymValue::new_symbolic(&ctx, "x", 8);
        let sym64 = SymValue::new_symbolic(&ctx, "y", 64);

        // Comparison should NOT crash
        let result = sym8.ult(&ctx, &sym64);
        assert!(result.is_symbolic());
        assert_eq!(result.bits(), 1); // Comparison returns 1-bit
    }

    #[test]
    fn test_bitwise_different_bitwidths() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let sym8 = SymValue::new_symbolic(&ctx, "x", 8);
        let sym32 = SymValue::new_symbolic(&ctx, "y", 32);

        // AND, OR, XOR should NOT crash
        let and_result = sym8.and(&ctx, &sym32);
        assert!(and_result.is_symbolic());
        assert_eq!(and_result.bits(), 32);

        let or_result = sym8.or(&ctx, &sym32);
        assert!(or_result.is_symbolic());
        assert_eq!(or_result.bits(), 32);

        let xor_result = sym8.xor(&ctx, &sym32);
        assert!(xor_result.is_symbolic());
        assert_eq!(xor_result.bits(), 32);
    }
}
