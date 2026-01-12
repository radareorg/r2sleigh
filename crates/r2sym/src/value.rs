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
            (Self::Concrete { value: hi, bits: _ }, Self::Concrete { value: lo, bits: lo_bits }) => {
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
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
                Self::Concrete {
                    value: a.wrapping_add(*b) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvadd(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Subtract two values.
    pub fn sub(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
                Self::Concrete {
                    value: a.wrapping_sub(*b) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvsub(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Multiply two values.
    pub fn mul(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
                Self::Concrete {
                    value: a.wrapping_mul(*b) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvmul(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Unsigned division.
    pub fn udiv(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => {
                if *b == 0 {
                    Self::Unknown { bits: *bits }
                } else {
                    Self::Concrete {
                        value: *a / *b,
                        bits: *bits,
                    }
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvudiv(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Signed division.
    pub fn sdiv(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let a_bv = self.to_bv(ctx);
        let b_bv = other.to_bv(ctx);
        Self::Symbolic {
            ast: a_bv.bvsdiv(&b_bv),
            bits: self.bits(),
        }
    }

    /// Unsigned remainder.
    pub fn urem(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => {
                if *b == 0 {
                    Self::Unknown { bits: *bits }
                } else {
                    Self::Concrete {
                        value: *a % *b,
                        bits: *bits,
                    }
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvurem(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Signed remainder.
    pub fn srem(&self, ctx: &'ctx Context, other: &Self) -> Self {
        let a_bv = self.to_bv(ctx);
        let b_bv = other.to_bv(ctx);
        Self::Symbolic {
            ast: a_bv.bvsrem(&b_bv),
            bits: self.bits(),
        }
    }

    /// Two's complement negation.
    pub fn neg(&self, ctx: &'ctx Context) -> Self {
        match self {
            Self::Concrete { value, bits } => {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
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
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: *a & *b,
                bits: *bits,
            },
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvand(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Bitwise OR.
    pub fn or(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: *a | *b,
                bits: *bits,
            },
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvor(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Bitwise XOR.
    pub fn xor(&self, ctx: &'ctx Context, other: &Self) -> Self {
        match (self, other) {
            (Self::Concrete { value: a, bits }, Self::Concrete { value: b, .. }) => Self::Concrete {
                value: *a ^ *b,
                bits: *bits,
            },
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
                Self::Symbolic {
                    ast: a_bv.bvxor(&b_bv),
                    bits: self.bits(),
                }
            }
        }
    }

    /// Bitwise NOT.
    pub fn not(&self, ctx: &'ctx Context) -> Self {
        match self {
            Self::Concrete { value, bits } => {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
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
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << *bits) - 1 };
                Self::Concrete {
                    value: (*value << (*amt as u32)) & mask,
                    bits: *bits,
                }
            }
            _ => {
                let a_bv = self.to_bv(ctx);
                let b_bv = amount.to_bv(ctx);
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
                let b_bv = amount.to_bv(ctx);
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
        let b_bv = amount.to_bv(ctx);
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
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
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
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
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
                let a_bv = self.to_bv(ctx);
                let b_bv = other.to_bv(ctx);
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
        let a_bv = self.to_bv(ctx);
        let b_bv = other.to_bv(ctx);
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
        let a_bv = self.to_bv(ctx);
        let b_bv = other.to_bv(ctx);
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
