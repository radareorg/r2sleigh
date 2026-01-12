//! Expression building and simplification.
//!
//! This module converts SSA operations to C expressions and performs
//! algebraic simplifications.

use r2ssa::{SSAOp, SSAVar};

use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};

/// Expression builder that converts SSA operations to C expressions.
pub struct ExpressionBuilder {
    /// Pointer size in bits.
    _ptr_size: u32,
}

impl ExpressionBuilder {
    /// Create a new expression builder.
    pub fn new(ptr_size: u32) -> Self {
        Self { _ptr_size: ptr_size }
    }

    /// Convert an SSA variable to a C expression.
    pub fn var_to_expr(&self, var: &SSAVar) -> CExpr {
        let name = self.var_name(var);
        CExpr::Var(name)
    }

    /// Get a C variable name for an SSA variable.
    pub fn var_name(&self, var: &SSAVar) -> String {
        // Clean up the name
        let base = if var.name.starts_with("reg:") {
            // Extract register name or use offset
            format!("r{}", var.name.trim_start_matches("reg:"))
        } else if var.name.starts_with("unique:") || var.name.starts_with("tmp:") {
            format!("t{}", var.version)
        } else {
            var.name.replace(':', "_")
        };

        if var.version > 0 {
            format!("{}_{}", base, var.version)
        } else {
            base
        }
    }

    /// Convert an SSA operation to a C statement.
    pub fn op_to_stmt(&self, op: &SSAOp) -> Option<CStmt> {
        match op {
            SSAOp::Copy { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = self.var_to_expr(src);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Load { dst, addr, .. } => {
                let lhs = self.var_to_expr(dst);
                let addr_expr = self.var_to_expr(addr);
                let rhs = CExpr::Deref(Box::new(addr_expr));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Store { addr, val, .. } => {
                let addr_expr = self.var_to_expr(addr);
                let val_expr = self.var_to_expr(val);
                let lhs = CExpr::Deref(Box::new(addr_expr));
                Some(CStmt::Expr(CExpr::assign(lhs, val_expr)))
            }
            SSAOp::IntAdd { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Add)
            }
            SSAOp::IntSub { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Sub)
            }
            SSAOp::IntMult { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Mul)
            }
            SSAOp::IntDiv { dst, a, b }
            | SSAOp::IntSDiv { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Div)
            }
            SSAOp::IntRem { dst, a, b }
            | SSAOp::IntSRem { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Mod)
            }
            SSAOp::IntAnd { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::BitAnd)
            }
            SSAOp::IntOr { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::BitOr)
            }
            SSAOp::IntXor { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::BitXor)
            }
            SSAOp::IntLeft { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Shl)
            }
            SSAOp::IntRight { dst, a, b }
            | SSAOp::IntSRight { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Shr)
            }
            SSAOp::IntLess { dst, a, b }
            | SSAOp::IntSLess { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Lt)
            }
            SSAOp::IntLessEqual { dst, a, b }
            | SSAOp::IntSLessEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Le)
            }
            SSAOp::IntEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Eq)
            }
            SSAOp::IntNotEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Ne)
            }
            SSAOp::IntNegate { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::unary(UnaryOp::Neg, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::IntNot { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::unary(UnaryOp::BitNot, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::BoolAnd { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::And)
            }
            SSAOp::BoolOr { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Or)
            }
            SSAOp::BoolXor { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::BitXor)
            }
            SSAOp::BoolNot { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::unary(UnaryOp::Not, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                // Cast to larger type
                let lhs = self.var_to_expr(dst);
                let ty = self.type_from_size(dst.size);
                let rhs = CExpr::cast(ty, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Trunc { dst, src } => {
                // Cast to smaller type
                let lhs = self.var_to_expr(dst);
                let ty = self.type_from_size(dst.size);
                let rhs = CExpr::cast(ty, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatAdd { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Add)
            }
            SSAOp::FloatSub { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Sub)
            }
            SSAOp::FloatMult { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Mul)
            }
            SSAOp::FloatDiv { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Div)
            }
            SSAOp::FloatNeg { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::unary(UnaryOp::Neg, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatLess { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Lt)
            }
            SSAOp::FloatLessEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Le)
            }
            SSAOp::FloatEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Eq)
            }
            SSAOp::FloatNotEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Ne)
            }
            SSAOp::Int2Float { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let ty = CType::Float(dst.size);
                let rhs = CExpr::cast(ty, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Float2Int { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let ty = self.type_from_size(dst.size);
                let rhs = CExpr::cast(ty, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatFloat { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let ty = CType::Float(dst.size);
                let rhs = CExpr::cast(ty, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Call { target } => {
                // Generate call expression
                let call = CExpr::call(self.var_to_expr(target), vec![]);
                Some(CStmt::Expr(call))
            }
            SSAOp::Return { target } => {
                Some(CStmt::Return(Some(self.var_to_expr(target))))
            }
            SSAOp::Branch { .. } | SSAOp::CBranch { .. } => {
                // Branches are handled by control flow structuring
                None
            }
            SSAOp::Phi { .. } => {
                // Phi nodes are handled separately
                None
            }
            SSAOp::Nop => None,
            SSAOp::Unimplemented => {
                Some(CStmt::comment("Unimplemented operation"))
            }
            _ => None,
        }
    }

    /// Create a binary operation statement.
    fn binary_op_stmt(
        &self,
        dst: &SSAVar,
        src1: &SSAVar,
        src2: &SSAVar,
        op: BinaryOp,
    ) -> Option<CStmt> {
        let lhs = self.var_to_expr(dst);
        let rhs = CExpr::binary(op, self.var_to_expr(src1), self.var_to_expr(src2));
        Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
    }

    /// Extract a condition expression from a branch operation.
    pub fn extract_condition(&self, op: &SSAOp) -> Option<CExpr> {
        match op {
            SSAOp::CBranch { cond, .. } => Some(self.var_to_expr(cond)),
            _ => None,
        }
    }

    /// Get a C type from a bit size.
    fn type_from_size(&self, bits: u32) -> CType {
        match bits {
            1 => CType::Bool,
            8 => CType::Int(8),
            16 => CType::Int(16),
            32 => CType::Int(32),
            64 => CType::Int(64),
            _ => CType::Int(bits),
        }
    }

    /// Simplify an expression.
    pub fn simplify(&self, expr: CExpr) -> CExpr {
        match expr {
            // x + 0 = x
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // 0 + x = x
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } if matches!(*left, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*right)
            }
            // x - 0 = x
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // x * 1 = x
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(1) | CExpr::UIntLit(1)) => {
                self.simplify(*left)
            }
            // 1 * x = x
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } if matches!(*left, CExpr::IntLit(1) | CExpr::UIntLit(1)) => {
                self.simplify(*right)
            }
            // x * 0 = 0
            CExpr::Binary {
                op: BinaryOp::Mul,
                right,
                ..
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                CExpr::IntLit(0)
            }
            // 0 * x = 0
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                ..
            } if matches!(*left, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                CExpr::IntLit(0)
            }
            // x / 1 = x
            CExpr::Binary {
                op: BinaryOp::Div,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(1) | CExpr::UIntLit(1)) => {
                self.simplify(*left)
            }
            // x & 0 = 0
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                right,
                ..
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                CExpr::IntLit(0)
            }
            // x | 0 = x
            CExpr::Binary {
                op: BinaryOp::BitOr,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // x ^ 0 = x
            CExpr::Binary {
                op: BinaryOp::BitXor,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // x << 0 = x
            CExpr::Binary {
                op: BinaryOp::Shl,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // x >> 0 = x
            CExpr::Binary {
                op: BinaryOp::Shr,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => {
                self.simplify(*left)
            }
            // !!x = x (for boolean)
            CExpr::Unary {
                op: UnaryOp::Not,
                ref operand,
            } if matches!(operand.as_ref(), CExpr::Unary { op: UnaryOp::Not, .. }) => {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary { op: UnaryOp::Not, operand }
                    }
                } else {
                    expr
                }
            }
            // --x = x
            CExpr::Unary {
                op: UnaryOp::Neg,
                ref operand,
            } if matches!(operand.as_ref(), CExpr::Unary { op: UnaryOp::Neg, .. }) => {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary { op: UnaryOp::Neg, operand }
                    }
                } else {
                    expr
                }
            }
            // ~~x = x
            CExpr::Unary {
                op: UnaryOp::BitNot,
                ref operand,
            } if matches!(operand.as_ref(), CExpr::Unary { op: UnaryOp::BitNot, .. }) => {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary { op: UnaryOp::BitNot, operand }
                    }
                } else {
                    expr
                }
            }
            // Constant folding for integers
            CExpr::Binary {
                op,
                ref left,
                ref right,
            } if matches!(left.as_ref(), CExpr::IntLit(_)) && matches!(right.as_ref(), CExpr::IntLit(_)) => {
                if let (CExpr::IntLit(a), CExpr::IntLit(b)) = (left.as_ref(), right.as_ref()) {
                    match op {
                        BinaryOp::Add => CExpr::IntLit(a.wrapping_add(*b)),
                        BinaryOp::Sub => CExpr::IntLit(a.wrapping_sub(*b)),
                        BinaryOp::Mul => CExpr::IntLit(a.wrapping_mul(*b)),
                        BinaryOp::Div if *b != 0 => CExpr::IntLit(a / b),
                        BinaryOp::Mod if *b != 0 => CExpr::IntLit(a % b),
                        BinaryOp::BitAnd => CExpr::IntLit(a & b),
                        BinaryOp::BitOr => CExpr::IntLit(a | b),
                        BinaryOp::BitXor => CExpr::IntLit(a ^ b),
                        BinaryOp::Shl => CExpr::IntLit(a << (b & 63)),
                        BinaryOp::Shr => CExpr::IntLit(a >> (b & 63)),
                        BinaryOp::Eq => CExpr::IntLit(if a == b { 1 } else { 0 }),
                        BinaryOp::Ne => CExpr::IntLit(if a != b { 1 } else { 0 }),
                        BinaryOp::Lt => CExpr::IntLit(if a < b { 1 } else { 0 }),
                        BinaryOp::Le => CExpr::IntLit(if a <= b { 1 } else { 0 }),
                        BinaryOp::Gt => CExpr::IntLit(if a > b { 1 } else { 0 }),
                        BinaryOp::Ge => CExpr::IntLit(if a >= b { 1 } else { 0 }),
                        _ => expr,
                    }
                } else {
                    expr
                }
            }
            // Recursively simplify binary operations
            CExpr::Binary { op, left, right } => {
                let left = self.simplify(*left);
                let right = self.simplify(*right);
                CExpr::binary(op, left, right)
            }
            // Recursively simplify unary operations
            CExpr::Unary { op, operand } => {
                let operand = self.simplify(*operand);
                CExpr::unary(op, operand)
            }
            // Other expressions pass through
            _ => expr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_name() {
        let builder = ExpressionBuilder::new(64);

        let var = SSAVar::new("reg:0", 1, 64);
        assert!(builder.var_name(&var).contains("r"));

        let var = SSAVar::new("unique:1234", 0, 32);
        assert!(builder.var_name(&var).starts_with("t"));
    }

    #[test]
    fn test_simplify_add_zero() {
        let builder = ExpressionBuilder::new(64);

        let expr = CExpr::binary(BinaryOp::Add, CExpr::var("x"), CExpr::int(0));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::var("x"));
    }

    #[test]
    fn test_simplify_mul_one() {
        let builder = ExpressionBuilder::new(64);

        let expr = CExpr::binary(BinaryOp::Mul, CExpr::var("x"), CExpr::int(1));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::var("x"));
    }

    #[test]
    fn test_simplify_mul_zero() {
        let builder = ExpressionBuilder::new(64);

        let expr = CExpr::binary(BinaryOp::Mul, CExpr::var("x"), CExpr::int(0));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::int(0));
    }

    #[test]
    fn test_constant_folding() {
        let builder = ExpressionBuilder::new(64);

        let expr = CExpr::binary(BinaryOp::Add, CExpr::int(2), CExpr::int(3));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::int(5));

        let expr = CExpr::binary(BinaryOp::Mul, CExpr::int(4), CExpr::int(5));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::int(20));
    }

    #[test]
    fn test_double_negation() {
        let builder = ExpressionBuilder::new(64);

        let expr = CExpr::unary(UnaryOp::Neg, CExpr::unary(UnaryOp::Neg, CExpr::var("x")));
        let simplified = builder.simplify(expr);
        assert_eq!(simplified, CExpr::var("x"));
    }
}
