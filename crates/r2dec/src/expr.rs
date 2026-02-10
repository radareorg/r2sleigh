//! Expression building and simplification.
//!
//! This module converts SSA operations to C expressions and performs
//! algebraic simplifications.

use std::collections::HashMap;

use r2ssa::{SSAOp, SSAVar};

use crate::address::parse_address_from_var_name;
use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};

/// Expression builder that converts SSA operations to C expressions.
pub struct ExpressionBuilder {
    /// Pointer size in bits.
    _ptr_size: u32,
    /// Function address to name mapping.
    function_names: HashMap<u64, String>,
    /// String literal address mapping.
    strings: HashMap<u64, String>,
    /// Symbol/global address mapping.
    symbols: HashMap<u64, String>,
}

impl ExpressionBuilder {
    /// Create a new expression builder.
    pub fn new(ptr_size: u32) -> Self {
        Self {
            _ptr_size: ptr_size,
            function_names: HashMap::new(),
            strings: HashMap::new(),
            symbols: HashMap::new(),
        }
    }

    /// Set function names for address resolution.
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.function_names = names;
    }

    /// Set string literals for address resolution.
    pub fn set_strings(&mut self, strings: HashMap<u64, String>) {
        self.strings = strings;
    }

    /// Set symbol names for address resolution.
    pub fn set_symbols(&mut self, symbols: HashMap<u64, String>) {
        self.symbols = symbols;
    }

    /// Convert an SSA variable to a C expression.
    pub fn var_to_expr(&self, var: &SSAVar) -> CExpr {
        if let Some(addr) = parse_address_from_var_name(&var.name)
            && let Some(resolved) = self.resolve_addr_literal(addr)
        {
            return resolved;
        }
        let name = self.var_name(var);
        CExpr::Var(name)
    }

    /// Get a C variable name for an SSA variable.
    pub fn var_name(&self, var: &SSAVar) -> String {
        // Clean up the name
        let base = if var.name.starts_with("reg:") {
            // Extract register name or use offset
            let reg = var.name.trim_start_matches("reg:");
            if is_hex_name(reg) {
                format!("r{}", reg)
            } else {
                reg.to_string()
            }
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
            SSAOp::IntAdd { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Add),
            SSAOp::IntSub { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Sub),
            SSAOp::IntMult { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Mul),
            SSAOp::IntDiv { dst, a, b } | SSAOp::IntSDiv { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Div)
            }
            SSAOp::IntRem { dst, a, b } | SSAOp::IntSRem { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Mod)
            }
            SSAOp::IntAnd { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::BitAnd),
            SSAOp::IntOr { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::BitOr),
            SSAOp::IntXor { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::BitXor),
            SSAOp::IntLeft { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Shl),
            SSAOp::IntRight { dst, a, b } | SSAOp::IntSRight { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Shr)
            }
            SSAOp::IntLess { dst, a, b } | SSAOp::IntSLess { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Lt)
            }
            SSAOp::IntLessEqual { dst, a, b } | SSAOp::IntSLessEqual { dst, a, b } => {
                self.binary_op_stmt(dst, a, b, BinaryOp::Le)
            }
            SSAOp::IntEqual { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Eq),
            SSAOp::IntNotEqual { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Ne),
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
            SSAOp::BoolAnd { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::And),
            SSAOp::BoolOr { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Or),
            SSAOp::BoolXor { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::BitXor),
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
            SSAOp::FloatAdd { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Add),
            SSAOp::FloatSub { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Sub),
            SSAOp::FloatMult { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Mul),
            SSAOp::FloatDiv { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Div),
            SSAOp::FloatNeg { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::unary(UnaryOp::Neg, self.var_to_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatAbs { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("fabs".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatSqrt { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("sqrt".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatCeil { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("ceil".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatFloor { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("floor".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatRound { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("round".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatNaN { dst, src } => {
                let lhs = self.var_to_expr(dst);
                let rhs = CExpr::call(CExpr::Var("isnan".to_string()), vec![self.var_to_expr(src)]);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::FloatLess { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Lt),
            SSAOp::FloatLessEqual { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Le),
            SSAOp::FloatEqual { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Eq),
            SSAOp::FloatNotEqual { dst, a, b } => self.binary_op_stmt(dst, a, b, BinaryOp::Ne),
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
            SSAOp::Return { target } => Some(CStmt::Return(Some(self.var_to_expr(target)))),
            SSAOp::Branch { .. } | SSAOp::CBranch { .. } => {
                // Branches are handled by control flow structuring
                None
            }
            SSAOp::Phi { .. } => {
                // Phi nodes are handled separately
                None
            }
            SSAOp::Nop => None,
            SSAOp::Unimplemented => Some(CStmt::comment("Unimplemented operation")),
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

    /// Get a C type from a byte size.
    fn type_from_size(&self, size: u32) -> CType {
        match size {
            0 => CType::Unknown,
            1 => CType::Int(8),
            2 => CType::Int(16),
            4 => CType::Int(32),
            8 => CType::Int(64),
            _ => CType::Int(size.saturating_mul(8)),
        }
    }

    fn resolve_addr_literal(&self, addr: u64) -> Option<CExpr> {
        if addr <= 0xff {
            return None;
        }
        if let Some(name) = self.function_names.get(&addr) {
            return Some(CExpr::Var(name.clone()));
        }
        if let Some(s) = self.strings.get(&addr) {
            return Some(CExpr::StringLit(s.clone()));
        }
        if let Some(name) = self.symbols.get(&addr) {
            return Some(CExpr::Var(name.clone()));
        }
        None
    }

    /// Simplify an expression.
    pub fn simplify(&self, expr: CExpr) -> CExpr {
        match expr {
            // x + 0 = x
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // 0 + x = x
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } if matches!(*left, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*right),
            // x - 0 = x
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // x * 1 = x
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(1) | CExpr::UIntLit(1)) => self.simplify(*left),
            // 1 * x = x
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } if matches!(*left, CExpr::IntLit(1) | CExpr::UIntLit(1)) => self.simplify(*right),
            // x * 0 = 0
            CExpr::Binary {
                op: BinaryOp::Mul,
                right,
                ..
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => CExpr::IntLit(0),
            // 0 * x = 0
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                ..
            } if matches!(*left, CExpr::IntLit(0) | CExpr::UIntLit(0)) => CExpr::IntLit(0),
            // x / 1 = x
            CExpr::Binary {
                op: BinaryOp::Div,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(1) | CExpr::UIntLit(1)) => self.simplify(*left),
            // x & 0 = 0
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                right,
                ..
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => CExpr::IntLit(0),
            // x | 0 = x
            CExpr::Binary {
                op: BinaryOp::BitOr,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // x ^ 0 = x
            CExpr::Binary {
                op: BinaryOp::BitXor,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // x << 0 = x
            CExpr::Binary {
                op: BinaryOp::Shl,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // x >> 0 = x
            CExpr::Binary {
                op: BinaryOp::Shr,
                left,
                right,
            } if matches!(*right, CExpr::IntLit(0) | CExpr::UIntLit(0)) => self.simplify(*left),
            // !!x = x (for boolean)
            CExpr::Unary {
                op: UnaryOp::Not,
                ref operand,
            } if matches!(
                operand.as_ref(),
                CExpr::Unary {
                    op: UnaryOp::Not,
                    ..
                }
            ) =>
            {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary {
                            op: UnaryOp::Not,
                            operand,
                        }
                    }
                } else {
                    expr
                }
            }
            // --x = x
            CExpr::Unary {
                op: UnaryOp::Neg,
                ref operand,
            } if matches!(
                operand.as_ref(),
                CExpr::Unary {
                    op: UnaryOp::Neg,
                    ..
                }
            ) =>
            {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary {
                            op: UnaryOp::Neg,
                            operand,
                        }
                    }
                } else {
                    expr
                }
            }
            // ~~x = x
            CExpr::Unary {
                op: UnaryOp::BitNot,
                ref operand,
            } if matches!(
                operand.as_ref(),
                CExpr::Unary {
                    op: UnaryOp::BitNot,
                    ..
                }
            ) =>
            {
                if let CExpr::Unary { operand, .. } = expr {
                    if let CExpr::Unary { operand: inner, .. } = *operand {
                        self.simplify(*inner)
                    } else {
                        CExpr::Unary {
                            op: UnaryOp::BitNot,
                            operand,
                        }
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
            } if matches!(left.as_ref(), CExpr::IntLit(_))
                && matches!(right.as_ref(), CExpr::IntLit(_)) =>
            {
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

fn is_hex_name(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_var_name() {
        let builder = ExpressionBuilder::new(64);

        let var = SSAVar::new("reg:0", 1, 64);
        assert!(builder.var_name(&var).contains("r"));

        let var = SSAVar::new("unique:1234", 0, 32);
        assert!(builder.var_name(&var).starts_with("t"));
    }

    #[test]
    fn test_var_to_expr_resolves_const_symbol() {
        let mut builder = ExpressionBuilder::new(64);
        let mut symbols = HashMap::new();
        symbols.insert(0x404080, "obj.global_counter".to_string());
        builder.set_symbols(symbols);

        let var = SSAVar::new("const:404080", 0, 8);
        assert_eq!(
            builder.var_to_expr(&var),
            CExpr::Var("obj.global_counter".to_string())
        );
    }

    #[test]
    fn test_var_to_expr_resolves_ram_symbol_with_suffix() {
        let mut builder = ExpressionBuilder::new(64);
        let mut symbols = HashMap::new();
        symbols.insert(0x404080, "obj.global_counter".to_string());
        builder.set_symbols(symbols);

        let var = SSAVar::new("ram:404080_7", 0, 8);
        assert_eq!(
            builder.var_to_expr(&var),
            CExpr::Var("obj.global_counter".to_string())
        );
    }

    #[test]
    fn test_var_to_expr_resolution_precedence() {
        let mut builder = ExpressionBuilder::new(64);
        let mut functions = HashMap::new();
        let mut strings = HashMap::new();
        let mut symbols = HashMap::new();
        functions.insert(0x401000, "sym.main".to_string());
        strings.insert(0x401000, "string_loses".to_string());
        symbols.insert(0x401000, "obj.loses".to_string());
        strings.insert(0x402000, "string_wins".to_string());
        symbols.insert(0x402000, "obj.loses".to_string());
        symbols.insert(0x403000, "obj.wins".to_string());
        builder.set_function_names(functions);
        builder.set_strings(strings);
        builder.set_symbols(symbols);

        assert_eq!(
            builder.var_to_expr(&SSAVar::new("const:401000", 0, 8)),
            CExpr::Var("sym.main".to_string())
        );
        assert_eq!(
            builder.var_to_expr(&SSAVar::new("const:402000", 0, 8)),
            CExpr::StringLit("string_wins".to_string())
        );
        assert_eq!(
            builder.var_to_expr(&SSAVar::new("const:403000", 0, 8)),
            CExpr::Var("obj.wins".to_string())
        );
    }

    #[test]
    fn test_var_to_expr_unknown_address_falls_back() {
        let builder = ExpressionBuilder::new(64);
        let var = SSAVar::new("const:5000", 0, 8);
        assert_eq!(
            builder.var_to_expr(&var),
            CExpr::Var("const_5000".to_string())
        );
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
