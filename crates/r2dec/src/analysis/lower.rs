use std::collections::{HashMap, HashSet};

use r2ssa::{SSAOp, SSAVar};
use r2types::TypeOracle;

use super::utils::parse_const_value;
use crate::address::parse_address_from_var_name;
use crate::ast::{BinaryOp, CExpr, CType, UnaryOp};
use crate::fold::PtrArith;

pub(crate) struct LowerCtx<'a> {
    pub(crate) definitions: &'a HashMap<String, CExpr>,
    pub(crate) use_counts: &'a HashMap<String, usize>,
    pub(crate) condition_vars: &'a HashSet<String>,
    pub(crate) pinned: &'a HashSet<String>,
    pub(crate) var_aliases: &'a HashMap<String, String>,
    pub(crate) ptr_arith: &'a HashMap<String, PtrArith>,
    pub(crate) function_names: &'a HashMap<u64, String>,
    pub(crate) strings: &'a HashMap<u64, String>,
    pub(crate) symbols: &'a HashMap<u64, String>,
    pub(crate) type_oracle: Option<&'a dyn TypeOracle>,
}

impl<'a> LowerCtx<'a> {
    pub(crate) fn var_name(&self, var: &SSAVar) -> String {
        if var.is_const() {
            let val = parse_const_value(&var.name).unwrap_or(0);
            if val > 0xffff {
                return format!("0x{:x}", val);
            }
            return format!("{}", val);
        }

        if let Some(addr) = parse_address_from_var_name(&var.name) {
            if let Some(name) = self.function_names.get(&addr) {
                return name.clone();
            }
            if let Some(name) = self.symbols.get(&addr) {
                return name.clone();
            }
        }

        let display = var.display_name();
        if let Some(alias) = self.var_aliases.get(&display) {
            return alias.clone();
        }

        let base = if var.name.starts_with("reg:") {
            let reg = var.name.trim_start_matches("reg:");
            if is_hex_name(reg) {
                format!("r{}", reg)
            } else {
                reg.to_string()
            }
        } else if var.name.starts_with("tmp:") {
            format!("t{}", var.version)
        } else {
            var.name.to_lowercase()
        };

        if var.version > 0 {
            format!("{}_{}", base, var.version)
        } else {
            base
        }
    }

    pub(crate) fn get_expr(&self, var: &SSAVar) -> CExpr {
        self.get_expr_with_depth(var, 0, &mut HashSet::new())
    }

    fn get_expr_with_depth(
        &self,
        var: &SSAVar,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if var.is_const() {
            return self.const_to_expr(var);
        }

        if let Some(addr) = parse_address_from_var_name(&var.name)
            && let Some(expr) = self.resolve_addr_literal(addr)
        {
            return expr;
        }

        let key = var.display_name();
        if depth < 8
            && self.should_inline(&key)
            && visited.insert(key.clone())
            && let Some(expr) = self.definitions.get(&key)
        {
            return expr.clone();
        }

        CExpr::Var(self.var_name(var))
    }

    pub(crate) fn op_to_expr(&self, op: &SSAOp) -> CExpr {
        match op {
            SSAOp::Copy { src, .. } => self.get_expr(src),
            SSAOp::Load { addr, .. } => {
                if let Some(ptr) = self.ptr_arith.get(&addr.display_name()) {
                    self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
                } else {
                    CExpr::Deref(Box::new(self.get_expr(addr)))
                }
            }
            SSAOp::IntAdd { a, b, .. } => self.binary_expr(BinaryOp::Add, a, b),
            SSAOp::IntSub { a, b, .. } => self.binary_expr(BinaryOp::Sub, a, b),
            SSAOp::IntMult { a, b, .. } => self.binary_expr(BinaryOp::Mul, a, b),
            SSAOp::IntDiv { dst, a, b } => self.typed_binary_expr(
                BinaryOp::Div,
                a,
                b,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSDiv { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Div, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntRem { dst, a, b } => self.typed_binary_expr(
                BinaryOp::Mod,
                a,
                b,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSRem { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Mod, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntAnd { a, b, .. } => self.binary_expr(BinaryOp::BitAnd, a, b),
            SSAOp::IntOr { a, b, .. } => self.binary_expr(BinaryOp::BitOr, a, b),
            SSAOp::IntXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::IntLeft { a, b, .. } => self.binary_expr(BinaryOp::Shl, a, b),
            SSAOp::IntRight { dst, a, b } => self.typed_binary_expr(
                BinaryOp::Shr,
                a,
                b,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSRight { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Shr, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntLess { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Lt,
                a,
                b,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLess { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Lt,
                a,
                b,
                Some(type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntLessEqual { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Le,
                a,
                b,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLessEqual { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Le,
                a,
                b,
                Some(type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntEqual { a, b, .. } => self.binary_expr(BinaryOp::Eq, a, b),
            SSAOp::IntNotEqual { a, b, .. } => self.binary_expr(BinaryOp::Ne, a, b),
            SSAOp::IntNegate { src, .. } => CExpr::unary(UnaryOp::Neg, self.get_expr(src)),
            SSAOp::IntNot { src, .. } => CExpr::unary(UnaryOp::BitNot, self.get_expr(src)),
            SSAOp::BoolAnd { a, b, .. } => self.binary_expr(BinaryOp::And, a, b),
            SSAOp::BoolOr { a, b, .. } => self.binary_expr(BinaryOp::Or, a, b),
            SSAOp::BoolXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::BoolNot { src, .. } => CExpr::unary(UnaryOp::Not, self.get_expr(src)),
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                CExpr::cast(type_from_size(dst.size), self.get_expr(src))
            }
            SSAOp::Trunc { dst, src } => CExpr::cast(type_from_size(dst.size), self.get_expr(src)),
            SSAOp::Piece { dst, hi, lo } => {
                let shift_bits = lo.size.saturating_mul(8);
                let dst_ty = uint_type_from_size(dst.size);
                let hi_cast = CExpr::cast(dst_ty.clone(), self.get_expr(hi));
                let lo_cast = CExpr::cast(dst_ty.clone(), self.get_expr(lo));
                let shifted = if shift_bits == 0 {
                    hi_cast
                } else {
                    CExpr::binary(BinaryOp::Shl, hi_cast, CExpr::IntLit(shift_bits as i64))
                };
                CExpr::binary(BinaryOp::BitOr, shifted, lo_cast)
            }
            SSAOp::Subpiece { dst, src, offset } => {
                if *offset == 0 && dst.size == src.size {
                    self.get_expr(src)
                } else if *offset == 0 {
                    CExpr::cast(uint_type_from_size(dst.size), self.get_expr(src))
                } else {
                    let shift_bits = offset.saturating_mul(8);
                    let src_cast = CExpr::cast(uint_type_from_size(src.size), self.get_expr(src));
                    let shifted =
                        CExpr::binary(BinaryOp::Shr, src_cast, CExpr::IntLit(shift_bits as i64));
                    CExpr::cast(uint_type_from_size(dst.size), shifted)
                }
            }
            SSAOp::FloatAdd { a, b, .. } => self.binary_expr(BinaryOp::Add, a, b),
            SSAOp::FloatSub { a, b, .. } => self.binary_expr(BinaryOp::Sub, a, b),
            SSAOp::FloatMult { a, b, .. } => self.binary_expr(BinaryOp::Mul, a, b),
            SSAOp::FloatDiv { a, b, .. } => self.binary_expr(BinaryOp::Div, a, b),
            SSAOp::FloatNeg { src, .. } => CExpr::unary(UnaryOp::Neg, self.get_expr(src)),
            SSAOp::FloatLess { a, b, .. } => self.binary_expr(BinaryOp::Lt, a, b),
            SSAOp::FloatLessEqual { a, b, .. } => self.binary_expr(BinaryOp::Le, a, b),
            SSAOp::FloatEqual { a, b, .. } => self.binary_expr(BinaryOp::Eq, a, b),
            SSAOp::FloatNotEqual { a, b, .. } => self.binary_expr(BinaryOp::Ne, a, b),
            SSAOp::Int2Float { dst, src } => {
                let ty = CType::Float(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Float2Int { dst, src } => {
                CExpr::cast(type_from_size(dst.size), self.get_expr(src))
            }
            SSAOp::Cast { dst, src } => CExpr::cast(type_from_size(dst.size), self.get_expr(src)),
            SSAOp::Call { target } => CExpr::call(self.get_expr(target), vec![]),
            SSAOp::CallInd { target } => {
                CExpr::call(CExpr::Deref(Box::new(self.get_expr(target))), vec![])
            }
            SSAOp::CallOther {
                output: _,
                userop,
                inputs,
            } => {
                let mut args = Vec::with_capacity(inputs.len() + 1);
                args.push(CExpr::StringLit(format!("userop_{}", userop)));
                for input in inputs {
                    args.push(self.get_expr(input));
                }
                CExpr::call(CExpr::Var("callother".to_string()), args)
            }
            SSAOp::CpuId { .. } => CExpr::call(
                CExpr::Var("callother".to_string()),
                vec![CExpr::StringLit("cpuid".to_string())],
            ),
            SSAOp::PtrAdd {
                base,
                index,
                element_size,
                ..
            } => self.ptr_arith_expr(base, index, *element_size, false),
            SSAOp::PtrSub {
                base,
                index,
                element_size,
                ..
            } => self.ptr_arith_expr(base, index, *element_size, true),
            _ => {
                if let Some(dst) = op.dst() {
                    CExpr::Var(self.var_name(dst))
                } else {
                    CExpr::Var("__unhandled_op__".to_string())
                }
            }
        }
    }

    fn should_inline(&self, var_name: &str) -> bool {
        let use_count = self.use_counts.get(var_name).copied().unwrap_or(0);
        if use_count == 0 || use_count > 3 {
            return false;
        }

        if self.pinned.contains(var_name) {
            return false;
        }

        if self.condition_vars.contains(var_name) {
            return false;
        }

        if var_name.starts_with("tmp:") || var_name.starts_with("const:") {
            return true;
        }

        use_count == 1
    }

    fn const_to_expr(&self, var: &SSAVar) -> CExpr {
        let val = parse_const_value(&var.name).unwrap_or(0);
        if let Some(addr) = parse_address_from_var_name(&var.name)
            && let Some(expr) = self.resolve_addr_literal(addr)
        {
            return expr;
        }
        if val > 0x7fffffff {
            CExpr::UIntLit(val)
        } else {
            CExpr::IntLit(val as i64)
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

    fn binary_expr(&self, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> CExpr {
        CExpr::binary(op, self.get_expr(a), self.get_expr(b))
    }

    fn cast_expr_if_needed(&self, expr: CExpr, ty: CType) -> CExpr {
        if let CExpr::Cast { ty: existing, .. } = &expr
            && *existing == ty
        {
            return expr;
        }
        CExpr::cast(ty, expr)
    }

    fn typed_binary_expr(
        &self,
        op: BinaryOp,
        a: &SSAVar,
        b: &SSAVar,
        operand_ty: Option<CType>,
    ) -> CExpr {
        let mut lhs = self.get_expr(a);
        let mut rhs = self.get_expr(b);
        if let Some(ty) = operand_ty {
            lhs = self.cast_expr_if_needed(lhs, ty.clone());
            rhs = self.cast_expr_if_needed(rhs, ty);
        }
        CExpr::binary(op, lhs, rhs)
    }

    fn ptr_arith_expr(
        &self,
        base: &SSAVar,
        index: &SSAVar,
        element_size: u32,
        is_sub: bool,
    ) -> CExpr {
        let base_expr = self.get_expr(base);
        let index_expr = self.get_expr(index);
        let scaled = if element_size <= 1 {
            index_expr
        } else {
            CExpr::binary(
                BinaryOp::Mul,
                index_expr,
                CExpr::IntLit(element_size as i64),
            )
        };
        let op = if is_sub { BinaryOp::Sub } else { BinaryOp::Add };
        CExpr::binary(op, base_expr, scaled)
    }

    fn ptr_subscript_expr(
        &self,
        base: &SSAVar,
        index: &SSAVar,
        element_size: u32,
        is_sub: bool,
    ) -> CExpr {
        let elem_ty = if let Some(oracle) = self.type_oracle {
            let base_ty = oracle.type_of(base);
            if oracle.is_array(base_ty) || oracle.is_pointer(base_ty) {
                uint_type_from_size(element_size)
            } else {
                type_from_size(element_size)
            }
        } else {
            uint_type_from_size(element_size)
        };
        let base_expr = CExpr::cast(CType::ptr(elem_ty), self.get_expr(base));
        let index_expr = if is_sub {
            CExpr::unary(UnaryOp::Neg, self.get_expr(index))
        } else {
            self.get_expr(index)
        };
        CExpr::Subscript {
            base: Box::new(base_expr),
            index: Box::new(index_expr),
        }
    }
}

fn type_from_size(size: u32) -> CType {
    match size {
        0 => CType::Unknown,
        1 => CType::Int(8),
        2 => CType::Int(16),
        4 => CType::Int(32),
        8 => CType::Int(64),
        _ => CType::Int(size.saturating_mul(8)),
    }
}

fn uint_type_from_size(size: u32) -> CType {
    match size {
        0 => CType::Unknown,
        1 => CType::UInt(8),
        2 => CType::UInt(16),
        4 => CType::UInt(32),
        8 => CType::UInt(64),
        _ => CType::UInt(size.saturating_mul(8)),
    }
}

fn is_hex_name(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx<'a>(
        definitions: &'a HashMap<String, CExpr>,
        use_counts: &'a HashMap<String, usize>,
        condition_vars: &'a HashSet<String>,
        pinned: &'a HashSet<String>,
        var_aliases: &'a HashMap<String, String>,
        ptr_arith: &'a HashMap<String, PtrArith>,
        function_names: &'a HashMap<u64, String>,
        strings: &'a HashMap<u64, String>,
        symbols: &'a HashMap<u64, String>,
    ) -> LowerCtx<'a> {
        LowerCtx {
            definitions,
            use_counts,
            condition_vars,
            pinned,
            var_aliases,
            ptr_arith,
            function_names,
            strings,
            symbols,
            type_oracle: None,
        }
    }

    #[test]
    fn resolve_addr_literal_prefers_function_then_string_then_symbol() {
        let mut fn_map = HashMap::new();
        let mut str_map = HashMap::new();
        let mut sym_map = HashMap::new();

        fn_map.insert(0x401000, "sym.main".to_string());
        str_map.insert(0x402000, "format: %d\\n".to_string());
        sym_map.insert(0x403000, "obj.global".to_string());
        str_map.insert(0x404000, "string_wins_over_symbol".to_string());
        sym_map.insert(0x404000, "obj.same_addr".to_string());
        fn_map.insert(0x405000, "sym.wins".to_string());
        str_map.insert(0x405000, "string_loses".to_string());
        sym_map.insert(0x405000, "symbol_loses".to_string());
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &fn_map,
            &str_map,
            &sym_map,
        );

        assert_eq!(
            ctx.resolve_addr_literal(0x401000),
            Some(CExpr::Var("sym.main".to_string()))
        );
        assert_eq!(
            ctx.resolve_addr_literal(0x402000),
            Some(CExpr::StringLit("format: %d\\n".to_string()))
        );
        assert_eq!(
            ctx.resolve_addr_literal(0x403000),
            Some(CExpr::Var("obj.global".to_string()))
        );
        assert_eq!(
            ctx.resolve_addr_literal(0x404000),
            Some(CExpr::StringLit("string_wins_over_symbol".to_string()))
        );
        assert_eq!(
            ctx.resolve_addr_literal(0x405000),
            Some(CExpr::Var("sym.wins".to_string()))
        );
    }

    #[test]
    fn resolve_addr_literal_skips_small_and_unknown_values() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &fn_map,
            &str_map,
            &sym_map,
        );

        assert_eq!(ctx.resolve_addr_literal(0xff), None);
        assert_eq!(ctx.resolve_addr_literal(0x5000), None);
    }

    #[test]
    fn get_expr_resolves_ram_addresses_to_strings() {
        let fn_map = HashMap::new();
        let mut str_map = HashMap::new();
        let sym_map = HashMap::new();
        str_map.insert(0x403048, "Usage: %s <test_num> [args...]\\n".to_string());
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let var = SSAVar::new("ram:403048", 0, 8);
        assert_eq!(
            ctx.get_expr(&var),
            CExpr::StringLit("Usage: %s <test_num> [args...]\\n".to_string())
        );
    }
}
