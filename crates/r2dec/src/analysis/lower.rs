use std::collections::{HashMap, HashSet};

use r2ssa::{SSAOp, SSAVar};
use r2types::TypeOracle;

use super::utils::{format_traced_name, parse_const_value};
use super::{StackSlotProvenance, ValueProvenance};
use crate::address::parse_address_from_var_name;
use crate::ast::{BinaryOp, CExpr, CType, UnaryOp};
use crate::fold::PtrArith;

pub(crate) struct LowerCtx<'a> {
    pub(crate) definitions: &'a HashMap<String, CExpr>,
    pub(crate) use_counts: &'a HashMap<String, usize>,
    pub(crate) condition_vars: &'a HashSet<String>,
    pub(crate) pinned: &'a HashSet<String>,
    pub(crate) var_aliases: &'a HashMap<String, String>,
    pub(crate) type_hints: &'a HashMap<String, CType>,
    pub(crate) ptr_arith: &'a HashMap<String, PtrArith>,
    pub(crate) stack_slots: &'a HashMap<String, StackSlotProvenance>,
    pub(crate) forwarded_values: &'a HashMap<String, ValueProvenance>,
    pub(crate) function_names: &'a HashMap<u64, String>,
    pub(crate) strings: &'a HashMap<u64, String>,
    pub(crate) symbols: &'a HashMap<u64, String>,
    pub(crate) type_oracle: Option<&'a dyn TypeOracle>,
}

impl<'a> LowerCtx<'a> {
    fn lookup_type_hint(&self, name: &str) -> Option<&CType> {
        self.type_hints
            .get(name)
            .or_else(|| self.type_hints.get(&name.to_ascii_lowercase()))
    }

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
        if let Some(prov) = self.forwarded_values.get(&key)
            && depth < 8
            && visited.insert(format!("prov:{key}"))
        {
            return self.expr_for_ssa_name_with_depth(&prov.source, depth + 1, visited);
        }
        if depth < 8
            && self.should_inline(&key)
            && visited.insert(key.clone())
            && let Some(expr) = self.definitions.get(&key)
        {
            return expr.clone();
        }

        CExpr::Var(self.var_name(var))
    }

    pub(crate) fn expr_for_ssa_name(&self, name: &str) -> CExpr {
        self.expr_for_ssa_name_with_depth(name, 0, &mut HashSet::new())
    }

    fn expr_for_ssa_name_with_depth(
        &self,
        name: &str,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > 8 {
            return CExpr::Var(format_traced_name(name, self.var_aliases));
        }

        if let Some(val) = parse_const_value(name) {
            return if val > 0x7fffffff {
                CExpr::UIntLit(val)
            } else {
                CExpr::IntLit(val as i64)
            };
        }

        if let Some(addr) = parse_address_from_var_name(name)
            && let Some(expr) = self.resolve_addr_literal(addr)
        {
            return expr;
        }

        if let Some(prov) = self.forwarded_values.get(name)
            && visited.insert(format!("prov:{name}"))
        {
            return self.expr_for_ssa_name_with_depth(&prov.source, depth + 1, visited);
        }

        if let Some(expr) = self.definitions.get(name)
            && visited.insert(name.to_string())
        {
            return expr.clone();
        }

        if let Some(alias) = self.var_aliases.get(name) {
            return CExpr::Var(alias.clone());
        }

        CExpr::Var(format_traced_name(name, self.var_aliases))
    }

    pub(crate) fn op_to_expr(&self, op: &SSAOp) -> CExpr {
        match op {
            SSAOp::Copy { src, .. } => self.get_expr(src),
            SSAOp::Load { dst, addr, .. } => {
                if let Some(sub) = self.try_subscript_from_var(addr, dst.size) {
                    sub
                } else {
                    self.typed_deref_expr(addr, dst.size)
                }
            }
            SSAOp::IntAdd { a, b, .. } => self.binary_expr(BinaryOp::Add, a, b),
            SSAOp::IntSub { a, b, .. } => self.binary_expr(BinaryOp::Sub, a, b),
            SSAOp::IntMult { a, b, .. } => self.binary_expr(BinaryOp::Mul, a, b),
            SSAOp::IntDiv { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Div, a, b, Some(uint_type_from_size(dst.size)))
            }
            SSAOp::IntSDiv { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Div, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntRem { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Mod, a, b, Some(uint_type_from_size(dst.size)))
            }
            SSAOp::IntSRem { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Mod, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntAnd { a, b, .. } => self.binary_expr(BinaryOp::BitAnd, a, b),
            SSAOp::IntOr { a, b, .. } => self.binary_expr(BinaryOp::BitOr, a, b),
            SSAOp::IntXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::IntLeft { a, b, .. } => self.binary_expr(BinaryOp::Shl, a, b),
            SSAOp::IntRight { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Shr, a, b, Some(uint_type_from_size(dst.size)))
            }
            SSAOp::IntSRight { dst, a, b } => {
                self.typed_binary_expr(BinaryOp::Shr, a, b, Some(type_from_size(dst.size)))
            }
            SSAOp::IntLess { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Lt,
                a,
                b,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLess { a, b, .. } => {
                self.typed_binary_expr(BinaryOp::Lt, a, b, Some(type_from_size(a.size.max(b.size))))
            }
            SSAOp::IntLessEqual { a, b, .. } => self.typed_binary_expr(
                BinaryOp::Le,
                a,
                b,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLessEqual { a, b, .. } => {
                self.typed_binary_expr(BinaryOp::Le, a, b, Some(type_from_size(a.size.max(b.size))))
            }
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
            SSAOp::FloatAbs { src, .. } => {
                CExpr::call(CExpr::Var("fabs".to_string()), vec![self.get_expr(src)])
            }
            SSAOp::FloatSqrt { src, .. } => {
                CExpr::call(CExpr::Var("sqrt".to_string()), vec![self.get_expr(src)])
            }
            SSAOp::FloatCeil { src, .. } => {
                CExpr::call(CExpr::Var("ceil".to_string()), vec![self.get_expr(src)])
            }
            SSAOp::FloatFloor { src, .. } => {
                CExpr::call(CExpr::Var("floor".to_string()), vec![self.get_expr(src)])
            }
            SSAOp::FloatRound { src, .. } => {
                CExpr::call(CExpr::Var("round".to_string()), vec![self.get_expr(src)])
            }
            SSAOp::FloatNaN { src, .. } => {
                CExpr::call(CExpr::Var("isnan".to_string()), vec![self.get_expr(src)])
            }
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
            SSAOp::FloatFloat { dst, src } => {
                CExpr::cast(CType::Float(dst.size), self.get_expr(src))
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
    ) -> Option<CExpr> {
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
        let base_expr =
            self.normalize_pointer_base_expr(&self.expr_for_ssa_name(&base.display_name()), 0);
        let index_expr =
            self.normalize_index_expr(&self.expr_for_ssa_name(&index.display_name()), 0)?;
        self.build_subscript_expr(base_expr, index_expr, elem_ty, is_sub)
    }

    fn typed_deref_expr(&self, addr: &SSAVar, elem_size: u32) -> CExpr {
        let addr_expr = self.get_expr(addr);
        let addr_ty = self.type_oracle.map(|oracle| oracle.type_of(addr));
        let is_pointer_typed = if let (Some(oracle), Some(ty)) = (self.type_oracle, addr_ty) {
            oracle.is_pointer(ty) || oracle.is_array(ty)
        } else {
            false
        };

        let casted = if is_pointer_typed || self.looks_like_pointer_expr(&addr_expr) {
            addr_expr
        } else {
            let elem_ty = uint_type_from_size(elem_size);
            CExpr::cast(CType::ptr(elem_ty), addr_expr)
        };
        CExpr::Deref(Box::new(casted))
    }

    fn looks_like_pointer_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Cast { ty, .. } => matches!(ty, CType::Pointer(_)),
            CExpr::Deref(_)
            | CExpr::Subscript { .. }
            | CExpr::Member { .. }
            | CExpr::PtrMember { .. } => true,
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                lower.starts_with("arg")
                    || lower.contains("ptr")
                    || lower.contains("addr")
                    || self
                        .lookup_type_hint(name)
                        .map(|ty| matches!(ty, CType::Pointer(_) | CType::Struct(_)))
                        .unwrap_or(false)
            }
            CExpr::Paren(inner) => self.looks_like_pointer_expr(inner),
            _ => false,
        }
    }

    fn try_subscript_from_var(&self, addr: &SSAVar, elem_size: u32) -> Option<CExpr> {
        if let Some(expr) = self.definitions.get(&addr.display_name())
            && let Some(sub) = self.try_subscript_from_addr_expr(expr, elem_size)
        {
            return Some(sub);
        }
        if let Some(ptr) = self.ptr_arith.get(&addr.display_name()) {
            return self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub);
        }
        None
    }

    fn try_subscript_from_addr_expr(&self, expr: &CExpr, elem_size: u32) -> Option<CExpr> {
        let (base_expr, index_expr, _scale, is_sub) = self.extract_base_index_scale(expr)?;
        let elem_ty = uint_type_from_size(elem_size);
        let base_expr = self.normalize_pointer_base_expr(&base_expr, 0);
        let index_expr = self.normalize_index_expr(&index_expr, 0)?;
        self.build_subscript_expr(base_expr, index_expr, elem_ty, is_sub)
    }

    fn extract_base_index_scale(&self, expr: &CExpr) -> Option<(CExpr, CExpr, u32, bool)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => self.extract_base_index_from_add(left, right),
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => self
                .extract_base_index_from_add(left, right)
                .map(|(base, index, scale, is_sub)| (base, index, scale, !is_sub)),
            CExpr::Cast { expr: inner, .. } | CExpr::Paren(inner) => {
                self.extract_base_index_scale(inner)
            }
            CExpr::Var(name) => self
                .definitions
                .get(name)
                .and_then(|inner| self.extract_base_index_scale(inner)),
            _ => None,
        }
    }

    fn extract_base_index_from_add(
        &self,
        left: &CExpr,
        right: &CExpr,
    ) -> Option<(CExpr, CExpr, u32, bool)> {
        if let Some((index, scale)) = self.extract_mul_const(right, 0) {
            let elem_size = self.scale_to_elem_size(scale)?;
            return Some((left.clone(), index, elem_size, scale < 0));
        }
        if let Some((index, scale)) = self.extract_mul_const(left, 0) {
            let elem_size = self.scale_to_elem_size(scale)?;
            return Some((right.clone(), index, elem_size, scale < 0));
        }
        None
    }

    fn scale_to_elem_size(&self, scale: i64) -> Option<u32> {
        let abs = scale.checked_abs()? as u64;
        if abs == 0 {
            return None;
        }
        u32::try_from(abs).ok()
    }

    fn extract_mul_const(&self, expr: &CExpr, depth: u32) -> Option<(CExpr, i64)> {
        if depth > 8 {
            return None;
        }

        match expr {
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } => {
                if let Some(scale) = self.literal_to_i64(right) {
                    let index = left.as_ref().clone();
                    if self.is_semantic_index_expr(&index) {
                        return Some((index, scale));
                    }
                    return None;
                }
                if let Some(scale) = self.literal_to_i64(left) {
                    let index = right.as_ref().clone();
                    if self.is_semantic_index_expr(&index) {
                        return Some((index, scale));
                    }
                    return None;
                }
                None
            }
            CExpr::Binary {
                op: BinaryOp::Shl,
                left,
                right,
            } => {
                let shift = self.literal_to_i64(right)?;
                if !(0..=62).contains(&shift) {
                    return None;
                }
                let scale = 1_i64.checked_shl(shift as u32)?;
                self.extract_mul_const(left, depth + 1)
                    .and_then(|(inner, inner_scale)| {
                        inner_scale
                            .checked_mul(scale)
                            .map(|combined| (inner, combined))
                    })
                    .or_else(|| {
                        let index = left.as_ref().clone();
                        self.is_semantic_index_expr(&index)
                            .then_some((index, scale))
                    })
            }
            CExpr::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                left,
                right,
            } => {
                let (left_expr, left_scale) = self.extract_mul_const(left, depth + 1)?;
                let (right_expr, right_scale) = self.extract_mul_const(right, depth + 1)?;
                let left_norm = self.normalize_index_expr(&left_expr, 0)?;
                let right_norm = self.normalize_index_expr(&right_expr, 0)?;
                if left_norm != right_norm {
                    return None;
                }
                let combined = match expr {
                    CExpr::Binary {
                        op: BinaryOp::Add, ..
                    } => left_scale.checked_add(right_scale)?,
                    CExpr::Binary {
                        op: BinaryOp::Sub, ..
                    } => left_scale.checked_sub(right_scale)?,
                    _ => unreachable!(),
                };
                (combined != 0).then_some((left_norm, combined))
            }
            CExpr::Unary {
                op: UnaryOp::Neg,
                operand,
            } => self
                .extract_mul_const(operand, depth + 1)
                .map(|(expr, scale)| (expr, -scale))
                .or_else(|| Some((operand.as_ref().clone(), -1))),
            CExpr::Cast { expr: inner, .. } | CExpr::Paren(inner) => {
                self.extract_mul_const(inner, depth + 1)
            }
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                let semantic_visible_name = !lower.starts_with("tmp:")
                    && !lower.starts_with("const:")
                    && !lower.starts_with("ram:")
                    && !lower.starts_with("local_")
                    && !lower.starts_with('t')
                    && !lower.starts_with('v');
                if semantic_visible_name
                    && !self.is_non_index_pointer_expr(expr)
                    && self.is_semantic_index_expr(expr)
                {
                    return Some((expr.clone(), 1));
                }
                if let Some(inner) = self.definitions.get(name) {
                    self.extract_mul_const(inner, depth + 1)
                } else if !self.is_non_index_pointer_expr(expr) && self.is_semantic_index_expr(expr)
                {
                    Some((expr.clone(), 1))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn literal_to_i64(&self, expr: &CExpr) -> Option<i64> {
        match expr {
            CExpr::IntLit(v) => Some(*v),
            CExpr::UIntLit(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    fn is_semantic_index_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => self
                .definitions
                .get(name)
                .map(|inner| self.is_semantic_index_expr(inner))
                .unwrap_or_else(|| {
                    let lower = name.to_ascii_lowercase();
                    let stack_placeholder =
                        lower == "stack" || lower == "saved_fp" || lower.starts_with("stack_");
                    !name.starts_with("const:")
                        && !name.starts_with("ram:")
                        && (!stack_placeholder
                            && (!self.stack_slots.contains_key(name)
                                || lower.starts_with("local_")
                                || lower.starts_with("arg")))
                }),
            CExpr::Unary { operand, .. } => self.is_semantic_index_expr(operand),
            CExpr::Binary { left, right, .. } => {
                self.is_semantic_index_expr(left) || self.is_semantic_index_expr(right)
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.is_semantic_index_expr(inner)
            }
            _ => false,
        }
    }

    fn build_subscript_expr(
        &self,
        base_expr: CExpr,
        index_expr: CExpr,
        elem_ty: CType,
        is_sub: bool,
    ) -> Option<CExpr> {
        if !self.looks_like_pointer_expr(&base_expr)
            || self.is_non_index_pointer_expr(&index_expr)
            || !self.is_semantic_index_expr(&index_expr)
            || base_expr == index_expr
        {
            return None;
        }

        let base_cast = CExpr::cast(CType::ptr(elem_ty), base_expr);
        let index_final = if is_sub {
            CExpr::unary(UnaryOp::Neg, index_expr)
        } else {
            index_expr
        };

        Some(CExpr::Subscript {
            base: Box::new(base_cast),
            index: Box::new(index_final),
        })
    }

    fn normalize_pointer_base_expr(&self, expr: &CExpr, depth: u32) -> CExpr {
        if depth > 4 {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => self
                .definitions
                .get(name)
                .map(|inner| self.normalize_pointer_base_expr(inner, depth + 1))
                .filter(|inner| self.looks_like_pointer_expr(inner))
                .unwrap_or_else(|| expr.clone()),
            CExpr::Paren(inner) => {
                CExpr::Paren(Box::new(self.normalize_pointer_base_expr(inner, depth + 1)))
            }
            CExpr::Cast { ty, expr: inner } => CExpr::Cast {
                ty: ty.clone(),
                expr: Box::new(self.normalize_pointer_base_expr(inner, depth + 1)),
            },
            _ => expr.clone(),
        }
    }

    fn normalize_index_expr(&self, expr: &CExpr, depth: u32) -> Option<CExpr> {
        if depth > 4 {
            return self.is_semantic_index_expr(expr).then_some(expr.clone());
        }

        match expr {
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                let semantic_visible_name = !lower.starts_with("tmp:")
                    && !lower.starts_with("const:")
                    && !lower.starts_with("ram:")
                    && !lower.starts_with("local_")
                    && !lower.starts_with('t')
                    && !lower.starts_with('v');
                if semantic_visible_name
                    && !self.is_non_index_pointer_expr(expr)
                    && self.is_semantic_index_expr(expr)
                {
                    return Some(expr.clone());
                }
                if let Some(inner) = self.definitions.get(name)
                    && let Some(normalized) = self.normalize_index_expr(inner, depth + 1)
                    && !self.is_non_index_pointer_expr(&normalized)
                {
                    return Some(normalized);
                }
                if self.definitions.contains_key(name) {
                    return None;
                }
                if self.is_non_index_pointer_expr(expr) {
                    None
                } else {
                    self.is_semantic_index_expr(expr).then_some(expr.clone())
                }
            }
            CExpr::Paren(inner) => self
                .normalize_index_expr(inner, depth + 1)
                .map(|normalized| CExpr::Paren(Box::new(normalized))),
            CExpr::Cast { ty, expr: inner } => self
                .normalize_index_expr(inner, depth + 1)
                .map(|normalized| CExpr::cast(ty.clone(), normalized)),
            CExpr::Unary { op, operand } => self
                .normalize_index_expr(operand, depth + 1)
                .map(|normalized| CExpr::unary(*op, normalized)),
            _ => self.is_semantic_index_expr(expr).then_some(expr.clone()),
        }
    }

    fn is_non_index_pointer_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Cast { ty, .. } => matches!(ty, CType::Pointer(_)),
            CExpr::Deref(_) | CExpr::Subscript { .. } | CExpr::PtrMember { .. } => true,
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                lower.contains("ptr")
                    || lower.contains("addr")
                    || self.stack_slots.contains_key(name)
                    || self
                        .lookup_type_hint(name)
                        .map(|ty| matches!(ty, CType::Pointer(_) | CType::Struct(_)))
                        .unwrap_or(false)
            }
            CExpr::Paren(inner) => self.is_non_index_pointer_expr(inner),
            CExpr::Unary { operand, .. } => self.is_non_index_pointer_expr(operand),
            _ => false,
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

    #[allow(clippy::too_many_arguments)]
    fn make_ctx<'a>(
        definitions: &'a HashMap<String, CExpr>,
        use_counts: &'a HashMap<String, usize>,
        condition_vars: &'a HashSet<String>,
        pinned: &'a HashSet<String>,
        var_aliases: &'a HashMap<String, String>,
        ptr_arith: &'a HashMap<String, PtrArith>,
        stack_slots: &'a HashMap<String, StackSlotProvenance>,
        forwarded_values: &'a HashMap<String, ValueProvenance>,
        function_names: &'a HashMap<u64, String>,
        strings: &'a HashMap<u64, String>,
        symbols: &'a HashMap<u64, String>,
    ) -> LowerCtx<'a> {
        let type_hints = Box::leak(Box::new(HashMap::new()));
        LowerCtx {
            definitions,
            use_counts,
            condition_vars,
            pinned,
            var_aliases,
            type_hints,
            ptr_arith,
            stack_slots,
            forwarded_values,
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
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
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
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
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
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
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

    #[test]
    fn load_generic_deref_casts_non_pointer_like_address() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5001", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:5000", 1, 8),
        });
        let CExpr::Deref(inner) = expr else {
            panic!("expected dereference expression");
        };
        assert!(
            matches!(
                inner.as_ref(),
                CExpr::Cast {
                    ty: CType::Pointer(_),
                    ..
                }
            ),
            "generic lower path should cast non-pointer-like address expressions"
        );
    }

    #[test]
    fn load_generic_deref_avoids_cast_for_pointer_like_address() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5101", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("arg1", 0, 8),
        });
        let CExpr::Deref(inner) = expr else {
            panic!("expected dereference expression");
        };
        assert!(
            !matches!(
                inner.as_ref(),
                CExpr::Cast {
                    ty: CType::Pointer(_),
                    ..
                }
            ),
            "pointer-like address expressions should not be re-cast"
        );
    }

    #[test]
    fn load_preserves_negative_index_subscript_shape() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let definitions = HashMap::from([(
            "tmp:addr_1".to_string(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::binary(
                    BinaryOp::Mul,
                    CExpr::Cast {
                        ty: CType::Int(64),
                        expr: Box::new(CExpr::unary(UnaryOp::Neg, CExpr::Var("arg2".to_string()))),
                    },
                    CExpr::IntLit(4),
                ),
            ),
        )]);
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5002", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:addr", 1, 8),
        });

        let CExpr::Subscript { base, index } = expr else {
            panic!("expected subscript expression");
        };
        assert!(matches!(base.as_ref(), CExpr::Cast { .. }));
        assert!(
            matches!(
                index.as_ref(),
                CExpr::Cast { expr, .. }
                    if matches!(expr.as_ref(), CExpr::Unary { op: UnaryOp::Neg, .. })
            ),
            "negative index shape should survive lowering"
        );
    }

    #[test]
    fn load_does_not_fabricate_stack_slot_aliases() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let definitions = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::from([(
            "tmp:stackaddr_1".to_string(),
            StackSlotProvenance { offset: -0x18 },
        )]);
        let forwarded_values = HashMap::new();
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5003", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:stackaddr", 1, 8),
        });

        let CExpr::Deref(inner) = expr else {
            panic!("expected conservative dereference expression");
        };
        assert!(
            !matches!(inner.as_ref(), CExpr::Var(name) if name.starts_with("local_") || name == "stack"),
            "analysis lowering should not fabricate visible stack aliases"
        );
    }

    #[test]
    fn load_base_plus_const_does_not_become_fake_subscript() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let definitions = HashMap::from([(
            "tmp:addr_1".to_string(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::IntLit(8),
            ),
        )]);
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5004", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:addr", 1, 8),
        });

        assert!(
            !matches!(expr, CExpr::Subscript { .. }),
            "base + const should stay as pointer arithmetic/deref, not fake subscript"
        );
    }

    #[test]
    fn load_alias_expanded_const_index_does_not_become_fake_subscript() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let definitions = HashMap::from([
            ("tmp:index_1".to_string(), CExpr::IntLit(0)),
            (
                "tmp:addr_1".to_string(),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("arg1".to_string()),
                    CExpr::binary(
                        BinaryOp::Mul,
                        CExpr::Var("tmp:index_1".to_string()),
                        CExpr::IntLit(4),
                    ),
                ),
            ),
        ]);
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5005", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:addr", 1, 8),
        });

        assert!(
            !matches!(expr, CExpr::Subscript { .. }),
            "constant-resolved index carriers must not become fake array subscripts"
        );
    }

    #[test]
    fn load_unstable_alias_expanded_base_does_not_become_member_access() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let ptr_arith = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let definitions = HashMap::from([
            ("tmp:base_1".to_string(), CExpr::Var("rdx_1".to_string())),
            (
                "tmp:addr_1".to_string(),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("tmp:base_1".to_string()),
                    CExpr::IntLit(8),
                ),
            ),
        ]);
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5006", 1, 4),
            space: "ram".to_string(),
            addr: SSAVar::new("tmp:addr", 1, 8),
        });

        assert!(
            !matches!(expr, CExpr::PtrMember { .. }),
            "unstable alias-expanded bases must not become pointer member syntax"
        );
    }

    #[test]
    fn ptr_arith_prefers_expression_recovered_real_index_over_pointer_local() {
        let fn_map = HashMap::new();
        let str_map = HashMap::new();
        let sym_map = HashMap::new();
        let use_counts = HashMap::new();
        let condition_vars = HashSet::new();
        let pinned = HashSet::new();
        let var_aliases = HashMap::new();
        let stack_slots = HashMap::new();
        let forwarded_values = HashMap::new();
        let addr = SSAVar::new("tmp:addr", 1, 8);
        let arr = SSAVar::new("arg1", 0, 8);
        let ptr_local = SSAVar::new("tmp:arr_local", 1, 8);
        let ptr_arith = HashMap::from([(
            addr.display_name(),
            PtrArith {
                base: arr.clone(),
                index: ptr_local,
                element_size: 4,
                is_sub: false,
            },
        )]);
        let definitions = HashMap::from([
            (
                "tmp:arr_local_1".to_string(),
                CExpr::Var("local_8".to_string()),
            ),
            ("local_8".to_string(), CExpr::Var("arg1".to_string())),
            ("local_c".to_string(), CExpr::Var("arg2".to_string())),
            (
                addr.display_name(),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("local_8".to_string()),
                    CExpr::binary(
                        BinaryOp::Mul,
                        CExpr::Var("local_c".to_string()),
                        CExpr::IntLit(4),
                    ),
                ),
            ),
        ]);
        let ctx = make_ctx(
            &definitions,
            &use_counts,
            &condition_vars,
            &pinned,
            &var_aliases,
            &ptr_arith,
            &stack_slots,
            &forwarded_values,
            &fn_map,
            &str_map,
            &sym_map,
        );

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst: SSAVar::new("tmp:5007", 1, 4),
            space: "ram".to_string(),
            addr,
        });

        let CExpr::Subscript { base, index } = expr else {
            panic!("expected subscript expression");
        };
        assert!(
            matches!(base.as_ref(), CExpr::Cast { expr, .. } if matches!(expr.as_ref(), CExpr::Var(name) if name == "arg1")),
            "subscript base should normalize back to the semantic pointer source"
        );
        assert!(
            matches!(index.as_ref(), CExpr::Var(name) if name == "arg2"),
            "subscript index should use the semantic index source, not the pointer local alias: {index:?}"
        );
    }
}
