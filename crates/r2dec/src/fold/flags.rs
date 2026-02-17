use std::collections::HashSet;

use r2ssa::{SSAOp, SSAVar};

use crate::analysis;
use crate::ast::{BinaryOp, CExpr, UnaryOp};

use super::context::FoldingContext;
use super::op_lower::parse_const_value;
use super::{
    MAX_COND_STACK_ALIAS_DEPTH, MAX_PREDICATE_OPERAND_DEPTH, MAX_PREDICATE_SIMPLIFY_DEPTH,
    MAX_SF_SURROGATE_DEPTH, MAX_SUB_LIKE_DEPTH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompareContext {
    Eq,
    Ne,
    SignedNegative,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct CompareTuple {
    lhs: CExpr,
    rhs: CExpr,
    context: CompareContext,
}

impl<'a> FoldingContext<'a> {
    pub(super) fn normalize_assignment_predicate_rhs(&self, rhs: CExpr) -> CExpr {
        if self.is_assignment_predicate_expr(&rhs) {
            self.simplify_condition_expr(rhs)
        } else {
            rhs
        }
    }

    pub(super) fn predicate_candidate_for_var(&self, var: &SSAVar) -> Option<CExpr> {
        let key = var.display_name();
        self.lookup_definition(&key)
            .or_else(|| self.formatted_defs_map().get(&key).cloned())
            .or_else(|| {
                let rendered = self.var_name(var);
                self.formatted_defs_map().get(&rendered).cloned()
            })
    }

    pub(super) fn resolve_predicate_rhs_for_var(&self, src: &SSAVar, fallback: CExpr) -> CExpr {
        let fallback_simplified = self.normalize_assignment_predicate_rhs(fallback);
        if self.is_assignment_predicate_expr(&fallback_simplified) {
            return fallback_simplified;
        }

        if let Some(candidate) = self.predicate_candidate_for_var(src)
            && self.is_assignment_predicate_expr(&candidate)
        {
            return self.simplify_condition_expr(candidate);
        }

        fallback_simplified
    }

    pub(super) fn is_assignment_predicate_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                is_cpu_flag(&name.to_lowercase())
                    || self.flag_only_values_set().contains(name)
                    || self.condition_vars_set().contains(name)
            }
            CExpr::Unary {
                op: UnaryOp::Not, ..
            } => true,
            CExpr::Binary { op, .. } => matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::BitAnd
                    | BinaryOp::BitXor
            ),
            CExpr::Paren(inner) => self.is_assignment_predicate_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.is_assignment_predicate_expr(inner),
            _ => false,
        }
    }

    /// Extract a condition expression from a branch operation.
    pub fn extract_condition(&self, op: &SSAOp) -> Option<CExpr> {
        match op {
            SSAOp::CBranch { cond, .. } => {
                let expr = self.get_condition_expr(cond);
                Some(self.rewrite_stack_expr(expr))
            }
            _ => None,
        }
    }

    /// Get the expression for a condition variable, always inlining its definition.
    /// Unlike get_expr(), this bypasses the should_inline() check because we always
    /// want to see the actual condition expression, not a temp variable name.
    pub(super) fn get_condition_expr(&self, var: &SSAVar) -> CExpr {
        // Always inline constants
        if var.is_const() {
            return self.const_to_expr(var);
        }

        let key = var.display_name();
        let expr = self
            .definitions_map()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| CExpr::Var(self.var_name(var)));
        let expr = self.rewrite_stack_expr(expr);
        let expr = self.rewrite_condition_stack_aliases(expr);
        self.simplify_condition_expr(expr)
    }

    pub(super) fn rewrite_condition_stack_aliases(&self, expr: CExpr) -> CExpr {
        let mut visited = HashSet::new();
        self.rewrite_condition_stack_aliases_inner(expr, 0, &mut visited)
    }

    pub(super) fn rewrite_condition_stack_aliases_inner(
        &self,
        expr: CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > MAX_COND_STACK_ALIAS_DEPTH {
            return expr;
        }

        match expr {
            CExpr::Var(name) => self.rewrite_condition_stack_var(name, depth, visited),
            other => other.map_children(&mut |child| {
                self.rewrite_condition_stack_aliases_inner(child, depth + 1, visited)
            }),
        }
    }

    pub(super) fn rewrite_condition_stack_var(
        &self,
        name: String,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > MAX_COND_STACK_ALIAS_DEPTH {
            return CExpr::Var(name);
        }

        if self
            .stack_vars_map()
            .values()
            .any(|candidate| candidate.eq_ignore_ascii_case(&name))
        {
            return CExpr::Var(name);
        }

        if let Some(alias) = self.resolve_stack_alias_from_addr_expr(&CExpr::Var(name.clone()), 0)
            && !alias.eq_ignore_ascii_case(&name)
        {
            return CExpr::Var(alias);
        }

        if !visited.insert(name.clone()) {
            return CExpr::Var(name);
        }

        let resolved = self
            .lookup_definition(&name)
            .or_else(|| self.formatted_defs_map().get(&name).cloned());

        let rewritten = if let Some(expr) = resolved {
            let expr = self.rewrite_condition_stack_aliases_inner(expr, depth + 1, visited);
            if let Some(alias) = self.resolve_stack_alias_from_addr_expr(&expr, 0) {
                CExpr::Var(alias)
            } else {
                CExpr::Var(name.clone())
            }
        } else {
            CExpr::Var(name.clone())
        };

        visited.remove(&name);
        rewritten
    }

    pub(super) fn simplify_condition_expr(&self, expr: CExpr) -> CExpr {
        analysis::PredicateSimplifier::new(self).simplify_condition_expr(expr)
    }

    pub(crate) fn simplify_predicate_expr(&self, expr: CExpr) -> CExpr {
        self.simplify_predicate_expr_inner(expr, 0)
    }

    pub(super) fn simplify_predicate_expr_inner(&self, expr: CExpr, depth: u32) -> CExpr {
        if depth > MAX_PREDICATE_SIMPLIFY_DEPTH {
            return expr;
        }

        let normalized = match expr {
            CExpr::Unary { op, operand } => CExpr::Unary {
                op,
                operand: Box::new(self.simplify_predicate_expr_inner(*operand, depth + 1)),
            },
            CExpr::Binary { op, left, right } => CExpr::Binary {
                op,
                left: Box::new(self.simplify_predicate_expr_inner(*left, depth + 1)),
                right: Box::new(self.simplify_predicate_expr_inner(*right, depth + 1)),
            },
            CExpr::Paren(inner) => CExpr::Paren(Box::new(
                self.simplify_predicate_expr_inner(*inner, depth + 1),
            )),
            CExpr::Cast { ty, expr } => CExpr::Cast {
                ty,
                expr: Box::new(self.simplify_predicate_expr_inner(*expr, depth + 1)),
            },
            other => other,
        };

        let rewritten = self.rewrite_predicate_once(normalized.clone());
        if rewritten != normalized {
            return self.simplify_predicate_expr_inner(rewritten, depth + 1);
        }
        rewritten
    }

    pub(super) fn rewrite_predicate_once(&self, expr: CExpr) -> CExpr {
        match expr {
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                if let Some(gt) = self.rewrite_signed_positive_and(left.as_ref(), right.as_ref()) {
                    gt
                } else {
                    CExpr::binary(BinaryOp::And, *left, *right)
                }
            }
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => match *operand {
                CExpr::Binary {
                    op: BinaryOp::Eq,
                    left,
                    right,
                } => CExpr::binary(BinaryOp::Ne, *left, *right),
                CExpr::Binary {
                    op: BinaryOp::Ne,
                    left,
                    right,
                } => CExpr::binary(BinaryOp::Eq, *left, *right),
                other => CExpr::unary(UnaryOp::Not, other),
            },
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if self.is_zero_expr(right.as_ref()) => *left,
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => self.rewrite_zero_comparison(BinaryOp::Eq, *left, *right),
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => self.rewrite_zero_comparison(BinaryOp::Ne, *left, *right),
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } => {
                if self.is_zero_expr(right.as_ref())
                    && let Some(base) = self.strip_sub_zero(left.as_ref())
                {
                    return CExpr::binary(BinaryOp::Lt, base, CExpr::IntLit(0));
                }
                CExpr::binary(BinaryOp::Lt, *left, *right)
            }
            CExpr::Var(name) => {
                if let Some(val) = parse_const_value(&name) {
                    if val > 0x7fffffff {
                        CExpr::UIntLit(val)
                    } else {
                        CExpr::IntLit(val as i64)
                    }
                } else {
                    CExpr::Var(name)
                }
            }
            other => other,
        }
    }

    pub(super) fn rewrite_signed_positive_and(&self, left: &CExpr, right: &CExpr) -> Option<CExpr> {
        let left_ne = self.extract_cmp_zero_operand(left, BinaryOp::Ne);
        let right_ge = self.extract_cmp_zero_operand(right, BinaryOp::Ge);
        if let (Some(a), Some(b)) = (left_ne.clone(), right_ge.clone())
            && a == b
        {
            return Some(CExpr::binary(BinaryOp::Gt, a, CExpr::IntLit(0)));
        }

        let left_ge = self.extract_cmp_zero_operand(left, BinaryOp::Ge);
        let right_ne = self.extract_cmp_zero_operand(right, BinaryOp::Ne);
        if let (Some(a), Some(b)) = (left_ge, right_ne)
            && a == b
        {
            return Some(CExpr::binary(BinaryOp::Gt, a, CExpr::IntLit(0)));
        }

        None
    }

    pub(super) fn extract_cmp_zero_operand(&self, expr: &CExpr, op: BinaryOp) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: expr_op,
                left,
                right,
            } if *expr_op == op => {
                if self.is_zero_expr(right.as_ref()) {
                    return Some(left.as_ref().clone());
                }
                if self.is_zero_expr(left.as_ref()) {
                    return Some(right.as_ref().clone());
                }
                None
            }
            CExpr::Paren(inner) => self.extract_cmp_zero_operand(inner, op),
            CExpr::Cast { expr: inner, .. } => self.extract_cmp_zero_operand(inner, op),
            _ => None,
        }
    }

    pub(super) fn rewrite_zero_comparison(
        &self,
        cmp_op: BinaryOp,
        left: CExpr,
        right: CExpr,
    ) -> CExpr {
        if self.is_zero_expr(&right) {
            if let Some(base) = self.strip_test_self(&left) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
            if let Some((base, value)) = self.strip_sub_const(&left) {
                return CExpr::binary(cmp_op, base, self.normalize_sub_cmp_constant(value));
            }
            if let Some(base) = self.strip_sub_zero(&left) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
        }

        if self.is_zero_expr(&left) {
            if let Some(base) = self.strip_test_self(&right) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
            if let Some((base, value)) = self.strip_sub_const(&right) {
                return CExpr::binary(cmp_op, base, self.normalize_sub_cmp_constant(value));
            }
            if let Some(base) = self.strip_sub_zero(&right) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
        }

        CExpr::binary(cmp_op, left, right)
    }

    pub(super) fn normalize_sub_cmp_constant(&self, value: CExpr) -> CExpr {
        match value {
            CExpr::IntLit(v) if v >= 0x100 => CExpr::Var(format!("0x{:x}", v as u64)),
            CExpr::UIntLit(v) if v >= 0x100 => CExpr::Var(format!("0x{:x}", v)),
            other => other,
        }
    }

    pub(super) fn const_expr_for_comparison(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            CExpr::IntLit(_) | CExpr::UIntLit(_) => Some(expr.clone()),
            CExpr::Paren(inner) => self.const_expr_for_comparison(inner),
            CExpr::Cast { expr: inner, .. } => self.const_expr_for_comparison(inner),
            CExpr::Var(name) => {
                if let Some(val) = parse_const_value(name) {
                    if val > 0x7fffffff {
                        Some(CExpr::UIntLit(val))
                    } else {
                        Some(CExpr::IntLit(val as i64))
                    }
                } else if let Some(hex) =
                    name.strip_prefix("0x").or_else(|| name.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).ok().map(|val| {
                        if val > 0x7fffffff {
                            CExpr::UIntLit(val)
                        } else {
                            CExpr::IntLit(val as i64)
                        }
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(super) fn strip_sub_const(&self, expr: &CExpr) -> Option<(CExpr, CExpr)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => self
                .const_expr_for_comparison(right)
                .map(|value| (left.as_ref().clone(), value)),
            CExpr::Paren(inner) => self.strip_sub_const(inner),
            CExpr::Cast { expr: inner, .. } => self.strip_sub_const(inner),
            CExpr::Var(name) => self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                .and_then(|inner| self.strip_sub_const(&inner)),
            _ => None,
        }
    }

    pub(super) fn strip_sub_zero(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if self.is_zero_expr(right.as_ref()) => Some(left.as_ref().clone()),
            CExpr::Paren(inner) => self.strip_sub_zero(inner),
            CExpr::Cast { expr: inner, .. } => self.strip_sub_zero(inner),
            CExpr::Var(name) => self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                .and_then(|inner| self.strip_sub_zero(&inner)),
            _ => None,
        }
    }

    pub(super) fn strip_test_self(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                left,
                right,
            } if left == right => Some(left.as_ref().clone()),
            CExpr::Paren(inner) => self.strip_test_self(inner),
            CExpr::Cast { expr: inner, .. } => self.strip_test_self(inner),
            CExpr::Var(name) => self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                .and_then(|inner| self.strip_test_self(&inner)),
            _ => None,
        }
    }

    pub(super) fn is_zero_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Paren(inner) => self.is_zero_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.is_zero_expr(inner),
            CExpr::IntLit(0) | CExpr::UIntLit(0) => true,
            CExpr::Var(name) => name == "0" || name == "elf_header",
            _ => false,
        }
    }

    pub(super) fn is_predicate_like_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                is_cpu_flag(&name.to_lowercase())
                    || self.flag_only_values_set().contains(name)
                    || self.condition_vars_set().contains(name)
            }
            CExpr::Unary {
                op: UnaryOp::Not, ..
            } => true,
            CExpr::Binary { op, .. } => matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::BitAnd
                    | BinaryOp::BitXor
                    | BinaryOp::Sub
            ),
            CExpr::Paren(inner) => self.is_predicate_like_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.is_predicate_like_expr(inner),
            CExpr::IntLit(_) | CExpr::UIntLit(_) => true,
            _ => false,
        }
    }

    pub(super) fn should_expand_predicate_var(&self, name: &str) -> bool {
        if is_cpu_flag(&name.to_lowercase())
            || self.condition_vars_set().contains(name)
            || self.flag_only_values_set().contains(name)
        {
            return true;
        }

        self.lookup_definition(name)
            .or_else(|| self.formatted_defs_map().get(name).cloned())
            .map(|expr| self.is_predicate_like_expr(&expr))
            .unwrap_or(false)
    }

    pub(crate) fn expand_predicate_vars(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > MAX_PREDICATE_OPERAND_DEPTH {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if let Some(inner) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    && let CExpr::Var(inner_name) = inner
                {
                    if inner_name.starts_with("arg") {
                        return CExpr::Var(inner_name);
                    }
                    if let Some(alias) = self.arg_alias_for_rendered_name(&inner_name) {
                        return CExpr::Var(alias);
                    }
                }
                if !self.should_expand_predicate_var(name) || !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let expanded = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .filter(|inner| self.is_predicate_like_expr(inner))
                    .map(|inner| self.expand_predicate_vars(&inner, depth + 1, visited))
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                expanded
            }
            CExpr::Unary { op, operand } => {
                CExpr::unary(*op, self.expand_predicate_vars(operand, depth + 1, visited))
            }
            CExpr::Binary { op, left, right } => CExpr::binary(
                *op,
                self.expand_predicate_vars(left, depth + 1, visited),
                self.expand_predicate_vars(right, depth + 1, visited),
            ),
            CExpr::Paren(inner) => CExpr::Paren(Box::new(self.expand_predicate_vars(
                inner,
                depth + 1,
                visited,
            ))),
            CExpr::Cast { ty, expr: inner } => CExpr::Cast {
                ty: ty.clone(),
                expr: Box::new(self.expand_predicate_vars(inner, depth + 1, visited)),
            },
            _ => expr.clone(),
        }
    }

    /// Try to reconstruct a high-level comparison from x86 flag patterns.
    /// Handles patterns like:
    /// - BoolNot(ZF) -> a != b
    /// - ZF -> a == b  
    /// - !ZF && (OF == SF) -> a > b (signed, JG)
    /// - OF == SF -> a >= b (signed, JGE)
    /// - OF != SF -> a < b (signed, JL)
    /// - ZF || (OF != SF) -> a <= b (signed, JLE)
    /// - !CF && !ZF -> a > b (unsigned, JA)
    /// - !CF -> a >= b (unsigned, JAE)
    /// - CF -> a < b (unsigned, JB)
    /// - CF || ZF -> a <= b (unsigned, JBE)
    pub(crate) fn try_reconstruct_condition(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            // Pattern: Binary AND - check for signed greater than: !ZF && (OF == SF)
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_gt_from_and(left, right) {
                    return Some(rel);
                }
                if let Some(rel) = self.reconstruct_signed_gt_from_and(right, left) {
                    return Some(rel);
                }

                // Try !ZF && (OF == SF) -> a > b (signed)
                if let (Some(zf_name), true) = (self.extract_not_zf(left), self.is_of_eq_sf(right))
                    && let Some((a, b)) = self.lookup_flag_origin(&zf_name)
                {
                    return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                }
                // Try reversed: (OF == SF) && !ZF
                if let (Some(zf_name), true) = (self.extract_not_zf(right), self.is_of_eq_sf(left))
                    && let Some((a, b)) = self.lookup_flag_origin(&zf_name)
                {
                    return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                }

                // Try !CF && !ZF -> a > b (unsigned, JA)
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_not_cf(left), self.extract_not_zf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_not_cf(right), self.extract_not_zf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                None
            }

            // Pattern: Binary OR - check for unsigned less-equal: CF || ZF
            CExpr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_le_from_or(left, right) {
                    return Some(rel);
                }
                if let Some(rel) = self.reconstruct_signed_le_from_or(right, left) {
                    return Some(rel);
                }

                // Try CF || ZF -> a <= b (unsigned, JBE)
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_cf(left), self.extract_zf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_cf(right), self.extract_zf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                // Try ZF || (OF != SF) -> a <= b (signed, JLE)
                if let (Some(zf_name), true) = (self.extract_zf(left), self.is_of_ne_sf(right))
                    && let Some((a, b)) = self.lookup_flag_origin(&zf_name)
                {
                    return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                }
                // Try reversed
                if let (Some(zf_name), true) = (self.extract_zf(right), self.is_of_ne_sf(left))
                    && let Some((a, b)) = self.lookup_flag_origin(&zf_name)
                {
                    return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                }

                None
            }

            // Pattern: Binary Eq - check for OF == SF (signed >=)
            // AND temp == 0 patterns (TEST/CMP reconstruction)
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_ge_from_eq(expr) {
                    return Some(rel);
                }

                // OF == SF -> a >= b (signed, JGE)
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(left), self.extract_sf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(right), self.extract_sf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Fallback: temp == 0 where temp is from TEST/CMP
                if let Some(result) = self.try_reconstruct_cmp_zero(left, right, BinaryOp::Eq) {
                    return Some(result);
                }
                // Also try reversed (0 == temp)
                if let Some(result) = self.try_reconstruct_cmp_zero(right, left, BinaryOp::Eq) {
                    return Some(result);
                }
                None
            }

            // Pattern: Binary Ne - check for OF != SF (signed <)
            // AND temp != 0 patterns (TEST/CMP reconstruction)
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_lt_from_ne(expr) {
                    return Some(rel);
                }

                // OF != SF -> a < b (signed, JL)
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(left), self.extract_sf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(right), self.extract_sf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Fallback: temp != 0 where temp is from TEST/CMP
                if let Some(result) = self.try_reconstruct_cmp_zero(left, right, BinaryOp::Ne) {
                    return Some(result);
                }
                if let Some(result) = self.try_reconstruct_cmp_zero(right, left, BinaryOp::Ne) {
                    return Some(result);
                }
                None
            }

            CExpr::Paren(inner) => self.try_reconstruct_condition(inner),

            CExpr::Cast { ty, expr: inner } => {
                self.try_reconstruct_condition(inner)
                    .map(|reconstructed| CExpr::Cast {
                        ty: ty.clone(),
                        expr: Box::new(reconstructed),
                    })
            }

            // Pattern: !ZF (BoolNot of ZF) means "not equal"
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => {
                if let CExpr::Var(flag_name) = operand.as_ref() {
                    let flag_lower = flag_name.to_lowercase();
                    if flag_lower.contains("zf") {
                        // !ZF means a != b
                        if let Some((left, right)) = self.lookup_flag_origin(flag_name) {
                            return Some(CExpr::binary(
                                BinaryOp::Ne,
                                CExpr::Var(left),
                                CExpr::Var(right),
                            ));
                        }
                    }
                    // !CF means a >= b (unsigned, JAE)
                    if flag_lower.contains("cf")
                        && let Some((left, right)) = self.lookup_flag_origin(flag_name)
                    {
                        return Some(CExpr::binary(
                            BinaryOp::Ge,
                            CExpr::Var(left),
                            CExpr::Var(right),
                        ));
                    }
                }

                // Try !(CF || ZF) -> a > b (unsigned, JA) - negation of JBE
                if let CExpr::Binary {
                    op: BinaryOp::Or,
                    left: or_left,
                    right: or_right,
                } = operand.as_ref()
                {
                    if let (Some(cf_name), Some(_zf_name)) =
                        (self.extract_cf(or_left), self.extract_zf(or_right))
                        && let Some((a, b)) = self.lookup_flag_origin(&cf_name)
                    {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    // Try reversed
                    if let (Some(cf_name), Some(_zf_name)) =
                        (self.extract_cf(or_right), self.extract_zf(or_left))
                        && let Some((a, b)) = self.lookup_flag_origin(&cf_name)
                    {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                // Try to recurse into the operand and negate the result
                if let Some(inner) = self.try_reconstruct_condition(operand) {
                    // Negate comparison operators directly instead of wrapping in !()
                    return Some(match inner {
                        CExpr::Binary {
                            op: BinaryOp::Eq,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Ne,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Ne,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Eq,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Lt,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Ge,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Ge,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Lt,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Gt,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Le,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Le,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Gt,
                            left,
                            right,
                        },
                        other => CExpr::unary(UnaryOp::Not, other),
                    });
                }
                None
            }

            // Pattern: ZF directly means "equal"
            CExpr::Var(flag_name) => {
                let flag_lower = flag_name.to_lowercase();
                if flag_lower.contains("zf")
                    && let Some((left, right)) = self.lookup_flag_origin(flag_name)
                {
                    return Some(CExpr::binary(
                        BinaryOp::Eq,
                        CExpr::Var(left),
                        CExpr::Var(right),
                    ));
                }
                // CF directly means a < b (unsigned, JB)
                if flag_lower.contains("cf")
                    && let Some((left, right)) = self.lookup_flag_origin(flag_name)
                {
                    return Some(CExpr::binary(
                        BinaryOp::Lt,
                        CExpr::Var(left),
                        CExpr::Var(right),
                    ));
                }
                None
            }

            _ => None,
        }
    }

    /// Try to reconstruct a comparison from `temp == 0` or `temp != 0` patterns.
    ///
    /// For `TEST reg, reg; JZ/JNZ`:
    ///   - `t1 = IntAnd(RBX, RBX)` -> `ZF = (t1 == 0)` -> CBranch(ZF)
    ///   - When we see `Var(t1) == IntLit(0)`, trace t1's definition:
    ///     - If `BitAnd(a, b)` where a == b (TEST): produce `a == 0` / `a != 0`
    ///     - If `Sub(a, b)` (CMP): produce `a == b` / `a != b`
    pub(super) fn try_reconstruct_cmp_zero(
        &self,
        var_side: &CExpr,
        zero_side: &CExpr,
        cmp_op: BinaryOp,
    ) -> Option<CExpr> {
        // zero_side must be 0
        let is_zero = match zero_side {
            CExpr::IntLit(0) => true,
            CExpr::Var(name) if name == "elf_header" || name == "0" => true,
            _ => false,
        };
        if !is_zero {
            return None;
        }

        // var_side must be a variable reference
        let var_name = match var_side {
            CExpr::Var(name) => name,
            _ => return None,
        };

        // Look up the definition of this variable (try SSA key first, then formatted name)
        let def = self
            .definitions_map()
            .get(var_name)
            .or_else(|| self.formatted_defs_map().get(var_name))?;

        match def {
            // TEST reg, reg pattern: IntAnd(a, b) where a == b
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                left,
                right,
            } => {
                if left == right {
                    // TEST reg, reg -> reg == 0 / reg != 0
                    return Some(CExpr::binary(cmp_op, *left.clone(), CExpr::IntLit(0)));
                }
                // TEST a, b (different operands) -> (a & b) == 0 / != 0
                Some(CExpr::binary(
                    cmp_op,
                    CExpr::binary(BinaryOp::BitAnd, *left.clone(), *right.clone()),
                    CExpr::IntLit(0),
                ))
            }
            // CMP a, b pattern: Sub(a, b) where the sub is a CMP (result only used for flags)
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => {
                // CMP a, b; JE/JNE -> a == b / a != b
                Some(CExpr::binary(cmp_op, *left.clone(), *right.clone()))
            }
            _ => None,
        }
    }

    // ========== Helper functions for flag pattern detection ==========

    pub(super) fn extract_flag_name(&self, expr: &CExpr, flag: &str) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if is_specific_flag_name(name, flag) {
                return Some(name.clone());
            }

            if let Some(CExpr::Var(inner)) = self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                && is_specific_flag_name(&inner, flag)
            {
                return Some(inner);
            }
        }
        None
    }

    /// Extract ZF variable name from an expression (if it's a ZF flag reference).
    pub(super) fn extract_zf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "zf")
    }

    /// Extract CF variable name from an expression (if it's a CF flag reference).
    pub(super) fn extract_cf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "cf")
    }

    /// Extract SF variable name from an expression (if it's a SF flag reference).
    pub(super) fn extract_sf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "sf")
    }

    /// Extract OF variable name from an expression (if it's an OF flag reference).
    pub(super) fn extract_of(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "of")
    }

    /// Extract ZF variable name from a !ZF expression.
    pub(super) fn extract_not_zf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.extract_zf(operand);
        }
        None
    }

    /// Extract CF variable name from a !CF expression.
    pub(super) fn extract_not_cf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.extract_cf(operand);
        }
        None
    }

    /// Check if expression is OF == SF.
    pub(super) fn is_of_eq_sf(&self, expr: &CExpr) -> bool {
        if let CExpr::Binary {
            op: BinaryOp::Eq,
            left,
            right,
        } = expr
        {
            let has_of_sf = self.extract_of(left).is_some() && self.is_sf_like_expr(right);
            let has_sf_of = self.is_sf_like_expr(left) && self.extract_of(right).is_some();
            return has_of_sf || has_sf_of;
        }
        false
    }

    /// Check if expression is OF != SF.
    pub(super) fn is_of_ne_sf(&self, expr: &CExpr) -> bool {
        if let CExpr::Binary {
            op: BinaryOp::Ne,
            left,
            right,
        } = expr
        {
            let has_of_sf = self.extract_of(left).is_some() && self.is_sf_like_expr(right);
            let has_sf_of = self.is_sf_like_expr(left) && self.extract_of(right).is_some();
            return has_of_sf || has_sf_of;
        }
        // Also check for !(OF == SF)
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.is_of_eq_sf(operand);
        }
        false
    }

    pub(super) fn reconstruct_signed_gt_from_and(
        &self,
        cmp_expr: &CExpr,
        of_sf_expr: &CExpr,
    ) -> Option<CExpr> {
        let cmp = self.canonical_compare_tuple(cmp_expr)?;
        if cmp.context != CompareContext::Ne {
            return None;
        }

        let (of_name, sf_expr) = self.extract_of_sf_pair(of_sf_expr, false)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        if !self.compare_tuple_operands_match(&cmp, &sf_cmp) {
            return None;
        }
        if !self.compare_tuple_matches_flag_origin(&cmp, &of_name) {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Gt, cmp.lhs, cmp.rhs))
    }

    pub(super) fn reconstruct_signed_le_from_or(
        &self,
        cmp_expr: &CExpr,
        of_sf_expr: &CExpr,
    ) -> Option<CExpr> {
        let cmp = self.canonical_compare_tuple(cmp_expr)?;
        if cmp.context != CompareContext::Eq {
            return None;
        }

        let (of_name, sf_expr) = self.extract_of_sf_pair(of_sf_expr, true)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        if !self.compare_tuple_operands_match(&cmp, &sf_cmp) {
            return None;
        }
        if !self.compare_tuple_matches_flag_origin(&cmp, &of_name) {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Le, cmp.lhs, cmp.rhs))
    }

    pub(super) fn reconstruct_signed_ge_from_eq(&self, expr: &CExpr) -> Option<CExpr> {
        let (_of_name, sf_expr) = self.extract_of_sf_pair(expr, false)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Ge, sf_cmp.lhs, sf_cmp.rhs))
    }

    pub(super) fn reconstruct_signed_lt_from_ne(&self, expr: &CExpr) -> Option<CExpr> {
        let (_of_name, sf_expr) = self.extract_of_sf_pair(expr, true)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Lt, sf_cmp.lhs, sf_cmp.rhs))
    }

    pub(super) fn extract_of_sf_pair<'b>(
        &self,
        expr: &'b CExpr,
        want_ne: bool,
    ) -> Option<(String, &'b CExpr)> {
        let op_match = if want_ne { BinaryOp::Ne } else { BinaryOp::Eq };
        if let CExpr::Binary { op, left, right } = expr {
            if *op != op_match {
                return None;
            }
            if let Some(of_name) = self.extract_of(left) {
                return Some((of_name, right));
            }
            if let Some(of_name) = self.extract_of(right) {
                return Some((of_name, left));
            }
        }
        None
    }

    pub(super) fn canonical_compare_tuple(&self, expr: &CExpr) -> Option<CompareTuple> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => Some(self.normalize_compare_tuple(CompareTuple {
                lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                rhs: self.resolve_predicate_operand(right, 0, &mut HashSet::new()),
                context: CompareContext::Eq,
            })),
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => Some(self.normalize_compare_tuple(CompareTuple {
                lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                rhs: self.resolve_predicate_operand(right, 0, &mut HashSet::new()),
                context: CompareContext::Ne,
            })),
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } if self.is_zero_expr(right) => {
                if let Some((sub_lhs, sub_rhs)) = self.extract_sub_operands(left) {
                    return Some(self.normalize_compare_tuple(CompareTuple {
                        lhs: self.resolve_predicate_operand(&sub_lhs, 0, &mut HashSet::new()),
                        rhs: self.resolve_predicate_operand(&sub_rhs, 0, &mut HashSet::new()),
                        context: CompareContext::SignedNegative,
                    }));
                }
                Some(self.normalize_compare_tuple(CompareTuple {
                    lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                    rhs: CExpr::IntLit(0),
                    context: CompareContext::SignedNegative,
                }))
            }
            CExpr::Paren(inner) => self.canonical_compare_tuple(inner),
            CExpr::Cast { expr: inner, .. } => self.canonical_compare_tuple(inner),
            _ => None,
        }
    }

    pub(super) fn extract_sub_operands(&self, expr: &CExpr) -> Option<(CExpr, CExpr)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => Some((left.as_ref().clone(), right.as_ref().clone())),
            CExpr::Paren(inner) => self.extract_sub_operands(inner),
            CExpr::Cast { expr: inner, .. } => self.extract_sub_operands(inner),
            CExpr::Var(name) => {
                if let Some(def) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                {
                    return self.extract_sub_operands(&def);
                }
                None
            }
            _ => None,
        }
    }

    pub(super) fn normalize_compare_tuple(&self, mut tuple: CompareTuple) -> CompareTuple {
        if matches!(tuple.context, CompareContext::Eq | CompareContext::Ne)
            && self.is_literal_expr(&tuple.lhs)
            && !self.is_literal_expr(&tuple.rhs)
        {
            std::mem::swap(&mut tuple.lhs, &mut tuple.rhs);
        }
        tuple
    }

    pub(super) fn compare_tuple_operands_match(&self, a: &CompareTuple, b: &CompareTuple) -> bool {
        a.lhs == b.lhs && a.rhs == b.rhs
    }

    pub(super) fn compare_tuple_matches_flag_origin(
        &self,
        tuple: &CompareTuple,
        of_name: &str,
    ) -> bool {
        let Some(origin) = self.compare_tuple_from_flag_origin(of_name) else {
            return true;
        };

        // If either side still contains opaque temporaries, treat origin matching as
        // advisory only. Local tuple consistency (cmp vs SF-surrogate) remains mandatory.
        if self.expr_contains_opaque_temp(&tuple.lhs)
            || self.expr_contains_opaque_temp(&tuple.rhs)
            || self.expr_contains_opaque_temp(&origin.lhs)
            || self.expr_contains_opaque_temp(&origin.rhs)
            || self.expr_contains_unresolved_memory(&tuple.lhs)
            || self.expr_contains_unresolved_memory(&tuple.rhs)
            || self.expr_contains_unresolved_memory(&origin.lhs)
            || self.expr_contains_unresolved_memory(&origin.rhs)
        {
            return true;
        }

        tuple.lhs == origin.lhs && tuple.rhs == origin.rhs
    }

    pub(super) fn compare_tuple_from_flag_origin(&self, flag_name: &str) -> Option<CompareTuple> {
        let (lhs_name, rhs_name) = self.lookup_flag_origin(flag_name)?;
        let lhs = self.resolve_predicate_operand(
            &self.origin_name_to_expr(&lhs_name),
            0,
            &mut HashSet::new(),
        );
        let rhs = self.resolve_predicate_operand(
            &self.origin_name_to_expr(&rhs_name),
            0,
            &mut HashSet::new(),
        );

        Some(self.normalize_compare_tuple(CompareTuple {
            lhs,
            rhs,
            context: CompareContext::SignedNegative,
        }))
    }

    pub(super) fn origin_name_to_expr(&self, name: &str) -> CExpr {
        if let Some(parsed) = self.parse_expr_from_name(name) {
            return parsed;
        }
        CExpr::Var(name.to_string())
    }

    pub(super) fn parse_expr_from_name(&self, name: &str) -> Option<CExpr> {
        if let Some(val) = parse_const_value(name) {
            return Some(if val > 0x7fffffff {
                CExpr::UIntLit(val)
            } else {
                CExpr::IntLit(val as i64)
            });
        }

        if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X"))
            && let Ok(val) = u64::from_str_radix(hex, 16)
        {
            return Some(if val > 0x7fffffff {
                CExpr::UIntLit(val)
            } else {
                CExpr::IntLit(val as i64)
            });
        }

        if let Ok(dec) = name.parse::<i64>() {
            return Some(CExpr::IntLit(dec));
        }

        None
    }

    pub(super) fn resolve_predicate_operand(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > MAX_PREDICATE_OPERAND_DEPTH {
            return expr.clone();
        }

        match expr {
            CExpr::Paren(inner) => self.resolve_predicate_operand(inner, depth + 1, visited),
            CExpr::Cast { expr: inner, .. } => {
                self.resolve_predicate_operand(inner, depth + 1, visited)
            }
            CExpr::Deref(inner) => {
                if let Some(stack_var) = self.simplify_stack_access(inner) {
                    CExpr::Var(stack_var)
                } else {
                    expr.clone()
                }
            }
            CExpr::Var(name) => {
                if let Some(parsed) = self.parse_expr_from_name(name) {
                    return parsed;
                }
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| {
                        if let Some(stack_var) = self.stack_alias_from_deref_expr(&inner) {
                            CExpr::Var(stack_var)
                        } else if matches!(
                            inner,
                            CExpr::Var(_) | CExpr::Paren(_) | CExpr::Cast { .. } | CExpr::Deref(_)
                        ) {
                            self.resolve_predicate_operand(&inner, depth + 1, visited)
                        } else {
                            CExpr::Var(name.clone())
                        }
                    })
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                resolved
            }
            _ => expr.clone(),
        }
    }

    pub(super) fn is_literal_expr(&self, expr: &CExpr) -> bool {
        matches!(
            expr,
            CExpr::IntLit(_) | CExpr::UIntLit(_) | CExpr::FloatLit(_) | CExpr::CharLit(_)
        )
    }

    pub(super) fn is_opaque_temp_name(&self, name: &str) -> bool {
        if name.starts_with("var_") {
            return true;
        }
        if let Some(rest) = name.strip_prefix('t') {
            return rest
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);
        }
        false
    }

    pub(super) fn is_semantic_binding_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with("local_")
            || lower.starts_with("arg")
            || lower.starts_with("field_")
            || lower.starts_with("var_")
            || lower.starts_with("sub_")
            || lower.starts_with("str.")
            || lower.starts_with("0x")
            || lower.contains('.')
    }

    pub(super) fn is_register_like_base_name(&self, name: &str) -> bool {
        self.inputs.arch.is_register_like_base_name(name)
    }

    pub(super) fn is_ephemeral_ssa_target(&self, name: &str) -> bool {
        if Self::is_semantic_binding_name(name) {
            return false;
        }

        if self.is_opaque_temp_name(name) {
            return true;
        }

        let lower = name.to_ascii_lowercase();
        let base = match lower.rsplit_once('_') {
            Some((base, suffix))
                if !base.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()) =>
            {
                base
            }
            _ => lower.as_str(),
        };

        self.is_register_like_base_name(base)
    }

    pub(super) fn expr_contains_opaque_temp(&self, expr: &CExpr) -> bool {
        let mut found = false;
        expr.visit(&mut |node| {
            if let CExpr::Var(name) = node
                && self.is_opaque_temp_name(name)
            {
                found = true;
            }
        });
        found
    }

    pub(super) fn expr_contains_unresolved_memory(&self, expr: &CExpr) -> bool {
        let mut found = false;
        expr.visit(&mut |node| {
            if matches!(node, CExpr::Deref(_)) {
                found = true;
            }
        });
        found
    }

    pub(super) fn is_sf_like_expr(&self, expr: &CExpr) -> bool {
        self.extract_sf(expr).is_some() || self.is_sf_surrogate(expr)
    }

    pub(super) fn is_sf_surrogate(&self, expr: &CExpr) -> bool {
        let mut visited = HashSet::new();
        self.is_sf_surrogate_inner(expr, &mut visited, 0)
    }

    pub(super) fn is_sf_surrogate_inner(
        &self,
        expr: &CExpr,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        // Guard against deeply nested/cyclic definitions from large CFGs.
        if depth > MAX_SF_SURROGATE_DEPTH {
            return false;
        }
        match expr {
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } if self.is_zero_expr(right) => self.is_sub_like_expr_inner(left, visited, depth + 1),
            CExpr::Paren(inner) => self.is_sf_surrogate_inner(inner, visited, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.is_sf_surrogate_inner(inner, visited, depth + 1)
            }
            CExpr::Var(name) => {
                if !visited.insert(name.clone()) {
                    return false;
                }
                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| self.is_sf_surrogate_inner(&inner, visited, depth + 1))
                    .unwrap_or(false);
                visited.remove(name);
                resolved
            }
            _ => false,
        }
    }

    pub(super) fn is_sub_like_expr_inner(
        &self,
        expr: &CExpr,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if depth > MAX_SUB_LIKE_DEPTH {
            return false;
        }
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub, ..
            } => true,
            CExpr::Paren(inner) => self.is_sub_like_expr_inner(inner, visited, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.is_sub_like_expr_inner(inner, visited, depth + 1)
            }
            CExpr::Var(name) => {
                if !visited.insert(name.clone()) {
                    return false;
                }
                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| self.is_sub_like_expr_inner(&inner, visited, depth + 1))
                    .unwrap_or(false);
                visited.remove(name);
                resolved
            }
            _ => false,
        }
    }

    /// Extract switch expression from an operation (for switch statement detection).
    pub fn extract_switch_expr(&self, op: &SSAOp) -> Option<CExpr> {
        // Look for indirect branch (BranchInd) which typically holds the switch variable
        if let SSAOp::BranchInd { target } = op {
            return Some(self.get_expr(target));
        }
        None
    }

    /// Look up the original comparison operands for a flag variable.
    pub(super) fn lookup_flag_origin(&self, flag_name: &str) -> Option<(String, String)> {
        let (flag_base, flag_version) = parse_flag_name(flag_name)?;

        // Try exact match first (case-insensitive) including version.
        for (key, origin) in self.flag_origins_map() {
            if let Some((key_base, key_version)) = parse_flag_name(key)
                && key_base == flag_base
                && key_version == flag_version
            {
                return Some(origin.clone());
            }
        }

        // Fallback by base-name only when there is exactly one candidate.
        // This avoids picking an arbitrary origin for unsuffixed flags.
        let candidates: Vec<(String, String)> = self
            .flag_origins_map()
            .iter()
            .filter_map(|(key, origin)| {
                let (key_base, _) = parse_flag_name(key)?;
                if key_base == flag_base {
                    Some(origin.clone())
                } else {
                    None
                }
            })
            .collect();

        if candidates.len() == 1 {
            return candidates.into_iter().next();
        }

        None
    }
}

fn parse_flag_name(name: &str) -> Option<(String, Option<String>)> {
    let lower = name.to_ascii_lowercase();
    if is_flag_base_name(&lower) {
        return Some((lower, None));
    }

    let (base, suffix) = lower.split_once('_')?;
    if is_flag_base_name(base) && !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
    {
        return Some((base.to_string(), Some(suffix.to_string())));
    }

    None
}

fn is_specific_flag_name(name: &str, flag: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == flag {
        return true;
    }

    let Some((base, suffix)) = lower.split_once('_') else {
        return false;
    };

    base == flag && !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
}

fn is_flag_base_name(name: &str) -> bool {
    matches!(
        name,
        "cf" | "pf" | "af" | "zf" | "sf" | "of" | "df" | "tf" | "if" | "iopl" | "nt" | "rf" | "vm"
    )
}

/// Check if a name is a CPU flag that should be eliminated when unused.
pub(crate) fn is_cpu_flag(name: &str) -> bool {
    // Match exact flag names
    if matches!(
        name,
        "cf" | "pf"
            | "af"
            | "zf"
            | "sf"
            | "of"
            | "df"
            | "tf"
            | "if"
            | "iopl"
            | "nt"
            | "rf"
            | "vm"
            | "ac"
            | "vif"
            | "vip"
            | "id"
    ) {
        return true;
    }

    // Also match versioned flags (e.g., cf_1, zf_2)
    name.starts_with("cf_")
        || name.starts_with("pf_")
        || name.starts_with("af_")
        || name.starts_with("zf_")
        || name.starts_with("sf_")
        || name.starts_with("of_")
}

#[cfg(test)]
#[path = "tests/flags.rs"]
mod tests;
