use std::collections::{HashMap, HashSet};

use r2ssa::{SSAOp, SSAVar};

use super::utils::parse_const_value;
use crate::ast::{BinaryOp, CExpr, CType, UnaryOp};
use crate::fold::PtrArith;

pub(crate) struct LowerCtx<'a> {
    pub(crate) definitions: &'a HashMap<String, CExpr>,
    pub(crate) use_counts: &'a HashMap<String, usize>,
    pub(crate) condition_vars: &'a HashSet<String>,
    pub(crate) pinned: &'a HashSet<String>,
    pub(crate) var_aliases: &'a HashMap<String, String>,
    pub(crate) ptr_arith: &'a HashMap<String, PtrArith>,
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
            SSAOp::IntDiv { a, b, .. } | SSAOp::IntSDiv { a, b, .. } => {
                self.binary_expr(BinaryOp::Div, a, b)
            }
            SSAOp::IntRem { a, b, .. } | SSAOp::IntSRem { a, b, .. } => {
                self.binary_expr(BinaryOp::Mod, a, b)
            }
            SSAOp::IntAnd { a, b, .. } => self.binary_expr(BinaryOp::BitAnd, a, b),
            SSAOp::IntOr { a, b, .. } => self.binary_expr(BinaryOp::BitOr, a, b),
            SSAOp::IntXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::IntLeft { a, b, .. } => self.binary_expr(BinaryOp::Shl, a, b),
            SSAOp::IntRight { a, b, .. } | SSAOp::IntSRight { a, b, .. } => {
                self.binary_expr(BinaryOp::Shr, a, b)
            }
            SSAOp::IntLess { a, b, .. } | SSAOp::IntSLess { a, b, .. } => {
                self.binary_expr(BinaryOp::Lt, a, b)
            }
            SSAOp::IntLessEqual { a, b, .. } | SSAOp::IntSLessEqual { a, b, .. } => {
                self.binary_expr(BinaryOp::Le, a, b)
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
        if val > 0x7fffffff {
            CExpr::UIntLit(val)
        } else {
            CExpr::IntLit(val as i64)
        }
    }

    fn binary_expr(&self, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> CExpr {
        CExpr::binary(op, self.get_expr(a), self.get_expr(b))
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
        let elem_ty = uint_type_from_size(element_size);
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
