//! Type inference and representation.
//!
//! This module provides type inference for decompiled code,
//! mapping SSA variables to C types.

use std::collections::HashMap;

use r2ssa::{SSAFunction, SSAOp, SSAVar};

use crate::ast::CType;

/// Type inference context.
pub struct TypeInference {
    /// Inferred types for variables.
    var_types: HashMap<SSAVar, CType>,
    /// Known function signatures.
    func_types: HashMap<String, FunctionType>,
    /// Pointer size in bits.
    _ptr_size: u32,
}

/// Function type signature.
#[derive(Debug, Clone)]
pub struct FunctionType {
    pub return_type: CType,
    pub params: Vec<CType>,
    pub variadic: bool,
}

impl TypeInference {
    /// Create a new type inference context.
    pub fn new(ptr_size: u32) -> Self {
        Self {
            var_types: HashMap::new(),
            func_types: HashMap::new(),
            _ptr_size: ptr_size,
        }
    }

    /// Infer types for all variables in a function.
    pub fn infer_function(&mut self, func: &SSAFunction) {
        // First pass: collect explicit type information
        for block in func.blocks() {
            for op in &block.ops {
                self.infer_from_op(op);
            }
        }

        // Second pass: propagate types through uses
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 10 {
            changed = false;
            for block in func.blocks() {
                for op in &block.ops {
                    if self.propagate_types(op) {
                        changed = true;
                    }
                }
            }
            iterations += 1;
        }
    }

    /// Infer types from a single operation.
    fn infer_from_op(&mut self, op: &SSAOp) {
        match op {
            SSAOp::Copy { dst, src } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(src, ty);
            }
            SSAOp::Load { dst, addr, .. } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty);
                self.set_type(addr, CType::ptr(CType::Void));
            }
            SSAOp::Store { addr, val, .. } => {
                self.set_type(addr, CType::ptr(CType::Void));
                let ty = self.type_from_size(val.size);
                self.set_type(val, ty);
            }
            SSAOp::IntAdd { dst, a, b }
            | SSAOp::IntSub { dst, a, b }
            | SSAOp::IntMult { dst, a, b }
            | SSAOp::IntAnd { dst, a, b }
            | SSAOp::IntOr { dst, a, b }
            | SSAOp::IntXor { dst, a, b } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntDiv { dst, a, b }
            | SSAOp::IntRem { dst, a, b } => {
                let ty = CType::UInt(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntSDiv { dst, a, b }
            | SSAOp::IntSRem { dst, a, b } => {
                let ty = CType::Int(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntLess { dst, a, b }
            | SSAOp::IntLessEqual { dst, a, b }
            | SSAOp::IntEqual { dst, a, b }
            | SSAOp::IntNotEqual { dst, a, b } => {
                self.set_type(dst, CType::Bool);
                let ty = self.type_from_size(a.size);
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntSLess { dst, a, b }
            | SSAOp::IntSLessEqual { dst, a, b } => {
                self.set_type(dst, CType::Bool);
                let ty = CType::Int(a.size);
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntNegate { dst, src }
            | SSAOp::IntNot { dst, src } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(src, ty);
            }
            SSAOp::IntLeft { dst, a, b }
            | SSAOp::IntRight { dst, a, b }
            | SSAOp::IntSRight { dst, a, b } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty);
                self.set_type(b, CType::UInt(8));
            }
            SSAOp::IntZExt { dst, src } => {
                self.set_type(dst, CType::UInt(dst.size));
                self.set_type(src, CType::UInt(src.size));
            }
            SSAOp::IntSExt { dst, src } => {
                self.set_type(dst, CType::Int(dst.size));
                self.set_type(src, CType::Int(src.size));
            }
            SSAOp::BoolAnd { dst, a, b }
            | SSAOp::BoolOr { dst, a, b }
            | SSAOp::BoolXor { dst, a, b } => {
                self.set_type(dst, CType::Bool);
                self.set_type(a, CType::Bool);
                self.set_type(b, CType::Bool);
            }
            SSAOp::BoolNot { dst, src } => {
                self.set_type(dst, CType::Bool);
                self.set_type(src, CType::Bool);
            }
            SSAOp::FloatAdd { dst, a, b }
            | SSAOp::FloatSub { dst, a, b }
            | SSAOp::FloatMult { dst, a, b }
            | SSAOp::FloatDiv { dst, a, b } => {
                let ty = CType::Float(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::FloatNeg { dst, src }
            | SSAOp::FloatAbs { dst, src }
            | SSAOp::FloatSqrt { dst, src } => {
                let ty = CType::Float(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(src, ty);
            }
            SSAOp::FloatLess { dst, a, b }
            | SSAOp::FloatLessEqual { dst, a, b }
            | SSAOp::FloatEqual { dst, a, b }
            | SSAOp::FloatNotEqual { dst, a, b } => {
                self.set_type(dst, CType::Bool);
                let ty = CType::Float(a.size);
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::Int2Float { dst, src } => {
                self.set_type(dst, CType::Float(dst.size));
                self.set_type(src, CType::Int(src.size));
            }
            SSAOp::Float2Int { dst, src } => {
                self.set_type(dst, CType::Int(dst.size));
                self.set_type(src, CType::Float(src.size));
            }
            SSAOp::FloatFloat { dst, src } => {
                self.set_type(dst, CType::Float(dst.size));
                self.set_type(src, CType::Float(src.size));
            }
            SSAOp::Trunc { dst, src } => {
                let dst_ty = self.type_from_size(dst.size);
                let src_ty = self.type_from_size(src.size);
                self.set_type(dst, dst_ty);
                self.set_type(src, src_ty);
            }
            SSAOp::Phi { dst, sources } => {
                let ty = self.type_from_size(dst.size);
                self.set_type(dst, ty.clone());
                for src in sources {
                    self.set_type(src, ty.clone());
                }
            }
            _ => {}
        }
    }

    /// Propagate types through uses.
    fn propagate_types(&mut self, op: &SSAOp) -> bool {
        let mut changed = false;

        // If we have a type for the destination, propagate to sources
        if let Some(dst) = op.dst() {
            if let Some(dst_ty) = self.var_types.get(dst).cloned() {
                for src in op.sources() {
                    if !self.var_types.contains_key(src) {
                        self.var_types.insert(src.clone(), dst_ty.clone());
                        changed = true;
                    }
                }
            }
        }

        // If we have types for sources, propagate to destination
        if let Some(dst) = op.dst() {
            if !self.var_types.contains_key(dst) {
                for src in op.sources() {
                    if let Some(src_ty) = self.var_types.get(src).cloned() {
                        self.var_types.insert(dst.clone(), src_ty);
                        changed = true;
                        break;
                    }
                }
            }
        }

        changed
    }

    /// Set the type of a variable.
    fn set_type(&mut self, var: &SSAVar, ty: CType) {
        // Don't overwrite more specific types
        if let Some(existing) = self.var_types.get(var) {
            if self.is_more_specific(existing, &ty) {
                return;
            }
        }
        self.var_types.insert(var.clone(), ty);
    }

    /// Check if type A is more specific than type B.
    fn is_more_specific(&self, a: &CType, b: &CType) -> bool {
        match (a, b) {
            (CType::Pointer(_), CType::Int(_) | CType::UInt(_)) => true,
            (CType::Int(_), CType::UInt(_)) => true,
            (CType::Struct(_), CType::Pointer(_)) => true,
            _ => false,
        }
    }

    /// Get the type of a variable.
    pub fn get_type(&self, var: &SSAVar) -> CType {
        self.var_types
            .get(var)
            .cloned()
            .unwrap_or_else(|| self.type_from_size(var.size))
    }

    /// Get a type from a size.
    pub fn type_from_size(&self, size: u32) -> CType {
        match size {
            1 => CType::Bool,
            8 => CType::Int(8),
            16 => CType::Int(16),
            32 => CType::Int(32),
            64 => CType::Int(64),
            _ => CType::Int(size),
        }
    }

    /// Register a function type.
    pub fn add_function_type(&mut self, name: &str, func_type: FunctionType) {
        self.func_types.insert(name.to_string(), func_type);
    }

    /// Get a function type.
    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.func_types.get(name)
    }

    /// Detect pointer arithmetic patterns.
    pub fn detect_pointer_patterns(&mut self, func: &SSAFunction) {
        for block in func.blocks() {
            for op in &block.ops {
                if let SSAOp::IntAdd { dst, a, b } = op {
                    let ty_a = self.get_type(a);
                    let ty_b = self.get_type(b);

                    if matches!(ty_a, CType::Pointer(_)) {
                        self.set_type(dst, ty_a);
                    } else if matches!(ty_b, CType::Pointer(_)) {
                        self.set_type(dst, ty_b);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_from_size() {
        let ti = TypeInference::new(64);

        assert_eq!(ti.type_from_size(1), CType::Bool);
        assert_eq!(ti.type_from_size(8), CType::Int(8));
        assert_eq!(ti.type_from_size(32), CType::Int(32));
        assert_eq!(ti.type_from_size(64), CType::Int(64));
    }

    #[test]
    fn test_is_more_specific() {
        let ti = TypeInference::new(64);

        // Pointer is more specific than int
        assert!(ti.is_more_specific(
            &CType::ptr(CType::Void),
            &CType::Int(64)
        ));

        // Signed is more specific than unsigned
        assert!(ti.is_more_specific(
            &CType::Int(32),
            &CType::UInt(32)
        ));
    }
}
