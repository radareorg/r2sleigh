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
    /// Function names by address (injected from external context).
    function_names: HashMap<u64, String>,
    /// Pointer size in bits.
    ptr_size: u32,
    /// Calling-convention argument registers for the active architecture.
    arg_regs: Vec<String>,
    /// Return-value registers for the active architecture.
    ret_regs: Vec<String>,
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
        let mut ti = Self {
            var_types: HashMap::new(),
            func_types: HashMap::new(),
            function_names: HashMap::new(),
            ptr_size,
            arg_regs: if ptr_size == 64 {
                vec![
                    "rdi".to_string(),
                    "rsi".to_string(),
                    "rdx".to_string(),
                    "rcx".to_string(),
                    "r8".to_string(),
                    "r9".to_string(),
                ]
            } else {
                vec![]
            },
            ret_regs: if ptr_size == 64 {
                vec!["rax".to_string(), "eax".to_string()]
            } else {
                vec!["eax".to_string()]
            },
        };
        // Add known libc function signatures
        ti.add_known_functions();
        ti
    }

    /// Add known C library function signatures.
    fn add_known_functions(&mut self) {
        let size_t = CType::UInt(self.ptr_size);

        // memcpy(void* dst, const void* src, size_t n)
        self.func_types.insert(
            "memcpy".to_string(),
            FunctionType {
                return_type: CType::void_ptr(),
                params: vec![CType::void_ptr(), CType::void_ptr(), size_t.clone()],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.memcpy".to_string(),
            FunctionType {
                return_type: CType::void_ptr(),
                params: vec![CType::void_ptr(), CType::void_ptr(), size_t.clone()],
                variadic: false,
            },
        );

        // printf(const char* fmt, ...)
        self.func_types.insert(
            "printf".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::ptr(CType::Int(8))],
                variadic: true,
            },
        );
        self.func_types.insert(
            "sym.imp.printf".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::ptr(CType::Int(8))],
                variadic: true,
            },
        );

        // strcmp(const char* s1, const char* s2)
        self.func_types.insert(
            "strcmp".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::ptr(CType::Int(8)), CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.strcmp".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::ptr(CType::Int(8)), CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );

        // strlen(const char* s)
        self.func_types.insert(
            "strlen".to_string(),
            FunctionType {
                return_type: size_t.clone(),
                params: vec![CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.strlen".to_string(),
            FunctionType {
                return_type: size_t.clone(),
                params: vec![CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );

        // malloc(size_t size)
        self.func_types.insert(
            "malloc".to_string(),
            FunctionType {
                return_type: CType::void_ptr(),
                params: vec![size_t.clone()],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.malloc".to_string(),
            FunctionType {
                return_type: CType::void_ptr(),
                params: vec![size_t],
                variadic: false,
            },
        );

        // free(void* ptr)
        self.func_types.insert(
            "free".to_string(),
            FunctionType {
                return_type: CType::Void,
                params: vec![CType::void_ptr()],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.free".to_string(),
            FunctionType {
                return_type: CType::Void,
                params: vec![CType::void_ptr()],
                variadic: false,
            },
        );

        // setlocale(int category, const char* locale) -> char*
        self.func_types.insert(
            "setlocale".to_string(),
            FunctionType {
                return_type: CType::ptr(CType::Int(8)),
                params: vec![CType::Int(32), CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );
        self.func_types.insert(
            "sym.imp.setlocale".to_string(),
            FunctionType {
                return_type: CType::ptr(CType::Int(8)),
                params: vec![CType::Int(32), CType::ptr(CType::Int(8))],
                variadic: false,
            },
        );
    }

    /// Infer types for all variables in a function.
    pub fn infer_function(&mut self, func: &SSAFunction) {
        // First pass: collect explicit type information from operations
        for block in func.blocks() {
            for op in &block.ops {
                self.infer_from_op(op);
            }
        }

        // Second pass: apply known API signatures to call args/returns.
        self.infer_call_types(func);

        // Third pass: detect pointer arithmetic patterns
        self.detect_pointer_patterns(func);

        // Fourth pass: propagate types through uses
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
            SSAOp::IntDiv { dst, a, b } | SSAOp::IntRem { dst, a, b } => {
                let ty = CType::UInt(dst.size);
                self.set_type(dst, ty.clone());
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntSDiv { dst, a, b } | SSAOp::IntSRem { dst, a, b } => {
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
            SSAOp::IntSLess { dst, a, b } | SSAOp::IntSLessEqual { dst, a, b } => {
                self.set_type(dst, CType::Bool);
                let ty = CType::Int(a.size);
                self.set_type(a, ty.clone());
                self.set_type(b, ty);
            }
            SSAOp::IntNegate { dst, src } | SSAOp::IntNot { dst, src } => {
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

    fn infer_call_types(&mut self, func: &SSAFunction) {
        for block in func.blocks() {
            for (call_idx, op) in block.ops.iter().enumerate() {
                let target = match op {
                    SSAOp::Call { target } | SSAOp::CallInd { target } => target,
                    _ => continue,
                };

                let Some(sig) = self.resolve_call_signature(target) else {
                    continue;
                };

                self.apply_arg_signature(&block.ops, call_idx, &sig.params);
                self.apply_return_signature(&block.ops, call_idx, &sig.return_type);
            }
        }
    }

    fn apply_arg_signature(&mut self, ops: &[SSAOp], call_idx: usize, params: &[CType]) {
        if self.arg_regs.is_empty() || params.is_empty() {
            return;
        }

        let mut seen: HashMap<usize, SSAVar> = HashMap::new();
        let mut idx = call_idx;
        while idx > 0 {
            idx -= 1;
            let prev = &ops[idx];

            if matches!(prev, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                break;
            }

            let (dst, src) = match prev {
                SSAOp::Copy { dst, src }
                | SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src } => (dst, src),
                _ => continue,
            };

            let dst_lower = dst.name.to_lowercase();
            if let Some(arg_pos) = self.arg_regs.iter().position(|r| r == &dst_lower) {
                if arg_pos < params.len() && !seen.contains_key(&arg_pos) {
                    let ty = params[arg_pos].clone();
                    self.set_type(dst, ty.clone());
                    self.set_type(src, ty);
                    seen.insert(arg_pos, src.clone());
                }
            }
        }
    }

    fn apply_return_signature(&mut self, ops: &[SSAOp], call_idx: usize, ret_ty: &CType) {
        if matches!(ret_ty, CType::Void) {
            return;
        }

        let mut idx = call_idx + 1;
        while idx < ops.len() {
            let next = &ops[idx];

            if matches!(next, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                break;
            }

            match next {
                SSAOp::Copy { dst, src }
                | SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src } => {
                    if self.is_return_reg(src) {
                        self.set_type(src, ret_ty.clone());
                        self.set_type(dst, ret_ty.clone());
                        return;
                    }
                }
                _ => {}
            }

            idx += 1;
        }
    }

    fn is_return_reg(&self, var: &SSAVar) -> bool {
        let name = var.name.to_lowercase();
        self.ret_regs.iter().any(|r| r == &name)
    }

    fn resolve_call_signature(&self, target: &SSAVar) -> Option<FunctionType> {
        if let Some(addr) = parse_const_addr(&target.name) {
            if let Some(name) = self.function_names.get(&addr) {
                if let Some(sig) = self.lookup_function_type(name) {
                    return Some(sig);
                }
            }
        }

        self.lookup_function_type(&target.name)
    }

    fn lookup_function_type(&self, name: &str) -> Option<FunctionType> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        if let Some(sig) = self.func_types.get(name) {
            return Some(sig.clone());
        }

        let lower = name.to_lowercase();
        if let Some(sig) = self.func_types.get(&lower) {
            return Some(sig.clone());
        }

        if let Some(stripped) = lower.strip_prefix("sym.imp.") {
            if let Some(sig) = self.func_types.get(stripped) {
                return Some(sig.clone());
            }
        }

        let imp_name = format!("sym.imp.{}", lower);
        self.func_types.get(&imp_name).cloned()
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
            0 => CType::Unknown,
            1 => CType::Int(8),
            2 => CType::Int(16),
            4 => CType::Int(32),
            8 => CType::Int(64),
            _ => CType::Int(size.saturating_mul(8)),
        }
    }

    /// Set externally-resolved function names (address -> symbol).
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.function_names = names;
    }

    /// Export inferred types keyed by variable display/lowered names.
    pub fn var_type_hints(&self) -> HashMap<String, CType> {
        let mut out = HashMap::new();
        for (var, ty) in &self.var_types {
            let key = var.display_name();
            out.insert(key.clone(), ty.clone());
            out.insert(key.to_lowercase(), ty.clone());

            let base = var.name.to_lowercase();
            out.insert(base.clone(), ty.clone());
            out.insert(format!("{}_{}", base, var.version), ty.clone());
        }
        out
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
                match op {
                    // Pointer arithmetic: ptr + offset
                    SSAOp::IntAdd { dst, a, b } => {
                        let ty_a = self.get_type(a);
                        let ty_b = self.get_type(b);

                        if matches!(ty_a, CType::Pointer(_)) {
                            self.set_type(dst, ty_a);
                        } else if matches!(ty_b, CType::Pointer(_)) {
                            self.set_type(dst, ty_b);
                        }
                    }
                    // Pointer arithmetic: ptr - offset
                    SSAOp::IntSub { dst, a, b } => {
                        let ty_a = self.get_type(a);
                        let ty_b = self.get_type(b);

                        // ptr - int = ptr
                        if matches!(ty_a, CType::Pointer(_)) && !matches!(ty_b, CType::Pointer(_)) {
                            self.set_type(dst, ty_a);
                        }
                        // ptr - ptr = size_t (not a pointer)
                    }
                    // Copy propagates pointer type
                    SSAOp::Copy { dst, src } => {
                        let ty_src = self.get_type(src);
                        if matches!(ty_src, CType::Pointer(_)) {
                            self.set_type(dst, ty_src);
                        }
                    }
                    // Load/Store addresses are always pointers
                    SSAOp::Load { addr, .. } | SSAOp::Store { addr, .. } => {
                        // Mark the address as a pointer if not already
                        let ty = self.get_type(addr);
                        if !matches!(ty, CType::Pointer(_)) {
                            self.set_type(addr, CType::void_ptr());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Detect if a variable is used as a string (passed to string functions).
    pub fn detect_string_usage(
        &mut self,
        func: &SSAFunction,
        function_names: &HashMap<u64, String>,
    ) {
        for block in func.blocks() {
            for op in &block.ops {
                if let SSAOp::Call { target } = op {
                    // Try to get the function name from the call target
                    if target.is_const() {
                        if let Some(addr) = parse_const_addr(&target.name) {
                            if let Some(name) = function_names.get(&addr) {
                                // Check if this is a string function
                                if let Some(func_type) = self.func_types.get(name) {
                                    // Mark parameters as the appropriate types
                                    // This is a simplified version - full implementation would
                                    // track which registers hold the arguments
                                    if name.contains("printf")
                                        || name.contains("strlen")
                                        || name.contains("strcmp")
                                    {
                                        // First param is a char*
                                        // We'd need call analysis to properly track this
                                    }
                                    let _ = func_type; // Silence unused warning for now
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Parse a constant address from an SSA variable name.
fn parse_const_addr(name: &str) -> Option<u64> {
    if let Some(val_str) = name.strip_prefix("const:") {
        let val_str = val_str.split('_').next().unwrap_or(val_str);
        if let Some(hex) = val_str
            .strip_prefix("0x")
            .or_else(|| val_str.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).ok();
        }
        // Try as plain hex
        u64::from_str_radix(val_str, 16).ok()
    } else if let Some(val_str) = name.strip_prefix("ram:") {
        let val_str = val_str.split('_').next().unwrap_or(val_str);
        u64::from_str_radix(val_str, 16).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_from_size() {
        let ti = TypeInference::new(64);

        assert_eq!(ti.type_from_size(1), CType::Int(8));
        assert_eq!(ti.type_from_size(2), CType::Int(16));
        assert_eq!(ti.type_from_size(4), CType::Int(32));
        assert_eq!(ti.type_from_size(8), CType::Int(64));
    }

    #[test]
    fn test_is_more_specific() {
        let ti = TypeInference::new(64);

        // Pointer is more specific than int
        assert!(ti.is_more_specific(&CType::ptr(CType::Void), &CType::Int(64)));

        // Signed is more specific than unsigned
        assert!(ti.is_more_specific(&CType::Int(32), &CType::UInt(32)));
    }
}
