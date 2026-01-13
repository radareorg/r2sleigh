//! Variable naming and recovery.
//!
//! This module handles variable naming, stack variable recovery,
//! and parameter detection.

use std::collections::HashMap;

use r2ssa::{SSAFunction, SSAOp, SSAVar};

use crate::ast::CType;

/// Variable information.
#[derive(Debug, Clone)]
pub struct VarInfo {
    /// The SSA variable.
    pub ssa_var: SSAVar,
    /// The C name for this variable.
    pub name: String,
    /// The inferred type.
    pub ty: CType,
    /// Whether this is a parameter.
    pub is_param: bool,
    /// Whether this is a local variable.
    pub is_local: bool,
    /// Stack offset (if stack variable).
    pub stack_offset: Option<i64>,
}

/// Variable recovery and naming context.
pub struct VariableRecovery {
    /// All recovered variables.
    vars: HashMap<SSAVar, VarInfo>,
    /// Name counter for generating unique names.
    name_counters: HashMap<String, usize>,
    /// Stack pointer register name.
    sp_name: String,
    /// Frame pointer register name.
    fp_name: String,
    /// Pointer size in bits.
    _ptr_size: u32,
}

impl VariableRecovery {
    /// Create a new variable recovery context.
    pub fn new(sp_name: &str, fp_name: &str, ptr_size: u32) -> Self {
        Self {
            vars: HashMap::new(),
            name_counters: HashMap::new(),
            sp_name: sp_name.to_string(),
            fp_name: fp_name.to_string(),
            _ptr_size: ptr_size,
        }
    }

    /// Recover variables from an SSA function.
    pub fn recover(&mut self, func: &SSAFunction) {
        // First pass: identify stack variables
        self.find_stack_variables(func);

        // Second pass: identify parameters
        self.find_parameters(func);

        // Third pass: name remaining variables
        self.name_remaining(func);
    }

    /// Find stack variables (loads/stores relative to SP/FP).
    fn find_stack_variables(&mut self, func: &SSAFunction) {
        for block in func.blocks() {
            for op in &block.ops {
                match op {
                    SSAOp::Load { dst, addr, .. } => {
                        if let Some(offset) = self.get_stack_offset(addr) {
                            let name = self.gen_stack_var_name(offset);
                            let ty = self.type_from_size(dst.size);
                            self.vars.insert(
                                dst.clone(),
                                VarInfo {
                                    ssa_var: dst.clone(),
                                    name,
                                    ty,
                                    is_param: false,
                                    is_local: true,
                                    stack_offset: Some(offset),
                                },
                            );
                        }
                    }
                    SSAOp::Store { addr, val, .. } => {
                        if let Some(offset) = self.get_stack_offset(addr) {
                            let name = self.gen_stack_var_name(offset);
                            let ty = self.type_from_size(val.size);
                            self.vars.insert(
                                val.clone(),
                                VarInfo {
                                    ssa_var: val.clone(),
                                    name,
                                    ty,
                                    is_param: false,
                                    is_local: true,
                                    stack_offset: Some(offset),
                                },
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get stack offset from an address variable.
    fn get_stack_offset(&self, addr: &SSAVar) -> Option<i64> {
        if addr.name.contains(&self.sp_name) || addr.name.contains(&self.fp_name) {
            return Some(0);
        }
        None
    }

    /// Generate a name for a stack variable.
    fn gen_stack_var_name(&mut self, offset: i64) -> String {
        if offset >= 0 {
            format!("local_{:x}", offset)
        } else {
            format!("arg_{:x}", -offset)
        }
    }

    /// Find function parameters.
    fn find_parameters(&mut self, func: &SSAFunction) {
        let entry = match func.entry_block() {
            Some(b) => b,
            None => return,
        };

        let mut defined = std::collections::HashSet::new();

        for op in &entry.ops {
            // Check uses first
            for src in op.sources() {
                if !defined.contains(src) && !self.vars.contains_key(src) {
                    let name = self.gen_param_name(&src);
                    let ty = self.type_from_size(src.size);
                    self.vars.insert(
                        src.clone(),
                        VarInfo {
                            ssa_var: src.clone(),
                            name,
                            ty,
                            is_param: true,
                            is_local: false,
                            stack_offset: None,
                        },
                    );
                }
            }

            // Then definitions
            if let Some(dst) = op.dst() {
                defined.insert(dst.clone());
            }
        }
    }

    /// Generate a parameter name.
    fn gen_param_name(&mut self, var: &SSAVar) -> String {
        // Use register name if it's a common parameter register
        let name = var.name.to_lowercase();
        if name.contains("rdi") || name.contains("edi") {
            return "arg1".to_string();
        }
        if name.contains("rsi") || name.contains("esi") {
            return "arg2".to_string();
        }
        if name.contains("rdx") || name.contains("edx") {
            return "arg3".to_string();
        }
        if name.contains("rcx") || name.contains("ecx") {
            return "arg4".to_string();
        }
        if name.contains("r8") {
            return "arg5".to_string();
        }
        if name.contains("r9") {
            return "arg6".to_string();
        }

        // ARM calling convention
        if name.contains("r0") || name.contains("x0") {
            return "arg1".to_string();
        }
        if name.contains("r1") || name.contains("x1") {
            return "arg2".to_string();
        }
        if name.contains("r2") || name.contains("x2") {
            return "arg3".to_string();
        }
        if name.contains("r3") || name.contains("x3") {
            return "arg4".to_string();
        }

        // Generic parameter name
        let count = self.name_counters.entry("arg".to_string()).or_insert(0);
        *count += 1;
        format!("arg{}", count)
    }

    /// Name remaining variables.
    fn name_remaining(&mut self, func: &SSAFunction) {
        for block in func.blocks() {
            for op in &block.ops {
                if let Some(dst) = op.dst() {
                    if !self.vars.contains_key(&dst) {
                        let name = self.gen_var_name(&dst);
                        let ty = self.type_from_size(dst.size);
                        self.vars.insert(
                            dst.clone(),
                            VarInfo {
                                ssa_var: dst.clone(),
                                name,
                                ty,
                                is_param: false,
                                is_local: false,
                                stack_offset: None,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Generate a variable name.
    fn gen_var_name(&mut self, var: &SSAVar) -> String {
        let base = if var.name.contains("reg:") {
            "v"
        } else if var.name.contains("tmp:") || var.name.contains("unique:") {
            "t"
        } else {
            "v"
        };

        let count = self.name_counters.entry(base.to_string()).or_insert(0);
        *count += 1;
        format!("{}{}", base, count)
    }

    /// Get a type from a bit size.
    fn type_from_size(&self, size: u32) -> CType {
        match size {
            1 => CType::Bool,
            8 => CType::Int(8),
            16 => CType::Int(16),
            32 => CType::Int(32),
            64 => CType::Int(64),
            _ => CType::Int(size),
        }
    }

    /// Get variable info.
    pub fn get_var(&self, var: &SSAVar) -> Option<&VarInfo> {
        self.vars.get(var)
    }

    /// Get the C name for a variable.
    pub fn get_name(&self, var: &SSAVar) -> String {
        self.vars
            .get(var)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| format!("unk_{}", var.version))
    }

    /// Get all parameters.
    pub fn parameters(&self) -> Vec<&VarInfo> {
        self.vars.values().filter(|v| v.is_param).collect()
    }

    /// Get all local variables.
    pub fn locals(&self) -> Vec<&VarInfo> {
        self.vars.values().filter(|v| v.is_local).collect()
    }

    /// Update variable type.
    pub fn set_type(&mut self, var: &SSAVar, ty: CType) {
        if let Some(info) = self.vars.get_mut(var) {
            info.ty = ty;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_param_name() {
        let mut vr = VariableRecovery::new("rsp", "rbp", 64);

        let var_rdi = SSAVar::new("reg:rdi", 0, 64);
        assert_eq!(vr.gen_param_name(&var_rdi), "arg1");

        let var_rsi = SSAVar::new("reg:rsi", 0, 64);
        assert_eq!(vr.gen_param_name(&var_rsi), "arg2");
    }

    #[test]
    fn test_gen_var_name() {
        let mut vr = VariableRecovery::new("rsp", "rbp", 64);

        let var1 = SSAVar::new("reg:0", 1, 64);
        let name1 = vr.gen_var_name(&var1);

        let var2 = SSAVar::new("reg:8", 1, 64);
        let name2 = vr.gen_var_name(&var2);

        assert_ne!(name1, name2);
    }

    #[test]
    fn test_stack_var_name() {
        let mut vr = VariableRecovery::new("rsp", "rbp", 64);

        let name = vr.gen_stack_var_name(8);
        assert_eq!(name, "local_8");

        let name = vr.gen_stack_var_name(-8);
        assert_eq!(name, "arg_8");
    }
}
