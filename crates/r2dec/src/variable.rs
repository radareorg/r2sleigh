//! Variable naming and recovery.
//!
//! This module handles variable naming, stack variable recovery,
//! and parameter detection.

use std::collections::{HashMap, HashSet};

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
    /// Used parameter names (to avoid duplicates).
    used_param_names: HashSet<String>,
    /// Used local variable names (to avoid duplicates).
    used_local_names: HashSet<String>,
    /// Used general variable names (to avoid duplicates).
    used_var_names: HashSet<String>,
    /// Stack pointer register name.
    sp_name: String,
    /// Frame pointer register name.
    fp_name: String,
    /// Pointer size in bits (reserved for architecture-aware type sizing).
    #[allow(dead_code)]
    ptr_size: u32,
    /// Loop variable counter (i, j, k, ...).
    loop_var_idx: usize,
    /// Return value register name.
    ret_reg: String,
}

impl VariableRecovery {
    /// Create a new variable recovery context.
    pub fn new(sp_name: &str, fp_name: &str, ptr_size: u32) -> Self {
        // Determine return register based on architecture
        let ret_reg = if ptr_size == 64 {
            "rax".to_string()
        } else {
            "eax".to_string()
        };

        Self {
            vars: HashMap::new(),
            name_counters: HashMap::new(),
            used_param_names: HashSet::new(),
            used_local_names: HashSet::new(),
            used_var_names: HashSet::new(),
            sp_name: sp_name.to_string(),
            fp_name: fp_name.to_string(),
            ptr_size,
            loop_var_idx: 0,
            ret_reg,
        }
    }

    /// Recover variables from an SSA function.
    pub fn recover(&mut self, func: &SSAFunction) {
        // First pass: identify stack variables
        self.find_stack_variables(func);

        // Second pass: identify parameters
        self.find_parameters(func);

        // Third pass: identify special variables (return values, loop counters)
        self.find_special_variables(func);

        // Fourth pass: name remaining variables
        self.name_remaining(func);
    }

    /// Find special variables like return values and loop counters.
    fn find_special_variables(&mut self, func: &SSAFunction) {
        // Find potential loop counters (variables incremented in a block)
        let mut increment_vars: HashSet<String> = HashSet::new();

        for block in func.blocks() {
            for op in &block.ops {
                // Look for patterns like: x = x + 1
                if let SSAOp::IntAdd { dst, a, b } = op {
                    // Check if adding a constant 1
                    if b.is_const() && b.name.contains("1") {
                        // Check if dst is a new version of a
                        let dst_base = dst.name.split('_').next().unwrap_or(&dst.name);
                        let a_base = a.name.split('_').next().unwrap_or(&a.name);
                        if dst_base == a_base {
                            increment_vars.insert(dst_base.to_lowercase());
                        }
                    }
                }
            }
        }

        // Name loop counters
        for block in func.blocks() {
            for op in &block.ops {
                if let Some(dst) = op.dst() {
                    if self.vars.contains_key(&dst) {
                        continue;
                    }

                    let base = dst
                        .name
                        .split('_')
                        .next()
                        .unwrap_or(&dst.name)
                        .to_lowercase();

                    // Check if this is a loop counter
                    if increment_vars.contains(&base) && dst.size == 32 {
                        let name = self.next_loop_var();
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

        // Find return values (last rax assignment before return)
        self.find_return_values(func);
    }

    /// Find return value variables.
    fn find_return_values(&mut self, func: &SSAFunction) {
        // Look for the last assignment to the return register in each exit block
        for block in func.blocks() {
            let mut last_ret_var: Option<SSAVar> = None;
            let mut has_return = false;

            for op in &block.ops {
                // Check if this block ends with a branch (could be a return)
                // Returns typically load RIP from stack and branch indirectly
                if let SSAOp::Branch { .. } | SSAOp::BranchInd { .. } = op {
                    has_return = true;
                }

                // Track last assignment to return register
                if let Some(dst) = op.dst() {
                    let name_lower = dst.name.to_lowercase();
                    if name_lower.contains(&self.ret_reg)
                        || name_lower.contains("eax")
                        || name_lower.contains("rax")
                    {
                        last_ret_var = Some(dst.clone());
                    }
                }
            }

            // If this block has a return and we found a return register assignment
            if has_return {
                if let Some(ret_var) = last_ret_var {
                    if !self.vars.contains_key(&ret_var) {
                        let name = self.make_unique_var_name("result".to_string());
                        let ty = self.type_from_size(ret_var.size);
                        self.vars.insert(
                            ret_var.clone(),
                            VarInfo {
                                ssa_var: ret_var,
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

    /// Get the next loop variable name (i, j, k, l, m, n, then idx1, idx2, ...).
    fn next_loop_var(&mut self) -> String {
        const LOOP_VARS: [&str; 6] = ["i", "j", "k", "l", "m", "n"];

        let name = if self.loop_var_idx < LOOP_VARS.len() {
            LOOP_VARS[self.loop_var_idx].to_string()
        } else {
            format!("idx{}", self.loop_var_idx - LOOP_VARS.len() + 1)
        };

        self.loop_var_idx += 1;
        self.make_unique_var_name(name)
    }

    /// Make a variable name unique.
    fn make_unique_var_name(&mut self, base_name: String) -> String {
        if !self.used_var_names.contains(&base_name) {
            self.used_var_names.insert(base_name.clone());
            return base_name;
        }

        let mut counter = 2;
        loop {
            let candidate = format!("{}_{}", base_name, counter);
            if !self.used_var_names.contains(&candidate) {
                self.used_var_names.insert(candidate.clone());
                return candidate;
            }
            counter += 1;
        }
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
        let base_name = if offset >= 0 {
            format!("local_{:x}", offset)
        } else {
            format!("arg_{:x}", -offset)
        };

        // Ensure uniqueness
        if !self.used_local_names.contains(&base_name) {
            self.used_local_names.insert(base_name.clone());
            return base_name;
        }

        // Find a unique suffix
        let mut counter = 2;
        loop {
            let candidate = format!("{}_{}", base_name, counter);
            if !self.used_local_names.contains(&candidate) {
                self.used_local_names.insert(candidate.clone());
                return candidate;
            }
            counter += 1;
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
        let base_name = if name.contains("rdi") || name.contains("edi") {
            "arg1".to_string()
        } else if name.contains("rsi") || name.contains("esi") {
            "arg2".to_string()
        } else if name.contains("rdx") || name.contains("edx") {
            "arg3".to_string()
        } else if name.contains("rcx") || name.contains("ecx") {
            "arg4".to_string()
        } else if name.contains("r8") {
            "arg5".to_string()
        } else if name.contains("r9") {
            "arg6".to_string()
        // ARM calling convention
        } else if name.contains("r0") || name.contains("x0") {
            "arg1".to_string()
        } else if name.contains("r1") || name.contains("x1") {
            "arg2".to_string()
        } else if name.contains("r2") || name.contains("x2") {
            "arg3".to_string()
        } else if name.contains("r3") || name.contains("x3") {
            "arg4".to_string()
        } else {
            // Generic parameter name
            let count = self.name_counters.entry("arg".to_string()).or_insert(0);
            *count += 1;
            format!("arg{}", count)
        };

        // Ensure uniqueness
        self.make_unique_param_name(base_name)
    }

    /// Make a parameter name unique by adding a suffix if needed.
    fn make_unique_param_name(&mut self, base_name: String) -> String {
        if !self.used_param_names.contains(&base_name) {
            self.used_param_names.insert(base_name.clone());
            return base_name;
        }

        // Find a unique suffix
        let mut counter = 2;
        loop {
            let candidate = format!("{}_{}", base_name, counter);
            if !self.used_param_names.contains(&candidate) {
                self.used_param_names.insert(candidate.clone());
                return candidate;
            }
            counter += 1;
        }
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
