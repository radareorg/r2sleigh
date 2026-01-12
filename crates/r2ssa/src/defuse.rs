//! Def-use chain analysis for SSA blocks.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::op::SSAOp;
use crate::var::SSAVar;
use crate::SSABlock;

/// Information about where a variable is defined and used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefUseInfo {
    /// Maps each variable (name_version) to the operation index that defines it.
    /// A variable with version 0 has no definition (it's an input).
    pub definitions: HashMap<String, Option<usize>>,

    /// Maps each variable (name_version) to the operation indices that use it.
    pub uses: HashMap<String, Vec<usize>>,

    /// Variables that are inputs (used but never defined in this block).
    pub inputs: HashSet<String>,

    /// Variables that are outputs (defined but never used in this block).
    pub outputs: HashSet<String>,

    /// Variables that are live (defined and used within this block).
    pub live: HashSet<String>,
}

impl DefUseInfo {
    /// Create a new empty def-use info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the definition site of a variable.
    pub fn get_def(&self, var: &SSAVar) -> Option<usize> {
        let key = var.display_name();
        self.definitions.get(&key).copied().flatten()
    }

    /// Get all use sites of a variable.
    pub fn get_uses(&self, var: &SSAVar) -> &[usize] {
        let key = var.display_name();
        self.uses.get(&key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Check if a variable is an input to this block.
    pub fn is_input(&self, var: &SSAVar) -> bool {
        self.inputs.contains(&var.display_name())
    }

    /// Check if a variable is an output from this block.
    pub fn is_output(&self, var: &SSAVar) -> bool {
        self.outputs.contains(&var.display_name())
    }

    /// Check if a variable is live (both defined and used).
    pub fn is_live(&self, var: &SSAVar) -> bool {
        self.live.contains(&var.display_name())
    }

    /// Get all input variable names.
    pub fn input_vars(&self) -> impl Iterator<Item = &str> {
        self.inputs.iter().map(|s| s.as_str())
    }

    /// Get all output variable names.
    pub fn output_vars(&self) -> impl Iterator<Item = &str> {
        self.outputs.iter().map(|s| s.as_str())
    }
}

/// Compute def-use chains for an SSA block.
///
/// This analyzes which operations define and use each variable,
/// and identifies inputs (used but not defined) and outputs
/// (defined but not used).
pub fn def_use(block: &SSABlock) -> DefUseInfo {
    let mut info = DefUseInfo::new();

    // First pass: record all definitions
    for (idx, op) in block.ops.iter().enumerate() {
        if let Some(dst) = op.dst() {
            let key = dst.display_name();
            info.definitions.insert(key, Some(idx));
        }
    }

    // Second pass: record all uses
    for (idx, op) in block.ops.iter().enumerate() {
        for src in op.sources() {
            let key = src.display_name();
            info.uses.entry(key).or_default().push(idx);
        }
    }

    // Identify inputs: variables that are used but not defined
    for (var_name, _uses) in &info.uses {
        if !info.definitions.contains_key(var_name) {
            info.inputs.insert(var_name.clone());
            // Also record that this variable has no definition
            info.definitions.insert(var_name.clone(), None);
        }
    }

    // Identify outputs: variables that are defined but not used
    for (var_name, def) in &info.definitions {
        if def.is_some() && !info.uses.contains_key(var_name) {
            info.outputs.insert(var_name.clone());
        }
    }

    // Identify live variables: defined and used
    for (var_name, def) in &info.definitions {
        if def.is_some() && info.uses.contains_key(var_name) {
            info.live.insert(var_name.clone());
        }
    }

    info
}

/// Dead code analysis: find operations whose results are never used.
pub fn dead_ops(block: &SSABlock) -> Vec<usize> {
    let info = def_use(block);
    let mut dead = Vec::new();

    for (idx, op) in block.ops.iter().enumerate() {
        // Skip operations with side effects
        if op.is_control_flow() || op.is_memory_write() {
            continue;
        }

        // Check if this operation's output is used
        if let Some(dst) = op.dst() {
            let key = dst.display_name();
            if !info.uses.contains_key(&key) {
                dead.push(idx);
            }
        }
    }

    dead
}

/// Constant propagation info: find operations that define constants.
pub fn find_constants(block: &SSABlock) -> HashMap<String, u64> {
    let mut constants = HashMap::new();

    for op in &block.ops {
        if let SSAOp::Copy { dst, src } = op {
            // Check if source is a constant
            if src.is_const() {
                // Parse the constant value from the name (e.g., "const:0x42")
                if let Some(val_str) = src.name.strip_prefix("const:") {
                    if let Ok(val) = if val_str.starts_with("0x") {
                        u64::from_str_radix(&val_str[2..], 16)
                    } else {
                        val_str.parse()
                    } {
                        constants.insert(dst.display_name(), val);
                    }
                }
            }
        }
    }

    constants
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_var(name: &str, version: u32, size: u32) -> SSAVar {
        SSAVar::new(name, version, size)
    }

    #[test]
    fn test_def_use_simple() {
        let mut block = SSABlock::new(0x1000, 4);

        // RAX_0 is input, RAX_1 = RAX_0 + RBX_0
        let rax_0 = make_var("RAX", 0, 8);
        let rbx_0 = make_var("RBX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);

        block.push(SSAOp::IntAdd {
            dst: rax_1.clone(),
            a: rax_0.clone(),
            b: rbx_0.clone(),
        });

        let info = def_use(&block);

        // RAX_0 and RBX_0 are inputs (used but not defined)
        assert!(info.is_input(&rax_0));
        assert!(info.is_input(&rbx_0));

        // RAX_1 is output (defined but not used)
        assert!(info.is_output(&rax_1));

        // RAX_1 is defined at op 0
        assert_eq!(info.get_def(&rax_1), Some(0));

        // RAX_0 is used at op 0
        assert_eq!(info.get_uses(&rax_0), &[0]);
    }

    #[test]
    fn test_def_use_chain() {
        let mut block = SSABlock::new(0x1000, 8);

        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let rax_2 = make_var("RAX", 2, 8);
        let rbx_0 = make_var("RBX", 0, 8);

        // RAX_1 = RAX_0 + 1
        block.push(SSAOp::IntAdd {
            dst: rax_1.clone(),
            a: rax_0.clone(),
            b: make_var("const:1", 0, 8),
        });

        // RAX_2 = RAX_1 + RBX_0
        block.push(SSAOp::IntAdd {
            dst: rax_2.clone(),
            a: rax_1.clone(),
            b: rbx_0.clone(),
        });

        let info = def_use(&block);

        // RAX_1 is live (defined at 0, used at 1)
        assert!(info.is_live(&rax_1));
        assert_eq!(info.get_def(&rax_1), Some(0));
        assert_eq!(info.get_uses(&rax_1), &[1]);

        // RAX_2 is output (defined but not used)
        assert!(info.is_output(&rax_2));
    }

    #[test]
    fn test_dead_ops() {
        let mut block = SSABlock::new(0x1000, 8);

        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let rbx_1 = make_var("RBX", 1, 8);

        // RAX_1 = RAX_0 + 1 (used later)
        block.push(SSAOp::IntAdd {
            dst: rax_1.clone(),
            a: rax_0.clone(),
            b: make_var("const:1", 0, 8),
        });

        // RBX_1 = RAX_1 + 2 (not used - dead)
        block.push(SSAOp::IntAdd {
            dst: rbx_1,
            a: rax_1.clone(),
            b: make_var("const:2", 0, 8),
        });

        // Store RAX_1 (uses RAX_1, has side effect)
        block.push(SSAOp::Store {
            space: "ram".to_string(),
            addr: make_var("const:0x1000", 0, 8),
            val: rax_1,
        });

        let dead = dead_ops(&block);
        assert_eq!(dead, vec![1]); // Only op 1 is dead
    }

    #[test]
    fn test_find_constants() {
        let mut block = SSABlock::new(0x1000, 4);

        let rax_1 = make_var("RAX", 1, 8);
        let const_42 = make_var("const:0x42", 0, 8);

        block.push(SSAOp::Copy {
            dst: rax_1,
            src: const_42,
        });

        let constants = find_constants(&block);
        assert_eq!(constants.get("RAX_1"), Some(&0x42));
    }
}
