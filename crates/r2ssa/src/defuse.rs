//! Def-use chain analysis for SSA blocks.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::SSABlock;
use crate::var::SSAVar;

/// Information about where a variable is defined and used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefUseInfo {
    /// Presentation-only map from displayed variable names to definition sites.
    ///
    /// A displayed name that identifies multiple exact variables is retained
    /// with no definition instead of selecting one of them as authoritative.
    pub definitions: HashMap<String, Option<usize>>,

    /// Presentation-only map from displayed variable names to use sites.
    pub uses: HashMap<String, Vec<usize>>,

    /// Presentation names of variables that are inputs.
    pub inputs: HashSet<String>,

    /// Presentation names of variables that are outputs.
    pub outputs: HashSet<String>,

    /// Presentation names of variables that are live.
    pub live: HashSet<String>,

    /// Exact semantic def-use state. These fields are rebuilt by [`def_use`]
    /// and intentionally excluded from the legacy presentation serialization.
    #[serde(skip)]
    exact_definitions: HashMap<SSAVar, Option<usize>>,
    #[serde(skip)]
    exact_uses: HashMap<SSAVar, Vec<usize>>,
    #[serde(skip)]
    exact_inputs: HashSet<SSAVar>,
    #[serde(skip)]
    exact_outputs: HashSet<SSAVar>,
    #[serde(skip)]
    exact_live: HashSet<SSAVar>,
}

impl DefUseInfo {
    /// Create a new empty def-use info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the definition site of a variable.
    pub fn get_def(&self, var: &SSAVar) -> Option<usize> {
        self.exact_definitions.get(var).copied().flatten()
    }

    /// Get all use sites of a variable.
    pub fn get_uses(&self, var: &SSAVar) -> &[usize] {
        self.exact_uses
            .get(var)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if a variable is an input to this block.
    pub fn is_input(&self, var: &SSAVar) -> bool {
        self.exact_inputs.contains(var)
    }

    /// Check if a variable is an output from this block.
    pub fn is_output(&self, var: &SSAVar) -> bool {
        self.exact_outputs.contains(var)
    }

    /// Check if a variable is live (both defined and used).
    pub fn is_live(&self, var: &SSAVar) -> bool {
        self.exact_live.contains(var)
    }

    /// Get all input variable names.
    pub fn input_vars(&self) -> impl Iterator<Item = &str> {
        self.inputs.iter().map(|s| s.as_str())
    }

    /// Get all output variable names.
    pub fn output_vars(&self) -> impl Iterator<Item = &str> {
        self.outputs.iter().map(|s| s.as_str())
    }

    fn rebuild_presentation(&mut self) {
        self.definitions.clear();
        self.uses.clear();
        self.inputs.clear();
        self.outputs.clear();
        self.live.clear();

        for (var, definition) in &self.exact_definitions {
            self.definitions
                .entry(var.display_name())
                .and_modify(|existing| {
                    if *existing != *definition {
                        *existing = None;
                    }
                })
                .or_insert(*definition);
        }
        for (var, uses) in &self.exact_uses {
            let displayed_uses = self.uses.entry(var.display_name()).or_default();
            displayed_uses.extend(uses);
            displayed_uses.sort_unstable();
            displayed_uses.dedup();
        }
        self.inputs
            .extend(self.exact_inputs.iter().map(SSAVar::display_name));
        self.outputs
            .extend(self.exact_outputs.iter().map(SSAVar::display_name));
        self.live
            .extend(self.exact_live.iter().map(SSAVar::display_name));
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
            info.exact_definitions.insert(dst.clone(), Some(idx));
        }
    }

    // Second pass: record all uses
    for (idx, op) in block.ops.iter().enumerate() {
        for src in op.sources() {
            info.exact_uses.entry(src.clone()).or_default().push(idx);
        }
    }

    // Identify inputs: variables that are used but not defined
    for var in info.exact_uses.keys() {
        if !info.exact_definitions.contains_key(var) {
            info.exact_inputs.insert(var.clone());
            // Also record that this variable has no definition
            info.exact_definitions.insert(var.clone(), None);
        }
    }

    // Identify outputs: variables that are defined but not used
    for (var, def) in &info.exact_definitions {
        if def.is_some() && !info.exact_uses.contains_key(var) {
            info.exact_outputs.insert(var.clone());
        }
    }

    // Identify live variables: defined and used
    for (var, def) in &info.exact_definitions {
        if def.is_some() && info.exact_uses.contains_key(var) {
            info.exact_live.insert(var.clone());
        }
    }

    info.rebuild_presentation();

    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::SSAOp;

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
            a: rax_0,
            b: SSAVar::constant(1, 8),
        });

        // RAX_2 = RAX_1 + RBX_0
        block.push(SSAOp::IntAdd {
            dst: rax_2.clone(),
            a: rax_1.clone(),
            b: rbx_0,
        });

        let info = def_use(&block);

        // RAX_1 is live (defined at 0, used at 1)
        assert!(info.is_live(&rax_1));
        assert_eq!(info.get_def(&rax_1), Some(0));
        assert_eq!(info.get_uses(&rax_1), &[1]);

        // RAX_2 is output (defined but not used)
        assert!(info.is_output(&rax_2));
    }
}
