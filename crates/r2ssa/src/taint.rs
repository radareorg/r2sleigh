//! Taint analysis built on SSA def-use chains.
//!
//! Tracks data flow from taint sources to sinks through the SSA graph.
//!
//! # Example
//!
//! ```ignore
//! use r2ssa::{SSAFunction, TaintAnalysis, DefaultTaintPolicy};
//!
//! let func = SSAFunction::from_blocks(&blocks).unwrap();
//! let policy = DefaultTaintPolicy::all_inputs();
//! let analysis = TaintAnalysis::new(&func, policy);
//! let result = analysis.analyze();
//!
//! for hit in &result.sink_hits {
//!     println!("Taint reaches sink at 0x{:x}", hit.block_addr);
//! }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::function::{SSAFunction, UseLocation};
use crate::op::SSAOp;
use crate::var::SSAVar;

/// A label identifying a taint source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Unique identifier for this taint source.
    pub id: String,
    /// Human-readable description.
    pub description: Option<String>,
}

impl TaintLabel {
    /// Create a new taint label with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: None,
        }
    }

    /// Add a description to this label.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Taint state for a single variable: set of labels that taint it.
pub type TaintSet = HashSet<TaintLabel>;

/// Policy for defining taint sources, sinks, and sanitizers.
///
/// Implement this trait to customize taint analysis behavior.
pub trait TaintPolicy {
    /// Check if a variable is a taint source. Returns labels if so.
    fn is_source(&self, var: &SSAVar, block_addr: u64) -> Option<Vec<TaintLabel>>;

    /// Check if an operation is a taint sink.
    fn is_sink(&self, op: &SSAOp, block_addr: u64) -> bool;

    /// Check if an operation sanitizes (clears) taint from its output.
    /// Default: no sanitizers.
    fn is_sanitizer(&self, _op: &SSAOp) -> bool {
        false
    }

    /// Custom propagation rule. By default, taint flows from all sources to dst.
    /// Return None to use default (union of source taints).
    fn propagate(&self, _op: &SSAOp, _source_taints: &[&TaintSet]) -> Option<TaintSet> {
        None
    }
}

/// Default policy: function inputs (version 0 registers) are sources.
#[derive(Debug, Clone, Default)]
pub struct DefaultTaintPolicy {
    /// Variable names to treat as sources. If empty, all version-0 registers are sources.
    pub sources: HashSet<String>,
    /// Whether calls are sinks.
    pub sink_calls: bool,
    /// Whether stores are sinks.
    pub sink_stores: bool,
}

impl DefaultTaintPolicy {
    /// Create a new default policy.
    pub fn new() -> Self {
        Self {
            sources: HashSet::new(),
            sink_calls: true,
            sink_stores: true,
        }
    }

    /// Add a specific variable name as a source.
    pub fn with_source(mut self, name: impl Into<String>) -> Self {
        self.sources.insert(name.into());
        self
    }

    /// Mark all function inputs (version 0 non-const, non-temp) as sources.
    pub fn all_inputs() -> Self {
        Self {
            sources: HashSet::new(), // Empty means all inputs
            sink_calls: true,
            sink_stores: true,
        }
    }

    /// Configure whether calls are sinks.
    pub fn with_sink_calls(mut self, enabled: bool) -> Self {
        self.sink_calls = enabled;
        self
    }

    /// Configure whether stores are sinks.
    pub fn with_sink_stores(mut self, enabled: bool) -> Self {
        self.sink_stores = enabled;
        self
    }
}

impl TaintPolicy for DefaultTaintPolicy {
    fn is_source(&self, var: &SSAVar, _block_addr: u64) -> Option<Vec<TaintLabel>> {
        // Version 0 variables that are registers (not const/temp) are inputs
        if var.version == 0 && var.is_register() {
            if self.sources.is_empty() || self.sources.contains(&var.name) {
                return Some(vec![TaintLabel::new(format!("input:{}", var.name))]);
            }
        }
        None
    }

    fn is_sink(&self, op: &SSAOp, _block_addr: u64) -> bool {
        match op {
            SSAOp::Call { .. } | SSAOp::CallInd { .. } if self.sink_calls => true,
            SSAOp::Store { .. } if self.sink_stores => true,
            _ => false,
        }
    }
}

/// A taint reaching a sink.
#[derive(Debug, Clone)]
pub struct SinkHit {
    /// Block address where the sink is located.
    pub block_addr: u64,
    /// Operation index within the block.
    pub op_idx: usize,
    /// The sink operation.
    pub op: SSAOp,
    /// Variables that are tainted at this sink, with their taint labels.
    pub tainted_vars: Vec<(SSAVar, TaintSet)>,
}

/// Result of taint analysis.
#[derive(Debug, Clone, Default)]
pub struct TaintResult {
    /// Taint state for each variable (by display_name).
    pub var_taints: HashMap<String, TaintSet>,
    /// Sink violations: operations where tainted data reaches a sink.
    pub sink_hits: Vec<SinkHit>,
}

impl TaintResult {
    /// Check if a variable is tainted.
    pub fn is_tainted(&self, var: &SSAVar) -> bool {
        self.var_taints
            .get(&var.display_name())
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    }

    /// Get taint labels for a variable.
    pub fn get_taint(&self, var: &SSAVar) -> Option<&TaintSet> {
        self.var_taints.get(&var.display_name())
    }

    /// Check if any sinks were hit by tainted data.
    pub fn has_violations(&self) -> bool {
        !self.sink_hits.is_empty()
    }

    /// Get the number of tainted variables.
    pub fn num_tainted(&self) -> usize {
        self.var_taints.values().filter(|t| !t.is_empty()).count()
    }

    /// Get all tainted variable names.
    pub fn tainted_vars(&self) -> impl Iterator<Item = &str> {
        self.var_taints
            .iter()
            .filter(|(_, t)| !t.is_empty())
            .map(|(name, _)| name.as_str())
    }
}

/// Taint analysis engine.
///
/// Performs forward taint propagation through SSA def-use chains.
pub struct TaintAnalysis<'a, P: TaintPolicy> {
    func: &'a SSAFunction,
    policy: P,
}

impl<'a, P: TaintPolicy> TaintAnalysis<'a, P> {
    /// Create a new taint analysis for the given function.
    pub fn new(func: &'a SSAFunction, policy: P) -> Self {
        Self { func, policy }
    }

    /// Run forward taint propagation.
    ///
    /// Returns a `TaintResult` containing the taint state for all variables
    /// and any sink violations found.
    pub fn analyze(&self) -> TaintResult {
        let mut var_taints: HashMap<String, TaintSet> = HashMap::new();
        let mut worklist: VecDeque<SSAVar> = VecDeque::new();

        // Phase 1: Initialize sources
        self.initialize_sources(&mut var_taints, &mut worklist);

        // Phase 2: Forward propagation via worklist
        self.propagate(&mut var_taints, &mut worklist);

        // Phase 3: Find sink hits
        let sink_hits = self.find_sink_hits(&var_taints);

        TaintResult {
            var_taints,
            sink_hits,
        }
    }

    /// Initialize taint sources.
    fn initialize_sources(
        &self,
        var_taints: &mut HashMap<String, TaintSet>,
        worklist: &mut VecDeque<SSAVar>,
    ) {
        for block in self.func.blocks() {
            // Check phi sources
            for phi in &block.phis {
                for (_, src) in &phi.sources {
                    self.maybe_add_source(src, block.addr, var_taints, worklist);
                }
            }

            // Check op sources
            for op in &block.ops {
                for src in op.sources() {
                    self.maybe_add_source(src, block.addr, var_taints, worklist);
                }
            }
        }
    }

    /// Check if a variable is a source and add it to the taint state.
    fn maybe_add_source(
        &self,
        var: &SSAVar,
        block_addr: u64,
        var_taints: &mut HashMap<String, TaintSet>,
        worklist: &mut VecDeque<SSAVar>,
    ) {
        if let Some(labels) = self.policy.is_source(var, block_addr) {
            let key = var.display_name();
            let taint = var_taints.entry(key).or_default();
            let old_size = taint.len();
            taint.extend(labels);
            if taint.len() > old_size {
                worklist.push_back(var.clone());
            }
        }
    }

    /// Forward propagation via worklist algorithm.
    ///
    /// Uses taint-state tracking instead of a simple visited set to ensure
    /// all labels are propagated even when a variable is reached via multiple paths.
    fn propagate(
        &self,
        var_taints: &mut HashMap<String, TaintSet>,
        worklist: &mut VecDeque<SSAVar>,
    ) {
        // Track the taint state we've already propagated for each variable.
        // This allows re-propagation when new labels are added.
        let mut propagated: HashMap<String, TaintSet> = HashMap::new();

        while let Some(var) = worklist.pop_front() {
            let key = var.display_name();

            let current_taint = match var_taints.get(&key) {
                Some(t) if !t.is_empty() => t.clone(),
                _ => continue,
            };

            // Check if we have new labels to propagate
            let already_propagated = propagated.entry(key.clone()).or_default();
            let new_labels: TaintSet = current_taint
                .difference(already_propagated)
                .cloned()
                .collect();

            if new_labels.is_empty() {
                continue;
            }

            // Mark these labels as propagated
            already_propagated.extend(new_labels.clone());

            // Find all uses of this variable
            let uses = self.func.find_uses(&var);
            for (block_addr, use_loc) in uses {
                match use_loc {
                    UseLocation::Phi { phi_idx, .. } => {
                        self.propagate_to_phi(
                            block_addr,
                            phi_idx,
                            &new_labels,
                            var_taints,
                            worklist,
                        );
                    }
                    UseLocation::Op { op_idx, .. } => {
                        self.propagate_to_op(
                            block_addr,
                            op_idx,
                            &new_labels,
                            var_taints,
                            worklist,
                        );
                    }
                }
            }
        }
    }

    /// Propagate taint through a phi node.
    fn propagate_to_phi(
        &self,
        block_addr: u64,
        phi_idx: usize,
        current_taint: &TaintSet,
        var_taints: &mut HashMap<String, TaintSet>,
        worklist: &mut VecDeque<SSAVar>,
    ) {
        if let Some(block) = self.func.get_block(block_addr) {
            if let Some(phi) = block.phis.get(phi_idx) {
                let dst_key = phi.dst.display_name();
                let dst_taint = var_taints.entry(dst_key).or_default();
                let old_size = dst_taint.len();
                dst_taint.extend(current_taint.clone());
                if dst_taint.len() > old_size {
                    worklist.push_back(phi.dst.clone());
                }
            }
        }
    }

    /// Propagate taint through an operation.
    fn propagate_to_op(
        &self,
        block_addr: u64,
        op_idx: usize,
        current_taint: &TaintSet,
        var_taints: &mut HashMap<String, TaintSet>,
        worklist: &mut VecDeque<SSAVar>,
    ) {
        if let Some(block) = self.func.get_block(block_addr) {
            if let Some(op) = block.ops.get(op_idx) {
                // Check sanitizer
                if self.policy.is_sanitizer(op) {
                    return;
                }

                // Propagate to destination
                if let Some(dst) = op.dst() {
                    // Collect all source taints for custom propagation
                    let source_taints: Vec<&TaintSet> = op
                        .sources()
                        .iter()
                        .filter_map(|src| var_taints.get(&src.display_name()))
                        .collect();

                    // Try custom propagation rule first
                    let new_taint = if let Some(custom) =
                        self.policy.propagate(op, &source_taints)
                    {
                        custom
                    } else {
                        // Default: union of incoming taint
                        current_taint.clone()
                    };

                    let dst_key = dst.display_name();
                    let dst_taint = var_taints.entry(dst_key).or_default();
                    let old_size = dst_taint.len();
                    dst_taint.extend(new_taint);
                    if dst_taint.len() > old_size {
                        worklist.push_back(dst.clone());
                    }
                }
            }
        }
    }

    /// Find all sink hits.
    fn find_sink_hits(&self, var_taints: &HashMap<String, TaintSet>) -> Vec<SinkHit> {
        let mut sink_hits = Vec::new();

        for block in self.func.blocks() {
            for (op_idx, op) in block.ops.iter().enumerate() {
                if self.policy.is_sink(op, block.addr) {
                    let mut tainted_vars = Vec::new();
                    for src in op.sources() {
                        let key = src.display_name();
                        if let Some(taint) = var_taints.get(&key) {
                            if !taint.is_empty() {
                                tainted_vars.push((src.clone(), taint.clone()));
                            }
                        }
                    }
                    if !tainted_vars.is_empty() {
                        sink_hits.push(SinkHit {
                            block_addr: block.addr,
                            op_idx,
                            op: op.clone(),
                            tainted_vars,
                        });
                    }
                }
            }
        }

        sink_hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_var(name: &str, version: u32) -> SSAVar {
        SSAVar::new(name, version, 8)
    }

    #[test]
    fn test_taint_label() {
        let label = TaintLabel::new("user_input").with_description("From stdin");
        assert_eq!(label.id, "user_input");
        assert_eq!(label.description, Some("From stdin".to_string()));
    }

    #[test]
    fn test_taint_label_equality() {
        let l1 = TaintLabel::new("src1");
        let l2 = TaintLabel::new("src1");
        let l3 = TaintLabel::new("src2");

        assert_eq!(l1, l2);
        assert_ne!(l1, l3);
    }

    #[test]
    fn test_default_policy_source_all_inputs() {
        let policy = DefaultTaintPolicy::all_inputs();

        // Version 0 register is a source
        let reg = make_var("RAX", 0);
        assert!(policy.is_source(&reg, 0x1000).is_some());

        // Version 1 is not a source (already defined)
        let reg_v1 = make_var("RAX", 1);
        assert!(policy.is_source(&reg_v1, 0x1000).is_none());

        // Const is not a source
        let cst = make_var("const:42", 0);
        assert!(policy.is_source(&cst, 0x1000).is_none());

        // Temp is not a source
        let tmp = make_var("tmp:0x1000", 0);
        assert!(policy.is_source(&tmp, 0x1000).is_none());
    }

    #[test]
    fn test_default_policy_source_specific() {
        let policy = DefaultTaintPolicy::new().with_source("RDI").with_source("RSI");

        // RDI v0 is a source
        let rdi = make_var("RDI", 0);
        assert!(policy.is_source(&rdi, 0x1000).is_some());

        // RSI v0 is a source
        let rsi = make_var("RSI", 0);
        assert!(policy.is_source(&rsi, 0x1000).is_some());

        // RAX v0 is NOT a source (not in list)
        let rax = make_var("RAX", 0);
        assert!(policy.is_source(&rax, 0x1000).is_none());
    }

    #[test]
    fn test_default_policy_sink() {
        let policy = DefaultTaintPolicy::new();

        let call_op = SSAOp::Call {
            target: make_var("const:0x1000", 0),
        };
        assert!(policy.is_sink(&call_op, 0));

        let call_ind_op = SSAOp::CallInd {
            target: make_var("RAX", 1),
        };
        assert!(policy.is_sink(&call_ind_op, 0));

        let store_op = SSAOp::Store {
            space: "ram".to_string(),
            addr: make_var("RAX", 1),
            val: make_var("RBX", 0),
        };
        assert!(policy.is_sink(&store_op, 0));

        let add_op = SSAOp::IntAdd {
            dst: make_var("RAX", 2),
            a: make_var("RAX", 1),
            b: make_var("RBX", 0),
        };
        assert!(!policy.is_sink(&add_op, 0));
    }

    #[test]
    fn test_default_policy_sink_disabled() {
        let policy = DefaultTaintPolicy::new()
            .with_sink_calls(false)
            .with_sink_stores(false);

        let call_op = SSAOp::Call {
            target: make_var("const:0x1000", 0),
        };
        assert!(!policy.is_sink(&call_op, 0));

        let store_op = SSAOp::Store {
            space: "ram".to_string(),
            addr: make_var("RAX", 1),
            val: make_var("RBX", 0),
        };
        assert!(!policy.is_sink(&store_op, 0));
    }

    #[test]
    fn test_taint_result_empty() {
        let result = TaintResult::default();
        assert!(!result.has_violations());
        assert_eq!(result.num_tainted(), 0);

        let var = make_var("RAX", 0);
        assert!(!result.is_tainted(&var));
        assert!(result.get_taint(&var).is_none());
    }

    #[test]
    fn test_taint_result_with_data() {
        let mut result = TaintResult::default();

        let var = make_var("RAX", 1);
        let mut taint = TaintSet::new();
        taint.insert(TaintLabel::new("input:RDI"));
        result.var_taints.insert(var.display_name(), taint);

        assert!(result.is_tainted(&var));
        assert_eq!(result.num_tainted(), 1);

        let taint_labels = result.get_taint(&var).unwrap();
        assert!(taint_labels.contains(&TaintLabel::new("input:RDI")));
    }

    #[test]
    fn test_taint_set_operations() {
        let mut set = TaintSet::new();
        set.insert(TaintLabel::new("src1"));
        set.insert(TaintLabel::new("src2"));

        assert_eq!(set.len(), 2);
        assert!(set.contains(&TaintLabel::new("src1")));
        assert!(set.contains(&TaintLabel::new("src2")));
        assert!(!set.contains(&TaintLabel::new("src3")));
    }

    // Custom policy for testing
    struct TestPolicy {
        source_var: String,
    }

    impl TaintPolicy for TestPolicy {
        fn is_source(&self, var: &SSAVar, _block_addr: u64) -> Option<Vec<TaintLabel>> {
            if var.name == self.source_var && var.version == 0 {
                Some(vec![TaintLabel::new("test_source")])
            } else {
                None
            }
        }

        fn is_sink(&self, op: &SSAOp, _block_addr: u64) -> bool {
            matches!(op, SSAOp::Store { .. })
        }

        fn is_sanitizer(&self, op: &SSAOp) -> bool {
            // XOR with self is a sanitizer (common zeroing pattern)
            if let SSAOp::IntXor { a, b, .. } = op {
                a == b
            } else {
                false
            }
        }
    }

    #[test]
    fn test_custom_policy() {
        let policy = TestPolicy {
            source_var: "user_data".to_string(),
        };

        let src = SSAVar::new("user_data", 0, 8);
        assert!(policy.is_source(&src, 0).is_some());

        let other = SSAVar::new("RAX", 0, 8);
        assert!(policy.is_source(&other, 0).is_none());

        let store = SSAOp::Store {
            space: "ram".to_string(),
            addr: SSAVar::new("RAX", 1, 8),
            val: SSAVar::new("RBX", 0, 8),
        };
        assert!(policy.is_sink(&store, 0));

        let call = SSAOp::Call {
            target: SSAVar::new("const:0x1000", 0, 8),
        };
        assert!(!policy.is_sink(&call, 0));

        // XOR RAX, RAX is a sanitizer
        let xor_self = SSAOp::IntXor {
            dst: SSAVar::new("RAX", 2, 8),
            a: SSAVar::new("RAX", 1, 8),
            b: SSAVar::new("RAX", 1, 8),
        };
        assert!(policy.is_sanitizer(&xor_self));

        // XOR RAX, RBX is not a sanitizer
        let xor_other = SSAOp::IntXor {
            dst: SSAVar::new("RAX", 2, 8),
            a: SSAVar::new("RAX", 1, 8),
            b: SSAVar::new("RBX", 0, 8),
        };
        assert!(!policy.is_sanitizer(&xor_other));
    }
}
