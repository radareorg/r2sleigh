//! Function-level SSA representation.
//!
//! This module provides the `SSAFunction` type which combines all SSA
//! components for a complete function: CFG, dominator tree, phi nodes,
//! and renamed operations.

use std::collections::HashMap;

use r2il::{ArchSpec, PointerHint, R2ILBlock, ScalarKind, StorageClass, Varnode, VarnodeMetadata};
use serde::{Deserialize, Serialize};

use crate::cfg::{CFG, CFGEdge};
use crate::defuse::{BackwardSlice, SliceOpRef, backward_slice_from_op, backward_slice_from_var};
use crate::domtree::DomTree;
use crate::naming::build_register_name_map;
use crate::op::SSAOp;
use crate::phi::{PhiPlacement, collect_defs_from_cfg_with_names};
use crate::rename::rename_function_with_names;
use crate::var::SSAVar;

/// Switch case information: Vec of (case_value, target_address) pairs and optional default target.
pub type SwitchInfo = (Vec<(u64, u64)>, Option<u64>);

/// A function in SSA form.
///
/// This is the main entry point for function-level SSA analysis.
/// It contains the CFG, dominator tree, and SSA operations for all blocks.
#[derive(Debug, Clone)]
pub struct SSAFunction {
    /// The function's name (if known).
    pub name: Option<String>,
    /// Entry point address.
    pub entry: u64,
    /// Control flow graph.
    cfg: CFG,
    /// Dominator tree.
    domtree: DomTree,
    /// SSA operations for each block.
    blocks: HashMap<u64, SSABlock>,
    /// Block addresses in reverse postorder.
    block_order: Vec<u64>,
    /// Semantic metadata hints keyed by canonical SSA base variable name.
    semantic_var_hints: HashMap<String, VarnodeMetadata>,
}

/// A basic block in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSABlock {
    /// Block address.
    pub addr: u64,
    /// Block size in bytes.
    pub size: u32,
    /// SSA operations in this block.
    pub ops: Vec<SSAOp>,
    /// Phi nodes at the start of this block.
    pub phis: Vec<PhiNode>,
}

/// A phi node in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiNode {
    /// The destination variable.
    pub dst: SSAVar,
    /// The source variables, one per predecessor.
    pub sources: Vec<(u64, SSAVar)>, // (predecessor addr, variable)
}

/// Location metadata for a source variable use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSite {
    /// Source from a phi node input.
    Phi {
        phi_idx: usize,
        src_idx: usize,
        pred_addr: u64,
    },
    /// Source from a regular SSA operation input.
    Op { op_idx: usize, src_idx: usize },
}

/// A source variable with its location metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRef<'a> {
    pub var: &'a SSAVar,
    pub site: SourceSite,
}

/// Location metadata for a destination variable definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefSite {
    /// Destination written by a phi node.
    Phi { phi_idx: usize },
    /// Destination written by a regular operation.
    Op { op_idx: usize },
}

/// A destination variable with its definition site metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefRef<'a> {
    pub var: &'a SSAVar,
    pub site: DefSite,
}

fn pointer_hint_rank(hint: PointerHint) -> u8 {
    match hint {
        PointerHint::Unknown => 0,
        PointerHint::PointerLike => 1,
        PointerHint::CodePointer => 2,
    }
}

fn scalar_kind_rank(kind: ScalarKind) -> u8 {
    match kind {
        ScalarKind::Unknown => 0,
        ScalarKind::Bitvector => 1,
        ScalarKind::Bool | ScalarKind::SignedInt | ScalarKind::UnsignedInt | ScalarKind::Float => 2,
    }
}

fn storage_class_rank(class: StorageClass) -> u8 {
    match class {
        StorageClass::Unknown => 0,
        StorageClass::Register => 1,
        StorageClass::Stack
        | StorageClass::Heap
        | StorageClass::Global
        | StorageClass::ThreadLocal
        | StorageClass::ConstData
        | StorageClass::Volatile => 2,
    }
}

fn merge_ranked_hint<T: Copy>(dst: &mut Option<T>, src: Option<T>, rank: impl Fn(T) -> u8) {
    let Some(src_val) = src else {
        return;
    };
    match *dst {
        Some(dst_val) if rank(dst_val) >= rank(src_val) => {}
        _ => *dst = Some(src_val),
    }
}

fn merge_varnode_metadata(dst: &mut VarnodeMetadata, src: &VarnodeMetadata) {
    merge_ranked_hint(
        &mut dst.storage_class,
        src.storage_class,
        storage_class_rank,
    );
    merge_ranked_hint(&mut dst.pointer_hint, src.pointer_hint, pointer_hint_rank);
    merge_ranked_hint(&mut dst.scalar_kind, src.scalar_kind, scalar_kind_rank);

    if dst.float_encoding.is_none() {
        dst.float_encoding = src.float_encoding;
    }
    if dst.endianness.is_none() {
        dst.endianness = src.endianness;
    }
    if dst.permissions.is_none() {
        dst.permissions = src.permissions;
    }
    if dst.valid_range.is_none() {
        dst.valid_range = src.valid_range;
    }
    if dst.bank_id.is_none() {
        dst.bank_id = src.bank_id.clone();
    }
    if dst.segment_id.is_none() {
        dst.segment_id = src.segment_id.clone();
    }
}

fn normalized_varnode_metadata(meta: &VarnodeMetadata) -> Option<VarnodeMetadata> {
    let mut out = meta.clone();
    if matches!(out.storage_class, Some(StorageClass::Unknown)) {
        out.storage_class = None;
    }
    if matches!(out.pointer_hint, Some(PointerHint::Unknown)) {
        out.pointer_hint = None;
    }
    if matches!(out.scalar_kind, Some(ScalarKind::Unknown)) {
        out.scalar_kind = None;
    }

    let has_hint = out.storage_class.is_some()
        || out.pointer_hint.is_some()
        || out.scalar_kind.is_some()
        || out.float_encoding.is_some()
        || out.endianness.is_some()
        || out.permissions.is_some()
        || out.valid_range.is_some()
        || out.bank_id.is_some()
        || out.segment_id.is_some();

    has_hint.then_some(out)
}

fn collect_semantic_var_hints(
    blocks: &[R2ILBlock],
    reg_names: Option<&crate::naming::RegisterNameMap>,
) -> HashMap<String, VarnodeMetadata> {
    let mut hints: HashMap<String, VarnodeMetadata> = HashMap::new();

    let mut collect_var = |vn: &Varnode| {
        let Some(meta) = vn.meta.as_ref() else {
            return;
        };
        let Some(meta) = normalized_varnode_metadata(meta) else {
            return;
        };
        let key = crate::naming::varnode_to_name(vn, reg_names).to_ascii_lowercase();
        hints
            .entry(key)
            .and_modify(|existing| merge_varnode_metadata(existing, &meta))
            .or_insert(meta);
    };

    for block in blocks {
        for op in &block.ops {
            if let Some(dst) = op.output() {
                collect_var(dst);
            }
            for src in op.inputs() {
                collect_var(src);
            }
        }
    }

    hints
}

impl SSAFunction {
    /// Build an SSA function from a sequence of r2il blocks.
    pub fn from_blocks(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_with_arch(blocks, None)
    }

    /// Build an SSA function from blocks with constructor-time SCCP enabled.
    pub fn from_blocks_with_arch(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        let mut func = Self::from_blocks_raw(blocks, arch)?;
        // Constructor path applies SCCP by default while keeping legacy SSA consumers stable.
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_const_prop: false,
            enable_inst_combine: false,
            enable_copy_prop: false,
            enable_cse: false,
            enable_dce: false,
            preserve_memory_reads: false,
        };
        func.optimize(&cfg);
        Some(func)
    }

    /// Build an SSA function from blocks without running optimization passes.
    ///
    /// This performs raw SSA construction:
    /// 1. Build CFG from blocks
    /// 2. Compute dominator tree
    /// 3. Place phi nodes
    /// 4. Rename variables
    pub fn from_blocks_raw(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        if blocks.is_empty() {
            return None;
        }

        // Build CFG
        let cfg = CFG::from_blocks(blocks)?;
        let entry = cfg.entry;

        // Compute dominator tree
        let domtree = DomTree::compute(&cfg);

        let reg_names = arch.map(build_register_name_map);
        let reg_names_ref = reg_names.as_ref();
        let semantic_var_hints = collect_semantic_var_hints(blocks, reg_names_ref);

        // Collect variable definitions and sizes
        let (defs, var_sizes) = collect_defs_from_cfg_with_names(&cfg, reg_names_ref);

        // Place phi nodes
        let phi_placement = PhiPlacement::compute(&cfg, &domtree, &defs, &var_sizes);

        // Rename variables
        let renamed =
            rename_function_with_names(&cfg, &domtree, &phi_placement, &var_sizes, reg_names_ref);

        // Build SSA blocks
        let mut ssa_blocks = HashMap::new();
        for &addr in &renamed.block_order {
            let cfg_block = cfg.get_block(addr)?;
            let ops = renamed.blocks.get(&addr).cloned().unwrap_or_default();

            // Separate phi nodes from other ops
            let (phi_ops, other_ops): (Vec<_>, Vec<_>) = ops
                .into_iter()
                .partition(|op| matches!(op, SSAOp::Phi { .. }));

            // Convert phi ops to PhiNode structs
            let preds = cfg.predecessors(addr);
            let phis: Vec<PhiNode> = phi_ops
                .into_iter()
                .filter_map(|op| {
                    if let SSAOp::Phi { dst, sources } = op {
                        let phi_sources: Vec<(u64, SSAVar)> = sources
                            .into_iter()
                            .zip(preds.iter())
                            .map(|(var, &pred)| (pred, var))
                            .collect();
                        Some(PhiNode {
                            dst,
                            sources: phi_sources,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let ssa_block = SSABlock {
                addr,
                size: cfg_block.size,
                ops: other_ops,
                phis,
            };
            ssa_blocks.insert(addr, ssa_block);
        }

        Some(Self {
            name: None,
            entry,
            cfg,
            domtree,
            blocks: ssa_blocks,
            block_order: renamed.block_order,
            semantic_var_hints,
        })
    }

    /// Build raw SSA without architecture metadata.
    pub fn from_blocks_raw_no_arch(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_raw(blocks, None)
    }

    /// Set the function name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the entry block.
    pub fn entry_block(&self) -> Option<&SSABlock> {
        self.blocks.get(&self.entry)
    }

    /// Get a block by address.
    pub fn get_block(&self, addr: u64) -> Option<&SSABlock> {
        self.blocks.get(&addr)
    }

    /// Get a mutable block by address.
    pub fn get_block_mut(&mut self, addr: u64) -> Option<&mut SSABlock> {
        self.blocks.get_mut(&addr)
    }

    /// Get all blocks in reverse postorder.
    pub fn blocks(&self) -> impl Iterator<Item = &SSABlock> {
        self.block_order
            .iter()
            .filter_map(|&addr| self.blocks.get(&addr))
    }

    /// Get block addresses in reverse postorder.
    pub fn block_addrs(&self) -> &[u64] {
        &self.block_order
    }

    /// Look up semantic metadata hints for an SSA variable.
    pub fn semantic_var_metadata(&self, var: &SSAVar) -> Option<&VarnodeMetadata> {
        self.semantic_var_metadata_by_name(&var.name)
    }

    /// Look up semantic metadata hints by canonical SSA base variable name.
    pub fn semantic_var_metadata_by_name(&self, name: &str) -> Option<&VarnodeMetadata> {
        self.semantic_var_hints.get(&name.to_ascii_lowercase())
    }

    /// Get the number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Get the CFG.
    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    /// Get mutable access to the CFG.
    pub fn cfg_mut(&mut self) -> &mut CFG {
        &mut self.cfg
    }

    /// Get the dominator tree.
    pub fn domtree(&self) -> &DomTree {
        &self.domtree
    }

    /// Get predecessors of a block.
    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        self.cfg.predecessors(addr)
    }

    /// Get successors of a block.
    pub fn successors(&self, addr: u64) -> Vec<u64> {
        self.cfg.successors(addr)
    }

    /// Get switch info for a block, if it's a switch terminator.
    /// Returns Some((cases, default)) where cases is Vec<(value, target)>.
    pub fn switch_info(&self, addr: u64) -> Option<SwitchInfo> {
        let block = self.cfg.get_block(addr)?;
        if let crate::cfg::BlockTerminator::Switch { cases, default } = &block.terminator {
            Some((cases.clone(), *default))
        } else {
            None
        }
    }

    /// Check if block A dominates block B.
    pub fn dominates(&self, a: u64, b: u64) -> bool {
        self.domtree.dominates(a, b)
    }

    /// Get the immediate dominator of a block.
    pub fn idom(&self, block: u64) -> Option<u64> {
        self.domtree.idom(block)
    }

    /// Get the edge type between two blocks.
    pub fn edge_type(&self, from: u64, to: u64) -> Option<CFGEdge> {
        self.cfg.edge_type(from, to)
    }

    /// Remove a block from SSA and CFG.
    pub fn remove_block(&mut self, addr: u64) {
        self.blocks.remove(&addr);
        self.block_order.retain(|&a| a != addr);
        self.cfg.remove_block(addr);
    }

    /// Remove phi sources for a specific predecessor edge.
    pub fn remove_phi_source(&mut self, block_addr: u64, pred_addr: u64) {
        if let Some(block) = self.blocks.get_mut(&block_addr) {
            for phi in &mut block.phis {
                phi.sources.retain(|(pred, _)| *pred != pred_addr);
            }
        }
    }

    /// Recompute cached metadata after CFG mutation.
    pub fn refresh_after_cfg_mutation(&mut self) {
        self.blocks
            .retain(|addr, _| self.cfg.get_block(*addr).is_some());
        self.block_order = self.cfg.reverse_postorder();
        self.domtree = DomTree::compute(&self.cfg);
    }

    /// Iterate over all SSA operations in the function.
    pub fn all_ops(&self) -> impl Iterator<Item = &SSAOp> {
        self.blocks.values().flat_map(|b| b.ops.iter())
    }

    /// Iterate over all phi nodes in the function.
    pub fn all_phis(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks.values().flat_map(|b| b.phis.iter())
    }

    /// Get all variables defined in this function.
    pub fn defined_vars(&self) -> Vec<SSAVar> {
        let mut vars = Vec::new();

        // Collect from phi nodes
        for phi in self.all_phis() {
            vars.push(phi.dst.clone());
        }

        // Collect from operations
        for op in self.all_ops() {
            if let Some(dst) = op.dst() {
                vars.push(dst.clone());
            }
        }

        vars
    }

    /// Get all variables used in this function.
    pub fn used_vars(&self) -> Vec<SSAVar> {
        let mut vars = Vec::new();

        // Collect from phi nodes
        for phi in self.all_phis() {
            for (_, var) in &phi.sources {
                vars.push(var.clone());
            }
        }

        // Collect from operations
        for op in self.all_ops() {
            for src in op.sources() {
                vars.push(src.clone());
            }
        }

        vars
    }

    /// Find the definition of a variable.
    ///
    /// Returns the block address and operation index where the variable is defined.
    pub fn find_def(&self, var: &SSAVar) -> Option<(u64, DefLocation)> {
        for (&addr, block) in &self.blocks {
            // Check phi nodes
            for (i, phi) in block.phis.iter().enumerate() {
                if &phi.dst == var {
                    return Some((addr, DefLocation::Phi(i)));
                }
            }

            // Check operations
            for (i, op) in block.ops.iter().enumerate() {
                if op.dst() == Some(var) {
                    return Some((addr, DefLocation::Op(i)));
                }
            }
        }
        None
    }

    /// Find all uses of a variable.
    ///
    /// Returns a list of (block address, use location) pairs.
    pub fn find_uses(&self, var: &SSAVar) -> Vec<(u64, UseLocation)> {
        let mut uses = Vec::new();

        for (&addr, block) in &self.blocks {
            block.for_each_source(|src| {
                if src.var != var {
                    return;
                }
                let use_loc = match src.site {
                    SourceSite::Phi {
                        phi_idx, src_idx, ..
                    } => UseLocation::Phi { phi_idx, src_idx },
                    SourceSite::Op { op_idx, src_idx } => UseLocation::Op { op_idx, src_idx },
                };
                uses.push((addr, use_loc));
            });
        }

        uses
    }

    /// Iterate over all source uses in all blocks.
    pub fn for_each_source<F: FnMut(u64, SourceRef<'_>)>(&self, mut f: F) {
        for block in self.blocks() {
            block.for_each_source(|src| f(block.addr, src));
        }
    }

    /// Iterate over all definitions in all blocks.
    pub fn for_each_def<F: FnMut(u64, DefRef<'_>)>(&self, mut f: F) {
        for block in self.blocks() {
            block.for_each_def(|def| f(block.addr, def));
        }
    }

    /// Compute a backward slice for a sink variable.
    pub fn backward_slice(&self, sink: &SSAVar) -> BackwardSlice {
        backward_slice_from_var(self, sink)
    }

    /// Compute a backward slice starting from an SSA operation.
    pub fn backward_slice_from_op(&self, block_addr: u64, op_idx: usize) -> BackwardSlice {
        backward_slice_from_op(self, SliceOpRef::Op { block_addr, op_idx })
    }

    /// Compute a backward slice starting from a phi node.
    pub fn backward_slice_from_phi(&self, block_addr: u64, phi_idx: usize) -> BackwardSlice {
        backward_slice_from_op(
            self,
            SliceOpRef::Phi {
                block_addr,
                phi_idx,
            },
        )
    }

    /// Run SSA optimizations on this function.
    pub fn optimize(
        &mut self,
        config: &crate::optimize::OptimizationConfig,
    ) -> crate::optimize::OptimizationStats {
        crate::optimize::optimize_function(self, config)
    }

    /// Print the function in a human-readable format.
    pub fn dump(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "Function: {}\n",
            self.name.as_deref().unwrap_or("<unnamed>")
        ));
        out.push_str(&format!("Entry: 0x{:x}\n", self.entry));
        out.push_str(&format!("Blocks: {}\n\n", self.num_blocks()));

        for &addr in &self.block_order {
            if let Some(block) = self.blocks.get(&addr) {
                out.push_str(&format!("Block 0x{:x}:\n", addr));

                // Predecessors
                let preds = self.predecessors(addr);
                if !preds.is_empty() {
                    out.push_str(&format!(
                        "  preds: {}\n",
                        preds
                            .iter()
                            .map(|p| format!("0x{:x}", p))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                // Phi nodes
                for phi in &block.phis {
                    let sources: Vec<String> = phi
                        .sources
                        .iter()
                        .map(|(pred, var)| format!("[0x{:x}]: {}", pred, var))
                        .collect();
                    out.push_str(&format!("  {} = phi({})\n", phi.dst, sources.join(", ")));
                }

                // Operations
                for op in &block.ops {
                    out.push_str(&format!("  {:?}\n", op));
                }

                // Successors
                let succs = self.successors(addr);
                if !succs.is_empty() {
                    out.push_str(&format!(
                        "  succs: {}\n",
                        succs
                            .iter()
                            .map(|s| format!("0x{:x}", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                out.push('\n');
            }
        }

        out
    }
}

/// Location of a variable definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefLocation {
    /// Defined by a phi node at the given index.
    Phi(usize),
    /// Defined by an operation at the given index.
    Op(usize),
}

/// Location of a variable use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseLocation {
    /// Used in a phi node.
    Phi { phi_idx: usize, src_idx: usize },
    /// Used in an operation.
    Op { op_idx: usize, src_idx: usize },
}

impl SSABlock {
    /// Visit all phi source variables in deterministic index order.
    pub fn for_each_phi_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis.iter().enumerate() {
            for (src_idx, (pred_addr, src)) in phi.sources.iter().enumerate() {
                f(SourceRef {
                    var: src,
                    site: SourceSite::Phi {
                        phi_idx,
                        src_idx,
                        pred_addr: *pred_addr,
                    },
                });
            }
        }
    }

    /// Visit all operation source variables in deterministic index order.
    pub fn for_each_op_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        for (op_idx, op) in self.ops.iter().enumerate() {
            let mut src_idx = 0usize;
            op.for_each_source(|src| {
                f(SourceRef {
                    var: src,
                    site: SourceSite::Op { op_idx, src_idx },
                });
                src_idx += 1;
            });
        }
    }

    /// Visit all source variables (phis first, then ops) in index order.
    pub fn for_each_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        self.for_each_phi_source(&mut f);
        self.for_each_op_source(f);
    }

    /// Visit all destination definitions (phis first, then ops) in index order.
    pub fn for_each_def<F: FnMut(DefRef<'_>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis.iter().enumerate() {
            f(DefRef {
                var: &phi.dst,
                site: DefSite::Phi { phi_idx },
            });
        }

        for (op_idx, op) in self.ops.iter().enumerate() {
            if let Some(dst) = op.dst() {
                f(DefRef {
                    var: dst,
                    site: DefSite::Op { op_idx },
                });
            }
        }
    }

    /// Get all operations including phi nodes (as SSAOp::Phi).
    pub fn all_ops(&self) -> impl Iterator<Item = SSAOp> + '_ {
        let phi_ops = self.phis.iter().map(|phi| SSAOp::Phi {
            dst: phi.dst.clone(),
            sources: phi.sources.iter().map(|(_, v)| v.clone()).collect(),
        });
        phi_ops.chain(self.ops.iter().cloned())
    }

    /// Check if this block has any phi nodes.
    pub fn has_phis(&self) -> bool {
        !self.phis.is_empty()
    }

    /// Get the number of phi nodes.
    pub fn num_phis(&self) -> usize {
        self.phis.len()
    }

    /// Get the number of operations (excluding phi nodes).
    pub fn num_ops(&self) -> usize {
        self.ops.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{PointerHint, R2ILOp, SpaceId, Varnode, VarnodeMetadata};

    fn make_const(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
            meta: None,
        }
    }

    fn make_reg(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    fn make_ram(addr: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Ram,
            offset: addr,
            size,
            meta: None,
        }
    }

    #[test]
    fn test_ssa_function_linear() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
        assert_eq!(func.entry, 0x1000);
        assert_eq!(func.num_blocks(), 2);

        // Check that entry block has the copy operations
        let entry = func.entry_block().unwrap();
        assert_eq!(entry.num_ops(), 2);
        assert!(!entry.has_phis());
    }

    #[test]
    fn test_ssa_function_diamond() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
        assert_eq!(func.num_blocks(), 4);

        // Merge block should have a phi node
        let merge = func.get_block(0x100c).unwrap();
        assert!(merge.has_phis());
        assert_eq!(merge.num_phis(), 1);

        // Phi should have two sources
        let phi = &merge.phis[0];
        assert_eq!(phi.sources.len(), 2);
    }

    #[test]
    fn test_find_def_use() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();

        // Find definition of reg:0 v1
        let var = SSAVar::new("reg:0", 1, 8);
        let def = func.find_def(&var);
        assert!(def.is_some());
        let (addr, loc) = def.unwrap();
        assert_eq!(addr, 0x1000);
        assert!(matches!(loc, DefLocation::Op(0)));

        // Find uses of reg:0 v1
        let uses = func.find_uses(&var);
        assert!(!uses.is_empty());
    }

    #[test]
    fn test_dump() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(42, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks)
            .unwrap()
            .with_name("test_func");

        let dump = func.dump();
        assert!(dump.contains("test_func"));
        assert!(dump.contains("0x1000"));
        assert!(dump.contains("0x1004"));
    }

    #[test]
    fn test_from_blocks_default_runs_optimization() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks(&blocks).expect("optimized SSA should build");
        assert!(
            func.num_blocks() < blocks.len(),
            "optimized constructor should prune dead branch blocks via SCCP"
        );
    }

    #[test]
    fn test_refresh_after_cfg_mutation_recomputes_order_and_domtree() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        func.remove_block(0x1004);
        func.refresh_after_cfg_mutation();

        assert!(!func.block_addrs().contains(&0x1004));
        assert!(func.get_block(0x1004).is_none());
        assert_eq!(func.idom(0x1008), Some(0x1000));
    }

    #[test]
    fn test_semantic_var_metadata_is_collected_from_source_blocks() {
        let mut src = make_reg(0x10, 8);
        src.set_meta(VarnodeMetadata {
            pointer_hint: Some(PointerHint::PointerLike),
            ..Default::default()
        });

        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::Copy {
                dst: make_reg(0, 8),
                src,
            }],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let meta = func
            .semantic_var_metadata_by_name("reg:10")
            .expect("expected semantic metadata for source register");

        assert_eq!(meta.pointer_hint, Some(PointerHint::PointerLike));
    }

    #[test]
    fn test_for_each_source_reports_phi_and_op_sites() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(3, 8),
                }],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let merge = func.get_block(0x100c).expect("merge block");
        assert!(merge.has_phis(), "fixture should produce a merge phi");

        let mut seen = Vec::new();
        merge.for_each_source(|src| {
            seen.push(match src.site {
                SourceSite::Phi {
                    phi_idx,
                    src_idx,
                    pred_addr,
                } => format!(
                    "phi:{}:{}:0x{:x}:{}",
                    phi_idx,
                    src_idx,
                    pred_addr,
                    src.var.display_name()
                ),
                SourceSite::Op { op_idx, src_idx } => {
                    format!("op:{}:{}:{}", op_idx, src_idx, src.var.display_name())
                }
            });
        });

        assert_eq!(seen.len(), 4, "2 phi sources + 2 IntAdd sources expected");
        assert!(
            seen[0].starts_with("phi:0:0:"),
            "first source should be first phi input"
        );
        assert!(
            seen[1].starts_with("phi:0:1:"),
            "second source should be second phi input"
        );
        assert!(
            seen[2].starts_with("op:0:0:"),
            "third source should be first op input"
        );
        assert!(
            seen[3].starts_with("op:0:1:"),
            "fourth source should be second op input"
        );
    }

    #[test]
    fn test_for_each_def_reports_phi_and_op_defs() {
        let block = SSABlock {
            addr: 0x2000,
            size: 4,
            phis: vec![PhiNode {
                dst: SSAVar::new("reg:0", 2, 8),
                sources: vec![(0x1000, SSAVar::new("reg:0", 0, 8))],
            }],
            ops: vec![
                SSAOp::Copy {
                    dst: SSAVar::new("reg:8", 1, 8),
                    src: SSAVar::new("reg:0", 2, 8),
                },
                SSAOp::Return {
                    target: SSAVar::new("reg:8", 1, 8),
                },
            ],
        };

        let mut seen = Vec::new();
        block.for_each_def(|def| {
            seen.push(match def.site {
                DefSite::Phi { phi_idx } => format!("phi:{}:{}", phi_idx, def.var.display_name()),
                DefSite::Op { op_idx } => format!("op:{}:{}", op_idx, def.var.display_name()),
            });
        });

        assert_eq!(
            seen,
            vec!["phi:0:reg:0_2".to_string(), "op:0:reg:8_1".to_string()]
        );
    }
}
