//! Phi-node placement for SSA construction.
//!
//! This module implements the phi-node placement algorithm using the
//! iterated dominance frontier, as described by Cytron et al.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::cfg::CFG;
use crate::control::{SsaExecutionStopReason, SsaWorkControl};
use crate::domtree::DomTree;
use crate::naming::{RegisterNameMap, varnode_to_name};
use crate::var::{CanonicalStorageId, SSAVar};

/// Exact identity used by phi placement and SSA renaming.
///
/// The semantic name remains presentation advice. Width is part of the
/// identity because Sleigh may reuse one Unique offset for unrelated scratch
/// values of different widths, and register-name maps may expose multiple
/// slices under one spelling. Canonical storage completes the identity; the
/// name remains a separate presentation projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RenameIdentity {
    pub name: String,
    pub size: u32,
    pub storage: CanonicalStorageId,
}

impl RenameIdentity {
    pub fn new(name: impl Into<String>, storage: CanonicalStorageId) -> Self {
        Self {
            name: name.into(),
            size: storage.size,
            storage,
        }
    }

    pub fn from_varnode(varnode: &r2il::Varnode, reg_names: Option<&RegisterNameMap>) -> Self {
        Self::new(
            varnode_to_name(varnode, reg_names),
            CanonicalStorageId::from_varnode(varnode),
        )
    }

    pub fn synthetic(name: impl Into<String>, size: u32) -> Self {
        Self::new(name, CanonicalStorageId::unknown(0, size))
    }

    pub fn as_var(&self, version: u32, disambiguator: u32) -> SSAVar {
        SSAVar::new(&self.name, version, self.size).with_rename_disambiguator(disambiguator)
    }
}

pub type DefinitionSitesByIdentity = BTreeMap<RenameIdentity, BTreeSet<u64>>;
pub type CanonicalStorageByIdentity = BTreeMap<RenameIdentity, CanonicalStorageId>;
pub type DefinitionCollection = (DefinitionSitesByIdentity, CanonicalStorageByIdentity);

/// Information about phi nodes to be placed in the CFG.
#[derive(Debug, Clone, Default)]
pub struct PhiPlacement {
    /// Phi nodes to place at each block, keyed internally by exact rename identity.
    pub phis: HashMap<u64, Vec<PhiInfo>>,
}

/// Information about a single phi node.
#[derive(Debug, Clone)]
pub struct PhiInfo {
    /// Typed rename identity. The name inside it is retained for presentation.
    pub identity: RenameIdentity,
    /// Lifted storage identity, independent of register/display names.
    pub storage: Option<CanonicalStorageId>,
    /// The predecessor blocks that contribute values.
    pub predecessors: Vec<u64>,
}

impl PhiPlacement {
    /// Create a new empty phi placement.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute phi placement while polling dominance-frontier worklists.
    pub fn compute_with_storage_and_control<C: SsaWorkControl + ?Sized>(
        cfg: &CFG,
        domtree: &DomTree,
        defs: &DefinitionSitesByIdentity,
        storage_by_identity: &CanonicalStorageByIdentity,
        control: &C,
    ) -> Result<Self, SsaExecutionStopReason> {
        control.poll()?;
        let mut placement = Self::new();

        for (identity, def_blocks) in defs {
            control.poll()?;
            let mut def_list: Vec<u64> = def_blocks.iter().copied().collect();
            def_list.sort_unstable();
            let mut phi_blocks: Vec<u64> = domtree
                .iterated_frontier_with_control(&def_list, control)?
                .into_iter()
                .collect();
            phi_blocks.sort_unstable();

            for phi_block in phi_blocks {
                control.poll()?;
                let preds = cfg.predecessors(phi_block);
                if preds.len() >= 2 {
                    let storage = storage_by_identity.get(identity).copied();
                    let phi_info = PhiInfo {
                        identity: identity.clone(),
                        storage,
                        predecessors: preds,
                    };
                    placement.phis.entry(phi_block).or_default().push(phi_info);
                }
            }
        }

        for phis in placement.phis.values_mut() {
            control.poll()?;
            phis.sort_unstable_by(|lhs, rhs| {
                lhs.identity
                    .cmp(&rhs.identity)
                    .then(lhs.predecessors.cmp(&rhs.predecessors))
            });
        }

        control.poll()?;
        Ok(placement)
    }

    /// Get phi nodes for a specific block.
    pub fn get_phis(&self, block: u64) -> &[PhiInfo] {
        self.phis.get(&block).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Collect definitions and storage while polling the block/operation scan.
pub fn collect_defs_from_cfg_with_names_storage_and_control<C: SsaWorkControl + ?Sized>(
    cfg: &CFG,
    reg_names: Option<&RegisterNameMap>,
    control: &C,
) -> Result<DefinitionCollection, SsaExecutionStopReason> {
    control.poll()?;
    let mut defs = DefinitionSitesByIdentity::new();
    let mut storage_by_identity = CanonicalStorageByIdentity::new();

    for addr in cfg.block_addrs() {
        control.poll()?;
        let Some(block) = cfg.get_block(addr) else {
            continue;
        };
        for op in &block.ops {
            control.poll()?;
            for varnode in op.inputs() {
                if !matches!(varnode.space, r2il::SpaceId::Const) {
                    let identity = RenameIdentity::from_varnode(varnode, reg_names);
                    defs.entry(identity.clone()).or_default();
                    storage_by_identity.insert(identity.clone(), identity.storage);
                }
            }
            if let Some(varnode) = get_op_output_varnode(op) {
                let identity = RenameIdentity::from_varnode(varnode, reg_names);
                defs.entry(identity.clone()).or_default().insert(block.addr);
                storage_by_identity.insert(identity.clone(), identity.storage);
            }
        }
    }

    control.poll()?;
    Ok((defs, storage_by_identity))
}

/// The rename identities one call-boundary register names.
///
/// Renaming resolves these itself and, doing so per call site, could see an
/// identity a previous site had just created. Resolving once against the
/// definitions the body already has removes that order dependency.
pub fn call_boundary_identities(
    defs: &DefinitionSitesByIdentity,
    reg: &crate::rename::CallBoundaryDef,
    reg_names: Option<&RegisterNameMap>,
) -> BTreeSet<RenameIdentity> {
    let needle = reg.name.to_ascii_lowercase();
    let mut identities = defs
        .keys()
        .filter(|candidate| {
            candidate.size == reg.size && candidate.name.to_ascii_lowercase() == needle
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        && let Some(reg_names) = reg_names
    {
        for ((offset, size), candidate) in reg_names {
            if *size == reg.size && candidate.eq_ignore_ascii_case(&reg.name) {
                identities.insert(RenameIdentity::new(
                    candidate,
                    CanonicalStorageId {
                        space: crate::CanonicalStorageSpace::Register,
                        offset: *offset,
                        size: *size,
                    },
                ));
            }
        }
    }
    if identities.is_empty() {
        identities.insert(RenameIdentity::synthetic(&reg.name, reg.size));
    }
    identities
}

/// Record the definitions renaming will add at every call.
///
/// A call clobbers its convention's registers, and renaming writes a
/// `CallDefine` for each. Phi placement ran before those existed, so a
/// register two paths defined -- one by a call and one by an instruction --
/// reached a join with no phi, and the return that read it had no value.
pub fn add_call_boundary_def_sites(
    cfg: &CFG,
    call_boundaries: &crate::rename::CallBoundaryConfig,
    reg_names: Option<&RegisterNameMap>,
    defs: &mut DefinitionSitesByIdentity,
    storage_by_identity: &mut CanonicalStorageByIdentity,
) {
    // Only a carrier the body itself mentions. A register that appears
    // nowhere but in the clobber list is read by no statement, so no phi for
    // it can be observed and placing one only invents a live-in value.
    let resolved = call_boundaries
        .defined_regs
        .iter()
        .map(|reg| {
            let identities = call_boundary_identities(defs, reg, reg_names);
            identities
                .into_iter()
                .filter(|identity| defs.contains_key(identity))
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    for addr in cfg.block_addrs() {
        let Some(block) = cfg.get_block(addr) else {
            continue;
        };
        for op in &block.ops {
            // Only a direct call names a callee whose body may have been read;
            // anything else defines the whole list.
            let preserved = match op {
                r2il::R2ILOp::Call { target } if target.is_ram() => {
                    call_boundaries.preserved_by_target.get(&target.offset)
                }
                r2il::R2ILOp::CallInd { .. } => None,
                _ => continue,
            };
            for identity in resolved.iter().flatten() {
                if preserved.is_some_and(|preserved| preserved.contains(&identity.storage)) {
                    continue;
                }
                defs.entry(identity.clone()).or_default().insert(block.addr);
                storage_by_identity.insert(identity.clone(), identity.storage);
            }
        }
    }
}

fn get_op_output_varnode(op: &r2il::R2ILOp) -> Option<&r2il::Varnode> {
    use r2il::R2ILOp::*;

    match op {
        Copy { dst, .. }
        | Load { dst, .. }
        | IntAdd { dst, .. }
        | IntSub { dst, .. }
        | IntMult { dst, .. }
        | IntDiv { dst, .. }
        | IntSDiv { dst, .. }
        | IntRem { dst, .. }
        | IntSRem { dst, .. }
        | IntNegate { dst, .. }
        | IntCarry { dst, .. }
        | IntSCarry { dst, .. }
        | IntSBorrow { dst, .. }
        | IntAnd { dst, .. }
        | IntOr { dst, .. }
        | IntXor { dst, .. }
        | IntNot { dst, .. }
        | IntLeft { dst, .. }
        | IntRight { dst, .. }
        | IntSRight { dst, .. }
        | IntEqual { dst, .. }
        | IntNotEqual { dst, .. }
        | IntLess { dst, .. }
        | IntSLess { dst, .. }
        | IntLessEqual { dst, .. }
        | IntSLessEqual { dst, .. }
        | IntZExt { dst, .. }
        | IntSExt { dst, .. }
        | BoolNot { dst, .. }
        | BoolAnd { dst, .. }
        | BoolOr { dst, .. }
        | BoolXor { dst, .. }
        | Piece { dst, .. }
        | Subpiece { dst, .. }
        | PopCount { dst, .. }
        | Lzcount { dst, .. }
        | FloatAdd { dst, .. }
        | FloatSub { dst, .. }
        | FloatMult { dst, .. }
        | FloatDiv { dst, .. }
        | FloatNeg { dst, .. }
        | FloatAbs { dst, .. }
        | FloatSqrt { dst, .. }
        | FloatCeil { dst, .. }
        | FloatFloor { dst, .. }
        | FloatRound { dst, .. }
        | FloatNaN { dst, .. }
        | FloatEqual { dst, .. }
        | FloatNotEqual { dst, .. }
        | FloatLess { dst, .. }
        | FloatLessEqual { dst, .. }
        | Int2Float { dst, .. }
        | Float2Int { dst, .. }
        | FloatFloat { dst, .. }
        | Trunc { dst, .. }
        | CpuId { dst }
        | Multiequal { dst, .. }
        | Indirect { dst, .. }
        | PtrAdd { dst, .. }
        | PtrSub { dst, .. }
        | SegmentOp { dst, .. }
        | New { dst, .. }
        | Cast { dst, .. }
        | Extract { dst, .. }
        | Insert { dst, .. } => Some(dst),
        CallOther { output, .. } => output.as_ref(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {}
