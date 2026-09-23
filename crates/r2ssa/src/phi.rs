//! Phi-node placement for SSA construction.
//!
//! This module implements the phi-node placement algorithm using the
//! iterated dominance frontier, as described by Cytron et al.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::cfg::CFG;
use crate::control::{SsaExecutionStopReason, SsaWorkControl};
use crate::domtree::DomTree;
use crate::function::{RegisterFamilyInfo, RegisterFamilySlot};
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

    /// The identity a varnode is renamed under: its register family's root
    /// when the architecture's geometry puts it inside a wider register, and
    /// the exact varnode otherwise (doc/adr-register-identity.md §2).
    pub fn for_varnode(
        varnode: &r2il::Varnode,
        reg_names: Option<&RegisterNameMap>,
        families: Option<&RegisterFamilyInfo>,
    ) -> Self {
        match register_root_slot(varnode, families) {
            Some(root) => Self::for_root_slot(root, reg_names),
            None => Self::from_varnode(varnode, reg_names),
        }
    }

    /// The root's identity is the one its own varnode would get, so a whole
    /// read of the register and a lane read of it name one value.
    pub(crate) fn for_root_slot(
        root: RegisterFamilySlot,
        reg_names: Option<&RegisterNameMap>,
    ) -> Self {
        let varnode = r2il::Varnode {
            space: r2il::SpaceId::Register,
            offset: root.offset,
            size: root.width,
            meta: None,
        };
        Self::from_varnode(&varnode, reg_names)
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

    /// Take from `complete` the merges this placement lacks, where the
    /// identity is live at the block that would carry them.
    pub fn merge_live_additions(
        &mut self,
        complete: Self,
        live_in: &HashMap<u64, BTreeSet<RenameIdentity>>,
    ) {
        for (block, phis) in complete.phis {
            let existing = self.phis.entry(block).or_default();
            let held = existing
                .iter()
                .map(|phi| phi.identity.clone())
                .collect::<BTreeSet<_>>();
            let live = live_in.get(&block);
            for phi in phis {
                if held.contains(&phi.identity)
                    || !live.is_some_and(|live| live.contains(&phi.identity))
                {
                    continue;
                }
                existing.push(phi);
            }
            existing.sort_unstable_by(|lhs, rhs| {
                lhs.identity
                    .cmp(&rhs.identity)
                    .then(lhs.predecessors.cmp(&rhs.predecessors))
            });
        }
    }

    /// Get phi nodes for a specific block.
    pub fn get_phis(&self, block: u64) -> &[PhiInfo] {
        self.phis.get(&block).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// The root slot a register varnode lies inside, when it is a lane of a wider
/// register the architecture declares.
pub(crate) fn register_root_slot(
    varnode: &r2il::Varnode,
    families: Option<&RegisterFamilyInfo>,
) -> Option<RegisterFamilySlot> {
    if !matches!(varnode.space, r2il::SpaceId::Register) {
        return None;
    }
    families?.root_slot_over(varnode.offset, varnode.size)
}

/// Collect definitions and storage while polling the block/operation scan.
/// Which op site accesses a promoted stack slot, and the varnode standing for
/// the slot there. Empty where nothing was promoted.
pub type PromotedStackSlots = std::collections::BTreeMap<(u64, usize), r2il::Varnode>;

pub fn collect_defs_from_cfg_with_names_storage_and_control<C: SsaWorkControl + ?Sized>(
    cfg: &CFG,
    reg_names: Option<&RegisterNameMap>,
    families: Option<&RegisterFamilyInfo>,
    promoted: &PromotedStackSlots,
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
        for (op_idx, op) in block.ops.iter().enumerate() {
            control.poll()?;
            // A promoted slot's access defines or reads the slot's own
            // identity, which is what gives it a merge at a join the same way
            // a register gets one.
            if let Some(slot) = promoted.get(&(block.addr, op_idx)) {
                let identity = RenameIdentity::for_varnode(slot, reg_names, families);
                storage_by_identity.insert(identity.clone(), identity.storage);
                match op {
                    r2il::R2ILOp::Store { .. } => {
                        defs.entry(identity).or_default().insert(block.addr);
                    }
                    _ => {
                        defs.entry(identity).or_default();
                    }
                }
            }
            for varnode in op.inputs() {
                if !matches!(varnode.space, r2il::SpaceId::Const) {
                    let identity = RenameIdentity::for_varnode(varnode, reg_names, families);
                    defs.entry(identity.clone()).or_default();
                    storage_by_identity.insert(identity.clone(), identity.storage);
                }
            }
            if let Some(varnode) = get_op_output_varnode(op) {
                let identity = RenameIdentity::for_varnode(varnode, reg_names, families);
                defs.entry(identity.clone()).or_default().insert(block.addr);
                storage_by_identity.insert(identity.clone(), identity.storage);
            }
        }
    }

    control.poll()?;
    Ok((defs, storage_by_identity))
}

/// The identity a call's clobber of one register defines: the root its reads are renamed under.
pub(crate) fn clobber_identity(
    storage: CanonicalStorageId,
    reg_names: Option<&RegisterNameMap>,
    families: Option<&RegisterFamilyInfo>,
) -> RenameIdentity {
    let varnode = r2il::Varnode {
        space: r2il::SpaceId::Register,
        offset: storage.offset,
        size: storage.size,
        meta: None,
    };
    RenameIdentity::for_varnode(&varnode, reg_names, families)
}

/// The clobbers a call makes that this body can observe: those of a register it defines.
fn observed_clobbers(
    call_boundaries: &crate::rename::CallBoundaryConfig,
    reg_names: Option<&RegisterNameMap>,
    families: Option<&RegisterFamilyInfo>,
    defs: &DefinitionSitesByIdentity,
) -> BTreeSet<RenameIdentity> {
    call_boundaries
        .clobbered
        .iter()
        .map(|storage| clobber_identity(*storage, reg_names, families))
        .filter(|identity| defs.contains_key(identity))
        .collect()
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
    families: Option<&RegisterFamilyInfo>,
) -> BTreeSet<RenameIdentity> {
    // A convention register is one family: whatever width it is named at,
    // the identity it defines or reads is the family's root.
    if let Some(root) = families.and_then(|families| families.widest_slot_for_name(&reg.name)) {
        return BTreeSet::from([RenameIdentity::for_root_slot(root, reg_names)]);
    }
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
    families: Option<&RegisterFamilyInfo>,
    defs: &mut DefinitionSitesByIdentity,
    storage_by_identity: &mut CanonicalStorageByIdentity,
) {
    // Only a carrier the body itself mentions. A register that appears
    // nowhere but in the clobber list is read by no statement, so no phi for
    // it can be observed and placing one only invents a live-in value.
    let resolved = observed_clobbers(call_boundaries, reg_names, families, defs);
    // The same question for the carrier each callee's own interface names as
    // its result, asked before a def site is added so the answer cannot depend
    // on the order the calls are walked.
    let results = call_boundaries
        .result_by_target
        .iter()
        .map(|(target, reg)| {
            let identities = call_boundary_identities(defs, reg, reg_names, families)
                .into_iter()
                .filter(|identity| defs.contains_key(identity))
                .collect::<BTreeSet<_>>();
            (*target, identities)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for addr in cfg.block_addrs() {
        let Some(block) = cfg.get_block(addr) else {
            continue;
        };
        for op in &block.ops {
            if !matches!(op, r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. }) {
                continue;
            }
            let callee = call_boundaries.callee_boundary(op);
            let result = callee
                .target
                .and_then(|target| results.get(&target))
                .into_iter()
                .flatten();
            for identity in resolved.iter().chain(result) {
                if callee
                    .preserved
                    .is_some_and(|preserved| preserved.contains(&identity.storage))
                {
                    continue;
                }
                defs.entry(identity.clone()).or_default().insert(block.addr);
                storage_by_identity.insert(identity.clone(), identity.storage);
            }
        }
    }
}

/// Where each identity is live, so a phi is placed only where a read can see
/// it.
///
/// A call reads its arguments and a return its value through the convention
/// rather than through an operand, so both are added to the reads a block
/// makes; without them the carrier a return hands back looks dead everywhere.
pub fn live_in_by_block(
    cfg: &CFG,
    call_boundaries: &crate::rename::CallBoundaryConfig,
    reg_names: Option<&RegisterNameMap>,
    families: Option<&RegisterFamilyInfo>,
    defs: &DefinitionSitesByIdentity,
) -> HashMap<u64, BTreeSet<RenameIdentity>> {
    let resolve = |regs: &[crate::rename::CallBoundaryDef]| {
        regs.iter()
            .flat_map(|reg| call_boundary_identities(defs, reg, reg_names, families))
            .filter(|identity| defs.contains_key(identity))
            .collect::<BTreeSet<_>>()
    };
    let clobbered = observed_clobbers(call_boundaries, reg_names, families, defs);
    let arguments = resolve(&call_boundaries.argument_regs);
    let returned = resolve(&call_boundaries.return_regs);

    // Number every identity the walk can name, then answer in words.
    //
    // Liveness used to be an ordered set of identities per block, rebuilt from
    // the successors on every visit, with the identity of each operand
    // constructed -- name and all -- each time an operation was looked at. The
    // question asked of the result is only whether one identity is live at one
    // block, one identity's liveness does not depend on another's, and the set
    // of identities a function can name is fixed before the walk starts. So
    // the identities are numbered once, each operation's effect on them is
    // recorded once, and the fixed point is bitwise.
    let mut identities: Vec<RenameIdentity> = Vec::new();
    let mut numbers: HashMap<RenameIdentity, u32> = HashMap::new();
    let number_of = |identity: RenameIdentity,
                     identities: &mut Vec<RenameIdentity>,
                     numbers: &mut HashMap<RenameIdentity, u32>| {
        if let Some(number) = numbers.get(&identity) {
            return *number;
        }
        let number = identities.len() as u32;
        identities.push(identity.clone());
        numbers.insert(identity, number);
        number
    };

    let addrs = cfg.block_addrs().collect::<Vec<_>>();
    let mut effects: Vec<Vec<LivenessOpEffect>> = Vec::with_capacity(addrs.len());
    let mut present = Vec::with_capacity(addrs.len());
    for addr in &addrs {
        let Some(block) = cfg.get_block(*addr) else {
            effects.push(Vec::new());
            present.push(false);
            continue;
        };
        present.push(true);
        let mut rows = Vec::with_capacity(block.ops.len());
        for op in &block.ops {
            let kill = get_op_output_varnode(op)
                .filter(|varnode| register_root_slot(varnode, families).is_none())
                .map(|varnode| {
                    number_of(
                        RenameIdentity::for_varnode(varnode, reg_names, families),
                        &mut identities,
                        &mut numbers,
                    )
                });
            let reads = op
                .inputs()
                .into_iter()
                .filter(|varnode| !matches!(varnode.space, r2il::SpaceId::Const))
                .map(|varnode| {
                    number_of(
                        RenameIdentity::for_varnode(varnode, reg_names, families),
                        &mut identities,
                        &mut numbers,
                    )
                })
                .collect::<Vec<_>>();
            rows.push(LivenessOpEffect {
                boundary: match op {
                    r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. } => {
                        LivenessBoundary::Call
                    }
                    r2il::R2ILOp::Return { .. } => LivenessBoundary::Return,
                    _ => LivenessBoundary::None,
                },
                kill,
                reads,
            });
        }
        effects.push(rows);
    }
    let numbers_of_set = |set: &BTreeSet<RenameIdentity>,
                          numbers: &HashMap<RenameIdentity, u32>| {
        set.iter()
            .filter_map(|identity| numbers.get(identity).copied())
            .collect::<Vec<_>>()
    };
    let clobbered_numbers = numbers_of_set(&clobbered, &numbers);
    let argument_numbers = numbers_of_set(&arguments, &numbers);
    let returned_numbers = numbers_of_set(&returned, &numbers);

    let words = identities.len().div_ceil(64).max(1);
    let mut live = vec![0u64; addrs.len() * words];
    let mut position = HashMap::with_capacity(addrs.len());
    for (index, addr) in addrs.iter().enumerate() {
        position.insert(*addr, index);
    }
    let mut worklist = addrs
        .iter()
        .enumerate()
        .rev()
        .filter(|(index, _)| present[*index])
        .map(|(index, _)| index)
        .collect::<std::collections::VecDeque<_>>();
    let mut queued = vec![true; addrs.len()];
    let mut scratch = vec![0u64; words];
    while let Some(index) = worklist.pop_front() {
        queued[index] = false;
        let addr = addrs[index];
        scratch.iter_mut().for_each(|word| *word = 0);
        for successor in cfg.successors(addr) {
            let Some(successor) = position.get(&successor).copied() else {
                continue;
            };
            let base = successor * words;
            for (word, value) in scratch.iter_mut().zip(&live[base..base + words]) {
                *word |= value;
            }
        }
        for effect in effects[index].iter().rev() {
            match effect.boundary {
                LivenessBoundary::Call => {
                    for number in &clobbered_numbers {
                        scratch[*number as usize / 64] &= !(1u64 << (*number % 64));
                    }
                    for number in &argument_numbers {
                        scratch[*number as usize / 64] |= 1u64 << (*number % 64);
                    }
                }
                LivenessBoundary::Return => {
                    for number in &returned_numbers {
                        scratch[*number as usize / 64] |= 1u64 << (*number % 64);
                    }
                }
                LivenessBoundary::None => {}
            }
            if let Some(number) = effect.kill {
                scratch[number as usize / 64] &= !(1u64 << (number % 64));
            }
            for number in &effect.reads {
                scratch[*number as usize / 64] |= 1u64 << (*number % 64);
            }
        }
        let base = index * words;
        if live[base..base + words] == scratch[..] {
            continue;
        }
        live[base..base + words].copy_from_slice(&scratch);
        for predecessor in cfg.predecessors(addr) {
            let Some(predecessor) = position.get(&predecessor).copied() else {
                continue;
            };
            if present[predecessor] && !queued[predecessor] {
                queued[predecessor] = true;
                worklist.push_back(predecessor);
            }
        }
    }

    let mut live_in = HashMap::with_capacity(addrs.len());
    for (index, addr) in addrs.iter().enumerate() {
        if !present[index] {
            continue;
        }
        let base = index * words;
        let mut set = BTreeSet::new();
        for (word_index, word) in live[base..base + words].iter().enumerate() {
            let mut bits = *word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                set.insert(identities[word_index * 64 + bit].clone());
            }
        }
        live_in.insert(*addr, set);
    }
    live_in
}

/// What one operation does to the liveness of the numbered identities.
struct LivenessOpEffect {
    boundary: LivenessBoundary,
    kill: Option<u32>,
    reads: Vec<u32>,
}

/// The convention's own reads and writes at a call or a return.
enum LivenessBoundary {
    None,
    Call,
    Return,
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
