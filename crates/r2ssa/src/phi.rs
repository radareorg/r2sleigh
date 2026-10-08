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
                // A merge has two or more ways in, the entry included: where
                // the body branches back to it, the entry edge is one of them.
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

    /// Keep only the merges whose identity is live on entry to their block.
    pub fn retain_live(mut self, live_in: &HashMap<u64, BTreeSet<RenameIdentity>>) -> Self {
        for (block, phis) in &mut self.phis {
            let live = live_in.get(block);
            phis.retain(|phi| live.is_some_and(|live| live.contains(&phi.identity)));
        }
        self.phis.retain(|_, phis| !phis.is_empty());
        self
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
pub fn collect_defs_from_cfg_with_names_storage_and_control<C: SsaWorkControl + ?Sized>(
    cfg: &CFG,
    reg_names: Option<&RegisterNameMap>,
    families: Option<&RegisterFamilyInfo>,
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
    if let Some(root) = families.and_then(|families| families.root_slot_for_name(&reg.name)) {
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
    naming: IdentityNaming<'_>,
    defs: &DefinitionSitesByIdentity,
) -> HashMap<u64, BTreeSet<RenameIdentity>> {
    let IdentityNaming {
        reg_names,
        families,
    } = naming;
    let resolve = |regs: &[CanonicalStorageId]| {
        regs.iter()
            .map(|storage| clobber_identity(*storage, reg_names, families))
            .filter(|identity| defs.contains_key(identity))
            .collect::<BTreeSet<_>>()
    };
    // A root a call keeps part of is written in place, like a lane, so the call does not kill it.
    let clobbered = observed_clobbers(call_boundaries, reg_names, families, defs)
        .into_iter()
        .filter(|identity| !call_boundaries.keeps_part_of(identity.storage))
        .collect::<BTreeSet<_>>();
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
    let mut numbering = IdentityNumbers {
        naming,
        identities: Vec::new(),
        numbers: HashMap::new(),
        bases: Vec::new(),
        bits: 0,
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
        let rows = block.ops.iter().map(|op| numbering.effect(op)).collect();
        effects.push(rows);
    }
    // A call or a return reads or writes the whole of each register the
    // convention names.
    let wholes = |set: &BTreeSet<RenameIdentity>| {
        set.iter()
            .filter_map(|identity| numbering.whole(identity))
            .collect::<Vec<_>>()
    };
    let clobbered_bytes = wholes(&clobbered);
    let argument_bytes = wholes(&arguments);
    let returned_bytes = wholes(&returned);
    let IdentityNumbers {
        identities,
        bases,
        bits,
        ..
    } = numbering;

    let words = (bits as usize).div_ceil(64).max(1);
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
                    for bytes in &clobbered_bytes {
                        set_bits(&mut scratch, bytes, false);
                    }
                    for bytes in &argument_bytes {
                        set_bits(&mut scratch, bytes, true);
                    }
                }
                LivenessBoundary::Return => {
                    for bytes in &returned_bytes {
                        set_bits(&mut scratch, bytes, true);
                    }
                }
                LivenessBoundary::None => {}
            }
            if let Some(bytes) = &effect.kill {
                set_bits(&mut scratch, bytes, false);
            }
            for bytes in &effect.reads {
                set_bits(&mut scratch, bytes, true);
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
        let row = &live[base..base + words];
        // An identity is live where any byte of it is.
        let set = identities
            .iter()
            .zip(&bases)
            .filter(|(_, bytes)| any_bit(row, bytes))
            .map(|(identity, _)| identity.clone())
            .collect();
        live_in.insert(*addr, set);
    }
    live_in
}

/// How a varnode is named as a rename identity: the register names and the
/// register families that put a lane inside its root.
#[derive(Debug, Clone, Copy)]
pub struct IdentityNaming<'a> {
    pub reg_names: Option<&'a RegisterNameMap>,
    pub families: Option<&'a RegisterFamilyInfo>,
}

/// Every identity a walk names, numbered in the order first met, with one
/// liveness bit per byte of it.
///
/// Liveness is by byte rather than by identity because a lane is renamed as
/// its root: writing `edx` defines `rdx`'s low four bytes and keeps the rest,
/// and reading `edx` reads only those four. Counted by identity, a lane write
/// ends nothing and a lane read keeps the whole root live, so the root merges
/// wherever any of it was ever written. Counted by byte, a lane write ends
/// the bytes it writes, and the root merges only where some byte is read
/// before it is written again.
struct IdentityNumbers<'a> {
    naming: IdentityNaming<'a>,
    identities: Vec<RenameIdentity>,
    numbers: HashMap<RenameIdentity, u32>,
    /// Each identity's bytes, as a range of bits.
    bases: Vec<std::ops::Range<u32>>,
    bits: u32,
}

impl IdentityNumbers<'_> {
    fn number_identity(&mut self, identity: RenameIdentity) -> u32 {
        if let Some(number) = self.numbers.get(&identity) {
            return *number;
        }
        let number = self.identities.len() as u32;
        let width = identity.storage.size.max(1);
        self.bases.push(self.bits..self.bits + width);
        self.bits += width;
        self.identities.push(identity.clone());
        self.numbers.insert(identity, number);
        number
    }

    /// The bits of the bytes `varnode` covers in the identity it is renamed
    /// as: a lane's own bytes of its root, or the whole of anything else.
    fn bytes(&mut self, varnode: &r2il::Varnode) -> std::ops::Range<u32> {
        let identity =
            RenameIdentity::for_varnode(varnode, self.naming.reg_names, self.naming.families);
        let root = identity.storage;
        let number = self.number_identity(identity);
        let whole = self.bases[number as usize].clone();
        let lane = varnode
            .offset
            .checked_sub(root.offset)
            .and_then(|start| u32::try_from(start).ok())
            .filter(|start| start + varnode.size <= root.size);
        match lane {
            Some(start) if register_root_slot(varnode, self.naming.families).is_some() => {
                whole.start + start..whole.start + start + varnode.size
            }
            _ => whole,
        }
    }

    /// All the bytes of an identity the walk has met; `None` for one it
    /// never met, which no operation reads or writes.
    fn whole(&self, identity: &RenameIdentity) -> Option<std::ops::Range<u32>> {
        let number = self.numbers.get(identity)?;
        Some(self.bases[*number as usize].clone())
    }

    /// What one operation reads and defines, as renaming writes it.
    fn effect(&mut self, op: &r2il::R2ILOp) -> LivenessOpEffect {
        let kill = get_op_output_varnode(op).map(|varnode| self.bytes(varnode));
        let reads = op
            .inputs()
            .into_iter()
            .filter(|varnode| !matches!(varnode.space, r2il::SpaceId::Const))
            .map(|varnode| self.bytes(varnode))
            .collect();
        LivenessOpEffect {
            boundary: match op {
                r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. } => LivenessBoundary::Call,
                r2il::R2ILOp::Return { .. } => LivenessBoundary::Return,
                _ => LivenessBoundary::None,
            },
            kill,
            reads,
        }
    }
}

/// What one operation does to the liveness of the numbered identities.
struct LivenessOpEffect {
    boundary: LivenessBoundary,
    kill: Option<std::ops::Range<u32>>,
    reads: Vec<std::ops::Range<u32>>,
}

/// Set or clear a range of bits.
fn set_bits(words: &mut [u64], bits: &std::ops::Range<u32>, on: bool) {
    for bit in bits.clone() {
        let (word, mask) = (bit as usize / 64, 1u64 << (bit % 64));
        if on {
            words[word] |= mask;
        } else {
            words[word] &= !mask;
        }
    }
}

/// Whether any bit of a range is set.
fn any_bit(words: &[u64], bits: &std::ops::Range<u32>) -> bool {
    bits.clone()
        .any(|bit| words[bit as usize / 64] & (1u64 << (bit % 64)) != 0)
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
