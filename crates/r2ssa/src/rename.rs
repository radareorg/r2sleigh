//! SSA renaming algorithm.
//!
//! This module implements the SSA renaming pass that assigns version numbers
//! to variables, following the algorithm from Cytron et al.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use std::sync::Arc;

use crate::cfg::CFG;
use crate::control::{SsaExecutionStopReason, SsaWorkControl};
use crate::domtree::DomTree;
use crate::function::{RegisterFamilyInfo, RegisterFamilySlot};
use crate::naming::RegisterNameMap;
use crate::op::SSAOp;
use crate::phi::{DefinitionSitesByIdentity, PhiPlacement, RenameIdentity, register_root_slot};
use crate::var::{CanonicalStorageId, CanonicalStorageSpace, SSAVar};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RenameProjection {
    name: String,
    size: u32,
}

impl From<&RenameIdentity> for RenameProjection {
    fn from(identity: &RenameIdentity) -> Self {
        Self {
            name: identity.name.clone(),
            size: identity.size,
        }
    }
}

/// Context for SSA renaming.
#[derive(Debug)]
pub struct RenameContext {
    /// Stack of versions for each exact semantic-name/width/storage identity.
    /// The top of the stack is the current version.
    stacks: HashMap<RenameIdentity, Vec<u32>>,
    /// Collision-free version namespace for the user-facing SSAVar projection.
    counters: HashMap<RenameProjection, u32>,
    /// Dense deterministic discriminator for exact identities whose public
    /// name/width projection is otherwise identical.
    disambiguators: HashMap<RenameIdentity, u32>,
    next_disambiguator: HashMap<RenameProjection, u32>,
    /// The register geometry: a lane renames as a projection of its family's
    /// root (doc/adr-register-identity.md). `None` keeps exact-varnode identities.
    families: Option<Arc<RegisterFamilyInfo>>,
    lanes: LaneState,
}

/// The lane temporaries of the instruction being renamed, and the operations
/// they add around the one the lift wrote.
#[derive(Debug, Default)]
struct LaneState {
    /// (root offset, lane offset, lane width, the temporary holding it).
    temps: Vec<(u64, u64, u32, SSAVar)>,
    /// `Subpiece` reads to place before the operation.
    prefix: Vec<SSAOp>,
    /// `Insert` writes to place after it.
    suffix: Vec<SSAOp>,
    /// Storage for the root values those operations read and write.
    storage: Vec<(SSAVar, CanonicalStorageId)>,
    /// The block and operation index, for the temporaries' names.
    site: (u64, usize),
    serial: u32,
    /// The lane this operation writes is widened into its root later in the
    /// same instruction, so the temporary alone defines it.
    defer_lane_write: bool,
}

/// Decompiler-safe call boundary policy.
#[derive(Debug, Clone, Default)]
pub struct CallBoundaryConfig {
    /// Registers that must receive a fresh SSA definition after a call.
    pub defined_regs: Vec<CallBoundaryDef>,
    /// The carrier the callee puts back where it found it.
    ///
    /// A call instruction's own p-code carries the whole architectural cost of
    /// transferring control: on x86-64 that is `RSP = RSP - 8` and the store of
    /// the return address, on AArch64 a write to the link register and nothing
    /// on the stack. Whatever it spends, the callee's return refunds -- but the
    /// callee is not part of this function, so nothing in the lifted body
    /// refunds it, and the caller's stack pointer drifts by one return-address
    /// slot at every call it makes. Two calls, sixteen bytes; three,
    /// twenty-four. Every stack offset taken after the first call then names
    /// the wrong slot, which is worse than naming none.
    ///
    /// The convention is what states the refund, so this carries a storage only
    /// where the source stated it. `None` leaves the drift visible rather than
    /// correcting it on a guess.
    pub stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
    /// Registers a direct callee's own body proves it leaves untouched, by
    /// callee entry address. A call to such a callee defines none of these:
    /// the value the caller held going in is the value it holds coming out,
    /// which is exactly what a compiler that has seen the callee relies on.
    pub preserved_by_target: BTreeMap<u64, BTreeSet<CanonicalStorageId>>,
    /// The carriers a call reads without naming them in an operand.
    pub argument_regs: Vec<CallBoundaryDef>,
    /// The carriers a return reads without naming them in an operand.
    pub return_regs: Vec<CallBoundaryDef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBoundaryDef {
    pub name: String,
    pub size: u32,
}

impl RenameContext {
    /// Create a new rename context.
    pub fn new() -> Self {
        Self::with_families(None)
    }

    pub fn with_families(families: Option<Arc<RegisterFamilyInfo>>) -> Self {
        Self {
            stacks: HashMap::new(),
            counters: HashMap::new(),
            disambiguators: HashMap::new(),
            next_disambiguator: HashMap::new(),
            families,
            lanes: LaneState::default(),
        }
    }

    fn root_storage(root: RegisterFamilySlot) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: root.offset,
            size: root.width,
        }
    }

    fn lane_lsb_byte(&self, root: RegisterFamilySlot, varnode: &r2il::Varnode) -> u64 {
        self.families
            .as_ref()
            .expect("a lane is found only through its families")
            .lane_lsb_byte(root, varnode.offset, varnode.size)
    }

    fn fresh_lane_temp(&mut self, size: u32) -> SSAVar {
        let (block, op_idx) = self.lanes.site;
        let serial = self.lanes.serial;
        self.lanes.serial += 1;
        SSAVar::new(format!("tmp:lane:{block:x}:{op_idx:x}:{serial:x}"), 1, size)
    }

    /// Start renaming the operation at `site`; a new instruction forgets the
    /// lane temporaries of the last one.
    fn begin_op(&mut self, site: (u64, usize), new_instruction: bool, defer_lane_write: bool) {
        self.lanes.site = site;
        self.lanes.defer_lane_write = defer_lane_write;
        if new_instruction {
            self.lanes.temps.clear();
        }
    }

    /// A read of a lane is a `Subpiece` of its root's current value, shared by
    /// every read of that lane in the instruction.
    fn read_lane(
        &mut self,
        varnode: &r2il::Varnode,
        root: RegisterFamilySlot,
        reg_names: Option<&RegisterNameMap>,
    ) -> SSAVar {
        if let Some((_, _, _, temp)) =
            self.lanes
                .temps
                .iter()
                .find(|(root_offset, offset, width, _)| {
                    *root_offset == root.offset
                        && *offset == varnode.offset
                        && *width == varnode.size
                })
        {
            return temp.clone();
        }
        let identity = RenameIdentity::for_root_slot(root, reg_names);
        let root_value = self.read_var(&identity);
        let temp = self.fresh_lane_temp(varnode.size);
        let offset = self.lane_lsb_byte(root, varnode);
        self.lanes.prefix.push(SSAOp::Subpiece {
            dst: temp.clone(),
            src: root_value.clone(),
            offset: u32::try_from(offset).expect("lane inside its root"),
        });
        self.lanes
            .storage
            .push((root_value, Self::root_storage(root)));
        self.lanes
            .temps
            .push((root.offset, varnode.offset, varnode.size, temp.clone()));
        temp
    }

    /// A write of a lane defines a temporary and, unless the lift widens that
    /// lane into the root later in the instruction, inserts it into the root.
    fn write_lane(
        &mut self,
        varnode: &r2il::Varnode,
        root: RegisterFamilySlot,
        defined_vars: &mut Vec<RenameIdentity>,
        reg_names: Option<&RegisterNameMap>,
    ) -> SSAVar {
        let temp = self.fresh_lane_temp(varnode.size);
        let written_end = varnode.offset + u64::from(varnode.size);
        self.lanes.temps.retain(|(root_offset, offset, width, _)| {
            *root_offset != root.offset
                || *offset >= written_end
                || offset + u64::from(*width) <= varnode.offset
        });
        self.lanes
            .temps
            .push((root.offset, varnode.offset, varnode.size, temp.clone()));
        if self.lanes.defer_lane_write {
            return temp;
        }
        let identity = RenameIdentity::for_root_slot(root, reg_names);
        let before = self.read_var(&identity);
        let after = self.write_var(&identity);
        defined_vars.push(identity);
        let position =
            u32::try_from(self.lane_lsb_byte(root, varnode) * 8).expect("lane inside its root");
        self.lanes.suffix.push(SSAOp::Insert {
            dst: after.clone(),
            src: before.clone(),
            value: temp.clone(),
            position: SSAVar::constant(u64::from(position), 4),
        });
        let storage = Self::root_storage(root);
        self.lanes.storage.push((before, storage));
        self.lanes.storage.push((after, storage));
        temp
    }

    /// A write of a whole root ends what its lanes' temporaries stood for.
    fn forget_lanes_of(&mut self, varnode: &r2il::Varnode) {
        if matches!(varnode.space, r2il::SpaceId::Register) {
            self.lanes
                .temps
                .retain(|(root_offset, ..)| *root_offset != varnode.offset);
        }
    }

    /// Initialize one exact rename identity.
    pub fn init_identity(&mut self, identity: RenameIdentity) {
        let projection = RenameProjection::from(&identity);
        if !self.disambiguators.contains_key(&identity) {
            let next = self
                .next_disambiguator
                .entry(projection.clone())
                .or_insert(0);
            self.disambiguators.insert(identity.clone(), *next);
            *next = next.checked_add(1).expect("rename discriminator exhausted");
        }
        // Start with version 0 on the stack (representing "undefined" or function entry)
        self.stacks
            .entry(identity.clone())
            .or_insert_with(|| vec![0]);
        self.counters.entry(projection).or_insert(0);
    }

    /// Get the current version of a variable (for reading).
    pub fn current_version(&self, identity: &RenameIdentity) -> u32 {
        self.stacks
            .get(identity)
            .and_then(|stack| stack.last().copied())
            .unwrap_or(0)
    }

    /// Generate a new version of a variable (for writing).
    pub fn new_version(&mut self, identity: &RenameIdentity) -> u32 {
        let counter = self
            .counters
            .entry(RenameProjection::from(identity))
            .or_insert(0);
        *counter += 1;
        let version = *counter;
        self.stacks
            .entry(identity.clone())
            .or_default()
            .push(version);
        version
    }

    /// Pop a version from a variable's stack (when leaving a block's scope).
    pub fn pop_version(&mut self, identity: &RenameIdentity) {
        if let Some(stack) = self.stacks.get_mut(identity) {
            stack.pop();
        }
    }

    /// Create an SSAVar for reading one exact rename identity.
    pub fn read_var(&self, identity: &RenameIdentity) -> SSAVar {
        self.var_at(identity, self.current_version(identity))
    }

    fn var_at(&self, identity: &RenameIdentity, version: u32) -> SSAVar {
        identity.as_var(
            version,
            self.disambiguators.get(identity).copied().unwrap_or(0),
        )
    }

    /// Create an SSAVar for writing one exact rename identity.
    pub fn write_var(&mut self, identity: &RenameIdentity) -> SSAVar {
        let disambiguator = self.disambiguators.get(identity).copied().unwrap_or(0);
        identity.as_var(self.new_version(identity), disambiguator)
    }

    /// Whether this identity has a version stack, meaning the body defines it.
    pub fn knows_identity(&self, identity: &RenameIdentity) -> bool {
        self.stacks.contains_key(identity)
    }

    /// Find initialized identities with this register spelling and exact width.
    pub fn matching_identities_ci(&self, name: &str, size: u32) -> Vec<RenameIdentity> {
        let needle = name.to_ascii_lowercase();
        let mut matches: Vec<RenameIdentity> = self
            .stacks
            .keys()
            .filter(|candidate| {
                candidate.size == size && candidate.name.to_ascii_lowercase() == needle
            })
            .cloned()
            .collect();
        matches.sort_unstable();
        matches
    }
}

impl Default for RenameContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of renaming a function.
#[derive(Debug, Clone)]
pub struct RenamedFunction {
    /// SSA operations for each block (block addr -> ops).
    pub blocks: HashMap<u64, Vec<SSAOp>>,
    /// Block addresses in order.
    pub block_order: Vec<u64>,
    /// Lifted storage provenance for SSA values.
    ///
    /// This map is populated directly from source varnodes while renaming. A
    /// display name is only the key that associates the already-proven source
    /// identity with its SSA version; it is never parsed or resolved through
    /// architecture register names.
    pub canonical_storage_by_var: BTreeMap<SSAVar, CanonicalStorageId>,
    ambiguous_storage_vars: BTreeSet<SSAVar>,
}

impl RenamedFunction {
    /// Create a new empty renamed function.
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            block_order: Vec::new(),
            canonical_storage_by_var: BTreeMap::new(),
            ambiguous_storage_vars: BTreeSet::new(),
        }
    }
}

/// Perform SSA renaming while polling its block and operation worklists.
#[allow(clippy::too_many_arguments)]
pub fn rename_function_with_names_and_call_boundaries_and_control<C: SsaWorkControl + ?Sized>(
    cfg: &CFG,
    domtree: &DomTree,
    phi_placement: &PhiPlacement,
    definitions: &DefinitionSitesByIdentity,
    reg_names: Option<&RegisterNameMap>,
    families: Option<Arc<RegisterFamilyInfo>>,
    call_boundaries: Option<&CallBoundaryConfig>,
    control: &C,
) -> Result<RenamedFunction, SsaExecutionStopReason> {
    control.poll()?;
    let mut ctx = RenameContext::with_families(families);
    let mut result = RenamedFunction::new();

    // Initialize all variables
    for identity in definitions.keys() {
        control.poll()?;
        ctx.init_identity(identity.clone());
    }

    // Also initialize variables from phi nodes
    let mut phi_blocks: Vec<u64> = phi_placement.phis.keys().copied().collect();
    phi_blocks.sort_unstable();
    for block_addr in phi_blocks {
        control.poll()?;
        for phi in phi_placement.get_phis(block_addr) {
            control.poll()?;
            ctx.init_identity(phi.identity.clone());
        }
    }

    // The convention names the carrier a call leaves alone; renaming needs the
    // identity that carrier was lifted as.
    let stack_pointer_identity = call_boundaries
        .and_then(|boundary| boundary.stack_pointer_restored_by_callee)
        .and_then(|storage| sole_identity_on_storage(definitions, storage));

    // Get block order (reverse postorder for dominator tree traversal)
    result.block_order = cfg.reverse_postorder();

    // Initialize empty blocks
    for &addr in &result.block_order {
        control.poll()?;
        result.blocks.insert(addr, Vec::new());
    }

    // Prepopulate phi placeholders so predecessor-edge source propagation can update them
    // even if the merge block is renamed later in dominator traversal.
    for &addr in &result.block_order {
        control.poll()?;
        let block_ops = result.blocks.get_mut(&addr).expect("preinitialized block");
        for phi in phi_placement.get_phis(addr) {
            control.poll()?;
            let sources: Vec<SSAVar> = phi
                .predecessors
                .iter()
                .map(|_| ctx.var_at(&phi.identity, 0))
                .collect();
            block_ops.push(SSAOp::Phi {
                dst: ctx.var_at(&phi.identity, 0),
                sources,
            });
        }
    }

    // Rename starting from entry block using dominator tree traversal.
    rename_block(
        cfg.entry,
        cfg,
        domtree,
        phi_placement,
        &mut ctx,
        &mut result,
        reg_names,
        call_boundaries,
        stack_pointer_identity.as_ref(),
        control,
    )?;

    control.poll()?;
    Ok(result)
}

/// The one identity lifted onto this exact storage, when there is exactly one.
///
/// Storage is the structural identity and the name beside it is presentation.
/// Two identities sharing a storage means the lift disagreed with itself about
/// what that location is; restoring one of them would assert the callee wrote
/// through a location it may not have, so this declines instead.
fn sole_identity_on_storage(
    definitions: &DefinitionSitesByIdentity,
    storage: CanonicalStorageId,
) -> Option<RenameIdentity> {
    let mut matches = definitions
        .keys()
        .filter(|identity| identity.storage == storage);
    let identity = matches.next()?;
    matches.next().is_none().then(|| identity.clone())
}

/// Rename a block and its dominated descendants.
#[allow(clippy::too_many_arguments)]
fn rename_block<C: SsaWorkControl + ?Sized>(
    block_addr: u64,
    cfg: &CFG,
    domtree: &DomTree,
    phi_placement: &PhiPlacement,
    ctx: &mut RenameContext,
    result: &mut RenamedFunction,
    reg_names: Option<&RegisterNameMap>,
    call_boundaries: Option<&CallBoundaryConfig>,
    stack_pointer_identity: Option<&RenameIdentity>,
    control: &C,
) -> Result<(), SsaExecutionStopReason> {
    // An exit frame keeps each block's definitions live until all dominated
    // children have been renamed, matching the recursive traversal's scope.
    let mut stack: Vec<(u64, Option<Vec<RenameIdentity>>)> = vec![(block_addr, None)];
    while let Some((block_addr, exit_defs)) = stack.pop() {
        control.poll()?;
        if let Some(defined_vars) = exit_defs {
            for var in defined_vars {
                ctx.pop_version(&var);
            }
            continue;
        }

        // Track variables defined in this block for cleanup.
        let mut defined_vars: Vec<RenameIdentity> = Vec::new();

        // 1. Rename phi node destinations.
        let phis = phi_placement.get_phis(block_addr);
        let block_ops = result
            .blocks
            .get_mut(&block_addr)
            .expect("preinitialized block");
        for (phi_idx, phi) in phis.iter().enumerate() {
            control.poll()?;
            let dst = ctx.write_var(&phi.identity);
            if let Some(storage) = phi.storage {
                record_canonical_storage(
                    &mut result.canonical_storage_by_var,
                    &mut result.ambiguous_storage_vars,
                    &dst,
                    storage,
                );
            }
            defined_vars.push(phi.identity.clone());

            // Update the precreated placeholder so predecessor-edge propagation can land
            // before or after the merge block is renamed.
            match block_ops.get_mut(phi_idx) {
                Some(SSAOp::Phi {
                    dst: existing_dst,
                    sources,
                }) => {
                    *existing_dst = dst;
                    if sources.len() != phi.predecessors.len() {
                        *sources = phi
                            .predecessors
                            .iter()
                            .map(|_| ctx.var_at(&phi.identity, 0))
                            .collect();
                    }
                }
                _ => {
                    let sources: Vec<SSAVar> = phi
                        .predecessors
                        .iter()
                        .map(|_| ctx.var_at(&phi.identity, 0))
                        .collect();
                    block_ops.insert(phi_idx, SSAOp::Phi { dst, sources });
                }
            }
        }

        // 2. Rename operations in the block.
        if let Some(block) = cfg.get_block(block_addr) {
            // The carrier as the call instruction found it, before that
            // instruction's own p-code spent anything transferring control.
            // Restoring to this needs no per-architecture quantity: whatever
            // the machine moved is exactly what the callee brings back.
            let mut instruction_addr: Option<u64> = None;
            let mut carrier_entering_instruction: Option<SSAVar> = None;
            let mut lane_instruction: Option<Option<u64>> = None;
            for (op_idx, op) in block.ops.iter().enumerate() {
                control.poll()?;
                let op_addr = block.op_instruction_addr(op_idx);
                if let Some(identity) = stack_pointer_identity
                    && op_addr.is_some()
                    && op_addr != instruction_addr
                {
                    instruction_addr = op_addr;
                    carrier_entering_instruction = Some(ctx.read_var(identity));
                }
                // An op without an instruction address is an instruction of
                // its own for the lane temporaries.
                let new_instruction = op_addr.is_none() || lane_instruction != Some(op_addr);
                lane_instruction = Some(op_addr);
                ctx.begin_op(
                    (block_addr, op_idx),
                    new_instruction,
                    lane_write_widened_later(block, op_idx, ctx.families.as_deref()),
                );
                let renamed_op = rename_op(op, op_addr, ctx, &mut defined_vars, reg_names);
                let block_ops = result.blocks.get_mut(&block_addr).unwrap();
                block_ops.append(&mut ctx.lanes.prefix);
                let boundary_reads =
                    if matches!(op, r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. })
                        && let Some(boundary) = call_boundaries
                    {
                        append_call_boundary_reads(block_ops, ctx, boundary, reg_names)
                    } else {
                        Vec::new()
                    };
                record_renamed_op_storage(op, &renamed_op, result);
                for (var, storage) in boundary_reads {
                    record_canonical_storage(
                        &mut result.canonical_storage_by_var,
                        &mut result.ambiguous_storage_vars,
                        &var,
                        storage,
                    );
                }
                let block_ops = result.blocks.get_mut(&block_addr).unwrap();
                block_ops.push(renamed_op);
                block_ops.append(&mut ctx.lanes.suffix);
                for (var, storage) in ctx.lanes.storage.drain(..) {
                    record_canonical_storage(
                        &mut result.canonical_storage_by_var,
                        &mut result.ambiguous_storage_vars,
                        &var,
                        storage,
                    );
                }

                if matches!(op, r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. })
                    && let Some(boundary) = call_boundaries
                {
                    // Only a direct call names a callee whose body may have
                    // been read; anything else defines the whole list.
                    let preserved = match op {
                        r2il::R2ILOp::Call { target } if target.is_ram() => {
                            boundary.preserved_by_target.get(&target.offset)
                        }
                        _ => None,
                    };
                    let boundary_defs = append_call_boundary_defs(
                        &mut result.blocks,
                        block_addr,
                        ctx,
                        &mut defined_vars,
                        boundary,
                        preserved,
                        reg_names,
                    );
                    for (dst, storage) in boundary_defs {
                        record_canonical_storage(
                            &mut result.canonical_storage_by_var,
                            &mut result.ambiguous_storage_vars,
                            &dst,
                            storage,
                        );
                    }
                }

                // After the clobbers, not before them: the run of `CallDefine`
                // directly following a call is how a result is found, and an
                // operation in the middle of it ends that run early.
                if matches!(op, r2il::R2ILOp::Call { .. } | r2il::R2ILOp::CallInd { .. })
                    && let (Some(identity), Some(entering)) = (
                        stack_pointer_identity,
                        carrier_entering_instruction.as_ref(),
                    )
                    && ctx.read_var(identity) != *entering
                {
                    // Only where this instruction moved the carrier. An
                    // AArch64 `bl` writes the link register and leaves the
                    // stack alone, so there is nothing to bring back; defining
                    // the carrier anyway would add a definition to a block that
                    // has none, which phi placement was computed without.
                    let dst = ctx.write_var(identity);
                    defined_vars.push(identity.clone());
                    result
                        .blocks
                        .get_mut(&block_addr)
                        .unwrap()
                        .push(SSAOp::CallRestore {
                            dst: dst.clone(),
                            src: entering.clone(),
                        });
                    record_canonical_storage(
                        &mut result.canonical_storage_by_var,
                        &mut result.ambiguous_storage_vars,
                        &dst,
                        identity.storage,
                    );
                }
            }
        }

        // 3. Fill in phi sources in successor blocks.
        for succ_addr in cfg.successors(block_addr) {
            control.poll()?;
            fill_phi_sources(block_addr, succ_addr, phi_placement, ctx, result);
        }

        // 4. Rename dominated children before leaving this block's scope.
        stack.push((block_addr, Some(defined_vars)));
        for &child in domtree.children(block_addr).iter().rev() {
            stack.push((child, None));
        }
    }
    Ok(())
}

/// Whether a value is a lane temporary: a projection of a register root with
/// no storage of its own.
pub(crate) fn is_lane_temp(var: &SSAVar) -> bool {
    var.name.starts_with("tmp:lane:")
}

/// The lane this operation writes is superseded within the instruction: a
/// later operation writes the whole root -- the lift's own `IntZExt`, or the
/// select a guarded write became -- before anything reads the root, so the
/// root's definition is that operation's and the lane needs no insert.
fn lane_write_widened_later(
    block: &crate::cfg::BasicBlock,
    op_idx: usize,
    families: Option<&RegisterFamilyInfo>,
) -> bool {
    let Some(lane) = block.ops[op_idx].output() else {
        return false;
    };
    let Some(root) = register_root_slot(lane, families) else {
        return false;
    };
    let Some(instruction) = block.op_instruction_addr(op_idx) else {
        return false;
    };
    let root_end = root.offset + u64::from(root.width);
    let overlaps_root = |varnode: &r2il::Varnode| {
        matches!(varnode.space, r2il::SpaceId::Register)
            && varnode.offset < root_end
            && varnode.offset + u64::from(varnode.size) > root.offset
    };
    let is_lane = |varnode: &r2il::Varnode| {
        varnode.space == lane.space && varnode.offset == lane.offset && varnode.size == lane.size
    };
    for later_idx in op_idx + 1..block.ops.len() {
        if block.op_instruction_addr(later_idx) != Some(instruction) {
            return false;
        }
        let later = &block.ops[later_idx];
        // A read of the root, or of any other lane of it, needs the insert.
        if later
            .inputs()
            .iter()
            .any(|input| overlaps_root(input) && !is_lane(input))
        {
            return false;
        }
        if later.output().is_some_and(|out| {
            matches!(out.space, r2il::SpaceId::Register)
                && out.offset == root.offset
                && out.size == root.width
        }) {
            return true;
        }
    }
    false
}

fn record_renamed_op_storage(source: &r2il::R2ILOp, renamed: &SSAOp, result: &mut RenamedFunction) {
    if let (Some(varnode), Some(var)) = (source.output(), renamed.dst())
        && !is_lane_temp(var)
    {
        record_canonical_storage(
            &mut result.canonical_storage_by_var,
            &mut result.ambiguous_storage_vars,
            var,
            CanonicalStorageId::from_varnode(varnode),
        );
    }

    let source_inputs = source.inputs();
    let renamed_inputs = renamed.sources();
    if source_inputs.len() != renamed_inputs.len() {
        // A mismatched operation contract cannot safely attach positional
        // provenance. Leaving these values unbound makes proof consumers fail
        // closed rather than assigning the wrong storage identity.
        return;
    }
    for (varnode, var) in source_inputs.into_iter().zip(renamed_inputs) {
        if is_lane_temp(var) {
            continue;
        }
        record_canonical_storage(
            &mut result.canonical_storage_by_var,
            &mut result.ambiguous_storage_vars,
            var,
            CanonicalStorageId::from_varnode(varnode),
        );
    }
}

fn record_canonical_storage(
    storage_by_var: &mut BTreeMap<SSAVar, CanonicalStorageId>,
    ambiguous_vars: &mut BTreeSet<SSAVar>,
    var: &SSAVar,
    storage: CanonicalStorageId,
) {
    if ambiguous_vars.contains(var) {
        return;
    }
    if storage_by_var
        .get(var)
        .is_some_and(|existing| *existing != storage)
    {
        storage_by_var.remove(var);
        ambiguous_vars.insert(var.clone());
        return;
    }
    storage_by_var.insert(var.clone(), storage);
}

fn append_call_boundary_defs(
    blocks: &mut HashMap<u64, Vec<SSAOp>>,
    block_addr: u64,
    ctx: &mut RenameContext,
    defined_vars: &mut Vec<RenameIdentity>,
    call_boundaries: &CallBoundaryConfig,
    preserved_by_callee: Option<&BTreeSet<CanonicalStorageId>>,
    reg_names: Option<&RegisterNameMap>,
) -> Vec<(SSAVar, CanonicalStorageId)> {
    let Some(block_ops) = blocks.get_mut(&block_addr) else {
        return Vec::new();
    };
    let mut retained = Vec::new();

    // Every width the convention names a register at is one family, and the
    // callee clobbers its root once.
    let mut clobbered: BTreeSet<RenameIdentity> = BTreeSet::new();
    for reg in &call_boundaries.defined_regs {
        let mut actual_identities: BTreeSet<RenameIdentity> = match ctx
            .families
            .as_deref()
            .and_then(|families| families.widest_slot_for_name(&reg.name))
        {
            Some(root) => BTreeSet::from([RenameIdentity::for_root_slot(root, reg_names)]),
            None => ctx
                .matching_identities_ci(&reg.name, reg.size)
                .into_iter()
                .collect(),
        };
        if actual_identities.is_empty()
            && let Some(reg_names) = reg_names
        {
            for ((offset, size), candidate) in reg_names {
                if *size == reg.size && candidate.eq_ignore_ascii_case(&reg.name) {
                    actual_identities.insert(RenameIdentity::new(
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
        if actual_identities.is_empty() {
            actual_identities.insert(RenameIdentity::synthetic(&reg.name, reg.size));
        }
        clobbered.extend(actual_identities);
    }
    for identity in clobbered {
        let storage = identity.storage;
        if preserved_by_callee.is_some_and(|preserved| preserved.contains(&storage)) {
            continue;
        }
        ctx.init_identity(identity.clone());
        let dst = ctx.write_var(&identity);
        defined_vars.push(identity);
        if matches!(storage.space, crate::CanonicalStorageSpace::Register) {
            retained.push((dst.clone(), storage));
        }
        block_ops.push(SSAOp::CallDefine { dst });
    }
    retained
}

/// Emit the reads a call boundary makes, before the call itself.
///
/// Before, because the reaching definition of an argument carrier is the one
/// standing at the call, and because the run of `CallDefine` that follows a
/// call is how a result is found -- anything inserted into that run ends it
/// early for the five scans that read it.
///
/// Only carriers the body already defines are read. A call in a function that
/// never writes the carrier would otherwise read an entry value with no
/// producer, which is one step from a parameter the function does not have.
fn append_call_boundary_reads(
    block_ops: &mut Vec<SSAOp>,
    ctx: &RenameContext,
    call_boundaries: &CallBoundaryConfig,
    reg_names: Option<&RegisterNameMap>,
) -> Vec<(SSAVar, CanonicalStorageId)> {
    let mut read: BTreeSet<RenameIdentity> = BTreeSet::new();
    for reg in &call_boundaries.argument_regs {
        match ctx
            .families
            .as_deref()
            .and_then(|families| families.widest_slot_for_name(&reg.name))
        {
            Some(root) => {
                let identity = RenameIdentity::for_root_slot(root, reg_names);
                if ctx.knows_identity(&identity) {
                    read.insert(identity);
                }
            }
            None => read.extend(ctx.matching_identities_ci(&reg.name, reg.size)),
        }
    }
    let mut retained = Vec::new();
    for identity in read {
        let src = ctx.read_var(&identity);
        if matches!(
            identity.storage.space,
            crate::CanonicalStorageSpace::Register
        ) {
            retained.push((src.clone(), identity.storage));
        }
        block_ops.push(SSAOp::CallUse { src });
    }
    retained
}

/// Fill in phi sources for a successor block.
fn fill_phi_sources(
    pred_addr: u64,
    succ_addr: u64,
    phi_placement: &PhiPlacement,
    ctx: &RenameContext,
    result: &mut RenamedFunction,
) {
    let phis = phi_placement.get_phis(succ_addr);
    if phis.is_empty() {
        return;
    }

    // Find the index of this predecessor
    let pred_idx = phis
        .first()
        .and_then(|phi| phi.predecessors.iter().position(|&p| p == pred_addr));

    let Some(pred_idx) = pred_idx else {
        return;
    };

    let incoming = phis
        .iter()
        .map(|phi| {
            let source = ctx.read_var(&phi.identity);
            if let Some(storage) = phi.storage
                && storage.size == source.size
            {
                record_canonical_storage(
                    &mut result.canonical_storage_by_var,
                    &mut result.ambiguous_storage_vars,
                    &source,
                    storage,
                );
            }
            source
        })
        .collect::<Vec<_>>();

    // Update phi sources in the result
    let block_ops = result.blocks.get_mut(&succ_addr).unwrap();
    let mut phi_idx = 0;

    for op in block_ops.iter_mut() {
        if let SSAOp::Phi { sources, .. } = op
            && phi_idx < phis.len()
        {
            if pred_idx < sources.len() {
                sources[pred_idx] = incoming[phi_idx].clone();
            }
            phi_idx += 1;
        }
    }
}

/// Rename a single r2il operation to an SSA operation.
fn write_varnode(
    varnode: &r2il::Varnode,
    ctx: &mut RenameContext,
    defined_vars: &mut Vec<RenameIdentity>,
    reg_names: Option<&RegisterNameMap>,
) -> SSAVar {
    if let Some(root) = register_root_slot(varnode, ctx.families.as_deref()) {
        return ctx.write_lane(varnode, root, defined_vars, reg_names);
    }
    ctx.forget_lanes_of(varnode);
    let identity = RenameIdentity::from_varnode(varnode, reg_names);
    let renamed = ctx.write_var(&identity);
    defined_vars.push(identity);
    renamed
}

fn rename_op(
    op: &r2il::R2ILOp,
    instruction: Option<u64>,
    ctx: &mut RenameContext,
    defined_vars: &mut Vec<RenameIdentity>,
    reg_names: Option<&RegisterNameMap>,
) -> SSAOp {
    use r2il::R2ILOp::*;

    match op {
        Copy { dst, src } => {
            let src_ssa = read_varnode(src, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Copy {
                dst: dst_ssa,
                src: src_ssa,
            }
        }

        Load { dst, addr, space } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Load {
                dst: dst_ssa,
                addr: addr_ssa,
                space: *space,
            }
        }

        Store { addr, val, space } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let val_ssa = read_varnode(val, ctx, reg_names);
            SSAOp::Store {
                addr: addr_ssa,
                val: val_ssa,
                space: *space,
            }
        }
        BlockTransfer {
            space,
            kind,
            destination,
            source,
            count,
            direction,
            element_size,
        } => SSAOp::BlockTransfer {
            space: *space,
            kind: *kind,
            destination: read_varnode(destination, ctx, reg_names),
            source: read_varnode(source, ctx, reg_names),
            count: read_varnode(count, ctx, reg_names),
            direction: read_varnode(direction, ctx, reg_names),
            element_size: *element_size,
        },
        Fence { ordering } => SSAOp::Fence {
            ordering: *ordering,
        },
        LoadLinked {
            dst,
            addr,
            space,
            ordering,
        } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::LoadLinked {
                dst: dst_ssa,
                addr: addr_ssa,
                space: *space,
                ordering: *ordering,
            }
        }
        StoreConditional {
            result,
            addr,
            val,
            space,
            ordering,
        } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let val_ssa = read_varnode(val, ctx, reg_names);
            let result_ssa = result
                .as_ref()
                .map(|r| write_varnode(r, ctx, defined_vars, reg_names));
            SSAOp::StoreConditional {
                result: result_ssa,
                addr: addr_ssa,
                val: val_ssa,
                space: *space,
                ordering: *ordering,
            }
        }
        AtomicCAS {
            dst,
            addr,
            expected,
            replacement,
            space,
            ordering,
        } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let expected_ssa = read_varnode(expected, ctx, reg_names);
            let replacement_ssa = read_varnode(replacement, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::AtomicCAS {
                dst: dst_ssa,
                space: *space,
                addr: addr_ssa,
                expected: expected_ssa,
                replacement: replacement_ssa,
                ordering: *ordering,
            }
        }
        LoadGuarded {
            dst,
            addr,
            guard,
            space,
            ordering,
        } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let guard_ssa = read_varnode(guard, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::LoadGuarded {
                dst: dst_ssa,
                addr: addr_ssa,
                guard: guard_ssa,
                space: *space,
                ordering: *ordering,
            }
        }
        StoreGuarded {
            addr,
            val,
            guard,
            space,
            ordering,
        } => {
            let addr_ssa = read_varnode(addr, ctx, reg_names);
            let val_ssa = read_varnode(val, ctx, reg_names);
            let guard_ssa = read_varnode(guard, ctx, reg_names);
            SSAOp::StoreGuarded {
                space: *space,
                addr: addr_ssa,
                val: val_ssa,
                guard: guard_ssa,
                ordering: *ordering,
            }
        }

        Branch { target } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            SSAOp::Branch {
                target: target_ssa,
                instruction,
            }
        }

        CBranch { target, cond } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            let cond_ssa = read_varnode(cond, ctx, reg_names);
            SSAOp::CBranch {
                target: target_ssa,
                cond: cond_ssa,
            }
        }

        BranchInd { target } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            SSAOp::BranchInd {
                target: target_ssa,
                instruction,
            }
        }

        Call { target } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            SSAOp::Call {
                target: target_ssa,
                instruction,
            }
        }

        CallInd { target } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            SSAOp::CallInd {
                target: target_ssa,
                instruction,
            }
        }

        Return { target } => {
            let target_ssa = read_varnode(target, ctx, reg_names);
            SSAOp::Return { target: target_ssa }
        }

        IntAdd { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntAdd {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSub { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSub {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntMult { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntMult {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntDiv { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntDiv {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSDiv { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSDiv {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntRem { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntRem {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSRem { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSRem {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntAnd { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntAnd {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntOr { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntOr {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntXor { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntXor {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntLeft { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntLeft {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntRight { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntRight {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSRight { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSRight {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntNotEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntNotEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntLess { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntLess {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSLess { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSLess {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntLessEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntLessEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSLessEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSLessEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntCarry { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntCarry {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSCarry { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSCarry {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntSBorrow { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::IntSBorrow {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        IntNegate { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::IntNegate { dst: d, src: s }
            })
        }

        IntNot { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::IntNot { dst: d, src: s }
        }),

        IntZExt { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::IntZExt { dst: d, src: s }
        }),

        IntSExt { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::IntSExt { dst: d, src: s }
        }),

        BoolNot { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::BoolNot { dst: d, src: s }
        }),

        BoolAnd { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::BoolAnd {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        BoolOr { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::BoolOr {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        BoolXor { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::BoolXor {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        Piece { dst, hi, lo } => {
            let hi_ssa = read_varnode(hi, ctx, reg_names);
            let lo_ssa = read_varnode(lo, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Piece {
                dst: dst_ssa,
                hi: hi_ssa,
                lo: lo_ssa,
            }
        }

        Subpiece { dst, src, offset } => {
            let src_ssa = read_varnode(src, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Subpiece {
                dst: dst_ssa,
                src: src_ssa,
                offset: *offset,
            }
        }

        PopCount { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::PopCount { dst: d, src: s }
        }),

        Lzcount { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::Lzcount { dst: d, src: s }
        }),

        // Floating point operations
        FloatAdd { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatAdd {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatSub { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatSub {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatMult { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatMult {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatDiv { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatDiv {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatNeg { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::FloatNeg { dst: d, src: s }
        }),

        FloatAbs { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::FloatAbs { dst: d, src: s }
        }),

        FloatSqrt { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::FloatSqrt { dst: d, src: s }
            })
        }

        FloatCeil { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::FloatCeil { dst: d, src: s }
            })
        }

        FloatFloor { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::FloatFloor { dst: d, src: s }
            })
        }

        FloatRound { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::FloatRound { dst: d, src: s }
            })
        }

        FloatNaN { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::FloatNaN { dst: d, src: s }
        }),

        FloatEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatNotEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatNotEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatLess { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatLess {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        FloatLessEqual { dst, a, b } => {
            rename_binary_op(dst, a, b, ctx, defined_vars, reg_names, |d, s1, s2| {
                SSAOp::FloatLessEqual {
                    dst: d,
                    a: s1,
                    b: s2,
                }
            })
        }

        Int2Float { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::Int2Float { dst: d, src: s }
            })
        }

        Float2Int { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::Float2Int { dst: d, src: s }
            })
        }

        FloatFloat { dst, src } => {
            rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
                SSAOp::FloatFloat { dst: d, src: s }
            })
        }

        Trunc { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::Trunc { dst: d, src: s }
        }),

        Nop => SSAOp::Nop,

        Unimplemented => SSAOp::Unimplemented,

        Breakpoint => SSAOp::Breakpoint,

        CpuId { dst } => {
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::CpuId { dst: dst_ssa }
        }

        CallOther {
            output,
            userop,
            inputs,
        } => {
            let inputs_ssa: Vec<SSAVar> = inputs
                .iter()
                .map(|v| read_varnode(v, ctx, reg_names))
                .collect();
            let output_ssa = output
                .as_ref()
                .map(|v| write_varnode(v, ctx, defined_vars, reg_names));
            SSAOp::CallOther {
                output: output_ssa,
                userop: *userop,
                inputs: inputs_ssa,
            }
        }

        Multiequal { dst, inputs } => {
            let inputs_ssa: Vec<SSAVar> = inputs
                .iter()
                .map(|v| read_varnode(v, ctx, reg_names))
                .collect();
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Phi {
                dst: dst_ssa,
                sources: inputs_ssa,
            }
        }

        Indirect {
            dst,
            src,
            indirect: _,
        } => {
            // Indirect is used for aliasing - treat as a copy for SSA purposes
            let src_ssa = read_varnode(src, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Copy {
                dst: dst_ssa,
                src: src_ssa,
            }
        }

        PtrAdd {
            dst,
            base,
            index,
            element_size,
        } => {
            let base_ssa = read_varnode(base, ctx, reg_names);
            let index_ssa = read_varnode(index, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::PtrAdd {
                dst: dst_ssa,
                base: base_ssa,
                index: index_ssa,
                element_size: *element_size,
            }
        }

        PtrSub {
            dst,
            base,
            index,
            element_size,
        } => {
            let base_ssa = read_varnode(base, ctx, reg_names);
            let index_ssa = read_varnode(index, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::PtrSub {
                dst: dst_ssa,
                base: base_ssa,
                index: index_ssa,
                element_size: *element_size,
            }
        }

        SegmentOp {
            dst,
            segment,
            offset,
        } => {
            let seg_ssa = read_varnode(segment, ctx, reg_names);
            let off_ssa = read_varnode(offset, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::SegmentOp {
                dst: dst_ssa,
                segment: seg_ssa,
                offset: off_ssa,
            }
        }

        New { dst, src } => {
            let src_ssa = read_varnode(src, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::New {
                dst: dst_ssa,
                src: src_ssa,
            }
        }

        Cast { dst, src } => rename_unary_op(dst, src, ctx, defined_vars, reg_names, |d, s| {
            SSAOp::Cast { dst: d, src: s }
        }),

        Extract { dst, src, position } => {
            let src_ssa = read_varnode(src, ctx, reg_names);
            let pos_ssa = read_varnode(position, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Extract {
                dst: dst_ssa,
                src: src_ssa,
                position: pos_ssa,
            }
        }

        Insert {
            dst,
            src,
            value,
            position,
        } => {
            let src_ssa = read_varnode(src, ctx, reg_names);
            let val_ssa = read_varnode(value, ctx, reg_names);
            let pos_ssa = read_varnode(position, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Insert {
                dst: dst_ssa,
                src: src_ssa,
                value: val_ssa,
                position: pos_ssa,
            }
        }

        Select {
            dst,
            cond,
            if_true,
            if_false,
        } => {
            let cond_ssa = read_varnode(cond, ctx, reg_names);
            let true_ssa = read_varnode(if_true, ctx, reg_names);
            let false_ssa = read_varnode(if_false, ctx, reg_names);
            let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
            SSAOp::Select {
                dst: dst_ssa,
                cond: cond_ssa,
                if_true: true_ssa,
                if_false: false_ssa,
            }
        }
    }
}

/// Helper for renaming binary operations.
fn rename_binary_op<F>(
    dst: &r2il::Varnode,
    src1: &r2il::Varnode,
    src2: &r2il::Varnode,
    ctx: &mut RenameContext,
    defined_vars: &mut Vec<RenameIdentity>,
    reg_names: Option<&RegisterNameMap>,
    f: F,
) -> SSAOp
where
    F: FnOnce(SSAVar, SSAVar, SSAVar) -> SSAOp,
{
    let src1_ssa = read_varnode(src1, ctx, reg_names);
    let src2_ssa = read_varnode(src2, ctx, reg_names);
    let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
    f(dst_ssa, src1_ssa, src2_ssa)
}

/// Helper for renaming unary operations.
fn rename_unary_op<F>(
    dst: &r2il::Varnode,
    src: &r2il::Varnode,
    ctx: &mut RenameContext,
    defined_vars: &mut Vec<RenameIdentity>,
    reg_names: Option<&RegisterNameMap>,
    f: F,
) -> SSAOp
where
    F: FnOnce(SSAVar, SSAVar) -> SSAOp,
{
    let src_ssa = read_varnode(src, ctx, reg_names);
    let dst_ssa = write_varnode(dst, ctx, defined_vars, reg_names);
    f(dst_ssa, src_ssa)
}

/// Read a varnode and return an SSAVar.
fn read_varnode(
    vn: &r2il::Varnode,
    ctx: &mut RenameContext,
    reg_names: Option<&RegisterNameMap>,
) -> SSAVar {
    use r2il::SpaceId;

    match vn.space {
        SpaceId::Const => {
            // Constants don't need versioning
            SSAVar::constant(vn.offset, vn.size)
        }
        _ => {
            if let Some(root) = register_root_slot(vn, ctx.families.as_deref()) {
                return ctx.read_lane(vn, root, reg_names);
            }
            let identity = RenameIdentity::from_varnode(vn, reg_names);
            ctx.read_var(&identity)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

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

    fn make_unique(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Unique,
            offset,
            size,
            meta: None,
        }
    }

    #[test]
    fn same_named_same_width_storages_keep_distinct_live_ins_and_graph_values() {
        let mut arch = ArchSpec::new("rename-storage-collision");
        arch.add_register(RegisterDef::new("alias", 0, 8));
        arch.add_register(RegisterDef::new("alias", 8, 8));
        let blocks = vec![R2ILBlock {
            addr: 0x2000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_unique(0x100, 8),
                    src: make_reg(0, 8),
                },
                R2ILOp::Copy {
                    dst: make_unique(0x108, 8),
                    src: make_reg(8, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_const(2, 8),
                },
                R2ILOp::Return {
                    target: make_const(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let function = crate::function::SSAFunction::from_blocks_raw(&blocks, Some(&arch))
            .expect("raw SSA with colliding register spellings");
        let ops = &function.get_block(0x2000).expect("entry block").ops;
        let (
            SSAOp::Copy {
                src: first_live_in, ..
            },
            SSAOp::Copy {
                src: second_live_in,
                ..
            },
        ) = (&ops[0], &ops[1])
        else {
            panic!("expected two live-in copies");
        };
        assert_eq!(first_live_in.name, second_live_in.name);
        assert_eq!(first_live_in.size, second_live_in.size);
        assert_eq!(first_live_in.version, 0);
        assert_eq!(second_live_in.version, 0);
        assert_ne!(
            first_live_in, second_live_in,
            "exact storage must survive the shared display projection"
        );

        let first_def = ops[2].dst().expect("first alias definition");
        let second_def = ops[3].dst().expect("second alias definition");
        assert_ne!(first_def, second_def);
        assert_eq!((first_def.version, second_def.version), (1, 2));

        let graph = crate::graph::SsaGraph::from_function(&function);
        let first_value = graph
            .value_id_for_var(first_live_in)
            .expect("first live-in graph value");
        let second_value = graph
            .value_id_for_var(second_live_in)
            .expect("second live-in graph value");
        assert_ne!(first_value, second_value);
        assert_eq!(
            graph.canonical_storage_for_var(first_live_in),
            Some(CanonicalStorageId::from_varnode(&make_reg(0, 8)))
        );
        assert_eq!(
            graph.canonical_storage_for_var(second_live_in),
            Some(CanonicalStorageId::from_varnode(&make_reg(8, 8)))
        );
    }
}
