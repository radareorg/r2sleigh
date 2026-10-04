//! SSA block and conversion from r2il.

use std::collections::HashMap;

use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::Disassembler;
use serde::Serialize;

use crate::arena::{OpArena, OpId, OpOrigin, Pass, local_id};
use crate::function::PhiNode;
use crate::name::{InternedName, intern_ascii_lowercase, intern_fmt};
use crate::op::SSAOp;
use crate::var::SSAVar;

/// The single conditional branch this block turns on, and where it sits.
///
/// It ends the block, or it guards the block's tail: a predicated
/// instruction's branch skips the instruction's own operations, so the
/// transfer it decides stands after it. `r2il::guarded_transfer` is where the
/// machine graph reads the same shape, and this is the SSA form of it.
pub fn branch_condition(block: &SSABlock) -> Option<(usize, &SSAVar)> {
    let terminal = block.ops.len().checked_sub(1)?;
    let mut branches = block
        .ops
        .iter()
        .enumerate()
        .filter_map(|(idx, op)| match op {
            SSAOp::CBranch { cond, .. } => Some((idx, cond)),
            _ => None,
        });
    let found = branches.next()?;
    branches.next().is_none().then_some(())?;
    let guards_tail = block.ops[found.0 + 1..].iter().any(|op| {
        matches!(
            op,
            SSAOp::Return { .. } | SSAOp::Branch { .. } | SSAOp::BranchInd { .. }
        )
    });
    (found.0 == terminal || guards_tail).then_some(found)
}

/// An SSA basic block containing versioned operations.
///
/// Lifting produces one with no phis and renaming fills them in, so the two
/// stages share a type and a function's blocks can be read without copying.
///
/// Every operation and every phi carries an [`OpId`] beside it, in a vector
/// kept in step with it. Both are private to this module: reading is a slice,
/// rewriting an operation in place keeps its id, and the only paths that
/// change how many operations a block has mint an id for what they insert and
/// tombstone the id of what they remove.
#[derive(Debug, Clone, Serialize)]
pub struct SSABlock<V = SSAVar> {
    /// The address of the instruction.
    pub addr: u64,
    /// The size of the instruction in bytes.
    pub size: u32,
    /// The SSA operations.
    ops: Vec<SSAOp<V>>,
    /// Each operation's identity, at the operation's index.
    #[serde(skip)]
    ids: Vec<OpId>,
    /// Phi nodes at the start of this block.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    phis: Vec<PhiNode<V>>,
    /// Each phi's identity, at the phi's index.
    #[serde(skip)]
    phi_ids: Vec<OpId>,
}

impl<V> SSABlock<V> {
    /// The same block over other operands, every operation and phi keeping
    /// its id.
    pub fn map_operands<W>(&self, f: &mut impl FnMut(&V) -> W) -> SSABlock<W> {
        SSABlock {
            addr: self.addr,
            size: self.size,
            ops: self.ops.iter().map(|op| op.map(f)).collect(),
            ids: self.ids.clone(),
            phis: self.phis.iter().map(|phi| phi.map(f)).collect(),
            phi_ids: self.phi_ids.clone(),
        }
    }
}

impl<V> Default for SSABlock<V> {
    fn default() -> Self {
        Self {
            addr: 0,
            size: 0,
            ops: Vec::new(),
            ids: Vec::new(),
            phis: Vec::new(),
            phi_ids: Vec::new(),
        }
    }
}

/// Context for SSA conversion, tracking variable versions.
///
/// Keyed by the interned spelling rather than by a string of its own: the
/// name is already stored once, so the version table hashes an identifier
/// instead of the characters and stores no second copy.
#[derive(Debug, Default)]
pub struct SSAContext {
    /// Current version for each variable name.
    versions: HashMap<&'static InternedName, u32>,
    /// Versions allocated by the current operation but not yet visible to reads.
    pending_versions: HashMap<&'static InternedName, u32>,
}

impl SSAContext {
    /// Create a new SSA context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current version of a variable (for reading).
    /// Returns 0 if the variable hasn't been seen yet.
    pub fn current_version(&self, name: &'static InternedName) -> u32 {
        *self.versions.get(name).unwrap_or(&0)
    }

    /// Allocate a new version for a variable (for writing).
    /// Returns the new version number.
    pub fn new_version(&mut self, name: &'static InternedName) -> u32 {
        let entry = self.versions.entry(name).or_insert(0);
        *entry += 1;
        *entry
    }

    fn defer_version(&mut self, name: &'static InternedName) -> u32 {
        let current = self
            .pending_versions
            .get(name)
            .copied()
            .unwrap_or_else(|| self.current_version(name));
        let version = current + 1;
        self.pending_versions.insert(name, version);
        version
    }

    fn commit_deferred_versions(&mut self) {
        for (name, version) in self.pending_versions.drain() {
            self.versions.insert(name, version);
        }
    }

    /// Get all variables that have been defined (version > 0).
    pub fn defined_vars(&self) -> impl Iterator<Item = (&'static str, u32)> {
        self.versions.iter().filter_map(|(name, &ver)| {
            if ver > 0 {
                Some((name.text(), ver))
            } else {
                None
            }
        })
    }
}

impl<V> SSABlock<V> {
    /// Create a new empty SSA block.
    pub fn new(addr: u64, size: u32) -> Self {
        Self::from_parts(addr, size, Vec::new(), Vec::new())
    }

    /// A block holding these operations and phis, numbered by itself until a
    /// function adopts it ([`crate::arena`]).
    pub fn from_parts(addr: u64, size: u32, ops: Vec<SSAOp<V>>, phis: Vec<PhiNode<V>>) -> Self {
        Self {
            addr,
            size,
            ids: (0..ops.len()).map(local_id).collect(),
            ops,
            phi_ids: (0..phis.len()).map(local_id).collect(),
            phis,
        }
    }

    /// A block of operations a function has already minted ids for.
    pub(crate) fn from_sited(
        addr: u64,
        size: u32,
        ops: Vec<(OpId, SSAOp<V>)>,
        phis: Vec<(OpId, PhiNode<V>)>,
    ) -> Self {
        let (ids, ops) = ops.into_iter().unzip();
        let (phi_ids, phis) = phis.into_iter().unzip();
        Self {
            addr,
            size,
            ops,
            ids,
            phis,
            phi_ids,
        }
    }

    /// Give every phi and operation an id from a function's arena: a block
    /// built outside a function, adopted as though the lift emitted it.
    #[cfg(test)]
    pub(crate) fn adopt(&mut self, arena: &mut OpArena) {
        self.phi_ids = self
            .phis
            .iter()
            .map(|_| {
                arena.mint(OpOrigin::Derived {
                    from: None,
                    pass: Pass::PhiPlacement,
                })
            })
            .collect();
        let block = self.addr;
        self.ids = (0..self.ops.len())
            .map(|index| {
                arena.mint(OpOrigin::Lifted {
                    block,
                    index,
                    instruction: None,
                })
            })
            .collect();
    }

    /// The operations, in order.
    pub fn ops(&self) -> &[SSAOp<V>] {
        &self.ops
    }

    /// The phis, in order.
    pub fn phis(&self) -> &[PhiNode<V>] {
        &self.phis
    }

    /// Each operation with its identity, in order.
    pub fn sited(&self) -> impl DoubleEndedIterator<Item = (OpId, &SSAOp<V>)> + ExactSizeIterator {
        self.ids.iter().copied().zip(&self.ops)
    }

    /// Each phi with its identity, in order.
    pub fn sited_phis(
        &self,
    ) -> impl DoubleEndedIterator<Item = (OpId, &PhiNode<V>)> + ExactSizeIterator {
        self.phi_ids.iter().copied().zip(&self.phis)
    }

    /// The identity of the operation at `index`.
    pub fn op_id(&self, index: usize) -> Option<OpId> {
        self.ids.get(index).copied()
    }

    /// The identity of the phi at `index`.
    pub fn phi_id(&self, index: usize) -> Option<OpId> {
        self.phi_ids.get(index).copied()
    }

    /// Where an operation sits in this block, by a scan of the block.
    pub fn position(&self, id: OpId) -> Option<usize> {
        self.ids.iter().position(|held| *held == id)
    }

    /// The operations, to be rewritten in place: each keeps its id.
    pub fn ops_mut(&mut self) -> &mut [SSAOp<V>] {
        &mut self.ops
    }

    /// The phis, to be rewritten in place: each keeps its id.
    pub fn phis_mut(&mut self) -> &mut [PhiNode<V>] {
        &mut self.phis
    }

    /// Add an operation to a block being built one instruction at a time,
    /// numbered by the block itself.
    pub(crate) fn push(&mut self, op: SSAOp<V>) {
        self.ids.push(local_id(self.ops.len()));
        self.ops.push(op);
    }

    /// Add a phi to a block being built by hand, numbered by the block
    /// itself.
    #[cfg(test)]
    pub(crate) fn push_phi(&mut self, phi: PhiNode<V>) {
        self.phi_ids.push(local_id(self.phis.len()));
        self.phis.push(phi);
    }

    /// Get the number of operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Check if the block is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Insert operations at `at`, minting each an id derived by `pass` from
    /// the operation named beside it.
    pub(crate) fn insert_ops(
        &mut self,
        arena: &mut OpArena,
        at: usize,
        pass: Pass,
        ops: impl IntoIterator<Item = (SSAOp<V>, Option<OpId>)>,
    ) {
        let at = at.min(self.ops.len());
        let (ops, ids): (Vec<_>, Vec<_>) = ops
            .into_iter()
            .map(|(op, from)| (op, arena.mint(OpOrigin::Derived { from, pass })))
            .unzip();
        self.ops.splice(at..at, ops);
        self.ids.splice(at..at, ids);
    }

    /// Remove the operation at `at`, tombstoning its id.
    pub(crate) fn remove_op(&mut self, arena: &mut OpArena, at: usize, pass: Pass) -> SSAOp<V> {
        arena.kill(self.ids.remove(at), pass);
        self.ops.remove(at)
    }

    /// Keep the phis `keep` accepts, tombstoning the rest.
    pub(crate) fn retain_phis(
        &mut self,
        arena: &mut OpArena,
        pass: Pass,
        mut keep: impl FnMut(&PhiNode<V>) -> bool,
    ) {
        let mut index = 0;
        while index < self.phis.len() {
            if keep(&self.phis[index]) {
                index += 1;
            } else {
                self.phis.remove(index);
                arena.kill(self.phi_ids.remove(index), pass);
            }
        }
    }

    /// Tombstone every phi and operation of a block leaving the function.
    pub(crate) fn kill_all(&self, arena: &mut OpArena, pass: Pass) {
        for id in self.phi_ids.iter().chain(&self.ids) {
            arena.kill(*id, pass);
        }
    }

    /// Replace every operation, tombstoning the old ones and minting the new
    /// ones as derived by `pass` from nothing.
    pub(crate) fn replace_ops(&mut self, arena: &mut OpArena, pass: Pass, ops: Vec<SSAOp<V>>) {
        for id in self.ids.drain(..) {
            arena.kill(id, pass);
        }
        self.ids = ops
            .iter()
            .map(|_| arena.mint(OpOrigin::Derived { from: None, pass }))
            .collect();
        self.ops = ops;
    }

    /// Replace every phi, as [`Self::replace_ops`] does operations.
    pub(crate) fn replace_phis(&mut self, arena: &mut OpArena, pass: Pass, phis: Vec<PhiNode<V>>) {
        for id in self.phi_ids.drain(..) {
            arena.kill(id, pass);
        }
        self.phi_ids = phis
            .iter()
            .map(|_| arena.mint(OpOrigin::Derived { from: None, pass }))
            .collect();
        self.phis = phis;
    }
}

impl<V> SSABlock<V> {
    /// Apply one block's share of an [`crate::function::EditPlan`] in a single
    /// walk of its operations, minting what it inserts in the order the
    /// insertions end up in the block.
    ///
    /// The plan names its operands; `convert` gives each operation it
    /// inserts or substitutes over this block's operands.
    pub(crate) fn apply(
        &mut self,
        arena: &mut OpArena,
        edits: crate::function::BlockEdits,
        convert: &mut impl FnMut(&SSAOp) -> SSAOp<V>,
    ) {
        let crate::function::BlockEdits { start, mut at } = edits;
        let old_ops = std::mem::take(&mut self.ops);
        let old_ids = std::mem::take(&mut self.ids);
        let mut ops = Vec::with_capacity(old_ops.len());
        let mut ids = Vec::with_capacity(old_ids.len());
        fn place<V>(
            ops: &mut Vec<SSAOp<V>>,
            ids: &mut Vec<OpId>,
            arena: &mut OpArena,
            runs: Vec<crate::function::Insertion>,
            convert: &mut impl FnMut(&SSAOp) -> SSAOp<V>,
        ) {
            let flat = runs
                .into_iter()
                .flat_map(|(pass, run)| run.into_iter().map(move |(op, from)| (pass, op, from)));
            for (pass, op, from) in flat {
                ids.push(arena.mint(OpOrigin::Derived { from, pass }));
                ops.push(convert(&op));
            }
        }
        place(&mut ops, &mut ids, arena, start, convert);
        for (id, op) in old_ids.into_iter().zip(old_ops) {
            let Some(edit) = at.remove(&id) else {
                ids.push(id);
                ops.push(op);
                continue;
            };
            place(&mut ops, &mut ids, arena, edit.before, convert);
            if let Some(pass) = edit.kill {
                arena.kill(id, pass);
            } else {
                ids.push(id);
                ops.push(edit.replace.map_or(op, |op| convert(&op)));
            }
            place(&mut ops, &mut ids, arena, edit.after, convert);
        }
        self.ops = ops;
        self.ids = ids;
    }
}

/// One block of a function, open for change together with the function's
/// arena, so that whatever changes the block's shape mints or tombstones ids
/// as it does. Reading goes through [`SSABlock`].
pub struct BlockMut<'a, V = SSAVar> {
    block: &'a mut SSABlock<V>,
    arena: &'a mut OpArena,
}

impl<'a, V> BlockMut<'a, V> {
    /// Open `block` for change. Every id the block holds must have been
    /// minted from `arena`: a block the function owns gets its own arena from
    /// the function, and a detached block numbered by itself pairs with an
    /// empty one.
    pub fn new(block: &'a mut SSABlock<V>, arena: &'a mut OpArena) -> Self {
        Self { block, arena }
    }

    /// The operations, to be rewritten in place: each keeps its id.
    pub fn ops_mut(&mut self) -> &mut [SSAOp<V>] {
        self.block.ops_mut()
    }

    /// The phis, to be rewritten in place: each keeps its id.
    pub fn phis_mut(&mut self) -> &mut [PhiNode<V>] {
        self.block.phis_mut()
    }

    /// Insert one operation at `at`, derived by `pass` from `from`.
    pub fn insert_op(&mut self, at: usize, op: SSAOp<V>, from: Option<OpId>, pass: Pass) {
        self.block.insert_ops(self.arena, at, pass, [(op, from)]);
    }

    /// Append one operation, derived by `pass` from `from`.
    pub fn push_op(&mut self, op: SSAOp<V>, from: Option<OpId>, pass: Pass) {
        let end = self.block.len();
        self.insert_op(end, op, from, pass);
    }

    /// Insert operations at `at`, each derived by `pass` from the operation
    /// named beside it.
    pub fn insert_ops(
        &mut self,
        at: usize,
        pass: Pass,
        ops: impl IntoIterator<Item = (SSAOp<V>, Option<OpId>)>,
    ) {
        self.block.insert_ops(self.arena, at, pass, ops);
    }

    /// Remove the operation at `at`, tombstoning its id.
    pub fn remove_op(&mut self, at: usize, pass: Pass) -> SSAOp<V> {
        self.block.remove_op(self.arena, at, pass)
    }

    /// Keep the phis `keep` accepts, tombstoning the rest.
    pub fn retain_phis(&mut self, pass: Pass, keep: impl FnMut(&PhiNode<V>) -> bool) {
        self.block.retain_phis(self.arena, pass, keep);
    }

    /// Replace every operation: the old ids die, the new ones are minted.
    pub fn replace_ops(&mut self, pass: Pass, ops: Vec<SSAOp<V>>) {
        self.block.replace_ops(self.arena, pass, ops);
    }

    /// Replace every phi: the old ids die, the new ones are minted.
    pub fn replace_phis(&mut self, pass: Pass, phis: Vec<PhiNode<V>>) {
        self.block.replace_phis(self.arena, pass, phis);
    }
}

impl<V> std::ops::Deref for BlockMut<'_, V> {
    type Target = SSABlock<V>;

    fn deref(&self) -> &SSABlock<V> {
        self.block
    }
}

/// Convert an r2il block to SSA form.
///
/// This performs single-block SSA conversion:
/// - Each read uses the current version of the variable
/// - Each write creates a new version
///
/// # Arguments
/// * `block` - The r2il block to convert
/// * `disasm` - Disassembler for resolving varnode names
///
/// # Returns
/// An SSA block with versioned variables
pub fn to_ssa(block: &R2ILBlock, disasm: &Disassembler) -> SSABlock {
    let mut ctx = SSAContext::new();
    let mut ssa_block = SSABlock::new(block.addr, block.size);

    for (op_index, op) in block.ops.iter().enumerate() {
        let instruction = block
            .op_metadata(op_index)
            .and_then(|metadata| metadata.instruction_addr);
        let ssa_op = convert_op(op, instruction, disasm, &mut ctx);
        ctx.commit_deferred_versions();
        ssa_block.push(ssa_op);
    }

    ssa_block
}

/// Convert a varnode to an SSA variable name.
///
/// For registers:
/// - If a name is found, use the name directly (e.g., "rax", "cf")
/// - If no name is found, use "reg:offset" fallback (e.g., "reg:10")
fn varnode_to_name(vn: &Varnode, disasm: &Disassembler) -> &'static InternedName {
    match vn.space {
        SpaceId::Register => match disasm.register_spelling(vn) {
            Some(name) => intern_ascii_lowercase(&name),
            None => intern_fmt(format_args!("reg:{:x}", vn.offset)),
        },
        SpaceId::Unique => intern_fmt(format_args!("tmp:{:x}", vn.offset)),
        SpaceId::Const => intern_fmt(format_args!("const:{:x}", vn.offset)),
        SpaceId::Ram => intern_fmt(format_args!("ram:{:x}", vn.offset)),
        SpaceId::Custom(id) if id == crate::promote::PROMOTED_SLOT_SPACE => intern_fmt(
            format_args!("{}", crate::naming::frame_slot_name(vn.offset as i64)),
        ),
        SpaceId::Custom(id) => intern_fmt(format_args!("space{}:{:x}", id, vn.offset)),
    }
}

/// Convert a varnode to an SSA variable for reading (uses current version).
fn read_var(vn: &Varnode, disasm: &Disassembler, ctx: &SSAContext) -> SSAVar {
    let name = varnode_to_name(vn, disasm);
    let version = ctx.current_version(name);
    SSAVar::from_interned(name, version, vn.size)
}

/// Convert a varnode to an SSA variable for writing.
///
/// The new version remains invisible to reads until the current operation is
/// fully converted.
fn write_var(vn: &Varnode, disasm: &Disassembler, ctx: &mut SSAContext) -> SSAVar {
    let name = varnode_to_name(vn, disasm);
    let version = ctx.defer_version(name);
    SSAVar::from_interned(name, version, vn.size)
}

/// Convert an R2ILOp to an SSAOp.
fn convert_op(
    op: &R2ILOp,
    instruction: Option<u64>,
    disasm: &Disassembler,
    ctx: &mut SSAContext,
) -> SSAOp {
    use R2ILOp::*;

    match op {
        Copy { dst, src } => SSAOp::Copy {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Load { dst, space, addr } => SSAOp::Load {
            dst: write_var(dst, disasm, ctx),
            space: *space,
            addr: read_var(addr, disasm, ctx),
        },

        Store { space, addr, val } => SSAOp::Store {
            space: *space,
            addr: read_var(addr, disasm, ctx),
            val: read_var(val, disasm, ctx),
        },
        BlockTransfer(transfer) => SSAOp::BlockTransfer(Box::new(crate::op::BlockTransferOp {
            space: transfer.space,
            kind: transfer.kind,
            destination: read_var(&transfer.destination, disasm, ctx),
            source: read_var(&transfer.source, disasm, ctx),
            count: read_var(&transfer.count, disasm, ctx),
            direction: read_var(&transfer.direction, disasm, ctx),
            element_size: transfer.element_size,
            // Written after every read, as the fields are evaluated in order.
            answer: transfer.answer.as_ref().map(|v| write_var(v, disasm, ctx)),
        })),
        Fence { ordering } => SSAOp::Fence {
            ordering: *ordering,
        },
        LoadLinked {
            dst,
            space,
            addr,
            ordering,
        } => SSAOp::LoadLinked {
            dst: write_var(dst, disasm, ctx),
            space: *space,
            addr: read_var(addr, disasm, ctx),
            ordering: *ordering,
        },
        StoreConditional {
            result,
            space,
            addr,
            val,
            ordering,
        } => SSAOp::StoreConditional {
            result: result.as_ref().map(|v| write_var(v, disasm, ctx)),
            space: *space,
            addr: read_var(addr, disasm, ctx),
            val: read_var(val, disasm, ctx),
            ordering: *ordering,
        },
        AtomicCAS {
            dst,
            space,
            addr,
            expected,
            replacement,
            ordering,
        } => SSAOp::AtomicCAS(Box::new(crate::op::AtomicCasOp {
            dst: write_var(dst, disasm, ctx),
            space: *space,
            addr: read_var(addr, disasm, ctx),
            expected: read_var(expected, disasm, ctx),
            replacement: read_var(replacement, disasm, ctx),
            ordering: *ordering,
        })),
        LoadGuarded {
            dst,
            space,
            addr,
            guard,
            ordering,
        } => SSAOp::LoadGuarded {
            dst: write_var(dst, disasm, ctx),
            space: *space,
            addr: read_var(addr, disasm, ctx),
            guard: read_var(guard, disasm, ctx),
            ordering: *ordering,
        },
        StoreGuarded {
            space,
            addr,
            val,
            guard,
            ordering,
        } => SSAOp::StoreGuarded {
            space: *space,
            addr: read_var(addr, disasm, ctx),
            val: read_var(val, disasm, ctx),
            guard: read_var(guard, disasm, ctx),
            ordering: *ordering,
        },

        IntAdd { dst, a, b } => SSAOp::IntAdd {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSub { dst, a, b } => SSAOp::IntSub {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntMult { dst, a, b } => SSAOp::IntMult {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntDiv { dst, a, b } => SSAOp::IntDiv {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSDiv { dst, a, b } => SSAOp::IntSDiv {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntRem { dst, a, b } => SSAOp::IntRem {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSRem { dst, a, b } => SSAOp::IntSRem {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntNegate { dst, src } => SSAOp::IntNegate {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        IntCarry { dst, a, b } => SSAOp::IntCarry {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSCarry { dst, a, b } => SSAOp::IntSCarry {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSBorrow { dst, a, b } => SSAOp::IntSBorrow {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntAnd { dst, a, b } => SSAOp::IntAnd {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntOr { dst, a, b } => SSAOp::IntOr {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntXor { dst, a, b } => SSAOp::IntXor {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntNot { dst, src } => SSAOp::IntNot {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        IntLeft { dst, a, b } => SSAOp::IntLeft {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntRight { dst, a, b } => SSAOp::IntRight {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSRight { dst, a, b } => SSAOp::IntSRight {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntEqual { dst, a, b } => SSAOp::IntEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntNotEqual { dst, a, b } => SSAOp::IntNotEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntLess { dst, a, b } => SSAOp::IntLess {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSLess { dst, a, b } => SSAOp::IntSLess {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntLessEqual { dst, a, b } => SSAOp::IntLessEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntSLessEqual { dst, a, b } => SSAOp::IntSLessEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        IntZExt { dst, src } => SSAOp::IntZExt {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        IntSExt { dst, src } => SSAOp::IntSExt {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        BoolNot { dst, src } => SSAOp::BoolNot {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        BoolAnd { dst, a, b } => SSAOp::BoolAnd {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        BoolOr { dst, a, b } => SSAOp::BoolOr {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        BoolXor { dst, a, b } => SSAOp::BoolXor {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        Piece { dst, hi, lo } => SSAOp::Piece {
            dst: write_var(dst, disasm, ctx),
            hi: read_var(hi, disasm, ctx),
            lo: read_var(lo, disasm, ctx),
        },

        Subpiece { dst, src, offset } => SSAOp::Subpiece {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
            offset: *offset,
        },

        PopCount { dst, src } => SSAOp::PopCount {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Lzcount { dst, src } => SSAOp::Lzcount {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Branch { target } => SSAOp::Branch {
            target: read_var(target, disasm, ctx),
            instruction,
        },

        CBranch { target, cond } => SSAOp::CBranch {
            target: read_var(target, disasm, ctx),
            cond: read_var(cond, disasm, ctx),
        },

        BranchInd { target } => SSAOp::BranchInd {
            target: read_var(target, disasm, ctx),
            instruction,
        },

        Call { target } => SSAOp::Call {
            target: read_var(target, disasm, ctx),
            instruction,
        },

        CallInd { target } => SSAOp::CallInd {
            target: read_var(target, disasm, ctx),
            instruction,
        },

        Return { target } => SSAOp::Return {
            target: read_var(target, disasm, ctx),
        },

        FloatAdd { dst, a, b } => SSAOp::FloatAdd {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatSub { dst, a, b } => SSAOp::FloatSub {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatMult { dst, a, b } => SSAOp::FloatMult {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatDiv { dst, a, b } => SSAOp::FloatDiv {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatNeg { dst, src } => SSAOp::FloatNeg {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatAbs { dst, src } => SSAOp::FloatAbs {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatSqrt { dst, src } => SSAOp::FloatSqrt {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatCeil { dst, src } => SSAOp::FloatCeil {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatFloor { dst, src } => SSAOp::FloatFloor {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatRound { dst, src } => SSAOp::FloatRound {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatNaN { dst, src } => SSAOp::FloatNaN {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatEqual { dst, a, b } => SSAOp::FloatEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatNotEqual { dst, a, b } => SSAOp::FloatNotEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatLess { dst, a, b } => SSAOp::FloatLess {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        FloatLessEqual { dst, a, b } => SSAOp::FloatLessEqual {
            dst: write_var(dst, disasm, ctx),
            a: read_var(a, disasm, ctx),
            b: read_var(b, disasm, ctx),
        },

        Int2Float { dst, src } => SSAOp::Int2Float {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Float2Int { dst, src } => SSAOp::Float2Int {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        FloatFloat { dst, src } => SSAOp::FloatFloat {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Trunc { dst, src } => SSAOp::Trunc {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        CallOther {
            output,
            userop,
            inputs,
        } => SSAOp::CallOther {
            output: output.as_ref().map(|o| write_var(o, disasm, ctx)),
            userop: *userop,
            inputs: inputs.iter().map(|i| read_var(i, disasm, ctx)).collect(),
        },

        Nop => SSAOp::Nop,

        Unimplemented => SSAOp::Unimplemented,

        CpuId { dst } => SSAOp::CpuId {
            dst: write_var(dst, disasm, ctx),
        },

        Breakpoint => SSAOp::Breakpoint,

        Multiequal { dst, inputs } => {
            // Multiequal is already a phi-like construct, convert to Phi
            SSAOp::Phi {
                dst: write_var(dst, disasm, ctx),
                sources: inputs.iter().map(|i| read_var(i, disasm, ctx)).collect(),
            }
        }

        Indirect { dst, src, .. } => {
            // Indirect is used for aliasing analysis; treat as copy for now
            SSAOp::Copy {
                dst: write_var(dst, disasm, ctx),
                src: read_var(src, disasm, ctx),
            }
        }

        PtrAdd {
            dst,
            base,
            index,
            element_size,
        } => SSAOp::PtrAdd {
            dst: write_var(dst, disasm, ctx),
            base: read_var(base, disasm, ctx),
            index: read_var(index, disasm, ctx),
            element_size: *element_size,
        },

        PtrSub {
            dst,
            base,
            index,
            element_size,
        } => SSAOp::PtrSub {
            dst: write_var(dst, disasm, ctx),
            base: read_var(base, disasm, ctx),
            index: read_var(index, disasm, ctx),
            element_size: *element_size,
        },

        SegmentOp {
            dst,
            segment,
            offset,
        } => SSAOp::SegmentOp {
            dst: write_var(dst, disasm, ctx),
            segment: read_var(segment, disasm, ctx),
            offset: read_var(offset, disasm, ctx),
        },

        New { dst, src } => SSAOp::New {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Cast { dst, src } => SSAOp::Cast {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
        },

        Extract { dst, src, position } => SSAOp::Extract {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
            position: read_var(position, disasm, ctx),
        },

        Insert {
            dst,
            src,
            value,
            position,
        } => SSAOp::Insert(Box::new(crate::op::InsertOp {
            dst: write_var(dst, disasm, ctx),
            src: read_var(src, disasm, ctx),
            value: read_var(value, disasm, ctx),
            position: read_var(position, disasm, ctx),
        })),

        Select {
            dst,
            cond,
            if_true,
            if_false,
        } => {
            let cond = read_var(cond, disasm, ctx);
            let if_true = read_var(if_true, disasm, ctx);
            let if_false = read_var(if_false, disasm, ctx);
            SSAOp::Select(Box::new(crate::op::SelectOp {
                dst: write_var(dst, disasm, ctx),
                cond,
                if_true,
                if_false,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssa_context_versioning() {
        let mut ctx = SSAContext::new();
        let rax = crate::name::intern("RAX");
        let rbx = crate::name::intern("RBX");

        // First read should get version 0
        assert_eq!(ctx.current_version(rax), 0);

        // First write should get version 1
        assert_eq!(ctx.new_version(rax), 1);

        // Next read should get version 1
        assert_eq!(ctx.current_version(rax), 1);

        // Second write should get version 2
        assert_eq!(ctx.new_version(rax), 2);

        // Different variable starts at 0
        assert_eq!(ctx.current_version(rbx), 0);
    }

    #[test]
    fn test_deferred_write_is_not_visible_to_same_op_reads() {
        let mut ctx = SSAContext::new();
        let rax = crate::name::intern("RAX");

        assert_eq!(ctx.defer_version(rax), 1);
        assert_eq!(ctx.current_version(rax), 0);
        ctx.commit_deferred_versions();
        assert_eq!(ctx.current_version(rax), 1);
    }

    #[test]
    fn test_ssa_block_basic() {
        let block: SSABlock = SSABlock::new(0x1000, 4);
        assert_eq!(block.addr, 0x1000);
        assert_eq!(block.size, 4);
        assert!(block.is_empty());
        assert_eq!(block.len(), 0);
    }
}
