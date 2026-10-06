//! The stack-protector check, decided under `Premise::UbFreeSource` (doc/adr-frame-model.md, P4.4).
//!
//! The guard is the memory the platform states it at (`r2abi::stack_guard`), addressed from the
//! entry value of a register the platform reserves. A
//! check compares two reads of it, each direct or through a frame slot written once from one, and
//! a mismatch leaves for a block that only calls a function that does not return. A UB-free source
//! writes neither the guard nor outside its own objects, so both reads agree and the check passes.

use std::collections::BTreeSet;

use crate::arena::OpId;
use crate::cfg::BlockTerminator;
use crate::dense::{IdMap, IdSet};
use crate::function::{EditPlan, SSAFunction, ShapeEdit};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::VarId;

type Op = SSAOp<VarId>;

/// An address as a root value plus a constant byte offset.
type Affine = (VarId, i64);

/// One recognised check: what decides it and which operations the compiler inserted for it.
struct Check {
    block: u64,
    branch: OpId,
    target: VarId,
    /// The edge a passing check takes, and whether it is the branch's own target.
    pass: u64,
    pass_is_target: bool,
    fail: u64,
    inserted: IdSet<OpId>,
    /// The guard read every other read of the check equals under the premise, and those rereads.
    first: VarId,
    rereads: IdMap<OpId, VarId>,
}

/// Decide every stack-protector check the function holds; the operations each one inserted are
/// recorded on the function for the certificate that elides them.
pub(crate) fn decide(func: &mut SSAFunction, machine: &SourceMachineContext) {
    if !machine.accepts(r2source::Premise::UbFreeSource) {
        return;
    }
    // Only the slot the platform states: a thread-local variable read twice is no guard.
    let Some(guard) = machine
        .call_effect()
        .and_then(r2source::SourceCallEffect::stack_guard)
    else {
        return;
    };
    let defs = Definitions::of(func);
    let slots = SlotStores::of(func, &defs);
    let checks = func
        .block_addrs()
        .iter()
        .filter_map(|addr| check(func, &defs, &slots, guard, *addr))
        .collect::<Vec<_>>();
    if checks.is_empty() {
        return;
    }
    let mut decided = EditPlan::new();
    let mut inserted = IdSet::default();
    for check in &checks {
        let op = if check.pass_is_target {
            SSAOp::Branch {
                target: check.target,
                instruction: None,
            }
        } else {
            SSAOp::Nop
        };
        decided.replace(check.branch, op);
        decided.reshape(ShapeEdit::RemoveEdge {
            from: check.block,
            to: check.fail,
        });
        decided.reshape(ShapeEdit::SetTerminator {
            block: check.block,
            terminator: BlockTerminator::Branch { target: check.pass },
        });
        decided.reshape(ShapeEdit::DropPhiSources {
            block: check.fail,
            pred: check.block,
        });
        inserted.extend(check.inserted.iter());
        // Under the premise every reread holds what the first read did, so `reload - guard` folds to zero.
        for (op, dst) in check.rereads.iter() {
            decided.replace(
                op,
                SSAOp::Copy {
                    dst: *dst,
                    src: check.first,
                },
            );
        }
    }
    // A failure block no other edge reaches goes with the edges into it.
    let failed = checks
        .iter()
        .map(|check| check.fail)
        .collect::<BTreeSet<_>>();
    let deciding = checks
        .iter()
        .map(|check| check.block)
        .collect::<BTreeSet<_>>();
    let mut removed = BTreeSet::new();
    for fail in failed {
        if func
            .predecessors(fail)
            .iter()
            .all(|pred| deciding.contains(pred))
        {
            decided.reshape(ShapeEdit::RemoveBlock(fail));
            removed.insert(fail);
        }
    }
    decided.reorder();
    func.apply_edits(decided);
    func.record_compiler_inserted(inserted, removed);
}

/// Each variable's defining operation, and the walks over it this check needs.
struct Definitions {
    defs: IdMap<VarId, (OpId, Op)>,
    /// Where each operation sits: its block and its index there.
    positions: IdMap<OpId, (u64, usize)>,
    /// A bound on any definition chain: every step moves to an operand defined earlier.
    values: usize,
}

impl Definitions {
    fn of(func: &SSAFunction) -> Self {
        let values = func.values().len();
        let mut defs = IdMap::new(values);
        let mut positions = IdMap::new(func.id_limit());
        for addr in func.block_addrs() {
            let Some(block) = func.get_block(*addr) else {
                continue;
            };
            for (index, (id, op)) in block.sited().enumerate() {
                positions.insert(id, (*addr, index));
                if let Some(dst) = op.dst() {
                    defs.insert(*dst, (id, op.clone()));
                }
            }
        }
        Self {
            defs,
            positions,
            values,
        }
    }

    /// Whether operation `a` runs before `b` on every path to `b`.
    fn precedes(&self, func: &SSAFunction, a: OpId, b: OpId) -> bool {
        match (self.positions.get(a), self.positions.get(b)) {
            (Some((block_a, at)), Some((block_b, bt))) if block_a == block_b => at < bt,
            (Some((block_a, _)), Some((block_b, _))) => func.dominates(*block_a, *block_b),
            _ => false,
        }
    }

    fn op(&self, var: VarId) -> Option<&(OpId, Op)> {
        self.defs.get(var)
    }

    /// The value a run of copies forwards.
    fn copied(&self, mut var: VarId) -> VarId {
        for _ in 0..self.values {
            match self.op(var) {
                Some((_, SSAOp::Copy { src, .. })) => var = *src,
                _ => return var,
            }
        }
        var
    }

    /// An address as a root and a constant offset, through copies and constant adds and subtracts.
    fn affine(&self, func: &SSAFunction, mut var: VarId) -> Affine {
        let mut offset = 0i64;
        let constant = |var: VarId| func.var(var).constant_bits().map(|bits| bits as i64);
        for _ in 0..self.values {
            match self.op(var) {
                Some((_, SSAOp::Copy { src, .. })) => var = *src,
                Some((_, SSAOp::IntAdd { a, b, .. })) if constant(*b).is_some() => {
                    offset = offset.wrapping_add(constant(*b).unwrap_or(0));
                    var = *a;
                }
                Some((_, SSAOp::IntAdd { a, b, .. })) if constant(*a).is_some() => {
                    offset = offset.wrapping_add(constant(*a).unwrap_or(0));
                    var = *b;
                }
                Some((_, SSAOp::IntSub { a, b, .. })) if constant(*b).is_some() => {
                    offset = offset.wrapping_sub(constant(*b).unwrap_or(0));
                    var = *a;
                }
                _ => break,
            }
        }
        (var, offset)
    }

    /// The load a value is, through copies: its operation and its address.
    fn load(&self, func: &SSAFunction, var: VarId) -> Option<(OpId, Affine, u32)> {
        match self.op(self.copied(var)) {
            Some((id, SSAOp::Load { dst, addr, .. })) => {
                Some((*id, self.affine(func, *addr), func.var(*dst).size))
            }
            _ => None,
        }
    }
}

/// Every store whose address is a root plus a constant, by root; written once, by the walk below.
struct SlotStores {
    by_root: IdMap<VarId, Vec<(i64, i64, OpId, VarId)>>,
}

impl SlotStores {
    fn of(func: &SSAFunction, defs: &Definitions) -> Self {
        let mut by_root = IdMap::<VarId, Vec<_>>::new(func.values().len());
        for block in func
            .block_addrs()
            .iter()
            .filter_map(|addr| func.get_block(*addr))
        {
            for (id, op) in block.sited() {
                if let SSAOp::Store { addr, val, .. } = op {
                    let (root, offset) = defs.affine(func, *addr);
                    let width = i64::from(func.var(*val).size);
                    by_root
                        .get_or_insert_with(root, Vec::new)
                        .push((offset, width, id, *val));
                }
            }
        }
        Self { by_root }
    }

    /// The one store that writes any byte of `[offset, offset + width)` from `root`, if exactly one does.
    fn sole_writer(&self, (root, offset): Affine, width: u32) -> Option<(OpId, VarId)> {
        let end = offset + i64::from(width);
        let mut writers = self
            .by_root
            .get(root)?
            .iter()
            .filter(|(start, size, ..)| *start < end && offset < start + size);
        let (start, size, id, val) = writers.next()?;
        (writers.next().is_none() && (*start, *size) == (offset, i64::from(width)))
            .then_some((*id, *val))
    }
}

/// One side of a check: the guard it reads, the first read of it, the operations it took, and
/// the rereads the premise equates with the first read.
struct GuardRead {
    guard: Affine,
    first: (OpId, VarId),
    ops: Vec<OpId>,
    rereads: Vec<(OpId, VarId)>,
}

fn guard_read(
    func: &SSAFunction,
    defs: &Definitions,
    slots: &SlotStores,
    guard: &r2source::SourceStackGuard,
    var: VarId,
) -> Option<GuardRead> {
    let (load, address, width) = defs.load(func, var)?;
    let loaded = defs.op(defs.copied(var))?.1.dst().copied()?;
    if is_guard(func, guard, address, width) {
        return Some(GuardRead {
            guard: address,
            first: (load, loaded),
            ops: vec![load],
            rereads: Vec::new(),
        });
    }
    // A reload of a frame slot whose only writer, run before it, stored a direct read of the guard.
    let (store, stored) = slots.sole_writer(address, width)?;
    let (guard_load, stored_address, stored_width) = defs.load(func, stored)?;
    if !is_guard(func, guard, stored_address, stored_width) || !defs.precedes(func, store, load) {
        return None;
    }
    let first = defs.op(defs.copied(stored))?.1.dst().copied()?;
    Some(GuardRead {
        guard: stored_address,
        first: (guard_load, first),
        ops: vec![load, store, guard_load],
        rereads: vec![(load, loaded)],
    })
}

/// Whether a read of `width` bytes at `address` is a read of the platform's stack guard.
fn is_guard(
    func: &SSAFunction,
    guard: &r2source::SourceStackGuard,
    (root, offset): Affine,
    width: u32,
) -> bool {
    func.var(root).version == 0
        && func.storage_of(root) == Some(guard.base)
        && u64::try_from(offset).ok() == Some(guard.offset)
        && width == guard.width
}

/// The check that ends one block, when it compares two reads of one guard.
fn check(
    func: &SSAFunction,
    defs: &Definitions,
    slots: &SlotStores,
    guard: &r2source::SourceStackGuard,
    addr: u64,
) -> Option<Check> {
    let BlockTerminator::ConditionalBranch {
        true_target,
        false_target,
    } = func.cfg().get_block(addr)?.terminator
    else {
        return None;
    };
    let block = func.get_block(addr)?;
    let (branch, target, cond) = block.sited().rev().find_map(|(id, op)| match op {
        SSAOp::CBranch { target, cond } => Some((id, *target, *cond)),
        _ => None,
    })?;
    let (left, right, equal_when_true) = equality(func, defs, cond)?;
    let left = guard_read(func, defs, slots, guard, left)?;
    let right = guard_read(func, defs, slots, guard, right)?;
    if left.guard != right.guard {
        return None;
    }
    let (pass, fail) = if equal_when_true {
        (true_target, false_target)
    } else {
        (false_target, true_target)
    };
    if !fails_without_return(func, fail) {
        return None;
    }
    // The first read of the two runs before the other; the other and every reread equal it.
    let (first, second) = if defs.precedes(func, left.first.0, right.first.0) {
        (left.first, right.first)
    } else if defs.precedes(func, right.first.0, left.first.0) {
        (right.first, left.first)
    } else if left.first == right.first {
        (left.first, right.first)
    } else {
        return None;
    };
    let mut rereads = IdMap::default();
    rereads.extend(left.rereads.iter().chain(&right.rereads).copied());
    if second != first {
        rereads.insert(second.0, second.1);
    }
    // Every other read of the guard in the checking block is the check's: a compare may read it once per flag.
    rereads.extend(block.sited().filter_map(|(id, op)| match op {
        SSAOp::Load { dst, addr, .. }
            if id != first.0 && defs.affine(func, *addr) == left.guard =>
        {
            Some((id, *dst))
        }
        _ => None,
    }));
    if !rereads
        .iter()
        .all(|(op, _)| defs.precedes(func, first.0, op))
    {
        return None;
    }
    let mut inserted = left
        .ops
        .iter()
        .chain(&right.ops)
        .copied()
        .collect::<IdSet<_>>();
    inserted.extend(rereads.iter().map(|(op, _)| op));
    Some(Check {
        block: addr,
        branch,
        target,
        pass,
        pass_is_target: pass == true_target,
        fail,
        inserted,
        first: first.1,
        rereads,
    })
}

/// A condition that is true exactly when two values are equal (or exactly when they differ), and
/// the two values.
fn equality(func: &SSAFunction, defs: &Definitions, cond: VarId) -> Option<(VarId, VarId, bool)> {
    let zero = |var: VarId| func.var(var).constant_bits() == Some(0);
    let (left, right, equal) = match &defs.op(defs.copied(cond))?.1 {
        SSAOp::IntEqual { a, b, .. } => (*a, *b, true),
        SSAOp::IntNotEqual { a, b, .. } => (*a, *b, false),
        SSAOp::BoolNot { src, .. } => {
            let (left, right, equal) = equality(func, defs, *src)?;
            return Some((left, right, !equal));
        }
        _ => return None,
    };
    // `a - b == 0` and `a ^ b == 0` hold exactly when `a == b`.
    let difference = if zero(right) {
        Some(left)
    } else if zero(left) {
        Some(right)
    } else {
        None
    };
    if let Some(difference) = difference
        && let Some((_, SSAOp::IntSub { a, b, .. } | SSAOp::IntXor { a, b, .. })) =
            defs.op(defs.copied(difference))
    {
        return Some((*a, *b, equal));
    }
    Some((left, right, equal))
}

/// Whether a block leaves the function only through a call that does not come back.
fn fails_without_return(func: &SSAFunction, block: u64) -> bool {
    func.successors(block).is_empty()
        && func.get_block(block).is_some_and(|block| {
            let ops = block.ops();
            ops.iter().any(|op| matches!(op, SSAOp::Call { .. }))
                && !ops.iter().any(|op| matches!(op, SSAOp::Return { .. }))
        })
}
