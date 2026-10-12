//! A stack check a runtime decides, under `Premise::GoRuntime`: Go's prologue compares the stack
//! pointer with `stackguard0` and calls a routine that re-enters the function
//! (doc/adr-language-profile.md, item 3).

use std::collections::BTreeSet;

use crate::arena::OpId;
use crate::cfg::BlockTerminator;
use crate::dense::IdSet;
use crate::frame_address::{Affine, Definitions};
use crate::function::{EditPlan, SSAFunction, ShapeEdit};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::VarId;
use r2source::{CanonicalStorageId, SourceStackGuard};

/// One recognised check: the branch that decides it, its two edges and the operations it is.
struct Check {
    block: u64,
    branch: OpId,
    target: VarId,
    pass: u64,
    pass_is_target: bool,
    fail: u64,
    inserted: IdSet<OpId>,
}

/// Decide every stack check whose failing edge re-enters the function: under the runtime's
/// contract for the routine the container names, the failing edge composes to the passing one.
pub(crate) fn decide(func: &mut SSAFunction, machine: &SourceMachineContext) {
    if !machine.accepts(r2source::Premise::GoRuntime) {
        return;
    }
    let Some(bound) = machine
        .call_effect()
        .and_then(r2source::SourceCallEffect::stack_bound)
    else {
        return;
    };
    let Some(stack_pointer) = machine.stack_pointer_carrier() else {
        return;
    };
    let defs = Definitions::of(func);
    let checks = func
        .block_addrs()
        .iter()
        .filter_map(|addr| check(func, &defs, machine, bound, stack_pointer, *addr))
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
    }
    let removed = remove_failing_blocks(func, &checks, &mut decided);
    decided.reorder();
    func.apply_edits(decided);
    let addresses = crate::stack_protector::inserted_addresses(func, &inserted);
    inserted.extend(addresses.iter());
    func.record_compiler_inserted(inserted, removed);
    func.record_premise(r2source::Premise::GoRuntime);
}

/// Remove each failing block only the decided checks reach, with its edge back to the entry.
fn remove_failing_blocks(
    func: &SSAFunction,
    checks: &[Check],
    decided: &mut EditPlan,
) -> BTreeSet<u64> {
    let deciding = checks
        .iter()
        .map(|check| check.block)
        .collect::<BTreeSet<_>>();
    let mut removed = BTreeSet::new();
    for fail in checks
        .iter()
        .map(|check| check.fail)
        .collect::<BTreeSet<_>>()
    {
        if !func
            .predecessors(fail)
            .iter()
            .all(|pred| deciding.contains(pred))
        {
            continue;
        }
        // A growth path that jumps back to the entry leaves it a source the entry's merges drop.
        for next in func.successors(fail) {
            decided.reshape(ShapeEdit::RemoveEdge {
                from: fail,
                to: next,
            });
            decided.reshape(ShapeEdit::DropPhiSources {
                block: next,
                pred: fail,
            });
        }
        decided.reshape(ShapeEdit::RemoveBlock(fail));
        removed.insert(fail);
    }
    removed
}

/// The check ending one block: an unsigned `sp - k <= stackguard0` whose true edge re-enters.
fn check(
    func: &SSAFunction,
    defs: &Definitions,
    machine: &SourceMachineContext,
    bound: &SourceStackGuard,
    stack_pointer: CanonicalStorageId,
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
    let (low, guard, mut inserted) = unsigned_at_most(func, defs, cond)?;
    let (root, _) = defs.affine(func, low);
    if func.var(root).version != 0 || func.storage_of(root) != Some(stack_pointer) {
        return None;
    }
    let (load, address, width) = defs.load(func, guard)?;
    if !is_bound(func, bound, address, width) {
        return None;
    }
    // A compare against the bound whose failing edge no runtime model re-enters stays a branch.
    if !reenters(func, defs, machine, stack_pointer, true_target) {
        r2il::refusal_evidence!(
            "stack-bound",
            "{addr:#x}: compares against the stack bound, but {true_target:#x} re-enters by no model"
        );
        return None;
    }
    inserted.insert(load);
    inserted.insert(branch);
    inserted.extend(only_read_by(func, defs, low, &inserted).iter());
    Some(Check {
        block: addr,
        branch,
        target,
        pass: false_target,
        pass_is_target: false_target == true_target,
        fail: true_target,
        inserted,
    })
}

/// The operations defining `value` through copies and constant offsets, while the check's own
/// operations are all that read what each defines: the stack pointer arithmetic it compares.
fn only_read_by(
    func: &SSAFunction,
    defs: &Definitions,
    value: VarId,
    check: &IdSet<OpId>,
) -> IdSet<OpId> {
    let mut taken = IdSet::default();
    let mut current = value;
    loop {
        let Some((id, op)) = defs.op(current) else {
            return taken;
        };
        let read_elsewhere = func.blocks().iter().any(|block| {
            block
                .sited_phis()
                .any(|(_, phi)| phi.sources.iter().any(|(_, s)| *s == current))
                || block.sited().any(|(at, op)| {
                    !check.contains(at) && !taken.contains(at) && op.sources().contains(&&current)
                })
        });
        if read_elsewhere {
            return taken;
        }
        taken.insert(*id);
        current = match op {
            SSAOp::Copy { src, .. } => *src,
            SSAOp::IntAdd { a, b, .. } | SSAOp::IntSub { a, b, .. } if func.var(*b).is_const() => {
                *a
            }
            _ => return taken,
        };
        if func.var(current).version == 0 {
            return taken;
        }
    }
}

/// `cond` as unsigned `a <= b`, with the operations that compute it: an `INT_LESSEQUAL`, or the
/// carry-or-zero of a compare (`a < b`, as x86's borrow or AArch64's `!(b <= a)`, or'd with
/// `a - b == 0` or `a == b`).
fn unsigned_at_most(
    func: &SSAFunction,
    defs: &Definitions,
    cond: VarId,
) -> Option<(VarId, VarId, IdSet<OpId>)> {
    let (id, op) = defs.op(defs.copied(cond))?;
    let mut ops = IdSet::default();
    ops.insert(*id);
    match op {
        SSAOp::IntLessEqual { a, b, .. } => Some((*a, *b, ops)),
        SSAOp::BoolOr { a, b, .. } => {
            let (less, equal) = [(*a, *b), (*b, *a)]
                .into_iter()
                .find_map(|(less, equal)| Some((strictly_below(defs, less)?, equal)))?;
            let (less_ids, left, right) = less;
            let (equal_id, equal_op) = defs.op(defs.copied(equal))?;
            let SSAOp::IntEqual { a, b, .. } = equal_op else {
                return None;
            };
            let zero = |var: VarId| func.var(var).constant_bits() == Some(0);
            let same = (*a == left && *b == right) || (*a == right && *b == left);
            let difference = [(*a, *b), (*b, *a)]
                .into_iter()
                .find_map(|(value, other)| zero(other).then_some(value))
                .and_then(|value| defs.op(defs.copied(value)))
                .filter(
                    |(_, op)| matches!(op, SSAOp::IntSub { a, b, .. } if *a == left && *b == right),
                );
            if !same && difference.is_none() {
                return None;
            }
            ops.extend(less_ids.iter());
            ops.insert(*equal_id);
            if let Some((sub, _)) = difference {
                ops.insert(*sub);
            }
            Some((left, right, ops))
        }
        _ => None,
    }
}

/// `value` as unsigned `a < b`, with the operations that compute it: an `INT_LESS`, or the
/// negation of `b <= a`.
fn strictly_below(defs: &Definitions, value: VarId) -> Option<(IdSet<OpId>, VarId, VarId)> {
    let (id, op) = defs.op(defs.copied(value))?;
    let mut ops = IdSet::default();
    ops.insert(*id);
    match op {
        SSAOp::IntLess { a, b, .. } => Some((ops, *a, *b)),
        SSAOp::BoolNot { src, .. } => {
            let (at_most, op) = defs.op(defs.copied(*src))?;
            let SSAOp::IntLessEqual { a, b, .. } = op else {
                return None;
            };
            ops.insert(*at_most);
            Some((ops, *b, *a))
        }
        _ => None,
    }
}

/// Whether a read of `width` bytes at `address` is a read of the convention's stack bound.
fn is_bound(
    func: &SSAFunction,
    bound: &SourceStackGuard,
    (root, offset): Affine,
    width: u32,
) -> bool {
    func.var(root).version == 0
        && func.storage_of(root) == Some(bound.base)
        && u64::try_from(offset).ok() == Some(bound.offset)
        && width == bound.width
}

/// Whether a block only calls a routine that re-enters the function, writing nothing but the
/// stack below and around its entry pointer (Go spills argument registers there, and the call
/// pushes its return address).
fn reenters(
    func: &SSAFunction,
    defs: &Definitions,
    machine: &SourceMachineContext,
    stack_pointer: CanonicalStorageId,
    block: u64,
) -> bool {
    // The function's own address: the root is a synthetic block when a branch also enters it.
    let entry = func.entry;
    let leaves = func.successors(block);
    if !(leaves.is_empty() || leaves == [entry]) {
        return false;
    }
    let Some(block) = func.get_block(block) else {
        return false;
    };
    let mut calls = block.ops().iter().filter_map(|op| match op {
        SSAOp::Call { target, .. } => Some(*target),
        _ => None,
    });
    let (Some(target), None) = (calls.next(), calls.next()) else {
        return false;
    };
    // A direct call names its target as the RAM it transfers to, or as a constant.
    let address = func
        .storage_of(target)
        .filter(|storage| storage.space == crate::CanonicalStorageSpace::Ram)
        .map(|storage| storage.offset)
        .or_else(|| func.var(target).constant_bits());
    address.is_some_and(|target| machine.reenters_caller(target))
        && block.ops().iter().all(|op| match op {
            SSAOp::Store { addr, .. } => {
                let (root, _) = defs.affine(func, *addr);
                func.var(root).version == 0 && func.storage_of(root) == Some(stack_pointer)
            }
            // The one modelled call and the boundary it states, the jump back, and values.
            SSAOp::Call { .. }
            | SSAOp::CallDefine { .. }
            | SSAOp::CallUse { .. }
            | SSAOp::CallRestore { .. }
            | SSAOp::Branch { .. }
            | SSAOp::Nop => true,
            op => is_value(op),
        })
}

/// Whether an operation only computes a value: no memory, no control, no trap.
fn is_value(op: &SSAOp<VarId>) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::IntAdd { .. }
            | SSAOp::IntSub { .. }
            | SSAOp::IntMult { .. }
            | SSAOp::IntNegate { .. }
            | SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::IntAnd { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. }
            | SSAOp::IntNot { .. }
            | SSAOp::IntLeft { .. }
            | SSAOp::IntRight { .. }
            | SSAOp::IntSRight { .. }
            | SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::Piece { .. }
            | SSAOp::Subpiece { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::PtrAdd { .. }
            | SSAOp::PtrSub { .. }
            | SSAOp::Cast { .. }
    )
}
