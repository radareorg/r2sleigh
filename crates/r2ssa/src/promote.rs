//! Frame slots nothing outside the function can observe, promoted to values.
//!
//! This runs on the lifted R2IL blocks, before SSA construction, so a slot the
//! function only ever writes and reads itself never becomes a memory effect at
//! all. It sat after `function.rs`'s seven-thousand-line test module, where
//! nothing looking for it would find it.

use std::collections::{BTreeMap, BTreeSet};

use r2il::{R2ILBlock, R2ILOp};

use super::*;

/// The `(base register, displacement)` an address computed in this block names.
///
/// The walk stops at a frame base, or at a register nothing earlier in the
/// block defines; a frame address parked in another register on the way is
/// followed back through it.
/// A frame address whose place is unknown: nothing below can say which slot
/// it reaches, so the function keeps its frame in memory.
fn unplaced(place: Option<i64>, block: &R2ILBlock, at: usize) -> Option<i64> {
    if place.is_none() {
        r2il::refusal_evidence!(
            "promote-stack-slot",
            "{:#x}:{at} forms a frame address the frame cannot place",
            block.addr
        );
    }
    place
}

/// Whether a prologue store spills a value the function was entered with --
/// a parameter, or a register the function saves for its caller: the slot is
/// that value's home, proven by dataflow and never by the register's name or
/// offset.
///
/// The walk runs back from the store through the entry block. A copy that
/// wrote the bytes being stored hands them on from its source, byte for byte
/// -- `mov eax, edi; mov [rbp-4], al` stores `dil` -- and anything else that
/// wrote them computed them. A call before the store may have left anything
/// in any register the convention does not have it preserve, so what follows
/// it is not what the function was entered with: `call f; mov [rbp-4], eax`
/// spills `f`'s result. What the walk reaches at the top of the block is a
/// register's entry value.
fn spills_an_incoming_value(entry: &R2ILBlock, at: usize, val: &r2il::Varnode) -> bool {
    let mut root = val.clone();
    for earlier in entry.ops[..at].iter().rev() {
        if matches!(earlier, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }) {
            return false;
        }
        let Some(dst) = earlier.output() else {
            continue;
        };
        if dst.space != root.space
            || dst.offset >= root.offset + u64::from(root.size)
            || root.offset >= dst.offset + u64::from(dst.size)
        {
            continue;
        }
        let covers = dst.offset <= root.offset
            && root.offset + u64::from(root.size) <= dst.offset + u64::from(dst.size);
        match earlier {
            R2ILOp::Copy { src, .. }
                if covers && src.size == dst.size && src.space != r2il::SpaceId::Const =>
            {
                root = r2il::Varnode {
                    space: src.space,
                    offset: src.offset + (root.offset - dst.offset),
                    size: root.size,
                    meta: None,
                };
            }
            _ => return false,
        }
    }
    root.space == r2il::SpaceId::Register
}

fn resolved_stack_address(
    block: &R2ILBlock,
    upto: usize,
    addr: &r2il::Varnode,
    is_frame_base: &dyn Fn(&r2il::Varnode) -> bool,
) -> Option<(r2il::Varnode, i64)> {
    if addr.space == r2il::SpaceId::Register && is_frame_base(addr) {
        return Some((addr.clone(), 0));
    }
    let mut current = addr.clone();
    let mut displacement = 0i64;
    let mut at = upto;
    while at > 0 {
        at -= 1;
        let op = &block.ops[at];
        let Some(dst) = op.output() else { continue };
        if *dst != current {
            continue;
        }
        match op {
            R2ILOp::Copy { src, .. } => current = src.clone(),
            R2ILOp::IntAdd { a, b, .. } => {
                if let Some(amount) = r2il_constant_before(block, at, b, 0) {
                    displacement += amount as i64;
                    current = a.clone();
                } else if let Some(amount) = r2il_constant_before(block, at, a, 0) {
                    displacement += amount as i64;
                    current = b.clone();
                } else {
                    return None;
                }
            }
            R2ILOp::IntSub { a, b, .. } => {
                displacement -= r2il_constant_before(block, at, b, 0)? as i64;
                current = a.clone();
            }
            _ => return None,
        }
        if current.space == r2il::SpaceId::Register && is_frame_base(&current) {
            return Some((current, displacement));
        }
    }
    (current.space == r2il::SpaceId::Register).then_some((current, displacement))
}

/// One access's place in the frame, in the stack pointer's coordinate.
///
/// An address through the frame pointer names the same slot as one through the
/// stack pointer; which register the compiler chose is not a property of the
/// slot, so both are answered in the one coordinate the widths are keyed by.
/// The constant a varnode holds at `upto` in `block`, through the copies and
/// integer arithmetic over constants that define it, or nothing.
fn r2il_constant_before(
    block: &R2ILBlock,
    upto: usize,
    varnode: &r2il::Varnode,
    depth: usize,
) -> Option<u64> {
    if varnode.space == r2il::SpaceId::Const {
        return Some(varnode.offset);
    }
    if depth >= 8 {
        return None;
    }
    let at = block.ops[..upto]
        .iter()
        .rposition(|op| op.output() == Some(varnode))?;
    let operand = |vn: &r2il::Varnode| r2il_constant_before(block, at, vn, depth + 1);
    let width_bits = varnode.size.checked_mul(8)?;
    let mask = if width_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    };
    let value = match &block.ops[at] {
        R2ILOp::Copy { src, .. } => operand(src)?,
        R2ILOp::IntAdd { a, b, .. } => operand(a)?.wrapping_add(operand(b)?),
        R2ILOp::IntSub { a, b, .. } => operand(a)?.wrapping_sub(operand(b)?),
        R2ILOp::IntMult { a, b, .. } => operand(a)?.wrapping_mul(operand(b)?),
        R2ILOp::IntOr { a, b, .. } => operand(a)? | operand(b)?,
        R2ILOp::IntLeft { a, b, .. } => {
            operand(a)?.checked_shl(u32::try_from(operand(b)?).ok()?)?
        }
        R2ILOp::IntZExt { src, .. } => operand(src)?,
        _ => return None,
    };
    Some(value & mask)
}

/// Leading zero bits a value is proven to carry before `upto` in this block.
fn r2il_leading_zeros_before(
    block: &R2ILBlock,
    upto: usize,
    varnode: &r2il::Varnode,
    depth: usize,
) -> Option<u32> {
    let width_bits = varnode.size.checked_mul(8)?;
    let bit_length = |value: u64| 64 - value.leading_zeros();
    if varnode.space == r2il::SpaceId::Const {
        return Some(width_bits.saturating_sub(bit_length(varnode.offset)));
    }
    if depth >= 8 {
        return None;
    }
    let at = block.ops[..upto]
        .iter()
        .rposition(|op| op.output() == Some(varnode))?;
    let operand = |vn: &r2il::Varnode| r2il_leading_zeros_before(block, at, vn, depth + 1);
    let constant = |vn: &r2il::Varnode| r2il_constant_before(block, at, vn, depth + 1);
    let zeros = match &block.ops[at] {
        R2ILOp::Copy { src, .. } if src.size == varnode.size => operand(src)?,
        R2ILOp::IntZExt { src, .. } => {
            width_bits.checked_sub(src.size.checked_mul(8)?)? + operand(src).unwrap_or(0)
        }
        R2ILOp::IntMult { a, b, .. } => match (constant(a), constant(b)) {
            (Some(scale), _) => operand(b)?.checked_sub(bit_length(scale))?,
            (_, Some(scale)) => operand(a)?.checked_sub(bit_length(scale))?,
            _ => return None,
        },
        R2ILOp::IntLeft { a, b, .. } => {
            operand(a)?.checked_sub(u32::try_from(constant(b)?).ok()?)?
        }
        R2ILOp::IntRight { a, b, .. } => {
            (operand(a)? + u32::try_from(constant(b)?).ok()?).min(width_bits)
        }
        R2ILOp::IntAnd { a, b, .. } => match (constant(a), constant(b)) {
            (Some(mask), _) => {
                (width_bits.saturating_sub(bit_length(mask))).max(operand(b).unwrap_or(0))
            }
            (_, Some(mask)) => {
                (width_bits.saturating_sub(bit_length(mask))).max(operand(a).unwrap_or(0))
            }
            _ => operand(a)?.max(operand(b)?),
        },
        R2ILOp::IntAdd { a, b, .. } => operand(a)?.min(operand(b)?).checked_sub(1)?,
        _ => return None,
    };
    Some(zeros.min(width_bits))
}

/// Whether a value's top bit is proven clear before `upto` in this block.
fn r2il_non_negative_before(block: &R2ILBlock, upto: usize, varnode: &r2il::Varnode) -> bool {
    r2il_leading_zeros_before(block, upto, varnode, 0).is_some_and(|zeros| zeros >= 1)
}

fn frame_displacement(
    is_stack_pointer: &impl Fn(&r2il::Varnode) -> bool,
    is_frame_pointer: &impl Fn(&r2il::Varnode) -> bool,
    frame_pointer_offset: Option<i64>,
    base: &r2il::Varnode,
    displacement: i64,
) -> Option<i64> {
    if is_stack_pointer(base) {
        return Some(displacement);
    }
    if is_frame_pointer(base) {
        return frame_pointer_offset.map(|offset| displacement + offset);
    }
    None
}

/// The space promoted stack slots live in: not memory, and not the lifter's
/// scratch either.
pub(crate) const PROMOTED_SLOT_SPACE: u32 = 0x5301;

/// Where a promoted frame slot sits relative to the entry frame, where this storage is one.
pub fn promoted_slot_offset(storage: &crate::CanonicalStorageId) -> Option<i64> {
    let promoted = storage.space == crate::CanonicalStorageSpace::Custom(PROMOTED_SLOT_SPACE);
    promoted.then_some(storage.offset as i64)
}

/// A stack slot promoted out of memory, keyed by where it sits in the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PromotedSlot {
    displacement: i64,
    width: u32,
}

/// One access to a promoted slot.
struct SlotAccess {
    block: usize,
    op: usize,
    slot: PromotedSlot,
}

/// Promote a private stack slot to a variable before construction runs.
///
/// A slot the program only ever writes and reads whole, whose address never
/// leaves the accesses that name it, behaves exactly like a register: `-O0`
/// spills a value into it and reads it back, and the C that says so has one
/// variable rather than a slot and a copy. Turning its stores and loads into
/// copies of one synthetic varnode lets the builder's own phi placement merge
/// it at joins, which is what a value that is one thing on one path and another
/// on a second needs and what no certificate can supply after the fact.
///
/// Every condition is checked here because construction is what decides which
/// value each read sees. A slot the source named is left alone: the name is
/// what the rendering is for, and a promoted slot carries none.
pub(crate) fn promote_private_stack_slots(
    blocks: &[R2ILBlock],
    stack_pointer: Option<CanonicalStorageId>,
    interface: Option<&SourceFunctionInterface>,
    calls_refund_stack: bool,
) -> Option<crate::phi::PromotedStackSlots> {
    r2il::refusal_evidence!("promote-stack-slot", "asked over {} blocks", blocks.len());
    let Some(stack_pointer) = stack_pointer else {
        r2il::refusal_evidence!("promote-stack-slot", "no stack pointer carrier");
        return None;
    };
    if stack_pointer.space != CanonicalStorageSpace::Register {
        r2il::refusal_evidence!("promote-stack-slot", "the stack pointer is not a register");
        return None;
    }
    let is_stack_pointer = |varnode: &r2il::Varnode| {
        varnode.space == r2il::SpaceId::Register && varnode.offset == stack_pointer.offset
    };
    let entry = blocks.first()?;
    // The prologue: the stack pointer decrements that open the frame, one or
    // several -- `stp x29, x30, [sp, #-0x60]!` then `sub sp, sp, #0x270` --
    // with the callee-saved stores between them. Every access counts from the
    // frame the last of them leaves; an access between two steps is moved to
    // that frame by the steps still to come.
    // A stack probe (`___chkstk_darwin`) may sit between the steps, so a call
    // does not end the prologue; the first write that is not a constant
    // decrement does.
    let mut steps = Vec::<(usize, i64)>::new();
    let mut sp_offset = 0i64;
    for (at, op) in entry.ops.iter().enumerate() {
        let Some(dst) = op.output() else {
            continue;
        };
        if !is_stack_pointer(dst) {
            continue;
        }
        // `sub sp, sp, #1, lsl #12` subtracts a constant the lift computes in a
        // temporary; the amount is what matters, not how it was spelled.
        let step = match op {
            R2ILOp::IntSub { a, b, .. } if is_stack_pointer(a) => {
                r2il_constant_before(entry, at, b, 0).map(|amount| -(amount as i64))
            }
            R2ILOp::IntAdd { a, b, .. } if is_stack_pointer(a) => {
                r2il_constant_before(entry, at, b, 0).map(|amount| amount as i64)
            }
            R2ILOp::Copy { src, .. } => resolved_stack_address(entry, at, src, &is_stack_pointer)
                .filter(|(base, _)| is_stack_pointer(base))
                .map(|(_, displacement)| displacement),
            _ => None,
        };
        match step {
            Some(step) if step < 0 => {
                sp_offset += step;
                steps.push((at, sp_offset));
            }
            _ => break,
        }
    }
    let Some(&(prologue_at, final_offset)) = steps.last() else {
        r2il::refusal_evidence!("promote-stack-slot", "no prologue frame subtraction");
        return None;
    };
    let frame_size = -final_offset;
    // How far the stack pointer at `at` in the entry block sits above the
    // frame the prologue leaves: zero once the prologue is done.
    let entry_adjustment = |block_index: usize, at: usize| -> i64 {
        if block_index != 0 || at > prologue_at {
            return 0;
        }
        let reached = steps
            .iter()
            .take_while(|(step_at, _)| *step_at < at)
            .last()
            .map_or(0, |(_, offset)| *offset);
        reached - final_offset
    };
    // The register the prologue points at the frame, where there is one. Code
    // compiled without optimisation addresses its locals through it as soon as
    // the function calls anything, so without this the pass only ever sees a
    // leaf.
    let frame_pointer = entry
        .ops
        .iter()
        .enumerate()
        .skip(steps.first().map_or(0, |(at, _)| *at + 1))
        .find_map(|(at, op)| {
            let R2ILOp::Copy { dst, src } = op else {
                return None;
            };
            if dst.space != r2il::SpaceId::Register || is_stack_pointer(dst) {
                return None;
            }
            let (base, displacement) = resolved_stack_address(entry, at, src, &is_stack_pointer)?;
            is_stack_pointer(&base)
                .then(|| (at, dst.clone(), displacement + entry_adjustment(0, at)))
        });
    let is_frame_pointer = |varnode: &r2il::Varnode| {
        frame_pointer
            .as_ref()
            .is_some_and(|(_, register, _)| register == varnode)
    };
    let frame_base_register =
        |varnode: &r2il::Varnode| is_stack_pointer(varnode) || is_frame_pointer(varnode);
    // The frame pointer is a base only once the prologue has pointed it at the
    // frame: before that it still holds the caller's, which the prologue saves
    // like any other callee-saved register.
    let is_frame_base = |varnode: &r2il::Varnode, block_index: usize, at: usize| {
        is_stack_pointer(varnode)
            || is_frame_pointer(varnode)
                && !(block_index == 0
                    && frame_pointer
                        .as_ref()
                        .is_some_and(|(established, _, _)| at <= *established))
    };
    // A block that leaves the function -- by returning, or by a branch to an
    // address no block of it owns, which is a tail call -- may restore the
    // stack pointer and read the frame at its new place on the way out.
    let block_addrs = blocks
        .iter()
        .map(|block| block.addr)
        .collect::<BTreeSet<_>>();
    let leaves = |block: &R2ILBlock| match block.ops.last() {
        Some(R2ILOp::Return { .. }) => true,
        Some(R2ILOp::Branch { target }) => {
            target.space == r2il::SpaceId::Ram && !block_addrs.contains(&target.offset)
        }
        _ => false,
    };
    // Which displacements the source named, in the coordinate the accesses use.
    let declared = interface
        .map(|interface| {
            interface
                .stack_slots()
                .iter()
                .filter(|slot| slot.base() == StackAddressBase::StackPointer)
                .map(|slot| {
                    let start = slot.offset() + frame_size;
                    (start, start + i64::from(slot.size_bytes()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // Whether any declared object covers part of a place.
    let declared_covers = |displacement: i64, width: u32| {
        declared
            .iter()
            .any(|(start, end)| *start < displacement + i64::from(width) && displacement < *end)
    };

    let mut accesses = Vec::new();
    let mut widths = BTreeMap::<i64, BTreeSet<u32>>::new();
    // Frame addresses that left the frame's own accesses: into a register, a
    // store, or a call. Whatever they point at, and everything above it, may
    // be reached from outside, so those places stay in memory.
    let mut escaped = BTreeSet::<i64>::new();
    // A slot the prologue fills from an argument register is that parameter's
    // home, and the parameter entity already owns it: promoting it leaves the
    // parameter's binding with nothing but copies of itself and no write at
    // all, which placement reads as an object assigned nowhere.
    let mut parameter_homes = BTreeSet::<i64>::new();
    let fp_offset = frame_pointer.as_ref().map(|(_, _, offset)| *offset);
    for (index, block) in blocks.iter().enumerate() {
        let block_leaves = leaves(block);
        // How far the stack pointer sits above the frame here: the whole frame
        // before the prologue, nothing once it is open, and the epilogue's
        // restores on the way out. `None` once a write moved it somewhere the
        // frame cannot name.
        let mut delta: Option<i64> = Some(if index == 0 { frame_size } else { 0 });
        // Everything this block derives from a frame base, with the place in
        // the frame it points at.
        let mut derived = Vec::<(r2il::Varnode, i64)>::new();
        // Frame addresses displaced by an index: at or above the place named, wherever the index reaches.
        let mut indexed = Vec::<(r2il::Varnode, i64)>::new();
        let holds = |set: &Vec<(r2il::Varnode, i64)>, want: &r2il::Varnode| {
            set.iter().any(|(held, _)| held == want)
        };
        let from_of = |set: &Vec<(r2il::Varnode, i64)>, want: &r2il::Varnode| {
            set.iter()
                .find(|(held, _)| held == want)
                .map(|(_, from)| *from)
        };
        // The slot a call spends on its return address: the callee refunds
        // it, so neither the move nor the store is the frame's.
        let call_pushes = block
            .ops
            .windows(3)
            .enumerate()
            .filter(|(_, ops)| {
                calls_refund_stack
                    && matches!(
                        (&ops[0], &ops[1], &ops[2]),
                        (
                            R2ILOp::IntSub { dst, a, .. },
                            R2ILOp::Store { addr, val, .. },
                            R2ILOp::Call { .. } | R2ILOp::CallInd { .. },
                        ) if is_stack_pointer(dst)
                            && is_stack_pointer(a)
                            && addr == dst
                            && val.space == r2il::SpaceId::Const
                    )
            })
            .map(|(at, _)| at)
            .collect::<BTreeSet<_>>();
        for (at, op) in block.ops.iter().enumerate() {
            if call_pushes.contains(&at) || at > 0 && call_pushes.contains(&(at - 1)) {
                continue;
            }
            if let Some(dst) = op.output()
                && is_stack_pointer(dst)
            {
                // Where the stack pointer lands, relative to the frame.
                let landed = match op {
                    R2ILOp::IntSub { a, b, .. } if is_stack_pointer(a) => delta
                        .zip(r2il_constant_before(block, at, b, 0))
                        .map(|(delta, amount)| delta - amount as i64),
                    R2ILOp::IntAdd { a, b, .. } if is_stack_pointer(a) => delta
                        .zip(r2il_constant_before(block, at, b, 0))
                        .map(|(delta, amount)| delta + amount as i64),
                    R2ILOp::Copy { src, .. } => {
                        resolved_stack_address(block, at, src, &frame_base_register).and_then(
                            |(base, displacement)| {
                                if is_stack_pointer(&base) {
                                    delta.map(|delta| delta + displacement)
                                } else if is_frame_pointer(&base) {
                                    fp_offset.map(|offset| offset + displacement)
                                } else {
                                    None
                                }
                            },
                        )
                    }
                    _ => None,
                };
                let allowed = match (delta, landed) {
                    (Some(from), Some(to)) if to < from => index == 0,
                    (Some(_), Some(_)) => block_leaves,
                    (_, None) => block_leaves,
                    (None, Some(_)) => false,
                };
                if !allowed {
                    r2il::refusal_evidence!(
                        "promote-stack-slot",
                        "{:#x}:{at} moves the stack pointer from {delta:?} to {landed:?} under the frame's accesses",
                        block.addr
                    );
                    return None;
                }
                delta = landed;
                continue;
            }
            if let Some(dst) = op.output()
                && is_frame_pointer(dst)
                && !(index == 0
                    && frame_pointer
                        .as_ref()
                        .is_some_and(|(established, _, _)| at <= *established))
                && !block_leaves
            {
                r2il::refusal_evidence!(
                    "promote-stack-slot",
                    "{:#x}:{at} writes the frame pointer and does not leave",
                    block.addr
                );
                return None;
            }
            // A read of the stack pointer itself is not a read of a slot: the
            // epilogue computes its own flags from it. What may not happen is a
            // *derived* address reaching anything but an access below.
            // Where a frame-like value points: `None` for a value that is not
            // one, `Some(None)` for a base the frame cannot place here.
            let place_of = |want: &r2il::Varnode| -> Option<Option<i64>> {
                if let Some((_, place)) = derived.iter().find(|(held, _)| held == want) {
                    Some(Some(*place))
                } else if is_stack_pointer(want) {
                    Some(delta)
                } else if is_frame_base(want, index, at) {
                    Some(fp_offset)
                } else {
                    None
                }
            };
            let mut derived_here = false;
            match op {
                R2ILOp::Load { dst, addr, .. } => {
                    r2il::refusal_evidence!(
                        "promote-stack-slot",
                        "{:#x}:{at} load {dst} through {addr}: held={} frame_base={} place={:?}",
                        block.addr,
                        holds(&derived, addr),
                        is_frame_base(addr, index, at),
                        place_of(addr)
                    );
                    if holds(&derived, addr) || is_frame_base(addr, index, at) {
                        let Some((base, displacement)) =
                            resolved_stack_address(block, at, addr, &frame_base_register)
                        else {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} loads through an address that resolves to no place",
                                block.addr
                            );
                            return None;
                        };
                        let displacement = frame_displacement(
                            &is_stack_pointer,
                            &is_frame_pointer,
                            frame_pointer.as_ref().map(|(_, _, offset)| *offset),
                            &base,
                            displacement,
                        );
                        let Some(displacement) = displacement
                            .zip(if is_stack_pointer(&base) {
                                delta
                            } else {
                                Some(0)
                            })
                            .map(|(displacement, delta)| displacement + delta)
                        else {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} accesses through {base} at a place the frame cannot name (delta {delta:?})",
                                block.addr
                            );
                            return None;
                        };
                        widths.entry(displacement).or_default().insert(dst.size);
                        accesses.push(SlotAccess {
                            block: index,
                            op: at,
                            slot: PromotedSlot {
                                displacement,
                                width: dst.size,
                            },
                        });
                    }
                }
                R2ILOp::Store { addr, val, .. } => {
                    if let Some(place) = place_of(val) {
                        r2il::refusal_evidence!(
                            "promote-stack-slot",
                            "{:#x}:{at} stores frame address {val} at place {place:?}",
                            block.addr
                        );
                        let Some(place) = place else {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} stores a frame address the frame cannot place",
                                block.addr
                            );
                            return None;
                        };
                        escaped.insert(place);
                    }
                    if holds(&derived, addr) || is_frame_base(addr, index, at) {
                        let Some((base, displacement)) =
                            resolved_stack_address(block, at, addr, &frame_base_register)
                        else {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} stores through an address that resolves to no place",
                                block.addr
                            );
                            return None;
                        };
                        let displacement = frame_displacement(
                            &is_stack_pointer,
                            &is_frame_pointer,
                            frame_pointer.as_ref().map(|(_, _, offset)| *offset),
                            &base,
                            displacement,
                        );
                        let Some(displacement) = displacement
                            .zip(if is_stack_pointer(&base) {
                                delta
                            } else {
                                Some(0)
                            })
                            .map(|(displacement, delta)| displacement + delta)
                        else {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} accesses through {base} at a place the frame cannot name (delta {delta:?})",
                                block.addr
                            );
                            return None;
                        };
                        widths.entry(displacement).or_default().insert(val.size);
                        if index == 0 && spills_an_incoming_value(block, at, val) {
                            parameter_homes.insert(displacement);
                        }
                        accesses.push(SlotAccess {
                            block: index,
                            op: at,
                            slot: PromotedSlot {
                                displacement,
                                width: val.size,
                            },
                        });
                    }
                }
                // The frame bases themselves are not derived values: the
                // prologue's own subtraction rewrites the stack pointer and the
                // epilogue reads it back to compute its flags, and neither is a
                // frame address travelling somewhere it should not.
                R2ILOp::Copy { dst, src } if place_of(src).is_some() => {
                    let place = place_of(src).flatten();
                    if !is_frame_base(dst, index, at) {
                        {
                            // A redefinition replaces the place the register held, so a later reader finds this one and not the first.
                            let place = unplaced(place, block, at)?;
                            derived.retain(|(held, _)| held != dst);
                            derived.push((dst.clone(), place));
                            derived_here = true;
                        }
                    }
                }
                R2ILOp::IntAdd { dst, a, b } if place_of(a).is_some() || place_of(b).is_some() => {
                    let (base, other) = if place_of(a).is_some() {
                        (a, b)
                    } else {
                        (b, a)
                    };
                    let place = place_of(base)
                        .flatten()
                        .zip(r2il_constant_before(block, at, other, 0));
                    let place = place.map(|(place, amount)| place + amount as i64);
                    r2il::refusal_evidence!(
                        "promote-stack-slot",
                        "{:#x}:{at} {dst} = {base} + {other} derives place {place:?} (base {:?}, frame base {})",
                        block.addr,
                        place_of(base),
                        is_frame_base(dst, index, at)
                    );
                    if !is_frame_base(dst, index, at) {
                        // A non-negative index of unknown size reaches the base and everything above it, and nothing below.
                        if place.is_none()
                            && let Some(from) = place_of(base).flatten()
                            && r2il_constant_before(block, at, other, 0).is_none()
                            && r2il_non_negative_before(block, at, other)
                        {
                            r2il::refusal_evidence!(
                                "promote-stack-slot",
                                "{:#x}:{at} {dst} indexes the frame from {from}",
                                block.addr
                            );
                            derived.retain(|(held, _)| held != dst);
                            indexed.retain(|(held, _)| held != dst);
                            indexed.push((dst.clone(), from));
                            escaped.insert(from);
                            derived_here = true;
                        } else {
                            // A redefinition replaces the place the register held, so a later reader finds this one and not the first.
                            let place = unplaced(place, block, at)?;
                            derived.retain(|(held, _)| held != dst);
                            indexed.retain(|(held, _)| held != dst);
                            derived.push((dst.clone(), place));
                            derived_here = true;
                        }
                    }
                }
                R2ILOp::IntAdd { dst, a, b } | R2ILOp::IntSub { dst, a, b }
                    if holds(&indexed, a) || holds(&indexed, b) =>
                {
                    let (base, other) = if holds(&indexed, a) { (a, b) } else { (b, a) };
                    let from = from_of(&indexed, base).expect("held");
                    let amount =
                        r2il_constant_before(block, at, other, 0).map(|amount| amount as i64);
                    let from = match (op, amount) {
                        (R2ILOp::IntAdd { .. }, Some(amount)) => Some(from + amount),
                        (R2ILOp::IntSub { .. }, Some(amount)) if base == a => Some(from - amount),
                        (R2ILOp::IntAdd { .. }, None)
                            if r2il_non_negative_before(block, at, other) =>
                        {
                            Some(from)
                        }
                        _ => None,
                    };
                    let Some(from) = from else {
                        r2il::refusal_evidence!(
                            "promote-stack-slot",
                            "{:#x}:{at} moves an indexed frame address somewhere the frame cannot place",
                            block.addr
                        );
                        return None;
                    };
                    if !is_frame_base(dst, index, at) {
                        derived.retain(|(held, _)| held != dst);
                        indexed.retain(|(held, _)| held != dst);
                        indexed.push((dst.clone(), from));
                        escaped.insert(from);
                        derived_here = true;
                    }
                }
                R2ILOp::Copy { dst, src } if holds(&indexed, src) => {
                    let from = from_of(&indexed, src).expect("held");
                    if !is_frame_base(dst, index, at) {
                        derived.retain(|(held, _)| held != dst);
                        indexed.retain(|(held, _)| held != dst);
                        indexed.push((dst.clone(), from));
                        derived_here = true;
                    }
                }
                R2ILOp::IntSub { dst, a, b } if place_of(a).is_some() || place_of(b).is_some() => {
                    let place = place_of(a)
                        .flatten()
                        .zip(r2il_constant_before(block, at, b, 0))
                        .map(|(place, amount)| place - amount as i64);
                    if !is_frame_base(dst, index, at) {
                        {
                            // A redefinition replaces the place the register held, so a later reader finds this one and not the first.
                            let place = unplaced(place, block, at)?;
                            derived.retain(|(held, _)| held != dst);
                            derived.push((dst.clone(), place));
                            derived_here = true;
                        }
                    }
                }
                // A comparison of a frame address neither reaches the slot nor
                // lets anything else reach it; the lift computes flags beside
                // every address it forms.
                _ if op.output().is_some_and(|dst| dst.size == 1) => {}
                _ if op
                    .inputs()
                    .into_iter()
                    .any(|input| holds(&derived, input) || holds(&indexed, input)) =>
                {
                    r2il::refusal_evidence!(
                        "promote-stack-slot",
                        "{:#x}:{at} reads a frame address it does not access through: {op}",
                        block.addr
                    );
                    return None;
                }
                _ => {}
            }
            // A frame address that lands in a register leaves this block. The
            // stack pointer's own prologue and epilogue writes are not that:
            // the discipline check above has already accounted for them.
            if let Some(dst) = op.output()
                && let Some((_, place)) = derived.iter().find(|(held, _)| held == dst)
                && dst.space != r2il::SpaceId::Unique
                && !is_frame_base(dst, index, at)
            {
                escaped.insert(*place);
            }
            // A temporary the lift reuses holds a frame address only until it
            // is next written with something else.
            if !derived_here && let Some(dst) = op.output() {
                derived.retain(|(held, _)| held != dst);
                indexed.retain(|(held, _)| held != dst);
            }
        }
    }
    // One width per place, no place overlapping another, and nothing the source
    // named.
    // A spilled incoming value the function never loads back was passed on,
    // not kept: the slot is an outgoing argument, not a home.
    let read_back = |displacement: i64| {
        accesses.iter().any(|access| {
            access.slot.displacement == displacement
                && matches!(blocks[access.block].ops[access.op], R2ILOp::Load { .. })
        })
    };
    let mut promotable = BTreeSet::<PromotedSlot>::new();
    for (displacement, sizes) in &widths {
        let is_home = parameter_homes.contains(displacement) && read_back(*displacement);
        let reachable = escaped.range(..=*displacement).next_back();
        let widest = *sizes.iter().next_back().expect("one width");
        let is_declared = declared_covers(*displacement, widest);
        if sizes.len() != 1 || is_declared || is_home || reachable.is_some() {
            r2il::refusal_evidence!(
                "promote-stack-slot",
                "slot at {displacement} stays in memory: widths {sizes:?}, declared {is_declared}, parameter home {is_home}, escaped base {reachable:?}"
            );
            continue;
        }
        let width = widest;
        let overlaps = widths.iter().any(|(other, other_sizes)| {
            other != displacement
                && other_sizes.iter().any(|other_width| {
                    *other < displacement + i64::from(width)
                        && *displacement < other + i64::from(*other_width)
                })
        });
        if overlaps {
            r2il::refusal_evidence!(
                "promote-stack-slot",
                "slot at {displacement} of {width} bytes overlaps another place"
            );
            continue;
        }
        promotable.insert(PromotedSlot {
            displacement: *displacement,
            width,
        });
    }
    if promotable.is_empty() {
        r2il::refusal_evidence!(
            "promote-stack-slot",
            "no slot qualifies of {} places, {} declared",
            widths.len(),
            declared.len()
        );
        return None;
    }
    let mut varnode_for = BTreeMap::<PromotedSlot, r2il::Varnode>::new();
    for slot in &promotable {
        varnode_for.insert(
            *slot,
            r2il::Varnode {
                // Its own space, not `Unique`. A lowering temporary is
                // block-local scratch and several rules read the space to say
                // so; a promoted slot is a variable of the function and its
                // declaration has to dominate every region that reads it.
                space: r2il::SpaceId::Custom(PROMOTED_SLOT_SPACE),
                // Where the slot sits relative to the frame the function was
                // entered with, which is the coordinate every other frame
                // object is named by, so the promoted variable keeps the name
                // the slot had. Displacements are distinct, so the offsets are.
                offset: (slot.displacement - frame_size) as u64,
                size: slot.width,
                meta: None,
            },
        );
    }
    let mut rewrites = crate::phi::PromotedStackSlots::new();
    for access in &accesses {
        if let Some(varnode) = varnode_for.get(&access.slot) {
            rewrites.insert((blocks[access.block].addr, access.op), varnode.clone());
        }
    }
    if rewrites.is_empty() {
        r2il::refusal_evidence!(
            "promote-stack-slot",
            "{} promotable slots but no access rewrites",
            promotable.len()
        );
        return None;
    }
    r2il::refusal_evidence!(
        "promote-stack-slot",
        "{} slots promoted out of memory across {} accesses: {:?}",
        promotable.len(),
        rewrites.len(),
        promotable.iter().collect::<Vec<_>>()
    );
    Some(rewrites)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn unique(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Unique, offset, size)
    }

    /// `sp -= 32; [sp + 8] = val; load [sp + 8]` with `before_the_spill`
    /// ahead of the store: how many of the slot's accesses are promoted.
    fn promoted_accesses(before_the_spill: Vec<R2ILOp>, val: Varnode) -> usize {
        let sp = reg(0, 8);
        let width = val.size;
        let mut block = R2ILBlock::new(0x4000, 4);
        block.push(R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: Varnode::constant(32, 8),
        });
        for op in before_the_spill {
            block.push(op);
        }
        block.push(R2ILOp::IntAdd {
            dst: unique(0x100, 8),
            a: sp.clone(),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: unique(0x100, 8),
            val,
        });
        block.push(R2ILOp::IntAdd {
            dst: unique(0x108, 8),
            a: sp,
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Load {
            dst: unique(0x110, width),
            space: SpaceId::Ram,
            addr: unique(0x108, 8),
        });
        block.push(R2ILOp::Return { target: reg(8, 8) });
        let storage = |offset| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        promote_private_stack_slots(&[block], Some(storage(0)), None, true)
            .map_or(0, |promoted| promoted.len())
    }

    #[test]
    fn a_home_is_proven_by_the_entry_value_it_spills() {
        // [sp + 8] = r2 before anything writes r2: its entry value, the
        // parameter's home, which stays in memory under the parameter's name.
        assert_eq!(promoted_accesses(Vec::new(), reg(24, 8)), 0);

        // The same register after a call holds what the call left, not the
        // parameter: `call f; mov [rbp-4], eax` spills a result, and the slot
        // is an ordinary private one.
        let call = R2ILOp::Call {
            target: Varnode::constant(0x9000, 8),
        };
        assert_eq!(promoted_accesses(vec![call], reg(24, 8)), 2);

        // A lane of a copy of the parameter is the parameter's lane:
        // `mov eax, edi; mov [rbp-4], al` spills its low byte.
        let copy = R2ILOp::Copy {
            dst: reg(16, 8),
            src: reg(24, 8),
        };
        assert_eq!(promoted_accesses(vec![copy], reg(16, 1)), 0);

        // A register computed before the store is no one's entry value.
        let computed = R2ILOp::IntAdd {
            dst: reg(24, 8),
            a: reg(24, 8),
            b: Varnode::constant(1, 8),
        };
        assert_eq!(promoted_accesses(vec![computed], reg(24, 8)), 2);
    }
}
