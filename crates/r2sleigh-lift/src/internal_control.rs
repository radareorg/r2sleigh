//! Normalization for P-code-relative control flow inside one instruction.
//!
//! Ghidra usually encodes instruction-local branches with a constant-space
//! target whose signed offset is relative to the branch operation's index.
//! Some specifications instead resolve a skip to the RAM address of the next
//! instruction. Those edges are not machine CFG edges. Forward branches over
//! speculatable value operations are converted to explicit value selects;
//! unsupported local control becomes `Unimplemented` so downstream consumers
//! refuse instead of inventing a CFG.

use std::collections::{BTreeMap, HashMap, HashSet};

use r2il::{BlockTransferKind, OpMetadata, R2ILBlock, R2ILOp, SpaceId, Varnode};

pub(crate) fn normalize_instruction_local_control(block: &mut R2ILBlock) {
    // A repeated string instruction's p-code is a loop, and the loop is how the
    // specification writes a block operation. Recognising it first is what
    // keeps the guard below from turning the whole instruction into
    // `Unimplemented`, which is all it could otherwise do with a backward edge.
    if let Some(rewritten) = block_transfer_from_repeat(block) {
        block.ops = rewritten;
        block.op_metadata = BTreeMap::new();
        return;
    }
    loop {
        let Some((branch_index, branch, target_index)) = block
            .ops
            .iter()
            .enumerate()
            .find_map(|(index, op)| local_branch(block, index, op))
        else {
            break;
        };

        if target_index <= branch_index || target_index > block.ops.len() {
            block.ops[branch_index] = R2ILOp::Unimplemented;
            continue;
        }

        match branch {
            LocalBranch::Unconditional(_) => {
                rewrite_unconditional_forward_branch(block, branch_index, target_index);
            }
            LocalBranch::Conditional { cond, .. } => {
                if block.ops[branch_index + 1..target_index]
                    .iter()
                    .all(R2ILOp::is_speculatable_value)
                {
                    rewrite_conditional_forward_branch(block, branch_index, target_index, cond);
                } else {
                    block.ops[branch_index] = R2ILOp::Unimplemented;
                }
            }
        }
    }
}

/// One pointer step of a string instruction, and the saved pointer it wrote.
///
/// Sleigh writes `p += width` or `p -= width` as a single expression over the
/// direction flag: the old pointer is saved, the ascending result computed, and
/// twice the width subtracted when the flag is set.
struct PointerStep {
    pointer: Varnode,
    saved: Varnode,
    direction: Varnode,
    width: u64,
}

fn constant_value(varnode: &Varnode) -> Option<u64> {
    (varnode.space == SpaceId::Const).then_some(varnode.offset)
}

fn same(a: &Varnode, b: &Varnode) -> bool {
    a.space == b.space && a.offset == b.offset && a.size == b.size
}

/// Match `saved = p; t1 = p + w; t2 = zext(df); t3 = 2w * t2; p = t1 - t3`.
fn pointer_step(ops: &[R2ILOp], at: usize) -> Option<(PointerStep, usize)> {
    let [
        R2ILOp::Copy {
            dst: saved,
            src: base,
        },
        R2ILOp::IntAdd {
            dst: ascending,
            a: add_base,
            b: width,
        },
        R2ILOp::IntZExt {
            dst: widened,
            src: direction,
        },
        R2ILOp::IntMult {
            dst: scaled,
            a: twice,
            b: scale_source,
        },
        R2ILOp::IntSub {
            dst: stepped,
            a: sub_base,
            b: subtrahend,
        },
    ] = ops.get(at..at.checked_add(5)?)?
    else {
        return None;
    };
    let width = constant_value(width)?;
    if width == 0
        || !same(base, add_base)
        || !same(base, stepped)
        || !same(ascending, sub_base)
        || !same(widened, scale_source)
        || !same(scaled, subtrahend)
        || constant_value(twice)? != width.checked_mul(2)?
    {
        return None;
    }
    Some((
        PointerStep {
            pointer: base.clone(),
            saved: saved.clone(),
            direction: direction.clone(),
            width,
        },
        at + 5,
    ))
}

/// The block operation a repeated string instruction performs, with the
/// register updates it also performs written beside it.
///
/// The shape proved here is the whole of it: a guard leaving the instruction
/// when the counter is zero, a decrement of that counter by one, one or two
/// pointer steps of the same width in the same direction, the transfer itself,
/// and a backward branch to this instruction. Anything else is not this
/// operation and is left to the general normalization.
fn block_transfer_from_repeat(block: &R2ILBlock) -> Option<Vec<R2ILOp>> {
    let ops = &block.ops;
    let last = ops.len().checked_sub(1)?;
    let R2ILOp::Branch { target } = &ops[last] else {
        return None;
    };
    if target.space != SpaceId::Ram || target.offset != block.addr {
        return None;
    }
    let [
        R2ILOp::IntEqual {
            dst: guard,
            a: counter,
            b: zero,
        },
        R2ILOp::CBranch { target: exit, cond },
    ] = ops.get(0..2)?
    else {
        return None;
    };
    let fallthrough = block.addr.checked_add(u64::from(block.size))?;
    if constant_value(zero)? != 0
        || !same(guard, cond)
        || exit.space != SpaceId::Ram
        || exit.offset != fallthrough
    {
        return None;
    }
    let R2ILOp::IntSub {
        dst: decremented,
        a: decrement_base,
        b: one,
    } = &ops[2]
    else {
        return None;
    };
    if !same(counter, decremented) || !same(counter, decrement_base) || constant_value(one)? != 1 {
        return None;
    }

    let (destination, mut cursor) = pointer_step(ops, 3)?;
    let source = match pointer_step(ops, cursor) {
        Some((step, next)) => {
            cursor = next;
            Some(step)
        }
        None => None,
    };
    if let Some(source) = &source
        && (source.width != destination.width || !same(&source.direction, &destination.direction))
    {
        return None;
    }

    // The transfer. A move loads through the saved source pointer and stores
    // through the saved destination; a fill stores a register's value.
    let (kind, transferred) = match ops.get(cursor..last)? {
        [
            R2ILOp::Load {
                dst: loaded,
                space: SpaceId::Ram,
                addr,
            },
            R2ILOp::Copy {
                dst: staged,
                src: staging_source,
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: store_addr,
                val,
            },
        ] => {
            let source = source.as_ref()?;
            if !same(addr, &source.saved)
                || !same(loaded, staging_source)
                || !same(staged, val)
                || !same(store_addr, &destination.saved)
                || u64::from(loaded.size) != destination.width
            {
                return None;
            }
            (BlockTransferKind::Move, source.pointer.clone())
        }
        [
            R2ILOp::Copy {
                dst: staged,
                src: filled,
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: store_addr,
                val,
            },
        ] => {
            if source.is_some()
                || !same(staged, val)
                || !same(store_addr, &destination.saved)
                || u64::from(filled.size) != destination.width
            {
                return None;
            }
            (BlockTransferKind::Fill, filled.clone())
        }
        _ => return None,
    };

    let element_size = u32::try_from(destination.width).ok()?;
    let mut rewritten = vec![R2ILOp::BlockTransfer {
        space: SpaceId::Ram,
        kind,
        destination: destination.pointer.clone(),
        source: transferred,
        count: counter.clone(),
        direction: destination.direction.clone(),
        element_size,
    }];
    // The instruction advances both pointers by the whole extent and leaves the
    // counter at zero. Those are its writes, and they are ordinary operations.
    let mut allocator = InstructionTempAllocator::for_ops(ops);
    let extent = allocator.allocate(counter.size)?;
    let widened_direction = allocator.allocate(counter.size)?;
    let signed_extent = allocator.allocate(counter.size)?;
    let twice_extent = allocator.allocate(counter.size)?;
    rewritten.push(R2ILOp::IntMult {
        dst: extent.clone(),
        a: counter.clone(),
        b: Varnode::constant(destination.width, counter.size),
    });
    rewritten.push(R2ILOp::IntZExt {
        dst: widened_direction.clone(),
        src: destination.direction.clone(),
    });
    rewritten.push(R2ILOp::IntMult {
        dst: twice_extent.clone(),
        a: extent.clone(),
        b: widened_direction.clone(),
    });
    rewritten.push(R2ILOp::IntMult {
        dst: twice_extent.clone(),
        a: twice_extent.clone(),
        b: Varnode::constant(2, counter.size),
    });
    rewritten.push(R2ILOp::IntSub {
        dst: signed_extent.clone(),
        a: extent.clone(),
        b: twice_extent,
    });
    for pointer in [Some(&destination), source.as_ref()].into_iter().flatten() {
        rewritten.push(R2ILOp::IntAdd {
            dst: pointer.pointer.clone(),
            a: pointer.pointer.clone(),
            b: signed_extent.clone(),
        });
    }
    rewritten.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, counter.size),
    });
    Some(rewritten)
}

#[derive(Debug)]
enum LocalBranch {
    Unconditional(Varnode),
    Conditional { target: Varnode, cond: Varnode },
}

impl LocalBranch {
    fn target(&self) -> &Varnode {
        match self {
            Self::Unconditional(target) | Self::Conditional { target, .. } => target,
        }
    }
}

fn local_branch(
    block: &R2ILBlock,
    branch_index: usize,
    op: &R2ILOp,
) -> Option<(usize, LocalBranch, usize)> {
    let branch = match op {
        R2ILOp::Branch { target } => LocalBranch::Unconditional(target.clone()),
        R2ILOp::CBranch { target, cond } => LocalBranch::Conditional {
            target: target.clone(),
            cond: cond.clone(),
        },
        _ => return None,
    };
    let target_index = match branch.target().space {
        SpaceId::Const => relative_target_index(branch_index, branch.target()),
        // Some Sleigh specifications spell a local skip to the end of an
        // instruction as the RAM address of the following instruction rather
        // than as a constant-space relative P-code label. It is local only
        // when operations still follow the branch in this single-instruction
        // block; an ordinary native branch to its fallthrough has no such
        // operations and must remain control flow.
        SpaceId::Ram
            if branch_index + 1 < block.ops.len()
                && branch.target().offset == block.addr.checked_add(u64::from(block.size))? =>
        {
            Some(block.ops.len())
        }
        _ => None,
    }?;
    Some((branch_index, branch, target_index))
}

fn relative_target_index(branch_index: usize, target: &Varnode) -> Option<usize> {
    let bit_width = target.size.checked_mul(8)?;
    if bit_width == 0 || bit_width > 64 {
        return None;
    }
    let shift = 64u32.checked_sub(bit_width)?;
    let relative = ((target.offset << shift) as i64) >> shift;
    branch_index.checked_add_signed(isize::try_from(relative).ok()?)
}

fn rewrite_unconditional_forward_branch(
    block: &mut R2ILBlock,
    branch_index: usize,
    target_index: usize,
) {
    let old_ops = std::mem::take(&mut block.ops);
    let old_metadata = std::mem::take(&mut block.op_metadata);
    let mut ops = Vec::with_capacity(old_ops.len().saturating_sub(target_index - branch_index));
    let mut metadata = BTreeMap::new();

    for (old_index, op) in old_ops.into_iter().enumerate() {
        if old_index >= branch_index && old_index < target_index {
            continue;
        }
        push_with_old_metadata(&mut ops, &mut metadata, op, &old_metadata, old_index);
    }
    block.ops = ops;
    block.op_metadata = metadata;
}

fn rewrite_conditional_forward_branch(
    block: &mut R2ILBlock,
    branch_index: usize,
    target_index: usize,
    cond: Varnode,
) {
    let old_ops = std::mem::take(&mut block.ops);
    let old_metadata = std::mem::take(&mut block.op_metadata);
    let old_len = old_ops.len();
    let mut allocator = InstructionTempAllocator::for_ops(&old_ops);
    let mut ops = Vec::with_capacity(old_ops.len() + target_index - branch_index - 1);
    let mut metadata = BTreeMap::new();
    let mut live_at_target = HashSet::new();
    for op in old_ops[target_index..].iter().rev() {
        if let Some(output) = op.output() {
            live_at_target.remove(output);
        }
        live_at_target.extend(op.inputs().into_iter().cloned());
    }
    let mut candidates = HashMap::<Varnode, Varnode>::new();
    let mut preserved = Vec::<(Varnode, Varnode, usize)>::new();
    let mut preserved_index = HashMap::<Varnode, usize>::new();

    let emit_preserved = |ops: &mut Vec<R2ILOp>,
                          metadata: &mut BTreeMap<usize, OpMetadata>,
                          preserved: &[(Varnode, Varnode, usize)]| {
        for (dst, candidate, old_index) in preserved {
            push_with_old_metadata(
                ops,
                metadata,
                R2ILOp::Select {
                    dst: dst.clone(),
                    cond: cond.clone(),
                    if_true: dst.clone(),
                    if_false: candidate.clone(),
                },
                &old_metadata,
                *old_index,
            );
        }
    };

    for (old_index, mut op) in old_ops.into_iter().enumerate() {
        if old_index == branch_index {
            continue;
        }
        if old_index == target_index {
            emit_preserved(&mut ops, &mut metadata, &preserved);
        }
        if old_index > branch_index && old_index < target_index {
            for input in op.inputs_mut() {
                if let Some(candidate) = candidates.get(input) {
                    *input = candidate.clone();
                }
            }
            let Some(dst) = op.output().cloned() else {
                push_unimplemented(&mut ops, &mut metadata, &old_metadata, old_index);
                continue;
            };
            let Some(candidate) = allocator.allocate(dst.size) else {
                push_unimplemented(&mut ops, &mut metadata, &old_metadata, old_index);
                continue;
            };
            *op.output_mut()
                .expect("speculatable value operation has output") = candidate.clone();
            push_with_old_metadata(&mut ops, &mut metadata, op, &old_metadata, old_index);
            candidates.insert(dst.clone(), candidate.clone());
            if dst.space != SpaceId::Unique || live_at_target.contains(&dst) {
                if let Some(index) = preserved_index.get(&dst).copied() {
                    preserved[index] = (dst, candidate, old_index);
                } else {
                    preserved_index.insert(dst.clone(), preserved.len());
                    preserved.push((dst, candidate, old_index));
                }
            }
            continue;
        }
        push_with_old_metadata(&mut ops, &mut metadata, op, &old_metadata, old_index);
    }
    // No old operation visits `target_index` when the local label is one past
    // the instruction. Emit the externally surviving definitions here.
    if target_index == old_len {
        emit_preserved(&mut ops, &mut metadata, &preserved);
    }
    block.ops = ops;
    block.op_metadata = metadata;
}

fn push_unimplemented(
    ops: &mut Vec<R2ILOp>,
    metadata: &mut BTreeMap<usize, OpMetadata>,
    old_metadata: &BTreeMap<usize, OpMetadata>,
    old_index: usize,
) {
    push_with_old_metadata(
        ops,
        metadata,
        R2ILOp::Unimplemented,
        old_metadata,
        old_index,
    );
}

fn push_with_old_metadata(
    ops: &mut Vec<R2ILOp>,
    metadata: &mut BTreeMap<usize, OpMetadata>,
    op: R2ILOp,
    old_metadata: &BTreeMap<usize, OpMetadata>,
    old_index: usize,
) {
    let new_index = ops.len();
    ops.push(op);
    if let Some(meta) = old_metadata.get(&old_index) {
        metadata.insert(new_index, meta.clone());
    }
}

struct InstructionTempAllocator {
    next: u64,
}

impl InstructionTempAllocator {
    fn for_ops(ops: &[R2ILOp]) -> Self {
        let next = ops
            .iter()
            .flat_map(|op| op.inputs().into_iter().chain(op.output()))
            .filter(|varnode| varnode.space == SpaceId::Unique)
            .filter_map(|varnode| varnode.offset.checked_add(u64::from(varnode.size.max(1))))
            .max()
            .unwrap_or(0)
            .saturating_add(7)
            & !7;
        Self { next }
    }

    fn allocate(&mut self, size: u32) -> Option<Varnode> {
        let width = u64::from(size.max(1));
        let offset = self.next;
        self.next = self.next.checked_add(width)?.checked_add(7)? & !7;
        Some(Varnode::unique(offset, size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_relative_branch_becomes_value_select() {
        let result = Varnode::unique(0x100, 4);
        let divisor = Varnode::register(0x20, 4);
        let dividend = Varnode::register(0x24, 4);
        let cond = Varnode::unique(0x108, 1);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::Copy {
                dst: result.clone(),
                src: Varnode::constant(0, 4),
            },
            R2ILOp::IntEqual {
                dst: cond.clone(),
                a: divisor.clone(),
                b: Varnode::constant(0, 4),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(2, 8),
                cond: cond.clone(),
            },
            R2ILOp::IntSDiv {
                dst: result.clone(),
                a: dividend,
                b: divisor,
            },
            R2ILOp::Copy {
                dst: Varnode::register(0x28, 4),
                src: result.clone(),
            },
        ];

        normalize_instruction_local_control(&mut block);

        assert!(
            !block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::CBranch { .. }))
        );
        let select = block
            .ops
            .iter()
            .find_map(|op| match op {
                R2ILOp::Select {
                    dst,
                    cond,
                    if_true,
                    if_false,
                } => Some((dst, cond, if_true, if_false)),
                _ => None,
            })
            .expect("value select");
        assert_eq!(select.0, &result);
        assert_eq!(select.1, &cond);
        assert_eq!(select.2, &result);
        assert_eq!(select.3.space, SpaceId::Unique);
        assert_ne!(select.3, &result);
    }

    #[test]
    fn conditional_relative_branch_over_effect_refuses() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::CBranch {
                target: Varnode::constant(2, 8),
                cond: Varnode::register(0x20, 1),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::register(0x28, 8),
                val: Varnode::register(0x30, 4),
            },
        ];

        normalize_instruction_local_control(&mut block);

        assert!(matches!(block.ops.first(), Some(R2ILOp::Unimplemented)));
    }

    #[test]
    fn conditional_ram_branch_over_values_becomes_selects() {
        let flags = Varnode::register(0x20, 1);
        let candidate = Varnode::unique(0x100, 1);
        let cond = Varnode::unique(0x108, 1);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::CBranch {
                target: Varnode::ram(0x1004, 8),
                cond: cond.clone(),
            },
            R2ILOp::Copy {
                dst: candidate.clone(),
                src: Varnode::constant(1, 1),
            },
            R2ILOp::Copy {
                dst: flags.clone(),
                src: candidate.clone(),
            },
        ];

        normalize_instruction_local_control(&mut block);

        assert!(
            !block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::CBranch { .. }))
        );
        assert!(block.ops.iter().any(|op| matches!(
            op,
            R2ILOp::Select {
                dst,
                cond: select_cond,
                if_true,
                if_false,
            } if dst == &flags
                && select_cond == &cond
                && if_true == &flags
                && if_false.space == SpaceId::Unique
        )));
        assert!(
            block
                .ops
                .iter()
                .flat_map(R2ILOp::inputs)
                .all(|input| input != &candidate),
            "the undefined guarded temporary must be replaced by its candidate"
        );
    }

    #[test]
    fn terminal_ram_branch_to_following_instruction_stays_control_flow() {
        let branch = R2ILOp::CBranch {
            target: Varnode::ram(0x1004, 8),
            cond: Varnode::register(0x20, 1),
        };
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![branch.clone()];

        normalize_instruction_local_control(&mut block);

        assert_eq!(block.ops, vec![branch]);
    }
}
