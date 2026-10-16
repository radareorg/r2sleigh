//! Normalization for P-code-relative control flow inside one instruction.
//!
//! Ghidra usually encodes instruction-local branches with a constant-space
//! target whose signed offset is relative to the branch operation's index.
//! Some specifications instead resolve a skip to the RAM address of the next
//! instruction. Those edges are not machine CFG edges. A local loop is replaced
//! by what it computes where that is proven ([`unroll`] for loops every
//! decision of which is a constant, [`scan`] for bit scans). Forward branches
//! become value selects and guarded accesses, innermost first ([`skips`]);
//! one that cannot turns itself and all it guards into `Unimplemented`, so
//! downstream consumers refuse instead of inventing a CFG.

mod atomic;
mod scan;
mod skips;
mod unroll;

use std::collections::BTreeMap;

use r2il::{
    BlockStop, BlockTransfer, BlockTransferKind, MemoryOrdering, R2ILBlock, R2ILOp, SpaceId,
    Varnode,
};

pub(crate) fn normalize_instruction_local_control(
    block: &mut R2ILBlock,
    names: &dyn Fn(u32) -> Option<String>,
    register_big_endian: bool,
) {
    // A repeated string instruction's p-code is a loop, and the loop is how the
    // specification writes a block operation. Recognising it first is what
    // keeps the guard below from turning the whole instruction into
    // `Unimplemented`, which is all it could otherwise do with a backward edge.
    // A scan or a compare leaves one local skip behind, over its last pass, for the loop below.
    if let Some(rewritten) = block_transfer_from_repeat(block) {
        block.ops = rewritten;
        block.op_metadata = BTreeMap::new();
    }
    // A conditional store is the other idiom the guard below cannot keep: it
    // skips over a store, which is not a value operation and cannot be
    // speculated past. The whole sequence is one linked load or one
    // conditional store, and the vocabulary already has both.
    let bracket = rewrite_atomic_idioms(block, names);
    // Any other loop is either decided by constants, and runs as many passes
    // as they say, or is a bit scan, and computes a count. A loop that is
    // neither is left for the guard below.
    resolve_local_loops(block);
    skips::normalize(block);
    // A bracketed access is typed once its compare-and-exchange's skip is a guarded store.
    if let Some(bracket) = bracket {
        atomic::type_bracket(block, bracket, names, register_big_endian);
    }
}

/// Replace an instruction's local loop with what it computes, where that is
/// proven: unrolled where every decision is a constant, a count where the loop
/// is a bit scan.
fn resolve_local_loops(block: &mut R2ILBlock) {
    let loops = block
        .ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| local_branch(block, index, op))
        .any(|(index, _, target)| target <= index);
    if !loops {
        return;
    }
    if let Some((ops, metadata)) = unroll::unrolled(block) {
        block.ops = ops;
        block.op_metadata = metadata;
    } else if let Some(ops) = scan::closed_form(block) {
        block.ops = ops;
        block.op_metadata = BTreeMap::new();
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

/// A repeated string instruction's loop: a zero-count guard, a decrement, and one or two equal pointer steps.
struct Repeat<'a> {
    ops: &'a [R2ILOp],
    counter: &'a Varnode,
    destination: PointerStep,
    source: Option<PointerStep>,
    /// Where the element work begins, after the steps.
    body: usize,
}

impl Repeat<'_> {
    fn steps(&self) -> impl Iterator<Item = &PointerStep> {
        [Some(&self.destination), self.source.as_ref()]
            .into_iter()
            .flatten()
    }
}

/// The guard, the decrement and the steps every repeated string instruction opens with.
fn repeat_prologue(block: &R2ILBlock) -> Option<Repeat<'_>> {
    let ops = block.ops.as_slice();
    let [
        R2ILOp::IntEqual {
            dst: guard,
            a: counter,
            b: zero,
        },
        R2ILOp::CBranch { target: exit, cond },
        R2ILOp::IntSub {
            dst: decremented,
            a: decrement_base,
            b: one,
        },
    ] = ops.get(0..3)?
    else {
        return None;
    };
    let fallthrough = block.addr.checked_add(u64::from(block.size))?;
    if constant_value(zero)? != 0
        || !same(guard, cond)
        || exit.space != SpaceId::Ram
        || exit.offset != fallthrough
        || !same(counter, decremented)
        || !same(counter, decrement_base)
        || constant_value(one)? != 1
    {
        return None;
    }
    let (destination, mut body) = pointer_step(ops, 3)?;
    let source = match pointer_step(ops, body) {
        Some((step, next)) => {
            body = next;
            Some(step)
        }
        None => None,
    };
    let repeat = Repeat {
        ops,
        counter,
        destination,
        source,
        body,
    };
    // The extent is counted in the counter's width, so every pointer must share it.
    if repeat.steps().any(|step| {
        step.pointer.size != counter.size
            || step.width != repeat.destination.width
            || !same(&step.direction, &repeat.destination.direction)
    }) {
        return None;
    }
    Some(repeat)
}

/// The block operation a repeated string instruction performs, with its register and flag updates beside it.
fn block_transfer_from_repeat(block: &R2ILBlock) -> Option<Vec<R2ILOp>> {
    let repeat = repeat_prologue(block)?;
    let last = repeat.ops.len().checked_sub(1)?;
    match &repeat.ops[last] {
        R2ILOp::Branch { target }
            if target.space == SpaceId::Ram && target.offset == block.addr =>
        {
            transfer_from_repeat(&repeat, last)
        }
        R2ILOp::CBranch { target, cond }
            if target.space == SpaceId::Ram && target.offset == block.addr =>
        {
            comparison_from_repeat(&repeat, last, cond)
        }
        _ => None,
    }
}

/// A move or a fill writes every element, leaving the counter zero and each pointer past the extent.
fn transfer_from_repeat(repeat: &Repeat<'_>, last: usize) -> Option<Vec<R2ILOp>> {
    let (destination, source) = (&repeat.destination, repeat.source.as_ref());
    // A move loads through the saved source and stores through the saved destination; a fill stores a value.
    let (kind, transferred) = match repeat.ops.get(repeat.body..last)? {
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
            let source = source?;
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
    let counter = repeat.counter;
    let mut allocator = InstructionTempAllocator::for_ops(repeat.ops);
    let mut rewritten = vec![R2ILOp::BlockTransfer(Box::new(BlockTransfer {
        space: SpaceId::Ram,
        kind,
        destination: destination.pointer.clone(),
        source: transferred,
        count: counter.clone(),
        direction: destination.direction.clone(),
        element_size: u32::try_from(destination.width).ok()?,
        answer: None,
    }))];
    advance_pointers(repeat, counter, &mut allocator, &mut rewritten)?;
    rewritten.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, counter.size),
    });
    Some(rewritten)
}

/// Advance every pointer by `reached` elements in the walk's direction.
fn advance_pointers(
    repeat: &Repeat<'_>,
    reached: &Varnode,
    allocator: &mut InstructionTempAllocator,
    rewritten: &mut Vec<R2ILOp>,
) -> Option<()> {
    let size = repeat.counter.size;
    let extent = allocator.allocate(size)?;
    let widened_direction = allocator.allocate(size)?;
    let signed_extent = allocator.allocate(size)?;
    let twice_extent = allocator.allocate(size)?;
    rewritten.push(R2ILOp::IntMult {
        dst: extent.clone(),
        a: reached.clone(),
        b: Varnode::constant(repeat.destination.width, size),
    });
    rewritten.push(R2ILOp::IntZExt {
        dst: widened_direction.clone(),
        src: repeat.destination.direction.clone(),
    });
    rewritten.push(R2ILOp::IntMult {
        dst: twice_extent.clone(),
        a: extent.clone(),
        b: widened_direction,
    });
    rewritten.push(R2ILOp::IntMult {
        dst: twice_extent.clone(),
        a: twice_extent.clone(),
        b: Varnode::constant(2, size),
    });
    rewritten.push(R2ILOp::IntSub {
        dst: signed_extent.clone(),
        a: extent,
        b: twice_extent,
    });
    for step in repeat.steps() {
        rewritten.push(R2ILOp::IntAdd {
            dst: step.pointer.clone(),
            a: step.pointer.clone(),
            b: signed_extent.clone(),
        });
    }
    Some(())
}

/// Where one side of the loop's comparison comes from.
enum Compared {
    /// The element read through the saved destination pointer.
    Destination,
    /// The element read through the saved source pointer.
    Source,
    /// A value nothing in the instruction writes, the same on every pass.
    Value(Varnode),
}

fn overlaps(a: &Varnode, b: &Varnode) -> bool {
    a.space == b.space
        && a.offset < b.offset.saturating_add(u64::from(b.size))
        && b.offset < a.offset.saturating_add(u64::from(a.size))
}

/// The last operation before `before` that writes any part of `varnode`.
fn last_writer(ops: &[R2ILOp], before: usize, varnode: &Varnode) -> Option<usize> {
    (0..before).rev().find(|index| {
        ops[*index]
            .output()
            .is_some_and(|output| overlaps(output, varnode))
    })
}

/// What one operand of the comparison is, traced through the copies that stage it.
fn compared(
    repeat: &Repeat<'_>,
    body: &[R2ILOp],
    before: usize,
    operand: &Varnode,
) -> Option<Compared> {
    let (mut operand, mut before) = (operand.clone(), before);
    loop {
        let Some(at) = last_writer(body, before, &operand) else {
            let written = repeat.ops[..repeat.body]
                .iter()
                .filter_map(R2ILOp::output)
                .any(|output| overlaps(output, &operand));
            return (!written && operand.space != SpaceId::Const)
                .then_some(Compared::Value(operand));
        };
        match &body[at] {
            R2ILOp::Copy { dst, src } if same(dst, &operand) => {
                (operand, before) = (src.clone(), at)
            }
            R2ILOp::Load { dst, addr, .. } if same(dst, &operand) => {
                if same(addr, &repeat.destination.saved) {
                    return Some(Compared::Destination);
                }
                let source = repeat.source.as_ref()?;
                return same(addr, &source.saved).then_some(Compared::Source);
            }
            _ => return None,
        }
    }
}

/// A scan or a compare, whose test `x - y == 0` is exactly `x == y`; the flags are its last pass over the answered pair.
fn comparison_from_repeat(
    repeat: &Repeat<'_>,
    last: usize,
    continues: &Varnode,
) -> Option<Vec<R2ILOp>> {
    let ops = repeat.ops;
    // The branch back is taken while the pair is equal, or while it is not.
    let (tail, equal, runs_while_equal) = match &ops[last - 1] {
        R2ILOp::BoolNot { dst, src } if same(dst, continues) => (last - 1, src.clone(), false),
        _ => (last, continues.clone(), true),
    };
    let body = ops.get(repeat.body..tail)?;
    if !body_is_one_pass(repeat, body) {
        return None;
    }
    let test_at = last_writer(body, body.len(), &equal)?;
    let R2ILOp::IntEqual { dst, a, b } = &body[test_at] else {
        return None;
    };
    let difference = match (constant_value(a), constant_value(b)) {
        (_, Some(0)) => a,
        (Some(0), _) => b,
        _ => return None,
    };
    let difference_at = last_writer(body, test_at, difference)?;
    let R2ILOp::IntSub {
        dst: subtracted,
        a: minuend,
        b: subtrahend,
    } = &body[difference_at]
    else {
        return None;
    };
    let width = repeat.destination.width;
    if !same(dst, &equal) || !same(subtracted, difference) || u64::from(difference.size) != width {
        return None;
    }
    let stop = match runs_while_equal {
        true => BlockStop::Unequal,
        false => BlockStop::Equal,
    };
    let pair = (
        compared(repeat, body, difference_at, minuend)?,
        compared(repeat, body, difference_at, subtrahend)?,
    );
    let (kind, operand) = match (pair, repeat.source.as_ref()) {
        ((Compared::Value(value), Compared::Destination), None)
        | ((Compared::Destination, Compared::Value(value)), None)
            if u64::from(value.size) == width =>
        {
            (BlockTransferKind::Scan(stop), value)
        }
        ((Compared::Source, Compared::Destination), Some(source))
        | ((Compared::Destination, Compared::Source), Some(source)) => {
            (BlockTransferKind::Compare(stop), source.pointer.clone())
        }
        _ => return None,
    };

    let counter = repeat.counter;
    let mut allocator = InstructionTempAllocator::for_ops(ops);
    // The answer is how far the walk reached, then the element or pair it compared last.
    let parts = u32::try_from(repeat.steps().count()).ok()?;
    let element = u32::try_from(width).ok()?;
    let answer = allocator.allocate(counter.size.checked_add(parts.checked_mul(element)?)?)?;
    let mut rewritten = vec![R2ILOp::BlockTransfer(Box::new(BlockTransfer {
        space: SpaceId::Ram,
        kind,
        destination: repeat.destination.pointer.clone(),
        source: operand,
        count: counter.clone(),
        direction: repeat.destination.direction.clone(),
        element_size: element,
        answer: Some(answer.clone()),
    }))];
    let consumed = allocator.allocate(counter.size)?;
    rewritten.push(R2ILOp::Subpiece {
        dst: consumed.clone(),
        src: answer.clone(),
        offset: 0,
    });
    // The destination's element first, then the source's, each where its saved pointer read.
    let mut last = Vec::<(Varnode, Varnode)>::new();
    for (index, step) in (0u32..).zip(repeat.steps()) {
        let part = allocator.allocate(element)?;
        rewritten.push(R2ILOp::Subpiece {
            dst: part.clone(),
            src: answer.clone(),
            offset: counter.size + index * element,
        });
        last.push((step.saved.clone(), part));
    }
    advance_pointers(repeat, &consumed, &mut allocator, &mut rewritten)?;
    rewritten.push(R2ILOp::IntSub {
        dst: counter.clone(),
        a: counter.clone(),
        b: consumed.clone(),
    });
    // The last pass reads what the walk compared last, which the answer already holds.
    let mut last_pass = Vec::with_capacity(body.len());
    for op in body {
        let R2ILOp::Load { dst, addr, .. } = op else {
            last_pass.push(op.clone());
            continue;
        };
        let (_, part) = last.iter().find(|(saved, _)| same(saved, addr))?;
        last_pass.push(R2ILOp::Copy {
            dst: dst.clone(),
            src: part.clone(),
        });
    }
    // A zero count reaches no element, and the skip is the guard the last pass runs under.
    let skipped = allocator.allocate(1)?;
    rewritten.push(R2ILOp::IntEqual {
        dst: skipped.clone(),
        a: consumed,
        b: Varnode::constant(0, counter.size),
    });
    let distance = u64::try_from(last_pass.len() + 1).ok()?;
    rewritten.push(R2ILOp::CBranch {
        target: Varnode::constant(distance, 8),
        cond: skipped,
    });
    rewritten.extend(last_pass);
    Some(rewritten)
}

/// Whether every pass computes alike, so the last pass run once after the block is the machine's last pass.
fn body_is_one_pass(repeat: &Repeat<'_>, body: &[R2ILOp]) -> bool {
    let reaches_last_pass = |input: &Varnode| {
        same(input, repeat.counter) || repeat.steps().any(|step| same(input, &step.pointer))
    };
    let prologue = &repeat.ops[..repeat.body];
    let mut this_pass = Vec::<&Varnode>::new();
    for op in body {
        match op {
            // A read through a saved pointer is the element the walk compares.
            R2ILOp::Load {
                dst,
                space: SpaceId::Ram,
                addr,
            } => {
                if !repeat.steps().any(|step| same(addr, &step.saved))
                    || u64::from(dst.size) != repeat.destination.width
                {
                    return false;
                }
                this_pass.push(dst);
                continue;
            }
            op if !op.is_speculatable_value() => return false,
            _ => {}
        }
        for input in op.inputs() {
            if input.space == SpaceId::Const || this_pass.iter().any(|output| same(output, input)) {
                continue;
            }
            // Only the counter and the pointers carry into the last pass.
            let written_before = body
                .iter()
                .chain(prologue)
                .filter_map(R2ILOp::output)
                .any(|output| overlaps(output, input));
            if written_before && !reaches_last_pass(input) {
                return false;
            }
        }
        if let Some(output) = op.output() {
            this_pass.push(output);
        }
    }
    true
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

/// The width of the control value a transfer reads, where the operation is one.
fn transfer_target_size(op: &R2ILOp) -> Option<u32> {
    match op {
        R2ILOp::Return { target }
        | R2ILOp::BranchInd { target }
        | R2ILOp::Branch { target }
        | R2ILOp::Call { target }
        | R2ILOp::CallInd { target } => Some(target.size),
        _ => None,
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
    branch_index.checked_add_signed(isize::try_from(target.signed_label()?).ok()?)
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

/// The exclusive-access idioms as `LoadLinked` and `StoreConditional`, and the
/// atomic bracket the walk meets, which is typed after `skips`.
fn rewrite_atomic_idioms(
    block: &mut R2ILBlock,
    names: &dyn Fn(u32) -> Option<String>,
) -> Option<atomic::Bracket> {
    fn user_op(
        block: &R2ILBlock,
        index: usize,
        names: &dyn Fn(u32) -> Option<String>,
    ) -> Option<(String, Option<Varnode>, Vec<Varnode>)> {
        let R2ILOp::CallOther {
            userop,
            output,
            inputs,
        } = block.ops.get(index)?
        else {
            return None;
        };
        Some((names(*userop)?, output.clone(), inputs.clone()))
    }
    let mut rewrote = false;
    let mut bracket = None;
    let mut at = 0;
    while at < block.ops.len() {
        let Some((name, output, inputs)) = user_op(block, at, names) else {
            at += 1;
            continue;
        };
        bracket = bracket.or(atomic::Bracket::opening(&name));
        let rewritten = match name.as_str() {
            "ExclusiveAccess" | "SetExclusiveMonitors" => linked_load(block, at, &inputs),
            "hasExclusiveAccess" => conditional_store(block, at, output.as_ref(), &inputs),
            "ExclusiveMonitorPass" => monitored_store(block, at, output.as_ref(), &inputs, names),
            _ => None,
        };
        match rewritten {
            Some((span, ops)) => {
                block.ops.splice(at..at + span, ops);
                block.op_metadata = BTreeMap::new();
                rewrote = true;
            }
            None => at += 1,
        }
    }
    if rewrote {
        absorb_ordering(block);
    }
    bracket
}

/// An exclusive's acquire fence after its linked load, or release fence before its conditional
/// store, is that access's ordering; without one it is Relaxed (`vendor/README.md`).
fn absorb_ordering(block: &mut R2ILBlock) {
    let position = |found: fn(&R2ILOp) -> bool| block.ops.iter().position(found);
    let linked = position(|op| matches!(op, R2ILOp::LoadLinked { .. }));
    let conditional = position(|op| matches!(op, R2ILOp::StoreConditional { .. }));
    let fence = |range: std::ops::Range<usize>, wanted: MemoryOrdering| {
        (range.start..range.end)
            .find(|&at| matches!(block.ops[at], R2ILOp::Fence { ordering } if ordering == wanted))
    };
    // A pair's second load has no ordering of its own, so the fence after it stays.
    let acquire = linked
        .filter(|&at| {
            !block.ops[at..]
                .iter()
                .any(|op| matches!(op, R2ILOp::Load { .. }))
        })
        .and_then(|at| Some((at, fence(at..block.ops.len(), MemoryOrdering::Acquire)?)));
    let release = conditional.and_then(|at| Some((at, fence(0..at, MemoryOrdering::Release)?)));
    let mut absorbed = Vec::with_capacity(2);
    if let Some((at, fence)) = acquire
        && let R2ILOp::LoadLinked { ordering, .. } = &mut block.ops[at]
    {
        *ordering = MemoryOrdering::Acquire;
        absorbed.push(fence);
    }
    if let Some((at, fence)) = release {
        let ok = block.ops[at].output().cloned();
        for op in &mut block.ops[at..] {
            match op {
                R2ILOp::StoreConditional { ordering, .. } => *ordering = MemoryOrdering::Release,
                R2ILOp::StoreGuarded {
                    guard, ordering, ..
                } if ok.as_ref().is_some_and(|ok| same(ok, guard)) => {
                    *ordering = MemoryOrdering::Release;
                }
                _ => {}
            }
        }
        absorbed.push(fence);
    }
    if absorbed.is_empty() {
        return;
    }
    absorbed.sort_unstable();
    for fence in absorbed.into_iter().rev() {
        block.ops.remove(fence);
    }
    block.op_metadata = BTreeMap::new();
}

/// `mark(addr[, bytes]); dst = LOAD [ram] addr` is `dst = LoadLinked(addr)`, Relaxed until
/// [`absorb_ordering`] reads its fence; a pair's second load stays a plain one.
fn linked_load(block: &R2ILBlock, at: usize, inputs: &[Varnode]) -> Option<(usize, Vec<R2ILOp>)> {
    let ([addr] | [addr, _]) = inputs else {
        return None;
    };
    let R2ILOp::Load {
        dst,
        space,
        addr: loaded,
    } = block.ops.get(at + 1)?
    else {
        return None;
    };
    same(loaded, addr).then(|| {
        (
            2,
            vec![R2ILOp::LoadLinked {
                dst: dst.clone(),
                space: *space,
                addr: addr.clone(),
                ordering: MemoryOrdering::Relaxed,
            }],
        )
    })
}

/// The `strex` sequence, which writes nought on success:
///
/// ```text
///   ok  = hasExclusiveAccess(addr)
///   rd  = 1
///   not = !ok
///   if (not) goto done
///   rd  = 0
///   STORE [ram] addr = val
/// done:
/// ```
fn conditional_store(
    block: &R2ILBlock,
    at: usize,
    ok: Option<&Varnode>,
    inputs: &[Varnode],
) -> Option<(usize, Vec<R2ILOp>)> {
    let [addr] = inputs else {
        return None;
    };
    let ok = ok?;
    let R2ILOp::Copy {
        dst: failed,
        src: one,
    } = block.ops.get(at + 1)?
    else {
        return None;
    };
    let R2ILOp::BoolNot {
        dst: not,
        src: tested,
    } = block.ops.get(at + 2)?
    else {
        return None;
    };
    let R2ILOp::CBranch { cond, .. } = block.ops.get(at + 3)? else {
        return None;
    };
    let R2ILOp::Copy {
        dst: succeeded,
        src: zero,
    } = block.ops.get(at + 4)?
    else {
        return None;
    };
    let R2ILOp::Store {
        space,
        addr: stored,
        val,
    } = block.ops.get(at + 5)?
    else {
        return None;
    };
    if !(same(tested, ok)
        && same(cond, not)
        && same(failed, succeeded)
        && same(stored, addr)
        && constant_value(one) == Some(1)
        && constant_value(zero) == Some(0))
    {
        return None;
    }
    Some((
        6,
        vec![
            R2ILOp::StoreConditional {
                result: Some(ok.clone()),
                space: *space,
                addr: addr.clone(),
                val: val.clone(),
                ordering: MemoryOrdering::Relaxed,
            },
            R2ILOp::BoolNot {
                dst: not.clone(),
                src: ok.clone(),
            },
            // The machine writes nought where the store took, so the register
            // the instruction names is the negation of the success it reports.
            R2ILOp::IntZExt {
                dst: failed.clone(),
                src: not.clone(),
            },
        ],
    ))
}

/// AArch64's `ok = ExclusiveMonitorPass(addr); if (!ok) skip { stores }; status = ...Status()`
/// is `ok = StoreConditional`, a pair's +8 store under `ok`, `status = !ok` (Arm ARM C6.2.350).
fn monitored_store(
    block: &R2ILBlock,
    at: usize,
    ok: Option<&Varnode>,
    inputs: &[Varnode],
    names: &dyn Fn(u32) -> Option<String>,
) -> Option<(usize, Vec<R2ILOp>)> {
    let ([addr] | [addr, _]) = inputs else {
        return None;
    };
    let ok = ok?;
    let R2ILOp::BoolNot {
        dst: not,
        src: tested,
    } = block.ops.get(at + 1)?
    else {
        return None;
    };
    let skip = at + 2;
    let (_, LocalBranch::Conditional { cond, .. }, done) =
        local_branch(block, skip, block.ops.get(skip)?)?
    else {
        return None;
    };
    let reported = done.checked_sub(1).filter(|reported| *reported > skip)?;
    let R2ILOp::CallOther {
        userop,
        output: Some(status),
        inputs: none,
    } = block.ops.get(reported)?
    else {
        return None;
    };
    if !(same(tested, ok)
        && same(&cond, not)
        && none.is_empty()
        && status.size == not.size
        && names(*userop).as_deref() == Some("ExclusiveMonitorsStatus"))
    {
        return None;
    }
    let guarded = &block.ops[skip + 1..reported];
    // The temporaries the skip guarded now run either way, so nothing after it may read one.
    let temporaries: Vec<&Varnode> = guarded.iter().filter_map(R2ILOp::output).collect();
    let read_after = block.ops[done..]
        .iter()
        .flat_map(R2ILOp::inputs)
        .any(|input| temporaries.iter().any(|written| same(written, input)));
    if read_after {
        return None;
    }
    let mut ops = stores_under(guarded, addr, ok)?;
    ops.push(R2ILOp::BoolNot {
        dst: not.clone(),
        src: ok.clone(),
    });
    ops.push(R2ILOp::Copy {
        dst: status.clone(),
        src: not.clone(),
    });
    Some((done - at, ops))
}

/// The skipped run with its first store, which must be at `addr`, conditional and answering `ok`,
/// and any later one guarded by `ok`; `None` where anything else but a temporary is under it.
fn stores_under(guarded: &[R2ILOp], addr: &Varnode, ok: &Varnode) -> Option<Vec<R2ILOp>> {
    let mut ops = Vec::with_capacity(guarded.len() + 2);
    let mut linked = false;
    for op in guarded {
        match op {
            R2ILOp::Store {
                space,
                addr: stored,
                val,
            } if !linked => {
                if !same(stored, addr) {
                    return None;
                }
                linked = true;
                ops.push(R2ILOp::StoreConditional {
                    result: Some(ok.clone()),
                    space: *space,
                    addr: addr.clone(),
                    val: val.clone(),
                    ordering: MemoryOrdering::Relaxed,
                });
            }
            R2ILOp::Store { space, addr, val } => ops.push(R2ILOp::StoreGuarded {
                space: *space,
                addr: addr.clone(),
                val: val.clone(),
                guard: ok.clone(),
                ordering: MemoryOrdering::Relaxed,
            }),
            op if op.is_speculatable_value()
                && op.output().is_some_and(|dst| dst.space == SpaceId::Unique) =>
            {
                ops.push(op.clone());
            }
            _ => return None,
        }
    }
    linked.then_some(ops)
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
            R2ILOp::IntAdd {
                dst: result.clone(),
                a: dividend,
                b: divisor,
            },
            R2ILOp::Copy {
                dst: Varnode::register(0x28, 4),
                src: result.clone(),
            },
        ];

        normalize_instruction_local_control(&mut block, &|_| None, false);

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
    fn conditional_relative_branch_over_a_load_guards_it_and_selects_the_value() {
        // The read carries the condition, and what the destination holds when
        // the condition does not hold is what it held before -- which is the
        // selection the skip rewrite already emits, over an ordinary copy.
        let cond = Varnode::register(0x20, 1);
        let dst = Varnode::register(0x30, 4);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::CBranch {
                target: Varnode::constant(2, 8),
                cond: cond.clone(),
            },
            R2ILOp::Load {
                dst: dst.clone(),
                space: SpaceId::Ram,
                addr: Varnode::register(0x28, 4),
            },
        ];

        normalize_instruction_local_control(&mut block, &|_| None, false);

        let R2ILOp::BoolNot { dst: guard, src } = block.ops.first().expect("the guard") else {
            panic!("{:?}", block.ops);
        };
        assert_eq!(src, &cond);
        let read = block
            .ops
            .iter()
            .find_map(|op| match op {
                R2ILOp::LoadGuarded {
                    dst, guard: stated, ..
                } if stated == guard => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{:?}", block.ops));
        // The read goes to a temporary of its own, never to the register.
        assert_eq!(read.space, SpaceId::Unique);
        assert!(
            block.ops.iter().any(|op| matches!(
                op,
                R2ILOp::Select { dst: selected, cond: on, if_true, .. }
                    if selected == &dst && on == &cond && if_true == &dst
            )),
            "{:?}",
            block.ops
        );
        assert!(
            !block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::Unimplemented | R2ILOp::Load { .. })),
            "{:?}",
            block.ops
        );
    }

    #[test]
    fn conditional_relative_branch_over_a_store_guards_it() {
        // A store cannot be speculated, so the skip over one used to make the
        // whole instruction `Unimplemented`. It is not speculated now either:
        // it carries the branch's own condition, negated, which is what a
        // predicated store is and what the vocabulary already spells.
        let cond = Varnode::register(0x20, 1);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::CBranch {
                target: Varnode::constant(2, 8),
                cond: cond.clone(),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::register(0x28, 8),
                val: Varnode::register(0x30, 4),
            },
        ];

        normalize_instruction_local_control(&mut block, &|_| None, false);

        let R2ILOp::BoolNot { dst: guard, src } = block.ops.first().expect("the guard") else {
            panic!("{:?}", block.ops);
        };
        assert_eq!(src, &cond);
        assert!(
            block.ops.iter().any(|op| matches!(
                op,
                R2ILOp::StoreGuarded { guard: stated, .. } if stated == guard
            )),
            "{:?}",
            block.ops
        );
        assert!(
            !block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::Unimplemented | R2ILOp::Store { .. })),
            "{:?}",
            block.ops
        );
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

        normalize_instruction_local_control(&mut block, &|_| None, false);

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

        normalize_instruction_local_control(&mut block, &|_| None, false);

        assert_eq!(block.ops, vec![branch]);
    }

    /// `i = 63; zf = x == 0; if (zf) goto done; loop: if ((x >> i) != 0)
    /// goto done; i = i - 1; goto loop; done: rax = i` -- BSR's shape, with
    /// the walk's start and step given.
    fn descending_scan(start: u64, step: u64) -> R2ILBlock {
        let (index, found, shifted) = (
            Varnode::unique(0x100, 8),
            Varnode::unique(0x110, 1),
            Varnode::unique(0x118, 8),
        );
        let (source, zero_flag, destination) = (
            Varnode::register(0x8, 8),
            Varnode::register(0x206, 1),
            Varnode::register(0x0, 8),
        );
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::Copy {
                dst: index.clone(),
                src: Varnode::constant(start, 8),
            },
            R2ILOp::IntEqual {
                dst: zero_flag.clone(),
                a: source.clone(),
                b: Varnode::constant(0, 8),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(6, 4),
                cond: zero_flag,
            },
            R2ILOp::IntRight {
                dst: shifted.clone(),
                a: source,
                b: index.clone(),
            },
            R2ILOp::IntNotEqual {
                dst: found.clone(),
                a: shifted,
                b: Varnode::constant(0, 8),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(3, 4),
                cond: found,
            },
            R2ILOp::IntSub {
                dst: index.clone(),
                a: index.clone(),
                b: Varnode::constant(step, 8),
            },
            R2ILOp::Branch {
                target: Varnode::constant(u64::from((-4i32) as u32), 4),
            },
            R2ILOp::Copy {
                dst: destination,
                src: index,
            },
        ];
        block
    }

    #[test]
    fn a_descending_scan_from_the_top_bit_becomes_its_count() {
        let mut block = descending_scan(63, 1);

        normalize_instruction_local_control(&mut block, &|_| None, false);

        assert!(
            block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::Lzcount { .. })),
            "{:?}",
            block.ops
        );
        assert!(
            !block.ops.iter().any(|op| matches!(
                op,
                R2ILOp::Unimplemented | R2ILOp::Branch { .. } | R2ILOp::CBranch { .. }
            )),
            "{:?}",
            block.ops
        );
    }

    /// A walk that could run past the register, or that skips positions, is
    /// no count this module states, and stays the refusal it was rather than
    /// becoming one.
    #[test]
    fn a_scan_with_another_start_or_step_stays_refused() {
        for (start, step) in [(62, 1), (64, 1), (63, 2)] {
            let mut block = descending_scan(start, step);

            normalize_instruction_local_control(&mut block, &|_| None, false);

            assert!(
                block
                    .ops
                    .iter()
                    .any(|op| matches!(op, R2ILOp::Unimplemented)),
                "start {start}, step {step}: {:?}",
                block.ops
            );
            assert!(
                !block
                    .ops
                    .iter()
                    .any(|op| matches!(op, R2ILOp::Lzcount { .. } | R2ILOp::PopCount { .. })),
                "start {start}, step {step}: {:?}",
                block.ops
            );
        }
    }

    /// `i = 0; loop: i = i + 1; if (i != r) goto loop` counts to a register:
    /// the decision is data, so the loop is not unrolled to any number of
    /// passes, and stays refused.
    #[test]
    fn a_loop_decided_by_data_stays_refused() {
        let (index, again) = (Varnode::unique(0x100, 8), Varnode::unique(0x110, 1));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::Copy {
                dst: index.clone(),
                src: Varnode::constant(0, 8),
            },
            R2ILOp::IntAdd {
                dst: index.clone(),
                a: index.clone(),
                b: Varnode::constant(1, 8),
            },
            R2ILOp::IntNotEqual {
                dst: again.clone(),
                a: index.clone(),
                b: Varnode::register(0x8, 8),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(u64::from((-2i32) as u32), 4),
                cond: again,
            },
            R2ILOp::Copy {
                dst: Varnode::register(0x0, 8),
                src: index,
            },
        ];

        normalize_instruction_local_control(&mut block, &|_| None, false);

        assert_eq!(block.ops.len(), 5, "{:?}", block.ops);
        assert!(
            matches!(block.ops[3], R2ILOp::Unimplemented),
            "{:?}",
            block.ops
        );
    }

    /// The same loop against a constant bound runs exactly as many passes as
    /// the bound says, and no local branch is left.
    #[test]
    fn a_loop_decided_by_constants_runs_its_passes() {
        let (index, again) = (Varnode::unique(0x100, 8), Varnode::unique(0x110, 1));
        let counter = Varnode::register(0x0, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            R2ILOp::Copy {
                dst: index.clone(),
                src: Varnode::constant(0, 8),
            },
            R2ILOp::IntAdd {
                dst: counter.clone(),
                a: counter.clone(),
                b: Varnode::constant(3, 8),
            },
            R2ILOp::IntAdd {
                dst: index.clone(),
                a: index.clone(),
                b: Varnode::constant(1, 8),
            },
            R2ILOp::IntNotEqual {
                dst: again.clone(),
                a: index,
                b: Varnode::constant(5, 8),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(u64::from((-3i32) as u32), 4),
                cond: again,
            },
        ];

        normalize_instruction_local_control(&mut block, &|_| None, false);

        let additions = block
            .ops
            .iter()
            .filter(|op| matches!(op, R2ILOp::IntAdd { dst, .. } if dst == &counter))
            .count();
        assert_eq!(additions, 5, "{:?}", block.ops);
        assert!(
            !block
                .ops
                .iter()
                .any(|op| matches!(op, R2ILOp::Unimplemented | R2ILOp::CBranch { .. })),
            "{:?}",
            block.ops
        );
    }
}
