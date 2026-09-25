//! Bit-scan loops, rewritten to the count each one computes.
//!
//! Sleigh writes x86 BSF, BSR and TZCNT (`ia.sinc`, `bmi1.sinc`) as p-code
//! loops that step across the source until they meet a set bit. Whether such
//! a loop exits depends on the data, so [`super::unroll`] cannot decide it, but
//! what it computes is a count of leading or trailing zeros, and the
//! vocabulary states both totally: `Lzcount`, and `PopCount(~x & (x - 1))`,
//! which is the number of trailing zeros of `x` and the width at zero. Each
//! shape below is matched operation by operation against what the
//! specification writes, never by the instruction's name, and the loop alone
//! is replaced: every other operation, the flag writes and the result write
//! among them, stays as the specification writes it.
//!
//! Two shapes are written, one per way the loop walks.
//!
//! **An index walk** (BSR, BSF). `i = c0`, a guard `if (x == 0) goto done`,
//! then a pass that tests one position and steps `i` by one:
//!
//! ```text
//!   descending (BSR): loop: if ((x >> i) != 0) goto done; i = i - 1; goto loop
//!   ascending  (BSF): loop: if (((x >> i) & 1) != 0) goto done; i = i + 1; goto loop
//! ```
//!
//! The guard excludes `x == 0`. Scanning down from `c0 = w - 1`, a non-zero `x`
//! has `x >> i != 0` exactly for `i <= msb(x)`, so the walk stops at
//! `i = msb(x) = (w - 1) - lzcount(x)`; scanning up from `c0 = 0` it stops at
//! the lowest set bit, `i = tzcount(x)`. Either way it stops within `w` passes
//! and `i` never leaves `[0, w)`. Any other start is not matched: the walk
//! could then run past the register, and nothing bounds it.
//!
//! Where `x == 0`, the specification writes the start `c0` (`w - 1` or `0`) to
//! the destination. No documentation gives that value: AMD states the
//! destination is left unchanged, Intel that it is undefined. Leaving it
//! unchanged is the one reading both allow, and the one code that preloads
//! the destination before the scan depends on, so the guard is made to skip
//! the destination write as well, and the whole register keeps what it held.
//! ZF, which the specification writes before the guard, keeps its definition.
//!
//! **A shifting walk** (TZCNT). `n = 0; t = x`, then
//!
//! ```text
//!   loop: if ((t & 1) != 0) goto done; n = n + 1; t = (t >> 1) | 1 << (w - 1); goto loop
//! ```
//!
//! After `k <= w` passes `t` is `x >> k` with its top `k` bits set, so its low
//! bit is bit `k` of `x` while `k < w`, and one at `k = w`: the walk stops at
//! `n = tzcount(x)`, and at `n = w` when `x == 0`, which is
//! `PopCount(~x & (x - 1))` at every `x`. The walk's own `t` is not read after
//! the loop, which is checked.
//!
//! Evidence: `disasm::local_control_tests` runs the specification's own loop
//! and the rewrite from the same states, over every 16-bit source and across
//! the bit positions of the 32- and 64-bit forms; the `kani_proofs` below state
//! the three counting lemmas at 64 bits for every source.
//!
//! Cost: one pass over the instruction's operations.

use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

use super::{
    InstructionTempAllocator, LocalBranch, constant_value, last_writer, local_branch, overlaps,
    same,
};

/// The loop the rewrite replaces: `header..back` is one pass, `back` the
/// branch to the next one, and `back + 1` where the one exit test lands.
struct ScanLoop {
    header: usize,
    back: usize,
    exit: usize,
}

impl ScanLoop {
    fn done(&self) -> usize {
        self.back + 1
    }
}

/// The instruction with its bit-scan loop replaced by the count it computes,
/// or `None` where the loop is not one of the two shapes the module states.
pub(super) fn closed_form(block: &R2ILBlock) -> Option<Vec<R2ILOp>> {
    let scan = scan_loop(block)?;
    index_walk(block, &scan).or_else(|| shifting_walk(block, &scan))
}

/// The one loop of the instruction: a single unconditional branch back, and a
/// single conditional exit inside the pass, landing just past the branch back.
fn scan_loop(block: &R2ILBlock) -> Option<ScanLoop> {
    let branches = block
        .ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| local_branch(block, index, op))
        .collect::<Vec<_>>();
    let mut backs = branches.iter().filter(|(index, _, target)| target <= index);
    let &(back, ref branch, header) = backs.next()?;
    if backs.next().is_some() || !matches!(branch, LocalBranch::Unconditional(_)) {
        return None;
    }
    let mut exits = branches
        .iter()
        .filter(|(index, _, _)| (header..back).contains(index));
    let &(exit, ref exit_branch, landing) = exits.next()?;
    if exits.next().is_some()
        || landing != back + 1
        || !matches!(exit_branch, LocalBranch::Conditional { .. })
    {
        return None;
    }
    Some(ScanLoop { header, back, exit })
}

/// Which way an index walk steps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// BSR: from `w - 1` down, testing `x >> i != 0`.
    Down,
    /// BSF: from `0` up, testing `(x >> i) & 1 != 0`.
    Up,
}

/// One pass of an index walk: the scanned value, the index and the direction.
struct IndexPass<'a> {
    source: &'a Varnode,
    index: &'a Varnode,
    direction: Direction,
}

/// Match the pass, from the test through the step, and what it scans.
fn index_pass<'a>(pass: &'a [R2ILOp], exit_cond: &Varnode) -> Option<IndexPass<'a>> {
    let (shift, found, tested, step) = match pass {
        [
            shift @ R2ILOp::IntRight { .. },
            R2ILOp::IntNotEqual { dst, a, b },
            _,
            step,
        ] => (shift, (dst, a, b), None, step),
        [
            shift @ R2ILOp::IntRight { .. },
            R2ILOp::IntAnd {
                dst: bit,
                a: masked,
                b: mask,
            },
            R2ILOp::IntNotEqual { dst, a, b },
            _,
            step,
        ] => (shift, (dst, a, b), Some((bit, masked, mask)), step),
        _ => return None,
    };
    let R2ILOp::IntRight {
        dst: shifted,
        a: source,
        b: index,
    } = shift
    else {
        return None;
    };
    let (found, compared, zero) = found;
    if !same(found, exit_cond) || constant_value(zero) != Some(0) {
        return None;
    }
    // The tested value is the shifted source itself (down), or its low bit (up).
    let direction = match tested {
        None if same(compared, shifted) => Direction::Down,
        Some((bit, masked, mask))
            if same(masked, shifted) && same(compared, bit) && constant_value(mask) == Some(1) =>
        {
            Direction::Up
        }
        _ => return None,
    };
    let stepped = match (step, direction) {
        (R2ILOp::IntSub { dst, a, b }, Direction::Down)
        | (R2ILOp::IntAdd { dst, a, b }, Direction::Up) => {
            same(dst, index) && same(a, index) && constant_value(b) == Some(1)
        }
        _ => false,
    };
    stepped.then_some(IndexPass {
        source,
        index,
        direction,
    })
}

/// BSR and BSF: the index walk behind a zero guard, rewritten to
/// `(w - 1) - Lzcount(x)` or `PopCount(~x & (x - 1))`, with the guard skipping
/// the destination write.
fn index_walk(block: &R2ILBlock, scan: &ScanLoop) -> Option<Vec<R2ILOp>> {
    let ops = &block.ops;
    let R2ILOp::CBranch {
        cond: exit_cond, ..
    } = &ops[scan.exit]
    else {
        return None;
    };
    // A memory source is loaded again at the top of each pass; that load
    // reads what the one before the guard read, so the pass begins after it.
    let reload = match &ops[scan.header] {
        R2ILOp::Load { dst, .. } => Some(dst),
        _ => None,
    };
    let first = scan.header + usize::from(reload.is_some());
    let pass = index_pass(ops.get(first..scan.back)?, exit_cond)?;
    if first + pass_test_offset(pass.direction) != scan.exit {
        return None;
    }
    let reloads_source =
        reload.is_none_or(|dst| same(dst, pass.source) && reload_is_redundant(ops, scan.header));
    let width = u64::from(pass.source.size) * 8;
    let start = match pass.direction {
        Direction::Down => width - 1,
        Direction::Up => 0,
    };
    // The source is the same on every pass, and only the step moves the index.
    let pass_ops = &ops[first..scan.back];
    if written_in(pass_ops, pass.source)
        || writers(pass_ops, pass.index) != 1
        || !reloads_source
        || starting_constant(ops, scan.header, pass.index) != Some(start)
        || !only_reads_after(ops, scan, &[pass.index, pass.source])
    {
        return None;
    }
    let guard = zero_guard(ops, scan, pass.source)?;
    let tail = destination_write(ops, scan.done(), pass.index)?;
    let mut allocator = InstructionTempAllocator::for_ops(ops);
    let count = match pass.direction {
        Direction::Down => highest_set_bit(&mut allocator, pass.source, pass.index)?,
        Direction::Up => trailing_zeros(&mut allocator, pass.source, pass.index)?,
    };
    let mut rewritten = ops[..scan.header].to_vec();
    rewritten.extend(count);
    rewritten.extend_from_slice(tail);
    // Where the source is zero, the guard now skips the destination write too.
    let past_end = u64::try_from(rewritten.len() - guard).ok()?;
    let R2ILOp::CBranch { target, .. } = &mut rewritten[guard] else {
        return None;
    };
    *target = Varnode::constant(past_end, 4);
    Some(rewritten)
}

/// Where the exit test sits in a pass: after the shift and compare (down), or
/// the shift, mask and compare (up).
fn pass_test_offset(direction: Direction) -> usize {
    match direction {
        Direction::Down => 2,
        Direction::Up => 3,
    }
}

/// `(w - 1) - Lzcount(x)`, the index of the highest set bit of a non-zero `x`.
fn highest_set_bit(
    allocator: &mut InstructionTempAllocator,
    source: &Varnode,
    index: &Varnode,
) -> Option<Vec<R2ILOp>> {
    let leading = allocator.allocate(index.size)?;
    let last = u64::from(source.size) * 8 - 1;
    Some(vec![
        R2ILOp::Lzcount {
            dst: leading.clone(),
            src: source.clone(),
        },
        R2ILOp::IntSub {
            dst: index.clone(),
            a: Varnode::constant(last, index.size),
            b: leading,
        },
    ])
}

/// `PopCount(~x & (x - 1))`: the trailing zeros of `x`, and its width at zero.
fn trailing_zeros(
    allocator: &mut InstructionTempAllocator,
    source: &Varnode,
    count: &Varnode,
) -> Option<Vec<R2ILOp>> {
    let inverted = allocator.allocate(source.size)?;
    let less_one = allocator.allocate(source.size)?;
    let below = allocator.allocate(source.size)?;
    Some(vec![
        R2ILOp::IntNot {
            dst: inverted.clone(),
            src: source.clone(),
        },
        R2ILOp::IntSub {
            dst: less_one.clone(),
            a: source.clone(),
            b: Varnode::constant(1, source.size),
        },
        R2ILOp::IntAnd {
            dst: below.clone(),
            a: inverted,
            b: less_one,
        },
        R2ILOp::PopCount {
            dst: count.clone(),
            src: below,
        },
    ])
}

/// TZCNT: the shifting walk, rewritten to `PopCount(~x & (x - 1))` over the
/// value the walk starts from.
fn shifting_walk(block: &R2ILBlock, scan: &ScanLoop) -> Option<Vec<R2ILOp>> {
    let ops = &block.ops;
    let [
        R2ILOp::IntAnd {
            dst: bit,
            a: walked,
            b: one,
        },
        R2ILOp::IntNotEqual {
            dst: found,
            a: tested,
            b: zero,
        },
        R2ILOp::CBranch { cond, .. },
        R2ILOp::IntAdd {
            dst: count,
            a: counted,
            b: step,
        },
        R2ILOp::IntRight {
            dst: shifted,
            a: shift_base,
            b: places,
        },
        R2ILOp::IntOr {
            dst: next,
            a: filled,
            b: top,
        },
    ] = ops.get(scan.header..scan.back)?
    else {
        return None;
    };
    let top_bit = 1u64.checked_shl(walked.size.checked_mul(8)?.checked_sub(1)?)?;
    let shaped = scan.exit == scan.header + 2
        && same(tested, bit)
        && same(cond, found)
        && same(counted, count)
        && same(shift_base, walked)
        && same(filled, shifted)
        && same(next, walked)
        && constant_value(one) == Some(1)
        && constant_value(zero) == Some(0)
        && constant_value(step) == Some(1)
        && constant_value(places) == Some(1)
        && constant_value(top) == Some(top_bit);
    // The walked value and the count are two storages, and each is written
    // once a pass: by the shift and by the step.
    let pass_ops = &ops[scan.header..scan.back];
    if !shaped
        || overlaps(walked, count)
        || writers(pass_ops, walked) != 1
        || writers(pass_ops, count) != 1
        || !straight_before(block, scan.header)
        || starting_constant(ops, scan.header, count) != Some(0)
        || !only_reads_after(ops, scan, &[count])
    {
        return None;
    }
    let mut allocator = InstructionTempAllocator::for_ops(ops);
    let mut rewritten = ops[..scan.header].to_vec();
    rewritten.extend(trailing_zeros(&mut allocator, walked, count)?);
    rewritten.extend_from_slice(&ops[scan.done()..]);
    Some(rewritten)
}

/// How many of `ops` write part of `varnode`.
fn writers(ops: &[R2ILOp], varnode: &Varnode) -> usize {
    ops.iter()
        .filter_map(R2ILOp::output)
        .filter(|output| overlaps(output, varnode))
        .count()
}

/// Whether anything in `ops` writes part of `varnode`.
fn written_in(ops: &[R2ILOp], varnode: &Varnode) -> bool {
    writers(ops, varnode) > 0
}

/// The constant the loop's index or count holds when the loop is entered:
/// its last write before the loop must be a copy of one.
fn starting_constant(ops: &[R2ILOp], header: usize, varnode: &Varnode) -> Option<u64> {
    let writer = last_writer(ops, header, varnode)?;
    match &ops[writer] {
        R2ILOp::Copy { dst, src } if same(dst, varnode) => constant_value(src),
        _ => None,
    }
}

/// Whether no local branch comes before the loop, so everything before it runs.
fn straight_before(block: &R2ILBlock, header: usize) -> bool {
    block.ops[..header]
        .iter()
        .enumerate()
        .all(|(index, op)| local_branch(block, index, op).is_none())
}

/// Whether the operations after the loop read nothing the loop wrote but
/// `kept`, whose values the rewrite states.
fn only_reads_after(ops: &[R2ILOp], scan: &ScanLoop, kept: &[&Varnode]) -> bool {
    let pass = &ops[scan.header..scan.back];
    ops[scan.done()..]
        .iter()
        .flat_map(R2ILOp::inputs)
        .filter(|input| input.space != SpaceId::Const)
        .all(|input| kept.iter().any(|k| same(k, input)) || !written_in(pass, input))
}

/// Whether the load opening each pass reads what an identical load before the
/// loop read into the same storage, with nothing between writing that storage,
/// the address, or memory.
fn reload_is_redundant(ops: &[R2ILOp], header: usize) -> bool {
    let R2ILOp::Load { dst, addr, .. } = &ops[header] else {
        return false;
    };
    let Some(earlier) = (0..header).rev().find(|index| ops[*index] == ops[header]) else {
        return false;
    };
    ops[earlier + 1..header].iter().all(|op| {
        !op.is_memory_write()
            && op
                .output()
                .is_none_or(|output| !overlaps(output, dst) && !overlaps(output, addr))
    })
}

/// The guard that skips the loop where the source is zero: the one local
/// branch before the loop, landing where the loop exits, on a condition that
/// is `x == 0` or `(x == 0) == 1`, with `x` unwritten from the test on.
///
/// Answers the guard's index.
fn zero_guard(ops: &[R2ILOp], scan: &ScanLoop, source: &Varnode) -> Option<usize> {
    let guards = (0..scan.header)
        .filter(|index| matches!(ops[*index], R2ILOp::Branch { .. } | R2ILOp::CBranch { .. }))
        .collect::<Vec<_>>();
    let [guard] = guards.as_slice() else {
        return None;
    };
    let R2ILOp::CBranch { target, cond } = &ops[*guard] else {
        return None;
    };
    let lands = target.space == SpaceId::Const
        && super::relative_target_index(*guard, target) == Some(scan.done());
    let test = zero_test(ops, *guard, cond, source)?;
    let unwritten = !written_in(&ops[test + 1..scan.header], source);
    (lands && unwritten).then_some(*guard)
}

/// Where `cond` is computed as `x == 0`, looking through one `== 1`.
fn zero_test(ops: &[R2ILOp], before: usize, cond: &Varnode, source: &Varnode) -> Option<usize> {
    let at = last_writer(ops, before, cond)?;
    let R2ILOp::IntEqual { dst, a, b } = &ops[at] else {
        return None;
    };
    if !same(dst, cond) {
        return None;
    }
    match constant_value(b)? {
        0 if same(a, source) => Some(at),
        1 if a.size == 1 => zero_test(ops, at, a, source),
        _ => None,
    }
}

/// The operations after the loop, where each only writes the destination
/// register from the index or from the part of it written just before (a
/// 32-bit write and its zero extension).
fn destination_write<'a>(ops: &'a [R2ILOp], done: usize, index: &Varnode) -> Option<&'a [R2ILOp]> {
    let tail = ops.get(done..)?;
    let mut written = vec![index];
    for op in tail {
        let (R2ILOp::Copy { dst, src } | R2ILOp::IntZExt { dst, src }) = op else {
            return None;
        };
        if dst.space != SpaceId::Register || !written.iter().any(|w| same(w, src)) {
            return None;
        }
        written.push(dst);
    }
    (!tail.is_empty()).then_some(tail)
}

/// The three counting lemmas, over every 64-bit source: each walk, run as the
/// specification writes it, stops at the count the rewrite states.
#[cfg(kani)]
mod kani_proofs {
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_descending_walk_stops_at_the_highest_set_bit() {
        let x: u64 = kani::any();
        kani::assume(x != 0);
        let mut index: u64 = 63;
        while (x >> index) == 0 {
            index -= 1;
        }
        assert_eq!(index, 63 - u64::from(x.leading_zeros()));
    }

    #[kani::proof]
    #[kani::unwind(65)]
    fn an_ascending_walk_stops_at_the_lowest_set_bit() {
        let x: u64 = kani::any();
        kani::assume(x != 0);
        let mut index: u64 = 0;
        while (x >> index) & 1 == 0 {
            index += 1;
        }
        assert_eq!(index, u64::from((!x & x.wrapping_sub(1)).count_ones()));
    }

    #[kani::proof]
    #[kani::unwind(66)]
    fn a_shifting_walk_counts_the_trailing_zeros_and_the_width_at_zero() {
        let x: u64 = kani::any();
        let (mut count, mut walked): (u64, u64) = (0, x);
        while walked & 1 == 0 {
            count += 1;
            walked = (walked >> 1) | 1 << 63;
        }
        assert_eq!(count, u64::from((!x & x.wrapping_sub(1)).count_ones()));
    }
}
