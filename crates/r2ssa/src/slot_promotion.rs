//! Frame slots taken out of memory as SSA values, before preparation (doc/adr-frame-model.md, P4.3).
//!
//! A place every access to which is a load or store of one width at one entry offset, that no
//! escaped frame address reaches and no declaration names, is a variable: a store becomes a copy
//! into a new version of `stack:mN`, a load a copy out of the version that reaches it, a merge a
//! phi. Escape is the frame's one walk (`semantic::frame_reach`, D290); an escape reaches every
//! place on either side of it, out to a save slot. `O(places x blocks)` to rename.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::dense::IdSet;
use crate::frame_address::Definitions;
use crate::function::{EditPlan, PhiNode, SSAFunction, ShapeEdit};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::semantic::{Access, FramePoints, Walked, walk};
use crate::value_table::{Minting, VarId};
use crate::var::SSAVar;

/// The space promoted stack slots live in: not memory, and not the lifter's scratch either.
pub(crate) const PROMOTED_SLOT_SPACE: u32 = 0x5301;

/// Where a promoted frame slot sits relative to the entry frame, where this storage is one.
pub fn promoted_slot_offset(storage: &crate::CanonicalStorageId) -> Option<i64> {
    let promoted = storage.space == crate::CanonicalStorageSpace::Custom(PROMOTED_SLOT_SPACE);
    promoted.then_some(storage.offset as i64)
}

/// Promote every eligible frame place of `func`, the loads and stores rewritten; the frame's
/// points, from the one escape walk (D290), are what every later reader of escape asks.
pub(crate) fn promote(
    func: &mut SSAFunction,
    machine: &SourceMachineContext,
    calls_refund_stack: bool,
) -> (IdSet<OpId>, FramePoints) {
    let defs = Definitions::of(func);
    if let Some(exhausted) = defs.exhausted() {
        func.note_exhausted(exhausted);
    }
    let mut decided = BTreeMap::new();
    let (walked, promotable) = walk(func, &defs, machine, calls_refund_stack, |walked| {
        decided.clear();
        // An entry block something branches back to runs its prologue again: no place is fixed.
        if walked.points.unplaced() || func.cfg().has_entry_edge() {
            return BTreeMap::new();
        }
        let saves = saves(func, &defs, &walked.accesses, machine);
        eligible(func, &defs, walked, (&saves, &mut decided), machine)
    });
    let Walked {
        mut points,
        accesses,
        ..
    } = walked;
    points.rewrite_decides = decided;
    if points.unplaced() {
        r2il::refusal_evidence!(
            "promote-stack-slot",
            "{:#x}: a frame address no offset places reaches an access or leaves, so nothing is promoted",
            func.entry
        );
        return (IdSet::default(), points);
    }
    if promotable.is_empty() {
        return (IdSet::default(), points);
    }
    r2il::refusal_evidence!(
        "promote-stack-slot",
        "{:#x}: {} slots promoted out of memory: {:?}",
        func.entry,
        promotable.len(),
        promotable.keys().collect::<Vec<_>>()
    );
    (rename(func, &accesses, &promotable), points)
}

/// The places a register lane the convention preserves is saved into at its entry value
/// (`saved_register`); they bound what an escaped address reaches.
fn saves(
    func: &SSAFunction,
    defs: &Definitions,
    accesses: &BTreeMap<i64, Vec<Access>>,
    machine: &SourceMachineContext,
) -> BTreeSet<i64> {
    let (effect, stack_pointer) = (machine.calls(), machine.stack_pointer_carrier());
    let saved = |access: &Access| {
        let val = match func.get_block(access.block)?.ops().get(access.index)? {
            SSAOp::Store { val, .. } => *val,
            _ => return None,
        };
        crate::saved_register::entry_lane_of_var(func, defs, val)
            .filter(|lane| crate::saved_register::preserved(effect, stack_pointer, *lane))
    };
    accesses
        .iter()
        .filter(|(_, list)| {
            (list.iter()).any(|access| {
                access.store && access.block == func.root() && saved(access).is_some()
            })
        })
        .map(|(offset, _)| *offset)
        .collect()
}

/// Each place a variable may stand for, with its one width.
fn eligible(
    func: &SSAFunction,
    defs: &Definitions,
    walked: &Walked,
    (saves, decided): (&BTreeSet<i64>, &mut BTreeMap<i64, u32>),
    machine: &SourceMachineContext,
) -> BTreeMap<i64, u32> {
    let (accesses, points) = (&walked.accesses, &walked.points);
    let reachable = |place: i64| points.reaches(place, saves);
    let declared = machine
        .function_interface()
        .map(|interface| interface.stack_slots().to_vec())
        .unwrap_or_default();
    let declared_covers = |offset: i64, width: u32| {
        declared.iter().any(|slot| {
            slot.base() == crate::StackAddressBase::StackPointer
                && slot.offset() < offset + i64::from(width)
                && offset < slot.offset() + i64::from(slot.size_bytes())
        })
    };
    let mut promotable = BTreeMap::new();
    let overlapped = overlapped_places(accesses);
    for (offset, list) in accesses {
        // The caller's storage stays in memory: the return address, stack arguments.
        if !machine.stack_owner(*offset).callee_owned() {
            continue;
        }
        let widths = list
            .iter()
            .map(|access| access.width)
            .collect::<BTreeSet<_>>();
        let Some(width) = widths.iter().next().copied().filter(|_| widths.len() == 1) else {
            continue;
        };
        let overlaps = overlapped.contains(offset);
        let stores = list.iter().filter(|access| access.store).count();
        let read_only_home = stores == 1
            && list.iter().filter(|access| access.store).any(|access| {
                func.get_block(access.block)
                    .and_then(|block| match block.ops().get(access.index) {
                        Some(SSAOp::Store { val, .. }) => Some(entry_value(func, defs, *val)),
                        _ => None,
                    })
                    .unwrap_or(false)
            });
        let is_declared = declared_covers(*offset, width) && !read_only_home;
        // A save read back stays in memory: the frame round-trip certificate answers for it.
        let is_save = saves.contains(offset) && list.iter().any(|access| !access.store);
        let handed = points.handed().contains(offset);
        // A call may rewrite its own argument area, so a load after it reads memory (D369).
        let rewritten = points.rewritten().contains(offset);
        let otherwise = overlaps || is_save || is_declared || handed || reachable(*offset);
        if !otherwise {
            decided.insert(*offset, width);
        }
        if overlaps || is_save || is_declared || handed || rewritten || reachable(*offset) {
            r2il::refusal_evidence!(
                "promote-stack-slot",
                "{:#x}: slot at {offset} stays in memory: overlap {overlaps}, save {is_save}, declared {is_declared}, handed {handed}, rewritten {rewritten}, reached {}",
                func.entry,
                reachable(*offset)
            );
            continue;
        }
        promotable.insert(*offset, width);
    }
    promotable
}

/// One rewrite of a slot's access, found by the walk: a load reads `version`, a store defines it.
enum Rewrite {
    Load { op: OpId, dst: VarId, version: u32 },
    Store { op: OpId, val: VarId, version: u32 },
}

/// A step of the dominator-tree walk: enter a block, or leave one and undo its versions.
enum Step {
    Enter(u64),
    Leave(usize),
}

/// What the walk found per slot: its version count, its rewrites, and each merge's arrivals.
struct Versions {
    next: Vec<u32>,
    rewrites: Vec<Vec<Rewrite>>,
    sources: BTreeMap<(u64, usize), Vec<(u64, u32)>>,
}

/// The places another place's access overlaps: one sweep of the sorted places, each the interval
/// from its offset to its widest access's end, `O(places + accesses)`.
fn overlapped_places(accesses: &BTreeMap<i64, Vec<Access>>) -> BTreeSet<i64> {
    let spans = accesses
        .iter()
        .map(|(offset, list)| {
            let widest = list.iter().map(|access| access.width).max().unwrap_or(0);
            (*offset, offset.saturating_add(i64::from(widest)))
        })
        .collect::<Vec<_>>();
    let mut overlapped = BTreeSet::new();
    // A place before this one that reaches into it is marked by its own next-place test below.
    let mut reach = i64::MIN;
    for (index, (offset, end)) in spans.iter().enumerate() {
        let next_inside = spans.get(index + 1).is_some_and(|(next, _)| next < end);
        if reach > *offset || next_inside {
            overlapped.insert(*offset);
        }
        reach = reach.max(*end);
    }
    overlapped
}

/// Rewrite every access of every promotable place into copies of its versions, with merges.
/// One dominator-tree walk serves every place: `O(B + E + accesses + merge operands)`.
fn rename(
    func: &mut SSAFunction,
    accesses: &BTreeMap<i64, Vec<Access>>,
    promotable: &BTreeMap<i64, u32>,
) -> IdSet<OpId> {
    let slots = promotable
        .iter()
        .map(|(offset, width)| (*offset, *width))
        .collect::<Vec<_>>();
    let (per_slot, by_block) = index_accesses(accesses, &slots);
    let merges = per_slot
        .iter()
        .map(|blocks| merge_blocks(func, blocks))
        .collect::<Vec<_>>();
    let versions = walk_versions(func, &by_block, &merges);
    emit(func, &slots, &merges, versions)
}

type SlotBlocks<'a> = BTreeMap<u64, Vec<&'a Access>>;
type BlockAccesses<'a> = BTreeMap<u64, Vec<(usize, &'a Access)>>;

/// Per slot and per block, its accesses in op order; per block, every slot's.
fn index_accesses<'a>(
    accesses: &'a BTreeMap<i64, Vec<Access>>,
    slots: &[(i64, u32)],
) -> (Vec<SlotBlocks<'a>>, BlockAccesses<'a>) {
    let mut per_slot = vec![SlotBlocks::new(); slots.len()];
    let mut by_block = BlockAccesses::new();
    for (slot, (offset, _)) in slots.iter().enumerate() {
        for access in &accesses[offset] {
            per_slot[slot].entry(access.block).or_default().push(access);
            by_block
                .entry(access.block)
                .or_default()
                .push((slot, access));
        }
    }
    for list in per_slot.iter_mut().flat_map(|blocks| blocks.values_mut()) {
        list.sort_by_key(|access| access.index);
    }
    for list in by_block.values_mut() {
        list.sort_by_key(|(_, access)| access.index);
    }
    (per_slot, by_block)
}

/// The blocks where a slot's versions merge, numbered 1..=m in block order.
fn merge_blocks(func: &SSAFunction, blocks: &SlotBlocks<'_>) -> BTreeMap<u64, u32> {
    let live_in = live_in(func, blocks);
    let defined = blocks
        .iter()
        .filter(|(_, list)| list.iter().any(|access| access.store))
        .map(|(block, _)| *block)
        .collect::<Vec<_>>();
    func.domtree()
        .iterated_frontier(&defined)
        .into_iter()
        .filter(|block| live_in.contains(block) && func.predecessors(*block).len() >= 2)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .zip(1u32..)
        .collect()
}

/// The dominator-tree walk: each block entered with the versions that reach it, undone on leaving.
fn walk_versions(
    func: &SSAFunction,
    by_block: &BlockAccesses<'_>,
    merges: &[BTreeMap<u64, u32>],
) -> Versions {
    let mut merges_at = BTreeMap::<u64, Vec<usize>>::new();
    for (slot, at) in merges.iter().enumerate() {
        for block in at.keys() {
            merges_at.entry(*block).or_default().push(slot);
        }
    }
    let mut versions = Versions {
        next: merges.iter().map(|at| at.len() as u32 + 1).collect(),
        rewrites: merges.iter().map(|_| Vec::new()).collect(),
        sources: BTreeMap::new(),
    };
    let mut current = vec![0u32; merges.len()];
    let mut undo = Vec::<(usize, u32)>::new();
    let mut steps = vec![Step::Enter(func.root())];
    let mut seen = BTreeSet::new();
    while let Some(step) = steps.pop() {
        let block = match step {
            Step::Enter(block) if seen.insert(block) => block,
            Step::Enter(_) => continue,
            Step::Leave(mark) => {
                for (slot, version) in undo.drain(mark..).rev() {
                    current[slot] = version;
                }
                continue;
            }
        };
        let mark = undo.len();
        for slot in merges_at.get(&block).into_iter().flatten() {
            undo.push((*slot, current[*slot]));
            current[*slot] = merges[*slot][&block];
        }
        for (slot, access) in by_block.get(&block).into_iter().flatten() {
            let op = func
                .get_block(block)
                .and_then(|b| b.ops().get(access.index));
            if let Some(defined) = versions.rewrite(*slot, access.op, op, current[*slot]) {
                undo.push((*slot, current[*slot]));
                current[*slot] = defined;
            }
        }
        for successor in func.successors(block) {
            for slot in merges_at.get(&successor).into_iter().flatten() {
                let arrived = versions.sources.entry((successor, *slot)).or_default();
                arrived.push((block, current[*slot]));
            }
        }
        steps.push(Step::Leave(mark));
        steps.extend(
            func.domtree()
                .children(block)
                .iter()
                .rev()
                .map(|child| Step::Enter(*child)),
        );
    }
    versions
}

impl Versions {
    /// Record the rewrite of one access that reads `current`; a store returns the version it defines.
    fn rewrite(
        &mut self,
        slot: usize,
        at: OpId,
        op: Option<&SSAOp<VarId>>,
        current: u32,
    ) -> Option<u32> {
        match op? {
            SSAOp::Load { dst, .. } => {
                self.rewrites[slot].push(Rewrite::Load {
                    op: at,
                    dst: *dst,
                    version: current,
                });
                None
            }
            SSAOp::Store { val, .. } => {
                let version = self.next[slot];
                self.next[slot] += 1;
                self.rewrites[slot].push(Rewrite::Store {
                    op: at,
                    val: *val,
                    version,
                });
                Some(version)
            }
            _ => None,
        }
    }
}

/// Mint and edit slot by slot, versions in order, so ids are a function of the walk alone.
fn emit(
    func: &mut SSAFunction,
    slots: &[(i64, u32)],
    merges: &[BTreeMap<u64, u32>],
    mut versions: Versions,
) -> IdSet<OpId> {
    let mut plan = EditPlan::new();
    let mut minting = Minting::new(func.values());
    let mut rewritten = IdSet::default();
    for (slot, (offset, width)) in slots.iter().enumerate() {
        let storage = crate::CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Custom(PROMOTED_SLOT_SPACE),
            offset: *offset as u64,
            size: *width,
        };
        let name = crate::naming::frame_slot_name(*offset);
        let ids = (0..versions.next[slot])
            .map(|version| {
                minting.intern_with_storage(&SSAVar::new(&name, version, *width), storage)
            })
            .collect::<Vec<_>>();
        for rewrite in &versions.rewrites[slot] {
            let (op, copy) = match *rewrite {
                Rewrite::Load { op, dst, version } => (
                    op,
                    SSAOp::Copy {
                        dst,
                        src: ids[version as usize],
                    },
                ),
                Rewrite::Store { op, val, version } => (
                    op,
                    SSAOp::Copy {
                        dst: ids[version as usize],
                        src: val,
                    },
                ),
            };
            plan.replace(op, copy);
            rewritten.insert(op);
        }
        for (block, version) in &merges[slot] {
            let arrived = versions.sources.remove(&(*block, slot)).unwrap_or_default();
            let reaching = |pred: u64| {
                arrived
                    .iter()
                    .find(|(from, _)| *from == pred)
                    .map_or(0, |(_, version)| *version)
            };
            let sources = func
                .predecessors(*block)
                .into_iter()
                .map(|pred| (pred, ids[reaching(pred) as usize]))
                .collect();
            plan.reshape(ShapeEdit::InsertPhi {
                block: *block,
                phi: PhiNode {
                    dst: ids[*version as usize],
                    sources,
                    canonical_storage: Some(storage),
                },
            });
        }
    }
    plan.adopt(minting.finish());
    func.apply_edits(plan);
    rewritten
}

/// The blocks the slot is live into: read before written there, or live out with no write.
fn live_in(func: &SSAFunction, by_block: &BTreeMap<u64, Vec<&Access>>) -> BTreeSet<u64> {
    let reads_first = |block: u64| {
        by_block
            .get(&block)
            .and_then(|accesses| accesses.first())
            .is_some_and(|access| !access.store)
    };
    let writes = |block: u64| {
        by_block
            .get(&block)
            .is_some_and(|accesses| accesses.iter().any(|access| access.store))
    };
    // Only blocks that access the slot can read it first: the walk stays in its live range.
    let mut live = by_block
        .keys()
        .copied()
        .filter(|block| reads_first(*block))
        .collect::<BTreeSet<_>>();
    let mut pending = live.iter().copied().collect::<Vec<_>>();
    // Backward: a predecessor that does not write the slot is live into as well; each block enters once.
    while let Some(block) = pending.pop() {
        for pred in func.predecessors(block) {
            if !writes(pred) && live.insert(pred) {
                pending.push(pred);
            }
        }
    }
    live
}

/// Whether a value is what a register held on entry, whole or as its low lane (`edi` of `rdi`).
fn entry_value(func: &SSAFunction, defs: &Definitions, var: VarId) -> bool {
    let var = defs.copied(var);
    match defs.op(var).map(|(_, op)| op) {
        Some(SSAOp::Subpiece { src, offset: 0, .. }) => func.var(defs.copied(*src)).version == 0,
        _ => func.var(var).version == 0 && func.var(var).constant_bits().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dense::DenseId;

    /// Each place another place's access overlaps, by testing every pair: the rule the sweep keeps.
    fn pairwise_overlaps(accesses: &BTreeMap<i64, Vec<Access>>) -> BTreeSet<i64> {
        let span = |offset: i64, width: u32| (offset, offset + i64::from(width));
        let spans = accesses
            .iter()
            .flat_map(|(offset, list)| list.iter().map(|access| span(*offset, access.width)))
            .collect::<Vec<_>>();
        let mut overlapped = BTreeSet::new();
        for (offset, end) in &spans {
            let meets = |(other, other_end): &(i64, i64)| {
                other != offset && other < end && offset < other_end
            };
            if spans.iter().any(meets) {
                overlapped.insert(*offset);
            }
        }
        overlapped
    }

    /// The sweep marks exactly the places the pairwise test did, over generated frames.
    #[test]
    fn the_overlap_sweep_is_the_pairwise_test() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..2000 {
            let mut accesses = BTreeMap::<i64, Vec<Access>>::new();
            for index in 0..next(8) {
                let offset = -(next(24) as i64) - 1;
                let width = [1, 2, 4, 8][next(4) as usize];
                accesses.entry(offset).or_default().push(Access {
                    op: OpId::from_index(index as usize),
                    block: 0,
                    index: index as usize,
                    width,
                    store: false,
                });
            }
            let pairwise = pairwise_overlaps(&accesses);
            let spans = accesses
                .iter()
                .map(|(offset, list)| {
                    (
                        *offset,
                        list.iter().map(|access| access.width).collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(overlapped_places(&accesses), pairwise, "{spans:?}");
        }
    }
}
