//! Loads that reread a word no write has touched since an earlier load, so are its bits: an exact frame
//! slot, or one address read twice. Along single-predecessor chains, `O(ops log slots)` (doc/adr-frame-model.md, "Reloads").

use std::collections::BTreeMap;

use crate::SSAOp;
use crate::StackAddressBase;
use crate::dense::IdMap;
use crate::function::{DecompilePrepFacts, StackAddressRoot};
use crate::graph::{BlockId, SsaGraph, ValueId};
use crate::semantic::resolve_entry_stack_root;

/// Widest access the held slots are searched for overlap at.
const WIDEST: u32 = 64;

/// Where a frame slot is within its origin, and how wide: the key a held load is found by.
type Slot = (i64, u32);

/// How many origins a frame is addressed from.
const ORIGINS: usize = 3;

const fn origin(base: StackAddressBase) -> usize {
    match base {
        StackAddressBase::FramePointer => 0,
        StackAddressBase::StackPointer => 1,
        StackAddressBase::Realigned => 2,
    }
}

/// What walking a block did to the held loads, to be undone on leaving it.
enum Undo {
    Added(usize, Slot),
    Removed(usize, Slot, ValueId),
    Dropped(usize, BTreeMap<Slot, ValueId>),
    /// A place's first load, and what the place held before.
    Read(usize, (u32, ValueId)),
    /// A write ended the era the places were read in.
    Forgot(u32),
}

/// A word outside the exact frame: the value its address is built on, the constant added, and the width read.
type Place = (Option<ValueId>, i64, u32);

/// The first load of each exact frame slot on the path being walked. Not `Clone`: a branch is entered by
/// noting the trail's length and left by rewinding it (doc/adr-frame-model.md, "Reloads").
#[derive(Default)]
struct Held {
    by_origin: [BTreeMap<Slot, ValueId>; ORIGINS],
    /// Per place, the era its first load was read in and that load; held only while the era lasts.
    places: Vec<(u32, ValueId)>,
    /// The era since the last write, and the next one unused: a write starts a new era in `O(1)`.
    era: u32,
    eras: u32,
    trail: Vec<Undo>,
}

impl Held {
    fn get(&self, root: StackAddressRoot, size: u32) -> Option<ValueId> {
        self.by_origin[origin(root.base)]
            .get(&(root.offset, size))
            .copied()
    }

    fn add(&mut self, root: StackAddressRoot, size: u32, value: ValueId) {
        let (origin, slot) = (origin(root.base), (root.offset, size));
        self.by_origin[origin].insert(slot, value);
        self.trail.push(Undo::Added(origin, slot));
    }

    /// Whatever the operation may have written, or left unstated: nothing is held.
    fn clear(&mut self) {
        (0..ORIGINS).for_each(|origin| self.drop_origin(origin));
        self.forget_places();
    }

    /// A write may reach any word outside the exact frame: no place read before it is held.
    fn forget_places(&mut self) {
        if !self.places.is_empty() {
            self.trail.push(Undo::Forgot(self.era));
            self.eras += 1;
            self.era = self.eras;
        }
    }

    /// The load this place was first read by since the last write, else `load` becomes it.
    fn reread(&mut self, place: usize, load: ValueId) -> Option<ValueId> {
        let held = self.places[place];
        if held.0 == self.era {
            return Some(held.1);
        }
        self.trail.push(Undo::Read(place, held));
        self.places[place] = (self.era, load);
        None
    }

    fn drop_origin(&mut self, origin: usize) {
        if !self.by_origin[origin].is_empty() {
            let table = std::mem::take(&mut self.by_origin[origin]);
            self.trail.push(Undo::Dropped(origin, table));
        }
    }

    /// What a store leaves held: an exact frame slot keeps the slots of its origin it misses and drops the
    /// other origins', any other store keeps none.
    fn store(&mut self, stored: Option<(StackAddressRoot, u32)>) {
        let Some((root, size)) = stored else {
            return self.clear();
        };
        self.forget_places();
        let mine = origin(root.base);
        (0..ORIGINS)
            .filter(|origin| *origin != mine)
            .for_each(|origin| self.drop_origin(origin));
        // An older slot reaches `WIDEST` bytes past its offset, so nothing before that overlaps.
        let low = root.offset.saturating_sub(i64::from(WIDEST));
        let high = root.offset.saturating_add(i64::from(size));
        let overlapped = (self.by_origin[mine].range((low, 0)..(high, 0)))
            .filter(|((offset, width), _)| {
                let end = |at: i64, size: u32| at.saturating_add(i64::from(size));
                *offset < end(root.offset, size) && root.offset < end(*offset, *width)
            })
            .map(|(slot, value)| (*slot, *value))
            .collect::<Vec<_>>();
        for (slot, value) in overlapped {
            self.by_origin[mine].remove(&slot);
            self.trail.push(Undo::Removed(mine, slot, value));
        }
    }

    /// Undo everything done since the trail was `mark` long.
    fn rewind(&mut self, mark: usize) {
        while self.trail.len() > mark {
            match self.trail.pop() {
                Some(Undo::Added(origin, slot)) => _ = self.by_origin[origin].remove(&slot),
                Some(Undo::Removed(origin, slot, value)) => {
                    self.by_origin[origin].insert(slot, value);
                }
                Some(Undo::Dropped(origin, table)) => self.by_origin[origin] = table,
                Some(Undo::Read(place, held)) => self.places[place] = held,
                Some(Undo::Forgot(era)) => self.era = era,
                None => return,
            }
        }
    }
}

/// A block to walk, or the point to rewind to when its subtree is done.
enum Visit {
    Enter(BlockId),
    Leave(usize),
}

/// The graph walked, and the rereads found so far.
struct Rereads<'a> {
    graph: &'a SsaGraph,
    prep: Option<&'a DecompilePrepFacts>,
    /// The place each load outside the exact frame reads, where another load reads the same one.
    places: IdMap<ValueId, usize>,
    found: IdMap<ValueId, ValueId>,
}

/// The exact frame slot an address is, where it is one.
fn frame_slot(
    prep: Option<&DecompilePrepFacts>,
    addr: ValueId,
    space: r2il::SpaceId,
) -> Option<StackAddressRoot> {
    (space == r2il::SpaceId::Ram)
        .then(|| resolve_entry_stack_root(prep, addr))
        .flatten()
}

/// The place an address names: a constant is itself, a sum with a constant is its other side's copy
/// class and the constant, anything else its own class.
fn place_of(graph: &SsaGraph, prep: &DecompilePrepFacts, addr: ValueId, size: u32) -> Place {
    let literal = |value: ValueId| graph.value(value)?.var.constant_bits();
    let class = |value: ValueId| crate::view::class_value(graph, Some(&prep.views), value);
    if let Some(bits) = literal(addr) {
        return (None, bits as i64, size);
    }
    let sum = graph.def_inst(addr).and_then(|inst| {
        let SSAOp::IntAdd { a, b, .. } = graph.op(inst)? else {
            return None;
        };
        match (literal(*a), literal(*b)) {
            (None, Some(bits)) => Some((*a, bits as i64)),
            (Some(bits), None) => Some((*b, bits as i64)),
            _ => None,
        }
    });
    let (base, offset) = sum.unwrap_or((addr, 0));
    (Some(class(base)), offset, size)
}

/// A dense number for each place two loads or more read, by the load: `O(L log L)` over the loads.
fn shared_places(graph: &SsaGraph, prep: &DecompilePrepFacts) -> (IdMap<ValueId, usize>, usize) {
    let mut loads = Vec::new();
    for inst in &graph.insts {
        let (Some(SSAOp::Load { space, addr, .. }), Some(out)) = (graph.op(inst.id), inst.output)
        else {
            continue;
        };
        let size = graph.value(out).map_or(0, |value| value.var.size);
        let outside =
            *space == r2il::SpaceId::Ram && frame_slot(Some(prep), *addr, *space).is_none();
        if outside && size > 0 && size <= WIDEST {
            loads.push((place_of(graph, prep, *addr, size), out));
        }
    }
    loads.sort_unstable();
    let mut places = IdMap::new(graph.values.len());
    let mut count = 0;
    for run in loads.chunk_by(|left, right| left.0 == right.0) {
        if run.len() > 1 {
            run.iter()
                .for_each(|(_, out)| _ = places.insert(*out, count));
            count += 1;
        }
    }
    (places, count)
}

/// For each load that rereads a slot unchanged, the value of the load it rereads.
pub(crate) fn reloads(
    graph: &SsaGraph,
    prep: Option<&DecompilePrepFacts>,
) -> IdMap<ValueId, ValueId> {
    let (places, count) = match prep {
        Some(prep) => shared_places(graph, prep),
        None => (IdMap::new(0), 0),
    };
    let mut rereads = Rereads {
        graph,
        prep,
        places,
        found: IdMap::new(graph.values.len()),
    };
    if prep.is_none() {
        return rereads.found;
    }
    let sole_predecessor = |block: BlockId| match graph.blocks[block.0 as usize].predecessors[..] {
        [only] if only != block => Some(only),
        _ => None,
    };
    // A sole-predecessor block continues its parent's slots, the rest start empty: each block is entered
    // once, and the table is empty again when its tree is left.
    let mut held = Held {
        places: vec![(0, ValueId(0)); count],
        era: 1,
        eras: 1,
        ..Held::default()
    };
    let mut pending: Vec<Visit> = (graph.blocks.iter())
        .filter(|block| sole_predecessor(block.id).is_none())
        .map(|block| Visit::Enter(block.id))
        .collect();
    while let Some(visit) = pending.pop() {
        let block = match visit {
            Visit::Enter(block) => block,
            Visit::Leave(mark) => {
                held.rewind(mark);
                continue;
            }
        };
        pending.push(Visit::Leave(held.trail.len()));
        for &inst in graph.op_insts(block) {
            let (Some(op), Some(node)) = (graph.op(inst), graph.inst(inst)) else {
                continue;
            };
            rereads.step(op, node.output, &mut held);
        }
        let mut children = (graph.blocks[block.0 as usize].successors.iter())
            .copied()
            .filter(|child| sole_predecessor(*child) == Some(block))
            .collect::<Vec<_>>();
        children.sort_unstable();
        children.dedup();
        pending.extend(children.into_iter().map(Visit::Enter));
    }
    rereads.found
}

/// Put each reload in the copy class of the load it rereads: the loads of one slot are one value, so a
/// guard on any of them bounds all of them. `O(V)` over the class table, by union-find on its entries.
pub(crate) fn unite_classes(class: &mut [ValueId], reloads: &IdMap<ValueId, ValueId>) {
    fn find(parent: &mut [ValueId], mut at: ValueId) -> ValueId {
        while parent[at.0 as usize] != at {
            let up = parent[parent[at.0 as usize].0 as usize];
            parent[at.0 as usize] = up;
            at = up;
        }
        at
    }
    // Every representative is its own parent, so a chain ends.
    let mut parent = class.to_vec();
    for rep in class.iter() {
        if let Some(own) = parent.get_mut(rep.0 as usize) {
            *own = *rep;
        }
    }
    for (reload, first) in reloads.iter() {
        let (Some(a), Some(b)) = (class.get(reload.0 as usize), class.get(first.0 as usize)) else {
            continue;
        };
        let (a, b) = (find(&mut parent, *a), find(&mut parent, *b));
        if a != b {
            parent[a.max(b).0 as usize] = a.min(b);
        }
    }
    for entry in class.iter_mut() {
        *entry = find(&mut parent, *entry);
    }
}

impl Rereads<'_> {
    /// A load outside the exact frame: the load of its place since the last write, where there is one.
    fn reread_place(&mut self, out: ValueId, held: &mut Held) {
        let first = (self.places.get(out)).and_then(|place| held.reread(*place, out));
        if let Some(first) = first {
            self.found.insert(out, first);
        }
    }

    fn step(&mut self, op: &SSAOp<ValueId>, output: Option<ValueId>, held: &mut Held) {
        let (graph, prep) = (self.graph, self.prep);
        let slot = |addr: ValueId, space: r2il::SpaceId| frame_slot(prep, addr, space);
        match op {
            SSAOp::Load { space, addr, .. } => {
                let Some(out) = output else {
                    return;
                };
                let Some(root) = slot(*addr, *space) else {
                    return self.reread_place(out, held);
                };
                let size = graph.value(out).map_or(0, |value| value.var.size);
                if size == 0 || size > WIDEST {
                    return;
                }
                match held.get(root, size) {
                    Some(first) => {
                        self.found.insert(out, first);
                    }
                    None => held.add(root, size, out),
                }
            }
            SSAOp::Store { space, addr, val } => {
                let size = graph.value(*val).map_or(0, |value| value.var.size);
                let wide = size > 0 && size <= WIDEST;
                held.store(
                    slot(*addr, *space)
                        .filter(|_| wide)
                        .map(|root| (root, size)),
                );
            }
            op if clobbers(op) => held.clear(),
            _ => {}
        }
    }
}

/// Whether the operation may write memory the frame holds, or leave what a load reads unstated.
fn clobbers(op: &SSAOp<ValueId>) -> bool {
    op.is_memory_write()
        || op.is_call()
        || matches!(
            op,
            SSAOp::CallOther { .. }
                | SSAOp::Fence { .. }
                | SSAOp::ClearExclusive
                | SSAOp::IndivisibleAccess
                | SSAOp::BlockTransfer(_)
                | SSAOp::Unimplemented
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(base: StackAddressBase, offset: i64) -> StackAddressRoot {
        StackAddressRoot { base, offset }
    }

    fn sp(offset: i64) -> StackAddressRoot {
        root(StackAddressBase::StackPointer, offset)
    }

    #[test]
    fn leaving_a_branch_restores_what_it_cleared_stored_over_and_added() {
        let mut held = Held::default();
        held.add(sp(0x10), 4, ValueId(1));
        held.add(sp(0x20), 4, ValueId(2));
        let mark = held.trail.len();
        held.store(Some((sp(0x12), 4)));
        assert_eq!(held.get(sp(0x10), 4), None);
        assert_eq!(held.get(sp(0x20), 4), Some(ValueId(2)));
        held.clear();
        held.add(sp(0x30), 4, ValueId(3));
        held.rewind(mark);
        assert_eq!(held.get(sp(0x10), 4), Some(ValueId(1)));
        assert_eq!(held.get(sp(0x20), 4), Some(ValueId(2)));
        assert_eq!(held.get(sp(0x30), 4), None);
    }

    #[test]
    fn a_store_drops_exactly_the_slots_it_overlaps_and_the_other_origins() {
        let mut held = Held::default();
        let frame = |offset| root(StackAddressBase::FramePointer, offset);
        held.add(sp(0x0c), 4, ValueId(1));
        held.add(sp(0x08), 8, ValueId(2));
        held.add(sp(0x14), 4, ValueId(3));
        held.add(sp(0x00), 64, ValueId(4));
        held.add(frame(0x10), 4, ValueId(5));
        held.store(Some((sp(0x10), 4)));
        let kept = [(0x0c, 4), (0x14, 4), (0x08, 8), (0x00, 64)]
            .map(|(offset, size)| held.get(sp(offset), size));
        // The first is clear of the store; the second and third are adjacent to it or end at it; only the last reaches in.
        assert_eq!(
            kept,
            [Some(ValueId(1)), Some(ValueId(3)), Some(ValueId(2)), None]
        );
        assert_eq!(held.get(frame(0x10), 4), None);
    }
}
