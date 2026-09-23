//! Where each value is live, as positions in blocks.
//!
//! Two values may share one C object exactly when neither is still needed at
//! a point where the other holds the object, so every coalescing decision is
//! a question about live ranges. This answers it once, from the graph, for
//! every value: the blocks a value is live in, and within each block the
//! positions it is live after.
//!
//! A position is an instruction ordinal in a block. A value is live after
//! position `p` when some path from just after `p` reaches a read of it without
//! passing its definition. A merge reads each source on the incoming edge, so
//! that read sits past the last ordinal of the predecessor, and a value the
//! caller reads is read past the last ordinal of every returning block that
//! hands it back. Both are [`BLOCK_END`].

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::{BlockId, InstId, InstPayload, SsaGraph, UseSite, ValueId};
use crate::liveout::FunctionLiveOut;
use crate::op::SSAOp;

/// Past every instruction of a block: an edge read, or leaving the function.
pub const BLOCK_END: u32 = u32::MAX;

/// One stretch of one block over which a value is live.
///
/// `start` is the first position the value is live after and `end` the first
/// it is not, so a value read by the instruction that defines another ends
/// exactly where the other begins and the two do not overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LiveSegment {
    pub block: BlockId,
    pub start: u32,
    pub end: u32,
}

impl LiveSegment {
    fn overlaps(self, other: LiveSegment) -> bool {
        self.block == other.block && self.start < other.end && other.start < self.end
    }

    const fn contains(self, block: BlockId, position: u32) -> bool {
        self.block.0 == block.0 && self.start <= position && position < self.end
    }
}

/// The live segments of every value, and which values hold one content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueLiveness {
    /// Per value, where its segments start in `segments`; one extra at the end.
    offsets: Vec<u32>,
    /// Sorted by block within each value.
    segments: Vec<LiveSegment>,
    /// Union-find parent over values that re-express one content at another
    /// width: a copy, a zero extension, a sign extension.
    content: Vec<u32>,
    /// Merges nothing reads, directly or through other such merges.
    unread_phi: Vec<bool>,
}

/// Per-value scratch for one block, stamped so nothing is cleared between values.
#[derive(Clone, Copy, Default)]
struct BlockScratch {
    stamp: u32,
    /// Last read strictly before the definition, in the definition's block.
    last_use_before_def: Option<u32>,
    /// Last read at or after the definition, or anywhere in another block.
    last_use: Option<u32>,
    live_in: bool,
    live_out: bool,
}

impl ValueLiveness {
    pub fn compute(graph: &SsaGraph, live_out: &FunctionLiveOut) -> Self {
        Self::compute_with_relocations(graph, live_out, &BTreeMap::new(), &[], &BTreeSet::new())
    }

    /// State that two values hold one content, on evidence the graph alone
    /// does not carry: two reads of one memory object with no write between.
    pub fn declare_same_content(&mut self, left: ValueId, right: ValueId) {
        if (left.0 as usize) < self.content.len() && (right.0 as usize) < self.content.len() {
            content_union(&mut self.content, left.0, right.0);
        }
    }

    /// Liveness as the text will have it once some definitions are folded
    /// into their readers: a read made by a folded instruction happens where
    /// the reader is, and the operands it reads are needed until then.
    /// `relocations` maps each folded definition to its one reader, and a
    /// chain of folds resolves to the last reader.
    /// `ignored_reads` are use sites the text never performs -- a call's
    /// conventional read of a register the certified call does not pass --
    /// and they hold nothing live.
    pub fn compute_with_relocations(
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        relocations: &BTreeMap<InstId, InstId>,
        same_content: &[(ValueId, ValueId)],
        ignored_reads: &BTreeSet<UseSite>,
    ) -> Self {
        let relocate = |mut inst: InstId| {
            let mut steps = 0;
            while let Some(next) = relocations.get(&inst) {
                inst = *next;
                steps += 1;
                if steps > relocations.len() {
                    break;
                }
            }
            inst
        };
        let value_count = graph.values.len();
        let block_count = graph.blocks.len();
        // Which values are one content seen more than once. A copy or a
        // widening re-expresses what it read; a lane is part of it; the merges
        // one block makes over one location are that location's single state
        // at that point, seen at several widths, and so are the values a
        // function is entered with. None of these can hold two contents at
        // once, whatever their live ranges do.
        let mut content = (0..value_count as u32).collect::<Vec<u32>>();
        let location_of = |value: ValueId| {
            graph
                .value(value)
                .and_then(|value| value.canonical_storage)
                .filter(|storage| !storage.is_unknown())
                .map(|storage| storage.location())
        };
        let mut first_phi_by_location = std::collections::HashMap::new();
        for inst in &graph.insts {
            let Some(output) = inst.output else {
                continue;
            };
            match &inst.payload {
                InstPayload::Phi { .. } => {
                    if let Some(location) = location_of(output) {
                        match first_phi_by_location.entry((inst.block, location)) {
                            std::collections::hash_map::Entry::Vacant(slot) => {
                                slot.insert(output);
                            }
                            std::collections::hash_map::Entry::Occupied(slot) => {
                                content_union(&mut content, slot.get().0, output.0);
                            }
                        }
                    }
                }
                InstPayload::Op(op) => {
                    let views_input = match op {
                        SSAOp::Copy { .. } | SSAOp::IntZExt { .. } | SSAOp::IntSExt { .. } => {
                            match (
                                graph.value(output),
                                inst.inputs.first().and_then(|input| graph.value(*input)),
                            ) {
                                (Some(out), Some(inp)) => out.var.size >= inp.var.size,
                                _ => false,
                            }
                        }
                        SSAOp::Subpiece { .. } => true,
                        _ => false,
                    };
                    if views_input && let Some(input) = inst.inputs.first() {
                        content_union(&mut content, output.0, input.0);
                    }
                }
            }
        }
        let mut first_entry_by_location = std::collections::HashMap::new();
        for value in &graph.values {
            if graph.def_inst(value.id).is_some() || value.var.is_const() {
                continue;
            }
            if let Some(location) = location_of(value.id) {
                match first_entry_by_location.entry(location) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(value.id);
                    }
                    std::collections::hash_map::Entry::Occupied(slot) => {
                        content_union(&mut content, slot.get().0, value.id.0);
                    }
                }
            }
        }

        // The caller's reads, indexed by value rather than scanned per block.
        let returned = returned_blocks_by_value(graph, live_out, value_count);
        let dead_phi = unread_phis(graph, live_out);

        let mut scratch = vec![BlockScratch::default(); block_count];
        let mut touched = Vec::<BlockId>::new();
        let mut pending = Vec::<BlockId>::new();
        let mut offsets = Vec::with_capacity(value_count + 1);
        let mut segments = Vec::<LiveSegment>::new();

        for value in &graph.values {
            offsets.push(segments.len() as u32);
            let stamp = value.id.0 + 1;
            let definition = graph
                .def_inst(value.id)
                .and_then(|inst| graph.inst(inst))
                .map(|inst| (inst.block, inst.ordinal as u32));
            // A value the function is entered with is held from before its
            // first position; it occupies nothing until something reads it.
            let (def_block, def_ordinal) = definition.unwrap_or((graph.entry, 0));
            touched.clear();
            let touch =
                |block: BlockId, scratch: &mut Vec<BlockScratch>, touched: &mut Vec<BlockId>| {
                    let cell = &mut scratch[block.0 as usize];
                    if cell.stamp != stamp {
                        *cell = BlockScratch {
                            stamp,
                            ..BlockScratch::default()
                        };
                        touched.push(block);
                    }
                };
            touch(def_block, &mut scratch, &mut touched);

            // Every read, as the block and position it happens at.
            let mut reads = Vec::<(BlockId, u32)>::new();
            for site in graph.use_sites(value.id) {
                if ignored_reads.contains(site) {
                    continue;
                }
                let Some(inst) = graph.inst(relocate(site.inst)) else {
                    continue;
                };
                if dead_phi[inst.id.0 as usize] {
                    continue;
                }
                match &inst.payload {
                    InstPayload::Phi { predecessors } => {
                        if let Some(predecessor) = predecessors.get(site.input_idx) {
                            reads.push((*predecessor, BLOCK_END));
                        }
                    }
                    InstPayload::Op(_) => reads.push((inst.block, inst.ordinal as u32)),
                }
            }
            reads.extend(
                returned
                    .of(value.id)
                    .iter()
                    .map(|block| (*block, BLOCK_END)),
            );

            for (block, position) in reads {
                touch(block, &mut scratch, &mut touched);
                let cell = &mut scratch[block.0 as usize];
                let before_def = block == def_block && position < def_ordinal;
                if before_def {
                    cell.last_use_before_def = Some(
                        cell.last_use_before_def
                            .map_or(position, |last| last.max(position)),
                    );
                } else {
                    cell.last_use = Some(cell.last_use.map_or(position, |last| last.max(position)));
                }
                if position == BLOCK_END {
                    cell.live_out = true;
                }
                if block != def_block || before_def {
                    // Live from the top of this block back to the definition.
                    pending.clear();
                    pending.push(block);
                    while let Some(block) = pending.pop() {
                        touch(block, &mut scratch, &mut touched);
                        let cell = &mut scratch[block.0 as usize];
                        if cell.live_in {
                            continue;
                        }
                        cell.live_in = true;
                        let Some(node) = graph.blocks.get(block.0 as usize) else {
                            continue;
                        };
                        for predecessor in &node.predecessors {
                            touch(*predecessor, &mut scratch, &mut touched);
                            scratch[predecessor.0 as usize].live_out = true;
                            if *predecessor != def_block {
                                pending.push(*predecessor);
                            }
                        }
                    }
                }
            }

            order_touched_blocks(&mut touched, &scratch, stamp);
            for block in &touched {
                let cell = scratch[block.0 as usize];
                if *block == def_block {
                    if cell.live_in
                        && let Some(last) = cell.last_use_before_def
                    {
                        segments.push(LiveSegment {
                            block: *block,
                            start: 0,
                            end: last,
                        });
                    }
                    // A definition holds the object at its own position even
                    // when nothing reads it, so a dead write still cannot
                    // land on a value another instruction is about to read.
                    let floor = if definition.is_some() {
                        Some(def_ordinal + 1)
                    } else {
                        None
                    };
                    let end = if cell.live_out {
                        Some(BLOCK_END)
                    } else {
                        match (cell.last_use, floor) {
                            (Some(last), Some(floor)) => Some(last.max(floor)),
                            (Some(last), None) => Some(last),
                            (None, floor) => floor,
                        }
                    };
                    if let Some(end) = end {
                        segments.push(LiveSegment {
                            block: *block,
                            start: def_ordinal,
                            end,
                        });
                    }
                } else if cell.live_in {
                    let end = if cell.live_out {
                        BLOCK_END
                    } else {
                        cell.last_use.unwrap_or(0)
                    };
                    segments.push(LiveSegment {
                        block: *block,
                        start: 0,
                        end,
                    });
                }
            }
        }
        offsets.push(segments.len() as u32);

        let mut liveness = Self {
            offsets,
            segments,
            content,
            unread_phi: dead_phi,
        };
        for (left, right) in same_content {
            liveness.declare_same_content(*left, *right);
        }
        liveness
    }

    /// Whether this merge is read by nothing, so it merges nothing the text
    /// performs and cannot make two values one object.
    pub fn phi_is_unread(&self, inst: InstId) -> bool {
        self.unread_phi
            .get(inst.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    /// Where `value` is live, by block.
    pub fn segments(&self, value: ValueId) -> &[LiveSegment] {
        let index = value.0 as usize;
        match (self.offsets.get(index), self.offsets.get(index + 1)) {
            (Some(start), Some(end)) => &self.segments[*start as usize..*end as usize],
            _ => &[],
        }
    }

    /// Whether `value` is still needed after `position` in `block`.
    pub fn live_after(&self, value: ValueId, block: BlockId, position: u32) -> bool {
        self.segments(value)
            .iter()
            .any(|segment| segment.contains(block, position))
    }

    /// Whether the two values hold one content, so that both may occupy one
    /// object however their live ranges overlap.
    pub fn same_content(&self, left: ValueId, right: ValueId) -> bool {
        content_find(&self.content, left.0) == content_find(&self.content, right.0)
    }

    /// Whether the two values cannot share an object.
    pub fn interferes(&self, left: ValueId, right: ValueId) -> bool {
        if left == right || self.same_content(left, right) {
            return false;
        }
        let (mut a, mut b) = (
            self.segments(left).iter().peekable(),
            self.segments(right).iter().peekable(),
        );
        while let (Some(x), Some(y)) = (a.peek(), b.peek()) {
            if x.overlaps(**y) {
                return true;
            }
            if (x.block, x.end) <= (y.block, y.end) {
                a.next();
            } else {
                b.next();
            }
        }
        false
    }
}

fn content_find(parent: &[u32], mut value: u32) -> u32 {
    while parent[value as usize] != value {
        value = parent[value as usize];
    }
    value
}

fn content_union(parent: &mut [u32], left: u32, right: u32) {
    let left = content_find(parent, left);
    let right = content_find(parent, right);
    if left != right {
        parent[left.max(right) as usize] = left.min(right);
    }
}

/// The returning blocks each value is handed back from, indexed by value.
struct ReturnedBlocks {
    offsets: Vec<u32>,
    blocks: Vec<BlockId>,
}

impl ReturnedBlocks {
    fn of(&self, value: ValueId) -> &[BlockId] {
        let index = value.0 as usize;
        match (self.offsets.get(index), self.offsets.get(index + 1)) {
            (Some(start), Some(end)) => &self.blocks[*start as usize..*end as usize],
            _ => &[],
        }
    }
}

/// One counting pass over the caller's reads, in `O(values + reads)`.
fn returned_blocks_by_value(
    graph: &SsaGraph,
    live_out: &FunctionLiveOut,
    value_count: usize,
) -> ReturnedBlocks {
    let reads = live_out
        .by_return()
        .filter_map(|(addr, values)| Some((graph.block_id_for_addr(addr)?, values)))
        .flat_map(|(block, values)| values.map(move |value| (value, block)))
        .filter(|(value, _)| (value.0 as usize) < value_count)
        .collect::<Vec<_>>();
    let mut offsets = vec![0u32; value_count + 1];
    for (value, _) in &reads {
        offsets[value.0 as usize + 1] += 1;
    }
    for index in 0..value_count {
        offsets[index + 1] += offsets[index];
    }
    let mut next = offsets.clone();
    let mut blocks = vec![BlockId(0); reads.len()];
    for (value, block) in reads {
        let slot = &mut next[value.0 as usize];
        blocks[*slot as usize] = block;
        *slot += 1;
    }
    ReturnedBlocks { offsets, blocks }
}

/// Merges nothing reads, even through other such merges: a worklist fixpoint in `O(insts + uses)`.
fn unread_phis(graph: &SsaGraph, live_out: &FunctionLiveOut) -> Vec<bool> {
    let mut dead = vec![false; graph.insts.len()];
    let mut readers = (0..graph.values.len() as u32)
        .map(|value| graph.use_sites(ValueId(value)).len())
        .collect::<Vec<_>>();
    let unread_phi = |value: ValueId, readers: &[usize]| {
        let inst = graph.def_inst(value)?;
        let is_phi = matches!(graph.inst(inst)?.payload, InstPayload::Phi { .. });
        (is_phi && readers[value.0 as usize] == 0 && !live_out.contains(value)).then_some(inst)
    };
    let mut pending = graph
        .insts
        .iter()
        .filter_map(|inst| unread_phi(inst.output?, &readers))
        .collect::<Vec<_>>();
    while let Some(inst) = pending.pop() {
        if std::mem::replace(&mut dead[inst.0 as usize], true) {
            continue;
        }
        let Some(inst) = graph.inst(inst) else {
            continue;
        };
        for input in &inst.inputs {
            let count = &mut readers[input.0 as usize];
            *count = count.saturating_sub(1);
            pending.extend(unread_phi(*input, &readers));
        }
    }
    dead
}

/// Order touched blocks by id, by sort (`k log k`) or stamp scan (`blocks`), whichever is cheaper.
fn order_touched_blocks(touched: &mut Vec<BlockId>, scratch: &[BlockScratch], stamp: u32) {
    let count = touched.len();
    if count * (usize::BITS - count.leading_zeros()) as usize <= scratch.len() {
        touched.sort_unstable();
        return;
    }
    touched.clear();
    touched.extend(
        scratch
            .iter()
            .enumerate()
            .filter(|(_, cell)| cell.stamp == stamp)
            .map(|(block, _)| BlockId(block as u32)),
    );
}

/// The live segments of a set of values that share, or are proposed to share,
/// one object.
///
/// Built up by union: two components are asked whether they interfere, then
/// the smaller is absorbed into the larger, so a run of a thousand versions
/// costs a thousand small merges rather than a thousand rescans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentLiveness {
    by_block: BTreeMap<BlockId, Vec<(LiveSegment, ValueId)>>,
    members: usize,
}

impl ComponentLiveness {
    pub fn of(liveness: &ValueLiveness, value: ValueId) -> Self {
        let mut by_block = BTreeMap::<BlockId, Vec<(LiveSegment, ValueId)>>::new();
        for segment in liveness.segments(value) {
            by_block
                .entry(segment.block)
                .or_default()
                .push((*segment, value));
        }
        Self {
            by_block,
            members: 1,
        }
    }

    pub const fn members(&self) -> usize {
        self.members
    }

    /// Whether any value of one component is live where a value of the other
    /// holds the object, the two values not being one content.
    pub fn interferes(&self, other: &Self, liveness: &ValueLiveness) -> bool {
        self.first_interference(other, liveness).is_some()
    }

    /// The first pair of values, one from each component, that are both live
    /// at one point and are not one content; which pair it is names the
    /// reason a union was declined.
    pub fn first_interference(
        &self,
        other: &Self,
        liveness: &ValueLiveness,
    ) -> Option<(ValueId, ValueId)> {
        let (small, large) = if self.by_block.len() <= other.by_block.len() {
            (self, other)
        } else {
            (other, self)
        };
        small.by_block.iter().find_map(|(block, mine)| {
            large.by_block.get(block).and_then(|theirs| {
                mine.iter().find_map(|(segment, value)| {
                    theirs.iter().find_map(|(candidate, member)| {
                        (segment.overlaps(*candidate) && !liveness.same_content(*value, *member))
                            .then_some((*value, *member))
                    })
                })
            })
        })
    }

    /// Take the other component's segments into this one.
    pub fn absorb(&mut self, other: Self) {
        if other.by_block.len() > self.by_block.len() {
            let mine = std::mem::replace(self, other);
            return self.absorb(mine);
        }
        for (block, segments) in other.by_block {
            self.by_block.entry(block).or_default().extend(segments);
        }
        self.members += other.members;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::SSAFunction;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("EAX", 0, 4));
        arch.add_register(RegisterDef::new("RCX", 8, 8));
        arch.add_register(RegisterDef::new("RDX", 16, 8));
        arch.add_register(RegisterDef::new("cond", 32, 1));
        arch.add_register(RegisterDef::new("RIP", 0x288, 8));
        arch
    }

    fn value_named(graph: &SsaGraph, name: &str, version: u32) -> ValueId {
        graph
            .values
            .iter()
            .position(|value| {
                value.var.name().eq_ignore_ascii_case(name) && value.var.version == version
            })
            .map(|index| ValueId(index as u32))
            .unwrap_or_else(|| panic!("no {name}_{version}"))
    }

    fn defined_at(graph: &SsaGraph, addr: u64, op_idx: usize) -> ValueId {
        graph
            .inst_id_for_op_site(addr, op_idx)
            .and_then(|inst| graph.inst(inst))
            .and_then(|inst| inst.output)
            .unwrap_or_else(|| panic!("no definition at {addr:#x}:{op_idx}"))
    }

    fn block_at(graph: &SsaGraph, addr: u64) -> BlockId {
        graph.block_id_for_addr(addr).expect("block")
    }

    /// Whether `value` is live after `position` in `block`, found by walking
    /// forward from that point to any read without crossing the definition.
    fn naive_live_after(graph: &SsaGraph, value: ValueId, block: BlockId, position: u32) -> bool {
        let def = graph.def_inst(value).and_then(|inst| graph.inst(inst));
        if def.is_some_and(|def| def.block == block && def.ordinal as u32 == position) {
            return true;
        }
        // Merges nothing reads, by repeated elimination.
        let mut dead = vec![false; graph.insts.len()];
        loop {
            let before = dead.iter().filter(|dead| **dead).count();
            for inst in &graph.insts {
                if let (InstPayload::Phi { .. }, Some(output)) = (&inst.payload, inst.output)
                    && graph
                        .use_sites(output)
                        .iter()
                        .all(|site| dead[site.inst.0 as usize])
                {
                    dead[inst.id.0 as usize] = true;
                }
            }
            if dead.iter().filter(|dead| **dead).count() == before {
                break;
            }
        }
        let reads_here = |block: BlockId, ordinal: u32| {
            graph.use_sites(value).iter().any(|site| {
                graph.inst(site.inst).is_some_and(|inst| {
                    !dead[inst.id.0 as usize]
                        && match &inst.payload {
                            InstPayload::Phi { predecessors } => {
                                ordinal == BLOCK_END
                                    && predecessors.get(site.input_idx) == Some(&block)
                            }
                            InstPayload::Op(_) => {
                                inst.block == block && inst.ordinal as u32 == ordinal
                            }
                        }
                })
            })
        };
        // Scan a block from `first` to its end; None means the scan crossed
        // the definition, Some(reached) whether a read was met.
        let scan = |block: BlockId, first: u32| -> Option<bool> {
            let node = graph.block(block).expect("block");
            for ordinal in first..node.insts.len() as u32 {
                if reads_here(block, ordinal) {
                    return Some(true);
                }
                if def.is_some_and(|def| def.block == block && def.ordinal as u32 == ordinal) {
                    return None;
                }
            }
            Some(reads_here(block, BLOCK_END))
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = Vec::new();
        match if position == BLOCK_END {
            Some(false)
        } else {
            scan(block, position + 1)
        } {
            Some(true) => return true,
            None => return false,
            Some(false) => pending.extend(
                graph
                    .block(block)
                    .expect("block")
                    .successors
                    .iter()
                    .copied(),
            ),
        }
        while let Some(block) = pending.pop() {
            if !seen.insert(block) {
                continue;
            }
            match scan(block, 0) {
                Some(true) => return true,
                None => continue,
                Some(false) => pending.extend(
                    graph
                        .block(block)
                        .expect("block")
                        .successors
                        .iter()
                        .copied(),
                ),
            }
        }
        false
    }

    fn agrees_with_naive(graph: &SsaGraph, liveness: &ValueLiveness) {
        for value in &graph.values {
            for node in &graph.blocks {
                for position in 0..node.insts.len() as u32 {
                    assert_eq!(
                        liveness.live_after(value.id, node.id, position),
                        naive_live_after(graph, value.id, node.id, position),
                        "{} after {:?}:{position}",
                        value.var.display_name(),
                        node.id
                    );
                }
            }
        }
    }

    fn loop_with_exit_read() -> (SSAFunction, SsaGraph) {
        // entry: RAX = RCX
        // header: RAX = phi(entry RAX, latch RAX); if cond goto exit
        // body:   RDX = RAX; RAX = RAX + 1
        // latch:  RAX = RAX + RCX; goto header
        // exit:   RDX = RAX + 5; return
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(8, 8),
        });
        let mut header = R2ILBlock::new(0x1004, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1010, 8),
            cond: reg(32, 1),
        });
        let mut body = R2ILBlock::new(0x1008, 4);
        body.push(R2ILOp::Copy {
            dst: reg(16, 8),
            src: reg(0, 8),
        });
        body.push(R2ILOp::IntAdd {
            dst: reg(0, 8),
            a: reg(0, 8),
            b: Varnode::constant(1, 8),
        });
        let mut latch = R2ILBlock::new(0x100c, 4);
        latch.push(R2ILOp::IntAdd {
            dst: reg(0, 8),
            a: reg(0, 8),
            b: reg(8, 8),
        });
        latch.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });
        let mut exit = R2ILBlock::new(0x1010, 4);
        exit.push(R2ILOp::IntAdd {
            dst: reg(16, 8),
            a: reg(0, 8),
            b: Varnode::constant(5, 8),
        });
        exit.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let func =
            SSAFunction::from_blocks_with_arch(&[entry, header, body, latch, exit], Some(&arch()))
                .expect("ssa");
        let graph = SsaGraph::from_function(&func);
        (func, graph)
    }

    #[test]
    fn a_loop_carrier_dies_into_its_update_and_is_reborn_at_the_merge() {
        let (_func, graph) = loop_with_exit_read();
        let liveness = ValueLiveness::compute(&graph, &FunctionLiveOut::default());
        let merged = value_named(&graph, "RAX", 2);
        let updated = defined_at(&graph, 0x1008, 1);
        let carried = defined_at(&graph, 0x100c, 0);
        let header = block_at(&graph, 0x1004);
        let body = block_at(&graph, 0x1008);
        let latch = block_at(&graph, 0x100c);
        let exit = block_at(&graph, 0x1010);

        // The merge is read in the body and at the exit, so it leaves the
        // header on both edges and ends at its update in the body.
        assert!(liveness.live_after(merged, header, 0));
        assert!(liveness.live_after(merged, body, 0));
        assert!(!liveness.live_after(merged, body, 1));
        assert!(!liveness.live_after(merged, latch, 0));
        assert!(!liveness.live_after(merged, exit, 0));
        // The update is read only by the latch, and the latch value only by
        // the merge on the back edge.
        assert!(liveness.live_after(updated, body, 1));
        assert!(!liveness.live_after(updated, latch, 0));
        assert!(liveness.live_after(carried, latch, 0));
        assert!(liveness.live_after(carried, latch, 1));
        // Nothing in the chain is needed while the next link holds the
        // register, so the whole carrier is one object.
        assert!(!liveness.interferes(merged, updated));
        assert!(!liveness.interferes(updated, carried));
        assert!(!liveness.interferes(merged, carried));
        agrees_with_naive(&graph, &liveness);
    }

    #[test]
    fn a_source_read_after_its_merge_interferes_with_it() {
        // header: RAX = phi(entry, latch); latch: RDX = RAX_merged (read after
        // the update is computed into another register), RAX = RCX.
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(8, 8),
        });
        let mut header = R2ILBlock::new(0x1004, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::constant(0x100c, 8),
            cond: reg(32, 1),
        });
        let mut latch = R2ILBlock::new(0x1008, 4);
        latch.push(R2ILOp::IntAdd {
            dst: reg(16, 8),
            a: reg(0, 8),
            b: Varnode::constant(1, 8),
        });
        latch.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(16, 8),
        });
        latch.push(R2ILOp::IntAdd {
            dst: reg(8, 8),
            a: reg(16, 8),
            b: reg(8, 8),
        });
        latch.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });
        let mut exit = R2ILBlock::new(0x100c, 4);
        exit.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[entry, header, latch, exit], Some(&arch()))
            .expect("ssa");
        let graph = SsaGraph::from_function(&func);
        let liveness = ValueLiveness::compute(&graph, &FunctionLiveOut::default());
        let merged = value_named(&graph, "RAX", 2);
        let next = defined_at(&graph, 0x1008, 0);
        let written_back = defined_at(&graph, 0x1008, 1);
        let latch = block_at(&graph, 0x1008);
        // RDX_1 is read after RAX_3 = RDX_1 is written and before the back
        // edge, so it is live while RAX_3 holds the register: the two cannot
        // be one object even though one is a copy of the other... except that
        // a copy is the same content, which is exactly the exemption.
        assert!(liveness.live_after(next, latch, 1));
        assert!(liveness.same_content(next, written_back));
        assert!(!liveness.interferes(next, written_back));
        // The merge dies at the first read in the latch.
        assert!(!liveness.live_after(merged, latch, 0));
        agrees_with_naive(&graph, &liveness);
    }

    #[test]
    fn a_returned_value_is_live_to_the_end_of_its_returning_block() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(8, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: reg(16, 8),
            a: reg(8, 8),
            b: Varnode::constant(1, 8),
        });
        block.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch())).expect("ssa");
        let graph = SsaGraph::from_function(&func);
        let rax = crate::CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let live_out = FunctionLiveOut::compute(&func, &graph, &[rax]);
        let liveness = ValueLiveness::compute(&graph, &live_out);
        let returned = defined_at(&graph, 0x1000, 0);
        let scratch = defined_at(&graph, 0x1000, 1);
        let block = block_at(&graph, 0x1000);
        assert!(live_out.contains(returned));
        assert!(liveness.live_after(returned, block, 1));
        assert!(liveness.live_after(returned, block, 2));
        assert!(liveness.live_after(scratch, block, 1));
        assert!(!liveness.live_after(scratch, block, 2));
        // The returned value is live where the scratch register is written, so
        // the two do not share an object.
        assert!(liveness.interferes(returned, scratch));
    }

    #[test]
    fn components_merge_small_into_large_and_keep_every_segment() {
        let (_func, graph) = loop_with_exit_read();
        let liveness = ValueLiveness::compute(&graph, &FunctionLiveOut::default());
        let merged = value_named(&graph, "RAX", 2);
        let updated = defined_at(&graph, 0x1008, 1);
        let copy = defined_at(&graph, 0x1008, 0);
        let mut run = ComponentLiveness::of(&liveness, merged);
        let next = ComponentLiveness::of(&liveness, updated);
        assert!(!run.interferes(&next, &liveness));
        run.absorb(next);
        assert_eq!(run.members(), 2);
        // RDX_1 is a copy of the merge, written in the body while the merge is
        // still read by the update: same content, so no interference; then
        // it is dead, so nothing else interferes with it either.
        let other = ComponentLiveness::of(&liveness, copy);
        assert!(!run.interferes(&other, &liveness));
    }
}
