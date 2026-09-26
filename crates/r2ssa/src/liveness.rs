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
//!
//! Two values live at once may still share an object when they are one
//! content: the narrower one's bits are the wider one's low bits, so the
//! object holding the wider one holds the narrower one too. [`ValueContent`]
//! answers that from the value view -- the one fact of which bits equal which
//! -- and from the places the lifter and the memory facts say hold one
//! content. It is sound because the text never elides a write that changes
//! the bits: a copy is dropped only when it is whole and its two sides are one
//! binding, and an extension or a narrowing keeps its statement.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::{BlockId, InstId, InstPayload, SsaGraph, UseSite, ValueId};
use crate::liveout::FunctionLiveOut;
use crate::machine_context::SourceMachineContext;
use crate::var::{CanonicalStorageId, CanonicalStorageSpace};
use crate::view::{ValueViews, ViewExtension};

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
    /// Which values hold one content.
    content: ValueContent,
    /// Merges nothing reads, directly or through other such merges.
    unread_phi: Vec<bool>,
}

/// Which values hold one content: where the narrower of two values is the
/// wider one's low bits, so one object holds both.
///
/// Each value is its view -- the low `prefix` bits of a root value, and what is
/// above them -- and the roots are joined where something beside the
/// operations says two of them share their low bits: the merges one block
/// makes over one register at several widths, and the values a function is
/// entered with at several widths, where the lifter maps them onto one bit of
/// one carrier; and two reads of the same bytes that the same memory reaches.
/// A join records how many low bits the two share, and a path of joins shares
/// the fewest of its steps', so an answer is never more than the evidence
/// says.
///
/// The lanes are placed by the lifter's lane-to-byte mapping, not by storage
/// offset: on a big-endian register file the lane at a register's own offset
/// is its high end. Where the lifter states no mapping, two storages are
/// joined only when they are the same bytes at the same width. Renaming
/// already reads and writes a register family's lanes as a `SUBPIECE` or
/// `INSERT` of its root at the lane's significance, which the view reads; the
/// joins are for merges and entry values built at several widths.
///
/// `same_content(a, b)` holds when `a` and `b` reach one root and the narrower
/// of the two is the other's low bits: both carry the root's bits at least as
/// far as the narrower's width, or both carry the same prefix of it with the
/// same stated extension above. A lane at a non-zero offset, an extension
/// against the value it extends where their bits differ, and a sign-extended
/// against a zero-extended copy are never one content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueContent {
    /// Per value, its view with the root as a value.
    views: Vec<ContentView>,
    /// Per root, the root it is joined to and how many low bits they share;
    /// a root joined to nothing is its own, sharing every bit.
    links: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentView {
    root: u32,
    prefix: u32,
    extension: ViewExtension,
    width: u32,
}

/// The bit of a carrier a value's least significant bit is, as the lifter
/// maps the value's storage onto its carrier. Two values at one anchor share
/// their low bits, whichever the register file's byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LaneAnchor {
    space: CanonicalStorageSpace,
    carrier_offset: u64,
    carrier_size: u32,
    lsb: u64,
}

/// Where the lifter maps `storage`: its carrier and the bit its low bit sits
/// at. A storage the lifter states no mapping for is anchored to itself alone.
fn lane_anchor(
    storage: CanonicalStorageId,
    lanes: Option<&SourceMachineContext>,
) -> Option<LaneAnchor> {
    if storage.is_unknown() {
        return None;
    }
    if let Some(projection) = lanes.and_then(|context| context.register_projection(storage))
        && let r2il::RegisterProjectionDisposition::Bound { carrier, slice } =
            projection.disposition
    {
        return Some(LaneAnchor {
            space: storage.space,
            carrier_offset: carrier.offset,
            carrier_size: carrier.size,
            lsb: slice.lsb_bit_offset,
        });
    }
    Some(LaneAnchor {
        space: storage.space,
        carrier_offset: storage.offset,
        carrier_size: storage.size,
        lsb: 0,
    })
}

impl ValueContent {
    /// The content of every value of `graph`: its view, with the merges and
    /// entry values the lifter maps onto one carrier bit joined.
    ///
    /// `O(V + E)` for the view and `O(V log V)` to group the lanes.
    pub fn of(graph: &SsaGraph, lanes: Option<&SourceMachineContext>) -> Self {
        let views = ValueViews::of_graph(graph);
        let width = |var: &crate::var::SSAVar| var.size.saturating_mul(8);
        let mut content = Self {
            views: graph
                .values
                .iter()
                .map(|value| {
                    let own = ContentView {
                        root: value.id.0,
                        prefix: width(&value.var),
                        extension: ViewExtension::Exact,
                        width: width(&value.var),
                    };
                    views
                        .derived_view(&value.var)
                        .and_then(|view| {
                            Some(ContentView {
                                root: graph.value_id_for_var(&view.root)?.0,
                                prefix: view.prefix_bits,
                                extension: view.extension,
                                width: own.width,
                            })
                        })
                        .unwrap_or(own)
                })
                .collect(),
            links: (0..graph.values.len() as u32)
                .map(|value| (value, u32::MAX))
                .collect(),
        };
        let anchor_of = |value: ValueId| {
            graph
                .value(value)
                .and_then(|value| value.canonical_storage)
                .and_then(|storage| lane_anchor(storage, lanes))
        };
        // The merges one block makes over one carrier bit are that lane's one
        // state there, at several widths; the values a function is entered
        // with are its state at entry.
        let mut lanes_at = BTreeMap::<(Option<BlockId>, LaneAnchor), Vec<ValueId>>::new();
        for inst in &graph.insts {
            if let (InstPayload::Phi { .. }, Some(output)) = (&inst.payload, inst.output)
                && let Some(anchor) = anchor_of(output)
            {
                lanes_at
                    .entry((Some(inst.block), anchor))
                    .or_default()
                    .push(output);
            }
        }
        for value in &graph.values {
            if graph.def_inst(value.id).is_some() || value.var.is_const() {
                continue;
            }
            if let Some(anchor) = anchor_of(value.id) {
                lanes_at.entry((None, anchor)).or_default().push(value.id);
            }
        }
        for members in lanes_at.values() {
            // Each is the widest one's low bits.
            let Some(widest) = members
                .iter()
                .copied()
                .max_by_key(|member| (content.width(*member), std::cmp::Reverse(member.0)))
            else {
                continue;
            };
            for member in members {
                if *member != widest {
                    let shared = content.width(*member).min(content.width(widest));
                    content.join(widest, *member, shared);
                }
            }
        }
        content.flatten();
        content
    }

    /// State that each pair's two values hold one content at their full width,
    /// on evidence the graph does not carry: two reads of the same bytes that
    /// the same memory reaches.
    pub fn declare_same_content(&mut self, pairs: &[(ValueId, ValueId)]) {
        for (left, right) in pairs {
            let shared = self.width(*left).min(self.width(*right));
            self.join(*left, *right, shared);
        }
        self.flatten();
    }

    /// Whether the two values hold one content, so that both may occupy one
    /// object however their live ranges overlap.
    pub fn same_content(&self, left: ValueId, right: ValueId) -> bool {
        if left == right {
            return true;
        }
        let (
            Some((left_root, left_prefix, left_extension)),
            Some((right_root, right_prefix, right_extension)),
        ) = (self.anchor(left), self.anchor(right))
        else {
            return false;
        };
        if left_root != right_root {
            return false;
        }
        let narrower = self.width(left).min(self.width(right));
        left_prefix.min(right_prefix) >= narrower
            || (left_prefix == right_prefix
                && left_extension == right_extension
                && matches!(left_extension, ViewExtension::Zero | ViewExtension::Sign))
    }

    fn width(&self, value: ValueId) -> u32 {
        self.views
            .get(value.0 as usize)
            .map_or(0, |view| view.width)
    }

    /// A value's root after the joins, how many of its low bits are that
    /// root's, and what is above them. Joins are flat once built, so this is
    /// one step.
    fn anchor(&self, value: ValueId) -> Option<(u32, u32, ViewExtension)> {
        let view = self.views.get(value.0 as usize)?;
        let (mut root, mut shared) = (view.root, u32::MAX);
        while let Some(&(parent, bits)) = self.links.get(root as usize)
            && parent != root
        {
            shared = shared.min(bits);
            root = parent;
        }
        let prefix = view.prefix.min(shared);
        // A join that shares fewer bits than the view leaves the rest of the
        // view's prefix unstated relative to the joined root.
        let extension = if prefix < view.prefix {
            ViewExtension::Unknown
        } else {
            view.extension
        };
        Some((root, prefix, extension))
    }

    /// The root `node` is joined to, and the fewest low bits a step on the way
    /// shares; halves the path as it goes.
    fn find_mut(&mut self, mut node: u32) -> (u32, u32) {
        let mut shared = u32::MAX;
        loop {
            let (parent, bits) = self.links[node as usize];
            if parent == node {
                return (node, shared);
            }
            let (grandparent, above) = self.links[parent as usize];
            let step = if grandparent == parent {
                bits
            } else {
                bits.min(above)
            };
            self.links[node as usize] = (grandparent, step);
            shared = shared.min(step);
            node = grandparent;
        }
    }

    /// Record that the low `shared` bits of two values are equal.
    fn join(&mut self, left: ValueId, right: ValueId, shared: u32) {
        let (Some(left), Some(right)) = (
            self.views.get(left.0 as usize).copied(),
            self.views.get(right.0 as usize).copied(),
        ) else {
            return;
        };
        let (left_root, left_bits) = self.find_mut(left.root);
        let (right_root, right_bits) = self.find_mut(right.root);
        if left_root == right_root {
            return;
        }
        let bits = shared
            .min(left.prefix.min(left_bits))
            .min(right.prefix.min(right_bits));
        if bits == 0 {
            return;
        }
        // The wider root stays the root. A lane joined under its register
        // leaves every other lane's path at its own width; the other way
        // round, every lane would share only the narrowest one's bits.
        let rank = |root: u32| (std::cmp::Reverse(self.width(ValueId(root))), root);
        let (parent, child) = if rank(left_root) <= rank(right_root) {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        self.links[child as usize] = (parent, bits);
    }

    /// Point every root straight at the root it is joined to.
    fn flatten(&mut self) {
        for node in 0..self.links.len() as u32 {
            let (root, shared) = self.find_mut(node);
            if root != node {
                self.links[node as usize] = (root, shared);
            }
        }
    }
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
    pub fn compute(graph: &SsaGraph, live_out: &FunctionLiveOut, content: ValueContent) -> Self {
        Self::compute_with_relocations(graph, live_out, &BTreeMap::new(), content, &BTreeSet::new())
    }

    /// Which values hold one content, as this liveness judges it.
    pub const fn content(&self) -> &ValueContent {
        &self.content
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
        content: ValueContent,
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

        Self {
            offsets,
            segments,
            content,
            unread_phi: dead_phi,
        }
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
        self.content.same_content(left, right)
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
/// costs a thousand small merges rather than a thousand rescans. Within a
/// block the segments are kept in the order they start, so the question is
/// one sweep over the two components' segments in that block rather than every
/// pair of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentLiveness {
    /// Per block, the segments sorted by where they start.
    by_block: BTreeMap<BlockId, Vec<(LiveSegment, ValueId)>>,
    members: usize,
    segments: usize,
}

impl ComponentLiveness {
    pub fn of(liveness: &ValueLiveness, value: ValueId) -> Self {
        let mut by_block = BTreeMap::<BlockId, Vec<(LiveSegment, ValueId)>>::new();
        let segments = liveness.segments(value);
        for segment in segments {
            by_block
                .entry(segment.block)
                .or_default()
                .push((*segment, value));
        }
        for block in by_block.values_mut() {
            block.sort_by_key(|(segment, _)| segment.start);
        }
        Self {
            by_block,
            members: 1,
            segments: segments.len(),
        }
    }

    pub const fn members(&self) -> usize {
        self.members
    }

    /// How many live segments the component holds.
    pub const fn segment_count(&self) -> usize {
        self.segments
    }

    /// Whether any value of one component is live where a value of the other
    /// holds the object, the two values not being one content.
    pub fn interferes(&self, other: &Self, liveness: &ValueLiveness) -> bool {
        self.first_interference(other, liveness).is_some()
    }

    /// The first pair of values, one from each component, that are both live
    /// at one point and are not one content; which pair it is names the
    /// reason a union was declined.
    ///
    /// For each block both components are live in, one sweep in start order:
    /// a segment is compared only with the other component's segments that
    /// began no later and have not ended where it begins, which are exactly
    /// the ones it can overlap from that side. `O(m + n)` per shared block
    /// plus the overlapping pairs, where the nested scan it replaces was
    /// `O(m * n)`.
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
            large
                .by_block
                .get(block)
                .and_then(|theirs| first_overlap(mine, theirs, liveness))
        })
    }

    /// Take the other component's segments into this one.
    pub fn absorb(&mut self, other: Self) {
        if other.by_block.len() > self.by_block.len() {
            let mine = std::mem::replace(self, other);
            return self.absorb(mine);
        }
        for (block, segments) in other.by_block {
            let held = self.by_block.entry(block).or_default();
            held.extend(segments);
            // Two sorted runs: the stable sort merges them in linear time.
            held.sort_by_key(|(segment, _)| segment.start);
        }
        self.members += other.members;
        self.segments += other.segments;
    }
}

/// The first overlapping pair of one block's segments, one from each side,
/// that are not one content. Both sides are sorted by start.
fn first_overlap(
    mine: &[(LiveSegment, ValueId)],
    theirs: &[(LiveSegment, ValueId)],
    liveness: &ValueLiveness,
) -> Option<(ValueId, ValueId)> {
    let (mut next_mine, mut next_theirs) = (0, 0);
    let mut open_mine = Vec::<(LiveSegment, ValueId)>::new();
    let mut open_theirs = Vec::<(LiveSegment, ValueId)>::new();
    loop {
        let take_mine = match (mine.get(next_mine), theirs.get(next_theirs)) {
            (Some((left, _)), Some((right, _))) => left.start <= right.start,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let (segment, value, open_other, open_same) = if take_mine {
            let (segment, value) = mine[next_mine];
            next_mine += 1;
            (segment, value, &mut open_theirs, &mut open_mine)
        } else {
            let (segment, value) = theirs[next_theirs];
            next_theirs += 1;
            (segment, value, &mut open_mine, &mut open_theirs)
        };
        // What ended where this begins overlaps nothing that begins later.
        open_other.retain(|(open, _)| open.end > segment.start);
        for (open, member) in open_other.iter() {
            if segment.overlaps(*open) && !liveness.same_content(value, *member) {
                return Some(if take_mine {
                    (value, *member)
                } else {
                    (*member, value)
                });
            }
        }
        open_same.push((segment, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::SSAFunction;
    use r2il::{
        ArchSpec, R2ILBlock, R2ILOp, RegisterDef, RegisterProjection,
        RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
    };

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
        let liveness = ValueLiveness::compute(
            &graph,
            &FunctionLiveOut::default(),
            ValueContent::of(&graph, None),
        );
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
        let liveness = ValueLiveness::compute(
            &graph,
            &FunctionLiveOut::default(),
            ValueContent::of(&graph, None),
        );
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
        let liveness = ValueLiveness::compute(&graph, &live_out, ValueContent::of(&graph, None));
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
        let liveness = ValueLiveness::compute(
            &graph,
            &FunctionLiveOut::default(),
            ValueContent::of(&graph, None),
        );
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

    #[test]
    fn a_value_is_one_content_only_with_the_values_whose_low_bits_it_is() {
        // t = RCX; signed = SEXT(t); high = SUBPIECE(signed, 8);
        // zero = ZEXT(t); low = SUBPIECE(zero, 0).
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSExt {
            dst: Varnode::unique(0x100, 16),
            src: reg(8, 8),
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(16, 8),
            src: Varnode::unique(0x100, 16),
            offset: 8,
        });
        block.push(R2ILOp::IntZExt {
            dst: Varnode::unique(0x200, 16),
            src: reg(8, 8),
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(0, 8),
            src: Varnode::unique(0x200, 16),
            offset: 0,
        });
        block.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch())).expect("ssa");
        let graph = SsaGraph::from_function(&func);
        let content = ValueContent::of(&graph, None);
        let t = value_named(&graph, "RCX", 0);
        let signed = defined_at(&graph, 0x1000, 0);
        let high = defined_at(&graph, 0x1000, 1);
        let zero = defined_at(&graph, 0x1000, 2);
        let low = defined_at(&graph, 0x1000, 3);
        // The sign word a division extends into is not the dividend: one
        // object cannot hold both while both are needed.
        assert!(!content.same_content(t, high));
        assert!(!content.same_content(signed, high));
        // The two extensions agree only below the value's width.
        assert!(!content.same_content(signed, zero));
        // The value is the low bits of each extension, and the low lane of its
        // zero extension is the value itself.
        assert!(content.same_content(t, signed));
        assert!(content.same_content(t, zero));
        assert!(content.same_content(t, low));
        assert!(content.same_content(zero, low));
        let liveness = ValueLiveness::compute(&graph, &FunctionLiveOut::default(), content);
        assert!(!liveness.same_content(t, high));
    }

    #[test]
    fn a_register_lane_is_one_content_with_its_root_where_the_lifter_puts_its_low_bits() {
        // A big-endian register file: `w0`, the low word of `r0`, is its
        // higher-addressed half, and `hw0` at `r0`'s own offset is its high
        // word. Both are read on entry.
        let storage = |offset, size| RegisterStorage { offset, size };
        let lane = |written: RegisterStorage, lsb_bit_offset, size_bits| RegisterProjection {
            written,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: storage(0, 8),
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset,
                    size_bits,
                },
            },
        };
        let mut arch = ArchSpec::new("big-endian-lanes");
        arch.addr_size = 8;
        arch.set_instruction_endianness(r2il::Endianness::Big);
        arch.set_memory_endianness(r2il::Endianness::Big);
        arch.add_register(RegisterDef::new("r0", 0, 8));
        arch.add_register(RegisterDef::new("hw0", 0, 4));
        arch.add_register(RegisterDef::new("w0", 4, 4));
        arch.add_register(RegisterDef::new("pc", 0x100, 8));
        arch.register_projections = vec![
            lane(storage(0, 4), 32, 32),
            lane(storage(0, 8), 0, 64),
            lane(storage(4, 4), 0, 32),
        ];
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x18, 4),
            src: Varnode::new(SpaceId::Register, 0, 4),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x20, 4),
            src: Varnode::new(SpaceId::Register, 4, 4),
        });
        block.push(R2ILOp::Return {
            target: reg(0x100, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        let graph = SsaGraph::from_function(&func);
        let content = ValueContent::of(&graph, None);
        let whole = value_named(&graph, "r0", 0);
        let copied = |offset| {
            graph
                .values
                .iter()
                .find(|value| {
                    value.var.size == 4
                        && value.canonical_storage.is_some_and(|storage| {
                            storage.space == crate::CanonicalStorageSpace::Unique
                                && storage.offset == offset
                        })
                })
                .map(|value| value.id)
                .expect("copied lane")
        };
        let (high, low) = (copied(0x18), copied(0x20));
        assert!(content.same_content(whole, low), "w0 is r0's low word");
        assert!(
            !content.same_content(whole, high),
            "hw0 shares r0's offset, not its low bits"
        );
        assert!(!content.same_content(high, low));
    }

    #[test]
    fn merged_lanes_are_joined_where_the_lifter_puts_their_low_bits() {
        // Values a function is entered with at three widths of one register,
        // built as separate variables (renaming would have made them lanes of
        // the root). On this big-endian file the word at the register's own
        // offset is its high half and the word four bytes in its low half.
        let storage = |offset, size| crate::CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset,
            size,
        };
        let entries = [("r0", 0, 8), ("hw0", 0, 4), ("w0", 4, 4)]
            .map(|(name, offset, size)| (crate::SSAVar::new(name, 0, size), storage(offset, size)));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let mut func = SSAFunction::from_blocks_raw_no_arch(&[block]).expect("ssa");
        func.get_block_mut(0x1000).expect("block").ops = entries
            .iter()
            .enumerate()
            .map(|(index, (entry, _))| crate::op::SSAOp::Copy {
                dst: crate::SSAVar::new(format!("tmp:{index}"), 1, entry.size),
                src: entry.clone(),
            })
            .collect();
        let mut graph = SsaGraph::from_function(&func);
        for value in &mut graph.values {
            if let Some((_, at)) = entries.iter().find(|(entry, _)| *entry == value.var) {
                value.canonical_storage = Some(*at);
            }
        }
        let lane = |written: RegisterStorage, lsb_bit_offset, size_bits| RegisterProjection {
            written,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: RegisterStorage { offset: 0, size: 8 },
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset,
                    size_bits,
                },
            },
        };
        let mut arch = ArchSpec::new("big-endian-lanes");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("r0", 0, 8));
        arch.add_register(RegisterDef::new("hw0", 0, 4));
        arch.add_register(RegisterDef::new("w0", 4, 4));
        arch.register_projections = vec![
            lane(RegisterStorage { offset: 0, size: 4 }, 32, 32),
            lane(RegisterStorage { offset: 0, size: 8 }, 0, 64),
            lane(RegisterStorage { offset: 4, size: 4 }, 0, 32),
        ];
        let context = crate::SourceMachineContext::from_blocks(&[], Some(&arch));
        let content = ValueContent::of(&graph, Some(&context));
        let [whole, high, low] = ["r0", "hw0", "w0"].map(|name| value_named(&graph, name, 0));
        assert!(content.same_content(whole, low), "w0 is r0's low word");
        assert!(
            !content.same_content(whole, high),
            "hw0 shares r0's offset, not its low bits"
        );
        assert!(!content.same_content(high, low));
        // Where the lifter states no mapping, nothing is joined by offset.
        let unmapped = ValueContent::of(&graph, None);
        assert!(!unmapped.same_content(whole, high));
        assert!(!unmapped.same_content(whole, low));
    }

    #[test]
    fn the_sweep_finds_an_interference_exactly_where_a_pair_interferes() {
        let (_func, graph) = loop_with_exit_read();
        let liveness = ValueLiveness::compute(
            &graph,
            &FunctionLiveOut::default(),
            ValueContent::of(&graph, None),
        );
        let values = graph
            .values
            .iter()
            .map(|value| value.id)
            .collect::<Vec<_>>();
        for left in &values {
            for right in &values {
                let one = ComponentLiveness::of(&liveness, *left);
                let other = ComponentLiveness::of(&liveness, *right);
                assert_eq!(
                    one.interferes(&other, &liveness),
                    left != right && liveness.interferes(*left, *right),
                    "{left:?} against {right:?}"
                );
            }
        }
        // A component of several values interferes with a value exactly when
        // one of its members does.
        for (index, first) in values.iter().enumerate() {
            for second in &values[index + 1..] {
                if liveness.interferes(*first, *second) {
                    continue;
                }
                let mut run = ComponentLiveness::of(&liveness, *first);
                run.absorb(ComponentLiveness::of(&liveness, *second));
                for other in &values {
                    if other == first || other == second {
                        continue;
                    }
                    assert_eq!(
                        run.interferes(&ComponentLiveness::of(&liveness, *other), &liveness),
                        liveness.interferes(*first, *other) || liveness.interferes(*second, *other),
                        "{first:?}+{second:?} against {other:?}"
                    );
                }
            }
        }
    }
}
