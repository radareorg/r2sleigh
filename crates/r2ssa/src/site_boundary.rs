//! What the code after a call does with its callee's result registers: a backward byte liveness
//! over the caller's blocks, solved once per body (doc/adr-call-boundary.md, `SiteBoundary`).

use r2il::eval::independence::{leaves_zero, reads_of};
use r2il::{Endianness, R2ILBlock, R2ILOp, SpaceId, Varnode};
use r2source::{
    CanonicalStorageId, SourceCallerLanes, SourceClosedResult, SourceConventionSlots,
    SourceFunctionInterface, SourceReadLanes, SourceResultCause,
};

/// One bit per byte of a result register; a register past 128 bytes keeps its last bit for the rest.
type Bytes = u128;

/// Bytes of one register, one bit each from its lowest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteMask(pub u128);

impl ByteMask {
    /// One past the highest byte, where the bytes run from byte 0 without a gap.
    pub const fn low_run(self) -> Option<u32> {
        let run = self.0.trailing_ones();
        match run > 0 && (run == 128 || self.0 >> run == 0) {
            true => Some(run),
            false => None,
        }
    }
}

/// A result lane: 0 the integer register, 1 the float one, 2 the second integer one, then the rest
/// of the return set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(pub u8);

impl LaneId {
    pub const INTEGER: Self = Self(0);
    pub const FLOAT: Self = Self(1);
    pub const SECOND: Self = Self(2);
}

/// A caller's block as the walk that lifted it holds it: the lift is all this reads of it.
pub trait Lifted {
    fn lifted(&self) -> &R2ILBlock;
}

impl Lifted for R2ILBlock {
    fn lifted(&self) -> &R2ILBlock {
        self
    }
}

/// The lanes the convention types: the integer register, the float one, the second integer one.
pub const TYPED: usize = 3;
/// The return set past the typed lanes: x86-64 states xmm1, st0 and st1, AArch64 q1 to q3.
pub const OTHERS: usize = 4;
pub const LANES: usize = r2source::RESULT_LANES;
const _: () = assert!(TYPED + OTHERS == LANES);

/// The result registers of a convention: the integer, float and second integer ones, each absent
/// where it names none, and the rest of its return set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResultLanes {
    pub integer: Option<CanonicalStorageId>,
    pub float: Option<CanonicalStorageId>,
    pub second: Option<CanonicalStorageId>,
    pub others: [Option<CanonicalStorageId>; OTHERS],
}

impl ResultLanes {
    /// The result registers `slots` names, and each of `results` (the convention's return set) that
    /// overlaps none of them, past the first `OTHERS`, which no convention graded here has.
    pub fn of(slots: &SourceConventionSlots, results: &[CanonicalStorageId]) -> Self {
        let mut lanes = Self {
            integer: slots.result_slot(),
            float: slots.float_result_slot(),
            second: slots.second_result_slot(),
            ..Self::default()
        };
        let mut others = Vec::new();
        for storage in results {
            let typed = [lanes.integer, lanes.float, lanes.second];
            let taken = typed.iter().chain(&others).flatten();
            if !taken
                .clone()
                .any(|held: &CanonicalStorageId| overlap(*held, *storage))
            {
                others.push(Some(*storage));
            }
        }
        lanes.others = std::array::from_fn(|at| others.get(at).copied().flatten());
        lanes
    }

    /// The register each lane tracks, none where there is no such lane.
    pub fn slots(&self) -> [Option<CanonicalStorageId>; LANES] {
        let typed = [self.integer, self.float, self.second];
        std::array::from_fn(|at| match at {
            0..TYPED => typed[at],
            _ => self.others[at - TYPED],
        })
    }
}

/// The bytes of the result registers a call to a callee nothing is known of may take: the registers
/// the convention passes arguments in, and the variadic count a callee that is variadic reads.
pub fn unknown_call_takes(lanes: ResultLanes, slots: &SourceConventionSlots) -> LaneBytes {
    let counted = slots.variadic_count_register();
    LaneBytes::covered_by(
        lanes,
        &[argument_registers(slots), counted.into_iter().collect()].concat(),
    )
}

/// The bytes of the result registers a body entered with its arguments hands to the calls it makes.
pub fn argument_takes(lanes: ResultLanes, slots: &SourceConventionSlots) -> LaneBytes {
    LaneBytes::covered_by(lanes, &argument_registers(slots))
}

pub fn argument_registers(slots: &SourceConventionSlots) -> Vec<CanonicalStorageId> {
    [slots.argument_slots(), slots.float_argument_slots()].concat()
}

/// What becomes of the bytes of one result register after a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneFate {
    /// No path reads them, hands them back or leaves them: overwritten, or the path ends first.
    Dead,
    /// Some path reads these bytes, the lowest among them, before any call that may leave them.
    Read(ByteMask),
    /// No path reads or loses them; some returns with these bytes in place.
    Returned(ByteMask),
    /// Some path leaves them where the walk did not follow, a call may take them, a tail transfer
    /// hands them on, or a read misses the lowest byte.
    Unknown,
}

/// What one call site states of its callee's boundary: evidence only, never arity proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBoundary {
    /// Bytes of each argument register (integer, then float, in convention order) the call's own
    /// block writes before it.
    pub written: Box<[ByteMask]>,
    /// The fate of each result lane after the call, by `LaneId`; none where the convention names no
    /// such register.
    pub fates: [Option<LaneFate>; LANES],
}

impl SiteBoundary {
    fn unknown(lanes: ResultLanes, written: Box<[ByteMask]>) -> Self {
        Self {
            written,
            fates: lanes.slots().map(|slot| slot.map(|_| LaneFate::Unknown)),
        }
    }

    /// The fate of `lane`, none where the convention names no such register.
    pub fn fate(&self, lane: LaneId) -> Option<LaneFate> {
        self.fates.get(usize::from(lane.0)).copied().flatten()
    }
}

/// Bytes of the result registers, one bit per byte of each: integer, float, second integer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaneBytes([Bytes; LANES]);

impl LaneBytes {
    /// Every byte of every result register: what a callee nothing is known of may write.
    pub const EVERYTHING: Self = Self([Bytes::MAX; LANES]);

    /// The bytes of the result registers that `slots` cover.
    pub fn covered_by(lanes: ResultLanes, slots: &[CanonicalStorageId]) -> Self {
        let mut covered = Self::default();
        for (at, lane) in Lanes::of(lanes).0.iter().enumerate() {
            let Some(lane) = lane else { continue };
            for slot in slots {
                covered.0[at] |= lane.bytes_of(*slot);
            }
        }
        covered
    }

    /// Whether any byte of lane `lane` is among these.
    pub fn touches(self, lane: usize) -> bool {
        self.0.get(lane).is_some_and(|bytes| *bytes != 0)
    }

    /// These bytes and `other`'s.
    #[must_use]
    pub fn and(mut self, other: Self) -> Self {
        for lane in 0..LANES {
            self.0[lane] |= other.0[lane];
        }
        self
    }
}

/// What a call leaves of the result registers it overwrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrites {
    /// Nothing is known of the callee: bytes live before it are live after it.
    Nothing,
    /// The callee overwrites these bytes on every path to its return.
    Bytes(LaneBytes),
    /// The convention clobbers every result register: a read after the call is the callee's.
    All,
}

/// What one call does to the result registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallEffect {
    /// The bytes the callee may take as arguments or forward. A byte it may take stays open: not
    /// dead, and no evidence that the caller reads the result.
    pub takes: LaneBytes,
    /// Bytes it takes besides, unless its count register holds nought where the call runs.
    pub counted: Option<Counted>,
    pub overwrites: Overwrites,
}

/// The vector registers a variadic callee takes by the count its caller states in `register`
/// (System V psABI 3.5.7: `%al` bounds the vector registers used): none, where it holds nought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counted {
    pub register: CanonicalStorageId,
    pub takes: LaneBytes,
    /// Where the callee is declared with fixed arguments: the bytes it takes besides where the call's
    /// block states a count, as a compiler does for a callee its header declares variadic.
    pub stated: Option<LaneBytes>,
}

/// What a call's own block states of the variadic count before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    /// No write of the count register since the block's start or the last control operation.
    Unstated,
    /// One instruction leaves it nought.
    Nought,
    /// Any other write.
    Other,
}

/// What the call at one operation of a body does to the result registers.
pub trait CallEffects {
    fn at(&self, block: usize, op: usize) -> CallEffect;
}

/// Calls that take `takes` and overwrite nothing known.
pub struct TakeOnly(pub LaneBytes);

impl CallEffects for TakeOnly {
    fn at(&self, _block: usize, _op: usize) -> CallEffect {
        CallEffect {
            takes: self.0,
            counted: None,
            overwrites: Overwrites::Nothing,
        }
    }
}

/// What a body does with the result registers it is entered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySummary {
    /// The bytes some path reads, forwards in a tail transfer or loses before writing them.
    pub takes: LaneBytes,
    /// The bytes every path to a return overwrites.
    pub overwrites: LaneBytes,
}

/// The bytes of the lanes, each tracked at the slot its register sits in.
#[derive(Clone, Copy)]
struct Lanes([Option<Lane>; LANES]);

#[derive(Clone, Copy)]
struct Lane {
    slot: CanonicalStorageId,
    all: Bytes,
}

impl Lanes {
    fn of(lanes: ResultLanes) -> Self {
        Self(lanes.slots().map(|slot| slot.map(Lane::new)))
    }

    fn all(&self, lane: usize) -> Bytes {
        self.0[lane].map_or(0, |lane| lane.all)
    }

    /// Every byte of each lane.
    fn every(&self) -> [Bytes; LANES] {
        std::array::from_fn(|lane| self.all(lane))
    }

    /// The bytes of each lane `varnode` touches; a storage outside the register file touches none.
    fn bytes_in(&self, varnode: &Varnode) -> [Bytes; LANES] {
        if varnode.space != SpaceId::Register {
            return [0; LANES];
        }
        let storage = CanonicalStorageId::from_varnode(varnode);
        std::array::from_fn(|lane| self.0[lane].map_or(0, |lane| lane.bytes_of(storage)))
    }
}

impl Lane {
    fn new(slot: CanonicalStorageId) -> Self {
        Self {
            slot,
            all: span(0, u64::from(slot.size)),
        }
    }

    fn bytes_of(&self, storage: CanonicalStorageId) -> Bytes {
        if storage.space != self.slot.space {
            return 0;
        }
        let start = self.slot.offset;
        let end = start.saturating_add(u64::from(self.slot.size));
        let from = storage.offset.max(start);
        let to = (storage.offset.saturating_add(u64::from(storage.size))).min(end);
        match from < to {
            true => span(from - start, to - start),
            false => 0,
        }
    }
}

/// `plane` and `bytes` together.
fn merge(plane: &mut [Bytes; LANES], bytes: [Bytes; LANES]) {
    for (held, more) in plane.iter_mut().zip(bytes) {
        *held |= more;
    }
}

/// Bits `from..to`; a register past 128 bytes keeps its last bit for the rest.
fn span(from: u64, to: u64) -> Bytes {
    let (from, to) = (from.min(127), to.min(128));
    (from..to).fold(0, |mask, byte| mask | 1 << byte)
}

/// The bytes of each result register some path from a point may still hold as a call left them, by
/// what the path does with them.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Live {
    /// Read by an instruction, though a later call may have overwritten them first.
    read: [Bytes; LANES],
    /// Handed back by a return.
    returned: [Bytes; LANES],
    /// Handed on by a tail transfer to code the body does not hold.
    forwarded: [Bytes; LANES],
    /// Lost: past a block the walk could not follow, or taken by a call that may read them.
    open: [Bytes; LANES],
}

impl Live {
    fn join(&mut self, other: &Self) {
        for lane in 0..LANES {
            self.read[lane] |= other.read[lane];
            self.returned[lane] |= other.returned[lane];
            self.forwarded[lane] |= other.forwarded[lane];
            self.open[lane] |= other.open[lane];
        }
    }

    fn kill_all(&mut self, bytes: [Bytes; LANES]) {
        for plane in [
            &mut self.read,
            &mut self.returned,
            &mut self.forwarded,
            &mut self.open,
        ] {
            for (held, gone) in plane.iter_mut().zip(bytes) {
                *held &= !gone;
            }
        }
    }

    /// A read of the lowest byte before any call that may leave it is the call's value (`or edx,
    /// esi` after `sete dl` is not); dead only where nothing reads, loses, returns or hands it on.
    fn fate(&self, lane: usize) -> LaneFate {
        if self.read[lane] & 1 != 0 {
            LaneFate::Read(ByteMask(self.read[lane]))
        } else if self.read[lane] | self.open[lane] | self.forwarded[lane] != 0 {
            LaneFate::Unknown
        } else if self.returned[lane] != 0 {
            LaneFate::Returned(ByteMask(self.returned[lane]))
        } else {
            LaneFate::Dead
        }
    }
}

/// Where control goes between a caller's lifted blocks, as the walk that lifted them stated it.
pub struct CallerFlow<'a, B> {
    blocks: &'a [B],
    /// Each block's address and index, ascending.
    starts: Vec<(u64, usize)>,
    successors: Edges,
    predecessors: Edges,
    /// Blocks that leave the body: by a branch to code it does not hold, or by running on past the
    /// last operation.
    leaves: Vec<bool>,
    /// Blocks whose end the walk could not follow.
    open: Vec<bool>,
    /// Blocks holding control flow other than one terminator at their end: no write there kills.
    irregular: Vec<bool>,
    /// What each operation of each block may do, where the block's first operation is `first[block]`.
    modes: Vec<Mode>,
    first: Vec<u32>,
}

/// How an operation takes part in the pass.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Mode {
    /// Its write may not happen: it belongs to an instruction that branches within itself.
    weak: bool,
    /// It changes nothing the program keeps (a multi-byte `nop` forms an address and drops it), so
    /// what it reads is no read.
    inert: bool,
    /// Its instruction cancels a register against itself (`sbb edx, edx`), so no operation of it
    /// reads a value of a register: only flags, from the register's bits.
    blind: bool,
    /// The inputs of the operation no effect of its instruction depends on (`r2il::eval::independence`).
    ignored: u32,
}

/// The mode of each operation of `block`: whole instructions are weak, inert or blind as their
/// operations say; one the lift stamped with no instruction is a run alone, its write uncertain.
fn modes_of(block: &R2ILBlock, irregular: bool, endian: Endianness) -> Vec<Mode> {
    let mut modes = vec![
        Mode {
            weak: irregular,
            ..Mode::default()
        };
        block.ops.len()
    ];
    let mut run = 0;
    while run < block.ops.len() {
        let Some(instruction) = block.instruction_of(run) else {
            modes[run].weak = true;
            modes[run].ignored = reads_of(&block.ops[run..=run], false, endian).ignored[0];
            run += 1;
            continue;
        };
        let mut end = run + 1;
        while end < block.ops.len() && block.instruction_of(end) == Some(instruction) {
            end += 1;
        }
        let ops = &block.ops[run..end];
        let inert = (ops.iter()).all(|op| !op.is_control_flow() && op.writes_only_temporaries());
        let weak = ops.iter().any(R2ILOp::is_local_branch);
        let reads = reads_of(ops, true, endian);
        for (mode, ignored) in modes[run..end].iter_mut().zip(reads.ignored) {
            mode.weak |= weak;
            mode.inert |= inert;
            mode.blind |= reads.cancels_register;
            mode.ignored = ignored;
        }
        run = end;
    }
    modes
}

/// Block indices by block, flat.
struct Edges {
    starts: Vec<u32>,
    items: Vec<u32>,
}

impl Edges {
    fn of(blocks: usize, mut pairs: Vec<(u32, u32)>) -> Self {
        pairs.sort_unstable();
        pairs.dedup();
        let mut starts = vec![0u32; blocks + 1];
        for (from, _) in &pairs {
            starts[*from as usize + 1] += 1;
        }
        for at in 0..blocks {
            starts[at + 1] += starts[at];
        }
        let items = pairs.into_iter().map(|(_, to)| to).collect();
        Self { starts, items }
    }

    fn of_block(&self, block: usize) -> &[u32] {
        &self.items[self.starts[block] as usize..self.starts[block + 1] as usize]
    }
}

/// Whether `block` holds control flow other than a call, a local branch or one terminator at its end.
fn has_stray_control_flow(block: &R2ILBlock) -> bool {
    let last = block.ops.len().checked_sub(1);
    (block.ops.iter().enumerate()).any(|(op, operation)| {
        operation.is_control_flow()
            && !operation.is_call()
            && Some(op) != last
            && !operation.is_local_branch()
    })
}

/// Whether a direct branch of `block` goes to an address `reaches` finds no edge to: a tail transfer.
fn branches_out(block: &R2ILBlock, reaches: &dyn Fn(u64) -> bool) -> bool {
    (block.ops.iter())
        .filter(|operation| operation.is_control_flow() && !operation.is_call())
        .filter_map(R2ILOp::transfer)
        .any(|transfer| {
            transfer.direct
                && transfer.target.space == SpaceId::Ram
                && !reaches(transfer.target.offset)
        })
}

/// Whether control runs on past the last operation of `block`: a conditional branch falls through,
/// any other control operation, or one the lift cannot state, names where it goes itself.
fn runs_on(block: &R2ILBlock) -> bool {
    !block
        .ops
        .last()
        .is_some_and(|op| op.is_control_flow() && !matches!(op, R2ILOp::CBranch { .. }))
}

fn ends_in_indirect_branch(block: &R2ILBlock) -> bool {
    matches!(block.ops.last(), Some(R2ILOp::BranchInd { .. }))
}

fn index(at: usize) -> u32 {
    u32::try_from(at).expect("fewer than 2^32 blocks")
}

impl<'a, B: Lifted> CallerFlow<'a, B> {
    /// The flow of `blocks`: `edges` are `(block, address control reaches after it)` and `open` the
    /// blocks the walk could not follow past (an edge to no block opens its block); `endian` is the machine's.
    pub fn new(
        blocks: &'a [B],
        edges: impl IntoIterator<Item = (usize, u64)>,
        open: impl IntoIterator<Item = usize>,
        endian: Endianness,
    ) -> Self {
        let mut starts = (blocks.iter().enumerate())
            .map(|(at, block)| (block.lifted().addr, at))
            .collect::<Vec<_>>();
        starts.sort_unstable();
        starts.dedup_by_key(|(address, _)| *address);
        let block_at = |address: u64| {
            let at = starts
                .binary_search_by_key(&address, |(start, _)| *start)
                .ok()?;
            Some(starts[at].1)
        };
        let mut open_blocks = vec![false; blocks.len()];
        for at in open {
            open_blocks[at] = true;
        }
        let mut pairs = Vec::new();
        for (from, address) in edges {
            match block_at(address) {
                Some(to) => pairs.push((index(from), index(to))),
                None => open_blocks[from] = true,
            }
        }
        let successors = Edges::of(blocks.len(), pairs.clone());
        let reaches = |from: usize, address: u64| {
            block_at(address).is_some_and(|to| successors.of_block(from).contains(&index(to)))
        };
        let mut leaves = vec![false; blocks.len()];
        let mut irregular = vec![false; blocks.len()];
        for (at, block) in blocks.iter().map(Lifted::lifted).enumerate() {
            irregular[at] = has_stray_control_flow(block);
            let end = block.addr + u64::from(block.size);
            // A branch no edge follows, or running on past the last operation where no edge goes,
            // leaves for code the body does not hold.
            leaves[at] = branches_out(block, &|address| reaches(at, address))
                || (runs_on(block) && !reaches(at, end));
            // An indirect branch no edge resolves goes where the walk did not follow.
            open_blocks[at] |= ends_in_indirect_branch(block) && successors.of_block(at).is_empty();
        }
        let mut first = Vec::with_capacity(blocks.len() + 1);
        let mut modes = Vec::new();
        for (at, block) in blocks.iter().enumerate() {
            first.push(u32::try_from(modes.len()).expect("fewer than 2^32 operations"));
            modes.extend(modes_of(block.lifted(), irregular[at], endian));
        }
        let predecessors = Edges::of(
            blocks.len(),
            pairs.iter().map(|(from, to)| (*to, *from)).collect(),
        );
        Self {
            blocks,
            starts,
            successors,
            predecessors,
            leaves,
            open: open_blocks,
            irregular,
            modes,
            first,
        }
    }

    /// Whether the operation at (block, op) is a call.
    pub fn is_call(&self, block: usize, op: usize) -> bool {
        self.blocks[block].lifted().ops[op].is_call()
    }

    /// The boundary at each of `sites` (block, operation), from one pass; one past its budget gives
    /// every site Unknown. `arguments` are the registers `written` covers.
    pub fn site_fates(
        &self,
        lanes: ResultLanes,
        effects: &dyn CallEffects,
        sites: &[(usize, usize)],
        arguments: &[CanonicalStorageId],
    ) -> Vec<SiteBoundary> {
        let mut fates = (sites.iter())
            .map(|&(block, op)| {
                let written = written_before(self.blocks[block].lifted(), op, arguments);
                SiteBoundary::unknown(lanes, written)
            })
            .collect::<Vec<_>>();
        if sites.is_empty() {
            return fates;
        }
        let pass = Pass::new(self, Lanes::of(lanes), effects);
        let Some(live_in) = pass.solve(pass.budget()) else {
            return fates;
        };
        // Each block is replayed once, from its end back to its first site.
        let mut by_block = (0..sites.len()).collect::<Vec<_>>();
        by_block.sort_by_key(|site| (sites[*site].0, std::cmp::Reverse(sites[*site].1)));
        for run in by_block.chunk_by(|one, other| sites[*one].0 == sites[*other].0) {
            let wanted = run.iter().map(|site| (*site, sites[*site].1));
            pass.replay(sites[run[0]].0, wanted, &live_in, &mut fates);
        }
        fates
    }

    /// What the body entered at `entry` takes of the result registers and overwrites on every path
    /// to a return; none where no block starts there or the pass exceeded its budget.
    pub fn entry_summary(
        &self,
        entry: u64,
        lanes: ResultLanes,
        effects: &dyn CallEffects,
    ) -> Option<EntrySummary> {
        let at = self
            .starts
            .binary_search_by_key(&entry, |(start, _)| *start)
            .ok()
            .map(|at| self.starts[at].1)?;
        let tracked = Lanes::of(lanes);
        let pass = Pass::new(self, tracked, effects);
        let live = pass.solve(pass.budget())?.swap_remove(at);
        let (mut takes, mut overwrites) = (LaneBytes::default(), LaneBytes::default());
        for lane in 0..LANES {
            let taken = live.read[lane] | live.forwarded[lane] | live.open[lane];
            takes.0[lane] = taken;
            overwrites.0[lane] = tracked.all(lane) & !(taken | live.returned[lane]);
        }
        Some(EntrySummary { takes, overwrites })
    }
}

/// One solve of one body for one set of lanes.
struct Pass<'p, 'a, B> {
    flow: &'p CallerFlow<'a, B>,
    lanes: Lanes,
    effects: &'p dyn CallEffects,
    /// What each counting call's block states of its count, by the call's place in the operations.
    counts: std::collections::BTreeMap<usize, Count>,
}

impl<'p, 'a, B: Lifted> Pass<'p, 'a, B> {
    fn new(flow: &'p CallerFlow<'a, B>, lanes: Lanes, effects: &'p dyn CallEffects) -> Self {
        Self {
            flow,
            lanes,
            effects,
            counts: counts(flow, effects),
        }
    }

    /// What the call at `op` takes and does: a variadic callee's vector registers are taken unless
    /// the call states it uses none, and a fixed one takes more where the call states a count.
    fn call_at(&self, block: usize, op: usize) -> CallEffect {
        let mut call = self.effects.at(block, op);
        let Some(counted) = call.counted.take() else {
            return call;
        };
        let at = self.flow.first[block] as usize + op;
        let count = self.counts.get(&at).copied().unwrap_or(Count::Other);
        let more = match (counted.stated, count) {
            (None, Count::Nought) | (Some(_), Count::Unstated) => LaneBytes::default(),
            (None, _) => counted.takes,
            (Some(stated), Count::Nought) => stated,
            (Some(stated), Count::Other) => stated.and(counted.takes),
        };
        call.takes = call.takes.and(more);
        call
    }

    /// Visits a pass may make: each block as often as its live set can move, which is once per
    /// bit of the four planes, plus the first visit.
    fn budget(&self) -> usize {
        let bytes = (self.lanes.0.iter().flatten())
            .map(|lane| lane.all.count_ones() as usize)
            .sum::<usize>();
        let height = 4 * bytes;
        let blocks = self.flow.blocks.len();
        blocks.saturating_mul(height + 1).saturating_add(blocks)
    }

    /// Live bytes at every block's start, or none where the pass visited more blocks than `budget`.
    fn solve(&self, budget: usize) -> Option<Vec<Live>> {
        let blocks = self.flow.blocks.len();
        let mut live_in = vec![Live::default(); blocks];
        // Work is the blocks whose output may have moved; the last block first, as flow runs forward.
        let mut work = (0..blocks).collect::<std::collections::BTreeSet<_>>();
        let mut visits = 0usize;
        while let Some(block) = work.pop_last() {
            visits += 1;
            if visits > budget {
                return None;
            }
            let mut live = self.out_of(block, &live_in);
            for (op, operation) in self.flow.blocks[block]
                .lifted()
                .ops
                .iter()
                .enumerate()
                .rev()
            {
                self.step(&mut live, block, op, operation);
            }
            if live != live_in[block] {
                live_in[block] = live;
                work.extend(
                    (self.flow.predecessors.of_block(block).iter()).map(|from| *from as usize),
                );
            }
        }
        Some(live_in)
    }

    /// The bytes live where `block` ends: its successors' starts, and everything where it leaves
    /// the body or the walk lost it.
    fn out_of(&self, block: usize, live_in: &[Live]) -> Live {
        let mut out = Live::default();
        for successor in self.flow.successors.of_block(block) {
            out.join(&live_in[*successor as usize]);
        }
        for lane in 0..LANES {
            if self.flow.leaves[block] {
                out.forwarded[lane] |= self.lanes.all(lane);
            }
            if self.flow.open[block] || self.flow.irregular[block] {
                out.open[lane] |= self.lanes.all(lane);
            }
        }
        out
    }

    /// The fate after each wanted call of `block` (site, operation; later operations first).
    fn replay(
        &self,
        block: usize,
        wanted: impl Iterator<Item = (usize, usize)>,
        live_in: &[Live],
        fates: &mut [SiteBoundary],
    ) {
        let ops = &self.flow.blocks[block].lifted().ops;
        let mut live = self.out_of(block, live_in);
        let mut next = ops.len();
        for (site, op) in wanted {
            for at in (op + 1..next).rev() {
                self.step(&mut live, block, at, &ops[at]);
            }
            next = next.min(op + 1);
            if !predicated(self.flow.blocks[block].lifted(), op) {
                fates[site].fates = self.fate_of(&live);
            }
        }
    }

    /// Move `live` from after `operation` to before it.
    fn step(&self, live: &mut Live, block: usize, op: usize, operation: &R2ILOp) {
        let mode = self.flow.modes[self.flow.first[block] as usize + op];
        if mode.inert {
            return;
        }
        let call = operation.is_call().then(|| self.call_at(block, op));
        // What the operation overwrites ends those bytes' liveness, ahead of what it reads.
        if !mode.weak {
            live.kill_all(self.overwritten(operation, call.as_ref()));
        }
        // A read past a write that may not happen, a call that may leave a byte as it found it or
        // an operation with unstated effects may read that operation's value: no proof of ours.
        let doubtful = match &call {
            Some(call) if call.overwrites != Overwrites::All => self.lanes.every(),
            _ if operation.reads_unstated() => self.lanes.every(),
            _ if mode.weak => operation
                .output()
                .map_or([0; LANES], |output| self.lanes.bytes_in(output)),
            _ => [0; LANES],
        };
        for ((open, read), doubt) in live.open.iter_mut().zip(&mut live.read).zip(doubtful) {
            *open |= *read & doubt;
            *read &= !doubt;
        }
        if matches!(operation, R2ILOp::Return { .. }) {
            merge(&mut live.returned, self.lanes.every());
        }
        if let Some(call) = &call {
            merge(&mut live.open, call.takes.0);
        }
        // Reads the lift does not state may be of any lane: open, never dead.
        if operation.reads_unstated() {
            merge(&mut live.open, self.lanes.every());
        }
        if !mode.blind {
            self.read(live, operation, mode.ignored);
        }
    }

    /// The bytes `operation` overwrites: a call's by its callee, any other's by its output.
    fn overwritten(&self, operation: &R2ILOp, call: Option<&CallEffect>) -> [Bytes; LANES] {
        match (call.map(|call| call.overwrites), operation.output()) {
            (Some(Overwrites::Nothing), _) | (None, None) => [0; LANES],
            (Some(Overwrites::Bytes(written)), _) => written.0,
            (Some(Overwrites::All), _) => self.lanes.every(),
            (None, Some(output)) => self.lanes.bytes_in(output),
        }
    }

    /// Add what `operation` reads of the inputs not in `ignored`. A copy of the rest of a register
    /// is a read of it, as any operation's is.
    fn read(&self, live: &mut Live, operation: &R2ILOp, ignored: u32) {
        for (at, input) in operation.inputs().into_iter().enumerate() {
            if ignored == u32::MAX || (at < 32 && ignored >> at & 1 == 1) {
                continue;
            }
            merge(&mut live.read, self.lanes.bytes_in(input));
        }
    }

    fn fate_of(&self, live: &Live) -> [Option<LaneFate>; LANES] {
        std::array::from_fn(|at| self.lanes.0[at].map(|_| live.fate(at)))
    }
}

/// What the block of each call of `flow` that counts states of the count, by the call's place in
/// its operations.
fn counts<B: Lifted>(
    flow: &CallerFlow<'_, B>,
    effects: &dyn CallEffects,
) -> std::collections::BTreeMap<usize, Count> {
    let calls = (flow.blocks.iter().enumerate()).flat_map(|(block, found)| {
        let ops = &found.lifted().ops;
        (0..ops.len())
            .filter(|op| ops[*op].is_call())
            .map(move |op| (block, op))
    });
    let counted = calls.filter_map(|(block, op)| {
        let counted = effects.at(block, op).counted?;
        let count = count_of(flow.blocks[block].lifted(), op, counted.register);
        Some((flow.first[block] as usize + op, count))
    });
    counted.collect()
}

/// What the block states `register` holds where the call at `op` runs: the last write to it before,
/// back to the previous control operation. Each walk ends at the previous call, so `O(ops)`.
fn count_of(block: &R2ILBlock, op: usize, register: CanonicalStorageId) -> Count {
    let at = Varnode::register(register.offset, register.size);
    let end = register.offset.saturating_add(u64::from(register.size));
    let writes = |output: &Varnode| {
        output.space == SpaceId::Register
            && output.offset < end
            && register.offset < output.offset.saturating_add(u64::from(output.size))
    };
    for earlier in (0..op).rev() {
        let operation = &block.ops[earlier];
        // A call or a branch between may have written it, or joined paths that did.
        if operation.is_control_flow() {
            return Count::Unstated;
        }
        if !operation.output().is_some_and(writes) {
            continue;
        }
        let Some(instruction) = block.instruction_of(earlier) else {
            return Count::Other;
        };
        let same = |at: usize| block.instruction_of(at) == Some(instruction);
        let from = (0..earlier).rev().take_while(|at| same(*at)).last();
        let to = (earlier + 1..op).take_while(|at| same(*at)).last();
        let ops = &block.ops[from.unwrap_or(earlier)..=to.unwrap_or(earlier)];
        return match leaves_zero(ops, &at) {
            true => Count::Nought,
            false => Count::Other,
        };
    }
    Count::Unstated
}

/// Whether the call at `index` is one its own instruction may skip (an ARM32 conditional `bl`
/// lifts to a branch around it).
fn predicated(block: &R2ILBlock, index: usize) -> bool {
    let instruction = |at: usize| block.instruction_of(at);
    let Some(call) = instruction(index) else {
        return true;
    };
    (0..index)
        .rev()
        .take_while(|at| instruction(*at) == Some(call))
        .any(|at| block.ops[at].is_control_flow())
}

/// The bytes of each of `arguments` the block writes before the call at `op`, back to the previous
/// control operation. `O(op)`.
fn written_before(
    block: &R2ILBlock,
    op: usize,
    arguments: &[CanonicalStorageId],
) -> Box<[ByteMask]> {
    let mut written = vec![ByteMask::default(); arguments.len()];
    for operation in block.ops[..op].iter().rev() {
        if operation.is_control_flow() {
            break;
        }
        let Some(output) = operation
            .output()
            .filter(|out| out.space == SpaceId::Register)
        else {
            continue;
        };
        let storage = CanonicalStorageId::from_varnode(output);
        for (slot, mask) in arguments.iter().zip(&mut written) {
            mask.0 |= Lane::new(*slot).bytes_of(storage);
        }
    }
    written.into()
}

/// Whether two storages share a byte.
fn overlap(a: CanonicalStorageId, b: CanonicalStorageId) -> bool {
    a.space == b.space
        && a.offset < b.offset.saturating_add(u64::from(b.size))
        && b.offset < a.offset.saturating_add(u64::from(a.size))
}

/// What the closed world decides of a body's result from its open interface and every call's fate on
/// each lane (doc/adr-call-boundary.md, "S7 as built"; D202). Recovery applies it in the same seal.
pub fn decide(
    open: &SourceFunctionInterface,
    callers: &SourceCallerLanes,
) -> Option<SourceClosedResult> {
    // A declaration states the result.
    if open.types_are_declared() {
        return None;
    }
    let lane = |id: LaneId| callers.lanes[usize::from(id.0)];
    let (integer, float, second) = (
        lane(LaneId::INTEGER),
        lane(LaneId::FLOAT),
        lane(LaneId::SECOND),
    );
    let carriers = open.result_carriers();
    // A body may hand back any lane of the return set as its caller left it (d72 round 6), so a void
    // needs each dead at every call.
    let lanes = &callers.lanes;
    let all_dead = callers.exhaustive && lanes.iter().all(|lane| lane.dead || !lane.held);
    let cycle = lanes.iter().any(|lane| lane.cycle);
    match open.return_kind() {
        r2source::SourceFunctionReturn::Register { .. } => {
            let paired = carriers.is_some_and(|carriers| carriers.second.is_some());
            if paired && second.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Pair));
            }
            if integer.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            if all_dead {
                return Some(SourceClosedResult::Unread);
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        r2source::SourceFunctionReturn::Unproven => {
            let carriers = carriers?;
            if integer.read && (carriers.float.is_none() || !float.read) {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            if carriers.float.is_some() && float.read && !integer.read {
                let bytes = float
                    .width
                    .flatten()
                    .filter(|bytes| matches!(bytes, 4 | 8))?;
                let bytes = u8::try_from(bytes).ok()?;
                return Some(SourceClosedResult::Read(SourceReadLanes::Float { bytes }));
            }
            if all_dead {
                // No defined byte reaches a return where the body only hands back an input.
                let causes = (open.unproven_result())
                    .map(|unproven| unproven.causes().to_vec())
                    .unwrap_or_default();
                let undefined = causes.iter().all(|cause| {
                    matches!(
                        cause,
                        SourceResultCause::HandedBack | SourceResultCause::NoReturn
                    )
                });
                return Some(match undefined {
                    true => SourceClosedResult::Void,
                    false => SourceClosedResult::Unread,
                });
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use r2il::{Endianness, R2ILBlock, R2ILOp, SpaceId, Varnode};
    use r2source::{CanonicalStorageId, CanonicalStorageSpace};

    use super::{
        CallEffect, CallEffects, CallerFlow, Counted, LANES as LANE_COUNT, LaneBytes, LaneFate,
        OTHERS, Overwrites, ResultLanes, SiteBoundary, TakeOnly,
    };

    /// A fate without its bytes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum K {
        Dead,
        Read,
        Returned,
        Unknown,
    }

    fn shape(fate: Option<LaneFate>) -> Option<K> {
        fate.map(|fate| match fate {
            LaneFate::Dead => K::Dead,
            LaneFate::Read(_) => K::Read,
            LaneFate::Returned(_) => K::Returned,
            LaneFate::Unknown => K::Unknown,
        })
    }

    /// `head` and then the default for every further one of the return set's other registers.
    fn pad<T: Copy + Default, const N: usize>(head: [T; N]) -> [T; OTHERS] {
        let mut padded = [T::default(); OTHERS];
        padded[..N].copy_from_slice(&head);
        padded
    }

    const RAX: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    const XMM0: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x1200,
        size: 8,
    };
    const RDX: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x10,
        size: 8,
    };
    const LANES: ResultLanes = ResultLanes {
        integer: Some(RAX),
        float: Some(XMM0),
        second: None,
        others: [None; OTHERS],
    };
    const NOTHING: &TakeOnly = &TakeOnly(LaneBytes([0; LANE_COUNT]));
    const FLOAT_LANE: usize = 1;

    /// A block at `addr` of `size` bytes from operations stamped as one instruction each.
    fn block(addr: u64, size: u32, ops: Vec<R2ILOp>) -> R2ILBlock {
        let mut block = R2ILBlock::new(addr, size);
        for (at, op) in ops.into_iter().enumerate() {
            block.push_from(op, addr + at as u64);
        }
        block
    }

    fn call() -> R2ILOp {
        R2ILOp::Call {
            target: Varnode::ram(0x2000, 8),
        }
    }

    fn ret() -> R2ILOp {
        R2ILOp::Return {
            target: Varnode::register(0x20, 8),
        }
    }

    fn jump(to: u64) -> R2ILOp {
        R2ILOp::Branch {
            target: Varnode::ram(to, 8),
        }
    }

    fn branch(to: u64) -> R2ILOp {
        R2ILOp::CBranch {
            target: Varnode::ram(to, 8),
            cond: Varnode::register(0x100, 1),
        }
    }

    fn write(offset: u64, size: u32) -> R2ILOp {
        R2ILOp::Copy {
            dst: Varnode::register(offset, size),
            src: Varnode::constant(0, size),
        }
    }

    /// The register moved to memory: a read of its bytes.
    fn store(offset: u64, size: u32) -> R2ILOp {
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0x30, 8),
            val: Varnode::register(offset, size),
        }
    }

    /// `eax = eax ^ eax`, which reads EAX in form only.
    fn zero_eax() -> R2ILOp {
        R2ILOp::IntXor {
            dst: Varnode::register(0, 4),
            a: Varnode::register(0, 4),
            b: Varnode::register(0, 4),
        }
    }

    fn zero_extend() -> R2ILOp {
        R2ILOp::IntZExt {
            dst: Varnode::register(0, 8),
            src: Varnode::register(0, 4),
        }
    }

    /// The fate after the call at (block 0, op 0), whose blocks flow by `edges`, among `open` ones.
    fn fates(blocks: &[R2ILBlock], edges: &[(usize, u64)], open: &[usize]) -> SiteBoundary {
        fates_with(blocks, edges, open, NOTHING)
    }

    fn fates_with(
        blocks: &[R2ILBlock],
        edges: &[(usize, u64)],
        open: &[usize],
        effects: &dyn CallEffects,
    ) -> SiteBoundary {
        let flow = CallerFlow::new(
            blocks,
            edges.iter().copied(),
            open.iter().copied(),
            Endianness::Little,
        );
        flow.site_fates(LANES, effects, &[(0, 0)], &[])
            .swap_remove(0)
    }

    fn integer(fate: SiteBoundary) -> K {
        shape(fate.fates[0]).expect("the integer register is tracked")
    }

    /// `call f; mov [rsi], eax`: the caller reads EAX as the call left it.
    #[test]
    fn a_read_of_the_result_register_after_the_call_is_a_read() {
        let blocks = [block(0x1000, 8, vec![call(), store(0, 4), ret()])];
        let fate = fates(&blocks, &[], &[]);
        assert_eq!(integer(fate), K::Read);
    }

    /// `xor eax, eax` lifts to a 4-byte write and a zero-extension that covers RAX: the call's RAX
    /// is overwritten unread, and the self-cancelling xor reads nothing.
    #[test]
    fn a_write_extended_over_the_register_kills_it() {
        let ops = vec![call(), zero_eax(), zero_extend(), store(0, 4), ret()];
        let blocks = [block(0x1000, 8, ops)];
        assert_eq!(integer(fates(&blocks, &[], &[])), K::Dead);
    }

    /// Writing only `al` leaves seven bytes the call left: a read of the whole register keeps them
    /// live, though not as the value (it reaches no byte of it below them).
    #[test]
    fn a_write_of_part_of_a_register_kills_only_that_part() {
        let part = [block(
            0x1000,
            8,
            vec![call(), write(0, 1), store(0, 8), ret()],
        )];
        assert_eq!(integer(fates(&part, &[], &[])), K::Unknown);
        let whole = [block(
            0x1000,
            8,
            vec![call(), write(0, 8), store(0, 8), ret()],
        )];
        assert_eq!(integer(fates(&whole, &[], &[])), K::Dead);
    }

    /// `call f; test; jz L; xor eax, eax; ret / L: xor eax, eax; ret`: dead on both arms.
    #[test]
    fn a_result_overwritten_on_both_arms_of_a_branch_is_dead() {
        let overwrite = |at| block(at, 4, vec![zero_eax(), zero_extend(), ret()]);
        let blocks = [
            block(0x1000, 8, vec![call(), branch(0x1010)]),
            overwrite(0x1008),
            overwrite(0x1010),
        ];
        let edges = [(0, 0x1008), (0, 0x1010)];
        assert_eq!(integer(fates(&blocks, &edges, &[])), K::Dead);
    }

    /// The same, with a read on either arm: it is read.
    #[test]
    fn a_result_read_on_one_arm_is_read() {
        let overwrite = |at| block(at, 4, vec![zero_eax(), zero_extend(), ret()]);
        let read = |at| block(at, 4, vec![store(0, 4), ret()]);
        let edges = [(0, 0x1008), (0, 0x1010)];
        let call_block = || block(0x1000, 8, vec![call(), branch(0x1010)]);
        let second = [call_block(), overwrite(0x1008), read(0x1010)];
        assert_eq!(integer(fates(&second, &edges, &[])), K::Read);
        let first = [call_block(), read(0x1008), overwrite(0x1010)];
        assert_eq!(integer(fates(&first, &edges, &[])), K::Read);
    }

    /// `L: mov [m], eax; call f; jne L; xor eax, eax; ret`: the back edge carries the call's result
    /// to the read at the loop's head, which no scan of the call's own block reaches.
    #[test]
    fn a_read_reached_by_a_loop_s_back_edge_is_a_read() {
        let blocks = [
            block(0x1000, 4, vec![store(0, 4), call(), branch(0x1000)]),
            block(0x1004, 4, vec![zero_eax(), zero_extend(), ret()]),
        ];
        let flow = CallerFlow::new(&blocks, [(0, 0x1000), (0, 0x1004)], [], Endianness::Little);
        let fated = flow.site_fates(LANES, NOTHING, &[(0, 1)], &[]);
        assert_eq!(integer(fated[0].clone()), K::Read);
    }

    /// The call is the last operation of its block, so the writes after it are in the next one.
    #[test]
    fn the_writes_in_the_block_after_the_call_are_seen() {
        let blocks = [
            block(0x1000, 4, vec![call()]),
            block(0x1004, 4, vec![zero_eax(), zero_extend(), ret()]),
        ];
        let fate = fates(&blocks, &[(0, 0x1004)], &[]);
        assert_eq!(integer(fate), K::Dead);
    }

    /// Returning with the register as it is hands it to the caller's caller: neither read nor dead.
    #[test]
    fn a_result_in_place_at_a_return_is_returned() {
        let blocks = [block(0x1000, 4, vec![call(), ret()])];
        let fate = fates(&blocks, &[], &[]);
        assert_eq!(integer(fate), K::Returned);
    }

    /// A branch to code the body does not hold is a tail transfer: the callee there may read it,
    /// which this pass does not read, so the bytes are unknown and forward to no caller.
    #[test]
    fn a_tail_transfer_with_the_register_in_place_is_unknown() {
        let blocks = [block(0x1000, 4, vec![call(), jump(0x5000)])];
        assert_eq!(integer(fates(&blocks, &[], &[])), K::Unknown);
        // Running on past the last operation into code the body does not hold is the same.
        let falling = [block(0x1000, 4, vec![call(), write(0x40, 8)])];
        assert_eq!(integer(fates(&falling, &[], &[])), K::Unknown);
    }

    /// A block the walk could not follow past may do anything with the register.
    #[test]
    fn an_unresolved_end_is_unknown() {
        let blocks = [block(0x1000, 4, vec![call(), jump(0x1010)])];
        assert_eq!(integer(fates(&blocks, &[], &[0])), K::Unknown);
        let target = Varnode::register(0x38, 8);
        let indirect = [block(0x1000, 4, vec![call(), R2ILOp::BranchInd { target }])];
        assert_eq!(integer(fates(&indirect, &[], &[])), K::Unknown);
        // An edge to an address no block starts at is control lost.
        let lost = [block(0x1000, 4, vec![call()])];
        let fate = fates(&lost, &[(0, 0x9999)], &[]);
        assert_eq!(integer(fate), K::Unknown);
    }

    /// A branch in the middle of a block, to somewhere other than a label of its own instruction, is
    /// control the pass cannot order: nothing after it kills, and the result stays open.
    #[test]
    fn a_branch_in_the_middle_of_a_block_leaves_the_result_open() {
        let ops = vec![call(), branch(0x1010), write(0, 8), ret()];
        let blocks = [block(0x1000, 8, ops), block(0x1010, 4, vec![ret()])];
        let fate = fates(&blocks, &[(0, 0x1010)], &[]);
        assert_eq!(integer(fate), K::Unknown);
    }

    /// An operation the lift cannot state (`Unimplemented`) may read any register, and go anywhere.
    #[test]
    fn control_the_lift_cannot_state_is_unknown() {
        let blocks = [block(0x1000, 4, vec![call(), R2ILOp::Unimplemented])];
        assert_eq!(integer(fates(&blocks, &[], &[])), K::Unknown);
    }

    /// A path that ends at a call its callee never returns from has nothing after it to read.
    #[test]
    fn a_path_that_ends_at_a_call_that_never_returns_is_dead() {
        let blocks = [block(0x1000, 4, vec![call(), call()])];
        assert_eq!(integer(fates(&blocks, &[], &[])), K::Dead);
    }

    /// `call f; jz L; xor eax, eax; ret / L: jmp elsewhere`: one arm overwrites the register and the
    /// other hands it to code the body does not hold, so the join is unknown.
    #[test]
    fn an_arm_that_leaves_the_body_keeps_the_register_at_the_join() {
        let blocks = [
            block(0x1000, 8, vec![call(), branch(0x1010)]),
            block(0x1008, 4, vec![zero_eax(), zero_extend(), ret()]),
            block(0x1010, 4, vec![jump(0x5000)]),
        ];
        let fate = fates(&blocks, &[(0, 0x1008), (0, 0x1010)], &[]);
        assert_eq!(integer(fate), K::Unknown);
    }

    /// A write to a register after the call is code that runs once the call returns, and runs on.
    #[test]
    fn a_block_that_runs_on_past_its_last_write_hands_its_registers_on() {
        let ops = vec![call(), write(0x40, 8)];
        assert_eq!(
            integer(fates(&[block(0x1000, 4, ops)], &[], &[])),
            K::Unknown
        );
    }

    /// `sbb eax, eax` compares EAX with itself, and its flags read the nibble of EAX beside it: none
    /// of that is a read of the value a call left. `add eax, 1` reads the same nibble and the value.
    #[test]
    fn an_instruction_naming_a_register_twice_in_a_cancelling_operation_reads_none_of_it() {
        let eax = || Varnode::register(0, 4);
        let compare = R2ILOp::IntLess {
            dst: Varnode::register(0x200, 1),
            a: eax(),
            b: eax(),
        };
        let nibble = R2ILOp::IntAnd {
            dst: Varnode::unique(0, 4),
            a: eax(),
            b: Varnode::constant(0xf, 4),
        };
        let add = R2ILOp::IntAdd {
            dst: eax(),
            a: eax(),
            b: Varnode::constant(1, 4),
        };
        let after = |instruction: Vec<R2ILOp>| {
            let mut block = R2ILBlock::new(0x1000, 16);
            block.push_from(call(), 0x1000);
            for op in instruction {
                block.push_from(op, 0x1004);
            }
            block.push_from(zero_extend(), 0x1004);
            block.push_from(ret(), 0x1008);
            integer(fates(&[block], &[], &[]))
        };
        assert_eq!(after(vec![compare, nibble.clone(), zero_eax()]), K::Dead);
        assert_eq!(after(vec![nibble, add]), K::Read);
    }

    /// `or eax, -1` gives -1 whatever EAX holds: it reads no value of the call's result. A mask that
    /// keeps a bit of it does.
    #[test]
    fn an_operation_whose_result_ignores_the_register_reads_none_of_its_value() {
        let or = |mask| R2ILOp::IntOr {
            dst: Varnode::register(0, 4),
            a: Varnode::register(0, 4),
            b: Varnode::constant(mask, 4),
        };
        let after = |mask| {
            let ops = vec![call(), or(mask), zero_extend(), store(0, 4), ret()];
            integer(fates(&[block(0x1000, 8, ops)], &[], &[]))
        };
        assert_eq!(after(0xffff_ffff), K::Dead);
        assert_eq!(after(0x7fff_ffff), K::Read);
    }

    /// Operations the lift stamped with no instruction are not one instruction: a cancelling
    /// operation among them blinds none of the others, and each one's write may not happen.
    #[test]
    fn operations_with_no_instruction_blind_none_of_each_other() {
        let mut unstamped = R2ILBlock::new(0x1000, 8);
        unstamped.push_from(call(), 0x1000);
        for op in [zero_eax(), store(0, 4), ret()] {
            unstamped.push(op);
        }
        // The unstamped zeroing may or may not run: the store may read it, no proof of the call's.
        assert_eq!(integer(fates(&[unstamped], &[], &[])), K::Unknown);
        let mut stamped = R2ILBlock::new(0x1000, 8);
        stamped.push_from(call(), 0x1000);
        for op in [zero_eax(), zero_extend(), store(0, 4)] {
            stamped.push_from(op, 0x1004);
        }
        stamped.push_from(ret(), 0x1008);
        assert_eq!(integer(fates(&[stamped], &[], &[])), K::Dead);
    }

    /// A user operation, `cpuid` and an instruction the lift could not state read registers no operand
    /// names: the result before one stays open though a write follows, and a temporary it reads too.
    #[test]
    fn an_operation_whose_reads_the_lift_does_not_state_leaves_the_result_open() {
        let user = R2ILOp::CallOther {
            output: None,
            userop: 3,
            inputs: Vec::new(),
        };
        let cpuid = R2ILOp::CpuId {
            dst: Varnode::register(0x10, 4),
        };
        for unstated in [user, cpuid, R2ILOp::Unimplemented] {
            let ops = vec![call(), unstated, zero_eax(), zero_extend(), ret()];
            let fate = fates(&[block(0x1000, 8, ops)], &[], &[]);
            assert_eq!(integer(fate), K::Unknown);
        }
        let mut lifted = R2ILBlock::new(0x1000, 16);
        lifted.push_from(call(), 0x1000);
        lifted.push_from(
            R2ILOp::Copy {
                dst: Varnode::unique(0, 4),
                src: Varnode::register(0, 4),
            },
            0x1004,
        );
        lifted.push_from(R2ILOp::Unimplemented, 0x1004);
        lifted.push_from(zero_eax(), 0x1006);
        lifted.push_from(zero_extend(), 0x1006);
        lifted.push_from(ret(), 0x1008);
        // The copy before the unstated operation reads the call's EAX.
        assert_eq!(integer(fates(&[lifted], &[], &[])), K::Read);
    }

    /// An operation that reads registers no operand names may write any: a read after it is the
    /// register's value as it left it, no evidence of what the call returned.
    #[test]
    fn a_read_after_an_operation_with_unstated_effects_is_no_evidence() {
        let ops = vec![call(), R2ILOp::Unimplemented, store(0, 8), ret()];
        let fate = fates(&[block(0x1000, 8, ops)], &[], &[]);
        assert_eq!(integer(fate), K::Unknown);
    }

    /// A move of XMM0 into XMM1 reads both quads of XMM0 however the lift splits it: one copy, two quads,
    /// four dwords, or the high quad through a temporary (`vmovsd`). A copy is a read like a computation.
    #[test]
    fn a_move_of_a_vector_register_reads_its_rest_however_the_lift_splits_it() {
        let high = CanonicalStorageId {
            offset: XMM0.offset + 8,
            ..XMM0
        };
        let lanes = ResultLanes {
            others: pad([Some(high)]),
            ..LANES
        };
        let copy = |dst: u64, src: u64, size: u32| R2ILOp::Copy {
            dst: Varnode::register(dst, size),
            src: Varnode::register(src, size),
        };
        let (xmm0, xmm1) = (XMM0.offset, XMM1.offset);
        let splits: [(&str, Vec<R2ILOp>); 4] = [
            ("whole", vec![copy(xmm1, xmm0, 16)]),
            (
                "quads",
                vec![copy(xmm1, xmm0, 8), copy(xmm1 + 8, xmm0 + 8, 8)],
            ),
            (
                "dwords",
                (0..4)
                    .map(|at| copy(xmm1 + 4 * at, xmm0 + 4 * at, 4))
                    .collect(),
            ),
            (
                "through a temporary",
                vec![
                    R2ILOp::Copy {
                        dst: Varnode::unique(0, 8),
                        src: Varnode::register(xmm0 + 8, 8),
                    },
                    copy(xmm1, xmm0, 8),
                    R2ILOp::Copy {
                        dst: Varnode::register(xmm1 + 8, 8),
                        src: Varnode::unique(0, 8),
                    },
                ],
            ),
        ];
        let after = |instruction: Vec<R2ILOp>| {
            let mut block = R2ILBlock::new(0x1000, 16);
            block.push_from(call(), 0x1000);
            for op in instruction {
                block.push_from(op, 0x1004);
            }
            block.push_from(zero_eax(), 0x1008);
            block.push_from(zero_extend(), 0x1008);
            block.push_from(ret(), 0x100c);
            let blocks = [block];
            let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
            flow.site_fates(lanes, NOTHING, &[(0, 0)], &[])
                .swap_remove(0)
        };
        let [(_, first), rest @ ..] = splits;
        let moved = after(first);
        assert_eq!(shape(moved.fates[FLOAT_LANE]), Some(K::Read));
        assert_eq!(
            shape(moved.fates[3]),
            Some(K::Read),
            "the high quad is read"
        );
        for (what, split) in rest {
            assert_eq!(after(split).fates, moved.fates, "{what}");
        }
        // A float add on the high quad reads it.
        let added = vec![
            copy(xmm1, xmm0, 8),
            R2ILOp::FloatAdd {
                dst: Varnode::register(xmm1 + 8, 8),
                a: Varnode::register(xmm1 + 8, 8),
                b: Varnode::register(xmm0 + 8, 8),
            },
        ];
        assert_eq!(shape(after(added).fates[3]), Some(K::Read));
    }

    /// An operation reads its inputs whatever becomes of its output: `xorpd` on the high quad reads it
    /// though a later write overwrites what it computed, so the quad is not dead.
    #[test]
    fn an_operation_whose_output_no_path_holds_still_reads() {
        let high = CanonicalStorageId {
            offset: XMM0.offset + 8,
            ..XMM0
        };
        let lanes = ResultLanes {
            others: pad([Some(high)]),
            ..LANES
        };
        let negate = R2ILOp::IntXor {
            dst: Varnode::register(high.offset, 8),
            a: Varnode::register(high.offset, 8),
            b: Varnode::constant(1 << 63, 8),
        };
        let clear = R2ILOp::Copy {
            dst: Varnode::register(high.offset, 8),
            src: Varnode::constant(0, 8),
        };
        let fate = |ops: Vec<R2ILOp>| {
            let blocks = [block(0x1000, 8, ops)];
            CallerFlow::new(&blocks, [], [], Endianness::Little)
                .site_fates(lanes, NOTHING, &[(0, 0)], &[])
                .swap_remove(0)
        };
        let overwritten = fate(vec![call(), negate.clone(), clear, ret()]);
        assert_eq!(shape(overwritten.fates[3]), Some(K::Read));
        let kept = fate(vec![call(), negate, ret()]);
        assert_eq!(shape(kept.fates[3]), Some(K::Read));
    }

    /// A multi-byte `nop` forms an address from RAX in a temporary and drops it: that reads nothing.
    #[test]
    fn a_nop_that_forms_an_address_from_the_register_reads_nothing() {
        let address = R2ILOp::IntAdd {
            dst: Varnode::unique(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(0, 8),
        };
        let ops = vec![call(), address, zero_eax(), zero_extend(), ret()];
        assert_eq!(integer(fates(&[block(0x1000, 8, ops)], &[], &[])), K::Dead);
        // The same address stored, so that it is used, is a read.
        let used = R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0x30, 8),
            val: Varnode::register(0, 8),
        };
        let ops = vec![call(), used, zero_eax(), zero_extend(), ret()];
        assert_eq!(integer(fates(&[block(0x1000, 8, ops)], &[], &[])), K::Read);
    }

    /// What the call at op 1 does; the site at op 0 is the call whose result is asked.
    struct Later(CallEffect);

    impl CallEffects for Later {
        fn at(&self, block: usize, op: usize) -> CallEffect {
            match op {
                0 => NOTHING.at(block, op),
                _ => self.0,
            }
        }
    }

    /// Every call but the first is a variadic one: it takes XMM0 by the count in AL.
    struct Variadic;

    impl CallEffects for Variadic {
        fn at(&self, block: usize, op: usize) -> CallEffect {
            if (block, op) == (0, 0) {
                return NOTHING.at(block, op);
            }
            let al = CanonicalStorageId { size: 1, ..RAX };
            CallEffect {
                takes: LaneBytes::covered_by(LANES, &[al]),
                counted: Some(Counted {
                    register: al,
                    takes: LaneBytes::covered_by(LANES, &[XMM0]),
                    stated: None,
                }),
                overwrites: Overwrites::All,
            }
        }
    }

    /// `call f; <count>; call printf`: a variadic callee takes the vector registers unless the last
    /// write to AL before it, in its block, leaves it nought.
    #[test]
    fn a_variadic_calls_vector_registers_are_taken_unless_its_block_counts_none() {
        let float = |ops: Vec<R2ILOp>| {
            let blocks = [block(
                0x1000,
                8,
                [vec![call()], ops, vec![call(), ret()]].concat(),
            )];
            shape(fates_with(&blocks, &[], &[], &Variadic).fates[1])
                .expect("the float register is tracked")
        };
        let set = |al: u64| R2ILOp::Copy {
            dst: Varnode::register(0, 1),
            src: Varnode::constant(al, 1),
        };
        assert_eq!(float(vec![write(0, 1)]), K::Dead);
        assert_eq!(float(vec![write(0, 4), write(0x30, 8)]), K::Dead);
        // The count is something else, or unstated.
        assert_eq!(float(vec![set(1)]), K::Unknown);
        assert_eq!(float(vec![]), K::Unknown);
        assert_eq!(float(vec![write(0, 1), write(0x1200, 8)]), K::Dead);
        // A write to the rest of RAX leaves AL as it was.
        assert_eq!(float(vec![write(1, 7)]), K::Unknown);
        // A write the lift stamped with no instruction is not folded with its neighbours.
        let mut unstamped = R2ILBlock::new(0x1000, 8);
        unstamped.push_from(call(), 0x1000);
        unstamped.push(write(0, 1));
        unstamped.push_from(call(), 0x1002);
        unstamped.push_from(ret(), 0x1003);
        let fate = fates_with(&[unstamped], &[], &[], &Variadic);
        assert_eq!(shape(fate.fates[1]), Some(K::Unknown));
        // Written in another block, it is not stated here.
        let blocks = [
            block(0x1000, 8, vec![call(), write(0, 1)]),
            block(0x1008, 8, vec![call(), ret()]),
        ];
        let fate = fates_with(&blocks, &[(0, 0x1008)], &[], &Variadic);
        assert_eq!(shape(fate.fates[1]), Some(K::Unknown));
    }

    /// `call f; call g; mov [m], rax; ret`: g ends the bytes it is known to overwrite on every path.
    /// A read after one that overwrites nothing known may be f's, so f's register is not dead.
    #[test]
    fn a_later_call_ends_the_bytes_it_overwrites_and_no_others() {
        let blocks = [block(0x1000, 8, vec![call(), call(), store(0, 8), ret()])];
        let after = |overwrites| {
            let later = Later(CallEffect {
                counted: None,
                takes: LaneBytes::default(),
                overwrites,
            });
            integer(fates_with(&blocks, &[], &[], &later))
        };
        assert_eq!(after(Overwrites::All), K::Dead);
        // A read past a call that may leave the register may read that call's value.
        assert_eq!(after(Overwrites::Nothing), K::Unknown);
        let low = LaneBytes::covered_by(LANES, &[CanonicalStorageId { size: 4, ..RAX }]);
        assert_eq!(after(Overwrites::Bytes(low)), K::Unknown);
        let whole = LaneBytes::covered_by(LANES, &[RAX]);
        assert_eq!(after(Overwrites::Bytes(whole)), K::Dead);
    }

    /// A byte a later call may take as an argument stays open: not dead, and no evidence of a read.
    #[test]
    fn a_byte_a_later_call_may_take_is_open() {
        let blocks = [block(0x1000, 8, vec![call(), call(), ret()])];
        let takes = LaneBytes::covered_by(LANES, &[CanonicalStorageId { size: 1, ..RAX }]);
        let later = |takes| {
            Later(CallEffect {
                counted: None,
                takes,
                overwrites: Overwrites::All,
            })
        };
        let fate = fates_with(&blocks, &[], &[], &later(takes));
        assert_eq!(integer(fate), K::Unknown);
        let elsewhere = LaneBytes::covered_by(
            LANES,
            &[CanonicalStorageId {
                offset: 0x80,
                ..RAX
            }],
        );
        let fate = fates_with(&blocks, &[], &[], &later(elsewhere));
        assert_eq!(integer(fate), K::Dead);
    }

    /// An instruction that branches within itself may skip its write: the register is not dead after it.
    #[test]
    fn a_write_under_a_branch_within_its_instruction_kills_nothing() {
        let mut conditional = R2ILBlock::new(0x1000, 8);
        conditional.push_from(call(), 0x1000);
        // One instruction: skip the write when the condition holds.
        let skip = R2ILOp::CBranch {
            target: Varnode::constant(2, 1),
            cond: Varnode::register(0x100, 1),
        };
        conditional.push_from(skip, 0x1004);
        conditional.push_from(write(0, 8), 0x1004);
        conditional.push_from(ret(), 0x1006);
        assert_eq!(integer(fates(&[conditional], &[], &[])), K::Returned);
    }

    /// ARM32's `blne f` lifts to a branch around the call within its own instruction: the site is no
    /// evidence. A plain `bl` is.
    #[test]
    fn a_call_its_own_instruction_may_skip_is_unknown() {
        let mut conditional = R2ILBlock::new(0x1000, 4);
        let skip = R2ILOp::CBranch {
            target: Varnode::constant(2, 1),
            cond: Varnode::register(0x100, 1),
        };
        conditional.push_from(skip, 0x1000);
        conditional.push_from(call(), 0x1000);
        conditional.push_from(zero_eax(), 0x1004);
        conditional.push_from(zero_extend(), 0x1004);
        conditional.push_from(ret(), 0x1008);
        let flow = CallerFlow::new(
            std::slice::from_ref(&conditional),
            [],
            [],
            Endianness::Little,
        );
        let fated = flow.site_fates(LANES, NOTHING, &[(0, 1)], &[]);
        assert_eq!(integer(fated[0].clone()), K::Unknown);
        let plain = [block(
            0x1000,
            4,
            vec![call(), zero_eax(), zero_extend(), ret()],
        )];
        assert_eq!(integer(fates(&plain, &[], &[])), K::Dead);
    }

    /// A pass that visits more blocks than its budget gives every site unknown, never a partial answer.
    #[test]
    fn a_pass_past_its_budget_is_unknown_everywhere() {
        let looping = [
            block(0x1000, 4, vec![store(0, 4), call(), branch(0x1000)]),
            block(0x1004, 4, vec![ret()]),
        ];
        let flow = CallerFlow::new(&looping, [(0, 0x1000), (0, 0x1004)], [], Endianness::Little);
        let pass = super::Pass::new(&flow, super::Lanes::of(LANES), NOTHING);
        assert!(pass.solve(1).is_none());
        assert!(pass.solve(pass.budget()).is_some());
    }

    /// `sete dl; or esi, edx` reads the three bytes above DL that the call left, which the code never
    /// uses: they keep the register live, and are no evidence that the caller takes it as a result.
    #[test]
    fn a_read_of_the_bytes_above_a_written_one_is_not_a_read_of_the_value() {
        let ops = vec![call(), write(0x10, 1), store(0x10, 4), ret()];
        let blocks = [block(0x1000, 8, ops)];
        let lanes = ResultLanes {
            second: Some(RDX),
            ..LANES
        };
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
        let fate = flow
            .site_fates(lanes, NOTHING, &[(0, 0)], &[])
            .swap_remove(0);
        assert_eq!(shape(fate.fates[2]), Some(K::Unknown));
        // The same read of the whole of EDX, with nothing written above it, is the value.
        let blocks = [block(0x1000, 8, vec![call(), store(0x10, 4), ret()])];
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
        let fate = flow
            .site_fates(lanes, NOTHING, &[(0, 0)], &[])
            .swap_remove(0);
        assert_eq!(shape(fate.fates[2]), Some(K::Read));
    }

    /// The second integer register is a lane of its own, read apart from the first.
    #[test]
    fn the_second_register_is_read_apart_from_the_first() {
        let ops = vec![call(), store(0x10, 8), zero_eax(), zero_extend(), ret()];
        let blocks = [block(0x1000, 8, ops)];
        let lanes = ResultLanes {
            second: Some(RDX),
            ..LANES
        };
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
        let fate = flow
            .site_fates(lanes, NOTHING, &[(0, 0)], &[])
            .swap_remove(0);
        assert_eq!(shape(fate.fates[0]), Some(K::Dead));
        assert_eq!(shape(fate.fates[2]), Some(K::Read));
    }

    const XMM1: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x1240,
        size: 16,
    };
    const ST0: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x1100,
        size: 10,
    };

    /// The fate of the two registers of the return set no type reads, after `call; ops`.
    fn others_after(ops: Vec<R2ILOp>) -> SiteBoundary {
        let lanes = ResultLanes {
            others: pad([Some(XMM1), Some(ST0)]),
            ..LANES
        };
        let blocks = [block(0x1000, 8, [vec![call()], ops].concat())];
        CallerFlow::new(&blocks, [], [], Endianness::Little)
            .site_fates(lanes, NOTHING, &[(0, 0)], &[])
            .swap_remove(0)
    }

    /// The registers of the return set no lane types are read like any other: a call after which
    /// one is read has its result read there, and the typed lanes say nothing of it.
    #[test]
    fn a_read_of_a_return_register_no_lane_types_is_a_read_of_it() {
        let fate = others_after(vec![store(0x1240, 8), ret()]);
        assert_eq!(shape(fate.fates[3]), Some(K::Read));
        assert_eq!(integer(fate), K::Returned);
        // The x87 stack's top is the second of them.
        let fate = others_after(vec![store(0x1100, 8), ret()]);
        assert_eq!(shape(fate.fates[4]), Some(K::Read));
        // The upper bytes of a vector register are not a type's lane, and are read as the rest are.
        let fate = others_after(vec![store(0x1248, 8), ret()]);
        assert_eq!(shape(fate.fates[3]), Some(K::Unknown));
    }

    /// A read of XMM0 whole (`movups [rsi], xmm0`) reads both halves, and the high half alone reads it,
    /// with a float lane or without one.
    #[test]
    fn the_rest_of_the_float_register_is_read_by_a_read_of_it_whole_or_alone() {
        let high = CanonicalStorageId {
            offset: 0x1208,
            ..XMM0
        };
        let lanes = |float| ResultLanes {
            float,
            others: pad([Some(high)]),
            ..LANES
        };
        let after = |lanes: ResultLanes, read: R2ILOp| {
            let blocks = [block(0x1000, 8, vec![call(), read, ret()])];
            CallerFlow::new(&blocks, [], [], Endianness::Little)
                .site_fates(lanes, NOTHING, &[(0, 0)], &[])
                .swap_remove(0)
        };
        let whole = after(lanes(Some(XMM0)), store(0x1200, 16));
        assert_eq!(
            (shape(whole.fates[1]), shape(whole.fates[3])),
            (Some(K::Read), Some(K::Read))
        );
        let half = after(lanes(Some(XMM0)), store(0x1208, 8));
        assert_eq!(
            (shape(half.fates[1]), shape(half.fates[3])),
            (Some(K::Returned), Some(K::Read))
        );
        let none = after(lanes(None), store(0x1208, 8));
        assert_eq!(shape(none.fates[3]), Some(K::Read));
    }

    /// Written whole before any read, they are dead; returned in place, they are handed back and
    /// neither read nor dead; one read among them makes the group read.
    #[test]
    fn the_return_registers_no_lane_types_are_dead_only_when_each_is() {
        let clear = |offset, size| write(offset, size);
        let dead_after = others_after(vec![clear(0x1240, 16), clear(0x1100, 10), ret()]);
        assert_eq!(
            (shape(dead_after.fates[3]), shape(dead_after.fates[4])),
            (Some(K::Dead), Some(K::Dead))
        );
        let handed = others_after(vec![clear(0x1100, 10), ret()]);
        assert_eq!(shape(handed.fates[3]), Some(K::Returned));
        let mixed = others_after(vec![clear(0x1240, 16), store(0x1100, 8), ret()]);
        assert_eq!(shape(mixed.fates[4]), Some(K::Read));
    }

    /// A convention with no such registers has none of them dead either, and none read.
    #[test]
    fn no_other_return_register_is_no_dead_one() {
        let blocks = [block(0x1000, 8, vec![call(), ret()])];
        let fate = fates(&blocks, &[], &[]);
        assert_eq!(fate.fates[3..], [None; OTHERS]);
    }

    /// A body entered with the registers as a caller left them: what it may read of them, and what
    /// every path to a return overwrites.
    #[test]
    fn a_body_summary_names_what_it_takes_and_what_it_overwrites_on_every_path() {
        let summary = |blocks: &[R2ILBlock], edges: &[(usize, u64)]| {
            let flow = CallerFlow::new(blocks, edges.iter().copied(), [], Endianness::Little);
            flow.entry_summary(0x1000, LANES, NOTHING)
                .expect("a block starts there")
        };
        let rax =
            |bytes| LaneBytes::covered_by(LANES, &[CanonicalStorageId { size: bytes, ..RAX }]);
        // `mov eax, 1; ret` overwrites RAX's low four bytes and its high four stay: only the whole
        // register written is every byte.
        let low = summary(&[block(0x1000, 4, vec![write(0, 4), ret()])], &[]);
        assert_eq!(low.overwrites, rax(4));
        let whole = summary(&[block(0x1000, 4, vec![write(0, 8), ret()])], &[]);
        assert_eq!(whole.overwrites, rax(8));
        // A write on the second arm only is a write the body may make: the walk takes every arm.
        let late = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![ret()]),
            block(0x1010, 4, vec![write(0, 4), ret()]),
        ];
        assert_eq!(
            summary(&late, &[(0, 0x1004), (0, 0x1010)]).overwrites,
            LaneBytes::default()
        );
        // A write on one arm only is no overwrite.
        let arms = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![write(0, 8), ret()]),
            block(0x1010, 4, vec![ret()]),
        ];
        let one_arm = summary(&arms, &[(0, 0x1004), (0, 0x1010)]);
        assert_eq!(one_arm.overwrites, LaneBytes::default());
        // `test al, al` before the write takes AL.
        let variadic = summary(
            &[block(0x1000, 4, vec![store(0, 1), write(0, 8), ret()])],
            &[],
        );
        assert_eq!(variadic.takes, rax(1));
        // A tail transfer hands the register to code the body does not hold.
        let tail = summary(&[block(0x1000, 4, vec![jump(0x5000)])], &[]);
        assert_eq!(tail.takes, LaneBytes::covered_by(LANES, &[RAX, XMM0]));
    }
}

#[cfg(test)]
mod masks {
    use r2il::{Endianness, R2ILBlock, R2ILOp, SpaceId, Varnode};
    use r2source::{CanonicalStorageId, CanonicalStorageSpace};

    use super::{ByteMask, CallerFlow, LaneFate, OTHERS, ResultLanes, TakeOnly};

    const RAX: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    const RDI: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x38,
        size: 8,
    };
    const LANES: ResultLanes = ResultLanes {
        integer: Some(RAX),
        float: None,
        second: None,
        others: [None; OTHERS],
    };

    fn after(ops: Vec<R2ILOp>) -> super::SiteBoundary {
        let mut block = R2ILBlock::new(0x1000, 16);
        let call = R2ILOp::Call {
            target: Varnode::ram(0x2000, 8),
        };
        let ops = [
            vec![R2ILOp::Copy {
                dst: Varnode::register(0x38, 4),
                src: Varnode::constant(1, 4),
            }],
            vec![call],
            ops,
        ]
        .concat();
        for (at, op) in ops.into_iter().enumerate() {
            block.push_from(op, 0x1000 + at as u64);
        }
        let flow = CallerFlow::new(std::slice::from_ref(&block), [], [], Endianness::Little);
        let nothing = TakeOnly(super::LaneBytes::default());
        flow.site_fates(LANES, &nothing, &[(0, 1)], &[RDI])
            .swap_remove(0)
    }

    /// `mov edi, 1; call f; mov [rsi], eax; ret`: four bytes read, four written before.
    #[test]
    fn a_fate_states_the_bytes_and_the_site_its_written_arguments() {
        let store = R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0x30, 8),
            val: Varnode::register(0, 4),
        };
        let ret = R2ILOp::Return {
            target: Varnode::register(0x20, 8),
        };
        let read = after(vec![store, ret.clone()]);
        assert_eq!(read.fates[0], Some(LaneFate::Read(ByteMask(0xf))));
        assert_eq!(&*read.written, &[ByteMask(0xf)]);
        let returned = after(vec![ret]);
        assert_eq!(returned.fates[0], Some(LaneFate::Returned(ByteMask(0xff))));
        assert_eq!(ByteMask(0xf).low_run(), Some(4));
        assert_eq!(ByteMask(0xf0).low_run(), None);
    }
}
