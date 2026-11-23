//! What the code after a call does with its callee's result registers: a backward byte liveness
//! over the caller's blocks, solved once per body (doc/adr-call-boundary.md, `SiteBoundary`).

use r2il::eval::independence::{leaves_zero, reads_of};
use r2il::{Endianness, R2ILBlock, R2ILOp, SpaceId, Varnode};
use r2source::{CanonicalStorageId, ConventionModel};

use crate::arch::Arch;

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
pub const LANES: usize = TYPED + OTHERS;

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
    pub fn of(slots: &ConventionModel, results: &[CanonicalStorageId]) -> Self {
        let mut lanes = Self {
            integer: slots.result(),
            float: slots.results().float,
            second: slots.results().second,
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

    /// The lane the cited `follows` row of `model` puts after the float one, and its dense id: the
    /// one statement of it, for recovery and for the callers' join. O(lanes).
    pub fn after_float(
        &self,
        model: &[r2source::convention::ResultLane],
    ) -> Option<(CanonicalStorageId, usize)> {
        let float = self.float?;
        let first = model.iter().position(|lane| overlap(lane.storage, float))?;
        let second = model.iter().find(|lane| lane.follows == Some(first))?;
        let id = (self.slots().iter()).position(|slot| *slot == Some(second.storage))?;
        Some((second.storage, id))
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

pub fn argument_registers(slots: &ConventionModel) -> Vec<CanonicalStorageId> {
    [
        slots.arguments(r2source::convention::SlotClass::Integer),
        slots.arguments(r2source::convention::SlotClass::Float),
    ]
    .concat()
}

/// What becomes of the bytes of one result register after a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneFate {
    /// No path reads them, hands them back or leaves them: overwritten, or the path ends first.
    Dead,
    /// Some path reads these bytes, the lowest among them, before any call that may leave them;
    /// another may return `returned` to the caller's callers, or lose some (`lost`), as `Unknown` (D610).
    Read {
        bytes: ByteMask,
        returned: ByteMask,
        lost: bool,
    },
    /// No path reads or loses them; some returns with these bytes in place.
    Returned(ByteMask),
    /// Some path leaves them where the walk did not follow, a call may take them, a tail transfer
    /// hands them on, or a read misses the lowest byte.
    Unknown,
}

/// What one call site states of its callee's boundary: evidence only, never arity proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBoundary {
    /// The fate of each result lane after the call, by `LaneId`; none where the convention names no
    /// such register.
    pub fates: [Option<LaneFate>; LANES],
}

impl SiteBoundary {
    fn unknown(lanes: ResultLanes) -> Self {
        Self {
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

impl r2source::Negative for CallEffect {
    const FACTS: &'static [r2source::NegativeFact] = &[r2source::NegativeFact::Kept];
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
    /// The bytes its callee leaves as found on every path to a return: a read after the call reads
    /// what was there before it.
    pub kept: LaneBytes,
    /// The bytes the callee certainly reads: a cited fixed float parameter's, a read at the call
    /// (D228). An integer argument a callee may leave alone is no read.
    pub reads: LaneBytes,
}

/// The vector registers a variadic callee takes by the count its caller states in `register`
/// (System V psABI 3.2.3: `%al` bounds the vector registers used): none, where it holds nought.
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
            kept: LaneBytes::default(),
            reads: LaneBytes::default(),
        }
    }
}

/// One bit per register of a machine's outermost registers (`Arch::outermost_registers`), in order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniverseSet(Box<[u64]>);

impl UniverseSet {
    fn empty(registers: usize) -> Self {
        Self(vec![0; registers.div_ceil(64)].into())
    }

    fn insert(&mut self, at: usize) {
        self.0[at / 64] |= 1 << (at % 64);
    }

    pub fn contains(&self, at: usize) -> bool {
        self.0
            .get(at / 64)
            .is_some_and(|word| word >> (at % 64) & 1 == 1)
    }

    /// Whether no register is in the set.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    fn without(&self, other: &Self) -> Self {
        Self(
            (self.0.iter().zip(&other.0))
                .map(|(one, gone)| one & !gone)
                .collect(),
        )
    }

    fn and(&self, other: &Self) -> Self {
        Self(
            (self.0.iter().zip(&other.0))
                .map(|(one, also)| one & also)
                .collect(),
        )
    }
}

/// The registers a call may change: each outermost register the convention clobbers, as bits over
/// the machine's outermost registers (doc/adr-result-side.md, section 5).
pub struct CallUniverse<'m> {
    outermost: &'m [CanonicalStorageId],
    clobbered: UniverseSet,
}

impl<'m> CallUniverse<'m> {
    /// The universe on `machine` of a convention that `clobbers`; the SSA preserved set reads the
    /// same. `O(r)` asks.
    pub fn of(clobbers: &dyn Fn(CanonicalStorageId) -> bool, machine: &'m Arch) -> Self {
        let outermost = machine.outermost_registers();
        let mut clobbered = UniverseSet::empty(outermost.len());
        for (at, storage) in outermost.iter().enumerate() {
            if clobbers(*storage) {
                clobbered.insert(at);
            }
        }
        Self {
            outermost,
            clobbered,
        }
    }

    /// The registers of the universe, in the machine's order.
    pub fn registers(&self) -> impl Iterator<Item = CanonicalStorageId> + '_ {
        (self.outermost.iter().enumerate())
            .filter(|(at, _)| self.clobbered.contains(*at))
            .map(|(_, storage)| *storage)
    }
}

/// Registers as `offset:size`, space-separated: the evidence both preserved sets print, for the
/// loss count that compares them (doc/adr-result-side.md, "S31b as built").
pub fn spelled(storages: impl Iterator<Item = CanonicalStorageId>) -> String {
    let spelled = storages.map(|storage| format!("{:#x}:{}", storage.offset, storage.size));
    spelled.collect::<Vec<_>>().join(" ")
}

/// The outermost registers sharing a byte with `storage`: one run, as their starts and ends ascend.
/// `O(log r)`.
fn overlapping(
    outermost: &[CanonicalStorageId],
    storage: CanonicalStorageId,
) -> std::ops::Range<usize> {
    if storage.space != r2source::CanonicalStorageSpace::Register {
        return 0..0;
    }
    let end = storage.offset.saturating_add(u64::from(storage.size));
    let from = outermost
        .partition_point(|held| held.offset.saturating_add(u64::from(held.size)) <= storage.offset);
    let to = outermost.partition_point(|held| held.offset < end);
    from..to.max(from)
}

/// What `unwritten` reads beside the flow: the machine, whether the convention clobbers a register (none
/// without a call effect), which terminal call is declared `Never`, and each call's callee if named.
#[derive(Clone, Copy)]
pub struct KeptBy<'a> {
    pub machine: &'a Arch,
    pub clobbers: Option<&'a dyn Fn(CanonicalStorageId) -> bool>,
    pub never: &'a dyn Fn(usize, usize) -> bool,
    pub callee: &'a dyn Fn(usize, usize) -> Option<u64>,
}

/// What a body does to the registers it is entered with (doc/adr-result-side.md, section 5): one
/// row per body, its own calls read shallowly, so no row reads another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterEffect {
    /// The universe's registers no operation but a call writes on a path to a return; empty unless
    /// every exit is a return or a declared never-returning call and every call there names a callee.
    pub unwritten: UniverseSet,
    /// The callees of the calls on a path to a return, ascending: `unwritten` is kept only where
    /// each keeps it (D363), which [`RegisterEffect::closed`] answers.
    pub pending: Box<[u64]>,
    /// The result bytes every path to a return overwrites.
    pub overwrites: LaneBytes,
    /// The result bytes some path reads, forwards in a tail transfer or loses before writing them.
    pub takes: LaneBytes,
    /// The lanes `overwrites` and `takes` index: the body's own convention's.
    pub lanes: ResultLanes,
    /// The machine whose outermost registers `kept` indexes.
    machine: Arch,
}

impl RegisterEffect {
    /// The registers `unwritten` holds, in the machine's order.
    pub fn unwritten_registers(&self) -> impl Iterator<Item = CanonicalStorageId> + '_ {
        (self.machine.outermost_registers().iter().enumerate())
            .filter(|(at, _)| self.unwritten.contains(*at))
            .map(|(_, storage)| *storage)
    }

    /// The greatest the body can keep: `unwritten`, before any pending callee is asked (D413).
    pub fn unwritten_kept(&self) -> Kept {
        Kept {
            set: self.unwritten.clone(),
            machine: self.machine.clone(),
        }
    }

    /// Each result register with the low bytes the body may read of it before writing them: one
    /// past the highest byte `takes` holds, 0 where it takes none (D372). `O(LANES)`.
    pub fn register_reads(&self) -> LaneReads {
        let slots = self.lanes.slots();
        let read = (slots.iter().zip(self.takes.0)).filter_map(|(slot, taken)| {
            let slot = (*slot)?;
            Some((slot, (128 - taken.leading_zeros()).min(slot.size)))
        });
        LaneReads(read.collect())
    }

    /// What the body keeps once every pending callee keeps it, as `kept` answers each (none keeps
    /// nothing); asked in order until nothing is left. `O(p × r / 64)` plus the asks.
    pub fn closed(&self, mut kept: impl FnMut(u64) -> Option<Kept>) -> Kept {
        let mut set = self.unwritten.clone();
        for callee in &self.pending {
            if set.is_empty() {
                break;
            }
            set = match kept(*callee) {
                Some(callee) if callee.machine == self.machine => set.and(&callee.set),
                _ => UniverseSet::empty(self.machine.outermost_registers().len()),
            };
        }
        Kept {
            set,
            machine: self.machine.clone(),
        }
    }
}

/// The registers a call to a body leaves as found: its effect closed over its callees' (D363).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    set: UniverseSet,
    /// The machine whose outermost registers `set` indexes.
    machine: Arch,
}

impl Kept {
    /// Whether kept registers cover every byte of `storage`. `O(log r)` plus the registers it overlaps.
    pub fn keeps(&self, storage: CanonicalStorageId) -> bool {
        let outermost = self.machine.outermost_registers();
        let end = storage.offset.saturating_add(u64::from(storage.size));
        let mut reached = storage.offset;
        for at in overlapping(outermost, storage) {
            let held = outermost[at];
            if !self.set.contains(at) {
                continue;
            }
            if held.offset > reached {
                return false;
            }
            reached = reached.max(held.offset.saturating_add(u64::from(held.size)));
            if reached >= end {
                return true;
            }
        }
        false
    }

    /// The registers this body keeps, in the machine's order.
    pub fn kept_registers(&self) -> impl Iterator<Item = CanonicalStorageId> + '_ {
        (self.machine.outermost_registers().iter().enumerate())
            .filter(|(at, _)| self.set.contains(*at))
            .map(|(_, storage)| *storage)
    }

    /// Every byte of each lane whose register this body keeps whole.
    pub fn kept_lanes(&self, lanes: ResultLanes) -> LaneBytes {
        let mut kept = LaneBytes::default();
        for (at, slot) in lanes.slots().iter().enumerate() {
            if let Some(slot) = slot.filter(|slot| self.keeps(*slot)) {
                kept.0[at] = Lane::new(slot).all;
            }
        }
        kept
    }
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

/// The bytes of `every` a call's callee may change: all but those it keeps.
fn unkept(every: [Bytes; LANES], kept: LaneBytes) -> [Bytes; LANES] {
    std::array::from_fn(|lane| every[lane] & !kept.0[lane])
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
            LaneFate::Read {
                bytes: ByteMask(self.read[lane]),
                returned: ByteMask(self.returned[lane]),
                lost: self.open[lane] | self.forwarded[lane] != 0,
            }
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
    graph: Graph,
    /// What each operation of each block may do, where the block's first operation is `first[block]`.
    modes: Vec<Mode>,
    first: Vec<u32>,
}

/// The blocks of a body as a lane pass reads them, apart from their operations.
#[derive(Clone)]
struct Graph {
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
    /// Each call that may unwind, by block and operation, ascending, and the block its landing pad
    /// starts ([`NO_BLOCK`] where none does): an edge taken before the call ("Pads in the flow").
    unwinds: Box<[(u32, u32, u32)]>,
    /// The registers the unwinder writes before it enters a pad: killed on that edge.
    unwinder: Box<[CanonicalStorageId]>,
}

/// A pad address no block of the flow starts at.
const NO_BLOCK: u32 = u32::MAX;

impl Graph {
    /// The pad block the call at (block, op) unwinds to; `O(log u)`.
    fn unwind(&self, block: usize, op: usize) -> Option<u32> {
        let key = (index(block), index(op));
        let at = (self.unwinds).binary_search_by_key(&key, |(block, op, _)| (*block, *op));
        at.ok().map(|at| self.unwinds[at].2)
    }
}

/// The low bytes a walked body may read of each result register before writing it (D372, D411),
/// minted only by [`RegisterEffect::register_reads`], whose `takes` holds every read and forward.
#[doc = "```compile_fail,E0423\nlet forged = r2ssa::site_boundary::LaneReads(Box::new([]));\n```"]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneReads(Box<[(CanonicalStorageId, u32)]>);

impl r2source::Negative for LaneReads {
    const FACTS: &'static [r2source::NegativeFact] = &[r2source::NegativeFact::CallReadBytes];
}

impl LaneReads {
    /// The registers with the bytes read of each, in the body's lane order.
    pub fn pairs(&self) -> &[(CanonicalStorageId, u32)] {
        &self.0
    }

    /// These reads less the registers `drop` names: a narrower bound is never minted.
    pub(crate) fn without(&self, drop: impl Fn(&CanonicalStorageId) -> bool) -> Self {
        Self(
            self.0
                .iter()
                .filter(|(slot, _)| !drop(slot))
                .copied()
                .collect(),
        )
    }

    #[cfg(test)]
    pub(crate) fn walked(pairs: &[(CanonicalStorageId, u32)]) -> Self {
        Self(pairs.into())
    }
}

/// How an operation takes part in the pass.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Mode {
    /// Its write may not happen: it belongs to an instruction that branches within itself.
    weak: bool,
    /// It changes nothing the program keeps (a multi-byte `nop` forms an address and drops it), so
    /// what it reads is no read.
    inert: bool,
    /// The inputs inside a register its instruction cancels against itself (`sbb edx, edx`), as
    /// `ignored`'s bits: no value read; more than two cancelled registers drop no read (D393).
    cancelled: u32,
    /// The inputs of the operation no effect of its instruction depends on (`r2il::eval::independence`).
    ignored: u32,
}

/// The inputs of `operation` inside one of `cancelled`, as bits; the first 32 inputs only.
fn cancelled_inputs(operation: &R2ILOp, cancelled: &[CanonicalStorageId]) -> u32 {
    if cancelled.is_empty() {
        return 0;
    }
    let inside = |input: &Varnode| {
        let input = CanonicalStorageId::from_varnode(input);
        cancelled.iter().any(|cancelled| {
            input.space == cancelled.space
                && cancelled.offset <= input.offset
                && input.offset + u64::from(input.size)
                    <= cancelled.offset + u64::from(cancelled.size)
        })
    };
    (operation.inputs().into_iter().enumerate().take(32))
        .filter(|(_, input)| inside(input))
        .fold(0, |bits, (at, _)| bits | 1 << at)
}

/// The mode of each operation of `block`: whole instructions are weak, inert or cancelling as their
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
            modes[run].ignored = reads_of(&block.ops[run..=run], false, endian).ignored()[0];
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
        // Past two cancelled registers no read is dropped: each input of the instruction stays one.
        let cancelled = match reads.cancelled().registers() {
            cancelled @ ([_] | [_, _]) => cancelled
                .iter()
                .map(CanonicalStorageId::from_varnode)
                .collect(),
            _ => Vec::new(),
        };
        let each = (modes[run..end].iter_mut()).zip(reads.ignored()).zip(ops);
        for ((mode, ignored), op) in each {
            mode.weak |= weak;
            mode.inert |= inert;
            mode.cancelled = cancelled_inputs(op, &cancelled);
            mode.ignored = *ignored;
        }
        run = end;
    }
    modes
}

/// Block indices by block, flat.
#[derive(Clone)]
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
            graph: Graph {
                starts,
                successors,
                predecessors,
                leaves,
                open: open_blocks,
                irregular,
                unwinds: Box::default(),
                unwinder: Box::default(),
            },
            modes,
            first,
        }
    }

    /// The flow with each call's (block, operation) unwind edge to a pad address, `unwinder` written
    /// on it (doc/adr-result-side.md, "Pads in the flow"). `O((B + E + U) log U)`.
    pub fn with_unwinds(
        mut self,
        unwinds: impl IntoIterator<Item = ((usize, usize), u64)>,
        unwinder: &[CanonicalStorageId],
    ) -> Self {
        let graph = &mut self.graph;
        let block_at = |address: u64| {
            let at = (graph.starts).binary_search_by_key(&address, |(start, _)| *start);
            at.ok().map_or(NO_BLOCK, |at| index(graph.starts[at].1))
        };
        let mut edges = (unwinds.into_iter())
            .map(|((block, op), pad)| (index(block), index(op), block_at(pad)))
            .collect::<Vec<_>>();
        edges.sort_unstable();
        edges.dedup_by_key(|(block, op, _)| (*block, *op));
        // A pad's live set moving requeues the call's block, so the pad counts among its successors' readers.
        let blocks = graph.leaves.len();
        let mut pairs = (0..blocks)
            .flat_map(|from| {
                (graph.successors.of_block(from).iter()).map(move |to| (*to, index(from)))
            })
            .collect::<Vec<_>>();
        pairs.extend(
            (edges.iter())
                .filter(|edge| edge.2 != NO_BLOCK)
                .map(|(block, _, pad)| (*pad, *block)),
        );
        graph.predecessors = Edges::of(blocks, pairs);
        graph.unwinds = edges.into();
        graph.unwinder = unwinder.into();
        self
    }

    /// Whether the operation at (block, op) is a call.
    pub fn is_call(&self, block: usize, op: usize) -> bool {
        self.blocks[block].lifted().ops[op].is_call()
    }

    /// The boundary at each of `sites` (block, operation), from one pass; one past its budget gives
    /// every site Unknown.
    pub fn site_fates(
        &self,
        lanes: ResultLanes,
        effects: &dyn CallEffects,
        sites: &[(usize, usize)],
    ) -> Vec<SiteBoundary> {
        site_fates_of(self, lanes, effects, sites)
    }

    /// What the body entered at `entry` does to its entry registers; none past the budget or where no
    /// block starts there. `O((B + E) × LANES)`.
    pub fn register_effect(
        &self,
        entry: u64,
        lanes: ResultLanes,
        effects: &dyn CallEffects,
        kept: &KeptBy<'_>,
    ) -> Option<RegisterEffect> {
        let at = self
            .graph
            .starts
            .binary_search_by_key(&entry, |(start, _)| *start)
            .ok()
            .map(|at| self.graph.starts[at].1)?;
        let tracked = Lanes::of(lanes);
        let pass = Pass::new(self, tracked, effects);
        let live = pass.solve(pass.budget())?.swap_remove(at);
        let (mut takes, mut overwrites) = (LaneBytes::default(), LaneBytes::default());
        for lane in 0..LANES {
            let taken = live.read[lane] | live.forwarded[lane] | live.open[lane];
            takes.0[lane] = taken;
            overwrites.0[lane] = tracked.all(lane) & !(taken | live.returned[lane]);
        }
        let (unwritten, pending) = self.unwritten(kept);
        Some(RegisterEffect {
            unwritten,
            pending,
            overwrites,
            takes,
            lanes,
            machine: kept.machine.clone(),
        })
    }

    /// The universe's registers no operation but a call writes where a return is reached, and those
    /// calls' callees; none past an open or undeclared exit, a call naming no callee or an unstated operation.
    fn unwritten(&self, by: &KeptBy<'_>) -> (UniverseSet, Box<[u64]>) {
        let KeptBy {
            machine,
            clobbers,
            never,
            callee,
        } = *by;
        let outermost = machine.outermost_registers();
        let none = (UniverseSet::empty(outermost.len()), Box::default());
        let mut returning = Vec::new();
        for (at, block) in self.blocks.iter().map(Lifted::lifted).enumerate() {
            if self.graph.open[at] || self.graph.leaves[at] || self.graph.irregular[at] {
                return none;
            }
            if (block.ops.iter()).any(|op| matches!(op, R2ILOp::Return { .. })) {
                returning.push(at);
            }
            if !self.graph.successors.of_block(at).is_empty() {
                continue;
            }
            match block.ops.last() {
                Some(R2ILOp::Return { .. }) => {}
                Some(op) if op.is_call() && never(at, block.ops.len() - 1) => {}
                _ => return none,
            }
        }
        // A body no return ends keeps nothing; else the blocks a return is reached from, `O(B + E)`.
        if returning.is_empty() {
            return none;
        }
        let mut reaching = vec![false; self.blocks.len()];
        while let Some(at) = returning.pop() {
            if !std::mem::replace(&mut reaching[at], true) {
                let from = self.graph.predecessors.of_block(at).iter();
                returning.extend(from.map(|from| *from as usize));
            }
        }
        // Across an unwind edge only callee-saved registers hold (Itanium C++ ABI 1.6.3): a pad that
        // reaches a return, or names no block, keeps nothing.
        let unwound = |(_, _, pad): &(u32, u32, u32)| *pad == NO_BLOCK || reaching[*pad as usize];
        if self.graph.unwinds.iter().any(unwound) {
            return none;
        }
        let mut written = UniverseSet::empty(outermost.len());
        let mut pending = Vec::new();
        let reached = (self.blocks.iter().enumerate()).filter(|(at, _)| reaching[*at]);
        let operations = reached.flat_map(|(at, block)| {
            (block.lifted().ops.iter().enumerate()).map(move |(op, operation)| (at, op, operation))
        });
        for (at, op, operation) in operations {
            if operation.is_call() {
                match callee(at, op) {
                    Some(entered) => pending.push(entered),
                    None => return none,
                }
                continue;
            }
            let through = |access: r2il::MemoryAccess<'_>| access.space == SpaceId::Register;
            if operation.reads_unstated() || operation.memory_accesses().any(through) {
                return none;
            }
            let output = operation
                .output()
                .filter(|out| out.space == SpaceId::Register);
            let storage = output.map(CanonicalStorageId::from_varnode);
            let overlapped = storage.map(|storage| overlapping(outermost, storage));
            overlapped
                .into_iter()
                .flatten()
                .for_each(|at| written.insert(at));
        }
        pending.sort_unstable();
        pending.dedup();
        match clobbers {
            Some(clobbers) => (
                CallUniverse::of(clobbers, machine)
                    .clobbered
                    .without(&written),
                pending.into(),
            ),
            None => none,
        }
    }
}

/// One operation as a lane pass reads it: an inert one is no step (doc/adr-result-side.md, "D589").
#[derive(Clone, Copy)]
struct Step {
    op: usize,
    /// Its write may not happen.
    weak: bool,
    call: bool,
    ret: bool,
    /// The lift does not state what it reads.
    unstated: bool,
    /// The lane bytes its output covers.
    writes: [Bytes; LANES],
    /// The lane bytes its inputs cover, less those its instruction reads in form only.
    reads: [Bytes; LANES],
}

impl Step {
    /// Whether `Pass::step` leaves every live set as it finds it: no call, return or unstated read,
    /// and no lane byte written or read.
    fn is_identity(&self) -> bool {
        !(self.call || self.ret || self.unstated)
            && self.writes == [0; LANES]
            && self.reads == [0; LANES]
    }
}

/// What a lane pass reads of a body: the lifted blocks, or their projection ([`LaneFlow`]).
trait Steps {
    fn graph(&self) -> &Graph;
    /// The steps of `block`'s operations in `ops`, last first, their bytes in `lanes`.
    fn steps_back(
        &self,
        block: usize,
        ops: std::ops::Range<usize>,
        lanes: &Lanes,
        visit: impl FnMut(&Step),
    );
    /// Every call, by block and operation, in order.
    fn calls(&self) -> impl Iterator<Item = (usize, usize)>;
    /// What the call's block states `register` holds where it runs.
    fn count(&self, block: usize, op: usize, register: CanonicalStorageId) -> Count;
    /// Whether the call's own instruction may skip it.
    fn predicated(&self, block: usize, op: usize) -> bool;
}

impl<B: Lifted> Steps for CallerFlow<'_, B> {
    fn graph(&self) -> &Graph {
        &self.graph
    }

    fn steps_back(
        &self,
        block: usize,
        ops: std::ops::Range<usize>,
        lanes: &Lanes,
        mut visit: impl FnMut(&Step),
    ) {
        let operations = &self.blocks[block].lifted().ops;
        let first = self.first[block] as usize;
        for op in (ops.start..ops.end.min(operations.len())).rev() {
            let mode = self.modes[first + op];
            if mode.inert {
                continue;
            }
            visit(&step_of(&operations[op], op, mode, lanes));
        }
    }

    fn calls(&self) -> impl Iterator<Item = (usize, usize)> {
        (self.blocks.iter().enumerate()).flat_map(|(block, found)| {
            let ops = &found.lifted().ops;
            (0..ops.len())
                .filter(|op| ops[*op].is_call())
                .map(move |op| (block, op))
        })
    }

    fn count(&self, block: usize, op: usize, register: CanonicalStorageId) -> Count {
        count_of(self.blocks[block].lifted(), op, register)
    }

    fn predicated(&self, block: usize, op: usize) -> bool {
        predicated(self.blocks[block].lifted(), op)
    }
}

/// `operation` as a step, its bytes in `lanes`. `O(inputs × LANES)`.
fn step_of(operation: &R2ILOp, op: usize, mode: Mode, lanes: &Lanes) -> Step {
    let ignored = mode.ignored | mode.cancelled;
    let mut reads = [0; LANES];
    for (at, input) in operation.inputs().into_iter().enumerate() {
        if ignored == u32::MAX || (at < 32 && ignored >> at & 1 == 1) {
            continue;
        }
        merge(&mut reads, lanes.bytes_in(input));
    }
    Step {
        op,
        weak: mode.weak,
        call: operation.is_call(),
        ret: matches!(operation, R2ILOp::Return { .. }),
        unstated: operation.reads_unstated(),
        writes: (operation.output()).map_or([0; LANES], |output| lanes.bytes_in(output)),
        reads,
    }
}

/// One solve of one body for one set of lanes.
struct Pass<'p, F> {
    flow: &'p F,
    lanes: Lanes,
    effects: &'p dyn CallEffects,
    /// What each counting call's block states of its count, by block and operation.
    counts: std::collections::BTreeMap<(usize, usize), Count>,
}

impl<'p, F: Steps> Pass<'p, F> {
    fn new(flow: &'p F, lanes: Lanes, effects: &'p dyn CallEffects) -> Self {
        let counted = flow.calls().filter_map(|(block, op)| {
            let counted = effects.at(block, op).counted?;
            Some(((block, op), flow.count(block, op, counted.register)))
        });
        Self {
            flow,
            lanes,
            effects,
            counts: counted.collect(),
        }
    }

    /// What the call at `op` takes and does: a variadic callee's vector registers are taken unless
    /// the call states it uses none, and a fixed one takes more where the call states a count.
    fn call_at(&self, block: usize, op: usize) -> CallEffect {
        let mut call = self.effects.at(block, op);
        let Some(counted) = call.counted.take() else {
            return call;
        };
        let count = self
            .counts
            .get(&(block, op))
            .copied()
            .unwrap_or(Count::Other);
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
        let blocks = self.flow.graph().leaves.len();
        blocks.saturating_mul(height + 1).saturating_add(blocks)
    }

    /// Live bytes at every block's start, or none where the pass visited more blocks than `budget`.
    fn solve(&self, budget: usize) -> Option<Vec<Live>> {
        let graph = self.flow.graph();
        let blocks = graph.leaves.len();
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
            (self.flow).steps_back(block, 0..usize::MAX, &self.lanes, |step| {
                self.step(&mut live, block, step, &live_in);
            });
            if live != live_in[block] {
                live_in[block] = live;
                work.extend((graph.predecessors.of_block(block).iter()).map(|from| *from as usize));
            }
        }
        Some(live_in)
    }

    /// The bytes live where `block` ends: its successors' starts, and everything where it leaves
    /// the body or the walk lost it.
    fn out_of(&self, block: usize, live_in: &[Live]) -> Live {
        let graph = self.flow.graph();
        let mut out = Live::default();
        for successor in graph.successors.of_block(block) {
            out.join(&live_in[*successor as usize]);
        }
        for lane in 0..LANES {
            if graph.leaves[block] {
                out.forwarded[lane] |= self.lanes.all(lane);
            }
            if graph.open[block] || graph.irregular[block] {
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
        let mut live = self.out_of(block, live_in);
        let mut next = usize::MAX;
        for (site, op) in wanted {
            (self.flow).steps_back(block, op + 1..next, &self.lanes, |step| {
                self.step(&mut live, block, step, live_in);
            });
            next = next.min(op + 1);
            if !self.flow.predicated(block, op) {
                fates[site].fates = self.fate_of(&live);
            }
        }
    }

    /// Move `live` from after the step to before it; a call that may unwind joins its pad's entry.
    fn step(&self, live: &mut Live, block: usize, step: &Step, live_in: &[Live]) {
        let call = step.call.then(|| self.call_at(block, step.op));
        // What the operation overwrites ends those bytes' liveness, ahead of what it reads.
        if !step.weak {
            live.kill_all(match &call {
                Some(call) => self.overwritten(call),
                None => step.writes,
            });
        }
        // A read past a write that may not happen, a call that may leave a byte as it found it or
        // an operation with unstated effects may read that operation's value: no proof of ours.
        let doubtful = match &call {
            Some(call) if call.overwrites != Overwrites::All => {
                unkept(self.lanes.every(), call.kept)
            }
            _ if step.unstated => self.lanes.every(),
            _ if step.weak => step.writes,
            _ => [0; LANES],
        };
        for ((open, read), doubt) in live.open.iter_mut().zip(&mut live.read).zip(doubtful) {
            *open |= *read & doubt;
            *read &= !doubt;
        }
        if step.ret {
            merge(&mut live.returned, self.lanes.every());
        }
        if let Some(call) = &call {
            merge(&mut live.open, call.takes.0);
            merge(&mut live.read, call.reads.0);
        }
        // Reads the lift does not state may be of any lane: open, never dead.
        if step.unstated {
            merge(&mut live.open, self.lanes.every());
        }
        merge(&mut live.read, step.reads);
        if let Some(pad) = step
            .call
            .then(|| self.flow.graph().unwind(block, step.op))
            .flatten()
        {
            live.join(&self.pad_entry(pad, live_in));
        }
    }

    /// What is live before an unwinding call through its pad: the unwinder's lanes killed, the rest
    /// open ("Pads in the flow"); a pad no block starts loses every lane.
    fn pad_entry(&self, pad: u32, live_in: &[Live]) -> Live {
        let every = self.lanes.every();
        if pad == NO_BLOCK {
            return Live {
                open: every,
                ..Live::default()
            };
        }
        let mut entry = live_in[pad as usize];
        let mut killed = [0; LANES];
        for register in &self.flow.graph().unwinder {
            let varnode = Varnode::register(register.offset, register.size);
            merge(&mut killed, self.lanes.bytes_in(&varnode));
        }
        entry.kill_all(killed);
        for lane in 0..LANES {
            let doubt = every[lane] & !killed[lane];
            let held = entry.read[lane] | entry.returned[lane] | entry.forwarded[lane];
            entry.open[lane] |= held & doubt;
            entry.read[lane] &= !doubt;
            entry.returned[lane] &= !doubt;
            entry.forwarded[lane] &= !doubt;
        }
        entry
    }

    /// The bytes a call overwrites, by its callee.
    fn overwritten(&self, call: &CallEffect) -> [Bytes; LANES] {
        match call.overwrites {
            Overwrites::Nothing => [0; LANES],
            Overwrites::Bytes(written) => written.0,
            Overwrites::All => self.lanes.every(),
        }
    }

    fn fate_of(&self, live: &Live) -> [Option<LaneFate>; LANES] {
        std::array::from_fn(|at| self.lanes.0[at].map(|_| live.fate(at)))
    }
}

/// The boundary at each of `sites` from one pass over `flow`; past its budget every site is Unknown.
fn site_fates_of<F: Steps>(
    flow: &F,
    lanes: ResultLanes,
    effects: &dyn CallEffects,
    sites: &[(usize, usize)],
) -> Vec<SiteBoundary> {
    let mut fates = vec![SiteBoundary::unknown(lanes); sites.len()];
    if sites.is_empty() {
        return fates;
    }
    let pass = Pass::new(flow, Lanes::of(lanes), effects);
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

/// A body's flow as its lane pass reads it, without its lift (doc/adr-result-side.md, "D589 as
/// built"), and giving the lift's fates. Size `O(B + E + steps)`.
pub struct LaneFlow {
    lanes: ResultLanes,
    graph: Graph,
    /// Each block's first event, and one past the last.
    first: Box<[u32]>,
    events: Box<[Event]>,
    /// Each event's nonzero lane bytes: those written, then those read, lane by lane.
    bytes: Box<[Bytes]>,
    /// Each call by block and operation, ascending.
    calls: Box<[CallEvent]>,
}

/// A step, its lane bytes in `LaneFlow::bytes` from `at`.
#[derive(Clone, Copy)]
struct Event {
    op: u32,
    at: u32,
    /// `weak`, `call`, `ret`, `unstated` from bit 0.
    flags: u8,
    /// The lanes with bytes written, and with bytes read, one bit each.
    written: u8,
    read: u8,
}

#[derive(Clone, Copy)]
struct CallEvent {
    block: u32,
    op: u32,
    /// The count register a caller's effect named at the projection, and what the block states of it.
    count: Option<(CanonicalStorageId, Count)>,
    predicated: bool,
}

/// The lanes `plane` holds bytes in, one bit each.
fn lane_mask(plane: &[Bytes; LANES]) -> u8 {
    (0..LANES)
        .filter(|lane| plane[*lane] != 0)
        .fold(0u8, |bits, lane| bits | 1 << lane)
}

impl Event {
    /// `step`, its byte sets stored from `at` of the flow's bytes.
    fn of(step: &Step, at: usize) -> Self {
        Self {
            op: index(step.op),
            at: index(at),
            flags: u8::from(step.weak)
                | u8::from(step.call) << 1
                | u8::from(step.ret) << 2
                | u8::from(step.unstated) << 3,
            written: lane_mask(&step.writes),
            read: lane_mask(&step.reads),
        }
    }
}

impl CallEvent {
    /// The call at `(block, op)`, with what its block states of the count register `counted`.
    fn of<B: Lifted>(
        flow: &CallerFlow<'_, B>,
        (block, op): (usize, usize),
        counted: Option<CanonicalStorageId>,
    ) -> Self {
        Self {
            block: index(block),
            op: index(op),
            count: counted.map(|register| (register, flow.count(block, op, register))),
            predicated: flow.predicated(block, op),
        }
    }
}

impl LaneFlow {
    /// The steps of `flow` in `lanes`, each call's count of the register `counted` names. `O(ops)`.
    pub fn of<B: Lifted>(
        flow: &CallerFlow<'_, B>,
        lanes: ResultLanes,
        counted: impl Fn(usize, usize) -> Option<CanonicalStorageId>,
    ) -> Self {
        let tracked = Lanes::of(lanes);
        let (mut first, mut events, mut bytes, mut calls) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for block in 0..flow.blocks.len() {
            first.push(index(events.len()));
            let mut steps = Vec::new();
            flow.steps_back(block, 0..usize::MAX, &tracked, |step| steps.push(*step));
            for step in steps.iter().rev().filter(|step| !step.is_identity()) {
                events.push(Event::of(step, bytes.len()));
                bytes.extend(
                    step.writes
                        .iter()
                        .chain(&step.reads)
                        .filter(|held| **held != 0),
                );
                let call = step.call.then_some((block, step.op));
                calls.extend(call.map(|at| CallEvent::of(flow, at, counted(at.0, at.1))));
            }
        }
        first.push(index(events.len()));
        Self {
            lanes,
            graph: flow.graph.clone(),
            first: first.into(),
            events: events.into(),
            bytes: bytes.into(),
            calls: calls.into(),
        }
    }

    /// The lanes its steps are in.
    pub fn lanes(&self) -> ResultLanes {
        self.lanes
    }

    /// The count register named at the projection for the call at (block, op).
    pub fn count_register(&self, block: usize, op: usize) -> Option<CanonicalStorageId> {
        Some(self.call(block, op)?.count?.0)
    }

    /// The boundary at each of `sites`, as [`CallerFlow::site_fates`] gives it over the lift.
    pub fn site_fates(
        &self,
        effects: &dyn CallEffects,
        sites: &[(usize, usize)],
    ) -> Vec<SiteBoundary> {
        site_fates_of(self, self.lanes, effects, sites)
    }

    /// The bytes it holds on the heap.
    pub fn heap_bytes(&self) -> usize {
        let graph = &self.graph;
        let edges = |edges: &Edges| 4 * (edges.starts.len() + edges.items.len());
        16 * graph.starts.len()
            + 12 * graph.unwinds.len()
            + edges(&graph.successors)
            + edges(&graph.predecessors)
            + 3 * graph.leaves.len()
            + 4 * self.first.len()
            + size_of::<Event>() * self.events.len()
            + size_of::<Bytes>() * self.bytes.len()
            + size_of::<CallEvent>() * self.calls.len()
    }

    fn call(&self, block: usize, op: usize) -> Option<&CallEvent> {
        let key = (index(block), index(op));
        let at = (self.calls).binary_search_by_key(&key, |call| (call.block, call.op));
        at.ok().map(|at| &self.calls[at])
    }
}

impl Steps for LaneFlow {
    fn graph(&self) -> &Graph {
        &self.graph
    }

    fn steps_back(
        &self,
        block: usize,
        ops: std::ops::Range<usize>,
        lanes: &Lanes,
        mut visit: impl FnMut(&Step),
    ) {
        debug_assert!(Lanes::of(self.lanes).every() == lanes.every());
        let events = &self.events[self.first[block] as usize..self.first[block + 1] as usize];
        let from = events.partition_point(|event| (event.op as usize) < ops.start);
        let to = events.partition_point(|event| (event.op as usize) < ops.end);
        for event in events[from..to].iter().rev() {
            let mut held = self.bytes[event.at as usize..].iter();
            let mut unpack = |mask: u8| {
                std::array::from_fn(|lane| match mask >> lane & 1 {
                    1 => *held.next().expect("a byte set per lane bit"),
                    _ => 0,
                })
            };
            let writes = unpack(event.written);
            let reads = unpack(event.read);
            visit(&Step {
                op: event.op as usize,
                weak: event.flags & 1 != 0,
                call: event.flags & 2 != 0,
                ret: event.flags & 4 != 0,
                unstated: event.flags & 8 != 0,
                writes,
                reads,
            });
        }
    }

    fn calls(&self) -> impl Iterator<Item = (usize, usize)> {
        (self.calls.iter()).map(|call| (call.block as usize, call.op as usize))
    }

    /// The count stated at the projection, where `register` is the one named there; any other
    /// register's is no statement.
    fn count(&self, block: usize, op: usize, register: CanonicalStorageId) -> Count {
        match self.call(block, op).and_then(|call| call.count) {
            Some((named, count)) if named == register => count,
            _ => Count::Other,
        }
    }

    fn predicated(&self, block: usize, op: usize) -> bool {
        self.call(block, op).is_none_or(|call| call.predicated)
    }
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

/// What becomes of one register's value from a point of a body (S30, doc/adr-call-boundary.md
/// "S30 as built"): no path reads it, every path hands it only to transfers' arguments, or other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterFate {
    /// No path reads, returns, loses or hands it on: overwritten, or the path ends first.
    Dead,
    /// Every path that does not drop it hands it to these transfers' arguments, ascending.
    Handed(Box<[Handoff]>),
    /// Some path reads it, returns it, leaves it where the walk did not follow, or ran past the budget.
    Other,
}

/// One transfer the register reaches as an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handoff {
    /// The instruction making the transfer.
    pub instruction: u64,
    pub target: Transfer,
    pub storage: CanonicalStorageId,
}

/// Where a transfer goes, as its operation encodes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transfer {
    Direct(u64),
    Indirect,
}

/// What a body's transfers do with one register: S25's per-site reads, asked of the call or tail
/// transfer at (block, operation).
pub trait CallReadsAt {
    /// The function or loader slot the walk read the transfer at (block, operation) going to.
    fn target(&self, block: usize, op: usize) -> Option<u64>;
    /// Whether the transfer may read `register` as an argument.
    fn reads(&self, block: usize, op: usize, register: CanonicalStorageId) -> bool;
    /// Whether the call overwrites `register` on every path back, so a later read is the call's.
    fn overwrites(&self, block: usize, op: usize, register: CanonicalStorageId) -> bool;
}

impl<B: Lifted> CallerFlow<'_, B> {
    /// The fate of `register` after operation `op` of `block`. `O(B + E)` operations: each block is
    /// walked once, since the one tracked value is alive or not at its start.
    pub fn fate_after(
        &self,
        block: usize,
        op: usize,
        register: CanonicalStorageId,
        reads: &dyn CallReadsAt,
    ) -> RegisterFate {
        self.fate_from((block, op + 1), register, reads)
    }

    /// The fate of `register` as the body entered at `entry` is entered; `Other` where no block starts there.
    pub fn fate_from_entry(
        &self,
        entry: u64,
        register: CanonicalStorageId,
        reads: &dyn CallReadsAt,
    ) -> RegisterFate {
        let at = self
            .graph
            .starts
            .binary_search_by_key(&entry, |(start, _)| *start);
        match at.ok().map(|at| self.graph.starts[at].1) {
            Some(block) => self.fate_from((block, 0), register, reads),
            None => RegisterFate::Other,
        }
    }

    fn fate_from(
        &self,
        start: (usize, usize),
        register: CanonicalStorageId,
        reads: &dyn CallReadsAt,
    ) -> RegisterFate {
        // A value reaching a pad is read by no transfer this walk follows: no proof (D598).
        if !self.graph.unwinds.is_empty() {
            return RegisterFate::Other;
        }
        let mut seen = vec![false; self.blocks.len()];
        let mut pending = vec![start];
        let mut handed = Vec::new();
        while let Some((block, from)) = pending.pop() {
            match self.fate_in(block, from, register, reads, &mut handed) {
                Walked::Other => return RegisterFate::Other,
                Walked::Ends => {}
                Walked::RunsOn => {
                    for next in self.graph.successors.of_block(block) {
                        let next = *next as usize;
                        if !std::mem::replace(&mut seen[next], true) {
                            pending.push((next, 0));
                        }
                    }
                }
            }
        }
        handed.sort_unstable();
        handed.dedup();
        match handed.is_empty() {
            true => RegisterFate::Dead,
            false => RegisterFate::Handed(handed.into()),
        }
    }

    /// One block from operation `from`: what the tracked value meets before the block ends.
    fn fate_in(
        &self,
        block: usize,
        from: usize,
        register: CanonicalStorageId,
        reads: &dyn CallReadsAt,
        handed: &mut Vec<Handoff>,
    ) -> Walked {
        // A block's own leaving transfer is read below; only control past its end is open.
        if self.graph.irregular[block] {
            return Walked::Other;
        }
        let lifted = self.blocks[block].lifted();
        let holds = |address: u64| {
            let at = self
                .graph
                .starts
                .binary_search_by_key(&address, |(start, _)| *start);
            at.is_ok()
        };
        for (at, operation) in lifted.ops.iter().enumerate().skip(from) {
            let mode = self.modes[self.first[block] as usize + at];
            let instruction = lifted.instruction_of(at).unwrap_or(lifted.addr);
            if let Some(transfer) = operation.transfer()
                && !operation.is_local_branch()
            {
                let encoded = transfer.direct && transfer.target.space == SpaceId::Ram;
                let target = match (reads.target(block, at), encoded) {
                    (Some(read), _) => Transfer::Direct(read),
                    (None, true) => Transfer::Direct(transfer.target.offset),
                    (None, false) => Transfer::Indirect,
                };
                let leaves = !transfer.call
                    && (!encoded || !holds(transfer.target.offset))
                    && !operation.is_local_branch();
                // A call through the register, or a branch through it, reads it.
                if !transfer.direct && covers_any(transfer.target, register) {
                    return Walked::Other;
                }
                if transfer.call || leaves {
                    if reads.reads(block, at, register) {
                        handed.push(Handoff {
                            instruction,
                            target,
                            storage: register,
                        });
                    }
                    if leaves && target == Transfer::Indirect {
                        return Walked::Other;
                    }
                    if leaves && !matches!(operation, R2ILOp::CBranch { .. }) {
                        return Walked::Ends;
                    }
                    if transfer.call && reads.overwrites(block, at, register) {
                        return Walked::Ends;
                    }
                    continue;
                }
            }
            if matches!(operation, R2ILOp::Return { .. }) {
                return Walked::Other;
            }
            if mode.inert {
                continue;
            }
            // An instruction cancelling a register against itself reads no value of it.
            let read = (operation.inputs().into_iter().enumerate()).any(|(at, input)| {
                covers_any(input, register) && (at >= 32 || mode.cancelled & 1 << at == 0)
            });
            if read {
                return Walked::Other;
            }
            let written = operation
                .output()
                .filter(|out| out.space == SpaceId::Register);
            let whole = written.is_some_and(|out| {
                let out = CanonicalStorageId::from_varnode(out);
                out.offset <= register.offset
                    && register.offset + u64::from(register.size)
                        <= out.offset + u64::from(out.size)
            });
            if whole && !mode.weak {
                return Walked::Ends;
            }
        }
        if self.graph.leaves[block] || self.graph.open[block] {
            return Walked::Other;
        }
        Walked::RunsOn
    }
}

/// What one block's walk meets.
enum Walked {
    /// The value is overwritten or control leaves for good: the path ends.
    Ends,
    /// It is still alive where the block ends.
    RunsOn,
    Other,
}

/// Whether `varnode` names a byte of `register`.
fn covers_any(varnode: &Varnode, register: CanonicalStorageId) -> bool {
    varnode.space == SpaceId::Register
        && overlap(CanonicalStorageId::from_varnode(varnode), register)
}

/// Whether two storages share a byte.
fn overlap(a: CanonicalStorageId, b: CanonicalStorageId) -> bool {
    a.space == b.space
        && a.offset < b.offset.saturating_add(u64::from(b.size))
        && b.offset < a.offset.saturating_add(u64::from(a.size))
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
            LaneFate::Read { .. } => K::Read,
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
        projected(&flow, effects, &[(0, 0)]).swap_remove(0)
    }

    /// The fates at `sites` over the lift, checked equal to its projection's (D589).
    fn projected(
        flow: &CallerFlow<'_, R2ILBlock>,
        effects: &dyn CallEffects,
        sites: &[(usize, usize)],
    ) -> Vec<SiteBoundary> {
        let lifted = flow.site_fates(LANES, effects, sites);
        let counted = |block, op| {
            effects
                .at(block, op)
                .counted
                .map(|counted| counted.register)
        };
        let projection = super::LaneFlow::of(flow, LANES, counted);
        assert_eq!(projection.site_fates(effects, sites), lifted);
        lifted
    }

    /// `call f` among 40 operations that touch no lane, then a read of EAX and a counted call: the
    /// projection keeps 4 steps and gives the lift's fates at both calls (D589).
    #[test]
    fn a_projection_of_lane_free_operations_gives_the_lifts_fates() {
        let quiet = |at: u64| write(0x40 + 8 * (at % 4), 8);
        let al = R2ILOp::Copy {
            dst: Varnode::register(0, 1),
            src: Varnode::constant(0, 1),
        };
        let ops = [
            (0..20).map(quiet).collect::<Vec<_>>(),
            vec![call()],
            (20..40).map(quiet).collect(),
            vec![al, call(), store(0, 4), ret()],
        ]
        .concat();
        let blocks = [block(0x1000, 64, ops)];
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
        let fated = projected(&flow, &Variadic, &[(0, 20), (0, 42)]);
        assert_eq!(fated.len(), 2);
        let projection = super::LaneFlow::of(&flow, LANES, |_, _| None);
        assert_eq!(
            projection.events.len(),
            5,
            "two calls, the AL write, the read, the return"
        );
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
        let fated = flow.site_fates(LANES, NOTHING, &[(0, 1)]);
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

    /// `eor3 v0, v2, v1, v1` cancels v1 against itself and reads v2: an instruction cancelling EDX
    /// still reads the EAX a call left (D393). Before, it read none of its inputs.
    #[test]
    fn an_instruction_cancelling_one_register_still_reads_another() {
        let edx = || Varnode::register(0x10, 4);
        let cancel = R2ILOp::IntXor {
            dst: Varnode::unique(0x40, 4),
            a: edx(),
            b: edx(),
        };
        let add = R2ILOp::IntAdd {
            dst: Varnode::register(0, 4),
            a: Varnode::register(0, 4),
            b: Varnode::unique(0x40, 4),
        };
        let mut block = R2ILBlock::new(0x1000, 16);
        block.push_from(call(), 0x1000);
        for op in [cancel, add] {
            block.push_from(op, 0x1004);
        }
        block.push_from(zero_extend(), 0x1004);
        block.push_from(ret(), 0x1008);
        assert_eq!(integer(fates(&[block], &[], &[])), K::Read);
    }

    /// A vector self-xor lifted as two lane xors cancels both lanes; EAX beside them stays a read.
    #[test]
    fn an_instruction_cancelling_two_lanes_still_reads_another_register() {
        let lane = |offset| Varnode::register(offset, 8);
        let cancel = |offset, out| R2ILOp::IntXor {
            dst: Varnode::unique(out, 8),
            a: lane(offset),
            b: lane(offset),
        };
        let both = R2ILOp::IntOr {
            dst: Varnode::unique(0x50, 8),
            a: Varnode::unique(0x40, 8),
            b: Varnode::unique(0x48, 8),
        };
        let add = R2ILOp::IntAdd {
            dst: Varnode::register(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x50, 8),
        };
        let mut block = R2ILBlock::new(0x1000, 16);
        block.push_from(call(), 0x1000);
        for op in [cancel(0x1300, 0x40), cancel(0x1308, 0x48), both, add] {
            block.push_from(op, 0x1004);
        }
        block.push_from(zero_extend(), 0x1004);
        block.push_from(ret(), 0x1008);
        assert_eq!(integer(fates(&[block], &[], &[])), K::Read);
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
            flow.site_fates(lanes, NOTHING, &[(0, 0)]).swap_remove(0)
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
                .site_fates(lanes, NOTHING, &[(0, 0)])
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
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
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
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
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
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
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
        let fated = projected(&flow, NOTHING, &[(0, 1)]);
        assert_eq!(integer(fated[0].clone()), K::Unknown);
        let plain = [block(
            0x1000,
            4,
            vec![call(), zero_eax(), zero_extend(), ret()],
        )];
        assert_eq!(integer(fates(&plain, &[], &[])), K::Dead);
    }

    /// Calls in block 0 overwrite every lane; the pad's call (block 1, op 1) too: what reaches the
    /// pad's entry is its first operation's read alone.
    struct Clobbering;

    impl CallEffects for Clobbering {
        fn at(&self, _block: usize, _op: usize) -> CallEffect {
            CallEffect {
                takes: LaneBytes::default(),
                counted: None,
                overwrites: Overwrites::All,
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
            }
        }
    }

    /// `call f; call g` (g unwinds to the pad at 0x1010); `ret`. The pad reads `read` at
    /// `size` bytes, calls, and returns. The fates at both calls, with and without the edge.
    fn unwinding(read: u64, size: u32, unwinder: &[CanonicalStorageId]) -> [[SiteBoundary; 2]; 2] {
        let blocks = [
            block(0x1000, 16, vec![call(), call(), ret()]),
            block(0x1010, 16, vec![store(read, size), call(), ret()]),
        ];
        let sites = [(0, 0), (0, 1)];
        let fates = |unwinds: &[((usize, usize), u64)]| {
            let flow = CallerFlow::new(&blocks, [], [], Endianness::Little)
                .with_unwinds(unwinds.iter().copied(), unwinder);
            let fated = projected(&flow, &Clobbering, &sites);
            [fated[0].clone(), fated[1].clone()]
        };
        [fates(&[]), fates(&[((0, 1), 0x1010)])]
    }

    /// The unwinding call's own fate is its normal return's: the callee returned no result to the pad.
    #[test]
    fn a_calls_own_fate_is_its_normal_returns_whatever_its_pad_reads() {
        let [without, with] = unwinding(0, 8, &[RAX, RDX]);
        assert_eq!(with[1], without[1]);
        assert_eq!(integer(with[1].clone()), K::Returned);
    }

    /// An earlier call's RAX reaching a pad's read of RAX is the unwinder's value, not the call's.
    #[test]
    fn a_pads_read_of_a_register_the_unwinder_writes_reads_no_earlier_call() {
        let [without, with] = unwinding(0, 8, &[RAX, RDX]);
        assert_eq!(integer(without[0].clone()), K::Dead);
        assert_eq!(integer(with[0].clone()), K::Dead);
        // No register the unwinder writes is cited: the read is open, never dead.
        let [_, unstated] = unwinding(0, 8, &[]);
        assert_eq!(integer(unstated[0].clone()), K::Unknown);
    }

    /// An earlier call's XMM0 reaching a pad's read of XMM0: the ABI leaves it undefined, so open.
    #[test]
    fn a_pads_read_of_an_undefined_register_is_open_never_dead() {
        let [without, with] = unwinding(0x1200, 8, &[RAX, RDX]);
        assert_eq!(shape(without[0].fates[FLOAT_LANE]), Some(K::Dead));
        assert_eq!(shape(with[0].fates[FLOAT_LANE]), Some(K::Unknown));
    }

    /// A pad edge to an address no block starts loses every lane before the call.
    #[test]
    fn a_pad_no_block_starts_loses_every_lane() {
        let blocks = [block(0x1000, 16, vec![call(), call(), ret()])];
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little)
            .with_unwinds([((0, 1), 0x2000)], &[RAX, RDX]);
        let fated = projected(&flow, &Clobbering, &[(0, 0)]);
        assert_eq!(integer(fated[0].clone()), K::Unknown);
    }

    /// A body whose pad reaches a return keeps nothing: across the edge only callee-saved registers hold.
    #[test]
    fn a_pad_that_reaches_a_return_keeps_nothing_across_its_edge() {
        let blocks = [
            block(0x1000, 16, vec![call(), ret()]),
            block(0x1010, 16, vec![write(0x40, 8), ret()]),
        ];
        let machine = machine();
        let rsp = CanonicalStorageId {
            offset: 0x20,
            ..RAX
        };
        let clobbers = |storage: CanonicalStorageId| storage != rsp;
        let callee = |_: usize, _: usize| Some(0x2000);
        let by = super::KeptBy {
            machine: &machine,
            clobbers: Some(&clobbers),
            never: &|_, _| false,
            callee: &callee,
        };
        let kept = |unwinds: &[((usize, usize), u64)]| {
            let flow = CallerFlow::new(&blocks, [], [], Endianness::Little)
                .with_unwinds(unwinds.iter().copied(), &[RAX, RDX]);
            let effect = flow
                .register_effect(0x1000, LANES, NOTHING, &by)
                .expect("an entry");
            effect.unwritten_registers().count()
        };
        assert!(kept(&[]) > 0);
        assert_eq!(kept(&[((0, 0), 0x1010)]), 0);
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
        let fate = flow.site_fates(lanes, NOTHING, &[(0, 0)]).swap_remove(0);
        assert_eq!(shape(fate.fates[2]), Some(K::Unknown));
        // The same read of the whole of EDX, with nothing written above it, is the value.
        let blocks = [block(0x1000, 8, vec![call(), store(0x10, 4), ret()])];
        let flow = CallerFlow::new(&blocks, [], [], Endianness::Little);
        let fate = flow.site_fates(lanes, NOTHING, &[(0, 0)]).swap_remove(0);
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
        let fate = flow.site_fates(lanes, NOTHING, &[(0, 0)]).swap_remove(0);
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
            .site_fates(lanes, NOTHING, &[(0, 0)])
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
                .site_fates(lanes, NOTHING, &[(0, 0)])
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

    /// `call f; call leaf; movq [rdi], xmm0`: a leaf that keeps XMM0 leaves f's, so the read is
    /// f's; one that keeps only RAX may have changed it.
    #[test]
    fn a_read_past_a_later_call_that_keeps_the_lane_is_the_earlier_calls_read() {
        let blocks = [block(
            0x1000,
            8,
            vec![call(), call(), store(0x1200, 8), ret()],
        )];
        let after = |kept: &[CanonicalStorageId]| {
            let later = Later(CallEffect {
                counted: None,
                takes: LaneBytes::default(),
                overwrites: Overwrites::Bytes(LaneBytes::covered_by(LANES, &[RAX])),
                kept: LaneBytes::covered_by(LANES, kept),
                reads: LaneBytes::default(),
            });
            let fate = fates_with(&blocks, &[], &[], &later);
            (shape(fate.fates[0]), shape(fate.fates[FLOAT_LANE]))
        };
        assert_eq!(after(&[XMM0]), (Some(K::Dead), Some(K::Read)));
        assert_eq!(after(&[]), (Some(K::Dead), Some(K::Unknown)));
        assert_eq!(after(&[RDX]), (Some(K::Dead), Some(K::Unknown)));
    }

    /// RAX, RDX, the vector registers and the rest the tests name; RSP is the one a call preserves.
    fn machine() -> crate::Arch {
        let mut spec = r2il::ArchSpec::new("x86-64");
        spec.addr_size = 8;
        for (name, offset, size) in [
            ("RAX", 0, 8),
            ("EAX", 0, 4),
            ("RDX", 0x10, 8),
            ("RSP", 0x20, 8),
            ("RSI", 0x30, 8),
            ("RDI", 0x38, 8),
            ("R8", 0x40, 8),
            ("cond", 0x100, 1),
            ("XMM0", 0x1200, 16),
            ("XMM1", 0x1240, 16),
        ] {
            spec.add_register(r2il::RegisterDef::new(name, offset, size));
        }
        crate::Arch::new(spec)
    }

    fn effect_with(
        blocks: &[R2ILBlock],
        edges: &[(usize, u64)],
        open: &[usize],
        never: &dyn Fn(usize, usize) -> bool,
    ) -> super::RegisterEffect {
        let rsp = CanonicalStorageId {
            offset: 0x20,
            ..RAX
        };
        let clobbers = |storage: CanonicalStorageId| storage != rsp;
        let machine = machine();
        let flow = CallerFlow::new(
            blocks,
            edges.iter().copied(),
            open.iter().copied(),
            Endianness::Little,
        );
        // A direct call enters its target; any other call names no callee.
        let callee = |block: usize, op: usize| match &blocks[block].ops[op] {
            R2ILOp::Call { target } => Some(target.offset),
            _ => None,
        };
        let by = super::KeptBy {
            machine: &machine,
            clobbers: Some(&clobbers),
            never,
            callee: &callee,
        };
        flow.register_effect(0x1000, LANES, NOTHING, &by)
            .expect("a block starts there")
    }

    fn effect(blocks: &[R2ILBlock], edges: &[(usize, u64)]) -> super::RegisterEffect {
        effect_with(blocks, edges, &[], &|_, _| false)
    }

    /// What a body with no pending call keeps; a pending callee keeps nothing.
    fn kept(effect: &super::RegisterEffect) -> super::Kept {
        effect.closed(|_| None)
    }

    /// A body entered with the registers as a caller left them: what it may read of them, and what
    /// every path to a return overwrites.
    #[test]
    fn a_body_effect_names_what_it_takes_and_what_it_overwrites_on_every_path() {
        let rax =
            |bytes| LaneBytes::covered_by(LANES, &[CanonicalStorageId { size: bytes, ..RAX }]);
        // `mov eax, 1; ret` overwrites RAX's low four bytes and its high four stay.
        let low = effect(&[block(0x1000, 4, vec![write(0, 4), ret()])], &[]);
        assert_eq!(low.overwrites, rax(4));
        let whole = effect(&[block(0x1000, 4, vec![write(0, 8), ret()])], &[]);
        assert_eq!(whole.overwrites, rax(8));
        // A write on the second arm only is a write the body may make: the walk takes every arm.
        let late = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![ret()]),
            block(0x1010, 4, vec![write(0, 4), ret()]),
        ];
        let late = effect(&late, &[(0, 0x1004), (0, 0x1010)]);
        assert_eq!(late.overwrites, LaneBytes::default());
        // `test al, al` before the write takes AL.
        let variadic = effect(
            &[block(0x1000, 4, vec![store(0, 1), write(0, 8), ret()])],
            &[],
        );
        assert_eq!(variadic.takes, rax(1));
        // A tail transfer hands the register to code the body does not hold.
        let tail = effect(&[block(0x1000, 4, vec![jump(0x5000)])], &[]);
        assert_eq!(tail.takes, LaneBytes::covered_by(LANES, &[RAX, XMM0]));
    }

    /// `mov eax, 1; ret` keeps XMM0 and RDX and writes RAX; RSP is no register a call may change.
    #[test]
    fn a_leaf_keeps_each_register_it_never_writes() {
        let leaf = kept(&effect(&[block(0x1000, 4, vec![write(0, 4), ret()])], &[]));
        assert!(leaf.keeps(XMM0) && leaf.keeps(RDX), "{leaf:?}");
        assert!(!leaf.keeps(RAX), "{leaf:?}");
        let rsp = CanonicalStorageId {
            offset: 0x20,
            ..RAX
        };
        assert!(!leaf.keeps(rsp), "{leaf:?}");
        let float = LaneBytes::covered_by(LANES, &[XMM0]);
        assert_eq!(leaf.kept_lanes(LANES), float);
    }

    /// A write on one path to a return is a register the body may change.
    #[test]
    fn a_body_that_writes_the_lane_on_one_path_keeps_nothing_of_it() {
        let arms = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![write(0x1208, 4), ret()]),
            block(0x1010, 4, vec![ret()]),
        ];
        let arms = kept(&effect(&arms, &[(0, 0x1004), (0, 0x1010)]));
        assert!(!arms.keeps(XMM0) && arms.keeps(RDX), "{arms:?}");
        assert_eq!(arms.kept_lanes(LANES), LaneBytes::covered_by(LANES, &[RAX]));
    }

    /// An exit the walk did not follow, or a branch to code the body does not hold, may write
    /// anything: the body keeps nothing.
    #[test]
    fn a_body_with_an_open_exit_or_a_tail_transfer_keeps_nothing() {
        let returns = [block(0x1000, 4, vec![ret()])];
        assert!(kept(&effect(&returns, &[])).keeps(XMM0));
        let open = effect_with(&returns, &[], &[0], &|_, _| false);
        assert!(open.unwritten.is_empty(), "{open:?}");
        let tail = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![ret()]),
        ];
        let tail = effect(&tail, &[(0, 0x1004)]);
        assert!(tail.unwritten.is_empty(), "{tail:?}");
    }

    /// `cpuid` and a user operation write registers no operand names: the body keeps nothing.
    #[test]
    fn a_body_with_an_unstated_operation_keeps_nothing() {
        let user = R2ILOp::CallOther {
            output: None,
            userop: 3,
            inputs: Vec::new(),
        };
        let cpuid = R2ILOp::CpuId {
            dst: Varnode::register(0x10, 4),
        };
        for unstated in [user, cpuid, R2ILOp::Unimplemented] {
            let body = effect(&[block(0x1000, 4, vec![unstated, ret()])], &[]);
            assert!(body.unwritten.is_empty(), "{body:?}");
        }
    }

    /// A store into the register space, or a branch in the middle of a block, writes or goes where
    /// the scan does not follow: nothing is kept.
    #[test]
    fn a_body_with_a_register_space_store_or_a_stray_branch_keeps_nothing() {
        let into = R2ILOp::Store {
            space: SpaceId::Register,
            addr: Varnode::constant(0x1200, 8),
            val: Varnode::constant(0, 8),
        };
        let stored = effect(&[block(0x1000, 4, vec![into, ret()])], &[]);
        assert!(stored.unwritten.is_empty(), "{stored:?}");
        let stray = [
            block(0x1000, 4, vec![branch(0x1010), write(0, 8), ret()]),
            block(0x1010, 4, vec![ret()]),
        ];
        let stray = effect(&stray, &[(0, 0x1010)]);
        assert!(stray.unwritten.is_empty(), "{stray:?}");
    }

    /// A call on a path to a return keeps what its callee keeps and the body leaves unwritten
    /// (D363); a call naming no callee keeps nothing.
    #[test]
    fn a_call_on_a_path_to_a_return_keeps_what_its_callee_keeps() {
        let body = effect(&[block(0x1000, 4, vec![write(0, 8), call(), ret()])], &[]);
        assert_eq!(&*body.pending, &[0x2000]);
        assert!(kept(&body).set.is_empty(), "{body:?}");
        // The leaf at 0x2000 writes RDX alone.
        let leaf = kept(&effect(
            &[block(0x1000, 4, vec![write(0x10, 8), ret()])],
            &[],
        ));
        let through = body.closed(|callee| (callee == 0x2000).then(|| leaf.clone()));
        let rsi = CanonicalStorageId {
            offset: 0x30,
            ..RAX
        };
        assert!(through.keeps(XMM0) && through.keeps(rsi), "{through:?}");
        assert!(!through.keeps(RAX) && !through.keeps(RDX), "{through:?}");
        let indirect = R2ILOp::CallInd {
            target: Varnode::register(0, 8),
        };
        let indirect = effect(&[block(0x1000, 4, vec![indirect, ret()])], &[]);
        assert!(indirect.unwritten.is_empty() && indirect.pending.is_empty());
    }

    /// `jz L; ret / L: movq xmm0, rax; call abort`: an exit at a call declared never to return
    /// reaches no return, so its writes are unseen; an exit at any other call keeps nothing.
    #[test]
    fn a_never_returning_exit_hides_its_writes() {
        let blocks = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![ret()]),
            block(0x1010, 4, vec![write(0x1200, 8), call()]),
        ];
        let edges = [(0, 0x1004), (0, 0x1010)];
        let declared = effect_with(&blocks, &edges, &[], &|block, op| (block, op) == (2, 1));
        assert!(kept(&declared).keeps(XMM0), "{declared:?}");
        let derived = effect_with(&blocks, &edges, &[], &|_, _| false);
        assert!(derived.unwritten.is_empty(), "{derived:?}");
        // A body every path of which ends at such a call reaches no return, and keeps nothing.
        let never = [block(0x1000, 4, vec![write(0x1200, 8), call()])];
        let never = effect_with(&never, &[], &[], &|_, _| true);
        assert!(never.unwritten.is_empty(), "{never:?}");
    }

    /// Reads every register at every transfer; a call overwrites `overwritten`.
    struct ReadsAll {
        overwritten: bool,
    }

    impl super::CallReadsAt for ReadsAll {
        fn target(&self, _block: usize, _op: usize) -> Option<u64> {
            None
        }

        fn reads(&self, _block: usize, _op: usize, _register: CanonicalStorageId) -> bool {
            true
        }

        fn overwrites(&self, _block: usize, _op: usize, _register: CanonicalStorageId) -> bool {
            self.overwritten
        }
    }

    const RDI: CanonicalStorageId = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x38,
        size: 8,
    };

    fn fate(
        blocks: &[R2ILBlock],
        edges: &[(usize, u64)],
        overwritten: bool,
    ) -> super::RegisterFate {
        let flow = CallerFlow::new(blocks, edges.iter().copied(), [], Endianness::Little);
        flow.fate_from_entry(0x1000, RDI, &ReadsAll { overwritten })
    }

    fn handed(at: u64, to: u64) -> super::Handoff {
        super::Handoff {
            instruction: at,
            target: super::Transfer::Direct(to),
            storage: RDI,
        }
    }

    /// `jmp atexit` hands the entry's RDI on; a call hands it on and the walk goes past it (S30).
    #[test]
    fn a_register_handed_to_a_tail_transfer_or_a_call_is_handed() {
        let tail = fate(&[block(0x1000, 4, vec![jump(0x5000)])], &[], false);
        assert_eq!(
            tail,
            super::RegisterFate::Handed([handed(0x1000, 0x5000)].into())
        );
        let twice = [block(
            0x1000,
            8,
            vec![call(), call(), write(0x38, 8), ret()],
        )];
        let expected = [handed(0x1000, 0x2000), handed(0x1001, 0x2000)];
        assert_eq!(
            fate(&twice, &[], false),
            super::RegisterFate::Handed(expected.into())
        );
        // A call that overwrites RDI ends the path: the second call is handed nothing of it.
        let once = [handed(0x1000, 0x2000)];
        assert_eq!(
            fate(&twice, &[], true),
            super::RegisterFate::Handed(once.into())
        );
    }

    /// A read, a return with RDI live, or a store of it is no handoff.
    #[test]
    fn a_register_read_returned_or_stored_is_other() {
        let returned = [block(0x1000, 4, vec![ret()])];
        assert_eq!(fate(&returned, &[], false), super::RegisterFate::Other);
        let stored = [block(
            0x1000,
            4,
            vec![store(0x38, 8), write(0x38, 8), ret()],
        )];
        assert_eq!(fate(&stored, &[], false), super::RegisterFate::Other);
        let dead = [block(0x1000, 4, vec![write(0x38, 8), ret()])];
        assert_eq!(fate(&dead, &[], false), super::RegisterFate::Dead);
        // One arm returns it: the other arm's handoff does not decide.
        let arms = [
            block(0x1000, 4, vec![branch(0x1010)]),
            block(0x1004, 4, vec![jump(0x5000)]),
            block(0x1010, 4, vec![ret()]),
        ];
        let arms = fate(&arms, &[(0, 0x1004), (0, 0x1010)], false);
        assert_eq!(arms, super::RegisterFate::Other);
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
        flow.site_fates(LANES, &nothing, &[(0, 1)]).swap_remove(0)
    }

    /// `mov edi, 1; call f; mov [rsi], eax; ret`: four bytes read, and all eight handed back.
    #[test]
    fn a_fate_states_the_bytes_it_reads() {
        let store = R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0x30, 8),
            val: Varnode::register(0, 4),
        };
        let ret = R2ILOp::Return {
            target: Varnode::register(0x20, 8),
        };
        let read = after(vec![store.clone(), ret.clone()]);
        let (bytes, lost) = (ByteMask(0xf), false);
        let returned = ByteMask(0xff);
        let fate = LaneFate::Read {
            bytes,
            returned,
            lost,
        };
        assert_eq!(read.fates[0], Some(fate));
        // `xor eax, eax` before the return: the four bytes read are every byte taken (D610).
        let cleared = R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(0, 8),
        };
        let whole = after(vec![store, cleared, ret.clone()]);
        let returned = ByteMask(0);
        let fate = LaneFate::Read {
            bytes,
            returned,
            lost,
        };
        assert_eq!(whole.fates[0], Some(fate));
        let returned = after(vec![ret]);
        assert_eq!(returned.fates[0], Some(LaneFate::Returned(ByteMask(0xff))));
        assert_eq!(ByteMask(0xf).low_run(), Some(4));
        assert_eq!(ByteMask(0xf0).low_run(), None);
    }
}
