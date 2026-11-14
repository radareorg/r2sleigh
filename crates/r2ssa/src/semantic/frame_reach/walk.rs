//! The frame's one escape walk, default deny, before slot promotion (doc/adr-frame-model.md,
//! "Escape spans"). A value's set and a place's held set only grow: `O(rounds x 65 x (V + E))`.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::dense::{DenseId, IdMap};
use crate::frame_address::Definitions;
use crate::function::SSAFunction;
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::VarId;

/// How far an address may move from where it points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Extent {
    /// Only upward: a non-negative index, or a callee proven to reach only upward.
    Upward,
    /// Either way.
    Either,
    /// Computed from the address by more than offset arithmetic (a mask, a mix, a merge that moves
    /// again): the seal keeps it in its object; promotion and the canary place it nowhere.
    Derived,
}

/// An entry offset an address points at, and which way it may move from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FramePoint {
    pub at: i64,
    pub extent: Extent,
}

/// Where an access the walk does not take as one exact load or store points.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Origin {
    Points(Vec<FramePoint>),
    /// A frame address no offset places.
    Unplaced,
}

/// An access through a frame address no exact load or store of one place states: it stays in
/// memory, and the seal asks the object model whether it lands in a frame object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpaqueAccess {
    pub(crate) op: OpId,
    pub(crate) origin: Origin,
    /// Whether it may write: only a load is known not to.
    pub(crate) writes: bool,
}

impl OpaqueAccess {
    /// One operation's two accesses as one: every point either names, writing where either may.
    fn join(&self, other: &Self) -> Self {
        let origin = match (&self.origin, &other.origin) {
            (Origin::Points(mine), Origin::Points(theirs)) => {
                let points = mine.iter().chain(theirs).copied().collect::<BTreeSet<_>>();
                Origin::Points(points.into_iter().collect())
            }
            _ => Origin::Unplaced,
        };
        Self {
            op: self.op,
            origin,
            writes: self.writes || other.writes,
        }
    }
}

/// Two rounds' opaque accesses, each by operation order, joined per operation. O(n + m).
fn merged_opaque(mine: Vec<OpaqueAccess>, theirs: Vec<OpaqueAccess>) -> Vec<OpaqueAccess> {
    let mut out: Vec<OpaqueAccess> = Vec::with_capacity(mine.len().max(theirs.len()));
    let mut all = mine.into_iter().chain(theirs).collect::<Vec<_>>();
    all.sort_by_key(|access| access.op);
    for access in all {
        match out.last_mut() {
            Some(last) if last.op == access.op => *last = last.join(&access),
            _ => out.push(access),
        }
    }
    out
}

/// A call's written area as spans from its pointer; `None` where nothing bounds it.
type Area<'a> = Option<&'a [(i64, i64)]>;

/// What the frame's addresses do, by entry offset (D290). `None` on a function means `whole`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FramePoints {
    /// An address no offset places leaves the function.
    pub(crate) whole: bool,
    /// `whole`, an unplaced opaque access or a derived point: no place is fixed. It only turns on
    /// as the walk adds them (D397).
    pub(crate) unplaced: bool,
    /// The addresses that leave the function.
    pub(crate) escaped: BTreeSet<FramePoint>,
    /// Accesses no exact load or store states, in operation order.
    pub(crate) opaque: Vec<OpaqueAccess>,
    /// Places holding an address a call reads as a stack argument: the store stays.
    pub(crate) handed: BTreeSet<i64>,
    /// Places a call's argument area covers that a load reads after a call: they stay (D369).
    pub(crate) rewritten: BTreeSet<i64>,
    /// The entry offset each call's or tail transfer's area is measured from, by instruction then
    /// operation; `None` where no offset places the stack pointer (D351, D398: the one table).
    pub(crate) call_bases: Vec<CallBase>,
    /// Each (callee, argument position) whose upward reach the walk asked, in any round (D365).
    pub(crate) asked_reach: BTreeSet<(u64, usize)>,
    /// The first instruction that moves the stack pointer by an amount no constant states (D355).
    pub(crate) dynamic: Option<DynamicFrame>,
    /// The entry-relative spans at or above the entry pointer its exact stores write (D377).
    pub(crate) incoming_stores: Vec<(i64, i64)>,
    /// The calls of the body to itself, by instruction.
    pub(crate) own_calls: BTreeSet<u64>,
    /// The places holding an address, with their widest access: what a kept build compares read
    /// areas over (D377).
    pub(crate) held_places: Places,
    /// The places whose promotion only `rewritten` decides, with their width: what a written area
    /// changes in a build (D377).
    pub(crate) rewrite_decides: Places,
    /// The places slot promotion took out of memory, by entry offset (D389).
    pub(crate) promoted: BTreeSet<i64>,
}

/// One call's or tail transfer's area base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallBase {
    pub(crate) instruction: Option<u64>,
    pub(crate) op: OpId,
    pub(crate) base: Option<i64>,
    /// A transfer leaving the body: nothing after it in the body loads what it writes (D381).
    pub(crate) tail: bool,
}

/// Entry offsets with a width, and the widest: a span meets one in `O(log places)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Places {
    widths: BTreeMap<i64, u32>,
    widest: u32,
}

impl Places {
    pub(crate) fn new(widths: BTreeMap<i64, u32>) -> Self {
        let widest = widths.values().copied().max().unwrap_or(1);
        Self { widths, widest }
    }

    /// Whether no place shares a byte with `[low, high)`.
    fn untouched(&self, (low, high): (i64, i64)) -> bool {
        let near = (self.widths).range(low.saturating_sub(i64::from(self.widest))..high);
        !near
            .into_iter()
            .any(|(place, width)| place + i64::from(*width) > low)
    }

    fn join(&mut self, other: Self) {
        for (place, width) in other.widths {
            let widest = self.widths.entry(place).or_insert(width);
            *widest = (*widest).max(width);
        }
        self.widest = self.widest.max(other.widest);
    }
}

/// A frame no offset places past one instruction: `sub rsp, rax` after `__chkstk`, an `alloca`
/// (D355). The frame model's typed refusal; the route prints it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DynamicFrame {
    pub instruction: u64,
}

impl std::fmt::Display for DynamicFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "dynamic frame: the stack pointer at {:#x} moves by an amount no constant states",
            self.instruction
        )
    }
}

impl FramePoints {
    /// Every place may be reached: an escape or an access no offset places.
    pub(crate) fn whole_frame() -> Self {
        Self {
            whole: true,
            unplaced: true,
            ..Self::default()
        }
    }

    fn set_whole(&mut self) {
        self.whole = true;
        self.unplaced = true;
    }

    /// An address leaving at `point`.
    fn leave(&mut self, point: FramePoint) {
        self.unplaced |= point.extent == Extent::Derived;
        self.escaped.insert(point);
    }

    /// Both rounds' points: what either states leaves or is accessed.
    fn absorb(&mut self, other: Self) {
        self.whole |= other.whole;
        self.unplaced |= other.unplaced;
        self.escaped.extend(other.escaped);
        self.opaque = merged_opaque(std::mem::take(&mut self.opaque), other.opaque);
        self.handed.extend(other.handed);
        self.rewritten.extend(other.rewritten);
        self.asked_reach.extend(other.asked_reach);
        self.dynamic = self.dynamic.into_iter().chain(other.dynamic).min();
        self.incoming_stores = merged(
            self.incoming_stores
                .iter()
                .chain(&other.incoming_stores)
                .copied(),
        );
        self.own_calls.extend(other.own_calls);
        self.held_places.join(other.held_places);
        // Both rounds walk the same calls: a base the two disagree on is none.
        for (mine, theirs) in self.call_bases.iter_mut().zip(other.call_bases) {
            debug_assert_eq!(mine.op, theirs.op);
            mine.base = mine.base.filter(|base| theirs.base == Some(*base));
        }
    }

    /// Whether two read and two written areas of one call cover the same address-holding places,
    /// rewrite-decided places and incoming bytes (D377). `O(spans x log places)`.
    pub(crate) fn areas_alike(
        &self,
        instruction: u64,
        reads: [Area<'_>; 2],
        writes: [Area<'_>; 2],
    ) -> bool {
        // A call to itself writes what the rest of the body writes, so every area counts.
        if !self.own_calls.is_empty() && writes[0] != writes[1] {
            return false;
        }
        // A call no offset places reads and writes the whole frame whatever its areas say.
        let at = (self.call_bases).partition_point(|call| call.instruction < Some(instruction));
        let base = match self
            .call_bases
            .get(at)
            .filter(|call| call.instruction == Some(instruction))
        {
            Some(CallBase {
                base: Some(base), ..
            }) => *base,
            Some(_) => return true,
            None => return reads[0] == reads[1] && writes[0] == writes[1],
        };
        let at = |area: Area<'_>| match area {
            Some(area) => merged(
                (area.iter())
                    .map(|(low, high)| (base.wrapping_add(*low), base.wrapping_add(*high))),
            ),
            None => merged([(base, 0)].into_iter()),
        };
        let read = differing(&at(reads[0]), &at(reads[1]));
        let written = differing(&at(writes[0]), &at(writes[1]));
        read.into_iter()
            .all(|span| self.held_places.untouched(span))
            && (written.into_iter()).all(|span| span.1 <= 0 && self.rewrite_decides.untouched(span))
    }

    /// What a call to this body may write of its caller's stack, from the call's pointer; a self call
    /// in two rounds (doc/adr-callee-builds.md, D377, D381). `O(calls x spans)`.
    pub fn call_writes(&self, context: &SourceMachineContext) -> Option<Vec<(i64, i64)>> {
        let writing = self.opaque.iter().any(|access| access.writes);
        if self.whole || !self.escaped.is_empty() || writing {
            return None;
        }
        let address = i64::from(context.memory_model().default_address_bits() / 8);
        // An unstated mechanism spends nothing or one address (D386).
        let (least, most) = context
            .return_mechanism()
            .map_or((0, address), |mechanism| {
                let spent = r2source::SourceReturnMechanism::spent(Some(mechanism));
                (spent, spent)
            });
        let mut fixed = self.incoming_stores.clone();
        let mut own_bases = Vec::new();
        for call in &self.call_bases {
            // A call above what its transfer spends could move a cycle's spans up each round.
            let base = call.base.filter(|base| *base <= least)?;
            let instruction = call.instruction?;
            if self.own_calls.contains(&instruction) {
                own_bases.push(base);
                continue;
            }
            // A tail transfer writes what its source-correlated callee states; any other, all.
            let stated = (!call.tail)
                || (context.raw_call_site_at(instruction))
                    .is_some_and(|identity| context.is_tail_call_site(identity));
            let writes = stated
                .then(|| context.call_reads(Some(instruction)))
                .flatten()?
                .writes?;
            fixed.extend(writes.iter().map(|(low, high)| (base + low, base + high)));
        }
        // Two rounds: a call to itself whose writes move the spans again bounds nothing (D377).
        let round = |own: &[(i64, i64)]| {
            let shifted = own_bases
                .iter()
                .flat_map(|base| own.iter().map(move |(low, high)| (base + low, base + high)));
            let incoming = fixed
                .iter()
                .copied()
                .chain(shifted)
                .filter(|(_, high)| *high > 0);
            merged(incoming.map(|(low, high)| ((low.max(0) - most).max(0), high - least)))
        };
        let first = round(&[]);
        let second = round(&first);
        (own_bases.is_empty() || second == first).then_some(first)
    }

    /// Whether slot promotion took the place at entry offset `place` out of memory. O(log).
    pub fn promoted(&self, place: i64) -> bool {
        self.promoted.contains(&place)
    }

    /// The frame's typed refusal, where the stack pointer moves by an unstated amount (D355).
    pub const fn dynamic_frame(&self) -> Option<DynamicFrame> {
        self.dynamic
    }

    /// Whether an address no offset places escapes or is accessed. O(1).
    pub(crate) const fn unplaced(&self) -> bool {
        self.unplaced
    }

    /// The points that escape or are accessed opaquely.
    fn reaching(&self) -> impl Iterator<Item = FramePoint> + '_ {
        let opaque = self.opaque.iter().flat_map(|access| match &access.origin {
            Origin::Points(points) => points.as_slice(),
            Origin::Unplaced => &[],
        });
        self.escaped.iter().chain(opaque).copied()
    }

    /// Whether an escaped or opaque address may reach `place`, crossing no save of `saves`.
    /// `O(points x log saves)`.
    pub(crate) fn reaches(&self, place: i64, saves: &BTreeSet<i64>) -> bool {
        let separated = |from: i64| {
            let (low, high) = (from.min(place), from.max(place));
            high > low.saturating_add(1) && saves.range(low + 1..high).next().is_some()
        };
        self.unplaced()
            || self.reaching().any(|point| {
                (point.extent == Extent::Either || point.at <= place) && !separated(point.at)
            })
    }

    /// Whether an escaped or opaque address points into `[lo, hi)`: a compiler slot there is no
    /// object an index below it spans, so only points inside it name it. `O(points)`.
    pub(crate) fn names(&self, lo: i64, hi: i64) -> bool {
        self.unplaced() || self.reaching().any(|point| lo <= point.at && point.at < hi)
    }

    pub(crate) const fn handed(&self) -> &BTreeSet<i64> {
        &self.handed
    }

    /// Places a call may write that a load reads after it (D369).
    pub(crate) const fn rewritten(&self) -> &BTreeSet<i64> {
        &self.rewritten
    }

    pub(crate) const fn asked_reach(&self) -> &BTreeSet<(u64, usize)> {
        &self.asked_reach
    }

    /// The places a call's write area covers that a load reads after it (D369), with each call's
    /// base by instruction: what asks a call nothing states to state itself (D376).
    pub fn rewriting_calls(&self) -> impl Iterator<Item = (u64, i64)> + '_ {
        let bases = (self.call_bases.iter())
            .filter(|call| !call.tail)
            .filter_map(|call| Some((call.instruction?, call.base?)));
        bases.filter(|(_, base)| *base < 0 && self.rewritten.range(*base..0).next().is_some())
    }
}

/// One exact access at a place, for promotion's rewrite.
pub(crate) struct Access {
    pub(crate) op: OpId,
    pub(crate) block: u64,
    pub(crate) index: usize,
    pub(crate) width: u32,
    pub(crate) store: bool,
}

pub(crate) type Accesses = BTreeMap<i64, Vec<Access>>;

/// Where a value derived from the entry stack pointer points, inside the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Point {
    Exact(i64),
    /// This offset plus an index: upward only where the index is non-negative.
    Indexed {
        from: i64,
        up: bool,
    },
    /// Computed from the address at this offset by more than offset arithmetic.
    Derived(i64),
}

impl Point {
    const fn frame_point(self) -> FramePoint {
        match self {
            Self::Exact(at)
            | Self::Indexed {
                from: at,
                up: false,
            } => FramePoint {
                at,
                extent: Extent::Either,
            },
            Self::Indexed { from, up: true } => FramePoint {
                at: from,
                extent: Extent::Upward,
            },
            Self::Derived(at) => FramePoint {
                at,
                extent: Extent::Derived,
            },
        }
    }
}

/// A value's points, or `Top` for a frame address no offset places.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Points(BTreeSet<Point>),
    Top,
}

/// More distinct points than this on one value refuse as `Top`.
const POINTS: usize = 64;

impl Value {
    fn one(point: Point) -> Self {
        Self::Points(BTreeSet::from([point]))
    }

    fn exact(&self) -> Option<i64> {
        match self {
            Self::Points(points) if points.len() == 1 => match points.first() {
                Some(Point::Exact(at)) => Some(*at),
                _ => None,
            },
            _ => None,
        }
    }

    /// The same places, computed from by more than offset arithmetic.
    fn degraded(&self) -> Self {
        match self {
            Self::Points(points) => Self::Points(
                (points.iter())
                    .map(|point| Point::Derived(point.frame_point().at))
                    .collect(),
            ),
            Self::Top => Self::Top,
        }
    }

    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Points(a), Self::Points(b)) => {
                let joined = a.union(b).copied().collect::<BTreeSet<_>>();
                if joined.len() > POINTS {
                    r2il::refusal_evidence!(
                        "frame-reach",
                        "a value may point at {} places, past {POINTS}: no offset places it",
                        joined.len()
                    );
                    Self::Top
                } else {
                    Self::Points(joined)
                }
            }
            _ => Self::Top,
        }
    }
}

/// The walk's answer: the points, and each exact access by place for promotion's rewrite.
pub(crate) struct Walked {
    pub(crate) points: FramePoints,
    pub(crate) accesses: Accesses,
    /// The places an address is stored into, where the round let a place carry one.
    carriers: BTreeSet<i64>,
}

/// Walk `func`'s frame addresses; `promotable` picks each round's promoted places and the set
/// only shrinks, so at most one round per place. Returns the last round and its places.
pub(crate) fn walk(
    func: &SSAFunction,
    defs: &Definitions,
    machine: &SourceMachineContext,
    calls_refund_stack: bool,
    mut promotable: impl FnMut(&Walked) -> BTreeMap<i64, u32>,
) -> (Walked, BTreeMap<i64, u32>) {
    let refused = |points: FramePoints| {
        let walked = Walked {
            points,
            accesses: Accesses::new(),
            carriers: BTreeSet::new(),
        };
        (walked, BTreeMap::new())
    };
    let Some(stack_pointer) = machine.stack_pointer_carrier() else {
        return refused(FramePoints::whole_frame());
    };
    let entry_sp = (0..func.values().len())
        .map(VarId::from_index)
        .find(|id| func.var(*id).version == 0 && func.storage_of(*id) == Some(stack_pointer));
    // No entry stack pointer value: no frame address exists, and every transfer is at entry (D381).
    let Some(entry_sp) = entry_sp else {
        let arguments = StackArguments::of(func, machine, stack_pointer, None);
        let values = IdMap::new(func.values().len());
        return refused(FramePoints {
            own_calls: arguments.own_calls(),
            call_bases: arguments.by_call(&values),
            ..FramePoints::default()
        });
    };
    if defs.exhausted().is_some() {
        return refused(FramePoints::whole_frame());
    }
    let sinks = Sinks::of(func, machine, stack_pointer, entry_sp, calls_refund_stack);
    let uses = Uses::of(func);
    let mut carried: Option<BTreeSet<i64>> = None;
    let mut asked = BTreeSet::new();
    // An entry edge runs the prologue again: an offset names a place per pass, so any escape or
    // opaque access reaches the whole frame.
    let reentered = func.cfg().has_entry_edge();
    loop {
        let mut walked = Walker::new((func, defs, &uses), entry_sp, &sinks, carried.as_ref()).run();
        let promoted = promotable(&walked);
        let unplaced = walked.points.unplaced();
        // An unplaced round promotes nothing: its places keep their stores, so each stored
        // address also leaves, as the round where no place carries states.
        if unplaced && carried.as_ref().is_none_or(|carried| !carried.is_empty()) {
            let kept = BTreeSet::new();
            let stored = Walker::new((func, defs, &uses), entry_sp, &sinks, Some(&kept)).run();
            walked.points.absorb(stored.points);
        }
        asked.extend(walked.points.asked_reach.iter().copied());
        if reentered && !(walked.points.escaped.is_empty() && walked.points.opaque.is_empty()) {
            walked.points.set_whole();
        }
        let settled =
            unplaced || (walked.carriers.iter()).all(|place| promoted.contains_key(place));
        if settled {
            walked.points.asked_reach = asked;
            r2il::refusal_evidence!(
                "frame-reach",
                "{:#x}: escaped {:?}, opaque {:?}, unplaced {}",
                func.entry,
                walked.points.escaped,
                (walked.points.opaque.iter())
                    .map(|access| &access.origin)
                    .collect::<BTreeSet<_>>(),
                walked.points.unplaced()
            );
            return (walked, promoted);
        }
        carried = Some(promoted.keys().copied().collect());
    }
}

/// The (callee, argument position) a `CallUse` hands to, and whether its reach is upward only.
type ReachAsk = ((u64, usize), bool);

/// Where a frame address leaves through a call.
struct Sinks<'a> {
    calls_refund_stack: bool,
    /// The registers a call may read where no `CallUse` says which: none under a convention.
    read_by_calls: Box<dyn Fn(crate::CanonicalStorageId) -> bool + 'a>,
    /// The (callee, position) the `CallUse` at this block and index hands its register to, and
    /// whether the callee reaches only upward through it.
    upward_at: Box<dyn Fn(u64, usize, crate::CanonicalStorageId) -> Option<ReachAsk> + 'a>,
    stack_arguments: StackArguments,
    /// The stack and frame pointers: the frame's own bases, not addresses handed on.
    bases: [Option<crate::CanonicalStorageId>; 2],
    machine: &'a SourceMachineContext,
}

impl<'a> Sinks<'a> {
    fn of(
        func: &'a SSAFunction,
        machine: &'a SourceMachineContext,
        stack_pointer: crate::CanonicalStorageId,
        entry_sp: VarId,
        calls_refund_stack: bool,
    ) -> Self {
        let calls = func
            .blocks()
            .iter()
            .any(|block| block.ops().iter().any(SSAOp::is_call));
        let convention = machine.convention().is_some();
        // The stack and frame pointers are the frame's own bases, not addresses handed on.
        let bases = [
            Some(stack_pointer),
            machine.machine_roles().frame_pointer_storage(),
        ];
        let read_by_calls = move |storage: crate::CanonicalStorageId| {
            calls
                && !convention
                && storage.space == crate::CanonicalStorageSpace::Register
                && !bases.contains(&Some(storage))
        };
        // The callee is the call's raw identity's target, its reach indexed by the site's model.
        let upward_at = move |block: u64, index: usize, storage: crate::CanonicalStorageId| {
            let ops = func.get_block(block).map(|block| block.ops())?;
            let call = ops[index + 1..].iter().find_map(|op| match op {
                SSAOp::CallUse { .. } => None,
                op => Some(op.call().filter(|call| call.direct)),
            });
            let instruction = call.flatten().and_then(|call| call.instruction);
            let target = (instruction
                .and_then(|instruction| machine.raw_call_site_at(instruction)))
            .and_then(crate::semantic::direct_target_from_raw_identity)?;
            let position = (machine
                .site_integer_arguments(instruction, Some(target))
                .iter())
            .position(|slot| slot.space == storage.space && slot.offset == storage.offset)?;
            let upward = (machine.callee_reach_at(target, position))
                .is_some_and(crate::interproc::ArgumentReach::is_upward);
            Some(((target, position), upward))
        };
        Self {
            calls_refund_stack,
            bases,
            read_by_calls: Box::new(read_by_calls),
            upward_at: Box::new(upward_at),
            stack_arguments: StackArguments::of(func, machine, stack_pointer, Some(entry_sp)),
            machine,
        }
    }
}

/// The stack each call may read: a frame address stored there leaves the body
/// (doc/adr-call-boundary.md, "D217 as built").
struct StackArguments {
    calls: Vec<CallArguments>,
}

/// One call's or tail transfer's argument area, from the stack pointer it is measured at.
struct CallArguments {
    op: OpId,
    /// The block the call is in and its index there.
    at: (u64, usize),
    /// The stack pointer reaching it; none where the body never reads one, the entry pointer.
    pointer: Option<VarId>,
    /// What the transfer spends where no restore records the pointer entering it.
    shift: i64,
    /// `CallReads::stack` of the call; none reads every place from the pointer to entry.
    area: Option<Vec<(i64, i64)>>,
    /// `CallReads::writes` of the call; none writes every place from the pointer to entry.
    writes: Option<Vec<(i64, i64)>>,
    /// A direct call to the body itself that nothing else states.
    own: bool,
    /// A transfer that leaves the body: its callee's writes above the entry pointer are the
    /// body's, and nothing after it in the body sees them (D381).
    tail: bool,
    instruction: Option<u64>,
}

impl StackArguments {
    /// One dominator-tree walk carries the stack pointer to every call: `O(B + ops)`.
    fn of(
        func: &SSAFunction,
        machine: &SourceMachineContext,
        stack_pointer: crate::CanonicalStorageId,
        entry_sp: Option<VarId>,
    ) -> Self {
        let site = Site {
            func,
            machine,
            spent: r2source::SourceReturnMechanism::spent(machine.return_mechanism()),
            stack_pointer,
        };
        let mut calls = Vec::new();
        let mut steps = vec![(func.root(), entry_sp)];
        let mut seen = BTreeSet::new();
        while let Some((address, mut pointer)) = steps.pop() {
            let Some(block) = func.get_block(address).filter(|_| seen.insert(address)) else {
                continue;
            };
            if let Some((_, phi)) = block.sited_phis().find(|(_, phi)| site.is_pointer(phi.dst)) {
                pointer = Some(phi.dst);
            }
            pointer = site.calls((address, block), pointer, &mut calls);
            let children = func.domtree().children(address);
            steps.extend(children.iter().rev().map(|child| (*child, pointer)));
        }
        Self { calls }
    }

    /// What a call writes: the body's own writes for a call to itself (`own`), else its statement.
    fn writes_of<'s>(
        call: &'s CallArguments,
        own: Option<&'s [(i64, i64)]>,
    ) -> Option<&'s [(i64, i64)]> {
        match call.own {
            true => own,
            false => call.writes.as_deref(),
        }
    }

    /// The calls of the body to itself, by instruction.
    fn own_calls(&self) -> BTreeSet<u64> {
        (self.calls.iter())
            .filter(|call| call.own)
            .filter_map(|call| call.instruction)
            .collect()
    }

    /// Each call's area base, by instruction then operation.
    fn by_call(&self, values: &IdMap<VarId, Value>) -> Vec<CallBase> {
        let mut bases = (self.calls.iter())
            .map(|call| CallBase {
                instruction: call.instruction,
                op: call.op,
                base: call.base(values),
                tail: call.tail,
            })
            .collect::<Vec<_>>();
        bases.sort_by_key(|call| (call.instruction, call.op));
        bases
    }

    /// Places a call's written area covers that a load reads after it (D369). A union dataflow; sets
    /// only grow: `O((B + E) x K log K + A log A)`.
    fn rewritten(
        &self,
        func: &SSAFunction,
        (values, accesses): (&IdMap<VarId, Value>, &Accesses),
        own: Option<&[(i64, i64)]>,
    ) -> BTreeSet<i64> {
        // Each call's area as entry-relative spans, by block and index; an unplaced call covers all.
        let mut in_block = BTreeMap::<u64, Vec<CallSpans>>::new();
        for call in self.calls.iter().filter(|call| !call.tail) {
            let spans = match (call.base(values), Self::writes_of(call, own)) {
                (None, _) => vec![(i64::MIN, i64::MAX)],
                (Some(base), Some(area)) => merged(
                    area.iter()
                        .map(|(low, high)| (base.wrapping_add(*low), base.wrapping_add(*high))),
                ),
                // Unbounded, it is still this frame's: it ends at the entry pointer.
                (Some(base), None) => merged([(base, 0)].into_iter()),
            };
            in_block
                .entry(call.at.0)
                .or_default()
                .push((call.at.1, spans));
        }
        let entering = reaching_writes(func, &in_block);
        // Each load against what reaches it: the block's entry and the calls before it there.
        let mut loads = (accesses.iter())
            .flat_map(|(place, list)| list.iter().map(move |access| (*place, access)))
            .filter(|(_, access)| !access.store)
            .map(|(place, access)| (access.block, access.index, place, access.width))
            .collect::<Vec<_>>();
        loads.sort_unstable();
        let mut rewritten = BTreeSet::new();
        for list in loads.chunk_by(|one, other| one.0 == other.0) {
            let block = list[0].0;
            let calls = in_block.get(&block).cloned().unwrap_or_default();
            let live = entering.get(&block).cloned().unwrap_or_default();
            rewritten_in_block(list, calls, live, &mut rewritten);
        }
        rewritten
    }

    /// The places of `stored` some call may read, given each place's widest access.
    fn read(&self, values: &IdMap<VarId, Value>, stored: &BTreeMap<i64, u32>) -> BTreeSet<i64> {
        let mut read = BTreeSet::new();
        for call in &self.calls {
            // A call at a pointer no offset places may read any place.
            let Some(base) = call.base(values) else {
                return stored.keys().copied().collect();
            };
            let within = |place: i64, width: u32| match &call.area {
                Some(area) => area.iter().any(|(low, high)| {
                    base.wrapping_add(*low) < place.saturating_add(i64::from(width))
                        && place < base.wrapping_add(*high)
                }),
                // Unbounded, a call's still ends at the entry pointer; a tail transfer's does not.
                None => place.saturating_add(i64::from(width)) > base && (call.tail || place < 0),
            };
            read.extend(
                (stored.iter())
                    .filter(|(place, width)| within(**place, **width))
                    .map(|(place, _)| *place),
            );
        }
        read
    }
}

impl CallArguments {
    /// The entry offset the call's area is measured from, where an offset places its pointer.
    fn base(&self, values: &IdMap<VarId, Value>) -> Option<i64> {
        let base = match self.pointer {
            Some(pointer) => values.get(pointer)?.exact()?,
            None => 0,
        };
        Some(base.wrapping_add(self.shift))
    }
}

/// What every call of one function shares: the machine, and what a transfer spends.
struct Site<'a> {
    func: &'a SSAFunction,
    machine: &'a SourceMachineContext,
    spent: i64,
    stack_pointer: crate::CanonicalStorageId,
}

impl Site<'_> {
    fn is_pointer(&self, var: VarId) -> bool {
        self.func.storage_of(var) == Some(self.stack_pointer)
    }

    /// Each call and tail transfer of a block, entered at the stack `pointer`; the pointer leaving it.
    fn calls(
        &self,
        (address, block): (u64, &crate::block::SSABlock<VarId>),
        mut pointer: Option<VarId>,
        out: &mut Vec<CallArguments>,
    ) -> Option<VarId> {
        let ops = block.ops();
        for (index, (id, op)) in block.sited().enumerate() {
            let at = (id, (address, index));
            let call = self.call(at, &ops[index..], pointer);
            out.extend(call.or_else(|| self.tail(at, op, pointer)));
            pointer = op
                .dst()
                .copied()
                .filter(|dst| self.is_pointer(*dst))
                .or(pointer);
        }
        pointer
    }

    /// A transfer leaving the body at `pointer`, as a returning call: a source-correlated tail takes
    /// its callee's statement; any other tail reads and writes all (D381).
    fn tail(
        &self,
        (op, at): (OpId, (u64, usize)),
        ssa: &SSAOp<VarId>,
        pointer: Option<VarId>,
    ) -> Option<CallArguments> {
        let transfer = ssa.transfer().filter(|transfer| !transfer.call)?;
        let identified = (transfer.instruction)
            .and_then(|instruction| self.machine.raw_call_site_at(instruction))
            .filter(|identity| self.machine.is_tail_call_site(*identity));
        let leaves = identified.is_some()
            || match transfer.direct {
                true => self
                    .func
                    .storage_of(*transfer.target)
                    .is_some_and(|target| {
                        target.space == crate::CanonicalStorageSpace::Ram
                            && self.func.get_block(target.offset).is_none()
                    }),
                false => {
                    self.func.successors(at.0).is_empty()
                        || (self.func.cfg().get_block(at.0)).is_some_and(|block| {
                            matches!(
                                block.terminator,
                                crate::cfg::BlockTerminator::ConditionalExit { .. }
                            )
                        })
                }
            };
        if !leaves {
            return None;
        }
        let reads = identified.and_then(|_| self.machine.call_reads(transfer.instruction));
        let (area, writes) = reads.map_or((None, None), |reads| (reads.stack, reads.writes));
        Some(CallArguments {
            op,
            at,
            pointer,
            shift: self.spent,
            area,
            writes,
            own: false,
            tail: true,
            instruction: transfer.instruction,
        })
    }

    /// The call `ops` starts with, in the boundary's coordinates: the pointer a restore records
    /// entering the transfer, else the one reaching it past what the transfer spends.
    fn call(
        &self,
        (op, at): (OpId, (u64, usize)),
        ops: &[SSAOp<VarId>],
        pointer: Option<VarId>,
    ) -> Option<CallArguments> {
        let call = ops.first()?.call()?;
        let entering = (ops[1..].iter())
            .take_while(|op| matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }))
            .find_map(|op| match op {
                SSAOp::CallRestore { dst, src } if self.is_pointer(*dst) => Some(*src),
                _ => None,
            });
        let (pointer, shift) = entering.map_or((pointer, self.spent), |src| (Some(src), 0));
        let reads = self.machine.call_reads(call.instruction);
        let target = (call
            .instruction
            .and_then(|at| self.machine.raw_call_site_at(at)))
        .map(r2source::SourceCallSiteIdentity::target);
        let entry = target.is_some_and(|target| {
            target.space == crate::CanonicalStorageSpace::Ram && target.offset == self.func.entry
        });
        let writes = reads.as_ref().and_then(|reads| reads.writes.clone());
        Some(CallArguments {
            own: entry && writes.is_none(),
            tail: false,
            op,
            at,
            pointer,
            shift,
            writes,
            instruction: call.instruction,
            area: reads.and_then(|reads| reads.stack),
        })
    }
}

/// One round's worklist over the frame's addresses, and what it has found.
struct Walker<'a> {
    func: &'a SSAFunction,
    defs: &'a Definitions,
    entry_sp: VarId,
    sinks: &'a Sinks<'a>,
    /// The places an address stored into flows to the loads of; every place when `None`.
    carried: Option<&'a BTreeSet<i64>>,
    uses: &'a Uses,
    values: IdMap<VarId, Value>,
    /// Each opaque access by its operation, its origins joined (D397).
    opaque: IdMap<OpId, OpaqueAccess>,
    /// Merges a source reached that have no value yet: the partial merges to check (D398).
    merge_candidates: Vec<VarId>,
    pending: Vec<VarId>,
    accesses: Accesses,
    points: FramePoints,
    /// What each carrying place holds of the frame's addresses, and the values loaded from it.
    held: BTreeMap<i64, Value>,
    loaded: BTreeMap<i64, Vec<VarId>>,
    carriers: BTreeSet<i64>,
    /// Stores of an address whose place is not yet known: they escape if it never is.
    deferred: Vec<(VarId, VarId)>,
    /// Each exact place a frame address is stored into, with the address.
    stored: BTreeMap<i64, Value>,
}

/// Each value's readers: the operations and the merges. Built once per walk, read every round.
struct Uses {
    ops: IdMap<VarId, Vec<(OpId, u64, usize)>>,
    phis: IdMap<VarId, Vec<VarId>>,
}

impl Uses {
    /// O(ops + phi sources).
    fn of(func: &SSAFunction) -> Self {
        let mut ops = IdMap::<VarId, Vec<(OpId, u64, usize)>>::new(func.values().len());
        let mut phis = IdMap::<VarId, Vec<VarId>>::new(func.values().len());
        for addr in func.block_addrs() {
            let Some(block) = func.get_block(*addr) else {
                continue;
            };
            for (_, phi) in block.sited_phis() {
                for (_, source) in &phi.sources {
                    phis.get_or_insert_with(*source, Vec::new).push(phi.dst);
                }
            }
            for (index, (id, op)) in block.sited().enumerate() {
                for source in op.sources() {
                    ops.get_or_insert_with(*source, Vec::new)
                        .push((id, *addr, index));
                }
            }
        }
        Self { ops, phis }
    }
}

impl<'a> Walker<'a> {
    fn new(
        (func, defs, uses): (&'a SSAFunction, &'a Definitions, &'a Uses),
        entry_sp: VarId,
        sinks: &'a Sinks<'a>,
        carried: Option<&'a BTreeSet<i64>>,
    ) -> Self {
        let mut values = IdMap::<VarId, Value>::new(func.values().len());
        values.insert(entry_sp, Value::one(Point::Exact(0)));
        Self {
            func,
            defs,
            entry_sp,
            sinks,
            carried,
            uses,
            values,
            opaque: IdMap::new(func.id_limit()),
            merge_candidates: Vec::new(),
            pending: vec![entry_sp],
            accesses: Accesses::new(),
            points: FramePoints::default(),
            held: BTreeMap::new(),
            loaded: BTreeMap::new(),
            carriers: BTreeSet::new(),
            deferred: Vec::new(),
            stored: BTreeMap::new(),
        }
    }

    fn run(mut self) -> Walked {
        loop {
            while let Some(var) = self.pending.pop() {
                self.visit(var);
            }
            // A merge some of whose sources are frame addresses and some not reads another place
            // on some path: its points, at no exact place.
            let partial = self.partial_merges();
            if partial.is_empty() {
                break;
            }
            for dst in partial {
                let known = self.known_sources(dst);
                self.set(dst, known.degraded());
            }
        }
        self.finish()
    }

    fn set(&mut self, var: VarId, value: Value) {
        let joined = self
            .values
            .get(var)
            .map_or_else(|| value.clone(), |known| known.join(&value));
        if self.values.get(var) != Some(&joined) {
            self.values.insert(var, joined);
            self.pending.push(var);
        }
    }

    fn escape(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                // Handed on, an address may be indexed either way.
                for point in points {
                    self.points.leave(match point {
                        Point::Derived(_) => point.frame_point(),
                        _ => FramePoint {
                            at: point.frame_point().at,
                            extent: Extent::Either,
                        },
                    });
                }
            }
            Value::Top => self.points.set_whole(),
        }
    }

    fn escape_up(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                for point in points {
                    self.points.leave(match point {
                        Point::Exact(at) => FramePoint {
                            at: *at,
                            extent: Extent::Upward,
                        },
                        indexed => indexed.frame_point(),
                    });
                }
            }
            Value::Top => self.points.set_whole(),
        }
    }

    /// An access at `op` no exact load or store states, joined with what `op` was found to do.
    fn opaque(&mut self, op: OpId, value: &Value, writes: bool) {
        let origin = match value {
            Value::Points(points) => {
                let points = points.iter().map(|point| point.frame_point());
                Origin::Points(points.collect::<BTreeSet<_>>().into_iter().collect())
            }
            Value::Top => Origin::Unplaced,
        };
        self.points.unplaced |= match &origin {
            Origin::Unplaced => true,
            Origin::Points(points) => points.iter().any(|point| point.extent == Extent::Derived),
        };
        let access = OpaqueAccess { op, origin, writes };
        let joined = match self.opaque.get(op) {
            Some(known) => known.join(&access),
            None => access,
        };
        self.opaque.insert(op, joined);
    }

    /// Everything `var`'s value reaches: the merges it feeds and each operation reading it.
    fn visit(&mut self, var: VarId) {
        let Some(value) = self.values.get(var).cloned() else {
            return;
        };
        if var != self.entry_sp
            && (self.func.storage_of(var))
                .is_some_and(|storage| (self.sinks.read_by_calls)(storage))
        {
            self.escape(&value);
        }
        for dst in self.uses.phis.get(var).cloned().unwrap_or_default() {
            let (root, offset) = self.defs.affine(self.func, dst);
            let merged = if root == self.entry_sp {
                Some(Value::one(Point::Exact(offset)))
            } else if self.values.get(dst).is_some() {
                // A merge that moves again is carried round a loop or past a partial source: its
                // places at no exact offset, so a stepped pointer settles (the widening).
                Some(self.known_sources(dst).degraded())
            } else {
                self.merged_sources(dst)
            };
            match merged {
                Some(merged) => self.set(dst, merged),
                None => self.merge_candidates.push(dst),
            }
        }
        for (id, block, index) in self.uses.ops.get(var).cloned().unwrap_or_default() {
            let Some(op) = (self.func.get_block(block)).and_then(|block| block.ops().get(index))
            else {
                continue;
            };
            let whole_before = self.points.unplaced;
            self.read(var, &value, op, (id, block, index));
            if self.points.unplaced && !whole_before {
                r2il::refusal_evidence!(
                    "frame-reach",
                    "{block:#x}:{index} {op:?} takes a frame address no offset places"
                );
            }
        }
    }

    /// The join of a merge's sources, once every one is a frame address.
    fn merged_sources(&self, phi: VarId) -> Option<Value> {
        let mut joined = None::<Value>;
        for source in self.defs.phi_sources(phi) {
            let value = self.values.get(*source)?;
            joined = Some(joined.map_or_else(|| value.clone(), |known| known.join(value)));
        }
        joined
    }

    /// The join of a merge's sources that are frame addresses.
    fn known_sources(&self, phi: VarId) -> Value {
        (self.defs.phi_sources(phi).iter())
            .filter_map(|source| self.values.get(*source))
            .fold(Value::Points(BTreeSet::new()), |joined, value| {
                joined.join(value)
            })
    }

    /// One operation reading `var`, which holds `value`.
    fn read(&mut self, var: VarId, value: &Value, op: &SSAOp<VarId>, site: (OpId, u64, usize)) {
        let (id, block, index) = site;
        match op {
            SSAOp::Load { dst, addr, .. } if *addr == var => {
                let width = self.func.var(*dst).size;
                match value.exact() {
                    Some(place) => {
                        self.loaded.entry(place).or_default().push(*dst);
                        if let Some(address) = self.held.get(&place).cloned() {
                            self.set(*dst, address);
                        }
                        self.access(place, id, block, index, width, false);
                    }
                    None => self.opaque(id, value, false),
                }
            }
            SSAOp::Store { addr, val, .. } => {
                self.store(*addr, *val);
                let refunded =
                    || call_push(self.func, block, index, *val, self.sinks.calls_refund_stack);
                if *addr == var && !refunded() {
                    let width = self.func.var(*val).size;
                    match value.exact() {
                        Some(place) => self.access(place, id, block, index, width, true),
                        None => self.opaque(id, value, true),
                    }
                }
            }
            SSAOp::Copy { dst, .. } | SSAOp::CallRestore { dst, .. } => {
                self.set(*dst, value.clone());
            }
            SSAOp::IntAdd { dst, a, b } | SSAOp::IntSub { dst, a, b } => {
                let subtract = matches!(op, SSAOp::IntSub { .. });
                let next = self.displaced(var, value, (*a, *b), subtract);
                // The stack pointer moved by what no constant states: the frame is dynamic.
                let pointer = self.func.storage_of(*dst) == self.func.storage_of(self.entry_sp);
                if pointer && value.exact().is_some() && next.exact().is_none() {
                    let instruction = self
                        .func
                        .instruction_of(id)
                        .map(|at| DynamicFrame { instruction: at });
                    self.points.dynamic = self.points.dynamic.into_iter().chain(instruction).min();
                }
                self.set(*dst, next);
            }
            SSAOp::CallUse { storage, .. } => {
                let asked = (self.sinks.upward_at)(block, index, *storage);
                if let Some((pair, _)) = asked {
                    self.points.asked_reach.insert(pair);
                }
                if asked.is_some_and(|(_, upward)| upward) {
                    self.escape_up(value);
                } else {
                    self.escape(value);
                }
            }
            SSAOp::CallOther { .. } => self.escape(value),
            // An access no exact load or store states: through its address it stays in memory;
            // any other operand it reads is handed on.
            _ if memory_addresses(op).is_some() => {
                let addresses = memory_addresses(op).unwrap_or_default();
                if addresses.contains(&var) {
                    self.opaque(id, value, true);
                }
                let handed = (op.sources().iter())
                    .any(|source| **source == var && !addresses.contains(*source));
                if handed {
                    self.escape(value);
                }
            }
            // A truth value or a count: the address is only tested, and nothing of it is carried.
            SSAOp::CBranch { target, .. } if *target != var => {}
            _ if op.value_use() == r2il::ValueUse::Tests => {}
            // Masked, mixed or narrowed, it points into what the address did, at no exact place
            // (the seal's provenance rule): its own uses decide what it reaches.
            _ if op.value_use() != r2il::ValueUse::Consumes => {
                if let Some(dst) = op.dst() {
                    self.set(*dst, value.degraded());
                }
            }
            // Default deny: a target, a return or an unmodelled use reaches every place.
            _ => self.points.set_whole(),
        }
    }

    fn access(&mut self, place: i64, op: OpId, block: u64, index: usize, width: u32, store: bool) {
        self.accesses.entry(place).or_default().push(Access {
            op,
            block,
            index,
            width,
            store,
        });
    }

    /// A frame address stored: carried by a place that may be promoted, else handed on.
    fn store(&mut self, addr: VarId, val: VarId) {
        let Some(address) = self.values.get(val).cloned() else {
            return;
        };
        let carries = |place: i64| self.carried.is_none_or(|carried| carried.contains(&place));
        let place = self.values.get(addr).map(Value::exact);
        // A place stored again holds what it held and the new address at no exact offset, so a
        // cursor stepped through memory settles (the widening).
        let widened = |known: Option<&Value>| match known {
            Some(known) if known.join(&address) != *known => known.join(&address.degraded()),
            Some(known) => known.clone(),
            None => address.clone(),
        };
        if let Some(Some(place)) = place {
            let joined = widened(self.stored.get(&place));
            self.stored.insert(place, joined);
        }
        match place {
            Some(Some(place)) if carries(place) => {
                self.carriers.insert(place);
                let joined = widened(self.held.get(&place));
                if self.held.insert(place, joined.clone()).as_ref() != Some(&joined) {
                    for dst in self.loaded.get(&place).cloned().unwrap_or_default() {
                        self.set(dst, joined.clone());
                    }
                }
            }
            Some(_) => self.escape(&address),
            None => self.deferred.push((val, addr)),
        }
    }

    /// Where `var`, holding `value`, is moved by the other operand of an add or subtract.
    fn displaced(
        &self,
        var: VarId,
        value: &Value,
        (a, b): (VarId, VarId),
        subtract: bool,
    ) -> Value {
        let other = if a == var { b } else { a };
        let Value::Points(points) = value else {
            return Value::Top;
        };
        if subtract && b == var {
            return value.degraded();
        }
        let amount = self.defs.constant(self.func, other);
        let up = !subtract && non_negative(self.func, self.defs, other);
        let moved = points.iter().map(|point| match (*point, amount) {
            // Machine addresses are modular, as in the lifted arithmetic.
            (Point::Exact(offset), Some(amount)) => Point::Exact(if subtract {
                offset.wrapping_sub(amount)
            } else {
                offset.wrapping_add(amount)
            }),
            (kept @ (Point::Indexed { .. } | Point::Derived(_)), Some(_)) => kept,
            (derived @ Point::Derived(_), None) => derived,
            (Point::Exact(from) | Point::Indexed { from, .. }, None) => Point::Indexed { from, up },
        });
        Value::Points(moved.collect())
    }

    /// The merges with no value yet some of whose sources are frame addresses, in id order: the
    /// candidates a visit left, each source visit adding one, so O(candidates log) per call.
    fn partial_merges(&mut self) -> Vec<VarId> {
        let mut partial = std::mem::take(&mut self.merge_candidates);
        partial.retain(|dst| self.values.get(*dst).is_none());
        partial.sort_unstable();
        partial.dedup();
        partial
    }

    /// A tail transfer hands its callee every register: an address one holds where the transfer
    /// runs escapes (D381). `O(addressed values x tails)` dominance tests.
    fn hand_to_tails(&mut self, arguments: &StackArguments) {
        let tails = (arguments.calls.iter())
            .filter(|call| call.tail)
            .map(|call| call.op)
            .collect::<Vec<_>>();
        if tails.is_empty() {
            return;
        }
        let handed = (self.values.iter())
            .filter(|(var, _)| *var != self.entry_sp)
            .filter(|(var, _)| {
                self.func.storage_of(*var).is_some_and(|storage| {
                    storage.space == crate::CanonicalStorageSpace::Register
                        && !self.sinks.bases.contains(&Some(storage))
                })
            })
            .filter(|(var, _)| {
                (tails.iter()).any(|tail| self.defs.defined_before(self.func, *var, *tail))
            })
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        for value in &handed {
            self.escape(value);
        }
    }

    fn finish(mut self) -> Walked {
        let opaque = std::mem::replace(&mut self.opaque, IdMap::new(0));
        self.points.opaque = opaque.into_iter().map(|(_, access)| access).collect();
        // The flag the walk kept is what its points state (D397).
        debug_assert_eq!(
            self.points.unplaced,
            self.points.whole
                || (self.points.opaque.iter())
                    .any(|access| matches!(access.origin, Origin::Unplaced))
                || self
                    .points
                    .reaching()
                    .any(|point| point.extent == Extent::Derived)
        );
        for (val, addr) in std::mem::take(&mut self.deferred) {
            if self.values.get(addr).is_none()
                && let Some(address) = self.values.get(val).cloned()
            {
                self.escape(&address);
            }
        }
        // An address in a slot a call reads is handed to the callee: it escapes, and the slot
        // keeps its store.
        let widths = (self.stored.keys())
            .map(|place| {
                let widest =
                    (self.accesses.get(place).into_iter().flatten()).map(|access| access.width);
                (*place, widest.max().unwrap_or(1))
            })
            .collect();
        let arguments = &self.sinks.stack_arguments;
        self.hand_to_tails(arguments);
        let handed = arguments.read(&self.values, &widths);
        self.points.held_places = Places::new(widths);
        for place in &handed {
            if let Some(address) = self.stored.get(place).cloned() {
                self.escape(&address);
            }
        }
        self.points.handed = handed;
        let stores = (self.accesses.iter()).flat_map(|(place, list)| {
            let stored = list.iter().filter(|access| access.store);
            stored.map(|access| (*place, place.saturating_add(i64::from(access.width))))
        });
        let above = stores
            .filter(|(_, high)| *high > 0)
            .map(|(low, high)| (low.max(0), high));
        self.points.incoming_stores = merged(above);
        self.points.own_calls = arguments.own_calls();
        self.points.call_bases = arguments.by_call(&self.values);
        // A call to itself writes what the body does, as far as the rest states (D377).
        let own = (!self.points.own_calls.is_empty())
            .then(|| self.points.call_writes(self.sinks.machine))
            .flatten();
        self.points.rewritten =
            arguments.rewritten(self.func, (&self.values, &self.accesses), own.as_deref());
        Walked {
            points: self.points,
            accesses: self.accesses,
            carriers: self.carriers,
        }
    }
}

/// The addresses an access other than a plain load or store reads.
fn memory_addresses(op: &SSAOp<VarId>) -> Option<Vec<VarId>> {
    match op {
        SSAOp::LoadLinked { addr, .. }
        | SSAOp::StoreConditional { addr, .. }
        | SSAOp::LoadGuarded { addr, .. }
        | SSAOp::StoreGuarded { addr, .. } => Some(vec![*addr]),
        SSAOp::Atomic(access) => Some(vec![access.addr]),
        SSAOp::BlockTransfer(transfer) => Some(vec![transfer.destination, transfer.source]),
        _ => None,
    }
}

/// Whether a store is a call pushing its return address, which the callee refunds.
fn call_push(func: &SSAFunction, block: u64, index: usize, val: VarId, refunds: bool) -> bool {
    refunds
        && func.var(val).constant_bits().is_some()
        && func.get_block(block).is_some_and(|block| {
            block.ops()[index + 1..]
                .iter()
                .find(|op| !matches!(op, SSAOp::CallUse { .. }))
                .is_some_and(SSAOp::is_call)
        })
}

/// Whether a value is never negative: an extension from narrower, or a masked, shifted or
/// scaled one.
fn non_negative(func: &SSAFunction, defs: &Definitions, var: VarId) -> bool {
    let width = func.var(var).size * 8;
    match defs.op(defs.copied(var)).map(|(_, op)| op) {
        Some(SSAOp::IntZExt { .. }) => true,
        Some(SSAOp::IntAnd { a, b, .. }) => [*a, *b].iter().any(|mask| {
            func.var(*mask)
                .constant_bits()
                .is_some_and(|bits| width >= 1 && bits >> (width - 1) & 1 == 0)
        }),
        Some(SSAOp::IntRight { b, .. }) => {
            func.var(*b).constant_bits().is_some_and(|bits| bits > 0)
        }
        Some(SSAOp::IntLeft { a, b, .. } | SSAOp::IntMult { a, b, .. }) => {
            non_negative(func, defs, *a)
                && func
                    .var(*b)
                    .constant_bits()
                    .is_some_and(|bits| bits < u64::from(width))
        }
        _ => func
            .var(var)
            .constant_bits()
            .is_some_and(|bits| width >= 1 && bits >> (width - 1) & 1 == 0),
    }
}

/// A call's index in its block and the entry-relative spans it may write.
type CallSpans = (usize, Vec<(i64, i64)>);

/// The merged write spans reaching each block's entry. A worklist whose sets only grow, each at most
/// K times (K the calls' spans): `O(K x (B + E) x K log K)` worst, one round where they nest.
fn reaching_writes(
    func: &SSAFunction,
    in_block: &BTreeMap<u64, Vec<CallSpans>>,
) -> BTreeMap<u64, Vec<(i64, i64)>> {
    let mut entering = BTreeMap::<u64, Vec<(i64, i64)>>::new();
    let mut pending = in_block.keys().copied().collect::<Vec<_>>();
    while let Some(block) = pending.pop() {
        let calls = in_block.get(&block).map_or(&[][..], Vec::as_slice);
        let made = calls.iter().flat_map(|(_, spans)| spans.iter().copied());
        let entry = entering.get(&block).map_or(&[][..], Vec::as_slice);
        let leaving = merged(entry.iter().copied().chain(made));
        for next in func.successors(block) {
            if grow(entering.entry(next).or_default(), &leaving) {
                pending.push(next);
            }
        }
    }
    entering
}

/// `known` joined with `more`; whether it grew.
fn grow(known: &mut Vec<(i64, i64)>, more: &[(i64, i64)]) -> bool {
    let grown = merged(known.iter().chain(more).copied());
    let changed = grown != *known;
    *known = grown;
    changed
}

/// The loaded places of one block's `loads` (by index) that `live` or an earlier call there covers.
fn rewritten_in_block(
    loads: &[(u64, usize, i64, u32)],
    mut calls: Vec<CallSpans>,
    mut live: Vec<(i64, i64)>,
    rewritten: &mut BTreeSet<i64>,
) {
    calls.sort_unstable_by_key(|(index, _)| *index);
    let mut calls = calls.into_iter().peekable();
    for (_, index, place, width) in loads {
        let mut added = Vec::new();
        while let Some((_, spans)) = calls.next_if(|(call, _)| call < index) {
            added.extend(spans);
        }
        if !added.is_empty() {
            grow(&mut live, &added);
        }
        if overlaps(&live, *place, place.saturating_add(i64::from(*width))) {
            rewritten.insert(*place);
        }
    }
}

/// Whether merged `spans` share a byte with `[low, high)`. O(log n).
fn overlaps(spans: &[(i64, i64)], low: i64, high: i64) -> bool {
    let after = spans.partition_point(|(start, _)| *start < high);
    after
        .checked_sub(1)
        .is_some_and(|index| spans[index].1 > low)
}

/// Spans sorted with overlapping and touching ones joined. O(n log n).
fn merged(spans: impl Iterator<Item = (i64, i64)>) -> Vec<(i64, i64)> {
    let mut spans = spans.filter(|(low, high)| low < high).collect::<Vec<_>>();
    spans.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::with_capacity(spans.len());
    for (low, high) in spans {
        match out.last_mut() {
            Some(last) if low <= last.1 => last.1 = last.1.max(high),
            _ => out.push((low, high)),
        }
    }
    out
}

/// The bytes exactly one of two merged span lists covers. O(n + m).
fn differing(one: &[(i64, i64)], other: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut edges = (one.iter().chain(other))
        .flat_map(|(low, high)| [*low, *high])
        .collect::<Vec<_>>();
    edges.sort_unstable();
    edges.dedup();
    let covers = |spans: &[(i64, i64)], at: i64| {
        let after = spans.partition_point(|(low, _)| *low <= at);
        after
            .checked_sub(1)
            .is_some_and(|index| at < spans[index].1)
    };
    let pieces = edges.windows(2).map(|pair| (pair[0], pair[1]));
    merged(pieces.filter(|(low, _)| covers(one, *low) != covers(other, *low)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped(points: &[(i64, Extent)]) -> FramePoints {
        FramePoints {
            escaped: (points.iter())
                .map(|(at, extent)| FramePoint {
                    at: *at,
                    extent: *extent,
                })
                .collect(),
            ..FramePoints::default()
        }
    }

    /// A compiler slot is no object an index below it spans: only a point inside it names it.
    #[test]
    fn an_indexed_point_below_a_slot_does_not_name_it() {
        let points = escaped(&[(-64, Extent::Upward)]);
        assert!(!points.names(-16, -8));
        assert!(points.names(-64, -56));
        assert!(escaped(&[(-12, Extent::Either)]).names(-16, -8));
    }

    /// An escape reaches out to a save on either side, and upward only from an upward point.
    #[test]
    fn a_save_bounds_what_an_escape_reaches() {
        let saves = BTreeSet::from([-24]);
        let either = escaped(&[(-40, Extent::Either)]);
        assert!(either.reaches(-48, &saves) && either.reaches(-32, &saves));
        assert!(!either.reaches(-16, &saves));
        let upward = escaped(&[(-40, Extent::Upward)]);
        assert!(!upward.reaches(-48, &saves) && upward.reaches(-32, &saves));
    }

    /// Default deny: a derived point, an unplaced access or the whole frame reach every place.
    #[test]
    fn written_areas_differ_only_where_a_loaded_place_or_an_incoming_byte_lies() {
        assert_eq!(differing(&[(-32, 0)], &[]), vec![(-32, 0)]);
        assert_eq!(
            differing(&[(-32, -8)], &[(-16, 8)]),
            vec![(-32, -16), (-8, 8)]
        );
        let points = FramePoints {
            rewrite_decides: Places::new(BTreeMap::from([(-24, 8)])),
            call_bases: vec![CallBase {
                instruction: Some(0x10),
                op: OpId::from_index(0),
                base: Some(-32),
                tail: false,
            }],
            ..FramePoints::default()
        };
        // From the base at -32: unbounded covers the loaded [-24, -16), `(0, 4)` does not.
        assert!(!points.areas_alike(0x10, [None; 2], [None, Some(&[(0, 4)])]));
        assert!(points.areas_alike(0x10, [None; 2], [Some(&[(0, 4)]), Some(&[])]));
        // `(0, 40)` reaches past the entry pointer, which the body's own statement reads.
        assert!(!points.areas_alike(0x10, [None; 2], [Some(&[]), Some(&[(0, 40)])]));
    }

    #[test]
    fn a_derived_or_unplaced_point_reaches_every_place() {
        let none = BTreeSet::new();
        let mut derived = FramePoints::default();
        derived.leave(FramePoint {
            at: -40,
            extent: Extent::Derived,
        });
        assert!(derived.reaches(-200, &none));
        assert!(FramePoints::whole_frame().names(-16, -8));
        let opaque = FramePoints {
            opaque: vec![OpaqueAccess {
                op: OpId::from_index(0),
                origin: Origin::Unplaced,
                writes: true,
            }],
            unplaced: true,
            ..FramePoints::default()
        };
        assert!(opaque.unplaced() && opaque.reaches(-8, &none));
        assert!(!FramePoints::default().reaches(-8, &none));
    }
}
