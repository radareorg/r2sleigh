//! The frame's one escape walk, default deny, before slot promotion (doc/adr-frame-model.md,
//! "Escape spans"; doc/adr-callee-builds.md, "D365 as built"): `O(rounds x 65 x (V + E))`.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::call_reads::StackArea;
use crate::control::SsaWorkControl;
use crate::dense::{Csr, DenseId, IdMap, IdVec, Node};
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
    /// The walk that found `call_bases` classified every operation's transfer (D411).
    pub(crate) transfers: Option<crate::call_reads::Transfers>,
    /// The first instruction that moves the stack pointer by an amount no constant states (D355).
    pub(crate) dynamic: Option<DynamicFrame>,
    /// The entry-relative spans at or above the entry pointer its exact stores write (D377).
    pub(crate) incoming_stores: Vec<(i64, i64)>,
    /// The calls of the body to itself, by instruction.
    pub(crate) own_calls: BTreeSet<u64>,
    /// The places slot promotion took out of memory, by entry offset (D389).
    pub(crate) promoted: BTreeSet<i64>,
    /// Each cited printf whose format register a reload of a clean place gives, by instruction:
    /// the literal every store there writes (D432).
    pub(crate) formats: BTreeMap<u64, u64>,
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

    /// An address handed on: it may be indexed either way.
    fn escape(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                for point in points {
                    self.leave(match point {
                        Point::Derived(_) => point.frame_point(),
                        _ => FramePoint {
                            at: point.frame_point().at,
                            extent: Extent::Either,
                        },
                    });
                }
            }
            Value::Top => self.set_whole(),
        }
    }

    /// An address handed to a callee that reaches only upward through it.
    fn escape_up(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                for point in points {
                    self.leave(match point {
                        Point::Exact(at) => FramePoint {
                            at: *at,
                            extent: Extent::Upward,
                        },
                        indexed => indexed.frame_point(),
                    });
                }
            }
            Value::Top => self.set_whole(),
        }
    }

    /// Both rounds' points: what either states leaves or is accessed.
    fn absorb(&mut self, other: Self) {
        self.whole |= other.whole;
        self.unplaced |= other.unplaced;
        self.escaped.extend(other.escaped);
        self.opaque = merged_opaque(std::mem::take(&mut self.opaque), other.opaque);
        self.handed.extend(other.handed);
        self.rewritten.extend(other.rewritten);
        self.dynamic = self.dynamic.into_iter().chain(other.dynamic).min();
        self.incoming_stores = merged(
            self.incoming_stores
                .iter()
                .chain(&other.incoming_stores)
                .copied(),
        );
        self.own_calls.extend(other.own_calls);
        // Both rounds walk the same calls: a base the two disagree on is none.
        for (mine, theirs) in self.call_bases.iter_mut().zip(other.call_bases) {
            debug_assert_eq!(mine.op, theirs.op);
            mine.base = mine.base.filter(|base| theirs.base == Some(*base));
        }
    }

    /// What a call to this body may write of its caller's stack, from the call's pointer; a self call
    /// in two rounds (doc/adr-callee-builds.md, D377, D381). `O(calls x spans)`.
    pub fn call_writes(
        &self,
        context: &SourceMachineContext,
    ) -> Option<crate::call_reads::StackWrites> {
        let transfers = self.transfers?;
        // A tail transfer writes what its source-correlated callee states; any other, all.
        let stated = |_: usize, call: &CallBase, instruction: u64| {
            let stated = (!call.tail)
                || (context.raw_call_site_at(instruction))
                    .is_some_and(|identity| context.is_tail_call_site(identity));
            stated
                .then(|| context.call_reads(Some(instruction)))
                .flatten()?
                .writes
                .clone()
        };
        let spans = self.writes_bound(spent(context), stated)?;
        Some(crate::call_reads::StackWrites::within(spans, transfers))
    }

    /// `call_writes` with each call's statement from `stated`, and what a transfer spends.
    fn writes_bound(
        &self,
        (least, most): (i64, i64),
        stated: impl Fn(usize, &CallBase, u64) -> Option<Vec<(i64, i64)>>,
    ) -> Option<Vec<(i64, i64)>> {
        let writing = self.opaque.iter().any(|access| access.writes);
        if self.whole || !self.escaped.is_empty() || writing {
            return None;
        }
        let mut fixed = self.incoming_stores.clone();
        let mut own_bases = Vec::new();
        for (index, call) in self.call_bases.iter().enumerate() {
            // A call above what its transfer spends could move a cycle's spans up each round.
            let base = call.base.filter(|base| *base <= least)?;
            let instruction = call.instruction?;
            if self.own_calls.contains(&instruction) {
                own_bases.push(base);
                continue;
            }
            let writes = stated(index, call, instruction)?;
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

    /// The literal each reloaded printf format holds, by the call's instruction (D432).
    pub const fn reloaded_formats(&self) -> &BTreeMap<u64, u64> {
        &self.formats
    }

    /// What a restatement keeps the canary's decision on: whether a point is unplaced, and every
    /// offset an escaped or opaque address points at (`names`).
    fn named(&self) -> (bool, BTreeSet<i64>) {
        let at = self.reaching().map(|point| point.at);
        (self.unplaced, at.collect())
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

/// What a transfer spends at least and at most: an unstated mechanism spends nothing or one
/// address (D386).
fn spent(context: &SourceMachineContext) -> (i64, i64) {
    let address = i64::from(context.memory_model().default_address_bits() / 8);
    context
        .return_mechanism()
        .map_or((0, address), |mechanism| {
            let spent = r2source::SourceReturnMechanism::spent(Some(mechanism));
            (spent, spent)
        })
}

/// One exact access at a place, for promotion's rewrite.
#[derive(Debug)]
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

/// What the decision reads of the callees: each (callee, position)'s upward reach and each call's
/// read and written areas (D365). Nothing else of the context reaches it.
pub(crate) struct Evidence<'a> {
    context: &'a SourceMachineContext,
}

impl<'a> Evidence<'a> {
    pub(crate) fn of(context: &'a SourceMachineContext) -> Self {
        debug_assert!(!context.reloads_settled(), "a walk reads settled rows");
        Self { context }
    }

    /// What the call at `instruction` writes were its format the literal at `literal` (D432).
    fn reloaded_writes(&self, instruction: u64, literal: u64) -> Option<Vec<(i64, i64)>> {
        self.context
            .reloaded_call_reads(instruction, literal)?
            .writes
    }

    fn upward(&self, (target, position): (u64, usize)) -> bool {
        (self.context.callee_reach_at(target, position))
            .is_some_and(crate::interproc::ArgumentReach::is_upward)
    }

    /// The stack a call may read and write, from its pointer; none where nothing bounds it.
    fn areas(&self, instruction: Option<u64>) -> (StackArea, StackArea) {
        let reads = self.context.call_reads(instruction);
        reads.map_or((None, None), |reads| {
            (reads.stack.clone(), reads.writes.clone())
        })
    }
}

/// What promotion reads of one round's accessed places, none of it a callee's: `slot_promotion`
/// states it from the body, the decision reads it (D365).
#[derive(Debug, Default)]
pub(crate) struct PlaceFacts {
    /// The places a preserved register's entry value is saved into: they bound an escape.
    pub(crate) saves: BTreeSet<i64>,
    /// Each place the function owns that every access reads or writes at one width.
    pub(crate) candidates: BTreeMap<i64, PlaceBits>,
}

/// One candidate place: its width, and what keeps it in memory whatever a callee states.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlaceBits {
    pub(crate) width: u32,
    pub(crate) overlaps: bool,
    /// A save slot read back: the frame round-trip certificate answers for it.
    pub(crate) save: bool,
    pub(crate) declared: bool,
}

/// One round's propagation: everything the round found that no callee states (D365).
#[derive(Debug)]
struct RoundTable {
    /// The escapes, opaque accesses, dynamic frame, incoming stores and call bases.
    points: FramePoints,
    /// Each `CallUse` handing a frame address to a callee's position, with the address.
    sinks: Vec<((u64, usize), Value)>,
    /// Each exact place a frame address is stored into: the address and the widest access there.
    stored: BTreeMap<i64, (Value, u32)>,
    /// Each call's area base, by `WalkSite::calls`.
    bases: Vec<Option<i64>>,
    accesses: Accesses,
    carriers: BTreeSet<i64>,
    places: PlaceFacts,
    /// The cited printf sites whose format a load of one place gives (D432).
    reloads: Vec<Reload>,
}

/// A cited printf whose format register a load of `place` in the call's own block gives, every
/// store to `place` writing `literal` at its one width (D432).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reload {
    /// The call's index in `WalkSite::calls`.
    call: usize,
    /// The load's index in the call's block.
    load: usize,
    place: i64,
    width: u32,
    literal: u64,
}

/// A reload the gate passed, with the area its call writes were its format the stored literal.
type Gated = (Reload, Vec<(i64, i64)>);

/// What every round of one walk shares, none of it a callee's.
#[derive(Debug)]
struct WalkSite {
    entry: u64,
    calls: Vec<CallArguments>,
    transfers: crate::call_reads::Transfers,
    /// An entry edge runs the prologue again: an offset names a place per pass.
    reentered: bool,
    /// What a transfer spends at least and at most.
    spent: (i64, i64),
    /// The lifted graph's blocks ascending, a [`Node`] indexing them, each one's successors and
    /// predecessors, and the nodes in reverse postorder: read by the writes reaching each load.
    blocks: Vec<u64>,
    successors: Csr<Node, Node>,
    predecessors: Csr<Node, Node>,
    order: Vec<Node>,
    /// The entry block's node: where no store has yet reached a place.
    root: Option<Node>,
}

impl WalkSite {
    /// The site of `func`'s walk; each edge placed by binary search, `O(E log B)`, and an edge out
    /// of the lifted blocks dropped.
    fn of(func: &SSAFunction, machine: &SourceMachineContext, arguments: StackArguments) -> Self {
        let mut blocks = func.block_addrs().to_vec();
        blocks.sort_unstable();
        let edges = (blocks.iter().enumerate()).flat_map(|(at, block)| {
            let from = Node::from_index(at);
            let next = func.successors(*block).into_iter();
            next.filter_map(|next| node_of(&blocks, next).map(|to| (from, to)))
                .collect::<Vec<_>>()
        });
        let edges = edges.collect::<Vec<_>>();
        let successors = Csr::from_pairs(blocks.len(), edges.iter().copied());
        let predecessors =
            Csr::from_pairs(blocks.len(), edges.iter().map(|(from, to)| (*to, *from)));
        // `block_addrs` is the reverse postorder of the blocks the entry reaches.
        let order = (func.block_addrs().iter())
            .filter_map(|block| node_of(&blocks, *block))
            .collect();
        let root = node_of(&blocks, func.root());
        Self {
            entry: func.entry,
            root,
            reentered: func.cfg().has_entry_edge(),
            spent: spent(machine),
            blocks,
            successors,
            predecessors,
            order,
            calls: arguments.calls,
            transfers: arguments.transfers,
        }
    }

    /// The node of the block at `addr`, by binary search: `O(log B)`.
    fn node(&self, addr: u64) -> Option<Node> {
        node_of(&self.blocks, addr)
    }
}

fn node_of(blocks: &[u64], addr: u64) -> Option<Node> {
    blocks.binary_search(&addr).ok().map(Node::from_index)
}

/// One round as walked and decided: what a restatement decides again and compares.
#[derive(Debug)]
struct HeldRound {
    table: RoundTable,
    promoted: BTreeMap<i64, u32>,
    unplaced: bool,
}

#[derive(Debug)]
enum Decided {
    /// No stack pointer carrier or no settled definitions: the whole frame, whatever a callee states.
    Whole,
    Rounds(Box<HeldRounds>),
}

/// Every round a walk held, and the site they share.
#[derive(Debug)]
struct HeldRounds {
    site: WalkSite,
    rounds: Vec<HeldRound>,
    /// The round where no place carries, where the last round was unplaced.
    no_carrier: Option<RoundTable>,
}

/// A build's frame walk: its rounds' tables and decisions, held beside a recovered build so a
/// restatement decides them again (doc/adr-callee-builds.md, "D365 as built").
#[derive(Debug)]
pub(crate) struct FrameWalk {
    decided: Decided,
    /// The canary's projection of the decided points (`FramePoints::named`).
    named: (bool, BTreeSet<i64>),
    /// The reloaded formats decided, which the context settles (D432).
    formats: BTreeMap<u64, u64>,
}

impl FrameWalk {
    /// The walk that decided `points`: what a restatement compares against.
    fn of(points: &FramePoints, decided: Decided) -> Self {
        Self {
            decided,
            named: points.named(),
            formats: points.formats.clone(),
        }
    }

    /// The last round's exact accesses, by place, for promotion's rewrite.
    pub(crate) fn accesses(&self) -> Option<&Accesses> {
        match &self.decided {
            Decided::Whole => None,
            Decided::Rounds(held) => (held.rounds.last()).map(|round| &round.table.accesses),
        }
    }

    /// The points every round decides against `evidence` where each round promotes and places as it
    /// did and the canary's projection is equal; `None` where a decision moved. `O(rounds x |D|)`.
    pub(crate) fn restate<C: SsaWorkControl + ?Sized>(
        &self,
        evidence: &Evidence<'_>,
        control: &C,
    ) -> Option<FramePoints> {
        let Decided::Rounds(held) = &self.decided else {
            return Some(FramePoints::whole_frame());
        };
        let HeldRounds {
            site,
            rounds,
            no_carrier,
        } = held.as_ref();
        let mut steps = 0;
        let mut last = None;
        for round in rounds {
            let (points, promoted) = decide(&round.table, site, evidence, &mut steps);
            if promoted != round.promoted || points.unplaced() != round.unplaced {
                control.frame_decided(steps);
                return None;
            }
            last = Some((points, promoted));
        }
        let (points, promoted) = last?;
        let points = settle(
            points,
            &promoted,
            no_carrier.as_ref(),
            site,
            (evidence, &mut steps),
        );
        control.frame_decided(steps);
        (points.named() == self.named && points.formats == self.formats).then_some(points)
    }
}

/// One round decided: its points and the places it promotes. `O(sinks x 64 + calls x places +
/// (B + E) K log K + places x points log saves)`; `steps` counts sink points and candidates.
fn decide(
    table: &RoundTable,
    site: &WalkSite,
    evidence: &Evidence<'_>,
    steps: &mut u64,
) -> (FramePoints, BTreeMap<i64, u32>) {
    let points = decide_points(table, site, (evidence, steps));
    *steps += table.places.candidates.len() as u64;
    let promoted = eligible(&points, &table.places, site);
    (points, promoted)
}

/// A round's points against the callees: each sink escapes upward or either way, a stored address
/// a call reads escapes, and the calls' writes decide `rewritten`.
fn decide_points(
    table: &RoundTable,
    site: &WalkSite,
    (evidence, steps): (&Evidence<'_>, &mut u64),
) -> FramePoints {
    let mut points = table.points.clone();
    for (pair, value) in &table.sinks {
        *steps += match value {
            Value::Points(set) => set.len() as u64,
            Value::Top => 1,
        };
        let whole_before = points.unplaced;
        if evidence.upward(*pair) {
            points.escape_up(value);
        } else {
            points.escape(value);
        }
        if points.unplaced && !whole_before {
            r2il::refusal_evidence!(
                "frame-reach",
                "the call to {:#x} takes a frame address no offset places at argument {}",
                pair.0,
                pair.1
            );
        }
    }
    let areas = (site.calls.iter())
        .map(|call| match call.reads_stated {
            true => evidence.areas(call.instruction),
            false => (None, None),
        })
        .collect::<Vec<_>>();
    let handed = read((&site.calls, &table.bases), &areas, &table.stored);
    for place in &handed {
        if let Some((address, _)) = table.stored.get(place) {
            points.escape(address);
        }
    }
    points.handed = handed;
    let own = |(call, (_, writes)): (&CallArguments, &(StackArea, StackArea))| {
        call.targets_entry && writes.is_none()
    };
    let calls = || site.calls.iter().zip(&areas);
    points.own_calls = calls()
        .filter(|pair| own(*pair))
        .filter_map(|(call, _)| call.instruction)
        .collect();
    // A call to itself writes what the body does, as far as the rest states (D377).
    // `call_bases` lists the calls by instruction then operation, as `by_call` sorts them.
    let mut order = (0..site.calls.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| (site.calls[*index].instruction, site.calls[*index].op));
    let stated = |index: usize, call: &CallBase, _: u64| {
        debug_assert_eq!(site.calls[order[index]].op, call.op);
        areas[order[index]].1.clone()
    };
    let own_writes = (!points.own_calls.is_empty())
        .then(|| points.writes_bound(site.spent, stated))
        .flatten();
    let writes = calls()
        .map(|pair| match own(pair) {
            true => own_writes.as_deref(),
            false => pair.1.1.as_deref(),
        })
        .collect::<Vec<_>>();
    let reloads = conditional(table, site, &points, evidence);
    let (rewritten, formats) = rewritten(site, (&table.bases, &writes), &table.accesses, &reloads);
    (points.rewritten, points.formats) = (rewritten, formats);
    points
}

/// The reloads whose place nothing but a call's write keeps in memory, each with the area its call
/// writes were its format the stored literal (D432). `O(R x reads)`.
fn conditional(
    table: &RoundTable,
    site: &WalkSite,
    points: &FramePoints,
    evidence: &Evidence<'_>,
) -> Vec<Gated> {
    let clean = |reload: &Reload| {
        let kept = kept(points, &table.places, reload.place);
        let entered = site.root.is_some() && !site.reentered;
        entered && kept.is_some_and(|(width, kept)| width == reload.width && !kept)
    };
    (table.reloads.iter().filter(|reload| clean(reload)))
        .filter_map(|reload| {
            let instruction = site.calls[reload.call].instruction?;
            Some((
                *reload,
                evidence.reloaded_writes(instruction, reload.literal)?,
            ))
        })
        .collect()
}

/// A candidate place's width, and whether anything but a call's write keeps it in memory: an
/// overlap, a save, a declaration, a handed address or an escape; none for no candidate.
fn kept(points: &FramePoints, places: &PlaceFacts, offset: i64) -> Option<(u32, bool)> {
    let bits = places.candidates.get(&offset)?;
    let handed = points.handed().contains(&offset);
    let reached = points.reaches(offset, &places.saves);
    let kept = bits.overlaps || bits.save || bits.declared || handed || reached;
    Some((bits.width, kept))
}

/// Each cited printf whose format register its own block loads from one place, every store to
/// which writes one constant at the place's one width (D432). `O(C x u + A log C)`.
fn reloads(
    (func, defs): (&SSAFunction, &Definitions),
    machine: &SourceMachineContext,
    site: &WalkSite,
    accesses: &Accesses,
) -> Vec<Reload> {
    let format_load = |call: &CallArguments| {
        let register = machine.reloaded_format_register(call.instruction?)?;
        let ops = func.get_block(call.at.0)?.ops();
        let uses = (ops.get(..call.at.1)?.iter().rev()).map_while(|op| match op {
            SSAOp::CallUse { src, storage } => Some((*src, *storage)),
            _ => None,
        });
        let (src, _) = uses.into_iter().find(|(_, storage)| *storage == register)?;
        let (load, _, width) = defs.load(func, src)?;
        (width == register.size).then_some(load)
    };
    let mut wanted = (site.calls.iter().enumerate())
        .filter(|(_, call)| !call.tail)
        .filter_map(|(index, call)| Some((format_load(call)?, index)))
        .collect::<Vec<_>>();
    wanted.sort_unstable();
    let stored = |access: &Access| match func.get_block(access.block)?.ops().get(access.index)? {
        SSAOp::Store { val, .. } => defs.constant(func, *val),
        _ => None,
    };
    let mut found = Vec::new();
    for (place, list) in accesses.iter().filter(|_| !wanted.is_empty()) {
        let width = list.first().map_or(0, |access| access.width);
        let literals = (list.iter().filter(|access| access.store))
            .map(stored)
            .collect::<Option<BTreeSet<_>>>();
        let one = list.iter().all(|access| access.width == width);
        let Some(&literal) = literals
            .filter(|set| set.len() == 1 && one)
            .as_ref()
            .and_then(BTreeSet::first)
        else {
            continue;
        };
        for access in list.iter().filter(|access| !access.store) {
            let from = wanted.partition_point(|(op, _)| *op < access.op);
            for (_, call) in wanted[from..].iter().take_while(|(op, _)| *op == access.op) {
                let (block, at) = site.calls[*call].at;
                found.extend(
                    (access.block == block && access.index < at).then_some(Reload {
                        call: *call,
                        load: access.index,
                        place: *place,
                        width,
                        literal: literal.cast_unsigned(),
                    }),
                );
            }
        }
    }
    found.sort_unstable_by_key(|reload| reload.call);
    found
}

/// The last round's points settled: the no-carrier round's absorbed, a reentered frame whole, and
/// the promoted places recorded where a place is fixed.
fn settle(
    mut points: FramePoints,
    promoted: &BTreeMap<i64, u32>,
    no_carrier: Option<&RoundTable>,
    site: &WalkSite,
    (evidence, steps): (&Evidence<'_>, &mut u64),
) -> FramePoints {
    // An unplaced round promotes nothing: its places keep their stores, so each stored address
    // also leaves, as the round where no place carries states.
    if let Some(table) = no_carrier {
        points.absorb(decide_points(table, site, (evidence, steps)));
    }
    if site.reentered && !(points.escaped.is_empty() && points.opaque.is_empty()) {
        points.set_whole();
    }
    if !points.unplaced() {
        points.promoted = promoted.keys().copied().collect();
    }
    points
}

/// Each place a variable may stand for, with its one width: no escape reaches it, no call reads
/// or rewrites it, and nothing else keeps it (doc/adr-frame-model.md, P4.3).
fn eligible(points: &FramePoints, places: &PlaceFacts, site: &WalkSite) -> BTreeMap<i64, u32> {
    // An entry block something branches back to runs its prologue again: no place is fixed.
    if points.unplaced() || site.reentered {
        return BTreeMap::new();
    }
    let mut promotable = BTreeMap::new();
    for (offset, bits) in &places.candidates {
        let handed = points.handed().contains(offset);
        // A call may rewrite its own argument area, so a load after it reads memory (D369).
        let rewritten = points.rewritten().contains(offset);
        let reached = points.reaches(*offset, &places.saves);
        let PlaceBits {
            width,
            overlaps,
            save,
            declared,
        } = *bits;
        if kept(points, places, *offset).is_none_or(|(_, kept)| kept) || rewritten {
            r2il::refusal_evidence!(
                "promote-stack-slot",
                "{:#x}: slot at {offset} stays in memory: overlap {overlaps}, save {save}, declared {declared}, handed {handed}, rewritten {rewritten}, reached {reached}",
                site.entry,
            );
            continue;
        }
        promotable.insert(*offset, width);
    }
    promotable
}

/// The one round of a body with no entry stack pointer value: every transfer is at entry (D381).
fn walk_at_entry<C: SsaWorkControl + ?Sized>(
    func: &SSAFunction,
    site: WalkSite,
    evidence: &Evidence<'_>,
    control: &C,
) -> (FrameWalk, FramePoints, BTreeMap<i64, u32>) {
    let mut steps = 0;
    let values = IdMap::new(func.values().len());
    let table = RoundTable::empty(&site, &values);
    let (points, promoted) = decide(&table, &site, evidence, &mut steps);
    let unplaced = points.unplaced();
    let points = settle(points, &promoted, None, &site, (evidence, &mut steps));
    control.frame_decided(steps);
    let rounds = vec![HeldRound {
        table,
        promoted: promoted.clone(),
        unplaced,
    }];
    let held = HeldRounds {
        site,
        rounds,
        no_carrier: None,
    };
    let walk = FrameWalk::of(&points, Decided::Rounds(Box::new(held)));
    (walk, points, promoted)
}

/// Walk `func`'s frame addresses, round by round: propagate, then decide against the callees'
/// statements. The promoted set only shrinks, so at most one round per place.
pub(crate) fn walk<C: SsaWorkControl + ?Sized>(
    func: &SSAFunction,
    (defs, machine): (&Definitions, &SourceMachineContext),
    calls_refund_stack: bool,
    places: impl Fn(&Accesses) -> PlaceFacts,
    control: &C,
) -> (FrameWalk, FramePoints, BTreeMap<i64, u32>) {
    let whole = || {
        let walk = FrameWalk::of(&FramePoints::whole_frame(), Decided::Whole);
        (walk, FramePoints::whole_frame(), BTreeMap::new())
    };
    let Some(stack_pointer) = machine.stack_pointer_carrier() else {
        return whole();
    };
    let entry_sp = (0..func.values().len())
        .map(VarId::from_index)
        .find(|id| func.var(*id).version == 0 && func.storage_of(*id) == Some(stack_pointer));
    if entry_sp.is_some() && defs.exhausted().is_some() {
        return whole();
    }
    let evidence = Evidence::of(machine);
    let (mut walk_steps, mut steps) = (0, 0);
    let arguments = StackArguments::of(func, machine, stack_pointer, entry_sp);
    let site = WalkSite::of(func, machine, arguments);
    // No entry stack pointer value: no frame address exists, and every transfer is at entry (D381).
    let Some(entry_sp) = entry_sp else {
        return walk_at_entry(func, site, &evidence, control);
    };
    let sinks = Sinks::of(func, machine, stack_pointer, calls_refund_stack);
    let uses = Uses::of(func);
    let body = (func, defs, &uses);
    let mut carried: Option<BTreeSet<i64>> = None;
    let mut rounds = Vec::new();
    loop {
        let walker = Walker::new(body, entry_sp, (&sinks, &site), carried.as_ref());
        let mut table = walker.run(&mut walk_steps);
        table.places = places(&table.accesses);
        table.reloads = reloads((func, defs), machine, &site, &table.accesses);
        let (points, promoted) = decide(&table, &site, &evidence, &mut steps);
        let unplaced = points.unplaced();
        let no_carrier = (unplaced && carried.as_ref().is_none_or(|carried| !carried.is_empty()))
            .then(|| {
                let kept = BTreeSet::new();
                Walker::new(body, entry_sp, (&sinks, &site), Some(&kept)).run(&mut walk_steps)
            });
        let settled = unplaced || (table.carriers.iter()).all(|place| promoted.contains_key(place));
        rounds.push(HeldRound {
            table,
            promoted: promoted.clone(),
            unplaced,
        });
        if !settled {
            carried = Some(promoted.keys().copied().collect());
            continue;
        }
        let points = settle(
            points,
            &promoted,
            no_carrier.as_ref(),
            &site,
            (&evidence, &mut steps),
        );
        control.frame_walked(walk_steps);
        control.frame_decided(steps);
        let origins = (points.opaque.iter()).map(|access| &access.origin);
        let (escaped, opaque) = (&points.escaped, origins.collect::<BTreeSet<_>>());
        let unplaced = points.unplaced();
        r2il::refusal_evidence!(
            "frame-reach",
            "{:#x}: escaped {escaped:?}, opaque {opaque:?}, unplaced {unplaced}",
            func.entry,
        );
        let promotable = match points.unplaced() {
            true => BTreeMap::new(),
            false => promoted,
        };
        let held = HeldRounds {
            site,
            rounds,
            no_carrier,
        };
        let walk = FrameWalk::of(&points, Decided::Rounds(Box::new(held)));
        return (walk, points, promotable);
    }
}

impl RoundTable {
    /// A round over a body with no frame address: only its calls' bases.
    fn empty(site: &WalkSite, values: &IdMap<VarId, Value>) -> Self {
        Self {
            points: FramePoints {
                call_bases: by_call(&site.calls, values),
                transfers: Some(site.transfers),
                ..FramePoints::default()
            },
            sinks: Vec::new(),
            stored: BTreeMap::new(),
            bases: (site.calls.iter()).map(|call| call.base(values)).collect(),
            accesses: Accesses::new(),
            carriers: BTreeSet::new(),
            places: PlaceFacts::default(),
            reloads: Vec::new(),
        }
    }
}

/// The (callee, position) a `CallUse` at a block and index hands its register to.
type CalleeAt<'a> = Box<dyn Fn(u64, usize, crate::CanonicalStorageId) -> Option<(u64, usize)> + 'a>;

/// Where a frame address leaves through a call.
struct Sinks<'a> {
    calls_refund_stack: bool,
    /// The registers a call may read where no `CallUse` says which: none under a convention.
    read_by_calls: Box<dyn Fn(crate::CanonicalStorageId) -> bool + 'a>,
    /// The (callee, position) the `CallUse` at this block and index hands its register to, by the
    /// site's model; the decision reads the callee's reach there.
    callee_at: CalleeAt<'a>,
    /// The stack and frame pointers: the frame's own bases, not addresses handed on.
    bases: [Option<crate::CanonicalStorageId>; 2],
}

impl<'a> Sinks<'a> {
    fn of(
        func: &'a SSAFunction,
        machine: &'a SourceMachineContext,
        stack_pointer: crate::CanonicalStorageId,
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
        // The callee is the call's raw identity's target, its position by the site's model.
        let callee_at = move |block: u64, index: usize, storage: crate::CanonicalStorageId| {
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
            Some((target, position))
        };
        Self {
            calls_refund_stack,
            bases,
            read_by_calls: Box::new(read_by_calls),
            callee_at: Box::new(callee_at),
        }
    }
}

/// The stack each call may read: a frame address stored there leaves the body
/// (doc/adr-call-boundary.md, "D217 as built").
struct StackArguments {
    calls: Vec<CallArguments>,
    transfers: crate::call_reads::Transfers,
}

/// One call or tail transfer, from the stack pointer its area is measured at; its areas are the
/// decision's to read (D365).
#[derive(Debug)]
struct CallArguments {
    op: OpId,
    /// The block the call is in and its index there.
    at: (u64, usize),
    /// The stack pointer reaching it; none where the body never reads one, the entry pointer.
    pointer: Option<VarId>,
    /// What the transfer spends where no restore records the pointer entering it.
    shift: i64,
    /// A direct call to the body itself: it writes what the body does where nothing else states.
    targets_entry: bool,
    /// Whether a statement may bound its areas: any call, and a tail the source correlates.
    reads_stated: bool,
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
        // Each operation of each block the walk reached went through `SSAOp::transfer`.
        let transfers = crate::call_reads::Transfers::classified();
        Self { calls, transfers }
    }
}

/// Each call's area base, by instruction then operation.
fn by_call(calls: &[CallArguments], values: &IdMap<VarId, Value>) -> Vec<CallBase> {
    let mut bases = (calls.iter())
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

/// A call's written area as spans from its pointer; `None` where nothing bounds it.
type Area<'a> = Option<&'a [(i64, i64)]>;

/// The loaded keys, then one unset key per reloaded place (D432), and what a span covers of them.
struct Keys {
    /// One per loaded `(place, width)`, sorted: a load's bit is its key's.
    loaded: Vec<(i64, u32)>,
    /// One per reloaded `(place, width)`, sorted, numbered after `loaded`.
    unset: Vec<(i64, u32)>,
    /// Each unset key with its place's loaded key.
    paired: Vec<(usize, usize)>,
    widest: i64,
}

impl Keys {
    fn of(accesses: &Accesses, reloads: &[Gated]) -> Self {
        let mut loaded = (accesses.iter())
            .flat_map(|(place, list)| list.iter().map(move |access| (*place, access)))
            .filter(|(_, access)| !access.store)
            .map(|(place, access)| (place, access.width))
            .collect::<Vec<_>>();
        loaded.sort_unstable();
        loaded.dedup();
        let mut unset = (reloads.iter())
            .map(|(reload, _)| (reload.place, reload.width))
            .collect::<Vec<_>>();
        unset.sort_unstable();
        unset.dedup();
        let paired = (unset.iter().enumerate())
            .filter_map(|(at, key)| Some((loaded.binary_search(key).ok()?, loaded.len() + at)))
            .collect();
        let widest = (loaded.iter().map(|(_, width)| i64::from(*width)).max()).unwrap_or(0);
        Self {
            loaded,
            unset,
            paired,
            widest,
        }
    }

    fn bits(&self) -> usize {
        self.loaded.len() + self.unset.len()
    }

    fn loaded(&self, place: i64, width: u32) -> Option<usize> {
        self.loaded.binary_search(&(place, width)).ok()
    }

    fn unset(&self, place: i64, width: u32) -> Option<usize> {
        let at = self.unset.binary_search(&(place, width)).ok()?;
        Some(self.loaded.len() + at)
    }

    /// The keys `spans` cover: a loaded key's unset key with it.
    fn covered(&self, spans: &[(i64, i64)]) -> Vec<u64> {
        let mut words = covered(&self.loaded, self.widest, spans, self.bits());
        for (loaded, unset) in &self.paired {
            if bit(&words, *loaded) {
                words[unset / 64] |= 1 << (unset % 64);
            }
        }
        words
    }
}

/// Places a call's write reaches with no exact store of theirs between (D369, D427), and each
/// reload's literal where its place holds it (D432); doc/adr-one-ir.md, "Reaching frame writes".
fn rewritten(
    site: &WalkSite,
    (bases, writes): (&[Option<i64>], &[Area<'_>]),
    accesses: &Accesses,
    reloads: &[Gated],
) -> (BTreeSet<i64>, BTreeMap<u64, u64>) {
    let every = || (accesses.keys().copied().collect(), BTreeMap::new());
    let keys = Keys::of(accesses, reloads);
    let mut events = IdVec::from_fn(site.blocks.len(), |_: Node| Vec::<(usize, Event)>::new());
    if !call_events(site, (bases, writes), (&keys, reloads), &mut events) {
        return every();
    }
    let mut loads = Vec::new();
    let mut rewritten = BTreeSet::new();
    // Only a place of one width has a store that covers every load of it.
    let each = accesses.iter().flat_map(|(place, list)| {
        let one = list.iter().all(|access| access.width == list[0].width);
        list.iter().map(move |access| (*place, one, access))
    });
    for (place, one, access) in each {
        let Some(at) = keys.loaded(place, access.width) else {
            continue;
        };
        let Some(node) = site.node(access.block) else {
            // Default deny: a load outside the numbered blocks may read a rewritten place.
            if !access.store {
                rewritten.insert(place);
            }
            continue;
        };
        let event = match access.store {
            true if one => Event::Kill(at),
            true => continue,
            false => {
                loads.push(place);
                Event::Load(at, loads.len() - 1)
            }
        };
        if let (Event::Kill(_), Some(unset)) = (&event, keys.unset(place, access.width)) {
            events[node].push((access.index, Event::Kill(unset)));
        }
        events[node].push((access.index, event));
    }
    let mut seed = vec![0u64; keys.bits().div_ceil(64)];
    fill(&mut seed, keys.loaded.len(), keys.bits());
    let solve = (site.order.as_slice(), &site.successors, &site.predecessors);
    let entry = (keys.bits(), (site.root, seed.as_slice()));
    let Some(solved) = reaching_rewrites(solve, &mut events, entry, reloads.len()) else {
        return every();
    };
    let reached = (loads.iter()).zip(solved.reached);
    rewritten.extend(reached.filter_map(|(place, hit)| hit.then_some(*place)));
    let held = (reloads.iter()).zip(solved.held).filter(|(_, held)| *held);
    let formats = held.filter_map(|((reload, _), _)| {
        let instruction = site.calls[reload.call].instruction?;
        Some((instruction, reload.literal))
    });
    (rewritten, formats.collect())
}

/// Each non-tail call's write, a reload's as its format load and its conditional write (D432);
/// false where a call lies outside the numbered blocks, which may rewrite every loaded place.
fn call_events(
    site: &WalkSite,
    (bases, writes): (&[Option<i64>], &[Area<'_>]),
    (keys, reloads): (&Keys, &[Gated]),
    events: &mut IdVec<Node, Vec<(usize, Event)>>,
) -> bool {
    let calls = (site.calls.iter()).zip(bases).zip(writes).enumerate();
    for (index, ((call, base), area)) in calls.filter(|(_, ((call, _), _))| !call.tail) {
        let spans = |area: Area<'_>| match (base, area) {
            (None, _) => vec![(i64::MIN, i64::MAX)],
            // The call's own push and its callee's frame lie below its pointer.
            (Some(base), Some(area)) => merged(
                (area.iter())
                    .map(|(low, high)| (base.wrapping_add(*low), base.wrapping_add(*high)))
                    .chain([(i64::MIN, *base)]),
            ),
            // Unbounded, it is still this frame's: it ends at the entry pointer.
            (Some(base), None) => merged([(i64::MIN, *base), (*base, 0)].into_iter()),
        };
        let Some(node) = site.node(call.at.0) else {
            return false;
        };
        let slot = (reloads
            .binary_search_by_key(&index, |(reload, _)| reload.call)
            .ok())
        .filter(|_| base.is_some());
        let unset = slot.and_then(|slot| {
            let (reload, bounded) = &reloads[slot];
            Some((
                slot,
                reload.load,
                bounded,
                keys.unset(reload.place, reload.width)?,
            ))
        });
        let event = match unset {
            Some((slot, load, bounded, unset)) => {
                let (bounded, whole) = (
                    keys.covered(&spans(Some(bounded))),
                    keys.covered(&spans(*area)),
                );
                let extra = (whole.iter().zip(&bounded))
                    .map(|(whole, bounded)| whole & !bounded)
                    .collect();
                events[node].push((load, Event::Format(slot, unset)));
                Event::Reloaded {
                    slot,
                    bounded,
                    extra,
                }
            }
            None => Event::Write(keys.covered(&spans(*area))),
        };
        events[node].push((call.at.1, event));
    }
    true
}

/// One event of a block, by its index there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    /// A call writes the keys set in these words.
    Write(Vec<u64>),
    /// An exact store of the key's place at its one width.
    Kill(usize),
    /// A load of the key, numbered.
    Load(usize, usize),
    /// Reload `slot`'s format load: its unset key, read for the call after it (D432).
    Format(usize, usize),
    /// Reload `slot`'s call: it writes `bounded`, and `extra` too where its load read the place unset.
    Reloaded {
        slot: usize,
        bounded: Vec<u64>,
        extra: Vec<u64>,
    },
}

/// The keys `spans` overlap, as words over `bits` keys: each span's keys found by binary search and
/// filled by word. `O(S (log P + P / 64 + W))` for `W` keys starting below a span's low end.
fn covered(keys: &[(i64, u32)], widest: i64, spans: &[(i64, i64)], bits: usize) -> Vec<u64> {
    let mut words = vec![0u64; bits.div_ceil(64)];
    for (low, high) in spans {
        let from = keys.partition_point(|(place, _)| *place <= low.saturating_sub(widest));
        let inside = keys.partition_point(|(place, _)| place < low);
        let end = keys.partition_point(|(place, _)| place < high);
        for at in from..inside {
            let (place, width) = keys[at];
            if place.saturating_add(i64::from(width)) > *low {
                words[at / 64] |= 1 << (at % 64);
            }
        }
        fill(&mut words, inside, end.max(inside));
    }
    words
}

/// Set bits `[from, to)`. `O((to - from) / 64 + 1)`.
fn fill(words: &mut [u64], from: usize, to: usize) {
    let mut at = from;
    while at < to {
        let bit = at % 64;
        let take = (64 - bit).min(to - at);
        let mask = match take {
            64 => u64::MAX,
            _ => ((1u64 << take) - 1) << bit,
        };
        words[at / 64] |= mask;
        at += take;
    }
}

#[cfg(test)]
thread_local! {
    /// Blocks `reaching_rewrites` evaluated.
    pub(crate) static REWRITE_EVALUATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// What [`reaching_rewrites`] solves: whether a write reaches each numbered load, and whether each
/// reload's place held its literal at its load.
#[derive(Debug, PartialEq, Eq)]
struct Solved {
    reached: Vec<bool>,
    held: Vec<bool>,
}

/// The least solution of each block's events on `fixpoint::sparse` in reverse postorder, the root
/// entered with `seed`; `None` where the driver refuses (doc/adr-one-ir.md, "D432 as built").
fn reaching_rewrites(
    (order, successors, predecessors): (&[Node], &Csr<Node, Node>, &Csr<Node, Node>),
    events: &mut IdVec<Node, Vec<(usize, Event)>>,
    (keys, (root, seed)): (usize, (Option<Node>, &[u64])),
    slots: usize,
) -> Option<Solved> {
    let words = keys.div_ceil(64);
    let mut loads = 0;
    let transfer = IdVec::from_fn(events.len(), |node: Node| {
        let list = &mut events[node];
        list.sort_by_key(|(index, _)| *index);
        let numbered = list.iter().filter_map(|(_, event)| match event {
            Event::Load(_, number) => Some(number + 1),
            _ => None,
        });
        loads = numbered.fold(loads, usize::max);
        let conditional = (list.iter()).any(|(_, event)| matches!(event, Event::Reloaded { .. }));
        (!conditional).then(|| block_transfer(list, words))
    });
    let entering = |node: Node, cells: &IdMap<Node, Vec<u64>>| {
        let mut state = vec![0u64; words];
        if root == Some(node) {
            or_into(&mut state, seed);
        }
        for out in (predecessors.get(node).iter()).filter_map(|pred| cells.get(*pred)) {
            or_into(&mut state, out);
        }
        state
    };
    let start = vec![0u64; words];
    let cells = crate::fixpoint::sparse(
        "rewritten",
        keys,
        order,
        successors,
        start,
        |node, cells| {
            #[cfg(test)]
            REWRITE_EVALUATIONS.with(|count| count.set(count.get() + 1));
            let mut state = entering(node, cells);
            match &transfer[node] {
                Some((generated, killed)) => {
                    for ((word, generated), killed) in state.iter_mut().zip(generated).zip(killed) {
                        *word = (*word & !killed) | generated;
                    }
                }
                None => step(&mut state, &events[node], None),
            }
            state
        },
    )
    .ok()?;
    let mut solved = Solved {
        reached: vec![false; loads],
        held: vec![false; slots],
    };
    for (node, list) in events.iter() {
        let mut state = entering(node, &cells);
        step(&mut state, list, Some(&mut solved));
    }
    Some(solved)
}

/// Run a block's events over `state` in index order, recording loads and reloads into `solved`.
/// Monotone: a set unset bit only adds `extra`. `O(events x words)`.
fn step(state: &mut [u64], list: &[(usize, Event)], mut solved: Option<&mut Solved>) {
    let mut unset = Vec::new();
    for (_, event) in list {
        match event {
            Event::Write(set) => or_into(state, set),
            Event::Kill(key) => state[key / 64] &= !(1 << (key % 64)),
            Event::Load(key, number) => {
                if let Some(solved) = solved.as_deref_mut() {
                    solved.reached[*number] = bit(state, *key);
                }
            }
            Event::Format(slot, key) => {
                let held = !bit(state, *key);
                unset.push((*slot, !held));
                if let Some(solved) = solved.as_deref_mut() {
                    solved.held[*slot] = held;
                }
            }
            Event::Reloaded {
                slot,
                bounded,
                extra,
            } => {
                or_into(state, bounded);
                let found = unset.iter().find(|(at, _)| at == slot);
                if found.is_none_or(|(_, unset)| *unset) {
                    or_into(state, extra);
                }
            }
        }
    }
}

/// One block's `(gen, kill)` from its events in index order: the last write or kill of a key
/// decides it. `O(events x words)`.
fn block_transfer(list: &[(usize, Event)], words: usize) -> (Vec<u64>, Vec<u64>) {
    let (mut generated, mut killed) = (vec![0u64; words], vec![0u64; words]);
    for (_, event) in list {
        match event {
            Event::Write(set) => {
                or_into(&mut generated, set);
                (killed.iter_mut().zip(set)).for_each(|(word, set)| *word &= !set);
            }
            Event::Kill(key) => {
                generated[key / 64] &= !(1 << (key % 64));
                killed[key / 64] |= 1 << (key % 64);
            }
            Event::Load(..) | Event::Format(..) | Event::Reloaded { .. } => {}
        }
    }
    (generated, killed)
}

fn or_into(words: &mut [u64], set: &[u64]) {
    (words.iter_mut().zip(set)).for_each(|(word, set)| *word |= set);
}

fn bit(words: &[u64], key: usize) -> bool {
    words[key / 64] >> (key % 64) & 1 == 1
}

/// The places of `stored` some call may read, given each place's widest access and each call's
/// read area by `calls`.
fn read(
    (calls, bases): (&[CallArguments], &[Option<i64>]),
    areas: &[(StackArea, StackArea)],
    stored: &BTreeMap<i64, (Value, u32)>,
) -> BTreeSet<i64> {
    let mut read = BTreeSet::new();
    for ((call, base), (area, _)) in calls.iter().zip(bases).zip(areas) {
        // A call at a pointer no offset places may read any place.
        let Some(base) = *base else {
            return stored.keys().copied().collect();
        };
        let within = |place: i64, width: u32| match area {
            Some(area) => area.iter().any(|(low, high)| {
                base.wrapping_add(*low) < place.saturating_add(i64::from(width))
                    && place < base.wrapping_add(*high)
            }),
            // Unbounded, a call's still ends at the entry pointer; a tail transfer's does not.
            None => place.saturating_add(i64::from(width)) > base && (call.tail || place < 0),
        };
        read.extend(
            (stored.iter())
                .filter(|(place, (_, width))| within(**place, *width))
                .map(|(place, _)| *place),
        );
    }
    read
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
        Some(CallArguments {
            op,
            at,
            pointer,
            shift: self.spent,
            targets_entry: false,
            reads_stated: identified.is_some(),
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
        let target = (call
            .instruction
            .and_then(|at| self.machine.raw_call_site_at(at)))
        .map(r2source::SourceCallSiteIdentity::target);
        let targets_entry = target.is_some_and(|target| {
            target.space == crate::CanonicalStorageSpace::Ram && target.offset == self.func.entry
        });
        Some(CallArguments {
            targets_entry,
            reads_stated: true,
            tail: false,
            op,
            at,
            pointer,
            shift,
            instruction: call.instruction,
        })
    }
}

/// One round's worklist over the frame's addresses, and what it has found.
struct Walker<'a> {
    func: &'a SSAFunction,
    defs: &'a Definitions,
    entry_sp: VarId,
    sinks: &'a Sinks<'a>,
    site: &'a WalkSite,
    /// Each `CallUse` handing a frame address to a callee's position, and the value it reads.
    handed_on: IdMap<OpId, ((u64, usize), VarId)>,
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
        (sinks, site): (&'a Sinks<'a>, &'a WalkSite),
        carried: Option<&'a BTreeSet<i64>>,
    ) -> Self {
        let mut values = IdMap::<VarId, Value>::new(func.values().len());
        values.insert(entry_sp, Value::one(Point::Exact(0)));
        Self {
            func,
            defs,
            entry_sp,
            sinks,
            site,
            handed_on: IdMap::new(func.id_limit()),
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

    /// The round's propagation; `steps` counts each value visit.
    fn run(mut self, steps: &mut u64) -> RoundTable {
        loop {
            while let Some(var) = self.pending.pop() {
                *steps += 1;
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
        self.points.escape(value);
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
            // Handed to a callee's position, it leaves by the callee's reach, the decision's to read.
            SSAOp::CallUse { storage, .. } => {
                match (self.sinks.callee_at)(block, index, *storage) {
                    Some(pair) => {
                        self.handed_on.insert(id, (pair, var));
                    }
                    None => self.escape(value),
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
    /// runs escapes (D381). `O((values + blocks) log blocks)` through one dominator index.
    fn hand_to_tails(&mut self) {
        let tails = (self.site.calls.iter()).filter(|call| call.tail);
        let reach = self.defs.reach_of(self.func, tails.map(|call| call.op));
        if reach.is_empty() {
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
            .filter(|(var, _)| self.defs.defined_before_some(*var, &reach))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        for value in &handed {
            self.escape(value);
        }
    }

    /// The round's table: every escape no callee decides, and what the decision reads.
    fn finish(mut self) -> RoundTable {
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
        self.hand_to_tails();
        // A value only grows, so its last is every point a sink was handed.
        let handed_on = std::mem::replace(&mut self.handed_on, IdMap::new(0));
        let sinks = (handed_on.into_iter())
            .filter_map(|(_, (pair, var))| Some((pair, self.values.get(var)?.clone())))
            .collect();
        let stored = (std::mem::take(&mut self.stored).into_iter())
            .map(|(place, address)| {
                let widest =
                    (self.accesses.get(&place).into_iter().flatten()).map(|access| access.width);
                (place, (address, widest.max().unwrap_or(1)))
            })
            .collect();
        let stores = (self.accesses.iter()).flat_map(|(place, list)| {
            let stored = list.iter().filter(|access| access.store);
            stored.map(|access| (*place, place.saturating_add(i64::from(access.width))))
        });
        let above = stores
            .filter(|(_, high)| *high > 0)
            .map(|(low, high)| (low.max(0), high));
        self.points.incoming_stores = merged(above);
        self.points.call_bases = by_call(&self.site.calls, &self.values);
        self.points.transfers = Some(self.site.transfers);
        RoundTable {
            points: self.points,
            sinks,
            stored,
            bases: (self.site.calls.iter())
                .map(|call| call.base(&self.values))
                .collect(),
            accesses: self.accesses,
            carriers: self.carriers,
            places: PlaceFacts::default(),
            reloads: Vec::new(),
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

    /// `n` blocks in id order, each edge `(from, to)`: successors and predecessors.
    fn graph(n: usize, edges: &[(usize, usize)]) -> (Vec<Node>, Csr<Node, Node>, Csr<Node, Node>) {
        let pairs =
            (edges.iter()).map(|(from, to)| (Node::from_index(*from), Node::from_index(*to)));
        let successors = Csr::from_pairs(n, pairs.clone().collect::<Vec<_>>());
        let predecessors =
            Csr::from_pairs(n, pairs.map(|(from, to)| (to, from)).collect::<Vec<_>>());
        (
            (0..n).map(Node::from_index).collect(),
            successors,
            predecessors,
        )
    }

    /// An event's block, its position there and its key.
    type At = (Node, usize, usize);

    fn one_key(key: usize, keys: usize) -> Vec<u64> {
        let mut words = vec![0; keys.div_ceil(64)];
        words[key / 64] |= 1 << (key % 64);
        words
    }

    /// Whether a write of `key` reaches the event at `(block, at)` with no kill of it between, by
    /// the definition: a search over the blocks every path crosses whole.
    fn reached_by_paths(
        successors: &Csr<Node, Node>,
        events: &IdVec<Node, Vec<(usize, Event)>>,
        (block, at, key): At,
    ) -> bool {
        let kills = |event: &Event| matches!(event, Event::Kill(killed) if *killed == key);
        let writes = |event: &Event| matches!(event, Event::Write(set) if set[key / 64] >> (key % 64) & 1 == 1);
        let mut seen = vec![false; events.len()];
        let mut pending = Vec::new();
        for (node, list) in events.iter() {
            // The last write or kill of the key in a block decides what leaves it.
            let last = list
                .iter()
                .rev()
                .map(|(_, event)| event)
                .find(|event| kills(event) || writes(event));
            if last.is_some_and(writes) {
                pending.extend(successors.get(node).iter().copied());
            }
            // A write before the event in its own block, with no kill between.
            let before = list.iter().take(at).rev().map(|(_, event)| event);
            if node == block && before.take_while(|event| !kills(event)).any(writes) {
                return true;
            }
        }
        while let Some(node) = pending.pop() {
            let list = &events[node];
            if node == block && !list.iter().take(at).any(|(_, event)| kills(event)) {
                return true;
            }
            if !std::mem::replace(&mut seen[node.index()], true)
                && !list.iter().any(|(_, event)| kills(event))
            {
                pending.extend(successors.get(node).iter().copied());
            }
        }
        false
    }

    /// `key` and random others below `keys`.
    fn random_set(next: &mut impl FnMut(u64) -> u64, key: usize, keys: usize) -> Vec<u64> {
        let mut set = one_key(key, keys);
        set.iter_mut().for_each(|word| *word |= next(u64::MAX));
        let spare = keys % 64;
        if let (Some(last), true) = (set.last_mut(), spare > 0) {
            *last &= (1 << spare) - 1;
        }
        set
    }

    /// The fixpoint gives the kill-aware path union on graphs with cycles, self edges, blocks no
    /// edge reaches and keys across a word boundary (D427).
    #[test]
    fn reaching_rewrites_is_the_kill_aware_union_over_every_path() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..200 {
            let n = 1 + next(12) as usize;
            let keys = 1 + next(80) as usize;
            let edges = (0..next(24))
                .map(|_| (next(n as u64) as usize, next(n as u64) as usize))
                .collect::<Vec<_>>();
            let (order, successors, predecessors) = graph(n, &edges);
            let mut events = IdVec::from_fn(n, |_: Node| Vec::<(usize, Event)>::new());
            let mut loads = Vec::new();
            for _ in 0..next(16) {
                let node = Node::from_index(next(n as u64) as usize);
                let key = next(keys as u64) as usize;
                let at = events[node].len();
                let event = match next(3) {
                    0 => Event::Write(random_set(&mut next, key, keys)),
                    1 => Event::Kill(key),
                    _ => Event::Load(key, loads.len()),
                };
                loads.extend(matches!(event, Event::Load(..)).then_some((node, at, key)));
                events[node].push((at, event));
            }
            let expected = (loads.iter())
                .map(|load| reached_by_paths(&successors, &events, *load))
                .collect::<Vec<_>>();
            let none = vec![0u64; keys.div_ceil(64)];
            let solved = reaching_rewrites(
                (order.as_slice(), &successors, &predecessors),
                &mut events,
                (keys, (None, &none)),
                0,
            );
            let solved = solved.map(|solved| solved.reached);
            assert_eq!(solved, Some(expected), "{edges:?} {events:?}");
        }
    }

    /// One random event at the end of `node`: a write, a kill, a load, or a reload's format load
    /// and its call. Loads and format loads are recorded as `(node, at, key)`.
    fn push_random(
        next: &mut impl FnMut(u64) -> u64,
        (list, keys): (&mut Vec<(usize, Event)>, usize),
        (node, loads, formats): (Node, &mut Vec<At>, &mut Vec<At>),
    ) {
        let key = next(keys as u64) as usize;
        let at = list.len();
        match next(4) {
            0 => list.push((at, Event::Write(random_set(next, key, keys)))),
            1 => list.push((at, Event::Kill(key))),
            2 => {
                loads.push((node, at, key));
                list.push((at, Event::Load(key, loads.len() - 1)));
            }
            _ => {
                let slot = formats.len();
                formats.push((node, at, key));
                list.push((at, Event::Format(slot, key)));
                let (bounded, extra) = (random_set(next, key, keys), random_set(next, key, keys));
                let reloaded = Event::Reloaded {
                    slot,
                    bounded,
                    extra,
                };
                list.push((at + 1, reloaded));
            }
        }
    }

    /// `events` with each reload's call a plain write: `extra` included where `unset` says.
    fn as_writes(
        events: &IdVec<Node, Vec<(usize, Event)>>,
        unset: &[bool],
    ) -> IdVec<Node, Vec<(usize, Event)>> {
        let write = |event: &Event| match event {
            Event::Reloaded {
                slot,
                bounded,
                extra,
            } => {
                let mut set = bounded.clone();
                (unset[*slot]).then(|| or_into(&mut set, extra));
                Event::Write(set)
            }
            other => other.clone(),
        };
        IdVec::from_fn(events.len(), |node: Node| {
            (events[node].iter())
                .map(|(at, event)| (*at, write(event)))
                .collect()
        })
    }

    /// The least solution by the definition: the path search, each reload unset where its format
    /// load is reached, iterated from none unset to its fixpoint.
    fn least_by_paths(
        successors: &Csr<Node, Node>,
        events: &IdVec<Node, Vec<(usize, Event)>>,
        (loads, formats): (&[At], &[At]),
    ) -> Solved {
        let mut unset = vec![false; formats.len()];
        loop {
            let plain = as_writes(events, &unset);
            let reached = |at: &At| reached_by_paths(successors, &plain, *at);
            let next = formats.iter().map(reached).collect::<Vec<_>>();
            if next == unset {
                let held = unset.iter().map(|unset| !unset).collect();
                return Solved {
                    reached: loads.iter().map(reached).collect(),
                    held,
                };
            }
            unset = next;
        }
    }

    /// The least solution with reloads and an entry seed (D432), against [`least_by_paths`].
    #[test]
    fn reaching_rewrites_with_reloads_is_their_least_path_solution() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..300 {
            let n = 1 + next(10) as usize;
            let keys = 1 + next(70) as usize;
            let edges = (0..next(20))
                .map(|_| (next(n as u64) as usize, next(n as u64) as usize))
                .collect::<Vec<_>>();
            let (order, successors, predecessors) = graph(n, &edges);
            let first = next(keys as u64) as usize;
            let entry = random_set(&mut next, first, keys);
            // For the path search the root's seed is a write before its first event.
            let root = Node::from_index(0);
            let mut events = IdVec::from_fn(n, |_: Node| Vec::<(usize, Event)>::new());
            events[root].push((0, Event::Write(entry.clone())));
            let (mut loads, mut formats) = (Vec::new(), Vec::new());
            for _ in 0..next(16) {
                let node = Node::from_index(next(n as u64) as usize);
                let at = (node, &mut loads, &mut formats);
                push_random(&mut next, (&mut events[node], keys), at);
            }
            let expected = least_by_paths(&successors, &events, (&loads, &formats));
            events[root].remove(0);
            let solved = reaching_rewrites(
                (order.as_slice(), &successors, &predecessors),
                &mut events,
                (keys, (Some(root), &entry)),
                formats.len(),
            );
            assert_eq!(solved, Some(expected), "{edges:?} {events:?}");
        }
    }

    /// A write and a load of one key in each of four blocks, then a chain or a cycle of `n`
    /// blocks: the evaluations grow linearly in `n`.
    fn rewrite_evaluations(n: usize, cyclic: bool) -> usize {
        let mut edges = (0..n - 1).map(|at| (at, at + 1)).collect::<Vec<_>>();
        if cyclic {
            edges.push((n - 1, 0));
        }
        let (order, successors, predecessors) = graph(n, &edges);
        let mut events = IdVec::from_fn(n, |_: Node| Vec::<(usize, Event)>::new());
        for at in 0..4 {
            let node = Node::from_index(at * n / 4);
            events[node].push((0, Event::Load(at, at)));
            events[node].push((1, Event::Write(one_key(at, 4))));
        }
        REWRITE_EVALUATIONS.with(|count| count.set(0));
        let solved = reaching_rewrites(
            (order.as_slice(), &successors, &predecessors),
            &mut events,
            (4, (None, &[0])),
            0,
        );
        assert!(solved.is_some());
        REWRITE_EVALUATIONS.with(std::cell::Cell::get)
    }

    #[test]
    fn reaching_rewrites_grows_linearly_in_the_blocks() {
        for cyclic in [false, true] {
            let (one, two) = (
                rewrite_evaluations(256, cyclic),
                rewrite_evaluations(512, cyclic),
            );
            assert!(two < 3 * one, "cyclic {cyclic}: {one} then {two}");
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
