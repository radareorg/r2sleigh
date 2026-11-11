//! The callee's boundary (doc/adr-call-boundary.md, "The callee's boundary"): what every call the
//! program makes does with a function's result lanes, joined once per callee and world.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2il::R2ILOp;
use r2source::{
    CanonicalStorageId, SourceClosedResult, SourceConventionSlots, SourceReadLanes,
    SourceResultCause,
};
use r2ssa::site_boundary::{
    ByteMask, CallEffect, CallEffects, CallerFlow, Counted, EntrySummary, LANES, LaneBytes,
    LaneFate, LaneId, Overwrites, ResultLanes, SiteBoundary, argument_registers, argument_takes,
    unknown_call_takes,
};

use super::analysis::Walked;
use super::requests::SurveyQuery;
use super::{ProgramInputs, Source, View};
use crate::body::{Body, BodyBlock, UnresolvedReason};
use crate::native::NativeTarget;
use crate::query::db::{Db, Hold, Query, Retention};

/// Whether a boundary joins the program's calls: only under `aa`, which surveys every caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum World {
    /// The body and its callees alone: a fresh open, which joins no sites.
    #[default]
    Open,
    /// Every call the image shows, once `aa` surveyed it.
    Closed,
}

/// An import, by the address its calls reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportId(pub u64);

/// Whose boundary: a function of the image by its entry, or an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeKey {
    Entry(u64),
    Import(ImportId),
}

/// One lane joined over every call to a callee.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JoinedLane {
    /// Whether a body may leave a result here: the typed lanes, and each lane the convention also
    /// passes arguments in (its entry bytes may be handed back). x87's are written before they hold one.
    pub held: bool,
    /// Some call reads the lane as the call leaves it.
    pub read: bool,
    /// The bytes those reads take.
    pub bytes: ByteMask,
    /// Some call may take, lose or hand on the lane.
    pub unknown: bool,
    /// Some call returns the lane on into a cycle of forwarders.
    pub cycle: bool,
    /// Every call leaves the lane dead.
    pub dead: bool,
    /// The bytes every read narrower than the lane takes, where they agree; `Some(None)` where two disagree.
    pub width: Option<Option<u32>>,
}

/// What one callee's boundary states (doc/adr-call-boundary.md, `CallBoundary`): under the closed
/// world, the fate of each result lane over every call; for an import, the registers it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallBoundary {
    Sites {
        lanes: [JoinedLane; LANES],
        calls: u32,
        /// Some caller the survey names was not read, so these calls may not be every call.
        unread: bool,
        /// The callers a returned lane is dead in only if their own calls are every way in.
        forwarders: Box<[u64]>,
        /// Whether a forwarding cycle the database cut reached the answer, which then depends on
        /// the function of the cycle asked first: such an answer is not held.
        cut: bool,
    },
    Import {
        reads: Option<crate::imports::ImportReads>,
    },
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for CallBoundary {
    type Key = (CalleeKey, World);
    type Value = Option<CallBoundary>;
    const NAME: &'static str = "call-boundary";
    const RETENTION: Retention = Retention::Held;

    /// Work: an import's placement; a function's held caller fates, one search per call and one
    /// ask per forwarder. A cut answer is solved again per ask, over the forwarders it reaches.
    fn compute(db: &Db<ProgramInputs<S>>, &(callee, world): &(CalleeKey, World)) -> Self::Value {
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        match (callee, world) {
            (CalleeKey::Import(ImportId(at)), _) => {
                let name = crate::native::Program::import_at(&view, at)?;
                let target = walker.target(view.thumb_at(at));
                Some(CallBoundary::Import {
                    reads: crate::native::import_reads(target, &name),
                })
            }
            // A cold `pdd` joins no sites.
            (CalleeKey::Entry(_), World::Open) => None,
            (CalleeKey::Entry(entry), World::Closed) => sites_of(db, entry),
        }
    }

    fn hold(value: &Self::Value) -> Hold {
        match value {
            Some(CallBoundary::Sites { cut: true, .. }) => Hold::Transient,
            _ => Hold::Held,
        }
    }
}

/// The fates of every call to `callee`, joined, with each returned lane forwarded to its caller's
/// own boundary; a function nothing calls joins no call.
fn sites_of<S: Source + 'static>(db: &Db<ProgramInputs<S>>, callee: u64) -> Option<CallBoundary> {
    let survey = db.get::<SurveyQuery>(&()).ok()?;
    let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
    let held = held_lanes(db, callee)?;
    let mut lanes = held.map(|held| JoinedLane {
        held,
        dead: true,
        ..JoinedLane::default()
    });
    let mut calls = 0u32;
    // A caller that is not read may read the result: the calls read are then not every call.
    let mut unread = false;
    // A call two bodies hold (one walk enters the other's tail) is one call, read once.
    let mut seen = BTreeSet::new();
    // Each returned lane, by caller, lane and bytes, forwarded after the direct fates are joined.
    let mut returned = BTreeSet::new();
    let mut forwarders = BTreeSet::new();
    for &caller in survey.callers_of(callee) {
        let Some(Ok(thumb)) = survey.walked_in(caller) else {
            unread = true;
            continue;
        };
        let Some(sites) = (db.get::<SiteFates>(&(caller, thumb)).ok()).and_then(|f| (*f).clone())
        else {
            unread = true;
            continue;
        };
        for site in of_callee(&sites, callee) {
            if !seen.insert(site.instruction) {
                continue;
            }
            calls = calls.saturating_add(1);
            let fates = lanes.iter_mut().zip(site.boundary.fates).enumerate();
            for (at, (joined, fate)) in fates {
                let Some(LaneFate::Returned(bytes)) = fate else {
                    join(joined, fate.map(Forwarded::Fate));
                    continue;
                };
                returned.insert((caller, at, bytes));
            }
        }
    }
    // A caller's boundary is asked only where its answer could move the decision: a lane no call
    // reads, while every lane a body may hold is dead or returned (O(callers) asks, each held).
    let mut cut = false;
    // Each caller's boundary is asked once for all its lanes: a cut answer is not held.
    let mut theirs = BTreeMap::new();
    for (caller, at, bytes) in returned {
        let open = lanes
            .iter()
            .any(|lane| lane.held && (lane.unknown || lane.cycle));
        let fate = match (lanes[at].read, open) {
            (true, _) => Some(Forwarded::Fate(LaneFate::Unknown)),
            (false, true) if at >= 3 => Some(Forwarded::Fate(LaneFate::Unknown)),
            _ => {
                let key = (CalleeKey::Entry(caller), World::Closed);
                let boundary = theirs
                    .entry(caller)
                    .or_insert_with(|| db.get::<CallBoundary>(&key).ok());
                forwarded(boundary.as_deref(), at, bytes, &mut cut)
            }
        };
        if let Some(Forwarded::DeadIfEveryWayIn) = fate {
            forwarders.insert(caller);
        }
        join(&mut lanes[at], fate);
    }
    r2il::refusal_evidence!(
        "call-boundary",
        "{callee:#x}: {calls} calls, unread callers {unread}, lanes {lanes:?}"
    );
    // No call at all is evidence too: the closed world decides only where nothing else enters.
    Some(CallBoundary::Sites {
        lanes,
        calls,
        unread,
        forwarders: forwarders.into_iter().collect(),
        cut,
    })
}

/// Whether the calls a boundary joined are every way the image enters `callee`, and each forwarder's
/// too: asked only by a decision that rests on it. Each function is answered once per question.
pub(crate) fn every_way_in<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
    boundary: &CallBoundary,
) -> bool {
    every_way_in_from(db, callee, boundary, &mut BTreeMap::new())
}

/// `every_way_in`, with each function's answer so far: `None` while it is being asked.
fn every_way_in_from<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
    boundary: &CallBoundary,
    asked: &mut BTreeMap<u64, Option<bool>>,
) -> bool {
    let CallBoundary::Sites {
        calls,
        unread,
        forwarders,
        ..
    } = boundary
    else {
        return false;
    };
    if let Some(answer) = asked.get(&callee) {
        return answer.unwrap_or(false);
    }
    asked.insert(callee, None);
    let mut answer = !unread && super::reads::only_called(db, callee, *calls);
    for caller in forwarders.iter() {
        if !answer {
            break;
        }
        let key = (CalleeKey::Entry(*caller), World::Closed);
        let found = db.get::<CallBoundary>(&key).ok();
        let theirs = found.as_deref().and_then(Option::as_ref);
        answer = theirs.is_some_and(|theirs| every_way_in_from(db, *caller, theirs, asked));
    }
    asked.insert(callee, Some(answer));
    answer
}

/// Which result lanes of `callee`'s convention a body may leave a result in: the typed three, and
/// each other lane that is an argument location. The x87 lanes hold nothing on entry (SysV 3.2.1).
fn held_lanes<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
) -> Option<[bool; LANES]> {
    let view = View::new(db, true);
    let walker = super::returns::Walking::new(view.clone(), true).ok()?;
    let target = walker.target(view.thumb_at(callee));
    let slots = target.convention.convention_slots().ok()?;
    let slots_of = lanes_of(target, &slots).slots();
    let arguments = argument_registers(&slots);
    let input = |lane: &CanonicalStorageId| {
        arguments.iter().any(|argument| {
            argument.space == lane.space
                && argument.offset < lane.offset + u64::from(lane.size)
                && lane.offset < argument.offset + u64::from(argument.size)
        })
    };
    Some(std::array::from_fn(|at| {
        slots_of[at].is_some_and(|lane| at < 3 || input(&lane))
    }))
}

/// A site's fate on one lane once a return is followed into the caller's own boundary.
enum Forwarded {
    Fate(LaneFate),
    /// The caller's callers read these bytes, at the width their reads agree on (`JoinedLane`).
    Read(ByteMask, Option<Option<u32>>),
    Cycle,
    /// Every call to the caller leaves the lane dead: dead where those calls are every way in.
    DeadIfEveryWayIn,
}

/// The caller's own boundary on lane `at` (`None` where the database cut a cycle): what its callers
/// do with the `bytes` a call returns into it. A cut, here or in the caller's answer, sets `cut`.
fn forwarded(
    boundary: Option<&Option<CallBoundary>>,
    at: usize,
    bytes: ByteMask,
    cut: &mut bool,
) -> Option<Forwarded> {
    let Some(boundary) = boundary else {
        *cut = true;
        return Some(Forwarded::Cycle);
    };
    let Some(CallBoundary::Sites {
        lanes, cut: theirs, ..
    }) = boundary
    else {
        return Some(Forwarded::Fate(LaneFate::Unknown));
    };
    *cut |= *theirs;
    let lane = lanes[at];
    // A read takes the callee's bytes only where it reads them, from the lowest (`Live::fate`).
    let reached = ByteMask(lane.bytes.0 & bytes.0);
    // A width their reads agree on stands only where the callee's bytes fill it.
    let width = lane
        .width
        .map(|width| width.filter(|width| reached.low_run().is_some_and(|run| run >= *width)));
    Some(match lane {
        _ if reached.0 & 1 != 0 => Forwarded::Read(reached, width),
        _ if reached.0 != 0 => Forwarded::Fate(LaneFate::Unknown),
        lane if lane.cycle => Forwarded::Cycle,
        // Whether the caller's calls are every way in is asked only by the decision that rests on it.
        lane if lane.dead => Forwarded::DeadIfEveryWayIn,
        _ => Forwarded::Fate(LaneFate::Unknown),
    })
}

/// `fate` joined into `lane`; none (no such register) changes nothing.
fn join(lane: &mut JoinedLane, fate: Option<Forwarded>) {
    let Some(fate) = fate else { return };
    match fate {
        Forwarded::Fate(LaneFate::Dead) | Forwarded::DeadIfEveryWayIn => {}
        Forwarded::Fate(LaneFate::Read(bytes)) => {
            // A read of the whole register states no width.
            let width = bytes.low_run().filter(|width| *width < 16);
            read(lane, bytes, width.map(Some));
        }
        Forwarded::Read(bytes, width) => read(lane, bytes, width),
        Forwarded::Fate(LaneFate::Returned(_) | LaneFate::Unknown) => {
            lane.unknown = true;
            lane.dead = false;
        }
        Forwarded::Cycle => {
            lane.cycle = true;
            lane.dead = false;
        }
    }
}

/// A read of `bytes` joined into `lane`, at `width` where it states one; `Some(None)` disagrees.
fn read(lane: &mut JoinedLane, bytes: ByteMask, width: Option<Option<u32>>) {
    lane.read = true;
    lane.bytes = ByteMask(lane.bytes.0 | bytes.0);
    lane.dead = false;
    if let Some(width) = width {
        lane.width = Some(match lane.width {
            None => width,
            Some(known) => known.filter(|known| Some(*known) == width),
        });
    }
}

/// What the closed world decides of a body's result from its open interface and its boundary (D202,
/// D213); `every_way_in` is asked only where every call leaving the result dead decides it.
pub(crate) fn decide(
    open: &r2source::SourceFunctionInterface,
    boundary: &CallBoundary,
    every_way_in: impl FnOnce() -> bool,
) -> Option<SourceClosedResult> {
    let CallBoundary::Sites { lanes, calls, .. } = boundary else {
        return None;
    };
    // A declaration states the result.
    if open.types_are_declared() {
        return None;
    }
    let carriers = open.result_carriers();
    // An integer register no return defines holds no result, and the second one holds a result
    // only beside it (SysV psABI 3.2.3, AAPCS64 6.9): a call reading either reads its own bytes.
    let undefined = carriers.is_some_and(|carriers| carriers.integer_undefined);
    let holds = |at: usize| {
        lanes[at].held
            && !(undefined
                && (at == usize::from(LaneId::INTEGER.0) || at == usize::from(LaneId::SECOND.0)))
    };
    let lane = |id: LaneId| lanes[usize::from(id.0)];
    let (integer, float, second) = (
        lane(LaneId::INTEGER),
        lane(LaneId::FLOAT),
        lane(LaneId::SECOND),
    );
    let integer_read = integer.read && !undefined;
    // Every lane a body may hand back as its caller left it (d72 round 6) is dead at every call.
    let all_dead = || (0..LANES).all(|at| lanes[at].dead || !holds(at)) && every_way_in();
    let cycle = (0..LANES).any(|at| holds(at) && lanes[at].cycle);
    match open.return_kind() {
        r2source::SourceFunctionReturn::Register { .. } => {
            let paired = carriers.is_some_and(|carriers| carriers.second.is_some());
            if paired && second.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Pair));
            }
            if integer.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            // Nothing calls it: only a void the reference index proves is worth building it for.
            if *calls > 0 && all_dead() {
                return Some(SourceClosedResult::Unread);
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        r2source::SourceFunctionReturn::Unproven => {
            let carriers = carriers?;
            if integer_read && (carriers.float.is_none() || !float.read) {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            if carriers.float.is_some() && float.read && !integer_read {
                let bytes = float
                    .width
                    .flatten()
                    .filter(|bytes| matches!(bytes, 4 | 8))?;
                let bytes = u8::try_from(bytes).ok()?;
                return Some(SourceClosedResult::Read(SourceReadLanes::Float { bytes }));
            }
            // No defined byte reaches a return where the body only hands back an input.
            let causes = (open.unproven_result())
                .map(|unproven| unproven.causes().to_vec())
                .unwrap_or_default();
            let handed_back = causes.iter().all(|cause| {
                matches!(
                    cause,
                    SourceResultCause::HandedBack | SourceResultCause::NoReturn
                )
            });
            if (*calls > 0 || handed_back) && all_dead() {
                return Some(match handed_back {
                    true => SourceClosedResult::Void,
                    false => SourceClosedResult::Unread,
                });
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        _ => None,
    }
}

/// A source of a callee's result, strongest first (doc/adr-call-boundary.md, "The callee's boundary").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    /// DWARF or a library declaration whose arrivals hold.
    Declared,
    /// The body's own proof.
    Body,
    /// What every call the closed world shows does with the result.
    Calls,
}

/// A source the authority order overrules on one result lane: refusal evidence, never a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispute {
    pub lane: LaneId,
    pub kept: Authority,
    pub lost: Authority,
}

/// A call reading a lane the callee overwrites on every path, where a declaration or the body says
/// it returns nothing, loses; one it leaves alone hands the caller its own bytes. O(lanes).
pub(crate) fn disputes(
    open: &r2source::SourceFunctionInterface,
    boundary: &CallBoundary,
    overwritten: impl Fn(LaneId) -> bool,
) -> Vec<Dispute> {
    let CallBoundary::Sites { lanes, .. } = boundary else {
        return Vec::new();
    };
    if open.return_kind() != r2source::SourceFunctionReturn::Void {
        return Vec::new();
    }
    let kept = match open.types_are_declared() {
        true => Authority::Declared,
        false => Authority::Body,
    };
    [LaneId::INTEGER, LaneId::FLOAT, LaneId::SECOND]
        .into_iter()
        .filter(|lane| lanes[usize::from(lane.0)].read && overwritten(*lane))
        .map(|lane| Dispute {
            lane,
            kept,
            lost: Authority::Calls,
        })
        .collect()
}

/// One direct call a body makes, and its boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AfterCall {
    pub(super) callee: u64,
    /// The call's instruction, which names a call two bodies hold (one walk enters the other's tail).
    pub(super) instruction: u64,
    pub(super) boundary: SiteBoundary,
}

/// The calls of `calls` to `callee`, in instruction order.
fn of_callee(calls: &[AfterCall], callee: u64) -> impl Iterator<Item = &AfterCall> {
    let first = calls.partition_point(|call| call.callee < callee);
    calls[first..]
        .iter()
        .take_while(move |call| call.callee == callee)
}

/// The boundary at every direct call of one walked body, by caller entry and whether it is Thumb.
pub(super) struct SiteFates;

impl<S: Source + 'static> Query<ProgramInputs<S>> for SiteFates {
    type Key = (u64, bool);
    type Value = Option<Arc<[AfterCall]>>;
    const NAME: &'static str = "site-fates";
    const RETENTION: Retention = Retention::Held;

    /// Work: one backward pass over the body, `O((B + E) × lanes)` within its budget, and one entry
    /// summary per distinct callee not yet summarised.
    fn compute(db: &Db<ProgramInputs<S>>, &(caller, thumb): &(u64, bool)) -> Self::Value {
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        let target = walker.target(thumb);
        let slots = target.convention.convention_slots().ok()?;
        let walking = db.get::<Walked>(&(caller, thumb)).ok()?;
        let body = walking.0.as_ref().ok()?.body();
        let reading = Reading {
            db,
            view: &view,
            lanes: lanes_of(target, &slots),
            slots: &slots,
            call: target.convention.call_effect().ok(),
            depth: Depth::Deep,
        };
        let direct = direct_calls(body).collect::<Vec<_>>();
        let sites = (direct.iter())
            .map(|call| (call.block, call.op))
            .collect::<Vec<_>>();
        let flow = flow_of(body, target.disasm.arch_spec().memory_endianness);
        let arguments = argument_registers(&slots);
        let fates = flow.site_fates(reading.lanes, &reading.effects(body), &sites, &arguments);
        let mut calls = (direct.iter().zip(fates))
            .map(|(call, boundary)| AfterCall {
                callee: call.callee,
                instruction: call.instruction,
                boundary,
            })
            .collect::<Vec<_>>();
        calls.sort_by_key(|call| (call.callee, call.instruction));
        calls.dedup_by_key(|call| (call.callee, call.instruction));
        Some(calls.into())
    }
}

/// What a body does with the result registers it is entered with, by entry and whether it is
/// Thumb: the bytes it may take, and the bytes every path to a return overwrites.
pub(super) struct CalleeEntry;

impl<S: Source + 'static> Query<ProgramInputs<S>> for CalleeEntry {
    type Key = (u64, bool);
    type Value = Option<EntrySummary>;
    const NAME: &'static str = "callee-entry";
    const RETENTION: Retention = Retention::Held;

    /// Work: one backward pass over the callee's body, its own calls read shallowly, so the
    /// summary asks no other callee.
    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Self::Value {
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        let target = walker.target(thumb);
        let slots = target.convention.convention_slots().ok()?;
        let walking = db.get::<Walked>(&(entry, thumb)).ok()?;
        let body = walking.0.as_ref().ok()?.body();
        let reading = Reading {
            db,
            view: &view,
            lanes: lanes_of(target, &slots),
            slots: &slots,
            call: target.convention.call_effect().ok(),
            depth: Depth::Shallow,
        };
        let effects = reading.effects(body);
        let flow = flow_of(body, target.disasm.arch_spec().memory_endianness);
        flow.entry_summary(entry, reading.lanes, &effects)
    }
}

/// The convention's result lanes: the typed three, then the rest of its return set.
fn lanes_of(target: &NativeTarget<'_>, slots: &SourceConventionSlots) -> ResultLanes {
    let results = (target.convention.results.iter())
        .map(|lane| lane.storage)
        .collect::<Vec<CanonicalStorageId>>();
    ResultLanes::of(slots, &results)
}

/// One call the walk read, by its block and operation.
struct DirectCall {
    block: usize,
    op: usize,
    callee: u64,
    instruction: u64,
}

/// The calls the walk read to a function of the program, in block order.
fn direct_calls(body: &Body) -> impl Iterator<Item = DirectCall> + '_ {
    (body.blocks.iter().enumerate()).flat_map(|(block, found)| calls_in(block, found))
}

fn calls_in(block: usize, found: &BodyBlock) -> impl Iterator<Item = DirectCall> + '_ {
    (found.transfers.iter())
        .filter(|transfer| transfer.kind == r2source::AdvisoryCallTransfer::Call)
        .map(move |transfer| DirectCall {
            block,
            op: transfer.op,
            callee: transfer.target,
            instruction: (found.lifted.instruction_of(transfer.op)).unwrap_or(found.lifted.addr),
        })
}

/// The flow of a walked body: its successors, and the blocks past which it could not follow.
fn flow_of(body: &Body, endian: r2il::Endianness) -> CallerFlow<'_, BodyBlock> {
    let edges = (body.blocks.iter().enumerate())
        .flat_map(|(at, block)| (block.successors.iter()).map(move |(_, address)| (at, *address)));
    // A stop inside a block is its last transfer; one at a target no block holds is its
    // predecessor's edge to nothing, which the flow opens.
    let open = body.unresolved.iter().filter_map(|stop| {
        if matches!(stop.reason, UnresolvedReason::Overlaps { .. }) {
            return None;
        }
        let after = body
            .blocks
            .partition_point(|block| block.lifted.addr <= stop.addr);
        let at = after.checked_sub(1)?;
        let block = &body.blocks[at].lifted;
        (stop.addr < block.addr + u64::from(block.size)).then_some(at)
    });
    CallerFlow::new(&body.blocks, edges, open, endian)
}

/// How far a callee of the body is read for what a call to it does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    /// By the callee's own entry summary.
    Deep,
    /// Inside a summary: by what is known without another body, and its own calls set the count.
    Shallow,
}

/// What the calls of a body are read against: the database, the machine and the registers.
struct Reading<'a, S: Source + 'static> {
    db: &'a Db<ProgramInputs<S>>,
    view: &'a View<'a, S>,
    lanes: ResultLanes,
    slots: &'a SourceConventionSlots,
    /// What the convention says a call leaves standing: a format held in a preserved register.
    call: Option<r2source::SourceCallEffect>,
    depth: Depth,
}

impl<S: Source + 'static> Reading<'_, S> {
    /// What each call of `body` does to the result registers: by callee for the calls the walk
    /// read, and what nothing is known of for the rest.
    fn effects<'b>(&self, body: &'b Body) -> Effects<'b> {
        let ops = body.blocks.iter().flat_map(|block| &block.lifted.ops);
        let direct = ops.filter_map(|operation| match operation {
            R2ILOp::Call { target } => Some(target.offset),
            _ => None,
        });
        // A call the walk folded to a target (`lea rax, f; call rax`) is a call to it.
        let folded = (body.blocks.iter().enumerate())
            .flat_map(|(at, block)| {
                (block.transfers.iter())
                    .filter(|transfer| transfer.kind == r2source::AdvisoryCallTransfer::Call)
                    .filter(|t| !matches!(block.lifted.ops[t.op], R2ILOp::Call { .. }))
                    .map(move |transfer| ((at, transfer.op), transfer.target))
            })
            .collect::<BTreeMap<_, _>>();
        let callees = (direct.chain(folded.values().copied())).collect::<BTreeSet<_>>();
        let mut by_callee = BTreeMap::new();
        let mut formatted = BTreeMap::new();
        for callee in callees {
            let (effect, format) = self.callee(callee);
            by_callee.insert(callee, effect);
            if let Some(format) = format {
                formatted.insert(callee, format);
            }
        }
        let mut effects = Effects {
            body,
            by_callee,
            folded,
            by_site: BTreeMap::new(),
            indirect: CallEffect {
                takes: self.unknown(),
                counted: None,
                overwrites: Overwrites::All,
            },
        };
        if !formatted.is_empty() {
            effects.by_site = self.formatted_sites(&effects, &formatted);
        }
        effects
    }

    /// Each call to a printf-format import whose block folds its format to a literal with no
    /// floating conversion: it takes no tail vector register (D218). One forward pass per block.
    fn formatted_sites(
        &self,
        effects: &Effects<'_>,
        formatted: &BTreeMap<u64, Formatted>,
    ) -> BTreeMap<(usize, usize), CallEffect> {
        let mut sites = BTreeMap::new();
        for (at, block) in effects.body.blocks.iter().enumerate() {
            let mut origins = r2ssa::origin::BlockOrigins::default();
            for (op, operation) in block.lifted.ops.iter().enumerate() {
                let format = (operation.is_call())
                    .then(|| effects.callee_at(at, op))
                    .flatten()
                    .and_then(|callee| formatted.get(&callee));
                let effect = format.and_then(|format| self.unfloated(&origins, format));
                sites.extend(effect.map(|effect| ((at, op), effect)));
                origins.step_under(operation, self.call.as_ref());
            }
        }
        sites
    }

    /// The call's effect without its tail vector registers, where `origins` fold its format to a
    /// literal the printf reader parses whole and finds no floating conversion in.
    fn unfloated(
        &self,
        origins: &r2ssa::origin::BlockOrigins,
        format: &Formatted,
    ) -> Option<CallEffect> {
        let register = r2il::Varnode::register(format.register.offset, format.register.size);
        let address = origins.of(&register)?.constant()?;
        let text = crate::native::text_at(self.view, address)?;
        let consumed = r2ssa::printf::printf_consumed_arguments(&text).ok()?;
        (!consumed.any_floating).then_some(format.unfloated)
    }

    /// What a call to a callee nothing is known of may take: a summary's own calls set the variadic
    /// count themselves, so only a caller counts it.
    fn unknown(&self) -> LaneBytes {
        match self.depth {
            Depth::Deep => unknown_call_takes(self.lanes, self.slots),
            Depth::Shallow => argument_takes(self.lanes, self.slots),
        }
    }

    /// A call to `callee`: an import overwrites every result register and takes what it reads (and,
    /// for a printf format, what a float-free format takes); an image function, what its body does.
    fn callee(&self, callee: u64) -> (CallEffect, Option<Formatted>) {
        if crate::native::Program::import_at(self.view, callee).is_some() {
            let boundary = self
                .db
                .get::<CallBoundary>(&(CalleeKey::Import(ImportId(callee)), World::Open));
            let reads = match boundary.ok().as_deref() {
                Some(Some(CallBoundary::Import { reads })) => reads.clone(),
                _ => None,
            };
            let formatted = (reads.as_ref())
                .and_then(|reads| Some((reads, reads.format.as_ref()?)))
                .map(|(reads, format)| {
                    let mut unfloated = reads.clone();
                    unfloated
                        .registers
                        .retain(|read| !format.floats.contains(read));
                    let (takes, counted) = self.import_takes(Some(unfloated));
                    Formatted {
                        register: format.format,
                        unfloated: CallEffect {
                            takes,
                            counted,
                            overwrites: Overwrites::All,
                        },
                    }
                });
            let (takes, counted) = self.import_takes(reads);
            let effect = CallEffect {
                takes,
                counted,
                overwrites: Overwrites::All,
            };
            return (effect, formatted);
        }
        // A summary reads no other summary, so one costs one pass over one body (ADR, Cost).
        let summary = (self.depth == Depth::Deep)
            .then(|| {
                let thumb = self.view.thumb_at(callee);
                self.db.get::<CalleeEntry>(&(callee, thumb))
            })
            .and_then(Result::ok);
        let effect = match summary.and_then(|summary| *summary) {
            Some(summary) => CallEffect {
                takes: summary.takes,
                counted: None,
                overwrites: Overwrites::Bytes(summary.overwrites),
            },
            None => CallEffect {
                takes: self.unknown(),
                counted: None,
                overwrites: Overwrites::Nothing,
            },
        };
        (effect, None)
    }

    /// What the import's placement reads (S8 `Placement::reads`); its count register bounds the
    /// vector registers. An import no row binds takes what an unknown callee does.
    fn import_takes(
        &self,
        reads: Option<crate::imports::ImportReads>,
    ) -> (LaneBytes, Option<Counted>) {
        let Some(reads) = reads else {
            return (self.unknown(), None);
        };
        let Some(register) = reads.count_register else {
            return (LaneBytes::covered_by(self.lanes, &reads.registers), None);
        };
        let floats = self.slots.float_argument_slots();
        let overlaps = |a: &CanonicalStorageId, b: &CanonicalStorageId| {
            a.space == b.space
                && a.offset < b.offset + u64::from(b.size)
                && b.offset < a.offset + u64::from(a.size)
        };
        let mut integers = (reads.registers.iter())
            .filter(|read| !floats.iter().any(|float| overlaps(read, float)))
            .copied()
            .collect::<Vec<_>>();
        // A summary's own calls set the count themselves, so only a caller's call takes it.
        if self.depth == Depth::Deep {
            integers.push(register);
        }
        let counted = Counted {
            register,
            takes: LaneBytes::covered_by(self.lanes, floats),
            stated: None,
        };
        (LaneBytes::covered_by(self.lanes, &integers), Some(counted))
    }
}

/// A printf-format import: the register its format arrives in, and what a call takes where that
/// format has no floating conversion.
struct Formatted {
    register: CanonicalStorageId,
    unfloated: CallEffect,
}

/// What each call of one body does to the result registers.
struct Effects<'b> {
    body: &'b Body,
    by_callee: BTreeMap<u64, CallEffect>,
    /// The calls the walk folded to a target, by block and operation.
    folded: BTreeMap<(usize, usize), u64>,
    /// The calls whose own format states what they take, by block and operation.
    by_site: BTreeMap<(usize, usize), CallEffect>,
    /// A call whose callee the walk did not read: it may take the arguments and clobbers the lot.
    indirect: CallEffect,
}

impl Effects<'_> {
    fn callee_at(&self, block: usize, op: usize) -> Option<u64> {
        match &self.body.blocks[block].lifted.ops[op] {
            R2ILOp::Call { target } => Some(target.offset),
            _ => self.folded.get(&(block, op)).copied(),
        }
    }
}

impl CallEffects for Effects<'_> {
    fn at(&self, block: usize, op: usize) -> CallEffect {
        if let Some(effect) = self.by_site.get(&(block, op)) {
            return *effect;
        }
        (self.callee_at(block, op))
            .and_then(|callee| self.by_callee.get(&callee))
            .copied()
            .unwrap_or(self.indirect)
    }
}

#[cfg(test)]
mod tests {
    use super::{Authority, CallBoundary, Dispute, JoinedLane, LANES, LaneId, disputes};
    use r2source::confidence::{Basis, Confidence};
    use r2source::{ConventionId, SourceFunctionInterface, SourceFunctionReturn};

    fn void(declared: bool) -> SourceFunctionInterface {
        let interface = SourceFunctionInterface::new(
            b"void".to_vec(),
            ConventionId::SysVAmd64,
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("a void interface");
        match declared {
            true => interface.with_types(Confidence::of(Basis::DebugInfo)),
            false => interface,
        }
    }

    /// Every call leaves every lane dead but the integer one, which one call reads.
    fn read_integer() -> CallBoundary {
        let mut lanes = [JoinedLane {
            held: true,
            dead: true,
            ..JoinedLane::default()
        }; LANES];
        lanes[usize::from(LaneId::INTEGER.0)] = JoinedLane {
            held: true,
            read: true,
            ..JoinedLane::default()
        };
        CallBoundary::Sites {
            lanes,
            calls: 1,
            unread: false,
            forwarders: Box::default(),
            cut: false,
        }
    }

    #[test]
    fn a_call_reading_a_lane_the_callee_overwrites_loses_to_the_declaration() {
        let found = disputes(&void(true), &read_integer(), |_| true);
        let lost = Dispute {
            lane: LaneId::INTEGER,
            kept: Authority::Declared,
            lost: Authority::Calls,
        };
        assert_eq!(found, vec![lost]);
        let found = disputes(&void(false), &read_integer(), |_| true);
        assert_eq!(found[0].kept, Authority::Body);
    }

    /// A callee that leaves the lane alone hands the caller its own bytes back: no dispute.
    #[test]
    fn a_call_reading_a_lane_the_callee_leaves_alone_disputes_nothing() {
        assert!(disputes(&void(true), &read_integer(), |_| false).is_empty());
    }
}
