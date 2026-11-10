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
use crate::query::db::{Db, Query, Retention};

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
        /// Whether these calls are every way the image enters the callee.
        exhaustive: bool,
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

    /// Work: an import's placement, `O(locations)`; a function's callers' fates, each body solved
    /// once and held, then one binary search per call and one held read per forwarding caller.
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
}

/// The fates of every call to `callee`, joined, with each returned lane forwarded to its caller's
/// own boundary; `None` where the program makes no call the walk read.
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
    // Each returned lane, by caller and lane, forwarded after the direct fates are joined.
    let mut returned = BTreeSet::new();
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
                let Some(LaneFate::Returned(_)) = fate else {
                    join(joined, fate.map(Forwarded::Fate));
                    continue;
                };
                returned.insert((caller, at));
            }
        }
    }
    // A caller's boundary is asked only where its answer could move the decision: a lane no call
    // reads, while every lane a body may hold is dead or returned (O(callers) asks, each held).
    for (caller, at) in returned {
        let open = lanes
            .iter()
            .any(|lane| lane.held && (lane.unknown || lane.cycle));
        let fate = match (lanes[at].read, open) {
            (true, _) => Some(Forwarded::Fate(LaneFate::Unknown)),
            (false, true) if at >= 3 => Some(Forwarded::Fate(LaneFate::Unknown)),
            _ => forwarded(db, caller, at),
        };
        join(&mut lanes[at], fate);
    }
    // Only a result every call leaves dead asks whether the calls are every way in.
    let exhaustive = !unread
        && calls > 0
        && lanes.iter().all(|lane| lane.dead || !lane.held)
        && super::reads::only_called(db, callee, calls);
    r2il::refusal_evidence!(
        "call-boundary",
        "{callee:#x}: {calls} calls, unread callers {unread}, exhaustive {exhaustive}, lanes {lanes:?}"
    );
    (calls > 0).then_some(CallBoundary::Sites {
        lanes,
        calls,
        exhaustive,
    })
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
    Cycle,
}

/// The caller's own boundary on lane `at`: what its callers do with the bytes it returns.
fn forwarded<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    caller: u64,
    at: usize,
) -> Option<Forwarded> {
    let boundary = match db.get::<CallBoundary>(&(CalleeKey::Entry(caller), World::Closed)) {
        Ok(boundary) => boundary,
        Err(_) => return Some(Forwarded::Cycle),
    };
    let Some(CallBoundary::Sites {
        lanes, exhaustive, ..
    }) = boundary.as_ref()
    else {
        return Some(Forwarded::Fate(LaneFate::Unknown));
    };
    let lane = lanes[at];
    Some(match lane {
        lane if lane.read => Forwarded::Fate(LaneFate::Read(ByteMask(1))),
        lane if lane.cycle => Forwarded::Cycle,
        lane if lane.dead && *exhaustive => Forwarded::Fate(LaneFate::Dead),
        _ => Forwarded::Fate(LaneFate::Unknown),
    })
}

/// `fate` joined into `lane`; none (no such register) changes nothing.
fn join(lane: &mut JoinedLane, fate: Option<Forwarded>) {
    let Some(fate) = fate else { return };
    match fate {
        Forwarded::Fate(LaneFate::Dead) => {}
        Forwarded::Fate(LaneFate::Read(bytes)) => {
            lane.read = true;
            lane.dead = false;
            // A read of the whole register states no width.
            if let Some(width) = bytes.low_run().filter(|width| *width < 16) {
                lane.width = Some(match lane.width {
                    None => Some(width),
                    Some(known) => known.filter(|known| *known == width),
                });
            }
        }
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

/// What the closed world decides of a body's result from its open interface and its boundary
/// (doc/adr-call-boundary.md, "S7 as built"; D202).
pub(crate) fn decide(
    open: &r2source::SourceFunctionInterface,
    boundary: &CallBoundary,
) -> Option<SourceClosedResult> {
    let CallBoundary::Sites {
        lanes, exhaustive, ..
    } = boundary
    else {
        return None;
    };
    // A declaration states the result.
    if open.types_are_declared() {
        return None;
    }
    let lane = |id: LaneId| lanes[usize::from(id.0)];
    let (integer, float, second) = (
        lane(LaneId::INTEGER),
        lane(LaneId::FLOAT),
        lane(LaneId::SECOND),
    );
    let carriers = open.result_carriers();
    // Every lane of the return set: a body may hand back any of them as its caller left it (d72
    // round 6), so a void needs each dead at every call.
    let all_dead = *exhaustive && lanes.iter().all(|lane| lane.dead || !lane.held);
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
        Effects {
            body,
            by_callee: (callees.into_iter())
                .map(|callee| (callee, self.callee(callee)))
                .collect(),
            folded,
            indirect: CallEffect {
                takes: self.unknown(),
                counted: None,
                overwrites: Overwrites::All,
            },
        }
    }

    /// What a call to a callee nothing is known of may take: a summary's own calls set the variadic
    /// count themselves, so only a caller counts it.
    fn unknown(&self) -> LaneBytes {
        match self.depth {
            Depth::Deep => unknown_call_takes(self.lanes, self.slots),
            Depth::Shallow => argument_takes(self.lanes, self.slots),
        }
    }

    /// A call to `callee`: an import overwrites every result register and takes what its boundary
    /// reads; a function of the image takes and overwrites what its own body does.
    fn callee(&self, callee: u64) -> CallEffect {
        if crate::native::Program::import_at(self.view, callee).is_some() {
            let boundary = self
                .db
                .get::<CallBoundary>(&(CalleeKey::Import(ImportId(callee)), World::Open));
            let reads = match boundary.ok().as_deref() {
                Some(Some(CallBoundary::Import { reads })) => reads.clone(),
                _ => None,
            };
            let (takes, counted) = self.import_takes(reads);
            return CallEffect {
                takes,
                counted,
                overwrites: Overwrites::All,
            };
        }
        // A summary reads no other summary, so one costs one pass over one body (ADR, Cost).
        let summary = (self.depth == Depth::Deep)
            .then(|| {
                let thumb = self.view.thumb_at(callee);
                self.db.get::<CalleeEntry>(&(callee, thumb))
            })
            .and_then(Result::ok);
        match summary.and_then(|summary| *summary) {
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
        }
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

/// What each call of one body does to the result registers.
struct Effects<'b> {
    body: &'b Body,
    by_callee: BTreeMap<u64, CallEffect>,
    /// The calls the walk folded to a target, by block and operation.
    folded: BTreeMap<(usize, usize), u64>,
    /// A call whose callee the walk did not read: it may take the arguments and clobbers the lot.
    indirect: CallEffect,
}

impl CallEffects for Effects<'_> {
    fn at(&self, block: usize, op: usize) -> CallEffect {
        let callee = match &self.body.blocks[block].lifted.ops[op] {
            R2ILOp::Call { target } => Some(target.offset),
            _ => self.folded.get(&(block, op)).copied(),
        };
        callee
            .and_then(|callee| self.by_callee.get(&callee))
            .copied()
            .unwrap_or(self.indirect)
    }
}
