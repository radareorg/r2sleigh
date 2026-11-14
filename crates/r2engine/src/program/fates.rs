//! The callee's boundary (doc/adr-call-boundary.md, "The callee's boundary"; doc/adr-result-side.md,
//! section 3): every call's fate on each result lane, joined once per callee, and its result decided once.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2il::R2ILOp;
use r2source::{
    CanonicalStorageId, ConventionModel, SourceClosedResult, SourceReadLanes, SourceResultCause,
};
use r2ssa::dense::{Csr, DenseId, IdMap};
use r2ssa::site_boundary::{
    ByteMask, CallEffect, CallEffects, CallerFlow, Counted, LANES, LaneBytes, LaneFate, LaneId,
    Overwrites, RegisterEffect, ResultLanes, SiteBoundary, argument_registers,
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

impl JoinedLane {
    /// `other` joined in: each flag rises, `dead` falls, the bytes grow and two widths disagree.
    fn merge(&mut self, other: &Self) {
        self.read |= other.read;
        self.unknown |= other.unknown;
        self.cycle |= other.cycle;
        self.dead &= other.dead;
        self.bytes = ByteMask(self.bytes.0 | other.bytes.0);
        self.width = match (self.width, other.width) {
            (None, width) | (width, None) => width,
            (Some(one), Some(other)) => Some(one.filter(|one| Some(*one) == other)),
        };
    }
}

/// What one callee's boundary states (doc/adr-result-side.md, section 3): under the closed world,
/// each lane's fate over every call and the result decided from it; for an import, what it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallBoundary {
    Sites {
        forwarding: Box<Forwarding>,
        result: BoundaryResult,
    },
    Import {
        reads: Option<r2ssa::call_reads::CallReads>,
    },
}

/// What the closed world decides of one function's result, once (doc/adr-result-side.md, section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryResult {
    /// Each lane's decision, by `LaneId`.
    pub lanes: [LaneDecision; LANES],
    /// What the seal applies as a stated input; none where the calls decide nothing.
    pub result: Option<SourceClosedResult>,
    /// Whether a way in is a cited slot, which the decision's premises read (`SourceClosedDecision`).
    pub through_slot: bool,
    /// The sources the authority order overrules: refusal evidence, never a decision.
    pub disputes: Box<[Dispute]>,
}

/// One result lane, decided over every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneDecision {
    /// The body holds no result here: no such lane, an unheld one, or one beside an undefined integer.
    NoResult,
    /// Some call reads it.
    Read,
    /// Every call leaves it dead, and the calls are every way in.
    Dead,
    /// A call returns it on through a cycle of forwarders, which proves no read.
    Cycle,
    /// Nothing decides it.
    Open,
}

/// What a body's own seal states of its result, which the decision reads: the supply, handed in
/// by the seal that asks (doc/adr-result-side.md, "S31a as built").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Supply {
    /// A declaration states the result, which no call overrules.
    pub declared: bool,
    pub returns: Returns,
    /// The registers an unproven or written result may be in.
    pub carriers: Option<Carriers>,
    /// Every cause of an unproven result is a handed-back input or no return.
    pub handed_back: bool,
}

/// The shape of a body's own result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Returns {
    Void,
    Register,
    Unproven,
    Other,
}

/// Which carriers an unproven result names beside the integer register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Carriers {
    pub float: bool,
    pub second: bool,
    /// No return defines a byte of the integer register (scratch-result cases 1 to 3).
    pub integer_undefined: bool,
    /// The lane after the float one that a return leaves written, as the open read states it.
    pub float_second: Option<u8>,
}

impl Supply {
    /// The supply a sealed interface states. O(causes).
    pub fn of(open: &r2source::SourceFunctionInterface) -> Self {
        let returns = match open.return_kind() {
            r2source::SourceFunctionReturn::Void => Returns::Void,
            r2source::SourceFunctionReturn::Register { .. } => Returns::Register,
            r2source::SourceFunctionReturn::Unproven => Returns::Unproven,
            _ => Returns::Other,
        };
        let carriers = open.result_carriers().map(|carriers| Carriers {
            float: carriers.float.is_some(),
            second: carriers.second.is_some(),
            integer_undefined: carriers.integer_undefined,
            float_second: carriers.float_second,
        });
        let causes = open
            .unproven_result()
            .map(r2source::SourceUnprovenResult::causes);
        let handed_back = causes.unwrap_or_default().iter().all(|cause| {
            matches!(
                cause,
                SourceResultCause::HandedBack | SourceResultCause::NoReturn
            )
        });
        Self {
            declared: open.types_are_declared(),
            returns,
            carriers,
            handed_back,
        }
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for CallBoundary {
    /// The callee and the world; a function's supply is its open read's (D317).
    type Key = (CalleeKey, World);
    type Value = Option<CallBoundary>;
    const NAME: &'static str = "call-boundary";
    const RETENTION: Retention = Retention::Held;

    /// Work: an import's placement; a function's forwarding component, read once, and `O(LANES)`
    /// to decide.
    fn compute(db: &Db<ProgramInputs<S>>, &(callee, world): &(CalleeKey, World)) -> Self::Value {
        let view = View::new(db, true);
        match (callee, world) {
            (CalleeKey::Import(ImportId(at)), _) => {
                let walker = super::returns::Walking::new(view.clone(), true).ok()?;
                let name = crate::native::Program::import_at(&view, at)?;
                let target = walker.target(view.thumb_at(at));
                Some(CallBoundary::Import {
                    reads: crate::native::import_reads(target, &name),
                })
            }
            // A cold `pdd` joins no sites.
            (CalleeKey::Entry(_), World::Open) => None,
            (CalleeKey::Entry(entry), World::Closed) => {
                // One decision reads another only through the forwarder component (ADR section 4).
                if db.running("call-boundary") > 1 {
                    db.defect(format_args!(
                        "call-boundary {entry:#x} reached inside another"
                    ));
                }
                if db.running("register-effects") > 0 {
                    db.defect(format_args!(
                        "call-boundary {entry:#x} reached from a register effect"
                    ));
                }
                let thumb = view.thumb_at(entry);
                // Each call's per-lane statement composes a callee's supply into the open read (D317).
                let open = db
                    .get::<super::analysis::CalleeReads>(&(entry, thumb))
                    .ok()?;
                let open = open.0.interface.as_ref()?;
                let forwarding = (*db.get::<ComponentForwarding>(&entry).ok()?).clone()?;
                let result = BoundaryResult::decided(db, (entry, thumb), &forwarding, open);
                r2il::refusal_evidence!(
                    "call-boundary",
                    "{entry:#x}: closed world decides {:?}",
                    result.result
                );
                for dispute in &result.disputes {
                    r2il::refusal_evidence!("call-boundary-dispute", "{entry:#x}: {dispute:?}");
                }
                Some(CallBoundary::Sites {
                    forwarding: Box::new(forwarding),
                    result,
                })
            }
        }
    }
}

/// The calls to one function joined, before any returned lane is forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Direct {
    lanes: [JoinedLane; LANES],
    calls: u32,
    /// The loader's own calls a cited row states (r2abi `loader_call`, D237, D240); their reads are in `lanes`.
    loader_calls: u32,
    /// Every take hands the address into cited slots, one of which reads the result (D227).
    slot_read: bool,
    /// Some caller the survey names was not read, so these calls may not be every call.
    unread: bool,
    /// Each lane a call returns on into its caller, which that caller's own calls decide.
    returned: Box<[Returned]>,
}

/// The returned lanes kept for their callers, decided from the direct calls alone so the forwarder
/// graph rests on none of its answers; a lane not kept is joined `Unknown`, never dead. O(returned).
fn forwarded_lanes(
    lanes: &mut [JoinedLane; LANES],
    returned: BTreeSet<Returned>,
    float_second: Option<usize>,
) -> Vec<Returned> {
    let open = lanes
        .iter()
        .any(|lane| lane.held && (lane.unknown || lane.cycle));
    // A lane past the typed three decides a void, or, after a float lane some call may read, a group.
    let float = usize::from(LaneId::FLOAT.0);
    let grouped = lanes[float].read || returned.iter().any(|returned| returned.at == float);
    let second = float_second.filter(|_| grouped);
    let kept = returned.into_iter().filter(|returned| {
        let past = returned.at >= 3 && Some(returned.at) != second;
        let decided = lanes[returned.at].read || (open && past);
        if decided {
            join(
                &mut lanes[returned.at],
                Some(Forwarded::Fate(LaneFate::Unknown)),
            );
        }
        !decided
    });
    kept.collect()
}

/// A lane a call returns on: the caller, the lane and the bytes it hands back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Returned {
    caller: u64,
    at: usize,
    bytes: ByteMask,
}

/// Every call to one function joined, with no returned lane forwarded: the forwarder graph's node.
pub(super) struct DirectSites;

impl<S: Source + 'static> Query<ProgramInputs<S>> for DirectSites {
    type Key = u64;
    type Value = Option<Direct>;
    const NAME: &'static str = "direct-sites";
    const RETENTION: Retention = Retention::Held;

    /// Work: each caller's held site fates, and a search per caller for its calls to `callee`.
    fn compute(db: &Db<ProgramInputs<S>>, &callee: &u64) -> Self::Value {
        direct_sites(db, callee)
    }
}

/// The fates of every call to `callee`, joined; a returned lane is kept for its caller only where
/// that could move the decision (doc/adr-result-side.md, "S31a as built").
fn direct_sites<S: Source + 'static>(db: &Db<ProgramInputs<S>>, callee: u64) -> Option<Direct> {
    let survey = db.get::<SurveyQuery>(&()).ok()?;
    let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
    let (held, float_second) = held_lanes(db, callee)?;
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
    let mut returned = BTreeSet::new();
    // A caller's site fates deposit its register effect, so a caller calling it reads it held (D354).
    for caller in callee_first(&survey, survey.callers_of(callee)) {
        if let Some(Ok(thumb)) = survey.walked_in(caller) {
            let _ = db.get::<SiteFates>(&(caller, thumb));
        }
    }
    let view = View::new(db, true);
    // A caller under another convention states its sites' fates in its lanes: none is read (D385).
    let convention = |entry: u64| view.convention_at(entry).ok().map(|ruled| ruled.id);
    let own = convention(callee);
    let alike = |caller: u64| own.is_some() && convention(caller) == own;
    for &caller in survey.callers_of(callee) {
        let Some(Ok(thumb)) = survey.walked_in(caller) else {
            unread = true;
            continue;
        };
        if !alike(caller) {
            unread = true;
            continue;
        }
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
            join_site(&mut lanes, caller, &site.boundary, &mut returned);
        }
    }
    // A body that leaves for `callee` by a branch returns what `callee` returns: each held lane is
    // its own result, read as its callers read it (D227, `__wrap_main`'s `b main`).
    for &caller in survey.tail_callers_of(callee) {
        if !alike(caller) {
            unread = true;
            continue;
        }
        let held = (lanes.iter().enumerate()).filter(|(_, lane)| lane.held);
        returned.extend(held.map(|(at, _)| Returned {
            caller,
            at,
            bytes: ByteMask(u128::MAX),
        }));
    }
    let loader_calls = loader_reads(db.inputs().source.container(), callee, &mut lanes);
    let slot_read = slot_reads(db, callee, &mut lanes);
    let returned = forwarded_lanes(&mut lanes, returned, float_second).into();
    r2il::refusal_evidence!(
        "call-boundary",
        "{callee:#x}: {calls} calls, unread callers {unread}, lanes {lanes:?}"
    );
    Some(Direct {
        lanes,
        calls,
        loader_calls,
        slot_read,
        unread,
        returned,
    })
}

/// Whether every take of `callee` hands it into cited slots one of which reads an integer result,
/// that read joined into `lanes` (D227): `O(log takes)` where nothing takes it.
fn slot_reads<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
    lanes: &mut [JoinedLane; LANES],
) -> bool {
    let escapes = db.get::<super::reads::Escapes>(&()).ok();
    let ways = escapes.as_deref().and_then(Option::as_ref);
    if ways.is_none_or(|ways| ways.takes_of(callee).is_empty()) {
        return false;
    }
    let proof = db.get::<super::slots::DeclaredSlot>(&callee).ok();
    let Some(r2abi::ResultRead::Integer { bytes }) =
        proof.and_then(|proof| *proof).map(|p| p.reads)
    else {
        return false;
    };
    let read = ByteMask((1u128 << bytes) - 1);
    let lane = &mut lanes[usize::from(LaneId::INTEGER.0)];
    join(lane, Some(Forwarded::Fate(LaneFate::Read(read))));
    true
}

/// `callers` (ascending) ordered so each comes after every other one it calls, a cycle broken where
/// the search enters it: a post-order over the calls among them, `O(E log k)` for `E` calls into them.
fn callee_first(survey: &super::requests::Survey, callers: &[u64]) -> Vec<u64> {
    let mut calls = vec![Vec::new(); callers.len()];
    for (to, called) in callers.iter().enumerate() {
        for caller in survey.callers_of(*called) {
            if let Ok(from) = callers.binary_search(caller)
                && from != to
            {
                calls[from].push(to);
            }
        }
    }
    let mut seen = vec![false; callers.len()];
    let mut order = Vec::with_capacity(callers.len());
    // Each caller enters the stack once, and each of its calls is stepped past once.
    for root in 0..callers.len() {
        if std::mem::replace(&mut seen[root], true) {
            continue;
        }
        let mut stack = vec![(root, 0usize)];
        while let Some((at, next)) = stack.last_mut() {
            match calls[*at].get(*next).copied() {
                Some(to) => {
                    *next += 1;
                    let fresh = !std::mem::replace(&mut seen[to], true);
                    stack.extend(fresh.then_some((to, 0)));
                }
                None => {
                    order.push(callers[*at]);
                    stack.pop();
                }
            }
        }
    }
    order
}

/// The loader's calls to `callee` a cited row states, each read joined into `lanes` (D237, D240):
/// `O(entries)`.
fn loader_reads(container: &super::Container, callee: u64, lanes: &mut [JoinedLane; LANES]) -> u32 {
    let library = super::c_library(container);
    let mut calls = 0u32;
    for entry in (container.entries.iter()).filter(|entry| entry.vaddr == callee) {
        let Some(call) = r2abi::loader_call(container.format, library, entry.kind) else {
            continue;
        };
        calls = calls.saturating_add(1);
        if let r2abi::ResultRead::Integer { bytes } = call.reads_result {
            let read = ByteMask((1u128 << bytes) - 1);
            join(
                &mut lanes[usize::from(LaneId::INTEGER.0)],
                Some(Forwarded::Fate(LaneFate::Read(read))),
            );
        }
    }
    calls
}

/// One call's fate on each lane joined into `lanes`; a lane it returns on waits for its caller.
fn join_site(
    lanes: &mut [JoinedLane; LANES],
    caller: u64,
    site: &SiteBoundary,
    returned: &mut BTreeSet<Returned>,
) {
    for (at, (joined, fate)) in lanes.iter_mut().zip(site.fates).enumerate() {
        match fate {
            Some(LaneFate::Returned(bytes)) => {
                returned.insert(Returned { caller, at, bytes });
            }
            fate => join(joined, fate.map(Forwarded::Fate)),
        }
    }
}

/// One function's lanes once every returned lane is forwarded to its caller's own calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarding {
    pub lanes: [JoinedLane; LANES],
    pub calls: u32,
    pub loader_calls: u32,
    /// A cited slot every take reaches reads the result (D227).
    pub slot_read: bool,
    pub unread: bool,
    /// The callers a returned lane is dead in only if their own calls are every way in.
    pub forwarders: Box<[u64]>,
}

/// A function's forwarding, solved with every member of its strongly connected component of the
/// forwarder graph (doc/adr-result-side.md, section 4, "Forwarding and cycles").
pub(super) struct ComponentForwarding;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ComponentForwarding {
    type Key = u64;
    type Value = Option<Forwarding>;
    const NAME: &'static str = "forwarded";
    const RETENTION: Retention = Retention::Held;

    /// Work: Tarjan's search over the callers a lane is returned to, `O(V + E)` over what it
    /// reaches, then each component's fixpoint, `O(V + E × height)`; every member is deposited.
    fn compute(db: &Db<ProgramInputs<S>>, &root: &u64) -> Self::Value {
        let solved = |node: u64| {
            (db.held::<ComponentForwarding>(&node).ok().flatten()).filter(|_| node != root)
        };
        let mut search = super::resolved::Search::default();
        search.run(root, |node| match solved(node) {
            Some(_) => Vec::new(),
            None => callers_returned_to(db, node),
        });
        let mut answers = BTreeMap::new();
        for members in &search.closed {
            if members.iter().all(|member| solved(*member).is_some()) {
                continue;
            }
            let outside = |caller: u64| match answers.get(&caller) {
                Some(answer) => Some(Option::clone(answer)),
                None => solved(caller).map(|held| (*held).clone()),
            };
            for (member, answer) in solve(db, members, outside) {
                answers.insert(member, answer);
            }
        }
        let own = answers.remove(&root).flatten();
        db.deposit::<ComponentForwarding>(answers);
        own
    }
}

/// The callers `node`'s calls return a lane on to, each once, ascending.
fn callers_returned_to<S: Source + 'static>(db: &Db<ProgramInputs<S>>, node: u64) -> Vec<u64> {
    let direct = db.get::<DirectSites>(&node).ok();
    let returned = direct.as_deref().and_then(Option::as_ref);
    let callers = returned
        .into_iter()
        .flat_map(|direct| direct.returned.iter());
    let callers = callers.map(|returned| returned.caller);
    callers.collect::<BTreeSet<_>>().into_iter().collect()
}

/// A member of one component, by its place in the sorted members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Member(u32);

impl DenseId for Member {
    fn index(self) -> usize {
        self.0 as usize
    }
    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 members"))
    }
}

/// Each lane can move this often: four flags, 128 byte bits and two width steps.
const LANE_HEIGHT: usize = 4 + 128 + 2;

/// Which members' reads rest on a callback slot: their own, or a caller's whose result returns
/// theirs, outside or inside the component, to a fixpoint. Each member turns once: `O(V + E)`.
fn slotted(
    component: &Component<'_>,
    outside: &impl Fn(u64) -> Option<Option<Forwarding>>,
) -> Vec<bool> {
    let count = component.members.len();
    let mut slotted = vec![false; count];
    let mut returned_to = vec![Vec::new(); count];
    let mut pending = Vec::new();
    for (at, direct) in component.directs.iter().enumerate() {
        let Some(direct) = direct else { continue };
        let mut own = direct.slot_read;
        for returned in &direct.returned {
            match component.member(returned.caller) {
                Some(inside) => returned_to[inside.index()].push(at),
                None => {
                    own |= outside(returned.caller)
                        .flatten()
                        .is_some_and(|theirs| theirs.slot_read)
                }
            }
        }
        if own {
            slotted[at] = true;
            pending.push(at);
        }
    }
    while let Some(caller) = pending.pop() {
        for callee in std::mem::take(&mut returned_to[caller]) {
            if !slotted[callee] {
                slotted[callee] = true;
                pending.push(callee);
            }
        }
    }
    slotted
}

/// One component's members solved together: the least fixpoint of the reads a lane forwarded inside
/// the component takes, then each inside edge that reaches no read is a cycle, never dead.
fn solve<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    members: &[u64],
    outside: impl Fn(u64) -> Option<Option<Forwarding>>,
) -> Vec<(u64, Option<Forwarding>)> {
    let directs = (members.iter())
        .map(|member| (*db.get::<DirectSites>(member).ok()?).clone())
        .collect::<Vec<_>>();
    let component = Component { members, directs };
    let mut forwarders = vec![BTreeSet::new(); members.len()];
    let fixed = component.fixed(&outside, &mut forwarders);
    let order = (0..members.len())
        .map(Member::from_index)
        .collect::<Vec<_>>();
    let readers = Csr::from_pairs(
        members.len(),
        component.edges().map(|(from, to)| (to, from)),
    );
    let cells = r2ssa::fixpoint::sparse(
        "forwarded",
        LANES * LANE_HEIGHT,
        &order,
        &readers,
        BOTTOM,
        |member, cells: &IdMap<Member, [JoinedLane; LANES]>| {
            let Some(mut lanes) = fixed[member.index()] else {
                return BOTTOM;
            };
            for (lane, fate) in component.inside(member, cells) {
                join(&mut lanes[lane], fate);
            }
            // Inflationary: what a cell held stays, so each cell only rises.
            if let Some(held) = cells.get(member).filter(|held| **held != BOTTOM) {
                lanes
                    .iter_mut()
                    .zip(held)
                    .for_each(|(lane, held)| lane.merge(held));
            }
            lanes
        },
    );
    let Ok(cells) = cells else {
        return members.iter().map(|member| (*member, None)).collect();
    };
    let slotted = slotted(&component, &outside);
    let solved = (0..members.len()).map(|at| {
        let direct = component.directs[at].as_ref()?;
        let member = Member::from_index(at);
        let mut lanes = cells.get(member).copied().unwrap_or(BOTTOM);
        // A lane returned inside the component that reaches no read there proves none.
        for (lane, fate) in component.inside(member, &cells) {
            if fate.is_none() {
                join(&mut lanes[lane], Some(Forwarded::Cycle));
            }
        }
        let slot_read = slotted[at];
        Some(Forwarding {
            lanes,
            calls: direct.calls,
            loader_calls: direct.loader_calls,
            slot_read,
            unread: direct.unread,
            forwarders: std::mem::take(&mut forwarders[at]).into_iter().collect(),
        })
    });
    let solved = solved.collect::<Vec<_>>();
    members.iter().copied().zip(solved).collect()
}

/// Lanes no call reaches: the fixpoint's start.
const BOTTOM: [JoinedLane; LANES] = [JoinedLane {
    held: false,
    read: false,
    bytes: ByteMask(0),
    unknown: false,
    cycle: false,
    dead: false,
    width: None,
}; LANES];

/// One component of the forwarder graph: its members ascending, and each one's calls joined.
struct Component<'m> {
    members: &'m [u64],
    directs: Vec<Option<Direct>>,
}

impl Component<'_> {
    fn member(&self, caller: u64) -> Option<Member> {
        self.members
            .binary_search(&caller)
            .ok()
            .map(Member::from_index)
    }

    /// Each lane returned from one member into another: the returner and the caller.
    fn edges(&self) -> impl Iterator<Item = (Member, Member)> + '_ {
        (self.directs.iter().enumerate()).flat_map(move |(at, direct)| {
            let returned = direct.iter().flat_map(|direct| direct.returned.iter());
            returned.filter_map(move |returned| {
                Some((Member::from_index(at), self.member(returned.caller)?))
            })
        })
    }

    /// Each member's own calls and its returns to callers outside the component: fixed during the
    /// solve; a caller whose calls all leave the lane dead is a forwarder.
    fn fixed(
        &self,
        outside: &impl Fn(u64) -> Option<Option<Forwarding>>,
        forwarders: &mut [BTreeSet<u64>],
    ) -> Vec<Option<[JoinedLane; LANES]>> {
        let fixed = (self.directs.iter().zip(forwarders)).map(|(direct, forwarders)| {
            let direct = direct.as_ref()?;
            let mut lanes = direct.lanes;
            let away = direct.returned.iter();
            for returned in away.filter(|returned| self.member(returned.caller).is_none()) {
                let theirs = outside(returned.caller).flatten();
                let fate = forwarded(theirs.as_ref(), returned.at, returned.bytes);
                let dead = matches!(fate, Some(Forwarded::DeadIfEveryWayIn));
                forwarders.extend(dead.then_some(returned.caller));
                join(&mut lanes[returned.at], fate);
            }
            Some(lanes)
        });
        fixed.collect()
    }

    /// Each lane `member` returns inside the component, with what the caller's cell takes of it.
    fn inside<'c>(
        &'c self,
        member: Member,
        cells: &'c IdMap<Member, [JoinedLane; LANES]>,
    ) -> impl Iterator<Item = (usize, Option<Forwarded>)> + 'c {
        let direct = self.directs[member.index()].iter();
        let returned = direct.flat_map(|direct| direct.returned.iter());
        returned.filter_map(move |returned| {
            let caller = self.member(returned.caller)?;
            let theirs = cells
                .get(caller)
                .map_or(BOTTOM[0], |lanes| lanes[returned.at]);
            Some((returned.at, read_inside(theirs, returned.bytes)))
        })
    }
}

/// What a lane returned to a member of the same component takes from that member's calls: a read,
/// or what it may do; nothing yet where it is dead or a cycle there.
fn read_inside(theirs: JoinedLane, bytes: ByteMask) -> Option<Forwarded> {
    let reached = ByteMask(theirs.bytes.0 & bytes.0);
    let width = (theirs.width)
        .map(|width| width.filter(|width| reached.low_run().is_some_and(|run| run >= *width)));
    match theirs {
        _ if reached.0 & 1 != 0 => Some(Forwarded::Read(reached, width)),
        _ if reached.0 != 0 => Some(Forwarded::Fate(LaneFate::Unknown)),
        lane if lane.unknown || lane.read => Some(Forwarded::Fate(LaneFate::Unknown)),
        _ => None,
    }
}

/// Whether the calls a forwarding joined are every way the image enters a function, and each
/// forwarder's are too: a forwarder is in a later component, so the question ends.
pub(super) struct EveryWayIn;

impl<S: Source + 'static> Query<ProgramInputs<S>> for EveryWayIn {
    type Key = u64;
    type Value = bool;
    const NAME: &'static str = "every-way-in";
    const RETENTION: Retention = Retention::Held;

    /// Work: `only_called` once, and one ask per forwarder.
    fn compute(db: &Db<ProgramInputs<S>>, &callee: &u64) -> bool {
        let found = db.get::<ComponentForwarding>(&callee).ok();
        let Some(forwarding) = found.as_deref().and_then(Option::as_ref) else {
            return false;
        };
        let mut answer =
            !forwarding.unread && super::reads::only_called(db, callee, forwarding.calls);
        for caller in forwarding.forwarders.iter() {
            if !answer {
                break;
            }
            answer = db.get::<EveryWayIn>(caller).is_ok_and(|theirs| *theirs);
        }
        answer
    }
}

/// Whether a float result is one group with the lane after it: the body writes that lane at a
/// return and some call reads both (doc/adr-result-side.md, "Struct in registers"). O(1).
fn group_read(supply: Supply, lanes: &[JoinedLane; LANES]) -> bool {
    let second = supply.carriers.and_then(|carriers| carriers.float_second);
    let read = |at: usize| lanes.get(at).is_some_and(|lane| lane.read);
    read(usize::from(LaneId::FLOAT.0)) && second.is_some_and(|at| read(usize::from(at)))
}

/// Which result lanes of `callee`'s convention a body may leave a result in: the typed three, and
/// each other lane that is an argument location. The x87 lanes hold nothing on entry (SysV 3.2.1).
fn held_lanes<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
) -> Option<([bool; LANES], Option<usize>)> {
    let view = View::new(db, true);
    let target = own_target(&view, callee, view.thumb_at(callee))?;
    let slots = &*target.convention;
    let slots_of = lanes_of(&target, slots).slots();
    let arguments = argument_registers(slots);
    let input = |lane: &CanonicalStorageId| {
        arguments.iter().any(|argument| {
            argument.space == lane.space
                && argument.offset < lane.offset + u64::from(lane.size)
                && lane.offset < argument.offset + u64::from(argument.size)
        })
    };
    let lanes = lanes_of(&target, slots);
    let second = (lanes.after_float(&target.convention.results)).map(|(_, id)| id);
    let held = std::array::from_fn(|at| slots_of[at].is_some_and(|lane| at < 3 || input(&lane)));
    Some((held, second))
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

/// What a caller in a later component does, on lane `at`, with the `bytes` a call returns into it.
fn forwarded(theirs: Option<&Forwarding>, at: usize, bytes: ByteMask) -> Option<Forwarded> {
    let Some(theirs) = theirs else {
        return Some(Forwarded::Fate(LaneFate::Unknown));
    };
    let lane = theirs.lanes[at];
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

impl BoundaryResult {
    /// The decision from the open read's supply and the calls' forwarding (the demand): every way
    /// in is asked only where every lane is dead.
    fn decided<S: Source + 'static>(
        db: &Db<ProgramInputs<S>>,
        (entry, thumb): (u64, bool),
        forwarding: &Forwarding,
        open: &r2source::SourceFunctionInterface,
    ) -> Self {
        let supply = Supply::of(open);
        let lanes = &forwarding.lanes;
        let mut asked = None;
        let mut every_way_in =
            || *asked.get_or_insert_with(|| db.get::<EveryWayIn>(&entry).is_ok_and(|all| *all));
        let grouped = group_read(supply, lanes);
        let result = match grouped {
            true => None,
            false => decided_result(supply, forwarding, &mut every_way_in),
        };
        let result = result.or_else(|| declared_void(db, entry, supply, forwarding));
        let overwritten = |lane: LaneId| {
            let effect = db.get::<RegisterEffects>(&(entry, thumb));
            (effect.ok().as_deref().and_then(Option::as_ref))
                .is_some_and(|effect| effect.overwrites.touches(usize::from(lane.0)))
        };
        let disputes = disputes_of(supply, lanes, overwritten);
        let disputes = (disputes.into_iter().chain(body_disputes(open))).collect::<Vec<_>>();
        let holds = holds(supply, lanes);
        let dead = asked == Some(true);
        let decisions = std::array::from_fn(|at| match lanes[at] {
            _ if !holds[at] => LaneDecision::NoResult,
            lane if lane.read => LaneDecision::Read,
            lane if lane.cycle => LaneDecision::Cycle,
            lane if lane.dead && dead => LaneDecision::Dead,
            _ => LaneDecision::Open,
        });
        Self {
            lanes: decisions,
            result,
            through_slot: result.is_some() && forwarding.slot_read,
            disputes: disputes.into(),
        }
    }

    /// The decision the seal applies, with what it assumes.
    pub const fn decision(&self) -> Option<r2source::SourceClosedDecision> {
        match self.result {
            Some(result) => Some(r2source::SourceClosedDecision {
                result,
                through_slot: self.through_slot,
            }),
            None => None,
        }
    }
}

/// `DeclaredVoid`: every way in hands the address only into cited `void (*)(...)` slots, so
/// under `UbFreeSource` nothing reads the result (doc/adr-result-side.md, S30 as built).
fn declared_void<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    entry: u64,
    supply: Supply,
    forwarding: &Forwarding,
) -> Option<SourceClosedResult> {
    let undecided = matches!(supply.returns, Returns::Unproven | Returns::Register);
    if supply.declared || !undecided || forwarding.unread || !forwarding.forwarders.is_empty() {
        return None;
    }
    let holds = holds(supply, &forwarding.lanes);
    let lanes = &forwarding.lanes;
    let quiet = |at: usize| !holds[at] || !(lanes[at].read || lanes[at].unknown || lanes[at].cycle);
    if !(0..LANES).all(quiet) || !super::reads::calls_claimed(db, entry, forwarding.calls) {
        return None;
    }
    let proof = (*db.get::<super::slots::DeclaredSlot>(&entry).ok()?)?;
    (proof.reads == r2abi::ResultRead::Nothing)
        .then_some(SourceClosedResult::DeclaredVoid(proof.origin))
}

/// Which lanes the body may hold a result in: an integer register no return defines holds none, and
/// the second holds a result only beside it (SysV psABI 3.2.3, AAPCS64 6.9).
fn holds(supply: Supply, lanes: &[JoinedLane; LANES]) -> [bool; LANES] {
    let carriers = supply.carriers;
    let undefined = carriers.is_some_and(|carriers| carriers.integer_undefined);
    std::array::from_fn(|at| {
        lanes[at].held
            && !(undefined
                && (at == usize::from(LaneId::INTEGER.0) || at == usize::from(LaneId::SECOND.0)))
    })
}

/// What the closed world decides of a body's result from its open interface and the calls' lanes
/// (D202, D213); a function nothing calls keeps its open result (doc/adr-result-side.md, section 3).
fn decided_result(
    supply: Supply,
    forwarding: &Forwarding,
    every_way_in: &mut dyn FnMut() -> bool,
) -> Option<SourceClosedResult> {
    let Forwarding {
        lanes,
        calls,
        loader_calls,
        ..
    } = forwarding;
    // A declaration states the result.
    if supply.declared {
        return None;
    }
    let carriers = supply.carriers;
    let holds = holds(supply, lanes);
    let lane = |id: LaneId| lanes[usize::from(id.0)];
    let (integer, float, second) = (
        lane(LaneId::INTEGER),
        lane(LaneId::FLOAT),
        lane(LaneId::SECOND),
    );
    // An integer register no return defines holds no result: a call reading it reads its own bytes.
    let integer_read = integer.read && holds[usize::from(LaneId::INTEGER.0)];
    // Every lane a body may hand back as its caller left it (d72 round 6) is dead at every one of
    // `ways` calls, of which there is one or more.
    let mut all_dead =
        |ways: u32| ways > 0 && (0..LANES).all(|at| lanes[at].dead || !holds[at]) && every_way_in();
    // A loader call a cited row states is a call (D237); a written result's `Unread` moves no C, so
    // only the program's own calls ask every way in for it (doc/adr-call-boundary.md, "S7 cost").
    let ways = match supply.handed_back && supply.returns == Returns::Unproven {
        true => calls + loader_calls,
        false => *calls,
    };
    let cycle = (0..LANES).any(|at| holds[at] && lanes[at].cycle);
    match supply.returns {
        Returns::Register => {
            let paired = carriers.is_some_and(|carriers| carriers.second);
            if paired && second.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Pair));
            }
            if integer.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            if all_dead(ways) {
                return Some(SourceClosedResult::Unread);
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        Returns::Unproven => {
            let carriers = carriers?;
            // A call reading the second register takes the pair, as for a register result.
            if carriers.second && second.read {
                return Some(SourceClosedResult::Read(SourceReadLanes::Pair));
            }
            if integer_read && (!carriers.float || !float.read) {
                return Some(SourceClosedResult::Read(SourceReadLanes::Integer));
            }
            if carriers.float && float.read && !integer_read {
                let bytes = float
                    .width
                    .flatten()
                    .filter(|bytes| matches!(bytes, 4 | 8))?;
                let bytes = u8::try_from(bytes).ok()?;
                return Some(SourceClosedResult::Read(SourceReadLanes::Float { bytes }));
            }
            // No defined byte reaches a return where the body only hands back an input.
            if all_dead(ways) {
                return Some(match supply.handed_back {
                    true => SourceClosedResult::Void,
                    false => SourceClosedResult::Unread,
                });
            }
            cycle.then_some(SourceClosedResult::ForwardCycle)
        }
        Returns::Void | Returns::Other => None,
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
fn disputes_of(
    supply: Supply,
    lanes: &[JoinedLane; LANES],
    overwritten: impl Fn(LaneId) -> bool,
) -> Vec<Dispute> {
    if supply.returns != Returns::Void {
        return Vec::new();
    }
    let kept = match supply.declared {
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

/// The lanes where a declaration overrules its own body's returns: DWARF stays first, and the
/// body's loss is evidence (doc/adr-result-side.md, "Declaration against body"). O(lanes).
fn body_disputes(
    declared: &r2source::SourceFunctionInterface,
) -> impl Iterator<Item = Dispute> + '_ {
    declared.body_disputed_lanes().map(|(lane, _)| Dispute {
        lane: match lane {
            r2source::SourceTypedLane::Integer => LaneId::INTEGER,
            r2source::SourceTypedLane::Float => LaneId::FLOAT,
        },
        kept: Authority::Declared,
        lost: Authority::Body,
    })
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

    /// Work: the body's own register effect, deposited, then one backward pass over the body,
    /// `O((B + E) × lanes)` within its budget, and one held effect and `KeptAcross` per callee.
    fn compute(db: &Db<ProgramInputs<S>>, &(caller, thumb): &(u64, bool)) -> Self::Value {
        read_body(db, (caller, thumb), |read| {
            // Deposited before any deep read, so the row depends on what a computed row reads (ADR).
            let held = db.held::<RegisterEffects>(&(caller, thumb));
            if held.is_ok_and(|held| held.is_none()) {
                let effect = read.effect(caller);
                match db.has_read::<RegisterEffects>() {
                    true => db.defect(format_args!(
                        "register-effects {caller:#x} deposited after a row"
                    )),
                    false => db.deposit::<RegisterEffects>([((caller, thumb), effect)]),
                }
            }
            let direct = direct_calls(read.body).collect::<Vec<_>>();
            let sites = (direct.iter())
                .map(|call| (call.block, call.op))
                .collect::<Vec<_>>();
            let deep = &read.deep;
            let fates = (read.flow).site_fates(deep.lanes, &deep.effects(read.body), &sites);
            let mut calls = (direct.iter().zip(fates))
                .map(|(call, boundary)| AfterCall {
                    callee: call.callee,
                    instruction: call.instruction,
                    boundary,
                })
                .collect::<Vec<_>>();
            calls.sort_by_key(|call| (call.callee, call.instruction));
            calls.dedup_by_key(|call| (call.callee, call.instruction));
            calls.into()
        })
    }
}

/// What a body does to the registers it is entered with, by entry and whether it is Thumb
/// (doc/adr-result-side.md, section 5): no world, and its calls read shallowly, so no row reads another.
pub(super) struct RegisterEffects;

impl<S: Source + 'static> Query<ProgramInputs<S>> for RegisterEffects {
    type Key = (u64, bool);
    type Value = Option<RegisterEffect>;
    const NAME: &'static str = "register-effects";
    const RETENTION: Retention = Retention::Held;

    /// Work: one backward pass over the body and one scan of the blocks a return is reached from;
    /// `SiteFates` deposits the row of each body it walks, so only a body it did not walk is lifted here.
    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Self::Value {
        read_body(db, (entry, thumb), |read| read.effect(entry)).flatten()
    }
}

/// What a call to a body keeps: its register effect closed over each pending callee's own answer
/// (D363). A cycle, a callee with no row or another machine keeps nothing. `O(p × r / 64)` per row.
pub(super) struct KeptAcross;

impl<S: Source + 'static> Query<ProgramInputs<S>> for KeptAcross {
    type Key = (u64, bool);
    type Value = Option<r2ssa::site_boundary::Kept>;
    const NAME: &'static str = "kept-across";
    const RETENTION: Retention = Retention::Held;

    /// Work: one row, then each pending callee's answer until nothing is left; worst case the
    /// bodies a return path reaches, each lifted once.
    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Self::Value {
        let effect = db.get::<RegisterEffects>(&(entry, thumb)).ok()?;
        let effect = (*effect).as_ref()?;
        let view = View::new(db, true);
        Some(effect.closed(|callee| {
            let key = (callee, view.thumb_at(callee));
            (*db.get::<KeptAcross>(&key).ok()?).clone()
        }))
    }
}

/// One walked body as the site fates and the register effect read it: the one prefix both share.
pub(super) struct BodyRead<'a, S: Source + 'static> {
    walker: &'a super::returns::Walking<'a, S>,
    target: &'a NativeTarget<'a>,
    pub(super) body: &'a Body,
    pub(super) flow: CallerFlow<'a, BodyBlock>,
    /// Its calls read without another body, as the register effect reads them.
    shallow: Reading<'a, S>,
    /// Its calls read by each callee's register effect, as the site fates read them.
    deep: Reading<'a, S>,
}

/// The walked body at `key` with its target and flow, handed to `then`; none where it has no walk.
pub(super) fn read_body<S: Source + 'static, R>(
    db: &Db<ProgramInputs<S>>,
    (entry, thumb): (u64, bool),
    then: impl FnOnce(&BodyRead<'_, S>) -> R,
) -> Option<R> {
    let view = View::new(db, true);
    let walker = super::returns::Walking::new(view.clone(), true).ok()?;
    let target = &view.target_of(walker.machine(thumb)?, entry).ok()?;
    let slots = &*target.convention;
    let walking = db.get::<Walked>(&(entry, thumb)).ok()?;
    let body = walking.0.as_ref().ok()?.body();
    let reading = |depth| Reading {
        db,
        view: &view,
        lanes: lanes_of(target, slots),
        slots,
        unstated: r2ssa::call_reads::CallReads::every_location(&target.call),
        call: std::sync::Arc::clone(&target.call),
        depth,
    };
    Some(then(&BodyRead {
        walker: &walker,
        target,
        body,
        flow: flow_of(body, target.disasm.arch_spec().memory_endianness),
        shallow: reading(Depth::Shallow),
        deep: reading(Depth::Deep),
    }))
}

impl<'a, S: Source + 'static> BodyRead<'a, S> {
    /// The convention a call clobbers by, where its call effect is stated; none clobbers nothing.
    pub(super) fn clobbering(&self) -> Option<&'a r2source::ConventionModel> {
        let model = &*self.target.call;
        model.effect_refused().is_none().then_some(model)
    }

    /// The body's register effect, its calls read shallowly.
    fn effect(&self, entry: u64) -> Option<RegisterEffect> {
        effect_on_flow(
            &self.shallow,
            self.walker,
            self.target,
            (entry, self.body, &self.flow),
        )
    }
}

/// The register effect of the walked body at `entry` over its flow, its calls read shallowly by
/// `reading`.
fn effect_on_flow<S: Source + 'static>(
    reading: &Reading<'_, S>,
    walker: &super::returns::Walking<'_, S>,
    target: &NativeTarget<'_>,
    (entry, body, flow): (u64, &Body, &CallerFlow<'_, BodyBlock>),
) -> Option<RegisterEffect> {
    let effects = reading.effects(body);
    // Only a declared `Never` with no premise proves a call never returns; a derived one is a bound.
    let never = |block: usize, op: usize| {
        use crate::discovery::Walker;
        let declared = |callee| walker.declared(callee);
        (effects.callee_at(block, op).and_then(declared)).is_some_and(|said| said.proves_never())
    };
    // A convention whose call effect is refused keeps nothing: every register is clobbered.
    let model = target
        .call
        .effect_refused()
        .is_none()
        .then_some(&*target.call);
    let clobbers = model.map(|model| move |storage| model.clobbers(storage));
    // An import has no row, so a call to one keeps nothing without asking.
    let callee = |block: usize, op: usize| {
        let entered = effects.callee_at(block, op)?;
        crate::native::Program::import_at(reading.view, entered)
            .is_none()
            .then_some(entered)
    };
    let by = r2ssa::site_boundary::KeptBy {
        machine: target.arch,
        clobbers: (clobbers.as_ref())
            .map(|clobbers| clobbers as &dyn Fn(CanonicalStorageId) -> bool),
        never: &never,
        callee: &callee,
    };
    let effect = flow.register_effect(entry, reading.lanes, &effects, &by);
    r2il::refusal_evidence!(
        "register-effect",
        "{entry:#x}: {}",
        (effect.as_ref()).map_or("none".into(), |effect| {
            let pending = effect.pending.iter().map(|callee| format!("{callee:#x}"));
            let pending = pending.collect::<Vec<_>>().join(" ");
            let unwritten = r2ssa::site_boundary::spelled(effect.unwritten_registers());
            format!("{unwritten} pending [{pending}]")
        })
    );
    effect
}

/// The function's target under its own `CalleeConvention`; none under a row that refuses its
/// boundary (Go ABI0's stack results), whose lanes state nothing (D385, default-deny).
fn own_target<'p, S: Source + 'static>(
    view: &View<'p, S>,
    entry: u64,
    thumb: bool,
) -> Option<NativeTarget<'p>> {
    let target = view.target_of(view.machine_in(thumb)?, entry).ok()?;
    target.convention.refused.is_none().then_some(target)
}

/// The convention's result lanes: the typed three, then the rest of its return set.
fn lanes_of(target: &NativeTarget<'_>, slots: &ConventionModel) -> ResultLanes {
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

/// The argument registers a call to the import at `callee` may read, as its placed row states;
/// `None` where no row binds it, which reads every location.
pub(super) fn import_reads<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
) -> Option<Vec<CanonicalStorageId>> {
    let key = (CalleeKey::Import(ImportId(callee)), World::Open);
    let boundary = db.get::<CallBoundary>(&key).ok()?;
    match boundary.as_ref() {
        Some(CallBoundary::Import { reads }) => reads.as_ref().map(|reads| reads.registers.clone()),
        _ => None,
    }
}

/// How far a callee of the body is read for what a call to it does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    /// By the callee's held register effect.
    Deep,
    /// Inside a register effect: by what is known without another body; its calls set the count.
    Shallow,
}

/// What the calls of a body are read against: the database, the machine and the registers.
struct Reading<'a, S: Source + 'static> {
    db: &'a Db<ProgramInputs<S>>,
    view: &'a View<'a, S>,
    lanes: ResultLanes,
    slots: &'a ConventionModel,
    /// What a call to a callee nothing states may read: the convention's every location.
    unstated: r2ssa::call_reads::CallReads,
    /// What a call leaves standing under the calls' model: a format held in a preserved register.
    call: std::sync::Arc<ConventionModel>,
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
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
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
        // Asked once, only where the block fold leaves a format unknown (Gb).
        let mut seal = None;
        for (at, block) in effects.body.blocks.iter().enumerate() {
            let mut origins = r2ssa::origin::BlockOrigins::default();
            for (op, operation) in block.lifted.ops.iter().enumerate() {
                let format = (operation.is_call())
                    .then(|| effects.callee_at(at, op))
                    .flatten()
                    .and_then(|callee| formatted.get(&callee));
                let effect = format.and_then(|format| {
                    self.unfloated(&origins, format).or_else(|| {
                        let seal = seal.get_or_insert_with(|| self.convention_seal(effects.body));
                        let sealed = seal.as_deref()?;
                        let instruction = block.lifted.instruction_of(op)?;
                        let address = sealed.folded_before_call(instruction, format.register)?;
                        self.unfloated_at(address, format)
                    })
                });
                sites.extend(effect.map(|effect| ((at, op), effect)));
                origins.step_under(operation, Some(&self.call));
            }
        }
        sites
    }

    /// The caller sealed against the convention, where it seals: a spilled format reloaded in
    /// another block folds through its promoted slot, and an escaped slot stays in memory (D217).
    fn convention_seal(&self, body: &Body) -> Option<Arc<r2ssa::TrustedSeal>> {
        let key = (body.entry, self.view.thumb_at(body.entry));
        let sealing = self.db.get::<super::analysis::ConventionSeal>(&key).ok()?;
        sealing.0.as_ref().ok().cloned()
    }

    /// The call's effect without its tail vector registers, where the format at `address` is a
    /// literal the printf reader parses whole and finds no floating conversion in.
    fn unfloated_at(&self, address: u64, format: &Formatted) -> Option<CallEffect> {
        let text = crate::native::immutable_text_at(self.view, address)?;
        let consumed = r2abi::format::printf_consumed_arguments(&text).ok()?;
        (!consumed.any_floating).then_some(format.unfloated)
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
        self.unfloated_at(address, format)
    }

    /// What a call to a callee nothing is known of may take: an effect's own calls set the variadic
    /// count themselves, so only a caller counts it.
    fn unknown(&self) -> LaneBytes {
        self.unstated.takes(self.lanes, self.depth == Depth::Deep)
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
                    let (takes, counted, reads) = self.import_takes(Some(unfloated));
                    Formatted {
                        register: format.format,
                        unfloated: CallEffect {
                            takes,
                            counted,
                            overwrites: Overwrites::All,
                            kept: LaneBytes::default(),
                            reads,
                        },
                    }
                });
            let (takes, counted, reads) = self.import_takes(reads);
            let effect = CallEffect {
                takes,
                counted,
                overwrites: Overwrites::All,
                kept: LaneBytes::default(),
                reads,
            };
            return (effect, formatted);
        }
        // A row reads no other row, so one costs one pass over one body (ADR, Cost); what the call
        // keeps is the row closed over its callees' (D363).
        let key = (callee, self.view.thumb_at(callee));
        let row = (self.depth == Depth::Deep)
            .then(|| self.db.get::<RegisterEffects>(&key))
            .and_then(Result::ok);
        // A row's lane bytes are in its body's lanes; another convention's lanes read none (D385).
        let row = row.as_deref().and_then(Option::as_ref);
        let effect = match row.filter(|row| row.lanes == self.lanes) {
            Some(row) => CallEffect {
                takes: row.takes,
                counted: None,
                overwrites: Overwrites::Bytes(row.overwrites),
                kept: (self.db.get::<KeptAcross>(&key).ok())
                    .and_then(|kept| (*kept).as_ref().map(|kept| kept.kept_lanes(self.lanes)))
                    .unwrap_or_default(),
                reads: LaneBytes::default(),
            },
            None => CallEffect {
                takes: self.unknown(),
                counted: None,
                overwrites: Overwrites::Nothing,
                kept: LaneBytes::default(),
                reads: LaneBytes::default(),
            },
        };
        (effect, None)
    }

    /// What the import's placement reads, the vector registers bounded by its count register,
    /// and what it certainly reads (D228); an unbound import takes what an unknown callee does.
    fn import_takes(
        &self,
        reads: Option<r2ssa::call_reads::CallReads>,
    ) -> (LaneBytes, Option<Counted>, LaneBytes) {
        let Some(reads) = reads else {
            return (self.unknown(), None, LaneBytes::default());
        };
        let floats = self.slots.arguments(r2source::convention::SlotClass::Float);
        let overlaps = |a: &CanonicalStorageId, b: &CanonicalStorageId| {
            a.space == b.space
                && a.offset < b.offset + u64::from(b.size)
                && b.offset < a.offset + u64::from(a.size)
        };
        let Some(register) = reads.count_register else {
            let fixed = reads.stated && reads.format.is_none();
            let certain = (reads.registers.iter())
                .filter(|read| fixed && floats.iter().any(|float| overlaps(read, float)))
                .copied()
                .collect::<Vec<_>>();
            let takes = LaneBytes::covered_by(self.lanes, &reads.registers);
            return (takes, None, LaneBytes::covered_by(self.lanes, &certain));
        };
        let mut integers = (reads.registers.iter())
            .filter(|read| !floats.iter().any(|float| overlaps(read, float)))
            .copied()
            .collect::<Vec<_>>();
        // An effect's own calls set the count themselves, so only a caller's call takes it.
        if self.depth == Depth::Deep {
            integers.push(register);
        }
        let counted = Counted {
            register,
            takes: LaneBytes::covered_by(self.lanes, floats),
            stated: None,
        };
        let takes = LaneBytes::covered_by(self.lanes, &integers);
        (takes, Some(counted), LaneBytes::default())
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
    use super::{
        Authority, Dispute, JoinedLane, LANES, LaneId, Returned, Supply, disputes_of,
        forwarded_lanes,
    };
    use r2source::confidence::{Basis, Confidence};
    use r2source::{ConventionId, SourceFunctionInterface, SourceFunctionReturn};
    use r2ssa::site_boundary::ByteMask;
    use std::collections::BTreeSet;

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
    fn read_integer() -> [JoinedLane; LANES] {
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
        lanes
    }

    #[test]
    fn a_call_reading_a_lane_the_callee_overwrites_loses_to_the_declaration() {
        let found = disputes_of(Supply::of(&void(true)), &read_integer(), |_| true);
        let lost = Dispute {
            lane: LaneId::INTEGER,
            kept: Authority::Declared,
            lost: Authority::Calls,
        };
        assert_eq!(found, vec![lost]);
        let found = disputes_of(Supply::of(&void(false)), &read_integer(), |_| true);
        assert_eq!(found[0].kept, Authority::Body);
    }

    /// A declared `void` whose body's returns leave a written integer lane keeps `void`, and the
    /// body loses; a recovered interface or an open lane disputes nothing (D331).
    #[test]
    fn a_declaration_its_body_contradicts_is_kept_and_the_body_loses() {
        use r2source::{CanonicalStorageId, CanonicalStorageSpace, SourceBodyLane};
        let rax = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let body = |lane| r2source::SourceBodyResult {
            integer: Some((rax, lane)),
            float: None,
        };
        let written = void(true).with_body_result(body(SourceBodyLane::Written));
        let lost = Dispute {
            lane: LaneId::INTEGER,
            kept: Authority::Declared,
            lost: Authority::Body,
        };
        assert_eq!(super::body_disputes(&written).collect::<Vec<_>>(), [lost]);
        let open = void(true).with_body_result(body(SourceBodyLane::Open));
        assert_eq!(super::body_disputes(&open).count(), 0);
        // A declared `void` holds no result in the lane, so a lane no return defines agrees.
        let none = void(true).with_body_result(body(SourceBodyLane::None));
        assert_eq!(super::body_disputes(&none).count(), 0);
        let recovered = void(false).with_body_result(body(SourceBodyLane::Written));
        assert_eq!(super::body_disputes(&recovered).count(), 0);
        // The IPA-SRA shape: a declared register result no return defines.
        let returns = SourceFunctionReturn::Register { storage: rax };
        let int =
            SourceFunctionInterface::new(b"int".to_vec(), ConventionId::SysVAmd64, [], returns, []);
        let int = int
            .expect("an interface")
            .with_types(Confidence::of(Basis::DebugInfo));
        let dropped = int.clone().with_body_result(body(SourceBodyLane::None));
        assert_eq!(super::body_disputes(&dropped).collect::<Vec<_>>(), [lost]);
        let written = int.with_body_result(body(SourceBodyLane::Written));
        assert_eq!(super::body_disputes(&written).count(), 0);
    }

    /// A callee that leaves the lane alone hands the caller its own bytes back: no dispute.
    #[test]
    fn a_call_reading_a_lane_the_callee_leaves_alone_disputes_nothing() {
        assert!(disputes_of(Supply::of(&void(true)), &read_integer(), |_| false).is_empty());
    }

    /// A returned lane the prune does not forward is `Unknown`, never dead by omission; the lane
    /// after the float one is forwarded where a call reads the float lane (S24).
    #[test]
    fn a_lane_the_prune_does_not_forward_is_unknown_never_dead() {
        let held = JoinedLane {
            held: true,
            dead: true,
            ..JoinedLane::default()
        };
        let returned = |at: usize| Returned {
            caller: 0x2000,
            at,
            bytes: ByteMask(0xff),
        };
        // The integer lane is open, the float lane read: lanes 3 and 4 are returned on.
        let mut lanes = [held; LANES];
        lanes[0].unknown = true;
        lanes[0].dead = false;
        lanes[1].read = true;
        lanes[1].dead = false;
        let both = BTreeSet::from([returned(3), returned(4)]);
        let kept = forwarded_lanes(&mut lanes, both.clone(), Some(3));
        assert_eq!(kept, vec![returned(3)]);
        assert!(lanes[3].dead && !lanes[3].unknown, "{:?}", lanes[3]);
        assert!(lanes[4].unknown && !lanes[4].dead, "{:?}", lanes[4]);
        // No call reads or returns the float lane: neither is forwarded, and both are unknown.
        let mut lanes = [held; LANES];
        lanes[0].unknown = true;
        lanes[0].dead = false;
        assert!(forwarded_lanes(&mut lanes, both, Some(3)).is_empty());
        for at in [3, 4] {
            assert!(lanes[at].unknown && !lanes[at].dead, "{:?}", lanes[at]);
        }
    }

    /// Go 1.18: `g` compiled (ABIInternal), `mov rax, rbx; ret`, and `h` assembly (ABI0), `call g; ret`.
    fn go_bodies() -> crate::program::OpenProgram<crate::program::reads::tests::Image> {
        use crate::program::{Arch, Container, Endian, Section, SectionRole, Segment, Symbol};
        use crate::program::{Languages, Permissions, SourceLanguage, SymbolKind};
        const BASE: u64 = 0x1000;
        let mut bytes = vec![0xcc; 0x20];
        bytes[..4].copy_from_slice(&[0x48, 0x89, 0xd8, 0xc3]);
        bytes[0x10..0x16].copy_from_slice(&[0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3]);
        let function = |name: &str, vaddr| Symbol {
            name: name.into(),
            vaddr,
            size: 4,
            kind: SymbolKind::Function,
            defined: true,
            ..Symbol::default()
        };
        let container = Container {
            arch: Arch {
                name: "x86-64".to_owned(),
                bits: 64,
                endian: Endian::Little,
                instructions: None,
            },
            segments: vec![Segment {
                vaddr: BASE,
                vsize: 0x20,
                file_size: 0x20,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                ..Segment::default()
            }],
            sections: vec![Section {
                name: ".text".to_owned(),
                vaddr: BASE,
                vsize: 0x20,
                role: SectionRole::Code,
                loaded: true,
                ..Section::default()
            }],
            symbols: vec![function("main.g", BASE), function("main.h", BASE + 0x10)],
            languages: Languages {
                program: SourceLanguage::Go,
                ranges: Vec::new(),
                go_version: Some((1, 18)),
                go_assembly: Some(std::iter::once(BASE + 0x10).collect()),
            },
            ..Container::default()
        };
        let image = crate::program::reads::tests::Image {
            vaddr: BASE,
            bytes,
            container,
        };
        crate::program::OpenProgram::of(image)
    }

    /// A Go body's register effect is in its own convention's lanes (D385): ABIInternal `g` holds RBX,
    /// ABI0 `h` others. Default-deny: `h`'s refused row holds no lanes and states no site model.
    #[test]
    fn a_go_body_s_register_effect_is_in_its_own_convention_s_lanes() {
        use super::RegisterEffects;
        use crate::program::CalleeConvention;
        let open = go_bodies();
        let db = &open.db;
        let ruled = |entry| (*db.get::<CalleeConvention>(&entry).expect("held")).clone();
        assert_eq!(ruled(0x1000).map(|it| it.id), Ok(ConventionId::GoAmd64));
        assert_eq!(ruled(0x1010).map(|it| it.id), Ok(ConventionId::GoAmd64Abi0));
        let row = |entry| {
            let row = db.get::<RegisterEffects>(&(entry, false)).expect("held");
            (*row).clone().expect("a walked body has a row")
        };
        let (g, h) = (row(0x1000), row(0x1010));
        let rbx = r2source::CanonicalStorageId {
            space: r2source::CanonicalStorageSpace::Register,
            offset: 0x18,
            size: 8,
        };
        let at = g.lanes.slots().iter().position(|slot| *slot == Some(rbx));
        let at = at.expect("ABIInternal returns in rbx");
        assert!(g.takes.touches(at), "{:?}", g.takes);
        assert_ne!(h.lanes, g.lanes);
        let direct = db.get::<super::DirectSites>(&0x1000).expect("held");
        let direct = (*direct).clone().expect("g's calls are joined");
        assert!(direct.unread, "{direct:?}");
        assert!(super::held_lanes(db, 0x1010).is_none());
        let view = crate::program::View::new(db, true);
        assert!(crate::native::Program::site_convention_at(&view, 0x1010).is_none());
        let any = db
            .get::<crate::program::AnyCall>(&ConventionId::SysVAmd64)
            .expect("held");
        let any = (*any).clone().expect("joined");
        assert!(any.clobbers(rbx));
    }
}
