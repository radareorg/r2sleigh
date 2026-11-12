//! One resolved body per function, as queries (doc/adr-resolved-bodies.md, P6 and P7).
//!
//! A function whose result a callee's statement could prove is resolved again against that callee
//! resolved, bottom-up over the components of those demands; under `aa`, so is one whose arity
//! a callee's could make exact; a cycle's arities and results are their least fixpoint.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2source::{
    SourceArityFloor, SourceFloorCause, SourceFunctionInterface, SourceResultCause,
    SourceResultSeed, SourceUnprovenCall, SourceUnprovenResult, SourceUnstatedCall,
};

use super::analysis::{CalleeReads, Shared, built_read, callee_built, callee_read};
use super::{ProgramInputs, Source, View};
use crate::native::{Built, CalleeRead, Stated, Unreadable};
use crate::query::db::{Db, Hold, Query, Retention};

/// A function by its entry and whether it is Thumb.
type Node = (u64, bool);

/// Which owners a resolution waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Demand {
    /// The callees whose stated result could prove a function's: every request.
    Result,
    /// Those, and the callees whose stated arity could make a floor exact: the closure over them
    /// is paid only once `aa` surveyed the program (doc/adr-resolved-bodies.md, "Arity").
    Arity,
}

/// The strongly connected component a function is in, over the edges to the owners its demand
/// names. SM's summaries reuse it (ROADMAP P7, SM).
pub(super) struct Component;

/// A component's members in address order, shared by every member's answer: O(k) for k members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Members {
    pub(super) members: std::rc::Rc<[Node]>,
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Component {
    type Key = (Node, Demand);
    type Value = Members;
    const NAME: &'static str = "component";
    const RETENTION: Retention = Retention::Held;

    /// Tarjan's algorithm from `root` over owner edges, O(V + E) over what it reaches; every component it closes is deposited.
    fn compute(db: &Db<ProgramInputs<S>>, &(root, demand): &(Node, Demand)) -> Members {
        let view = View::new(db, true);
        let mut search = Search::default();
        search.run(root, |node| owners(db, &view, node, demand));
        let own = search.of[&root];
        let closed = search.closed.into_iter().map(|members| Members { members });
        let mut closed = closed.collect::<Vec<_>>();
        let answers = closed.iter().enumerate();
        let answers = answers.filter(|(at, _)| *at != own);
        let answers = answers.flat_map(|(_, members)| {
            let each = members.members.iter();
            each.map(|node| ((*node, demand), members.clone()))
        });
        db.deposit::<Component>(answers.collect::<Vec<_>>());
        closed.swap_remove(own)
    }
}

/// The bodies whose statement could prove this function's result or arity, resolved alone; an
/// import's is its declaration's.
fn owners<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    node: Node,
    demand: Demand,
) -> Vec<Node> {
    let read = db
        .get::<CalleeReads>(&node)
        .expect("a read asks for no demand");
    bodies(view, &read.0, demand)
}

/// The bodies among the owners a read's demand names, in address order, each in the instruction
/// set it is entered in.
fn bodies<S: Source + 'static>(view: &View<'_, S>, read: &CalleeRead, demand: Demand) -> Vec<Node> {
    let arity = match demand {
        Demand::Result => BTreeSet::new(),
        Demand::Arity => arity_owners(read),
    };
    let owners = result_owners(read.interface.as_ref())
        .into_iter()
        .chain(arity);
    owned_bodies(view, owners.collect())
}

/// The bodies among `owners`, in address order, each in the instruction set it is entered in.
fn owned_bodies<S: Source + 'static>(view: &View<'_, S>, owners: BTreeSet<u64>) -> Vec<Node> {
    let owners = owners.into_iter();
    let bodies = owners.filter(|owner| crate::native::Program::import_at(view, *owner).is_none());
    bodies.map(|owner| (owner, view.thumb_at(owner))).collect()
}

/// The callees whose stated arity could make a read's floor exact: none where any cause is not a
/// call to a callee stating nothing or a floor (D37). O(causes).
fn arity_owners(read: &CalleeRead) -> BTreeSet<u64> {
    let floor = (read.interface.as_ref()).and_then(SourceFunctionInterface::arity_floor);
    let owners = floor.into_iter().flat_map(SourceArityFloor::causes);
    let owners = owners.map(|cause| match cause {
        SourceFloorCause::HandedOn(
            SourceUnprovenCall::Unstated(callee) | SourceUnprovenCall::Floor(callee),
        ) => Some(*callee),
        SourceFloorCause::HandedOn(
            SourceUnprovenCall::Indirect | SourceUnprovenCall::Stated(_),
        )
        | SourceFloorCause::UnresolvedTransfer
        | SourceFloorCause::SupervisorEntry
        | SourceFloorCause::ArgumentAreaUnplaced
        | SourceFloorCause::ArgumentAreaRead
        | SourceFloorCause::ArgumentAreaPastBudget
        | SourceFloorCause::ArgumentAreaEscapes
        | SourceFloorCause::RegisterRead
        | SourceFloorCause::Homed
        | SourceFloorCause::Unplaced(_) => None,
    });
    owners.collect::<Option<_>>().unwrap_or_default()
}

/// The callees whose stated result could prove an interface's: none where any cause is not a
/// call to a named callee (D37). O(causes).
fn result_owners(interface: Option<&SourceFunctionInterface>) -> BTreeSet<u64> {
    let unproven = interface.and_then(SourceFunctionInterface::unproven_result);
    let owners = unproven.into_iter().flat_map(SourceUnprovenResult::causes);
    let owners = owners.map(|cause| match cause {
        SourceResultCause::Returned(SourceUnstatedCall::Direct(callee))
        | SourceResultCause::Tailed(SourceUnstatedCall::Direct(callee)) => Some(*callee),
        SourceResultCause::Returned(SourceUnstatedCall::Indirect)
        | SourceResultCause::Tailed(SourceUnstatedCall::Indirect)
        | SourceResultCause::TailsDisagree
        | SourceResultCause::NoReturn
        | SourceResultCause::Clobbered
        | SourceResultCause::HandedBack
        | SourceResultCause::Ambiguous
        | SourceResultCause::Undefined
        | SourceResultCause::Written
        | SourceResultCause::Unread
        | SourceResultCause::ForwardCycle
        | SourceResultCause::LanesUnbounded
        | SourceResultCause::Unstated => None,
    });
    owners.collect::<Option<_>>().unwrap_or_default()
}

/// One function resolved against the resolved callees its result or arity waits on.
pub(super) struct Resolved;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Resolved {
    type Key = (Node, Demand);
    type Value = Shared<CalleeRead>;
    const NAME: &'static str = "resolved";
    const RETENTION: Retention = Retention::Held;

    /// Work: one preparation per function whose result or arity an owner outside its component
    /// could prove, and a cycle's arity fixpoint (`least_fixpoint`).
    fn compute(db: &Db<ProgramInputs<S>>, &(node, demand): &(Node, Demand)) -> Shared<CalleeRead> {
        // A closed seal may read a held decision; a decision never reads a closed seal.
        if demand == Demand::Arity && db.running("call-boundary") > 0 {
            db.defect(format_args!(
                "call-boundary reached resolved {:#x} at arity",
                node.0
            ));
        }
        // A register effect reads its body's lift alone (doc/adr-result-side.md, section 5).
        if db.running("register-effects") > 0 {
            db.defect(format_args!(
                "register-effects reached resolved {:#x}",
                node.0
            ));
        }
        // A result is resolved from one build of each function below it, where no cycle is known.
        if demand == Demand::Result
            && !in_held_cycle(db, node)
            && let Some(read) = built_resolved(db, node)
        {
            return read;
        }
        let alone = db
            .get::<CalleeReads>(&node)
            .expect("a read asks for no resolution");
        let view = View::new(db, true);
        let owners = bodies(&view, &alone.0, demand);
        if owners.is_empty() {
            return closed_alone(db, &view, node, &alone, demand);
        }
        let cycle = db
            .get::<Component>(&(node, demand))
            .expect("a component asks for no resolution");
        if member_owned(&alone.0, &cycle.members, demand) {
            return least_fixpoint(db, &view, &cycle.members, node, demand);
        }
        outside_resolved(db, node, &alone, &cycle.members, demand)
    }

    fn hold(value: &Shared<CalleeRead>) -> Hold {
        match value.0.facts {
            Err(Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// Whether a held component of more than one member holds `node`: its fixpoint decides it.
fn in_held_cycle<S: Source + 'static>(db: &Db<ProgramInputs<S>>, node: Node) -> bool {
    let held = db.held::<Component>(&(node, Demand::Result));
    matches!(held, Ok(Some(component)) if component.members.len() > 1)
}

/// Whether an owner's read states its result or an exact arity: what resolving again against it
/// could prove.
fn proves(read: &CalleeRead) -> bool {
    let Some(interface) = read.interface.as_ref() else {
        return false;
    };
    let returns = interface.return_kind() != r2source::SourceFunctionReturn::Unproven;
    read.facts.is_ok() && (returns || interface.arity().is_exact())
}

/// One function of the build search: built alone, the owners its build names, the next to visit.
struct Open {
    node: Node,
    built: Built,
    owners: Vec<Node>,
    next: usize,
}

/// `root`'s result from one build of each function its owners reach, or `None` where a cycle or
/// another owner set leaves it to the component (doc/adr-callee-builds.md). O(V + E) builds.
fn built_resolved<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    root: Node,
) -> Option<Shared<CalleeRead>> {
    let view = View::new(db, true);
    let key = |node| (node, Demand::Result);
    let mut answers = BTreeMap::<Node, Shared<CalleeRead>>::new();
    let mut path = Vec::<Open>::new();
    if let Some(read) = enter(db, &view, root, &mut path) {
        return Some(read);
    }
    // Terminates: each function enters the path once, and each frame visits each owner once.
    while let Some(open) = path.last_mut() {
        let owner = open.owners.get(open.next).copied();
        open.next += 1;
        let Some(owner) = owner else {
            let open = path.pop().expect("the frame just read");
            let node = open.node;
            let read = close(db, &view, open, &answers)?;
            if node == root {
                return Some(read);
            }
            held(db, node, &read);
            answers.insert(node, read);
            continue;
        };
        if answers.contains_key(&owner) {
            continue;
        }
        if path.iter().any(|open| open.node == owner) {
            r2il::refusal_evidence!(
                "resolved-build",
                "{:#x}: its owners close a cycle at {:#x}, left to the component",
                root.0,
                owner.0
            );
            return None;
        }
        // A member of a held cycle is its component's to resolve.
        let known = match in_held_cycle(db, owner) {
            true => Some(db.get::<Resolved>(&key(owner)).ok()?),
            false => db.held::<Resolved>(&key(owner)).ok().flatten(),
        };
        let read = match known {
            Some(known) => (*known).clone(),
            None => match enter(db, &view, owner, &mut path) {
                Some(read) => held(db, owner, &read),
                None => continue,
            },
        };
        answers.insert(owner, read);
    }
    None
}

/// A function's resolution found beside the root's, held unless the request stopped it.
fn held<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
    read: &Shared<CalleeRead>,
) -> Shared<CalleeRead> {
    if !stopped(&read.0) {
        db.deposit::<Resolved>([((node, Demand::Result), read.clone())]);
    }
    read.clone()
}

/// A function entering the build search: its answer where its build names no owner, else its
/// frame pushed.
fn enter<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    node: Node,
    path: &mut Vec<Open>,
) -> Option<Shared<CalleeRead>> {
    let built = match callee_built(db, node) {
        Ok(built) => built,
        Err(reason) => {
            let unread = CalleeRead {
                interface: None,
                facts: Err(reason),
            };
            return Some(alone_read(db, node, unread));
        }
    };
    let owners = owned_bodies(view, result_owners(built.interface()));
    if owners.is_empty() {
        return Some(alone_read(db, node, built_read(db, node, built, &[]).0));
    }
    path.push(Open {
        node,
        built,
        owners,
        next: 0,
    });
    None
}

/// A function's alone read, held as `CalleeReads` answers it.
fn alone_read<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
    read: CalleeRead,
) -> Shared<CalleeRead> {
    let read = Shared(Arc::new(read));
    if !stopped(&read.0) {
        db.deposit::<CalleeReads>([(node, read.clone())]);
    }
    read
}

/// A built function whose owners are all resolved: its build updated by their statements where
/// one proves something, else sealed alone. `None` where its alone read names other owners.
fn close<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    open: Open,
    answers: &BTreeMap<Node, Shared<CalleeRead>>,
) -> Option<Shared<CalleeRead>> {
    let Open {
        node,
        built,
        owners,
        ..
    } = open;
    let resolved = owners.iter().map(|owner| {
        let read = answers.get(owner).expect("every owner is visited");
        (owner.0, Arc::clone(&read.0))
    });
    let resolved = resolved.collect::<Vec<_>>();
    // An owner the request stopped decides nothing, and no answer standing on the stop is held.
    if resolved.iter().any(|(_, read)| stopped(read)) {
        return Some(stopped_read());
    }
    if !resolved.iter().any(|(_, read)| proves(read)) {
        let alone = alone_read(db, node, built_read(db, node, built, &[]).0);
        // The alone read is the first build's unless it restated text or failed past the build.
        let same = stopped(&alone.0) || bodies(view, &alone.0, Demand::Result) == owners;
        return same.then_some(alone);
    }
    let restatable = built.restatable();
    let (read, again) = built_read(db, node, built, &resolved);
    r2il::refusal_evidence!(
        "resolved-build",
        "{:#x}: resolved from its build against {} owners, restatable {restatable}",
        node.0,
        resolved.len()
    );
    // The owners a build names are its alone read's unless the alone read is another seal than
    // its build's: paid for where this resolution was, and in a debug build.
    if (again || cfg!(debug_assertions)) && !stopped(&read) {
        let alone = callee_read(db, node, Stated::default());
        if !stopped(&alone) && bodies(view, &alone, Demand::Result) != owners {
            if !again {
                db.defect(format_args!(
                    "{:#x}: its build names other owners than its alone read",
                    node.0
                ));
            }
            alone_read(db, node, alone);
            return None;
        }
    }
    Some(Shared(Arc::new(read)))
}

/// A function resolved against its owners outside its component, or alone where none of them
/// states its result or an exact arity.
fn outside_resolved<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
    alone: &Shared<CalleeRead>,
    members: &[Node],
    demand: Demand,
) -> Shared<CalleeRead> {
    let outside = bodies(&View::new(db, true), &alone.0, demand).into_iter();
    let outside = outside.filter(|owner| members.binary_search(owner).is_err());
    let mut resolved = Vec::new();
    for owner in outside {
        let read = db
            .get::<Resolved>(&(owner, demand))
            .expect("demands below a cycle close");
        resolved.push((owner.0, Arc::clone(&read.0)));
    }
    // An owner the request stopped decides nothing, and no answer standing on the stop is held.
    if resolved.iter().any(|(_, read)| stopped(read)) {
        return stopped_read();
    }
    // Resolving again pays only where some owner now states its result or an exact arity, or the
    // closed world decides it.
    if !resolved.iter().any(|(_, read)| proves(read)) {
        return closed_alone(db, &View::new(db, true), node, alone, demand);
    }
    let stated = Stated {
        owners: &resolved,
        assumed: &[],
        world: world_of(demand),
    };
    Shared(Arc::new(callee_read(db, node, stated)))
}

/// The world a demand reads results in: `aa`'s arity closure is the closed world's.
fn world_of(demand: Demand) -> super::World {
    match demand {
        Demand::Arity => super::World::Closed,
        Demand::Result => super::World::Open,
    }
}

/// A function read alone, again in the closed world where its `CallBoundary` decides its result.
fn closed_alone<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    node: Node,
    alone: &Shared<CalleeRead>,
    demand: Demand,
) -> Shared<CalleeRead> {
    let decided = (demand == Demand::Arity && alone.0.interface.is_some())
        .then(|| crate::native::Program::closed_result(view, node.0))
        .flatten();
    if decided.is_none() {
        return alone.clone();
    }
    let stated = Stated {
        owners: &[],
        assumed: &[],
        world: super::World::Closed,
    };
    Shared(Arc::new(callee_read(db, node, stated)))
}

fn stopped(read: &CalleeRead) -> bool {
    matches!(read.facts, Err(Unreadable::Stopped))
}

fn stopped_read() -> Shared<CalleeRead> {
    Shared(Arc::new(CalleeRead {
        interface: None,
        facts: Err(Unreadable::Stopped),
    }))
}

/// Whether a read's arity is a floor some member of its component owns.
fn arity_open(read: &CalleeRead, members: &[Node]) -> bool {
    arity_owners(read)
        .iter()
        .any(|owner| is_member(members, *owner))
}

/// Whether a read's result is unproven on calls some member of its component owns.
fn result_open(read: &CalleeRead, members: &[Node]) -> bool {
    result_owners(read.interface.as_ref())
        .iter()
        .any(|owner| is_member(members, *owner))
}

fn is_member(members: &[Node], owner: u64) -> bool {
    members.binary_search_by_key(&owner, |(at, _)| *at).is_ok()
}

/// Whether a read's arity or result, as `demand` asks, is one a member of its component owns.
fn member_owned(read: &CalleeRead, members: &[Node], demand: Demand) -> bool {
    result_open(read, members) || (demand == Demand::Arity && arity_open(read, members))
}

/// What a read states that a cycle's fixpoint moves: its parameters' count and whether that is a
/// floor, and, where the member's result is open, the result it states.
type State = (usize, bool, Option<Option<SourceResultSeed>>);

/// The arity and result a cycle's fixpoint assumes of a member, and the interface its callers are
/// handed.
struct Assumed {
    count: usize,
    floor: bool,
    /// Where the member's result is open: the result assumed, `None` inside being unstated, the top.
    result: Option<Option<SourceResultSeed>>,
    /// The result an untracked member states in its own right, which no member can move.
    kept: Option<SourceResultSeed>,
    interface: SourceFunctionInterface,
}

impl Assumed {
    /// What a read states: exact arity where `exact`, the seed as the result where `track`, else
    /// the result the read states of its own (nothing waits on it).
    fn of(read: &CalleeRead, exact: bool, track: bool) -> Option<Self> {
        let interface = read.interface.as_ref()?;
        let cause = interface.arity_floor().filter(|_| !exact);
        let result = track.then(|| interface.unproven_result().and_then(|r| r.seed()));
        let kept = interface.stated_result().filter(|_| !track);
        Some(Self {
            count: interface.arity().floor(),
            floor: cause.is_some(),
            result,
            kept,
            interface: interface
                .clone()
                .assumed(cause.cloned(), result.flatten().or(kept)),
        })
    }

    fn state(assumed: &Option<Self>) -> Option<State> {
        let held = assumed.as_ref()?;
        Some((held.count, held.floor, held.result))
    }

    /// What a read of a member states, as far as the member's assumption tracks it.
    fn read_state(read: &CalleeRead, tracked: bool) -> Option<State> {
        let interface = read.interface.as_ref()?;
        let arity = interface.arity();
        let result = tracked.then(|| interface.stated_result());
        Some((arity.floor(), !arity.is_exact(), result))
    }

    /// Raise an assumption to what a read of its member states; whether it moved.
    fn raise(assumed: &mut Option<Self>, read: &CalleeRead) -> bool {
        let Some(held) = assumed else {
            return false;
        };
        let Some(interface) = &read.interface else {
            *assumed = None;
            return true;
        };
        let arity = interface.arity();
        let count = arity.floor().max(held.count);
        let floor = held.floor || !arity.is_exact();
        let result = held
            .result
            .map(|seed| join(seed, interface.stated_result()));
        if (count, floor, result) == (held.count, held.floor, held.result) {
            return false;
        }
        let cause = (interface.arity_floor()).or_else(|| held.interface.arity_floor());
        let from = match arity.floor() >= held.count {
            true => interface.clone(),
            false => held.interface.clone(),
        };
        let seed = result.flatten().or(held.kept);
        let interface = from.assumed(cause.filter(|_| floor).cloned(), seed);
        *held = Self {
            count,
            floor,
            result,
            kept: held.kept,
            interface,
        };
        true
    }
}

/// The result both states: the wider of two integers in one carrier, and none where either is
/// unstated or they are not one carrier.
fn join(
    held: Option<SourceResultSeed>,
    read: Option<SourceResultSeed>,
) -> Option<SourceResultSeed> {
    let (held, read) = (held?, read?);
    (held.slot == read.slot).then(|| SourceResultSeed {
        slot: held.slot,
        bits: held.bits.max(read.bits),
        signed: held.signed && read.signed,
        above: match held.bits == read.bits && held.above == read.above {
            true => held.above,
            false => r2source::SourceAbove::Undefined,
        },
    })
}

/// A cycle's arities and results as their least fixpoint (doc/adr-resolved-bodies.md, "Arity" and
/// "A cycle's results"); the answer for `node`, the other open members' deposited.
fn least_fixpoint<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    members: &[Node],
    node: Node,
    demand: Demand,
) -> Shared<CalleeRead> {
    let mut cycle = Cycle::new(db, members, demand);
    let mut pending = (0..members.len())
        .filter(|at| cycle.open[*at])
        .collect::<BTreeSet<_>>();
    // Terminates: an assumption only rises (count, floor, none; result width, none), and each rise
    // queues its callers once: O(k + (s + 6)·E) preparations.
    while let Some(at) = pending.pop_first() {
        let Some(rose) = cycle.resolve(db, view, at) else {
            return stopped_read();
        };
        if rose {
            pending.extend(cycle.callers[at].iter().copied());
        }
    }
    let open = (0..members.len()).filter(|at| cycle.open[*at]);
    let mut answers = open.map(|at| (at, cycle.settled(at)));
    let mut answers = answers.by_ref().collect::<Vec<_>>();
    // A read below its assumption is no fixpoint: every open member keeps what it had.
    if answers.iter().any(|(_, read)| read.is_none()) {
        r2il::refusal_evidence!(
            "cycle-fixpoint",
            "a member of {:#x}'s cycle read below its assumption",
            node.0
        );
        for (at, read) in &mut answers {
            *read = Some(outside_resolved(
                db,
                members[*at],
                &cycle.alone[*at],
                members,
                demand,
            ));
        }
    }
    let mut own = None;
    let mut deposited = Vec::new();
    for (at, read) in answers {
        let read = read.expect("every open member is answered");
        match members[at] == node {
            true => own = Some(read),
            false => deposited.push(((members[at], demand), read)),
        }
    }
    db.deposit::<Resolved>(deposited);
    own.expect("the member asked for is open")
}

/// One component's least fixpoint in progress: a member whose floor or result a member owns is
/// open, seeded at what it reads alone; every other member an open one calls is stated as resolved.
struct Cycle<'m> {
    members: &'m [Node],
    demand: Demand,
    alone: Vec<Shared<CalleeRead>>,
    open: Vec<bool>,
    /// Whether an open member's result is the one it owns.
    tracked: Vec<bool>,
    assumed: Vec<Option<Assumed>>,
    /// Whether a member is stated yet: an open one from its seed, another once an open one calls it.
    stated: Vec<bool>,
    outside: Vec<Vec<(u64, Arc<CalleeRead>)>>,
    callees: Vec<Vec<usize>>,
    callers: Vec<Vec<usize>>,
    answers: Vec<Option<Shared<CalleeRead>>>,
}

impl<'m> Cycle<'m> {
    fn new<S: Source + 'static>(
        db: &Db<ProgramInputs<S>>,
        members: &'m [Node],
        demand: Demand,
    ) -> Self {
        let alone = members.iter().map(|member| {
            db.get::<CalleeReads>(member)
                .expect("a read asks for no resolution")
                .as_ref()
                .clone()
        });
        let alone = alone.collect::<Vec<_>>();
        let open = (alone.iter()).map(|read| member_owned(&read.0, members, demand));
        let open = open.collect::<Vec<_>>();
        let tracked = alone.iter().map(|read| result_open(&read.0, members));
        let tracked = tracked.collect::<Vec<_>>();
        let assumed = alone.iter().zip(&open).zip(&tracked);
        let assumed = assumed.map(|((read, open), track)| {
            let exact = demand == Demand::Arity && arity_open(&read.0, members);
            open.then(|| Assumed::of(&read.0, exact, *track)).flatten()
        });
        let k = members.len();
        Self {
            members,
            demand,
            assumed: assumed.collect(),
            stated: open.clone(),
            tracked,
            alone,
            open,
            outside: vec![Vec::new(); k],
            callees: vec![Vec::new(); k],
            callers: vec![Vec::new(); k],
            answers: vec![None; k],
        }
    }

    /// Resolve an open member against what is assumed of the members it calls: whether its
    /// assumption rose, or `None` where the request stopped.
    fn resolve<S: Source + 'static>(
        &mut self,
        db: &Db<ProgramInputs<S>>,
        view: &View<'_, S>,
        at: usize,
    ) -> Option<bool> {
        // A member's owners and callees are read at its first resolution: until then it is pending.
        if self.answers[at].is_none() {
            self.index(db, view, at)?;
        }
        let stated = self.callees[at].iter().filter_map(|callee| {
            let held = self.assumed[*callee].as_ref()?;
            Some((self.members[*callee].0, held.interface.clone()))
        });
        let stated = stated.collect::<Vec<_>>();
        // A member is read in the world of the seal that consumes it, as one read alone is.
        let stated = Stated {
            owners: &self.outside[at],
            assumed: &stated,
            world: world_of(self.demand),
        };
        let read = callee_read(db, self.members[at], stated);
        if stopped(&read) {
            return None;
        }
        let rose = Assumed::raise(&mut self.assumed[at], &read);
        self.answers[at] = Some(Shared(Arc::new(read)));
        Some(rose)
    }

    /// An open member's owners outside the component, and the members it calls, each stated.
    fn index<S: Source + 'static>(
        &mut self,
        db: &Db<ProgramInputs<S>>,
        view: &View<'_, S>,
        at: usize,
    ) -> Option<()> {
        let owners = bodies(view, &self.alone[at].0, self.demand).into_iter();
        for owner in owners.filter(|owner| self.members.binary_search(owner).is_err()) {
            let read = resolved(db, owner, self.demand)?;
            self.outside[at].push((owner.0, read.0));
        }
        // The members it calls are the callees its causes name, so no walk finds them.
        let members = self.members;
        let alone = &self.alone[at].0;
        let arity = match self.demand {
            Demand::Result => BTreeSet::new(),
            Demand::Arity => arity_owners(alone),
        };
        let named = result_owners(alone.interface.as_ref())
            .into_iter()
            .chain(arity);
        let named = named.collect::<BTreeSet<_>>().into_iter();
        let calls =
            named.filter_map(|callee| members.binary_search_by_key(&callee, |(at, _)| *at).ok());
        for callee in calls {
            self.callees[at].push(callee);
            self.callers[callee].push(at);
            if !self.stated[callee] {
                let read = resolved(db, members[callee], self.demand)?;
                self.assumed[callee] = Assumed::of(&read.0, false, false);
                self.stated[callee] = true;
            }
        }
        Some(())
    }

    /// An open member's last read where it states what was assumed of it, or `None`.
    fn settled(&self, at: usize) -> Option<Shared<CalleeRead>> {
        let read = self.answers[at]
            .clone()
            .expect("every open member is resolved");
        let state = Assumed::read_state(&read.0, self.tracked[at]);
        (state == Assumed::state(&self.assumed[at])).then_some(read)
    }
}

/// A function as `Resolved` answers it for `demand`, or `None` where the request stopped.
fn resolved<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
    demand: Demand,
) -> Option<Shared<CalleeRead>> {
    let read = db
        .get::<Resolved>(&(node, demand))
        .expect("demands below a cycle close");
    (!stopped(&read.0)).then(|| (*read).clone())
}

/// One frame of the search: a function, its callees, and the next callee to visit.
struct Frame<N> {
    node: N,
    callees: Vec<N>,
    next: usize,
}

/// Tarjan's search over any graph, by an ordered node: components close callees first.
pub(super) struct Search<N = Node> {
    index: BTreeMap<N, usize>,
    low: BTreeMap<N, usize>,
    stack: Vec<N>,
    on_stack: BTreeSet<N>,
    /// Which closed component each function is in.
    of: BTreeMap<N, usize>,
    /// Each component in the order it closed, its members ascending.
    pub(super) closed: Vec<std::rc::Rc<[N]>>,
}

impl<N> Default for Search<N> {
    fn default() -> Self {
        Self {
            index: BTreeMap::new(),
            low: BTreeMap::new(),
            stack: Vec::new(),
            on_stack: BTreeSet::new(),
            of: BTreeMap::new(),
            closed: Vec::new(),
        }
    }
}

impl<N: Copy + Ord> Search<N> {
    /// The search terminates: each function is pushed once, and each frame advances over finitely many callees.
    pub(super) fn run(&mut self, root: N, callees: impl Fn(N) -> Vec<N>) {
        let mut frames = vec![self.open(root, &callees)];
        while let Some(frame) = frames.last_mut() {
            let node = frame.node;
            let Some(&callee) = frame.callees.get(frame.next) else {
                frames.pop();
                self.finish(node, frames.last().map(|caller| caller.node));
                continue;
            };
            frame.next += 1;
            match self.index.get(&callee) {
                None => frames.push(self.open(callee, &callees)),
                Some(&index) if self.on_stack.contains(&callee) => self.lower(node, index),
                Some(_) => {}
            }
        }
    }

    /// `node` has visited every callee: its caller's low link takes its own, and it may close a component.
    fn finish(&mut self, node: N, caller: Option<N>) {
        if let Some(caller) = caller {
            self.lower(caller, self.low[&node]);
        }
        self.close(node);
    }

    /// Lower `node`'s low link to `to` where that is lower.
    fn lower(&mut self, node: N, to: usize) {
        let low = self.low[&node].min(to);
        self.low.insert(node, low);
    }

    fn open(&mut self, node: N, callees: &impl Fn(N) -> Vec<N>) -> Frame<N> {
        let index = self.index.len();
        self.index.insert(node, index);
        self.low.insert(node, index);
        self.stack.push(node);
        self.on_stack.insert(node);
        let callees = callees(node);
        Frame {
            node,
            callees,
            next: 0,
        }
    }

    /// Where `node` is the first of its component on the stack, pop the component.
    fn close(&mut self, node: N) {
        if self.low[&node] != self.index[&node] {
            return;
        }
        let at = self
            .stack
            .iter()
            .rposition(|held| *held == node)
            .expect("on the stack");
        let mut members = self.stack.split_off(at);
        members.sort_unstable();
        let id = self.closed.len();
        for member in &members {
            self.on_stack.remove(member);
            self.of.insert(*member, id);
        }
        self.closed.push(members.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components(edges: &[(u64, u64)], root: u64) -> Vec<Vec<u64>> {
        let mut search = Search::<Node>::default();
        let callees = |(at, _): Node| {
            let out = edges.iter().filter(|(from, _)| *from == at);
            out.map(|(_, to)| (*to, false)).collect()
        };
        search.run((root, false), callees);
        let closed = search.closed.iter();
        closed
            .map(|closed| closed.iter().map(|(at, _)| *at).collect())
            .collect()
    }

    /// A read whose interface is a floor of exactly `causes`.
    fn floor_of(causes: impl IntoIterator<Item = SourceFloorCause>) -> CalleeRead {
        let interface = SourceFunctionInterface::new(
            b"owners".to_vec(),
            r2source::ConventionId::SysVAmd64,
            Vec::<r2source::SourceAbiParameterSpec>::new(),
            r2source::SourceFunctionReturn::Void,
            Vec::<r2source::SourceStackSlotSpec>::new(),
        )
        .expect("an interface")
        .with_arity_floor(SourceArityFloor::of(causes).expect("some cause"));
        CalleeRead {
            interface: Some(interface),
            facts: Err(Unreadable::NotWalked),
        }
    }

    #[test]
    fn a_floor_is_owned_only_where_every_cause_is_a_call_a_callee_can_lift() {
        use SourceFloorCause::HandedOn;
        let calls = [
            HandedOn(SourceUnprovenCall::Unstated(0x10)),
            HandedOn(SourceUnprovenCall::Floor(0x20)),
        ];
        assert_eq!(arity_owners(&floor_of(calls)), BTreeSet::from([0x10, 0x20]));
        // Each cause no callee's statement lifts keeps the whole floor, whatever else is owned.
        let unliftable = [
            HandedOn(SourceUnprovenCall::Indirect),
            HandedOn(SourceUnprovenCall::Stated(0x30)),
            SourceFloorCause::UnresolvedTransfer,
            SourceFloorCause::SupervisorEntry,
            SourceFloorCause::ArgumentAreaUnplaced,
            SourceFloorCause::ArgumentAreaRead,
            SourceFloorCause::ArgumentAreaPastBudget,
            SourceFloorCause::ArgumentAreaEscapes,
            SourceFloorCause::RegisterRead,
        ];
        for cause in unliftable {
            let causes = calls.into_iter().chain([cause]);
            assert_eq!(
                arity_owners(&floor_of(causes)),
                BTreeSet::new(),
                "{cause:?}"
            );
        }
    }

    #[test]
    fn a_component_closes_after_every_component_it_calls() {
        // 1 demands 2 and 3; 2 and 4 demand each other; 3 demands itself; 4 demands 5.
        let edges = [(1, 2), (1, 3), (2, 4), (4, 2), (3, 3), (4, 5)];
        assert_eq!(
            components(&edges, 1),
            [vec![5], vec![2, 4], vec![3], vec![1]]
        );
    }
}
