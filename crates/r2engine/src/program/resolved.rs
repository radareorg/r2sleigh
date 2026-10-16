//! One resolved body per function, as queries (doc/adr-resolved-bodies.md, P6 and P7).
//!
//! A function whose result a callee's statement could prove is resolved again against that callee
//! resolved, bottom-up over the components of those demands; under `aa`, so is one whose arity
//! a callee's could make exact, and a cycle's arities are their least fixpoint.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2source::{SourceArityFloor, SourceFloorCause, SourceFunctionInterface, SourceUnprovenCall};

use super::analysis::{CalleeReads, Shared, callee_read};
use super::{ProgramInputs, Source, View};
use crate::native::{CalleeRead, Stated, Unreadable};
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
        let answers = search.closed.iter().enumerate();
        let answers = answers.filter(|(at, _)| *at != own);
        let answers = answers.flat_map(|(_, members)| {
            let each = members.members.iter();
            each.map(|node| ((*node, demand), members.clone()))
        });
        db.deposit::<Component>(answers.collect::<Vec<_>>());
        search.closed.swap_remove(own)
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
    let owners = read.owners.result.iter().chain(&arity);
    let owners = owners.copied().collect::<BTreeSet<_>>().into_iter();
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
        | SourceFloorCause::RegisterRead => None,
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
        let alone = db
            .get::<CalleeReads>(&node)
            .expect("a read asks for no resolution");
        let view = View::new(db, true);
        let owners = bodies(&view, &alone.0, demand);
        if owners.is_empty() {
            return (*alone).clone();
        }
        let cycle = db
            .get::<Component>(&(node, demand))
            .expect("a component asks for no resolution");
        if demand == Demand::Arity && member_owned(&alone.0, &cycle.members) {
            return least_fixpoint(db, &view, &cycle.members, node);
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
    // Resolving again pays only where some owner now states its result or an exact arity.
    let proves = |(_, read): &(u64, Arc<CalleeRead>)| {
        let Some(interface) = read.interface.as_ref() else {
            return false;
        };
        let returns = interface.return_kind() != r2source::SourceFunctionReturn::Unproven;
        read.facts.is_ok() && (returns || interface.arity().is_exact())
    };
    if !resolved.iter().any(proves) {
        return alone.clone();
    }
    let stated = Stated {
        owners: &resolved,
        assumed: &[],
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
        owners: Default::default(),
    }))
}

/// Whether a read's arity is a floor some member of its component owns.
fn member_owned(read: &CalleeRead, members: &[Node]) -> bool {
    let member = |owner: &u64| members.binary_search_by_key(owner, |(at, _)| *at).is_ok();
    arity_owners(read).iter().any(member)
}

/// The arity a cycle's fixpoint assumes of a member, and the interface its callers are handed;
/// `None` is unstated, the top.
struct Assumed {
    count: usize,
    floor: bool,
    interface: SourceFunctionInterface,
}

impl Assumed {
    /// What a read states; `floor` false assumes it exact.
    fn of(read: &CalleeRead, floor: bool) -> Option<Self> {
        let interface = read.interface.as_ref()?;
        let cause = interface.arity_floor().filter(|_| floor);
        Some(Self {
            count: interface.arity().floor(),
            floor: cause.is_some(),
            interface: interface.clone().assumed_arity(cause.cloned()),
        })
    }

    fn state(assumed: &Option<Self>) -> Option<(usize, bool)> {
        assumed.as_ref().map(|held| (held.count, held.floor))
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
        if (count, floor) == (held.count, held.floor) {
            return false;
        }
        let cause = (interface.arity_floor()).or_else(|| held.interface.arity_floor());
        let from = match arity.floor() >= held.count {
            true => interface.clone(),
            false => held.interface.clone(),
        };
        *held = Self {
            count,
            floor,
            interface: from.assumed_arity(cause.filter(|_| floor).cloned()),
        };
        true
    }
}

/// A cycle's arities as their least fixpoint (doc/adr-resolved-bodies.md, "Arity"); the answer
/// for `node`, the other open members' deposited.
fn least_fixpoint<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    members: &[Node],
    node: Node,
) -> Shared<CalleeRead> {
    let mut cycle = Cycle::new(db, members);
    let mut pending = (0..members.len())
        .filter(|at| cycle.open[*at])
        .collect::<BTreeSet<_>>();
    // Terminates: an assumption only rises, its count bounded by the slots its body can read, then
    // a floor, then unstated; each rise queues its callers once: O(k + (s + 2)·E) preparations.
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
    // A read below its assumption is no fixpoint: every open member keeps the floor it had.
    if answers.iter().any(|(_, read)| read.is_none()) {
        r2il::refusal_evidence!(
            "arity-fixpoint",
            "a member of {:#x}'s cycle read below its assumed arity",
            node.0
        );
        for (at, read) in &mut answers {
            *read = Some(outside_resolved(
                db,
                members[*at],
                &cycle.alone[*at],
                members,
                Demand::Arity,
            ));
        }
    }
    let mut own = None;
    let mut deposited = Vec::new();
    for (at, read) in answers {
        let read = read.expect("every open member is answered");
        match members[at] == node {
            true => own = Some(read),
            false => deposited.push(((members[at], Demand::Arity), read)),
        }
    }
    db.deposit::<Resolved>(deposited);
    own.expect("the member asked for is open")
}

/// One component's least fixpoint in progress: a member whose floor a member owns is open, seeded
/// exact at what it reads alone; every other member an open one calls is stated as resolved.
struct Cycle<'m> {
    members: &'m [Node],
    alone: Vec<Shared<CalleeRead>>,
    open: Vec<bool>,
    assumed: Vec<Option<Assumed>>,
    /// Whether a member is stated yet: an open one from its seed, another once an open one calls it.
    stated: Vec<bool>,
    outside: Vec<Vec<(u64, Arc<CalleeRead>)>>,
    callees: Vec<Vec<usize>>,
    callers: Vec<Vec<usize>>,
    answers: Vec<Option<Shared<CalleeRead>>>,
}

impl<'m> Cycle<'m> {
    fn new<S: Source + 'static>(db: &Db<ProgramInputs<S>>, members: &'m [Node]) -> Self {
        let alone = members.iter().map(|member| {
            db.get::<CalleeReads>(member)
                .expect("a read asks for no resolution")
                .as_ref()
                .clone()
        });
        let alone = alone.collect::<Vec<_>>();
        let open = alone.iter().map(|read| member_owned(&read.0, members));
        let open = open.collect::<Vec<_>>();
        let assumed = alone.iter().zip(&open);
        let assumed =
            assumed.map(|(read, open)| open.then(|| Assumed::of(&read.0, false)).flatten());
        let k = members.len();
        Self {
            members,
            assumed: assumed.collect(),
            stated: open.clone(),
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
        let stated = Stated {
            owners: &self.outside[at],
            assumed: &stated,
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
        let owners = bodies(view, &self.alone[at].0, Demand::Arity).into_iter();
        for owner in owners.filter(|owner| self.members.binary_search(owner).is_err()) {
            let read = resolved(db, owner)?;
            self.outside[at].push((owner.0, read.0));
        }
        // The members it calls are the callees its floor's causes name, so no walk finds them.
        let members = self.members;
        let named = arity_owners(&self.alone[at].0).into_iter();
        let calls =
            named.filter_map(|callee| members.binary_search_by_key(&callee, |(at, _)| *at).ok());
        for callee in calls {
            self.callees[at].push(callee);
            self.callers[callee].push(at);
            if !self.stated[callee] {
                self.assumed[callee] = Assumed::of(&resolved(db, members[callee])?.0, true);
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
        let state = Assumed::state(&Assumed::of(&read.0, true));
        (state == Assumed::state(&self.assumed[at])).then_some(read)
    }
}

/// A function as `Resolved` answers it under `aa`, or `None` where the request stopped.
fn resolved<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
) -> Option<Shared<CalleeRead>> {
    let read = db
        .get::<Resolved>(&(node, Demand::Arity))
        .expect("demands below a cycle close");
    (!stopped(&read.0)).then(|| (*read).clone())
}

/// One frame of the search: a function, its callees, and the next callee to visit.
struct Frame {
    node: Node,
    callees: Vec<Node>,
    next: usize,
}

#[derive(Default)]
struct Search {
    index: BTreeMap<Node, usize>,
    low: BTreeMap<Node, usize>,
    stack: Vec<Node>,
    on_stack: BTreeSet<Node>,
    /// Which closed component each function is in.
    of: BTreeMap<Node, usize>,
    closed: Vec<Members>,
}

impl Search {
    /// The search terminates: each function is pushed once, and each frame advances over finitely many callees.
    fn run(&mut self, root: Node, callees: impl Fn(Node) -> Vec<Node>) {
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
    fn finish(&mut self, node: Node, caller: Option<Node>) {
        if let Some(caller) = caller {
            self.lower(caller, self.low[&node]);
        }
        self.close(node);
    }

    /// Lower `node`'s low link to `to` where that is lower.
    fn lower(&mut self, node: Node, to: usize) {
        let low = self.low[&node].min(to);
        self.low.insert(node, low);
    }

    fn open(&mut self, node: Node, callees: &impl Fn(Node) -> Vec<Node>) -> Frame {
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
    fn close(&mut self, node: Node) {
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
        self.closed.push(Members {
            members: members.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components(edges: &[(u64, u64)], root: u64) -> Vec<Vec<u64>> {
        let mut search = Search::default();
        let callees = |(at, _): Node| {
            let out = edges.iter().filter(|(from, _)| *from == at);
            out.map(|(_, to)| (*to, false)).collect()
        };
        search.run((root, false), callees);
        let closed = search.closed.iter();
        closed
            .map(|closed| closed.members.iter().map(|(at, _)| *at).collect())
            .collect()
    }

    /// A read whose interface is a floor of exactly `causes`.
    fn floor_of(causes: impl IntoIterator<Item = SourceFloorCause>) -> CalleeRead {
        let interface = SourceFunctionInterface::new(
            b"owners".to_vec(),
            "sysv",
            Vec::<r2source::SourceAbiParameterSpec>::new(),
            r2source::SourceFunctionReturn::Void,
            Vec::<r2source::SourceStackSlotSpec>::new(),
        )
        .expect("an interface")
        .with_arity_floor(SourceArityFloor::of(causes).expect("some cause"));
        CalleeRead {
            interface: Some(interface),
            facts: Err(Unreadable::NotWalked),
            owners: Default::default(),
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
