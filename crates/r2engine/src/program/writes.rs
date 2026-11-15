//! What a call to a walked body may write of its caller's stack, composed over the direct calls
//! its alone read leaves unstated (doc/adr-callee-builds.md, "D441 as built").

use r2ssa::call_reads::{StackWrites, WritesBound};
use r2ssa::dense::{DenseId, Node as Dense, Reached};

use super::analysis::CalleeReads;
use super::{ProgramInputs, Source, View};
use crate::native::Unreadable;
use crate::query::db::{Db, Hold, Query, Retention};

/// A function by its entry and whether it is Thumb.
type Node = (u64, bool);

/// One body's incoming writes over its write-blocking calls, each component of the write-dependence
/// graph solved once against `cycle_seed` (D441). Asked by D376's asks and the `aa` root only.
pub(super) struct IncomingWrites;

/// The composed writes, `None` where nothing bounds them, and whether the answer is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Composed {
    pub(super) writes: Option<StackWrites>,
    hold: Kept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kept {
    Held,
    /// A read met a query cycle, which depends on where it was entered.
    Transient,
    Stopped,
}

/// One body's alone read: its writes solved, the bound its blocking calls wait on, or how the read
/// failed to state either.
enum Alone {
    Solved(Option<StackWrites>),
    Blocked(WritesBound),
    Unheld(Kept),
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for IncomingWrites {
    type Key = Node;
    type Value = Composed;
    const NAME: &'static str = "incoming-writes";
    const RETENTION: Retention = Retention::Held;

    /// One condensation of what `root`'s blocking calls reach, O(V + E), held answers its leaves;
    /// each component solved once, callee first, O(calls x spans log spans) per member.
    fn compute(db: &Db<ProgramInputs<S>>, &root: &Node) -> Composed {
        let view = View::new(db, true);
        let edges = |node: Node| match held(db, node, root) {
            Some(_) => Vec::new(),
            None => match alone(db, node) {
                Alone::Blocked(bound) => blocking(&view, &bound),
                _ => Vec::new(),
            },
        };
        let reached = Reached::from(root, edges);
        let condensation = reached.condensation();
        db.note_condensed(condensation.visits());
        let count = reached.successors().len();
        let keys = (0..count)
            .map(|at| reached.key(Dense::from_index(at)))
            .collect::<Vec<_>>();
        let mut answers = vec![None::<StackWrites>; count];
        let mut kept = Kept::Held;
        let mut solved = Vec::new();
        for (component, members) in condensation.components() {
            if let [only] = members
                && let Some(known) = held(db, keys[only.index()], root)
            {
                answers[only.index()].clone_from(&known.writes);
                continue;
            }
            let bounds = members
                .iter()
                .map(|member| match alone(db, keys[member.index()]) {
                    Alone::Solved(writes) => Err(writes),
                    Alone::Blocked(bound) => Ok(bound),
                    Alone::Unheld(why) => {
                        kept = kept.max(why);
                        Err(None)
                    }
                });
            let bounds = bounds.collect::<Vec<_>>();
            let cyclic = condensation.is_cyclic(component);
            let computed = solved_component(&view, (&keys, &answers), members, &bounds, cyclic);
            for (member, writes) in members.iter().zip(computed) {
                answers[member.index()] = writes;
                solved.push(*member);
            }
        }
        let own = reached.root().index();
        if kept == Kept::Held {
            let others = solved.into_iter().filter(|node| node.index() != own);
            let others = others.map(|node| {
                let writes = answers[node.index()].clone();
                let hold = Kept::Held;
                (keys[node.index()], Composed { writes, hold })
            });
            db.deposit::<Self>(others.collect::<Vec<_>>());
        }
        Composed {
            writes: answers[own].clone(),
            hold: kept,
        }
    }

    fn hold(value: &Composed) -> Hold {
        match value.hold {
            Kept::Held => Hold::Held,
            Kept::Transient => Hold::Transient,
            Kept::Stopped => Hold::Stopped,
        }
    }
}

impl Kept {
    /// The weaker of two: a stop outranks a cycle, which outranks a held answer.
    fn max(self, other: Self) -> Self {
        match (self, other) {
            (Self::Stopped, _) | (_, Self::Stopped) => Self::Stopped,
            (Self::Transient, _) | (_, Self::Transient) => Self::Transient,
            _ => Self::Held,
        }
    }
}

/// A component's writes, member by member: an acyclic one's from its callees solved below it; a
/// cycle's only where every member, assumed to write `cycle_seed`, computes that seed, else none.
fn solved_component<S: Source + 'static>(
    view: &View<'_, S>,
    (keys, answers): (&[Node], &[Option<StackWrites>]),
    members: &[Dense],
    bounds: &[Result<WritesBound, Option<StackWrites>>],
    cyclic: bool,
) -> Vec<Option<StackWrites>> {
    let seed = StackWrites::cycle_seed();
    let stated = |target: u64| {
        let key = (target, view.thumb_at(target));
        let at = keys.binary_search(&key).ok()?;
        match cyclic && members.binary_search(&Dense::from_index(at)).is_ok() {
            true => seed.spans(),
            false => answers[at].as_ref()?.spans(),
        }
    };
    let computed = bounds.iter().map(|bound| match bound {
        Ok(bound) => bound.solve(stated),
        Err(solved) => solved.clone(),
    });
    let computed = computed.collect::<Vec<_>>();
    if !cyclic {
        return computed;
    }
    let holds =
        |writes: &Option<StackWrites>| writes.as_ref().and_then(StackWrites::spans) == seed.spans();
    match computed.iter().all(holds) {
        true => computed,
        false => {
            r2il::refusal_evidence!(
                "incoming-writes",
                "a write cycle of {} members computes other writes than its seed",
                members.len()
            );
            vec![None; members.len()]
        }
    }
}

/// A body's answer where held, never the root's own.
fn held<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    node: Node,
    root: Node,
) -> Option<std::rc::Rc<Composed>> {
    (node != root)
        .then(|| db.held::<IncomingWrites>(&node).ok().flatten())
        .flatten()
}

/// A body's bound as its alone read states it.
fn alone<S: Source + 'static>(db: &Db<ProgramInputs<S>>, node: Node) -> Alone {
    let Ok(read) = db.get::<CalleeReads>(&node) else {
        return Alone::Unheld(Kept::Transient);
    };
    match &read.0.facts {
        Ok(facts) => match facts.summary().incoming_bound() {
            Some(bound) => Alone::Blocked(bound.clone()),
            None => Alone::Solved(facts.summary().incoming_writes().cloned()),
        },
        Err(Unreadable::Stopped) => Alone::Unheld(Kept::Stopped),
        Err(_) => Alone::Solved(None),
    }
}

/// The bodies a bound's blocking calls go to, each in the instruction set it is entered in; an
/// import has no body, so its call stays unstated.
fn blocking<S: Source + 'static>(view: &View<'_, S>, bound: &WritesBound) -> Vec<Node> {
    let targets = bound.blocking().into_iter();
    let bodies =
        targets.filter(|target| crate::native::Program::import_at(view, *target).is_none());
    bodies
        .map(|target| (target, view.thumb_at(target)))
        .collect()
}
