//! One resolved body per function, as queries (doc/adr-resolved-bodies.md, P6).
//!
//! A function whose result is unproven because a callee's result is unstated is
//! resolved again against that callee resolved; members of one cycle of such
//! demands read each other as resolved alone.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::analysis::{CalleeReads, Shared, callee_read};
use super::{ProgramInputs, Source, View};
use crate::native::{CalleeRead, Unreadable};
use crate::query::db::{Db, Hold, Query};

/// A function by its entry and whether it is Thumb.
type Node = (u64, bool);

/// The cycle of result demands a function is in.
pub(super) struct Demand;

/// A component's members in address order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Members {
    pub(super) members: Vec<Node>,
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Demand {
    type Key = Node;
    type Value = Members;
    const NAME: &'static str = "demand";

    /// Tarjan's algorithm from `root` over result demands, O(V + E) over what it reaches; every component it closes is deposited.
    fn compute(db: &Db<ProgramInputs<S>>, &root: &Node) -> Members {
        let view = View::new(db, true);
        let mut search = Search::default();
        search.run(root, |node| owners(db, &view, node));
        let own = search.of[&root];
        let answers = search.closed.iter().enumerate();
        let answers = answers.filter(|(at, _)| *at != own);
        let answers = answers
            .flat_map(|(_, members)| members.members.iter().map(|node| (*node, members.clone())));
        db.deposit::<Demand>(answers.collect::<Vec<_>>());
        search.closed.swap_remove(own)
    }
}

/// The bodies whose unstated result owns this function's, resolved alone; an import's result is its declaration's.
fn owners<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    node: Node,
) -> Vec<Node> {
    let read = db
        .get::<CalleeReads>(&node)
        .expect("a read asks for no demand");
    bodies(view, &read.0)
}

/// The bodies among a read's result owners, each in the instruction set it is entered in.
fn bodies<S: Source + 'static>(view: &View<'_, S>, read: &CalleeRead) -> Vec<Node> {
    let owners = read.result_owners.iter().copied();
    let bodies = owners.filter(|owner| crate::native::Program::import_at(view, *owner).is_none());
    bodies.map(|owner| (owner, view.thumb_at(owner))).collect()
}

/// One function resolved against the resolved callees its result waits on.
pub(super) struct Resolved;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Resolved {
    type Key = Node;
    type Value = Shared<CalleeRead>;
    const NAME: &'static str = "resolved";

    /// Work: one preparation per function whose result an owner outside its demand cycle could prove.
    fn compute(db: &Db<ProgramInputs<S>>, &node: &Node) -> Shared<CalleeRead> {
        let alone = db
            .get::<CalleeReads>(&node)
            .expect("a read asks for no resolution");
        let view = View::new(db, true);
        let owners = bodies(&view, &alone.0);
        if owners.is_empty() {
            return (*alone).clone();
        }
        let cycle = db
            .get::<Demand>(&node)
            .expect("a demand asks for no resolution");
        let outside = owners
            .into_iter()
            .filter(|owner| !cycle.members.contains(owner));
        let mut resolved = Vec::new();
        for owner in outside {
            let read = db
                .get::<Resolved>(&owner)
                .expect("demands below a cycle close");
            resolved.push((owner.0, Arc::clone(&read.0)));
        }
        // An owner the request stopped decides nothing, and no answer standing on the stop is held.
        if resolved
            .iter()
            .any(|(_, read)| matches!(read.facts, Err(Unreadable::Stopped)))
        {
            return Shared(Arc::new(CalleeRead {
                interface: None,
                facts: Err(Unreadable::Stopped),
                result_owners: Default::default(),
            }));
        }
        // Resolving again pays only where some owner now states its result.
        let proves = |(_, read): &(u64, Arc<CalleeRead>)| {
            let interface = read.interface.as_ref();
            let returns = interface.map(r2source::SourceFunctionInterface::return_kind);
            read.facts.is_ok()
                && !matches!(
                    returns,
                    None | Some(r2source::SourceFunctionReturn::Unproven)
                )
        };
        if !resolved.iter().any(proves) {
            return (*alone).clone();
        }
        Shared(Arc::new(callee_read(db, node, &resolved)))
    }

    fn hold(value: &Shared<CalleeRead>) -> Hold {
        match value.0.facts {
            Err(Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
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
                if let Some(caller) = frames.last() {
                    let low = self.low[&node].min(self.low[&caller.node]);
                    self.low.insert(caller.node, low);
                }
                self.close(node);
                continue;
            };
            frame.next += 1;
            match self.index.get(&callee) {
                None => frames.push(self.open(callee, &callees)),
                Some(&index) if self.on_stack.contains(&callee) => {
                    let low = self.low[&node].min(index);
                    self.low.insert(node, low);
                }
                Some(_) => {}
            }
        }
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
        self.closed.push(Members { members });
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
