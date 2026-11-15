//! The survey's call graph condensed once: each body's rank, callee first (doc/adr-result-side.md,
//! "Relift order").

use std::sync::Arc;

use r2ssa::dense::{Condensation, Csr, DenseId, Node};

use super::requests::{Survey, SurveyQuery};
use super::{ProgramInputs, Source};
use crate::query::db::{Db, Query, Retention};

/// Each body the survey's calls and tail branches join, with its component and finish index.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Ranks {
    /// The bodies, ascending: a body's node is its place here.
    entries: Vec<u64>,
    /// Over caller-to-callee edges, successors ascending: a component closes after every one it calls.
    condensation: Condensation<Node>,
}

impl Ranks {
    /// `O(F + E)` for the search, `O(E log E)` to number and sort the edges.
    fn of(survey: &Survey) -> Self {
        let mut edges = survey.call_edges().collect::<Vec<_>>();
        edges.sort_unstable();
        edges.dedup();
        let mut entries = (edges.iter())
            .flat_map(|&(caller, callee)| [caller, callee])
            .collect::<Vec<_>>();
        entries.sort_unstable();
        entries.dedup();
        let node = |entry: u64| match entries.binary_search(&entry) {
            Ok(at) => Node::from_index(at),
            Err(_) => unreachable!("every edge's ends are numbered"),
        };
        let pairs = (edges.iter()).map(|&(caller, callee)| (node(caller), node(callee)));
        let successors = Csr::from_pairs(entries.len(), pairs.collect::<Vec<_>>());
        let condensation = Condensation::of(&successors, []);
        Self {
            entries,
            condensation,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The node of a body some call or tail branch joins; none for a body no edge names.
    pub(super) fn node(&self, entry: u64) -> Option<Node> {
        self.entries
            .binary_search(&entry)
            .ok()
            .map(Node::from_index)
    }

    /// The order the callers-first read pops a body in: its component (callee first), then its finish
    /// index, then its address.
    pub(super) fn order(&self, node: Node) -> (u32, u32, u64) {
        let component = self.condensation.component(node).0;
        (
            component,
            self.condensation.finish(node),
            self.entries[node.index()],
        )
    }

    /// Nodes entered plus edges followed by the one search.
    pub(super) fn visits(&self) -> u64 {
        self.condensation.visits()
    }
}

/// The survey's call graph condensed, a program-wide index computed once under `aa`.
pub(super) struct CallRanks;

impl<S: Source + 'static> Query<ProgramInputs<S>> for CallRanks {
    type Key = ();
    type Value = Option<Arc<Ranks>>;
    const NAME: &'static str = "call-ranks";
    const RETENTION: Retention = Retention::Held;

    /// Work: one condensation, `O(F + E)`, after sorting the `E` edges.
    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let survey = db.get::<SurveyQuery>(&()).ok()?;
        let survey = survey.as_ref().as_ref().ok()?;
        let ranks = Ranks::of(&survey.0);
        db.note_condensed(ranks.visits());
        Some(Arc::new(ranks))
    }
}
