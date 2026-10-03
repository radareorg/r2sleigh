//! Edits a pass plans, applied to a function in IR order.
//!
//! A pass that adds or removes operations does not mint while it walks the
//! function: it states what it wants as an [`EditPlan`] -- replace an
//! operation, insert operations at an anchor, kill an operation -- and the
//! function applies the plan in one walk, blocks in reverse postorder and
//! operations in order. Ids are therefore minted in IR order whatever order
//! the pass found its edits in (doc/adr-stable-identity.md).
//!
//! Applying a plan is `O(n)` in the operations of the blocks it touches, plus
//! `O(e log e)` to order its edits.

use std::collections::BTreeMap;

use crate::arena::{OpId, Pass};
use crate::op::SSAOp;

/// Where an insertion goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Anchor {
    /// Before every operation of the block at this address.
    Start(u64),
    /// Immediately before this operation.
    Before(OpId),
    /// Immediately after this operation.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no pass outside tests kills or appends yet; optimize and the demand pass do in step 2 of doc/adr-stable-identity.md"
        )
    )]
    After(OpId),
}

/// One edit of a plan.
#[derive(Debug, Clone)]
enum Edit {
    /// Rewrite an operation in place: it keeps its id.
    Replace { id: OpId, op: SSAOp },
    /// Insert operations at an anchor, each derived by `pass` from the
    /// operation named beside it.
    Insert {
        at: Anchor,
        pass: Pass,
        ops: Vec<(SSAOp, Option<OpId>)>,
    },
    /// Remove an operation; its id is tombstoned.
    Kill { id: OpId, pass: Pass },
}

/// What a pass wants changed, in the order it found it.
#[derive(Debug, Clone, Default)]
pub(crate) struct EditPlan {
    edits: Vec<Edit>,
}

impl EditPlan {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    pub(crate) fn replace(&mut self, id: OpId, op: SSAOp) {
        self.edits.push(Edit::Replace { id, op });
    }

    pub(crate) fn insert(
        &mut self,
        at: Anchor,
        pass: Pass,
        ops: impl IntoIterator<Item = (SSAOp, Option<OpId>)>,
    ) {
        let ops = ops.into_iter().collect::<Vec<_>>();
        if !ops.is_empty() {
            self.edits.push(Edit::Insert { at, pass, ops });
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no pass outside tests kills or appends yet; optimize and the demand pass do in step 2 of doc/adr-stable-identity.md"
        )
    )]
    pub(crate) fn kill(&mut self, id: OpId, pass: Pass) {
        self.edits.push(Edit::Kill { id, pass });
    }
}

/// Operations inserted together by one pass, each beside the operation it
/// is derived from.
pub(crate) type Insertion = (Pass, Vec<(SSAOp, Option<OpId>)>);

/// A plan sorted for one walk of one block: what goes at its start, and what
/// happens at and around each of its operations.
#[derive(Default)]
pub(crate) struct BlockEdits {
    pub(crate) start: Vec<Insertion>,
    pub(crate) at: BTreeMap<OpId, OpEdits>,
}

#[derive(Default)]
pub(crate) struct OpEdits {
    pub(crate) before: Vec<Insertion>,
    pub(crate) replace: Option<SSAOp>,
    pub(crate) kill: Option<Pass>,
    pub(crate) after: Vec<Insertion>,
}

impl BlockEdits {
    /// The edits at and around one operation of this block.
    fn at(&mut self, id: OpId) -> &mut OpEdits {
        self.at.entry(id).or_default()
    }
}

impl EditPlan {
    /// The plan grouped by block, the block of each anchor found by
    /// `block_of`. An edit naming an operation no block holds is dropped.
    ///
    /// Edits at one anchor keep the order the pass stated them in.
    pub(crate) fn by_block(
        self,
        block_of: impl Fn(OpId) -> Option<u64>,
    ) -> BTreeMap<u64, BlockEdits> {
        let mut blocks = BTreeMap::<u64, BlockEdits>::new();
        for edit in self.edits {
            let block = match &edit {
                Edit::Replace { id, .. } | Edit::Kill { id, .. } => block_of(*id),
                Edit::Insert { at, .. } => match *at {
                    Anchor::Start(block) => Some(block),
                    Anchor::Before(id) | Anchor::After(id) => block_of(id),
                },
            };
            let Some(block) = block else {
                continue;
            };
            let edits = blocks.entry(block).or_default();
            match edit {
                Edit::Replace { id, op } => edits.at(id).replace = Some(op),
                Edit::Kill { id, pass } => edits.at(id).kill = Some(pass),
                Edit::Insert { at, pass, ops } => match at {
                    Anchor::Start(_) => edits.start.push((pass, ops)),
                    Anchor::Before(id) => edits.at(id).before.push((pass, ops)),
                    Anchor::After(id) => edits.at(id).after.push((pass, ops)),
                },
            }
        }
        blocks
    }
}
