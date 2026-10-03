//! A function's blocks, the arena their operations' ids are minted from, and
//! the revision of them every derived fact names.
//!
//! Facts are computed from the blocks and then read while the blocks go on
//! being rewritten: entry lanes are minted, copies forwarded, boundary
//! constants placed. A fact computed before a rewrite and read after it
//! answers for an IR that no longer exists -- the value view did, and one bit
//! identity had two answers. The invariants this module makes mechanical:
//!
//! > every mutable path to the blocks advances the revision, so a fact stamped
//! > with the revision it was computed at can say whether it still describes
//! > them;
//! >
//! > every path that adds or removes an operation goes through the arena, so
//! > what is added is minted an id and what is removed is tombstoned.
//!
//! The vector is private to this module, so the compiler holds every other
//! module to these paths. Reading is a slice, and costs nothing; rewriting an
//! operation in place is a mutable slice of blocks, which cannot change how
//! many operations any block has.

use std::collections::BTreeMap;
use std::ops::Deref;

use crate::arena::{OpArena, OpId, Pass};
use crate::block::{BlockMut, SSABlock};

use super::edit::EditPlan;

#[derive(Debug, Clone, Default)]
pub(crate) struct Blocks {
    items: Vec<SSABlock>,
    arena: OpArena,
    revision: IrRevision,
}

/// How many times a function's blocks have been opened for change.
///
/// Opaque outside this crate: a fact can carry one, and only the blocks can
/// make one, so no fact claims a revision it was not computed at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrRevision(u64);

impl Blocks {
    pub(crate) fn new(items: Vec<SSABlock>, arena: OpArena) -> Self {
        Self {
            items,
            arena,
            revision: IrRevision::default(),
        }
    }

    /// Blocks no function has numbered yet: each is adopted into a fresh
    /// arena, in order, as though the lift emitted it.
    #[cfg(test)]
    pub(crate) fn adopting(mut items: Vec<SSABlock>) -> Self {
        let mut arena = OpArena::default();
        for block in &mut items {
            block.adopt(&mut arena);
        }
        Self::new(items, arena)
    }

    /// The blocks, to be rewritten in place: no block gains or loses an
    /// operation this way. The revision moves whether or not the caller ends
    /// up changing anything, which errs towards a fact being refreshed.
    pub(crate) fn edit(&mut self) -> &mut [SSABlock] {
        self.revision.0 += 1;
        &mut self.items
    }

    /// One block, open for any change, with the arena that change mints
    /// from.
    pub(crate) fn block_mut(&mut self, index: usize) -> Option<BlockMut<'_>> {
        self.revision.0 += 1;
        let block = self.items.get_mut(index)?;
        Some(BlockMut::new(block, &mut self.arena))
    }

    /// Keep the blocks `keep` accepts; every operation and phi of the others
    /// is tombstoned as removed by `pass`.
    pub(crate) fn retain(&mut self, pass: Pass, mut keep: impl FnMut(&SSABlock) -> bool) {
        self.revision.0 += 1;
        let arena = &mut self.arena;
        self.items.retain(|block| {
            let kept = keep(block);
            if !kept {
                block.kill_all(arena, pass);
            }
            kept
        });
    }

    /// Put the blocks in the order of `order`; a block it does not name is
    /// left out, as [`Self::retain`] leaves it.
    pub(crate) fn reorder(&mut self, order: &[u64]) {
        let named = order
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        self.retain(Pass::RemoveBlock, |block| named.contains(&block.addr));
        let mut by_addr = std::mem::take(&mut self.items)
            .into_iter()
            .map(|block| (block.addr, block))
            .collect::<BTreeMap<_, _>>();
        self.items = order
            .iter()
            .filter_map(|addr| by_addr.remove(addr))
            .collect();
    }

    /// Apply a pass's plan: blocks in the order they stand (reverse
    /// postorder), operations in order, so ids are minted in IR order.
    ///
    /// `O(n)` to find which block holds each operation, then one walk of each
    /// block the plan touches.
    pub(crate) fn apply(&mut self, plan: EditPlan) {
        if plan.is_empty() {
            return;
        }
        self.revision.0 += 1;
        let mut block_of = vec![None; self.arena.id_limit()];
        for block in &self.items {
            for (id, _) in block.sited() {
                block_of[id.index()] = Some(block.addr);
            }
        }
        let mut edits = plan.by_block(|id: OpId| block_of.get(id.index()).copied().flatten());
        for block in &mut self.items {
            if let Some(edits) = edits.remove(&block.addr) {
                block.apply(&mut self.arena, edits);
            }
        }
    }

    /// The arena every id of these blocks was minted from.
    pub(crate) const fn arena(&self) -> &OpArena {
        &self.arena
    }

    /// How many times the blocks have been opened for change.
    pub(crate) const fn revision(&self) -> IrRevision {
        self.revision
    }
}

impl Deref for Blocks {
    type Target = [SSABlock];

    fn deref(&self) -> &[SSABlock] {
        &self.items
    }
}

impl<'a> IntoIterator for &'a Blocks {
    type Item = &'a SSABlock;
    type IntoIter = std::slice::Iter<'a, SSABlock>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_keeps_the_revision_and_opening_for_change_moves_it() {
        let mut blocks = Blocks::new(Vec::new(), OpArena::default());
        assert_eq!(blocks.len(), 0);
        assert_eq!(blocks.revision(), IrRevision(0));
        blocks.edit();
        assert_eq!(blocks.revision(), IrRevision(1));
    }
}
