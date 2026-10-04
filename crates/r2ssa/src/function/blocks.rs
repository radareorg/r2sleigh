//! A function's blocks and the arena their operations' ids are minted from.
//!
//! The invariant this module makes mechanical:
//!
//! > every path that adds or removes an operation goes through the arena, so
//! > what is added is minted an id and what is removed is tombstoned.
//!
//! The vector is private to this module and its mutable paths to the
//! function module, so the compiler holds every other module to reading.
//! No fact names a revision of the blocks: facts are collected only from a
//! sealed function, whose blocks nothing changes (`super::stage`).
//! Reading is a slice, and costs nothing; rewriting an operation in place is
//! a mutable slice of blocks, which cannot change how many operations any
//! block has.

use std::collections::BTreeMap;
use std::ops::Deref;

use crate::arena::{OpArena, OpId, Pass};
use crate::block::{BlockMut, SSABlock};

use super::edit::EditPlan;

#[derive(Debug, Clone)]
pub(crate) struct Blocks<V = crate::value_table::VarId> {
    items: Vec<SSABlock<V>>,
    arena: OpArena,
}

impl<V> Default for Blocks<V> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            arena: OpArena::default(),
        }
    }
}

impl<V> Blocks<V> {
    pub(crate) fn new(items: Vec<SSABlock<V>>, arena: OpArena) -> Self {
        Self { items, arena }
    }

    /// Blocks no function has numbered yet: each is adopted into a fresh
    /// arena, in order, as though the lift emitted it.
    #[cfg(test)]
    pub(crate) fn adopting(mut items: Vec<SSABlock<V>>) -> Self {
        let mut arena = OpArena::default();
        for block in &mut items {
            block.adopt(&mut arena);
        }
        Self::new(items, arena)
    }

    /// The blocks, to be rewritten in place: no block gains or loses an
    /// operation this way. For the sealing steps that rewrite operands.
    pub(super) fn edit(&mut self) -> &mut [SSABlock<V>] {
        &mut self.items
    }

    /// One block, open for any change, with the arena that change mints
    /// from.
    pub(super) fn block_mut(&mut self, index: usize) -> Option<BlockMut<'_, V>> {
        let block = self.items.get_mut(index)?;
        Some(BlockMut::new(block, &mut self.arena))
    }

    /// Keep the blocks `keep` accepts; every operation and phi of the others
    /// is tombstoned as removed by `pass`.
    pub(super) fn retain(&mut self, pass: Pass, mut keep: impl FnMut(&SSABlock<V>) -> bool) {
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
    pub(super) fn reorder(&mut self, order: &[u64]) {
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
    pub(super) fn apply(
        &mut self,
        plan: EditPlan,
        convert: &mut impl FnMut(&crate::op::SSAOp) -> crate::op::SSAOp<V>,
    ) {
        if plan.is_empty() {
            return;
        }
        let mut block_of = vec![None; self.arena.id_limit()];
        for block in &self.items {
            for (id, _) in block.sited() {
                block_of[id.index()] = Some(block.addr);
            }
        }
        let mut edits = plan.by_block(|id: OpId| block_of.get(id.index()).copied().flatten());
        for block in &mut self.items {
            if let Some(edits) = edits.remove(&block.addr) {
                block.apply(&mut self.arena, edits, convert);
            }
        }
    }

    /// The arena every id of these blocks was minted from.
    pub(crate) const fn arena(&self) -> &OpArena {
        &self.arena
    }
}

impl<V> Deref for Blocks<V> {
    type Target = [SSABlock<V>];

    fn deref(&self) -> &[SSABlock<V>] {
        &self.items
    }
}

impl<'a, V> IntoIterator for &'a Blocks<V> {
    type Item = &'a SSABlock<V>;
    type IntoIter = std::slice::Iter<'a, SSABlock<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}
