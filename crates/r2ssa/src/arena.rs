//! Stable operation identity: one id per operation for the function's life.
//!
//! A position -- a block address and an index into its operations -- moves
//! whenever a pass inserts or removes an operation in front of it, so a fact
//! keyed by position stops naming the operation it was taken from at the
//! first edit (doc/adr-stable-identity.md). The invariant this module makes
//! mechanical:
//!
//! > every operation and every phi of a function holds an [`OpId`] minted from
//! > one per-function counter; the id never changes while the operation lives,
//! > and is never handed to another operation after it dies.
//!
//! The arena only grows. Minting appends a slot recording where the operation
//! came from ([`OpOrigin`]); removing one turns its slot into a tombstone that
//! keeps that origin and names the pass that removed it. Lookup is an index,
//! O(1); a function's arena costs one slot per operation it ever held.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One operation of one function, by identity rather than by position.
///
/// Dense: an index into the function's [`OpArena`]. Phis and operations
/// draw from the same counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpId(u32);

impl OpId {
    /// The slot this id indexes.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl crate::dense::DenseId for OpId {
    fn index(self) -> usize {
        self.0 as usize
    }
    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 operations"))
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The pass that minted an operation the lift never had, or removed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pass {
    /// Phi placement: a merge of the values reaching a block.
    PhiPlacement,
    /// Renaming: lane projections and inserts around a register-family
    /// access, and the carrier reads, clobbers and restore around a call.
    Rename,
    /// The zero a scratch insert root is entered with.
    ScratchZero,
    /// Entry-lane projections and the roots rebuilt from them.
    EntryLanes,
    /// A compare chain fused into one switch, its links' values hoisted.
    FuseCompareChain,
    /// A block removed from the function.
    RemoveBlock,
    /// The decompiler materialising a phi as copies on its incoming edges.
    PhiMaterialization,
    /// The decompiler relocating an entity's initializer.
    RelocateInitializer,
    /// A test fixture writing a block by hand.
    Fixture,
}

/// Where an operation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpOrigin {
    /// The lift emitted it: operation `index` of the lifted basic block at
    /// `block`, executed for the machine instruction at `instruction` when
    /// the lifter stamped one.
    Lifted {
        block: u64,
        index: usize,
        instruction: Option<u64>,
    },
    /// A pass added it, on behalf of the operation `from` when there is one.
    ///
    /// A phi, an entry lane and a scratch zero stand for no operation of the
    /// program, so they have none; everything else a pass adds is emitted
    /// for one operation, whose instruction it executes for.
    Derived { from: Option<OpId>, pass: Pass },
}

/// One slot of the arena: an operation that lives, or the tombstone of one
/// that was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpSlot {
    Live(OpOrigin),
    Dead { origin: OpOrigin, by: Pass },
}

impl OpSlot {
    pub const fn origin(&self) -> &OpOrigin {
        match self {
            Self::Live(origin) | Self::Dead { origin, .. } => origin,
        }
    }

    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }
}

/// Every operation one function ever held, by id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpArena {
    slots: Vec<OpSlot>,
}

impl OpArena {
    /// A new id for an operation from `origin`.
    pub(crate) fn mint(&mut self, origin: OpOrigin) -> OpId {
        let id = OpId(u32::try_from(self.slots.len()).expect("fewer than 2^32 operations"));
        self.slots.push(OpSlot::Live(origin));
        id
    }

    /// Mark an operation removed by `by`. Its id is never minted again.
    pub(crate) fn kill(&mut self, id: OpId, by: Pass) {
        if let Some(slot) = self.slots.get_mut(id.index())
            && let OpSlot::Live(origin) = *slot
        {
            *slot = OpSlot::Dead { origin, by };
        }
    }

    /// One more than the largest id minted so far: the length a dense map
    /// indexed by [`OpId`] needs.
    pub fn id_limit(&self) -> usize {
        self.slots.len()
    }

    pub fn slot(&self, id: OpId) -> Option<&OpSlot> {
        self.slots.get(id.index())
    }

    pub fn origin(&self, id: OpId) -> Option<&OpOrigin> {
        self.slot(id).map(OpSlot::origin)
    }

    /// Which machine instruction an operation executes for: its own when the
    /// lift emitted it, and that of the operation it was derived from
    /// otherwise.
    ///
    /// A derivation names an older id, so the walk ends; it is one or two
    /// steps in practice.
    pub fn instruction(&self, id: OpId) -> Option<u64> {
        let mut at = id;
        loop {
            match self.origin(at)? {
                OpOrigin::Lifted { instruction, .. } => return *instruction,
                OpOrigin::Derived { from, .. } => at = (*from)?,
            }
        }
    }

    /// Every slot, in id order.
    pub fn slots(&self) -> impl Iterator<Item = (OpId, &OpSlot)> {
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| (OpId(index as u32), slot))
    }
}

/// Ids for operations a block numbers by itself, before any function adopts
/// it: a block built one instruction at a time, or by a test.
pub(crate) const fn local_id(index: usize) -> OpId {
    OpId(index as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_never_reused_and_a_tombstone_keeps_its_origin() {
        let mut arena = OpArena::default();
        let lifted = OpOrigin::Lifted {
            block: 0x1000,
            index: 0,
            instruction: Some(0x1000),
        };
        let first = arena.mint(lifted);
        let lane = arena.mint(OpOrigin::Derived {
            from: Some(first),
            pass: Pass::Rename,
        });
        assert_eq!(arena.instruction(lane), Some(0x1000));
        arena.kill(first, Pass::RemoveBlock);
        let next = arena.mint(OpOrigin::Derived {
            from: None,
            pass: Pass::EntryLanes,
        });
        assert_ne!(next, first);
        assert_eq!(next.index(), 2);
        assert_eq!(
            arena.slot(first),
            Some(&OpSlot::Dead {
                origin: lifted,
                by: Pass::RemoveBlock
            })
        );
        // A dead operation's derivations still know their instruction.
        assert_eq!(arena.instruction(lane), Some(0x1000));
        assert_eq!(arena.instruction(next), None);
    }
}
