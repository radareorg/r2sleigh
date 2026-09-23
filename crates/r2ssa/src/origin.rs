//! What a value is, read forward from the start of one block.
//!
//! Several questions turn out to be this one question. A terminal indirect
//! branch asks which RAM slot its target was loaded from; an import stub asks
//! which slot it reads; a listing asks whether the address an instruction
//! loads from folds to a constant. Each was answered by its own walk over the
//! same operations, so this is that walk, once, with a name.
//!
//! The pass is `O(n log s)` for `n` operations and `s` distinct storages.
//! An operation this pass does not model clears its destination, so an older
//! origin can never survive a clobber and become false evidence.

use crate::{CanonicalStorageId, CanonicalStorageSpace};
use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};
use std::collections::BTreeMap;

/// Where a value came from, as far as one block's own operations show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueOrigin {
    /// A number the block computed, truncated to the width that holds it.
    Constant { value: u64, size: u32 },
    /// A memory slot whose contents the block loaded and has not since changed.
    LoadedSlot(CanonicalStorageId),
}

impl ValueOrigin {
    /// The number, where this origin is one.
    pub fn constant(self) -> Option<u64> {
        match self {
            Self::Constant { value, .. } => Some(value),
            Self::LoadedSlot(_) => None,
        }
    }

    /// The slot, where the value is what was read out of memory.
    ///
    /// A slot of no width, or one that runs off the end of the address space,
    /// names nothing readable and is refused here rather than by each caller.
    pub fn loaded_slot(self) -> Option<CanonicalStorageId> {
        match self {
            Self::LoadedSlot(slot)
                if slot.space == CanonicalStorageSpace::Ram
                    && slot.size != 0
                    && slot.offset.checked_add(u64::from(slot.size)).is_some() =>
            {
                Some(slot)
            }
            Self::Constant { .. } | Self::LoadedSlot(_) => None,
        }
    }
}

/// The address a transfer operation encodes, where it encodes one.
///
/// A branch target is not a value to be read: the varnode *is* the address,
/// whether Sleigh spells it in the constant space or the code space. That is
/// the one place a RAM varnode means its own offset rather than what is stored
/// there, so it is asked for separately from what a value holds.
pub fn encoded_target(target: &Varnode) -> Option<u64> {
    matches!(target.space, SpaceId::Const | SpaceId::Ram).then_some(target.offset)
}

/// What every storage holds at one point in a block.
#[derive(Debug, Default, Clone)]
pub struct BlockOrigins {
    origins: BTreeMap<CanonicalStorageId, ValueOrigin>,
}

impl BlockOrigins {
    /// Read forward over a block's first `ops` operations.
    pub fn upto(block: &R2ILBlock, ops: usize) -> Self {
        let mut state = Self::default();
        for op in block.ops.iter().take(ops) {
            state.step(op);
        }
        state
    }

    /// Read forward over the whole block.
    pub fn of_block(block: &R2ILBlock) -> Self {
        Self::upto(block, block.ops.len())
    }

    /// What a varnode holds here, where the block itself says.
    pub fn of(&self, value: &Varnode) -> Option<ValueOrigin> {
        match value.space {
            SpaceId::Const => Some(ValueOrigin::Constant {
                value: truncated(value.offset, value.size),
                size: value.size,
            }),
            // On x86-64 an indirect memory operand is lifted as the RAM value
            // itself, with no defining load. Its canonical storage is the slot.
            SpaceId::Ram => Some(ValueOrigin::LoadedSlot(CanonicalStorageId::from_varnode(
                value,
            ))),
            _ => self
                .origins
                .get(&CanonicalStorageId::from_varnode(value))
                .copied(),
        }
    }

    /// Apply one operation, so the state describes the point just after it.
    pub fn step(&mut self, op: &R2ILOp) {
        let Some(output) = op.output() else {
            return;
        };
        let storage = CanonicalStorageId::from_varnode(output);
        match self.after(op) {
            Some(origin) => self.origins.insert(storage, origin),
            None => self.origins.remove(&storage),
        };
    }

    /// Forget whatever any of these storages held, as a call leaves them undefined.
    pub fn forget(&mut self, storages: &[CanonicalStorageId]) {
        self.origins.retain(|held, _| {
            !storages.iter().any(|storage| {
                storage.space == held.space
                    && storage.offset < held.offset + u64::from(held.size)
                    && held.offset < storage.offset + u64::from(storage.size)
            })
        });
    }

    fn after(&self, op: &R2ILOp) -> Option<ValueOrigin> {
        match op {
            R2ILOp::Copy { src, .. } => self.of(src),
            R2ILOp::IntAdd { a, b, dst } => self.arithmetic(a, b, dst.size, u64::wrapping_add),
            R2ILOp::IntSub { a, b, dst } => self.arithmetic(a, b, dst.size, u64::wrapping_sub),
            // ARM clears the low bit of a loaded target before branching to
            // it: the bit selects the instruction set, not the address, so the
            // value still names the slot it was loaded from.
            R2ILOp::IntAnd { a, b, dst }
                if b.space == SpaceId::Const && b.offset == truncated(u64::MAX << 1, dst.size) =>
            {
                self.of(a)
            }
            R2ILOp::Load {
                dst,
                space: SpaceId::Ram,
                addr,
            } => Some(ValueOrigin::LoadedSlot(CanonicalStorageId {
                space: CanonicalStorageSpace::Ram,
                offset: self.of(addr)?.constant()?,
                size: dst.size,
            })),
            _ => None,
        }
    }

    fn arithmetic(
        &self,
        a: &Varnode,
        b: &Varnode,
        size: u32,
        combine: fn(u64, u64) -> u64,
    ) -> Option<ValueOrigin> {
        let (left, right) = (self.of(a)?.constant()?, self.of(b)?.constant()?);
        Some(ValueOrigin::Constant {
            value: truncated(combine(left, right), size),
            size,
        })
    }
}

/// A value as the width that holds it sees it.
fn truncated(value: u64, size: u32) -> u64 {
    match size {
        0 | 8.. => value,
        bytes => value & (u64::MAX >> (64 - bytes * 8)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(ops: Vec<R2ILOp>) -> R2ILBlock {
        let mut block = R2ILBlock::new(0x1000, 4);
        for op in ops {
            block.push(op);
        }
        block
    }

    #[test]
    fn a_chain_of_arithmetic_folds_to_one_number() {
        let scratch = Varnode::register(0, 8);
        let block = block(vec![
            R2ILOp::Copy {
                dst: scratch.clone(),
                src: Varnode::constant(0x1000, 8),
            },
            R2ILOp::IntAdd {
                dst: scratch.clone(),
                a: scratch.clone(),
                b: Varnode::constant(0x20, 8),
            },
            R2ILOp::IntSub {
                dst: scratch.clone(),
                a: scratch.clone(),
                b: Varnode::constant(8, 8),
            },
        ]);
        let origins = BlockOrigins::of_block(&block);
        assert_eq!(
            origins.of(&scratch).and_then(ValueOrigin::constant),
            Some(0x1018)
        );
    }

    #[test]
    fn a_load_through_a_folded_address_names_the_slot_it_read() {
        let address = Varnode::register(0, 8);
        let held = Varnode::register(8, 8);
        let block = block(vec![
            R2ILOp::Copy {
                dst: address.clone(),
                src: Varnode::constant(0x2000, 8),
            },
            R2ILOp::IntAdd {
                dst: address.clone(),
                a: address.clone(),
                b: Varnode::constant(0x18, 8),
            },
            R2ILOp::Load {
                dst: held.clone(),
                space: SpaceId::Ram,
                addr: address,
            },
        ]);
        let slot = BlockOrigins::of_block(&block)
            .of(&held)
            .and_then(ValueOrigin::loaded_slot)
            .expect("the load's address folded, so the slot it read is known");
        assert_eq!(slot.space, CanonicalStorageSpace::Ram);
        assert_eq!((slot.offset, slot.size), (0x2018, 8));
    }

    #[test]
    fn an_unmodelled_definition_clears_what_its_destination_held() {
        let scratch = Varnode::register(0, 8);
        let block = block(vec![
            R2ILOp::Copy {
                dst: scratch.clone(),
                src: Varnode::constant(0x1000, 8),
            },
            R2ILOp::IntMult {
                dst: scratch.clone(),
                a: scratch.clone(),
                b: Varnode::constant(3, 8),
            },
        ]);
        assert_eq!(BlockOrigins::of_block(&block).of(&scratch), None);
    }

    #[test]
    fn a_fold_is_truncated_to_the_width_that_holds_it() {
        let narrow = Varnode::register(0, 4);
        let block = block(vec![
            R2ILOp::Copy {
                dst: narrow.clone(),
                src: Varnode::constant(0xffff_ffff, 4),
            },
            R2ILOp::IntAdd {
                dst: narrow.clone(),
                a: narrow.clone(),
                b: Varnode::constant(2, 4),
            },
        ]);
        let origins = BlockOrigins::of_block(&block);
        assert_eq!(origins.of(&narrow).and_then(ValueOrigin::constant), Some(1));
    }

    #[test]
    fn only_clearing_the_instruction_set_bit_keeps_the_slot() {
        let target = Varnode::register(0, 4);
        let masked = |mask: Varnode| {
            let loaded = Varnode::register(8, 4);
            BlockOrigins::of_block(&block(vec![
                R2ILOp::Load {
                    dst: loaded.clone(),
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x2000, 4),
                },
                R2ILOp::IntAnd {
                    dst: target.clone(),
                    a: loaded,
                    b: mask,
                },
            ]))
            .of(&target)
            .and_then(ValueOrigin::loaded_slot)
            .map(|slot| slot.offset)
        };
        assert_eq!(masked(Varnode::constant(0xffff_fffe, 4)), Some(0x2000));
        // Any other mask computes a different number, not the slot's contents.
        assert_eq!(masked(Varnode::constant(0x7fff_ffff, 4)), None);
        assert_eq!(masked(Varnode::register(16, 4)), None);
    }

    #[test]
    fn a_slot_of_no_width_names_nothing_readable() {
        let empty = ValueOrigin::LoadedSlot(CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            offset: 0x2000,
            size: 0,
        });
        assert_eq!(empty.loaded_slot(), None);
    }
}
