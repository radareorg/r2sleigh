//! What a value is, read forward from the start of one block.
//!
//! Several questions turn out to be this one question. A terminal indirect
//! branch asks which RAM slot its target was loaded from; an import stub asks
//! which slot it reads; a listing asks whether the address an instruction
//! loads from folds to a constant. Each was answered by its own walk over the
//! same operations, so this is that walk, once, with a name.
//!
//! An origin lives only until a byte of its storage is written or a call intervenes (doc/ssa.md, "Block origins").

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
    /// Keyed by `(space, offset, size)`; no two tracked storages share a byte.
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
        if matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }) {
            // A callee may write any register; RAM is read by `of` directly and is never tracked.
            self.origins.clear();
            return;
        }
        let origin = self.after(op);
        self.forget_memory_write(op);
        let Some(output) = op.output() else {
            return;
        };
        let storage = CanonicalStorageId::from_varnode(output);
        self.forget_bytes(storage.space, storage.offset, storage.size.into());
        if let Some(origin) = origin
            && storage.size != 0
            && storage.space != CanonicalStorageSpace::Ram
        {
            self.origins.insert(storage, origin);
        }
    }

    /// Forget what a memory write may change: the bytes it names where its address folds, else its space.
    fn forget_memory_write(&mut self, op: &R2ILOp) {
        let (space, addr, size) = match op {
            R2ILOp::Store { space, addr, val }
            | R2ILOp::StoreConditional {
                space, addr, val, ..
            }
            | R2ILOp::StoreGuarded {
                space, addr, val, ..
            } => (*space, Some(addr), val.size),
            R2ILOp::AtomicCAS {
                space,
                addr,
                replacement,
                ..
            } => (*space, Some(addr), replacement.size),
            // Its extent turns on a count and a direction, so it may write anywhere in its space; a scan or a compare writes none.
            R2ILOp::BlockTransfer(transfer) if transfer.kind.writes_memory() => {
                (transfer.space, None, 0)
            }
            _ => return,
        };
        let space = CanonicalStorageId::from_varnode(&Varnode::new(space, 0, 0)).space;
        match addr.and_then(|addr| self.of(addr)?.constant()) {
            Some(offset) => self.forget_bytes(space, offset, size.into()),
            None => self.forget_bytes(space, 0, 1 << 64),
        }
    }

    /// Forget every tracked storage sharing a byte with `width` bytes at `start`, in `O(log s + k)`.
    fn forget_bytes(&mut self, space: CanonicalStorageSpace, start: u64, width: u128) {
        let reaches =
            |storage: &CanonicalStorageId| u128::from(storage.offset) + u128::from(storage.size);
        let from = CanonicalStorageId {
            space,
            offset: start,
            size: 0,
        };
        let below = self
            .origins
            .range(..from)
            .next_back()
            .map(|(storage, _)| *storage)
            .filter(|storage| storage.space == space && reaches(storage) > u128::from(start));
        let inside = self
            .origins
            .range(from..)
            .map(|(storage, _)| *storage)
            .take_while(|storage| {
                storage.space == space && u128::from(storage.offset) < u128::from(start) + width
            })
            .collect::<Vec<_>>();
        for storage in below.into_iter().chain(inside) {
            self.origins.remove(&storage);
        }
    }

    /// Apply one operation where the convention says what a call leaves standing; without one a call forgets everything.
    pub fn step_under(&mut self, op: &R2ILOp, call_effect: Option<&crate::SourceCallEffect>) {
        match (op, call_effect) {
            (R2ILOp::Call { .. } | R2ILOp::CallInd { .. }, Some(effect)) => {
                self.origins.retain(|storage, _| effect.preserves(*storage));
            }
            _ => self.step(op),
        }
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
    fn a_partial_write_kills_the_wider_origin() {
        let (wide, low_byte) = (Varnode::register(0, 8), Varnode::register(0, 1));
        let origins = BlockOrigins::of_block(&block(vec![
            R2ILOp::Copy {
                dst: wide.clone(),
                src: Varnode::constant(0x1000, 8),
            },
            R2ILOp::Copy {
                dst: low_byte.clone(),
                src: Varnode::constant(5, 1),
            },
        ]));
        assert_eq!(origins.of(&wide), None);
        assert_eq!(
            origins.of(&low_byte).and_then(ValueOrigin::constant),
            Some(5)
        );
        // A write that reaches into a storage from below kills it too.
        let high_half = Varnode::register(4, 4);
        let straddled = BlockOrigins::of_block(&block(vec![
            R2ILOp::Copy {
                dst: high_half.clone(),
                src: Varnode::constant(7, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::register(2, 4),
                src: Varnode::constant(9, 4),
            },
        ]));
        assert_eq!(straddled.of(&high_half), None);
    }

    #[test]
    fn a_store_into_the_register_space_kills_what_it_overwrites() {
        // vmov.i64 d0, #0; vld1.8 {d0[3]}, [r1]: NEON writes one lane through `*[register]`.
        let (d0, lane) = (Varnode::register(0x300, 8), Varnode::unique(0x80, 1));
        let lane_load = |addr: Varnode, space: SpaceId| {
            BlockOrigins::of_block(&block(vec![
                R2ILOp::Copy {
                    dst: d0.clone(),
                    src: Varnode::constant(0, 8),
                },
                R2ILOp::Copy {
                    dst: Varnode::unique(0x90, 4),
                    src: Varnode::constant(0x300, 4),
                },
                R2ILOp::IntAdd {
                    dst: Varnode::unique(0x90, 4),
                    a: Varnode::unique(0x90, 4),
                    b: addr,
                },
                R2ILOp::Store {
                    space,
                    addr: Varnode::unique(0x90, 4),
                    val: lane.clone(),
                },
            ]))
            .of(&d0)
            .and_then(ValueOrigin::constant)
        };
        assert_eq!(lane_load(Varnode::constant(3, 4), SpaceId::Register), None);
        // An address nothing folds may name any register.
        assert_eq!(
            lane_load(Varnode::register(0x20, 4), SpaceId::Register),
            None
        );
        // A store past its last byte, or into RAM, leaves it.
        assert_eq!(
            lane_load(Varnode::constant(8, 4), SpaceId::Register),
            Some(0)
        );
        assert_eq!(lane_load(Varnode::constant(3, 4), SpaceId::Ram), Some(0));
    }

    #[test]
    fn a_call_clears_a_register_origin() {
        let scratch = Varnode::register(0, 8);
        let origins = BlockOrigins::of_block(&block(vec![
            R2ILOp::Copy {
                dst: scratch.clone(),
                src: Varnode::constant(0x1000, 8),
            },
            R2ILOp::Call {
                target: Varnode::constant(0x2000, 8),
            },
        ]));
        assert_eq!(origins.of(&scratch), None);
    }

    #[test]
    fn a_call_under_a_convention_keeps_only_what_it_preserves() {
        let register = |offset| Varnode::register(offset, 8);
        let effect = crate::SourceCallEffect::new(
            [CanonicalStorageId::from_varnode(&register(0))],
            [CanonicalStorageId::from_varnode(&register(24))],
        )
        .expect("a consistent effect");
        let mut origins = BlockOrigins::default();
        for (offset, value) in [(0, 0x1000), (8, 0x2000), (24, 0x3000)] {
            let op = R2ILOp::Copy {
                dst: register(offset),
                src: Varnode::constant(value, 8),
            };
            origins.step_under(&op, Some(&effect));
        }
        let call = R2ILOp::Call {
            target: Varnode::constant(0x4000, 8),
        };
        origins.step_under(&call, Some(&effect));
        // Clobbered, and named neither way: both may have changed.
        assert_eq!(origins.of(&register(0)), None);
        assert_eq!(origins.of(&register(8)), None);
        assert_eq!(
            origins.of(&register(24)).and_then(ValueOrigin::constant),
            Some(0x3000)
        );
    }

    #[test]
    fn a_jump_through_a_clobbered_address_names_no_slot() {
        // mov rax, 0x1000; mov al, 5; jmp [rax]: the jump reads 0x1005's slot, not 0x1000's.
        let (address, target) = (Varnode::register(0, 8), Varnode::unique(0x100, 8));
        let block = block(vec![
            R2ILOp::Copy {
                dst: address.clone(),
                src: Varnode::constant(0x1000, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::register(0, 1),
                src: Varnode::constant(5, 1),
            },
            R2ILOp::Load {
                dst: target.clone(),
                space: SpaceId::Ram,
                addr: address,
            },
            R2ILOp::BranchInd { target },
        ]);
        assert_eq!(
            crate::machine_context::terminal_indirect_loaded_slot(&block, 3),
            None
        );
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
