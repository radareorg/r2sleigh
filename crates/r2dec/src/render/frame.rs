//! D4: the function's own frame as one array in entry-SP coordinates, aligned as the convention
//! states the entry stack (doc/adr-decompiler-rewrite.md, "D4's frame").

use std::collections::BTreeMap;

use r2ssa::{ObjectId, SsaArtifact};

/// Where each frame object lies in the one array, and the array's alignment and size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Frame {
    /// The least entry offset any object starts at; the array's byte `pad` stands for it.
    low: i64,
    pad: u32,
    alignment: u32,
    bytes: u32,
    objects: BTreeMap<ObjectId, (i64, u32)>,
}

impl Frame {
    /// The layout of `objects` (entry offset, size) under `sp % alignment == residue` at entry; an
    /// object reaching offset 0 or above is the caller's and left out. `None` where none is left.
    pub(super) fn lay_out(
        objects: impl IntoIterator<Item = (ObjectId, i64, u32)>,
        (alignment, residue): (u32, u32),
    ) -> Option<Self> {
        if alignment == 0 || residue >= alignment {
            return None;
        }
        let objects = objects
            .into_iter()
            .filter(|(_, offset, size)| {
                *size > 0
                    && offset
                        .checked_add(i64::from(*size))
                        .is_some_and(|end| end <= 0)
            })
            .map(|(object, offset, size)| (object, (offset, size)))
            .collect::<BTreeMap<_, _>>();
        let low = objects.values().map(|(offset, _)| *offset).min()?;
        // `frame + pad` must sit where `entry_sp + low` does, modulo the alignment.
        let pad = (i64::from(residue) + low).rem_euclid(i64::from(alignment));
        let bytes = u32::try_from(pad.checked_sub(low)?).ok()?;
        Some(Self {
            low,
            pad: u32::try_from(pad).ok()?,
            alignment,
            bytes,
            objects,
        })
    }

    /// The frame of the objects whose entry-SP coordinates r2ssa states, where the convention states
    /// the entry stack's alignment: every byte below the entry stack pointer is the function's own.
    pub(super) fn of(artifact: &SsaArtifact) -> Option<Self> {
        let entry = artifact
            .machine_context()
            .convention_slots()?
            .entry_stack()?;
        let roots = &artifact.facts().objects.entry_stack_roots;
        let placed = artifact
            .certificates()
            .stack_slots
            .iter()
            .filter_map(|(object, slot)| {
                if let Some(allocation) = &slot.callee_allocation {
                    return Some((*object, allocation.entry_offset, allocation.size_bytes));
                }
                let root = roots
                    .get(object)
                    .filter(|root| root.base == r2source::StackAddressBase::StackPointer)?;
                Some((*object, root.offset, slot.size?))
            });
        Self::lay_out(placed, (entry.alignment, entry.residue))
    }

    /// The array's byte index of `object`'s first byte, and the object's size.
    pub(super) fn at(&self, object: ObjectId) -> Option<(u32, u32)> {
        let (offset, size) = *self.objects.get(&object)?;
        let index = i64::from(self.pad) + (offset - self.low);
        Some((u32::try_from(index).ok()?, size))
    }

    pub(super) const fn bytes(&self) -> u32 {
        self.bytes
    }

    pub(super) const fn alignment(&self) -> u32 {
        self.alignment
    }
}

#[cfg(test)]
mod tests {
    use r2ssa::ObjectId;

    use super::Frame;

    /// x86-64: `%rsp + 8` is 16-aligned at entry, so an object at entry offset -24 sits at an
    /// address that is 0 modulo 16 and keeps that place in the array.
    #[test]
    fn the_frame_keeps_the_machine_s_alignment() {
        let objects = [(ObjectId(1), -24, 8), (ObjectId(2), -8, 8)];
        let frame = Frame::lay_out(objects, (16, 8)).expect("a frame");
        assert_eq!(frame.alignment(), 16);
        let (first, _) = frame.at(ObjectId(1)).expect("laid out");
        assert_eq!(first % 16, 0, "{frame:?}");
        assert_eq!(frame.at(ObjectId(2)), Some((first + 16, 8)));
        assert_eq!(frame.bytes(), first + 24);
        // AArch64: SP is 16-aligned at entry, so -24 is 8 modulo 16.
        let frame = Frame::lay_out(objects, (16, 0)).expect("a frame");
        assert_eq!(frame.at(ObjectId(1)).map(|(at, _)| at % 16), Some(8));
    }

    /// A slot reaching the entry stack pointer or above is the caller's: the frame leaves it out.
    #[test]
    fn a_caller_s_slot_is_no_part_of_the_frame() {
        let objects = [
            (ObjectId(1), -8, 16),
            (ObjectId(2), 8, 8),
            (ObjectId(3), -16, 8),
        ];
        let frame = Frame::lay_out(objects, (16, 8)).expect("the callee's slot");
        assert_eq!(frame.at(ObjectId(1)), None);
        assert_eq!(frame.at(ObjectId(2)), None);
        assert!(frame.at(ObjectId(3)).is_some());
        assert_eq!(Frame::lay_out([(ObjectId(2), 8, 8)], (16, 8)), None);
    }
}
