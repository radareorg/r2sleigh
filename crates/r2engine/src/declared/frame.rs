//! The frame a declaration states, in the coordinates objects are found in.
//!
//! Debug information measures a frame offset from an origin it names -- the
//! canonical frame address, or a register -- and the engine identifies a
//! frame object by where it sits relative to the stack pointer the function
//! was entered with. Every declared slot is restated there: from the canonical
//! frame address by what the call pushed, from the frame pointer by where the
//! prologue points it.

use r2abi::{FrameBase, FrameRole, Prototype};
use r2source::{
    CanonicalStorageId, SourceLogicalValue, SourceStackSlotName, SourceStackSlotRole,
    SourceStackSlotSpec, StackAddressBase,
};
use r2ssa::TrustedSsaArtifact;

use super::graph::Interned;
use super::{Declared, Placement, Restatement};
use crate::native::storage;

/// The slots a declaration states, and what it calls each.
///
/// A slot and its name are built together because the snapshot requires every
/// name to land on a slot the interface carries: a name for a place the
/// function does not have would be rendered against whatever the engine
/// happened to recover there.
#[derive(Default)]
pub(crate) struct DeclaredFrame {
    pub(crate) names: Vec<SourceStackSlotName>,
    pub(crate) slots: Vec<SourceStackSlotSpec>,
    /// The register the frame is measured from, where the declaration names
    /// one. A slot measured from it is a false statement about the machine
    /// unless the interface says which register that is.
    pub(crate) frame_pointer: Option<CanonicalStorageId>,
}

/// Where a declaration's offsets are measured from, in this machine.
struct Origin {
    base: StackAddressBase,
    storage: CanonicalStorageId,
    /// What to add to a declared offset to measure it from `storage`.
    shift: i64,
    frame_pointer: Option<CanonicalStorageId>,
}

impl Placement<'_> {
    /// The canonical frame address is the caller's stack pointer before the
    /// call, so it is the entry pointer plus what the call left on the stack,
    /// which the compiler specification states. A register base is measured
    /// from that register until the prologue says where it points.
    fn origin(&self, prototype: &Prototype) -> Option<Origin> {
        let stack_pointer = self.machine.roles.stack_pointer_storage()?;
        match prototype.frame_base? {
            FrameBase::CallFrameCfa => Some(Origin {
                base: StackAddressBase::StackPointer,
                storage: stack_pointer,
                shift: self
                    .target
                    .compiler
                    .return_address_slot
                    .map_or(0, |(_, size)| i64::from(size)),
                frame_pointer: None,
            }),
            FrameBase::Register(number) => {
                let bits = crate::engine_effective_ptr_bits(self.target.arch);
                let (role, name) =
                    r2abi::dwarf_frame_register(self.target.arch.name.as_str(), bits, number)?;
                // A base that is the stack pointer inside the body is a
                // distance from a value the body moves.
                if role != FrameRole::FramePointer {
                    return None;
                }
                let storage = storage(self.target.arch, name).ok()?;
                Some(Origin {
                    base: StackAddressBase::FramePointer,
                    storage,
                    shift: 0,
                    frame_pointer: Some(storage),
                })
            }
        }
    }

    /// Every slot the declaration places in the frame: each local, and each
    /// parameter it keeps there, which is that parameter's home with that
    /// parameter's type before anything is proved about the body.
    pub(super) fn frame(
        &self,
        declared: Declared<'_>,
        placed: &[CanonicalStorageId],
        parameters: &[Option<SourceLogicalValue>],
        interned: &mut Interned<'_>,
    ) -> DeclaredFrame {
        let Some(origin) = self.origin(declared.prototype) else {
            return DeclaredFrame::default();
        };
        let mut candidates = Vec::new();
        let homes = declared
            .prototype
            .parameters
            .iter()
            .zip(placed)
            .zip(parameters);
        for (index, ((parameter, arrived), value)) in homes.enumerate() {
            let (Some(offset), Some(value)) = (parameter.frame_offset, value) else {
                continue;
            };
            let Ok(size) = u32::try_from(value.carrier().size_bits() / 8) else {
                continue;
            };
            let home = SourceStackSlotSpec::new_parameter_home(
                origin.base,
                origin.storage,
                offset.saturating_add(origin.shift),
                size,
                index as u32,
                *arrived,
            );
            candidates.push((home.with_logical_type(value.type_id()), None));
        }
        for local in &declared.prototype.locals {
            // A slot with no stated extent is not a slot.
            let Some(size) = local.size_bytes else {
                continue;
            };
            let offset = local.frame_offset.saturating_add(origin.shift);
            let slot = SourceStackSlotSpec::new_local(origin.base, origin.storage, offset, size);
            let slot = match interned.object(local.ty) {
                Some(ty) => slot.with_logical_type(ty),
                None => slot,
            };
            let name = SourceStackSlotName::new(origin.base, offset, local.name.clone())
                .with_type_spelling(local.spelling.as_ref().map(|s| s.as_written().to_owned()));
            candidates.push((slot, Some(name)));
        }
        let mut frame = disjoint(&declared.prototype.name, candidates);
        frame.frame_pointer = origin.frame_pointer;
        frame
    }
}

/// The candidates no other candidate overlaps.
///
/// Two declarations over one place are two names for it: the compiler gave
/// them the same storage because their scopes do not overlap, and
/// `mbsstr_trimmed_wordbounded` has three at one offset. Nothing here chooses
/// a name per program point, so neither is stated; stating both would make
/// the whole declaration unstatable. One sort and one sweep: an interval
/// overlaps an earlier one exactly when it starts before the furthest end
/// seen so far.
fn disjoint(
    function: &str,
    mut candidates: Vec<(SourceStackSlotSpec, Option<SourceStackSlotName>)>,
) -> DeclaredFrame {
    candidates.sort_by_key(|(slot, _)| (slot.offset(), slot.size_bytes()));
    let end =
        |slot: &SourceStackSlotSpec| slot.offset().saturating_add(i64::from(slot.size_bytes()));
    let mut shared = vec![false; candidates.len()];
    let mut furthest: Option<(i64, usize)> = None;
    for (index, (slot, _)) in candidates.iter().enumerate() {
        if let Some((reach, owner)) = furthest
            && slot.offset() < reach
        {
            shared[index] = true;
            shared[owner] = true;
        }
        if furthest.is_none_or(|(reach, _)| end(slot) > reach) {
            furthest = Some((end(slot), index));
        }
    }
    let mut frame = DeclaredFrame::default();
    for ((slot, name), shared) in candidates.into_iter().zip(shared) {
        if shared {
            r2il::refusal_evidence!(
                "declared-stack-slot",
                "{function}: the slot at {:+} ({} bytes) shares its place with another declaration",
                slot.offset(),
                slot.size_bytes()
            );
            continue;
        }
        frame.slots.push(slot.with_debug_declaration());
        frame.names.extend(name);
    }
    frame
}

/// One declaration, with anything it measured from the frame pointer
/// measured from the entry stack pointer instead.
///
/// Unchanged where the declaration used no frame pointer. Where nothing proves
/// where the frame pointer points, the frame-relative slots stay as they are
/// and place nothing: a guessed distance would put every local at the wrong
/// address.
pub(crate) fn rebased(
    declared: Restatement,
    artifact: &TrustedSsaArtifact,
    prototype: Option<&Prototype>,
) -> Restatement {
    let frame_based = |base| base == StackAddressBase::FramePointer;
    let Some(interface) = declared.interface.as_ref() else {
        return declared;
    };
    if !interface
        .stack_slots()
        .iter()
        .any(|slot| frame_based(slot.base()))
    {
        return declared;
    }
    let (Some(frame_pointer), Some(stack_pointer)) = (
        interface.frame_pointer_storage(),
        interface.stack_pointer_storage(),
    ) else {
        return declared;
    };
    let Some(shift) = frame_pointer_distance(artifact, frame_pointer, prototype) else {
        return declared;
    };
    let slots = interface
        .stack_slots()
        .iter()
        .map(|slot| match frame_based(slot.base()) {
            false => *slot,
            true => slot.measured_from(
                StackAddressBase::StackPointer,
                stack_pointer,
                slot.offset().saturating_add(shift),
            ),
        })
        .collect::<Vec<_>>();
    let revision = interface.revision_identity().to_vec();
    Restatement {
        interface: crate::native::restate(interface, slots, revision),
        signature: declared.signature,
        slot_names: declared
            .slot_names
            .into_iter()
            .map(|name| match frame_based(name.base()) {
                false => name,
                true => SourceStackSlotName::new(
                    StackAddressBase::StackPointer,
                    name.offset().saturating_add(shift),
                    name.name(),
                )
                .with_type_spelling(name.type_spelling()),
            })
            .collect(),
    }
}

/// How far the frame pointer sits from the stack pointer the function was
/// entered with, as the prologue proves it.
///
/// Every value the body gives the frame pointer register that the analysis
/// roots at the entry stack pointer must sit at one distance: a frame pointer
/// that moved during the body, or a realigned frame, is not one distance and
/// states none. A parameter the prologue spills states the same slot in both
/// coordinate systems, and where one does it only checks the proof.
fn frame_pointer_distance(
    artifact: &TrustedSsaArtifact,
    frame_pointer: CanonicalStorageId,
    prototype: Option<&Prototype>,
) -> Option<i64> {
    let prepared = artifact.shared_artifact();
    let graph = prepared.graph();
    let mut proved: Option<i64> = None;
    for value in prepared.value_ids() {
        let holds_frame_pointer =
            graph.value(value).and_then(|value| value.canonical_storage) == Some(frame_pointer);
        if !holds_frame_pointer || graph.def_inst(value).is_none() {
            continue;
        }
        let Some(root) = prepared
            .entry_stack_address_root_for_value(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
        else {
            continue;
        };
        match proved {
            None => proved = Some(root.offset),
            Some(distance) if distance == root.offset => {}
            Some(distance) => {
                r2il::refusal_evidence!(
                    "declared-stack-slot",
                    "the frame pointer is set {distance:+} and {:+} from the entry: no one distance",
                    root.offset
                );
                return None;
            }
        }
    }
    let Some(proved) = proved else {
        r2il::refusal_evidence!(
            "declared-stack-slot",
            "no prologue proves where the frame pointer points, so the declaration's \
             frame-relative slots cannot be restated"
        );
        return None;
    };
    match prototype.and_then(|prototype| spilled_distance(artifact, prototype)) {
        Some(spilled) if spilled != proved => {
            r2il::refusal_evidence!(
                "declared-stack-slot",
                "the prologue puts the frame pointer {proved:+} from the entry and a spilled \
                 parameter puts it {spilled:+}"
            );
            None
        }
        _ => Some(proved),
    }
}

/// The frame pointer's distance from the entry as the parameters the body
/// spills state it: the declaration says where each sits in the frame, and the
/// body proves where it sits from the entry.
fn spilled_distance(artifact: &TrustedSsaArtifact, prototype: &Prototype) -> Option<i64> {
    let prepared = artifact.shared_artifact();
    let mut stated: Option<i64> = None;
    for slot in r2ssa::recover_interface::recovered_stack_slots(prepared.as_ref()) {
        let Some(declared) = slot
            .parameter
            .and_then(|index| prototype.parameters.get(index as usize))
            .and_then(|parameter| parameter.frame_offset)
        else {
            continue;
        };
        let distance = slot.offset.checked_sub(declared)?;
        match stated {
            None => stated = Some(distance),
            Some(stated) if stated == distance => {}
            Some(_) => return None,
        }
    }
    stated
}

/// The frame a restatement states: every declared slot as declared, and each
/// slot the body proves only where no declaration covers it.
///
/// The declaration says what the source put where; the body proves where its
/// own accesses land, and it proves nothing against a declaration it lies
/// inside. A home the body proves takes its parameter's type, and one for a
/// parameter the declaration already homes is the same statement made twice.
/// The declared slots are disjoint, so one search per proved slot finds the
/// only declared slot it could overlap: `O((S + D) log D)`.
pub(crate) fn restated_slots(
    declared: &[SourceStackSlotSpec],
    proved: Vec<SourceStackSlotSpec>,
    interface: &r2source::SourceFunctionInterface,
) -> Vec<SourceStackSlotSpec> {
    let mut sorted = declared.to_vec();
    sorted.sort_by_key(|slot| (slot.base(), slot.offset()));
    let homed = declared
        .iter()
        .filter_map(|slot| match slot.role() {
            SourceStackSlotRole::ParameterHome {
                parameter_index, ..
            } => Some(parameter_index),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let covered = |slot: &SourceStackSlotSpec| {
        let end = slot.offset().saturating_add(i64::from(slot.size_bytes()));
        let after =
            sorted.partition_point(|other| (other.base(), other.offset()) < (slot.base(), end));
        after.checked_sub(1).is_some_and(|index| {
            let other = &sorted[index];
            other.base() == slot.base()
                && other.offset().saturating_add(i64::from(other.size_bytes())) > slot.offset()
        })
    };
    let mut slots = declared.to_vec();
    for slot in proved {
        if covered(&slot) {
            continue;
        }
        let SourceStackSlotRole::ParameterHome {
            parameter_index, ..
        } = slot.role()
        else {
            slots.push(slot);
            continue;
        };
        if homed.contains(&parameter_index) {
            continue;
        }
        let typed = interface
            .parameter_logical_value(parameter_index as usize)
            .filter(|value| value.carrier().size_bits() == u64::from(slot.size_bytes()) * 8);
        slots.push(match typed {
            Some(value) => slot.with_logical_type(value.type_id()),
            None => slot,
        });
    }
    slots
}
