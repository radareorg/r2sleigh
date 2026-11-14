//! The caller's stack slots a body reads and never writes (doc/adr-frame-model.md, "Caller slots").

use std::collections::{BTreeMap, BTreeSet};

use super::SsaArtifact;
use crate::ObjectId;
use crate::semantic::{CallerSlotSupply, CallerStackSlotCertificate, FormalHome};

impl SsaArtifact {
    /// Fill the certificate once the artifact is sealed.
    pub(super) fn seal_caller_stack_slots(&mut self) {
        self.facts.certificates.caller_stack_slots = caller_stack_slots(self);
    }
}

/// Each caller slot only read, with what it holds. One pass over the accesses and the formals.
fn caller_stack_slots(artifact: &SsaArtifact) -> BTreeMap<ObjectId, CallerStackSlotCertificate> {
    let machine = artifact.machine_context();
    let area_placed = (machine.convention()).is_some_and(|model| model.stack_arguments().is_some())
        && (machine.return_mechanism().is_some() || !machine.call_moves_stack_pointer());
    let formals = (artifact.facts().boundaries.parameters.values())
        .filter_map(|formal| match formal.home {
            FormalHome::Frame {
                object,
                offset,
                bytes,
            } => Some((formal.index, object, offset, bytes)),
            FormalHome::Register { .. } => None,
        })
        .collect::<Vec<_>>();
    let accesses = artifact.certificates().memory_accesses.values();
    let written = (accesses.clone())
        .filter(|access| access.is_write)
        .map(|access| access.object)
        .collect::<BTreeSet<_>>();
    let mut slots = BTreeMap::new();
    let mut partial = BTreeSet::new();
    for access in accesses.filter(|access| !access.is_write && !written.contains(&access.object)) {
        let Some(entry_offset) = (artifact.entry_stack_offset(access.object))
            .filter(|offset| artifact.caller_frame_offset(*offset))
        else {
            continue;
        };
        let end = entry_offset.saturating_add(i64::from(access.width));
        let formal = formals
            .iter()
            .find(|(_, _, at, bytes)| *at < end && entry_offset < at + i64::from(*bytes));
        let supply = match formal {
            // A read of the whole formal at its home is the formal; any other overlap is no slot.
            Some((index, object, at, bytes)) => {
                if *object != access.object || *at != entry_offset || *bytes != access.width {
                    partial.insert(access.object);
                    continue;
                }
                CallerSlotSupply::Formal(*index)
            }
            None if area_placed && !artifact.return_address_stack_object(access.object) => {
                CallerSlotSupply::UnadmittedArgument
            }
            None => CallerSlotSupply::HeldFromEntry,
        };
        let certificate = CallerStackSlotCertificate {
            entry_offset,
            supply,
        };
        slots.insert(access.object, certificate);
    }
    slots.retain(|object, _| !partial.contains(object));
    slots
}
