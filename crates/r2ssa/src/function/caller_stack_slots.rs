//! The caller's stack slots a body reads and never writes (doc/adr-frame-model.md, "Caller slots").

use std::collections::{BTreeMap, BTreeSet};

use super::SsaArtifact;
use crate::ObjectId;
use crate::semantic::{CallerSlotSupply, CallerStackSlotCertificate};

impl SsaArtifact {
    /// Fill the certificate once the artifact is sealed.
    pub(super) fn seal_caller_stack_slots(&mut self) {
        self.facts.certificates.caller_stack_slots = caller_stack_slots(self);
    }
}

/// Each caller slot only read, with what it holds. One pass over the accesses and the parameters.
fn caller_stack_slots(artifact: &SsaArtifact) -> BTreeMap<ObjectId, CallerStackSlotCertificate> {
    let machine = artifact.machine_context();
    let interface = machine.function_interface();
    let area_placed = (machine.convention_slots())
        .is_some_and(|slots| slots.stack_arguments().is_some())
        && (machine.return_mechanism().is_some() || !machine.call_moves_stack_pointer());
    let admitted = (interface
        .map(|interface| interface.parameters())
        .unwrap_or_default())
    .iter()
    .filter_map(|parameter| parameter.location().stack())
    .collect::<Vec<_>>();
    let accesses = artifact.certificates().memory_accesses.values();
    let written = (accesses.clone())
        .filter(|access| access.is_write)
        .map(|access| access.object)
        .collect::<BTreeSet<_>>();
    let mut slots = BTreeMap::new();
    for access in accesses.filter(|access| !access.is_write && !written.contains(&access.object)) {
        let Some(entry_offset) = (artifact.entry_stack_offset(access.object))
            .filter(|offset| SsaArtifact::caller_frame_offset(*offset))
        else {
            continue;
        };
        let end = entry_offset.saturating_add(i64::from(access.width));
        if (admitted.iter()).any(|(at, size)| *at < end && entry_offset < at + i64::from(*size)) {
            continue;
        }
        let supply = match area_placed && !artifact.return_address_stack_object(access.object) {
            true => CallerSlotSupply::UnadmittedArgument,
            false => CallerSlotSupply::HeldFromEntry,
        };
        let certificate = CallerStackSlotCertificate {
            entry_offset,
            supply,
        };
        slots.insert(access.object, certificate);
    }
    slots
}
