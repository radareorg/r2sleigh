//! The frame stores no code can read back (doc/adr-frame-model.md, "Dead frame stores").

use std::collections::BTreeSet;

use super::SsaArtifact;
use crate::dense::IdSet;
use crate::graph::InstId;
use crate::{CallFrameReach, ExtentAssumption};

impl SsaArtifact {
    /// Fill the certificate once, after the extent facts it reads are sealed.
    pub(super) fn seal_dead_frame_stores(&mut self) {
        self.facts.certificates.dead_frame_stores = dead_frame_stores(self);
    }
}

/// The accesses of every callee-owned, write-only, unescaped, uncalled, bounded frame object, or
/// none while a frame read has an unbounded index. Cost: doc/adr-frame-model.md, "Dead frame stores".
fn dead_frame_stores(artifact: &SsaArtifact) -> IdSet<InstId> {
    let certificates = artifact.certificates();
    let unbounded =
        |object| artifact.extent_assumption(object) == Some(ExtentAssumption::UnboundedIndex);
    let read_objects = (certificates.memory_accesses.values())
        .filter(|access| !access.is_write)
        .map(|access| access.object)
        .collect::<BTreeSet<_>>();
    if read_objects.into_iter().any(unbounded) {
        return IdSet::default();
    }
    let reach = &artifact.objects().frame_reach;
    let (mut every_object, mut by_calls) = (false, BTreeSet::new());
    for (_, call) in reach.calls() {
        match call {
            CallFrameReach::Whole => every_object = true,
            CallFrameReach::Objects(objects) => by_calls.extend(objects.iter().copied()),
        }
    }
    let mut dead = IdSet::default();
    for slot in certificates.stack_slots.values() {
        let Some(allocation) = slot.callee_allocation.as_ref() else {
            continue;
        };
        let object = allocation.object;
        if reach.escaped(object)
            || every_object
            || by_calls.contains(&object)
            || artifact.extent_assumption(object).is_some()
        {
            continue;
        }
        let Some(owned) = (allocation.accesses.iter())
            .map(|access| certificates.memory_accesses.get(access))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if owned.is_empty() || owned.iter().any(|access| !access.is_write) {
            continue;
        }
        dead.extend(owned.iter().map(|access| access.access.inst));
    }
    dead
}
