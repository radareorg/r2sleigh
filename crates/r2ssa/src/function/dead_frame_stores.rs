//! The frame stores no code can read back (doc/adr-frame-model.md, "Dead frame stores").

use std::collections::BTreeSet;

use super::SsaArtifact;
use crate::CallFrameReach;
use crate::dense::{IdMap, IdSet};
use crate::graph::{InstId, InstPayload, ValueId};

impl SsaArtifact {
    /// Fill the certificate once, after the extent facts it reads are sealed.
    pub(super) fn seal_dead_frame_stores(&mut self) {
        let stores = dead_frame_stores(self);
        self.facts.certificates.dead_frame_store_values = dead_store_values(self, &stores);
        self.facts.certificates.dead_frame_stores = stores;
    }
}

/// The accesses of every callee-owned, write-only, unescaped, uncalled, bounded frame object, or
/// none while any frame read has an unbounded index. Cost: doc/adr-frame-model.md, "Dead frame stores".
fn dead_frame_stores(artifact: &SsaArtifact) -> IdSet<InstId> {
    let certificates = artifact.certificates();
    let unbounded =
        |object| (certificates.stack_slots.get(&object)).is_some_and(|slot| slot.unbounded_index);
    let read_objects = (artifact.structured().memory_accesses.values())
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
            || slot.unbounded_index
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

/// The pure operations (`demand::has_effect` false: no memory, trap, atomic or control effect)
/// whose value only a dead frame store writes: every use is such a store, stack geometry, a use no
/// observation depends on, or one of these. Each value keeps a count of its other uses, and each
/// edge lowers one count once: O(V + E).
fn dead_store_values(artifact: &SsaArtifact, stores: &IdSet<InstId>) -> IdSet<InstId> {
    let graph = artifact.graph();
    let geometry = &artifact.certificates().stack_geometry.insts;
    let unobserved = artifact.unobserved_merges().unobserved_uses();
    let live_out = artifact.live_out();
    let others = |value: ValueId| {
        (graph.use_sites(value).iter())
            .filter(|site| {
                !(stores.contains(site.inst)
                    || geometry.contains(site.inst)
                    || unobserved.contains(*site))
            })
            .count()
    };
    let mut remaining = IdMap::<ValueId, usize>::new(graph.values.len());
    let mut ready = Vec::new();
    let stored = |inst: InstId| {
        graph
            .inst(inst)
            .and_then(|inst| inst.inputs.get(1).copied())
    };
    for value in stores.iter().filter_map(stored) {
        if remaining.get(value).is_none() {
            let left = others(value);
            remaining.insert(value, left);
            if left == 0 {
                ready.push(value);
            }
        }
    }
    let mut values = IdSet::default();
    while let Some(value) = ready.pop() {
        let Some(def) = graph.def_inst(value).and_then(|def| graph.inst(def)) else {
            continue;
        };
        let pure = matches!(def.payload, InstPayload::Op(_)) && !crate::demand::has_effect(def);
        if !pure || live_out.contains(value) || !values.insert(def.id) {
            continue;
        }
        for input in &def.inputs {
            let left = remaining
                .get(*input)
                .copied()
                .unwrap_or_else(|| others(*input));
            let left = left.saturating_sub(1);
            remaining.insert(*input, left);
            if left == 0 {
                ready.push(*input);
            }
        }
    }
    values
}
