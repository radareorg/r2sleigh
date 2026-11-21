//! The memory operations a parameter's value reaches, read against the places (doc/adr-aggregates.md).

use std::collections::BTreeMap;

use r2il::SpaceId;

use super::{MemoryPlaces, ParameterReach, Place, PlaceBase, ReachedField};
use crate::graph::{InstId, InstPayload};
use crate::semantic::{SourceBoundaryFacts, StackReloadSourceCertificate, StructuredDataflowFacts};
use crate::{SSAOp, SsaGraph, ValueId};

/// Each formal's reach. It runs through every operation and merge P feeds and its home's
/// reloads, and ends at a load's output, a new base; each value is expanded once.
pub(super) fn parameters(
    places: &MemoryPlaces,
    graph: &SsaGraph,
    boundaries: &SourceBoundaryFacts,
    structured: &StructuredDataflowFacts,
    stack_reloads: &crate::dense::IdMap<ValueId, StackReloadSourceCertificate>,
) -> BTreeMap<u32, ParameterReach> {
    let mut reloads_of = crate::dense::IdMap::<ValueId, Vec<ValueId>>::default();
    for reload in stack_reloads.values() {
        if reload.relation == crate::view::ViewRelation::Identity
            && reload.value_width == reload.memory_width
        {
            (reloads_of.get_or_insert_with(reload.canonical_source, Vec::new)).push(reload.value);
        }
    }
    let mut out = BTreeMap::new();
    for (slot, parameter) in &boundaries.parameters {
        let Some(value) = parameter.value() else {
            continue;
        };
        let operations = reached_memory_operations(graph, &reloads_of, value);
        if operations.is_empty() {
            continue;
        }
        out.insert(*slot, fields_of(*slot, &operations, places, structured));
    }
    out
}

/// How a memory operation the parameter's value reaches uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reached {
    Read,
    Write,
    Unmodelled,
}

/// The memory operations the parameter's value reaches: RAM loads and stores by their address, and
/// any other memory operation it feeds at all.
fn reached_memory_operations(
    graph: &SsaGraph,
    reloads_of: &crate::dense::IdMap<ValueId, Vec<ValueId>>,
    parameter: ValueId,
) -> Vec<(InstId, Reached)> {
    let mut operations = Vec::new();
    let mut reached = crate::dense::IdSet::default();
    let mut pending = vec![parameter];
    while let Some(value) = pending.pop() {
        if !reached.insert(value) {
            continue;
        }
        pending.extend(reloads_of.get(value).into_iter().flatten().copied());
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                continue;
            };
            match &inst.payload {
                InstPayload::Op(SSAOp::Load {
                    space: SpaceId::Ram,
                    addr,
                    ..
                }) if *addr == value => {
                    operations.push((inst.id, Reached::Read));
                }
                InstPayload::Op(SSAOp::Store {
                    space: SpaceId::Ram,
                    addr,
                    ..
                }) if *addr == value => {
                    operations.push((inst.id, Reached::Write));
                }
                // A spilled value comes back through its home's reloads; anything else a load,
                // store or call does with it leaves the pointee alone.
                InstPayload::Op(op)
                    if op.is_call()
                        || matches!(
                            op,
                            SSAOp::Load { .. } | SSAOp::Store { .. } | SSAOp::CallOther { .. }
                        ) => {}
                // What a linked, guarded or atomic load returns is memory's, never the parameter.
                InstPayload::Op(op) if op.is_memory_read() || op.is_memory_write() => {
                    operations.push((inst.id, Reached::Unmodelled));
                }
                _ => pending.extend(inst.output),
            }
        }
    }
    // In instruction order, each once: the first refusal is the earliest instruction's.
    operations.sort_unstable();
    operations.dedup();
    operations
}

/// The reached operations' places as fields of `slot`, or the first that is not one.
fn fields_of(
    slot: u32,
    operations: &[(InstId, Reached)],
    places: &MemoryPlaces,
    structured: &StructuredDataflowFacts,
) -> ParameterReach {
    let mut fields = Vec::new();
    for &(inst, reached) in operations {
        let is_write = match reached {
            Reached::Read => false,
            Reached::Write => true,
            Reached::Unmodelled => {
                return ParameterReach::Refused {
                    inst,
                    base: PlaceBase::Parameter(slot),
                    place: Some(Place::Unplaced(super::Unplaced::Unmodelled)),
                };
            }
        };
        let mut any = false;
        for access in structured.accesses_at(inst) {
            if access.is_write != is_write {
                continue;
            }
            any = true;
            let Some(placed) = (structured.position(access.id)).and_then(|at| places.at(at)) else {
                return ParameterReach::Refused {
                    inst,
                    base: PlaceBase::None,
                    place: None,
                };
            };
            match (placed.base, placed.place) {
                (PlaceBase::Parameter(base), Place::Field { offset, width }) if base == slot => {
                    fields.push(ReachedField {
                        offset,
                        width,
                        access: access.id,
                        value: access.value,
                    });
                }
                (base, place) => {
                    return ParameterReach::Refused {
                        inst,
                        base,
                        place: Some(place),
                    };
                }
            }
        }
        if !any {
            return ParameterReach::Refused {
                inst,
                base: PlaceBase::None,
                place: None,
            };
        }
    }
    fields.sort();
    ParameterReach::Fields(fields)
}
