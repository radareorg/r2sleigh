//! Canonical semantic sidecar facts for prepared SSA functions.
//!
//! These facts keep object, memory, predicate, and call-site provenance in
//! `r2ssa` so downstream crates stop reconstructing them independently.

mod assumptions;
mod boundaries;
mod call_sites;
mod certificates;
mod control_domains;
mod declared_slots;
mod facts;
mod loops;
mod objects;
mod predicates;
mod prefix;
mod private_objects;
mod shared;
mod structured;
#[cfg(test)]
mod tests;
mod trips;

pub(crate) use assumptions::*;
pub(crate) use boundaries::*;
pub(crate) use call_sites::*;
pub use certificates::*;
pub use control_domains::*;
pub(crate) use declared_slots::*;
pub use facts::*;
pub(crate) use loops::*;
pub(crate) use objects::*;
pub(crate) use predicates::*;
pub(crate) use prefix::*;
pub(crate) use private_objects::*;
pub(crate) use shared::*;
pub(crate) use structured::*;
pub(crate) use trips::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use r2il::SpaceId;
use serde::{Deserialize, Serialize};

use crate::address::{AddressProvenanceFacts, collect_address_provenance};
use crate::assumption::{AssumptionSet, AssumptionSubject, AssumptionUsageReport, AssumptionValue};
use crate::cfg::BlockTerminator;
use crate::function::{DecompilePrepFacts, SSAFunction, StackAddressBase, StackAddressRoot};
use crate::graph::{InstId, InstPayload, SsaGraph, UseSite, ValueId};
use crate::machine_context::{
    MachineRegisterGeometryState, SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION,
    SOURCE_TYPE_GRAPH_SCHEMA_VERSION, SourceCallResult, SourceCallSiteIdentity, SourceCarrierKind,
    SourceFunctionReturn, SourceLogicalValue, SourceMachineContext, SourceStackAllocationContract,
    SourceStackSlotRole, SourceStackSlotSpec, SourceTypeKind,
};
use crate::obligation::SemanticObligationInventory;
use crate::op::SSAOp;
use crate::span::StorageSpans;
use crate::var::{CanonicalStorageId, CanonicalStorageSpace, SSAVar};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFunctionFacts {
    pub addresses: AddressProvenanceFacts,
    /// What every value can be. One answer, where each question used to walk
    /// the graph for a bound of its own.
    pub values: crate::values::ValueRanges,
    pub objects: ObjectModel,
    pub memory: MemorySSAFacts,
    pub predicates: PredicateFacts,
    pub call_sites: CallSiteFacts,
    pub boundaries: SourceBoundaryFacts,
    pub structured: StructuredDataflowFacts,
    pub control_domains: ControlDomainFacts,
    /// The frame objects no address naming them ever leaves the function:
    /// not stored, handed to a call, returned, or used by an access the model
    /// could not place. Nothing outside the function can read or write them.
    pub private_stack_objects: BTreeSet<ObjectId>,
    pub certificates: PreparedFunctionCertificates,
    pub obligations: SemanticObligationInventory,
    pub assumptions: AssumptionSet,
    pub applied_assumption_bindings: Vec<PreparedAssumptionBinding>,
    pub assumption_usage: AssumptionUsageReport,
}

/// What one collection reads, so the phases take one name rather than six.
pub(crate) struct CollectionOver<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) storage_spans: &'a StorageSpans,
    pub(crate) assumptions: &'a AssumptionSet,
    pub(crate) machine_context: Option<&'a SourceMachineContext>,
    /// Which caller asked, so a trace says which of the three collections it is.
    pub(crate) site: &'static str,
}

/// What each phase of the collector cost, and how much it produced.
///
/// One function in a binary built at `-O2` grew past the harness's memory limit
/// inside this collector while the same function alone took two seconds; the
/// phase that grows is the one to trace, and nothing downstream could tell
/// which it was. The bytes matter as much as the milliseconds, and for the same
/// reason: a count of entries says nothing about what each entry holds.
///
/// Each mark reports the time and the bytes *that phase* spent, rather than the
/// running total from the collector's entry, so a reader does not have to
/// difference the lines. Off the trace, a mark costs a branch.
struct PhaseRecorder {
    tracing: bool,
    who: String,
    blocks: usize,
    since: std::time::Instant,
    bytes: usize,
}

impl PhaseRecorder {
    fn open(site: &'static str, function: &SSAFunction) -> Self {
        let tracing = r2il::refusal_evidence::tracing();
        Self {
            tracing,
            who: if tracing {
                format!(
                    "{site}@{:#x}",
                    function.entry_block().map_or(0, |block| block.addr)
                )
            } else {
                String::new()
            },
            blocks: function.num_blocks(),
            since: std::time::Instant::now(),
            bytes: if tracing {
                r2il::allocation::live_bytes()
            } else {
                0
            },
        }
    }

    fn mark(&mut self, name: &str, size: usize) {
        if !self.tracing {
            return;
        }
        let live = r2il::allocation::live_bytes();
        let grew = live.saturating_sub(self.bytes);
        let spent = self.since.elapsed();
        self.bytes = live;
        self.since = std::time::Instant::now();
        // Against the blocks, because what a phase costs is only a defect when
        // it grows faster than the function it is reading.
        r2il::refusal_evidence!(
            "collect-phase",
            "{} {name} {}us size {size} bytes {grew} blocks {} us/block {}",
            self.who,
            spent.as_micros(),
            self.blocks,
            spent.as_micros() / self.blocks.max(1) as u128
        );
    }
}

impl PreparedFunctionFacts {
    pub fn collect(function: &SSAFunction, graph: &SsaGraph) -> Self {
        let liveness = crate::liveness::ValueLiveness::compute(
            graph,
            &crate::liveout::FunctionLiveOut::default(),
            crate::liveness::ValueContent::of(graph, None),
        );
        let storage_spans = StorageSpans::compute(graph, &liveness);
        Self::collect_inner(
            CollectionOver {
                function,
                graph,
                storage_spans: &storage_spans,
                assumptions: &AssumptionSet::default(),
                machine_context: None,
                site: "collect",
            },
            &crate::control::UncheckedSsaWorkControl,
        )
        .expect("an unchecked control never stops")
    }

    pub fn collect_with_assumptions(
        function: &SSAFunction,
        graph: &SsaGraph,
        assumptions: &AssumptionSet,
    ) -> Self {
        let liveness = crate::liveness::ValueLiveness::compute(
            graph,
            &crate::liveout::FunctionLiveOut::default(),
            crate::liveness::ValueContent::of(graph, None),
        );
        let storage_spans = StorageSpans::compute(graph, &liveness);
        Self::collect_inner(
            CollectionOver {
                function,
                graph,
                storage_spans: &storage_spans,
                assumptions,
                machine_context: None,
                site: "assume",
            },
            &crate::control::UncheckedSsaWorkControl,
        )
        .expect("an unchecked control never stops")
    }

    pub(crate) fn collect_with_context(
        function: &SSAFunction,
        graph: &SsaGraph,
        storage_spans: &StorageSpans,
        assumptions: &AssumptionSet,
        machine_context: &SourceMachineContext,
        site: &'static str,
    ) -> Self {
        Self::collect_inner(
            CollectionOver {
                function,
                graph,
                storage_spans,
                assumptions,
                machine_context: Some(machine_context),
                site,
            },
            &crate::control::UncheckedSsaWorkControl,
        )
        .expect("an unchecked control never stops")
    }

    /// The same collection, stopping between phases when the run is cancelled.
    ///
    /// Preparation is the most expensive thing the engine does and it used to
    /// be the one stretch a deadline could not reach, so a cancelled request
    /// still paid for every phase of it.
    pub(crate) fn collect_with_context_and_control<C: crate::SsaWorkControl + ?Sized>(
        over: CollectionOver<'_>,
        control: &C,
    ) -> Result<Self, crate::SsaExecutionStopReason> {
        Self::collect_inner(over, control)
    }

    fn collect_inner<C: crate::SsaWorkControl + ?Sized>(
        over: CollectionOver<'_>,
        control: &C,
    ) -> Result<Self, crate::SsaExecutionStopReason> {
        let CollectionOver {
            function,
            graph,
            storage_spans,
            assumptions,
            machine_context,
            site,
        } = over;
        let mut phases = PhaseRecorder::open(site, function);
        let MemoryPrefix {
            addresses,
            call_sites,
            declared_slots,
            predicates,
            latches_by_header,
            values,
            objects,
            memory,
            memory_accesses,
            member_run_stores,
        } = MemoryPrefix::collect(function, graph, machine_context, &mut phases, control)?;
        macro_rules! phase {
            ($name:literal, $size:expr) => {{
                phases.mark($name, $size);
                control.poll()?;
            }};
        }
        let return_storages = machine_context
            .into_iter()
            .flat_map(|context| context.abi_model().return_registers())
            .map(|slot| slot.storage())
            .collect::<Vec<_>>();
        let live_out = crate::liveout::FunctionLiveOut::compute(function, graph, &return_storages);
        let (loops, inductions) = collect_structured_loop_facts(
            Body {
                function,
                graph,
                machine_context,
            },
            LoopEvidence {
                predicates: &predicates,
                values: &values,
                latches_by_header: &latches_by_header,
            },
            &live_out,
            storage_spans,
        );
        phase!("loops", loops.len());
        let boundaries =
            collect_source_boundary_facts(function, graph, &call_sites, machine_context, &live_out);
        phase!("boundaries", boundaries.calls.len());
        let structured = StructuredDataflowFacts {
            unstructured_cycle_blocks: collect_unstructured_cycle_blocks(graph, &loops),
            inductions,
            loops,
            memory_accesses,
            member_run_stores,
            recursive_calls: collect_structured_recursive_call_facts(function, graph, &call_sites),
        };
        phase!("structured", structured.memory_accesses.len());
        let control_domains = collect_control_domain_facts(function, &predicates, &structured);
        phase!("control_domains", 0);
        let private_stack_objects = private_stack_objects(graph, &objects, &structured, &live_out);
        // Before the obligations, because whether an access is a statement at
        // all depends on it: a round trip leaves the object as it found it, so
        // neither half is an observable effect.
        let memory_round_trips = collect_memory_round_trips(graph, &structured);
        let obligations = SemanticObligationInventory::collect(
            graph,
            &structured,
            &boundaries,
            machine_context,
            &private_stack_objects,
            &memory_round_trips,
        );
        phase!("obligations", obligations.obligations().len());
        r2il::refusal_evidence!("obligation-shape", "{}", obligations.probe_shape());
        // A lifted body merges every storage live across a join, so the graph
        // records uses that carry no program observation. `DeadPhis` names
        // exactly those, and the merges stay in the function by design, so a
        // certificate that asks whether the program reads a value has to ask
        // this rather than count raw use sites.
        let unobserved =
            crate::deadphi::DeadPhis::find_from(graph, &live_out, &obligations, &boundaries);
        let body = Body {
            function,
            graph,
            machine_context,
        };
        let derived = Derived {
            values: &values,
            boundaries: &boundaries,
            objects: &objects,
            memory: &memory,
            predicates: &predicates,
            call_sites: &call_sites,
            structured: &structured,
        };
        let certificates = collect_prepared_function_certificates(
            body,
            derived,
            &unobserved,
            &live_out,
            &private_stack_objects,
            &declared_slots,
            memory_round_trips,
        );
        phase!("certificates", certificates.stack_slots.len());
        let (applied_assumption_bindings, assumption_usage) = collect_prepared_assumption_usage(
            graph,
            &objects,
            &predicates,
            assumptions,
            machine_context,
        );
        phase!("assumptions", 0);
        Ok(Self {
            addresses,
            values,
            objects,
            memory,
            predicates,
            call_sites,
            boundaries,
            structured,
            control_domains,
            private_stack_objects,
            certificates,
            obligations,
            assumptions: assumptions.clone(),
            applied_assumption_bindings,
            assumption_usage,
        })
    }
}

/// Add the entry carriers that implicit call reads alone expose.
///
/// This is one pass over the existing graph plus one bounded pass over ABI
/// slots. The graph value has no defining instruction; it is an exact boundary
/// value whose eventual use is owned by a callsite certificate.
///
/// Two sets of storages need one: the source's declared formal parameters, and
/// the convention's argument registers. The second is what a call reads
/// implicitly. A function that hands its incoming first argument straight to a
/// callee never reads that register explicitly, so nothing else materializes
/// its entry carrier; the boundary then resolved the argument to
/// `PreservedEntry` with no value to name, and the whole call's argument list
/// was refused for it -- every argument, not just that one. It cost 100 call
/// sites of minigzip at -O0 and 125 at -O2 their certificates. Recovery
/// already treats such a carrier as a parameter, but a function whose captured
/// prototype names fewer parameters than it passes through is not recovered at
/// all, and that is where this bit.
///
/// The claim a materialized carrier makes is that the storage held some value
/// on entry, which is true of every register; it becomes load-bearing only
/// where something reads it, and a carrier nothing reads has no definition and
/// no uses, so it is elided.
pub(crate) fn ensure_source_formal_parameter_values(
    graph: &mut SsaGraph,
    machine_context: &SourceMachineContext,
) {
    let mut existing = unique_entry_values_by_storage(graph);
    let materialize = |graph: &mut SsaGraph,
                       existing: &mut BTreeMap<CanonicalStorageId, Option<ValueId>>,
                       storage: CanonicalStorageId| {
        if existing.contains_key(&storage) {
            return;
        }
        let name = machine_context
            .register_name(storage)
            .unwrap_or_else(|| format!("reg:{:x}", storage.offset));
        if let Some(value) = graph.ensure_entry_value(SSAVar::initial(name, storage.size), storage)
        {
            existing.insert(storage, Some(value));
        }
    };
    for parameter in source_formal_parameter_projections(machine_context) {
        materialize(graph, &mut existing, parameter.graph_storage);
    }
    // The convention's own argument slots, not the interface's parameter list:
    // what a call may read implicitly is fixed by the calling convention, and
    // a function whose captured prototype declares fewer parameters than it
    // passes through is exactly the case that needs this.
    if let Some(slots) = machine_context.convention_slots() {
        let argument_storages = slots.argument_slots().to_vec();
        for storage in argument_storages {
            materialize(graph, &mut existing, storage);
        }
    }
}

/// The value a storage holds immediately before one operation.
///
/// The walk `semantic.rs` does for a call's own arguments, named and made
/// public: an engine that wants to know what a body put in a register before
/// a call has no other way to ask, and a second walk would be a second answer
/// to one question.
pub fn value_reaching(
    artifact: &crate::SsaArtifact,
    block_addr: u64,
    op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ValueId> {
    match reaching_abi_value_in_block_with_policy(
        artifact.function(),
        artifact.graph(),
        artifact.machine_context(),
        block_addr,
        op_index,
        storage,
        true,
    )? {
        ReachingAbiState::Value(value) => Some(value),
        // A carrier the callee is entered with unchanged is a fact about this
        // function's own entry, not a value this body computed.
        ReachingAbiState::PreservedEntry => None,
    }
}

/// The predicates one function's branches establish, for a test that needs
/// the same narrowing the analysis phase gets.
#[cfg(test)]
pub(crate) fn collect_predicate_facts_for_test(
    function: &SSAFunction,
    graph: &SsaGraph,
) -> PredicateFacts {
    collect_predicate_facts(function, graph)
}
