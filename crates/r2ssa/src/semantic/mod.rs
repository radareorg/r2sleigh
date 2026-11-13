//! Canonical semantic sidecar facts for prepared SSA functions.
//!
//! These facts keep object, memory, predicate, and call-site provenance in
//! `r2ssa` so downstream crates stop reconstructing them independently.

mod assumptions;
mod boundaries;
mod call_sites;
mod certificates;
mod control_domains;
mod covering;
mod declared_slots;
mod facts;
mod frame_reach;
mod loops;
mod objects;
mod predicates;
mod prefix;
mod private_objects;
mod reaching;
mod shared;
mod structured;
mod supervisor;
#[cfg(test)]
mod tests;
mod trips;

pub use supervisor::SupervisorCall;

pub(crate) use assumptions::*;
pub(crate) use boundaries::*;
pub(crate) use call_sites::*;
pub use certificates::*;
pub use control_domains::*;
pub(crate) use declared_slots::*;
pub use facts::*;
pub(crate) use frame_reach::{Access, Walked, walk};
pub use frame_reach::{CallFrameReach, FramePoints, FrameReach};
pub(crate) use loops::*;
pub(crate) use objects::*;
pub(crate) use predicates::*;
pub(crate) use prefix::*;
pub(crate) use private_objects::*;
pub(crate) use reaching::ReachingStorage;
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
use crate::obligation::{SeedingFacts, SemanticObligationInventory};
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
    /// The bytes of each value the function's meaning reads; `None` where an exit hands registers
    /// to code outside the graph.
    pub demanded: Option<crate::demand::DemandedBytes>,
    pub obligations: SemanticObligationInventory,
    pub assumptions: AssumptionSet,
    pub applied_assumption_bindings: Vec<PreparedAssumptionBinding>,
    pub assumption_usage: AssumptionUsageReport,
    /// What the body states at its boundary, where its interface was recovered from it: the slot
    /// uses its parameters were minted from and its result lanes' bytes (doc/adr-call-boundary.md).
    pub body_boundary: Option<std::sync::Arc<crate::body_boundary::BodyBoundary>>,
}

/// What one collection reads, so the phases take one name rather than six.
pub(crate) struct CollectionOver<'a> {
    pub(crate) function: &'a SSAFunction,
    /// The prep facts of `function`, where it was prepared: the sealed
    /// function's, or a provisional function's own.
    pub(crate) prep: Option<&'a crate::function::DecompilePrepFacts>,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) assumptions: &'a AssumptionSet,
    pub(crate) machine_context: Option<&'a SourceMachineContext>,
    /// Which caller asked, so a trace says which of the three collections it is.
    pub(crate) site: &'static str,
    pub(crate) certified: Certified,
}

/// Which certificates a collection derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Certified {
    Whole,
    /// The return controls alone, which is all interface recovery reads (doc/adr-callee-builds.md).
    ReturnControls,
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
    bytes: Option<usize>,
}

impl PhaseRecorder {
    fn open(site: &'static str, function: &SSAFunction) -> Self {
        let tracing = r2il::refusal_evidence::tracing();
        Self {
            tracing,
            who: if tracing {
                format!("{site}@{:#x}", function.entry)
            } else {
                String::new()
            },
            blocks: function.num_blocks(),
            since: std::time::Instant::now(),
            bytes: tracing.then(r2il::allocation::live_bytes).flatten(),
        }
    }

    fn mark(&mut self, name: &str, size: usize) {
        if !self.tracing {
            return;
        }
        let live = r2il::allocation::live_bytes();
        let grew = r2il::allocation::Evidence(r2il::allocation::grown(self.bytes, live));
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
    /// The facts of a function, or the pass that moved a state past its stated height, which
    /// refuses the function (doc/adr-fixpoint.md).
    pub fn collect(
        function: &SSAFunction,
        graph: &SsaGraph,
    ) -> Result<Self, crate::fixpoint::Exhausted> {
        Self::collect_unchecked(CollectionOver {
            function,
            prep: None,
            graph,
            assumptions: &AssumptionSet::default(),
            machine_context: None,
            site: "collect",
            certified: Certified::Whole,
        })
    }

    pub(crate) fn collect_with_context(
        function: &SSAFunction,
        prep: Option<&crate::function::DecompilePrepFacts>,
        graph: &SsaGraph,
        assumptions: &AssumptionSet,
        machine_context: &SourceMachineContext,
        site: &'static str,
    ) -> Result<Self, crate::fixpoint::Exhausted> {
        Self::collect_unchecked(CollectionOver {
            function,
            prep,
            graph,
            assumptions,
            machine_context: Some(machine_context),
            site,
            certified: Certified::Whole,
        })
    }

    /// The facts interface recovery reads of a function built but not sealed.
    pub(crate) fn collect_for_recovery(
        function: &SSAFunction,
        prep: Option<&crate::function::DecompilePrepFacts>,
        graph: &SsaGraph,
        machine_context: &SourceMachineContext,
    ) -> Result<Self, crate::fixpoint::Exhausted> {
        Self::collect_unchecked(CollectionOver {
            function,
            prep,
            graph,
            assumptions: &AssumptionSet::default(),
            machine_context: Some(machine_context),
            site: "recover",
            certified: Certified::ReturnControls,
        })
    }

    fn collect_unchecked(over: CollectionOver<'_>) -> Result<Self, crate::fixpoint::Exhausted> {
        match Self::collect_inner(over, &crate::control::UncheckedSsaWorkControl) {
            Ok((facts, _)) => Ok(facts),
            Err(crate::SsaPrepareError::Exhausted(exhausted)) => Err(exhausted),
            Err(_) => unreachable!("an unchecked control never stops"),
        }
    }

    /// The same collection, stopping between phases when the run is cancelled.
    ///
    /// Preparation is the most expensive thing the engine does and it used to
    /// be the one stretch a deadline could not reach, so a cancelled request
    /// still paid for every phase of it.
    pub(crate) fn collect_with_context_and_control<C: crate::SsaWorkControl + ?Sized>(
        over: CollectionOver<'_>,
        control: &C,
    ) -> Result<(Self, CollectedLiveness), crate::SsaPrepareError> {
        Self::collect_inner(over, control)
    }

    fn collect_inner<C: crate::SsaWorkControl + ?Sized>(
        over: CollectionOver<'_>,
        control: &C,
    ) -> Result<(Self, CollectedLiveness), crate::SsaPrepareError> {
        let CollectionOver {
            function,
            prep,
            graph,
            assumptions,
            machine_context,
            site,
            certified,
        } = over;
        let mut phases = PhaseRecorder::open(site, function);
        let MemoryPrefix {
            addresses,
            call_sites,
            declared_slots,
            predicates,
            values,
            objects,
            memory,
            memory_accesses,
            member_run_stores,
        } = MemoryPrefix::collect(
            Body {
                function,
                prep,
                graph,
                machine_context,
            },
            &mut phases,
            control,
        )?;
        macro_rules! phase {
            ($name:literal, $size:expr) => {{
                phases.mark($name, $size);
                control.poll()?;
            }};
        }
        let return_storages = (machine_context.and_then(SourceMachineContext::function_interface))
            .into_iter()
            .flat_map(|interface| interface.return_kind().storages())
            .collect::<Vec<_>>();
        let live_out = crate::liveout::FunctionLiveOut::compute(function, graph, &return_storages);
        let boundaries = collect_source_boundary_facts(
            Body {
                function,
                prep,
                graph,
                machine_context,
            },
            &call_sites,
            &live_out,
            &objects,
        );
        phase!("boundaries", boundaries.calls.len());
        // The one liveness of this function. A call's conventional read of a
        // register its certified boundary does not pass is no read the text
        // performs, and two reads of the same bytes the same memory versions
        // reach hold one content; both are known here, before anything reads
        // a span, so liveness is computed once, with them.
        let ignored_reads = crate::function::unpassed_call_reads(graph, &boundaries);
        let mut content = crate::liveness::ValueContent::of(graph, machine_context);
        content.declare_same_content(&crate::function::same_content_reads(
            &memory_accesses,
            &memory,
        ));
        let live_values = crate::liveness::ValueLiveness::compute_with_relocations(
            graph,
            &live_out,
            &crate::dense::IdMap::default(),
            content,
            &ignored_reads,
        );
        let storage_spans = StorageSpans::compute(graph, &live_values);
        phase!("liveness", 0);
        let (loops, inductions) = collect_structured_loop_facts(
            Body {
                function,
                prep,
                graph,
                machine_context,
            },
            LoopEvidence {
                predicates: &predicates,
                values: &values,
            },
            &live_out,
            &storage_spans,
        );
        phase!("loops", loops.len());
        let structured = StructuredDataflowFacts {
            unstructured_cycle_blocks: collect_unstructured_cycle_blocks(graph, &loops),
            inductions,
            loops,
            memory_accesses,
            member_run_stores,
            recursive_calls: collect_structured_recursive_call_facts(function, &call_sites),
        };
        phase!("structured", structured.memory_accesses.len());
        let control_domains = collect_control_domain_facts(function, &predicates, &structured)?;
        phase!("control_domains", 0);
        let private_stack_objects = private_stack_objects(&objects);
        // Before the obligations, because whether an access is a statement at
        // all depends on it: a round trip leaves the object as it found it, so
        // neither half is an observable effect.
        let memory_round_trips = collect_memory_round_trips(graph, &structured);
        let obligations = SemanticObligationInventory::collect(
            graph,
            &structured,
            &boundaries,
            machine_context,
            &SeedingFacts::new(
                &private_stack_objects,
                &memory_round_trips,
                &meeting_arms(function),
                (function.compiler_inserted().iter())
                    .filter_map(|op| graph.inst_for_op(op))
                    .collect(),
            ),
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
            prep,
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
            obligations: &obligations,
        };
        let certificates = match certified {
            Certified::Whole => collect_prepared_function_certificates(
                body,
                derived,
                &unobserved,
                &live_out,
                &private_stack_objects,
                &declared_slots,
                memory_round_trips,
                &addresses,
            )?,
            Certified::ReturnControls => {
                let (machine_return_controls, machine_return_control_by_inst) =
                    collect_machine_return_control_certificates(
                        &boundaries,
                        graph,
                        &objects,
                        &structured,
                        &unobserved,
                    );
                PreparedFunctionCertificates {
                    machine_return_controls,
                    machine_return_control_by_inst,
                    ..PreparedFunctionCertificates::default()
                }
            }
        };
        phase!("certificates", certificates.stack_slots.len());
        let (applied_assumption_bindings, assumption_usage) = collect_prepared_assumption_usage(
            graph,
            &objects,
            &predicates,
            assumptions,
            machine_context,
        );
        phase!("assumptions", 0);
        let demanded = demanded(body, (&call_sites, &boundaries), &live_out, &ignored_reads);
        let facts = Self {
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
            demanded,
            obligations,
            assumptions: assumptions.clone(),
            applied_assumption_bindings,
            assumption_usage,
            body_boundary: None,
        };
        Ok((
            facts,
            CollectedLiveness {
                live_out,
                ignored_reads,
            },
        ))
    }
}

/// What `DemandedBytes` says of `body`, where every exit is named.
fn demanded(
    body: Body<'_>,
    calls: (&CallSiteFacts, &SourceBoundaryFacts),
    live_out: &crate::liveout::FunctionLiveOut,
    ignored: &BTreeSet<crate::graph::UseSite>,
) -> Option<crate::demand::DemandedBytes> {
    let interface = (body.machine_context).and_then(SourceMachineContext::function_interface);
    let result = interface.and_then(returned_bytes);
    // Such a return reads no register, so no return block is left unnamed.
    let unread = interface.is_some_and(returns_no_register);
    // A return a written result leaves undefined (case 1) reads no register either.
    let undefined = (calls.1.returns.values())
        .filter(|boundary| boundary.result_unproven && result.is_some())
        .filter_map(|boundary| body.graph.block_addr_of(boundary.at))
        .collect::<BTreeSet<_>>();
    let without = match unread {
        true => crate::liveout::FunctionLiveOut::default(),
        false => live_out.without(&undefined),
    };
    let live_out = &without;
    let (tails, reads) = tail_reads(body, calls).unwrap_or_default();
    crate::demand::exits_are_named_beside(body.function, live_out, &tails).then(|| {
        crate::demand::DemandedBytes::of_returning(body.graph, live_out, (result, &reads), ignored)
    })
}

/// Blocks that leave by a tail transfer, and the bytes of each value their callees read.
type TailReads = (BTreeSet<u64>, Vec<(ValueId, crate::bytes::ByteMask)>);

/// Tail-transfer exits and what their callees read: each argument and the result lane's `logical`
/// bytes; `None` where a tail states no narrower width (doc/adr-call-boundary.md, "S2 as built").
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the tail exits of one body: a few blocks, where a dense index costs O(blocks)"
    )
)]
fn tail_reads(
    body: Body<'_>,
    (call_sites, boundaries): (&CallSiteFacts, &SourceBoundaryFacts),
) -> Option<TailReads> {
    let mut tails = BTreeSet::new();
    let mut reads = Vec::new();
    let tail_calls =
        (call_sites.by_id.values()).filter(|call| call.transfer == CallSiteTransfer::TailCall);
    for call in tail_calls {
        let boundary = boundaries.calls.get(&call.id)?;
        let named =
            boundary.complete && boundary.arguments_complete && boundary.variadic == Some(false);
        let Some(SourceCallResult::Register { storage, width }) = boundary.result_kind else {
            return None;
        };
        if !named || width.fills(storage) {
            return None;
        }
        let block = body
            .graph
            .inst(call.at)
            .and_then(|inst| body.graph.block(inst.block))?;
        tails.insert(block.addr);
        for argument in &boundary.arguments {
            if let SourceCallArgumentValue::Value(value) = argument.value {
                reads.push((value, crate::bytes::ByteMask::All));
            }
        }
        let lane = crate::liveout::FunctionLiveOut::reaching(
            body.function,
            body.graph,
            storage,
            block.addr,
        );
        for value in lane.iter() {
            let held = body
                .graph
                .value(value)
                .and_then(|held| held.canonical_storage);
            let mask = match held.is_some_and(|held| held.offset == storage.offset) {
                true => crate::bytes::ByteMask::whole(u32::from(width.logical)),
                false => crate::bytes::ByteMask::All,
            };
            reads.push((value, mask));
        }
    }
    Some((tails, reads))
}

/// Whether no return of `interface` reads a register: a `void` one hands back nothing, and one whose
/// result is `Unproven` is a residual that stops before any caller reads (ROADMAP D340).
pub(crate) fn returns_no_register(interface: &r2source::SourceFunctionInterface) -> bool {
    matches!(
        interface.return_kind(),
        r2source::SourceFunctionReturn::Void | r2source::SourceFunctionReturn::Unproven
    )
}

/// The bytes of its result register a function's caller reads: the low bytes the declared type
/// occupies where the interface places one there (an `int` in RAX), else the whole register.
pub fn returned_bytes(interface: &r2source::SourceFunctionInterface) -> Option<CanonicalStorageId> {
    let r2source::SourceFunctionReturn::Register { storage } = interface.return_kind() else {
        return None;
    };
    let declared = (interface.return_logical_value())
        .map(|value| value.carrier())
        .filter(|carrier| carrier.offset_bits() == 0 && carrier.size_bits() % 8 == 0)
        .and_then(|carrier| u32::try_from(carrier.size_bits() / 8).ok())
        .filter(|bytes| *bytes > 0);
    Some(CanonicalStorageId {
        size: declared.map_or(storage.size, |bytes| bytes.min(storage.size)),
        ..storage
    })
}

/// What the sealed artifact keeps of the liveness a collection computed: the value liveness and
/// storage spans the loop facts read go with the collection (doc/adr-memory-model.md, decision 1).
pub(crate) struct CollectedLiveness {
    pub(crate) live_out: crate::liveout::FunctionLiveOut,
    /// Reads the text never performs: a call's conventional read of a
    /// register the certified call does not pass.
    pub(crate) ignored_reads: std::collections::BTreeSet<crate::graph::UseSite>,
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
    for (_, graph_storage) in source_formal_parameter_projections(machine_context)
        .iter()
        .filter_map(|parameter| parameter.register())
    {
        materialize(graph, &mut existing, graph_storage);
    }
    // The convention's own argument slots, not the interface's parameter list:
    // what a call may read implicitly is fixed by the calling convention, and
    // a function whose captured prototype declares fewer parameters than it
    // passes through is exactly the case that needs this.
    if let Some(slots) = machine_context.convention() {
        let argument_storages = slots
            .arguments(r2source::convention::SlotClass::Integer)
            .to_vec();
        for storage in argument_storages {
            materialize(graph, &mut existing, storage);
        }
    }
}

/// The value a storage holds immediately before one operation of a sealed function: the walk a
/// call's own arguments take, which needs the seal and no collected fact.
pub(crate) fn value_reaching(
    sealed: &crate::Sealed,
    machine_context: &SourceMachineContext,
    op: crate::OpId,
    storage: CanonicalStorageId,
) -> Option<ValueId> {
    let graph = sealed.graph();
    let (block_addr, op_index) = graph.walk_start(graph.inst_for_op(op)?)?;
    match reaching_abi_value_in_block_with_policy(
        sealed.function(),
        Some(sealed.decompile_prep_facts()),
        graph,
        machine_context,
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
    collect_predicate_facts(function, None, graph)
}

/// The blocks whose conditional branch sends both arms to one block: a direct transfer.
fn meeting_arms(function: &crate::SSAFunction) -> BTreeSet<u64> {
    (function.cfg().blocks())
        .filter(|block| {
            matches!(block.terminator, crate::cfg::BlockTerminator::ConditionalBranch {
                true_target, false_target } if true_target == false_target)
        })
        .map(|block| block.addr)
        .collect()
}
