//! A body's memory facts, which read nothing liveness, spans, carriers or obligations say.

use super::*;

/// The facts every collection reads before it asks anything about liveness.
pub(crate) struct MemoryPrefix {
    pub(crate) addresses: AddressProvenanceFacts,
    pub(crate) call_sites: CallSiteFacts,
    pub(crate) declared_slots: DeclaredStackSlots,
    pub(crate) predicates: PredicateFacts,
    /// Each loop header with the blocks that branch back to it.
    pub(crate) latches_by_header: BTreeMap<u64, BTreeSet<u64>>,
    pub(crate) values: crate::values::ValueRanges,
    pub(crate) objects: ObjectModel,
    pub(crate) memory: MemorySSAFacts,
    pub(crate) memory_accesses: BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    pub(crate) member_run_stores: BTreeMap<InstId, MemberRunStoreCertificate>,
}

impl MemoryPrefix {
    pub(super) fn collect<C: crate::SsaWorkControl + ?Sized>(
        function: &SSAFunction,
        graph: &SsaGraph,
        machine_context: Option<&SourceMachineContext>,
        phases: &mut PhaseRecorder,
        control: &C,
    ) -> Result<Self, crate::SsaExecutionStopReason> {
        macro_rules! phase {
            ($name:literal, $size:expr) => {{
                phases.mark($name, $size);
                control.poll()?;
            }};
        }
        let addresses = collect_address_provenance(function, graph, machine_context);
        phase!("addresses", graph.insts.len());
        let call_sites = collect_call_sites(
            function,
            graph,
            function.decompile_prep_facts(),
            machine_context,
        );
        phase!("call_sites", call_sites.by_id.len());
        let declared_slots = collect_declared_stack_slots(machine_context);
        let mut predicates = collect_predicate_facts(function, graph);
        phase!("predicates", 0);
        // The value fixpoint widens at loop headers, which the back edges alone decide.
        let latches_by_header = latches_by_header(function);
        let widen_at = latches_by_header.keys().copied().collect::<BTreeSet<_>>();
        let values = crate::values::solve_value_ranges(graph, function, &predicates, &widen_at);
        // A table dispatch switches on what indexes the table's read, known only now.
        for (block_addr, selector) in crate::indirect::dispatch_selectors(function, graph, &values)
        {
            if let Some(fact) = predicates.switches.get_mut(&block_addr) {
                fact.selector.get_or_insert(selector);
            }
        }
        let (bounded, total) = values.bounded();
        r2il::refusal_evidence!("value-ranges", "{bounded} of {total} values bounded");
        phase!("values", bounded);
        let (objects, memory) = collect_object_and_memory_facts(
            function,
            graph,
            &addresses,
            &call_sites,
            machine_context,
            &declared_slots,
            &values,
        );
        phase!("objects", objects.objects.len());
        let (memory_accesses, member_run_stores) = collect_structured_memory_access_facts(
            function,
            graph,
            &objects,
            &memory,
            machine_context,
            &declared_slots,
        );
        phase!("accesses", memory_accesses.len());
        Ok(Self {
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
        })
    }
}

/// What the references query reads: the frame's objects and which loads reload a store.
pub(crate) struct ReferenceFacts {
    pub(crate) objects: ObjectModel,
    pub(crate) stack_reloads: BTreeMap<ValueId, StackReloadSourceCertificate>,
}

impl ReferenceFacts {
    /// The memory prefix, and the stack reloads read from it; nothing else.
    pub(crate) fn collect(
        function: &SSAFunction,
        graph: &SsaGraph,
        machine_context: &SourceMachineContext,
    ) -> Self {
        let mut phases = PhaseRecorder::open("references", function);
        let prefix = MemoryPrefix::collect(
            function,
            graph,
            Some(machine_context),
            &mut phases,
            &crate::control::UncheckedSsaWorkControl,
        )
        .expect("an unchecked control never stops");
        let stack_reloads = collect_stack_reload_source_certificates(
            function,
            graph,
            &prefix.objects,
            &prefix.memory,
            &prefix.memory_accesses,
        );
        Self {
            objects: prefix.objects,
            stack_reloads,
        }
    }
}
