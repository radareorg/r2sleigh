//! A body's memory facts, which read nothing liveness, spans, carriers or obligations say.

use std::sync::Arc;

use super::*;

/// What a build alone decides, read through `BuildFacts`: a kept build's second recovery borrows
/// it unchanged (doc/adr-callee-builds.md, "D289 as built").
pub(crate) struct StaticPrefix {
    pub(crate) addresses: Arc<AddressProvenanceFacts>,
    pub(crate) call_sites: Arc<CallSiteFacts>,
    pub(crate) predicates: Arc<PredicateFacts>,
    pub(crate) values: Arc<crate::values::ValueRanges>,
    /// Each value's content before memory evidence joins two; a collection copies it, `O(V)`.
    content: crate::liveness::ValueContent,
}

impl StaticPrefix {
    /// The four static phases and the content base. `O(collection)` once per build.
    pub(crate) fn collect<C: crate::SsaWorkControl + ?Sized>(
        function: &SSAFunction,
        machine_context: Option<&SourceMachineContext>,
        (prep, graph): (Option<&crate::function::DecompilePrepFacts>, &SsaGraph),
        control: &C,
    ) -> Result<Self, crate::SsaPrepareError> {
        let mut phases = PhaseRecorder::open("static", function);
        let build = BuildFacts::of(function, machine_context);
        macro_rules! phase {
            ($name:literal, $size:expr) => {{
                phases.mark($name, $size);
                control.poll()?;
            }};
        }
        let addresses = collect_address_provenance(build, prep, graph);
        phase!("addresses", graph.insts.len());
        let call_sites = collect_call_sites(build, graph, prep);
        phase!("call_sites", call_sites.by_id.len());
        let mut predicates = collect_predicate_facts(build, prep, graph);
        phase!("predicates", 0);
        let values = crate::values::solve_value_ranges(graph, build, prep, &predicates);
        // A table dispatch switches on what indexes the table's read, known only now.
        for (block_addr, selector) in crate::indirect::dispatch_selectors(graph, &values) {
            if let Some(fact) = predicates.switches.get_mut(&block_addr) {
                fact.selector.get_or_insert(selector);
            }
        }
        let (bounded, total) = values.bounded();
        r2il::refusal_evidence!("value-ranges", "{bounded} of {total} values bounded");
        phase!("values", bounded);
        let content =
            crate::liveness::ValueContent::of(graph, |storage| build.register_projection(storage));
        control.static_prefix_built();
        Ok(Self {
            addresses: Arc::new(addresses),
            call_sites: Arc::new(call_sites),
            predicates: Arc::new(predicates),
            values: Arc::new(values),
            content,
        })
    }

    /// The content base, for one collection to join its memory evidence into.
    pub(crate) fn content(&self) -> crate::liveness::ValueContent {
        self.content.clone()
    }
}

/// The facts a collection reads of memory before it asks anything about liveness.
pub(crate) struct MemoryPrefix {
    pub(crate) objects: ObjectModel,
    pub(crate) memory: MemorySSAFacts,
    pub(crate) memory_accesses: BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    pub(crate) member_run_stores: crate::dense::IdMap<InstId, MemberRunStoreCertificate>,
}

impl MemoryPrefix {
    pub(super) fn collect<C: crate::SsaWorkControl + ?Sized>(
        body: Body<'_>,
        (prefix, declared_slots): (&StaticPrefix, &DeclaredStackSlots),
        phases: &mut PhaseRecorder,
        control: &C,
    ) -> Result<Self, crate::SsaPrepareError> {
        let Body {
            function,
            prep,
            graph,
            machine_context,
        } = body;
        macro_rules! phase {
            ($name:literal, $size:expr) => {{
                phases.mark($name, $size);
                control.poll()?;
            }};
        }
        let (objects, memory) = collect_object_and_memory_facts(
            function,
            prep,
            graph,
            &prefix.addresses,
            machine_context,
            declared_slots,
            &prefix.values,
        )?;
        control.frame_built();
        phase!("objects", objects.objects.len());
        let (memory_accesses, member_run_stores) = collect_structured_memory_access_facts(
            graph,
            &objects,
            &memory,
            machine_context,
            declared_slots,
        );
        phase!("accesses", memory_accesses.len());
        Ok(Self {
            objects,
            memory,
            memory_accesses,
            member_run_stores,
        })
    }
}
