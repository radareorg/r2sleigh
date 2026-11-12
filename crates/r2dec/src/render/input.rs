//! D0: what the staged pipeline reads, and nothing else (doc/adr-decompiler-rewrite.md); the
//! fields are private, so a stage reaches the sealed facts only through these accessors.

use r2ssa::{PreparedFunctionCertificates, SSAFunction, SemanticObligationInventory, SsaGraph};
use r2types::{FunctionControlFacts, ReturnTypeFact, SourceOwnedFunctionFacts};

/// One sealed function as the staged pipeline reads it.
pub struct RenderInput<'a> {
    facts: &'a SourceOwnedFunctionFacts,
    ptr_bits: u32,
}

impl<'a> RenderInput<'a> {
    pub fn new(facts: &'a SourceOwnedFunctionFacts, ptr_bits: u32) -> Self {
        Self { facts, ptr_bits }
    }

    /// The sealed function: its blocks, operations, CFG, dominators and loops.
    pub fn function(&self) -> &'a SSAFunction {
        self.facts.source().function()
    }

    /// The sealed artifact, which D2 canonicalises once.
    pub(crate) fn artifact(&self) -> &'a r2ssa::SsaArtifact {
        self.facts.source()
    }

    /// The value graph over the sealed function, by dense id.
    pub fn graph(&self) -> &'a SsaGraph {
        self.facts.source().graph()
    }

    pub fn certificates(&self) -> &'a PreparedFunctionCertificates {
        self.facts.source().certificates()
    }

    pub fn obligations(&self) -> &'a SemanticObligationInventory {
        self.facts.source().obligations()
    }

    pub fn control(&self) -> Option<&'a FunctionControlFacts> {
        self.facts.report().control()
    }

    /// What the function returns, as the type analysis decided it once.
    pub fn return_type(&self) -> Option<&'a ReturnTypeFact> {
        self.facts.return_type()
    }

    /// What the analysis declares parameter `slot` to be, where it is admissible at `width_bits`.
    pub fn parameter_declaration(
        &self,
        slot: usize,
        width_bits: u32,
    ) -> Option<r2types::CTypeLike> {
        self.facts.parameter_declaration(slot, width_bits)
    }

    /// What parameter `slot` is declared, where its row's basis states a type: debug information
    /// or a library's prototype, its own or a declared callee slot's (D261), never a body reading.
    pub fn declared_parameter(&self, slot: usize, width_bits: u32) -> Option<r2types::CTypeLike> {
        (self.facts.parameter_declaration_fact(slot, width_bits))
            .filter(|fact| fact.confidence.basis.states_type())
            .map(|fact| fact.value)
    }

    /// The one name of parameter `slot` (r2types `FunctionFacts::parameter_name`).
    pub fn parameter_name(&self, slot: usize) -> String {
        self.facts.report().parameter_name(slot)
    }

    /// The structures the function's parameter accesses lay out, by tag (doc/adr-aggregates.md).
    pub fn inferred_aggregates(
        &self,
    ) -> &'a std::collections::BTreeMap<String, r2types::AggregateDefinition> {
        &self.facts.report().type_facts().inferred_aggregates
    }

    /// Each parameter that points to an inferred structure, with the member at each offset.
    pub fn parameter_structures(
        &self,
    ) -> &'a std::collections::BTreeMap<usize, r2types::ParameterStructure> {
        &self.facts.report().type_facts().parameter_structures
    }

    /// The types the function's declaration states, as one graph: its aggregates' layouts.
    pub fn type_graph(&self) -> Option<&'a r2ssa::SourceTypeGraph> {
        (self.facts.source().machine_context().function_interface())
            .and_then(r2ssa::SourceFunctionInterface::type_graph)
    }

    /// The types the callee of the call at `inst` declares, as its own interface's graph states them.
    pub fn callee_type_graph(&self, inst: r2ssa::InstId) -> Option<&'a r2ssa::SourceTypeGraph> {
        let site = (self.facts.report().callsites())?
            .by_callsite
            .get(inst)?
            .call_site_id;
        (self.facts.source().call_site_interface(site))?
            .exact_callee_interface()?
            .type_graph()
    }

    /// The type graph each call site's callee declares, in call-site order.
    pub fn callee_type_graphs(&self) -> impl Iterator<Item = &'a r2ssa::SourceTypeGraph> + '_ {
        let sites = (self.facts.report().callsites()).into_iter();
        sites
            .flat_map(|callsites| callsites.by_callsite.values())
            .filter_map(|facts| {
                (self.facts.source().call_site_interface(facts.call_site_id))?
                    .exact_callee_interface()?
                    .type_graph()
            })
    }

    /// How many parameters the function takes at least, where its interface states only a floor
    /// (D37), with the causes it names; the proof line carries it to the header (D100).
    pub fn arity_floor(&self) -> Option<(usize, &'a r2source::SourceArityFloor)> {
        let interface = self.artifact().machine_context().function_interface()?;
        let floor = interface.arity_floor()?;
        Some((interface.arity().floor(), floor))
    }

    /// Whether arguments continue past the parameters, as the function's interface states.
    pub fn variadic(&self) -> bool {
        (self.artifact().machine_context().function_interface())
            .is_some_and(r2source::SourceFunctionInterface::is_variadic)
    }

    /// Who each call site calls, as r2types resolved it.
    /// Whether the result's second register is open: the body writes it on every return and no
    /// call read decides whether it holds half of the result (doc/adr-language-profile.md, item 1).
    pub fn open_second_result(&self) -> bool {
        (self.artifact().machine_context().function_interface())
            .and_then(r2source::SourceFunctionInterface::result_carriers)
            .is_some_and(|carriers| carriers.second.is_some())
    }

    /// The result lanes where the body's returns contradict the declaration, which is kept (D331).
    pub fn body_disputed_lanes(
        &self,
    ) -> Vec<(r2source::SourceTypedLane, r2source::SourceBodyLane)> {
        (self.artifact().machine_context().function_interface())
            .map(|own| own.body_disputed_lanes().collect())
            .unwrap_or_default()
    }

    /// How many call sites take a prototype the source declares (a library table's or the binary's).
    pub fn declared_call_prototypes(&self) -> usize {
        self.facts
            .report()
            .callsites()
            .into_iter()
            .flat_map(|facts| facts.by_callsite.values())
            .filter(|fact| {
                fact.callee_signature_types
                    .as_ref()
                    .is_some_and(|types| types.grade() <= r2source::Grade::Declared)
            })
            .count()
    }

    /// The prototype the call at `inst` calls its callee with, where the source states, proves or
    /// declares its types; a reading nothing proves is no declaration.
    pub fn declared_callee_signature(
        &self,
        inst: r2ssa::InstId,
    ) -> Option<&'a r2types::FunctionType> {
        let graded = (self.facts.report().callsites())
            .and_then(|callsites| callsites.by_callsite.get(inst))
            .filter(|facts| {
                (facts.callee_signature_types.as_ref())
                    .is_some_and(|types| types.grade() <= r2source::Grade::Declared)
            })
            .and_then(|facts| facts.callee_signature.as_ref());
        let identity = (self.callee_resolution())
            .and_then(|resolution| resolution.identity_for_callsite(inst))
            .filter(|identity| {
                identity
                    .signature_source
                    .is_some_and(|s| s.is_declaration())
            })
            .and_then(|identity| identity.signature.as_ref());
        graded.or(identity)
    }

    /// The carrier's bits where the callee of the call at `inst` states no result (D201, D330).
    pub fn callee_unproven_bits(&self, inst: r2ssa::InstId) -> Option<u32> {
        (self.facts.report().callsites())
            .and_then(|callsites| callsites.by_callsite.get(inst))
            .and_then(|facts| facts.callee_unproven_bits)
    }

    /// The callee's own projection for the call at `inst`, from a callee body the capture holds,
    /// whose carriers r2ssa matched to the call site: its header's types, and its unproven carrier.
    pub fn callee_projection(
        &self,
        inst: r2ssa::InstId,
    ) -> Option<(&'a r2types::FunctionType, Option<u32>)> {
        let facts = (self.facts.report().callsites())
            .and_then(|callsites| callsites.by_callsite.get(inst))
            .filter(|facts| {
                (facts.callee_signature_types.as_ref())
                    .is_some_and(|types| types.basis == r2source::Basis::CarrierWidth)
            })?;
        Some((facts.callee_signature.as_ref()?, facts.callee_unproven_bits))
    }

    /// The text at each address the capture proves holds it: static data the program never writes,
    /// as r2engine states it in the snapshot.
    pub fn string_literals(&self) -> &'a std::collections::BTreeMap<u64, String> {
        self.facts.report().display_names().strings()
    }

    /// The container's name for each data address the function refers to.
    pub fn data_symbols(&self) -> &'a std::collections::BTreeMap<u64, String> {
        self.facts.report().display_names().symbols()
    }

    /// The type the program's debug information declares at each named data address.
    pub fn data_object_types(&self) -> &'a r2types::ProgramDataObjectTypeFacts {
        &self.facts.report().type_facts().program_data_objects
    }

    /// The name of each function the function calls, by entry.
    pub fn function_names(&self) -> &'a std::collections::BTreeMap<u64, String> {
        self.facts.report().display_names().functions()
    }

    pub fn callee_resolution(&self) -> Option<&'a r2types::CalleeResolutionFacts> {
        self.facts.report().callee_resolution()
    }

    /// The name the source states for the function, where it states one.
    pub fn name(&self) -> Option<&'a str> {
        self.function().name.as_deref()
    }

    pub const fn ptr_bits(&self) -> u32 {
        self.ptr_bits
    }
}
