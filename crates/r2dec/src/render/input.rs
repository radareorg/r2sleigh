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

    /// What parameter `slot` is declared, where a declaration states the function's own types: its
    /// debug information or a library's prototype, never a reading of its body.
    pub fn declared_parameter(&self, slot: usize, width_bits: u32) -> Option<r2types::CTypeLike> {
        let interface = self.facts.source().machine_context().function_interface()?;
        (interface.types().grade() <= r2source::Grade::Declared)
            .then(|| self.parameter_declaration(slot, width_bits))
            .flatten()
    }

    /// Who each call site calls, as r2types resolved it.
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
        let key = r2types::CallsiteKey { at: inst };
        let graded = (self.facts.report().callsites())
            .and_then(|callsites| callsites.by_callsite.get(&key))
            .filter(|facts| {
                (facts.callee_signature_types.as_ref())
                    .is_some_and(|types| types.grade() <= r2source::Grade::Declared)
            })
            .and_then(|facts| facts.callee_signature.as_ref());
        let identity = (self.callee_resolution())
            .and_then(|resolution| resolution.identity_for_callsite(key))
            .filter(|identity| {
                identity
                    .signature_source
                    .is_some_and(|s| s.is_declaration())
            })
            .and_then(|identity| identity.signature.as_ref());
        graded.or(identity)
    }

    /// The text at each address the capture proves holds it: static data the program never writes,
    /// as r2engine states it in the snapshot. The one table legacy's literals read.
    pub fn string_literals(&self) -> &'a std::collections::BTreeMap<u64, String> {
        self.facts.report().display_names().strings()
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
