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

    /// The name the source states for the function, where it states one.
    pub fn name(&self) -> Option<&'a str> {
        self.function().name.as_deref()
    }

    pub const fn ptr_bits(&self) -> u32 {
        self.ptr_bits
    }
}
