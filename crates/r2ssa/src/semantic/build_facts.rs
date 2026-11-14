//! What a static phase reads of a build: its blocks and the call sites the source names, and
//! nothing a callee states, so a restatement keeps it (doc/adr-callee-builds.md, D289).

use crate::cfg::CFG;
use crate::domtree::DomTree;
use crate::function::SSAFunction;
use crate::machine_context::{SourceCallSiteIdentity, SourceMachineContext};
use crate::var::CanonicalStorageId;
use r2il::RegisterProjection;

/// A build's shape and its source's call sites; the `build_facts_reads_a_callee_fact` Dylint
/// allows only these reads (doc/adr-callee-builds.md, "D289 as built").
#[derive(Clone, Copy)]
pub struct BuildFacts<'a> {
    function: &'a SSAFunction,
    context: Option<&'a SourceMachineContext>,
}

impl<'a> BuildFacts<'a> {
    /// The function's shape alone, with no source.
    pub const fn bare(function: &'a SSAFunction) -> Self {
        Self {
            function,
            context: None,
        }
    }

    pub(crate) const fn of(
        function: &'a SSAFunction,
        context: Option<&'a SourceMachineContext>,
    ) -> Self {
        Self { function, context }
    }

    pub const fn entry(&self) -> u64 {
        self.function.entry
    }

    pub fn root(&self) -> u64 {
        self.function.root()
    }

    pub fn block_addrs(&self) -> &'a [u64] {
        self.function.block_addrs()
    }

    pub fn cfg(&self) -> &'a CFG {
        self.function.cfg()
    }

    pub fn domtree(&self) -> &'a DomTree {
        self.function.domtree()
    }

    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        self.function.predecessors(addr)
    }

    pub fn successors(&self, addr: u64) -> Vec<u64> {
        self.function.successors(addr)
    }

    pub fn dominates(&self, a: u64, b: u64) -> bool {
        self.function.dominates(a, b)
    }

    pub fn stack_pointer_carrier(&self) -> Option<CanonicalStorageId> {
        self.context
            .and_then(SourceMachineContext::stack_pointer_carrier)
    }

    /// The carrier lane a register write lands in, as the lift's geometry states.
    pub fn register_projection(
        &self,
        written: CanonicalStorageId,
    ) -> Option<&'a RegisterProjection> {
        self.context?.register_projection(written)
    }

    pub fn raw_call_site_at(&self, instruction: u64) -> Option<SourceCallSiteIdentity> {
        self.context?.raw_call_site_at(instruction)
    }

    pub fn is_tail_call_site(&self, identity: SourceCallSiteIdentity) -> bool {
        self.context
            .is_some_and(|context| context.is_tail_call_site(identity))
    }

    pub(crate) fn slot_target(&self, identity: SourceCallSiteIdentity) -> Option<u64> {
        self.context?.slot_target(identity)
    }

    pub fn callee_linkage(
        &self,
        identity: SourceCallSiteIdentity,
    ) -> r2source::AdvisoryCalleeLinkage {
        self.context
            .map_or(r2source::AdvisoryCalleeLinkage::Unknown, |context| {
                context.callee_linkage(identity)
            })
    }
}
