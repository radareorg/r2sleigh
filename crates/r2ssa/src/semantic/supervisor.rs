//! What each instruction that enters the kernel asks it to do.
//!
//! The instruction is one Sleigh says enters the supervisor
//! (`SSAFunction::enters_supervisor`, from the language's own user-operation
//! table), found in a body the walk proved reachable -- never a byte pattern
//! searched for, which matches inside other instructions and in data. The
//! number is the value of the platform's number register that reaches the
//! instruction, where the value analysis proves it is one value: no
//! emulation, so no step budget to run out of, and a number that is not
//! proven is said to be unknown rather than guessed.
//!
//! Cost: one reaching-storage pass, O(V + E), and one lookup per call.

use super::*;

/// One instruction that enters the kernel, and the call number it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SupervisorCall {
    /// The instruction's address.
    pub address: u64,
    /// Whether it is the platform's system-call instruction; `hvc` and `smc` are not.
    pub system: bool,
    /// The number, read only for a system call, where every path to the instruction leaves the
    /// register holding the same proven value.
    pub number: Option<u64>,
}

impl crate::SsaArtifact {
    /// Every supervisor call in the body, in address order, with the number
    /// `number` holds as each system call is made.
    pub fn supervisor_calls(&self, number: CanonicalStorageId) -> Vec<SupervisorCall> {
        let function = self.function();
        let graph = self.graph();
        let sites = (graph.blocks.iter())
            .flat_map(|block| graph.op_insts(block.id).iter().copied())
            .filter(|inst| {
                graph
                    .op(*inst)
                    .is_some_and(|op| function.enters_supervisor(op))
            })
            .collect::<Vec<_>>();
        if sites.is_empty() {
            return Vec::new();
        }
        let mut reaching = super::ReachingStorage::new(function, graph, number);
        let mut calls = sites
            .into_iter()
            .filter_map(|site| {
                let address = graph.instruction_for_inst(site)?;
                let system = graph
                    .op(site)
                    .is_some_and(|op| function.enters_system_call(op));
                let number = match system.then(|| reaching.before(site)).flatten() {
                    Some(ReachingStorageState::Value(value)) => self.proven_constant(value),
                    _ => None,
                };
                Some(SupervisorCall {
                    address,
                    system,
                    number,
                })
            })
            .collect::<Vec<_>>();
        calls.sort_unstable();
        calls.dedup();
        calls
    }

    /// The one value `value` can hold, where the analysis proves it.
    fn proven_constant(&self, value: ValueId) -> Option<u64> {
        let values = self.values();
        match (values.lower_bound(value), values.upper_bound(value)) {
            (Some(low), Some(high)) if low == high => Some(low),
            _ => None,
        }
    }
}
