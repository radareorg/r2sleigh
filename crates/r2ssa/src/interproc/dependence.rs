//! Which of a function's formals each value is computed from.
//!
//! The reach a summary states through an argument is only as sound as its
//! account of every access that could touch the argument's object. An access
//! the classifier cannot place (`Unknown`), or places through an argument at
//! no stated offset, could be anywhere its address can point; a call the
//! local summary cannot see into can reach wherever its arguments point. Both
//! used to be answered for the whole function at once -- an unknown call
//! emptied every argument's reach, and an unknown access emptied none -- when
//! the fact that decides it is per formal: which formals the address, or the
//! argument, is computed from.
//!
//! `dep(v) ⊆ formals` is a forward union over def-use. A formal seeds its own
//! bit; an operation unions its operands'; a merge unions its inputs'. A load
//! is computed from nothing, unless it reads back a stack slot, when it is
//! computed from what was stored there: a pointer read out of an argument's
//! object is a pointee (`crate::address`), whose accesses belong to another
//! object and are summarized on their own path. A call's definitions may be
//! computed from whatever it was passed.
//!
//! Bits only grow, and each value holds one per formal, so every pass over the
//! blocks either adds a bit or is the last: at most `k·V + 1` passes for `k`
//! formals, and in practice the loop nesting depth plus two.

use std::collections::BTreeMap;

use crate::abi::AbiProfile;
use crate::function::SsaArtifact;
use crate::graph::{InstId, ValueId};
use crate::op::SSAOp;
use crate::semantic::{ReachingStorageState, SourceCallArgumentValue};
use crate::{CallBoundarySlot, CanonicalStorageId};

/// The formals a bit stands for: bit `i` is formal `i`, and the last bit every
/// formal from there on.
const LAST_BIT: usize = 63;

fn bit(formal: usize) -> u64 {
    1u64 << formal.min(LAST_BIT)
}

/// The formal-dependence set of every value of one function.
pub(crate) struct FormalDependence {
    bits: Vec<u64>,
    /// Formals a call could reach through without the summary seeing how.
    unseen: u64,
    /// What each argument register holds before each instruction, for the
    /// calls no callee states the arity of: only computed where one exists.
    carriers: BTreeMap<CanonicalStorageId, BTreeMap<InstId, ReachingStorageState>>,
}

impl FormalDependence {
    pub(crate) fn of(prepared: &SsaArtifact, abi: &AbiProfile) -> Self {
        let graph = prepared.graph();
        let mut bits = vec![0u64; graph.values.len()];
        for (value, formal) in formal_values(prepared, abi) {
            bits[value.0 as usize] |= bit(formal);
        }
        let indirect = prepared
            .call_sites()
            .by_id
            .values()
            .any(|call| call.direct_target.is_none());
        let carriers = abi
            .argument_storages()
            .filter(|_| indirect)
            .map(|storage| {
                let states = crate::semantic::reaching_storage_states_before(
                    prepared.function(),
                    graph,
                    storage,
                );
                (storage, states)
            })
            .collect();
        let mut dependence = Self {
            bits,
            unseen: 0,
            carriers,
        };
        while dependence.pass(prepared) {}
        dependence
    }

    /// The formals `value` is computed from.
    pub(crate) fn bits_of(&self, value: ValueId) -> u64 {
        self.bits.get(value.0 as usize).copied().unwrap_or(0)
    }

    /// The formals the values a call is handed are computed from: the values
    /// its boundary names where the boundary is complete, and every formal
    /// where it is not -- a carrier the body never wrote still holds the
    /// formal it arrived with.
    ///
    /// A call with no direct target has no callee to state its arity: the
    /// boundary lists the carriers this body wrote, and the callee may read
    /// every other argument register as well, whatever it holds there.
    pub(crate) fn passed_to_call(&self, prepared: &SsaArtifact, call: crate::CallSiteId) -> u64 {
        let Some(boundary) = prepared
            .facts()
            .boundaries
            .calls
            .get(&call)
            .filter(|boundary| boundary.arguments_complete)
        else {
            return u64::MAX;
        };
        let listed = boundary
            .arguments
            .iter()
            .map(|argument| match argument.value {
                SourceCallArgumentValue::Value(value) => self.bits_of(value),
                SourceCallArgumentValue::PreservedEntry => match argument.slot {
                    CallBoundarySlot::Register { storage, .. } => {
                        self.entry_bits(prepared, storage)
                    }
                    // A stack word nothing here stored is the caller's.
                    CallBoundarySlot::Stack(_) => 0,
                },
            })
            .fold(0, |left, right| left | right);
        let direct = prepared
            .call_sites()
            .by_id
            .get(&call)
            .is_some_and(|site| site.direct_target.is_some());
        if direct {
            return listed;
        }
        let named = boundary
            .arguments
            .iter()
            .filter_map(|argument| match argument.slot {
                CallBoundarySlot::Register { storage, .. } => Some(storage),
                CallBoundarySlot::Stack(_) => None,
            })
            .collect::<Vec<_>>();
        self.carriers
            .iter()
            .filter(|(storage, _)| !named.contains(storage))
            .map(|(storage, states)| match states.get(&boundary.at) {
                Some(ReachingStorageState::Value(value)) => self.bits_of(*value),
                Some(ReachingStorageState::PreservedEntry) => self.entry_bits(prepared, *storage),
                Some(ReachingStorageState::Unknown | ReachingStorageState::Conflict) | None => {
                    u64::MAX
                }
            })
            .fold(listed, |left, right| left | right)
    }

    /// The formals whose objects every call this function makes can reach.
    pub(crate) fn passed_to_calls(&self) -> u64 {
        self.unseen
    }

    /// The formal an entry register holds, as a bit.
    fn entry_bits(&self, prepared: &SsaArtifact, storage: CanonicalStorageId) -> u64 {
        let graph = prepared.graph();
        graph
            .values
            .iter()
            .filter(|value| {
                value.var.version == 0
                    && graph.def_inst(value.id).is_none()
                    && value.canonical_storage.is_some_and(|held| {
                        crate::semantic::register_storages_overlap(held, storage)
                    })
            })
            .map(|value| self.bits_of(value.id))
            .fold(0, |left, right| left | right)
    }

    /// One pass over the blocks in order; whether any value gained a bit.
    fn pass(&mut self, prepared: &SsaArtifact) -> bool {
        let function = prepared.function();
        let graph = prepared.graph();
        let mut changed = false;
        for block in function.blocks() {
            for phi in &block.phis {
                let inputs = phi
                    .sources
                    .iter()
                    .map(|(_, source)| self.var_bits(prepared, source))
                    .fold(0, |left, right| left | right);
                changed |= self.raise(prepared, &phi.dst, inputs);
            }
            // What the last call in this block was handed: the definitions
            // that follow it are what it left, and may be any of it.
            let mut last_call = 0u64;
            for (index, op) in block.ops.iter().enumerate() {
                let inputs = match op {
                    SSAOp::Load { dst, .. }
                    | SSAOp::LoadLinked { dst, .. }
                    | SSAOp::LoadGuarded { dst, .. } => self.reloaded_bits(prepared, dst),
                    SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                        last_call = graph
                            .inst_id_for_op_site(block.addr, index)
                            .and_then(|inst| prepared.call_sites().by_inst.get(&inst))
                            .map_or(u64::MAX, |call| self.passed_to_call(prepared, *call));
                        let unseen = self.unseen | last_call;
                        changed |= unseen != self.unseen;
                        self.unseen = unseen;
                        continue;
                    }
                    SSAOp::CallDefine { .. } => last_call,
                    op => op
                        .sources()
                        .into_iter()
                        .map(|source| self.var_bits(prepared, source))
                        .fold(0, |left, right| left | right),
                };
                if let Some(dst) = op.dst() {
                    changed |= self.raise(prepared, dst, inputs);
                }
            }
        }
        changed
    }

    /// A load's bits: what was stored in the stack slot it reads back.
    fn reloaded_bits(&self, prepared: &SsaArtifact, dst: &crate::SSAVar) -> u64 {
        prepared
            .graph()
            .value_id_for_var(dst)
            .and_then(|value| prepared.stack_reload_certificate_for_value(value))
            .map_or(0, |reload| self.bits_of(reload.source))
    }

    fn var_bits(&self, prepared: &SsaArtifact, var: &crate::SSAVar) -> u64 {
        prepared
            .graph()
            .value_id_for_var(var)
            .map_or(0, |value| self.bits_of(value))
    }

    fn raise(&mut self, prepared: &SsaArtifact, var: &crate::SSAVar, bits: u64) -> bool {
        let Some(value) = prepared.graph().value_id_for_var(var) else {
            return false;
        };
        let Some(held) = self.bits.get_mut(value.0 as usize) else {
            return false;
        };
        let raised = *held | bits;
        let changed = raised != *held;
        *held = raised;
        changed
    }
}

/// Every value that is a formal, and which argument of the summary it is.
///
/// Numbered the way the summary's `Arg { index }` regions are: by the ABI's
/// argument slot for the formal's storage, and by the preparation's own index
/// where the storage is a lane of a slot rather than the slot.
fn formal_values(prepared: &SsaArtifact, abi: &AbiProfile) -> Vec<(ValueId, usize)> {
    let Some(prep) = prepared.function().decompile_prep_facts() else {
        return Vec::new();
    };
    let graph = prepared.graph();
    // Only the values a formal arrives as: an entry register, or the lane
    // projection minted from one. A copy or a reload of a formal is also a
    // formal to the address facts, but it is computed from the entry value
    // and inherits its bit; seeding it by its own storage would name the
    // register it was copied into rather than the argument it holds.
    prep.formal_parameter_bases
        .iter()
        .chain(prep.formal_parameters.iter())
        .filter_map(|(var, index)| {
            let value = graph.value_id_for_var(var)?;
            let entry = graph.def_inst(value).is_none();
            if !entry && graph.formal_projection_storage(value).is_none() {
                return None;
            }
            let storage = graph.value(value)?.canonical_storage;
            let argument = storage
                .filter(|_| entry)
                .and_then(|storage| abi.exact_argument_index_for_storage(storage))
                .unwrap_or(*index);
            Some((value, argument))
        })
        .collect()
}

/// Whether a set of bits names `formal`.
pub(crate) fn names_formal(bits: u64, formal: usize) -> bool {
    bits & bit(formal) != 0
}
