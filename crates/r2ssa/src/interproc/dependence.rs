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
//! of memory the function does not own is computed from nothing: a pointer
//! read out of an argument's object is a pointee (`crate::address`), whose
//! accesses belong to another object and are summarized on their own path. A
//! load of the function's own frame is computed from every value stored where
//! it may read, and a call's definitions from whatever it was passed.
//!
//! **The frame.** A formal stored into the frame is still the function's to
//! account for, and where it goes next depends on who can read the place it
//! was stored at. A frame object is private when no address naming it leaves
//! the body (`SsaArtifact::stack_object_is_private`); only this body's own
//! loads read it, and they carry the stored formal on. Where any frame
//! object's address leaves, every frame place is exposed: until the frame is
//! partitioned into objects with extents (P4), an escaped address says
//! nothing about where its object starts -- `&h.x` handed out reaches `h.p`
//! below it (`container_of`) as well as anything above. That includes the
//! slots promotion took out of memory: promotion keeps in memory only what
//! lies at or above an escaped address, so a formal the machine stores below
//! one is, in the prepared function, a write of a promoted slot, and it is
//! exposed the same way. A formal stored at an exposed place can be read by
//! whatever the address reached, as surely as if it were handed over, so the
//! summary counts it as unplaced, and a call handed a frame address is handed
//! every formal stored at an exposed place.
//!
//! Bits only grow, and each value holds one per formal, so every pass over the
//! blocks either adds a bit or is the last: at most `k·V + 1` passes for `k`
//! formals, and in practice the loop nesting depth plus two. The frame's
//! store-to-load relation is computed once, over distinct locations, before
//! the passes.

use std::collections::BTreeMap;

use r2il::SpaceId;

use crate::abi::AbiProfile;
use crate::function::SsaArtifact;
use crate::graph::{InstId, ValueId};
use crate::op::SSAOp;
use crate::semantic::{
    MemoryLocation, ObjectKind, ObjectModel, ReachingStorageState, RelativeMemoryAddress,
    SourceCallArgumentValue, memory_locations_may_alias,
};
use crate::var::SSAVar;
use crate::{CallBoundarySlot, CanonicalStorageId, ObjectId};

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
    /// What the frame carries from the stores into it to the loads out of it.
    frame: FrameTraffic,
    /// The formals stored at an exposed frame place, as of the last pass.
    exposed: u64,
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
            frame: FrameTraffic::of(prepared),
            exposed: 0,
        };
        while dependence.pass(prepared) {}
        dependence
    }

    /// The formals stored where something outside the function can read
    /// them: an exposed frame place, or a promoted slot of an escaping frame.
    pub(crate) fn exposed_formals(&self) -> u64 {
        self.exposed
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
                SourceCallArgumentValue::Value(value) => self.handed(prepared, value),
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
                Some(ReachingStorageState::Value(value)) => self.handed(prepared, *value),
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

    /// The formals a call handed `value` is handed: the value's own, and,
    /// where it is a frame address, every formal stored at a place of the
    /// frame the address exposes.
    fn handed(&self, prepared: &SsaArtifact, value: ValueId) -> u64 {
        let names_frame = prepared
            .objects()
            .object_for_value(value, SpaceId::Ram)
            .is_some_and(|object| is_frame_object(prepared.objects(), object));
        self.bits_of(value) | if names_frame { self.exposed } else { 0 }
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
        let exposed = self
            .frame
            .exposed
            .iter()
            .map(|value| self.bits_of(*value))
            .fold(0, |left, right| left | right);
        let mut changed = exposed != self.exposed;
        self.exposed = exposed;
        for block in prepared.function().blocks() {
            for phi in &block.phis {
                let inputs = phi
                    .sources
                    .iter()
                    .map(|(_, source)| self.var_bits(prepared, source))
                    .fold(0, |left, right| left | right);
                changed |= self.raise(prepared, &phi.dst, inputs);
            }
            changed |= self.ops_pass(prepared, block);
        }
        changed
    }

    /// One block's operations, in order; whether any value gained a bit.
    fn ops_pass(&mut self, prepared: &SsaArtifact, block: &crate::block::SSABlock) -> bool {
        let mut changed = false;
        // What the last call in this block was handed: the definitions that
        // follow it are what it left, and may be any of it.
        let mut last_call = 0u64;
        for (index, op) in block.ops.iter().enumerate() {
            if matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                last_call = prepared
                    .graph()
                    .inst_id_for_op_site(block.addr, index)
                    .and_then(|inst| prepared.call_sites().by_inst.get(&inst))
                    .map_or(u64::MAX, |call| self.passed_to_call(prepared, *call));
                let unseen = self.unseen | last_call;
                changed |= unseen != self.unseen;
                self.unseen = unseen;
                continue;
            }
            let Some(dst) = op.dst() else {
                continue;
            };
            let inputs = self.op_bits(prepared, op, last_call);
            changed |= self.raise(prepared, dst, inputs);
        }
        changed
    }

    /// The bits an operation's output is computed from.
    fn op_bits(&self, prepared: &SsaArtifact, op: &SSAOp, last_call: u64) -> u64 {
        match op {
            SSAOp::Load { dst, .. }
            | SSAOp::LoadLinked { dst, .. }
            | SSAOp::LoadGuarded { dst, .. } => self.reloaded_bits(prepared, dst),
            SSAOp::CallDefine { .. } => last_call,
            SSAOp::AtomicCAS(swap) => {
                self.reloaded_bits(prepared, &swap.dst)
                    | op.sources()
                        .into_iter()
                        .map(|source| self.var_bits(prepared, source))
                        .fold(0, |left, right| left | right)
            }
            op => op
                .sources()
                .into_iter()
                .map(|source| self.var_bits(prepared, source))
                .fold(0, |left, right| left | right),
        }
    }

    /// A load's bits: what was stored where it may read, where that is the
    /// function's own frame, and what the stack-reload certificate names.
    fn reloaded_bits(&self, prepared: &SsaArtifact, dst: &SSAVar) -> u64 {
        let Some(value) = prepared.graph().value_id_for_var(dst) else {
            return 0;
        };
        let certified = prepared
            .stack_reload_certificate_for_value(value)
            .map_or(0, |reload| self.bits_of(reload.source));
        self.frame
            .sources
            .get(&value)
            .into_iter()
            .flatten()
            .map(|stored| self.bits_of(*stored))
            .fold(certified, |left, right| left | right)
    }

    fn var_bits(&self, prepared: &SsaArtifact, var: &SSAVar) -> u64 {
        prepared
            .graph()
            .value_id_for_var(var)
            .map_or(0, |value| self.bits_of(value))
    }

    fn raise(&mut self, prepared: &SsaArtifact, var: &SSAVar, bits: u64) -> bool {
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

/// What the function's own frame carries: which stored values each load of it
/// may read, and which values something outside the function could read.
#[derive(Default)]
struct FrameTraffic {
    /// Each load of the frame, and the values stored where it may read.
    sources: BTreeMap<ValueId, Vec<ValueId>>,
    /// Every value written to the frame where an escaping address can reach
    /// it: stored to it, or written to a slot promotion took out of it.
    exposed: Vec<ValueId>,
}

/// One access of the frame: where the memory facts put it, or `None` where
/// they give it no place, which may be anywhere in the frame.
type FramePlace = Option<MemoryLocation>;

impl FrameTraffic {
    /// One pass over the operations for the frame's accesses; the may-alias
    /// relation is asked once per pair of distinct places, not per pair of
    /// accesses, and a slot read and written many times is one place.
    fn of(prepared: &SsaArtifact) -> Self {
        let graph = prepared.graph();
        let objects = prepared.objects();
        let mut loads = Vec::<(ValueId, FramePlace)>::new();
        let mut stores = Vec::<(InstId, ValueId, FramePlace)>::new();
        for block in prepared.function().blocks() {
            for (index, op) in block.ops.iter().enumerate() {
                let Some(inst) = graph.inst_id_for_op_site(block.addr, index) else {
                    continue;
                };
                let (addr, space, loaded, stored) = match op {
                    SSAOp::Load { dst, addr, space }
                    | SSAOp::LoadLinked {
                        dst, addr, space, ..
                    }
                    | SSAOp::LoadGuarded {
                        dst, addr, space, ..
                    } => (addr, *space, Some(dst), None),
                    SSAOp::Store { addr, val, space }
                    | SSAOp::StoreGuarded {
                        addr, val, space, ..
                    }
                    | SSAOp::StoreConditional {
                        addr, val, space, ..
                    } => (addr, *space, None, Some(val)),
                    SSAOp::AtomicCAS(swap) => (
                        &swap.addr,
                        swap.space,
                        Some(&swap.dst),
                        Some(&swap.replacement),
                    ),
                    _ => continue,
                };
                let is_frame = prepared
                    .object_for_var(addr, space)
                    .is_some_and(|object| is_frame_object(objects, object));
                if !is_frame {
                    continue;
                }
                let place = |facts: Option<&[MemoryLocation]>| -> FramePlace {
                    let [location] = facts? else {
                        return None;
                    };
                    let mut location = location.clone();
                    // An indexed address is somewhere in its object the
                    // machine computes; the memory facts state its base.
                    if graph
                        .value_id_for_var(addr)
                        .is_some_and(|value| objects.index_for_address(value).is_some())
                    {
                        location.address = RelativeMemoryAddress::Unknown;
                    }
                    Some(location)
                };
                if let Some(value) = loaded.and_then(|dst| graph.value_id_for_var(dst)) {
                    let uses = prepared.memory().uses_by_inst.get(&inst).map(|uses| {
                        uses.iter()
                            .map(|fact| fact.location.clone())
                            .collect::<Vec<_>>()
                    });
                    loads.push((value, place(uses.as_deref())));
                }
                if let Some(value) = stored.and_then(|val| graph.value_id_for_var(val)) {
                    let defs = prepared.memory().defs_by_inst.get(&inst).map(|defs| {
                        defs.iter()
                            .map(|fact| fact.location.clone())
                            .collect::<Vec<_>>()
                    });
                    stores.push((inst, value, place(defs.as_deref())));
                }
            }
        }

        let mut stored_at = BTreeMap::<&FramePlace, Vec<ValueId>>::new();
        for (_, value, place) in &stores {
            stored_at.entry(place).or_default().push(*value);
        }
        let mut read_at = BTreeMap::<&FramePlace, Vec<ValueId>>::new();
        for (value, place) in &loads {
            read_at.entry(place).or_default().push(*value);
        }
        let mut sources = BTreeMap::<ValueId, Vec<ValueId>>::new();
        for (read, readers) in &read_at {
            let reached = stored_at
                .iter()
                .filter(|(written, _)| places_may_alias(objects, read, written))
                .flat_map(|(_, values)| values.iter().copied())
                .collect::<Vec<_>>();
            if reached.is_empty() {
                continue;
            }
            for reader in readers {
                sources.insert(*reader, reached.clone());
            }
        }

        // Until the frame is laid out as objects with extents (P4), an address
        // that leaves the function says nothing about where the object it
        // names starts or ends. So one escaping frame address exposes every
        // frame place, promoted ones included, and a function none escapes
        // from exposes none.
        let escapes = objects.objects.keys().any(|object| {
            is_frame_object(objects, *object) && !prepared.stack_object_is_private(*object)
        });
        let exposed = if escapes {
            stores
                .iter()
                .map(|(_, value, _)| *value)
                .chain(promoted_slot_writes(prepared))
                .collect()
        } else {
            Vec::new()
        };
        Self { sources, exposed }
    }
}

/// Every value an operation writes to a frame slot promotion took out of
/// memory: the machine stores it to the frame; the prepared function holds it
/// in a variable.
fn promoted_slot_writes(prepared: &SsaArtifact) -> impl Iterator<Item = ValueId> + '_ {
    let graph = prepared.graph();
    prepared
        .function()
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter_map(SSAOp::dst)
        .filter_map(move |dst| {
            let value = graph.value_id_for_var(dst)?;
            graph
                .value(value)?
                .canonical_storage
                .as_ref()
                .and_then(crate::promote::promoted_slot_offset)
                .map(|_| value)
        })
}

/// Whether two frame places may share a byte; a place the facts do not state
/// may share one with anything.
fn places_may_alias(objects: &ObjectModel, left: &FramePlace, right: &FramePlace) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => memory_locations_may_alias(objects, left, right),
        _ => true,
    }
}

fn is_frame_object(objects: &ObjectModel, object: ObjectId) -> bool {
    objects.object(object).is_some_and(|fact| {
        matches!(
            fact.kind,
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
        )
    })
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
