//! What the body proves about itself, phase by phase.

mod call_results;
mod expressions;
mod returns;
mod shared;
pub(crate) use shared::exact_copy_chain_to_entry_storage;
mod stack;

pub use call_results::*;
pub use expressions::*;
pub use returns::*;
pub use shared::*;
pub use stack::*;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofNodeId {
    pub owner: &'static str,
    pub kind: &'static str,
    pub anchor: u64,
    pub ordinal: u64,
}

impl ProofNodeId {
    pub const fn new(owner: &'static str, kind: &'static str, anchor: u64, ordinal: u64) -> Self {
        Self {
            owner,
            kind,
            anchor,
            ordinal,
        }
    }

    pub const fn loop_certificate(header: u64, loop_id: LoopId) -> Self {
        Self::new("r2ssa", "loop", header, loop_id.0 as u64)
    }

    pub const fn switch_certificate(block_addr: u64) -> Self {
        Self::new("r2ssa", "switch", block_addr, 0)
    }
}

impl std::fmt::Display for ProofNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:0x{:x}:{}",
            self.owner, self.kind, self.anchor, self.ordinal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopCertificate {
    pub proof_node: ProofNodeId,
    pub loop_id: LoopId,
    pub header: u64,
    pub latches: Vec<u64>,
    pub body: Vec<u64>,
    pub exits: Vec<u64>,
    pub condition: Option<PredicateId>,
    /// Counted-loop construction, present only when the condition reads this
    /// exact induction phi and one renderable entry member dominates it.
    pub for_loop: Option<ForLoopCertificate>,
}

/// Name-free certificate for moving a loop carrier's dominating entry and
/// latch update into a C `for` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForLoopCertificate {
    pub induction_phi: ValueId,
    pub induction_init: ValueId,
    pub induction_update: ValueId,
    pub latch: u64,
    pub initializer: LoopCarrierEdgeValue,
}

/// The operations a certified dispatch performs to reach its target.
///
/// Grown backwards from the transfer to a fixpoint: an operation belongs to the
/// dispatch when everything that reads it is already in the dispatch, which can
/// only be decided once its readers are known. The selector stops the walk
/// twice over -- the switch spells it, and the guard that bounds the index
/// reads it too.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
/// The private-frame loads whose result reaches no observation: one pass over the loads and
/// their uses, O(accesses + uses), reading `DeadPhis`'s closure rather than recomputing it.
fn unobserved_private_reads(
    graph: &crate::SsaGraph,
    structured: &StructuredDataflowFacts,
    private_objects: &BTreeSet<ObjectId>,
    unobserved: &crate::deadphi::DeadPhis,
    live_out: &crate::liveout::FunctionLiveOut,
) -> crate::dense::IdSet<InstId> {
    let unread = |value: ValueId| {
        !live_out.contains(value)
            && (graph.use_sites(value).iter())
                .all(|site| unobserved.unobserved_uses().contains(site))
    };
    (structured.memory_accesses.values())
        .filter(|access| {
            !access.is_write
                && access.provenance_complete
                && private_objects.contains(&access.object)
        })
        .map(|access| access.id.inst)
        .filter(|inst| {
            graph.inst(*inst).is_some_and(|inst| {
                matches!(
                    inst.payload,
                    crate::graph::InstPayload::Op(crate::SSAOp::Load { .. })
                ) && inst.output.is_some_and(unread)
            })
        })
        .collect()
}

fn dispatch_operations(
    graph: &crate::SsaGraph,
    unobserved: &crate::deadphi::DeadPhis,
    block_addr: u64,
    selector: Option<ValueId>,
) -> Vec<InstId> {
    let Some(block) = graph
        .block_by_addr
        .get(&block_addr)
        .and_then(|id| graph.block(*id))
    else {
        return Vec::new();
    };
    let Some(transfer) = block.insts.iter().copied().rev().find(|inst| {
        matches!(
            graph.inst(*inst).map(|inst| &inst.payload),
            Some(crate::graph::InstPayload::Op(
                crate::SSAOp::BranchInd { .. } | crate::SSAOp::Switch { .. }
            ))
        )
    }) else {
        return Vec::new();
    };
    // The operations of this block the transfer is computed by, other than
    // the selector: a definition joins once every use of its value is an
    // operation already found. A worklist: each value keeps the uses not
    // yet found, and its definition joins when the last one is.
    let mut found = crate::dense::IdSet::<InstId>::default();
    found.insert(transfer);
    let mut outstanding = crate::dense::IdMap::<ValueId, Vec<InstId>>::default();
    let mut pending = vec![transfer];
    while let Some(inst) = pending.pop() {
        let Some(inputs) = graph.inst(inst).map(|inst| inst.inputs.clone()) else {
            continue;
        };
        for value in inputs {
            if selector == Some(value) {
                continue;
            }
            let Some(definition) = graph.def_inst(value) else {
                continue;
            };
            if found.contains(definition)
                || graph.inst(definition).map(|inst| inst.block) != Some(block.id)
            {
                continue;
            }
            // A use no observation depends on (a flag the add also computes) keeps nothing outside.
            let uses = outstanding.get_or_insert_with(value, || {
                (graph.use_sites(value).iter())
                    .filter(|site| !unobserved.unobserved_uses().contains(site))
                    .map(|site| site.inst)
                    .collect()
            });
            uses.retain(|user| *user != inst);
            if uses.iter().all(|user| found.contains(*user)) && found.insert(definition) {
                pending.push(definition);
            }
        }
    }
    found.iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCertificate {
    pub proof_node: ProofNodeId,
    pub block_addr: u64,
    pub selector: Option<ValueId>,
    pub cases: Vec<(u64, u64)>,
    pub default: Option<u64>,
    /// The operations the dispatch performs to reach its target: scaling the
    /// selector, addressing the table, reading the entry, transferring to it.
    ///
    /// A structured `switch` is made of these, so the certificate owns them and
    /// the renderer never sees them. Leaving them for the renderer to explain
    /// meant the table read named a value the plan had elided, and the only
    /// account left was a marked gap over a dispatch the engine had proved.
    pub dispatch: Vec<InstId>,
    /// The bound test that alone admits control to the dispatch, where it admits exactly the case values.
    pub guard: Option<SwitchGuardCertificate>,
}

/// A predicate whose one edge into the dispatch holds exactly when the selector is a case value, so its other edge is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchGuardCertificate {
    pub predicate: PredicateId,
    /// The block the predicate ends, the dispatch's only predecessor.
    pub block_addr: u64,
    /// Where control goes for every selector value that is no case.
    pub default: u64,
}

/// The guard whose edge into `dispatch` admits exactly the selector values `cases` names; `None` where anything else can reach it.
fn switch_guard(
    function: &SSAFunction,
    graph: &SsaGraph,
    predicates: &PredicateFacts,
    fact: &SwitchPredicateFact,
) -> Option<SwitchGuardCertificate> {
    let selector = fact.selector?;
    let [guard] = function.predecessors(fact.block_addr)[..] else {
        return None;
    };
    let [assumption] = &predicates.block_assumptions.get(&fact.block_addr)?[..] else {
        return None;
    };
    let predicate = predicates.predicates.get(&assumption.predicate)?;
    let default = match assumption.truth {
        true => predicate.false_target,
        false => predicate.true_target,
    };
    if assumption.predecessor != guard || guard == fact.block_addr || default == fact.block_addr {
        return None;
    }
    let comparison = predicate.comparison.as_ref()?;
    let constant = |value: ValueId| graph.value(value)?.var.constant_bits();
    // The edge in holds `selector <u bound` for the half-open bound, whichever way round the comparison is written.
    let bound = match (comparison.kind, assumption.truth) {
        (CompareKind::Less, true) if comparison.lhs == selector => constant(comparison.rhs)?,
        (CompareKind::Less, false) if comparison.rhs == selector => {
            constant(comparison.lhs)?.checked_add(1)?
        }
        (CompareKind::LessEqual, true) if comparison.lhs == selector => {
            constant(comparison.rhs)?.checked_add(1)?
        }
        (CompareKind::LessEqual, false) if comparison.rhs == selector => constant(comparison.lhs)?,
        _ => return None,
    };
    let values = fact
        .cases
        .iter()
        .map(|(value, _)| *value)
        .collect::<BTreeSet<_>>();
    // Every value under the bound is a case and no case lies past it.
    let admitted = bound > 0 && values.iter().copied().eq(0..bound);
    admitted.then_some(SwitchGuardCertificate {
        predicate: assumption.predicate,
        block_addr: guard,
        default,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfRegionCertificate {
    pub predicate: PredicateId,
    pub block_addr: u64,
    pub true_target: u64,
    pub false_target: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionCertificate {
    pub value: ValueId,
    pub defining_inst: Option<InstId>,
    pub inputs: Vec<ValueId>,
    pub width: u32,
    pub renderable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAccessCertificate {
    pub access: StructuredAccessId,
    pub space: SpaceId,
    pub object: ObjectId,
    pub address: ValueId,
    pub value: Option<ValueId>,
    pub is_write: bool,
    pub width: u32,
    /// Where in the object the access lands, when the memory fact states it.
    pub object_offset: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlotCertificate {
    pub object: ObjectId,
    pub space: SpaceId,
    pub base: StackAddressBase,
    pub offset: i64,
    pub size: Option<u32>,
    /// Aggregate geometry for an object reached through a computed index.
    ///
    /// This is a disposition rather than an optional array: an indexed object
    /// that failed the proof must remain distinguishable from an ordinary
    /// scalar object, so no consumer can retry the inference from address
    /// spelling.
    pub array_layout: StackArrayLayoutDisposition,
    /// Exact source slot identity when the immutable function interface owns a
    /// unique slot at this base and offset. Absence grants no local or
    /// parameter-home role downstream.
    pub source_slot: Option<SourceStackSlotSpec>,
    /// Values a reload proves to be this slot's contents at their full width.
    ///
    /// A load whose reaching memory version is one store, at the slot's own
    /// location and width, holds what that store wrote; so does a copy of it.
    /// Rendering them and the slot as one variable asserts only that equality.
    pub reload_values: crate::dense::IdSet<ValueId>,
    /// Values a full-width store writes into the slot. Each is offered to the
    /// slot's object on its own, judged by identity and liveness.
    pub stored_values: crate::dense::IdSet<ValueId>,
    /// Exact proof that a source-less object lies wholly inside storage owned
    /// by this callee at every access. This is deliberately separate from a
    /// source slot: compiler-created spills and temporaries are real machine
    /// objects without becoming source variables.
    pub callee_allocation: Option<CalleeStackAllocationCertificate>,
    /// The slot is storage read at more than one width: `size` is the extent
    /// its accesses reach and it declares as bytes, not as a scalar.
    pub byte_array: bool,
    /// An access reaches the object at an index no value range bounds, so it may land anywhere.
    pub unbounded_index: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallsiteCertificate {
    pub call_site: CallSiteId,
    pub at: InstId,
    pub target: ValueId,
    pub direct_target: Option<u64>,
    pub fallthrough: Option<u64>,
    pub transfer: CallSiteTransfer,
    /// Who the site calls, as the source's symbol or relocation said; import
    /// policy rests on this and never on the shape of a name.
    pub callee_linkage: r2source::AdvisoryCalleeLinkage,
    pub argument_values: Vec<ValueId>,
    /// Whether the callee takes a variadic tail, as radare2's prototype for it
    /// says. Not a machine fact: nothing in the call instruction distinguishes
    /// a variadic callee from any other, and a rendering that spells a
    /// declaration for the callee needs to know which it is.
    pub variadic: bool,
    /// How many leading `argument_values` the callee's prototype names.
    ///
    /// Absent where no prototype described the call, which is not the same as
    /// zero: zero says the callee is declared to take nothing.
    pub fixed_argument_count: Option<usize>,
    pub variadic_argument_count_evidence: Option<VariadicCallsiteArgumentCountEvidence>,
    pub variadic_argument_count_refusal: Option<VariadicCallsiteArgumentCountRefusal>,
    pub stack_argument_values: Vec<StackCallArgumentCertificate>,
    /// The store of the return address the lift writes through the stack
    /// pointer just before the transfer, where the convention pushes one.
    pub return_address_store: Option<InstId>,
    pub argument_certificates: Vec<CallArgumentCertificate>,
    /// Whether the ABI boundary proved a reaching value for every argument the
    /// callee's interface declares.
    ///
    /// False leaves `argument_values` empty, which is not the same fact as a
    /// callee that takes none. A rendering that cannot tell them apart spells
    /// `callee()` for both.
    pub arguments_complete: bool,
    /// Whether every result value the caller observes was proved.
    pub results_complete: bool,
    /// Whether a prototype or the callee's own interface describes the call, rather than its arity being read off the registers written before it.
    pub described: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArgumentCertificate {
    pub index: usize,
    pub value: ValueId,
    pub location: CallArgumentLocation,
    pub source_inst: Option<InstId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallArgumentLocation {
    Register {
        storage: CanonicalStorageId,
    },
    Stack {
        object: ObjectId,
        offset: i64,
        memory_access: StructuredAccessId,
    },
    /// An outgoing slot promotion made a variable: the argument is the value
    /// that variable holds at the call, and no memory access carries it.
    Variable {
        offset: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProofFailure {
    pub owner: &'static str,
    pub anchor: u64,
    pub obligation: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedFunctionCertificates {
    pub loops: BTreeMap<LoopId, LoopCertificate>,
    pub switches: BTreeMap<u64, SwitchCertificate>,
    pub if_regions: BTreeMap<PredicateId, IfRegionCertificate>,
    pub expressions: crate::dense::IdMap<ValueId, ExpressionCertificate>,
    pub memory_accesses: BTreeMap<StructuredAccessId, MemoryAccessCertificate>,
    /// The accesses one instruction performs, by direction.
    pub memory_accesses_by_inst: BTreeMap<(InstId, bool), Vec<StructuredAccessId>>,
    pub stack_slots: BTreeMap<ObjectId, StackSlotCertificate>,
    pub stack_frame_round_trips: BTreeMap<ObjectId, StackFrameRoundTripCertificate>,
    pub stack_frame_round_trip_by_inst: crate::dense::IdMap<InstId, ObjectId>,
    /// Accesses that together leave the object exactly as they found it.
    pub memory_round_trips: BTreeMap<StructuredAccessId, MemoryRoundTripCertificate>,
    pub stack_geometry: StackGeometryCertificate,
    pub machine_return_controls: crate::dense::IdMap<InstId, MachineReturnControlCertificate>,
    pub machine_return_control_by_inst: crate::dense::IdMap<InstId, InstId>,
    pub callsites: BTreeMap<CallSiteId, CallsiteCertificate>,
    /// Every call's return-address store, for the ledgers that ask per op.
    pub call_return_address_stores: crate::dense::IdSet<InstId>,
    /// The operations a stack-protector check inserted, decided under `Premise::UbFreeSource`.
    pub compiler_inserted: crate::dense::IdSet<InstId>,
    /// Frame stores no code can read back, filled once the artifact is sealed
    /// (doc/adr-frame-model.md, "Dead frame stores").
    pub dead_frame_stores: crate::dense::IdSet<InstId>,
    /// Loads of a private frame object whose value no observation reads: every use is one
    /// `DeadPhis` states unobserved, and the function does not hand it back.
    pub unobserved_private_reads: crate::dense::IdSet<InstId>,
    pub call_results: crate::dense::IdMap<ValueId, CallResultCertificate>,
    pub call_results_by_inst: crate::dense::IdMap<InstId, ValueId>,
    pub call_results_by_callsite: BTreeMap<CallSiteId, Vec<ValueId>>,
    pub stack_reloads: crate::dense::IdMap<ValueId, StackReloadSourceCertificate>,
    pub returns: Vec<ReturnValueCertificate>,
    pub returns_by_inst: crate::dense::IdMap<InstId, usize>,
    /// Merges of two values that the one condition above them selects between.
    pub two_way_selections: crate::dense::IdMap<InstId, TwoWaySelectionCertificate>,
    pub failures: Vec<PreparedProofFailure>,
}

/// Remove the certified byte stride from one offset without manufacturing a
/// value. More involved affine expressions remain valid array geometry but do
/// not get a direct element spelling here; the general rewrite rules may still
/// prove those accesses independently.
pub(crate) fn stack_array_element_index(
    graph: &SsaGraph,
    byte_offset: ValueId,
    stride: u32,
) -> Option<StackArrayElementIndex> {
    let stride = u64::from(stride);
    if stride == 0 {
        return None;
    }
    if let Some(constant) = graph.value(byte_offset)?.var.constant_bits() {
        return constant
            .is_multiple_of(stride)
            .then_some(StackArrayElementIndex::Constant(constant / stride));
    }
    if stride == 1 {
        return Some(StackArrayElementIndex::Value(byte_offset));
    }
    let inst = graph.inst(graph.def_inst(byte_offset)?)?;
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    let input = |index: usize| inst.inputs.get(index).copied();
    let constant =
        |index: usize| input(index).and_then(|value| graph.value(value)?.var.constant_bits());
    match op {
        SSAOp::Copy { .. } | SSAOp::New { .. } | SSAOp::Cast { .. } | SSAOp::IntZExt { .. } => {
            stack_array_element_index(graph, input(0)?, stride as u32)
        }
        SSAOp::IntMult { .. } => match (constant(0), constant(1)) {
            (Some(scale), _) if scale == stride => Some(StackArrayElementIndex::Value(input(1)?)),
            (_, Some(scale)) if scale == stride => Some(StackArrayElementIndex::Value(input(0)?)),
            _ => None,
        },
        SSAOp::IntLeft { .. } if stride.is_power_of_two() => (constant(1)?
            == u64::from(stride.trailing_zeros()))
        .then_some(StackArrayElementIndex::Value(input(0)?)),
        _ => None,
    }
}

/// The objects some access reaches at an index no value range bounds: one pass over the accesses.
fn unbounded_index_objects(
    values: &crate::values::ValueRanges,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
) -> BTreeSet<ObjectId> {
    (structured.memory_accesses.values())
        .filter(|access| {
            objects.address_is_indexed(access.address)
                && (objects.index_for_address(access.address))
                    .is_none_or(|index| values.upper_bound(index).is_none())
        })
        .map(|access| access.object)
        .collect()
}

/// Decide array geometry once, beside the object and memory facts that own it.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
    )
)]
pub(crate) fn stack_array_layout(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    object: ObjectId,
) -> StackArrayLayoutDisposition {
    let indexed_addresses = structured
        .memory_accesses
        .values()
        .filter(|access| access.object == object && objects.address_is_indexed(access.address))
        .map(|access| access.address)
        .collect::<BTreeSet<_>>();
    if indexed_addresses.is_empty() {
        return StackArrayLayoutDisposition::NotIndexed;
    }
    // An index from a displaced base says how far from the displacement the
    // element is, not how far into the object.
    if indexed_addresses
        .iter()
        .any(|address| objects.indexed_base_is_displaced(*address))
    {
        return StackArrayLayoutDisposition::Refused(StackArrayLayoutRefusal::DisplacedIndexBase);
    }

    let mut element_width = None;
    for access in structured
        .memory_accesses
        .values()
        .filter(|access| access.object == object)
    {
        if !access.provenance_complete || access.width == 0 {
            return StackArrayLayoutDisposition::Refused(
                StackArrayLayoutRefusal::IncompleteAccessProvenance,
            );
        }
        match element_width {
            None => element_width = Some(access.width),
            Some(width) if width == access.width => {}
            Some(_) => {
                return StackArrayLayoutDisposition::Refused(
                    StackArrayLayoutRefusal::ConflictingAccessWidths,
                );
            }
        }
    }
    let Some(element_width) = element_width else {
        return StackArrayLayoutDisposition::Refused(
            StackArrayLayoutRefusal::IncompleteAccessProvenance,
        );
    };

    // How far apart the elements are is how far the index steps, which the
    // value analysis says. Taking it from the access width instead reads an
    // array of structures touched a member at a time as an array of that
    // member.
    let mut stride = None;
    for address in &indexed_addresses {
        let Some(step) = objects
            .index_for_address(*address)
            .and_then(|byte_offset| values.stride(byte_offset))
            .and_then(|step| u32::try_from(step).ok())
        else {
            continue;
        };
        if stride.is_some_and(|known| known != step) {
            return StackArrayLayoutDisposition::Refused(
                StackArrayLayoutRefusal::ConflictingStrides,
            );
        }
        stride = Some(step);
    }
    // An object every access reaches at a constant offset has no step to
    // read, and its elements are as wide as the accesses.
    let stride = stride.unwrap_or(element_width);

    // The extent bounds every indexed access, so one index no range bounds refuses it.
    let mut maximum_constant_offset = Some(0);
    let mut indexed_elements = Vec::with_capacity(indexed_addresses.len());
    for address in &indexed_addresses {
        let Some(byte_offset) = objects.index_for_address(*address) else {
            maximum_constant_offset = None;
            continue;
        };
        let bound = values.upper_bound(byte_offset);
        maximum_constant_offset = maximum_constant_offset
            .zip(bound)
            .map(|(old, b)| old.max(b));
        indexed_elements.push(StackArrayElementCertificate {
            address: *address,
            byte_offset,
            element_index: stack_array_element_index(graph, byte_offset, stride),
        });
    }
    r2il::refusal_evidence!(
        "stack-array-layout",
        "{object:?} element_width={element_width} max_offset={maximum_constant_offset:?} indexed={:?}",
        indexed_elements
            .iter()
            .map(|element| (element.address, element.byte_offset))
            .collect::<Vec<_>>()
    );
    let Some(maximum_constant_offset) = maximum_constant_offset else {
        return StackArrayLayoutDisposition::Refused(
            StackArrayLayoutRefusal::MissingConstantOffset,
        );
    };
    // The index's range is MAY evidence: every index the program executes
    // lies inside the object, so where the frame says the object must end,
    // the elements end there too, however far the range admits.
    let maximum_constant_offset = match objects.frame_ceilings.get(&object) {
        Some(ceiling) if *ceiling >= u64::from(stride) => {
            let last = (ceiling / u64::from(stride) - 1) * u64::from(stride);
            if last < maximum_constant_offset {
                r2il::refusal_evidence!(
                    "stack-array-layout",
                    "{object:?} index reaches {maximum_constant_offset}, the frame ends it at {ceiling}"
                );
            }
            maximum_constant_offset.min(last)
        }
        _ => maximum_constant_offset,
    };
    let Some(extent) = maximum_constant_offset.checked_add(u64::from(stride)) else {
        return StackArrayLayoutDisposition::Refused(StackArrayLayoutRefusal::InvalidExtent);
    };
    if extent == 0 || !extent.is_multiple_of(u64::from(stride)) {
        return StackArrayLayoutDisposition::Refused(StackArrayLayoutRefusal::InvalidExtent);
    }
    StackArrayLayoutDisposition::Proven(StackArrayLayoutCertificate {
        object,
        element_width,
        stride,
        maximum_constant_offset,
        extent,
        indexed_elements: indexed_elements.into_boxed_slice(),
    })
}

#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
pub(crate) fn counted_for_loop_certificate(
    function: &SSAFunction,
    graph: &SsaGraph,
    predicates: &PredicateFacts,
    structured: &StructuredDataflowFacts,
    loop_fact: &StructuredLoopFact,
) -> Option<ForLoopCertificate> {
    let comparison = predicates
        .predicates
        .get(&loop_fact.condition?)?
        .comparison
        .as_ref()?;
    // The clause variable is the first induction exactly one side of the
    // condition reads. The two cones are complete closures, taken once per
    // loop rather than once per carrier, so "this side does not read it" is
    // proven, never the verdict of a walk that stopped.
    let lhs_reads = dependence_cone(graph, comparison.lhs);
    let rhs_reads = dependence_cone(graph, comparison.rhs);
    let (carrier, induction) = loop_fact.carriers.iter().find_map(|carrier| {
        let induction = structured.inductions.get(carrier.phi)?;
        (lhs_reads.contains(&carrier.phi) != rhs_reads.contains(&carrier.phi))
            .then_some((carrier, induction))
    })?;
    let phi = induction.phi;
    if induction.loop_id != loop_fact.id
        || induction.header != loop_fact.header
        || loop_fact.latches.as_slice() != [induction.latch]
        || !induction.validate(graph)
    {
        return None;
    }
    let mut initializers = carrier.entries.iter().filter(|entry| {
        entry.value == induction.init
            && function.dominates(entry.predecessor, loop_fact.header)
            && graph
                .def_inst(entry.value)
                .and_then(|inst| graph.inst(inst))
                .is_some_and(|inst| {
                    matches!(inst.payload, InstPayload::Op(_))
                        && graph.block(inst.block).map(|block| block.addr)
                            == Some(entry.predecessor)
                })
    });
    let initializer = initializers.next()?;
    if initializers.next().is_some() {
        return None;
    }
    if !initializer.validate(graph) {
        return None;
    }
    if !movable_for_clause_value(
        function,
        graph,
        initializer.value,
        initializer.predecessor,
        loop_fact.header,
    ) || !movable_for_clause_value(
        function,
        graph,
        induction.update,
        induction.latch,
        loop_fact.header,
    ) {
        return None;
    }
    Some(ForLoopCertificate {
        induction_phi: phi,
        induction_init: induction.init,
        induction_update: induction.update,
        latch: induction.latch,
        initializer: *initializer,
    })
}

/// Whether moving one definition into a `for` clause preserves its block order.
///
/// The defining block must flow only to the loop header, and only inert or
/// control operations may follow the definition. This walks at most the two
/// clause-owning block suffixes per loop; it never rescans the function.
pub(crate) fn movable_for_clause_value(
    function: &SSAFunction,
    graph: &SsaGraph,
    value: ValueId,
    block_addr: u64,
    loop_header: u64,
) -> bool {
    if function.successors(block_addr).as_slice() != [loop_header] {
        return false;
    }
    let Some(definition) = graph.def_inst(value) else {
        return false;
    };
    let Some(op) = graph.op_for_inst(definition) else {
        return false;
    };
    graph.block_addr_of(definition) == Some(block_addr)
        && function.get_block(block_addr).is_some_and(|block| {
            let Some(suffix) = block
                .position(op)
                .and_then(|index| index.checked_add(1))
                .and_then(|start| block.ops().get(start..))
            else {
                return false;
            };
            suffix
                .iter()
                .all(|op| matches!(op, SSAOp::Branch { .. } | SSAOp::Nop))
        })
}

pub(crate) fn collect_prepared_function_certificates(
    body: Body<'_>,
    derived: Derived<'_>,
    unobserved: &crate::deadphi::DeadPhis,
    live_out: &crate::liveout::FunctionLiveOut,
    private_objects: &BTreeSet<ObjectId>,
    declared_slots: &DeclaredStackSlots,
    memory_round_trips: BTreeMap<StructuredAccessId, MemoryRoundTripCertificate>,
) -> PreparedFunctionCertificates {
    let Body {
        function,
        prep,
        graph,
        machine_context,
    } = body;
    let Derived {
        values,
        boundaries,
        objects,
        memory,
        predicates,
        call_sites,
        structured,
    } = derived;
    let DeclaredStackSlots {
        by_key: exact_stack_slots,
    } = declared_slots.clone();

    let loops = structured
        .loops
        .iter()
        .map(|(id, fact)| {
            (
                *id,
                LoopCertificate {
                    proof_node: ProofNodeId::loop_certificate(fact.header, *id),
                    loop_id: *id,
                    header: fact.header,
                    latches: fact.latches.clone(),
                    body: fact.body.clone(),
                    exits: fact.exits.clone(),
                    condition: fact.condition,
                    for_loop: counted_for_loop_certificate(
                        function, graph, predicates, structured, fact,
                    ),
                },
            )
        })
        .collect();

    let switches = predicates
        .switches
        .iter()
        .filter(|(_, fact)| !fact.cases.is_empty())
        .map(|(block_addr, fact)| {
            (
                *block_addr,
                SwitchCertificate {
                    proof_node: ProofNodeId::switch_certificate(*block_addr),
                    block_addr: *block_addr,
                    selector: fact.selector,
                    cases: fact.cases.clone(),
                    default: fact.default,
                    dispatch: dispatch_operations(graph, unobserved, *block_addr, fact.selector),
                    guard: switch_guard(function, graph, predicates, fact),
                },
            )
        })
        .collect();

    let if_regions = predicates
        .predicates
        .iter()
        .map(|(id, fact)| {
            (
                *id,
                IfRegionCertificate {
                    predicate: *id,
                    block_addr: fact.block_addr,
                    true_target: fact.true_target,
                    false_target: fact.false_target,
                },
            )
        })
        .collect();

    let renderable_expressions =
        collect_renderable_expression_values(function, prep, graph, structured);
    let expressions = graph
        .values
        .iter()
        .map(|value| {
            let defining_inst = graph.def_of.get(value.id.0 as usize).and_then(|id| *id);
            let inputs = defining_inst
                .and_then(|inst| graph.inst(inst))
                .map(|inst| inst.inputs.clone())
                .unwrap_or_default();
            (
                value.id,
                ExpressionCertificate {
                    value: value.id,
                    defining_inst,
                    inputs,
                    width: value.var.size,
                    renderable: renderable_expressions.contains(value.id),
                },
            )
        })
        .collect();

    let mut memory_accesses_by_inst = BTreeMap::<(InstId, bool), Vec<StructuredAccessId>>::new();
    let memory_accesses = structured
        .memory_accesses
        .iter()
        .map(|(id, fact)| {
            memory_accesses_by_inst
                .entry((id.inst, fact.is_write))
                .or_default()
                .push(*id);
            (
                *id,
                MemoryAccessCertificate {
                    access: *id,
                    space: fact.space,
                    object: fact.object,
                    address: fact.address,
                    value: fact.value,
                    is_write: fact.is_write,
                    width: fact.width,
                    object_offset: fact.object_offset,
                },
            )
        })
        .collect();

    let stack_array_layouts = objects
        .objects
        .keys()
        .copied()
        .map(|object| {
            (
                object,
                stack_array_layout(graph, values, objects, structured, object),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut callee_stack_allocations = collect_callee_stack_allocation_certificates(
        function,
        prep,
        graph,
        machine_context,
        objects,
        structured,
        &exact_stack_slots,
        &AllocationSizing {
            array_layouts: &stack_array_layouts,
            values,
        },
    );
    let (stack_frame_round_trips, stack_frame_round_trip_by_inst) =
        collect_stack_frame_round_trip_certificates(
            body,
            derived,
            &callee_stack_allocations,
            unobserved,
            live_out,
        );
    // A callee allocation names a source-less object: a local radare2 inferred
    // keeps one only where it proved a frame save round trip.
    callee_stack_allocations.retain(|object, _| {
        let declared = objects
            .objects
            .get(object)
            .is_some_and(|fact| match fact.kind {
                ObjectKind::StackSlot { base, offset, .. }
                | ObjectKind::FrameObject { base, offset, .. } => {
                    exact_stack_slots.contains_key(&(base, offset))
                }
                _ => false,
            });
        !declared || stack_frame_round_trips.contains_key(object)
    });
    let (machine_return_controls, machine_return_control_by_inst) =
        collect_machine_return_control_certificates(
            boundaries, graph, objects, structured, unobserved,
        );
    let stack_geometry = collect_stack_geometry_certificate(
        boundaries,
        prep,
        graph,
        objects,
        structured,
        &StackGeometryContext {
            frame_round_trips: &stack_frame_round_trips,
            return_controls: &machine_return_controls,
            unobserved,
            machine_context,
            declared_slots,
        },
    );
    let unbounded_index = unbounded_index_objects(values, objects, structured);
    let stack_slots = objects
        .objects
        .iter()
        .filter_map(|(object, fact)| match fact.kind {
            ObjectKind::StackSlot {
                space: SpaceId::Ram,
                base,
                offset,
            }
            | ObjectKind::FrameObject {
                space: SpaceId::Ram,
                base,
                offset,
            } => {
                let declared = matches!(
                    stack_array_layouts.get(object),
                    Some(StackArrayLayoutDisposition::Proven(_))
                ) || exact_stack_slots.contains_key(&(base, offset))
                    || callee_stack_allocations.contains_key(object);
                let storage = if declared {
                    None
                } else {
                    accessed_object_storage(graph, values, objects, structured, *object)
                };
                r2il::refusal_evidence!(
                    "stack-slot-storage",
                    "{object:?} at {base:?}{offset:+} declared={declared} (layout={:?} slot={} callee={}) storage={storage:?} accesses={:?}",
                    stack_array_layouts.get(object).map(|layout| match layout {
                        StackArrayLayoutDisposition::Proven(layout) => format!("proven {}", layout.extent),
                        StackArrayLayoutDisposition::NotIndexed => "not indexed".to_string(),
                        StackArrayLayoutDisposition::Refused(reason) => format!("{reason:?}"),
                    }),
                    exact_stack_slots.contains_key(&(base, offset)),
                    callee_stack_allocations.contains_key(object),
                    structured
                        .memory_accesses
                        .values()
                        .filter(|access| access.object == *object)
                        .map(|access| (
                            access.address,
                            access.width,
                            objects.address_is_indexed(access.address),
                            access.object_offset
                        ))
                        .collect::<Vec<_>>()
                );
                Some((
                    *object,
                    StackSlotCertificate {
                        object: *object,
                        space: SpaceId::Ram,
                        base,
                        offset,
                        byte_array: storage.is_some_and(|(_, bytes)| bytes)
                            || callee_stack_allocations
                                .get(object)
                                .is_some_and(|allocation| allocation.byte_array),
                        // Failing both, accesses at one width with complete provenance state how wide it is.
                        size: stack_array_layouts
                            .get(object)
                            .and_then(|layout| match layout {
                                StackArrayLayoutDisposition::Proven(layout) => {
                                    u32::try_from(layout.extent).ok()
                                }
                                StackArrayLayoutDisposition::NotIndexed
                                | StackArrayLayoutDisposition::Refused(_) => None,
                            })
                            .or_else(|| {
                                exact_stack_slots
                                    .get(&(base, offset))
                                    .map(SourceStackSlotSpec::size_bytes)
                            })
                            .or_else(|| {
                                callee_stack_allocations
                                    .get(object)
                                    .map(|certificate| certificate.size_bytes)
                            })
                            .or_else(|| storage.map(|(bytes, _)| bytes)),
                        array_layout: stack_array_layouts
                            .get(object)
                            .cloned()
                            .unwrap_or(StackArrayLayoutDisposition::NotIndexed),
                        source_slot: exact_stack_slots.get(&(base, offset)).copied(),
                        reload_values: crate::dense::IdSet::default(),
                        stored_values: crate::dense::IdSet::default(),
                        callee_allocation: callee_stack_allocations.get(object).cloned(),
                        unbounded_index: unbounded_index.contains(object),
                    },
                ))
            }
            ObjectKind::StackSlot { .. }
            | ObjectKind::FrameObject { .. }
            | ObjectKind::Global { .. }
            | ObjectKind::Parameter { .. }
            | ObjectKind::HeapAlloc { .. }
            | ObjectKind::EscapedUnknown { .. }
            | ObjectKind::Pointee { .. } => None,
        })
        .collect();

    // The stores of a constant through the stack pointer, per block: on
    // amd64 the nearest one before a call is the return address the call
    // pushed, and nothing else stores a literal there just before calling.
    // A constant stored through the stack pointer just before a call is the
    // return address only where the call pushes one; where a register carries
    // it, such a store is an argument like any other.
    let stack_pointer = machine_context
        .filter(|context| context.call_moves_stack_pointer())
        .and_then(SourceMachineContext::stack_pointer_carrier);
    let mut constant_stack_stores =
        crate::dense::IdMap::<crate::BlockId, Vec<(usize, InstId)>>::default();
    if let Some(stack_pointer) = stack_pointer {
        for inst in &graph.insts {
            let InstPayload::Op(SSAOp::Store { val, .. }) = &inst.payload else {
                continue;
            };
            let through_stack_pointer = inst.inputs.first().is_some_and(|address| {
                graph
                    .value(*address)
                    .and_then(|value| value.canonical_storage)
                    .is_some_and(|storage| storage.location() == stack_pointer.location())
            });
            if graph.var(*val).constant_bits().is_some() && through_stack_pointer {
                constant_stack_stores
                    .get_or_insert_with(inst.block, Default::default)
                    .push((inst.ordinal, inst.id));
            }
        }
    }
    let return_address_store_before = |call: InstId| {
        let call = graph.inst(call)?;
        constant_stack_stores
            .get(call.block)?
            .iter()
            .filter(|(ordinal, _)| *ordinal < call.ordinal)
            .max_by_key(|(ordinal, _)| *ordinal)
            .map(|(_, inst)| *inst)
    };
    let callsites = call_sites
        .by_id
        .iter()
        .map(|(id, fact)| {
            let stack_argument_values = collect_stack_call_argument_values(
                function,
                prep,
                graph,
                objects,
                structured,
                fact,
                machine_context.is_none_or(SourceMachineContext::call_moves_stack_pointer),
            );
            let boundary = boundaries
                .calls
                .get(id)
                .filter(|boundary| boundary.at == fact.at);
            // The arguments are certified wherever they were proved, whatever became of the results.
            let complete_arguments = boundary.filter(|boundary| boundary.arguments_complete);
            let (mut argument_certificates, declared_stack_arguments) = complete_arguments
                .map(|boundary| {
                    exact_register_call_arguments(
                        boundary,
                        graph,
                        machine_context,
                        prep.map(|prep| &prep.views),
                    )
                })
                .unwrap_or_default();
            // A stack argument the prototype declared: the boundary proved
            // which value reaches which coordinate, and the outgoing-store
            // scan names the object and access that carry it. One without
            // an object is a slot this function never wrote, and the call
            // is then not fully described.
            let mut declared_stack_complete = true;
            for declared in &declared_stack_arguments {
                match stack_argument_values.iter().find(|stack_arg| {
                    stack_arg.stack_offset == declared.entry_offset
                        && stack_arg.value == declared.value
                }) {
                    Some(stack_arg) => {
                        let Some(access) = structured.memory_accesses.get(&stack_arg.memory_access)
                        else {
                            declared_stack_complete = false;
                            break;
                        };
                        argument_certificates.push(CallArgumentCertificate {
                            index: declared.index,
                            value: declared.value,
                            location: CallArgumentLocation::Stack {
                                object: access.object,
                                offset: stack_arg.stack_offset,
                                memory_access: stack_arg.memory_access,
                            },
                            source_inst: Some(stack_arg.memory_access.inst),
                        });
                    }
                    None if graph.values.iter().any(|value| {
                        value.var.name() == crate::naming::frame_slot_name(declared.entry_offset)
                    }) =>
                    {
                        argument_certificates.push(CallArgumentCertificate {
                            index: declared.index,
                            value: declared.value,
                            location: CallArgumentLocation::Variable {
                                offset: declared.entry_offset,
                            },
                            source_inst: None,
                        });
                    }
                    None => {
                        r2il::refusal_evidence!(
                            "call-argument-stack-object",
                            "callsite {:?} argument {} at entry offset {} has no outgoing store object among {:?}",
                            fact.at,
                            declared.index,
                            declared.entry_offset,
                            stack_argument_values
                                .iter()
                                .map(|argument| argument.stack_offset)
                                .collect::<Vec<_>>()
                        );
                        declared_stack_complete = false;
                        break;
                    }
                }
            }
            if !declared_stack_complete {
                argument_certificates.clear();
            }
            argument_certificates.sort_by_key(|argument| argument.index);
            let argument_values = argument_certificates
                .iter()
                .map(|argument| argument.value)
                .collect::<Vec<_>>();
            // Only the slots a prototype declared are arguments. The scan
            // sees every store above the call's stack pointer, and in a
            // function with a frame that is also the register save area a
            // variadic prologue fills and every spill below it; claiming
            // those as call inputs made the ledger read values whose
            // objects it had already proven dead.
            let stack_argument_values = stack_argument_values
                .into_iter()
                .filter(|stack_arg| {
                    argument_certificates.iter().any(|argument| {
                        matches!(
                            argument.location,
                            CallArgumentLocation::Stack { memory_access, .. }
                                if memory_access == stack_arg.memory_access
                        )
                    })
                })
                .collect::<Vec<_>>();
            // The prototype and its callsite-count disposition must survive an
            // incomplete boundary: that incompleteness is exactly what lets a
            // renderer refuse an unresolved variadic format explicitly.
            let (variadic, fixed_argument_count, count_evidence, count_refusal) =
                boundary.map_or((false, None, None, None), |boundary| {
                    (
                        boundary.variadic.unwrap_or(false),
                        boundary.fixed_argument_count,
                        boundary.variadic_argument_count_evidence,
                        boundary.variadic_argument_count_refusal,
                    )
                });
            // Which half of the boundary was proved, kept apart. A call whose
            // results are known and whose argument mapping is not is a
            // different thing from one that takes no arguments.
            let (arguments_complete, results_complete) =
                boundary.map_or((false, false), |boundary| {
                    (boundary.arguments_complete, boundary.results_complete)
                });
            (
                *id,
                CallsiteCertificate {
                    call_site: *id,
                    at: fact.at,
                    target: fact.target,
                    direct_target: fact.direct_target,
                    fallthrough: fact.fallthrough,
                    transfer: fact.transfer,
                    callee_linkage: fact.callee_linkage,
                    argument_values,
                    variadic,
                    fixed_argument_count,
                    variadic_argument_count_evidence: count_evidence,
                    variadic_argument_count_refusal: count_refusal,
                    stack_argument_values,
                    return_address_store: return_address_store_before(fact.at),
                    argument_certificates,
                    arguments_complete,
                    results_complete,
                    described: boundary.is_some_and(|boundary| boundary.described),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let call_return_address_stores = callsites
        .values()
        .filter_map(|certificate: &CallsiteCertificate| certificate.return_address_store)
        .collect::<crate::dense::IdSet<_>>();

    let (call_results, call_results_by_inst, call_results_by_callsite) =
        collect_call_result_certificates(body, derived);
    let stack_reloads = collect_stack_reload_source_certificates(
        body,
        objects,
        memory,
        &structured.memory_accesses,
    );
    let mut stack_slots: BTreeMap<ObjectId, StackSlotCertificate> = stack_slots;
    // A full-width read of a private slot is the slot's value, whatever store
    // put it there. Requiring one reaching store as well would exclude every
    // variable a loop writes, which is most of them at -O0. A full-width
    // write is the slot's value too, offered to the object one at a time.
    for access in structured.memory_accesses.values() {
        if !access.provenance_complete || access.space != SpaceId::Ram {
            continue;
        }
        if !private_objects.contains(&access.object) {
            continue;
        }
        // A round trip's read is the stored value, already answered by the
        // store it reads back; it is not a read of the slot the renderer names.
        if !access.is_write
            && memory_round_trips.values().any(|certificate| {
                certificate.read == access.id || certificate.redundant_reads.contains(&access.id)
            })
        {
            continue;
        }
        // An address the machine indexes reads an element, not the slot.
        if objects.address_is_indexed(access.address) {
            continue;
        }
        let Some(value) = access.value else {
            continue;
        };
        let value_width = graph
            .value(value)
            .map_or(access.width, |graph_value| graph_value.var.size);
        // A read narrower or wider than the slot is a projection of it, not
        // the slot's own value.
        if value_width != access.width {
            continue;
        }
        if let Some(slot) = stack_slots.get_mut(&access.object)
            && slot.size == Some(access.width)
        {
            if access.is_write {
                slot.stored_values.insert(value);
            } else {
                slot.reload_values.insert(value);
            }
        }
    }
    // And the values that are those reads' bits, which the reload
    // certificates state; a value only computed from a read -- an extension,
    // a lane, a sign word of the same width as the slot -- is not the slot.
    for certificate in stack_reloads.values() {
        if certificate.relation != crate::view::ViewRelation::Identity
            || certificate.value_width != certificate.memory_width
            || !private_objects.contains(&certificate.object)
        {
            continue;
        }
        if let Some(slot) = stack_slots.get_mut(&certificate.object)
            && slot.size == Some(certificate.memory_width)
        {
            slot.reload_values.insert(certificate.value);
        }
    }
    let (returns, returns_by_inst) =
        collect_return_value_certificates(boundaries, graph, machine_context, &stack_reloads);
    let compiler_inserted = unobserved_compiler_inserted(function, graph, &returns);

    PreparedFunctionCertificates {
        loops,
        switches,
        if_regions,
        expressions,
        memory_accesses,
        memory_accesses_by_inst,
        memory_round_trips,
        stack_slots,
        stack_frame_round_trips,
        stack_frame_round_trip_by_inst,
        stack_geometry,
        machine_return_controls,
        machine_return_control_by_inst,
        callsites,
        call_return_address_stores,
        compiler_inserted,
        dead_frame_stores: crate::dense::IdSet::default(),
        unobserved_private_reads: unobserved_private_reads(
            graph,
            structured,
            private_objects,
            unobserved,
            live_out,
        ),
        call_results,
        call_results_by_inst,
        call_results_by_callsite,
        stack_reloads,
        returns,
        returns_by_inst,
        two_way_selections: collect_two_way_selection_certificates(function, graph),
        failures: Vec::new(),
    }
}

/// Whether a value is what a register slot holds: its storage, a root whose low lane it is, an entry lane's projection, or a lane inserted there (B3).
fn holds(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    value: &crate::graph::GraphValue,
    storage: CanonicalStorageId,
) -> bool {
    if let Some(own) = value.canonical_storage
        && own.space == CanonicalStorageSpace::Register
    {
        return own == storage
            || machine_context.is_some_and(|context| context.is_low_lane_of(storage, own));
    }
    if graph.formal_projection_storage(value.id) == Some(storage) {
        return true;
    }
    // A temporary names no register: it holds the slot where an insert puts it there.
    graph.use_sites(value.id).iter().any(|site| {
        let Some(inst) = graph.inst(site.inst) else {
            return false;
        };
        let crate::graph::InstPayload::Op(crate::op::SSAOp::Insert(insert)) = &inst.payload else {
            return false;
        };
        let root = inst
            .output
            .and_then(|out| graph.value(out)?.canonical_storage);
        let position = graph
            .value(insert.position)
            .and_then(|position| position.var.constant_bits());
        let (Some(root), Some(bits)) = (root, position) else {
            return false;
        };
        insert.value == value.id
            && bits % 8 == 0
            && root.space == storage.space
            && root.offset.checked_add(bits / 8) == Some(storage.offset)
            && value.var.size == storage.size
    })
}

pub(crate) fn exact_register_call_arguments(
    boundary: &SourceCallBoundaryFact,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    views: Option<&crate::view::ValueViews<ValueId>>,
) -> (Vec<CallArgumentCertificate>, Vec<BoundaryStackArgument>) {
    macro_rules! give_up {
        ($reason:literal $(, $arg:expr)* $(,)?) => {{
            r2il::refusal_evidence!(
                "call-argument-coordinates",
                concat!("call site {:?} at {:?}: ", $reason),
                boundary.call_site,
                boundary.at,
                $($arg,)*
            );
            return (Vec::new(), Vec::new());
        }};
    }
    let mut by_index = BTreeMap::new();
    let mut stack_by_index = BTreeMap::new();
    for (position, argument) in boundary.arguments.iter().enumerate() {
        let CallBoundarySlot::Register { index, storage } = argument.slot else {
            // An argument the convention passes on the stack: the boundary
            // proved the value and the slot's entry-relative coordinate, and
            // the object model names the slot's object for the certificate.
            let (CallBoundarySlot::Stack(entry_offset), SourceCallArgumentValue::Value(value)) =
                (argument.slot, argument.value)
            else {
                give_up!("slot {:?} is {:?}", argument.slot, argument.value);
            };
            if stack_by_index
                .insert(position, (value, entry_offset))
                .is_some()
            {
                give_up!("stack slot {} is claimed twice", position);
            }
            continue;
        };
        let SourceCallArgumentValue::Value(value) = argument.value else {
            give_up!("slot {} at {:?} is {:?}", index, storage, argument.value);
        };
        let Ok(index) = usize::try_from(index) else {
            give_up!("slot index {} is out of range", index);
        };
        // A lane value stands for the wider root write the slot holds, where the views prove it.
        let carrier = argument.lane_of.unwrap_or(value);
        if argument.lane_of.is_some()
            && views.and_then(|views| {
                crate::semantic::shared::proven_low_lane(views, graph, carrier, storage)
            }) != Some(value)
        {
            give_up!(
                "slot {} value {:?} is not the low lane of {:?}",
                index,
                value,
                carrier
            );
        }
        let Some(graph_value) = graph.value(carrier) else {
            give_up!("slot {} value {:?} is not in the graph", index, carrier);
        };
        if !holds(graph, machine_context, graph_value, storage) {
            give_up!(
                "slot {} wants {:?} but {:?} is at {:?}",
                index,
                storage,
                value,
                graph_value.canonical_storage
            );
        }
        if by_index
            .insert(
                index,
                CallArgumentCertificate {
                    index,
                    value,
                    location: CallArgumentLocation::Register { storage },
                    source_inst: graph.def_inst(value),
                },
            )
            .is_some()
        {
            give_up!("slot {} is claimed twice", index);
        }
    }
    if by_index
        .keys()
        .chain(stack_by_index.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .ne(0..by_index.len() + stack_by_index.len())
    {
        give_up!(
            "slots {:?} and stack slots {:?} are not contiguous",
            by_index.keys(),
            stack_by_index.keys()
        );
    }
    let certificates = by_index.into_values().collect::<Vec<_>>();
    let stack = stack_by_index
        .into_iter()
        .map(|(index, (value, entry_offset))| BoundaryStackArgument {
            index,
            value,
            entry_offset,
        })
        .collect();
    (certificates, stack)
}

/// One stack-passed argument a complete boundary proved, awaiting the object
/// model's name for its slot.
pub(crate) struct BoundaryStackArgument {
    pub(crate) index: usize,
    pub(crate) value: ValueId,
    pub(crate) entry_offset: i64,
}

/// The operations a decided stack-protector check inserted that nothing outside them observes.
///
/// One the program still reads (a carrier returned holding the canary) keeps its statement, and
/// so do the operations it reads; at most one liveness pass, `O(V + E)`, per operation released.
fn unobserved_compiler_inserted(
    function: &crate::function::SSAFunction,
    graph: &crate::graph::SsaGraph,
    returns: &[ReturnValueCertificate],
) -> crate::dense::IdSet<InstId> {
    let mut inserted = function
        .compiler_inserted()
        .iter()
        .filter_map(|op| graph.inst_for_op(op))
        .collect::<crate::dense::IdSet<_>>();
    loop {
        let observed = observed_values(graph, returns, &inserted);
        let released = inserted
            .iter()
            .filter(|inst| {
                graph
                    .inst(*inst)
                    .and_then(|inst| inst.output)
                    .is_some_and(|value| observed[value.0 as usize])
            })
            .collect::<Vec<_>>();
        if released.is_empty() {
            return inserted;
        }
        for inst in released {
            inserted.remove(inst);
        }
    }
}

/// Every value an effect, a return or a call reads, through the operations that compute it,
/// with the operations in `silent` read by nothing.
fn observed_values(
    graph: &crate::graph::SsaGraph,
    returns: &[ReturnValueCertificate],
    silent: &crate::dense::IdSet<InstId>,
) -> Vec<bool> {
    let mut observed = vec![false; graph.values.len()];
    let mut pending = returns
        .iter()
        .map(|certificate| certificate.value)
        .collect::<Vec<_>>();
    for inst in &graph.insts {
        let effect = match &inst.payload {
            crate::graph::InstPayload::Op(op) => {
                inst.output.is_none()
                    || matches!(
                        op,
                        crate::SSAOp::Call { .. }
                            | crate::SSAOp::CallInd { .. }
                            | crate::SSAOp::CallOther { .. }
                    )
            }
            _ => false,
        };
        if effect && !silent.contains(inst.id) {
            pending.extend(inst.inputs.iter().copied());
        }
    }
    while let Some(value) = pending.pop() {
        let Some(seen) = observed.get_mut(value.0 as usize) else {
            continue;
        };
        if std::mem::replace(seen, true) {
            continue;
        }
        if let Some(definition) = graph.def_inst(value).and_then(|inst| graph.inst(inst))
            && !silent.contains(definition.id)
        {
            pending.extend(definition.inputs.iter().copied());
        }
    }
    observed
}
