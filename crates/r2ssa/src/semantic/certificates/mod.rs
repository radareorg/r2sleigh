//! What the body proves about itself, phase by phase.

mod call_results;
mod expressions;
mod returns;
mod shared;
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
fn dispatch_operations(
    graph: &crate::SsaGraph,
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
    let mut found = vec![transfer];
    loop {
        let candidates: Vec<ValueId> = found
            .iter()
            .filter_map(|inst| graph.inst(*inst))
            .flat_map(|inst| inst.inputs.iter().copied())
            .collect();
        let mut grew = false;
        for value in candidates {
            if selector == Some(value) {
                continue;
            }
            let Some(definition) = graph.def_inst(value) else {
                continue;
            };
            if found.contains(&definition)
                || graph.inst(definition).map(|inst| inst.block) != Some(block.id)
                || !graph
                    .use_sites(value)
                    .iter()
                    .all(|site| found.contains(&site.inst))
            {
                continue;
            }
            found.push(definition);
            grew = true;
        }
        if !grew {
            break;
        }
    }
    found.sort_unstable();
    found
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
    pub block_addr: u64,
    pub op_index: usize,
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
    pub reload_values: BTreeSet<ValueId>,
    /// Values a full-width store writes into the slot. Each is offered to the
    /// slot's object on its own, judged by identity and liveness.
    pub stored_values: BTreeSet<ValueId>,
    /// Exact proof that a source-less object lies wholly inside storage owned
    /// by this callee at every access. This is deliberately separate from a
    /// source slot: compiler-created spills and temporaries are real machine
    /// objects without becoming source variables.
    pub callee_allocation: Option<CalleeStackAllocationCertificate>,
    /// The slot is storage read at more than one width: `size` is the extent
    /// its accesses reach and it declares as bytes, not as a scalar.
    pub byte_array: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallsiteCertificate {
    pub call_site: CallSiteId,
    pub at: InstId,
    pub block_addr: u64,
    pub op_index: usize,
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
    pub expressions: BTreeMap<ValueId, ExpressionCertificate>,
    pub memory_accesses: BTreeMap<StructuredAccessId, MemoryAccessCertificate>,
    pub memory_accesses_by_op: BTreeMap<(u64, usize, bool), Vec<StructuredAccessId>>,
    pub stack_slots: BTreeMap<ObjectId, StackSlotCertificate>,
    pub stack_frame_round_trips: BTreeMap<ObjectId, StackFrameRoundTripCertificate>,
    pub stack_frame_round_trip_by_inst: BTreeMap<InstId, ObjectId>,
    /// Accesses that together leave the object exactly as they found it.
    pub memory_round_trips: BTreeMap<StructuredAccessId, MemoryRoundTripCertificate>,
    pub stack_geometry: StackGeometryCertificate,
    pub machine_return_controls: BTreeMap<InstId, MachineReturnControlCertificate>,
    pub machine_return_control_by_inst: BTreeMap<InstId, InstId>,
    pub callsites: BTreeMap<CallSiteId, CallsiteCertificate>,
    pub callsites_by_inst: BTreeMap<InstId, CallSiteId>,
    /// Every call's return-address store, for the ledgers that ask per op.
    pub call_return_address_stores: BTreeSet<InstId>,
    pub call_results: BTreeMap<ValueId, CallResultCertificate>,
    pub call_results_by_inst: BTreeMap<InstId, ValueId>,
    pub call_results_by_callsite: BTreeMap<CallSiteId, Vec<ValueId>>,
    pub stack_reloads: BTreeMap<ValueId, StackReloadSourceCertificate>,
    pub returns: Vec<ReturnValueCertificate>,
    pub returns_by_inst: BTreeMap<InstId, usize>,
    /// Merges of two values that the one condition above them selects between.
    pub two_way_selections: BTreeMap<InstId, TwoWaySelectionCertificate>,
    pub failures: Vec<PreparedProofFailure>,
}

pub(crate) fn frame_gap_extent(
    objects: &ObjectModel,
    base: StackAddressBase,
    offset: i64,
) -> Option<u32> {
    if offset >= 0 {
        return None;
    }
    let next = objects
        .objects
        .values()
        .filter_map(|fact| match fact.kind {
            ObjectKind::StackSlot {
                base: other_base,
                offset: other,
                ..
            }
            | ObjectKind::FrameObject {
                base: other_base,
                offset: other,
                ..
            } if other_base == base && other > offset => Some(other),
            _ => None,
        })
        .min()
        .unwrap_or(0)
        .min(0);
    u32::try_from(next - offset)
        .ok()
        .filter(|extent| *extent > 0)
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

/// Decide array geometry once, beside the object and memory facts that own it.
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

    let mut maximum_constant_offset = None;
    let mut indexed_elements = Vec::with_capacity(indexed_addresses.len());
    for address in &indexed_addresses {
        let Some(byte_offset) = objects.index_for_address(*address) else {
            continue;
        };
        if let Some(bound) = values.upper_bound(byte_offset) {
            maximum_constant_offset =
                Some(maximum_constant_offset.map_or(bound, |old: u64| old.max(bound)));
        }
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

pub(crate) fn counted_for_loop_certificate(
    function: &SSAFunction,
    graph: &SsaGraph,
    predicates: &PredicateFacts,
    structured: &StructuredDataflowFacts,
    loop_fact: &StructuredLoopFact,
) -> Option<ForLoopCertificate> {
    let phi = loop_fact.induction_phi?;
    let induction = structured.inductions.get(&phi)?;
    if induction.loop_id != loop_fact.id
        || induction.header != loop_fact.header
        || loop_fact.latches.as_slice() != [induction.latch]
        || loop_fact.induction_init != Some(induction.init)
        || loop_fact.induction_update != Some(induction.update)
        || !induction.validate(graph)
    {
        return None;
    }
    let comparison = predicates
        .predicates
        .get(&loop_fact.condition?)?
        .comparison
        .as_ref()?;
    let lhs_reads_phi = value_depends_on(graph, comparison.lhs, phi);
    let rhs_reads_phi = value_depends_on(graph, comparison.rhs, phi);
    if lhs_reads_phi == rhs_reads_phi {
        return None;
    }
    let carrier = loop_fact
        .carriers
        .iter()
        .find(|carrier| carrier.phi == phi)?;
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
    let Some((definition_block, op_index)) = graph
        .def_inst(value)
        .and_then(|inst| graph.op_site_for_inst(inst))
    else {
        return false;
    };
    definition_block == block_addr
        && function.get_block(block_addr).is_some_and(|block| {
            let Some(suffix) = op_index
                .checked_add(1)
                .and_then(|start| block.ops.get(start..))
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
                    dispatch: dispatch_operations(graph, *block_addr, fact.selector),
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

    let renderable_expressions = collect_renderable_expression_values(function, graph, structured);
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
                    renderable: renderable_expressions.contains(&value.id),
                },
            )
        })
        .collect();

    let mut memory_accesses_by_op = BTreeMap::<(u64, usize, bool), Vec<StructuredAccessId>>::new();
    let memory_accesses = structured
        .memory_accesses
        .iter()
        .map(|(id, fact)| {
            memory_accesses_by_op
                .entry((fact.block_addr, fact.op_index, fact.is_write))
                .or_default()
                .push(*id);
            (
                *id,
                MemoryAccessCertificate {
                    access: *id,
                    block_addr: fact.block_addr,
                    op_index: fact.op_index,
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
    let callee_stack_allocations = collect_callee_stack_allocation_certificates(
        function,
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
    // A callee allocation names a source-less object. A local radare2 inferred
    // was admitted above only so that a frame save it named could be proven a
    // round trip; where it was not, the slot keeps its own identity.
    let callee_stack_allocations = {
        let mut allocations = callee_stack_allocations;
        allocations.retain(|object, _| {
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
        allocations
    };
    let (machine_return_controls, machine_return_control_by_inst) =
        collect_machine_return_control_certificates(
            boundaries, graph, objects, structured, unobserved,
        );
    let stack_geometry = collect_stack_geometry_certificate(
        boundaries,
        function,
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
                        // No access sizes it and nothing declares it, but its address left the body: a buffer a callee fills.
                        // The frame lays it out between its neighbours, and that gap is its extent, as bytes.
                        // An address that never leaves and is never accessed is a stack position, not an object, and the gap says nothing about it.
                        .or_else(|| {
                            objects
                                .address_escapes(*object)
                                .then(|| frame_gap_extent(objects, base, offset))
                                .flatten()
                                .map(|extent| (extent, true))
                        })
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
                        // Failing both, the object's own accesses say how wide it
                        // is. Every access reaching it at one width, with complete
                        // provenance, is a fact about the program rather than an
                        // opinion about it -- and radare2 has no opinion to offer
                        // for most of these: it reports no stack variables at all
                        // for `murmur3_32`, which has fourteen of them.
                        //
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
                        reload_values: BTreeSet::new(),
                        stored_values: BTreeSet::new(),
                        callee_allocation: callee_stack_allocations.get(object).cloned(),
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
    let mut constant_stack_stores: BTreeMap<crate::BlockId, Vec<(usize, InstId)>> = BTreeMap::new();
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
            if val.constant_bits().is_some() && through_stack_pointer {
                constant_stack_stores
                    .entry(inst.block)
                    .or_default()
                    .push((inst.ordinal, inst.id));
            }
        }
    }
    let return_address_store_before = |call: InstId| {
        let call = graph.inst(call)?;
        constant_stack_stores
            .get(&call.block)?
            .iter()
            .filter(|(ordinal, _)| *ordinal < call.ordinal)
            .max_by_key(|(ordinal, _)| *ordinal)
            .map(|(_, inst)| *inst)
    };
    let mut callsites_by_inst = BTreeMap::new();
    let callsites = call_sites
        .by_id
        .iter()
        .map(|(id, fact)| {
            let (block_addr, op_index) = graph.op_site_for_inst(fact.at).unwrap_or_default();
            let stack_argument_values = collect_stack_call_argument_values(
                function,
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
            let complete_boundary = boundary.filter(|boundary| boundary.complete);
            let (mut argument_certificates, declared_stack_arguments) = complete_boundary
                .map(|boundary| exact_register_call_arguments(boundary, graph))
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
                            "callsite ({block_addr:#x}, {op_index}) argument {} at entry offset {} has no outgoing store object among {:?}",
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
            callsites_by_inst.insert(fact.at, *id);
            (
                *id,
                CallsiteCertificate {
                    call_site: *id,
                    at: fact.at,
                    block_addr,
                    op_index,
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
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let call_return_address_stores = callsites
        .values()
        .filter_map(|certificate: &CallsiteCertificate| certificate.return_address_store)
        .collect::<BTreeSet<_>>();

    let (call_results, call_results_by_inst, call_results_by_callsite) =
        collect_call_result_certificates(body, derived);
    let stack_reloads =
        collect_stack_reload_source_certificates(function, graph, objects, memory, structured);
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
    // And the copies of those reads, which the reload certificates already
    // followed through the operations that preserve a value.
    for certificate in stack_reloads.values() {
        if certificate.value_width != certificate.memory_width
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

    PreparedFunctionCertificates {
        loops,
        switches,
        if_regions,
        expressions,
        memory_accesses,
        memory_accesses_by_op,
        memory_round_trips,
        stack_slots,
        stack_frame_round_trips,
        stack_frame_round_trip_by_inst,
        stack_geometry,
        machine_return_controls,
        machine_return_control_by_inst,
        callsites,
        callsites_by_inst,
        call_return_address_stores,
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

pub(crate) fn exact_register_call_arguments(
    boundary: &SourceCallBoundaryFact,
    graph: &SsaGraph,
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
        let Some(graph_value) = graph.value(value) else {
            give_up!("slot {} value {:?} is not in the graph", index, value);
        };
        if graph_value.canonical_storage != Some(storage) {
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
