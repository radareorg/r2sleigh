//! The facts read off a prepared artifact, one builder per question.

use super::*;

pub type OpSiteKey = (u64, usize);

pub type MemoryOpSiteKey = (u64, usize, bool);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallsiteRenderFact {
    pub callsite: CallsiteKey,
    pub target: Option<r2ssa::ValueId>,
    pub disposition: CallsiteRenderDisposition,
    pub proof_values: Vec<r2ssa::ValueId>,
    pub residual_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallsiteRenderDisposition {
    /// The call is a statement of this function. Whether it assigns its result
    /// is the binding plan's answer, from the value the statement defines.
    Statement,
    /// A value-returning callee returns directly to this function's caller.
    TerminalReturn,
    /// A void callee returns directly to this function's caller.
    TerminalVoidReturn,
    Residualized,
}

impl CallsiteRenderDisposition {
    pub const fn is_terminal_return(self) -> bool {
        matches!(self, Self::TerminalReturn | Self::TerminalVoidReturn)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlotOwnerRenderAuthorization {
    pub object: r2ssa::ObjectId,
    pub offset: i64,
    pub name: String,
}

pub(crate) fn stack_slot_offset(slot: &StackSlotKey) -> i64 {
    slot.offset
}

pub(crate) fn stack_slot_matches_offset(slot: &StackSlotKey, offset: i64) -> bool {
    stack_slot_offset(slot) == offset
}

pub(crate) fn visible_stack_binding_kind_is_renderable(kind: &VisibleBindingKind) -> bool {
    matches!(
        kind,
        VisibleBindingKind::Param | VisibleBindingKind::Local | VisibleBindingKind::StackObject
    )
}

pub(crate) fn external_stack_slot_role_is_renderable(role: ExternalStackSlotRole) -> bool {
    matches!(
        role,
        ExternalStackSlotRole::Local | ExternalStackSlotRole::StackArg
    )
}

pub(crate) fn recovered_stack_owner_name_is_renderable(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    !lower.is_empty()
        && lower != "stack"
        && lower != "slot"
        && lower != "saved_fp"
        && lower != "fake_stack_slot"
        && !lower.starts_with("stack_")
        && !lower.starts_with("slot_")
        && !lower.starts_with("local_")
        && !lower.starts_with("arg_")
        && !lower.starts_with("var_")
}

pub(crate) fn remember_stack_param_owner_name(
    candidate: &mut Option<String>,
    name: &str,
) -> Option<()> {
    let name = name.trim();
    if name.is_empty() {
        return Some(());
    }
    if let Some(existing) = candidate.as_ref() {
        return existing.eq_ignore_ascii_case(name).then_some(());
    }
    *candidate = Some(name.to_string());
    Some(())
}

pub(crate) fn stack_owner_type_is_renderable(ty: &CTypeLike) -> bool {
    !matches!(ty, CTypeLike::Unknown | CTypeLike::Void)
}

pub(crate) fn signature_param_name_type_is_renderable(
    signature: Option<&FunctionSignatureSpec>,
    name: &str,
) -> bool {
    signature
        .into_iter()
        .flat_map(|signature| signature.params.iter())
        .any(|param| {
            param.name.eq_ignore_ascii_case(name)
                && param
                    .ty
                    .as_ref()
                    .is_some_and(stack_owner_type_is_renderable)
        })
}

pub(crate) fn indexed_param_home_name<'a>(
    signature: Option<&'a FunctionSignatureSpec>,
    slot: &ExternalStackSlotSpec,
) -> Option<&'a str> {
    if !matches!(slot.role, ExternalStackSlotRole::ParamHome) {
        return None;
    }
    let param = signature?.params.get(slot.param_index?)?;
    let name = param.name.trim();
    (!name.is_empty()
        && param
            .ty
            .as_ref()
            .is_some_and(stack_owner_type_is_renderable))
    .then_some(name)
}

pub(crate) fn type_like_size_bytes(ty: &CTypeLike, ptr_bits: u32) -> Option<u64> {
    match ty {
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => None,
        CTypeLike::Bool => Some(1),
        CTypeLike::Int { bits, .. } | CTypeLike::Float(bits) => {
            Some((u64::from(*bits).saturating_add(7) / 8).max(1))
        }
        CTypeLike::Pointer(_) => Some((ptr_bits / 8).max(1) as u64),
        CTypeLike::Array(inner, Some(count)) => {
            type_like_size_bytes(inner, ptr_bits).map(|size| size.saturating_mul(*count as u64))
        }
        CTypeLike::Array(inner, None) => type_like_size_bytes(inner, ptr_bits),
        CTypeLike::Const(inner) => type_like_size_bytes(inner, ptr_bits),
        CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_)
        | CTypeLike::Typedef { .. } => None,
    }
}

/// Whether a rendering can emit a definition for this aggregate.
///
/// A rendering that declares a value of a tag it cannot define does not
/// compile, and a rendering that does not compile scores nothing. The plan
/// therefore has to ask the same question the emitter will ask later, and this
/// is that question in one place so the two cannot drift apart -- which is the
/// shape of defect that `term_renders_inline` and `materialize_term` already
/// had once.
///
/// The requirements are the emitter's: the graph carries a layout, every member
/// projects to a spellable type, each member's width either matches its size or
/// divides it exactly so the member can be rebuilt as an array, and the members
/// together account for the size the capture measured.
pub fn aggregate_is_definable(graph: &r2ssa::SourceTypeGraph, name: &str) -> bool {
    let Some(layout) = graph
        .aggregates()
        .iter()
        .find(|aggregate| aggregate.name() == name)
    else {
        return false;
    };
    if layout.members().is_empty() {
        return false;
    }
    for member in layout.members() {
        let mut visiting = std::collections::BTreeSet::<u32>::new();
        let Some(member_ty) =
            crate::analysis::source_type_like(graph, member.type_id(), &mut visiting)
        else {
            return false;
        };
        match declaration_type_width_bits(&member_ty, 64) {
            Some(width) if u64::from(width) == member.size_bits() => {}
            Some(width)
                if width > 0
                    && member.size_bits() % u64::from(width) == 0
                    && usize::try_from(member.size_bits() / u64::from(width)).is_ok() => {}
            _ => return false,
        }
    }
    let covered = layout
        .members()
        .iter()
        .map(|member| member.offset_bits() + member.size_bits())
        .max()
        .unwrap_or(0);
    covered == layout.size_bits()
}

pub(crate) fn function_type_matches_source_interface(
    signature: &crate::FunctionType,
    interface: &r2ssa::SourceFunctionInterface,
    ptr_bits: u32,
) -> bool {
    if ptr_bits == 0 || signature.params.len() != interface.parameters().len() {
        return false;
    }
    let parameter_widths_match = signature.params.iter().enumerate().all(|(index, ty)| {
        let Some(actual_bits) = declaration_type_width_bits(ty, ptr_bits).map(u64::from) else {
            return false;
        };
        let expected_bits = interface
            .parameter_logical_value(index)
            .map(|logical| logical.carrier().size_bits())
            .or_else(|| {
                interface
                    .parameters()
                    .get(index)
                    .map(|parameter| u64::from(parameter.location().size_bytes()) * 8)
            });
        expected_bits == Some(actual_bits)
    });
    if !parameter_widths_match {
        return false;
    }
    match (interface.return_kind(), &signature.return_type) {
        (r2ssa::SourceFunctionReturn::Void, CTypeLike::Void) => true,
        (r2ssa::SourceFunctionReturn::Register { storage }, ty) => {
            let actual_bits = declaration_type_width_bits(ty, ptr_bits).map(u64::from);
            let expected_bits = interface
                .return_logical_value()
                .map(|logical| logical.carrier().size_bits())
                .or_else(|| Some(u64::from(storage.size) * 8));
            actual_bits == expected_bits
        }
        _ => false,
    }
}

pub(crate) fn field_certificate_width_matches(
    cert: &crate::facts::FieldAccessCertificate,
    access_width: u32,
    ptr_bits: u32,
) -> bool {
    cert.field_type
        .as_deref()
        .and_then(|field_type| parse_c_type_like(field_type, ptr_bits))
        .and_then(|ty| type_like_size_bytes(&ty, ptr_bits))
        .is_none_or(|width| width == u64::from(access_width))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionRenderFact {
    pub value: r2ssa::ValueId,
    pub defining_inst: Option<r2ssa::InstId>,
    pub width: u32,
    pub renderable: bool,
}

/// A renderable expression tied to canonical SSA identity and dependencies.
///
/// `bindings` records semantic roles such as ABI parameters without replacing
/// the expression's stable value identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedExpr {
    pub id: r2ssa::SemanticId,
    pub fact: ExpressionRenderFact,
    pub inputs: Vec<r2ssa::SemanticId>,
    pub bindings: BTreeSet<r2ssa::SemanticId>,
    pub guarded_phi: Option<GuardedPhiRenderFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedPhiRenderFact {
    pub predicate: r2ssa::SemanticId,
    pub when_true: GuardedPhiArmRenderFact,
    pub when_false: GuardedPhiArmRenderFact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedPhiArmRenderFact {
    pub sources: Vec<r2ssa::SemanticId>,
    pub rendered: r2ssa::SemanticId,
}

/// A certified addressable resource. Resources have identity and layout but do
/// not execute, so they must never be counted as observable effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifiedEntity {
    Parameter {
        id: r2ssa::SemanticId,
        slot: u32,
        entry_values: BTreeSet<r2ssa::ValueId>,
        /// Values a reload of this parameter's home slot proves to be the
        /// parameter. The home is the parameter's own storage, so a register
        /// the body fills from it is the parameter and not a copy of it.
        home_reload_values: BTreeSet<r2ssa::ValueId>,
        carrier_width: u32,
        /// Exact logical type from the immutable source interface. Absence is
        /// unknown and must not be repaired from a merged renderer signature.
        ty: Option<CTypeLike>,
    },
    StackSlot {
        id: r2ssa::SemanticId,
        object: r2ssa::ObjectId,
        base: r2ssa::StackAddressBase,
        offset: i64,
        size: Option<u32>,
        array_layout: r2ssa::StackArrayLayoutDisposition,
        /// Full source slot identity, including its local/parameter-home role.
        /// Absence grants no source-variable identity; a separate upstream
        /// callee-allocation proof is required for an anonymous C object.
        source_slot: Option<r2ssa::SourceStackSlotSpec>,
        /// Values a reload proves to be this slot's contents at full width.
        /// Empty where nothing loads the slot back into a register.
        reload_values: BTreeSet<r2ssa::ValueId>,
        /// Values a full-width store writes into the slot, each an offer.
        stored_values: BTreeSet<r2ssa::ValueId>,
        /// Upstream proof for a compiler-created, source-less callee-owned
        /// stack object. Consumers may use it but must not reconstruct it.
        callee_allocation: Option<r2ssa::CalleeStackAllocationCertificate>,
        /// Exact declared type of the slot from the immutable source
        /// interface's type graph. Absence is unknown and must not be
        /// repaired from evidence.
        ty: Option<CTypeLike>,
    },
    LoopCarrier {
        id: r2ssa::SemanticId,
        loop_id: r2ssa::LoopId,
        header: u64,
        phi: r2ssa::ValueId,
        width: u32,
        identity_values: BTreeSet<r2ssa::ValueId>,
        entries: Vec<r2ssa::LoopCarrierEdgeValue>,
        updates: Vec<r2ssa::LoopCarrierUpdateFact>,
        dominating_initializers: Vec<r2ssa::LoopCarrierEdgeValue>,
        members: Vec<r2ssa::LoopCarrierMemberFact>,
        ty: Option<CTypeLike>,
    },
}

impl CertifiedEntity {
    pub const fn id(&self) -> r2ssa::SemanticId {
        match self {
            Self::Parameter { id, .. }
            | Self::StackSlot { id, .. }
            | Self::LoopCarrier { id, .. } => *id,
        }
    }

    /// Canonical SSA values that may name one mutable renderer binding.
    ///
    /// Membership is program-point sensitive: entry values, loop updates, and
    /// dominating initializers may participate only when lowering preserves the
    /// assignments at their original definition sites. This certificate does
    /// not authorize globally substituting any member's expression with the
    /// binding. Stack-slot entities return `None` because object identity alone
    /// is not a certificate of `ValueId` membership.
    pub fn coalescing_values(&self) -> Option<BTreeSet<r2ssa::ValueId>> {
        match self {
            Self::Parameter {
                entry_values,
                home_reload_values,
                ..
            } => Some(
                entry_values
                    .iter()
                    .chain(home_reload_values.iter())
                    .copied()
                    .collect(),
            ),
            // A member whose only role is sharing a run with a real member is
            // the span's to offer, under the liveness rule, not the carrier's
            // to claim; the same rule `LoopCarrierFact::coalescing_values`
            // applies.
            Self::LoopCarrier { members, .. } => Some(
                members
                    .iter()
                    .filter(|member| {
                        member
                            .roles
                            .iter()
                            .any(|role| *role != r2ssa::LoopCarrierMemberRole::StorageContinuation)
                    })
                    .map(|member| member.value)
                    .collect(),
            ),
            // A reload of a slot is the slot, so it and the registers that
            // ferry it are one variable. A parameter's home is excluded: the
            // parameter entity owns those values and decides there.
            Self::StackSlot {
                source_slot,
                reload_values,
                ..
            } if !reload_values.is_empty()
                && !matches!(
                    source_slot.map(|slot| slot.role()),
                    Some(
                        r2ssa::SourceStackSlotRole::ParameterHome { .. }
                            | r2ssa::SourceStackSlotRole::Parameter { .. }
                    )
                ) =>
            {
                Some(reload_values.clone())
            }
            Self::StackSlot { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertifiedEffectKind {
    MemoryRead,
    MemoryWrite,
    Return,
}

/// A certified observable effect or addressable resource.
///
/// Variants retain the typed canonical payload, so consumers never need to
/// recover semantic identity from rendered text or tuple-shaped sidecars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifiedEffect {
    Memory {
        id: r2ssa::SemanticId,
        fact: MemoryAccessRenderFact,
    },
    Return {
        id: r2ssa::SemanticId,
        at: r2ssa::InstId,
        fact: ReturnValueRenderFact,
    },
}

impl CertifiedEffect {
    pub const fn id(&self) -> r2ssa::SemanticId {
        match self {
            Self::Memory { id, .. } | Self::Return { id, .. } => *id,
        }
    }

    pub const fn kind(&self) -> CertifiedEffectKind {
        match self {
            Self::Memory { fact, .. } if fact.is_write => CertifiedEffectKind::MemoryWrite,
            Self::Memory { .. } => CertifiedEffectKind::MemoryRead,
            Self::Return { .. } => CertifiedEffectKind::Return,
        }
    }

    pub const fn control_domain(&self) -> &r2ssa::ControlDomain {
        match self {
            Self::Memory { fact, .. } => &fact.control_domain,
            Self::Return { fact, .. } => &fact.control_domain,
        }
    }

    pub const fn memory_fact(&self) -> Option<&MemoryAccessRenderFact> {
        match self {
            Self::Memory { fact, .. } => Some(fact),
            _ => None,
        }
    }

    pub const fn return_fact(&self) -> Option<&ReturnValueRenderFact> {
        match self {
            Self::Return { fact, .. } => Some(fact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAccessRenderFact {
    pub access: r2ssa::StructuredAccessId,
    pub block_addr: u64,
    pub op_index: usize,
    pub space: r2il::SpaceId,
    pub object: r2ssa::ObjectId,
    pub address: r2ssa::ValueId,
    pub value: Option<r2ssa::ValueId>,
    pub is_write: bool,
    pub width: u32,
    /// Where in the object the access lands, when the memory fact states it.
    pub object_offset: Option<i64>,
    /// True when one certified expression root contains multiple paths to this
    /// read and would duplicate the effect if rendered inline.
    pub materialize_result: bool,
    pub control_domain: r2ssa::ControlDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteralRenderFact {
    pub value: r2ssa::ValueId,
    pub address: u64,
    pub text: String,
    pub source: StringLiteralRenderSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringLiteralRenderSource {
    TypedFunctionFacts,
    Radare2TypedCollector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAccessRenderFact {
    pub access: r2ssa::StructuredAccessId,
    pub block_addr: u64,
    pub op_index: usize,
    pub object: r2ssa::ObjectId,
    pub is_write: bool,
    pub field_offset: u64,
    pub field_name: String,
    pub field_type: Option<CTypeLike>,
    pub access_width: u32,
    /// What the member is taken from, when the producer knows it. A parameter
    /// for a member reached through a pointer; `None` when the member is the
    /// object's own declared slot and the slot's name is the base.
    pub base: Option<r2ssa::SemanticId>,
    /// Where the field name came from.
    pub source: MemberAccessSource,
}

/// Where a member fact's field name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAccessSource {
    /// The source's own type graph named this field at this offset and width.
    DeclaredType,
    /// An external layout matched the base's spelling to a known structure.
    ExternalLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayAccessRenderFact {
    pub access: r2ssa::StructuredAccessId,
    pub block_addr: u64,
    pub op_index: usize,
    pub object: r2ssa::ObjectId,
    pub is_write: bool,
    pub field_offset: u64,
    pub element_stride: u64,
    pub access_width: u32,
    pub base: Option<r2ssa::SemanticId>,
    pub index: Option<r2ssa::SemanticId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnValueRenderFact {
    pub block_addr: u64,
    pub op_index: usize,
    pub value: r2ssa::ValueId,
    pub width: u32,
    pub control_domain: r2ssa::ControlDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPredicateFact {
    pub id: r2ssa::PredicateId,
    pub block_addr: u64,
    pub condition: r2ssa::ValueId,
    pub comparison: Option<PredicateComparisonFact>,
    pub evaluated_comparison: Option<PredicateComparisonFact>,
    /// Comparison selected by prepared semantics for rendering at the source
    /// branch program point.
    pub render_comparison: Option<PredicateComparisonFact>,
    pub true_target: u64,
    pub false_target: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicateComparisonFact {
    pub kind: r2ssa::CompareKind,
    pub lhs: r2ssa::ValueId,
    pub rhs: r2ssa::ValueId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBlockAssumptionFact {
    pub predecessor: u64,
    pub predicate: r2ssa::PredicateId,
    pub truth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopStructureFact {
    pub loop_id: r2ssa::LoopId,
    pub proof_node: String,
    pub header: u64,
    pub condition: Option<r2ssa::PredicateId>,
    pub condition_value: Option<r2ssa::ValueId>,
    pub body: Vec<u64>,
    pub latches: Vec<u64>,
    pub exits: Vec<u64>,
    pub for_loop: Option<r2ssa::ForLoopCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchSelectorFact {
    pub proof_node: String,
    pub block_addr: u64,
    pub selector: Option<r2ssa::ValueId>,
    pub cases: Vec<(u64, u64)>,
    pub default: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResultFact {
    pub callsite: CallsiteKey,
    pub call_site_id: r2ssa::CallSiteId,
    pub at: r2ssa::InstId,
    pub value: r2ssa::ValueId,
    pub width: u32,
    pub relation: r2ssa::CallResultValueRelation,
    pub carrier: r2ssa::ReturnCarrier,
    pub owner: Option<r2ssa::ValueOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallsiteArgumentFacts {
    pub callsite: CallsiteKey,
    pub call_site_id: r2ssa::CallSiteId,
    pub at: r2ssa::InstId,
    pub target: r2ssa::ValueId,
    pub direct_target: Option<u64>,
    pub argument_values: Vec<CallArgumentValueFact>,
    /// Whether the callee takes a variadic tail, as the source's prototype for
    /// it says. Two call sites of one variadic callee legitimately pass
    /// different numbers of arguments, and the declaration a rendering owes
    /// the callee has to say so or it cannot describe both.
    pub variadic: bool,
    /// How many leading `argument_values` the callee's prototype names, where
    /// a prototype described the call. The rest are the variadic tail.
    pub fixed_argument_count: Option<usize>,
    /// Exact logical signature projected from a callee body in the same
    /// source-owned capture. Its carrier contract has already been checked
    /// against this call site by `r2ssa`.
    pub callee_signature: Option<crate::FunctionType>,
    /// Whether that signature is radare2's by-name prototype for an import.
    pub callee_signature_from_source_types: bool,
    /// Per-callsite argument-count proof for a variadic call. This is absent
    /// for fixed calls and never inferred from live argument registers.
    pub variadic_argument_count_evidence: Option<r2ssa::VariadicCallsiteArgumentCountEvidence>,
    pub variadic_argument_count_refusal: Option<r2ssa::VariadicCallsiteArgumentCountRefusal>,
    pub register_argument_locations: Vec<RegisterCallArgumentLocationFact>,
    pub stack_argument_locations: Vec<StackCallArgumentLocationFact>,
    /// Whether the ABI boundary proved a reaching value for every argument the
    /// callee's interface declares. False empties `argument_values`, which
    /// reads identically to a callee that takes none.
    pub arguments_complete: bool,
    /// Whether every result value the caller observes was proved.
    pub results_complete: bool,
}

impl CallsiteArgumentFacts {
    pub fn argument_value(&self, index: usize) -> Option<r2ssa::ValueId> {
        self.argument_values
            .iter()
            .find(|argument| argument.index == index)
            .map(|argument| argument.value)
    }

    pub fn canonical_argument_values(&self) -> Vec<r2ssa::ValueId> {
        let mut by_index = BTreeMap::new();
        for argument in &self.argument_values {
            by_index.insert(argument.index, argument.value);
        }
        for argument in &self.stack_argument_locations {
            by_index.entry(argument.index).or_insert(argument.value);
        }
        by_index.into_values().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallArgumentValueFact {
    pub index: usize,
    pub value: r2ssa::ValueId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterCallArgumentLocationFact {
    pub index: usize,
    pub value: r2ssa::ValueId,
    pub storage: r2ssa::CanonicalStorageId,
    pub source_inst: Option<r2ssa::InstId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackCallArgumentLocationFact {
    pub index: usize,
    pub value: r2ssa::ValueId,
    pub object: r2ssa::ObjectId,
    pub offset: i64,
    pub memory_access: r2ssa::StructuredAccessId,
    pub source_inst: Option<r2ssa::InstId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InterprocSummaryView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) set: Option<r2ssa::InterprocSummarySet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rollup: Option<SummaryEffectRollup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) helpers: Vec<SummaryHelperView>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryEffectRollup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_return_relation: Option<r2ssa::SummaryReturnRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_param_facts: Vec<SummaryOutParamFact>,
    #[serde(default)]
    pub pointer_param_indices: Vec<usize>,
    #[serde(default)]
    pub transfer_count: usize,
    #[serde(default)]
    pub allocation_count: usize,
    #[serde(default)]
    pub lifetime_count: usize,
    #[serde(default)]
    pub sync_count: usize,
    #[serde(default)]
    pub atomic_count: usize,
    pub helper_summary_count: usize,
    pub has_unknown_calls: bool,
    pub touches_unknown_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHelperView {
    pub function_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_count_hint: Option<usize>,
    pub return_relation: r2ssa::SummaryReturnRelation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_param_facts: Vec<SummaryOutParamFact>,
    #[serde(default)]
    pub pointer_param_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_effects: Vec<r2ssa::SummaryTransferEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allocation_effects: Vec<r2ssa::SummaryAllocationEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifetime_effects: Vec<r2ssa::SummaryLifetimeEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_effects: Vec<r2ssa::SummarySyncEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub atomic_effects: Vec<r2ssa::SummaryAtomicEffect>,
    pub has_unknown_calls: bool,
    pub touches_unknown_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryOutParamFact {
    pub param_index: usize,
    pub evidence: OutParamCertificateEvidence,
    pub source: OutParamCertificateSource,
}

impl InterprocSummaryView {
    pub fn new(
        set: Option<r2ssa::InterprocSummarySet>,
    ) -> Result<Self, r2ssa::interproc::InterprocSummarySchemaError> {
        if let Some(set) = set.as_ref() {
            set.validate_current_schema()?;
        }
        let rollup = summary_rollup(set.as_ref());
        let helpers = helper_views(set.as_ref());
        Ok(Self {
            set,
            rollup,
            helpers,
        })
    }

    pub fn as_set(&self) -> Option<&r2ssa::InterprocSummarySet> {
        self.set.as_ref()
    }

    pub fn root_summary(&self) -> Option<&r2ssa::FunctionSemanticSummary> {
        let set = self.set.as_ref()?;
        let root = set.root?;
        set.summaries.get(&root)
    }

    pub fn diagnostics(&self) -> Option<&r2ssa::InterprocSummaryDiagnostics> {
        self.set.as_ref().map(|set| &set.diagnostics)
    }

    pub fn helper_summary_for_name(&self, name: &str) -> Option<&r2ssa::FunctionSemanticSummary> {
        let normalized = name.trim().to_ascii_lowercase();
        self.set.as_ref()?.summaries.values().find(|summary| {
            summary
                .name
                .as_deref()
                .is_some_and(|summary_name| summary_name.trim().to_ascii_lowercase() == normalized)
        })
    }

    pub fn helper_view_for_name(&self, name: &str) -> Option<&SummaryHelperView> {
        let normalized = name.trim().to_ascii_lowercase();
        self.helpers.iter().find(|summary| {
            summary
                .name
                .as_deref()
                .is_some_and(|summary_name| summary_name.trim().to_ascii_lowercase() == normalized)
        })
    }

    pub fn out_param_indices(&self) -> Vec<usize> {
        out_param_indices_from_facts(
            self.rollup
                .as_ref()
                .map(|rollup| rollup.out_param_facts.as_slice())
                .unwrap_or(&[]),
        )
    }

    pub fn pointer_param_indices(&self) -> &[usize] {
        self.rollup
            .as_ref()
            .map(|rollup| rollup.pointer_param_indices.as_slice())
            .unwrap_or(&[])
    }
}

/// The logical return type licensed by the exact source interface and every
/// certified machine return boundary.
///
/// This is independent of whether advisory type recovery happened to create a
/// whole [`FunctionSignatureSpec`]. In particular, a tail-only function has no
/// `SSAOp::Return` from which the decompiler could infer a type, while its exact
/// tail-call boundary still proves the carrier returned on the caller's behalf.
pub fn exact_source_return_type(source: &r2ssa::SsaArtifact) -> Option<CTypeLike> {
    let context = source.machine_context();
    let abi = context.abi_model();
    let memory = context.memory_model();
    if !abi.is_available()
        || !abi.return_boundary_is_coherent()
        || !memory.is_available()
        || !memory.is_coherent()
    {
        return None;
    }
    let interface = context.function_interface()?;
    let r2ssa::SourceFunctionReturn::Register { storage } = interface.return_kind() else {
        return None;
    };
    if storage.space != r2ssa::CanonicalStorageSpace::Register || storage.size == 0 {
        return None;
    }
    let logical = interface.return_logical_value()?;
    let graph = interface.type_graph()?;
    let source_type = graph
        .types()
        .get(usize::try_from(logical.type_id()).ok()?)
        .filter(|source_type| source_type.id() == logical.type_id())?;
    let projection = logical.carrier();
    let storage_bits = u64::from(storage.size).checked_mul(8)?;
    if projection.offset_bits() != 0
        || projection.size_bits() == 0
        || projection.size_bits() != source_type.size_bits()
        || projection.size_bits() % 8 != 0
        || projection.size_bits() > storage_bits
    {
        return None;
    }
    let logical_width = match projection.kind() {
        r2ssa::SourceCarrierKind::Full if projection.size_bits() == storage_bits => storage.size,
        r2ssa::SourceCarrierKind::LowBits
            if projection.size_bits() < storage_bits
                && matches!(
                    source_type.kind(),
                    r2ssa::SourceTypeKind::SignedInteger | r2ssa::SourceTypeKind::UnsignedInteger
                ) =>
        {
            u32::try_from(projection.size_bits() / 8).ok()?
        }
        _ => return None,
    };
    let expected_carrier = r2ssa::ReturnCarrier::Register { storage };
    let mut return_count = 0usize;
    for &block_addr in source.function().block_addrs() {
        let block = source.function().get_block(block_addr)?;
        for (op_index, op) in block.ops.iter().enumerate() {
            if !matches!(op, r2ssa::SSAOp::Return { .. }) {
                continue;
            }
            return_count = return_count.checked_add(1)?;
            let certificate = source.return_certificate_for_op(block_addr, op_index)?;
            if !exact_return_certificate_matches(
                certificate,
                logical,
                logical_width,
                &expected_carrier,
            ) {
                return None;
            }
        }
    }
    let mut tail_return_count = 0usize;
    for call_site in source
        .facts()
        .call_sites
        .by_id
        .values()
        .filter(|call_site| call_site.transfer == r2ssa::CallSiteTransfer::TailCall)
    {
        let certificate = source.certificates().callsites.get(&call_site.id)?;
        let boundary = source.facts().boundaries.calls.get(&call_site.id)?;
        if !exact_tail_return_certificate_matches(call_site, certificate, boundary, storage) {
            return None;
        }
        tail_return_count = tail_return_count.checked_add(1)?;
    }
    let certified_tail_return_count = source
        .certificates()
        .callsites
        .values()
        .filter(|certificate| certificate.transfer == r2ssa::CallSiteTransfer::TailCall)
        .count();
    if return_count + tail_return_count == 0
        || source.certificates().returns.len() != return_count
        || source.certificates().returns_by_inst.len() != return_count
        || certified_tail_return_count != tail_return_count
    {
        return None;
    }

    crate::analysis::source_type_like(graph, logical.type_id(), &mut BTreeSet::new())
}

pub(crate) fn exact_return_certificate_matches(
    certificate: &r2ssa::ReturnValueCertificate,
    logical: r2ssa::SourceLogicalValue,
    logical_width: u32,
    expected_carrier: &r2ssa::ReturnCarrier,
) -> bool {
    certificate.source_logical_value == Some(logical)
        && certificate.width == logical_width
        && certificate.carrier.as_ref() == Some(expected_carrier)
}

pub(crate) fn exact_tail_return_certificate_matches(
    call_site: &r2ssa::CallSiteFact,
    certificate: &r2ssa::CallsiteCertificate,
    boundary: &r2ssa::SourceCallBoundaryFact,
    expected_storage: r2ssa::CanonicalStorageId,
) -> bool {
    call_site.transfer == r2ssa::CallSiteTransfer::TailCall
        && call_site.raw_identity.is_some()
        && certificate.transfer == r2ssa::CallSiteTransfer::TailCall
        && certificate.call_site == call_site.id
        && certificate.at == call_site.at
        && certificate.target == call_site.target
        && boundary.call_site == call_site.id
        && boundary.at == call_site.at
        && boundary.complete
        && boundary.result_kind
            == Some(r2ssa::SourceCallResult::Register {
                storage: expected_storage,
            })
}

/// The aggregate a type node names, when it names one.
/// The parameter slot an address is wholly relative to.
pub(crate) fn parameter_base_of(
    prepared: &r2ssa::SsaArtifact,
    address: r2ssa::ValueId,
) -> Option<usize> {
    let expression = prepared.addresses().parameter_expression(address)?;
    expression.terms.is_empty().then_some(expression.parameter)
}

/// The aggregate a pointer parameter points at.
pub(crate) fn parameter_pointee_type(
    interface: &r2ssa::SourceFunctionInterface,
    parameter: usize,
) -> Option<u32> {
    let logical = interface.parameter_logical_value(parameter)?;
    let graph = interface.type_graph()?;
    let ty = graph
        .types()
        .get(usize::try_from(logical.type_id()).ok()?)?;
    match ty.kind() {
        r2ssa::SourceTypeKind::Pointer { target_type_id } => Some(target_type_id),
        _ => None,
    }
}

pub(crate) fn aggregate_layout_for_type(
    graph: &r2ssa::SourceTypeGraph,
    type_id: u32,
) -> Option<&r2ssa::SourceAggregateLayout> {
    let ty = graph.types().get(usize::try_from(type_id).ok()?)?;
    let aggregate_id = match ty.kind() {
        r2ssa::SourceTypeKind::Struct { aggregate_id }
        | r2ssa::SourceTypeKind::Union { aggregate_id } => aggregate_id,
        _ => return None,
    };
    graph
        .aggregates()
        .get(usize::try_from(aggregate_id).ok()?)
        .filter(|aggregate| aggregate.id() == aggregate_id && aggregate.type_id() == type_id)
}

pub(crate) fn parameter_entry_value_has_live_use(
    prepared: &r2ssa::SsaArtifact,
    root: r2ssa::ValueId,
    implicit_call_arguments: &BTreeSet<r2ssa::ValueId>,
) -> bool {
    let graph = prepared.graph();
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(value) = pending.pop() {
        if !visited.insert(value) {
            continue;
        }
        if implicit_call_arguments.contains(&value) {
            return true;
        }
        for use_site in graph.use_sites(value) {
            let Some(inst) = graph.inst(use_site.inst) else {
                continue;
            };
            if matches!(inst.payload, r2ssa::InstPayload::Phi { .. }) {
                if let Some(output) = inst.output {
                    pending.push(output);
                }
                continue;
            }
            return true;
        }
    }
    false
}

/// Whether a recovered type is better evidence than what is already recorded.
///
/// A width is not a type. A slot that nothing is known about is given the width
/// of the register that spilled it, and any structured type outranks that; a
/// type that is already structured is never demoted, so a recovered type cannot
/// overwrite a declared one.
pub(crate) fn recovered_type_outranks(
    existing: &CTypeLike,
    recovered: &CTypeLike,
    ptr_bits: u32,
    type_db: &crate::ExternalTypeDb,
) -> bool {
    if crate::signature_infer::signature_types_are_equivalent(existing, recovered, ptr_bits) {
        return false;
    }
    if crate::facts::signature_hint_can_replace_existing(
        existing,
        Some(recovered),
        ptr_bits,
        type_db,
    ) {
        return true;
    }
    crate::facts::is_weak_storage_scalar_type(existing, ptr_bits)
        && recovered_type_is_evidence(recovered, ptr_bits)
}

/// Whether a type says more than the width of the storage that held it.
pub(crate) fn recovered_type_is_evidence(ty: &CTypeLike, ptr_bits: u32) -> bool {
    match ty {
        CTypeLike::Pointer(inner) => !matches!(inner.as_ref(), CTypeLike::Unknown),
        CTypeLike::Float(_)
        | CTypeLike::Bool
        | CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_) => true,
        CTypeLike::Typedef { name, .. } => {
            !crate::facts::is_weak_storage_scalar_typedef(name, ptr_bits)
        }
        _ => false,
    }
}

/// Operation-proven signedness refines a weak scalar of the same width.
pub(crate) fn recovered_scalar_signedness_outranks(
    existing: &CTypeLike,
    recovered: &CTypeLike,
    ptr_bits: u32,
) -> bool {
    let scalar = |ty: &CTypeLike| match ty {
        CTypeLike::Int { bits, signedness } => Some((*bits, *signedness)),
        CTypeLike::Typedef { name, .. } => match crate::parse_c_type_like(name, ptr_bits) {
            Some(CTypeLike::Int { bits, signedness }) => Some((bits, signedness)),
            _ => None,
        },
        _ => None,
    };
    let (Some((existing_bits, existing_signedness)), Some((recovered_bits, recovered_signedness))) =
        (scalar(existing), scalar(recovered))
    else {
        return false;
    };
    existing_bits == recovered_bits
        && existing_signedness != recovered_signedness
        && recovered_signedness != crate::Signedness::Unknown
}

pub(crate) fn struct_name_from_pointer_type(ty: Option<&CTypeLike>) -> Option<&str> {
    let CTypeLike::Pointer(inner) = ty? else {
        return None;
    };
    match inner.as_ref() {
        CTypeLike::Struct(name) | CTypeLike::Typedef { name, .. } => Some(name),
        _ => None,
    }
}

pub(crate) fn prepared_callee_resolution_facts(
    prepared: &r2ssa::SsaArtifact,
    function_facts: &FunctionFacts,
) -> CalleeResolutionFacts {
    let type_facts = function_facts.types.clone().canonicalized();
    // These were empty maps, so every direct call resolved to nothing and
    // rendered as `sub_<addr>` even when radare2 had the name all along.
    let function_names = function_facts
        .display_names
        .functions()
        .iter()
        .map(|(addr, name)| (*addr, name.clone()))
        .collect::<HashMap<_, _>>();
    let symbols = function_facts
        .display_names
        .symbols()
        .iter()
        .map(|(addr, name)| (*addr, name.clone()))
        .collect::<HashMap<_, _>>();
    let known_function_signatures = type_facts
        .known_function_signatures
        .iter()
        .map(|(name, ty)| (crate::normalize_callee_name(name), ty.clone()))
        .collect::<HashMap<_, _>>();
    // The linkage radare2 read off the symbol or relocation that named each
    // call target is the fact import policy rests on; a name's shape is not.
    let mut callee_facts = type_facts.callee_facts;
    for cert in prepared.certificates().callsites.values() {
        let linkage = match cert.callee_linkage {
            r2source::AdvisoryCalleeLinkage::Unknown => continue,
            r2source::AdvisoryCalleeLinkage::Internal => CalleeLinkage::Internal,
            r2source::AdvisoryCalleeLinkage::Imported => CalleeLinkage::Imported,
        };
        let Some(target) = cert.direct_target else {
            continue;
        };
        let fact = callee_facts.entry(target).or_insert_with(|| {
            CalleeFact::named(target, function_names.get(&target).cloned(), linkage)
        });
        if fact.linkage == CalleeLinkage::Unknown {
            fact.linkage = linkage;
        }
    }
    let ctx = CalleeIdentityContext {
        function_names: &function_names,
        symbols: &symbols,
        callee_facts: &callee_facts,
        known_function_signatures: &known_function_signatures,
    };

    CalleeResolutionFacts::from_direct_call_targets(
        prepared
            .call_sites()
            .by_id
            .values()
            .filter_map(|call_site| {
                let direct_target = prepared.resolved_call_target(call_site)?;
                let (block_addr, op_index) = prepared.inst_op_site(call_site.at)?;
                Some((
                    CallsiteKey {
                        block_addr,
                        op_index,
                    },
                    direct_target,
                ))
            }),
        &ctx,
    )
}

pub(crate) fn prepared_callsite_argument_facts(
    prepared: &r2ssa::SsaArtifact,
) -> FunctionCallsiteFacts {
    let by_callsite = prepared
        .certificates()
        .callsites
        .values()
        .filter_map(|cert| {
            let (block_addr, op_index) = prepared.inst_op_site(cert.at)?;
            let callsite = CallsiteKey {
                block_addr,
                op_index,
            };
            let argument_values = cert
                .argument_values
                .iter()
                .copied()
                .enumerate()
                .map(|(index, value)| CallArgumentValueFact { index, value })
                .collect();
            let register_argument_locations = cert
                .argument_certificates
                .iter()
                .filter_map(|argument| {
                    let r2ssa::CallArgumentLocation::Register { storage } = &argument.location
                    else {
                        return None;
                    };
                    Some(RegisterCallArgumentLocationFact {
                        index: argument.index,
                        value: argument.value,
                        storage: *storage,
                        source_inst: argument.source_inst,
                    })
                })
                .collect();
            let stack_argument_locations = cert
                .argument_certificates
                .iter()
                .filter_map(|argument| {
                    let r2ssa::CallArgumentLocation::Stack {
                        object,
                        offset,
                        memory_access,
                    } = argument.location
                    else {
                        return None;
                    };
                    Some(StackCallArgumentLocationFact {
                        index: argument.index,
                        value: argument.value,
                        object,
                        offset,
                        memory_access,
                        source_inst: argument.source_inst,
                    })
                })
                .collect();
            Some((
                callsite,
                CallsiteArgumentFacts {
                    callsite,
                    call_site_id: cert.call_site,
                    at: cert.at,
                    target: cert.target,
                    direct_target: cert.direct_target,
                    argument_values,
                    variadic: cert.variadic,
                    fixed_argument_count: cert.fixed_argument_count,
                    // Carrier widths alone do not prove C signedness. A
                    // source-owned callee analysis fills this only after its
                    // exact retained interface matches this call site.
                    callee_signature: None,
                    callee_signature_from_source_types: false,
                    variadic_argument_count_evidence: cert.variadic_argument_count_evidence,
                    variadic_argument_count_refusal: cert.variadic_argument_count_refusal,
                    register_argument_locations,
                    stack_argument_locations,
                    arguments_complete: cert.arguments_complete,
                    results_complete: cert.results_complete,
                },
            ))
        })
        .collect();
    FunctionCallsiteFacts { by_callsite }
}

pub(crate) fn prepared_call_result_facts(prepared: &r2ssa::SsaArtifact) -> FunctionCallResultFacts {
    let mut by_value = BTreeMap::new();
    let mut by_callsite = BTreeMap::<CallsiteKey, Vec<r2ssa::ValueId>>::new();
    for cert in prepared.certificates().call_results.values() {
        let Some(callsite_cert) = prepared.certificates().callsites.get(&cert.call_site) else {
            continue;
        };
        let callsite = CallsiteKey {
            block_addr: callsite_cert.block_addr,
            op_index: callsite_cert.op_index,
        };
        by_callsite.entry(callsite).or_default().push(cert.value);
        by_value.insert(
            cert.value,
            CallResultFact {
                callsite,
                call_site_id: cert.call_site,
                at: cert.at,
                value: cert.value,
                width: cert.width,
                relation: cert.relation,
                carrier: cert.carrier.clone(),
                owner: cert.owner.clone(),
            },
        );
    }
    FunctionCallResultFacts {
        by_value,
        by_callsite,
    }
}

pub(crate) fn prepared_call_render_facts(prepared: &r2ssa::SsaArtifact) -> FunctionCallRenderFacts {
    let by_callsite = prepared
        .certificates()
        .callsites
        .values()
        .map(|cert| {
            let callsite = CallsiteKey {
                block_addr: cert.block_addr,
                op_index: cert.op_index,
            };
            // This fact says how control leaves the site, not what the
            // statement assigns; the plan owns that, from the value it defines.
            let count_refusal = if cert.variadic {
                cert.variadic_argument_count_refusal.or_else(|| {
                    cert.variadic_argument_count_evidence.is_none().then_some(
                        r2ssa::VariadicCallsiteArgumentCountRefusal::MissingFormatParameter,
                    )
                })
            } else {
                None
            };
            let disposition = if count_refusal.is_some() {
                CallsiteRenderDisposition::Residualized
            } else if cert.transfer == r2ssa::CallSiteTransfer::TailCall {
                // A tail transfer returns whatever the callee leaves, and
                // what the caller's own declaration says of that decides the
                // spelling: a void function discards it (`callee(); return;`),
                // a function returning a value hands it on (`return callee();`)
                // only where the callee produces one, and a function that
                // declares a value the callee does not produce returns nothing
                // this can prove.
                let function_returns_void = prepared
                    .machine_context()
                    .function_interface()
                    .map(|interface| interface.return_kind())
                    .is_some_and(|kind| kind == r2ssa::SourceFunctionReturn::Void);
                match prepared
                    .facts()
                    .boundaries
                    .calls
                    .get(&cert.call_site)
                    .filter(|boundary| boundary.results_complete && boundary.at == cert.at)
                    .and_then(|boundary| boundary.result_kind)
                {
                    Some(_) if function_returns_void => {
                        CallsiteRenderDisposition::TerminalVoidReturn
                    }
                    Some(r2ssa::SourceCallResult::Register { .. }) => {
                        CallsiteRenderDisposition::TerminalReturn
                    }
                    Some(r2ssa::SourceCallResult::Void) => {
                        CallsiteRenderDisposition::TerminalVoidReturn
                    }
                    // Nothing describes the callee, so nothing says what it
                    // returns. The transfer is still a transfer: control
                    // leaves through it and comes back to this function's
                    // caller, so whatever the callee leaves in the result slot
                    // is this function's result. Rendering it as
                    // `return callee(...)` claims only what the ABI already
                    // says; the alternative was dropping the call entirely,
                    // which is a wrong answer rather than a cautious one.
                    // A void caller discards the value, which the arm above
                    // covers once the boundary names a kind, and here too.
                    None if function_returns_void => CallsiteRenderDisposition::TerminalVoidReturn,
                    None => CallsiteRenderDisposition::TerminalReturn,
                }
            } else {
                CallsiteRenderDisposition::Statement
            };
            (
                callsite,
                CallsiteRenderFact {
                    callsite,
                    target: Some(cert.target),
                    disposition,
                    proof_values: cert.argument_values.clone(),
                    residual_reason: count_refusal
                        .map(|refusal| format!("variadic callsite: {}", refusal.kind())),
                },
            )
        })
        .collect();
    FunctionCallRenderFacts { by_callsite }
}

pub(crate) fn prepared_memory_access_field_offset(
    prepared: &r2ssa::SsaArtifact,
    memory: &MemoryAccessRenderFact,
) -> Option<u64> {
    let offset = prepared_address_base_offset(prepared, memory.address, 0)?;
    u64::try_from(offset).ok()
}

pub(crate) fn prepared_memory_access_param_slot(
    prepared: &r2ssa::SsaArtifact,
    memory: &MemoryAccessRenderFact,
    param_slots: &ParamSlotResolver,
) -> Option<usize> {
    prepared_address_base_param_slot(prepared, memory.address, param_slots, 0)
}

pub(crate) fn prepared_memory_access_ptr_bits(
    prepared: &r2ssa::SsaArtifact,
    memory: &MemoryAccessRenderFact,
) -> u32 {
    prepared
        .graph()
        .value(memory.address)
        .map(|value| value.var.size.saturating_mul(8))
        .filter(|bits| *bits > 0)
        .unwrap_or(64)
}

pub(crate) fn prepared_address_base_offset(
    prepared: &r2ssa::SsaArtifact,
    value: r2ssa::ValueId,
    depth: usize,
) -> Option<i64> {
    if depth > 8 {
        return None;
    }
    let graph = prepared.graph();
    let var = &graph.value(value)?.var;
    if const_var_i64(var).is_some() {
        return None;
    }
    if prepared
        .stack_reload_certificate_for_value(value)
        .and_then(|reload| graph.value(reload.canonical_source))
        .is_some_and(|source| source.var.version == 0 && source.var.is_register())
    {
        return Some(0);
    }
    let Some(def_inst) = graph.def_inst(value) else {
        return Some(0);
    };
    let inst = graph.inst(def_inst)?;
    if matches!(inst.payload, r2ssa::InstPayload::Phi { .. }) {
        let mut resolved = None;
        for input in &inst.inputs {
            let Some(offset) = prepared_address_base_offset(prepared, *input, depth + 1) else {
                continue;
            };
            if resolved.is_some_and(|existing| existing != offset) {
                return None;
            }
            resolved = Some(offset);
        }
        return resolved;
    }
    let r2ssa::InstPayload::Op(op) = &inst.payload else {
        unreachable!("handled phi instruction before op matching");
    };
    match op {
        r2ssa::SSAOp::Copy { src, .. }
        | r2ssa::SSAOp::New { src, .. }
        | r2ssa::SSAOp::Cast { src, .. }
        | r2ssa::SSAOp::Subpiece { src, .. }
        | r2ssa::SSAOp::IntZExt { src, .. }
        | r2ssa::SSAOp::IntSExt { src, .. } => prepared_var_base_offset(prepared, src, depth + 1),
        r2ssa::SSAOp::IntAdd { a, b, .. } => {
            prepared_binary_const_offset(prepared, a, b, depth + 1, 1)
        }
        r2ssa::SSAOp::IntSub { a, b, .. } => {
            prepared_binary_const_offset(prepared, a, b, depth + 1, -1)
        }
        r2ssa::SSAOp::PtrAdd {
            base,
            index,
            element_size,
            ..
        } => {
            let delta = const_var_i64(index)?.checked_mul(i64::from(*element_size))?;
            prepared_var_base_offset(prepared, base, depth + 1)?.checked_add(delta)
        }
        r2ssa::SSAOp::PtrSub {
            base,
            index,
            element_size,
            ..
        } => {
            let delta = const_var_i64(index)?.checked_mul(i64::from(*element_size))?;
            prepared_var_base_offset(prepared, base, depth + 1)?.checked_sub(delta)
        }
        _ => None,
    }
}

pub(crate) fn prepared_var_base_offset(
    prepared: &r2ssa::SsaArtifact,
    var: &r2ssa::SSAVar,
    depth: usize,
) -> Option<i64> {
    let value = prepared.graph().value_id_for_var(var)?;
    prepared_address_base_offset(prepared, value, depth)
}

pub(crate) fn prepared_binary_const_offset(
    prepared: &r2ssa::SsaArtifact,
    a: &r2ssa::SSAVar,
    b: &r2ssa::SSAVar,
    depth: usize,
    rhs_sign: i64,
) -> Option<i64> {
    match (const_var_i64(a), const_var_i64(b)) {
        (None, Some(rhs)) => {
            let delta = rhs.checked_mul(rhs_sign)?;
            prepared_var_base_offset(prepared, a, depth)?.checked_add(delta)
        }
        (Some(lhs), None) if rhs_sign == 1 => {
            prepared_var_base_offset(prepared, b, depth)?.checked_add(lhs)
        }
        _ => None,
    }
}

pub(crate) fn prepared_address_base_param_slot(
    prepared: &r2ssa::SsaArtifact,
    value: r2ssa::ValueId,
    param_slots: &ParamSlotResolver,
    depth: usize,
) -> Option<usize> {
    if depth > 8 {
        return None;
    }
    let graph = prepared.graph();
    let var = &graph.value(value)?.var;
    if const_var_i64(var).is_some() {
        return None;
    }
    if let Some(source) = prepared
        .stack_reload_certificate_for_value(value)
        .and_then(|reload| graph.value(reload.canonical_source))
        && source.var.version == 0
    {
        return param_slots.slot_for_value(source.id);
    }
    let Some(def_inst) = graph.def_inst(value) else {
        return param_slots.slot_for_value(value);
    };
    let inst = graph.inst(def_inst)?;
    if matches!(inst.payload, r2ssa::InstPayload::Phi { .. }) {
        let mut resolved = None;
        for input in &inst.inputs {
            let Some(slot) =
                prepared_address_base_param_slot(prepared, *input, param_slots, depth + 1)
            else {
                continue;
            };
            if resolved.is_some_and(|existing| existing != slot) {
                return None;
            }
            resolved = Some(slot);
        }
        return resolved;
    }
    let r2ssa::InstPayload::Op(op) = &inst.payload else {
        unreachable!("handled phi instruction before op matching");
    };
    match op {
        r2ssa::SSAOp::Copy { src, .. }
        | r2ssa::SSAOp::New { src, .. }
        | r2ssa::SSAOp::Cast { src, .. }
        | r2ssa::SSAOp::Subpiece { src, .. }
        | r2ssa::SSAOp::IntZExt { src, .. }
        | r2ssa::SSAOp::IntSExt { src, .. } => {
            prepared_var_base_param_slot(prepared, src, param_slots, depth + 1)
        }
        r2ssa::SSAOp::IntAdd { a, b, .. } => {
            prepared_add_param_slot(prepared, a, b, param_slots, depth + 1)
        }
        r2ssa::SSAOp::IntSub { a, b, .. } => {
            prepared_sub_param_slot(prepared, a, b, param_slots, depth + 1)
        }
        r2ssa::SSAOp::PtrAdd { base, .. } | r2ssa::SSAOp::PtrSub { base, .. } => {
            prepared_var_base_param_slot(prepared, base, param_slots, depth + 1)
        }
        _ => None,
    }
}

pub(crate) fn prepared_var_base_param_slot(
    prepared: &r2ssa::SsaArtifact,
    var: &r2ssa::SSAVar,
    param_slots: &ParamSlotResolver,
    depth: usize,
) -> Option<usize> {
    let value = prepared.graph().value_id_for_var(var)?;
    prepared_address_base_param_slot(prepared, value, param_slots, depth)
}

pub(crate) fn prepared_add_param_slot(
    prepared: &r2ssa::SsaArtifact,
    a: &r2ssa::SSAVar,
    b: &r2ssa::SSAVar,
    param_slots: &ParamSlotResolver,
    depth: usize,
) -> Option<usize> {
    match (const_var_i64(a), const_var_i64(b)) {
        (None, Some(_)) => prepared_var_base_param_slot(prepared, a, param_slots, depth),
        (Some(_), None) => prepared_var_base_param_slot(prepared, b, param_slots, depth),
        _ => None,
    }
}

pub(crate) fn prepared_sub_param_slot(
    prepared: &r2ssa::SsaArtifact,
    a: &r2ssa::SSAVar,
    b: &r2ssa::SSAVar,
    param_slots: &ParamSlotResolver,
    depth: usize,
) -> Option<usize> {
    match (const_var_i64(a), const_var_i64(b)) {
        (None, Some(_)) => prepared_var_base_param_slot(prepared, a, param_slots, depth),
        _ => None,
    }
}

pub(crate) fn const_var_i64(var: &r2ssa::SSAVar) -> Option<i64> {
    let raw = var.constant_bits()?;
    let bits = var.size.saturating_mul(8);
    if bits == 0 || bits >= 64 {
        return Some(raw as i64);
    }
    let sign_bit = 1u64.checked_shl(bits - 1)?;
    let mask = 1u64.checked_shl(bits)?.wrapping_sub(1);
    let truncated = raw & mask;
    if truncated & sign_bit == 0 {
        Some(truncated as i64)
    } else {
        Some((truncated | !mask) as i64)
    }
}

pub(crate) fn prepared_predicate_render_comparison<'a>(
    prepared: &r2ssa::SsaArtifact,
    predicate: &'a r2ssa::PredicateFact,
) -> Option<&'a r2ssa::CompareProvenance> {
    predicate
        .evaluated_comparison
        .as_ref()
        .filter(|comparison| {
            [comparison.lhs, comparison.rhs].into_iter().any(|value| {
                prepared
                    .structured()
                    .loops
                    .values()
                    .flat_map(|loop_fact| &loop_fact.carriers)
                    .flat_map(|carrier| &carrier.updates)
                    .any(|update| {
                        update.predecessor == predicate.block_addr
                            && (update.value == value || update.identity_values.contains(&value))
                    })
            })
        })
        .or(predicate.comparison.as_ref())
}

pub(crate) fn prepared_guarded_phi_render_fact(
    prepared: &r2ssa::SsaArtifact,
    value: r2ssa::ValueId,
) -> Option<GuardedPhiRenderFact> {
    let graph = prepared.graph();
    let inst = graph.inst(graph.def_inst(value)?)?;
    let r2ssa::InstPayload::Phi { predecessors } = &inst.payload else {
        return None;
    };
    if predecessors.len() < 2 || predecessors.len() != inst.inputs.len() {
        return None;
    }
    let merge_block = graph.block(inst.block)?.addr;
    let predicates = prepared.predicates();
    let mut arms = Vec::with_capacity(predecessors.len());
    for (predecessor, source) in predecessors.iter().zip(inst.inputs.iter().copied()) {
        let predecessor = graph.block(*predecessor)?.addr;
        let domain = prepared.control_domains().for_block(predecessor)?;
        if !domain.complete {
            return None;
        }
        let mut truths = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for guard in &domain.guards {
            let r2ssa::ControlGuard::Branch { predicate, truth } = guard else {
                continue;
            };
            record_guarded_phi_truth(&mut truths, &mut conflicts, *predicate, *truth);
        }
        for assumption in predicates
            .block_assumptions
            .get(&merge_block)
            .into_iter()
            .flatten()
            .filter(|assumption| assumption.predecessor == predecessor)
        {
            record_guarded_phi_truth(
                &mut truths,
                &mut conflicts,
                assumption.predicate,
                assumption.truth,
            );
        }
        for conflict in conflicts {
            truths.remove(&conflict);
        }
        arms.push((source, truths));
    }

    let mut candidates = arms.first()?.1.keys().copied().collect::<BTreeSet<_>>();
    for (_, truths) in arms.iter().skip(1) {
        candidates.retain(|predicate| truths.contains_key(predicate));
    }
    for predicate in candidates {
        let mut when_true = Vec::new();
        let mut when_false = Vec::new();
        for (source, truths) in &arms {
            let truth = *truths.get(&predicate)?;
            let rendered = prepared_guarded_phi_arm_value(prepared, predicate, truth, *source);
            if truth {
                when_true.push((*source, rendered));
            } else {
                when_false.push((*source, rendered));
            }
        }
        if when_true.is_empty() || when_false.is_empty() {
            continue;
        }
        let true_rendered = when_true[0].1;
        let false_rendered = when_false[0].1;
        if when_true
            .iter()
            .any(|(_, rendered)| *rendered != true_rendered)
            || when_false
                .iter()
                .any(|(_, rendered)| *rendered != false_rendered)
        {
            continue;
        }
        return Some(GuardedPhiRenderFact {
            predicate: r2ssa::SemanticId::predicate(predicate),
            when_true: GuardedPhiArmRenderFact {
                sources: when_true
                    .into_iter()
                    .map(|(source, _)| r2ssa::SemanticId::expression(source))
                    .collect(),
                rendered: r2ssa::SemanticId::expression(true_rendered),
            },
            when_false: GuardedPhiArmRenderFact {
                sources: when_false
                    .into_iter()
                    .map(|(source, _)| r2ssa::SemanticId::expression(source))
                    .collect(),
                rendered: r2ssa::SemanticId::expression(false_rendered),
            },
        });
    }
    None
}

pub(crate) fn record_guarded_phi_truth(
    truths: &mut BTreeMap<r2ssa::PredicateId, bool>,
    conflicts: &mut BTreeSet<r2ssa::PredicateId>,
    predicate: r2ssa::PredicateId,
    truth: bool,
) {
    if truths
        .insert(predicate, truth)
        .is_some_and(|existing| existing != truth)
    {
        conflicts.insert(predicate);
    }
}

pub(crate) fn prepared_guarded_phi_arm_value(
    prepared: &r2ssa::SsaArtifact,
    predicate: r2ssa::PredicateId,
    truth: bool,
    source: r2ssa::ValueId,
) -> r2ssa::ValueId {
    let Some(comparison) = prepared
        .predicates()
        .predicates
        .get(&predicate)
        .and_then(|predicate| predicate.comparison.as_ref())
    else {
        return source;
    };
    if !matches!(
        (comparison.kind, truth),
        (r2ssa::CompareKind::Equal, true) | (r2ssa::CompareKind::NotEqual, false)
    ) {
        return source;
    }
    let replacement = if comparison.lhs == source {
        comparison.rhs
    } else if comparison.rhs == source {
        comparison.lhs
    } else {
        return source;
    };
    if prepared
        .value_var(replacement)
        .is_some_and(r2ssa::SSAVar::is_const)
    {
        replacement
    } else {
        source
    }
}

pub(crate) fn prepared_render_facts(prepared: &r2ssa::SsaArtifact) -> FunctionRenderFacts {
    let certificates = prepared.certificates();
    let mut certified_exprs = certificates
        .expressions
        .iter()
        .map(|(value, cert)| {
            let call_result = certificates.call_results.get(value);
            let mut bindings = BTreeSet::new();
            if let Some(result) = call_result {
                bindings.insert(r2ssa::SemanticId::call(result.call_site));
                if let r2ssa::ReturnCarrier::StackSlot { object, .. } = &result.carrier {
                    bindings.insert(r2ssa::SemanticId::stack_slot(*object));
                }
                if let Some(r2ssa::ValueOwner::StackSlot { object, .. }) = &result.owner {
                    bindings.insert(r2ssa::SemanticId::stack_slot(*object));
                }
            }
            let fact = ExpressionRenderFact {
                value: cert.value,
                defining_inst: cert.defining_inst,
                width: cert.width,
                renderable: cert.renderable || call_result.is_some(),
            };
            (
                r2ssa::SemanticId::expression(*value),
                CertifiedExpr {
                    id: r2ssa::SemanticId::expression(*value),
                    fact,
                    inputs: cert
                        .inputs
                        .iter()
                        .copied()
                        .map(r2ssa::SemanticId::expression)
                        .collect(),
                    bindings,
                    guarded_phi: prepared_guarded_phi_render_fact(prepared, *value),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut certified_memory_effects = certificates
        .memory_accesses
        .iter()
        .map(|(access, cert)| {
            let id = r2ssa::SemanticId::memory_access(*access);
            let control_domain = prepared
                .control_domains()
                .for_block(cert.block_addr)
                .expect("memory certificate block has a control domain")
                .clone();
            (
                id,
                CertifiedEffect::Memory {
                    id,
                    fact: MemoryAccessRenderFact {
                        access: cert.access,
                        block_addr: cert.block_addr,
                        op_index: cert.op_index,
                        space: cert.space,
                        object: cert.object,
                        address: cert.address,
                        value: cert.value,
                        is_write: cert.is_write,
                        width: cert.width,
                        object_offset: cert.object_offset,
                        materialize_result: false,
                        control_domain,
                    },
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let memory_effects_by_op = certificates
        .memory_accesses_by_op
        .iter()
        .map(|(op, accesses)| {
            (
                *op,
                accesses
                    .iter()
                    .copied()
                    .map(r2ssa::SemanticId::memory_access)
                    .collect(),
            )
        })
        .collect();
    let certified_return_effects = certificates
        .returns
        .iter()
        .map(|cert| {
            let id = r2ssa::SemanticId::return_value(cert.at);
            let control_domain = prepared
                .control_domains()
                .for_block(cert.block_addr)
                .expect("return certificate block has a control domain")
                .clone();
            (
                id,
                CertifiedEffect::Return {
                    id,
                    at: cert.at,
                    fact: ReturnValueRenderFact {
                        block_addr: cert.block_addr,
                        op_index: cert.op_index,
                        value: cert.value,
                        width: cert.width,
                        control_domain,
                    },
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let return_effects_by_op = certified_return_effects
        .iter()
        .filter_map(|(id, effect)| {
            effect
                .return_fact()
                .map(|fact| ((fact.block_addr, fact.op_index), *id))
        })
        .collect();
    let mut certified_entities = certificates
        .stack_slots
        .iter()
        .map(|(object, cert)| {
            let id = r2ssa::SemanticId::stack_slot(*object);
            (
                id,
                CertifiedEntity::StackSlot {
                    id,
                    object: *object,
                    base: cert.base,
                    offset: cert.offset,
                    size: cert.size,
                    array_layout: cert.array_layout.clone(),
                    source_slot: cert.source_slot,
                    reload_values: cert.reload_values.clone(),
                    stored_values: cert.stored_values.clone(),
                    callee_allocation: cert.callee_allocation.clone(),
                    ty: cert
                        .source_slot
                        .and_then(|slot| slot.logical_type())
                        .and_then(|type_id| {
                            let graph = prepared
                                .machine_context()
                                .function_interface()?
                                .type_graph()?;
                            crate::analysis::source_type_like(graph, type_id, &mut BTreeSet::new())
                        }),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let observable_roots = certificates
        .returns
        .iter()
        .map(|cert| cert.value)
        .chain(
            certificates
                .memory_accesses
                .values()
                .flat_map(|cert| std::iter::once(cert.address).chain(cert.value)),
        )
        .chain(certificates.callsites.values().flat_map(|cert| {
            cert.argument_values
                .iter()
                .copied()
                .chain(cert.stack_argument_values.iter().map(|arg| arg.value))
        }))
        .chain(
            prepared
                .predicates()
                .predicates
                .values()
                .flat_map(|predicate| {
                    let mut roots = Vec::new();
                    if let Some(comparison) =
                        prepared_predicate_render_comparison(prepared, predicate)
                    {
                        roots.extend([comparison.lhs, comparison.rhs]);
                    } else {
                        roots.push(predicate.condition);
                    }
                    roots
                }),
        )
        .chain(
            prepared
                .predicates()
                .switches
                .values()
                .filter_map(|switch| switch.selector),
        )
        .collect::<BTreeSet<_>>();
    let mut observable_values = observable_roots;
    let mut pending = observable_values.iter().copied().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        let Some(inst) = prepared
            .graph()
            .def_inst(value)
            .and_then(|inst| prepared.graph().inst(inst))
        else {
            continue;
        };
        for input in &inst.inputs {
            if observable_values.insert(*input) {
                pending.push(*input);
            }
        }
    }
    // Whether a carrier is part of the program is a question about the program,
    // and r2ssa is what answers those. Asking instead whether the phi sits in a
    // backward slice from the roots certified so far made publication depend on
    // what else had been certified, so a carrier whose only consumer was the
    // function's own result vanished whenever the return went uncertified.
    let unobserved = prepared.unobserved_merges();
    let mut carrier_edge_roots = Vec::new();
    let mut carrier_identity_values = BTreeSet::new();
    for carrier in prepared
        .structured()
        .loops
        .values()
        .flat_map(|loop_fact| loop_fact.carriers.iter())
        .filter(|carrier| !unobserved.contains(carrier.phi))
    {
        carrier_identity_values.extend(carrier.identity_values.iter().copied());
        carrier_edge_roots.extend(carrier.entries.iter().map(|entry| entry.value));
        carrier_edge_roots.extend(carrier.updates.iter().map(|update| update.value));
        for value in carrier.members.iter().map(|member| member.value) {
            if let Some(expr) = certified_exprs.get_mut(&r2ssa::SemanticId::expression(value)) {
                expr.bindings.insert(carrier.id);
            }
        }
        certified_entities.insert(
            carrier.id,
            CertifiedEntity::LoopCarrier {
                id: carrier.id,
                loop_id: carrier.loop_id,
                header: carrier.header,
                phi: carrier.phi,
                width: carrier.width,
                identity_values: carrier.identity_values.clone(),
                entries: carrier.entries.clone(),
                updates: carrier.updates.clone(),
                dominating_initializers: carrier.dominating_initializers.clone(),
                members: carrier.members.clone(),
                ty: None,
            },
        );
    }
    let consumer_roots = prepared_render_consumer_occurrences(prepared, carrier_edge_roots);
    // One propagation answers every read: how often a value is inlined does
    // not depend on which read is asking.
    let inline_multiplicity =
        expression_inline_multiplicity(prepared.graph(), &consumer_roots, &carrier_identity_values);
    for effect in certified_memory_effects.values_mut() {
        let CertifiedEffect::Memory { fact, .. } = effect else {
            continue;
        };
        let Some(value) = fact.value.filter(|_| !fact.is_write) else {
            continue;
        };
        if certificates.stack_slots.contains_key(&fact.object) {
            continue;
        }
        fact.materialize_result = inline_multiplicity.get(&value).copied().unwrap_or(0) > 1;
    }
    let mut certified_effects = certified_memory_effects;
    certified_effects.extend(certified_return_effects);
    FunctionRenderFacts {
        certified_exprs,
        certified_entities,
        certified_effects,
        return_effects_by_op,
        memory_effects_by_op,
        string_literals_by_value: BTreeMap::new(),
        member_accesses_by_op: BTreeMap::new(),
        array_accesses_by_op: BTreeMap::new(),
    }
}

pub(crate) fn prepared_render_consumer_occurrences(
    prepared: &r2ssa::SsaArtifact,
    carrier_edge_roots: impl IntoIterator<Item = r2ssa::ValueId>,
) -> Vec<r2ssa::ValueId> {
    let certificates = prepared.certificates();
    let mut roots = certificates
        .returns
        .iter()
        .map(|cert| cert.value)
        .collect::<Vec<_>>();
    for cert in certificates.memory_accesses.values() {
        roots.push(cert.address);
        if cert.is_write {
            roots.extend(cert.value);
        }
    }
    for cert in certificates.callsites.values() {
        roots.extend(cert.argument_values.iter().copied());
        roots.extend(cert.stack_argument_values.iter().map(|arg| arg.value));
    }
    for predicate in prepared.predicates().predicates.values() {
        if let Some(comparison) = prepared_predicate_render_comparison(prepared, predicate) {
            roots.extend([comparison.lhs, comparison.rhs]);
        } else {
            roots.push(predicate.condition);
        }
    }
    roots.extend(
        prepared
            .predicates()
            .switches
            .values()
            .filter_map(|switch| switch.selector),
    );
    roots.extend(carrier_edge_roots);
    roots
}

/// How many times each value is inlined into the expressions rooted at
/// `roots`, saturated at two.
///
/// Rendering inlines an expression, so a value reachable by two distinct
/// dependency paths is printed twice, and the caller only needs to know
/// whether that happens at all.
///
/// This is one propagation for the whole function rather than one search per
/// value asked about. The search it replaces enumerated paths and memoised a
/// value only when nothing below it was still being computed -- which, on a
/// cycle, is every value above the cycle, so the memo was defeated exactly
/// where it was needed and the walk fell back to enumerating paths. Any
/// function with a loop therefore cost time exponential in its shared
/// subexpressions: `gz_decomp` in zlib built at -O2, eighteen blocks and
/// eighty-two instructions, did not finish in two hundred seconds, and a
/// sweep of that binary died on it.
///
/// Multiplicity flows the other way, from the roots down to the leaves, and is
/// a least fixpoint over a lattice of three values. It is monotone, so a
/// worklist settles it in one pass over each edge per increase, and a cycle is
/// no longer a special case: a value a loop carries back into itself simply
/// reaches two, which is what "printed more than once" means for it. A carrier
/// identity is where inlining stops, so it neither counts nor propagates.
pub(crate) fn expression_inline_multiplicity(
    graph: &r2ssa::SsaGraph,
    roots: &[r2ssa::ValueId],
    carrier_identities: &BTreeSet<r2ssa::ValueId>,
) -> BTreeMap<r2ssa::ValueId, u8> {
    let mut multiplicity = BTreeMap::<r2ssa::ValueId, u8>::new();
    let mut worklist = Vec::new();
    for root in roots {
        if carrier_identities.contains(root) {
            continue;
        }
        let slot = multiplicity.entry(*root).or_insert(0);
        let raised = slot.saturating_add(1).min(2);
        if raised != *slot {
            *slot = raised;
            worklist.push(*root);
        }
    }
    while let Some(value) = worklist.pop() {
        let Some(share) = multiplicity.get(&value).copied() else {
            continue;
        };
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        for input in &inst.inputs {
            if carrier_identities.contains(input) {
                continue;
            }
            let slot = multiplicity.entry(*input).or_insert(0);
            let raised = slot.saturating_add(share).min(2);
            if raised != *slot {
                *slot = raised;
                worklist.push(*input);
            }
        }
    }
    multiplicity
}

pub(crate) fn prepared_control_facts(prepared: &r2ssa::SsaArtifact) -> FunctionControlFacts {
    let predicates = prepared.predicates();
    let certificates = prepared.certificates();
    let branch_predicates = predicates
        .predicates
        .values()
        .map(|predicate| {
            (
                predicate.block_addr,
                BranchPredicateFact {
                    id: predicate.id,
                    block_addr: predicate.block_addr,
                    condition: predicate.condition,
                    comparison: predicate.comparison.as_ref().map(|comparison| {
                        PredicateComparisonFact {
                            kind: comparison.kind,
                            lhs: comparison.lhs,
                            rhs: comparison.rhs,
                        }
                    }),
                    evaluated_comparison: predicate.evaluated_comparison.as_ref().map(
                        |comparison| PredicateComparisonFact {
                            kind: comparison.kind,
                            lhs: comparison.lhs,
                            rhs: comparison.rhs,
                        },
                    ),
                    render_comparison: prepared_predicate_render_comparison(prepared, predicate)
                        .map(|comparison| PredicateComparisonFact {
                            kind: comparison.kind,
                            lhs: comparison.lhs,
                            rhs: comparison.rhs,
                        }),
                    true_target: predicate.true_target,
                    false_target: predicate.false_target,
                },
            )
        })
        .collect();
    let block_assumptions = predicates
        .block_assumptions
        .iter()
        .map(|(block_addr, assumptions)| {
            (
                *block_addr,
                assumptions
                    .iter()
                    .map(|assumption| ControlBlockAssumptionFact {
                        predecessor: assumption.predecessor,
                        predicate: assumption.predicate,
                        truth: assumption.truth,
                    })
                    .collect(),
            )
        })
        .collect();
    let loops = certificates
        .loops
        .iter()
        .map(|(loop_id, cert)| {
            (
                *loop_id,
                LoopStructureFact {
                    loop_id: *loop_id,
                    proof_node: cert.proof_node.to_string(),
                    header: cert.header,
                    condition: cert.condition,
                    condition_value: cert.condition.and_then(|id| {
                        predicates
                            .predicates
                            .get(&id)
                            .map(|predicate| predicate.condition)
                    }),
                    body: sorted_u64s(&cert.body),
                    latches: sorted_u64s(&cert.latches),
                    exits: sorted_u64s(&cert.exits),
                    for_loop: cert.for_loop.clone(),
                },
            )
        })
        .collect();
    let switches = predicates
        .switches
        .iter()
        .map(|(block_addr, switch)| {
            (
                *block_addr,
                SwitchSelectorFact {
                    proof_node: r2ssa::ProofNodeId::switch_certificate(*block_addr).to_string(),
                    block_addr: switch.block_addr,
                    selector: switch.selector,
                    cases: switch.cases.clone(),
                    default: switch.default,
                },
            )
        })
        .collect();
    FunctionControlFacts {
        branch_predicates,
        block_assumptions,
        loops,
        switches,
        control_domains: prepared.control_domains().clone(),
    }
}

pub(crate) fn sorted_u64s(values: &[u64]) -> Vec<u64> {
    let mut values = values.to_vec();
    values.sort_unstable();
    values
}

pub(crate) fn summary_rollup(
    set: Option<&r2ssa::InterprocSummarySet>,
) -> Option<SummaryEffectRollup> {
    let set = set?;
    let root_summary = set.root.and_then(|root| set.summaries.get(&root));
    let out_param_facts = root_summary
        .map(summary_out_param_facts)
        .unwrap_or_default();

    let mut pointer_param_indices = root_summary
        .map(|summary| {
            let mut indices = summary
                .arg_effects
                .iter()
                .filter_map(|(idx, effect)| {
                    (effect.read || effect.write || effect.escape || effect.free).then_some(*idx)
                })
                .collect::<Vec<_>>();
            for effect in &summary.memory_effects {
                if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.location.region {
                    indices.push(index);
                }
            }
            push_structured_summary_pointer_indices(summary, &mut indices);
            indices
        })
        .unwrap_or_default();
    pointer_param_indices.sort_unstable();
    pointer_param_indices.dedup();

    Some(SummaryEffectRollup {
        root_name: root_summary.and_then(|summary| summary.name.clone()),
        root_return_relation: root_summary.map(|summary| summary.return_relation.clone()),
        out_param_facts,
        pointer_param_indices,
        transfer_count: root_summary.map_or(0, |summary| summary.transfer_effects.len()),
        allocation_count: root_summary.map_or(0, |summary| summary.allocation_effects.len()),
        lifetime_count: root_summary.map_or(0, |summary| summary.lifetime_effects.len()),
        sync_count: root_summary.map_or(0, |summary| summary.sync_effects.len()),
        atomic_count: root_summary.map_or(0, |summary| summary.atomic_effects.len()),
        helper_summary_count: set
            .summaries
            .len()
            .saturating_sub(usize::from(set.root.is_some())),
        has_unknown_calls: root_summary.is_some_and(|summary| summary.has_unknown_calls),
        touches_unknown_memory: root_summary.is_some_and(|summary| summary.touches_unknown_memory),
    })
}

pub(crate) fn helper_views(set: Option<&r2ssa::InterprocSummarySet>) -> Vec<SummaryHelperView> {
    let Some(set) = set else {
        return Vec::new();
    };
    let mut helpers = set
        .summaries
        .iter()
        .filter(|(id, _)| Some(**id) != set.root)
        .map(|(id, summary)| {
            let out_param_facts = summary_out_param_facts(summary);

            let mut pointer_param_indices = summary
                .arg_effects
                .iter()
                .filter_map(|(idx, effect)| {
                    (effect.read || effect.write || effect.escape || effect.free).then_some(*idx)
                })
                .collect::<Vec<_>>();
            for effect in &summary.memory_effects {
                if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.location.region {
                    pointer_param_indices.push(index);
                }
            }
            push_structured_summary_pointer_indices(summary, &mut pointer_param_indices);
            pointer_param_indices.sort_unstable();
            pointer_param_indices.dedup();

            SummaryHelperView {
                function_id: id.0,
                name: summary.name.clone(),
                arg_count_hint: summary.arg_count_hint,
                return_relation: summary.return_relation.clone(),
                out_param_facts,
                pointer_param_indices,
                transfer_effects: summary.transfer_effects.clone(),
                allocation_effects: summary.allocation_effects.clone(),
                lifetime_effects: summary.lifetime_effects.clone(),
                sync_effects: summary.sync_effects.clone(),
                atomic_effects: summary.atomic_effects.clone(),
                has_unknown_calls: summary.has_unknown_calls,
                touches_unknown_memory: summary.touches_unknown_memory,
            }
        })
        .collect::<Vec<_>>();
    helpers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.function_id.cmp(&right.function_id))
    });
    helpers
}

pub(crate) fn summary_out_param_facts(
    summary: &r2ssa::FunctionSemanticSummary,
) -> Vec<SummaryOutParamFact> {
    let mut facts = summary
        .arg_effects
        .iter()
        .enumerate()
        .filter(|(_, (_, effect))| effect.write)
        .map(|(effect_index, (idx, _))| SummaryOutParamFact {
            param_index: *idx,
            evidence: OutParamCertificateEvidence::InterprocArgWrite,
            source: OutParamCertificateSource::InterprocSummaryEffect {
                function_id: summary.id.0,
                evidence: OutParamCertificateEvidence::InterprocArgWrite,
                param_index: *idx,
                effect_index,
            },
        })
        .collect::<Vec<_>>();
    for (effect_index, effect) in summary.memory_effects.iter().enumerate() {
        if effect.kind == r2ssa::SummaryMemoryEffectKind::Write
            && let r2ssa::SummaryMemoryRegion::Arg { index } = effect.location.region
        {
            facts.push(SummaryOutParamFact {
                param_index: index,
                evidence: OutParamCertificateEvidence::InterprocMemoryWrite,
                source: OutParamCertificateSource::InterprocSummaryEffect {
                    function_id: summary.id.0,
                    evidence: OutParamCertificateEvidence::InterprocMemoryWrite,
                    param_index: index,
                    effect_index,
                },
            });
        }
    }
    for (effect_index, effect) in summary.transfer_effects.iter().enumerate() {
        if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.dst.region {
            facts.push(SummaryOutParamFact {
                param_index: index,
                evidence: OutParamCertificateEvidence::InterprocTransferDst,
                source: OutParamCertificateSource::InterprocSummaryEffect {
                    function_id: summary.id.0,
                    evidence: OutParamCertificateEvidence::InterprocTransferDst,
                    param_index: index,
                    effect_index,
                },
            });
        }
    }
    facts.sort();
    facts.dedup();
    facts
}

pub(crate) fn out_param_indices_from_facts(facts: &[SummaryOutParamFact]) -> Vec<usize> {
    let mut indices = facts
        .iter()
        .map(|fact| fact.param_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

pub(crate) fn push_structured_summary_pointer_indices(
    summary: &r2ssa::FunctionSemanticSummary,
    indices: &mut Vec<usize>,
) {
    for effect in &summary.transfer_effects {
        if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.dst.region {
            indices.push(index);
        }
        if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.src.region {
            indices.push(index);
        }
    }
    for effect in &summary.lifetime_effects {
        indices.push(effect.arg);
    }
    for effect in &summary.sync_effects {
        indices.push(effect.arg);
    }
}
