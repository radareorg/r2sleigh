//! The fact types more than one phase reads.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PredicateId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControlDomainId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallSiteId(pub u32);

/// Stable identity for a semantic entity inside one prepared SSA artifact.
///
/// These IDs are derived only from canonical SSA/object identities and ABI
/// parameter slots. They deliberately do not depend on rendered names, AST
/// positions, or traversal order in downstream consumers. Re-preparing the
/// same canonical [`SSAFunction`] therefore produces the same semantic IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticId {
    Expression(ValueId),
    Parameter(u32),
    StackSlot(ObjectId),
    LoopCarrier(ValueId),
    MemoryAccess(StructuredAccessId),
    Return(InstId),
    Call(CallSiteId),
    Predicate(PredicateId),
    ControlDomain(ControlDomainId),
    Effect(InstId),
}

impl SemanticId {
    pub const fn expression(value: ValueId) -> Self {
        Self::Expression(value)
    }

    pub fn parameter(slot: usize) -> Option<Self> {
        u32::try_from(slot).ok().map(Self::Parameter)
    }

    pub const fn stack_slot(object: ObjectId) -> Self {
        Self::StackSlot(object)
    }

    pub const fn loop_carrier(phi: ValueId) -> Self {
        Self::LoopCarrier(phi)
    }

    pub const fn memory_access(access: StructuredAccessId) -> Self {
        Self::MemoryAccess(access)
    }

    pub const fn return_value(at: InstId) -> Self {
        Self::Return(at)
    }

    pub const fn call(call_site: CallSiteId) -> Self {
        Self::Call(call_site)
    }

    pub const fn predicate(predicate: PredicateId) -> Self {
        Self::Predicate(predicate)
    }

    pub const fn control_domain(domain: ControlDomainId) -> Self {
        Self::ControlDomain(domain)
    }

    pub const fn effect(at: InstId) -> Self {
        Self::Effect(at)
    }
}

impl std::fmt::Display for SemanticId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expression(value) => write!(f, "expr:{}", value.0),
            Self::Parameter(slot) => write!(f, "param:{slot}"),
            Self::StackSlot(object) => write!(f, "stack:{}", object.0),
            Self::LoopCarrier(phi) => write!(f, "loop-carrier:{}", phi.0),
            Self::MemoryAccess(access) => {
                write!(f, "memory:{}:{}", access.inst.0, access.ordinal)
            }
            Self::Return(at) => write!(f, "return:{}", at.0),
            Self::Call(call_site) => write!(f, "call:{}", call_site.0),
            Self::Predicate(predicate) => write!(f, "predicate:{}", predicate.0),
            Self::ControlDomain(domain) => write!(f, "domain:{}", domain.0),
            Self::Effect(at) => write!(f, "effect:{}", at.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectSpaceId(pub SpaceId);

impl Ord for ObjectSpaceId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        memory_space_order(self.0).cmp(&memory_space_order(other.0))
    }
}

impl PartialOrd for ObjectSpaceId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryObjectKey {
    pub value: ValueId,
    pub space: SpaceId,
}

impl Ord for MemoryObjectKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value
            .cmp(&other.value)
            .then_with(|| memory_space_order(self.space).cmp(&memory_space_order(other.space)))
    }
}

impl PartialOrd for MemoryObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackObjectKey {
    pub root: StackAddressRoot,
    pub space: SpaceId,
}

impl Ord for StackObjectKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| memory_space_order(self.space).cmp(&memory_space_order(other.space)))
    }
}

impl PartialOrd for StackObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParameterObjectKey {
    pub index: usize,
    pub space: SpaceId,
}

impl Ord for ParameterObjectKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index
            .cmp(&other.index)
            .then_with(|| memory_space_order(self.space).cmp(&memory_space_order(other.space)))
    }
}

impl PartialOrd for ParameterObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalObjectKey {
    pub space: SpaceId,
    pub address: u64,
}

impl Ord for GlobalObjectKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        memory_space_order(self.space)
            .cmp(&memory_space_order(other.space))
            .then_with(|| self.address.cmp(&other.address))
    }
}

impl PartialOrd for GlobalObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectKind {
    StackSlot {
        space: SpaceId,
        base: StackAddressBase,
        offset: i64,
    },
    FrameObject {
        space: SpaceId,
        base: StackAddressBase,
        offset: i64,
    },
    Parameter {
        space: SpaceId,
        index: usize,
    },
    Global {
        space: SpaceId,
        address: u64,
    },
    HeapAlloc {
        space: SpaceId,
        call_site: CallSiteId,
    },
    EscapedUnknown {
        space: SpaceId,
    },
    /// The memory a pointer read from `base` at `offset` points to.
    ///
    /// `*(arg0 + 0x38)` is a pointer this function loaded; the object here is
    /// whatever it points at, and an access through it is at some offset
    /// inside this object. Before this kind existed every such access fell
    /// into `EscapedUnknown`, so a function that walked `strm->state->strm`
    /// had no name for either dereference. The base is itself an object --
    /// a parameter or another pointee -- so the identity is the whole access
    /// path from the parameter, and two different paths are two objects.
    Pointee {
        space: SpaceId,
        base: ObjectId,
        offset: i64,
        size: u32,
    },
}

impl ObjectKind {
    pub const fn space(&self) -> SpaceId {
        match self {
            Self::StackSlot { space, .. }
            | Self::FrameObject { space, .. }
            | Self::Parameter { space, .. }
            | Self::Global { space, .. }
            | Self::HeapAlloc { space, .. }
            | Self::EscapedUnknown { space }
            | Self::Pointee { space, .. } => *space,
        }
    }
}

/// The identity of a pointee object: the object the pointer was read from,
/// and where inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PointeeObjectKey {
    pub base: ObjectId,
    pub offset: i64,
    pub size: u32,
    pub space: ObjectSpaceId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFact {
    pub id: ObjectId,
    pub kind: ObjectKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectModel {
    pub objects: BTreeMap<ObjectId, ObjectFact>,
    pub value_objects: BTreeMap<MemoryObjectKey, ObjectId>,
    pub stack_objects: BTreeMap<StackObjectKey, ObjectId>,
    /// Machine-proven entry-SP coordinates for source-coordinate stack
    /// objects. Missing entries are intentionally treated as unknown.
    pub entry_stack_roots: BTreeMap<ObjectId, StackAddressRoot>,
    /// Exact modular address width for each source-owned memory space.
    /// Alias refinement is disabled when this source fact is unavailable.
    pub address_bits_by_space: BTreeMap<ObjectSpaceId, u32>,
    pub parameter_objects: BTreeMap<ParameterObjectKey, ObjectId>,
    pub pointee_objects: BTreeMap<PointeeObjectKey, ObjectId>,
    pub global_objects: BTreeMap<GlobalObjectKey, ObjectId>,
    pub escaped_unknown: BTreeMap<ObjectSpaceId, ObjectId>,
    /// Addresses that reach their object at an offset the machine computes.
    ///
    /// The object is exact -- `buf[i]` is inside `buf` -- and the offset within
    /// it is not known, which is the difference between an array element and a
    /// scalar slot. Every stage that would otherwise assume an access sits at
    /// its object's own offset has to ask this first.
    pub indexed_addresses: BTreeMap<ValueId, ValueId>,
    /// How far into its object an address sits, for a member of a declared
    /// aggregate or an address displaced from an object's base. Absent means
    /// the address is the object's own base.
    pub interior_offsets: BTreeMap<ValueId, i64>,
    /// Indexed addresses whose base is displaced from the object's base, so
    /// the index alone does not say where in the object the element is.
    pub displaced_indexed_addresses: BTreeSet<ValueId>,
    /// How far each of those starts from the object's base: `table[i].high`
    /// is the table's base plus four, indexed.
    pub indexed_displacements: BTreeMap<ValueId, i64>,
    /// How many bytes a callee is proven to write into each object from its base.
    pub callee_write_reach: BTreeMap<ObjectId, u32>,
    /// Stack objects whose address leaves this body as a value.
    pub escaping_addresses: BTreeSet<ObjectId>,
}

impl ObjectModel {
    /// Whether this indexed address starts from a displaced base.
    pub fn indexed_base_is_displaced(&self, value: ValueId) -> bool {
        self.displaced_indexed_addresses.contains(&value)
    }

    /// Whether this address reaches its object at a computed offset.
    pub fn address_is_indexed(&self, value: ValueId) -> bool {
        self.indexed_addresses.contains_key(&value)
    }

    /// How far into its object this address sits, for a declared aggregate's
    /// member. Absent means the address is the object's own base.
    pub fn interior_offset(&self, value: ValueId) -> Option<i64> {
        self.interior_offsets.get(&value).copied()
    }

    /// The value that supplies a computed offset into an object.
    pub fn index_for_address(&self, value: ValueId) -> Option<ValueId> {
        self.indexed_addresses.get(&value).copied()
    }

    /// How far an indexed address starts from its object's base.
    pub fn indexed_displacement(&self, value: ValueId) -> i64 {
        self.indexed_displacements.get(&value).copied().unwrap_or(0)
    }

    pub fn object_for_value(&self, value: ValueId, space: SpaceId) -> Option<ObjectId> {
        self.value_objects
            .get(&MemoryObjectKey { value, space })
            .copied()
    }

    pub fn object_for_var(
        &self,
        graph: &SsaGraph,
        value: &SSAVar,
        space: SpaceId,
    ) -> Option<ObjectId> {
        graph
            .value_id_for_var(value)
            .and_then(|value_id| self.object_for_value(value_id, space))
    }

    pub fn object(&self, id: ObjectId) -> Option<&ObjectFact> {
        self.objects.get(&id)
    }

    pub fn escaped_unknown_object(&self, space: SpaceId) -> Option<ObjectId> {
        self.escaped_unknown.get(&ObjectSpaceId(space)).copied()
    }

    /// Whether this object's address leaves the body as a value.
    pub fn address_escapes(&self, object: ObjectId) -> bool {
        self.escaping_addresses.contains(&object)
    }

    /// The parameter a chain of pointee objects starts from, if it starts
    /// from one.
    pub fn root_parameter(&self, id: ObjectId) -> Option<usize> {
        let mut current = id;
        // A chain is acyclic by construction and no longer than the object
        // table; the bound only guards against a corrupt model.
        for _ in 0..=self.objects.len() {
            match &self.object(current)?.kind {
                ObjectKind::Parameter { index, .. } => return Some(*index),
                ObjectKind::Pointee { base, .. } => current = *base,
                _ => return None,
            }
        }
        None
    }

    /// How an object reads as a C access path: `arg0`, `*(arg0 + 0x38)`,
    /// `*(*(arg0 + 0x38) + 0x0)`. Only parameters and pointees have one.
    pub fn access_path(&self, id: ObjectId) -> Option<String> {
        match &self.object(id)?.kind {
            ObjectKind::Parameter { index, .. } => Some(format!("arg{index}")),
            ObjectKind::Pointee { base, offset, .. } => {
                let base = self.access_path(*base)?;
                Some(if *offset == 0 {
                    format!("*{base}")
                } else if *offset > 0 {
                    format!("*({base} + 0x{offset:x})")
                } else {
                    format!("*({base} - 0x{:x})", offset.unsigned_abs())
                })
            }
            _ => None,
        }
    }

    pub fn memory_spaces(&self) -> impl Iterator<Item = SpaceId> + '_ {
        self.escaped_unknown.keys().map(|space| space.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryVersion {
    pub object: ObjectId,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelativeMemoryAddress {
    Exact(i64),
    Affine {
        terms: Vec<crate::AffineAddressTerm>,
        offset: i64,
    },
    Unknown,
}

impl RelativeMemoryAddress {
    pub fn exact_offset(&self) -> Option<i64> {
        match self {
            Self::Exact(offset) => Some(*offset),
            Self::Affine { .. } | Self::Unknown => None,
        }
    }

    pub fn constant_offset(&self) -> Option<i64> {
        match self {
            Self::Exact(offset) | Self::Affine { offset, .. } => Some(*offset),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryLocation {
    pub space: SpaceId,
    pub object: ObjectId,
    pub address: RelativeMemoryAddress,
    pub size: u32,
}

impl Ord for MemoryLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        memory_space_order(self.space)
            .cmp(&memory_space_order(other.space))
            .then_with(|| self.object.cmp(&other.object))
            .then_with(|| self.address.cmp(&other.address))
            .then_with(|| self.size.cmp(&other.size))
    }
}

impl PartialOrd for MemoryLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryUseFact {
    pub location: MemoryLocation,
    pub version: MemoryVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryDefFact {
    pub location: MemoryLocation,
    pub previous_version: MemoryVersion,
    pub next_version: MemoryVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPhiFact {
    pub object: ObjectId,
    pub location: MemoryLocation,
    pub output_version: MemoryVersion,
    pub inputs: Vec<(u64, MemoryVersion)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemorySSAFacts {
    pub uses_by_inst: BTreeMap<InstId, Vec<MemoryUseFact>>,
    pub defs_by_inst: BTreeMap<InstId, Vec<MemoryDefFact>>,
    pub phis_by_block: BTreeMap<u64, Vec<MemoryPhiFact>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareKind {
    Equal,
    NotEqual,
    Less,
    SignedLess,
    LessEqual,
    SignedLessEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareProvenance {
    pub kind: CompareKind,
    pub lhs: ValueId,
    pub rhs: ValueId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateFact {
    pub id: PredicateId,
    pub block_addr: u64,
    pub condition: ValueId,
    pub comparison: Option<CompareProvenance>,
    /// Comparison at the machine branch program point before algebraic
    /// normalization (for example, `sub_result != 0`).
    pub evaluated_comparison: Option<CompareProvenance>,
    pub true_target: u64,
    pub false_target: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAssumption {
    pub predecessor: u64,
    pub predicate: PredicateId,
    pub truth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPredicateFact {
    pub block_addr: u64,
    pub selector: Option<ValueId>,
    pub cases: Vec<(u64, u64)>,
    pub default: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredicateFacts {
    pub predicates: BTreeMap<PredicateId, PredicateFact>,
    pub block_assumptions: BTreeMap<u64, Vec<BlockAssumption>>,
    pub switches: BTreeMap<u64, SwitchPredicateFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMemoryEffect {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Alloc,
    Free,
    Unknown,
}

/// How control reaches and leaves one machine-proven call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSiteTransfer {
    /// An ordinary call returns to a block in this function.
    Call,
    /// A direct branch enters another function and that callee returns on this
    /// function's behalf.
    TailCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteFact {
    pub id: CallSiteId,
    pub at: InstId,
    /// Exact raw lifted identity when this fact belongs to an artifact-backed
    /// source machine context. Synthetic/context-free facts leave it absent.
    pub raw_identity: Option<SourceCallSiteIdentity>,
    pub target: ValueId,
    pub direct_target: Option<u64>,
    pub fallthrough: Option<u64>,
    pub transfer: CallSiteTransfer,
    pub memory_effect: CallMemoryEffect,
    /// Who the site calls, as the source's symbol or relocation said.
    pub callee_linkage: r2source::AdvisoryCalleeLinkage,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallSiteFacts {
    pub by_id: BTreeMap<CallSiteId, CallSiteFact>,
    pub by_inst: BTreeMap<InstId, CallSiteId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CallBoundarySlot {
    Register {
        index: u32,
        storage: crate::CanonicalStorageId,
    },
    Stack(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallBoundaryValueFact {
    pub slot: CallBoundarySlot,
    pub value: ValueId,
}

/// Where a call argument's value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCallArgumentValue {
    /// The function never defines this carrier before the call, so the value
    /// the callee receives is the one this function was entered with. No SSA
    /// value is named for it, because nothing in this function read it: a call
    /// takes its arguments implicitly.
    PreservedEntry,
    /// An exact value defined in this function reaches the call.
    Value(ValueId),
}

/// One argument carrier at a call boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCallArgumentFact {
    pub slot: CallBoundarySlot,
    pub value: SourceCallArgumentValue,
}

/// Per-callsite proof of a variadic argument count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariadicCallsiteArgumentCountEvidence {
    /// Which rule named the format parameter: radare2's recovered prototype,
    /// or the callee's own body. Orthogonal to `merged_literals`, which is
    /// about the literal rather than the parameter.
    pub parameter_rule: r2source::SourceFormatParameterRule,
    /// Whether several literals reach the format argument and agree on the
    /// count. A count is a property of the format, so formats that agree
    /// prove it the same way one does.
    pub merged_literals: bool,
    pub format_argument_index: usize,
    pub format_literal_address: u64,
    pub format_consumed_argument_count: usize,
    pub total_argument_count: usize,
}

/// Why a variadic callsite could not prove and project its own argument list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariadicCallsiteArgumentCountRefusal {
    MissingFormatParameter,
    FormatArgumentUnavailable,
    FormatArgumentNotLiteral,
    InvalidFormatString,
    ArgumentCountOverflow,
    CallingConventionMismatch,
    InsufficientRegisterArgumentCarriers,
    UnresolvedArgumentCarrier,
    /// The format consumes a floating operand, which the convention carries in
    /// its floating sequence rather than the integer one this recovery walks.
    FloatingVariadicArgument,
}

impl VariadicCallsiteArgumentCountRefusal {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::MissingFormatParameter => "missing_format_parameter",
            Self::FormatArgumentUnavailable => "format_argument_unavailable",
            Self::FormatArgumentNotLiteral => "format_argument_not_literal",
            Self::InvalidFormatString => "invalid_format_string",
            Self::ArgumentCountOverflow => "argument_count_overflow",
            Self::CallingConventionMismatch => "calling_convention_mismatch",
            Self::InsufficientRegisterArgumentCarriers => "insufficient_register_argument_carriers",
            Self::UnresolvedArgumentCarrier => "unresolved_argument_carrier",
            Self::FloatingVariadicArgument => "floating_variadic_argument",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCallBoundaryFact {
    pub call_site: CallSiteId,
    pub at: InstId,
    pub calling_convention: Option<String>,
    pub variadic: Option<bool>,
    pub noreturn: Option<bool>,
    pub result_kind: Option<SourceCallResult>,
    pub arguments: Vec<SourceCallArgumentFact>,
    /// How many leading entries of `arguments` the callee's prototype names.
    ///
    /// The rest are the tail a variadic call passes and no prototype can
    /// describe, so they are what makes two call sites of one callee differ.
    /// The split has to travel, because the declaration a rendering owes the
    /// callee can only spell the named ones.
    pub fixed_argument_count: Option<usize>,
    pub variadic_argument_count_evidence: Option<VariadicCallsiteArgumentCountEvidence>,
    pub variadic_argument_count_refusal: Option<VariadicCallsiteArgumentCountRefusal>,
    /// Result values this function actually observes.
    ///
    /// A complete non-void boundary may carry no entries here when the caller
    /// discards the result. `result_kind` still records the callee's exact
    /// result carrier; only a reaching SSA value is absent.
    pub results: Vec<CallBoundaryValueFact>,
    /// False until an ABI-aware boundary pass proves every argument and every
    /// result value the caller observes. An exact discarded result is complete
    /// because there is no caller-side value to identify.
    pub complete: bool,
    /// The same, per coordinate. A caller may resolve what a callee returns
    /// without resolving what it was passed, and the conjunction above threw
    /// away a proven result because an argument beside it was unproven.
    pub arguments_complete: bool,
    pub results_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReturnBoundaryFact {
    pub at: InstId,
    pub values: Vec<CallBoundaryValueFact>,
    /// Exact source-declared return-address carrier consumed by this return.
    pub return_address: Option<SourceReturnAddressFact>,
    /// Exact full-width stack-pointer value reaching this return when the
    /// source interface declares the typed stack-pointer carrier.
    pub exit_stack_pointer: Option<SourceReturnStackPointerFact>,
    /// False when the current source facts cannot distinguish void from an
    /// unresolved return carrier or cannot recover declared exit machine state.
    pub complete: bool,
    /// True when the exit machine state alone is fully recovered: the return
    /// address carrier and the exit stack pointer are both known. This is
    /// independent of whether any ABI described the values the return carries,
    /// so it holds for functions with no recovered ABI at all.
    pub machine_state_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceReturnAddressFact {
    /// Exact source-declared return-address carrier transported to the return.
    pub storage: CanonicalStorageId,
    /// Exact control-target value consumed by the return. This may either be
    /// the carrier itself or the result of one immediately preceding,
    /// full-width `Copy` from that carrier.
    pub value: ValueId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceReturnStackPointerFact {
    /// The lifted function never defines or consumes this carrier, and every
    /// predecessor path reaches the return without a call or overlapping
    /// partial/full-width write. The architectural entry value is therefore
    /// preserved without inventing an SSA value that does not exist.
    PreservedEntry { storage: CanonicalStorageId },
    /// A concrete graph value reaches the return. Its producer, when any, is
    /// rooted by the semantic-obligation inventory.
    ReachingValue {
        storage: CanonicalStorageId,
        value: ValueId,
    },
}

impl SourceReturnStackPointerFact {
    pub const fn storage(self) -> CanonicalStorageId {
        match self {
            Self::PreservedEntry { storage } | Self::ReachingValue { storage, .. } => storage,
        }
    }

    pub const fn value(self) -> Option<ValueId> {
        match self {
            Self::PreservedEntry { .. } => None,
            Self::ReachingValue { value, .. } => Some(value),
        }
    }
}

/// One exact source-declared ABI parameter and its canonical graph carrier.
///
/// `abi_storage` is the source calling-convention carrier. `graph_storage`
/// is the exact, source-declared logical projection used by SSA; it is never
/// inferred from a register name or an overlapping storage range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceFormalParameterFact {
    pub index: u32,
    pub abi_storage: CanonicalStorageId,
    pub graph_storage: CanonicalStorageId,
    /// Exact logical projection when the source supplied one. A full-width
    /// physical ABI parameter remains authoritative without a type graph; in
    /// that case `graph_storage == abi_storage` and this field is absent.
    pub logical_value: Option<SourceLogicalValue>,
    pub value: ValueId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceBoundaryFacts {
    pub parameters: BTreeMap<u32, SourceFormalParameterFact>,
    pub calls: BTreeMap<CallSiteId, SourceCallBoundaryFact>,
    pub returns: BTreeMap<InstId, SourceReturnBoundaryFact>,
    /// Convention-clobbered registers this body leaves exactly as it found
    /// them at every exit. A caller that reads one of these after calling
    /// here is reading its own value, not a clobber; see
    /// [`preserved_call_carriers`].
    pub preserved_call_carriers: BTreeSet<CanonicalStorageId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LoopId(pub u32);

/// A control-flow fact that must hold whenever a block executes.
///
/// Switch arms retain all values targeting one edge because a multi-label arm
/// is a disjunction, not several independent guards.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControlGuard {
    Branch {
        predicate: PredicateId,
        truth: bool,
    },
    SwitchArm {
        block_addr: u64,
        case_values: Vec<u64>,
        includes_default: bool,
    },
}

/// Canonical control context shared by every path reaching a block.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControlDomain {
    pub id: ControlDomainId,
    pub guards: Vec<ControlGuard>,
    pub loops: Vec<LoopId>,
    /// False means the CFG had no fully representable path proof for this block.
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredLoopKind {
    Natural,
    SelfLoop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoopCarrierEdgeValue {
    pub predecessor: u64,
    pub value: ValueId,
    /// Exact phi input consuming `value` on `predecessor`'s edge.
    ///
    /// Loop-carrier facts are an in-memory prepared-fact contract and are not
    /// part of r2ssa's serde schema, so this field does not change persisted
    /// artifact compatibility.
    pub site: UseSite,
}

impl LoopCarrierEdgeValue {
    /// Prove that this edge names the exact indexed input and predecessor of a
    /// canonical graph phi. This is O(1) in the size of the graph.
    pub fn validate(&self, graph: &SsaGraph) -> bool {
        loop_carrier_phi_input_matches(graph, self.predecessor, self.value, self.site)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LoopCarrierUpdateFact {
    pub predecessor: u64,
    pub value: ValueId,
    /// Exact header-phi input consuming `value` on `predecessor`'s edge.
    pub site: UseSite,
    /// Values bit-identical to `value` through same-width copy chains.
    pub identity_values: BTreeSet<ValueId>,
}

/// Exact program-point role one SSA value has in a certified loop carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoopCarrierMemberRole {
    HeaderPhi,
    Entry,
    LatchUpdate,
    UpdateIdentity,
    DominatingInitializer,
    StorageContinuation,
    PostLoopMerge,
    ProjectedPeer,
}

/// One sorted, source-owned member row for a loop carrier.
///
/// A value may have more than one role: for example, an update value is also
/// one of its exact copy-chain identities. The dense graph remains the owner of
/// definitions and uses; this row only seals the coalescing relation already
/// proven by those facts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LoopCarrierMemberFact {
    pub value: ValueId,
    pub roles: BTreeSet<LoopCarrierMemberRole>,
}

impl LoopCarrierUpdateFact {
    /// Prove that this update names the exact indexed input and predecessor of
    /// a canonical graph phi. This is O(1) in the size of the graph.
    pub fn validate(&self, graph: &SsaGraph) -> bool {
        loop_carrier_phi_input_matches(graph, self.predecessor, self.value, self.site)
    }
}

/// How one loop-carried value changes on a single trip round the latch.
///
/// Only shapes that can be stated exactly appear here. A recurrence whose step
/// this cannot name is absent rather than approximated: a consumer reading a
/// step is entitled to assume it is the whole truth about the value's motion,
/// and an approximate step would let a renderer spell `a[i]` for a pointer
/// that does not advance the way the spelling claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InductionStep {
    /// `x = x + value`, wrapping at the value's width.
    AddConst(u64),
    /// `x = x - value`, wrapping at the value's width.
    SubConst(u64),
    /// `x = x * multiplier + addend`, wrapping at the value's width, with a
    /// multiplier that is not one -- a unit multiplier is an add or a subtract
    /// and is spelled as one.
    Affine { multiplier: u64, addend: u64 },
}

impl InductionStep {
    /// The value after one trip, given the value before it.
    ///
    /// Wrapping, because the machine wraps: a step that disagreed with the
    /// program at its width would be worse than no step at all.
    pub const fn apply(self, value: u64, width_bits: u32) -> u64 {
        let mask = if width_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << width_bits) - 1
        };
        let stepped = match self {
            Self::AddConst(addend) => value.wrapping_add(addend),
            Self::SubConst(subtrahend) => value.wrapping_sub(subtrahend),
            Self::Affine { multiplier, addend } => {
                value.wrapping_mul(multiplier).wrapping_add(addend)
            }
        };
        stepped & mask
    }
}

/// One loop-carried value whose motion round the latch is known exactly.
///
/// This is induction-variable recovery stated as a fact rather than as a
/// transformation: the merge that carries the value, the value it holds on
/// entry, the value the latch writes back, and the step between them. It is
/// keyed by `ValueId` throughout, because a recurrence recognised by SSA
/// variable spelling is a recurrence that stops being recognised the moment a
/// name changes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InductionFact {
    pub loop_id: LoopId,
    pub header: u64,
    /// The header merge carrying the value.
    pub phi: ValueId,
    /// What the merge holds on the edge into the loop.
    pub init: ValueId,
    /// What the latch writes back.
    pub update: ValueId,
    /// The latch block whose edge carries `update`.
    pub latch: u64,
    pub width_bits: u32,
    pub step: InductionStep,
}

impl InductionFact {
    /// Prove this fact against the graph that owns it.
    ///
    /// The merge must be a phi, `init` and `update` must both be inputs of it,
    /// and re-deriving the step from `update`'s own definition must produce
    /// the step recorded here. The last check is the one that matters: it
    /// makes a stored step that no longer follows from the graph a validation
    /// failure rather than a fact a consumer would trust.
    pub fn validate(&self, graph: &SsaGraph) -> bool {
        let Some(phi_inst) = graph.def_inst(self.phi) else {
            return false;
        };
        let Some(inst) = graph.inst(phi_inst) else {
            return false;
        };
        if !matches!(inst.payload, InstPayload::Phi { .. }) {
            return false;
        }
        if !inst.inputs.contains(&self.init) || !inst.inputs.contains(&self.update) {
            return false;
        }
        induction_step_for_update(graph, self.phi, self.update, self.width_bits) == Some(self.step)
    }
}

/// A loop-carried mutable value proven directly from header phi edges.
///
/// `identity_values` contains phi outputs that denote the carrier state after
/// structured control flow chooses an incoming edge. Entry and update values
/// remain expressions; consumers must not globally replace them with the
/// carrier because their meaning depends on the edge program point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopCarrierFact {
    pub id: SemanticId,
    pub loop_id: LoopId,
    pub header: u64,
    pub phi: ValueId,
    pub width: u32,
    pub identity_values: BTreeSet<ValueId>,
    pub entries: Vec<LoopCarrierEdgeValue>,
    pub updates: Vec<LoopCarrierUpdateFact>,
    /// Entry-valued predecessor edges that dominate the loop header and can
    /// initialize the coalesced carrier before zero-iteration exits.
    pub dominating_initializers: Vec<LoopCarrierEdgeValue>,
    /// Complete exact members, sorted by `ValueId` and sealed from the role
    /// facts above plus post-loop and projected-peer certificates.
    pub members: Vec<LoopCarrierMemberFact>,
}

impl LoopCarrierFact {
    /// Exact source-owned coalescing membership for this carrier.
    ///
    /// The rows are sealed in [`StructuredLoopFact::validate_carrier_members`];
    /// this projection deliberately contains no second membership algorithm.
    pub fn coalescing_values(&self) -> BTreeSet<ValueId> {
        // A member whose only role is sharing a run with a real member is not
        // the carrier's claim: the run is the span's, and the span offers it to
        // the object under the liveness rule. Claiming it here put the folded
        // intermediates of an update -- `zext(byte)`, the xor -- in the
        // carrier's proposed set, and the carrier is still live where they
        // are written, so the whole union was declined for values that render
        // nothing.
        self.members
            .iter()
            .filter(|member| {
                member
                    .roles
                    .iter()
                    .any(|role| *role != LoopCarrierMemberRole::StorageContinuation)
            })
            .map(|member| member.value)
            .collect()
    }

    /// Validate every retained edge against the graph that owns this fact.
    ///
    /// Entry and update sites must be inputs of this carrier's header phi.
    /// Dominating initializer sites must be inputs of a phi whose output is
    /// one of this carrier's certified identity values.
    pub fn validate(&self, graph: &SsaGraph) -> bool {
        let Some(phi_inst) = graph.def_inst(self.phi) else {
            return false;
        };
        let Some(inst) = graph.inst(phi_inst) else {
            return false;
        };
        if !matches!(inst.payload, InstPayload::Phi { .. })
            || inst.output != Some(self.phi)
            || graph.block(inst.block).map(|block| block.addr) != Some(self.header)
            || self.id != SemanticId::loop_carrier(self.phi)
        {
            return false;
        }

        let entry_values = self
            .entries
            .iter()
            .map(|entry| entry.value)
            .collect::<BTreeSet<_>>();

        self.entries
            .iter()
            .all(|edge| edge.site.inst == phi_inst && edge.validate(graph))
            && self
                .updates
                .iter()
                .all(|update| update.site.inst == phi_inst && update.validate(graph))
            && self.dominating_initializers.iter().all(|edge| {
                edge.site.inst != phi_inst
                    && edge.validate(graph)
                    && entry_values.contains(&edge.value)
                    && graph
                        .inst(edge.site.inst)
                        .and_then(|inst| inst.output)
                        .is_some_and(|output| self.identity_values.contains(&output))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLoopFact {
    pub id: LoopId,
    pub kind: StructuredLoopKind,
    pub header: u64,
    pub latches: Vec<u64>,
    pub body: Vec<u64>,
    pub exits: Vec<u64>,
    pub condition: Option<PredicateId>,
    pub carriers: Vec<LoopCarrierFact>,
    pub induction_phi: Option<ValueId>,
    pub induction_init: Option<ValueId>,
    pub induction_update: Option<ValueId>,
    pub bound: Option<ValueId>,
}

impl StructuredLoopFact {
    /// Recompute and validate the sorted carrier-member rows against their
    /// exact graph, storage-run, and source machine contracts.
    ///
    /// A single [`LoopCarrierFact`] cannot validate projected peers because
    /// peerhood is a relation among the carriers in one loop. Keeping this
    /// check on the loop fact prevents a stored peer row and its owning loop
    /// from becoming two independently mutable answers.
    pub fn validate_carrier_members(
        &self,
        graph: &SsaGraph,
        storage_spans: &StorageSpans,
        machine_context: Option<&SourceMachineContext>,
    ) -> bool {
        if self.carriers.iter().any(|carrier| {
            carrier.loop_id != self.id || carrier.header != self.header || !carrier.validate(graph)
        }) {
            return false;
        }
        let body = self.body.iter().copied().collect::<BTreeSet<_>>();
        let latches = self.latches.iter().copied().collect::<BTreeSet<_>>();
        loop_carrier_member_rows(
            graph,
            self.header,
            &latches,
            &body,
            storage_spans,
            machine_context,
            &self.carriers,
        )
        .is_some_and(|expected| {
            expected.len() == self.carriers.len()
                && self
                    .carriers
                    .iter()
                    .zip(expected)
                    .all(|(carrier, expected)| carrier.members == expected)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StructuredAccessId {
    pub inst: InstId,
    pub ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredMemoryAccessFact {
    pub id: StructuredAccessId,
    pub block_addr: u64,
    pub op_index: usize,
    pub space: SpaceId,
    pub object: ObjectId,
    pub address: ValueId,
    pub value: Option<ValueId>,
    pub is_write: bool,
    pub width: u32,
    /// True only when exactly one memory-SSA fact annotates this raw subeffect.
    pub provenance_complete: bool,
    /// Where in the object this access lands, when the memory fact states it
    /// exactly. A member of a declared aggregate is the aggregate at an
    /// offset, and this is that offset.
    pub object_offset: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredRecursiveCallFact {
    pub call_site: CallSiteId,
    pub block_addr: u64,
    pub op_index: usize,
    pub target: u64,
}

/// A store that puts back into its object exactly what the object held.
///
/// A stack probe is the case. `or qword [rsp], 0` lifts to a load of the slot,
/// a copy of the loaded value, and a store of that copy back to the same
/// address: the page is touched, which is the instruction's whole purpose, and
/// memory ends as it began. So the store is not an assignment -- rendering it
/// would spell `x = x` for an object nothing ever assigned, which reads an
/// uninitialised variable -- and the load it puts back is not a program read.
///
/// The proof is local and exact: the stored value resolves through copies to a
/// load of the same object at the same offset and width, earlier in the same
/// block, with no other write to that object between the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRoundTripCertificate {
    pub write: StructuredAccessId,
    pub read: StructuredAccessId,
    pub object: ObjectId,
    pub block_addr: u64,
    pub write_op_index: usize,
    pub read_op_index: usize,
    /// Later loads of the same location, in the same block, with no write to
    /// the object between the certified read and them beyond the round trip's
    /// own. The location holds what it held, so each of these reads the value
    /// the certified read already produced and is the same read said again.
    /// The machine spells the flags of a read-modify-write this way: Sleigh
    /// re-loads the address once per flag it sets.
    pub redundant_reads: Vec<StructuredAccessId>,
    /// The op indexes of those reads, for the ledgers that ask per site.
    pub redundant_read_op_indexes: Vec<usize>,
}

/// One store of a proven constant whose bytes tile a run of declared members.
///
/// C has no spelling for a value wider than its widest scalar, so the store is
/// written as one assignment per member, each taking its slice of the constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRunStoreCertificate {
    pub inst: InstId,
    pub block_addr: u64,
    pub op_index: usize,
    pub object: ObjectId,
    pub address: ValueId,
    pub value: ValueId,
    /// Where the stored value is read, so the ledger can say it is not rendered.
    pub value_use: UseSite,
    pub members: Vec<MemberRunStoreMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRunStoreMember {
    /// The structured access this member's own assignment is, and is observed at.
    pub access: StructuredAccessId,
    /// How the rendering addresses this part of the object.
    pub place: MemberRunPlace,
    /// Byte offset in the object, which is where the member's name resolves.
    pub offset: u64,
    pub width: u32,
    pub source: MemberRunSource,
}

/// How a decomposed wide store's part is addressed in its object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRunPlace {
    /// A named member of a struct or union.
    Field(String),
    /// An element of an array, by index. The declaration gives the width.
    Element(u64),
    /// One unit of an object that declares no parts. The width is the
    /// store's own, so the rendering has to spell it.
    Unit { index: u64, bits: u64 },
}

/// What one member of a decomposed wide store receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRunSource {
    /// The member's slice of a proven constant.
    Constant(u64),
    /// A value exactly as wide as the member, composed into the stored value
    /// at the member's bytes.
    Lane(ValueId),
}

/// Where one byte of a value comes from, through the operations that only
/// move bytes: copies, zero extension, lane insertion and concatenation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteSource {
    Constant(u8),
    Lane { value: ValueId, byte: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredDataflowFacts {
    pub loops: BTreeMap<LoopId, StructuredLoopFact>,
    /// Loop-carried values whose motion round the latch is known exactly,
    /// keyed by the header merge that carries them.
    pub inductions: BTreeMap<ValueId, InductionFact>,
    /// Cyclic CFG blocks not represented by a structured loop fact.
    pub unstructured_cycle_blocks: BTreeSet<u64>,
    pub memory_accesses: BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    /// Wide constant stores written out one declared member at a time.
    pub member_run_stores: BTreeMap<InstId, MemberRunStoreCertificate>,
    pub recursive_calls: BTreeMap<CallSiteId, StructuredRecursiveCallFact>,
}

/// Exact, prepared interpretation of an external assumption subject.
///
/// `AnalysisAssumption` keeps the user's source spelling for diagnostics. This
/// certificate is the semantic authority: register subjects retain canonical
/// storage and SSA value identity, and stack subjects retain a typed base and
/// object. Consumers must not re-resolve the source spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedAssumptionBindingKind {
    Predicate {
        predicate: PredicateId,
        block_addr: u64,
        predecessor: Option<u64>,
        truth: bool,
    },
    Register {
        storage: CanonicalStorageId,
        value: ValueId,
        state_name: String,
        bits: u32,
    },
    StackSlot {
        base: StackAddressBase,
        offset: i64,
        object: ObjectId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAssumptionBinding {
    pub assumption: crate::AnalysisAssumption,
    pub binding: PreparedAssumptionBindingKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ObjectModelBuilder<'a> {
    pub(crate) facts: Option<&'a DecompilePrepFacts>,
    pub(crate) addresses: &'a AddressProvenanceFacts,
    pub(crate) declared_slots: &'a DeclaredStackSlots,
    pub(crate) objects: BTreeMap<ObjectId, ObjectFact>,
    pub(crate) value_objects: BTreeMap<MemoryObjectKey, ObjectId>,
    pub(crate) indexed_addresses: BTreeMap<ValueId, ValueId>,
    /// How far into its object an address sits, for a member of a declared
    /// aggregate or an address displaced from an object's base.
    pub(crate) interior_offsets: BTreeMap<ValueId, i64>,
    pub(crate) displaced_indexed_addresses: BTreeSet<ValueId>,
    pub(crate) indexed_displacements: BTreeMap<ValueId, i64>,
    /// Frame positions something proves an object starts at: a declared slot,
    /// a direct access, or an address that leaves as a value.
    pub(crate) evidenced_roots: BTreeSet<StackAddressRoot>,
    /// How far each evidenced root's indexed accesses reach.
    pub(crate) evidenced_spans: BTreeMap<StackAddressRoot, i64>,
    /// Roots whose address leaves the body as a value.
    pub(crate) escaping_roots: BTreeSet<StackAddressRoot>,
    /// How far a callee writes from each root it is handed.
    pub(crate) callee_write_spans: BTreeMap<StackAddressRoot, i64>,
    /// What every value can be, for an index's lower bound.
    pub(crate) values: &'a crate::values::ValueRanges,
    /// Addresses whose displaced parent is being resolved, against a cycle.
    pub(crate) resolving: BTreeSet<ValueId>,
    pub(crate) stack_pointer_carrier: Option<CanonicalStorageId>,
    pub(crate) machine_context: Option<&'a SourceMachineContext>,
    pub(crate) stack_objects: BTreeMap<StackObjectKey, ObjectId>,
    pub(crate) entry_stack_roots: BTreeMap<ObjectId, StackAddressRoot>,
    pub(crate) ambiguous_entry_stack_objects: BTreeSet<ObjectId>,
    pub(crate) address_bits_by_space: BTreeMap<ObjectSpaceId, u32>,
    pub(crate) parameter_objects: BTreeMap<ParameterObjectKey, ObjectId>,
    pub(crate) pointee_objects: BTreeMap<PointeeObjectKey, ObjectId>,
    pub(crate) global_objects: BTreeMap<GlobalObjectKey, ObjectId>,
    pub(crate) escaped_unknown: BTreeMap<ObjectSpaceId, ObjectId>,
    pub(crate) next_object_id: u32,
}

impl<'a> ObjectModelBuilder<'a> {
    pub(crate) fn new(
        facts: Option<&'a DecompilePrepFacts>,
        addresses: &'a AddressProvenanceFacts,
        declared_slots: &'a DeclaredStackSlots,
        machine_context: Option<&'a SourceMachineContext>,
    ) -> Self {
        let escaped_unknown_id = ObjectId(0);
        let mut objects = BTreeMap::new();
        objects.insert(
            escaped_unknown_id,
            ObjectFact {
                id: escaped_unknown_id,
                kind: ObjectKind::EscapedUnknown {
                    space: SpaceId::Ram,
                },
            },
        );
        let mut escaped_unknown = BTreeMap::new();
        escaped_unknown.insert(ObjectSpaceId(SpaceId::Ram), escaped_unknown_id);
        let address_bits_by_space = machine_context
            .filter(|context| context.memory_model().is_coherent())
            .map(|context| {
                context
                    .memory_model()
                    .spaces()
                    .iter()
                    .filter(|space| space.address_bits() > 0 && space.address_bits() <= 64)
                    .map(|space| (ObjectSpaceId(space.space()), space.address_bits()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            facts,
            addresses,
            declared_slots,
            objects,
            value_objects: BTreeMap::new(),
            indexed_addresses: BTreeMap::new(),
            interior_offsets: BTreeMap::new(),
            displaced_indexed_addresses: BTreeSet::new(),
            indexed_displacements: BTreeMap::new(),
            evidenced_roots: BTreeSet::new(),
            evidenced_spans: BTreeMap::new(),
            escaping_roots: BTreeSet::new(),
            callee_write_spans: BTreeMap::new(),
            values: empty_value_ranges(),
            resolving: BTreeSet::new(),
            stack_pointer_carrier: machine_context
                .and_then(SourceMachineContext::stack_pointer_carrier),
            machine_context,
            stack_objects: BTreeMap::new(),
            entry_stack_roots: BTreeMap::new(),
            ambiguous_entry_stack_objects: BTreeSet::new(),
            address_bits_by_space,
            parameter_objects: BTreeMap::new(),
            pointee_objects: BTreeMap::new(),
            global_objects: BTreeMap::new(),
            escaped_unknown,
            next_object_id: 1,
        }
    }

    /// The displacement already recorded for an indexed address.
    fn indexed_displacement_of(&self, value: ValueId) -> i64 {
        self.indexed_displacements.get(&value).copied().unwrap_or(0)
    }

    pub(crate) fn build(
        mut self,
        function: &SSAFunction,
        graph: &SsaGraph,
        values: &'a crate::values::ValueRanges,
    ) -> ObjectModel {
        self.values = values;
        if let Some(facts) = self.facts {
            for (start, end) in
                callee_write_spans(facts, function, graph, self.machine_context, values)
            {
                self.callee_write_spans
                    .entry(start)
                    .and_modify(|known| *known = (*known).max(end))
                    .or_insert(end);
            }
            let evidenced = evidenced_stack_roots(
                facts,
                self.declared_slots,
                function,
                graph,
                self.stack_pointer_carrier,
                values,
                &self.callee_write_spans,
            );
            self.evidenced_roots = evidenced.roots;
            self.evidenced_spans = evidenced.spans;
            self.escaping_roots = evidenced.escaping;
            let mut stack_roots: Vec<StackAddressRoot> =
                facts.stack_address_roots.values().copied().collect();
            stack_roots.sort_unstable();
            stack_roots.dedup();
            for root in stack_roots {
                if self.evidenced_roots.contains(&root) {
                    self.ensure_stack_object(root);
                }
            }
            for var in facts.stack_address_roots.keys() {
                let _ = self.object_for_address_value(graph, var, SpaceId::Ram);
            }
        }
        let parameter_indices = self
            .addresses
            .parameter_expressions
            .values()
            .map(|expression| expression.parameter)
            .chain(
                self.addresses
                    .pointee_expressions
                    .values()
                    .map(|expression| expression.root),
            )
            .collect::<BTreeSet<_>>();
        for parameter in parameter_indices {
            self.ensure_parameter_object(parameter);
        }
        // Seeded in path order so an object's id does not depend on which
        // access happened to be classified first.
        let pointee_chains = self
            .addresses
            .pointee_expressions
            .values()
            .map(|expression| (expression.root, expression.path.clone()))
            .collect::<BTreeSet<_>>();
        for (root, path) in pointee_chains {
            self.ensure_pointee_chain(root, &path);
        }

        for block in function.blocks() {
            for op in &block.ops {
                match op {
                    SSAOp::Load { addr, space, .. }
                    | SSAOp::Store { addr, space, .. }
                    | SSAOp::LoadLinked { addr, space, .. }
                    | SSAOp::StoreConditional { addr, space, .. }
                    | SSAOp::LoadGuarded { addr, space, .. }
                    | SSAOp::StoreGuarded { addr, space, .. } => {
                        let _ = self.object_for_address_value(graph, addr, *space);
                    }
                    SSAOp::AtomicCAS(swap) => {
                        let _ = self.object_for_address_value(graph, &swap.addr, swap.space);
                    }
                    _ => {}
                }
            }
        }

        let callee_write_reach = self
            .stack_objects
            .iter()
            .filter_map(|(key, object)| {
                let end = self.callee_write_spans.get(&key.root)?;
                let reach = u32::try_from(end.checked_sub(key.root.offset)?).ok()?;
                Some((*object, reach))
            })
            .collect();
        let escaping_addresses = self
            .stack_objects
            .iter()
            .filter(|(key, _)| self.escaping_roots.contains(&key.root))
            .map(|(_, object)| *object)
            .collect();
        ObjectModel {
            callee_write_reach,
            escaping_addresses,
            objects: self.objects,
            value_objects: self.value_objects,
            indexed_addresses: self.indexed_addresses,
            interior_offsets: self.interior_offsets,
            displaced_indexed_addresses: self.displaced_indexed_addresses,
            indexed_displacements: self.indexed_displacements,
            stack_objects: self.stack_objects,
            entry_stack_roots: self.entry_stack_roots,
            address_bits_by_space: self.address_bits_by_space,
            parameter_objects: self.parameter_objects,
            pointee_objects: self.pointee_objects,
            global_objects: self.global_objects,
            escaped_unknown: self.escaped_unknown,
        }
    }

    fn object_for_address_value(
        &mut self,
        graph: &SsaGraph,
        value: &SSAVar,
        space: SpaceId,
    ) -> ObjectId {
        let Some(value_id) = graph.value_id_for_var(value) else {
            return self.ensure_escaped_unknown(space);
        };
        let key = MemoryObjectKey {
            value: value_id,
            space,
        };
        if let Some(object) = self.value_objects.get(&key).copied() {
            return object;
        }

        let _ = self.ensure_escaped_unknown(space);
        let object = if space == SpaceId::Ram {
            if let Some(root) = resolve_stack_root(self.facts, value) {
                // A member of a declared aggregate is that aggregate at an
                // offset, so the address resolves to the slot that contains it.
                let (root, interior) = match self.declared_slots.containing(root) {
                    Some((container, displacement)) => (container, Some(displacement)),
                    None => (root, None),
                };
                // A position nothing proves an object starts at is not one.
                // Inside the span an evidenced root's index reaches it is a
                // place in that buffer, whichever register it was measured
                // from; otherwise the address is its operand's object,
                // displaced.
                if interior.is_none() && !self.evidenced_roots.contains(&root) {
                    let containing = self
                        .evidenced_spans
                        .iter()
                        .filter(|(base, end)| {
                            base.base == root.base
                                && base.offset < root.offset
                                && root.offset < **end
                                && self.evidenced_roots.contains(base)
                        })
                        .map(|(base, _)| *base)
                        .max_by_key(|base| base.offset);
                    if let Some(container) = containing {
                        let object = self.ensure_stack_object(container);
                        self.interior_offsets
                            .insert(value_id, root.offset - container.offset);
                        self.value_objects.insert(key, object);
                        return object;
                    }
                    if let Some(object) = self.displaced_object(graph, value_id) {
                        self.value_objects.insert(key, object);
                        return object;
                    }
                }
                let object = self.ensure_stack_object(root);
                if let Some(displacement) = interior {
                    self.interior_offsets.insert(value_id, displacement);
                } else if let Some(entry_root) = resolve_entry_stack_root(self.facts, value) {
                    self.record_entry_stack_root(object, entry_root);
                }
                object
            } else if let Some(root) = resolve_indexed_stack_root(self.facts, value) {
                // An address inside a stack object at an offset the machine
                // computes. It is the same object a constant offset from that
                // base would reach -- `buf[i]` and `buf[0]` are one buffer --
                // so it resolves to that object rather than escaping, which is
                // what left an indexed local with no identity at all.
                match self.indexed_object(graph, value_id) {
                    Some(object) => object,
                    None => {
                        if let Some(index) = self.index_operand_for_indexed_address(graph, value_id)
                        {
                            self.indexed_addresses.insert(value_id, index);
                        }
                        self.ensure_stack_object(root)
                    }
                }
            } else if let Some(expression) = self.addresses.parameter_expression(value_id) {
                self.ensure_parameter_object(expression.parameter)
            } else if let Some(expression) = self.addresses.pointee_expression(value_id) {
                self.ensure_pointee_chain(expression.root, &expression.path)
            } else if let Some(address) = resolve_const_value(self.facts, value) {
                self.ensure_global_object(GlobalObjectKey { space, address })
            } else {
                self.ensure_escaped_unknown(space)
            }
        } else if let Some(address) = resolve_const_value(self.facts, value) {
            self.ensure_global_object(GlobalObjectKey { space, address })
        } else {
            self.ensure_escaped_unknown(space)
        };
        self.value_objects.insert(key, object);
        object
    }

    /// The object an address displaced from another stack address names:
    /// that address's object, with the displacement carried as the offset
    /// inside it. `None` when the address is not a displacement of one.
    fn displaced_object(&mut self, graph: &SsaGraph, value_id: ValueId) -> Option<ObjectId> {
        if !self.resolving.insert(value_id) {
            return None;
        }
        let result = self
            .displaced_parent(graph, value_id)
            .and_then(|(parent, delta)| {
                let parent_var = graph.value(parent)?.var.clone();
                let object = self.object_for_address_value(graph, &parent_var, SpaceId::Ram);
                if !matches!(
                    self.objects.get(&object).map(|fact| &fact.kind),
                    Some(ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. })
                ) {
                    return None;
                }
                let offset = self.interior_offsets.get(&parent).copied().unwrap_or(0) + delta;
                if offset != 0 {
                    self.interior_offsets.insert(value_id, offset);
                }
                Some(object)
            });
        self.resolving.remove(&value_id);
        result
    }

    /// The stack address this one is computed from, and by how much.
    fn displaced_parent(&self, graph: &SsaGraph, value_id: ValueId) -> Option<(ValueId, i64)> {
        let inst = graph.inst(graph.def_inst(value_id)?)?;
        let rooted = |var: &SSAVar| resolve_stack_root(self.facts, var).is_some();
        let id = |var: &SSAVar| graph.value_id_for_var(var);
        match &inst.payload {
            crate::InstPayload::Op(crate::SSAOp::IntAdd { a, b, .. }) => {
                match (rooted(a), b.constant_bits(), rooted(b), a.constant_bits()) {
                    (true, Some(delta), _, _) => Some((id(a)?, delta as i64)),
                    (_, _, true, Some(delta)) => Some((id(b)?, delta as i64)),
                    _ => None,
                }
            }
            crate::InstPayload::Op(crate::SSAOp::IntSub { a, b, .. }) => {
                let delta = b.constant_bits()?;
                rooted(a).then(|| id(a).map(|a| (a, (delta as i64).wrapping_neg())))?
            }
            crate::InstPayload::Op(
                crate::SSAOp::Copy { src, .. }
                | crate::SSAOp::Cast { src, .. }
                | crate::SSAOp::CallRestore { src, .. },
            ) => rooted(src).then(|| id(src).map(|src| (src, 0)))?,
            crate::InstPayload::Phi { .. } => inst
                .inputs
                .iter()
                .copied()
                .find(|input| graph.value(*input).is_some_and(|value| rooted(&value.var)))
                .map(|input| (input, 0)),
            _ => None,
        }
    }

    /// The object an indexed address reaches: its base operand's, with the
    /// index recorded, and marked displaced when the base is not that object's
    /// own address.
    fn indexed_object(&mut self, graph: &SsaGraph, value_id: ValueId) -> Option<ObjectId> {
        if !self.resolving.insert(value_id) {
            return None;
        }
        let result = (|| {
            let inst = graph.inst(graph.def_inst(value_id)?)?;
            let (base, index) = match &inst.payload {
                crate::InstPayload::Op(crate::SSAOp::IntAdd { a, b, .. }) => {
                    let index = self.index_operand_for_indexed_address(graph, value_id)?;
                    let a_id = graph.value_id_for_var(a)?;
                    let b_id = graph.value_id_for_var(b)?;
                    (if index == a_id { b_id } else { a_id }, Some(index))
                }
                crate::InstPayload::Op(
                    crate::SSAOp::Copy { src, .. }
                    | crate::SSAOp::Cast { src, .. }
                    | crate::SSAOp::CallRestore { src, .. },
                ) => (graph.value_id_for_var(src)?, None),
                // Taken back by a constant from an address already inside the
                // object: the same object, at an offset nothing states.
                crate::InstPayload::Op(crate::SSAOp::IntSub { a, b, .. })
                    if b.constant_bits().is_some() =>
                {
                    (graph.value_id_for_var(a)?, None)
                }
                crate::InstPayload::Phi { .. } => (*inst.inputs.first()?, None),
                _ => return None,
            };
            let base_var = graph.value(base)?.var.clone();
            // A base nothing proves an object starts at reaches its object
            // at the first byte its index takes, and is that object at a
            // negative displacement: `buf[i - 1]` is `buf` from one below.
            let contained = index.and_then(|index| {
                let position = resolve_stack_root(self.facts, &base_var)?;
                if self.evidenced_roots.contains(&position) {
                    return None;
                }
                let first = self
                    .values
                    .lower_bound(index)
                    .and_then(|lower| i64::try_from(lower).ok())?;
                let reached = position.offset.checked_add(first)?;
                let container = self
                    .evidenced_roots
                    .iter()
                    .filter(|root| root.base == position.base && root.offset <= reached)
                    .filter(|root| {
                        root.offset == reached
                            || self
                                .evidenced_spans
                                .get(root)
                                .is_some_and(|end| reached < *end)
                    })
                    .max_by_key(|root| root.offset)
                    .copied()?;
                Some((container, position.offset - container.offset))
            });
            let object = match contained {
                Some((container, displacement)) => {
                    let object = self.ensure_stack_object(container);
                    if displacement != 0 {
                        self.interior_offsets.insert(base, displacement);
                    }
                    self.value_objects.insert(
                        MemoryObjectKey {
                            value: base,
                            space: SpaceId::Ram,
                        },
                        object,
                    );
                    object
                }
                None => self.object_for_address_value(graph, &base_var, SpaceId::Ram),
            };
            if !matches!(
                self.objects.get(&object).map(|fact| &fact.kind),
                Some(ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. })
            ) {
                return None;
            }
            // A constant added to an address that is already indexed does not
            // index it again: `(table + i * 8) + 4` is the same element four
            // bytes in. The index stays the base's and the constant joins the
            // displacement, which is how a machine that folds a member offset
            // into its addressing mode spells the second half of a pair.
            let folded_constant = index
                .and_then(|index| crate::constant::signed_value_of(graph, index))
                .filter(|_| self.indexed_addresses.contains_key(&base));
            let inherited = index.is_none() || folded_constant.is_some();
            let index = folded_constant
                .and(self.indexed_addresses.get(&base).copied())
                .or(index)
                .or_else(|| self.indexed_addresses.get(&base).copied())?;
            self.indexed_addresses.insert(value_id, index);
            // Where the address starts, when it is not the object's own base:
            // the index measures from there, so the reach does too.
            let displacement = self
                .interior_offsets
                .get(&base)
                .copied()
                .unwrap_or_else(|| self.indexed_displacement_of(base))
                .saturating_add(folded_constant.unwrap_or(0));
            if displacement != 0 {
                self.indexed_displacements.insert(value_id, displacement);
            }
            // An index inherited through arithmetic no longer measures from the
            // object's base, so it cannot say which element this is.
            if inherited
                || self
                    .interior_offsets
                    .get(&base)
                    .is_some_and(|offset| *offset != 0)
                || self.displaced_indexed_addresses.contains(&base)
            {
                self.displaced_indexed_addresses.insert(value_id);
            }
            Some(object)
        })();
        self.resolving.remove(&value_id);
        result
    }

    /// The operand of an indexed address that supplies the offset.
    ///
    /// The address is a sum of a value that carries a stack root and one that
    /// does not; the second is the index. Taking it from the graph rather than
    /// from the rendered expression keeps the answer exact -- the renderer
    /// would have to take an address apart again and guess which half is which.
    fn index_operand_for_indexed_address(
        &self,
        graph: &SsaGraph,
        address: ValueId,
    ) -> Option<ValueId> {
        let inst = graph.inst(graph.def_inst(address)?)?;
        let crate::InstPayload::Op(crate::SSAOp::IntAdd { a, b, .. }) = &inst.payload else {
            return None;
        };
        let a_id = graph.value_id_for_var(a)?;
        let b_id = graph.value_id_for_var(b)?;
        let a_rooted = resolve_stack_root(self.facts, a).is_some()
            || resolve_indexed_stack_root(self.facts, a).is_some();
        let b_rooted = resolve_stack_root(self.facts, b).is_some()
            || resolve_indexed_stack_root(self.facts, b).is_some();
        match (a_rooted, b_rooted) {
            (true, false) => Some(b_id),
            (false, true) => Some(a_id),
            _ => None,
        }
    }

    fn ensure_stack_object(&mut self, root: StackAddressRoot) -> ObjectId {
        let key = StackObjectKey {
            root,
            space: SpaceId::Ram,
        };
        if let Some(object) = self.stack_objects.get(&key).copied() {
            return object;
        }
        let id = self.alloc_object_id();
        self.objects.insert(
            id,
            ObjectFact {
                id,
                kind: ObjectKind::StackSlot {
                    space: SpaceId::Ram,
                    base: root.base,
                    offset: root.offset,
                },
            },
        );
        self.stack_objects.insert(key, id);
        id
    }

    fn ensure_global_object(&mut self, key: GlobalObjectKey) -> ObjectId {
        if let Some(object) = self.global_objects.get(&key).copied() {
            return object;
        }
        let id = self.alloc_object_id();
        self.objects.insert(
            id,
            ObjectFact {
                id,
                kind: ObjectKind::Global {
                    space: key.space,
                    address: key.address,
                },
            },
        );
        self.global_objects.insert(key, id);
        id
    }

    pub(crate) fn record_entry_stack_root(&mut self, object: ObjectId, root: StackAddressRoot) {
        if self.ambiguous_entry_stack_objects.contains(&object) {
            return;
        }
        match self.entry_stack_roots.get(&object) {
            Some(existing) if *existing == root => {}
            Some(_) => {
                self.entry_stack_roots.remove(&object);
                self.ambiguous_entry_stack_objects.insert(object);
            }
            None => {
                self.entry_stack_roots.insert(object, root);
            }
        }
    }

    fn ensure_parameter_object(&mut self, index: usize) -> ObjectId {
        let key = ParameterObjectKey {
            index,
            space: SpaceId::Ram,
        };
        if let Some(object) = self.parameter_objects.get(&key).copied() {
            return object;
        }
        let id = self.alloc_object_id();
        self.objects.insert(
            id,
            ObjectFact {
                id,
                kind: ObjectKind::Parameter {
                    space: SpaceId::Ram,
                    index,
                },
            },
        );
        self.parameter_objects.insert(key, id);
        id
    }

    /// The object at the end of a chain of loads from a parameter, creating
    /// every object along the way. Same path, same objects.
    fn ensure_pointee_chain(&mut self, root: usize, path: &[crate::PointeeStep]) -> ObjectId {
        let mut current = self.ensure_parameter_object(root);
        for step in path {
            let key = PointeeObjectKey {
                base: current,
                offset: step.offset,
                size: step.size,
                space: ObjectSpaceId(SpaceId::Ram),
            };
            current = if let Some(object) = self.pointee_objects.get(&key).copied() {
                object
            } else {
                let id = self.alloc_object_id();
                self.objects.insert(
                    id,
                    ObjectFact {
                        id,
                        kind: ObjectKind::Pointee {
                            space: SpaceId::Ram,
                            base: current,
                            offset: step.offset,
                            size: step.size,
                        },
                    },
                );
                self.pointee_objects.insert(key, id);
                id
            };
        }
        current
    }

    fn ensure_escaped_unknown(&mut self, space: SpaceId) -> ObjectId {
        let key = ObjectSpaceId(space);
        if let Some(object) = self.escaped_unknown.get(&key).copied() {
            return object;
        }
        let id = self.alloc_object_id();
        self.objects.insert(
            id,
            ObjectFact {
                id,
                kind: ObjectKind::EscapedUnknown { space },
            },
        );
        self.escaped_unknown.insert(key, id);
        id
    }

    fn alloc_object_id(&mut self) -> ObjectId {
        let id = ObjectId(self.next_object_id);
        self.next_object_id = self.next_object_id.saturating_add(1);
        id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReachingAbiState {
    PreservedEntry,
    Value(ValueId),
}

/// What one path back from a boundary contributes to the value reaching it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReachingAbiPath {
    Reaches(ReachingAbiState),
    /// The path re-entered a block already on it without passing a
    /// definition, so it carries whatever the other paths do. A loop nothing
    /// in it writes brings the value that entered it round unchanged, and a
    /// definition inside it would have put a merge at the header first.
    Cycle,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReachingAbiPolicy {
    pub(crate) allow_distinct_phi_inputs: bool,
    pub(crate) calls_are_barriers: bool,
    /// The stack pointer, whose merges of entry pointers are the entry pointer.
    pub(crate) stack_pointer: Option<CanonicalStorageId>,
    /// The carrier a call transfer moves by itself: the stack pointer, which
    /// the callee's return puts back only where the convention states it. A
    /// call is a barrier for this carrier and for nothing else, because every
    /// other register a call may change is a `CallDefine` the walk sees.
    pub(crate) transfer_carrier: Option<CanonicalStorageId>,
}

/// What reaches the end of `block_addr`, computed once per query.
///
/// A block's answer does not depend on the path that asked for it, except
/// for a block still being walked -- the root, scanned only up to its
/// boundary, or an ancestor on the current path, which a back edge asks
/// about -- and those keep the path's own scan. Without this the walk
/// enumerated every path through a diamond-shaped body and never finished.
/// The backward search for the value an ABI storage holds at a point.
///
/// The function, its graph, the storage being traced and the policy that says
/// what may be crossed are fixed for the whole walk; only the point moves. The
/// two walkers below are mutually recursive, so stating the fixed part once is
/// also what keeps their signatures readable.
#[derive(Clone, Copy)]
pub(crate) struct ReachingAbi<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) storage: CanonicalStorageId,
    pub(crate) policy: ReachingAbiPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReachingStorageState {
    Unknown,
    PreservedEntry,
    Value(ValueId),
    Conflict,
}

/// The frame positions an object starts at, how far each reaches, and the ones whose address leaves the body.
pub(crate) struct EvidencedStackRoots {
    pub(crate) roots: BTreeSet<StackAddressRoot>,
    pub(crate) spans: BTreeMap<StackAddressRoot, i64>,
    pub(crate) escaping: BTreeSet<StackAddressRoot>,
}

/// Declared stack slots, keyed by the coordinate objects are identified in.
///
/// A source declares every slot in entry coordinates, so the key is the
/// declaration and the object model and the certificates read the same table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DeclaredStackSlots {
    pub(crate) by_key: BTreeMap<(StackAddressBase, i64), SourceStackSlotSpec>,
}

impl DeclaredStackSlots {
    /// The declared slot this coordinate falls inside, and how far into it.
    ///
    /// A member of a declared aggregate is that aggregate at an offset, not an
    /// object of its own, so the address resolves to the slot that contains it.
    fn containing(&self, root: StackAddressRoot) -> Option<(StackAddressRoot, i64)> {
        self.by_key.iter().find_map(|((base, offset), slot)| {
            if *base != root.base || slot.size_bytes() == 0 {
                return None;
            }
            let displacement = root.offset.checked_sub(*offset)?;
            let inside = displacement > 0 && displacement < i64::from(slot.size_bytes());
            inside.then_some((
                StackAddressRoot {
                    base: *base,
                    offset: *offset,
                },
                displacement,
            ))
        })
    }
}

/// The function itself: its blocks, its graph, and the machine it was lifted
/// for.
///
/// The three are read by nearly every collector in this file and are never
/// apart, so they are one thing rather than three parameters each collector
/// repeats.
#[derive(Clone, Copy)]
pub(crate) struct Body<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) machine_context: Option<&'a SourceMachineContext>,
}

#[derive(Debug, Clone)]
pub(crate) struct LoopCarrierPeerCandidate {
    pub(crate) phi: ValueId,
    pub(crate) width: u32,
    pub(crate) entries: Vec<LoopCarrierEdgeValue>,
    pub(crate) updates: Vec<LoopCarrierUpdateFact>,
}

pub(crate) type LoopCarrierMemberRoles = BTreeMap<ValueId, BTreeSet<LoopCarrierMemberRole>>;

/// What the memory annotations say one raw sub-effect touches.
pub(crate) struct RawMemoryProvenance {
    pub(crate) object: ObjectId,
    pub(crate) object_offset: Option<i64>,
    pub(crate) complete: bool,
}

/// Where an access sits in the program.
///
/// The instruction, the block it is in and its index there travel together
/// through every rule that records a memory effect, so they are one thing.
#[derive(Clone, Copy)]
pub(crate) struct AccessSite {
    pub(crate) inst: InstId,
    pub(crate) block_addr: u64,
    pub(crate) op_index: usize,
}

/// Where a recorded effect goes, and the counter that orders the effects one
/// instruction produces.
pub(crate) struct EffectSink<'a> {
    pub(crate) facts: &'a mut BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    pub(crate) ordinal: &'a mut u32,
}

/// One raw memory access: what it touches, and what it does there.
#[derive(Clone, Copy)]
pub(crate) struct RawAccess {
    pub(crate) address: ValueId,
    pub(crate) space: SpaceId,
    pub(crate) value: Option<ValueId>,
    pub(crate) is_write: bool,
    pub(crate) width: u32,
}
