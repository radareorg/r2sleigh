//! Exhaustive source-side semantic obligation inventory.
//!
//! Render certificates answer whether one emitted construct is justified. This
//! module answers the complementary question: which canonical SSA instructions
//! and effects must survive every downstream transformation? The inventory is
//! built once from the prepared source artifact and uses canonical source sites,
//! never rendered names or AST positions, as persistent identities.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::CanonicalStorageId;
use crate::arena::OpId;
use crate::graph::{GraphInst, InstId, InstPayload, SsaGraph, UseSite, ValueId};
use crate::op::SSAOp;
use crate::semantic::{SourceBoundaryFacts, StructuredDataflowFacts};

pub const SEMANTIC_OBLIGATION_SCHEMA_VERSION: u32 = 11;

/// Stable identity of one canonical SSA instruction.
///
/// An operation is named by its [`OpId`], which no edit moves; its place in
/// the block is only how it is spelled ([`Self::spelled`]). Phi and
/// ordinary-op namespaces are separate so synthesized SSA joins cannot alias
/// lifted operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalInstructionId {
    pub block_addr: u64,
    pub site: CanonicalInstructionSite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CanonicalInstructionSite {
    Phi(CanonicalStorageId),
    Op(OpId),
    /// One exact native instruction span for which the trusted translator
    /// emitted no canonical P-code and supplied no no-effect authority.
    NativeSpan {
        instruction_addr: u64,
        size: u32,
    },
}

impl CanonicalInstructionId {
    /// A graph instruction's identity: its block, and its operation, or for a phi the storage it
    /// merges. The inventory reads it here and holds none.
    pub fn of(graph: &SsaGraph, inst: &GraphInst) -> Result<Self, ObligationInventoryFailure> {
        let failure = |block_addr, kind| ObligationInventoryFailure {
            inst: inst.id,
            block_addr,
            kind,
        };
        let block_addr = (graph.block(inst.block).map(|block| block.addr))
            .ok_or_else(|| failure(None, ObligationInventoryFailureKind::MissingBlock))?;
        let missing = |kind| failure(Some(block_addr), kind);
        let site = match inst.payload {
            InstPayload::Phi { .. } => {
                CanonicalInstructionSite::Phi((graph.written_storage(inst)).ok_or_else(|| {
                    missing(ObligationInventoryFailureKind::MissingCanonicalPhiStorage)
                })?)
            }
            InstPayload::Op(_) => CanonicalInstructionSite::Op(
                (graph.op_for_inst(inst.id))
                    .ok_or_else(|| missing(ObligationInventoryFailureKind::MissingOperationSite))?,
            ),
        };
        Ok(Self { block_addr, site })
    }

    /// This instruction as a person reads it, an operation by its place in
    /// its block: `0x{block}:op:{n}`.
    pub fn spelled(self, graph: &SsaGraph) -> SpelledInstruction {
        SpelledInstruction {
            id: self,
            ordinal: match self.site {
                CanonicalInstructionSite::Op(op) => graph
                    .inst_for_op(op)
                    .and_then(|inst| graph.op_ordinal(inst)),
                _ => None,
            },
        }
    }
}

/// A [`CanonicalInstructionId`] with the place its operation holds in the
/// sealed block it was spelled against.
///
/// Ordered as the spelling reads: by block, then phi before operation before
/// native span, then by place. Two ids order the same way only when spelled
/// against one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpelledInstruction {
    id: CanonicalInstructionId,
    ordinal: Option<usize>,
}

impl SpelledInstruction {
    fn key(&self) -> (u64, u8, Option<usize>, CanonicalInstructionSite) {
        let rank = match self.id.site {
            CanonicalInstructionSite::Phi(_) => 0,
            CanonicalInstructionSite::Op(_) => 1,
            CanonicalInstructionSite::NativeSpan { .. } => 2,
        };
        (self.id.block_addr, rank, self.ordinal, self.id.site)
    }
}

impl Ord for SpelledInstruction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for SpelledInstruction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for SpelledInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let block_addr = self.id.block_addr;
        match self.id.site {
            CanonicalInstructionSite::Phi(storage) => {
                write!(
                    f,
                    "0x{:x}:phi:{:?}:0x{:x}:{}",
                    block_addr, storage.space, storage.offset, storage.size
                )
            }
            CanonicalInstructionSite::Op(op) => match self.ordinal {
                Some(ordinal) => write!(f, "0x{block_addr:x}:op:{ordinal}"),
                // An operation the function it was spelled against does not
                // hold: named by identity, so it is never mistaken for one.
                None => write!(f, "0x{block_addr:x}:op#{op}"),
            },
            CanonicalInstructionSite::NativeSpan {
                instruction_addr,
                size,
            } => write!(f, "0x{block_addr:x}:native:0x{instruction_addr:x}:{size}"),
        }
    }
}

/// Why a source instruction must survive.
///
/// One instruction can own more than one obligation. For example, an atomic
/// compare-and-swap owns both memory-read and memory-write obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticObligationKind {
    ObservableMemoryRead,
    ObservableMemoryWrite,
    Call,
    CallArgument,
    CallResult,
    Return,
    ReturnValue,
    ControlPredicate,
    ControlTransfer,
    Trap,
    Atomicity,
    MemoryOrdering,
    VolatileOrUnknownEffect,
    /// A native instruction the lifter decoded to no semantics at all.
    ///
    /// Distinct from `VolatileOrUnknownEffect`, which is refusal evidence: this
    /// is a positive fact about the instruction rather than an absence of one.
    /// A failed decode produces an `Unimplemented` operation, so zero canonical
    /// operations means the decode succeeded and the instruction does nothing --
    /// `nop dword [rax]` is the case that matters, and calling it unknown
    /// refused eight otherwise-complete functions.
    NoNativeSemantics,
    /// An instruction of a stack-protector failure path a decided check removed
    /// (`crate::stack_protector`), which the program never reaches under `Premise::UbFreeSource`.
    CompilerInserted,
    LoopCarriedState,
    LiveStateTransition,
    LiveValueProducer,
}

impl SemanticObligationKind {
    /// Every kind in declaration order, which is its `Ord` and its seed bit.
    const ALL: [Self; 18] = [
        Self::ObservableMemoryRead,
        Self::ObservableMemoryWrite,
        Self::Call,
        Self::CallArgument,
        Self::CallResult,
        Self::Return,
        Self::ReturnValue,
        Self::ControlPredicate,
        Self::ControlTransfer,
        Self::Trap,
        Self::Atomicity,
        Self::MemoryOrdering,
        Self::VolatileOrUnknownEffect,
        Self::NoNativeSemantics,
        Self::CompilerInserted,
        Self::LoopCarriedState,
        Self::LiveStateTransition,
        Self::LiveValueProducer,
    ];

    /// Whether this obligation independently proves a program observation.
    ///
    /// Producer and loop-transition obligations are dependency annotations:
    /// they inherit liveness from the root that reached them and cannot mint it
    /// themselves. Unknown-effect obligations are refusal evidence. Treating
    /// either class as a fresh positive root loses evidence polarity and can
    /// promote preserved machine state into a source-level value.
    pub const fn is_positive_observation_root(self) -> bool {
        !matches!(
            self,
            Self::VolatileOrUnknownEffect
                | Self::NoNativeSemantics
                | Self::CompilerInserted
                | Self::LoopCarriedState
                | Self::LiveStateTransition
                | Self::LiveValueProducer
        )
    }
}

impl std::fmt::Display for SemanticObligationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ObservableMemoryRead => "memory-read",
            Self::ObservableMemoryWrite => "memory-write",
            Self::Call => "call",
            Self::CallArgument => "call-argument",
            Self::CallResult => "call-result",
            Self::Return => "return",
            Self::ReturnValue => "return-value",
            Self::ControlPredicate => "control-predicate",
            Self::ControlTransfer => "control-transfer",
            Self::Trap => "trap",
            Self::Atomicity => "atomicity",
            Self::MemoryOrdering => "memory-ordering",
            Self::VolatileOrUnknownEffect => "volatile-or-unknown",
            Self::NoNativeSemantics => "no-native-semantics",
            Self::CompilerInserted => "compiler-inserted",
            Self::LoopCarriedState => "loop-carried-state",
            Self::LiveStateTransition => "live-state-transition",
            Self::LiveValueProducer => "live-value-producer",
        };
        f.write_str(label)
    }
}

/// Stable identity of one source semantic obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SemanticObligationId {
    pub instruction: CanonicalInstructionId,
    pub kind: SemanticObligationKind,
    pub component: SemanticObligationComponent,
}

impl SemanticObligationId {
    /// This obligation as a person reads it:
    /// `{instruction}:{kind}:{component}`, the instruction spelled by
    /// [`CanonicalInstructionId::spelled`].
    pub fn spelled(self, graph: &SsaGraph) -> SpelledObligation {
        let ordinal = self.instruction.spelled(graph).ordinal;
        SpelledObligation {
            id: self,
            ordinal: ordinal.and_then(|ordinal| u32::try_from(ordinal).ok()),
        }
    }
}

/// A [`SemanticObligationId`] spelled against the sealed function it is about,
/// ordered as the spelling reads: by instruction, then kind and component. It
/// keeps the identity once and only the place its operation holds beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpelledObligation {
    id: SemanticObligationId,
    ordinal: Option<u32>,
}

impl SpelledObligation {
    /// The obligation spelled.
    pub const fn id(&self) -> SemanticObligationId {
        self.id
    }

    /// The obligation spelled, borrowed.
    pub const fn identity(&self) -> &SemanticObligationId {
        &self.id
    }

    /// Its instruction, spelled.
    pub fn instruction(&self) -> SpelledInstruction {
        SpelledInstruction {
            id: self.id.instruction,
            ordinal: self.ordinal.map(|ordinal| ordinal as usize),
        }
    }
}

impl Ord for SpelledObligation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.instruction().cmp(&other.instruction())).then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for SpelledObligation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for SpelledObligation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{:?}",
            self.instruction(),
            self.id.kind,
            self.id.component
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticObligationComponent {
    Whole,
    MemoryAccess(u32),
    PredicateOperand,
    Index(u32),
    RegisterSlot {
        index: u32,
        storage: CanonicalStorageId,
    },
    StackOffset(i64),
    LoopTransition {
        carrier: CanonicalStorageId,
        predecessor: u64,
    },
    MemoryOrdering(SemanticMemoryOrdering),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticMemoryOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
    Unknown,
}

impl From<r2il::MemoryOrdering> for SemanticMemoryOrdering {
    fn from(ordering: r2il::MemoryOrdering) -> Self {
        match ordering {
            r2il::MemoryOrdering::Relaxed => Self::Relaxed,
            r2il::MemoryOrdering::Acquire => Self::Acquire,
            r2il::MemoryOrdering::Release => Self::Release,
            r2il::MemoryOrdering::AcqRel => Self::AcqRel,
            r2il::MemoryOrdering::SeqCst => Self::SeqCst,
            r2il::MemoryOrdering::Unknown => Self::Unknown,
        }
    }
}

/// Initial source-side classification assigned exactly once per instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticInstructionState {
    LiveObligation,
    ProvenDead,
    StructuralControlOnly,
    UnsupportedUnknown,
    /// A span of a stack-protector failure path a decided check removed; it owes one obligation.
    CompilerInserted,
}

/// Exact source owner for one semantic site.
///
/// Graph instructions and genuine zero-op native spans are disjoint by type; a span's geometry
/// is the inventory's `native_spans`, under the site's instruction identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticSourceSite {
    GraphInstruction(InstId),
    GenuineNativeSpan,
}

impl SemanticSourceSite {
    pub const fn graph_inst(self) -> Option<InstId> {
        match self {
            Self::GraphInstruction(inst) => Some(inst),
            Self::GenuineNativeSpan => None,
        }
    }
}

impl std::fmt::Display for SemanticInstructionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::LiveObligation => "live",
            Self::ProvenDead => "proven-dead",
            Self::StructuralControlOnly => "structural-control-only",
            Self::UnsupportedUnknown => "unsupported-unknown",
            Self::CompilerInserted => "compiler-inserted",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticInstructionDisposition {
    pub id: CanonicalInstructionId,
    pub source: SemanticSourceSite,
    pub state: SemanticInstructionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticObligation {
    pub id: SemanticObligationId,
    pub source: SemanticSourceSite,
    /// Exact canonical values needed to realize this obligation.
    pub inputs: Vec<ValueId>,
    /// Exact graph use certified by an edge-specific obligation.
    ///
    /// This is present for a loop state transition and absent for obligations
    /// that are owned by an instruction as a whole. Consumers must use this
    /// indexed site directly instead of recovering a phi input from a
    /// predecessor address or value match.
    pub edge_use: Option<UseSite>,
}

/// Every obligation of one function, sorted by identity: one vector searched by halving, where
/// a tree held each eighty-byte identity twice (key and value) beside its node overhead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationTable(Vec<SemanticObligation>);

impl ObligationTable {
    /// The table of these obligations, whose identities are distinct: sorted in place, since a
    /// stable sort's scratch was the inventory's peak (doc/adr-memory-model.md, MM.10).
    fn of(mut obligations: Vec<SemanticObligation>) -> Self {
        obligations.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        debug_assert!(obligations.windows(2).all(|pair| pair[0].id != pair[1].id));
        Self(obligations)
    }

    fn position(&self, id: &SemanticObligationId) -> Result<usize, usize> {
        self.0.binary_search_by(|obligation| obligation.id.cmp(id))
    }

    pub fn get(&self, id: &SemanticObligationId) -> Option<&SemanticObligation> {
        self.position(id).ok().map(|at| &self.0[at])
    }

    /// The obligations of one instruction: a run, since identities sort by instruction first; one
    /// search finds it, and a run is a few obligations long.
    fn run(&self, instruction: &CanonicalInstructionId) -> &[SemanticObligation] {
        let start = (self.0).partition_point(|held| held.id.instruction < *instruction);
        let rest = &self.0[start..];
        let len = (rest.iter())
            .take_while(|held| held.id.instruction == *instruction)
            .count();
        &rest[..len]
    }

    pub fn contains_key(&self, id: &SemanticObligationId) -> bool {
        self.position(id).is_ok()
    }

    /// Add obligations none of which the table holds, in one sort and one merge: `false`, and the
    /// table untouched, where any identity repeats.
    fn extend_new(&mut self, mut added: Vec<SemanticObligation>) -> bool {
        added.sort_by_key(|obligation| obligation.id);
        let repeated = added.windows(2).any(|pair| pair[0].id == pair[1].id)
            || added
                .iter()
                .any(|obligation| self.contains_key(&obligation.id));
        if repeated {
            return false;
        }
        let held = std::mem::take(&mut self.0);
        let mut merged = Vec::with_capacity(held.len() + added.len());
        let (mut held, mut added) = (held.into_iter().peekable(), added.into_iter().peekable());
        while let (Some(old), Some(new)) = (held.peek(), added.peek()) {
            let next = match old.id < new.id {
                true => held.next(),
                false => added.next(),
            };
            merged.extend(next);
        }
        merged.extend(held.chain(added));
        self.0 = merged;
        true
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &SemanticObligationId> {
        self.0.iter().map(|obligation| &obligation.id)
    }

    pub fn values(&self) -> std::slice::Iter<'_, SemanticObligation> {
        self.0.iter()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SemanticObligationId, &SemanticObligation)> {
        self.0.iter().map(|obligation| (&obligation.id, obligation))
    }
}

impl<'a> IntoIterator for &'a ObligationTable {
    type Item = (&'a SemanticObligationId, &'a SemanticObligation);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, SemanticObligation>,
        fn(&'a SemanticObligation) -> (&'a SemanticObligationId, &'a SemanticObligation),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|obligation| (&obligation.id, obligation))
    }
}

/// Serialized as the identity-keyed map it replaced.
impl Serialize for ObligationTable {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter())
    }
}

/// Complete source inventory for one prepared function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationInventoryFailureKind {
    MissingBlock,
    MissingOperationSite,
    MissingCanonicalPhiStorage,
    DuplicateCanonicalInstruction,
    DuplicateObligationSeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationInventoryFailure {
    pub inst: InstId,
    pub block_addr: Option<u64>,
    pub kind: ObligationInventoryFailureKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticObligationInventory {
    schema_version: u32,
    source_instruction_count: usize,
    /// What every graph instruction owes, indexed by the instruction: its state and its run of
    /// the table. Its identity is the graph's, read when asked (`CanonicalInstructionId::of`).
    instructions: Vec<Option<Owed>>,
    /// The dispositions of native instruction spans the translator emitted no
    /// canonical operation for. They have no graph instruction to be indexed
    /// by, and there are none in an ordinary function.
    span_instructions: BTreeMap<CanonicalInstructionId, SemanticInstructionDisposition>,
    obligations: ObligationTable,
    native_spans: BTreeMap<CanonicalInstructionId, crate::GenuineNativeInstructionSpan>,
    construction_failures: Vec<ObligationInventoryFailure>,
    unstructured_cycle_blocks: BTreeSet<u64>,
    /// Whether some graph instruction's obligations were not one run of the table, or named an
    /// instruction with no disposition: the inventory then does not close.
    split_runs: bool,
    /// Whether the inventory closes, decided when it was built.
    ///
    /// Deciding it is a walk of every instruction and every obligation with a
    /// map lookup for each, over keys that are forty and eighty bytes wide.
    /// Six places in a render ask, and the answer cannot change between them:
    /// the inventory is built once and bound to its native spans once, and
    /// nothing else may touch it. So it is decided where it is built.
    complete: bool,
}

impl SemanticObligationInventory {
    fn empty(source_instruction_count: usize) -> Self {
        Self {
            schema_version: SEMANTIC_OBLIGATION_SCHEMA_VERSION,
            source_instruction_count,
            instructions: vec![None; source_instruction_count],
            span_instructions: BTreeMap::new(),
            obligations: ObligationTable::default(),
            native_spans: BTreeMap::new(),
            construction_failures: Vec::new(),
            unstructured_cycle_blocks: BTreeSet::new(),
            split_runs: false,
            complete: false,
        }
    }
}

/// One graph instruction's disposition as held: its state, and where its obligations sit in the
/// table, a run since identities sort by instruction first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct Owed {
    state: SemanticInstructionState,
    start: u32,
    len: u32,
}

/// What obligation seeding reads beside the graph and boundaries: the private stack objects, the
/// certified round trips, and the blocks whose conditional branch sends both arms to one block.
pub(crate) struct SeedingFacts<'a> {
    pub(crate) private_stack_objects: &'a BTreeSet<crate::ObjectId>,
    pub(crate) memory_round_trips: &'a BTreeMap<
        crate::semantic::StructuredAccessId,
        crate::semantic::MemoryRoundTripCertificate,
    >,
    pub(crate) meeting_arms: &'a BTreeSet<u64>,
}

impl<'a> SeedingFacts<'a> {
    pub(crate) const fn new(
        private_stack_objects: &'a BTreeSet<crate::ObjectId>,
        memory_round_trips: &'a BTreeMap<
            crate::semantic::StructuredAccessId,
            crate::semantic::MemoryRoundTripCertificate,
        >,
        meeting_arms: &'a BTreeSet<u64>,
    ) -> Self {
        Self {
            private_stack_objects,
            memory_round_trips,
            meeting_arms,
        }
    }

    /// Seed each conditional branch ending a block whose arms meet as the direct transfer it is,
    /// with no inputs: its condition is unread. The branches seeded.
    fn seed_direct_branches(
        &self,
        graph: &SsaGraph,
        required: &mut ObligationSeeds,
        explicit_inputs: &mut BTreeMap<
            (InstId, SemanticObligationKind, SemanticObligationComponent),
            Vec<ValueId>,
        >,
    ) -> crate::dense::IdSet<InstId> {
        let direct = self.direct_branches(graph);
        for inst in direct.iter() {
            let identity = (
                inst,
                SemanticObligationKind::ControlTransfer,
                SemanticObligationComponent::Whole,
            );
            seed_instruction(identity.0, identity.1, identity.2, required);
            explicit_inputs.insert(identity, Vec::new());
        }
        direct
    }

    fn direct_branches(&self, graph: &SsaGraph) -> crate::dense::IdSet<InstId> {
        (self.meeting_arms.iter())
            .filter_map(|addr| graph.block(*graph.block_by_addr.get(addr)?)?.insts.last())
            .filter(|inst| {
                matches!(
                    graph.inst(**inst).map(|inst| &inst.payload),
                    Some(InstPayload::Op(SSAOp::CBranch { .. }))
                )
            })
            .copied()
            .collect()
    }
}

impl SemanticObligationInventory {
    pub(crate) fn collect(
        graph: &SsaGraph,
        structured: &StructuredDataflowFacts,
        boundaries: &SourceBoundaryFacts,
        machine_context: Option<&crate::SourceMachineContext>,
        seeding: &SeedingFacts<'_>,
    ) -> Self {
        let (canonical_ids, mut construction_failures) = collect_canonical_instruction_ids(graph);
        let mut required = ObligationSeeds::new(graph.insts.len());
        let mut explicit_inputs = BTreeMap::<
            (InstId, SemanticObligationKind, SemanticObligationComponent),
            Vec<ValueId>,
        >::new();
        let mut explicit_edge_uses = BTreeMap::<
            (InstId, SemanticObligationKind, SemanticObligationComponent),
            UseSite,
        >::new();
        let mut unsupported = crate::dense::IdSet::<InstId>::default();
        let mut duplicate_seeds =
            BTreeSet::<(InstId, SemanticObligationKind, SemanticObligationComponent)>::new();
        // Private frame reads, owed only once the liveness walk reaches them: (inst, ordinal, address).
        let mut private_reads = Vec::new();

        let direct = seeding.seed_direct_branches(graph, &mut required, &mut explicit_inputs);
        for inst in graph.insts.iter().filter(|inst| !direct.contains(inst.id)) {
            match &inst.payload {
                InstPayload::Op(op) => {
                    seed_direct_obligations(
                        graph,
                        inst,
                        op,
                        &mut required,
                        &mut explicit_inputs,
                        &mut duplicate_seeds,
                        &mut unsupported,
                    );
                }
                InstPayload::Phi { .. } if graph.written_storage(inst).is_none() => {
                    unsupported.insert(inst.id);
                    seed_instruction(
                        inst.id,
                        SemanticObligationKind::VolatileOrUnknownEffect,
                        SemanticObligationComponent::Whole,
                        &mut required,
                    );
                }
                InstPayload::Phi { .. } => {}
            }
        }

        for access in structured.memory_accesses.values() {
            if r2il::refusal_evidence::tracing() && graph.inst(access.id.inst).is_none() {
                r2il::refusal_evidence!(
                    "access-instruction",
                    "{:?} names no instruction of this graph",
                    access.id
                );
            }
            if r2il::refusal_evidence::tracing()
                && let Some(inst) = graph.inst(access.id.inst)
                && !matches!(
                    inst.payload,
                    InstPayload::Op(
                        crate::SSAOp::Load { .. }
                            | crate::SSAOp::Store { .. }
                            | crate::SSAOp::LoadLinked { .. }
                            | crate::SSAOp::StoreConditional { .. }
                            | crate::SSAOp::LoadGuarded { .. }
                            | crate::SSAOp::StoreGuarded { .. }
                            | crate::SSAOp::AtomicCAS(_)
                    )
                )
            {
                r2il::refusal_evidence!(
                    "access-instruction",
                    "{:?} is a memory access filed on {:?}, which is {:?}",
                    access.id,
                    inst.id,
                    inst.payload
                );
            }
            // Reading a slot no outside pointer can name is no observable effect: the load owes
            // its value only while something reads it (seeded after the liveness walk below).
            let private_read = !access.is_write
                && access.provenance_complete
                && seeding.private_stack_objects.contains(&access.object);
            // A round trip leaves the object holding what it held, so neither
            // the write nor the reads it answers for owes anything of its own.
            // Seeding a dependency annotation instead would be wrong twice: it
            // makes the access a root of the backward walk below, and it makes
            // its instruction live whether or not anything reads the value. If
            // something does read the value, that walk reaches the load and
            // annotates it then, which is the whole of what it owes.
            let round_trip = seeding.memory_round_trips.values().any(|certificate| {
                certificate.write == access.id
                    || certificate.read == access.id
                    || certificate.redundant_reads.contains(&access.id)
            });
            if round_trip {
                continue;
            }
            if private_read {
                private_reads.push((access.id.inst, access.id.ordinal, access.address));
                continue;
            }
            let kind = if access.is_write {
                SemanticObligationKind::ObservableMemoryWrite
            } else {
                SemanticObligationKind::ObservableMemoryRead
            };
            let mut inputs = vec![access.address];
            if access.is_write
                && let Some(value) = access.value
            {
                inputs.push(value);
            }
            seed_instruction_with_inputs(
                access.id.inst,
                kind,
                SemanticObligationComponent::MemoryAccess(access.id.ordinal),
                inputs,
                &mut required,
                &mut explicit_inputs,
                &mut duplicate_seeds,
            );
            if !access.provenance_complete {
                unsupported.insert(access.id.inst);
                seed_instruction(
                    access.id.inst,
                    SemanticObligationKind::VolatileOrUnknownEffect,
                    SemanticObligationComponent::MemoryAccess(access.id.ordinal),
                    &mut required,
                );
            }
        }

        let mut incomplete_returns = Vec::new();
        for boundary in boundaries.returns.values() {
            seed_instruction(
                boundary.at,
                SemanticObligationKind::Return,
                SemanticObligationComponent::Whole,
                &mut required,
            );
            // An unproven result is a value a caller may read that nothing here can render.
            if boundary.result_unproven {
                seed_instruction_with_inputs(
                    boundary.at,
                    SemanticObligationKind::ReturnValue,
                    SemanticObligationComponent::Whole,
                    Vec::new(),
                    &mut required,
                    &mut explicit_inputs,
                    &mut duplicate_seeds,
                );
            }
            for value in &boundary.values {
                let logical_value =
                    crate::semantic::exact_logical_return_projection(graph, machine_context, value)
                        .map_or(value.value, |(logical, _, _)| logical);
                seed_instruction_with_inputs(
                    boundary.at,
                    SemanticObligationKind::ReturnValue,
                    boundary_component(value.slot),
                    vec![logical_value],
                    &mut required,
                    &mut explicit_inputs,
                    &mut duplicate_seeds,
                );
                seed_value_definition(
                    graph,
                    logical_value,
                    SemanticObligationKind::LiveValueProducer,
                    &mut required,
                );
            }
            if let Some(return_address) = boundary.return_address {
                seed_value_definition(
                    graph,
                    return_address.value,
                    SemanticObligationKind::LiveValueProducer,
                    &mut required,
                );
            }
            if let Some(crate::semantic::SourceReturnStackPointerFact::ReachingValue {
                value,
                ..
            }) = boundary.exit_stack_pointer
            {
                seed_value_definition(
                    graph,
                    value,
                    SemanticObligationKind::LiveValueProducer,
                    &mut required,
                );
            }
            if !boundary.complete {
                unsupported.insert(boundary.at);
                seed_instruction(
                    boundary.at,
                    SemanticObligationKind::VolatileOrUnknownEffect,
                    SemanticObligationComponent::Whole,
                    &mut required,
                );
                incomplete_returns.push(boundary.at);
            }
        }
        taint_incomplete_boundary_inputs(
            graph,
            &incomplete_returns,
            &mut required,
            &mut unsupported,
        );

        for boundary in boundaries.calls.values() {
            seed_instruction(
                boundary.at,
                SemanticObligationKind::Call,
                SemanticObligationComponent::Whole,
                &mut required,
            );
            for argument in &boundary.arguments {
                let component = match argument.slot {
                    crate::semantic::CallBoundarySlot::Register { index, storage } => {
                        SemanticObligationComponent::RegisterSlot { index, storage }
                    }
                    crate::semantic::CallBoundarySlot::Stack(offset) => {
                        SemanticObligationComponent::StackOffset(offset)
                    }
                };
                // A preserved-entry argument names no value in this function,
                // so it has no producer to keep live. The argument obligation
                // still exists: the call reads that carrier either way.
                let inputs = match argument.value {
                    crate::semantic::SourceCallArgumentValue::Value(value) => vec![value],
                    crate::semantic::SourceCallArgumentValue::PreservedEntry => Vec::new(),
                };
                seed_instruction_with_inputs(
                    boundary.at,
                    SemanticObligationKind::CallArgument,
                    component,
                    inputs,
                    &mut required,
                    &mut explicit_inputs,
                    &mut duplicate_seeds,
                );
                if let crate::semantic::SourceCallArgumentValue::Value(value) = argument.value {
                    seed_value_definition(
                        graph,
                        value,
                        SemanticObligationKind::LiveValueProducer,
                        &mut required,
                    );
                }
            }
            for value in &boundary.results {
                seed_instruction_with_inputs(
                    boundary.at,
                    SemanticObligationKind::CallResult,
                    boundary_component(value.slot),
                    vec![value.value],
                    &mut required,
                    &mut explicit_inputs,
                    &mut duplicate_seeds,
                );
                seed_value_definition(
                    graph,
                    value.value,
                    SemanticObligationKind::LiveValueProducer,
                    &mut required,
                );
            }
            if !boundary.complete {
                // The call, and only the call. What the boundary failed to
                // prove is which value fills which argument position at this
                // one site; the values reaching it are ordinary values this
                // function computes, and a gap over the call is the whole of
                // what cannot be rendered.
                unsupported.insert(boundary.at);
                seed_instruction(
                    boundary.at,
                    SemanticObligationKind::VolatileOrUnknownEffect,
                    SemanticObligationComponent::Whole,
                    &mut required,
                );
            }
        }

        // What an incomplete boundary keeps alive. The graph says a call may
        // read every carrier its convention passes arguments in, which is true
        // of the machine; a complete boundary then says which of them this call
        // does read, and those producers are already kept live above. Where the
        // boundary could not say, none of the carriers can be proven dead -- so
        // this is the whole of what the taint used to claim, bounded by the
        // convention's carriers instead of by the function's size.
        for boundary in boundaries.calls.values() {
            if boundary.complete {
                continue;
            }
            for read in graph.call_boundary_reads(boundary.at) {
                let Some(inst) = graph.inst(read) else {
                    continue;
                };
                for input in graph.inputs(inst.id) {
                    seed_value_definition(
                        graph,
                        *input,
                        SemanticObligationKind::LiveValueProducer,
                        &mut required,
                    );
                }
            }
        }

        // First close dependencies from observable effects and exact ABI boundaries. A loop
        // carrier is semantically live only when that independent root closure reaches its phi;
        // recognizer-retained facts must never decide source obligation liveness.
        propagate_live_dependencies(graph, &direct, &mut required);
        let live_before_loop_annotation = required.keys().collect::<crate::dense::IdSet<_>>();
        for fact in structured.loops.values() {
            for carrier in &fact.carriers {
                let carrier_inst = graph.def_inst(carrier.phi);
                if carrier_inst.is_none_or(|inst| !live_before_loop_annotation.contains(inst)) {
                    continue;
                }
                seed_value_definition(
                    graph,
                    carrier.phi,
                    SemanticObligationKind::LoopCarriedState,
                    &mut required,
                );
                let carrier_storage = carrier_inst
                    .and_then(|inst| graph.inst(inst))
                    .and_then(|inst| graph.written_storage(inst));
                for update in &carrier.updates {
                    if let (Some(carrier_inst), Some(carrier)) = (carrier_inst, carrier_storage)
                        && update.site.inst == carrier_inst
                        && update.validate(graph)
                    {
                        let component = SemanticObligationComponent::LoopTransition {
                            carrier,
                            predecessor: update.predecessor,
                        };
                        seed_instruction_with_inputs(
                            carrier_inst,
                            SemanticObligationKind::LiveStateTransition,
                            component,
                            vec![update.value],
                            &mut required,
                            &mut explicit_inputs,
                            &mut duplicate_seeds,
                        );
                        explicit_edge_uses
                            .entry((
                                carrier_inst,
                                SemanticObligationKind::LiveStateTransition,
                                component,
                            ))
                            .or_insert(update.site);
                    } else if let Some(carrier_inst) = carrier_inst {
                        unsupported.insert(carrier_inst);
                        seed_instruction(
                            carrier_inst,
                            SemanticObligationKind::VolatileOrUnknownEffect,
                            SemanticObligationComponent::Whole,
                            &mut required,
                        );
                    }
                }
            }
        }
        propagate_live_dependencies(graph, &direct, &mut required);
        // A private read the walk reached owes its access; its inputs are already walked.
        for (inst, ordinal, address) in private_reads {
            if required.contains(inst) {
                seed_instruction_with_inputs(
                    inst,
                    SemanticObligationKind::LiveValueProducer,
                    SemanticObligationComponent::MemoryAccess(ordinal),
                    vec![address],
                    &mut required,
                    &mut explicit_inputs,
                    &mut duplicate_seeds,
                );
            }
        }
        for (inst, _, _) in duplicate_seeds {
            let block_addr = graph
                .inst(inst)
                .and_then(|inst| graph.block(inst.block))
                .map(|block| block.addr);
            construction_failures.push(ObligationInventoryFailure {
                inst,
                block_addr,
                kind: ObligationInventoryFailureKind::DuplicateObligationSeed,
            });
        }

        let mut inventory = Self::empty(graph.insts.len());
        inventory.construction_failures = construction_failures;
        inventory.unstructured_cycle_blocks = structured.unstructured_cycle_blocks.clone();
        // One obligation per seed at most: sized once, the table keeps no growth.
        let mut obligations = Vec::with_capacity(required.len());
        for inst in &graph.insts {
            let Some(id) = canonical_ids.get(inst.id).copied() else {
                continue;
            };
            let kinds = required.take(inst.id);
            if !kinds.is_empty()
                && inst
                    .output
                    .is_some_and(|output| graph.use_sites(output).is_empty())
            {
                r2il::refusal_evidence!(
                    "unread-live-definition",
                    "{:?} ({}) defines {:?}, which nothing reads, and owes {kinds:?}",
                    inst.id,
                    id.spelled(graph),
                    inst.output
                );
            }
            let state = if unsupported.contains(inst.id) {
                SemanticInstructionState::UnsupportedUnknown
            } else if !kinds.is_empty() {
                SemanticInstructionState::LiveObligation
            } else if instruction_is_structural(&inst.payload) {
                SemanticInstructionState::StructuralControlOnly
            } else {
                SemanticInstructionState::ProvenDead
            };
            for (kind, component) in kinds {
                let obligation_id = SemanticObligationId {
                    instruction: id,
                    kind,
                    component,
                };
                obligations.push(SemanticObligation {
                    id: obligation_id,
                    source: SemanticSourceSite::GraphInstruction(inst.id),
                    inputs: explicit_inputs
                        .remove(&(inst.id, kind, component))
                        .unwrap_or_else(|| graph.inputs(inst.id).to_vec()),
                    edge_use: explicit_edge_uses.remove(&(inst.id, kind, component)),
                });
            }
            inventory.instructions[inst.id.0 as usize] = Some(Owed {
                state,
                start: 0,
                len: 0,
            });
        }
        inventory.obligations = ObligationTable::of(obligations);
        inventory.index_runs();
        inventory.complete = inventory.derive_is_complete();
        inventory
    }

    /// Bind exact genuine native spans to this inventory. Zero-op spans are
    /// retained as explicit unsupported obligations without synthesizing an
    /// R2IL or SSA instruction. This is private to the genuine-lift boundary.
    pub(crate) fn bind_genuine_native_spans(
        &mut self,
        spans: impl IntoIterator<Item = crate::GenuineNativeInstructionSpan>,
        compiler_inserted_blocks: &BTreeSet<u64>,
    ) -> bool {
        // Merged into the sorted table once at the end: one insert per span shifts its tail each time.
        let mut late = Vec::new();
        for span in spans {
            let id = CanonicalInstructionId {
                block_addr: span.block_addr(),
                site: CanonicalInstructionSite::NativeSpan {
                    instruction_addr: span.instruction_addr(),
                    size: span.size(),
                },
            };
            if self.native_spans.insert(id, span).is_some() {
                return false;
            }
            // A span of a removed failure block keeps an obligation the rendering answers as compiler-inserted.
            let inserted = compiler_inserted_blocks.contains(&span.block_addr());
            if span.canonical_op_count() != 0 && !inserted {
                continue;
            }
            let (kind, state) = if span.canonical_op_count() == 0 {
                (
                    SemanticObligationKind::NoNativeSemantics,
                    SemanticInstructionState::UnsupportedUnknown,
                )
            } else {
                (
                    SemanticObligationKind::CompilerInserted,
                    SemanticInstructionState::CompilerInserted,
                )
            };
            let obligation_id = SemanticObligationId {
                instruction: id,
                kind,
                component: SemanticObligationComponent::Whole,
            };
            if self
                .span_instructions
                .insert(
                    id,
                    SemanticInstructionDisposition {
                        id,
                        source: SemanticSourceSite::GenuineNativeSpan,
                        state,
                    },
                )
                .is_some()
            {
                return false;
            }
            late.push(SemanticObligation {
                id: obligation_id,
                source: SemanticSourceSite::GenuineNativeSpan,
                inputs: Vec::new(),
                edge_use: None,
            });
        }
        if !self.obligations.extend_new(late) {
            return false;
        }
        self.index_runs();
        self.complete = self.derive_is_complete();
        true
    }

    /// What `inst` owes, with its identity read off the graph. A reader that needs only the
    /// state asks [`Self::state_of`].
    pub fn instruction_for_inst(
        &self,
        graph: &SsaGraph,
        inst: InstId,
    ) -> Option<SemanticInstructionDisposition> {
        let state = self.state_of(inst)?;
        let id = CanonicalInstructionId::of(graph, graph.inst(inst)?).ok()?;
        Some(SemanticInstructionDisposition {
            id,
            source: SemanticSourceSite::GraphInstruction(inst),
            state,
        })
    }

    /// The state of `inst`'s disposition. O(1).
    pub fn state_of(&self, inst: InstId) -> Option<SemanticInstructionState> {
        Some(self.owed(inst)?.state)
    }

    fn owed(&self, inst: InstId) -> Option<&Owed> {
        self.instructions.get(inst.0 as usize)?.as_ref()
    }

    /// Point each graph instruction at its run of the table, once the table is sorted. The
    /// runs of one instruction are adjacent; where one is not, its run is left empty and the
    /// inventory does not close (`derive_is_complete`).
    fn index_runs(&mut self) {
        for owed in self.instructions.iter_mut().flatten() {
            (owed.start, owed.len) = (0, 0);
        }
        self.split_runs = false;
        let mut at = 0;
        while at < self.obligations.0.len() {
            let SemanticSourceSite::GraphInstruction(inst) = self.obligations.0[at].source else {
                at += 1;
                continue;
            };
            let len = (self.obligations.0[at..].iter())
                .take_while(|obligation| {
                    obligation.source == SemanticSourceSite::GraphInstruction(inst)
                })
                .count();
            match self
                .instructions
                .get_mut(inst.0 as usize)
                .and_then(Option::as_mut)
            {
                Some(owed) if owed.len == 0 => {
                    (owed.start, owed.len) = (at as u32, len as u32);
                }
                _ => self.split_runs = true,
            }
            at += len;
        }
    }

    /// How many graph instructions have a disposition.
    fn graph_instruction_count(&self) -> usize {
        self.instructions.iter().flatten().count()
    }

    /// Values whose exact source instruction is structural, owns no semantic
    /// obligation, and that the program never reads.
    ///
    /// This is the upstream elision authority for structural outputs such as
    /// unused call-clobber definitions. Consumers must not reclassify an op by
    /// matching its spelling or opcode. A used structural result is omitted
    /// from this set and remains an ordinary value that needs a binding.
    ///
    /// A use site is not the same thing as a read. A call clobbers a
    /// caller-saved register, the clobber reaches a merge, and the merge is one
    /// the program never observes: the graph records a use, and nothing reads
    /// the value. `murmur3_32` at -O0 is that case -- the call to `rotl32`
    /// clobbers `RCX`, the clobber flows into an unobserved phi, and asking the
    /// graph alone made the clobber an ordinary value owing a binding that no
    /// statement could ever assign, because what a clobbered register holds is
    /// not knowable and no C expression says it. So the reads are counted
    /// against the same dead-merge authority the rest of the model uses, and
    /// `unobserved_uses` is what says which occurrences are not reads.
    pub fn structural_unused_values(
        &self,
        graph: &SsaGraph,
        unobserved_uses: &BTreeSet<crate::UseSite>,
    ) -> Option<crate::dense::IdSet<ValueId>> {
        if !self.is_complete()
            || self.source_instruction_count != graph.insts.len()
            || self.graph_instruction_count() != graph.insts.len()
        {
            return None;
        }
        let mut values = crate::dense::IdSet::default();
        for graph_inst in &graph.insts {
            let Some(owed) = self.owed(graph_inst.id) else {
                continue;
            };
            if owed.state != SemanticInstructionState::StructuralControlOnly || owed.len != 0 {
                continue;
            }
            let Some(value) = graph_inst.output else {
                continue;
            };
            if graph.def_inst(value) != Some(graph_inst.id) || graph.value(value).is_none() {
                return None;
            }
            if graph
                .use_sites(value)
                .iter()
                .all(|site| unobserved_uses.contains(site))
            {
                values.insert(value);
            }
        }
        Some(values)
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn source_instruction_count(&self) -> usize {
        self.source_instruction_count
    }

    /// Every instruction's disposition: the graph's, then the native spans
    /// that produced no canonical operation.
    pub fn dispositions<'a>(
        &'a self,
        graph: &'a SsaGraph,
    ) -> impl Iterator<Item = SemanticInstructionDisposition> + 'a {
        (0..self.instructions.len())
            .filter_map(move |index| self.instruction_for_inst(graph, InstId(index as u32)))
            .chain(self.span_instructions.values().copied())
    }

    /// The disposition with this exact identity, by search.
    ///
    /// For fixtures. The runtime asks by graph instruction, which is an index.
    #[cfg(test)]
    pub(crate) fn disposition_with_id(
        &self,
        graph: &SsaGraph,
        id: CanonicalInstructionId,
    ) -> Option<SemanticInstructionDisposition> {
        self.dispositions(graph)
            .find(|disposition| disposition.id == id)
    }

    /// How many instructions the inventory dispositioned.
    fn disposition_count(&self) -> usize {
        self.instructions.iter().flatten().count() + self.span_instructions.len()
    }

    /// Exact source-derived native spans bound at the genuine-lift boundary.
    pub fn native_spans(
        &self,
    ) -> &BTreeMap<CanonicalInstructionId, crate::GenuineNativeInstructionSpan> {
        &self.native_spans
    }

    pub fn obligations(&self) -> &ObligationTable {
        &self.obligations
    }

    /// What the inventory holds, for the byte fit.
    pub fn probe_shape(&self) -> String {
        let obligation_inputs: usize = self.obligations.values().map(|o| o.inputs.len()).sum();
        let owned = (self.instructions.iter().flatten())
            .map(|owed| owed.len as usize)
            .sum::<usize>()
            + (self.span_instructions.values())
                .map(|d| self.owned(d).count())
                .sum::<usize>();
        format!(
            "instructions {} obligations {} by_inst {} native_spans {} inputs {} owned {} sizeof(id) {} sizeof(obligation) {} sizeof(disposition) {} sizeof(instid) {} sizeof(span) {}",
            self.disposition_count(),
            self.obligations.len(),
            self.graph_instruction_count(),
            self.native_spans.len(),
            obligation_inputs,
            owned,
            std::mem::size_of::<SemanticObligationId>(),
            std::mem::size_of::<SemanticObligation>(),
            std::mem::size_of::<Option<Owed>>(),
            std::mem::size_of::<CanonicalInstructionId>(),
            std::mem::size_of::<crate::GenuineNativeInstructionSpan>(),
        )
    }

    pub fn construction_failures(&self) -> &[ObligationInventoryFailure] {
        &self.construction_failures
    }

    pub fn unstructured_cycle_blocks(&self) -> &BTreeSet<u64> {
        &self.unstructured_cycle_blocks
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    fn derive_is_complete(&self) -> bool {
        let zero_op_span_count = self
            .native_spans
            .values()
            .filter(|span| span.canonical_op_count() == 0)
            .count()
            + self
                .span_instructions
                .values()
                .filter(|disposition| {
                    disposition.state == SemanticInstructionState::CompilerInserted
                })
                .count();
        if self.schema_version != SEMANTIC_OBLIGATION_SCHEMA_VERSION
            || !self.construction_failures.is_empty()
            || self.disposition_count() != self.source_instruction_count + zero_op_span_count
            || self.graph_instruction_count() != self.source_instruction_count
            || self.split_runs
        {
            // An incomplete inventory refuses the function at the binding
            // plan, and until now it said only that. Which of the six
            // conditions failed is the whole difference between a lifter gap,
            // an unstructured cycle and a seeding defect.
            r2il::refusal_evidence!(
                "obligation-inventory",
                "incomplete: schema={} failures={:?} unstructured_cycles={:?} \
                 instructions={} sources={} zero_op_spans={} by_inst={} split_runs={}",
                self.schema_version,
                self.construction_failures,
                self.unstructured_cycle_blocks,
                self.disposition_count(),
                self.source_instruction_count,
                zero_op_span_count,
                self.graph_instruction_count(),
                self.split_runs
            );
            return false;
        }
        let owes = |state| {
            matches!(
                state,
                SemanticInstructionState::LiveObligation
                    | SemanticInstructionState::UnsupportedUnknown
                    | SemanticInstructionState::CompilerInserted
            )
        };
        // A graph instruction owes exactly where its run is not empty.
        if (self.instructions.iter().flatten()).any(|owed| owes(owed.state) != (owed.len != 0)) {
            return false;
        }
        let owing_spans = (self.obligations.values())
            .filter(|obligation| obligation.source == SemanticSourceSite::GenuineNativeSpan)
            .map(|obligation| obligation.id.instruction)
            .collect::<BTreeSet<_>>();
        for (id, instruction) in &self.span_instructions {
            if instruction.id != *id
                || instruction.source != SemanticSourceSite::GenuineNativeSpan
                || self.native_spans.get(id).is_none_or(|span| {
                    (span.canonical_op_count() != 0)
                        != (instruction.state == SemanticInstructionState::CompilerInserted)
                        || id.block_addr != span.block_addr()
                        || !matches!(
                            id.site,
                            CanonicalInstructionSite::NativeSpan {
                                instruction_addr,
                                size,
                            } if instruction_addr == span.instruction_addr()
                                && size == span.size()
                        )
                })
                || owes(instruction.state) != owing_spans.contains(id)
            {
                return false;
            }
        }
        for (id, obligation) in &self.obligations {
            if match obligation.source {
                SemanticSourceSite::GraphInstruction(inst) => self.owed(inst).is_none(),
                SemanticSourceSite::GenuineNativeSpan => {
                    !self.span_instructions.contains_key(&id.instruction)
                }
            } || match (id.kind, id.component, obligation.source) {
                (
                    SemanticObligationKind::LiveStateTransition,
                    SemanticObligationComponent::LoopTransition { .. },
                    SemanticSourceSite::GraphInstruction(inst),
                ) => obligation.edge_use.is_none_or(|site| site.inst != inst),
                _ => obligation.edge_use.is_some(),
            } {
                return false;
            }
        }
        for (id, span) in &self.native_spans {
            if id.block_addr != span.block_addr()
                || !matches!(
                    id.site,
                    CanonicalInstructionSite::NativeSpan {
                        instruction_addr,
                        size,
                    } if instruction_addr == span.instruction_addr() && size == span.size()
                )
                || (span.canonical_op_count() == 0)
                    != self.span_instructions.get(id).is_some_and(|disposition| {
                        disposition.state != SemanticInstructionState::CompilerInserted
                    })
            {
                return false;
            }
        }
        true
    }

    /// What `inst` owes: its run of the table. O(1).
    pub fn obligations_for_inst(&self, inst: InstId) -> impl Iterator<Item = &SemanticObligation> {
        self.owed(inst)
            .map_or(&[][..], |owed| self.run_of(owed))
            .iter()
    }

    fn run_of(&self, owed: &Owed) -> &[SemanticObligation] {
        &self.obligations.0[owed.start as usize..(owed.start + owed.len) as usize]
    }

    /// What one disposition owes: a graph instruction's run, or a native span's by its identity.
    pub fn owned<'a>(
        &'a self,
        disposition: &SemanticInstructionDisposition,
    ) -> impl Iterator<Item = &'a SemanticObligation> + 'a {
        let source = disposition.source;
        let run = match source {
            SemanticSourceSite::GraphInstruction(inst) => {
                self.owed(inst).map_or(&[][..], |owed| self.run_of(owed))
            }
            SemanticSourceSite::GenuineNativeSpan => self.obligations.run(&disposition.id),
        };
        run.iter()
            .filter(move |obligation| obligation.source == source)
    }
}

fn boundary_component(slot: crate::semantic::CallBoundarySlot) -> SemanticObligationComponent {
    match slot {
        crate::semantic::CallBoundarySlot::Register { index, storage } => {
            SemanticObligationComponent::RegisterSlot { index, storage }
        }
        crate::semantic::CallBoundarySlot::Stack(offset) => {
            SemanticObligationComponent::StackOffset(offset)
        }
    }
}

fn collect_canonical_instruction_ids(
    graph: &SsaGraph,
) -> (
    crate::dense::IdMap<InstId, CanonicalInstructionId>,
    Vec<ObligationInventoryFailure>,
) {
    let mut ids = crate::dense::IdMap::new(graph.insts.len());
    let mut owners = BTreeMap::<CanonicalInstructionId, InstId>::new();
    let mut failures = Vec::new();
    for inst in &graph.insts {
        let id = match CanonicalInstructionId::of(graph, inst) {
            Ok(id) => id,
            Err(failure) => {
                failures.push(failure);
                continue;
            }
        };
        let block_addr = id.block_addr;
        if owners.insert(id, inst.id).is_some() {
            failures.push(ObligationInventoryFailure {
                inst: inst.id,
                block_addr: Some(block_addr),
                kind: ObligationInventoryFailureKind::DuplicateCanonicalInstruction,
            });
            continue;
        }
        ids.insert(inst.id, id);
    }
    (ids, failures)
}

/// What each instruction owes before the inventory is built: a bit per kind owed of the whole
/// instruction, and the few partial components sorted (doc/adr-memory-model.md, MM.10).
struct ObligationSeeds {
    whole: crate::dense::IdVec<InstId, u32>,
    parts: crate::dense::IdMap<InstId, Vec<(SemanticObligationKind, SemanticObligationComponent)>>,
}

impl ObligationSeeds {
    fn new(instructions: usize) -> Self {
        Self {
            whole: crate::dense::IdVec::filled(instructions, 0),
            parts: crate::dense::IdMap::default(),
        }
    }

    fn insert(
        &mut self,
        inst: InstId,
        kind: SemanticObligationKind,
        component: SemanticObligationComponent,
    ) {
        // A kind past `ALL` would be dropped by `take`.
        debug_assert_eq!(SemanticObligationKind::ALL.get(kind as usize), Some(&kind));
        if component == SemanticObligationComponent::Whole {
            self.whole[inst] |= 1 << kind as u32;
            return;
        }
        let parts = self.parts.get_or_insert_with(inst, Vec::new);
        if let Err(at) = parts.binary_search(&(kind, component)) {
            parts.insert(at, (kind, component));
        }
    }

    fn contains(&self, inst: InstId) -> bool {
        self.whole[inst] != 0 || self.parts.contains(inst)
    }

    /// How many (instruction, kind, component) seeds are held.
    fn len(&self) -> usize {
        let whole = self
            .whole
            .iter()
            .map(|(_, bits)| bits.count_ones() as usize);
        whole.sum::<usize>() + self.parts.values().map(Vec::len).sum::<usize>()
    }

    /// The seeded instructions, in id order.
    fn keys(&self) -> impl Iterator<Item = InstId> + '_ {
        (self.whole.iter()).filter_map(|(inst, _)| self.contains(inst).then_some(inst))
    }

    /// What `inst` owes, in (kind, component) order: `Whole` sorts first among a kind's components.
    fn take(&mut self, inst: InstId) -> Vec<(SemanticObligationKind, SemanticObligationComponent)> {
        let whole = std::mem::take(&mut self.whole[inst]);
        let mut parts = self
            .parts
            .remove(inst)
            .unwrap_or_default()
            .into_iter()
            .peekable();
        let mut owed = Vec::new();
        for kind in SemanticObligationKind::ALL {
            if whole & (1 << kind as u32) != 0 {
                owed.push((kind, SemanticObligationComponent::Whole));
            }
            while let Some(part) = parts.next_if(|(at, _)| *at == kind) {
                owed.push(part);
            }
        }
        owed
    }
}

/// Every definition that may reach a return whose interface is unproven: none can be proven dead.
///
/// One backward walk from all of them, `O(B + E + I)` (doc/adr-memory-model.md, MM.10): a block
/// reached through an edge keeps every definition, a return's own block those before its last.
fn taint_incomplete_boundary_inputs(
    graph: &SsaGraph,
    returns: &[InstId],
    required: &mut ObligationSeeds,
    unsupported: &mut crate::dense::IdSet<InstId>,
) {
    let mut last = crate::dense::IdMap::<crate::graph::BlockId, usize>::default();
    for inst in returns.iter().filter_map(|inst| graph.inst(*inst)) {
        let at = last.get_or_insert_with(inst.block, || inst.ordinal);
        *at = (*at).max(inst.ordinal);
    }
    let mut reaching = crate::dense::IdSet::default();
    let mut ready = (last.keys().filter_map(|block| graph.block(block)))
        .flat_map(|block| block.predecessors.iter().copied())
        .collect::<Vec<_>>();
    while let Some(block) = ready.pop() {
        if reaching.insert(block)
            && let Some(block) = graph.block(block)
        {
            ready.extend(block.predecessors.iter().copied());
        }
    }
    for candidate in &graph.insts {
        let kept = reaching.contains(candidate.block)
            || last
                .get(candidate.block)
                .is_some_and(|last| candidate.ordinal < *last);
        if candidate.output.is_none() || !kept {
            continue;
        }
        unsupported.insert(candidate.id);
        seed_instruction(
            candidate.id,
            SemanticObligationKind::VolatileOrUnknownEffect,
            SemanticObligationComponent::Whole,
            required,
        );
    }
}

fn seed_direct_obligations(
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
    op: &SSAOp<crate::graph::ValueId>,
    required: &mut ObligationSeeds,
    explicit_inputs: &mut BTreeMap<
        (InstId, SemanticObligationKind, SemanticObligationComponent),
        Vec<ValueId>,
    >,
    duplicate_seeds: &mut BTreeSet<(InstId, SemanticObligationKind, SemanticObligationComponent)>,
    unsupported: &mut crate::dense::IdSet<InstId>,
) {
    use SemanticObligationComponent as Component;
    use SemanticObligationKind as Kind;

    match op {
        SSAOp::Load { .. } | SSAOp::Store { .. } => {}
        // A block operation is not a structured access, so it owns what it reads and writes over its extent.
        SSAOp::BlockTransfer(transfer) => {
            if transfer.kind.writes_memory() {
                seed_instruction(
                    inst.id,
                    Kind::ObservableMemoryWrite,
                    Component::Whole,
                    required,
                );
            }
            if transfer.kind.reads_memory() {
                seed_instruction(
                    inst.id,
                    Kind::ObservableMemoryRead,
                    Component::Whole,
                    required,
                );
            }
        }
        SSAOp::Fence { ordering } => seed_instruction(
            inst.id,
            Kind::MemoryOrdering,
            Component::MemoryOrdering((*ordering).into()),
            required,
        ),
        SSAOp::LoadLinked { ordering, .. } | SSAOp::LoadGuarded { ordering, .. } => {
            seed_instruction(
                inst.id,
                Kind::MemoryOrdering,
                Component::MemoryOrdering((*ordering).into()),
                required,
            );
            if matches!(op, SSAOp::LoadLinked { .. }) {
                seed_instruction(inst.id, Kind::Atomicity, Component::Whole, required);
            } else if let Some(guard) = graph.inputs(inst.id).last().copied() {
                seed_instruction_with_inputs(
                    inst.id,
                    Kind::ControlPredicate,
                    Component::PredicateOperand,
                    vec![guard],
                    required,
                    explicit_inputs,
                    duplicate_seeds,
                );
            }
        }
        SSAOp::StoreConditional { ordering, .. } | SSAOp::StoreGuarded { ordering, .. } => {
            seed_instruction(
                inst.id,
                Kind::MemoryOrdering,
                Component::MemoryOrdering((*ordering).into()),
                required,
            );
            if matches!(op, SSAOp::StoreConditional { .. }) {
                seed_instruction(inst.id, Kind::Atomicity, Component::Whole, required);
            } else if let Some(guard) = graph.inputs(inst.id).last().copied() {
                seed_instruction_with_inputs(
                    inst.id,
                    Kind::ControlPredicate,
                    Component::PredicateOperand,
                    vec![guard],
                    required,
                    explicit_inputs,
                    duplicate_seeds,
                );
            }
        }
        SSAOp::AtomicCAS(swap) => {
            seed_instruction(inst.id, Kind::Atomicity, Component::Whole, required);
            seed_instruction(
                inst.id,
                Kind::MemoryOrdering,
                Component::MemoryOrdering(swap.ordering.into()),
                required,
            );
        }
        SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
            seed_instruction(inst.id, Kind::Call, Component::Whole, required);
        }
        SSAOp::Return { .. } => seed_instruction(inst.id, Kind::Return, Component::Whole, required),
        SSAOp::CBranch { .. } | SSAOp::Switch { .. } => {
            let predicate = graph.inputs(inst.id).last().copied().into_iter().collect();
            seed_instruction_with_inputs(
                inst.id,
                Kind::ControlPredicate,
                Component::Whole,
                predicate,
                required,
                explicit_inputs,
                duplicate_seeds,
            );
            seed_instruction(inst.id, Kind::ControlTransfer, Component::Whole, required);
        }
        SSAOp::Branch { .. } | SSAOp::BranchInd { .. } => {
            seed_instruction(inst.id, Kind::ControlTransfer, Component::Whole, required);
        }
        SSAOp::IntDiv { .. }
        | SSAOp::IntSDiv { .. }
        | SSAOp::IntRem { .. }
        | SSAOp::IntSRem { .. } => {
            seed_instruction(inst.id, Kind::Trap, Component::Whole, required)
        }
        SSAOp::Breakpoint => seed_instruction(inst.id, Kind::Trap, Component::Whole, required),
        SSAOp::CallOther { .. }
        | SSAOp::Unimplemented
        | SSAOp::CpuId { .. }
        | SSAOp::New { .. } => {
            unsupported.insert(inst.id);
            seed_instruction(
                inst.id,
                Kind::VolatileOrUnknownEffect,
                Component::Whole,
                required,
            );
        }
        SSAOp::Phi { .. }
        | SSAOp::Copy { .. }
        | SSAOp::IntAdd { .. }
        | SSAOp::IntSub { .. }
        | SSAOp::IntMult { .. }
        | SSAOp::IntNegate { .. }
        | SSAOp::IntCarry { .. }
        | SSAOp::IntSCarry { .. }
        | SSAOp::IntSBorrow { .. }
        | SSAOp::IntAnd { .. }
        | SSAOp::IntOr { .. }
        | SSAOp::IntXor { .. }
        | SSAOp::IntNot { .. }
        | SSAOp::IntLeft { .. }
        | SSAOp::IntRight { .. }
        | SSAOp::IntSRight { .. }
        | SSAOp::IntEqual { .. }
        | SSAOp::IntNotEqual { .. }
        | SSAOp::IntLess { .. }
        | SSAOp::IntSLess { .. }
        | SSAOp::IntLessEqual { .. }
        | SSAOp::IntSLessEqual { .. }
        | SSAOp::IntZExt { .. }
        | SSAOp::IntSExt { .. }
        | SSAOp::BoolNot { .. }
        | SSAOp::BoolAnd { .. }
        | SSAOp::BoolOr { .. }
        | SSAOp::BoolXor { .. }
        | SSAOp::Piece { .. }
        | SSAOp::Subpiece { .. }
        | SSAOp::PopCount { .. }
        | SSAOp::Lzcount { .. }
        | SSAOp::FloatAdd { .. }
        | SSAOp::FloatSub { .. }
        | SSAOp::FloatMult { .. }
        | SSAOp::FloatDiv { .. }
        | SSAOp::FloatNeg { .. }
        | SSAOp::FloatAbs { .. }
        | SSAOp::FloatSqrt { .. }
        | SSAOp::FloatCeil { .. }
        | SSAOp::FloatFloor { .. }
        | SSAOp::FloatRound { .. }
        | SSAOp::FloatNaN { .. }
        | SSAOp::FloatEqual { .. }
        | SSAOp::FloatNotEqual { .. }
        | SSAOp::FloatLess { .. }
        | SSAOp::FloatLessEqual { .. }
        | SSAOp::Int2Float { .. }
        | SSAOp::Float2Int { .. }
        | SSAOp::FloatFloat { .. }
        | SSAOp::Trunc { .. }
        | SSAOp::CallDefine { .. }
        | SSAOp::CallRestore { .. }
        | SSAOp::CallUse { .. }
        | SSAOp::Nop
        | SSAOp::PtrAdd { .. }
        | SSAOp::PtrSub { .. }
        | SSAOp::SegmentOp { .. }
        | SSAOp::Cast { .. }
        | SSAOp::Extract { .. }
        | SSAOp::Insert { .. }
        | SSAOp::Select { .. } => {}
    }
    if matches!(
        op,
        SSAOp::Fence {
            ordering: r2il::MemoryOrdering::Unknown
        } | SSAOp::LoadLinked {
            ordering: r2il::MemoryOrdering::Unknown,
            ..
        } | SSAOp::StoreConditional {
            ordering: r2il::MemoryOrdering::Unknown,
            ..
        } | SSAOp::LoadGuarded {
            ordering: r2il::MemoryOrdering::Unknown,
            ..
        } | SSAOp::StoreGuarded {
            ordering: r2il::MemoryOrdering::Unknown,
            ..
        }
    ) {
        unsupported.insert(inst.id);
    }
}

fn seed_instruction(
    inst: InstId,
    kind: SemanticObligationKind,
    component: SemanticObligationComponent,
    required: &mut ObligationSeeds,
) {
    required.insert(inst, kind, component);
}

fn seed_instruction_with_inputs(
    inst: InstId,
    kind: SemanticObligationKind,
    component: SemanticObligationComponent,
    inputs: Vec<ValueId>,
    required: &mut ObligationSeeds,
    explicit_inputs: &mut BTreeMap<
        (InstId, SemanticObligationKind, SemanticObligationComponent),
        Vec<ValueId>,
    >,
    duplicate_seeds: &mut BTreeSet<(InstId, SemanticObligationKind, SemanticObligationComponent)>,
) {
    seed_instruction(inst, kind, component, required);
    let identity = (inst, kind, component);
    if let std::collections::btree_map::Entry::Vacant(entry) = explicit_inputs.entry(identity) {
        entry.insert(inputs);
    } else {
        duplicate_seeds.insert(identity);
    }
}

fn seed_value_definition(
    graph: &SsaGraph,
    value: ValueId,
    kind: SemanticObligationKind,
    required: &mut ObligationSeeds,
) {
    if let Some(inst) = graph.def_inst(value) {
        seed_instruction(inst, kind, SemanticObligationComponent::Whole, required);
    }
}

fn propagate_live_dependencies(
    graph: &SsaGraph,
    direct: &crate::dense::IdSet<InstId>,
    required: &mut ObligationSeeds,
) {
    let mut ready = required.keys().collect::<VecDeque<_>>();
    let mut visited = crate::dense::IdSet::default();
    while let Some(inst_id) = ready.pop_front() {
        if !visited.insert(inst_id) {
            continue;
        }
        let Some(inst) = graph.inst(inst_id).filter(|_| !direct.contains(inst_id)) else {
            continue;
        };
        for input in graph.inputs(inst.id) {
            let Some(definition) = graph.def_inst(*input) else {
                continue;
            };
            let was_live = required.contains(definition);
            seed_instruction(
                definition,
                SemanticObligationKind::LiveValueProducer,
                SemanticObligationComponent::Whole,
                required,
            );
            if !was_live {
                ready.push_back(definition);
            }
        }
    }
}

fn instruction_is_structural(payload: &InstPayload) -> bool {
    matches!(
        payload,
        InstPayload::Op(
            SSAOp::Nop
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. }
                | SSAOp::CallUse { .. }
        )
    )
}

#[cfg(test)]
mod tests {
    /// The seeds yield what an ordered set of (kind, component) would, each once.
    #[test]
    fn seeds_yield_each_obligation_once_in_order() {
        use super::{SemanticObligationComponent as Component, SemanticObligationKind as Kind};
        assert!(
            Kind::ALL
                .iter()
                .enumerate()
                .all(|(at, kind)| *kind as usize == at)
        );
        assert!(Kind::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        let inst = crate::InstId(1);
        let mut seeds = super::ObligationSeeds::new(2);
        let mut ordered = std::collections::BTreeSet::new();
        for seed in [
            (Kind::LiveValueProducer, Component::Whole),
            (Kind::ReturnValue, Component::Index(2)),
            (Kind::ReturnValue, Component::Whole),
            (Kind::Call, Component::MemoryAccess(0)),
            (Kind::ReturnValue, Component::Index(2)),
            (Kind::Call, Component::Whole),
        ] {
            seeds.insert(inst, seed.0, seed.1);
            ordered.insert(seed);
        }
        assert!(seeds.contains(inst) && !seeds.contains(crate::InstId(0)));
        assert_eq!(seeds.keys().collect::<Vec<_>>(), [inst]);
        assert_eq!(seeds.take(inst), ordered.into_iter().collect::<Vec<_>>());
        assert!(!seeds.contains(inst));
    }

    #[test]
    fn late_obligations_merge_into_the_table_in_order_or_not_at_all() {
        let obligation = |block_addr: u64| super::SemanticObligation {
            id: super::SemanticObligationId {
                instruction: super::CanonicalInstructionId {
                    block_addr,
                    site: super::CanonicalInstructionSite::NativeSpan {
                        instruction_addr: block_addr,
                        size: 1,
                    },
                },
                kind: super::SemanticObligationKind::NoNativeSemantics,
                component: super::SemanticObligationComponent::Whole,
            },
            source: super::SemanticSourceSite::GraphInstruction(crate::InstId(0)),
            inputs: Vec::new(),
            edge_use: None,
        };
        let mut table = super::ObligationTable::of(vec![obligation(0x10), obligation(0x30)]);
        assert!(table.extend_new(vec![obligation(0x40), obligation(0x20), obligation(0x00)]));
        let order = table
            .keys()
            .map(|id| id.instruction.block_addr)
            .collect::<Vec<_>>();
        assert_eq!(order, [0x00, 0x10, 0x20, 0x30, 0x40]);
        // A repeated identity leaves the table as it was.
        assert!(!table.extend_new(vec![obligation(0x50), obligation(0x20)]));
        assert!(!table.extend_new(vec![obligation(0x60), obligation(0x60)]));
        assert_eq!(table.len(), 5);
    }

    /// The canonical identity of operation `index` of the block at
    /// `block_addr`, as a fixture names it.
    fn operation_at(
        artifact: &crate::SsaArtifact,
        block_addr: u64,
        index: usize,
    ) -> super::CanonicalInstructionId {
        super::CanonicalInstructionId {
            block_addr,
            site: super::CanonicalInstructionSite::Op(
                artifact
                    .named_block(block_addr)
                    .and_then(|block| block.op_id(index))
                    .expect("the fixture's operation"),
            ),
        }
    }
    use super::*;
    use crate::{
        CallBoundarySlot, CanonicalStorageId, CanonicalStorageSpace, SourceAbiParameterSpec,
        SourceCallArgumentSpec, SourceCallResult, SourceCallSiteIdentity, SourceCallSiteInterface,
        SourceFunctionInterface, SourceFunctionReturn, SsaArtifact,
    };
    use proptest::prelude::*;
    use r2il::{ArchSpec, MemoryOrdering, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    /// `jle next` where `next` is the fallthrough: a direct transfer owing no predicate, so the
    /// comparison feeding it is not live.
    #[test]
    fn a_branch_whose_arms_meet_owes_its_transfer_and_not_its_predicate() {
        let mut entry = R2ILBlock::new(0x1000, 4);
        let test = Varnode::unique(0x10, 1);
        entry.push(R2ILOp::IntSLessEqual {
            dst: test.clone(),
            a: Varnode::register(0, 4),
            b: Varnode::constant(5, 4),
        });
        entry.push(R2ILOp::CBranch {
            target: Varnode::ram(0x1004, 8),
            cond: test,
        });
        let mut next = R2ILBlock::new(0x1004, 4);
        next.push(R2ILOp::Return {
            target: Varnode::register(8, 8),
        });
        let artifact = SsaArtifact::raw(&[entry, next], None).expect("SSA artifact");
        let graph = artifact.graph();
        let inventory = &artifact.facts().obligations;
        let kinds = |ordinal| {
            let inst = graph
                .inst_spelled_at(0x1000, ordinal)
                .expect("an operation");
            (inventory.obligations_for_inst(inst))
                .map(|o| o.id.kind)
                .collect::<Vec<_>>()
        };
        assert_eq!(kinds(1), [SemanticObligationKind::ControlTransfer]);
        let producer = kinds(0);
        assert!(
            !producer.contains(&SemanticObligationKind::LiveValueProducer),
            "{producer:?}"
        );
        // The transfer reads nothing: no root reaches the condition (native.rs checks DeadPhis).
        let branch = graph.inst_spelled_at(0x1000, 1).expect("the branch");
        let transfer = inventory
            .obligations_for_inst(branch)
            .next()
            .expect("its transfer");
        assert!(transfer.inputs.is_empty(), "{transfer:?}");
    }

    #[test]
    fn only_independent_semantic_obligations_are_positive_observation_roots() {
        for kind in [
            SemanticObligationKind::ObservableMemoryRead,
            SemanticObligationKind::ObservableMemoryWrite,
            SemanticObligationKind::Call,
            SemanticObligationKind::CallArgument,
            SemanticObligationKind::CallResult,
            SemanticObligationKind::Return,
            SemanticObligationKind::ReturnValue,
            SemanticObligationKind::ControlPredicate,
            SemanticObligationKind::ControlTransfer,
            SemanticObligationKind::Trap,
            SemanticObligationKind::Atomicity,
            SemanticObligationKind::MemoryOrdering,
        ] {
            assert!(kind.is_positive_observation_root(), "{kind:?}");
        }
        for kind in [
            SemanticObligationKind::VolatileOrUnknownEffect,
            SemanticObligationKind::LoopCarriedState,
            SemanticObligationKind::LiveStateTransition,
            SemanticObligationKind::LiveValueProducer,
        ] {
            assert!(!kind.is_positive_observation_root(), "{kind:?}");
        }
    }

    fn obligation_fixture() -> Vec<R2ILBlock> {
        let mut entry = R2ILBlock::new(0x1000, 4);
        let addr = Varnode::register(0, 8);
        let loaded = Varnode::unique(0x10, 4);
        let dead = Varnode::unique(0x20, 4);
        entry.push(R2ILOp::Load {
            dst: loaded.clone(),
            space: SpaceId::Ram,
            addr: addr.clone(),
        });
        entry.push(R2ILOp::IntAdd {
            dst: dead,
            a: Varnode::constant(1, 4),
            b: Varnode::constant(2, 4),
        });
        entry.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val: loaded,
        });
        entry.push(R2ILOp::Return {
            target: Varnode::register(8, 8),
        });
        vec![entry]
    }

    // Storing back what was loaded is a certified round trip that owes no
    // write of its own, so a test about a write stores a value of its own.
    fn observable_write_fixture() -> Vec<R2ILBlock> {
        let mut entry = R2ILBlock::new(0x1000, 4);
        let addr = Varnode::register(0, 8);
        let sum = Varnode::unique(0x20, 4);
        entry.push(R2ILOp::IntAdd {
            dst: sum.clone(),
            a: Varnode::constant(1, 4),
            b: Varnode::constant(2, 4),
        });
        entry.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val: sum,
        });
        entry.push(R2ILOp::Return {
            target: Varnode::register(8, 8),
        });
        vec![entry]
    }

    fn loop_carrier_fixture() -> Vec<R2ILBlock> {
        let accumulator = Varnode::register(0, 8);
        let mut entry = R2ILBlock::new(0x2000, 4);
        entry.push(R2ILOp::Copy {
            dst: accumulator.clone(),
            src: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::ram(0x2010, 8),
        });

        let mut header = R2ILBlock::new(0x2010, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x2020, 8),
            cond: Varnode::constant(1, 1),
        });

        let mut exit = R2ILBlock::new(0x2014, 4);
        exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });

        let mut latch = R2ILBlock::new(0x2020, 4);
        latch.push(R2ILOp::IntAdd {
            dst: accumulator.clone(),
            a: accumulator,
            b: Varnode::constant(1, 8),
        });
        latch.push(R2ILOp::Branch {
            target: Varnode::ram(0x2010, 8),
        });

        vec![entry, header, exit, latch]
    }

    fn irreducible_cycle_fixture() -> Vec<R2ILBlock> {
        let mut entry = R2ILBlock::new(0x8000, 4);
        entry.push(R2ILOp::CBranch {
            target: Varnode::ram(0x8010, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut left = R2ILBlock::new(0x8004, 4);
        left.push(R2ILOp::Branch {
            target: Varnode::ram(0x8020, 8),
        });
        let mut right = R2ILBlock::new(0x8010, 4);
        right.push(R2ILOp::Branch {
            target: Varnode::ram(0x8020, 8),
        });
        let mut split = R2ILBlock::new(0x8020, 4);
        split.push(R2ILOp::CBranch {
            target: Varnode::ram(0x8010, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut back = R2ILBlock::new(0x8024, 4);
        back.push(R2ILOp::Branch {
            target: Varnode::ram(0x8004, 8),
        });
        vec![entry, left, right, split, back]
    }

    fn x86_64_call_arch() -> crate::Arch {
        crate::Arch::new(x86_64_call_arch_spec())
    }

    fn x86_64_call_arch_spec() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("rdi", 8, 8));
        arch.add_register(RegisterDef::new("rsi", 16, 8));
        arch.add_register(RegisterDef::new("rip", 24, 8));
        arch.add_register(RegisterDef::new("rdx", 32, 8));
        arch.add_register(RegisterDef::new("rcx", 40, 8));
        arch.add_register(RegisterDef::new("r8", 48, 8));
        arch.add_register(RegisterDef::new("r9", 56, 8));
        arch
    }

    /// The call arch's call effect: argument and result registers clobbered, the program counter preserved.
    fn x86_64_call_effect() -> Option<crate::SourceCallEffect> {
        crate::testing::call_effect(
            [0, 8, 16, 32, 40, 48, 56].map(|offset| register_storage(offset, 8)),
            [register_storage(24, 8)],
        )
    }

    fn register_storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    /// Name the transfer at `op_index` of `block` as lifted from instruction
    /// `block.addr + op_index`, and return the identity that names it.
    fn direct_call_identity(
        block: &mut R2ILBlock,
        op_index: usize,
        target: &Varnode,
    ) -> SourceCallSiteIdentity {
        let instruction = block.addr + op_index as u64;
        block.stamp_instruction(op_index, instruction);
        SourceCallSiteIdentity::new(instruction, CanonicalStorageId::from_varnode(target))
    }

    fn call_interface(
        revision: &[u8],
        identity: SourceCallSiteIdentity,
        complete: bool,
        arguments: impl IntoIterator<Item = SourceCallArgumentSpec>,
        variadic: bool,
        noreturn: bool,
        result: SourceCallResult,
    ) -> SourceCallSiteInterface {
        SourceCallSiteInterface::new(
            revision.to_vec(),
            identity,
            complete,
            "test-call-abi",
            arguments,
            variadic,
            noreturn,
            result,
        )
        .expect("valid callsite interface")
    }

    #[test]
    fn inventory_classifies_every_canonical_instruction_once() {
        let artifact = SsaArtifact::raw(&obligation_fixture(), None).expect("SSA artifact");
        let inventory = &artifact.facts().obligations;
        assert_eq!(inventory.disposition_count(), artifact.graph().insts.len());
        assert_eq!(
            inventory.graph_instruction_count(),
            artifact.graph().insts.len()
        );
        assert!(inventory.dispositions(artifact.graph()).all(|instruction| {
            instruction.state != SemanticInstructionState::LiveObligation
                || inventory.owned(&instruction).next().is_some()
        }));
        assert!(inventory.is_complete());
    }

    #[test]
    fn obligation_ids_are_stable_across_deterministic_reconstruction() {
        let blocks = obligation_fixture();
        let first = SsaArtifact::raw(&blocks, None).expect("first artifact");
        let second = SsaArtifact::raw(&blocks, None).expect("second artifact");
        assert_eq!(
            first
                .facts()
                .obligations
                .obligations
                .keys()
                .collect::<Vec<_>>(),
            second
                .facts()
                .obligations
                .obligations
                .keys()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn obligation_ids_do_not_depend_on_input_block_traversal_order() {
        let blocks = loop_carrier_fixture();
        let first = SsaArtifact::raw(&blocks, None).expect("ordered artifact");
        let mut reordered = blocks;
        reordered[1..].reverse();
        let second = SsaArtifact::raw(&reordered, None).expect("reordered artifact");
        assert_eq!(
            first.obligations().obligations.keys().collect::<Vec<_>>(),
            second.obligations().obligations.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn phi_obligation_ids_do_not_depend_on_register_display_names() {
        let blocks = loop_carrier_fixture();
        let mut first_arch = ArchSpec::new("test-a");
        first_arch.add_register(RegisterDef::new("counter_a", 0, 8));
        let mut second_arch = ArchSpec::new("test-b");
        second_arch.add_register(RegisterDef::new("counter_b", 0, 8));

        let first = SsaArtifact::raw(&blocks, Some(&crate::Arch::from(first_arch.clone())))
            .expect("first artifact");
        let second = SsaArtifact::raw(&blocks, Some(&crate::Arch::from(second_arch.clone())))
            .expect("second artifact");
        assert_eq!(
            first.obligations().obligations.keys().collect::<Vec<_>>(),
            second.obligations().obligations.keys().collect::<Vec<_>>()
        );
        assert!(first.obligations().obligations.keys().any(|id| matches!(
            id.instruction.site,
            CanonicalInstructionSite::Phi(CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            })
        )));
    }

    #[test]
    fn implicit_call_boundary_fails_closed_without_abi_snapshot() {
        let mut block = R2ILBlock::new(0x3000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::constant(0x11, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(16, 8),
            src: Varnode::constant(0x22, 8),
        });
        block.push(R2ILOp::Call {
            target: Varnode::ram(0x4000, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(24, 8),
        });

        let artifact =
            SsaArtifact::raw(&[block], Some(&x86_64_call_arch())).expect("call artifact");
        let arguments = artifact
            .obligations()
            .obligations
            .values()
            .filter(|obligation| obligation.id.kind == SemanticObligationKind::CallArgument)
            .collect::<Vec<_>>();
        assert!(arguments.is_empty());
        let call = artifact
            .obligations()
            .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x3000, 2))
            .expect("call instruction");
        assert_eq!(call.state, SemanticInstructionState::UnsupportedUnknown);
        assert!(
            artifact
                .obligations()
                .owned(&call)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::Call
                        && id.component == SemanticObligationComponent::Whole
                })
        );
        assert!(
            artifact
                .obligations()
                .owned(&call)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::VolatileOrUnknownEffect
                        && id.component == SemanticObligationComponent::Whole
                })
        );
        for ordinal in 0..2 {
            let setup = artifact
                .obligations()
                .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x3000, ordinal))
                .expect("implicit argument setup");
            assert_eq!(setup.state, SemanticInstructionState::UnsupportedUnknown);
            assert!(
                artifact
                    .obligations()
                    .owned(&setup)
                    .map(|obligation| &obligation.id)
                    .any(|id| {
                        id.kind == SemanticObligationKind::VolatileOrUnknownEffect
                            && id.component == SemanticObligationComponent::Whole
                    })
            );
        }
        assert!(artifact.obligations().is_complete());
    }

    #[test]
    fn explicit_zero_argument_void_call_is_distinct_from_missing_interface() {
        let target = Varnode::ram(0x4000, 8);
        let mut block = R2ILBlock::new(0x3040, 4);
        block.push(R2ILOp::Call {
            target: target.clone(),
        });
        let arch = x86_64_call_arch();

        let missing = SsaArtifact::raw(&[block.clone()], Some(&arch)).expect("missing interface");
        let missing_call = missing
            .facts()
            .boundaries
            .calls
            .get(&crate::semantic::CallSiteId(0))
            .expect("missing call boundary");
        assert!(!missing_call.complete);
        assert_eq!(missing_call.calling_convention, None);
        assert_eq!(missing_call.variadic, None);
        assert_eq!(missing_call.noreturn, None);
        assert_eq!(missing_call.result_kind, None);
        assert!(missing_call.arguments.is_empty());
        assert!(missing_call.results.is_empty());

        let identity = direct_call_identity(&mut block, 0, &target);
        let explicit = SsaArtifact::raw_with_interfaces(
            &[block.clone()],
            Some(&arch),
            None,
            vec![call_interface(
                b"call-revision-1",
                identity,
                true,
                [],
                false,
                true,
                SourceCallResult::Void,
            )],
        )
        .expect("explicit void interface");
        let explicit_call = explicit
            .facts()
            .boundaries
            .calls
            .get(&crate::semantic::CallSiteId(0))
            .expect("explicit call boundary");
        assert!(explicit_call.complete);
        assert_eq!(
            explicit_call.calling_convention.as_deref(),
            Some("test-call-abi")
        );
        assert_eq!(explicit_call.variadic, Some(false));
        assert_eq!(explicit_call.noreturn, Some(true));
        assert_eq!(explicit_call.result_kind, Some(SourceCallResult::Void));
        assert!(explicit_call.arguments.is_empty());
        assert!(explicit_call.results.is_empty());

        let incomplete = SsaArtifact::raw_with_interfaces(
            &[block],
            Some(&arch),
            None,
            vec![call_interface(
                b"call-revision-1",
                identity,
                false,
                [],
                false,
                false,
                SourceCallResult::Void,
            )],
        )
        .expect("explicit incomplete interface");
        let incomplete_call = incomplete
            .facts()
            .boundaries
            .calls
            .get(&crate::semantic::CallSiteId(0))
            .expect("incomplete call boundary");
        assert!(!incomplete_call.complete);
        assert_eq!(incomplete_call.result_kind, Some(SourceCallResult::Void));
        assert!(incomplete_call.arguments.is_empty());
        assert!(incomplete_call.results.is_empty());
    }

    #[test]
    fn explicit_register_argument_and_result_use_exact_declared_carriers() {
        let target = Varnode::ram(0x4100, 8);
        let argument_storage = register_storage(8, 8);
        let result_storage = register_storage(0, 8);
        let mut block = R2ILBlock::new(0x3080, 8);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::constant(0x2a, 8),
        });
        block.push(R2ILOp::Call {
            target: target.clone(),
        });
        let interface = call_interface(
            b"call-revision-2",
            direct_call_identity(&mut block, 1, &target),
            true,
            [SourceCallArgumentSpec::new(0, argument_storage)],
            false,
            false,
            SourceCallResult::Register {
                storage: result_storage,
            },
        );
        let artifact = crate::testing::prepared_under(
            &[block],
            &x86_64_call_arch(),
            None,
            vec![interface],
            x86_64_call_effect(),
        )
        .expect("call artifact");
        let boundary = artifact
            .facts()
            .boundaries
            .calls
            .get(&crate::semantic::CallSiteId(0))
            .expect("call boundary");

        assert!(boundary.complete);
        assert_eq!(boundary.variadic, Some(false));
        assert_eq!(boundary.noreturn, Some(false));
        assert_eq!(
            boundary.result_kind,
            Some(SourceCallResult::Register {
                storage: result_storage,
            })
        );
        assert_eq!(boundary.arguments.len(), 1);
        assert_eq!(
            boundary.arguments[0].slot,
            CallBoundarySlot::Register {
                index: 0,
                storage: argument_storage,
            }
        );
        assert_eq!(
            match boundary.arguments[0].value {
                crate::semantic::SourceCallArgumentValue::Value(value) => {
                    artifact.graph().def_inst(value)
                }
                crate::semantic::SourceCallArgumentValue::PreservedEntry => None,
            },
            artifact.graph().inst_spelled_at(0x3080, 0)
        );
        assert_eq!(boundary.results.len(), 1);
        assert_eq!(
            boundary.results[0].slot,
            CallBoundarySlot::Register {
                index: 0,
                storage: result_storage,
            }
        );
        assert!(matches!(
            artifact
                .graph()
                .def_inst(boundary.results[0].value)
                .and_then(|inst| artifact.graph().inst(inst))
                .map(|inst| &inst.payload),
            Some(InstPayload::Op(SSAOp::CallDefine { .. }))
        ));
    }

    #[test]
    fn structural_unused_values_distinguish_unused_and_observed_call_defines() {
        let target = Varnode::ram(0x4200, 8);
        let mut unused_block = R2ILBlock::new(0x30a0, 4);
        unused_block.push(R2ILOp::Call {
            target: target.clone(),
        });
        let unused = crate::testing::prepared_under(
            &[unused_block],
            &x86_64_call_arch(),
            None,
            Vec::new(),
            x86_64_call_effect(),
        )
        .expect("unused call-define artifact");
        let unused_values = unused
            .obligations()
            .structural_unused_values(unused.graph(), unused.unobserved_merges().unobserved_uses())
            .expect("complete structural-value inventory");
        let call_defines = unused
            .graph()
            .insts
            .iter()
            .filter(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::CallDefine { .. })))
            .filter_map(|inst| inst.output)
            .collect::<crate::dense::IdSet<_>>();
        assert!(!call_defines.is_empty());
        assert_eq!(unused_values, call_defines);

        let mut used_block = R2ILBlock::new(0x30a0, 4);
        used_block.push(R2ILOp::Call { target });
        used_block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x80, 8),
            src: Varnode::register(0, 8),
        });
        // The copy has to reach an observable effect for the call result to be
        // read. Being copied somewhere nothing goes on to look at is not being
        // read, and the inventory answers the second question, not the first.
        used_block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x4300, 8),
            val: Varnode::unique(0x80, 8),
        });
        let used = crate::testing::prepared_under(
            &[used_block],
            &x86_64_call_arch(),
            None,
            Vec::new(),
            x86_64_call_effect(),
        )
        .expect("used call-define artifact");
        let used_values = used
            .obligations()
            .structural_unused_values(used.graph(), used.unobserved_merges().unobserved_uses())
            .expect("complete structural-value inventory");
        let observed_call_result = used
            .graph()
            .insts
            .iter()
            .find(|inst| {
                used.graph().written_storage(inst)
                    == Some(CanonicalStorageId {
                        space: CanonicalStorageSpace::Unique,
                        offset: 0x80,
                        size: 8,
                    })
            })
            .and_then(|inst| used.graph().inputs(inst.id).first())
            .copied()
            .expect("copy consumes the exact post-call result");
        assert!(matches!(
            used.graph()
                .def_inst(observed_call_result)
                .and_then(|inst| used.graph().inst(inst))
                .map(|inst| &inst.payload),
            Some(InstPayload::Op(SSAOp::CallDefine { .. }))
        ));
        assert!(!used_values.contains(observed_call_result));
    }

    #[test]
    fn duplicate_wrong_target_and_missing_carrier_interfaces_fail_closed() {
        let target = Varnode::ram(0x4200, 8);
        let mut block = R2ILBlock::new(0x30c0, 4);
        block.push(R2ILOp::Call {
            target: target.clone(),
        });
        let identity = direct_call_identity(&mut block, 0, &target);
        let valid = call_interface(
            b"call-revision-3",
            identity,
            true,
            [],
            false,
            false,
            SourceCallResult::Void,
        );
        let duplicate = SsaArtifact::raw_with_interfaces(
            &[block.clone()],
            Some(&x86_64_call_arch()),
            None,
            vec![valid.clone(), valid],
        )
        .expect("duplicate interface artifact");
        assert!(
            !duplicate
                .facts()
                .boundaries
                .calls
                .get(&crate::semantic::CallSiteId(0))
                .expect("duplicate call boundary")
                .complete
        );

        let wrong_target = call_interface(
            b"call-revision-3",
            SourceCallSiteIdentity::new(
                0x30c0,
                CanonicalStorageId::from_varnode(&Varnode::ram(0x4300, 8)),
            ),
            true,
            [],
            false,
            false,
            SourceCallResult::Void,
        );
        let wrong_target_artifact = SsaArtifact::raw_with_interfaces(
            &[block.clone()],
            Some(&x86_64_call_arch()),
            None,
            vec![wrong_target],
        )
        .expect("wrong target artifact");
        assert!(
            !wrong_target_artifact
                .facts()
                .boundaries
                .calls
                .get(&crate::semantic::CallSiteId(0))
                .expect("wrong-target call boundary")
                .complete
        );

        let missing_carrier = call_interface(
            b"call-revision-3",
            identity,
            true,
            [SourceCallArgumentSpec::new(0, register_storage(0x100, 8))],
            false,
            false,
            SourceCallResult::Void,
        );
        let missing_carrier_artifact = SsaArtifact::raw_with_interfaces(
            &[block],
            Some(&x86_64_call_arch()),
            None,
            vec![missing_carrier],
        )
        .expect("missing carrier artifact");
        assert!(
            !missing_carrier_artifact
                .facts()
                .boundaries
                .calls
                .get(&crate::semantic::CallSiteId(0))
                .expect("missing-carrier call boundary")
                .complete
        );
    }

    #[test]
    fn indirect_call_uses_exact_interface_while_revision_mismatch_fails_closed() {
        let target = Varnode::register(8, 8);
        let mut indirect_block = R2ILBlock::new(0x3100, 4);
        indirect_block.push(R2ILOp::CallInd {
            target: target.clone(),
        });
        let indirect_identity = direct_call_identity(&mut indirect_block, 0, &target);
        let indirect_interface = call_interface(
            b"call-revision-4",
            indirect_identity,
            true,
            [],
            false,
            false,
            SourceCallResult::Void,
        );
        let indirect = SsaArtifact::raw_with_interfaces(
            &[indirect_block],
            Some(&x86_64_call_arch()),
            None,
            vec![indirect_interface],
        )
        .expect("indirect call artifact");
        let indirect_call = indirect
            .facts()
            .boundaries
            .calls
            .get(&crate::semantic::CallSiteId(0))
            .expect("indirect call boundary");
        assert!(indirect_call.call_site.eq(&crate::semantic::CallSiteId(0)));
        assert_eq!(
            indirect.facts().call_sites.by_id[&crate::semantic::CallSiteId(0)].raw_identity,
            Some(indirect_identity)
        );
        assert!(indirect_call.complete);
        assert!(indirect_call.arguments.is_empty());
        assert_eq!(indirect_call.result_kind, Some(SourceCallResult::Void));

        let direct_target = Varnode::ram(0x4400, 8);
        let mut direct_block = R2ILBlock::new(0x3140, 4);
        direct_block.push(R2ILOp::Call {
            target: direct_target.clone(),
        });
        let function_interface = SourceFunctionInterface::new(
            b"function-revision".to_vec(),
            "test-call-abi",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("function interface");
        let mismatched_call = call_interface(
            b"other-revision",
            direct_call_identity(&mut direct_block, 0, &direct_target),
            true,
            [],
            false,
            false,
            SourceCallResult::Void,
        );
        let mismatched = SsaArtifact::raw_with_interfaces(
            &[direct_block],
            Some(&x86_64_call_arch()),
            Some(function_interface),
            vec![mismatched_call],
        )
        .expect("revision mismatch artifact");
        assert!(
            !mismatched
                .facts()
                .boundaries
                .calls
                .get(&crate::semantic::CallSiteId(0))
                .expect("revision-mismatched call boundary")
                .complete
        );
    }

    #[test]
    fn architecture_profile_without_function_interface_keeps_return_incomplete() {
        let mut block = R2ILBlock::new(0x3100, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(0x42, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(24, 8),
        });

        let artifact =
            SsaArtifact::raw(&[block], Some(&x86_64_call_arch())).expect("return artifact");
        let producer = artifact
            .obligations()
            .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x3100, 0))
            .expect("potential return-value producer");
        assert_eq!(producer.state, SemanticInstructionState::UnsupportedUnknown);
        assert!(
            artifact
                .obligations()
                .owned(&producer)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::VolatileOrUnknownEffect
                        && id.component == SemanticObligationComponent::Whole
                })
        );
        let returned = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("return boundary");
        assert!(!returned.complete);
        assert!(returned.values.is_empty());
        assert!(artifact.obligations().is_complete());
    }

    #[test]
    fn untyped_interface_keeps_exact_parameter_but_refuses_incomplete_return_roles() {
        let mut block = R2ILBlock::new(0x3140, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x10, 8),
            src: Varnode::register(8, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(24, 8),
        });
        let parameter_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 8,
            size: 8,
        };
        let return_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let interface = SourceFunctionInterface::new(
            b"fixture-revision-1".to_vec(),
            "sysv-amd64",
            [SourceAbiParameterSpec::new(0, parameter_storage)],
            SourceFunctionReturn::Register {
                storage: return_storage,
            },
            [],
        )
        .expect("explicit interface");
        let artifact =
            SsaArtifact::raw_with_interface(&[block], Some(&x86_64_call_arch()), interface)
                .expect("return artifact");

        let returned = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("return boundary");
        let parameter = artifact
            .facts()
            .boundaries
            .parameters
            .get(&0)
            .expect("exact ABI parameter identity");
        assert_eq!(parameter.abi_storage, parameter_storage);
        assert_eq!(parameter.graph_storage, parameter_storage);
        assert_eq!(parameter.logical_value, None);
        // A plain interface's slot roles are not exact, which used to make the
        // whole model incoherent and empty the return boundary. The return
        // register it names is a different question.
        assert!(
            !artifact
                .machine_context()
                .function_interface()
                .expect("interface")
                .stack_slot_roles_complete()
        );
        assert!(
            artifact
                .machine_context()
                .abi_model()
                .return_boundary_is_coherent()
        );
        assert!(returned.complete);
        assert_eq!(returned.values.len(), 1);
        let producer = artifact
            .obligations()
            .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x3140, 1))
            .expect("return producer");
        // The boundary is complete, so nothing taints the value that reaches
        // it. An unattributed frame used to make this an unknown effect.
        assert_ne!(producer.state, SemanticInstructionState::UnsupportedUnknown);
        assert!(
            !artifact
                .obligations()
                .owned(&producer)
                .map(|obligation| &obligation.id)
                .any(|obligation| {
                    obligation.kind == SemanticObligationKind::VolatileOrUnknownEffect
                })
        );
    }

    #[test]
    fn a_call_keeps_the_definition_the_next_iteration_passes_it() {
        let mut entry = R2ILBlock::new(0x3170, 4);
        entry.push(R2ILOp::Branch {
            target: Varnode::ram(0x3180, 8),
        });
        let mut block = R2ILBlock::new(0x3180, 4);
        block.push(R2ILOp::Call {
            target: Varnode::ram(0x4000, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::constant(0x42, 8),
        });
        block.push(R2ILOp::Branch {
            target: Varnode::ram(0x3180, 8),
        });

        let artifact = SsaArtifact::for_decompile_with(
            &[entry, block],
            crate::DecompileInputs {
                arch: Some(&x86_64_call_arch()),
                // The convention: a call reads rdi, the register written below.
                call_effect: crate::testing::call_effect_reading(
                    [0, 8, 16, 32, 40, 48, 56].map(|offset| register_storage(offset, 8)),
                    [register_storage(24, 8)],
                    [register_storage(8, 8)],
                ),
                ..Default::default()
            },
        )
        .expect("loop artifact");
        // The copy writes an argument carrier the call reads on the next turn
        // of the loop, so it is live. Nothing about the boundary being
        // incomplete makes it an unknown effect: the value is one this
        // function computes and can spell.
        let (block_addr, op_index) = artifact
            .named_block(0x3180)
            .expect("loop block")
            .ops()
            .iter()
            .enumerate()
            .find_map(|(index, op)| {
                matches!(op, crate::op::SSAOp::Copy { dst, .. } if dst.name() == "rdi")
                    .then_some((0x3180u64, index))
            })
            .expect("argument-carrier definition");
        let next_iteration_argument = artifact
            .obligations()
            .disposition_with_id(
                artifact.graph(),
                operation_at(&artifact, block_addr, op_index),
            )
            .expect("next-iteration argument producer");
        assert_eq!(
            next_iteration_argument.state,
            SemanticInstructionState::LiveObligation
        );
        assert!(
            artifact
                .obligations()
                .owned(&next_iteration_argument)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::LiveValueProducer
                        && id.component == SemanticObligationComponent::Whole
                })
        );
        assert!(
            !artifact
                .obligations()
                .owned(&next_iteration_argument)
                .map(|obligation| &obligation.id)
                .any(|id| { id.kind == SemanticObligationKind::VolatileOrUnknownEffect })
        );
        assert!(artifact.obligations().is_complete());
    }

    #[test]
    fn duplicate_explicit_obligation_seed_fails_inventory_construction() {
        let mut block = R2ILBlock::new(0x3200, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::constant(0x11, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(16, 8),
            src: Varnode::constant(0x22, 8),
        });
        block.push(R2ILOp::Call {
            target: Varnode::ram(0x4000, 8),
        });
        let artifact =
            SsaArtifact::raw(&[block], Some(&x86_64_call_arch())).expect("call artifact");
        let graph = artifact.graph();
        let first = graph
            .inst(graph.inst_spelled_at(0x3200, 0).expect("first setup"))
            .and_then(|inst| inst.output)
            .expect("first argument value");
        let second = graph
            .inst(graph.inst_spelled_at(0x3200, 1).expect("second setup"))
            .and_then(|inst| inst.output)
            .expect("second argument value");
        let call_inst = graph.inst_spelled_at(0x3200, 2).expect("call instruction");
        let call_site = crate::semantic::CallSiteId(0);
        let slot = crate::semantic::CallBoundarySlot::Register {
            index: 0,
            storage: CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Register,
                offset: 8,
                size: 8,
            },
        };
        let mut boundaries = SourceBoundaryFacts::default();
        boundaries.calls.insert(
            call_site,
            crate::semantic::SourceCallBoundaryFact {
                call_site,
                at: call_inst,
                calling_convention: Some("test-abi".to_string()),
                variadic: Some(false),
                noreturn: Some(false),
                result_kind: Some(crate::SourceCallResult::Void),
                arguments: vec![
                    crate::semantic::SourceCallArgumentFact {
                        slot,
                        value: crate::semantic::SourceCallArgumentValue::Value(first),
                        lane_of: None,
                    },
                    crate::semantic::SourceCallArgumentFact {
                        slot,
                        value: crate::semantic::SourceCallArgumentValue::Value(second),
                        lane_of: None,
                    },
                ],
                fixed_argument_count: Some(2),
                variadic_argument_count_evidence: None,
                variadic_argument_count_refusal: None,
                results: Vec::new(),
                complete: true,
                arguments_complete: true,
                results_complete: true,
                described: true,
            },
        );
        let inventory = SemanticObligationInventory::collect(
            graph,
            artifact.structured(),
            &boundaries,
            None,
            &SeedingFacts::new(&BTreeSet::new(), &BTreeMap::new(), &BTreeSet::new()),
        );

        assert!(!inventory.is_complete());
        assert!(inventory.construction_failures().iter().any(|failure| {
            failure.inst == call_inst
                && failure.kind == ObligationInventoryFailureKind::DuplicateObligationSeed
        }));
        let arguments = inventory
            .obligations_for_inst(call_inst)
            .filter(|obligation| obligation.id.kind == SemanticObligationKind::CallArgument)
            .collect::<Vec<_>>();
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0].inputs, vec![first]);
    }

    #[test]
    fn atomic_cas_has_read_write_and_ordering_obligations() {
        let mut block = R2ILBlock::new(0x5000, 4);
        block.push(R2ILOp::AtomicCAS {
            dst: Varnode::unique(0x10, 8),
            space: SpaceId::Ram,
            addr: Varnode::register(0, 8),
            expected: Varnode::constant(1, 8),
            replacement: Varnode::constant(2, 8),
            ordering: MemoryOrdering::SeqCst,
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(8, 8),
        });

        let artifact = SsaArtifact::raw(&[block], None).expect("atomic artifact");
        let atomic = artifact
            .obligations()
            .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x5000, 0))
            .expect("atomic instruction");
        assert_eq!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .filter(|id| id.kind == SemanticObligationKind::ObservableMemoryRead)
                .count(),
            1
        );
        assert_eq!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .filter(|id| id.kind == SemanticObligationKind::ObservableMemoryWrite)
                .count(),
            1
        );
        assert!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::ObservableMemoryRead
                        && id.component == SemanticObligationComponent::MemoryAccess(0)
                })
        );
        assert!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::ObservableMemoryWrite
                        && id.component == SemanticObligationComponent::MemoryAccess(1)
                })
        );
        assert!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::Atomicity
                        && id.component == SemanticObligationComponent::Whole
                })
        );
        assert!(
            artifact
                .obligations()
                .owned(&atomic)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::MemoryOrdering
                        && id.component
                            == SemanticObligationComponent::MemoryOrdering(
                                SemanticMemoryOrdering::SeqCst,
                            )
                })
        );
    }

    #[test]
    fn unknown_atomic_ordering_is_unsupported() {
        let mut block = R2ILBlock::new(0x6000, 4);
        block.push(R2ILOp::Fence {
            ordering: MemoryOrdering::Unknown,
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(8, 8),
        });
        let artifact = SsaArtifact::raw(&[block], None).expect("fence artifact");
        let fence = artifact
            .obligations()
            .disposition_with_id(artifact.graph(), operation_at(&artifact, 0x6000, 0))
            .expect("fence instruction");
        assert_eq!(fence.state, SemanticInstructionState::UnsupportedUnknown);
        assert!(
            artifact
                .obligations()
                .owned(&fence)
                .map(|obligation| &obligation.id)
                .any(|id| {
                    id.kind == SemanticObligationKind::MemoryOrdering
                        && id.component
                            == SemanticObligationComponent::MemoryOrdering(
                                SemanticMemoryOrdering::Unknown,
                            )
                })
        );
    }

    #[test]
    fn storage_less_phi_refuses_complete_inventory() {
        let artifact = SsaArtifact::raw(&loop_carrier_fixture(), None).expect("loop artifact");
        let mut graph = artifact.graph().clone();
        let merged = graph
            .insts
            .iter()
            .find(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
            .and_then(|phi| phi.output)
            .expect("loop phi");
        graph.values[merged.0 as usize].canonical_storage = None;
        let inventory = SemanticObligationInventory::collect(
            &graph,
            artifact.structured(),
            &artifact.facts().boundaries,
            None,
            &SeedingFacts::new(&BTreeSet::new(), &BTreeMap::new(), &BTreeSet::new()),
        );
        assert!(!inventory.is_complete());
        assert!(inventory.construction_failures.iter().any(|failure| {
            failure.kind == ObligationInventoryFailureKind::MissingCanonicalPhiStorage
        }));
    }

    /// A cycle no natural loop owns has no loop certificate, and that is all:
    /// its instructions owe the same obligations as any other, and the
    /// structurer writes the cycle with `goto`s.
    #[test]
    fn irreducible_cycle_keeps_a_complete_inventory() {
        let artifact =
            SsaArtifact::raw(&irreducible_cycle_fixture(), None).expect("irreducible artifact");
        assert!(!artifact.structured().unstructured_cycle_blocks.is_empty());
        assert!(artifact.obligations().is_complete());
    }

    #[test]
    fn empty_irreducible_cycle_has_a_complete_empty_inventory() {
        let artifact =
            SsaArtifact::raw(&irreducible_cycle_fixture(), None).expect("irreducible artifact");
        let mut graph = artifact.graph().clone();
        graph.insts.clear();
        graph.values.clear();
        graph.def_of.clear();
        graph.clear_use_sites();
        graph.inst_by_op.clear();
        graph.op_by_inst.clear();
        for block in &mut graph.blocks {
            block.insts.clear();
        }
        let inventory = SemanticObligationInventory::collect(
            &graph,
            artifact.structured(),
            &artifact.facts().boundaries,
            None,
            &SeedingFacts::new(&BTreeSet::new(), &BTreeMap::new(), &BTreeSet::new()),
        );
        assert_eq!(inventory.source_instruction_count(), 0);
        assert!(!inventory.unstructured_cycle_blocks().is_empty());
        assert!(inventory.is_complete());
    }

    #[test]
    fn malformed_bidirectional_inventory_mapping_is_incomplete() {
        let artifact = SsaArtifact::raw(&obligation_fixture(), None).expect("SSA artifact");
        let mut inventory = artifact.obligations().clone();
        let obligation = inventory
            .obligations
            .0
            .first_mut()
            .expect("source obligation");
        obligation.source = SemanticSourceSite::GraphInstruction(InstId(u32::MAX));
        // The inventory decides this once, where it is built, so a mapping
        // broken afterwards is asked of the derivation rather than of the
        // answer it recorded before the break.
        assert!(!inventory.derive_is_complete());
    }

    #[test]
    fn loop_transition_carries_the_exact_phi_input_use_site() {
        let artifact = SsaArtifact::raw(&loop_carrier_fixture(), None).expect("loop artifact");
        let carrier = artifact
            .structured()
            .loops
            .values()
            .flat_map(|loop_fact| loop_fact.carriers.iter())
            .next()
            .expect("loop carrier");
        let update = carrier.updates.first().expect("loop update");
        let phi_inst = artifact
            .graph()
            .def_inst(carrier.phi)
            .expect("phi definition");
        let transition = artifact
            .obligations()
            .obligations_for_inst(phi_inst)
            .find(|obligation| {
                obligation.id.kind == SemanticObligationKind::LiveStateTransition
                    && matches!(
                        obligation.id.component,
                        SemanticObligationComponent::LoopTransition { predecessor, .. }
                            if predecessor == update.predecessor
                    )
            })
            .expect("carrier-edge transition");

        assert_eq!(transition.edge_use, Some(update.site));
        assert_eq!(transition.inputs, vec![update.value]);
        assert!(update.validate(artifact.graph()));
    }

    #[test]
    fn malformed_loop_transition_edge_fails_closed() {
        let artifact = SsaArtifact::raw(&loop_carrier_fixture(), None).expect("loop artifact");
        let mut structured = artifact.structured().clone();
        let undef = artifact
            .graph()
            .values
            .iter()
            .find(|value| artifact.graph().def_inst(value.id).is_none())
            .map(|value| value.id)
            .expect("undefined or constant value");
        let carrier = structured
            .loops
            .values_mut()
            .flat_map(|loop_fact| loop_fact.carriers.iter_mut())
            .next()
            .expect("loop carrier");
        carrier.updates[0].value = undef;
        let phi_inst = artifact
            .graph()
            .def_inst(carrier.phi)
            .expect("phi definition");

        let inventory = SemanticObligationInventory::collect(
            artifact.graph(),
            &structured,
            &artifact.facts().boundaries,
            None,
            &SeedingFacts::new(&BTreeSet::new(), &BTreeMap::new(), &BTreeSet::new()),
        );
        assert!(
            inventory
                .obligations_for_inst(phi_inst)
                .all(|obligation| obligation.id.kind
                    != SemanticObligationKind::LiveStateTransition),
            "a value/site mismatch must not produce an exact transition certificate"
        );
        assert!(inventory.obligations_for_inst(phi_inst).any(|obligation| {
            obligation.id.kind == SemanticObligationKind::VolatileOrUnknownEffect
        }));
    }

    #[test]
    fn shared_loop_update_values_keep_distinct_predecessor_obligations() {
        let accumulator = Varnode::register(0, 8);
        let mut entry = R2ILBlock::new(0x2000, 4);
        entry.push(R2ILOp::Copy {
            dst: accumulator.clone(),
            src: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::ram(0x2010, 8),
        });
        let mut header = R2ILBlock::new(0x2010, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x2020, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut exit = R2ILBlock::new(0x2014, 4);
        exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let mut update = R2ILBlock::new(0x2020, 4);
        update.push(R2ILOp::IntAdd {
            dst: accumulator.clone(),
            a: accumulator,
            b: Varnode::constant(1, 8),
        });
        update.push(R2ILOp::CBranch {
            target: Varnode::ram(0x2030, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut left_latch = R2ILBlock::new(0x2024, 4);
        left_latch.push(R2ILOp::Branch {
            target: Varnode::ram(0x2010, 8),
        });
        let mut right_latch = R2ILBlock::new(0x2030, 4);
        right_latch.push(R2ILOp::Branch {
            target: Varnode::ram(0x2010, 8),
        });
        let artifact = SsaArtifact::raw(
            &[entry, header, exit, update, left_latch, right_latch],
            None,
        )
        .expect("two-latch loop artifact");
        let carrier = artifact
            .structured()
            .loops
            .values()
            .flat_map(|loop_fact| loop_fact.carriers.iter())
            .next()
            .expect("loop carrier");
        assert_eq!(carrier.updates.len(), 2);
        assert_eq!(carrier.updates[0].value, carrier.updates[1].value);
        assert_ne!(carrier.updates[0].site, carrier.updates[1].site);
        let phi_inst = artifact
            .graph()
            .def_inst(carrier.phi)
            .expect("phi definition");
        assert!(
            carrier
                .updates
                .iter()
                .all(|update| update.site.inst == phi_inst && update.validate(artifact.graph()))
        );
        let inventory = artifact.obligations();
        let transitions = inventory
            .obligations_for_inst(phi_inst)
            .filter(|obligation| obligation.id.kind == SemanticObligationKind::LiveStateTransition)
            .collect::<Vec<_>>();
        assert_eq!(transitions.len(), 2);
        assert_ne!(transitions[0].id, transitions[1].id);
        assert_eq!(transitions[0].inputs, transitions[1].inputs);
    }

    #[test]
    fn an_observable_write_owes_a_write_obligation() {
        let artifact = SsaArtifact::raw(&observable_write_fixture(), None).expect("SSA artifact");
        let inventory = &artifact.facts().obligations;
        assert!(inventory.is_complete());
        assert!(
            inventory
                .obligations
                .keys()
                .any(|id| id.kind == SemanticObligationKind::ObservableMemoryWrite),
            "an observable write must owe a write obligation"
        );
    }

    #[test]
    fn a_loop_carrier_owes_a_latch_state_transition() {
        let artifact = SsaArtifact::raw(&loop_carrier_fixture(), None).expect("loop SSA artifact");
        assert!(
            artifact
                .obligations()
                .obligations
                .keys()
                .any(|id| id.kind == SemanticObligationKind::LiveStateTransition),
            "a loop carrier must owe a latch state transition"
        );
    }

    proptest! {
        #[test]
        fn obligation_ids_are_stable_for_all_non_entry_block_orders(
            priorities in any::<[u8; 3]>()
        ) {
            let blocks = loop_carrier_fixture();
            let first = SsaArtifact::raw(&blocks, None).expect("ordered artifact");
            let mut tail = blocks[1..].to_vec();
            tail.sort_by_key(|block| {
                let original = blocks[1..]
                    .iter()
                    .position(|candidate| candidate.addr == block.addr)
                    .expect("fixture block");
                (priorities[original], block.addr)
            });
            let mut reordered = vec![blocks[0].clone()];
            reordered.extend(tail);
            let second = SsaArtifact::raw(&reordered, None).expect("reordered artifact");
            prop_assert_eq!(
                first.obligations().obligations.keys().collect::<Vec<_>>(),
                second.obligations().obligations.keys().collect::<Vec<_>>()
            );
        }
    }
}
