//! Function-level SSA representation.
//!
//! This module provides the `SSAFunction` type which combines all SSA
//! components for a complete function: CFG, dominator tree, phi nodes,
//! and renamed operations.

mod blocks;
mod build;
mod caller_stack_slots;
mod dead_frame_stores;
mod edit;
mod named_edit;
mod rewrite;
mod stack_roots;
mod stage;

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::Arc;

use r2il::{ArchSpec, R2ILBlock, R2ILOp};
use r2sleigh_lift::{GenuineLiftedFunction, TrustedLiftedFunction};
use r2source::{OwnedFunctionSnapshot, SourceCallPreservedCarriers};
use serde::{Deserialize, Serialize};

use crate::aggregate_access::{
    AggregateAccessProjectionFacts, collect_aggregate_access_projections,
};
use crate::arena::{OpArena, OpId, Pass};
use crate::block::BlockMut;
pub use crate::block::SSABlock;
use crate::cfg::{CFG, CFGEdge};
use crate::control::{
    SsaExecutionStopReason, SsaPrepareError, SsaWorkControl, UncheckedSsaWorkControl,
};
use crate::dense::IdMap;
use crate::domtree::DomTree;
use crate::graph::SsaGraph;
use crate::graph::ValueId;
use crate::integrity::{SsaIntegrityError, validate_ssa_function};
#[cfg(test)]
use crate::machine_context::{SourceCallArgumentSpec, SourceCallResult};
use crate::machine_context::{
    SourceCallSiteIdentity, SourceCallSiteInterface, SourceFunctionInterface, SourceMachineContext,
    SourceMachineRoles,
};
use crate::op::SSAOp;
use crate::phi::{PhiPlacement, collect_defs_from_cfg_with_names_storage_and_control};
use crate::rename::{CallBoundaryConfig, CallBoundaryDef, rename_function};
use crate::semantic::{
    CallResultCertificate, CallSiteFacts, CallSiteId, CallsiteCertificate, MemoryAccessCertificate,
    MemoryDefFact, MemorySSAFacts, MemoryUseFact, ObjectId, ObjectModel, PredicateFacts,
    PreparedFunctionFacts, ReturnValueCertificate, StackReloadSourceCertificate,
    StructuredDataflowFacts,
};
use crate::value_table::VarId;
use crate::var::SSAVar;
use crate::{AssumptionSet, CanonicalStorageId, CanonicalStorageSpace};
use blocks::Blocks;
pub(crate) use edit::{Anchor, BlockEdits, EditPlan, Insertion, ShapeEdit};
pub use named_edit::NamedBlockMut;
pub use stage::{Lifted, Prepared, Sealed};

/// Query-only CFG risk summary for decompilation preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFGRiskSummary {
    pub block_count: usize,
    pub loop_count: usize,
    pub back_edge_count: usize,
    pub switch_block_count: usize,
    pub max_switch_cases: usize,
}

pub use r2source::StackAddressBase;

/// `SsaPrepareError::MalformedInput`, with the predicate that decided it named.
///
/// Fifteen checks in this file answer with that one variant, and it reaches a
/// reader as the single string "malformed SSA source input" -- which says that
/// something rejected the function and nothing about what. That was the last
/// unattributed hard error on the path where zlib's -O2 binaries were being
/// lost, and attributing a refusal to the predicate that made it is what turned
/// the return-boundary hunt from a search into a read.
///
/// `#[track_caller]` puts the caller's line in the message, so each site costs
/// nothing to say and cannot drift from where it actually is.
/// The validator's typed refusal, as the one error preparation reports, with
/// the integrity error named in the evidence.
fn integrity_refusal(error: SsaIntegrityError) -> SsaPrepareError {
    r2il::refusal_evidence!("ssa-integrity", "{error:?}");
    SsaPrepareError::Integrity(error.rule())
}

#[track_caller]
fn malformed_ssa_input() -> SsaPrepareError {
    let location = std::panic::Location::caller();
    r2il::refusal_evidence!(
        "ssa-malformed-input",
        "{}:{}",
        location.file(),
        location.line()
    );
    SsaPrepareError::MalformedInput
}

/// Proven stack-address root: `base +/- offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StackAddressRoot {
    pub base: StackAddressBase,
    pub offset: i64,
}

/// Decompiler-prep analysis facts derived from SSA.
///
/// Collected once, when a function is sealed, over the graph of the blocks
/// the sealed function keeps; nothing changes those blocks after, so the
/// facts never describe blocks that no longer exist. Every fact is an index
/// over the graph's values (doc/adr-one-ir.md): a lookup is `O(1)` and reads
/// no name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompilePrepFacts {
    /// Which values carry the same bits, and each value's representative.
    ///
    /// The one identity fact every stage builds on (`crate::view`): a value
    /// shares identity with another only where their bits are equal at full
    /// width, so an extension or a lane at a non-zero offset is never the
    /// value it was read from.
    pub views: crate::view::ValueViews<crate::graph::ValueId>,
    pub stack_address_roots: IdMap<crate::graph::ValueId, StackAddressRoot>,
    /// Exact address roots normalized to the entry stack pointer by machine
    /// dataflow. Unlike `stack_address_roots`, these roots are never rebased
    /// to a source-declared frame-pointer coordinate system.
    pub entry_stack_address_roots: IdMap<crate::graph::ValueId, StackAddressRoot>,
    /// Addresses that lie inside a stack object at an offset the machine
    /// computes rather than states.
    ///
    /// `stack_address_roots` records an exact offset from a base, which is what
    /// a scalar slot needs and what an array element cannot have: `buf[i]` is
    /// `frame_base + (-0x20) + i`, and the second addition has no constant to
    /// fold, so the address gets no root at all and its object escapes. The
    /// root recorded here names the object the index is into -- the base and
    /// the constant part -- and says nothing about which element, which is
    /// exactly what is known.
    pub indexed_stack_address_roots: IdMap<crate::graph::ValueId, StackAddressRoot>,
    /// Entry SSA values bound to canonical ABI parameter slots.
    pub formal_parameters: IdMap<crate::graph::ValueId, usize>,
    /// Full-width entry ABI values that may serve as parameter address bases.
    pub formal_parameter_bases: IdMap<crate::graph::ValueId, usize>,
    /// The stack-root solve moved a state past its height: the function refuses.
    pub(crate) exhausted: Option<crate::fixpoint::Exhausted>,
}

impl Default for DecompilePrepFacts {
    fn default() -> Self {
        Self {
            views: crate::view::ValueViews::default(),
            stack_address_roots: IdMap::new(0),
            entry_stack_address_roots: IdMap::new(0),
            indexed_stack_address_roots: IdMap::new(0),
            formal_parameters: IdMap::new(0),
            formal_parameter_bases: IdMap::new(0),
            exhausted: None,
        }
    }
}

/// Unforgeable run-local identity for one immutable SSA artifact.
///
/// Moving or sharing an artifact through [`Arc`] retains this identity.
/// Rebuilding identical source bytes creates a distinct identity, so
/// downstream proof owners can reject artifact-local handles from an
/// independently reconstructed graph without relying on names, addresses, or
/// a probabilistic hash.
#[derive(Clone)]
pub struct SsaArtifactAuthority(Arc<()>);

impl SsaArtifactAuthority {
    fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl std::fmt::Debug for SsaArtifactAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsaArtifactAuthority(..)")
    }
}

impl PartialEq for SsaArtifactAuthority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SsaArtifactAuthority {}

impl std::hash::Hash for SsaArtifactAuthority {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&Arc::as_ptr(&self.0), state);
    }
}

/// The interface, offered per question rather than all-or-nothing.
///
/// Whole-model coherence hid the interface from SSA construction entirely, so
/// one unattributed frame slot cost the argument carriers and the return
/// projection too. Each use below asks only the question it depends on.
///
/// Construction reads only what is known before it runs. Where the source
/// states no interface, that is the calling convention: its argument
/// registers and its result register are the carriers at the boundary
/// whatever this function's own signature turns out to be. An interface
/// recovered from the body comes after construction and is read at the
/// seal, so one build serves both recovery and the artifact.
#[derive(Clone, Copy)]
pub(crate) struct InterfaceQuestions<'a> {
    interface: Option<&'a SourceFunctionInterface>,
    return_boundary: bool,
    argument_placement: bool,
    frame_geometry: bool,
    convention: Option<&'a r2source::ConventionModel>,
}

impl<'a> InterfaceQuestions<'a> {
    fn new(machine_context: &'a SourceMachineContext) -> Self {
        let abi = machine_context.abi_model();
        Self {
            interface: machine_context.function_interface(),
            return_boundary: abi.return_boundary_is_coherent(),
            argument_placement: abi.argument_placement_is_coherent(),
            frame_geometry: abi.frame_geometry_is_coherent(),
            convention: None,
        }
    }

    /// No interface at all: no question about it can be answered.
    fn none() -> Self {
        Self {
            interface: None,
            return_boundary: false,
            argument_placement: false,
            frame_geometry: false,
            convention: None,
        }
    }

    /// No interface the source states: construction asks the convention.
    fn before_recovery(convention: Option<&'a r2source::ConventionModel>) -> Self {
        Self {
            convention,
            ..Self::none()
        }
    }

    /// The registers at this function's boundary that every caller reads
    /// or writes whole: the interface's argument and result registers, or,
    /// with none stated, the convention's.
    pub(crate) fn construction_carriers(self) -> Vec<CanonicalStorageId> {
        let register = |storage: &CanonicalStorageId| {
            (storage.space == CanonicalStorageSpace::Register).then_some(*storage)
        };
        if let Some(convention) = self.convention {
            return convention
                .arguments(r2source::convention::SlotClass::Integer)
                .iter()
                .chain(convention.result().as_ref())
                .filter_map(register)
                .collect();
        }
        self.for_argument_placement()
            .into_iter()
            .flat_map(|interface| {
                interface
                    .parameters()
                    .iter()
                    .filter_map(crate::SourceAbiParameterSpec::register_storage)
            })
            .chain(
                self.for_return_boundary()
                    .into_iter()
                    .flat_map(|interface| interface.return_kind().storages()),
            )
            .collect()
    }

    /// The registers a caller reads the result from, whose merges in a returning block keep their
    /// sources: the interface's, where it describes them coherently, or the convention's.
    pub(crate) fn return_carriers(self) -> Vec<CanonicalStorageId> {
        match self.convention {
            Some(convention) => convention
                .result()
                .into_iter()
                .chain(convention.results().second)
                .filter(|slot| slot.space == CanonicalStorageSpace::Register)
                .collect(),
            None => self
                .for_return_boundary()
                .map(crate::optimize::coherent_return_carriers)
                .unwrap_or_default(),
        }
    }

    fn for_return_boundary(self) -> Option<&'a SourceFunctionInterface> {
        self.interface.filter(|_| self.return_boundary)
    }

    fn for_argument_placement(self) -> Option<&'a SourceFunctionInterface> {
        self.interface.filter(|_| self.argument_placement)
    }

    fn for_frame_geometry(self) -> Option<&'a SourceFunctionInterface> {
        self.interface.filter(|_| self.frame_geometry)
    }
}

/// The sealed artifact's liveness: where values leave the function and the reads the text never
/// performs; the build's value liveness and spans are dropped (doc/adr-memory-model.md, decision 1).
#[derive(Debug, Clone)]
pub struct ArtifactLiveness {
    live_out: crate::liveout::FunctionLiveOut,
    /// Reads the text never performs: a call's conventional read of a register
    /// the certified call does not pass.
    ignored_reads: std::collections::BTreeSet<crate::graph::UseSite>,
}

impl ArtifactLiveness {
    pub const fn live_out(&self) -> &crate::liveout::FunctionLiveOut {
        &self.live_out
    }

    pub const fn ignored_reads(&self) -> &std::collections::BTreeSet<crate::graph::UseSite> {
        &self.ignored_reads
    }
}

/// What the source called things, which only the renderer reads.
///
/// Neither field is a dataflow, ABI or typing fact. They are retained because
/// the lift and the snapshot are the only things that ever saw them, and both
/// are gone by the time anything renders.
#[derive(Debug, Clone, Default)]
pub struct ArtifactSpellings {
    /// Spellings the source carried for the addresses this function calls, so
    /// the renderer prints `sym.imp.strcmp` where it would print an address.
    display_names: r2source::DisplayNames,
    /// The names of the architecture's user-defined operations, indexed as
    /// `SSAOp::CallOther` indexes them. An index is meaningless without the
    /// table it came from, so the table travels with the artifact rather than
    /// the renderer guessing.
    user_operations: Arc<[String]>,
}

/// What an artifact is built with besides its function: where it came from,
/// how its names read to a person, and the native instructions its
/// obligations are about. Given at construction, so nothing is written into
/// an artifact once it is built.
struct Finish {
    provenance: SsaArtifactProvenance,
    spellings: ArtifactSpellings,
    /// Each native instruction of a genuine lift, which the obligations are
    /// bound to; absent where the function was not lifted from one.
    native_spans: Option<Vec<crate::GenuineNativeInstructionSpan>>,
    /// The boundary recovery read off the body, where the interface was recovered.
    body_boundary: Option<Arc<crate::body_boundary::BodyBoundary>>,
}

impl Finish {
    /// A function a test or an internal path built, from no lift.
    fn manual() -> Self {
        Self {
            provenance: SsaArtifactProvenance::Manual,
            spellings: ArtifactSpellings::default(),
            native_spans: None,
            body_boundary: None,
        }
    }
}

/// Canonical SSA artifact consumed by downstream analysis layers.
#[derive(Debug)]
pub struct SsaArtifact {
    authority: SsaArtifactAuthority,
    provenance: SsaArtifactProvenance,
    /// The sealed function, its prep facts and its graph: everything below
    /// was derived from it, and nothing can change it.
    sealed: Sealed,
    liveness: ArtifactLiveness,
    unobserved_merges: crate::deadphi::DeadPhis,
    facts: PreparedFunctionFacts,
    machine_context: SourceMachineContext,
    aggregate_accesses: AggregateAccessProjectionFacts,
    member_calls: crate::member_call::MemberCalls,
    spellings: ArtifactSpellings,
}

/// Public classification of an artifact's construction boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsaArtifactProvenanceKind {
    Manual,
    GenuineLiftOnly,
    TrustedSource,
}

/// Exact native instruction coverage derived only from one genuine lift.
///
/// This is retained beside canonical P-code rather than being materialized as
/// a synthetic R2IL operation. Its canonical-operation range binds the native
/// bytes to the exact translator output from the same lift event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GenuineNativeInstructionSpan {
    block_addr: u64,
    instruction_addr: u64,
    size: u32,
    first_canonical_op: u64,
    canonical_op_count: u64,
}

impl GenuineNativeInstructionSpan {
    pub const fn block_addr(self) -> u64 {
        self.block_addr
    }

    pub const fn instruction_addr(self) -> u64 {
        self.instruction_addr
    }

    pub const fn size(self) -> u32 {
        self.size
    }

    pub const fn first_canonical_op(self) -> u64 {
        self.first_canonical_op
    }

    pub const fn canonical_op_count(self) -> u64 {
        self.canonical_op_count
    }
}

fn genuine_native_instruction_spans(
    lifted: &GenuineLiftedFunction,
) -> Vec<GenuineNativeInstructionSpan> {
    lifted
        .blocks()
        .iter()
        .flat_map(|block| {
            let block_addr = block.block().addr;
            block.instruction_spans().iter().copied().map(move |span| {
                GenuineNativeInstructionSpan {
                    block_addr,
                    instruction_addr: span.addr(),
                    size: span.size(),
                    first_canonical_op: span.first_canonical_op(),
                    canonical_op_count: span.canonical_op_count(),
                }
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
enum SsaArtifactProvenance {
    Manual,
    TrustedSource(OwnedFunctionSnapshot),
}

/// Opaque certifiable SSA prepared only from a source-retaining trusted lift.
/// Generic/manual [`SsaArtifact`] constructors cannot produce this wrapper.
#[derive(Debug, Clone)]
pub struct TrustedSsaArtifact {
    artifact: Arc<SsaArtifact>,
    source_block_count: usize,
    arch: crate::Arch,
}

/// A trusted lift built, recovered and sealed, its facts not yet collected: what a preparation
/// reads before it pays for the fact pass (doc/adr-resolved-bodies.md, "Summaries").
pub struct TrustedSeal {
    sealed: Sealed,
    machine_context: SourceMachineContext,
    finish: Finish,
    source_block_count: usize,
    arch: crate::Arch,
    /// The heap live as the seal began, which the preparation's trace measures from.
    entry_bytes: Option<usize>,
}

impl TrustedSeal {
    /// The context the function is sealed in: its interface, recovered or stated, and its owners.
    pub const fn machine_context(&self) -> &SourceMachineContext {
        &self.machine_context
    }

    /// Every constant a sealed value folds to with what preparation admitted, in value order.
    pub fn folded_values(&self) -> impl Iterator<Item = u64> + '_ {
        let folded = self.sealed.folded().prepared.iter();
        folded.filter_map(|(_, value)| *value)
    }

    /// The constant one value folds to with what preparation admitted.
    pub fn folded_value(&self, value: crate::graph::ValueId) -> Option<u64> {
        self.sealed.folded().prepared.get(value).copied().flatten()
    }

    /// The sealed graph, which owns each operation.
    pub fn graph(&self) -> &crate::graph::SsaGraph {
        self.sealed.graph()
    }

    /// Where each dispatch reads its table: the values the artifact's facts would solve from it.
    pub fn dispatch_table_reads(&self) -> Vec<crate::indirect::DispatchTableRead> {
        let sealed = &self.sealed;
        let (function, graph) = (sealed.function(), sealed.graph());
        crate::indirect::prepared_dispatch_table_reads(
            function,
            graph,
            sealed.decompile_prep_facts(),
        )
    }

    /// The value a storage holds immediately before one operation, as a call's arguments read it.
    pub fn value_reaching(
        &self,
        op: crate::OpId,
        storage: r2source::CanonicalStorageId,
    ) -> Option<crate::graph::ValueId> {
        crate::semantic::value_reaching(&self.sealed, &self.machine_context, op, storage)
    }

    /// The constant a storage holds before the call the instruction at `instruction` makes, as
    /// its arguments read it: through promoted slots, never through memory. O(ops).
    pub fn folded_before_call(
        &self,
        instruction: u64,
        storage: r2source::CanonicalStorageId,
    ) -> Option<u64> {
        let graph = self.sealed.graph();
        let call = (graph.insts.iter()).find(|inst| {
            graph
                .op(inst.id)
                .and_then(SSAOp::call)
                .is_some_and(|call| call.instruction == Some(instruction))
        })?;
        let op = graph.op_for_inst(call.id)?;
        self.folded_value(self.value_reaching(op, storage)?)
    }

    /// The artifact: the sealed function's facts collected.
    pub fn collect<C: SsaWorkControl + ?Sized>(
        self,
        control: &C,
    ) -> Result<TrustedSsaArtifact, SsaPrepareError> {
        let Self {
            sealed,
            machine_context,
            finish,
            source_block_count,
            arch,
            entry_bytes,
        } = self;
        let artifact =
            SsaArtifact::collect_sealed(sealed, machine_context, finish, control, entry_bytes)?;
        Ok(TrustedSsaArtifact {
            artifact: Arc::new(artifact),
            source_block_count,
            arch,
        })
    }
}

/// Whether construction recovers an interface the source does not state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    Recover,
    /// Built against the convention alone, for a reader that asks no question of the interface.
    Convention,
}

/// A trusted lift built and prepared, before the seal.
struct Constructed {
    /// The function as built: its name, exits and premises are written at the seal.
    function: Prepared,
    machine_context: SourceMachineContext,
    finish: Finish,
    source_block_count: usize,
    arch: crate::Arch,
    /// Whether the recovered result is void on the premise that no caller outside the image reads it.
    closed_world: bool,
    exits: AssumedExits,
    /// The build recovery read, where it recovered the interface: what a restatement reuses.
    reuse: Option<Reuse>,
    /// Whether that build is a prior construction's, taken as it stood.
    kept: bool,
}

/// The build a recovery read and what that build read of the callees (doc/adr-callee-builds.md).
struct Reuse {
    key: BuildKey,
    provisional: Provisional,
}

/// A build offered to a construction: taken where the callees state the same to it.
struct Prior {
    key: BuildKey,
    function: Prepared,
    provisional: Provisional,
}

impl Prior {
    /// Whether the callees `key` reads state to this build what it was built against: every part
    /// equal, the argument areas only where promotion read them.
    fn builds(&self, key: &BuildKey) -> bool {
        // An area that begins below its call's pointer is outside what promotion's record covers.
        let below = |key: &BuildKey| {
            let mut ranges = key.argument_areas.iter().flat_map(|(_, area)| area);
            ranges.any(|(low, _)| *low < 0)
        };
        let unread = !self.function.argument_areas_read() && !below(&self.key) && !below(key);
        let areas = unread || self.key.argument_areas == key.argument_areas;
        let reach = same_where_asked(self.function.asked_reach(), &self.key.upward, &key.upward);
        areas && reach && self.key.without_areas() == key.without_areas()
    }
}

/// Whether two keys' upward positions agree at every (callee, position) promotion asked: a
/// callee's other positions decide nothing in the build (D365). `O(asked x log)`.
fn same_where_asked(
    asked: &BTreeSet<(u64, usize)>,
    built: &BTreeMap<u64, BTreeSet<usize>>,
    now: &BTreeMap<u64, BTreeSet<usize>>,
) -> bool {
    let upward = |key: &BTreeMap<u64, BTreeSet<usize>>, (target, position): &(u64, usize)| {
        (key.get(target)).is_some_and(|positions| positions.contains(position))
    };
    (asked.iter()).all(|pair| upward(built, pair) == upward(now, pair))
}

#[cfg(test)]
mod asked_reach_tests {
    use super::*;

    #[test]
    fn a_reach_moves_the_build_only_where_promotion_asked() {
        let asked = BTreeSet::from([(0x2000, 0)]);
        let built = BTreeMap::from([(0x2000, BTreeSet::from([0]))]);
        let elsewhere = BTreeMap::from([(0x2000, BTreeSet::from([0, 1])), (0x3000, [0].into())]);
        assert!(same_where_asked(&asked, &built, &elsewhere));
        let flipped = BTreeMap::from([(0x2000, BTreeSet::from([1]))]);
        assert!(!same_where_asked(&asked, &built, &flipped));
        assert!(!same_where_asked(&asked, &BTreeMap::new(), &built));
    }
}

/// Everything the build before recovery reads of the callees' statements: equal keys over one lift
/// build equal functions (doc/adr-callee-builds.md).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildKey {
    /// The carriers a call defines.
    clobbered: Box<[CanonicalStorageId]>,
    /// The carriers each callee keeps that a call would otherwise define.
    kept: BTreeMap<u64, Vec<CanonicalStorageId>>,
    results: BTreeMap<u64, CallBoundaryDef>,
    return_addresses: BTreeMap<u64, CanonicalStorageId>,
    security_checks: BTreeSet<u64>,
    narrow_results: crate::lanes::CallResults,
    /// The argument area each call's complete interface states, by its instruction.
    argument_areas: Vec<(u64, Vec<(i64, i64)>)>,
    reentering: BTreeSet<u64>,
    unstated_imports: BTreeMap<u64, crate::UnstatedImport>,
    conventions: SiteConventions,
    /// The argument positions through which each callee reaches only upward: all the frame walk
    /// reads of its reach, compared only where it asked (D365).
    upward: BTreeMap<u64, BTreeSet<usize>>,
    premises: BTreeSet<r2source::Premise>,
}

/// Which result carriers a call defines whole without its callee naming one: the same root, no
/// byte of which the convention keeps.
struct DefinedWhole<'a> {
    /// What a call keeps or reserves; none where it has no model, and then no carrier is.
    stays: Option<Vec<CanonicalStorageId>>,
    families: &'a RegisterFamilyInfo,
}

impl<'a> DefinedWhole<'a> {
    fn of(context: &SourceMachineContext, arch: &'a crate::Arch) -> Self {
        let stays = context.calls().map(|model| {
            let stays = model.preserved.iter().chain(model.reserved.iter());
            stays.map(|lanes| lanes.storage).collect()
        });
        Self {
            stays,
            families: arch.register_families(),
        }
    }

    /// Whether a carrier of `clobbered` holds `result` and the convention keeps none of its family.
    fn defines(&self, clobbered: &[CanonicalStorageId], result: CanonicalStorageId) -> bool {
        let Some(stays) = &self.stays else {
            return false;
        };
        let within =
            (clobbered.iter()).any(|carrier| crate::semantic::storage_contains(*carrier, result));
        let Some((start, end)) = self.families.family_extent(result.offset, result.size) else {
            return false;
        };
        let kept = |kept: &CanonicalStorageId| {
            kept.space == CanonicalStorageSpace::Register
                && kept.offset < end
                && start < kept.offset + u64::from(kept.size)
        };
        within && !stays.iter().any(kept)
    }
}

impl BuildKey {
    /// Every part but the argument areas.
    fn without_areas(&self) -> impl PartialEq + '_ {
        (
            (&self.clobbered, &self.kept, &self.results),
            &self.return_addresses,
            (&self.security_checks, &self.narrow_results),
            (&self.reentering, &self.unstated_imports, &self.premises),
            &self.conventions,
        )
    }

    /// The first part `other` states differently, for the trace.
    fn difference(&self, other: &Self) -> String {
        if self.kept != other.kept {
            format!("kept set: {:?} against {:?}", self.kept, other.kept)
        } else if self.results != other.results {
            format!(
                "result carrier: {:?} against {:?}",
                self.results, other.results
            )
        } else if self.return_addresses != other.return_addresses {
            "return address".to_owned()
        } else if self.security_checks != other.security_checks {
            "security check".to_owned()
        } else if self.narrow_results != other.narrow_results {
            "result width".to_owned()
        } else if self.without_areas() != other.without_areas() {
            "premise or import".to_owned()
        } else if self.argument_areas != other.argument_areas {
            "argument area".to_owned()
        } else {
            "argument reach".to_owned()
        }
    }

    /// O(callees x clobbered + call sites).
    fn of(
        (context, arch): (&SourceMachineContext, &crate::Arch),
        callees: &CalleeBoundaries,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Self {
        let clobbered = context.call_clobbered_carriers();
        let whole = DefinedWhole::of(context, arch);
        let results = (callees.results.iter()).filter(|(target, _)| {
            let result = callees.result_storages.get(*target);
            !result.is_some_and(|result| whole.defines(clobbered, *result))
        });
        let results = results
            .map(|(target, def)| (*target, def.clone()))
            .collect();
        let defined = |kept: &CanonicalStorageId| {
            (clobbered.iter())
                .any(|carrier| crate::semantic::register_storages_overlap(*kept, *carrier))
        };
        let kept = callees.preserved.iter().filter_map(|(target, carriers)| {
            let kept = carriers.iter().copied().filter(defined).collect::<Vec<_>>();
            (!kept.is_empty()).then_some((*target, kept))
        });
        let areas = context.raw_call_sites().keys().filter_map(|instruction| {
            Some((*instruction, context.call_reads(Some(*instruction))?.stack?))
        });
        Self {
            clobbered: clobbered.into(),
            kept: kept.collect(),
            results,
            return_addresses: callees.return_addresses.clone(),
            security_checks: callees.security_checks.clone(),
            narrow_results: crate::lanes::CallResults::of(context),
            argument_areas: areas.collect(),
            reentering: evidence.reentering.clone(),
            unstated_imports: evidence.unstated_imports.clone(),
            conventions: callees.conventions.clone(),
            upward: (evidence.reach.iter())
                .map(|(target, reach)| {
                    let upward = reach.iter().filter(|(_, reach)| reach.is_upward());
                    (*target, upward.map(|(position, _)| *position).collect())
                })
                .filter(|(_, positions): &(u64, BTreeSet<usize>)| !positions.is_empty())
                .collect(),
            premises: premises.clone(),
        }
    }
}

impl Constructed {
    /// The function named, its exits and premises recorded, and sealed in its context.
    fn seal<C: SsaWorkControl + ?Sized>(self, control: &C) -> Result<TrustedSeal, SsaPrepareError> {
        let Self {
            mut function,
            machine_context,
            finish,
            source_block_count,
            arch,
            closed_world,
            exits,
            reuse,
            kept: _,
        } = self;
        drop(reuse);
        // A name radare2 derived from the entry address restates the address and is left absent.
        if let SsaArtifactProvenance::TrustedSource(source) = &finish.provenance {
            let presented = source.presentation().display_name();
            if !r2source::display_names::is_generated_function_name(presented) {
                function = function.named(presented.to_string());
            }
        }
        let mut function = function.with_assumed_exits(&exits);
        if closed_world {
            function = function.assuming(r2source::Premise::ClosedWorld);
        }
        control.poll()?;
        let entry_bytes = r2il::allocation::live_bytes();
        let sealed = function.seal(&machine_context)?;
        control.poll()?;
        Ok(TrustedSeal {
            sealed,
            machine_context,
            finish,
            source_block_count,
            arch,
            entry_bytes,
        })
    }

    /// The first part of this construction that `other` states differently, by name.
    fn difference(&self, other: &Self) -> Option<&'static str> {
        let text = |value: &dyn std::fmt::Debug| format!("{value:?}");
        let facts =
            |reuse: &Option<Reuse>| reuse.as_ref().map(|held| text(&held.provisional.facts));
        let boundary = |finish: &Finish| finish.body_boundary.clone();
        if text(&self.function) != text(&other.function) {
            Some("function")
        } else if text(&self.machine_context) != text(&other.machine_context) {
            Some("machine context")
        } else if facts(&self.reuse) != facts(&other.reuse) {
            Some("provisional facts")
        } else if boundary(&self.finish) != boundary(&other.finish) {
            Some("body boundary")
        } else if (self.closed_world, &self.exits) != (other.closed_world, &other.exits) {
            Some("premises")
        } else {
            None
        }
    }
}

/// A trusted lift built and its interface recovered, not yet sealed: what a restatement of its
/// callees updates (doc/adr-callee-builds.md).
pub struct TrustedConstruction {
    constructed: Constructed,
    lifted: TrustedLiftedFunction,
}

impl TrustedConstruction {
    /// The context the function was built in: its interface, recovered or stated.
    pub const fn machine_context(&self) -> &SourceMachineContext {
        &self.constructed.machine_context
    }

    /// Whether a restatement of the callees can keep this build: its interface was recovered and
    /// no pass over it exhausted.
    pub const fn restatable(&self) -> bool {
        self.constructed.reuse.is_some()
    }

    /// The construction sealed, its facts not yet collected.
    pub fn seal<C: SsaWorkControl + ?Sized>(
        self,
        control: &C,
    ) -> Result<TrustedSeal, SsaPrepareError> {
        let Self {
            constructed,
            lifted,
        } = self;
        drop(lifted);
        constructed.seal(control)
    }

    /// This construction against other callee statements, and whether its build was kept
    /// (`BuildKey`); equal to `construct` over the same lift, which a debug build checks.
    pub fn restated<C: SsaWorkControl + ?Sized>(
        self,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<(Self, bool), SsaPrepareError> {
        let Self {
            constructed,
            lifted,
        } = self;
        let Constructed {
            function, reuse, ..
        } = constructed;
        let prior = reuse.map(|Reuse { key, provisional }| Prior {
            key,
            function,
            provisional,
        });
        let recovery = Recovery::Recover;
        let constructed = TrustedSsaArtifact::construct(
            &lifted, arch, control, evidence, premises, recovery, prior,
        )?;
        let kept = constructed.kept;
        #[cfg(debug_assertions)]
        if kept {
            let full = TrustedSsaArtifact::construct(
                &lifted, arch, control, evidence, premises, recovery, None,
            )?;
            if let Some(part) = constructed.difference(&full) {
                panic!(
                    "{:#x}: a restated construction differs from a rebuild in its {part}",
                    constructed.function.entry
                );
            }
        }
        Ok((
            Self {
                constructed,
                lifted,
            },
            kept,
        ))
    }

    /// The first part of this construction that `other` states differently, by name: a test's
    /// comparison of a restated construction with one built anew.
    pub fn difference(&self, other: &Self) -> Option<&'static str> {
        self.constructed.difference(&other.constructed)
    }
}

/// See [`SsaArtifact::register_identity_census`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegisterIdentityCensus {
    pub split_entry_families: usize,
}

/// What a decompilation preparation is given besides the blocks.
///
/// Rust has no default arguments, and the gap had been filled by a chain of
/// `for_decompile_with_...` constructors, each adding one of these values and
/// announcing it in its own name. One structure with a default says the same
/// thing once, and lets the call site name the fields it actually sets.
#[derive(Default)]
pub struct DecompileInputs<'a> {
    pub arch: Option<&'a crate::Arch>,
    pub function_interface: Option<SourceFunctionInterface>,
    pub machine_roles: SourceMachineRoles,
    /// The function's convention and its calls'; without them a call reads and clobbers every
    /// outermost register (RULING 2.1).
    pub conventions: Option<r2source::Conventions>,
    pub call_site_interfaces: Vec<SourceCallSiteInterface>,
    /// Call sites the source proved are tail calls, by identity. A tail call
    /// through a relocated slot is a `BranchInd` that only a context knowing
    /// the identity certifies as a call.
    pub tail_call_identities: Vec<SourceCallSiteIdentity>,
    /// Which registers each direct callee's body proves it leaves untouched,
    /// so construction defines nothing a call did not touch.
    pub callee_preserved_carriers: CalleePreservedCarriers,
    /// What each direct callee's own boundary returns, by entry address. A
    /// result the convention calls unaffected is still defined by the call.
    pub callee_interfaces: BTreeMap<u64, SourceFunctionInterface>,
}

/// Release the base of every INSERT whose demanded bytes lie in its lane.
///
/// The demand is rooted at what leaves through the return registers, so it
/// is computed over the graph of the function as prepared. Only a function
/// with an INSERT into a value that is not a constant can release anything,
/// and only one pays for the pass.
fn release_undemanded_bytes(
    function: &SSAFunction,
    machine_context: &SourceMachineContext,
    graph: &SsaGraph,
) -> EditPlan {
    let inserts = function
        .blocks()
        .iter()
        .flat_map(|block| block.ops())
        .any(|op| {
            matches!(op, SSAOp::Insert(insert)
                if function.var(insert.src).constant_bits().is_none())
        });
    if !inserts {
        return EditPlan::new();
    }
    let interface = machine_context.function_interface();
    let return_storages = (interface.into_iter())
        .flat_map(|interface| interface.return_kind().storages())
        .collect::<Vec<_>>();
    // A return whose result is unproven is a residual: it reads no register (ROADMAP D340). A
    // `void` return reads none either, and its bases are released by D342.
    let unproven = interface.map(r2source::SourceFunctionInterface::return_kind)
        == Some(r2source::SourceFunctionReturn::Unproven);
    let live_out = match unproven {
        true => crate::liveout::FunctionLiveOut::default(),
        false => crate::liveout::FunctionLiveOut::compute(function, graph, &return_storages),
    };
    if !crate::demand::exits_are_named(function, &live_out) {
        r2il::refusal_evidence!(
            "demanded-bytes",
            "an exit hands registers to code outside the graph; no base is released"
        );
        return EditPlan::new();
    }
    let demand = crate::demand::DemandedBytes::of(graph, &live_out, Some(machine_context));
    function.release_undemanded_insert_bases(graph, &demand)
}

/// The def-use of one body as it was lifted, entered at `entry` (not always its lowest block), with no pass that folds a use away.
///
/// Which listed number is a step towards another is read off this, so the listing and the
/// reference index answer it from the same graph.
pub fn def_use_graph(
    blocks: &[R2ILBlock],
    arch: Option<&crate::Arch>,
    entry: u64,
) -> Result<SsaGraph, SsaPrepareError> {
    let function = SSAFunction::from_blocks_raw_entered_at(blocks, arch, entry)?;
    let graph = Lifted::new(function)
        .validate()
        .map_err(integrity_refusal)?
        .def_use_graph();
    match graph.blocks.is_empty() {
        true => Err(malformed_ssa_input()),
        false => Ok(graph),
    }
}

impl SsaArtifact {
    #[cfg(test)]
    fn new(function: SSAFunction) -> Self {
        Self::new_with_context(function, SourceMachineContext::from_blocks(&[], None))
    }

    /// The artifact of a function a test prepared itself.
    #[cfg(test)]
    fn from_prepared(prepared: Prepared, machine_context: SourceMachineContext) -> Self {
        Self::seal_finished(
            prepared,
            machine_context,
            Finish::manual(),
            &UncheckedSsaWorkControl,
        )
        .expect("an unchecked control never stops")
    }

    fn new_with_context(function: SSAFunction, machine_context: SourceMachineContext) -> Self {
        Self::new_with_context_and_control(function, machine_context, &UncheckedSsaWorkControl)
            .expect("internal SSA artifact construction requires a validated function")
    }

    fn new_with_context_and_control<C: SsaWorkControl + ?Sized>(
        function: SSAFunction,
        machine_context: SourceMachineContext,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::new_with_context_control_and_provenance(
            function,
            machine_context,
            SsaArtifactProvenance::Manual,
            control,
        )
    }

    fn new_with_context_control_and_provenance<C: SsaWorkControl + ?Sized>(
        function: SSAFunction,
        machine_context: SourceMachineContext,
        provenance: SsaArtifactProvenance,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        let prepared = Lifted::new(function)
            .validate()
            .map_err(integrity_refusal)?;
        Self::seal_finished(
            prepared,
            machine_context,
            Finish {
                provenance,
                ..Finish::manual()
            },
            control,
        )
    }

    /// Seal a prepared function and derive the artifact's facts from it.
    fn seal_finished<C: SsaWorkControl + ?Sized>(
        prepared: Prepared,
        machine_context: SourceMachineContext,
        finish: Finish,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        let prepare_entry_bytes = r2il::allocation::live_bytes();
        let sealed = prepared.seal(&machine_context)?;
        Self::collect_sealed(
            sealed,
            machine_context,
            finish,
            control,
            prepare_entry_bytes,
        )
    }

    /// Collect a sealed function's facts into the artifact.
    fn collect_sealed<C: SsaWorkControl + ?Sized>(
        sealed: Sealed,
        machine_context: SourceMachineContext,
        finish: Finish,
        control: &C,
        prepare_entry_bytes: Option<usize>,
    ) -> Result<Self, SsaPrepareError> {
        let mut artifact =
            sealed.into_artifact(machine_context, finish, control, prepare_entry_bytes)?;
        artifact.seal_body_proven_interface();
        artifact.seal_dead_frame_stores();
        artifact.seal_caller_stack_slots();
        Ok(artifact)
    }

    /// Read the body's own facts into the function interface, so that a
    /// caller correlated against it and the signature derived from it see one
    /// interface rather than the capture's and a promoted copy of it.
    fn seal_body_proven_interface(&mut self) {
        self.seal_body_result();
        let Some(index) = body_proven_format_parameter(self) else {
            return;
        };
        let Some(interface) = self.machine_context.function_interface() else {
            return;
        };
        if let Ok(sealed) = interface.clone().with_body_proven_format_parameter(index) {
            self.machine_context.seal_function_interface(sealed);
        }
    }

    /// What the body's returns leave in the result lanes of a function a declaration states, which
    /// recovery never read (doc/adr-result-side.md, "Declaration against body").
    fn seal_body_result(&mut self) {
        let context = &self.machine_context;
        let declared = (context.function_interface()).filter(|own| own.types_are_declared());
        let (Some(interface), Some(model)) = (declared, context.convention()) else {
            return;
        };
        let body = crate::recover_interface::body_result_lanes(
            self.function(),
            self.graph(),
            self.facts(),
            model,
        );
        let sealed = interface.clone().with_body_result(body);
        self.machine_context.seal_function_interface(sealed);
    }

    /// Run-local identity shared by every clone and downstream proof derived
    /// from this exact artifact instance.
    pub const fn authority(&self) -> &SsaArtifactAuthority {
        &self.authority
    }

    pub fn provenance_kind(&self) -> SsaArtifactProvenanceKind {
        match &self.provenance {
            SsaArtifactProvenance::Manual => SsaArtifactProvenanceKind::Manual,
            SsaArtifactProvenance::TrustedSource(_) => SsaArtifactProvenanceKind::TrustedSource,
        }
    }

    pub fn from_blocks(blocks: &[R2ILBlock], arch: Option<&crate::Arch>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_with_arch(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    pub fn raw(blocks: &[R2ILBlock], arch: Option<&crate::Arch>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_raw(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    /// Build raw SSA with an explicit, revision-bound function interface.
    pub fn raw_with_interface(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::raw_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build raw SSA with explicit, revision-bound function and callsite
    /// interfaces. A missing function interface does not weaken the per-callsite
    /// revision and carrier checks.
    pub fn raw_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_raw(blocks, arch)?,
            SourceMachineContext::from_blocks_with_interfaces(
                blocks,
                arch,
                function_interface,
                SourceMachineRoles::default(),
                None,
                call_site_interfaces,
            ),
        ))
    }

    pub fn for_decompile(blocks: &[R2ILBlock], arch: Option<&crate::Arch>) -> Option<Self> {
        Self::for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build a complete decompiler SSA artifact under cooperative control.
    ///
    /// Work is assembled in local values. A stop returns an explicit error and
    /// drops all intermediate state rather than exposing a partial artifact.
    pub fn for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let machine_context = SourceMachineContext::from_blocks(blocks, arch);
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::none(),
            &machine_context,
            &CalleeBoundaries::default(),
            None,
            control,
        )?;
        control.poll()?;
        Self::seal_finished(function, machine_context, Finish::manual(), control)
    }

    /// Build decompiler-prepared SSA with an explicit function interface.
    pub fn for_decompile_with_interface(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::for_decompile_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build decompiler-prepared SSA with explicit, revision-bound function and
    /// callsite interfaces.
    pub fn for_decompile_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Option<Self> {
        Self::for_decompile_with_interfaces_and_machine_roles(
            blocks,
            arch,
            function_interface,
            SourceMachineRoles::default(),
            call_site_interfaces,
        )
    }

    /// Build decompiler-prepared SSA with independently source-owned machine
    /// roles. Machine geometry is not contingent on an exact prototype.
    pub fn for_decompile_with_interfaces_and_machine_roles(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Option<Self> {
        Self::for_decompile_with(
            blocks,
            DecompileInputs {
                arch,
                function_interface,
                machine_roles,
                call_site_interfaces,
                ..Default::default()
            },
        )
    }

    /// Build decompiler-prepared SSA from the blocks and whatever the source
    /// knows about them.
    pub fn for_decompile_with(blocks: &[R2ILBlock], inputs: DecompileInputs<'_>) -> Option<Self> {
        let DecompileInputs {
            arch,
            function_interface,
            machine_roles,
            conventions,
            call_site_interfaces,
            tail_call_identities,
            callee_preserved_carriers,
            callee_interfaces,
        } = inputs;
        let callees =
            CalleeBoundaries::from_interfaces(arch, &callee_preserved_carriers, &callee_interfaces);
        let mut machine_context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            blocks,
            arch,
            function_interface,
            machine_roles,
            conventions,
            call_site_interfaces,
            tail_call_identities,
        );
        machine_context.set_callee_preserved(callees.preserved().clone());
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::new(&machine_context),
            &machine_context,
            &callees,
            None,
            &UncheckedSsaWorkControl,
        )
        .ok()?;
        Some(
            Self::seal_finished(
                function,
                machine_context,
                Finish::manual(),
                &UncheckedSsaWorkControl,
            )
            .expect("internal SSA artifact construction requires a validated function"),
        )
    }

    /// Build controlled decompiler SSA from explicit source interfaces, machine roles and call effect.
    pub fn for_decompile_with_interfaces_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        conventions: Option<r2source::Conventions>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            blocks,
            arch,
            function_interface,
            machine_roles,
            conventions,
            call_site_interfaces,
        );
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::new(&machine_context),
            &machine_context,
            &CalleeBoundaries::default(),
            None,
            control,
        )?;
        control.poll()?;
        Self::seal_finished(function, machine_context, Finish::manual(), control)
    }

    pub fn for_patterns(blocks: &[R2ILBlock], arch: Option<&crate::Arch>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_patterns(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    pub fn for_symbolic(blocks: &[R2ILBlock], arch: Option<&crate::Arch>) -> Option<Self> {
        Self::for_symbolic_with_interfaces(blocks, arch, None, Vec::new())
    }

    /// Build symbolic SSA with an explicit, revision-bound function interface.
    pub fn for_symbolic_with_interface(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::for_symbolic_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build symbolic SSA with exact function and callsite interfaces.
    pub fn for_symbolic_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&crate::Arch>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Option<Self> {
        let function = SSAFunction::from_blocks_raw(blocks, arch)?;
        Some(Self::new_with_context(
            function,
            SourceMachineContext::from_blocks_with_interfaces(
                blocks,
                arch,
                function_interface,
                SourceMachineRoles::default(),
                None,
                call_site_interfaces,
            ),
        ))
    }

    pub fn function(&self) -> &SSAFunction {
        self.sealed.function()
    }

    /// The decompiler-prep facts, collected once when the function was
    /// sealed.
    pub fn decompile_prep_facts(&self) -> &DecompilePrepFacts {
        self.sealed.decompile_prep_facts()
    }

    /// The formal a value is: one the entry proves, which the prep facts
    /// hold, or one the address facts prove holds exactly that parameter
    /// with nothing added -- a copy or a reload of it. The entry's answer is
    /// authoritative where both answer.
    ///
    /// Two owners, each for its own evidence. The address facts are
    /// collected over the prep facts, so writing their answer back into the
    /// prep facts left the two describing different functions. O(1).
    pub fn formal_parameter_of(&self, value: ValueId) -> Option<usize> {
        self.decompile_prep_facts()
            .formal_parameter_of(value)
            .or_else(|| self.addressed_formal(value))
    }

    /// The formal whose bits a view names: the root itself, or a formal that
    /// is exactly those bits of the root -- `esi` of `rsi`, which a widening
    /// of `esi` views as `rsi`'s low 32 bits. O(formals).
    pub fn formal_parameter_of_view(
        &self,
        view: &crate::view::ValueView<ValueId>,
    ) -> Option<usize> {
        let prep = self.decompile_prep_facts();
        let names = |formal: ValueId| {
            let lane = prep.view(formal);
            lane.root == view.root
                && lane.prefix_bits == view.prefix_bits
                && lane.extension == crate::view::ViewExtension::Exact
        };
        self.formal_parameter_of(view.root).or_else(|| {
            self.formal_parameters()
                .find_map(|(formal, index)| names(formal).then_some(index))
        })
    }

    /// Every value that is a formal, with its parameter: the entry's first,
    /// then the address facts', each in its own order.
    pub fn formal_parameters(&self) -> impl Iterator<Item = (ValueId, usize)> + '_ {
        let prep = self.decompile_prep_facts();
        let entry = prep
            .formal_parameters
            .iter()
            .map(|(value, index)| (value, *index));
        let addressed = self
            .addresses()
            .parameter_expressions
            .iter()
            .filter(|(_, expression)| expression.terms.is_empty() && expression.offset == 0)
            .filter_map(move |(value, expression)| {
                (!prep.formal_parameters.contains(value)).then_some((value, expression.parameter))
            });
        entry.chain(addressed)
    }

    /// The parameter a value holds exactly, by the address facts.
    fn addressed_formal(&self, value: ValueId) -> Option<usize> {
        let expression = self.addresses().parameter_expression(value)?;
        (expression.terms.is_empty() && expression.offset == 0).then_some(expression.parameter)
    }

    /// What the calling convention says this function's caller may read.
    ///
    /// Derived from the machine context the snapshot carried, so it is the
    /// source's account of the ABI rather than a guess made from a name.
    pub fn abi(&self) -> Option<crate::abi::Formals<'_>> {
        crate::abi::Formals::of(&self.machine_context)
    }

    /// The value liveness and storage spans the build computed and dropped, computed again the
    /// same way for a test that reads them.
    #[cfg(test)]
    pub(crate) fn recomputed_liveness(
        &self,
    ) -> (crate::liveness::ValueLiveness, crate::span::StorageSpans) {
        let graph = self.graph();
        let mut content = crate::liveness::ValueContent::of(graph, Some(&self.machine_context));
        content.declare_same_content(&same_content_reads(
            &self.facts.structured.memory_accesses,
            &self.facts.memory,
        ));
        let values = crate::liveness::ValueLiveness::compute_with_relocations(
            graph,
            self.liveness.live_out(),
            &crate::dense::IdMap::default(),
            content,
            self.liveness.ignored_reads(),
        );
        let spans = crate::span::StorageSpans::compute(graph, &values);
        (values, spans)
    }

    /// Carriers this function moves through memory that already holds them.
    ///
    /// A register the loop spills to a frame slot and reloads is not what
    /// carried the value; the slot is. Published so a renderer can name one
    /// variable where the machine used two.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
        )
    )]
    pub fn memory_mirrored_carriers(&self) -> std::collections::BTreeSet<crate::SemanticId> {
        let structured = &self.facts.structured;
        let objects = &self.facts.objects;
        let mut mirrored = std::collections::BTreeSet::new();
        for loop_fact in structured.loops.values() {
            for carrier in &loop_fact.carriers {
                let members = carrier.coalescing_values();
                if crate::mirror::carrier_mirrors_memory(
                    structured,
                    objects,
                    self.graph(),
                    loop_fact,
                    &members,
                ) {
                    mirrored.insert(carrier.id);
                }
            }
        }
        mirrored
    }

    /// The merges no value observation depends on.
    ///
    /// Published rather than removed. Rules choosing among candidates should skip
    /// these; rules simulating machine state still need them, because a merge can
    /// be the only statement of what a register holds at a loop head.
    pub const fn unobserved_merges(&self) -> &crate::deadphi::DeadPhis {
        &self.unobserved_merges
    }

    /// Complete upstream-certified domain of pure values no program
    /// observation depends on.
    pub const fn unobserved_values(&self) -> &crate::dense::IdSet<crate::graph::ValueId> {
        self.unobserved_merges.unobserved_values()
    }

    /// The values this function hands back, which have no reader inside it.
    pub const fn live_out(&self) -> &crate::liveout::FunctionLiveOut {
        self.liveness.live_out()
    }

    /// Every liveness fact together, for a consumer that needs more than one.
    pub const fn liveness(&self) -> &ArtifactLiveness {
        &self.liveness
    }

    /// Reads the text never performs, which hold nothing live.
    pub const fn ignored_reads(&self) -> &std::collections::BTreeSet<crate::graph::UseSite> {
        self.liveness.ignored_reads()
    }

    pub fn graph(&self) -> &SsaGraph {
        self.sealed.graph()
    }

    /// Whether `value` is defined where operation `ordinal` of the block at `block_addr` reads (the
    /// rule the boundary facts are checked by); `usize::MAX` asks at the block's end.
    pub fn value_defined_before(&self, value: ValueId, block_addr: u64, ordinal: usize) -> bool {
        crate::integrity::defined_before(
            self.sealed.function(),
            self.sealed.graph(),
            value,
            block_addr,
            ordinal,
        )
    }

    pub fn facts(&self) -> &PreparedFunctionFacts {
        &self.facts
    }

    pub const fn machine_context(&self) -> &SourceMachineContext {
        &self.machine_context
    }

    /// The source's interface for one of this function's call sites.
    ///
    /// A call site is known to the source by the instruction it was lifted
    /// from, which the call-site fact carries as its raw identity.
    pub fn call_site_interface(&self, call_site: CallSiteId) -> Option<&SourceCallSiteInterface> {
        self.facts
            .call_sites
            .by_id
            .get(&call_site)?
            .raw_identity
            .and_then(|identity| self.machine_context.call_site_interface(identity))
    }

    pub const fn aggregate_accesses(&self) -> &AggregateAccessProjectionFacts {
        &self.aggregate_accesses
    }

    /// Each call site's member-call row, derived beside the projections (S32).
    pub const fn member_calls(&self) -> &crate::member_call::MemberCalls {
        &self.member_calls
    }

    pub fn with_assumptions(&self, assumptions: &AssumptionSet) -> Self {
        let mut facts = PreparedFunctionFacts::collect_with_context(
            self.function(),
            Some(self.decompile_prep_facts()),
            self.graph(),
            assumptions,
            &self.machine_context,
            "assume",
        )
        .expect("assumptions reach no fixpoint, and this function's collection settled");
        facts.body_boundary.clone_from(&self.facts.body_boundary);
        let aggregate_accesses =
            collect_aggregate_access_projections(&crate::aggregate_access::ProjectionSources {
                graph: self.graph(),
                views: &self.decompile_prep_facts().views,
                addresses: &facts.addresses,
                accesses: &facts.structured.memory_accesses,
                stack_slots: &facts.certificates.stack_slots,
                machine_context: &self.machine_context,
            });
        let member_calls = crate::member_call::collect_member_calls(
            self.graph(),
            &facts.call_sites,
            &aggregate_accesses,
            &self.machine_context,
        );
        let mut assumed = Self {
            authority: SsaArtifactAuthority::new(),
            provenance: SsaArtifactProvenance::Manual,
            sealed: self.sealed.clone(),
            liveness: self.liveness.clone(),
            unobserved_merges: self.unobserved_merges.clone(),
            facts,
            machine_context: self.machine_context.clone(),
            aggregate_accesses,
            member_calls,
            spellings: self.spellings.clone(),
        };
        assumed.seal_dead_frame_stores();
        assumed.seal_caller_stack_slots();
        assumed
    }

    /// Spellings the source carried for the addresses this function calls.
    pub fn display_names(&self) -> &r2source::DisplayNames {
        &self.spellings.display_names
    }

    /// State what each entry of a code pointer table names, and how radare2
    /// spells it.
    ///
    /// A slot a relocation fills holds no address the file states, so the
    /// function an entry names is the only statement of what a load of that
    /// slot is, and the name is what a rendering can spell in its place.
    pub fn record_code_pointer_entries(
        &mut self,
        entries: impl IntoIterator<Item = (u64, u64, Option<String>)>,
    ) {
        let mut recorded = BTreeMap::new();
        for (address, target, name) in entries {
            recorded.insert(address, target);
            if let Some(name) = name {
                self.spellings.display_names.insert_function(target, name);
            }
        }
        self.machine_context.set_code_pointer_entries(recorded);
    }

    /// The source's own prototype text for this function, where it had one.
    pub fn source_signature(&self) -> Option<&r2source::SourceSignaturePresentation> {
        match &self.provenance {
            SsaArtifactProvenance::TrustedSource(source) => source.presentation().signature(),
            SsaArtifactProvenance::Manual => None,
        }
    }

    /// The whole table, for a consumer that outlives the artifact.
    pub fn user_operations(&self) -> Arc<[String]> {
        Arc::clone(&self.spellings.user_operations)
    }

    pub fn objects(&self) -> &ObjectModel {
        &self.facts.objects
    }

    /// What each value can hold, as the ascent and the narrowing left it.
    ///
    /// One interval per value, narrowed at the definition site rather than at
    /// every point that reads it, so this is what the value can hold anywhere
    /// it is live and not what it holds at a particular instruction. A caller
    /// that wants the second has to say so; a caller that prints this as the
    /// first is claiming more than was proved.
    pub fn values(&self) -> &crate::values::ValueRanges {
        &self.facts.values
    }

    pub fn addresses(&self) -> &crate::AddressProvenanceFacts {
        &self.facts.addresses
    }

    pub fn memory(&self) -> &MemorySSAFacts {
        &self.facts.memory
    }

    /// Whether nothing outside the function can reach a frame object: no
    /// address naming it leaves the body.
    pub fn stack_object_is_private(&self, object: ObjectId) -> bool {
        self.facts.private_stack_objects.contains(&object)
    }

    pub fn predicates(&self) -> &PredicateFacts {
        &self.facts.predicates
    }

    pub fn call_sites(&self) -> &CallSiteFacts {
        &self.facts.call_sites
    }

    pub fn structured(&self) -> &StructuredDataflowFacts {
        &self.facts.structured
    }

    pub fn control_domains(&self) -> &crate::semantic::ControlDomainFacts {
        &self.facts.control_domains
    }

    /// Whether frame management owns this stack object: the slot a callee-saved
    /// carrier round-trips through, or the one a return control reads from.
    pub fn frame_managed_stack_object(&self, object: crate::ObjectId) -> bool {
        let certificates = self.certificates();
        certificates.stack_frame_round_trips.contains_key(&object)
            || certificates
                .machine_return_controls
                .values()
                .any(|certificate| certificate.claimed_stack_object() == Some(object))
    }

    /// Whether this stack object is one the rendering can declare and name.
    ///
    /// A frame-management slot is not a program object, and neither is one
    /// whose extent nothing states.
    /// The formal parameter a frame slot is the home of, proved in this preparation: a declarable
    /// entry-relative slot a parameter's value is stored into (doc/adr-frame-model.md, P4.5).
    pub fn proved_parameter_home(&self, object: crate::ObjectId) -> Option<u32> {
        let slot = self.certificates().stack_slots.get(&object)?;
        if slot.source_slot.is_some()
            || slot.size.is_none()
            || slot.base != crate::StackAddressBase::StackPointer
            || !self.declarable_stack_object(object)
        {
            return None;
        }
        let facts = self.decompile_prep_facts();
        slot.stored_values
            .iter()
            .find_map(|value| facts.formal_parameter_of(value))
            .and_then(|index| u32::try_from(index).ok())
    }

    /// What a frame slot is: the role its declaration states, or a parameter home the frame proves.
    pub fn stack_slot_role(
        &self,
        object: crate::ObjectId,
    ) -> Option<r2source::SourceStackSlotRole> {
        if let Some(declared) = self.certificates().stack_slots.get(&object)?.source_slot {
            return Some(declared.role());
        }
        let parameter_index = self.proved_parameter_home(object)?;
        let home_storage = self
            .machine_context()
            .function_interface()?
            .parameters()
            .get(parameter_index as usize)?
            .register_storage()?;
        Some(r2source::SourceStackSlotRole::ParameterHome {
            parameter_index,
            home_storage,
        })
    }

    /// The source type of a frame slot: its declaration's, or a proved home's parameter type at
    /// the home's width.
    pub fn stack_slot_logical_type(&self, object: crate::ObjectId) -> Option<u32> {
        let slot = self.certificates().stack_slots.get(&object)?;
        if let Some(declared) = slot.source_slot {
            return declared.logical_type();
        }
        let index = self.proved_parameter_home(object)?;
        let value = self
            .machine_context()
            .function_interface()?
            .parameter_logical_value(index as usize)?;
        (value.carrier().size_bits() == u64::from(slot.size?) * 8).then(|| value.type_id())
    }

    /// Why the extent this object is declared at is assumed, where nothing declares or proves it.
    pub fn extent_assumption(&self, object: crate::ObjectId) -> Option<crate::ExtentAssumption> {
        let slot = self.certificates().stack_slots.get(&object)?;
        if slot.source_slot.is_some() {
            return None;
        }
        // An unbounded index may pass any reach, so a reach is the extent only when every index is bounded.
        let assumption = match slot.array_layout {
            _ if slot.unbounded_index => Some(crate::ExtentAssumption::UnboundedIndex),
            crate::StackArrayLayoutDisposition::Proven(_) => None,
            _ if self.objects().callee_write_reach.contains_key(&object) => None,
            _ => self
                .objects()
                .frame_reach
                .escaped(object)
                .then_some(crate::ExtentAssumption::EscapedAddress),
        }?;
        // Asked last: declarability scans the function's accesses.
        (self.declarable_stack_object(object) && self.proved_parameter_home(object).is_none())
            .then_some(assumption)
    }

    /// Why the frame object a memory obligation reads or writes has an assumed extent, if it does.
    pub fn obligation_extent_assumption(
        &self,
        id: crate::SemanticObligationId,
    ) -> Option<crate::ExtentAssumption> {
        use crate::{SemanticObligationComponent as Component, SemanticObligationKind as Kind};
        // A private frame read is a value producer; its access is still one the extent may not cover.
        let is_write = match (id.kind, id.component) {
            (Kind::ObservableMemoryRead | Kind::LiveValueProducer, Component::MemoryAccess(_)) => {
                false
            }
            (Kind::ObservableMemoryWrite, Component::MemoryAccess(_)) => true,
            _ => return None,
        };
        let crate::SemanticSourceSite::GraphInstruction(inst) =
            self.obligations().obligations().get(&id)?.source
        else {
            return None;
        };
        let access = self.memory_certificate_for_inst(inst, is_write)?;
        self.extent_assumption(access.object)
    }

    pub fn declarable_stack_object(&self, object: crate::ObjectId) -> bool {
        !self.frame_managed_stack_object(object)
            && !self.call_return_address_object(object)
            && !self.compiler_inserted_stack_object(object)
            && self
                .certificates()
                .stack_slots
                .get(&object)
                .is_some_and(|slot| slot.size.is_some_and(|size| size > 0))
    }

    /// Whether every access to this object is a call pushing its return address: the callee's frame, not a local.
    pub fn call_return_address_object(&self, object: crate::ObjectId) -> bool {
        self.object_accessed_only_by(
            object,
            &self.certificates().call_return_address_stores,
            true,
        )
    }

    /// Whether every access to this object is one a decided compiler-inserted check made: the canary.
    pub fn compiler_inserted_stack_object(&self, object: crate::ObjectId) -> bool {
        self.object_accessed_only_by(object, &self.certificates().compiler_inserted, false)
    }

    /// Whether the object has an access and every access is an instruction of `insts` (each a write, if asked).
    fn object_accessed_only_by(
        &self,
        object: crate::ObjectId,
        insts: &crate::dense::IdSet<crate::graph::InstId>,
        writes_only: bool,
    ) -> bool {
        let stores = insts;
        let mut accesses = self
            .structured()
            .memory_accesses
            .values()
            .filter(|access| access.object == object);
        let mut any = false;
        let pushed = accesses.all(|access| {
            any = true;
            (access.is_write || !writes_only) && stores.contains(access.id.inst)
        });
        any && pushed
    }

    /// The entry-relative offset of a stack object addressed from the entry stack pointer.
    pub(crate) fn entry_stack_offset(&self, object: crate::ObjectId) -> Option<i64> {
        match self.objects().object(object).map(|found| &found.kind) {
            Some(crate::ObjectKind::StackSlot {
                base: crate::StackAddressBase::StackPointer,
                offset,
                ..
            }) => Some(*offset),
            _ => None,
        }
    }

    /// Whether this stack object is the caller's storage rather than this body's: the return
    /// address, a stack-passed argument, or what the loader left at a process entry.
    pub fn caller_stack_object(&self, object: crate::ObjectId) -> bool {
        self.entry_stack_offset(object)
            .is_some_and(|offset| self.caller_frame_offset(offset))
    }

    /// Whether an offset from the entry stack pointer lies in the caller's storage, by the
    /// convention's one rule (`ConventionModel::owner`): a Microsoft x64 home is the callee's.
    pub fn caller_frame_offset(&self, offset: i64) -> bool {
        !self.machine_context().stack_owner(offset).callee_owned()
    }

    /// Whether this object is the slot the caller pushed the return address into.
    ///
    /// The machine states where that is: a convention whose call pushes the return
    /// address says so as a return mechanism, and the slot it names is at the
    /// pointer the function was entered with. It is caller storage like a stack
    /// argument, but it is not an argument -- nothing in the program assigns it,
    /// and a rendering that declares it as a local reads a name it never wrote.
    pub fn return_address_stack_object(&self, object: crate::ObjectId) -> bool {
        let mechanism = self
            .machine_context()
            .function_interface()
            .and_then(crate::SourceFunctionInterface::return_mechanism);
        mechanism.is_some_and(|mechanism| {
            self.entry_stack_offset(object) == Some(mechanism.stack_offset())
        })
    }

    pub fn certificates(&self) -> &crate::semantic::PreparedFunctionCertificates {
        &self.facts.certificates
    }

    pub fn obligations(&self) -> &crate::obligation::SemanticObligationInventory {
        &self.facts.obligations
    }

    pub fn callsite_certificate_for_inst(
        &self,
        inst: crate::graph::InstId,
    ) -> Option<&CallsiteCertificate> {
        let callsite = self.facts.call_sites.by_inst.get(inst)?;
        self.facts.certificates.callsites.get(callsite)
    }

    /// The one call this block makes, found rather than indexed.
    ///
    /// A call's operation index moves whenever construction emits another
    /// boundary fact beside it, and a test that hard-codes the index is
    /// asserting about the lowering's bookkeeping rather than about the call.
    #[cfg(test)]
    pub(crate) fn sole_callsite_certificate_in_block(
        &self,
        block_addr: u64,
    ) -> Option<&CallsiteCertificate> {
        let mut found = self
            .facts
            .certificates
            .callsites
            .values()
            .filter(|certificate| self.graph().block_addr_of(certificate.at) == Some(block_addr));
        let certificate = found.next()?;
        found.next().is_none().then_some(certificate)
    }

    pub fn memory_certificate_for_inst(
        &self,
        inst: crate::graph::InstId,
        is_write: bool,
    ) -> Option<&MemoryAccessCertificate> {
        let certs = &self.facts.certificates;
        self.facts
            .certificates
            .memory_accesses_by_inst
            .get(inst)?
            .get(is_write)
            .iter()
            .filter_map(|id| certs.memory_accesses.get(id))
            .find(|cert| cert.is_write == is_write)
    }

    pub fn stack_reload_certificate_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<&StackReloadSourceCertificate> {
        self.facts.certificates.stack_reloads.get(value_id)
    }

    pub fn stack_reload_certificate_for_inst(
        &self,
        inst: crate::graph::InstId,
    ) -> Option<&StackReloadSourceCertificate> {
        let value = self.graph().inst(inst)?.output?;
        self.facts.certificates.stack_reloads.get(value)
    }

    pub fn call_result_certificate_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<&CallResultCertificate> {
        self.facts.certificates.call_results.get(value_id)
    }

    pub fn return_certificate_for_inst(
        &self,
        inst: crate::graph::InstId,
    ) -> Option<&ReturnValueCertificate> {
        let index = self.facts.certificates.returns_by_inst.get(inst)?;
        self.facts.certificates.returns.get(*index)
    }

    pub fn resolved_call_target(&self, call: &crate::semantic::CallSiteFact) -> Option<u64> {
        call.direct_target.or_else(|| {
            let value_id = canonical_root_value_id(self, call.target);
            let value = self.graph().value(value_id)?;
            value.var.constant_bits().or_else(|| {
                value.canonical_storage.and_then(|storage| {
                    matches!(
                        storage.space,
                        crate::CanonicalStorageSpace::Constant | crate::CanonicalStorageSpace::Ram
                    )
                    .then_some(storage.offset)
                })
            })
        })
    }

    /// The constant one value computes to, where it computes to one.
    ///
    /// A machine forms an address in more than one instruction -- aarch64
    /// spells one as a page and an offset -- so the address a value names is
    /// not always a constant the lift wrote down. This is the one answer to
    /// that question: four places used to fold it privately, and a consumer
    /// outside the crate had none.
    pub fn folded_value(&self, value_id: crate::graph::ValueId) -> Option<u64> {
        self.sealed
            .folded()
            .prepared
            .get(value_id)
            .copied()
            .flatten()
    }

    /// The constant a value computes to from the graph alone, without what
    /// preparation admitted; one lookup into the table folded at the seal.
    pub(crate) fn bare_folded_value(&self, value_id: crate::graph::ValueId) -> Option<u64> {
        self.sealed.folded().bare.get(value_id).copied().flatten()
    }

    /// Every value the body computes, in graph order.
    pub fn value_ids(&self) -> impl Iterator<Item = crate::graph::ValueId> + '_ {
        (0..self.graph().values.len())
            .filter_map(|index| u32::try_from(index).ok())
            .map(crate::graph::ValueId)
    }

    pub fn value_var(&self, value_id: crate::graph::ValueId) -> Option<&SSAVar> {
        self.graph().value(value_id).map(|value| &value.var)
    }

    /// Exact stack-relative coordinate proved for one artifact-local SSA value.
    ///
    /// Consumers must not recover this fact from a register spelling such as
    /// `rsp`, `rbp`, or `sp`. The decompiler-preparation pass owns the typed
    /// stack-carrier proof; this method only projects that proof onto the
    /// graph's stable [`ValueId`](crate::graph::ValueId) identity.
    pub fn stack_address_root_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<StackAddressRoot> {
        let facts = self.decompile_prep_facts();
        facts.stack_address_root_of(value_id).copied().or_else(|| {
            let root = canonical_root_value_id(self, value_id);
            facts.stack_address_root_of(root).copied()
        })
    }

    /// Entry-stack-relative coordinate proved for one artifact-local SSA value.
    ///
    /// This is deliberately separate from [`Self::stack_address_root_for_value`]:
    /// a frame-pointer-relative value can have a current-frame coordinate while
    /// lacking the stronger entry-stack proof after an unknown machine effect.
    /// How far this graph is from one identity per register family: the
    /// alias temporaries normalization had to mint, and the families that
    /// entered the function under more than one version-zero value. Both are
    /// zero once a register family has one SSA identity
    /// (`doc/adr-register-identity.md`).
    pub fn register_identity_census(&self) -> RegisterIdentityCensus {
        let families = RegisterFamilyInfo::from_register_storages(
            self.machine_context
                .register_storages_by_name()
                .iter()
                .filter(|(_, storage)| storage.space == CanonicalStorageSpace::Register)
                .map(|(name, storage)| (name.as_str(), storage.offset, storage.size)),
        );
        let mut entries_by_family = FxHashMap::<usize, usize>::default();
        for value in &self.graph().values {
            if value.var.version != 0 || self.graph().def_inst(value.id).is_some() {
                continue;
            }
            let Some(storage) = value
                .canonical_storage
                .filter(|storage| storage.space == CanonicalStorageSpace::Register)
            else {
                continue;
            };
            if let Some(member) = families.member_at_offset(storage.offset, storage.size) {
                *entries_by_family.entry(member.family_id).or_default() += 1;
            }
        }
        RegisterIdentityCensus {
            split_entry_families: entries_by_family.values().filter(|n| **n > 1).count(),
        }
    }

    pub fn entry_stack_address_root_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<StackAddressRoot> {
        let facts = self.decompile_prep_facts();
        facts
            .entry_stack_address_root_of(value_id)
            .copied()
            .or_else(|| {
                let root = canonical_root_value_id(self, value_id);
                facts.entry_stack_address_root_of(root).copied()
            })
    }

    /// Every block spelled by name, off the graph that owns each operation after the seal.
    pub fn named_blocks(&self) -> Vec<SSABlock> {
        self.graph().named_blocks()
    }

    /// One block spelled by name, off the graph; see [`Self::named_blocks`].
    pub fn named_block(&self, addr: u64) -> Option<SSABlock> {
        self.graph().named_block(addr)
    }

    /// The function in the text [`SSAFunction::dump`] prints, its operations read off the graph.
    pub fn dump(&self) -> String {
        let function = self.function();
        dump_blocks(
            function.name.as_deref(),
            function.entry,
            &self.named_blocks(),
            function,
            SSAVar::clone,
        )
    }

    /// The instruction a test names by its block and its place among the
    /// block's operations.
    #[cfg(test)]
    pub(crate) fn inst_at(&self, block_addr: u64, index: usize) -> Option<crate::graph::InstId> {
        self.graph().inst_spelled_at(block_addr, index)
    }

    pub fn object_for_var(&self, var: &SSAVar, space: r2il::SpaceId) -> Option<ObjectId> {
        self.graph()
            .value_id_for_var(var)
            .and_then(|value_id| self.objects().object_for_value(value_id, space))
    }

    pub fn memory_uses_for_inst(&self, inst: crate::graph::InstId) -> Option<&[MemoryUseFact]> {
        self.memory()
            .uses_by_inst
            .get(inst)
            .map(|facts| facts.as_slice())
    }

    pub fn memory_defs_for_inst(&self, inst: crate::graph::InstId) -> Option<&[MemoryDefFact]> {
        self.memory()
            .defs_by_inst
            .get(inst)
            .map(|facts| facts.as_slice())
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.sealed = self.sealed.named(name.into());
        self
    }
}

/// Pair each call prototype the source captured with the lifted call it
/// describes.
///
/// The source captures prototypes keyed by instruction address, because a call
/// site identity names a block address, an operation index and a target
/// storage, none of which exist before the function is lifted. Here both are
/// available, so a prototype is matched to a lifted call only when the
/// instruction it was recorded against and the target it names both agree with
/// the machine. A prototype that matches nothing, or matches more than one
/// call, is dropped rather than guessed at.
/// The one lifted call whose instruction and target both match this advisory
/// call, if exactly one does.
fn unique_call_site_identity(
    blocks: &[R2ILBlock],
    calls: &CallOperations,
    call: &r2source::AdvisoryCallSite,
) -> Option<SourceCallSiteIdentity> {
    let at = calls.at(call.instruction_address()).iter();
    let mut matches = at.filter_map(|&(block, op_index)| {
        let block = &blocks[block];
        let op = &block.ops[op_index];
        {
            {
                let instruction = || {
                    block
                        .instruction_of(op_index)
                        .filter(|instruction| *instruction == call.instruction_address())
                };
                let last = op_index + 1 == block.ops.len();
                let (target, reaches) = match (call.transfer(), op) {
                    (r2source::AdvisoryCallTransfer::Call, R2ILOp::Call { target }) => {
                        let target = CanonicalStorageId::from_varnode(target);
                        (target, target.offset)
                    }
                    // The site is the target value; the address is what its block folds it to.
                    (r2source::AdvisoryCallTransfer::Call, R2ILOp::CallInd { target })
                        if instruction().is_some() =>
                    {
                        (
                            CanonicalStorageId::from_varnode(target),
                            crate::origin::folded_call_target(block, op_index)?,
                        )
                    }
                    // The site is the target value; the address is the slot its block loads it from.
                    (r2source::AdvisoryCallTransfer::CallSlot, R2ILOp::CallInd { target })
                        if instruction().is_some() =>
                    {
                        (
                            CanonicalStorageId::from_varnode(target),
                            crate::machine_context::loaded_target_slot(block, op_index)?.offset,
                        )
                    }
                    (r2source::AdvisoryCallTransfer::TailJump, R2ILOp::Branch { target })
                        if last =>
                    {
                        let target = CanonicalStorageId::from_varnode(target);
                        (target, target.offset)
                    }
                    (r2source::AdvisoryCallTransfer::TailSlot, R2ILOp::BranchInd { .. })
                        if last =>
                    {
                        let slot =
                            crate::machine_context::terminal_indirect_loaded_slot(block, op_index)?;
                        (slot, slot.offset)
                    }
                    _ => return None,
                };
                let instruction = instruction()?;
                (reaches == call.target_address())
                    .then(|| SourceCallSiteIdentity::new(instruction, target))
            }
        }
    });
    let identity = matches.next()?;
    matches.next().is_none().then_some(identity)
}

/// Each control-flow operation of the lifted body by the instruction holding it: built once, so
/// finding a site is O(log n) and no site rescans the body.
struct CallOperations {
    by_instruction: BTreeMap<u64, Vec<(usize, usize)>>,
}

impl CallOperations {
    fn of(blocks: &[R2ILBlock]) -> Self {
        let mut index = Self {
            by_instruction: BTreeMap::new(),
        };
        for (at, block) in blocks.iter().enumerate() {
            for (op, operation) in block.ops.iter().enumerate() {
                if !operation.is_control_flow() {
                    continue;
                }
                if let Some(instruction) = block.instruction_of(op) {
                    index
                        .by_instruction
                        .entry(instruction)
                        .or_default()
                        .push((at, op));
                }
            }
        }
        index
    }

    /// The control-flow operations of the instruction at `address`, in order.
    fn at(&self, address: u64) -> &[(usize, usize)] {
        self.by_instruction.get(&address).map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone)]
struct CorrelatedCallSites {
    tail_calls: Vec<SourceCallSiteIdentity>,
    interfaces: Vec<SourceCallSiteInterface>,
    /// Who each correlated site calls, where the source knew: the binary's own function or an import.
    callee_linkages: BTreeMap<SourceCallSiteIdentity, r2source::AdvisoryCalleeLinkage>,
    /// The name the source gave each correlated site's callee.
    callee_names: BTreeMap<SourceCallSiteIdentity, String>,
    /// The sealed import slot each correlated `CallSlot` site calls through.
    slot_targets: BTreeMap<SourceCallSiteIdentity, u64>,
    /// The sites whose contract is one the snapshot states for a typed member (S32).
    member_sites: BTreeSet<SourceCallSiteIdentity>,
}

fn correlate_call_site_interfaces(
    source: &OwnedFunctionSnapshot,
    (blocks, calls): (&[R2ILBlock], &CallOperations),
    callee_interfaces: &BTreeMap<u64, SourceFunctionInterface>,
    callees: &CalleeBoundaries,
) -> CorrelatedCallSites {
    let mut tail_calls = Vec::new();
    let mut interfaces = Vec::new();
    let mut callee_linkages = BTreeMap::new();
    let mut slot_targets = BTreeMap::new();
    let mut callee_names = BTreeMap::new();
    for call in source.advisory_calls() {
        let Some(identity) = unique_call_site_identity(blocks, calls, call) else {
            // The source named a call the lift does not have exactly one
            // operation for, so nothing here can carry its prototype.
            r2il::refusal_evidence!(
                "call-site-correlation",
                "advisory {:?} at {:#x} target {:#x} matches no unique lifted operation",
                call.transfer(),
                call.instruction_address(),
                call.target_address()
            );
            continue;
        };
        if matches!(
            call.transfer(),
            r2source::AdvisoryCallTransfer::TailJump | r2source::AdvisoryCallTransfer::TailSlot
        ) {
            tail_calls.push(identity);
        }
        if call.linkage() != r2source::AdvisoryCalleeLinkage::Unknown {
            callee_linkages.insert(identity, call.linkage());
        }
        if call.transfer() == r2source::AdvisoryCallTransfer::CallSlot {
            slot_targets.insert(identity, call.target_address());
        }
        if let Some(name) = call.target_name() {
            callee_names.insert(identity, name.to_string());
        }
        // The callee body captured with the caller states the site's interface.
        let Some(callee) = callee_interfaces.get(&call.target_address()) else {
            continue;
        };
        let Some(mut interface) = crate::recover_interface::mint_recovered_call_site_interface(
            callee,
            callees.preserved().get(&call.target_address()),
            &crate::recover_interface::convention_results(source.convention()),
            identity,
            source.source_revision_identity(),
        ) else {
            continue;
        };
        // The gettext family hands back a translation of its own argument (a name rule).
        if let Some(target_name) = call.target_name()
            && let Some(rule) = r2source::SourceFormatForwardingRule::for_target_name(target_name)
            && let Ok(bound) = interface.clone().with_format_forwarding(rule)
        {
            interface = bound;
        }
        interfaces.push(interface);
    }
    // A member's contract states a site no advisory call names; one the source states wins.
    let members = source.member_calls();
    let stated = (interfaces.iter())
        .filter(|_| !members.is_empty())
        .map(SourceCallSiteInterface::identity)
        .collect::<BTreeSet<_>>();
    let mut member_sites = BTreeSet::new();
    for member in members {
        let identity = member.identity();
        if !stated.contains(&identity) {
            member_sites.insert(identity);
            interfaces.push(member.clone());
        }
    }
    CorrelatedCallSites {
        tail_calls,
        interfaces,
        callee_linkages,
        callee_names,
        slot_targets,
        member_sites,
    }
}

/// Which of this function's own parameters its body forwards as a format.
///
/// The callsites this body was correlated against already say which argument
/// each callee consumes as a format: radare2's prototype for the printf
/// family, or the callee's own body when it is a wrapper defined in this
/// binary. The value that argument carries is traced back to a parameter of
/// this function. Whether this function itself takes a variadic tail is not
/// the question: `vfprintf` takes a `va_list` and forwards its format all the
/// same, and a wrapper's `va_list` half is exactly what the variadic half
/// forwards through.
fn body_proven_format_parameter(shared: &SsaArtifact) -> Option<u32> {
    use crate::semantic::SourceCallArgumentValue;
    let boundaries = &shared.facts().boundaries;
    if boundaries.parameters.is_empty() {
        return None;
    }
    let mut proven: Option<u32> = None;
    for (call_site, boundary) in &boundaries.calls {
        let Some(interface) = shared.call_site_interface(*call_site) else {
            continue;
        };
        let Some(rule) = interface.format_parameter_rule() else {
            continue;
        };
        let format_index = rule.parameter_index() as usize;
        let Some(argument) = boundary.arguments.get(format_index) else {
            r2il::refusal_evidence!(
                "body-format-parameter",
                "{call_site:?} names its format at {format_index} and carries {} arguments",
                boundary.arguments.len()
            );
            continue;
        };
        let SourceCallArgumentValue::Value(value) = argument.value else {
            r2il::refusal_evidence!(
                "body-format-parameter",
                "the format argument of {call_site:?} is this function's entry carrier, not a value"
            );
            continue;
        };
        let Some(index) = forwarded_parameter_index(shared, value, &mut BTreeSet::new()) else {
            r2il::refusal_evidence!(
                "body-format-parameter",
                "the format argument {value:?} of {call_site:?} is no parameter of this function"
            );
            continue;
        };
        match proven {
            Some(existing) if existing != index => {
                r2il::refusal_evidence!(
                    "body-format-parameter",
                    "forwards disagree: parameter {existing} and parameter {index}"
                );
                return None;
            }
            _ => proven = Some(index),
        }
    }
    if let Some(index) = proven {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "this body forwards parameter {index} as a format"
        );
    }
    proven
}

/// The parameter this value carries, directly, through a copy or merge, or
/// through its home.
///
/// An unoptimised wrapper spills its format parameter to the parameter home
/// and reloads it before forwarding, and the reload reaches the call through
/// the register copy that sets up the argument, so the value at the call is
/// two steps from the entry carrier. The frame round-trip certificate
/// deliberately refuses to cover a parameter home -- its job is to prove frame
/// traffic is an elidable save and restore, and a parameter home is a variable
/// the program uses -- so the identity is established here instead, and claims
/// only that: the value holds the parameter, not that the traffic may go.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
fn forwarded_parameter_index(
    shared: &SsaArtifact,
    value: crate::ValueId,
    seen: &mut BTreeSet<crate::ValueId>,
) -> Option<u32> {
    use crate::graph::InstPayload;
    if !seen.insert(value) {
        return None;
    }
    let boundaries = &shared.facts().boundaries;
    if let Some((index, _)) = boundaries
        .parameters
        .iter()
        .find(|(_, parameter)| parameter.value() == Some(value))
    {
        return Some(*index);
    }
    let graph = shared.graph();
    let Some(definition) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "{value:?} has no defining instruction and is not a parameter"
        );
        return None;
    };
    // A copy or a merge carries whatever reached it, so every input has to
    // name the same parameter for the value to name one.
    let agreeing = |inputs: &[crate::ValueId], shared: &SsaArtifact, seen: &mut BTreeSet<_>| {
        let mut answer: Option<u32> = None;
        for input in inputs {
            let index = forwarded_parameter_index(shared, *input, seen)?;
            match answer {
                Some(existing) if existing != index => return None,
                _ => answer = Some(index),
            }
        }
        answer
    };
    match &definition.payload {
        InstPayload::Phi { .. } | InstPayload::Op(SSAOp::Copy { .. }) => {
            return agreeing(graph.inputs(definition.id), shared, seen);
        }
        InstPayload::Op(SSAOp::Load { .. }) => {}
        InstPayload::Op(op) => {
            r2il::refusal_evidence!(
                "body-format-parameter",
                "{value:?} is defined by {}, which carries no parameter identity",
                format!("{op:?}").chars().take(60).collect::<String>()
            );
            return None;
        }
    }
    let structured = shared.structured();
    // The access this load is, and the object it reads.
    let Some(read) = structured.memory_accesses.values().find(|access| {
        !access.is_write && access.value == Some(value) && access.provenance_complete
    }) else {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "the load of {value:?} has no complete structured read to name its object"
        );
        return None;
    };
    // One store to that object, of the parameter, and every access the same
    // width: anything else and the home holds something the program changed.
    let writes = structured
        .memory_accesses
        .values()
        .filter(|access| access.object == read.object && access.is_write)
        .collect::<Vec<_>>();
    let [store] = writes.as_slice() else {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "object {:?} behind {value:?} has {} writes, not one",
            read.object,
            writes.len()
        );
        return None;
    };
    if !store.provenance_complete || store.width != read.width {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "the store to {:?} is {} bytes complete={} against a {} byte read",
            read.object,
            store.width,
            store.provenance_complete,
            read.width
        );
        return None;
    }
    let stored = store.value?;
    let index = forwarded_parameter_index(shared, stored, seen);
    if index.is_none() {
        r2il::refusal_evidence!(
            "body-format-parameter",
            "the home behind {value:?} was written {stored:?}, which is no parameter"
        );
    }
    index
}

impl TrustedSsaArtifact {
    /// Prepare one certifiable SSA artifact from a source-retaining canonical
    /// lift. No detached interface, layout, or raw block input is accepted at
    /// this boundary, and an architecture only as tables over the lift's own.
    pub fn prepare_with_control<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::prepare_with_callee_interfaces(
            lifted,
            None,
            control,
            &CalleeEvidence::default(),
            &BTreeSet::new(),
        )
    }

    /// Prepare, describing each call whose callee body came in this capture.
    ///
    /// The interfaces are keyed by callee entry address and are consulted only
    /// where the source itself recovered no prototype for the call.
    pub fn prepare_with_callee_interfaces<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<Self, SsaPrepareError> {
        Self::seal_with_callee_interfaces(lifted, arch, control, evidence, premises)?
            .collect(control)
    }

    /// Build, recover and seal as `prepare_with_callee_interfaces` does, and stop before the facts
    /// are collected: a reader of the seal alone pays for no fact pass.
    pub fn seal_with_callee_interfaces<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<TrustedSeal, SsaPrepareError> {
        Self::sealed(
            lifted,
            arch,
            control,
            (evidence, premises),
            Recovery::Recover,
        )
    }

    /// Build against the convention alone and seal, recovering nothing: for a reader of values
    /// inside the body, such as a dispatch's table or a call's argument, which no interface decides.
    pub fn seal_against_convention<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<TrustedSeal, SsaPrepareError> {
        Self::sealed(
            lifted,
            arch,
            control,
            (evidence, premises),
            Recovery::Convention,
        )
    }

    /// Build and recover as `seal_with_callee_interfaces` does, and stop before the seal: a reader
    /// of the interface alone pays for no seal, and a restatement of the callees updates the build.
    pub fn construct_with_callee_interfaces<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<TrustedConstruction, SsaPrepareError> {
        let recovery = Recovery::Recover;
        let constructed =
            Self::construct(&lifted, arch, control, evidence, premises, recovery, None)?;
        Ok(TrustedConstruction {
            constructed,
            lifted,
        })
    }

    /// The trusted lift built under `recovery` and sealed, its facts not yet collected.
    fn sealed<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        (evidence, premises): (&CalleeEvidence, &BTreeSet<r2source::Premise>),
        recovery: Recovery,
    ) -> Result<TrustedSeal, SsaPrepareError> {
        let constructed =
            Self::construct(&lifted, arch, control, evidence, premises, recovery, None)?;
        drop(lifted);
        constructed.seal(control)
    }

    /// The function built against its interface, stated or recovered, and the context it is sealed in.
    #[expect(
        clippy::too_many_arguments,
        reason = "the trusted lift, its tables, the work budget, the callees' evidence, the accepted premises and the recovery are construction's independent inputs"
    )]
    fn construct<C: SsaWorkControl + ?Sized>(
        lifted: &TrustedLiftedFunction,
        arch: Option<&crate::Arch>,
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
        recovery: Recovery,
        prior: Option<Prior>,
    ) -> Result<Constructed, SsaPrepareError> {
        let CalleeEvidence {
            interfaces: callee_interfaces,
            preserved: callee_preserved_carriers,
            reach: callee_argument_reach,
            library,
            reentering,
            exits,
            unstated_imports,
            conventions: site_conventions,
        } = evidence;
        let callee_statements = crate::machine_context::CalleeStatement::of(callee_interfaces);
        let source = lifted.source().clone();
        let genuine = lifted.lifted();
        // The session's tables, where they are built over the lift's own architecture.
        let arch = match arch.filter(|arch| arch.shares(genuine.arch_spec())) {
            Some(arch) => arch.clone(),
            None => {
                r2il::refusal_evidence!(
                    "arch-tables",
                    "{:#x}: the lift's architecture is not the one supplied ({}), so its tables are built again",
                    source.image().entry_address(),
                    arch.is_some()
                );
                crate::Arch::new(Arc::clone(genuine.shared_arch_spec()))
            }
        };
        let blocks = genuine
            .blocks()
            .iter()
            .map(|block| block.block().clone())
            .collect::<Vec<_>>();
        let native_spans = genuine_native_instruction_spans(genuine);
        // Where each block may continue past its last instruction is the
        // source's to say: a call's return is a fact about the callee, which
        // the lifted operations cannot carry.
        let declared_successors = crate::cfg::DeclaredSuccessors::from_source_image(source.image());
        // The machine context already models an absent interface: it becomes an
        // unavailable, incoherent ABI model, and every consumer filters on
        // coherence. Refusing here instead would suppress the whole function
        // for a fact the pipeline is built to carry.
        let calls = CallOperations::of(&blocks);
        // What each callee said about its own boundary, read once for every
        // pass that asks what a call to it does to the registers.
        let callees = CalleeBoundaries::from_interfaces(
            Some(&arch),
            callee_preserved_carriers,
            callee_interfaces,
        )
        .with_conventions(site_conventions.clone());
        let correlated_call_sites =
            correlate_call_site_interfaces(&source, (&blocks, &calls), callee_interfaces, &callees);
        let callees = callees.with_slots(&correlated_call_sites.slot_targets);
        // Every call target the source named, whether or not a prototype was
        // recovered for it: a name and a prototype are independent facts.
        let mut display_names = r2source::DisplayNames::new();
        for call in source.advisory_calls() {
            if let Some(name) = call.target_name() {
                display_names.insert_function(call.target_address(), name);
            }
        }
        for (addr, text) in source.image().string_literals() {
            display_names.insert_string(*addr, text.clone());
        }
        // The names radare2 has for the data this function points at. Display
        // facts, like the strings above: they say what an address is called,
        // never what is stored there.
        for object in source.image().data_symbols() {
            display_names.insert_symbol(object.address(), object.name().to_string());
        }
        display_names.set_parameters(
            source
                .presentation()
                .parameter_names()
                .iter()
                .map(|name| name.to_string()),
        );
        // Keyed by the coordinate the source declared. A frame-relative slot is
        // restated into entry coordinates later, and the lookup translates back.
        display_names.set_stack_slot_names(
            source
                .presentation()
                .stack_slot_names()
                .iter()
                .map(|slot| (slot.base(), slot.offset(), slot.name().to_string())),
        );
        // A source without a recovered prototype still describes its ABI in the
        // instructions: a register read before it is written carries a value the
        // caller supplied. Recover that rather than refusing the function, but
        // never in preference to an interface the source already carries.
        //
        // Three links, and any of them yielding nothing leaves the function with
        // no ABI at all: every question about its return kind then answers
        // `unavailable`, the return boundary is incomplete, and the renderer
        // refuses with no way to tell which link gave up. That was the largest
        // single refusal cause in the corpus, so each link says so.
        // Construction reads the source's interface where it states one and
        // the convention where it does not; a recovered interface is read
        // from the seal on.
        // Without one, the function is built once, against the convention,
        // and that build is both what recovery reads and what is sealed:
        // nothing construction reads differs between the two contexts.
        let stated_interface = source.function_interface().is_some();
        let mut built = None;
        // The build recovery read, its prep facts and what it read of the callees.
        let mut reuse = None;
        let mut kept = false;
        // Whether the recovered result is void on the premise that no caller outside the image reads it.
        let mut closed_world = false;
        let mut body_boundary = None;
        let function_interface = match source.function_interface().cloned() {
            Some(interface) => Some(interface),
            None if recovery == Recovery::Convention => None,
            None => 'recovered: {
                // Which of the two interfaces a function ends up with decides
                // how its return boundary is checked, and the difference is
                // large: a source interface carries the declared result width,
                // while a recovered one can only report the width the
                // instructions observe. Nothing downstream says which one was
                // used, so a boundary that refused because the source was
                // absent looked identical to one that refused with the source
                // present. Say it here, where the choice is made.
                r2il::refusal_evidence!(
                    "interface-source-absent",
                    "the capture carried no function interface; recovering one from {} blocks",
                    blocks.len()
                );
                // Recovery reads the decompile-normalized build the artifact
                // seals, so a call it numbers is the call the artifact numbers.
                let mut provisional_machine_context =
                    SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
                        blocks.as_slice(),
                        Some(&arch),
                        None,
                        *source.machine_roles(),
                        source.conventions().cloned(),
                        correlated_call_sites.interfaces.clone(),
                        correlated_call_sites.tail_calls.clone(),
                    );
                // The recovery proves variadic counts from the same literals
                // the final pass reads; without them every format was unproven.
                provisional_machine_context
                    .bind_source_string_literals(source.image().string_literals());
                provisional_machine_context.bind_read_only(source.image().read_only());
                provisional_machine_context.set_callee_statements(&callee_statements);
                provisional_machine_context
                    .set_slot_targets(correlated_call_sites.slot_targets.clone());
                provisional_machine_context
                    .set_member_call_sites(correlated_call_sites.member_sites.clone());
                provisional_machine_context.set_reentering_callees(reentering.clone());
                provisional_machine_context.set_unstated_imports(unstated_imports.clone());
                // Promotion's frame walk reads what each callee reaches, by the site's model.
                provisional_machine_context
                    .set_callee_argument_reach(callee_argument_reach.clone());
                provisional_machine_context.set_site_conventions(site_conventions.clone());
                // The preliminary build may be the one sealed, so it decides under the same premises.
                provisional_machine_context.set_accepted_premises(premises.clone());
                // A build against callees that state the same to it is this build.
                let key = BuildKey::of(
                    (&provisional_machine_context, &arch),
                    &callees,
                    evidence,
                    premises,
                );
                if let Some(prior) = prior.as_ref().filter(|prior| !prior.builds(&key)) {
                    r2il::refusal_evidence!(
                        "build-key",
                        "{:#x}: the callees state another {}",
                        source.image().entry_address(),
                        prior.key.difference(&key)
                    );
                }
                let (preliminary, held) = match prior.filter(|prior| prior.builds(&key)) {
                    Some(prior) => {
                        kept = true;
                        let mut function = prior.function;
                        function.set_callee_passes(callees.preserved());
                        (Ok(function), Some(prior.provisional))
                    }
                    None => (
                        SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                            &blocks,
                            Some(&arch),
                            InterfaceQuestions::before_recovery(source.convention()),
                            &provisional_machine_context,
                            &callees,
                            Some(&declared_successors),
                            control,
                        ),
                        None,
                    ),
                };
                let Ok(preliminary) = preliminary else {
                    r2il::refusal_evidence!(
                        "interface-recovery",
                        "the decompile-normalized preliminary SSA needed to read the ABI off \
                         the instructions could not be built from {} blocks",
                        blocks.len()
                    );
                    break 'recovered None;
                };
                // Interface recovery must see the same exact call boundaries
                // as final preparation. A source-correlated tail transfer owns
                // the result boundary, and an ordinary call exposes an entry
                // carrier handed straight to its callee. The latter is still
                // a parameter even though implicit call reads leave no source
                // operation behind.
                // This build is the one the artifact seals. The prep facts
                // read here are recovery's own: the seal rewrites the blocks
                // (boundary constants, lane projections, demand) and derives
                // its facts afresh from the rewritten function.
                let preliminary = built.insert(preliminary);
                let preliminary_prep = match held {
                    Some(held) => held,
                    None => match preliminary.provisional_prep_facts(control) {
                        Ok(facts) => facts,
                        Err(_) => break 'recovered None,
                    },
                };
                let preliminary_prep = &reuse.insert((key, preliminary_prep)).1;
                // The preliminary build may be the one sealed: its provisional facts and
                // recovery's own are passes over it, and an exhausted one refuses it.
                if let Some(exhausted) = preliminary_prep.facts.exhausted {
                    preliminary.note_exhausted(exhausted);
                }
                // Without a model no register is an argument or a result: nothing is recovered.
                let Some(model) = source.convention() else {
                    break 'recovered None;
                };
                let recovered = crate::recover_interface::recover_interface_with_context(
                    preliminary,
                    preliminary_prep,
                    model,
                    &provisional_machine_context,
                    crate::recover_interface::Stated::of(&source),
                );
                let recovered = match recovered {
                    Ok(Some(recovered)) => recovered,
                    Ok(None) => break 'recovered None,
                    Err(exhausted) => {
                        preliminary.note_exhausted(exhausted);
                        break 'recovered None;
                    }
                };
                closed_world = recovered.assumes_closed_world();
                body_boundary = Some(Arc::new(recovered.boundary().clone()));
                let minted = crate::recover_interface::mint_recovered_interface(
                    &recovered,
                    source.machine_roles(),
                    source.source_revision_identity(),
                    model.id,
                    Some(model),
                );
                if minted.is_none() {
                    r2il::refusal_evidence!(
                        "interface-recovery",
                        "the recovered ABI could not be minted into an interface: \
                         parameters={} result={:?} convention={:?}",
                        recovered.parameters().len(),
                        recovered.result(),
                        model.id
                    );
                }
                minted
            }
        };
        // A call to this function itself has its contract in the interface just settled.
        let mut call_interfaces = correlated_call_sites.interfaces;
        if let Some(own) = function_interface.as_ref() {
            for call in source.advisory_calls() {
                if call.target_address() != source.image().entry_address() {
                    continue;
                }
                let Some(identity) = unique_call_site_identity(&blocks, &calls, call) else {
                    continue;
                };
                if call_interfaces
                    .iter()
                    .any(|known| known.identity() == identity)
                {
                    continue;
                }
                if let Some(interface) =
                    crate::recover_interface::mint_recovered_call_site_interface(
                        own,
                        None,
                        &crate::recover_interface::convention_results(source.convention()),
                        identity,
                        source.source_revision_identity(),
                    )
                {
                    call_interfaces.push(interface);
                }
            }
        }
        let mut machine_context =
            SourceMachineContext::from_blocks_with_interfaces_tail_calls_and_terminals(
                blocks.as_slice(),
                Some(&arch),
                function_interface,
                *source.machine_roles(),
                source.conventions().cloned(),
                call_interfaces,
                correlated_call_sites.tail_calls,
                &declared_successors.terminal_blocks(),
            );
        machine_context.set_callee_linkages(correlated_call_sites.callee_linkages);
        machine_context.set_callee_names(correlated_call_sites.callee_names);
        machine_context.set_callee_argument_reach(callee_argument_reach.clone());
        machine_context.set_site_conventions(site_conventions.clone());
        machine_context.set_callee_library(library.clone());
        machine_context.set_reentering_callees(reentering.clone());
        machine_context.set_unstated_imports(unstated_imports.clone());
        machine_context.set_callee_preserved(callees.preserved().clone());
        // A call to this function itself is stated by the interface just settled, where it mints none.
        let mut callee_statements = callee_statements;
        let entry = source.image().entry_address();
        if let Some(own) = machine_context.function_interface()
            && !callee_interfaces.contains_key(&entry)
        {
            let own = BTreeMap::from([(entry, own.clone())]);
            callee_statements.extend(crate::machine_context::CalleeStatement::of(&own));
        }
        machine_context.set_callee_statements(&callee_statements);
        machine_context.set_slot_targets(correlated_call_sites.slot_targets);
        machine_context.set_member_call_sites(correlated_call_sites.member_sites);
        machine_context.set_frame_saves(source.image().frame_saves());
        machine_context.set_accepted_premises(premises.clone());
        // What each entry of a captured code pointer table names, recorded
        // before the facts are collected: a load of such a slot is proven
        // from this, and the collection is what proves it.
        let mut code_pointer_entries = BTreeMap::new();
        let mut code_pointer_tables = BTreeMap::new();
        for table in source.image().code_pointer_tables() {
            code_pointer_tables.insert(table.instruction(), table.clone());
            let entry_size = u64::from(table.entry_size());
            for (index, target) in table.targets().iter().enumerate() {
                let Some(address) = u64::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_mul(entry_size))
                    .and_then(|offset| table.address().checked_add(offset))
                else {
                    continue;
                };
                code_pointer_entries.insert(address, *target);
                if let Some(name) = table.target_name(index) {
                    display_names.insert_function(*target, name);
                }
            }
        }
        machine_context.set_code_pointer_entries(code_pointer_entries);
        machine_context.set_code_pointer_tables(code_pointer_tables);
        r2il::refusal_evidence!(
            "snapshot-literals",
            "the decoded image delivers {} string literals",
            source.image().string_literals().len()
        );
        machine_context.bind_source_string_literals(source.image().string_literals());
        machine_context.bind_read_only(source.image().read_only());
        machine_context.bind_data_structs(source.image());
        let function = match built {
            Some(built) => built,
            None => {
                let questions = match stated_interface {
                    true => InterfaceQuestions::new(&machine_context),
                    false => InterfaceQuestions::before_recovery(source.convention()),
                };
                SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                    blocks.as_slice(),
                    Some(&arch),
                    questions,
                    &machine_context,
                    &callees,
                    Some(&declared_successors),
                    control,
                )?
            }
        };
        if function.entry != source.image().entry_address() {
            return Err(malformed_ssa_input());
        }
        // A build an exhausted pass marked is not offered again.
        let reuse = reuse.filter(|_| function.exhausted().is_none());
        control.poll()?;
        Ok(Constructed {
            function,
            closed_world,
            exits: exits.clone(),
            reuse: reuse.map(|(key, provisional)| Reuse { key, provisional }),
            kept,
            machine_context,
            finish: Finish {
                provenance: SsaArtifactProvenance::TrustedSource(source),
                spellings: ArtifactSpellings {
                    display_names,
                    user_operations: Arc::from(arch.user_ops.clone()),
                },
                native_spans: Some(native_spans),
                body_boundary,
            },
            source_block_count: blocks.len(),
            arch,
        })
    }

    pub fn prepare(lifted: TrustedLiftedFunction) -> Result<Self, SsaPrepareError> {
        Self::prepare_with_control(lifted, &UncheckedSsaWorkControl)
    }

    /// Read-only analysis view. This does not allow a generic artifact to be
    /// converted back into a trusted wrapper.
    pub fn artifact(&self) -> &SsaArtifact {
        self.artifact.as_ref()
    }

    /// Shared ownership of the exact immutable artifact retained by this
    /// trusted wrapper.
    pub fn shared_artifact(&self) -> Arc<SsaArtifact> {
        Arc::clone(&self.artifact)
    }

    /// Whether `artifact` is the exact allocation retained by this trusted
    /// wrapper. Equal content from an independent allocation is not enough.
    pub fn shares_artifact(&self, artifact: &Arc<SsaArtifact>) -> bool {
        Arc::ptr_eq(&self.artifact, artifact)
    }

    /// How many blocks the trusted lift produced.
    ///
    /// The p-code itself used to be retained here as evidence of the lift
    /// event. Nothing read it: preparation consumes it into the SSA function
    /// and the graph, native spans are separate evidence in the obligation
    /// inventory, and the only question anyone asked of the blocks afterwards
    /// was how many there were. On one 501-block function that retention was
    /// fourteen megabytes, held for the life of the artifact and of the cache
    /// entry that keeps it.
    pub const fn source_block_count(&self) -> usize {
        self.source_block_count
    }

    /// Architecture extracted from the same embedded trusted Sleigh profile.
    pub fn arch_spec(&self) -> &ArchSpec {
        self.arch.spec()
    }

    /// That architecture with its tables.
    pub const fn arch(&self) -> &crate::Arch {
        &self.arch
    }

    pub fn source(&self) -> &OwnedFunctionSnapshot {
        match &self.artifact.provenance {
            SsaArtifactProvenance::TrustedSource(source) => source,
            SsaArtifactProvenance::Manual => {
                unreachable!("TrustedSsaArtifact always retains source provenance")
            }
        }
    }
}

/// The value the canonical root names, or `value_id` where the root is not a
/// value of this graph.
pub(crate) fn canonical_root_value_id(
    prepared: &SsaArtifact,
    value_id: crate::graph::ValueId,
) -> crate::graph::ValueId {
    crate::view::class_value(
        prepared.graph(),
        Some(&prepared.decompile_prep_facts().views),
        value_id,
    )
}

impl Deref for SsaArtifact {
    type Target = SSAFunction;

    fn deref(&self) -> &Self::Target {
        self.function()
    }
}

impl DecompilePrepFacts {
    /// The value naming `value`'s bit-identity class, where it is not
    /// `value` and the class is named by a value rather than a literal.
    pub fn canonical_root_of(&self, value: ValueId) -> Option<ValueId> {
        self.views
            .representative_of(value)
            .and_then(crate::view::Representative::value)
    }

    /// The representative every value with `value`'s bits at its width is
    /// named by: an `O(1)` lookup into the view (`crate::view`).
    pub fn canonical_root(&self, value: ValueId) -> crate::view::Representative<ValueId> {
        self.views.representative(value)
    }

    /// The bits `value` is read from, stated relative to their root.
    pub fn view(&self, value: ValueId) -> crate::view::ValueView<ValueId> {
        self.views.view(value)
    }

    /// Whether `a` and `b` are the same bits at the same width.
    pub fn same_bits(&self, a: ValueId, b: ValueId) -> bool {
        self.views.same_bits(a, b)
    }

    /// The value `value` equals as an unsigned integer: the root of its
    /// chain of copies and zero extensions, or `value` itself.
    pub fn same_integer_root(&self, value: ValueId) -> ValueId {
        self.views.same_integer_root(value)
    }

    pub fn indexed_stack_address_root_of(&self, value: ValueId) -> Option<&StackAddressRoot> {
        self.indexed_stack_address_roots.get(value)
    }

    pub fn stack_address_root_of(&self, value: ValueId) -> Option<&StackAddressRoot> {
        self.stack_address_roots.get(value)
    }

    pub fn entry_stack_address_root_of(&self, value: ValueId) -> Option<&StackAddressRoot> {
        self.entry_stack_address_roots.get(value)
    }

    pub fn formal_parameter_of(&self, value: ValueId) -> Option<usize> {
        self.formal_parameters.get(value).copied()
    }
}

/// A function in SSA form.
///
/// This is the main entry point for function-level SSA analysis.
/// It contains the CFG, dominator tree, and SSA operations for all blocks.
#[derive(Debug)]
pub struct SSAFunction {
    /// Whether a call leaves the carriers that address this frame alone, as the call effect says.
    call_preserved_carriers: Option<SourceCallPreservedCarriers>,
    /// The user operations that enter the supervisor, as the lift names them.
    supervisor_calls: BTreeSet<u32>,
    /// What each direct callee proves it leaves as found, less its result: a call to it passes those (D212).
    callee_passes: Arc<CalleePreservedCarriers>,
    /// The frame's one escape walk, run before promotion (D290); none reads as the whole frame.
    frame_points: Option<Arc<crate::semantic::FramePoints>>,
    /// The lifted memory operations promotion took out of memory.
    ///
    /// A promoted slot access is a copy of a variable in the prepared
    /// operations, so it is no longer one of the function's memory
    /// operations, and every layer that counts those has to agree.
    promoted_slots: BTreeSet<(u64, usize)>,
    /// The operations a decided compiler-inserted check is: a canary (under `Premise::UbFreeSource`)
    /// or a runtime's stack bound (by its model).
    compiler_inserted: crate::dense::IdSet<crate::arena::OpId>,
    /// The failure blocks a decided compiler-inserted check removed, by address and byte size; their instructions stay owed.
    compiler_inserted_blocks: BTreeMap<u64, u32>,
    /// The edges those checks removed, (from, to): the source's successors the graph no longer holds.
    compiler_removed_edges: BTreeSet<(u64, u64)>,
    /// Each decided canary check's `reload - guard` and the block its passing edge alone enters.
    passing_differences: Vec<(crate::value_table::VarId, u64)>,
    /// Every decided canary check's difference, sorted: a write no C expression defines.
    checked_differences: Vec<crate::value_table::VarId>,
    /// The blocks SCCP dropped as unreachable after deciding a branch, by address and byte size; they owe no obligation.
    decided_dead_blocks: BTreeMap<u64, u32>,
    /// The edges SCCP dropped with them, (from, to).
    decided_dead_edges: BTreeSet<(u64, u64)>,
    /// The premises a rewrite of this function relied on, whatever later became of what it rewrote.
    premises: BTreeSet<r2source::Premise>,
    /// The calls its walk ended at on a model's word that the callee never returns.
    assumed_exits: AssumedExits,
    /// The architectural stack pointer, as the machine roles name it.
    ///
    /// The roles know it for every function, including one whose signature
    /// the source never linked or whose declared slots are not exact; the
    /// interface's copy is absent or withheld for exactly those, and the
    /// entry-relative position of anything derived from the stack pointer is
    /// a machine fact that does not wait on either.
    stack_pointer_carrier: Option<CanonicalStorageId>,
    /// The function's name (if known).
    pub name: Option<String>,
    /// The address the function is entered at, which names it. Not always
    /// the root of its graph: see [`Self::root`].
    pub entry: u64,
    /// Control flow graph.
    cfg: CFG,
    /// Dominator tree.
    domtree: DomTree,
    /// The natural loops of `cfg`, computed on first use from it and the
    /// dominator tree, and forgotten whenever those are recomputed.
    natural_loops: std::sync::OnceLock<crate::natural_loops::NaturalLoops>,
    /// SSA operations, one entry per block, in reverse postorder.
    ///
    /// Dense and ordered rather than a hash map beside a separate order, so
    /// that reading the blocks is a slice rather than a walk of one container
    /// looking each address up in another. Every mutable path advances its
    /// revision, which the prep facts are stamped with.
    blocks: Blocks,
    /// What each operand id of `blocks` is spelled as: one table, filled as
    /// operations enter the function (`crate::value_table`).
    values: crate::value_table::ValueTable,
    /// Where each block address sits in `blocks`.
    block_index: BTreeMap<u64, u32>,
    /// The same addresses as `blocks`, in the same order, for readers that want
    /// the addresses without the operations.
    block_order: Vec<u64>,
    /// Entry-lane projections: the value standing for a lane of a register as
    /// the function was entered with it, defined at entry as a `Subpiece` of
    /// the family root's entry value (doc/adr-register-identity.md §6).
    /// Keyed by the projection's variable, valued by the lane's storage.
    formal_projections: crate::dense::IdMap<VarId, CanonicalStorageId>,
    /// Entry roots rebuilt from their declared lanes: the value a read of the
    /// whole register takes once the formals describe it, defined at entry
    /// from the projections with zero above them. Keyed by the rebuilt
    /// variable, valued by the root's storage. The rebuild restates what the
    /// caller passed; it is no write the body made.
    formal_roots: crate::dense::IdMap<VarId, CanonicalStorageId>,
    /// Each entry-lane formal at the low end of its root, and that root: the
    /// formal is the caller's own value of the lane, live at entry with no
    /// definition, and its bits are the root's low bits.
    entry_lanes: crate::dense::IdMap<VarId, VarId>,
    /// Which bytes each operation and phi wrote as data, recorded when the
    /// function was lifted and kept through every rewrite by id
    /// (doc/adr-written-lanes.md).
    written: crate::lanes::Written,
    /// The first pass over it that moved a state past its stated height: the function refuses.
    exhausted: Option<crate::fixpoint::Exhausted>,
}

/// Reads that see one content: loads of the same bytes of one object -- the
/// same object, an exact offset in it, the same width -- that the same memory
/// versions reach, in whatever block.
///
/// A memory version is one write, one merge of writes, or the object's content
/// at entry, and every write that may reach the bytes -- a call included, for
/// whatever has escaped -- makes a new one. Two reads the same set of versions
/// reaches therefore read the same bytes as last written by the same writes.
/// A read with no exact offset, or annotated by more than one location, says
/// nothing. `O(A log A)` in the reads.
pub(crate) fn same_content_reads(
    memory_accesses: &BTreeMap<
        crate::semantic::StructuredAccessId,
        crate::semantic::StructuredMemoryAccessFact,
    >,
    memory: &crate::semantic::MemorySSAFacts,
) -> Vec<(crate::graph::ValueId, crate::graph::ValueId)> {
    type ReadKey = (
        crate::ObjectId,
        i64,
        u32,
        Vec<crate::semantic::MemoryVersion>,
    );
    let mut first_read = BTreeMap::<ReadKey, crate::graph::ValueId>::new();
    let mut pairs = Vec::new();
    for access in memory_accesses.values() {
        if access.is_write || !access.provenance_complete {
            continue;
        }
        let (Some(value), Some(offset)) = (access.value, access.object_offset) else {
            continue;
        };
        let versions = memory
            .uses_by_inst
            .get(access.id.inst)
            .into_iter()
            .flatten()
            .filter(|reached| {
                reached.location.object == access.object
                    && reached.location.size == access.width
                    && reached.location.address.exact_offset() == Some(offset)
            })
            .map(|reached| reached.version)
            .collect::<std::collections::BTreeSet<_>>();
        if versions.is_empty() {
            continue;
        }
        let key = (
            access.object,
            offset,
            access.width,
            versions.into_iter().collect(),
        );
        match first_read.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(value);
            }
            std::collections::btree_map::Entry::Occupied(slot) => {
                pairs.push((*slot.get(), value));
            }
        }
    }
    pairs
}

/// The reads a call's text does not perform: each `CallUse` whose register its call's stated
/// `CallReads` leaves out (D283); an unstated call reads every register. `O(insts + calls x regs)`.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a use site is an (instruction, operand) pair, not a dense id"
    )
)]
pub(crate) fn unpassed_call_reads(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
) -> std::collections::BTreeSet<crate::graph::UseSite> {
    let model = machine_context.and_then(SourceMachineContext::calls);
    // The reads minted just before a call are its own; any other run is read by no call.
    let mut unpassed = std::collections::BTreeSet::new();
    for block in &graph.blocks {
        let mut run = Vec::new();
        for &inst in &block.insts {
            let op = graph.op(inst);
            if let Some(SSAOp::CallUse { storage, .. }) = op {
                run.push((inst, *storage));
                continue;
            }
            // A run no call ends is read by none.
            let Some(call) = op.and_then(SSAOp::call) else {
                let unread = run
                    .drain(..)
                    .map(|(inst, _)| crate::graph::UseSite { inst, input_idx: 0 });
                unpassed.extend(unread);
                continue;
            };
            let reads = (machine_context.zip(call.instruction))
                .and_then(|(context, instruction)| context.call_reads(Some(instruction)));
            let unread = run.drain(..).filter(|(_, storage)| {
                (reads.as_ref().zip(model))
                    .is_some_and(|(reads, model)| reads.reads_none_of(model, *storage))
            });
            unpassed.extend(unread.map(|(inst, _)| crate::graph::UseSite { inst, input_idx: 0 }));
        }
        unpassed.extend(
            run.into_iter()
                .map(|(inst, _)| crate::graph::UseSite { inst, input_idx: 0 }),
        );
    }
    unpassed
}

fn block_at_mut<'a, V>(
    index: &BTreeMap<u64, u32>,
    blocks: &'a mut [SSABlock<V>],
    addr: u64,
) -> Option<&'a mut SSABlock<V>> {
    blocks.get_mut(*index.get(&addr)? as usize)
}

impl SSAFunction {
    /// Which machine instruction this operation executes for; see
    /// [`OpArena::instruction`].
    pub fn instruction_of(&self, id: OpId) -> Option<u64> {
        self.arena().instruction(id)
    }

    /// Every operation and phi this function ever held, by id.
    /// Which bytes each operation and phi wrote as data, as lifted.
    pub fn written(&self) -> &crate::lanes::Written {
        &self.written
    }

    /// The record; for a raw function no preparation recorded, the record as it stands. A sealed
    /// function keeps only its conventional extensions, so it is never captured again.
    pub fn written_or_captured(&self) -> std::borrow::Cow<'_, crate::lanes::Written> {
        match self.written.is_empty() && !self.blocks.is_sealed() {
            false => std::borrow::Cow::Borrowed(&self.written),
            true => std::borrow::Cow::Owned(crate::lanes::Written::capture(
                self,
                &crate::lanes::CallResults::default(),
            )),
        }
    }

    /// Record that a pass over this function moved a state past its stated height; the first
    /// stands, and preparation refuses with it.
    pub(crate) fn note_exhausted(&mut self, exhausted: crate::fixpoint::Exhausted) {
        self.exhausted.get_or_insert(exhausted);
    }

    /// The first pass over this function that moved a state past its stated height.
    pub(crate) const fn exhausted(&self) -> Option<crate::fixpoint::Exhausted> {
        self.exhausted
    }

    /// Record what each operation writes, before anything rewrites one.
    pub(crate) fn capture_written(&mut self, calls: &crate::lanes::CallResults) {
        self.written = crate::lanes::Written::capture(self, calls);
    }

    /// The seal's last step: the graph owns each operation, its origin and each value from here
    /// (doc/adr-one-ir.md, MM.6).
    pub(crate) fn drop_operations(&mut self) {
        debug_assert_eq!(
            self.blocks.len(),
            self.block_order.len(),
            "one block per address"
        );
        self.blocks.drop_operations();
        self.values = crate::value_table::ValueTable::default();
    }

    pub(crate) fn shrink_to_fit(&mut self) {
        self.blocks.shrink_to_fit();
        self.values.shrink_to_fit();
    }

    /// Keep of the record only what the sealed function's readers ask.
    pub(crate) fn seal_written(&mut self) {
        self.written = std::mem::take(&mut self.written).sealed();
    }

    pub fn arena(&self) -> &OpArena {
        debug_assert!(
            !self.blocks.is_sealed(),
            "a sealed function's origins are the graph's"
        );
        self.blocks.arena()
    }

    /// One more than the largest id minted so far: the length of a dense
    /// map indexed by [`OpId`].
    pub fn id_limit(&self) -> usize {
        self.blocks.arena().id_limit()
    }

    /// Apply a pass's plan: its operation edits in IR order, minting what
    /// they insert, then its merge and control-flow edits in the order the
    /// pass stated them, then the reorder it asked for.
    ///
    /// The one path by which a pass changes a function. `O(n)` in the
    /// operations for the operation edits, one block lookup per merge edit,
    /// and one reverse postorder and dominator computation for a reorder.
    pub(crate) fn apply_edits(&mut self, mut plan: EditPlan) {
        if plan.is_empty() {
            return;
        }
        let (shape, reorder) = plan.take_shape();
        if !shape.is_empty() {
            // The loops are the control graph's; any edit to it forgets them.
            self.natural_loops = std::sync::OnceLock::new();
        }
        self.values.adopt(plan.take_minted());
        self.blocks.apply(plan);
        for edit in shape {
            match edit {
                ShapeEdit::ReplacePhi { block, id, phi } => {
                    if let Some(mut block) = self.block_for_change(block) {
                        let index = block.sited_phis().position(|(held, _)| held == id);
                        if let Some(index) = index {
                            block.phis_mut()[index] = phi;
                        }
                    }
                }
                ShapeEdit::DropPhiSources { block, pred } => {
                    if let Some(mut block) = self.block_for_change(block) {
                        for phi in block.phis_mut() {
                            phi.sources.retain(|(source, _)| *source != pred);
                        }
                    }
                }
                ShapeEdit::InsertPhi { block, phi } => {
                    if let Some(mut block) = self.block_for_change(block) {
                        block.push_phi(phi, crate::arena::Pass::PhiPlacement);
                    }
                }
                ShapeEdit::RemoveEdge { from, to } => self.cfg.remove_edge(from, to),
                ShapeEdit::SetTerminator { block, terminator } => {
                    self.cfg.set_terminator(block, terminator);
                }
                ShapeEdit::RemoveBlock(addr) => self.cfg.remove_block(addr),
            }
        }
        if reorder {
            self.reorder_from_cfg();
        }
    }

    /// One block, open for change with the arena; for applying a plan.
    fn block_for_change(&mut self, addr: u64) -> Option<BlockMut<'_, VarId>> {
        let index = *self.block_index.get(&addr)? as usize;
        self.blocks.block_mut(index)
    }

    /// One block, open for change in variables by name: what is written is
    /// interned into the function's table as it is written.
    fn named_block_for_change(&mut self, addr: u64) -> Option<NamedBlockMut<'_>> {
        let index = *self.block_index.get(&addr)? as usize;
        let block = self.blocks.block_mut(index)?;
        Some(NamedBlockMut::new(block, &mut self.values))
    }

    /// Keep the blocks the control-flow graph still has, in its reverse
    /// postorder, and recompute the dominators.
    fn reorder_from_cfg(&mut self) {
        let cfg = &self.cfg;
        self.blocks.retain(Pass::RemoveBlock, |block| {
            cfg.get_block(block.addr).is_some()
        });
        self.block_order = self.cfg.reverse_postorder();
        self.reorder_blocks();
        self.domtree = DomTree::compute(&self.cfg);
        self.natural_loops = std::sync::OnceLock::new();
    }
}

#[cfg(test)]
impl SSAFunction {
    /// The prep facts of this function as it stands, with no interface, and
    /// the graph they are keyed by, for a test that reads them off a
    /// function it does not seal.
    pub(crate) fn prep_facts_for_test(&self) -> Provisional {
        let graph = SsaGraph::from_function_with_storage(self);
        let facts = self
            .collect_decompile_prep_facts_with_control(&graph, None, &UncheckedSsaWorkControl)
            .expect("an unchecked control never stops");
        Provisional { graph, facts }
    }

    /// One block, open for change, for a test that writes a fixture a block
    /// at a time; outside tests a block opens only on a [`Lifted`] function.
    pub(crate) fn edit_block(&mut self, addr: u64) -> Option<NamedBlockMut<'_>> {
        self.named_block_for_change(addr)
    }

    /// The control-flow graph, open for a test that corrupts it to show the
    /// validator refuses what follows.
    pub(crate) fn corrupt_cfg(&mut self) -> &mut CFG {
        self.natural_loops = std::sync::OnceLock::new();
        &mut self.cfg
    }

    /// Drop a block from the blocks and the graph and repair nothing that
    /// named it, for a test that shows the validator refuses what follows.
    pub(crate) fn corrupt_remove_block(&mut self, addr: u64) {
        self.blocks
            .retain(Pass::RemoveBlock, |block| block.addr != addr);
        self.block_order.retain(|&a| a != addr);
        self.block_index = block_index_of(&self.blocks);
        self.cfg.remove_block(addr);
    }
}

/// Where each block sits in a reverse-postorder block vector.
fn block_index_of<V>(blocks: &[SSABlock<V>]) -> BTreeMap<u64, u32> {
    blocks
        .iter()
        .enumerate()
        .filter_map(|(index, block)| Some((block.addr, u32::try_from(index).ok()?)))
        .collect()
}

impl Clone for SSAFunction {
    fn clone(&self) -> Self {
        Self {
            call_preserved_carriers: self.call_preserved_carriers,
            supervisor_calls: self.supervisor_calls.clone(),
            callee_passes: Arc::clone(&self.callee_passes),
            frame_points: self.frame_points.clone(),
            promoted_slots: self.promoted_slots.clone(),
            compiler_inserted: self.compiler_inserted.clone(),
            compiler_inserted_blocks: self.compiler_inserted_blocks.clone(),
            compiler_removed_edges: self.compiler_removed_edges.clone(),
            passing_differences: self.passing_differences.clone(),
            checked_differences: self.checked_differences.clone(),
            decided_dead_blocks: self.decided_dead_blocks.clone(),
            decided_dead_edges: self.decided_dead_edges.clone(),
            premises: self.premises.clone(),
            assumed_exits: self.assumed_exits.clone(),
            stack_pointer_carrier: self.stack_pointer_carrier,
            name: self.name.clone(),
            entry: self.entry,
            cfg: self.cfg.clone(),
            domtree: self.domtree.clone(),
            natural_loops: self.natural_loops.clone(),
            blocks: self.blocks.clone(),
            values: self.values.clone(),
            block_index: self.block_index.clone(),
            block_order: self.block_order.clone(),
            formal_projections: self.formal_projections.clone(),
            formal_roots: self.formal_roots.clone(),
            entry_lanes: self.entry_lanes.clone(),
            written: self.written.clone(),
            exhausted: self.exhausted,
        }
    }
}

/// One function's operations after a pass rewrote them, over the function they
/// belong to.
///
/// The control-flow graph, the dominator tree, the storage map and the
/// projections are statements about the function, not about its operations, so
/// a pass that rewrites operations borrows them rather than copying them.
#[derive(Debug)]
pub struct RewrittenFunction<'a> {
    source: &'a SSAFunction,
    blocks: Vec<SSABlock>,
    block_index: BTreeMap<u64, u32>,
    /// The source's arena, copied, so that what this rewrite inserts is
    /// minted above every id the source holds and never names one of its
    /// operations.
    arena: OpArena,
}

impl<'a> RewrittenFunction<'a> {
    /// Pair rewritten operations with the function whose shape they keep.
    pub fn new(source: &'a SSAFunction, blocks: Vec<SSABlock>) -> Self {
        let block_index = block_index_of(&blocks);
        Self {
            source,
            blocks,
            block_index,
            arena: source.arena().clone(),
        }
    }

    /// The function the operations were rewritten from.
    pub const fn source(&self) -> &'a SSAFunction {
        self.source
    }

    pub const fn entry(&self) -> u64 {
        self.source.entry
    }

    /// The block control enters by; see [`SSAFunction::root`].
    pub const fn root(&self) -> u64 {
        self.source.root()
    }

    pub fn name(&self) -> Option<&str> {
        self.source.name.as_deref()
    }

    pub fn cfg(&self) -> &CFG {
        self.source.cfg()
    }

    pub fn domtree(&self) -> &DomTree {
        self.source.domtree()
    }

    pub fn natural_loops(&self) -> &crate::natural_loops::NaturalLoops {
        self.source.natural_loops()
    }

    /// All blocks in reverse postorder.
    pub fn blocks(&self) -> &[SSABlock] {
        &self.blocks
    }

    pub fn block_addrs(&self) -> &[u64] {
        self.source.block_addrs()
    }

    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn get_block(&self, addr: u64) -> Option<&SSABlock> {
        self.blocks.get(*self.block_index.get(&addr)? as usize)
    }

    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        self.source.predecessors(addr)
    }

    pub fn successors(&self, addr: u64) -> Vec<u64> {
        self.source.successors(addr)
    }

    pub fn dominates(&self, a: u64, b: u64) -> bool {
        self.source.dominates(a, b)
    }

    /// One block of this copy, with the arena what it gains is minted from.
    fn block_mut(&mut self, addr: u64) -> Option<BlockMut<'_>> {
        let index = *self.block_index.get(&addr)? as usize;
        Some(BlockMut::new(self.blocks.get_mut(index)?, &mut self.arena))
    }

    /// Insert operations at `at` in the block at `addr`, each derived by
    /// `pass` from the operation named beside it and minted an id above every
    /// id the source holds. Answers whether the block exists.
    pub fn insert_ops(
        &mut self,
        addr: u64,
        at: usize,
        pass: Pass,
        ops: impl IntoIterator<Item = (SSAOp, Option<OpId>)>,
    ) -> bool {
        let Some(mut block) = self.block_mut(addr) else {
            return false;
        };
        block.insert_ops(at, pass, ops);
        true
    }

    /// Remove the operation at `at` of the block at `addr`; its id is
    /// tombstoned in this copy's arena, never in the source's.
    pub fn remove_op(&mut self, addr: u64, at: usize, pass: Pass) -> Option<SSAOp> {
        let mut block = self.block_mut(addr)?;
        (at < block.len()).then(|| block.remove_op(at, pass))
    }

    /// Keep the phis of the block at `addr` that `keep` accepts. Answers
    /// whether the block exists.
    pub fn retain_phis(
        &mut self,
        addr: u64,
        pass: Pass,
        keep: impl FnMut(&PhiNode) -> bool,
    ) -> bool {
        let Some(mut block) = self.block_mut(addr) else {
            return false;
        };
        block.retain_phis(pass, keep);
        true
    }

    /// Every operation the source and this rewrite ever held, by id.
    pub fn arena(&self) -> &OpArena {
        &self.arena
    }

    /// A second copy of these operations over the same function, for a test
    /// that wants to rewrite them again.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            source: self.source,
            blocks: self.blocks.clone(),
            block_index: self.block_index.clone(),
            arena: self.arena.clone(),
        }
    }

    /// The rewritten operations, in the text the source function dumps.
    pub fn dump(&self) -> String {
        dump_blocks(
            self.name(),
            self.entry(),
            self.blocks(),
            self.source,
            SSAVar::clone,
        )
    }
}

/// One function's blocks as text, shared by a function and by operations
/// rewritten over it.
/// `spell` says what variable an operand of `blocks` is.
fn dump_blocks<V>(
    name: Option<&str>,
    entry: u64,
    blocks: &[SSABlock<V>],
    shape: &SSAFunction,
    spell: impl Fn(&V) -> SSAVar,
) -> String {
    // The entry-edge block has no address of its own; its key is spelled
    // for what it stands for.
    let block_name = |addr: u64| {
        if addr == crate::cfg::ENTRY_EDGE {
            "entry-edge".to_string()
        } else {
            format!("0x{addr:x}")
        }
    };
    let mut out = String::new();

    out.push_str(&format!("Function: {}\n", name.unwrap_or("<unnamed>")));
    out.push_str(&format!("Entry: 0x{:x}\n", entry));
    out.push_str(&format!("Blocks: {}\n\n", blocks.len()));

    for block in blocks {
        {
            let addr = block.addr;
            out.push_str(&format!("Block {}:\n", block_name(addr)));

            // Predecessors
            let preds = shape.predecessors(addr);
            if !preds.is_empty() {
                out.push_str(&format!(
                    "  preds: {}\n",
                    preds
                        .iter()
                        .map(|p| block_name(*p))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            // Phi nodes
            for phi in block.phis() {
                let sources: Vec<String> = phi
                    .sources
                    .iter()
                    .map(|(pred, var)| format!("[{}]: {}", block_name(*pred), spell(var)))
                    .collect();
                out.push_str(&format!(
                    "  {} = phi({})\n",
                    spell(&phi.dst),
                    sources.join(", ")
                ));
            }

            // Operations, spelled the way the phis above are: `SSAOp` has a
            // Display of its own and the derived Debug was shadowing it.
            for op in block.ops() {
                out.push_str(&format!("  {}\n", op.map(&mut |operand| spell(operand))));
            }

            // Successors
            let succs = shape.successors(addr);
            if !succs.is_empty() {
                out.push_str(&format!(
                    "  succs: {}\n",
                    succs
                        .iter()
                        .map(|s| format!("0x{:x}", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            out.push('\n');
        }
    }

    out
}

impl<V> PhiNode<V> {
    /// The same merge over other operands.
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> PhiNode<W> {
        PhiNode {
            dst: f(&self.dst),
            sources: self
                .sources
                .iter()
                .map(|(pred, source)| (*pred, f(source)))
                .collect(),
            canonical_storage: self.canonical_storage,
        }
    }
}

/// A phi node in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiNode<V = SSAVar> {
    /// The destination variable.
    pub dst: V,
    /// The source variables, one per predecessor.
    pub sources: Vec<(u64, V)>, // (predecessor addr, variable)
    /// Name-independent lifted storage identity.
    #[serde(default)]
    pub canonical_storage: Option<CanonicalStorageId>,
}

/// Location metadata for a source variable use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSite {
    /// Source from a phi node input.
    Phi {
        phi_idx: usize,
        src_idx: usize,
        pred_addr: u64,
    },
    /// Source from a regular SSA operation input.
    Op { op_idx: usize, src_idx: usize },
}

/// A source variable with its location metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRef<'a, V = SSAVar> {
    pub var: &'a V,
    pub site: SourceSite,
}

/// Location metadata for a destination variable definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefSite {
    /// Destination written by a phi node.
    Phi { phi_idx: usize },
    /// Destination written by a regular operation.
    Op { op_idx: usize },
}

/// A destination variable with its definition site metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefRef<'a, V = SSAVar> {
    pub var: &'a V,
    pub site: DefSite,
}

/// Registers each direct callee's body proves it leaves exactly as it found
/// them, keyed by the callee's entry address.
///
/// A compiler that has seen the callee relies on this: with `-fipa-ra` GCC
/// keeps a value in an argument register across a call to a leaf that never
/// writes it, so the caller reads that register after the call as its own.
/// Construction consults this before emitting a `CallDefine`, so the read
/// reaches the value the compiler meant rather than a clobber that never
/// happened.
pub type CalleePreservedCarriers = BTreeMap<u64, BTreeSet<CanonicalStorageId>>;

/// What the engine knows of the functions a body calls, by entry address.
#[derive(Debug, Clone, Default)]
pub struct CalleeEvidence {
    /// The interface each callee's own body proved.
    pub interfaces: BTreeMap<u64, SourceFunctionInterface>,
    /// The registers each callee's body proves it leaves alone.
    pub preserved: CalleePreservedCarriers,
    /// How far each callee reaches through each pointer it is handed.
    pub reach: BTreeMap<u64, BTreeMap<usize, crate::interproc::ArgumentReach>>,
    /// The model of each imported library routine called, from r2abi.
    pub library: BTreeMap<u64, crate::interproc::FunctionSemanticSummary>,
    /// The callees a runtime model says re-enter their caller at its entry (Go's stack growth).
    pub reentering: BTreeSet<u64>,
    /// The calls the walk ended the body at because a model says the callee never returns.
    pub exits: AssumedExits,
    /// The imports called whose declaration states no interface, and why.
    pub unstated_imports: BTreeMap<u64, crate::UnstatedImport>,
    /// The convention a call to each callee runs under where the program states it: a bound
    /// import's default, a declaration's own (RULING 1.6, 2.6); every other call runs under `calls`.
    pub conventions: SiteConventions,
}

/// The convention each stated callee runs under, by entry address.
pub type SiteConventions = BTreeMap<u64, Arc<r2source::ConventionModel>>;

/// Calls whose fall-through a body's walk ended because a model, not the program, says the callee
/// never returns, and what that takes for granted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssumedExits {
    pub calls: usize,
    pub premises: BTreeSet<r2source::Premise>,
    /// Blocks, ascending, ending at a call whose callee only a walk found reaching no return: a
    /// bound, so neither an exit nor a `noreturn` (D255).
    pub unproven: Vec<u64>,
}

/// What the callees this function calls said about their own boundaries.
///
/// One callee, one answer: the carriers its body proves it hands back
/// untouched, and the carrier its interface names as its result. Both sides of
/// a call read this same statement, so neither can believe something the other
/// denies.
#[derive(Debug, Clone, Default)]
pub(crate) struct CalleeBoundaries {
    preserved: CalleePreservedCarriers,
    /// The convention each stated callee runs under; the rest run under the calls' model.
    conventions: SiteConventions,
    /// The import slot each `CallSlot` site calls through, by instruction (D364).
    slots: BTreeMap<u64, u64>,
    results: BTreeMap<u64, CallBoundaryDef>,
    /// The storage of each of `results`.
    result_storages: BTreeMap<u64, CanonicalStorageId>,
    /// Callees whose body proves the result carrier holds the return address.
    return_addresses: BTreeMap<u64, CanonicalStorageId>,
    /// Callees whose body is a proven `/GS` check, which returns no result.
    security_checks: BTreeSet<u64>,
}

impl CalleeBoundaries {
    /// Read both facts off the interfaces the callees' own bodies proved.
    pub(crate) fn from_interfaces(
        arch: Option<&crate::Arch>,
        preserved: &CalleePreservedCarriers,
        interfaces: &BTreeMap<u64, SourceFunctionInterface>,
    ) -> Self {
        let names = arch.map(crate::Arch::register_names);
        let mut preserved = preserved.clone();
        let mut results = BTreeMap::new();
        let mut result_storages = BTreeMap::new();
        let mut return_addresses = BTreeMap::new();
        let mut security_checks = BTreeSet::new();
        for (address, interface) in interfaces {
            // A check's call is the compiler's; what it leaves in the result carrier is no result.
            if interface.security_check() {
                security_checks.insert(*address);
                continue;
            }
            // The same boundary cannot both hand a register back untouched and name it as what it
            // returns: a pair's two registers alike.
            let returned = interface.return_kind().storages().collect::<Vec<_>>();
            if let Some(carriers) = preserved.get_mut(address) {
                carriers.retain(|carrier| {
                    !(returned.iter()).any(|storage| {
                        crate::semantic::register_storages_overlap(*carrier, *storage)
                    })
                });
            }
            // The first register is the result a call defines whatever the convention clobbers; a
            // pair's second (SysV RDX, AAPCS64 x1) is caller-saved, so every call defines it.
            let Some(&storage) = returned.first() else {
                continue;
            };
            let Some(name) = names
                .as_ref()
                .and_then(|names| names.get(&(storage.offset, storage.size)))
            else {
                continue;
            };
            results.insert(
                *address,
                CallBoundaryDef {
                    name: name.clone(),
                    size: storage.size,
                },
            );
            result_storages.insert(*address, storage);
            if interface.body_proven_return_address() && returned.len() == 1 {
                return_addresses.insert(*address, storage);
            }
        }
        Self {
            preserved,
            conventions: SiteConventions::new(),
            slots: BTreeMap::new(),
            results,
            result_storages,
            return_addresses,
            security_checks,
        }
    }

    /// The same statements with the convention each stated callee runs under.
    pub(crate) fn with_conventions(mut self, conventions: SiteConventions) -> Self {
        self.conventions = conventions;
        self
    }

    /// The same statements with the slot each correlated `CallSlot` site calls through.
    fn with_slots(mut self, slots: &BTreeMap<SourceCallSiteIdentity, u64>) -> Self {
        let by_instruction = slots.iter().map(|(site, slot)| (site.instruction(), *slot));
        self.slots = by_instruction.collect();
        self
    }

    /// The callees whose body is a proven `/GS` check.
    pub(crate) const fn security_checks(&self) -> &BTreeSet<u64> {
        &self.security_checks
    }

    /// What each callee proves it leaves alone, less its own result carrier.
    pub(crate) const fn preserved(&self) -> &CalleePreservedCarriers {
        &self.preserved
    }

    /// The carrier each callee proves holds the address the call pushed.
    pub(crate) const fn return_addresses(&self) -> &BTreeMap<u64, CanonicalStorageId> {
        &self.return_addresses
    }
}

/// What a call boundary does to this body's registers.
///
/// `stack_pointer_restored_by_callee` carries the storage only when the source
/// stated that the convention restores it; see the field's own documentation
/// for why the caller's stack pointer is otherwise wrong from its first call
/// onward.
/// Under no calls' model a call reads and clobbers every outermost register (RULING 2.1).
fn decompile_call_boundary_config(
    blocks: &[R2ILBlock],
    arch: Option<&crate::Arch>,
    machine_context: &SourceMachineContext,
    stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
    callees: CalleeBoundaries,
) -> Result<Option<CallBoundaryConfig>, SsaPrepareError> {
    let Some(arch) = arch else {
        return Ok(None);
    };
    let calls = blocks
        .iter()
        .flat_map(|block| &block.ops)
        .any(R2ILOp::is_call);
    let model = machine_context.calls();
    // A body that never calls has no call to clobber anything. What a call keeps is what the
    // convention preserves and what the platform reserves alike: neither is a call's definition.
    let (clobbered, preserved) = match calls {
        true => (
            machine_context.call_clobbered_carriers().to_vec(),
            (model
                .map(|model| (model.preserved_registers().iter()).chain(model.system_reserved())))
            .into_iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        ),
        false => (Vec::new(), Vec::new()),
    };
    // No register is a result under no model: the result is unproven, never void (S34).
    let returned = (model.and_then(r2source::ConventionModel::result_reads)).unwrap_or(&[]);
    let config = CallBoundaryConfig {
        clobbered,
        preserved,
        stack_pointer_restored_by_callee,
        preserved_by_target: callees.preserved,
        convention_by_target: callees.conventions,
        slot_by_instruction: callees.slots,
        result_by_target: callees.results,
        argument_regs: match calls {
            true => arch.call_reads(model).to_vec(),
            false => Vec::new(),
        },
        return_regs: returned.to_vec(),
    };
    let inert = config.clobbered.is_empty()
        && config.stack_pointer_restored_by_callee.is_none()
        && config.argument_regs.is_empty()
        && config.return_regs.is_empty();
    Ok((!inert).then_some(config))
}

impl SSAFunction {
    /// The architectural stack pointer, as the machine roles name it.
    pub const fn stack_pointer_carrier(&self) -> Option<CanonicalStorageId> {
        self.stack_pointer_carrier
    }

    /// State what each direct callee leaves as found, for a build kept against other statements.
    pub(crate) fn set_callee_passes(&mut self, preserved: &CalleePreservedCarriers) {
        self.callee_passes = Arc::new(preserved.clone());
    }

    /// Whether the direct callee at `target` leaves every byte of `storage` as it found it.
    pub(crate) fn call_passes(&self, target: u64, storage: CanonicalStorageId) -> bool {
        (self.callee_passes.get(&target)).is_some_and(|kept| crate::semantic::covers(kept, storage))
    }

    /// Whether this user operation enters the supervisor, whose kernel-written result no contract names.
    pub fn enters_supervisor<V>(&self, op: &SSAOp<V>) -> bool {
        matches!(op, SSAOp::CallOther { userop, .. } if self.supervisor_calls.contains(userop))
    }

    /// The memory operations slot promotion rewrote into copies, by where they were lifted:
    /// `(block, index)`, read while the function has its origins.
    pub const fn promoted_slots(&self) -> &BTreeSet<(u64, usize)> {
        &self.promoted_slots
    }

    /// Whether what promotion decided read some call's argument area.
    pub(crate) fn argument_areas_read(&self) -> bool {
        (self.frame_points.as_deref()).is_some_and(crate::semantic::FramePoints::by_area)
    }

    /// The (callee, argument position) pairs whose upward reach promotion's walk asked (D365).
    pub(crate) fn asked_reach(&self) -> &BTreeSet<(u64, usize)> {
        static NONE: BTreeSet<(u64, usize)> = BTreeSet::new();
        (self.frame_points.as_deref()).map_or(&NONE, crate::semantic::FramePoints::asked_reach)
    }

    /// What the frame's addresses do, by entry offset; none where no walk ran (the whole frame).
    pub fn frame_points(&self) -> Option<&crate::semantic::FramePoints> {
        self.frame_points.as_deref()
    }

    pub(crate) fn record_promoted_slots(
        &mut self,
        (ops, points): (
            crate::dense::IdSet<crate::arena::OpId>,
            crate::semantic::FramePoints,
        ),
    ) {
        self.frame_points = Some(Arc::new(points));
        let arena = self.arena();
        self.promoted_slots = (ops.iter())
            .filter_map(|op| match arena.origin(op)? {
                crate::arena::OpOrigin::Lifted { block, index, .. } => Some((*block, *index)),
                crate::arena::OpOrigin::Derived { .. } => None,
            })
            .collect();
    }

    /// The operations a decided compiler-inserted check is (`crate::stack_protector`,
    /// `crate::stack_bound`).
    pub fn compiler_inserted(&self) -> &crate::dense::IdSet<crate::arena::OpId> {
        &self.compiler_inserted
    }

    pub(crate) fn record_compiler_inserted(
        &mut self,
        ops: crate::dense::IdSet<crate::arena::OpId>,
        blocks: BTreeMap<u64, u32>,
        edges: BTreeSet<(u64, u64)>,
    ) {
        self.compiler_inserted.extend(ops.iter());
        self.compiler_inserted_blocks.extend(blocks);
        self.compiler_removed_edges.extend(edges);
    }

    pub(crate) fn record_passing_differences(
        &mut self,
        differences: impl IntoIterator<Item = (crate::value_table::VarId, u64)>,
    ) {
        self.passing_differences.extend(differences);
    }

    pub(crate) fn record_checked_differences(
        &mut self,
        differences: impl IntoIterator<Item = crate::value_table::VarId>,
    ) {
        self.checked_differences.extend(differences);
        self.checked_differences.sort_unstable();
        self.checked_differences.dedup();
    }

    /// Whether a decided check wrote anything: its residue is no C expression's (case 3).
    pub(crate) fn has_compiler_inserted_writes(&self) -> bool {
        !self.compiler_inserted.is_empty() || !self.checked_differences.is_empty()
    }

    /// Whether `var` is a decided canary check's difference (doc/adr-scratch-result.md, case 3).
    pub(crate) fn is_checked_difference(&self, var: crate::value_table::VarId) -> bool {
        self.checked_differences.binary_search(&var).is_ok()
    }

    /// A decided canary check's difference, 0 past its passing edge, and the block that edge enters.
    pub(crate) fn passing_differences(&self) -> &[(crate::value_table::VarId, u64)] {
        &self.passing_differences
    }

    /// Record a premise a rewrite relied on.
    pub(crate) fn record_premise(&mut self, premise: r2source::Premise) {
        self.premises.insert(premise);
    }

    /// The premises a rewrite of this function relied on: a decided check changed its control flow,
    /// or its walk ended at a call a model says never returns.
    pub fn premises(&self) -> &BTreeSet<r2source::Premise> {
        &self.premises
    }

    /// The calls its walk ended at on a model's word that the callee never returns.
    pub fn assumed_exits(&self) -> &AssumedExits {
        &self.assumed_exits
    }

    pub(crate) fn record_assumed_exits(&mut self, exits: &AssumedExits) {
        self.premises.extend(exits.premises.iter().copied());
        self.assumed_exits = exits.clone();
    }

    /// The failure blocks a decided compiler-inserted check removed.
    pub fn compiler_inserted_blocks(&self) -> &BTreeMap<u64, u32> {
        &self.compiler_inserted_blocks
    }

    /// The blocks a decided branch left unreachable, which the function's bytes still hold.
    pub fn decided_dead_blocks(&self) -> &BTreeMap<u64, u32> {
        &self.decided_dead_blocks
    }

    /// The edges a decided branch dropped, (from, to), in address order.
    pub fn decided_dead_edges(&self) -> &BTreeSet<(u64, u64)> {
        &self.decided_dead_edges
    }

    pub(crate) fn record_decided_dead(
        &mut self,
        blocks: BTreeMap<u64, u32>,
        edges: BTreeSet<(u64, u64)>,
    ) {
        self.decided_dead_blocks.extend(blocks);
        self.decided_dead_edges.extend(edges);
    }

    /// The edges a decided check removed, (from, to), in address order.
    pub fn compiler_removed_edges(&self) -> &BTreeSet<(u64, u64)> {
        &self.compiler_removed_edges
    }

    /// Set the function name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The block control enters the function by: the root of the graph,
    /// which no edge reaches.
    ///
    /// It is the block at [`Self::entry`] unless a branch in the body also
    /// targets that address; then it is the empty [`crate::cfg::ENTRY_EDGE`]
    /// block in front of it, where the values the function is entered with
    /// are defined and from which they reach the merges at `entry`. A pass
    /// that starts a walk, seeds an entry state or places an entry
    /// definition starts here; `entry` names the function.
    pub const fn root(&self) -> u64 {
        self.cfg.entry
    }

    /// Get a block by address.
    pub fn get_block(&self, addr: u64) -> Option<&SSABlock<VarId>> {
        self.blocks.get(*self.block_index.get(&addr)? as usize)
    }

    /// All blocks in reverse postorder.
    pub fn blocks(&self) -> &[SSABlock<VarId>] {
        &self.blocks
    }

    /// The variable an operand id is spelled as.
    pub fn var(&self, id: VarId) -> &SSAVar {
        debug_assert!(
            !self.blocks.is_sealed(),
            "a sealed function's values are the graph's"
        );
        self.values.var(id)
    }

    /// The table of every operand id.
    pub const fn values(&self) -> &crate::value_table::ValueTable {
        debug_assert!(
            !self.blocks.is_sealed(),
            "a sealed function's values are the graph's"
        );
        &self.values
    }

    /// An operation with its operands spelled as variables, for a reader
    /// that still works in names (doc/adr-one-ir.md, stages 4 and 5 move the
    /// last of them onto ids). A variable's name is interned, so the copy
    /// clones no string.
    pub fn named(&self, op: &SSAOp<VarId>) -> SSAOp {
        op.map(&mut |id| self.var(*id).clone())
    }

    /// A block with its operands spelled as variables, every operation and
    /// phi keeping its id; see [`Self::named`].
    pub fn named_block(&self, addr: u64) -> Option<SSABlock> {
        Some(
            self.get_block(addr)?
                .map_operands(&mut |id| self.var(*id).clone()),
        )
    }

    /// Every block, named; see [`Self::named_block`].
    pub fn named_blocks(&self) -> Vec<SSABlock> {
        self.blocks()
            .iter()
            .map(|block| block.map_operands(&mut |id| self.var(*id).clone()))
            .collect()
    }

    /// Get block addresses in reverse postorder.
    pub fn block_addrs(&self) -> &[u64] {
        &self.block_order
    }

    /// Return name-independent storage provenance retained from the lifted
    /// varnode that produced or supplied this SSA value.
    ///
    /// Values are attached from raw varnodes at the lift/SSA seam, into the
    /// value table's storage column. Consumers must not reconstruct this
    /// information from `SSAVar::name`.
    pub(crate) fn canonical_storage_for_var(&self, var: &SSAVar) -> Option<CanonicalStorageId> {
        debug_assert!(
            !self.blocks.is_sealed(),
            "a sealed function's values are the graph's"
        );
        self.values.storage_of_var(var)
    }

    /// The lifted storage of a variable the function holds by id.
    pub(crate) fn storage_of(&self, id: VarId) -> Option<CanonicalStorageId> {
        debug_assert!(
            !self.blocks.is_sealed(),
            "a sealed function's values are the graph's"
        );
        self.values.storage(id)
    }

    /// Get the number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.block_order.len()
    }

    /// Get the CFG.
    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    /// Get the dominator tree.
    pub fn domtree(&self) -> &DomTree {
        &self.domtree
    }

    /// The natural loops of the control graph.
    pub fn natural_loops(&self) -> &crate::natural_loops::NaturalLoops {
        self.natural_loops
            .get_or_init(|| crate::natural_loops::NaturalLoops::compute(&self.cfg, &self.domtree))
    }

    /// Get predecessors of a block.
    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        self.cfg.predecessors(addr)
    }

    /// Get successors of a block.
    pub fn successors(&self, addr: u64) -> Vec<u64> {
        self.cfg.successors(addr)
    }

    /// Check if block A dominates block B.
    pub fn dominates(&self, a: u64, b: u64) -> bool {
        self.domtree.dominates(a, b)
    }

    /// Summarize CFG features that are useful for conservative decompiler preflight.
    ///
    /// This is intentionally query-only: it reports structure, but does not encode
    /// fallback policy or mutate SSA state.
    pub fn cfg_risk_summary(&self) -> CFGRiskSummary {
        let back_edges = self.cfg.collect_back_edges();
        let back_edge_count = back_edges.values().map(Vec::len).sum();
        let loop_count = back_edges.len();
        let mut switch_block_count = 0usize;
        let mut max_switch_cases = 0usize;

        for &addr in &self.block_order {
            if let Some(crate::cfg::BlockTerminator::Switch { cases, default }) =
                self.cfg.get_block(addr).map(|block| &block.terminator)
            {
                switch_block_count += 1;
                let case_count = cases.len() + usize::from(default.is_some());
                max_switch_cases = max_switch_cases.max(case_count);
            }
        }

        // The program's blocks: the entry-edge block is the graph's own.
        let block_count = self.num_blocks().max(self.cfg.block_addrs().count())
            - usize::from(self.cfg.has_entry_edge());

        CFGRiskSummary {
            block_count,
            loop_count,
            back_edge_count,
            switch_block_count,
            max_switch_cases,
        }
    }

    /// Get the immediate dominator of a block.
    pub fn idom(&self, block: u64) -> Option<u64> {
        self.domtree.idom(block)
    }

    /// Get the edge type between two blocks.
    pub fn edge_type(&self, from: u64, to: u64) -> Option<CFGEdge> {
        self.cfg.edge_type(from, to)
    }

    /// Put the blocks back in the order `block_order` states, and reindex.
    fn reorder_blocks(&mut self) {
        self.blocks.reorder(&self.block_order);
        self.block_index = block_index_of(&self.blocks);
    }

    /// Iterate over all SSA operations in the function.
    pub fn all_ops(&self) -> impl Iterator<Item = &SSAOp<VarId>> {
        self.blocks.iter().flat_map(|b| b.ops().iter())
    }

    /// Iterate over all source uses in all blocks.
    pub fn for_each_source<F: FnMut(u64, SourceRef<'_>)>(&self, mut f: F) {
        for block in self.blocks() {
            block.for_each_source(|src| {
                f(
                    block.addr,
                    SourceRef {
                        var: self.var(*src.var),
                        site: src.site,
                    },
                );
            });
        }
    }

    /// The storage an entry-lane projection stands for.
    pub fn formal_projection_storage(&self, id: VarId) -> Option<CanonicalStorageId> {
        self.formal_projections.get(id).copied()
    }

    pub(crate) fn formal_projection_ids(
        &self,
    ) -> impl Iterator<Item = (VarId, &CanonicalStorageId)> {
        self.formal_projections.iter()
    }

    pub(crate) fn formal_root_ids(&self) -> impl Iterator<Item = (VarId, &CanonicalStorageId)> {
        self.formal_roots.iter()
    }

    /// Each entry-lane formal at the low end of its root, with the root.
    pub(crate) fn entry_lanes(&self) -> impl Iterator<Item = (VarId, VarId)> + '_ {
        self.entry_lanes.iter().map(|(lane, root)| (lane, *root))
    }

    /// Print the function in a human-readable format.
    pub fn dump(&self) -> String {
        dump_blocks(
            self.name.as_deref(),
            self.entry,
            self.blocks(),
            self,
            |id| self.var(*id).clone(),
        )
    }
}

/// One storage range inside a register family, identified by where it starts
/// and how wide it is rather than by any name the architecture gives it.
/// Whether `R2SLEIGH_DUMP_IL` asks for the lifted blocks on stderr.
fn dump_il() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("R2SLEIGH_DUMP_IL").is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterFamilySlot {
    pub family_id: usize,
    pub offset: u64,
    pub width: u32,
}

#[derive(Debug, Clone, Copy)]
struct RegisterFamilyMember {
    family_id: usize,
    offset: u64,
    width: u32,
}

/// Which register storage ranges alias which, derived from the architecture's
/// own register geometry rather than from a table of names.
#[derive(Debug, Clone, Default)]
pub struct RegisterFamilyInfo {
    name_to_member: FxHashMap<String, RegisterFamilyMember>,
    /// Whether a 32-bit write to a general register clears the rest of it.
    /// Which family covers a register-space range, for storage the arch does not name.
    family_ranges: Vec<(u64, u64, usize)>,
    family_slots: FxHashMap<usize, Vec<RegisterFamilySlot>>,
    /// The narrowest declared slot of each family that contains every range
    /// one function touches of it; see [`Self::with_program_roots`].
    program_roots: FxHashMap<usize, RegisterFamilySlot>,
    /// Whether a register's lowest address holds its most significant byte.
    big_endian: bool,
}

impl RegisterFamilyInfo {
    pub fn from_arch(arch: &ArchSpec) -> Self {
        Self::from_register_storages(
            arch.registers
                .iter()
                .map(|reg| (reg.name.as_str(), reg.offset, reg.size)),
        )
        .with_big_endian(arch.register_bytes_are_big_endian())
    }

    /// The same families with the register file's byte order stated.
    pub fn with_big_endian(mut self, big_endian: bool) -> Self {
        self.big_endian = big_endian;
        self
    }

    /// The same families with each one's root narrowed to what a function
    /// actually touches of it.
    ///
    /// The architecture names ranges no program uses: Ghidra models `XMM2` as
    /// a lane of a 512-bit `ZMM2`, and a function doing legacy SSE work never
    /// mentions the wider register at all. Renaming such a lane as a
    /// projection of `ZMM2` would make its first write read a 512-bit value
    /// nothing supplied, and the rendering an uninitialised read. The root is
    /// therefore the narrowest declared slot containing every range this
    /// function reads or writes of the family, which is `XMM2` there and the
    /// full register wherever the program really uses it -- a call's clobber
    /// of the whole carrier included, which is why those ranges are counted
    /// here too.
    pub fn with_program_roots(&self, used: impl IntoIterator<Item = (u64, u32)>) -> Self {
        let mut extents = FxHashMap::<usize, (u64, u64)>::default();
        for (offset, size) in used {
            let Some(member) = self.member_at_offset(offset, size) else {
                continue;
            };
            let end = offset.saturating_add(u64::from(size));
            let extent = extents.entry(member.family_id).or_insert((offset, end));
            extent.0 = extent.0.min(offset);
            extent.1 = extent.1.max(end);
        }
        let mut program_roots = FxHashMap::default();
        for (family_id, (start, end)) in extents {
            let Some(slots) = self.family_slots.get(&family_id) else {
                continue;
            };
            if let Some(slot) = slots
                .iter()
                .filter(|slot| {
                    slot.offset <= start && end <= slot.offset.saturating_add(u64::from(slot.width))
                })
                .min_by_key(|slot| slot.width)
            {
                program_roots.insert(family_id, *slot);
            }
        }
        Self {
            program_roots,
            ..self.clone()
        }
    }

    /// The byte a lane starts at, counted from its root's least significant
    /// byte, which is the offset a `Subpiece` or `Insert` of the root takes.
    pub fn lane_lsb_byte(&self, root: RegisterFamilySlot, offset: u64, size: u32) -> u64 {
        if self.big_endian {
            (root.offset + u64::from(root.width)) - (offset + u64::from(size))
        } else {
            offset - root.offset
        }
    }

    /// Build the families from register storage geometry alone.
    ///
    /// Membership is a fact about which byte ranges overlap, so any caller
    /// holding names and canonical storage -- an `ArchSpec` or a prepared
    /// function's machine context -- gets the same answer from the same
    /// geometry, with no per-architecture name table in between.
    pub fn from_register_storages<'a, I>(registers: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, u64, u32)>,
    {
        #[derive(Clone)]
        struct RangeReg {
            name: String,
            offset: u64,
            size: u32,
        }

        fn find(parents: &mut [usize], idx: usize) -> usize {
            if parents[idx] != idx {
                let root = find(parents, parents[idx]);
                parents[idx] = root;
            }
            parents[idx]
        }

        fn union(parents: &mut [usize], a: usize, b: usize) {
            let root_a = find(parents, a);
            let root_b = find(parents, b);
            if root_a != root_b {
                parents[root_b] = root_a;
            }
        }

        fn range_end(reg: &RangeReg) -> u64 {
            reg.offset.saturating_add(reg.size as u64)
        }

        let regs: Vec<RangeReg> = registers
            .into_iter()
            .map(|(name, offset, size)| RangeReg {
                name: name.to_lowercase(),
                offset,
                size,
            })
            .collect();

        if regs.is_empty() {
            return Self::default();
        }

        let mut parents: Vec<usize> = (0..regs.len()).collect();
        let mut sorted_indices: Vec<usize> = (0..regs.len()).collect();
        sorted_indices.sort_unstable_by_key(|&idx| (regs[idx].offset, range_end(&regs[idx])));

        let mut cluster_root = sorted_indices[0];
        let mut cluster_end = range_end(&regs[cluster_root]);
        for &idx in sorted_indices.iter().skip(1) {
            let reg = &regs[idx];
            if reg.offset < cluster_end {
                union(&mut parents, cluster_root, idx);
                cluster_end = cluster_end.max(range_end(reg));
            } else {
                cluster_root = idx;
                cluster_end = range_end(reg);
            }
        }

        let mut root_to_family = FxHashMap::default();
        let mut next_family_id = 0usize;
        let mut name_to_member = FxHashMap::default();
        let mut family_width_sets: FxHashMap<(usize, u64), FxHashSet<u32>> = FxHashMap::default();

        for (idx, reg) in regs.iter().enumerate() {
            let root = find(&mut parents, idx);
            let family_id = *root_to_family.entry(root).or_insert_with(|| {
                let id = next_family_id;
                next_family_id += 1;
                id
            });
            name_to_member.insert(
                reg.name.clone(),
                RegisterFamilyMember {
                    family_id,
                    offset: reg.offset,
                    width: reg.size,
                },
            );
            family_width_sets
                .entry((family_id, reg.offset))
                .or_default()
                .insert(reg.size);
        }

        let family_widths_by_offset: FxHashMap<(usize, u64), Vec<u32>> = family_width_sets
            .into_iter()
            .map(|(family_and_offset, mut widths)| {
                let mut widths: Vec<u32> = widths.drain().collect();
                widths.sort_unstable();
                (family_and_offset, widths)
            })
            .collect();
        let mut family_slots: FxHashMap<usize, Vec<RegisterFamilySlot>> = FxHashMap::default();
        for (&(family_id, offset), widths) in &family_widths_by_offset {
            family_slots
                .entry(family_id)
                .or_default()
                .extend(widths.iter().copied().map(|width| RegisterFamilySlot {
                    family_id,
                    offset,
                    width,
                }));
        }
        for slots in family_slots.values_mut() {
            slots.sort_unstable_by_key(|slot| (slot.offset, slot.width));
            slots.dedup();
        }

        let mut family_ranges: Vec<(u64, u64, usize)> = Vec::new();
        for (idx, reg) in regs.iter().enumerate() {
            let family_id = root_to_family[&find(&mut parents, idx)];
            family_ranges.push((reg.offset, range_end(reg), family_id));
        }
        family_ranges.sort_unstable();
        family_ranges.dedup();
        let mut merged: Vec<(u64, u64, usize)> = Vec::with_capacity(family_ranges.len());
        for (start, end, family_id) in family_ranges {
            match merged.last_mut() {
                Some(last) if last.2 == family_id && start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end, family_id)),
            }
        }

        Self {
            name_to_member,
            family_ranges: merged,
            family_slots,
            program_roots: FxHashMap::default(),
            big_endian: false,
        }
    }

    /// The program root containing the named register: the identity of its
    /// family in this function, as `root_slot_containing` answers for storage.
    pub fn root_slot_for_name(&self, name: &str) -> Option<RegisterFamilySlot> {
        let member = self.member_for_name(name)?;
        self.root_slot_containing(member.offset, member.width)
    }

    fn member_for_name(&self, name: &str) -> Option<RegisterFamilyMember> {
        if let Some(member) = self.name_to_member.get(name) {
            return Some(*member);
        }
        self.name_to_member
            .get(name.to_ascii_lowercase().as_str())
            .copied()
    }

    /// The whole register a storage range is part of.
    /// The widest register containing a storage range: the identity every
    /// value of the family has under `doc/adr-register-identity.md`. `None`
    /// for a range no family covers, and for one that is already its root.
    pub(crate) fn root_slot_over(&self, offset: u64, size: u32) -> Option<RegisterFamilySlot> {
        let root = self.root_slot_containing(offset, size)?;
        (root.offset != offset || root.width != size).then_some(root)
    }

    /// The root a storage range lies in, which may be the range itself.
    pub(crate) fn root_slot_containing(
        &self,
        offset: u64,
        size: u32,
    ) -> Option<RegisterFamilySlot> {
        let member = self.member_at_offset(offset, size)?;
        let end = offset.saturating_add(u64::from(size));
        self.program_roots
            .get(&member.family_id)
            .copied()
            .filter(|root| {
                root.offset <= offset && end <= root.offset.saturating_add(u64::from(root.width))
            })
            .or_else(|| self.widest_slot_containing(member))
    }

    /// Where the family a storage range belongs to begins and ends in the register file.
    pub(crate) fn family_extent(&self, offset: u64, size: u32) -> Option<(u64, u64)> {
        let end = offset.checked_add(u64::from(size))?;
        let index = (self.family_ranges).partition_point(|(start, _, _)| *start <= offset);
        let (start, family_end, _) = *self.family_ranges[..index].iter().next_back()?;
        (start <= offset && end <= family_end).then_some((start, family_end))
    }

    fn widest_slot_containing(&self, member: RegisterFamilyMember) -> Option<RegisterFamilySlot> {
        self.family_slots
            .get(&member.family_id)?
            .iter()
            .filter(|slot| {
                slot.offset <= member.offset
                    && member.offset + u64::from(member.width)
                        <= slot.offset + u64::from(slot.width)
            })
            .max_by_key(|slot| slot.width)
            .copied()
    }

    /// Which family a storage range belongs to, for a varnode the arch does not name.
    ///
    /// Family membership is a fact about storage, so an unnamed sub-range of a
    /// register belongs to the same family as the register that contains it.
    fn member_at_offset(&self, offset: u64, size: u32) -> Option<RegisterFamilyMember> {
        let end = offset.checked_add(size as u64)?;
        let idx = self
            .family_ranges
            .partition_point(|(start, _, _)| *start <= offset);
        let (start, family_end, family_id) = *self.family_ranges[..idx].iter().next_back()?;
        if offset < start || end > family_end {
            return None;
        }
        Some(RegisterFamilyMember {
            family_id,
            offset,
            width: size,
        })
    }
}

impl<V> SSABlock<V> {
    /// Visit all phi source variables in deterministic index order.
    pub fn for_each_phi_source<F: FnMut(SourceRef<'_, V>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis().iter().enumerate() {
            for (src_idx, (pred_addr, src)) in phi.sources.iter().enumerate() {
                f(SourceRef {
                    var: src,
                    site: SourceSite::Phi {
                        phi_idx,
                        src_idx,
                        pred_addr: *pred_addr,
                    },
                });
            }
        }
    }

    /// Visit all operation source variables in deterministic index order.
    pub fn for_each_op_source<F: FnMut(SourceRef<'_, V>)>(&self, mut f: F) {
        for (op_idx, op) in self.ops().iter().enumerate() {
            let mut src_idx = 0usize;
            op.for_each_source(|src| {
                f(SourceRef {
                    var: src,
                    site: SourceSite::Op { op_idx, src_idx },
                });
                src_idx += 1;
            });
        }
    }

    /// Visit all source variables (phis first, then ops) in index order.
    pub fn for_each_source<F: FnMut(SourceRef<'_, V>)>(&self, mut f: F) {
        self.for_each_phi_source(&mut f);
        self.for_each_op_source(f);
    }

    /// Visit all destination definitions (phis first, then ops) in index order.
    pub fn for_each_def<F: FnMut(DefRef<'_, V>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis().iter().enumerate() {
            f(DefRef {
                var: &phi.dst,
                site: DefSite::Phi { phi_idx },
            });
        }

        for (op_idx, op) in self.ops().iter().enumerate() {
            if let Some(dst) = op.dst() {
                f(DefRef {
                    var: dst,
                    site: DefSite::Op { op_idx },
                });
            }
        }
    }

    /// Check if this block has any phi nodes.
    pub fn has_phis(&self) -> bool {
        !self.phis().is_empty()
    }

    /// Get the number of phi nodes.
    pub fn num_phis(&self) -> usize {
        self.phis().len()
    }

    /// Get the number of operations (excluding phi nodes).
    pub fn num_ops(&self) -> usize {
        self.ops().len()
    }
}

mod forward;

#[cfg(test)]
mod tests;

/// Prep facts and the graph whose values key them, for a function analysed but not sealed.
pub(crate) struct Provisional {
    pub(crate) graph: SsaGraph,
    pub(crate) facts: DecompilePrepFacts,
}

#[cfg(test)]
impl Provisional {
    /// The graph's value for a variable the test names.
    pub(crate) fn value(&self, var: &SSAVar) -> ValueId {
        self.graph
            .value_id_for_var(var)
            .unwrap_or_else(|| panic!("{var} is a value of the graph"))
    }
}

impl Deref for Provisional {
    type Target = DecompilePrepFacts;

    fn deref(&self) -> &DecompilePrepFacts {
        &self.facts
    }
}
