//! Function-level SSA representation.
//!
//! This module provides the `SSAFunction` type which combines all SSA
//! components for a complete function: CFG, dominator tree, phi nodes,
//! and renamed operations.

mod blocks;
mod build;
mod dead_frame_stores;
mod edit;
mod named_edit;
mod rewrite;
mod stack_roots;
mod stage;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, OnceLock, RwLock};

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
    SourceCallSiteIdentity, SourceCallSiteInterface, SourceConventionSlots,
    SourceFunctionInterface, SourceMachineContext, SourceMachineRoles,
};
use crate::naming::{ARCH_DERIVED_CACHE_MAX_ENTRIES, ArchCacheTag, cached_register_name_map};
use crate::op::SSAOp;
use crate::phi::{PhiPlacement, collect_defs_from_cfg_with_names_storage_and_control};
use crate::rename::{CallBoundaryConfig, CallBoundaryDef, rename_function};
use crate::semantic::{
    CallResultCertificate, CallSiteFacts, CallSiteId, CallsiteCertificate, MemoryAccessCertificate,
    MemoryDefFact, MemorySSAFacts, MemoryUseFact, ObjectId, ObjectModel, PredicateFacts,
    PreparedFunctionFacts, ReturnValueCertificate, StackReloadSourceCertificate,
    StructuredDataflowFacts,
};
use crate::span::StorageSpans;
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
#[track_caller]
fn integrity_refusal(error: SsaIntegrityError) -> SsaPrepareError {
    r2il::refusal_evidence!("ssa-integrity", "{error:?}");
    malformed_ssa_input()
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
    convention: Option<&'a SourceConventionSlots>,
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
    fn before_recovery(convention: &'a SourceConventionSlots) -> Self {
        Self {
            convention: Some(convention),
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
                .argument_slots()
                .iter()
                .chain(convention.result_slot().as_ref())
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
                    .and_then(|interface| match interface.return_kind() {
                        crate::SourceFunctionReturn::Register { storage } => Some(storage),
                        crate::SourceFunctionReturn::Void
                        | crate::SourceFunctionReturn::Unproven => None,
                    }),
            )
            .collect()
    }

    /// The register a caller reads the result from, whose merges in a
    /// returning block keep their sources: the interface's, where it
    /// describes it coherently, or the convention's.
    pub(crate) fn return_carrier(self) -> Option<CanonicalStorageId> {
        match self.convention {
            Some(convention) => convention
                .result_slot()
                .filter(|slot| slot.space == CanonicalStorageSpace::Register),
            None => self
                .for_return_boundary()
                .and_then(crate::optimize::coherent_return_carrier),
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

/// Where every value is live, and what that liveness is allowed to ignore.
///
/// Every field here answers one question -- can these two values share a name
/// -- and only the binding plan asks it. Grouping them keeps a dataflow pass
/// from reaching a liveness fact it has no business reading.
#[derive(Debug, Clone)]
pub struct ArtifactLiveness {
    storage_spans: StorageSpans,
    live_out: crate::liveout::FunctionLiveOut,
    values: crate::liveness::ValueLiveness,
    /// Reads the text never performs: a call's conventional read of a register
    /// the certified call does not pass.
    ignored_reads: std::collections::BTreeSet<crate::graph::UseSite>,
}

impl ArtifactLiveness {
    pub const fn storage_spans(&self) -> &StorageSpans {
        &self.storage_spans
    }

    pub const fn live_out(&self) -> &crate::liveout::FunctionLiveOut {
        &self.live_out
    }

    /// Where every value is live, the fact every coalescing decision is made from.
    pub const fn values(&self) -> &crate::liveness::ValueLiveness {
        &self.values
    }

    pub const fn ignored_reads(&self) -> &std::collections::BTreeSet<crate::graph::UseSite> {
        &self.ignored_reads
    }

    /// The same liveness, with the given definitions read where they were
    /// inlined rather than where they were written.
    ///
    /// Four of the five facts here answer this one question together, so a
    /// caller that relocates reads asks for it rather than threading them.
    pub fn with_relocations(
        &self,
        graph: &SsaGraph,
        relocations: &crate::dense::IdMap<crate::graph::InstId, crate::graph::InstId>,
    ) -> crate::liveness::ValueLiveness {
        if relocations.is_empty() {
            return self.values.clone();
        }
        crate::liveness::ValueLiveness::compute_with_relocations(
            graph,
            &self.live_out,
            relocations,
            self.values.content().clone(),
            &self.ignored_reads,
        )
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
}

impl Finish {
    /// A function a test or an internal path built, from no lift.
    fn manual() -> Self {
        Self {
            provenance: SsaArtifactProvenance::Manual,
            spellings: ArtifactSpellings::default(),
            native_spans: None,
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
    arch: ArchSpec,
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
    pub arch: Option<&'a ArchSpec>,
    pub function_interface: Option<SourceFunctionInterface>,
    pub machine_roles: SourceMachineRoles,
    /// Where the calling convention places arguments. A variadic call needs
    /// them: its prototype names only the fixed arguments, so where argument
    /// `n + 1` would go is a question only the convention answers.
    pub convention_slots: Option<SourceConventionSlots>,
    /// What a call does to the registers; a body that calls is refused without it.
    pub call_effect: Option<r2source::SourceCallEffect>,
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
    let return_storages = machine_context
        .abi_model()
        .return_registers()
        .iter()
        .map(|slot| slot.storage())
        .collect::<Vec<_>>();
    let live_out = crate::liveout::FunctionLiveOut::compute(function, graph, &return_storages);
    if !crate::demand::exits_are_named(function, &live_out) {
        r2il::refusal_evidence!(
            "demanded-bytes",
            "an exit hands registers to code outside the graph; no base is released"
        );
        return EditPlan::new();
    }
    let demand = crate::demand::Demand::of(graph, &live_out);
    function.release_undemanded_insert_bases(graph, &demand)
}

/// The def-use of one body as it was lifted, with no pass that folds a use away.
///
/// Which listed number is a step towards another is read off this, so the listing and the
/// reference index answer it from the same graph.
pub fn def_use_graph(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<SsaGraph> {
    let function = SSAFunction::from_blocks_raw(blocks, arch)?;
    let machine_context = SourceMachineContext::from_blocks(blocks, arch);
    let sealed = Lifted::new(function)
        .validate()
        .map_err(integrity_refusal)
        .ok()?
        .seal(&machine_context)
        .map_err(integrity_refusal)
        .ok()?;
    let graph = sealed.graph().clone();
    (!graph.blocks.is_empty()).then_some(graph)
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
        let sealed = prepared.seal(&machine_context).map_err(integrity_refusal)?;
        let mut artifact =
            sealed.into_artifact(machine_context, finish, control, prepare_entry_bytes)?;
        artifact.seal_body_proven_interface();
        artifact.seal_dead_frame_stores();
        Ok(artifact)
    }

    /// Read the body's own facts into the function interface, so that a
    /// caller correlated against it and the signature derived from it see one
    /// interface rather than the capture's and a promoted copy of it.
    fn seal_body_proven_interface(&mut self) {
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

    pub fn from_blocks(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_with_arch(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    pub fn raw(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_raw(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    /// Build raw SSA with an explicit, revision-bound function interface.
    pub fn raw_with_interface(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::raw_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build raw SSA with explicit, revision-bound function and callsite
    /// interfaces. A missing function interface does not weaken the per-callsite
    /// revision and carrier checks.
    pub fn raw_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
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
                None,
                call_site_interfaces,
            ),
        ))
    }

    pub fn for_decompile(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build a complete decompiler SSA artifact under cooperative control.
    ///
    /// Work is assembled in local values. A stop returns an explicit error and
    /// drops all intermediate state rather than exposing a partial artifact.
    pub fn for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
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
        arch: Option<&ArchSpec>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::for_decompile_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build decompiler-prepared SSA with explicit, revision-bound function and
    /// callsite interfaces.
    pub fn for_decompile_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
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
        arch: Option<&ArchSpec>,
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
            convention_slots,
            call_effect,
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
            convention_slots,
            call_effect,
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
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        call_effect: Option<r2source::SourceCallEffect>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            blocks,
            arch,
            function_interface,
            machine_roles,
            None,
            call_effect,
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

    pub fn for_patterns(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_patterns(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    pub fn for_symbolic(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::for_symbolic_with_interfaces(blocks, arch, None, Vec::new())
    }

    /// Build symbolic SSA with an explicit, revision-bound function interface.
    pub fn for_symbolic_with_interface(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: SourceFunctionInterface,
    ) -> Option<Self> {
        Self::for_symbolic_with_interfaces(blocks, arch, Some(function_interface), Vec::new())
    }

    /// Build symbolic SSA with exact function and callsite interfaces.
    pub fn for_symbolic_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
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
    pub fn abi(&self) -> Option<crate::abi::AbiProfile> {
        crate::abi::AbiProfile::from_machine_context(&self.machine_context)
    }

    /// Where each storage stops holding one value and starts holding another.
    pub const fn storage_spans(&self) -> &StorageSpans {
        self.liveness.storage_spans()
    }

    /// Carriers whose values are not all one storage holding one value.
    ///
    /// A carrier is state a register preserves, and a register is reused, so a
    /// carrier can reach across the point where its storage changed meaning.
    /// Anything that wants to call a carrier one variable has to ask this first.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
        )
    )]
    pub fn carriers_spanning_a_reuse(&self) -> std::collections::BTreeSet<crate::SemanticId> {
        let spans = self.storage_spans();
        let mut spanning = std::collections::BTreeSet::new();
        for loop_fact in self.facts.structured.loops.values() {
            for carrier in &loop_fact.carriers {
                let members = carrier.coalescing_values();
                let occupants = self.carrier_storage_occupants(carrier, &members);
                if !spans.all_one_span(occupants.iter().copied()) {
                    spanning.insert(carrier.id);
                }
            }
        }
        spanning
    }

    /// The members of a carrier that live in the storage the carrier is.
    ///
    /// A carrier's members include the value each update computes, and a lifter
    /// is free to compute that anywhere: Sleigh routes a flag-setting subtract
    /// through a unique-space temporary, so `subs x1, x1, 1` contributes a member
    /// in `Unique` to a carrier that is a register. That temporary is the
    /// arithmetic, not the storage, and asking whether it shares a run with the
    /// register asks whether two different places are one place, which they never
    /// are. Every counter on this target was answered "spans a reuse" on that
    /// basis, dropped from the name aliases, and rendered as the value it held on
    /// entry -- a loop whose condition never changes.
    ///
    /// Reuse is a question about one storage holding two meanings, so only the
    /// members in that storage can answer it.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
        )
    )]
    fn carrier_storage_occupants(
        &self,
        carrier: &crate::semantic::LoopCarrierFact,
        members: &std::collections::BTreeSet<crate::ValueId>,
    ) -> std::collections::BTreeSet<crate::ValueId> {
        let storage_of = |value: crate::ValueId| {
            self.graph()
                .value(value)
                .and_then(|value| value.canonical_storage)
                .filter(|storage| !storage.is_unknown())
        };
        let Some(carrier_storage) = storage_of(carrier.phi) else {
            return members.clone();
        };
        members
            .iter()
            .copied()
            .filter(|member| {
                storage_of(*member)
                    .is_some_and(|storage| carrier_storage.location() == storage.location())
            })
            .collect()
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

    /// Where every value is live, the fact every coalescing decision is made from.
    pub const fn value_liveness(&self) -> &crate::liveness::ValueLiveness {
        self.liveness.values()
    }

    /// Reads the text never performs, which hold nothing live.
    pub const fn ignored_reads(&self) -> &std::collections::BTreeSet<crate::graph::UseSite> {
        self.liveness.ignored_reads()
    }

    pub fn graph(&self) -> &SsaGraph {
        self.sealed.graph()
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

    pub fn with_assumptions(&self, assumptions: &AssumptionSet) -> Self {
        let facts = PreparedFunctionFacts::collect_with_context(
            self.function(),
            Some(self.decompile_prep_facts()),
            self.graph(),
            assumptions,
            &self.machine_context,
            "assume",
        );
        let aggregate_accesses = collect_aggregate_access_projections(
            self.graph(),
            &facts.addresses,
            &facts.structured.memory_accesses,
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
            spellings: self.spellings.clone(),
        };
        assumed.seal_dead_frame_stores();
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
            crate::StackArrayLayoutDisposition::Proven(_) => None,
            crate::StackArrayLayoutDisposition::Refused(
                crate::StackArrayLayoutRefusal::MissingConstantOffset,
            ) => Some(crate::ExtentAssumption::UnboundedIndex),
            _ if self.indexed_past_any_bound(slot) => Some(crate::ExtentAssumption::UnboundedIndex),
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

    /// An access at an index no value range bounds, whatever else refused the layout first.
    fn indexed_past_any_bound(&self, slot: &crate::StackSlotCertificate) -> bool {
        let Some(allocation) = slot.callee_allocation.as_ref() else {
            return false;
        };
        let certificates = self.certificates();
        allocation.accesses.iter().any(|id| {
            certificates.memory_accesses.get(id).is_some_and(|access| {
                self.objects()
                    .index_for_address(access.address)
                    .is_some_and(|index| self.values().upper_bound(index).is_none())
            })
        })
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

    /// Whether every access to this object is one a decided stack-protector check inserted: the canary.
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
    fn entry_stack_offset(&self, object: crate::ObjectId) -> Option<i64> {
        match self.objects().object(object).map(|found| &found.kind) {
            Some(crate::ObjectKind::StackSlot {
                base: crate::StackAddressBase::StackPointer,
                offset,
                ..
            }) => Some(*offset),
            _ => None,
        }
    }

    /// Whether this stack object is the caller's storage rather than this body's.
    ///
    /// The frame grows down from the entry stack pointer, so an object at or above
    /// it is the caller's storage: the return address, a stack-passed argument, or
    /// -- at a process entry -- what the loader left there. Nothing in this body
    /// assigns it, and requiring a definition asks for one that cannot exist.
    pub fn caller_stack_object(&self, object: crate::ObjectId) -> bool {
        self.entry_stack_offset(object)
            .is_some_and(Self::caller_frame_offset)
    }

    /// Whether an offset from the entry stack pointer lies in the caller's storage.
    pub const fn caller_frame_offset(offset: i64) -> bool {
        offset >= 0
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
            .get(&(inst, is_write))?
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

    pub fn call_result_certificate_for_inst(
        &self,
        inst: crate::graph::InstId,
    ) -> Option<&CallResultCertificate> {
        let value = self.facts.certificates.call_results_by_inst.get(inst)?;
        self.facts.certificates.call_results.get(*value)
    }

    pub fn call_result_certificates_for_callsite(
        &self,
        call_site: CallSiteId,
    ) -> Vec<&CallResultCertificate> {
        self.facts
            .certificates
            .call_results_by_callsite
            .get(&call_site)
            .into_iter()
            .flatten()
            .filter_map(|value| self.facts.certificates.call_results.get(*value))
            .collect()
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
        let mut entries_by_family = HashMap::<usize, usize>::new();
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

    /// The instruction a test names by its block and its place among the
    /// block's operations.
    #[cfg(test)]
    pub(crate) fn inst_at(&self, block_addr: u64, index: usize) -> Option<crate::graph::InstId> {
        let op = self.function().get_block(block_addr)?.op_id(index)?;
        self.graph().inst_for_op(op)
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
    call: &r2source::AdvisoryCallSite,
) -> Option<SourceCallSiteIdentity> {
    let mut matches = blocks.iter().flat_map(|block| {
        block
            .ops
            .iter()
            .enumerate()
            .filter_map(move |(op_index, op)| {
                let instruction = || {
                    block
                        .op_metadata(op_index)
                        .and_then(|metadata| metadata.instruction_addr)
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
            })
    });
    let identity = matches.next()?;
    matches.next().is_none().then_some(identity)
}

/// What the code after the call at `identity` reads of the two result registers `callee` leaves
/// one of, where it writes both (doc/adr-resolved-bodies.md, "Caller reads").
fn reads_after(
    blocks: &[R2ILBlock],
    identity: SourceCallSiteIdentity,
    callee: &SourceFunctionInterface,
) -> Option<r2source::SourceResultReads> {
    let (integer, float) = callee.result_carriers()?;
    blocks.iter().find_map(|block| {
        let index = block.ops.iter().enumerate().position(|(index, op)| {
            matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. })
                && block
                    .op_metadata(index)
                    .and_then(|metadata| metadata.instruction_addr)
                    == Some(identity.instruction())
        })?;
        Some(crate::caller_reads::reads_after_call(
            block,
            index,
            Some(integer),
            Some(float),
        ))
    })
}

#[derive(Clone)]
struct CorrelatedCallSites {
    tail_calls: Vec<SourceCallSiteIdentity>,
    interfaces: Vec<SourceCallSiteInterface>,
    /// Who each correlated site calls, where the source knew: the binary's own function or an import.
    callee_linkages: BTreeMap<SourceCallSiteIdentity, r2source::AdvisoryCalleeLinkage>,
    /// The name the source gave each correlated site's callee.
    callee_names: BTreeMap<SourceCallSiteIdentity, String>,
}

fn correlate_call_site_interfaces(
    source: &OwnedFunctionSnapshot,
    blocks: &[R2ILBlock],
    callee_interfaces: &BTreeMap<u64, SourceFunctionInterface>,
) -> CorrelatedCallSites {
    let mut tail_calls = Vec::new();
    let mut interfaces = Vec::new();
    let mut callee_linkages = BTreeMap::new();
    let mut callee_names = BTreeMap::new();
    for call in source.advisory_calls() {
        let Some(identity) = unique_call_site_identity(blocks, call) else {
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
        if let Some(name) = call.target_name() {
            callee_names.insert(identity, name.to_string());
        }
        // A prototype the source recovered supplies the physical call
        // contract. When this capture also carries the callee body, retain its
        // recovered logical interface only after those physical carriers
        // agree. radare2 reports no prototype for most local functions; in
        // that case the callee-derived interface supplies both layers.
        let recovered = callee_interfaces.get(&call.target_address());
        r2il::refusal_evidence!(
            "call-site-correlation",
            "advisory {:?} at {:#x} target {:#x} prototype_arguments={:?} callee_interface={}",
            call.transfer(),
            call.instruction_address(),
            call.target_address(),
            call.prototype().map(|prototype| prototype.arguments.len()),
            recovered.is_some()
        );
        let Some(prototype) = call.prototype() else {
            let Some(callee) = recovered else {
                continue;
            };
            if let Some(mut interface) =
                crate::recover_interface::mint_recovered_call_site_interface(
                    callee,
                    identity,
                    source.source_revision_identity(),
                    reads_after(blocks, identity, callee),
                )
            {
                // The gettext family is named, not prototyped, so the rule
                // that its result is a translation of its own argument binds
                // here as it does on the prototype path below.
                if let Some(target_name) = call.target_name()
                    && let Some(rule) =
                        r2source::SourceFormatForwardingRule::for_target_name(target_name)
                    && let Ok(bound) = interface.clone().with_format_forwarding(rule)
                {
                    interface = bound;
                }
                interfaces.push(interface);
            }
            continue;
        };
        let Ok(mut interface) = SourceCallSiteInterface::new(
            source.source_revision_identity().to_vec(),
            identity,
            true,
            prototype.calling_convention.clone(),
            prototype.arguments.iter().copied(),
            prototype.variadic,
            prototype.noreturn,
            prototype.result,
        ) else {
            continue;
        };
        // A callee body captured with the caller owns the logical fixed-call
        // signature, but only after its physical carriers agree exactly with
        // this source-owned callsite contract.
        if let Some(callee) = recovered
            && let Ok(with_callee) = interface
                .clone()
                .with_exact_callee_interface(callee.clone())
        {
            interface = with_callee;
        }
        // The exact target identity correlates this call with the prototype
        // radare2 recovered for that target. Parameter names are otherwise
        // presentation-only; promote precisely one `format` name into the
        // checked callsite contract, where it serves as provenance for literal
        // format counting at a variadic call and, at a `va_list` call, says
        // which argument a caller's body forwards as its own format.
        if let Some(target_name) = call.target_name() {
            let mut signatures =
                source
                    .presentation()
                    .callee_signatures()
                    .iter()
                    .filter(|(name, signature)| {
                        name.as_ref() == target_name
                            && signature.is_variadic() == prototype.variadic
                            && signature.named_parameters().len() == prototype.arguments.len()
                    });
            if let (Some((_, signature)), None) = (signatures.next(), signatures.next()) {
                let mut formats = signature
                    .named_parameters()
                    .iter()
                    .enumerate()
                    .filter(|(_, parameter)| parameter_names_a_format_string(parameter));
                if let (Some((index, _)), None) = (formats.next(), formats.next())
                    && let Ok(index) = u32::try_from(index)
                    && let Ok(bound) = interface.clone().with_radare2_format_parameter(index)
                {
                    interface = bound;
                }
            }
        }
        // A call to the gettext family hands back a translation of one of its
        // own arguments, so a caller whose format came from here counts from
        // the msgid it passed. radare2 has no prototype for the family and
        // could not express this if it did -- the format is the return value,
        // not a parameter -- so the name is matched where names are known and
        // the fact travels on the interface.
        if let Some(target_name) = call.target_name()
            && let Some(rule) = r2source::SourceFormatForwardingRule::for_target_name(target_name)
            && let Ok(bound) = interface.clone().with_format_forwarding(rule)
        {
            interface = bound;
        }
        // radare2 has a prototype for the printf family and almost never for a
        // wrapper defined in this binary, so the name above finds nothing for
        // the wrapper. Its own body proved which parameter it forwards as a
        // format, and that travels on the callee interface; the builder leaves
        // an already-bound radare2 rule alone.
        if let Some(callee) = recovered
            && let Some(index) = callee.body_proven_format_parameter()
            && let Ok(bound) = interface.clone().with_body_proven_format_parameter(index)
        {
            interface = bound;
        }
        interfaces.push(interface);
    }
    CorrelatedCallSites {
        tail_calls,
        interfaces,
        callee_linkages,
        callee_names,
    }
}

/// Whether a prototype's parameter is the format string of a variadic call.
///
/// The name is the evidence and the type is the guard. radare2 spells the role
/// `format` for the printf family and `fmt` for the err/warn family, and both
/// are the same role; `execl(const char *path, const char *arg, ...)` is why
/// the name is still required, because its last named parameter is a `char *`
/// that no conversion specifier is counted from.
fn parameter_names_a_format_string(parameter: &r2source::SourceSignatureParameter) -> bool {
    let named = parameter.name().is_some_and(|name| {
        matches!(
            name.trim_start_matches('_'),
            "format" | "fmt" | "format_string" | "fmtstr"
        )
    });
    named
        && parameter
            .type_spelling()
            .is_some_and(|spelling| spelling.contains("char") && spelling.contains('*'))
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
        .find(|(_, parameter)| parameter.value == value)
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
            return agreeing(&definition.inputs, shared, seen);
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
    /// lift. No detached interface, architecture, layout, or raw block input is
    /// accepted at this boundary.
    pub fn prepare_with_control<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::prepare_with_callee_interfaces(
            lifted,
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
        control: &C,
        evidence: &CalleeEvidence,
        premises: &BTreeSet<r2source::Premise>,
    ) -> Result<Self, SsaPrepareError> {
        let CalleeEvidence {
            interfaces: callee_interfaces,
            preserved: callee_preserved_carriers,
            reach: callee_argument_reach,
            library,
        } = evidence;
        let callee_statements = crate::machine_context::CalleeStatement::of(callee_interfaces);
        let source = lifted.source().clone();
        let genuine = lifted.lifted();
        let arch = genuine.arch_spec().clone();
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
        let correlated_call_sites =
            correlate_call_site_interfaces(&source, &blocks, callee_interfaces);
        // What each callee said about its own boundary, read once for every
        // pass that asks what a call to it does to the registers.
        let callees = CalleeBoundaries::from_interfaces(
            Some(&arch),
            callee_preserved_carriers,
            callee_interfaces,
        );
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
        let mut result_owners = BTreeSet::new();
        let mut result_ambiguous = false;
        let function_interface = match source.function_interface().cloned() {
            Some(interface) => Some(interface),
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
                        Some(source.convention_slots().clone()),
                        source.call_effect().cloned(),
                        correlated_call_sites.interfaces.clone(),
                        correlated_call_sites.tail_calls.clone(),
                    );
                // The recovery proves variadic counts from the same literals
                // the final pass reads; without them every format was unproven.
                provisional_machine_context
                    .bind_source_string_literals(source.image().string_literals());
                provisional_machine_context.bind_read_only(source.image().read_only());
                provisional_machine_context.set_callee_statements(&callee_statements);
                // The preliminary build may be the one sealed, so it decides under the same premises.
                provisional_machine_context.set_accepted_premises(premises.clone());
                let Ok(preliminary) =
                    SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                        &blocks,
                        Some(&arch),
                        InterfaceQuestions::before_recovery(source.convention_slots()),
                        &provisional_machine_context,
                        &callees,
                        Some(&declared_successors),
                        control,
                    )
                else {
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
                let Ok(preliminary_prep) = preliminary.provisional_prep_facts(control) else {
                    break 'recovered None;
                };
                let recovered = crate::recover_interface::recover_interface_with_context(
                    preliminary,
                    &preliminary_prep,
                    source.convention_slots(),
                    &provisional_machine_context,
                    crate::recover_interface::Stated::of(source.function()),
                );
                let Some(recovered) = recovered else {
                    break 'recovered None;
                };
                result_owners.clone_from(recovered.result_owners());
                result_ambiguous = recovered.result_ambiguous();
                let minted = crate::recover_interface::mint_recovered_interface(
                    &recovered,
                    source.machine_roles(),
                    source.source_revision_identity(),
                    source.convention_slots().calling_convention(),
                );
                if minted.is_none() {
                    r2il::refusal_evidence!(
                        "interface-recovery",
                        "the recovered ABI could not be minted into an interface: \
                         parameters={} result={:?} convention={:?}",
                        recovered.parameters().len(),
                        recovered.result(),
                        source.convention_slots().calling_convention()
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
                let Some(identity) = unique_call_site_identity(&blocks, call) else {
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
                        identity,
                        source.source_revision_identity(),
                        reads_after(&blocks, identity, own),
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
                Some(source.convention_slots().clone()),
                source.call_effect().cloned(),
                call_interfaces,
                correlated_call_sites.tail_calls,
                &declared_successors.terminal_blocks(),
            );
        machine_context.set_callee_linkages(correlated_call_sites.callee_linkages);
        machine_context.set_callee_names(correlated_call_sites.callee_names);
        machine_context.set_callee_argument_reach(callee_argument_reach.clone());
        machine_context.set_callee_library(library.clone());
        machine_context.set_callee_preserved(callees.preserved().clone());
        machine_context.set_result_owners(result_owners);
        machine_context.set_result_ambiguous(result_ambiguous);
        machine_context.set_callee_statements(&callee_statements);
        machine_context.set_frame_saves(source.image().frame_saves());
        machine_context.set_accepted_premises(premises.clone());
        // What each entry of a captured code pointer table names, recorded
        // before the facts are collected: a load of such a slot is proven
        // from this, and the collection is what proves it.
        let mut code_pointer_entries = BTreeMap::new();
        for table in source.image().code_pointer_tables() {
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
        r2il::refusal_evidence!(
            "snapshot-literals",
            "the decoded image delivers {} string literals",
            source.image().string_literals().len()
        );
        machine_context.bind_source_string_literals(source.image().string_literals());
        machine_context.bind_read_only(source.image().read_only());
        let mut function = match built {
            Some(built) => built,
            None => {
                let questions = match stated_interface {
                    true => InterfaceQuestions::new(&machine_context),
                    false => InterfaceQuestions::before_recovery(source.convention_slots()),
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
        // What the source calls this function. A name radare2 derived from the
        // entry address restates the address and is left absent, so consumers
        // that would only spell it back out are not misled into thinking the
        // function was named.
        let presented = source.presentation().display_name();
        if !r2source::display_names::is_generated_function_name(presented) {
            function = function.named(presented.to_string());
        }
        if function.entry != source.image().entry_address() {
            return Err(malformed_ssa_input());
        }
        control.poll()?;
        let artifact = SsaArtifact::seal_finished(
            function,
            machine_context,
            Finish {
                provenance: SsaArtifactProvenance::TrustedSource(source),
                spellings: ArtifactSpellings {
                    display_names,
                    user_operations: Arc::from(arch.user_ops.clone()),
                },
                native_spans: Some(native_spans),
            },
            control,
        )?;
        Ok(Self {
            artifact: Arc::new(artifact),
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
    pub const fn arch_spec(&self) -> &ArchSpec {
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
    /// The lifted memory operations promotion took out of memory.
    ///
    /// A promoted slot access is a copy of a variable in the prepared
    /// operations, so it is no longer one of the function's memory
    /// operations, and every layer that counts those has to agree.
    promoted_slots: crate::dense::IdSet<crate::arena::OpId>,
    /// The operations a stack-protector check inserted, decided under `Premise::UbFreeSource`.
    compiler_inserted: crate::dense::IdSet<crate::arena::OpId>,
    /// The failure blocks a decided stack-protector check removed, whose instructions stay owed.
    compiler_inserted_blocks: BTreeSet<u64>,
    /// The premises a rewrite of this function relied on, whatever later became of what it rewrote.
    premises: BTreeSet<r2source::Premise>,
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

/// A call's conventional reads of registers the certified call does not
/// pass. The graph states a read of every register the convention lets a
/// callee read, so that liveness before the facts exist errs safe; once the
/// call boundary says which values are arguments, the rest are not reads.
///
/// A read is passed when it has the bits of a passed argument, not only its
/// id: the boundary names the value that reached the argument register, and
/// copy forwarding may have left the call reading the value that copy
/// carried. Both are one class (`view::class_values`), and the text reads it.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a use site is an (instruction, operand) pair, not a dense id"
    )
)]
pub(crate) fn uncertified_call_reads(
    graph: &SsaGraph,
    views: Option<&crate::view::ValueViews<ValueId>>,
    boundaries: &crate::semantic::SourceBoundaryFacts,
) -> std::collections::BTreeSet<crate::graph::UseSite> {
    let class = crate::view::class_values(graph, views);
    let class_of = |value: crate::graph::ValueId| class.get(value.0 as usize).copied();
    let mut passed = std::collections::BTreeSet::new();
    for boundary in boundaries.calls.values() {
        for argument in &boundary.arguments {
            if let crate::semantic::SourceCallArgumentValue::Value(value) = argument.value {
                passed.insert(class_of(value).unwrap_or(value));
            }
        }
    }
    graph
        .insts
        .iter()
        .filter(|inst| {
            matches!(
                inst.payload,
                crate::graph::InstPayload::Op(SSAOp::CallUse { .. })
            )
        })
        .flat_map(|inst| {
            inst.inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| !passed.contains(&class_of(**input).unwrap_or(**input)))
                .map(move |(input_idx, _)| crate::graph::UseSite {
                    inst: inst.id,
                    input_idx,
                })
        })
        .collect()
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
        self.blocks.arena().instruction(id)
    }

    /// Every operation and phi this function ever held, by id.
    /// Which bytes each operation and phi wrote as data, as lifted.
    pub fn written(&self) -> &crate::lanes::Written {
        &self.written
    }

    /// The record, or for a function no preparation recorded -- one built
    /// raw, which nothing has optimised -- the record taken from it as it
    /// stands, which is as lifted.
    pub fn written_or_captured(&self) -> std::borrow::Cow<'_, crate::lanes::Written> {
        match self.written.is_empty() {
            false => std::borrow::Cow::Borrowed(&self.written),
            true => std::borrow::Cow::Owned(crate::lanes::Written::capture(self)),
        }
    }

    /// Record what each operation writes, before anything rewrites one.
    pub(crate) fn capture_written(&mut self) {
        self.written = crate::lanes::Written::capture(self);
    }

    pub fn arena(&self) -> &OpArena {
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
            promoted_slots: self.promoted_slots.clone(),
            compiler_inserted: self.compiler_inserted.clone(),
            compiler_inserted_blocks: self.compiler_inserted_blocks.clone(),
            premises: self.premises.clone(),
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
    results: BTreeMap<u64, CallBoundaryDef>,
    /// Callees whose body proves the result carrier holds the return address.
    return_addresses: BTreeMap<u64, CanonicalStorageId>,
}

impl CalleeBoundaries {
    /// Read both facts off the interfaces the callees' own bodies proved.
    pub(crate) fn from_interfaces(
        arch: Option<&ArchSpec>,
        preserved: &CalleePreservedCarriers,
        interfaces: &BTreeMap<u64, SourceFunctionInterface>,
    ) -> Self {
        let names = arch.map(cached_register_name_map);
        let mut preserved = preserved.clone();
        let mut results = BTreeMap::new();
        let mut return_addresses = BTreeMap::new();
        for (address, interface) in interfaces {
            let crate::SourceFunctionReturn::Register { storage } = interface.return_kind() else {
                continue;
            };
            // The same boundary cannot both hand a register back untouched and
            // name it as what it returns.
            let overlaps = |carrier: &CanonicalStorageId| {
                crate::semantic::register_storages_overlap(*carrier, storage)
            };
            if let Some(carriers) = preserved.get_mut(address) {
                carriers.retain(|carrier| !overlaps(carrier));
            }
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
            if interface.body_proven_return_address() {
                return_addresses.insert(*address, storage);
            }
        }
        Self {
            preserved,
            results,
            return_addresses,
        }
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
/// A body that calls under no stated call effect is refused rather than read as if a register survived.
fn decompile_call_boundary_config(
    blocks: &[R2ILBlock],
    arch: Option<&ArchSpec>,
    machine_context: &SourceMachineContext,
    stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
    callees: CalleeBoundaries,
) -> Result<Option<CallBoundaryConfig>, SsaPrepareError> {
    let calls = blocks
        .iter()
        .flat_map(|block| &block.ops)
        .any(|op| matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }));
    if calls && machine_context.call_effect().is_none() {
        r2il::refusal_evidence!(
            "call-effect",
            "{:#x}: the body calls and its convention states nothing a call leaves standing",
            blocks.first().map_or(0, |block| block.addr)
        );
        return Err(SsaPrepareError::NoCallEffect);
    }
    if arch.is_none() {
        return Ok(None);
    }
    // A body that never calls has no call to clobber anything.
    // What a call keeps is what the convention preserves and what the
    // platform reserves to the system alike: neither is a definition the call
    // makes, so both are gaps in any wider root it does write.
    let (clobbered, preserved) = match machine_context.call_effect().filter(|_| calls) {
        Some(effect) => (
            machine_context.call_clobbered_carriers().to_vec(),
            effect
                .preserved()
                .iter()
                .chain(effect.system_reserved())
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let reads = machine_context
        .call_effect()
        .map(crate::SourceCallEffect::reads);
    let config = CallBoundaryConfig {
        clobbered,
        preserved,
        stack_pointer_restored_by_callee,
        preserved_by_target: callees.preserved,
        result_by_target: callees.results,
        argument_regs: reads.map(|reads| reads.call().to_vec()).unwrap_or_default(),
        return_regs: reads.map(|reads| reads.ret().to_vec()).unwrap_or_default(),
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

    /// Whether this user operation enters the supervisor, whose kernel-written result no contract names.
    pub fn enters_supervisor<V>(&self, op: &SSAOp<V>) -> bool {
        matches!(op, SSAOp::CallOther { userop, .. } if self.supervisor_calls.contains(userop))
    }

    /// The memory operations slot promotion rewrote into copies.
    pub fn promoted_slots(&self) -> &crate::dense::IdSet<crate::arena::OpId> {
        &self.promoted_slots
    }

    pub(crate) fn record_promoted_slots(&mut self, ops: crate::dense::IdSet<crate::arena::OpId>) {
        self.promoted_slots = ops;
    }

    /// The operations a decided stack-protector check inserted (`crate::stack_protector`).
    pub fn compiler_inserted(&self) -> &crate::dense::IdSet<crate::arena::OpId> {
        &self.compiler_inserted
    }

    pub(crate) fn record_compiler_inserted(
        &mut self,
        ops: crate::dense::IdSet<crate::arena::OpId>,
        blocks: BTreeSet<u64>,
    ) {
        self.compiler_inserted.extend(ops.iter());
        self.compiler_inserted_blocks.extend(blocks);
    }

    /// Record a premise a rewrite relied on.
    pub(crate) fn record_premise(&mut self, premise: r2source::Premise) {
        self.premises.insert(premise);
    }

    /// The premises a rewrite of this function relied on: a decided check changed its control flow.
    pub fn premises(&self) -> &BTreeSet<r2source::Premise> {
        &self.premises
    }

    /// The failure blocks a decided stack-protector check removed.
    pub fn compiler_inserted_blocks(&self) -> &BTreeSet<u64> {
        &self.compiler_inserted_blocks
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
        self.values.var(id)
    }

    /// The table of every operand id.
    pub const fn values(&self) -> &crate::value_table::ValueTable {
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
        self.values.storage_of_var(var)
    }

    /// The lifted storage of a variable the function holds by id.
    pub(crate) fn storage_of(&self, id: VarId) -> Option<CanonicalStorageId> {
        self.values.storage(id)
    }

    /// Get the number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
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

        for block in self.blocks() {
            if let Some(crate::cfg::BlockTerminator::Switch { cases, default }) = self
                .cfg
                .get_block(block.addr)
                .map(|block| &block.terminator)
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
    name_to_member: HashMap<String, RegisterFamilyMember>,
    /// Whether a 32-bit write to a general register clears the rest of it.
    /// Which family covers a register-space range, for storage the arch does not name.
    family_ranges: Vec<(u64, u64, usize)>,
    family_slots: HashMap<usize, Vec<RegisterFamilySlot>>,
    /// The narrowest declared slot of each family that contains every range
    /// one function touches of it; see [`Self::with_program_roots`].
    program_roots: HashMap<usize, RegisterFamilySlot>,
    /// Whether a register's lowest address holds its most significant byte.
    big_endian: bool,
}

fn register_family_info_cache() -> &'static RwLock<HashMap<ArchCacheTag, Arc<RegisterFamilyInfo>>> {
    static CACHE: OnceLock<RwLock<HashMap<ArchCacheTag, Arc<RegisterFamilyInfo>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) fn cached_register_family_info(arch: &ArchSpec) -> Arc<RegisterFamilyInfo> {
    let cache_tag = ArchCacheTag::from_arch(arch);

    if let Some(cached) = register_family_info_cache()
        .read()
        .expect("register family cache read lock poisoned")
        .get(&cache_tag)
        .cloned()
    {
        return cached;
    }

    let info = Arc::new(RegisterFamilyInfo::from_arch(arch));
    let mut cache = register_family_info_cache()
        .write()
        .expect("register family cache write lock poisoned");
    if let Some(cached) = cache.get(&cache_tag) {
        return Arc::clone(cached);
    }
    if cache.len() >= ARCH_DERIVED_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(cache_tag, info.clone());
    info
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
        let mut extents = HashMap::<usize, (u64, u64)>::new();
        for (offset, size) in used {
            let Some(member) = self.member_at_offset(offset, size) else {
                continue;
            };
            let end = offset.saturating_add(u64::from(size));
            let extent = extents.entry(member.family_id).or_insert((offset, end));
            extent.0 = extent.0.min(offset);
            extent.1 = extent.1.max(end);
        }
        let mut program_roots = HashMap::new();
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

        let mut root_to_family = HashMap::new();
        let mut next_family_id = 0usize;
        let mut name_to_member = HashMap::new();
        let mut family_width_sets: HashMap<(usize, u64), HashSet<u32>> = HashMap::new();

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

        let family_widths_by_offset: HashMap<(usize, u64), Vec<u32>> = family_width_sets
            .into_iter()
            .map(|(family_and_offset, mut widths)| {
                let mut widths: Vec<u32> = widths.drain().collect();
                widths.sort_unstable();
                (family_and_offset, widths)
            })
            .collect();
        let mut family_slots: HashMap<usize, Vec<RegisterFamilySlot>> = HashMap::new();
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
            program_roots: HashMap::new(),
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
