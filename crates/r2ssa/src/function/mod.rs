//! Function-level SSA representation.
//!
//! This module provides the `SSAFunction` type which combines all SSA
//! components for a complete function: CFG, dominator tree, phi nodes,
//! and renamed operations.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, OnceLock, RwLock};

use r2il::{ArchSpec, R2ILBlock, R2ILOp};
use r2sleigh_lift::{GenuineLiftedFunction, GenuineLiftedFunctionAuthority, TrustedLiftedFunction};
use r2source::{OwnedFunctionSnapshot, SourceCallPreservedCarriers};
use serde::{Deserialize, Serialize};

use crate::aggregate_access::{
    AggregateAccessProjectionFacts, collect_aggregate_access_projections,
};
pub use crate::block::SSABlock;
use crate::block::SSABlock as LocalSSABlock;
use crate::cfg::{CFG, CFGEdge};
use crate::control::{
    SsaExecutionStopReason, SsaPrepareError, SsaWorkControl, UncheckedSsaWorkControl,
};
use crate::defuse::{BackwardSlice, SliceOpRef, backward_slice_from_op, backward_slice_from_var};
use crate::domtree::DomTree;
use crate::graph::SsaGraph;
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
use crate::var::{SSAVar, SSAVarNameKind};
use crate::{AssumptionSet, CanonicalStorageId, CanonicalStorageSpace};

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecompilePrepFacts {
    /// The canonical root of each value, as an unordered index.
    ///
    /// Nothing iterates it -- the fingerprint sorts what it takes -- and the
    /// root propagation asks it three and a half million times for one
    /// five-hundred-block function, so every question was a walk down an
    /// ordered tree comparing variable names. Hashing the variable once and
    /// probing is the same answer for a fraction of the comparisons.
    pub canonical_value_roots: HashMap<SSAVar, SSAVar>,
    pub stack_address_roots: BTreeMap<SSAVar, StackAddressRoot>,
    /// Exact address roots normalized to the entry stack pointer by machine
    /// dataflow. Unlike `stack_address_roots`, these roots are never rebased
    /// to a source-declared frame-pointer coordinate system.
    pub entry_stack_address_roots: BTreeMap<SSAVar, StackAddressRoot>,
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
    pub indexed_stack_address_roots: BTreeMap<SSAVar, StackAddressRoot>,
    /// Entry SSA values bound to canonical ABI parameter slots.
    pub formal_parameters: BTreeMap<SSAVar, usize>,
    /// Full-width entry ABI values that may serve as parameter address bases.
    pub formal_parameter_bases: BTreeMap<SSAVar, usize>,
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
#[derive(Clone, Copy)]
struct InterfaceQuestions<'a> {
    interface: Option<&'a SourceFunctionInterface>,
    return_boundary: bool,
    argument_placement: bool,
    frame_geometry: bool,
    machine_carriers: bool,
}

impl<'a> InterfaceQuestions<'a> {
    fn new(machine_context: &'a SourceMachineContext) -> Self {
        let abi = machine_context.abi_model();
        Self {
            interface: machine_context.function_interface(),
            return_boundary: abi.return_boundary_is_coherent(),
            argument_placement: abi.argument_placement_is_coherent(),
            frame_geometry: abi.frame_geometry_is_coherent(),
            machine_carriers: abi.machine_carriers_are_coherent(),
        }
    }

    /// No interface at all: no question about it can be answered.
    fn none() -> Self {
        Self {
            interface: None,
            return_boundary: false,
            argument_placement: false,
            frame_geometry: false,
            machine_carriers: false,
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

    fn for_machine_carriers(self) -> Option<&'a SourceFunctionInterface> {
        self.interface.filter(|_| self.machine_carriers)
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
    /// Pairs of values the memory facts prove hold one content -- reads of one
    /// object with no write between -- for anyone who recomputes the liveness
    /// with reads relocated.
    same_content_pairs: Vec<(crate::graph::ValueId, crate::graph::ValueId)>,
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

    pub fn same_content_pairs(&self) -> &[(crate::graph::ValueId, crate::graph::ValueId)] {
        &self.same_content_pairs
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
        relocations: &std::collections::BTreeMap<crate::graph::InstId, crate::graph::InstId>,
    ) -> crate::liveness::ValueLiveness {
        if relocations.is_empty() {
            return self.values.clone();
        }
        crate::liveness::ValueLiveness::compute_with_relocations(
            graph,
            &self.live_out,
            relocations,
            &self.same_content_pairs,
            &self.ignored_reads,
        )
    }
}

/// What the source called things, which only the renderer reads.
///
/// Neither field is a dataflow, ABI or typing fact. They are retained because
/// the lift and the snapshot are the only things that ever saw them, and both
/// are gone by the time anything renders.
#[derive(Debug, Clone)]
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

/// Canonical SSA artifact consumed by downstream analysis layers.
#[derive(Debug)]
pub struct SsaArtifact {
    authority: SsaArtifactAuthority,
    provenance: SsaArtifactProvenance,
    function: SSAFunction,
    graph: SsaGraph,
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
    /// The kind is the whole fact: a genuine lift alone certifies nothing,
    /// so the authority it was built from has no reader here.
    GenuineLiftOnly,
    TrustedSource(OwnedFunctionSnapshot),
}

/// Opaque certifiable SSA prepared only from a source-retaining trusted lift.
/// Generic/manual [`SsaArtifact`] constructors cannot produce this wrapper.
#[derive(Debug, Clone)]
pub struct TrustedSsaArtifact {
    artifact: Arc<SsaArtifact>,
    lift_authority: GenuineLiftedFunctionAuthority,
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

impl SsaArtifact {
    #[cfg(test)]
    fn new(function: SSAFunction) -> Self {
        Self::new_with_context(function, SourceMachineContext::from_blocks(&[], None))
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
        mut function: SSAFunction,
        mut machine_context: SourceMachineContext,
        provenance: SsaArtifactProvenance,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        let prepare_entry_bytes = r2il::allocation::live_bytes();
        // The validator answers with a typed integrity error naming the block
        // and the edge it disagreed about; discarding it left the reader with
        // "malformed SSA source input" and nothing to look at.
        validate_ssa_function(&function).map_err(|error| {
            r2il::refusal_evidence!("ssa-integrity", "{error:?}");
            malformed_ssa_input()
        })?;
        function.apply_convention_cleared_direction_flag(&machine_context);
        function.mint_entry_lane_projections(&machine_context);
        // Before the graph, so every fact built from it counts readers of a
        // copied value where they are, not where the copy was. It rewrites
        // reads to variables the validated function already defines, so the
        // validation above still holds; the minted lanes could not pass it.
        function.forward_copies();
        machine_context.remap_memory_sites_to_prepared(&function);
        let mut graph = SsaGraph::from_function_with_storage(&function);
        crate::semantic::ensure_source_formal_parameter_values(&mut graph, &machine_context);
        let formal_parameters =
            crate::semantic::collect_source_formal_parameter_facts(&graph, &machine_context);
        function.install_exact_formal_parameters(&graph, &formal_parameters);
        let return_storages = machine_context
            .abi_model()
            .return_registers()
            .iter()
            .map(|slot| slot.storage())
            .collect::<Vec<_>>();
        let live_out =
            crate::liveout::FunctionLiveOut::compute(&function, &graph, &return_storages);
        let mut liveness = crate::liveness::ValueLiveness::compute(&graph, &live_out);
        let storage_spans = StorageSpans::compute(&graph, &liveness);
        let graph_built_bytes = r2il::allocation::live_bytes();
        let facts = PreparedFunctionFacts::collect_with_context_and_control(
            crate::semantic::CollectionOver {
                function: &function,
                graph: &graph,
                storage_spans: &storage_spans,
                assumptions: &AssumptionSet::default(),
                machine_context: Some(&machine_context),
                site: "prepare",
            },
            control,
        )?;
        // What one prepared function holds is the space every later stage has
        // to work above, so it is reported beside the phases that built it.
        r2il::refusal_evidence!(
            "prepare-held",
            "{:#x}/{} holds {} bytes after preparation: function+graph {} facts {}",
            function.entry,
            function.num_blocks(),
            r2il::allocation::live_bytes().saturating_sub(prepare_entry_bytes),
            graph_built_bytes.saturating_sub(prepare_entry_bytes),
            r2il::allocation::live_bytes().saturating_sub(graph_built_bytes)
        );
        // Two reads of one object with no write to it between are one
        // content, which the graph cannot see and the memory facts can. The
        // spans above were judged without this and are at worst finer.
        let same_content_pairs = same_content_reads(&facts.structured);
        // A call's conventional read of a register the certified call does
        // not pass is not a read the text performs, and held values live
        // across every call that the machine merely might have read. The
        // spans above were judged with those reads and are at worst finer.
        let ignored_reads = uncertified_call_reads(&graph, &facts.boundaries);
        liveness = crate::liveness::ValueLiveness::compute_with_relocations(
            &graph,
            &live_out,
            &std::collections::BTreeMap::new(),
            &same_content_pairs,
            &ignored_reads,
        );
        function.install_formal_parameter_identity(&graph, &facts.addresses);
        let unobserved_merges = crate::deadphi::DeadPhis::find(&graph, &live_out, &facts);
        let aggregate_accesses = collect_aggregate_access_projections(
            &graph,
            &facts.addresses,
            &facts.structured.memory_accesses,
            &machine_context,
        );
        control.poll()?;
        let mut artifact = Self {
            authority: SsaArtifactAuthority::new(),
            provenance,
            function,
            graph,
            liveness: ArtifactLiveness {
                storage_spans,
                live_out,
                values: liveness,
                same_content_pairs,
                ignored_reads,
            },
            unobserved_merges,
            facts,
            machine_context,
            aggregate_accesses,
            spellings: ArtifactSpellings {
                display_names: r2source::DisplayNames::default(),
                user_operations: Arc::from([] as [String; 0]),
            },
        };
        artifact.seal_body_proven_interface();
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
            SsaArtifactProvenance::GenuineLiftOnly => SsaArtifactProvenanceKind::GenuineLiftOnly,
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
                call_site_interfaces,
            ),
        ))
    }

    pub fn for_decompile(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_decompile(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
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
        let function = SSAFunction::from_blocks_for_decompile_with_control(blocks, arch, control)?;
        control.poll()?;
        let machine_context = SourceMachineContext::from_blocks(blocks, arch);
        Self::new_with_context_and_control(function, machine_context, control)
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
            call_site_interfaces,
            tail_call_identities,
            callee_preserved_carriers,
            callee_interfaces,
        } = inputs;
        let machine_context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            blocks,
            arch,
            function_interface,
            machine_roles,
            convention_slots,
            call_site_interfaces,
            tail_call_identities,
        );
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                blocks,
                arch,
                InterfaceQuestions::new(&machine_context),
                machine_context.machine_roles().call_preserved_carriers(),
                machine_context.stack_pointer_carrier(),
                &CalleeBoundaries::from_interfaces(
                    arch,
                    &callee_preserved_carriers,
                    &callee_interfaces,
                ),
                None,
                &UncheckedSsaWorkControl,
            )
            .ok()?,
            machine_context,
        ))
    }

    /// Build controlled decompiler SSA with explicit source interfaces and
    /// independently source-owned machine roles.
    pub fn for_decompile_with_interfaces_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            blocks,
            arch,
            function_interface,
            machine_roles,
            None,
            call_site_interfaces,
        );
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::new(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleeBoundaries::default(),
            None,
            control,
        )?;
        control.poll()?;
        Self::new_with_context_and_control(function, machine_context, control)
    }

    /// Build analysis-only decompiler SSA directly from an immutable genuine lift.
    ///
    /// A genuine lift proves instruction origin, but detached source interfaces
    /// do not prove that ABI facts came from the same immutable source snapshot.
    /// This path therefore cannot grant certification authority.
    pub fn for_decompile_from_genuine_lift_with_interfaces_and_control<
        C: SsaWorkControl + ?Sized,
    >(
        lifted: &GenuineLiftedFunction,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let Some(function_interface) = function_interface else {
            return Err(malformed_ssa_input());
        };
        if function_interface.revision_identity() != lifted.authority().layout().revision_identity()
        {
            return Err(malformed_ssa_input());
        }
        let blocks = lifted
            .blocks()
            .iter()
            .map(|block| block.block().clone())
            .collect::<Vec<_>>();
        let native_spans = genuine_native_instruction_spans(lifted);
        let arch = lifted.arch_spec();
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            blocks.as_slice(),
            Some(arch),
            Some(function_interface),
            SourceMachineRoles::default(),
            None,
            call_site_interfaces,
        );
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks.as_slice(),
            Some(arch),
            InterfaceQuestions::new(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleeBoundaries::default(),
            None,
            control,
        )?;
        if function.entry != lifted.authority().layout().entry_addr() {
            return Err(malformed_ssa_input());
        }
        control.poll()?;
        let mut artifact = Self::new_with_context_control_and_provenance(
            function,
            machine_context,
            SsaArtifactProvenance::GenuineLiftOnly,
            control,
        )?;
        if !artifact
            .facts
            .obligations
            .bind_genuine_native_spans(native_spans)
        {
            return Err(malformed_ssa_input());
        }
        Ok(artifact)
    }

    /// Build analysis-only decompiler SSA from one complete genuine lift.
    pub fn for_decompile_from_genuine_lift_with_interfaces(
        lifted: &GenuineLiftedFunction,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Result<Self, SsaPrepareError> {
        Self::for_decompile_from_genuine_lift_with_interfaces_and_control(
            lifted,
            function_interface,
            call_site_interfaces,
            &UncheckedSsaWorkControl,
        )
    }

    pub fn for_patterns(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_patterns(blocks, arch)?,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    /// Build a complete pattern/type-inference SSA artifact under cooperative control.
    pub fn for_patterns_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let function = SSAFunction::from_blocks_for_patterns_with_control(blocks, arch, control)?;
        control.poll()?;
        Self::new_with_context_and_control(
            function,
            SourceMachineContext::from_blocks(blocks, arch),
            control,
        )
    }

    pub fn for_data_refs(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_data_refs(blocks, arch)?,
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
        let mut function = SSAFunction::from_blocks_raw(blocks, arch)?;
        function.refresh_decompile_prep_facts();
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
        &self.function
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
    fn carrier_storage_occupants(
        &self,
        carrier: &crate::semantic::LoopCarrierFact,
        members: &std::collections::BTreeSet<crate::ValueId>,
    ) -> std::collections::BTreeSet<crate::ValueId> {
        let storage_of = |value: crate::ValueId| {
            self.graph
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
                    &self.graph,
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
    pub const fn unobserved_values(&self) -> &std::collections::BTreeSet<crate::graph::ValueId> {
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

    /// Pairs of values the memory facts prove hold one content.
    pub fn same_content_pairs(&self) -> &[(crate::graph::ValueId, crate::graph::ValueId)] {
        self.liveness.same_content_pairs()
    }

    /// Reads the text never performs, which hold nothing live.
    pub const fn ignored_reads(&self) -> &std::collections::BTreeSet<crate::graph::UseSite> {
        self.liveness.ignored_reads()
    }

    pub fn graph(&self) -> &SsaGraph {
        &self.graph
    }

    pub fn into_function(self) -> SSAFunction {
        self.function
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
            &self.function,
            &self.graph,
            self.liveness.storage_spans(),
            assumptions,
            &self.machine_context,
            "assume",
        );
        let aggregate_accesses = collect_aggregate_access_projections(
            &self.graph,
            &facts.addresses,
            &facts.structured.memory_accesses,
            &self.machine_context,
        );
        Self {
            authority: SsaArtifactAuthority::new(),
            provenance: SsaArtifactProvenance::Manual,
            function: self.function.clone(),
            graph: self.graph.clone(),
            liveness: self.liveness.clone(),
            unobserved_merges: self.unobserved_merges.clone(),
            facts,
            machine_context: self.machine_context.clone(),
            aggregate_accesses,
            spellings: self.spellings.clone(),
        }
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
            SsaArtifactProvenance::Manual | SsaArtifactProvenance::GenuineLiftOnly => None,
        }
    }

    /// The whole table, for a consumer that outlives the artifact.
    pub fn user_operations(&self) -> Arc<[String]> {
        Arc::clone(&self.spellings.user_operations)
    }

    pub fn objects(&self) -> &ObjectModel {
        &self.facts.objects
    }

    pub fn addresses(&self) -> &crate::AddressProvenanceFacts {
        &self.facts.addresses
    }

    pub fn memory(&self) -> &MemorySSAFacts {
        &self.facts.memory
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
    pub fn declarable_stack_object(&self, object: crate::ObjectId) -> bool {
        !self.frame_managed_stack_object(object)
            && self
                .certificates()
                .stack_slots
                .get(&object)
                .is_some_and(|slot| slot.size.is_some_and(|size| size > 0))
    }

    pub fn certificates(&self) -> &crate::semantic::PreparedFunctionCertificates {
        &self.facts.certificates
    }

    pub fn obligations(&self) -> &crate::obligation::SemanticObligationInventory {
        &self.facts.obligations
    }

    pub fn callsite_certificate_for_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&CallsiteCertificate> {
        let inst = self.graph.inst_id_for_op_site(block_addr, op_idx)?;
        let callsite = self.facts.certificates.callsites_by_inst.get(&inst)?;
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
            .filter(|certificate| certificate.block_addr == block_addr);
        let certificate = found.next()?;
        found.next().is_none().then_some(certificate)
    }

    pub fn memory_certificates_for_op_site(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Vec<&MemoryAccessCertificate> {
        let certs = &self.facts.certificates;
        let read = certs
            .memory_accesses_by_op
            .get(&(block_addr, op_idx, false))
            .into_iter()
            .flatten();
        let write = certs
            .memory_accesses_by_op
            .get(&(block_addr, op_idx, true))
            .into_iter()
            .flatten();
        read.chain(write)
            .filter_map(|id| certs.memory_accesses.get(id))
            .collect()
    }

    pub fn memory_certificate_for_op_site(
        &self,
        block_addr: u64,
        op_idx: usize,
        is_write: bool,
    ) -> Option<&MemoryAccessCertificate> {
        let certs = &self.facts.certificates;
        self.facts
            .certificates
            .memory_accesses_by_op
            .get(&(block_addr, op_idx, is_write))?
            .iter()
            .filter_map(|id| certs.memory_accesses.get(id))
            .find(|cert| cert.is_write == is_write)
    }

    pub fn stack_reload_certificate_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<&StackReloadSourceCertificate> {
        self.facts.certificates.stack_reloads.get(&value_id)
    }

    pub fn stack_reload_certificate_for_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&StackReloadSourceCertificate> {
        let inst = self.graph.inst_id_for_op_site(block_addr, op_idx)?;
        let value = self.graph.inst(inst)?.output?;
        self.facts.certificates.stack_reloads.get(&value)
    }

    pub fn call_result_certificate_for_value(
        &self,
        value_id: crate::graph::ValueId,
    ) -> Option<&CallResultCertificate> {
        self.facts.certificates.call_results.get(&value_id)
    }

    pub fn call_result_certificate_for_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&CallResultCertificate> {
        let inst = self.graph.inst_id_for_op_site(block_addr, op_idx)?;
        let value = self.facts.certificates.call_results_by_inst.get(&inst)?;
        self.facts.certificates.call_results.get(value)
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
            .filter_map(|value| self.facts.certificates.call_results.get(value))
            .collect()
    }

    pub fn return_certificate_for_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&ReturnValueCertificate> {
        let inst = self.graph.inst_id_for_op_site(block_addr, op_idx)?;
        let index = self.facts.certificates.returns_by_inst.get(&inst)?;
        self.facts.certificates.returns.get(*index)
    }

    pub fn resolved_call_target(&self, call: &crate::semantic::CallSiteFact) -> Option<u64> {
        call.direct_target.or_else(|| {
            let value_id = canonical_root_value_id(self, call.target);
            let value = self.graph.value(value_id)?;
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
        crate::constant::prepared_folded_value(
            self.graph(),
            self.function().decompile_prep_facts(),
            value_id,
        )
    }

    /// Every value the body computes, in graph order.
    pub fn value_ids(&self) -> impl Iterator<Item = crate::graph::ValueId> + '_ {
        (0..self.graph().values.len())
            .filter_map(|index| u32::try_from(index).ok())
            .map(crate::graph::ValueId)
    }

    pub fn value_var(&self, value_id: crate::graph::ValueId) -> Option<&SSAVar> {
        self.graph.value(value_id).map(|value| &value.var)
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
        let facts = self.function.decompile_prep_facts()?;
        let value = self.value_var(value_id)?;
        facts.stack_address_root_of(value).copied().or_else(|| {
            let root = canonical_root_value_id(self, value_id);
            self.value_var(root)
                .and_then(|root| facts.stack_address_root_of(root))
                .copied()
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
        for value in &self.graph.values {
            if value.var.version != 0 || self.graph.def_inst(value.id).is_some() {
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
        let facts = self.function.decompile_prep_facts()?;
        let value = self.value_var(value_id)?;
        facts
            .entry_stack_address_root_of(value)
            .copied()
            .or_else(|| {
                let root = canonical_root_value_id(self, value_id);
                self.value_var(root)
                    .and_then(|root| facts.entry_stack_address_root_of(root))
                    .copied()
            })
    }

    pub fn inst_op_site(&self, inst_id: crate::graph::InstId) -> Option<(u64, usize)> {
        self.graph.op_site_for_inst(inst_id)
    }

    pub fn object_for_var(&self, var: &SSAVar, space: r2il::SpaceId) -> Option<ObjectId> {
        self.graph
            .value_id_for_var(var)
            .and_then(|value_id| self.objects().object_for_value(value_id, space))
    }

    pub fn memory_uses_for_op_site(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&[MemoryUseFact]> {
        self.graph
            .inst_id_for_op_site(block_addr, op_idx)
            .and_then(|inst_id| self.memory().uses_by_inst.get(&inst_id))
            .map(|facts| facts.as_slice())
    }

    pub fn memory_defs_for_op_site(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<&[MemoryDefFact]> {
        self.graph
            .inst_id_for_op_site(block_addr, op_idx)
            .and_then(|inst_id| self.memory().defs_by_inst.get(&inst_id))
            .map(|facts| facts.as_slice())
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.function = self.function.with_name(name);
        self
    }

    pub fn local_ssa_blocks(&self) -> &[LocalSSABlock] {
        self.function.blocks()
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
                let target = match (call.transfer(), op) {
                    (r2source::AdvisoryCallTransfer::Call, R2ILOp::Call { target }) => {
                        CanonicalStorageId::from_varnode(target)
                    }
                    (r2source::AdvisoryCallTransfer::TailJump, R2ILOp::Branch { target })
                        if op_index + 1 == block.ops.len() =>
                    {
                        CanonicalStorageId::from_varnode(target)
                    }
                    (r2source::AdvisoryCallTransfer::TailSlot, R2ILOp::BranchInd { .. })
                        if op_index + 1 == block.ops.len() =>
                    {
                        crate::machine_context::terminal_indirect_loaded_slot(block, op_index)?
                    }
                    _ => return None,
                };
                let instruction = block
                    .op_metadata(op_index)
                    .and_then(|metadata| metadata.instruction_addr)?;
                (instruction == call.instruction_address()
                    && target.offset == call.target_address())
                .then(|| SourceCallSiteIdentity::new(instruction, target))
            })
    });
    let identity = matches.next()?;
    matches.next().is_none().then_some(identity)
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
            &BTreeMap::new(),
            &CalleePreservedCarriers::new(),
            &BTreeMap::new(),
        )
    }

    /// Prepare, describing each call whose callee body came in this capture.
    ///
    /// The interfaces are keyed by callee entry address and are consulted only
    /// where the source itself recovered no prototype for the call.
    pub fn prepare_with_callee_interfaces<C: SsaWorkControl + ?Sized>(
        lifted: TrustedLiftedFunction,
        control: &C,
        callee_interfaces: &BTreeMap<u64, SourceFunctionInterface>,
        callee_preserved_carriers: &CalleePreservedCarriers,
        callee_argument_reach: &BTreeMap<
            u64,
            BTreeMap<usize, crate::interproc::SummaryArgumentReach>,
        >,
    ) -> Result<Self, SsaPrepareError> {
        let source = lifted.source().clone();
        let genuine = lifted.lifted();
        let lift_authority = genuine.authority().clone();
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
                // Recover against the same decompile-normalized SSA shape the
                // final artifact will use. The generic SSA constructor can
                // number a call differently from decompile preparation after
                // call-result and register-alias operations are inserted; an
                // exact source callsite then fails to correlate in the
                // provisional pass even though it correlates in the final one.
                let mut provisional_machine_context =
                    SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
                        blocks.as_slice(),
                        Some(&arch),
                        None,
                        *source.machine_roles(),
                        Some(source.convention_slots().clone()),
                        correlated_call_sites.interfaces.clone(),
                        correlated_call_sites.tail_calls.clone(),
                    );
                // The recovery proves variadic counts from the same literals
                // the final pass reads; without them every format was unproven.
                provisional_machine_context
                    .bind_source_string_literals(source.image().string_literals());
                let Ok(preliminary) =
                    SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                        &blocks,
                        Some(&arch),
                        InterfaceQuestions::none(),
                        provisional_machine_context
                            .machine_roles()
                            .call_preserved_carriers(),
                        provisional_machine_context.stack_pointer_carrier(),
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
                let recovered = crate::recover_interface::recover_interface_with_context(
                    &preliminary,
                    source.convention_slots(),
                    &provisional_machine_context,
                    source.function().loader_role(),
                );
                let Some(recovered) = recovered else {
                    break 'recovered None;
                };
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
        let mut machine_context =
            SourceMachineContext::from_blocks_with_interfaces_tail_calls_and_terminals(
                blocks.as_slice(),
                Some(&arch),
                function_interface,
                *source.machine_roles(),
                Some(source.convention_slots().clone()),
                correlated_call_sites.interfaces,
                correlated_call_sites.tail_calls,
                &declared_successors.terminal_blocks(),
            );
        machine_context.set_callee_linkages(correlated_call_sites.callee_linkages);
        machine_context.set_callee_names(correlated_call_sites.callee_names);
        machine_context.set_callee_argument_reach(callee_argument_reach.clone());
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
        let mut function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks.as_slice(),
            Some(&arch),
            InterfaceQuestions::new(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &callees,
            Some(&declared_successors),
            control,
        )?;
        // What the source calls this function. A name radare2 derived from the
        // entry address restates the address and is left absent, so consumers
        // that would only spell it back out are not misled into thinking the
        // function was named.
        let presented = source.presentation().display_name();
        if !r2source::display_names::is_generated_function_name(presented) {
            function = function.with_name(presented);
        }
        if function.entry != source.image().entry_address() {
            return Err(malformed_ssa_input());
        }
        control.poll()?;
        let mut artifact = SsaArtifact::new_with_context_control_and_provenance(
            function,
            machine_context,
            SsaArtifactProvenance::TrustedSource(source),
            control,
        )?;
        artifact.spellings = ArtifactSpellings {
            display_names,
            user_operations: Arc::from(arch.user_ops.clone()),
        };
        if !artifact
            .facts
            .obligations
            .bind_genuine_native_spans(native_spans)
        {
            return Err(malformed_ssa_input());
        }
        Ok(Self {
            artifact: Arc::new(artifact),
            lift_authority,
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

    pub const fn lift_authority(&self) -> &GenuineLiftedFunctionAuthority {
        &self.lift_authority
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
            SsaArtifactProvenance::Manual | SsaArtifactProvenance::GenuineLiftOnly => {
                unreachable!("TrustedSsaArtifact always retains source provenance")
            }
        }
    }
}

/// The end of the canonical-root chain from `var`.
///
/// One walker for both phases: the map is mutable while the facts are being
/// built and frozen afterwards, but the relation is the same one, so there is
/// one place that follows it. `insert_canonical_root` establishes acyclicity by
/// canonicalising the root it is given before storing it; the visited set here
/// is what makes a violation of that invariant visible instead of a hang, and
/// it says so rather than returning whichever node the walk stopped at as if it
/// were the root.
pub(crate) fn canonical_root_in<'a>(
    roots: &'a HashMap<SSAVar, SSAVar>,
    var: &'a SSAVar,
) -> &'a SSAVar {
    let mut current = var;
    // A walk that visits more entries than the map holds has been somewhere
    // twice, which is the only way it can fail to terminate. Counting says so
    // for the cost of an integer; the set of visited variables that said so
    // before allocated an ordered-set node on every call, and this is the
    // most-called function of a whole analysis.
    for _ in 0..=roots.len() {
        let Some(next) = roots.get(current) else {
            return current;
        };
        if next == current {
            return current;
        }
        current = next;
    }
    r2il::refusal_evidence!(
        "canonical-root-cycle",
        "the canonical-root map cycles at {current:?} on the walk from {var:?}"
    );
    current
}

/// The value the canonical root names, or `value_id` where the root is not a
/// value of this graph.
pub(crate) fn canonical_root_value_id(
    prepared: &SsaArtifact,
    value_id: crate::graph::ValueId,
) -> crate::graph::ValueId {
    let Some(facts) = prepared.function().decompile_prep_facts() else {
        return value_id;
    };
    let Some(start) = prepared.value_var(value_id) else {
        return value_id;
    };
    prepared
        .graph()
        .value_id_for_var(facts.canonical_root(start))
        .unwrap_or(value_id)
}

impl Deref for SsaArtifact {
    type Target = SSAFunction;

    fn deref(&self) -> &Self::Target {
        &self.function
    }
}

impl DecompilePrepFacts {
    pub fn canonical_root_of(&self, var: &SSAVar) -> Option<&SSAVar> {
        self.canonical_value_roots.get(var)
    }

    /// The canonical root of `var`: the fixed point of `canonical_root_of`.
    ///
    /// The walk terminates because every step moves to a var it has not seen
    /// and the map is finite, so it runs at most once per var and ends at the
    /// fixed point. The visited set makes the map's acyclicity -- which
    /// `insert_canonical_root` establishes by canonicalising before it stores
    /// -- a checked property rather than an assumed one. Stopping short of the
    /// fixed point would hand back a value that is not the root, and identity
    /// is what every later stage builds on.
    pub fn canonical_root<'a>(&'a self, var: &'a SSAVar) -> &'a SSAVar {
        canonical_root_in(&self.canonical_value_roots, var)
    }

    pub fn indexed_stack_address_root_of(&self, var: &SSAVar) -> Option<&StackAddressRoot> {
        self.indexed_stack_address_roots.get(var)
    }

    pub fn stack_address_root_of(&self, var: &SSAVar) -> Option<&StackAddressRoot> {
        self.stack_address_roots.get(var)
    }

    pub fn entry_stack_address_root_of(&self, var: &SSAVar) -> Option<&StackAddressRoot> {
        self.entry_stack_address_roots.get(var)
    }

    pub fn formal_parameter_of(&self, var: &SSAVar) -> Option<usize> {
        self.formal_parameters.get(var).copied()
    }
}

/// A function in SSA form.
///
/// This is the main entry point for function-level SSA analysis.
/// It contains the CFG, dominator tree, and SSA operations for all blocks.
#[derive(Debug)]
pub struct SSAFunction {
    /// Whether a call leaves the carriers that address this frame alone.
    ///
    /// Held here rather than read off the function interface, because the
    /// source publishes it for functions whose interface it withholds, and
    /// those are the ones that need it.
    call_preserved_carriers: Option<SourceCallPreservedCarriers>,
    /// The lifted memory operations promotion took out of memory.
    ///
    /// A promoted slot access is a copy of a variable in the prepared
    /// operations, so it is no longer one of the function's memory
    /// operations, and every layer that counts those has to agree.
    promoted_slot_sites: BTreeSet<(u64, usize)>,
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
    /// Entry point address.
    pub entry: u64,
    /// Control flow graph.
    cfg: CFG,
    /// Dominator tree.
    domtree: DomTree,
    /// SSA operations, one entry per block, in reverse postorder.
    ///
    /// Dense and ordered rather than a hash map beside a separate order, so
    /// that reading the blocks is a slice rather than a walk of one container
    /// looking each address up in another.
    blocks: Vec<SSABlock>,
    /// Where each block address sits in `blocks`.
    block_index: BTreeMap<u64, u32>,
    /// The same addresses as `blocks`, in the same order, for readers that want
    /// the addresses without the operations.
    block_order: Vec<u64>,
    /// Canonical lifted storage retained during SSA renaming.
    ///
    /// Values are attached from raw varnodes at the lift/SSA seam. Consumers
    /// must not reconstruct this information from `SSAVar::name`.
    canonical_storage_by_var: BTreeMap<SSAVar, CanonicalStorageId>,
    /// Entry-lane projections: the value standing for a lane of a register as
    /// the function was entered with it, defined at entry as a `Subpiece` of
    /// the family root's entry value (doc/adr-register-identity.md §8, 6).
    /// Keyed by the projection's variable, valued by the lane's storage.
    formal_projections: BTreeMap<SSAVar, CanonicalStorageId>,
    /// Optional decompiler-prep fact snapshot for the current SSA state.
    decompile_prep_facts: Option<DecompilePrepFacts>,
    /// Structural def/use index for repeated SSA queries.
    query_index: RwLock<Option<SsaQueryIndex>>,
}

/// Where every variable is defined and read, without saying so twice.
///
/// The function already holds each variable once, at the site that names it,
/// so an index keyed by an owned copy of the variable pays for a second name
/// per definition and a third per use. These are the sites alone, ordered by
/// the variable they mention, and a query binary-searches them and reads the
/// variable back out of the block. One name, one owner, and the answers and
/// their order are the ones the owned index gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SsaQueryIndex {
    defs: Vec<(u32, DefLocation)>,
    uses: Vec<(u32, UseLocation)>,
}

/// One block of a reverse-postorder vector, by address.
/// Reads of one memory object that see the same content: consecutive reads
/// in one block with no write to that object between them.
fn same_content_reads(
    structured: &crate::semantic::StructuredDataflowFacts,
) -> Vec<(crate::graph::ValueId, crate::graph::ValueId)> {
    let mut by_block_object =
        BTreeMap::<(u64, crate::ObjectId), Vec<&crate::semantic::StructuredMemoryAccessFact>>::new(
        );
    for access in structured.memory_accesses.values() {
        by_block_object
            .entry((access.block_addr, access.object))
            .or_default()
            .push(access);
    }
    let mut pairs = Vec::new();
    for accesses in by_block_object.values_mut() {
        accesses.sort_by_key(|access| access.op_index);
        let mut last_read = None;
        for access in accesses.iter() {
            if access.is_write {
                last_read = None;
                continue;
            }
            let Some(value) = access.value else {
                continue;
            };
            if let Some(previous) = last_read {
                pairs.push((previous, value));
            }
            last_read = Some(value);
        }
    }
    pairs
}

/// A call's conventional reads of registers the certified call does not
/// pass. The graph states a read of every register the convention lets a
/// callee read, so that liveness before the facts exist errs safe; once the
/// call boundary says which values are arguments, the rest are not reads.
fn uncertified_call_reads(
    graph: &SsaGraph,
    boundaries: &crate::semantic::SourceBoundaryFacts,
) -> std::collections::BTreeSet<crate::graph::UseSite> {
    let mut passed = std::collections::BTreeSet::new();
    for boundary in boundaries.calls.values() {
        for argument in &boundary.arguments {
            if let crate::semantic::SourceCallArgumentValue::Value(value) = argument.value {
                passed.insert(value);
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
                .filter(|(_, input)| !passed.contains(input))
                .map(move |(input_idx, _)| crate::graph::UseSite {
                    inst: inst.id,
                    input_idx,
                })
        })
        .collect()
}

fn block_at_mut<'a>(
    index: &BTreeMap<u64, u32>,
    blocks: &'a mut [SSABlock],
    addr: u64,
) -> Option<&'a mut SSABlock> {
    blocks.get_mut(*index.get(&addr)? as usize)
}

/// Where each block sits in a reverse-postorder block vector.
fn block_index_of(blocks: &[SSABlock]) -> BTreeMap<u64, u32> {
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
            promoted_slot_sites: self.promoted_slot_sites.clone(),
            stack_pointer_carrier: self.stack_pointer_carrier,
            name: self.name.clone(),
            entry: self.entry,
            cfg: self.cfg.clone(),
            domtree: self.domtree.clone(),
            blocks: self.blocks.clone(),
            block_index: self.block_index.clone(),
            block_order: self.block_order.clone(),
            canonical_storage_by_var: self.canonical_storage_by_var.clone(),
            formal_projections: self.formal_projections.clone(),
            decompile_prep_facts: self.decompile_prep_facts.clone(),
            query_index: RwLock::new(None),
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
}

impl<'a> RewrittenFunction<'a> {
    /// Pair rewritten operations with the function whose shape they keep.
    pub fn new(source: &'a SSAFunction, blocks: Vec<SSABlock>) -> Self {
        let block_index = block_index_of(&blocks);
        Self {
            source,
            blocks,
            block_index,
        }
    }

    /// The function the operations were rewritten from.
    pub const fn source(&self) -> &'a SSAFunction {
        self.source
    }

    pub const fn entry(&self) -> u64 {
        self.source.entry
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

    pub fn entry_block(&self) -> Option<&SSABlock> {
        self.get_block(self.entry())
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

    /// One block's operations, mutable, for the pass that is still building.
    pub fn get_block_mut(&mut self, addr: u64) -> Option<&mut SSABlock> {
        let index = *self.block_index.get(&addr)? as usize;
        self.blocks.get_mut(index)
    }

    /// A second copy of these operations over the same function, for a test
    /// that wants to rewrite them again.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self::new(self.source, self.blocks.clone())
    }

    /// The rewritten operations, in the text the source function dumps.
    pub fn dump(&self) -> String {
        dump_blocks(self.name(), self.entry(), self.blocks(), self.source)
    }
}

/// One function's blocks as text, shared by a function and by operations
/// rewritten over it.
fn dump_blocks(name: Option<&str>, entry: u64, blocks: &[SSABlock], shape: &SSAFunction) -> String {
    let mut out = String::new();

    out.push_str(&format!("Function: {}\n", name.unwrap_or("<unnamed>")));
    out.push_str(&format!("Entry: 0x{:x}\n", entry));
    out.push_str(&format!("Blocks: {}\n\n", blocks.len()));

    for block in blocks {
        {
            let addr = block.addr;
            out.push_str(&format!("Block 0x{:x}:\n", addr));

            // Predecessors
            let preds = shape.predecessors(addr);
            if !preds.is_empty() {
                out.push_str(&format!(
                    "  preds: {}\n",
                    preds
                        .iter()
                        .map(|p| format!("0x{:x}", p))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            // Phi nodes
            for phi in &block.phis {
                let sources: Vec<String> = phi
                    .sources
                    .iter()
                    .map(|(pred, var)| format!("[0x{:x}]: {}", pred, var))
                    .collect();
                out.push_str(&format!("  {} = phi({})\n", phi.dst, sources.join(", ")));
            }

            // Operations, spelled the way the phis above are: `SSAOp` has a
            // Display of its own and the derived Debug was shadowing it.
            for op in &block.ops {
                out.push_str(&format!("  {op}\n"));
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

/// A phi node in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiNode {
    /// The destination variable.
    pub dst: SSAVar,
    /// The source variables, one per predecessor.
    pub sources: Vec<(u64, SSAVar)>, // (predecessor addr, variable)
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
pub struct SourceRef<'a> {
    pub var: &'a SSAVar,
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
pub struct DefRef<'a> {
    pub var: &'a SSAVar,
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
            if let Some(carriers) = preserved.get_mut(address) {
                carriers.retain(|carrier| carrier.location() != storage.location());
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

    /// The carrier each callee proves holds the address the call pushed.
    pub(crate) const fn return_addresses(&self) -> &BTreeMap<u64, CanonicalStorageId> {
        &self.return_addresses
    }
}

/// What a call boundary does to this architecture's registers.
///
/// `stack_pointer_restored_by_callee` carries the storage only when the source
/// stated that the convention restores it; see the field's own documentation
/// for why the caller's stack pointer is otherwise wrong from its first call
/// onward.
fn decompile_call_boundary_config(
    arch: Option<&ArchSpec>,
    stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
    callees: CalleeBoundaries,
) -> Option<CallBoundaryConfig> {
    let arch = arch?;
    let defined_regs = call_clobbered_register_defs(arch);
    if defined_regs.is_empty() && stack_pointer_restored_by_callee.is_none() {
        return None;
    }
    Some(CallBoundaryConfig {
        defined_regs,
        stack_pointer_restored_by_callee,
        preserved_by_target: callees.preserved,
        result_by_target: callees.results,
        argument_regs: call_argument_register_defs(arch),
        return_regs: return_read_register_defs(arch),
    })
}

/// The registers a call reads without naming them in an operand: the
/// convention's argument carriers.
fn call_argument_register_defs(arch: &ArchSpec) -> Vec<CallBoundaryDef> {
    let named = |names: &[(&str, u32)]| {
        names
            .iter()
            .map(|(name, size)| CallBoundaryDef {
                name: (*name).to_string(),
                size: *size,
            })
            .collect()
    };
    match arch.name.to_ascii_lowercase().as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => named(&[
            ("rdi", 8),
            ("edi", 4),
            ("rsi", 8),
            ("esi", 4),
            ("rdx", 8),
            ("edx", 4),
            ("rcx", 8),
            ("ecx", 4),
            ("r8", 8),
            ("r8d", 4),
            ("r9", 8),
            ("r9d", 4),
            ("rax", 8),
            ("eax", 4),
        ]),
        "x86" | "x86-32" | "i386" | "i686" => named(&[("eax", 4)]),
        "arm" if arch.addr_size == 4 => named(&[("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4)]),
        "aarch64" | "arm64" => named(&[
            ("x0", 8),
            ("w0", 4),
            ("x1", 8),
            ("w1", 4),
            ("x2", 8),
            ("w2", 4),
            ("x3", 8),
            ("w3", 4),
            ("x4", 8),
            ("w4", 4),
            ("x5", 8),
            ("w5", 4),
            ("x6", 8),
            ("w6", 4),
            ("x7", 8),
            ("w7", 4),
            ("x8", 8),
            ("w8", 4),
        ]),
        _ => Vec::new(),
    }
}

/// The registers a return reads without naming them in an operand: the
/// convention's result carriers, plus the stack and frame it hands back.
fn return_read_register_defs(arch: &ArchSpec) -> Vec<CallBoundaryDef> {
    let named = |names: &[(&str, u32)]| {
        names
            .iter()
            .map(|(name, size)| CallBoundaryDef {
                name: (*name).to_string(),
                size: *size,
            })
            .collect()
    };
    match arch.name.to_ascii_lowercase().as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => {
            named(&[("rax", 8), ("eax", 4), ("rdx", 8), ("edx", 4)])
        }
        "x86" | "x86-32" | "i386" | "i686" => named(&[("eax", 4), ("edx", 4)]),
        "arm" if arch.addr_size == 4 => named(&[("r0", 4), ("r1", 4)]),
        "aarch64" | "arm64" => named(&[("x0", 8), ("w0", 4), ("x1", 8), ("w1", 4)]),
        _ => Vec::new(),
    }
}

/// The registers a call may leave changed under this architecture's
/// convention: what a caller must treat as freshly defined after a call it
/// knows nothing more about.
///
/// This list has one owner. Construction emits a `CallDefine` for each entry
/// at every call, and a callee's return boundary tests the same entries to
/// state which of them its body leaves untouched, so the two sides can never
/// disagree about which registers are in question.
pub(crate) fn call_clobbered_register_defs(arch: &ArchSpec) -> Vec<CallBoundaryDef> {
    let lower = arch.name.to_ascii_lowercase();
    match lower.as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => vec![
            CallBoundaryDef {
                name: "rax".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "eax".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "rdi".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "rsi".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "rdx".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "rcx".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "r8".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "r9".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "r10".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "r11".to_string(),
                size: 8,
            },
        ],
        "x86" | "x86-32" | "i386" | "i686" => vec![
            CallBoundaryDef {
                name: "eax".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "ecx".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "edx".to_string(),
                size: 4,
            },
        ],
        "arm" if arch.addr_size == 4 => vec![
            CallBoundaryDef {
                name: "r0".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "r1".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "r2".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "r3".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "r12".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "lr".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "ip".to_string(),
                size: 4,
            },
        ],
        "aarch64" | "arm64" => vec![
            CallBoundaryDef {
                name: "x0".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w0".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x1".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w1".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x2".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w2".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x3".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w3".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x4".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w4".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x5".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w5".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x6".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w6".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x7".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w7".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x8".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w8".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x9".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w9".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x10".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w10".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x11".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w11".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x12".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w12".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x13".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w13".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x14".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w14".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x15".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w15".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x16".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w16".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x17".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w17".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "x30".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "w30".to_string(),
                size: 4,
            },
        ],
        "riscv32" | "rv32" | "rv32gc" => vec![
            CallBoundaryDef {
                name: "ra".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t0".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t1".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t2".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t3".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t4".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t5".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "t6".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a0".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a1".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a2".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a3".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a4".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a5".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a6".to_string(),
                size: 4,
            },
            CallBoundaryDef {
                name: "a7".to_string(),
                size: 4,
            },
        ],
        "riscv64" | "rv64" | "rv64gc" => vec![
            CallBoundaryDef {
                name: "ra".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t0".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t1".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t2".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t3".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t4".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t5".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "t6".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a0".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a1".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a2".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a3".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a4".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a5".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a6".to_string(),
                size: 8,
            },
            CallBoundaryDef {
                name: "a7".to_string(),
                size: 8,
            },
        ],
        _ => Vec::new(),
    }
}

/// Whether the convention puts the stack pointer back after a call.
///
/// The source publishes this beside the machine roles for every function,
/// including the ones whose signature it never linked; the interface's copy is
/// the fallback, and it is defaulted to false for exactly those functions, so
/// asking it first asks the answerer that does not know.
fn stack_pointer_restored_across_calls(
    carriers: Option<SourceCallPreservedCarriers>,
    function_interface: Option<&SourceFunctionInterface>,
) -> bool {
    carriers.map_or_else(
        || {
            function_interface
                .is_some_and(SourceFunctionInterface::stack_pointer_preserved_across_calls)
        },
        SourceCallPreservedCarriers::stack_pointer,
    )
}

/// The same question for the frame pointer, which has no carrier to restore
/// when the function keeps none.
fn frame_pointer_restored_across_calls(
    carriers: Option<SourceCallPreservedCarriers>,
    function_interface: Option<&SourceFunctionInterface>,
) -> bool {
    carriers.map_or_else(
        || {
            function_interface.is_some_and(|interface| {
                interface.frame_pointer_storage().is_none()
                    || interface.frame_pointer_preserved_across_calls()
            })
        },
        SourceCallPreservedCarriers::frame_pointer,
    )
}

impl SSAFunction {
    /// The architectural stack pointer, as the machine roles name it.
    pub const fn stack_pointer_carrier(&self) -> Option<CanonicalStorageId> {
        self.stack_pointer_carrier
    }

    #[cfg(test)]
    pub(crate) fn from_exact_test_blocks(blocks: &[SSABlock], cfg: CFG) -> Self {
        let entry = cfg
            .entry_block()
            .map(|block| block.addr)
            .unwrap_or_default();
        let domtree = DomTree::compute(&cfg);
        let block_order = cfg.reverse_postorder();
        let ordered = block_order
            .iter()
            .filter_map(|addr| blocks.iter().find(|block| block.addr == *addr).cloned())
            .collect::<Vec<_>>();
        Self {
            call_preserved_carriers: None,
            promoted_slot_sites: BTreeSet::new(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            block_index: block_index_of(&ordered),
            blocks: ordered,
            block_order,
            canonical_storage_by_var: BTreeMap::new(),
            formal_projections: BTreeMap::new(),
            decompile_prep_facts: None,
            query_index: RwLock::new(None),
        }
    }

    /// Build an SSA function from a sequence of r2il blocks.
    pub fn from_blocks(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_with_arch(blocks, None)
    }

    /// Build an SSA function from blocks with constructor-time SCCP enabled.
    pub fn from_blocks_with_arch(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        let mut func = Self::from_blocks_raw(blocks, arch)?;
        // Constructor path applies SCCP by default while keeping legacy SSA consumers stable.
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: false,
        };
        func.optimize(&cfg);
        validate_ssa_function(&func).ok()?;
        Some(func)
    }

    /// Build SSA prepared for decompilation.
    ///
    /// Unlike the generic constructor path, this preserves copy/cast and
    /// address-provenance roots by default and only applies explicitly
    /// configured decompiler-safe cleanup.
    pub fn from_blocks_for_decompile(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
    ) -> Option<Self> {
        Self::from_blocks_for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build decompiler-prepared SSA while polling expensive worklists.
    ///
    /// The function is constructed locally and returned only after every
    /// preparation and canonicalization phase completes.
    pub fn from_blocks_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::none(),
            None,
            None,
            &CalleeBoundaries::default(),
            None,
            control,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_blocks_for_decompile_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        questions: InterfaceQuestions<'_>,
        call_preserved_carriers: Option<SourceCallPreservedCarriers>,
        stack_pointer_carrier: Option<CanonicalStorageId>,
        callees: &CalleeBoundaries,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        // The lifted text as it arrived, for a reader tracing a defect that
        // the SSA may already have folded away; the SSA dump is r2dec's.
        if dump_il() {
            for block in blocks {
                eprintln!("R2IL block {:#x} ({} ops)", block.addr, block.ops.len());
                for (index, op) in block.ops.iter().enumerate() {
                    eprintln!("  {index}: {op:?}");
                }
            }
        }
        control.poll()?;
        // The convention says the callee leaves this carrier where it found
        // it, and the machine's own p-code moved it to transfer control. Both
        // halves have to be in hand before SSA construction, because it is
        // construction that decides which value each later read of the carrier
        // sees.
        let stack_pointer_restored_by_callee = stack_pointer_carrier.filter(|_| {
            stack_pointer_restored_across_calls(
                call_preserved_carriers,
                questions.for_machine_carriers(),
            )
        });
        // The carriers the convention names at this function's own boundary:
        // every caller reads the result register and writes the argument
        // registers, so the whole of each is used even where the body's own
        // operations name only a lane of one.
        let abi_carriers = questions
            .for_argument_placement()
            .into_iter()
            .flat_map(|interface| {
                interface
                    .parameters()
                    .iter()
                    .filter_map(crate::SourceAbiParameterSpec::register_storage)
            })
            .chain(questions.for_return_boundary().and_then(|interface| {
                match interface.return_kind() {
                    crate::SourceFunctionReturn::Register { storage } => Some(storage),
                    crate::SourceFunctionReturn::Void | crate::SourceFunctionReturn::Unproven => {
                        None
                    }
                }
            }))
            .collect::<Vec<_>>();

        // Which frame slots behave like variables. Asked of the lifted text,
        // before construction, because construction is what decides which
        // value each read of a variable sees.
        let promoted = crate::promote::promote_private_stack_slots(
            blocks,
            stack_pointer_carrier,
            questions.interface,
            &abi_carriers,
            stack_pointer_restored_by_callee.is_some(),
        )
        .unwrap_or_default();
        // The same phase report the semantic collector gives, for the half of
        // a decompile's bytes that are already held before the collector runs.
        // Construction is three passes over the same body and they do not cost
        // alike; without this the whole of it is one number.
        let started = std::time::Instant::now();
        let held = std::cell::Cell::new(r2il::allocation::live_bytes());
        let phase = |name: &str, size: usize| {
            let live = r2il::allocation::live_bytes();
            let grew = live.saturating_sub(held.get());
            held.set(live);
            r2il::refusal_evidence!(
                "collect-phase",
                "build@{:#x}/{} {name} {} ms size {size} bytes {grew}",
                blocks.first().map_or(0, |block| block.addr),
                blocks.len(),
                started.elapsed().as_millis()
            );
        };
        let mut func = Self::from_blocks_raw_for_decompile_with_carriers_and_control(
            blocks,
            arch,
            stack_pointer_restored_by_callee,
            callees,
            declared_successors,
            &abi_carriers,
            &promoted,
            control,
        )?;
        phase("raw", func.num_blocks());
        func.call_preserved_carriers = call_preserved_carriers;
        func.stack_pointer_carrier = stack_pointer_carrier;
        // Before preparation, so the arithmetic above the constant folds with it.
        func.forward_proven_call_return_addresses(callees);
        // Preparation reads the interface for the return projection only.
        func.prepare_for_decompile_with_interface_and_control(
            &crate::optimize::DecompilePrepConfig::default(),
            questions.for_return_boundary(),
            control,
        )?;
        phase("prepared", func.num_blocks());
        // The prep facts read it for the declared stack bases.
        func.refresh_decompile_prep_facts_with_interface_and_control(
            questions.for_frame_geometry(),
            control,
        )?;
        phase("prep_facts", func.num_blocks());
        validate_ssa_function(&func).map_err(|error| {
            r2il::refusal_evidence!("ssa-integrity", "{error:?}");
            malformed_ssa_input()
        })?;
        phase("validated", 0);
        control.poll()?;
        Ok(func)
    }

    /// Build SSA prepared for pattern/type inference.
    ///
    /// This keeps memory reads and address arithmetic intact while still
    /// applying limited whole-function SCCP so layout-sensitive patterns
    /// collapse to a canonical indexed+offset form for downstream consumers.
    pub fn from_blocks_for_patterns(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::from_blocks_for_patterns_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build pattern/type-inference SSA while polling expensive worklists.
    pub fn from_blocks_for_patterns_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        let mut func = Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            None,
            None,
            &[],
            &Default::default(),
            control,
        )?;
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: true,
        };
        func.decompile_prep_facts = None;
        func.invalidate_query_index();
        crate::optimize::optimize_function_with_control(&mut func, &cfg, control)?;
        validate_ssa_function(&func).map_err(|_| malformed_ssa_input())?;
        func.refresh_decompile_prep_facts_with_control(control)?;
        control.poll()?;
        Ok(func)
    }

    /// Build SSA for data-reference recovery.
    ///
    /// This keeps memory reads intact and applies a single SCCP pass to
    /// recover cross-block constant targets without paying the extra
    /// subregister normalization and decompile-prep cost.
    pub fn from_blocks_for_data_refs(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
    ) -> Option<Self> {
        let mut func = Self::from_blocks_raw(blocks, arch)?;
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: true,
        };
        func.optimize(&cfg);
        validate_ssa_function(&func).ok()?;
        Some(func)
    }

    /// Build an SSA function from blocks without running optimization passes.
    ///
    /// This performs raw SSA construction:
    /// 1. Build CFG from blocks
    /// 2. Compute dominator tree
    /// 3. Place phi nodes
    /// 4. Rename variables
    pub fn from_blocks_raw(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::from_blocks_raw_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build raw SSA while polling the caller's cancellation and deadline.
    ///
    /// Renaming a whole function is not work a caller can abandon once it has
    /// started, so a preflight that builds raw SSA only to inspect it needs
    /// this seam: without it the poll-free builder runs to completion past a
    /// deadline the request has already missed.
    pub fn from_blocks_raw_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            None,
            None,
            &[],
            &Default::default(),
            control,
        )
    }

    /// Build raw SSA prepared with decompiler-safe call boundaries.
    pub fn from_blocks_raw_for_decompile(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
    ) -> Option<Self> {
        Self::from_blocks_raw_for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl)
            .ok()
    }

    /// Build raw decompiler SSA while polling construction worklists.
    pub fn from_blocks_raw_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_raw_for_decompile_with_carriers_and_control(
            blocks,
            arch,
            None,
            &CalleeBoundaries::default(),
            None,
            &[],
            &Default::default(),
            control,
        )
    }

    /// The same, told which carrier the convention says a callee restores.
    #[allow(clippy::too_many_arguments)]
    fn from_blocks_raw_for_decompile_with_carriers_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
        callees: &CalleeBoundaries,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
        promoted: &crate::phi::PromotedStackSlots,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let policy =
            decompile_call_boundary_config(arch, stack_pointer_restored_by_callee, callees.clone());
        Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            policy.as_ref(),
            declared_successors,
            abi_carriers,
            promoted,
            control,
        )
    }

    fn from_blocks_raw_with_policy_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        call_boundaries: Option<&CallBoundaryConfig>,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
        promoted: &crate::phi::PromotedStackSlots,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        if blocks.is_empty() {
            return Err(malformed_ssa_input());
        }

        // Build CFG
        let cfg = CFG::from_blocks_with_declared_successors(blocks, declared_successors)
            .ok_or_else(malformed_ssa_input)?;
        control.poll()?;
        let entry = cfg.entry;

        // Compute dominator tree
        let domtree = DomTree::compute_with_control(&cfg, control)?;

        let reg_names = arch.map(cached_register_name_map);
        let reg_names_ref = reg_names.as_deref();
        // One identity per register family: a lane is renamed as a projection
        // of its root (doc/adr-register-identity.md).
        // One identity per register family, rooted at what this function
        // touches of it rather than at the widest name the architecture has.
        let families = arch.map(cached_register_family_info).map(|families| {
            let mut used = Vec::new();
            for block in cfg.blocks() {
                for op in &block.ops {
                    for varnode in op.inputs().into_iter().chain(op.output()) {
                        if matches!(varnode.space, r2il::SpaceId::Register) {
                            used.push((varnode.offset, varnode.size));
                        }
                    }
                }
            }
            // The carriers the convention names at this function's boundary.
            for carrier in abi_carriers {
                if carrier.space == CanonicalStorageSpace::Register {
                    used.push((carrier.offset, carrier.size));
                }
            }
            // A convention's clobber list describes what a call does, so it
            // widens a root only in a function that makes one.
            let calls = cfg.blocks().any(|block| {
                block
                    .ops
                    .iter()
                    .any(|op| matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }))
            });
            if let Some(call_boundaries) = call_boundaries.filter(|_| calls) {
                for reg in &call_boundaries.defined_regs {
                    if let Some(slot) = families.slot_for_name(&reg.name) {
                        used.push((slot.offset, reg.size.max(slot.width)));
                    }
                }
            }
            Arc::new(families.with_program_roots(used))
        });
        let families_ref = families.as_deref();

        // Collect variable definitions and sizes
        let (mut defs, mut storage_by_identity) =
            collect_defs_from_cfg_with_names_storage_and_control(
                &cfg,
                reg_names_ref,
                families_ref,
                promoted,
                control,
            )?;

        // Place phi nodes
        let mut phi_placement = PhiPlacement::compute_with_storage_and_control(
            &cfg,
            &domtree,
            &defs,
            &storage_by_identity,
            control,
        )?;
        // A call defines its convention's registers, and renaming writes those
        // definitions after placement has run, so the merges they need are
        // added here -- pruned, because an unread merge only invents a live-in.
        if let Some(call_boundaries) = call_boundaries {
            crate::phi::add_call_boundary_def_sites(
                &cfg,
                call_boundaries,
                reg_names_ref,
                families_ref,
                &mut defs,
                &mut storage_by_identity,
            );
            let complete = PhiPlacement::compute_with_storage_and_control(
                &cfg,
                &domtree,
                &defs,
                &storage_by_identity,
                control,
            )?;
            let live_in = crate::phi::live_in_by_block(
                &cfg,
                call_boundaries,
                reg_names_ref,
                families_ref,
                &defs,
            );
            phi_placement.merge_live_additions(complete, &live_in);
        }

        // Rename variables
        let renamed = rename_function(
            crate::rename::RenameInputs {
                cfg: &cfg,
                domtree: &domtree,
                phi_placement: &phi_placement,
                reg_names: reg_names_ref,
                call_boundaries,
                promoted,
            },
            &defs,
            families.clone(),
            control,
        )?;

        // Build SSA blocks. The renamed ops move across rather than being
        // cloned: holding both copies doubled every operation of the function,
        // and each operation owns up to four named variables.
        let mut renamed_blocks = renamed.blocks;
        let renamed_block_order = renamed.block_order;
        let renamed_storage = renamed.canonical_storage_by_var;
        let mut ssa_blocks = Vec::with_capacity(renamed_block_order.len());
        for &addr in &renamed_block_order {
            control.poll()?;
            let cfg_block = cfg.get_block(addr).ok_or_else(malformed_ssa_input)?;
            let ops = renamed_blocks.remove(&addr).unwrap_or_default();

            // Separate phi nodes from other ops
            let (phi_ops, other_ops): (Vec<_>, Vec<_>) = ops
                .into_iter()
                .partition(|op| matches!(op, SSAOp::Phi { .. }));

            // Convert phi ops to PhiNode structs
            let preds = cfg.predecessors(addr);
            let mut phis = Vec::with_capacity(phi_ops.len());
            for (phi_idx, op) in phi_ops.into_iter().enumerate() {
                let SSAOp::Phi { dst, sources } = op else {
                    unreachable!("phi partition contains only phi operations");
                };
                if sources.len() != preds.len() {
                    return Err(malformed_ssa_input());
                }
                let phi_sources = sources
                    .into_iter()
                    .zip(preds.iter().copied())
                    .map(|(var, pred)| (pred, var))
                    .collect();
                let canonical_storage = phi_placement
                    .get_phis(addr)
                    .get(phi_idx)
                    .and_then(|phi| phi.storage);
                phis.push(PhiNode {
                    dst,
                    sources: phi_sources,
                    canonical_storage,
                });
            }

            let ssa_block = SSABlock {
                addr,
                size: cfg_block.size,
                ops: other_ops,
                phis,
            };
            ssa_blocks.push(ssa_block);
        }

        let mut cfg = cfg;
        cfg.release_operations();
        let mut function = Self {
            call_preserved_carriers: None,
            promoted_slot_sites: promoted.keys().copied().collect(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            block_index: block_index_of(&ssa_blocks),
            block_order: renamed_block_order,
            blocks: ssa_blocks,
            canonical_storage_by_var: renamed_storage,
            formal_projections: BTreeMap::new(),
            decompile_prep_facts: None,
            query_index: RwLock::new(None),
        };
        function.zero_scratch_insert_roots(abi_carriers);
        // The validator answers with a typed integrity error naming the block
        // and the edge it disagreed about; discarding it left the reader with
        // "malformed SSA source input" and nothing to look at.
        validate_ssa_function(&function).map_err(|error| {
            if r2il::refusal_evidence::tracing() {
                let mut addrs = function.block_order.clone();
                addrs.sort_unstable();
                eprintln!("ssa block domain ({}): {addrs:x?}", addrs.len());
            }
            r2il::refusal_evidence!("ssa-integrity", "{error:?}");
            malformed_ssa_input()
        })?;
        control.poll()?;
        Ok(function)
    }

    /// Build raw SSA without architecture metadata.
    pub fn from_blocks_raw_no_arch(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_raw(blocks, None)
    }

    /// Which lifted memory operations promotion took out of memory.
    pub fn promoted_slot_sites(&self) -> &BTreeSet<(u64, usize)> {
        &self.promoted_slot_sites
    }

    /// Set the function name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the entry block.
    pub fn entry_block(&self) -> Option<&SSABlock> {
        self.get_block(self.entry)
    }

    /// Get a block by address.
    pub fn get_block(&self, addr: u64) -> Option<&SSABlock> {
        self.blocks.get(*self.block_index.get(&addr)? as usize)
    }

    /// Get a mutable block by address.
    pub fn get_block_mut(&mut self, addr: u64) -> Option<&mut SSABlock> {
        let index = *self.block_index.get(&addr)? as usize;
        self.invalidate_query_index();
        self.decompile_prep_facts = None;
        self.blocks.get_mut(index)
    }

    /// All blocks in reverse postorder.
    pub fn blocks(&self) -> &[SSABlock] {
        &self.blocks
    }

    /// Get block addresses in reverse postorder.
    pub fn block_addrs(&self) -> &[u64] {
        &self.block_order
    }

    /// Return name-independent storage provenance retained from the lifted
    /// varnode that produced or supplied this SSA value.
    pub(crate) fn canonical_storage_for_var(&self, var: &SSAVar) -> Option<CanonicalStorageId> {
        self.canonical_storage_by_var.get(var).copied()
    }

    /// Get the number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Get the CFG.
    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    /// Get mutable access to the CFG.
    pub fn cfg_mut(&mut self) -> &mut CFG {
        self.invalidate_query_index();
        self.decompile_prep_facts = None;
        &mut self.cfg
    }

    /// Get the dominator tree.
    pub fn domtree(&self) -> &DomTree {
        &self.domtree
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

        let block_count = self.num_blocks().max(self.cfg.block_addrs().count());

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

    /// Remove a block from SSA and CFG.
    pub fn remove_block(&mut self, addr: u64) {
        self.blocks.retain(|block| block.addr != addr);
        self.block_order.retain(|&a| a != addr);
        self.block_index = block_index_of(&self.blocks);
        self.cfg.remove_block(addr);
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Remove phi sources for a specific predecessor edge.
    pub fn remove_phi_source(&mut self, block_addr: u64, pred_addr: u64) {
        if let Some(block) = self.get_block_mut(block_addr) {
            for phi in &mut block.phis {
                phi.sources.retain(|(pred, _)| *pred != pred_addr);
            }
        }
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Recompute cached metadata after CFG mutation.
    /// Put the blocks back in the order `block_order` states, and reindex.
    fn reorder_blocks(&mut self) {
        let mut ordered = Vec::with_capacity(self.block_order.len());
        for &addr in &self.block_order {
            if let Some(position) = self.blocks.iter().position(|block| block.addr == addr) {
                ordered.push(self.blocks.swap_remove(position));
            }
        }
        self.blocks = ordered;
        self.block_index = block_index_of(&self.blocks);
    }

    pub fn refresh_after_cfg_mutation(&mut self) {
        self.blocks
            .retain(|block| self.cfg.get_block(block.addr).is_some());
        self.block_order = self.cfg.reverse_postorder();
        self.reorder_blocks();
        self.domtree = DomTree::compute(&self.cfg);
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Iterate over all SSA operations in the function.
    pub fn all_ops(&self) -> impl Iterator<Item = &SSAOp> {
        self.blocks.iter().flat_map(|b| b.ops.iter())
    }

    /// Iterate over all phi nodes in the function.
    pub fn all_phis(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks.iter().flat_map(|b| b.phis.iter())
    }

    /// Get all variables defined in this function.
    pub fn defined_vars(&self) -> Vec<SSAVar> {
        let mut vars = Vec::new();

        // Collect from phi nodes
        for phi in self.all_phis() {
            vars.push(phi.dst.clone());
        }

        // Collect from operations
        for op in self.all_ops() {
            if let Some(dst) = op.dst() {
                vars.push(dst.clone());
            }
        }

        vars
    }

    /// Get all variables used in this function.
    pub fn used_vars(&self) -> Vec<SSAVar> {
        let mut vars = Vec::new();

        // Collect from phi nodes
        for phi in self.all_phis() {
            for (_, var) in &phi.sources {
                vars.push(var.clone());
            }
        }

        // Collect from operations
        for op in self.all_ops() {
            for src in op.sources() {
                vars.push(src.clone());
            }
        }

        vars
    }

    /// Find the definition of a variable.
    ///
    /// Returns the block address and operation index where the variable is defined.
    pub fn find_def(&self, var: &SSAVar) -> Option<(u64, DefLocation)> {
        self.ensure_query_index();
        self.query_index
            .read()
            .expect("SSA query index lock poisoned")
            .as_ref()
            .and_then(|index| index.find_def(&self.blocks, var))
    }

    /// Find all uses of a variable.
    ///
    /// Returns a list of (block address, use location) pairs.
    pub fn find_uses(&self, var: &SSAVar) -> Vec<(u64, UseLocation)> {
        self.ensure_query_index();
        self.query_index
            .read()
            .expect("SSA query index lock poisoned")
            .as_ref()
            .map(|index| index.find_uses(&self.blocks, var))
            .unwrap_or_default()
    }

    /// Return whether a value reaches any use other than a pure SSA carrier.
    ///
    /// Copy destinations and phi destinations are followed transitively. This
    /// makes dead carrier cycles removable without relying on register names,
    /// while conservatively treating malformed use locations as meaningful.
    pub fn has_noncarrier_use(&self, var: &SSAVar) -> bool {
        let mut pending = vec![var.clone()];
        let mut visited = HashSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            for (block_addr, location) in self.find_uses(&current) {
                let Some(block) = self.get_block(block_addr) else {
                    return true;
                };
                let carrier = match location {
                    UseLocation::Phi { phi_idx, .. } => {
                        block.phis.get(phi_idx).map(|phi| phi.dst.clone())
                    }
                    UseLocation::Op { op_idx, .. } => {
                        block.ops.get(op_idx).and_then(|op| match op {
                            SSAOp::Copy { dst, .. } => Some(dst.clone()),
                            _ => None,
                        })
                    }
                };
                let Some(carrier) = carrier else {
                    return true;
                };
                pending.push(carrier);
            }
        }
        false
    }

    /// Iterate over all source uses in all blocks.
    pub fn for_each_source<F: FnMut(u64, SourceRef<'_>)>(&self, mut f: F) {
        for block in self.blocks() {
            block.for_each_source(|src| f(block.addr, src));
        }
    }

    /// Iterate over all definitions in all blocks.
    pub fn for_each_def<F: FnMut(u64, DefRef<'_>)>(&self, mut f: F) {
        for block in self.blocks() {
            block.for_each_def(|def| f(block.addr, def));
        }
    }

    /// Compute a backward slice for a sink variable.
    pub fn backward_slice(&self, sink: &SSAVar) -> BackwardSlice {
        backward_slice_from_var(self, sink)
    }

    /// Seal-check the complete SSA definition/use, phi, storage, and width contract.
    #[expect(
        clippy::result_large_err,
        reason = "the public validator returns the exact typed SSA failure; validation is an artifact-boundary operation"
    )]
    pub fn validate_integrity(&self) -> Result<(), SsaIntegrityError> {
        validate_ssa_function(self)
    }

    /// Compute a backward slice starting from an SSA operation.
    pub fn backward_slice_from_op(&self, block_addr: u64, op_idx: usize) -> BackwardSlice {
        backward_slice_from_op(self, SliceOpRef::Op { block_addr, op_idx })
    }

    /// Compute a backward slice starting from a phi node.
    pub fn backward_slice_from_phi(&self, block_addr: u64, phi_idx: usize) -> BackwardSlice {
        backward_slice_from_op(
            self,
            SliceOpRef::Phi {
                block_addr,
                phi_idx,
            },
        )
    }

    /// Run SSA optimizations on this function.
    pub fn optimize(
        &mut self,
        config: &crate::optimize::OptimizationConfig,
    ) -> crate::optimize::OptimizationStats {
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
        crate::optimize::optimize_function(self, config)
    }

    /// Prepare SSA for decompilation using provenance-preserving defaults.
    pub fn prepare_for_decompile(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
    ) -> crate::optimize::OptimizationStats {
        self.prepare_for_decompile_with_control(config, &UncheckedSsaWorkControl)
            .expect("unchecked decompiler preparation cannot stop")
    }

    fn prepare_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
        control: &C,
    ) -> Result<crate::optimize::OptimizationStats, SsaExecutionStopReason> {
        self.prepare_for_decompile_with_interface_and_control(config, None, control)
    }

    fn prepare_for_decompile_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<crate::optimize::OptimizationStats, SsaExecutionStopReason> {
        control.poll()?;
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
        let cfg: crate::optimize::OptimizationConfig = config.into();
        crate::optimize::optimize_function_with_interface_and_control(
            self,
            &cfg,
            function_interface,
            control,
        )
    }

    /// Snapshot the current decompiler-prep fact view, if available.
    pub fn decompile_prep_facts(&self) -> Option<&DecompilePrepFacts> {
        self.decompile_prep_facts.as_ref()
    }

    /// Install the canonical source-boundary parameter projection into the
    /// decompiler preparation view. This deliberately accepts `ValueId`
    /// facts, then resolves the already-built graph value back to its `SSAVar`;
    /// no register spelling participates in slot identity.
    /// The storage an entry-lane projection stands for.
    pub fn formal_projection_storage(&self, var: &SSAVar) -> Option<CanonicalStorageId> {
        self.formal_projections.get(var).copied()
    }

    pub(crate) fn formal_projection_vars(
        &self,
    ) -> impl Iterator<Item = (&SSAVar, &CanonicalStorageId)> {
        self.formal_projections.iter()
    }

    /// Give every lane of a register read as the function was entered with it
    /// one value: a `Subpiece` of the root's entry value, defined at entry.
    ///
    /// A formal declared narrower than its carrier is such a lane whether or
    /// not the body reads it, so it is minted from the interface; every other
    /// entry-lane read the renamer produced -- one `Subpiece` per reading
    /// instruction -- becomes a copy of the one projection. The projection has
    /// no register storage of its own: it is a temporary the boundary facts
    /// know by this table (doc/adr-register-identity.md §8, 6).
    /// Start a scratch register's lane writes from zero rather than from what
    /// the caller left in it.
    ///
    /// A lane written into a register the function never read is not
    /// preserving anything: `pinsrd xmm3, eax, 0` into a register no earlier
    /// instruction defined reads bits the caller happened to leave, and no
    /// compiled program depends on them. The insert still needs a value to
    /// build on, and C has to spell it, so where the root's entry value is
    /// read by nothing but the inserts themselves -- and the convention names
    /// no carrier there, so nobody passed anything in it -- the chain starts
    /// at zero and the rendering has no uninitialised read.
    fn zero_scratch_insert_roots(&mut self, abi_carriers: &[CanonicalStorageId]) {
        // A candidate's bits reach nothing but inserts. A merge passes the
        // same undefined bits along, so a use as a phi source is followed to
        // that merge and asked the same question; any other read -- a spill of
        // a callee-saved register, a return of an untouched argument -- is a
        // use of what the caller left, and disqualifies it.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum ScratchUse {
            InsertSource,
            Carried,
            Observed,
        }
        let mut uses = BTreeMap::<SSAVar, Vec<(ScratchUse, SSAVar)>>::new();
        for block in self.blocks.iter() {
            for phi in &block.phis {
                for (_, src) in &phi.sources {
                    uses.entry(src.clone())
                        .or_default()
                        .push((ScratchUse::Carried, phi.dst.clone()));
                }
            }
            for op in &block.ops {
                if let SSAOp::Insert(insert) = op {
                    let (src, value, position) = (&insert.src, &insert.value, &insert.position);
                    uses.entry(src.clone())
                        .or_default()
                        .push((ScratchUse::InsertSource, src.clone()));
                    for other in [value, position] {
                        uses.entry((*other).clone())
                            .or_default()
                            .push((ScratchUse::Observed, (*other).clone()));
                    }
                } else {
                    for src in op.sources() {
                        uses.entry(src.clone())
                            .or_default()
                            .push((ScratchUse::Observed, src.clone()));
                    }
                }
            }
        }
        let reaches_inserts_only = |start: &SSAVar| {
            let mut pending = vec![start.clone()];
            let mut seen = BTreeSet::new();
            let mut inserted = false;
            while let Some(var) = pending.pop() {
                if !seen.insert(var.clone()) {
                    continue;
                }
                for (kind, next) in uses.get(&var).into_iter().flatten() {
                    match kind {
                        ScratchUse::InsertSource => inserted = true,
                        ScratchUse::Carried => pending.push(next.clone()),
                        ScratchUse::Observed => return false,
                    }
                }
            }
            inserted
        };
        let scratch = uses
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|var| var.version == 0 && reaches_inserts_only(var))
            .filter_map(|var| {
                let storage = self.canonical_storage_by_var.get(&var).copied()?;
                (storage.space == CanonicalStorageSpace::Register
                    && !abi_carriers.iter().any(|carrier| {
                        carrier.space == storage.space
                            && carrier.offset < storage.offset + u64::from(storage.size)
                            && storage.offset < carrier.offset + u64::from(carrier.size)
                    }))
                .then_some(var)
            })
            .collect::<BTreeSet<_>>();
        if scratch.is_empty() {
            return;
        }
        // A vector register is wider than any C constant, so its zero is the
        // zero-extension of a narrow one -- the same operation the prelude
        // spells for every other wide value.
        let mut minted = Vec::new();
        let zeros = scratch
            .iter()
            .map(|var| {
                let zero = if var.size <= 16 {
                    SSAVar::constant(0, var.size)
                } else {
                    let disambiguator = self
                        .canonical_storage_by_var
                        .keys()
                        .filter(|other| other.name() == var.name())
                        .map(SSAVar::rename_disambiguator)
                        .max()
                        .map_or(1, |max| max + 1);
                    // Version one: it is a definition, and version zero is
                    // reserved for the value a block was entered with.
                    let zero = SSAVar::new(var.name(), 1, var.size)
                        .with_rename_disambiguator(disambiguator);
                    minted.push(SSAOp::IntZExt {
                        dst: zero.clone(),
                        src: SSAVar::constant(0, 4),
                    });
                    if let Some(storage) = self.canonical_storage_by_var.get(var).copied() {
                        self.canonical_storage_by_var.insert(zero.clone(), storage);
                    }
                    zero
                };
                (var.clone(), zero)
            })
            .collect::<BTreeMap<_, _>>();
        for block in self.blocks.iter_mut() {
            for phi in &mut block.phis {
                for (_, src) in &mut phi.sources {
                    if let Some(zero) = zeros.get(src) {
                        *src = zero.clone();
                    }
                }
            }
            for op in &mut block.ops {
                if let SSAOp::Insert(insert) = op
                    && let Some(zero) = zeros.get(&insert.src)
                {
                    insert.src = zero.clone();
                }
            }
        }
        if let Some(entry) = self.get_block_mut(self.entry) {
            entry.ops.splice(0..0, minted);
        }
        self.invalidate_query_index();
    }

    /// Replace the direction flag's entry value with the zero the convention
    /// requires of it.
    ///
    /// A repeated string instruction reads the flag to decide which way it
    /// walks, and no compiled function sets it -- the corpus contains no `cld`
    /// or `std` at all -- so what it holds where the instruction reads it is
    /// whatever the caller left. Both x86 ABIs require the caller to leave it
    /// clear, on entry and at every call, and that is the whole of what makes
    /// the direction knowable. Substituting the constant here rather than
    /// reading the fact at the rendering is what lets the arithmetic beside the
    /// transfer fold: the instruction's own pointer updates are written over
    /// the flag, and with it a constant they collapse to the extent.
    ///
    /// Nothing is substituted for a convention that states no such thing, or a
    /// machine with no such flag, and a function that writes the flag itself
    /// has a later version the entry value does not reach.
    pub(crate) fn apply_convention_cleared_direction_flag(
        &mut self,
        machine_context: &SourceMachineContext,
    ) {
        let clears = machine_context
            .convention_slots()
            .is_some_and(|slots| slots.abi_class().clears_direction_flag_on_entry());
        let Some(storage) = machine_context.machine_roles().direction_flag_storage() else {
            return;
        };
        if !clears {
            return;
        }
        let entry_values = self
            .canonical_storage_by_var
            .iter()
            .filter(|(var, var_storage)| var.version == 0 && **var_storage == storage)
            .map(|(var, _)| var.clone())
            .collect::<BTreeSet<_>>();
        if entry_values.is_empty() {
            return;
        }
        r2il::refusal_evidence!(
            "direction-flag-cleared",
            "the convention clears {storage:?} on entry; {} entry reads become zero",
            entry_values.len()
        );
        let substitute = |var: &SSAVar| {
            if entry_values.contains(var) {
                SSAVar::constant(0, var.size)
            } else {
                var.clone()
            }
        };
        for block in self.blocks.iter_mut() {
            for phi in &mut block.phis {
                for (_, src) in &mut phi.sources {
                    *src = substitute(src);
                }
            }
            for op in &mut block.ops {
                *op = crate::optimize::map_sources_in_op(op, &substitute);
            }
        }
        self.invalidate_query_index();
    }

    pub(crate) fn mint_entry_lane_projections(&mut self, machine_context: &SourceMachineContext) {
        let is_root_entry = |var: &SSAVar, storage: Option<CanonicalStorageId>| {
            var.version == 0
                && storage.is_some_and(|storage| {
                    storage.space == CanonicalStorageSpace::Register && storage.size == var.size
                })
        };
        // Lane key: (root storage, byte offset in the root, width) -> the root's
        // entry variable and the reads to fold into the projection.
        // Lane key: (root storage, byte offset in the root, width) -> the root's
        // entry variable and the reads inside the lane, each with its offset
        // from the lane's start.
        let mut lanes = BTreeMap::<
            (CanonicalStorageId, u32, u32),
            (Option<SSAVar>, Vec<(u64, usize, u32)>),
        >::new();
        // The entry registers the renamer read whole: a formal inside one of
        // them is a lane of that root, whatever width the convention names
        // it at -- `d1` is a lane of `z1` as much as `edi` is one of `rdi`.
        let entry_roots = self
            .canonical_storage_by_var
            .iter()
            .filter(|(var, storage)| {
                var.version == 0
                    && storage.space == CanonicalStorageSpace::Register
                    && storage.size == var.size
            })
            .map(|(_, storage)| *storage)
            .collect::<Vec<_>>();
        for projection in crate::semantic::source_formal_parameter_projections(machine_context) {
            let lane = projection.graph_storage;
            let root = entry_roots
                .iter()
                .copied()
                .find(|root| {
                    *root != lane
                        && root.offset <= lane.offset
                        && lane.offset + u64::from(lane.size) <= root.offset + u64::from(root.size)
                })
                .unwrap_or(projection.abi_storage);
            if root == lane {
                continue;
            }
            let Some(offset) = lane
                .offset
                .checked_sub(root.offset)
                .and_then(|offset| u32::try_from(offset).ok())
            else {
                continue;
            };
            r2il::refusal_evidence!(
                "entry-lane",
                "formal {} lane {:?} of root {:?}",
                projection.index,
                lane,
                root
            );
            lanes.entry((root, offset, lane.size)).or_default();
        }
        if lanes.is_empty() {
            return;
        }
        // Only a lane the interface declares is a formal; any other lane read
        // of an entry root stays the `Subpiece` of the caller's value it is.
        for addr in self.block_order.clone() {
            let Some(block) = self.get_block(addr) else {
                continue;
            };
            for (op_index, op) in block.ops.iter().enumerate() {
                let SSAOp::Subpiece { dst, src, offset } = op else {
                    continue;
                };
                let storage = self.canonical_storage_by_var.get(src).copied();
                if !is_root_entry(src, storage) {
                    continue;
                }
                let Some(root) = storage else {
                    continue;
                };
                // A read inside a declared lane reads the formal, whether it
                // is the whole lane or a byte of it.
                let Some((key, inside)) = lanes.keys().find_map(|key| {
                    (key.0 == root && key.1 <= *offset && *offset + dst.size <= key.1 + key.2)
                        .then_some((*key, *offset - key.1))
                }) else {
                    r2il::refusal_evidence!(
                        "entry-lane",
                        "({addr:#x}, {op_index}) reads {offset}+{} of entry root {:?}, no declared lane",
                        dst.size,
                        root
                    );
                    continue;
                };
                let lane = lanes.get_mut(&key).expect("a key just found");
                lane.0.get_or_insert_with(|| src.clone());
                lane.1.push((addr, op_index, inside));
            }
        }
        let mut minted = Vec::new();
        // Each root's declared lanes, to rebuild the root from them below.
        let mut lanes_by_root = BTreeMap::<SSAVar, (CanonicalStorageId, Vec<(SSAVar, u32)>)>::new();
        for ((root, offset, width), (root_var, reads)) in lanes {
            // The root's entry value is the renamer's, when it named one; a
            // fresh name would enter the family a second time.
            let root_var = root_var
                .or_else(|| {
                    self.canonical_storage_by_var
                        .iter()
                        .find(|(var, storage)| var.version == 0 && **storage == root)
                        .map(|(var, _)| var.clone())
                })
                .unwrap_or_else(|| {
                    let name = machine_context
                        .register_name(root)
                        .unwrap_or_else(|| format!("reg:{:x}", root.offset));
                    SSAVar::initial(name, root.size)
                });
            let lane_storage = CanonicalStorageId {
                space: CanonicalStorageSpace::Register,
                offset: root.offset + u64::from(offset),
                size: width,
            };
            // The formal is named as the lane register the caller filled, the
            // way an entry value is named after its register.
            let name = machine_context
                .register_name(lane_storage)
                .map(|name| name.to_ascii_uppercase())
                .unwrap_or_else(|| format!("reg:{:x}:{width}", lane_storage.offset));
            let projection = SSAVar::new(name, 0, width);
            self.canonical_storage_by_var
                .entry(root_var.clone())
                .or_insert(root);
            self.formal_projections
                .insert(projection.clone(), lane_storage);
            for (addr, op_index, inside) in reads {
                if let Some(block) = block_at_mut(&self.block_index, &mut self.blocks, addr)
                    && let Some(SSAOp::Subpiece { dst, .. }) = block.ops.get(op_index)
                {
                    let dst = dst.clone();
                    block.ops[op_index] = if inside == 0 && dst.size == width {
                        SSAOp::Copy {
                            dst,
                            src: projection.clone(),
                        }
                    } else {
                        SSAOp::Subpiece {
                            dst,
                            src: projection.clone(),
                            offset: inside,
                        }
                    };
                }
            }
            lanes_by_root
                .entry(root_var.clone())
                .or_insert((root, Vec::new()))
                .1
                .push((projection.clone(), offset));
            minted.push(SSAOp::Subpiece {
                dst: projection,
                src: root_var,
                offset,
            });
        }
        // The caller's root is its formals: a read of the whole register --
        // a merge input, a spill -- takes the declared lanes with zero above
        // them, so no rendering reads a register byte no formal names.
        //
        // The bytes above a declared lane are not the caller's to describe.
        // The declaration is the source's own statement of what it passed, so
        // no source expression names them, and where the interface was
        // recovered rather than declared they are exactly the bytes no
        // observation reached -- which is why the recovery declared the lane
        // narrow in the first place. Either way nothing the program computes
        // depends on them, and zero is as good a value as the register held.
        // Every variable the body reads, and the highest disambiguator each
        // name carries. Both were asked once per root, and each asking walked
        // the whole function, so a body with many entry registers paid for it
        // as many times over.
        let mut read_anywhere = BTreeSet::<SSAVar>::new();
        for block in self.blocks.iter() {
            for phi in &block.phis {
                read_anywhere.extend(phi.sources.iter().map(|(_, src)| src.clone()));
            }
            for op in &block.ops {
                read_anywhere.extend(op.sources().into_iter().cloned());
            }
        }
        let mut highest_disambiguator = BTreeMap::<String, u32>::new();
        for var in self.canonical_storage_by_var.keys() {
            let entry = highest_disambiguator
                .entry(var.name().to_string())
                .or_insert(0);
            *entry = (*entry).max(var.rename_disambiguator());
        }
        let mut substitutions = BTreeMap::<SSAVar, SSAVar>::new();
        for (root_var, (root, lanes)) in lanes_by_root {
            // Only for a root a C integer can hold; a vector register's
            // lanes are not parameters and have no declaration to rest on.
            if root.size > 8 {
                continue;
            }
            if !read_anywhere.contains(&root_var) {
                continue;
            }
            let disambiguator = highest_disambiguator
                .get(root_var.name())
                .map_or(1, |max| max + 1);
            let composed =
                SSAVar::new(root_var.name(), 0, root.size).with_rename_disambiguator(disambiguator);
            match lanes.as_slice() {
                [(lane, 0)] if lane.size < root.size => minted.push(SSAOp::IntZExt {
                    dst: composed.clone(),
                    src: lane.clone(),
                }),
                _ => {
                    let mut carried = SSAVar::constant(0, root.size);
                    for (index, (lane, offset)) in lanes.iter().enumerate() {
                        let dst = if index + 1 == lanes.len() {
                            composed.clone()
                        } else {
                            SSAVar::new(
                                format!("tmp:root:{}:{index}", root_var.name()),
                                1,
                                root.size,
                            )
                        };
                        minted.push(SSAOp::Insert(Box::new(crate::op::InsertOp {
                            dst: dst.clone(),
                            src: carried,
                            value: lane.clone(),
                            position: SSAVar::constant(u64::from(*offset) * 8, 4),
                        })));
                        carried = dst;
                    }
                }
            }
            highest_disambiguator.insert(composed.name().to_string(), disambiguator);
            self.canonical_storage_by_var.insert(composed.clone(), root);
            substitutions.insert(root_var, composed);
        }
        // One walk for every root. Each root substitutes one variable, and
        // rewriting the body once per root read every operation R times to do
        // R independent substitutions; no root's replacement is another
        // root's key, because each composed variable is minted here.
        if !substitutions.is_empty() {
            let replace = |var: &SSAVar| {
                substitutions
                    .get(var)
                    .cloned()
                    .unwrap_or_else(|| var.clone())
            };
            for block in self.blocks.iter_mut() {
                for phi in &mut block.phis {
                    for (_, src) in &mut phi.sources {
                        *src = replace(src);
                    }
                }
                for op in &mut block.ops {
                    *op = crate::optimize::map_sources_in_op(op, &replace);
                }
            }
        }
        if let Some(entry) = block_at_mut(&self.block_index, &mut self.blocks, self.entry) {
            entry.ops.splice(0..0, minted);
        }
        self.invalidate_query_index();
    }

    fn install_exact_formal_parameters(
        &mut self,
        graph: &SsaGraph,
        parameters: &BTreeMap<u32, crate::semantic::SourceFormalParameterFact>,
    ) {
        let Some(prep) = self.decompile_prep_facts.as_mut() else {
            return;
        };
        prep.formal_parameters.clear();
        prep.formal_parameter_bases.clear();
        for (slot, parameter) in parameters {
            let Ok(index) = usize::try_from(*slot) else {
                continue;
            };
            let Some(value) = graph.value(parameter.value) else {
                continue;
            };
            let entry_value = graph.def_inst(parameter.value).is_none()
                && value.var.version == 0
                && value.var.size == parameter.graph_storage.size
                && value.canonical_storage == Some(parameter.graph_storage);
            let projection =
                graph.formal_projection_storage(parameter.value) == Some(parameter.graph_storage);
            if parameter.index != *slot || !(entry_value || projection) {
                continue;
            }
            prep.formal_parameters.insert(value.var.clone(), index);
            if parameter.graph_storage == parameter.abi_storage {
                prep.formal_parameter_bases.insert(value.var.clone(), index);
            }
        }
    }

    /// Record every value that is a formal parameter, and which one.
    ///
    /// A formal reaches its uses through more than the storage it entered in:
    /// a copy, a widening, a lane projection and the reload of the slot the
    /// prologue spilled it to all deliver the same value. Four call sites each
    /// answered that question with their own partial walk, and none of them
    /// reached the reload. The address facts already answer it exactly -- they
    /// seed from the ABI storages and propagate through those steps, across
    /// the frame included -- so a value is the formal when its parameter
    /// expression names one with nothing added to it. What
    /// `install_exact_formal_parameters` proved is authoritative and is not
    /// overwritten here.
    fn install_formal_parameter_identity(
        &mut self,
        graph: &SsaGraph,
        addresses: &crate::AddressProvenanceFacts,
    ) {
        let Some(prep) = self.decompile_prep_facts.as_mut() else {
            return;
        };
        let exact = prep.formal_parameters.len();
        for (value, expression) in &addresses.parameter_expressions {
            if !expression.terms.is_empty() || expression.offset != 0 {
                continue;
            }
            let Some(var) = graph.value(*value).map(|value| value.var.clone()) else {
                continue;
            };
            prep.formal_parameters
                .entry(var)
                .or_insert(expression.parameter);
        }
        r2il::refusal_evidence!(
            "formal-identity",
            "{} values are a formal, {exact} of them proved at entry, from {} parameter expressions",
            prep.formal_parameters.len(),
            addresses.parameter_expressions.len()
        );
    }

    /// Refresh the cached decompiler-prep facts for the current SSA state.
    pub fn refresh_decompile_prep_facts(&mut self) {
        self.refresh_decompile_prep_facts_with_interface_and_control(
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("unchecked decompiler fact collection cannot stop");
    }

    fn refresh_decompile_prep_facts_with_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        self.refresh_decompile_prep_facts_with_interface_and_control(None, control)
    }

    fn refresh_decompile_prep_facts_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        let facts = self.collect_decompile_prep_facts_with_control(function_interface, control)?;
        control.poll()?;
        self.decompile_prep_facts = Some(facts);
        Ok(())
    }

    fn collect_decompile_prep_facts_with_control<C: SsaWorkControl + ?Sized>(
        &self,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<DecompilePrepFacts, SsaExecutionStopReason> {
        control.poll()?;
        // A call only threatens entry-relative facts if it can leave the stack
        // and frame carriers changed. The convention states which carriers a
        // callee restores, and the source now carries that statement, so a
        // direct or indirect call is no longer a reason to withhold every
        // entry-relative fact from the function that makes one.
        //
        // Operations whose effect the model does not describe are a different
        // matter: nothing says what they leave behind, so they still stop this.
        // The convention fact the source published, and only then the
        // interface's copy of it.
        //
        // radare2 determines whether a call preserves the frame carriers from
        // the calling convention, and records it even for a function whose
        // signature it never linked -- deliberately, so signatureless functions
        // keep their entry-relative facts. It travels beside the machine roles
        // because the interface block is withheld for exactly those functions;
        // when it is withheld the interface still arrives, reconstructed with
        // both flags defaulted to false. Asking the interface first therefore
        // asked the answerer that does not know, and every function that calls
        // lost every fact about its own frame: no stack roots, so no
        // certificate that a slot is its own, so its dead spills could not be
        // dropped and rendered as variables set and never used.
        // Each half asked of the answerer that knows it, so the two questions
        // cannot drift apart from the one SSA construction already asked about
        // the stack pointer.
        let call_carriers_are_restored =
            stack_pointer_restored_across_calls(self.call_preserved_carriers, function_interface)
                && frame_pointer_restored_across_calls(
                    self.call_preserved_carriers,
                    function_interface,
                );
        // A user operation writes only its output varnode, so one whose output
        // is not a frame carrier -- a NEON reduction into a vector register --
        // leaves the entry-relative facts standing; one without an output, a
        // syscall, may have done anything.
        let frame_carriers = [
            self.stack_pointer_carrier(),
            function_interface.and_then(SourceFunctionInterface::frame_pointer_storage),
        ];
        let writes_no_frame_carrier = |output: &Option<SSAVar>| {
            output.as_ref().is_some_and(|dst| {
                self.canonical_storage_for_var(dst).is_none_or(|storage| {
                    !frame_carriers.iter().flatten().any(|carrier| {
                        crate::semantic::register_storages_overlap(storage, *carrier)
                    })
                })
            })
        };
        let entry_stack_roots_are_stable = self.blocks().iter().all(|block| {
            block.ops.iter().all(|op| match op {
                SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. } => call_carriers_are_restored,
                SSAOp::CallOther { output, .. } => writes_no_frame_carrier(output),
                SSAOp::Unimplemented | SSAOp::CpuId { .. } | SSAOp::New { .. } => false,
                _ => true,
            })
        });
        let mut facts = DecompilePrepFacts::default();
        let mut declared_stack_bases = BTreeMap::new();
        let mut entry_stack_address_size = None;
        // The stack pointer is a machine fact: the roles name it for every
        // function, and the entry-relative position of anything derived from
        // it does not wait on a linked signature or exact slot roles. Only the
        // declared slots' bases come from the interface, and only where its
        // roles are exact.
        if let Some(storage) = function_interface
            .and_then(SourceFunctionInterface::stack_pointer_storage)
            .or(self.stack_pointer_carrier)
        {
            declared_stack_bases.insert(storage, StackAddressBase::StackPointer);
            if entry_stack_roots_are_stable {
                entry_stack_address_size = Some(storage.size);
            }
        }
        // A slot's base register is a per-slot fact. Requiring every slot's
        // role to be attributed before believing any slot's base installed no
        // stack bases at all when one local went unclassified, which left
        // every stack address in the function without a root -- and with it
        // every frame object a call takes the address of.
        if let Some(interface) = function_interface.filter(|interface| {
            interface.stack_pointer_storage().is_some()
                && interface.return_address_storage().is_some()
        }) {
            for slot in interface.stack_slots() {
                declared_stack_bases.insert(slot.base_storage(), slot.base());
            }
        }
        for var in self.canonical_storage_by_var.keys() {
            if var.version != 0 {
                continue;
            }
            let Some(storage) = self.canonical_storage_for_var(var) else {
                continue;
            };
            if let Some(base) = declared_stack_bases.get(&storage).copied() {
                facts
                    .stack_address_roots
                    .insert(var.clone(), StackAddressRoot { base, offset: 0 });
                if entry_stack_roots_are_stable && base == StackAddressBase::StackPointer {
                    facts.entry_stack_address_roots.insert(
                        var.clone(),
                        StackAddressRoot {
                            base: StackAddressBase::StackPointer,
                            offset: 0,
                        },
                    );
                }
            }
        }
        self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
        if self.root_realigned_stack_pointer(&mut facts, entry_stack_address_size) {
            self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
        }
        // A stack pointer carried around a loop cannot be rooted by a meet: the
        // phi wants every source rooted, and the back edge derives from the phi,
        // so neither ever starts. Assume the back edge agrees with the sources
        // that are rooted, propagate, and keep the assumption only if the back
        // edge comes back agreeing. An unbalanced loop body disagrees by its own
        // drift and is rejected, which is the same answer the meet gave -- but
        // only for the loops that really drift.
        let mut rejected = BTreeSet::new();
        loop {
            control.poll()?;
            let proven = facts.clone();
            let speculated = self.speculate_loop_carried_stack_roots(&mut facts, &rejected);
            if speculated.is_empty() {
                break;
            }
            self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
            let failed = self.unverified_stack_root_speculations(&facts, &speculated);
            r2il::refusal_evidence!(
                "stack-root-speculation",
                "{:#x}: speculated {:?} failed {:?}",
                self.entry,
                speculated
                    .iter()
                    .map(|(dst, root, entry)| (dst.display_name(), *root, *entry))
                    .collect::<Vec<_>>(),
                failed.iter().map(SSAVar::display_name).collect::<Vec<_>>()
            );
            // A round that holds may make a later merge speculable: the
            // second loop's stack pointer rests on the first loop's, whose
            // root arrived only now. Stopping here left it unrooted.
            if !failed.is_empty() {
                facts = proven;
                rejected.extend(failed);
            }
        }

        control.poll()?;
        Ok(facts)
    }

    /// Root the stack pointer a mask realigned, as an origin of its own.
    ///
    /// `and esp, -16` keeps the pointer and throws away up to fifteen bytes of
    /// where it came from, so no coordinate in the entry frame names it. What
    /// it does name is a frame of its own: every push and every local below it
    /// sits at a distance from the masked pointer the arithmetic states, and
    /// every call in the body finds its outgoing argument area there. Exactly
    /// one realignment is rooted, because two would be two origins nothing
    /// here can tell apart.
    fn root_realigned_stack_pointer(
        &self,
        facts: &mut DecompilePrepFacts,
        entry_stack_address_size: Option<u32>,
    ) -> bool {
        let mut realigned = None;
        for block in self.blocks() {
            for op in &block.ops {
                let SSAOp::IntAnd { dst, a, b } = op else {
                    continue;
                };
                if entry_stack_address_size != Some(dst.size) {
                    continue;
                }
                let a_root = canonical_root_in(&facts.canonical_value_roots, a);
                let b_root = canonical_root_in(&facts.canonical_value_roots, b);
                if !aligns_stack_pointer(a, a_root, b, b_root, &facts.stack_address_roots)
                    && !aligns_stack_pointer(b, b_root, a, a_root, &facts.stack_address_roots)
                {
                    continue;
                }
                if realigned.replace(dst.clone()).is_some() {
                    r2il::refusal_evidence!(
                        "stack-root-realign",
                        "{:#x}: more than one mask realigns the stack pointer",
                        self.entry
                    );
                    return false;
                }
            }
        }
        let Some(dst) = realigned else {
            return false;
        };
        let root = StackAddressRoot {
            base: StackAddressBase::Realigned,
            offset: 0,
        };
        r2il::refusal_evidence!(
            "stack-root-realign",
            "{:#x}: {dst} is the realigned frame's origin",
            self.entry
        );
        insert_stack_root(&mut facts.stack_address_roots, dst.clone(), root);
        insert_stack_root(&mut facts.entry_stack_address_roots, dst, root);
        true
    }

    /// Root the phis whose rooted sources agree, assuming the rest will.
    ///
    /// Returns what was assumed, so a second propagation can judge it. Only a
    /// phi with at least one rooted source and no disagreement among the rooted
    /// ones is a candidate: with nothing known there is nothing to assume.
    fn speculate_loop_carried_stack_roots(
        &self,
        facts: &mut DecompilePrepFacts,
        rejected: &BTreeSet<SSAVar>,
    ) -> Vec<(SSAVar, StackAddressRoot, bool)> {
        let mut speculated = Vec::new();
        for &addr in &self.block_order {
            let Some(block) = self.get_block(addr) else {
                continue;
            };
            for phi in &block.phis {
                if rejected.contains(&phi.dst) {
                    continue;
                }
                for entry in [false, true] {
                    let roots = if entry {
                        &facts.entry_stack_address_roots
                    } else {
                        &facts.stack_address_roots
                    };
                    if roots.contains_key(&phi.dst) {
                        continue;
                    }
                    let known = phi
                        .sources
                        .iter()
                        .filter_map(|(_, source)| {
                            resolve_stack_root(source, &facts.canonical_value_roots, roots)
                        })
                        .collect::<BTreeSet<_>>();
                    let [root] = known.into_iter().collect::<Vec<_>>()[..] else {
                        continue;
                    };
                    speculated.push((phi.dst.clone(), root, entry));
                }
            }
        }
        for (dst, root, entry) in &speculated {
            let roots = if *entry {
                &mut facts.entry_stack_address_roots
            } else {
                &mut facts.stack_address_roots
            };
            insert_stack_root(roots, dst.clone(), *root);
        }
        speculated
    }

    /// The assumptions a second propagation did not bear out.
    ///
    /// A speculation holds when every source of the phi is now rooted and every
    /// one of them agrees with what was assumed.
    fn unverified_stack_root_speculations(
        &self,
        facts: &DecompilePrepFacts,
        speculated: &[(SSAVar, StackAddressRoot, bool)],
    ) -> Vec<SSAVar> {
        let mut failed = Vec::new();
        for &addr in &self.block_order {
            let Some(block) = self.get_block(addr) else {
                continue;
            };
            for phi in &block.phis {
                for (dst, root, entry) in speculated {
                    if *dst != phi.dst {
                        continue;
                    }
                    let roots = if *entry {
                        &facts.entry_stack_address_roots
                    } else {
                        &facts.stack_address_roots
                    };
                    if common_stack_root(&phi.sources, &facts.canonical_value_roots, roots)
                        != Some(*root)
                    {
                        failed.push(phi.dst.clone());
                    }
                }
            }
        }
        failed
    }

    /// Propagate stack-address roots to a fixpoint.
    ///
    /// Separated so it can be re-run: a stack pointer carried around a loop
    /// is rooted only after a speculation, and the speculation is judged by
    /// what a second run of this makes of it.
    fn propagate_stack_roots<C: SsaWorkControl + ?Sized>(
        &self,
        facts: &mut DecompilePrepFacts,
        entry_stack_address_size: Option<u32>,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        let mut changed = true;
        while changed {
            control.poll()?;
            changed = false;
            for &addr in &self.block_order {
                control.poll()?;
                let Some(block) = self.get_block(addr) else {
                    continue;
                };

                for phi in &block.phis {
                    control.poll()?;
                    // Resolve each source's root once. The three questions
                    // below all read it, and asking each of them separately
                    // walked the root map three times per incoming edge and
                    // copied a variable's name on every walk.
                    let source_roots = phi
                        .sources
                        .iter()
                        .map(|(_, src)| canonical_root_in(&facts.canonical_value_roots, src))
                        .collect::<Vec<_>>();
                    let common = common_root_of(&source_roots).cloned();
                    let stack_root = common_stack_root_of(
                        &phi.sources,
                        &source_roots,
                        &facts.stack_address_roots,
                    );
                    let entry_stack_root = entry_stack_address_size
                        .is_some_and(|size| {
                            phi.dst.size == size
                                && phi.sources.iter().all(|(_, source)| source.size == size)
                        })
                        .then(|| {
                            common_stack_root_of(
                                &phi.sources,
                                &source_roots,
                                &facts.entry_stack_address_roots,
                            )
                        })
                        .flatten();
                    drop(source_roots);
                    if let Some(root) = common {
                        changed |= insert_canonical_root(
                            &mut facts.canonical_value_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                    if let Some(root) = stack_root {
                        changed |= insert_stack_root(
                            &mut facts.stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                    if let Some(root) = entry_stack_root {
                        changed |= insert_stack_root(
                            &mut facts.entry_stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                }
                for op in &block.ops {
                    control.poll()?;
                    // Each operand's root is resolved once for the questions
                    // below. Asking the helpers to resolve it themselves cost a
                    // walk of the root map and a copy of a variable's name per
                    // question, and a sum asks six.
                    match op {
                        SSAOp::Copy { dst, src }
                        | SSAOp::Cast { dst, src }
                        | SSAOp::CallRestore { dst, src } => {
                            let src_root = canonical_root_in(&facts.canonical_value_roots, src);
                            let stack = stack_root_of(src, src_root, &facts.stack_address_roots);
                            let entry_stack = entry_stack_address_size
                                .is_some_and(|size| dst.size == size && src.size == size)
                                .then(|| {
                                    stack_root_of(src, src_root, &facts.entry_stack_address_roots)
                                })
                                .flatten();
                            let src_root = src_root.clone();
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                src_root,
                            );
                            if let Some(stack_root) = stack {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                            if let Some(stack_root) = entry_stack {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                        }
                        SSAOp::Subpiece { dst, src, .. } => {
                            let src_root = canonical_root_in(&facts.canonical_value_roots, src);
                            let adapted = adapt_root_width(src_root, dst.size)
                                .unwrap_or_else(|| src_root.clone());
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                adapted,
                            );
                        }
                        SSAOp::IntAdd { dst, a, b } => {
                            let a_root = canonical_root_in(&facts.canonical_value_roots, a);
                            let b_root = canonical_root_in(&facts.canonical_value_roots, b);
                            // An exact root is preferred; this records the
                            // object an address is inside when the offset
                            // within it is computed rather than stated.
                            let indexed = (!facts.stack_address_roots.contains_key(dst))
                                .then(|| {
                                    indexed_stack_address_root_from_add(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.stack_address_roots,
                                        &facts.indexed_stack_address_roots,
                                    )
                                })
                                .flatten();
                            let exact = stack_address_root_from_add(
                                a,
                                a_root,
                                b,
                                b_root,
                                &facts.stack_address_roots,
                            );
                            let entry = entry_stack_address_size
                                .is_some_and(|size| {
                                    dst.size == size && a.size == size && b.size == size
                                })
                                .then(|| {
                                    stack_address_root_from_add(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.entry_stack_address_roots,
                                    )
                                })
                                .flatten();
                            if let Some(root) = indexed {
                                changed |= insert_stack_root(
                                    &mut facts.indexed_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = exact {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = entry {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                        }
                        SSAOp::IntSub { dst, a, b } => {
                            let a_root = canonical_root_in(&facts.canonical_value_roots, a);
                            let b_root = canonical_root_in(&facts.canonical_value_roots, b);
                            let exact = stack_address_root_from_sub(
                                a,
                                a_root,
                                b,
                                b_root,
                                &facts.stack_address_roots,
                            );
                            let indexed = (!facts.stack_address_roots.contains_key(dst)
                                && exact.is_none())
                            .then(|| {
                                indexed_stack_address_root_from_sub(
                                    a,
                                    a_root,
                                    b,
                                    b_root,
                                    &facts.indexed_stack_address_roots,
                                )
                            })
                            .flatten();
                            let entry = entry_stack_address_size
                                .is_some_and(|size| {
                                    dst.size == size && a.size == size && b.size == size
                                })
                                .then(|| {
                                    stack_address_root_from_sub(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.entry_stack_address_roots,
                                    )
                                })
                                .flatten();
                            if let Some(root) = exact {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = indexed {
                                changed |= insert_stack_root(
                                    &mut facts.indexed_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = entry {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                        }
                        SSAOp::IntZExt { .. } | SSAOp::IntSExt { .. } => {}
                        _ => {}
                    }

                    if let Some(dst) = op.dst() {
                        changed |= ensure_value_root_identity(
                            &mut facts.canonical_value_roots,
                            dst.clone(),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn ensure_query_index(&self) {
        if self
            .query_index
            .read()
            .expect("SSA query index lock poisoned")
            .is_some()
        {
            return;
        }
        let index = SsaQueryIndex::build(self);
        *self
            .query_index
            .write()
            .expect("SSA query index lock poisoned") = Some(index);
    }

    fn invalidate_query_index(&self) {
        *self
            .query_index
            .write()
            .expect("SSA query index lock poisoned") = None;
    }

    /// Print the function in a human-readable format.
    pub fn dump(&self) -> String {
        dump_blocks(self.name.as_deref(), self.entry, self.blocks(), self)
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

    /// The slot a named register occupies, or `None` when the architecture
    /// does not name it.
    pub fn slot_for_name(&self, name: &str) -> Option<RegisterFamilySlot> {
        let member = self.member_for_name(name)?;
        Some(RegisterFamilySlot {
            family_id: member.family_id,
            offset: member.offset,
            width: member.width,
        })
    }

    /// The widest register containing the named one: the canonical identity of
    /// the family, which every alias of it shares.
    pub fn widest_slot_for_name(&self, name: &str) -> Option<RegisterFamilySlot> {
        self.widest_slot_containing(self.member_for_name(name)?)
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
        let member = self.member_at_offset(offset, size)?;
        let end = offset.saturating_add(u64::from(size));
        let root = self
            .program_roots
            .get(&member.family_id)
            .copied()
            .filter(|root| {
                root.offset <= offset && end <= root.offset.saturating_add(u64::from(root.width))
            })
            .or_else(|| self.widest_slot_containing(member))?;
        (root.offset != offset || root.width != size).then_some(root)
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

fn adapt_root_width(root: &SSAVar, width: u32) -> Option<SSAVar> {
    if root.size == width {
        return (!root.name_kind().is_constant() || root.constant_bits().is_some())
            .then(|| root.clone());
    }
    if let Some(value) = root.constant_bits() {
        return Some(SSAVar::constant(mask_const_to_width(value, width), width));
    }
    if root.size > width && can_width_adapt_root(root) {
        return Some(root.with_size(width));
    }
    None
}

fn can_width_adapt_root(root: &SSAVar) -> bool {
    !root.is_const()
        && !root.is_temp()
        && !matches!(
            root.name_kind(),
            SSAVarNameKind::Memory | SSAVarNameKind::AddressSpace | SSAVarNameKind::Frame
        )
}

fn mask_const_to_width(value: u64, width: u32) -> u64 {
    let bits = width.saturating_mul(8);
    if bits >= 64 {
        value
    } else if bits == 0 {
        0
    } else {
        value & ((1u64 << bits) - 1)
    }
}

fn canonicalize_value_root(root: &SSAVar, roots: &HashMap<SSAVar, SSAVar>) -> SSAVar {
    canonical_root_in(roots, root).clone()
}

fn ensure_value_root_identity(roots: &mut HashMap<SSAVar, SSAVar>, var: SSAVar) -> bool {
    if roots.contains_key(&var) {
        return false;
    }
    roots.insert(var.clone(), var);
    true
}

fn insert_canonical_root(roots: &mut HashMap<SSAVar, SSAVar>, dst: SSAVar, root: SSAVar) -> bool {
    let root = canonicalize_value_root(&root, roots);
    let changed = !matches!(roots.get(&dst), Some(existing) if *existing == root);
    roots.insert(dst, root.clone());
    roots.entry(root.clone()).or_insert(root);
    changed
}

/// The one root every incoming edge already resolved to, if they agree.
fn common_root_of<'a>(roots: &[&'a SSAVar]) -> Option<&'a SSAVar> {
    let first = *roots.first()?;
    roots.iter().all(|root| *root == first).then_some(first)
}

/// The one stack root every incoming edge names, given their resolved roots.
fn common_stack_root_of(
    sources: &[(u64, SSAVar)],
    resolved: &[&SSAVar],
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let of = |index: usize| {
        let (_, source) = sources.get(index)?;
        stack_roots
            .get(source)
            .copied()
            .or_else(|| stack_roots.get(*resolved.get(index)?).copied())
    };
    let first = of(0)?;
    (1..sources.len())
        .all(|index| of(index) == Some(first))
        .then_some(first)
}

fn resolve_stack_root(
    var: &SSAVar,
    roots: &HashMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    // The variable's own answer first. Resolving its canonical root before
    // asking cost a walk and a copy of the root's name on every call, and the
    // root propagation makes three and a half million of them for one
    // five-hundred-block function; the root is only needed when the variable
    // itself has no stack root recorded.
    if let Some(root) = stack_roots.get(var).copied() {
        return Some(root);
    }
    stack_roots.get(canonical_root_in(roots, var)).copied()
}

fn common_stack_root(
    sources: &[(u64, SSAVar)],
    roots: &HashMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let mut iter = sources.iter();
    let (_, first_src) = iter.next()?;
    let first = resolve_stack_root(first_src, roots, stack_roots)?;
    if iter.all(|(_, src)| resolve_stack_root(src, roots, stack_roots) == Some(first)) {
        Some(first)
    } else {
        None
    }
}

/// The stack root a variable names, given the root it already resolved to.
fn stack_root_of(
    var: &SSAVar,
    root: &SSAVar,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    stack_roots
        .get(var)
        .copied()
        .or_else(|| stack_roots.get(root).copied())
}

/// The displacement a variable adds, given the root it already resolved to.
fn signed_stack_delta_of(var: &SSAVar, root: &SSAVar) -> Option<i64> {
    signed_stack_delta(var).or_else(|| (root != var).then(|| signed_stack_delta(root)).flatten())
}

fn stack_address_root_from_add(
    a: &SSAVar,
    a_root: &SSAVar,
    b: &SSAVar,
    b_root: &SSAVar,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    // One side at a time: an operand with no stack root is the ordinary case,
    // and asking for the other side's displacement first cost work for every
    // sum in the function.
    if let Some(base) = stack_root_of(a, a_root, stack_roots)
        && let Some(delta) = signed_stack_delta_of(b, b_root)
    {
        return Some(StackAddressRoot {
            base: base.base,
            offset: base.offset.checked_add(delta)?,
        });
    }
    if let Some(base) = stack_root_of(b, b_root, stack_roots)
        && let Some(delta) = signed_stack_delta_of(a, a_root)
    {
        return Some(StackAddressRoot {
            base: base.base,
            offset: base.offset.checked_add(delta)?,
        });
    }
    None
}

/// The stack object an address is inside when its offset within it is not a
/// constant.
///
/// One operand carries a stack root -- exact, or itself already indexed -- and
/// the other is not a constant the analysis can fold. The sum is therefore
/// inside the same object at an offset nobody knows, which is what an element
/// of an array on the stack is. An operand that *is* a foldable constant is
/// left to `stack_address_root_from_add`, whose answer is stronger.
fn indexed_stack_address_root_from_add(
    a: &SSAVar,
    a_root: &SSAVar,
    b: &SSAVar,
    b_root: &SSAVar,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
    indexed_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let base_of = |var: &SSAVar, root: &SSAVar| {
        stack_root_of(var, root, stack_roots).or_else(|| stack_root_of(var, root, indexed_roots))
    };
    let index_is_opaque = |var: &SSAVar, root: &SSAVar| {
        signed_stack_delta_of(var, root).is_none() && base_of(var, root).is_none()
    };
    if let Some(base) = base_of(a, a_root)
        && index_is_opaque(b, b_root)
    {
        return Some(base);
    }
    if let Some(base) = base_of(b, b_root)
        && index_is_opaque(a, a_root)
    {
        return Some(base);
    }
    // `buf + i + 4` is still inside `buf`, exactly as `buf + i - 3` is: a
    // base that is already indexed stays in its object when a constant
    // displaces it, which is how a machine folds a member's offset into the
    // addressing mode of an indexed access.
    if let Some(base) = stack_root_of(a, a_root, indexed_roots)
        && signed_stack_delta_of(b, b_root).is_some()
    {
        return Some(base);
    }
    if let Some(base) = stack_root_of(b, b_root, indexed_roots)
        && signed_stack_delta_of(a, a_root).is_some()
    {
        return Some(base);
    }
    None
}

/// An address inside an object, taken back by a constant.
///
/// `buf + i - 3` is still inside `buf` at an offset nothing states, exactly as
/// `buf + i` is. Only an already-indexed base qualifies: an exact base less a
/// constant is an exact position and `stack_address_root_from_sub` states it,
/// and an exact base less an opaque amount points below the object.
fn indexed_stack_address_root_from_sub(
    a: &SSAVar,
    a_root: &SSAVar,
    b: &SSAVar,
    b_root: &SSAVar,
    indexed_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let base = stack_root_of(a, a_root, indexed_roots)?;
    signed_stack_delta_of(b, b_root).is_some().then_some(base)
}

/// Whether `mask` aligns a value that is a position in the entry stack frame.
///
/// The mask clears low bits, which is a negative power of two read as a signed
/// displacement. A mask of anything else, or of a pointer already realigned,
/// is not one this can name.
fn aligns_stack_pointer(
    value: &SSAVar,
    value_root: &SSAVar,
    mask: &SSAVar,
    mask_root: &SSAVar,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> bool {
    let Some(base) = stack_root_of(value, value_root, stack_roots) else {
        return false;
    };
    let Some(alignment) = signed_stack_delta_of(mask, mask_root).and_then(i64::checked_neg) else {
        return false;
    };
    base.base == StackAddressBase::StackPointer
        && alignment >= 2
        && alignment.unsigned_abs().is_power_of_two()
}

fn stack_address_root_from_sub(
    a: &SSAVar,
    a_root: &SSAVar,
    b: &SSAVar,
    b_root: &SSAVar,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let base = stack_root_of(a, a_root, stack_roots)?;
    let delta = signed_stack_delta_of(b, b_root)?;
    Some(StackAddressRoot {
        base: base.base,
        offset: base.offset.checked_sub(delta)?,
    })
}

/// The displacement an address computation adds, resolved through copies.
///
/// A displacement does not always arrive as a constant operand. AArch64 Sleigh
/// materialises `add x29, sp, 0x60` as `tmp:A = 0x60; x29 = sp + tmp:A`, so the
/// operand is a temp and the constant is one copy away. Reading only the operand
/// left every frame pointer established that way without a stack root, and with
/// it every address derived from the frame pointer -- which is most of a
/// non-leaf function's locals.
fn signed_stack_delta(var: &SSAVar) -> Option<i64> {
    let value = var.constant_bits()?;
    let bits = var.size.checked_mul(8)?;
    match bits {
        0 => None,
        64 => Some(value as i64),
        1..=63 => {
            let sign = 1u64.checked_shl(bits - 1)?;
            let mask = 1u64.checked_shl(bits)?.wrapping_sub(1);
            let value = value & mask;
            Some(if value & sign == 0 {
                value as i64
            } else {
                (value | !mask) as i64
            })
        }
        _ => None,
    }
}

fn insert_stack_root(
    stack_roots: &mut BTreeMap<SSAVar, StackAddressRoot>,
    dst: SSAVar,
    root: StackAddressRoot,
) -> bool {
    match stack_roots.get(&dst) {
        Some(existing) if *existing == root => false,
        _ => {
            stack_roots.insert(dst, root);
            true
        }
    }
}

/// Location of a variable definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefLocation {
    /// Defined by a phi node at the given index.
    Phi(usize),
    /// Defined by an operation at the given index.
    Op(usize),
}

/// Location of a variable use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UseLocation {
    /// Used in a phi node.
    Phi { phi_idx: usize, src_idx: usize },
    /// Used in an operation.
    Op { op_idx: usize, src_idx: usize },
}

/// The variable a definition site names, read back out of the blocks.
fn defined_var<'a>(blocks: &'a [SSABlock], site: &(u32, DefLocation)) -> Option<&'a SSAVar> {
    let block = blocks.get(site.0 as usize)?;
    match site.1 {
        DefLocation::Phi(phi_idx) => block.phis.get(phi_idx).map(|phi| &phi.dst),
        DefLocation::Op(op_idx) => block.ops.get(op_idx)?.dst(),
    }
}

/// The variable a use site reads, read back out of the blocks.
fn used_var<'a>(blocks: &'a [SSABlock], site: &(u32, UseLocation)) -> Option<&'a SSAVar> {
    let block = blocks.get(site.0 as usize)?;
    match site.1 {
        UseLocation::Phi { phi_idx, src_idx } => block
            .phis
            .get(phi_idx)?
            .sources
            .get(src_idx)
            .map(|(_, src)| src),
        UseLocation::Op { op_idx, src_idx } => {
            block.ops.get(op_idx)?.sources().get(src_idx).copied()
        }
    }
}

impl SsaQueryIndex {
    fn build(function: &SSAFunction) -> Self {
        let blocks = function.blocks();
        let mut defs = Vec::new();
        let mut uses = Vec::new();
        for (index, block) in blocks.iter().enumerate() {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            for (phi_idx, phi) in block.phis.iter().enumerate() {
                defs.push((index, DefLocation::Phi(phi_idx)));
                for src_idx in 0..phi.sources.len() {
                    uses.push((index, UseLocation::Phi { phi_idx, src_idx }));
                }
            }
            for (op_idx, op) in block.ops.iter().enumerate() {
                if op.dst().is_some() {
                    defs.push((index, DefLocation::Op(op_idx)));
                }
                for src_idx in 0..op.sources().len() {
                    uses.push((index, UseLocation::Op { op_idx, src_idx }));
                }
            }
        }
        // Ordered by the variable and then by the site, so a query's range is
        // contiguous and the sites inside it arrive in the order a walk of the
        // blocks would have produced.
        defs.sort_by(|left, right| {
            defined_var(blocks, left)
                .cmp(&defined_var(blocks, right))
                .then_with(|| left.cmp(right))
        });
        uses.sort_by(|left, right| {
            used_var(blocks, left)
                .cmp(&used_var(blocks, right))
                .then_with(|| left.cmp(right))
        });
        Self { defs, uses }
    }

    /// The last site defining `var`, which is the one an insert-ordered map
    /// kept when a malformed function defines a variable twice.
    fn find_def(&self, blocks: &[SSABlock], var: &SSAVar) -> Option<(u64, DefLocation)> {
        let start = self
            .defs
            .partition_point(|site| defined_var(blocks, site) < Some(var));
        let site = self.defs[start..]
            .iter()
            .take_while(|site| defined_var(blocks, site) == Some(var))
            .last()?;
        Some((blocks.get(site.0 as usize)?.addr, site.1))
    }

    fn find_uses(&self, blocks: &[SSABlock], var: &SSAVar) -> Vec<(u64, UseLocation)> {
        let start = self
            .uses
            .partition_point(|site| used_var(blocks, site) < Some(var));
        self.uses[start..]
            .iter()
            .take_while(|site| used_var(blocks, site) == Some(var))
            .filter_map(|site| Some((blocks.get(site.0 as usize)?.addr, site.1)))
            .collect()
    }
}

impl SSABlock {
    /// Visit all phi source variables in deterministic index order.
    pub fn for_each_phi_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis.iter().enumerate() {
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
    pub fn for_each_op_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        for (op_idx, op) in self.ops.iter().enumerate() {
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
    pub fn for_each_source<F: FnMut(SourceRef<'_>)>(&self, mut f: F) {
        self.for_each_phi_source(&mut f);
        self.for_each_op_source(f);
    }

    /// Visit all destination definitions (phis first, then ops) in index order.
    pub fn for_each_def<F: FnMut(DefRef<'_>)>(&self, mut f: F) {
        for (phi_idx, phi) in self.phis.iter().enumerate() {
            f(DefRef {
                var: &phi.dst,
                site: DefSite::Phi { phi_idx },
            });
        }

        for (op_idx, op) in self.ops.iter().enumerate() {
            if let Some(dst) = op.dst() {
                f(DefRef {
                    var: dst,
                    site: DefSite::Op { op_idx },
                });
            }
        }
    }

    /// Get all operations including phi nodes (as SSAOp::Phi).
    pub fn all_ops(&self) -> impl Iterator<Item = SSAOp> + '_ {
        let phi_ops = self.phis.iter().map(|phi| SSAOp::Phi {
            dst: phi.dst.clone(),
            sources: phi.sources.iter().map(|(_, v)| v.clone()).collect(),
        });
        phi_ops.chain(self.ops.iter().cloned())
    }

    /// Check if this block has any phi nodes.
    pub fn has_phis(&self) -> bool {
        !self.phis.is_empty()
    }

    /// Get the number of phi nodes.
    pub fn num_phis(&self) -> usize {
        self.phis.len()
    }

    /// Get the number of operations (excluding phi nodes).
    pub fn num_ops(&self) -> usize {
        self.ops.len()
    }
}

mod forward;

#[cfg(test)]
mod tests;
