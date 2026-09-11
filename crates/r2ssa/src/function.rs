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
use crate::rename::{
    CallBoundaryConfig, CallBoundaryDef, rename_function_with_names_and_call_boundaries_and_control,
};
use crate::semantic::{
    CallResultCertificate, CallSiteFacts, CallSiteId, CallsiteCertificate, MemoryAccessCertificate,
    MemoryDefFact, MemorySSAFacts, MemoryUseFact, ObjectId, ObjectModel, PredicateFacts,
    PreparedFunctionFacts, ReturnValueCertificate, StackReloadSourceCertificate,
    StructuredDataflowFacts,
};
use crate::span::StorageSpans;
use crate::var::{SSAVar, SSAVarNameKind};
use crate::{AssumptionSet, CanonicalStorageId, CanonicalStorageSpace};

/// Switch case information: Vec of (case_value, target_address) pairs and optional default target.
pub type SwitchInfo = (Vec<(u64, u64)>, Option<u64>);

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
    pub canonical_value_roots: BTreeMap<SSAVar, SSAVar>,
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

/// Typed preparation mode for downstream SSA consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionPrepareMode {
    Generic,
    Raw,
    Decompile,
    Patterns,
    DataRefs,
    Symbolic,
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

fn coherent_function_interface(
    machine_context: &SourceMachineContext,
) -> Option<&SourceFunctionInterface> {
    machine_context
        .abi_model()
        .is_coherent()
        .then(|| machine_context.function_interface())
        .flatten()
}

/// Canonical SSA artifact consumed by downstream analysis layers.
#[derive(Debug)]
pub struct SsaArtifact {
    authority: SsaArtifactAuthority,
    provenance: SsaArtifactProvenance,
    function: SSAFunction,
    graph: SsaGraph,
    storage_spans: StorageSpans,
    live_out: crate::liveout::FunctionLiveOut,
    unobserved_merges: crate::deadphi::DeadPhis,
    mode: FunctionPrepareMode,
    facts: PreparedFunctionFacts,
    machine_context: SourceMachineContext,
    aggregate_accesses: AggregateAccessProjectionFacts,
    /// Spellings the source carried for the addresses this function calls.
    ///
    /// Retained rather than recomputed because the snapshot is the only thing
    /// that ever saw them, and it is gone by the time anything renders. No
    /// dataflow, ABI or typing decision reads this; it exists so the renderer
    /// can print `sym.imp.strcmp` where it would otherwise print an address.
    display_names: r2source::DisplayNames,
    /// The names of the architecture's user-defined operations, indexed as
    /// `SSAOp::CallOther` indexes them.
    ///
    /// Retained for the same reason as `display_names`: only the lift ever saw
    /// the architecture, and `SSAOp::CallOther` carries an index alone. An
    /// index is meaningless without the table it came from, and matching on one
    /// would be an architecture-specific constant, so the table travels with
    /// the artifact rather than the renderer guessing.
    user_operations: Arc<[String]>,
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
    GenuineLiftOnly(GenuineLiftedFunctionAuthority),
    TrustedSource(OwnedFunctionSnapshot),
}

/// Opaque certifiable SSA prepared only from a source-retaining trusted lift.
/// Generic/manual [`SsaArtifact`] constructors cannot produce this wrapper.
#[derive(Debug, Clone)]
pub struct TrustedSsaArtifact {
    artifact: Arc<SsaArtifact>,
    lift_authority: GenuineLiftedFunctionAuthority,
    source_blocks: Arc<[R2ILBlock]>,
    arch: ArchSpec,
}

/// See [`SsaArtifact::register_identity_census`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegisterIdentityCensus {
    pub split_entry_families: usize,
}

impl SsaArtifact {
    #[cfg(test)]
    fn new(function: SSAFunction, mode: FunctionPrepareMode) -> Self {
        Self::new_with_context(function, mode, SourceMachineContext::from_blocks(&[], None))
    }

    fn new_with_context(
        function: SSAFunction,
        mode: FunctionPrepareMode,
        machine_context: SourceMachineContext,
    ) -> Self {
        Self::new_with_context_and_control(
            function,
            mode,
            machine_context,
            &UncheckedSsaWorkControl,
        )
        .expect("internal SSA artifact construction requires a validated function")
    }

    fn new_with_context_and_control<C: SsaWorkControl + ?Sized>(
        function: SSAFunction,
        mode: FunctionPrepareMode,
        machine_context: SourceMachineContext,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::new_with_context_control_and_provenance(
            function,
            mode,
            machine_context,
            SsaArtifactProvenance::Manual,
            control,
        )
    }

    fn new_with_context_control_and_provenance<C: SsaWorkControl + ?Sized>(
        mut function: SSAFunction,
        mode: FunctionPrepareMode,
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
        function.mint_entry_lane_projections(&machine_context);
        machine_context.remap_memory_sites_to_prepared(&function);
        let mut graph = SsaGraph::from_function_with_storage(&function);
        crate::semantic::ensure_source_formal_parameter_values(&mut graph, &machine_context);
        let formal_parameters =
            crate::semantic::collect_source_formal_parameter_facts(&graph, &machine_context);
        function.install_exact_formal_parameters(&graph, &formal_parameters);
        let storage_spans = StorageSpans::compute(&function, &graph);
        let graph_built_bytes = r2il::allocation::live_bytes();
        let return_storages = machine_context
            .abi_model()
            .return_registers()
            .iter()
            .map(|slot| slot.storage())
            .collect::<Vec<_>>();
        let live_out =
            crate::liveout::FunctionLiveOut::compute(&function, &graph, &return_storages);
        let facts = PreparedFunctionFacts::collect_with_context(
            &function,
            &graph,
            &storage_spans,
            &AssumptionSet::default(),
            &machine_context,
            "prepare",
        );
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
        let unobserved_merges = crate::deadphi::DeadPhis::find(&graph, &live_out, &facts);
        let aggregate_accesses = collect_aggregate_access_projections(
            &graph,
            &facts.addresses,
            &facts.structured.memory_accesses,
            &machine_context,
        );
        control.poll()?;
        Ok(Self {
            authority: SsaArtifactAuthority::new(),
            provenance,
            function,
            graph,
            storage_spans,
            live_out,
            unobserved_merges,
            mode,
            facts,
            machine_context,
            aggregate_accesses,
            display_names: r2source::DisplayNames::default(),
            user_operations: Arc::from([] as [String; 0]),
        })
    }

    /// Run-local identity shared by every clone and downstream proof derived
    /// from this exact artifact instance.
    pub const fn authority(&self) -> &SsaArtifactAuthority {
        &self.authority
    }

    pub fn provenance_kind(&self) -> SsaArtifactProvenanceKind {
        match &self.provenance {
            SsaArtifactProvenance::Manual => SsaArtifactProvenanceKind::Manual,
            SsaArtifactProvenance::GenuineLiftOnly(_) => SsaArtifactProvenanceKind::GenuineLiftOnly,
            SsaArtifactProvenance::TrustedSource(_) => SsaArtifactProvenanceKind::TrustedSource,
        }
    }

    /// Opaque genuine-lift authority retained by either lifted provenance kind.
    /// Genuine lift authority alone is not sufficient for certification.
    pub fn genuine_lift_authority(&self) -> Option<&GenuineLiftedFunctionAuthority> {
        match &self.provenance {
            SsaArtifactProvenance::Manual => None,
            SsaArtifactProvenance::GenuineLiftOnly(authority) => Some(authority),
            SsaArtifactProvenance::TrustedSource(_) => None,
        }
    }

    pub fn from_blocks(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_with_arch(blocks, arch)?,
            FunctionPrepareMode::Generic,
            SourceMachineContext::from_blocks(blocks, arch),
        ))
    }

    pub fn raw(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_raw(blocks, arch)?,
            FunctionPrepareMode::Raw,
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
            FunctionPrepareMode::Raw,
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
            FunctionPrepareMode::Decompile,
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
        Self::new_with_context_and_control(
            function,
            FunctionPrepareMode::Decompile,
            machine_context,
            control,
        )
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
        Self::for_decompile_with_interfaces_roles_and_convention(
            blocks,
            arch,
            function_interface,
            machine_roles,
            None,
            call_site_interfaces,
        )
    }

    /// The same, describing where the calling convention places arguments.
    ///
    /// The slots are a fact about the convention rather than about this
    /// function, and a variadic call needs them: its prototype names only the
    /// fixed arguments, so where argument `n + 1` would go is a question only
    /// the convention answers.
    pub fn for_decompile_with_interfaces_roles_and_convention(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        convention_slots: Option<SourceConventionSlots>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Option<Self> {
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            blocks,
            arch,
            function_interface,
            machine_roles,
            convention_slots,
            call_site_interfaces,
        );
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                blocks,
                arch,
                coherent_function_interface(&machine_context),
                machine_context.machine_roles().call_preserved_carriers(),
                machine_context.stack_pointer_carrier(),
                &CalleePreservedCarriers::new(),
                None,
                &UncheckedSsaWorkControl,
            )
            .ok()?,
            FunctionPrepareMode::Decompile,
            machine_context,
        ))
    }

    /// Build decompiler-prepared SSA whose machine context also carries the
    /// tail calls the source proved, by call-site identity.
    ///
    /// This is the shape production builds from a capture: a tail call
    /// through a relocated slot is a `BranchInd` the source names as a call
    /// site, and only a context that knows the identity certifies it as one.
    pub fn for_decompile_with_interfaces_and_tail_calls(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        tail_call_identities: Vec<SourceCallSiteIdentity>,
    ) -> Option<Self> {
        Self::for_decompile_with_callee_preserved_carriers(
            blocks,
            arch,
            function_interface,
            call_site_interfaces,
            tail_call_identities,
            &CalleePreservedCarriers::new(),
        )
    }

    /// The same, told which registers each direct callee's body proves it
    /// leaves untouched, so construction defines nothing a call did not touch.
    pub fn for_decompile_with_callee_preserved_carriers(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        tail_call_identities: Vec<SourceCallSiteIdentity>,
        callee_preserved_carriers: &CalleePreservedCarriers,
    ) -> Option<Self> {
        let machine_context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            blocks,
            arch,
            function_interface,
            SourceMachineRoles::default(),
            None,
            call_site_interfaces,
            tail_call_identities,
        );
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                blocks,
                arch,
                coherent_function_interface(&machine_context),
                machine_context.machine_roles().call_preserved_carriers(),
                machine_context.stack_pointer_carrier(),
                callee_preserved_carriers,
                None,
                &UncheckedSsaWorkControl,
            )
            .ok()?,
            FunctionPrepareMode::Decompile,
            machine_context,
        ))
    }

    /// Build controlled decompiler SSA with explicit source interfaces.
    pub fn for_decompile_with_interfaces_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<SourceFunctionInterface>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::for_decompile_with_interfaces_machine_roles_and_control(
            blocks,
            arch,
            function_interface,
            SourceMachineRoles::default(),
            call_site_interfaces,
            control,
        )
    }

    /// Controlled counterpart of
    /// [`Self::for_decompile_with_interfaces_and_machine_roles`].
    pub fn for_decompile_with_interfaces_machine_roles_and_control<C: SsaWorkControl + ?Sized>(
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
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleePreservedCarriers::new(),
            None,
            control,
        )?;
        control.poll()?;
        Self::new_with_context_and_control(
            function,
            FunctionPrepareMode::Decompile,
            machine_context,
            control,
        )
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
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleePreservedCarriers::new(),
            None,
            control,
        )?;
        if function.entry != lifted.authority().layout().entry_addr() {
            return Err(malformed_ssa_input());
        }
        control.poll()?;
        let mut artifact = Self::new_with_context_control_and_provenance(
            function,
            FunctionPrepareMode::Decompile,
            machine_context,
            SsaArtifactProvenance::GenuineLiftOnly(lifted.authority().clone()),
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
            FunctionPrepareMode::Patterns,
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
            FunctionPrepareMode::Patterns,
            SourceMachineContext::from_blocks(blocks, arch),
            control,
        )
    }

    pub fn for_data_refs(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Some(Self::new_with_context(
            SSAFunction::from_blocks_for_data_refs(blocks, arch)?,
            FunctionPrepareMode::DataRefs,
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
            FunctionPrepareMode::Symbolic,
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

    pub fn mode(&self) -> FunctionPrepareMode {
        self.mode
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
        &self.storage_spans
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
        &self.live_out
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
            &self.storage_spans,
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
            storage_spans: self.storage_spans.clone(),
            live_out: self.live_out.clone(),
            unobserved_merges: self.unobserved_merges.clone(),
            mode: self.mode,
            facts,
            machine_context: self.machine_context.clone(),
            aggregate_accesses,
            display_names: self.display_names.clone(),
            user_operations: Arc::clone(&self.user_operations),
        }
    }

    /// Spellings the source carried for the addresses this function calls.
    pub fn display_names(&self) -> &r2source::DisplayNames {
        &self.display_names
    }

    /// The name the architecture gives one of its user-defined operations.
    ///
    /// `None` when the artifact was built without an architecture, or when the
    /// index is outside the table -- both of which mean the operation cannot be
    /// identified and must be refused rather than guessed at.
    pub fn user_operation_name(&self, userop: u32) -> Option<&str> {
        self.user_operations
            .get(userop as usize)
            .map(String::as_str)
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

    pub fn local_ssa_blocks(&self) -> Vec<LocalSSABlock> {
        self.function
            .blocks()
            .map(|block| LocalSSABlock {
                addr: block.addr,
                size: block.size,
                ops: block.ops.clone(),
            })
            .collect()
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
}

fn correlate_call_site_interfaces(
    source: &OwnedFunctionSnapshot,
    blocks: &[R2ILBlock],
    callee_interfaces: &BTreeMap<u64, SourceFunctionInterface>,
) -> CorrelatedCallSites {
    let mut tail_calls = Vec::new();
    let mut interfaces = Vec::new();
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
            if let Some(interface) = crate::recover_interface::mint_recovered_call_site_interface(
                callee,
                identity,
                source.source_revision_identity(),
            ) {
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
        // checked callsite contract, where it can serve as provenance for
        // literal format counting. Missing or ambiguous names stay unknown.
        if prototype.variadic
            && let Some(target_name) = call.target_name()
        {
            let mut signatures =
                source
                    .presentation()
                    .callee_signatures()
                    .iter()
                    .filter(|(name, signature)| {
                        name.as_ref() == target_name
                            && signature.is_variadic()
                            && signature.named_parameters().len() == prototype.arguments.len()
                    });
            if let (Some((_, signature)), None) = (signatures.next(), signatures.next()) {
                let mut formats = signature
                    .named_parameters()
                    .iter()
                    .enumerate()
                    .filter(|(_, parameter)| parameter.name() == Some("format"));
                if let (Some((index, _)), None) = (formats.next(), formats.next())
                    && let Ok(index) = u32::try_from(index)
                    && let Ok(bound) = interface.clone().with_radare2_format_parameter(index)
                {
                    interface = bound;
                }
            }
        }
        interfaces.push(interface);
    }
    CorrelatedCallSites {
        tail_calls,
        interfaces,
    }
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
                let provisional_machine_context =
                    SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
                        blocks.as_slice(),
                        Some(&arch),
                        None,
                        *source.machine_roles(),
                        Some(source.convention_slots().clone()),
                        correlated_call_sites.interfaces.clone(),
                        correlated_call_sites.tail_calls.clone(),
                    );
                let Ok(preliminary) =
                    SSAFunction::from_blocks_for_decompile_with_interface_and_control(
                        &blocks,
                        Some(&arch),
                        None,
                        provisional_machine_context
                            .machine_roles()
                            .call_preserved_carriers(),
                        provisional_machine_context.stack_pointer_carrier(),
                        callee_preserved_carriers,
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
        machine_context.bind_source_string_literals(source.image().string_literals());
        let mut function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            blocks.as_slice(),
            Some(&arch),
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            callee_preserved_carriers,
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
            FunctionPrepareMode::Decompile,
            machine_context,
            SsaArtifactProvenance::TrustedSource(source),
            control,
        )?;
        artifact.display_names = display_names;
        artifact.user_operations = Arc::from(arch.user_ops.clone());
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
            source_blocks: blocks.into(),
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

    /// Exact canonical Sleigh P-code retained from the trusted lift event.
    /// Native spans, including zero-op spans, remain separate source evidence
    /// in the artifact obligation inventory.
    pub fn source_blocks(&self) -> &[R2ILBlock] {
        &self.source_blocks
    }

    /// Architecture extracted from the same embedded trusted Sleigh profile.
    pub const fn arch_spec(&self) -> &ArchSpec {
        &self.arch
    }

    /// Everything this function proves about itself.
    ///
    /// The pointer tables come from the source, which can read memory; the
    /// range of each index comes from the branches that had to be taken to
    /// reach the call. Both are needed, and only here are both in hand.
    pub fn proven_facts(&self) -> crate::proven::ProvenFacts {
        crate::proven::prove(self.artifact(), self.source().image().code_pointer_tables())
    }

    pub fn source(&self) -> &OwnedFunctionSnapshot {
        match &self.artifact.provenance {
            SsaArtifactProvenance::TrustedSource(source) => source,
            SsaArtifactProvenance::Manual | SsaArtifactProvenance::GenuineLiftOnly(_) => {
                unreachable!("TrustedSsaArtifact always retains source provenance")
            }
        }
    }
}

fn canonical_root_value_id(
    prepared: &SsaArtifact,
    value_id: crate::graph::ValueId,
) -> crate::graph::ValueId {
    let Some(facts) = prepared.function().decompile_prep_facts() else {
        return value_id;
    };
    let Some(start) = prepared.value_var(value_id) else {
        return value_id;
    };
    let mut current = start.clone();
    let mut current_id = value_id;
    for _ in 0..32 {
        let Some(next) = facts.canonical_root_of(&current) else {
            break;
        };
        if next == &current {
            break;
        }
        let Some(next_id) = prepared.graph().value_id_for_var(next) else {
            break;
        };
        current = next.clone();
        current_id = next_id;
    }
    current_id
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
    /// SSA operations for each block.
    blocks: HashMap<u64, SSABlock>,
    /// Block addresses in reverse postorder.
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SsaQueryIndex {
    defs: HashMap<SSAVar, (u64, DefLocation)>,
    uses: HashMap<SSAVar, Vec<(u64, UseLocation)>>,
}

impl Clone for SSAFunction {
    fn clone(&self) -> Self {
        Self {
            call_preserved_carriers: self.call_preserved_carriers,
            stack_pointer_carrier: self.stack_pointer_carrier,
            name: self.name.clone(),
            entry: self.entry,
            cfg: self.cfg.clone(),
            domtree: self.domtree.clone(),
            blocks: self.blocks.clone(),
            block_order: self.block_order.clone(),
            canonical_storage_by_var: self.canonical_storage_by_var.clone(),
            formal_projections: self.formal_projections.clone(),
            decompile_prep_facts: self.decompile_prep_facts.clone(),
            query_index: RwLock::new(None),
        }
    }
}

/// A basic block in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSABlock {
    /// Block address.
    pub addr: u64,
    /// Block size in bytes.
    pub size: u32,
    /// SSA operations in this block.
    pub ops: Vec<SSAOp>,
    /// Phi nodes at the start of this block.
    pub phis: Vec<PhiNode>,
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

/// What a call boundary does to this architecture's registers.
///
/// `stack_pointer_restored_by_callee` carries the storage only when the source
/// stated that the convention restores it; see the field's own documentation
/// for why the caller's stack pointer is otherwise wrong from its first call
/// onward.
fn decompile_call_boundary_config(
    arch: Option<&ArchSpec>,
    stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
    preserved_by_target: CalleePreservedCarriers,
) -> Option<CallBoundaryConfig> {
    let arch = arch?;
    let defined_regs = call_clobbered_register_defs(arch);
    if defined_regs.is_empty() && stack_pointer_restored_by_callee.is_none() {
        return None;
    }
    Some(CallBoundaryConfig {
        defined_regs,
        stack_pointer_restored_by_callee,
        preserved_by_target,
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
    #[cfg(test)]
    pub(crate) fn from_exact_test_blocks(blocks: &[SSABlock], cfg: CFG) -> Self {
        let entry = cfg
            .entry_block()
            .map(|block| block.addr)
            .unwrap_or_default();
        let domtree = DomTree::compute(&cfg);
        let block_order = cfg.reverse_postorder();
        Self {
            call_preserved_carriers: None,
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            blocks: blocks
                .iter()
                .cloned()
                .map(|block| (block.addr, block))
                .collect(),
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
            None,
            None,
            None,
            &CalleePreservedCarriers::new(),
            None,
            control,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_blocks_for_decompile_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        function_interface: Option<&SourceFunctionInterface>,
        call_preserved_carriers: Option<SourceCallPreservedCarriers>,
        stack_pointer_carrier: Option<CanonicalStorageId>,
        callee_preserved_carriers: &CalleePreservedCarriers,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        // The convention says the callee leaves this carrier where it found
        // it, and the machine's own p-code moved it to transfer control. Both
        // halves have to be in hand before SSA construction, because it is
        // construction that decides which value each later read of the carrier
        // sees.
        let stack_pointer_restored_by_callee = stack_pointer_carrier.filter(|_| {
            stack_pointer_restored_across_calls(call_preserved_carriers, function_interface)
        });
        // The carriers the convention names at this function's own boundary:
        // every caller reads the result register and writes the argument
        // registers, so the whole of each is used even where the body's own
        // operations name only a lane of one.
        let abi_carriers = function_interface.map_or_else(Vec::new, |interface| {
            interface
                .parameters()
                .iter()
                .filter_map(crate::SourceAbiParameterSpec::register_storage)
                .chain(match interface.return_kind() {
                    crate::SourceFunctionReturn::Register { storage } => Some(storage),
                    _ => None,
                })
                .collect()
        });
        let mut func = Self::from_blocks_raw_for_decompile_with_carriers_and_control(
            blocks,
            arch,
            stack_pointer_restored_by_callee,
            callee_preserved_carriers,
            declared_successors,
            &abi_carriers,
            control,
        )?;
        func.call_preserved_carriers = call_preserved_carriers;
        func.stack_pointer_carrier = stack_pointer_carrier;
        func.prepare_for_decompile_with_interface_and_control(
            &crate::optimize::DecompilePrepConfig::default(),
            function_interface,
            control,
        )?;
        func.refresh_decompile_prep_facts_with_interface_and_control(function_interface, control)?;
        validate_ssa_function(&func).map_err(|_| malformed_ssa_input())?;
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
        let mut func =
            Self::from_blocks_raw_with_policy_and_control(blocks, arch, None, None, &[], control)?;
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
        Self::from_blocks_raw_with_policy_and_control(blocks, arch, None, None, &[], control)
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
            &CalleePreservedCarriers::new(),
            None,
            &[],
            control,
        )
    }

    /// The same, told which carrier the convention says a callee restores.
    fn from_blocks_raw_for_decompile_with_carriers_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
        callee_preserved_carriers: &CalleePreservedCarriers,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let policy = decompile_call_boundary_config(
            arch,
            stack_pointer_restored_by_callee,
            callee_preserved_carriers.clone(),
        );
        Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            policy.as_ref(),
            declared_successors,
            abi_carriers,
            control,
        )
    }

    fn from_blocks_raw_with_policy_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        call_boundaries: Option<&CallBoundaryConfig>,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
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
        let renamed = rename_function_with_names_and_call_boundaries_and_control(
            &cfg,
            &domtree,
            &phi_placement,
            &defs,
            reg_names_ref,
            families.clone(),
            call_boundaries,
            control,
        )?;

        // Build SSA blocks
        let mut ssa_blocks = HashMap::new();
        for &addr in &renamed.block_order {
            control.poll()?;
            let cfg_block = cfg.get_block(addr).ok_or_else(malformed_ssa_input)?;
            let ops = renamed.blocks.get(&addr).cloned().unwrap_or_default();

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
            ssa_blocks.insert(addr, ssa_block);
        }

        let mut function = Self {
            call_preserved_carriers: None,
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            blocks: ssa_blocks,
            block_order: renamed.block_order,
            canonical_storage_by_var: renamed.canonical_storage_by_var,
            formal_projections: BTreeMap::new(),
            decompile_prep_facts: None,
            query_index: RwLock::new(None),
        };
        function.zero_scratch_insert_roots(abi_carriers);
        // The validator answers with a typed integrity error naming the block
        // and the edge it disagreed about; discarding it left the reader with
        // "malformed SSA source input" and nothing to look at.
        validate_ssa_function(&function).map_err(|error| {
            if std::env::var_os("R2DEC_TRACE_REFUSAL").is_some() {
                let mut addrs = function.blocks.keys().copied().collect::<Vec<_>>();
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

    /// Set the function name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the entry block.
    pub fn entry_block(&self) -> Option<&SSABlock> {
        self.blocks.get(&self.entry)
    }

    /// Get a block by address.
    pub fn get_block(&self, addr: u64) -> Option<&SSABlock> {
        self.blocks.get(&addr)
    }

    /// Get a mutable block by address.
    pub fn get_block_mut(&mut self, addr: u64) -> Option<&mut SSABlock> {
        self.invalidate_query_index();
        self.decompile_prep_facts = None;
        self.blocks.get_mut(&addr)
    }

    /// Get all blocks in reverse postorder.
    pub fn blocks(&self) -> impl Iterator<Item = &SSABlock> {
        self.block_order
            .iter()
            .filter_map(|&addr| self.blocks.get(&addr))
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

    /// Get switch info for a block, if it's a switch terminator.
    /// Returns Some((cases, default)) where cases is Vec<(value, target)>.
    pub fn switch_info(&self, addr: u64) -> Option<SwitchInfo> {
        let block = self.cfg.get_block(addr)?;
        if let crate::cfg::BlockTerminator::Switch { cases, default } = &block.terminator {
            Some((cases.clone(), *default))
        } else {
            None
        }
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
            if let Some((cases, default)) = self.switch_info(block.addr) {
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
        self.blocks.remove(&addr);
        self.block_order.retain(|&a| a != addr);
        self.cfg.remove_block(addr);
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Remove phi sources for a specific predecessor edge.
    pub fn remove_phi_source(&mut self, block_addr: u64, pred_addr: u64) {
        if let Some(block) = self.blocks.get_mut(&block_addr) {
            for phi in &mut block.phis {
                phi.sources.retain(|(pred, _)| *pred != pred_addr);
            }
        }
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Recompute cached metadata after CFG mutation.
    pub fn refresh_after_cfg_mutation(&mut self) {
        self.blocks
            .retain(|addr, _| self.cfg.get_block(*addr).is_some());
        self.block_order = self.cfg.reverse_postorder();
        self.domtree = DomTree::compute(&self.cfg);
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Iterate over all SSA operations in the function.
    pub fn all_ops(&self) -> impl Iterator<Item = &SSAOp> {
        self.blocks.values().flat_map(|b| b.ops.iter())
    }

    /// Iterate over all phi nodes in the function.
    pub fn all_phis(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks.values().flat_map(|b| b.phis.iter())
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
            .and_then(|index| index.defs.get(var).copied())
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
            .and_then(|index| index.uses.get(var).cloned())
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
        for block in self.blocks.values() {
            for phi in &block.phis {
                for (_, src) in &phi.sources {
                    uses.entry(src.clone())
                        .or_default()
                        .push((ScratchUse::Carried, phi.dst.clone()));
                }
            }
            for op in &block.ops {
                if let SSAOp::Insert {
                    src,
                    value,
                    position,
                    ..
                } = op
                {
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
                        .filter(|other| other.name == var.name)
                        .map(SSAVar::rename_disambiguator)
                        .max()
                        .map_or(1, |max| max + 1);
                    // Version one: it is a definition, and version zero is
                    // reserved for the value a block was entered with.
                    let zero = SSAVar::new(var.name.clone(), 1, var.size)
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
        for block in self.blocks.values_mut() {
            for phi in &mut block.phis {
                for (_, src) in &mut phi.sources {
                    if let Some(zero) = zeros.get(src) {
                        *src = zero.clone();
                    }
                }
            }
            for op in &mut block.ops {
                if let SSAOp::Insert { src, .. } = op
                    && let Some(zero) = zeros.get(src)
                {
                    *src = zero.clone();
                }
            }
        }
        if let Some(entry) = self.blocks.get_mut(&self.entry) {
            entry.ops.splice(0..0, minted);
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
        for projection in crate::semantic::source_formal_parameter_projections(machine_context) {
            if projection.graph_storage == projection.abi_storage {
                continue;
            }
            let Some(offset) = projection
                .graph_storage
                .offset
                .checked_sub(projection.abi_storage.offset)
                .and_then(|offset| u32::try_from(offset).ok())
            else {
                continue;
            };
            lanes
                .entry((
                    projection.abi_storage,
                    offset,
                    projection.graph_storage.size,
                ))
                .or_default();
        }
        if lanes.is_empty() {
            return;
        }
        // Only a lane the interface declares is a formal; any other lane read
        // of an entry root stays the `Subpiece` of the caller's value it is.
        for addr in self.block_order.clone() {
            let Some(block) = self.blocks.get(&addr) else {
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
                if let Some(block) = self.blocks.get_mut(&addr)
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
        for (root_var, (root, lanes)) in lanes_by_root {
            // Only for a root a C integer can hold; a vector register's
            // lanes are not parameters and have no declaration to rest on.
            if root.size > 8 {
                continue;
            }
            let read_elsewhere = self.blocks.values().any(|block| {
                block
                    .phis
                    .iter()
                    .any(|phi| phi.sources.iter().any(|(_, src)| *src == root_var))
                    || block.ops.iter().any(|op| op.sources().contains(&&root_var))
            });
            if !read_elsewhere {
                continue;
            }
            let disambiguator = self
                .canonical_storage_by_var
                .keys()
                .filter(|var| var.name == root_var.name)
                .map(SSAVar::rename_disambiguator)
                .max()
                .map_or(1, |max| max + 1);
            let composed = SSAVar::new(root_var.name.clone(), 0, root.size)
                .with_rename_disambiguator(disambiguator);
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
                            SSAVar::new(format!("tmp:root:{}:{index}", root_var.name), 1, root.size)
                        };
                        minted.push(SSAOp::Insert {
                            dst: dst.clone(),
                            src: carried,
                            value: lane.clone(),
                            position: SSAVar::constant(u64::from(*offset) * 8, 4),
                        });
                        carried = dst;
                    }
                }
            }
            self.canonical_storage_by_var.insert(composed.clone(), root);
            let replace = |var: &SSAVar| {
                if *var == root_var {
                    composed.clone()
                } else {
                    var.clone()
                }
            };
            for block in self.blocks.values_mut() {
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
        if let Some(entry) = self.blocks.get_mut(&self.entry) {
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
        let entry_stack_roots_are_stable = self.blocks().all(|block| {
            block.ops.iter().all(|op| match op {
                SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. } => call_carriers_are_restored,
                SSAOp::CallOther { .. }
                | SSAOp::Unimplemented
                | SSAOp::CpuId { .. }
                | SSAOp::New { .. } => false,
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
        if let Some(interface) = function_interface.filter(|interface| {
            interface.stack_slot_roles_complete()
                && interface.stack_pointer_storage().is_some()
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
                    let source_roots = phi
                        .sources
                        .iter()
                        .map(|(_, src)| resolve_value_root(src, &facts.canonical_value_roots))
                        .collect::<Vec<_>>();
                    if let Some(root) = common_root(&source_roots) {
                        changed |= insert_canonical_root(
                            &mut facts.canonical_value_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }

                    if let Some(root) = common_stack_root(
                        &phi.sources,
                        &facts.canonical_value_roots,
                        &facts.stack_address_roots,
                    ) {
                        changed |= insert_stack_root(
                            &mut facts.stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                    if entry_stack_address_size.is_some_and(|size| {
                        phi.dst.size == size
                            && phi.sources.iter().all(|(_, source)| source.size == size)
                    }) && let Some(root) = common_stack_root(
                        &phi.sources,
                        &facts.canonical_value_roots,
                        &facts.entry_stack_address_roots,
                    ) {
                        changed |= insert_stack_root(
                            &mut facts.entry_stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                }
                for op in &block.ops {
                    control.poll()?;
                    match op {
                        SSAOp::Copy { dst, src }
                        | SSAOp::Cast { dst, src }
                        | SSAOp::CallRestore { dst, src } => {
                            let src_root = resolve_value_root(src, &facts.canonical_value_roots);
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                src_root.clone(),
                            );
                            if let Some(stack_root) = resolve_stack_root(
                                src,
                                &facts.canonical_value_roots,
                                &facts.stack_address_roots,
                            ) {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                            if entry_stack_address_size
                                .is_some_and(|size| dst.size == size && src.size == size)
                                && let Some(stack_root) = resolve_stack_root(
                                    src,
                                    &facts.canonical_value_roots,
                                    &facts.entry_stack_address_roots,
                                )
                            {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                        }
                        SSAOp::Trunc { dst, src } | SSAOp::Subpiece { dst, src, .. } => {
                            let src_root = resolve_value_root(src, &facts.canonical_value_roots);
                            let adapted = adapt_root_width(&src_root, dst.size)
                                .unwrap_or_else(|| src_root.clone());
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                adapted,
                            );
                        }
                        SSAOp::IntAdd { dst, a, b } => {
                            // An exact root is preferred; this records the
                            // object an address is inside when the offset
                            // within it is computed rather than stated.
                            if !facts.stack_address_roots.contains_key(dst)
                                && let Some(root) = indexed_stack_address_root_from_add(
                                    a,
                                    b,
                                    &facts.canonical_value_roots,
                                    &facts.stack_address_roots,
                                    &facts.indexed_stack_address_roots,
                                )
                            {
                                changed |= insert_stack_root(
                                    &mut facts.indexed_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = stack_address_root_from_add(
                                a,
                                b,
                                &facts.canonical_value_roots,
                                &facts.stack_address_roots,
                            ) {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if entry_stack_address_size.is_some_and(|size| {
                                dst.size == size && a.size == size && b.size == size
                            }) && let Some(root) = stack_address_root_from_add(
                                a,
                                b,
                                &facts.canonical_value_roots,
                                &facts.entry_stack_address_roots,
                            ) {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                        }
                        SSAOp::IntSub { dst, a, b } => {
                            if let Some(root) = stack_address_root_from_sub(
                                a,
                                b,
                                &facts.canonical_value_roots,
                                &facts.stack_address_roots,
                            ) {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if entry_stack_address_size.is_some_and(|size| {
                                dst.size == size && a.size == size && b.size == size
                            }) && let Some(root) = stack_address_root_from_sub(
                                a,
                                b,
                                &facts.canonical_value_roots,
                                &facts.entry_stack_address_roots,
                            ) {
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

        control.poll()?;
        Ok(facts)
    }

    /// Get the switch-selector SSA value that drives a switch block, if recoverable.
    pub fn infer_switch_selector_var(&self, block_addr: u64) -> Option<SSAVar> {
        let block = self.get_block(block_addr)?;
        let Some(target) = block.ops.iter().rev().find_map(|op| match op {
            SSAOp::BranchInd { target, .. } => Some(target),
            _ => None,
        }) else {
            r2il::refusal_evidence!(
                "switch-selector-walk",
                "{block_addr:#x} has no indirect branch to walk back from"
            );
            return None;
        };
        self.infer_switch_selector_var_from_value(target, 0)
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

    fn infer_switch_selector_var_from_value(&self, var: &SSAVar, depth: u32) -> Option<SSAVar> {
        if depth > 16 {
            return None;
        }

        let Some((block_addr, location)) = self.find_def(var) else {
            let constish = Self::is_constish_switch_value(var);
            if constish {
                r2il::refusal_evidence!(
                    "switch-selector-walk",
                    "{} has no definition and reads as a constant",
                    var.display_name()
                );
            }
            return (!constish).then(|| var.clone());
        };
        let DefLocation::Op(op_idx) = location else {
            r2il::refusal_evidence!(
                "switch-selector-walk",
                "{} is defined by a merge in {block_addr:#x}, which the walk does not cross",
                var.display_name()
            );
            return None;
        };
        let block = self.get_block(block_addr)?;
        let op = block.ops.get(op_idx)?;
        r2il::refusal_evidence!(
            "switch-selector-walk",
            "step {depth}: {} defined at {block_addr:#x} op {op_idx}",
            var.display_name()
        );
        match op {
            SSAOp::Copy { src, .. }
            | SSAOp::IntZExt { src, .. }
            | SSAOp::IntSExt { src, .. }
            | SSAOp::Trunc { src, .. }
            | SSAOp::Cast { src, .. }
            | SSAOp::Subpiece { src, .. } => {
                self.infer_switch_selector_var_from_value(src, depth + 1)
            }
            SSAOp::Load { addr, .. } => {
                if self.is_stack_slot_address_var(addr, depth + 1) {
                    Some(var.clone())
                } else {
                    // A table load carries the index inside its address, so
                    // that is tried first. A plain dereference does not, and
                    // then the byte read is itself the selector: `switch (*p)`
                    // with `p` a local pointer is every string-scanning switch.
                    self.infer_switch_selector_var_from_address(addr, depth + 1)
                        .or_else(|| {
                            r2il::refusal_evidence!(
                                "switch-selector-walk",
                                "{} is read through an address that carries no index, so the value read is the selector",
                                var.display_name()
                            );
                            Some(var.clone())
                        })
                }
            }
            SSAOp::IntAdd { a, b, .. } | SSAOp::IntSub { a, b, .. } => {
                self.infer_switch_selector_var_from_sum(a, b, depth + 1)
            }
            SSAOp::IntMult { a, b, .. } => {
                self.infer_switch_selector_var_from_scaled(a, b, depth + 1)
            }
            // A masked value *is* the selector, not a step towards one.
            // `switch (len & 3)` compiles to a table indexed by the mask's
            // result, and walking past it loses the mask: murmur3's tail
            // rendered `switch (arg1)`, which a 61-byte message matches none of.
            SSAOp::IntAnd { .. } => Some(var.clone()),
            // The walk that finds nothing is the one worth naming: a switch
            // whose selector is unproven cannot structure, and the reader was
            // told only "unrepresentable operation" several layers later.
            other => {
                r2il::refusal_evidence!(
                    "switch-selector-walk",
                    "{} defined at {block_addr:#x} op {op_idx} by {other:?} is not a selector step",
                    var.display_name()
                );
                None
            }
        }
    }

    fn infer_switch_selector_var_from_address(&self, addr: &SSAVar, depth: u32) -> Option<SSAVar> {
        if depth > 16 {
            return None;
        }

        let (block_addr, DefLocation::Op(op_idx)) = self.find_def(addr)? else {
            return None;
        };
        let block = self.get_block(block_addr)?;
        let op = block.ops.get(op_idx)?;
        r2il::refusal_evidence!(
            "switch-selector-walk",
            "address step {depth}: {} defined at {block_addr:#x} op {op_idx}",
            addr.display_name()
        );
        match op {
            SSAOp::Copy { src, .. }
            | SSAOp::IntZExt { src, .. }
            | SSAOp::IntSExt { src, .. }
            | SSAOp::Trunc { src, .. }
            | SSAOp::Cast { src, .. }
            | SSAOp::Subpiece { src, .. } => {
                self.infer_switch_selector_var_from_address(src, depth + 1)
            }
            SSAOp::IntAdd { a, b, .. } | SSAOp::IntSub { a, b, .. } => {
                self.infer_switch_selector_var_from_sum(a, b, depth + 1)
            }
            SSAOp::IntMult { a, b, .. } => {
                self.infer_switch_selector_var_from_scaled(a, b, depth + 1)
            }
            // The address walk used to end here without a word, which is why a
            // switch on a dereferenced pointer went unexplained for so long.
            other => {
                r2il::refusal_evidence!(
                    "switch-selector-walk",
                    "address {} defined at {block_addr:#x} op {op_idx} by {other:?} carries no index",
                    addr.display_name()
                );
                None
            }
        }
    }

    fn infer_switch_selector_var_from_sum(
        &self,
        a: &SSAVar,
        b: &SSAVar,
        depth: u32,
    ) -> Option<SSAVar> {
        if Self::is_constish_switch_value(a) {
            return self.infer_switch_selector_var_from_value(b, depth);
        }
        if Self::is_constish_switch_value(b) {
            return self.infer_switch_selector_var_from_value(a, depth);
        }
        self.infer_switch_selector_var_from_scaled(a, b, depth)
            .or_else(|| self.infer_switch_selector_var_from_scaled(b, a, depth))
            // Neither side is a constant, which is the offset-table form: one
            // register holds the table's address and the other the entry loaded
            // from it, and the jump adds them. Following each in turn reaches
            // the index that entry was loaded with; the base side dead-ends,
            // because a table address is not a selector. Without this the walk
            // never reaches the mask above, and x86-64 -O1 murmur3 inferred no
            // selector at all.
            .or_else(|| self.infer_switch_selector_var_from_value(a, depth + 1))
            .or_else(|| self.infer_switch_selector_var_from_value(b, depth + 1))
    }

    fn infer_switch_selector_var_from_scaled(
        &self,
        a: &SSAVar,
        b: &SSAVar,
        depth: u32,
    ) -> Option<SSAVar> {
        if Self::is_constish_switch_value(a) {
            return self.infer_switch_selector_var_from_value(b, depth);
        }
        if Self::is_constish_switch_value(b) {
            return self.infer_switch_selector_var_from_value(a, depth);
        }
        None
    }

    fn is_stack_slot_address_var(&self, var: &SSAVar, depth: u32) -> bool {
        if depth > 16 {
            return false;
        }

        let lower = var.name.to_ascii_lowercase();
        let base = lower.split('_').next().unwrap_or(lower.as_str());
        if matches!(base, "rbp" | "rsp" | "ebp" | "esp" | "bp" | "sp") {
            return true;
        }

        let Some((block_addr, DefLocation::Op(op_idx))) = self.find_def(var) else {
            return false;
        };
        let Some(block) = self.get_block(block_addr) else {
            return false;
        };
        let Some(op) = block.ops.get(op_idx) else {
            return false;
        };
        match op {
            SSAOp::Copy { src, .. }
            | SSAOp::IntZExt { src, .. }
            | SSAOp::IntSExt { src, .. }
            | SSAOp::Trunc { src, .. }
            | SSAOp::Cast { src, .. }
            | SSAOp::Subpiece { src, .. } => self.is_stack_slot_address_var(src, depth + 1),
            SSAOp::IntAdd { a, b, .. } | SSAOp::IntSub { a, b, .. } => {
                (self.is_stack_slot_address_var(a, depth + 1) && Self::is_constish_switch_value(b))
                    || (self.is_stack_slot_address_var(b, depth + 1)
                        && Self::is_constish_switch_value(a))
            }
            _ => false,
        }
    }

    fn is_constish_switch_value(var: &SSAVar) -> bool {
        var.is_const() || var.is_memory()
    }

    /// Print the function in a human-readable format.
    pub fn dump(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "Function: {}\n",
            self.name.as_deref().unwrap_or("<unnamed>")
        ));
        out.push_str(&format!("Entry: 0x{:x}\n", self.entry));
        out.push_str(&format!("Blocks: {}\n\n", self.num_blocks()));

        for &addr in &self.block_order {
            if let Some(block) = self.blocks.get(&addr) {
                out.push_str(&format!("Block 0x{:x}:\n", addr));

                // Predecessors
                let preds = self.predecessors(addr);
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

                // Operations
                for op in &block.ops {
                    out.push_str(&format!("  {:?}\n", op));
                }

                // Successors
                let succs = self.successors(addr);
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
}

/// One storage range inside a register family, identified by where it starts
/// and how wide it is rather than by any name the architecture gives it.
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
            SSAVarNameKind::Memory | SSAVarNameKind::AddressSpace
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

fn canonicalize_value_root(root: &SSAVar, roots: &BTreeMap<SSAVar, SSAVar>) -> SSAVar {
    let mut current = root.clone();
    let mut seen = HashSet::new();

    loop {
        let Some(next) = roots.get(&current) else {
            break;
        };
        if *next == current || !seen.insert(current.clone()) {
            break;
        }
        current = next.clone();
    }

    current
}

fn ensure_value_root_identity(roots: &mut BTreeMap<SSAVar, SSAVar>, var: SSAVar) -> bool {
    if roots.contains_key(&var) {
        return false;
    }
    roots.insert(var.clone(), var);
    true
}

fn insert_canonical_root(roots: &mut BTreeMap<SSAVar, SSAVar>, dst: SSAVar, root: SSAVar) -> bool {
    let root = canonicalize_value_root(&root, roots);
    let changed = !matches!(roots.get(&dst), Some(existing) if *existing == root);
    roots.insert(dst.clone(), root.clone());
    roots.entry(root.clone()).or_insert(root);
    changed
}

fn common_root(values: &[SSAVar]) -> Option<SSAVar> {
    let first = values.first()?.clone();
    if values.iter().all(|value| *value == first) {
        Some(first)
    } else {
        None
    }
}

fn resolve_value_root(var: &SSAVar, roots: &BTreeMap<SSAVar, SSAVar>) -> SSAVar {
    canonicalize_value_root(var, roots)
}

fn resolve_stack_root(
    var: &SSAVar,
    roots: &BTreeMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let resolved = resolve_value_root(var, roots);
    stack_roots
        .get(var)
        .copied()
        .or_else(|| stack_roots.get(&resolved).copied())
}

fn common_stack_root(
    sources: &[(u64, SSAVar)],
    roots: &BTreeMap<SSAVar, SSAVar>,
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

fn stack_root_from_operand(
    var: &SSAVar,
    roots: &BTreeMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    resolve_stack_root(var, roots, stack_roots)
}

fn stack_address_root_from_add(
    a: &SSAVar,
    b: &SSAVar,
    roots: &BTreeMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    if let (Some(base), Some(delta)) = (
        stack_root_from_operand(a, roots, stack_roots),
        signed_stack_delta_through_roots(b, roots),
    ) {
        return Some(StackAddressRoot {
            base: base.base,
            offset: base.offset.checked_add(delta)?,
        });
    }
    if let (Some(base), Some(delta)) = (
        stack_root_from_operand(b, roots, stack_roots),
        signed_stack_delta_through_roots(a, roots),
    ) {
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
    b: &SSAVar,
    roots: &BTreeMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
    indexed_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let base_of = |var: &SSAVar| {
        stack_root_from_operand(var, roots, stack_roots)
            .or_else(|| stack_root_from_operand(var, roots, indexed_roots))
    };
    let index_is_opaque = |var: &SSAVar| {
        signed_stack_delta_through_roots(var, roots).is_none() && base_of(var).is_none()
    };
    if let Some(base) = base_of(a)
        && index_is_opaque(b)
    {
        return Some(base);
    }
    if let Some(base) = base_of(b)
        && index_is_opaque(a)
    {
        return Some(base);
    }
    None
}

fn stack_address_root_from_sub(
    a: &SSAVar,
    b: &SSAVar,
    roots: &BTreeMap<SSAVar, SSAVar>,
    stack_roots: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Option<StackAddressRoot> {
    let base = stack_root_from_operand(a, roots, stack_roots)?;
    let delta = signed_stack_delta_through_roots(b, roots)?;
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
fn signed_stack_delta_through_roots(var: &SSAVar, roots: &BTreeMap<SSAVar, SSAVar>) -> Option<i64> {
    if let Some(delta) = signed_stack_delta(var) {
        return Some(delta);
    }
    let root = resolve_value_root(var, roots);
    (root != *var).then(|| signed_stack_delta(&root)).flatten()
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefLocation {
    /// Defined by a phi node at the given index.
    Phi(usize),
    /// Defined by an operation at the given index.
    Op(usize),
}

/// Location of a variable use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseLocation {
    /// Used in a phi node.
    Phi { phi_idx: usize, src_idx: usize },
    /// Used in an operation.
    Op { op_idx: usize, src_idx: usize },
}

impl SsaQueryIndex {
    fn build(function: &SSAFunction) -> Self {
        let mut defs = HashMap::new();
        let mut uses: HashMap<SSAVar, Vec<(u64, UseLocation)>> = HashMap::new();

        for block in function.blocks() {
            for (phi_idx, phi) in block.phis.iter().enumerate() {
                defs.insert(phi.dst.clone(), (block.addr, DefLocation::Phi(phi_idx)));
                for (src_idx, (_, src)) in phi.sources.iter().enumerate() {
                    uses.entry(src.clone())
                        .or_default()
                        .push((block.addr, UseLocation::Phi { phi_idx, src_idx }));
                }
            }

            for (op_idx, op) in block.ops.iter().enumerate() {
                if let Some(dst) = op.dst() {
                    defs.insert(dst.clone(), (block.addr, DefLocation::Op(op_idx)));
                }
                for (src_idx, src) in op.sources().into_iter().enumerate() {
                    uses.entry(src.clone())
                        .or_default()
                        .push((block.addr, UseLocation::Op { op_idx, src_idx }));
                }
            }
        }

        Self { defs, uses }
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

#[cfg(test)]
mod tests {

    fn advisory_call_site(
        instruction: u64,
        target: u64,
        transfer: u8,
    ) -> r2source::AdvisoryCallSite {
        let mut writer = r2source::snapshot_wire::SnapshotWireWriter::new();
        writer.u64(instruction);
        writer.u64(target);
        writer.string("").expect("empty call name");
        writer.u8(transfer);
        writer.bool(false);
        let bytes = writer.finish().expect("callsite wire");
        let mut reader =
            r2source::snapshot_wire::SnapshotWireReader::new(&bytes).expect("callsite reader");
        r2source::snapshot_wire::read_call_site(&mut reader).expect("callsite")
    }

    #[test]
    fn tail_jump_identity_requires_matching_terminal_branch() {
        let mut branch = R2ILBlock::new(0x1000, 4);
        branch.push_with_metadata(
            R2ILOp::Branch {
                target: make_const(0x5000, 8),
            },
            Some(r2il::OpMetadata {
                instruction_addr: Some(0x1000),
                ..r2il::OpMetadata::default()
            }),
        );
        let tail = advisory_call_site(0x1000, 0x5000, 1);
        let identity = unique_call_site_identity(&[branch.clone()], &tail)
            .expect("exact terminal branch is the source-proven callsite");
        assert_eq!(identity.instruction(), 0x1000);
        assert_eq!(identity.target().offset, 0x5000);

        let ordinary_call = advisory_call_site(0x1000, 0x5000, 0);
        assert!(unique_call_site_identity(&[branch.clone()], &ordinary_call).is_none());

        branch.ops.push(R2ILOp::Nop);
        assert!(unique_call_site_identity(&[branch], &tail).is_none());

        let mut call = R2ILBlock::new(0x2000, 4);
        call.push_with_metadata(
            R2ILOp::Call {
                target: make_const(0x6000, 8),
            },
            Some(r2il::OpMetadata {
                instruction_addr: Some(0x2000),
                ..r2il::OpMetadata::default()
            }),
        );
        call.push(R2ILOp::Nop);
        let ordinary_call = advisory_call_site(0x2000, 0x6000, 0);
        assert!(
            unique_call_site_identity(&[call], &ordinary_call).is_some(),
            "ordinary calls keep their original nonterminal correlation rule"
        );
    }

    #[test]
    fn tail_slot_identity_unifies_direct_ram_and_loaded_register_targets() {
        let slot = 0x1000_4010;
        let tail = advisory_call_site(0x2010, slot, 2);

        let mut direct_ram = R2ILBlock::new(0x2000, 0x14);
        direct_ram.push_with_metadata(
            R2ILOp::BranchInd {
                target: Varnode::ram(slot, 8),
            },
            Some(r2il::OpMetadata {
                instruction_addr: Some(0x2010),
                ..r2il::OpMetadata::default()
            }),
        );
        let direct_identity = unique_call_site_identity(&[direct_ram], &tail)
            .expect("the terminal branch reads the relocated RAM slot directly");

        let base = Varnode::constant(0x1000_4000, 8);
        let displacement = Varnode::constant(0x10, 8);
        let address = Varnode::unique(0x6500, 8);
        let loaded = Varnode::register(0x4080, 8);
        let pc = Varnode::register(0, 8);
        let mut through_register = R2ILBlock::new(0x2000, 0x14);
        through_register.push(R2ILOp::IntAdd {
            dst: address.clone(),
            a: base,
            b: displacement,
        });
        through_register.push(R2ILOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: address,
        });
        through_register.push(R2ILOp::Copy {
            dst: pc.clone(),
            src: loaded,
        });
        through_register.push_with_metadata(
            R2ILOp::BranchInd { target: pc },
            Some(r2il::OpMetadata {
                instruction_addr: Some(0x2010),
                ..r2il::OpMetadata::default()
            }),
        );
        let loaded_identity = unique_call_site_identity(&[through_register], &tail)
            .expect("the terminal branch reads a value loaded from the relocated slot");

        assert_eq!(direct_identity.target(), loaded_identity.target());
        assert_eq!(direct_identity.target().space, CanonicalStorageSpace::Ram);
        assert_eq!(direct_identity.target().offset, slot);
        assert!(unique_call_site_identity(&[R2ILBlock::new(0x2000, 0x14)], &tail,).is_none());
    }

    #[test]
    fn tail_jump_is_a_terminal_callsite_without_call_clobbers() {
        // Direct code targets lifted from a real branch retain RAM storage;
        // unlike an arithmetic literal, their SSA variable has no
        // `constant_bits` payload.
        let target = make_ram(0x5000, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Branch {
            target: target.clone(),
        });
        block.stamp_instruction(0, 0x1000);
        let identity =
            SourceCallSiteIdentity::new(0x1000, CanonicalStorageId::from_varnode(&target));
        let interface = SourceCallSiteInterface::new(
            b"tail-jump".to_vec(),
            identity,
            true,
            "aapcs64",
            [],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("tail callsite interface");
        let context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            &[block.clone()],
            None,
            None,
            SourceMachineRoles::default(),
            None,
            vec![interface],
            vec![identity],
        );
        let function =
            SSAFunction::from_blocks_for_decompile(&[block], None).expect("tail branch SSA");
        let artifact =
            SsaArtifact::new_with_context(function, FunctionPrepareMode::Decompile, context);

        let prepared_block = artifact.function().get_block(0x1000).expect("tail block");
        assert!(matches!(
            prepared_block.ops.as_slice(),
            [SSAOp::Branch { .. }]
        ));
        assert!(
            !prepared_block
                .ops
                .iter()
                .any(|op| matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }))
        );
        let call = artifact
            .callsite_certificate_for_op(0x1000, 0)
            .expect("tail callsite certificate");
        assert_eq!(call.transfer, crate::semantic::CallSiteTransfer::TailCall);
        assert_eq!(call.fallthrough, None);
        assert_eq!(call.direct_target, Some(0x5000));
        let obligations = artifact
            .obligations()
            .obligations_for_inst(call.at)
            .map(|obligation| obligation.id.kind)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(obligations.contains(&crate::SemanticObligationKind::Call));
        assert!(obligations.contains(&crate::SemanticObligationKind::ControlTransfer));
    }

    #[test]
    fn tail_slot_is_a_terminal_callsite_through_either_ssa_shape() {
        let slot = 0x401008;
        let target_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            offset: slot,
            size: 8,
        };

        let mut direct_ram = R2ILBlock::new(0x1600, 4);
        direct_ram.push(R2ILOp::BranchInd {
            target: Varnode::ram(slot, 8),
        });
        direct_ram.stamp_instruction(0, 0x1600);

        let address = Varnode::unique(0x6500, 8);
        let loaded = Varnode::register(0x4080, 8);
        let pc = Varnode::register(0, 8);
        let mut through_register = R2ILBlock::new(0x2600, 16);
        through_register.push(R2ILOp::IntAdd {
            dst: address.clone(),
            a: Varnode::constant(0x401000, 8),
            b: Varnode::constant(8, 8),
        });
        through_register.push(R2ILOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: address,
        });
        through_register.push(R2ILOp::Copy {
            dst: pc.clone(),
            src: loaded,
        });
        through_register.push(R2ILOp::BranchInd { target: pc });
        through_register.stamp_instruction(3, 0x260c);

        for (block, op_index, instruction) in
            [(direct_ram, 0, 0x1600), (through_register, 3, 0x260c)]
        {
            let identity = SourceCallSiteIdentity::new(instruction, target_storage);
            let interface = SourceCallSiteInterface::new(
                b"tail-slot".to_vec(),
                identity,
                true,
                "sysv64",
                [],
                false,
                false,
                SourceCallResult::Void,
            )
            .expect("tail slot interface");
            let context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
                std::slice::from_ref(&block),
                None,
                None,
                SourceMachineRoles::default(),
                None,
                vec![interface],
                vec![identity],
            );
            let function =
                SSAFunction::from_blocks_for_decompile(std::slice::from_ref(&block), None)
                    .expect("tail slot SSA");
            let artifact =
                SsaArtifact::new_with_context(function, FunctionPrepareMode::Decompile, context);
            let certificate = artifact
                .callsite_certificate_for_op(block.addr, op_index)
                .expect("tail slot callsite certificate");
            assert_eq!(
                certificate.transfer,
                crate::semantic::CallSiteTransfer::TailCall
            );
            assert_eq!(certificate.direct_target, Some(slot));
            assert_eq!(certificate.fallthrough, None);
        }
    }

    #[test]
    fn stack_root_follows_a_displacement_materialised_into_a_temp() {
        // AArch64 Sleigh writes `add x29, sp, 0x60` as
        // `tmp:A = 0x60; x29 = sp + tmp:A`, so the displacement operand is a
        // temp and the constant is one copy away. Reading only the operand left
        // the frame pointer with no stack root, and with it every address
        // derived from the frame pointer, which is most of a non-leaf
        // function's locals.
        use super::{StackAddressBase, StackAddressRoot, stack_address_root_from_add};
        use std::collections::BTreeMap;

        let sp = SSAVar::new("sp", 1, 8);
        let displacement = SSAVar::new("tmp:11e80", 1, 8);
        let literal = SSAVar::constant(0x60, 8);

        let mut stack_roots = BTreeMap::new();
        stack_roots.insert(
            sp.clone(),
            StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x70,
            },
        );
        let mut roots = BTreeMap::new();
        assert_eq!(
            stack_address_root_from_add(&sp, &displacement, &roots, &stack_roots,),
            None,
            "with nothing linking the temp to the constant there is no delta to add"
        );

        roots.insert(displacement.clone(), literal);
        assert_eq!(
            stack_address_root_from_add(&sp, &displacement, &roots, &stack_roots,),
            Some(StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x10,
            }),
            "the frame pointer sits 0x60 above a 0x70 frame, so 0x10 below entry"
        );
    }
    use super::*;
    use crate::semantic::{CallArgumentLocation, SemanticId};
    use crate::{
        CallBoundarySlot, CanonicalStorageSpace, SourceAbiParameterSpec, SourceCallArgumentFact,
        SourceCallArgumentValue, SourceFunctionReturn, SourceStackSlotSpec, ValueId,
    };
    use r2il::{R2ILOp, RegisterDef, SpaceId, SwitchCase, SwitchInfo as R2ILSwitchInfo, Varnode};
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    fn make_const(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
            meta: None,
        }
    }

    fn make_reg(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    fn make_ram(addr: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Ram,
            offset: addr,
            size,
            meta: None,
        }
    }

    fn make_unique(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Unique,
            offset,
            size,
            meta: None,
        }
    }

    fn make_arm64_alias_arch() -> ArchSpec {
        let mut arch = ArchSpec::new("aarch64");
        arch.add_register(RegisterDef::new("x0", 0x00, 8));
        arch.add_register(RegisterDef::new("w0", 0x00, 4));
        arch.add_register(RegisterDef::new("x8", 0x80, 8));
        arch.add_register(RegisterDef::new("w8", 0x80, 4));
        arch.add_register(RegisterDef::new("x9", 0x88, 8));
        arch.add_register(RegisterDef::new("w9", 0x88, 4));
        arch
    }

    fn make_x86_64_prep_arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("rbx", 8, 8));
        arch.add_register(RegisterDef::new("rsp", 16, 8));
        arch.add_register(RegisterDef::new("rbp", 24, 8));
        arch
    }

    fn vector_loop_alias_arch(prefix: &str) -> ArchSpec {
        let mut arch = ArchSpec::new("range-alias-test");
        let acc = format!("{prefix}_acc");
        let loaded = format!("{prefix}_loaded");
        arch.add_register(RegisterDef::new(&acc, 0x100, 16));
        arch.add_register(RegisterDef::new(format!("{prefix}_acc_a"), 0x100, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_acc_b"), 0x104, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_acc_c"), 0x108, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_acc_d"), 0x10c, 4));
        arch.add_register(RegisterDef::new(&loaded, 0x200, 16));
        arch.add_register(RegisterDef::new(format!("{prefix}_load_a"), 0x200, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_load_b"), 0x204, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_load_c"), 0x208, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_load_d"), 0x20c, 4));
        arch.add_register(RegisterDef::new(format!("{prefix}_return64"), 0x300, 8));
        arch.add_register(RegisterDef::new(format!("{prefix}_return32"), 0x300, 4));
        arch
    }

    fn vector_loop_alias_blocks(base: u64) -> Vec<R2ILBlock> {
        let header = base + 4;
        let exit = base + 8;
        let body = base + 12;
        let mut body_ops = vec![R2ILOp::Load {
            dst: make_reg(0x200, 16),
            space: SpaceId::Ram,
            addr: make_const(0x8000, 8),
        }];
        for lane in 0u64..4 {
            let offset = lane * 4;
            body_ops.push(R2ILOp::IntAdd {
                dst: make_reg(0x100 + offset, 4),
                a: make_reg(0x100 + offset, 4),
                b: make_reg(0x200 + offset, 4),
            });
        }
        body_ops.push(R2ILOp::Branch {
            target: make_const(header, 8),
        });

        vec![
            R2ILBlock {
                addr: base,
                size: 4,
                ops: vec![
                    R2ILOp::IntXor {
                        dst: make_reg(0x100, 16),
                        a: make_reg(0x100, 16),
                        b: make_reg(0x100, 16),
                    },
                    R2ILOp::Branch {
                        target: make_const(header, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: header,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(body, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: exit,
                size: 4,
                ops: vec![
                    R2ILOp::Subpiece {
                        dst: make_reg(0x300, 4),
                        src: make_reg(0x100, 16),
                        offset: 0,
                    },
                    R2ILOp::IntZExt {
                        dst: make_reg(0x300, 8),
                        src: make_reg(0x300, 4),
                    },
                    R2ILOp::Return {
                        target: make_reg(0x300, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: body,
                size: 4,
                ops: body_ops,
                switch_info: None,
                op_metadata: Default::default(),
            },
        ]
    }

    #[test]
    fn graph_value_storage_is_retained_from_varnodes_across_cosmetic_names() {
        fn arch(prefix: &str) -> ArchSpec {
            let mut arch = ArchSpec::new("storage-provenance-test");
            arch.add_register(RegisterDef::new(format!("{prefix}_out"), 0x10, 8));
            arch.add_register(RegisterDef::new(format!("{prefix}_input"), 0x20, 8));
            arch.add_register(RegisterDef::new(format!("{prefix}_return"), 0x30, 8));
            arch
        }

        let blocks = [R2ILBlock {
            addr: 0x2200,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: make_reg(0x10, 8),
                    a: make_reg(0x20, 8),
                    b: make_const(7, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0x30, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let left = SSAFunction::from_blocks_raw(&blocks, Some(&arch("left")))
            .expect("left SSA must build");
        let right = SSAFunction::from_blocks_raw(&blocks, Some(&arch("right")))
            .expect("right SSA must build");
        let left_graph = SsaGraph::from_function(&left);
        let right_graph = SsaGraph::from_function(&right);

        let projection = |graph: &SsaGraph| {
            graph
                .values
                .iter()
                .map(|value| {
                    (
                        value.id,
                        value.var.version,
                        value.var.size,
                        value.canonical_storage,
                        graph.def_inst(value.id),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(projection(&left_graph), projection(&right_graph));
        assert_ne!(
            left_graph
                .values
                .iter()
                .map(|value| value.var.name.as_str())
                .collect::<Vec<_>>(),
            right_graph
                .values
                .iter()
                .map(|value| value.var.name.as_str())
                .collect::<Vec<_>>()
        );
        let storages = left_graph
            .values
            .iter()
            .map(|value| value.canonical_storage.expect("raw value provenance"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            storages,
            BTreeSet::from([
                CanonicalStorageId {
                    space: crate::CanonicalStorageSpace::Register,
                    offset: 0x10,
                    size: 8,
                },
                CanonicalStorageId {
                    space: crate::CanonicalStorageSpace::Register,
                    offset: 0x20,
                    size: 8,
                },
                CanonicalStorageId {
                    space: crate::CanonicalStorageSpace::Register,
                    offset: 0x30,
                    size: 8,
                },
                CanonicalStorageId {
                    space: crate::CanonicalStorageSpace::Constant,
                    offset: 7,
                    size: 8,
                },
            ])
        );
    }

    fn assert_vector_loop_alias_provenance(base: u64, prefix: &str) {
        let function = SSAFunction::from_blocks_raw(
            &vector_loop_alias_blocks(base),
            Some(&vector_loop_alias_arch(prefix)),
        )
        .expect("vector loop SSA should build");
        let accumulator = |var: &SSAVar| {
            function
                .canonical_storage_for_var(var)
                .is_some_and(|storage| {
                    storage.space == CanonicalStorageSpace::Register
                        && storage.offset == 0x100
                        && storage.size == 16
                })
        };
        // The accumulator is one family, so the loop carries one merge of it.
        let header = function.get_block(base + 4).expect("loop header");
        let accumulator_phis = header
            .phis
            .iter()
            .filter(|phi| accumulator(&phi.dst))
            .collect::<Vec<_>>();
        let [phi] = accumulator_phis.as_slice() else {
            panic!("one accumulator phi, got {:?}", header.phis);
        };
        let graph = SsaGraph::from_function(&function);
        assert_eq!(phi.sources.len(), 2);
        for (_, source) in &phi.sources {
            let value = graph.value_id_for_var(source).expect("phi input value");
            assert!(
                graph.def_inst(value).is_some(),
                "every merge input must have an SSA producer: {source}"
            );
        }

        // Each lane update reads its lane of the accumulator and of the load
        // as a subpiece and inserts the sum back at the lane's position.
        let body = function.get_block(base + 12).expect("vector body");
        let loaded = body
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Load { dst, .. } if dst.size == 16 => Some(dst.clone()),
                _ => None,
            })
            .expect("wide vector load");
        let lane_reads_of = |source: &dyn Fn(&SSAVar) -> bool| {
            body.ops
                .iter()
                .filter_map(|op| match op {
                    SSAOp::Subpiece { src, offset, dst } if source(src) && dst.size == 4 => {
                        Some(*offset)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(lane_reads_of(&|src| *src == loaded), vec![0, 4, 8, 12]);
        assert_eq!(lane_reads_of(&accumulator), vec![0, 4, 8, 12]);
        let insert_positions = body
            .ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::Insert {
                    dst,
                    src,
                    value,
                    position,
                } if accumulator(dst) && accumulator(src) && value.size == 4 => {
                    position.constant_bits()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(insert_positions, vec![0, 32, 64, 96]);

        // The exit reads the low lane of the merged accumulator.
        let exit = function.get_block(base + 8).expect("loop exit");
        assert!(exit.ops.iter().any(|op| matches!(
            op,
            SSAOp::Subpiece { dst, src, offset: 0 } if dst.size == 4 && *src == phi.dst
        )));
        assert!(
            !function
                .blocks()
                .flat_map(|block| &block.ops)
                .any(|op| matches!(op, SSAOp::Piece { .. }))
        );
    }

    #[test]
    fn decompile_artifact_two_address_stack_updates_read_incoming_versions() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::new("rip", 32, 8));
        let rsp = make_reg(16, 8);
        let rbp = make_reg(24, 8);
        let rip = make_reg(32, 8);
        let saved_fp = make_unique(0x10, 8);
        let restored_fp = make_unique(0x18, 8);
        let return_target = make_unique(0x20, 8);
        let blocks = [R2ILBlock {
            addr: 0x1000,
            size: 9,
            ops: vec![
                R2ILOp::Copy {
                    dst: saved_fp.clone(),
                    src: rbp.clone(),
                },
                R2ILOp::IntSub {
                    dst: rsp.clone(),
                    a: rsp.clone(),
                    b: make_const(8, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: rsp.clone(),
                    val: saved_fp,
                },
                R2ILOp::Load {
                    dst: restored_fp.clone(),
                    space: SpaceId::Ram,
                    addr: rsp.clone(),
                },
                R2ILOp::IntAdd {
                    dst: rsp.clone(),
                    a: rsp.clone(),
                    b: make_const(8, 8),
                },
                R2ILOp::Copy {
                    dst: rbp,
                    src: restored_fp,
                },
                R2ILOp::Load {
                    dst: return_target.clone(),
                    space: SpaceId::Ram,
                    addr: rsp.clone(),
                },
                R2ILOp::IntAdd {
                    dst: rsp.clone(),
                    a: rsp,
                    b: make_const(8, 8),
                },
                R2ILOp::Copy {
                    dst: rip,
                    src: return_target,
                },
                R2ILOp::Return {
                    target: make_reg(32, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let interface = SourceFunctionInterface::new_exact(
            b"two-address-stack-updates".to_vec(),
            "sysv",
            [],
            crate::SourceFunctionReturn::Void,
            [],
        )
        .expect("exact source interface");
        let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("decompile SSA artifact");
        let updates = artifact
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::IntSub { dst, a, .. } | SSAOp::IntAdd { dst, a, .. }
                    if dst.name == "rsp" =>
                {
                    Some((dst.version, a.name.as_str(), a.version))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            updates,
            vec![(1, "rsp", 0), (2, "rsp", 1), (3, "rsp", 2)],
            "PUSH-, POP-, and RET-like SP updates must read the incoming SSA version"
        );
    }

    fn controlled_prep_blocks() -> Vec<R2ILBlock> {
        vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1004, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(8, 8),
                        src: make_reg(0, 8),
                    },
                    R2ILOp::Return {
                        target: make_ram(0, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ]
    }

    struct StopAtPoll {
        polls: Cell<usize>,
        stop_at: usize,
        cancellation: crate::SsaCancellationToken,
        execution: crate::SsaExecutionControl,
    }

    impl StopAtPoll {
        fn new(stop_at: usize) -> Self {
            let cancellation = crate::SsaCancellationToken::default();
            let execution = crate::SsaExecutionControl::with_cancellation(cancellation.clone());
            Self {
                polls: Cell::new(0),
                stop_at,
                cancellation,
                execution,
            }
        }
    }

    impl SsaWorkControl for StopAtPoll {
        fn poll(&self) -> Result<(), SsaExecutionStopReason> {
            let polls = self.polls.get() + 1;
            self.polls.set(polls);
            if polls == self.stop_at {
                self.cancellation.cancel();
            }
            self.execution.poll()
        }
    }

    #[test]
    fn checked_decompile_builder_reports_pre_cancelled() {
        let cancellation = crate::SsaCancellationToken::default();
        cancellation.cancel();
        let control = crate::SsaExecutionControl::with_cancellation(cancellation);

        let result =
            SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

        assert!(matches!(result, Err(SsaPrepareError::Cancelled)));
    }

    #[test]
    fn checked_decompile_builder_reports_expired_deadline() {
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond is representable");
        let control = crate::SsaExecutionControl::with_deadline(deadline);

        let result =
            SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

        assert!(matches!(result, Err(SsaPrepareError::DeadlineExceeded)));
        assert!(matches!(
            SsaArtifact::for_decompile_with_control(
                &[],
                None,
                &crate::SsaExecutionControl::default()
            ),
            Err(SsaPrepareError::MalformedInput)
        ));
    }

    #[test]
    fn checked_decompile_builder_observes_mid_dominator_worklist_cancellation() {
        // Polls 1-3 cover builder/CFG boundaries; poll 6 occurs while the
        // two-entry RPO index is being assembled by the dominator builder.
        let control = StopAtPoll::new(6);

        let result =
            SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

        assert!(matches!(result, Err(SsaPrepareError::Cancelled)));
        assert_eq!(control.polls.get(), 6);
    }

    /// An artifact built without an architecture names no user-operation.
    ///
    /// `SSAOp::CallOther` carries an index alone, and an index means nothing
    /// without the table it was assigned from. Returning `None` is what lets a
    /// consumer refuse; inventing a name, or matching the index against a
    /// hardcoded one, would make the answer depend on which architecture the
    /// caller happened to be holding.
    #[test]
    fn an_artifact_without_an_architecture_names_no_user_operation() {
        let blocks = controlled_prep_blocks();
        let artifact = SsaArtifact::for_decompile(&blocks, None).expect("artifact");
        assert_eq!(artifact.user_operation_name(0), None);
        assert_eq!(artifact.user_operation_name(u32::MAX), None);
    }

    #[test]
    fn unchecked_and_controlled_decompile_builders_produce_identical_artifacts() {
        let blocks = controlled_prep_blocks();
        let unchecked = SsaArtifact::for_decompile(&blocks, None).expect("unchecked artifact");
        let controlled = SsaArtifact::for_decompile_with_control(
            blocks.as_slice(),
            None,
            &crate::SsaExecutionControl::default(),
        )
        .expect("controlled artifact");

        assert_eq!(unchecked.mode(), controlled.mode());
        assert_eq!(
            unchecked.function().block_addrs(),
            controlled.function().block_addrs()
        );
        for (lhs, rhs) in unchecked
            .function()
            .blocks()
            .zip(controlled.function().blocks())
        {
            assert_eq!(lhs.addr, rhs.addr);
            assert_eq!(lhs.size, rhs.size);
            assert_eq!(lhs.ops, rhs.ops);
            assert_eq!(lhs.phis.len(), rhs.phis.len());
            for (lhs_phi, rhs_phi) in lhs.phis.iter().zip(&rhs.phis) {
                assert_eq!(lhs_phi.dst, rhs_phi.dst);
                assert_eq!(lhs_phi.sources, rhs_phi.sources);
                assert_eq!(lhs_phi.canonical_storage, rhs_phi.canonical_storage);
            }
        }
        assert_eq!(
            unchecked.function().decompile_prep_facts(),
            controlled.function().decompile_prep_facts()
        );
        assert_eq!(unchecked.graph(), controlled.graph());
        assert_eq!(unchecked.facts(), controlled.facts());
        assert_eq!(unchecked.machine_context(), controlled.machine_context());
    }

    #[test]
    fn test_ssa_function_linear() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
        assert_eq!(func.entry, 0x1000);
        assert_eq!(func.num_blocks(), 2);

        // Check that entry block has the copy operations
        let entry = func.entry_block().unwrap();
        assert_eq!(entry.num_ops(), 2);
        assert!(!entry.has_phis());
    }

    #[test]
    fn a_lane_read_is_a_subpiece_of_the_root_it_reads() {
        let arch = make_arm64_alias_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0x88, 8),
                    src: make_const(0xdead, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x4000, 8),
                    val: make_reg(0x88, 4),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let func = SSAFunction::from_blocks_raw(&blocks, Some(&arch)).expect("raw SSA");
        let ops = &func.entry_block().expect("entry block").ops;
        let stored = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Store { val, .. } => Some(val.clone()),
                _ => None,
            })
            .expect("store");
        assert!(
            ops.iter().any(|op| matches!(
                op,
                SSAOp::Subpiece { dst, src, offset: 0 }
                    if *dst == stored
                        && src.name.eq_ignore_ascii_case("x9")
                        && src.version == 1
                        && src.size == 8
            )),
            "the lane read is a subpiece of the written root: {ops:?}"
        );
    }

    #[test]
    fn a_lane_read_of_a_constant_root_is_the_constant() {
        let arch = make_arm64_alias_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0x88, 8),
                    src: make_const(0xdead, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x4000, 8),
                    val: make_reg(0x88, 4),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let func =
            SSAFunction::from_blocks_for_decompile(&blocks, Some(&arch)).expect("decompile SSA");
        let store = func
            .entry_block()
            .expect("entry block")
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Store { val, .. } => Some(val),
                _ => None,
            })
            .expect("observable store");
        let stored = func
            .entry_block()
            .expect("entry block")
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Copy { dst, src } if dst == store => Some(src.clone()),
                _ => None,
            })
            .unwrap_or_else(|| store.clone());
        assert_eq!(stored, SSAVar::constant(0xdead, 4));
    }

    #[test]
    fn prepared_function_ssa_tracks_mode_and_keeps_named_blocks() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch))
            .expect("prepared SSA should build")
            .with_name("prepared_demo");

        assert_eq!(prepared.mode(), FunctionPrepareMode::Decompile);
        assert_eq!(prepared.name.as_deref(), Some("prepared_demo"));
        assert!(
            prepared.decompile_prep_facts().is_some(),
            "decompile preparation should retain prep facts"
        );

        let local_blocks = prepared.local_ssa_blocks();
        assert_eq!(local_blocks.len(), 1);
        assert_eq!(local_blocks[0].addr, 0x1000);
        assert_eq!(
            local_blocks[0].ops,
            prepared.blocks().next().expect("entry block").ops
        );

        let symbolic = SsaArtifact::for_symbolic(&blocks, Some(&arch))
            .expect("symbolic prepared SSA should build");
        assert_eq!(symbolic.mode(), FunctionPrepareMode::Symbolic);
        assert!(
            symbolic.decompile_prep_facts().is_some(),
            "symbolic preparation should retain canonical prep facts for shared consumers"
        );
    }

    #[test]
    fn prepared_function_ssa_refuses_display_named_stack_object_facts() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1100,
                size: 4,
                ops: vec![
                    R2ILOp::IntSub {
                        dst: Varnode {
                            space: SpaceId::Unique,
                            offset: 0x10,
                            size: 8,
                            meta: None,
                        },
                        a: make_reg(24, 8),
                        b: make_const(0x20, 8),
                    },
                    R2ILOp::Load {
                        dst: make_reg(0, 8),
                        space: SpaceId::Ram,
                        addr: Varnode {
                            space: SpaceId::Unique,
                            offset: 0x10,
                            size: 8,
                            meta: None,
                        },
                    },
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: make_const(0x4040, 8),
                        val: make_reg(0, 8),
                    },
                    R2ILOp::IntEqual {
                        dst: make_reg(8, 1),
                        a: make_reg(0, 8),
                        b: make_const(0, 8),
                    },
                    R2ILOp::CBranch {
                        target: make_const(0x1108, 8),
                        cond: make_reg(8, 1),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1104,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1108,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");

        assert!(prepared.objects().stack_objects.is_empty());
        assert!(
            prepared
                .objects()
                .global_objects
                .iter()
                .any(|(key, _)| key.address == 0x4040),
            "constant RAM address should seed a global object"
        );

        let entry = prepared.get_block(0x1100).expect("entry block");
        let load_ref = SliceOpRef::Op {
            block_addr: 0x1100,
            op_idx: 1,
        };
        let store_ref = SliceOpRef::Op {
            block_addr: 0x1100,
            op_idx: 2,
        };
        let load_inst = prepared
            .graph()
            .inst_id_for_op_site(load_ref.block_addr(), 1)
            .expect("load inst");
        let store_inst = prepared
            .graph()
            .inst_id_for_op_site(store_ref.block_addr(), 2)
            .expect("store inst");
        assert!(
            prepared.memory().uses_by_inst.contains_key(&load_inst),
            "load should read through MemorySSA facts"
        );
        assert!(
            prepared.memory().defs_by_inst.contains_key(&store_inst),
            "store should define a new memory version"
        );
        // The flag is a lane of `rbx`: its write inserts into the root and
        // the branch's read is a subpiece of it.
        assert_eq!(entry.ops.len(), 7);

        assert_eq!(prepared.predicates().predicates.len(), 1);
        let predicate = prepared
            .predicates()
            .predicates
            .values()
            .next()
            .expect("branch predicate");
        assert_eq!(predicate.block_addr, 0x1100);
        assert_eq!(predicate.true_target, 0x1108);
        assert_eq!(predicate.false_target, 0x1104);
        assert_eq!(
            predicate.comparison.as_ref().map(|cmp| cmp.kind),
            Some(crate::semantic::CompareKind::Equal)
        );
        assert!(
            prepared
                .predicates()
                .block_assumptions
                .contains_key(&0x1104)
        );
        assert!(
            prepared
                .predicates()
                .block_assumptions
                .contains_key(&0x1108)
        );
    }

    #[test]
    fn ssa_artifact_exposes_typed_graph_queries() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1080,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(0x33, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let artifact = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("artifact");
        let graph = artifact.graph();
        let value = artifact
            .blocks()
            .next()
            .and_then(|block| block.ops.first())
            .and_then(|op| op.dst())
            .cloned()
            .expect("destination value");
        let value_id = graph.value_id_for_var(&value).expect("value id");
        let def_inst = graph.def_inst(value_id).expect("definition");
        let use_sites = graph.use_sites(value_id);

        assert_eq!(
            graph.value(value_id).expect("value").var,
            value,
            "graph should retain render metadata for each typed value"
        );
        assert_eq!(
            graph.inst(def_inst).expect("inst").output,
            Some(value_id),
            "def_of should point back to the defining instruction"
        );
        assert_eq!(
            use_sites.len(),
            1,
            "return should consume the copied value once"
        );
    }

    #[test]
    fn prepared_function_refuses_return_without_source_boundary_authority() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1010, 8),
                    cond: make_reg(8, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1014, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1010,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1014, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1014,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        assert!(prepared.certificates().returns.is_empty());
        assert!(prepared.return_certificate_for_op(0x1014, 0).is_none());
        assert!(prepared.return_certificate_for_op(0x1004, 0).is_none());
        assert!(prepared.return_certificate_for_op(0x1010, 0).is_none());
    }

    #[test]
    fn prepared_function_does_not_infer_return_phi_without_source_boundary_authority() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1100,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1110, 8),
                    cond: make_reg(8, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1104,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(7, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1114, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1110,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(7, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1114, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1114,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        assert!(prepared.certificates().returns.is_empty());
        assert!(prepared.return_certificate_for_op(0x1114, 0).is_none());
    }

    #[test]
    fn prepared_function_does_not_infer_memory_backed_return_phi() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1200,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1210, 8),
                    cond: make_reg(8, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1204,
                size: 4,
                ops: vec![
                    R2ILOp::Load {
                        dst: make_reg(0, 4),
                        space: r2il::SpaceId::Ram,
                        addr: make_reg(8, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1214, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1210,
                size: 4,
                ops: vec![
                    R2ILOp::Load {
                        dst: make_reg(0, 4),
                        space: r2il::SpaceId::Ram,
                        addr: make_reg(8, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1214, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1214,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 4),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        assert!(prepared.certificates().returns.is_empty());
        assert!(prepared.return_certificate_for_op(0x1214, 0).is_none());
    }

    #[test]
    fn prepared_function_refuses_display_named_stack_reload_at_control_return() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::new("rip", 0x30, 8));
        let slot = make_unique(0x1880, 8);
        let stored = make_unique(0x1888, 8);
        let blocks = vec![
            R2ILBlock {
                addr: 0x1880,
                size: 4,
                ops: vec![
                    R2ILOp::IntAdd {
                        dst: slot.clone(),
                        a: make_reg(24, 8),
                        b: make_const(u64::MAX - 7, 8),
                    },
                    R2ILOp::Call {
                        target: make_const(0x401000, 8),
                    },
                    R2ILOp::Copy {
                        dst: stored.clone(),
                        src: make_reg(0, 8),
                    },
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: slot.clone(),
                        val: stored,
                    },
                    R2ILOp::Load {
                        dst: make_reg(0, 8),
                        space: SpaceId::Ram,
                        addr: slot,
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1890, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1890,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0x30, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        let return_op_idx = prepared
            .function()
            .get_block(0x1890)
            .and_then(|block| {
                block
                    .ops
                    .iter()
                    .position(|op| matches!(op, SSAOp::Return { target } if target.name.eq_ignore_ascii_case("rip")))
            })
            .expect("control return op");
        assert!(
            prepared
                .return_certificate_for_op(0x1890, return_op_idx)
                .is_none()
        );
    }

    #[test]
    fn prepared_function_refuses_display_named_stack_merge_at_control_return() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::new("rip", 0x30, 8));
        let slot = make_unique(0x1900, 8);
        let cmp_load = make_unique(0x1908, 8);
        let cond = make_unique(0x1910, 1);
        let blocks = vec![
            R2ILBlock {
                addr: 0x1900,
                size: 4,
                ops: vec![
                    R2ILOp::IntAdd {
                        dst: slot.clone(),
                        a: make_reg(24, 8),
                        b: make_const(u64::MAX - 7, 8),
                    },
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: slot.clone(),
                        val: make_reg(8, 8),
                    },
                    R2ILOp::Load {
                        dst: cmp_load.clone(),
                        space: SpaceId::Ram,
                        addr: slot.clone(),
                    },
                    R2ILOp::IntEqual {
                        dst: cond.clone(),
                        a: cmp_load,
                        b: make_const(0, 8),
                    },
                    R2ILOp::CBranch {
                        target: make_const(0x1908, 8),
                        cond,
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1904,
                size: 4,
                ops: vec![
                    R2ILOp::Load {
                        dst: make_reg(0, 8),
                        space: SpaceId::Ram,
                        addr: slot,
                    },
                    R2ILOp::Branch {
                        target: make_const(0x190c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1908,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(0, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x190c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x190c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0x30, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        let return_op_idx = prepared
            .function()
            .get_block(0x190c)
            .and_then(|block| {
                block
                    .ops
                    .iter()
                    .position(|op| matches!(op, SSAOp::Return { target } if target.name.eq_ignore_ascii_case("rip")))
            })
            .expect("control return op");
        assert!(
            prepared
                .return_certificate_for_op(0x190c, return_op_idx)
                .is_none()
        );
    }

    #[test]
    fn ssa_artifact_graph_ids_are_deterministic() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1200,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1204,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let first = SsaArtifact::raw(&blocks, None).expect("first artifact");
        let second = SsaArtifact::raw(&blocks, None).expect("second artifact");

        assert_eq!(
            first.graph(),
            second.graph(),
            "graph ids should be stable across builds"
        );
    }

    #[test]
    fn prepared_function_ssa_collects_call_sites_and_memory_effects() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1200,
                size: 4,
                ops: vec![R2ILOp::Call {
                    target: make_const(0x401000, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1204,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
        let call = prepared
            .call_sites()
            .by_id
            .values()
            .next()
            .expect("call site fact");
        assert_eq!(call.direct_target, Some(0x401000));
        assert_eq!(call.fallthrough, Some(0x1204));
        assert_eq!(
            call.memory_effect,
            crate::semantic::CallMemoryEffect::Unknown
        );

        let call_ref = call.at;
        let uses = prepared
            .memory()
            .uses_by_inst
            .get(&call_ref)
            .expect("call memory use fact");
        let defs = prepared
            .memory()
            .defs_by_inst
            .get(&call_ref)
            .expect("call memory def fact");
        assert_eq!(uses.len(), 1);
        assert_eq!(defs.len(), 1);
        assert_eq!(uses[0].location.object, defs[0].location.object);
        assert_eq!(
            prepared
                .objects()
                .object(uses[0].location.object)
                .map(|fact| &fact.kind),
            Some(&crate::semantic::ObjectKind::EscapedUnknown {
                space: r2il::SpaceId::Ram,
            })
        );
    }

    /// One call, two calls, three: the stack pointer is where it started.
    ///
    /// Sleigh lifts an x86-64 `call` as `RSP = RSP - 8` and the store of the
    /// return address. The callee's `ret` puts the eight back, and the callee
    /// is not in this function, so before the convention said so nothing did:
    /// a function with one call grew a phantom slot at entry - 16, with two at
    /// entry - 24, with three at entry - 32. Offsets taken after a call then
    /// named a slot that does not exist, or worse, one that does and holds
    /// something else.
    #[test]
    fn a_call_leaves_the_stack_pointer_where_the_convention_says_it_found_it() {
        let arch = make_x86_64_prep_arch();
        let sp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let ra_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 24,
            size: 8,
        };
        let rsp = make_reg(16, 8);

        // Three calls, each lifted the way Sleigh lifts one: the return
        // address pushed, then the transfer. Every operation carries the
        // instruction it came from, because that is what says where one call
        // instruction's stack traffic ends.
        let mut ops = Vec::new();
        let mut op_metadata = std::collections::BTreeMap::new();
        for index in 0..3u64 {
            let instr_addr = 0x4000 + index * 5;
            let first = ops.len();
            ops.push(R2ILOp::IntSub {
                dst: rsp.clone(),
                a: rsp.clone(),
                b: make_const(8, 8),
            });
            ops.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: rsp.clone(),
                val: make_const(instr_addr + 5, 8),
            });
            ops.push(R2ILOp::Call {
                target: make_ram(0x401000, 8),
            });
            for op_index in first..ops.len() {
                op_metadata.insert(
                    op_index,
                    r2il::OpMetadata {
                        instruction_addr: Some(instr_addr),
                        ..Default::default()
                    },
                );
            }
        }
        let last = ops.len();
        ops.push(R2ILOp::Return {
            target: make_const(0, 8),
        });
        op_metadata.insert(
            last,
            r2il::OpMetadata {
                instruction_addr: Some(0x400f),
                ..Default::default()
            },
        );

        let blocks = vec![R2ILBlock {
            addr: 0x4000,
            size: 16,
            ops,
            switch_info: None,
            op_metadata,
        }];

        let interface = SourceFunctionInterface::new_exact(
            b"call-chain-stack-pointer".to_vec(),
            "sysv",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("exact interface")
        .with_return_address_storage(ra_storage)
        .expect("return-address carrier")
        .with_stack_pointer_storage(sp_storage)
        .expect("stack-pointer carrier")
        .with_preserved_call_carriers(true, true);

        let prepared = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("prepared SSA should build");
        let function = prepared.function();
        let facts = function.decompile_prep_facts().expect("prep facts");
        let block = function.get_block(0x4000).expect("entry block");

        // The projection is the layer a new operation is most easily missed
        // in: three separate tables key on the operation kind, and all three
        // are needed before an entity exists for the restore's output. Two of
        // them refuse loudly and one -- the type table -- refuses as an entity
        // that was never built, which reads as a mismatch a long way from its
        // cause. Asserting it here costs nothing and is what the corpus took a
        // locked run to say.
        crate::machine::MachineFunction::from_artifact(&prepared)
            .expect("a restore is an ordinary machine expression");

        // Every restore the boundary states, in order. Three calls, three of
        // them, and the last one is what the return sees.
        let restored = block
            .ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::CallRestore { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            restored.len(),
            3,
            "each call restores the carrier once: {:?}",
            block.ops
        );

        for (index, dst) in restored.iter().enumerate() {
            assert_eq!(
                facts.entry_stack_address_root_of(dst).copied(),
                Some(StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: 0,
                }),
                "after call {index} the stack pointer is the entry stack pointer"
            );
        }

        // And nothing in the function ever offers a slot at the drifted
        // addresses the un-refunded pushes used to leave behind.
        let drifted = block
            .ops
            .iter()
            .filter_map(|op| op.dst())
            .filter_map(|dst| facts.entry_stack_address_root_of(dst).copied())
            .filter(|root| {
                root.base == StackAddressBase::StackPointer
                    && matches!(root.offset, -16 | -24 | -32)
            })
            .collect::<Vec<_>>();
        assert!(
            drifted.is_empty(),
            "no value addresses a slot the drift invented: {drifted:?}"
        );
    }

    #[test]
    fn decompile_ssa_models_post_call_arm64_return_register_clobber() {
        let arch = make_arm64_alias_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1400,
            size: 16,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0x00, 8),
                    src: make_const(0, 8),
                },
                R2ILOp::Call {
                    target: make_ram(0x401000, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(0x80, 8),
                    src: make_reg(0x00, 8),
                },
                R2ILOp::IntEqual {
                    dst: Varnode {
                        space: SpaceId::Unique,
                        offset: 0x20,
                        size: 1,
                        meta: None,
                    },
                    a: make_reg(0x80, 8),
                    b: make_const(0, 8),
                },
                R2ILOp::CBranch {
                    target: make_const(0x1410, 8),
                    cond: Varnode {
                        space: SpaceId::Unique,
                        offset: 0x20,
                        size: 1,
                        meta: None,
                    },
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        let ops = &prepared.get_block(0x1400).expect("entry block").ops;
        let post_call_x0 = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::CallDefine { dst } if dst.name == "x0" => Some(dst.clone()),
                _ => None,
            })
            .expect("decompile SSA should define a fresh x0 after calls");

        let copied_x8_source = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Copy { dst, src } if dst.name == "x8" => Some(src.clone()),
                _ => None,
            })
            .expect("expected x8 copy from call return register");

        assert_eq!(
            copied_x8_source, post_call_x0,
            "post-call x8 copy must use the fresh call result owner, not the pre-call x0"
        );
        assert_ne!(
            copied_x8_source,
            SSAVar::constant(0, 8),
            "call result must not fold back to the pre-call literal"
        );

        let x0_value = prepared
            .graph()
            .value_id_for_var(&post_call_x0)
            .expect("post-call x0 value");
        assert!(
            prepared
                .call_result_certificate_for_value(x0_value)
                .is_none()
        );

        let copied_x8_dst = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Copy { dst, src } if dst.name == "x8" && src == &post_call_x0 => {
                    Some(dst.clone())
                }
                _ => None,
            })
            .expect("expected x8 alias of the certified call result");
        let copied_x8_value = prepared
            .graph()
            .value_id_for_var(&copied_x8_dst)
            .expect("copied x8 value");
        assert!(
            prepared
                .call_result_certificate_for_value(copied_x8_value)
                .is_none()
        );

        for op in ops {
            if let SSAOp::CallDefine { dst } = op
                && dst.name == "x8"
            {
                let x8_call_define_value = prepared
                    .graph()
                    .value_id_for_var(dst)
                    .expect("x8 call-define value");
                assert!(
                    prepared
                        .call_result_certificate_for_value(x8_call_define_value)
                        .is_none(),
                    "caller-saved x8 clobber must not be certified as a return value"
                );
            }
        }
    }

    #[test]
    fn prepared_function_ssa_recovers_direct_call_target_from_ram_literal() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1300,
                size: 4,
                ops: vec![R2ILOp::Call {
                    target: make_ram(0x401239, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1304,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
        let call = prepared
            .call_sites()
            .by_id
            .values()
            .next()
            .expect("call site fact");
        assert_eq!(call.direct_target, Some(0x401239));
        assert_eq!(call.fallthrough, Some(0x1304));
    }

    #[test]
    fn symbolic_function_ssa_recovers_indirect_call_target_from_copied_ram_literal() {
        let tmp = Varnode {
            space: SpaceId::Unique,
            offset: 0x10,
            size: 8,
            meta: None,
        };
        let blocks = vec![
            R2ILBlock {
                addr: 0x1310,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: tmp.clone(),
                        src: make_ram(0x1400a6010, 8),
                    },
                    R2ILOp::CallInd { target: tmp },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1314,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared =
            SsaArtifact::for_symbolic(&blocks, None).expect("symbolic prepared SSA should build");
        let call = prepared
            .call_sites()
            .by_id
            .values()
            .next()
            .expect("call site fact");
        assert_eq!(call.direct_target, Some(0x1400a6010));
        assert_eq!(call.fallthrough, Some(0x1314));
    }

    #[test]
    fn resolved_call_target_uses_canonical_copied_const_root_when_fact_is_unresolved() {
        let tmp = Varnode {
            space: SpaceId::Unique,
            offset: 0x10,
            size: 8,
            meta: None,
        };
        let blocks = vec![R2ILBlock {
            addr: 0x1310,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: tmp.clone(),
                    src: make_const(0x401050, 8),
                },
                R2ILOp::CallInd { target: tmp },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared =
            SsaArtifact::for_symbolic(&blocks, None).expect("symbolic prepared SSA should build");
        let call = prepared
            .call_sites()
            .by_id
            .values()
            .next()
            .expect("call site fact");
        assert_eq!(call.direct_target, Some(0x401050));
        assert_eq!(prepared.resolved_call_target(call), Some(0x401050));

        let mut unresolved_fact = call.clone();
        unresolved_fact.direct_target = None;
        assert_eq!(
            prepared.resolved_call_target(&unresolved_fact),
            Some(0x401050),
            "resolved call target must use the prepared canonical copied const root"
        );
    }

    #[test]
    fn prepared_function_ssa_builds_memory_phis_per_object() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1300,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1308, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1304,
                size: 4,
                ops: vec![
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: make_const(0x5000, 8),
                        val: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x130c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1308,
                size: 4,
                ops: vec![R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                    val: make_const(2, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x130c,
                size: 4,
                ops: vec![
                    R2ILOp::Load {
                        dst: make_reg(0, 8),
                        space: SpaceId::Ram,
                        addr: make_const(0x5000, 8),
                    },
                    R2ILOp::Return {
                        target: make_reg(0, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
        let phis = prepared
            .memory()
            .phis_by_block
            .get(&0x130c)
            .expect("merge-block memory phi");
        assert_eq!(phis.len(), 1);
        assert_eq!(phis[0].inputs.len(), 2);

        let load_ref = SliceOpRef::Op {
            block_addr: 0x130c,
            op_idx: 0,
        };
        let load_inst = prepared
            .graph()
            .inst_id_for_op_site(load_ref.block_addr(), 0)
            .expect("load inst");
        let load_use = prepared
            .memory()
            .uses_by_inst
            .get(&load_inst)
            .and_then(|facts| facts.first())
            .expect("load use");
        assert_eq!(load_use.version, phis[0].output_version);
    }

    #[test]
    fn prepared_function_ssa_collects_structured_dataflow_facts() {
        let loop_blocks = vec![
            R2ILBlock {
                addr: 0x1400,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1408, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1404,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1408,
                size: 4,
                ops: vec![
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: make_const(0x5000, 8),
                        val: make_const(7, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1400, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared = SsaArtifact::raw(&loop_blocks, None).expect("prepared SSA should build");
        let structured = prepared.structured();
        let loop_fact = structured.loops.values().next().expect("natural loop fact");
        assert_eq!(structured.loops.len(), 1);
        assert_eq!(loop_fact.header, 0x1400);
        assert_eq!(loop_fact.latches, vec![0x1408]);
        assert_eq!(loop_fact.exits, vec![0x1404]);
        assert!(loop_fact.body.contains(&0x1400));
        assert!(loop_fact.body.contains(&0x1408));
        assert!(loop_fact.condition.is_some());
        assert!(structured.memory_accesses.values().any(|access| {
            access.block_addr == 0x1408 && access.op_index == 0 && access.is_write
        }));
        let certificates = prepared.certificates();
        assert_eq!(certificates.loops.len(), 1);
        assert!(certificates.switches.is_empty());
        assert!(!certificates.expressions.is_empty());
        assert_eq!(
            certificates.memory_accesses.len(),
            structured.memory_accesses.len()
        );
        assert!(certificates.returns.is_empty());

        let recursive_blocks = vec![
            R2ILBlock {
                addr: 0x1500,
                size: 4,
                ops: vec![R2ILOp::Call {
                    target: make_const(0x1500, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1504,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let recursive =
            SsaArtifact::raw(&recursive_blocks, None).expect("recursive SSA should build");
        let call = recursive
            .structured()
            .recursive_calls
            .values()
            .next()
            .expect("recursive call fact");
        assert_eq!(recursive.structured().recursive_calls.len(), 1);
        assert_eq!(call.block_addr, 0x1500);
        assert_eq!(call.target, 0x1500);
    }

    /// A machine, a convention and a callsite whose prototype names two
    /// parameters. The second is optionally the radare2-identified format.
    fn variadic_format_call_artifact(
        defined: usize,
        variadic: bool,
        format_parameter: Option<u32>,
        format: Option<&str>,
    ) -> SsaArtifact {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
            arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
        }
        let slot = |index: usize| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: (index as u64) * 8,
            size: 8,
        };

        let mut ops = (0..defined)
            .map(|index| R2ILOp::Copy {
                dst: make_reg((index as u64) * 8, 8),
                src: make_const(
                    if u32::try_from(index).ok() == format_parameter {
                        0x3000
                    } else {
                        0x10 + index as u64
                    },
                    8,
                ),
            })
            .collect::<Vec<_>>();
        let call_index = ops.len();
        ops.push(R2ILOp::Call {
            target: make_const(0x2000, 8),
        });
        ops.push(R2ILOp::Return {
            target: make_const(0, 8),
        });
        let mut block = R2ILBlock {
            addr: 0x1600,
            size: 4,
            ops,
            switch_info: None,
            op_metadata: Default::default(),
        };
        block.stamp_instruction(call_index, 0x1600 + call_index as u64);
        let blocks = vec![block];

        let mut interface = SourceCallSiteInterface::new(
            b"variadic-tail".to_vec(),
            SourceCallSiteIdentity::new(
                0x1600 + call_index as u64,
                CanonicalStorageId {
                    space: CanonicalStorageSpace::Constant,
                    offset: 0x2000,
                    size: 8,
                },
            ),
            true,
            "amd64",
            [
                SourceCallArgumentSpec::new(0, slot(0)),
                SourceCallArgumentSpec::new(1, slot(1)),
            ],
            variadic,
            false,
            SourceCallResult::Void,
        )
        .expect("exact callsite interface");
        if let Some(index) = format_parameter {
            interface = interface
                .with_radare2_format_parameter(index)
                .expect("format parameter belongs to the fixed prefix");
        }
        let convention =
            SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
                .expect("convention slots");
        let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(convention),
            vec![interface],
        );
        if let Some(format) = format {
            machine_context.bind_source_string_literals(&[(0x3000, format.to_string())]);
        }
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            &blocks,
            Some(&arch),
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleePreservedCarriers::new(),
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("decompile SSA");
        SsaArtifact::new_with_context(function, FunctionPrepareMode::Decompile, machine_context)
    }

    /// A call whose format argument is a merge of two literals.
    ///
    /// The compiler that folded two `fprintf` calls into one left exactly this
    /// shape, and the count is a property of the format rather than of the
    /// path that chose it.
    fn merged_format_call(first: &str, second: &str) -> CallsiteCertificate {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
            arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
        }
        let slot = |index: usize| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: (index as u64) * 8,
            size: 8,
        };
        let mut join = R2ILBlock {
            addr: 0x1014,
            size: 4,
            ops: vec![
                R2ILOp::Call {
                    target: make_const(0x2000, 8),
                },
                R2ILOp::Return {
                    target: make_const(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        };
        join.stamp_instruction(0, 0x1014);
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(0x10, 8),
                    },
                    R2ILOp::CBranch {
                        target: make_const(0x1010, 8),
                        cond: make_reg(24, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(8, 8),
                        src: make_const(0x3000, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1014, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1010,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(8, 8),
                        src: make_const(0x3010, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1014, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            join,
        ];

        let interface = SourceCallSiteInterface::new(
            b"merged-format".to_vec(),
            SourceCallSiteIdentity::new(
                0x1014,
                CanonicalStorageId {
                    space: CanonicalStorageSpace::Constant,
                    offset: 0x2000,
                    size: 8,
                },
            ),
            true,
            "amd64",
            [
                SourceCallArgumentSpec::new(0, slot(0)),
                SourceCallArgumentSpec::new(1, slot(1)),
            ],
            true,
            false,
            SourceCallResult::Void,
        )
        .expect("exact callsite interface")
        .with_radare2_format_parameter(1)
        .expect("format parameter belongs to the fixed prefix");
        let convention =
            SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
                .expect("convention slots");
        let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(convention),
            vec![interface],
        );
        machine_context.bind_source_string_literals(&[
            (0x3000, first.to_string()),
            (0x3010, second.to_string()),
        ]);
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            &blocks,
            Some(&arch),
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleePreservedCarriers::new(),
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("decompile SSA");
        SsaArtifact::new_with_context(function, FunctionPrepareMode::Decompile, machine_context)
            .callsite_certificate_for_op(0x1014, 0)
            .expect("callsite certificate")
            .clone()
    }

    #[test]
    fn merged_formats_that_agree_prove_the_variadic_count() {
        let call = merged_format_call("opened %d", "closed %d");
        let evidence = call
            .variadic_argument_count_evidence
            .expect("merged literal count");
        assert_eq!(
            evidence.source,
            crate::VariadicCallsiteArgumentCountSource::Radare2MergedFormatStrings
        );
        assert_eq!(evidence.format_argument_index, 1);
        assert_eq!(evidence.format_consumed_argument_count, 1);
        assert_eq!(evidence.total_argument_count, 3);
        assert!(call.variadic_argument_count_refusal.is_none());
    }

    #[test]
    fn merged_formats_that_disagree_prove_nothing() {
        let call = merged_format_call("opened %d", "closed %d as %s");
        assert!(call.variadic_argument_count_evidence.is_none());
        assert_eq!(
            call.variadic_argument_count_refusal,
            Some(crate::VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral)
        );
    }

    fn variadic_format_call(
        defined: usize,
        variadic: bool,
        format_parameter: Option<u32>,
        format: Option<&str>,
    ) -> CallsiteCertificate {
        variadic_format_call_artifact(defined, variadic, format_parameter, format)
            .callsite_certificate_for_op(0x1600, defined)
            .expect("callsite certificate")
            .clone()
    }

    #[test]
    fn a_variadic_call_uses_its_literal_format_not_written_scratch_registers() {
        let no_tail = variadic_format_call(4, true, Some(1), Some("complete: 100%%"));
        assert_eq!(no_tail.argument_values.len(), 2);
        assert_eq!(no_tail.fixed_argument_count, Some(2));
        assert_eq!(
            no_tail
                .variadic_argument_count_evidence
                .expect("literal count evidence")
                .format_consumed_argument_count,
            0
        );

        let width_and_value = variadic_format_call(4, true, Some(1), Some("%*d"));
        assert_eq!(width_and_value.argument_values.len(), 4);
        assert_eq!(
            width_and_value
                .variadic_argument_count_evidence
                .expect("literal count evidence")
                .format_consumed_argument_count,
            2
        );

        let first_parameter_is_format = variadic_format_call(3, true, Some(0), Some("%u"));
        assert_eq!(first_parameter_is_format.argument_values.len(), 3);
        assert_eq!(
            first_parameter_is_format
                .variadic_argument_count_evidence
                .expect("literal count evidence")
                .format_argument_index,
            0
        );
    }

    /// Two sites reaching one variadic callee keep separate literal-count
    /// evidence. Both sites write every convention register, so a result of
    /// four for either call would expose the old register-write guess.
    #[test]
    fn two_calls_to_one_variadic_callee_may_pass_different_counts() {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
            arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
        }
        let slot = |index: usize| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: (index as u64) * 8,
            size: 8,
        };
        let target = make_const(0x2000, 8);
        let first_call_index = 4;
        let second_call_index = 9;
        let mut blocks = vec![R2ILBlock {
            addr: 0x1680,
            size: 11,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_const(0x3000, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(16, 8),
                    src: make_const(2, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(24, 8),
                    src: make_const(3, 8),
                },
                R2ILOp::Call {
                    target: target.clone(),
                },
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(4, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_const(0x3010, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(16, 8),
                    src: make_const(5, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(24, 8),
                    src: make_const(6, 8),
                },
                R2ILOp::Call {
                    target: target.clone(),
                },
                R2ILOp::Return {
                    target: make_const(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        blocks[0].stamp_instruction(first_call_index, 0x1680 + first_call_index as u64);
        blocks[0].stamp_instruction(second_call_index, 0x1680 + second_call_index as u64);
        let interface = |op_index: usize| {
            SourceCallSiteInterface::new(
                b"same-variadic-callee".to_vec(),
                SourceCallSiteIdentity::new(
                    0x1680 + op_index as u64,
                    CanonicalStorageId::from_varnode(&target),
                ),
                true,
                "amd64",
                [
                    SourceCallArgumentSpec::new(0, slot(0)),
                    SourceCallArgumentSpec::new(1, slot(1)),
                ],
                true,
                false,
                SourceCallResult::Void,
            )
            .and_then(|interface| interface.with_radare2_format_parameter(1))
            .expect("exact variadic callsite interface")
        };
        let convention =
            SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
                .expect("convention slots");
        let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(convention),
            vec![interface(first_call_index), interface(second_call_index)],
        );
        machine_context.bind_source_string_literals(&[
            (0x3000, "%u:%u".to_string()),
            (0x3010, "complete: 100%%".to_string()),
        ]);
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            &blocks,
            Some(&arch),
            coherent_function_interface(&machine_context),
            machine_context.machine_roles().call_preserved_carriers(),
            machine_context.stack_pointer_carrier(),
            &CalleePreservedCarriers::new(),
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("decompile SSA");
        let artifact = SsaArtifact::new_with_context(
            function,
            FunctionPrepareMode::Decompile,
            machine_context,
        );

        let calls = artifact
            .certificates()
            .callsites
            .values()
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        let [first, second] = calls.as_slice() else {
            unreachable!("the callsite count was checked above")
        };
        assert_eq!(first.target, second.target);
        assert_eq!(first.fixed_argument_count, Some(2));
        assert_eq!(second.fixed_argument_count, Some(2));
        assert_eq!(first.argument_values.len(), 4);
        assert_eq!(second.argument_values.len(), 2);
        assert_eq!(
            first
                .variadic_argument_count_evidence
                .expect("first literal count")
                .format_literal_address,
            0x3000
        );
        assert_eq!(
            second
                .variadic_argument_count_evidence
                .expect("second literal count")
                .format_literal_address,
            0x3010
        );
    }

    #[test]
    fn variadic_calls_without_literal_format_evidence_refuse() {
        let no_format_role = variadic_format_call(4, true, None, Some("%d"));
        assert!(no_format_role.argument_values.is_empty());
        assert_eq!(
            no_format_role.variadic_argument_count_refusal,
            Some(crate::VariadicCallsiteArgumentCountRefusal::MissingFormatParameter)
        );

        let non_literal = variadic_format_call(4, true, Some(1), None);
        assert!(non_literal.argument_values.is_empty());
        assert_eq!(
            non_literal.variadic_argument_count_refusal,
            Some(crate::VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral)
        );
    }

    /// A callee that is not variadic takes what its prototype says, however
    /// many argument registers the caller happens to have written. Extending
    /// past the prototype there would be a claim about the callee, not an
    /// observation about the call.
    #[test]
    fn a_fixed_callee_takes_only_the_arguments_its_prototype_names() {
        let call = variadic_format_call(4, false, None, None);
        assert_eq!(call.argument_values.len(), 2);
        assert!(!call.variadic);
        assert_eq!(call.fixed_argument_count, Some(2));
    }

    #[test]
    fn source_declared_entry_parameter_flows_into_an_implicit_call_read() {
        let mut arch = ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("x0", 0x4000, 8));
        arch.add_register(RegisterDef::new("x30", 0x4100, 8));
        arch.add_register(RegisterDef::new("sp", 0x4200, 8));
        let argument_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0x4000,
            size: 8,
        };
        let return_address_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0x4100,
            size: 8,
        };
        let stack_pointer_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0x4200,
            size: 8,
        };
        let revision = b"preserved-entry-call-argument";
        let target = make_const(0x401000, 8);
        let mut blocks = [R2ILBlock {
            addr: 0x1600,
            size: 4,
            ops: vec![R2ILOp::Call {
                target: target.clone(),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        blocks[0].stamp_instruction(0, 0x1600);
        let function_interface = SourceFunctionInterface::new_exact(
            revision.to_vec(),
            "aapcs64",
            [SourceAbiParameterSpec::new(0, argument_storage)],
            SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address_storage))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer_storage))
        .expect("exact function interface");
        let call_interface = SourceCallSiteInterface::new(
            revision.to_vec(),
            SourceCallSiteIdentity::new(0x1600, CanonicalStorageId::from_varnode(&target)),
            true,
            "aapcs64",
            [SourceCallArgumentSpec::new(0, argument_storage)],
            false,
            false,
            SourceCallResult::Register {
                storage: argument_storage,
            },
        )
        .expect("exact callsite interface");

        let prepared = SsaArtifact::for_decompile_with_interfaces(
            &blocks,
            Some(&arch),
            Some(function_interface),
            vec![call_interface],
        )
        .expect("prepared SSA");
        assert!(prepared.machine_context().abi_model().is_coherent());
        let parameter = prepared
            .facts()
            .boundaries
            .parameters
            .get(&0)
            .expect("source formal parameter fact");
        assert_eq!(parameter.graph_storage, argument_storage);
        assert_eq!(prepared.graph().def_inst(parameter.value), None);
        assert_eq!(
            prepared
                .function()
                .decompile_prep_facts()
                .and_then(|facts| {
                    prepared
                        .graph()
                        .value(parameter.value)
                        .and_then(|value| facts.formal_parameter_of(&value.var))
                }),
            Some(0),
        );

        let boundary = prepared
            .facts()
            .boundaries
            .calls
            .get(&CallSiteId(0))
            .expect("source call boundary");
        assert!(boundary.complete);
        assert_eq!(
            boundary.arguments.as_slice(),
            [SourceCallArgumentFact {
                slot: CallBoundarySlot::Register {
                    index: 0,
                    storage: argument_storage,
                },
                value: SourceCallArgumentValue::Value(parameter.value),
            }]
        );
        let certificate = prepared
            .callsite_certificate_for_op(0x1600, 0)
            .expect("prepared callsite certificate");
        assert_eq!(certificate.argument_values, [parameter.value]);
        assert_eq!(certificate.argument_certificates.len(), 1);
        assert_eq!(certificate.argument_certificates[0].value, parameter.value);
        assert_eq!(certificate.argument_certificates[0].source_inst, None);
        let obligation = prepared
            .obligations()
            .obligations_for_inst(certificate.at)
            .find(|obligation| obligation.id.kind == crate::SemanticObligationKind::CallArgument)
            .expect("call argument obligation");
        assert_eq!(obligation.inputs, [parameter.value]);
    }

    #[test]
    fn prepared_certificates_index_call_args_memory_and_returns() {
        let mut arch = make_arm64_alias_arch();
        for register in &mut arch.registers {
            if register.offset == 0 {
                register.name = if register.size == 8 { "rdx" } else { "edx" }.to_string();
            }
        }
        let mut blocks = vec![R2ILBlock {
            addr: 0x1600,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(7, 8),
                },
                R2ILOp::Load {
                    dst: make_reg(0x80, 8),
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                },
                R2ILOp::Call {
                    target: make_const(0x2000, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        blocks[0].stamp_instruction(2, 0x1602);

        let argument_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let call_interface = SourceCallSiteInterface::new(
            b"renamed-register-call-args".to_vec(),
            SourceCallSiteIdentity::new(
                0x1602,
                CanonicalStorageId {
                    space: CanonicalStorageSpace::Constant,
                    offset: 0x2000,
                    size: 8,
                },
            ),
            true,
            "aapcs64",
            [SourceCallArgumentSpec::new(0, argument_storage)],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("exact callsite interface");
        let prepared = SsaArtifact::for_decompile_with_interfaces(
            &blocks,
            Some(&arch),
            None,
            vec![call_interface],
        )
        .expect("prepared SSA");
        let call = prepared
            .callsite_certificate_for_op(0x1600, 2)
            .expect("callsite certificate");
        assert_eq!(call.block_addr, 0x1600);
        assert_eq!(call.op_index, 2);
        assert_eq!(call.argument_values.len(), 1);
        let arg_value = call.argument_values[0];
        let arg = prepared.graph().value(arg_value).expect("arg value");
        assert_eq!(arg.canonical_storage, Some(argument_storage));
        let arg_source = prepared
            .graph()
            .def_inst(arg_value)
            .expect("register argument producer");
        let producer = prepared
            .graph()
            .inst(arg_source)
            .expect("argument producer");
        assert!(matches!(
            producer.payload,
            crate::graph::InstPayload::Op(SSAOp::Copy { .. })
        ));
        let [input] = producer.inputs.as_slice() else {
            panic!("register argument copy must have one exact input");
        };
        assert!(
            prepared
                .graph()
                .value(*input)
                .is_some_and(|value| value.var.constant_bits() == Some(7))
        );
        assert_eq!(call.argument_certificates.len(), 1);
        let typed_arg = &call.argument_certificates[0];
        assert_eq!(typed_arg.index, 0);
        assert_eq!(typed_arg.value, arg_value);
        assert_eq!(typed_arg.source_inst, Some(arg_source));
        match &typed_arg.location {
            CallArgumentLocation::Register { storage } => {
                assert_eq!(*storage, argument_storage)
            }
            CallArgumentLocation::Stack { .. } => {
                panic!("register argument should not be certified as stack")
            }
        }

        let memory = prepared
            .memory_certificate_for_op_site(0x1600, 1, false)
            .expect("memory certificate");
        assert_eq!(memory.block_addr, 0x1600);
        assert_eq!(memory.op_index, 1);
        assert!(!memory.is_write);

        let return_idx = prepared
            .function()
            .get_block(0x1600)
            .and_then(|block| {
                block
                    .ops
                    .iter()
                    .position(|op| matches!(op, SSAOp::Return { .. }))
            })
            .expect("return op index");
        assert!(
            prepared
                .return_certificate_for_op(0x1600, return_idx)
                .is_none()
        );

        let result = prepared
            .function()
            .get_block(0x1600)
            .and_then(|block| {
                block
                    .ops
                    .iter()
                    .enumerate()
                    .find_map(|(op_idx, op)| match op {
                        SSAOp::CallDefine { dst } => Some((op_idx, dst)),
                        _ => None,
                    })
            })
            .expect("post-call result op");
        assert!(
            prepared
                .call_result_certificate_for_op(0x1600, result.0)
                .is_none()
        );
        assert!(
            prepared
                .call_result_certificates_for_callsite(call.call_site)
                .is_empty()
        );
    }

    #[test]
    fn call_result_certificates_require_a_complete_machine_boundary() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![R2ILBlock {
            addr: 0x1680,
            size: 4,
            ops: vec![
                R2ILOp::Call {
                    target: make_const(0x401000, 8),
                },
                R2ILOp::Copy {
                    dst: make_unique(0x20, 8),
                    src: make_reg(0, 8),
                },
                R2ILOp::Call {
                    target: make_const(0x402000, 8),
                },
                R2ILOp::Copy {
                    dst: make_unique(0x30, 8),
                    src: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let first = SsaArtifact::for_decompile(&blocks, Some(&arch))
            .expect("first prepared SSA should build");
        let second = SsaArtifact::for_decompile(&blocks, Some(&arch))
            .expect("second prepared SSA should build");
        assert_eq!(
            first.certificates().call_results,
            second.certificates().call_results,
            "call-result certificates must be deterministic"
        );

        assert!(first.certificates().call_results.is_empty());
        assert!(first.certificates().call_results_by_callsite.is_empty());

        // With a convention boundary, a read of a contained return-register
        // lane is exact evidence for the result width even when the full
        // convention carrier itself has no reader. This is how an unknown
        // prototype returning in EAX is observed under an RAX result slot.
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::sub("eax", 0, 4, "rax"));
        let widened = make_unique(0x40, 8);
        let blocks = [R2ILBlock {
            addr: 0x16c0,
            size: 4,
            ops: vec![
                R2ILOp::Call {
                    target: make_const(0x403000, 8),
                },
                R2ILOp::IntZExt {
                    dst: widened.clone(),
                    src: make_reg(0, 4),
                },
                R2ILOp::Copy {
                    dst: make_unique(0x48, 8),
                    src: widened,
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let full_result = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let convention =
            SourceConventionSlots::new("amd64", [], Some(full_result)).expect("result convention");
        let prepared = SsaArtifact::for_decompile_with_interfaces_roles_and_convention(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(convention),
            Vec::new(),
        )
        .expect("prepared SSA with convention boundary");
        let call = prepared
            .callsite_certificate_for_op(0x16c0, 0)
            .expect("convention-certified call");
        // The call defines the root once; the lane the program reads is a
        // `Subpiece` of it, certified as that result sliced.
        let eax = prepared
            .function()
            .get_block(0x16c0)
            .into_iter()
            .flat_map(|block| &block.ops)
            .find_map(|op| match op {
                SSAOp::Subpiece {
                    dst,
                    src,
                    offset: 0,
                } if dst.size == 4 && src.name.eq_ignore_ascii_case("rax") => {
                    prepared.graph().value_id_for_var(dst)
                }
                _ => None,
            })
            .expect("post-call EAX lane read");
        let result = prepared
            .call_result_certificate_for_value(eax)
            .expect("observed return lane certificate");
        assert_eq!(result.call_site, call.call_site);
        assert_eq!(
            result.relation,
            crate::semantic::CallResultValueRelation::Derived
        );
        assert_eq!(result.width, 4);
        assert_eq!(
            result.carrier,
            crate::semantic::ReturnCarrier::Register {
                storage: full_result
            }
        );
    }

    #[test]
    fn prepared_call_result_refuses_display_named_stack_store_reload_owner() {
        let arch = make_x86_64_prep_arch();
        let slot = make_unique(0x1780, 8);
        let stored = make_unique(0x1788, 8);
        let loaded = make_unique(0x1790, 8);
        let alias = make_unique(0x1798, 8);
        let truncated = make_unique(0x17a0, 4);
        let blocks = vec![R2ILBlock {
            addr: 0x1780,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: slot.clone(),
                    a: make_reg(24, 8),
                    b: make_const(u64::MAX - 7, 8),
                },
                R2ILOp::Call {
                    target: make_const(0x401000, 8),
                },
                R2ILOp::Copy {
                    dst: stored.clone(),
                    src: make_reg(0, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: slot.clone(),
                    val: stored,
                },
                R2ILOp::Load {
                    dst: loaded.clone(),
                    space: SpaceId::Ram,
                    addr: slot,
                },
                R2ILOp::Copy {
                    dst: alias.clone(),
                    src: loaded.clone(),
                },
                R2ILOp::Subpiece {
                    dst: truncated.clone(),
                    src: loaded,
                    offset: 0,
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        let alias_var = prepared
            .function()
            .get_block(0x1780)
            .and_then(|block| {
                block.ops.iter().find_map(|op| match op {
                    SSAOp::Copy { dst, .. } if dst.name == "tmp:1798" => Some(dst.clone()),
                    _ => None,
                })
            })
            .expect("reloaded alias");
        let alias_value = prepared
            .graph()
            .value_id_for_var(&alias_var)
            .expect("alias value");
        assert!(
            prepared
                .call_result_certificate_for_value(alias_value)
                .is_none()
        );
        let truncated_var = prepared
            .function()
            .get_block(0x1780)
            .and_then(|block| {
                block.ops.iter().find_map(|op| match op {
                    SSAOp::Subpiece { dst, .. } if dst.name == "tmp:17a0" => Some(dst),
                    _ => None,
                })
            })
            .expect("truncated call-result value");
        assert!(
            prepared
                .graph()
                .value_id_for_var(truncated_var)
                .and_then(|value| prepared.call_result_certificate_for_value(value))
                .is_none()
        );
    }

    #[test]
    fn prepared_stack_reload_refuses_display_named_param_home() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::new("rsi", 32, 8));
        arch.add_register(RegisterDef::new("esi", 32, 4));

        let slot = make_unique(0x1820, 8);
        let loaded = make_unique(0x1828, 4);
        let extended = make_unique(0x1830, 8);
        let blocks = vec![R2ILBlock {
            addr: 0x1820,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: slot.clone(),
                    a: make_reg(24, 8),
                    b: make_const(0xffffffffffffffe0, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: slot.clone(),
                    val: make_reg(32, 4),
                },
                R2ILOp::Load {
                    dst: loaded.clone(),
                    space: SpaceId::Ram,
                    addr: slot,
                },
                R2ILOp::IntSExt {
                    dst: extended.clone(),
                    src: loaded,
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        assert!(
            prepared
                .stack_reload_certificate_for_op(0x1820, 2)
                .is_none()
        );

        let extended_value = prepared
            .graph()
            .value_id_for_var(&SSAVar::new("tmp:1830", 1, 8))
            .expect("extended index value");
        assert!(
            prepared
                .stack_reload_certificate_for_value(extended_value)
                .is_none()
        );
    }

    #[test]
    fn prepared_callsite_refuses_display_named_stack_home_arguments() {
        let arch = make_x86_64_prep_arch();
        let stack_home = Varnode {
            space: SpaceId::Unique,
            offset: 0x1740,
            size: 8,
            meta: None,
        };
        let blocks = vec![R2ILBlock {
            addr: 0x1740,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: stack_home.clone(),
                    a: make_reg(16, 8),
                    b: make_const(0x20, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: stack_home,
                    val: make_const(7, 8),
                },
                R2ILOp::Call {
                    target: make_const(0x401000, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let prepared =
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
        let call = prepared
            .callsite_certificate_for_op(0x1740, 2)
            .expect("callsite certificate");

        assert!(call.stack_argument_values.is_empty());
        assert!(
            call.argument_certificates
                .iter()
                .all(|argument| !matches!(argument.location, CallArgumentLocation::Stack { .. }))
        );
    }

    #[test]
    fn prepared_expression_certificates_require_structural_render_proof() {
        let pure_blocks = vec![R2ILBlock {
            addr: 0x1700,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(7, 8),
                },
                R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(1, 8),
                },
                R2ILOp::Return {
                    target: make_reg(8, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let pure = SsaArtifact::raw(&pure_blocks, None).expect("pure SSA");
        let pure_value = pure
            .graph()
            .inst_id_for_op_site(0x1700, 1)
            .and_then(|inst| pure.graph().inst(inst))
            .and_then(|inst| inst.output)
            .expect("pure expression output");
        assert!(
            pure.certificates()
                .expressions
                .get(&pure_value)
                .is_some_and(|cert| cert.renderable),
            "pure expression outputs should be renderable"
        );

        let load_blocks = vec![R2ILBlock {
            addr: 0x1710,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(0, 8),
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let loaded = SsaArtifact::raw(&load_blocks, None).expect("load SSA");
        let loaded_value = loaded
            .graph()
            .inst_id_for_op_site(0x1710, 0)
            .and_then(|inst| loaded.graph().inst(inst))
            .and_then(|inst| inst.output)
            .expect("load output");
        assert!(
            loaded
                .certificates()
                .expressions
                .get(&loaded_value)
                .is_some_and(|cert| cert.renderable),
            "memory-load expression outputs require a structured memory-read certificate"
        );

        let userop_out = Varnode {
            space: SpaceId::Unique,
            offset: 0x2222,
            size: 8,
            meta: None,
        };
        let userop_blocks = vec![R2ILBlock {
            addr: 0x1720,
            size: 4,
            ops: vec![
                R2ILOp::CallOther {
                    output: Some(userop_out.clone()),
                    userop: 99,
                    inputs: vec![make_reg(0, 8)],
                },
                R2ILOp::Return { target: userop_out },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let userop = SsaArtifact::raw(&userop_blocks, None).expect("userop SSA");
        let userop_value = userop
            .graph()
            .inst_id_for_op_site(0x1720, 0)
            .and_then(|inst| userop.graph().inst(inst))
            .and_then(|inst| inst.output)
            .expect("userop output");
        assert!(
            userop
                .certificates()
                .expressions
                .get(&userop_value)
                .is_some_and(|cert| !cert.renderable),
            "opaque userop outputs must not be renderable by width alone"
        );
    }

    #[test]
    fn prepared_return_register_subpiece_zext_chain_is_renderable() {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", 0x00, 8));
        arch.add_register(RegisterDef::new("eax", 0x00, 4));
        arch.add_register(RegisterDef::new("rsi", 0x10, 8));
        arch.add_register(RegisterDef::new("esi", 0x10, 4));
        arch.add_register(RegisterDef::new("rdx", 0x18, 8));
        arch.add_register(RegisterDef::new("edx", 0x18, 4));
        arch.add_register(RegisterDef::new("rip", 0x20, 8));

        let blocks = vec![R2ILBlock {
            addr: 0x1740,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: make_unique(0x4000, 8),
                    a: make_reg(0x18, 8),
                    b: make_reg(0x10, 8),
                },
                R2ILOp::Subpiece {
                    dst: make_reg(0x00, 4),
                    src: make_unique(0x4000, 8),
                    offset: 0,
                },
                R2ILOp::IntZExt {
                    dst: make_reg(0x00, 8),
                    src: make_reg(0x00, 4),
                },
                R2ILOp::Return {
                    target: make_reg(0x20, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA");
        let return_value = prepared
            .graph()
            .inst_id_for_op_site(0x1740, 2)
            .and_then(|inst| prepared.graph().inst(inst))
            .and_then(|inst| inst.output)
            .expect("zero-extended return-register value");

        let expr_cert = prepared
            .certificates()
            .expressions
            .get(&return_value)
            .expect("return value expression certificate");
        let input_debug = expr_cert
            .inputs
            .iter()
            .map(|value| {
                let name = prepared
                    .value_var(*value)
                    .map(|var| var.display_name())
                    .unwrap_or_else(|| "<unknown>".to_string());
                let renderable = prepared
                    .certificates()
                    .expressions
                    .get(value)
                    .is_some_and(|cert| cert.renderable);
                format!("{name}:{renderable}")
            })
            .collect::<Vec<_>>();
        let mut tmp_debug = Vec::new();
        for value in &expr_cert.inputs {
            if let Some(cert) = prepared.certificates().expressions.get(value) {
                let value_name = prepared
                    .value_var(*value)
                    .map(|var| var.display_name())
                    .unwrap_or_else(|| "<unknown>".to_string());
                for input in &cert.inputs {
                    let input_name = prepared
                        .value_var(*input)
                        .map(|var| var.display_name())
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let renderable = prepared
                        .certificates()
                        .expressions
                        .get(input)
                        .is_some_and(|cert| cert.renderable);
                    tmp_debug.push(format!("{value_name}->{input_name}:{renderable}"));
                }
            }
        }
        assert!(
            expr_cert.renderable,
            "return-register subpiece/zext chain should be renderable; ret={:?} inputs={:?} tmp_inputs={:?}",
            prepared.value_var(return_value),
            input_debug,
            tmp_debug
        );
    }

    #[test]
    fn prepared_return_certificates_require_complete_source_boundary() {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1760,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(7, 8),
                    },
                    R2ILOp::Branch {
                        target: Varnode::ram(0x1770, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1770,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(9, 8),
                    },
                    R2ILOp::Return {
                        target: make_reg(0, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA");

        assert!(prepared.certificates().returns.is_empty());
        assert!(prepared.return_certificate_for_op(0x1770, 1).is_none());
        assert!(
            prepared.return_certificate_for_op(0x1760, 0).is_none(),
            "a predecessor return-register write is dataflow, not a return effect"
        );
    }

    #[test]
    fn prepared_expression_certificates_render_only_identity_phis() {
        fn prepared_with_phi_values(left: u64, right: u64) -> SsaArtifact {
            let arch = make_x86_64_prep_arch();
            let blocks = vec![
                R2ILBlock {
                    addr: 0x1710,
                    size: 4,
                    ops: vec![R2ILOp::CBranch {
                        target: make_const(0x1724, 8),
                        cond: make_reg(8, 8),
                    }],
                    switch_info: None,
                    op_metadata: Default::default(),
                },
                R2ILBlock {
                    addr: 0x1714,
                    size: 4,
                    ops: vec![
                        R2ILOp::Copy {
                            dst: make_reg(0, 8),
                            src: make_const(left, 8),
                        },
                        R2ILOp::Branch {
                            target: make_const(0x1730, 8),
                        },
                    ],
                    switch_info: None,
                    op_metadata: Default::default(),
                },
                R2ILBlock {
                    addr: 0x1724,
                    size: 4,
                    ops: vec![
                        R2ILOp::Copy {
                            dst: make_reg(0, 8),
                            src: make_const(right, 8),
                        },
                        R2ILOp::Branch {
                            target: make_const(0x1730, 8),
                        },
                    ],
                    switch_info: None,
                    op_metadata: Default::default(),
                },
                R2ILBlock {
                    addr: 0x1730,
                    size: 4,
                    ops: vec![R2ILOp::Return {
                        target: make_reg(0, 8),
                    }],
                    switch_info: None,
                    op_metadata: Default::default(),
                },
            ];
            SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build")
        }

        let identity_phi = prepared_with_phi_values(7, 7);
        let identity_value = identity_phi
            .graph()
            .inst_id_for_op_site(0x1730, 0)
            .and_then(|inst| identity_phi.graph().inst(inst))
            .and_then(|inst| inst.inputs.first().copied())
            .expect("identity phi return input");
        assert!(
            identity_phi
                .certificates()
                .expressions
                .get(&identity_value)
                .is_some_and(|cert| cert.renderable),
            "identity phi over one renderable ValueId should be renderable"
        );

        let mixed_phi = prepared_with_phi_values(7, 9);
        let mixed_value = mixed_phi
            .graph()
            .inst_id_for_op_site(0x1730, 0)
            .and_then(|inst| mixed_phi.graph().inst(inst))
            .and_then(|inst| inst.inputs.first().copied())
            .expect("mixed phi return input");
        assert!(
            mixed_phi
                .certificates()
                .expressions
                .get(&mixed_value)
                .is_some_and(|cert| cert.renderable),
            "non-memory phi with sibling values should be renderable; divergence handled by structurer"
        );
    }

    #[test]
    fn prepared_expression_certificates_render_loop_carried_recurrence_phi() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1800,
                size: 0x10,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1810, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1810,
                size: 0x4,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1820, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1814,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1820,
                size: 0x4,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1810, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let init = SSAVar::new("RAX", 0, 8);
        let phi = SSAVar::new("RAX", 2, 8);
        let update_source = SSAVar::new("tmp:update", 1, 8);
        let update = SSAVar::new("RAX", 3, 8);
        function.get_block_mut(0x1810).expect("loop header").phis = vec![PhiNode {
            dst: phi.clone(),
            sources: vec![(0x1800, init), (0x1820, update.clone())],
            canonical_storage: None,
        }];
        function.get_block_mut(0x1820).expect("loop latch").ops = vec![
            SSAOp::IntAdd {
                dst: update_source.clone(),
                a: phi.clone(),
                b: SSAVar::constant(1, 8),
            },
            SSAOp::Copy {
                dst: update,
                src: update_source.clone(),
            },
            SSAOp::Branch {
                target: SSAVar::new("ram:1810", 0, 8),
                instruction: None,
            },
        ];
        function.get_block_mut(0x1814).expect("loop exit").ops = vec![SSAOp::Return {
            target: phi.clone(),
        }];

        let prepared = SsaArtifact::new(function, FunctionPrepareMode::Raw);
        let carrier = prepared
            .structured()
            .loops
            .values()
            .flat_map(|loop_fact| loop_fact.carriers.iter())
            .find(|carrier| carrier.phi == prepared.graph().value_id_for_var(&phi).unwrap())
            .expect("loop-carried phi fact");
        assert_eq!(carrier.id, SemanticId::loop_carrier(carrier.phi));
        assert_eq!(carrier.entries.len(), 1);
        assert_eq!(carrier.updates.len(), 1);
        assert!(
            carrier.updates[0]
                .identity_values
                .contains(&prepared.graph().value_id_for_var(&update_source).unwrap()),
            "same-width copy sources retain exact update identity at the latch program point"
        );
        assert!(carrier.identity_values.contains(&carrier.phi));
        assert!(
            prepared
                .certificates()
                .expressions
                .get(&carrier.phi)
                .is_some_and(|cert| cert.renderable),
            "loop-header phi is renderable when the loop certificate proves the backedge and the update is pure modulo that phi"
        );
    }

    #[test]
    fn prepared_predicates_preserve_machine_point_comparison_before_normalization() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1900,
                size: 0x4,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1910, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1904,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1910,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let before = SSAVar::new("RAX", 0, 8);
        let one = SSAVar::constant(1, 8);
        let updated = SSAVar::new("tmp:updated", 1, 8);
        let zero = SSAVar::constant(0, 8);
        let condition = SSAVar::new("tmp:condition", 1, 1);
        function.get_block_mut(0x1900).expect("branch block").ops = vec![
            SSAOp::IntSub {
                dst: updated.clone(),
                a: before.clone(),
                b: one.clone(),
            },
            SSAOp::IntNotEqual {
                dst: condition.clone(),
                a: updated.clone(),
                b: zero.clone(),
            },
            SSAOp::CBranch {
                target: SSAVar::new("ram:1910", 0, 8),
                cond: condition,
            },
        ];

        let prepared = SsaArtifact::new(function, FunctionPrepareMode::Raw);
        let predicate = prepared
            .predicates()
            .predicates
            .values()
            .find(|predicate| predicate.block_addr == 0x1900)
            .expect("branch predicate");
        let normalized = predicate
            .comparison
            .as_ref()
            .expect("normalized comparison");
        assert_eq!(normalized.kind, crate::CompareKind::NotEqual);
        assert_eq!(
            normalized.lhs,
            prepared.graph().value_id_for_var(&before).unwrap()
        );
        assert_eq!(
            normalized.rhs,
            prepared.graph().value_id_for_var(&one).unwrap()
        );
        let evaluated = predicate
            .evaluated_comparison
            .as_ref()
            .expect("machine-point comparison");
        assert_eq!(evaluated.kind, crate::CompareKind::NotEqual);
        assert_eq!(
            evaluated.lhs,
            prepared.graph().value_id_for_var(&updated).unwrap()
        );
        assert_eq!(
            evaluated.rhs,
            prepared.graph().value_id_for_var(&zero).unwrap()
        );
    }

    #[test]
    fn prepared_predicates_recover_signed_greater_equal_from_x86_flags() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1920,
                size: 0x4,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1930, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1924,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1930,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let lhs = SSAVar::new("EAX", 0, 4);
        let rhs = SSAVar::new("ECX", 0, 4);
        let difference = SSAVar::new("tmp:difference", 1, 4);
        let overflow = SSAVar::new("OF", 1, 1);
        let sign = SSAVar::new("SF", 1, 1);
        let condition = SSAVar::new("tmp:condition", 1, 1);
        function.get_block_mut(0x1920).expect("branch block").ops = vec![
            SSAOp::IntSBorrow {
                dst: overflow.clone(),
                a: lhs.clone(),
                b: rhs.clone(),
            },
            SSAOp::IntSub {
                dst: difference.clone(),
                a: lhs.clone(),
                b: rhs.clone(),
            },
            SSAOp::IntSLess {
                dst: sign.clone(),
                a: difference,
                b: SSAVar::constant(0, 4),
            },
            SSAOp::IntEqual {
                dst: condition.clone(),
                a: overflow,
                b: sign,
            },
            SSAOp::CBranch {
                target: SSAVar::new("ram:1930", 0, 8),
                cond: condition,
            },
        ];

        let prepared = SsaArtifact::new(function, FunctionPrepareMode::Raw);
        let comparison = prepared
            .predicates()
            .predicates
            .values()
            .find(|predicate| predicate.block_addr == 0x1920)
            .and_then(|predicate| predicate.comparison.as_ref())
            .expect("signed flag comparison");

        assert_eq!(comparison.kind, crate::CompareKind::SignedLessEqual);
        assert_eq!(
            comparison.lhs,
            prepared.graph().value_id_for_var(&rhs).unwrap(),
            "OF == SF means rhs <= lhs"
        );
        assert_eq!(
            comparison.rhs,
            prepared.graph().value_id_for_var(&lhs).unwrap()
        );
    }

    #[test]
    fn loop_carrier_certifies_dominating_initializer_for_zero_iteration_exit() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1a00,
                size: 0x10,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1a30, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1a10,
                size: 0x10,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1a20, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1a20,
                size: 0x10,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1a20, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1a30,
                size: 0x10,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1a50, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1a40,
                size: 0x10,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1a50, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1a50,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let init = SSAVar::new("RAX", 0, 8);
        let phi = SSAVar::new("RAX", 2, 8);
        let update_source = SSAVar::new("tmp:update", 1, 8);
        let update = SSAVar::new("RAX", 3, 8);
        let result = SSAVar::new("RAX", 4, 8);
        let chained_result = SSAVar::new("RAX", 5, 8);
        function.get_block_mut(0x1a20).expect("loop header").phis = vec![PhiNode {
            dst: phi.clone(),
            sources: vec![(0x1a10, init.clone()), (0x1a20, update.clone())],
            canonical_storage: None,
        }];
        function.get_block_mut(0x1a20).expect("loop header").ops = vec![
            SSAOp::IntAdd {
                dst: update_source.clone(),
                a: phi.clone(),
                b: SSAVar::constant(1, 8),
            },
            SSAOp::Copy {
                dst: update.clone(),
                src: update_source,
            },
            SSAOp::CBranch {
                target: SSAVar::new("ram:1a20", 0, 8),
                cond: SSAVar::constant(1, 1),
            },
        ];
        function.get_block_mut(0x1a30).expect("loop exit").phis = vec![PhiNode {
            dst: result.clone(),
            sources: vec![(0x1a00, init.clone()), (0x1a20, update.clone())],
            canonical_storage: None,
        }];
        function.get_block_mut(0x1a30).expect("loop exit").ops = vec![SSAOp::CBranch {
            target: SSAVar::new("ram:1a50", 0, 8),
            cond: SSAVar::constant(1, 1),
        }];
        function.get_block_mut(0x1a40).expect("exit bypass").ops = vec![SSAOp::Branch {
            target: SSAVar::new("ram:1a50", 0, 8),
            instruction: None,
        }];
        function.get_block_mut(0x1a50).expect("final exit").phis = vec![PhiNode {
            dst: chained_result.clone(),
            sources: vec![(0x1a30, result.clone()), (0x1a40, init.clone())],
            canonical_storage: None,
        }];
        function.get_block_mut(0x1a50).expect("final exit").ops = vec![SSAOp::Return {
            target: chained_result.clone(),
        }];

        let prepared = SsaArtifact::new(function, FunctionPrepareMode::Raw);
        let phi_value = prepared.graph().value_id_for_var(&phi).unwrap();
        let init_value = prepared.graph().value_id_for_var(&init).unwrap();
        let update_value = prepared.graph().value_id_for_var(&update).unwrap();
        let result_value = prepared.graph().value_id_for_var(&result).unwrap();
        let chained_result_value = prepared.graph().value_id_for_var(&chained_result).unwrap();
        let phi_inst = prepared.graph().def_inst(phi_value).unwrap();
        let result_inst = prepared.graph().def_inst(result_value).unwrap();
        let loop_fact = prepared
            .structured()
            .loops
            .values()
            .find(|loop_fact| {
                loop_fact
                    .carriers
                    .iter()
                    .any(|carrier| carrier.phi == phi_value)
            })
            .expect("structured loop fact");
        let carrier = loop_fact
            .carriers
            .iter()
            .find(|carrier| carrier.phi == phi_value)
            .expect("loop carrier");
        assert!(carrier.validate(prepared.graph()));
        assert!(carrier.identity_values.contains(&result_value));
        assert!(carrier.identity_values.contains(&chained_result_value));
        assert!(loop_fact.validate_carrier_members(
            prepared.graph(),
            prepared.storage_spans(),
            Some(prepared.machine_context()),
        ));
        for result in [result_value, chained_result_value] {
            assert!(carrier.members.iter().any(|member| {
                member.value == result
                    && member
                        .roles
                        .contains(&crate::LoopCarrierMemberRole::PostLoopMerge)
            }));
        }
        assert_eq!(
            carrier.entries,
            vec![crate::LoopCarrierEdgeValue {
                predecessor: 0x1a10,
                value: init_value,
                site: crate::UseSite {
                    inst: phi_inst,
                    input_idx: 0,
                },
            }]
        );
        assert_eq!(carrier.updates.len(), 1);
        assert_eq!(carrier.updates[0].predecessor, 0x1a20);
        assert_eq!(carrier.updates[0].value, update_value);
        assert_eq!(
            carrier.updates[0].site,
            crate::UseSite {
                inst: phi_inst,
                input_idx: 1,
            }
        );
        assert_eq!(
            carrier.dominating_initializers,
            vec![crate::LoopCarrierEdgeValue {
                predecessor: 0x1a00,
                value: init_value,
                site: crate::UseSite {
                    inst: result_inst,
                    input_idx: 0,
                },
            }]
        );

        let mut forged = carrier.clone();
        forged.entries[0].site.input_idx = 1;
        assert!(
            !forged.validate(prepared.graph()),
            "a carrier must reject a site that names a different phi input"
        );
        let mut forged_loop = loop_fact.clone();
        forged_loop.carriers[0].members[0]
            .roles
            .insert(crate::LoopCarrierMemberRole::ProjectedPeer);
        assert!(
            !forged_loop.validate_carrier_members(
                prepared.graph(),
                prepared.storage_spans(),
                Some(prepared.machine_context()),
            ),
            "stored membership must not validate against its own tampered rows"
        );
    }

    fn projected_peer_loop_artifact(
        phi_order: &[usize],
        name_prefix: &str,
        coherent_storage_run: bool,
    ) -> SsaArtifact {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1b00,
                size: 0x10,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1b10, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1b10,
                size: 0x10,
                ops: vec![R2ILOp::CBranch {
                    target: make_ram(0x1b30, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1b20,
                size: 0x10,
                ops: vec![R2ILOp::Branch {
                    target: make_ram(0x1b10, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1b30,
                size: 0x4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let widths = [8_u32, 4, 2];
        let entries = widths
            .iter()
            .enumerate()
            .map(|(index, width)| SSAVar::new(format!("{name_prefix}:entry:{index}"), 0, *width))
            .collect::<Vec<_>>();
        let phis = widths
            .iter()
            .enumerate()
            .map(|(index, width)| SSAVar::new(format!("{name_prefix}:phi:{index}"), 1, *width))
            .collect::<Vec<_>>();
        let updates = widths
            .iter()
            .enumerate()
            .map(|(index, width)| SSAVar::new(format!("{name_prefix}:update:{index}"), 2, *width))
            .collect::<Vec<_>>();
        let storage = |size| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size,
        };
        let phi_nodes = widths
            .iter()
            .enumerate()
            .map(|(index, width)| PhiNode {
                dst: phis[index].clone(),
                sources: vec![
                    (0x1b00, entries[index].clone()),
                    (0x1b20, updates[index].clone()),
                ],
                canonical_storage: Some(storage(*width)),
            })
            .collect::<Vec<_>>();

        let mut function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw peer loop should build");
        function.get_block_mut(0x1b10).expect("loop header").phis = phi_order
            .iter()
            .map(|index| phi_nodes[*index].clone())
            .collect();
        function.get_block_mut(0x1b10).expect("loop header").ops = vec![SSAOp::CBranch {
            target: SSAVar::new("ram:1b30", 0, 8),
            cond: SSAVar::constant(1, 1),
        }];
        function.get_block_mut(0x1b20).expect("loop latch").ops = if coherent_storage_run {
            vec![
                SSAOp::IntZExt {
                    dst: updates[0].clone(),
                    src: phis[1].clone(),
                },
                SSAOp::IntZExt {
                    dst: updates[1].clone(),
                    src: phis[2].clone(),
                },
                SSAOp::Subpiece {
                    dst: updates[2].clone(),
                    src: phis[0].clone(),
                    offset: 0,
                },
                SSAOp::Branch {
                    target: SSAVar::new("ram:1b10", 0, 8),
                    instruction: None,
                },
            ]
        } else {
            vec![
                SSAOp::IntAdd {
                    dst: updates[0].clone(),
                    a: phis[0].clone(),
                    b: SSAVar::constant(1, 8),
                },
                SSAOp::IntAdd {
                    dst: updates[1].clone(),
                    a: phis[1].clone(),
                    b: SSAVar::constant(1, 4),
                },
                SSAOp::IntAdd {
                    dst: updates[2].clone(),
                    a: phis[2].clone(),
                    b: SSAVar::constant(1, 2),
                },
                SSAOp::Branch {
                    target: SSAVar::new("ram:1b10", 0, 8),
                    instruction: None,
                },
            ]
        };
        function.get_block_mut(0x1b30).expect("loop exit").ops = vec![SSAOp::Return {
            target: phis[0].clone(),
        }];
        for (index, width) in widths.iter().copied().enumerate() {
            for value in [&entries[index], &phis[index], &updates[index]] {
                function
                    .canonical_storage_by_var
                    .insert(value.clone(), storage(width));
            }
        }

        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::sub("EAX", 0, 4, "RAX"));
        arch.add_register(RegisterDef::sub("AX", 0, 2, "RAX"));
        let rax = r2il::RegisterStorage { offset: 0, size: 8 };
        let eax = r2il::RegisterStorage { offset: 0, size: 4 };
        let ax = r2il::RegisterStorage { offset: 0, size: 2 };
        arch.register_projections = vec![
            r2il::RegisterProjection {
                written: ax,
                disposition: r2il::RegisterProjectionDisposition::Bound {
                    carrier: rax,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 16,
                    },
                },
            },
            r2il::RegisterProjection {
                written: eax,
                disposition: r2il::RegisterProjectionDisposition::Bound {
                    carrier: rax,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 32,
                    },
                },
            },
            r2il::RegisterProjection {
                written: rax,
                disposition: r2il::RegisterProjectionDisposition::Bound {
                    carrier: rax,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 64,
                    },
                },
            },
        ];
        let mut geometry_blocks = blocks.clone();
        geometry_blocks[0].ops = vec![
            R2ILOp::Copy {
                dst: make_unique(0x1b00, 8),
                src: make_reg(0, 8),
            },
            R2ILOp::Copy {
                dst: make_unique(0x1b10, 4),
                src: make_reg(0, 4),
            },
            R2ILOp::Copy {
                dst: make_unique(0x1b20, 2),
                src: make_reg(0, 2),
            },
        ];
        let machine_context = SourceMachineContext::from_blocks(&geometry_blocks, Some(&arch));
        assert_eq!(
            machine_context.register_geometry_state(),
            crate::MachineRegisterGeometryState::Available,
        );
        for written in [ax, eax, rax] {
            assert!(matches!(
                machine_context
                    .register_projection(CanonicalStorageId {
                        space: CanonicalStorageSpace::Register,
                        offset: written.offset,
                        size: written.size,
                    })
                    .map(|projection| projection.disposition),
                Some(r2il::RegisterProjectionDisposition::Bound { carrier, .. })
                    if carrier == rax
            ));
        }
        SsaArtifact::new_with_context(function, FunctionPrepareMode::Raw, machine_context)
    }

    fn projected_peer_role_signature(
        prepared: &SsaArtifact,
    ) -> Vec<(u32, Vec<crate::LoopCarrierMemberRole>)> {
        let loop_fact = prepared
            .structured()
            .loops
            .values()
            .next()
            .expect("projected peer loop");
        let leader = loop_fact
            .carriers
            .iter()
            .max_by_key(|carrier| carrier.width)
            .expect("wide loop carrier");
        let mut signature = leader
            .members
            .iter()
            .map(|member| {
                (
                    prepared
                        .graph()
                        .value(member.value)
                        .and_then(|value| value.canonical_storage)
                        .map_or(0, |storage| storage.size),
                    member.roles.iter().copied().collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        signature.sort();
        signature
    }

    fn projected_peer_certificate_component(
        loop_fact: &crate::StructuredLoopFact,
    ) -> BTreeSet<ValueId> {
        let mut sets = loop_fact
            .carriers
            .iter()
            .map(crate::LoopCarrierFact::coalescing_values)
            .collect::<Vec<_>>();
        sets.sort_by_key(|members| members.first().copied());
        let mut component = sets.first().cloned().unwrap_or_default();
        let mut pending = sets.into_iter().skip(1).collect::<Vec<_>>();
        loop {
            let mut changed = false;
            pending.retain(|members| {
                if component.is_disjoint(members) {
                    true
                } else {
                    component.extend(members.iter().copied());
                    changed = true;
                    false
                }
            });
            if !changed {
                break;
            }
        }
        component
    }

    #[test]
    fn projected_loop_peers_form_one_order_and_name_independent_component() {
        let forward = projected_peer_loop_artifact(&[0, 1, 2], "named", true);
        let shuffled = projected_peer_loop_artifact(&[2, 0, 1], "renamed", true);

        assert_eq!(
            projected_peer_role_signature(&forward),
            projected_peer_role_signature(&shuffled),
            "role membership is keyed by source storage and SSA evidence, not names or phi order"
        );
        for prepared in [&forward, &shuffled] {
            let loop_fact = prepared
                .structured()
                .loops
                .values()
                .next()
                .expect("projected peer loop");
            assert!(loop_fact.validate_carrier_members(
                prepared.graph(),
                prepared.storage_spans(),
                Some(prepared.machine_context()),
            ));
            assert_eq!(loop_fact.carriers.len(), 3);
            let component = projected_peer_certificate_component(loop_fact);
            assert!(
                loop_fact
                    .carriers
                    .iter()
                    .all(|carrier| component.contains(&carrier.phi))
            );
            let leader = loop_fact
                .carriers
                .iter()
                .max_by_key(|carrier| carrier.width)
                .expect("wide carrier");
            assert_eq!(
                leader
                    .members
                    .iter()
                    .filter(|member| {
                        member
                            .roles
                            .contains(&crate::LoopCarrierMemberRole::ProjectedPeer)
                            && loop_fact
                                .carriers
                                .iter()
                                .any(|carrier| carrier.phi == member.value)
                    })
                    .count(),
                2,
            );
        }
    }

    #[test]
    fn projected_loop_peers_require_one_coherent_storage_run() {
        let prepared = projected_peer_loop_artifact(&[0, 1, 2], "separate", false);
        let loop_fact = prepared
            .structured()
            .loops
            .values()
            .next()
            .expect("separate peer loop");
        assert!(loop_fact.validate_carrier_members(
            prepared.graph(),
            prepared.storage_spans(),
            Some(prepared.machine_context()),
        ));
        assert!(
            loop_fact
                .carriers
                .iter()
                .all(|carrier| carrier.members.iter().all(|member| !member
                    .roles
                    .contains(&crate::LoopCarrierMemberRole::ProjectedPeer)))
        );
    }

    #[test]
    fn prepared_predicates_recover_signed_less_from_of_sf_flags() {
        let lhs = make_reg(0, 4);
        let rhs = make_reg(4, 4);
        let of = Varnode {
            space: SpaceId::Unique,
            offset: 0x2000,
            size: 1,
            meta: None,
        };
        let sf = Varnode {
            space: SpaceId::Unique,
            offset: 0x2001,
            size: 1,
            meta: None,
        };
        let sub = Varnode {
            space: SpaceId::Unique,
            offset: 0x2002,
            size: 4,
            meta: None,
        };
        let cond = Varnode {
            space: SpaceId::Unique,
            offset: 0x2003,
            size: 1,
            meta: None,
        };
        let blocks = vec![
            R2ILBlock {
                addr: 0x1600,
                size: 4,
                ops: vec![
                    R2ILOp::IntSBorrow {
                        dst: of.clone(),
                        a: lhs.clone(),
                        b: rhs.clone(),
                    },
                    R2ILOp::IntSub {
                        dst: sub.clone(),
                        a: lhs,
                        b: rhs,
                    },
                    R2ILOp::IntSLess {
                        dst: sf.clone(),
                        a: sub,
                        b: make_const(0, 4),
                    },
                    R2ILOp::IntNotEqual {
                        dst: cond.clone(),
                        a: of,
                        b: sf,
                    },
                    R2ILOp::CBranch {
                        target: make_const(0x1608, 8),
                        cond,
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1604,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1608,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
        let predicate = prepared
            .predicates()
            .predicates
            .values()
            .next()
            .expect("predicate fact");
        let compare = predicate
            .comparison
            .as_ref()
            .expect("signed compare provenance");
        assert_eq!(compare.kind, crate::semantic::CompareKind::SignedLess);
        assert_ne!(compare.lhs, compare.rhs);
    }

    #[test]
    fn test_ssa_function_diamond() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
        assert_eq!(func.num_blocks(), 4);

        // Merge block should have a phi node
        let merge = func.get_block(0x100c).unwrap();
        assert!(merge.has_phis());
        assert_eq!(merge.num_phis(), 1);

        // Phi should have two sources
        let phi = &merge.phis[0];
        assert_eq!(phi.sources.len(), 2);
    }

    #[test]
    fn cfg_risk_summary_reports_loops_and_switch_density() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1010, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x1020, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1010,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x1000, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1020,
                size: 4,
                ops: vec![],
                switch_info: Some(R2ILSwitchInfo {
                    switch_addr: 0x1020,
                    min_val: 0,
                    max_val: 2,
                    default_target: Some(0x1040),
                    cases: vec![
                        SwitchCase {
                            value: 0,
                            target: 0x1030,
                        },
                        SwitchCase {
                            value: 1,
                            target: 0x1040,
                        },
                    ],
                }),
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1030,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1040,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("ssa function");
        let summary = func.cfg_risk_summary();

        assert_eq!(summary.block_count, 6);
        assert_eq!(
            summary.loop_count, 1,
            "expected one natural loop, got {summary:?}"
        );
        assert_eq!(
            summary.back_edge_count, 1,
            "expected one back edge from loop latch, got {summary:?}"
        );
        assert_eq!(summary.switch_block_count, 1);
        assert_eq!(summary.max_switch_cases, 3);

        assert_eq!(
            CFG::from_blocks(&blocks)
                .expect("cfg should build")
                .risk_summary(),
            summary,
            "a caller that has only the graph must read the same risk as a caller holding SSA"
        );
    }

    #[test]
    fn producerless_switch_selector_is_retained_as_a_leaf() {
        let mut selector = R2ILBlock::new(0x1080, 4);
        selector.push(R2ILOp::BranchInd {
            target: make_reg(8, 8),
        });
        selector.set_switch_info(R2ILSwitchInfo {
            switch_addr: 0x1080,
            min_val: 1,
            max_val: 2,
            default_target: Some(0x10b0),
            cases: vec![
                SwitchCase {
                    value: 1,
                    target: 0x1090,
                },
                SwitchCase {
                    value: 2,
                    target: 0x10a0,
                },
            ],
        });
        let arms = [0x1090, 0x10a0, 0x10b0].map(|addr| {
            let mut block = R2ILBlock::new(addr, 4);
            block.push(R2ILOp::Return {
                target: make_reg(16, 8),
            });
            block
        });
        let artifact = SsaArtifact::raw(
            &[selector, arms[0].clone(), arms[1].clone(), arms[2].clone()],
            None,
        )
        .expect("switch artifact");
        let certificate = artifact
            .certificates()
            .switches
            .get(&0x1080)
            .expect("switch certificate");
        let selector = certificate.selector.expect("producerless selector leaf");
        let value = artifact
            .graph()
            .value(selector)
            .expect("selector graph value");
        assert_eq!(value.var.size, 8);
        let branch = artifact
            .graph()
            .insts
            .iter()
            .find(|instruction| {
                matches!(
                    instruction.payload,
                    crate::graph::InstPayload::Op(SSAOp::BranchInd { .. })
                )
            })
            .expect("branch instruction");
        assert_eq!(branch.inputs, vec![selector]);
    }

    #[test]
    fn public_ssa_path_handles_a_deep_cycle_and_reports_its_back_edge() {
        const BLOCK_COUNT: usize = 8_192;
        const BASE: u64 = 0x10_0000;

        let blocks = (0..BLOCK_COUNT)
            .map(|index| R2ILBlock {
                addr: BASE + index as u64 * 4,
                size: 4,
                ops: if index + 1 == BLOCK_COUNT {
                    vec![R2ILOp::Branch {
                        target: make_const(BASE, 8),
                    }]
                } else {
                    vec![R2ILOp::Nop]
                },
                switch_info: None,
                op_metadata: Default::default(),
            })
            .collect::<Vec<_>>();
        let expected_order = blocks.iter().map(|block| block.addr).collect::<Vec<_>>();
        let latch = BASE + (BLOCK_COUNT as u64 - 1) * 4;

        let function =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("SSA for deep cyclic CFG");
        let risk = function.cfg_risk_summary();

        assert_eq!(function.block_addrs(), expected_order);
        assert_eq!(risk.block_count, BLOCK_COUNT);
        assert_eq!(risk.loop_count, 1);
        assert_eq!(risk.back_edge_count, 1);
        assert_eq!(
            function.cfg().collect_back_edges().get(&BASE),
            Some(&vec![latch])
        );
    }

    #[test]
    fn test_raw_ssa_construction_is_deterministic_across_runs() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Copy {
                        dst: make_reg(8, 8),
                        src: make_reg(0, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Copy {
                        dst: make_reg(8, 8),
                        src: make_reg(0, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![
                    R2ILOp::IntXor {
                        dst: make_reg(16, 8),
                        a: make_reg(8, 8),
                        b: make_reg(0, 8),
                    },
                    R2ILOp::Return {
                        target: make_ram(0, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let mut dumps = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
            dumps.insert(func.dump());
        }

        assert_eq!(
            dumps.len(),
            1,
            "raw SSA output should stay stable across repeated construction"
        );
    }

    #[test]
    fn test_find_def_use() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();

        // Find definition of reg:0 v1
        let var = SSAVar::new("reg:0", 1, 8);
        let def = func.find_def(&var);
        assert!(def.is_some());
        let (addr, loc) = def.unwrap();
        assert_eq!(addr, 0x1000);
        assert!(matches!(loc, DefLocation::Op(0)));

        // Find uses of reg:0 v1
        let uses = func.find_uses(&var);
        assert!(!uses.is_empty());
    }

    #[test]
    fn noncarrier_use_follows_copy_and_phi_chains() {
        let blocks = [R2ILBlock::new(0x1000, 4), R2ILBlock::new(0x1004, 4)];
        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function");
        let source = SSAVar::new("flag", 1, 1);
        let copied = SSAVar::new("flag", 2, 1);
        let merged = SSAVar::new("flag", 3, 1);
        let forwarded = SSAVar::new("flag", 4, 1);
        func.get_block_mut(0x1000).expect("copy block").ops = vec![SSAOp::Copy {
            dst: copied.clone(),
            src: source.clone(),
        }];
        let merge = func.get_block_mut(0x1004).expect("merge block");
        merge.phis = vec![PhiNode {
            dst: merged.clone(),
            sources: vec![(0x1000, copied)],
            canonical_storage: None,
        }];
        merge.ops = vec![SSAOp::Copy {
            dst: forwarded.clone(),
            src: merged,
        }];

        assert!(!func.has_noncarrier_use(&source));

        func.get_block_mut(0x1004)
            .expect("consumer block")
            .ops
            .push(SSAOp::Return { target: forwarded });

        assert!(func.has_noncarrier_use(&source));
    }

    #[test]
    fn test_dump() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(42, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks)
            .unwrap()
            .with_name("test_func");

        let dump = func.dump();
        assert!(dump.contains("test_func"));
        assert!(dump.contains("0x1000"));
        assert!(dump.contains("0x1004"));
    }

    #[test]
    fn test_from_blocks_default_runs_optimization() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let func = SSAFunction::from_blocks(&blocks).expect("optimized SSA should build");
        assert!(
            func.num_blocks() < blocks.len(),
            "optimized constructor should prune dead branch blocks via SCCP"
        );
    }

    #[test]
    fn test_refresh_after_cfg_mutation_recomputes_order_and_domtree() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        func.remove_block(0x1004);
        func.refresh_after_cfg_mutation();

        assert!(!func.block_addrs().contains(&0x1004));
        assert!(func.get_block(0x1004).is_none());
        assert_eq!(func.idom(0x1008), Some(0x1000));
    }

    #[test]
    fn test_for_each_source_reports_phi_and_op_sites() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(3, 8),
                }],
                op_metadata: std::collections::BTreeMap::new(),
                switch_info: None,
            },
        ];

        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        let merge = func.get_block(0x100c).expect("merge block");
        assert!(merge.has_phis(), "fixture should produce a merge phi");

        let mut seen = Vec::new();
        merge.for_each_source(|src| {
            seen.push(match src.site {
                SourceSite::Phi {
                    phi_idx,
                    src_idx,
                    pred_addr,
                } => format!(
                    "phi:{}:{}:0x{:x}:{}",
                    phi_idx,
                    src_idx,
                    pred_addr,
                    src.var.display_name()
                ),
                SourceSite::Op { op_idx, src_idx } => {
                    format!("op:{}:{}:{}", op_idx, src_idx, src.var.display_name())
                }
            });
        });

        assert_eq!(seen.len(), 4, "2 phi sources + 2 IntAdd sources expected");
        assert!(
            seen[0].starts_with("phi:0:0:"),
            "first source should be first phi input"
        );
        assert!(
            seen[1].starts_with("phi:0:1:"),
            "second source should be second phi input"
        );
        assert!(
            seen[2].starts_with("op:0:0:"),
            "third source should be first op input"
        );
        assert!(
            seen[3].starts_with("op:0:1:"),
            "fourth source should be second op input"
        );
    }

    #[test]
    fn test_for_each_def_reports_phi_and_op_defs() {
        let block = SSABlock {
            addr: 0x2000,
            size: 4,
            phis: vec![PhiNode {
                dst: SSAVar::new("reg:0", 2, 8),
                sources: vec![(0x1000, SSAVar::new("reg:0", 0, 8))],
                canonical_storage: None,
            }],
            ops: vec![
                SSAOp::Copy {
                    dst: SSAVar::new("reg:8", 1, 8),
                    src: SSAVar::new("reg:0", 2, 8),
                },
                SSAOp::Return {
                    target: SSAVar::new("reg:8", 1, 8),
                },
            ],
        };

        let mut seen = Vec::new();
        block.for_each_def(|def| {
            seen.push(match def.site {
                DefSite::Phi { phi_idx } => format!("phi:{}:{}", phi_idx, def.var.display_name()),
                DefSite::Op { op_idx } => format!("op:{}:{}", op_idx, def.var.display_name()),
            });
        });

        assert_eq!(
            seen,
            vec!["phi:0:reg:0_2".to_string(), "op:0:reg:8_1".to_string()]
        );
    }

    #[test]
    fn vector_alias_loop_edges_keep_exact_lane_producers_across_names_and_relocation() {
        assert_vector_loop_alias_provenance(0x1000, "first_names");
        assert_vector_loop_alias_provenance(0x7fff_4000, "renamed_registers");
    }

    #[test]
    fn a_lane_write_inserts_into_the_entry_root() {
        let mut arch = ArchSpec::new("x86-64");
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::sub("AH", 1, 1, "RAX"));
        let mut block = R2ILBlock::new(0x1000, 4);
        // The caller's register is read on its own account, so it is not the
        // scratch register whose lane writes start from zero.
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_const(0x1ff8, 8),
            val: make_reg(0, 8),
        });
        block.push(R2ILOp::Copy {
            dst: make_reg(1, 1),
            src: make_const(3, 1),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_const(0x2000, 8),
            val: make_reg(0, 8),
        });

        let function = SSAFunction::from_blocks_with_arch(&[block], Some(&arch))
            .expect("partial-register fixture");
        let ops = &function.get_block(0x1000).expect("entry block").ops;
        let stored = ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::Store { val, .. } => Some(val.clone()),
                _ => None,
            })
            .next_back()
            .expect("the store after the lane write");
        assert_eq!(stored, SSAVar::new("RAX", 1, 8), "{ops:?}");
        let lane = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Insert {
                    dst,
                    src,
                    value,
                    position,
                } if *dst == stored && *src == SSAVar::new("RAX", 0, 8) => {
                    assert_eq!(position.constant_bits(), Some(8));
                    Some(value.clone())
                }
                _ => None,
            })
            .expect("the high byte is inserted into the entry root");
        assert!(
            lane.constant_bits() == Some(3)
                || ops.iter().any(|op| matches!(
                    op,
                    SSAOp::Copy { dst, src } if *dst == lane && src.constant_bits() == Some(3)
                )),
            "{ops:?}"
        );
        assert!(!ops.iter().any(|op| matches!(op, SSAOp::Piece { .. })));
    }

    /// The widest slot is the family's canonical identity, and every alias
    /// reaches the same one whatever width it names.
    #[test]
    fn widest_slot_is_one_canonical_identity_per_register() {
        let families = RegisterFamilyInfo::from_register_storages([
            ("RDI", 0x38u64, 8u32),
            ("EDI", 0x38, 4),
            ("DI", 0x38, 2),
            ("DIL", 0x38, 1),
        ]);

        let widest = families.widest_slot_for_name("rdi").expect("rdi is named");
        assert_eq!(widest.width, 8);
        for alias in ["edi", "di", "dil", "RDI"] {
            assert_eq!(
                families.widest_slot_for_name(alias).expect(alias),
                widest,
                "{alias}"
            );
        }
        assert!(families.widest_slot_for_name("rsi").is_none());
    }

    #[test]
    fn a_low_byte_read_of_a_constant_lane_write_is_the_constant() {
        let mut arch = ArchSpec::new("x86-64");
        arch.add_register(RegisterDef::new("RAX", 0x00, 8));
        arch.add_register(RegisterDef::new("EAX", 0x00, 4));
        arch.add_register(RegisterDef::new("AL", 0x00, 1));

        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 4),
                    src: make_const(0x41, 4),
                },
                R2ILOp::IntEqual {
                    dst: make_reg(0x200, 1),
                    a: make_reg(0, 1),
                    b: make_const(0x41, 1),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        // The lane write inserts into `RAX`; reading the byte back through
        // the insert and the constant is the optimizer's fold, so the fact is
        // stated of the optimized function.
        let mut func = SSAFunction::from_blocks_raw(&blocks, Some(&arch)).expect("raw SSA");
        crate::optimize::optimize_function(
            &mut func,
            &crate::optimize::OptimizationConfig::default(),
        );
        // The byte read back is the constant, so the comparison folds to true.
        let block = func.get_block(0x1000).expect("entry block");
        let flag = block
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Copy { dst, src } if dst.size == 1 && dst.name == "reg:200" => {
                    Some(src.clone())
                }
                SSAOp::IntEqual { a, .. } => Some(a.clone()),
                _ => None,
            })
            .expect("the comparison or its folded result survives");
        assert!(
            flag == SSAVar::constant(1, 1) || flag == SSAVar::constant(0x41, 1),
            "{:?}",
            block.ops
        );
    }

    #[test]
    fn test_decompile_prep_facts_collapse_copy_chain_and_trivial_phi_roots() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(0x42, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(0x42, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let arch = make_x86_64_prep_arch();
        let func = SSAFunction::from_blocks_for_decompile(&blocks, Some(&arch))
            .expect("prepared SSA should build");
        let facts = func.decompile_prep_facts().expect("prep facts");
        let merge = func.get_block(0x100c).expect("merge block");
        assert_eq!(merge.phis.len(), 1, "expected trivial merge phi");

        let const_root = SSAVar::constant(0x42, 8);
        let phi_dst = &merge.phis[0].dst;
        assert_eq!(
            facts.canonical_root_of(phi_dst),
            Some(&const_root),
            "merge phi should collapse to the shared constant root"
        );

        let left_dst = func
            .get_block(0x1004)
            .expect("left block")
            .ops
            .first()
            .and_then(|op| op.dst())
            .expect("left copy dst");
        let right_dst = func
            .get_block(0x1008)
            .expect("right block")
            .ops
            .first()
            .and_then(|op| op.dst())
            .expect("right copy dst");

        assert_eq!(facts.canonical_root_of(left_dst), Some(&const_root));
        assert_eq!(facts.canonical_root_of(right_dst), Some(&const_root));
        assert_eq!(facts.canonical_root_of(&const_root), Some(&const_root));
    }

    #[test]
    fn test_decompile_prep_facts_refuse_display_named_stack_roots() {
        let blocks = vec![R2ILBlock {
            addr: 0x2000,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        func.get_block_mut(0x2000).expect("entry block").ops = vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:1", 1, 8),
                a: SSAVar::new("rsp", 0, 8),
                b: SSAVar::constant(0xfffffffffffffff0, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("tmp:2", 1, 8),
                src: SSAVar::new("tmp:1", 1, 8),
            },
            SSAOp::IntSub {
                dst: SSAVar::new("tmp:3", 1, 8),
                a: SSAVar::new("rbp", 0, 8),
                b: SSAVar::constant(0x20, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("tmp:4", 1, 8),
                src: SSAVar::new("tmp:3", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:5", 1, 8),
                a: SSAVar::new("rsp", 0, 8),
                b: SSAVar::constant(0xffff_fff0, 4),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:max", 1, 8),
                a: SSAVar::new("rsp", 0, 8),
                b: SSAVar::constant(i64::MAX as u64, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:overflow", 1, 8),
                a: SSAVar::new("tmp:max", 1, 8),
                b: SSAVar::constant(1, 8),
            },
        ];
        func.refresh_decompile_prep_facts();

        let facts = func.decompile_prep_facts().expect("prep facts");
        assert!(
            facts.stack_address_roots.is_empty(),
            "display names cannot establish stack roots without typed carrier evidence"
        );
        assert_eq!(
            facts.canonical_root_of(&SSAVar::new("tmp:2", 1, 8)),
            Some(&SSAVar::new("tmp:1", 1, 8))
        );
        assert_eq!(
            facts.canonical_root_of(&SSAVar::new("tmp:4", 1, 8)),
            Some(&SSAVar::new("tmp:3", 1, 8))
        );
    }

    #[test]
    fn test_decompile_prep_facts_use_only_exact_typed_stack_carriers() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::new("rip", 32, 8));
        let rsp = make_reg(16, 8);
        let rbp = make_reg(24, 8);
        let blocks = vec![R2ILBlock {
            addr: 0x3000,
            size: 5,
            ops: vec![
                R2ILOp::Copy {
                    dst: rbp.clone(),
                    src: rsp.clone(),
                },
                R2ILOp::IntSub {
                    dst: rsp.clone(),
                    a: rsp.clone(),
                    b: make_const(0x20, 8),
                },
                R2ILOp::IntAdd {
                    dst: make_unique(0x10, 8),
                    a: rsp.clone(),
                    b: make_const(8, 8),
                },
                R2ILOp::IntSub {
                    dst: make_unique(0x18, 8),
                    a: rbp,
                    b: make_const(0x10, 8),
                },
                R2ILOp::Trunc {
                    dst: make_unique(0x20, 4),
                    src: rsp.clone(),
                },
                R2ILOp::Cast {
                    dst: make_unique(0x24, 4),
                    src: rsp.clone(),
                },
                R2ILOp::IntAdd {
                    dst: make_unique(0x28, 4),
                    a: rsp.clone(),
                    b: make_const(1, 8),
                },
                R2ILOp::IntSub {
                    dst: make_unique(0x2c, 4),
                    a: rsp,
                    b: make_const(1, 8),
                },
                R2ILOp::Return {
                    target: make_const(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let sp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let fp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 24,
            size: 8,
        };
        let ra_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 32,
            size: 8,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"typed-stack-roots".to_vec(),
            "sysv",
            [],
            SourceFunctionReturn::Void,
            [
                SourceStackSlotSpec::new_local(
                    StackAddressBase::FramePointer,
                    fp_storage,
                    -0x10,
                    8,
                ),
                SourceStackSlotSpec::new_local(
                    StackAddressBase::StackPointer,
                    sp_storage,
                    -0x18,
                    8,
                ),
            ],
        )
        .expect("exact typed interface")
        .with_return_address_storage(ra_storage)
        .expect("return-address carrier")
        .with_stack_pointer_storage(sp_storage)
        .expect("stack-pointer carrier");

        let typed = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("typed decompile artifact");
        let typed_function = typed.function();
        let typed_facts = typed_function.decompile_prep_facts().expect("typed facts");
        let op_roots = typed_function
            .get_block(0x3000)
            .expect("entry")
            .ops
            .iter()
            .filter_map(|op| op.dst())
            .filter_map(|dst| {
                typed_facts
                    .stack_address_root_of(dst)
                    .copied()
                    .map(|root| (typed_function.canonical_storage_for_var(dst), root))
            })
            .collect::<Vec<_>>();
        let entry_op_roots = typed_function
            .get_block(0x3000)
            .expect("entry")
            .ops
            .iter()
            .filter_map(|op| op.dst())
            .filter_map(|dst| {
                typed_facts
                    .entry_stack_address_root_of(dst)
                    .copied()
                    .map(|root| (typed_function.canonical_storage_for_var(dst), root))
            })
            .collect::<Vec<_>>();
        // The frame pointer has a position now, not a base of its own. Here it
        // is the entry stack pointer itself, which is what a frame pointer
        // established before any allocation is.
        assert!(
            op_roots.contains(&(
                Some(fp_storage),
                StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: 0,
                },
            )),
            "op roots were {op_roots:?}"
        );
        assert!(op_roots.contains(&(
            Some(sp_storage),
            StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x20,
            },
        )));
        assert!(op_roots.iter().any(|(_, root)| {
            *root
                == StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: -0x18,
                }
        }));
        assert!(entry_op_roots.contains(&(
            Some(fp_storage),
            StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: 0,
            },
        )));
        assert!(entry_op_roots.contains(&(
            Some(sp_storage),
            StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x20,
            },
        )));
        assert!(entry_op_roots.iter().any(|(_, root)| {
            *root
                == StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: -0x18,
                }
        }));
        assert!(
            typed_function
                .get_block(0x3000)
                .expect("entry")
                .ops
                .iter()
                .filter_map(SSAOp::dst)
                .filter(|dst| dst.size == 4)
                .all(|dst| typed_facts.entry_stack_address_root_of(dst).is_none()),
            "narrow copy/cast/add/sub values cannot carry entry-SP authority"
        );
        assert!(entry_op_roots.iter().any(|(_, root)| {
            *root
                == StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: -0x10,
                }
        }));
        // The same position, and now the same name for it. This used to assert
        // that the general map called the location frame-relative while the
        // entry map called it stack-relative -- one place under two
        // coordinates, which is what the two maps existed to keep apart.
        assert!(op_roots.iter().any(|(_, root)| {
            *root
                == StackAddressRoot {
                    base: StackAddressBase::StackPointer,
                    offset: -0x10,
                }
        }));

        let source_free = SsaArtifact::for_decompile(&blocks, Some(&arch))
            .expect("source-free decompile artifact");
        assert!(
            source_free
                .function()
                .decompile_prep_facts()
                .expect("source-free facts")
                .stack_address_roots
                .is_empty(),
            "register names and architecture storage alone cannot grant stack roots"
        );
    }

    #[test]
    fn artifact_projects_typed_stack_roots_by_value_id_without_register_aliases() {
        let mut arch = ArchSpec::new("opaque-stack-registers");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("machine_base_alpha", 16, 8));
        arch.add_register(RegisterDef::new("machine_base_beta", 24, 8));
        arch.add_register(RegisterDef::new("machine_return_gamma", 32, 8));

        let stack_pointer = make_reg(16, 8);
        let frame_pointer = make_reg(24, 8);
        let blocks = vec![R2ILBlock {
            addr: 0x3400,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: frame_pointer.clone(),
                    src: stack_pointer,
                },
                R2ILOp::IntSub {
                    dst: make_unique(0x48, 8),
                    a: frame_pointer,
                    b: make_const(0x18, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let sp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let fp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 24,
            size: 8,
        };
        let ra_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 32,
            size: 8,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"opaque-stack-registers".to_vec(),
            "opaque",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                fp_storage,
                -0x18,
                8,
            )],
        )
        .expect("typed interface")
        .with_return_address_storage(ra_storage)
        .expect("return-address carrier")
        .with_stack_pointer_storage(sp_storage)
        .expect("stack-pointer carrier")
        .with_frame_pointer_storage(fp_storage)
        .expect("frame-pointer carrier");

        let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("typed decompile artifact");
        let frame_setup = artifact
            .graph()
            .inst_id_for_op_site(0x3400, 0)
            .and_then(|inst| artifact.graph().inst(inst))
            .expect("frame setup graph instruction");
        let entry_sp = frame_setup.inputs[0];
        let local_address = artifact
            .graph()
            .inst_id_for_op_site(0x3400, 1)
            .and_then(|inst| artifact.graph().inst(inst))
            .and_then(|inst| inst.output)
            .expect("local-address graph value");

        assert_eq!(
            artifact.stack_address_root_for_value(entry_sp),
            Some(StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: 0,
            })
        );
        // Same place, named in the one coordinate objects use. The frame
        // pointer here is the entry stack pointer, so a local twenty-four
        // below it is twenty-four below entry.
        assert_eq!(
            artifact.stack_address_root_for_value(local_address),
            Some(StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x18,
            })
        );
        assert_eq!(
            artifact.entry_stack_address_root_for_value(local_address),
            Some(StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x18,
            })
        );
        assert!(
            [entry_sp, local_address].iter().all(|value| {
                let name = &artifact
                    .graph()
                    .value(*value)
                    .expect("graph value")
                    .var
                    .name;
                !matches!(
                    name.to_ascii_lowercase().as_str(),
                    "sp" | "rsp" | "fp" | "rbp"
                )
            }),
            "the typed ValueId projection must not depend on conventional raw aliases"
        );
    }

    #[test]
    fn entry_stack_roots_use_call_preservation_but_refuse_unknown_effects() {
        let mut arch = ArchSpec::new("custom-stack-call");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("custom_sp", 0x10, 8));
        arch.add_register(RegisterDef::new("custom_ra", 0x20, 8));
        let sp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 0x10,
            size: 8,
        };
        let ra_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 0x20,
            size: 8,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"custom-stack-call-roots".to_vec(),
            "custom-unknown",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                sp_storage,
                -8,
                8,
            )],
        )
        .expect("exact custom interface")
        .with_return_address_storage(ra_storage)
        .expect("custom return-address carrier")
        .with_stack_pointer_storage(sp_storage)
        .expect("custom stack-pointer carrier")
        .with_preserved_call_carriers(true, false);

        for (name, boundary) in [
            (
                "call",
                R2ILOp::Call {
                    target: make_const(0x5000, 8),
                },
            ),
            (
                "unknown effect",
                R2ILOp::CallOther {
                    output: None,
                    userop: 7,
                    inputs: Vec::new(),
                },
            ),
            (
                "cpu identity effect",
                R2ILOp::CpuId {
                    dst: make_unique(0x80, 8),
                },
            ),
            (
                "allocation effect",
                R2ILOp::New {
                    dst: make_unique(0x88, 8),
                    src: make_const(8, 8),
                },
            ),
        ] {
            let blocks = vec![R2ILBlock {
                addr: 0x3400,
                size: 4,
                ops: vec![
                    R2ILOp::IntSub {
                        dst: make_reg(0x10, 8),
                        a: make_reg(0x10, 8),
                        b: make_const(0x10, 8),
                    },
                    boundary,
                    R2ILOp::IntAdd {
                        dst: make_unique(0x40, 8),
                        a: make_reg(0x10, 8),
                        b: make_const(8, 8),
                    },
                    R2ILOp::Return {
                        target: make_reg(0x20, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            }];
            let artifact =
                SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface.clone())
                    .unwrap_or_else(|| panic!("{name} artifact must build"));
            let facts = artifact
                .function()
                .decompile_prep_facts()
                .expect("custom prep facts");
            assert!(
                !facts.stack_address_roots.is_empty(),
                "{name} must preserve source-declared stack roots"
            );
            if name == "call" {
                assert!(
                    !facts.entry_stack_address_roots.is_empty(),
                    "a convention-preserved SP retains entry-relative roots without an FP role"
                );
            } else {
                assert!(
                    facts.entry_stack_address_roots.is_empty(),
                    "{name} must invalidate entry-SP-relative roots"
                );
            }
        }
    }

    #[test]
    fn new_subregister_result_cannot_inherit_stack_address_authority() {
        let mut arch = make_x86_64_prep_arch();
        arch.add_register(RegisterDef::sub("esp", 16, 4, "rsp"));
        arch.add_register(RegisterDef::new("rip", 32, 8));
        let sp_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let ra_storage = CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 32,
            size: 8,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"new-subregister-stack-roots".to_vec(),
            "sysv",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                sp_storage,
                -8,
                8,
            )],
        )
        .expect("exact stack interface")
        .with_return_address_storage(ra_storage)
        .expect("return-address carrier")
        .with_stack_pointer_storage(sp_storage)
        .expect("stack-pointer carrier");
        let blocks = [R2ILBlock {
            addr: 0x3480,
            size: 4,
            ops: vec![
                R2ILOp::New {
                    dst: make_reg(16, 4),
                    src: make_reg(16, 8),
                },
                R2ILOp::Cast {
                    dst: make_unique(0x90, 8),
                    src: make_reg(16, 4),
                },
                R2ILOp::Load {
                    dst: make_unique(0x98, 4),
                    space: SpaceId::Ram,
                    addr: make_unique(0x90, 8),
                },
                R2ILOp::Return {
                    target: make_reg(32, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("subregister New artifact");
        let block = artifact.function().get_block(0x3480).expect("entry block");
        let new_dst = block
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::New { dst, .. } => Some(dst),
                _ => None,
            })
            .expect("New output");
        let load_addr = block
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Load { addr, .. } => Some(addr),
                _ => None,
            })
            .expect("load address");
        let facts = artifact
            .function()
            .decompile_prep_facts()
            .expect("decompile prep facts");

        assert!(facts.stack_address_root_of(new_dst).is_none());
        assert!(facts.stack_address_root_of(load_addr).is_none());
        assert!(facts.entry_stack_address_roots.is_empty());
        let object = artifact
            .object_for_var(load_addr, SpaceId::Ram)
            .expect("load address object");
        assert!(
            !artifact
                .objects()
                .stack_objects
                .values()
                .any(|candidate| *candidate == object)
        );
        assert!(!artifact.objects().entry_stack_roots.contains_key(&object));
    }

    #[test]
    fn test_decompile_prep_facts_refuse_renamed_stack_carriers() {
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        func.get_block_mut(0x1000).expect("entry").ops = vec![
            SSAOp::IntSub {
                dst: SSAVar::new("runtime.materialized.rsp", 1, 8),
                a: SSAVar::new("runtime.materialized.rsp", 0, 8),
                b: SSAVar::constant(8, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("runtime.materialized.rbp", 1, 8),
                src: SSAVar::new("runtime.materialized.rsp", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:fp_slot", 1, 8),
                a: SSAVar::new("runtime.materialized.rbp", 1, 8),
                b: SSAVar::constant(0xffffffffffffffe8, 8),
            },
        ];
        func.refresh_decompile_prep_facts();

        let facts = func.decompile_prep_facts().expect("prep facts");
        assert_eq!(
            facts.stack_address_root_of(&SSAVar::new("runtime.materialized.rsp", 1, 8)),
            None
        );
        assert_eq!(
            facts.stack_address_root_of(&SSAVar::new("runtime.materialized.rbp", 1, 8)),
            None
        );
        assert_eq!(
            facts.stack_address_root_of(&SSAVar::new("tmp:fp_slot", 1, 8)),
            None
        );
    }

    #[test]
    fn test_constant_display_names_do_not_supply_bits() {
        let named_constant = SSAVar::new("const:0x1234", 0, 8);
        assert_eq!(named_constant.constant_bits(), None);
        assert_eq!(adapt_root_width(&named_constant, 4), None);

        let mut canonical_constant = SSAVar::constant(0x1234, 8);
        canonical_constant.name = "not-a-constant".to_string();
        assert_eq!(canonical_constant.constant_bits(), Some(0x1234));
        assert_eq!(
            adapt_root_width(&canonical_constant, 4),
            Some(SSAVar::constant(0x1234, 4))
        );
    }

    #[test]
    fn prepared_ssa_preserves_exact_widths_when_unique_offsets_are_reused() {
        // Sleigh unique-space offsets are local scratch locations reused by
        // unrelated instruction templates. A later 8-byte definition must not
        // resize an earlier 16-byte IMUL overflow chain during SSA renaming.
        let extended = make_unique(0x2d180, 16);
        let product = make_unique(0x4b600, 16);
        let reused = make_unique(0x2d180, 8);
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntSExt {
                    dst: extended.clone(),
                    src: make_reg(0x88, 8),
                },
                R2ILOp::IntNotEqual {
                    dst: make_reg(0x200, 1),
                    a: extended,
                    b: product,
                },
                R2ILOp::Copy {
                    dst: reused,
                    src: make_reg(0x10, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];

        let artifact = SsaArtifact::raw(&blocks, None).expect("width-coherent prepared SSA");
        let ops = &artifact
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops;

        assert!(matches!(
            &ops[0],
            SSAOp::IntSExt { dst, src } if dst.size == 16 && src.size == 8
        ));
        assert!(matches!(
            &ops[1],
            SSAOp::IntNotEqual { dst, a, b }
                if dst.size == 1 && a.size == 16 && b.size == 16
        ));
        assert!(matches!(
            &ops[2],
            SSAOp::Copy { dst, src } if dst.size == 8 && src.size == 8
        ));
    }

    #[test]
    fn prepared_ssa_refuses_implicit_copy_and_comparison_width_changes() {
        for op in [
            R2ILOp::Copy {
                dst: make_unique(0x10, 8),
                src: make_reg(0x20, 4),
            },
            R2ILOp::IntNotEqual {
                dst: make_reg(0x200, 1),
                a: make_unique(0x10, 8),
                b: make_unique(0x20, 16),
            },
        ] {
            let blocks = vec![R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![op],
                switch_info: None,
                op_metadata: Default::default(),
            }];
            assert!(
                SsaArtifact::raw(&blocks, None).is_none(),
                "an implicit width change has no prepared-SSA proof"
            );
        }
    }

    fn call_preservation_arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("eax", 0, 4));
        arch.add_register(RegisterDef::new("rdi", 8, 8));
        arch.add_register(RegisterDef::new("rsi", 16, 8));
        arch.add_register(RegisterDef::new("rdx", 24, 8));
        arch
    }

    fn call_preservation_storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn call_preservation_block(ops: Vec<R2ILOp>) -> R2ILBlock {
        R2ILBlock {
            addr: 0x1000,
            size: 16,
            ops,
            switch_info: None,
            op_metadata: Default::default(),
        }
    }

    #[test]
    fn a_callee_proven_to_preserve_a_register_leaves_it_undefined_by_the_call() {
        let arch = call_preservation_arch();
        // call 0x2000; *rsi = rdi; return -- the compiler kept rdi live across
        // the call because it knows the callee never writes it.
        let block = call_preservation_block(vec![
            R2ILOp::Call {
                target: make_ram(0x2000, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: make_reg(16, 8),
                val: make_reg(8, 8),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ]);
        let rdi = call_preservation_storage(8, 8);
        let preserved = CalleePreservedCarriers::from([(0x2000u64, BTreeSet::from([rdi]))]);
        let with = SsaArtifact::for_decompile_with_callee_preserved_carriers(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            Vec::new(),
            Vec::new(),
            &preserved,
        )
        .expect("artifact with a preserving callee");
        let without = SsaArtifact::for_decompile_with_interfaces_and_tail_calls(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            Vec::new(),
            Vec::new(),
        )
        .expect("artifact without callee facts");
        let call_defines = |artifact: &SsaArtifact, name: &str| {
            artifact
                .function()
                .get_block(0x1000)
                .expect("entry block")
                .ops
                .iter()
                .filter(|op| {
                    matches!(op, SSAOp::CallDefine { dst } if dst.name.eq_ignore_ascii_case(name))
                })
                .count()
        };
        assert_eq!(call_defines(&without, "rdi"), 1);
        assert_eq!(call_defines(&with, "rdi"), 0);
        // What the callee may touch is still defined by the call.
        assert_eq!(call_defines(&with, "rsi"), 1);
        assert_eq!(call_defines(&with, "rax"), 1);
        // The store reads the value rdi held on entry, not a clobber.
        let stored = with
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Store { val, .. } => Some(val.clone()),
                _ => None,
            })
            .expect("the store survives");
        assert_eq!(
            stored.version, 0,
            "{stored:?} must be the entry value of rdi"
        );
    }

    #[test]
    fn a_leaf_body_preserves_every_clobbered_register_it_never_writes() {
        let arch = call_preservation_arch();
        let block = call_preservation_block(vec![
            R2ILOp::Copy {
                dst: make_reg(0, 4),
                src: make_const(1, 4),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ]);
        let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("leaf artifact");
        let preserved = &artifact.facts().boundaries.preserved_call_carriers;
        for offset in [8, 16, 24] {
            assert!(
                preserved.contains(&call_preservation_storage(offset, 8)),
                "register at {offset} is never written and must be preserved: {preserved:?}"
            );
        }
        assert!(!preserved.contains(&call_preservation_storage(0, 8)));
        assert!(!preserved.contains(&call_preservation_storage(0, 4)));
    }

    #[test]
    fn a_body_that_calls_preserves_nothing_its_own_call_may_touch() {
        let arch = call_preservation_arch();
        let block = call_preservation_block(vec![
            R2ILOp::Call {
                target: make_ram(0x2000, 8),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ]);
        let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("calling artifact");
        assert!(
            artifact
                .facts()
                .boundaries
                .preserved_call_carriers
                .is_empty(),
            "{:?}",
            artifact.facts().boundaries.preserved_call_carriers
        );
    }

    #[test]
    fn a_body_that_leaves_by_a_jump_claims_no_preserved_register() {
        let arch = call_preservation_arch();
        let block = call_preservation_block(vec![
            R2ILOp::Copy {
                dst: make_reg(0, 4),
                src: make_const(1, 4),
            },
            R2ILOp::Branch {
                target: make_ram(0x3000, 8),
            },
        ]);
        let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("jumping artifact");
        assert!(
            artifact
                .facts()
                .boundaries
                .preserved_call_carriers
                .is_empty(),
            "{:?}",
            artifact.facts().boundaries.preserved_call_carriers
        );
    }

    #[test]
    fn a_register_an_earlier_call_clobbered_is_not_an_argument_of_the_next_call() {
        let arch = call_preservation_arch();
        let slot = |offset| call_preservation_storage(offset, 8);
        // call A; rdi = 1; call B. B has no prototype, so its arguments are
        // what the machine set for it: rdi, and not the rsi and rdx that A's
        // clobbers left behind.
        let block = call_preservation_block(vec![
            R2ILOp::Call {
                target: make_ram(0x2000, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(8, 8),
                src: make_const(1, 8),
            },
            R2ILOp::Call {
                target: make_ram(0x3000, 8),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ]);
        let convention =
            SourceConventionSlots::new("amd64", vec![slot(8), slot(16), slot(24)], Some(slot(0)))
                .expect("convention slots");
        let machine_context = SourceMachineContext::from_blocks_with_interfaces(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(convention),
            Vec::new(),
        );
        let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            None,
            None,
            &CalleePreservedCarriers::new(),
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("decompile SSA");
        let artifact = SsaArtifact::new_with_context(
            function,
            FunctionPrepareMode::Decompile,
            machine_context,
        );
        let facts = artifact.facts();
        let boundary_of = |target: u64| {
            let call = facts
                .call_sites
                .by_id
                .values()
                .find(|call| call.direct_target == Some(target))
                .expect("call site");
            facts.boundaries.calls.get(&call.id).expect("call boundary")
        };
        assert!(boundary_of(0x2000).arguments.is_empty());
        let second = boundary_of(0x3000);
        assert!(second.complete, "{second:?}");
        assert_eq!(
            second
                .arguments
                .iter()
                .map(|argument| argument.slot)
                .collect::<Vec<_>>(),
            vec![crate::semantic::CallBoundarySlot::Register {
                index: 0,
                storage: slot(8),
            }],
            "{second:?}"
        );
    }

    #[test]
    fn a_declared_stack_argument_is_the_store_the_call_finds_above_its_stack_pointer() {
        // sp -= 8; [sp] = rdi        -- the caller materialises an argument
        // sp -= 8; [sp] = ret; call  -- the call instruction spends its slot
        // The prototype says argument 0 sits at +0 from the stack pointer as
        // the call finds it, which is the slot the first store filled.
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("rdi", 8, 8));
        arch.add_register(RegisterDef::new("rip", 16, 8));
        arch.add_register(RegisterDef::new("rsp", 32, 8));
        let storage = |offset, size| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        };
        let sp = make_reg(32, 8);
        let target = make_ram(0x2000, 8);
        let ops = vec![
            R2ILOp::IntSub {
                dst: sp.clone(),
                a: sp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: sp.clone(),
                val: make_reg(8, 8),
            },
            R2ILOp::IntSub {
                dst: sp.clone(),
                a: sp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: sp.clone(),
                val: make_const(0x100d, 8),
            },
            R2ILOp::Call {
                target: target.clone(),
            },
            R2ILOp::Return {
                target: make_reg(16, 8),
            },
        ];
        let call_index = 4;
        let mut op_metadata = std::collections::BTreeMap::new();
        for (index, instruction_addr) in [0x1000u64, 0x1000, 0x1008, 0x1008, 0x1008, 0x100d]
            .into_iter()
            .enumerate()
        {
            op_metadata.insert(
                index,
                r2il::OpMetadata {
                    instruction_addr: Some(instruction_addr),
                    ..Default::default()
                },
            );
        }
        let block = R2ILBlock {
            addr: 0x1000,
            size: 16,
            ops,
            switch_info: None,
            op_metadata,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"stack-argument".to_vec(),
            "test-stack-abi",
            [SourceAbiParameterSpec::new(0, storage(8, 8))],
            SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(storage(16, 8)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(32, 8)))
        .expect("caller interface");
        let roles = SourceMachineRoles::new(Some(storage(16, 8)), Some(storage(32, 8)))
            .expect("machine roles")
            .with_call_preserved_carriers(SourceCallPreservedCarriers::new(true, true));
        let identity =
            SourceCallSiteIdentity::new(0x1008, CanonicalStorageId::from_varnode(&target));
        let call_interface = SourceCallSiteInterface::new(
            b"stack-argument".to_vec(),
            identity,
            true,
            "test-stack-abi",
            [SourceCallArgumentSpec::on_stack(0, 0, 8)],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("callsite interface");
        let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
            &[block],
            Some(&arch),
            Some(interface),
            roles,
            vec![call_interface],
        )
        .expect("artifact");
        let facts = artifact.facts();
        let call = facts
            .call_sites
            .by_id
            .values()
            .find(|call| call.direct_target == Some(0x2000))
            .expect("call site");
        let boundary = facts.boundaries.calls.get(&call.id).expect("boundary");
        assert!(boundary.complete, "{boundary:?}");
        let [argument] = boundary.arguments.as_slice() else {
            panic!("one stack argument: {boundary:?}");
        };
        assert_eq!(
            argument.slot,
            crate::semantic::CallBoundarySlot::Stack(-8),
            "{boundary:?}"
        );
        let crate::semantic::SourceCallArgumentValue::Value(value) = argument.value else {
            panic!("{boundary:?}");
        };
        assert_eq!(
            artifact
                .graph()
                .value(value)
                .map(|value| value.var.name.as_str()),
            Some("rdi"),
            "the argument is what the first store put in the slot"
        );
        let certificate = artifact
            .callsite_certificate_for_op(0x1000, call_index)
            .expect("callsite certificate");
        assert!(
            matches!(
                certificate.argument_certificates.as_slice(),
                [crate::semantic::CallArgumentCertificate {
                    index: 0,
                    location: crate::semantic::CallArgumentLocation::Stack { offset: -8, .. },
                    ..
                }]
            ),
            "{:?}",
            certificate.argument_certificates
        );
    }
}
