//! r2engine owns cross-crate analysis orchestration.
//!
//! Fact ownership stays in the lower crates: SSA in `r2ssa`, type facts in
//! `r2types`, and rendering in `r2dec`. This crate is
//! the request-level scheduler boundary that decides which artifacts are
//! needed for a request. Analysis artifacts are built directly for each
//! source snapshot request.

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

pub mod discovery;
pub mod isolation;
pub mod names;
pub mod native;
pub mod program;
pub mod query;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use r2il::R2ILBlock;
use r2ssa::{CFGRiskSummary, SsaArtifact};
#[cfg(test)]
use r2types::FunctionTypeFacts;
use r2types::{
    FunctionFacts, MetadataScalarKind, TypeHint, merge_type_hint, type_hint_from_value_metadata,
};
use serde::{Deserialize, Serialize};

mod json;
use json::*;
pub use json::{
    RenderProofJson, RenderRefusalJson, RenderedFunctionJson, RenderedLineJson, RenderedLinkJson,
    RenderedResidualJson, RenderedVariableJson,
};
pub use r2sleigh_lift::disasm::syntax::number_spans;
pub use r2sleigh_lift::{NumberSpan, Syntax};

mod route;

pub use r2dec::{
    BindingMachineProjectionFailure, BindingObservationAudit, BindingObservationDomainAudit,
    BindingObservationJournalFailure, BindingShadowAuditFailure, BindingShadowAuditLedger,
    BindingShadowAuditOutcome, BindingShadowDomainAudit, DecompileRenderRefusal,
    EffectObligationAudit, EffectObligationDisposition, PlacementAudit, PlacementAuditRefusal,
};
use route::decompile_route_decision;
pub use route::{
    EngineDiagnostics, EngineFunctionIdentity, EnginePlan, EngineRequestKind, EngineRequestPlan,
    EngineRouteDecision, EngineTypeRouteDecision, EngineTypeRouteKind, EngineTypedRouteDecision,
    cfg_guard_reason_from_summary, plan_type_request, select_engine_plan,
    should_guard_program_orchestrator_decompile, should_use_prepared_semantic_view,
    type_cfg_allows_semantic_plan, type_cfg_bounded_reason, type_cfg_forces_bounded_plan,
    type_cfg_prefers_bounded_plan, type_route_decision,
};
#[cfg(test)]
use route::{plan_decompile_request, semantic_route_reason};
const MISSING_SOURCE_SNAPSHOT_REFUSAL: &str =
    "engine analysis requires an immutable source snapshot";

/// Immutable, source-owned interface facts for one exact lifted revision.
///
/// The engine only transports these facts into SSA. It does not infer a
/// revision identity or upgrade absent interface data into authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSourceSnapshot {
    revision_identity: Box<[u8]>,
    function_interface: Option<r2ssa::SourceFunctionInterface>,
    machine_roles: r2ssa::SourceMachineRoles,
    call_site_interfaces: Box<[r2ssa::SourceCallSiteInterface]>,
    /// What the source's convention says a call does, where it says.
    call_effect: Option<r2ssa::SourceCallEffect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineSourceSnapshotError {
    EmptyRevisionIdentity,
    FunctionRevisionMismatch,
    CallSiteRevisionMismatch,
    DuplicateCallSiteIdentity,
    DuplicateCallSiteLocation,
}

impl std::fmt::Display for EngineSourceSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid engine source snapshot: {self:?}")
    }
}

impl std::error::Error for EngineSourceSnapshotError {}

impl EngineSourceSnapshot {
    pub fn new(
        revision_identity: impl Into<Vec<u8>>,
        function_interface: Option<r2ssa::SourceFunctionInterface>,
        call_site_interfaces: impl IntoIterator<Item = r2ssa::SourceCallSiteInterface>,
    ) -> Result<Self, EngineSourceSnapshotError> {
        Self::new_with_machine_roles(
            revision_identity,
            function_interface,
            r2ssa::SourceMachineRoles::default(),
            call_site_interfaces,
        )
    }

    pub fn new_with_machine_roles(
        revision_identity: impl Into<Vec<u8>>,
        function_interface: Option<r2ssa::SourceFunctionInterface>,
        machine_roles: r2ssa::SourceMachineRoles,
        call_site_interfaces: impl IntoIterator<Item = r2ssa::SourceCallSiteInterface>,
    ) -> Result<Self, EngineSourceSnapshotError> {
        let revision_identity = revision_identity.into();
        if revision_identity.is_empty() {
            return Err(EngineSourceSnapshotError::EmptyRevisionIdentity);
        }
        if function_interface
            .as_ref()
            .is_some_and(|interface| interface.revision_identity() != revision_identity)
        {
            return Err(EngineSourceSnapshotError::FunctionRevisionMismatch);
        }
        let call_site_interfaces = call_site_interfaces.into_iter().collect::<Vec<_>>();
        if call_site_interfaces
            .iter()
            .any(|interface| interface.revision_identity() != revision_identity)
        {
            return Err(EngineSourceSnapshotError::CallSiteRevisionMismatch);
        }
        let mut identities = BTreeSet::new();
        let mut locations = BTreeSet::new();
        for interface in &call_site_interfaces {
            let identity = interface.identity();
            if !identities.insert(identity) {
                return Err(EngineSourceSnapshotError::DuplicateCallSiteIdentity);
            }
            if !locations.insert(identity.instruction()) {
                return Err(EngineSourceSnapshotError::DuplicateCallSiteLocation);
            }
        }
        Ok(Self {
            revision_identity: revision_identity.into_boxed_slice(),
            function_interface,
            machine_roles,
            call_site_interfaces: call_site_interfaces.into_boxed_slice(),
            call_effect: None,
        })
    }

    /// State what the source's convention says a call does.
    #[must_use]
    pub fn with_call_effect(mut self, call_effect: r2ssa::SourceCallEffect) -> Self {
        self.call_effect = Some(call_effect);
        self
    }

    pub const fn call_effect(&self) -> Option<&r2ssa::SourceCallEffect> {
        self.call_effect.as_ref()
    }

    pub const fn revision_identity(&self) -> &[u8] {
        &self.revision_identity
    }

    pub const fn function_interface(&self) -> Option<&r2ssa::SourceFunctionInterface> {
        self.function_interface.as_ref()
    }

    pub const fn machine_roles(&self) -> &r2ssa::SourceMachineRoles {
        &self.machine_roles
    }

    pub const fn call_site_interfaces(&self) -> &[r2ssa::SourceCallSiteInterface] {
        &self.call_site_interfaces
    }
}

pub fn direct_block_c_residual_comment(block_addr: u64) -> String {
    format!(
        "/* r2dec residual: block C output for 0x{block_addr:x} requires engine FunctionFacts route; direct C-like block decompile suppressed */"
    )
}

pub fn direct_block_ast_residual_json(block_addr: u64) -> String {
    let comment = format!(
        "r2dec residual: block AST for 0x{block_addr:x} requires engine FunctionFacts route; direct SSA op lowering suppressed"
    );
    let value = serde_json::json!([{ "Comment": comment }]);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "[]".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineAutoCallbackKind {
    AnalyzeFunction,
    DataRefs,
    PostAnalysisTaint,
    PostAnalysisXref,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineAutoCallbackRefusalReason {
    Allowed,
    ModeNotFull,
    TooManyBlocks,
    TooLarge,
    TooCostly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineAutoCallbackMetrics {
    pub basic_block_count: u32,
    pub cost: u32,
    pub linear_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineAutoCallbackPlan {
    pub allowed: bool,
    pub kind: EngineAutoCallbackKind,
    pub reason: EngineAutoCallbackRefusalReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePhase {
    SnapshotContext,
    LiftNormalize,
    Ssa,
    Obligations,
    Symbolic,
    Types,
    Certification,
    Structuring,
    Normalization,
    Rendering,
    FfiConversion,
}

impl EnginePhase {
    pub const ALL: [Self; 11] = [
        Self::SnapshotContext,
        Self::LiftNormalize,
        Self::Ssa,
        Self::Obligations,
        Self::Symbolic,
        Self::Types,
        Self::Certification,
        Self::Structuring,
        Self::Normalization,
        Self::Rendering,
        Self::FfiConversion,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotContext => "snapshot_context",
            Self::LiftNormalize => "lift_normalize",
            Self::Ssa => "ssa",
            Self::Obligations => "obligations",
            Self::Symbolic => "symbolic",
            Self::Types => "types",
            Self::Certification => "certification",
            Self::Structuring => "structuring",
            Self::Normalization => "normalization",
            Self::Rendering => "rendering",
            Self::FfiConversion => "ffi_conversion",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePhaseStatus {
    NotExecuted,
    Executed,
    /// The phase executed inside the elapsed span attributed to another
    /// boundary. Its zero duration means "not separately measured", not free.
    Folded,
    Refused,
}

impl EnginePhaseTimingJson {
    fn not_executed(phase: EnginePhase) -> Self {
        Self {
            phase,
            status: EnginePhaseStatus::NotExecuted,
            elapsed_us: 0,
        }
    }
}

fn empty_engine_phase_timings() -> Vec<EnginePhaseTimingJson> {
    EnginePhase::ALL
        .into_iter()
        .map(EnginePhaseTimingJson::not_executed)
        .collect()
}

pub fn engine_normalized_arch_name(arch: Option<&r2il::ArchSpec>) -> Option<String> {
    let arch = arch?;
    let family = r2ssa::MachineArchitectureFamily::from_arch_spec(Some(arch));
    Some(
        match family {
            r2ssa::MachineArchitectureFamily::X86 => "x86",
            r2ssa::MachineArchitectureFamily::X86_64 => "x86-64",
            r2ssa::MachineArchitectureFamily::Arm => "arm",
            r2ssa::MachineArchitectureFamily::AArch64 => "aarch64",
            r2ssa::MachineArchitectureFamily::RiscV32 => "riscv32",
            r2ssa::MachineArchitectureFamily::RiscV64 => "riscv64",
            r2ssa::MachineArchitectureFamily::Mips32 => "mips",
            r2ssa::MachineArchitectureFamily::Mips64 => "mips64",
            r2ssa::MachineArchitectureFamily::PowerPc32 => "powerpc",
            r2ssa::MachineArchitectureFamily::PowerPc64 => "powerpc64",
            r2ssa::MachineArchitectureFamily::Unknown => return Some(arch.name.clone()),
        }
        .to_string(),
    )
}

pub fn engine_arch_target(arch: Option<&r2il::ArchSpec>) -> (String, u32) {
    let arch_name = engine_normalized_arch_name(arch).unwrap_or_else(|| "unknown".to_string());
    let ptr_bits = arch.map(engine_effective_ptr_bits).unwrap_or(64);
    (arch_name, ptr_bits)
}

pub fn engine_effective_ptr_bits(arch: &r2il::ArchSpec) -> u32 {
    engine_effective_addr_size_bytes(arch).saturating_mul(8)
}

fn engine_effective_addr_size_bytes(arch: &r2il::ArchSpec) -> u32 {
    if arch.addr_size > 1 {
        return arch.addr_size;
    }

    if let Some(pc_size) = arch
        .registers
        .iter()
        .find(|reg| {
            matches!(
                reg.name.to_ascii_lowercase().as_str(),
                "pc" | "ip" | "eip" | "rip"
            )
        })
        .map(|reg| reg.size)
        .filter(|size| *size > 1)
    {
        return pc_size;
    }

    if let Some(default_size) = arch
        .spaces
        .iter()
        .find(|space| space.is_default && space.addr_size > 1)
        .map(|space| space.addr_size)
    {
        return default_size;
    }

    arch.spaces
        .iter()
        .map(|space| space.addr_size)
        .max()
        .filter(|size| *size > 1)
        .unwrap_or(arch.addr_size.max(1))
}

fn metadata_scalar_kind_from_r2il(kind: r2il::ScalarKind) -> MetadataScalarKind {
    match kind {
        r2il::ScalarKind::Bool => MetadataScalarKind::Bool,
        r2il::ScalarKind::SignedInt => MetadataScalarKind::SignedInt,
        r2il::ScalarKind::UnsignedInt => MetadataScalarKind::UnsignedInt,
        r2il::ScalarKind::Float => MetadataScalarKind::Float,
        r2il::ScalarKind::Bitvector => MetadataScalarKind::Bitvector,
        r2il::ScalarKind::Unknown => MetadataScalarKind::Unknown,
    }
}

fn metadata_type_hint_for_varnode(vn: &r2il::Varnode) -> Option<TypeHint> {
    let meta = vn.meta.as_ref()?;
    let pointer_like = meta
        .pointer_hint
        .is_some_and(|hint| !matches!(hint, r2il::PointerHint::Unknown));
    let scalar_kind = meta.scalar_kind.map(metadata_scalar_kind_from_r2il);

    type_hint_from_value_metadata(pointer_like, scalar_kind, vn.size)
}

pub fn collect_register_type_hints_with_names<F>(
    r2il_blocks: &[R2ILBlock],
    mut register_name: F,
) -> HashMap<String, TypeHint>
where
    F: FnMut(&r2il::Varnode) -> Option<String>,
{
    let mut hints = HashMap::new();

    let mut visit = |vn: &r2il::Varnode| {
        if !vn.is_register() {
            return;
        }
        let Some(hint) = metadata_type_hint_for_varnode(vn) else {
            return;
        };
        let Some(name) = register_name(vn) else {
            return;
        };

        merge_type_hint(&mut hints, name.to_ascii_lowercase(), hint);
    };

    for block in r2il_blocks {
        for op in &block.ops {
            if let Some(vn) = op.output() {
                visit(vn);
            }
            for vn in op.inputs() {
                visit(vn);
            }
        }
    }

    hints
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngineRenderTarget {
    pub arch_name: String,
    pub ptr_bits: u32,
}

impl Default for EngineRenderTarget {
    fn default() -> Self {
        Self::for_arch_name("x86-64", 64)
    }
}

impl EngineRenderTarget {
    pub fn for_arch_name(arch_name: &str, ptr_bits: u32) -> Self {
        let arch_name = match (arch_name.to_ascii_lowercase().as_str(), ptr_bits) {
            ("x86_64" | "x64" | "amd64", _) => "x86-64".to_string(),
            ("x86-64", _) => "x86-64".to_string(),
            ("x86-32" | "i386" | "i686", _) => "x86".to_string(),
            ("x86", _) => "x86".to_string(),
            _ => arch_name.to_string(),
        };
        Self {
            arch_name,
            ptr_bits,
        }
    }

    pub fn for_arch(arch: Option<&r2il::ArchSpec>) -> (String, u32, Self) {
        let (arch_name, ptr_bits) = engine_arch_target(arch);
        let target = Self::for_arch_name(&arch_name, ptr_bits);
        (arch_name, ptr_bits, target)
    }

    pub fn for_arch_with_ptr_bits(arch: Option<&r2il::ArchSpec>, ptr_bits: u32) -> (String, Self) {
        let arch_name = engine_normalized_arch_name(arch).unwrap_or_else(|| "unknown".to_string());
        let target = Self::for_arch_name(&arch_name, ptr_bits);
        (arch_name, target)
    }

    fn for_prepared(source: &SsaArtifact) -> Option<Self> {
        let memory = source.machine_context().memory_model();
        if !memory.is_available() || !memory.is_coherent() {
            return None;
        }
        let ptr_bits = memory.default_address_bits();
        if ptr_bits == 0 {
            return None;
        }
        let (arch_name, expected_bits) = match source.machine_context().architecture_family() {
            r2ssa::MachineArchitectureFamily::X86 => ("x86", 32),
            r2ssa::MachineArchitectureFamily::X86_64 => ("x86-64", 64),
            r2ssa::MachineArchitectureFamily::Arm => ("arm", 32),
            r2ssa::MachineArchitectureFamily::AArch64 => ("aarch64", 64),
            r2ssa::MachineArchitectureFamily::RiscV32 => ("riscv32", 32),
            r2ssa::MachineArchitectureFamily::RiscV64 => ("riscv64", 64),
            r2ssa::MachineArchitectureFamily::Mips32 => ("mips", 32),
            r2ssa::MachineArchitectureFamily::Mips64 => ("mips64", 64),
            r2ssa::MachineArchitectureFamily::PowerPc32 => ("powerpc", 32),
            r2ssa::MachineArchitectureFamily::PowerPc64 => ("powerpc64", 64),
            r2ssa::MachineArchitectureFamily::Unknown => return None,
        };
        if ptr_bits != expected_bits {
            return None;
        }
        Some(Self::for_arch_name(arch_name, ptr_bits))
    }

    fn to_decompiler_config(&self) -> r2dec::DecompilerConfig {
        r2dec::DecompilerConfig::for_arch_name(&self.arch_name, self.ptr_bits)
    }
}

#[derive(Debug, Clone)]
pub struct EngineMetrics {
    pub planning_time: Duration,
    pub ssa_time: Duration,
    pub semantic_time: Duration,
    pub type_time: Duration,
    pub render_time: Duration,
    /// Units of work this request counted, the deterministic measure of what
    /// the wall-clock deadline stands in for.
    pub work_spent: u64,
    /// Stable, complete phase inventory. A phase which this engine boundary
    /// did not execute is retained with `NotExecuted` status and zero time.
    pub phase_timings: Vec<EnginePhaseTimingJson>,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self {
            work_spent: 0,
            planning_time: Duration::default(),
            ssa_time: Duration::default(),
            semantic_time: Duration::default(),
            type_time: Duration::default(),
            render_time: Duration::default(),
            phase_timings: empty_engine_phase_timings(),
        }
    }
}

impl EngineMetrics {
    fn record_phase(&mut self, phase: EnginePhase, status: EnginePhaseStatus, elapsed: Duration) {
        let elapsed_us = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let timing = self
            .phase_timings
            .iter_mut()
            .find(|timing| timing.phase == phase)
            .expect("engine metrics must contain every stable phase");
        timing.status = status;
        timing.elapsed_us = elapsed_us;
    }

    fn refuse_from(&mut self, phase: EnginePhase) {
        let Some(start) = self
            .phase_timings
            .iter()
            .position(|timing| timing.phase == phase)
        else {
            return;
        };
        for timing in &mut self.phase_timings[start..] {
            if timing.status == EnginePhaseStatus::NotExecuted {
                timing.status = EnginePhaseStatus::Refused;
            }
        }
    }

    fn record_folded_if_not_executed(&mut self, phase: EnginePhase) {
        if self
            .phase_timings
            .iter()
            .any(|timing| timing.phase == phase && timing.status == EnginePhaseStatus::NotExecuted)
        {
            self.record_phase(phase, EnginePhaseStatus::Folded, Duration::default());
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineAnalysis {
    ssa_func: Arc<SsaArtifact>,
}

impl EngineAnalysis {
    /// Construct an engine-owned analysis from an already prepared SSA owner.
    pub(crate) fn from_prepared_ssa(ssa_func: Arc<SsaArtifact>) -> Self {
        Self { ssa_func }
    }

    /// Borrow the immutable prepared SSA consumed by this analysis.
    pub fn ssa_func(&self) -> &SsaArtifact {
        self.ssa_func.as_ref()
    }

    fn from_trusted_ssa(trusted: &r2ssa::TrustedSsaArtifact) -> Self {
        Self {
            ssa_func: trusted.shared_artifact(),
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn bounded_type_plan_budget_policy_is_fail_closed() {
        let interproc_max_iters = kani::any::<usize>();
        let interproc_converged: bool = kani::any();
        let prefers_bounded =
            type_analysis_interproc_prefers_bounded_plan(interproc_max_iters, interproc_converged);

        assert_eq!(
            prefers_bounded,
            interproc_max_iters <= 1 && !interproc_converged
        );
        if interproc_converged || interproc_max_iters > 1 {
            assert!(!prefers_bounded);
        }
    }
}

#[derive(Debug)]
pub struct EngineAnalysisArtifact {
    type_analysis: r2types::TypeAnalysis,
    /// Certifying view of the retained source, available only for the unmodified
    /// source-retaining trusted preparation path.
    trusted_ssa: Option<Arc<r2ssa::TrustedSsaArtifact>>,
}

impl EngineAnalysisArtifact {
    fn new(
        type_analysis: r2types::TypeAnalysis,
        trusted_ssa: Option<Arc<r2ssa::TrustedSsaArtifact>>,
    ) -> Option<Self> {
        let source = type_analysis.shared_source();
        if trusted_ssa
            .as_deref()
            .is_some_and(|trusted| !trusted.shares_artifact(&source))
        {
            return None;
        }
        Some(Self {
            type_analysis,
            trusted_ssa,
        })
    }

    /// Borrow the exact immutable SSA owner used to build these facts.
    pub fn ssa_func(&self) -> &SsaArtifact {
        self.type_analysis.source()
    }

    /// Borrow the report sealed to the exact immutable SSA owner.
    pub fn function_facts(&self) -> &FunctionFacts {
        self.type_analysis.function_facts()
    }

    /// Borrow the inseparable source-owned type analysis.
    pub fn type_analysis(&self) -> &r2types::TypeAnalysis {
        &self.type_analysis
    }

    /// Borrow request-local certification authority when this artifact retains it.
    pub fn trusted_ssa(&self) -> Option<&r2ssa::TrustedSsaArtifact> {
        self.trusted_ssa.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineSemanticMode {
    Full,
    Optional,
}

#[derive(Debug, Clone, Default)]
pub struct EngineCancellationToken {
    ssa: r2ssa::SsaCancellationToken,
}

impl EngineCancellationToken {
    pub fn cancel(&self) {
        self.ssa.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.ssa.is_cancelled()
    }
}

#[derive(Debug, Clone, Default)]
pub struct EngineExecutionControl {
    cancellation: EngineCancellationToken,
    deadline: Option<Instant>,
    /// Work this request has done, counted rather than timed, so the size of
    /// the thing the deadline stands in for can be measured.
    meter: Arc<r2ssa::SsaWorkMeter>,
}

impl EngineExecutionControl {
    /// Build a control in which cancellation and a deadline coexist.
    pub fn new(cancellation: EngineCancellationToken, deadline: Option<Instant>) -> Self {
        Self {
            cancellation,
            deadline,
            meter: Arc::new(r2ssa::SsaWorkMeter::default()),
        }
    }

    /// Work counted for this request so far.
    pub fn work_spent(&self) -> u64 {
        self.meter.spent()
    }

    pub fn with_cancellation_and_deadline(
        cancellation: EngineCancellationToken,
        deadline: Instant,
    ) -> Self {
        Self::new(cancellation, Some(deadline))
    }

    pub fn with_cancellation(cancellation: EngineCancellationToken) -> Self {
        Self::new(cancellation, None)
    }

    pub fn with_deadline(deadline: Instant) -> Self {
        Self::new(EngineCancellationToken::default(), Some(deadline))
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self::with_deadline(
            Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        )
    }

    pub fn cancellation(&self) -> EngineCancellationToken {
        self.cancellation.clone()
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn ssa_execution_control(&self) -> r2ssa::SsaExecutionControl {
        r2ssa::SsaExecutionControl::new(self.cancellation.ssa.clone(), self.deadline)
            .metered(Arc::clone(&self.meter))
    }

    fn replace_cancellation(&mut self, cancellation: EngineCancellationToken) {
        self.cancellation = cancellation;
    }

    fn replace_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    fn refusal_reason(&self, phase: EnginePhase) -> Option<String> {
        if self.cancellation.is_cancelled() {
            return Some(format!(
                "engine request cancelled before {} phase",
                phase.as_str()
            ));
        }
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            .then(|| {
                format!(
                    "engine request deadline exceeded before {} phase",
                    phase.as_str()
                )
            })
    }
}

#[derive(Debug, Clone)]
pub struct EngineExecutionRefusal {
    pub reason: String,
    pub phase: EnginePhase,
    pub metrics: Box<EngineMetrics>,
    pub diagnostics: Box<EngineDiagnostics>,
}

impl std::fmt::Display for EngineExecutionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for EngineExecutionRefusal {}

fn engine_execution_refusal(
    reason: String,
    phase: EnginePhase,
    mut metrics: EngineMetrics,
) -> EngineExecutionRefusal {
    metrics.refuse_from(phase);
    EngineExecutionRefusal {
        diagnostics: Box::new(EngineDiagnostics {
            plan: Some(EnginePlan::RefuseWithEvidence),
            route_reason: Some(reason.clone()),
            refusal: Some(reason.clone()),
            ..EngineDiagnostics::default()
        }),
        reason,
        phase,
        metrics: Box::new(metrics),
    }
}

fn engine_render_execution_refusal(
    reason: String,
    phase: EnginePhase,
    metrics: EngineMetrics,
) -> EngineExecutionRefusal {
    EngineExecutionRefusal {
        diagnostics: Box::new(EngineDiagnostics {
            plan: Some(EnginePlan::RefuseWithEvidence),
            route_reason: Some(reason.clone()),
            refusal: Some(reason.clone()),
            ..EngineDiagnostics::default()
        }),
        reason,
        phase,
        metrics: Box::new(metrics),
    }
}

fn ssa_prepare_execution_refusal(
    error: r2ssa::SsaPrepareError,
    metrics: EngineMetrics,
) -> EngineExecutionRefusal {
    let reason = match error {
        r2ssa::SsaPrepareError::Cancelled => {
            "engine request cancelled during ssa phase".to_string()
        }
        r2ssa::SsaPrepareError::DeadlineExceeded => {
            "engine request deadline exceeded during ssa phase".to_string()
        }
        r2ssa::SsaPrepareError::MalformedInput => {
            "malformed SSA source input during ssa phase".to_string()
        }
        r2ssa::SsaPrepareError::NoCallEffect => {
            "the convention states nothing a call leaves standing".to_string()
        }
    };
    engine_execution_refusal(reason, EnginePhase::Ssa, metrics)
}

fn poll_engine_execution(
    execution: &EngineExecutionControl,
    phase: EnginePhase,
    metrics: &EngineMetrics,
) -> Result<(), EngineExecutionRefusal> {
    if let Some(reason) = execution.refusal_reason(phase) {
        return Err(engine_execution_refusal(reason, phase, metrics.clone()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EngineAnalyzeRequest {
    pub function_name: String,
    pub function_addr: u64,
    /// The lift this request is built from, when the request is the thing that
    /// owns it. A trusted artifact already holds the blocks its SSA was built
    /// from, so this is empty on that path and `source_blocks` reads through
    /// the artifact: one lift, one owner.
    blocks: Vec<R2ILBlock>,
    pub arch: Option<r2il::ArchSpec>,
    pub source_snapshot: Option<Arc<EngineSourceSnapshot>>,
    trusted_ssa: Option<Arc<r2ssa::TrustedSsaArtifact>>,
    /// Bodies of the functions the root calls, captured in the same transaction.
    callee_facts: Vec<CalleeFacts>,
    /// Signatures the program declares for callees it carries no body for.
    declared_signatures: Vec<r2types::SourceOwnedCalleeSignature>,
    /// Each callee's own typed source context, retained until `r2types` derives
    /// the source-owned signature that callers may consume.
    pub ptr_bits: u32,
    pub semantic_metadata_enabled: bool,
    pub reg_type_hints: HashMap<String, r2types::TypeHint>,
    pub parsed_context: r2types::ParsedExternalContext,
    pub semantic_mode: EngineSemanticMode,
    pub include_interproc_summary_set: bool,
    pub execution: EngineExecutionControl,
}

#[derive(Debug, Clone)]
pub struct EngineAnalyzeRequestParts {
    pub function_name: String,
    pub function_addr: u64,
    pub blocks: Vec<R2ILBlock>,
    pub arch: Option<r2il::ArchSpec>,
    pub source_snapshot: Option<Arc<EngineSourceSnapshot>>,
    pub ptr_bits: u32,
    pub semantic_metadata_enabled: bool,
    pub reg_type_hints: HashMap<String, r2types::TypeHint>,
    pub parsed_context: r2types::ParsedExternalContext,
    pub include_interproc_summary_set: bool,
}

#[derive(Debug, Clone)]
pub struct EngineFunctionInput {
    pub function_name: String,
    pub function_addr: u64,
    pub blocks: Vec<R2ILBlock>,
    pub arch: Option<r2il::ArchSpec>,
    pub source_snapshot: Option<Arc<EngineSourceSnapshot>>,
    pub semantic_metadata_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineFunctionInputQuality {
    pub expected_blocks: usize,
    pub lifted_blocks: usize,
    pub read_failures: usize,
    pub invalid_blocks: usize,
    pub null_lift_failures: usize,
    pub truncated_blocks: usize,
}

impl EngineFunctionInputQuality {
    pub fn complete(lifted_blocks: usize) -> Self {
        Self {
            expected_blocks: lifted_blocks,
            lifted_blocks,
            read_failures: 0,
            invalid_blocks: 0,
            null_lift_failures: 0,
            truncated_blocks: 0,
        }
    }

    pub fn is_complete(self) -> bool {
        self.expected_blocks > 0
            && self.lifted_blocks > 0
            && self.expected_blocks == self.lifted_blocks
            && self.read_failures == 0
            && self.invalid_blocks == 0
            && self.null_lift_failures == 0
            && self.truncated_blocks == 0
    }

    pub fn refusal_reason(self) -> Option<String> {
        if self.expected_blocks == 0 || self.lifted_blocks == 0 {
            return Some(format!(
                "empty lifted function input: expected_blocks={} lifted_blocks={} read_failures={} invalid_blocks={} null_lift_failures={} truncated_blocks={}",
                self.expected_blocks,
                self.lifted_blocks,
                self.read_failures,
                self.invalid_blocks,
                self.null_lift_failures,
                self.truncated_blocks
            ));
        }
        (!self.is_complete()).then(|| {
            format!(
                "incomplete lifted function input: expected_blocks={} lifted_blocks={} read_failures={} invalid_blocks={} null_lift_failures={} truncated_blocks={}",
                self.expected_blocks,
                self.lifted_blocks,
                self.read_failures,
                self.invalid_blocks,
                self.null_lift_failures,
                self.truncated_blocks
            )
        })
    }

    pub fn refusal_reason_for_actual_lifted_blocks(
        self,
        actual_lifted_blocks: usize,
    ) -> Option<String> {
        if self.lifted_blocks != actual_lifted_blocks {
            return Some(format!(
                "inconsistent lifted function input: expected_blocks={} lifted_blocks={} actual_lifted_blocks={} read_failures={} invalid_blocks={} null_lift_failures={} truncated_blocks={}",
                self.expected_blocks,
                self.lifted_blocks,
                actual_lifted_blocks,
                self.read_failures,
                self.invalid_blocks,
                self.null_lift_failures,
                self.truncated_blocks
            ));
        }
        self.refusal_reason()
    }
}

fn function_input_quality_facts(
    quality: EngineFunctionInputQuality,
    actual_lifted_blocks: usize,
    refusal_reason: Option<String>,
) -> r2types::FunctionInputQualityFacts {
    r2types::FunctionInputQualityFacts {
        expected_blocks: quality.expected_blocks,
        lifted_blocks: quality.lifted_blocks,
        actual_lifted_blocks,
        read_failures: quality.read_failures,
        invalid_blocks: quality.invalid_blocks,
        null_lift_failures: quality.null_lift_failures,
        truncated_blocks: quality.truncated_blocks,
        refusal_reason,
    }
}

#[derive(Debug, Clone)]
pub struct EngineAnalyzeRequestInput {
    pub function_name: String,
    pub function_addr: u64,
    pub blocks: Vec<R2ILBlock>,
    pub arch: Option<r2il::ArchSpec>,
    pub source_snapshot: Option<Arc<EngineSourceSnapshot>>,
    pub ptr_bits: Option<u32>,
    pub semantic_metadata_enabled: bool,
    pub reg_type_hints: HashMap<String, r2types::TypeHint>,
    pub parsed_context: r2types::ParsedExternalContext,
    pub include_interproc_summary_set: bool,
}

#[derive(Debug, Clone)]
pub struct EngineAnalyzeFunctionRequestInput {
    pub function: EngineFunctionInput,
    pub ptr_bits: Option<u32>,
    pub reg_type_hints: HashMap<String, r2types::TypeHint>,
    pub parsed_context: r2types::ParsedExternalContext,
    pub include_interproc_summary_set: bool,
}

/// Names the source gave its stack slots, keyed the way the renderer looks them up.
///
/// These are presentation only: the role comes from the interface so a home or a
/// saved carrier is not offered as a local, and a name that matches no slot is
/// not carried at all.
/// A source type rendered as the source spells it.
///
/// The shared parser canonicalises a spelling to structure, which is right for
/// analysis and wrong for a name: it turns `char` into an eight-bit integer and
/// `size_t` into an unsigned word, so the rendered C says `int8_t *` where the
/// source said `char *`. Structure is already carried by the type graph, so the
/// spelling is what this has to preserve.
fn source_spelled_type(spelling: &str, ptr_bits: u32) -> Option<r2types::CTypeLike> {
    let mut rest = spelling.trim();
    if rest.is_empty() {
        return None;
    }
    let mut array_len = None;
    if let Some(start) = rest.rfind('[')
        && rest.ends_with(']')
    {
        let len = &rest[start + 1..rest.len() - 1];
        array_len = Some(len.trim().parse::<usize>().ok());
        rest = rest[..start].trim_end();
    }
    let mut pointers = 0usize;
    while let Some(stripped) = rest.strip_suffix('*') {
        pointers += 1;
        rest = stripped.trim_end();
    }
    // A qualifier on the pointee is part of the pointer's type; on the value it is not.
    let const_pointee = pointers > 0
        && rest.split_whitespace().any(|word| {
            matches!(
                word.to_ascii_lowercase().as_str(),
                "const" | "__const" | "__const__"
            )
        });
    let base_words = rest
        .split_whitespace()
        .filter(|word| {
            !matches!(
                word.to_ascii_lowercase().as_str(),
                "const"
                    | "volatile"
                    | "restrict"
                    | "__restrict"
                    | "__restrict__"
                    | "__const"
                    | "__const__"
            )
        })
        .collect::<Vec<_>>();
    let base_spelling = base_words.join(" ");
    if base_spelling.is_empty() {
        return None;
    }
    // A structural spelling stays structural so width-aware analysis keeps
    // working; a named one is carried by name so it renders as itself.
    let mut ty = match r2types::parse_c_type_like(&base_spelling, ptr_bits) {
        Some(r2types::CTypeLike::Void) => r2types::CTypeLike::Void,
        Some(
            structural @ (r2types::CTypeLike::Struct(_)
            | r2types::CTypeLike::Union(_)
            | r2types::CTypeLike::Enum(_)),
        ) => structural,
        // The name is what renders and the parse is what it stands for, so
        // width-aware analysis keeps working through the name instead of
        // having to re-read the text. A spelling that parses to nothing more
        // than itself carries no target, and a spelling that is the type
        // written out rather than a name for one carries no name.
        Some(r2types::CTypeLike::Typedef { .. }) => r2types::CTypeLike::typedef(base_spelling),
        Some(parsed) if !r2types::spelling_names_a_type(&base_spelling) => parsed,
        Some(parsed) => r2types::CTypeLike::named(base_spelling, parsed),
        None => return None,
    };
    if const_pointee {
        ty = r2types::CTypeLike::Const(Box::new(ty));
    }
    for _ in 0..pointers {
        ty = r2types::CTypeLike::Pointer(Box::new(ty));
    }
    if let Some(len) = array_len {
        ty = r2types::CTypeLike::Array(Box::new(ty), len);
    }
    Some(ty)
}

/// The struct layouts radare2 captured alongside the function, as the external
/// type database the field-naming path reads.
///
/// The snapshot already carries an aggregate layout for every struct its
/// signature mentions, but nothing turned those layouts into the database, so
/// it stayed empty in every real decompile. Field certificates are only kept
/// when the database confirms a field, so every struct access fell back to
/// pointer arithmetic however completely radare2 knew the type: `list_sum`
/// rendered `cur[1]` for `cur->next`.
fn trusted_external_type_db(trusted: &r2ssa::TrustedSsaArtifact) -> r2types::ExternalTypeDb {
    let mut db = r2types::ExternalTypeDb::default();
    let Some(graph) = trusted
        .source()
        .function_interface()
        .and_then(r2ssa::SourceFunctionInterface::type_graph)
    else {
        return db;
    };
    for aggregate in graph.aggregates() {
        let name = aggregate.name();
        if name.is_empty() {
            continue;
        }
        let mut fields = std::collections::BTreeMap::new();
        collect_external_struct_fields(graph, aggregate, 0, "", &mut fields, 0);
        if fields.is_empty() {
            continue;
        }
        db.structs.insert(
            r2types::normalize_external_type_name(name).to_ascii_lowercase(),
            r2types::ExternalStruct {
                name: name.to_string(),
                fields,
            },
        );
    }
    db
}

/// The scalar members of an aggregate, keyed by byte offset, with a nested
/// aggregate flattened into the dotted path that reaches its members.
///
/// Code reads the scalars, never the aggregate that contains them, so naming a
/// four-byte read after the eight-byte `Point` sharing its offset would claim a
/// member the access is not. Flattening gives that read the name it deserves:
/// `r->top_left.x` rather than an unnamed subscript.
fn collect_external_struct_fields(
    graph: &r2ssa::SourceTypeGraph,
    aggregate: &r2ssa::SourceAggregateLayout,
    base_offset: u64,
    prefix: &str,
    fields: &mut std::collections::BTreeMap<u64, r2types::ExternalField>,
    depth: u32,
) {
    // A type graph is acyclic, but a bound keeps a malformed capture from
    // walking forever.
    if depth > 4 {
        return;
    }
    for member in aggregate.members() {
        // A member the capture could not name, or one that does not start on a
        // byte, cannot be spelled as a field access.
        if member.name().is_empty() || member.offset_bits() % 8 != 0 {
            continue;
        }
        let Some(offset) = base_offset.checked_add(member.offset_bits() / 8) else {
            continue;
        };
        let path = if prefix.is_empty() {
            member.name().to_string()
        } else {
            format!("{prefix}.{}", member.name())
        };
        let member_type = usize::try_from(member.type_id())
            .ok()
            .and_then(|id| graph.types().get(id));
        // A union's members share one offset, so no single name is the name
        // of a read at it; the field stays unnamed rather than guessed.
        if let Some(source_type) = member_type
            && matches!(source_type.kind(), r2ssa::SourceTypeKind::Union { .. })
        {
            continue;
        }
        if let Some(source_type) = member_type
            && let r2ssa::SourceTypeKind::Struct { aggregate_id } = source_type.kind()
        {
            if let Some(nested) = graph
                .aggregates()
                .iter()
                .find(|candidate| candidate.id() == aggregate_id)
            {
                collect_external_struct_fields(graph, nested, offset, &path, fields, depth + 1);
            }
            continue;
        }
        fields.insert(
            offset,
            r2types::ExternalField {
                name: path,
                offset,
                ty: source_member_type_spelling(graph, member),
            },
        );
    }
}

/// How a captured aggregate member's type spells in C, so the width check that
/// gates a field certificate has something exact to measure against.
fn source_member_type_spelling(
    graph: &r2ssa::SourceTypeGraph,
    member: &r2ssa::SourceAggregateMember,
) -> Option<String> {
    let source_type = usize::try_from(member.type_id())
        .ok()
        .and_then(|id| graph.types().get(id))?;
    let bits = source_type.size_bits();
    let element = match source_type.kind() {
        r2ssa::SourceTypeKind::SignedInteger => format!("int{bits}_t"),
        r2ssa::SourceTypeKind::UnsignedInteger => format!("uint{bits}_t"),
        r2ssa::SourceTypeKind::Pointer { .. } => "void *".to_string(),
        r2ssa::SourceTypeKind::Float if bits == 32 => "float".to_string(),
        r2ssa::SourceTypeKind::Float if bits == 64 => "double".to_string(),
        r2ssa::SourceTypeKind::Float => "long double".to_string(),
        // An inline aggregate member has no scalar width to check an access
        // against, and an opaque kind is never a member at all.
        r2ssa::SourceTypeKind::Struct { .. }
        | r2ssa::SourceTypeKind::Union { .. }
        | r2ssa::SourceTypeKind::Array { .. }
        | r2ssa::SourceTypeKind::Void
        | r2ssa::SourceTypeKind::Code => return None,
    };
    // A member wider than one element repeats it. The capture states the repeat
    // count, but the Rust contract for a member does not carry it, so the
    // member's own width against the element width recovers the length. Without
    // the length only the first element could be named, and every later one fell
    // back to an offset placeholder: `st->r[2]` rendered as `st->f_8`.
    let count = source_member_element_count(member, bits)?;
    Some(if count > 1 {
        format!("{element}[{count}]")
    } else {
        element
    })
}

/// How many elements a captured member holds, from its own width against the
/// width of one element. `None` when the two do not divide evenly, because a
/// member that is not a whole number of elements is not an array of them.
fn source_member_element_count(
    member: &r2ssa::SourceAggregateMember,
    element_bits: u64,
) -> Option<u64> {
    if element_bits == 0 {
        return None;
    }
    let total_bits = member.size_bits();
    if total_bits == 0 || total_bits == element_bits {
        return Some(1);
    }
    total_bits
        .is_multiple_of(element_bits)
        .then(|| total_bits / element_bits)
}

/// The prototype the source recovered, spelled as the source spells it.
///
/// The type graph carries structure and the interface carries storage; only
/// this says `size_t` rather than `uint64_t`, or `char *` rather than a pointer
/// to an eight-bit integer.
fn trusted_source_signature(
    trusted: &r2ssa::TrustedSsaArtifact,
    ptr_bits: u32,
) -> Option<(r2types::FunctionSignatureSpec, Option<String>, bool)> {
    let signature = trusted.source().presentation().signature()?;
    // The ellipsis is not a parameter: carried as one, with no type, it left
    // a variadic thunk with a signature no caller could be matched against.
    let params = signature
        .named_parameters()
        .iter()
        .enumerate()
        .map(|(index, parameter)| r2types::FunctionParamSpec {
            name: parameter
                .name()
                .filter(|name| !name.is_empty())
                .map_or_else(|| format!("arg{index}"), str::to_string),
            ty: parameter
                .type_spelling()
                .and_then(|spelling| source_spelled_type(spelling, ptr_bits)),
        })
        .collect();
    let spec = r2types::FunctionSignatureSpec {
        ret_type: signature
            .return_type()
            .and_then(|spelling| source_spelled_type(spelling, ptr_bits)),
        params,
    };
    let callconv = signature
        .calling_convention()
        .filter(|convention| !convention.is_empty())
        .map(str::to_string);
    Some((spec, callconv, signature.noreturn()))
}

/// The prototype of each callee, keyed by the name the call renders with.
///
/// Without these an argument is typed by how wide its register is, so a call
/// to `malloc` takes whatever fits rather than the `size_t` it declares.
fn trusted_callee_signatures(
    trusted: &r2ssa::TrustedSsaArtifact,
    ptr_bits: u32,
) -> std::collections::HashMap<String, r2types::FunctionType> {
    trusted
        .source()
        .presentation()
        .callee_signatures()
        .iter()
        // A prototype with no parameters and no result is what radare2 writes
        // for a callee it knows nothing about. Carrying it would say the callee
        // takes no arguments, which is a claim, and would truncate the ones the
        // lift recovered.
        .filter(|(_, signature)| {
            !signature.parameters().is_empty()
                || signature
                    .return_type()
                    .is_some_and(|spelling| spelling.trim() != "void" && !spelling.is_empty())
        })
        .map(|(name, signature)| {
            (
                name.to_string(),
                r2types::FunctionType {
                    return_type: signature
                        .return_type()
                        .and_then(|spelling| source_spelled_type(spelling, ptr_bits))
                        .unwrap_or(r2types::CTypeLike::Unknown),
                    // The ellipsis is not a parameter and has no type. Copying
                    // it in as one, and then calling the whole prototype
                    // non-variadic, said `fprintf` takes exactly three
                    // arguments -- so every call to it was cut to three,
                    // whatever the machine passed.
                    params: signature
                        .named_parameters()
                        .iter()
                        .map(|parameter| {
                            parameter
                                .type_spelling()
                                .and_then(|spelling| source_spelled_type(spelling, ptr_bits))
                                .unwrap_or(r2types::CTypeLike::Unknown)
                        })
                        .collect(),
                    variadic: signature.is_variadic(),
                },
            )
        })
        .collect()
}

/// The register a body proves it returns in, or None when it proves none.
///
/// Every returning block must name a definition reaching the return register:
/// one that does not leaves the block unresolved, which is what a genuinely
/// void function looks like.
fn body_proven_return(shared: &r2ssa::SsaArtifact) -> Option<r2ssa::CanonicalStorageId> {
    let live_out = shared.live_out();
    if live_out.is_empty() || live_out.unresolved_blocks().next().is_some() {
        return None;
    }
    shared
        .machine_context()
        .abi_model()
        .return_registers()
        .first()
        .map(|slot| slot.storage())
}

/// Everything one callee contributes to a caller's request.
///
/// Each field is derived from that callee's own snapshot and nothing else, so
/// one derivation serves every caller of that function. The callee's prepared
/// body is read to produce this and is then done with: what a caller reads of
/// a callee is its interface, the local effect summary the interprocedural
/// fixpoint iterates over, and the C signature its own typed body proves.
/// Holding the body instead, so that a later caller could redo those
/// derivations from it, is what made a session retain a prepared function per
/// function in the program.
#[derive(Debug, Clone)]
pub struct CalleeFacts {
    address: u64,
    interface: r2ssa::SourceFunctionInterface,
    summary: r2ssa::PreparedCalleeSummary,
    signature: Option<r2types::SourceOwnedCalleeSignature>,
    /// Convention-clobbered registers this callee's body proves it leaves
    /// untouched at every exit; a caller reads them after the call as its own.
    preserved_carriers: BTreeSet<r2ssa::CanonicalStorageId>,
}

impl CalleeFacts {
    /// Derive a callee's contribution from the body that owns it. The body is
    /// read here and not retained.
    pub fn derive(callee: &Arc<r2ssa::TrustedSsaArtifact>, ptr_bits: u32) -> Option<Self> {
        let shared = callee.shared_artifact();
        let address = shared.function().entry;
        let interface = shared.machine_context().function_interface()?.clone();
        // radare2 defaults a function with no recovered prototype to void, and
        // a body that fills the return register on every return path says
        // otherwise; the body is the stronger claim about what it does.
        let interface = match body_proven_return(&shared) {
            Some(storage) => interface.with_body_proven_return(storage).ok()?,
            None => interface,
        };
        let preserved_carriers = shared.facts().boundaries.preserved_call_carriers.clone();
        let summary =
            r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(address), &shared)
                .ok()?;
        let context = trusted_parsed_context(callee, ptr_bits);
        let signature = r2types::build_source_owned_type_analysis(
            r2types::TypeAnalysisRequest::new(Arc::clone(&shared), context).ok()?,
        )
        .ok()
        .and_then(|analysis| analysis.source_owned_callee_signature());
        Some(Self {
            address,
            interface,
            summary,
            signature,
            preserved_carriers,
        })
    }

    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn interface(&self) -> &r2ssa::SourceFunctionInterface {
        &self.interface
    }

    /// How far this callee is proven to touch through each pointer argument.
    pub fn argument_touch_reach(
        &self,
    ) -> std::collections::BTreeMap<usize, r2ssa::SummaryArgumentReach> {
        self.summary.argument_touch_reach()
    }

    /// Registers this callee's body proves it leaves untouched at every exit.
    pub const fn preserved_carriers(&self) -> &BTreeSet<r2ssa::CanonicalStorageId> {
        &self.preserved_carriers
    }
}

fn trusted_parsed_context(
    trusted: &r2ssa::TrustedSsaArtifact,
    ptr_bits: u32,
) -> r2types::ParsedExternalContext {
    let signature = trusted_source_signature(trusted, ptr_bits);
    let external_type_db = trusted_external_type_db(trusted);
    // What this function's own capture states: an object's type is the program's, so no other request can add to it.
    let program_data_objects = r2types::ProgramDataObjectTypeFacts::from_radare2(
        trusted
            .source()
            .image()
            .data_symbols()
            .iter()
            .map(|object| (object.address(), object.type_spelling())),
        ptr_bits,
        &external_type_db,
    );
    r2types::ParsedExternalContext {
        known_function_signatures: trusted_callee_signatures(trusted, ptr_bits),
        stack_slots: trusted_stack_slot_names(trusted, ptr_bits),
        callconv: signature
            .as_ref()
            .and_then(|(_, callconv, _)| callconv.clone()),
        noreturn: signature.as_ref().is_some_and(|(_, _, noreturn)| *noreturn),
        current_signature: signature.as_ref().map(|(spec, _, _)| spec.clone()),
        merged_signature: signature.map(|(spec, _, _)| spec),
        external_type_db,
        program_data_objects,
        assumptions: trusted.artifact().facts().assumptions.clone(),
        ..r2types::ParsedExternalContext::default()
    }
}

fn trusted_stack_slot_names(
    trusted: &r2ssa::TrustedSsaArtifact,
    ptr_bits: u32,
) -> std::collections::BTreeMap<r2types::StackSlotKey, r2types::ExternalStackSlotSpec> {
    let snapshot = trusted.source();
    let Some(interface) = snapshot.function_interface() else {
        return Default::default();
    };
    let mut slots = std::collections::BTreeMap::new();
    for slot_name in snapshot.presentation().stack_slot_names() {
        let Some(slot) = interface
            .stack_slots()
            .iter()
            .find(|slot| slot.base() == slot_name.base() && slot.offset() == slot_name.offset())
        else {
            continue;
        };
        // A home is the parameter it spills and is named through the parameter
        // list, so only a slot that stands for itself is named here.
        let role = match slot.role() {
            r2ssa::SourceStackSlotRole::Local => r2types::ExternalStackSlotRole::Local,
            r2ssa::SourceStackSlotRole::UnclassifiedResource => {
                r2types::ExternalStackSlotRole::Unknown
            }
            r2ssa::SourceStackSlotRole::ParameterHome { .. }
            | r2ssa::SourceStackSlotRole::Parameter { .. } => continue,
        };
        slots.insert(
            r2types::StackSlotKey {
                base: slot_name.base(),
                offset: slot_name.offset(),
            },
            r2types::ExternalStackSlotSpec {
                name: slot_name.name().to_string(),
                ty: slot_name
                    .type_spelling()
                    .and_then(|spelling| source_spelled_type(spelling, ptr_bits)),
                role,
                ..r2types::ExternalStackSlotSpec::default()
            },
        );
    }
    slots
}

impl EngineAnalyzeRequest {
    pub fn full_semantics_from_input(input: EngineAnalyzeRequestInput) -> Self {
        Self::full_semantics(engine_analyze_request_parts_from_input(input))
    }

    pub fn full_semantics_for_function(input: EngineAnalyzeFunctionRequestInput) -> Self {
        Self::full_semantics_from_input(engine_analyze_request_input_from_function(input))
    }

    pub fn full_semantics_for_function_with_register_names<F>(
        mut input: EngineAnalyzeFunctionRequestInput,
        register_name: F,
    ) -> Self
    where
        F: FnMut(&r2il::Varnode) -> Option<String>,
    {
        if input.function.semantic_metadata_enabled {
            for (name, hint) in
                collect_register_type_hints_with_names(&input.function.blocks, register_name)
            {
                merge_type_hint(&mut input.reg_type_hints, name, hint);
            }
        }
        Self::full_semantics_for_function(input)
    }

    pub fn from_input_with_compile_missing_semantics(
        input: EngineAnalyzeRequestInput,
        compile_missing_semantics: bool,
    ) -> Self {
        Self::from_compile_missing_semantics(
            engine_analyze_request_parts_from_input(input),
            compile_missing_semantics,
        )
    }

    pub fn full_semantics(parts: EngineAnalyzeRequestParts) -> Self {
        Self::from_parts(parts, EngineSemanticMode::Full)
    }

    pub fn from_compile_missing_semantics(
        parts: EngineAnalyzeRequestParts,
        compile_missing_semantics: bool,
    ) -> Self {
        let semantic_mode = if compile_missing_semantics {
            EngineSemanticMode::Full
        } else {
            EngineSemanticMode::Optional
        };
        Self::from_parts(parts, semantic_mode)
    }

    fn from_parts(parts: EngineAnalyzeRequestParts, semantic_mode: EngineSemanticMode) -> Self {
        Self {
            function_name: parts.function_name,
            function_addr: parts.function_addr,
            blocks: parts.blocks,
            arch: parts.arch,
            source_snapshot: parts.source_snapshot,
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: parts.ptr_bits,
            semantic_metadata_enabled: parts.semantic_metadata_enabled,
            reg_type_hints: parts.reg_type_hints,
            parsed_context: parts.parsed_context,
            semantic_mode,
            include_interproc_summary_set: parts.include_interproc_summary_set,
            execution: EngineExecutionControl::default(),
        }
    }

    pub fn with_execution_control(mut self, execution: EngineExecutionControl) -> Self {
        self.execution = execution;
        self
    }

    /// Attach one request-local trusted SSA owner.
    ///
    /// The exact retained lift replaces every detached identity, block,
    /// architecture, source snapshot, type hint, external context, and
    /// precomputed-semantic input. Root-only interprocedural solving remains
    /// enabled when requested because it derives solely from this exact owner.
    /// Trusted authority remains request-local.
    pub fn with_trusted_ssa(mut self, trusted: Arc<r2ssa::TrustedSsaArtifact>) -> Self {
        let function_addr = trusted.source().function().address();
        // The capture knows what the program calls this function; taking the
        // synthesized form unconditionally made a refusal report `fcn.401680`
        // for a function the symbol table names `murmur3_32`.
        let captured = trusted.source().presentation().display_name();
        self.function_name = match captured.is_empty() {
            true => r2source::unnamed_function(function_addr),
            false => captured.to_owned(),
        };
        self.function_addr = function_addr;
        self.blocks = Vec::new();
        self.arch = Some(trusted.arch_spec().clone());
        self.ptr_bits = engine_arch_target(self.arch.as_ref()).1;
        self.source_snapshot = None;
        self.semantic_metadata_enabled = true;
        self.reg_type_hints.clear();
        // Where the program's sections lie is the caller's to state; the artifact knows one function.
        let program_extents = std::mem::take(&mut self.parsed_context.program_extents);
        self.parsed_context = trusted_parsed_context(&trusted, self.ptr_bits);
        self.parsed_context.program_extents = program_extents;
        self.semantic_mode = EngineSemanticMode::Full;
        self.trusted_ssa = Some(trusted);
        self
    }

    /// Attach what the functions the root calls contribute to it.
    ///
    /// Without them the solver has no callee to look at and must assume every
    /// direct call does anything to anything it was handed.
    /// Attach the signatures the program declares for callees it carries no
    /// body for, which is what an import is.
    pub fn with_declared_signatures(
        mut self,
        signatures: impl IntoIterator<Item = r2types::SourceOwnedCalleeSignature>,
    ) -> Self {
        self.declared_signatures = signatures.into_iter().collect();
        self
    }

    pub fn with_callee_facts(mut self, callees: impl IntoIterator<Item = CalleeFacts>) -> Self {
        self.callee_facts.clear();
        let mut seen = std::collections::BTreeSet::new();
        for callee in callees {
            if !seen.insert(callee.address()) {
                continue;
            }
            self.callee_facts.push(callee);
        }
        self
    }

    fn with_optional_trusted_ssa(self, trusted: Option<Arc<r2ssa::TrustedSsaArtifact>>) -> Self {
        match trusted {
            Some(trusted) => self.with_trusted_ssa(trusted),
            None => self,
        }
    }

    /// The blocks this request's SSA is built from, when the request is what
    /// owns them. A trusted artifact has already consumed its own.
    pub fn source_blocks(&self) -> &[R2ILBlock] {
        &self.blocks
    }

    /// How many blocks were lifted, asking whoever owns them.
    pub fn lifted_block_count(&self) -> usize {
        match self.trusted_ssa.as_deref() {
            Some(trusted) => trusted.source_block_count(),
            None => self.blocks.len(),
        }
    }

    fn canonicalize_trusted(self) -> Self {
        let trusted = self.trusted_ssa.clone();
        self.with_optional_trusted_ssa(trusted)
    }

    pub fn with_cancellation(mut self, cancellation: EngineCancellationToken) -> Self {
        self.execution.replace_cancellation(cancellation);
        self
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.execution.replace_deadline(deadline);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.execution.replace_deadline(
            Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        );
        self
    }
}

fn engine_analyze_request_input_from_function(
    input: EngineAnalyzeFunctionRequestInput,
) -> EngineAnalyzeRequestInput {
    EngineAnalyzeRequestInput {
        function_name: input.function.function_name,
        function_addr: input.function.function_addr,
        blocks: input.function.blocks,
        arch: input.function.arch,
        source_snapshot: input.function.source_snapshot,
        ptr_bits: input.ptr_bits,
        semantic_metadata_enabled: input.function.semantic_metadata_enabled,
        reg_type_hints: input.reg_type_hints,
        parsed_context: input.parsed_context,
        include_interproc_summary_set: input.include_interproc_summary_set,
    }
}

fn engine_analyze_request_parts_from_input(
    input: EngineAnalyzeRequestInput,
) -> EngineAnalyzeRequestParts {
    let ptr_bits = input
        .ptr_bits
        .unwrap_or_else(|| engine_arch_target(input.arch.as_ref()).1);
    EngineAnalyzeRequestParts {
        function_name: input.function_name,
        function_addr: input.function_addr,
        blocks: input.blocks,
        arch: input.arch,
        source_snapshot: input.source_snapshot,
        ptr_bits,
        semantic_metadata_enabled: input.semantic_metadata_enabled,
        reg_type_hints: input.reg_type_hints,
        parsed_context: input.parsed_context,
        include_interproc_summary_set: input.include_interproc_summary_set,
    }
}

#[derive(Debug)]
pub struct EngineAnalyzeResponse {
    pub artifact: EngineAnalysisArtifact,
    pub metrics: EngineMetrics,
    pub diagnostics: EngineDiagnostics,
}

/// One function's type analysis, sealed against its body and route, that every tier and `afi` read.
#[derive(Debug)]
pub struct SealedFunctionAnalysis {
    function_name: String,
    source_owned_facts: r2types::SourceOwnedFunctionFacts,
    trusted_ssa: Option<Arc<r2ssa::TrustedSsaArtifact>>,
    input_quality: Option<r2types::FunctionInputQualityFacts>,
    render_target: EngineRenderTarget,
    /// What sealing cost, which every rendering of it reports beside its own.
    metrics: EngineMetrics,
}

impl SealedFunctionAnalysis {
    pub const fn facts(&self) -> &r2types::SourceOwnedFunctionFacts {
        &self.source_owned_facts
    }
}

/// One tier asked of one sealed analysis, under one request's control.
#[derive(Clone)]
struct EngineDecompileRequest<'a> {
    tier: RenderTier,
    sealed: &'a SealedFunctionAnalysis,
    execution: EngineExecutionControl,
}

impl EngineDecompileRequest<'_> {
    fn function_facts(&self) -> &FunctionFacts {
        self.sealed.source_owned_facts.report()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EngineFunctionDecompileRequest {
    analysis: EngineAnalyzeRequest,
    input_quality: Option<EngineFunctionInputQuality>,
}

/// What a decompile is asked to produce.
///
/// The analysis is the same either way; this decides only what is rendered
/// from it, which is why it travels with the rendering rather than with the
/// request that computes the facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RenderTier {
    #[default]
    C,
    /// The structured tree the C is generated from.
    Structured,
    /// What the binding plan decided about each value: which variable it
    /// became, which expression it was folded into, or why nothing spells it.
    Values,
}

#[derive(Debug, Clone)]
pub struct EngineFunctionDecompileRequestInput {
    function: EngineFunctionInput,
    ptr_bits: Option<u32>,
    parsed_context: r2types::ParsedExternalContext,
    input_quality: EngineFunctionInputQuality,
    execution: EngineExecutionControl,
    trusted_ssa: Option<Arc<r2ssa::TrustedSsaArtifact>>,
    callee_facts: Vec<CalleeFacts>,
    declared_signatures: Vec<r2types::SourceOwnedCalleeSignature>,
    tier: RenderTier,
}

impl EngineFunctionDecompileRequestInput {
    /// How many blocks were lifted, asking whoever owns them.
    fn lifted_block_count(&self) -> usize {
        match self.trusted_ssa.as_deref() {
            Some(trusted) => trusted.source_block_count(),
            None => self.function.blocks.len(),
        }
    }

    pub fn single_function(
        function: EngineFunctionInput,
        ptr_bits: Option<u32>,
        parsed_context: r2types::ParsedExternalContext,
    ) -> Self {
        let function_block_count = function.blocks.len();
        Self {
            function,
            ptr_bits,
            parsed_context,
            input_quality: EngineFunctionInputQuality::complete(function_block_count),
            execution: EngineExecutionControl::default(),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            tier: RenderTier::C,
        }
    }

    pub fn with_input_quality(mut self, input_quality: EngineFunctionInputQuality) -> Self {
        self.input_quality = input_quality;
        self
    }

    pub fn with_execution_control(mut self, execution: EngineExecutionControl) -> Self {
        self.execution = execution;
        self
    }

    pub fn with_trusted_ssa(mut self, trusted: Arc<r2ssa::TrustedSsaArtifact>) -> Self {
        self.trusted_ssa = Some(trusted);
        self
    }

    /// Attach the bodies of the functions the root calls, captured with it.
    pub fn with_callee_facts(mut self, callees: impl IntoIterator<Item = CalleeFacts>) -> Self {
        self.callee_facts = callees.into_iter().collect();
        self
    }

    /// Attach the signatures the program declares for callees it carries no
    /// body for, which is what an import is.
    /// Render the structured tree instead of the C generated from it.
    pub fn rendering(mut self, tier: RenderTier) -> Self {
        self.tier = tier;
        self
    }

    pub fn with_declared_signatures(
        mut self,
        signatures: impl IntoIterator<Item = r2types::SourceOwnedCalleeSignature>,
    ) -> Self {
        self.declared_signatures = signatures.into_iter().collect();
        self
    }

    pub fn with_cancellation(mut self, cancellation: EngineCancellationToken) -> Self {
        self.execution.replace_cancellation(cancellation);
        self
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.execution.replace_deadline(deadline);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.execution.replace_deadline(
            Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        );
        self
    }
}

impl EngineFunctionDecompileRequest {
    pub(crate) fn full_semantics_for_function(input: EngineFunctionDecompileRequestInput) -> Self {
        let trusted_ssa = input.trusted_ssa;
        let callee_facts = input.callee_facts;
        let declared_signatures = input.declared_signatures;
        Self {
            input_quality: Some(input.input_quality),
            analysis: EngineAnalyzeRequest::full_semantics_for_function(
                EngineAnalyzeFunctionRequestInput {
                    function: input.function,
                    ptr_bits: input.ptr_bits,
                    reg_type_hints: HashMap::new(),
                    parsed_context: input.parsed_context,
                    include_interproc_summary_set: true,
                },
            )
            .with_execution_control(input.execution)
            .with_optional_trusted_ssa(trusted_ssa)
            .with_callee_facts(callee_facts)
            .with_declared_signatures(declared_signatures),
        }
    }
}

pub struct EngineSignatureInferenceRequest<'a> {
    pub analysis: &'a EngineAnalysis,
}

#[derive(Debug, Clone)]
pub struct EngineTypeAnalysisRequest {
    pub analysis: EngineAnalyzeRequest,
    pub caller_prefers_bounded_type_plan: bool,
}

#[derive(Debug, Clone)]
pub struct EngineFunctionAnalysisArtifactRequest {
    pub analysis: EngineAnalyzeRequest,
}

#[derive(Debug, Clone)]
pub struct EngineInterprocSummaryReportRequest {
    pub analysis: EngineAnalyzeRequest,
    pub iterations: usize,
    pub max_iterations: usize,
    pub converged: bool,
    pub scope_report: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct EngineInterprocSummaryReportResponse {
    pub report: EngineInterprocSummaryJson,
    pub metrics: EngineMetrics,
    pub diagnostics: EngineDiagnostics,
}

#[derive(Debug, Clone)]
pub struct EngineFunctionAnalysisArtifactRequestInput {
    pub function: EngineFunctionInput,
    pub ptr_bits: Option<u32>,
    pub parsed_context: r2types::ParsedExternalContext,
}

impl EngineFunctionAnalysisArtifactRequest {
    pub fn full_semantics_for_function(input: EngineFunctionAnalysisArtifactRequestInput) -> Self {
        Self {
            analysis: EngineAnalyzeRequest::full_semantics_for_function(
                EngineAnalyzeFunctionRequestInput {
                    function: input.function,
                    ptr_bits: input.ptr_bits,
                    reg_type_hints: HashMap::new(),
                    parsed_context: input.parsed_context,
                    include_interproc_summary_set: true,
                },
            ),
        }
    }

    pub fn full_semantics_for_function_with_register_names<F>(
        input: EngineFunctionAnalysisArtifactRequestInput,
        register_name: F,
    ) -> Self
    where
        F: FnMut(&r2il::Varnode) -> Option<String>,
    {
        Self {
            analysis: EngineAnalyzeRequest::full_semantics_for_function_with_register_names(
                EngineAnalyzeFunctionRequestInput {
                    function: input.function,
                    ptr_bits: input.ptr_bits,
                    reg_type_hints: HashMap::new(),
                    parsed_context: input.parsed_context,
                    include_interproc_summary_set: true,
                },
                register_name,
            ),
        }
    }
}

impl EngineInterprocSummaryReportRequest {
    pub fn full_semantics_for_function(
        input: EngineFunctionAnalysisArtifactRequestInput,
        iterations: usize,
        max_iterations: usize,
        converged: bool,
        scope_report: Option<serde_json::Value>,
    ) -> Self {
        Self {
            analysis: EngineFunctionAnalysisArtifactRequest::full_semantics_for_function(input)
                .analysis,
            iterations,
            max_iterations,
            converged,
            scope_report,
        }
    }

    pub fn full_semantics_for_function_with_register_names<F>(
        input: EngineFunctionAnalysisArtifactRequestInput,
        register_name: F,
        iterations: usize,
        max_iterations: usize,
        converged: bool,
        scope_report: Option<serde_json::Value>,
    ) -> Self
    where
        F: FnMut(&r2il::Varnode) -> Option<String>,
    {
        Self {
            analysis:
                EngineFunctionAnalysisArtifactRequest::full_semantics_for_function_with_register_names(
                    input,
                    register_name,
                )
                .analysis,
            iterations,
            max_iterations,
            converged,
            scope_report,
        }
    }
}

impl EngineTypeAnalysisRequest {
    pub fn from_interproc_budget(
        analysis: EngineAnalyzeRequest,
        interproc_max_iters: usize,
        interproc_converged: bool,
    ) -> Self {
        Self {
            analysis,
            caller_prefers_bounded_type_plan: type_analysis_interproc_prefers_bounded_plan(
                interproc_max_iters,
                interproc_converged,
            ),
        }
    }
}

pub fn type_analysis_interproc_prefers_bounded_plan(
    interproc_max_iters: usize,
    interproc_converged: bool,
) -> bool {
    interproc_max_iters <= 1 && !interproc_converged
}

#[derive(Debug)]
pub struct EngineTypeAnalysisResponse {
    type_analysis: r2types::TypeAnalysis,
    cfg_summary: CFGRiskSummary,
    route_decision: EngineTypeRouteDecision,
    decompile_route: r2types::DecompileRouteFacts,
    callsite_count: usize,
    current_summary: Option<r2ssa::FunctionSemanticSummary>,
    metrics: EngineMetrics,
    diagnostics: EngineDiagnostics,
}

impl EngineTypeAnalysisResponse {
    pub fn type_analysis(&self) -> &r2types::TypeAnalysis {
        &self.type_analysis
    }

    pub fn function_facts(&self) -> &FunctionFacts {
        self.type_analysis.function_facts()
    }

    pub fn cfg_summary(&self) -> &CFGRiskSummary {
        &self.cfg_summary
    }

    pub fn route_decision(&self) -> &EngineTypeRouteDecision {
        &self.route_decision
    }

    pub fn decompile_route(&self) -> &r2types::DecompileRouteFacts {
        &self.decompile_route
    }

    pub fn callsite_count(&self) -> usize {
        self.callsite_count
    }

    pub fn current_summary(&self) -> Option<&r2ssa::FunctionSemanticSummary> {
        self.current_summary.as_ref()
    }

    pub fn metrics(&self) -> &EngineMetrics {
        &self.metrics
    }

    pub fn diagnostics(&self) -> &EngineDiagnostics {
        &self.diagnostics
    }
}

/// What one tier produced.
///
/// The C tier produces a tree and the text the certified emitter wrote from
/// it, together, so a consumer can walk the function instead of parsing it and
/// the two cannot drift. Every other tier, and every refusal, produces a
/// listing that stands on its own.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineRendering {
    Function(Box<r2dec::RenderedFunction>),
    Listing(String),
}

impl EngineRendering {
    /// The text this tier prints.
    pub fn text(&self) -> &str {
        match self {
            Self::Function(rendered) => rendered.text(),
            Self::Listing(text) => text,
        }
    }

    pub fn into_text(self) -> String {
        match self {
            Self::Function(rendered) => rendered.into_text(),
            Self::Listing(text) => text,
        }
    }

    /// The tree behind the C, for a consumer that walks rather than parses.
    pub fn function(&self) -> Option<&r2dec::CFunction> {
        match self {
            Self::Function(rendered) => Some(rendered.function()),
            Self::Listing(_) => None,
        }
    }
}

impl std::fmt::Display for EngineRendering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

/// The counts of a ledger, or the not-run verdict when there is none.
fn effect_obligations_of(
    ledger: Option<&r2dec::ledger::ObligationLedger>,
) -> EffectObligationAudit {
    ledger.map_or(
        EffectObligationAudit::NOT_RUN,
        EffectObligationAudit::from_ledger,
    )
}

#[derive(Debug, Clone)]
pub struct EngineDecompileResponse {
    pub output: EngineRendering,
    pub binding_audit: BindingShadowAuditOutcome,
    pub obligation_ledger: Option<r2dec::ledger::ObligationLedger>,
    pub placement_audit: PlacementAudit,
    pub render_refusal: Option<DecompileRenderRefusal>,
    pub function_facts: FunctionFacts,
    pub input_quality: Option<r2types::FunctionInputQualityFacts>,
    pub metrics: EngineMetrics,
    pub diagnostics: EngineDiagnostics,
}

impl EngineDecompileResponse {
    /// What the ledger counts to, which is the verdict on this rendering.
    pub fn effect_obligations(&self) -> EffectObligationAudit {
        effect_obligations_of(self.obligation_ledger.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EngineSession;

impl EngineSession {
    pub const fn new() -> Self {
        Self
    }

    pub fn analyze(&self, request: EngineAnalyzeRequest) -> Option<EngineAnalyzeResponse> {
        self.analyze_checked(request).ok()
    }

    pub fn analyze_checked(
        &self,
        mut request: EngineAnalyzeRequest,
    ) -> Result<EngineAnalyzeResponse, EngineExecutionRefusal> {
        // Re-derive the complete request at the consumption boundary so a
        // caller cannot attach authority and then mutate public analysis
        // fields into a detached configuration.
        request = request.canonicalize_trusted();
        let started = Instant::now();
        let mut metrics = EngineMetrics::default();
        poll_engine_execution(&request.execution, EnginePhase::SnapshotContext, &metrics)?;
        let phase_started = Instant::now();
        if request.source_snapshot.is_none() && request.trusted_ssa.is_none() {
            return Err(engine_execution_refusal(
                MISSING_SOURCE_SNAPSHOT_REFUSAL.to_string(),
                EnginePhase::SnapshotContext,
                metrics,
            ));
        }
        metrics.record_phase(
            EnginePhase::SnapshotContext,
            EnginePhaseStatus::Executed,
            phase_started.elapsed(),
        );
        let ssa_control = request.execution.ssa_execution_control();
        self.analyze_with_ssa_control(request, started, metrics, &ssa_control)
    }

    pub fn interproc_summary_report(
        &self,
        request: EngineInterprocSummaryReportRequest,
    ) -> Option<EngineInterprocSummaryReportResponse> {
        let EngineInterprocSummaryReportRequest {
            analysis,
            iterations,
            max_iterations,
            converged,
            scope_report,
        } = request;
        let analysis = analysis.canonicalize_trusted();
        let response = self.analyze(analysis)?;
        let summary = response
            .artifact
            .function_facts()
            .summary_view()
            .root_summary();
        let report = interproc_summary_json(EngineInterprocSummaryJsonInput {
            callsite_count: summary.map(|summary| summary.callsite_count).unwrap_or(0),
            iterations,
            max_iterations,
            converged,
            summary,
            scope_report: scope_report.as_ref(),
        });
        Some(EngineInterprocSummaryReportResponse {
            report,
            metrics: response.metrics,
            diagnostics: response.diagnostics,
        })
    }

    fn analyze_with_ssa_control<C: r2ssa::SsaWorkControl + ?Sized>(
        &self,
        request: EngineAnalyzeRequest,
        started: Instant,
        mut metrics: EngineMetrics,
        ssa_control: &C,
    ) -> Result<EngineAnalyzeResponse, EngineExecutionRefusal> {
        poll_engine_execution(&request.execution, EnginePhase::Ssa, &metrics)?;
        let ssa_started = Instant::now();
        let analysis = if let Some(trusted) = request.trusted_ssa.as_ref() {
            ssa_control
                .poll()
                .map_err(|error| ssa_prepare_execution_refusal(error.into(), metrics.clone()))?;
            Arc::new(EngineAnalysis::from_trusted_ssa(trusted))
        } else {
            let Some(source_snapshot) = request.source_snapshot.as_deref() else {
                return Err(engine_execution_refusal(
                    MISSING_SOURCE_SNAPSHOT_REFUSAL.to_string(),
                    EnginePhase::SnapshotContext,
                    metrics,
                ));
            };
            Arc::new(
                match build_engine_analysis_from_parts_with_control(
                    &request.function_name,
                    request.source_blocks(),
                    request.arch.as_ref(),
                    source_snapshot,
                    ssa_control,
                ) {
                    Ok(analysis) => analysis,
                    Err(error) => {
                        metrics.record_phase(
                            EnginePhase::Ssa,
                            EnginePhaseStatus::Refused,
                            ssa_started.elapsed(),
                        );
                        return Err(ssa_prepare_execution_refusal(error, metrics));
                    }
                },
            )
        };
        metrics.record_phase(
            EnginePhase::Ssa,
            EnginePhaseStatus::Executed,
            ssa_started.elapsed(),
        );
        metrics.record_phase(
            EnginePhase::Obligations,
            EnginePhaseStatus::Folded,
            Duration::default(),
        );
        metrics.ssa_time = ssa_started.elapsed();

        poll_engine_execution(&request.execution, EnginePhase::Symbolic, &metrics)?;
        let artifact_started = Instant::now();
        let artifact = match build_engine_analysis_artifact(&request, analysis.as_ref()) {
            Ok(artifact) => artifact,
            Err(reason) => {
                poll_engine_execution(&request.execution, EnginePhase::Types, &metrics)?;
                return Err(engine_execution_refusal(
                    reason,
                    EnginePhase::Types,
                    metrics,
                ));
            }
        };
        let artifact_elapsed = artifact_started.elapsed();
        metrics.record_phase(
            EnginePhase::Types,
            EnginePhaseStatus::Executed,
            artifact_elapsed,
        );
        metrics.type_time = artifact_elapsed;
        poll_engine_execution(&request.execution, EnginePhase::Certification, &metrics)?;
        metrics.planning_time = started.elapsed();
        Ok(EngineAnalyzeResponse {
            artifact,
            metrics,
            diagnostics: EngineDiagnostics::default(),
        })
    }

    pub fn type_function(
        &self,
        request: EngineTypeAnalysisRequest,
    ) -> Option<EngineTypeAnalysisResponse> {
        self.type_function_checked(request).ok()
    }

    pub fn type_function_checked(
        &self,
        request: EngineTypeAnalysisRequest,
    ) -> Result<EngineTypeAnalysisResponse, EngineExecutionRefusal> {
        let started = Instant::now();
        let analysis_request = request.analysis.canonicalize_trusted();
        let analyze_response = self.analyze_checked(analysis_request.clone())?;
        let artifact = analyze_response.artifact;
        let cfg_summary = artifact.ssa_func().function().cfg_risk_summary();
        let route_decision = type_route_decision(
            artifact.function_facts(),
            &cfg_summary,
            request.caller_prefers_bounded_type_plan,
        );
        if !matches!(route_decision.kind, EngineTypeRouteKind::FullTypeEvidence) {
            return Err(engine_execution_refusal(
                route_decision.reason.unwrap_or_else(|| {
                    "bounded or summary-only type evidence cannot authorize full types".to_string()
                }),
                EnginePhase::Types,
                analyze_response.metrics,
            ));
        }
        let decompile_decision = decompile_route_decision(
            &analysis_request.function_name,
            artifact.function_facts(),
            Some(artifact.ssa_func()),
            &cfg_summary,
        );
        let callsite_count = count_prepared_callsites(artifact.ssa_func().local_ssa_blocks());
        let current_summary = current_interproc_summary(artifact.function_facts());
        let EngineAnalysisArtifact {
            type_analysis,
            trusted_ssa: _,
        } = artifact;

        Ok(EngineTypeAnalysisResponse {
            type_analysis,
            cfg_summary,
            route_decision,
            decompile_route: decompile_decision.route,
            callsite_count,
            current_summary,
            metrics: EngineMetrics {
                planning_time: started.elapsed(),
                ..analyze_response.metrics
            },
            diagnostics: analyze_response.diagnostics,
        })
    }

    /// Type one function once and seal the facts every tier reads; a refusal is the response a rendering returns.
    pub(crate) fn seal_function(
        &self,
        request: EngineFunctionDecompileRequest,
    ) -> Result<SealedFunctionAnalysis, Box<EngineDecompileResponse>> {
        let started = Instant::now();
        let EngineFunctionDecompileRequest {
            analysis: analysis_request,
            input_quality,
        } = request;
        let execution = analysis_request.execution.clone();
        let canonical_name = analysis_request.function_name.clone();
        let display_name = canonical_name;
        if let Err(refusal) = poll_engine_execution(
            &execution,
            EnginePhase::SnapshotContext,
            &EngineMetrics::default(),
        ) {
            return Err(Box::new(refused_decompile_response_with_metrics(
                &display_name,
                &refusal.reason,
                None,
                *refusal.metrics,
                *refusal.diagnostics,
            )));
        }
        let actual_lifted_blocks = analysis_request.lifted_block_count();
        let input_quality_facts = if let Some(quality) = input_quality {
            let reason = quality.refusal_reason_for_actual_lifted_blocks(actual_lifted_blocks);
            let facts = function_input_quality_facts(quality, actual_lifted_blocks, reason.clone());
            if let Some(reason) = reason {
                return Err(Box::new(refused_decompile_response(
                    &display_name,
                    &reason,
                    started.elapsed(),
                    Some(facts),
                )));
            }
            Some(facts)
        } else {
            None
        };
        let (_, requested_render_target) = EngineRenderTarget::for_arch_with_ptr_bits(
            analysis_request.arch.as_ref(),
            analysis_request.ptr_bits,
        );
        let analyze_response = match self.analyze_checked(analysis_request) {
            Ok(response) => response,
            Err(refusal) => {
                return Err(Box::new(refused_decompile_response_with_metrics(
                    &display_name,
                    &refusal.reason,
                    input_quality_facts,
                    *refusal.metrics,
                    *refusal.diagnostics,
                )));
            }
        };

        let mut metrics = analyze_response.metrics;
        let analyze_diagnostics = analyze_response.diagnostics;
        let artifact = analyze_response.artifact;
        let analyzed_function_facts = artifact.function_facts().clone();
        let Some(render_target) = EngineRenderTarget::for_prepared(artifact.ssa_func()) else {
            metrics.refuse_from(EnginePhase::Normalization);
            return Err(Box::new(
                refused_decompile_response_with_metrics_and_audits(
                    &display_name,
                    "source-owned machine context cannot define an exact render target",
                    input_quality_facts,
                    metrics,
                    analyze_diagnostics,
                    Some(analyzed_function_facts),
                    BindingShadowAuditOutcome::NotRun,
                    None,
                    PlacementAudit::NotRun,
                    None,
                ),
            ));
        };
        if render_target != requested_render_target {
            metrics.refuse_from(EnginePhase::Normalization);
            return Err(Box::new(
                refused_decompile_response_with_metrics_and_audits(
                    &display_name,
                    "requested render target does not match the source-owned machine context",
                    input_quality_facts,
                    metrics,
                    analyze_diagnostics,
                    Some(analyzed_function_facts),
                    BindingShadowAuditOutcome::NotRun,
                    None,
                    PlacementAudit::NotRun,
                    None,
                ),
            ));
        }

        if let Err(refusal) =
            poll_engine_execution(&execution, EnginePhase::Normalization, &metrics)
        {
            return Err(Box::new(
                refused_decompile_response_with_metrics_and_audits(
                    &display_name,
                    &refusal.reason,
                    input_quality_facts,
                    *refusal.metrics,
                    *refusal.diagnostics,
                    Some(analyzed_function_facts),
                    BindingShadowAuditOutcome::NotRun,
                    None,
                    PlacementAudit::NotRun,
                    None,
                ),
            ));
        }
        let normalization_started = Instant::now();
        let cfg_summary = artifact.ssa_func().function().cfg_risk_summary();
        let route = decompile_route_decision(
            &display_name,
            artifact.function_facts(),
            Some(artifact.ssa_func()),
            &cfg_summary,
        )
        .route;
        let finalization = r2types::DecompileFinalization {
            kind: route.kind,
            reason: route
                .reason
                .clone()
                .or_else(|| route.fallback_comment.clone())
                .unwrap_or_else(|| "engine decompile route decision".to_string()),
            fallback_comment: route.fallback_comment,
        };
        let EngineAnalysisArtifact {
            type_analysis,
            trusted_ssa,
        } = artifact;
        let source_owned_facts = match type_analysis.finalize_for_decompile(finalization) {
            Ok(facts) => facts,
            Err(_) => {
                metrics.refuse_from(EnginePhase::Normalization);
                return Err(Box::new(
                    refused_decompile_response_with_metrics_and_audits(
                        &display_name,
                        "requested decompile route is incompatible with source-owned facts",
                        input_quality_facts,
                        metrics,
                        analyze_diagnostics,
                        Some(analyzed_function_facts),
                        BindingShadowAuditOutcome::NotRun,
                        None,
                        PlacementAudit::NotRun,
                        None,
                    ),
                ));
            }
        };
        metrics.record_phase(
            EnginePhase::Normalization,
            EnginePhaseStatus::Executed,
            normalization_started.elapsed(),
        );
        Ok(SealedFunctionAnalysis {
            function_name: display_name,
            source_owned_facts,
            trusted_ssa,
            input_quality: input_quality_facts,
            render_target,
            metrics,
        })
    }

    pub fn decompile_function_from_input(
        &self,
        input: EngineFunctionDecompileRequestInput,
    ) -> EngineDecompileResponse {
        let tier = input.tier;
        let execution = input.execution.clone();
        match self.seal_function_from_input(input) {
            Ok(sealed) => self.render_sealed(&sealed, tier, &execution),
            Err(refused) => *refused,
        }
    }

    /// Type one function from checked input, once, for every tier and `afi` to read.
    pub fn seal_function_from_input(
        &self,
        input: EngineFunctionDecompileRequestInput,
    ) -> Result<SealedFunctionAnalysis, Box<EngineDecompileResponse>> {
        let actual_lifted_blocks = input.lifted_block_count();
        if let Some(reason) = input
            .input_quality
            .refusal_reason_for_actual_lifted_blocks(actual_lifted_blocks)
        {
            let input_quality = function_input_quality_facts(
                input.input_quality,
                actual_lifted_blocks,
                Some(reason.clone()),
            );
            return Err(Box::new(refused_decompile_response(
                &input.function.function_name,
                &reason,
                Duration::default(),
                Some(input_quality),
            )));
        }
        self.seal_function(EngineFunctionDecompileRequest::full_semantics_for_function(
            input,
        ))
    }

    /// Render one tier of an analysis already sealed, under this request's control.
    pub fn render_sealed(
        &self,
        sealed: &SealedFunctionAnalysis,
        tier: RenderTier,
        execution: &EngineExecutionControl,
    ) -> EngineDecompileResponse {
        self.decompile(EngineDecompileRequest {
            tier,
            sealed,
            execution: execution.clone(),
        })
    }

    fn decompile(&self, request: EngineDecompileRequest<'_>) -> EngineDecompileResponse {
        let render_control = request.execution.ssa_execution_control();
        self.decompile_with_r2dec_control(request, &render_control)
    }

    fn decompile_with_r2dec_control<C: r2ssa::SsaWorkControl>(
        &self,
        request: EngineDecompileRequest<'_>,
        render_control: &C,
    ) -> EngineDecompileResponse {
        let started = Instant::now();
        let sealed = request.sealed;
        let input_quality = sealed.input_quality.clone();
        let response_function_facts = request.function_facts().clone();
        if sealed.trusted_ssa.as_deref().is_some_and(|trusted| {
            !trusted.shares_artifact(&sealed.source_owned_facts.shared_source())
        }) {
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                "trusted SSA does not match the source-owned function facts",
                input_quality,
                sealed.metrics.clone(),
                EngineDiagnostics::default(),
                Some(response_function_facts),
                BindingShadowAuditOutcome::NotRun,
                None,
                PlacementAudit::NotRun,
                None,
            );
        }
        let mut diagnostics = decompile_diagnostics_from_function_facts(request.function_facts());
        let planning_time = started.elapsed();

        if let Err(refusal) = poll_engine_execution(
            &request.execution,
            EnginePhase::Certification,
            &sealed.metrics,
        ) {
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                &refusal.reason,
                input_quality,
                *refusal.metrics,
                *refusal.diagnostics,
                Some(response_function_facts),
                BindingShadowAuditOutcome::NotRun,
                None,
                PlacementAudit::NotRun,
                None,
            );
        }

        let render_started = Instant::now();
        let rendered = match render_engine_decompile_request(&request, render_control) {
            Ok(rendered) => rendered,
            Err(stop) => {
                let render_time = render_started.elapsed();
                let metrics = engine_metrics_for_render_stop(
                    sealed.metrics.clone(),
                    &stop,
                    planning_time,
                    render_time,
                );
                let binding_audit = *stop.binding_audit;
                let obligation_ledger = *stop.obligation_ledger;
                let placement_audit = stop.placement_audit;
                let render_refusal = stop.render_refusal.map(|refusal| *refusal);
                let refusal = engine_render_execution_refusal(stop.reason, stop.phase, metrics);
                return refused_decompile_response_with_metrics_and_audits(
                    &sealed.function_name,
                    &refusal.reason,
                    input_quality,
                    *refusal.metrics,
                    *refusal.diagnostics,
                    Some(response_function_facts),
                    binding_audit,
                    obligation_ledger,
                    placement_audit,
                    render_refusal,
                );
            }
        };
        let render_time = render_started.elapsed();
        let mut metrics = sealed.metrics.clone();
        if rendered.structuring_executed {
            metrics.record_phase(
                EnginePhase::Structuring,
                EnginePhaseStatus::Folded,
                Duration::default(),
            );
        }
        match &rendered.stopped {
            // A rendering and a stop. The phases that finished are folded and the
            // one that stopped is refused, exactly as a discarded rendering would
            // have recorded -- the difference is that the body survives.
            Some(stop) => {
                if stop.certification_completed {
                    metrics.record_folded_if_not_executed(EnginePhase::Certification);
                }
                if stop.normalization_completed {
                    metrics.record_folded_if_not_executed(EnginePhase::Normalization);
                }
                if stop.structuring_completed {
                    metrics.record_folded_if_not_executed(EnginePhase::Structuring);
                }
                metrics.record_phase(stop.phase, EnginePhaseStatus::Refused, render_time);
            }
            None => metrics.record_phase(
                EnginePhase::Rendering,
                EnginePhaseStatus::Executed,
                render_time,
            ),
        }
        diagnostics
            .warnings
            .extend(rendered.semantic_kernel_warnings);
        if let Some(stop) = &rendered.stopped {
            // The reason the run gives for itself is the stop, not the route it
            // was taking when the stop arrived. The refusal is recorded too: the
            // body above is what was reached, and a reader is entitled to know
            // it is not the whole function.
            diagnostics.route_reason = Some(stop.reason.clone());
            diagnostics.refusal = Some(stop.reason.clone());
        }
        metrics.planning_time += planning_time;
        metrics.render_time = render_time;
        let rendering_stopped = rendered.stopped.is_some();
        let (output, binding_audit, obligation_ledger, placement_audit, render_refusal) =
            rendered.product.finalize();
        if !rendering_stopped && let Some(reason) = placement_refusal_reason(placement_audit) {
            metrics.record_phase(
                EnginePhase::Rendering,
                EnginePhaseStatus::Refused,
                render_time,
            );
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                &reason,
                input_quality,
                metrics,
                diagnostics,
                Some(response_function_facts),
                binding_audit,
                obligation_ledger,
                placement_audit,
                render_refusal,
            );
        }
        if !rendering_stopped && let Some(refusal) = render_refusal {
            let reason = render_refusal_reason(refusal, &response_function_facts);
            metrics.record_phase(
                EnginePhase::Rendering,
                EnginePhaseStatus::Refused,
                render_time,
            );
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                &reason,
                input_quality,
                metrics,
                diagnostics,
                Some(response_function_facts),
                binding_audit,
                obligation_ledger,
                placement_audit,
                Some(refusal),
            );
        }
        if !rendering_stopped
            && let Some(reason) =
                effect_obligation_refusal_reason(effect_obligations_of(obligation_ledger.as_ref()))
        {
            metrics.record_phase(
                EnginePhase::Rendering,
                EnginePhaseStatus::Refused,
                render_time,
            );
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                &reason,
                input_quality,
                metrics,
                diagnostics,
                Some(response_function_facts),
                binding_audit,
                obligation_ledger,
                placement_audit,
                None,
            );
        }
        if let Err(refusal) =
            poll_engine_execution(&request.execution, EnginePhase::FfiConversion, &metrics)
        {
            return refused_decompile_response_with_metrics_and_audits(
                &sealed.function_name,
                &refusal.reason,
                input_quality,
                *refusal.metrics,
                *refusal.diagnostics,
                Some(response_function_facts),
                binding_audit,
                obligation_ledger,
                placement_audit,
                None,
            );
        }
        metrics.work_spent = request.execution.work_spent();
        EngineDecompileResponse {
            output,
            binding_audit,
            obligation_ledger,
            placement_audit,
            render_refusal,
            function_facts: response_function_facts,
            input_quality,
            metrics,
            diagnostics,
        }
    }
}

fn effect_obligation_refusal_reason(audit: EffectObligationAudit) -> Option<String> {
    (matches!(audit.disposition, EffectObligationDisposition::Refused)
        || audit.refused != 0
        || audit.unaccounted != 0
        || audit.conflicts != 0)
        .then(|| {
            fn tally(
                count: usize,
                label: &str,
                obligation: Option<r2ssa::SemanticObligationId>,
            ) -> String {
                obligation.map_or_else(
                    || format!("{count} {label}"),
                    |id| format!("{count} {label} ({} at {})", id.kind, id.instruction),
                )
            }
            format!(
                "native effect obligations refused: {}, {}, {}",
                tally(audit.refused, "refused", audit.refused_obligation),
                tally(
                    audit.unaccounted,
                    "unaccounted",
                    audit.unaccounted_obligation
                ),
                tally(audit.conflicts, "conflicts", audit.conflicting_obligation)
            )
        })
}

fn placement_refusal_reason(audit: PlacementAudit) -> Option<String> {
    match audit {
        PlacementAudit::Refused(refusal) => Some(format!(
            "native declaration placement refused: {}",
            refusal.kind()
        )),
        PlacementAudit::Applied | PlacementAudit::NotRun => None,
    }
}

/// The name of an enum variant, taken from its `Debug` form.
///
/// The refusal causes are typed and precise; what reached the reader was the
/// name of the *outer* variant alone, so sixty distinct journal failures all
/// printed as "observation journal" and could not be counted apart. The payload
/// already knows which one it is.
fn refusal_variant_name(debug: &str) -> String {
    debug
        .split(['(', '{', ' '])
        .next()
        .unwrap_or(debug)
        .to_string()
}

/// Why the renderer refused, for a reader.
///
/// A user operation the lift gives no semantics is named from the
/// specification's own table, so the next opaque instruction a compiler emits
/// says which one it is rather than where in the renderer it was noticed.
fn render_refusal_reason(refusal: DecompileRenderRefusal, facts: &FunctionFacts) -> String {
    match refusal {
        DecompileRenderRefusal::UnmodelledUserOperation { userop, block, op } => {
            match facts.user_operation_name(userop) {
                Some(name) => format!(
                    "native rendering refused: unmodelled machine operation {name} at {block:#x}:{op}"
                ),
                None => format!(
                    "native rendering refused: unmodelled machine operation #{userop} at {block:#x}:{op}"
                ),
            }
        }
        DecompileRenderRefusal::MissingMachineProjectionAuthorization(origin) => {
            format!(
                "native rendering refused: missing machine projection authorization: {origin:?}"
            )
        }
        DecompileRenderRefusal::MissingProgramVariableAuthorization => {
            "native rendering refused: missing program-variable authorization".to_string()
        }
        DecompileRenderRefusal::VariadicCallsiteArgumentCount(refusal) => format!(
            "native rendering refused: variadic callsite argument count: {}",
            refusal.kind()
        ),
        DecompileRenderRefusal::ObservationJournal(failure) => {
            format!(
                "native rendering refused: observation journal: {}",
                refusal_variant_name(&format!("{failure:?}"))
            )
        }
        DecompileRenderRefusal::DeclarationPlacement(refusal) => {
            format!(
                "native rendering refused: declaration placement: {}",
                refusal_variant_name(&format!("{refusal:?}"))
            )
        }
        DecompileRenderRefusal::RefusedBindingDisposition { .. } => {
            "native rendering refused: refused binding disposition".to_string()
        }
        DecompileRenderRefusal::NormalizationOriginUnavailable => {
            "native rendering refused: normalization origin unavailable".to_string()
        }
        DecompileRenderRefusal::UnrepresentableControlFlow => {
            "native rendering refused: unrepresentable control flow".to_string()
        }
        DecompileRenderRefusal::IncompleteEffectInventory => {
            "native rendering refused: incomplete effect inventory".to_string()
        }
        DecompileRenderRefusal::UnrepresentableOperation => {
            "native rendering refused: unrepresentable operation".to_string()
        }
    }
}

fn decompile_diagnostics_from_function_facts(function_facts: &FunctionFacts) -> EngineDiagnostics {
    let Some(route) = function_facts.decompile_route() else {
        return EngineDiagnostics {
            plan: None,
            route_reason: Some("missing FunctionFacts decompile route".to_string()),
            warnings: vec![
                "decompile request reached render without engine-stamped route facts".to_string(),
            ],
            refusal: None,
        };
    };
    EngineDiagnostics {
        plan: Some(engine_plan_from_decompile_route_kind(route.kind)),
        route_reason: route.reason.clone(),
        warnings: Vec::new(),
        refusal: route.fallback_comment.clone(),
    }
}

fn engine_plan_from_decompile_route_kind(kind: r2types::DecompileRouteKind) -> EnginePlan {
    match kind {
        r2types::DecompileRouteKind::Standard => EnginePlan::FastLocal,
        r2types::DecompileRouteKind::StructuredWorker => EnginePlan::SemanticStructured,
        r2types::DecompileRouteKind::SummaryIslands
        | r2types::DecompileRouteKind::LinearWorker
        | r2types::DecompileRouteKind::VmSummary => EnginePlan::SemanticSummary,
        r2types::DecompileRouteKind::FallbackComment => EnginePlan::RefuseWithEvidence,
    }
}

struct EngineRenderedDecompile {
    product: EngineRenderedProduct,
    semantic_kernel_warnings: Vec<String>,
    structuring_executed: bool,
    /// Set when rendering stopped and the output above is what it had reached.
    ///
    /// A rendering and a stop, not one or the other: the body is kept so the
    /// reader gets what was produced, and the phase is still recorded as refused
    /// so the accounting says the run did not finish.
    stopped: Option<EngineRenderExecutionStop>,
}

impl EngineRenderedDecompile {
    /// A tier that is not the C: rendered, with no audit to make about it,
    /// because nothing was sealed into an observation journal for it.
    fn structured(output: String) -> Self {
        Self {
            product: EngineRenderedProduct::Ready(Box::new(ReadyEngineRenderedProduct {
                output: EngineRendering::Listing(output),
                binding_audit: BindingShadowAuditOutcome::NotRun,
                obligation_ledger: None,
                placement_audit: PlacementAudit::NotRun,
                render_refusal: None,
            })),
            semantic_kernel_warnings: Vec::new(),
            structuring_executed: true,
            stopped: None,
        }
    }
}

struct ReadyEngineRenderedProduct {
    output: EngineRendering,
    binding_audit: BindingShadowAuditOutcome,
    obligation_ledger: Option<r2dec::ledger::ObligationLedger>,
    placement_audit: PlacementAudit,
    render_refusal: Option<DecompileRenderRefusal>,
}

enum EngineRenderedProduct {
    Ready(Box<ReadyEngineRenderedProduct>),
    Pending(Box<r2dec::PendingDecompileBindingAudit>),
}

impl EngineRenderedProduct {
    fn finalize(
        self,
    ) -> (
        EngineRendering,
        BindingShadowAuditOutcome,
        Option<r2dec::ledger::ObligationLedger>,
        PlacementAudit,
        Option<DecompileRenderRefusal>,
    ) {
        match self {
            Self::Ready(ready) => {
                let ReadyEngineRenderedProduct {
                    output,
                    binding_audit,
                    obligation_ledger,
                    placement_audit,
                    render_refusal,
                } = *ready;
                (
                    output,
                    binding_audit,
                    obligation_ledger,
                    placement_audit,
                    render_refusal,
                )
            }
            Self::Pending(pending) => {
                let audited = (*pending).finalize();
                let binding_audit = audited.binding_shadow();
                let obligation_ledger = audited.obligation_ledger().cloned();
                let placement_audit = audited.placement_audit();
                let render_refusal = audited.render_refusal();
                (
                    EngineRendering::Function(Box::new(audited.into_rendered())),
                    binding_audit,
                    obligation_ledger,
                    placement_audit,
                    render_refusal,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EngineRenderExecutionStop {
    reason: String,
    phase: EnginePhase,
    binding_audit: Box<BindingShadowAuditOutcome>,
    obligation_ledger: Box<Option<r2dec::ledger::ObligationLedger>>,
    placement_audit: PlacementAudit,
    render_refusal: Option<Box<DecompileRenderRefusal>>,
    certification_completed: bool,
    normalization_completed: bool,
    structuring_completed: bool,
}

fn engine_metrics_for_render_stop(
    mut metrics: EngineMetrics,
    stop: &EngineRenderExecutionStop,
    planning_time: Duration,
    render_time: Duration,
) -> EngineMetrics {
    if stop.certification_completed {
        metrics.record_folded_if_not_executed(EnginePhase::Certification);
    }
    if stop.normalization_completed {
        metrics.record_folded_if_not_executed(EnginePhase::Normalization);
    }
    if stop.structuring_completed {
        metrics.record_folded_if_not_executed(EnginePhase::Structuring);
    }
    metrics.record_phase(stop.phase, EnginePhaseStatus::Refused, render_time);
    metrics.planning_time += planning_time;
    metrics.render_time = render_time;
    metrics
}

fn engine_render_stop_reason(
    reason: r2ssa::SsaExecutionStopReason,
    phase: EnginePhase,
) -> EngineRenderExecutionStop {
    let reason = match reason {
        r2ssa::SsaExecutionStopReason::Cancelled => {
            format!("engine request cancelled during {} phase", phase.as_str())
        }
        r2ssa::SsaExecutionStopReason::DeadlineExceeded => format!(
            "engine request deadline exceeded during {} phase",
            phase.as_str()
        ),
    };
    EngineRenderExecutionStop {
        reason,
        phase,
        binding_audit: Box::new(BindingShadowAuditOutcome::NotRun),
        obligation_ledger: Box::new(None),
        placement_audit: PlacementAudit::NotRun,
        render_refusal: None,
        certification_completed: false,
        normalization_completed: false,
        structuring_completed: false,
    }
}

fn poll_engine_render_control<C: r2ssa::SsaWorkControl + ?Sized>(
    control: &C,
    phase: EnginePhase,
) -> Result<(), EngineRenderExecutionStop> {
    poll_engine_render_control_with_completion(control, phase, false, false)
}

fn poll_engine_render_control_with_completion<C: r2ssa::SsaWorkControl + ?Sized>(
    control: &C,
    phase: EnginePhase,
    certification_completed: bool,
    structuring_completed: bool,
) -> Result<(), EngineRenderExecutionStop> {
    control.poll().map_err(|reason| {
        let mut stop = engine_render_stop_reason(reason, phase);
        stop.certification_completed = certification_completed;
        stop.structuring_completed = structuring_completed;
        stop
    })
}

fn engine_render_stop_from_decompiler(
    stop: r2dec::DecompileExecutionStop,
    binding_audit: BindingShadowAuditOutcome,
    obligation_ledger: Option<r2dec::ledger::ObligationLedger>,
    placement_audit: PlacementAudit,
    render_refusal: Option<DecompileRenderRefusal>,
) -> EngineRenderExecutionStop {
    let phase = match stop.phase() {
        r2dec::DecompileWorkPhase::Normalization => EnginePhase::Normalization,
        r2dec::DecompileWorkPhase::Structuring => EnginePhase::Structuring,
        r2dec::DecompileWorkPhase::Rendering => EnginePhase::Rendering,
    };
    let mut mapped = engine_render_stop_reason(stop.reason(), phase);
    mapped.binding_audit = Box::new(binding_audit);
    mapped.obligation_ledger = Box::new(obligation_ledger);
    mapped.placement_audit = placement_audit;
    mapped.render_refusal = render_refusal.map(Box::new);
    match stop.phase() {
        r2dec::DecompileWorkPhase::Normalization => {}
        r2dec::DecompileWorkPhase::Structuring => {
            mapped.normalization_completed = true;
        }
        r2dec::DecompileWorkPhase::Rendering => {
            mapped.normalization_completed = true;
            mapped.structuring_completed = true;
        }
    }
    mapped
}

/// The tiers below the C, which print a listing and seal no journal.
///
/// `None` when the request is for the C itself. Both listings stop the same
/// way, so the stop is written once rather than once per tier.
fn render_listing_tier<C: r2ssa::SsaWorkControl>(
    request: &EngineDecompileRequest<'_>,
    control: &C,
    input: &r2dec::DecompilerInput,
) -> Option<Result<String, EngineRenderExecutionStop>> {
    let decompiler = r2dec::Decompiler::new(request.sealed.render_target.to_decompiler_config());
    let listing = match request.tier {
        RenderTier::Values => decompiler.values_input_with_control(input, control),
        RenderTier::Structured => decompiler.structured_input_with_control(input, control),
        RenderTier::C => return None,
    };
    Some(listing.map_err(|stop| EngineRenderExecutionStop {
        reason: format!("{stop:?}"),
        phase: EnginePhase::Rendering,
        binding_audit: Box::new(BindingShadowAuditOutcome::NotRun),
        obligation_ledger: Box::new(None),
        placement_audit: PlacementAudit::NotRun,
        render_refusal: None,
        certification_completed: false,
        normalization_completed: false,
        structuring_completed: false,
    }))
}

/// The rendering a stopped run reached, kept rather than discarded.
///
/// Discarding it reports a function that ran out of budget as one that produced
/// nothing, and takes the ledger that would have said so with it.
fn rendering_reached_before_the_stop(
    stop: r2dec::DecompileExecutionStop,
    partial: r2dec::PendingDecompileBindingAudit,
) -> EngineRenderedDecompile {
    let audited = partial.finalize();
    let binding_audit = audited.binding_shadow();
    let obligation_ledger = audited.obligation_ledger().cloned();
    let placement_audit = audited.placement_audit();
    let render_refusal = audited.render_refusal();
    let output = EngineRendering::Function(Box::new(audited.into_rendered()));
    EngineRenderedDecompile {
        product: EngineRenderedProduct::Ready(Box::new(ReadyEngineRenderedProduct {
            output,
            binding_audit,
            obligation_ledger: obligation_ledger.clone(),
            placement_audit,
            render_refusal,
        })),
        semantic_kernel_warnings: vec![format!(
            "rendering stopped in {:?}: {}; the body above is what was reached",
            stop.phase(),
            stop.reason()
        )],
        structuring_executed: true,
        stopped: Some(engine_render_stop_from_decompiler(
            stop,
            binding_audit,
            obligation_ledger,
            placement_audit,
            render_refusal,
        )),
    }
}

fn render_engine_decompile_request<C: r2ssa::SsaWorkControl>(
    request: &EngineDecompileRequest<'_>,
    control: &C,
) -> Result<EngineRenderedDecompile, EngineRenderExecutionStop> {
    poll_engine_render_control(control, EnginePhase::Rendering)?;
    // The route's own comment used to be returned here, as the whole
    // rendering, before the decompiler was constructed. It carried no audit,
    // no ledger and no refusal, so a function answered this way was reported
    // as rendered and fully proven while nothing about it had been proven at
    // all. The route is advice about the function; only the native
    // certificates answer for it.
    let input = decompiler_input_for_engine_request(request);
    // Keep a rendering the decompiler reached before it stopped. Discarding it
    // reports a function that ran out of budget as one that produced nothing,
    // and takes the ledger that would have said so with it.
    if let Some(listing) = render_listing_tier(request, control, &input) {
        return listing.map(EngineRenderedDecompile::structured);
    }
    let audited = match r2dec::Decompiler::new(request.sealed.render_target.to_decompiler_config())
        .decompile_input_keeping_partial_with_pending_binding_audit(&input, control)
    {
        Ok(pending) => pending,
        Err((stop, Some(partial))) if !partial.output().trim().is_empty() => {
            return Ok(rendering_reached_before_the_stop(stop, partial));
        }
        Err((stop, partial)) => {
            let (binding_audit, obligation_ledger, placement_audit, render_refusal) = partial
                .map(r2dec::PendingDecompileBindingAudit::finalize)
                .map_or(
                    (
                        BindingShadowAuditOutcome::NotRun,
                        None,
                        PlacementAudit::NotRun,
                        None,
                    ),
                    |audit| {
                        (
                            audit.binding_shadow(),
                            audit.obligation_ledger().cloned(),
                            audit.placement_audit(),
                            audit.render_refusal(),
                        )
                    },
                );
            return Err(engine_render_stop_from_decompiler(
                stop,
                binding_audit,
                obligation_ledger,
                placement_audit,
                render_refusal,
            ));
        }
    };
    if !audited.output().trim().is_empty() {
        return Ok(EngineRenderedDecompile {
            product: EngineRenderedProduct::Pending(Box::new(audited)),
            semantic_kernel_warnings: Vec::new(),
            structuring_executed: true,
            stopped: None,
        });
    }

    let audited = audited.finalize();
    let binding_audit = audited.binding_shadow();
    let obligation_ledger = audited.obligation_ledger().cloned();
    let placement_audit = audited.placement_audit();
    let render_refusal = audited.render_refusal();
    Ok(EngineRenderedDecompile {
        product: EngineRenderedProduct::Ready(Box::new(ReadyEngineRenderedProduct {
            output: EngineRendering::Listing(
                decompile_route_output_from_function_facts(
                    &request.sealed.function_name,
                    request.function_facts(),
                )
                .unwrap_or_default(),
            ),
            binding_audit,
            obligation_ledger,
            placement_audit,
            render_refusal,
        })),
        semantic_kernel_warnings: Vec::new(),
        structuring_executed: false,
        stopped: None,
    })
}

fn decompiler_input_for_engine_request(
    request: &EngineDecompileRequest<'_>,
) -> r2dec::DecompilerInput {
    r2dec::DecompilerInput::new(request.sealed.source_owned_facts.clone())
}

/// The measured cost of one decompile, per phase.
///
/// The engine has recorded a complete phase inventory since it was written and
/// no reachable command printed it, so a decompile could be timed only from
/// outside the process. A refusal is timed too: refusing has to be cheaper than
/// rendering, and a four-second refusal is exactly the case that measurement
/// from outside could not distinguish from a slow render.
///
/// A phase the boundary did not execute is omitted; `folded` says the phase ran
/// inside another phase's span, which is not the same as free.
pub fn format_phase_timing(metrics: &EngineMetrics) -> String {
    let mut measured = String::new();
    let work = metrics.work_spent;
    let mut total_us = 0u64;
    // `EnginePhase::ALL` order, so two runs of one function print one line.
    for timing in &metrics.phase_timings {
        match timing.status {
            EnginePhaseStatus::NotExecuted => continue,
            EnginePhaseStatus::Executed => {
                total_us = total_us.saturating_add(timing.elapsed_us);
                measured.push_str(&format!(
                    " {}={}us",
                    timing.phase.as_str(),
                    timing.elapsed_us
                ));
            }
            EnginePhaseStatus::Folded => {
                measured.push_str(&format!(" {}=folded", timing.phase.as_str()));
            }
            EnginePhaseStatus::Refused => {
                measured.push_str(&format!(" {}=refused", timing.phase.as_str()));
            }
        }
    }
    format!("/* r2dec timing: measured={total_us}us work={work}{measured} */")
}

/// The response for a function whose type analysis or rendering panicked: a
/// refusal that says where, so the defect is printed wherever the answer is.
///
/// `phase` is where the boundary that caught it begins; that phase and every
/// one after it this response did not run are refused, and none before it is
/// claimed, since the analysis this was read from ran those.
pub(crate) fn panicked_decompile_response(
    function_name: &str,
    panicked: &isolation::Panicked,
    phase: EnginePhase,
) -> EngineDecompileResponse {
    let mut metrics = EngineMetrics::default();
    metrics.refuse_from(phase);
    refused_decompile_response_with_metrics(
        function_name,
        &format!("the analysis {panicked}"),
        None,
        metrics,
        EngineDiagnostics::default(),
    )
}

/// A refusal before any phase ran: every phase from the snapshot on is refused.
fn refused_decompile_response(
    function_name: &str,
    reason: &str,
    planning_time: Duration,
    input_quality: Option<r2types::FunctionInputQualityFacts>,
) -> EngineDecompileResponse {
    let mut metrics = EngineMetrics {
        planning_time,
        ..EngineMetrics::default()
    };
    metrics.refuse_from(EnginePhase::SnapshotContext);
    refused_decompile_response_with_metrics(
        function_name,
        reason,
        input_quality,
        metrics,
        EngineDiagnostics::default(),
    )
}

fn refused_decompile_response_with_metrics(
    function_name: &str,
    reason: &str,
    input_quality: Option<r2types::FunctionInputQualityFacts>,
    metrics: EngineMetrics,
    diagnostics: EngineDiagnostics,
) -> EngineDecompileResponse {
    refused_decompile_response_with_metrics_and_audits(
        function_name,
        reason,
        input_quality,
        metrics,
        diagnostics,
        None,
        BindingShadowAuditOutcome::NotRun,
        None,
        PlacementAudit::NotRun,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the sole refusal constructor receives each independent typed ledger explicitly so none can be silently defaulted or reconstructed"
)]
fn refused_decompile_response_with_metrics_and_audits(
    function_name: &str,
    reason: &str,
    input_quality: Option<r2types::FunctionInputQualityFacts>,
    metrics: EngineMetrics,
    mut diagnostics: EngineDiagnostics,
    existing_function_facts: Option<FunctionFacts>,
    binding_audit: BindingShadowAuditOutcome,
    obligation_ledger: Option<r2dec::ledger::ObligationLedger>,
    placement_audit: PlacementAudit,
    render_refusal: Option<DecompileRenderRefusal>,
) -> EngineDecompileResponse {
    let function_facts = seal_refused_decompile_function_facts(
        existing_function_facts.unwrap_or_default(),
        function_name,
        reason,
    );
    let output = EngineRendering::Listing(
        decompile_route_output_from_function_facts(function_name, &function_facts)
            .expect("refused decompile response must stamp a fallback route"),
    );
    let route_diagnostics = decompile_diagnostics_from_function_facts(&function_facts);
    diagnostics.plan = route_diagnostics.plan;
    diagnostics.route_reason = route_diagnostics.route_reason;
    diagnostics.refusal = route_diagnostics.refusal;
    EngineDecompileResponse {
        output,
        binding_audit,
        obligation_ledger,
        placement_audit,
        render_refusal,
        function_facts,
        input_quality,
        metrics,
        diagnostics,
    }
}

fn seal_refused_decompile_function_facts(
    function_facts: FunctionFacts,
    function_name: &str,
    reason: &str,
) -> FunctionFacts {
    let output = artifact_guard_fallback_comment(function_name, reason);
    let route = r2types::DecompileRouteFacts {
        kind: r2types::DecompileRouteKind::FallbackComment,
        reason: Some(reason.to_string()),
        fallback_comment: Some(output),
        use_prepared_semantic_view: false,
    };
    function_facts.with_decompile_route(route)
}

fn decompile_route_output_from_function_facts(
    _function_name: &str,
    function_facts: &FunctionFacts,
) -> Option<String> {
    let route = function_facts.decompile_route()?;
    match route.kind {
        r2types::DecompileRouteKind::FallbackComment => route
            .fallback_comment
            .as_ref()
            .or(route.reason.as_ref())
            .cloned(),
        r2types::DecompileRouteKind::LinearWorker
        | r2types::DecompileRouteKind::SummaryIslands
        | r2types::DecompileRouteKind::StructuredWorker
        | r2types::DecompileRouteKind::VmSummary => function_facts
            .decompile_fallback_comment()
            .map(str::to_string),
        r2types::DecompileRouteKind::Standard => None,
    }
}

#[cfg(test)]
fn build_engine_analysis_from_parts(
    function_name: &str,
    blocks: &[R2ILBlock],
    arch: Option<&r2il::ArchSpec>,
    source_snapshot: &EngineSourceSnapshot,
) -> Option<EngineAnalysis> {
    build_engine_analysis_from_parts_with_control(
        function_name,
        blocks,
        arch,
        source_snapshot,
        &r2ssa::SsaExecutionControl::default(),
    )
    .ok()
}

fn build_engine_analysis_from_parts_with_control<C: r2ssa::SsaWorkControl + ?Sized>(
    function_name: &str,
    blocks: &[R2ILBlock],
    arch: Option<&r2il::ArchSpec>,
    source_snapshot: &EngineSourceSnapshot,
    control: &C,
) -> Result<EngineAnalysis, r2ssa::SsaPrepareError> {
    let ssa_func = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interfaces_and_control(
            blocks,
            arch,
            source_snapshot.function_interface().cloned(),
            *source_snapshot.machine_roles(),
            source_snapshot.call_site_interfaces().to_vec(),
            source_snapshot.call_effect().cloned(),
            control,
        )?
        .with_name(function_name),
    );
    control.poll()?;
    Ok(EngineAnalysis::from_prepared_ssa(ssa_func))
}

struct InterprocSummaryBuildInput<'a> {
    pub analysis: &'a EngineAnalysis,
    /// Bodies of the functions the root calls, captured with it. Without these
    /// every direct call is an unresolved callee, and the solver has to mark
    /// every pointer argument read, written and escaped.
    pub callee_summaries: &'a [r2ssa::PreparedCalleeSummary],
}

fn build_prepared_interproc_summary_set(
    input: InterprocSummaryBuildInput<'_>,
) -> Result<r2ssa::PreparedInterprocSummarySet, r2ssa::PreparedInterprocSummaryError> {
    let root = r2ssa::InterprocFunctionId(input.analysis.ssa_func.function().entry);
    let mut seen = std::collections::BTreeSet::new();
    let mut callees = Vec::new();
    for summary in input.callee_summaries {
        if summary.id() == root || !seen.insert(summary.id()) {
            continue;
        }
        callees.push(summary.clone());
    }
    r2ssa::solve_prepared_interproc_summary_set_from_callee_summaries(
        Arc::clone(&input.analysis.ssa_func),
        &callees,
    )
}

/// Each captured callee's C signature, proved once from its own typed body.
///
/// A callee that cannot prove a complete signature contributes nothing; the
/// root keeps the ordinary call-carrier fallback instead of manufacturing the
/// missing source types.
fn build_source_owned_callee_signatures(
    request: &EngineAnalyzeRequest,
) -> Vec<r2types::SourceOwnedCalleeSignature> {
    request
        .callee_facts
        .iter()
        .filter_map(|callee| callee.signature.clone())
        // A callee whose body the program does not carry has no facts to
        // derive, and its declaration is the only statement of what it takes.
        .chain(request.declared_signatures.iter().cloned())
        .collect()
}

pub fn block_guard_fallback_comment(
    function_name: &str,
    blocks: usize,
    max_blocks: usize,
) -> String {
    let function_name = sanitize_fallback_comment_text(function_name);
    format!(
        "/* r2dec budget: skipped decompilation for {} ({} blocks > limit {}). */",
        function_name, blocks, max_blocks
    )
}

pub fn cfg_guard_fallback_comment(
    function_name: &str,
    cfg_summary: &CFGRiskSummary,
) -> Option<String> {
    cfg_guard_reason_from_summary(cfg_summary)
        .map(|reason| artifact_guard_fallback_comment(function_name, &reason))
}

pub fn artifact_guard_fallback_comment(function_name: &str, reason: &str) -> String {
    let function_name = sanitize_fallback_comment_text(function_name);
    let reason = sanitize_fallback_comment_text(reason);
    format!("/* r2sleigh refused {}: {} */", function_name, reason)
}

fn build_engine_analysis_artifact(
    request: &EngineAnalyzeRequest,
    analysis: &EngineAnalysis,
) -> Result<EngineAnalysisArtifact, String> {
    let trusted_ssa = request
        .parsed_context
        .assumptions
        .is_empty()
        .then(|| request.trusted_ssa.clone())
        .flatten();
    let ssa_func = if request.parsed_context.assumptions.is_empty() {
        Arc::clone(&analysis.ssa_func)
    } else {
        Arc::new(
            analysis
                .ssa_func
                .with_assumptions(&request.parsed_context.assumptions),
        )
    };
    let semantic_analysis = EngineAnalysis::from_prepared_ssa(ssa_func);
    let interproc_summary_set = if request.include_interproc_summary_set {
        match build_prepared_interproc_summary_set(InterprocSummaryBuildInput {
            analysis: &semantic_analysis,
            callee_summaries: &request
                .callee_facts
                .iter()
                .map(|callee| callee.summary.clone())
                .collect::<Vec<_>>(),
        }) {
            Ok(summary) => Some(summary),
            Err(
                r2ssa::PreparedInterprocSummaryError::ArchitectureMismatch
                | r2ssa::PreparedInterprocSummaryError::UnknownOrIncoherentMachineContext,
            ) => None,
            Err(error) => {
                return Err(format!(
                    "interprocedural summary construction failed: {error:?}"
                ));
            }
        }
    } else {
        None
    };
    if let Some(reason) = request.execution.refusal_reason(EnginePhase::Types) {
        return Err(format!("type analysis stopped: {reason}"));
    }
    let mut type_request = r2types::TypeAnalysisRequest::new(
        Arc::clone(&semantic_analysis.ssa_func),
        request.parsed_context.clone(),
    )
    .map_err(|error| format!("type analysis request rejected the source: {error:?}"))?;
    type_request = type_request
        .with_source_owned_callee_signatures(build_source_owned_callee_signatures(request))
        .map_err(|error| {
            format!("type analysis request rejected the captured callees: {error:?}")
        })?;
    if let Some(interproc_summary_set) = interproc_summary_set {
        type_request = type_request
            .with_interproc_summary(interproc_summary_set)
            .map_err(|error| {
                format!("type analysis request rejected the interprocedural summary: {error:?}")
            })?;
    }
    let type_analysis = r2types::build_source_owned_type_analysis(type_request)
        .map_err(|error| format!("type analysis failed: {error:?}"))?;
    if let Some(reason) = request.execution.refusal_reason(EnginePhase::Certification) {
        return Err(format!("certification stopped: {reason}"));
    }
    EngineAnalysisArtifact::new(
        type_analysis,
        // Trusted capture authority is deliberately request-local and may
        // only accompany its exact retained SSA allocation.
        trusted_ssa,
    )
    .ok_or_else(|| {
        "trusted SSA authority does not accompany its own type analysis source".to_string()
    })
}

fn sanitize_fallback_comment_text(text: &str) -> String {
    text.replace("*/", "* /").replace(['\r', '\n'], " ")
}

fn current_interproc_summary(
    function_facts: &FunctionFacts,
) -> Option<r2ssa::FunctionSemanticSummary> {
    function_facts
        .interproc_summary_set()
        .and_then(|summary_set| {
            summary_set
                .root
                .and_then(|root| summary_set.summaries.get(&root).cloned())
        })
}

fn count_prepared_callsites(ssa_blocks: &[r2ssa::SSABlock]) -> usize {
    ssa_blocks
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter(|op| matches!(op, r2ssa::SSAOp::Call { .. } | r2ssa::SSAOp::CallInd { .. }))
        .count()
}
