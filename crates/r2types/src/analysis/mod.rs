mod arrays;
mod shared;
mod signature;
mod structs;

pub(crate) use arrays::*;
pub(crate) use shared::*;
pub(crate) use signature::*;
pub(crate) use structs::*;

use std::collections::{BTreeMap, BTreeSet};

use std::sync::Arc;

use r2ssa::{
    FunctionSemanticSummary, InterprocSummarySet, SsaArtifact, SummaryMemoryEffect,
    SummaryMemoryEffectKind, SummaryMemoryRegion, SummaryReturnRelation,
};

use crate::context::{ParsedExternalContext, is_generic_arg_name};
use crate::convert::CTypeLike;
use crate::facts::{
    ArrayIndexBase, ArrayIndexCertificate, CalleeAllocationEffect, CalleeAtomicEffect,
    CalleeAtomicOp, CalleeAtomicOrdering, CalleeFact, CalleeLifetimeEffect, CalleeLifetimeOp,
    CalleeMemoryEffect, CalleeMemoryEffectKind, CalleeMemoryLocation, CalleeMemoryRange,
    CalleeMemoryRegion, CalleeModelPolicyEvidence, CalleeReturnRelation, CalleeSyncEffect,
    CalleeSyncOp, CalleeTransferEffect, CalleeTransferLength, FunctionParamSpec,
    FunctionSignatureSpec, FunctionTypeFactInputs, FunctionTypeFacts, InterprocFactDiagnostics,
    OutParamCertificate, OutParamCertificateEvidence, OutParamCertificateSource,
    ScalarArrayRenderCandidate, SignatureCertificate, SignatureCertificateSource,
};
use crate::function_facts::{
    FunctionFacts, InterprocSummaryView, ProjectedFacts, SourceOwnedFunctionFacts,
};
use crate::model::Signedness;

#[derive(Debug)]
pub struct TypeAnalysis {
    source: Arc<SsaArtifact>,
    function_facts: ProjectedFacts,
    callee_signatures: BTreeMap<u64, crate::SourceOwnedCalleeSignature>,
}

#[derive(Debug, Clone)]
pub struct DecompileFinalization {
    pub kind: crate::DecompileRouteKind,
    pub reason: String,
    pub fallback_comment: Option<String>,
}

impl TypeAnalysis {
    pub fn source(&self) -> &SsaArtifact {
        self.source.as_ref()
    }

    pub fn shared_source(&self) -> Arc<SsaArtifact> {
        Arc::clone(&self.source)
    }

    pub fn function_facts(&self) -> &FunctionFacts {
        self.function_facts.report()
    }

    /// The render-authorized signature, or where the result is one of two carriers and the exact
    /// interface takes nothing, `(void)`: its result is typed at each call by its caller's read.
    fn signature_for_callers(&self) -> Option<std::borrow::Cow<'_, crate::FunctionSignatureSpec>> {
        let type_facts = self.function_facts.report().type_facts();
        if let Some(signature) = type_facts.render_authorized_signature() {
            return Some(std::borrow::Cow::Borrowed(signature));
        }
        let interface = self.source.machine_context().function_interface()?;
        interface.result_carriers()?;
        interface.parameters().is_empty().then(|| {
            std::borrow::Cow::Owned(crate::FunctionSignatureSpec {
                ret_type: None,
                params: Vec::new(),
            })
        })
    }

    /// The header's own unproven carrier, which every caller's extern spells as the header does.
    fn unproven_carrier_bits(&self) -> Option<u32> {
        let fact = self.function_facts.report().return_type()?;
        match fact.declared().filter(|_| fact.is_unproven())? {
            CTypeLike::Int { bits, .. } => Some(*bits),
            _ => None,
        }
    }

    /// Export the signature this exact retained body proves for its callers.
    ///
    /// The opaque result keeps the SSA and physical interface that authorize
    /// the logical C types, so it cannot be reattached to an unrelated call.
    pub fn source_owned_callee_signature(&self) -> Option<crate::SourceOwnedCalleeSignature> {
        let entry = self.source.function().entry;
        let interface = self.source.machine_context().function_interface();
        let carriers = interface.and_then(r2ssa::SourceFunctionInterface::result_carriers);
        let Some(signature) = self.signature_for_callers() else {
            r2il::refusal_evidence!(
                "callee-signature",
                "{entry:#x}: no render-authorized signature; certificate={:?}",
                self.function_facts
                    .report()
                    .type_facts()
                    .signature_certificate
                    .as_ref()
                    .map(|c| &c.sources)
            );
            return None;
        };
        // A result one of two carriers is typed at each call by the carrier its caller reads.
        let Some(return_type) = signature
            .ret_type
            .clone()
            .or(carriers.map(|_| CTypeLike::Unknown))
        else {
            r2il::refusal_evidence!(
                "callee-signature",
                "{entry:#x}: the signature has no return type"
            );
            return None;
        };
        let Some(render) = self.function_facts.report().render() else {
            r2il::refusal_evidence!("callee-signature", "{entry:#x}: no render facts");
            return None;
        };
        let ptr_bits = self
            .source
            .machine_context()
            .memory_model()
            .default_address_bits();
        // An import's prototype is radare2's: its parameters are what the
        // interface declares, and no body reads them for an entity to certify.
        let prototype = interface.is_some_and(r2ssa::SourceFunctionInterface::types_are_declared);
        let params = signature
            .params
            .iter()
            .enumerate()
            .map(|(slot, parameter)| {
                let id = r2ssa::SemanticId::parameter(slot)?;
                let carrier_width = match render.certified_entities.get(&id) {
                    Some(crate::CertifiedEntity::Parameter { carrier_width, .. }) => *carrier_width,
                    // The declared type occupies its own projection of the carrier: an int in a 64-bit register is 32 bits.
                    _ if prototype => match interface?.parameter_logical_value(slot) {
                        Some(logical) => u32::try_from(logical.carrier().size_bits() / 8).ok()?,
                        None => {
                            let spec = interface?.parameters().get(slot)?;
                            spec.register_storage()
                                .map(|storage| storage.size)
                                .or_else(|| spec.location().stack().map(|(_, size)| size))?
                        }
                    },
                    _ => {
                        r2il::refusal_evidence!(
                            "callee-signature",
                            "{entry:#x}: parameter {slot} ({}) has no certified entity",
                            parameter.name
                        );
                        return None;
                    }
                };
                let width_bits = carrier_width.checked_mul(8)?;
                // The header's own type, its sign the slot's row (D265), so an extern spells it alike.
                Some(crate::admit_declaration_type(
                    parameter.ty.clone()?,
                    width_bits,
                    ptr_bits,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let unproven = self.unproven_carrier_bits();
        // A body's slots bound no caller's type: a callee's derived facts read none of its own
        // callees, so a type reached through one would disagree with its extern (D262).
        let bases = vec![r2source::Basis::CarrierWidth; params.len()];
        crate::SourceOwnedCalleeSignature::new(
            &self.source,
            crate::FunctionType {
                return_type,
                params,
                bases,
                // Function interfaces own fixed carriers. Variadicity belongs
                // to the exact callsite prototype and is attached there.
                variadic: false,
            },
        )
        .map(|signature| signature.with_unproven_bits(unproven))
    }

    pub fn type_facts(&self) -> &FunctionTypeFacts {
        self.function_facts.report().type_facts()
    }

    pub fn finalize_for_decompile(
        mut self,
        finalization: DecompileFinalization,
    ) -> Result<SourceOwnedFunctionFacts, FinalizationRefused> {
        if !self.function_facts.stamp_route(
            finalization.kind,
            finalization.reason,
            finalization.fallback_comment,
        ) {
            return Err(FinalizationRefused {
                error: TypeAnalysisError::IncompatibleDecompileRoute,
                facts: Box::new(self.function_facts.into_report()),
            });
        }
        SourceOwnedFunctionFacts::seal_with_callee_signatures(
            self.source,
            self.function_facts,
            self.callee_signatures,
        )
        .map_err(|facts| FinalizationRefused {
            error: TypeAnalysisError::FunctionFactsSourceMismatch,
            facts,
        })
    }
}

/// Why finalization refused, and the facts it was handed, which the refusal carries.
#[derive(Debug)]
pub struct FinalizationRefused {
    pub error: TypeAnalysisError,
    pub facts: Box<crate::FunctionFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeAnalysisError {
    ForeignSemanticArtifact,
    ForeignInterprocSummary,
    InterprocSummarySchema(r2ssa::interproc::InterprocSummarySchemaError),
    MissingMachinePointerWidth,
    IncoherentMachineMemoryModel,
    AssumptionSetMismatch,
    FunctionFactsSourceMismatch,
    IncompatibleDecompileRoute,
    DerivedSignatureMismatch,
    DerivedTypeFactsMismatch,
    SourceEnrichmentFailed,
    DuplicateCalleeAddress,
}

#[derive(Debug, Clone)]
pub struct TypeAnalysisRequest {
    source: Arc<SsaArtifact>,
    parsed_context: ParsedExternalContext,
    interproc_summary: Option<r2ssa::PreparedInterprocSummarySet>,
    callee_signatures: BTreeMap<u64, crate::SourceOwnedCalleeSignature>,
}

impl TypeAnalysisRequest {
    pub fn new(
        source: Arc<SsaArtifact>,
        parsed_context: ParsedExternalContext,
    ) -> Result<Self, TypeAnalysisError> {
        if source.facts().assumptions != parsed_context.assumptions {
            return Err(TypeAnalysisError::AssumptionSetMismatch);
        }
        Ok(Self {
            source,
            parsed_context,
            interproc_summary: None,
            callee_signatures: BTreeMap::new(),
        })
    }

    pub fn with_interproc_summary(
        mut self,
        interproc_summary: r2ssa::PreparedInterprocSummarySet,
    ) -> Result<Self, TypeAnalysisError> {
        if !interproc_summary.matches_root(&self.source) {
            return Err(TypeAnalysisError::ForeignInterprocSummary);
        }
        self.interproc_summary = Some(interproc_summary);
        Ok(self)
    }

    pub fn with_source_owned_callee_signatures(
        mut self,
        signatures: impl IntoIterator<Item = crate::SourceOwnedCalleeSignature>,
    ) -> Result<Self, TypeAnalysisError> {
        for signature in signatures {
            if self
                .callee_signatures
                .insert(signature.address(), signature)
                .is_some()
            {
                return Err(TypeAnalysisError::DuplicateCalleeAddress);
            }
        }
        Ok(self)
    }

    pub fn source(&self) -> &Arc<SsaArtifact> {
        &self.source
    }
}

struct DerivedTypeAnalysis {
    function_facts: FunctionFacts,
    type_facts: FunctionTypeFacts,
}

struct DerivedTypeAnalysisInput {
    ptr_bits: u32,
    inferred_signature: InferredSignature,
    parsed_context: ParsedExternalContext,
    local_structs: LocalStructArtifacts,
    interproc_summary_set: Option<InterprocSummarySet>,
    diagnostics: TypeAnalysisDiagnostics,
}

#[cfg(test)]
type TypeAnalysisInput = DerivedTypeAnalysisInput;

fn summary_return_relation_to_callee(relation: &SummaryReturnRelation) -> CalleeReturnRelation {
    match relation {
        SummaryReturnRelation::Unknown => CalleeReturnRelation::Unknown,
        SummaryReturnRelation::Void => CalleeReturnRelation::Void,
        SummaryReturnRelation::Arg(idx) => CalleeReturnRelation::Arg(*idx),
        SummaryReturnRelation::Const(value) => CalleeReturnRelation::Const(*value),
        SummaryReturnRelation::HeapAlloc => CalleeReturnRelation::HeapAlloc,
        SummaryReturnRelation::Global(address) => CalleeReturnRelation::Global(*address),
    }
}

fn summary_memory_effect_to_callee(effect: &SummaryMemoryEffect) -> CalleeMemoryEffect {
    let kind = match effect.kind {
        SummaryMemoryEffectKind::Read => CalleeMemoryEffectKind::Read,
        SummaryMemoryEffectKind::Write => CalleeMemoryEffectKind::Write,
        SummaryMemoryEffectKind::Escape => CalleeMemoryEffectKind::Escape,
        SummaryMemoryEffectKind::Free => CalleeMemoryEffectKind::Free,
    };
    let location = CalleeMemoryLocation {
        region: match effect.location.region {
            SummaryMemoryRegion::Arg { index } => CalleeMemoryRegion::Arg { index },
            SummaryMemoryRegion::Global { address } => CalleeMemoryRegion::Global { address },
            SummaryMemoryRegion::HeapReturn => CalleeMemoryRegion::HeapReturn,
            SummaryMemoryRegion::Unknown => CalleeMemoryRegion::Unknown,
        },
        range: effect.location.range.map(|range| CalleeMemoryRange {
            offset_lo: range.offset_lo,
            offset_hi: range.offset_hi,
            width: range.width,
        }),
    };
    CalleeMemoryEffect { kind, location }
}

fn summary_location_to_callee(location: r2ssa::SummaryMemoryLocation) -> CalleeMemoryLocation {
    CalleeMemoryLocation {
        region: match location.region {
            r2ssa::SummaryMemoryRegion::Arg { index } => CalleeMemoryRegion::Arg { index },
            r2ssa::SummaryMemoryRegion::Global { address } => {
                CalleeMemoryRegion::Global { address }
            }
            r2ssa::SummaryMemoryRegion::HeapReturn => CalleeMemoryRegion::HeapReturn,
            r2ssa::SummaryMemoryRegion::Unknown => CalleeMemoryRegion::Unknown,
        },
        range: location.range.map(|range| CalleeMemoryRange {
            offset_lo: range.offset_lo,
            offset_hi: range.offset_hi,
            width: range.width,
        }),
    }
}

fn summary_transfer_effect_to_callee(
    effect: &r2ssa::SummaryTransferEffect,
) -> CalleeTransferEffect {
    CalleeTransferEffect {
        dst: summary_location_to_callee(effect.dst),
        src: summary_location_to_callee(effect.src),
        len: match effect.len {
            r2ssa::SummaryTransferLength::Arg(index) => CalleeTransferLength::Arg(index),
            r2ssa::SummaryTransferLength::Const(value) => CalleeTransferLength::Const(value),
            r2ssa::SummaryTransferLength::Unknown => CalleeTransferLength::Unknown,
        },
    }
}

fn summary_allocation_effect_to_callee(
    effect: &r2ssa::SummaryAllocationEffect,
) -> CalleeAllocationEffect {
    CalleeAllocationEffect {
        size_arg: effect.size_arg,
        zeroed: effect.zeroed,
    }
}

fn summary_lifetime_effect_to_callee(
    effect: &r2ssa::SummaryLifetimeEffect,
) -> CalleeLifetimeEffect {
    CalleeLifetimeEffect {
        arg: effect.arg,
        op: match effect.op {
            r2ssa::SummaryLifetimeOp::Free => CalleeLifetimeOp::Free,
            r2ssa::SummaryLifetimeOp::Retain => CalleeLifetimeOp::Retain,
            r2ssa::SummaryLifetimeOp::Release => CalleeLifetimeOp::Release,
        },
    }
}

fn summary_sync_effect_to_callee(effect: &r2ssa::SummarySyncEffect) -> CalleeSyncEffect {
    CalleeSyncEffect {
        arg: effect.arg,
        op: match effect.op {
            r2ssa::SummarySyncOp::Lock => CalleeSyncOp::Lock,
            r2ssa::SummarySyncOp::Unlock => CalleeSyncOp::Unlock,
        },
    }
}

fn summary_atomic_effect_to_callee(effect: &r2ssa::SummaryAtomicEffect) -> CalleeAtomicEffect {
    CalleeAtomicEffect {
        op: match effect.op {
            r2ssa::SummaryAtomicOp::LoadLinked => CalleeAtomicOp::LoadLinked,
            r2ssa::SummaryAtomicOp::StoreConditional => CalleeAtomicOp::StoreConditional,
            r2ssa::SummaryAtomicOp::CompareExchange => CalleeAtomicOp::CompareExchange,
            r2ssa::SummaryAtomicOp::ReadModifyWrite => CalleeAtomicOp::ReadModifyWrite,
            r2ssa::SummaryAtomicOp::Fence => CalleeAtomicOp::Fence,
        },
        location: summary_location_to_callee(effect.location),
        ordering: match effect.ordering {
            r2ssa::SummaryAtomicOrdering::Relaxed => CalleeAtomicOrdering::Relaxed,
            r2ssa::SummaryAtomicOrdering::Acquire => CalleeAtomicOrdering::Acquire,
            r2ssa::SummaryAtomicOrdering::Release => CalleeAtomicOrdering::Release,
            r2ssa::SummaryAtomicOrdering::AcqRel => CalleeAtomicOrdering::AcqRel,
            r2ssa::SummaryAtomicOrdering::SeqCst => CalleeAtomicOrdering::SeqCst,
            r2ssa::SummaryAtomicOrdering::Unknown => CalleeAtomicOrdering::Unknown,
        },
    }
}

fn summary_linkage_to_callee_linkage(
    linkage: r2ssa::FunctionSemanticLinkage,
) -> crate::CalleeLinkage {
    match linkage {
        r2ssa::FunctionSemanticLinkage::Unknown => crate::CalleeLinkage::Unknown,
        r2ssa::FunctionSemanticLinkage::Internal => crate::CalleeLinkage::Internal,
        r2ssa::FunctionSemanticLinkage::Imported => crate::CalleeLinkage::Imported,
    }
}

fn summary_to_callee_fact(summary: &FunctionSemanticSummary) -> CalleeFact {
    CalleeFact {
        function_id: summary.id.0,
        name: summary.name.clone(),
        linkage: summary_linkage_to_callee_linkage(summary.linkage),
        signature: None,
        model_policy_evidence: BTreeSet::from([CalleeModelPolicyEvidence::InterprocSummary]),
        direct_callees: summary.direct_callees.iter().copied().collect(),
        callsite_count: summary.callsite_count,
        has_unknown_calls: summary.has_unknown_calls,
        memory_effects: summary
            .memory_effects
            .iter()
            .map(summary_memory_effect_to_callee)
            .collect(),
        transfer_effects: summary
            .transfer_effects
            .iter()
            .map(summary_transfer_effect_to_callee)
            .collect(),
        allocation_effects: summary
            .allocation_effects
            .iter()
            .map(summary_allocation_effect_to_callee)
            .collect(),
        lifetime_effects: summary
            .lifetime_effects
            .iter()
            .map(summary_lifetime_effect_to_callee)
            .collect(),
        sync_effects: summary
            .sync_effects
            .iter()
            .map(summary_sync_effect_to_callee)
            .collect(),
        atomic_effects: summary
            .atomic_effects
            .iter()
            .map(summary_atomic_effect_to_callee)
            .collect(),
        return_relation: summary_return_relation_to_callee(&summary.return_relation),
        reads_global_memory: summary.reads_global_memory,
        writes_global_memory: summary.writes_global_memory,
        touches_unknown_memory: summary.touches_unknown_memory,
    }
}

fn callee_linkage_rank(linkage: crate::CalleeLinkage) -> u8 {
    match linkage {
        crate::CalleeLinkage::Unknown => 0,
        crate::CalleeLinkage::Internal => 1,
        crate::CalleeLinkage::Imported => 2,
    }
}

fn merge_callee_fact(existing: &mut CalleeFact, incoming: CalleeFact) {
    if existing.name.is_none() {
        existing.name = incoming.name;
    }
    if callee_linkage_rank(incoming.linkage) > callee_linkage_rank(existing.linkage) {
        existing.linkage = incoming.linkage;
    }
    existing
        .model_policy_evidence
        .extend(incoming.model_policy_evidence);
    if existing.direct_callees.is_empty() {
        existing.direct_callees = incoming.direct_callees;
    }
    existing.callsite_count = existing.callsite_count.max(incoming.callsite_count);
    existing.has_unknown_calls |= incoming.has_unknown_calls;
    if existing.memory_effects.is_empty() {
        existing.memory_effects = incoming.memory_effects;
    }
    if existing.transfer_effects.is_empty() {
        existing.transfer_effects = incoming.transfer_effects;
    }
    if existing.allocation_effects.is_empty() {
        existing.allocation_effects = incoming.allocation_effects;
    }
    if existing.lifetime_effects.is_empty() {
        existing.lifetime_effects = incoming.lifetime_effects;
    }
    if existing.sync_effects.is_empty() {
        existing.sync_effects = incoming.sync_effects;
    }
    if existing.atomic_effects.is_empty() {
        existing.atomic_effects = incoming.atomic_effects;
    }
    if matches!(
        existing.return_relation,
        crate::CalleeReturnRelation::Unknown
    ) {
        existing.return_relation = incoming.return_relation;
    }
    existing.reads_global_memory |= incoming.reads_global_memory;
    existing.writes_global_memory |= incoming.writes_global_memory;
    existing.touches_unknown_memory |= incoming.touches_unknown_memory;
}

fn merged_context_and_summary_callee_facts(
    context_facts: &BTreeMap<u64, CalleeFact>,
    summary_set: Option<&r2ssa::InterprocSummarySet>,
) -> BTreeMap<u64, CalleeFact> {
    let mut facts = context_facts.clone();
    if let Some(summary_set) = summary_set {
        for (id, summary) in &summary_set.summaries {
            if Some(*id) == summary_set.root {
                continue;
            }
            let incoming = summary_to_callee_fact(summary);
            match facts.entry(id.0) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    merge_callee_fact(entry.get_mut(), incoming);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(incoming);
                }
            }
        }
    }
    facts
}

fn build_type_analysis_inner(
    mut input: DerivedTypeAnalysisInput,
    callee_facts: BTreeMap<u64, CalleeFact>,
) -> DerivedTypeAnalysis {
    // This inner projection builder is also used by detached report-only
    // tests. Invalid advisory reports lose all interprocedural evidence here;
    // the source-owned entrypoint validates and propagates the exact schema
    // error before calling this function.
    let summary_view =
        InterprocSummaryView::new(input.interproc_summary_set.clone()).unwrap_or_default();

    let semantic_projection = SemanticTypeProjection::from_inputs(&summary_view);
    let authoritative_external_arity = input
        .parsed_context
        .current_signature
        .as_ref()
        .into_iter()
        .chain(input.parsed_context.merged_signature.as_ref())
        .any(signature_param_count_is_authoritative);

    let mut signature_certificate_sources = Vec::new();
    if authoritative_external_arity {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::ExternalContext,
        );
    }
    let inferred_signature_spec = inferred_signature_to_spec(&input.inferred_signature);
    if inferred_signature_spec.is_some() && !authoritative_external_arity {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::LocalInference,
        );
    }

    let merged_signature = merge_local_signature_into_merged_signature(
        input.parsed_context.merged_signature.clone(),
        inferred_signature_spec,
    );

    let mut diagnostics = input.diagnostics;
    diagnostics.solver_warnings = input.parsed_context.diagnostics.clone();
    if summary_view
        .diagnostics()
        .is_some_and(|diagnostics| !diagnostics.converged)
    {
        diagnostics.warnings.push(
            "interprocedural summary did not converge; downgraded summary-driven type hints"
                .to_string(),
        );
    }

    let local_structs = input.local_structs;
    let array_index_certificates = exact_indexed_access_certificates_from_local_artifacts(
        &local_structs,
        merged_signature.as_ref(),
        input.ptr_bits,
    );
    let mut scalar_array_render_candidates = array_index_certificates.render_candidates;
    scalar_array_render_candidates.sort();
    scalar_array_render_candidates.dedup();
    let array_index_certificates = array_index_certificates.array_index;
    let signature_certificate = signature_certificate_from_merged(
        merged_signature.as_ref(),
        &signature_certificate_sources,
    );
    let out_param_certificates = out_param_certificates_from_projection(
        &semantic_projection,
        merged_signature.as_ref(),
        input.ptr_bits,
    );
    apply_signature_context_overrides(
        &mut input.inferred_signature,
        merged_signature.as_ref(),
        input.ptr_bits,
    );
    let type_facts = FunctionTypeFacts::builder(FunctionTypeFactInputs {
        merged_signature,
        // Enrichment states these as it writes each slot.
        parameter_types: crate::ParameterTypes::default(),
        // Enrichment states these from the solve, beside the exact signature.
        inferred_aggregates: BTreeMap::new(),
        parameter_structures: BTreeMap::new(),
        register_params: input.parsed_context.register_params.clone(),
        callee_facts,
        program_data_objects: input.parsed_context.program_data_objects.clone(),
        field_access_certificates: local_structs.source_fields,
        array_index_certificates,
        scalar_array_render_candidates,
        out_param_certificates,
        signature_certificate,
        interproc_diagnostics: input
            .interproc_summary_set
            .as_ref()
            .map(|summary_set| InterprocFactDiagnostics {
                iterations: summary_set.diagnostics.iterations,
                max_iterations: summary_set.diagnostics.max_iterations,
                converged: summary_set.diagnostics.converged,
                scope_size: summary_set.diagnostics.scope_size,
                scc_count: summary_set.diagnostics.scc_count,
                max_scc_size: summary_set.diagnostics.max_scc_size,
            })
            .unwrap_or_default(),
        diagnostics: diagnostics.solver_warnings.clone(),
    })
    .build();
    DerivedTypeAnalysis {
        function_facts: FunctionFacts::new(type_facts.clone())
            .with_assumptions(input.parsed_context.assumptions.clone())
            .with_summary_view(summary_view)
            .with_diagnostics(type_facts.diagnostics.clone()),
        type_facts,
    }
}

#[cfg(test)]
fn build_type_analysis(input: DerivedTypeAnalysisInput) -> DerivedTypeAnalysis {
    let callee_facts = merged_context_and_summary_callee_facts(
        &input.parsed_context.callee_facts,
        input.interproc_summary_set.as_ref(),
    );
    build_type_analysis_inner(input, callee_facts)
}

#[cfg(test)]
fn signed_int_type(bits: u32) -> CTypeLike {
    CTypeLike::Int {
        bits,
        signedness: Signedness::Signed,
    }
}

pub fn build_source_owned_type_analysis(
    request: TypeAnalysisRequest,
) -> Result<TypeAnalysis, TypeAnalysisError> {
    let TypeAnalysisRequest {
        source,
        parsed_context,
        interproc_summary,
        callee_signatures,
    } = request;
    if source.facts().assumptions != parsed_context.assumptions {
        return Err(TypeAnalysisError::AssumptionSetMismatch);
    }
    let memory_model = source.machine_context().memory_model();
    if !memory_model.is_available() || !memory_model.is_coherent() {
        return Err(TypeAnalysisError::IncoherentMachineMemoryModel);
    }
    let ptr_bits = memory_model.default_address_bits();
    if ptr_bits == 0 {
        return Err(TypeAnalysisError::MissingMachinePointerWidth);
    }
    let interproc_report = interproc_summary
        .as_ref()
        .map(|summary| summary.report().clone());
    require_current_interproc_report_for_source_owned(interproc_report.as_ref())?;
    let callee_facts = merged_context_and_summary_callee_facts(
        &parsed_context.callee_facts,
        interproc_report.as_ref(),
    );
    // One solve per function: the calls are projected first, so it sees every callee prototype.
    let calls = crate::function_facts::CallFacts::project(
        source.as_ref(),
        source.display_names(),
        &callee_facts,
        &callee_signatures,
    );
    let solved = calls.solve(source.as_ref());
    let inferred_signature = crate::infer_signature_from_prepared_ssa(source.as_ref(), &solved);
    let diagnostics = TypeAnalysisDiagnostics::default();
    let local_structs = infer_local_struct_artifacts_from_prepared_ssa(source.as_ref());
    let derived_input = DerivedTypeAnalysisInput {
        ptr_bits,
        inferred_signature,
        parsed_context,
        local_structs,
        interproc_summary_set: interproc_report,
        diagnostics,
    };
    let derived = build_type_analysis_inner(derived_input, callee_facts);
    let mut function_facts = derived.function_facts;
    if let Some(interproc_summary) = interproc_summary {
        function_facts = function_facts.with_prepared_interproc_summary(interproc_summary);
    }
    if derived.type_facts != *function_facts.type_facts() {
        return Err(TypeAnalysisError::DerivedTypeFactsMismatch);
    }
    if crate::prepare::prepared_arch_display_name(source.as_ref()).is_none() {
        return Err(TypeAnalysisError::SourceEnrichmentFailed);
    }
    let function_facts = SourceOwnedFunctionFacts::enrich_report_from_source(
        source.as_ref(),
        function_facts,
        calls,
        &solved,
    );
    let analysis = TypeAnalysis {
        source,
        function_facts,
        callee_signatures,
    };
    Ok(analysis)
}

fn require_current_interproc_report_for_source_owned(
    report: Option<&InterprocSummarySet>,
) -> Result<(), TypeAnalysisError> {
    report
        .map(InterprocSummarySet::validate_current_schema)
        .transpose()
        .map(|_| ())
        .map_err(TypeAnalysisError::InterprocSummarySchema)
}

/// Project exact, revision-bound source aggregate accesses into the canonical
/// type certificate keyed by ABI parameter slot and byte offset.
///
/// The r2ssa projection has already joined the immutable source type graph,
/// parameter provenance, memory occurrence, and access width. r2types only
/// publishes projections whose logical member type retains that exact width;
/// it does not recover a field from address syntax or a rendered name.
pub(crate) fn field_access_certificates_from_source_aggregate_accesses(
    source: &r2ssa::SsaArtifact,
) -> Vec<crate::FieldAccessCertificate> {
    let Some(interface) = source.machine_context().function_interface() else {
        return Vec::new();
    };
    let Some(graph) = interface.type_graph() else {
        return Vec::new();
    };
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    let mut by_location = BTreeMap::<(usize, u64), Option<crate::FieldAccessCertificate>>::new();
    let projections = source.aggregate_accesses();
    for (slot, projection) in projections.parameter_projections(interface.revision_identity()) {
        // An indexed array member names no field at one offset (D360).
        let Ok(slot) = usize::try_from(slot) else {
            continue;
        };
        if projection.member_indexed() {
            continue;
        }
        let Some(field_type) = crate::convert::source_type_like(graph, projection.member_type_id)
        else {
            continue;
        };
        if crate::function_facts::type_like_size_bytes(&field_type, ptr_bits)
            != Some(u64::from(projection.byte_width))
        {
            continue;
        }
        let certificate = crate::FieldAccessCertificate {
            slot,
            field_offset: projection.byte_offset,
            field_name: projection.member_name.to_string(),
            field_type: Some(field_type),
        };
        let key = (slot, projection.byte_offset);
        match by_location.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(certificate));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(&certificate) {
                    entry.insert(None);
                }
            }
        }
    }
    by_location.into_values().flatten().collect::<Vec<_>>()
}

/// An indexed access certifies an array where the element stride (scalar or the graph's aggregate
/// size) is the coefficient and it reads a whole element or a projected member. O(accesses x fields).
fn exact_indexed_access_certificates_from_local_artifacts(
    local_structs: &LocalStructArtifacts,
    merged_signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
) -> ScalarArrayAccessCertificates {
    let mut certificates = ScalarArrayAccessCertificates::default();
    for candidate in &local_structs.indexed_accesses {
        if candidate.access_width == 0 || candidate.element_stride == 0 {
            continue;
        }
        let Some(param_ty) = merged_signature
            .and_then(|signature| signature.params.get(candidate.slot))
            .and_then(|param| param.ty.as_ref())
        else {
            continue;
        };
        let scalar = match param_ty {
            CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => {
                scalar_element_stride(inner, ptr_bits)
            }
            _ => continue,
        };
        let aggregate = || {
            local_structs
                .pointee_strides
                .get(candidate.slot)
                .copied()
                .flatten()
        };
        if scalar.or_else(aggregate) != Some(candidate.element_stride) {
            continue;
        }
        let full_element_access = candidate.field_offset == 0
            && u64::from(candidate.access_width) == candidate.element_stride;
        let named = local_structs.source_fields.iter().any(|field| {
            field.slot == candidate.slot && field.field_offset == candidate.field_offset
        });
        if !full_element_access && !named {
            continue;
        }
        certificates.array_index.push(ArrayIndexCertificate {
            slot: candidate.slot,
            base: Some(ArrayIndexBase::Param {
                index: candidate.slot,
            }),
            field_offset: candidate.field_offset,
            element_stride: candidate.element_stride,
        });
        certificates.render_candidates.push(*candidate);
    }
    certificates.array_index.sort();
    certificates.array_index.dedup();
    certificates.render_candidates.sort();
    certificates.render_candidates.dedup();
    certificates
}

fn push_signature_certificate_source(
    sources: &mut Vec<SignatureCertificateSource>,
    source: SignatureCertificateSource,
) {
    if !sources.contains(&source) {
        sources.push(source);
    }
}

fn signature_certificate_from_merged(
    merged_signature: Option<&FunctionSignatureSpec>,
    sources: &[SignatureCertificateSource],
) -> Option<SignatureCertificate> {
    let signature = merged_signature?;
    SignatureCertificate::from_signature(signature, sources.iter().copied())
}

fn out_param_certificates_from_projection(
    projection: &SemanticTypeProjection,
    merged_signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
) -> Vec<OutParamCertificate> {
    let mut certificates = projection
        .out_param_evidence
        .iter()
        .filter(|(_, evidence)| !evidence.is_empty())
        .map(|(param_index, evidence)| {
            let param = merged_signature.and_then(|signature| signature.params.get(*param_index));
            let param_name = param
                .map(|param| param.name.clone())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| r2source::positional_parameter_name(*param_index));
            let pointee_type = param
                .and_then(|param| param.ty.as_ref())
                .and_then(|ty| match ty {
                    CTypeLike::Pointer(inner) => Some(render_signature_type(inner, ptr_bits)),
                    _ => None,
                });
            OutParamCertificate {
                param_index: *param_index,
                param_name,
                pointee_type,
                evidence: evidence.iter().copied().collect(),
                sources: projection
                    .out_param_sources
                    .get(param_index)
                    .map(|sources| sources.iter().cloned().collect())
                    .unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();
    certificates.sort();
    certificates.dedup();
    certificates
}

#[cfg(test)]
mod tests;
