mod arrays;
mod assumptions;
mod bindings;
mod globals;
mod shared;
mod signature;
mod stack;
mod structs;

pub(crate) use arrays::*;
pub(crate) use assumptions::*;
pub(crate) use bindings::*;
pub(crate) use globals::*;
pub(crate) use shared::*;
pub(crate) use signature::*;
pub(crate) use stack::*;
pub(crate) use structs::*;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use r2ssa::{
    FunctionSemanticSummary, InterprocSummarySet, MemoryVersion, ObjectKind, SSABlock, SSAOp,
    SSAVar, SsaArtifact, SummaryArgEffect, SummaryMemoryEffect, SummaryMemoryEffectKind,
    SummaryMemoryRegion, SummaryReturnRelation,
};

use crate::context::{
    ExternalRegisterParamSpec, ExternalStackBase, ExternalStackSlotRole, ExternalStackVarSpec,
    ParsedExternalContext, StackSlotKey, apply_main_signature_override,
    canonical_main_signature_spec, is_generic_arg_name, sanitize_c_identifier,
};
use crate::convert::{CTypeLike, parse_c_type_like, render_c_type_like};
use crate::external::{
    ExternalField, ExternalStruct, ExternalTypeDb, ExternalUnion, normalize_external_type_name,
};
#[cfg(test)]
use crate::facts::FunctionSignatureProjection;
use crate::facts::{
    ArrayIndexBase, ArrayIndexCertificate, CalleeAllocationEffect, CalleeArgEffect,
    CalleeAtomicEffect, CalleeAtomicOp, CalleeAtomicOrdering, CalleeFact, CalleeLifetimeEffect,
    CalleeLifetimeOp, CalleeMemoryEffect, CalleeMemoryEffectKind, CalleeMemoryLocation,
    CalleeMemoryRange, CalleeMemoryRegion, CalleeModelPolicyEvidence, CalleeReturnRelation,
    CalleeSyncEffect, CalleeSyncOp, CalleeTransferEffect, CalleeTransferLength, FunctionParamSpec,
    FunctionSignatureSpec, FunctionTypeFactInputs, FunctionTypeFacts, InterprocFactDiagnostics,
    LocalFieldAccessFact, OutParamCertificate, OutParamCertificateEvidence,
    OutParamCertificateSource, ScalarArrayRenderCandidate, SignatureCertificate,
    SignatureCertificateSource, VisibleBinding, VisibleBindingKind,
};
use crate::function_facts::{FunctionFacts, InterprocSummaryView, SourceOwnedFunctionFacts};
use crate::inferred_signature_from_signature_spec;
use crate::model::Signedness;
use crate::prepare::recover_vars_arch_profile;
use crate::prepare::ssa_var_block_key;
use crate::signedness::{ScalarSignednessEvidence, infer_scalar_signedness};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypePlan {
    /// The target's pointer width.
    ///
    /// The plan carries types now, and a type only becomes a C spelling
    /// against a target: `long` and `size_t` are the width of a pointer, and
    /// which width that is belongs to the function being written back, not to
    /// whichever renderer happens to run.
    pub ptr_bits: u32,
    pub signature: InferredSignature,
    pub var_type_candidates: Vec<VarTypeCandidate>,
    pub var_rename_candidates: Vec<VarRenameCandidate>,
    pub struct_decls: Vec<StructDeclCandidate>,
    pub global_type_links: Vec<GlobalTypeLinkCandidate>,
    pub diagnostics: TypeAnalysisDiagnostics,
}

#[derive(Debug)]
pub struct TypeAnalysis {
    source: Arc<SsaArtifact>,
    function_facts: FunctionFacts,
    plan: TypePlan,
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

    pub fn matches_source(&self, source: &Arc<SsaArtifact>) -> bool {
        Arc::ptr_eq(&self.source, source)
    }

    pub fn function_facts(&self) -> &FunctionFacts {
        &self.function_facts
    }

    /// Export the signature this exact retained body proves for its callers.
    ///
    /// The opaque result keeps the SSA and physical interface that authorize
    /// the logical C types, so it cannot be reattached to an unrelated call.
    pub fn source_owned_callee_signature(&self) -> Option<crate::SourceOwnedCalleeSignature> {
        let entry = self.source.function().entry;
        let Some(signature) = self
            .function_facts
            .type_facts()
            .render_authorized_signature()
        else {
            r2il::refusal_evidence!(
                "callee-signature",
                "{entry:#x}: no render-authorized signature; certificate={:?}",
                self.function_facts
                    .type_facts()
                    .signature_certificate
                    .as_ref()
                    .map(|c| c.confidence)
            );
            return None;
        };
        let Some(return_type) = signature.ret_type.clone() else {
            r2il::refusal_evidence!(
                "callee-signature",
                "{entry:#x}: the signature has no return type"
            );
            return None;
        };
        let Some(render) = self.function_facts.render() else {
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
        let interface = self.source.machine_context().function_interface();
        let prototype =
            interface.is_some_and(r2ssa::SourceFunctionInterface::prototype_from_source_types);
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
                Some(crate::admit_declaration_type(
                    parameter.ty.clone()?,
                    width_bits,
                    ptr_bits,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        crate::SourceOwnedCalleeSignature::new(
            &self.source,
            crate::FunctionType {
                return_type,
                params,
                // Function interfaces own fixed carriers. Variadicity belongs
                // to the exact callsite prototype and is attached there.
                variadic: false,
            },
        )
    }

    fn enrich_from_source_for_decompile(&mut self) -> bool {
        if crate::prepare::prepared_arch_display_name(self.source.as_ref()).is_none() {
            return false;
        }
        let prior_plan = self.plan.clone();
        let (changed_parameters, return_type_changed) =
            SourceOwnedFunctionFacts::enrich_report_from_source_with_callee_signatures(
                self.source.as_ref(),
                &mut self.function_facts,
                &self.callee_signatures,
            );
        if (!changed_parameters.is_empty() || return_type_changed)
            && !self.refresh_plan_after_source_constraints(&changed_parameters)
        {
            // The plan is the analysis's projection of the facts, and it is
            // refreshed atomically: a plan that binds one argument twice, or
            // to a register that is no slot, would write conflicting types
            // back, so such a plan is left as it was. That is a fact about the
            // the analysis, not about the decompilation. The enriched facts are
            // what the rendering reads, and they stand; only the plan keeps
            // its prior signature, which the certificate check sees.
            // Failing the whole function here had cost every function whose
            // plan carried one such binding its decompilation.
            r2il::refusal_evidence!(
                "signature-refresh",
                "plan not refreshed: changed slots {changed_parameters:?} return_changed={return_type_changed}; facts enriched, plan kept"
            );
            self.plan = prior_plan;
        }
        true
    }

    pub fn type_facts(&self) -> &FunctionTypeFacts {
        self.function_facts.type_facts()
    }

    pub fn finalize_for_decompile(
        mut self,
        finalization: DecompileFinalization,
    ) -> Result<SourceOwnedFunctionFacts, TypeAnalysisError> {
        if !SourceOwnedFunctionFacts::stamp_report_decompile_route(
            &mut self.function_facts,
            finalization.kind,
            finalization.reason,
            finalization.fallback_comment,
        ) {
            return Err(TypeAnalysisError::IncompatibleDecompileRoute);
        }
        SourceOwnedFunctionFacts::seal_with_callee_signatures(
            self.source,
            self.function_facts,
            self.callee_signatures,
        )
        .ok_or(TypeAnalysisError::FunctionFactsSourceMismatch)
    }

    /// Project the enriched signature into the type plan.
    ///
    /// `changed_slots` is the enrichment's own account of which parameter
    /// declarations changed; nothing is recounted here, and the return type
    /// arrives with the signature itself. The refresh is
    /// atomic over the plan's argument bindings: a binding with no register,
    /// with a register that is no argument slot, or a second binding for one
    /// slot leaves the plan untouched and returns false, because a plan half
    /// refreshed would write conflicting types back.
    fn refresh_plan_after_source_constraints(&mut self, changed_slots: &BTreeSet<usize>) -> bool {
        let Some(signature) = self
            .function_facts
            .type_facts()
            .render_authorized_signature()
            .cloned()
        else {
            // Nothing is authorized for the plan to carry, so there is
            // nothing to refresh; the facts changed all the same, and the
            // rendering reads the facts.
            r2il::refusal_evidence!(
                "signature-refresh",
                "no render-authorized signature; plan not refreshed for changed slots {changed_slots:?}"
            );
            return true;
        };
        let source = self.source.as_ref();
        let Some(arch_name) = crate::prepare::prepared_arch_display_name(source) else {
            return false;
        };
        let ptr_bits = source
            .machine_context()
            .memory_model()
            .default_address_bits();
        if ptr_bits == 0 {
            return false;
        }
        let function_name = source
            .function()
            .name
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| r2source::unnamed_function(source.function().entry));
        let mut plan = self.plan.clone();
        plan.signature = inferred_signature_from_signature_spec(
            &function_name,
            arch_name,
            ptr_bits,
            self.function_facts.type_facts().callconv.as_deref(),
            &signature,
        );
        let mut refreshed_slots = BTreeSet::new();
        for candidate in plan
            .var_type_candidates
            .iter_mut()
            .filter(|candidate| candidate.isarg)
        {
            let Some(register) = candidate.reg.as_deref() else {
                return false;
            };
            let Some(slot) =
                exact_source_argument_slot_for_register(self.source.as_ref(), register)
            else {
                return false;
            };
            if !changed_slots.contains(&slot) {
                continue;
            }
            if !refreshed_slots.insert(slot) {
                return false;
            }
            let Some(ty) = signature
                .params
                .get(slot)
                .and_then(|parameter| parameter.ty.as_ref())
            else {
                return false;
            };
            let size =
                estimate_c_type_size_bytes(&render_signature_type(ty, ptr_bits), ptr_bits) as u32;
            candidate.var_type = ty.clone();
            candidate.size = size;
            candidate.source = TypeFactSource::CalleeSignature;
            if !candidate
                .evidence
                .contains(&TypeEvidence::CertifiedCallArgument)
            {
                candidate.evidence.push(TypeEvidence::CertifiedCallArgument);
            }
        }
        // A changed slot with no argument candidate is not an inconsistency:
        // the plan carries no variable for that parameter, so there is nothing
        // to refresh for it. Demanding one made every function whose declared
        // parameter types the source interface supplies -- but whose plan names
        // no register variable for one of them -- fail its whole analysis, and
        // with it the decompilation, once the interface began supplying every
        // parameter's type rather than only the return's.
        let unrefreshed = changed_slots
            .difference(&refreshed_slots)
            .copied()
            .collect::<Vec<_>>();
        if !unrefreshed.is_empty() {
            r2il::refusal_evidence!(
                "signature-refresh",
                "slots {unrefreshed:?} changed type with no argument candidate to carry it"
            );
        }
        self.plan = plan;
        true
    }
}

fn exact_source_argument_slot_for_register(source: &SsaArtifact, register: &str) -> Option<usize> {
    let context = source.machine_context();
    let register_storage = context.register_storage(register)?;
    if register_storage.space != r2ssa::CanonicalStorageSpace::Register
        || register_storage.size == 0
    {
        return None;
    }
    let interface = context.function_interface()?;
    let abi = context.abi_model();
    if !abi.is_available() || !abi.argument_placement_is_coherent() {
        return None;
    }
    let mut matches = interface.parameters().iter().filter(|parameter| {
        let Some(parameter_storage) = parameter.register_storage() else {
            return false;
        };
        if parameter_storage.space != register_storage.space
            || parameter_storage.offset != register_storage.offset
            || register_storage.size > parameter_storage.size
        {
            return false;
        }
        let mut abi_slots = abi
            .argument_registers()
            .iter()
            .filter(|slot| slot.index() == parameter.index());
        abi_slots
            .next()
            .is_some_and(|slot| slot.storage() == parameter_storage)
            && abi_slots.next().is_none()
    });
    let parameter = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    usize::try_from(parameter.index()).ok()
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

    pub fn parsed_context(&self) -> &ParsedExternalContext {
        &self.parsed_context
    }
}

struct DerivedTypeAnalysis {
    signature: InferredSignature,
    function_facts: FunctionFacts,
    type_facts: FunctionTypeFacts,
    plan: TypePlan,
}

struct DerivedTypeAnalysisInput<'a> {
    function_name: &'a str,
    ptr_bits: u32,
    inferred_signature: InferredSignature,
    recovered_vars: &'a [RecoveredVariable],
    ssa_blocks: &'a [SSABlock],
    parsed_context: ParsedExternalContext,
    local_structs: LocalStructArtifacts,
    interproc_summary_set: Option<InterprocSummarySet>,
    diagnostics: TypeAnalysisDiagnostics,
}

struct DerivedTypeAnalysisSemanticInputs<'a> {
    local_field_accesses: &'a [LocalFieldAccessFact],
}

struct PreparedMachineVarProfile {
    architecture: r2ssa::MachineArchitectureFamily,
    pointer_arg_slots: HashMap<String, usize>,
}

#[cfg(test)]
type TypeAnalysisInput<'a> = DerivedTypeAnalysisInput<'a>;

fn summary_arg_effect_to_callee(effect: &SummaryArgEffect) -> CalleeArgEffect {
    CalleeArgEffect {
        read: effect.read,
        write: effect.write,
        escape: effect.escape,
        free: effect.free,
    }
}

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

fn summary_observed_param_count(summary: &FunctionSemanticSummary) -> usize {
    let mut max_idx = summary.arg_effects.keys().copied().max();
    for effect in &summary.memory_effects {
        if let SummaryMemoryRegion::Arg { index } = effect.location.region {
            max_idx = Some(max_idx.unwrap_or(0).max(index));
        }
    }
    for effect in &summary.transfer_effects {
        if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.dst.region {
            max_idx = Some(max_idx.unwrap_or(0).max(index));
        }
        if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.src.region {
            max_idx = Some(max_idx.unwrap_or(0).max(index));
        }
        if let r2ssa::SummaryTransferLength::Arg(index) = effect.len {
            max_idx = Some(max_idx.unwrap_or(0).max(index));
        }
    }
    for effect in &summary.lifetime_effects {
        max_idx = Some(max_idx.unwrap_or(0).max(effect.arg));
    }
    for effect in &summary.sync_effects {
        max_idx = Some(max_idx.unwrap_or(0).max(effect.arg));
    }
    max_idx.map_or(0, |idx| idx + 1)
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

/// Pointer hints the interprocedural summary itself proves for a callee's
/// parameters.
fn summary_param_type_hints(summary: &FunctionSemanticSummary) -> BTreeMap<usize, CTypeLike> {
    let pointer_ty = CTypeLike::Pointer(Box::new(CTypeLike::Void));
    let mut hints = BTreeMap::new();
    let max_idx = summary_observed_param_count(summary);
    for idx in 0..max_idx {
        if summary_suggests_pointer_param(summary, idx) {
            hints.entry(idx).or_insert_with(|| pointer_ty.clone());
        }
    }
    hints
}

/// The return type the summary's own return relation gives, or nothing.
fn summary_return_type_hint(
    summary: &FunctionSemanticSummary,
    param_type_hints: &BTreeMap<usize, CTypeLike>,
) -> Option<CTypeLike> {
    match summary.return_relation {
        SummaryReturnRelation::Void => Some(CTypeLike::Void),
        SummaryReturnRelation::HeapAlloc => Some(heap_allocation_return_type()),
        SummaryReturnRelation::Arg(idx) => param_type_hints.get(&idx).cloned(),
        _ => None,
    }
}

fn summary_to_callee_fact(summary: &FunctionSemanticSummary) -> CalleeFact {
    let param_type_hints = summary_param_type_hints(summary);
    let return_type_hint = summary_return_type_hint(summary, &param_type_hints);
    let arg_effects = summary
        .arg_effects
        .iter()
        .map(|(idx, effect)| (*idx, summary_arg_effect_to_callee(effect)))
        .collect::<BTreeMap<_, _>>();
    CalleeFact {
        function_id: summary.id.0,
        name: summary.name.clone(),
        linkage: summary_linkage_to_callee_linkage(summary.linkage),
        signature: None,
        signature_callconv: None,
        signature_noreturn: false,
        model_policy_evidence: BTreeSet::from([CalleeModelPolicyEvidence::InterprocSummary]),
        direct_callees: summary.direct_callees.iter().copied().collect(),
        callsite_count: summary.callsite_count,
        has_unknown_calls: summary.has_unknown_calls,
        arg_effects,
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
        param_type_hints,
        return_type_hint,
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
    if existing.arg_effects.is_empty() {
        existing.arg_effects = incoming.arg_effects;
    }
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
    if existing.param_type_hints.is_empty() {
        existing.param_type_hints = incoming.param_type_hints;
    }
    if existing.return_type_hint.is_none() {
        existing.return_type_hint = incoming.return_type_hint;
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
    mut input: DerivedTypeAnalysisInput<'_>,
    semantic_inputs: Option<DerivedTypeAnalysisSemanticInputs<'_>>,
    prep_facts: Option<&r2ssa::DecompilePrepFacts>,
    machine_profile: Option<&PreparedMachineVarProfile>,
    registers: &crate::RegisterIdentity,
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

    let type_assumption_usage = apply_type_hint_assumptions_to_context(
        &mut input.parsed_context,
        &mut input.inferred_signature,
        input.ptr_bits,
        Some(&semantic_projection),
        registers,
    );

    // Borrowed after the last mutation of the context, and not copied: the
    // database is per binary while this runs per function.
    let type_db = &input.parsed_context.external_type_db;
    let type_assumption_parameter_slots = applied_type_assumption_parameter_slots(
        &type_assumption_usage,
        &input.parsed_context,
        registers,
    );
    let mut signature_certificate_sources = Vec::new();
    if authoritative_external_arity {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::ExternalContext,
        );
    }
    if !type_assumption_parameter_slots.is_empty() {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::TypeAssumption,
        );
    }
    let inferred_signature_spec =
        inferred_signature_to_spec(&input.inferred_signature, input.ptr_bits);
    if inferred_signature_spec.is_some() && !authoritative_external_arity {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::LocalInference,
        );
    }

    let mut merged_signature = merge_local_signature_into_merged_signature(
        input.parsed_context.merged_signature.clone(),
        inferred_signature_spec,
    );
    let inferred_register_params =
        inferred_signature_abi_register_params(&input.inferred_signature, input.ptr_bits);
    let mut canonicalize_register_params = input.parsed_context.register_params.clone();
    if inferred_register_params.len() > canonicalize_register_params.len() {
        canonicalize_register_params
            .extend_from_slice(&inferred_register_params[canonicalize_register_params.len()..]);
    }
    canonicalize_param_home_stack_slots(
        merged_signature.as_ref(),
        &canonicalize_register_params,
        &mut input.parsed_context.stack_slots,
        input.ssa_blocks,
        prep_facts,
        registers,
    );
    hide_unproven_stack_pointer_frame_slots(&mut input.parsed_context.stack_slots);
    apply_main_signature_override(input.function_name, &mut merged_signature);
    let role_hint_has_authoritative_empty_params = false;
    let before_interproc_signature = merged_signature.clone();
    apply_interproc_summary_to_signature(
        &mut merged_signature,
        &mut input.inferred_signature,
        &summary_view,
        Some(&semantic_projection),
        input.ptr_bits,
        type_db,
    );
    if merged_signature != before_interproc_signature {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::InterprocSummary,
        );
    }

    let mut diagnostics = input.diagnostics;
    diagnostics.solver_warnings = input.parsed_context.diagnostics.clone();
    diagnostics
        .warnings
        .extend(semantic_projection.refusal_warnings());
    if summary_view
        .diagnostics()
        .is_some_and(|diagnostics| !diagnostics.converged)
    {
        diagnostics.warnings.push(
            "interprocedural summary did not converge; downgraded summary-driven type hints"
                .to_string(),
        );
    }

    let external_structs = collect_external_struct_candidates_from_db(
        &input.parsed_context.external_type_db,
        input.ptr_bits,
    );
    let mut local_structs = input.local_structs;
    augment_local_struct_artifacts_with_projection(
        &mut local_structs,
        &semantic_projection,
        input.ptr_bits,
    );
    if let Some(semantic) = semantic_inputs.as_ref() {
        augment_local_struct_artifacts_with_local_field_accesses(
            &mut local_structs,
            semantic.local_field_accesses,
            input.ptr_bits,
        );
    }
    align_local_structs_with_external(
        &mut local_structs.struct_decls,
        &mut local_structs.slot_type_overrides,
        &local_structs.slot_field_profiles,
        &external_structs,
        input.ptr_bits,
    );
    prefer_stronger_local_struct_overrides(
        &local_structs.struct_decls,
        &mut local_structs.slot_type_overrides,
        &local_structs.slot_field_profiles,
        input.ptr_bits,
    );
    materialize_unresolved_signature_struct_layouts(
        merged_signature.as_ref(),
        &mut local_structs.struct_decls,
        &mut local_structs.slot_type_overrides,
        &input.parsed_context.external_type_db,
        input.ptr_bits,
    );
    let array_index_field_profiles = local_structs.slot_field_profiles.clone();
    let indexed_local_struct_refinement_slots = indexed_local_struct_refinement_slots(
        &local_structs,
        &signature_certificate_sources,
        &type_assumption_parameter_slots,
    );
    prune_conflicting_local_struct_overrides(
        &merged_signature,
        &mut local_structs.struct_decls,
        &mut local_structs.slot_type_overrides,
        &mut local_structs.slot_field_profiles,
        &indexed_local_struct_refinement_slots,
        &input.parsed_context.external_type_db,
        input.ptr_bits,
    );

    let struct_decls = dedup_struct_decls(
        external_structs
            .into_iter()
            .chain(local_structs.struct_decls.clone())
            .collect(),
    );

    let mut type_db = input.parsed_context.external_type_db.clone();
    merge_local_structs_into_type_db(&mut type_db, &struct_decls, input.ptr_bits);
    let before_slot_signature = merged_signature.clone();
    let merged_signature = merge_slot_type_overrides_into_signature(
        merged_signature,
        &local_structs.slot_type_overrides,
        &indexed_local_struct_refinement_slots,
        &type_db,
        input.ptr_bits,
        role_hint_has_authoritative_empty_params,
    );
    if merged_signature != before_slot_signature {
        push_signature_certificate_source(
            &mut signature_certificate_sources,
            SignatureCertificateSource::SlotTypeOverride,
        );
    }
    let mut array_index_certificates = array_index_certificates_from_struct_artifacts(
        &local_structs,
        &array_index_field_profiles,
        merged_signature.as_ref(),
        &type_db,
        input.ptr_bits,
    );
    let mut exact_indexed_access_certificates =
        exact_indexed_access_certificates_from_local_artifacts(
            &local_structs,
            &array_index_certificates,
            merged_signature.as_ref(),
            &type_db,
            input.ptr_bits,
        );
    array_index_certificates.append(&mut exact_indexed_access_certificates.array_index);
    let scalar_array_access_certificates = scalar_array_access_certificates_from_ssa(
        input.ssa_blocks,
        &input.parsed_context,
        &type_db,
        merged_signature.as_ref(),
        &local_structs.slot_element_strides,
        ScalarArrayMachineProfile {
            architecture: machine_profile
                .map(|profile| profile.architecture)
                .unwrap_or(r2ssa::MachineArchitectureFamily::Unknown),
            pointer_arg_slots: machine_profile.map(|profile| &profile.pointer_arg_slots),
            ptr_bits: input.ptr_bits,
        },
    );
    array_index_certificates.extend(scalar_array_access_certificates.array_index);
    let mut scalar_array_render_candidates = exact_indexed_access_certificates.render_candidates;
    let local_indexed_slots = scalar_array_render_candidates
        .iter()
        .map(|candidate| candidate.slot)
        .collect::<HashSet<_>>();
    scalar_array_render_candidates.extend(
        scalar_array_access_certificates
            .render_candidates
            .into_iter()
            .filter(|candidate| !local_indexed_slots.contains(&candidate.slot)),
    );
    scalar_array_render_candidates.sort();
    scalar_array_render_candidates.dedup();
    let mut field_access_certificates =
        field_access_certificates_from_struct_artifacts(&local_structs);
    field_access_certificates.append(&mut exact_indexed_access_certificates.field_access);
    field_access_certificates.extend(scalar_array_access_certificates.field_access);
    field_access_certificates.sort();
    field_access_certificates.dedup();
    let signature_certificate = signature_certificate_from_merged(
        merged_signature.as_ref(),
        &signature_certificate_sources,
    );
    let out_param_certificates = out_param_certificates_from_projection(
        &semantic_projection,
        merged_signature.as_ref(),
        input.ptr_bits,
    );
    let current_context_maps =
        signature_context_maps(merged_signature.as_ref(), input.ptr_bits, &type_db);
    apply_signature_context_overrides(
        &mut input.inferred_signature,
        merged_signature.as_ref(),
        input.ptr_bits,
        &type_db,
    );
    let existing_types =
        parse_existing_var_types_from_specs(&input.parsed_context.stack_slots, input.ptr_bits);
    let stack_access_widths = canonical_stack_access_widths(input.ssa_blocks, prep_facts);
    let arch_name = if input.inferred_signature.arch.is_empty() {
        input.parsed_context.callconv.as_deref()
    } else {
        Some(input.inferred_signature.arch.as_str())
    };
    let stack_access_signedness =
        canonical_stack_access_signedness(input.ssa_blocks, prep_facts, arch_name);
    let is_main_signature = merged_signature
        .as_ref()
        .is_some_and(is_canonical_main_signature_spec);
    let var_type_ctx = VarTypeCandidateContext {
        current_context_maps: &current_context_maps,
        merged_signature: merged_signature.as_ref(),
        slot_type_overrides: &local_structs.slot_type_overrides,
        stack_slots: &input.parsed_context.stack_slots,
        existing_types: &existing_types,
        stack_access_widths: &stack_access_widths,
        stack_access_signedness: &stack_access_signedness,
        ptr_bits: input.ptr_bits,
        is_main_signature,
    };
    let var_type_candidates =
        build_var_type_candidates(input.recovered_vars, &var_type_ctx, &mut diagnostics);
    apply_canonical_stack_width_types(
        &mut input.parsed_context.stack_slots,
        input.recovered_vars,
        &var_type_candidates,
    );
    let var_rename_candidates = build_var_rename_candidates(
        input.recovered_vars,
        &current_context_maps.param_names,
        &input.parsed_context.stack_slots,
    );
    let visible_bindings = build_visible_bindings(
        merged_signature.as_ref(),
        &input.parsed_context.register_params,
        &input.parsed_context.stack_slots,
        input.recovered_vars,
        &var_type_candidates,
        &var_rename_candidates,
        input.ptr_bits,
    );
    let type_facts = FunctionTypeFacts::builder(FunctionTypeFactInputs {
        merged_signature: merged_signature.clone(),
        callconv: input.parsed_context.callconv.clone(),
        noreturn: input.parsed_context.noreturn,
        known_function_signatures: input.parsed_context.known_function_signatures.clone(),
        register_params: input.parsed_context.register_params.clone(),
        stack_slots: input.parsed_context.stack_slots.clone(),
        visible_bindings,
        callee_facts: merged_context_and_summary_callee_facts(
            &input.parsed_context.callee_facts,
            input.interproc_summary_set.as_ref(),
        ),
        external_type_db: type_db,
        program_data_objects: input.parsed_context.program_data_objects.clone(),
        slot_type_overrides: local_structs.slot_type_overrides.clone(),
        slot_field_profiles: local_structs.slot_field_profiles.clone(),
        local_field_accesses: semantic_inputs
            .as_ref()
            .map(|semantic| semantic.local_field_accesses.to_vec())
            .unwrap_or_default(),
        field_access_certificates,
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
    let global_type_links = score_global_type_links(
        input.ssa_blocks,
        &struct_decls,
        &var_type_candidates,
        input.ptr_bits,
        &input.parsed_context.program_extents,
    );

    let plan = TypePlan {
        ptr_bits: input.ptr_bits,
        signature: input.inferred_signature.clone(),
        var_type_candidates,
        var_rename_candidates,
        struct_decls: struct_decls.clone(),
        global_type_links,
        diagnostics: diagnostics.clone(),
    };

    DerivedTypeAnalysis {
        signature: input.inferred_signature,
        function_facts: FunctionFacts::new(type_facts.clone())
            .with_assumptions(input.parsed_context.assumptions.clone())
            .with_summary_view(summary_view)
            .with_diagnostics(type_facts.diagnostics.clone())
            .with_assumption_usage(type_assumption_usage),
        type_facts,
        plan,
    }
}

#[cfg(test)]
fn register_identity_from(registers: &[(&str, u64, u32)]) -> crate::RegisterIdentity {
    let storages = registers
        .iter()
        .map(|(name, offset, size)| {
            (
                (*name).to_string(),
                r2ssa::CanonicalStorageId {
                    space: r2ssa::CanonicalStorageSpace::Register,
                    offset: *offset,
                    size: *size,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    crate::RegisterIdentity::from_register_storages(&storages)
}

#[cfg(test)]
fn x86_64_register_identity() -> crate::RegisterIdentity {
    register_identity_from(&[
        ("rax", 0x00, 8),
        ("eax", 0x00, 4),
        ("ax", 0x00, 2),
        ("al", 0x00, 1),
        ("ah", 0x01, 1),
        ("rdx", 0x10, 8),
        ("edx", 0x10, 4),
        ("dx", 0x10, 2),
        ("dl", 0x10, 1),
        ("dh", 0x11, 1),
        ("rdi", 0x38, 8),
        ("edi", 0x38, 4),
        ("dil", 0x38, 1),
        ("rsi", 0x30, 8),
        ("esi", 0x30, 4),
        ("sil", 0x30, 1),
        ("rcx", 0x08, 8),
        ("ecx", 0x08, 4),
    ])
}

#[cfg(test)]
fn aarch64_register_identity() -> crate::RegisterIdentity {
    let mut registers = Vec::new();
    for index in 0..31u64 {
        let offset = 0x1000 + index * 8;
        registers.push((format!("x{index}"), offset, 8u32));
        registers.push((format!("w{index}"), offset, 4u32));
    }
    registers.push(("sp".to_string(), 0x1100, 8));
    let storages = registers
        .iter()
        .map(|(name, offset, size)| {
            (
                name.clone(),
                r2ssa::CanonicalStorageId {
                    space: r2ssa::CanonicalStorageSpace::Register,
                    offset: *offset,
                    size: *size,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    crate::RegisterIdentity::from_register_storages(&storages)
}

#[cfg(test)]
fn build_type_analysis(input: DerivedTypeAnalysisInput<'_>) -> DerivedTypeAnalysis {
    let machine = detached_x86_64_test_machine_profile();
    build_type_analysis_inner(
        input,
        None,
        None,
        Some(&machine),
        &x86_64_register_identity(),
    )
}

#[cfg(test)]
fn build_type_analysis_with_prep_facts(
    input: DerivedTypeAnalysisInput<'_>,
    prep_facts: &r2ssa::DecompilePrepFacts,
) -> DerivedTypeAnalysis {
    let machine = detached_x86_64_test_machine_profile();
    build_type_analysis_inner(
        input,
        None,
        Some(prep_facts),
        Some(&machine),
        &x86_64_register_identity(),
    )
}

#[cfg(test)]
fn detached_x86_64_test_machine_profile() -> PreparedMachineVarProfile {
    let architecture = r2ssa::MachineArchitectureFamily::X86_64;
    PreparedMachineVarProfile {
        architecture,
        pointer_arg_slots: collect_pointer_arg_slot_map(architecture, 64),
    }
}

#[cfg(test)]
fn signed_int_type(bits: u32) -> CTypeLike {
    CTypeLike::Int {
        bits,
        signedness: Signedness::Signed,
    }
}

#[cfg(test)]
fn void_pointer_type() -> CTypeLike {
    CTypeLike::Pointer(Box::new(CTypeLike::Void))
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
    let function_name = source
        .function()
        .name
        .clone()
        .unwrap_or_else(|| r2source::unnamed_function(source.function().entry));
    let ssa_blocks = source.local_ssa_blocks();
    let inferred_signature = crate::infer_signature_from_prepared_ssa(source.as_ref());
    let recovered_vars = crate::prepare::recover_vars_from_prepared_ssa(source.as_ref(), ptr_bits);
    let mut diagnostics = TypeAnalysisDiagnostics::default();
    let arch_name = crate::prepare::prepared_arch_display_name(source.as_ref());
    let machine_profile = PreparedMachineVarProfile {
        architecture: source.machine_context().architecture_family(),
        pointer_arg_slots: collect_prepared_pointer_arg_slot_map(source.as_ref()),
    };
    let local_structs = infer_local_struct_artifacts_from_prepared_ssa(
        source.as_ref(),
        arch_name,
        ptr_bits,
        &mut diagnostics,
    );
    let local_field_accesses = local_field_accesses_named(
        &local_structs,
        &crate::prepare::source_field_names(source.as_ref()),
    );
    let interproc_report = interproc_summary
        .as_ref()
        .map(|summary| summary.report().clone());
    require_current_interproc_report_for_source_owned(interproc_report.as_ref())?;
    let derived_input = DerivedTypeAnalysisInput {
        function_name: &function_name,
        ptr_bits,
        inferred_signature,
        recovered_vars: &recovered_vars,
        ssa_blocks,
        parsed_context,
        local_structs,
        interproc_summary_set: interproc_report,
        diagnostics,
    };
    let semantic_inputs = Some(DerivedTypeAnalysisSemanticInputs {
        local_field_accesses: &local_field_accesses,
    });
    let derived = build_type_analysis_inner(
        derived_input,
        semantic_inputs,
        source.decompile_prep_facts(),
        Some(&machine_profile),
        &crate::RegisterIdentity::from_prepared(source.as_ref()),
    );
    let mut function_facts = derived.function_facts;
    if let Some(interproc_summary) = interproc_summary {
        function_facts = function_facts.with_prepared_interproc_summary(interproc_summary);
    }
    if derived.signature != derived.plan.signature {
        return Err(TypeAnalysisError::DerivedSignatureMismatch);
    }
    if derived.type_facts != *function_facts.type_facts() {
        return Err(TypeAnalysisError::DerivedTypeFactsMismatch);
    }
    let exact_source_fields = field_access_certificates_from_source_aggregate_accesses(&source);
    if !exact_source_fields.is_empty() {
        let mut type_facts = function_facts.type_facts().clone();
        for certificate in exact_source_fields {
            type_facts.field_access_certificates.retain(|existing| {
                existing.slot != certificate.slot
                    || existing.field_offset != certificate.field_offset
            });
            type_facts.field_access_certificates.push(certificate);
        }
        function_facts.replace_type_facts(type_facts);
    }
    let mut analysis = TypeAnalysis {
        source,
        function_facts,
        plan: derived.plan,
        callee_signatures,
    };
    if !analysis.enrich_from_source_for_decompile() {
        return Err(TypeAnalysisError::SourceEnrichmentFailed);
    }
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

/// Project advisory local field observations without granting certificates.
fn local_field_accesses_from_struct_artifacts(
    local_structs: &LocalStructArtifacts,
) -> Vec<LocalFieldAccessFact> {
    local_field_accesses_named(local_structs, &BTreeMap::new())
}

/// The same observations, naming each field what the source called it when the
/// source said.
///
/// Naming a field after its offset is what you do when nothing told you its
/// name. When debug info did tell you, using the offset anyway throws the
/// answer away.
pub(crate) fn local_field_accesses_named(
    local_structs: &LocalStructArtifacts,
    source_field_names: &BTreeMap<(usize, u64), String>,
) -> Vec<LocalFieldAccessFact> {
    let mut accesses = Vec::new();
    for (slot, fields) in &local_structs.slot_field_profiles {
        for (field_offset, field_type) in fields {
            accesses.push(LocalFieldAccessFact {
                slot: *slot,
                field_offset: *field_offset,
                field_name: source_field_names
                    .get(&(*slot, *field_offset))
                    .cloned()
                    .unwrap_or_else(|| format!("f_{field_offset:x}")),
                field_type: Some(field_type.clone()),
            });
        }
    }
    accesses.sort();
    accesses
}

fn field_access_certificates_from_struct_artifacts(
    local_structs: &LocalStructArtifacts,
) -> Vec<crate::FieldAccessCertificate> {
    local_field_accesses_from_struct_artifacts(local_structs)
        .into_iter()
        .map(|access| crate::FieldAccessCertificate {
            slot: access.slot,
            field_offset: access.field_offset,
            field_name: access.field_name,
            field_type: access.field_type,
        })
        .collect()
}

/// One source type as the C model spells it.
///
/// Public because a rendering that declares a value of an aggregate has to
/// define that aggregate, and the definition's member types come from the same
/// graph the declaration did.
/// The graph's type wearing the qualifiers the declaration spelled.
///
/// The graph carries structure and no qualifier; the prototype text carries
/// both. Where the two agree on shape, a `const` the text puts on a pointee
/// goes onto the graph's pointee, and nothing else moves.
pub(crate) fn requalify(graph: CTypeLike, spelled: &CTypeLike) -> CTypeLike {
    match (graph, spelled) {
        (CTypeLike::Const(inner), spelled) => {
            CTypeLike::Const(Box::new(requalify(*inner, spelled)))
        }
        (inner, CTypeLike::Const(spelled)) => CTypeLike::Const(Box::new(requalify(inner, spelled))),
        (CTypeLike::Pointer(inner), CTypeLike::Pointer(spelled)) => {
            CTypeLike::Pointer(Box::new(requalify(*inner, spelled)))
        }
        (CTypeLike::Array(inner, count), CTypeLike::Array(spelled, _)) => {
            CTypeLike::Array(Box::new(requalify(*inner, spelled)), count)
        }
        (CTypeLike::Typedef { name, ty }, spelled) => CTypeLike::Typedef {
            name,
            ty: Box::new(requalify(*ty, spelled)),
        },
        (graph, CTypeLike::Typedef { ty: spelled, .. }) => requalify(graph, spelled),
        (graph, _) => graph,
    }
}

pub fn source_type_like(
    graph: &r2ssa::SourceTypeGraph,
    type_id: u32,
    visiting: &mut BTreeSet<u32>,
) -> Option<CTypeLike> {
    if !visiting.insert(type_id) {
        return None;
    }
    let source_type = graph
        .types()
        .get(usize::try_from(type_id).ok()?)
        .filter(|source_type| source_type.id() == type_id)?;
    let bits = u32::try_from(source_type.size_bits()).ok()?;
    // What the source called this type, when it called it anything. The name
    // renders and the structure stands behind it, so a rendering keeps the
    // spelling the program was written with without any consumer losing the
    // width. Compilation destroys names; this is the only place one survives.
    let named = |ty: CTypeLike| match graph
        .aliases()
        .iter()
        .find(|alias| alias.type_id() == type_id)
    {
        Some(alias) => CTypeLike::named(alias.name(), ty),
        None => ty,
    };
    let ty = match source_type.kind() {
        r2ssa::SourceTypeKind::SignedInteger => CTypeLike::Int {
            bits,
            signedness: Signedness::Signed,
        },
        r2ssa::SourceTypeKind::UnsignedInteger => CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        },
        r2ssa::SourceTypeKind::Pointer { target_type_id } => {
            let target = source_type_like(graph, target_type_id, visiting)?;
            // `CTypeLike::Function` already spells a pointer to function,
            // `ret(*)(params)`, so wrapping it adds an indirection the program
            // does not have and spells `void(*)(void)*`, which is not C.
            if matches!(target, CTypeLike::Function { .. }) {
                target
            } else {
                CTypeLike::Pointer(Box::new(target))
            }
        }
        r2ssa::SourceTypeKind::Struct { aggregate_id } => {
            let aggregate = graph
                .aggregates()
                .get(usize::try_from(aggregate_id).ok()?)
                .filter(|aggregate| {
                    aggregate.id() == aggregate_id && aggregate.type_id() == type_id
                })?;
            CTypeLike::Struct(aggregate.name().to_string())
        }
        r2ssa::SourceTypeKind::Union { aggregate_id } => {
            let aggregate = graph
                .aggregates()
                .get(usize::try_from(aggregate_id).ok()?)
                .filter(|aggregate| {
                    aggregate.id() == aggregate_id && aggregate.type_id() == type_id
                })?;
            CTypeLike::Union(aggregate.name().to_string())
        }
        r2ssa::SourceTypeKind::Array {
            element_type_id,
            count,
        } => CTypeLike::Array(
            Box::new(source_type_like(graph, element_type_id, visiting)?),
            Some(usize::try_from(count).ok()?),
        ),
        r2ssa::SourceTypeKind::Float => CTypeLike::Float(bits),
        r2ssa::SourceTypeKind::Void => CTypeLike::Void,
        // A function whose signature the graph does not carry; spelled with
        // an empty parameter list, which in C is an unspecified one.
        r2ssa::SourceTypeKind::Code => CTypeLike::Function {
            ret: Box::new(CTypeLike::Void),
            params: Box::new([]),
        },
    };
    visiting.remove(&type_id);
    Some(named(ty))
}

/// Project exact, revision-bound source aggregate accesses into the canonical
/// type certificate keyed by ABI parameter slot and byte offset.
///
/// The r2ssa projection has already joined the immutable source type graph,
/// parameter provenance, memory occurrence, and access width. r2types only
/// publishes projections whose logical member type retains that exact width;
/// it does not recover a field from address syntax or a rendered name.
fn field_access_certificates_from_source_aggregate_accesses(
    source: &r2ssa::SsaArtifact,
) -> Vec<crate::FieldAccessCertificate> {
    let Some(interface) = source.machine_context().function_interface() else {
        return Vec::new();
    };
    let Some(graph) = interface.type_graph() else {
        return Vec::new();
    };
    let Some(projections) = source
        .aggregate_accesses()
        .projections_for_revision(interface.revision_identity())
    else {
        return Vec::new();
    };
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    let mut by_location = BTreeMap::<(usize, u64), Option<crate::FieldAccessCertificate>>::new();
    for projection in projections.values() {
        let Ok(slot) = usize::try_from(projection.source_parameter_index) else {
            continue;
        };
        let Some(field_type) =
            source_type_like(graph, projection.member_type_id, &mut BTreeSet::new())
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
            field_type: Some(render_c_type_like(&field_type)),
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

fn array_index_certificates_from_struct_artifacts(
    local_structs: &LocalStructArtifacts,
    slot_field_profiles: &HashMap<usize, BTreeMap<u64, String>>,
    merged_signature: Option<&FunctionSignatureSpec>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Vec<ArrayIndexCertificate> {
    let mut certificates = Vec::new();

    let mut slots: Vec<_> = slot_field_profiles.keys().copied().collect();
    slots.sort_unstable();
    for slot in slots {
        let Some(fields) = slot_field_profiles.get(&slot) else {
            continue;
        };
        if fields.is_empty() {
            continue;
        }

        let stride =
            aggregate_stride_for_slot(slot, local_structs, merged_signature, type_db, ptr_bits)
                .or_else(|| profile_minimum_stride(fields, ptr_bits));
        let Some(element_stride) = stride.filter(|stride| *stride > 0) else {
            continue;
        };

        for field_offset in fields.keys() {
            certificates.push(ArrayIndexCertificate {
                slot,
                base: Some(ArrayIndexBase::Param { index: slot }),
                field_offset: *field_offset,
                element_stride,
            });
        }
    }

    certificates.sort();
    certificates.dedup();
    certificates
}

fn exact_indexed_access_certificates_from_local_artifacts(
    local_structs: &LocalStructArtifacts,
    layout_certificates: &[ArrayIndexCertificate],
    merged_signature: Option<&FunctionSignatureSpec>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> ScalarArrayAccessCertificates {
    let mut certificates = ScalarArrayAccessCertificates::default();
    for candidate in &local_structs.indexed_accesses {
        if candidate.access_width == 0 || candidate.element_stride == 0 {
            continue;
        }
        let layout_certified = layout_certificates.iter().any(|certificate| {
            certificate.slot == candidate.slot
                && certificate.field_offset == candidate.field_offset
                && certificate.element_stride == candidate.element_stride
                && matches!(
                    certificate.base,
                    Some(ArrayIndexBase::Param { index }) if index == candidate.slot
                )
        });
        if layout_certified {
            certificates.render_candidates.push(*candidate);
            continue;
        }
        let Some(signature) = merged_signature else {
            continue;
        };
        let Some(param_ty) = signature
            .params
            .get(candidate.slot)
            .and_then(|param| param.ty.as_ref())
        else {
            continue;
        };
        if pointer_element_stride(param_ty, type_db, ptr_bits) != Some(candidate.element_stride) {
            continue;
        }
        let field_layout = aggregate_pointee_type_names_from_type(param_ty)
            .into_iter()
            .find_map(|type_name| {
                external_layout_field_access_for_offset(
                    type_db,
                    &type_name,
                    candidate.field_offset,
                    u64::from(candidate.access_width),
                    ptr_bits,
                )
            });
        let full_element_access = candidate.field_offset == 0
            && u64::from(candidate.access_width) == candidate.element_stride;
        if !full_element_access && field_layout.is_none() {
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
        if let Some(field) = field_layout {
            certificates
                .field_access
                .push(crate::FieldAccessCertificate {
                    slot: candidate.slot,
                    field_offset: candidate.field_offset,
                    field_name: field.name,
                    field_type: field.ty,
                });
        }
        certificates.render_candidates.push(*candidate);
    }
    certificates.array_index.sort();
    certificates.array_index.dedup();
    certificates.field_access.sort();
    certificates.field_access.dedup();
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
                .unwrap_or_else(|| format!("arg{}", param_index + 1));
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

fn aggregate_stride_for_slot(
    slot: usize,
    local_structs: &LocalStructArtifacts,
    merged_signature: Option<&FunctionSignatureSpec>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Option<u64> {
    local_structs
        .slot_element_strides
        .get(&slot)
        .copied()
        .or_else(|| {
            local_structs
                .slot_type_overrides
                .get(&slot)
                .into_iter()
                .flat_map(|raw_ty| aggregate_pointee_type_names_from_str(raw_ty, ptr_bits))
                .chain(
                    merged_signature
                        .and_then(|signature| signature.params.get(slot))
                        .and_then(|param| param.ty.as_ref())
                        .into_iter()
                        .flat_map(aggregate_pointee_type_names_from_type),
                )
                .find_map(|name| external_aggregate_size(type_db, &name, ptr_bits))
        })
}

fn aggregate_pointee_type_names_from_str(raw_ty: &str, ptr_bits: u32) -> Vec<String> {
    parse_c_type_like(raw_ty, ptr_bits)
        .map(|ty| aggregate_pointee_type_names_from_type(&ty))
        .unwrap_or_default()
}

fn profile_minimum_stride(fields: &BTreeMap<u64, String>, ptr_bits: u32) -> Option<u64> {
    fields
        .iter()
        .filter_map(|(offset, ty)| offset.checked_add(estimate_c_type_size_bytes(ty, ptr_bits)))
        .max()
}

fn canonical_stack_access_widths(
    ssa_blocks: &[SSABlock],
    prep_facts: Option<&r2ssa::DecompilePrepFacts>,
) -> BTreeMap<StackSlotKey, BTreeSet<u32>> {
    let Some(prep_facts) = prep_facts else {
        return BTreeMap::new();
    };
    let mut widths = BTreeMap::<StackSlotKey, BTreeSet<u32>>::new();
    for op in ssa_blocks.iter().flat_map(|block| &block.ops) {
        let (addr, size) = match op {
            SSAOp::Load {
                dst,
                space: r2il::SpaceId::Ram,
                addr,
            } => (addr, dst.size),
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr,
                val,
            } => (addr, val.size),
            _ => continue,
        };
        if size == 0 {
            continue;
        }
        let Some(root) = prep_facts.stack_address_root_of(addr).copied() else {
            continue;
        };
        widths.entry(root).or_default().insert(size);
    }
    widths
}

fn canonical_stack_access_signedness(
    ssa_blocks: &[SSABlock],
    prep_facts: Option<&r2ssa::DecompilePrepFacts>,
    arch_name: Option<&str>,
) -> BTreeMap<StackSlotKey, BTreeSet<ScalarSignednessEvidence>> {
    let Some(prep_facts) = prep_facts else {
        return BTreeMap::new();
    };
    let scalar_signedness = infer_scalar_signedness(
        ssa_blocks.iter().flat_map(|block| block.ops.iter()),
        std::iter::empty(),
        arch_name,
    );
    let mut signedness = BTreeMap::<StackSlotKey, BTreeSet<ScalarSignednessEvidence>>::new();
    for op in ssa_blocks.iter().flat_map(|block| &block.ops) {
        let (addr, value) = match op {
            SSAOp::Load {
                dst,
                space: r2il::SpaceId::Ram,
                addr,
            } => (addr, dst),
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr,
                val,
            } => (addr, val),
            _ => continue,
        };
        let Some(observed) = scalar_signedness.get(value) else {
            continue;
        };
        let Some(root) = prep_facts.stack_address_root_of(addr).copied() else {
            continue;
        };
        signedness
            .entry(root)
            .or_default()
            .extend(observed.iter().copied());
    }
    signedness
}

fn hide_unproven_stack_pointer_frame_slots(
    stack_slots: &mut BTreeMap<StackSlotKey, ExternalStackVarSpec>,
) {
    let has_frame_pointer_slots = stack_slots
        .keys()
        .any(|slot_key| matches!(slot_key.base, ExternalStackBase::FramePointer));
    if !has_frame_pointer_slots {
        return;
    }

    for (slot_key, slot) in stack_slots {
        if !matches!(slot_key.base, ExternalStackBase::StackPointer)
            || slot_key.offset != 0
            || !matches!(slot.role, ExternalStackSlotRole::Unknown)
            || slot.param_index.is_some()
            || slot.param_name.is_some()
            || slot.source_reg.is_some()
            || !is_low_quality_stack_name(&slot.name)
        {
            continue;
        }
        slot.role = ExternalStackSlotRole::SavedFp;
        slot.name = "saved_fp".to_string();
    }
}

fn is_canonical_main_signature_spec(signature: &FunctionSignatureSpec) -> bool {
    signature == &canonical_main_signature_spec()
}

fn signature_context_maps(
    signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) -> SignatureContextMaps {
    let mut maps = SignatureContextMaps::default();
    let Some(signature) = signature else {
        return maps;
    };
    for (idx, param) in signature.params.iter().enumerate() {
        if let Some(ty) = param.ty.as_ref() {
            let ty_str = render_signature_type(ty, ptr_bits);
            if !type_name_is_generic(&ty_str)
                || param_has_authoritative_named_scalar_role(param, ptr_bits, type_db)
            {
                maps.param_types.insert(idx, ty_str);
            }
        }
        if !is_generic_arg_name(&param.name) {
            maps.param_names.insert(idx, param.name.clone());
        }
    }
    maps
}

fn unresolved_named_struct_target_for_param(
    param: &FunctionParamSpec,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Option<String> {
    let Some(CTypeLike::Pointer(inner)) = param.ty.as_ref() else {
        return None;
    };
    match inner.as_ref() {
        CTypeLike::Struct(name) => unresolved_named_struct_target(name, type_db),
        CTypeLike::Typedef { name, .. } if !type_db_resolves_type_name(type_db, name, ptr_bits) => {
            unresolved_named_struct_target(name, type_db)
        }
        _ => None,
    }
}

fn unresolved_named_struct_target(name: &str, type_db: &ExternalTypeDb) -> Option<String> {
    let name = canonical_struct_decl_name(name);
    if name.is_empty()
        || is_generated_local_struct_name(&name)
        || external_named_aggregate_has_real_layout(type_db, &name)
    {
        return None;
    }
    Some(name)
}

fn canonical_struct_decl_name(name: &str) -> String {
    let trimmed = name.trim();
    for prefix in ["struct ", "union ", "enum "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn merge_or_insert_local_struct_decl(
    struct_decls: &mut Vec<StructDeclCandidate>,
    incoming: StructDeclCandidate,
    ptr_bits: u32,
) {
    let Some(existing) = struct_decls
        .iter_mut()
        .find(|decl| decl.name.eq_ignore_ascii_case(&incoming.name))
    else {
        struct_decls.push(incoming);
        return;
    };

    let mut fields = existing
        .fields
        .iter()
        .cloned()
        .map(|field| (field.offset, field))
        .collect::<BTreeMap<_, _>>();
    for field in incoming.fields {
        fields.entry(field.offset).or_insert(field);
    }
    existing.fields = fields.into_values().collect();
    existing.confidence = existing.confidence.max(incoming.confidence);
    existing.source = StructDeclSource::LocalInferred;
    if let Some(decl) = build_struct_decl(&existing.name, &existing.fields, ptr_bits) {
        existing.decl = decl;
    }
}

fn materialize_unresolved_signature_struct_layouts(
    merged_signature: Option<&FunctionSignatureSpec>,
    struct_decls: &mut Vec<StructDeclCandidate>,
    slot_type_overrides: &mut HashMap<usize, String>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) {
    let Some(signature) = merged_signature else {
        return;
    };

    let mut slots = slot_type_overrides.keys().copied().collect::<Vec<_>>();
    slots.sort_unstable();
    for slot in slots {
        let Some(raw_ty) = slot_type_overrides.get(&slot) else {
            continue;
        };
        let Some(local_name) = generated_local_struct_name_from_override(raw_ty, ptr_bits) else {
            continue;
        };
        let Some(param) = signature.params.get(slot) else {
            continue;
        };
        let Some(target_name) = unresolved_named_struct_target_for_param(param, type_db, ptr_bits)
        else {
            continue;
        };
        let Some(local_decl) = struct_decls
            .iter()
            .find(|decl| {
                decl.source == StructDeclSource::LocalInferred
                    && decl.name.eq_ignore_ascii_case(&local_name)
            })
            .cloned()
        else {
            continue;
        };
        let Some(decl) = build_struct_decl(&target_name, &local_decl.fields, ptr_bits) else {
            continue;
        };
        merge_or_insert_local_struct_decl(
            struct_decls,
            StructDeclCandidate {
                name: target_name.clone(),
                decl,
                confidence: local_decl.confidence,
                source: StructDeclSource::LocalInferred,
                fields: local_decl.fields,
            },
            ptr_bits,
        );
        slot_type_overrides.insert(slot, format!("struct {target_name} *"));
    }
}

fn dedup_struct_decls(mut decls: Vec<StructDeclCandidate>) -> Vec<StructDeclCandidate> {
    decls.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    let mut merged: Vec<StructDeclCandidate> = Vec::new();
    for decl in decls {
        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.name.eq_ignore_ascii_case(&decl.name))
        {
            if should_replace_struct_decl(existing, &decl) {
                *existing = decl;
            }
        } else {
            merged.push(decl);
        }
    }
    merged
}

fn should_replace_struct_decl(
    existing: &StructDeclCandidate,
    candidate: &StructDeclCandidate,
) -> bool {
    candidate.source == StructDeclSource::LocalInferred
        && is_generated_local_struct_name(&candidate.name)
        && existing.name.eq_ignore_ascii_case(&candidate.name)
}

fn parse_existing_var_types_from_specs(
    stack_vars: &BTreeMap<StackSlotKey, ExternalStackVarSpec>,
    ptr_bits: u32,
) -> HashMap<String, String> {
    stack_vars
        .values()
        .filter(|var| slot_role_allows_external_local_identity(var.role))
        .filter_map(|var| {
            let ty = var
                .ty
                .as_ref()
                .map(|ty| render_signature_type(ty, ptr_bits))?;
            Some((var.name.clone(), normalize_external_type_name(&ty)))
        })
        .collect()
}

#[cfg(test)]
mod tests;
