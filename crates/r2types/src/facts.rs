use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::context::ExternalRegisterParamSpec;
use crate::convert::CTypeLike;
use crate::model::Signedness;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionType {
    pub return_type: CTypeLike,
    pub params: Vec<CTypeLike>,
    /// The basis each parameter's type rests on; only `DebugInfo` and `Declared` state one (D261).
    pub bases: Vec<r2source::Basis>,
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldAccessCertificate {
    pub slot: usize,
    pub field_offset: u64,
    pub field_name: String,
    pub field_type: Option<CTypeLike>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArrayIndexBase {
    Param { index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArrayIndexCertificate {
    pub slot: usize,
    pub base: Option<ArrayIndexBase>,
    pub field_offset: u64,
    pub element_stride: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalarArrayRenderCandidate {
    pub slot: usize,
    /// The load or store, by identity in the sealed function.
    pub op: r2ssa::OpId,
    pub is_write: bool,
    pub field_offset: u64,
    pub element_stride: u64,
    pub access_width: u32,
    pub index_value: Option<r2ssa::ValueId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OutParamCertificateEvidence {
    SemanticTypeSeed,
    InterprocArgWrite,
    InterprocMemoryWrite,
    InterprocTransferDst,
    NativeWorkerWrite,
    NativeRegionWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OutParamCertificateSource {
    SemanticClaim {
        stable_id: u64,
        anchor: u64,
    },
    InterprocSummaryEffect {
        function_id: u64,
        evidence: OutParamCertificateEvidence,
        param_index: usize,
        effect_index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OutParamCertificate {
    pub param_index: usize,
    pub param_name: String,
    pub pointee_type: Option<String>,
    pub evidence: Vec<OutParamCertificateEvidence>,
    pub sources: Vec<OutParamCertificateSource>,
}

impl OutParamCertificate {
    pub fn has_source_identity(&self) -> bool {
        !self.evidence.is_empty()
            && self.sources.iter().any(|source| match source {
                OutParamCertificateSource::SemanticClaim { .. } => true,
                OutParamCertificateSource::InterprocSummaryEffect {
                    evidence,
                    param_index,
                    ..
                } => *param_index == self.param_index && self.evidence.contains(evidence),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCertificate {
    pub signature: FunctionSignatureSpec,
    pub sources: Vec<SignatureCertificateSource>,
}

impl SignatureCertificate {
    pub fn from_signature(
        signature: &FunctionSignatureSpec,
        sources: impl IntoIterator<Item = SignatureCertificateSource>,
    ) -> Option<Self> {
        let mut sources = sources.into_iter().collect::<Vec<_>>();
        if sources.is_empty() {
            sources.push(SignatureCertificateSource::LocalInference);
        }
        sources.sort();
        sources.dedup();

        let source_authorizes_empty_arity = signature.params.is_empty()
            && sources.iter().any(|source| source.certifies_signature());
        let local_evidence_authorizes_inferred_arity = !signature.params.is_empty()
            && sources.iter().any(|source| {
                matches!(
                    source,
                    SignatureCertificateSource::LocalInference
                        | SignatureCertificateSource::CalleeSignature
                        | SignatureCertificateSource::SlotTypeOverride
                        | SignatureCertificateSource::SemanticProjection
                        | SignatureCertificateSource::SourceInterface
                )
            })
            && signature.params.iter().all(|param| param.ty.is_some());
        if !(signature.basis == SignatureBasis::Declared
            || source_authorizes_empty_arity
            || local_evidence_authorizes_inferred_arity)
        {
            return None;
        }

        Some(Self {
            signature: signature.clone(),
            sources,
        })
    }

    pub fn certifies_signature(&self) -> bool {
        signature_is_specific(&self.signature)
            && self
                .sources
                .iter()
                .any(|source| source.certifies_signature())
            && !self.signature.params.iter().any(|param| {
                signature_param_type_uncertified(
                    param.ty.as_ref(),
                    (self.sources).contains(&SignatureCertificateSource::ExternalContext),
                )
            })
    }

    pub fn authorizes_signature_render(&self) -> bool {
        signature_is_specific(&self.signature)
    }
}

fn signature_param_type_uncertified(ty: Option<&CTypeLike>, allow_void_pointer: bool) -> bool {
    if allow_void_pointer
        && matches!(
            ty,
            Some(CTypeLike::Pointer(inner)) if matches!(inner.as_ref(), CTypeLike::Void)
        )
    {
        return false;
    }
    is_generic_signature_type(ty)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureCertificateSource {
    ExternalContext,
    LocalInference,
    CalleeSignature,
    SlotTypeOverride,
    SummaryRole,
    SummaryKind,
    SemanticProjection,
    /// The return type alone is projected from the immutable source function
    /// interface and matched to exact native return-value certificates. This
    /// does not certify parameter types or certify a full signature by
    /// itself.
    SourceReturnType,
    /// The whole signature is projected from the immutable source function
    /// interface's type graph: every parameter and the return carry the exact
    /// declared type the binding layer already uses. radare2's spelled
    /// signature is only the fallback where no graph was captured.
    SourceInterface,
}

impl SignatureCertificateSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExternalContext => "external_context",
            Self::LocalInference => "local_inference",
            Self::CalleeSignature => "callee_signature",
            Self::SlotTypeOverride => "slot_type_override",
            Self::SummaryRole => "summary_role",
            Self::SummaryKind => "summary_kind",
            Self::SemanticProjection => "semantic_projection",
            Self::SourceReturnType => "source_return_type",
            Self::SourceInterface => "source_interface",
        }
    }

    /// Whether a declaration states the signature: a library's prototype for the name, or the
    /// source's own interface. Every other source infers it.
    pub fn is_declaration(self) -> bool {
        matches!(self, Self::ExternalContext | Self::SourceInterface)
    }

    pub fn certifies_signature(self) -> bool {
        matches!(
            self,
            Self::ExternalContext
                | Self::SourceInterface
                | Self::SlotTypeOverride
                | Self::SemanticProjection
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionParamSpec {
    /// `None` where the declaration names no parameter: DWARF states a `DW_TAG_formal_parameter`
    /// with or without `DW_AT_name`, and a printed signature spells the position.
    pub name: Option<String>,
    pub ty: Option<CTypeLike>,
}

/// What a signature's parameter list rests on: a declaration states its arity, inference does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureBasis {
    Declared,
    #[default]
    Inferred,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionSignatureSpec {
    pub ret_type: Option<CTypeLike>,
    pub params: Vec<FunctionParamSpec>,
    pub basis: SignatureBasis,
}

/// The record a parameter points to as its accesses lay it out (doc/adr-memory-places.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterRecord {
    pub tag: String,
    /// The member each accessed offset is, by its index in the definition's members.
    pub fields: BTreeMap<i64, usize>,
    /// Wider accesses spelled as a byte copy at the member at their offset.
    pub spans: std::collections::BTreeSet<(i64, u32)>,
    /// Accesses neither a member nor a span, with why; they keep their byte arithmetic.
    pub refused: Vec<(i64, u32, crate::SpanRefusal)>,
}

/// The records this function's parameters' accesses lay out (doc/adr-memory-places.md).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    /// Each record's definition, by tag.
    pub definitions: BTreeMap<String, crate::AggregateDefinition>,
    /// Each parameter that points to one: its tag, members, spans and refused accesses.
    pub parameters: BTreeMap<usize, ParameterRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeMemoryEffectKind {
    Read,
    Write,
    Escape,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeMemoryRegion {
    Arg { index: usize },
    Global { address: u64 },
    HeapReturn,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeMemoryRange {
    pub offset_lo: i64,
    pub offset_hi: i64,
    pub width: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeMemoryLocation {
    pub region: CalleeMemoryRegion,
    pub range: Option<CalleeMemoryRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeMemoryEffect {
    pub kind: CalleeMemoryEffectKind,
    pub location: CalleeMemoryLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeTransferLength {
    Arg(usize),
    Const(u64),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeTransferEffect {
    pub dst: CalleeMemoryLocation,
    pub src: CalleeMemoryLocation,
    pub len: CalleeTransferLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeAllocationEffect {
    pub size_arg: Option<usize>,
    pub zeroed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeLifetimeOp {
    Free,
    Retain,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeLifetimeEffect {
    pub arg: usize,
    pub op: CalleeLifetimeOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeSyncOp {
    Lock,
    Unlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeSyncEffect {
    pub arg: usize,
    pub op: CalleeSyncOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeAtomicOp {
    LoadLinked,
    StoreConditional,
    CompareExchange,
    ReadModifyWrite,
    Fence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeAtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalleeAtomicEffect {
    pub op: CalleeAtomicOp,
    pub location: CalleeMemoryLocation,
    pub ordering: CalleeAtomicOrdering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeReturnRelation {
    Unknown,
    Void,
    Arg(usize),
    Const(u64),
    HeapAlloc,
    Global(u64),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeLinkage {
    #[default]
    Unknown,
    Internal,
    Imported,
}

impl CalleeLinkage {
    pub fn authorizes_import_policy(self) -> bool {
        matches!(self, Self::Imported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeModelPolicyEvidence {
    InterprocSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalleeFact {
    pub function_id: u64,
    pub name: Option<String>,
    pub linkage: CalleeLinkage,
    pub signature: Option<FunctionType>,
    pub model_policy_evidence: BTreeSet<CalleeModelPolicyEvidence>,
    pub direct_callees: Vec<u64>,
    pub callsite_count: usize,
    pub has_unknown_calls: bool,
    pub memory_effects: Vec<CalleeMemoryEffect>,
    pub transfer_effects: Vec<CalleeTransferEffect>,
    pub allocation_effects: Vec<CalleeAllocationEffect>,
    pub lifetime_effects: Vec<CalleeLifetimeEffect>,
    pub sync_effects: Vec<CalleeSyncEffect>,
    pub atomic_effects: Vec<CalleeAtomicEffect>,
    pub return_relation: CalleeReturnRelation,
    pub reads_global_memory: bool,
    pub writes_global_memory: bool,
    pub touches_unknown_memory: bool,
}

pub(crate) const fn model_policy_authorized_from_evidence_count(evidence_count: usize) -> bool {
    evidence_count > 0
}

impl CalleeFact {
    /// A callee known only by its address, name and linkage: nothing about what it does.
    pub fn named(function_id: u64, name: Option<String>, linkage: CalleeLinkage) -> Self {
        Self {
            function_id,
            name,
            linkage,
            signature: None,
            model_policy_evidence: BTreeSet::new(),
            direct_callees: Vec::new(),
            callsite_count: 0,
            has_unknown_calls: false,
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: CalleeReturnRelation::Unknown,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        }
    }

    pub fn authorizes_model_policy(&self) -> bool {
        model_policy_authorized_from_evidence_count(self.model_policy_evidence.len())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterprocFactDiagnostics {
    pub iterations: usize,
    pub max_iterations: usize,
    pub converged: bool,
    pub scope_size: usize,
    pub scc_count: usize,
    pub max_scc_size: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionTypeFacts {
    pub merged_signature: Option<FunctionSignatureSpec>,
    /// What each parameter's type in the merged signature rests on, one row per convention slot
    /// (doc/adr-provenance.md, C2; D261).
    pub parameter_types: crate::ParameterTypes,
    /// The records this function's parameters' accesses lay out.
    pub records: Records,
    pub register_params: Vec<ExternalRegisterParamSpec>,
    pub callee_facts: BTreeMap<u64, CalleeFact>,
    pub program_data_objects: crate::ProgramDataObjectTypeFacts,
    pub field_access_certificates: Vec<FieldAccessCertificate>,
    pub array_index_certificates: Vec<ArrayIndexCertificate>,
    pub scalar_array_render_candidates: Vec<ScalarArrayRenderCandidate>,
    pub out_param_certificates: Vec<OutParamCertificate>,
    pub signature_certificate: Option<SignatureCertificate>,
    pub interproc_diagnostics: InterprocFactDiagnostics,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionTypeFactInputs {
    pub merged_signature: Option<FunctionSignatureSpec>,
    pub parameter_types: crate::ParameterTypes,
    pub records: Records,
    pub register_params: Vec<ExternalRegisterParamSpec>,
    pub callee_facts: BTreeMap<u64, CalleeFact>,
    pub program_data_objects: crate::ProgramDataObjectTypeFacts,
    pub field_access_certificates: Vec<FieldAccessCertificate>,
    pub array_index_certificates: Vec<ArrayIndexCertificate>,
    pub scalar_array_render_candidates: Vec<ScalarArrayRenderCandidate>,
    pub out_param_certificates: Vec<OutParamCertificate>,
    pub signature_certificate: Option<SignatureCertificate>,
    pub interproc_diagnostics: InterprocFactDiagnostics,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionTypeFactsBuilder {
    inputs: FunctionTypeFactInputs,
}

impl FunctionTypeFacts {
    pub fn is_empty(&self) -> bool {
        self.merged_signature.is_none()
            && self.register_params.is_empty()
            && self.callee_facts.is_empty()
            && self.program_data_objects == crate::ProgramDataObjectTypeFacts::default()
            && self.field_access_certificates.is_empty()
            && self.array_index_certificates.is_empty()
            && self.scalar_array_render_candidates.is_empty()
            && self.out_param_certificates.is_empty()
            && self.signature_certificate.is_none()
            && self.interproc_diagnostics == InterprocFactDiagnostics::default()
            && self.diagnostics.is_empty()
    }

    pub fn canonicalized(self) -> Self {
        FunctionTypeFacts::builder(FunctionTypeFactInputs {
            merged_signature: self.merged_signature,
            parameter_types: self.parameter_types,
            records: self.records,
            register_params: self.register_params,
            callee_facts: self.callee_facts,
            program_data_objects: self.program_data_objects,
            field_access_certificates: self.field_access_certificates,
            array_index_certificates: self.array_index_certificates,
            scalar_array_render_candidates: self.scalar_array_render_candidates,
            out_param_certificates: self.out_param_certificates,
            signature_certificate: self.signature_certificate,
            interproc_diagnostics: self.interproc_diagnostics,
            diagnostics: self.diagnostics,
        })
        .build()
    }

    pub fn builder(inputs: FunctionTypeFactInputs) -> FunctionTypeFactsBuilder {
        FunctionTypeFactsBuilder::new(inputs)
    }

    pub fn certify_current_signature_with_source(
        &mut self,
        source: SignatureCertificateSource,
    ) -> bool {
        let Some(signature) = self.merged_signature.as_ref() else {
            self.signature_certificate = None;
            return false;
        };
        let mut sources = self
            .signature_certificate
            .as_ref()
            .filter(|certificate| certificate.signature == *signature)
            .map(|certificate| certificate.sources.clone())
            .unwrap_or_default();
        if !sources.contains(&source) {
            sources.push(source);
        }
        self.signature_certificate = SignatureCertificate::from_signature(signature, sources);
        self.signature_certificate.is_some()
    }

    pub fn render_authorized_signature(&self) -> Option<&FunctionSignatureSpec> {
        let certificate = self.signature_certificate.as_ref()?;
        if !certificate.authorizes_signature_render() {
            return None;
        }
        let signature = self.merged_signature.as_ref()?;
        (certificate.signature == *signature).then_some(signature)
    }

    pub fn certified_signature(&self) -> Option<&FunctionSignatureSpec> {
        let certificate = self.signature_certificate.as_ref()?;
        if !certificate.certifies_signature() {
            return None;
        }
        let signature = self.merged_signature.as_ref()?;
        (certificate.signature == *signature).then_some(signature)
    }
}

/// The signature states a type, or names a parameter.
pub fn signature_is_specific(signature: &FunctionSignatureSpec) -> bool {
    signature.ret_type.is_some()
        || signature
            .params
            .iter()
            .any(|param| param.ty.is_some() || param.name.is_some())
}

pub fn is_generic_signature_type(ty: Option<&CTypeLike>) -> bool {
    match ty {
        None => true,
        Some(CTypeLike::Unknown | CTypeLike::Void) => true,
        Some(CTypeLike::Pointer(inner)) => {
            matches!(inner.as_ref(), CTypeLike::Unknown | CTypeLike::Void)
        }
        _ => false,
    }
}

pub fn signature_hint_can_replace_existing(
    existing: &CTypeLike,
    hint: Option<&CTypeLike>,
    ptr_bits: u32,
) -> bool {
    let existing = crate::word_free(existing);
    if is_generic_signature_type(Some(existing)) {
        return true;
    }
    let Some(hint) = hint else {
        return false;
    };
    if crate::signature_infer::signature_types_are_equivalent(existing, hint, ptr_bits) {
        return false;
    }
    match (existing, hint) {
        (
            CTypeLike::Int {
                bits,
                signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
            },
            CTypeLike::Typedef { name, ty },
        ) => {
            let normalized = name.trim().to_ascii_lowercase();
            crate::analysis::typedef_resolves(&normalized, ty)
                || matches!(normalized.as_str(), "int" | "unsigned int")
                || (normalized == "uintptr_t" && *bits == ptr_bits)
        }
        (
            CTypeLike::Int {
                signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
                ..
            },
            CTypeLike::Bool,
        ) => true,
        (
            CTypeLike::Int {
                signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
                ..
            },
            CTypeLike::Enum(_),
        ) => true,
        (
            CTypeLike::Int {
                bits,
                signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
            },
            CTypeLike::Pointer(_),
        ) => *bits == ptr_bits,
        (CTypeLike::Pointer(inner), CTypeLike::Pointer(new_inner)) => {
            matches!(inner.as_ref(), CTypeLike::Void | CTypeLike::Unknown)
                && !matches!(new_inner.as_ref(), CTypeLike::Void | CTypeLike::Unknown)
                || signature_hint_can_replace_existing(
                    inner.as_ref(),
                    Some(new_inner.as_ref()),
                    ptr_bits,
                )
                || (matches!(
                    (inner.as_ref(), new_inner.as_ref()),
                    (
                        CTypeLike::Int {
                            bits: 8,
                            signedness: _
                        },
                        CTypeLike::Int {
                            bits: 8,
                            signedness: _
                        }
                    )
                ) && !crate::signature_infer::signature_types_are_equivalent(
                    existing, hint, ptr_bits,
                ))
                || (matches!(
                    new_inner.as_ref(),
                    CTypeLike::Typedef { .. }
                        | CTypeLike::Struct(_)
                        | CTypeLike::Union(_)
                        | CTypeLike::Enum(_)
                ) && !matches!(
                    inner.as_ref(),
                    CTypeLike::Typedef { .. }
                        | CTypeLike::Struct(_)
                        | CTypeLike::Union(_)
                        | CTypeLike::Enum(_)
                ))
        }
        (
            CTypeLike::Typedef {
                name: existing_name,
                ..
            },
            CTypeLike::Typedef {
                name: hint_name,
                ty: hint_target,
            },
        ) => {
            is_weak_storage_scalar_typedef(existing_name, ptr_bits)
                && crate::analysis::typedef_resolves(hint_name, hint_target)
        }
        (
            CTypeLike::Typedef {
                name: existing_name,
                ..
            },
            CTypeLike::Pointer(_),
        ) => is_weak_pointer_sized_storage_typedef(existing_name, ptr_bits),
        _ => false,
    }
}

pub fn is_weak_storage_scalar_type(ty: &CTypeLike, ptr_bits: u32) -> bool {
    match crate::word_free(ty) {
        CTypeLike::Int { .. } => true,
        CTypeLike::Typedef { name, .. } => is_weak_storage_scalar_typedef(name, ptr_bits),
        _ => false,
    }
}

pub fn is_weak_storage_scalar_typedef(name: &str, ptr_bits: u32) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "unsigned short"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
    ) || (ptr_bits == 64
        && matches!(
            normalized.as_str(),
            "long" | "unsigned long" | "int64_t" | "uint64_t"
        ))
}

pub fn is_weak_pointer_sized_storage_typedef(name: &str, ptr_bits: u32) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    (ptr_bits == 64
        && matches!(
            normalized.as_str(),
            "long" | "unsigned long" | "int64_t" | "uint64_t"
        ))
        || (ptr_bits == 32
            && matches!(
                normalized.as_str(),
                "int" | "unsigned" | "unsigned int" | "int32_t" | "uint32_t"
            ))
}

impl FunctionTypeFactsBuilder {
    pub fn new(inputs: FunctionTypeFactInputs) -> Self {
        Self { inputs }
    }

    pub fn build(mut self) -> FunctionTypeFacts {
        let mut field_access_certificates =
            std::mem::take(&mut self.inputs.field_access_certificates);
        field_access_certificates.sort();
        field_access_certificates.dedup();
        let mut array_index_certificates =
            std::mem::take(&mut self.inputs.array_index_certificates);
        array_index_certificates.sort();
        array_index_certificates.dedup();
        let mut scalar_array_render_candidates =
            std::mem::take(&mut self.inputs.scalar_array_render_candidates);
        scalar_array_render_candidates.sort();
        scalar_array_render_candidates.dedup();
        let mut out_param_certificates = std::mem::take(&mut self.inputs.out_param_certificates);
        out_param_certificates.retain(OutParamCertificate::has_source_identity);
        out_param_certificates.sort();
        out_param_certificates.dedup();

        let FunctionTypeFactInputs {
            merged_signature,
            parameter_types,
            records,
            register_params,
            callee_facts,
            program_data_objects,
            signature_certificate,
            interproc_diagnostics,
            diagnostics,
            ..
        } = self.inputs;

        let mut diagnostics = diagnostics;
        dedup_preserving_order(&mut diagnostics);

        FunctionTypeFacts {
            merged_signature,
            parameter_types,
            records,
            register_params,
            callee_facts,
            program_data_objects,
            field_access_certificates,
            array_index_certificates,
            scalar_array_render_candidates,
            out_param_certificates,
            signature_certificate,
            interproc_diagnostics,
            diagnostics,
        }
    }
}

fn dedup_preserving_order(items: &mut Vec<String>) {
    let mut seen = rustc_hash::FxHashSet::default();
    items.retain(|item| seen.insert(item.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_int(bits: u32) -> CTypeLike {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Signed,
        }
    }

    fn test_param(name: &str, ty: CTypeLike) -> FunctionParamSpec {
        FunctionParamSpec {
            name: Some(name.to_string()),
            ty: Some(ty),
        }
    }

    fn unnamed_param(ty: CTypeLike) -> FunctionParamSpec {
        FunctionParamSpec {
            name: None,
            ty: Some(ty),
        }
    }

    fn exact_signature() -> FunctionSignatureSpec {
        FunctionSignatureSpec {
            ret_type: Some(test_int(32)),
            params: vec![test_param("value", test_int(32))],
            basis: SignatureBasis::Declared,
        }
    }

    #[test]
    fn local_only_signature_certificate_does_not_certify_the_signature() {
        let certificate = SignatureCertificate::from_signature(
            &exact_signature(),
            [SignatureCertificateSource::LocalInference],
        )
        .expect("exact local signature should still be recorded as a certificate");

        assert!(
            !certificate.certifies_signature(),
            "local inference alone is not enough evidence to mutate radare2 signature state"
        );
    }

    #[test]
    fn source_return_type_certificate_does_not_certify_a_parameter() {
        let certificate = SignatureCertificate::from_signature(
            &exact_signature(),
            [SignatureCertificateSource::SourceReturnType],
        )
        .expect("an exact return projection should remain renderable");

        assert!(certificate.authorizes_signature_render());
        assert!(!certificate.certifies_signature());
        assert_eq!(
            SignatureCertificateSource::SourceReturnType.as_str(),
            "source_return_type"
        );
    }

    #[test]
    fn local_inference_certifies_typed_generic_parameter_names_for_rendering() {
        let signature = FunctionSignatureSpec {
            ret_type: Some(test_int(32)),
            params: vec![unnamed_param(test_int(64)), unnamed_param(test_int(32))],
            basis: SignatureBasis::Inferred,
        };
        let certificate = SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::LocalInference],
        )
        .expect("SSA-proven typed parameters should certify rendering");

        assert!(certificate.authorizes_signature_render());
        assert!(!certificate.certifies_signature());
    }

    #[test]
    fn external_signature_certificate_certifies_the_signature() {
        let certificate = SignatureCertificate::from_signature(
            &exact_signature(),
            [SignatureCertificateSource::ExternalContext],
        )
        .expect("exact external signature should be certifiable");

        assert!(
            certificate.certifies_signature(),
            "external typed context is authoritative signature evidence"
        );
    }

    #[test]
    fn external_empty_signature_certificate_authorizes_exact_empty_arity() {
        let signature = FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Void),
            params: Vec::new(),
            basis: SignatureBasis::Inferred,
        };
        let certificate = SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::ExternalContext],
        )
        .expect("external void(void) signature should certify exact empty arity");

        assert!(certificate.certifies_signature());
        assert!(certificate.signature.params.is_empty());
    }

    #[test]
    fn external_void_pointer_params_are_certifiable_context_types() {
        let signature = FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Void),
            params: vec![FunctionParamSpec {
                name: Some("dst".to_string()),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
            }],
            basis: SignatureBasis::Declared,
        };
        let certificate = SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::ExternalContext],
        )
        .expect("external void pointer parameters are explicit C types");

        assert!(certificate.certifies_signature());
    }

    #[test]
    fn external_name_only_signature_authorizes_render_not_the_signature() {
        let signature = FunctionSignatureSpec {
            ret_type: None,
            params: vec![FunctionParamSpec {
                name: Some("count".to_string()),
                ty: None,
            }],
            basis: SignatureBasis::Declared,
        };
        let certificate = SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::ExternalContext],
        )
        .expect("external name and arity evidence should be renderable");

        assert!(certificate.authorizes_signature_render());
        assert!(
            !certificate.certifies_signature(),
            "incomplete parameter types must not mutate radare2 signature state"
        );
    }

    #[test]
    fn current_signature_certification_preserves_and_adds_sources() {
        let mut facts = FunctionTypeFacts {
            merged_signature: Some(exact_signature()),
            signature_certificate: SignatureCertificate::from_signature(
                &exact_signature(),
                [SignatureCertificateSource::ExternalContext],
            ),
            ..FunctionTypeFacts::default()
        };

        assert!(
            facts.certify_current_signature_with_source(
                SignatureCertificateSource::SemanticProjection
            )
        );
        let certificate = facts
            .signature_certificate
            .expect("current signature should remain certified");

        assert_eq!(
            certificate.sources,
            vec![
                SignatureCertificateSource::ExternalContext,
                SignatureCertificateSource::SemanticProjection,
            ]
        );
    }

    #[test]
    fn render_authorized_signature_requires_matching_certificate() {
        let signature = exact_signature();
        let different_signature = FunctionSignatureSpec {
            ret_type: Some(test_int(32)),
            params: vec![test_param("other", test_int(32))],
            basis: SignatureBasis::Declared,
        };
        let facts = FunctionTypeFacts {
            merged_signature: Some(signature),
            signature_certificate: SignatureCertificate::from_signature(
                &different_signature,
                [SignatureCertificateSource::ExternalContext],
            ),
            ..FunctionTypeFacts::default()
        };

        assert!(
            facts.render_authorized_signature().is_none(),
            "consumers must not render a merged signature that is not the certified signature"
        );
    }

    #[test]
    fn render_authorized_signature_returns_certified_current_signature() {
        let signature = exact_signature();
        let facts = FunctionTypeFacts {
            merged_signature: Some(signature.clone()),
            signature_certificate: SignatureCertificate::from_signature(
                &signature,
                [SignatureCertificateSource::ExternalContext],
            ),
            ..FunctionTypeFacts::default()
        };

        assert_eq!(facts.render_authorized_signature(), Some(&signature));
    }

    #[test]
    fn certified_signature_rejects_render_only_certificate() {
        let signature = FunctionSignatureSpec {
            ret_type: None,
            params: vec![FunctionParamSpec {
                name: Some("count".to_string()),
                ty: None,
            }],
            basis: SignatureBasis::Declared,
        };
        let facts = FunctionTypeFacts {
            merged_signature: Some(signature),
            signature_certificate: SignatureCertificate::from_signature(
                &FunctionSignatureSpec {
                    ret_type: None,
                    params: vec![FunctionParamSpec {
                        name: Some("count".to_string()),
                        ty: None,
                    }],
                    basis: SignatureBasis::Declared,
                },
                [SignatureCertificateSource::ExternalContext],
            ),
            ..FunctionTypeFacts::default()
        };

        assert!(facts.render_authorized_signature().is_some());
        assert!(facts.certified_signature().is_none());
    }

    #[test]
    fn builder_keeps_an_unnamed_parameter_unnamed() {
        let signature = FunctionSignatureSpec {
            ret_type: Some(test_int(32)),
            params: vec![unnamed_param(test_int(64)), unnamed_param(test_int(32))],
            basis: SignatureBasis::Inferred,
        };
        let certificate = SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::LocalInference],
        );
        let facts = FunctionTypeFacts::builder(FunctionTypeFactInputs {
            merged_signature: Some(signature),
            signature_certificate: certificate,
            ..FunctionTypeFactInputs::default()
        })
        .build();

        let signature = facts.render_authorized_signature().expect("signature");
        assert!(signature.params.iter().all(|param| param.name.is_none()));
    }

    /// A declaration states its arity whatever it calls a parameter, `arg1` included; inference
    /// states none, however it names one (D480).
    #[test]
    fn a_declared_parameter_spelled_like_a_position_is_authoritative() {
        let untyped = |name: Option<&str>, basis| FunctionSignatureSpec {
            ret_type: Some(test_int(64)),
            params: vec![FunctionParamSpec {
                name: name.map(str::to_string),
                ty: None,
            }],
            basis,
        };
        let external = [SignatureCertificateSource::ExternalContext];
        for name in [Some("arg1"), None] {
            let declared = untyped(name, SignatureBasis::Declared);
            assert!(SignatureCertificate::from_signature(&declared, external).is_some());
        }
        let inferred = untyped(Some("value"), SignatureBasis::Inferred);
        assert!(SignatureCertificate::from_signature(&inferred, external).is_none());
    }
}
