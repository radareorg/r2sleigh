//! What more than one of these asks.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeFactSource {
    LocalInferred,
    CalleeSignature,
    SignatureRegistry,
    ExistingState,
    ExternalTypeDb,
    DataflowRanked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeEvidence {
    SsaVarRecovery,
    CertifiedCallArgument,
    CanonicalStackAccessWidth,
    CanonicalStackSignedness,
    ExternalSignatureCurrent,
    CanonicalMainSignature,
    SsaFieldOffsetPattern,
    ExistingStackType,
    ExternalStackAnnotation,
    ExternalStackName,
    ExternalParamName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructDeclSource {
    LocalInferred,
    ExternalTypeDb,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InferredSignatureParam {
    pub name: String,
    pub param_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferredSignature {
    pub function_name: String,
    pub signature: String,
    pub ret_type: String,
    pub params: Vec<InferredSignatureParam>,
    pub callconv: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RecoveredVariable {
    pub name: String,
    pub kind: String,
    pub delta: i64,
    #[serde(rename = "type")]
    pub var_type: String,
    pub isarg: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reg: Option<String>,
}

impl RecoveredVariable {
    /// The recovered type, parsed once with the canonical parser.
    ///
    /// The spelling is radare2's, so it stays a `String` on the wire -- this is
    /// what radare2 told us, not something we decided. What should not happen
    /// is each consumer taking the spelling apart its own way, which is how one
    /// of them came to test for a pointer with `contains('*')`.
    pub fn recovered_type(&self, ptr_bits: u32) -> Option<CTypeLike> {
        parse_c_type_like(&self.var_type, ptr_bits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructFieldCandidate {
    pub name: String,
    pub offset: u64,
    /// The field's type, as a type.
    pub field_type: CTypeLike,
    pub confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructDeclCandidate {
    pub name: String,
    pub decl: String,
    pub confidence: u8,
    pub source: StructDeclSource,
    pub fields: Vec<StructFieldCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VarTypeCandidate {
    pub name: String,
    pub kind: String,
    pub delta: i64,
    /// The type this variable is being given, as a type.
    ///
    /// Rendered only where it leaves for radare2 or a JSON payload.
    pub var_type: CTypeLike,
    pub isarg: bool,
    pub reg: Option<String>,
    pub size: u32,
    pub confidence: u8,
    pub source: TypeFactSource,
    pub evidence: Vec<TypeEvidence>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TypeAnalysisDiagnostics {
    pub conflicts: Vec<String>,
    pub warnings: Vec<String>,
    pub solver_warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Advisory local-inference report.
///
/// This detached projection is not certificate authority. Authoritative
/// the analysis derives it internally from a retained [`SsaArtifact`] owner.
pub(crate) struct LocalStructArtifacts {
    pub struct_decls: Vec<StructDeclCandidate>,
    pub slot_type_overrides: HashMap<usize, String>,
    pub slot_field_profiles: HashMap<usize, BTreeMap<u64, String>>,
    pub slot_element_strides: HashMap<usize, u64>,
    pub indexed_accesses: Vec<ScalarArrayRenderCandidate>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SemanticTypeProjection {
    pub(crate) return_type_hint: Option<CTypeLike>,
    pub(crate) pointer_param_indices: BTreeSet<usize>,
    pub(crate) out_param_indices: BTreeSet<usize>,
    pub(crate) out_param_evidence: BTreeMap<usize, BTreeSet<OutParamCertificateEvidence>>,
    pub(crate) out_param_sources: BTreeMap<usize, BTreeSet<OutParamCertificateSource>>,
    pub(crate) param_type_hints: BTreeMap<usize, CTypeLike>,
    pub(crate) param_name_hints: BTreeMap<usize, String>,
    pub(crate) slot_field_profiles: BTreeMap<usize, BTreeMap<u64, String>>,
    pub(crate) refused_param_projections: BTreeMap<usize, String>,
}

/// What the interprocedural summary proves about this function's parameters.
///
/// This was `SemanticTypeProjection` built from a symbolic artifact as well as
/// from the summary. The artifact is gone; the summary's own arg, memory,
/// transfer, lifetime and sync effects are what remain, and they are r2ssa
/// facts rather than symbolic ones.
impl SemanticTypeProjection {
    pub(crate) fn from_inputs(summary_view: &InterprocSummaryView) -> Self {
        let mut projection = Self::default();
        if let Some(summary) = summary_view.root_summary() {
            for idx in 0..=summary.arg_effects.keys().copied().max().unwrap_or(0) {
                if summary_suggests_pointer_param(summary, idx) {
                    projection.pointer_param_indices.insert(idx);
                }
            }
            for (effect_index, (idx, effect)) in summary.arg_effects.iter().enumerate() {
                if effect.write {
                    mark_projection_out_param(
                        &mut projection,
                        *idx,
                        OutParamCertificateEvidence::InterprocArgWrite,
                        interproc_out_param_source(
                            summary,
                            OutParamCertificateEvidence::InterprocArgWrite,
                            *idx,
                            effect_index,
                        ),
                    );
                }
            }
            for (effect_index, effect) in summary.memory_effects.iter().enumerate() {
                if effect.kind == r2ssa::SummaryMemoryEffectKind::Write
                    && let r2ssa::SummaryMemoryRegion::Arg { index } = effect.location.region
                {
                    projection.pointer_param_indices.insert(index);
                    mark_projection_out_param(
                        &mut projection,
                        index,
                        OutParamCertificateEvidence::InterprocMemoryWrite,
                        interproc_out_param_source(
                            summary,
                            OutParamCertificateEvidence::InterprocMemoryWrite,
                            index,
                            effect_index,
                        ),
                    );
                }
            }
            for (effect_index, effect) in summary.transfer_effects.iter().enumerate() {
                if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.dst.region {
                    projection.pointer_param_indices.insert(index);
                    mark_projection_out_param(
                        &mut projection,
                        index,
                        OutParamCertificateEvidence::InterprocTransferDst,
                        interproc_out_param_source(
                            summary,
                            OutParamCertificateEvidence::InterprocTransferDst,
                            index,
                            effect_index,
                        ),
                    );
                }
                if let r2ssa::SummaryMemoryRegion::Arg { index } = effect.src.region {
                    projection.pointer_param_indices.insert(index);
                }
            }
            for effect in &summary.lifetime_effects {
                projection.pointer_param_indices.insert(effect.arg);
            }
            for effect in &summary.sync_effects {
                projection.pointer_param_indices.insert(effect.arg);
            }
        }
        projection
    }

    pub(crate) fn corroborates_param_type_hint(&self, index: usize, hint: &CTypeLike) -> bool {
        if self
            .param_type_hints
            .get(&index)
            .is_some_and(|semantic_hint| semantic_hints_compatible(semantic_hint, hint))
        {
            return true;
        }
        if !matches!(hint, CTypeLike::Pointer(_)) {
            return false;
        }
        self.pointer_param_indices.contains(&index)
            || self.out_param_indices.contains(&index)
            || self.slot_field_profiles.contains_key(&index)
    }

    pub(crate) fn corroborates_stack_slot_type_hint(&self, slot: usize, hint: &CTypeLike) -> bool {
        matches!(hint, CTypeLike::Pointer(_)) && self.slot_field_profiles.contains_key(&slot)
    }

    pub(crate) fn refusal_warnings(&self) -> Vec<String> {
        self.refused_param_projections
            .iter()
            .map(|(idx, reason)| format!("semantic type projection refused arg{idx}: {reason}"))
            .collect()
    }
}

pub(crate) fn c_int_type() -> CTypeLike {
    typedef_type("int")
}

pub(crate) fn c_uint_type() -> CTypeLike {
    typedef_type("unsigned int")
}

pub(crate) fn typedef_type(name: &str) -> CTypeLike {
    CTypeLike::typedef(name)
}

pub(crate) fn mark_projection_out_param(
    projection: &mut SemanticTypeProjection,
    index: usize,
    evidence: OutParamCertificateEvidence,
    source: OutParamCertificateSource,
) {
    projection.out_param_indices.insert(index);
    projection
        .out_param_evidence
        .entry(index)
        .or_default()
        .insert(evidence);
    projection
        .out_param_sources
        .entry(index)
        .or_default()
        .insert(source);
    projection.refused_param_projections.remove(&index);
}

pub(crate) fn interproc_out_param_source(
    summary: &FunctionSemanticSummary,
    evidence: OutParamCertificateEvidence,
    param_index: usize,
    effect_index: usize,
) -> OutParamCertificateSource {
    OutParamCertificateSource::InterprocSummaryEffect {
        function_id: summary.id.0,
        evidence,
        param_index,
        effect_index,
    }
}

pub(crate) fn semantic_hints_compatible(
    semantic_hint: &CTypeLike,
    requested_hint: &CTypeLike,
) -> bool {
    if semantic_hint == requested_hint {
        return true;
    }
    matches!(
        (semantic_hint, requested_hint),
        (CTypeLike::Pointer(_), CTypeLike::Pointer(_))
            | (
                CTypeLike::Int {
                    signedness: Signedness::Unsigned,
                    ..
                },
                CTypeLike::Int { .. }
            )
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecoveredVarKey {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) delta: i64,
    pub(crate) isarg: bool,
    pub(crate) reg: Option<String>,
}

impl RecoveredVarKey {
    fn new(name: &str, kind: &str, delta: i64, isarg: bool, reg: Option<&str>) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
            kind: kind.to_ascii_lowercase(),
            delta,
            isarg,
            reg: reg.map(str::to_ascii_lowercase),
        }
    }

    pub(crate) fn for_recovered_var(var: &RecoveredVariable) -> Self {
        Self::new(
            &var.name,
            &var.kind,
            var.delta,
            var.isarg,
            var.reg.as_deref(),
        )
    }

    pub(crate) fn for_type_candidate(candidate: &VarTypeCandidate) -> Self {
        Self::new(
            &candidate.name,
            &candidate.kind,
            candidate.delta,
            candidate.isarg,
            candidate.reg.as_deref(),
        )
    }
}

pub(crate) fn summary_suggests_pointer_param(
    summary: &FunctionSemanticSummary,
    idx: usize,
) -> bool {
    summary
        .arg_effects
        .get(&idx)
        .is_some_and(|effect| effect.read || effect.write || effect.escape || effect.free)
        || summary.memory_effects.iter().any(|effect| {
            matches!(effect.location.region, SummaryMemoryRegion::Arg { index } if index == idx)
        })
        || summary.transfer_effects.iter().any(|effect| {
            matches!(effect.dst.region, r2ssa::SummaryMemoryRegion::Arg { index } if index == idx)
                || matches!(effect.src.region, r2ssa::SummaryMemoryRegion::Arg { index } if index == idx)
        })
        || summary
            .lifetime_effects
            .iter()
            .any(|effect| effect.arg == idx)
        || summary.sync_effects.iter().any(|effect| effect.arg == idx)
}

pub(crate) fn exact_ssa_const_offset(var: &SSAVar, ptr_bits: u32) -> Option<i64> {
    Some(signed_offset_from_const(var.constant_bits()?, ptr_bits))
}

pub(crate) fn aggregate_lookup_keys(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |candidate: &str| {
        let key = candidate.trim().to_ascii_lowercase();
        if !key.is_empty() && !out.contains(&key) {
            out.push(key);
        }
    };

    let trimmed = name.trim();
    push(trimmed);
    for prefix in ["struct ", "union ", "enum "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            push(rest);
        }
    }

    let normalized = normalize_external_type_name(trimmed);
    if normalized != "void *" {
        push(&normalized);
        for prefix in ["struct ", "union ", "enum "] {
            if let Some(rest) = normalized.strip_prefix(prefix) {
                push(rest);
            }
        }
    }

    out
}

pub(crate) fn parse_signature_type_preserving_c_typedefs(
    ty: &str,
    ptr_bits: u32,
) -> Option<CTypeLike> {
    match normalize_external_type_name(ty)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "int" => Some(c_int_type()),
        "unsigned int" => Some(c_uint_type()),
        "short" | "short int" => Some(typedef_type("short")),
        "unsigned short" | "unsigned short int" => Some(typedef_type("unsigned short")),
        "long" | "long int" => Some(typedef_type("long")),
        "unsigned long" | "unsigned long int" => Some(typedef_type("unsigned long")),
        "size_t" => Some(typedef_type("size_t")),
        "ssize_t" => Some(typedef_type("ssize_t")),
        "ptrdiff_t" => Some(typedef_type("ptrdiff_t")),
        "uintptr_t" => Some(typedef_type("uintptr_t")),
        "intptr_t" => Some(typedef_type("intptr_t")),
        _ => parse_c_type_like(ty, ptr_bits),
    }
}

pub(crate) fn inferred_signature_to_spec(
    signature: &InferredSignature,
    ptr_bits: u32,
) -> Option<FunctionSignatureSpec> {
    let ret_type = parse_signature_type_preserving_c_typedefs(&signature.ret_type, ptr_bits);
    let params = signature
        .params
        .iter()
        .map(|param| FunctionParamSpec {
            name: param.name.clone(),
            ty: parse_signature_type_preserving_c_typedefs(&param.param_type, ptr_bits),
        })
        .collect::<Vec<_>>();
    if ret_type.is_none() && params.iter().all(|param| param.ty.is_none()) {
        return None;
    }
    Some(FunctionSignatureSpec { ret_type, params })
}

pub(crate) fn stack_base_for_recovered_var_kind(kind: &str) -> Option<ExternalStackBase> {
    match kind {
        "b" => Some(ExternalStackBase::FramePointer),
        "s" => Some(ExternalStackBase::StackPointer),
        _ => None,
    }
}

pub(crate) fn stack_slot_key_for_recovered_var(var: &RecoveredVariable) -> Option<StackSlotKey> {
    Some(StackSlotKey {
        base: stack_base_for_recovered_var_kind(&var.kind)?,
        offset: var.delta,
    })
}

pub(crate) fn is_generic_signature_type(ty: Option<&CTypeLike>) -> bool {
    crate::is_generic_signature_type(ty)
}

pub(crate) fn indexed_local_struct_refinement_slots(
    local_structs: &LocalStructArtifacts,
    signature_sources: &[SignatureCertificateSource],
    type_assumption_parameter_slots: &HashSet<usize>,
) -> HashSet<usize> {
    if signature_sources.is_empty()
        || signature_sources.iter().any(|source| {
            !matches!(
                source,
                SignatureCertificateSource::LocalInference
                    | SignatureCertificateSource::TypeAssumption
                    | SignatureCertificateSource::SlotTypeOverride
            )
        })
    {
        return HashSet::new();
    }
    local_structs
        .slot_element_strides
        .keys()
        .filter(|slot| !type_assumption_parameter_slots.contains(slot))
        .copied()
        .collect()
}

pub(crate) fn override_type_is_generated_local_struct(raw_ty: &str, ptr_bits: u32) -> bool {
    generated_local_struct_name_from_override(raw_ty, ptr_bits).is_some()
}

pub(crate) fn generated_local_struct_name_from_override(
    raw_ty: &str,
    ptr_bits: u32,
) -> Option<String> {
    if let Some(name) = parse_struct_ptr_type_name(raw_ty)
        && is_generated_local_struct_name(&name)
    {
        return Some(name);
    }
    let Some(CTypeLike::Pointer(inner)) = parse_c_type_like(raw_ty, ptr_bits) else {
        return None;
    };
    match inner.as_ref() {
        CTypeLike::Struct(name) | CTypeLike::Typedef { name, .. }
            if is_generated_local_struct_name(name) =>
        {
            Some(name.clone())
        }
        _ => None,
    }
}

/// Whether a type name denotes something we can actually resolve.
///
/// This replaces `role_registry::semantic_typedef_is_authoritative`, a
/// hardcoded list of about two hundred spellings -- most of them private to GNU
/// coreutils and gnulib -- which decided whether a typedef was concrete enough
/// to keep rather than replace. A name on the list was authoritative for every
/// binary and a name off it for none, whatever the binary actually said.
///
/// The question is answerable from evidence. A name resolves if the C language
/// resolves it, which `parse_c_type_like` already answers for the builtin and
/// stdint spellings; or if the external type database holds a real layout for
/// it; or if the database holds a typedef entry that eventually names one.
/// Unlike the list, that says the same thing about a coreutils typedef and
/// about anybody else's, and it says it from what the binary carries.
pub(crate) fn type_db_resolves_type_name(
    type_db: &ExternalTypeDb,
    name: &str,
    ptr_bits: u32,
) -> bool {
    // Typedefs this decompiler mints itself. These are resolvable because we
    // define them in the emitted prelude, not because some binary declared
    // them, so no evidence from the binary is required or possible.
    if matches!(name.trim(), "allocation_ptr" | "memory_ptr") {
        return true;
    }
    if parse_c_type_like(name, ptr_bits).is_some_and(|ty| !matches!(ty, CTypeLike::Typedef { .. }))
    {
        return true;
    }
    if external_named_aggregate_has_real_layout(type_db, name) {
        return true;
    }
    aggregate_lookup_keys(name)
        .iter()
        .any(|key| type_db.typedefs.contains_key(key))
}

pub(crate) fn external_named_aggregate_has_real_layout(
    type_db: &ExternalTypeDb,
    name: &str,
) -> bool {
    let mut keys = aggregate_lookup_keys(name);
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        for key in &keys {
            if type_db
                .structs
                .get(key)
                .is_some_and(|st| !st.fields.is_empty())
            {
                return true;
            }
            if type_db
                .unions
                .get(key)
                .is_some_and(|un| !un.fields.is_empty())
            {
                return true;
            }
            if type_db
                .enums
                .get(key)
                .is_some_and(|en| !en.variants.is_empty())
            {
                return true;
            }
        }

        let Some(typedef) = keys.iter().find_map(|key| type_db.typedefs.get(key)) else {
            return false;
        };
        let typedef_key = typedef.name.to_ascii_lowercase();
        if !seen.insert(typedef_key) {
            return false;
        }
        keys = aggregate_lookup_keys(&typedef.target);
    }
    false
}

pub(crate) fn signature_param_blocks_generated_local_struct_override(
    param: Option<&FunctionParamSpec>,
    raw_ty: &str,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> bool {
    if !override_type_is_generated_local_struct(raw_ty, ptr_bits) {
        return false;
    }
    let Some(param) = param else {
        return false;
    };
    if is_generic_signature_type(param.ty.as_ref()) {
        return false;
    }
    let Some(ty) = param.ty.as_ref() else {
        return false;
    };
    match ty {
        CTypeLike::Pointer(inner) => match inner.as_ref() {
            CTypeLike::Unknown | CTypeLike::Void => false,
            CTypeLike::Struct(name) => external_named_aggregate_has_real_layout(type_db, name),
            CTypeLike::Typedef { name, .. } => {
                type_db_resolves_type_name(type_db, name, ptr_bits)
                    || external_named_aggregate_has_real_layout(type_db, name)
            }
            CTypeLike::Union(_) | CTypeLike::Enum(_) => true,
            _ => true,
        },
        CTypeLike::Int { bits, .. } if *bits == ptr_bits && is_generic_arg_name(&param.name) => {
            false
        }
        _ => true,
    }
}

pub(crate) fn parse_struct_ptr_type_name(ty: &str) -> Option<String> {
    ty.trim()
        .strip_prefix("struct ")
        .and_then(|rest| rest.strip_suffix(" *"))
        .map(str::to_string)
}

pub(crate) fn estimate_c_type_size_bytes(ty: &str, ptr_bits: u32) -> u64 {
    if let Some(parsed) = parse_c_type_like(ty, ptr_bits)
        && let Some(size) = estimate_type_like_size_bytes(&parsed, ptr_bits)
        && size > 0
    {
        return size;
    }

    let lower = normalize_external_type_name(ty).trim().to_ascii_lowercase();
    if lower.contains('*') {
        return (ptr_bits / 8).max(1) as u64;
    }
    if lower == "double" || lower == "long double" {
        return 8;
    }
    1
}

pub(crate) fn estimate_type_like_size_bytes(ty: &CTypeLike, ptr_bits: u32) -> Option<u64> {
    match ty {
        CTypeLike::Const(inner) => estimate_type_like_size_bytes(inner, ptr_bits),
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => None,
        CTypeLike::Bool => Some(1),
        CTypeLike::Int { bits, .. } | CTypeLike::Float(bits) => {
            Some((u64::from(*bits).saturating_add(7) / 8).max(1))
        }
        CTypeLike::Pointer(_) => Some((ptr_bits / 8).max(1) as u64),
        CTypeLike::Array(inner, Some(count)) => estimate_type_like_size_bytes(inner, ptr_bits)
            .map(|inner_size| inner_size.saturating_mul(*count as u64)),
        CTypeLike::Array(inner, None) => estimate_type_like_size_bytes(inner, ptr_bits),
        CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_)
        | CTypeLike::Typedef { .. } => None,
    }
}

pub(crate) fn render_signature_type(ty: &CTypeLike, ptr_bits: u32) -> String {
    crate::render_signature_type(ty, ptr_bits)
}

pub(crate) fn type_name_is_opaque_placeholder(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let stripped = lower
        .trim_start_matches("struct ")
        .trim_start_matches("union ")
        .trim_start_matches("enum ")
        .trim_end_matches('*')
        .trim_end();
    stripped.starts_with("anon_") || stripped.starts_with("type_0x") || lower.contains(" type_0x")
}

pub(crate) fn is_generated_local_struct_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .trim_start_matches("struct ")
        .starts_with("sla_struct_")
}

pub(crate) fn type_name_is_generic(ty: &str) -> bool {
    let normalized = normalize_external_type_name(ty);
    let lower = normalized.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    if lower.starts_with("byte[") {
        return true;
    }
    if type_name_is_opaque_placeholder(&lower) {
        return true;
    }
    matches!(
        lower.as_str(),
        "void *"
            | "void*"
            | "char *"
            | "char*"
            | "const char *"
            | "const char*"
            | "signed char *"
            | "signed char*"
            | "unsigned char *"
            | "unsigned char*"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
    )
}

pub(crate) fn is_low_quality_stack_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("var_")
        || lower.starts_with("local_")
        || lower.starts_with("stack_")
        || lower == "saved_fp"
        || is_generic_arg_name(&lower)
}

pub(crate) fn size_to_type(size: u32) -> String {
    match size {
        1 => "int8_t".to_string(),
        2 => "int16_t".to_string(),
        4 => "int32_t".to_string(),
        8 => "int64_t".to_string(),
        _ => format!("byte[{size}]"),
    }
}

pub(crate) fn size_to_unsigned_type(size: u32) -> String {
    match size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        _ => format!("byte[{size}]"),
    }
}

pub(crate) fn signed_offset_from_const(raw: u64, ptr_bits: u32) -> i64 {
    let bits = ptr_bits.clamp(8, 64);
    if bits == 64 {
        return raw as i64;
    }
    let mask = (1u64 << bits) - 1;
    let sign = 1u64 << (bits - 1);
    let v = raw & mask;
    if (v & sign) != 0 {
        (v | (!mask)) as i64
    } else {
        v as i64
    }
}
