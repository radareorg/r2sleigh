//! What more than one of these asks.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InferredSignatureParam {
    pub name: String,
    pub ty: CTypeLike,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferredSignature {
    pub function_name: String,
    /// `None` until something decides the result.
    pub ret_type: Option<CTypeLike>,
    pub params: Vec<InferredSignatureParam>,
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
    /// Each slot's pointee aggregate size in bytes, read from the interface graph by type id (D345).
    pub pointee_strides: Vec<Option<u64>>,
    /// The member certificates r2ssa's projection states; the only member names (D345).
    pub source_fields: Vec<crate::FieldAccessCertificate>,
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

#[doc(alias = "default_deny_pointer")]
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

/// An inferred type with C's own integer names kept as names, so a declared
/// `int` or `size_t` is not mistaken for a width the body can refine.
pub(crate) fn preserving_c_typedefs(ty: &CTypeLike) -> CTypeLike {
    let CTypeLike::Typedef { name, ty: target } = ty else {
        return ty.clone();
    };
    match name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .as_str()
    {
        "int" => c_int_type(),
        "unsigned int" => c_uint_type(),
        "short" | "short int" => typedef_type("short"),
        "unsigned short" | "unsigned short int" => typedef_type("unsigned short"),
        "long" | "long int" => typedef_type("long"),
        "unsigned long" | "unsigned long int" => typedef_type("unsigned long"),
        name @ ("size_t" | "ssize_t" | "ptrdiff_t" | "uintptr_t" | "intptr_t") => {
            CTypeLike::named(name, target.unaliased().clone())
        }
        _ => ty.clone(),
    }
}

pub(crate) fn inferred_signature_to_spec(
    signature: &InferredSignature,
) -> Option<FunctionSignatureSpec> {
    let ret_type = signature.ret_type.as_ref().map(preserving_c_typedefs);
    let params = signature
        .params
        .iter()
        .map(|param| FunctionParamSpec {
            name: param.name.clone(),
            ty: Some(preserving_c_typedefs(&param.ty)),
        })
        .collect::<Vec<_>>();
    if ret_type.is_none() && params.is_empty() {
        return None;
    }
    Some(FunctionSignatureSpec { ret_type, params })
}

pub(crate) fn is_generic_signature_type(ty: Option<&CTypeLike>) -> bool {
    crate::is_generic_signature_type(ty)
}

/// Whether a typedef resolves: a stated target, a name C or `<stdint.h>` defines, or a name
/// this decompiler mints. A name some aggregate shares proves nothing (D345).
pub(crate) fn typedef_resolves(name: &str, target: &CTypeLike) -> bool {
    !matches!(target, CTypeLike::Unknown)
        || matches!(name.trim(), "allocation_ptr" | "memory_ptr")
        || crate::convert::names_a_standard_type(name)
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
        CTypeLike::Pointer(_) | CTypeLike::UnprototypedFunction(_) => {
            Some((ptr_bits / 8).max(1) as u64)
        }
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
