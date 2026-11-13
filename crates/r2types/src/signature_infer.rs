use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};

use r2ssa::{ObjectKind, SSAOp, SSAVar, SsaArtifact};

use crate::convert::CTypeLike;

use crate::analysis::{InferredSignature, InferredSignatureParam};
use crate::model::Signedness;
use crate::prepare::recover_signature_params_from_prepared_ssa;
use crate::signedness::ScalarSignednessEvidence;
use r2ssa::dense::IdMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParamCandidate {
    pub name: String,
    pub ty: CTypeLike,
    pub arg_index: usize,
    pub size_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSignatureParam {
    pub name: String,
    pub arg_index: usize,
    /// A register formal's entry value; a stack formal has none (`FormalHome::Frame`).
    pub value: Option<r2ssa::ValueId>,
    pub size_bytes: u32,
    pub initial_ty: CTypeLike,
}

/// The signature the prepared function shows, typed by the function's one solve and return decision.
pub(crate) fn infer_signature_from_prepared_ssa(
    prepared: &SsaArtifact,
    solved: &crate::function_facts::SolvedFunction,
) -> InferredSignature {
    let evidence_types = &solved.evidence;
    let function_name = prepared
        .function()
        .name
        .clone()
        .unwrap_or_else(|| r2source::unnamed_function(prepared.function().entry));
    let ptr_bits = prepared
        .machine_context()
        .memory_model()
        .default_address_bits();
    let recovered_params = recover_signature_params_from_prepared_ssa(prepared, ptr_bits);
    let certified_parameter_widths = certified_parameter_memory_widths(prepared);

    let mut canonical_params = recovered_params
        .iter()
        .map(|param| {
            let certified_ty = certified_parameter_pointer_type(
                param.initial_ty.clone(),
                certified_parameter_widths.get(&param.arg_index),
            );
            let aggregate = (solved.aggregates.get(&param.arg_index)).map(|aggregate| {
                CTypeLike::Pointer(Box::new(CTypeLike::Struct(aggregate.tag.clone())))
            });
            let ty = aggregate.unwrap_or_else(|| {
                param
                    .value
                    .and_then(|value| evidence_types.value_type(value))
                    .cloned()
                    .unwrap_or(certified_ty)
            });
            SignatureParamCandidate {
                name: param.name.clone(),
                ty,
                arg_index: param.arg_index,
                size_bytes: param.size_bytes,
            }
        })
        .collect::<Vec<_>>();
    refine_parameter_signedness(
        prepared,
        &recovered_params,
        &solved.signedness,
        &mut canonical_params,
    );

    build_inferred_signature(
        &function_name,
        ptr_bits,
        &canonical_params,
        solved.returns.decided(),
    )
}

fn certified_parameter_memory_widths(prepared: &SsaArtifact) -> FxHashMap<usize, BTreeSet<u32>> {
    let mut widths = FxHashMap::<usize, BTreeSet<u32>>::default();
    for access in prepared.certificates().memory_accesses.values() {
        let Some(index) = certified_memory_parameter(prepared, access) else {
            continue;
        };
        widths.entry(index).or_default().insert(access.width);
    }
    widths
}

fn certified_memory_parameter(
    prepared: &SsaArtifact,
    access: &r2ssa::MemoryAccessCertificate,
) -> Option<usize> {
    if access.space != r2il::SpaceId::Ram {
        return None;
    }
    prepared
        .objects()
        .object(access.object)
        .and_then(|object| match object.kind {
            ObjectKind::Parameter {
                space: r2il::SpaceId::Ram,
                index,
            } => Some(index),
            _ => None,
        })
        .or_else(|| {
            prepared
                .addresses()
                .parameter_expression(access.address)
                .map(|expression| expression.parameter)
        })
}

/// Each parameter a certified memory access addresses, as a pointer to the structure its
/// accesses lay out, else to the one width every such access reads, signed as its loads seed it
/// (D265), or to `void`.
pub(crate) fn certified_parameter_pointers(
    prepared: &SsaArtifact,
    aggregates: &BTreeMap<usize, crate::aggregates::InferredAggregate>,
    signedness: &IdMap<r2ssa::ValueId, BTreeSet<ScalarSignednessEvidence>>,
) -> BTreeMap<usize, CTypeLike> {
    let signs = pointee_signs(prepared, signedness);
    let floats = pointee_floats(prepared);
    certified_parameter_memory_widths(prepared)
        .into_iter()
        .map(|(index, widths)| {
            if let Some(aggregate) = aggregates.get(&index) {
                let tag = CTypeLike::Struct(aggregate.tag.clone());
                return (index, CTypeLike::Pointer(Box::new(tag)));
            }
            let pointer = match certified_parameter_pointer_type(CTypeLike::Void, Some(&widths)) {
                CTypeLike::Pointer(inner) => match *inner {
                    // A pointee every access carries as a float of its width is that float (D353).
                    CTypeLike::Int {
                        bits: bits @ (32 | 64),
                        ..
                    } if floats.get(&(index, bits)) == Some(&true) => {
                        CTypeLike::Pointer(Box::new(CTypeLike::Float(bits)))
                    }
                    CTypeLike::Int { bits, .. } => {
                        let sign = (signs.get(&(index, bits)).copied())
                            .unwrap_or(crate::SignFact::Unstated);
                        let bits = u8::try_from(bits).unwrap_or(u8::MAX);
                        let width = r2source::Basis::Dereferenced;
                        let pointee = crate::IntegerDecl { bits, width, sign };
                        CTypeLike::Pointer(Box::new(pointee.spelled()))
                    }
                    inner => CTypeLike::Pointer(Box::new(inner)),
                },
                other => other,
            };
            (index, pointer)
        })
        .collect()
}

/// Whether every certified access through each parameter at `(parameter, bits)` carries a float:
/// a load whose every use, through copies and merges, is a float operation, a store of one's
/// result. A float operation decodes the bits as IEEE 754 (D353). O(accesses + uses reached).
fn pointee_floats(prepared: &SsaArtifact) -> BTreeMap<(usize, u32), bool> {
    let graph = prepared.graph();
    let float_op = |op: &SSAOp<r2ssa::ValueId>| {
        matches!(
            op,
            SSAOp::FloatAdd { .. }
                | SSAOp::FloatSub { .. }
                | SSAOp::FloatMult { .. }
                | SSAOp::FloatDiv { .. }
                | SSAOp::FloatNeg { .. }
                | SSAOp::FloatAbs { .. }
                | SSAOp::FloatSqrt { .. }
                | SSAOp::FloatCeil { .. }
                | SSAOp::FloatFloor { .. }
                | SSAOp::FloatRound { .. }
                | SSAOp::FloatNaN { .. }
                | SSAOp::FloatEqual { .. }
                | SSAOp::FloatNotEqual { .. }
                | SSAOp::FloatLess { .. }
                | SSAOp::FloatLessEqual { .. }
                | SSAOp::Float2Int { .. }
                | SSAOp::FloatFloat { .. }
                | SSAOp::Trunc { .. }
        )
    };
    // Every use reached through copies and merges is a float operation, and one is reached.
    let read_as_float = |value: r2ssa::ValueId| {
        let mut seen = r2ssa::dense::IdSet::new(graph.values.len());
        let (mut pending, mut any) = (vec![value], false);
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            for site in graph.use_sites(value) {
                let Some(inst) = graph.inst(site.inst) else {
                    return false;
                };
                match &inst.payload {
                    r2ssa::InstPayload::Op(SSAOp::Copy { dst, .. }) => pending.push(*dst),
                    r2ssa::InstPayload::Phi { .. } => pending.extend(inst.output),
                    r2ssa::InstPayload::Op(op) if float_op(op) => any = true,
                    _ => return false,
                }
            }
        }
        any
    };
    let written_as_float = |value: r2ssa::ValueId| {
        (graph.def_inst(value).and_then(|inst| graph.op(inst))).is_some_and(float_op)
    };
    let mut floats = BTreeMap::<(usize, u32), bool>::new();
    for access in prepared.certificates().memory_accesses.values() {
        let Some(index) = certified_memory_parameter(prepared, access) else {
            continue;
        };
        let float = access.value.is_some_and(|value| match access.is_write {
            true => written_as_float(value),
            false => read_as_float(value),
        });
        let cell = floats
            .entry((index, access.width.saturating_mul(8)))
            .or_insert(true);
        *cell &= float;
    }
    floats
}

/// The sign each parameter's pointee is read at, by `(parameter, bits)`: the evidence on every
/// certified load through it at that width. O(certified accesses).
fn pointee_signs(
    prepared: &SsaArtifact,
    inferred: &IdMap<r2ssa::ValueId, BTreeSet<ScalarSignednessEvidence>>,
) -> BTreeMap<(usize, u32), crate::SignFact> {
    let graph = prepared.graph();
    let mut seen = BTreeMap::<(usize, u32), (bool, bool)>::new();
    for access in prepared.certificates().memory_accesses.values() {
        let Some(index) = certified_memory_parameter(prepared, access) else {
            continue;
        };
        let Some(value) = access.value else {
            continue;
        };
        if graph
            .value(value)
            .is_none_or(|value| value.var.size != access.width)
        {
            continue;
        }
        let Some(observed) = inferred.get(value) else {
            continue;
        };
        let cell = seen
            .entry((index, access.width.saturating_mul(8)))
            .or_default();
        cell.0 |= observed.contains(&ScalarSignednessEvidence::Signed);
        cell.1 |= observed.contains(&ScalarSignednessEvidence::Unsigned);
    }
    (seen.into_iter())
        .map(|(key, (signed, unsigned))| (key, crate::SignFact::of(signed, unsigned)))
        .collect()
}

fn certified_parameter_pointer_type(
    initial_ty: CTypeLike,
    widths: Option<&BTreeSet<u32>>,
) -> CTypeLike {
    let Some(widths) = widths else {
        return initial_ty;
    };
    if matches!(
        initial_ty,
        CTypeLike::Pointer(ref inner)
            if !matches!(inner.as_ref(), CTypeLike::Void | CTypeLike::Unknown)
    ) {
        return initial_ty;
    }
    let Some(width) = widths.first().copied().filter(|_| widths.len() == 1) else {
        return CTypeLike::Pointer(Box::new(CTypeLike::Void));
    };
    let bits = width.saturating_mul(8);
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return CTypeLike::Pointer(Box::new(CTypeLike::Void));
    }
    CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits,
        signedness: Signedness::Unknown,
    }))
}

fn refine_parameter_signedness(
    prepared: &SsaArtifact,
    recovered_params: &[RecoveredSignatureParam],
    inferred: &IdMap<r2ssa::ValueId, BTreeSet<ScalarSignednessEvidence>>,
    params: &mut [SignatureParamCandidate],
) {
    let pointees = pointee_signs(prepared, inferred);
    for param in params {
        let scalar = || {
            let observed = recovered_params
                .iter()
                .find(|recovered| recovered.arg_index == param.arg_index)
                .and_then(|recovered| recovered.value)
                .and_then(|value| inferred.get(value));
            observed.map(|observed| {
                crate::SignFact::of(
                    observed.contains(&ScalarSignednessEvidence::Signed),
                    observed.contains(&ScalarSignednessEvidence::Unsigned),
                )
            })
        };
        let target = match &mut param.ty {
            CTypeLike::Int { signedness, .. } if *signedness == Signedness::Unknown => {
                scalar().map(|sign| (sign, signedness))
            }
            CTypeLike::Pointer(inner) => match inner.as_mut() {
                CTypeLike::Int { bits, signedness } if *signedness == Signedness::Unknown => {
                    (pointees.get(&(param.arg_index, *bits)).copied())
                        .map(|sign| (sign, signedness))
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((sign, target)) = target
            && let Some(signedness) = sign.signedness()
        {
            *target = signedness;
        }
    }
}

/// The same-width aliases parameter signedness flows through beside the
/// merges: a certified reload and the value it reloads, and a parameter's
/// home and its reload.
pub(crate) fn signedness_aliases(
    prepared: &SsaArtifact,
    recovered_params: &[RecoveredSignatureParam],
) -> Vec<(r2ssa::ValueId, r2ssa::ValueId)> {
    let graph = prepared.graph();
    prepared
        .certificates()
        .stack_reloads
        .values()
        .filter(|reload| {
            reload.relation == r2ssa::ViewRelation::Identity
                && reload.value_width == reload.memory_width
        })
        .map(|reload| (reload.canonical_source, reload.value))
        .chain(
            certified_parameter_home_aliases(prepared, recovered_params)
                .iter()
                .filter_map(|(source, reload)| {
                    Some((
                        graph.value_id_for_var(source)?,
                        graph.value_id_for_var(reload)?,
                    ))
                }),
        )
        .collect()
}

fn certified_parameter_home_aliases(
    prepared: &SsaArtifact,
    recovered_params: &[RecoveredSignatureParam],
) -> Vec<(SSAVar, SSAVar)> {
    let mut writes = FxHashMap::<r2ssa::ObjectId, Vec<&r2ssa::MemoryAccessCertificate>>::default();
    for access in prepared.certificates().memory_accesses.values() {
        if access.is_write
            && access.space == r2il::SpaceId::Ram
            && prepared
                .objects()
                .object(access.object)
                .is_some_and(|object| {
                    matches!(
                        object.kind,
                        ObjectKind::StackSlot {
                            space: r2il::SpaceId::Ram,
                            ..
                        } | ObjectKind::FrameObject {
                            space: r2il::SpaceId::Ram,
                            ..
                        }
                    )
                })
        {
            writes.entry(access.object).or_default().push(access);
        }
    }

    let mut aliases = Vec::new();
    for (object, stores) in writes {
        let [store] = stores.as_slice() else {
            continue;
        };
        let Some(stored) = store
            .value
            .and_then(|value| transparent_same_width_source(prepared, value))
        else {
            continue;
        };
        let Some(parameter_var) = recovered_params
            .iter()
            .filter_map(|parameter| prepared.value_var(parameter.value?))
            .find(|var| **var == stored)
        else {
            continue;
        };
        for load in prepared
            .certificates()
            .memory_accesses
            .values()
            .filter(|access| {
                !access.is_write && access.space == r2il::SpaceId::Ram && access.object == object
            })
        {
            if load.width != store.width || load.width != parameter_var.size {
                continue;
            }
            let Some(reload) = load
                .value
                .and_then(|value| prepared.value_var(value))
                .cloned()
            else {
                continue;
            };
            aliases.push((parameter_var.clone(), reload));
        }
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
fn transparent_same_width_source(prepared: &SsaArtifact, start: r2ssa::ValueId) -> Option<SSAVar> {
    let mut current = start;
    let mut visited = FxHashSet::default();
    while visited.insert(current) {
        let current_var = prepared.value_var(current)?.clone();
        let Some(inst) = prepared
            .graph()
            .def_inst(current)
            .and_then(|inst| prepared.graph().inst(inst))
        else {
            return Some(current_var);
        };
        let r2ssa::InstPayload::Op(op) = &inst.payload else {
            return Some(current_var);
        };
        let graph = prepared.graph();
        let source = match op {
            SSAOp::Copy { src, .. } | SSAOp::New { src, .. } | SSAOp::Cast { src, .. } => *src,
            SSAOp::Subpiece { src, offset, .. }
                if *offset == 0 && graph.var(*src).size == current_var.size =>
            {
                *src
            }
            _ => return Some(current_var),
        };
        if graph.var(source).size != current_var.size {
            return Some(current_var);
        }
        current = source;
    }
    None
}

fn is_unmaterialized_aggregate_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.is_empty() || lower == "anon" || lower.starts_with("anon_")
}

pub fn materialize_signature_type_like(ty: CTypeLike, ptr_bits: u32) -> CTypeLike {
    match ty {
        CTypeLike::Pointer(inner) => {
            if matches!(*inner, CTypeLike::Unknown | CTypeLike::Void)
                || matches!(
                    inner.as_ref(),
                    CTypeLike::Struct(name)
                        | CTypeLike::Union(name)
                        | CTypeLike::Enum(name)
                        if is_unmaterialized_aggregate_name(name)
                )
            {
                return CTypeLike::Pointer(Box::new(CTypeLike::Void));
            }
            CTypeLike::Pointer(Box::new(materialize_signature_type_like(*inner, ptr_bits)))
        }
        CTypeLike::Array(inner, len) => {
            if matches!(*inner, CTypeLike::Unknown | CTypeLike::Void) {
                return CTypeLike::Array(
                    Box::new(CTypeLike::Int {
                        bits: 8,
                        signedness: Signedness::Unsigned,
                    }),
                    len,
                );
            }
            CTypeLike::Array(
                Box::new(materialize_signature_type_like(*inner, ptr_bits)),
                len,
            )
        }
        CTypeLike::Unknown => crate::unstated_word(ptr_bits.max(8)),
        CTypeLike::Struct(name) if is_unmaterialized_aggregate_name(&name) => {
            crate::unstated_word(ptr_bits.max(8))
        }
        CTypeLike::Union(name) if is_unmaterialized_aggregate_name(&name) => {
            crate::unstated_word(ptr_bits.max(8))
        }
        CTypeLike::Enum(name) if is_unmaterialized_aggregate_name(&name) => {
            crate::unstated_word(ptr_bits.max(8))
        }
        CTypeLike::Typedef { name, .. } if name.trim().is_empty() => {
            crate::unstated_word(ptr_bits.max(8))
        }
        // No owner stated the sign, so C spells none (D265).
        CTypeLike::Int {
            bits: bits @ (8 | 16 | 32 | 64),
            signedness: Signedness::Unknown,
        } => crate::unstated_word(bits),
        other => other,
    }
}

/// Whether two signature types are the same type for signature purposes: equal once materialized
/// and builtin names folded; an unstated sign is its word, equal only to itself (D265).
pub fn signature_types_are_equivalent(left: &CTypeLike, right: &CTypeLike, ptr_bits: u32) -> bool {
    normalized_signature_type(left, ptr_bits) == normalized_signature_type(right, ptr_bits)
}

fn normalized_signature_type(ty: &CTypeLike, ptr_bits: u32) -> CTypeLike {
    resolve_builtin_typedefs(
        materialize_signature_type_like(ty.clone(), ptr_bits),
        ptr_bits,
    )
}

/// Fold a typedef whose name spells its own type (`int32_t`) into that type.
///
/// `size_t` stays a name: it states more than its width. Plain `int` folds to `int32_t`.
pub(crate) fn resolve_builtin_typedefs(ty: CTypeLike, ptr_bits: u32) -> CTypeLike {
    match ty {
        CTypeLike::Typedef { name, ty } => {
            let target = match ty.unaliased() {
                CTypeLike::Unknown => crate::convert::standard_type(&name, ptr_bits),
                target => Some(target.clone()),
            };
            let is_plain_c_int = matches!(name.trim().to_ascii_lowercase().as_str(), "int");
            match target {
                Some(target)
                    if is_plain_c_int || render_signature_type(&target, ptr_bits) == name =>
                {
                    target
                }
                _ => CTypeLike::Typedef { name, ty },
            }
        }
        CTypeLike::Pointer(inner) => {
            CTypeLike::Pointer(Box::new(resolve_builtin_typedefs(*inner, ptr_bits)))
        }
        CTypeLike::Array(inner, len) => {
            CTypeLike::Array(Box::new(resolve_builtin_typedefs(*inner, ptr_bits)), len)
        }
        CTypeLike::Const(inner) => {
            CTypeLike::Const(Box::new(resolve_builtin_typedefs(*inner, ptr_bits)))
        }
        other => other,
    }
}

pub fn render_signature_type(ty: &CTypeLike, ptr_bits: u32) -> String {
    match materialize_signature_type_like(ty.clone(), ptr_bits) {
        CTypeLike::Const(inner) => format!("const {}", render_signature_type(&inner, ptr_bits)),
        CTypeLike::Void => "void".to_string(),
        CTypeLike::Bool => "bool".to_string(),
        CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Signed,
        } => "int8_t".to_string(),
        CTypeLike::Int {
            bits: 16,
            signedness: Signedness::Signed,
        } => "int16_t".to_string(),
        CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        } => "int32_t".to_string(),
        CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        } => "int64_t".to_string(),
        // The one spelling of a 128-bit integer a C compiler accepts, as
        // `render_c_type_like` spells it; `int128_t` is not one.
        CTypeLike::Int {
            bits: 128,
            signedness: Signedness::Signed | Signedness::Unknown,
        } => "__int128_t".to_string(),
        CTypeLike::Int {
            bits,
            signedness: Signedness::Signed | Signedness::Unknown,
        } => format!("int{bits}_t"),
        CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Unsigned,
        } => "uint8_t".to_string(),
        CTypeLike::Int {
            bits: 16,
            signedness: Signedness::Unsigned,
        } => "uint16_t".to_string(),
        CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Unsigned,
        } => "uint32_t".to_string(),
        CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        } => "uint64_t".to_string(),
        CTypeLike::Int {
            bits: 128,
            signedness: Signedness::Unsigned,
        } => "__uint128_t".to_string(),
        CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        } => format!("uint{bits}_t"),
        CTypeLike::Float(32) => "float".to_string(),
        CTypeLike::Float(64) => "double".to_string(),
        CTypeLike::Float(bits) => format!("float{bits}"),
        CTypeLike::BitVector(bits) => format!("struct {}", crate::convert::bit_vector_tag(bits)),
        CTypeLike::Pointer(inner) => format!("{}*", render_signature_type(&inner, ptr_bits)),
        CTypeLike::Array(inner, Some(size)) => {
            format!("{}[{}]", render_signature_type(&inner, ptr_bits), size)
        }
        CTypeLike::Array(inner, None) => format!("{}[]", render_signature_type(&inner, ptr_bits)),
        CTypeLike::Struct(name) => format!("struct {name}"),
        CTypeLike::Union(name) => format!("union {name}"),
        CTypeLike::Enum(name) => format!("enum {name}"),
        CTypeLike::Typedef { name, .. } => name,
        CTypeLike::Function { .. } | CTypeLike::UnprototypedFunction(_) => "void (*)()".to_string(),
        CTypeLike::Unknown => "int64_t".to_string(),
    }
}

use crate::context::sanitize_c_identifier;

fn uniquify_name(base: String, used: &mut FxHashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    let mut index = 1usize;
    loop {
        let candidate = format!("{base}_{index}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        index += 1;
    }
}

fn normalize_inferred_param_name(
    raw_name: &str,
    fallback_idx: usize,
    used: &mut FxHashSet<String>,
) -> String {
    let fallback = r2source::positional_parameter_name(fallback_idx);
    let clean = sanitize_c_identifier(raw_name).unwrap_or_else(|| fallback.clone());
    let clean = if clean.is_empty() { fallback } else { clean };
    uniquify_name(clean, used)
}

/// A type as an inferred signature states it: materialized, an unstated sign its word (D265).
fn signature_type(ty: &CTypeLike, ptr_bits: u32) -> CTypeLike {
    materialize_signature_type_like(ty.clone(), ptr_bits)
}

pub(crate) fn build_inferred_signature(
    function_name: &str,
    ptr_bits: u32,
    params: &[SignatureParamCandidate],
    ret_type: Option<&CTypeLike>,
) -> InferredSignature {
    let mut ordered = params.to_vec();
    ordered.sort_by(|a, b| {
        a.arg_index
            .cmp(&b.arg_index)
            .then_with(|| a.name.cmp(&b.name))
    });
    let mut used_param_names = FxHashSet::default();
    let mut json_params = Vec::new();
    for param in &ordered {
        let slot = if param.arg_index == usize::MAX {
            json_params.len()
        } else {
            param.arg_index
        };
        while json_params.len() < slot {
            let gap_slot = json_params.len();
            json_params.push(InferredSignatureParam {
                name: normalize_inferred_param_name(
                    &r2source::positional_parameter_name(gap_slot),
                    gap_slot,
                    &mut used_param_names,
                ),
                ty: signature_type(
                    &CTypeLike::Int {
                        bits: ptr_bits.max(8),
                        signedness: Signedness::Unknown,
                    },
                    ptr_bits,
                ),
            });
        }
        json_params.push(InferredSignatureParam {
            name: normalize_inferred_param_name(&param.name, slot, &mut used_param_names),
            ty: signature_type(&param.ty, ptr_bits),
        });
    }
    // An undecided return states nothing.
    let ret_type = ret_type.map(|ty| signature_type(ty, ptr_bits));
    InferredSignature {
        function_name: function_name.to_string(),
        ret_type,
        params: json_params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature with the function solved alone, no callee prototype supplied.
    fn inferred(prepared: &SsaArtifact) -> InferredSignature {
        let ptr_bits = prepared
            .machine_context()
            .memory_model()
            .default_address_bits();
        let solved =
            crate::function_facts::SolvedFunction::of(prepared, &BTreeMap::new(), ptr_bits);
        infer_signature_from_prepared_ssa(prepared, &solved)
    }

    #[test]
    fn plain_int_and_canonical_int32_are_equivalent() {
        let source_spelling = CTypeLike::typedef("int");
        let canonical = CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        };

        assert!(signature_types_are_equivalent(
            &source_spelling,
            &canonical,
            64
        ));
        assert!(signature_types_are_equivalent(
            &CTypeLike::Pointer(Box::new(source_spelling)),
            &CTypeLike::Pointer(Box::new(canonical)),
            64
        ));
    }

    /// Where comparing types differs from comparing the text they print to.
    ///
    /// The six sites this predicate replaced compared rendered strings, so any
    /// two types that print the same were treated as one. Comparing the types
    /// instead is only safe where the renderer is injective, and this test says
    /// exactly where it is not, rather than leaving it to be discovered by a
    /// wrong decompilation.
    #[test]
    fn comparing_types_agrees_with_comparing_their_spellings() {
        let mut cases = vec![
            CTypeLike::Void,
            CTypeLike::Bool,
            CTypeLike::Unknown,
            CTypeLike::Float(32),
            CTypeLike::Float(64),
            CTypeLike::Struct("Demo".to_string()),
            CTypeLike::Union("Demo".to_string()),
            CTypeLike::typedef("demo_t"),
            // The collision worth naming: a typedef whose spelling is exactly a
            // built-in type's spelling.
            CTypeLike::typedef("int32_t"),
            CTypeLike::typedef("size_t"),
        ];
        for bits in [8u32, 16, 32, 64] {
            for signedness in [
                Signedness::Signed,
                Signedness::Unsigned,
                Signedness::Unknown,
            ] {
                cases.push(CTypeLike::Int { bits, signedness });
            }
        }
        let scalars = cases.clone();
        for scalar in scalars {
            cases.push(CTypeLike::Pointer(Box::new(scalar)));
        }

        let ptr_bits = 64;
        let mut divergences = Vec::new();
        for left in &cases {
            for right in &cases {
                let by_type = signature_types_are_equivalent(left, right, ptr_bits);
                let by_spelling =
                    render_signature_type(left, ptr_bits) == render_signature_type(right, ptr_bits);
                if by_type != by_spelling {
                    divergences.push(format!(
                        "{left:?} vs {right:?}: by type {by_type}, by spelling {by_spelling}"
                    ));
                }
            }
        }
        assert!(
            divergences.is_empty(),
            "comparing types disagrees with comparing spellings:\n{}",
            divergences.join("\n")
        );
    }

    fn x86_return_arch() -> r2ssa::Arch {
        r2ssa::Arch::new(x86_return_arch_spec())
    }

    fn x86_return_arch_spec() -> r2il::ArchSpec {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("RAX", 0, 8));
        arch.add_register(r2il::RegisterDef::new("RIP", 8, 8));
        arch.add_register(r2il::RegisterDef::new("RSP", 16, 8));
        arch
    }

    fn prepared_x86_scalar_return(
        return_carrier_name: &str,
        convention: r2source::ConventionId,
    ) -> SsaArtifact {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new(return_carrier_name, 0, 8));
        arch.add_register(r2il::RegisterDef::new("RIP", 8, 8));
        arch.add_register(r2il::RegisterDef::new("RSP", 16, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            format!("signature-{return_carrier_name}").into_bytes(),
            convention,
            [],
            r2ssa::SourceFunctionReturn::Register {
                storage: register(0),
            },
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(register(8)))
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .expect("exact renamed return interface");
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntZExt {
            dst: r2il::Varnode::register(0, 8),
            src: r2il::Varnode::unique(0x20, 4),
        });
        block.push(r2il::R2ILOp::Return {
            target: r2il::Varnode::register(8, 8),
        });
        SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared renamed return source")
    }

    fn aarch64_parameter_arch() -> r2ssa::Arch {
        r2ssa::Arch::new(aarch64_parameter_arch_spec())
    }

    fn aarch64_parameter_arch_spec() -> r2il::ArchSpec {
        let mut arch = r2il::ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.add_register(r2il::RegisterDef::new("x0", 0, 8));
        arch.add_register(r2il::RegisterDef::new("w0", 0, 4));
        arch.add_register(r2il::RegisterDef::new("sp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("lr", 24, 8));
        arch
    }

    fn aarch64_prepared_with_stack_slot(
        block: r2il::R2ILBlock,
        stack_slot: r2ssa::SourceStackSlotSpec,
    ) -> SsaArtifact {
        let register_storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let parameter = register_storage(0);
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"aarch64-stack-fixture".to_vec(),
            r2source::ConventionId::Aapcs64,
            [r2ssa::SourceAbiParameterSpec::new(0, parameter)],
            r2ssa::SourceFunctionReturn::Void,
            [stack_slot],
        )
        .and_then(|interface| interface.with_return_address_storage(register_storage(24)))
        .and_then(|interface| interface.with_stack_pointer_storage(register_storage(16)))
        .expect("exact AArch64 stack interface");
        SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&aarch64_parameter_arch()),
            interface,
        )
        .expect("prepared exact AArch64 stack fixture")
    }

    #[test]
    fn prepared_signature_recovers_unsigned_byte_pointee_through_certified_stack_reload() {
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntSub {
            dst: r2il::Varnode::unique(0x10, 8),
            a: r2il::Varnode::register(16, 8),
            b: r2il::Varnode::constant(8, 8),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x20, 1),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::register(0, 8),
        });
        block.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
            val: r2il::Varnode::unique(0x20, 1),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x30, 1),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
        });
        block.push(r2il::R2ILOp::IntZExt {
            dst: r2il::Varnode::unique(0x40, 4),
            src: r2il::Varnode::unique(0x30, 1),
        });
        // The widened byte is observed: a dead extension states no sign (D265).
        block.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::register(8, 8),
            val: r2il::Varnode::unique(0x40, 4),
        });
        let prepared = aarch64_prepared_with_stack_slot(
            block,
            r2ssa::SourceStackSlotSpec::new_local(
                r2ssa::StackAddressBase::StackPointer,
                r2ssa::CanonicalStorageId {
                    space: r2ssa::CanonicalStorageSpace::Register,
                    offset: 16,
                    size: 8,
                },
                -8,
                1,
            ),
        );
        let inferred = inferred(&prepared);

        assert_eq!(
            render_signature_type(&inferred.params[0].ty, 64),
            "uint8_t*"
        );
    }

    #[test]
    fn prepared_signature_recovers_unsigned_scalar_through_certified_stack_reload() {
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntSub {
            dst: r2il::Varnode::unique(0x10, 8),
            a: r2il::Varnode::register(16, 8),
            b: r2il::Varnode::constant(8, 8),
        });
        block.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
            val: r2il::Varnode::register(0, 8),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x20, 8),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
        });
        block.push(r2il::R2ILOp::IntLess {
            dst: r2il::Varnode::unique(0x30, 1),
            a: r2il::Varnode::unique(0x20, 8),
            b: r2il::Varnode::constant(10, 8),
        });
        block.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x2000, 8),
            cond: r2il::Varnode::unique(0x30, 1),
        });
        let stack_pointer = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let parameter = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let prepared = aarch64_prepared_with_stack_slot(
            block,
            r2ssa::SourceStackSlotSpec::new_parameter_home(
                r2ssa::StackAddressBase::StackPointer,
                stack_pointer,
                -8,
                8,
                0,
                parameter,
            ),
        );
        let inferred = inferred(&prepared);

        assert_eq!(
            render_signature_type(&inferred.params[0].ty, 64),
            "uint64_t"
        );
    }

    #[test]
    fn overwritten_stack_home_does_not_alias_parameter_signedness() {
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntSub {
            dst: r2il::Varnode::unique(0x10, 8),
            a: r2il::Varnode::register(16, 8),
            b: r2il::Varnode::constant(8, 8),
        });
        block.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
            val: r2il::Varnode::register(0, 8),
        });
        block.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
            val: r2il::Varnode::constant(1, 8),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x20, 8),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x10, 8),
        });
        let stack_pointer = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 16,
            size: 8,
        };
        let parameter = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let prepared = aarch64_prepared_with_stack_slot(
            block,
            r2ssa::SourceStackSlotSpec::new_parameter_home(
                r2ssa::StackAddressBase::StackPointer,
                stack_pointer,
                -8,
                8,
                0,
                parameter,
            ),
        );
        let recovered = [RecoveredSignatureParam {
            name: "value".to_string(),
            arg_index: 0,
            value: prepared.graph().value_id_for_var(&SSAVar::new("x0", 0, 8)),
            size_bytes: 8,
            initial_ty: CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unknown,
            },
        }];

        assert!(certified_parameter_home_aliases(&prepared, &recovered).is_empty());
    }

    #[test]
    fn prepared_signature_uses_certified_return_value_not_control_target() {
        let arch = x86_return_arch();
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntZExt {
            dst: r2il::Varnode::register(0, 8),
            src: r2il::Varnode::unique(0x20, 4),
        });
        block.push(r2il::R2ILOp::Return {
            target: r2il::Varnode::register(8, 8),
        });
        let return_storage = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"certified-signature-return-fixture".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [],
            r2ssa::SourceFunctionReturn::Register {
                storage: return_storage,
            },
            [],
        )
        .and_then(|interface| {
            interface.with_return_address_storage(r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 8,
                size: 8,
            })
        })
        .and_then(|interface| {
            interface.with_stack_pointer_storage(r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 16,
                size: 8,
            })
        })
        .expect("exact function return interface");
        let prepared = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("prepared exact return SSA");
        assert_eq!(
            prepared.certificates().returns.len(),
            1,
            "source-owned return fixture must certify one value"
        );
        let inferred = inferred(&prepared);

        // The certified value is untyped, so no return is claimed, least of all the control target's.
        assert_eq!(
            inferred
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            ""
        );
    }

    #[test]
    fn misleading_xmm0_spelling_does_not_manufacture_a_float_return() {
        let inferred = inferred(&prepared_x86_scalar_return(
            "xmm0_misleading",
            r2source::ConventionId::SysVAmd64,
        ));

        assert_eq!(
            inferred
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            ""
        );
        assert_ne!(
            inferred
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            "float"
        );
        assert_ne!(
            inferred
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            "double"
        );
    }

    #[test]
    fn prepared_signature_does_not_type_a_return_from_program_counter() {
        // Nothing the program counter holds is returned: void only where the boundary says so, else nothing.
        let arch = x86_return_arch();
        let returning = || {
            let mut block = r2il::R2ILBlock::new(0x1000, 4);
            block.push(r2il::R2ILOp::Return {
                target: r2il::Varnode::register(8, 8),
            });
            block
        };
        let unstated =
            SsaArtifact::for_patterns(&[returning()], Some(&arch)).expect("prepared SSA");
        assert_eq!(
            inferred(&unstated)
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            ""
        );
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let void = r2ssa::SourceFunctionInterface::new_exact(
            b"void-return-through-pc".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [],
            r2ssa::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(register(8)))
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .expect("void interface");
        let stated = SsaArtifact::for_decompile_with_interface(&[returning()], Some(&arch), void)
            .expect("prepared void source");
        assert_eq!(
            inferred(&stated)
                .ret_type
                .as_ref()
                .map(|ty| render_signature_type(ty, 64))
                .unwrap_or_default(),
            "void"
        );
    }

    #[test]
    fn sparse_abi_parameters_materialize_preceding_slots() {
        let params = vec![
            SignatureParamCandidate {
                name: "arg0".to_string(),
                ty: CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Unknown,
                },
                arg_index: 0,
                size_bytes: 8,
            },
            SignatureParamCandidate {
                name: "arg6".to_string(),
                ty: CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                },
                arg_index: 6,
                size_bytes: 4,
            },
        ];

        let inferred = build_inferred_signature("stack_arg", 64, &params, Some(&CTypeLike::Void));

        assert_eq!(inferred.params.len(), 7);
        for (slot, param) in inferred.params.iter().enumerate() {
            assert_eq!(param.name, format!("arg{slot}"));
        }
        // A gap and a parameter no seed signs spell the unstated word (D265).
        assert_eq!(
            render_signature_type(&inferred.params[1].ty, 64),
            "r2sleigh_word_u64"
        );
        assert_eq!(render_signature_type(&inferred.params[6].ty, 64), "int32_t");
    }
}
