//! Which accesses certify an array, and what its elements are.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScalarArrayAccessCertificates {
    pub(crate) array_index: Vec<ArrayIndexCertificate>,
    pub(crate) field_access: Vec<crate::FieldAccessCertificate>,
    pub(crate) render_candidates: Vec<ScalarArrayRenderCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalLayoutFieldAccess {
    pub(crate) name: String,
    pub(crate) ty: Option<String>,
}

pub(crate) fn external_layout_field_access_for_offset(
    type_db: &ExternalTypeDb,
    type_name: &str,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    for key in aggregate_lookup_keys(type_name) {
        if let Some(st) = type_db.structs.get(&key)
            && let Some(field) =
                external_struct_field_access_for_offset(st, offset, access_width, ptr_bits)
        {
            return Some(field);
        }
        if let Some(un) = type_db.unions.get(&key)
            && let Some(field) =
                external_union_field_access_for_offset(un, offset, access_width, ptr_bits)
        {
            return Some(field);
        }
    }
    None
}

pub(crate) fn external_struct_field_access_for_offset(
    st: &ExternalStruct,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    st.fields
        .range(..=offset)
        .next_back()
        .and_then(|(_, field)| {
            external_field_access_for_offset(field, offset, access_width, ptr_bits)
        })
}

pub(crate) fn external_union_field_access_for_offset(
    un: &ExternalUnion,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    if offset != 0 {
        return None;
    }
    un.fields
        .values()
        .find_map(|field| external_field_access_for_offset(field, offset, access_width, ptr_bits))
}

pub(crate) fn external_field_access_for_offset(
    field: &ExternalField,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    if offset < field.offset {
        return None;
    }
    let rel = offset - field.offset;
    let field_ty = field.ty.as_deref();
    if let Some(CTypeLike::Array(inner, len)) =
        field_ty.and_then(|ty| parse_c_type_like(ty, ptr_bits))
    {
        let elem_size = estimate_type_like_size_bytes(&inner, ptr_bits)?;
        if elem_size == 0 || !rel.is_multiple_of(elem_size) || access_width > elem_size {
            return None;
        }
        let index = rel / elem_size;
        if len.is_some_and(|count| index >= count as u64) {
            return None;
        }
        return Some(ExternalLayoutFieldAccess {
            name: format!("{}[{index}]", field.name),
            ty: Some(render_signature_type(&inner, ptr_bits)),
        });
    }

    if rel == 0 {
        return Some(ExternalLayoutFieldAccess {
            name: field.name.clone(),
            ty: field.ty.clone(),
        });
    }

    None
}

pub(crate) fn pointer_element_stride(
    ty: &CTypeLike,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Option<u64> {
    match ty {
        CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => {
            scalar_element_stride(inner, ptr_bits).or_else(|| {
                aggregate_pointee_type_names_from_type(ty)
                    .into_iter()
                    .find_map(|name| external_aggregate_size(type_db, &name, ptr_bits))
            })
        }
        _ => None,
    }
}

pub(crate) fn scalar_element_stride(ty: &CTypeLike, ptr_bits: u32) -> Option<u64> {
    match ty {
        CTypeLike::Const(inner) => scalar_element_stride(inner, ptr_bits),
        CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => {
            estimate_type_like_size_bytes(ty, ptr_bits).filter(|size| *size > 0)
        }
        CTypeLike::Typedef { name, .. } => {
            let normalized = normalize_external_type_name(name);
            parse_c_type_like(&normalized, ptr_bits).and_then(|parsed| match parsed {
                CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => {
                    estimate_type_like_size_bytes(&parsed, ptr_bits).filter(|size| *size > 0)
                }
                _ => None,
            })
        }
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::Array(_, _)
        | CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_)
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => None,
        CTypeLike::Pointer(_) | CTypeLike::UnprototypedFunction(_) => {
            Some((ptr_bits / 8).max(1) as u64)
        }
    }
}

pub(crate) fn aggregate_pointee_type_names_from_type(ty: &CTypeLike) -> Vec<String> {
    let mut out = Vec::new();
    if let CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) = ty {
        collect_aggregate_type_names(inner, &mut out);
    }
    out
}

pub(crate) fn collect_aggregate_type_names(ty: &CTypeLike, out: &mut Vec<String>) {
    match ty {
        CTypeLike::Const(inner) => collect_aggregate_type_names(inner, out),
        CTypeLike::Struct(name) | CTypeLike::Union(name) | CTypeLike::Enum(name) => {
            push_unique_type_name(out, name);
        }
        CTypeLike::Typedef { name, .. } => {
            push_unique_type_name(out, name);
            push_unique_type_name(out, &format!("struct {name}"));
            push_unique_type_name(out, &format!("union {name}"));
        }
        CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => {
            collect_aggregate_type_names(inner, out);
        }
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::Bool
        | CTypeLike::Int { .. }
        | CTypeLike::Float(_)
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. }
        | CTypeLike::UnprototypedFunction(_) => {}
    }
}

pub(crate) fn push_unique_type_name(out: &mut Vec<String>, name: &str) {
    let trimmed = name.trim();
    if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
        out.push(trimmed.to_string());
    }
}

pub(crate) fn external_aggregate_size(
    type_db: &ExternalTypeDb,
    name: &str,
    ptr_bits: u32,
) -> Option<u64> {
    for key in aggregate_lookup_keys(name) {
        if let Some(st) = type_db.structs.get(&key)
            && let Some(size) = external_struct_size(st, ptr_bits)
        {
            return Some(size);
        }
        if let Some(un) = type_db.unions.get(&key) {
            let size = un
                .fields
                .values()
                .filter_map(|field| {
                    field
                        .ty
                        .as_deref()
                        .map(|ty| estimate_c_type_size_bytes(ty, ptr_bits))
                })
                .max()
                .unwrap_or(1);
            return Some(size);
        }
    }
    None
}

pub(crate) fn external_struct_size(st: &ExternalStruct, ptr_bits: u32) -> Option<u64> {
    st.fields
        .values()
        .filter_map(|field| {
            let ty = field.ty.as_deref().unwrap_or("uint8_t");
            let width = estimate_c_type_size_bytes(ty, ptr_bits).max(1);
            field.offset.checked_add(width)
        })
        .max()
}
