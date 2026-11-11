//! Aggregates the frame proves, and how they meet the declared ones.

use super::*;

/// What the prepared function states of its parameters' indexed accesses; the named-SSA struct
/// walk and its scores are gone (ROADMAP T step 3: they reached no output).
pub(crate) fn infer_local_struct_artifacts_from_prepared_ssa(
    prepared: &SsaArtifact,
) -> LocalStructArtifacts {
    LocalStructArtifacts {
        indexed_accesses: prepared_parameter_indexed_accesses(prepared),
        ..LocalStructArtifacts::default()
    }
}

pub(crate) fn prepared_parameter_indexed_accesses(
    prepared: &SsaArtifact,
) -> Vec<ScalarArrayRenderCandidate> {
    let mut candidates = Vec::new();
    for access in prepared.certificates().memory_accesses.values() {
        if access.space != r2il::SpaceId::Ram {
            continue;
        }
        let Some(address) = prepared.addresses().parameter_expression(access.address) else {
            continue;
        };
        let [index] = address.terms.as_slice() else {
            continue;
        };
        let Ok(element_stride) = u64::try_from(index.coefficient) else {
            continue;
        };
        let Ok(field_offset) = u64::try_from(address.offset) else {
            continue;
        };
        if element_stride == 0
            || field_offset >= element_stride
            || u64::from(access.width) > element_stride - field_offset
            || !prepared
                .certificates()
                .renderable_expressions
                .contains(index.value)
        {
            continue;
        }
        let Some(op) = prepared.graph().op_for_inst(access.access.inst) else {
            continue;
        };
        candidates.push(ScalarArrayRenderCandidate {
            slot: address.parameter,
            op,
            is_write: access.is_write,
            field_offset,
            element_stride,
            access_width: access.width,
            index_value: Some(index.value),
        });
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

pub(crate) fn collect_external_struct_candidates_from_db(
    db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Vec<StructDeclCandidate> {
    let mut keys: Vec<String> = db.structs.keys().cloned().collect();
    keys.sort();

    let mut out = Vec::new();
    for key in keys {
        let Some(st) = db.structs.get(&key) else {
            continue;
        };
        if type_name_is_opaque_placeholder(&st.name) || st.fields.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        for (offset, field) in &st.fields {
            let field_type = field.ty.clone().unwrap_or(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Unsigned,
            });
            fields.push(StructFieldCandidate {
                name: field.name.clone(),
                offset: *offset,
                field_type,
            });
        }
        let Some(decl) = build_struct_decl(&st.name, &fields, ptr_bits) else {
            continue;
        };
        out.push(StructDeclCandidate {
            name: st.name.clone(),
            decl,
            confidence: 95,
            source: StructDeclSource::ExternalTypeDb,
            fields,
        });
    }
    out
}

pub(crate) fn merge_local_structs_into_type_db(
    db: &mut ExternalTypeDb,
    struct_decls: &[StructDeclCandidate],
) {
    for decl in struct_decls {
        let key = decl.name.to_ascii_lowercase();
        let mut fields = BTreeMap::new();
        for field in &decl.fields {
            fields.insert(
                field.offset,
                ExternalField {
                    name: field.name.clone(),
                    offset: field.offset,
                    ty: Some(field.field_type.clone()),
                },
            );
        }
        let candidate = ExternalStruct {
            name: decl.name.clone(),
            fields,
        };
        match db.structs.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if decl.source == StructDeclSource::LocalInferred
                    && (is_generated_local_struct_name(&decl.name) || entry.get().fields.is_empty())
                {
                    entry.insert(candidate);
                }
            }
        }
    }
}

pub(crate) fn build_struct_decl(
    struct_name: &str,
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
) -> Option<String> {
    build_struct_decl_with_size(struct_name, fields, ptr_bits, None)
}

pub(crate) fn build_struct_decl_with_size(
    struct_name: &str,
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
    exact_size: Option<u64>,
) -> Option<String> {
    if fields.is_empty() {
        return None;
    }
    let mut sorted_fields = fields.iter().collect::<Vec<_>>();
    sorted_fields.sort_by_key(|field| (field.offset, field.name.as_str()));

    let mut cursor = 0u64;
    let mut lines = Vec::new();
    for field in sorted_fields {
        if field.offset > cursor {
            let gap = field.offset - cursor;
            lines.push(format!("    uint8_t _pad_{cursor:x}[{gap}];"));
            cursor = field.offset;
        }

        let field_type = render_signature_type(&field.field_type, ptr_bits);
        lines.push(format!("    {} {};", field_type, field.name));
        cursor = cursor.saturating_add(estimate_c_type_size_bytes(&field.field_type, ptr_bits));
    }
    if let Some(exact_size) = exact_size {
        if cursor > exact_size {
            return None;
        }
        if cursor < exact_size {
            let gap = exact_size - cursor;
            lines.push(format!("    uint8_t _pad_{cursor:x}[{gap}];"));
        }
    }

    let body = lines.join("\n");
    Some(format!("struct {struct_name} {{\n{body}\n}};"))
}
