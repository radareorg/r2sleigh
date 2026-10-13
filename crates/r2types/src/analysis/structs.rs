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

pub(crate) fn augment_local_struct_artifacts_with_projection(
    local_structs: &mut LocalStructArtifacts,
    projection: &SemanticTypeProjection,
    ptr_bits: u32,
) {
    for (slot, projected) in &projection.slot_field_profiles {
        let profile = local_structs.slot_field_profiles.entry(*slot).or_default();
        for (offset, field_type) in projected {
            profile.entry(*offset).or_insert(field_type.clone());
        }
        if profile.is_empty() || local_structs.slot_type_overrides.contains_key(slot) {
            continue;
        }
        let struct_name = format!("sla_struct_symbolic_arg{}", slot + 1);
        let Some(fields) = profile
            .iter()
            .map(|(offset, field_type)| {
                Some(StructFieldCandidate {
                    name: format!("f_{offset:x}"),
                    offset: *offset,
                    field_type: parse_c_type_like(field_type, ptr_bits)?,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let Some(decl) = build_struct_decl(&struct_name, &fields, ptr_bits) else {
            continue;
        };
        if !local_structs
            .struct_decls
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&struct_name))
        {
            local_structs.struct_decls.push(StructDeclCandidate {
                name: struct_name.clone(),
                decl,
                confidence: 84,
                source: StructDeclSource::LocalInferred,
                fields,
            });
        }
        local_structs
            .slot_type_overrides
            .insert(*slot, format!("struct {struct_name} *"));
    }
}

pub(crate) fn augment_local_struct_artifacts_with_local_field_accesses(
    local_structs: &mut LocalStructArtifacts,
    local_field_accesses: &[LocalFieldAccessFact],
    ptr_bits: u32,
) {
    let mut projected_profiles = BTreeMap::<usize, BTreeMap<u64, String>>::new();
    for access in local_field_accesses {
        let field_type = access
            .field_type
            .clone()
            .unwrap_or_else(|| access.field_name.clone());
        projected_profiles
            .entry(access.slot)
            .or_default()
            .entry(access.field_offset)
            .or_insert(field_type);
    }

    for (slot, projected) in projected_profiles {
        let profile = local_structs.slot_field_profiles.entry(slot).or_default();
        for (offset, field_type) in projected {
            profile.entry(offset).or_insert(field_type);
        }
        if profile.is_empty() || local_structs.slot_type_overrides.contains_key(&slot) {
            continue;
        }

        let allow_single_field = profile.len() == 1;
        if profile.len() < 2 && !allow_single_field {
            continue;
        }
        let mut shape = String::new();
        let Some(fields) = profile
            .iter()
            .map(|(offset, field_type)| {
                shape.push_str(&format!("{offset:x}:{field_type};"));
                Some(StructFieldCandidate {
                    name: format!("f_{offset:x}"),
                    offset: *offset,
                    field_type: parse_c_type_like(field_type, ptr_bits)?,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        shape.hash(&mut hasher);
        let struct_name = format!("sla_struct_{:016x}", hasher.finish());
        let Some(decl) = build_struct_decl(&struct_name, &fields, ptr_bits) else {
            continue;
        };
        if !local_structs
            .struct_decls
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&struct_name))
        {
            local_structs.struct_decls.push(StructDeclCandidate {
                name: struct_name.clone(),
                decl,
                confidence: 90,
                source: StructDeclSource::LocalInferred,
                fields,
            });
        }
        local_structs
            .slot_type_overrides
            .insert(slot, format!("struct {struct_name} *"));
    }
}

pub(crate) fn signature_param_blocks_local_struct_override(
    signature: &Option<FunctionSignatureSpec>,
    slot: usize,
    raw_ty: &str,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> bool {
    signature_param_blocks_generated_local_struct_override(
        signature.as_ref().and_then(|sig| sig.params.get(slot)),
        raw_ty,
        type_db,
        ptr_bits,
    )
}

pub(crate) fn prune_conflicting_local_struct_overrides(
    merged_signature: &Option<FunctionSignatureSpec>,
    struct_decls: &mut Vec<StructDeclCandidate>,
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &mut HashMap<usize, BTreeMap<u64, String>>,
    indexed_local_struct_refinement_slots: &HashSet<usize>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) {
    let blocked_slots = slot_type_overrides
        .iter()
        .filter_map(|(slot, raw_ty)| {
            (!indexed_local_struct_refinement_slots.contains(slot)
                && signature_param_blocks_local_struct_override(
                    merged_signature,
                    *slot,
                    raw_ty,
                    type_db,
                    ptr_bits,
                ))
            .then_some(*slot)
        })
        .collect::<Vec<_>>();
    if blocked_slots.is_empty() {
        return;
    }

    for slot in &blocked_slots {
        slot_type_overrides.remove(slot);
        slot_field_profiles.remove(slot);
    }

    let referenced_local_names = slot_type_overrides
        .values()
        .filter_map(|ty| ty.trim().strip_prefix("struct "))
        .filter_map(|rest| rest.trim_end().strip_suffix(" *"))
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    struct_decls.retain(|decl| {
        decl.source != StructDeclSource::LocalInferred
            || referenced_local_names.contains(&decl.name.to_ascii_lowercase())
    });
}

pub(crate) fn collect_external_struct_candidates_from_db(
    db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Vec<StructDeclCandidate> {
    let mut keys: Vec<String> = db.structs.keys().cloned().collect();
    keys.sort();

    let mut out = Vec::new();
    'structs: for key in keys {
        let Some(st) = db.structs.get(&key) else {
            continue;
        };
        if type_name_is_opaque_placeholder(&st.name)
            || st.fields.is_empty()
            || db.is_aggregate_typedef(&st.name)
        {
            continue;
        }
        let mut fields = Vec::new();
        for (offset, field) in &st.fields {
            let raw_ty = field.ty.clone().unwrap_or_else(|| "uint8_t".to_string());
            let Some(field_type) = parse_c_type_like(&raw_ty, ptr_bits) else {
                continue 'structs;
            };
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
    ptr_bits: u32,
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
                    ty: Some(render_signature_type(&field.field_type, ptr_bits)),
                },
            );
        }
        let candidate = ExternalStruct {
            name: decl.name.clone(),
            fields,
        };
        match db.structs.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if decl.source == StructDeclSource::LocalInferred
                    && (is_generated_local_struct_name(&decl.name) || entry.get().fields.is_empty())
                {
                    entry.insert(candidate);
                }
            }
        }
    }
}

pub(crate) fn canonical_field_type_key(ty: &str, ptr_bits: u32) -> String {
    let normalized = normalize_external_type_name(ty);
    parse_c_type_like(&normalized, ptr_bits)
        .map(|parsed| render_signature_type(&parsed, ptr_bits).to_ascii_lowercase())
        .unwrap_or_else(|| normalized.to_ascii_lowercase())
}

pub(crate) fn struct_fields_signature(
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = fields
        .iter()
        .map(|f| {
            (
                f.offset,
                canonical_field_type_key(&render_signature_type(&f.field_type, ptr_bits), ptr_bits),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out
}

pub(crate) fn local_struct_profile_score(
    decl: &StructDeclCandidate,
    profile: &BTreeMap<u64, String>,
    ptr_bits: u32,
) -> Option<(usize, usize, usize, i32)> {
    if decl.source != StructDeclSource::LocalInferred || profile.is_empty() {
        return None;
    }

    let field_map = decl
        .fields
        .iter()
        .map(|field| {
            (
                field.offset,
                canonical_field_type_key(
                    &render_signature_type(&field.field_type, ptr_bits),
                    ptr_bits,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut offset_matches = 0usize;
    let mut typed_matches = 0usize;
    for (offset, ty) in profile {
        let Some(field_ty) = field_map.get(offset) else {
            continue;
        };
        offset_matches += 1;
        if field_ty == &canonical_field_type_key(ty, ptr_bits) {
            typed_matches += 1;
        }
    }

    (offset_matches > 0).then_some((
        offset_matches,
        typed_matches,
        decl.fields.len(),
        i32::from(decl.confidence),
    ))
}

pub(crate) fn prefer_stronger_local_struct_overrides(
    struct_decls: &[StructDeclCandidate],
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &HashMap<usize, BTreeMap<u64, String>>,
    ptr_bits: u32,
) {
    for (slot, ty) in slot_type_overrides.iter_mut() {
        let Some(profile) = slot_field_profiles.get(slot) else {
            continue;
        };
        if profile.is_empty() {
            continue;
        }

        let current_name = parse_struct_ptr_type_name(ty);
        let current_decl = current_name.as_ref().and_then(|name| {
            struct_decls
                .iter()
                .find(|decl| decl.name.eq_ignore_ascii_case(name))
        });
        if current_decl.is_some_and(|decl| decl.source == StructDeclSource::ExternalTypeDb)
            || current_name.is_some() && current_decl.is_none()
        {
            continue;
        }

        let current_score =
            current_decl.and_then(|decl| local_struct_profile_score(decl, profile, ptr_bits));
        let best_local = struct_decls
            .iter()
            .filter_map(|decl| {
                local_struct_profile_score(decl, profile, ptr_bits)
                    .map(|score| (score, decl.name.clone()))
            })
            .max_by(|(left_score, left_name), (right_score, right_name)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| left_name.cmp(right_name))
            });

        let Some((best_score, best_name)) = best_local else {
            continue;
        };
        if current_score.is_none_or(|score| best_score > score) {
            *ty = format!("struct {} *", best_name);
        }
    }
}

pub(crate) fn structurally_compatible(
    local_fields: &[(u64, String)],
    ext_fields: &[(u64, String)],
) -> bool {
    if local_fields.is_empty() || ext_fields.is_empty() {
        return false;
    }
    let mut matches = 0usize;
    for (off, ty) in local_fields {
        if ext_fields
            .iter()
            .any(|(eoff, ety)| eoff == off && ety == ty)
        {
            matches += 1;
        }
    }
    matches >= local_fields.len().min(2)
}

pub(crate) fn align_local_structs_with_external(
    struct_decls: &mut [StructDeclCandidate],
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &HashMap<usize, BTreeMap<u64, String>>,
    external_structs: &[StructDeclCandidate],
    ptr_bits: u32,
) {
    let mut local_to_external: HashMap<String, String> = HashMap::new();
    for local in struct_decls.iter_mut() {
        if local.source != StructDeclSource::LocalInferred {
            continue;
        }
        let local_sig = struct_fields_signature(&local.fields, ptr_bits);
        for ext in external_structs {
            let ext_sig = struct_fields_signature(&ext.fields, ptr_bits);
            if structurally_compatible(&local_sig, &ext_sig) {
                local_to_external.insert(local.name.clone(), ext.name.clone());
                local.confidence = local.confidence.max(92);
                break;
            }
        }
    }

    for (slot, ty) in slot_type_overrides.iter_mut() {
        let Some(profile) = slot_field_profiles.get(slot) else {
            continue;
        };
        if profile.is_empty() {
            continue;
        }
        let replacement = external_structs.iter().find_map(|ext| {
            let ext_sig = struct_fields_signature(&ext.fields, ptr_bits);
            let local_sig: Vec<(u64, String)> = profile
                .iter()
                .map(|(off, ty)| (*off, canonical_field_type_key(ty, ptr_bits)))
                .collect();
            if structurally_compatible(&local_sig, &ext_sig) {
                Some(ext.name.clone())
            } else {
                None
            }
        });
        if let Some(ext_name) = replacement {
            *ty = format!("struct {} *", ext_name);
            continue;
        }
        if let Some(local_name) = ty
            .strip_prefix("struct ")
            .and_then(|s| s.strip_suffix(" *"))
            .map(str::to_string)
            && let Some(ext_name) = local_to_external.get(&local_name)
        {
            *ty = format!("struct {} *", ext_name);
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
        cursor = cursor.saturating_add(estimate_c_type_size_bytes(&field_type, ptr_bits));
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
