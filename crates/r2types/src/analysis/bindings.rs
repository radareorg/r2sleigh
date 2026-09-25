//! What each variable is called and what type it is given.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VarRenameCandidate {
    pub name: String,
    pub target_name: String,
    pub confidence: u8,
    pub source: TypeFactSource,
    pub evidence: Vec<TypeEvidence>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SignatureContextMaps {
    pub(crate) param_types: HashMap<usize, String>,
    pub(crate) param_names: HashMap<usize, String>,
}

pub(crate) struct VarTypeCandidateContext<'a> {
    pub(crate) current_context_maps: &'a SignatureContextMaps,
    pub(crate) merged_signature: Option<&'a FunctionSignatureSpec>,
    pub(crate) slot_type_overrides: &'a HashMap<usize, String>,
    pub(crate) stack_slots: &'a BTreeMap<StackSlotKey, ExternalStackVarSpec>,
    pub(crate) existing_types: &'a HashMap<String, String>,
    pub(crate) stack_access_widths: &'a BTreeMap<StackSlotKey, BTreeSet<u32>>,
    pub(crate) stack_access_signedness:
        &'a BTreeMap<StackSlotKey, BTreeSet<ScalarSignednessEvidence>>,
    pub(crate) ptr_bits: u32,
    pub(crate) is_main_signature: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VisibleBindingKey {
    Param(usize),
    Stack(StackSlotKey),
}

pub(crate) fn slot_spec_for_recovered_var<'a>(
    var: &RecoveredVariable,
    stack_slots: &'a BTreeMap<StackSlotKey, ExternalStackVarSpec>,
) -> Option<&'a ExternalStackVarSpec> {
    if let Some(slot_key) = stack_slot_key_for_recovered_var(var)
        && let Some(slot) = stack_slots.get(&slot_key)
    {
        return Some(slot);
    }
    None
}

pub(crate) fn slot_role_is_hidden(role: ExternalStackSlotRole) -> bool {
    matches!(
        role,
        ExternalStackSlotRole::ParamHome
            | ExternalStackSlotRole::SavedReg
            | ExternalStackSlotRole::SavedFp
    )
}

pub(crate) fn slot_role_allows_external_local_identity(role: ExternalStackSlotRole) -> bool {
    matches!(
        role,
        ExternalStackSlotRole::Local
            | ExternalStackSlotRole::StackArg
            | ExternalStackSlotRole::Unknown
    )
}

pub(crate) fn visible_binding_kind_for_slot_role(
    role: ExternalStackSlotRole,
) -> VisibleBindingKind {
    match role {
        ExternalStackSlotRole::Local => VisibleBindingKind::Local,
        ExternalStackSlotRole::StackArg => VisibleBindingKind::Param,
        ExternalStackSlotRole::ParamHome => VisibleBindingKind::HiddenHome,
        ExternalStackSlotRole::SavedReg | ExternalStackSlotRole::SavedFp => {
            VisibleBindingKind::HiddenSaved
        }
        ExternalStackSlotRole::Unknown => VisibleBindingKind::Unknown,
    }
}

pub(crate) fn visible_binding_key_for_recovered_var(
    var: &RecoveredVariable,
) -> Option<VisibleBindingKey> {
    if let Some(slot_key) = stack_slot_key_for_recovered_var(var) {
        return Some(VisibleBindingKey::Stack(slot_key));
    }
    if var.isarg {
        return var
            .name
            .strip_prefix("arg")
            .and_then(|idx| idx.parse::<usize>().ok())
            .map(VisibleBindingKey::Param);
    }
    None
}

pub(crate) fn name_is_low_signal_binding(name: &str) -> bool {
    is_low_quality_stack_name(name) || is_generic_arg_name(name)
}

pub(crate) fn visible_binding_type_specificity(ty: &CTypeLike) -> u8 {
    match ty {
        CTypeLike::Const(inner) => visible_binding_type_specificity(inner),
        CTypeLike::Unknown => 0,
        CTypeLike::Void => 1,
        CTypeLike::Function { .. } | CTypeLike::BitVector(_) => 2,
        CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => 4,
        CTypeLike::Typedef { .. } | CTypeLike::Enum(_) => 5,
        CTypeLike::Struct(_) | CTypeLike::Union(_) => 6,
        CTypeLike::Array(inner, _) => 12 + visible_binding_type_specificity(inner).min(12),
        CTypeLike::Pointer(inner) => 10 + visible_binding_type_specificity(inner).min(12),
    }
}

pub(crate) fn candidate_visible_binding_type_is_better(
    existing: Option<&CTypeLike>,
    candidate: Option<&CTypeLike>,
) -> bool {
    match (existing, candidate) {
        (_, None) => false,
        (None | Some(CTypeLike::Unknown), Some(_)) => true,
        (Some(existing), Some(candidate)) => {
            visible_binding_type_specificity(candidate) > visible_binding_type_specificity(existing)
        }
    }
}

pub(crate) fn merge_visible_binding(existing: &mut VisibleBinding, candidate: VisibleBinding) {
    let VisibleBinding {
        name,
        ty,
        kind,
        stack_slot,
        param_index,
        source_reg,
    } = candidate;
    let existing_low_signal = name_is_low_signal_binding(&existing.name);
    let candidate_low_signal = name_is_low_signal_binding(&name);
    if existing.name.is_empty() || (existing_low_signal && !candidate_low_signal) {
        existing.name = name;
    }

    if candidate_visible_binding_type_is_better(existing.ty.as_ref(), ty.as_ref()) {
        existing.ty = ty;
    }

    if matches!(existing.kind, VisibleBindingKind::Unknown)
        || (matches!(existing.kind, VisibleBindingKind::Local)
            && matches!(kind, VisibleBindingKind::StackObject))
    {
        existing.kind = kind;
    }

    if existing.stack_slot.is_none() && stack_slot.is_some() {
        existing.stack_slot = stack_slot;
    }
    if existing.param_index.is_none() && param_index.is_some() {
        existing.param_index = param_index;
    }
    if existing.source_reg.is_none() && source_reg.is_some() {
        existing.source_reg = source_reg;
    }
}

pub(crate) fn build_visible_bindings(
    merged_signature: Option<&FunctionSignatureSpec>,
    register_params: &[crate::context::ExternalRegisterParamSpec],
    stack_slots: &BTreeMap<StackSlotKey, ExternalStackVarSpec>,
    recovered_vars: &[RecoveredVariable],
    var_type_candidates: &[VarTypeCandidate],
    var_rename_candidates: &[VarRenameCandidate],
    ptr_bits: u32,
) -> Vec<VisibleBinding> {
    let mut bindings = BTreeMap::<VisibleBindingKey, VisibleBinding>::new();

    for (idx, param) in merged_signature
        .map(|sig| sig.params.iter().enumerate().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        bindings.insert(
            VisibleBindingKey::Param(idx),
            VisibleBinding {
                name: if is_generic_arg_name(&param.name) {
                    format!("arg{}", idx + 1)
                } else {
                    param.name.clone()
                },
                ty: param.ty.clone(),
                kind: VisibleBindingKind::Param,
                stack_slot: None,
                param_index: Some(idx),
                source_reg: register_params.get(idx).map(|param| param.reg.clone()),
            },
        );
    }

    for (idx, reg_param) in register_params.iter().enumerate() {
        let candidate = VisibleBinding {
            name: if reg_param.name.is_empty() {
                format!("arg{}", idx + 1)
            } else {
                reg_param.name.clone()
            },
            ty: reg_param.ty.clone(),
            kind: VisibleBindingKind::Param,
            stack_slot: None,
            param_index: Some(idx),
            source_reg: Some(reg_param.reg.clone()),
        };
        bindings
            .entry(VisibleBindingKey::Param(idx))
            .and_modify(|existing| merge_visible_binding(existing, candidate.clone()))
            .or_insert(candidate);
    }

    let rename_map = var_rename_candidates
        .iter()
        .map(|candidate| (candidate.name.as_str(), candidate.target_name.clone()))
        .collect::<HashMap<_, _>>();
    let mut type_map = BTreeMap::<RecoveredVarKey, CTypeLike>::new();
    for candidate in var_type_candidates {
        // The candidate carries a type now, so there is nothing left to parse
        // and nothing to skip for being unparseable.
        let ty = candidate.var_type.clone();
        let key = RecoveredVarKey::for_type_candidate(candidate);
        type_map
            .entry(key)
            .and_modify(|existing| {
                if candidate_visible_binding_type_is_better(Some(existing), Some(&ty)) {
                    *existing = ty.clone();
                }
            })
            .or_insert(ty);
    }

    for (slot_key, slot_spec) in stack_slots {
        let key = slot_spec
            .param_index
            .filter(|_| matches!(slot_spec.role, ExternalStackSlotRole::StackArg))
            .map(VisibleBindingKey::Param)
            .unwrap_or_else(|| VisibleBindingKey::Stack(*slot_key));
        let candidate = VisibleBinding {
            name: slot_spec
                .param_name
                .as_ref()
                .filter(|_| matches!(slot_spec.role, ExternalStackSlotRole::StackArg))
                .cloned()
                .or_else(|| (!slot_spec.name.is_empty()).then(|| slot_spec.name.clone()))
                .unwrap_or_else(|| match key {
                    VisibleBindingKey::Param(idx) => format!("arg{}", idx + 1),
                    VisibleBindingKey::Stack(_) => "local".to_string(),
                }),
            ty: slot_spec.ty.clone(),
            kind: visible_binding_kind_for_slot_role(slot_spec.role),
            stack_slot: Some(*slot_key),
            param_index: slot_spec.param_index,
            source_reg: slot_spec.source_reg.clone(),
        };
        bindings
            .entry(key)
            .and_modify(|existing| merge_visible_binding(existing, candidate.clone()))
            .or_insert(candidate);
    }

    for var in recovered_vars {
        let Some(key) = visible_binding_key_for_recovered_var(var) else {
            continue;
        };
        let recovered_stack_arg_index = if var.isarg && matches!(key, VisibleBindingKey::Stack(_)) {
            var.name
                .strip_prefix("arg")
                .and_then(|idx| idx.parse::<usize>().ok())
        } else {
            None
        };
        let candidate_name = rename_map
            .get(var.name.as_str())
            .cloned()
            .unwrap_or_else(|| {
                recovered_stack_arg_index
                    .map(|idx| format!("arg{}", idx + 1))
                    .unwrap_or_else(|| var.name.clone())
            });
        let candidate = VisibleBinding {
            name: sanitize_c_identifier(&candidate_name).unwrap_or(candidate_name),
            ty: type_map
                .get(&RecoveredVarKey::for_recovered_var(var))
                .cloned()
                .or_else(|| parse_c_type_like(&var.var_type, ptr_bits)),
            kind: if var.isarg {
                VisibleBindingKind::Param
            } else if matches!(key, VisibleBindingKey::Stack(_)) {
                VisibleBindingKind::Local
            } else {
                VisibleBindingKind::Unknown
            },
            stack_slot: match &key {
                VisibleBindingKey::Stack(slot_key) => Some(*slot_key),
                VisibleBindingKey::Param(_) => None,
            },
            param_index: match key {
                VisibleBindingKey::Param(idx) => Some(idx),
                VisibleBindingKey::Stack(_) => recovered_stack_arg_index,
            },
            source_reg: var.reg.clone(),
        };
        bindings
            .entry(key)
            .and_modify(|existing| merge_visible_binding(existing, candidate.clone()))
            .or_insert(candidate);
    }

    bindings.into_values().collect()
}

pub(crate) fn integer_type_bits(ty: &str, ptr_bits: u32) -> Option<u32> {
    match parse_c_type_like(ty, ptr_bits)? {
        CTypeLike::Int { bits, .. } => Some(bits),
        _ => None,
    }
}

pub(crate) fn exact_stack_access_bits(
    var: &RecoveredVariable,
    widths: &BTreeMap<StackSlotKey, BTreeSet<u32>>,
) -> Option<u32> {
    let slot = stack_slot_key_for_recovered_var(var)?;
    let widths = widths.get(&slot)?;
    let mut widths = widths.iter().copied();
    let bytes = widths.next()?;
    if widths.next().is_some() {
        return None;
    }
    bytes.checked_mul(8)
}

pub(crate) fn exact_stack_access_signedness(
    var: &RecoveredVariable,
    signedness: &BTreeMap<StackSlotKey, BTreeSet<ScalarSignednessEvidence>>,
) -> Option<ScalarSignednessEvidence> {
    let slot = stack_slot_key_for_recovered_var(var)?;
    let mut observed = signedness.get(&slot)?.iter().copied();
    let signedness = observed.next()?;
    observed.next().is_none().then_some(signedness)
}

pub(crate) fn build_var_type_candidates(
    vars: &[RecoveredVariable],
    ctx: &VarTypeCandidateContext<'_>,
    diagnostics: &mut TypeAnalysisDiagnostics,
) -> Vec<VarTypeCandidate> {
    let mut out = Vec::with_capacity(vars.len());
    for var in vars {
        let slot_spec = slot_spec_for_recovered_var(var, ctx.stack_slots);
        if slot_spec.is_some_and(|spec| slot_role_is_hidden(spec.role)) {
            continue;
        }

        let mut source = TypeFactSource::LocalInferred;
        let mut confidence = if var
            .recovered_type(ctx.ptr_bits)
            .is_some_and(|ty| ty.is_pointer())
        {
            92
        } else if var.isarg {
            88
        } else {
            84
        };
        let mut evidence = vec![TypeEvidence::SsaVarRecovery];
        let mut chosen_type = var.var_type.clone();
        let arg_slot = var
            .name
            .strip_prefix("arg")
            .and_then(|idx| idx.parse::<usize>().ok());

        if let Some(slot) = arg_slot
            && let Some(sig_ty) = ctx.current_context_maps.param_types.get(&slot)
            && !type_name_is_generic(sig_ty)
        {
            chosen_type = sig_ty.clone();
            confidence = 96;
            source = TypeFactSource::SignatureRegistry;
            evidence.push(TypeEvidence::ExternalSignatureCurrent);
        } else if let Some(slot) = arg_slot
            && let Some(sig_ty) = ctx
                .merged_signature
                .and_then(|sig| sig.params.get(slot))
                .and_then(|param| param.ty.as_ref())
                .map(|ty| render_signature_type(ty, ctx.ptr_bits))
            && !type_name_is_generic(&sig_ty)
        {
            chosen_type = sig_ty;
            confidence = 96;
            source = TypeFactSource::SignatureRegistry;
            if ctx.is_main_signature {
                evidence.push(TypeEvidence::CanonicalMainSignature);
            } else {
                evidence.push(TypeEvidence::ExternalSignatureCurrent);
            }
        } else if let Some(slot) = arg_slot
            && let Some(struct_ty) = ctx.slot_type_overrides.get(&slot)
            && type_name_is_generic(&chosen_type)
        {
            chosen_type = struct_ty.clone();
            confidence = 90;
            source = TypeFactSource::LocalInferred;
            evidence.push(TypeEvidence::SsaFieldOffsetPattern);
        }

        if let Some(existing_ty) = ctx.existing_types.get(&var.name)
            && !type_name_is_generic(existing_ty)
        {
            if type_name_is_generic(&chosen_type) {
                chosen_type = existing_ty.clone();
                confidence = 98;
                source = TypeFactSource::ExistingState;
                evidence.push(TypeEvidence::ExistingStackType);
            } else if !existing_ty.eq_ignore_ascii_case(&chosen_type) {
                diagnostics.conflicts.push(format!(
                    "var `{}` existing type `{}` conflicts with inferred `{}`",
                    var.name, existing_ty, chosen_type
                ));
            }
        }

        let exact_access_bits = exact_stack_access_bits(var, ctx.stack_access_widths);
        if exact_access_bits
            .is_some_and(|bits| integer_type_bits(&chosen_type, ctx.ptr_bits) == Some(bits))
        {
            confidence = confidence.max(96);
            source = TypeFactSource::DataflowRanked;
            evidence.push(TypeEvidence::CanonicalStackAccessWidth);
        }
        if let Some(signedness) = exact_stack_access_signedness(var, ctx.stack_access_signedness)
            && let Some(bits) = exact_access_bits
            && integer_type_bits(&chosen_type, ctx.ptr_bits) == Some(bits)
        {
            if let Some(signed_type) = storage_type_spelling(bits / 8, signedness.signedness()) {
                chosen_type = signed_type;
            }
            confidence = confidence.max(97);
            source = TypeFactSource::DataflowRanked;
            evidence.push(TypeEvidence::CanonicalStackSignedness);
        }

        if let Some(ext) = slot_spec
            && let Some(ext_ty) = ext.ty.as_ref()
            && slot_role_allows_external_local_identity(ext.role)
        {
            let ext_ty_str = render_signature_type(ext_ty, ctx.ptr_bits);
            let external_conflicts_with_exact_integer_width =
                exact_access_bits.is_some_and(|bits| {
                    integer_type_bits(&chosen_type, ctx.ptr_bits) == Some(bits)
                        && integer_type_bits(&ext_ty_str, ctx.ptr_bits)
                            .is_some_and(|external_bits| external_bits != bits)
                });
            let external_should_override = !type_name_is_generic(&ext_ty_str)
                && !external_conflicts_with_exact_integer_width
                && (type_name_is_generic(&chosen_type)
                    || (matches!(source, TypeFactSource::LocalInferred)
                        && is_low_signal_storage_scalar_type(&chosen_type, ctx.ptr_bits)));
            if external_conflicts_with_exact_integer_width {
                diagnostics.conflicts.push(format!(
                    "var `{}` external stack type `{}` conflicts with canonical {}-bit memory accesses",
                    var.name,
                    ext_ty_str,
                    exact_access_bits.unwrap()
                ));
            }
            if external_should_override {
                chosen_type = ext_ty_str;
                confidence = 97;
                source = TypeFactSource::ExternalTypeDb;
                evidence.push(TypeEvidence::ExternalStackAnnotation);
            }
        }

        let Some(var_type) = parse_c_type_like(&chosen_type, ctx.ptr_bits) else {
            diagnostics.warnings.push(format!(
                "var `{}` type `{chosen_type}` was not a placeable C type",
                var.name
            ));
            continue;
        };
        let size =
            estimate_type_like_size_bytes(&var_type, ctx.ptr_bits).unwrap_or_default() as u32;
        out.push(VarTypeCandidate {
            name: var.name.clone(),
            kind: var.kind.clone(),
            delta: var.delta,
            var_type,
            isarg: var.isarg,
            reg: var.reg.clone(),
            size,
            confidence,
            source,
            evidence,
        });
    }
    out
}

pub(crate) fn build_var_rename_candidates(
    vars: &[RecoveredVariable],
    param_names: &HashMap<usize, String>,
    stack_slots: &BTreeMap<StackSlotKey, ExternalStackVarSpec>,
) -> Vec<VarRenameCandidate> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for var in vars {
        let slot_spec = slot_spec_for_recovered_var(var, stack_slots);

        if let Some(ext) = slot_spec
            && ext.name != var.name
            && is_low_quality_stack_name(&var.name)
            && !is_low_quality_stack_name(&ext.name)
            && slot_role_allows_external_local_identity(ext.role)
        {
            let target_name = sanitize_c_identifier(&ext.name).unwrap_or_else(|| ext.name.clone());
            let edge = format!("{}->{target_name}", var.name);
            if !target_name.is_empty() && target_name != var.name && seen.insert(edge) {
                out.push(VarRenameCandidate {
                    name: var.name.clone(),
                    target_name,
                    confidence: 94,
                    source: TypeFactSource::ExternalTypeDb,
                    evidence: vec![TypeEvidence::ExternalStackName],
                });
            }
        }

        if let Some(ext) = slot_spec
            && matches!(ext.role, ExternalStackSlotRole::StackArg)
            && let Some(param_name) = ext.param_name.as_ref()
            && is_low_quality_stack_name(&var.name)
        {
            let target_name =
                sanitize_c_identifier(param_name).unwrap_or_else(|| param_name.clone());
            let edge = format!("{}->{target_name}", var.name);
            if !target_name.is_empty() && target_name != var.name && seen.insert(edge) {
                out.push(VarRenameCandidate {
                    name: var.name.clone(),
                    target_name,
                    confidence: 95,
                    source: TypeFactSource::SignatureRegistry,
                    evidence: vec![TypeEvidence::ExternalParamName],
                });
            }
        }

        let arg_slot = var
            .name
            .strip_prefix("arg")
            .and_then(|idx| idx.parse::<usize>().ok());
        if let Some(slot) = arg_slot
            && let Some(param_name) = param_names.get(&slot)
            && is_generic_arg_name(&var.name)
        {
            let target_name =
                sanitize_c_identifier(param_name).unwrap_or_else(|| param_name.clone());
            let edge = format!("{}->{target_name}", var.name);
            if !target_name.is_empty() && target_name != var.name && seen.insert(edge) {
                out.push(VarRenameCandidate {
                    name: var.name.clone(),
                    target_name,
                    confidence: 95,
                    source: TypeFactSource::SignatureRegistry,
                    evidence: vec![TypeEvidence::ExternalParamName],
                });
            }
        }
    }

    out
}

pub(crate) fn is_low_signal_storage_scalar_type(ty: &str, ptr_bits: u32) -> bool {
    parse_c_type_like(ty, ptr_bits).is_some_and(|parsed| matches!(parsed, CTypeLike::Int { .. }))
}
