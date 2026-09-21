//! The function signature, from the body and from what was declared.

use super::*;

pub(crate) fn semantic_role_param_name_is_weak(name: &str) -> bool {
    crate::signature_param_name_is_weak(name)
}

pub(crate) fn heap_allocation_return_type() -> CTypeLike {
    CTypeLike::typedef("allocation_ptr")
}

pub(crate) fn infer_interproc_return_type(
    summary: &FunctionSemanticSummary,
    merged_signature: Option<&FunctionSignatureSpec>,
    inferred_signature: &InferredSignature,
    ptr_bits: u32,
) -> Option<CTypeLike> {
    match summary.return_relation {
        SummaryReturnRelation::Void => Some(CTypeLike::Void),
        SummaryReturnRelation::HeapAlloc => Some(heap_allocation_return_type()),
        SummaryReturnRelation::Arg(idx) => merged_signature
            .and_then(|signature| signature.params.get(idx))
            .and_then(|param| param.ty.clone())
            .filter(|ty| !is_generic_signature_type(Some(ty)))
            .or_else(|| {
                inferred_signature
                    .params
                    .get(idx)
                    .and_then(|param| parse_c_type_like(&param.param_type, ptr_bits))
                    .filter(|ty| !is_generic_signature_type(Some(ty)))
            }),
        _ => None,
    }
}

pub(crate) fn maybe_upgrade_param_to_pointer(
    summary: &FunctionSemanticSummary,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) {
    let pointer_ty = CTypeLike::Pointer(Box::new(CTypeLike::Void));

    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }

    let Some(signature) = merged_signature.as_mut() else {
        return;
    };

    for idx in 0..signature.params.len().max(inferred_signature.params.len()) {
        if !summary_suggests_pointer_param(summary, idx) {
            continue;
        }

        let merged_param = signature.params.get_mut(idx);
        let inferred_param = inferred_signature.params.get_mut(idx);

        if merged_param.as_ref().is_some_and(|param| {
            param_has_authoritative_named_scalar_role(param, ptr_bits, type_db)
        }) || inferred_param.as_ref().is_some_and(|param| {
            inferred_param_has_authoritative_named_scalar_role(param, ptr_bits, type_db)
        }) {
            continue;
        }

        let merged_is_generic = merged_param.as_ref().is_some_and(|param| {
            param.ty.as_ref().is_none_or(|ty| {
                is_generic_signature_type(Some(ty))
                    || matches!(
                        ty,
                        CTypeLike::Int {
                            bits,
                            signedness: Signedness::Signed
                                | Signedness::Unsigned
                                | Signedness::Unknown,
                        } if *bits == ptr_bits
                    )
            })
        });

        let inferred_is_generic = inferred_param.as_ref().is_some_and(|param| {
            type_name_is_generic(&param.param_type)
                || matches!(
                    parse_c_type_like(&param.param_type, ptr_bits),
                    Some(CTypeLike::Int {
                        bits,
                        signedness: Signedness::Signed
                            | Signedness::Unsigned
                            | Signedness::Unknown,
                    }) if bits == ptr_bits
                )
        });

        if merged_is_generic && let Some(param) = merged_param {
            param.ty = Some(pointer_ty.clone());
        }
        if inferred_is_generic && let Some(param) = inferred_param {
            param.param_type = render_signature_type(&pointer_ty, ptr_bits);
        }
    }
}

pub(crate) fn upgrade_param_indices_to_pointer(
    indices: impl IntoIterator<Item = usize>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) {
    let pointer_ty = CTypeLike::Pointer(Box::new(CTypeLike::Void));

    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }

    let Some(signature) = merged_signature.as_mut() else {
        return;
    };

    for idx in indices {
        let merged_param = signature.params.get_mut(idx);
        let inferred_param = inferred_signature.params.get_mut(idx);

        if merged_param.as_ref().is_some_and(|param| {
            param_has_authoritative_named_scalar_role(param, ptr_bits, type_db)
        }) || inferred_param.as_ref().is_some_and(|param| {
            inferred_param_has_authoritative_named_scalar_role(param, ptr_bits, type_db)
        }) {
            continue;
        }

        let merged_is_generic = merged_param.as_ref().is_some_and(|param| {
            param.ty.as_ref().is_none_or(|ty| {
                is_generic_signature_type(Some(ty))
                    || matches!(
                        ty,
                        CTypeLike::Int {
                            bits,
                            signedness: Signedness::Signed
                                | Signedness::Unsigned
                                | Signedness::Unknown,
                        } if *bits == ptr_bits
                    )
            })
        });

        let inferred_is_generic = inferred_param.as_ref().is_some_and(|param| {
            type_name_is_generic(&param.param_type)
                || matches!(
                    parse_c_type_like(&param.param_type, ptr_bits),
                    Some(CTypeLike::Int {
                        bits,
                        signedness: Signedness::Signed
                            | Signedness::Unsigned
                            | Signedness::Unknown,
                    }) if bits == ptr_bits
                )
        });

        if merged_is_generic && let Some(param) = merged_param {
            param.ty = Some(pointer_ty.clone());
        }
        if inferred_is_generic && let Some(param) = inferred_param {
            param.param_type = render_signature_type(&pointer_ty, ptr_bits);
        }
    }
}

pub(crate) fn type_is_authoritative_named_scalar_role(
    ty: &CTypeLike,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> bool {
    match ty {
        CTypeLike::Bool | CTypeLike::Enum(_) => true,
        CTypeLike::Typedef { name, .. } => type_db_resolves_type_name(type_db, name, ptr_bits),
        _ => false,
    }
}

pub(crate) fn param_has_authoritative_named_scalar_role(
    param: &FunctionParamSpec,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) -> bool {
    !semantic_role_param_name_is_weak(&param.name)
        && param
            .ty
            .as_ref()
            .is_some_and(|ty| type_is_authoritative_named_scalar_role(ty, type_db, ptr_bits))
}

pub(crate) fn inferred_param_has_authoritative_named_scalar_role(
    param: &InferredSignatureParam,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) -> bool {
    if semantic_role_param_name_is_weak(&param.name) {
        return false;
    }
    parse_signature_type_preserving_c_typedefs(&param.param_type, ptr_bits)
        .as_ref()
        .is_some_and(|ty| type_is_authoritative_named_scalar_role(ty, type_db, ptr_bits))
}

pub(crate) fn summary_hint_can_replace_weak_existing(
    existing: &CTypeLike,
    hint: &CTypeLike,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) -> bool {
    crate::summary_hint_can_replace_weak_existing(existing, hint, ptr_bits, type_db)
}

pub(crate) fn upgrade_param_type_hints(
    hints: &BTreeMap<usize, CTypeLike>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) {
    if hints.is_empty() {
        return;
    }
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }

    if let Some(signature) = merged_signature.as_mut() {
        for (idx, hint) in hints {
            if let Some(param) = signature.params.get_mut(*idx) {
                let should_replace = param.ty.as_ref().is_none_or(|existing| {
                    summary_hint_can_replace_weak_existing(existing, hint, ptr_bits, type_db)
                });
                if should_replace {
                    param.ty = Some(hint.clone());
                }
            }
        }
    }

    for (idx, hint) in hints {
        if let Some(param) = inferred_signature.params.get_mut(*idx) {
            let existing_ty = parse_c_type_like(&param.param_type, ptr_bits);
            let should_replace = type_name_is_generic(&param.param_type)
                || existing_ty.as_ref().is_some_and(|existing| {
                    summary_hint_can_replace_weak_existing(existing, hint, ptr_bits, type_db)
                });
            if should_replace {
                param.param_type = render_signature_type(hint, ptr_bits);
            }
        }
    }
}

pub(crate) fn upgrade_return_type_hint(
    hint: Option<&CTypeLike>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) -> bool {
    let Some(hint) = hint else {
        return false;
    };
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }

    let mut changed = false;
    if let Some(signature) = merged_signature.as_mut() {
        let should_replace = signature.ret_type.as_ref().is_none_or(|existing| {
            summary_hint_can_replace_weak_existing(existing, hint, ptr_bits, type_db)
                || matches!(hint, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        existing,
                        Some(hint),
                        ptr_bits,
                        type_db,
                    )
        });
        if should_replace && signature.ret_type.as_ref() != Some(hint) {
            signature.ret_type = Some(hint.clone());
            changed = true;
        }
    }

    let existing_ty = parse_c_type_like(&inferred_signature.ret_type, ptr_bits);
    let should_replace = type_name_is_generic(&inferred_signature.ret_type)
        || existing_ty.as_ref().is_some_and(|existing| {
            summary_hint_can_replace_weak_existing(existing, hint, ptr_bits, type_db)
                || matches!(hint, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        existing,
                        Some(hint),
                        ptr_bits,
                        type_db,
                    )
        });
    if should_replace {
        let rendered = render_signature_type(hint, ptr_bits);
        if inferred_signature.ret_type != rendered {
            inferred_signature.ret_type = rendered;
            changed = true;
        }
    }
    if changed {
        inferred_signature.signature = format_signature(
            &inferred_signature.function_name,
            &inferred_signature.ret_type,
            &inferred_signature.params,
        );
    }
    changed
}

pub(crate) fn upgrade_param_name_hints(
    hints: &BTreeMap<usize, String>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
) {
    if hints.is_empty() {
        return;
    }
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }
    if let Some(signature) = merged_signature.as_mut() {
        for (idx, hint) in hints {
            if let Some(param) = signature.params.get_mut(*idx)
                && (param.name.is_empty() || is_generic_arg_name(&param.name))
            {
                param.name = hint.clone();
            }
        }
    }
    for (idx, hint) in hints {
        if let Some(param) = inferred_signature.params.get_mut(*idx)
            && (param.name.is_empty() || is_generic_arg_name(&param.name))
        {
            param.name = hint.clone();
        }
    }
    inferred_signature.signature = format_signature(
        &inferred_signature.function_name,
        &inferred_signature.ret_type,
        &inferred_signature.params,
    );
}

pub(crate) fn projection_pointer_upgrade_indices(
    projection: &SemanticTypeProjection,
) -> Vec<usize> {
    projection
        .pointer_param_indices
        .iter()
        .copied()
        .filter(|idx| {
            projection
                .param_type_hints
                .get(idx)
                .is_none_or(|ty| matches!(ty, CTypeLike::Pointer(_)))
        })
        .collect()
}

pub(crate) fn apply_interproc_summary_to_signature(
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    summary_view: &InterprocSummaryView,
    semantic_projection: Option<&SemanticTypeProjection>,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) {
    let Some(summary) = summary_view.root_summary() else {
        if let Some(projection) = semantic_projection {
            upgrade_return_type_hint(
                projection.return_type_hint.as_ref(),
                merged_signature,
                inferred_signature,
                ptr_bits,
                type_db,
            );
            upgrade_param_name_hints(
                &projection.param_name_hints,
                merged_signature,
                inferred_signature,
                ptr_bits,
            );
            upgrade_param_indices_to_pointer(
                projection_pointer_upgrade_indices(projection),
                merged_signature,
                inferred_signature,
                ptr_bits,
                type_db,
            );
            upgrade_param_type_hints(
                &projection.param_type_hints,
                merged_signature,
                inferred_signature,
                ptr_bits,
                type_db,
            );
        }
        return;
    };
    maybe_upgrade_param_to_pointer(
        summary,
        merged_signature,
        inferred_signature,
        ptr_bits,
        type_db,
    );
    if let Some(projection) = semantic_projection {
        upgrade_return_type_hint(
            projection.return_type_hint.as_ref(),
            merged_signature,
            inferred_signature,
            ptr_bits,
            type_db,
        );
        upgrade_param_name_hints(
            &projection.param_name_hints,
            merged_signature,
            inferred_signature,
            ptr_bits,
        );
        upgrade_param_indices_to_pointer(
            projection_pointer_upgrade_indices(projection),
            merged_signature,
            inferred_signature,
            ptr_bits,
            type_db,
        );
        upgrade_param_type_hints(
            &projection.param_type_hints,
            merged_signature,
            inferred_signature,
            ptr_bits,
            type_db,
        );
    }
    let Some(ret_ty) = infer_interproc_return_type(
        summary,
        merged_signature.as_ref(),
        inferred_signature,
        ptr_bits,
    ) else {
        return;
    };

    let should_override = merged_signature
        .as_ref()
        .and_then(|signature| signature.ret_type.as_ref())
        .is_none_or(|ty| {
            is_generic_signature_type(Some(ty))
                || summary_hint_can_replace_weak_existing(ty, &ret_ty, ptr_bits, type_db)
                || matches!(summary.return_relation, SummaryReturnRelation::HeapAlloc)
                    && crate::signature_hint_can_replace_existing(ty, Some(&ret_ty), ptr_bits,
                type_db,
            )
                || matches!(ret_ty, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        ty,
                        Some(&ret_ty),
                        ptr_bits,
                type_db,
            )
                || matches!(
                    (&ret_ty, ty),
                    (
                        CTypeLike::Pointer(_),
                        CTypeLike::Int {
                            bits,
                            signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
                        }
                    ) if *bits == ptr_bits
                )
        });
    if !should_override {
        return;
    }

    // A declared `void` is a fact about the interface, not an absent one. A
    // summary watches what the machine leaves in the return register, which a
    // function returning nothing still writes, so letting that stand against the
    // declaration turned `void list_free(Node *head)` into `void *` and left the
    // body returning the program counter.
    let declared_void_return = merged_signature
        .as_ref()
        .and_then(|signature| signature.ret_type.as_ref())
        .is_some_and(|ty| matches!(ty, CTypeLike::Void));
    if declared_void_return && !matches!(ret_ty, CTypeLike::Void) {
        return;
    }

    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }
    if let Some(signature) = merged_signature.as_mut() {
        signature.ret_type = Some(ret_ty.clone());
    }

    if type_name_is_generic(&inferred_signature.ret_type)
        || parse_c_type_like(&inferred_signature.ret_type, ptr_bits).is_some_and(|ty| {
            summary_hint_can_replace_weak_existing(&ty, &ret_ty, ptr_bits, type_db)
        })
        || matches!(summary.return_relation, SummaryReturnRelation::HeapAlloc)
            && parse_c_type_like(&inferred_signature.ret_type, ptr_bits).is_some_and(|ty| {
                crate::signature_hint_can_replace_existing(&ty, Some(&ret_ty), ptr_bits, type_db)
            })
        || matches!(ret_ty, CTypeLike::Void)
            && parse_c_type_like(&inferred_signature.ret_type, ptr_bits).is_some_and(|ty| {
                crate::signature_return_hint_can_replace_existing(
                    &ty,
                    Some(&ret_ty),
                    ptr_bits,
                    type_db,
                )
            })
        || matches!(
            parse_c_type_like(&inferred_signature.ret_type, ptr_bits),
            Some(CTypeLike::Int {
                bits,
                signedness: Signedness::Signed | Signedness::Unsigned | Signedness::Unknown,
            }) if bits == ptr_bits
        )
    {
        inferred_signature.ret_type = render_signature_type(&ret_ty, ptr_bits);
    }
}

pub(crate) fn merge_local_signature_into_merged_signature(
    external: Option<FunctionSignatureSpec>,
    local: Option<FunctionSignatureSpec>,
) -> Option<FunctionSignatureSpec> {
    match (external, local) {
        (None, None) => None,
        (Some(signature), None) => Some(signature),
        (None, Some(signature)) => Some(signature),
        (Some(mut external), Some(local)) => {
            let external_param_count_is_authoritative =
                signature_param_count_is_authoritative(&external);
            // A declared `void` return says the function returns nothing. That
            // is an answer, not a missing one, and it is the only return type a
            // local reading of the machine cannot contradict: a function that
            // returns nothing still leaves something in the return register.
            // Treating it as unknown let inference replace it with `int64_t`,
            // which is weak enough that recovered evidence then replaced it with
            // `void *`, so `void list_free(Node *head)` rendered as returning a
            // pointer and its body ended `return rip;`.
            let external_returns_void = matches!(external.ret_type.as_ref(), Some(CTypeLike::Void));
            if external_returns_void {
                // Keep it.
            } else if local_signature_should_override_external(
                local.ret_type.as_ref(),
                external.ret_type.as_ref(),
            ) || (!external_param_count_is_authoritative
                && scalar_signedness_conflicts(local.ret_type.as_ref(), external.ret_type.as_ref()))
            {
                external.ret_type = local.ret_type;
            } else if is_generic_signature_type(external.ret_type.as_ref()) {
                external.ret_type = local.ret_type.or(external.ret_type);
            }

            if !external_param_count_is_authoritative && external.params.len() < local.params.len()
            {
                external
                    .params
                    .resize_with(local.params.len(), || FunctionParamSpec {
                        name: String::new(),
                        ty: None,
                    });
            }

            for (idx, local_param) in local.params.into_iter().enumerate() {
                if idx >= external.params.len() {
                    continue;
                }
                let target = &mut external.params[idx];
                if target.name.is_empty() {
                    target.name = format!("arg{}", idx + 1);
                }
                if !is_generic_arg_name(&local_param.name) && is_generic_arg_name(&target.name) {
                    target.name = local_param.name.clone();
                }
                if local_param_should_override_external(
                    local_param.ty.as_ref(),
                    target.ty.as_ref(),
                    &target.name,
                ) || (!external_param_count_is_authoritative
                    && is_generic_arg_name(&target.name)
                    && scalar_signedness_conflicts(local_param.ty.as_ref(), target.ty.as_ref()))
                {
                    target.ty = local_param.ty;
                } else if is_generic_signature_type(target.ty.as_ref()) {
                    target.ty = local_param.ty.or(target.ty.take());
                }
            }

            Some(external)
        }
    }
}

pub(crate) fn local_signature_should_override_external(
    local: Option<&CTypeLike>,
    external: Option<&CTypeLike>,
) -> bool {
    let Some(local) = local else {
        return false;
    };
    match external {
        None => true,
        Some(external) if is_generic_signature_type(Some(external)) => true,
        Some(external) => local_scalar_override_should_apply(local, external),
    }
}

pub(crate) fn local_param_should_override_external(
    local: Option<&CTypeLike>,
    external: Option<&CTypeLike>,
    external_name: &str,
) -> bool {
    if external.is_some() && !is_generic_arg_name(external_name) {
        return false;
    }
    local_signature_should_override_external(local, external)
}

pub(crate) fn local_scalar_override_should_apply(local: &CTypeLike, external: &CTypeLike) -> bool {
    match (local, external) {
        (CTypeLike::Pointer(_), CTypeLike::Int { .. }) => true,
        (CTypeLike::Bool, CTypeLike::Bool) => false,
        (
            CTypeLike::Bool,
            CTypeLike::Int {
                bits: external_bits,
                ..
            },
        ) => *external_bits >= 8,
        (
            CTypeLike::Int {
                bits: local_bits,
                signedness: local_signedness,
            },
            CTypeLike::Int {
                bits: external_bits,
                signedness: external_signedness,
            },
        ) => {
            *local_bits < *external_bits
                || (*local_bits == *external_bits
                    && !matches!(local_signedness, Signedness::Unknown)
                    && matches!(external_signedness, Signedness::Unknown))
        }
        _ => false,
    }
}

pub(crate) fn scalar_signedness_conflicts(
    local: Option<&CTypeLike>,
    external: Option<&CTypeLike>,
) -> bool {
    matches!(
        (local, external),
        (
            Some(CTypeLike::Int {
                bits: local_bits,
                signedness: local_signedness,
            }),
            Some(CTypeLike::Int {
                bits: external_bits,
                signedness: external_signedness,
            })
        ) if local_bits == external_bits
            && !matches!(local_signedness, Signedness::Unknown)
            && !matches!(external_signedness, Signedness::Unknown)
            && local_signedness != external_signedness
    )
}

pub(crate) fn apply_signature_context_overrides(
    signature_out: &mut InferredSignature,
    signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
    type_db: &ExternalTypeDb,
) {
    let Some(signature) = signature else {
        return;
    };

    let authoritative_param_count = signature_param_count_is_authoritative(signature)
        || crate::signature_projection_is_exact(signature);
    if authoritative_param_count && signature_out.params.len() > signature.params.len() {
        signature_out.params.truncate(signature.params.len());
    }

    while signature_out.params.len() < signature.params.len() {
        let idx = signature_out.params.len();
        let param_type = signature
            .params
            .get(idx)
            .and_then(|param| param.ty.as_ref())
            .map(|ty| render_signature_type(ty, ptr_bits))
            .unwrap_or_else(|| "void *".to_string());
        signature_out.params.push(InferredSignatureParam {
            name: format!("arg{}", idx + 1),
            param_type,
        });
    }

    if let Some(ret_ty) = signature.ret_type.as_ref() {
        let ret_ty = render_signature_type(ret_ty, ptr_bits);
        if !is_generic_signature_type(signature.ret_type.as_ref()) {
            signature_out.ret_type = ret_ty;
        }
    }

    for (idx, param) in signature.params.iter().enumerate() {
        if let Some(ty) = param.ty.as_ref() {
            let ty_str = render_signature_type(ty, ptr_bits);
            if (!type_name_is_generic(&ty_str)
                || param_has_authoritative_named_scalar_role(param, ptr_bits, type_db))
                && let Some(inferred_param) = signature_out.params.get_mut(idx)
            {
                inferred_param.param_type = ty_str;
            }
        }
        if !is_generic_arg_name(&param.name)
            && let Some(inferred_param) = signature_out.params.get_mut(idx)
        {
            inferred_param.name = param.name.clone();
        }
    }

    signature_out.signature = format_signature(
        &signature_out.function_name,
        &signature_out.ret_type,
        &signature_out.params,
    );
}

pub(crate) fn signature_strength(signature: &FunctionSignatureSpec) -> u8 {
    crate::signature_strength(signature)
}

pub(crate) fn signature_param_count_is_authoritative(signature: &FunctionSignatureSpec) -> bool {
    crate::signature_param_count_is_authoritative(signature)
}

pub(crate) fn signature_has_typed_param_count_evidence(signature: &FunctionSignatureSpec) -> bool {
    !signature.params.is_empty()
        && signature_strength(signature) >= crate::SIGNATURE_PROJECTION_STRONG_CONFIDENCE
}

pub(crate) fn signature_param_allows_local_struct_override(
    param: Option<&FunctionParamSpec>,
    ptr_bits: u32,
) -> bool {
    let Some(param) = param else {
        return true;
    };

    if is_generic_signature_type(param.ty.as_ref()) {
        return true;
    }

    if matches!(
        param.ty.as_ref(),
        Some(CTypeLike::Pointer(inner)) if matches!(inner.as_ref(), CTypeLike::Typedef { .. })
    ) {
        return false;
    }

    is_generic_arg_name(&param.name)
        && matches!(
            param.ty.as_ref(),
            Some(CTypeLike::Int { bits, .. }) if *bits == ptr_bits
        )
}

pub(crate) fn merge_slot_type_overrides_into_signature(
    mut signature: Option<FunctionSignatureSpec>,
    slot_type_overrides: &HashMap<usize, String>,
    indexed_local_struct_refinement_slots: &HashSet<usize>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
    preserve_param_count: bool,
) -> Option<FunctionSignatureSpec> {
    if slot_type_overrides.is_empty() {
        return signature;
    }

    let max_slot = slot_type_overrides.keys().copied().max()?;
    let sig = signature.get_or_insert_with(Default::default);
    let allow_param_count_extension =
        !preserve_param_count && !signature_has_typed_param_count_evidence(sig);
    while allow_param_count_extension && sig.params.len() <= max_slot {
        let idx = sig.params.len();
        sig.params.push(FunctionParamSpec {
            name: format!("arg{}", idx + 1),
            ty: None,
        });
    }

    for (slot, raw_ty) in slot_type_overrides {
        if *slot >= sig.params.len() {
            continue;
        }
        let Some(parsed) = parse_c_type_like(raw_ty, ptr_bits) else {
            continue;
        };
        let param = &mut sig.params[*slot];
        if indexed_local_struct_refinement_slots.contains(slot)
            || (!signature_param_blocks_generated_local_struct_override(
                Some(param),
                raw_ty,
                type_db,
                ptr_bits,
            ) && signature_param_allows_local_struct_override(Some(param), ptr_bits))
        {
            param.ty = Some(parsed);
        }
    }

    signature
}

pub(crate) fn format_signature(
    function_name: &str,
    ret_type: &str,
    params: &[InferredSignatureParam],
) -> String {
    crate::format_signature_prototype(function_name, ret_type, params)
}
