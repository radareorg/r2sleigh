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
                    .map(|param| param.ty.clone())
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
) {
    let pointer_ty = CTypeLike::Pointer(Box::new(CTypeLike::Void));

    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature);
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

        if merged_param
            .as_ref()
            .is_some_and(|param| param_has_authoritative_named_scalar_role(param))
            || inferred_param
                .as_ref()
                .is_some_and(|param| inferred_param_has_authoritative_named_scalar_role(param))
        {
            continue;
        }

        let merged_is_generic = merged_param.as_ref().is_some_and(|param| {
            param.ty.as_ref().is_none_or(|ty| {
                is_generic_signature_type(Some(ty))
                    || matches!(
                        crate::word_free(ty),
                        CTypeLike::Int {
                            bits,
                            signedness: Signedness::Signed
                                | Signedness::Unsigned
                                | Signedness::Unknown,
                        } if *bits == ptr_bits
                    )
            })
        });

        let inferred_is_generic = inferred_param
            .as_ref()
            .is_some_and(|param| inferred_type_is_word(Some(&param.ty), ptr_bits));

        if merged_is_generic && let Some(param) = merged_param {
            param.ty = Some(pointer_ty.clone());
        }
        if inferred_is_generic && let Some(param) = inferred_param {
            param.ty = pointer_ty.clone();
        }
    }
}

pub(crate) fn upgrade_param_indices_to_pointer(
    indices: impl IntoIterator<Item = usize>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
) {
    let pointer_ty = CTypeLike::Pointer(Box::new(CTypeLike::Void));

    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature);
    }

    let Some(signature) = merged_signature.as_mut() else {
        return;
    };

    for idx in indices {
        let merged_param = signature.params.get_mut(idx);
        let inferred_param = inferred_signature.params.get_mut(idx);

        if merged_param
            .as_ref()
            .is_some_and(|param| param_has_authoritative_named_scalar_role(param))
            || inferred_param
                .as_ref()
                .is_some_and(|param| inferred_param_has_authoritative_named_scalar_role(param))
        {
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

        let inferred_is_generic = inferred_param
            .as_ref()
            .is_some_and(|param| inferred_type_is_word(Some(&param.ty), ptr_bits));

        if merged_is_generic && let Some(param) = merged_param {
            param.ty = Some(pointer_ty.clone());
        }
        if inferred_is_generic && let Some(param) = inferred_param {
            param.ty = pointer_ty.clone();
        }
    }
}

pub(crate) fn type_is_authoritative_named_scalar_role(ty: &CTypeLike) -> bool {
    match ty {
        CTypeLike::Bool | CTypeLike::Enum(_) => true,
        CTypeLike::Typedef { name, ty } => typedef_resolves(name, ty),
        _ => false,
    }
}

pub(crate) fn param_has_authoritative_named_scalar_role(param: &FunctionParamSpec) -> bool {
    !semantic_role_param_name_is_weak(&param.name)
        && param
            .ty
            .as_ref()
            .is_some_and(type_is_authoritative_named_scalar_role)
}

pub(crate) fn inferred_param_has_authoritative_named_scalar_role(
    param: &InferredSignatureParam,
) -> bool {
    if semantic_role_param_name_is_weak(&param.name) {
        return false;
    }
    type_is_authoritative_named_scalar_role(&preserving_c_typedefs(&param.ty))
}

pub(crate) fn summary_hint_can_replace_weak_existing(
    existing: &CTypeLike,
    hint: &CTypeLike,
    ptr_bits: u32,
) -> bool {
    crate::summary_hint_can_replace_weak_existing(existing, hint, ptr_bits)
}

pub(crate) fn upgrade_param_type_hints(
    hints: &BTreeMap<usize, CTypeLike>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
) {
    if hints.is_empty() {
        return;
    }
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature);
    }

    if let Some(signature) = merged_signature.as_mut() {
        for (idx, hint) in hints {
            if let Some(param) = signature.params.get_mut(*idx) {
                let should_replace = param.ty.as_ref().is_none_or(|existing| {
                    summary_hint_can_replace_weak_existing(existing, hint, ptr_bits)
                });
                if should_replace {
                    param.ty = Some(hint.clone());
                }
            }
        }
    }

    for (idx, hint) in hints {
        if let Some(param) = inferred_signature.params.get_mut(*idx) {
            let should_replace = inferred_type_is_generic(Some(&param.ty), ptr_bits)
                || summary_hint_can_replace_weak_existing(&param.ty, hint, ptr_bits);
            if should_replace {
                param.ty = hint.clone();
            }
        }
    }
}

pub(crate) fn upgrade_return_type_hint(
    hint: Option<&CTypeLike>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
) -> bool {
    let Some(hint) = hint else {
        return false;
    };
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature);
    }

    let mut changed = false;
    if let Some(signature) = merged_signature.as_mut() {
        let should_replace = signature.ret_type.as_ref().is_none_or(|existing| {
            summary_hint_can_replace_weak_existing(existing, hint, ptr_bits)
                || matches!(hint, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        existing,
                        Some(hint),
                        ptr_bits,
                    )
        });
        if should_replace && signature.ret_type.as_ref() != Some(hint) {
            signature.ret_type = Some(hint.clone());
            changed = true;
        }
    }

    let existing_ty = inferred_signature.ret_type.clone();
    let should_replace = inferred_type_is_generic(existing_ty.as_ref(), ptr_bits)
        || existing_ty.as_ref().is_some_and(|existing| {
            summary_hint_can_replace_weak_existing(existing, hint, ptr_bits)
                || matches!(hint, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        existing,
                        Some(hint),
                        ptr_bits,
                    )
        });
    if should_replace && inferred_signature.ret_type.as_ref() != Some(hint) {
        inferred_signature.ret_type = Some(hint.clone());
        changed = true;
    }
    changed
}

pub(crate) fn upgrade_param_name_hints(
    hints: &BTreeMap<usize, String>,
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
) {
    if hints.is_empty() {
        return;
    }
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature);
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
) {
    let Some(summary) = summary_view.root_summary() else {
        if let Some(projection) = semantic_projection {
            upgrade_return_type_hint(
                projection.return_type_hint.as_ref(),
                merged_signature,
                inferred_signature,
                ptr_bits,
            );
            upgrade_param_name_hints(
                &projection.param_name_hints,
                merged_signature,
                inferred_signature,
            );
            upgrade_param_indices_to_pointer(
                projection_pointer_upgrade_indices(projection),
                merged_signature,
                inferred_signature,
                ptr_bits,
            );
            upgrade_param_type_hints(
                &projection.param_type_hints,
                merged_signature,
                inferred_signature,
                ptr_bits,
            );
        }
        return;
    };
    maybe_upgrade_param_to_pointer(summary, merged_signature, inferred_signature, ptr_bits);
    if let Some(projection) = semantic_projection {
        upgrade_return_type_hint(
            projection.return_type_hint.as_ref(),
            merged_signature,
            inferred_signature,
            ptr_bits,
        );
        upgrade_param_name_hints(
            &projection.param_name_hints,
            merged_signature,
            inferred_signature,
        );
        upgrade_param_indices_to_pointer(
            projection_pointer_upgrade_indices(projection),
            merged_signature,
            inferred_signature,
            ptr_bits,
        );
        upgrade_param_type_hints(
            &projection.param_type_hints,
            merged_signature,
            inferred_signature,
            ptr_bits,
        );
    }
    let Some(ret_ty) =
        infer_interproc_return_type(summary, merged_signature.as_ref(), inferred_signature)
    else {
        return;
    };

    let should_override = merged_signature
        .as_ref()
        .and_then(|signature| signature.ret_type.as_ref())
        .is_none_or(|ty| {
            is_generic_signature_type(Some(ty))
                || summary_hint_can_replace_weak_existing(ty, &ret_ty, ptr_bits)
                || matches!(summary.return_relation, SummaryReturnRelation::HeapAlloc)
                    && crate::signature_hint_can_replace_existing(ty, Some(&ret_ty), ptr_bits,
            )
                || matches!(ret_ty, CTypeLike::Void)
                    && crate::signature_return_hint_can_replace_existing(
                        ty,
                        Some(&ret_ty),
                        ptr_bits,
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
        *merged_signature = inferred_signature_to_spec(inferred_signature);
    }
    if let Some(signature) = merged_signature.as_mut() {
        signature.ret_type = Some(ret_ty.clone());
    }

    let existing = inferred_signature.ret_type.as_ref();
    if inferred_type_is_generic(existing, ptr_bits)
        || existing.is_some_and(|ty| summary_hint_can_replace_weak_existing(ty, &ret_ty, ptr_bits))
        || matches!(summary.return_relation, SummaryReturnRelation::HeapAlloc)
            && existing.is_some_and(|ty| {
                crate::signature_hint_can_replace_existing(ty, Some(&ret_ty), ptr_bits)
            })
        || matches!(ret_ty, CTypeLike::Void)
            && existing.is_some_and(|ty| {
                crate::signature_return_hint_can_replace_existing(ty, Some(&ret_ty), ptr_bits)
            })
        || inferred_type_is_word(existing, ptr_bits)
    {
        inferred_signature.ret_type = Some(ret_ty);
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
                    target.name = r2source::positional_parameter_name(idx);
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
        let ty = signature
            .params
            .get(idx)
            .and_then(|param| param.ty.clone())
            .unwrap_or_else(|| CTypeLike::Pointer(Box::new(CTypeLike::Void)));
        signature_out.params.push(InferredSignatureParam {
            name: r2source::positional_parameter_name(idx),
            ty,
        });
    }

    if let Some(ret_ty) = signature.ret_type.as_ref()
        && !is_generic_signature_type(signature.ret_type.as_ref())
    {
        signature_out.ret_type = Some(ret_ty.clone());
    }

    for (idx, param) in signature.params.iter().enumerate() {
        if let Some(ty) = param.ty.as_ref()
            && (!inferred_type_is_generic(Some(ty), ptr_bits)
                || param_has_authoritative_named_scalar_role(param))
            && let Some(inferred_param) = signature_out.params.get_mut(idx)
        {
            inferred_param.ty = ty.clone();
        }
        if !is_generic_arg_name(&param.name)
            && let Some(inferred_param) = signature_out.params.get_mut(idx)
        {
            inferred_param.name = param.name.clone();
        }
    }
}

pub(crate) fn signature_param_count_is_authoritative(signature: &FunctionSignatureSpec) -> bool {
    crate::signature_param_count_is_authoritative(signature)
}

/// Whether an inferred type says nothing a weaker hint may not replace: none, a carrier of a width
/// C has no integer for, an opaque or `void`/`char` pointer, or a C integer name (D268).
pub(crate) fn inferred_type_is_generic(ty: Option<&CTypeLike>, ptr_bits: u32) -> bool {
    ty.is_none_or(|ty| {
        type_is_generic(&crate::signature_infer::materialize_signature_type_like(
            ty.clone(),
            ptr_bits,
        ))
    })
}

fn type_is_generic(ty: &CTypeLike) -> bool {
    let named = |ty: &CTypeLike, names: &[&str]| matches!(ty, CTypeLike::Typedef { name, .. } if names.contains(&name.trim()));
    let opaque = |ty: &CTypeLike| match ty {
        CTypeLike::Struct(tag) | CTypeLike::Union(tag) | CTypeLike::Enum(tag) => {
            type_name_is_opaque_placeholder(tag)
        }
        _ => false,
    };
    match ty {
        CTypeLike::BitVector(_) => true,
        CTypeLike::Pointer(pointee) => {
            let pointee = match pointee.as_ref() {
                CTypeLike::Const(inner) => inner.as_ref(),
                pointee => pointee,
            };
            matches!(pointee, CTypeLike::Void | CTypeLike::Unknown)
                || named(pointee, &["char", "signed char", "unsigned char"])
                || opaque(pointee)
        }
        ty => {
            named(
                ty,
                &["int", "unsigned", "unsigned int", "long", "unsigned long"],
            ) || opaque(ty)
        }
    }
}

/// Whether an inferred type is generic or a bare machine word.
fn inferred_type_is_word(ty: Option<&CTypeLike>, ptr_bits: u32) -> bool {
    inferred_type_is_generic(ty, ptr_bits)
        || ty.is_some_and(
            |ty| matches!(ty.unaliased(), CTypeLike::Int { bits, .. } if *bits == ptr_bits),
        )
}
