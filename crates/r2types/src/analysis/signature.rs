//! The function signature, from the body and from what was declared.

use super::*;

/// A typed C name that is no plain word: `bool`, an enum, a typedef that resolves.
fn type_is_authoritative_named_scalar_role(ty: &CTypeLike) -> bool {
    match ty {
        CTypeLike::Bool | CTypeLike::Enum(_) => true,
        CTypeLike::Typedef { name, ty } => typedef_resolves(name, ty),
        _ => false,
    }
}

pub(crate) fn param_has_authoritative_named_scalar_role(param: &FunctionParamSpec) -> bool {
    !crate::signature_param_name_is_weak(&param.name)
        && param
            .ty
            .as_ref()
            .is_some_and(type_is_authoritative_named_scalar_role)
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
