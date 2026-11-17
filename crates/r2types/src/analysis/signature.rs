//! The function signature, from the body and from what was declared.

use super::*;

pub(crate) fn merge_local_signature_into_merged_signature(
    external: Option<FunctionSignatureSpec>,
    local: Option<FunctionSignatureSpec>,
) -> Option<FunctionSignatureSpec> {
    match (external, local) {
        (None, None) => None,
        (Some(signature), None) => Some(signature),
        (None, Some(signature)) => Some(signature),
        (Some(mut external), Some(local)) => {
            let external_param_count_is_authoritative = external.basis == SignatureBasis::Declared;
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
                        name: None,
                        ty: None,
                    });
            }

            for (idx, local_param) in local.params.into_iter().enumerate() {
                if idx >= external.params.len() {
                    continue;
                }
                let target = &mut external.params[idx];
                if target.name.is_none() {
                    target.name = local_param.name.clone();
                }
                // A declared parameter's stated type stands; inference fills what it leaves (D481).
                if external_param_count_is_authoritative && target.ty.is_some() {
                    continue;
                }
                if local_signature_should_override_external(
                    local_param.ty.as_ref(),
                    target.ty.as_ref(),
                ) || (!external_param_count_is_authoritative
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
