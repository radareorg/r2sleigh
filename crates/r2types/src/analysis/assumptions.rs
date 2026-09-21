//! What an operator asserted about a type, applied to the context.

use super::*;

pub(crate) fn assumption_type_hint(
    assumption: &r2ssa::AnalysisAssumption,
    ptr_bits: u32,
) -> Option<CTypeLike> {
    let r2ssa::AssumptionValue::TypeHint { ty } = &assumption.value else {
        return None;
    };
    parse_signature_type_preserving_c_typedefs(ty, ptr_bits)
}

pub(crate) fn type_hint_conflicts(existing: &CTypeLike, hint: &CTypeLike, ptr_bits: u32) -> bool {
    !crate::signature_infer::signature_types_are_equivalent(existing, hint, ptr_bits)
}

pub(crate) fn type_hint_requires_semantic_corroboration(
    assumption: &r2ssa::AnalysisAssumption,
) -> bool {
    matches!(assumption.provenance, r2ssa::AssumptionProvenance::Derived)
}

pub(crate) fn type_hint_can_replace_weak_existing(
    assumption: &r2ssa::AnalysisAssumption,
    existing: &CTypeLike,
    binding_name: Option<&str>,
    ptr_bits: u32,
) -> bool {
    if is_generic_signature_type(Some(existing)) {
        return true;
    }

    match assumption.provenance {
        r2ssa::AssumptionProvenance::User => {
            binding_name.is_none_or(is_generic_arg_name)
                && matches!(existing, CTypeLike::Int { .. })
        }
        r2ssa::AssumptionProvenance::ImportedContext => {
            let generic_binding = binding_name.is_none_or(is_generic_arg_name);
            generic_binding
                && matches!(
                    existing,
                    CTypeLike::Int {
                        bits,
                        signedness: Signedness::Signed
                            | Signedness::Unsigned
                            | Signedness::Unknown,
                    } if *bits == ptr_bits
                )
        }
        r2ssa::AssumptionProvenance::Replay | r2ssa::AssumptionProvenance::Derived => false,
    }
}

pub(crate) fn apply_type_hint_to_signature_param(
    merged_signature: &mut Option<FunctionSignatureSpec>,
    inferred_signature: &mut InferredSignature,
    index: usize,
    assumption: &r2ssa::AnalysisAssumption,
    hint: &CTypeLike,
    ptr_bits: u32,
) -> Result<bool, String> {
    if merged_signature.is_none() {
        *merged_signature = inferred_signature_to_spec(inferred_signature, ptr_bits);
    }

    let mut applied = false;
    if let Some(signature) = merged_signature.as_mut() {
        let Some(param) = signature.params.get_mut(index) else {
            return Ok(false);
        };
        match param.ty.as_ref() {
            None => {
                param.ty = Some(hint.clone());
                applied = true;
            }
            Some(existing)
                if type_hint_can_replace_weak_existing(
                    assumption,
                    existing,
                    Some(&param.name),
                    ptr_bits,
                ) =>
            {
                param.ty = Some(hint.clone());
                applied = true;
            }
            Some(existing) if !type_hint_conflicts(existing, hint, ptr_bits) => {
                applied = true;
            }
            Some(existing) => {
                return Err(format!(
                    "parameter {} already has incompatible type {}",
                    index,
                    render_signature_type(existing, ptr_bits)
                ));
            }
        }
    }

    if let Some(param) = inferred_signature.params.get_mut(index) {
        let existing_ty = parse_c_type_like(&param.param_type, ptr_bits);
        let can_replace = type_name_is_generic(&param.param_type)
            || existing_ty.as_ref().is_some_and(|existing| {
                type_hint_can_replace_weak_existing(
                    assumption,
                    existing,
                    Some(&param.name),
                    ptr_bits,
                )
            });
        if can_replace {
            param.param_type = render_signature_type(hint, ptr_bits);
            applied = true;
        }
    }

    Ok(applied)
}

pub(crate) fn apply_type_hint_assumptions_to_context(
    parsed_context: &mut ParsedExternalContext,
    inferred_signature: &mut InferredSignature,
    ptr_bits: u32,
    semantic_projection: Option<&SemanticTypeProjection>,
    registers: &crate::RegisterIdentity,
) -> r2ssa::AssumptionUsageReport {
    let mut usage = r2ssa::AssumptionUsageReport::default();
    let inferred_register_params =
        inferred_signature_abi_register_params(inferred_signature, ptr_bits);
    if inferred_register_params.len() > parsed_context.register_params.len() {
        parsed_context
            .register_params
            .extend_from_slice(&inferred_register_params[parsed_context.register_params.len()..]);
    }
    let assumptions = parsed_context.assumptions.items.clone();
    for assumption in &assumptions {
        let Some(hint) = assumption_type_hint(assumption, ptr_bits) else {
            continue;
        };
        match &assumption.subject {
            r2ssa::AssumptionSubject::Parameter { index } => {
                let corroborated = semantic_projection.is_some_and(|projection| {
                    projection.corroborates_param_type_hint(*index, &hint)
                });
                if type_hint_requires_semantic_corroboration(assumption) && !corroborated {
                    usage.mark_ignored(assumption);
                    continue;
                }
                match apply_type_hint_to_signature_param(
                    &mut parsed_context.merged_signature,
                    inferred_signature,
                    *index,
                    assumption,
                    &hint,
                    ptr_bits,
                ) {
                    Ok(true) => usage.mark_applied(assumption),
                    Ok(false) => usage.mark_ignored(assumption),
                    Err(reason) => usage.mark_conflict(assumption, reason),
                }
            }
            r2ssa::AssumptionSubject::Register { name } => {
                let Some((idx, reg_param)) = parsed_context
                    .register_params
                    .iter_mut()
                    .enumerate()
                    .find(|(_, param)| {
                        registers.same_parameter_storage(&param.reg, name)
                            || param.name.eq_ignore_ascii_case(name)
                    })
                else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                let corroborated = semantic_projection
                    .is_some_and(|projection| projection.corroborates_param_type_hint(idx, &hint));
                if type_hint_requires_semantic_corroboration(assumption) && !corroborated {
                    usage.mark_ignored(assumption);
                    continue;
                }

                let reg_applied = match reg_param.ty.as_ref() {
                    None => {
                        reg_param.ty = Some(hint.clone());
                        true
                    }
                    Some(existing)
                        if type_hint_can_replace_weak_existing(
                            assumption,
                            existing,
                            Some(&reg_param.name),
                            ptr_bits,
                        ) =>
                    {
                        reg_param.ty = Some(hint.clone());
                        true
                    }
                    Some(existing) if !type_hint_conflicts(existing, &hint, ptr_bits) => true,
                    Some(existing) => {
                        usage.mark_conflict(
                            assumption,
                            format!(
                                "register {} already has incompatible type {}",
                                name,
                                render_signature_type(existing, ptr_bits)
                            ),
                        );
                        continue;
                    }
                };
                match apply_type_hint_to_signature_param(
                    &mut parsed_context.merged_signature,
                    inferred_signature,
                    idx,
                    assumption,
                    &hint,
                    ptr_bits,
                ) {
                    Ok(true) => usage.mark_applied(assumption),
                    Ok(false) if reg_applied => usage.mark_applied(assumption),
                    Ok(false) => usage.mark_ignored(assumption),
                    Err(reason) => usage.mark_conflict(assumption, reason),
                }
            }
            r2ssa::AssumptionSubject::StackSlot { base, offset } => {
                let key = StackSlotKey {
                    base: *base,
                    offset: *offset,
                };
                let corroborated = semantic_projection.is_some_and(|projection| {
                    parsed_context
                        .stack_slots
                        .get(&key)
                        .and_then(|slot| slot.param_index)
                        .is_some_and(|slot| {
                            projection.corroborates_stack_slot_type_hint(slot, &hint)
                        })
                });
                if type_hint_requires_semantic_corroboration(assumption) && !corroborated {
                    usage.mark_ignored(assumption);
                    continue;
                }
                let Some(slot) = parsed_context.stack_slots.get_mut(&key) else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                let mut applied = match slot.ty.as_ref() {
                    None => {
                        slot.ty = Some(hint.clone());
                        true
                    }
                    Some(existing)
                        if type_hint_can_replace_weak_existing(
                            assumption,
                            existing,
                            Some(&slot.name),
                            ptr_bits,
                        ) =>
                    {
                        slot.ty = Some(hint.clone());
                        true
                    }
                    Some(existing) if !type_hint_conflicts(existing, &hint, ptr_bits) => true,
                    Some(existing) => {
                        usage.mark_conflict(
                            assumption,
                            format!(
                                "stack slot {}@{} already has incompatible type {}",
                                match key.base {
                                    ExternalStackBase::FramePointer => "bp",
                                    ExternalStackBase::StackPointer => "sp",
                                    ExternalStackBase::Realigned => "aligned sp",
                                },
                                key.offset,
                                render_signature_type(existing, ptr_bits)
                            ),
                        );
                        continue;
                    }
                };

                if let Some(index) = slot.param_index {
                    match apply_type_hint_to_signature_param(
                        &mut parsed_context.merged_signature,
                        inferred_signature,
                        index,
                        assumption,
                        &hint,
                        ptr_bits,
                    ) {
                        Ok(result) => applied |= result,
                        Err(reason) => {
                            usage.mark_conflict(assumption, reason);
                            continue;
                        }
                    }
                }
                if applied {
                    usage.mark_applied(assumption);
                } else {
                    usage.mark_ignored(assumption);
                }
            }
            _ => {}
        }
    }
    usage
}

pub(crate) fn applied_type_assumption_parameter_slots(
    usage: &r2ssa::AssumptionUsageReport,
    parsed_context: &ParsedExternalContext,
    registers: &crate::RegisterIdentity,
) -> HashSet<usize> {
    usage
        .applied
        .iter()
        .filter_map(|assumption| match &assumption.subject {
            r2ssa::AssumptionSubject::Parameter { index } => Some(*index),
            r2ssa::AssumptionSubject::Register { name } => {
                parsed_context.register_params.iter().position(|param| {
                    registers.same_parameter_storage(&param.reg, name)
                        || param.name.eq_ignore_ascii_case(name)
                })
            }
            r2ssa::AssumptionSubject::StackSlot { base, offset } => parsed_context
                .stack_slots
                .get(&StackSlotKey {
                    base: *base,
                    offset: *offset,
                })
                .and_then(|slot| slot.param_index),
            r2ssa::AssumptionSubject::Predicate { .. }
            | r2ssa::AssumptionSubject::Target { .. }
            | r2ssa::AssumptionSubject::MemoryWindow { .. } => None,
        })
        .collect()
}

pub(crate) fn inferred_signature_abi_register_params(
    signature: &InferredSignature,
    ptr_bits: u32,
) -> Vec<ExternalRegisterParamSpec> {
    if ptr_bits != 64 {
        return Vec::new();
    }
    let arch = signature.arch.trim().to_ascii_lowercase();
    let callconv = signature.callconv.trim().to_ascii_lowercase();
    let is_sysv64 = matches!(arch.as_str(), "x86-64" | "x86_64" | "x64" | "amd64")
        && matches!(callconv.as_str(), "amd64" | "sysv" | "sysv64" | "x86-64");
    // AArch64 has one standard convention for these registers, and radare2
    // leaves the calling-convention field empty rather than naming it, so an
    // unnamed convention on that architecture is AAPCS64 rather than unknown.
    let is_aapcs64 = matches!(arch.as_str(), "aarch64" | "arm64")
        && matches!(
            callconv.as_str(),
            "" | "aapcs" | "aapcs64" | "arm64" | "aarch64"
        );
    const SYSV64_ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    const AAPCS64_ARG_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
    let arg_regs: &[&str] = if is_sysv64 {
        &SYSV64_ARG_REGS
    } else if is_aapcs64 {
        &AAPCS64_ARG_REGS
    } else {
        return Vec::new();
    };
    signature
        .params
        .iter()
        .take(arg_regs.len())
        .enumerate()
        .map(|(idx, param)| ExternalRegisterParamSpec {
            name: param.name.clone(),
            ty: parse_c_type_like(&param.param_type, ptr_bits),
            reg: arg_regs[idx].to_string(),
        })
        .collect()
}
