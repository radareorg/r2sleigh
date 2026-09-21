//! Where a parameter lives when the frame keeps it in memory.

use super::*;

pub(crate) fn canonicalize_param_home_stack_slots(
    merged_signature: Option<&FunctionSignatureSpec>,
    register_params: &[crate::context::ExternalRegisterParamSpec],
    stack_slots: &mut BTreeMap<StackSlotKey, ExternalStackVarSpec>,
    ssa_blocks: &[SSABlock],
    prep_facts: Option<&r2ssa::DecompilePrepFacts>,
    registers: &crate::RegisterIdentity,
) {
    if register_params.is_empty() || ssa_blocks.is_empty() {
        return;
    }

    let trivial_value_sources = collect_trivial_value_sources(ssa_blocks);
    let mut slot_addr_by_var = HashMap::<String, StackSlotKey>::new();
    for block in ssa_blocks {
        for op in &block.ops {
            match op {
                SSAOp::IntAdd { dst, .. } => {
                    let slot_key = prep_facts
                        .and_then(|facts| facts.stack_address_root_of(dst))
                        .copied();
                    if let Some(slot_key) = slot_key {
                        slot_addr_by_var.insert(dst.display_name(), slot_key);
                    }
                }
                SSAOp::IntSub { dst, .. } => {
                    let slot_key = prep_facts
                        .and_then(|facts| facts.stack_address_root_of(dst))
                        .copied();
                    if let Some(slot_key) = slot_key {
                        slot_addr_by_var.insert(dst.display_name(), slot_key);
                    }
                }
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr,
                    val,
                } => {
                    let Some(source_slot_key) = slot_addr_by_var
                        .get(&addr.display_name())
                        .cloned()
                        .or_else(|| {
                            prep_facts
                                .and_then(|facts| facts.stack_address_root_of(addr))
                                .copied()
                        })
                    else {
                        continue;
                    };
                    let rooted_val = resolve_trivial_value_root(&trivial_value_sources, val);
                    let Some((param_index, param_reg)) =
                        register_params.iter().enumerate().find_map(|(idx, param)| {
                            registers
                                .same_parameter_storage(&param.reg, rooted_val.name())
                                .then_some((idx, param.reg.clone()))
                        })
                    else {
                        continue;
                    };
                    if rooted_val.version != 0 {
                        continue;
                    }
                    let param_name = merged_signature
                        .and_then(|sig| sig.params.get(param_index))
                        .map(|param| param.name.clone())
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| format!("arg{}", param_index + 1));
                    let slot_key = source_slot_key;
                    if slot_key != source_slot_key
                        && let Some(source_slot) = stack_slots.remove(&source_slot_key)
                    {
                        stack_slots.entry(slot_key).or_insert(source_slot);
                    }
                    let slot =
                        stack_slots
                            .entry(slot_key)
                            .or_insert_with(|| ExternalStackVarSpec {
                                name: format!("{param_name}_home"),
                                ty: merged_signature
                                    .and_then(|sig| sig.params.get(param_index))
                                    .and_then(|param| param.ty.clone()),
                                role: ExternalStackSlotRole::Unknown,
                                param_index: None,
                                param_name: None,
                                source_reg: None,
                            });
                    if !matches!(
                        slot.role,
                        ExternalStackSlotRole::Unknown
                            | ExternalStackSlotRole::Local
                            | ExternalStackSlotRole::StackArg
                    ) {
                        continue;
                    }
                    slot.role = ExternalStackSlotRole::ParamHome;
                    slot.param_index = Some(param_index);
                    slot.param_name = Some(param_name.clone());
                    slot.source_reg = Some(param_reg);
                    if is_low_quality_stack_name(&slot.name) || slot.name.is_empty() {
                        slot.name = format!("{param_name}_home");
                    }
                }
                _ => {}
            }
        }
    }
}

pub(crate) fn collect_trivial_value_sources(ssa_blocks: &[SSABlock]) -> HashMap<SSAVar, SSAVar> {
    let mut trivial_value_sources = HashMap::new();
    for block in ssa_blocks {
        for op in &block.ops {
            match op {
                SSAOp::Copy { dst, src }
                | SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src } => {
                    trivial_value_sources.insert(dst.clone(), src.clone());
                }
                SSAOp::Subpiece { dst, src, offset } if *offset == 0 => {
                    trivial_value_sources.insert(dst.clone(), src.clone());
                }
                _ => {}
            }
        }
    }
    trivial_value_sources
}

pub(crate) fn resolve_trivial_value_root(
    trivial_value_sources: &HashMap<SSAVar, SSAVar>,
    value: &SSAVar,
) -> SSAVar {
    let mut current = value.clone();
    let mut seen = HashSet::new();
    while seen.insert(current.clone()) {
        let Some(next) = trivial_value_sources.get(&current) else {
            break;
        };
        current = next.clone();
    }
    current
}

pub(crate) fn apply_canonical_stack_width_types(
    stack_slots: &mut BTreeMap<StackSlotKey, ExternalStackVarSpec>,
    vars: &[RecoveredVariable],
    candidates: &[VarTypeCandidate],
) {
    let candidates = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .evidence
                .contains(&TypeEvidence::CanonicalStackAccessWidth)
        })
        .map(|candidate| (RecoveredVarKey::for_type_candidate(candidate), candidate))
        .collect::<BTreeMap<_, _>>();
    for var in vars {
        let Some(slot_key) = stack_slot_key_for_recovered_var(var) else {
            continue;
        };
        let Some(slot) = stack_slots.get_mut(&slot_key) else {
            continue;
        };
        let Some(candidate) = candidates.get(&RecoveredVarKey::for_recovered_var(var)) else {
            continue;
        };
        let candidate_ty = candidate.var_type.clone();
        let CTypeLike::Int {
            bits: candidate_bits,
            ..
        } = &candidate_ty
        else {
            continue;
        };
        let Some(CTypeLike::Int {
            bits: existing_bits,
            ..
        }) = slot.ty.as_ref()
        else {
            continue;
        };
        let has_exact_signedness = candidate
            .evidence
            .contains(&TypeEvidence::CanonicalStackSignedness);
        if existing_bits != candidate_bits
            || (has_exact_signedness && slot.ty.as_ref() != Some(&candidate_ty))
        {
            slot.ty = Some(candidate_ty);
        }
    }
}
