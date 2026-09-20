use super::*;

use super::rules::{ParameterCandidate, parameter_candidates, parameter_width};

fn binding_declaration_width(ty: &CType, ptr_bits: u32) -> Option<u32> {
    super::rules::declaration_type_width(ty, ptr_bits)
}

/// Resolve the certificate relation independently of construction's union-find.
///
/// The graph is bipartite: values point to every exact upstream certificate that
/// contains them, and certificate identities point back to their resolved member
/// sets. A sorted BFS computes each transitive component without depending on the
/// construction representative, union schedule, or component accumulator.
#[cfg(test)]
pub(super) fn seal_binding_components(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &MachineProjection,
) -> Result<Vec<SealBindingComponent>, BindingPlanBuildError> {
    let eligible = super::rules::component_eligible_values(source_owned, projection)?;
    seal_binding_components_with(
        source_owned,
        projection,
        &eligible,
        source_owned.source().value_liveness(),
    )
}

fn seal_binding_components_with(
    source_owned: &SourceOwnedFunctionFacts,
    _projection: &MachineProjection,
    eligible: &[bool],
    liveness: &r2ssa::liveness::ValueLiveness,
) -> Result<Vec<SealBindingComponent>, BindingPlanBuildError> {
    // One derivation. The partition is a sequence of unions each judged by
    // liveness, with literals offered last and only to a run a merge of which
    // reads them; a second procedure that had to reproduce that order
    // disagreed with the first the moment the order mattered, and what the
    // seal checks is that the bindings the plan made are exactly these
    // components, not that two procedures agree.
    Ok(
        super::construction::binding_components_with(source_owned, eligible, liveness)?
            .into_iter()
            .map(|component| SealBindingComponent {
                members: component.members,
                sources: component.sources,
            })
            .collect(),
    )
}

/// Collect declaration-width evidence independently of construction's maximum.
///
/// Each member contributes the declaration width its own reads ask for.
/// Validation later proves minimality by requiring the declaration to satisfy
/// every lower bound and equal at least one witness. That is equivalent to the
/// least upper bound without sharing construction's `max` implementation.
fn seal_width_evidence(
    source_owned: &SourceOwnedFunctionFacts,
    machine_projection: &MachineProjection,
    component: &SealBindingComponent,
) -> Result<SealWidthEvidence, BindingPlanBuildError> {
    let mut lower_bounds = Vec::new();
    for value in &component.members {
        let read_end_bits = match super::construction::member_read_end_bits(
            source_owned,
            machine_projection,
            *value,
        )? {
            Ok(bits) => bits,
            Err(reason) => return Ok(SealWidthEvidence::Refused(reason)),
        };
        let Some(width_bits) = super::construction::declaration_width_holding(read_end_bits) else {
            return Ok(SealWidthEvidence::Refused(
                ValueRefusal::UnsupportedDeclarationWidth {
                    value: *value,
                    width_bits: read_end_bits,
                },
            ));
        };
        lower_bounds.push(width_bits);
    }
    Ok(SealWidthEvidence::Exact { lower_bounds })
}

/// Recompute the Stage 4 comparison oracle directly from the exact source.
///
/// The candidate plan's dispositions are intentionally not an input. This makes
/// a wrong plan disposition observable instead of validating the candidate
/// against itself.
///
/// The machine projection is a different thing and is taken rather than rebuilt.
/// It is derived from the source alone -- the plan owns one only because it
/// needs one -- and `BindingPlan::validate_source` has already proven the one
/// passed here is what this exact source produces. Lowering the whole arena a
/// second time is not a second opinion, only the same answer at the price of a
/// render: two of these ran per function before this, once in
/// `BindingPlan::build_shadow` and once here. What the oracle's independence
/// buys is that no plan *decision* reaches it, and that is unchanged.
pub(crate) fn build_upstream_shadow_oracle<'a>(
    source_owned: &SourceOwnedFunctionFacts,
    machine_projection: &'a MachineProjection,
    partition: &super::rules::RewriteInliningPartition,
) -> Result<UpstreamShadowOracle<'a>, BindingPlanBuildError> {
    let source = source_owned.source();
    let graph = source.graph();
    let return_controls = certified_return_control_values(source);
    let direct_control_targets = certified_direct_control_target_values(source);
    let direct_call_targets = super::certified_direct_call_target_values(source);
    let call_return_addresses = super::certified_call_return_address_values(source);
    let stack_frame_values = certified_stack_frame_values(source);
    let stack_geometry_values = certified_stack_geometry_values(source);
    let unobserved_values = source.unobserved_values();
    let structural_unused = source
        .obligations()
        .structural_unused_values(graph, source.unobserved_merges().unobserved_uses())
        .ok_or(BindingPlanBuildError::Seal(
            BindingPlanSourceMismatch::Authority,
        ))?;
    // Both kinds of deadness, derived the same way the plan derives them: no
    // reader in the graph at all, and every reader having stopped reading it
    // when the terms were rewritten.
    let boundary_reads = super::readers::BoundaryReads::compute(source);
    let plan_facts = super::rules::PlanFacts {
        owned: source_owned,
        projection: machine_projection,
        boundary: &boundary_reads,
    };
    let unread = super::rules::unread_defined_values(plan_facts);
    let unrendered = super::rules::unrendered_defined_values(plan_facts, &partition.canonical);
    let resolved = seal_binding_components_with(
        source_owned,
        machine_projection,
        &partition.component_eligible,
        &partition.liveness,
    )?;
    if u32::try_from(resolved.len()).is_err() {
        return Err(BindingPlanBuildError::TooManyBindings {
            count: resolved.len(),
        });
    }
    let literal_values = machine_projection
        .arena()
        .iter()
        .filter_map(|(_, expr)| match expr.kind() {
            MachineExprKind::Constant { binding, .. } => Some(binding.value()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let inlinable = &partition.inlinable;
    let mut values = vec![None; graph.values.len()];
    for graph_value in &graph.values {
        if return_controls.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::ReturnControl,
            ));
            continue;
        }
        if direct_control_targets.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::DirectControlTarget,
            ));
            continue;
        }
        if direct_call_targets.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::DirectCallTarget,
            ));
            continue;
        }
        if call_return_addresses.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::CallReturnAddress,
            ));
            continue;
        }
        if stack_frame_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::StackFrame,
            ));
            continue;
        }
        if stack_geometry_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::DeadStackBase,
            ));
            continue;
        }
        if source.unobserved_merges().contains(graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::UnobservedMerge,
            ));
            continue;
        }
        if unobserved_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::UnobservedValue,
            ));
            continue;
        }
        if structural_unused.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::UnusedStructuralValue,
            ));
            continue;
        }
        if unread.contains(&graph_value.id) || unrendered.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                r2ssa::ledger::ElisionReason::DeadUnusedTemporary,
            ));
            continue;
        }
        if graph_value.var.constant_bits().is_none() {
            if inlinable.contains(&graph_value.id) {
                values[graph_value.id.0 as usize] =
                    Some(UpstreamValueDisposition::InlineExpression);
            }
            continue;
        }
        values[graph_value.id.0 as usize] = Some(if literal_values.contains(&graph_value.id) {
            UpstreamValueDisposition::InlineConstant
        } else {
            {
                // Same switch the other refusals use. A missing literal
                // projection says only that some constant never reached the
                // machine arena; which constant, and what reads it, is what
                // tells you why no lowering path asked for it.
                if r2il::refusal_evidence::tracing() {
                    eprintln!(
                        "missing literal projection {:?} bits={:?} name={:?} uses={} defs={:?}",
                        graph_value.id,
                        graph_value.var.constant_bits(),
                        graph_value.var.name(),
                        graph.use_sites(graph_value.id).len(),
                        graph
                            .def_inst(graph_value.id)
                            .and_then(|inst| graph.inst(inst))
                            .map(|inst| format!("{:?}", inst.payload)
                                .chars()
                                .take(110)
                                .collect::<String>()),
                    );
                }
                // Classified exactly as `construction` classifies it: the two
                // derivations are compared, so a reason computed on one side
                // only is a disagreement rather than a better message.
                let unmodelled_userop = graph
                    .use_sites(graph_value.id)
                    .iter()
                    .filter_map(|site| graph.inst(site.inst))
                    .find_map(|inst| match &inst.payload {
                        r2ssa::InstPayload::Op(r2ssa::SSAOp::CallOther { userop, .. }) => {
                            Some(*userop)
                        }
                        _ => None,
                    });
                UpstreamValueDisposition::Refused(match unmodelled_userop {
                    Some(userop) => ValueRefusal::UnmodelledUserOperation {
                        value: graph_value.id,
                        userop,
                    },
                    None => ValueRefusal::MissingLiteralProjection {
                        value: graph_value.id,
                    },
                })
            }
        });
    }

    // The components are the partition; a member already answered for above
    // -- folded into its reader, elided, a literal -- keeps that answer, and
    // the object is the members that still need one. A component with none
    // is no object, the same rule construction applies.
    let mut components = Vec::with_capacity(resolved.len());
    for component in &resolved {
        let members = component
            .members
            .iter()
            .copied()
            .filter(|value| values[value.0 as usize].is_none())
            .collect::<BTreeSet<_>>();
        if members.is_empty() {
            continue;
        }
        let bound = SealBindingComponent {
            members,
            sources: component.sources.clone(),
        };
        let component_id = CanonicalComponentId(components.len() as u32);
        let disposition = match seal_width_evidence(source_owned, machine_projection, &bound)? {
            SealWidthEvidence::Exact { .. } => UpstreamValueDisposition::Bound {
                component: component_id,
            },
            SealWidthEvidence::Refused(reason) => UpstreamValueDisposition::Refused(reason),
        };
        for value in &bound.members {
            values[value.0 as usize] = Some(disposition);
        }
        components.push(
            bound
                .members
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
    }

    let values = values
        .into_iter()
        .enumerate()
        .map(|(index, disposition)| {
            disposition.ok_or(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::UnexpectedValueDisposition {
                    value: ValueId(index as u32),
                },
            ))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    Ok(UpstreamShadowOracle {
        machine_projection,
        components: components.into_boxed_slice(),
        values,
    })
}

impl BindingPlan {
    pub(super) fn validate_seal(
        &self,
        source_owned: &SourceOwnedFunctionFacts,
    ) -> Result<(), BindingPlanBuildError> {
        let source = source_owned.source();
        self.validate_source(source)
            .map_err(BindingPlanBuildError::Seal)?;
        let graph = source.graph();
        // The rewriter and partition are a function of the source and the
        // projection, and the seal cannot influence either, so the derivation
        // the plan already holds is the one a fresh derivation would produce.
        // This used to re-derive it, which cost a whole term arena to arrive at
        // the same answer.
        let sealed_canonical = &self.partition.canonical;
        for graph_value in &graph.values {
            let planned = self.partition.canonical.value(graph_value.id);
            let sealed = sealed_canonical.value(graph_value.id);
            let agrees = match (planned, sealed) {
                (Some(planned), Some(sealed)) => {
                    planned.canonical == sealed.canonical
                        && planned.discharges == sealed.discharges
                        && planned.multiplicity == sealed.multiplicity
                }
                (None, None) => true,
                _ => false,
            };
            if !agrees {
                return Err(BindingPlanBuildError::CanonicalDisagreement {
                    value: graph_value.id,
                });
            }
        }
        // Once per seal, not once per inlined value: this walks the whole
        // machine arena.
        let inlinable = &self.partition.inlinable;
        let ptr_bits = source
            .machine_context()
            .memory_model()
            .default_address_bits();
        if self.dispositions.len() != graph.values.len() {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::DispositionCount {
                    expected: graph.values.len(),
                    actual: self.dispositions.len(),
                },
            ));
        }

        // The components are the partition; the objects are their members
        // that hold a binding. A member folded or elided keeps its own proof
        // above, and a component with no bound member is no object.
        let expected = seal_binding_components_with(
            source_owned,
            &self.machine_projection,
            &self.partition.component_eligible,
            &self.partition.liveness,
        )?
        .into_iter()
        .filter_map(|mut component| {
            component.members.retain(|value| {
                matches!(
                    self.dispositions.get(value.0 as usize),
                    Some(ValueDisposition::Bound { .. })
                )
            });
            (!component.members.is_empty()).then_some(component)
        })
        .collect::<Vec<_>>();
        let unobserved_merges = source.unobserved_merges();
        let unobserved_values = source.unobserved_values();
        let return_controls = certified_return_control_values(source);
        let direct_control_targets = certified_direct_control_target_values(source);
        let direct_call_targets = super::certified_direct_call_target_values(source);
        let call_return_addresses = super::certified_call_return_address_values(source);
        let stack_frame_values = certified_stack_frame_values(source);
        let stack_geometry_values = certified_stack_geometry_values(source);
        let structural_unused = source
            .obligations()
            .structural_unused_values(graph, unobserved_merges.unobserved_uses())
            .ok_or(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::Authority,
            ))?;
        let boundary_reads = super::readers::BoundaryReads::compute(source);
        let plan_facts = super::rules::PlanFacts {
            owned: source_owned,
            projection: &self.machine_projection,
            boundary: &boundary_reads,
        };
        let unread = super::rules::unread_defined_values(plan_facts);
        let unrendered =
            super::rules::unrendered_defined_values(plan_facts, &self.partition.canonical);
        let effectful = super::rules::effectful_definition_values(source);
        for (index, graph_value) in graph.values.iter().enumerate() {
            if graph_value.id.0 as usize != index {
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::ValueTopology {
                        index,
                        value: graph_value.id,
                    },
                ));
            }
        }
        let width_evidence = expected
            .iter()
            .map(|component| seal_width_evidence(source_owned, &self.machine_projection, component))
            .collect::<Result<Vec<_>, _>>()?;
        let mut actual_by_binding = vec![BTreeSet::<ValueId>::new(); self.bindings.len()];
        for (index, disposition) in self.dispositions.iter().enumerate() {
            let value = ValueId(index as u32);
            let graph_value = &graph.values[index];
            match disposition {
                ValueDisposition::Bound { binding } => {
                    if graph_value.var.constant_bits().is_some() {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::UnexpectedValueDisposition { value },
                        ));
                    }
                    let Some(members) = actual_by_binding.get_mut(binding.index()) else {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::InvalidBindingReference {
                                value,
                                binding: *binding,
                            },
                        ));
                    };
                    members.insert(value);
                }
                ValueDisposition::Inline { term, proof } => {
                    let owned = proof.authority == *source.authority() && proof.term == *term;
                    let exact_canonical = self
                        .partition
                        .canonical
                        .value(value)
                        .is_some_and(|canonical| canonical.canonical == *term);
                    let exact_expression = graph_value.var.constant_bits().is_none()
                        && inlinable.contains(&value)
                        && exact_canonical;
                    let exact_literal = graph_value.var.constant_bits().is_some()
                        && exact_canonical
                        && matches!(
                            self.partition.canonical.arena().term(*term).kind,
                            r2rewrite::TermKind::Literal(_)
                        );
                    if !owned || !(exact_literal || exact_expression) {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::InvalidLiteralInline { value },
                        ));
                    }
                }
                // Both reasons describe a constant the arena does not hold, and
                // the seal's question is the same for either: is this value a
                // constant, and is the refusal about this value.
                ValueDisposition::Refused {
                    reason:
                        ValueRefusal::MissingLiteralProjection { value: refused }
                        | ValueRefusal::UnmodelledUserOperation { value: refused, .. },
                } if *refused == value && graph_value.var.constant_bits().is_some() => {}
                ValueDisposition::Refused { .. }
                    if graph_value.var.constant_bits().is_none()
                        && !unobserved_merges.contains(value)
                        && !unobserved_values.contains(&value)
                        && !return_controls.contains(&value)
                        && !direct_control_targets.contains(&value)
                        && !direct_call_targets.contains(&value)
                        && !stack_frame_values.contains(&value)
                        && !stack_geometry_values.contains(&value)
                        && !structural_unused.contains(&value)
                        && !unread.contains(&value)
                        && !unrendered.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::UnobservedMerge
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && unobserved_merges.contains(value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::UnobservedValue
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && unobserved_values.contains(&value)
                        && !unobserved_merges.contains(value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::ReturnControl
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && return_controls.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::DirectControlTarget
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && direct_control_targets.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::DirectCallTarget
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && direct_call_targets.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::CallReturnAddress
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && call_return_addresses.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::StackFrame
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && stack_frame_values.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::DeadStackBase
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && stack_geometry_values.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::UnusedStructuralValue
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && structural_unused.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::DeadUnusedTemporary
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && (unread.contains(&value) || unrendered.contains(&value)) => {}
                // Unread, and its instruction renders anyway. The proof is
                // both halves: the value is dead by one of the ordinary
                // measures, and its definition owns a memory effect.
                ValueDisposition::Elided { reason, proof }
                    if *reason == r2ssa::ledger::ElisionReason::UnreadEffectfulValue
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && effectful.contains(&value)
                        && (unread.contains(&value)
                            || unrendered.contains(&value)
                            || structural_unused.contains(&value)
                            || unobserved_values.contains(&value)
                            || unobserved_merges.contains(value)) => {}
                ValueDisposition::Elided { .. } => {
                    return Err(BindingPlanBuildError::Seal(
                        BindingPlanSourceMismatch::InvalidElisionProof { value },
                    ));
                }
                ValueDisposition::Refused { .. } => {
                    return Err(BindingPlanBuildError::Seal(
                        BindingPlanSourceMismatch::UnexpectedValueDisposition { value },
                    ));
                }
            }
        }

        let mut binding_index = 0_usize;
        for (component, evidence) in expected.iter().zip(width_evidence) {
            match evidence {
                SealWidthEvidence::Exact { lower_bounds } => {
                    let binding_id = BindingId(binding_index as u32);
                    let binding = &self.bindings[binding_index];
                    let actual = &actual_by_binding[binding_index];
                    let expected_sources = component.sources.iter().copied().collect::<Vec<_>>();
                    // Re-derive whether the caller supplies a member rather
                    // than trusting the plan's own answer.
                    let expected_caller_supplied = super::rules::is_caller_supplied(
                        source_owned,
                        graph,
                        &component.members,
                        &component.sources,
                    );
                    // Re-derived here too rather than trusting the plan: a
                    // call clobber nothing claims is supplied from outside.
                    let mut expected_call_clobbered = false;
                    let mut clobber_set_agrees = true;
                    for value in component.members.iter() {
                        let expected = graph.def_inst(*value).is_some_and(|inst| {
                            graph.inst(inst).is_some_and(|inst| {
                                matches!(
                                    inst.payload,
                                    r2ssa::InstPayload::Op(r2ssa::SSAOp::CallDefine { .. })
                                )
                            })
                        }) && !source_owned
                            .source()
                            .facts()
                            .certificates
                            .call_results
                            .contains_key(value);
                        expected_call_clobbered |= expected;
                        clobber_set_agrees &= self.value_is_call_clobber(*value) == expected;
                    }
                    if actual != &component.members
                        || binding.certificate.sources.as_ref() != expected_sources.as_slice()
                        || binding.caller_supplied != expected_caller_supplied
                        || binding.call_clobbered != expected_call_clobbered
                        || !clobber_set_agrees
                    {
                        // Which of the five terms disagreed is which layer to
                        // look at; the refusal alone names only the binding.
                        r2il::refusal_evidence!(
                            "seal-certificate-membership",
                            "{binding_id:?}: members {actual:?} vs {:?}; sources {:?} vs {:?}; caller_supplied={}/{} call_clobbered={}/{} clobber_set={}",
                            component.members,
                            binding.certificate.sources,
                            expected_sources,
                            binding.caller_supplied,
                            expected_caller_supplied,
                            binding.call_clobbered,
                            expected_call_clobbered,
                            clobber_set_agrees
                        );
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::CertificateMembership {
                                binding: binding_id,
                            },
                        ));
                    }
                    let Some(width_bits) =
                        binding_declaration_width(&binding.declaration_type, ptr_bits)
                    else {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::DeclarationWidth {
                                binding: binding_id,
                            },
                        ));
                    };
                    let satisfies_every_bound = lower_bounds
                        .iter()
                        .all(|lower_bound| *lower_bound <= width_bits);
                    let has_minimality_witness = lower_bounds.contains(&width_bits);
                    if width_bits == 0 || !satisfies_every_bound || !has_minimality_witness {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::DeclarationWidth {
                                binding: binding_id,
                            },
                        ));
                    }
                    binding_index += 1;
                }
                SealWidthEvidence::Refused(reason) => {
                    for value in &component.members {
                        if self.disposition(*value) != Some(&ValueDisposition::Refused { reason }) {
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::UnexpectedValueDisposition {
                                    value: *value,
                                },
                            ));
                        }
                    }
                }
            }
        }

        let parameter_candidates = parameter_candidates(source_owned);
        if self.parameters.len() != parameter_candidates.len() {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::ParameterCount {
                    expected: parameter_candidates.len(),
                    actual: self.parameters.len(),
                },
            ));
        }
        let mut slots_by_reused_binding = BTreeMap::<BindingId, Vec<u32>>::new();
        for (index, candidate) in parameter_candidates.iter().enumerate() {
            let Some(ParameterCandidate::Exact {
                entity,
                width_bytes,
                entry_values,
            }) = candidate
            else {
                continue;
            };
            let slot = index as u32;
            if parameter_width(*entity, slot, *width_bytes).is_err() || entry_values.is_empty() {
                continue;
            }
            let mut binding = None;
            if entry_values
                .iter()
                .all(|value| match self.disposition(*value) {
                    Some(ValueDisposition::Bound { binding: candidate })
                        if binding.is_none_or(|existing| existing == *candidate) =>
                    {
                        binding = Some(*candidate);
                        true
                    }
                    _ => false,
                })
                && let Some(binding) = binding
            {
                slots_by_reused_binding
                    .entry(binding)
                    .or_default()
                    .push(slot);
            }
        }

        for (index, candidate) in parameter_candidates.into_iter().enumerate() {
            let slot = index as u32;
            let expected_disposition = match candidate {
                None => {
                    if self.parameters[index].is_some() {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::UnexpectedParameterDisposition { slot },
                        ));
                    }
                    continue;
                }
                Some(ParameterCandidate::Refused(reason)) => {
                    ParameterDisposition::Refused { reason }
                }
                Some(ParameterCandidate::Exact {
                    entity,
                    width_bytes,
                    entry_values,
                }) => match parameter_width(entity, slot, width_bytes) {
                    Err(reason) => ParameterDisposition::Refused { reason },
                    Ok(width_bits) if entry_values.is_empty() => {
                        let binding = BindingId(binding_index as u32);
                        let planned =
                            self.bindings
                                .get(binding_index)
                                .ok_or(BindingPlanBuildError::Seal(
                                    BindingPlanSourceMismatch::UnexpectedParameterDisposition {
                                        slot,
                                    },
                                ))?;
                        if planned.certificate.sources.as_ref()
                            != [BindingCertificateSource::CertifiedEntity(entity)]
                            || !actual_by_binding[binding_index].is_empty()
                        {
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::ParameterCertificate { slot, binding },
                            ));
                        }
                        if !super::rules::declaration_type_describes_width(
                            &planned.declaration_type,
                            width_bits,
                            ptr_bits,
                        ) {
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::ParameterDeclarationWidth {
                                    slot,
                                    binding,
                                },
                            ));
                        }
                        binding_index += 1;
                        ParameterDisposition::Bound {
                            binding,
                            width_bits,
                        }
                    }
                    Ok(width_bits) => {
                        let mut binding = None;
                        let missing = entry_values.iter().copied().find(|value| {
                            match self.disposition(*value) {
                                Some(ValueDisposition::Bound { binding: candidate })
                                    if binding.is_none_or(|existing| existing == *candidate) =>
                                {
                                    binding = Some(*candidate);
                                    false
                                }
                                _ => true,
                            }
                        });
                        if let Some(value) = missing {
                            ParameterDisposition::Refused {
                                reason: ParameterRefusal::MissingValueBinding {
                                    entity,
                                    slot,
                                    value,
                                },
                            }
                        } else {
                            let binding = binding.expect("non-empty exact entry-value set");
                            let owners = &slots_by_reused_binding[&binding];
                            if owners.len() > 1 {
                                ParameterDisposition::Refused {
                                    reason: ParameterRefusal::ConflictingBindingOwnership {
                                        binding,
                                        first_slot: owners[0],
                                        second_slot: owners[1],
                                    },
                                }
                            } else {
                                ParameterDisposition::Bound {
                                    binding,
                                    width_bits,
                                }
                            }
                        }
                    }
                },
            };
            if self.parameter_disposition(slot) != Some(expected_disposition) {
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::UnexpectedParameterDisposition { slot },
                ));
            }
        }

        let expected_stack_objects = source_owned
            .report()
            .render()
            .into_iter()
            .flat_map(|render| render.certified_entities.values())
            .filter_map(|entity| match entity {
                r2types::CertifiedEntity::StackSlot {
                    id,
                    object,
                    base,
                    offset,
                    size,
                    array_layout,
                    source_slot,
                    reload_values,
                    stored_values,
                    callee_allocation,
                    ty: _,
                } => Some((
                    *id,
                    *object,
                    *base,
                    *offset,
                    *size,
                    array_layout.clone(),
                    *source_slot,
                    reload_values.clone(),
                    stored_values.clone(),
                    callee_allocation.clone(),
                )),
                r2types::CertifiedEntity::Parameter { .. }
                | r2types::CertifiedEntity::LoopCarrier { .. } => None,
            })
            .collect::<Vec<_>>();
        if self.stack_objects.len() != expected_stack_objects.len() {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::StackObjectCount {
                    expected: expected_stack_objects.len(),
                    actual: self.stack_objects.len(),
                },
            ));
        }
        for (
            entity,
            object,
            base,
            offset,
            size,
            array_layout,
            source_slot,
            reload_values,
            stored_values,
            callee_allocation,
        ) in expected_stack_objects
        {
            let exact_certificate = source.certificates().stack_slots.get(&object);
            if exact_certificate.is_none_or(|certificate| {
                certificate.object != object
                    || certificate.base != base
                    || certificate.offset != offset
                    || certificate.size != size
                    || certificate.array_layout != array_layout
                    || certificate.source_slot != source_slot
                    || certificate.reload_values != reload_values
                    || certificate.stored_values != stored_values
                    || certificate.callee_allocation != callee_allocation
            }) {
                r2il::refusal_evidence!(
                    "stack-object-seal",
                    "{object:?}: the source certifies no slot with this geometry"
                );
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::UnexpectedStackObjectDisposition { object },
                ));
            }
            if source
                .certificates()
                .stack_frame_round_trips
                .contains_key(&object)
                || super::certified_return_control_stack_objects(source).contains(&object)
            {
                let expected = StackObjectDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::StackFrame,
                };
                if self.stack_object_disposition(object) != Some(expected) {
                    r2il::refusal_evidence!(
                        "stack-object-seal",
                        "{object:?}: the frame round trip is elided and the plan says {:?}",
                        self.stack_object_disposition(object)
                    );
                    return Err(BindingPlanBuildError::Seal(
                        BindingPlanSourceMismatch::UnexpectedStackObjectDisposition { object },
                    ));
                }
                continue;
            }
            let expected_disposition = match (source_slot, callee_allocation) {
                // Neither strong form answers, so the object is named by the
                // width its own accesses agree on. Without even that there is
                // no geometry to state and it stays refused.
                (None, None) if size.is_none() => StackObjectDisposition::Refused {
                    reason: StackObjectRefusal::MissingSourceIdentity { object },
                },
                (None, None) => {
                    let size_bytes = size.expect("the arm above covers a missing width");
                    let Some(width_bits) = size_bytes.checked_mul(8).filter(|width| *width > 0)
                    else {
                        let expected = StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::InvalidWidth { object, size_bytes },
                        };
                        if self.stack_object_disposition(object) != Some(expected) {
                            r2il::refusal_evidence!(
                                "stack-object-seal",
                                "{object:?}: no width, so the plan has to refuse it and says {:?}",
                                self.stack_object_disposition(object)
                            );
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::UnexpectedStackObjectDisposition {
                                    object,
                                },
                            ));
                        }
                        continue;
                    };
                    let declaration_type = super::rules::declaration_type_for_stack_object(
                        source_owned,
                        object,
                        width_bits,
                        ptr_bits,
                    );
                    let adopted = adopted_reload_binding(
                        &self.dispositions,
                        &actual_by_binding,
                        &reload_values,
                        &stored_values,
                        Some(&declaration_type),
                    );
                    let Some(binding) =
                        adopted.or_else(|| BindingId::from_dense_index(binding_index))
                    else {
                        return Err(BindingPlanBuildError::TooManyBindings {
                            count: binding_index.saturating_add(1),
                        });
                    };
                    let planned =
                        self.bindings
                            .get(binding.index())
                            .ok_or(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::UnexpectedStackObjectDisposition {
                                    object,
                                },
                            ))?;
                    if !stack_object_certificate_agrees(
                        planned,
                        entity,
                        adopted.is_some(),
                        &actual_by_binding[binding.index()],
                        &reload_values,
                        &stored_values,
                    ) {
                        r2il::refusal_evidence!(
                            "seal-stack-object",
                            "{object:?} at {binding:?} adopted={} sources={:?} bound={:?} reloads={:?}",
                            adopted.is_some(),
                            planned.certificate.sources,
                            actual_by_binding[binding.index()],
                            reload_values
                        );
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::StackObjectCertificate { object, binding },
                        ));
                    }
                    if !stack_object_declaration_agrees(
                        source_owned,
                        object,
                        planned,
                        width_bits,
                        ptr_bits,
                    ) {
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::StackObjectDeclarationWidth {
                                object,
                                binding,
                            },
                        ));
                    }
                    if adopted.is_none() {
                        binding_index += 1;
                    }
                    StackObjectDisposition::Bound { binding }
                }
                (None, Some(certificate)) => {
                    if certificate.object != object
                        || size != Some(certificate.size_bytes)
                        || certificate.accesses.is_empty()
                        || certificate.active_sp_offsets.is_empty()
                    {
                        StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::MissingSourceIdentity { object },
                        }
                    } else {
                        let width_bits = certificate
                            .size_bytes
                            .checked_mul(8)
                            .filter(|width| *width > 0);
                        let declaration_type = width_bits.map(|width_bits| {
                            super::rules::declaration_type_for_stack_object(
                                source_owned,
                                object,
                                width_bits,
                                ptr_bits,
                            )
                        });
                        let adopted = adopted_reload_binding(
                            &self.dispositions,
                            &actual_by_binding,
                            &reload_values,
                            &stored_values,
                            declaration_type.as_ref(),
                        );
                        let Some(binding) =
                            adopted.or_else(|| BindingId::from_dense_index(binding_index))
                        else {
                            return Err(BindingPlanBuildError::TooManyBindings {
                                count: binding_index.saturating_add(1),
                            });
                        };
                        let planned = self.bindings.get(binding.index()).ok_or(
                            BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::UnexpectedStackObjectDisposition {
                                    object,
                                },
                            ),
                        )?;
                        if !stack_object_certificate_agrees(
                            planned,
                            entity,
                            adopted.is_some(),
                            &actual_by_binding[binding.index()],
                            &reload_values,
                            &stored_values,
                        ) {
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::StackObjectCertificate {
                                    object,
                                    binding,
                                },
                            ));
                        }
                        if width_bits.is_none_or(|width_bits| {
                            !stack_object_declaration_agrees(
                                source_owned,
                                object,
                                planned,
                                width_bits,
                                ptr_bits,
                            )
                        }) {
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::StackObjectDeclarationWidth {
                                    object,
                                    binding,
                                },
                            ));
                        }
                        if adopted.is_none() {
                            binding_index += 1;
                        }
                        StackObjectDisposition::Bound { binding }
                    }
                }
                (Some(_), Some(_)) => StackObjectDisposition::Refused {
                    reason: StackObjectRefusal::MissingSourceIdentity { object },
                },
                (Some(source_slot), None)
                    if source_slot.base() != base
                        || source_slot.offset() != offset
                        || size != Some(source_slot.size_bytes())
                            && !matches!(
                                &array_layout,
                                r2ssa::StackArrayLayoutDisposition::Proven(layout)
                                    if layout.object == object
                                        && u32::try_from(layout.extent).ok() == size
                                        && (source_slot.size_bytes()
                                            == layout.element_width
                                            || Some(source_slot.size_bytes()) == size)
                            ) =>
                {
                    StackObjectDisposition::Refused {
                        reason: StackObjectRefusal::MissingSourceIdentity { object },
                    }
                }
                (Some(source_slot), None) => {
                    let size_bytes = size.expect("source stack object has certified geometry");
                    let Some(width_bits) = size_bytes.checked_mul(8).filter(|width| *width > 0)
                    else {
                        let expected = StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::InvalidWidth { object, size_bytes },
                        };
                        if self.stack_object_disposition(object) != Some(expected) {
                            r2il::refusal_evidence!(
                                "stack-object-seal",
                                "{object:?}: no width, so the plan has to refuse it and says {:?}",
                                self.stack_object_disposition(object)
                            );
                            return Err(BindingPlanBuildError::Seal(
                                BindingPlanSourceMismatch::UnexpectedStackObjectDisposition {
                                    object,
                                },
                            ));
                        }
                        continue;
                    };
                    let role = super::rules::effective_stack_slot_role(
                        source_owned,
                        &source_slot,
                        base,
                        offset,
                    );
                    let role = super::rules::verified_stack_slot_role(
                        source_owned,
                        &self.machine_projection,
                        &self.partition.canonical,
                        &self.dispositions,
                        |index| match self.parameter_disposition(index) {
                            Some(ParameterDisposition::Bound { binding, .. }) => Some(binding),
                            _ => None,
                        },
                        object,
                        role,
                    );
                    match role {
                        r2ssa::SourceStackSlotRole::Local => {
                            // The slot's certified reloads are one object with
                            // it, so the object shares their binding instead of
                            // taking one of its own.
                            let declaration_type = super::rules::declaration_type_for_stack_object(
                                source_owned,
                                object,
                                width_bits,
                                ptr_bits,
                            );
                            let adopted = adopted_reload_binding(
                                &self.dispositions,
                                &actual_by_binding,
                                &reload_values,
                                &stored_values,
                                Some(&declaration_type),
                            );
                            let Some(binding) =
                                adopted.or_else(|| BindingId::from_dense_index(binding_index))
                            else {
                                return Err(BindingPlanBuildError::TooManyBindings {
                                    count: binding_index.saturating_add(1),
                                });
                            };
                            let planned =
                                self.bindings
                                    .get(binding.index())
                                    .ok_or(BindingPlanBuildError::Seal(
                                    BindingPlanSourceMismatch::UnexpectedStackObjectDisposition {
                                        object,
                                    },
                                ))?;
                            if !stack_object_certificate_agrees(
                                planned,
                                entity,
                                adopted.is_some(),
                                &actual_by_binding[binding.index()],
                                &reload_values,
                                &stored_values,
                            ) {
                                return Err(BindingPlanBuildError::Seal(
                                    BindingPlanSourceMismatch::StackObjectCertificate {
                                        object,
                                        binding,
                                    },
                                ));
                            }
                            if !stack_object_declaration_agrees(
                                source_owned,
                                object,
                                planned,
                                width_bits,
                                ptr_bits,
                            ) {
                                return Err(BindingPlanBuildError::Seal(
                                    BindingPlanSourceMismatch::StackObjectDeclarationWidth {
                                        object,
                                        binding,
                                    },
                                ));
                            }
                            if adopted.is_none() {
                                binding_index += 1;
                            }
                            StackObjectDisposition::Bound { binding }
                        }
                        r2ssa::SourceStackSlotRole::ParameterHome {
                            parameter_index, ..
                        } => match self.parameter_disposition(parameter_index) {
                            Some(ParameterDisposition::Bound {
                                binding,
                                width_bits: parameter_width_bits,
                            }) if parameter_width_bits == width_bits => {
                                StackObjectDisposition::Bound { binding }
                            }
                            Some(ParameterDisposition::Bound {
                                width_bits: parameter_width_bits,
                                ..
                            }) => StackObjectDisposition::Refused {
                                reason: StackObjectRefusal::ParameterHomeWidthMismatch {
                                    object,
                                    parameter_index,
                                    slot_width_bits: width_bits,
                                    parameter_width_bits,
                                },
                            },
                            _ => StackObjectDisposition::Refused {
                                reason: StackObjectRefusal::ParameterHomeUnavailable {
                                    object,
                                    parameter_index,
                                },
                            },
                        },
                        r2ssa::SourceStackSlotRole::Parameter { parameter_index } => {
                            match self.parameter_disposition(parameter_index) {
                                Some(ParameterDisposition::Bound {
                                    binding,
                                    width_bits: parameter_width_bits,
                                }) if parameter_width_bits == width_bits => {
                                    StackObjectDisposition::Bound { binding }
                                }
                                Some(ParameterDisposition::Bound {
                                    width_bits: parameter_width_bits,
                                    ..
                                }) => StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::StackParameterWidthMismatch {
                                        object,
                                        parameter_index,
                                        slot_width_bits: width_bits,
                                        parameter_width_bits,
                                    },
                                },
                                _ => StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::StackParameterUnavailable {
                                        object,
                                        parameter_index,
                                    },
                                },
                            }
                        }
                        r2ssa::SourceStackSlotRole::UnclassifiedResource => {
                            StackObjectDisposition::Refused {
                                reason: StackObjectRefusal::UnclassifiedSourceRole { object },
                            }
                        }
                    }
                }
            };
            if self.stack_object_disposition(object) != Some(expected_disposition) {
                r2il::refusal_evidence!(
                    "stack-object-seal",
                    "{object:?}: the plan says {:?} and the source says {expected_disposition:?}",
                    self.stack_object_disposition(object)
                );
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::UnexpectedStackObjectDisposition { object },
                ));
            }
        }
        if binding_index != self.bindings.len() {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::BindingCount {
                    expected: binding_index,
                    actual: self.bindings.len(),
                },
            ));
        }
        Ok(())
    }
}

/// The binding a slot adopts from its reloads, when that binding holds
/// nothing else; the seal's twin of `construction::shared_reload_binding`.
fn adopted_reload_binding(
    dispositions: &[ValueDisposition],
    actual_by_binding: &[BTreeSet<ValueId>],
    reload_values: &BTreeSet<ValueId>,
    stored_values: &BTreeSet<ValueId>,
    declaration_type: Option<&CType>,
) -> Option<BindingId> {
    if declaration_type.is_some_and(|ty| {
        matches!(
            ty,
            r2types::CTypeLike::Struct(_)
                | r2types::CTypeLike::Union(_)
                | r2types::CTypeLike::Array(..)
        )
    }) {
        return None;
    }
    super::construction::unanimous_value_binding(dispositions, reload_values.iter().copied())
        .filter(|binding| {
            actual_by_binding
                .get(binding.index())
                .is_some_and(|actual| slot_members_agree(actual, reload_values, stored_values))
        })
}

/// The binding holds every reload and nothing but reloads and stored values.
fn slot_members_agree(
    actual: &BTreeSet<ValueId>,
    reload_values: &BTreeSet<ValueId>,
    stored_values: &BTreeSet<ValueId>,
) -> bool {
    actual.is_superset(reload_values)
        && actual
            .iter()
            .all(|value| reload_values.contains(value) || stored_values.contains(value))
}

/// Whether the binding a stack object took carries the object's certificate.
///
/// A shared binding also holds the values the object's reloads certify, so it
/// carries other sources beside this entity and is not empty.
fn stack_object_certificate_agrees(
    planned: &Binding,
    entity: r2ssa::SemanticId,
    adopted: bool,
    actual: &BTreeSet<ValueId>,
    reload_values: &BTreeSet<ValueId>,
    stored_values: &BTreeSet<ValueId>,
) -> bool {
    if adopted {
        planned
            .certificate
            .sources
            .contains(&BindingCertificateSource::CertifiedEntity(entity))
            && slot_members_agree(actual, reload_values, stored_values)
    } else {
        planned.certificate.sources.as_ref() == [BindingCertificateSource::CertifiedEntity(entity)]
            && actual.is_empty()
    }
}

/// Whether the planned declaration is the one the slot's own rule derives.
///
/// An aggregate has no scalar width to check, so the seal asks the site that
/// owns the decision rather than re-deriving a width it cannot see.
fn stack_object_declaration_agrees(
    source_owned: &SourceOwnedFunctionFacts,
    object: r2ssa::ObjectId,
    planned: &Binding,
    width_bits: u32,
    ptr_bits: u32,
) -> bool {
    // Asked through any name the source gave the type: a named aggregate is
    // still an aggregate, and an aggregate has no scalar width to measure, so
    // what vouches for it is that the rule would decide it the same way again.
    if planned.declaration_type.is_aggregate() {
        return planned.declaration_type
            == super::rules::declaration_type_for_stack_object(
                source_owned,
                object,
                width_bits,
                ptr_bits,
            );
    }
    super::rules::declaration_type_describes_width(&planned.declaration_type, width_bits, ptr_bits)
}
