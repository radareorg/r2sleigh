use super::*;

use super::rules::{ParameterCandidate, parameter_candidates, parameter_width};

fn binding_declaration_width(ty: &CType, ptr_bits: u32) -> Option<u32> {
    super::rules::declaration_type_width(ty, ptr_bits)
}

/// Whether a binding's sources account for its members: a singleton has one,
/// a storage span carries one, and a certified parameter or frame slot -- the
/// sources that give the object its role -- coalesces one of them.
///
/// Which values share a variable is not re-derived here. It was decided by
/// the procedure that built the plan, and running that procedure again could
/// only ever agree with it; what proves it is the reaching-values check over
/// the rendered text (`stale_reads`), which asks of every read the text makes
/// whether it sees the value it stands for.
fn sources_account_for_members(
    source_owned: &SourceOwnedFunctionFacts,
    component: &SealBindingComponent,
) -> bool {
    let render = source_owned.report().render();
    !component.sources.is_empty()
        && component.sources.iter().all(|source| match source {
            BindingCertificateSource::Singleton => component.members.len() == 1,
            BindingCertificateSource::StorageSpan(span) => component
                .members
                .iter()
                .any(|value| source_owned.source().storage_spans().span_of(*value) == Some(*span)),
            BindingCertificateSource::CertifiedEntity(entity) => match entity {
                SemanticId::Parameter(_) | SemanticId::StackSlot(_) => render
                    .and_then(|render| render.certified_entities.get(entity))
                    .and_then(r2types::CertifiedEntity::coalescing_values)
                    .is_none_or(|values| {
                        values.iter().any(|value| component.members.contains(value))
                    }),
                _ => true,
            },
        })
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
/// The candidate plan's dispositions are not an input: every elision, inline
/// and refusal here is derived again, so a wrong plan disposition is
/// observable instead of validating the candidate against itself. The one
/// plan decision it takes is the partition -- which values share a variable
/// -- because the only way to derive it again is to run the procedure that
/// made it, which can only agree; what proves the partition is the
/// reaching-values check over the rendered text (`stale_reads`).
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
    plan: &'a BindingPlan,
) -> Result<UpstreamShadowOracle<'a>, BindingPlanBuildError> {
    let machine_projection = plan.machine_projection();
    let partition = plan.partition();
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
    // The components are the plan's own. Every other judgment here is
    // re-derived, but which values share a variable is the one decision a
    // second run of the procedure that made it could only repeat; the
    // reaching-values check over the rendered text is what proves it.
    let resolved = plan.chosen_components();
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
                crate::ledger::ElisionReason::ReturnControl,
            ));
            continue;
        }
        if direct_control_targets.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::DirectControlTarget,
            ));
            continue;
        }
        if direct_call_targets.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::DirectCallTarget,
            ));
            continue;
        }
        if call_return_addresses.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::CallReturnAddress,
            ));
            continue;
        }
        if stack_frame_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::StackFrame,
            ));
            continue;
        }
        if stack_geometry_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::DeadStackBase,
            ));
            continue;
        }
        if source.unobserved_merges().contains(graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::UnobservedMerge,
            ));
            continue;
        }
        if unobserved_values.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::UnobservedValue,
            ));
            continue;
        }
        if structural_unused.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::UnusedStructuralValue,
            ));
            continue;
        }
        if unread.contains(&graph_value.id) || unrendered.contains(&graph_value.id) {
            values[graph_value.id.0 as usize] = Some(UpstreamValueDisposition::Elided(
                crate::ledger::ElisionReason::DeadUnusedTemporary,
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

/// Whether a refusal is the one a component's width evidence gives: a read
/// incoherent with a member, or a width no declaration can state.
const fn is_width_refusal(reason: ValueRefusal) -> bool {
    matches!(
        reason,
        ValueRefusal::IncoherentUseProjection { .. }
            | ValueRefusal::IncoherentWriteProjection { .. }
            | ValueRefusal::UnsupportedDeclarationWidth { .. }
    )
}

impl BindingPlan {
    /// The values refused together because their object's width could not be
    /// stated, grouped by that one refusal.
    fn width_refused_groups(&self) -> BTreeMap<ValueRefusal, BTreeSet<ValueId>> {
        let mut groups = BTreeMap::<ValueRefusal, BTreeSet<ValueId>>::new();
        for (index, disposition) in self.dispositions.iter().enumerate() {
            if let ValueDisposition::Refused { reason } = disposition
                && is_width_refusal(*reason)
            {
                groups
                    .entry(*reason)
                    .or_default()
                    .insert(ValueId(index as u32));
            }
        }
        groups
    }

    /// The components the plan chose: each binding's members, and each group
    /// of values refused together for want of a width.
    fn chosen_components(&self) -> Vec<SealBindingComponent> {
        let mut components = vec![BTreeSet::<ValueId>::new(); self.bindings.len()];
        for (index, disposition) in self.dispositions.iter().enumerate() {
            if let ValueDisposition::Bound { binding } = disposition
                && let Some(members) = components.get_mut(binding.index())
            {
                members.insert(ValueId(index as u32));
            }
        }
        components
            .into_iter()
            .zip(self.bindings.iter())
            .map(|(members, binding)| SealBindingComponent {
                members,
                sources: binding.certificate.sources.iter().copied().collect(),
            })
            .chain(
                self.width_refused_groups()
                    .into_values()
                    .map(|members| SealBindingComponent {
                        members,
                        sources: BTreeSet::new(),
                    }),
            )
            .collect()
    }

    /// Every group of values refused for want of a width is refused for the
    /// reason its own members' reads give.
    fn validate_width_refusals(
        &self,
        source_owned: &SourceOwnedFunctionFacts,
    ) -> Result<(), BindingPlanBuildError> {
        for (reason, members) in self.width_refused_groups() {
            let group = SealBindingComponent {
                members,
                sources: BTreeSet::new(),
            };
            let evidence = seal_width_evidence(source_owned, &self.machine_projection, &group)?;
            if !matches!(evidence, SealWidthEvidence::Refused(found) if found == reason) {
                let value = group.members.first().copied().unwrap_or(ValueId(0));
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::UnexpectedValueDisposition { value },
                ));
            }
        }
        Ok(())
    }

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
                    if *reason == crate::ledger::ElisionReason::UnobservedMerge
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && unobserved_merges.contains(value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::UnobservedValue
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && unobserved_values.contains(&value)
                        && !unobserved_merges.contains(value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::ReturnControl
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && return_controls.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::DirectControlTarget
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && direct_control_targets.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::DirectCallTarget
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && direct_call_targets.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::CallReturnAddress
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && call_return_addresses.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::StackFrame
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && stack_frame_values.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::DeadStackBase
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && stack_geometry_values.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::UnusedStructuralValue
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && structural_unused.contains(&value) => {}
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::DeadUnusedTemporary
                        && proof.authority == *source.authority()
                        && proof.value == value
                        && (unread.contains(&value) || unrendered.contains(&value)) => {}
                // Unread, and its instruction renders anyway. The proof is
                // both halves: the value is dead by one of the ordinary
                // measures, and its definition owns a memory effect.
                ValueDisposition::Elided { reason, proof }
                    if *reason == crate::ledger::ElisionReason::UnreadEffectfulValue
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

        // Each binding is checked on what its own members decide: that its
        // sources account for them, the width their reads demand, and whether
        // the caller supplies one. Which values share it is the plan's, proven
        // over the rendered text (`stale_reads`).
        //
        // The value bindings come first, one per component with a member left
        // to bind; a parameter's or a frame object's own binding follows them
        // with no value of its own, and is checked with its object below.
        let expected = actual_by_binding
            .iter()
            .zip(self.bindings.iter())
            .take_while(|(members, _)| !members.is_empty())
            .map(|(members, binding)| SealBindingComponent {
                members: members.clone(),
                sources: binding.certificate.sources.iter().copied().collect(),
            })
            .collect::<Vec<_>>();
        if let Some(index) = actual_by_binding
            .iter()
            .skip(expected.len())
            .position(|members| !members.is_empty())
        {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::CertificateMembership {
                    binding: BindingId((expected.len() + index) as u32),
                },
            ));
        }
        let width_evidence = expected
            .iter()
            .map(|component| seal_width_evidence(source_owned, &self.machine_projection, component))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate_width_refusals(source_owned)?;
        let mut binding_index = 0_usize;
        for (component, evidence) in expected.iter().zip(width_evidence) {
            match evidence {
                SealWidthEvidence::Exact { lower_bounds } => {
                    let binding_id = BindingId(binding_index as u32);
                    let binding = &self.bindings[binding_index];
                    // Re-derive whether the caller supplies a member rather
                    // than trusting the plan's own answer.
                    let expected_caller_supplied = super::rules::is_caller_supplied(
                        source_owned,
                        graph,
                        &component.members,
                        &component.sources,
                    );
                    if component.members.is_empty()
                        || !sources_account_for_members(source_owned, component)
                        || binding.caller_supplied != expected_caller_supplied
                    {
                        // Which of the terms disagreed is which layer to look
                        // at; the refusal alone names only the binding.
                        r2il::refusal_evidence!(
                            "seal-certificate-membership",
                            "{binding_id:?}: members {:?}; sources {:?}; caller_supplied={}/{}",
                            component.members,
                            binding.certificate.sources,
                            binding.caller_supplied,
                            expected_caller_supplied
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
                        // The type itself has no width the model can state.
                        r2il::refusal_evidence!(
                            "seal-declaration-width",
                            "{binding_id:?}: {:?} has no width",
                            binding.declaration_type
                        );
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
                        // Which of the three the width broke says which layer to look at.
                        r2il::refusal_evidence!(
                            "seal-declaration-width",
                            "{binding_id:?}: {:?} is {width_bits} bits over {lower_bounds:?}; covers={satisfies_every_bound} witnessed={has_minimality_witness}",
                            binding.declaration_type
                        );
                        return Err(BindingPlanBuildError::Seal(
                            BindingPlanSourceMismatch::DeclarationWidth {
                                binding: binding_id,
                            },
                        ));
                    }
                    binding_index += 1;
                }
                // A bound object whose members' reads admit no declaration
                // width is one the plan should have refused.
                SealWidthEvidence::Refused(_) => {
                    return Err(BindingPlanBuildError::Seal(
                        BindingPlanSourceMismatch::DeclarationWidth {
                            binding: BindingId(binding_index as u32),
                        },
                    ));
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
                    reason: crate::ledger::ElisionReason::StackFrame,
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
                        r2il::refusal_evidence!(
                            "stack-object-declaration",
                            "{object:?}: the plan declares {:?} for an object {width_bits} bits \
                             wide, and the rule would declare {:?}",
                            planned.declaration_type,
                            super::rules::declaration_type_for_stack_object(
                                source_owned,
                                object,
                                width_bits,
                                ptr_bits,
                            )
                        );
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
                            r2il::refusal_evidence!(
                                "stack-object-declaration",
                                "{object:?}: the plan declares {:?} for an object {width_bits:?} \
                                 bits wide, and the rule would declare {:?}",
                                planned.declaration_type,
                                width_bits.map(|width_bits| {
                                    super::rules::declaration_type_for_stack_object(
                                        source_owned,
                                        object,
                                        width_bits,
                                        ptr_bits,
                                    )
                                })
                            );
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
                                r2il::refusal_evidence!(
                                    "stack-object-declaration",
                                    "{object:?}: the plan declares {:?} for a declared slot \
                                     {width_bits} bits wide, and the rule would declare {:?}",
                                    planned.declaration_type,
                                    super::rules::declaration_type_for_stack_object(
                                        source_owned,
                                        object,
                                        width_bits,
                                        ptr_bits,
                                    )
                                );
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
        // Which reads are residuals is derived again from the dispositions the
        // seal has just checked and the parameters it has just re-derived,
        // rather than trusting the plan's own map: a value the plan names that
        // this does not, or the reverse, is the first one in value order.
        let parameter_bindings = self
            .parameters
            .iter()
            .filter_map(|parameter| match parameter {
                Some(ParameterDisposition::Bound { binding, .. }) => Some(*binding),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let expected_unspecified = super::construction::unspecified_reads(
            source_owned,
            &self.dispositions,
            &parameter_bindings,
        );
        if expected_unspecified != self.unspecified {
            let value = expected_unspecified
                .iter()
                .chain(self.unspecified.iter())
                .find(|(value, read)| {
                    expected_unspecified.get(value) != self.unspecified.get(value)
                        || expected_unspecified.get(value) != Some(read)
                })
                .map_or(ValueId(0), |(value, _)| *value);
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::UnexpectedValueDisposition { value },
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
                .is_some_and(|actual| {
                    super::construction::slot_members_agree(actual, reload_values, stored_values)
                })
        })
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
            && super::construction::slot_members_agree(actual, reload_values, stored_values)
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

// Reaching values.
//
// The partition is judged by liveness when it is built, and liveness admits
// two values into one object when neither is needed where the other is
// written -- or when it has declared them one content at two widths, which is
// a claim rather than a proof. What the text needs is narrower and checkable
// after the fact: every rendered read of a variable sees exactly the SSA value
// it stands for. This is that check, over the text as it is finally ordered,
// owing nothing to how the partition was chosen.

/// One rendered read of a C variable, and the SSA value it stands for.
///
/// A read of a value its own statement defines -- the steps a merged
/// `x -= 32` takes -- is that statement's business and is not one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RenderedRead {
    pub(crate) binding: BindingId,
    pub(crate) value: ValueId,
    pub(crate) block: u64,
    /// Final render order: a read at the order of a write is evaluated first.
    pub(crate) order: u64,
    /// The structured region the read is rendered in, which tells the copies
    /// of a block the structured form duplicated apart.
    pub(crate) region: usize,
    /// The instruction the read serves, which a gap anchors on when the read
    /// cannot be split.
    pub(crate) at: Option<InstId>,
}

/// One assignment the text spells, after which a C variable holds an SSA
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RenderedWrite {
    pub(crate) binding: BindingId,
    /// What the variable holds afterwards; `None` for a store of something
    /// that is no SSA value of this variable, after which it holds none.
    pub(crate) value: Option<ValueId>,
    pub(crate) block: u64,
    pub(crate) order: u64,
    /// The structured region the write is rendered in.
    pub(crate) region: usize,
    /// The writing instruction's place in `block`; `None` where the write
    /// stands in `block` for an instruction of another -- a merge's copy on
    /// the edge out of it -- and so comes after every one of `block`'s own.
    pub(crate) ordinal: Option<usize>,
}

/// A definition the text does not spell, because it cannot change what its
/// variable holds: a copy of a value the variable already holds, or a reload
/// of the variable's own storage. It has no occurrence, so it is placed among
/// the variable's writes by instruction order, which is exact for what the
/// check asks of it: nothing but a write changes what a variable holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElidedDefinition {
    pub(crate) binding: BindingId,
    pub(crate) value: ValueId,
    pub(crate) block: u64,
    /// The defining instruction's place in `block`.
    pub(crate) ordinal: usize,
    pub(crate) source: ElidedSource,
}

/// What an elided definition's value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElidedSource {
    /// A copy, an extension or a restore of this value, which the variable
    /// must hold where the definition is for the definition to say nothing.
    Value(ValueId),
    /// A reload of the variable's own storage: whatever it holds there.
    Content,
}

/// A merge the SSA makes at entry to `block`: `output` is what `incoming`
/// supplied on the edge taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReachingMerge {
    pub(crate) block: u64,
    pub(crate) output: ValueId,
    pub(crate) incoming: Vec<(u64, ValueId)>,
}

/// The control flow the check runs over, by block address.
pub(crate) trait ReachingControlFlow {
    fn entry(&self) -> u64;
    /// Every block reachable from the entry, each after its predecessors
    /// except across back edges.
    fn reverse_postorder(&self) -> Vec<u64>;
    fn predecessors(&self, block: u64) -> Vec<u64>;
}

impl ReachingControlFlow for r2ssa::SSAFunction {
    fn entry(&self) -> u64 {
        self.entry
    }

    fn reverse_postorder(&self) -> Vec<u64> {
        self.block_addrs().to_vec()
    }

    fn predecessors(&self, block: u64) -> Vec<u64> {
        r2ssa::SSAFunction::predecessors(self, block)
    }
}

/// Everything the check reads besides the control flow.
pub(crate) struct ReachingFacts<'a> {
    pub(crate) reads: &'a [RenderedRead],
    pub(crate) writes: &'a [RenderedWrite],
    pub(crate) elided: &'a [ElidedDefinition],
    pub(crate) merges: &'a [ReachingMerge],
    /// The variable a value is bound to.
    pub(crate) binding_of: &'a dyn Fn(ValueId) -> Option<BindingId>,
    /// The value whose low bits a value is, by its own definition: a copy, an
    /// extension, a restore. Syntax, never a claim that two computations
    /// happen to agree.
    pub(crate) re_expresses: &'a dyn Fn(ValueId) -> Option<ValueId>,
    /// The values the function is entered with, SSA version 0.
    pub(crate) entry_values: &'a BTreeSet<ValueId>,
    /// Whether two regions are arms no execution reaches both of. One block
    /// rendered in two such regions is two copies, one per path, and each is
    /// entered holding what the block is entered with.
    pub(crate) exclusive: &'a dyn Fn(usize, usize) -> bool,
}

/// A read that does not see the value it stands for on every path to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleRead {
    pub(crate) read: RenderedRead,
    /// What the variable may hold there instead; empty where some path
    /// reaches the read holding nothing the check can name.
    pub(crate) instead: BTreeSet<ValueId>,
}

/// A set of values, as bits over one variable's universe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldSet(Vec<u64>);

impl HeldSet {
    fn empty(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    fn full(len: usize) -> Self {
        let mut set = Self(vec![u64::MAX; len.div_ceil(64)]);
        if !len.is_multiple_of(64)
            && let Some(last) = set.0.last_mut()
        {
            *last = (1u64 << (len % 64)) - 1;
        }
        set
    }

    fn has(&self, bit: usize) -> bool {
        self.0[bit / 64] & (1 << (bit % 64)) != 0
    }

    fn insert(&mut self, bit: usize) {
        self.0[bit / 64] |= 1 << (bit % 64);
    }

    fn meet(&mut self, other: &Self) {
        for (word, theirs) in self.0.iter_mut().zip(&other.0) {
            *word &= theirs;
        }
    }

    fn join(&mut self, other: &Self) {
        for (word, theirs) in self.0.iter_mut().zip(&other.0) {
            *word |= theirs;
        }
    }
}

/// One event of one variable inside one block.
#[derive(Debug, Clone, Copy)]
enum HeldEvent {
    Read(RenderedRead),
    Write(Option<ValueId>),
    Elided(ElidedDefinition),
}

/// What one variable must and may hold at one point.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    must: HeldSet,
    may: HeldSet,
}

/// The check for one variable: its values, its events by block -- one
/// sequence per rendered copy of the block, in the order the text performs
/// them -- the merges into it, and what it holds on entry.
struct VariableFlow<'a> {
    bits: BTreeMap<ValueId, usize>,
    values: Vec<ValueId>,
    events: BTreeMap<u64, Vec<Vec<HeldEvent>>>,
    merges: BTreeMap<u64, Vec<&'a ReachingMerge>>,
    entry: Held,
}

impl<'a> VariableFlow<'a> {
    fn new(
        facts: &ReachingFacts<'_>,
        events: VariableEvents<'_>,
        merges: Vec<&'a ReachingMerge>,
        entry_values: &[ValueId],
    ) -> Self {
        let mut universe = BTreeSet::new();
        universe.extend(events.reads.iter().map(|read| read.value));
        universe.extend(entry_values.iter().copied());
        for write in events.writes {
            universe.extend(
                write
                    .value
                    .into_iter()
                    .flat_map(|value| closure(facts, value)),
            );
        }
        for elided in events.elided {
            universe.extend(closure(facts, elided.value));
            if let ElidedSource::Value(source) = elided.source {
                universe.insert(source);
            }
        }
        for merge in &merges {
            universe.insert(merge.output);
            universe.extend(merge.incoming.iter().map(|(_, value)| *value));
        }
        let values = universe.into_iter().collect::<Vec<_>>();
        let bits = values
            .iter()
            .enumerate()
            .map(|(bit, value)| (*value, bit))
            .collect::<BTreeMap<_, _>>();
        let mut by_block = BTreeMap::<u64, Vec<&ReachingMerge>>::new();
        for merge in merges {
            by_block.entry(merge.block).or_default().push(merge);
        }
        let mut entry = Held {
            must: HeldSet::empty(values.len()),
            may: HeldSet::empty(values.len()),
        };
        for value in entry_values {
            entry.must.insert(bits[value]);
            entry.may.insert(bits[value]);
        }
        Self {
            bits,
            values,
            events: ordered_events(events, facts.exclusive),
            merges: by_block,
            entry,
        }
    }

    /// Whether this variable only ever holds one value and is never emptied
    /// by a store of something else, so that must-assignment alone, which
    /// placement proves, decides every read of it.
    fn is_trivial(&self) -> bool {
        self.values.len() <= 1
            && self.merges.is_empty()
            && self
                .events
                .values()
                .flatten()
                .flatten()
                .all(|event| matches!(event, HeldEvent::Read(_) | HeldEvent::Write(Some(_))))
    }

    /// What the variable holds after the edge from `pred` into `block`: each
    /// merge at `block` is held where every value it takes from that edge is,
    /// judged on what the edge carried before any merge renamed it.
    fn across_edge(&self, pred: u64, block: u64, out: &Held) -> Held {
        let mut held = out.clone();
        for merge in self.merges.get(&block).into_iter().flatten() {
            let from_pred = merge
                .incoming
                .iter()
                .filter(|(from, _)| *from == pred)
                .map(|(_, value)| self.bits[value])
                .collect::<Vec<_>>();
            if from_pred.is_empty() {
                continue;
            }
            let output = self.bits[&merge.output];
            if from_pred.iter().all(|bit| out.must.has(*bit)) {
                held.must.insert(output);
            }
            if from_pred.iter().any(|bit| out.may.has(*bit)) {
                held.may.insert(output);
            }
        }
        held
    }

    /// What the variable holds on entry to `block`. A predecessor not yet
    /// visited contributes nothing, which is the top of the must lattice.
    fn entering<C: ReachingControlFlow + ?Sized>(
        &self,
        cfg: &C,
        block: u64,
        out: &BTreeMap<u64, Held>,
    ) -> Held {
        let mut held = if block == cfg.entry() {
            self.entry.clone()
        } else {
            Held {
                must: HeldSet::full(self.values.len()),
                may: HeldSet::empty(self.values.len()),
            }
        };
        for pred in cfg.predecessors(block) {
            if let Some(pred_out) = out.get(&pred) {
                let arriving = self.across_edge(pred, block, pred_out);
                held.must.meet(&arriving.must);
                held.may.join(&arriving.may);
            }
        }
        held
    }

    /// Run `block` over what it is entered with, handing each read that does
    /// not see its value to `stale`. A block the text renders more than once
    /// runs each copy from its entry, and leaves what every copy leaves.
    fn through(
        &self,
        facts: &ReachingFacts<'_>,
        block: u64,
        held: Held,
        stale: &mut dyn FnMut(&RenderedRead, &Held),
    ) -> Held {
        let Some(copies) = self.events.get(&block) else {
            return held;
        };
        let mut left = None::<Held>;
        for copy in copies {
            let out = self.through_copy(facts, copy, held.clone(), stale);
            match left.as_mut() {
                None => left = Some(out),
                Some(left) => {
                    left.must.meet(&out.must);
                    left.may.join(&out.may);
                }
            }
        }
        left.unwrap_or(held)
    }

    fn through_copy(
        &self,
        facts: &ReachingFacts<'_>,
        events: &[HeldEvent],
        mut held: Held,
        stale: &mut dyn FnMut(&RenderedRead, &Held),
    ) -> Held {
        for event in events {
            match event {
                HeldEvent::Read(read) if !held.must.has(self.bits[&read.value]) => {
                    stale(read, &held);
                }
                HeldEvent::Read(_) => {}
                HeldEvent::Write(value) => held = self.written(facts, *value),
                HeldEvent::Elided(elided) => self.rename(facts, elided, &mut held),
            }
        }
        held
    }

    /// What the variable holds after a write of `value`: that value and
    /// whatever its definition re-expresses, and nothing else.
    fn written(&self, facts: &ReachingFacts<'_>, value: Option<ValueId>) -> Held {
        let mut must = HeldSet::empty(self.values.len());
        value
            .iter()
            .flat_map(|value| closure(facts, *value))
            .filter_map(|written| self.bits.get(&written))
            .for_each(|bit| must.insert(*bit));
        Held {
            may: must.clone(),
            must,
        }
    }

    /// An elided definition names what the variable already holds: its value
    /// is held where its source is, and a reload of the variable's own
    /// storage is whatever the variable holds. What else it held, it holds.
    fn rename(&self, facts: &ReachingFacts<'_>, elided: &ElidedDefinition, held: &mut Held) {
        let (must, may) = match elided.source {
            ElidedSource::Content => (true, true),
            ElidedSource::Value(source) => {
                let bit = self.bits[&source];
                (held.must.has(bit), held.may.has(bit))
            }
        };
        for value in closure(facts, elided.value) {
            let bit = self.bits[&value];
            if must {
                held.must.insert(bit);
            }
            if may {
                held.may.insert(bit);
            }
        }
    }

    /// One round-robin pass in `order`; whether any block's exit changed.
    fn sweep<C: ReachingControlFlow + ?Sized>(
        &self,
        cfg: &C,
        facts: &ReachingFacts<'_>,
        order: &[u64],
        out: &mut BTreeMap<u64, Held>,
    ) -> bool {
        let mut changed = false;
        for block in order {
            let entered = self.entering(cfg, *block, out);
            let left = self.through(facts, *block, entered, &mut |_, _| {});
            changed |= out.insert(*block, left.clone()).as_ref() != Some(&left);
        }
        changed
    }

    /// Every stale read of this variable.
    ///
    /// Round-robin in reverse postorder to a fixed point, then one sweep that
    /// reports. Every transfer is monotone -- a write replaces the set, a
    /// read leaves it alone, a merge adds its output where its inputs are --
    /// and every must-set starts at the top and only loses members, so the
    /// iteration stops after at most one pass per member of each block's set.
    /// The kill-and-generate part of the framework is rapid, so it settles
    /// within Kam and Ullman's d + 2 passes, d the loop-connectedness of the
    /// order; a merge whose input is itself a merge of an enclosing loop can
    /// add one pass per level of that nesting.
    fn stale_reads<C: ReachingControlFlow + ?Sized>(
        &self,
        cfg: &C,
        facts: &ReachingFacts<'_>,
        order: &[u64],
    ) -> Vec<StaleRead> {
        let mut out = BTreeMap::<u64, Held>::new();
        while self.sweep(cfg, facts, order, &mut out) {}
        let mut stale = Vec::new();
        for block in order {
            let entered = self.entering(cfg, *block, &out);
            self.through(facts, *block, entered, &mut |read, held| {
                stale.push(StaleRead {
                    read: *read,
                    instead: self
                        .values
                        .iter()
                        .enumerate()
                        .filter(|(bit, value)| held.may.has(*bit) && **value != read.value)
                        .map(|(_, value)| *value)
                        .collect(),
                });
            });
        }
        stale
    }
}

/// One variable's reads, writes and elided definitions.
#[derive(Clone, Copy)]
struct VariableEvents<'e> {
    reads: &'e [RenderedRead],
    writes: &'e [RenderedWrite],
    elided: &'e [ElidedDefinition],
}

/// One variable's events by block, one sequence per rendered copy of the
/// block, in the order the text performs them.
///
/// Regions that are not exclusive of each other hold one copy; a block the
/// structured form duplicated into exclusive arms is one copy per arm. At one
/// position a read precedes the write, and writes at one position -- one
/// statement assigning the variable several times over -- follow their
/// instructions. An elided definition happens in every copy, right after the
/// last of the copy's writes of the variable whose instruction precedes its
/// own, or first where none does.
fn ordered_events(
    events: VariableEvents<'_>,
    exclusive: &dyn Fn(usize, usize) -> bool,
) -> BTreeMap<u64, Vec<Vec<HeldEvent>>> {
    let mut by_block = BTreeMap::<u64, Vec<(usize, KeyedEvent, Option<usize>)>>::new();
    for read in events.reads {
        by_block.entry(read.block).or_default().push((
            read.region,
            (
                i128::from(read.order),
                0,
                u64::from(read.value.0),
                HeldEvent::Read(*read),
            ),
            None,
        ));
    }
    for write in events.writes {
        by_block.entry(write.block).or_default().push((
            write.region,
            (
                i128::from(write.order),
                1,
                write.ordinal.map_or(u64::MAX, |ordinal| ordinal as u64),
                HeldEvent::Write(write.value),
            ),
            write.ordinal,
        ));
    }
    let mut elided_by_block = BTreeMap::<u64, Vec<&ElidedDefinition>>::new();
    for elided in events.elided {
        elided_by_block
            .entry(elided.block)
            .or_default()
            .push(elided);
        by_block.entry(elided.block).or_default();
    }
    by_block
        .into_iter()
        .map(|(block, occurrences)| {
            let elided = elided_by_block.get(&block).map_or(&[][..], Vec::as_slice);
            let copies = block_copies(&occurrences, exclusive)
                .into_iter()
                .map(|copy| sequence_copy(copy, elided))
                .collect();
            (block, copies)
        })
        .collect()
}

/// An event keyed by where the text performs it: (order, rank, tie, event),
/// order -1 being the start of the block's copy.
type KeyedEvent = (i128, u8, u64, HeldEvent);

/// One copy's events in the order the text performs them, with each elided
/// definition right after the last of the copy's writes whose instruction
/// precedes its own.
fn sequence_copy(
    mut copy: Vec<(KeyedEvent, Option<usize>)>,
    elided: &[&ElidedDefinition],
) -> Vec<HeldEvent> {
    let placed = elided
        .iter()
        .map(|elided| {
            let after = copy
                .iter()
                .filter(|(_, ordinal)| ordinal.is_some_and(|ordinal| ordinal < elided.ordinal))
                .map(|((order, ..), _)| *order)
                .max()
                .unwrap_or(-1);
            (
                (after, 3, elided.ordinal as u64, HeldEvent::Elided(**elided)),
                None,
            )
        })
        .collect::<Vec<_>>();
    copy.extend(placed);
    copy.sort_by_key(|((order, rank, tie, _), _)| (*order, *rank, *tie));
    copy.into_iter().map(|((.., event), _)| event).collect()
}

/// A block's occurrences split into the copies the text renders: regions
/// that are not exclusive of one another are one copy. A block with no
/// occurrence at all is one empty copy.
fn block_copies<K: Copy>(
    occurrences: &[(usize, K, Option<usize>)],
    exclusive: &dyn Fn(usize, usize) -> bool,
) -> Vec<Vec<(K, Option<usize>)>> {
    let regions = occurrences
        .iter()
        .map(|(region, ..)| *region)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    // Few regions per block: a quadratic grouping is the cheap one.
    let mut copy_of = (0..regions.len()).collect::<Vec<_>>();
    let pairs = (0..regions.len())
        .flat_map(|left| (left + 1..regions.len()).map(move |right| (left, right)))
        .filter(|(left, right)| !exclusive(regions[*left], regions[*right]))
        .collect::<Vec<_>>();
    for (left, right) in pairs {
        let (from, to) = (copy_of[right], copy_of[left]);
        copy_of
            .iter_mut()
            .filter(|copy| **copy == from)
            .for_each(|copy| *copy = to);
    }
    let mut copies = BTreeMap::<usize, Vec<(K, Option<usize>)>>::new();
    for (region, keyed, ordinal) in occurrences {
        let index = regions.binary_search(region).unwrap_or_default();
        copies
            .entry(copy_of[index])
            .or_default()
            .push((*keyed, *ordinal));
    }
    if copies.is_empty() {
        return vec![Vec::new()];
    }
    copies.into_values().collect()
}

/// A value and every value its definition re-expresses, in turn.
fn closure(facts: &ReachingFacts<'_>, value: ValueId) -> Vec<ValueId> {
    let mut chain = vec![value];
    while let Some(next) = chain.last().and_then(|last| (facts.re_expresses)(*last)) {
        if chain.contains(&next) {
            break;
        }
        chain.push(next);
    }
    chain
}

/// Every rendered read, of any variable, that does not see the value it
/// stands for on every path to it.
///
/// Variables are checked one at a time, each over its own values:
/// O(passes x (blocks + edges) x values / 64) per variable, and only the
/// variables that hold more than one value, or are merged into, or are
/// emptied by a store, are checked at all.
pub(crate) fn stale_reads<C: ReachingControlFlow + ?Sized>(
    cfg: &C,
    facts: &ReachingFacts<'_>,
) -> Vec<StaleRead> {
    let order = cfg.reverse_postorder();
    let mut reads = BTreeMap::<BindingId, Vec<RenderedRead>>::new();
    for read in facts.reads {
        reads.entry(read.binding).or_default().push(*read);
    }
    let mut writes = BTreeMap::<BindingId, Vec<RenderedWrite>>::new();
    for write in facts.writes {
        writes.entry(write.binding).or_default().push(*write);
    }
    let mut elided = BTreeMap::<BindingId, Vec<ElidedDefinition>>::new();
    for definition in facts.elided {
        elided
            .entry(definition.binding)
            .or_default()
            .push(*definition);
    }
    let mut merges = BTreeMap::<BindingId, Vec<&ReachingMerge>>::new();
    for merge in facts.merges {
        if let Some(binding) = (facts.binding_of)(merge.output) {
            merges.entry(binding).or_default().push(merge);
        }
    }
    let mut entry_values = BTreeMap::<BindingId, Vec<ValueId>>::new();
    for value in facts.entry_values {
        if let Some(binding) = (facts.binding_of)(*value) {
            entry_values.entry(binding).or_default().push(*value);
        }
    }
    let mut stale = Vec::new();
    for (binding, binding_reads) in &reads {
        let flow = VariableFlow::new(
            facts,
            VariableEvents {
                reads: binding_reads,
                writes: writes.get(binding).map_or(&[], Vec::as_slice),
                elided: elided.get(binding).map_or(&[], Vec::as_slice),
            },
            merges.remove(binding).unwrap_or_default(),
            entry_values.get(binding).map_or(&[], Vec::as_slice),
        );
        if !flow.is_trivial() {
            stale.extend(flow.stale_reads(cfg, facts, &order));
        }
    }
    stale
}

/// How the stale reads are answered: the values that leave their variable
/// for one of their own, and the reads nothing can split.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReachingRepair {
    pub(crate) evict: BTreeSet<ValueId>,
    pub(crate) unsplittable: Vec<StaleRead>,
    /// The binding every value had in the plan the reads were checked
    /// against, `u32::MAX` for none: what a split refines.
    pub(crate) partition: Option<std::rc::Rc<[u32]>>,
}

impl ReachingRepair {
    /// Whether every read saw its value.
    pub(crate) fn is_empty(&self) -> bool {
        self.evict.is_empty() && self.unsplittable.is_empty()
    }
}

/// Split each stale read's variable so that the read sees its value.
///
/// A stale read of `v` through a variable holding other values too takes `v`
/// out: `v` gets a variable of its own, every write of `v` writes it and every
/// read of `v` reads it, and the variable it left only gets finer. A value the
/// function was entered with is what its variable was made to hold -- a
/// parameter's home -- so there the values that overwrote it leave instead. A
/// read of a variable holding one value, or of an entry value nothing
/// nameable overwrote, has nothing to split: it is the residual.
pub(crate) fn reaching_repair(
    stale: Vec<StaleRead>,
    facts: &ReachingFacts<'_>,
    members: &dyn Fn(BindingId) -> usize,
) -> ReachingRepair {
    let mut repair = ReachingRepair::default();
    for read in stale {
        let binding = read.read.binding;
        if members(binding) < 2 {
            repair.unsplittable.push(read);
        } else if !facts.entry_values.contains(&read.read.value) {
            repair.evict.insert(read.read.value);
        } else {
            let overwriting = read
                .instead
                .iter()
                .copied()
                .filter(|value| {
                    (facts.binding_of)(*value) == Some(binding)
                        && !facts.entry_values.contains(value)
                })
                .collect::<Vec<_>>();
            if overwriting.is_empty() {
                repair.unsplittable.push(read);
            } else {
                repair.evict.extend(overwriting);
            }
        }
    }
    repair
}

#[cfg(test)]
mod reaching_tests {
    use super::*;

    /// A control flow graph spelled as edges between block addresses.
    struct Edges {
        entry: u64,
        order: Vec<u64>,
        edges: Vec<(u64, u64)>,
    }

    impl ReachingControlFlow for Edges {
        fn entry(&self) -> u64 {
            self.entry
        }

        fn reverse_postorder(&self) -> Vec<u64> {
            self.order.clone()
        }

        fn predecessors(&self, block: u64) -> Vec<u64> {
            self.edges
                .iter()
                .filter(|(_, to)| *to == block)
                .map(|(from, _)| *from)
                .collect()
        }
    }

    const B: BindingId = BindingId(0);

    fn read(value: u32, block: u64, order: u64) -> RenderedRead {
        RenderedRead {
            binding: B,
            value: ValueId(value),
            block,
            order,
            region: 0,
            at: None,
        }
    }

    fn write(value: u32, block: u64, order: u64) -> RenderedWrite {
        RenderedWrite {
            binding: B,
            value: Some(ValueId(value)),
            block,
            order,
            region: 0,
            ordinal: Some(order as usize),
        }
    }

    /// Check `reads` and `writes` of the one variable every value is bound
    /// to, and split what is stale.
    fn check(
        cfg: &Edges,
        reads: &[RenderedRead],
        writes: &[RenderedWrite],
        merges: &[ReachingMerge],
        entry: &[u32],
    ) -> (Vec<StaleRead>, ReachingRepair) {
        let entry_values = entry.iter().copied().map(ValueId).collect::<BTreeSet<_>>();
        let binding_of = |_: ValueId| Some(B);
        let re_expresses = |_: ValueId| None;
        let facts = ReachingFacts {
            reads,
            writes,
            elided: &[],
            merges,
            binding_of: &binding_of,
            re_expresses: &re_expresses,
            entry_values: &entry_values,
            exclusive: &|_, _| false,
        };
        let stale = stale_reads(cfg, &facts);
        let repair = reaching_repair(stale.clone(), &facts, &|_| 2);
        (stale, repair)
    }

    fn straight_line() -> Edges {
        Edges {
            entry: 0x10,
            order: vec![0x10],
            edges: vec![],
        }
    }

    /// Two values one liveness judgement put in one variable, and a read of
    /// the first placed after the second is written: `x = a; x = b; use(x)`
    /// where the use stands for `a`. The read is stale, and the repair gives
    /// `a` a variable of its own.
    #[test]
    fn an_injected_stale_read_is_found_and_its_value_split_out() {
        let (stale, repair) = check(
            &straight_line(),
            &[read(1, 0x10, 3), read(2, 0x10, 4)],
            &[write(1, 0x10, 1), write(2, 0x10, 2)],
            &[],
            &[],
        );
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert_eq!(stale[0].read.value, ValueId(1));
        assert_eq!(stale[0].instead, BTreeSet::from([ValueId(2)]));
        assert_eq!(repair.evict, BTreeSet::from([ValueId(1)]));
        assert!(repair.unsplittable.is_empty());
    }

    /// A loop whose carrier and its update share one variable. Read after
    /// the update is written, the carrier is stale -- the lost copy -- and
    /// read before it, it is not.
    #[test]
    fn a_carrier_read_after_its_update_is_written_is_stale() {
        // 0x10 -> 0x20 (header) -> 0x30 (latch) -> 0x20, 0x20 -> 0x40.
        let cfg = Edges {
            entry: 0x10,
            order: vec![0x10, 0x20, 0x30, 0x40],
            edges: vec![(0x10, 0x20), (0x20, 0x30), (0x30, 0x20), (0x20, 0x40)],
        };
        // v1 = init; v2 = phi(v1, v3); v3 = v2 + 1.
        let merges = [ReachingMerge {
            block: 0x20,
            output: ValueId(2),
            incoming: vec![(0x10, ValueId(1)), (0x30, ValueId(3))],
        }];
        let writes = [write(1, 0x10, 1), write(3, 0x30, 6)];
        let (stale, _) = check(
            &cfg,
            &[read(2, 0x20, 3), read(2, 0x30, 5), read(2, 0x40, 9)],
            &writes,
            &merges,
            &[],
        );
        assert!(stale.is_empty(), "{stale:?}");
        let (stale, repair) = check(
            &cfg,
            &[read(2, 0x20, 3), read(2, 0x30, 7), read(2, 0x40, 9)],
            &writes,
            &merges,
            &[],
        );
        assert_eq!(
            stale
                .iter()
                .map(|stale| stale.read.order)
                .collect::<Vec<_>>(),
            vec![7],
            "{stale:?}"
        );
        assert_eq!(repair.evict, BTreeSet::from([ValueId(2)]));
    }

    /// A merge only one of whose edges delivers its input in the variable
    /// does not put its output there: the other edge left something else.
    #[test]
    fn a_merge_is_held_only_where_every_edge_delivers_its_input() {
        // 0x10 -> 0x20, 0x10 -> 0x30, both -> 0x40.
        let cfg = Edges {
            entry: 0x10,
            order: vec![0x10, 0x20, 0x30, 0x40],
            edges: vec![(0x10, 0x20), (0x10, 0x30), (0x20, 0x40), (0x30, 0x40)],
        };
        let merges = [ReachingMerge {
            block: 0x40,
            output: ValueId(4),
            incoming: vec![(0x20, ValueId(2)), (0x30, ValueId(3))],
        }];
        // The arm at 0x30 writes 3 and then 5, so it leaves 5 behind.
        let (stale, repair) = check(
            &cfg,
            &[read(4, 0x40, 9)],
            &[write(2, 0x20, 1), write(3, 0x30, 2), write(5, 0x30, 3)],
            &merges,
            &[],
        );
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert_eq!(stale[0].instead, BTreeSet::from([ValueId(2), ValueId(5)]));
        assert_eq!(repair.evict, BTreeSet::from([ValueId(4)]));
    }

    /// A parameter's home overwritten before the parameter is read: the
    /// parameter is what the variable exists for, so the value that
    /// overwrote it is the one that leaves.
    #[test]
    fn an_overwritten_entry_value_evicts_what_overwrote_it() {
        let (stale, repair) = check(
            &straight_line(),
            &[read(0, 0x10, 1), read(0, 0x10, 5)],
            &[write(7, 0x10, 3)],
            &[],
            &[0],
        );
        assert_eq!(
            stale
                .iter()
                .map(|stale| stale.read.order)
                .collect::<Vec<_>>(),
            vec![5]
        );
        assert_eq!(repair.evict, BTreeSet::from([ValueId(7)]));
    }

    /// A variable holding one value has nothing to split off: its stale read
    /// is the residual.
    #[test]
    fn a_stale_read_of_a_variable_of_one_value_is_unsplittable() {
        let reads = [read(1, 0x10, 5)];
        let writes = [
            write(1, 0x10, 1),
            RenderedWrite {
                binding: B,
                value: None,
                block: 0x10,
                order: 3,
                region: 0,
                ordinal: Some(3),
            },
        ];
        let entry_values = BTreeSet::new();
        let binding_of = |_: ValueId| Some(B);
        let re_expresses = |_: ValueId| None;
        let facts = ReachingFacts {
            reads: &reads,
            writes: &writes,
            elided: &[],
            merges: &[],
            binding_of: &binding_of,
            re_expresses: &re_expresses,
            entry_values: &entry_values,
            exclusive: &|_, _| false,
        };
        let stale = stale_reads(&straight_line(), &facts);
        let repair = reaching_repair(stale, &facts, &|_| 1);
        assert!(repair.evict.is_empty());
        assert_eq!(repair.unsplittable.len(), 1);
        assert!(repair.unsplittable[0].instead.is_empty());
    }

    /// A copy's destination holds its source too, by the copy's own syntax:
    /// reading the source after the copy is written sees it.
    #[test]
    fn a_copy_holds_what_it_copies() {
        let reads = [read(1, 0x10, 5)];
        let writes = [write(1, 0x10, 1), write(2, 0x10, 3)];
        let entry_values = BTreeSet::new();
        let binding_of = |_: ValueId| Some(B);
        let re_expresses = |value: ValueId| (value == ValueId(2)).then_some(ValueId(1));
        let facts = ReachingFacts {
            reads: &reads,
            writes: &writes,
            elided: &[],
            merges: &[],
            binding_of: &binding_of,
            re_expresses: &re_expresses,
            entry_values: &entry_values,
            exclusive: &|_, _| false,
        };
        assert!(stale_reads(&straight_line(), &facts).is_empty());
    }

    /// A block the structured form rendered once in each of two exclusive
    /// arms is two copies, each entered with what the block is entered with:
    /// the first copy's write does not reach the second copy's read. Where
    /// the regions are not exclusive, the same occurrences are one sequence
    /// and the read after the write is stale.
    #[test]
    fn copies_of_one_block_in_exclusive_arms_are_entered_apart() {
        let in_region = |mut read: RenderedRead, region| {
            read.region = region;
            read
        };
        let written_in = |mut write: RenderedWrite, region| {
            write.region = region;
            write
        };
        let reads = [
            in_region(read(0, 0x10, 5), 1),
            in_region(read(0, 0x10, 8), 2),
        ];
        let writes = [
            written_in(write(3, 0x10, 6), 1),
            written_in(write(3, 0x10, 9), 2),
        ];
        let entry_values = BTreeSet::from([ValueId(0)]);
        let binding_of = |_: ValueId| Some(B);
        let re_expresses = |_: ValueId| None;
        let check = |exclusive: &dyn Fn(usize, usize) -> bool| {
            let facts = ReachingFacts {
                reads: &reads,
                writes: &writes,
                elided: &[],
                merges: &[],
                binding_of: &binding_of,
                re_expresses: &re_expresses,
                entry_values: &entry_values,
                exclusive,
            };
            stale_reads(&straight_line(), &facts)
                .iter()
                .map(|stale| stale.read.order)
                .collect::<Vec<_>>()
        };
        assert_eq!(check(&|left, right| left != right), Vec::<u64>::new());
        assert_eq!(check(&|_, _| false), vec![8]);
    }

    /// A definition the text elides is placed among the variable's writes by
    /// its instruction: a copy names what the variable holds only where its
    /// source is held, and a later write ends it like any other value.
    #[test]
    fn an_elided_copy_holds_where_its_source_is_and_until_the_next_write() {
        let elided = |value: u32, ordinal: usize, source: u32| ElidedDefinition {
            binding: B,
            value: ValueId(value),
            block: 0x10,
            ordinal,
            source: ElidedSource::Value(ValueId(source)),
        };
        // v1 written at 1; w2 = copy v1 at 2; v3 written at 4; w5 = copy v9,
        // which the variable never holds, at 5.
        let writes = [write(1, 0x10, 1), write(3, 0x10, 4)];
        let copies = [elided(2, 2, 1), elided(5, 5, 9)];
        let reads = [read(2, 0x10, 3), read(2, 0x10, 6), read(5, 0x10, 7)];
        let entry_values = BTreeSet::new();
        let binding_of = |_: ValueId| Some(B);
        let re_expresses = |_: ValueId| None;
        let facts = ReachingFacts {
            reads: &reads,
            writes: &writes,
            elided: &copies,
            merges: &[],
            binding_of: &binding_of,
            re_expresses: &re_expresses,
            entry_values: &entry_values,
            exclusive: &|_, _| false,
        };
        assert_eq!(
            stale_reads(&straight_line(), &facts)
                .iter()
                .map(|stale| (stale.read.value.0, stale.read.order))
                .collect::<Vec<_>>(),
            vec![(2, 6), (5, 7)]
        );
    }
}
