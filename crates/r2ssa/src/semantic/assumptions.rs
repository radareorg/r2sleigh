//! What an operator assumed, and whether the body used it.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PredicateBranchAssumptionResolution {
    Applied {
        predicate: PredicateId,
        block_addr: u64,
        predecessor: Option<u64>,
        truth: bool,
    },
    Ignored,
    Conflict(String),
}

pub(crate) fn resolve_predicate_branch_assumption(
    predicates: &PredicateFacts,
    assumption: &crate::AnalysisAssumption,
) -> Option<PredicateBranchAssumptionResolution> {
    let (
        AssumptionSubject::Predicate {
            predicate,
            block_addr,
            predecessor,
        },
        AssumptionValue::Branch { truth },
    ) = (&assumption.subject, &assumption.value)
    else {
        return None;
    };
    let Some(fact) = predicates.predicates.get(predicate) else {
        return Some(PredicateBranchAssumptionResolution::Ignored);
    };
    if fact.block_addr != *block_addr {
        return Some(PredicateBranchAssumptionResolution::Conflict(format!(
            "predicate block mismatch (expected 0x{block_addr:x}, observed 0x{:x})",
            fact.block_addr
        )));
    }
    if let Some(predecessor) = predecessor {
        let expected = if *truth {
            fact.true_target
        } else {
            fact.false_target
        };
        if *predecessor != expected {
            return Some(PredicateBranchAssumptionResolution::Conflict(format!(
                "branch predecessor 0x{predecessor:x} does not match selected edge 0x{expected:x}"
            )));
        }
    }
    Some(PredicateBranchAssumptionResolution::Applied {
        predicate: *predicate,
        block_addr: *block_addr,
        predecessor: *predecessor,
        truth: *truth,
    })
}

pub(crate) fn contradictory_predicate_assumptions(
    predicates: &PredicateFacts,
    assumptions: &AssumptionSet,
) -> BTreeSet<PredicateId> {
    let mut truths = BTreeMap::<PredicateId, BTreeSet<bool>>::new();
    for assumption in assumptions.iter() {
        let Some(PredicateBranchAssumptionResolution::Applied {
            predicate, truth, ..
        }) = resolve_predicate_branch_assumption(predicates, assumption)
        else {
            continue;
        };
        truths.entry(predicate).or_default().insert(truth);
    }
    truths
        .into_iter()
        .filter_map(|(predicate, truths)| (truths.len() > 1).then_some(predicate))
        .collect()
}

pub(crate) fn collect_prepared_assumption_usage(
    graph: &SsaGraph,
    objects: &ObjectModel,
    base_predicates: &PredicateFacts,
    assumptions: &AssumptionSet,
    machine_context: Option<&SourceMachineContext>,
) -> (Vec<PreparedAssumptionBinding>, AssumptionUsageReport) {
    let mut bindings = Vec::new();
    let mut usage = AssumptionUsageReport::default();
    let contradictory = contradictory_predicate_assumptions(base_predicates, assumptions);

    for assumption in assumptions.iter() {
        if let Some(resolution) = resolve_predicate_branch_assumption(base_predicates, assumption) {
            match resolution {
                PredicateBranchAssumptionResolution::Applied {
                    predicate,
                    block_addr,
                    predecessor,
                    truth,
                } => {
                    if contradictory.contains(&predicate) {
                        usage.mark_conflict(
                            assumption,
                            format!("contradictory branch truths for predicate {}", predicate.0),
                        );
                        continue;
                    }
                    usage.mark_applied(assumption);
                    bindings.push(PreparedAssumptionBinding {
                        assumption: assumption.clone(),
                        binding: PreparedAssumptionBindingKind::Predicate {
                            predicate,
                            block_addr,
                            predecessor,
                            truth,
                        },
                    });
                }
                PredicateBranchAssumptionResolution::Ignored => {
                    usage.mark_ignored(assumption);
                }
                PredicateBranchAssumptionResolution::Conflict(reason) => {
                    usage.mark_conflict(assumption, reason);
                }
            }
            continue;
        }
        match (&assumption.subject, &assumption.value) {
            (AssumptionSubject::Register { name }, _) => {
                let Some(machine_context) = machine_context else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                let Some(storage) = machine_context.register_storage(name) else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                let mut candidates = graph.values.iter().filter(|value| {
                    value.var.version == 0 && value.canonical_storage == Some(storage)
                });
                let Some(value) = candidates.next() else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                if candidates.next().is_some() {
                    usage.mark_conflict(
                        assumption,
                        "canonical register storage has multiple entry SSA values",
                    );
                    continue;
                }
                usage.mark_applied(assumption);
                bindings.push(PreparedAssumptionBinding {
                    assumption: assumption.clone(),
                    binding: PreparedAssumptionBindingKind::Register {
                        storage,
                        value: value.id,
                        state_name: value.var.display_name(),
                        bits: storage.size.saturating_mul(8),
                    },
                });
            }
            (AssumptionSubject::StackSlot { base, offset }, _) => {
                let Some((root, object)) =
                    objects.stack_objects.iter().find_map(|(key, object)| {
                        let root = key.root;
                        (key.space == SpaceId::Ram && root.base == *base && root.offset == *offset)
                            .then_some((root, *object))
                    })
                else {
                    usage.mark_ignored(assumption);
                    continue;
                };
                usage.mark_applied(assumption);
                bindings.push(PreparedAssumptionBinding {
                    assumption: assumption.clone(),
                    binding: PreparedAssumptionBindingKind::StackSlot {
                        base: root.base,
                        offset: root.offset,
                        object,
                    },
                });
            }
            _ => usage.mark_ignored(assumption),
        }
    }

    (bindings, usage)
}
