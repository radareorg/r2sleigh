//! What the collector reads off each branch.

use super::super::*;
use super::*;

#[test]
fn predicate_branch_assumption_wrong_block_preserves_base_semantics() {
    let base = predicate_assumption_diamond();
    let predicate = base
        .predicates()
        .predicates
        .values()
        .next()
        .expect("diamond predicate")
        .clone();
    let assumption = predicate_branch_assumption(
        &predicate,
        predicate.true_target,
        Some(predicate.true_target),
        true,
    );

    assert_conflicting_predicate_assumption_preserves_semantics(
        &base,
        assumption,
        "predicate block mismatch (expected 0x9040, observed 0x9000)",
    );
}

#[test]
fn predicate_branch_assumption_wrong_predecessor_preserves_base_semantics() {
    let base = predicate_assumption_diamond();
    let predicate = base
        .predicates()
        .predicates
        .values()
        .next()
        .expect("diamond predicate")
        .clone();
    let assumption = predicate_branch_assumption(
        &predicate,
        predicate.block_addr,
        Some(predicate.false_target),
        true,
    );

    assert_conflicting_predicate_assumption_preserves_semantics(
        &base,
        assumption,
        "branch predecessor 0x9004 does not match selected edge 0x9040",
    );
}

#[test]
fn valid_predicate_branch_assumption_binds_without_mutating_source_facts() {
    let base = predicate_assumption_diamond();
    let predicate = base
        .predicates()
        .predicates
        .values()
        .next()
        .expect("diamond predicate")
        .clone();
    let assumption = predicate_branch_assumption(
        &predicate,
        predicate.block_addr,
        Some(predicate.true_target),
        true,
    );
    let conditioned = base.with_assumptions(&AssumptionSet::new(vec![assumption.clone()]));

    assert_predicate_assumption_preserves_source_semantics(&base, &conditioned);
    assert_eq!(conditioned.facts().assumption_usage.applied, [assumption]);
    assert!(conditioned.facts().assumption_usage.ignored.is_empty());
    assert!(conditioned.facts().assumption_usage.conflicts.is_empty());
    assert_eq!(conditioned.facts().applied_assumption_bindings.len(), 1);
    assert!(matches!(
        conditioned.facts().applied_assumption_bindings[0].binding,
        super::super::PreparedAssumptionBindingKind::Predicate {
            predicate: bound,
            block_addr,
            predecessor: Some(selected),
            truth: true,
        } if bound == predicate.id
            && block_addr == predicate.block_addr
            && selected == predicate.true_target
    ));
}

#[test]
fn contradictory_predicate_branch_assumptions_leave_source_facts_unchanged() {
    let base = predicate_assumption_diamond();
    let predicate = base
        .predicates()
        .predicates
        .values()
        .next()
        .expect("diamond predicate")
        .clone();
    let assumptions = AssumptionSet::new(vec![
        predicate_branch_assumption(
            &predicate,
            predicate.block_addr,
            Some(predicate.true_target),
            true,
        ),
        predicate_branch_assumption(
            &predicate,
            predicate.block_addr,
            Some(predicate.false_target),
            false,
        ),
    ]);
    let conditioned = base.with_assumptions(&assumptions);

    assert_predicate_assumption_preserves_source_semantics(&base, &conditioned);
    assert!(conditioned.facts().applied_assumption_bindings.is_empty());
    assert!(conditioned.facts().assumption_usage.applied.is_empty());
    assert!(conditioned.facts().assumption_usage.ignored.is_empty());
    assert_eq!(conditioned.facts().assumption_usage.conflicts.len(), 2);
    assert!(
        conditioned
            .facts()
            .assumption_usage
            .conflicts
            .iter()
            .all(|conflict| { conflict.reason == "contradictory branch truths for predicate 0" })
    );
}

#[test]
fn contradictory_predicate_preflight_is_input_order_independent() {
    let base = predicate_assumption_diamond();
    let predicate = base
        .predicates()
        .predicates
        .values()
        .next()
        .expect("diamond predicate")
        .clone();
    let truth = predicate_branch_assumption(
        &predicate,
        predicate.block_addr,
        Some(predicate.true_target),
        true,
    );
    let falsehood = predicate_branch_assumption(
        &predicate,
        predicate.block_addr,
        Some(predicate.false_target),
        false,
    );
    let first = base.with_assumptions(&AssumptionSet::new(vec![truth.clone(), falsehood.clone()]));
    let second = base.with_assumptions(&AssumptionSet::new(vec![falsehood, truth]));

    for conditioned in [&first, &second] {
        assert_predicate_assumption_preserves_source_semantics(&base, conditioned);
        assert!(conditioned.facts().applied_assumption_bindings.is_empty());
        assert_eq!(conditioned.facts().assumption_usage.conflicts.len(), 2);
        assert_eq!(
            conditioned
                .facts()
                .assumption_usage
                .conflicts
                .iter()
                .filter_map(|conflict| match conflict.assumption.value {
                    AssumptionValue::Branch { truth } => Some(truth),
                    _ => None,
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([false, true])
        );
    }
}
