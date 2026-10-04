//! What each branch tests, and what a switch dispatches on.

use super::*;
use crate::dense::IdMap;

pub(crate) fn collect_predicate_facts(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
) -> PredicateFacts {
    let mut predicates = BTreeMap::new();
    let mut block_assumptions = BTreeMap::<u64, Vec<BlockAssumption>>::new();
    let mut switches = BTreeMap::new();
    let compare_defs = collect_compare_defs(prep, graph);
    let evaluated_compare_defs = &compare_defs.evaluated;
    let compare_defs = &compare_defs.normalized;
    let mut next_predicate_id = 0u32;

    for &block_addr in function.block_addrs() {
        let Some(block) = function.get_block(block_addr) else {
            continue;
        };
        let Some(cfg_block) = function.cfg().get_block(block_addr) else {
            continue;
        };
        match &cfg_block.terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                let Some((_, cond)) = crate::branch_condition(block) else {
                    continue;
                };
                let condition = graph.value_of(*cond).expect("predicate condition in graph");
                let id = PredicateId(next_predicate_id);
                next_predicate_id = next_predicate_id.saturating_add(1);
                predicates.insert(
                    id,
                    PredicateFact {
                        id,
                        block_addr,
                        condition,
                        comparison: compare_defs.get(condition).cloned(),
                        evaluated_comparison: evaluated_compare_defs.get(condition).cloned(),
                        true_target: *true_target,
                        false_target: *false_target,
                    },
                );
                block_assumptions
                    .entry(*true_target)
                    .or_default()
                    .push(BlockAssumption {
                        predecessor: block_addr,
                        predicate: id,
                        truth: true,
                    });
                block_assumptions
                    .entry(*false_target)
                    .or_default()
                    .push(BlockAssumption {
                        predecessor: block_addr,
                        predicate: id,
                        truth: false,
                    });
            }
            BlockTerminator::Switch { cases, default } => {
                switches.insert(
                    block_addr,
                    SwitchPredicateFact {
                        block_addr,
                        // A fused comparison chain names its selector
                        // outright. A dispatch through a table does not, and
                        // what it switches on comes from the value analysis,
                        // which has not run yet -- it is filled in there.
                        selector: block.ops().iter().rev().find_map(|op| match op {
                            SSAOp::Switch { selector } => graph.value_of(*selector),
                            _ => None,
                        }),
                        cases: cases.clone(),
                        default: *default,
                    },
                );
            }
            _ => {}
        }
    }

    PredicateFacts {
        predicates,
        block_assumptions,
        switches,
    }
}

/// A comparison per value: which values compare what, by the graph's ids.
pub(crate) type CompareMap = IdMap<ValueId, CompareProvenance>;

/// The two operands of a subtraction or flag a comparison is read from.
type SourcePairs = IdMap<ValueId, (ValueId, ValueId)>;

pub(crate) struct CompareDefinitions {
    pub(crate) normalized: CompareMap,
    pub(crate) evaluated: CompareMap,
}

/// The graph's operations in block order. An operand is defined by an
/// operation that dominates its reader, and so comes before it: a single
/// pass in this order sees every operand settled.
fn graph_ops(graph: &SsaGraph) -> impl Iterator<Item = &SSAOp<ValueId>> {
    graph.insts.iter().filter_map(|inst| match &inst.payload {
        InstPayload::Op(op) => Some(op),
        InstPayload::Phi { .. } => None,
    })
}

pub(crate) fn collect_compare_defs(
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
) -> CompareDefinitions {
    let len = graph.values.len();
    let mut normalized = CompareMap::new(len);
    let mut evaluated = CompareMap::new(len);
    // A compared operand is named by its copy class: the values with its bits
    // at its width, as the one identity fact states them.
    let views = prep.map(|facts| &facts.views);
    let operand = |value: ValueId| crate::view::class_value(graph, views, value);
    let constant = |value: ValueId| graph.var(value).constant_bits();
    let mut sub_sources = SourcePairs::new(len);
    let mut signed_overflow_sources = SourcePairs::new(len);
    let mut signed_sign_sources = SourcePairs::new(len);

    for op in graph_ops(graph) {
        if let SSAOp::IntSub { dst, a, b } = *op {
            sub_sources.insert(dst, (operand(a), operand(b)));
        }
    }

    for op in graph_ops(graph) {
        if let SSAOp::IntSBorrow { dst, a, b } = *op {
            signed_overflow_sources.insert(dst, (operand(a), operand(b)));
        }
        if let SSAOp::IntSLess { dst, a, b } = *op
            && constant(b) == Some(0)
            && let Some(pair) = sub_sources.get(a).copied()
        {
            signed_sign_sources.insert(dst, pair);
        }
    }
    propagate_compare_source_aliases(graph, &mut signed_overflow_sources);
    propagate_compare_source_aliases(graph, &mut signed_sign_sources);

    for op in graph_ops(graph) {
        let signed = signed_flag_compare_components(
            graph,
            op,
            &signed_overflow_sources,
            &signed_sign_sources,
        );
        if let Some((dst, kind, lhs, rhs)) = compare_components(op) {
            let (lhs_id, rhs_id) = (operand(*lhs), operand(*rhs));
            evaluated.insert(
                *dst,
                CompareProvenance {
                    kind,
                    lhs: lhs_id,
                    rhs: rhs_id,
                },
            );
            let (normalized_lhs, normalized_rhs) = normalize_zero_sub_compare_operands(
                graph,
                kind,
                (*lhs, *rhs),
                (lhs_id, rhs_id),
                &sub_sources,
            );
            normalized.insert(
                *dst,
                CompareProvenance {
                    kind,
                    lhs: normalized_lhs,
                    rhs: normalized_rhs,
                },
            );
        }
        if let Some((dst, kind, lhs, rhs)) = signed {
            let comparison = CompareProvenance { kind, lhs, rhs };
            normalized.insert(dst, comparison.clone());
            evaluated.insert(dst, comparison);
        }
    }

    propagate_compare_definitions(graph, &mut normalized);
    propagate_compare_definitions(graph, &mut evaluated);
    CompareDefinitions {
        normalized,
        evaluated,
    }
}

/// Carry each comparison through the operations that keep it: copies,
/// extensions, the low piece, negation, and the conjunction or disjunction of
/// two.
///
/// One pass. No phi carries a comparison here, and an operation's operands
/// are defined by operations that dominate it, which come before it in
/// reverse postorder: so every operand is settled when its reader is
/// reached. Each value is defined once, so nothing is overwritten.
pub(crate) fn propagate_compare_definitions(graph: &SsaGraph, compare_defs: &mut CompareMap) {
    for op in graph_ops(graph) {
        let propagated = match *op {
            SSAOp::Copy { dst, src }
            | SSAOp::Cast { dst, src }
            | SSAOp::IntZExt { dst, src }
            | SSAOp::IntSExt { dst, src }
            | SSAOp::Trunc { dst, src }
            | SSAOp::Subpiece {
                dst,
                src,
                offset: 0,
            } => compare_defs
                .get(src)
                .cloned()
                .map(|comparison| (dst, comparison)),
            SSAOp::BoolNot { dst, src } => compare_defs
                .get(src)
                .and_then(invert_compare_provenance)
                .map(|comparison| (dst, comparison)),
            SSAOp::BoolAnd { dst, a, b } => compare_defs
                .get(a)
                .zip(compare_defs.get(b))
                .and_then(|(lhs, rhs)| combine_compare_provenance(graph, lhs, rhs, false))
                .map(|comparison| (dst, comparison)),
            SSAOp::BoolOr { dst, a, b } => compare_defs
                .get(a)
                .zip(compare_defs.get(b))
                .and_then(|(lhs, rhs)| combine_compare_provenance(graph, lhs, rhs, true))
                .map(|comparison| (dst, comparison)),
            _ => None,
        };
        if let Some((dst, comparison)) = propagated {
            compare_defs.insert(dst, comparison);
        }
    }
}

/// Carry each comparison's operands through the operations that keep a
/// value's bits: one pass, for the reason `propagate_compare_definitions`
/// is one.
fn propagate_compare_source_aliases(graph: &SsaGraph, sources: &mut SourcePairs) {
    for op in graph_ops(graph) {
        let (SSAOp::Copy { dst, src }
        | SSAOp::Cast { dst, src }
        | SSAOp::IntZExt { dst, src }
        | SSAOp::IntSExt { dst, src }
        | SSAOp::Trunc { dst, src }
        | SSAOp::Subpiece {
            dst,
            src,
            offset: 0,
        }) = *op
        else {
            continue;
        };
        if let Some(source) = sources.get(src).copied() {
            sources.insert(dst, source);
        }
    }
}

pub(crate) fn invert_compare_provenance(
    comparison: &CompareProvenance,
) -> Option<CompareProvenance> {
    let (kind, swap_operands) = match comparison.kind {
        CompareKind::Equal => (CompareKind::NotEqual, false),
        CompareKind::NotEqual => (CompareKind::Equal, false),
        CompareKind::Less => (CompareKind::LessEqual, true),
        CompareKind::SignedLess => (CompareKind::SignedLessEqual, true),
        CompareKind::LessEqual => (CompareKind::Less, true),
        CompareKind::SignedLessEqual => (CompareKind::SignedLess, true),
    };
    Some(CompareProvenance {
        kind,
        lhs: if swap_operands {
            comparison.rhs
        } else {
            comparison.lhs
        },
        rhs: if swap_operands {
            comparison.lhs
        } else {
            comparison.rhs
        },
    })
}

pub(crate) fn combine_compare_provenance(
    graph: &SsaGraph,
    lhs: &CompareProvenance,
    rhs: &CompareProvenance,
    is_or: bool,
) -> Option<CompareProvenance> {
    combine_compare_provenance_by(lhs, rhs, is_or, |lhs, rhs| {
        compare_values_equivalent(graph, lhs, rhs)
    })
}

pub(crate) fn combine_compare_provenance_by(
    lhs: &CompareProvenance,
    rhs: &CompareProvenance,
    is_or: bool,
    equivalent: impl Fn(ValueId, ValueId) -> bool,
) -> Option<CompareProvenance> {
    if lhs.kind == rhs.kind && equivalent(lhs.lhs, rhs.lhs) && equivalent(lhs.rhs, rhs.rhs) {
        return Some(lhs.clone());
    }

    let equality_operands_match = |ordered: &CompareProvenance, equality: &CompareProvenance| {
        equivalent(ordered.lhs, equality.lhs) && equivalent(ordered.rhs, equality.rhs)
            || equivalent(ordered.lhs, equality.rhs) && equivalent(ordered.rhs, equality.lhs)
    };
    let (ordered, equality) = if matches!(
        lhs.kind,
        CompareKind::Less
            | CompareKind::SignedLess
            | CompareKind::LessEqual
            | CompareKind::SignedLessEqual
    ) && matches!(rhs.kind, CompareKind::Equal | CompareKind::NotEqual)
    {
        (lhs, rhs)
    } else if matches!(
        rhs.kind,
        CompareKind::Less
            | CompareKind::SignedLess
            | CompareKind::LessEqual
            | CompareKind::SignedLessEqual
    ) && matches!(lhs.kind, CompareKind::Equal | CompareKind::NotEqual)
    {
        (rhs, lhs)
    } else {
        return None;
    };
    if !equality_operands_match(ordered, equality) {
        return None;
    }

    let kind = match (is_or, ordered.kind, equality.kind) {
        (true, CompareKind::Less, CompareKind::Equal) => CompareKind::LessEqual,
        (true, CompareKind::SignedLess, CompareKind::Equal) => CompareKind::SignedLessEqual,
        (false, CompareKind::LessEqual, CompareKind::NotEqual) => CompareKind::Less,
        (false, CompareKind::SignedLessEqual, CompareKind::NotEqual) => CompareKind::SignedLess,
        _ => return None,
    };
    Some(CompareProvenance {
        kind,
        lhs: ordered.lhs,
        rhs: ordered.rhs,
    })
}

pub(crate) fn compare_values_equivalent(graph: &SsaGraph, lhs: ValueId, rhs: ValueId) -> bool {
    compare_values_equivalent_inner(graph, lhs, rhs, 0, &mut BTreeSet::new())
}

pub(crate) fn compare_values_equivalent_inner(
    graph: &SsaGraph,
    lhs: ValueId,
    rhs: ValueId,
    depth: usize,
    visiting: &mut BTreeSet<(ValueId, ValueId)>,
) -> bool {
    if lhs == rhs {
        return true;
    }
    if depth >= 16 {
        return false;
    }
    let pair = if lhs < rhs { (lhs, rhs) } else { (rhs, lhs) };
    if !visiting.insert(pair) {
        return false;
    }
    let equivalent = (|| {
        let lhs_value = graph.value(lhs)?;
        let rhs_value = graph.value(rhs)?;
        if lhs_value.var.size != rhs_value.var.size {
            return Some(false);
        }
        if lhs_value.var.constant_bits().is_some() || rhs_value.var.constant_bits().is_some() {
            return Some(
                lhs_value.var.constant_bits().is_some()
                    && rhs_value.var.constant_bits().is_some()
                    && const_value(&lhs_value.var) == const_value(&rhs_value.var),
            );
        }
        let lhs_inst = graph.inst(graph.def_inst(lhs)?)?;
        let rhs_inst = graph.inst(graph.def_inst(rhs)?)?;
        let (InstPayload::Op(lhs_op), InstPayload::Op(rhs_op)) =
            (&lhs_inst.payload, &rhs_inst.payload)
        else {
            return Some(false);
        };
        let mut equivalent_sources = |lhs: &ValueId, rhs: &ValueId| {
            compare_values_equivalent_inner(graph, *lhs, *rhs, depth + 1, visiting)
        };
        Some(match (lhs_op, rhs_op) {
            (
                SSAOp::Subpiece {
                    src: lhs,
                    offset: lhs_offset,
                    ..
                },
                SSAOp::Subpiece {
                    src: rhs,
                    offset: rhs_offset,
                    ..
                },
            ) => lhs_offset == rhs_offset && equivalent_sources(lhs, rhs),
            (SSAOp::IntZExt { src: lhs, .. }, SSAOp::IntZExt { src: rhs, .. })
            | (SSAOp::IntSExt { src: lhs, .. }, SSAOp::IntSExt { src: rhs, .. })
            | (SSAOp::Trunc { src: lhs, .. }, SSAOp::Trunc { src: rhs, .. })
            | (SSAOp::Cast { src: lhs, .. }, SSAOp::Cast { src: rhs, .. }) => {
                equivalent_sources(lhs, rhs)
            }
            _ => false,
        })
    })()
    .unwrap_or(false);
    visiting.remove(&pair);
    equivalent
}

fn normalize_zero_sub_compare_operands(
    graph: &SsaGraph,
    kind: CompareKind,
    (lhs, rhs): (ValueId, ValueId),
    ids: (ValueId, ValueId),
    sub_sources: &SourcePairs,
) -> (ValueId, ValueId) {
    if !matches!(kind, CompareKind::Equal | CompareKind::NotEqual) {
        return ids;
    }
    let zero = |value: ValueId| graph.var(value).constant_bits() == Some(0);
    if zero(rhs)
        && let Some(pair) = sub_sources.get(lhs).copied()
    {
        return pair;
    }
    if zero(lhs)
        && let Some(pair) = sub_sources.get(rhs).copied()
    {
        return pair;
    }
    ids
}

fn signed_flag_compare_components(
    graph: &SsaGraph,
    op: &SSAOp<ValueId>,
    signed_overflow_sources: &SourcePairs,
    signed_sign_sources: &SourcePairs,
) -> Option<(ValueId, CompareKind, ValueId, ValueId)> {
    let (dst, a, b, equal) = match *op {
        SSAOp::IntNotEqual { dst, a, b } => (dst, a, b, false),
        SSAOp::IntEqual { dst, a, b } => (dst, a, b, true),
        _ => return None,
    };
    let paired = |overflow: ValueId, sign: ValueId| {
        signed_overflow_sources
            .get(overflow)
            .zip(signed_sign_sources.get(sign))
            .filter(|(overflow, sign)| compare_operand_pairs_equivalent(graph, overflow, sign))
            .map(|(overflow, _)| *overflow)
    };
    let (lhs, rhs) = paired(a, b).or_else(|| paired(b, a))?;
    Some(if equal {
        (dst, CompareKind::SignedLessEqual, rhs, lhs)
    } else {
        (dst, CompareKind::SignedLess, lhs, rhs)
    })
}

pub(crate) fn compare_operand_pairs_equivalent(
    graph: &SsaGraph,
    lhs: &(ValueId, ValueId),
    rhs: &(ValueId, ValueId),
) -> bool {
    compare_values_equivalent(graph, lhs.0, rhs.0) && compare_values_equivalent(graph, lhs.1, rhs.1)
}

pub(crate) fn compare_components<V>(op: &SSAOp<V>) -> Option<(&V, CompareKind, &V, &V)> {
    match op {
        SSAOp::IntEqual { dst, a, b } => Some((dst, CompareKind::Equal, a, b)),
        SSAOp::IntNotEqual { dst, a, b } => Some((dst, CompareKind::NotEqual, a, b)),
        SSAOp::IntLess { dst, a, b } => Some((dst, CompareKind::Less, a, b)),
        SSAOp::IntSLess { dst, a, b } => Some((dst, CompareKind::SignedLess, a, b)),
        SSAOp::IntLessEqual { dst, a, b } => Some((dst, CompareKind::LessEqual, a, b)),
        SSAOp::IntSLessEqual { dst, a, b } => Some((dst, CompareKind::SignedLessEqual, a, b)),
        _ => None,
    }
}
