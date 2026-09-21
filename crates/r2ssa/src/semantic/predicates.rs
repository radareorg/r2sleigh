//! What each branch tests, and what a switch dispatches on.

use super::*;

pub(crate) fn collect_predicate_facts(function: &SSAFunction, graph: &SsaGraph) -> PredicateFacts {
    let mut predicates = BTreeMap::new();
    let mut block_assumptions = BTreeMap::<u64, Vec<BlockAssumption>>::new();
    let mut switches = BTreeMap::new();
    let compare_defs = collect_compare_defs(function, graph);
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
                let id = PredicateId(next_predicate_id);
                next_predicate_id = next_predicate_id.saturating_add(1);
                predicates.insert(
                    id,
                    PredicateFact {
                        id,
                        block_addr,
                        condition: graph
                            .value_id_for_var(cond)
                            .expect("predicate condition in graph"),
                        comparison: compare_defs.get(cond).cloned(),
                        evaluated_comparison: evaluated_compare_defs.get(cond).cloned(),
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
                        selector: block.ops.iter().rev().find_map(|op| match op {
                            SSAOp::Switch { selector } => graph.value_id_for_var(selector),
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

pub(crate) struct CompareDefinitions {
    pub(crate) normalized: BTreeMap<SSAVar, CompareProvenance>,
    pub(crate) evaluated: BTreeMap<SSAVar, CompareProvenance>,
}

pub(crate) fn collect_compare_defs(function: &SSAFunction, graph: &SsaGraph) -> CompareDefinitions {
    let mut normalized = BTreeMap::<SSAVar, CompareProvenance>::new();
    let mut evaluated = BTreeMap::<SSAVar, CompareProvenance>::new();
    let copy_sources = collect_compare_copy_sources(function);
    let mut sub_sources = BTreeMap::<SSAVar, (ValueId, ValueId)>::new();
    let mut signed_overflow_sources = BTreeMap::<SSAVar, (ValueId, ValueId)>::new();
    let mut signed_sign_sources = BTreeMap::<SSAVar, (ValueId, ValueId)>::new();

    for block in function.blocks() {
        for op in &block.ops {
            if let SSAOp::IntSub { dst, a, b } = op
                && let (Some(lhs), Some(rhs)) = (
                    canonical_compare_operand(graph, &copy_sources, a),
                    canonical_compare_operand(graph, &copy_sources, b),
                )
            {
                sub_sources.insert(dst.clone(), (lhs, rhs));
            }
        }
    }

    for block in function.blocks() {
        for op in &block.ops {
            if let SSAOp::IntSBorrow { dst, a, b } = op
                && let (Some(lhs), Some(rhs)) = (
                    canonical_compare_operand(graph, &copy_sources, a),
                    canonical_compare_operand(graph, &copy_sources, b),
                )
            {
                signed_overflow_sources.insert(dst.clone(), (lhs, rhs));
            }
            if let SSAOp::IntSLess { dst, a, b } = op
                && const_value(b) == Some(0)
                && let Some((lhs, rhs)) = sub_sources.get(a).copied()
            {
                signed_sign_sources.insert(dst.clone(), (lhs, rhs));
            }
        }
    }
    propagate_compare_source_aliases(function, &mut signed_overflow_sources);
    propagate_compare_source_aliases(function, &mut signed_sign_sources);

    for block in function.blocks() {
        for op in &block.ops {
            let Some((dst, kind, lhs, rhs)) = compare_components(op) else {
                if let Some((dst, kind, lhs, rhs)) = signed_flag_compare_components(
                    graph,
                    op,
                    &signed_overflow_sources,
                    &signed_sign_sources,
                ) {
                    let comparison = CompareProvenance { kind, lhs, rhs };
                    normalized.insert(dst.clone(), comparison.clone());
                    evaluated.insert(dst.clone(), comparison);
                }
                continue;
            };
            let Some(lhs_id) = canonical_compare_operand(graph, &copy_sources, lhs) else {
                continue;
            };
            let Some(rhs_id) = canonical_compare_operand(graph, &copy_sources, rhs) else {
                continue;
            };
            evaluated.insert(
                dst.clone(),
                CompareProvenance {
                    kind,
                    lhs: lhs_id,
                    rhs: rhs_id,
                },
            );
            let (normalized_lhs, normalized_rhs) =
                normalize_zero_sub_compare_operands(kind, lhs, rhs, lhs_id, rhs_id, &sub_sources);
            normalized.insert(
                dst.clone(),
                CompareProvenance {
                    kind,
                    lhs: normalized_lhs,
                    rhs: normalized_rhs,
                },
            );
            if let Some((dst, kind, lhs, rhs)) = signed_flag_compare_components(
                graph,
                op,
                &signed_overflow_sources,
                &signed_sign_sources,
            ) {
                let comparison = CompareProvenance { kind, lhs, rhs };
                normalized.insert(dst.clone(), comparison.clone());
                evaluated.insert(dst.clone(), comparison);
            }
        }
    }

    propagate_compare_definitions(function, graph, &mut normalized);
    propagate_compare_definitions(function, graph, &mut evaluated);
    CompareDefinitions {
        normalized,
        evaluated,
    }
}

pub(crate) fn propagate_compare_definitions(
    function: &SSAFunction,
    graph: &SsaGraph,
    compare_defs: &mut BTreeMap<SSAVar, CompareProvenance>,
) {
    loop {
        let mut changed = false;
        for block in function.blocks() {
            for op in &block.ops {
                let propagated = match op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::IntZExt { dst, src }
                    | SSAOp::IntSExt { dst, src }
                    | SSAOp::Trunc { dst, src } => compare_defs
                        .get(src)
                        .cloned()
                        .map(|comparison| (dst, comparison)),
                    SSAOp::Subpiece {
                        dst,
                        src,
                        offset: 0,
                    } => compare_defs
                        .get(src)
                        .cloned()
                        .map(|comparison| (dst, comparison)),
                    SSAOp::BoolNot { dst, src } => compare_defs.get(src).and_then(|comparison| {
                        invert_compare_provenance(comparison).map(|comparison| (dst, comparison))
                    }),
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
                let Some((dst, comparison)) = propagated else {
                    continue;
                };
                if compare_defs.get(dst) != Some(&comparison) {
                    compare_defs.insert(dst.clone(), comparison);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

pub(crate) fn collect_compare_copy_sources(function: &SSAFunction) -> BTreeMap<SSAVar, SSAVar> {
    let mut sources = BTreeMap::new();
    for block in function.blocks() {
        for op in &block.ops {
            if let SSAOp::Copy { dst, src } = op {
                sources.insert(dst.clone(), src.clone());
            }
        }
    }
    sources
}

pub(crate) fn canonical_compare_operand(
    graph: &SsaGraph,
    copy_sources: &BTreeMap<SSAVar, SSAVar>,
    var: &SSAVar,
) -> Option<ValueId> {
    // The visited set is the whole termination argument: each step moves to a
    // var it has not seen and the map is finite.
    let mut current = var;
    let mut visited = BTreeSet::new();
    while visited.insert(current) {
        let Some(source) = copy_sources.get(current) else {
            return graph.value_id_for_var(current);
        };
        current = source;
    }
    None
}

pub(crate) fn propagate_compare_source_aliases(
    function: &SSAFunction,
    sources: &mut BTreeMap<SSAVar, (ValueId, ValueId)>,
) {
    loop {
        let mut changed = false;
        for block in function.blocks() {
            for op in &block.ops {
                let (dst, src) = match op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::IntZExt { dst, src }
                    | SSAOp::IntSExt { dst, src }
                    | SSAOp::Trunc { dst, src } => (dst, src),
                    SSAOp::Subpiece {
                        dst,
                        src,
                        offset: 0,
                    } => (dst, src),
                    _ => continue,
                };
                let Some(source) = sources.get(src).copied() else {
                    continue;
                };
                if sources.get(dst) != Some(&source) {
                    sources.insert(dst.clone(), source);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
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
        let mut equivalent_sources = |lhs: &SSAVar, rhs: &SSAVar| {
            graph
                .value_id_for_var(lhs)
                .zip(graph.value_id_for_var(rhs))
                .is_some_and(|(lhs, rhs)| {
                    compare_values_equivalent_inner(graph, lhs, rhs, depth + 1, visiting)
                })
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

pub(crate) fn normalize_zero_sub_compare_operands(
    kind: CompareKind,
    lhs: &SSAVar,
    rhs: &SSAVar,
    lhs_id: ValueId,
    rhs_id: ValueId,
    sub_sources: &BTreeMap<SSAVar, (ValueId, ValueId)>,
) -> (ValueId, ValueId) {
    if !matches!(kind, CompareKind::Equal | CompareKind::NotEqual) {
        return (lhs_id, rhs_id);
    }
    if const_value(rhs) == Some(0)
        && let Some((sub_lhs, sub_rhs)) = sub_sources.get(lhs).copied()
    {
        return (sub_lhs, sub_rhs);
    }
    if const_value(lhs) == Some(0)
        && let Some((sub_lhs, sub_rhs)) = sub_sources.get(rhs).copied()
    {
        return (sub_lhs, sub_rhs);
    }
    (lhs_id, rhs_id)
}

pub(crate) fn signed_flag_compare_components<'a>(
    graph: &SsaGraph,
    op: &'a SSAOp,
    signed_overflow_sources: &BTreeMap<SSAVar, (ValueId, ValueId)>,
    signed_sign_sources: &BTreeMap<SSAVar, (ValueId, ValueId)>,
) -> Option<(&'a SSAVar, CompareKind, ValueId, ValueId)> {
    let (dst, a, b, equal) = match op {
        SSAOp::IntNotEqual { dst, a, b } => (dst, a, b, false),
        SSAOp::IntEqual { dst, a, b } => (dst, a, b, true),
        _ => return None,
    };
    let overflow = signed_overflow_sources.get(a);
    let sign = signed_sign_sources.get(b);
    let (lhs, rhs) = overflow
        .zip(sign)
        .filter(|(overflow, sign)| compare_operand_pairs_equivalent(graph, overflow, sign))
        .map(|(overflow, _)| *overflow)
        .or_else(|| {
            let overflow = signed_overflow_sources.get(b);
            let sign = signed_sign_sources.get(a);
            overflow
                .zip(sign)
                .filter(|(overflow, sign)| compare_operand_pairs_equivalent(graph, overflow, sign))
                .map(|(overflow, _)| *overflow)
        })?;
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

pub(crate) fn compare_components(op: &SSAOp) -> Option<(&SSAVar, CompareKind, &SSAVar, &SSAVar)> {
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
