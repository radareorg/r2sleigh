//! Which values a statement may spell, and which merge is a choice.

use super::super::*;

/// A merge of two values that one condition selects between.
///
/// The phi carries the blocks its edges come from and the conditional branch
/// above them names which edge is which, so the merge is a selection: the value
/// is `condition ? if_true : if_false`. A compiler often puts the jump to the
/// merge in a block of its own, so each arm is a run of single-predecessor
/// blocks walked back to the branch rather than the branch's own successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwoWaySelectionCertificate {
    /// The block whose conditional branch chooses between the two arms.
    pub branch: u64,
    /// The value that branch tests.
    pub condition: ValueId,
    /// The merge's input reached on the branch's taken edge.
    pub if_true: ValueId,
    /// The merge's input reached on the other edge.
    pub if_false: ValueId,
}

/// The literal a value stands for, through the copies that carry it.
///
/// An arm that assigns a constant does it through a temporary, so the merge's
/// operand is the copy's output rather than the literal; the literal is what
/// means the same thing wherever the conditional reads it.
pub(crate) fn constant_root_through_copies(graph: &SsaGraph, value: ValueId) -> Option<ValueId> {
    let mut at = value;
    for _ in 0..graph.values.len() {
        if graph
            .value(at)
            .is_some_and(|value| value.var.constant_bits().is_some())
        {
            return Some(at);
        }
        let definition = graph.def_inst(at)?;
        let inst = graph.inst(definition)?;
        match &inst.payload {
            crate::graph::InstPayload::Op(SSAOp::Copy { .. }) => {
                at = *inst.inputs.first()?;
            }
            _ => return None,
        }
    }
    None
}

/// Every merge of two values that one condition selects between.
pub(crate) fn collect_two_way_selection_certificates(
    function: &SSAFunction,
    graph: &SsaGraph,
) -> BTreeMap<InstId, TwoWaySelectionCertificate> {
    let mut certificates = BTreeMap::new();
    for inst in &graph.insts {
        let crate::graph::InstPayload::Phi { predecessors } = &inst.payload else {
            continue;
        };
        if inst.inputs.len() != 2 || predecessors.len() != 2 {
            continue;
        }
        let Some(merge) = graph.block(inst.block).map(|block| block.addr) else {
            continue;
        };
        let Some(arms) = predecessors
            .iter()
            .map(|id| graph.block(*id).map(|block| block.addr))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        // The straight-line run an arm sits at the end of. Every block on the
        // way has one predecessor, which is what makes the run an arm rather
        // than a join of its own.
        let run = |arm: u64| -> Vec<u64> {
            let mut chain = vec![arm];
            let mut at = arm;
            while chain.len() <= graph.blocks.len() {
                let Some(block) = graph
                    .block_id_for_addr(at)
                    .and_then(|id| graph.block(id))
                    .filter(|block| block.predecessors.len() == 1)
                else {
                    break;
                };
                let Some(previous) = graph.block(block.predecessors[0]).map(|block| block.addr)
                else {
                    break;
                };
                if chain.contains(&previous) {
                    break;
                }
                chain.push(previous);
                at = previous;
            }
            chain
        };
        let runs = [run(arms[0]), run(arms[1])];
        let mut selection = None;
        for candidate in runs.iter().flat_map(|chain| chain.iter().copied()) {
            let Some(block) = function.cfg().get_block(candidate) else {
                continue;
            };
            let crate::cfg::BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } = block.terminator
            else {
                continue;
            };
            let edge = |chain: &[u64]| -> Option<u64> {
                let at = chain.iter().position(|block| *block == candidate)?;
                match at.checked_sub(1) {
                    Some(previous) => chain.get(previous).copied(),
                    // The arm is the branch's own block, so it leaves by the
                    // edge that goes straight to the merge.
                    None => Some(merge),
                }
            };
            let (Some(left), Some(right)) = (edge(&runs[0]), edge(&runs[1])) else {
                continue;
            };
            if left == right {
                continue;
            }
            if left == true_target && right == false_target {
                selection = Some((candidate, 0usize, 1usize));
            } else if right == true_target && left == false_target {
                selection = Some((candidate, 1usize, 0usize));
            }
            if selection.is_some() {
                break;
            }
        }
        let Some((branch, true_input, false_input)) = selection else {
            continue;
        };
        // The selection reads the branch's condition wherever the merged value
        // is spelled, so the merge has to dominate every reader. A value read
        // above the merge is spelled above it too, and the condition's read
        // would then sit outside the region that declares it.
        let Some(output) = inst.output else {
            continue;
        };
        // A merge that addresses memory is the object model's business, and a
        // conditional spelling of an address is not what any of that machinery
        // expects. Only a merge of ordinary values becomes a selection.
        let addresses_memory = graph.use_sites(output).iter().any(|site| {
            site.input_idx == 0
                && matches!(
                    graph.inst(site.inst).map(|inst| &inst.payload),
                    Some(crate::graph::InstPayload::Op(
                        SSAOp::Load { .. } | SSAOp::Store { .. }
                    ))
                )
        });
        if addresses_memory {
            continue;
        }
        let readable = graph.use_sites(output).iter().all(|site| {
            graph
                .inst(site.inst)
                .and_then(|inst| graph.block(inst.block))
                .is_some_and(|block| function.dominates(merge, block.addr))
        });
        if !readable {
            continue;
        }
        let Some(condition) = graph
            .block_id_for_addr(branch)
            .and_then(|id| graph.block(id))
            .and_then(|block| {
                block.insts.iter().rev().find_map(|id| {
                    let inst = graph.inst(*id)?;
                    match &inst.payload {
                        crate::graph::InstPayload::Op(SSAOp::CBranch { .. }) => {
                            inst.inputs.last().copied()
                        }
                        _ => None,
                    }
                })
            })
        else {
            continue;
        };
        // The conditional reads one arm's value where the merge is rather than
        // in the arm, so what it reads has to mean the same thing there. A
        // literal does, wherever the arm spelled it; so does an object whose
        // definition dominates the merge. An arm-local object does not.
        let means_the_same = |value: ValueId| {
            if constant_root_through_copies(graph, value).is_some() {
                return true;
            }
            graph.def_inst(value).is_none_or(|definition| {
                graph
                    .inst(definition)
                    .and_then(|inst| graph.block(inst.block))
                    .is_some_and(|block| function.dominates(block.addr, merge))
            })
        };
        if !means_the_same(inst.inputs[true_input]) || !means_the_same(inst.inputs[false_input]) {
            continue;
        }
        certificates.insert(
            inst.id,
            TwoWaySelectionCertificate {
                branch,
                condition,
                if_true: inst.inputs[true_input],
                if_false: inst.inputs[false_input],
            },
        );
    }
    certificates
}

pub(crate) fn collect_renderable_expression_values(
    function: &SSAFunction,
    graph: &SsaGraph,
    structured: &StructuredDataflowFacts,
) -> BTreeSet<ValueId> {
    let certified_memory_read_insts = structured
        .memory_accesses
        .values()
        .filter(|access| !access.is_write && access.width > 0)
        .map(|access| access.id.inst)
        .collect::<BTreeSet<_>>();
    let mut renderable = BTreeSet::new();
    let mut ready = VecDeque::new();

    for value in &graph.values {
        if expression_leaf_is_renderable(value) && renderable.insert(value.id) {
            ready.push_back(value.id);
        }
    }

    let mut eligible = vec![false; graph.insts.len()];
    let mut missing_inputs = vec![0usize; graph.insts.len()];
    for inst in &graph.insts {
        let Some(output) = inst.output else {
            continue;
        };
        if graph.value(output).is_none_or(|value| value.var.size == 0) {
            continue;
        }
        if !expression_inst_is_renderable(function, graph, inst, &certified_memory_read_insts) {
            continue;
        }

        if matches!(&inst.payload, InstPayload::Phi { .. }) {
            renderable.insert(output);
            ready.push_back(output);
        } else if matches!(
            &inst.payload,
            InstPayload::Op(
                SSAOp::Copy { .. }
                    | SSAOp::New { .. }
                    | SSAOp::Subpiece { .. }
                    | SSAOp::Piece { .. }
                    | SSAOp::IntZExt { .. }
                    | SSAOp::IntSExt { .. }
                    | SSAOp::Trunc { .. }
                    | SSAOp::Cast { .. }
            )
        ) {
            let input_renderable = inst.inputs.iter().all(|i| renderable.contains(i));
            if input_renderable {
                renderable.insert(output);
                ready.push_back(output);
            } else {
                eligible[inst.id.0 as usize] = true;
                missing_inputs[inst.id.0 as usize] = inst
                    .inputs
                    .iter()
                    .filter(|input| !renderable.contains(input))
                    .count();
            }
        } else {
            eligible[inst.id.0 as usize] = true;
            missing_inputs[inst.id.0 as usize] = inst
                .inputs
                .iter()
                .filter(|input| !renderable.contains(input))
                .count();
            if missing_inputs[inst.id.0 as usize] == 0 && renderable.insert(output) {
                ready.push_back(output);
            }
        }
    }

    loop {
        while let Some(value) = ready.pop_front() {
            for use_site in graph.use_sites(value) {
                let inst_idx = use_site.inst.0 as usize;
                if !eligible.get(inst_idx).copied().unwrap_or(false)
                    || missing_inputs.get(inst_idx).copied().unwrap_or(0) == 0
                {
                    continue;
                }
                missing_inputs[inst_idx] -= 1;
                if missing_inputs[inst_idx] == 0
                    && let Some(output) = graph.inst(use_site.inst).and_then(|inst| inst.output)
                    && renderable.insert(output)
                {
                    ready.push_back(output);
                }
            }
        }

        let mut added_loop_phi = false;
        for inst in &graph.insts {
            let Some(output) = inst.output else {
                continue;
            };
            if renderable.contains(&output) {
                continue;
            }
            if expression_loop_phi_is_renderable(
                function,
                graph,
                structured,
                inst,
                &renderable,
                &certified_memory_read_insts,
            ) && renderable.insert(output)
            {
                ready.push_back(output);
                added_loop_phi = true;
            }
        }
        if !added_loop_phi {
            break;
        }
    }

    renderable
}

pub(crate) fn expression_leaf_is_renderable(value: &crate::graph::GraphValue) -> bool {
    value.var.size > 0
        && (value.var.constant_bits().is_some()
            || (value.var.version == 0
                && matches!(
                    value.canonical_storage,
                    Some(CanonicalStorageId {
                        space: CanonicalStorageSpace::Register,
                        ..
                    })
                )))
}

pub(crate) fn expression_inst_is_renderable(
    _function: &SSAFunction,
    _graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
    certified_memory_read_insts: &BTreeSet<InstId>,
) -> bool {
    match &inst.payload {
        InstPayload::Phi { .. } => true,
        InstPayload::Op(op) => {
            expression_op_is_pure(op)
                || (op.is_memory_read() && certified_memory_read_insts.contains(&inst.id))
        }
    }
}

pub(crate) fn expression_phi_is_identity_renderable(
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
) -> bool {
    let Some(first) = inst.inputs.first() else {
        return false;
    };
    expression_phi_is_identity(inst) && !expression_value_depends_on_memory_read(graph, *first)
}

pub(crate) fn expression_phi_is_renderable(
    function: &SSAFunction,
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
) -> bool {
    expression_phi_is_identity_renderable(graph, inst)
        || expression_phi_has_single_canonical_root(function, graph, inst)
}

pub(crate) fn expression_phi_has_single_canonical_root(
    function: &SSAFunction,
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
) -> bool {
    let Some(prep_facts) = function.decompile_prep_facts() else {
        return false;
    };
    // The inputs are one value when they name one representative: the same
    // bits at the same width, as the view states them. A representative the
    // graph holds no value for -- the literal a constant lane determines --
    // is compared as the variable it is.
    let mut roots = inst.inputs.iter().filter_map(|input| {
        let var = graph.value(*input).map(|value| &value.var)?;
        Some((prep_facts.canonical_root(var), *input))
    });
    let Some((first_root, first_input)) = roots.next() else {
        return false;
    };
    let first = graph.value_id_for_var(first_root).unwrap_or(first_input);
    if expression_value_depends_on_memory_read(graph, first) {
        return false;
    }
    roots.all(|(root, _)| root == first_root)
}

/// Whether any value this one is computed from reads memory.
///
/// The visited set is the termination argument: the def-use graph is finite
/// and each value is expanded once, so the walk is linear in it. A depth bound
/// here would answer "no memory read" for a dependence it declined to look
/// at, which is the one answer that must never be guessed.
pub(crate) fn expression_value_depends_on_memory_read(graph: &SsaGraph, value: ValueId) -> bool {
    let mut stack = vec![value];
    let mut visited = BTreeSet::new();

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(inst) = graph
            .def_inst(current)
            .and_then(|inst_id| graph.inst(inst_id))
        else {
            continue;
        };
        if matches!(&inst.payload, InstPayload::Op(op) if op.is_memory_read()) {
            return true;
        }
        stack.extend(inst.inputs.iter().copied());
    }

    false
}

pub(crate) fn expression_loop_phi_is_renderable(
    function: &SSAFunction,
    graph: &SsaGraph,
    structured: &StructuredDataflowFacts,
    inst: &crate::graph::GraphInst,
    renderable: &BTreeSet<ValueId>,
    certified_memory_read_insts: &BTreeSet<InstId>,
) -> bool {
    let InstPayload::Phi { predecessors } = &inst.payload else {
        return false;
    };
    let Some(output) = inst.output else {
        return false;
    };
    let Some(header) = graph.block(inst.block).map(|block| block.addr) else {
        return false;
    };
    let Some(loop_fact) = structured.loops.values().find(|fact| fact.header == header) else {
        return false;
    };
    if inst.inputs.len() != predecessors.len() {
        return false;
    }

    let latches = loop_fact.latches.iter().copied().collect::<BTreeSet<_>>();
    let env = ExpressionRenderEnv {
        function,
        graph,
        certified_memory_read_insts,
    };
    let mut saw_entry = false;
    let mut saw_backedge = false;
    for (pred_id, input) in predecessors.iter().zip(inst.inputs.iter().copied()) {
        let Some(pred_addr) = graph.block(*pred_id).map(|block| block.addr) else {
            return false;
        };
        if latches.contains(&pred_addr) {
            saw_backedge = true;
            let mut visited = BTreeSet::new();
            if !value_renderable_modulo_loop_phi(&env, input, output, renderable, &mut visited, 0) {
                return false;
            }
        } else {
            saw_entry = true;
            if !renderable.contains(&input) {
                return false;
            }
        }
    }

    saw_entry && saw_backedge
}

pub(crate) struct ExpressionRenderEnv<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) certified_memory_read_insts: &'a BTreeSet<InstId>,
}

pub(crate) fn value_renderable_modulo_loop_phi(
    env: &ExpressionRenderEnv<'_>,
    value: ValueId,
    loop_phi: ValueId,
    renderable: &BTreeSet<ValueId>,
    visited: &mut BTreeSet<ValueId>,
    depth: usize,
) -> bool {
    if value == loop_phi || renderable.contains(&value) {
        return true;
    }
    if depth >= 32 || !visited.insert(value) {
        return false;
    }

    let result = env
        .graph
        .def_inst(value)
        .and_then(|inst_id| env.graph.inst(inst_id))
        .is_some_and(|inst| {
            let eligible = match &inst.payload {
                InstPayload::Phi { .. } => {
                    expression_phi_is_renderable(env.function, env.graph, inst)
                }
                InstPayload::Op(op) => {
                    expression_op_is_pure(op)
                        || (op.is_memory_read()
                            && env.certified_memory_read_insts.contains(&inst.id))
                }
            };
            eligible
                && inst.inputs.iter().all(|input| {
                    value_renderable_modulo_loop_phi(
                        env,
                        *input,
                        loop_phi,
                        renderable,
                        visited,
                        depth + 1,
                    )
                })
        });

    visited.remove(&value);
    result
}

pub(crate) fn expression_op_is_pure(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::IntAdd { .. }
            | SSAOp::IntSub { .. }
            | SSAOp::IntMult { .. }
            | SSAOp::IntDiv { .. }
            | SSAOp::IntSDiv { .. }
            | SSAOp::IntRem { .. }
            | SSAOp::IntSRem { .. }
            | SSAOp::IntNegate { .. }
            | SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::IntAnd { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. }
            | SSAOp::IntNot { .. }
            | SSAOp::IntLeft { .. }
            | SSAOp::IntRight { .. }
            | SSAOp::IntSRight { .. }
            | SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::Piece { .. }
            | SSAOp::Subpiece { .. }
            | SSAOp::PopCount { .. }
            | SSAOp::Lzcount { .. }
            | SSAOp::FloatAdd { .. }
            | SSAOp::FloatSub { .. }
            | SSAOp::FloatMult { .. }
            | SSAOp::FloatDiv { .. }
            | SSAOp::FloatNeg { .. }
            | SSAOp::FloatAbs { .. }
            | SSAOp::FloatSqrt { .. }
            | SSAOp::FloatCeil { .. }
            | SSAOp::FloatFloor { .. }
            | SSAOp::FloatRound { .. }
            | SSAOp::FloatNaN { .. }
            | SSAOp::FloatEqual { .. }
            | SSAOp::FloatNotEqual { .. }
            | SSAOp::FloatLess { .. }
            | SSAOp::FloatLessEqual { .. }
            | SSAOp::Int2Float { .. }
            | SSAOp::Float2Int { .. }
            | SSAOp::FloatFloat { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::PtrAdd { .. }
            | SSAOp::PtrSub { .. }
            | SSAOp::SegmentOp { .. }
            | SSAOp::Cast { .. }
            | SSAOp::Extract { .. }
            | SSAOp::Insert { .. }
            | SSAOp::Select { .. }
    )
}
