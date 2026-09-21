//! Where the body calls, in canonical identity.

use super::*;

pub(crate) fn collect_call_sites(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep_facts: Option<&DecompilePrepFacts>,
    machine_context: Option<&SourceMachineContext>,
) -> CallSiteFacts {
    let mut by_id = BTreeMap::new();
    let mut by_inst = BTreeMap::new();
    let mut next_id = 0u32;

    for &block_addr in function.block_addrs() {
        let Some(block) = function.get_block(block_addr) else {
            continue;
        };
        let fallthrough = match function
            .cfg()
            .get_block(block_addr)
            .map(|block| &block.terminator)
        {
            Some(BlockTerminator::Call { fallthrough, .. })
            | Some(BlockTerminator::IndirectCall { fallthrough }) => *fallthrough,
            _ => None,
        };

        for (op_idx, op) in block.ops.iter().enumerate() {
            let id = CallSiteId(next_id);
            // The transfer names the instruction it was lifted from, and the
            // raw input names which of its instructions are call sites; that
            // is the whole correlation. A transfer with no instruction is
            // synthetic and belongs to no source-described site.
            let instruction = match op {
                SSAOp::Call { instruction, .. }
                | SSAOp::CallInd { instruction, .. }
                | SSAOp::Branch { instruction, .. }
                | SSAOp::BranchInd { instruction, .. } => *instruction,
                _ => None,
            };
            let raw_identity = machine_context
                .zip(instruction)
                .and_then(|(context, instruction)| context.raw_call_site_at(instruction));
            let (target, transfer) = match op {
                SSAOp::Call { target, .. } | SSAOp::CallInd { target, .. } => {
                    (target.clone(), CallSiteTransfer::Call)
                }
                SSAOp::Branch { target, .. } | SSAOp::BranchInd { target, .. }
                    if machine_context.is_some_and(|context| {
                        raw_identity.is_some_and(|identity| {
                            context.is_tail_call_site(identity)
                                && match op {
                                    SSAOp::Branch { .. } => graph
                                        .value_id_for_var(target)
                                        .and_then(|value| graph.value(value))
                                        .is_some_and(|value| {
                                            value.canonical_storage == Some(identity.target())
                                        }),
                                    // A slot in memory, or the register the
                                    // jump goes through: both are targets a
                                    // tail transfer can name, and the register
                                    // case is checked the same way the direct
                                    // tail jump is, against the value the
                                    // branch actually reads.
                                    SSAOp::BranchInd { .. } => {
                                        identity.target().space == crate::CanonicalStorageSpace::Ram
                                            || graph
                                                .value_id_for_var(target)
                                                .and_then(|value| graph.value(value))
                                                .is_some_and(|value| {
                                                    value.canonical_storage
                                                        == Some(identity.target())
                                                })
                                    }
                                    _ => false,
                                }
                        })
                    }) =>
                {
                    (target.clone(), CallSiteTransfer::TailCall)
                }
                _ => continue,
            };
            let Some(inst_id) = graph.inst_id_for_op_site(block_addr, op_idx) else {
                continue;
            };
            let Some(target_id) = graph.value_id_for_var(&target) else {
                continue;
            };
            next_id = next_id.saturating_add(1);
            let direct_target = resolve_graph_literal_value(graph, prep_facts, &target)
                .or_else(|| raw_identity.and_then(direct_target_from_raw_identity));
            by_inst.insert(inst_id, id);
            by_id.insert(
                id,
                CallSiteFact {
                    id,
                    at: inst_id,
                    raw_identity,
                    target: target_id,
                    direct_target,
                    fallthrough: if transfer == CallSiteTransfer::TailCall {
                        None
                    } else if op_idx + 1 == block.ops.len() {
                        fallthrough
                    } else {
                        None
                    },
                    transfer,
                    memory_effect: CallMemoryEffect::Unknown,
                    callee_linkage: raw_identity.zip(machine_context).map_or(
                        r2source::AdvisoryCalleeLinkage::Unknown,
                        |(identity, context)| context.callee_linkage(identity),
                    ),
                },
            );
        }
    }

    CallSiteFacts { by_id, by_inst }
}

pub(crate) fn direct_target_from_raw_identity(identity: SourceCallSiteIdentity) -> Option<u64> {
    let target = identity.target();
    matches!(
        target.space,
        CanonicalStorageSpace::Constant | CanonicalStorageSpace::Ram
    )
    .then_some(target.offset)
}
