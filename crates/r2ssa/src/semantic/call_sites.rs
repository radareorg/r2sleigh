//! Where the body calls, in canonical identity.

use super::*;

pub(crate) fn collect_call_sites(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep_facts: Option<&DecompilePrepFacts>,
    machine_context: Option<&SourceMachineContext>,
) -> CallSiteFacts {
    let mut by_id = BTreeMap::new();
    let mut by_inst = crate::dense::IdMap::default();
    let mut next_id = 0u32;

    for &block_addr in function.block_addrs() {
        let Some(block) = graph.block_id_for_addr(block_addr) else {
            continue;
        };
        let insts = graph.op_insts(block);
        let fallthrough = match function
            .cfg()
            .get_block(block_addr)
            .map(|block| &block.terminator)
        {
            Some(BlockTerminator::Call { fallthrough, .. })
            | Some(BlockTerminator::IndirectCall { fallthrough }) => *fallthrough,
            _ => None,
        };

        for (op_idx, &inst_id) in insts.iter().enumerate() {
            let Some(op) = graph.op(inst_id) else {
                continue;
            };
            let id = CallSiteId(next_id);
            // The raw input names which instructions are call sites; a transfer with no
            // instruction is synthetic and belongs to no source-described site.
            let Some(flow) = op.transfer() else {
                continue;
            };
            let target = *flow.target;
            let raw_identity = machine_context
                .zip(flow.instruction)
                .and_then(|(context, instruction)| context.raw_call_site_at(instruction));
            let transfer = if flow.call {
                CallSiteTransfer::Call
            } else if machine_context.is_some_and(|context| {
                raw_identity.is_some_and(|identity| {
                    context.is_tail_call_site(identity)
                        && if flow.direct {
                            graph.value(target).is_some_and(|value| {
                                value.canonical_storage == Some(identity.target())
                            })
                        } else {
                            // A slot in memory or the register the jump goes through.
                            identity.target().space == crate::CanonicalStorageSpace::Ram
                                || graph.value(target).is_some_and(|value| {
                                    value.canonical_storage == Some(identity.target())
                                })
                        }
                })
            }) {
                CallSiteTransfer::TailCall
            } else {
                continue;
            };
            let target_id = target;
            next_id = next_id.saturating_add(1);
            let direct_target = resolve_graph_literal_value(graph, prep_facts, target_id)
                .or_else(|| raw_identity.and_then(direct_target_from_raw_identity))
                .or_else(|| {
                    let (identity, context) = raw_identity.zip(machine_context)?;
                    context.slot_target(identity)
                });
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
                    } else if op_idx + 1 == insts.len() {
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
