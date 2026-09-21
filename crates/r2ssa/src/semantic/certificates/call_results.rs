//! What a call leaves behind, and which of it the body reads.

use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResultCertificate {
    pub call_site: CallSiteId,
    pub at: InstId,
    pub block_addr: u64,
    pub op_index: usize,
    pub value: ValueId,
    pub width: u32,
    pub relation: CallResultValueRelation,
    pub carrier: ReturnCarrier,
    pub owner: Option<ValueOwner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallResultValueRelation {
    Identity,
    Derived,
}

impl CallResultValueRelation {
    pub fn is_identity(self) -> bool {
        self == Self::Identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueOwner {
    Value(ValueId),
    StackSlot { object: ObjectId, offset: i64 },
}

pub(crate) type CallResultCertificateIndexes = (
    BTreeMap<ValueId, CallResultCertificate>,
    BTreeMap<InstId, ValueId>,
    BTreeMap<CallSiteId, Vec<ValueId>>,
);

pub(crate) fn collect_call_result_certificates(
    body: Body<'_>,
    derived: Derived<'_>,
) -> CallResultCertificateIndexes {
    let (function, graph) = (body.function, body.graph);
    let call_sites = derived.call_sites;
    let mut call_results = BTreeMap::new();
    let mut call_results_by_inst = BTreeMap::new();
    let mut call_results_by_callsite = BTreeMap::<CallSiteId, Vec<ValueId>>::new();
    let callsites_by_op = call_sites
        .by_id
        .iter()
        .filter_map(|(id, fact)| graph.op_site_for_inst(fact.at).map(|site| (site, *id)))
        .collect::<BTreeMap<_, _>>();
    let mut out_states = BTreeMap::<u64, CallResultFlowState>::new();
    let mut worklist = function
        .blocks()
        .iter()
        .map(|block| block.addr)
        .collect::<VecDeque<_>>();
    let mut queued = function
        .blocks()
        .iter()
        .map(|block| block.addr)
        .collect::<BTreeSet<_>>();

    while let Some(block_addr) = worklist.pop_front() {
        queued.remove(&block_addr);
        let Some(block) = function.get_block(block_addr) else {
            continue;
        };
        let input = merge_call_result_flow_predecessors(function, &out_states, block_addr);
        let output = process_call_result_flow_block(
            body,
            derived,
            block,
            &callsites_by_op,
            input,
            CallResultSink {
                call_results: &mut call_results,
                call_results_by_inst: &mut call_results_by_inst,
                call_results_by_callsite: &mut call_results_by_callsite,
            },
        );
        if out_states.get(&block_addr) == Some(&output) {
            continue;
        }
        out_states.insert(block_addr, output);
        for succ in function.successors(block_addr) {
            if queued.insert(succ) {
                worklist.push_back(succ);
            }
        }
    }

    for values in call_results_by_callsite.values_mut() {
        values.sort_unstable();
        values.dedup();
    }

    (call_results, call_results_by_inst, call_results_by_callsite)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CallResultFlowState {
    pub(crate) tracked: BTreeMap<ValueId, CallResultCertificate>,
    pub(crate) stack_owners: BTreeMap<(ObjectId, i64), CallResultCertificate>,
}

pub(crate) fn merge_call_result_flow_predecessors(
    function: &SSAFunction,
    out_states: &BTreeMap<u64, CallResultFlowState>,
    block_addr: u64,
) -> CallResultFlowState {
    let preds = function.predecessors(block_addr);
    let Some((first, rest)) = preds.split_first() else {
        return CallResultFlowState::default();
    };
    let mut merged = out_states.get(first).cloned().unwrap_or_default();
    for pred in rest {
        let pred_state = out_states.get(pred).cloned().unwrap_or_default();
        merged
            .tracked
            .retain(|value, cert| pred_state.tracked.get(value) == Some(cert));
        merged
            .stack_owners
            .retain(|slot, cert| pred_state.stack_owners.get(slot) == Some(cert));
    }
    merged
}

/// The three indexes a call-result certificate is recorded in at once.
pub(crate) struct CallResultSink<'a> {
    pub(crate) call_results: &'a mut BTreeMap<ValueId, CallResultCertificate>,
    pub(crate) call_results_by_inst: &'a mut BTreeMap<InstId, ValueId>,
    pub(crate) call_results_by_callsite: &'a mut BTreeMap<CallSiteId, Vec<ValueId>>,
}

pub(crate) fn process_call_result_flow_block(
    body: Body<'_>,
    derived: Derived<'_>,
    block: &crate::FunctionSSABlock,
    callsites_by_op: &BTreeMap<(u64, usize), CallSiteId>,
    mut state: CallResultFlowState,
    sink: CallResultSink<'_>,
) -> CallResultFlowState {
    let (function, graph) = (body.function, body.graph);
    let (boundaries, objects, call_sites, structured) = (
        derived.boundaries,
        derived.objects,
        derived.call_sites,
        derived.structured,
    );
    let CallResultSink {
        call_results,
        call_results_by_inst,
        call_results_by_callsite,
    } = sink;
    let mut active_call = None;
    for (op_index, op) in block.ops.iter().enumerate() {
        match op {
            SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                kill_return_register_flow_values(&mut state);
                active_call = callsites_by_op.get(&(block.addr, op_index)).copied();
            }
            SSAOp::CallDefine { dst } => {
                let Some(call_site_id) = active_call else {
                    continue;
                };
                let Some(call_site) = call_sites.by_id.get(&call_site_id) else {
                    continue;
                };
                let Some(value) = graph.value_id_for_var(dst) else {
                    continue;
                };
                let Some(boundary) = boundaries
                    .calls
                    .get(&call_site_id)
                    .filter(|boundary| boundary.results_complete)
                else {
                    continue;
                };
                let mut exact_results = boundary
                    .results
                    .iter()
                    .filter(|result| result.value == value);
                let (result, relation) = match exact_results.next() {
                    Some(result) => {
                        if exact_results.next().is_some() {
                            continue;
                        }
                        (result, CallResultValueRelation::Identity)
                    }
                    // The call defines the register the callee returned in and
                    // separately defines the lane of it the callee's prototype
                    // is declared at: an `int` returned in `rax` gives a
                    // `CallDefine` for `RAX` and one for `EAX`. The boundary
                    // certifies the carrier, because that is the storage the
                    // interface names, so the lane matched nothing and the
                    // renderer had no source call for the definition the
                    // program actually reads. `murmur3_32` at -O0 stores `eax`
                    // to a local after every `memcpy` and was refused for it.
                    //
                    // A lane is not a second result. It is this result, sliced,
                    // which is what `Derived` says.
                    None => {
                        let Some(storage) =
                            graph.value(value).and_then(|value| value.canonical_storage)
                        else {
                            continue;
                        };
                        let mut lanes = boundary.results.iter().filter(|result| {
                            graph
                                .value(result.value)
                                .and_then(|result| result.canonical_storage)
                                .is_some_and(|carrier| {
                                    carrier.space == storage.space
                                        && carrier.offset == storage.offset
                                        && carrier.size > storage.size
                                })
                        });
                        let Some(result) = lanes.next() else {
                            if trace_call_definitions() {
                                eprintln!(
                                    "  no lane carrier for {value:?} {storage:?} among {:?}",
                                    boundary
                                        .results
                                        .iter()
                                        .map(|r| graph
                                            .value(r.value)
                                            .and_then(|v| v.canonical_storage))
                                        .collect::<Vec<_>>()
                                );
                            }
                            continue;
                        };
                        if lanes.next().is_some() {
                            continue;
                        }
                        if trace_call_definitions() {
                            eprintln!("  lane certified {value:?} from {:?}", result.value);
                        }
                        (result, CallResultValueRelation::Derived)
                    }
                };
                let Some(carrier) = return_carrier_for_boundary_slot(result.slot) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: call_site_id,
                    at: graph
                        .inst_id_for_op_site(block.addr, op_index)
                        .unwrap_or(call_site.at),
                    block_addr: block.addr,
                    op_index,
                    value,
                    width: dst.size,
                    relation,
                    carrier,
                    owner: Some(ValueOwner::Value(value)),
                };
                insert_call_result_certificate(
                    call_results,
                    call_results_by_inst,
                    call_results_by_callsite,
                    &mut state.tracked,
                    cert,
                );
            }
            SSAOp::Copy { dst, src } => {
                let Some(src_value) = graph.value_id_for_var(src) else {
                    continue;
                };
                let Some(source) = state.tracked.get(&src_value) else {
                    continue;
                };
                let Some(dst_value) = graph.value_id_for_var(dst) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: source.call_site,
                    at: graph
                        .inst_id_for_op_site(block.addr, op_index)
                        .unwrap_or(source.at),
                    block_addr: block.addr,
                    op_index,
                    value: dst_value,
                    width: dst.size,
                    relation: source.relation,
                    carrier: source.carrier.clone(),
                    owner: source.owner.clone().or(Some(ValueOwner::Value(src_value))),
                };
                insert_call_result_certificate(
                    call_results,
                    call_results_by_inst,
                    call_results_by_callsite,
                    &mut state.tracked,
                    cert,
                );
            }
            SSAOp::IntZExt { dst, src }
            | SSAOp::IntSExt { dst, src }
            | SSAOp::Trunc { dst, src }
            | SSAOp::Cast { dst, src, .. }
            | SSAOp::Subpiece { dst, src, .. } => {
                let Some(src_value) = graph.value_id_for_var(src) else {
                    continue;
                };
                let Some(source) = state.tracked.get(&src_value) else {
                    continue;
                };
                let Some(dst_value) = graph.value_id_for_var(dst) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: source.call_site,
                    at: graph
                        .inst_id_for_op_site(block.addr, op_index)
                        .unwrap_or(source.at),
                    block_addr: block.addr,
                    op_index,
                    value: dst_value,
                    width: dst.size,
                    relation: CallResultValueRelation::Derived,
                    carrier: source.carrier.clone(),
                    owner: source.owner.clone().or(Some(ValueOwner::Value(src_value))),
                };
                insert_call_result_certificate(
                    call_results,
                    call_results_by_inst,
                    call_results_by_callsite,
                    &mut state.tracked,
                    cert,
                );
            }
            SSAOp::Store {
                space: SpaceId::Ram,
                val,
                ..
            } => {
                let value = graph.value_id_for_var(val);
                let stack_access = value
                    .and_then(|value| {
                        stack_memory_access_at(StackMemoryAccessInput {
                            function,
                            graph,
                            structured,
                            objects,
                            block_addr: block.addr,
                            op_index,
                            is_write: true,
                            value: Some(value),
                        })
                    })
                    .or_else(|| {
                        stack_memory_access_at(StackMemoryAccessInput {
                            function,
                            graph,
                            structured,
                            objects,
                            block_addr: block.addr,
                            op_index,
                            is_write: true,
                            value: None,
                        })
                    });
                let Some((object, offset, _access)) = stack_access else {
                    continue;
                };
                let Some(value) = value else {
                    state.stack_owners.remove(&(object, offset));
                    continue;
                };
                let Some(source) = state.tracked.get(&value).cloned() else {
                    state.stack_owners.remove(&(object, offset));
                    continue;
                };
                state.stack_owners.insert(
                    (object, offset),
                    CallResultCertificate {
                        owner: Some(ValueOwner::StackSlot { object, offset }),
                        ..source.clone()
                    },
                );
                call_results.entry(value).and_modify(|cert| {
                    cert.owner = Some(ValueOwner::StackSlot { object, offset });
                });
                state.tracked.entry(value).and_modify(|cert| {
                    cert.owner = Some(ValueOwner::StackSlot { object, offset });
                });
            }
            SSAOp::Load {
                space: SpaceId::Ram,
                dst,
                ..
            } => {
                let Some(dst_value) = graph.value_id_for_var(dst) else {
                    continue;
                };
                let Some((object, offset, access)) =
                    stack_memory_access_at(StackMemoryAccessInput {
                        function,
                        graph,
                        structured,
                        objects,
                        block_addr: block.addr,
                        op_index,
                        is_write: false,
                        value: Some(dst_value),
                    })
                else {
                    continue;
                };
                let Some(source) = state.stack_owners.get(&(object, offset)) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: source.call_site,
                    at: graph
                        .inst_id_for_op_site(block.addr, op_index)
                        .unwrap_or(source.at),
                    block_addr: block.addr,
                    op_index,
                    value: dst_value,
                    width: dst.size,
                    relation: source.relation,
                    carrier: ReturnCarrier::StackSlot {
                        object,
                        offset,
                        memory_access: Some(access),
                    },
                    owner: Some(ValueOwner::StackSlot { object, offset }),
                };
                insert_call_result_certificate(
                    call_results,
                    call_results_by_inst,
                    call_results_by_callsite,
                    &mut state.tracked,
                    cert,
                );
            }
            _ => {}
        }
    }
    state
}

pub(crate) fn kill_return_register_flow_values(state: &mut CallResultFlowState) {
    state
        .tracked
        .retain(|_, certificate| !matches!(certificate.carrier, ReturnCarrier::Register { .. }));
}

pub(crate) fn insert_call_result_certificate(
    call_results: &mut BTreeMap<ValueId, CallResultCertificate>,
    call_results_by_inst: &mut BTreeMap<InstId, ValueId>,
    call_results_by_callsite: &mut BTreeMap<CallSiteId, Vec<ValueId>>,
    tracked: &mut BTreeMap<ValueId, CallResultCertificate>,
    cert: CallResultCertificate,
) {
    call_results_by_inst.insert(cert.at, cert.value);
    call_results_by_callsite
        .entry(cert.call_site)
        .or_default()
        .push(cert.value);
    tracked.insert(cert.value, cert.clone());
    call_results.insert(cert.value, cert);
}

pub(crate) struct StackMemoryAccessInput<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) structured: &'a StructuredDataflowFacts,
    pub(crate) objects: &'a ObjectModel,
    pub(crate) block_addr: u64,
    pub(crate) op_index: usize,
    pub(crate) is_write: bool,
    pub(crate) value: Option<ValueId>,
}

pub(crate) fn stack_memory_access_at(
    input: StackMemoryAccessInput<'_>,
) -> Option<(ObjectId, i64, StructuredAccessId)> {
    input
        .structured
        .memory_accesses
        .iter()
        .filter(|(_, access)| {
            access.block_addr == input.block_addr
                && access.op_index == input.op_index
                && access.is_write == input.is_write
                && input.value.is_none_or(|value| access.value == Some(value))
                && ram_memory_access_matches_source(
                    input.function,
                    input.graph,
                    input.objects,
                    access,
                )
        })
        .filter_map(|(access_id, access)| {
            stack_object_offset(input.objects, access.object)
                .map(|offset| (access.object, offset, *access_id))
        })
        .next()
}

pub(crate) fn stack_object_offset(objects: &ObjectModel, object: ObjectId) -> Option<i64> {
    stack_object_root(objects, object).map(|(_, offset)| offset)
}
