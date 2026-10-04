//! What a call leaves behind, and which of it the body reads.

use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResultCertificate {
    pub call_site: CallSiteId,
    pub at: InstId,
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
    crate::dense::IdMap<ValueId, CallResultCertificate>,
    crate::dense::IdMap<InstId, ValueId>,
    BTreeMap<CallSiteId, Vec<ValueId>>,
);

pub(crate) fn collect_call_result_certificates(
    body: Body<'_>,
    derived: Derived<'_>,
) -> CallResultCertificateIndexes {
    let function = body.function;
    let call_sites = derived.call_sites;
    let mut call_results = crate::dense::IdMap::default();
    let mut call_results_by_inst = crate::dense::IdMap::default();
    let mut call_results_by_callsite = BTreeMap::<CallSiteId, Vec<ValueId>>::new();
    let callsites_by_inst = &call_sites.by_inst;
    // Settle the tracked results on the fixpoint driver first, writing no
    // certificate: a state seen before the merges settle may claim an owner
    // the settled state does not, and a certificate written from it would
    // outlive it. Each tracked value or owner can only be dropped, once.
    let height = body.graph.values.len().saturating_add(1);
    let solved = crate::fixpoint::forward(
        function,
        "call-results",
        height,
        CallResultFlowState::default(),
        |block_addr, input| {
            let Some(block) = function.get_block(block_addr) else {
                return input.clone();
            };
            process_call_result_flow_block(
                body,
                derived,
                block,
                callsites_by_inst,
                input.clone(),
                CallResultSink {
                    call_results: &mut crate::dense::IdMap::default(),
                    call_results_by_inst: &mut crate::dense::IdMap::default(),
                    call_results_by_callsite: &mut BTreeMap::new(),
                },
            )
        },
    );
    let solved = match solved {
        Ok(solved) => solved,
        Err(exhausted) => {
            r2il::refusal_evidence!("call-results", "{exhausted}");
            return Default::default();
        }
    };
    // Then the certificates, once, from each block's settled entry state.
    for &block_addr in function.block_addrs() {
        let (Some(block), Some(input)) = (
            function.get_block(block_addr),
            solved.entry.get(&block_addr),
        ) else {
            continue;
        };
        process_call_result_flow_block(
            body,
            derived,
            block,
            callsites_by_inst,
            input.clone(),
            CallResultSink {
                call_results: &mut call_results,
                call_results_by_inst: &mut call_results_by_inst,
                call_results_by_callsite: &mut call_results_by_callsite,
            },
        );
    }

    for values in call_results_by_callsite.values_mut() {
        values.sort_unstable();
        values.dedup();
    }

    (call_results, call_results_by_inst, call_results_by_callsite)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CallResultFlowState {
    pub(crate) tracked: crate::dense::IdMap<ValueId, CallResultCertificate>,
    pub(crate) stack_owners: BTreeMap<(ObjectId, i64), CallResultCertificate>,
}

impl crate::fixpoint::Join for CallResultFlowState {
    /// What every path that reaches the merge agrees on: a tracked result
    /// or owner survives only where both sides hold the same certificate.
    /// The driver never joins an unreached predecessor, so a loop's back edge
    /// does not empty the header before it has been walked.
    fn join(&mut self, other: &Self) -> bool {
        let before = (self.tracked.len(), self.stack_owners.len());
        self.tracked
            .retain(|value, cert| other.tracked.get(value) == Some(cert));
        self.stack_owners
            .retain(|slot, cert| other.stack_owners.get(slot) == Some(cert));
        before != (self.tracked.len(), self.stack_owners.len())
    }
}

/// The three indexes a call-result certificate is recorded in at once.
pub(crate) struct CallResultSink<'a> {
    pub(crate) call_results: &'a mut crate::dense::IdMap<ValueId, CallResultCertificate>,
    pub(crate) call_results_by_inst: &'a mut crate::dense::IdMap<InstId, ValueId>,
    pub(crate) call_results_by_callsite: &'a mut BTreeMap<CallSiteId, Vec<ValueId>>,
}

pub(crate) fn process_call_result_flow_block(
    body: Body<'_>,
    derived: Derived<'_>,
    block: &crate::SSABlock<crate::VarId>,
    callsites_by_inst: &crate::dense::IdMap<InstId, CallSiteId>,
    mut state: CallResultFlowState,
    sink: CallResultSink<'_>,
) -> CallResultFlowState {
    let graph = body.graph;
    let width = |id: &crate::VarId| body.function.var(*id).size;
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
    for (id, op) in block.sited() {
        let Some(inst) = graph.inst_for_op(id) else {
            continue;
        };
        match op {
            SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                kill_return_register_flow_values(&mut state);
                active_call = callsites_by_inst.get(inst).copied();
            }
            SSAOp::CallDefine { dst } => {
                let Some(call_site_id) = active_call else {
                    continue;
                };
                if !call_sites.by_id.contains_key(&call_site_id) {
                    continue;
                }
                let Some(value) = graph.value_of(*dst) else {
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
                    at: inst,
                    value,
                    width: width(dst),
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
                let Some(src_value) = graph.value_of(*src) else {
                    continue;
                };
                let Some(source) = state.tracked.get(src_value) else {
                    continue;
                };
                let Some(dst_value) = graph.value_of(*dst) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: source.call_site,
                    at: inst,
                    value: dst_value,
                    width: width(dst),
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
                let Some(src_value) = graph.value_of(*src) else {
                    continue;
                };
                let Some(source) = state.tracked.get(src_value) else {
                    continue;
                };
                let Some(dst_value) = graph.value_of(*dst) else {
                    continue;
                };
                let cert = CallResultCertificate {
                    call_site: source.call_site,
                    at: inst,
                    value: dst_value,
                    width: width(dst),
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
                let value = graph.value_of(*val);
                let stack_access = value
                    .and_then(|value| {
                        stack_memory_access_at(StackMemoryAccessInput {
                            graph,
                            structured,
                            objects,
                            inst,
                            is_write: true,
                            value: Some(value),
                        })
                    })
                    .or_else(|| {
                        stack_memory_access_at(StackMemoryAccessInput {
                            graph,
                            structured,
                            objects,
                            inst,
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
                let Some(source) = state.tracked.get(value).cloned() else {
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
                if let Some(cert) = call_results.get_mut(value) {
                    cert.owner = Some(ValueOwner::StackSlot { object, offset });
                }
                if let Some(cert) = state.tracked.get_mut(value) {
                    cert.owner = Some(ValueOwner::StackSlot { object, offset });
                }
            }
            SSAOp::Load {
                space: SpaceId::Ram,
                dst,
                ..
            } => {
                let Some(dst_value) = graph.value_of(*dst) else {
                    continue;
                };
                let Some((object, offset, access)) =
                    stack_memory_access_at(StackMemoryAccessInput {
                        graph,
                        structured,
                        objects,
                        inst,
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
                    at: inst,
                    value: dst_value,
                    width: width(dst),
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
    call_results: &mut crate::dense::IdMap<ValueId, CallResultCertificate>,
    call_results_by_inst: &mut crate::dense::IdMap<InstId, ValueId>,
    call_results_by_callsite: &mut BTreeMap<CallSiteId, Vec<ValueId>>,
    tracked: &mut crate::dense::IdMap<ValueId, CallResultCertificate>,
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
    pub(crate) graph: &'a SsaGraph,
    pub(crate) structured: &'a StructuredDataflowFacts,
    pub(crate) objects: &'a ObjectModel,
    pub(crate) inst: InstId,
    pub(crate) is_write: bool,
    pub(crate) value: Option<ValueId>,
}

pub(crate) fn stack_memory_access_at(
    input: StackMemoryAccessInput<'_>,
) -> Option<(ObjectId, i64, StructuredAccessId)> {
    // Only this operation's instruction can own a match, so search its accesses alone.
    let inst = input.inst;
    let first = StructuredAccessId { inst, ordinal: 0 };
    let last = StructuredAccessId {
        inst,
        ordinal: u32::MAX,
    };
    input
        .structured
        .memory_accesses
        .range(first..=last)
        .filter(|(_, access)| {
            access.is_write == input.is_write
                && input.value.is_none_or(|value| access.value == Some(value))
                && ram_memory_access_matches_source(input.graph, input.objects, access)
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
