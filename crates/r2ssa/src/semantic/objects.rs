//! The frame's objects and what the body does to memory.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessSummary {
    pub(crate) uses: Vec<MemoryLocation>,
    pub(crate) defs: Vec<MemoryLocation>,
}

pub(crate) fn collect_object_and_memory_facts(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    addresses: &AddressProvenanceFacts,
    machine_context: Option<&SourceMachineContext>,
    declared_slots: &DeclaredStackSlots,
    values: &crate::values::ValueRanges,
) -> (ObjectModel, MemorySSAFacts) {
    let facts = prep;
    let builder = ObjectModelBuilder::new(facts, addresses, declared_slots, machine_context);
    let mut object_model = builder.build(function, graph, values);
    object_model.frame_reach =
        FrameReach::of(function, prep, graph, &object_model, machine_context);
    let access_summaries =
        collect_access_summaries(function, graph, facts, addresses, &object_model);
    let memory = build_memory_ssa(function, graph, &object_model, access_summaries);
    (object_model, memory)
}

pub(crate) fn collect_access_summaries(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep_facts: Option<&DecompilePrepFacts>,
    addresses: &AddressProvenanceFacts,
    object_model: &ObjectModel,
) -> BTreeMap<InstId, AccessSummary> {
    let mut summaries = BTreeMap::new();

    for block in function.blocks() {
        for (op_id, op) in block.sited() {
            let Some(inst_id) = graph.inst_for_op(op_id) else {
                continue;
            };
            let mut uses = Vec::new();
            let mut defs = Vec::new();
            match op {
                SSAOp::Load { dst, addr, space }
                | SSAOp::LoadLinked {
                    dst, addr, space, ..
                }
                | SSAOp::LoadGuarded {
                    dst, addr, space, ..
                } => {
                    uses.push(memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        dst.size,
                    ));
                }
                SSAOp::Store { addr, val, space }
                | SSAOp::StoreGuarded {
                    addr, val, space, ..
                } => {
                    defs.push(memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        val.size,
                    ));
                }
                SSAOp::StoreConditional {
                    addr, val, space, ..
                } => {
                    let location = memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        val.size,
                    );
                    uses.push(location.clone());
                    defs.push(location);
                }
                SSAOp::AtomicCAS(swap) => {
                    let location = memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        &swap.addr,
                        swap.space,
                        swap.expected.size.max(swap.replacement.size),
                    );
                    uses.push(location.clone());
                    defs.push(location);
                }
                // Every call may read and write whatever has escaped, whether or
                // not a call site certifies it: a call the site facts do not
                // know is no less a call. Leaving it out made two reads of an
                // escaped object on either side of it one memory version.
                SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                    let locations = call_locations(object_model, inst_id);
                    uses.extend(locations.iter().cloned());
                    defs.extend(locations);
                }
                _ => {}
            }
            if !uses.is_empty() || !defs.is_empty() {
                summaries.insert(inst_id, AccessSummary { uses, defs });
            }
        }
    }

    summaries
}

/// What a call reads and writes: the escaped memory of every space, and the
/// frame the callee finds above its stack pointer -- this call's argument
/// area, or the whole frame where nothing bounds it -- as whole objects. What
/// has escaped, the escaped memory already covers.
fn call_locations(object_model: &ObjectModel, call: InstId) -> Vec<MemoryLocation> {
    let escaped = object_model.memory_spaces().filter_map(|space| {
        Some(MemoryLocation {
            space,
            object: object_model.escaped_unknown_object(space)?,
            address: RelativeMemoryAddress::Unknown,
            size: 0,
        })
    });
    let reach = object_model.frame_reach.call(call);
    let frame = object_model.objects.iter().filter_map(|(id, fact)| {
        let space = match fact.kind {
            ObjectKind::StackSlot { space, .. } | ObjectKind::FrameObject { space, .. } => space,
            _ => return None,
        };
        let reached = match reach {
            CallFrameReach::Whole => true,
            CallFrameReach::Objects(objects) => objects.contains(id),
        };
        (reached && !object_model.frame_reach.escaped(*id)).then_some(MemoryLocation {
            space,
            object: *id,
            address: RelativeMemoryAddress::Unknown,
            size: 0,
        })
    });
    escaped.chain(frame).collect()
}

pub(crate) fn build_memory_ssa(
    function: &SSAFunction,
    graph: &SsaGraph,
    object_model: &ObjectModel,
    access_summaries: BTreeMap<InstId, AccessSummary>,
) -> MemorySSAFacts {
    let mut phis_by_block = BTreeMap::new();

    let mut next_version_by_object = BTreeMap::<ObjectId, u32>::new();
    for object in object_model.objects.keys() {
        next_version_by_object.insert(*object, 1);
    }

    let mut def_versions = BTreeMap::<InstId, Vec<MemoryVersion>>::new();
    for (inst_id, summary) in &access_summaries {
        if summary.defs.is_empty() {
            continue;
        }
        let versions = summary
            .defs
            .iter()
            .map(|location| {
                let next = next_version_by_object.entry(location.object).or_insert(1);
                let version = MemoryVersion {
                    object: location.object,
                    version: *next,
                };
                *next = next.saturating_add(1);
                version
            })
            .collect::<Vec<_>>();
        def_versions.insert(*inst_id, versions);
    }

    let mut in_states = BTreeMap::<u64, BTreeMap<MemoryLocation, MemoryVersion>>::new();
    let mut out_states = BTreeMap::<u64, BTreeMap<MemoryLocation, MemoryVersion>>::new();
    let mut phi_versions = BTreeMap::<(u64, MemoryLocation), MemoryVersion>::new();
    let mut phi_inputs = BTreeMap::<(u64, MemoryLocation), Vec<(u64, MemoryVersion)>>::new();
    let (uses_by_inst, defs_by_inst) = loop {
        let mut changed = false;
        let mut uses_by_inst = BTreeMap::<InstId, Vec<MemoryUseFact>>::new();
        let mut defs_by_inst = BTreeMap::<InstId, Vec<MemoryDefFact>>::new();
        for &block_addr in function.block_addrs() {
            let preds = function.predecessors(block_addr);
            let mut in_state = BTreeMap::new();

            if !preds.is_empty() {
                let locations = preds
                    .iter()
                    .filter_map(|pred| out_states.get(pred))
                    .flat_map(|state| state.keys().cloned())
                    .collect::<BTreeSet<_>>();
                for location in locations {
                    let inputs = preds
                        .iter()
                        .map(|pred| {
                            let version = out_states
                                .get(pred)
                                .and_then(|state| state.get(&location).copied())
                                .unwrap_or(MemoryVersion {
                                    object: location.object,
                                    version: 0,
                                });
                            (*pred, version)
                        })
                        .collect::<Vec<_>>();
                    let first_version = inputs.first().map(|(_, version)| *version);
                    let merged = if inputs
                        .iter()
                        .all(|(_, version)| Some(*version) == first_version)
                    {
                        first_version.expect("inputs is not empty")
                    } else {
                        let key = (block_addr, location.clone());
                        let phi = phi_versions.entry(key.clone()).or_insert_with(|| {
                            let next = next_version_by_object.entry(location.object).or_insert(1);
                            let version = MemoryVersion {
                                object: location.object,
                                version: *next,
                            };
                            *next = next.saturating_add(1);
                            version
                        });
                        phi_inputs.insert(key, inputs);
                        *phi
                    };
                    if merged.version != 0 {
                        in_state.insert(location, merged);
                    }
                }
            }

            if in_states.get(&block_addr) != Some(&in_state) {
                in_states.insert(block_addr, in_state.clone());
                changed = true;
            }

            let mut state = in_state;
            let Some(block) = function.get_block(block_addr) else {
                continue;
            };
            for (op_id, _) in block.sited() {
                let Some(inst_id) = graph.inst_for_op(op_id) else {
                    continue;
                };
                let Some(summary) = access_summaries.get(&inst_id) else {
                    continue;
                };
                for location in &summary.uses {
                    let mut reaching = state
                        .iter()
                        .filter(|(candidate, _)| {
                            memory_locations_may_alias(object_model, candidate, location)
                        })
                        .map(|(_, version)| *version)
                        .collect::<BTreeSet<_>>();
                    if reaching.is_empty() {
                        reaching.insert(MemoryVersion {
                            object: location.object,
                            version: 0,
                        });
                    }
                    for version in reaching {
                        uses_by_inst
                            .entry(inst_id)
                            .or_default()
                            .push(MemoryUseFact {
                                location: location.clone(),
                                version,
                            });
                    }
                }
                if let Some(def_versions_for_op) = def_versions.get(&inst_id) {
                    for (location, next_version) in
                        summary.defs.iter().zip(def_versions_for_op.iter())
                    {
                        let mut previous = state
                            .iter()
                            .filter(|(candidate, _)| {
                                memory_locations_may_alias(object_model, candidate, location)
                            })
                            .map(|(_, version)| *version)
                            .collect::<BTreeSet<_>>();
                        if previous.is_empty() {
                            previous.insert(MemoryVersion {
                                object: location.object,
                                version: 0,
                            });
                        }
                        for previous_version in previous {
                            defs_by_inst
                                .entry(inst_id)
                                .or_default()
                                .push(MemoryDefFact {
                                    location: location.clone(),
                                    previous_version,
                                    next_version: *next_version,
                                });
                        }
                        state.retain(|candidate, _| {
                            !memory_locations_may_alias(object_model, candidate, location)
                        });
                        state.insert(location.clone(), *next_version);
                    }
                }
            }

            if out_states.get(&block_addr) != Some(&state) {
                out_states.insert(block_addr, state);
                changed = true;
            }
        }

        if !changed {
            break (uses_by_inst, defs_by_inst);
        }
    };

    for ((block_addr, location), output_version) in phi_versions {
        let inputs = phi_inputs
            .remove(&(block_addr, location.clone()))
            .unwrap_or_default();
        phis_by_block
            .entry(block_addr)
            .or_insert_with(Vec::new)
            .push(MemoryPhiFact {
                object: location.object,
                location,
                output_version,
                inputs,
            });
    }

    MemorySSAFacts {
        uses_by_inst,
        defs_by_inst,
        phis_by_block,
    }
}
