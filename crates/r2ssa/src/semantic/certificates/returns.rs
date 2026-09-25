//! What the body proves about what it returns and how it leaves.

use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnValueCertificate {
    pub at: InstId,
    pub block_addr: u64,
    pub op_index: usize,
    pub value: ValueId,
    pub width: u32,
    pub carrier: Option<ReturnCarrier>,
    /// Exact logical return projection declared by the immutable source
    /// interface. `None` preserves the physical ABI-carrier behavior for
    /// interfaces that carry no logical type graph.
    pub source_logical_value: Option<SourceLogicalValue>,
}

pub(crate) fn collect_machine_return_control_certificates(
    boundaries: &SourceBoundaryFacts,
    graph: &SsaGraph,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    unobserved: &crate::deadphi::DeadPhis,
) -> (
    BTreeMap<InstId, MachineReturnControlCertificate>,
    BTreeMap<InstId, InstId>,
) {
    let mut certificates = BTreeMap::new();
    let mut by_inst = BTreeMap::new();
    for (at, boundary) in &boundaries.returns {
        let Some(return_address) = boundary.return_address else {
            continue;
        };
        let Some(return_inst) = graph.inst(*at) else {
            continue;
        };
        if return_inst.inputs.first() != Some(&return_address.value)
            || !matches!(return_inst.payload, InstPayload::Op(SSAOp::Return { .. }))
        {
            continue;
        }

        let mut insts = BTreeSet::new();
        let mut values = BTreeSet::from([return_address.value]);
        let mut current = return_address.value;
        let mut complete = true;
        let mut reload_object = None;
        // The prologue saves the return address once however many returns the
        // function has, so every return's certificate describes that one save.
        // These instructions are therefore exempt from the rule that no two
        // certificates may claim an instruction: that rule exists to stop two
        // certificates giving different accounts of one instruction, and here
        // they give the same account.
        let mut absorbed = BTreeSet::new();
        loop {
            let Some(inst) = graph.def_inst(current) else {
                break;
            };
            let Some(definition) = graph.inst(inst) else {
                complete = false;
                break;
            };
            match &definition.payload {
                InstPayload::Op(SSAOp::Copy { dst, src }) => {
                    let Some(source) = graph.value_id_for_var(src) else {
                        complete = false;
                        break;
                    };
                    if definition.output != Some(current)
                        || definition.inputs.as_slice() != [source]
                        || dst.size != return_address.storage.size
                        || src.size != return_address.storage.size
                        || !insts.insert(inst)
                        || !values.insert(source)
                    {
                        complete = false;
                        break;
                    }
                    current = source;
                }
                InstPayload::Op(SSAOp::Load {
                    space: SpaceId::Ram,
                    dst,
                    ..
                }) => {
                    let accesses = structured
                        .memory_accesses
                        .values()
                        .filter(|access| {
                            access.id.inst == inst
                                && !access.is_write
                                && access.value == Some(current)
                                && access.provenance_complete
                                && access.space == SpaceId::Ram
                                && access.width == return_address.storage.size
                        })
                        .collect::<Vec<_>>();
                    let [access] = accesses.as_slice() else {
                        complete = false;
                        break;
                    };
                    let stack_object = matches!(
                        objects.object(access.object).map(|object| &object.kind),
                        Some(
                            ObjectKind::StackSlot { .. }
                                | ObjectKind::FrameObject { .. }
                                | ObjectKind::Parameter { .. }
                        )
                    );
                    if !stack_object
                        || dst.size != return_address.storage.size
                        || definition.output != Some(current)
                        || definition.inputs.as_slice() != [access.address]
                        || !insts.insert(inst)
                    {
                        complete = false;
                        break;
                    }
                    reload_object = Some(access.object);
                    // The slot this reload came from holds the return address
                    // and nothing else. Its one write is the prologue's save,
                    // and the value it saves is the return address the function
                    // was entered with. Save and reload are one fact about
                    // control, so the certificate that answers for the reload
                    // answers for the save too; leaving the save to another
                    // collector is what renders it as a store to a variable no
                    // one reads, assigned from an entry value nothing wrote.
                    let object_accesses = structured
                        .memory_accesses
                        .values()
                        .filter(|other| other.object == access.object)
                        .collect::<Vec<_>>();
                    let writes = object_accesses
                        .iter()
                        .filter(|other| other.is_write)
                        .collect::<Vec<_>>();
                    let reads = object_accesses
                        .iter()
                        .filter(|other| !other.is_write)
                        .collect::<Vec<_>>();
                    if let ([store], [only_read]) = (writes.as_slice(), reads.as_slice())
                        && only_read.id == access.id
                        && store.provenance_complete
                        && store.space == SpaceId::Ram
                        && store.width == return_address.storage.size
                        && let Some(stored) = store.value
                        && let Some((storage, entry, save_insts, save_values)) =
                            exact_copy_chain_to_entry_storage(
                                graph,
                                stored,
                                return_address.storage.size,
                            )
                        && storage == return_address.storage
                        && insts.insert(store.id.inst)
                    {
                        absorbed.insert(store.id.inst);
                        absorbed.extend(save_insts.iter().copied());
                        insts.extend(save_insts);
                        values.extend(save_values);
                        values.insert(entry);
                    }
                    break;
                }
                _ => {
                    complete = false;
                    break;
                }
            }
        }
        let return_use = UseSite {
            inst: *at,
            input_idx: 0,
        };
        if !complete
            || insts.is_empty()
            // A use the merge analysis has already answered for is not a
            // reader. The link register reaches a return through phis that
            // merge it with itself; those merges render nothing, and counting
            // them as escapes refused the certificate on every path but the
            // first, which is how a saved return address kept its declaration
            // in a function with more than one return.
            || values.iter().any(|value| {
                graph.use_sites(*value).iter().any(|site| {
                    *site != return_use
                        && !insts.contains(&site.inst)
                        && !unobserved.unobserved_uses().contains(site)
                })
            })
            || insts
                .iter()
                .any(|inst| !absorbed.contains(inst) && by_inst.contains_key(inst))
        {
            continue;
        }
        let uses = insts
            .iter()
            .flat_map(|inst| {
                graph.inst(*inst).into_iter().flat_map(move |definition| {
                    (0..definition.inputs.len()).map(move |input_idx| UseSite {
                        inst: *inst,
                        input_idx,
                    })
                })
            })
            .collect::<BTreeSet<_>>();
        let certificate = MachineReturnControlCertificate {
            at: *at,
            storage: return_address.storage,
            control_value: return_address.value,
            insts,
            values,
            uses,
            absorbed_insts: absorbed,
            reload_object,
        };
        for inst in certificate
            .insts
            .iter()
            .filter(|inst| !certificate.absorbed_insts.contains(inst))
        {
            by_inst.insert(*inst, *at);
        }
        certificates.insert(*at, certificate);
    }
    (certificates, by_inst)
}

pub(crate) fn collect_return_value_certificates(
    boundaries: &SourceBoundaryFacts,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    stack_reloads: &BTreeMap<ValueId, StackReloadSourceCertificate>,
) -> (Vec<ReturnValueCertificate>, BTreeMap<InstId, usize>) {
    let mut returns = Vec::new();
    let mut returns_by_inst = BTreeMap::new();

    for (boundary_at, boundary) in &boundaries.returns {
        if boundary.at != *boundary_at || !boundary.complete {
            r2il::refusal_evidence!(
                "return-certificate",
                "{:?}: at_mismatch={} incomplete={}",
                boundary_at,
                boundary.at != *boundary_at,
                !boundary.complete
            );
            continue;
        }
        let Some((block_addr, op_index)) = graph.op_site_for_inst(boundary.at) else {
            continue;
        };
        let Some(inst) = graph.inst(boundary.at) else {
            continue;
        };
        if !matches!(inst.payload, InstPayload::Op(SSAOp::Return { .. })) {
            continue;
        }
        let certificate = {
            let [boundary_value] = boundary.values.as_slice() else {
                // A complete void boundary is authoritative, but it owns no value.
                if !boundary.values.is_empty() {
                    r2il::refusal_evidence!(
                        "return-certificate",
                        "{:?}: {} boundary values, not one",
                        boundary_at,
                        boundary.values.len()
                    );
                }
                continue;
            };
            let Some((value, width, source_logical_value)) =
                exact_logical_return_projection(graph, machine_context, boundary_value)
            else {
                r2il::refusal_evidence!(
                    "return-certificate",
                    "{:?}: no logical projection for {:?} in slot {:?}",
                    boundary_at,
                    boundary_value.value,
                    boundary_value.slot
                );
                continue;
            };
            ReturnValueCertificate {
                at: boundary.at,
                block_addr,
                op_index,
                value,
                width,
                carrier: return_carrier_for_boundary_value(boundary_value, stack_reloads),
                source_logical_value,
            }
        };
        returns_by_inst.insert(boundary.at, returns.len());
        returns.push(certificate);
    }

    (returns, returns_by_inst)
}

pub(crate) fn exact_logical_return_projection(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    boundary: &CallBoundaryValueFact,
) -> Option<(ValueId, u32, Option<SourceLogicalValue>)> {
    r2il::refusal_evidence!(
        "return-logical-projection",
        "entered for {:?} slot {:?}",
        boundary.value,
        boundary.slot
    );
    let Some(physical_value) = graph.value(boundary.value) else {
        r2il::refusal_evidence!(
            "return-logical-projection",
            "boundary value {:?} is not in the graph",
            boundary.value
        );
        return None;
    };
    let Some(interface) = machine_context.and_then(SourceMachineContext::function_interface) else {
        return Some((boundary.value, physical_value.var.size, None));
    };
    // Only an interface that states no types leaves the result the carrier's
    // width. One that states types and none for a register result has said
    // nothing about it, and the carrier's width is not a statement either:
    // the declaration owns the logical return, or nothing does.
    let Some(type_graph) = interface.type_graph() else {
        return Some((boundary.value, physical_value.var.size, None));
    };
    let Some(logical) = interface.return_logical_value() else {
        if matches!(
            interface.return_kind(),
            SourceFunctionReturn::Register { .. }
        ) {
            r2il::refusal_evidence!(
                "return-logical-projection",
                "the interface types its values and states no type for its register result"
            );
            return None;
        }
        return Some((boundary.value, physical_value.var.size, None));
    };
    let SourceFunctionReturn::Register { storage } = interface.return_kind() else {
        r2il::refusal_evidence!(
            "return-logical-projection",
            "interface declares no register return: {:?}",
            interface.return_kind()
        );
        return None;
    };
    let CallBoundarySlot::Register {
        storage: boundary_storage,
        ..
    } = boundary.slot
    else {
        r2il::refusal_evidence!(
            "return-logical-projection",
            "boundary slot is not a register: {:?}",
            boundary.slot
        );
        return None;
    };
    let Some(source_type) = type_graph
        .types()
        .get(usize::try_from(logical.type_id()).ok()?)
        .filter(|source_type| source_type.id() == logical.type_id())
    else {
        r2il::refusal_evidence!(
            "return-logical-projection",
            "type graph has no type {} for the declared return",
            logical.type_id()
        );
        return None;
    };
    let projection = logical.carrier();
    let physical_bits = u64::from(storage.size).checked_mul(8)?;
    if boundary_storage != storage
        || storage.space != CanonicalStorageSpace::Register
        || storage.size == 0
        || projection.offset_bits() != 0
        || projection.size_bits() == 0
        || projection.size_bits() != source_type.size_bits()
        || !projection.size_bits().is_multiple_of(8)
        || projection.size_bits() > physical_bits
    {
        r2il::refusal_evidence!(
            "return-logical-projection",
            "sanity gate: boundary {:?} vs declared {:?}, projection {} bits at offset {}, source type {} bits, physical {} bits",
            boundary_storage,
            storage,
            projection.size_bits(),
            projection.offset_bits(),
            source_type.size_bits(),
            physical_bits
        );
        return None;
    }
    match projection.kind() {
        // The value the walk reached is the carrier's own, or the operand a
        // lane insert wrote into it, which has no storage of its own.
        SourceCarrierKind::Full
            if projection.size_bits() == physical_bits
                && physical_value.var.size == storage.size
                && physical_value
                    .canonical_storage
                    .is_none_or(|reached| reached == storage) =>
        {
            Some((boundary.value, storage.size, Some(logical)))
        }
        // A float is a scalar in the carrier's low lane exactly as an integer
        // is: a `double` returned in a 128-bit vector register is its low half.
        SourceCarrierKind::LowBits
            if projection.size_bits() < physical_bits
                && matches!(
                    source_type.kind(),
                    SourceTypeKind::SignedInteger
                        | SourceTypeKind::UnsignedInteger
                        | SourceTypeKind::Float
                ) =>
        {
            let Ok(logical_width) = u32::try_from(projection.size_bits() / 8) else {
                r2il::refusal_evidence!(
                    "return-logical-projection",
                    "logical width {} bits does not fit a u32 byte count",
                    projection.size_bits()
                );
                return None;
            };
            let Some(logical_storage) =
                projected_logical_register_storage(storage, logical, type_graph)
            else {
                r2il::refusal_evidence!(
                    "return-logical-projection",
                    "no projected narrow storage for {} bits of {:?}",
                    projection.size_bits(),
                    storage
                );
                return None;
            };
            if physical_value.var.size == logical_width
                && physical_value.canonical_storage == Some(logical_storage)
            {
                return Some((boundary.value, logical_width, Some(logical)));
            }
            if physical_value.var.size != storage.size
                || physical_value.canonical_storage != Some(storage)
            {
                return None;
            }
            // The carrier's own definition is one extension of the logical
            // width, or the insert of that lane at its low end: certify the
            // lane value itself, usually the named local, so the return names
            // it rather than casting the carrier.
            if let Some(input) =
                exact_logical_lane_input(graph, boundary.value, physical_value, logical_width)
            {
                return Some((input, logical_width, Some(logical)));
            }
            // Otherwise the carrier holds the logical value in its low lane
            // whatever defined it -- a load, a call result, a full-width
            // computation, a merge of any of those -- because a caller of a
            // narrow return reads only that lane and the bits above it are
            // undefined by the convention. Certify the carrier at the logical
            // width; the render narrows it against the declared return type,
            // which is the conversion the source itself wrote
            // (`return (z_crc_t)data;`). Requiring every path to be an
            // extension refused the merged returns of most optimised
            // functions and every `return f(x);`, for no bit a caller could
            // observe.
            r2il::refusal_evidence!(
                "return-logical-projection",
                "LowBits width {} of {:?}: carrier {:?} certified at the logical width, defined by {}",
                logical_width,
                storage,
                boundary.value,
                graph
                    .def_inst(boundary.value)
                    .and_then(|id| graph.inst(id))
                    .map_or_else(
                        || "nothing".to_string(),
                        |inst| format!("{:?}", inst.payload)
                    )
            );
            Some((boundary.value, logical_width, Some(logical)))
        }
        kind => {
            r2il::refusal_evidence!(
                "return-logical-projection",
                "carrier kind {:?} of {:?}: projection {} bits, value {:?} is {} bytes at {:?}, source type {:?}",
                kind,
                storage,
                projection.size_bits(),
                boundary.value,
                physical_value.var.size,
                physical_value.canonical_storage,
                source_type.kind()
            );
            None
        }
    }
}

/// The lane value the carrier's own definition widens or inserts at its low
/// end, when that lane is the logical width.
///
/// Returns `None` for every other shape, including a merge, so the caller can
/// go on to ask the wider question rather than refusing here.
pub(crate) fn exact_logical_lane_input(
    graph: &SsaGraph,
    carrier: ValueId,
    carrier_value: &crate::graph::GraphValue,
    logical_width: u32,
) -> Option<ValueId> {
    let producer = graph.def_inst(carrier).and_then(|id| graph.inst(id))?;
    if producer.output != Some(carrier) {
        return None;
    }
    let (lane, lane_var) = match (&producer.payload, producer.inputs.as_slice()) {
        (InstPayload::Op(SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src }), [input])
            if *dst == carrier_value.var =>
        {
            (*input, src)
        }
        (InstPayload::Op(SSAOp::Insert(insert)), [_, input, _])
            if insert.dst == carrier_value.var && insert.position.constant_bits() == Some(0) =>
        {
            (*input, &insert.value)
        }
        _ => return None,
    };
    let lane_value = graph.value(lane)?;
    (lane_value.var == *lane_var && lane_value.var.size == logical_width).then_some(lane)
}

pub(crate) fn return_carrier_for_boundary_value(
    boundary: &CallBoundaryValueFact,
    stack_reloads: &BTreeMap<ValueId, StackReloadSourceCertificate>,
) -> Option<ReturnCarrier> {
    match boundary.slot {
        CallBoundarySlot::Register { .. } => return_carrier_for_boundary_slot(boundary.slot),
        CallBoundarySlot::Stack(offset) => {
            let reload = stack_reloads.get(&boundary.value)?;
            (reload.offset == offset).then_some(ReturnCarrier::StackSlot {
                object: reload.object,
                offset: reload.offset,
                memory_access: Some(reload.load_access),
            })
        }
    }
}
