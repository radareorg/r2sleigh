//! Frame objects nothing outside the function can observe.

use super::*;

pub(crate) fn private_stack_objects(
    graph: &SsaGraph,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    live_out: &crate::liveout::FunctionLiveOut,
) -> BTreeSet<ObjectId> {
    let mut private = BTreeSet::new();
    let mut access_addresses = BTreeSet::<(InstId, ValueId)>::new();
    for access in structured.memory_accesses.values() {
        if access.space == SpaceId::Ram {
            access_addresses.insert((access.id.inst, access.address));
        }
    }
    let mut addresses_by_object = BTreeMap::<ObjectId, BTreeSet<ValueId>>::new();
    // Every value that names some stack address. Arithmetic from one slot's
    // base to another slot's address stays inside the frame and is not escape.
    let mut stack_addresses = BTreeSet::<ValueId>::new();
    for (key, object) in &objects.value_objects {
        if key.space != SpaceId::Ram {
            continue;
        }
        addresses_by_object
            .entry(*object)
            .or_default()
            .insert(key.value);
        if objects.object(*object).is_some_and(|fact| {
            matches!(
                fact.kind,
                ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
            )
        }) {
            stack_addresses.insert(key.value);
        }
    }
    for (object, fact) in &objects.objects {
        if !matches!(
            fact.kind,
            ObjectKind::StackSlot {
                space: SpaceId::Ram,
                ..
            } | ObjectKind::FrameObject {
                space: SpaceId::Ram,
                ..
            }
        ) {
            continue;
        }
        // No value names the object, so no address of it exists to leave
        // the function: nothing outside can reach it, vacuously.
        let Some(addresses) = addresses_by_object.get(object) else {
            private.insert(*object);
            continue;
        };
        match stack_address_escape(
            graph,
            &access_addresses,
            &stack_addresses,
            live_out,
            addresses,
        ) {
            Some(site) => r2il::refusal_evidence!(
                "private-stack-objects",
                "object {object:?} is not private: an address naming it reaches {site:?} by {:?}",
                graph
                    .inst(site.inst)
                    .map(|inst| format!("{:?}", inst.payload)
                        .chars()
                        .take(120)
                        .collect::<String>())
            ),
            None => {
                private.insert(*object);
            }
        }
    }
    private
}

/// Where a slot's address leaves the function, if anywhere.
///
/// A pointer from outside can name a slot only if the slot's address left the
/// function, so the walk follows everything computed from the address forward
/// until it is stored, passed to a call, handed back to the caller, or used as
/// the address of an access the model could not place. A value that names
/// another stack slot is that slot's address and stops the walk; a flag or a
/// merge computed from the address is followed like any other value, and is
/// no escape unless what it feeds is.
pub(crate) fn stack_address_escape(
    graph: &SsaGraph,
    access_addresses: &BTreeSet<(InstId, ValueId)>,
    stack_addresses: &BTreeSet<ValueId>,
    live_out: &crate::liveout::FunctionLiveOut,
    addresses: &BTreeSet<ValueId>,
) -> Option<UseSite> {
    let mut pending = addresses.iter().copied().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        let derived = !addresses.contains(&value);
        if live_out.contains(value) {
            return graph.use_sites(value).first().copied().or_else(|| {
                graph
                    .def_inst(value)
                    .map(|inst| UseSite { inst, input_idx: 0 })
            });
        }
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                return Some(*site);
            };
            if site.input_idx == 0 && access_addresses.contains(&(site.inst, value)) {
                // The object's own access, or an access the model could not
                // place through a value computed from the address.
                if derived {
                    return Some(*site);
                }
                continue;
            }
            match &inst.payload {
                InstPayload::Phi { .. } => {}
                InstPayload::Op(op) => match op {
                    SSAOp::CBranch { .. } | SSAOp::Branch { .. } => continue,
                    SSAOp::Store { .. }
                    | SSAOp::BlockTransfer { .. }
                    | SSAOp::StoreConditional { .. }
                    | SSAOp::StoreGuarded { .. }
                    | SSAOp::AtomicCAS { .. }
                    | SSAOp::Load { .. }
                    | SSAOp::LoadLinked { .. }
                    | SSAOp::LoadGuarded { .. }
                    | SSAOp::CallUse { .. }
                    | SSAOp::Call { .. }
                    | SSAOp::CallInd { .. }
                    | SSAOp::CallOther { .. }
                    | SSAOp::BranchInd { .. }
                    | SSAOp::Switch { .. }
                    | SSAOp::Return { .. } => return Some(*site),
                    _ => {}
                },
            }
            let Some(output) = inst.output else {
                return Some(*site);
            };
            if stack_addresses.contains(&output) {
                continue;
            }
            pending.push(output);
        }
    }
    None
}

/// Every store that puts back into its object exactly what the object held.
///
/// Privacy is not required and would be wrong to require. The claim is that
/// memory ends holding what it held, which is true of the location whoever
/// else can name it; the probe's own slot is part of a frame whose address
/// reaches a callee, so a private-object test would decline exactly the case
/// this exists for. What is required is that both accesses are exactly
/// modelled -- an access the memory facts do not state completely carries an
/// unknown effect of its own and is never certified here.
pub(crate) fn collect_memory_round_trips(
    graph: &SsaGraph,
    structured: &StructuredDataflowFacts,
) -> BTreeMap<StructuredAccessId, MemoryRoundTripCertificate> {
    let mut certificates = BTreeMap::new();
    for write in structured.memory_accesses.values() {
        if !write.is_write || !write.provenance_complete {
            continue;
        }
        let Some(stored) = write.value else {
            continue;
        };
        // Through copies, because the operation that leaves memory unchanged is
        // spelled as one: Sleigh lowers `or x, 0` to a copy of the loaded value.
        let mut value = stored;
        while let Some(source) = graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .and_then(|inst| match &inst.payload {
                crate::graph::InstPayload::Op(crate::SSAOp::Copy { .. }) => {
                    inst.inputs.first().copied()
                }
                _ => None,
            })
        {
            value = source;
        }
        // The same address, not merely the same object. Two accesses to one
        // object at offsets nothing states exactly are not the same location:
        // `movzx eax, byte [rcx + r13]; mov byte [rdi + r13], al` is a byte
        // copy between two places in one region, and matching on the object
        // alone certified it as a round trip and deleted the copy.
        let Some(read) = structured.memory_accesses.values().find(|access| {
            !access.is_write
                && access.provenance_complete
                && access.value == Some(value)
                && access.address == write.address
                && access.object == write.object
                && access.object_offset == write.object_offset
                && access.width == write.width
                && access.block_addr == write.block_addr
                && access.op_index < write.op_index
        }) else {
            continue;
        };
        let overwritten = structured.memory_accesses.values().any(|access| {
            access.is_write
                && access.object == write.object
                && access.block_addr == write.block_addr
                && access.op_index > read.op_index
                && access.op_index < write.op_index
        });
        if overwritten {
            continue;
        }
        // Every later load of the same location the round trip left alone.
        // The search stops at the next write to the object, because after that
        // the location no longer holds what the certified read produced.
        let next_write = structured
            .memory_accesses
            .values()
            .filter(|access| {
                access.is_write
                    && access.object == write.object
                    && access.block_addr == write.block_addr
                    && access.op_index > write.op_index
            })
            .map(|access| access.op_index)
            .min()
            .unwrap_or(usize::MAX);
        let redundant = structured
            .memory_accesses
            .values()
            .filter(|access| {
                !access.is_write
                    && access.provenance_complete
                    && access.address == write.address
                    && access.object == write.object
                    && access.object_offset == write.object_offset
                    && access.width == write.width
                    && access.block_addr == write.block_addr
                    && access.op_index > write.op_index
                    && access.op_index < next_write
            })
            .collect::<Vec<_>>();
        r2il::refusal_evidence!(
            "memory-round-trip",
            "{:?} at {:#x}:{} stores back what {:?} read, so {:?} is unchanged; {} later reads say the same",
            write.id,
            write.block_addr,
            write.op_index,
            read.id,
            write.object,
            redundant.len()
        );
        certificates.insert(
            write.id,
            MemoryRoundTripCertificate {
                write: write.id,
                read: read.id,
                object: write.object,
                block_addr: write.block_addr,
                write_op_index: write.op_index,
                read_op_index: read.op_index,
                redundant_reads: redundant.iter().map(|access| access.id).collect(),
                redundant_read_op_indexes: redundant.iter().map(|access| access.op_index).collect(),
            },
        );
    }
    certificates
}
