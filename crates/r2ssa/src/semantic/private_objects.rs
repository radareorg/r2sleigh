//! Frame objects nothing outside the function can observe.

use super::*;

/// Frame objects no address of which leaves the function: the one escape analysis, `FrameReach` (doc/adr-frame-model.md).
pub(crate) fn private_stack_objects(objects: &ObjectModel) -> BTreeSet<ObjectId> {
    if objects.frame_reach.whole() {
        return BTreeSet::new();
    }
    let frame = objects.objects.iter().filter(|(_, fact)| {
        matches!(
            fact.kind,
            ObjectKind::StackSlot {
                space: SpaceId::Ram,
                ..
            } | ObjectKind::FrameObject {
                space: SpaceId::Ram,
                ..
            }
        )
    });
    let private = frame.filter(|(object, _)| !objects.frame_reach.escaped(**object));
    private.map(|(object, _)| *object).collect()
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
    // Where an access stands: its instruction's block and place in the
    // graph's order of that block.
    let place = |access: &crate::semantic::StructuredMemoryAccessFact| {
        graph
            .inst(access.id.inst)
            .map(|inst| (inst.block, inst.ordinal))
    };
    // Indexed once, so each write asks in O(log n) (doc/adr-frame-model.md, H):
    // the exact reads of each location in its block, and the writes of each object.
    type Location = (crate::graph::BlockId, ValueId, ObjectId, Option<i64>, u32);
    let mut reads = BTreeMap::<Location, Vec<(usize, &StructuredMemoryAccessFact)>>::new();
    let mut writes = BTreeMap::<(crate::graph::BlockId, ObjectId), Vec<usize>>::new();
    // The earliest read of each location that loaded each value: the read a round trip pairs with.
    let mut first_read = BTreeMap::<(Location, ValueId), (usize, StructuredAccessId)>::new();
    for access in structured.memory_accesses.values() {
        let Some((block, at)) = place(access) else {
            continue;
        };
        if access.is_write {
            writes.entry((block, access.object)).or_default().push(at);
        } else if access.provenance_complete {
            let location = (
                block,
                access.address,
                access.object,
                access.object_offset,
                access.width,
            );
            if let Some(value) = access.value {
                let earliest = first_read
                    .entry((location, value))
                    .or_insert((at, access.id));
                *earliest = (*earliest).min((at, access.id));
            }
            reads.entry(location).or_default().push((at, access));
        }
    }
    for list in writes.values_mut() {
        list.sort_unstable();
    }
    for list in reads.values_mut() {
        list.sort_by_key(|(at, access)| (*at, access.id));
    }
    for write in structured.memory_accesses.values() {
        if !write.is_write || !write.provenance_complete {
            continue;
        }
        let Some((write_block, write_at)) = place(write) else {
            continue;
        };
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
        let location = (
            write_block,
            write.address,
            write.object,
            write.object_offset,
            write.width,
        );
        let same = reads.get(&location).map_or(&[][..], Vec::as_slice);
        let Some(&(read_at, read_id)) = first_read
            .get(&(location, value))
            .filter(|(at, _)| *at < write_at)
        else {
            continue;
        };
        let Some(read) = structured.memory_accesses.get(&read_id) else {
            continue;
        };
        let object_writes = writes
            .get(&(write_block, write.object))
            .map_or(&[][..], Vec::as_slice);
        let after_read = object_writes.partition_point(|at| *at <= read_at);
        if object_writes
            .get(after_read)
            .is_some_and(|at| *at < write_at)
        {
            continue;
        }
        // Every later load of the same location the round trip left alone.
        // The search stops at the next write to the object, because after that
        // the location no longer holds what the certified read produced.
        let next_write = object_writes
            .get(object_writes.partition_point(|at| *at <= write_at))
            .copied()
            .unwrap_or(usize::MAX);
        let redundant = same[same.partition_point(|(at, _)| *at <= write_at)..]
            .iter()
            .take_while(|(at, _)| *at < next_write)
            .map(|(_, access)| *access)
            .collect::<Vec<_>>();
        r2il::refusal_evidence!(
            "memory-round-trip",
            "{:?} stores back what {:?} read, so {:?} is unchanged; {} later reads say the same",
            write.id,
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
                redundant_reads: redundant.iter().map(|access| access.id).collect(),
            },
        );
    }
    certificates
}
