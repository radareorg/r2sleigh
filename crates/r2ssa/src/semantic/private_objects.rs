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
    for write in structured.memory_accesses.values() {
        if !write.is_write || !write.provenance_complete {
            continue;
        }
        let Some((write_block, write_at)) = place(write) else {
            continue;
        };
        let in_write_block = |access: &crate::semantic::StructuredMemoryAccessFact| {
            place(access)
                .filter(|(block, _)| *block == write_block)
                .map(|(_, at)| at)
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
        let Some(read) = structured.memory_accesses.values().find(|access| {
            !access.is_write
                && access.provenance_complete
                && access.value == Some(value)
                && access.address == write.address
                && access.object == write.object
                && access.object_offset == write.object_offset
                && access.width == write.width
                && in_write_block(access).is_some_and(|at| at < write_at)
        }) else {
            continue;
        };
        let Some(read_at) = in_write_block(read) else {
            continue;
        };
        let overwritten = structured.memory_accesses.values().any(|access| {
            access.is_write
                && access.object == write.object
                && in_write_block(access).is_some_and(|at| at > read_at && at < write_at)
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
            .filter(|access| access.is_write && access.object == write.object)
            .filter_map(in_write_block)
            .filter(|at| *at > write_at)
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
                    && in_write_block(access).is_some_and(|at| at > write_at && at < next_write)
            })
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
