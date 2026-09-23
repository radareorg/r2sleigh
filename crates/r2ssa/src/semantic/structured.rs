//! The dataflow facts the structured form is built from.

use super::*;

/// The width one entry of a code pointer run this value carries has, when
/// every one of its bytes comes from such a run.
pub(crate) fn code_pointer_run_stride(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    value: ValueId,
) -> Option<u64> {
    let machine_context = machine_context?;
    let inst = graph.def_inst(value).and_then(|inst| graph.inst(inst))?;
    let InstPayload::Op(SSAOp::Load { space, .. }) = &inst.payload else {
        return None;
    };
    let size = graph.value(value)?.var.size;
    code_pointer_run_bytes(graph, Some(machine_context), inst, *space, size)?;
    Some(u64::from(
        machine_context.memory_model().default_address_bits(),
    ))
}

/// The aggregate a source type identifies, when it is one.
/// How the parts of an object a wide store covers are addressed.
///
/// A struct or union names them; an array numbers them. Both are runs of
/// declared parts, and only the spelling differs, so one store decomposes the
/// same way into either.
pub(crate) enum MemberRunLayout<'a> {
    Aggregate(&'a crate::SourceAggregateLayout),
    Elements {
        stride_bits: u64,
        count: u64,
    },
    /// The object declares no parts, and the value the store carries divides
    /// it: a run of code pointer entries is one address per entry, and the
    /// entry is what states the width.
    Units {
        stride_bits: u64,
    },
}

pub(crate) fn member_run_layout(
    graph: &crate::SourceTypeGraph,
    type_id: u32,
) -> Option<MemberRunLayout<'_>> {
    let ty = graph.types().get(usize::try_from(type_id).ok()?)?;
    match ty.kind() {
        crate::SourceTypeKind::Struct { aggregate_id }
        | crate::SourceTypeKind::Union { aggregate_id } => graph
            .aggregates()
            .get(usize::try_from(aggregate_id).ok()?)
            .filter(|aggregate| aggregate.id() == aggregate_id && aggregate.type_id() == type_id)
            .map(MemberRunLayout::Aggregate),
        crate::SourceTypeKind::Array {
            element_type_id,
            count,
        } => {
            let element = graph.types().get(usize::try_from(element_type_id).ok()?)?;
            let stride_bits = element.size_bits();
            // A stride that is not whole bytes names no element boundary the
            // store's bytes could land on.
            (stride_bits > 0 && stride_bits % 8 == 0)
                .then_some(MemberRunLayout::Elements { stride_bits, count })
        }
        _ => None,
    }
}

/// The members an access of `width_bits` at `offset_bits` covers exactly,
/// each with the bytes of the stored value that land on it.
pub(crate) fn member_run_slices(
    layout: &MemberRunLayout<'_>,
    inst: InstId,
    offset_bits: u64,
    width_bits: u64,
    bytes: &[ByteSource],
    endianness: crate::machine_context::MachineMemoryEndianness,
) -> Option<Vec<MemberRunStoreMember>> {
    use crate::machine_context::MachineMemoryEndianness as Endianness;
    let end_bits = offset_bits.checked_add(width_bits)?;
    let store_bytes = usize::try_from(width_bits / 8).ok()?;
    (bytes.len() == store_bytes).then_some(())?;
    let mut members = Vec::new();
    let mut cursor = offset_bits;
    while cursor < end_bits {
        let (place, size_bits) = match layout {
            MemberRunLayout::Aggregate(aggregate) => {
                let mut at_cursor = aggregate
                    .members()
                    .iter()
                    .filter(|member| member.offset_bits() == cursor && member.size_bits() > 0);
                let member = at_cursor.next()?;
                // Members sharing an offset name the same bytes twice, and
                // nothing here can say which of them the machine meant.
                at_cursor.next().is_none().then_some(())?;
                (
                    MemberRunPlace::Field(member.name().to_string()),
                    member.size_bits(),
                )
            }
            MemberRunLayout::Elements { stride_bits, count } => {
                cursor.is_multiple_of(*stride_bits).then_some(())?;
                let index = cursor / stride_bits;
                (index < *count).then_some(())?;
                (MemberRunPlace::Element(index), *stride_bits)
            }
            MemberRunLayout::Units { stride_bits } => {
                cursor.is_multiple_of(*stride_bits).then_some(())?;
                (
                    MemberRunPlace::Unit {
                        index: cursor / stride_bits,
                        bits: *stride_bits,
                    },
                    *stride_bits,
                )
            }
        };
        let next = cursor.checked_add(size_bits)?;
        if next > end_bits || size_bits % 8 != 0 || size_bits > 64 {
            return None;
        }
        let width = usize::try_from(size_bits / 8).ok()?;
        let memory_offset = usize::try_from(cursor.checked_sub(offset_bits)? / 8).ok()?;
        // The value's bytes that land on the member, least significant first:
        // the lowest addresses hold the lowest bytes on a little-endian
        // machine and the highest on a big-endian one.
        let first = match endianness {
            Endianness::Little => memory_offset,
            Endianness::Big => store_bytes.checked_sub(memory_offset)?.checked_sub(width)?,
            Endianness::Mixed | Endianness::Custom | Endianness::Unknown => return None,
        };
        let slice = bytes.get(first..first.checked_add(width)?)?;
        let source = member_run_source(slice)?;
        members.push(MemberRunStoreMember {
            access: StructuredAccessId {
                inst,
                ordinal: u32::try_from(members.len()).ok()?,
            },
            place,
            offset: cursor / 8,
            width: u32::try_from(width).ok()?,
            source,
        });
        cursor = next;
    }
    (members.len() > 1).then_some(members)
}

pub(crate) fn collect_unstructured_cycle_blocks(
    graph: &SsaGraph,
    loops: &BTreeMap<LoopId, StructuredLoopFact>,
) -> BTreeSet<u64> {
    let covered = loops
        .values()
        .flat_map(|loop_fact| loop_fact.body.iter().copied())
        .collect::<BTreeSet<_>>();
    graph
        .blocks
        .iter()
        .filter(|block| !covered.contains(&block.addr))
        .filter(|block| {
            let mut visited = BTreeSet::new();
            let mut pending = block.successors.clone();
            while let Some(candidate) = pending.pop() {
                if candidate == block.id {
                    return true;
                }
                if !visited.insert(candidate) {
                    continue;
                }
                if let Some(candidate) = graph.block(candidate) {
                    pending.extend(candidate.successors.iter().copied());
                }
            }
            false
        })
        .map(|block| block.addr)
        .collect()
}

pub(crate) fn collect_structured_memory_access_facts(
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    memory: &MemorySSAFacts,
    machine_context: Option<&SourceMachineContext>,
    declared_slots: &DeclaredStackSlots,
) -> (
    BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    BTreeMap<InstId, MemberRunStoreCertificate>,
) {
    let mut access_facts = BTreeMap::new();
    let mut member_run_stores = BTreeMap::new();
    for block in function.blocks() {
        for (op_index, op) in block.ops.iter().enumerate() {
            let Some(inst) = graph.inst_id_for_op_site(block.addr, op_index) else {
                continue;
            };
            let site = AccessSite {
                inst,
                block_addr: block.addr,
                op_index,
            };
            let mut ordinal = 0u32;
            match op {
                SSAOp::Load { dst, addr, space }
                | SSAOp::LoadLinked {
                    dst, addr, space, ..
                }
                | SSAOp::LoadGuarded {
                    dst, addr, space, ..
                } => {
                    if let Some(address) = graph.value_id_for_var(addr) {
                        insert_raw_memory_subeffect(
                            EffectSink {
                                facts: &mut access_facts,
                                ordinal: &mut ordinal,
                            },
                            memory,
                            objects,
                            site,
                            RawAccess {
                                address,
                                space: *space,
                                value: graph.value_id_for_var(dst),
                                is_write: false,
                                width: dst.size,
                            },
                        );
                    }
                }
                SSAOp::Store { addr, val, space }
                | SSAOp::StoreGuarded {
                    addr, val, space, ..
                } => {
                    if let Some(address) = graph.value_id_for_var(addr) {
                        let value = graph.value_id_for_var(val);
                        // A store of a constant across several declared members
                        // is those members' assignments, and each one is an
                        // access of its own for everything downstream.
                        let run = matches!(op, SSAOp::Store { .. })
                            .then(|| {
                                member_run_store(
                                    graph,
                                    objects,
                                    memory,
                                    machine_context,
                                    declared_slots,
                                    site,
                                    RawAccess {
                                        address,
                                        space: *space,
                                        value,
                                        is_write: true,
                                        width: val.size,
                                    },
                                )
                            })
                            .flatten();
                        match run {
                            Some(run) => {
                                for member in &run.members {
                                    insert_raw_member_subeffect(
                                        EffectSink {
                                            facts: &mut access_facts,
                                            ordinal: &mut ordinal,
                                        },
                                        memory,
                                        objects,
                                        site,
                                        RawAccess {
                                            address,
                                            space: *space,
                                            value,
                                            is_write: true,
                                            width: val.size,
                                        },
                                        run.object,
                                        member,
                                    );
                                }
                                member_run_stores.insert(inst, run);
                            }
                            None => insert_raw_memory_subeffect(
                                EffectSink {
                                    facts: &mut access_facts,
                                    ordinal: &mut ordinal,
                                },
                                memory,
                                objects,
                                site,
                                RawAccess {
                                    address,
                                    space: *space,
                                    value,
                                    is_write: true,
                                    width: val.size,
                                },
                            ),
                        }
                    }
                }
                SSAOp::StoreConditional {
                    addr, val, space, ..
                } => {
                    if let Some(address) = graph.value_id_for_var(addr) {
                        insert_raw_memory_subeffect(
                            EffectSink {
                                facts: &mut access_facts,
                                ordinal: &mut ordinal,
                            },
                            memory,
                            objects,
                            site,
                            RawAccess {
                                address,
                                space: *space,
                                value: None,
                                is_write: false,
                                width: val.size,
                            },
                        );
                        insert_raw_memory_subeffect(
                            EffectSink {
                                facts: &mut access_facts,
                                ordinal: &mut ordinal,
                            },
                            memory,
                            objects,
                            site,
                            RawAccess {
                                address,
                                space: *space,
                                value: graph.value_id_for_var(val),
                                is_write: true,
                                width: val.size,
                            },
                        );
                    }
                }
                SSAOp::AtomicCAS(swap) => {
                    let (dst, addr, replacement, space) =
                        (&swap.dst, &swap.addr, &swap.replacement, swap.space);
                    if let Some(address) = graph.value_id_for_var(addr) {
                        insert_raw_memory_subeffect(
                            EffectSink {
                                facts: &mut access_facts,
                                ordinal: &mut ordinal,
                            },
                            memory,
                            objects,
                            site,
                            RawAccess {
                                address,
                                space,
                                value: graph.value_id_for_var(dst),
                                is_write: false,
                                width: replacement.size,
                            },
                        );
                        insert_raw_memory_subeffect(
                            EffectSink {
                                facts: &mut access_facts,
                                ordinal: &mut ordinal,
                            },
                            memory,
                            objects,
                            site,
                            RawAccess {
                                address,
                                space,
                                value: graph.value_id_for_var(replacement),
                                is_write: true,
                                width: replacement.size,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }
    (access_facts, member_run_stores)
}

/// The declared members a wide constant store writes, one assignment each.
///
/// C has no scalar as wide as the store, and the layout says which members its
/// bytes are, so each member takes its own slice of the proven constant.
pub(crate) fn member_run_store(
    graph: &SsaGraph,
    objects: &ObjectModel,
    memory: &MemorySSAFacts,
    machine_context: Option<&SourceMachineContext>,
    declared_slots: &DeclaredStackSlots,
    site: AccessSite,
    store: RawAccess,
) -> Option<MemberRunStoreCertificate> {
    let value = store.value?;
    let AccessSite {
        inst,
        block_addr,
        op_index,
    } = site;
    let (address, space, width) = (store.address, store.space, store.width);
    if space != SpaceId::Ram || width == 0 {
        return None;
    }
    let type_graph = machine_context
        .and_then(SourceMachineContext::function_interface)
        .and_then(|interface| interface.type_graph())?;
    let provenance = raw_memory_subeffect_provenance(memory, objects, inst, store);
    if !provenance.complete {
        return None;
    }
    let offset_bits = u64::try_from(provenance.object_offset.filter(|offset| *offset >= 0)?)
        .ok()?
        .checked_mul(8)?;
    let (base, slot_offset) = match objects.object(provenance.object)?.kind {
        ObjectKind::StackSlot { base, offset, .. }
        | ObjectKind::FrameObject { base, offset, .. } => (base, offset),
        _ => return None,
    };
    let bytes = value_byte_sources(graph, machine_context, value)?;
    // What the object declares divides it; where it declares nothing, the
    // run of entries the store carries does.
    let layout = declared_slots
        .by_key
        .get(&(base, slot_offset))
        .and_then(SourceStackSlotSpec::logical_type)
        .and_then(|type_id| member_run_layout(type_graph, type_id))
        .or_else(|| {
            code_pointer_run_stride(graph, machine_context, value)
                .map(|stride_bits| MemberRunLayout::Units { stride_bits })
        })?;
    let members = member_run_slices(
        &layout,
        inst,
        offset_bits,
        u64::from(width).saturating_mul(8),
        &bytes,
        machine_context
            .map(|context| context.memory_model().default_endianness())
            .unwrap_or(crate::machine_context::MachineMemoryEndianness::Unknown),
    )?;
    // A lane is the member's whole value only when it is exactly as wide.
    for member in &members {
        if let MemberRunSource::Lane(lane) = member.source
            && graph.value(lane).map(|value| value.var.size) != Some(member.width)
        {
            return None;
        }
    }
    // The lifted store reads its address then its value, and the ledger needs
    // the exact operand it is about to call unrendered.
    let input_idx = graph
        .inst(inst)?
        .inputs
        .iter()
        .position(|input| *input == value)?;
    Some(MemberRunStoreCertificate {
        inst,
        block_addr,
        op_index,
        object: provenance.object,
        address,
        value,
        value_use: UseSite { inst, input_idx },
        members,
    })
}

/// One member's own write, carrying the whole store's proven provenance.
pub(crate) fn insert_raw_member_subeffect(
    sink: EffectSink<'_>,
    memory: &MemorySSAFacts,
    objects: &ObjectModel,
    site: AccessSite,
    store: RawAccess,
    object: ObjectId,
    member: &MemberRunStoreMember,
) {
    let (address, space) = (store.address, store.space);
    let provenance = raw_memory_subeffect_provenance(memory, objects, site.inst, store);
    insert_structured_memory_access(
        sink,
        site,
        RawAccess {
            address,
            space,
            value: match member.source {
                MemberRunSource::Constant(_) => None,
                MemberRunSource::Lane(value) => Some(value),
            },
            is_write: true,
            width: member.width,
        },
        object,
        provenance.complete,
        i64::try_from(member.offset).ok(),
    );
}

pub(crate) fn collect_structured_recursive_call_facts(
    function: &SSAFunction,
    graph: &SsaGraph,
    call_sites: &CallSiteFacts,
) -> BTreeMap<CallSiteId, StructuredRecursiveCallFact> {
    let mut recursive_calls = BTreeMap::new();
    for (call_site, fact) in &call_sites.by_id {
        let Some(target) = fact.direct_target else {
            continue;
        };
        if target != function.entry {
            continue;
        }
        let Some((block_addr, op_index)) = graph.op_site_for_inst(fact.at) else {
            continue;
        };
        recursive_calls.insert(
            *call_site,
            StructuredRecursiveCallFact {
                call_site: *call_site,
                block_addr,
                op_index,
                target,
            },
        );
    }
    recursive_calls
}
