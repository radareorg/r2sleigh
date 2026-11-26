//! What the body proves about what it returns and how it leaves.

use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnValueCertificate {
    pub at: InstId,
    /// The value returned, or a pair's low half.
    pub value: ValueId,
    /// A pair's high half, where `carrier` is a pair.
    pub high: Option<ValueId>,
    pub width: u32,
    pub carrier: Option<ReturnCarrier>,
    /// Exact logical return projection declared by the immutable source
    /// interface. `None` preserves the physical ABI-carrier behavior for
    /// interfaces that carry no logical type graph.
    pub source_logical_value: Option<SourceLogicalValue>,
}

#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
    )
)]
pub(crate) fn collect_machine_return_control_certificates(
    boundaries: &SourceBoundaryFacts,
    graph: &SsaGraph,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    unobserved: &crate::deadphi::DeadPhis,
) -> MachineReturnControls {
    let mut certificates = crate::dense::IdMap::default();
    let mut by_inst = crate::dense::IdMap::default();
    for (at, boundary) in &boundaries.returns {
        let Some(return_address) = boundary.return_address else {
            continue;
        };
        let Some(return_inst) = graph.inst(at) else {
            continue;
        };
        if graph.inputs(return_inst.id).first() != Some(&return_address.value)
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
        while let Some(inst) = graph.def_inst(current) {
            let Some(definition) = graph.inst(inst) else {
                complete = false;
                break;
            };
            match &definition.payload {
                InstPayload::Op(SSAOp::Copy { dst, src }) => {
                    let source = *src;
                    if definition.output != Some(current)
                        || graph.inputs(definition.id) != [source]
                        || graph.var(*dst).size != return_address.storage.size
                        || graph.var(source).size != return_address.storage.size
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
                        .accesses_at(inst)
                        .filter(|access| {
                            !access.is_write
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
                        || graph.var(*dst).size != return_address.storage.size
                        || definition.output != Some(current)
                        || graph.inputs(definition.id) != [access.address]
                        || !insts.insert(inst)
                    {
                        complete = false;
                        break;
                    }
                    reload_object = Some(access.object);
                    // The slot's one write saves the entry return address and its one read is this
                    // reload: one fact about control, so this certificate claims the save too.
                    let pair = match structured.access_ids_of(access.object) {
                        [first, second] => structured
                            .memory_accesses
                            .get(first)
                            .zip(structured.memory_accesses.get(second)),
                        _ => None,
                    };
                    let save =
                        pair.and_then(|(first, second)| match (first.is_write, second.is_write) {
                            (true, false) => Some((first, second)),
                            (false, true) => Some((second, first)),
                            _ => None,
                        });
                    if let Some((store, only_read)) = save
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
            inst: at,
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
                .any(|inst| !absorbed.contains(inst) && by_inst.contains(*inst))
        {
            continue;
        }
        let uses = insts
            .iter()
            .flat_map(|inst| {
                graph.inst(*inst).into_iter().flat_map(move |definition| {
                    (0..graph.inputs(definition.id).len()).map(move |input_idx| UseSite {
                        inst: *inst,
                        input_idx,
                    })
                })
            })
            .collect::<BTreeSet<_>>();
        let certificate = MachineReturnControlCertificate {
            at,
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
            by_inst.insert(*inst, at);
        }
        certificates.insert(at, certificate);
    }
    let objects = (certificates.values())
        .filter_map(MachineReturnControlCertificate::claimed_stack_object)
        .collect();
    MachineReturnControls {
        certificates,
        by_inst,
        objects,
    }
}

/// The body's return controls, the instructions each claims, and the stack objects they claim.
pub(crate) struct MachineReturnControls {
    pub(crate) certificates: crate::dense::IdMap<InstId, MachineReturnControlCertificate>,
    pub(crate) by_inst: crate::dense::IdMap<InstId, InstId>,
    pub(crate) objects: crate::dense::IdSet<ObjectId>,
}

pub(crate) fn collect_return_value_certificates(
    boundaries: &SourceBoundaryFacts,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    stack_reloads: &crate::dense::IdMap<ValueId, StackReloadSourceCertificate>,
) -> (
    Vec<ReturnValueCertificate>,
    crate::dense::IdMap<InstId, usize>,
) {
    let mut returns = Vec::new();
    let mut returns_by_inst = crate::dense::IdMap::default();

    for (boundary_at, boundary) in &boundaries.returns {
        if boundary.at != boundary_at || !boundary.complete {
            r2il::refusal_evidence!(
                "return-certificate",
                "{:?}: at_mismatch={} incomplete={}",
                boundary_at,
                boundary.at != boundary_at,
                !boundary.complete
            );
            continue;
        }
        let Some(inst) = graph.inst(boundary.at) else {
            continue;
        };
        if !matches!(inst.payload, InstPayload::Op(SSAOp::Return { .. })) {
            continue;
        }
        if let Some(certificate) = pair_certificate(boundary, machine_context) {
            returns_by_inst.insert(boundary.at, returns.len());
            returns.push(certificate);
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
                value,
                high: None,
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

/// A pair return's certificate: the boundary's value in each of the interface's two registers,
/// typed by its logical value as one integer of both widths.
fn pair_certificate(
    boundary: &crate::semantic::SourceReturnBoundaryFact,
    machine_context: Option<&SourceMachineContext>,
) -> Option<ReturnValueCertificate> {
    let interface = machine_context?.function_interface()?;
    let SourceFunctionReturn::Pair { low, high } = interface.return_kind() else {
        return None;
    };
    let logical = interface.return_logical_value()?;
    let bits = u64::from(low.size + high.size).checked_mul(8)?;
    if logical.carrier().kind() != r2source::SourceCarrierKind::Full
        || logical.carrier().size_bits() != bits
    {
        return None;
    }
    let half = |storage: CanonicalStorageId| {
        (boundary.values.iter()).find_map(|value| match value.slot {
            CallBoundarySlot::Register { storage: slot, .. } if slot == storage => {
                Some(value.value)
            }
            _ => None,
        })
    };
    Some(ReturnValueCertificate {
        at: boundary.at,
        value: half(low)?,
        high: Some(half(high)?),
        width: low.size + high.size,
        carrier: Some(ReturnCarrier::Pair { low, high }),
        source_logical_value: Some(logical),
    })
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
        // The value the walk reached is the carrier's own, or one with no register of its own: a
        // temporary, a literal or a promoted frame slot (clang -O0's `movsd xmm0, [rbp-24]`).
        SourceCarrierKind::Full
            if projection.size_bits() == physical_bits
                && physical_value.var.size == storage.size
                && physical_value.canonical_storage.is_none_or(|reached| {
                    reached == storage
                        || matches!(
                            reached.space,
                            CanonicalStorageSpace::Unique | CanonicalStorageSpace::Constant
                        )
                        || reached.space
                            == CanonicalStorageSpace::Custom(
                                crate::slot_promotion::PROMOTED_SLOT_SPACE,
                            )
                }) =>
        {
            Some((boundary.value, storage.size, Some(logical)))
        }
        // The slot is the low lane of the root the value defines (a double in
        // XMM0_Qa reached as XMM0): the lane at the slot's width, as below.
        SourceCarrierKind::Full
            if physical_value.var.size > storage.size
                && physical_value
                    .canonical_storage
                    .zip(machine_context)
                    .is_some_and(|(root, context)| context.is_low_lane_of(storage, root)) =>
        {
            let input = exact_logical_lane_input(graph, boundary.value, storage.size);
            Some((input.unwrap_or(boundary.value), storage.size, Some(logical)))
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
            if let Some(input) = exact_logical_lane_input(graph, boundary.value, logical_width) {
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

/// The value whose bytes are the carrier's low `logical_width` bytes,
/// exactly: the lane an extension widens, or one an insert writes at the
/// carrier's low end, followed down while that lane is still wider.
///
/// The low bytes of `zext(x)`, of `sext(x)` and of an insert of `x` at
/// position zero are the low bytes of `x` for any width up to `x`'s, so the
/// walk ends at a value exactly as wide as the logical return, or at the
/// first definition that is none of these. `movzx eax, al` then a 32-bit
/// write's zero extension is two steps from `RAX` to `AL`.
///
/// Returns `None` for every other shape, including a merge, so the caller can
/// go on to ask the wider question rather than refusing here.
pub(crate) fn exact_logical_lane_input(
    graph: &SsaGraph,
    carrier: ValueId,
    logical_width: u32,
) -> Option<ValueId> {
    let mut at = carrier;
    loop {
        let value = graph.value(at)?;
        if value.var.size == logical_width && at != carrier {
            return Some(at);
        }
        let producer = graph.def_inst(at).and_then(|id| graph.inst(id))?;
        if producer.output != Some(at) {
            return None;
        }
        let (lane, lane_var) = match (&producer.payload, graph.inputs(producer.id)) {
            (
                InstPayload::Op(SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src }),
                [input],
            ) if *dst == value.id => (*input, *src),
            (InstPayload::Op(SSAOp::Insert(insert)), [_, input, _])
                if insert.dst == value.id
                    && graph.var(insert.position).constant_bits() == Some(0) =>
            {
                (*input, insert.value)
            }
            _ => return None,
        };
        let lane_value = graph.value(lane)?;
        if lane != lane_var || lane_value.var.size < logical_width {
            return None;
        }
        at = lane;
    }
}

pub(crate) fn return_carrier_for_boundary_value(
    boundary: &CallBoundaryValueFact,
    stack_reloads: &crate::dense::IdMap<ValueId, StackReloadSourceCertificate>,
) -> Option<ReturnCarrier> {
    match boundary.slot {
        CallBoundarySlot::Register { .. } => return_carrier_for_boundary_slot(boundary.slot),
        CallBoundarySlot::Stack(offset) => {
            let reload = stack_reloads
                .get(boundary.value)
                .filter(|reload| reload.relation == crate::view::ViewRelation::Identity)?;
            (reload.offset == offset).then_some(ReturnCarrier::StackSlot {
                object: reload.object,
                offset: reload.offset,
                memory_access: Some(reload.load_access),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MachineReturnControlCertificate;
    use crate::{CanonicalStorageId, CanonicalStorageSpace, SourceMachineRoles, SsaArtifact};
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    const RA: u64 = 16;
    const SP: u64 = 32;

    fn arch() -> crate::Arch {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("rdi", 8, 8));
        arch.add_register(RegisterDef::new("rip", RA, 8));
        arch.add_register(RegisterDef::new("rsp", SP, 8));
        crate::Arch::from(arch)
    }

    fn register(offset: u64) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        }
    }

    fn roles() -> SourceMachineRoles {
        SourceMachineRoles::new(Some(register(RA)), Some(register(SP))).expect("machine roles")
    }

    /// Calls keep the stack pointer and return in `rax`.
    fn conventions() -> r2source::Conventions {
        r2source::convention::testing::model(r2source::ConventionId::SysVAmd64)
            .result(r2source::convention::SlotClass::Integer, register(0))
            .preserved([register(SP)])
            .conventions()
    }

    /// `[sp + offset] = value`, the address in a temporary of this block.
    fn store(block: &mut R2ILBlock, offset: u64, value: Varnode) {
        let address = Varnode::unique(0x100 + offset, 8);
        block.push(R2ILOp::IntAdd {
            dst: address.clone(),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(offset, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: address,
            val: value,
        });
    }

    /// Saves the return address at `[sp + 8]` and one local per return, calls an unbounded
    /// function; each of `returns` returns loads its local into `rax` and reloads the save.
    fn saved_return_body(returns: u64) -> Vec<R2ILBlock> {
        let frame = 16 + 8 * returns;
        let test_at = |index: u64| 0x2000 + 0x10 * index;
        let return_at = |index: u64| 0x8000 + 0x10 * index;
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::IntSub {
            dst: Varnode::register(SP, 8),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(frame, 8),
        });
        store(&mut entry, 8, Varnode::register(RA, 8));
        for index in 0..returns {
            store(&mut entry, 16 + 8 * index, Varnode::constant(index, 8));
        }
        // The call may write the frame, so every store stays one.
        entry.push(R2ILOp::Call {
            target: Varnode::constant(0x5000, 8),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::constant(test_at(0), 8),
        });
        let mut blocks = vec![entry];
        // Each test falls through to the next, the last to the first return.
        for index in 0..returns {
            let mut test = R2ILBlock::new(test_at(index), 0x10);
            let taken = Varnode::unique(0x50, 1);
            test.push(R2ILOp::IntEqual {
                dst: taken.clone(),
                a: Varnode::register(8, 8),
                b: Varnode::constant(index, 8),
            });
            test.push(R2ILOp::CBranch {
                target: Varnode::constant(return_at(index), 8),
                cond: taken,
            });
            blocks.push(test);
        }
        let mut last = R2ILBlock::new(test_at(returns), 4);
        last.push(R2ILOp::Branch {
            target: Varnode::constant(return_at(0), 8),
        });
        blocks.push(last);
        for index in 0..returns {
            let mut leave = R2ILBlock::new(return_at(index), 4);
            load(&mut leave, 16 + 8 * index, Varnode::register(0, 8));
            load(&mut leave, 8, Varnode::register(RA, 8));
            leave.push(R2ILOp::IntAdd {
                dst: Varnode::register(SP, 8),
                a: Varnode::register(SP, 8),
                b: Varnode::constant(frame, 8),
            });
            leave.push(R2ILOp::Return {
                target: Varnode::register(RA, 8),
            });
            blocks.push(leave);
        }
        blocks
    }

    /// `dst = [sp + offset]`, the address in a temporary of this block.
    fn load(block: &mut R2ILBlock, offset: u64, dst: Varnode) {
        let address = Varnode::unique(0x100 + offset, 8);
        block.push(R2ILOp::IntAdd {
            dst: address.clone(),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(offset, 8),
        });
        block.push(R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr: address,
        });
    }

    fn artifact(blocks: &[R2ILBlock]) -> SsaArtifact {
        SsaArtifact::for_decompile_with(
            blocks,
            crate::function::DecompileInputs {
                arch: Some(&arch()),
                machine_roles: roles(),
                conventions: Some(conventions()),
                ..Default::default()
            },
        )
        .expect("artifact")
    }

    /// Recovery collects the return controls alone; over the same body the objects they claim are
    /// the set the whole collection states, and the save answers as frame management (D422).
    #[test]
    fn the_return_controls_arm_states_the_objects_its_controls_claim() {
        let whole = artifact(&saved_return_body(1));
        let claimed = |controls: &crate::dense::IdMap<_, MachineReturnControlCertificate>| {
            (controls.values())
                .filter_map(MachineReturnControlCertificate::claimed_stack_object)
                .collect::<Vec<_>>()
        };
        let stated = claimed(&whole.certificates().machine_return_controls);
        assert_eq!(stated.len(), 1, "the save is claimed");
        let recovery = crate::semantic::PreparedFunctionFacts::collect_for_recovery(
            whole.function(),
            (Some(whole.decompile_prep_facts()), whole.graph()),
            whole.machine_context(),
            None,
        )
        .expect("an unchecked control never stops");
        let certificates = &recovery.certificates;
        assert_eq!(claimed(&certificates.machine_return_controls), stated);
        assert_eq!(
            certificates
                .return_control_objects
                .iter()
                .collect::<Vec<_>>(),
            stated
        );
        assert!(whole.frame_managed_stack_object(stated[0]));
        assert!(!whole.declarable_stack_object(stated[0]));
    }

    /// The element visits of asking, of a body with `returns` returns, whether each of its
    /// objects is declarable.
    #[cfg(feature = "work-meter")]
    fn declarable_visits(returns: u64) -> u64 {
        let artifact = artifact(&saved_return_body(returns));
        let objects = artifact.objects().objects.keys();
        assert!(
            artifact.objects().objects.len() as u64 > returns,
            "one question per local"
        );
        let here = || crate::dense::element_visits_on_this_thread().expect("a work-meter build");
        let before = here();
        let declarable =
            (objects.filter(|object| artifact.declarable_stack_object(**object))).count();
        let visits = here() - before;
        assert!(declarable as u64 >= returns, "each local is declarable");
        visits
    }

    /// A question about one object reads that object's facts: doubling the returns and locals
    /// at most doubles the visits the questions make (D422).
    #[cfg(feature = "work-meter")]
    #[test]
    fn declarable_questions_grow_linearly_with_the_returns() {
        let (once, twice) = (declarable_visits(64), declarable_visits(128));
        assert!(
            twice as f64 <= 2.05 * once as f64,
            "{once} visits at 64 returns, {twice} at 128"
        );
    }
}
