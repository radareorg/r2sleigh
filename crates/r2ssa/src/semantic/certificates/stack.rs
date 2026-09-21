//! What the frame proves: its geometry, its round trips, its reloads.

use super::super::*;

/// Upstream decision for declaring one indexed stack object as an array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackArrayLayoutDisposition {
    /// No prepared access reaches this object through an indexed address.
    NotIndexed,
    /// Every access agrees on the element width and the index graph contains
    /// an exact non-negative constant establishing the last byte offset.
    Proven(StackArrayLayoutCertificate),
    /// The object is indexed, but the exact geometry required by C was absent.
    Refused(StackArrayLayoutRefusal),
}

/// Exact byte geometry of one indexed stack object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackArrayLayoutCertificate {
    pub object: ObjectId,
    pub element_width: u32,
    pub stride: u32,
    pub maximum_constant_offset: u64,
    pub extent: u64,
    /// The complete stable set of indexed addresses reaching this object and
    /// the exact element index, when the byte scale can be removed without an
    /// invented expression.
    pub indexed_elements: Box<[StackArrayElementCertificate]>,
}

/// Exact index spelling for one access to a certified stack array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackArrayElementCertificate {
    pub address: ValueId,
    pub byte_offset: ValueId,
    pub element_index: Option<StackArrayElementIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackArrayElementIndex {
    Value(ValueId),
    Constant(u64),
}

/// Why an indexed stack object deliberately remained scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackArrayLayoutRefusal {
    IncompleteAccessProvenance,
    ConflictingAccessWidths,
    MissingConstantOffset,
    InvalidExtent,
    DisplacedIndexBase,
    /// Two accesses step through the object by different amounts, so it has
    /// no one element size.
    ConflictingStrides,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalleeStackAllocationCertificate {
    pub object: ObjectId,
    pub entry_offset: i64,
    pub size_bytes: u32,
    /// Every prepared access to this object, in stable access-id order.
    pub accesses: Box<[StructuredAccessId]>,
    /// Exact entry-SP-relative active stack-pointer offsets observed at those
    /// accesses. Repeated offsets are canonicalized away.
    pub active_sp_offsets: Box<[i64]>,
    /// True when the proof uses source-declared implicit storage beyond the
    /// active SP. Such a certificate is issued only for a call-free function.
    pub uses_implicit_area: bool,
    /// The size is the reach of the accesses rather than an element layout,
    /// so the object declares as bytes.
    pub byte_array: bool,
}

/// Exact proof that one anonymous callee-owned stack object is only a
/// save/reload carrier for entry machine state.
///
/// `insts` is the complete sorted operation domain removed by a consumer: the
/// same-width copy chain from the entry frame pointer into the store, the
/// store itself, every reload, and each reload's same-width copy chain back to
/// the exact entry storage. The collector issues this only when every value in
/// those chains has no observed use outside this domain -- a use no program
/// observation depends on, per [`crate::deadphi::DeadPhis`], is not a read the
/// program makes -- the object has no other access,
/// and the storage owns no parameter, result, call-boundary, stack-pointer, or
/// return-control role. Consumers therefore project an upstream disposition;
/// they never recognize prologue or epilogue syntax themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrameRoundTripCertificate {
    pub object: ObjectId,
    pub storage: CanonicalStorageId,
    pub entry_value: ValueId,
    pub store_access: StructuredAccessId,
    pub load_accesses: Box<[StructuredAccessId]>,
    pub insts: Box<[InstId]>,
    pub values: Box<[ValueId]>,
}

/// Closed graph domain used only to form certified stack addresses.
///
/// The collector computes the greatest set whose uses stay within pure
/// stack-root copy/add/sub operations, equal-root merge phis, exact stack-object
/// address operands, or separately certified frame save/reload operations. Any
/// call, return-value, comparison, ordinary arithmetic, or other escaping use
/// removes the value and every dependent computation from this certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackGeometryCertificate {
    pub insts: BTreeSet<InstId>,
    pub values: BTreeSet<ValueId>,
    pub uses: BTreeSet<UseSite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackCallArgumentCertificate {
    pub stack_offset: i64,
    pub value: ValueId,
    pub memory_access: StructuredAccessId,
}

pub(crate) fn exact_stack_pointer_offset(
    function: &SSAFunction,
    graph: &SsaGraph,
    state: ReachingStorageState,
) -> Option<i64> {
    match state {
        ReachingStorageState::PreservedEntry => Some(0),
        ReachingStorageState::Value(value) => graph
            .value(value)
            .and_then(|value| resolve_entry_stack_root(function.decompile_prep_facts(), &value.var))
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset),
        ReachingStorageState::Unknown | ReachingStorageState::Conflict => None,
    }
}

pub(crate) fn checked_ranges_overlap(
    left_offset: i64,
    left_size: u32,
    right_offset: i64,
    right_size: u32,
) -> bool {
    let Some(left_end) = left_offset.checked_add(i64::from(left_size)) else {
        return true;
    };
    let Some(right_end) = right_offset.checked_add(i64::from(right_size)) else {
        return true;
    };
    left_offset < right_end && right_offset < left_end
}

pub(crate) fn collect_callee_stack_allocation_certificates(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    exact_stack_slots: &BTreeMap<(StackAddressBase, i64), SourceStackSlotSpec>,
    sizing: &AllocationSizing<'_>,
) -> BTreeMap<ObjectId, CalleeStackAllocationCertificate> {
    let AllocationSizing {
        array_layouts,
        values,
    } = sizing;
    let Some(machine_context) = machine_context else {
        return BTreeMap::new();
    };
    let roles = machine_context.machine_roles();
    let (Some(stack_pointer), Some(contract)) = (
        roles.stack_pointer_storage(),
        roles.stack_allocation_contract(),
    ) else {
        return BTreeMap::new();
    };
    let contains_call = function.blocks().iter().any(|block| {
        block.ops.iter().any(|op| {
            matches!(
                op,
                SSAOp::Call { .. } | SSAOp::CallInd { .. } | SSAOp::CallOther { .. }
            )
        })
    });
    let explicit_contract = SourceStackAllocationContract::new(contract.growth());
    let active_stack_pointer_states =
        reaching_storage_states_before(function, graph, stack_pointer);
    let mut candidates = BTreeMap::new();

    for (object, fact) in &objects.objects {
        let (space, base, offset) = match fact.kind {
            ObjectKind::StackSlot {
                space,
                base,
                offset,
            }
            | ObjectKind::FrameObject {
                space,
                base,
                offset,
            } => (space, base, offset),
            ObjectKind::Parameter { .. }
            | ObjectKind::Global { .. }
            | ObjectKind::HeapAlloc { .. }
            | ObjectKind::EscapedUnknown { .. }
            | ObjectKind::Pointee { .. } => continue,
        };
        // A slot debug information declares, or a parameter's, is the
        // program's; a local radare2 inferred from the body's accesses is
        // evidence, and a frame save it named is still a frame save.
        if space != SpaceId::Ram
            || exact_stack_slots.get(&(base, offset)).is_some_and(|slot| {
                slot.declared_by_debug_info() || !matches!(slot.role(), SourceStackSlotRole::Local)
            })
        {
            continue;
        }
        let Some(entry_root) = objects.entry_stack_roots.get(object).copied() else {
            continue;
        };
        if entry_root.base != StackAddressBase::StackPointer {
            continue;
        }
        let accesses = structured
            .memory_accesses
            .values()
            .filter(|access| access.object == *object)
            .collect::<Vec<_>>();
        let Some(first) = accesses.first() else {
            continue;
        };
        let element_width = first.width;
        if element_width == 0
            || accesses.iter().any(|access| {
                access.width != element_width
                    || !access.provenance_complete
                    || !ram_memory_access_matches_source(function, graph, objects, access)
            })
        {
            continue;
        }
        // Without an element layout the object is still as large as its
        // accesses reach; only where nothing bounds them is it one element.
        let (size_bytes, byte_array) = match array_layouts.get(object) {
            Some(StackArrayLayoutDisposition::Proven(layout)) => {
                let Ok(extent) = u32::try_from(layout.extent) else {
                    continue;
                };
                (extent, false)
            }
            Some(StackArrayLayoutDisposition::NotIndexed)
            | Some(StackArrayLayoutDisposition::Refused(_))
            | None => accessed_object_storage(graph, values, objects, structured, *object)
                .unwrap_or((element_width, false)),
        };

        let mut active_sp_offsets = BTreeSet::new();
        let mut uses_implicit_area = false;
        let mut complete = true;
        for access in &accesses {
            let Some(active_sp_offset) = active_stack_pointer_states
                .get(&access.id.inst)
                .copied()
                .and_then(|state| exact_stack_pointer_offset(function, graph, state))
            else {
                complete = false;
                break;
            };
            if !contract.owns_entry_relative_range(active_sp_offset, entry_root.offset, size_bytes)
            {
                complete = false;
                break;
            }
            if !explicit_contract.owns_entry_relative_range(
                active_sp_offset,
                entry_root.offset,
                size_bytes,
            ) {
                uses_implicit_area = true;
            }
            active_sp_offsets.insert(active_sp_offset);
        }
        if !complete || uses_implicit_area && contains_call {
            continue;
        }
        candidates.insert(
            *object,
            CalleeStackAllocationCertificate {
                object: *object,
                entry_offset: entry_root.offset,
                size_bytes,
                accesses: accesses
                    .into_iter()
                    .map(|access| access.id)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                active_sp_offsets: active_sp_offsets
                    .into_iter()
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                uses_implicit_area,
                byte_array,
            },
        );
    }

    candidates.retain(|object, certificate| {
        !objects.objects.iter().any(|(other_object, other_fact)| {
            if other_object == object {
                return false;
            }
            let Some(other_root) = objects.entry_stack_roots.get(other_object) else {
                return false;
            };
            let other_size = match other_fact.kind {
                ObjectKind::StackSlot { base, offset, .. }
                | ObjectKind::FrameObject { base, offset, .. } => {
                    match array_layouts.get(other_object) {
                        Some(StackArrayLayoutDisposition::Proven(layout)) => {
                            u32::try_from(layout.extent).ok()
                        }
                        Some(StackArrayLayoutDisposition::NotIndexed)
                        | Some(StackArrayLayoutDisposition::Refused(_))
                        | None => None,
                    }
                    .or_else(|| {
                        exact_stack_slots
                            .get(&(base, offset))
                            .map(SourceStackSlotSpec::size_bytes)
                    })
                    .or_else(|| {
                        let widths = structured
                            .memory_accesses
                            .values()
                            .filter(|access| access.object == *other_object && access.width > 0)
                            .map(|access| access.width)
                            .collect::<BTreeSet<_>>();
                        (widths.len() == 1).then(|| *widths.first().expect("one width"))
                    })
                }
                ObjectKind::Parameter { .. }
                | ObjectKind::Global { .. }
                | ObjectKind::HeapAlloc { .. }
                | ObjectKind::EscapedUnknown { .. }
                | ObjectKind::Pointee { .. } => None,
            };
            other_size.is_some_and(|other_size| {
                checked_ranges_overlap(
                    certificate.entry_offset,
                    certificate.size_bytes,
                    other_root.offset,
                    other_size,
                )
            })
        })
    });
    candidates
}

pub(crate) fn exact_copy_chain_to_storage(
    graph: &SsaGraph,
    start: ValueId,
    storage: CanonicalStorageId,
) -> Option<(BTreeSet<InstId>, BTreeSet<ValueId>)> {
    let mut insts = BTreeSet::new();
    let mut values = BTreeSet::from([start]);
    let mut current = start;
    loop {
        let value = graph.value(current)?;
        if value.canonical_storage == Some(storage) {
            if !graph.use_sites(current).is_empty() {
                return None;
            }
            return Some((insts, values));
        }
        let uses = graph.use_sites(current);
        let [site] = uses else {
            return None;
        };
        let definition = graph.inst(site.inst)?;
        let InstPayload::Op(SSAOp::Copy { dst, src }) = &definition.payload else {
            return None;
        };
        let output = definition.output?;
        if site.input_idx != 0
            || definition.inputs.as_slice() != [current]
            || graph.value_id_for_var(src) != Some(current)
            || graph.value_id_for_var(dst) != Some(output)
            || src.size != storage.size
            || dst.size != storage.size
            || !insts.insert(site.inst)
            || !values.insert(output)
        {
            return None;
        }
        current = output;
    }
}

pub(crate) fn instruction_strictly_precedes(
    function: &SSAFunction,
    graph: &SsaGraph,
    first: InstId,
    second: InstId,
) -> bool {
    let Some((first_block, first_op)) = graph.op_site_for_inst(first) else {
        return false;
    };
    let Some((second_block, second_op)) = graph.op_site_for_inst(second) else {
        return false;
    };
    if first_block == second_block {
        first_op < second_op
    } else {
        function.dominates(first_block, second_block)
    }
}

pub(crate) fn collect_stack_frame_round_trip_certificates(
    body: Body<'_>,
    derived: Derived<'_>,
    callee_allocations: &BTreeMap<ObjectId, CalleeStackAllocationCertificate>,
    unobserved: &crate::deadphi::DeadPhis,
    live_out: &crate::liveout::FunctionLiveOut,
) -> (
    BTreeMap<ObjectId, StackFrameRoundTripCertificate>,
    BTreeMap<InstId, ObjectId>,
) {
    let Body {
        function,
        graph,
        machine_context,
    } = body;
    let (boundaries, structured) = (derived.boundaries, derived.structured);
    let mut certificates = BTreeMap::new();
    let mut by_inst = BTreeMap::new();
    for (object, allocation) in callee_allocations {
        let accesses = structured
            .memory_accesses
            .values()
            .filter(|access| access.object == *object)
            .collect::<Vec<_>>();
        let writes = accesses
            .iter()
            .copied()
            .filter(|access| access.is_write)
            .collect::<Vec<_>>();
        let reads = accesses
            .iter()
            .copied()
            .filter(|access| !access.is_write)
            .collect::<Vec<_>>();
        let [store] = writes.as_slice() else {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: {} writes, {} reads",
                writes.len(),
                reads.len()
            );
            continue;
        };
        if reads.is_empty()
            || accesses.len() != reads.len().saturating_add(1)
            || accesses.iter().any(|access| {
                !access.provenance_complete
                    || access.space != SpaceId::Ram
                    || access.width != allocation.size_bytes
            })
            || allocation.accesses.as_ref()
                != accesses
                    .iter()
                    .map(|access| access.id)
                    .collect::<Vec<_>>()
                    .as_slice()
        {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: accesses {:?} allocation {:?} size {}",
                accesses
                    .iter()
                    .map(|access| (
                        access.id,
                        access.is_write,
                        access.width,
                        access.provenance_complete,
                        access.space
                    ))
                    .collect::<Vec<_>>(),
                allocation.accesses,
                allocation.size_bytes
            );
            continue;
        }

        let Some(store_inst) = graph.inst(store.id.inst) else {
            continue;
        };
        let InstPayload::Op(SSAOp::Store {
            space: SpaceId::Ram,
            ..
        }) = &store_inst.payload
        else {
            continue;
        };
        let Some(stored_value) = store.value else {
            r2il::refusal_evidence!("frame-round-trip", "{object:?}: store carries no value");
            continue;
        };
        if store_inst.inputs.as_slice() != [store.address, stored_value] {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: store reads {:?}, fact says address {:?} value {stored_value:?}",
                store_inst.inputs,
                store.address
            );
            continue;
        }
        let Some((storage, entry_value, save_insts, save_values)) =
            exact_copy_chain_to_entry_storage(graph, stored_value, allocation.size_bytes)
        else {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: stored value {stored_value:?} is not a copy chain from an entry register"
            );
            continue;
        };
        let machine_roles = machine_context.map(SourceMachineContext::machine_roles);
        if machine_roles.is_some_and(|roles| {
            roles
                .stack_pointer_storage()
                .into_iter()
                .chain(roles.return_address_storage())
                .any(|reserved| register_storages_overlap(storage, reserved))
        }) || boundaries.parameters.values().any(|parameter| {
            parameter.value == entry_value
                || register_storages_overlap(storage, parameter.graph_storage)
                || register_storages_overlap(storage, parameter.abi_storage)
        }) || boundaries.calls.values().any(|boundary| {
            boundary.arguments.iter().any(|argument| {
                matches!(argument.value, SourceCallArgumentValue::Value(value) if value == entry_value)
            })
        }) || boundaries.returns.values().any(|boundary| {
            boundary.values.iter().any(|value| value.value == entry_value)
        }) || machine_context
            .and_then(SourceMachineContext::function_interface)
            .is_some_and(|interface| {
                interface.parameters().iter().any(|parameter| {
                    parameter
                        .register_storage()
                        .is_some_and(|carrier| register_storages_overlap(storage, carrier))
                }) || matches!(
                    interface.return_kind(),
                    SourceFunctionReturn::Register { storage: result }
                        if register_storages_overlap(storage, result)
                )
            })
        {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: {storage:?} is a reserved, parameter, argument or returned register"
            );
            continue;
        }

        let mut insts = save_insts;
        insts.insert(store.id.inst);
        let mut values = save_values;
        let mut load_accesses = Vec::with_capacity(reads.len());
        let mut complete = true;
        for load in reads {
            if !instruction_strictly_precedes(function, graph, store.id.inst, load.id.inst) {
                complete = false;
                break;
            }
            let Some(load_inst) = graph.inst(load.id.inst) else {
                complete = false;
                break;
            };
            let InstPayload::Op(SSAOp::Load {
                space: SpaceId::Ram,
                ..
            }) = &load_inst.payload
            else {
                complete = false;
                break;
            };
            let Some(loaded_value) = load.value else {
                complete = false;
                break;
            };
            if load_inst.inputs.as_slice() != [load.address]
                || load_inst.output != Some(loaded_value)
            {
                complete = false;
                break;
            }
            let Some((restore_insts, restore_values)) =
                exact_copy_chain_to_storage(graph, loaded_value, storage)
            else {
                r2il::refusal_evidence!(
                    "frame-round-trip",
                    "{object:?}: reload {loaded_value:?} does not reach {storage:?} by copies alone"
                );
                complete = false;
                break;
            };
            if insts.contains(&load.id.inst)
                || restore_insts.iter().any(|inst| insts.contains(inst))
                || restore_values.iter().any(|value| values.contains(value))
            {
                complete = false;
                break;
            }
            insts.insert(load.id.inst);
            insts.extend(restore_insts);
            values.extend(restore_values);
            load_accesses.push(load.id);
        }
        // A use the program does not observe is not a read of the saved
        // register. The lifted body merges every storage live across a join, so
        // a callee-saved entry value picks up loop-header and exit merges -- and
        // the lane projections register alias repair materializes to feed them
        // -- for a register the program writes before it reads. Those merges
        // stay in the function on purpose, for the consumers that simulate
        // machine state, so the certificate that decides whether they mean
        // anything has to consult the upstream unobserved-value proof instead of
        // counting raw use sites. Nothing else is relaxed: the domain is still
        // the exact copy/store/load chains, and `DeadPhis` is empty unless the
        // obligation inventory is complete, so an incompletely proven function
        // still declines.
        // A copy of the saved register that nothing reads -- its readers were
        // forwarded to the register itself -- reads it to no effect, and that
        // is a fact of the graph alone, so it holds when the inventory is
        // incomplete and `DeadPhis` says nothing.
        let unread_copy = |site: &UseSite| {
            graph.inst(site.inst).is_some_and(|inst| {
                matches!(inst.payload, InstPayload::Op(SSAOp::Copy { .. }))
                    && inst.output.is_some_and(|output| {
                        graph.use_sites(output).is_empty() && !live_out.contains(output)
                    })
            })
        };
        let escaping_read = values.iter().find_map(|value| {
            graph
                .use_sites(*value)
                .iter()
                .find(|site| {
                    !insts.contains(&site.inst)
                        && !unobserved.unobserved_uses().contains(site)
                        && !unread_copy(site)
                })
                .map(|site| (*value, *site))
        });
        if !complete
            || escaping_read.is_some()
            || insts.iter().any(|inst| by_inst.contains_key(inst))
        {
            r2il::refusal_evidence!(
                "frame-round-trip",
                "{object:?}: complete={complete} escaping read {escaping_read:?} of values {values:?} outside {insts:?}"
            );
            continue;
        }

        let certificate = StackFrameRoundTripCertificate {
            object: *object,
            storage,
            entry_value,
            store_access: store.id,
            load_accesses: load_accesses.into_boxed_slice(),
            insts: insts.iter().copied().collect::<Vec<_>>().into_boxed_slice(),
            values: values
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        for inst in &certificate.insts {
            by_inst.insert(*inst, *object);
        }
        certificates.insert(*object, certificate);
    }
    (certificates, by_inst)
}

/// What the geometry collector needs from the answers already given.
///
/// The stack pointer's own arithmetic is the last thing certified, because
/// whether a use of it counts as a reader depends on what the frame, the
/// return control, and the merge analysis have already accounted for.
pub(crate) struct StackGeometryContext<'a> {
    pub(crate) frame_round_trips: &'a BTreeMap<ObjectId, StackFrameRoundTripCertificate>,
    pub(crate) return_controls: &'a BTreeMap<InstId, MachineReturnControlCertificate>,
    pub(crate) unobserved: &'a crate::deadphi::DeadPhis,
    pub(crate) machine_context: Option<&'a SourceMachineContext>,
    pub(crate) declared_slots: &'a DeclaredStackSlots,
}

pub(crate) fn collect_stack_geometry_certificate(
    boundaries: &SourceBoundaryFacts,
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    answered: &StackGeometryContext<'_>,
) -> StackGeometryCertificate {
    let StackGeometryContext {
        frame_round_trips,
        return_controls,
        unobserved,
        machine_context,
        declared_slots,
    } = answered;
    let Some(prep) = function.decompile_prep_facts() else {
        return StackGeometryCertificate::default();
    };
    let stack_root = |value: ValueId| {
        graph
            .value(value)
            .and_then(|value| resolve_entry_stack_root(Some(prep), &value.var))
    };
    // A constant that arrived through a copy is still a constant. `add x29,
    // sp, #0x60` lifts to a copy of the immediate into a temporary and an add
    // of that temporary, so requiring the operand's own varnode to carry the
    // bits refused the one instruction that establishes the frame base, and
    // with it the whole stack-pointer chain: the prologue's decrement then
    // rendered as `SP_0 = SP_0 - 112`, reading an entry stack pointer no
    // statement had written. The walk ends because each step moves to a value
    // it has not seen and the graph is finite.
    let is_constant = |value: ValueId| {
        let mut current = value;
        let mut visited = BTreeSet::new();
        while visited.insert(current) {
            let Some(resolved) = graph.value(current) else {
                return false;
            };
            if resolved.var.constant_bits().is_some() {
                return true;
            }
            let Some(definition) = graph.def_inst(current).and_then(|inst| graph.inst(inst)) else {
                return false;
            };
            match &definition.payload {
                InstPayload::Op(SSAOp::Copy { .. }) if definition.inputs.len() == 1 => {
                    current = definition.inputs[0];
                }
                _ => return false,
            }
        }
        false
    };

    // A declared array does not collapse into a bare name. `base + const`
    // renders as `name[const]`, so the constant survives as the subscript
    // index and the address computation is not geometry that vanishes.
    let declared_arrays = machine_context
        .and_then(SourceMachineContext::function_interface)
        .and_then(crate::SourceFunctionInterface::type_graph)
        .map(|types: &crate::SourceTypeGraph| {
            declared_slots
                .by_key
                .values()
                .filter(|slot| {
                    slot.logical_type()
                        .and_then(|id| usize::try_from(id).ok())
                        .and_then(|id| types.types().get(id))
                        .is_some_and(|ty| matches!(ty.kind(), SourceTypeKind::Array { .. }))
                })
                .map(|slot| (slot.base(), slot.offset()))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let addresses_declared_array = |value: ValueId| {
        !declared_arrays.is_empty()
            && objects
                .object_for_value(value, SpaceId::Ram)
                .and_then(|object| objects.object(object))
                .is_some_and(|object| match object.kind {
                    ObjectKind::StackSlot { base, offset, .. }
                    | ObjectKind::FrameObject { base, offset, .. } => {
                        declared_arrays.contains(&(base, offset))
                    }
                    _ => false,
                })
    };
    let mut geometry_outputs = BTreeMap::<InstId, ValueId>::new();
    let mut geometry_inputs = BTreeSet::<ValueId>::new();
    for inst in &graph.insts {
        let Some(output) = inst.output.filter(|output| stack_root(*output).is_some()) else {
            continue;
        };
        let output_root = stack_root(output);
        let exact = match &inst.payload {
            InstPayload::Phi { predecessors } => {
                !predecessors.is_empty()
                    && inst.inputs.len() == predecessors.len()
                    && inst
                        .inputs
                        .iter()
                        .all(|input| stack_root(*input) == output_root)
            }
            // A restore is the copy the convention states: construction mints
            // it only for the carrier the callee brings back (rename.rs), so
            // its output is exactly its input's geometry.
            InstPayload::Op(SSAOp::Copy { .. } | SSAOp::CallRestore { .. }) => {
                inst.inputs.len() == 1 && stack_root(inst.inputs[0]).is_some()
            }
            InstPayload::Op(SSAOp::IntAdd { .. }) => {
                inst.inputs.len() == 2
                    && ((stack_root(inst.inputs[0]).is_some() && is_constant(inst.inputs[1]))
                        || (is_constant(inst.inputs[0]) && stack_root(inst.inputs[1]).is_some()))
                    && !addresses_declared_array(output)
            }
            InstPayload::Op(SSAOp::IntSub { .. }) => {
                inst.inputs.len() == 2
                    && stack_root(inst.inputs[0]).is_some()
                    && is_constant(inst.inputs[1])
            }
            _ => false,
        };
        if exact {
            geometry_outputs.insert(inst.id, output);
            geometry_inputs.extend(inst.inputs.iter().copied());
        }
    }

    let mut stack_address_uses = BTreeSet::new();
    for access in structured.memory_accesses.values() {
        let exact_stack_object = access.provenance_complete
            && matches!(
                objects.object(access.object).map(|object| &object.kind),
                Some(
                    ObjectKind::StackSlot { .. }
                        | ObjectKind::FrameObject { .. }
                        | ObjectKind::Parameter { .. }
                )
            );
        let Some(inst) = graph.inst(access.id.inst) else {
            continue;
        };
        if exact_stack_object && inst.inputs.first() == Some(&access.address) {
            stack_address_uses.insert(UseSite {
                inst: access.id.inst,
                input_idx: 0,
            });
        }
    }
    let frame_uses = frame_round_trips
        .values()
        .flat_map(|certificate| certificate.insts.iter())
        .flat_map(|inst| {
            graph.inst(*inst).into_iter().flat_map(move |definition| {
                (0..definition.inputs.len()).map(move |input_idx| UseSite {
                    inst: *inst,
                    input_idx,
                })
            })
        })
        .collect::<BTreeSet<_>>();
    let frame_values = frame_round_trips
        .values()
        .flat_map(|certificate| certificate.values.iter().copied())
        .collect::<BTreeSet<_>>();
    let return_control_uses = return_controls
        .values()
        .flat_map(|certificate| certificate.uses.iter().copied())
        .collect::<BTreeSet<_>>();
    let return_control_values = return_controls
        .values()
        .flat_map(|certificate| certificate.values.iter().copied())
        .collect::<BTreeSet<_>>();

    let mut program_values = boundaries
        .parameters
        .values()
        .map(|parameter| parameter.value)
        .collect::<BTreeSet<_>>();
    for boundary in boundaries.calls.values() {
        program_values.extend(boundary.arguments.iter().filter_map(
            |argument| match argument.value {
                SourceCallArgumentValue::PreservedEntry => None,
                SourceCallArgumentValue::Value(value) => Some(value),
            },
        ));
        program_values.extend(boundary.results.iter().map(|result| result.value));
    }
    for boundary in boundaries.returns.values() {
        program_values.extend(boundary.values.iter().map(|value| value.value));
    }

    let mut values = graph
        .values
        .iter()
        .filter(|value| {
            !program_values.contains(&value.id)
                && !frame_values.contains(&value.id)
                && !return_control_values.contains(&value.id)
                && (stack_root(value.id).is_some() || geometry_inputs.contains(&value.id))
                && graph
                    .def_inst(value.id)
                    .is_none_or(|inst| geometry_outputs.get(&inst).copied() == Some(value.id))
        })
        .map(|value| value.id)
        .collect::<BTreeSet<_>>();
    loop {
        let removed = values
            .iter()
            .copied()
            .filter_map(|value| {
                let site = graph.use_sites(value).iter().find(|site| {
                    !frame_uses.contains(site)
                        && !return_control_uses.contains(site)
                        && !stack_address_uses.contains(site)
                        // A use inside a definition nothing observes is not a
                        // reader. `sub sp, sp, #0x70` lifts with the carry and
                        // sign computations beside it, and nothing reads those
                        // flags; counting them dropped the stack pointer from
                        // its own geometry, and the prologue then rendered as
                        // `SP_0 = SP_0 - 112` over an entry value no statement
                        // had written.
                        && !unobserved.unobserved_uses().contains(site)
                        && !geometry_outputs
                            .get(&site.inst)
                            .is_some_and(|output| values.contains(output))
                })?;
                Some((value, *site))
            })
            .collect::<Vec<_>>();
        if removed.is_empty() {
            break;
        }
        for (value, site) in removed {
            r2il::refusal_evidence!(
                "stack-geometry",
                "{value:?} leaves the geometry: read at {site:?} by {:?}; reader unobserved={} reader output unobserved={:?}; entry root {:?} of {} entry roots, reader output root {:?}",
                graph.inst(site.inst).map(|inst| &inst.payload),
                unobserved.unobserved_uses().contains(&site),
                graph
                    .inst(site.inst)
                    .and_then(|inst| inst.output)
                    .map(|output| unobserved.unobserved_values().contains(&output)),
                stack_root(value),
                prep.entry_stack_address_roots.len(),
                graph
                    .inst(site.inst)
                    .and_then(|inst| inst.output)
                    .map(stack_root)
            );
            values.remove(&value);
        }
    }

    let insts = geometry_outputs
        .into_iter()
        .filter_map(|(inst, output)| values.contains(&output).then_some(inst))
        .collect::<BTreeSet<_>>();
    let mut uses = stack_address_uses
        .difference(&frame_uses)
        .copied()
        .filter(|site| !return_control_uses.contains(site))
        .collect::<BTreeSet<_>>();
    for inst in &insts {
        let Some(definition) = graph.inst(*inst) else {
            continue;
        };
        uses.extend((0..definition.inputs.len()).map(|input_idx| UseSite {
            inst: *inst,
            input_idx,
        }));
    }
    StackGeometryCertificate {
        insts,
        values,
        uses,
    }
}

/// The one width every complete access to this object uses.
///
/// `None` unless there is at least one access, all of them are the same width,
/// and every one carries complete provenance. A disagreement in width means the
/// object is read as more than one thing, which is not a geometry this can
/// state.
/// The storage an object's own accesses describe: one width, or, when they
/// disagree, the extent they reach, which declares as a byte array. Reuse of
/// a slot and slices of one variable both render through the byte spelling.
pub(crate) fn accessed_object_storage(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    object: ObjectId,
) -> Option<(u32, bool)> {
    // A callee proven to write the object from its base wrote that far,
    // whatever this body reads of it afterwards.
    if let Some(reach) = objects.callee_write_reach.get(&object) {
        let accessed = accessed_object_extent(values, objects, structured, object);
        return Some((accessed.map_or(*reach, |extent| extent.max(*reach)), true));
    }
    // An access at a computed index lands wherever the index reaches, so the
    // widths its accesses share say nothing about how far the object goes.
    if structured
        .memory_accesses
        .values()
        .any(|access| access.object == object && objects.address_is_indexed(access.address))
    {
        return accessed_object_extent(values, objects, structured, object)
            .map(|extent| (extent, true));
    }
    let mut width = None;
    let mut seen = 0usize;
    for access in structured.memory_accesses.values() {
        if access.object != object {
            continue;
        }
        seen += 1;
        if !access.provenance_complete || access.width == 0 {
            r2il::refusal_evidence!(
                "stack-object-width",
                "object={object:?} access={:?} provenance_complete={} width={}",
                access.address,
                access.provenance_complete,
                access.width
            );
            return None;
        }
        match width {
            None => width = Some(access.width),
            Some(existing) if existing == access.width => {}
            Some(existing) => {
                // Which accesses disagree, at what offsets, is what says
                // whether this is one object read two ways or two objects.
                let site_of = |id: &StructuredAccessId| graph.op_site_for_inst(id.inst);
                let filed = structured
                    .memory_accesses
                    .iter()
                    .filter(|(_, access)| access.object == object)
                    .map(|(id, access)| {
                        (
                            site_of(id),
                            access.address,
                            access.width,
                            access.object_offset,
                            access.is_write,
                        )
                    })
                    .collect::<Vec<_>>();
                r2il::refusal_evidence!(
                    "stack-object-width",
                    "object={object:?} widths disagree: {existing} and {}; accesses={filed:?}",
                    access.width
                );
                return accessed_object_extent(values, objects, structured, object)
                    .map(|extent| (extent, true));
            }
        }
    }
    if seen == 0 {
        // Which objects the accesses *do* carry is the fact that says whether
        // this object is unreferenced or the accesses were filed elsewhere.
        let filed: Vec<(ObjectId, ValueId, u32, bool)> = structured
            .memory_accesses
            .values()
            .map(|access| {
                (
                    access.object,
                    access.address,
                    access.width,
                    access.provenance_complete,
                )
            })
            .collect();
        r2il::refusal_evidence!(
            "stack-object-width",
            "object={object:?} has no accesses; all accesses={filed:?}"
        );
    }
    width.map(|width| (width, false))
}

/// The extent an object's accesses reach, when every one lands at a known
/// non-negative offset inside it; the containment proof is the offsets.
pub(crate) fn accessed_object_extent(
    values: &crate::values::ValueRanges,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    object: ObjectId,
) -> Option<u32> {
    let mut extent = 0u32;
    for access in structured.memory_accesses.values() {
        if access.object != object {
            continue;
        }
        // An indexed access files its offset as zero because the machine
        // computes it; how far it reaches is what the index can reach, from
        // where the address starts. An address displaced from the object's
        // base -- `table[i].high` -- reaches that much further, and its
        // displacement is the constant part the annotation kept. One whose
        // index has no proven bound leaves the extent unproven, and the
        // frame's own layout answers instead.
        let offset = if objects.address_is_indexed(access.address) {
            let index = objects.index_for_address(access.address)?;
            let bound = values.upper_bound(index);
            // One unbounded index leaves the whole object unsized, so which
            // access it was is the fact that says why a buffer lost its size.
            r2il::refusal_evidence!(
                "accessed-object-extent",
                "{object:?} access {:?} index {index:?} bound={bound:?} displacement={} width={}",
                access.address,
                objects.indexed_displacement(access.address),
                access.width
            );
            let bound = bound?;
            // A base below the object -- `buffer[i - 1]` addressed from one
            // byte under it -- reaches less far, not further, so nothing is
            // added for it.
            let displacement =
                u32::try_from(objects.indexed_displacement(access.address).max(0)).ok()?;
            u32::try_from(bound).ok()?.checked_add(displacement)?
        } else {
            u32::try_from(access.object_offset?).ok()?
        };
        extent = extent.max(offset.checked_add(access.width)?);
    }
    (extent > 0).then_some(extent)
}

pub(crate) struct AllocationSizing<'a> {
    pub(crate) array_layouts: &'a BTreeMap<ObjectId, StackArrayLayoutDisposition>,
    pub(crate) values: &'a crate::values::ValueRanges,
}

pub(crate) fn collect_stack_reload_source_certificates(
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    memory: &MemorySSAFacts,
    structured: &StructuredDataflowFacts,
) -> BTreeMap<ValueId, StackReloadSourceCertificate> {
    let store_sources = collect_stack_store_sources(function, graph, objects, memory, structured);
    let mut certificates = BTreeMap::new();
    let mut ready = VecDeque::new();

    for access in structured.memory_accesses.values().filter(|access| {
        !access.is_write && ram_memory_access_matches_source(function, graph, objects, access)
    }) {
        let Some(value) = access.value else {
            continue;
        };
        let Some((base, offset)) = stack_object_root(objects, access.object) else {
            continue;
        };
        let Some(use_fact) = unique_memory_use_for_access(memory, access) else {
            continue;
        };
        let Some(source) = store_sources.get(&use_fact.version) else {
            continue;
        };
        if source.object != access.object || source.memory_width != access.width {
            continue;
        }
        let cert = StackReloadSourceCertificate {
            value,
            reload: value,
            source: source.value,
            canonical_source: source.canonical_source,
            object: access.object,
            base,
            offset,
            value_width: graph
                .value(value)
                .map(|value| value.var.size)
                .unwrap_or(access.width),
            memory_width: access.width,
            store_access: source.access,
            load_access: access.id,
            store_inst: source.access.inst,
            load_inst: access.id.inst,
        };
        insert_stack_reload_source_certificate(&mut certificates, &mut ready, cert);
    }

    while let Some(value) = ready.pop_front() {
        let Some(cert) = certificates.get(&value).cloned() else {
            continue;
        };
        for use_site in graph.use_sites(value) {
            let Some(inst) = graph.inst(use_site.inst) else {
                continue;
            };
            let Some(output) = stack_reload_propagation_output(inst, value) else {
                continue;
            };
            if certificates.contains_key(&output) {
                continue;
            }
            let value_width = graph
                .value(output)
                .map(|value| value.var.size)
                .unwrap_or(cert.value_width);
            insert_stack_reload_source_certificate(
                &mut certificates,
                &mut ready,
                StackReloadSourceCertificate {
                    value: output,
                    value_width,
                    ..cert.clone()
                },
            );
        }
    }

    certificates
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackStoreSource {
    pub(crate) value: ValueId,
    pub(crate) canonical_source: ValueId,
    pub(crate) object: ObjectId,
    pub(crate) memory_width: u32,
    pub(crate) access: StructuredAccessId,
}

pub(crate) fn collect_stack_store_sources(
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    memory: &MemorySSAFacts,
    structured: &StructuredDataflowFacts,
) -> BTreeMap<MemoryVersion, StackStoreSource> {
    let mut sources = BTreeMap::new();
    for access in structured.memory_accesses.values().filter(|access| {
        access.is_write && ram_memory_access_matches_source(function, graph, objects, access)
    }) {
        let Some(value) = access.value else {
            continue;
        };
        if stack_object_root(objects, access.object).is_none() {
            continue;
        }
        let Some(def_fact) = unique_memory_def_for_access(memory, access) else {
            continue;
        };
        sources.insert(
            def_fact.next_version,
            StackStoreSource {
                value,
                canonical_source: canonical_stack_source_value(function, graph, value),
                object: access.object,
                memory_width: access.width,
                access: access.id,
            },
        );
    }
    sources
}

pub(crate) fn insert_stack_reload_source_certificate(
    certificates: &mut BTreeMap<ValueId, StackReloadSourceCertificate>,
    ready: &mut VecDeque<ValueId>,
    cert: StackReloadSourceCertificate,
) {
    let value = cert.value;
    if certificates.contains_key(&value) {
        return;
    }
    certificates.insert(value, cert);
    ready.push_back(value);
}

pub(crate) fn stack_reload_propagation_output(
    inst: &crate::graph::GraphInst,
    source: ValueId,
) -> Option<ValueId> {
    let output = inst.output?;
    match &inst.payload {
        InstPayload::Op(
            SSAOp::Copy { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::Cast { .. }
            | SSAOp::Subpiece { .. },
        ) if inst.inputs.len() == 1 && inst.inputs.first().copied() == Some(source) => Some(output),
        InstPayload::Phi { .. } if expression_phi_is_identity(inst) => {
            (inst.inputs.first().copied() == Some(source)).then_some(output)
        }
        _ => None,
    }
}

pub(crate) fn unique_memory_def_for_access<'a>(
    memory: &'a MemorySSAFacts,
    access: &StructuredMemoryAccessFact,
) -> Option<&'a MemoryDefFact> {
    let mut matches = memory
        .defs_by_inst
        .get(&access.id.inst)
        .into_iter()
        .flatten()
        .filter(|def| {
            def.location.space == access.space
                && def.location.object == access.object
                && def.location.size == access.width
        });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

pub(crate) fn unique_memory_use_for_access<'a>(
    memory: &'a MemorySSAFacts,
    access: &StructuredMemoryAccessFact,
) -> Option<&'a MemoryUseFact> {
    let mut matches = memory
        .uses_by_inst
        .get(&access.id.inst)
        .into_iter()
        .flatten()
        .filter(|use_fact| {
            use_fact.location.space == access.space
                && use_fact.location.object == access.object
                && use_fact.location.size == access.width
        });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

pub(crate) fn canonical_stack_source_value(
    function: &SSAFunction,
    graph: &SsaGraph,
    source: ValueId,
) -> ValueId {
    let Some(var) = graph.value(source).map(|value| &value.var) else {
        return source;
    };
    let root = canonical_value_root(function.decompile_prep_facts(), var);
    graph.value_id_for_var(root).unwrap_or(source)
}

pub(crate) fn collect_stack_call_argument_values(
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    structured: &StructuredDataflowFacts,
    call_site: &CallSiteFact,
    calls_move_stack_pointer: bool,
) -> Vec<StackCallArgumentCertificate> {
    let Some((block_addr, op_idx)) = graph.op_site_for_inst(call_site.at) else {
        return Vec::new();
    };
    let Some(block) = function.get_block(block_addr) else {
        return Vec::new();
    };

    // Outgoing slots sit at and above the stack pointer as the call
    // instruction finds it. Objects are keyed by their position in a frame, so
    // the boundary is that pointer's position in the same frame: anything
    // below it is this function's own, not an argument.
    let Some((entering, _)) = call_entering_stack_pointer_offset(
        function,
        graph,
        block,
        op_idx,
        calls_move_stack_pointer,
    ) else {
        return Vec::new();
    };
    let mut by_offset = BTreeMap::<i64, StackCallArgumentCertificate>::new();
    for (producer_idx, op) in block.ops[..op_idx].iter().enumerate().rev() {
        if matches!(
            op,
            SSAOp::Call { .. } | SSAOp::CallInd { .. } | SSAOp::Return { .. }
        ) {
            break;
        }
        let SSAOp::Store {
            space: SpaceId::Ram,
            val,
            ..
        } = op
        else {
            continue;
        };
        let Some(value) = graph.value_id_for_var(val) else {
            continue;
        };

        for (access_id, access) in structured.memory_accesses.iter().filter(|(_, access)| {
            access.block_addr == block_addr
                && access.op_index == producer_idx
                && access.is_write
                && ram_memory_access_matches_source(function, graph, objects, access)
        }) {
            if access.value != Some(value) {
                continue;
            }
            // The slot and the pointer entering the call are read in the same
            // frame: an object in another one is not this call's argument area.
            let Some((base, offset)) = stack_object_root(objects, access.object) else {
                continue;
            };
            if base != entering.base || offset < entering.offset {
                continue;
            }
            by_offset
                .entry(offset)
                .or_insert(StackCallArgumentCertificate {
                    stack_offset: offset,
                    value,
                    memory_access: *access_id,
                });
        }
    }

    by_offset.into_values().collect()
}
