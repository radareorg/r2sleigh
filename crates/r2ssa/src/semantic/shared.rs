//! What more than one phase asks, asked once.

use super::*;

pub(crate) fn memory_space_order(space: SpaceId) -> (u8, u32) {
    match space {
        SpaceId::Ram => (0, 0),
        SpaceId::Register => (1, 0),
        SpaceId::Unique => (2, 0),
        SpaceId::Const => (3, 0),
        SpaceId::Custom(id) => (4, id),
    }
}

pub(crate) fn loop_carrier_phi_input_matches(
    graph: &SsaGraph,
    predecessor: u64,
    value: ValueId,
    site: UseSite,
) -> bool {
    let Some(inst) = graph.inst(site.inst) else {
        return false;
    };
    let InstPayload::Phi { predecessors } = &inst.payload else {
        return false;
    };

    inst.inputs.get(site.input_idx) == Some(&value)
        && predecessors
            .get(site.input_idx)
            .and_then(|predecessor| graph.block(*predecessor))
            .map(|block| block.addr)
            == Some(predecessor)
}

/// The bytes of `value`, least significant first, as constants and slices of
/// the values that only byte-moving operations composed it from.
/// The bytes a load of a run of code pointer entries carries.
///
/// A relocation fills the slots, so the file states nothing about them and
/// what they become is the targets the capture recorded. Only a load that
/// starts at an entry and covers whole entries is one of these.
pub(crate) fn code_pointer_run_bytes(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    inst: &crate::graph::GraphInst,
    space: SpaceId,
    size: u32,
) -> Option<Vec<ByteSource>> {
    let machine_context = machine_context?;
    if space != SpaceId::Ram {
        return None;
    }
    let entry_bytes = machine_context.memory_model().default_address_bits() / 8;
    if entry_bytes == 0 || !size.is_multiple_of(entry_bytes) {
        return None;
    }
    let address = crate::constant::folded_value(graph, *inst.inputs.first()?)?;
    let mut bytes = Vec::with_capacity(size as usize);
    for entry in 0..size / entry_bytes {
        let at = address.checked_add(u64::from(entry) * u64::from(entry_bytes))?;
        let target = machine_context.code_pointer_entry(at)?;
        bytes.extend(
            (0..entry_bytes)
                .map(|byte| ByteSource::Constant(target.checked_shr(byte * 8).unwrap_or(0) as u8)),
        );
    }
    Some(bytes)
}

pub(crate) fn value_byte_sources(
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    value: ValueId,
) -> Option<Vec<ByteSource>> {
    let mut current = value;
    loop {
        let graph_value = graph.value(current)?;
        let size = graph_value.var.size;
        let constant = graph_value.var.constant_bits().or_else(|| {
            graph_value
                .canonical_storage
                .filter(|storage| storage.space == crate::CanonicalStorageSpace::Constant)
                .map(|storage| storage.offset)
        });
        if let Some(bits) = constant {
            return Some(
                (0..size)
                    .map(|byte| ByteSource::Constant(bits.checked_shr(byte * 8).unwrap_or(0) as u8))
                    .collect(),
            );
        }
        let leaf = || {
            Some(
                (0..size)
                    .map(|byte| ByteSource::Lane {
                        value: current,
                        byte,
                    })
                    .collect(),
            )
        };
        let Some(inst) = graph.def_inst(current).and_then(|inst| graph.inst(inst)) else {
            return leaf();
        };
        match &inst.payload {
            InstPayload::Op(SSAOp::Copy { .. }) => current = *inst.inputs.first()?,
            InstPayload::Op(SSAOp::Load { space, .. }) => {
                return code_pointer_run_bytes(graph, machine_context, inst, *space, size)
                    .or_else(leaf);
            }
            InstPayload::Op(SSAOp::IntZExt { .. }) => {
                let mut bytes = value_byte_sources(graph, machine_context, *inst.inputs.first()?)?;
                bytes.resize(size as usize, ByteSource::Constant(0));
                return Some(bytes);
            }
            InstPayload::Op(SSAOp::Piece { .. }) => {
                let mut bytes = value_byte_sources(graph, machine_context, *inst.inputs.get(1)?)?;
                bytes.extend(value_byte_sources(
                    graph,
                    machine_context,
                    *inst.inputs.first()?,
                )?);
                (bytes.len() == size as usize).then_some(())?;
                return Some(bytes);
            }
            InstPayload::Op(SSAOp::Insert { .. }) => {
                let mut bytes = value_byte_sources(graph, machine_context, *inst.inputs.first()?)?;
                let lane = value_byte_sources(graph, machine_context, *inst.inputs.get(1)?)?;
                let position = crate::constant::value_of(graph, *inst.inputs.get(2)?)?;
                if position % 8 != 0 {
                    return None;
                }
                let start = usize::try_from(position / 8).ok()?;
                (start.checked_add(lane.len())? <= bytes.len()).then_some(())?;
                bytes[start..start + lane.len()].copy_from_slice(&lane);
                return Some(bytes);
            }
            _ => return leaf(),
        }
    }
}

pub(crate) fn memory_locations_may_alias(
    objects: &ObjectModel,
    left: &MemoryLocation,
    right: &MemoryLocation,
) -> bool {
    let Some(left_object) = objects.object(left.object) else {
        return true;
    };
    let Some(right_object) = objects.object(right.object) else {
        return true;
    };
    if left_object.kind.space() != left.space || right_object.kind.space() != right.space {
        return true;
    }
    if left.space != right.space {
        return false;
    }
    let address_bits = objects
        .address_bits_by_space
        .get(&ObjectSpaceId(left.space))
        .copied();
    if left.object == right.object {
        return address_bits.is_some_and(|address_bits| {
            modular_memory_ranges_may_overlap(
                0,
                &left.address,
                left.size,
                0,
                &right.address,
                right.size,
                address_bits,
            )
        }) || address_bits.is_none();
    }
    if matches!(
        left_object.kind,
        ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
    ) && matches!(
        right_object.kind,
        ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
    ) && let (Some(left_root), Some(right_root)) = (
        objects.entry_stack_roots.get(&left.object),
        objects.entry_stack_roots.get(&right.object),
    ) && left_root.base == StackAddressBase::StackPointer
        && right_root.base == StackAddressBase::StackPointer
        && let Some(address_bits) = address_bits
    {
        return modular_memory_ranges_may_overlap(
            i128::from(left_root.offset),
            &left.address,
            left.size,
            i128::from(right_root.offset),
            &right.address,
            right.size,
            address_bits,
        );
    }
    match (&left_object.kind, &right_object.kind) {
        (ObjectKind::EscapedUnknown { .. }, _) | (_, ObjectKind::EscapedUnknown { .. }) => true,
        (
            ObjectKind::Parameter { .. },
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
        )
        | (
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
            ObjectKind::Parameter { .. },
        ) => false,
        (ObjectKind::Parameter { .. }, _) | (_, ObjectKind::Parameter { .. }) => true,
        // Memory reached through a parameter is not the frame, for the same
        // reason the parameter's own memory is not; against anything else it
        // may alias, because nothing here proves two pointers distinct.
        (
            ObjectKind::Pointee { .. },
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
        )
        | (
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
            ObjectKind::Pointee { .. },
        ) => false,
        (ObjectKind::Pointee { .. }, _) | (_, ObjectKind::Pointee { .. }) => true,
        (
            ObjectKind::Global {
                space: left_space,
                address: left_base,
            },
            ObjectKind::Global {
                space: right_space,
                address: right_base,
            },
        ) => {
            left_space != right_space
                || address_bits.is_none_or(|address_bits| {
                    modular_memory_ranges_may_overlap(
                        i128::from(*left_base),
                        &left.address,
                        left.size,
                        i128::from(*right_base),
                        &right.address,
                        right.size,
                        address_bits,
                    )
                })
        }
        (
            ObjectKind::StackSlot {
                base: left_base,
                offset: left_offset,
                ..
            }
            | ObjectKind::FrameObject {
                base: left_base,
                offset: left_offset,
                ..
            },
            ObjectKind::StackSlot {
                base: right_base,
                offset: right_offset,
                ..
            }
            | ObjectKind::FrameObject {
                base: right_base,
                offset: right_offset,
                ..
            },
        ) if left_base == right_base => address_bits.is_none_or(|address_bits| {
            modular_memory_ranges_may_overlap(
                i128::from(*left_offset),
                &left.address,
                left.size,
                i128::from(*right_offset),
                &right.address,
                right.size,
                address_bits,
            )
        }),
        (
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
            ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. },
        ) => true,
        (
            ObjectKind::HeapAlloc {
                call_site: left, ..
            },
            ObjectKind::HeapAlloc {
                call_site: right, ..
            },
        ) => left == right,
        _ => false,
    }
}

pub(crate) fn modular_memory_ranges_may_overlap(
    left_base: i128,
    left: &RelativeMemoryAddress,
    left_size: u32,
    right_base: i128,
    right: &RelativeMemoryAddress,
    right_size: u32,
    address_bits: u32,
) -> bool {
    if address_bits == 0 || address_bits > 64 || left_size == 0 || right_size == 0 {
        return true;
    }
    let (Some(left), Some(right)) = (left.exact_offset(), right.exact_offset()) else {
        return modular_affine_ranges_may_overlap(
            left_base,
            left,
            left_size,
            right_base,
            right,
            right_size,
            address_bits,
        );
    };
    let modulus = 1_i128 << address_bits;
    let left_size = i128::from(left_size);
    let right_size = i128::from(right_size);
    if left_size >= modulus || right_size >= modulus {
        return true;
    }
    let left_start = (left_base + i128::from(left)).rem_euclid(modulus);
    let right_start = (right_base + i128::from(right)).rem_euclid(modulus);
    modular_intervals_overlap(left_start, left_size, right_start, right_size, modulus)
}

pub(crate) fn modular_affine_ranges_may_overlap(
    left_base: i128,
    left: &RelativeMemoryAddress,
    left_size: u32,
    right_base: i128,
    right: &RelativeMemoryAddress,
    right_size: u32,
    address_bits: u32,
) -> bool {
    let (Some((left_terms, left_offset)), Some((right_terms, right_offset))) =
        (relative_affine_parts(left), relative_affine_parts(right))
    else {
        return true;
    };
    let mut difference = BTreeMap::<ValueId, i128>::new();
    for term in left_terms {
        *difference.entry(term.value).or_default() += i128::from(term.coefficient);
    }
    for term in right_terms {
        *difference.entry(term.value).or_default() -= i128::from(term.coefficient);
    }
    difference.retain(|_, coefficient| *coefficient != 0);
    let address_modulus = 1_u128 << address_bits;
    let congruence_modulus = difference
        .values()
        .map(|coefficient| coefficient.unsigned_abs())
        .fold(address_modulus, gcd_u128);
    let Ok(congruence_modulus) = i128::try_from(congruence_modulus) else {
        return true;
    };
    let constant = left_base + i128::from(left_offset) - right_base - i128::from(right_offset);
    let low = -i128::from(left_size.saturating_sub(1));
    let high = i128::from(right_size.saturating_sub(1));
    let candidate =
        low + (constant.rem_euclid(congruence_modulus) - low).rem_euclid(congruence_modulus);
    candidate <= high
}

pub(crate) fn relative_affine_parts(
    address: &RelativeMemoryAddress,
) -> Option<(&[crate::AffineAddressTerm], i64)> {
    match address {
        RelativeMemoryAddress::Exact(offset) => Some((&[], *offset)),
        RelativeMemoryAddress::Affine { terms, offset } => Some((terms, *offset)),
        RelativeMemoryAddress::Unknown => None,
    }
}

pub(crate) fn modular_intervals_overlap(
    left_start: i128,
    left_size: i128,
    right_start: i128,
    right_size: i128,
    modulus: i128,
) -> bool {
    let split = |start: i128, size: i128| {
        let end = start + size;
        if end <= modulus {
            [(start, end), (0, 0)]
        } else {
            [(start, modulus), (0, end - modulus)]
        }
    };
    let left = split(left_start, left_size);
    let right = split(right_start, right_size);
    left.into_iter().any(|(left_start, left_end)| {
        left_start < left_end
            && right.iter().any(|(right_start, right_end)| {
                right_start < right_end && left_start < *right_end && *right_start < left_end
            })
    })
}

pub(crate) fn gcd_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Mask for a width, saturating at the widest value this can state.
pub(crate) const fn induction_mask(width_bits: u32) -> u64 {
    if width_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    }
}

/// The constant a value holds, if it holds one.
pub(crate) fn induction_constant(graph: &SsaGraph, value: ValueId) -> Option<u64> {
    graph.value(value)?.var.constant_bits()
}

/// The affine parts `(multiplier, addend)` of `value` in terms of `phi`.
///
/// `phi` itself is `(1, 0)`; a constant is `(0, c)`; and add, subtract and
/// multiply-by-constant compose. Anything else has no affine reading and
/// returns `None`, which is what keeps a shape this cannot state exactly out
/// of the fact entirely.
///
/// The depth bound and the visited set are both needed: the bound stops a
/// legitimately deep expression from costing more than it is worth, and the
/// set stops a cycle through a merge from recursing forever.
pub(crate) fn induction_affine_parts(
    graph: &SsaGraph,
    phi: ValueId,
    value: ValueId,
    width_bits: u32,
    depth: u8,
    visited: &mut BTreeSet<ValueId>,
) -> Option<(u64, u64)> {
    if depth == 0 {
        return None;
    }
    if value == phi {
        return Some((1, 0));
    }
    let mask = induction_mask(width_bits);
    if let Some(constant) = induction_constant(graph, value) {
        return Some((0, constant & mask));
    }
    if !visited.insert(value) {
        return None;
    }
    let parts = induction_affine_parts_of_definition(graph, phi, value, width_bits, depth);
    visited.remove(&value);
    parts
}

pub(crate) fn induction_affine_parts_of_definition(
    graph: &SsaGraph,
    phi: ValueId,
    value: ValueId,
    width_bits: u32,
    depth: u8,
) -> Option<(u64, u64)> {
    let inst = graph.inst(graph.def_inst(value)?)?;
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    let mask = induction_mask(width_bits);
    let operand = |index: usize| inst.inputs.get(index).copied();
    let mut visited = BTreeSet::from([value]);
    let mut parts_of = |value: ValueId| {
        induction_affine_parts(graph, phi, value, width_bits, depth - 1, &mut visited)
    };
    match op {
        SSAOp::Copy { .. } => parts_of(operand(0)?),
        SSAOp::IntAdd { .. } => {
            let (lm, la) = parts_of(operand(0)?)?;
            let (rm, ra) = parts_of(operand(1)?)?;
            Some((lm.wrapping_add(rm) & mask, la.wrapping_add(ra) & mask))
        }
        SSAOp::IntSub { .. } => {
            let (lm, la) = parts_of(operand(0)?)?;
            let (rm, ra) = parts_of(operand(1)?)?;
            Some((lm.wrapping_sub(rm) & mask, la.wrapping_sub(ra) & mask))
        }
        SSAOp::IntMult { .. } => {
            let left = operand(0)?;
            let right = operand(1)?;
            // Exactly one operand must be constant. Multiplying two affine
            // terms is quadratic in the carrier and has no affine reading.
            if let Some(scale) = induction_constant(graph, left) {
                let (multiplier, addend) = parts_of(right)?;
                return Some((
                    multiplier.wrapping_mul(scale) & mask,
                    addend.wrapping_mul(scale) & mask,
                ));
            }
            let scale = induction_constant(graph, right)?;
            let (multiplier, addend) = parts_of(left)?;
            Some((
                multiplier.wrapping_mul(scale) & mask,
                addend.wrapping_mul(scale) & mask,
            ))
        }
        _ => None,
    }
}

/// The step `update` applies to `phi`, when it applies one this can state.
///
/// A multiplier of one is an add or a subtract; the subtract spelling is
/// chosen when the addend reads as a smaller negative number at this width,
/// which is what makes a decrementing counter say so rather than claim to add
/// a value near the top of its range. A multiplier of one with a zero addend
/// is the identity, which is not motion and is refused: a value that does not
/// change is a loop-invariant, and calling it an induction variable would let
/// a consumer index by something that never advances.
pub(crate) fn induction_step_for_update(
    graph: &SsaGraph,
    phi: ValueId,
    update: ValueId,
    width_bits: u32,
) -> Option<InductionStep> {
    let mut visited = BTreeSet::new();
    let (multiplier, addend) =
        induction_affine_parts(graph, phi, update, width_bits, 8, &mut visited)?;
    let mask = induction_mask(width_bits);
    let multiplier = multiplier & mask;
    let addend = addend & mask;
    if multiplier != 1 {
        return Some(InductionStep::Affine { multiplier, addend });
    }
    if addend == 0 {
        return None;
    }
    let negated = addend.wrapping_neg() & mask;
    if negated != 0 && negated < addend {
        Some(InductionStep::SubConst(negated))
    } else {
        Some(InductionStep::AddConst(addend))
    }
}

/// The arity a call takes from the convention when no prototype describes it.
///
/// A boundary otherwise completes in exactly one way, from a source-owned
/// callsite interface, and that is the better answer wherever it exists. Where
/// it does not -- an indirect call, a callee radare2 never resolved, a thunk --
/// the alternative was not fewer facts but none: the boundary stayed
/// incomplete, every obligation on it was seeded as an unknown effect, and the
/// function refused. `sym._init` in a stock GCC binary refuses for exactly
/// that, on the indirect `__gmon_start__` guard, and so does every import
/// thunk and every tail call.
///
/// The rule is the one the project owner settled: the count comes from the
/// convention's argument registers that this function provably wrote on the way
/// to the call and that reach it. That is dataflow evidence rather than a
/// guess, and it is the same evidence a variadic call's tail already rests on
/// -- the same scan answers both, so the two cannot come to disagree about what
/// counts as an argument. A call is a barrier in that scan, so a register left
/// set by an earlier call's arguments is not mistaken for this call's, and a
/// register this function never wrote ends the count: without a prototype
/// saying an argument exists, an untouched register carrying whatever the
/// function was entered with is no evidence that the call reads it.
///
/// The result is the widest observed view of the convention's result register,
/// and only when something reads it. A call defines both a full carrier and
/// its declared register lanes, while an unknown prototype tells us only the
/// full convention carrier. Code that consumes a 32-bit return therefore reads
/// the lane and may never read the 64-bit carrier. The contained lane is still
/// structural register geometry, and its exact use proves the width the caller
/// observes without guessing a prototype. No read proves nothing either way --
/// the callee may be `void`, or its result may simply be ignored -- and since
/// nothing observes it, claiming one would add a local no reader ever names.
///
/// Where the convention itself is unknown there is no ground to stand on, and
/// the boundary stays incomplete: the function refuses, which is the honest
/// answer and the one this leaves in place for that case alone.
/// Where the stack pointer stands as a call instruction finds it, before the
/// instruction's own p-code spends anything.
///
/// The position is named in the frame the pointer belongs to: the entry frame,
/// or the realigned one when a mask cut a new origin. Both sides of every
/// question asked about an outgoing slot are read in that same frame, so which
/// one it is travels with the offset.
///
/// Construction records exactly that carrier as the source of the
/// `CallRestore` it emits after the call, so no instruction boundary has to
/// be reconstructed here. A call the convention does not restore has no such
/// record, and the position is then unknown.
pub(crate) fn call_entering_stack_pointer_offset(
    function: &SSAFunction,
    graph: &SsaGraph,
    block: &crate::function::SSABlock,
    call_op_index: usize,
    calls_move_stack_pointer: bool,
) -> Option<(StackAddressRoot, bool)> {
    let recorded = block
        .ops
        .get(call_op_index.checked_add(1)?..)?
        .iter()
        .take_while(|op| matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }))
        .find_map(|op| match op {
            SSAOp::CallRestore { src, .. } => Some(src.clone()),
            _ => None,
        });
    let recorded_restore = recorded.is_some();
    let entering = match recorded {
        Some(entering) => entering,
        // A transfer that spends nothing on the carrier records no restore: a
        // tail call returns nowhere, so there is nothing to bring back, and
        // the pointer it found is the one reaching it.
        None => {
            let Some(storage) = function.stack_pointer_carrier() else {
                r2il::refusal_evidence!(
                    "call-entering-stack-pointer",
                    "call at ({:#x}, {call_op_index}) records no carrier and the machine names no stack pointer",
                    block.addr
                );
                return None;
            };
            match reaching_stack_pointer_before(
                function,
                graph,
                storage,
                block.addr,
                call_op_index,
                calls_move_stack_pointer,
            ) {
                Some(ReachingAbiState::PreservedEntry) => {
                    return Some((
                        StackAddressRoot {
                            base: StackAddressBase::StackPointer,
                            offset: 0,
                        },
                        false,
                    ));
                }
                Some(ReachingAbiState::Value(value)) => graph.value(value)?.var.clone(),
                None => {
                    r2il::refusal_evidence!(
                        "call-entering-stack-pointer",
                        "call at ({:#x}, {call_op_index}) records no carrier and no {storage:?} reaches it",
                        block.addr
                    );
                    return None;
                }
            }
        }
    };
    let entering = &entering;
    let Some(root) = resolve_entry_stack_root(function.decompile_prep_facts(), entering) else {
        r2il::refusal_evidence!(
            "call-entering-stack-pointer",
            "call at ({:#x}, {call_op_index}) found {entering}, which has no entry-relative root; \
             it is defined by {:?}; the function has {} entry-relative and {} declared-base roots",
            block.addr,
            {
                let defs = function
                    .blocks()
                    .iter()
                    .flat_map(|block| {
                        block
                            .phis
                            .iter()
                            .map(|phi| {
                                (
                                    phi.dst.clone(),
                                    format!(
                                        "Phi{:?}",
                                        phi.sources
                                            .iter()
                                            .map(|(_, source)| source.to_string())
                                            .collect::<Vec<_>>()
                                    ),
                                    phi.sources
                                        .iter()
                                        .map(|(_, source)| source.clone())
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .chain(block.ops.iter().filter_map(|op| {
                                op.dst().map(|dst| {
                                    (
                                        dst.clone(),
                                        format!("{op}"),
                                        op.sources().into_iter().cloned().collect::<Vec<_>>(),
                                    )
                                })
                            }))
                    })
                    .collect::<Vec<_>>();
                let mut chain = Vec::new();
                let mut cursor = Some(entering.clone());
                while let Some(var) = cursor.take() {
                    let rooted =
                        resolve_entry_stack_root(function.decompile_prep_facts(), &var).is_some();
                    let Some((_, text, sources)) = defs.iter().find(|(dst, _, _)| *dst == var)
                    else {
                        chain.push(format!("{var}=<no def> rooted={rooted}"));
                        break;
                    };
                    let source_roots = sources
                        .iter()
                        .filter(|source| source.name() == var.name())
                        .map(|source| {
                            format!(
                                "{source}:{:?}",
                                resolve_entry_stack_root(function.decompile_prep_facts(), source)
                                    .map(|root| root.offset)
                            )
                        })
                        .collect::<Vec<_>>();
                    chain.push(format!("{text} rooted={rooted} sources={source_roots:?}"));
                    if rooted || chain.len() > 12 {
                        break;
                    }
                    cursor = sources
                        .iter()
                        .find(|source| {
                            source.name() == var.name()
                                && resolve_entry_stack_root(function.decompile_prep_facts(), source)
                                    .is_none()
                        })
                        .or_else(|| sources.iter().find(|source| source.name() == var.name()))
                        .cloned();
                }
                chain
            },
            function
                .decompile_prep_facts()
                .map_or(0, |facts| facts.entry_stack_address_roots.len()),
            function
                .decompile_prep_facts()
                .map_or(0, |facts| facts.stack_address_roots.len())
        );
        return None;
    };
    matches!(
        root.base,
        StackAddressBase::StackPointer | StackAddressBase::Realigned
    )
    .then_some((root, recorded_restore))
}

/// Convention-clobbered registers this body leaves exactly as it found them
/// at every exit.
///
/// A register is preserved when no instruction anywhere in the body defines a
/// storage overlapping it. A call's own clobbers are the `CallDefine`s that
/// follow it, so a body that calls something it knows nothing more about
/// preserves nothing that call may touch, and the answer composes through
/// exactly the callees whose own bodies were read. This is the set a compiler
/// computes for the same purpose: GCC's `-fipa-ra` keeps a caller's value in
/// an argument register across a call to a callee it has seen never write it,
/// and the caller then reads that register after the call as its own.
///
/// Every exit has to be a return for the claim to hold. A block that leaves by
/// any other transfer hands control to a body not read here, so nothing is
/// claimed for the function; a call that ends its block with no successor is
/// one the source marked noreturn, which never comes back and constrains
/// nothing.
pub(crate) fn preserved_call_carriers(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
) -> BTreeSet<CanonicalStorageId> {
    let candidates = machine_context.call_clobbered_carriers();
    if candidates.is_empty() {
        return BTreeSet::new();
    }
    let mut saw_return = false;
    for block in function.blocks() {
        if !function.successors(block.addr).is_empty() {
            continue;
        }
        let terminal = block
            .ops
            .iter()
            .rev()
            .find(|op| !matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }));
        match terminal {
            Some(SSAOp::Return { .. }) => saw_return = true,
            Some(SSAOp::Call { .. } | SSAOp::CallInd { .. }) => {}
            _ => return BTreeSet::new(),
        }
    }
    if !saw_return {
        return BTreeSet::new();
    }
    let mut preserved = candidates.iter().copied().collect::<BTreeSet<_>>();
    for inst in &graph.insts {
        if inst.output.is_none() {
            continue;
        }
        let Some(written) = inst.canonical_storage else {
            continue;
        };
        preserved.retain(|storage| !register_storages_overlap(written, *storage));
        if preserved.is_empty() {
            break;
        }
    }
    preserved
}

pub(crate) fn projected_logical_register_storage(
    abi_storage: CanonicalStorageId,
    logical_value: SourceLogicalValue,
    type_graph: &crate::SourceTypeGraph,
) -> Option<CanonicalStorageId> {
    let source_type = type_graph.types().get(logical_value.type_id() as usize)?;
    let carrier = logical_value.carrier();
    let abi_bits = u64::from(abi_storage.size).checked_mul(8)?;
    if abi_storage.space != CanonicalStorageSpace::Register
        || carrier.offset_bits() != 0
        || carrier.size_bits() == 0
        || carrier.size_bits() != source_type.size_bits()
        || !carrier.size_bits().is_multiple_of(8)
    {
        return None;
    }
    match carrier.kind() {
        SourceCarrierKind::Full if carrier.size_bits() == abi_bits => Some(abi_storage),
        // A float occupies its carrier's low lane as an integer does, which is
        // how a `double` travels in a 128-bit vector register.
        SourceCarrierKind::LowBits
            if carrier.size_bits() < abi_bits
                && matches!(
                    source_type.kind(),
                    SourceTypeKind::SignedInteger
                        | SourceTypeKind::UnsignedInteger
                        | SourceTypeKind::Float
                ) =>
        {
            Some(CanonicalStorageId {
                space: abi_storage.space,
                offset: abi_storage.offset,
                size: u32::try_from(carrier.size_bits() / 8).ok()?,
            })
        }
        _ => None,
    }
}

pub(crate) fn reaching_abi_value_in_block(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ValueId> {
    reaching_abi_value_in_block_with_policy(
        function,
        graph,
        machine_context,
        block_addr,
        boundary_op_index,
        storage,
        true,
    )
    .and_then(|state| match state {
        ReachingAbiState::PreservedEntry => None,
        ReachingAbiState::Value(value) => Some(value),
    })
}

/// The stack pointer reaching a boundary, for a caller that has the carrier
/// but no machine context of its own.
pub(crate) fn reaching_stack_pointer_before(
    function: &SSAFunction,
    graph: &SsaGraph,
    storage: CanonicalStorageId,
    block_addr: u64,
    boundary_op_index: usize,
    calls_move_stack_pointer: bool,
) -> Option<ReachingAbiState> {
    let visited = BTreeMap::new();
    let search = ReachingAbi {
        function,
        graph,
        storage,
        policy: ReachingAbiPolicy {
            allow_distinct_phi_inputs: false,
            calls_are_barriers: true,
            stack_pointer: Some(storage),
            transfer_carrier: calls_move_stack_pointer.then_some(storage),
        },
    };
    match reaching_abi_value_before(
        search,
        block_addr,
        boundary_op_index,
        &visited,
        &mut BTreeMap::new(),
    )? {
        ReachingAbiPath::Reaches(state) => Some(state),
        ReachingAbiPath::Cycle => None,
    }
}

pub(crate) fn reaching_abi_value_in_block_with_policy(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
    allow_distinct_phi_inputs: bool,
) -> Option<ReachingAbiState> {
    let visited = BTreeMap::new();
    let search = ReachingAbi {
        function,
        graph,
        storage,
        policy: ReachingAbiPolicy {
            allow_distinct_phi_inputs,
            calls_are_barriers: true,
            stack_pointer: machine_context.stack_pointer_carrier(),
            transfer_carrier: machine_context
                .call_moves_stack_pointer()
                .then(|| machine_context.stack_pointer_carrier())
                .flatten(),
        },
    };
    match reaching_abi_value_before(
        search,
        block_addr,
        boundary_op_index,
        &visited,
        &mut BTreeMap::new(),
    )? {
        ReachingAbiPath::Reaches(state) => Some(state),
        ReachingAbiPath::Cycle => None,
    }
}

/// Whether to report how a call's definitions were found, read once.
pub(crate) fn trace_call_definitions() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("R2SSA_TRACE_CALLDEF").is_some())
}

pub(crate) fn reaching_abi_value_at_end(
    search: ReachingAbi<'_>,
    block_addr: u64,
    visited: &BTreeMap<u64, usize>,
    memo: &mut BTreeMap<u64, Option<ReachingAbiPath>>,
) -> Option<ReachingAbiPath> {
    let boundary = search.function.get_block(block_addr)?.ops.len();
    if visited.contains_key(&block_addr) {
        return reaching_abi_value_before(search, block_addr, boundary, visited, memo);
    }
    if let Some(known) = memo.get(&block_addr) {
        return *known;
    }
    let result = reaching_abi_value_before(search, block_addr, boundary, visited, memo);
    memo.insert(block_addr, result);
    result
}

pub(crate) fn reaching_abi_value_before(
    search: ReachingAbi<'_>,
    block_addr: u64,
    boundary_op_index: usize,
    visited: &BTreeMap<u64, usize>,
    memo: &mut BTreeMap<u64, Option<ReachingAbiPath>>,
) -> Option<ReachingAbiPath> {
    let ReachingAbi {
        function,
        graph,
        storage,
        policy,
    } = search;
    let block = function.get_block(block_addr)?;
    // A block already on this path was scanned up to the boundary it was
    // entered at; a back edge asks about the rest of it. What that rest
    // defines reaches the boundary round the loop, and what it does not
    // define leaves the path saying nothing new.
    let scanned_from = visited.get(&block_addr).copied();
    let scan_start = scanned_from.unwrap_or(0);
    if scanned_from.is_some_and(|scanned| boundary_op_index <= scanned) {
        return Some(ReachingAbiPath::Cycle);
    }
    let mut path_visited = visited.clone();
    path_visited.insert(block_addr, boundary_op_index);
    r2il::refusal_evidence!(
        "reaching-abi-value",
        "walk ({block_addr:#x}, {scan_start}..{boundary_op_index}) of {} ops for {storage:?}",
        block.ops.len()
    );
    for (op_index, op) in block
        .ops
        .get(scan_start..boundary_op_index)?
        .iter()
        .enumerate()
        .map(|(index, op)| (scan_start + index, op))
        .rev()
    {
        // A call's clobbers are the `CallDefine`s that follow it, each a
        // definition the overlap check below sees; the call itself is a
        // barrier only for the carrier the transfer moves.
        //
        // A user operation is a barrier for every register. The operation is
        // one the specification could not express in p-code, so what it writes
        // is not limited to the output it names: `dmb` writes nothing and
        // `cpuid` writes four registers it never mentions, and nothing here
        // tells them apart. Trusting the class cost this walk its soundness --
        // it kept a return boundary over a userop that may have moved the
        // stack pointer, which is a fact claimed about the program that the
        // program does not support.
        //
        // The nine `libarm.so` functions that a barrier before their return
        // costs are recovered by modelling the barrier in the lift, so that it
        // stops being a `CallOther` at all, rather than by widening what a
        // `CallOther` is assumed not to do.
        if policy.calls_are_barriers
            && (matches!(op, SSAOp::CallOther { .. } | SSAOp::Return { .. })
                || (matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
                    && policy
                        .transfer_carrier
                        .is_some_and(|carrier| register_storages_overlap(carrier, storage))))
        {
            r2il::refusal_evidence!(
                "reaching-abi-value",
                "({block_addr:#x}, {op_index}) is a barrier for {storage:?}: {op:?}"
            );
            return None;
        }
        if op.dst().is_none() {
            continue;
        }
        let Some(producer) = graph.inst_id_for_op_site(block_addr, op_index) else {
            continue;
        };
        let Some(dst_storage) = graph.inst(producer).and_then(|inst| inst.canonical_storage) else {
            // A definition with no canonical storage is invisible to this
            // walk, and the walk then answers with an older definition or the
            // entry carrier as if nothing had been written here. Say so.
            r2il::refusal_evidence!(
                "reaching-abi-value",
                "({block_addr:#x}, {op_index}) defines {:?} with no canonical storage; skipped while looking for {storage:?}",
                op.dst()
            );
            continue;
        };
        if !register_storages_overlap(dst_storage, storage) {
            continue;
        }
        if dst_storage != storage {
            // A call defines every clobbered carrier and every alias of it
            // as one event: `CallDefine RAX` and `CallDefine EAX` are the
            // same clobber seen at two widths, not a full write followed by a
            // partial one. The alias is skipped so the walk reaches the
            // carrier's own definition in the same group.
            if matches!(op, SSAOp::CallDefine { .. })
                && contained_register_storage_offset(storage, dst_storage).is_some()
            {
                continue;
            }
            // A lane write into the root: the value at the boundary is the
            // inserted value when the lane is the storage wanted, an older
            // definition when the lane is beside it.
            if let SSAOp::Insert(insert) = op
                && contained_register_storage_offset(dst_storage, storage).is_some()
                && let Some(lsb_bits) = insert.position.constant_bits()
            {
                let lane = CanonicalStorageId {
                    space: dst_storage.space,
                    offset: dst_storage.offset + lsb_bits / 8,
                    size: insert.value.size,
                };
                if lane == storage {
                    r2il::refusal_evidence!(
                        "reaching-abi-value",
                        "({block_addr:#x}, {op_index}) inserts {storage:?} into {dst_storage:?}"
                    );
                    return graph
                        .inst(producer)
                        .and_then(|inst| inst.inputs.get(1).copied())
                        .map(|value| ReachingAbiPath::Reaches(ReachingAbiState::Value(value)));
                }
                if lsb_bits % 8 == 0 && !register_storages_overlap(lane, storage) {
                    continue;
                }
            }
            // A later overlapping slice means an older exact-width definition
            // is not the value at this boundary. Generic boundary recovery has
            // no implicit register-merge semantics, so it must fail closed.
            r2il::refusal_evidence!(
                "reaching-abi-value",
                "({block_addr:#x}, {op_index}) writes {:?}, a slice of the {:?} wanted: {op:?}",
                dst_storage,
                storage
            );
            return None;
        }
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "({block_addr:#x}, {op_index}) defines {storage:?}: {:?}",
            graph.inst(producer).and_then(|inst| inst.output)
        );
        return graph
            .inst(producer)
            .and_then(|inst| inst.output)
            .map(|value| ReachingAbiPath::Reaches(ReachingAbiState::Value(value)));
    }
    if scanned_from.is_some() {
        return Some(ReachingAbiPath::Cycle);
    }
    let phi_insts = block
        .phis
        .iter()
        .filter(|phi| phi.canonical_storage == Some(storage))
        .filter_map(|phi| graph.value_id_for_var(&phi.dst))
        .filter_map(|value| graph.def_inst(value))
        .collect::<Vec<_>>();
    if let [phi_inst] = phi_insts.as_slice() {
        let phi = graph.inst(*phi_inst)?;
        if policy.allow_distinct_phi_inputs {
            return phi
                .output
                .map(|value| ReachingAbiPath::Reaches(ReachingAbiState::Value(value)));
        }
        let [first, rest @ ..] = phi.inputs.as_slice() else {
            return None;
        };
        if rest.iter().all(|input| input == first) {
            return Some(ReachingAbiPath::Reaches(ReachingAbiState::Value(*first)));
        }
        // A merge of the transfer carrier whose every input is the entry's
        // own stack pointer is that pointer: an early return that never
        // built the frame meets the epilogue that has unwound it.
        if policy.stack_pointer == Some(storage)
            && phi
                .inputs
                .iter()
                .all(|input| value_is_entry_stack_pointer(function, graph, *input, storage))
        {
            return Some(ReachingAbiPath::Reaches(ReachingAbiState::PreservedEntry));
        }
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "{block_addr:#x} merges {storage:?} from inputs that disagree: {:?}",
            phi.inputs
        );
        return None;
    }
    if !phi_insts.is_empty() {
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "{block_addr:#x} has {} phis for {storage:?}",
            phi_insts.len()
        );
        return None;
    }
    let predecessors = function.predecessors(block_addr);
    let mut values = Vec::new();
    // The entry is one way in whatever loops come back to it: the value the
    // function was entered with reaches its first boundary alongside what
    // any back edge carries.
    if graph.block_by_addr.get(&block_addr) == Some(&graph.entry) {
        let candidates = graph
            .values
            .iter()
            .filter(|value| {
                graph.def_inst(value.id).is_none()
                    && value.var.version == 0
                    && value.var.size == storage.size
                    && value.canonical_storage == Some(storage)
            })
            .map(|value| value.id)
            .collect::<Vec<_>>();
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "{storage:?} reaches the entry from {block_addr:#x}: {} entry candidates",
            candidates.len()
        );
        values.push(match candidates.as_slice() {
            [value] => ReachingAbiState::Value(*value),
            [] => ReachingAbiState::PreservedEntry,
            _ => return None,
        });
    } else if predecessors.is_empty() {
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "{block_addr:#x} has no predecessors and is not the entry"
        );
        return None;
    }
    for predecessor in &predecessors {
        match reaching_abi_value_at_end(search, *predecessor, &path_visited, memo)? {
            ReachingAbiPath::Reaches(state) => values.push(state),
            ReachingAbiPath::Cycle => {}
        }
    }
    let [first, rest @ ..] = values.as_slice() else {
        // Every way in came round a loop: this block is reachable only
        // through itself, and nothing outside it defined the storage.
        return Some(ReachingAbiPath::Cycle);
    };
    if !rest.iter().all(|value| value == first) {
        r2il::refusal_evidence!(
            "reaching-abi-value",
            "{block_addr:#x} has no phi for {:?} and its predecessors disagree: {:?}",
            storage,
            values
        );
        return None;
    }
    Some(ReachingAbiPath::Reaches(*first))
}

/// Whether `value` is the stack pointer the function was entered with: the
/// entry value itself, or one the geometry roots at the entry pointer with no
/// offset.
pub(crate) fn value_is_entry_stack_pointer(
    function: &SSAFunction,
    graph: &SsaGraph,
    value: ValueId,
    storage: CanonicalStorageId,
) -> bool {
    let Some(graph_value) = graph.value(value) else {
        return false;
    };
    if graph.def_inst(value).is_none()
        && graph_value.var.version == 0
        && graph_value.canonical_storage == Some(storage)
    {
        return true;
    }
    function
        .decompile_prep_facts()
        .and_then(|facts| facts.entry_stack_address_root_of(&graph_value.var))
        .is_some_and(|root| root.base == StackAddressBase::StackPointer && root.offset == 0)
}

pub(crate) fn register_storages_overlap(
    left: CanonicalStorageId,
    right: CanonicalStorageId,
) -> bool {
    if left.space != CanonicalStorageSpace::Register
        || right.space != CanonicalStorageSpace::Register
    {
        return false;
    }
    let Some(left_end) = left.offset.checked_add(u64::from(left.size)) else {
        return true;
    };
    let Some(right_end) = right.offset.checked_add(u64::from(right.size)) else {
        return true;
    };
    left.offset < right_end && right.offset < left_end
}

pub(crate) fn contained_register_storage_offset(
    container: CanonicalStorageId,
    contained: CanonicalStorageId,
) -> Option<u32> {
    if container.space != CanonicalStorageSpace::Register
        || contained.space != CanonicalStorageSpace::Register
        || contained.size == 0
        || contained.size >= container.size
        || contained.offset < container.offset
    {
        return None;
    }
    let container_end = container.offset.checked_add(u64::from(container.size))?;
    let contained_end = contained.offset.checked_add(u64::from(contained.size))?;
    if contained_end > container_end {
        return None;
    }
    u32::try_from(contained.offset.checked_sub(container.offset)?).ok()
}

/// The one widest call-defined view of a convention result that the caller
/// actually reads.
///
/// This is deliberately narrower than general alias recovery. Candidates are
/// only the consecutive `CallDefine` operations emitted for this exact call,
/// only exact or structurally contained register storage is admitted, and a
/// tie at the widest observed width refuses. The scan is bounded by the
/// architecture's call-clobber list rather than by the function size.
pub(crate) fn observed_convention_call_result_after_call(
    function: &SSAFunction,
    graph: &SsaGraph,
    live_out: &crate::liveout::FunctionLiveOut,
    block_addr: u64,
    call_op_index: usize,
    convention_storage: CanonicalStorageId,
) -> Option<CallBoundaryValueFact> {
    let block = function.get_block(block_addr)?;
    let candidates = block
        .ops
        .get(call_op_index.checked_add(1)?..)?
        .iter()
        .enumerate()
        .take_while(|(_, op)| matches!(op, SSAOp::CallDefine { .. }))
        .filter_map(|(relative_index, op)| {
            let SSAOp::CallDefine { dst } = op else {
                return None;
            };
            let inst = graph.inst_id_for_op_site(
                block_addr,
                call_op_index.checked_add(1)?.checked_add(relative_index)?,
            )?;
            let graph_inst = graph.inst(inst)?;
            let storage = graph_inst.canonical_storage?;
            if storage != convention_storage
                && contained_register_storage_offset(convention_storage, storage).is_none()
            {
                return None;
            }
            let value = graph_inst.output?;
            // The caller of this body is a reader too, and the use list alone cannot see it.
            if dst.size != storage.size || !crate::liveout::is_read(graph, live_out, value) {
                return None;
            }
            Some(CallBoundaryValueFact {
                slot: CallBoundarySlot::Register { index: 0, storage },
                value,
            })
        })
        .collect::<Vec<_>>();
    let widest = candidates
        .iter()
        .map(|candidate| match candidate.slot {
            CallBoundarySlot::Register { storage, .. } => storage.size,
            CallBoundarySlot::Stack(_) => 0,
        })
        .max()?;
    let mut widest_candidates = candidates.into_iter().filter(|candidate| {
        matches!(candidate.slot, CallBoundarySlot::Register { storage, .. } if storage.size == widest)
    });
    let selected = widest_candidates.next()?;
    widest_candidates.next().is_none().then_some(selected)
}

pub(crate) fn entry_storage_state(
    graph: &SsaGraph,
    storage: CanonicalStorageId,
) -> ReachingStorageState {
    let candidates = graph
        .values
        .iter()
        .filter(|value| {
            graph.def_inst(value.id).is_none()
                && value.var.version == 0
                && value.var.size == storage.size
                && value.canonical_storage == Some(storage)
        })
        .map(|value| value.id)
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [value] => ReachingStorageState::Value(*value),
        [] => ReachingStorageState::PreservedEntry,
        _ => ReachingStorageState::Conflict,
    }
}

pub(crate) fn storage_phi_value(
    function: &SSAFunction,
    graph: &SsaGraph,
    block_addr: u64,
    storage: CanonicalStorageId,
) -> Result<Option<ValueId>, ()> {
    let block = function.get_block(block_addr).ok_or(())?;
    let values = block
        .phis
        .iter()
        .filter(|phi| phi.canonical_storage == Some(storage))
        .filter_map(|phi| graph.value_id_for_var(&phi.dst))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(()),
    }
}

pub(crate) fn block_entry_storage_state(
    function: &SSAFunction,
    graph: &SsaGraph,
    exits: &BTreeMap<u64, ReachingStorageState>,
    block_addr: u64,
    storage: CanonicalStorageId,
) -> ReachingStorageState {
    if block_addr == function.entry {
        return entry_storage_state(graph, storage);
    }
    let predecessors = function.predecessors(block_addr);
    if predecessors.is_empty() {
        return ReachingStorageState::Conflict;
    }
    let known = predecessors
        .iter()
        .filter_map(|predecessor| exits.get(predecessor).copied())
        .filter(|state| *state != ReachingStorageState::Unknown)
        .collect::<Vec<_>>();
    let Some(first) = known.first().copied() else {
        return ReachingStorageState::Unknown;
    };
    if known.contains(&ReachingStorageState::Conflict) {
        return ReachingStorageState::Conflict;
    }
    match storage_phi_value(function, graph, block_addr, storage) {
        Ok(Some(value)) => ReachingStorageState::Value(value),
        Err(()) => ReachingStorageState::Conflict,
        Ok(None) => {
            if known.iter().all(|state| *state == first) {
                first
            } else {
                ReachingStorageState::Conflict
            }
        }
    }
}

pub(crate) fn transfer_storage_state(
    graph: &SsaGraph,
    block_addr: u64,
    op_index: usize,
    storage: CanonicalStorageId,
    state: ReachingStorageState,
) -> ReachingStorageState {
    let Some(inst) = graph
        .inst_id_for_op_site(block_addr, op_index)
        .and_then(|inst| graph.inst(inst))
    else {
        return ReachingStorageState::Conflict;
    };
    let Some(written) = inst.canonical_storage else {
        return state;
    };
    if !register_storages_overlap(written, storage) {
        return state;
    }
    if written != storage {
        return ReachingStorageState::Conflict;
    }
    inst.output
        .map(ReachingStorageState::Value)
        .unwrap_or(ReachingStorageState::Conflict)
}

/// Resolve one exact storage state at every source instruction with a sorted
/// fixpoint. A recursive predecessor walk cannot prove an unchanged value
/// through a loop backedge: revisiting the header looks like ambiguity even
/// when SSA carries one definition around the cycle. The finite state above
/// only moves from unknown to an exact answer or conflict, so the worklist is
/// deterministic and each block is revisited only when a predecessor answer
/// changes.
pub(crate) fn reaching_storage_states_before(
    function: &SSAFunction,
    graph: &SsaGraph,
    storage: CanonicalStorageId,
) -> BTreeMap<InstId, ReachingStorageState> {
    let block_addrs = function.block_addrs().to_vec();
    let mut exits = block_addrs
        .iter()
        .copied()
        .map(|addr| (addr, ReachingStorageState::Unknown))
        .collect::<BTreeMap<_, _>>();
    let mut pending = block_addrs.iter().copied().collect::<BTreeSet<_>>();
    while let Some(block_addr) = pending.pop_first() {
        let mut state = block_entry_storage_state(function, graph, &exits, block_addr, storage);
        let Some(block) = function.get_block(block_addr) else {
            exits.insert(block_addr, ReachingStorageState::Conflict);
            continue;
        };
        for op_index in 0..block.ops.len() {
            state = transfer_storage_state(graph, block_addr, op_index, storage, state);
        }
        if exits.get(&block_addr).copied() == Some(state) {
            continue;
        }
        exits.insert(block_addr, state);
        pending.extend(function.successors(block_addr));
    }

    let mut before = BTreeMap::new();
    for block_addr in block_addrs {
        let mut state = block_entry_storage_state(function, graph, &exits, block_addr, storage);
        let Some(block) = function.get_block(block_addr) else {
            continue;
        };
        for op_index in 0..block.ops.len() {
            if let Some(inst) = graph.inst_id_for_op_site(block_addr, op_index) {
                before.insert(inst, state);
            }
            state = transfer_storage_state(graph, block_addr, op_index, storage, state);
        }
    }
    before
}

/// The gap from a frame object up to the next one the frame lays out above
/// it, or to the entry stack pointer when it is the topmost: the extent of a
/// buffer that only a callee ever fills.
/// The frame positions an object is proven to start at.
///
/// A declared slot starts one; so does a direct access, an address that
/// leaves the function as a value -- through a call, or stored into memory --
/// a position the stack pointer itself takes, and the base of an indexed
/// access unless that base is itself a place inside another object.
/// A position that is only ever displaced from is not one.
/// How far a callee is proven to write through a frame address it is
/// handed: the bytes a modelled import fills from a length argument that is
/// a constant at the call. Those bytes are one object, whatever this body
/// later reads of them one at a time.
pub(crate) fn callee_write_spans(
    facts: &DecompilePrepFacts,
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    values: &crate::values::ValueRanges,
) -> Vec<(StackAddressRoot, i64)> {
    let Some(machine_context) = machine_context else {
        return Vec::new();
    };
    let registers = machine_context.abi_model().argument_registers();
    let mut reaching =
        BTreeMap::<CanonicalStorageId, BTreeMap<InstId, ReachingStorageState>>::new();
    let mut spans = Vec::new();
    for block in function.blocks() {
        for (op_idx, op) in block.ops.iter().enumerate() {
            let SSAOp::Call {
                target,
                instruction: Some(instruction),
            } = op
            else {
                continue;
            };
            let Some(name) = machine_context
                .raw_call_site_at(*instruction)
                .and_then(|identity| machine_context.callee_name(identity))
            else {
                continue;
            };
            let id = crate::interproc::InterprocFunctionId(
                resolve_graph_literal_value(graph, Some(facts), target).unwrap_or(0),
            );
            let Some(call) = graph.inst_id_for_op_site(block.addr, op_idx) else {
                continue;
            };
            let mut argument = |index: usize| -> Option<&SSAVar> {
                let storage = registers
                    .iter()
                    .find(|slot| slot.index() as usize == index)?
                    .storage();
                let states = reaching
                    .entry(storage)
                    .or_insert_with(|| reaching_storage_states_before(function, graph, storage));
                match states.get(&call)? {
                    ReachingStorageState::Value(value) => {
                        graph.value(*value).map(|value| &value.var)
                    }
                    _ => None,
                }
            };
            // A callee taken with this capture says how far it reaches through
            // each pointer it is handed. The bytes it covers are one object,
            // whatever this body reads of them afterwards, and the fact is
            // available here because the callee's body was read before this
            // one was prepared.
            if let Some(target) = resolve_graph_literal_value(graph, Some(facts), target)
                && let Some(reach) = machine_context.callee_argument_reach(target)
            {
                for (index, proven) in reach {
                    let Some(root) =
                        argument(*index).and_then(|var| resolve_stack_root(Some(facts), var))
                    else {
                        continue;
                    };
                    // A reach stated per index is multiplied out here, where
                    // the value this body passes for that index is known and
                    // the loop that drives it has a proven bound.
                    let mut bound = |scaling: usize| {
                        let var = argument(scaling)?;
                        let value = graph.value_id_for_var(var)?;
                        // What the index can be bounds how far the call
                        // reaches, which is how one that names a single
                        // element reaches exactly that far.
                        values
                            .upper_bound(value)
                            .or_else(|| values.upper_bound(crate::constant::root_of(graph, value)))
                            .or_else(|| crate::constant::folded_value(graph, value))
                    };
                    let Some(end) = proven
                        .bytes(&mut bound)
                        .and_then(|bytes| i64::try_from(bytes).ok())
                        .and_then(|bytes| root.offset.checked_add(bytes))
                    else {
                        r2il::refusal_evidence!(
                            "callee-write-span",
                            "{name} at {instruction:#x} reaches argument {index} at {root:?} by {proven:?}, unbounded here"
                        );
                        continue;
                    };
                    r2il::refusal_evidence!(
                        "callee-write-span",
                        "{name} at {instruction:#x} reaches argument {index} at {root:?} up to {end} by {proven:?}"
                    );
                    spans.push((root, end));
                }
            }
            let Some(seed) =
                crate::interproc::FunctionSemanticSummary::seed_for_callee_name(id, name)
            else {
                continue;
            };
            for transfer in &seed.transfer_effects {
                let crate::interproc::SummaryMemoryRegion::Arg { index } = transfer.dst.region
                else {
                    continue;
                };
                let Some(root) =
                    argument(index).and_then(|var| resolve_stack_root(Some(facts), var))
                else {
                    continue;
                };
                let length = match transfer.len {
                    crate::interproc::SummaryTransferLength::Const(length) => Some(length),
                    crate::interproc::SummaryTransferLength::Arg(length) => argument(length)
                        .and_then(|var| resolve_graph_literal_value(graph, Some(facts), var)),
                    crate::interproc::SummaryTransferLength::Unknown => None,
                };
                let Some(end) = length
                    .and_then(|length| i64::try_from(length).ok())
                    .and_then(|length| root.offset.checked_add(length))
                else {
                    continue;
                };
                r2il::refusal_evidence!(
                    "callee-write-span",
                    "{name} at {instruction:#x} writes argument {index} at {root:?} up to {end}"
                );
                spans.push((root, end));
            }
        }
    }
    spans
}

pub(crate) fn evidenced_stack_roots(
    facts: &DecompilePrepFacts,
    declared_slots: &DeclaredStackSlots,
    function: &SSAFunction,
    graph: &SsaGraph,
    stack_pointer_carrier: Option<CanonicalStorageId>,
    values: &crate::values::ValueRanges,
    callee_write_spans: &BTreeMap<StackAddressRoot, i64>,
) -> EvidencedStackRoots {
    let mut roots = BTreeSet::new();
    let exact_root = |var: &SSAVar| resolve_stack_root(Some(facts), var);
    let definition = |var: &SSAVar| {
        graph
            .value_id_for_var(var)
            .and_then(|value| graph.def_inst(value))
            .and_then(|inst| graph.inst(inst))
    };
    // The address a constant displacement was measured from, where it was.
    let displaced_from = |var: &SSAVar| match definition(var).map(|inst| &inst.payload) {
        Some(InstPayload::Op(SSAOp::IntAdd { a, b, .. })) => {
            let (base, delta) = if a.constant_bits().is_some() {
                (b, a)
            } else {
                (a, b)
            };
            (delta.constant_bits().is_some() && exact_root(base).is_some()).then(|| base.clone())
        }
        Some(InstPayload::Op(SSAOp::IntSub { a, b, .. })) => {
            (b.constant_bits().is_some() && exact_root(a).is_some()).then(|| a.clone())
        }
        _ => None,
    };
    // A position measured from an object is inside it, not the start of
    // another: `buf + 8` is a place in `buf`. A position measured from a
    // frame base is how the frame names a local, whichever way the
    // displacement runs -- every `rbp`-relative local is a negative one, and
    // asking the sign instead excluded every local on a frame-pointer
    // machine. The frame base is what a register carries; a place inside an
    // object is what a temporary holds.
    let interior_position = |var: &SSAVar| {
        displaced_from(var).is_some_and(|parent| graph.canonical_storage_for_var(&parent).is_none())
    };
    for block in function.blocks() {
        for op in &block.ops {
            match op {
                SSAOp::IntAdd { dst, a, b } | SSAOp::IntSub { dst, a, b } => {
                    if stack_pointer_carrier.is_some()
                        && graph.canonical_storage_for_var(dst) == stack_pointer_carrier
                        && let Some(root) = exact_root(dst)
                    {
                        roots.insert(root);
                    }
                    if facts.indexed_stack_address_root_of(dst).is_some()
                        && matches!(op, SSAOp::IntAdd { .. })
                    {
                        // The first byte an index reaches is the object's
                        // start: `buf[i - 1]` addressed from one below `buf`
                        // starts `buf`, not the byte below it.
                        let first_reached = |index: &SSAVar| {
                            graph
                                .value_id_for_var(index)
                                .and_then(|index| values.lower_bound(index))
                                .and_then(|lower| i64::try_from(lower).ok())
                                .unwrap_or(0)
                        };
                        for (base, index) in [(a, b), (b, a)] {
                            // Which operand of an indexed address became an
                            // object start, and why the other did not, is what
                            // says where a buffer's accesses will be filed.
                            r2il::refusal_evidence!(
                                "indexed-base-root",
                                "{} + {}: base {} root={:?} interior={}",
                                a.display_name(),
                                b.display_name(),
                                base.display_name(),
                                exact_root(base),
                                interior_position(base)
                            );
                            if let Some(root) = exact_root(base)
                                && !interior_position(base)
                            {
                                roots.insert(StackAddressRoot {
                                    base: root.base,
                                    offset: root.offset.saturating_add(first_reached(index)),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for slot in declared_slots.by_key.values() {
        roots.insert(StackAddressRoot {
            base: slot.base(),
            offset: slot.offset(),
        });
    }
    for block in function.blocks() {
        for op in &block.ops {
            let addr = match op {
                SSAOp::Load { addr, space, .. }
                | SSAOp::Store { addr, space, .. }
                | SSAOp::LoadLinked { addr, space, .. }
                | SSAOp::StoreConditional { addr, space, .. }
                | SSAOp::LoadGuarded { addr, space, .. }
                | SSAOp::StoreGuarded { addr, space, .. }
                    if *space == SpaceId::Ram =>
                {
                    addr
                }
                SSAOp::AtomicCAS(swap) if swap.space == SpaceId::Ram => &swap.addr,
                _ => continue,
            };
            if let Some(root) = resolve_stack_root(Some(facts), addr) {
                roots.insert(root);
            }
        }
    }
    // How far each root's indexed accesses reach: the base's position plus
    // what the index can reach plus the width read there. A position inside
    // that span is a place in the buffer, not the start of another object,
    // and treating it as one splits a buffer a vectoriser touched at fixed
    // offsets into fragments nothing is proven to write.
    let mut spans = BTreeMap::<StackAddressRoot, i64>::new();
    for block in function.blocks() {
        for (at, op) in block.ops.iter().enumerate() {
            let (addr, width) = match op {
                SSAOp::Load {
                    addr, dst, space, ..
                } if *space == SpaceId::Ram => (addr, dst.size),
                SSAOp::Store {
                    addr, val, space, ..
                } if *space == SpaceId::Ram => (addr, val.size),
                _ => continue,
            };
            // An access of its own width at an exact place proves those bytes
            // are one object: nothing writes eight bytes across two locals
            // that are both live, so a position inside what it covers is a
            // member of what it wrote rather than a neighbour. A struct
            // written by one wide store and read back a member at a time was
            // four objects, three of them read and never written.
            if let Some(root) = resolve_stack_root(Some(facts), addr)
                && let Some(end) = root.offset.checked_add(i64::from(width))
            {
                spans
                    .entry(root)
                    .and_modify(|known| *known = (*known).max(end))
                    .or_insert(end);
            }
            let Some(root) = facts.indexed_stack_address_root_of(addr) else {
                continue;
            };
            let Some(index) = graph
                .value_id_for_var(addr)
                .and_then(|address| object_index_operand(facts, graph, address))
            else {
                continue;
            };
            let Some(bound) = values.upper_bound(index) else {
                continue;
            };
            let Ok(reach) = i64::try_from(bound.saturating_add(u64::from(width))) else {
                continue;
            };
            let end = root.offset.saturating_add(reach);
            // What each indexed access contributes to its root's span is what
            // says whether a neighbour was swallowed by a bound or by a reach.
            r2il::refusal_evidence!(
                "indexed-span-reach",
                "{:#x}:{at} {root:?} index={index:?} bound={bound} width={width} end={end}",
                block.addr
            );
            let first = values
                .lower_bound(index)
                .and_then(|lower| i64::try_from(lower).ok())
                .unwrap_or(0);
            let start = StackAddressRoot {
                base: root.base,
                offset: root.offset.saturating_add(first),
            };
            spans
                .entry(start)
                .and_modify(|known| *known = (*known).max(end))
                .or_insert(end);
        }
    }
    for (start, end) in callee_write_spans {
        spans
            .entry(*start)
            .and_modify(|known| *known = (*known).max(*end))
            .or_insert(*end);
    }
    roots.retain(|root| {
        let inside = spans.iter().any(|(base, end)| {
            base.base == root.base && base.offset < root.offset && root.offset < *end
        });
        if inside {
            r2il::refusal_evidence!(
                "indexed-span-absorbs",
                "{root:?} is a place inside a span an index reaches: {spans:?}"
            );
        }
        !inside
    });
    let mut escaping = BTreeSet::new();
    for (var, root) in &facts.stack_address_roots {
        let Some(value) = graph.value_id_for_var(var) else {
            continue;
        };
        let escapes = graph.use_sites(value).iter().any(|site| {
            graph
                .inst(site.inst)
                .is_some_and(|inst| match &inst.payload {
                    InstPayload::Op(SSAOp::CallUse { .. }) => true,
                    InstPayload::Op(
                        SSAOp::Store { .. }
                        | SSAOp::StoreConditional { .. }
                        | SSAOp::StoreGuarded { .. },
                    ) => site.input_idx != 0,
                    _ => false,
                })
        });
        if escapes {
            roots.insert(*root);
            escaping.insert(*root);
        }
    }
    EvidencedStackRoots {
        roots,
        spans,
        escaping,
    }
}

/// The operand of an indexed address that supplies the index.
///
/// The same question `ObjectModel::index_for_address` answers, asked before
/// the object model exists: of a sum, the side that is not the stack address.
pub(crate) fn object_index_operand(
    facts: &DecompilePrepFacts,
    graph: &SsaGraph,
    address: ValueId,
) -> Option<ValueId> {
    let inst = graph.inst(graph.def_inst(address)?)?;
    let InstPayload::Op(SSAOp::IntAdd { a, b, .. }) = &inst.payload else {
        return None;
    };
    let rooted = |var: &SSAVar| resolve_stack_root(Some(facts), var).is_some();
    match (rooted(a), rooted(b)) {
        (true, false) => graph.value_id_for_var(b),
        (false, true) => graph.value_id_for_var(a),
        _ => None,
    }
}

/// The analysis before one has been solved: nothing is bounded.
pub(crate) fn empty_value_ranges() -> &'static crate::values::ValueRanges {
    static EMPTY: std::sync::OnceLock<crate::values::ValueRanges> = std::sync::OnceLock::new();
    EMPTY.get_or_init(crate::values::ValueRanges::default)
}

/// One member's source: a constant assembled from its bytes, or one value
/// whose whole width lands on it in order.
pub(crate) fn member_run_source(slice: &[ByteSource]) -> Option<MemberRunSource> {
    if let Some(bits) = slice
        .iter()
        .enumerate()
        .try_fold(0_u64, |bits, (index, byte)| match byte {
            ByteSource::Constant(value) => {
                Some(bits | (u64::from(*value)).checked_shl(u32::try_from(index).ok()? * 8)?)
            }
            ByteSource::Lane { .. } => None,
        })
    {
        return Some(MemberRunSource::Constant(bits));
    }
    let ByteSource::Lane { value, byte: 0 } = *slice.first()? else {
        return None;
    };
    slice
        .iter()
        .enumerate()
        .all(|(index, byte)| {
            matches!(byte, ByteSource::Lane { value: lane, byte } if *lane == value && *byte as usize == index)
        })
        .then_some(MemberRunSource::Lane(value))
}

pub(crate) fn insert_loop_carrier_member_role(
    rows: &mut LoopCarrierMemberRoles,
    value: ValueId,
    role: LoopCarrierMemberRole,
) -> bool {
    rows.entry(value).or_default().insert(role)
}

pub(crate) fn insert_loop_carrier_peer_roles(
    rows: &mut LoopCarrierMemberRoles,
    peer: &LoopCarrierPeerCandidate,
) {
    insert_loop_carrier_member_role(rows, peer.phi, LoopCarrierMemberRole::ProjectedPeer);
    for entry in &peer.entries {
        insert_loop_carrier_member_role(rows, entry.value, LoopCarrierMemberRole::Entry);
        insert_loop_carrier_member_role(rows, entry.value, LoopCarrierMemberRole::ProjectedPeer);
    }
    for update in &peer.updates {
        insert_loop_carrier_member_role(rows, update.value, LoopCarrierMemberRole::LatchUpdate);
        insert_loop_carrier_member_role(rows, update.value, LoopCarrierMemberRole::ProjectedPeer);
        for identity in &update.identity_values {
            insert_loop_carrier_member_role(rows, *identity, LoopCarrierMemberRole::UpdateIdentity);
            insert_loop_carrier_member_role(rows, *identity, LoopCarrierMemberRole::ProjectedPeer);
        }
    }
}

pub(crate) fn loop_carrier_peer_candidates(
    graph: &SsaGraph,
    header: u64,
    latches: &BTreeSet<u64>,
) -> Vec<LoopCarrierPeerCandidate> {
    let Some(header_block) = graph
        .block_id_for_addr(header)
        .and_then(|block| graph.block(block))
    else {
        return Vec::new();
    };
    let mut candidates = header_block
        .insts
        .iter()
        .filter_map(|inst_id| {
            let inst = graph.inst(*inst_id)?;
            let InstPayload::Phi { predecessors } = &inst.payload else {
                return None;
            };
            let phi = inst.output?;
            let width = graph.value(phi)?.var.size;
            if predecessors.len() != inst.inputs.len() || inst.inputs.is_empty() {
                return None;
            }
            let mut entries = Vec::new();
            let mut updates = Vec::new();
            for (input_idx, (predecessor, value)) in predecessors
                .iter()
                .copied()
                .zip(inst.inputs.iter().copied())
                .enumerate()
            {
                let predecessor = graph.block(predecessor)?.addr;
                let site = UseSite {
                    inst: *inst_id,
                    input_idx,
                };
                let edge = LoopCarrierEdgeValue {
                    predecessor,
                    value,
                    site,
                };
                if !edge.validate(graph) {
                    return None;
                }
                if latches.contains(&predecessor) {
                    updates.push(LoopCarrierUpdateFact {
                        predecessor,
                        value,
                        site,
                        identity_values: exact_copy_identity_values(graph, value),
                    });
                } else {
                    entries.push(edge);
                }
            }
            if entries.is_empty() || updates.is_empty() {
                return None;
            }
            entries.sort_unstable();
            entries.dedup();
            updates.sort_unstable();
            updates.dedup();
            Some(LoopCarrierPeerCandidate {
                phi,
                width,
                entries,
                updates,
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.phi);
    candidates.dedup_by_key(|candidate| candidate.phi);
    candidates
}

pub(crate) fn exact_loop_carrier_register_storage(
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    value: ValueId,
) -> Option<CanonicalStorageId> {
    if machine_context.register_geometry_state() != MachineRegisterGeometryState::Available {
        return None;
    }
    let written = graph.value(value)?.canonical_storage?;
    if written.space != CanonicalStorageSpace::Register {
        return None;
    }
    let projection = machine_context.register_projection(written)?;
    if projection.written.offset != written.offset || projection.written.size != written.size {
        return None;
    }
    let r2il::RegisterProjectionDisposition::Bound { carrier, .. } = projection.disposition else {
        return None;
    };
    Some(CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: carrier.offset,
        size: carrier.size,
    })
}

pub(crate) fn loop_carrier_projection_key(
    graph: &SsaGraph,
    storage_spans: &StorageSpans,
    machine_context: &SourceMachineContext,
    candidate: &LoopCarrierPeerCandidate,
) -> Option<(CanonicalStorageId, crate::span::SpanId, Vec<u64>, Vec<u64>)> {
    let carrier = exact_loop_carrier_register_storage(graph, machine_context, candidate.phi)?;
    let state = std::iter::once(candidate.phi)
        .chain(candidate.updates.iter().flat_map(|update| {
            std::iter::once(update.value).chain(update.identity_values.iter().copied())
        }))
        .collect::<BTreeSet<_>>();
    if !storage_spans.all_one_span(state.iter().copied()) {
        return None;
    }
    let span = storage_spans.span_of(candidate.phi)?;
    let entry_predecessors = candidate
        .entries
        .iter()
        .map(|edge| edge.predecessor)
        .collect::<Vec<_>>();
    let update_predecessors = candidate
        .updates
        .iter()
        .map(|update| update.predecessor)
        .collect::<Vec<_>>();
    Some((carrier, span, entry_predecessors, update_predecessors))
}

pub(crate) fn expand_loop_carrier_storage_continuations(
    graph: &SsaGraph,
    storage_spans: &StorageSpans,
    rows: &mut LoopCarrierMemberRoles,
) -> Option<()> {
    let spans = rows
        .keys()
        .copied()
        .map(|value| storage_spans.span_of(value))
        .collect::<Option<BTreeSet<_>>>()?;
    for span in spans {
        for value in storage_spans.members(span)? {
            let graph_value = graph.value(*value)?;
            if graph_value.var.is_const() {
                continue;
            }
            insert_loop_carrier_member_role(
                rows,
                *value,
                LoopCarrierMemberRole::StorageContinuation,
            );
        }
    }
    Some(())
}

pub(crate) fn loop_carrier_member_rows(
    graph: &SsaGraph,
    header: u64,
    latches: &BTreeSet<u64>,
    loop_body: &BTreeSet<u64>,
    storage_spans: &StorageSpans,
    machine_context: Option<&SourceMachineContext>,
    carriers: &[LoopCarrierFact],
) -> Option<Vec<Vec<LoopCarrierMemberFact>>> {
    if carriers
        .iter()
        .any(|carrier| carrier.header != header || !carrier.validate(graph))
    {
        return None;
    }

    let mut rows = carriers
        .iter()
        .map(|carrier| {
            let mut rows = LoopCarrierMemberRoles::new();
            insert_loop_carrier_member_role(
                &mut rows,
                carrier.phi,
                LoopCarrierMemberRole::HeaderPhi,
            );
            for identity in &carrier.identity_values {
                if *identity == carrier.phi {
                    continue;
                }
                let role = graph
                    .def_inst(*identity)
                    .and_then(|inst| graph.inst(inst))
                    .and_then(|inst| graph.block(inst.block))
                    .map(|block| {
                        if loop_body.contains(&block.addr) {
                            LoopCarrierMemberRole::StorageContinuation
                        } else {
                            LoopCarrierMemberRole::PostLoopMerge
                        }
                    })?;
                insert_loop_carrier_member_role(&mut rows, *identity, role);
            }
            for entry in &carrier.entries {
                insert_loop_carrier_member_role(
                    &mut rows,
                    entry.value,
                    LoopCarrierMemberRole::Entry,
                );
            }
            for update in &carrier.updates {
                insert_loop_carrier_member_role(
                    &mut rows,
                    update.value,
                    LoopCarrierMemberRole::LatchUpdate,
                );
                for identity in &update.identity_values {
                    insert_loop_carrier_member_role(
                        &mut rows,
                        *identity,
                        LoopCarrierMemberRole::UpdateIdentity,
                    );
                }
            }
            for initializer in &carrier.dominating_initializers {
                insert_loop_carrier_member_role(
                    &mut rows,
                    initializer.value,
                    LoopCarrierMemberRole::DominatingInitializer,
                );
            }
            Some(rows)
        })
        .collect::<Option<Vec<_>>>()?;

    let candidates = loop_carrier_peer_candidates(graph, header, latches);
    let mut leader_by_carrier = (0..carriers.len()).collect::<Vec<_>>();
    if let Some(machine_context) = machine_context {
        let mut candidates_by_key = BTreeMap::<_, Vec<usize>>::new();
        for (index, candidate) in candidates.iter().enumerate() {
            let Some(key) =
                loop_carrier_projection_key(graph, storage_spans, machine_context, candidate)
            else {
                continue;
            };
            candidates_by_key.entry(key).or_default().push(index);
        }
        let carrier_by_phi = carriers
            .iter()
            .enumerate()
            .map(|(index, carrier)| (carrier.phi, index))
            .collect::<BTreeMap<_, _>>();
        for candidate_group in candidates_by_key.values() {
            let Some((leader, leader_candidate)) = candidate_group
                .iter()
                .filter_map(|candidate_index| {
                    let candidate = &candidates[*candidate_index];
                    carrier_by_phi
                        .get(&candidate.phi)
                        .copied()
                        .map(|carrier_index| (carrier_index, *candidate_index))
                })
                .max_by_key(|(carrier_index, candidate_index)| {
                    (
                        candidates[*candidate_index].width,
                        std::cmp::Reverse(carriers[*carrier_index].phi),
                    )
                })
            else {
                continue;
            };
            let leader_width = candidates[leader_candidate].width;
            for candidate_index in candidate_group {
                let candidate = &candidates[*candidate_index];
                if let Some(peer_carrier) = carrier_by_phi.get(&candidate.phi).copied() {
                    leader_by_carrier[peer_carrier] = leader;
                }
                if candidate.width == leader_width {
                    continue;
                }
                insert_loop_carrier_peer_roles(&mut rows[leader], candidate);
                if let Some(peer_carrier) = carrier_by_phi.get(&candidate.phi).copied() {
                    insert_loop_carrier_peer_roles(
                        &mut rows[peer_carrier],
                        &candidates[leader_candidate],
                    );
                }
            }
        }
    }

    for row in &mut rows {
        expand_loop_carrier_storage_continuations(graph, storage_spans, row)?;
    }

    let mut roots_by_span = BTreeMap::<crate::span::SpanId, BTreeSet<usize>>::new();
    for (carrier_index, row) in rows.iter().enumerate() {
        let root = leader_by_carrier[carrier_index];
        if root != carrier_index {
            continue;
        }
        for value in row.keys() {
            roots_by_span
                .entry(storage_spans.span_of(*value)?)
                .or_default()
                .insert(root);
        }
    }

    // Seed the walk with the merges that can match a carrier, not with every
    // merge outside the loop.
    //
    // The body's first act is to look the merge's span up among the carriers'
    // spans and give up on a miss, and almost every merge in a function misses,
    // so the ordered set was built with thousands of entries per loop and
    // emptied again doing nothing. The guards below are the body's own, in its
    // order, so what is skipped here is exactly what it would have skipped.
    let mut pending = BTreeSet::new();
    for inst in &graph.insts {
        let InstPayload::Phi { .. } = &inst.payload else {
            continue;
        };
        let Some(block) = graph.block(inst.block) else {
            continue;
        };
        if block.addr == header || loop_body.contains(&block.addr) {
            continue;
        }
        let output = inst.output?;
        if inst.inputs.len() < 2 {
            continue;
        }
        if !roots_by_span.contains_key(&storage_spans.span_of(output)?) {
            continue;
        }
        pending.insert(inst.id);
    }
    while let Some(inst_id) = pending.pop_first() {
        let inst = graph.inst(inst_id)?;
        let InstPayload::Phi { .. } = &inst.payload else {
            continue;
        };
        let output = inst.output?;
        let block_addr = graph.block(inst.block)?.addr;
        if block_addr == header || loop_body.contains(&block_addr) || inst.inputs.len() < 2 {
            continue;
        }
        let output_span = storage_spans.span_of(output)?;
        let Some(candidate_roots) = roots_by_span.get(&output_span) else {
            continue;
        };
        let output_width = graph.value(output)?.var.size;
        let mut matches = candidate_roots.iter().copied().filter(|root| {
            let row = &rows[*root];
            let all_owned = inst.inputs.iter().all(|input| row.contains_key(input));
            let has_carried_state = inst.inputs.iter().any(|input| {
                row.get(input).is_some_and(|roles| {
                    roles.contains(&LoopCarrierMemberRole::LatchUpdate)
                        || roles.contains(&LoopCarrierMemberRole::UpdateIdentity)
                        || roles.contains(&LoopCarrierMemberRole::PostLoopMerge)
                })
            });
            let has_other_state = inst.inputs.iter().any(|input| {
                row.get(input).is_some_and(|roles| {
                    !roles.contains(&LoopCarrierMemberRole::LatchUpdate)
                        && !roles.contains(&LoopCarrierMemberRole::UpdateIdentity)
                        && !roles.contains(&LoopCarrierMemberRole::PostLoopMerge)
                })
            });
            let carrier = &carriers[*root];
            let width_is_exact = output_width == carrier.width;
            let projected_width_is_exact = !width_is_exact
                && machine_context.is_some_and(|context| {
                    match (
                        exact_loop_carrier_register_storage(graph, context, output),
                        exact_loop_carrier_register_storage(graph, context, carrier.phi),
                    ) {
                        (Some(output), Some(carrier)) => output == carrier,
                        _ => false,
                    }
                });
            all_owned
                && has_carried_state
                && has_other_state
                && (width_is_exact || projected_width_is_exact)
        });
        let Some(root) = matches.next() else {
            continue;
        };
        if matches.next().is_some() {
            continue;
        }
        if insert_loop_carrier_member_role(
            &mut rows[root],
            output,
            LoopCarrierMemberRole::PostLoopMerge,
        ) {
            for site in graph.use_sites(output) {
                if graph.inst(site.inst).is_some_and(|use_inst| {
                    matches!(use_inst.payload, InstPayload::Phi { .. })
                        && graph.block(use_inst.block).is_some_and(|block| {
                            block.addr != header && !loop_body.contains(&block.addr)
                        })
                }) {
                    pending.insert(site.inst);
                }
            }
        }
    }

    Some(
        rows.into_iter()
            .map(|rows| {
                rows.into_iter()
                    .map(|(value, roles)| LoopCarrierMemberFact { value, roles })
                    .collect()
            })
            .collect(),
    )
}

pub(crate) fn exact_copy_identity_values(graph: &SsaGraph, root: ValueId) -> BTreeSet<ValueId> {
    let mut identities = BTreeSet::from([root]);
    let mut pending = vec![root];
    while let Some(value) = pending.pop() {
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        let InstPayload::Op(SSAOp::Copy { dst, src }) = &inst.payload else {
            continue;
        };
        if dst.size != src.size {
            continue;
        }
        let Some(source) = graph.value_id_for_var(src) else {
            continue;
        };
        if identities.insert(source) {
            pending.push(source);
        }
    }
    identities
}

pub(crate) fn loop_condition(
    predicates: &PredicateFacts,
    header: u64,
    body: &BTreeSet<u64>,
    exits: &[u64],
) -> Option<PredicateId> {
    let exit_set = exits.iter().copied().collect::<BTreeSet<_>>();
    predicates
        .predicates
        .values()
        .filter(|predicate| body.contains(&predicate.block_addr))
        .filter(|predicate| {
            (body.contains(&predicate.true_target) && exit_set.contains(&predicate.false_target))
                || (body.contains(&predicate.false_target)
                    && exit_set.contains(&predicate.true_target))
        })
        .min_by_key(|predicate| {
            (
                usize::from(predicate.block_addr != header),
                predicate.block_addr,
                predicate.id,
            )
        })
        .map(|predicate| predicate.id)
}

pub(crate) fn value_depends_on(graph: &SsaGraph, value: ValueId, needle: ValueId) -> bool {
    if value == needle {
        return true;
    }
    let mut visited = BTreeSet::new();
    let mut stack = vec![(value, 0usize)];
    while let Some((current, depth)) = stack.pop() {
        if current == needle {
            return true;
        }
        if depth >= 16 || !visited.insert(current) {
            continue;
        }
        let Some(def_inst) = graph.def_inst(current) else {
            continue;
        };
        let Some(inst) = graph.inst(def_inst) else {
            continue;
        };
        for input in &inst.inputs {
            stack.push((*input, depth + 1));
        }
    }
    false
}

pub(crate) fn raw_memory_subeffect_provenance(
    memory: &MemorySSAFacts,
    objects: &ObjectModel,
    inst: InstId,
    access: RawAccess,
) -> RawMemoryProvenance {
    let RawAccess {
        space,
        is_write,
        width,
        ..
    } = access;
    let annotations = if is_write {
        memory
            .defs_by_inst
            .get(&inst)
            .into_iter()
            .flatten()
            .map(|fact| &fact.location)
            .collect::<BTreeSet<_>>()
    } else {
        memory
            .uses_by_inst
            .get(&inst)
            .into_iter()
            .flatten()
            .map(|fact| &fact.location)
            .collect::<BTreeSet<_>>()
    };
    let matching = annotations
        .iter()
        .filter(|location| {
            location.size == width
                && location.space == space
                && objects
                    .object(location.object)
                    .is_some_and(|object| object.kind.space() == space)
        })
        .collect::<Vec<_>>();
    let provenance_complete = annotations.len() == 1 && matching.len() == 1;
    let object = matching
        .first()
        .map(|location| location.object)
        .or_else(|| objects.escaped_unknown_object(space))
        .unwrap_or(ObjectId(0));
    // The one annotation that answered for this access also says where in the
    // object it lands, and it is keyed by the access rather than by an address
    // value, so both sides of the render can ask the same question.
    let object_offset = (matching.len() == 1)
        .then(|| {
            matching
                .first()
                .and_then(|location| location.address.exact_offset())
        })
        .flatten();
    RawMemoryProvenance {
        object,
        object_offset,
        complete: provenance_complete,
    }
}

pub(crate) fn insert_raw_memory_subeffect(
    sink: EffectSink<'_>,
    memory: &MemorySSAFacts,
    objects: &ObjectModel,
    site: AccessSite,
    access: RawAccess,
) {
    let provenance = raw_memory_subeffect_provenance(memory, objects, site.inst, access);
    insert_structured_memory_access(
        sink,
        site,
        access,
        provenance.object,
        provenance.complete,
        provenance.object_offset,
    );
}

pub(crate) fn insert_structured_memory_access(
    sink: EffectSink<'_>,
    site: AccessSite,
    access: RawAccess,
    object: ObjectId,
    provenance_complete: bool,
    object_offset: Option<i64>,
) {
    let AccessSite {
        inst,
        block_addr,
        op_index,
    } = site;
    let RawAccess {
        address,
        space,
        value,
        is_write,
        width,
    } = access;
    let EffectSink { facts, ordinal } = sink;
    let id = StructuredAccessId {
        inst,
        ordinal: *ordinal,
    };
    *ordinal = (*ordinal).saturating_add(1);
    facts.insert(
        id,
        StructuredMemoryAccessFact {
            id,
            block_addr,
            op_index,
            space,
            object,
            address,
            value,
            is_write,
            width,
            provenance_complete,
            object_offset,
        },
    );
}

pub(crate) fn memory_location_for_addr(
    prep_facts: Option<&DecompilePrepFacts>,
    addresses: &AddressProvenanceFacts,
    object_model: &ObjectModel,
    graph: &SsaGraph,
    addr: &SSAVar,
    space: SpaceId,
    size: u32,
) -> MemoryLocation {
    let value_id = graph.value_id_for_var(addr);
    let parameter_expression = (space == SpaceId::Ram)
        .then(|| value_id.and_then(|value| addresses.parameter_expression(value)))
        .flatten();
    let pointee_expression = (space == SpaceId::Ram)
        .then(|| value_id.and_then(|value| addresses.pointee_expression(value)))
        .flatten();
    let object = object_model
        .object_for_var(graph, addr, space)
        .or_else(|| {
            resolve_stack_root(prep_facts, addr).and_then(|root| {
                object_model
                    .stack_objects
                    .get(&StackObjectKey { root, space })
                    .copied()
            })
        })
        .or_else(|| {
            resolve_const_value(prep_facts, addr).and_then(|address| {
                object_model
                    .global_objects
                    .get(&GlobalObjectKey { space, address })
                    .copied()
            })
        })
        .or_else(|| object_model.escaped_unknown_object(space))
        .unwrap_or(ObjectId(0));
    MemoryLocation {
        space,
        object,
        address: parameter_expression
            .map(|expression| (expression.terms.as_slice(), expression.offset))
            .or_else(|| {
                pointee_expression
                    .map(|expression| (expression.terms.as_slice(), expression.offset))
            })
            .map_or_else(
                || {
                    if matches!(
                        object_model.object(object).map(|fact| &fact.kind),
                        Some(ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. })
                            | Some(ObjectKind::Global { .. })
                    ) {
                        // A member sits at its displacement inside the object;
                        // reading every access as offset zero would alias them.
                        RelativeMemoryAddress::Exact(
                            value_id
                                .and_then(|value| object_model.interior_offset(value))
                                .unwrap_or(0),
                        )
                    } else {
                        RelativeMemoryAddress::Unknown
                    }
                },
                |(terms, offset)| {
                    if terms.is_empty() {
                        RelativeMemoryAddress::Exact(offset)
                    } else {
                        RelativeMemoryAddress::Affine {
                            terms: terms.to_vec(),
                            offset,
                        }
                    }
                },
            ),
        size,
    }
}

pub(crate) fn resolve_const_value(facts: Option<&DecompilePrepFacts>, var: &SSAVar) -> Option<u64> {
    let root = canonical_value_root(facts, var);
    const_value(root).or_else(|| const_value(var))
}

pub(crate) fn resolve_graph_literal_value(
    graph: &SsaGraph,
    facts: Option<&DecompilePrepFacts>,
    var: &SSAVar,
) -> Option<u64> {
    let root = canonical_value_root(facts, var);
    let value = graph
        .value_id_for_var(root)
        .or_else(|| graph.value_id_for_var(var))
        .and_then(|id| graph.value(id))?;
    value.var.constant_bits().or_else(|| {
        value.canonical_storage.and_then(|storage| {
            matches!(
                storage.space,
                CanonicalStorageSpace::Constant | CanonicalStorageSpace::Ram
            )
            .then_some(storage.offset)
        })
    })
}

pub(crate) fn resolve_stack_root(
    facts: Option<&DecompilePrepFacts>,
    var: &SSAVar,
) -> Option<StackAddressRoot> {
    let facts = facts?;
    let root = canonical_value_root(Some(facts), var);
    facts
        .stack_address_root_of(var)
        .copied()
        .or_else(|| facts.stack_address_root_of(root).copied())
}

pub(crate) fn resolve_indexed_stack_root(
    facts: Option<&DecompilePrepFacts>,
    var: &SSAVar,
) -> Option<StackAddressRoot> {
    let facts = facts?;
    let root = canonical_value_root(Some(facts), var);
    facts
        .indexed_stack_address_root_of(var)
        .copied()
        .or_else(|| facts.indexed_stack_address_root_of(root).copied())
}

pub(crate) fn resolve_entry_stack_root(
    facts: Option<&DecompilePrepFacts>,
    var: &SSAVar,
) -> Option<StackAddressRoot> {
    let facts = facts?;
    let root = canonical_value_root(Some(facts), var);
    facts
        .entry_stack_address_root_of(var)
        .copied()
        .or_else(|| facts.entry_stack_address_root_of(root).copied())
}

pub(crate) fn canonical_value_root<'a>(
    facts: Option<&'a DecompilePrepFacts>,
    var: &'a SSAVar,
) -> &'a SSAVar {
    facts.map_or(var, |facts| facts.canonical_root(var))
}

pub(crate) fn const_value(var: &SSAVar) -> Option<u64> {
    var.constant_bits()
}
