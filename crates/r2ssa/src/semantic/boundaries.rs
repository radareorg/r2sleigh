//! What crosses a call or a return, and on whose authority.

use super::*;

/// Prove the count of one variadic call from its own literal format.
///
/// The rule naming the format parameter comes from the exact radare2
/// prototype already correlated with this callsite. The literal contents come
/// from the same immutable source snapshot. Register liveness is intentionally
/// absent from this decision: it can prove a requested carrier's value after
/// the count is known, but it cannot decide how many arguments the call made.
pub(crate) fn variadic_callsite_argument_count(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    interface: &r2source::SourceCallSiteInterface,
    fixed_arguments: &[Option<SourceCallArgumentFact>],
    forwarding: &FormatForwardingLookup<'_>,
) -> Result<VariadicCallsiteArgumentCountEvidence, VariadicCallsiteArgumentCountRefusal> {
    let Some(parameter_rule) = interface.format_parameter_rule() else {
        return Err(VariadicCallsiteArgumentCountRefusal::MissingFormatParameter);
    };
    let parameter_index = parameter_rule.parameter_index();
    let format_argument_index = usize::try_from(parameter_index)
        .map_err(|_| VariadicCallsiteArgumentCountRefusal::FormatArgumentUnavailable)?;
    let format_value = fixed_arguments
        .get(format_argument_index)
        .and_then(Option::as_ref)
        .ok_or(VariadicCallsiteArgumentCountRefusal::FormatArgumentUnavailable)?;
    let SourceCallArgumentValue::Value(format_value) = format_value.value else {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "format argument {format_argument_index} is the entry carrier, not a value this function defines"
        );
        return Err(VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral);
    };
    let format_var = graph
        .value(format_value)
        .map(|value| &value.var)
        .ok_or(VariadicCallsiteArgumentCountRefusal::FormatArgumentUnavailable)?;
    // A compiler that merges two `fprintf` calls leaves one call site whose
    // format argument is a phi of two literals. The count is a property of the
    // format, so formats that agree prove it exactly as a single one does.
    if resolve_const_value(function.decompile_prep_facts(), format_var).is_none() {
        return merged_format_literal_argument_count(
            FormatLiteralContext {
                function,
                graph,
                machine_context,
                forwarding,
            },
            interface,
            parameter_rule,
            format_value,
            format_argument_index,
        );
    }
    let format_literal_address = resolve_const_value(function.decompile_prep_facts(), format_var)
        .ok_or_else(|| {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "format argument {format_argument_index} at {:?} is {:?} (root {:?}), \
                 graph literal {:?}, defined by {:?}",
            interface
                .arguments()
                .get(format_argument_index)
                .map(|argument| argument.location()),
            format_var,
            canonical_value_root(function.decompile_prep_facts(), format_var),
            resolve_graph_literal_value(graph, function.decompile_prep_facts(), format_var),
            graph
                .value(format_value)
                .and_then(|value| graph.def_inst(value.id))
                .and_then(|id| graph.inst(id))
                .map(|inst| format!("{:?}", inst.payload)
                    .chars()
                    .take(80)
                    .collect::<String>())
        );
        VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral
    })?;
    let format = machine_context
        .source_string_literal(format_literal_address)
        .ok_or_else(|| {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "format argument {format_argument_index} points at {format_literal_address:#x}, where the source carries no string literal; the table holds {} literals",
                machine_context.source_string_literal_count()
            );
            VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral
        })?;
    let consumed = crate::printf::printf_consumed_arguments(format)
        .map_err(|_| VariadicCallsiteArgumentCountRefusal::InvalidFormatString)?;
    // A floating operand travels in the convention's floating sequence, which
    // this recovery does not walk; where the whole tail is on the stack it
    // sits in the same slots as any other operand.
    if consumed.any_floating && !variadic_tail_on_stack(machine_context) {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "format argument {format_argument_index} at {format_literal_address:#x} consumes a floating operand, which this recovery cannot place"
        );
        return Err(VariadicCallsiteArgumentCountRefusal::FloatingVariadicArgument);
    }
    let format_consumed_argument_count = consumed.count;
    let total_argument_count = interface
        .arguments()
        .len()
        .checked_add(format_consumed_argument_count)
        .ok_or(VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
    Ok(VariadicCallsiteArgumentCountEvidence {
        parameter_rule,
        merged_literals: false,
        format_argument_index,
        format_literal_address,
        format_consumed_argument_count,
        total_argument_count,
    })
}

/// Every format literal that can reach one merged format argument.
///
/// `None` as soon as a reaching definition is something other than a merge, a
/// copy, or a constant: a count proved from some of the formats would be a
/// count proved from none of them.
pub(crate) fn reaching_format_literals(
    context: FormatLiteralContext<'_>,
    value: ValueId,
    seen: &mut BTreeSet<ValueId>,
    found: &mut BTreeSet<u64>,
) -> bool {
    let FormatLiteralContext {
        function,
        graph,
        machine_context,
        forwarding,
    } = context;
    if !seen.insert(value) {
        return true;
    }
    let Some(var) = graph.value(value).map(|value| &value.var) else {
        return false;
    };
    if let Some(address) = resolve_const_value(function.decompile_prep_facts(), var) {
        found.insert(address);
        return true;
    }
    let Some(definition) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "reaching format walk stops at {value:?} ({}), which nothing in this function defines",
            var.display_name()
        );
        return false;
    };
    match &definition.payload {
        InstPayload::Phi { .. } | InstPayload::Op(SSAOp::Copy { .. }) => definition
            .inputs
            .iter()
            .all(|input| reaching_format_literals(context, *input, seen, found)),
        // A conditional move selects the format the same way a merge does, and
        // `cmov` is how a compiler spells the choice when it does not branch.
        // Only the two results can be the format; the condition is not one.
        InstPayload::Op(SSAOp::Select { .. }) => definition
            .inputs
            .iter()
            .skip(1)
            .all(|input| reaching_format_literals(context, *input, seen, found)),
        InstPayload::Op(op) => {
            // An address the code computes from constants -- a page and an
            // offset, the way arm64 spells one -- is the literal it names.
            if let Some(address) = crate::constant::prepared_folded_value(
                graph,
                function.decompile_prep_facts(),
                value,
            ) {
                found.insert(address);
                return true;
            }
            // A translation of a msgid consumes what the msgid consumes, so
            // the literal handed to the translator is the one that counts.
            if let Some(msgid) =
                forwarding.translated_msgid(function, graph, machine_context, value)
            {
                return reaching_format_literals(context, msgid, seen, found);
            }
            // Which operation the walk cannot see through is the fact that
            // decides whether the count is unprovable or merely unproven here.
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "reaching format walk stops at {value:?} ({}), defined by {}",
                var.display_name(),
                format!("{op:?}").chars().take(60).collect::<String>()
            );
            false
        }
    }
}

/// What a format value resolves through beyond copies and merges.
///
/// `printf(_("..."), ...)` hands `printf` whatever `gettext` returned, so the
/// walk over reaching literals meets a call result and stops. The call that
/// produced it carries the rule saying it returns a translation of its own
/// argument, and that argument's literal is the one whose conversions count.
pub(crate) struct FormatForwardingLookup<'a> {
    pub(crate) call_sites: &'a CallSiteFacts,
    pub(crate) entry_values: &'a BTreeMap<CanonicalStorageId, Option<ValueId>>,
}

/// What every step of the format-literal question needs, in one place.
///
/// The walk and the merge take the same four invariants, and threading them
/// one by one had grown the signatures past the point where the varying
/// arguments were visible. `VariadicCallsiteRecovery` is the same shape for
/// the carrier question.
#[derive(Copy, Clone)]
pub(crate) struct FormatLiteralContext<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) machine_context: &'a SourceMachineContext,
    pub(crate) forwarding: &'a FormatForwardingLookup<'a>,
}

impl FormatForwardingLookup<'_> {
    /// The call whose result this instruction defines.
    ///
    /// `CallDefine` operations follow their call in a run, so walking back
    /// over that run reaches the call itself. An instruction that is a call
    /// answers for itself.
    fn call_of_result(
        &self,
        function: &SSAFunction,
        graph: &SsaGraph,
        definition: InstId,
    ) -> Option<CallSiteId> {
        if let Some(call_site) = self.call_sites.by_inst.get(&definition) {
            return Some(*call_site);
        }
        let (block_addr, op_index) = graph.op_site_for_inst(definition)?;
        let block = function.get_block(block_addr)?;
        if !matches!(block.ops.get(op_index)?, SSAOp::CallDefine { .. }) {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "{definition:?} at {block_addr:#x}:{op_index} defines the format but the block spells it {}, while the graph spells it {}",
                block
                    .ops
                    .get(op_index)
                    .map_or("nothing".to_string(), |op| format!("{op:?}")
                        .chars()
                        .take(28)
                        .collect::<String>()),
                graph
                    .inst(definition)
                    .map_or("nothing".to_string(), |inst| format!("{:?}", inst.payload)
                        .chars()
                        .take(28)
                        .collect::<String>())
            );
            return None;
        }
        let mut index = op_index;
        while index > 0 {
            index -= 1;
            if !matches!(block.ops.get(index)?, SSAOp::CallDefine { .. }) {
                let inst = graph.inst_id_for_op_site(block_addr, index)?;
                let site = self.call_sites.by_inst.get(&inst).copied();
                if site.is_none() {
                    r2il::refusal_evidence!(
                        "variadic-format-literal",
                        "the call at {block_addr:#x}:{index} defining the format correlates to no call site"
                    );
                }
                return site;
            }
        }
        None
    }

    /// The msgid a translation call was handed, when `value` is its result.
    fn translated_msgid(
        &self,
        function: &SSAFunction,
        graph: &SsaGraph,
        machine_context: &SourceMachineContext,
        value: ValueId,
    ) -> Option<ValueId> {
        let definition = graph.def_inst(value)?;
        // A call's results are `CallDefine` operations that follow it, so the
        // value's own definition is not the call; the call is the operation
        // the run of defines began after.
        let Some(call_site) = self.call_of_result(function, graph, definition) else {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "{value:?} is defined by {definition:?}, which no call of this function results in"
            );
            return None;
        };
        let call_site = &call_site;
        let fact = self.call_sites.by_id.get(call_site)?;
        let interface = machine_context.call_site_interface(fact.raw_identity?)?;
        let Some(rule) = interface.format_forwarding() else {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "{value:?} came from the call at {:#x}, which returns no translation",
                fact.direct_target.unwrap_or_default()
            );
            return None;
        };
        let index = usize::try_from(rule.msgid_argument_index()).ok()?;
        let storage = interface.arguments().get(index)?.register_storage()?;
        let (block_addr, op_index) = graph.op_site_for_inst(fact.at)?;
        match reaching_abi_argument_in_block(
            function,
            graph,
            machine_context,
            self.entry_values,
            block_addr,
            op_index,
            storage,
        )? {
            SourceCallArgumentValue::Value(msgid) => {
                r2il::refusal_evidence!(
                    "variadic-format-literal",
                    "{value:?} is a translation of argument {index}, {msgid:?}"
                );
                Some(msgid)
            }
            SourceCallArgumentValue::PreservedEntry => None,
        }
    }
}

/// Whether the convention puts every variadic operand on the stack, where a
/// floating one is placed like any other.
pub(crate) fn variadic_tail_on_stack(machine_context: &SourceMachineContext) -> bool {
    machine_context
        .convention_slots()
        .is_some_and(r2source::SourceConventionSlots::variadic_tail_on_stack)
}

/// Prove a merged variadic count from formats that agree.
pub(crate) fn merged_format_literal_argument_count(
    context: FormatLiteralContext<'_>,
    interface: &r2source::SourceCallSiteInterface,
    parameter_rule: r2source::SourceFormatParameterRule,
    format_value: ValueId,
    format_argument_index: usize,
) -> Result<VariadicCallsiteArgumentCountEvidence, VariadicCallsiteArgumentCountRefusal> {
    let machine_context = context.machine_context;
    let mut addresses = BTreeSet::new();
    if !reaching_format_literals(context, format_value, &mut BTreeSet::new(), &mut addresses)
        || addresses.is_empty()
    {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "format argument {format_argument_index} reaches {} literals and at least one value that is not one",
            addresses.len()
        );
        return Err(VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral);
    }
    let mut agreed: Option<usize> = None;
    for address in &addresses {
        let Some(format) = machine_context.source_string_literal(*address) else {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "merged format argument {format_argument_index} reaches {address:#x}, where the source carries no string literal; the table holds {} literals",
                machine_context.source_string_literal_count()
            );
            return Err(VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral);
        };
        let consumed = crate::printf::printf_consumed_arguments(format)
            .map_err(|_| VariadicCallsiteArgumentCountRefusal::InvalidFormatString)?;
        if consumed.any_floating && !variadic_tail_on_stack(machine_context) {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "merged format argument {format_argument_index} reaches {address:#x}, which consumes a floating operand"
            );
            return Err(VariadicCallsiteArgumentCountRefusal::FloatingVariadicArgument);
        }
        // A call two paths share passes the same carriers on both, so the
        // call passes as many operands as the format that consumes most; on
        // the other path the surplus is what the machine passed too.
        let count = consumed.count;
        match agreed {
            None => agreed = Some(count),
            Some(existing) if existing == count => {}
            Some(existing) => {
                r2il::refusal_evidence!(
                    "variadic-format-literal",
                    "merged format argument {format_argument_index} reaches formats consuming {existing} and {count} arguments; the call passes {}",
                    existing.max(count)
                );
                agreed = Some(existing.max(count));
            }
        }
    }
    let format_consumed_argument_count =
        agreed.ok_or(VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral)?;
    let total_argument_count = interface
        .arguments()
        .len()
        .checked_add(format_consumed_argument_count)
        .ok_or(VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
    let format_literal_address = *addresses
        .first()
        .ok_or(VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral)?;
    r2il::refusal_evidence!(
        "variadic-format-literal",
        "merged format argument {format_argument_index} agrees on {format_consumed_argument_count} arguments across {addresses:?}"
    );
    // One literal reached through copies is one literal, and saying it was a
    // merge would claim a proof this call did not need.
    Ok(VariadicCallsiteArgumentCountEvidence {
        parameter_rule,
        merged_literals: addresses.len() > 1,
        format_argument_index,
        format_literal_address,
        format_consumed_argument_count,
        total_argument_count,
    })
}

/// Recover exactly the carriers requested by a proven format count.
pub(crate) struct VariadicCallsiteRecovery<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) machine_context: &'a SourceMachineContext,
    pub(crate) entry_values: &'a BTreeMap<CanonicalStorageId, Option<ValueId>>,
    pub(crate) block_addr: u64,
    pub(crate) op_index: usize,
}

pub(crate) fn variadic_callsite_arguments(
    recovery: VariadicCallsiteRecovery<'_>,
    interface: &r2source::SourceCallSiteInterface,
    fixed_arguments: &[Option<SourceCallArgumentFact>],
    evidence: VariadicCallsiteArgumentCountEvidence,
) -> Result<Vec<SourceCallArgumentFact>, VariadicCallsiteArgumentCountRefusal> {
    let convention = recovery
        .machine_context
        .convention_slots()
        .ok_or(VariadicCallsiteArgumentCountRefusal::CallingConventionMismatch)?;
    let slots = convention.argument_slots();
    if convention.calling_convention() != interface.calling_convention()
        || interface.arguments().len() > slots.len()
        || interface
            .arguments()
            .iter()
            .zip(slots)
            .any(|(argument, slot)| argument.register_storage() != Some(*slot))
    {
        return Err(VariadicCallsiteArgumentCountRefusal::CallingConventionMismatch);
    }
    // Arguments past the register carriers go in the outgoing argument area,
    // and the convention says where. Without that placement the register
    // prefix is all there is, and calling it the complete call would be a
    // false claim about a call that passes more.
    let stack_placement = convention.stack_arguments();
    // Where a position past the fixed prefix sits: the next register, or the
    // stack. Apple's arm64 ABI puts the whole variadic tail on the stack from
    // its first slot, whatever registers the prefix left free.
    let fixed = interface.arguments().len();
    let tail_on_stack = convention.variadic_tail_on_stack();
    let stack_index_of = |position: usize| -> Option<usize> {
        if tail_on_stack && position >= fixed {
            Some(position - fixed)
        } else if position >= slots.len() {
            Some(position - slots.len())
        } else {
            None
        }
    };
    if (0..evidence.total_argument_count).any(|position| stack_index_of(position).is_some())
        && stack_placement.is_none()
    {
        return Err(VariadicCallsiteArgumentCountRefusal::InsufficientRegisterArgumentCarriers);
    }

    let mut arguments = Vec::with_capacity(evidence.total_argument_count);
    for position in 0..evidence.total_argument_count {
        if let Some(stack_index) = stack_index_of(position) {
            let placement = stack_placement
                .ok_or(VariadicCallsiteArgumentCountRefusal::UnresolvedArgumentCarrier)?;
            let offset = placement
                .offset_of(stack_index)
                .ok_or(VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
            let (value, entry_offset) = reaching_stack_argument_before_call(
                CallPosition {
                    function: recovery.function,
                    graph: recovery.graph,
                    block_addr: recovery.block_addr,
                    op_index: recovery.op_index,
                    calls_move_stack_pointer: recovery.machine_context.call_moves_stack_pointer(),
                },
                StackArgument {
                    offset,
                    callee_offset: offset,
                    size_bytes: placement.stride_bytes(),
                },
            )
            .ok_or(VariadicCallsiteArgumentCountRefusal::UnresolvedArgumentCarrier)?;
            arguments.push(SourceCallArgumentFact {
                slot: CallBoundarySlot::Stack(entry_offset),
                value: SourceCallArgumentValue::Value(value),
            });
            continue;
        }
        let slot = *slots
            .get(position)
            .ok_or(VariadicCallsiteArgumentCountRefusal::UnresolvedArgumentCarrier)?;
        if let Some(argument) = fixed_arguments.get(position).and_then(|fact| *fact) {
            arguments.push(argument);
            continue;
        }
        let value = reaching_abi_argument_in_block(
            recovery.function,
            recovery.graph,
            recovery.machine_context,
            recovery.entry_values,
            recovery.block_addr,
            recovery.op_index,
            slot,
        )
        .ok_or(VariadicCallsiteArgumentCountRefusal::UnresolvedArgumentCarrier)?;
        let index = u32::try_from(position)
            .map_err(|_| VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
        arguments.push(SourceCallArgumentFact {
            slot: CallBoundarySlot::Register {
                index,
                storage: slot,
            },
            value,
        });
    }
    Ok(arguments)
}

/// What a call boundary carries when nothing knows the callee's signature.
pub(crate) struct ConventionCallBoundary {
    pub(crate) calling_convention: String,
    pub(crate) arguments: Vec<SourceCallArgumentFact>,
    pub(crate) results: Vec<CallBoundaryValueFact>,
}

/// The value a call reads from one slot of its outgoing argument area.
///
/// `offset` names the slot from the stack pointer as the call instruction
/// finds it, before the instruction's own p-code spends the return-address
/// slot. Construction records exactly that carrier as the source of the
/// `CallRestore` it emits after the call, so the slot's entry-relative
/// coordinate is that carrier's entry-relative position plus the offset. The
/// value is the last store to exactly that coordinate at exactly that width in
/// the run of operations since the previous call, which is where a compiler
/// materialises the arguments it cannot pass in registers. Returns the value
/// and the slot's entry-relative coordinate.
/// Where a call sits, for the searches that look backwards from it.
#[derive(Clone, Copy)]
pub(crate) struct CallPosition<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) block_addr: u64,
    pub(crate) op_index: usize,
    pub(crate) calls_move_stack_pointer: bool,
}

/// One stack argument: where the caller writes it, where the callee reads it,
/// and how wide it is.
#[derive(Clone, Copy)]
pub(crate) struct StackArgument {
    pub(crate) offset: i64,
    pub(crate) callee_offset: i64,
    pub(crate) size_bytes: u32,
}

pub(crate) fn reaching_stack_argument_before_call(
    at: CallPosition<'_>,
    argument: StackArgument,
) -> Option<(ValueId, i64)> {
    let CallPosition {
        function,
        graph,
        block_addr,
        op_index: call_op_index,
        calls_move_stack_pointer,
    } = at;
    let StackArgument {
        offset,
        callee_offset,
        size_bytes,
    } = argument;
    let block = function.get_block(block_addr)?;
    let Some((entering, transfer_moved_carrier)) = call_entering_stack_pointer_offset(
        function,
        graph,
        block,
        call_op_index,
        calls_move_stack_pointer,
    ) else {
        r2il::refusal_evidence!(
            "call-argument-stack-store",
            "callsite ({block_addr:#x}, {call_op_index}) has no frame position for the stack pointer entering the call"
        );
        return None;
    };
    let offset = if transfer_moved_carrier {
        offset
    } else {
        callee_offset
    };
    let entry_offset = entering.offset.checked_add(offset)?;
    let slot_name = crate::naming::frame_slot_name(entry_offset);
    // Promotion named the slot's variable after its entry coordinate; the
    // graph has such a value exactly when the slot left memory. The name
    // carries no frame, so only the entry frame may be asked for one.
    let promoted = entering.base == StackAddressBase::StackPointer
        && graph
            .values
            .iter()
            .any(|value| value.var.name() == slot_name);
    let mut visited = BTreeSet::new();
    reaching_stack_slot_value(
        function,
        graph,
        block_addr,
        call_op_index,
        StackSlotQuery {
            base: entering.base,
            entry_offset,
            slot_name: &slot_name,
            size_bytes,
            promoted,
        },
        &mut visited,
    )
    .map(|value| (value, entry_offset))
}

/// The outgoing slot an argument walk looks for.
#[derive(Clone, Copy)]
pub(crate) struct StackSlotQuery<'a> {
    /// The frame the offset is in: the entry one, or a realigned origin.
    pub(crate) base: StackAddressBase,
    pub(crate) entry_offset: i64,
    pub(crate) slot_name: &'a str,
    pub(crate) size_bytes: u32,
    /// The slot is a promoted variable: its store is a copy into the slot's
    /// variable, its merge is a phi, and a call does not disturb it.
    pub(crate) promoted: bool,
}

/// The value held by an outgoing stack slot at `boundary` in `block_addr`:
/// the last store to it in the block, or the slot variable's reaching version
/// when the slot was promoted. A shared call tail has its arguments stored in
/// each predecessor, so a block that says nothing asks its predecessors, which
/// must agree -- for a promoted slot the renamer put a phi where they differ.
pub(crate) fn reaching_stack_slot_value(
    function: &SSAFunction,
    graph: &SsaGraph,
    block_addr: u64,
    boundary: usize,
    query: StackSlotQuery<'_>,
    visited: &mut BTreeSet<u64>,
) -> Option<ValueId> {
    if !visited.insert(block_addr) {
        return None;
    }
    let block = function.get_block(block_addr)?;
    for op in block.ops.get(..boundary)?.iter().rev() {
        match op {
            SSAOp::Copy { dst, src } if query.promoted && dst.name() == query.slot_name => {
                if dst.size != query.size_bytes {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) promoted slot {} is {} bytes, the argument is {}",
                        query.slot_name,
                        dst.size,
                        query.size_bytes
                    );
                    return None;
                }
                return graph.value_id_for_var(src);
            }
            SSAOp::Call { .. } | SSAOp::CallInd { .. } | SSAOp::CallOther { .. }
                if !query.promoted =>
            {
                r2il::refusal_evidence!(
                    "call-argument-stack-store",
                    "({block_addr:#x}) an earlier call stands between the argument slot at {} and the call",
                    query.entry_offset
                );
                return None;
            }
            SSAOp::Store {
                space: SpaceId::Ram,
                addr,
                val,
            } if !query.promoted => {
                let Some(root) = resolve_entry_stack_root(function.decompile_prep_facts(), addr)
                else {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) store through {addr} has no root (wanted {:?} {})",
                        query.base,
                        query.entry_offset
                    );
                    continue;
                };
                if root.base != query.base || root.offset != query.entry_offset {
                    continue;
                }
                if val.size != query.size_bytes {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) store at entry offset {} is {} bytes, slot is {}",
                        query.entry_offset,
                        val.size,
                        query.size_bytes
                    );
                    return None;
                }
                return graph.value_id_for_var(val);
            }
            _ => {}
        }
    }
    if query.promoted
        && let Some(phi) = block
            .phis
            .iter()
            .find(|phi| phi.dst.name() == query.slot_name && phi.dst.size == query.size_bytes)
    {
        return graph.value_id_for_var(&phi.dst);
    }
    let predecessors = function.predecessors(block_addr);
    if predecessors.is_empty() {
        r2il::refusal_evidence!(
            "call-argument-stack-store",
            "({block_addr:#x}) no store reaches the argument slot at {} (promoted={})",
            query.entry_offset,
            query.promoted
        );
        return None;
    }
    let mut agreed = None;
    for predecessor in predecessors {
        let boundary = function.get_block(predecessor)?.ops.len();
        let value =
            reaching_stack_slot_value(function, graph, predecessor, boundary, query, visited)?;
        match agreed {
            None => agreed = Some(value),
            Some(existing) if existing == value => {}
            Some(existing) => {
                r2il::refusal_evidence!(
                    "call-argument-stack-store",
                    "({block_addr:#x}) predecessors leave {existing:?} and {value:?} in the argument slot at {}",
                    query.entry_offset
                );
                return None;
            }
        }
    }
    agreed
}

pub(crate) fn convention_call_boundary(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    live_out: &crate::liveout::FunctionLiveOut,
    block_addr: u64,
    op_index: usize,
) -> Option<ConventionCallBoundary> {
    let convention = machine_context.convention_slots()?;
    let mut arguments = Vec::new();
    for (position, slot) in convention.argument_slots().iter().enumerate() {
        let Ok(index) = u32::try_from(position) else {
            break;
        };
        let Some(value) = reaching_variadic_tail_argument_in_block(
            function,
            graph,
            machine_context,
            block_addr,
            op_index,
            *slot,
        ) else {
            break;
        };
        // A call whose signature nothing knows takes its arity from the
        // registers this body provably wrote before it. One the caller merely
        // arrived holding is not evidence the call reads it.
        if graph.def_inst(value).is_none() {
            break;
        }
        arguments.push(SourceCallArgumentFact {
            slot: CallBoundarySlot::Register {
                index,
                storage: *slot,
            },
            value: SourceCallArgumentValue::Value(value),
        });
    }
    // The convention fills every register slot before the argument area, and a
    // convention with none starts there: x86 cdecl passes everything on the
    // stack. A slot this function stored into before the call is one the call
    // reads, which is the same evidence the register scan takes, and the first
    // slot with no store ends the count exactly as an untouched register does.
    if arguments.len() == convention.argument_slots().len()
        && let Some(placement) = convention.stack_arguments()
    {
        // Where the area is depends on where the stack pointer stands. Without
        // that, an empty scan says nothing was looked at rather than that
        // nothing is there, and a call that passes arguments would be spelled
        // as one that passes none.
        if call_entering_stack_pointer_offset(
            function,
            graph,
            function.get_block(block_addr)?,
            op_index,
            machine_context.call_moves_stack_pointer(),
        )
        .is_none()
        {
            r2il::refusal_evidence!(
                "convention-argument-area",
                "callsite ({block_addr:#x}, {op_index}) cannot see the argument area its convention passes on"
            );
            return None;
        }
        // The callee names the same slot from the pointer it is entered with,
        // below the caller's by what the transfer spends on the return address.
        let spent = machine_context.return_mechanism().map_or(0, |mechanism| {
            i64::from(mechanism.stack_pointer_delta_bytes())
        });
        for position in 0.. {
            let Some(offset) = placement.offset_of(position) else {
                break;
            };
            let Some((value, entry_offset)) = reaching_stack_argument_before_call(
                CallPosition {
                    function,
                    graph,
                    block_addr,
                    op_index,
                    calls_move_stack_pointer: machine_context.call_moves_stack_pointer(),
                },
                StackArgument {
                    offset,
                    callee_offset: offset.saturating_add(spent),
                    size_bytes: placement.stride_bytes(),
                },
            ) else {
                break;
            };
            arguments.push(SourceCallArgumentFact {
                slot: CallBoundarySlot::Stack(entry_offset),
                value: SourceCallArgumentValue::Value(value),
            });
        }
    }

    let results = convention
        .result_slot()
        .and_then(|storage| {
            observed_convention_call_result_after_call(
                function, graph, live_out, block_addr, op_index, storage,
            )
        })
        .into_iter()
        .collect();

    Some(ConventionCallBoundary {
        calling_convention: convention.calling_convention().to_string(),
        arguments,
        results,
    })
}

pub(crate) fn collect_source_boundary_facts(
    function: &SSAFunction,
    graph: &SsaGraph,
    call_sites: &CallSiteFacts,
    machine_context: Option<&SourceMachineContext>,
    live_out: &crate::liveout::FunctionLiveOut,
) -> SourceBoundaryFacts {
    // Calls read register arguments implicitly, so a preserved entry carrier
    // has no graph use at the call instruction. Index exact entry values once
    // for the whole boundary pass and attach that identity when the reaching
    // proof says the carrier was untouched.
    let entry_values = unique_entry_values_by_storage(graph);
    let mut facts = SourceBoundaryFacts {
        parameters: machine_context
            .map(|machine_context| collect_source_formal_parameter_facts(graph, machine_context))
            .unwrap_or_default(),
        ..SourceBoundaryFacts::default()
    };

    for call_site in call_sites.by_id.values() {
        let mut boundary = SourceCallBoundaryFact {
            call_site: call_site.id,
            at: call_site.at,
            calling_convention: None,
            variadic: None,
            noreturn: None,
            result_kind: None,
            arguments: Vec::new(),
            fixed_argument_count: None,
            variadic_argument_count_evidence: None,
            variadic_argument_count_refusal: None,
            results: Vec::new(),
            // Calls carry implicit machine state. Only an exact source-owned
            // callsite interface may change this state to complete.
            complete: false,
            arguments_complete: false,
            results_complete: false,
            described: false,
        };
        if let Some((machine_context, interface)) = machine_context.and_then(|context| {
            call_site
                .raw_identity
                .and_then(|identity| context.call_site_interface(identity))
                .map(|interface| (context, interface))
        }) {
            boundary.calling_convention = Some(interface.calling_convention().to_string());
            boundary.variadic = Some(interface.is_variadic());
            boundary.described = true;
            boundary.noreturn = Some(interface.is_noreturn());
            boundary.result_kind = Some(interface.result());
            if interface.is_complete()
                && let Some((block_addr, op_index)) = graph.op_site_for_inst(call_site.at)
            {
                let fixed_arguments = interface
                    .arguments()
                    .iter()
                    .map(|argument| match argument.location() {
                        r2source::SourceParameterLocation::Register(storage) => {
                            // An argument the function passes straight through
                            // from its own entry has no definition here and is
                            // never read explicitly, so no SSA value names it.
                            // That is a description of where the value comes
                            // from, not a failure to find it.
                            let found = reaching_abi_argument_in_block(
                                function,
                                graph,
                                machine_context,
                                &entry_values,
                                block_addr,
                                op_index,
                                storage,
                            );
                            if found.is_none() {
                                r2il::refusal_evidence!(
                                    "call-argument",
                                    "callsite ({block_addr:#x}, {op_index}) argument {} in {:?} has no reaching value",
                                    argument.index(),
                                    storage
                                );
                            }
                            found.map(|value| SourceCallArgumentFact {
                                slot: CallBoundarySlot::Register {
                                    index: argument.index(),
                                    storage,
                                },
                                value,
                            })
                        }
                        r2source::SourceParameterLocation::Stack {
                            offset,
                            size_bytes,
                            callee_offset,
                        } => {
                            let found = reaching_stack_argument_before_call(
                                CallPosition {
                                    function,
                                    graph,
                                    block_addr,
                                    op_index,
                                    calls_move_stack_pointer: machine_context
                                        .call_moves_stack_pointer(),
                                },
                                StackArgument {
                                    offset,
                                    callee_offset,
                                    size_bytes,
                                },
                            );
                            if found.is_none() {
                                r2il::refusal_evidence!(
                                    "call-argument",
                                    "callsite ({block_addr:#x}, {op_index}) argument {} at stack +{offset} ({size_bytes} bytes) has no reaching store",
                                    argument.index()
                                );
                            }
                            found.map(|(value, entry_offset)| SourceCallArgumentFact {
                                slot: CallBoundarySlot::Stack(entry_offset),
                                value: SourceCallArgumentValue::Value(value),
                            })
                        }
                    })
                    .collect::<Vec<_>>();
                let results = match (call_site.transfer, interface.result()) {
                    (CallSiteTransfer::TailCall, _) | (_, SourceCallResult::Void) => {
                        Some(Vec::new())
                    }
                    (CallSiteTransfer::Call, SourceCallResult::Register { storage }) => {
                        call_result_values_after_call(
                            function,
                            graph,
                            machine_context,
                            block_addr,
                            op_index,
                            storage,
                        )
                    }
                };
                boundary.fixed_argument_count = Some(interface.arguments().len());
                let arguments_complete = if interface.is_variadic() {
                    match variadic_callsite_argument_count(
                        function,
                        graph,
                        machine_context,
                        interface,
                        &fixed_arguments,
                        &FormatForwardingLookup {
                            call_sites,
                            entry_values: &entry_values,
                        },
                    ) {
                        Ok(evidence) => {
                            boundary.variadic_argument_count_evidence = Some(evidence);
                            match variadic_callsite_arguments(
                                VariadicCallsiteRecovery {
                                    function,
                                    graph,
                                    machine_context,
                                    entry_values: &entry_values,
                                    block_addr,
                                    op_index,
                                },
                                interface,
                                &fixed_arguments,
                                evidence,
                            ) {
                                Ok(arguments) => {
                                    boundary.arguments = arguments;
                                    true
                                }
                                Err(refusal) => {
                                    // The count was proved and the carriers
                                    // were not, which is a different failure
                                    // from not knowing how many there are.
                                    r2il::refusal_evidence!(
                                        "variadic-callsite-arguments",
                                        "callsite ({block_addr:#x}, {op_index}) proved {} arguments and refused their carriers: {refusal:?}",
                                        evidence.total_argument_count
                                    );
                                    boundary.variadic_argument_count_refusal = Some(refusal);
                                    false
                                }
                            }
                        }
                        Err(refusal) => {
                            r2il::refusal_evidence!(
                                "variadic-callsite-arguments",
                                "callsite ({block_addr:#x}, {op_index}) could not prove its argument count: {refusal:?}"
                            );
                            boundary.variadic_argument_count_refusal = Some(refusal);
                            // The fixed prefix is the prototype's and is read
                            // whether or not the tail is counted: an import
                            // thunk forwarding its own tail still reads every
                            // fixed carrier, and that is what names its parameters.
                            if fixed_arguments.iter().all(Option::is_some) {
                                boundary.arguments =
                                    fixed_arguments.iter().flatten().copied().collect();
                            }
                            false
                        }
                    }
                } else if fixed_arguments.iter().all(Option::is_some) {
                    boundary.arguments = fixed_arguments.into_iter().flatten().collect();
                    true
                } else {
                    false
                };
                let results_complete = results.is_some();
                if let Some(found) = results.as_ref()
                    && found.is_empty()
                    && !matches!(interface.result(), SourceCallResult::Void)
                {
                    // A register result the walk found no value for is not the
                    // same as a void one, and only this says which happened.
                    r2il::refusal_evidence!(
                        "call-result-empty",
                        "callsite ({block_addr:#x}, {op_index}) declares {:?} and no value reaches it",
                        interface.result()
                    );
                }
                if !arguments_complete || !results_complete {
                    r2il::refusal_evidence!(
                        "call-boundary-incomplete",
                        "callsite ({block_addr:#x}, {op_index}) declares {} arguments: arguments_complete={arguments_complete} results_complete={results_complete}",
                        interface.arguments().len()
                    );
                }
                if let Some(results) = results {
                    boundary.results = results;
                }
                boundary.arguments_complete = arguments_complete;
                boundary.results_complete = results_complete;
                boundary.complete = arguments_complete && results_complete;
            }
        }
        if !boundary.complete
            && boundary.calling_convention.is_none()
            && let Some(machine_context) = machine_context
            && let Some((block_addr, op_index)) = graph.op_site_for_inst(call_site.at)
        {
            let convention = convention_call_boundary(
                function,
                graph,
                machine_context,
                live_out,
                block_addr,
                op_index,
            );
            // One record of what the fallback was asked and what it answered.
            r2il::refusal_evidence!(
                "call-boundary-fallback",
                "callsite ({block_addr:#x}, {op_index}) raw_identity={:?} interface={} built={} arguments={} results={}",
                call_site.raw_identity,
                call_site
                    .raw_identity
                    .is_some_and(|identity| machine_context
                        .call_site_interface(identity)
                        .is_some()),
                convention.is_some(),
                convention.as_ref().map_or(0, |found| found.arguments.len()),
                convention.as_ref().map_or(0, |found| found.results.len())
            );
            if let Some(convention) = convention {
                boundary.calling_convention = Some(convention.calling_convention);
                // Nothing said this callee is variadic, and the count came from
                // the machine rather than from a prototype, so every argument
                // found is a fixed one as far as anything here can tell.
                boundary.variadic = Some(false);
                boundary.fixed_argument_count = Some(convention.arguments.len());
                boundary.arguments = convention.arguments;
                boundary.results = convention.results;
                // Deliberately not the result kind. Where the convention says a
                // result would be left is a fact about the caller's side, and
                // recording it here would make interface recovery read a thunk's
                // tail transfer as proof that its target returns a value. What
                // the callee returns stays unproven; the renderer's disposition
                // decides what a transfer through this boundary looks like.
                boundary.complete = true;
                boundary.arguments_complete = true;
                boundary.results_complete = true;
            }
        }
        facts.calls.insert(call_site.id, boundary);
    }

    if let Some(machine_context) = machine_context {
        facts.preserved_call_carriers = preserved_call_carriers(function, graph, machine_context);
        if trace_call_definitions() {
            eprintln!(
                "  preserved across calls to {:#x}: {:?}",
                function.entry,
                facts
                    .preserved_call_carriers
                    .iter()
                    .map(|storage| machine_context
                        .register_name(*storage)
                        .unwrap_or_else(|| format!("{storage:?}")))
                    .collect::<Vec<_>>()
            );
        }
    }

    for inst in &graph.insts {
        if matches!(inst.payload, InstPayload::Op(SSAOp::Return { .. })) {
            let mut values = Vec::new();
            let mut return_address = None;
            let mut exit_stack_pointer = None;
            let mut complete = false;
            let mut machine_state_complete = false;
            // Machine exit state and return values are separate questions. The
            // carriers holding the return address and the stack pointer come
            // from the machine, so they are recoverable for any function; the
            // values a return carries are an ABI question and stay gated on a
            // coherent ABI. Gating both on the ABI is what previously left a
            // function without debug information with no exit facts at all.
            if let Some(machine_context) = machine_context {
                // The return carrier only. Frame attribution and the machine
                // carriers are separate questions and cannot invalidate it.
                let abi_is_coherent = machine_context.abi_model().is_available()
                    && machine_context.abi_model().return_boundary_is_coherent();
                let stack_pointer_storage = machine_context.stack_pointer_carrier();
                let return_address_storage = machine_context.return_address_carrier();
                let return_slots = machine_context.abi_model().return_registers();
                // A void return carries no values, so nothing about it is an
                // ABI question: there is no carrier to resolve and no
                // convention to be coherent about. Only a returned value is.
                use SourceFunctionReturn::{Unproven, Void};
                match machine_context
                    .function_interface()
                    .map(|interface| interface.return_kind())
                {
                    // An unproven result claims no value, so the return is as complete as a void one.
                    Some(Void | Unproven) => complete = true,
                    Some(SourceFunctionReturn::Register { .. }) if abi_is_coherent => {
                        if let Some((block_addr, op_index)) = graph.op_site_for_inst(inst.id) {
                            for slot in return_slots {
                                if let Some(value) = reaching_source_return_register_in_block(
                                    function,
                                    graph,
                                    machine_context,
                                    block_addr,
                                    op_index,
                                    slot.storage(),
                                ) {
                                    values.push(CallBoundaryValueFact {
                                        slot: CallBoundarySlot::Register {
                                            index: slot.index(),
                                            storage: slot.storage(),
                                        },
                                        value,
                                    });
                                }
                            }
                            complete =
                                !return_slots.is_empty() && values.len() == return_slots.len();
                        }
                    }
                    _ => {}
                }
                if let Some(storage) = stack_pointer_storage {
                    exit_stack_pointer = graph
                        .op_site_for_inst(inst.id)
                        .and_then(|(block_addr, op_index)| {
                            reaching_preserved_abi_value_in_block(
                                function,
                                graph,
                                machine_context,
                                block_addr,
                                op_index,
                                storage,
                            )
                        })
                        .map(|state| match state {
                            ReachingAbiState::PreservedEntry => {
                                SourceReturnStackPointerFact::PreservedEntry { storage }
                            }
                            ReachingAbiState::Value(value) => {
                                SourceReturnStackPointerFact::ReachingValue { storage, value }
                            }
                        });
                    complete &= exit_stack_pointer.is_some();
                }
                if let Some(storage) = return_address_storage {
                    return_address = exact_return_address_fact(graph, inst, storage);
                    complete &= return_address.is_some();
                }
                machine_state_complete = return_address.is_some() && exit_stack_pointer.is_some();
                if !complete {
                    r2il::refusal_evidence!(
                        "return-boundary-completeness",
                        "coherent={abi_is_coherent} kind={:?} slots={} values={} \
                         exit_sp={} return_address={}",
                        machine_context
                            .function_interface()
                            .map(|interface| interface.return_kind()),
                        machine_context.abi_model().return_registers().len(),
                        values.len(),
                        exit_stack_pointer.is_some(),
                        return_address.is_some()
                    );
                }
            }
            let result_unproven = machine_context
                .and_then(SourceMachineContext::function_interface)
                .is_some_and(|interface| interface.return_kind() == SourceFunctionReturn::Unproven);
            facts.returns.insert(
                inst.id,
                SourceReturnBoundaryFact {
                    at: inst.id,
                    values,
                    return_address,
                    exit_stack_pointer,
                    complete,
                    machine_state_complete,
                    result_unproven,
                },
            );
        }
    }
    facts
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SourceFormalParameterProjection {
    pub(crate) index: u32,
    pub(crate) abi_storage: CanonicalStorageId,
    pub(crate) graph_storage: CanonicalStorageId,
    pub(crate) logical_value: Option<SourceLogicalValue>,
}

/// Validate and project the source's ABI parameter slots once.
pub(crate) fn source_formal_parameter_projections(
    machine_context: &SourceMachineContext,
) -> Vec<SourceFormalParameterProjection> {
    // Whole-ABI coherence also covers return and stack roles. Those unrelated
    // roles cannot invalidate an exact parameter/type projection; each slot is
    // checked against the interface and graph below before it becomes a fact.
    if !machine_context.abi_model().is_available() {
        return Vec::new();
    }
    let Some(interface) = machine_context.function_interface() else {
        return Vec::new();
    };
    if interface.schema_version() != SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION
        || match interface.type_graph() {
            Some(type_graph) => {
                type_graph.schema_version() != SOURCE_TYPE_GRAPH_SCHEMA_VERSION
                    || interface.parameters().len() != interface.parameter_logical_values().len()
            }
            None => !interface.parameter_logical_values().is_empty(),
        }
    {
        r2il::refusal_evidence!(
            "formal-projections",
            "interface schema {} graph {:?} parameters {} logical values {}",
            interface.schema_version(),
            interface.type_graph().map(|graph| graph.schema_version()),
            interface.parameters().len(),
            interface.parameter_logical_values().len()
        );
        return Vec::new();
    }

    interface
        .parameters()
        .iter()
        .enumerate()
        .filter_map(|(parameter_position, parameter)| {
            // A parameter the convention passes on the stack is a frame
            // object rather than an entry register; the object model owns it.
            let abi_storage = parameter.register_storage()?;
            if machine_context
                .abi_model()
                .argument_registers()
                .iter()
                .filter(|slot| slot.index() == parameter.index() && slot.storage() == abi_storage)
                .count()
                != 1
            {
                r2il::refusal_evidence!(
                    "formal-projections",
                    "parameter {} storage {:?} is not exactly one argument register of the ABI model",
                    parameter.index(),
                    abi_storage
                );
                return None;
            }
            // A parameter the capture could not place keeps its ABI storage
            // and no exact type, which is what a function with no graph at all
            // already gets. It is not a reason to refuse the parameter.
            let logical_value = interface.parameter_logical_value(parameter_position);
            let graph_storage = match (logical_value, interface.type_graph()) {
                (Some(logical_value), Some(type_graph)) => {
                    projected_logical_register_storage(abi_storage, logical_value, type_graph)?
                }
                (None, _) => abi_storage,
                (Some(_), None) => return None,
            };
            Some(SourceFormalParameterProjection {
                index: parameter.index(),
                abi_storage,
                graph_storage,
                logical_value,
            })
        })
        .collect()
}

/// Index the exact entry values by source storage in one graph pass.
///
/// `None` records ambiguity and is deliberately sticky: materialization must
/// never turn two existing answers into a third one that merely looks exact.
pub(crate) fn unique_entry_values_by_storage(
    graph: &SsaGraph,
) -> BTreeMap<CanonicalStorageId, Option<ValueId>> {
    let mut values = BTreeMap::new();
    for value in &graph.values {
        let Some(storage) = value.canonical_storage else {
            continue;
        };
        if graph.def_inst(value.id).is_some() || value.var.version != 0 {
            continue;
        }
        values
            .entry(storage)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(value.id));
    }
    // A lane of an entry register is the projection minted for it
    // (doc/adr-register-identity.md §8, 6), the one value every entry read of
    // that lane is.
    for (value, storage) in graph.formal_projections() {
        values
            .entry(*storage)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(*value));
    }
    values
}

/// The single authoritative projection from source ABI parameter slots to
/// entry SSA values. Preparation and published boundary facts consume this
/// same answer; register spelling is never an identity input.
pub(crate) fn collect_source_formal_parameter_facts(
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
) -> BTreeMap<u32, SourceFormalParameterFact> {
    let entry_values = unique_entry_values_by_storage(graph);
    let mut facts = BTreeMap::new();
    for parameter in source_formal_parameter_projections(machine_context) {
        let Some(value) = entry_values
            .get(&parameter.graph_storage)
            .copied()
            .flatten()
        else {
            continue;
        };
        facts.insert(
            parameter.index,
            SourceFormalParameterFact {
                index: parameter.index,
                abi_storage: parameter.abi_storage,
                graph_storage: parameter.graph_storage,
                logical_value: parameter.logical_value,
                value,
            },
        );
    }
    facts
}

pub(crate) fn exact_return_address_fact(
    graph: &SsaGraph,
    return_inst: &crate::graph::GraphInst,
    storage: CanonicalStorageId,
) -> Option<SourceReturnAddressFact> {
    let [target_id] = return_inst.inputs.as_slice() else {
        r2il::refusal_evidence!(
            "return-address",
            "return has {} inputs, not one",
            return_inst.inputs.len()
        );
        return None;
    };
    let target = graph.value(*target_id)?;
    if target.var.size == storage.size && target.canonical_storage == Some(storage) {
        return Some(SourceReturnAddressFact {
            storage,
            value: target.id,
        });
    }

    // Some exact instruction semantics transport a declared return-address
    // carrier into the architectural control target immediately before the
    // return. Admit only that one-hop, full-width terminal transport. Broader
    // copy chains, casts, phis, partial aliases, and cross-block/non-terminal
    // definitions need distinct proofs.
    if let Some(producer) = graph.def_inst(target.id).and_then(|id| graph.inst(id))
        && let [source_id] = producer.inputs.as_slice()
        && let Some(source) = graph.value(*source_id)
        && let InstPayload::Op(SSAOp::Copy { dst, src }) = &producer.payload
        && producer.block == return_inst.block
        && producer.ordinal.checked_add(1) == Some(return_inst.ordinal)
        && producer.output == Some(target.id)
        && target.var == *dst
        && source.var == *src
        && target.var.size == storage.size
        && source.var.size == storage.size
        && source.canonical_storage == Some(storage)
    {
        return Some(SourceReturnAddressFact {
            storage,
            value: target.id,
        });
    }

    // A machine transports the address into its control value immediately
    // before the transfer: a full-width copy, or ARM's mask of the low bit,
    // which selects the instruction set rather than naming the address. Walk
    // that transport back -- the steps it admits are the only ones a machine
    // uses to reach its control value -- and the address is whatever it began
    // at: the declared carrier,
    // or the frame word an epilogue popped into the program counter.
    let mut carried = target;
    let mut consumer = return_inst.ordinal;
    while let Some(producer) = graph.def_inst(carried.id).and_then(|id| graph.inst(id))
        && producer.block == return_inst.block
        && producer.ordinal < consumer
        && producer.output == Some(carried.id)
        && carried.var.size == storage.size
    {
        let source = match &producer.payload {
            InstPayload::Op(SSAOp::Copy { dst, .. }) if carried.var == *dst => {
                producer.inputs.first()
            }
            InstPayload::Op(SSAOp::IntAnd { dst, b, .. })
                if carried.var == *dst
                    && b.is_const()
                    && b.constant_bits().is_some_and(|mask| mask & 1 == 0) =>
            {
                producer.inputs.first()
            }
            // The word an epilogue reloaded is the address the call pushed.
            InstPayload::Op(SSAOp::Load {
                space: r2il::SpaceId::Ram,
                dst,
                ..
            }) if carried.var == *dst => {
                return Some(SourceReturnAddressFact {
                    storage,
                    value: target.id,
                });
            }
            _ => None,
        };
        let Some(source) = source.and_then(|id| graph.value(*id)) else {
            break;
        };
        if source.canonical_storage == Some(storage) && source.var.size == storage.size {
            return Some(SourceReturnAddressFact {
                storage,
                value: target.id,
            });
        }
        carried = source;
        consumer = producer.ordinal;
    }

    // Once copies are forwarded the return names the value itself -- the word
    // reloaded from the frame -- and the copy that put it in the return-address
    // register stands beside it, read by nothing. That copy is the proof: the
    // machine returned through the register holding exactly this value.
    let block = graph.block(return_inst.block)?;
    block
        .insts
        .iter()
        .filter_map(|inst| graph.inst(*inst))
        .filter(|inst| inst.ordinal < return_inst.ordinal)
        .any(|inst| {
            matches!(inst.payload, InstPayload::Op(SSAOp::Copy { .. }))
                && inst.inputs.as_slice() == [target.id]
                && inst
                    .output
                    .and_then(|output| graph.value(output))
                    .is_some_and(|carrier| {
                        carrier.canonical_storage == Some(storage)
                            && carrier.var.size == storage.size
                            && target.var.size == storage.size
                    })
        })
        .then_some(SourceReturnAddressFact {
            storage,
            value: target.id,
        })
}

/// The value the source says a return exposes in one ABI register.
///
/// Every write to a register defines its root, so the return's value is the
/// root's reaching definition; the declared logical width narrows it in the
/// certificate (doc/adr-register-identity.md).
pub(crate) fn reaching_source_return_register_in_block(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ValueId> {
    let found = reaching_abi_value_in_block(
        function,
        graph,
        machine_context,
        block_addr,
        boundary_op_index,
        storage,
    );
    if found.is_none() {
        r2il::refusal_evidence!("return-register-unreachable", "carrier={storage:?}");
    }
    found
}

/// Resolve one variadic tail carrier, which must be the same on every path.
///
/// A named parameter may be answered by a merge of two definitions: the
/// prototype says the argument exists, so which of them reaches the call is a
/// question about the value and not about whether there is one. A tail slot
/// has no prototype behind it, and a merge whose inputs differ says only that
/// the register holds something -- which every register does. Admitting one
/// claimed an argument the machine had not set for this call, and the
/// placement audit then refused two `/bin/ls` functions for reading a value no
/// path had assigned.
pub(crate) fn reaching_variadic_tail_argument_in_block(
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
        false,
    )
    .and_then(|state| match state {
        ReachingAbiState::PreservedEntry => None,
        // A register an earlier call clobbered holds whatever that callee
        // left there. Nothing this function wrote reaches the slot, so no
        // argument was passed in it; counting it claimed an argument the
        // caller never set and read a value no statement had assigned.
        ReachingAbiState::Value(value) if value_is_call_clobber(graph, value) => None,
        ReachingAbiState::Value(value) => Some(value),
    })
}

/// Whether a value is the fresh definition a call leaves in a register it may
/// have clobbered, rather than anything this function computed.
pub(crate) fn value_is_call_clobber(graph: &SsaGraph, value: ValueId) -> bool {
    graph
        .def_inst(value)
        .and_then(|inst| graph.inst(inst))
        .is_some_and(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::CallDefine { .. })))
}

/// Resolve one call argument carrier, keeping the preserved-entry case.
pub(crate) fn reaching_abi_argument_in_block(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    entry_values: &BTreeMap<CanonicalStorageId, Option<ValueId>>,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<SourceCallArgumentValue> {
    reaching_abi_value_in_block_with_policy(
        function,
        graph,
        machine_context,
        block_addr,
        boundary_op_index,
        storage,
        true,
    )
    .map(|state| match state {
        ReachingAbiState::PreservedEntry => entry_values
            .get(&storage)
            .copied()
            .flatten()
            .map(SourceCallArgumentValue::Value)
            .unwrap_or_else(|| {
                r2il::refusal_evidence!(
                    "entry-value-lookup",
                    "{:?} reaches a call unchanged from entry; entry value {}",
                    storage,
                    match entry_values.get(&storage) {
                        None => "absent".to_string(),
                        Some(None) => "ambiguous".to_string(),
                        Some(Some(value)) => format!("{value:?}"),
                    }
                );
                SourceCallArgumentValue::PreservedEntry
            }),
        ReachingAbiState::Value(value) => SourceCallArgumentValue::Value(value),
    })
}

pub(crate) fn reaching_preserved_abi_value_in_block(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ReachingAbiState> {
    reaching_abi_value_in_block_with_policy(
        function,
        graph,
        machine_context,
        block_addr,
        boundary_op_index,
        storage,
        false,
    )
    .or_else(|| {
        storage_is_untouched_on_all_predecessor_paths(
            function,
            graph,
            block_addr,
            boundary_op_index,
            storage,
            machine_context.stack_pointer_carrier(),
        )
        .then_some(ReachingAbiState::PreservedEntry)
    })
}

pub(crate) fn storage_is_untouched_on_all_predecessor_paths(
    function: &SSAFunction,
    graph: &SsaGraph,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
    transfer_carrier: Option<CanonicalStorageId>,
) -> bool {
    let mut pending = vec![(block_addr, boundary_op_index)];
    let mut visited = BTreeSet::new();
    let mut reached_entry = false;
    while let Some((candidate_addr, end_op_index)) = pending.pop() {
        if !visited.insert(candidate_addr) {
            continue;
        }
        let Some(block) = function.get_block(candidate_addr) else {
            return false;
        };
        let Some(ops) = block.ops.get(..end_op_index) else {
            return false;
        };
        for (op_index, op) in ops.iter().enumerate() {
            // A call's clobbers are the `CallDefine`s that follow it, each a
            // definition checked for overlap below; the call itself touches
            // only the carrier the transfer moves. A user operation writes only its named output.
            if matches!(op, SSAOp::Return { .. })
                || (matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
                    && transfer_carrier
                        .is_some_and(|carrier| register_storages_overlap(carrier, storage)))
            {
                return false;
            }
            if op.dst().is_none() {
                continue;
            }
            let Some(inst) = graph
                .inst_id_for_op_site(candidate_addr, op_index)
                .and_then(|inst| graph.inst(inst))
            else {
                return false;
            };
            if inst
                .canonical_storage
                .is_some_and(|written| register_storages_overlap(written, storage))
            {
                return false;
            }
        }
        if candidate_addr == function.entry {
            reached_entry = true;
            continue;
        }
        let predecessors = function.predecessors(candidate_addr);
        if predecessors.is_empty() {
            return false;
        }
        pending.extend(predecessors.into_iter().filter_map(|predecessor| {
            function
                .get_block(predecessor)
                .map(|block| (predecessor, block.ops.len()))
        }));
    }
    reached_entry
}

/// Values this function observes from an exact non-void call result.
///
/// No `CallDefine` means the result is intentionally discarded, which is a
/// complete answer: C renders the non-void call as an expression statement.
/// Once any result definition exists, exactly one definition of the declared
/// carrier must be present; zero or several are an ambiguous boundary.
pub(crate) fn call_result_values_after_call(
    function: &SSAFunction,
    graph: &SsaGraph,
    _machine_context: &SourceMachineContext,
    block_addr: u64,
    call_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<Vec<CallBoundaryValueFact>> {
    let block = function.get_block(block_addr)?;
    let call_defines = block
        .ops
        .get(call_op_index.checked_add(1)?..)?
        .iter()
        .enumerate()
        .take_while(|(_, op)| matches!(op, SSAOp::CallDefine { .. }))
        .collect::<Vec<_>>();
    if call_defines.is_empty() {
        return Some(Vec::new());
    }
    let candidates = call_defines
        .into_iter()
        .filter_map(|(relative_index, op)| {
            let SSAOp::CallDefine { dst } = op else {
                return None;
            };
            let inst = graph.inst_id_for_op_site(
                block_addr,
                call_op_index
                    .saturating_add(1)
                    .saturating_add(relative_index),
            )?;
            let graph_inst = graph.inst(inst)?;
            if dst.size != storage.size || graph_inst.canonical_storage != Some(storage) {
                return None;
            }
            graph_inst.output
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [value] => Some(vec![CallBoundaryValueFact {
            slot: CallBoundarySlot::Register { index: 0, storage },
            value: *value,
        }]),
        _ => None,
    }
}
