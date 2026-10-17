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
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    interface: &r2source::SourceCallSiteInterface,
    fixed_arguments: &[Option<SourceCallArgumentFact>],
    forwarding: &FormatForwardingLookup<'_>,
) -> Result<VariadicCallsiteArgumentCountEvidence, VariadicCallsiteArgumentCountRefusal> {
    let Some(parameter_rule) = interface.format_parameter_rule() else {
        let bound = (interface.exact_callee_interface())
            .and_then(r2source::SourceFunctionInterface::tail_count)
            .ok_or(VariadicCallsiteArgumentCountRefusal::MissingFormatParameter)?;
        return counted_tail_argument_count(graph, prep, interface, fixed_arguments, bound);
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
    if resolve_const_value(graph, prep, format_value).is_none() {
        return merged_format_literal_argument_count(
            FormatLiteralContext {
                function,
                prep,
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
    let format_literal_address =
        resolve_const_value(graph, prep, format_value).ok_or_else(|| {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "format argument {format_argument_index} at {:?} is {:?} (root {:?}), \
                 graph literal {:?}, defined by {:?}",
                interface
                    .arguments()
                    .get(format_argument_index)
                    .map(|argument| argument.location()),
                format_var,
                prep.map(|prep| prep.canonical_root(format_value)),
                resolve_graph_literal_value(graph, prep, format_value),
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
        basis: VariadicCountBasis::Format(FormatCountEvidence {
            parameter_rule,
            merged_literals: false,
            format_argument_index,
            format_literal_address,
            format_consumed_argument_count,
        }),
        total_argument_count,
    })
}

/// A variadic call's count from the constant it passes for the parameter its callee's loop bounds
/// its tail by (ADR "Count-driven tail"); any other count stays a counted residual.
fn counted_tail_argument_count(
    graph: &SsaGraph,
    prep: Option<&crate::DecompilePrepFacts>,
    interface: &r2source::SourceCallSiteInterface,
    fixed_arguments: &[Option<SourceCallArgumentFact>],
    bound: r2source::SourceTailCount,
) -> Result<VariadicCallsiteArgumentCountEvidence, VariadicCallsiteArgumentCountRefusal> {
    // A tail this long is no call a count of constants places; the carriers would not be there.
    const LONGEST_TAIL: usize = 1024;
    let index = usize::try_from(bound.parameter_index)
        .map_err(|_| VariadicCallsiteArgumentCountRefusal::CountArgumentUnavailable)?;
    let argument = fixed_arguments
        .get(index)
        .and_then(Option::as_ref)
        .ok_or(VariadicCallsiteArgumentCountRefusal::CountArgumentUnavailable)?;
    let SourceCallArgumentValue::Value(value) = argument.value else {
        return Err(VariadicCallsiteArgumentCountRefusal::CountArgumentNotConstant);
    };
    let bits = resolve_const_value(graph, prep, value)
        .ok_or(VariadicCallsiteArgumentCountRefusal::CountArgumentNotConstant)?;
    let tail_arguments = bound
        .bound(bits)
        .filter(|tail| *tail <= LONGEST_TAIL)
        .ok_or(VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
    let total_argument_count = interface
        .arguments()
        .len()
        .checked_add(tail_arguments)
        .ok_or(VariadicCallsiteArgumentCountRefusal::ArgumentCountOverflow)?;
    Ok(VariadicCallsiteArgumentCountEvidence {
        basis: VariadicCountBasis::Count(TailCountEvidence {
            bound,
            tail_arguments,
        }),
        total_argument_count,
    })
}

/// Every format literal that can reach one merged format argument.
///
/// `None` as soon as a reaching definition is something other than a merge, a
/// copy, or a constant: a count proved from some of the formats would be a
/// count proved from none of them.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
pub(crate) fn reaching_format_literals(
    context: FormatLiteralContext<'_>,
    value: ValueId,
    seen: &mut BTreeSet<ValueId>,
    found: &mut BTreeSet<u64>,
) -> bool {
    let FormatLiteralContext {
        prep,
        graph,
        forwarding,
        ..
    } = context;
    if !seen.insert(value) {
        return true;
    }
    if graph.value(value).is_none() {
        return false;
    }
    if let Some(address) = resolve_const_value(graph, prep, value) {
        found.insert(address);
        return true;
    }
    let Some(definition) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
        r2il::refusal_evidence!(
            "variadic-format-literal",
            "reaching format walk stops at {value:?} ({}), which nothing in this function defines",
            graph.var(value).display_name()
        );
        return false;
    };
    match &definition.payload {
        InstPayload::Phi { .. } | InstPayload::Op(SSAOp::Copy { .. }) => graph
            .inputs(definition.id)
            .iter()
            .all(|input| reaching_format_literals(context, *input, seen, found)),
        // A conditional move selects the format the same way a merge does, and
        // `cmov` is how a compiler spells the choice when it does not branch.
        // Only the two results can be the format; the condition is not one.
        InstPayload::Op(SSAOp::Select { .. }) => graph
            .inputs(definition.id)
            .iter()
            .skip(1)
            .all(|input| reaching_format_literals(context, *input, seen, found)),
        InstPayload::Op(op) => {
            // An address the code computes from constants -- a page and an
            // offset, the way arm64 spells one -- is the literal it names.
            if let Some(address) = crate::constant::prepared_folded_value(graph, prep, value) {
                found.insert(address);
                return true;
            }
            // A translation of a msgid consumes what the msgid consumes, so
            // the literal handed to the translator is the one that counts.
            if let Some(msgid) = forwarding.translated_msgid(context, value) {
                return reaching_format_literals(context, msgid, seen, found);
            }
            // Which operation the walk cannot see through is the fact that
            // decides whether the count is unprovable or merely unproven here.
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "reaching format walk stops at {value:?} ({}), defined by {}",
                graph.var(value).display_name(),
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
    pub(crate) prep: Option<&'a crate::DecompilePrepFacts>,
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
    fn call_of_result(&self, graph: &SsaGraph, definition: InstId) -> Option<CallSiteId> {
        if let Some(call_site) = self.call_sites.by_inst.get(definition) {
            return Some(*call_site);
        }
        let (block_addr, op_index) = graph.walk_start(definition)?;
        let block = graph.inst(definition)?.block;
        let insts = graph.op_insts(block);
        if !matches!(graph.op(*insts.get(op_index)?)?, SSAOp::CallDefine { .. }) {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "{definition:?} at {block_addr:#x}:{op_index} defines the format but the graph spells it {}",
                graph
                    .inst(definition)
                    .map_or("nothing".to_string(), |inst| format!("{:?}", inst.payload)
                        .chars()
                        .take(28)
                        .collect::<String>())
            );
            return None;
        }
        let call = insts[..op_index]
            .iter()
            .rev()
            .find(|inst| !matches!(graph.op(**inst), Some(SSAOp::CallDefine { .. })))?;
        let site = self.call_sites.by_inst.get(*call).copied();
        if site.is_none() {
            r2il::refusal_evidence!(
                "variadic-format-literal",
                "the call at {block_addr:#x} defining the format correlates to no call site"
            );
        }
        site
    }

    /// The msgid a translation call was handed, when `value` is its result.
    fn translated_msgid(
        &self,
        context: FormatLiteralContext<'_>,
        value: ValueId,
    ) -> Option<ValueId> {
        let FormatLiteralContext {
            function,
            prep,
            graph,
            machine_context,
            ..
        } = context;
        let definition = graph.def_inst(value)?;
        // A call's results are `CallDefine` operations that follow it, so the
        // value's own definition is not the call; the call is the operation
        // the run of defines began after.
        let Some(call_site) = self.call_of_result(graph, definition) else {
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
        let (block_addr, op_index) = graph.walk_start(fact.at)?;
        match reaching_abi_argument_in_block(
            function,
            prep,
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
        basis: VariadicCountBasis::Format(FormatCountEvidence {
            parameter_rule,
            merged_literals: addresses.len() > 1,
            format_argument_index,
            format_literal_address,
            format_consumed_argument_count,
        }),
        total_argument_count,
    })
}

/// Recover exactly the carriers requested by a proven format count.
pub(crate) struct VariadicCallsiteRecovery<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) prep: Option<&'a crate::DecompilePrepFacts>,
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
    mut stack_pointer: Option<&mut ReachingStorage<'_>>,
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
                    prep: recovery.prep,
                    graph: recovery.graph,
                    block_addr: recovery.block_addr,
                    op_index: recovery.op_index,
                },
                StackArgument {
                    offset,
                    callee_offset: offset,
                    size_bytes: placement.stride_bytes(),
                },
                stack_pointer.as_deref_mut(),
            )
            .ok_or(VariadicCallsiteArgumentCountRefusal::UnresolvedArgumentCarrier)?;
            arguments.push(SourceCallArgumentFact {
                slot: CallBoundarySlot::Stack(entry_offset),
                value: SourceCallArgumentValue::Value(value),
                lane_of: None,
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
            recovery.prep,
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
            lane_of: None,
        });
    }
    Ok(arguments)
}

/// What a call boundary carries when nothing knows the callee's signature.
pub(crate) struct ConventionCallBoundary {
    pub(crate) calling_convention: String,
    pub(crate) arguments: Vec<SourceCallArgumentFact>,
    /// Why the registers do not prove how many arguments the call takes; the results stand either way.
    pub(crate) unproven: Option<CallBoundaryRefusal>,
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
    pub(crate) prep: Option<&'a crate::DecompilePrepFacts>,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) block_addr: u64,
    pub(crate) op_index: usize,
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
    stack_pointer: Option<&mut ReachingStorage<'_>>,
) -> Option<(ValueId, i64)> {
    let CallPosition {
        function,
        prep,
        graph,
        block_addr,
        op_index: call_op_index,
        ..
    } = at;
    let StackArgument {
        offset,
        callee_offset,
        size_bytes,
    } = argument;
    let Some((entering, transfer_moved_carrier)) =
        call_entering_stack_pointer_offset(at, stack_pointer)
    else {
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
        prep,
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
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    block_addr: u64,
    boundary: usize,
    query: StackSlotQuery<'_>,
    visited: &mut BTreeSet<u64>,
) -> Option<ValueId> {
    if !visited.insert(block_addr) {
        return None;
    }
    let block = graph.block_id_for_addr(block_addr)?;
    let var = |id: ValueId| graph.var(id);
    let ops = graph.op_insts(block).get(..boundary)?;
    for op in ops.iter().rev().filter_map(|inst| graph.op(*inst)) {
        match *op {
            SSAOp::Copy { dst, src } if query.promoted && var(dst).name() == query.slot_name => {
                if var(dst).size != query.size_bytes {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) promoted slot {} is {} bytes, the argument is {}",
                        query.slot_name,
                        var(dst).size,
                        query.size_bytes
                    );
                    return None;
                }
                return Some(src);
            }
            _ if (op.is_call() || matches!(op, SSAOp::CallOther { .. })) && !query.promoted => {
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
                let Some(root) = resolve_entry_stack_root(prep, addr) else {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) store through {} has no root (wanted {:?} {})",
                        var(addr),
                        query.base,
                        query.entry_offset
                    );
                    continue;
                };
                if root.base != query.base || root.offset != query.entry_offset {
                    continue;
                }
                if var(val).size != query.size_bytes {
                    r2il::refusal_evidence!(
                        "call-argument-stack-store",
                        "({block_addr:#x}) store at entry offset {} is {} bytes, slot is {}",
                        query.entry_offset,
                        var(val).size,
                        query.size_bytes
                    );
                    return None;
                }
                return Some(val);
            }
            _ => {}
        }
    }
    if query.promoted
        && let Some(phi) = (graph.phi_insts(block).iter())
            .filter_map(|inst| graph.inst(*inst)?.output)
            .find(|phi| var(*phi).name() == query.slot_name && var(*phi).size == query.size_bytes)
    {
        return Some(phi);
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
        let boundary = graph.op_insts(graph.block_id_for_addr(predecessor)?).len();
        let value = reaching_stack_slot_value(
            function,
            prep,
            graph,
            predecessor,
            boundary,
            query,
            visited,
        )?;
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

/// Whether the body writes `slot` anywhere other than as a call's clobber. O(values).
fn body_writes(graph: &SsaGraph, slot: CanonicalStorageId) -> bool {
    graph.values.iter().any(|value| {
        value
            .canonical_storage
            .is_some_and(|storage| register_storages_overlap(storage, slot))
            && graph.written_by_body(value.id)
            && !value_is_call_clobber(graph, value.id)
    })
}

/// The arity a call takes from the convention when no prototype describes it: exactly what its
/// callee's body states, or else the argument registers this body provably wrote before the call,
/// never proven past a floor (ROADMAP P7); and the result register where it is read.
pub(crate) fn convention_call_boundary(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    live_out: &crate::liveout::FunctionLiveOut,
    block_addr: u64,
    op_index: usize,
    arity: Option<crate::SourceArity>,
    entry_values: &BTreeMap<CanonicalStorageId, Option<ValueId>>,
    written_anywhere: &mut BTreeMap<CanonicalStorageId, bool>,
    mut stack_pointer: Option<&mut ReachingStorage<'_>>,
) -> Result<ConventionCallBoundary, CallBoundaryRefusal> {
    let convention =
        (machine_context.convention_slots()).ok_or(CallBoundaryRefusal::NoConvention)?;
    let results = |convention: &r2source::SourceConventionSlots| {
        convention
            .result_slot()
            .and_then(|storage| {
                observed_convention_call_result_after_call(
                    graph, live_out, block_addr, op_index, storage,
                )
            })
            .into_iter()
            .collect()
    };
    let at = CallPosition {
        function,
        prep,
        graph,
        block_addr,
        op_index,
    };
    if let Some(crate::SourceArity::Exact(count)) = arity {
        let (arguments, arguments_proven) =
            stated_call_arguments(at, machine_context, count, entry_values, stack_pointer);
        return Ok(ConventionCallBoundary {
            calling_convention: convention.calling_convention().to_string(),
            arguments,
            unproven: (!arguments_proven).then_some(CallBoundaryRefusal::StatedArgumentUnreached {
                count: position(count),
            }),
            results: results(convention),
        });
    }
    let at_least = arity.map_or(0, crate::SourceArity::floor);
    // Whether a call returns its result in `slot`: what a call leaves there is a value, elsewhere garbage.
    let result_slot = |slot: CanonicalStorageId| {
        machine_context
            .abi_model()
            .return_registers()
            .iter()
            .any(|register| {
                let storage = register.storage();
                storage.space == slot.space && storage.offset == slot.offset
            })
    };
    // Whether this function itself may take `slot` as a parameter: its interface says, and while
    // recovery has none yet, any slot the body did not write may be one it hands on.
    let own_parameter = |slot: CanonicalStorageId| {
        machine_context
            .function_interface()
            .is_none_or(|interface| {
                interface
                    .parameters()
                    .iter()
                    .filter_map(|parameter| parameter.register_storage())
                    .any(|storage| storage.space == slot.space && storage.offset == slot.offset)
            })
    };
    // A slot past `position` the body writes, reached through slots that could each be an
    // argument too. Arguments fill in order, so an untouched slot that is no parameter of this
    // function, which nothing could pass, proves the count ends below it.
    let written_later = |position: usize| {
        for slot in convention
            .argument_slots()
            .iter()
            .skip(position + 1)
            .copied()
        {
            match reaching_abi_value_in_block_with_policy(
                function,
                prep,
                graph,
                machine_context,
                block_addr,
                op_index,
                slot,
                false,
            ) {
                Some(ReachingAbiState::Value(value))
                    if graph.written_by_body(value) && !value_is_call_clobber(graph, value) =>
                {
                    return Some(slot);
                }
                Some(ReachingAbiState::PreservedEntry) if !own_parameter(slot) => return None,
                // What a call left outside its result is garbage: nothing a callee could take.
                Some(ReachingAbiState::Value(value))
                    if value_is_call_clobber(graph, value) && !result_slot(slot) =>
                {
                    return None;
                }
                Some(ReachingAbiState::Value(value))
                    if !graph.written_by_body(value) && !own_parameter(slot) =>
                {
                    return None;
                }
                _ => {}
            }
        }
        None
    };
    // A call's result in an argument slot, with a later slot written: the result may be passed on
    // (an accumulator), so the count is unproven.
    let passes_result_on = |slot: CanonicalStorageId, position: usize| {
        let written = result_slot(slot).then(|| written_later(position)).flatten();
        if let Some(written) = written {
            r2il::refusal_evidence!(
                "convention-arity-unproven",
                "callsite ({block_addr:#x}, {op_index}) holds a call's result in argument slot {position}, yet the body writes {written:?}"
            );
        }
        written.is_some()
    };
    let mut arguments = Vec::new();
    let mut unproven = None;
    for (position, slot) in convention.argument_slots().iter().enumerate() {
        let Ok(index) = u32::try_from(position) else {
            break;
        };
        // A call whose signature nothing knows takes its arity from the registers this body provably
        // wrote before it, and at least the `at_least` its callee's own body reads, whoever wrote them.
        let reaching = reaching_abi_value_in_block_with_policy(
            function,
            prep,
            graph,
            machine_context,
            block_addr,
            op_index,
            *slot,
            // Below the floor the callee reads the slot whatever merges into it.
            position < at_least,
        );
        let value = match reaching {
            // What an earlier call left ends the count, unless the body writes a later slot: then the
            // result may be passed on (an accumulator) and the count is unproven.
            Some(ReachingAbiState::Value(value))
                if value_is_call_clobber(graph, value) && position >= at_least =>
            {
                if passes_result_on(*slot, position) {
                    unproven = Some(CallBoundaryRefusal::ResultPassedOn { slot: index });
                }
                break;
            }
            Some(ReachingAbiState::Value(value)) if graph.written_by_body(value) => {
                SourceCallArgumentValue::Value(value)
            }
            // What this body arrived with: the call may read it, and only its callee says whether.
            Some(ReachingAbiState::Value(value)) if position < at_least => {
                SourceCallArgumentValue::Value(value)
            }
            // The arrival is named where the body has a value for it, which a rendering can account.
            Some(ReachingAbiState::PreservedEntry) if position < at_least => {
                match entry_values.get(slot).copied().flatten() {
                    Some(value) => SourceCallArgumentValue::Value(value),
                    None => SourceCallArgumentValue::PreservedEntry,
                }
            }
            // A slot the body did not write (an untouched or caller-supplied entry value, or one
            // it cannot see) ends the count unless the body writes a later one, or the slot holds
            // this function's own parameter: either way the call may be passed it.
            Some(_) | None => {
                // A merge the walk cannot resolve may hold an argument where the body writes the
                // register at all; a merge of arrivals and call clobbers holds none.
                let unseen_write = reaching.is_none()
                    && *written_anywhere
                        .entry(*slot)
                        .or_insert_with(|| body_writes(graph, *slot));
                if unseen_write || own_parameter(*slot) {
                    r2il::refusal_evidence!(
                        "convention-arity-unproven",
                        "callsite ({block_addr:#x}, {op_index}) may hand on parameter slot {position}"
                    );
                    unproven = Some(CallBoundaryRefusal::MayHandOn { slot: index });
                    break;
                }
                if let Some(written) = written_later(position) {
                    r2il::refusal_evidence!(
                        "convention-arity-unproven",
                        "callsite ({block_addr:#x}, {op_index}) did not write argument slot {position}, yet the body writes {written:?}"
                    );
                    unproven = Some(CallBoundaryRefusal::SlotSkipped { slot: index });
                    break;
                }
                break;
            }
        };
        let (value, lane_of) = super::shared::narrowed_argument(prep, graph, value, *slot);
        arguments.push(SourceCallArgumentFact {
            slot: CallBoundarySlot::Register {
                index,
                storage: *slot,
            },
            value,
            lane_of,
        });
    }
    // A variadic or unprototyped call counts no argument past its callee's floor from registers.
    if count_register_set(at, machine_context) {
        arguments.truncate(at_least);
        unproven = Some(CallBoundaryRefusal::CountRegisterSet);
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
        (graph.block_id_for_addr(block_addr)).ok_or(CallBoundaryRefusal::ArgumentAreaUnseen)?;
        if call_entering_stack_pointer_offset(
            CallPosition {
                function,
                prep,
                graph,
                block_addr,
                op_index,
            },
            stack_pointer.as_deref_mut(),
        )
        .is_none()
        {
            r2il::refusal_evidence!(
                "convention-argument-area",
                "callsite ({block_addr:#x}, {op_index}) cannot see the argument area its convention passes on"
            );
            return Err(CallBoundaryRefusal::ArgumentAreaUnseen);
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
                    prep,
                    graph,
                    block_addr,
                    op_index,
                },
                StackArgument {
                    offset,
                    callee_offset: offset.saturating_add(spent),
                    size_bytes: placement.stride_bytes(),
                },
                stack_pointer.as_deref_mut(),
            ) else {
                break;
            };
            arguments.push(SourceCallArgumentFact {
                slot: CallBoundarySlot::Stack(entry_offset),
                value: SourceCallArgumentValue::Value(value),
                lane_of: None,
            });
        }
    }

    // A floor is no call's contract: a slot the count found past it is shown, never proven (W7).
    let past_floor = arity.is_some() && arguments.len() > at_least;
    if past_floor && unproven.is_none() {
        r2il::refusal_evidence!(
            "convention-arity-floor",
            "callsite ({block_addr:#x}, {op_index}) calls a callee that takes at least {at_least} arguments; this body wrote {}",
            arguments.len()
        );
        unproven = Some(CallBoundaryRefusal::Floor {
            floor: position(at_least),
            written: position(arguments.len()),
        });
    }
    Ok(ConventionCallBoundary {
        calling_convention: convention.calling_convention().to_string(),
        arguments,
        unproven,
        results: results(convention),
    })
}

/// A count or slot position as a refusal states it.
fn position(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// The `count` arguments a callee's body states it takes, as they reach the call, register slots
/// first, then the argument area; and whether each was found. O(count) reaching walks.
fn stated_call_arguments(
    at: CallPosition<'_>,
    machine_context: &SourceMachineContext,
    count: usize,
    entry_values: &BTreeMap<CanonicalStorageId, Option<ValueId>>,
    mut stack_pointer: Option<&mut ReachingStorage<'_>>,
) -> (Vec<SourceCallArgumentFact>, bool) {
    let Some(convention) = machine_context.convention_slots() else {
        return (Vec::new(), false);
    };
    let registers = convention.argument_slots();
    let mut arguments = Vec::with_capacity(count);
    for (position, slot) in registers.iter().take(count).enumerate() {
        // The callee reads the slot whatever merges into it.
        let reaching = reaching_abi_value_in_block_with_policy(
            at.function,
            at.prep,
            at.graph,
            machine_context,
            at.block_addr,
            at.op_index,
            *slot,
            true,
        );
        let value = match reaching {
            Some(ReachingAbiState::Value(value)) => SourceCallArgumentValue::Value(value),
            Some(ReachingAbiState::PreservedEntry) => {
                entry_values.get(slot).copied().flatten().map_or(
                    SourceCallArgumentValue::PreservedEntry,
                    SourceCallArgumentValue::Value,
                )
            }
            None => return (arguments, false),
        };
        let (value, lane_of) = super::shared::narrowed_argument(at.prep, at.graph, value, *slot);
        let Ok(index) = u32::try_from(position) else {
            return (arguments, false);
        };
        arguments.push(SourceCallArgumentFact {
            slot: CallBoundarySlot::Register {
                index,
                storage: *slot,
            },
            value,
            lane_of,
        });
    }
    let stacked = count.saturating_sub(registers.len());
    if stacked == 0 {
        return (arguments, true);
    }
    let Some(placement) = convention.stack_arguments() else {
        return (arguments, false);
    };
    let spent = machine_context.return_mechanism().map_or(0, |mechanism| {
        i64::from(mechanism.stack_pointer_delta_bytes())
    });
    for position in 0..stacked {
        let Some(offset) = placement.offset_of(position) else {
            return (arguments, false);
        };
        let argument = StackArgument {
            offset,
            callee_offset: offset.saturating_add(spent),
            size_bytes: placement.stride_bytes(),
        };
        let Some((value, entry_offset)) =
            reaching_stack_argument_before_call(at, argument, stack_pointer.as_deref_mut())
        else {
            return (arguments, false);
        };
        arguments.push(SourceCallArgumentFact {
            slot: CallBoundarySlot::Stack(entry_offset),
            value: SourceCallArgumentValue::Value(value),
            lane_of: None,
        });
    }
    (arguments, true)
}

/// The boundary a convention built for a callee that mints no contract, beside what the callee's
/// body `stated`, where it states anything (CalleeStatement), or why an import states nothing.
fn adopt_convention(
    boundary: &mut SourceCallBoundaryFact,
    convention: ConventionCallBoundary,
    stated: Option<&crate::machine_context::CalleeStatement>,
    unstated: Option<crate::UnstatedImport>,
) {
    boundary.calling_convention = Some(convention.calling_convention);
    // Nothing said this callee is variadic, and the count came from the machine rather than from a
    // prototype, so every argument found is a fixed one as far as anything here can tell.
    boundary.variadic = Some(false);
    let arguments_proven = convention.unproven.is_none();
    boundary.fixed_argument_count = arguments_proven.then_some(convention.arguments.len());
    boundary.arguments = convention.arguments;
    // The convention's result is a guess about the caller's side; the callee's own proven
    // result, where its statement carries one, is the callee's fact (CalleeStatement).
    boundary.result_kind = stated
        .and_then(|statement| statement.result)
        .filter(|result| {
            !matches!(result, SourceCallResult::Void) || convention.results.is_empty()
        });
    boundary.results = convention.results;
    boundary.arguments_complete = arguments_proven;
    // A count no callee statement bounds is the caller's registers, not the callee's arity.
    boundary.arguments_proven = arguments_proven && stated.is_some();
    boundary.results_complete = true;
    boundary.complete = arguments_proven;
    // An import states its arguments only through a declaration; a count read for it is moot.
    boundary.refusal = match (unstated, convention.unproven, stated) {
        (Some(import), _, None) => Some(CallBoundaryRefusal::ImportUnstated(import)),
        (_, Some(refusal), _) => Some(refusal),
        (_, None, None) => Some(CallBoundaryRefusal::CountFromRegisters),
        (_, None, Some(_)) => None,
    };
}

pub(crate) fn collect_source_boundary_facts(
    body: Body<'_>,
    call_sites: &CallSiteFacts,
    live_out: &crate::liveout::FunctionLiveOut,
) -> SourceBoundaryFacts {
    let Body {
        function,
        prep,
        graph,
        machine_context,
    } = body;
    // Calls read register arguments implicitly, so a preserved entry carrier
    // has no graph use at the call instruction. Index exact entry values once
    // for the whole boundary pass and attach that identity when the reaching
    // proof says the carrier was untouched.
    let entry_values = unique_entry_values_by_storage(graph);
    // One reaching solve of the stack pointer for every call that asks where it stands.
    let mut stack_pointer_states = function
        .stack_pointer_carrier()
        .map(|stack_pointer| ReachingStorage::new(function, graph, stack_pointer));
    let mut facts = SourceBoundaryFacts {
        parameters: machine_context
            .map(|machine_context| collect_source_formal_parameter_facts(graph, machine_context))
            .unwrap_or_default(),
        ..SourceBoundaryFacts::default()
    };

    // Whether the body writes each argument register an unseen slot asks of, found once per register.
    let mut written_anywhere = BTreeMap::new();
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
            arguments_proven: false,
            refusal: Some(CallBoundaryRefusal::NoConvention),
        };
        if let Some((machine_context, interface)) = machine_context.and_then(|context| {
            call_site
                .raw_identity
                .and_then(|identity| context.call_site_interface(identity))
                .map(|interface| (context, interface))
        }) {
            boundary.calling_convention = Some(interface.calling_convention().to_string());
            boundary.variadic = Some(interface.is_variadic());
            boundary.noreturn = Some(interface.is_noreturn());
            boundary.result_kind = Some(interface.result());
            boundary.refusal = Some(CallBoundaryRefusal::InterfaceIncomplete);
            if interface.is_complete()
                && let Some((block_addr, op_index)) = graph.walk_start(call_site.at)
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
                                prep,
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
                            found.map(|value| {
                                let (value, lane_of) =
                                    super::shared::narrowed_argument(prep, graph, value, storage);
                                SourceCallArgumentFact {
                                    slot: CallBoundarySlot::Register {
                                        index: argument.index(),
                                        storage,
                                    },
                                    value,
                                    lane_of,
                                }
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
                                    prep,
                                    graph,
                                    block_addr,
                                    op_index,
                                },
                                StackArgument {
                                    offset,
                                    callee_offset,
                                    size_bytes,
                                },
                                stack_pointer_states.as_mut(),
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
                                lane_of: None,
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
                            graph,
                            machine_context,
                            block_addr,
                            op_index,
                            storage,
                        )
                    }
                    // Each half is the value the call leaves in its register, low first.
                    (CallSiteTransfer::Call, SourceCallResult::Pair { low, high }) => [low, high]
                        .into_iter()
                        .map(|storage| {
                            call_result_values_after_call(
                                graph,
                                machine_context,
                                block_addr,
                                op_index,
                                storage,
                            )
                        })
                        .collect::<Option<Vec<_>>>()
                        .map(|halves| halves.concat()),
                };
                boundary.fixed_argument_count = Some(interface.arguments().len());
                let arguments_complete = if interface.is_variadic() {
                    match variadic_callsite_argument_count(
                        function,
                        prep,
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
                                    prep,
                                    graph,
                                    machine_context,
                                    entry_values: &entry_values,
                                    block_addr,
                                    op_index,
                                },
                                interface,
                                &fixed_arguments,
                                evidence,
                                stack_pointer_states.as_mut(),
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
                    boundary.arguments = fixed_arguments.iter().flatten().copied().collect();
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
                let unreached = (interface.arguments().iter().zip(&fixed_arguments))
                    .find(|(_, found)| found.is_none())
                    .map(|(argument, _)| argument.index());
                boundary.refusal = match (boundary.variadic_argument_count_refusal, unreached) {
                    _ if arguments_complete && results_complete => None,
                    _ if arguments_complete => Some(CallBoundaryRefusal::ResultUnreached),
                    (Some(refusal), _) => Some(CallBoundaryRefusal::VariadicCount(refusal)),
                    (None, Some(index)) => {
                        Some(CallBoundaryRefusal::DeclaredArgumentUnreached { index })
                    }
                    (None, None) => Some(CallBoundaryRefusal::InterfaceIncomplete),
                };
                boundary.arguments_complete = arguments_complete;
                boundary.arguments_proven = arguments_complete;
                boundary.results_complete = results_complete;
                boundary.complete = arguments_complete && results_complete;
            }
        }
        // A callee that mints no contract (a floor of parameters, or an unproven result) is called
        // with what this body provably wrote, at least what the callee reads (CalleeStatement).
        if !boundary.complete
            && boundary.calling_convention.is_none()
            && let Some(machine_context) = machine_context
            && let Some((block_addr, op_index)) = graph.walk_start(call_site.at)
        {
            let stated = call_site
                .direct_target
                .and_then(|target| machine_context.callee_statement(target));
            let convention = convention_call_boundary(
                function,
                prep,
                graph,
                machine_context,
                live_out,
                block_addr,
                op_index,
                stated.map(|statement| statement.arity),
                &entry_values,
                &mut written_anywhere,
                stack_pointer_states.as_mut(),
            );
            // One record of what the fallback was asked and what it answered.
            r2il::refusal_evidence!(
                "call-boundary-fallback",
                "callsite ({block_addr:#x}, {op_index}) raw_identity={:?} target={:?} arity={:?} interface={} built={} arguments={} results={}",
                call_site.raw_identity,
                call_site.direct_target,
                stated.map(|statement| statement.arity),
                call_site
                    .raw_identity
                    .is_some_and(|identity| machine_context
                        .call_site_interface(identity)
                        .is_some()),
                convention.is_ok(),
                convention.as_ref().map_or(0, |found| found.arguments.len()),
                convention.as_ref().map_or(0, |found| found.results.len())
            );
            match convention {
                Err(refusal) => boundary.refusal = Some(refusal),
                Ok(convention) => {
                    let unstated = call_site
                        .direct_target
                        .and_then(|target| machine_context.unstated_import(target));
                    adopt_convention(&mut boundary, convention, stated, unstated);
                }
            }
        }
        debug_assert_eq!(
            boundary.refusal.is_none(),
            boundary.complete && boundary.arguments_proven,
            "{boundary:?}"
        );
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
                    // A pair's two registers are the return slots, low first.
                    Some(
                        SourceFunctionReturn::Register { .. } | SourceFunctionReturn::Pair { .. },
                    ) if abi_is_coherent => {
                        if let Some((block_addr, op_index)) = graph.walk_start(inst.id) {
                            for slot in return_slots {
                                if let Some(value) = reaching_source_return_register_in_block(
                                    function,
                                    prep,
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
                        .walk_start(inst.id)
                        .and_then(|(block_addr, op_index)| {
                            reaching_preserved_abi_value_in_block(
                                function,
                                prep,
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
    // (doc/adr-register-identity.md §6), the one value every entry read of
    // that lane is.
    for (value, storage) in graph.formal_projections() {
        values
            .entry(*storage)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(value));
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
    let [target_id] = graph.inputs(return_inst.id) else {
        r2il::refusal_evidence!(
            "return-address",
            "return has {} inputs, not one",
            graph.inputs(return_inst.id).len()
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
        && let [source_id] = graph.inputs(producer.id)
        && let Some(source) = graph.value(*source_id)
        && let InstPayload::Op(SSAOp::Copy { dst, src }) = &producer.payload
        && producer.block == return_inst.block
        && producer.ordinal.checked_add(1) == Some(return_inst.ordinal)
        && producer.output == Some(target.id)
        && target.id == *dst
        && *source_id == *src
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
            InstPayload::Op(SSAOp::Copy { dst, .. }) if carried.id == *dst => {
                graph.inputs(producer.id).first()
            }
            InstPayload::Op(SSAOp::IntAnd { dst, b, .. })
                if carried.id == *dst
                    && graph.var(*b).is_const()
                    && graph
                        .var(*b)
                        .constant_bits()
                        .is_some_and(|mask| mask & 1 == 0) =>
            {
                graph.inputs(producer.id).first()
            }
            // The word an epilogue reloaded is the address the call pushed.
            InstPayload::Op(SSAOp::Load {
                space: r2il::SpaceId::Ram,
                dst,
                ..
            }) if carried.id == *dst => {
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
                && graph.inputs(inst.id) == [target.id]
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
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ValueId> {
    let found = reaching_abi_value_in_block(
        function,
        prep,
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

/// Whether the body sets the convention's vector count for the call at `(block_addr, op_index)` and
/// for nothing else: a constant at most 8 only that call reads (psABI 3.5.7, ADR "Variadic tail").
fn count_register_set(at: CallPosition<'_>, machine_context: &SourceMachineContext) -> bool {
    let CallPosition {
        prep,
        graph,
        block_addr,
        op_index,
        ..
    } = at;
    let (Some(prep), Some(count)) = (
        prep,
        (machine_context.convention_slots()).and_then(|slots| slots.variadic_count_register()),
    ) else {
        return false;
    };
    // The call's own read of the count register names the value that reaches it.
    let reads = graph.boundary_reads_spelled_at(block_addr, op_index);
    let Some(value) = reads.iter().find_map(|read| match graph.op(*read) {
        Some(SSAOp::CallUse { src }) => (graph.value(*src))
            .and_then(|value| value.canonical_storage)
            .is_some_and(|storage| register_storages_overlap(storage, count))
            .then_some(*src),
        _ => None,
    }) else {
        return false;
    };
    let Some((constant, _)) = prep.views.representative_constant(value) else {
        return false;
    };
    let set = constant <= 8
        && graph.written_by_body(value)
        && !value_is_call_clobber(graph, value)
        && (graph.use_sites(value).iter()).all(|site| reads.contains(&site.inst))
        && !(constant == 0 && scrubs_the_guard(at, machine_context, value, count));
    r2il::refusal_evidence!(
        "convention-arity-unproven",
        "callsite ({block_addr:#x}, {op_index}) count register {value:?} set for it alone: {set}"
    );
    set
}

/// Whether zero `value` overwrites the stack guard the protector loaded into the count register
/// (gcc's `xor eax, eax` after the guard's store): the protector's, not a count. One reaching search.
fn scrubs_the_guard(
    at: CallPosition<'_>,
    machine_context: &SourceMachineContext,
    value: ValueId,
    count: CanonicalStorageId,
) -> bool {
    let CallPosition {
        function,
        prep,
        graph,
        ..
    } = at;
    let Some((block_addr, op_index)) = graph.def_inst(value).and_then(|def| graph.walk_start(def))
    else {
        return false;
    };
    let previous = reaching_abi_value_in_block_with_policy(
        function,
        prep,
        graph,
        machine_context,
        block_addr,
        op_index,
        count,
        false,
    );
    let Some(ReachingAbiState::Value(previous)) = previous else {
        return false;
    };
    let inserted = function.compiler_inserted();
    let mut current = previous;
    // Through the lanes and copies the guard reached the register by, to the protector's read. It
    // ends: each step is to a non-phi op's source, whose def dominates it, so the chain is acyclic.
    loop {
        let Some(def) = graph.def_inst(current) else {
            return false;
        };
        if graph
            .op_for_inst(def)
            .is_some_and(|op| inserted.contains(op))
        {
            return true;
        }
        match graph.op(def) {
            Some(
                SSAOp::Copy { src, .. } | SSAOp::IntZExt { src, .. } | SSAOp::Subpiece { src, .. },
            ) => {
                current = *src;
            }
            _ => return false,
        }
    }
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
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    entry_values: &BTreeMap<CanonicalStorageId, Option<ValueId>>,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<SourceCallArgumentValue> {
    reaching_abi_value_in_block_with_policy(
        function,
        prep,
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
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    boundary_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<ReachingAbiState> {
    reaching_abi_value_in_block_with_policy(
        function,
        prep,
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
        let Some(block) = graph.block_id_for_addr(candidate_addr) else {
            return false;
        };
        let Some(insts) = graph.op_insts(block).get(..end_op_index) else {
            return false;
        };
        for &inst in insts {
            let Some(op) = graph.op(inst) else {
                return false;
            };
            // A call's clobbers are the `CallDefine`s that follow it, each a
            // definition checked for overlap below; the call itself touches
            // only the carrier the transfer moves. A user operation writes only its named output.
            if matches!(op, SSAOp::Return { .. })
                || (op.is_call()
                    && transfer_carrier
                        .is_some_and(|carrier| register_storages_overlap(carrier, storage)))
            {
                return false;
            }
            if op.dst().is_none() {
                continue;
            }
            let Some(inst) = graph.inst(inst) else {
                return false;
            };
            if graph
                .written_storage(inst)
                .is_some_and(|written| register_storages_overlap(written, storage))
            {
                return false;
            }
        }
        if candidate_addr == function.root() {
            reached_entry = true;
            continue;
        }
        let predecessors = function.predecessors(candidate_addr);
        if predecessors.is_empty() {
            return false;
        }
        pending.extend(predecessors.into_iter().filter_map(|predecessor| {
            let block = graph.block_id_for_addr(predecessor)?;
            Some((predecessor, graph.op_insts(block).len()))
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
    graph: &SsaGraph,
    machine_context: &SourceMachineContext,
    block_addr: u64,
    call_op_index: usize,
    storage: CanonicalStorageId,
) -> Option<Vec<CallBoundaryValueFact>> {
    let block = graph.block_id_for_addr(block_addr)?;
    let call_defines = (graph.op_insts(block))
        .get(call_op_index.checked_add(1)?..)?
        .iter()
        .map_while(|&inst| match graph.op(inst)? {
            SSAOp::CallDefine { dst } => Some((inst, *dst)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if call_defines.is_empty() {
        return Some(Vec::new());
    }
    // A call that defines no part of the result register leaves the caller's value there, as
    // one to a body that never writes its argument-slot result does: no value, and complete.
    let defines_storage = call_defines.iter().any(|(inst, _)| {
        (graph.inst(*inst))
            .and_then(|inst| graph.written_storage(inst))
            .is_some_and(|defined| register_storages_overlap(defined, storage))
    });
    if !defines_storage {
        return Some(Vec::new());
    }
    let candidates = call_defines
        .into_iter()
        .filter_map(|(inst, dst)| {
            // The definition of the slot itself, or of the program root whose
            // low lane the slot is (doc/adr-byte-relation.md, B3).
            let graph_inst = graph.inst(inst)?;
            let defined = graph.written_storage(graph_inst)?;
            let exact = defined == storage && graph.var(dst).size == storage.size;
            let rooted = defined.space == storage.space
                && graph.var(dst).size == defined.size
                && machine_context.is_low_lane_of(storage, defined);
            (exact || rooted)
                .then_some(graph_inst.output?)
                .map(|value| (value, defined))
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [(value, defined)] => Some(vec![CallBoundaryValueFact {
            slot: CallBoundarySlot::Register {
                index: 0,
                storage: *defined,
            },
            value: *value,
        }]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    use super::*;

    /// The guard's read reaches the count register through six lanes and zero-extensions, past
    /// any fixed depth, and the zero written over it is still the protector's scrub.
    #[test]
    fn the_scrub_is_found_at_the_end_of_a_long_lane_chain() {
        let rax = Varnode::register(0, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x10, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
        });
        let mut from = Varnode::unique(0x10, 8);
        for step in 1..=5_u64 {
            let (dst, op) = if step % 2 == 1 {
                let dst = Varnode::unique(0x10 + 0x10 * step, 4);
                let op = R2ILOp::Subpiece {
                    dst: dst.clone(),
                    src: from,
                    offset: 0,
                };
                (dst, op)
            } else {
                let dst = Varnode::unique(0x10 + 0x10 * step, 8);
                let op = R2ILOp::IntZExt {
                    dst: dst.clone(),
                    src: from,
                };
                (dst, op)
            };
            block.push(op);
            from = dst;
        }
        block.push(R2ILOp::IntZExt {
            dst: rax.clone(),
            src: from,
        });
        block.push(R2ILOp::IntXor {
            dst: rax.clone(),
            a: rax.clone(),
            b: rax,
        });
        block.push(R2ILOp::Call {
            target: Varnode::constant(0x2000, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let context = SourceMachineContext::from_blocks(&[block.clone()], None);
        let mut function = SSAFunction::from_blocks_raw(&[block], None).expect("a function");
        let load = function
            .get_block(0x1000)
            .and_then(|block| {
                (block.sited()).find_map(|(id, op)| matches!(op, SSAOp::Load { .. }).then_some(id))
            })
            .expect("the guard's read");
        let mut inserted = crate::dense::IdSet::default();
        inserted.insert(load);
        function.record_compiler_inserted(inserted, BTreeSet::new());
        let sealed = crate::function::Lifted::new(function)
            .validate()
            .expect("it validates")
            .seal(&context)
            .expect("it seals");
        let graph = sealed.graph();
        let scrub = (graph.insts.iter())
            .find_map(|inst| match &inst.payload {
                InstPayload::Op(SSAOp::IntXor { .. }) => inst.output,
                _ => None,
            })
            .expect("the scrub");
        let at = CallPosition {
            function: sealed.function(),
            prep: Some(sealed.decompile_prep_facts()),
            graph,
            block_addr: 0x1000,
            op_index: 0,
        };
        let count = CanonicalStorageId {
            space: r2source::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        assert!(scrubs_the_guard(at, &context, scrub, count));
    }
}
