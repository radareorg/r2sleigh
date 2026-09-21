//! The stack slots the declaration names.

use super::*;

/// Record a declaration at one frame coordinate, keeping the widest.
///
/// Two slots that start at the same address are not two declarations of
/// different things: the wider one contains the narrower, which is a member of
/// it. radare2 routinely produces both -- a DWARF aggregate and the
/// access-inferred fragment it saw first -- and dropping the pair on collision
/// deleted the only declaration that carried an extent and a type, which is
/// what an access has to be found inside. A genuine disagreement is two
/// declarations of the same width that are not the same declaration, and only
/// that is ambiguous.
pub(crate) fn slot_is_declared_aggregate(
    types: Option<&crate::SourceTypeGraph>,
    slot: &SourceStackSlotSpec,
) -> bool {
    let Some((types, id)) = types.zip(slot.logical_type()) else {
        return false;
    };
    types.types().get(id as usize).is_some_and(|source_type| {
        matches!(
            source_type.kind(),
            crate::SourceTypeKind::Struct { .. }
                | crate::SourceTypeKind::Union { .. }
                | crate::SourceTypeKind::Array { .. }
        )
    })
}

pub(crate) fn declare_stack_slot(
    types: Option<&crate::SourceTypeGraph>,
    exact_stack_slots: &mut BTreeMap<(StackAddressBase, i64), SourceStackSlotSpec>,
    ambiguous_stack_slots: &mut BTreeSet<(StackAddressBase, i64)>,
    key: (StackAddressBase, i64),
    slot: SourceStackSlotSpec,
) {
    match exact_stack_slots.get(&key) {
        None => {
            exact_stack_slots.insert(key, slot);
        }
        Some(existing) if *existing == slot => {}
        // Only an aggregate can name what starts inside it. Two scalars of
        // different widths at one address are the ambiguity this always
        // refused, and rendering a narrow read of the wider one would spell
        // the whole object -- the width question, which is answered elsewhere.
        Some(existing)
            if existing.size_bytes() > slot.size_bytes()
                && slot_is_declared_aggregate(types, existing) =>
        {
            r2il::refusal_evidence!(
                "declared-stack-slot",
                "{key:?} keeps its {}-byte aggregate over a {}-byte declaration at the same address",
                existing.size_bytes(),
                slot.size_bytes()
            );
        }
        Some(existing)
            if slot.size_bytes() > existing.size_bytes()
                && slot_is_declared_aggregate(types, &slot) =>
        {
            r2il::refusal_evidence!(
                "declared-stack-slot",
                "{key:?} takes a {}-byte aggregate over the {}-byte declaration at the same address",
                slot.size_bytes(),
                existing.size_bytes()
            );
            exact_stack_slots.insert(key, slot);
        }
        Some(_) => {
            ambiguous_stack_slots.insert(key);
        }
    }
}

pub(crate) fn collect_declared_stack_slots(
    machine_context: Option<&SourceMachineContext>,
) -> DeclaredStackSlots {
    let mut exact_stack_slots = BTreeMap::new();
    let mut ambiguous_stack_slots = BTreeSet::new();
    if let Some(interface) = machine_context.and_then(SourceMachineContext::function_interface) {
        for slot in interface.stack_slots() {
            // Objects are identified by their entry-relative position, and a
            // source states its slots there; one declared against another
            // register has no place in the table and is not guessed into one.
            if slot.base() != StackAddressBase::StackPointer {
                r2il::refusal_evidence!(
                    "declared-stack-slot",
                    "slot {:?} at {} is declared against {:?}, not the entry stack pointer, and is dropped",
                    slot.base_storage(),
                    slot.offset(),
                    slot.base()
                );
                continue;
            }
            declare_stack_slot(
                interface.type_graph(),
                &mut exact_stack_slots,
                &mut ambiguous_stack_slots,
                (slot.base(), slot.offset()),
                *slot,
            );
        }
    }
    for key in ambiguous_stack_slots {
        r2il::refusal_evidence!(
            "declared-stack-slot",
            "key {key:?} was claimed twice and both declarations are dropped"
        );
        exact_stack_slots.remove(&key);
    }
    // What the frame ended up looking like, in the one coordinate objects are
    // identified in. A declared aggregate that never contains the accesses
    // reading its members is invisible, and the extent is what says whether it
    // should have.
    for (key, slot) in &exact_stack_slots {
        r2il::refusal_evidence!(
            "declared-stack-slot",
            "declared {:?} at {key:?} extent {} role {:?} type {:?}",
            slot.base_storage(),
            slot.size_bytes(),
            slot.role(),
            slot.logical_type()
        );
    }
    // A parameter the convention passes on the stack declares its own slot:
    // the interface places it at an entry offset, whatever the source named.
    if let Some(interface) = machine_context.and_then(SourceMachineContext::function_interface)
        && let Some(stack_pointer) = interface.stack_pointer_storage()
    {
        for (position, parameter) in interface.parameters().iter().enumerate() {
            let Some((offset, slot_bytes)) = parameter.location().stack() else {
                continue;
            };
            // The slot is declared at the parameter's own width, not the
            // convention's: `int` in an eight-byte slot is a four-byte slot.
            let size_bytes = interface
                .parameter_logical_value(position)
                .and_then(|logical| u32::try_from(logical.carrier().size_bits() / 8).ok())
                .filter(|bytes| *bytes > 0)
                .unwrap_or(slot_bytes);
            let key = (StackAddressBase::StackPointer, offset);
            let slot = SourceStackSlotSpec::new_parameter(
                StackAddressBase::StackPointer,
                stack_pointer,
                offset,
                size_bytes,
                parameter.index(),
            );
            match exact_stack_slots.get(&key) {
                Some(declared) if declared.role() == slot.role() => {}
                Some(declared) => {
                    r2il::refusal_evidence!(
                        "stack-slot-parameter",
                        "parameter {} at entry offset {offset} is declared as {:?}; the parameter owns it",
                        parameter.index(),
                        declared.role()
                    );
                    exact_stack_slots.insert(key, slot);
                }
                None => {
                    exact_stack_slots.insert(key, slot);
                }
            }
        }
    }
    DeclaredStackSlots {
        by_key: exact_stack_slots,
    }
}
