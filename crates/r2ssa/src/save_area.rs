//! A variadic prologue's register save area, proven from the machine (doc/adr-resolved-bodies.md,
//! "Variadic tail").

use r2source::convention::SlotClass;
use std::collections::{BTreeMap, BTreeSet};

use r2source::{
    CanonicalStorageId, SourceConventionSlots, SourceRegisterSaveArea, SourceSaveAreaAnchor,
    StackAddressBase,
};

use crate::graph::{InstId, InstPayload};
use crate::{SSAOp, SsaGraph, ValueId};

/// The argument registers a body saves to its convention's register save area: the slots below
/// `named` are its fixed parameters, and the entry values it saves are no parameter reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaveArea {
    pub(crate) named: usize,
    pub(crate) saved: crate::dense::IdSet<ValueId>,
    /// Where the area starts, its bound and where `va_start` stored the bound, at
    /// entry-stack-pointer offsets.
    pub(crate) base: i64,
    pub(crate) bound: i64,
    pub(crate) stored_at: i64,
}

/// The register save area the body fills, where its rules prove one (ADR "Variadic tail"), at
/// entry-stack-pointer offsets. O(insts + uses of the saved values), O(insts) per stored bound.
pub(crate) fn register_save_area(
    graph: &SsaGraph,
    prep: &crate::DecompilePrepFacts,
    slots: &SourceConventionSlots,
    observations: &crate::deadphi::ProvenProgramObservations,
) -> Option<SaveArea> {
    let area = slots.register_save_area()?;
    let arguments = slots.argument_slots();
    let width = i64::from(arguments.first()?.size);
    if arguments.iter().any(|slot| i64::from(slot.size) != width) {
        return None;
    }
    let at_entry = |value: ValueId| {
        prep.entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    };
    let (saves, stored_addresses) = entry_saves((graph, prep), arguments, &at_entry);
    let last = arguments.len() - 1;
    let position = |slot: usize| i64::try_from(slot).ok().map(|slot| slot * width);
    for &(top, ..) in &saves[last] {
        let base = top - position(last)?;
        let saved_at = |slot: usize| {
            let at = base + position(slot).unwrap_or(i64::MAX);
            saves[slot].iter().filter(move |(offset, ..)| *offset == at)
        };
        let mut named = last;
        while named > 0 && saved_at(named - 1).next().is_some() {
            named -= 1;
        }
        // A run from slot 0 is every argument spilled in order, an aggregate of them as readily.
        if named == 0 {
            continue;
        }
        let bound = match area.anchor {
            SourceSaveAreaAnchor::Base => base,
            SourceSaveAreaAnchor::End => base + position(arguments.len())?,
        };
        // `va_start`'s own write: the bound stored, and beside it the first unnamed slot's distance.
        let next = base + position(named)? - bound;
        if !stored_addresses.contains(&bound) {
            continue;
        }
        let Some(stored_at) = offset_stored((graph, prep), &at_entry, bound, area, next) else {
            r2il::refusal_evidence!(
                "register-save-area",
                "bound {bound} is stored and no constant {next} sits {} from it",
                area.offset_field
            );
            continue;
        };
        let mut saved = crate::dense::IdSet::new(graph.values.len());
        let mut stores = crate::dense::IdSet::new(graph.insts.len());
        for (_, value, store) in (named..=last).flat_map(saved_at) {
            saved.insert(*value);
            stores.insert(*store);
        }
        let unread = saved
            .iter()
            .find(|value| !read_only_by(graph, *value, &stores, (observations, &TAIL_KEPT)));
        if let Some(value) = unread {
            r2il::refusal_evidence!(
                "register-save-area",
                "the saved {value:?} is read beyond its save"
            );
        } else {
            return Some(SaveArea {
                named,
                saved,
                base,
                bound,
                stored_at,
            });
        }
    }
    r2il::refusal_evidence!(
        "register-save-area",
        "no save area: saves by slot {:?}, addresses stored {stored_addresses:?}",
        saves
            .iter()
            .map(|slot| slot.iter().map(|(at, ..)| *at).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    None
}

/// Microsoft x64's variadic prologue (doc/adr-call-boundary.md, rule 6): `&home[named]` is a declared
/// callee's `va_list` argument, and each later position is read only by its home. O(insts + calls).
pub(crate) fn home_va_list(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    facts: &crate::semantic::PreparedFunctionFacts,
    slots: &SourceConventionSlots,
    machine: &crate::SourceMachineContext,
    observations: &crate::deadphi::ProvenProgramObservations,
) -> Option<SaveArea> {
    let model = machine.convention().filter(|_| slots.shared_positions())?;
    let arguments = slots.argument_slots();
    let at_entry = |value: ValueId| {
        prep.entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    };
    let home_of = |position: usize| Some(model.home(u8::try_from(position).ok()?)?.start);
    let mut named = None::<usize>;
    for boundary in facts.boundaries.calls.values() {
        let callee = (facts.call_sites.by_id.get(&boundary.call_site))
            .and_then(|site| site.raw_identity)
            .and_then(|identity| machine.call_site_interface(identity))
            .and_then(r2source::SourceCallSiteInterface::exact_callee_interface);
        let Some(index) = callee
            .and_then(r2source::SourceFunctionInterface::va_list_parameter)
            .and_then(|index| usize::try_from(index).ok())
        else {
            continue;
        };
        let address = (boundary.arguments.get(index)).and_then(|argument| match argument.value {
            crate::semantic::SourceCallArgumentValue::Value(value) => at_entry(value),
            crate::semantic::SourceCallArgumentValue::PreservedEntry => None,
        });
        let handed =
            address.and_then(|offset| (0..arguments.len()).find(|p| home_of(*p) == Some(offset)));
        r2il::refusal_evidence!(
            "home-va-list",
            "{:?} hands its va_list argument {index} the entry offset {address:?} of {} arguments",
            boundary.call_site,
            boundary.arguments.len()
        );
        match (named, handed) {
            (_, None) => {}
            (None, Some(position)) => named = Some(position),
            (Some(known), Some(position)) if known == position => {}
            (Some(_), Some(_)) => return None,
        }
    }
    // A tail from position 0 leaves no fixed parameter to name it, which C cannot declare.
    let named = named.filter(|named| *named > 0)?;
    homed_tail((graph, prep), model, observations, named)
}

/// Microsoft x64's variadic body walking its own tail from the lowest home whose address it keeps;
/// the area stands only beside a proven `tail_count`. O(insts + uses).
pub(crate) fn home_cursor(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    machine: &crate::SourceMachineContext,
    observations: &crate::deadphi::ProvenProgramObservations,
) -> Option<SaveArea> {
    let model = machine
        .convention()
        .filter(|model| model.shares_positions())?;
    let positions = model.argument_registers(SlotClass::Integer).count();
    let homes = (0..positions)
        .map(|position| Some(model.home(u8::try_from(position).ok()?)?.start))
        .collect::<Option<Vec<_>>>()?;
    // The lowest home whose address is kept: used other than as the address of an access.
    let kept = |value: ValueId| {
        graph.use_sites(value).iter().any(|site| {
            let Some(inst) = graph.inst(site.inst) else {
                return true;
            };
            let unobserved = inst.output.is_some_and(|out| !observations.contains(out));
            match &inst.payload {
                InstPayload::Op(SSAOp::Load { addr, .. }) => *addr != value,
                InstPayload::Op(SSAOp::Store { addr, val, .. }) => *addr != value || *val == value,
                _ => !unobserved,
            }
        })
    };
    let named = (graph.values.iter())
        .filter(|value| graph.def_inst(value.id).is_some())
        .filter_map(|value| {
            let root = prep.entry_stack_address_root_of(value.id)?;
            let at = (root.base == StackAddressBase::StackPointer).then_some(root.offset)?;
            let position = homes.iter().position(|home| *home == at)?;
            kept(value.id).then_some(position)
        })
        .min()?;
    // A kept `&home[0]` is no tail a fixed parameter names.
    (named > 0).then_some(())?;
    homed_tail((graph, prep), model, observations, named)
}

/// The save area of a Microsoft x64 tail from `named`: each later position's entry value read only
/// by its home.
fn homed_tail(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    model: &r2source::ConventionModel,
    observations: &crate::deadphi::ProvenProgramObservations,
    named: usize,
) -> Option<SaveArea> {
    let arguments = model
        .argument_registers(SlotClass::Integer)
        .collect::<Vec<_>>();
    let arguments = arguments.as_slice();
    let at_entry = |value: ValueId| {
        prep.entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    };
    let home_of = |position: usize| Some(model.home(u8::try_from(position).ok()?)?.start);
    // Each tail position's entry value is read only by its home: a store there, or the copy a
    // promoted home left that nothing reads.
    let (saves, _) = entry_saves((graph, prep), arguments, &at_entry);
    let mut saved = crate::dense::IdSet::new(graph.values.len());
    let mut stores = crate::dense::IdSet::new(graph.insts.len());
    for (position, homed) in saves.iter().enumerate().skip(named) {
        let home = home_of(position)?;
        for (_, _, store) in homed.iter().filter(|(at, ..)| *at == home) {
            stores.insert(*store);
        }
    }
    for value in &graph.values {
        if graph.def_inst(value.id).is_none()
            && entry_slot(graph, value.id, arguments).is_some_and(|slot| slot >= named)
        {
            saved.insert(value.id);
        }
    }
    if let Some(value) = saved
        .iter()
        .find(|value| !read_only_by(graph, *value, &stores, (observations, &TAIL_KEPT)))
    {
        r2il::refusal_evidence!(
            "home-va-list",
            "the homed {value:?} is read beyond its home"
        );
        return None;
    }
    let base = home_of(0)?;
    let bound = home_of(named)?;
    Some(SaveArea {
        named,
        saved,
        base,
        bound,
        stored_at: bound,
    })
}

/// A saved tail register a call is handed is a tail still: a variadic header drops no argument.
const TAIL_KEPT: fn(InstId) -> bool = |_| false;

/// Per argument slot, where its entry value is stored: the position, the value and the store.
type Saves = Vec<Vec<(i64, ValueId, InstId)>>;

/// Each slot's entry value stored at a stack position, and every address stored to memory.
fn entry_saves(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    arguments: &[CanonicalStorageId],
    at_entry: &impl Fn(ValueId) -> Option<i64>,
) -> (Saves, BTreeSet<i64>) {
    let mut saves = vec![Vec::new(); arguments.len()];
    let mut stored_addresses = BTreeSet::new();
    for inst in &graph.insts {
        let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
            continue;
        };
        let at = at_entry(*addr);
        if let Some(offset) = at_entry(*val) {
            stored_addresses.insert(offset);
        }
        let value = prep.views.copy_root(*val);
        if let (Some(at), Some(slot)) = (at, entry_slot(graph, value, arguments)) {
            saves[slot].push((at, value, inst.id));
        }
    }
    (saves, stored_addresses)
}

/// Where `bound` is stored, if a constant store, alone or as a little-endian word with its
/// neighbour (clang), holds `next` in the offset field beside it. O(insts).
fn offset_stored(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    at_entry: &impl Fn(ValueId) -> Option<i64>,
    bound: i64,
    area: SourceRegisterSaveArea,
    next: i64,
) -> Option<i64> {
    let stores = || {
        graph.insts.iter().filter_map(|inst| match &inst.payload {
            InstPayload::Op(SSAOp::Store { addr, val, .. }) => Some((at_entry(*addr)?, *val)),
            _ => None,
        })
    };
    let fields = (stores())
        .filter(|(_, val)| at_entry(*val) == Some(bound))
        .map(|(at, _)| (at + area.offset_field, at))
        .collect::<BTreeMap<_, _>>();
    let width = i64::from(area.offset_width);
    let mask = u64::MAX >> (64 - 8 * area.offset_width.clamp(1, 8));
    stores().find_map(|(at, val)| {
        let (bits, size) = prep.views.representative_constant(val)?;
        // `bits` holds at most a word: a wider constant states no field past its eighth byte.
        let last = at + i64::from(size.min(8)) - width;
        if last < at {
            return None;
        }
        (fields.range(at..=last))
            .find(|(field, _)| (bits >> (8 * (**field - at))) & mask == next.cast_unsigned() & mask)
            .map(|(_, stored)| *stored)
    })
}

/// The argument slot `value` is the whole entry value of.
fn entry_slot(graph: &SsaGraph, value: ValueId, arguments: &[CanonicalStorageId]) -> Option<usize> {
    let entry = graph.value(value)?;
    if entry.var.version != 0 || !graph.caller_supplied(value) {
        return None;
    }
    let storage = entry.canonical_storage?;
    arguments.iter().position(|slot| *slot == storage)
}

/// Whether only `stores` read `value`, through merges and copies; a use proven unread (`xor ecx,
/// ecx`) reads nothing, and a call's implicit use reads it where `taken` says the call may.
pub(crate) fn read_only_by(
    graph: &SsaGraph,
    value: ValueId,
    stores: &crate::dense::IdSet<InstId>,
    (observations, taken): (
        &crate::deadphi::ProvenProgramObservations,
        &dyn Fn(InstId) -> bool,
    ),
) -> bool {
    let mut seen = crate::dense::IdSet::new(graph.values.len());
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                return false;
            };
            match (&inst.payload, inst.output) {
                (InstPayload::Phi { .. } | InstPayload::Op(SSAOp::Copy { .. }), output) => {
                    pending.extend(output);
                }
                (InstPayload::Op(SSAOp::CallUse { .. }), _) if !taken(site.inst) => {}
                (_, Some(output)) if observations.proven_unread(output) => {}
                _ if stores.contains(site.inst) => {}
                _ => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};
    use r2source::{
        CanonicalStorageSpace, SourceAbiParameterSpec, SourceFunctionInterface,
        SourceFunctionReturn,
    };

    use super::*;

    const SP: u64 = 0x100;

    fn register(offset: u64) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        }
    }

    /// Three argument slots `x0`..`x2`, a `va_list` holding the byte past the area and, 16 bytes
    /// on, the first unnamed slot's distance from it.
    fn slots() -> SourceConventionSlots {
        SourceConventionSlots::new(
            r2source::ConventionId::SysVAmd64,
            [register(0), register(8), register(16)],
            None,
        )
        .expect("slots")
        .with_register_save_area(Some(SourceRegisterSaveArea {
            anchor: SourceSaveAreaAnchor::End,
            offset_field: 16,
            offset_width: 4,
            stack_field: -8,
        }))
    }

    /// The `va_list` offset field of `named == 1` beside a bound stored at `sp + 0x28`.
    const OFFSET: (u64, u64, u32) = (0x38, (-16_i64).cast_unsigned(), 4);

    /// `sp -= 0x40`, then each `(register, sp offset)` stored, `sp + anchor` stored at `sp + 0x28`,
    /// each `(sp offset, constant, width)` stored, `sp + 0x20` and each of `read` to a global.
    fn body(
        saves: &[(u64, u64)],
        anchor: u64,
        constants: &[(u64, u64, u32)],
        read: &[u64],
    ) -> R2ILBlock {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::register(SP, 8),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(0x40, 8),
        });
        let mut temp = 0;
        let mut at = |block: &mut R2ILBlock, offset: u64| {
            temp += 8;
            block.push(R2ILOp::IntAdd {
                dst: Varnode::unique(temp, 8),
                a: Varnode::register(SP, 8),
                b: Varnode::constant(offset, 8),
            });
            Varnode::unique(temp, 8)
        };
        for &(saved, offset) in saves {
            let addr = at(&mut block, offset);
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr,
                val: Varnode::register(saved, 8),
            });
        }
        let bound = at(&mut block, anchor);
        let field = at(&mut block, 0x28);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: field,
            val: bound,
        });
        for &(offset, constant, width) in constants {
            let addr = at(&mut block, offset);
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr,
                val: Varnode::constant(constant, width),
            });
        }
        // The `va_list` handed on, as `va_start`'s callers do, so the frame stays in memory.
        let list = at(&mut block, 0x20);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
            val: list,
        });
        for &register in read {
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(0x9008, 8),
                val: Varnode::register(register, 8),
            });
        }
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(SP, 8),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(0x40, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(0x108, 8),
        });
        block
    }

    /// The save area `body` proves, prepared under an interface naming its stack pointer.
    fn area(
        saves: &[(u64, u64)],
        anchor: u64,
        constants: &[(u64, u64, u32)],
        read: &[u64],
    ) -> Option<SaveArea> {
        let mut arch = ArchSpec::new("save-area");
        arch.addr_size = 8;
        for (name, offset) in [("x0", 0), ("x1", 8), ("x2", 16), ("sp", SP), ("lr", 0x108)] {
            arch.add_register(RegisterDef::new(name, offset, 8));
        }
        let interface = SourceFunctionInterface::new_exact(
            b"save-area".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [SourceAbiParameterSpec::new(0, register(0))],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("interface")
        .with_return_address_storage(register(0x108))
        .expect("return address")
        .with_stack_pointer_storage(register(SP))
        .expect("stack pointer");
        let artifact = crate::testing::prepared(
            &[body(saves, anchor, constants, read)],
            &crate::Arch::from(arch),
            Some(interface),
            Vec::new(),
            [register(SP)],
        )
        .expect("prepared");
        let graph = artifact.graph();
        let live_out = crate::liveout::FunctionLiveOut::default();
        let observations = crate::deadphi::ProvenProgramObservations::find(
            graph,
            &live_out,
            artifact.facts(),
            None,
        )
        .expect("observations");
        register_save_area(
            graph,
            artifact.decompile_prep_facts(),
            &slots(),
            &observations,
        )
    }

    #[test]
    fn the_registers_past_the_named_ones_saved_in_order_below_a_stored_bound_are_a_tail() {
        let found = area(&[(8, 8), (16, 16)], 24, &[OFFSET], &[]).expect("a save area");
        assert_eq!(found.named, 1);
        assert_eq!(found.saved.len(), 2);
        // clang writes `__gr_offs` and `__vr_offs` as one word.
        let joined = (0x38, 0xffff_ff80_ffff_fff0, 8);
        assert_eq!(area(&[(8, 8), (16, 16)], 24, &[joined], &[]), found.into());
    }

    #[test]
    fn a_save_area_needs_its_bound_stored_a_named_slot_below_it_its_stride_and_no_other_read() {
        let saves = [(8, 8), (16, 16)];
        assert_eq!(area(&saves, 16, &[OFFSET], &[]), None, "no bound stored");
        assert_eq!(
            area(&[(0, 0), (8, 8), (16, 16)], 24, &[OFFSET], &[]),
            None,
            "every slot saved"
        );
        assert_eq!(
            area(&[(8, 16), (16, 8)], 24, &[OFFSET], &[]),
            None,
            "out of order"
        );
        assert_eq!(
            area(&saves, 24, &[OFFSET], &[16]),
            None,
            "a saved register read again"
        );
    }

    /// A struct of arguments 1..n whose address is stored is laid out as a save area, but no
    /// `va_start` wrote the offset field beside that address.
    #[test]
    fn a_suffix_aggregate_whose_address_is_stored_is_no_tail() {
        let saves = [(8, 8), (16, 16)];
        assert_eq!(area(&saves, 24, &[], &[]), None, "no offset field");
        let other = (0x38, (-8_i64).cast_unsigned(), 4);
        assert_eq!(area(&saves, 24, &[other], &[]), None, "another distance");
        let elsewhere = (0x3c, OFFSET.1, 4);
        assert_eq!(area(&saves, 24, &[elsewhere], &[]), None, "another field");
        let vector = (0x30, 0, 16);
        assert_eq!(area(&saves, 24, &[vector], &[]), None, "a vector of zeros");
    }
}
