//! Which of the frame's objects code outside this function can touch.
//!
//! Under the UB-free premise a callee reaches the frame only two ways: through
//! an address this function hands out, and through the argument area of the
//! call, which the callee finds above its own stack pointer. Everything else in
//! the frame is private, and a call neither reads nor writes it. Memory reached
//! through an unknown pointer is the same: only an escaped object can be at the
//! other end of it.
//!
//! - **Escape** is a forward taint from every frame address over the SSA
//!   graph: arithmetic, copies, extensions and merges carry it; a load does
//!   not, since what was stored is whatever was stored, and storing a frame
//!   address is itself an escape. A tainted value that reaches a call argument,
//!   the value of a store, or the inputs of an intrinsic escapes the object it
//!   points into. A tainted value that names no object escapes the whole
//!   frame -- there is no object to blame, so none may be called private.
//!   An access through an address the model places in no object escapes the
//!   object at its offset; a frame address used as code or in an unmodelled
//!   operation escapes the whole frame; a return does not escape (the frame
//!   ends with the call). Private objects are the frame objects not escaped.
//! - **The argument area** of a call is the slots its complete, non-variadic
//!   interface places on the stack, at the stack pointer the call is made with,
//!   and below the first of them the space the convention reserves for the
//!   callee. Without such an interface, or without the stack pointer at the
//!   call, the call reaches every frame object.
//!
//! Cost: O(V + E) for the taint, O(calls x objects) for the argument areas.

use super::*;

/// What one call reaches of the frame besides what has escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFrameReach {
    Objects(BTreeSet<ObjectId>),
    /// Nothing bounds it: the interface is unknown, incomplete or variadic,
    /// or the stack pointer at the call is not placed.
    Whole,
}

/// The frame objects outside code can touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameReach {
    escaped: BTreeSet<ObjectId>,
    /// The objects whose own address escapes, before the closure around them.
    direct: BTreeSet<ObjectId>,
    /// A frame address escaped that names no object, so every frame object is
    /// reachable.
    whole: bool,
    by_call: crate::dense::IdMap<InstId, CallFrameReach>,
}

impl FrameReach {
    /// Whether code outside this function can reach `object` through an
    /// address: any non-frame object can, a frame object only once escaped.
    pub fn escaped(&self, object: ObjectId) -> bool {
        self.whole || self.escaped.contains(&object)
    }

    /// Whether an escaping frame address named no object, so every frame
    /// object is reachable.
    pub const fn whole(&self) -> bool {
        self.whole
    }

    /// Every call this fact bounds or does not, in instruction order.
    pub fn calls(&self) -> impl Iterator<Item = (InstId, &CallFrameReach)> {
        self.by_call.iter()
    }

    /// The frame objects this call reaches through its argument area, beyond
    /// those that have escaped. A call this fact does not know reaches all.
    pub fn call(&self, call: InstId) -> &CallFrameReach {
        const WHOLE: &CallFrameReach = &CallFrameReach::Whole;
        self.by_call.get(call).unwrap_or(WHOLE)
    }

    pub(crate) fn of(
        function: &SSAFunction,
        prep: Option<&crate::DecompilePrepFacts>,
        graph: &SsaGraph,
        model: &ObjectModel,
        machine_context: Option<&SourceMachineContext>,
    ) -> Self {
        let Some(facts) = prep else {
            // Nothing places a frame address, so nothing is proven private.
            return Self {
                whole: true,
                ..Self::default()
            };
        };
        let frame = FrameIndex::of(model);
        let (mut escaped, whole) = escaped_objects(facts, graph, model, &frame);
        let direct = escaped.clone();
        let barriers = compiler_slots(function, graph, model, machine_context);
        close_upward(&mut escaped, &frame, &barriers);
        let by_call = call_reaches(function, graph, facts, &frame, machine_context);
        r2il::refusal_evidence!(
            "frame-reach",
            "{:#x}: {} of {} frame objects escape (whole frame: {whole}), {} calls bounded",
            function.entry,
            escaped.len(),
            frame.len(),
            by_call
                .values()
                .filter(|reach| matches!(reach, CallFrameReach::Objects(_)))
                .count()
        );
        Self {
            escaped,
            direct,
            whole,
            by_call,
        }
    }
}

impl FrameReach {
    /// Each run of escaped frame objects from the lowest whose own address escapes up to a slot the
    /// compiler owns or the frame's top, as one span: an escaped address may reach any of
    /// it, so it is one object, and C's pointer arithmetic across it is defined
    /// (doc/adr-frame-model.md, extent rule; decided 2026-10-07). Only runs of two or more objects.
    pub(crate) fn escape_spans(
        &self,
        function: &SSAFunction,
        graph: &SsaGraph,
        model: &ObjectModel,
        machine_context: Option<&SourceMachineContext>,
    ) -> Vec<(i64, i64)> {
        // Without the convention's saves nothing bounds a run below the return address.
        if self.whole
            || machine_context
                .and_then(SourceMachineContext::call_effect)
                .is_none()
        {
            return Vec::new();
        }
        let frame = FrameIndex::of(model);
        // Any register's entry value stored whole is its own object: a save, the return
        // address, a parameter's home.
        let mut barriers = compiler_slots(function, graph, model, machine_context);
        barriers.extend(graph.insts.iter().filter_map(|inst| match &inst.payload {
            crate::graph::InstPayload::Op(SSAOp::Store { space, .. }) => {
                let (address, mut value) = (*inst.inputs.first()?, *inst.inputs.get(1)?);
                // Through copies and low lanes, as a save of `x29` reads it.
                for _ in 0..graph.values.len() {
                    let definition = graph.def_inst(value).and_then(|inst| graph.inst(inst));
                    match definition.map(|inst| (&inst.payload, inst.inputs.first())) {
                        Some((
                            crate::graph::InstPayload::Op(
                                SSAOp::Copy { .. } | SSAOp::Subpiece { offset: 0, .. },
                            ),
                            Some(source),
                        )) => value = *source,
                        _ => break,
                    }
                }
                let entry = graph.value(value).is_some_and(|value| {
                    value.var.version == 0
                        && value
                            .canonical_storage
                            .is_some_and(|storage| storage.space == CanonicalStorageSpace::Register)
                }) || graph.formal_projection_storage(value).is_some();
                let key = MemoryObjectKey {
                    value: address,
                    space: *space,
                };
                entry
                    .then(|| model.value_objects.get(&key).copied())
                    .flatten()
            }
            _ => None,
        }));
        // How far each object's widest access reaches past its start, for a run nothing above ends.
        let mut widths = BTreeMap::<ObjectId, i64>::new();
        for inst in &graph.insts {
            let crate::graph::InstPayload::Op(op) = &inst.payload else {
                continue;
            };
            let (address, accessed, space) = match op {
                SSAOp::Load { dst, addr, space } => (*addr, *dst, *space),
                SSAOp::Store { addr, val, space } => (*addr, *val, *space),
                _ => continue,
            };
            let key = MemoryObjectKey {
                value: address,
                space,
            };
            if let (Some(object), Some(value)) =
                (model.value_objects.get(&key), graph.value(accessed))
            {
                let width = widths.entry(*object).or_default();
                *width = (*width).max(i64::from(value.var.size));
            }
        }
        let mut spans = Vec::new();
        // A run opens at an object whose own address escapes: below it lies the argument area
        // the calls pass on, which is no C object (an interior address reaching down past its
        // object's base stays the labelled assumption).
        let mut run: Option<(i64, usize)> = None;
        for (start, objects) in frame.starts.range(..0) {
            let barrier = objects.iter().any(|object| barriers.contains(object));
            let escaped = objects.iter().all(|object| self.escaped.contains(object));
            let opens = objects.iter().any(|object| self.direct.contains(object));
            if run.is_none() && !opens {
                continue;
            }
            if barrier || !escaped {
                if let Some((first, _)) = run.take() {
                    spans.push((first, *start));
                }
                continue;
            }
            run = Some(run.map_or((*start, 1), |(first, count)| (first, count + 1)));
        }
        // A run nothing above ends stops where its last object's widest access does.
        if let Some((first, _)) = run {
            let last = frame.starts.range(first..0).next_back();
            let end = last
                .map(|(start, objects)| {
                    let width = objects.iter().filter_map(|object| widths.get(object)).max();
                    start.saturating_add(width.copied().unwrap_or(1))
                })
                .unwrap_or(0)
                .min(0);
            spans.push((first, end));
        }
        r2il::refusal_evidence!(
            "frame-reach",
            "{:#x}: escaped runs merged as {spans:?}; escaped starts {:?}",
            function.entry,
            self.escaped
                .iter()
                .filter_map(|object| frame.start_of(*object))
                .collect::<BTreeSet<_>>()
        );
        spans
    }
}

/// Nothing proves where the object an escaped address points into ends: `rows[4]` is four
/// objects to the partition and one to the callee that indexes it. So an escaped address reaches
/// every object of this frame around it, out to a slot the compiler owns, which no C object spans.
/// `O(objects)` per escaped object.
fn close_upward(
    escaped: &mut BTreeSet<ObjectId>,
    frame: &FrameIndex,
    barriers: &BTreeSet<ObjectId>,
) {
    let starts = escaped
        .iter()
        .filter_map(|object| frame.start_of(*object))
        .filter(|start| *start < 0)
        .collect::<BTreeSet<_>>();
    let mut reached = BTreeSet::new();
    let stops =
        |objects: &BTreeSet<ObjectId>| objects.iter().any(|object| barriers.contains(object));
    for start in starts {
        // An interior address indexes down as well as up: `&rows[1]` reaches `rows[0]`.
        let up = frame.starts.range(start..0);
        let down = frame.starts.range(..start).rev();
        for run in [up.collect::<Vec<_>>(), down.collect::<Vec<_>>()] {
            for (_, objects) in run {
                if stops(objects) {
                    break;
                }
                reached.extend(objects.iter().copied());
            }
        }
    }
    escaped.extend(reached);
}

/// The frame slots the compiler owns: a save of a register the convention preserves (its entry
/// value stored) and a decided stack protector's canary.
fn compiler_slots(
    function: &SSAFunction,
    graph: &SsaGraph,
    model: &ObjectModel,
    machine_context: Option<&SourceMachineContext>,
) -> BTreeSet<ObjectId> {
    let effect = machine_context.and_then(SourceMachineContext::call_effect);
    let canary = function
        .compiler_inserted()
        .iter()
        .filter_map(|op| graph.inst_for_op(op))
        .collect::<crate::dense::IdSet<_>>();
    let preserved =
        |storage: CanonicalStorageId| effect.is_some_and(|effect| effect.preserves(storage));
    let entry = |value: ValueId| {
        graph
            .value(value)
            .filter(|value| value.var.version == 0)
            .and_then(|value| value.canonical_storage)
    };
    // The low lane of an entry register the convention preserves: AArch64's `d8` of `z8`.
    let preserved_low_lane = |root: CanonicalStorageId, size: u32| {
        effect.is_some_and(|effect| {
            effect.preserved().iter().any(|lane| {
                lane.size == size
                    && machine_context.is_some_and(|context| context.is_low_lane_of(*lane, root))
            })
        })
    };
    // A register's entry value, or the low lane of one, stored whole.
    let saved = |value: ValueId| {
        graph
            .formal_projection_storage(value)
            .is_some_and(preserved)
            || entry(value).is_some_and(preserved)
            || graph
                .def_inst(value)
                .and_then(|inst| graph.inst(inst))
                .is_some_and(|inst| {
                    matches!(
                        inst.payload,
                        crate::graph::InstPayload::Op(SSAOp::Subpiece { offset: 0, .. })
                    ) && inst
                        .inputs
                        .first()
                        .copied()
                        .and_then(entry)
                        .is_some_and(|root| {
                            graph
                                .value(value)
                                .is_some_and(|lane| preserved_low_lane(root, lane.var.size))
                        })
                })
    };
    graph
        .insts
        .iter()
        .filter_map(|inst| match &inst.payload {
            crate::graph::InstPayload::Op(SSAOp::Store { space, .. }) => {
                let (address, value) = (*inst.inputs.first()?, *inst.inputs.get(1)?);
                (saved(value) || canary.contains(inst.id)).then_some(MemoryObjectKey {
                    value: address,
                    space: *space,
                })
            }
            _ => None,
        })
        .filter_map(|key| model.value_objects.get(&key).copied())
        .collect()
}

/// The frame objects by where each starts in the entry frame, built once; the unplaced ones apart.
struct FrameIndex {
    starts: BTreeMap<i64, BTreeSet<ObjectId>>,
    unplaced: BTreeSet<ObjectId>,
}

impl FrameIndex {
    fn of(model: &ObjectModel) -> Self {
        let mut index = Self {
            starts: BTreeMap::new(),
            unplaced: BTreeSet::new(),
        };
        let frame = model.objects.iter().filter(|(_, fact)| {
            matches!(
                fact.kind,
                ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
            )
        });
        for (id, _) in frame {
            let start = model.entry_stack_roots.get(id);
            match start.filter(|root| root.base == StackAddressBase::StackPointer) {
                Some(root) => index.starts.entry(root.offset).or_default().insert(*id),
                None => index.unplaced.insert(*id),
            };
        }
        index
    }

    /// The entry offset an object starts at, where the frame places it.
    fn start_of(&self, object: ObjectId) -> Option<i64> {
        self.starts
            .iter()
            .find_map(|(start, objects)| objects.contains(&object).then_some(*start))
    }

    fn len(&self) -> usize {
        self.starts.values().map(BTreeSet::len).sum::<usize>() + self.unplaced.len()
    }

    /// The object an entry-relative position lies in: the one starting nearest at or below it, in O(log n).
    fn containing(&self, offset: i64) -> Option<ObjectId> {
        let (_, ids) = self.starts.range(..=offset).next_back()?;
        ids.first().copied()
    }
}

/// Where a frame address points, entry-relative, when the prep facts place it.
fn entry_offset(facts: &DecompilePrepFacts, value: ValueId) -> Option<i64> {
    facts
        .stack_address_root_of(value)
        .or_else(|| facts.indexed_stack_address_root_of(value))
        .filter(|root| root.base == StackAddressBase::StackPointer)
        .map(|root| root.offset)
}

/// The frame objects whose addresses escape, and whether one escaped that
/// names none.
fn escaped_objects(
    facts: &DecompilePrepFacts,
    graph: &SsaGraph,
    model: &ObjectModel,
    frame: &FrameIndex,
) -> (BTreeSet<ObjectId>, bool) {
    let frame_address = |value: ValueId| {
        graph.value(value).is_some_and(|value| {
            facts.stack_address_root_of(value.id).is_some()
                || facts.indexed_stack_address_root_of(value.id).is_some()
        })
    };
    // Which objects each tainted value may point into: its own, or what flows into it. Each set
    // only grows, bounded by the objects, so a value is re-queued at most once per object.
    let mut origins = crate::dense::IdMap::<ValueId, BTreeSet<ObjectId>>::default();
    let mut tainted = crate::dense::IdSet::default();
    let mut pending = Vec::new();
    for value in graph.values.iter().map(|value| value.id) {
        if frame_address(value) && tainted.insert(value) {
            let own = escaping_object(facts, graph, frame, value)
                .into_iter()
                .collect();
            origins.insert(value, own);
            pending.push(value);
        }
    }
    let mut escaped = BTreeSet::new();
    let mut whole = false;
    let placed = |value: ValueId| {
        let key = MemoryObjectKey {
            value,
            space: SpaceId::Ram,
        };
        model.value_objects.contains_key(&key)
    };
    while let Some(value) = pending.pop() {
        let from = origins.get(value).cloned().unwrap_or_default();
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                whole = true;
                continue;
            };
            match carries(inst, site.input_idx, placed(value)) {
                Carry::Escapes => match escaping_object(facts, graph, frame, value) {
                    Some(object) => {
                        escaped.insert(object);
                    }
                    // A merge of a frame address with something else: the objects it may name.
                    None if !from.is_empty() => escaped.extend(from.iter().copied()),
                    None => {
                        r2il::refusal_evidence!(
                            "frame-reach",
                            "{value:?} escapes through {:?} at no frame object",
                            inst.payload
                        );
                        whole = true;
                    }
                },
                Carry::Propagates => {
                    if let Some(out) = inst.output {
                        let known = origins.get_or_insert_with(out, BTreeSet::new);
                        let before = known.len();
                        known.extend(from.iter().copied());
                        if tainted.insert(out) || known.len() != before {
                            pending.push(out);
                        }
                    }
                }
                Carry::Stops => {}
                Carry::Everything => {
                    r2il::refusal_evidence!(
                        "frame-reach",
                        "{value:?} is taken as code or by an unmodelled operation: {:?}",
                        inst.payload
                    );
                    whole = true;
                }
            }
        }
    }
    if whole {
        r2il::refusal_evidence!(
            "frame-reach",
            "a frame address escapes that names no frame object, so the whole frame is reachable"
        );
    }
    (escaped, whole)
}

enum Carry {
    /// The value leaves the function's sight with the address it carries.
    Escapes,
    /// Control or code goes where the address says, so no object of the frame is private.
    Everything,
    /// The output is computed from the address and may be one.
    Propagates,
    /// The address is used as one, or reduced to something that is not one.
    Stops,
}

/// The frame object an escaping frame address points into, where the prep
/// facts place it in one.
fn escaping_object(
    facts: &DecompilePrepFacts,
    graph: &SsaGraph,
    frame: &FrameIndex,
    value: ValueId,
) -> Option<ObjectId> {
    let offset = entry_offset(facts, graph.value(value)?.id)?;
    frame.containing(offset)
}

/// What one use of a frame address does with it; `placed` is whether the model puts the address in an object.
///
/// A return is no escape: under the UB-free premise the frame ends with the call (doc/adr-frame-model.md).
fn carries(inst: &crate::graph::GraphInst, input: usize, placed: bool) -> Carry {
    let op = match &inst.payload {
        crate::graph::InstPayload::Phi { .. } => return Carry::Propagates,
        crate::graph::InstPayload::Op(op) => op,
    };
    let access = || if placed { Carry::Stops } else { Carry::Escapes };
    match op {
        SSAOp::CallUse { .. } | SSAOp::CallOther { .. } => Carry::Escapes,
        SSAOp::Call { .. }
        | SSAOp::CallInd { .. }
        | SSAOp::Branch { .. }
        | SSAOp::BranchInd { .. }
        | SSAOp::Switch { .. } => Carry::Everything,
        // A conditional branch reads its condition; an address there is a truth value.
        SSAOp::CBranch { .. } | SSAOp::Return { .. } => Carry::Stops,
        // Input 0 is the address; anything else stored is the value.
        SSAOp::Store { .. }
        | SSAOp::StoreConditional { .. }
        | SSAOp::StoreGuarded { .. }
        | SSAOp::AtomicCAS(_) => {
            if input == 0 {
                access()
            } else {
                Carry::Escapes
            }
        }
        SSAOp::Load { .. } | SSAOp::LoadLinked { .. } | SSAOp::LoadGuarded { .. } => access(),
        SSAOp::BlockTransfer(_) => access(),
        SSAOp::IntEqual { .. }
        | SSAOp::IntNotEqual { .. }
        | SSAOp::IntLess { .. }
        | SSAOp::IntSLess { .. }
        | SSAOp::IntLessEqual { .. }
        | SSAOp::IntSLessEqual { .. }
        | SSAOp::IntCarry { .. }
        | SSAOp::IntSCarry { .. }
        | SSAOp::IntSBorrow { .. }
        | SSAOp::PopCount { .. }
        | SSAOp::Lzcount { .. } => Carry::Stops,
        _ if inst.output.is_some() => Carry::Propagates,
        // An operation with no output that is none of the above does something unmodelled with the address.
        _ => Carry::Everything,
    }
}

/// The frame objects each call reaches through its argument area.
fn call_reaches(
    function: &SSAFunction,
    graph: &SsaGraph,
    facts: &DecompilePrepFacts,
    frame: &FrameIndex,
    machine_context: Option<&SourceMachineContext>,
) -> crate::dense::IdMap<InstId, CallFrameReach> {
    let mut out = crate::dense::IdMap::default();
    let Some(machine_context) = machine_context else {
        return out;
    };
    let Some(stack_pointer) = machine_context.stack_pointer_carrier() else {
        return out;
    };
    // The callee's own space below its first argument, which it may write.
    let reserved = machine_context
        .convention_slots()
        .and_then(r2source::SourceConventionSlots::stack_arguments)
        .map_or(0, |placement| placement.first_offset().max(0));
    let states = reaching_storage_states_before(function, graph, stack_pointer);
    for block in function.named_blocks() {
        for (op_id, op) in block.sited() {
            let instruction = match op {
                SSAOp::Call { instruction, .. } | SSAOp::CallInd { instruction, .. } => {
                    *instruction
                }
                _ => continue,
            };
            let Some(call) = graph.inst_for_op(op_id) else {
                continue;
            };
            let sp = match states.get(call) {
                Some(ReachingStorageState::Value(value)) => graph
                    .value(*value)
                    .and_then(|value| entry_offset(facts, value.id)),
                _ => None,
            };
            let interface = instruction
                .and_then(|instruction| machine_context.raw_call_site_at(instruction))
                .and_then(|identity| machine_context.call_site_interface(identity))
                .filter(|interface| interface.is_complete() && !interface.is_variadic());
            let (Some(sp), Some(interface)) = (sp, interface) else {
                out.insert(call, CallFrameReach::Whole);
                continue;
            };
            let slots =
                interface
                    .arguments()
                    .iter()
                    .filter_map(|argument| match argument.location() {
                        r2source::SourceParameterLocation::Stack {
                            offset, size_bytes, ..
                        } => {
                            let start = sp.saturating_add(offset);
                            Some((start, start.saturating_add(i64::from(size_bytes))))
                        }
                        r2source::SourceParameterLocation::Register(_) => None,
                    });
            let area = std::iter::once((sp, sp.saturating_add(reserved)))
                .chain(slots)
                .collect::<Vec<_>>();
            out.insert(call, CallFrameReach::Objects(objects_in(frame, &area)));
        }
    }
    out
}

/// The frame objects any byte of these entry-relative ranges lies in; an
/// object nothing places may be any of them.
fn objects_in(frame: &FrameIndex, ranges: &[(i64, i64)]) -> BTreeSet<ObjectId> {
    let mut found = frame.unplaced.clone();
    for (low, high) in ranges.iter().filter(|(low, high)| low < high) {
        found.extend(frame.containing(*low));
        found.extend(
            frame
                .starts
                .range(*low..*high)
                .flat_map(|(_, ids)| ids.iter().copied()),
        );
    }
    found
}
