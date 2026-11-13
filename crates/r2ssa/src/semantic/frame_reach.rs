//! Which of the frame's objects code outside this function can touch (doc/adr-frame-model.md).
//!
//! Under the UB-free premise a callee reaches the frame only through an address this function
//! hands out, and through the argument area of the call. The one escape walk (`walk`, D290)
//! runs at build, before promotion and the canary decision, and states the escaped entry
//! offsets; the seal maps them to objects (`FrameIndex::containing`) and walks nothing.
//! Cost: O(points x log objects) to map, O(calls x objects) for the argument areas.

use super::*;

mod walk;

use walk::Origin;
pub(crate) use walk::{Access, Walked, walk};
pub use walk::{FramePoint, FramePoints};

/// What one call reaches of the frame besides what has escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFrameReach {
    Objects(BTreeSet<ObjectId>),
    /// Nothing bounds it: the interface is unknown, incomplete or variadic,
    /// or the stack pointer at the call is not placed.
    Whole,
}

/// The frame objects outside code can touch; the default is the whole frame (default deny).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameReach {
    escaped: BTreeSet<ObjectId>,
    /// The objects whose own address escapes, before the closure around them.
    direct: BTreeSet<ObjectId>,
    /// A frame address escaped that names no object, so every frame object is reachable.
    whole: bool,
    /// The entry offsets at or above the entry stack pointer that escaped addresses point at.
    incoming: BTreeSet<i64>,
    by_call: crate::dense::IdMap<InstId, CallFrameReach>,
}

impl Default for FrameReach {
    fn default() -> Self {
        Self {
            escaped: BTreeSet::new(),
            direct: BTreeSet::new(),
            whole: true,
            incoming: BTreeSet::new(),
            by_call: crate::dense::IdMap::default(),
        }
    }
}

impl FrameReach {
    /// Whether code outside this function can reach `object` through an
    /// address: any non-frame object can, a frame object only once escaped.
    pub fn escaped(&self, object: ObjectId) -> bool {
        self.whole || self.escaped.contains(&object)
    }

    /// Whether the object's own address escapes, before the closure reaches any neighbour.
    pub fn escapes_directly(&self, object: ObjectId) -> bool {
        self.whole || self.direct.contains(&object)
    }

    /// Whether an escaping frame address named no object, so every frame
    /// object is reachable.
    pub const fn whole(&self) -> bool {
        self.whole
    }

    /// The entry offsets at or above the entry stack pointer (the homes and the argument area)
    /// that escaped addresses point at; none where one may point there at no offset known.
    pub const fn escaped_incoming(&self) -> Option<&BTreeSet<i64>> {
        match self.whole {
            true => None,
            false => Some(&self.incoming),
        }
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

    /// The build's points as objects: no walk, and so no points, is the whole frame.
    pub(crate) fn of(
        function: &SSAFunction,
        prep: Option<&crate::DecompilePrepFacts>,
        graph: &SsaGraph,
        model: &ObjectModel,
        machine_context: Option<&SourceMachineContext>,
    ) -> Self {
        let frame = FrameIndex::of(model);
        let areas = match (prep, machine_context) {
            (Some(facts), Some(context)) => call_areas(function, graph, facts, context),
            _ => crate::dense::IdMap::default(),
        };
        let by_call = (areas.iter())
            .map(|(call, area)| {
                let reach = area.as_ref().map_or(CallFrameReach::Whole, |area| {
                    CallFrameReach::Objects(objects_in(&frame, area))
                });
                (call, reach)
            })
            .collect::<crate::dense::IdMap<_, _>>();
        let Some(points) = function.frame_points() else {
            return Self {
                by_call,
                ..Self::default()
            };
        };
        let (leaving, mut whole) = leaving(points, graph, model);
        let mut direct = BTreeSet::new();
        for point in &leaving {
            match frame.containing(point.at) {
                Some(object) => drop(direct.insert(object)),
                None => {
                    r2il::refusal_evidence!(
                        "frame-reach",
                        "{:#x}: an address escapes at {} where no frame object is",
                        function.entry,
                        point.at
                    );
                    whole = true;
                }
            }
        }
        let incoming = (leaving.iter().map(|point| point.at))
            .filter(|at| *at >= 0)
            .collect();
        let mut escaped = direct.clone();
        let barriers = compiler_slots(function, graph, model, machine_context);
        close_upward(&mut escaped, &frame, &barriers);
        r2il::refusal_evidence!(
            "frame-reach",
            "{:#x}: {} of {} frame objects escape (whole frame: {whole}), escaped starts {:?}, {} calls bounded",
            function.entry,
            escaped.len(),
            frame.len(),
            escaped
                .iter()
                .filter_map(|object| frame.start_of(*object))
                .collect::<BTreeSet<_>>(),
            by_call
                .values()
                .filter(|reach| matches!(reach, CallFrameReach::Objects(_)))
                .count()
        );
        Self {
            escaped,
            direct,
            whole,
            incoming,
            by_call,
        }
    }
}

/// The points that leave, and whether one leaves no offset places. An opaque access the model
/// places in no frame object, or in the unknown object, hands on what it points at (S27). An
/// access preparation removed reads nothing. O(opaque accesses x log objects).
fn leaving(
    points: &FramePoints,
    graph: &SsaGraph,
    model: &ObjectModel,
) -> (BTreeSet<FramePoint>, bool) {
    let mut leaving = points.escaped.clone();
    let mut whole = points.whole;
    let unknown = model.escaped_unknown_object(SpaceId::Ram);
    let placed = |value: ValueId, space: SpaceId| {
        let key = MemoryObjectKey { value, space };
        (model.value_objects.get(&key)).is_some_and(|object| Some(*object) != unknown)
    };
    for access in &points.opaque {
        let Some(op) = graph.inst_for_op(access.op).and_then(|inst| graph.op(inst)) else {
            continue;
        };
        let addresses = access_addresses(op);
        if !addresses.is_empty()
            && addresses
                .iter()
                .all(|(value, space)| placed(*value, *space))
        {
            continue;
        }
        match &access.origin {
            Origin::Points(points) => leaving.extend(points.iter().copied()),
            Origin::Unplaced => {
                r2il::refusal_evidence!(
                    "frame-reach",
                    "{op:?} accesses a frame address no offset or object places"
                );
                whole = true;
            }
        }
    }
    (leaving, whole)
}

/// The addresses a memory access reads, with their spaces.
fn access_addresses(op: &SSAOp<ValueId>) -> Vec<(ValueId, SpaceId)> {
    match op {
        SSAOp::Load { addr, space, .. }
        | SSAOp::Store { addr, space, .. }
        | SSAOp::LoadLinked { addr, space, .. }
        | SSAOp::StoreConditional { addr, space, .. }
        | SSAOp::LoadGuarded { addr, space, .. }
        | SSAOp::StoreGuarded { addr, space, .. } => vec![(*addr, *space)],
        SSAOp::Atomic(access) => vec![(access.addr, access.space)],
        SSAOp::BlockTransfer(transfer) => vec![
            (transfer.destination, transfer.space),
            (transfer.source, transfer.space),
        ],
        _ => Vec::new(),
    }
}

/// Each run of the frame an escaped address may reach, from the lowest place whose own address
/// escapes up to a compiler slot or the frame's top, as one span: C's pointer arithmetic across
/// it is defined (doc/adr-frame-model.md, extent rule and "Escape spans"). Read by the one build
/// from the walk's offsets, before any object exists. O(points + accesses x log places).
pub(crate) fn escape_spans(
    function: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::DecompilePrepFacts,
    declared: &DeclaredStackSlots,
    machine_context: Option<&SourceMachineContext>,
) -> Vec<(i64, i64)> {
    let Some(points) = function.frame_points() else {
        return Vec::new();
    };
    // Without the convention's saves nothing bounds a run below the return address.
    if points.whole
        || machine_context
            .and_then(SourceMachineContext::call_effect)
            .is_none()
    {
        return Vec::new();
    }
    let offset = |value: ValueId| {
        (facts.stack_address_root_of(value))
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    };
    // Where places start and how wide each is accessed: the accesses and the declarations.
    let mut widths = BTreeMap::<i64, i64>::new();
    for op in graph.insts.iter().filter_map(|inst| match &inst.payload {
        crate::graph::InstPayload::Op(op) => Some(op),
        crate::graph::InstPayload::Phi { .. } => None,
    }) {
        let (address, accessed) = match op {
            SSAOp::Load { dst, addr, .. } => (*addr, *dst),
            SSAOp::Store { addr, val, .. } => (*addr, *val),
            _ => continue,
        };
        if let (Some(at), Some(value)) = (offset(address), graph.value(accessed)) {
            let width = widths.entry(at).or_default();
            *width = (*width).max(i64::from(value.var.size));
        }
    }
    for ((base, at), slot) in &declared.by_key {
        if *base == StackAddressBase::StackPointer {
            let width = widths.entry(*at).or_default();
            *width = (*width).max(i64::from(slot.size_bytes()));
        }
    }
    // A canary inside a declared aggregate is that aggregate's interior, not a slot (S27).
    let interior = |at: i64| {
        let root = StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: at,
        };
        declared.containing(root).is_some()
    };
    let barriers = (compiler_slot_stores(function, graph, machine_context, true).into_iter())
        .filter_map(|(address, canary)| {
            let at = offset(address)?;
            (!canary || !interior(at)).then_some(at)
        })
        .collect::<BTreeSet<_>>();
    // An opaque access no stack root places is in the unknown object: what it points at leaves
    // (S27), read here from the prep roots since no object exists yet.
    let unplaced_accesses = (points.opaque.iter())
        .filter(|access| {
            let op = graph.inst_for_op(access.op).and_then(|inst| graph.op(inst));
            op.is_some_and(|op| {
                (access_addresses(op).iter())
                    .any(|(value, _)| entry_offset(facts, *value).is_none())
            })
        })
        .flat_map(|access| match &access.origin {
            Origin::Points(points) => points.as_slice(),
            Origin::Unplaced => &[],
        });
    let opens = (points.escaped.iter())
        .chain(unplaced_accesses)
        .filter(|point| point.at < 0)
        .map(|point| {
            // An interior address opens the run at the place it lies inside.
            let inside = (widths.range(..=point.at).next_back())
                .filter(|(start, width)| point.at < start.saturating_add(**width));
            inside.map_or(point.at, |(start, _)| *start)
        })
        .collect::<BTreeSet<_>>();
    let mut spans = Vec::<(i64, i64)>::new();
    for first in opens {
        let covered = spans.last().is_some_and(|(_, end)| first < *end);
        if covered || barriers.contains(&first) {
            continue;
        }
        let end = match barriers.range(first + 1..0).next() {
            Some(barrier) => *barrier,
            // A run nothing above ends stops where its last place's widest access does.
            None => (widths.range(first..0).next_back())
                .map_or(0, |(start, width)| start.saturating_add((*width).max(1)))
                .min(0),
        };
        spans.push((first, end));
    }
    r2il::refusal_evidence!(
        "frame-reach",
        "{:#x}: escaped runs merged as {spans:?}; barriers at {barriers:?}",
        function.entry
    );
    spans
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
/// value stored) and a decided stack protector's canary not inside a wider object.
fn compiler_slots(
    function: &SSAFunction,
    graph: &SsaGraph,
    model: &ObjectModel,
    machine_context: Option<&SourceMachineContext>,
) -> BTreeSet<ObjectId> {
    (compiler_slot_stores(function, graph, machine_context, false).into_iter())
        .filter(|(address, canary)| !canary || model.interior_offset(*address).is_none())
        .filter_map(|(address, _)| {
            let key = MemoryObjectKey {
                value: address,
                space: SpaceId::Ram,
            };
            model.value_objects.get(&key).copied()
        })
        .collect()
}

/// The addresses of stores that fill a compiler slot, and whether each is the canary's: a save
/// of a preserved register, the canary, and with `entries` any non-argument register's entry
/// value (the return address, the frame pointer).
fn compiler_slot_stores(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
    entries: bool,
) -> Vec<(ValueId, bool)> {
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
                    ) && graph
                        .inputs(inst.id)
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
    // An entry value of a register no argument arrives in, stored whole, is the compiler's: a
    // save, the return address, the frame pointer. An argument's may be a local's initial value.
    let arguments = machine_context
        .and_then(SourceMachineContext::convention_slots)
        .map(|slots| {
            (slots.argument_slots().iter())
                .chain(slots.float_argument_slots())
                .copied()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let argument = |storage: CanonicalStorageId| {
        arguments.iter().any(|slot| {
            slot.space == storage.space
                && slot.offset <= storage.offset
                && storage.offset < slot.offset + u64::from(slot.size)
        })
    };
    let non_argument_entry = |mut value: ValueId| {
        // Through copies and low lanes, as a save of `x29` reads it.
        for _ in 0..graph.values.len() {
            let definition = graph.def_inst(value).and_then(|inst| graph.inst(inst));
            match definition.map(|inst| (&inst.payload, graph.inputs(inst.id).first())) {
                Some((
                    crate::graph::InstPayload::Op(
                        SSAOp::Copy { .. } | SSAOp::Subpiece { offset: 0, .. },
                    ),
                    Some(source),
                )) => value = *source,
                _ => break,
            }
        }
        graph
            .value(value)
            .filter(|value| value.var.version == 0)
            .and_then(|value| value.canonical_storage)
            .or_else(|| graph.formal_projection_storage(value))
            .is_some_and(|storage| {
                storage.space == CanonicalStorageSpace::Register && !argument(storage)
            })
    };
    (graph.insts.iter())
        .filter_map(|inst| match &inst.payload {
            crate::graph::InstPayload::Op(SSAOp::Store { .. }) => {
                let (address, value) = (
                    *graph.inputs(inst.id).first()?,
                    *graph.inputs(inst.id).get(1)?,
                );
                let own = canary.contains(inst.id);
                let filled = saved(value) || own || (entries && non_argument_entry(value));
                filled.then_some((address, own && !saved(value)))
            }
            _ => None,
        })
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

/// Each call's argument area at the entry offset of its stack pointer, or `None` where nothing
/// bounds it. One `ReachingStorage` walk, `O(ops)`.
fn call_areas(
    function: &SSAFunction,
    graph: &SsaGraph,
    facts: &DecompilePrepFacts,
    machine_context: &SourceMachineContext,
) -> crate::dense::IdMap<InstId, Option<Vec<(i64, i64)>>> {
    let mut out = crate::dense::IdMap::default();
    let Some(stack_pointer) = machine_context.stack_pointer_carrier() else {
        return out;
    };
    let mut states = ReachingStorage::new(function, graph, stack_pointer);
    for block in &graph.blocks {
        for &call in graph.op_insts(block.id) {
            let Some(op) = graph.op(call) else {
                continue;
            };
            let Some(transfer) = op.call() else {
                continue;
            };
            let instruction = transfer.instruction;
            let sp = match states.before(call) {
                Some(ReachingStorageState::Value(value)) => graph
                    .value(value)
                    .and_then(|value| entry_offset(facts, value.id)),
                _ => None,
            };
            let area = (machine_context.call_reads(instruction)).and_then(|reads| reads.stack);
            let area = sp.zip(area).map(|(sp, area)| {
                (area.iter())
                    .map(|(low, high)| (sp.saturating_add(*low), sp.saturating_add(*high)))
                    .collect::<Vec<_>>()
            });
            out.insert(call, area);
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
