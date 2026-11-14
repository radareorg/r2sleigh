//! Which frame objects outside code can touch: the walk's points mapped to objects at the seal
//! (doc/adr-frame-model.md, "Escape spans"). O(points x log objects), O(calls x objects).

use super::*;

mod walk;

use walk::Origin;
pub(crate) use walk::{Access, Places, Walked, walk};
pub use walk::{DynamicFrame, FramePoint, FramePoints};

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
        graph: &SsaGraph,
        model: &ObjectModel,
        machine_context: Option<&SourceMachineContext>,
    ) -> Self {
        let frame = FrameIndex::of(model);
        let by_call = call_reaches(function, graph, &frame, machine_context);
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
        let barriers = compiler_slots(model);
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

/// The points that leave, and whether one leaves unplaced; an opaque access outside every frame
/// object hands on what it points at (S27). O(opaque accesses x log objects).
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
        // Preparation mints no memory operation, so an access with no operation was deleted.
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

/// Each frame run an escaped address may reach, lowest escaping place to a compiler slot or the
/// top (doc/adr-frame-model.md, "Escape spans"). O(points + accesses x log places).
pub(crate) fn escape_spans(
    (function, graph, facts): (&SSAFunction, &SsaGraph, &crate::DecompilePrepFacts),
    declared: &DeclaredStackSlots,
    slots: &[ValueId],
    machine_context: Option<&SourceMachineContext>,
) -> Vec<(i64, i64)> {
    let Some(points) = function.frame_points() else {
        return Vec::new();
    };
    // Without the convention's saves nothing bounds a run below the return address.
    if points.whole
        || machine_context
            .and_then(SourceMachineContext::calls)
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
    let barriers = slots
        .iter()
        .filter_map(|address| offset(*address))
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

/// The stores into slots the compiler owns, a canary inside a declared slot or a write span left
/// out: the one set the escape runs and the seal read (D290). `O(stores x spans)`.
pub(crate) fn compiler_slot_addresses(
    (function, graph, facts): (&SSAFunction, &SsaGraph, &crate::DecompilePrepFacts),
    declared: &DeclaredStackSlots,
    spans: &BTreeMap<StackAddressRoot, i64>,
    machine_context: Option<&SourceMachineContext>,
) -> Vec<ValueId> {
    let inside = |root: StackAddressRoot| {
        declared.containing(root).is_some()
            || (spans.range(..root))
                .any(|(start, end)| start.base == root.base && root.offset < *end)
    };
    (compiler_slot_stores(function, graph, machine_context).into_iter())
        .filter(|(address, canary)| {
            !canary || !(facts.stack_address_root_of(*address).copied()).is_some_and(inside)
        })
        .map(|(address, _)| address)
        .collect()
}

/// Nothing proves where the object an escaped address points into ends: `rows[4]` is four
/// objects to the partition and one to the callee that indexes it. So an escaped address reaches
/// every object of this frame around it, out to a slot the compiler owns, which no C object spans.
/// One pass over the frame's starts below the entry pointer: `O(objects + escaped log escaped)`.
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
    let below = frame.starts.range(..0).collect::<Vec<_>>();
    let barrier = (below.iter())
        .map(|(_, objects)| objects.iter().any(|object| barriers.contains(object)))
        .collect::<Vec<_>>();
    // The first barrier at or above each start, from one backward pass.
    let mut next_barrier = vec![below.len(); below.len() + 1];
    for at in (0..below.len()).rev() {
        next_barrier[at] = if barrier[at] {
            at
        } else {
            next_barrier[at + 1]
        };
    }
    // Each start reaches down to the barrier below it and up to the one at or above it (the one
    // below where it is a barrier itself): an interior address indexes both ways.
    let mut runs = Vec::with_capacity(starts.len());
    let mut last_barrier = None;
    let mut next = starts.iter().peekable();
    for (at, (start, _)) in below.iter().enumerate() {
        if next.next_if(|wanted| *wanted == *start).is_some() {
            let low = last_barrier.map_or(0, |barrier: usize| barrier + 1);
            let high = next_barrier[at];
            runs.push((low, high));
        }
        if barrier[at] {
            last_barrier = Some(at);
        }
    }
    // Runs only grow rightwards in `low`; joined, each object is added once.
    let mut reached = BTreeSet::new();
    let mut covered = 0;
    for (low, high) in runs {
        for (_, objects) in &below[low.max(covered)..high.max(covered)] {
            reached.extend(objects.iter().copied());
        }
        covered = covered.max(high);
    }
    escaped.extend(reached);
}

/// The frame slots the compiler owns: a save of a register the convention preserves (its entry
/// value stored) and a decided stack protector's canary not inside a wider object.
fn compiler_slots(model: &ObjectModel) -> BTreeSet<ObjectId> {
    (model.compiler_slots.iter())
        .filter_map(|address| {
            let key = MemoryObjectKey {
                value: *address,
                space: SpaceId::Ram,
            };
            model.value_objects.get(&key).copied()
        })
        .collect()
}

/// Stores that fill a compiler slot (a preserved save, the return address carrier's entry value,
/// the canary), each marked whether it is the canary's.
fn compiler_slot_stores(
    function: &SSAFunction,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
) -> Vec<(ValueId, bool)> {
    let effect = machine_context.and_then(SourceMachineContext::calls);
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
            effect.preserved_registers().iter().any(|lane| {
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
    // The return address carrier's entry value (AArch64 `x30`), through copies and low lanes. An
    // entry value of another register is no proof: a count, a static chain or x8 may be a local's.
    let return_address = machine_context.and_then(SourceMachineContext::return_address_carrier);
    let return_address_entry = |mut value: ValueId| {
        let Some(carrier) =
            return_address.filter(|carrier| carrier.space == CanonicalStorageSpace::Register)
        else {
            return false;
        };
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
        (entry(value).or_else(|| graph.formal_projection_storage(value))) == Some(carrier)
    };
    (graph.insts.iter())
        .filter_map(|inst| match &inst.payload {
            crate::graph::InstPayload::Op(SSAOp::Store { .. }) => {
                let (address, value) = (
                    *graph.inputs(inst.id).first()?,
                    *graph.inputs(inst.id).get(1)?,
                );
                let own = canary.contains(inst.id);
                let filled = saved(value) || own || return_address_entry(value);
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

/// What each call reaches of the frame: its `CallReads::stack` from the base the walk placed, as
/// objects; the whole frame where either is missing. `O(insts + calls x log objects)`.
fn call_reaches(
    function: &SSAFunction,
    graph: &SsaGraph,
    frame: &FrameIndex,
    machine_context: Option<&SourceMachineContext>,
) -> crate::dense::IdMap<InstId, CallFrameReach> {
    let bases = function
        .frame_points()
        .map_or(&[][..], |points| &points.call_bases[..]);
    let mut by_call = crate::dense::IdMap::default();
    for inst in &graph.insts {
        if graph.op(inst.id).is_some_and(|op| op.call().is_some()) {
            by_call.insert(inst.id, CallFrameReach::Whole);
        }
    }
    for call_base in bases {
        let Some((call, base)) = graph.inst_for_op(call_base.op).zip(call_base.base) else {
            continue;
        };
        let instruction = graph
            .op(call)
            .and_then(|op| op.call())
            .map(|call| call.instruction);
        // What the call may read or write; nothing bounds it where either is unbounded (D377).
        let area = machine_context
            .zip(instruction)
            .and_then(|(context, instruction)| {
                let reads = context.call_reads(instruction)?;
                Some([reads.stack?, reads.writes?].concat())
            });
        if let Some(area) = area {
            let area = (area.iter())
                .map(|(low, high)| (base.saturating_add(*low), base.saturating_add(*high)))
                .collect::<Vec<_>>();
            by_call.insert(call, CallFrameReach::Objects(objects_in(frame, &area)));
        }
    }
    by_call
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
