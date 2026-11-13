//! The frame's one escape walk, default deny, before slot promotion (doc/adr-frame-model.md,
//! "Escape spans"). A value's set and a place's held set only grow: `O(rounds x 65 x (V + E))`.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::dense::{DenseId, IdMap};
use crate::frame_address::Definitions;
use crate::function::SSAFunction;
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::VarId;

/// How far an address may move from where it points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Extent {
    /// Only upward: a non-negative index, or a callee proven to reach only upward.
    Upward,
    /// Either way.
    Either,
    /// Computed from the address by more than offset arithmetic (a mask, a mix, a merge that moves
    /// again): the seal keeps it in its object; promotion and the canary place it nowhere.
    Derived,
}

/// An entry offset an address points at, and which way it may move from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FramePoint {
    pub at: i64,
    pub extent: Extent,
}

/// Where an access the walk does not take as one exact load or store points.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Origin {
    Points(Vec<FramePoint>),
    /// A frame address no offset places.
    Unplaced,
}

/// An access through a frame address no exact load or store of one place states: it stays in
/// memory, and the seal asks the object model whether it lands in a frame object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpaqueAccess {
    pub(crate) op: OpId,
    pub(crate) origin: Origin,
}

/// What the frame's addresses do, by entry offset (D290). `None` on a function means `whole`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FramePoints {
    /// An address no offset places leaves the function.
    pub(crate) whole: bool,
    /// The addresses that leave the function.
    pub(crate) escaped: BTreeSet<FramePoint>,
    /// Accesses no exact load or store states, in operation order.
    pub(crate) opaque: Vec<OpaqueAccess>,
    /// Places holding an address a call reads as a stack argument: the store stays.
    pub(crate) handed: BTreeSet<i64>,
    /// Some place holding an address lies where a call's argument area could reach (D226).
    pub(crate) by_area: bool,
}

impl FramePoints {
    /// Every place may be reached: an escape or an access no offset places.
    pub(crate) fn whole_frame() -> Self {
        Self {
            whole: true,
            ..Self::default()
        }
    }

    /// Whether an address no offset places escapes or is accessed.
    pub(crate) fn unplaced(&self) -> bool {
        self.whole
            || (self.opaque.iter()).any(|access| matches!(access.origin, Origin::Unplaced))
            || self.reaching().any(|point| point.extent == Extent::Derived)
    }

    /// The points that escape or are accessed opaquely.
    fn reaching(&self) -> impl Iterator<Item = FramePoint> + '_ {
        let opaque = self.opaque.iter().flat_map(|access| match &access.origin {
            Origin::Points(points) => points.as_slice(),
            Origin::Unplaced => &[],
        });
        self.escaped.iter().chain(opaque).copied()
    }

    /// Whether an escaped or opaque address may reach `place`, crossing no save of `saves`.
    /// `O(points x log saves)`.
    pub(crate) fn reaches(&self, place: i64, saves: &BTreeSet<i64>) -> bool {
        let separated = |from: i64| {
            let (low, high) = (from.min(place), from.max(place));
            high > low.saturating_add(1) && saves.range(low + 1..high).next().is_some()
        };
        self.unplaced()
            || self.reaching().any(|point| {
                (point.extent == Extent::Either || point.at <= place) && !separated(point.at)
            })
    }

    /// Whether an escaped or opaque address points into `[lo, hi)`: a compiler slot there is no
    /// object an index below it spans, so only points inside it name it. `O(points)`.
    pub(crate) fn names(&self, lo: i64, hi: i64) -> bool {
        self.unplaced() || self.reaching().any(|point| lo <= point.at && point.at < hi)
    }

    pub(crate) const fn handed(&self) -> &BTreeSet<i64> {
        &self.handed
    }

    pub(crate) const fn by_area(&self) -> bool {
        self.by_area
    }
}

/// One exact access at a place, for promotion's rewrite.
pub(crate) struct Access {
    pub(crate) op: OpId,
    pub(crate) block: u64,
    pub(crate) index: usize,
    pub(crate) width: u32,
    pub(crate) store: bool,
}

pub(crate) type Accesses = BTreeMap<i64, Vec<Access>>;

/// Where a value derived from the entry stack pointer points, inside the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Point {
    Exact(i64),
    /// This offset plus an index: upward only where the index is non-negative.
    Indexed {
        from: i64,
        up: bool,
    },
    /// Computed from the address at this offset by more than offset arithmetic.
    Derived(i64),
}

impl Point {
    const fn frame_point(self) -> FramePoint {
        match self {
            Self::Exact(at)
            | Self::Indexed {
                from: at,
                up: false,
            } => FramePoint {
                at,
                extent: Extent::Either,
            },
            Self::Indexed { from, up: true } => FramePoint {
                at: from,
                extent: Extent::Upward,
            },
            Self::Derived(at) => FramePoint {
                at,
                extent: Extent::Derived,
            },
        }
    }
}

/// A value's points, or `Top` for a frame address no offset places.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Points(BTreeSet<Point>),
    Top,
}

/// More distinct points than this on one value refuse as `Top`.
const POINTS: usize = 64;

impl Value {
    fn one(point: Point) -> Self {
        Self::Points(BTreeSet::from([point]))
    }

    fn exact(&self) -> Option<i64> {
        match self {
            Self::Points(points) if points.len() == 1 => match points.first() {
                Some(Point::Exact(at)) => Some(*at),
                _ => None,
            },
            _ => None,
        }
    }

    /// The same places, computed from by more than offset arithmetic.
    fn degraded(&self) -> Self {
        match self {
            Self::Points(points) => Self::Points(
                (points.iter())
                    .map(|point| Point::Derived(point.frame_point().at))
                    .collect(),
            ),
            Self::Top => Self::Top,
        }
    }

    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Points(a), Self::Points(b)) => {
                let joined = a.union(b).copied().collect::<BTreeSet<_>>();
                if joined.len() > POINTS {
                    r2il::refusal_evidence!(
                        "frame-reach",
                        "a value may point at {} places, past {POINTS}: no offset places it",
                        joined.len()
                    );
                    Self::Top
                } else {
                    Self::Points(joined)
                }
            }
            _ => Self::Top,
        }
    }
}

/// The walk's answer: the points, and each exact access by place for promotion's rewrite.
pub(crate) struct Walked {
    pub(crate) points: FramePoints,
    pub(crate) accesses: Accesses,
    /// The places an address is stored into, where the round let a place carry one.
    carriers: BTreeSet<i64>,
}

/// Walk `func`'s frame addresses once. `promotable` decides, from one round's points and
/// accesses, which places promotion takes; a place it refuses carries no address in the next
/// round. The set only shrinks, so at most one round per place. Returns the last round with
/// the places it promotes.
pub(crate) fn walk(
    func: &SSAFunction,
    defs: &Definitions,
    machine: &SourceMachineContext,
    calls_refund_stack: bool,
    mut promotable: impl FnMut(&Walked) -> BTreeMap<i64, u32>,
) -> (Walked, BTreeMap<i64, u32>) {
    let refused = |points: FramePoints| {
        let walked = Walked {
            points,
            accesses: Accesses::new(),
            carriers: BTreeSet::new(),
        };
        (walked, BTreeMap::new())
    };
    let Some(stack_pointer) = machine.stack_pointer_carrier() else {
        return refused(FramePoints::whole_frame());
    };
    let entry_sp = (0..func.values().len())
        .map(VarId::from_index)
        .find(|id| func.var(*id).version == 0 && func.storage_of(*id) == Some(stack_pointer));
    // No entry stack pointer value: no frame address exists.
    let Some(entry_sp) = entry_sp else {
        return refused(FramePoints::default());
    };
    if defs.exhausted().is_some() {
        return refused(FramePoints::whole_frame());
    }
    let sinks = Sinks::of(func, machine, stack_pointer, entry_sp, calls_refund_stack);
    let mut carried: Option<BTreeSet<i64>> = None;
    loop {
        let walked = Walker::new(func, defs, entry_sp, &sinks, carried.as_ref()).run();
        let promoted = promotable(&walked);
        // An unplaced round is the answer: withdrawing a carrier only hides the flow through it.
        let settled = walked.points.unplaced()
            || (walked.carriers.iter()).all(|place| promoted.contains_key(place));
        if settled {
            r2il::refusal_evidence!(
                "frame-reach",
                "{:#x}: escaped {:?}, opaque {:?}, unplaced {}",
                func.entry,
                walked.points.escaped,
                (walked.points.opaque.iter())
                    .map(|access| &access.origin)
                    .collect::<BTreeSet<_>>(),
                walked.points.unplaced()
            );
            return (walked, promoted);
        }
        carried = Some(promoted.keys().copied().collect());
    }
}

/// Where a frame address leaves through a call.
struct Sinks<'a> {
    calls_refund_stack: bool,
    /// The registers a call may read where no `CallUse` says which: none under a convention.
    read_by_calls: Box<dyn Fn(crate::CanonicalStorageId) -> bool + 'a>,
    /// Whether the `CallUse` at this block and index hands its value to a callee that reaches
    /// only upward through it.
    upward_at: Box<dyn Fn(u64, usize, VarId) -> bool + 'a>,
    stack_arguments: StackArguments,
}

impl<'a> Sinks<'a> {
    fn of(
        func: &'a SSAFunction,
        machine: &'a SourceMachineContext,
        stack_pointer: crate::CanonicalStorageId,
        entry_sp: VarId,
        calls_refund_stack: bool,
    ) -> Self {
        let calls = func
            .blocks()
            .iter()
            .any(|block| block.ops().iter().any(SSAOp::is_call));
        let convention = machine.convention_slots().is_some();
        // The stack and frame pointers are the frame's own bases, not addresses handed on.
        let bases = [
            Some(stack_pointer),
            machine.machine_roles().frame_pointer_storage(),
        ];
        let read_by_calls = move |storage: crate::CanonicalStorageId| {
            calls
                && !convention
                && storage.space == crate::CanonicalStorageSpace::Register
                && !bases.contains(&Some(storage))
        };
        let integer_arguments = machine
            .convention_slots()
            .map(|slots| slots.argument_slots().to_vec())
            .unwrap_or_default();
        let upward_at = move |block: u64, index: usize, src: VarId| {
            let Some(ops) = func.get_block(block).map(|block| block.ops()) else {
                return false;
            };
            let target = ops[index + 1..].iter().find_map(|op| match op {
                SSAOp::CallUse { .. } => None,
                op => Some(
                    op.call()
                        .filter(|call| call.direct)
                        .and_then(|call| func.var(*call.target).constant_bits()),
                ),
            });
            let Some(Some(target)) = target else {
                return false;
            };
            let Some(position) = func.storage_of(src).and_then(|storage| {
                integer_arguments
                    .iter()
                    .position(|slot| slot.space == storage.space && slot.offset == storage.offset)
            }) else {
                return false;
            };
            machine
                .callee_argument_reach(target)
                .and_then(|reach| reach.get(&position))
                .is_some_and(crate::interproc::ArgumentReach::is_upward)
        };
        Self {
            calls_refund_stack,
            read_by_calls: Box::new(read_by_calls),
            upward_at: Box::new(upward_at),
            stack_arguments: StackArguments::of(func, machine, stack_pointer, entry_sp),
        }
    }
}

/// The stack each call may read: a frame address stored there leaves the body
/// (doc/adr-call-boundary.md, "D217 as built").
struct StackArguments {
    calls: Vec<CallArguments>,
}

/// One call's argument area, from the stack pointer it is measured at.
struct CallArguments {
    pointer: VarId,
    /// What the transfer spends where no restore records the pointer entering it.
    shift: i64,
    /// `CallReads::stack` of the call; none reads every place from the pointer to entry.
    area: Option<Vec<(i64, i64)>>,
}

impl StackArguments {
    /// One dominator-tree walk carries the stack pointer to every call: `O(B + ops)`.
    fn of(
        func: &SSAFunction,
        machine: &SourceMachineContext,
        stack_pointer: crate::CanonicalStorageId,
        entry_sp: VarId,
    ) -> Self {
        let site = Site {
            func,
            machine,
            spent: machine.return_mechanism().map_or(0, |mechanism| {
                i64::from(mechanism.stack_pointer_delta_bytes())
            }),
            stack_pointer,
        };
        let mut calls = Vec::new();
        let mut steps = vec![(func.root(), entry_sp)];
        let mut seen = BTreeSet::new();
        while let Some((address, mut pointer)) = steps.pop() {
            let Some(block) = func.get_block(address).filter(|_| seen.insert(address)) else {
                continue;
            };
            if let Some((_, phi)) = block.sited_phis().find(|(_, phi)| site.is_pointer(phi.dst)) {
                pointer = phi.dst;
            }
            pointer = site.calls(block.ops(), pointer, &mut calls);
            let children = func.domtree().children(address);
            steps.extend(children.iter().rev().map(|child| (*child, pointer)));
        }
        Self { calls }
    }

    /// Each call's area base, where every call is at a placed pointer.
    fn bases(&self, values: &IdMap<VarId, Value>) -> Option<Vec<i64>> {
        (self.calls.iter())
            .map(|call| {
                let base = values.get(call.pointer)?.exact()?;
                Some(base.wrapping_add(call.shift))
            })
            .collect()
    }

    /// Whether `read` could differ under other argument areas: every call is at a placed pointer
    /// and some place of `stored` ends above one, where an area begins. O(calls x stored).
    fn reads_by_area(&self, values: &IdMap<VarId, Value>, stored: &BTreeMap<i64, u32>) -> bool {
        let lowest = self.bases(values).and_then(|bases| bases.into_iter().min());
        lowest.is_some_and(|base| {
            (stored.iter()).any(|(place, width)| place.saturating_add(i64::from(*width)) > base)
        })
    }

    /// The places of `stored` some call may read, given each place's widest access.
    fn read(&self, values: &IdMap<VarId, Value>, stored: &BTreeMap<i64, u32>) -> BTreeSet<i64> {
        let mut read = BTreeSet::new();
        for call in &self.calls {
            let Some(base) = values.get(call.pointer).and_then(Value::exact) else {
                // A call at a pointer no offset places may read any place.
                return stored.keys().copied().collect();
            };
            let base = base.wrapping_add(call.shift);
            let within = |place: i64, width: u32| match &call.area {
                Some(area) => area.iter().any(|(low, high)| {
                    base.wrapping_add(*low) < place.saturating_add(i64::from(width))
                        && place < base.wrapping_add(*high)
                }),
                // Unbounded, it is still this frame's: it ends at the entry pointer.
                None => place.saturating_add(i64::from(width)) > base && place < 0,
            };
            read.extend(
                (stored.iter())
                    .filter(|(place, width)| within(**place, **width))
                    .map(|(place, _)| *place),
            );
        }
        read
    }
}

/// What every call of one function shares: the machine, and what a transfer spends.
struct Site<'a> {
    func: &'a SSAFunction,
    machine: &'a SourceMachineContext,
    spent: i64,
    stack_pointer: crate::CanonicalStorageId,
}

impl Site<'_> {
    fn is_pointer(&self, var: VarId) -> bool {
        self.func.storage_of(var) == Some(self.stack_pointer)
    }

    /// Each call of a block's `ops`, entered at the stack `pointer`; the pointer leaving it.
    fn calls(
        &self,
        ops: &[SSAOp<VarId>],
        mut pointer: VarId,
        out: &mut Vec<CallArguments>,
    ) -> VarId {
        for (index, op) in ops.iter().enumerate() {
            out.extend(self.call(&ops[index..], pointer));
            pointer = op
                .dst()
                .copied()
                .filter(|dst| self.is_pointer(*dst))
                .unwrap_or(pointer);
        }
        pointer
    }

    /// The call `ops` starts with, in the boundary's coordinates: the pointer a restore records
    /// entering the transfer, else the one reaching it past what the transfer spends.
    fn call(&self, ops: &[SSAOp<VarId>], pointer: VarId) -> Option<CallArguments> {
        let call = ops.first()?.call()?;
        let entering = (ops[1..].iter())
            .take_while(|op| matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }))
            .find_map(|op| match op {
                SSAOp::CallRestore { dst, src } if self.is_pointer(*dst) => Some(*src),
                _ => None,
            });
        let (pointer, shift) = entering.map_or((pointer, self.spent), |src| (src, 0));
        Some(CallArguments {
            pointer,
            shift,
            area: (self.machine.call_reads(call.instruction)).and_then(|reads| reads.stack),
        })
    }
}

/// One round's worklist over the frame's addresses, and what it has found.
struct Walker<'a> {
    func: &'a SSAFunction,
    defs: &'a Definitions,
    entry_sp: VarId,
    sinks: &'a Sinks<'a>,
    /// The places an address stored into flows to the loads of; every place when `None`.
    carried: Option<&'a BTreeSet<i64>>,
    uses: IdMap<VarId, Vec<(OpId, u64, usize)>>,
    phi_uses: IdMap<VarId, Vec<VarId>>,
    values: IdMap<VarId, Value>,
    pending: Vec<VarId>,
    accesses: Accesses,
    points: FramePoints,
    /// What each carrying place holds of the frame's addresses, and the values loaded from it.
    held: BTreeMap<i64, Value>,
    loaded: BTreeMap<i64, Vec<VarId>>,
    carriers: BTreeSet<i64>,
    /// Stores of an address whose place is not yet known: they escape if it never is.
    deferred: Vec<(VarId, VarId)>,
    /// Each exact place a frame address is stored into, with the address.
    stored: BTreeMap<i64, Value>,
}

impl<'a> Walker<'a> {
    fn new(
        func: &'a SSAFunction,
        defs: &'a Definitions,
        entry_sp: VarId,
        sinks: &'a Sinks<'a>,
        carried: Option<&'a BTreeSet<i64>>,
    ) -> Self {
        let mut uses = IdMap::<VarId, Vec<(OpId, u64, usize)>>::new(func.values().len());
        let mut phi_uses = IdMap::<VarId, Vec<VarId>>::new(func.values().len());
        for addr in func.block_addrs() {
            let Some(block) = func.get_block(*addr) else {
                continue;
            };
            for (_, phi) in block.sited_phis() {
                for (_, source) in &phi.sources {
                    phi_uses.get_or_insert_with(*source, Vec::new).push(phi.dst);
                }
            }
            for (index, (id, op)) in block.sited().enumerate() {
                for source in op.sources() {
                    uses.get_or_insert_with(*source, Vec::new)
                        .push((id, *addr, index));
                }
            }
        }
        let mut values = IdMap::<VarId, Value>::new(func.values().len());
        values.insert(entry_sp, Value::one(Point::Exact(0)));
        Self {
            func,
            defs,
            entry_sp,
            sinks,
            carried,
            uses,
            phi_uses,
            values,
            pending: vec![entry_sp],
            accesses: Accesses::new(),
            points: FramePoints::default(),
            held: BTreeMap::new(),
            loaded: BTreeMap::new(),
            carriers: BTreeSet::new(),
            deferred: Vec::new(),
            stored: BTreeMap::new(),
        }
    }

    fn run(mut self) -> Walked {
        loop {
            while let Some(var) = self.pending.pop() {
                self.visit(var);
            }
            // A merge some of whose sources are frame addresses and some not reads another place
            // on some path: its points, at no exact place.
            let partial = self.partial_merges();
            if partial.is_empty() {
                break;
            }
            for dst in partial {
                let known = self.known_sources(dst);
                self.set(dst, known.degraded());
            }
        }
        self.finish()
    }

    fn set(&mut self, var: VarId, value: Value) {
        let joined = self
            .values
            .get(var)
            .map_or_else(|| value.clone(), |known| known.join(&value));
        if self.values.get(var) != Some(&joined) {
            self.values.insert(var, joined);
            self.pending.push(var);
        }
    }

    fn escape(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                // Handed on, an address may be indexed either way.
                self.points
                    .escaped
                    .extend(points.iter().map(|point| match point {
                        Point::Derived(_) => point.frame_point(),
                        _ => FramePoint {
                            at: point.frame_point().at,
                            extent: Extent::Either,
                        },
                    }));
            }
            Value::Top => self.points.whole = true,
        }
    }

    fn escape_up(&mut self, value: &Value) {
        match value {
            Value::Points(points) => {
                self.points
                    .escaped
                    .extend(points.iter().map(|point| match point {
                        Point::Exact(at) => FramePoint {
                            at: *at,
                            extent: Extent::Upward,
                        },
                        indexed => indexed.frame_point(),
                    }));
            }
            Value::Top => self.points.whole = true,
        }
    }

    fn opaque(&mut self, op: OpId, value: &Value) {
        let origin = match value {
            Value::Points(points) => {
                Origin::Points(points.iter().map(|point| point.frame_point()).collect())
            }
            Value::Top => Origin::Unplaced,
        };
        self.points.opaque.push(OpaqueAccess { op, origin });
    }

    /// Everything `var`'s value reaches: the merges it feeds and each operation reading it.
    fn visit(&mut self, var: VarId) {
        let Some(value) = self.values.get(var).cloned() else {
            return;
        };
        if var != self.entry_sp
            && (self.func.storage_of(var))
                .is_some_and(|storage| (self.sinks.read_by_calls)(storage))
        {
            self.escape(&value);
        }
        for dst in self.phi_uses.get(var).cloned().unwrap_or_default() {
            let (root, offset) = self.defs.affine(self.func, dst);
            let merged = if root == self.entry_sp {
                Some(Value::one(Point::Exact(offset)))
            } else if self.values.get(dst).is_some() {
                // A merge that moves again is carried round a loop or past a partial source: its
                // places at no exact offset, so a stepped pointer settles (the widening).
                Some(self.known_sources(dst).degraded())
            } else {
                self.merged_sources(dst)
            };
            if let Some(merged) = merged {
                self.set(dst, merged);
            }
        }
        for (id, block, index) in self.uses.get(var).cloned().unwrap_or_default() {
            let Some(op) = (self.func.get_block(block)).and_then(|block| block.ops().get(index))
            else {
                continue;
            };
            let whole_before = self.points.unplaced();
            self.read(var, &value, op, (id, block, index));
            if self.points.unplaced() && !whole_before {
                r2il::refusal_evidence!(
                    "frame-reach",
                    "{block:#x}:{index} {op:?} takes a frame address no offset places"
                );
            }
        }
    }

    /// The join of a merge's sources, once every one is a frame address.
    fn merged_sources(&self, phi: VarId) -> Option<Value> {
        let mut joined = None::<Value>;
        for source in self.defs.phi_sources(phi) {
            let value = self.values.get(*source)?;
            joined = Some(joined.map_or_else(|| value.clone(), |known| known.join(value)));
        }
        joined
    }

    /// The join of a merge's sources that are frame addresses.
    fn known_sources(&self, phi: VarId) -> Value {
        (self.defs.phi_sources(phi).iter())
            .filter_map(|source| self.values.get(*source))
            .fold(Value::Points(BTreeSet::new()), |joined, value| {
                joined.join(value)
            })
    }

    /// One operation reading `var`, which holds `value`.
    fn read(&mut self, var: VarId, value: &Value, op: &SSAOp<VarId>, site: (OpId, u64, usize)) {
        let (id, block, index) = site;
        match op {
            SSAOp::Load { dst, addr, .. } if *addr == var => {
                let width = self.func.var(*dst).size;
                match value.exact() {
                    Some(place) => {
                        self.loaded.entry(place).or_default().push(*dst);
                        if let Some(address) = self.held.get(&place).cloned() {
                            self.set(*dst, address);
                        }
                        self.access(place, id, block, index, width, false);
                    }
                    None => self.opaque(id, value),
                }
            }
            SSAOp::Store { addr, val, .. } => {
                self.store(*addr, *val);
                let refunded =
                    || call_push(self.func, block, index, *val, self.sinks.calls_refund_stack);
                if *addr == var && !refunded() {
                    let width = self.func.var(*val).size;
                    match value.exact() {
                        Some(place) => self.access(place, id, block, index, width, true),
                        None => self.opaque(id, value),
                    }
                }
            }
            SSAOp::Copy { dst, .. } | SSAOp::CallRestore { dst, .. } => {
                self.set(*dst, value.clone());
            }
            SSAOp::IntAdd { dst, a, b } | SSAOp::IntSub { dst, a, b } => {
                let subtract = matches!(op, SSAOp::IntSub { .. });
                let next = self.displaced(var, value, (*a, *b), subtract);
                self.set(*dst, next);
            }
            SSAOp::CallUse { src } if (self.sinks.upward_at)(block, index, *src) => {
                self.escape_up(value);
            }
            SSAOp::CallUse { .. } | SSAOp::CallOther { .. } => self.escape(value),
            // An access no exact load or store states: through its address it stays in memory;
            // any other operand it reads is handed on.
            _ if memory_addresses(op).is_some() => {
                let addresses = memory_addresses(op).unwrap_or_default();
                if addresses.contains(&var) {
                    self.opaque(id, value);
                }
                let handed = (op.sources().iter())
                    .any(|source| **source == var && !addresses.contains(*source));
                if handed {
                    self.escape(value);
                }
            }
            // A truth value or a count: the address is only tested, and nothing of it is carried.
            SSAOp::CBranch { target, .. } if *target != var => {}
            _ if op.value_use() == r2il::ValueUse::Tests => {}
            // Masked, mixed or narrowed, it points into what the address did, at no exact place
            // (the seal's provenance rule): its own uses decide what it reaches.
            _ if op.value_use() != r2il::ValueUse::Consumes => {
                if let Some(dst) = op.dst() {
                    self.set(*dst, value.degraded());
                }
            }
            // Default deny: a target, a return or an unmodelled use reaches every place.
            _ => self.points.whole = true,
        }
    }

    fn access(&mut self, place: i64, op: OpId, block: u64, index: usize, width: u32, store: bool) {
        self.accesses.entry(place).or_default().push(Access {
            op,
            block,
            index,
            width,
            store,
        });
    }

    /// A frame address stored: carried by a place that may be promoted, else handed on.
    fn store(&mut self, addr: VarId, val: VarId) {
        let Some(address) = self.values.get(val).cloned() else {
            return;
        };
        let carries = |place: i64| self.carried.is_none_or(|carried| carried.contains(&place));
        let place = self.values.get(addr).map(Value::exact);
        // A place stored again holds what it held and the new address at no exact offset, so a
        // cursor stepped through memory settles (the widening).
        let widened = |known: Option<&Value>| match known {
            Some(known) if known.join(&address) != *known => known.join(&address.degraded()),
            Some(known) => known.clone(),
            None => address.clone(),
        };
        if let Some(Some(place)) = place {
            let joined = widened(self.stored.get(&place));
            self.stored.insert(place, joined);
        }
        match place {
            Some(Some(place)) if carries(place) => {
                self.carriers.insert(place);
                let joined = widened(self.held.get(&place));
                if self.held.insert(place, joined.clone()).as_ref() != Some(&joined) {
                    for dst in self.loaded.get(&place).cloned().unwrap_or_default() {
                        self.set(dst, joined.clone());
                    }
                }
            }
            Some(_) => self.escape(&address),
            None => self.deferred.push((val, addr)),
        }
    }

    /// Where `var`, holding `value`, is moved by the other operand of an add or subtract.
    fn displaced(
        &self,
        var: VarId,
        value: &Value,
        (a, b): (VarId, VarId),
        subtract: bool,
    ) -> Value {
        let other = if a == var { b } else { a };
        let Value::Points(points) = value else {
            return Value::Top;
        };
        if subtract && b == var {
            return value.degraded();
        }
        let amount = self.defs.constant(self.func, other);
        let up = !subtract && non_negative(self.func, self.defs, other);
        let moved = points.iter().map(|point| match (*point, amount) {
            // Machine addresses are modular, as in the lifted arithmetic.
            (Point::Exact(offset), Some(amount)) => Point::Exact(if subtract {
                offset.wrapping_sub(amount)
            } else {
                offset.wrapping_add(amount)
            }),
            (kept @ (Point::Indexed { .. } | Point::Derived(_)), Some(_)) => kept,
            (derived @ Point::Derived(_), None) => derived,
            (Point::Exact(from) | Point::Indexed { from, .. }, None) => Point::Indexed { from, up },
        });
        Value::Points(moved.collect())
    }

    /// The merges with no value yet some of whose sources are frame addresses, in id order.
    fn partial_merges(&self) -> Vec<VarId> {
        let mut partial = (self.phi_uses.iter())
            .flat_map(|(_, dsts)| dsts.iter().copied())
            .filter(|dst| self.values.get(*dst).is_none())
            .filter(|dst| {
                (self.defs.phi_sources(*dst).iter())
                    .any(|source| self.values.get(*source).is_some())
            })
            .collect::<Vec<_>>();
        partial.sort_unstable();
        partial.dedup();
        partial
    }

    fn finish(mut self) -> Walked {
        for (val, addr) in std::mem::take(&mut self.deferred) {
            if self.values.get(addr).is_none()
                && let Some(address) = self.values.get(val).cloned()
            {
                self.escape(&address);
            }
        }
        // An address in a slot a call reads is handed to the callee: it escapes, and the slot
        // keeps its store.
        let widths = (self.stored.keys())
            .map(|place| {
                let widest =
                    (self.accesses.get(place).into_iter().flatten()).map(|access| access.width);
                (*place, widest.max().unwrap_or(1))
            })
            .collect();
        let arguments = &self.sinks.stack_arguments;
        self.points.by_area = arguments.reads_by_area(&self.values, &widths);
        let handed = arguments.read(&self.values, &widths);
        for place in &handed {
            if let Some(address) = self.stored.get(place).cloned() {
                self.escape(&address);
            }
        }
        self.points.handed = handed;
        Walked {
            points: self.points,
            accesses: self.accesses,
            carriers: self.carriers,
        }
    }
}

/// The addresses an access other than a plain load or store reads.
fn memory_addresses(op: &SSAOp<VarId>) -> Option<Vec<VarId>> {
    match op {
        SSAOp::LoadLinked { addr, .. }
        | SSAOp::StoreConditional { addr, .. }
        | SSAOp::LoadGuarded { addr, .. }
        | SSAOp::StoreGuarded { addr, .. } => Some(vec![*addr]),
        SSAOp::Atomic(access) => Some(vec![access.addr]),
        SSAOp::BlockTransfer(transfer) => Some(vec![transfer.destination, transfer.source]),
        _ => None,
    }
}

/// Whether a store is a call pushing its return address, which the callee refunds.
fn call_push(func: &SSAFunction, block: u64, index: usize, val: VarId, refunds: bool) -> bool {
    refunds
        && func.var(val).constant_bits().is_some()
        && func.get_block(block).is_some_and(|block| {
            block.ops()[index + 1..]
                .iter()
                .find(|op| !matches!(op, SSAOp::CallUse { .. }))
                .is_some_and(SSAOp::is_call)
        })
}

/// Whether a value is never negative: an extension from narrower, or a masked, shifted or
/// scaled one.
fn non_negative(func: &SSAFunction, defs: &Definitions, var: VarId) -> bool {
    let width = func.var(var).size * 8;
    match defs.op(defs.copied(var)).map(|(_, op)| op) {
        Some(SSAOp::IntZExt { .. }) => true,
        Some(SSAOp::IntAnd { a, b, .. }) => [*a, *b].iter().any(|mask| {
            func.var(*mask)
                .constant_bits()
                .is_some_and(|bits| width >= 1 && bits >> (width - 1) & 1 == 0)
        }),
        Some(SSAOp::IntRight { b, .. }) => {
            func.var(*b).constant_bits().is_some_and(|bits| bits > 0)
        }
        Some(SSAOp::IntLeft { a, b, .. } | SSAOp::IntMult { a, b, .. }) => {
            non_negative(func, defs, *a)
                && func
                    .var(*b)
                    .constant_bits()
                    .is_some_and(|bits| bits < u64::from(width))
        }
        _ => func
            .var(var)
            .constant_bits()
            .is_some_and(|bits| width >= 1 && bits >> (width - 1) & 1 == 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped(points: &[(i64, Extent)]) -> FramePoints {
        FramePoints {
            escaped: (points.iter())
                .map(|(at, extent)| FramePoint {
                    at: *at,
                    extent: *extent,
                })
                .collect(),
            ..FramePoints::default()
        }
    }

    /// A compiler slot is no object an index below it spans: only a point inside it names it.
    #[test]
    fn an_indexed_point_below_a_slot_does_not_name_it() {
        let points = escaped(&[(-64, Extent::Upward)]);
        assert!(!points.names(-16, -8));
        assert!(points.names(-64, -56));
        assert!(escaped(&[(-12, Extent::Either)]).names(-16, -8));
    }

    /// An escape reaches out to a save on either side, and upward only from an upward point.
    #[test]
    fn a_save_bounds_what_an_escape_reaches() {
        let saves = BTreeSet::from([-24]);
        let either = escaped(&[(-40, Extent::Either)]);
        assert!(either.reaches(-48, &saves) && either.reaches(-32, &saves));
        assert!(!either.reaches(-16, &saves));
        let upward = escaped(&[(-40, Extent::Upward)]);
        assert!(!upward.reaches(-48, &saves) && upward.reaches(-32, &saves));
    }

    /// Default deny: a derived point, an unplaced access or the whole frame reach every place.
    #[test]
    fn a_derived_or_unplaced_point_reaches_every_place() {
        let none = BTreeSet::new();
        assert!(escaped(&[(-40, Extent::Derived)]).reaches(-200, &none));
        assert!(FramePoints::whole_frame().names(-16, -8));
        let opaque = FramePoints {
            opaque: vec![OpaqueAccess {
                op: OpId::from_index(0),
                origin: Origin::Unplaced,
            }],
            ..FramePoints::default()
        };
        assert!(opaque.unplaced() && opaque.reaches(-8, &none));
        assert!(!FramePoints::default().reaches(-8, &none));
    }
}
