//! Frame slots taken out of memory as SSA values, before preparation (doc/adr-frame-model.md, P4.3).
//!
//! A place every access to which is a load or store of one width at one entry offset, that no
//! escaped frame address reaches and no declaration names, is a variable: a store becomes a copy
//! into a new version of `stack:mN`, a load a copy out of the version that reaches it, a merge a
//! phi. Escape is FrameReach's rule over the raw SSA: a frame address that reaches a call, a store's
//! value or an unmodelled operation reaches every place on either side of it, out to a save slot.
//! `O(V + E)` to classify, `O(places x blocks)` to rename.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::dense::{DenseId, IdMap, IdSet};
use crate::frame_address::Definitions;
use crate::function::{EditPlan, PhiNode, SSAFunction, ShapeEdit};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::{Minting, VarId};
use crate::var::SSAVar;

/// The space promoted stack slots live in: not memory, and not the lifter's scratch either.
pub(crate) const PROMOTED_SLOT_SPACE: u32 = 0x5301;

/// Where a promoted frame slot sits relative to the entry frame, where this storage is one.
pub fn promoted_slot_offset(storage: &crate::CanonicalStorageId) -> Option<i64> {
    let promoted = storage.space == crate::CanonicalStorageSpace::Custom(PROMOTED_SLOT_SPACE);
    promoted.then_some(storage.offset as i64)
}

/// Where a value derived from the entry stack pointer points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    /// Exactly this entry offset.
    Exact(i64),
    /// This offset plus an index: upward only where the index is non-negative.
    Indexed { from: i64, up: bool },
    /// A frame address no offset places.
    Unknown,
}

impl Point {
    fn join(self, other: Self) -> Self {
        if self == other { self } else { Self::Unknown }
    }
}

/// One access at an exact place.
struct Access {
    op: OpId,
    block: u64,
    index: usize,
    width: u32,
    store: bool,
}

/// What is never promoted, and what an escape cannot cross.
struct Reach {
    whole: bool,
    both: BTreeSet<i64>,
    up: BTreeSet<i64>,
}

/// Promote every eligible frame place of `func`; the loads and stores rewritten.
pub(crate) fn promote(
    func: &mut SSAFunction,
    machine: &SourceMachineContext,
    calls_refund_stack: bool,
) -> IdSet<OpId> {
    let Some(stack_pointer) = machine.stack_pointer_carrier() else {
        return IdSet::default();
    };
    // An entry block something branches back to runs its prologue more than once: no place is fixed.
    if func.cfg().has_entry_edge() {
        return IdSet::default();
    }
    let entry_sp = (0..func.values().len())
        .map(VarId::from_index)
        .find(|id| func.var(*id).version == 0 && func.storage_of(*id) == Some(stack_pointer));
    let Some(entry_sp) = entry_sp else {
        return IdSet::default();
    };
    let defs = Definitions::of(func);
    // A call may read the convention's argument registers (every register, with no convention),
    // so a frame address one of those holds is handed on.
    let calls = has_call(func);
    let arguments = machine.convention_slots().map(|slots| {
        slots
            .argument_slots()
            .iter()
            .chain(slots.float_argument_slots())
            .copied()
            .collect::<Vec<_>>()
    });
    // The stack and frame pointers are the frame's own bases, not addresses handed on.
    let bases = [
        Some(stack_pointer),
        machine.machine_roles().frame_pointer_storage(),
    ];
    // With a convention each call reads its arguments through `CallUse`; without one, a call may
    // read any register.
    let read_by_calls = |storage: crate::CanonicalStorageId| {
        calls
            && arguments.is_none()
            && storage.space == crate::CanonicalStorageSpace::Register
            && !bases.contains(&Some(storage))
    };
    // An address a direct callee is proven to reach only upward through escapes only upward.
    let integer_arguments = machine
        .convention_slots()
        .map(|slots| slots.argument_slots().to_vec())
        .unwrap_or_default();
    let upward_at = |block: u64, index: usize, src: VarId| {
        let Some(ops) = func.get_block(block).map(|block| block.ops()) else {
            return false;
        };
        let target = ops[index + 1..].iter().find_map(|op| match op {
            SSAOp::CallUse { .. } => None,
            SSAOp::Call { target, .. } => Some(func.var(*target).constant_bits()),
            _ => Some(None),
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
    let sinks = Sinks {
        calls_refund_stack,
        read_by_calls: &read_by_calls,
        upward_at: &upward_at,
    };
    // Assume every place may carry an address stored into it; withdraw the places promotion
    // refuses until the assumption holds. The set only shrinks: at most one round per place.
    let mut carried: Option<BTreeSet<i64>> = None;
    let (accesses, reach, promotable) = loop {
        let (accesses, reach, carriers) = classify(func, &defs, entry_sp, &sinks, carried.as_ref());
        if reach.whole {
            break (accesses, reach, BTreeMap::new());
        }
        let saves = saves(func, &defs, &accesses, machine);
        let promotable = eligible(func, &defs, &accesses, &reach, &saves, machine);
        if carriers.iter().all(|place| promotable.contains_key(place)) {
            break (accesses, reach, promotable);
        }
        carried = Some(promotable.keys().copied().collect());
    };
    if reach.whole {
        r2il::refusal_evidence!(
            "promote-stack-slot",
            "{:#x}: a frame address no offset places reaches an access or leaves, so nothing is promoted",
            func.entry
        );
        return IdSet::default();
    }
    if promotable.is_empty() {
        return IdSet::default();
    }
    r2il::refusal_evidence!(
        "promote-stack-slot",
        "{:#x}: {} slots promoted out of memory: {:?}",
        func.entry,
        promotable.len(),
        promotable.keys().collect::<Vec<_>>()
    );
    rename(func, &accesses, &promotable)
}

/// Where a frame address leaves through a call.
struct Sinks<'a> {
    calls_refund_stack: bool,
    /// Whether a call may read a register of this storage, where no `CallUse` says which.
    read_by_calls: &'a dyn Fn(crate::CanonicalStorageId) -> bool,
    /// Whether the `CallUse` at this block and index hands its value to a callee that reaches
    /// only upward through it.
    upward_at: &'a dyn Fn(u64, usize, VarId) -> bool,
}

/// Every exact access to the frame, by entry offset, what the frame's escapes reach, and the
/// places an address was stored into. An address stored into a place of `carried` (every place
/// when `None`) flows to that place's loads instead of escaping.
fn classify(
    func: &SSAFunction,
    defs: &Definitions,
    entry_sp: VarId,
    sinks: &Sinks<'_>,
    carried: Option<&BTreeSet<i64>>,
) -> (BTreeMap<i64, Vec<Access>>, Reach, BTreeSet<i64>) {
    let mut classifier = Classifier::new(func, defs, entry_sp, sinks, carried);
    loop {
        while let Some(var) = classifier.pending.pop() {
            classifier.visit(var);
        }
        // A merge some of whose sources are frame addresses and some not is one no offset places:
        // a load through it reads another place on some path.
        let partial = classifier.partial_merges();
        if partial.is_empty() {
            break;
        }
        for dst in partial {
            classifier.set(dst, Point::Unknown);
        }
    }
    classifier.finish()
}

/// The classifier's worklist over the frame's addresses, and what it has found.
struct Classifier<'a> {
    func: &'a SSAFunction,
    defs: &'a Definitions,
    entry_sp: VarId,
    sinks: &'a Sinks<'a>,
    carried: Option<&'a BTreeSet<i64>>,
    uses: IdMap<VarId, Vec<(OpId, u64, usize)>>,
    phi_uses: IdMap<VarId, Vec<VarId>>,
    points: IdMap<VarId, Point>,
    pending: Vec<VarId>,
    accesses: BTreeMap<i64, Vec<Access>>,
    reach: Reach,
    /// What each place holds of the frame's addresses, and the values loaded from it.
    held: BTreeMap<i64, Point>,
    loaded: BTreeMap<i64, Vec<VarId>>,
    carriers: BTreeSet<i64>,
    /// Stores of an address whose place is not yet known: they escape if it never is.
    deferred: Vec<(VarId, VarId)>,
}

impl<'a> Classifier<'a> {
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
        let mut points = IdMap::<VarId, Point>::new(func.values().len());
        points.insert(entry_sp, Point::Exact(0));
        Self {
            func,
            defs,
            entry_sp,
            sinks,
            carried,
            uses,
            phi_uses,
            points,
            pending: vec![entry_sp],
            accesses: BTreeMap::new(),
            reach: Reach {
                whole: false,
                both: BTreeSet::new(),
                up: BTreeSet::new(),
            },
            held: BTreeMap::new(),
            loaded: BTreeMap::new(),
            carriers: BTreeSet::new(),
            deferred: Vec::new(),
        }
    }

    fn set(&mut self, var: VarId, point: Point) {
        let joined = self
            .points
            .get(var)
            .map_or(point, |known| known.join(point));
        if self.points.get(var) != Some(&joined) {
            self.points.insert(var, joined);
            self.pending.push(var);
        }
    }

    fn escape(&mut self, point: Point) {
        match point {
            Point::Exact(offset) | Point::Indexed { from: offset, .. } => {
                self.reach.both.insert(offset);
            }
            Point::Unknown => self.reach.whole = true,
        }
    }

    fn escape_up(&mut self, point: Point) {
        match point {
            Point::Exact(offset)
            | Point::Indexed {
                from: offset,
                up: true,
            } => {
                self.reach.up.insert(offset);
            }
            Point::Indexed { from, up: false } => {
                self.reach.both.insert(from);
            }
            Point::Unknown => self.reach.whole = true,
        }
    }

    /// Everything `var`'s point reaches: the merges it feeds and each operation reading it.
    fn visit(&mut self, var: VarId) {
        let Some(point) = self.points.get(var).copied() else {
            return;
        };
        if var != self.entry_sp
            && self
                .func
                .storage_of(var)
                .is_some_and(self.sinks.read_by_calls)
        {
            self.escape(point);
        }
        for dst in self.phi_uses.get(var).cloned().unwrap_or_default() {
            let (root, offset) = self.defs.affine(self.func, dst);
            let merged = if root == self.entry_sp {
                Some(Point::Exact(offset))
            } else {
                merged_sources(self.defs, &self.points, dst)
            };
            if let Some(merged) = merged {
                self.set(dst, merged);
            }
        }
        for (id, block, index) in self.uses.get(var).cloned().unwrap_or_default() {
            let Some(op) = self
                .func
                .get_block(block)
                .and_then(|block| block.ops().get(index))
            else {
                continue;
            };
            let whole_before = self.reach.whole;
            self.read(var, point, op, (id, block, index));
            if self.reach.whole && !whole_before {
                r2il::refusal_evidence!(
                    "promote-stack-slot",
                    "{block:#x}:{index} {op:?} takes the frame address {point:?} where no offset places it"
                );
            }
        }
    }

    /// One operation reading `var`, which points at `point`.
    fn read(&mut self, var: VarId, point: Point, op: &SSAOp<VarId>, site: (OpId, u64, usize)) {
        let (id, block, index) = site;
        match op {
            SSAOp::Load { dst, addr, .. } if *addr == var => {
                if let Point::Exact(place) = point {
                    self.loaded.entry(place).or_default().push(*dst);
                    if let Some(address) = self.held.get(&place).copied() {
                        self.set(*dst, address);
                    }
                }
                let width = self.func.var(*dst).size;
                access(
                    &mut self.accesses,
                    &mut self.reach,
                    point,
                    id,
                    block,
                    index,
                    width,
                    false,
                );
            }
            SSAOp::Store { addr, val, .. } => {
                self.store(*addr, *val);
                if *addr == var
                    && !call_push(self.func, block, index, *val, self.sinks.calls_refund_stack)
                {
                    let width = self.func.var(*val).size;
                    access(
                        &mut self.accesses,
                        &mut self.reach,
                        point,
                        id,
                        block,
                        index,
                        width,
                        true,
                    );
                }
            }
            SSAOp::Copy { dst, .. } | SSAOp::CallRestore { dst, .. } => self.set(*dst, point),
            SSAOp::IntAdd { dst, a, b } | SSAOp::IntSub { dst, a, b } => {
                let subtract = matches!(op, SSAOp::IntSub { .. });
                let next = self.displaced(var, point, (*a, *b), subtract);
                self.set(*dst, next);
            }
            SSAOp::CallUse { src } if (self.sinks.upward_at)(block, index, *src) => {
                self.escape_up(point);
            }
            SSAOp::CallUse { .. } => self.escape(point),
            // A frame address used as code, or as a value an unmodelled operation reads.
            SSAOp::Call { .. }
            | SSAOp::CallInd { .. }
            | SSAOp::Branch { .. }
            | SSAOp::BranchInd { .. }
            | SSAOp::Return { .. }
            | SSAOp::CallOther { .. } => self.reach.whole = true,
            // Compared, masked or measured, it is a number: it is an address again only if what
            // it makes reaches an access or a sink, which its own uses decide.
            _ => {
                if let Some(dst) = op.dst() {
                    self.set(*dst, Point::Unknown);
                }
            }
        }
    }

    /// A frame address stored: carried by a place that may be promoted, else handed on.
    fn store(&mut self, addr: VarId, val: VarId) {
        let Some(address) = self.points.get(val).copied() else {
            return;
        };
        let carries = |place: i64| self.carried.is_none_or(|carried| carried.contains(&place));
        match self.points.get(addr).copied() {
            Some(Point::Exact(place)) if carries(place) => {
                self.carriers.insert(place);
                let joined = self
                    .held
                    .get(&place)
                    .map_or(address, |known| known.join(address));
                if self.held.insert(place, joined) != Some(joined) {
                    for dst in self.loaded.get(&place).cloned().unwrap_or_default() {
                        self.set(dst, joined);
                    }
                }
            }
            Some(_) => self.escape(address),
            None => self.deferred.push((val, addr)),
        }
    }

    /// Where `var`, at `point`, is moved by the other operand of an add or subtract.
    fn displaced(&self, var: VarId, point: Point, (a, b): (VarId, VarId), subtract: bool) -> Point {
        let other = if a == var { b } else { a };
        match (point, self.defs.constant(self.func, other)) {
            _ if subtract && b == var => Point::Unknown,
            (Point::Exact(offset), Some(amount)) => Point::Exact(if subtract {
                offset - amount
            } else {
                offset + amount
            }),
            (Point::Indexed { from, up }, Some(_)) => Point::Indexed { from, up },
            (Point::Exact(from) | Point::Indexed { from, .. }, None) => Point::Indexed {
                from,
                up: !subtract && non_negative(self.func, self.defs, other),
            },
            (Point::Unknown, _) => Point::Unknown,
        }
    }

    fn partial_merges(&self) -> BTreeSet<VarId> {
        self.phi_uses
            .iter()
            .flat_map(|(_, dsts)| dsts.iter().copied())
            .filter(|dst| self.points.get(*dst).is_none())
            .filter(|dst| {
                self.defs
                    .phi_sources(*dst)
                    .iter()
                    .any(|source| self.points.get(*source).is_some())
            })
            .collect()
    }

    fn finish(mut self) -> (BTreeMap<i64, Vec<Access>>, Reach, BTreeSet<i64>) {
        for (val, addr) in std::mem::take(&mut self.deferred) {
            if self.points.get(addr).is_none()
                && let Some(address) = self.points.get(val).copied()
            {
                self.escape(address);
            }
        }
        (self.accesses, self.reach, self.carriers)
    }
}

/// The join of a merge's sources, once every one is a frame address.
fn merged_sources(defs: &Definitions, points: &IdMap<VarId, Point>, phi: VarId) -> Option<Point> {
    let mut joined = None::<Point>;
    for source in defs.phi_sources(phi) {
        let point = points.get(*source).copied()?;
        joined = Some(joined.map_or(point, |known| known.join(point)));
    }
    joined
}

#[expect(
    clippy::too_many_arguments,
    reason = "one access, as the classifier found it"
)]
fn access(
    accesses: &mut BTreeMap<i64, Vec<Access>>,
    reach: &mut Reach,
    point: Point,
    op: OpId,
    block: u64,
    index: usize,
    width: u32,
    store: bool,
) {
    match point {
        Point::Exact(offset) => accesses.entry(offset).or_default().push(Access {
            op,
            block,
            index,
            width,
            store,
        }),
        Point::Indexed { from, up: true } => {
            reach.up.insert(from);
        }
        Point::Indexed { from, up: false } => {
            reach.both.insert(from);
        }
        Point::Unknown => reach.whole = true,
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
                .is_some_and(|op| matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. }))
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

/// The places a register the convention preserves is saved into at its entry value; they bound
/// what an escaped address reaches.
fn saves(
    func: &SSAFunction,
    defs: &Definitions,
    accesses: &BTreeMap<i64, Vec<Access>>,
    machine: &SourceMachineContext,
) -> BTreeSet<i64> {
    // With no convention nothing says which register a callee may keep, so every one is saved.
    let effect = machine.call_effect();
    accesses
        .iter()
        .filter(|(_, list)| {
            list.iter().any(|access| {
                access.store
                    && access.block == func.root()
                    && func
                        .get_block(access.block)
                        .and_then(|block| match block.ops().get(access.index) {
                            Some(SSAOp::Store { val, .. }) => Some(defs.copied(*val)),
                            _ => None,
                        })
                        .is_some_and(|val| {
                            // A register the convention preserves: the compiler's save, not a variable.
                            func.var(val).version == 0
                                && func.storage_of(val).is_some_and(|storage| {
                                    storage.space == crate::CanonicalStorageSpace::Register
                                        && effect.is_none_or(|effect| effect.preserves(storage))
                                })
                        })
            })
        })
        .map(|(offset, _)| *offset)
        .collect()
}

/// Each place a variable may stand for, with its one width.
fn eligible(
    func: &SSAFunction,
    defs: &Definitions,
    accesses: &BTreeMap<i64, Vec<Access>>,
    reach: &Reach,
    saves: &BTreeSet<i64>,
    machine: &SourceMachineContext,
) -> BTreeMap<i64, u32> {
    let separated = |from: i64, place: i64| {
        let (low, high) = (from.min(place), from.max(place));
        high > low.saturating_add(1) && saves.range(low + 1..high).next().is_some()
    };
    let reachable = |place: i64| {
        reach.both.iter().any(|from| !separated(*from, place))
            || reach
                .up
                .range(..=place)
                .any(|from| !separated(*from, place))
    };
    let declared = machine
        .function_interface()
        .map(|interface| interface.stack_slots().to_vec())
        .unwrap_or_default();
    let declared_covers = |offset: i64, width: u32| {
        declared.iter().any(|slot| {
            slot.base() == crate::StackAddressBase::StackPointer
                && slot.offset() < offset + i64::from(width)
                && offset < slot.offset() + i64::from(slot.size_bytes())
        })
    };
    let mut promotable = BTreeMap::new();
    let places = accesses.keys().copied().collect::<Vec<_>>();
    for (offset, list) in accesses {
        // At or above the entry stack pointer is the caller's: the return address, stack arguments.
        if *offset >= 0 {
            continue;
        }
        let widths = list
            .iter()
            .map(|access| access.width)
            .collect::<BTreeSet<_>>();
        let Some(width) = widths.iter().next().copied().filter(|_| widths.len() == 1) else {
            continue;
        };
        let overlaps = places.iter().any(|other| {
            other != offset
                && accesses[other].iter().any(|access| {
                    *other < offset + i64::from(width) && *offset < other + i64::from(access.width)
                })
        });
        let stores = list.iter().filter(|access| access.store).count();
        let read_only_home = stores == 1
            && list.iter().filter(|access| access.store).any(|access| {
                func.get_block(access.block)
                    .and_then(|block| match block.ops().get(access.index) {
                        Some(SSAOp::Store { val, .. }) => Some(entry_value(func, defs, *val)),
                        _ => None,
                    })
                    .unwrap_or(false)
            });
        let is_declared = declared_covers(*offset, width) && !read_only_home;
        // A save read back stays in memory: the frame round-trip certificate answers for it.
        let is_save = saves.contains(offset) && list.iter().any(|access| !access.store);
        if overlaps || is_save || is_declared || reachable(*offset) {
            r2il::refusal_evidence!(
                "promote-stack-slot",
                "{:#x}: slot at {offset} stays in memory: overlap {overlaps}, save {is_save}, declared {is_declared}, reached {}",
                func.entry,
                reachable(*offset)
            );
            continue;
        }
        promotable.insert(*offset, width);
    }
    promotable
}

/// Rewrite every access of every promotable place into copies of its versions, with merges.
fn rename(
    func: &mut SSAFunction,
    accesses: &BTreeMap<i64, Vec<Access>>,
    promotable: &BTreeMap<i64, u32>,
) -> IdSet<OpId> {
    let mut plan = EditPlan::new();
    let mut minting = Minting::new(func.values());
    let mut rewritten = IdSet::default();
    let root = func.root();
    for (offset, width) in promotable {
        let storage = crate::CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Custom(PROMOTED_SLOT_SPACE),
            offset: *offset as u64,
            size: *width,
        };
        let name = crate::naming::frame_slot_name(*offset);
        let mut version = 0u32;
        let mut fresh = |minting: &mut Minting<'_>| {
            version += 1;
            minting.intern_with_storage(&SSAVar::new(&name, version, *width), storage)
        };
        let entry = minting.intern_with_storage(&SSAVar::new(&name, 0, *width), storage);
        let list = &accesses[offset];
        // Per block, the accesses in order, and whether the block reads the slot before writing it.
        let mut by_block = BTreeMap::<u64, Vec<&Access>>::new();
        for access in list {
            by_block.entry(access.block).or_default().push(access);
        }
        for accesses in by_block.values_mut() {
            accesses.sort_by_key(|access| access.index);
        }
        let live_in = live_in(func, &by_block);
        let defined = by_block
            .iter()
            .filter(|(_, accesses)| accesses.iter().any(|access| access.store))
            .map(|(block, _)| *block)
            .collect::<Vec<_>>();
        let merges = func
            .domtree()
            .iterated_frontier(&defined)
            .into_iter()
            .filter(|block| live_in.contains(block) && func.predecessors(*block).len() >= 2)
            .collect::<BTreeSet<_>>();
        let mut merge_dst = BTreeMap::new();
        for block in &merges {
            merge_dst.insert(*block, fresh(&mut minting));
        }
        let mut sources = BTreeMap::<u64, Vec<(u64, VarId)>>::new();
        // A walk of the dominator tree, each block entered with the version that reaches it.
        let mut stack = vec![(root, entry)];
        let mut seen = BTreeSet::new();
        while let Some((block, reaching)) = stack.pop() {
            if !seen.insert(block) {
                continue;
            }
            let mut current = merge_dst.get(&block).copied().unwrap_or(reaching);
            for access in by_block.get(&block).into_iter().flatten() {
                let Some(op) = func
                    .get_block(block)
                    .and_then(|b| b.ops().get(access.index))
                else {
                    continue;
                };
                match op {
                    SSAOp::Load { dst, .. } => plan.replace(
                        access.op,
                        SSAOp::Copy {
                            dst: *dst,
                            src: current,
                        },
                    ),
                    SSAOp::Store { val, .. } => {
                        let next = fresh(&mut minting);
                        plan.replace(
                            access.op,
                            SSAOp::Copy {
                                dst: next,
                                src: *val,
                            },
                        );
                        current = next;
                    }
                    _ => continue,
                }
                rewritten.insert(access.op);
            }
            for successor in func.successors(block) {
                if merges.contains(&successor) {
                    sources.entry(successor).or_default().push((block, current));
                }
            }
            for child in func.domtree().children(block).iter().rev() {
                stack.push((*child, current));
            }
        }
        for block in &merges {
            let arrived = sources.remove(block).unwrap_or_default();
            let phi_sources = func
                .predecessors(*block)
                .into_iter()
                .map(|pred| {
                    let var = arrived
                        .iter()
                        .find(|(from, _)| *from == pred)
                        .map_or(entry, |(_, var)| *var);
                    (pred, var)
                })
                .collect();
            plan.reshape(ShapeEdit::InsertPhi {
                block: *block,
                phi: PhiNode {
                    dst: merge_dst[block],
                    sources: phi_sources,
                    canonical_storage: Some(storage),
                },
            });
        }
    }
    plan.adopt(minting.finish());
    func.apply_edits(plan);
    rewritten
}

/// The blocks the slot is live into: read before written there, or live out with no write.
fn live_in(func: &SSAFunction, by_block: &BTreeMap<u64, Vec<&Access>>) -> BTreeSet<u64> {
    let reads_first = |block: u64| {
        by_block
            .get(&block)
            .and_then(|accesses| accesses.first())
            .is_some_and(|access| !access.store)
    };
    let writes = |block: u64| {
        by_block
            .get(&block)
            .is_some_and(|accesses| accesses.iter().any(|access| access.store))
    };
    let mut live = func
        .block_addrs()
        .iter()
        .copied()
        .filter(|block| reads_first(*block))
        .collect::<BTreeSet<_>>();
    let mut pending = live.iter().copied().collect::<Vec<_>>();
    // Backward: a predecessor that does not write the slot is live into as well; each block enters once.
    while let Some(block) = pending.pop() {
        for pred in func.predecessors(block) {
            if !writes(pred) && live.insert(pred) {
                pending.push(pred);
            }
        }
    }
    live
}

/// Whether a value is what a register held on entry, whole or as its low lane (`edi` of `rdi`).
fn entry_value(func: &SSAFunction, defs: &Definitions, var: VarId) -> bool {
    let var = defs.copied(var);
    match defs.op(var).map(|(_, op)| op) {
        Some(SSAOp::Subpiece { src, offset: 0, .. }) => func.var(defs.copied(*src)).version == 0,
        _ => func.var(var).version == 0 && func.var(var).constant_bits().is_none(),
    }
}

fn has_call(func: &SSAFunction) -> bool {
    func.blocks().iter().any(|block| {
        block
            .ops()
            .iter()
            .any(|op| matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. }))
    })
}
