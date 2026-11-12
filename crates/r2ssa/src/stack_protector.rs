//! The stack-protector check, decided under `Premise::UbFreeSource` (doc/adr-frame-model.md, P4.4).
//!
//! The guard is the memory the platform states it at (`r2abi::guard_row`): a word addressed from
//! the entry value of a register the platform reserves, or a global the container binds. A
//! check compares two reads of it, each direct or through a frame slot written once from one, and
//! a mismatch leaves for a block that only calls a function that does not return. A UB-free source
//! writes neither the guard nor outside its own objects, so both reads agree and the check passes.

use std::collections::{BTreeMap, BTreeSet};

use crate::arena::OpId;
use crate::cfg::BlockTerminator;
use crate::dense::{IdMap, IdSet};
use crate::frame_address::{Affine, Definitions};
use crate::function::{EditPlan, SSAFunction, ShapeEdit};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::VarId;

/// One recognised check: what decides it and which operations the compiler inserted for it.
struct Check {
    block: u64,
    branch: OpId,
    target: VarId,
    /// The edge a passing check takes, and whether it is the branch's own target.
    pass: u64,
    pass_is_target: bool,
    fail: u64,
    inserted: IdSet<OpId>,
    /// The guard read every other read of the check equals under the premise, and those rereads.
    first: VarId,
    rereads: IdMap<OpId, VarId>,
    /// The `reload - guard` (or `^`) the condition tests.
    difference: Option<VarId>,
}

/// Decide every stack-protector check the function holds; the operations each one inserted are
/// recorded on the function for the certificate that elides them.
pub(crate) fn decide(func: &mut SSAFunction, machine: &SourceMachineContext) {
    if !machine.accepts(r2source::Premise::UbFreeSource) {
        return;
    }
    // Only the word the platform states: a thread-local variable read twice is no guard.
    let Some(guard) = Guard::of(machine) else {
        return;
    };
    let defs = Definitions::of(func);
    if let Some(exhausted) = defs.exhausted() {
        func.note_exhausted(exhausted);
    }
    let slots = SlotStores::of(func, &defs);
    let checks = func
        .block_addrs()
        .iter()
        .filter_map(|addr| check(func, &defs, &slots, guard, *addr))
        .collect::<Vec<_>>();
    let mut checked = IdSet::default();
    checked.extend(checks.iter().flat_map(|check| check.inserted.iter()));
    let unchecked = unchecked(
        func,
        &defs,
        guard,
        machine.stack_pointer_carrier(),
        &checked,
    );
    if checks.is_empty() && unchecked.is_empty() {
        return;
    }
    let mut decided = EditPlan::new();
    let mut passing = Vec::new();
    let mut inserted = IdSet::default();
    let removed_edges = (checks.iter())
        .map(|check| (check.block, check.fail))
        .collect::<BTreeSet<_>>();
    for check in &checks {
        let op = if check.pass_is_target {
            SSAOp::Branch {
                target: check.target,
                instruction: None,
            }
        } else {
            SSAOp::Nop
        };
        decided.replace(check.branch, op);
        decided.reshape(ShapeEdit::RemoveEdge {
            from: check.block,
            to: check.fail,
        });
        decided.reshape(ShapeEdit::SetTerminator {
            block: check.block,
            terminator: BlockTerminator::Branch { target: check.pass },
        });
        decided.reshape(ShapeEdit::DropPhiSources {
            block: check.fail,
            pred: check.block,
        });
        inserted.extend(check.inserted.iter());
        // Under the premise every reread holds what the first read did, so `reload - guard` is zero.
        for (op, dst) in check.rereads.iter() {
            decided.replace(
                op,
                SSAOp::Copy {
                    dst: *dst,
                    src: check.first,
                },
            );
        }
        // Past the passing edge the difference is 0; read there only where that edge alone enters.
        if let Some(difference) = check.difference
            && func.predecessors(check.pass) == [check.block]
        {
            passing.push((difference, check.pass));
        }
    }
    inserted.extend(unchecked.iter());
    let words = guard_words(func, &defs, guard, &inserted);
    // The rereads become copies below; their addresses are still the compiler's.
    let reread_addresses = (checks.iter())
        .flat_map(|check| check.rereads.iter())
        .filter_map(|(_, dst)| match defs.op(*dst) {
            Some((_, SSAOp::Load { addr, .. })) => Some(*addr),
            _ => None,
        })
        .collect::<Vec<_>>();
    // A failure block no other edge reaches goes with the edges into it.
    let failed = checks
        .iter()
        .map(|check| check.fail)
        .collect::<BTreeSet<_>>();
    let deciding = checks
        .iter()
        .map(|check| check.block)
        .collect::<BTreeSet<_>>();
    let mut removed = BTreeMap::new();
    for fail in failed {
        if func
            .predecessors(fail)
            .iter()
            .all(|pred| deciding.contains(pred))
        {
            decided.reshape(ShapeEdit::RemoveBlock(fail));
            removed.insert(fail, func.get_block(fail).map_or(0, |block| block.size));
        }
    }
    decided.reorder();
    func.apply_edits(decided);
    let addresses = inserted_addresses(func, &inserted, &reread_addresses);
    inserted.extend(addresses.iter());
    // A word load is the compiler's once its readers are: the guard reads and their addresses.
    let words = unread_words(func, &inserted, &words);
    if !words.is_empty() {
        inserted.extend(words);
        let addresses = inserted_addresses(func, &inserted, &[]);
        inserted.extend(addresses.iter());
    }
    func.record_compiler_inserted(inserted, removed, removed_edges);
    func.record_passing_differences(passing);
    func.record_checked_differences(checks.iter().filter_map(|check| check.difference));
    // Every decided check removed its failure edge, which holds only of a UB-free source.
    func.record_premise(r2source::Premise::UbFreeSource);
}

/// gcc's prologue in a body that never returns: guard reads only unread frame slots hold, and those
/// stores (doc/adr-call-boundary.md, S11 as built). One other reader keeps them all. O(ops).
fn unchecked(
    func: &SSAFunction,
    defs: &Definitions,
    guard: Guard<'_>,
    stack_pointer: Option<crate::CanonicalStorageId>,
    checked: &IdSet<OpId>,
) -> IdSet<OpId> {
    // Only a body with no way out but a call that does not come back: one that returns checks.
    let leaves = (func.block_addrs().iter())
        .filter_map(|addr| func.cfg().get_block(*addr))
        .any(|block| {
            matches!(
                block.terminator,
                BlockTerminator::Return
                    | BlockTerminator::ConditionalExit { .. }
                    | BlockTerminator::IndirectBranch
                    | BlockTerminator::None
            )
        });
    let Some(stack_pointer) = stack_pointer.filter(|_| !leaves) else {
        return IdSet::default();
    };
    let mut read = IdMap::<VarId, Vec<(i64, i64)>>::new(func.values().len());
    let mut uses = Uses::new(func.values().len());
    let mut loads = Vec::new();
    // A merge is a reader the guard rule does not follow; the escape walk follows it.
    let mut merged = IdSet::new(func.values().len());
    let mut merges = IdMap::<VarId, Vec<VarId>>::new(func.values().len());
    let entry =
        |var: VarId| func.var(var).version == 0 && func.storage_of(var) == Some(stack_pointer);
    let mut frame = Vec::new();
    for block in (func.block_addrs().iter()).filter_map(|addr| func.get_block(*addr)) {
        for (_, phi) in block.sited_phis() {
            for (_, source) in &phi.sources {
                merged.insert(*source);
                merges.get_or_insert_with(*source, Vec::new).push(phi.dst);
            }
        }
        for (id, op) in block.sited() {
            op.for_each_source(|source| {
                uses.get_or_insert_with(*source, Vec::new).push((id, op));
                frame.extend(Some(*source).filter(|source| entry(*source)));
            });
            if let SSAOp::Load { dst, addr, .. } = op {
                let (root, offset) = defs.affine(func, *addr);
                let width = func.var(*dst).size;
                let read_of_guard = !checked.contains(id)
                    && guard.read(func, defs, (root, offset), width).is_some();
                loads.extend(read_of_guard.then_some((id, *dst)));
                read.get_or_insert_with(root, Vec::new)
                    .push((offset, offset + i64::from(width)));
            }
        }
    }
    let escaped = escapes(func, defs, entry, frame, (&uses, &merges));
    let unread_frame_slot = |addr: VarId, width: u32| {
        let (root, offset) = defs.affine(func, addr);
        let end = offset + i64::from(width);
        let reached = |at: &i64| offset <= *at && *at < end;
        entry(root)
            && !escaped.whole
            && !escaped.at.iter().any(reached)
            && (read.get(root).into_iter().flatten()).all(|(lo, hi)| *hi <= offset || end <= *lo)
    };
    let mut inserted = IdSet::default();
    for found in loads {
        let Some(taken) = guard_stores(func, found, (&uses, &merged), &unread_frame_slot) else {
            return IdSet::default();
        };
        inserted.extend(taken);
    }
    inserted
}

/// What one reader of the guard's value does with it.
enum GuardUse {
    /// A copy or a narrowing hands it on.
    Follow(VarId),
    /// `xor eax, eax` reads the guard's lane and computes 0 whatever it holds.
    Cancel,
    /// A store to a frame slot nothing reads.
    Store,
}

/// The guard read at `load` and the stores it reaches, or `None` where any other reader sees it.
fn guard_stores(
    func: &SSAFunction,
    (load, loaded): (OpId, VarId),
    (uses, merged): (&Uses<'_>, &IdSet<VarId>),
    unread_frame_slot: &impl Fn(VarId, u32) -> bool,
) -> Option<Vec<OpId>> {
    let (mut taken, mut work) = (vec![load], vec![loaded]);
    while let Some(var) = work.pop() {
        if merged.contains(var) {
            return None;
        }
        for (id, op) in uses.get(var).into_iter().flatten() {
            let size = func.var(var).size;
            let Some(step) = guard_use(op, var, |addr| unread_frame_slot(addr, size)) else {
                r2il::refusal_evidence!(
                    "unchecked-guard",
                    "{:#x}: guard read {load:?} reaches {op:?}, so no read is the prologue's",
                    func.entry
                );
                return None;
            };
            match step {
                GuardUse::Follow(dst) => work.push(dst),
                GuardUse::Cancel => {}
                GuardUse::Store => taken.push(*id),
            }
        }
    }
    Some(taken)
}

fn guard_use(
    op: &SSAOp<VarId>,
    var: VarId,
    unread_frame_slot: impl Fn(VarId) -> bool,
) -> Option<GuardUse> {
    match op {
        SSAOp::Copy { dst, .. } | SSAOp::Subpiece { dst, .. } => Some(GuardUse::Follow(*dst)),
        SSAOp::IntXor { a, b, .. } | SSAOp::IntSub { a, b, .. } if a == b => Some(GuardUse::Cancel),
        SSAOp::Store { addr, val, .. } if *val == var && unread_frame_slot(*addr) => {
            Some(GuardUse::Store)
        }
        _ => None,
    }
}

/// The frame addresses a body hands on: each one put anywhere but a load's or store's address, by
/// its entry offset, or `whole` where no offset places it (a callee may then read the slot).
struct Escapes {
    whole: bool,
    at: Vec<i64>,
}

/// Each variable's readers.
type Uses<'f> = IdMap<VarId, Vec<(OpId, &'f SSAOp<VarId>)>>;

/// One walk from the entry stack pointer through exact address arithmetic and merges. O(ops).
fn escapes(
    func: &SSAFunction,
    defs: &Definitions,
    entry: impl Fn(VarId) -> bool,
    frame: Vec<VarId>,
    (uses, merges): (&Uses<'_>, &IdMap<VarId, Vec<VarId>>),
) -> Escapes {
    let mut escaped = Escapes {
        whole: false,
        at: Vec::new(),
    };
    let exact = |var: VarId| {
        let (root, offset) = defs.affine(func, var);
        entry(root).then_some(offset)
    };
    let mut seen = IdSet::new(func.values().len());
    let mut work = frame;
    while let Some(var) = work.pop() {
        if !seen.insert(var) {
            continue;
        }
        let mut hand_on = || match exact(var) {
            Some(offset) => escaped.at.push(offset),
            None => escaped.whole = true,
        };
        for (_, op) in uses.get(var).into_iter().flatten() {
            match op {
                SSAOp::Load { addr, .. } if *addr == var => {}
                SSAOp::Store { addr, val, .. } if *addr == var && *val != var => {}
                SSAOp::Copy { dst, .. }
                | SSAOp::CallRestore { dst, .. }
                | SSAOp::IntAdd { dst, .. }
                | SSAOp::IntSub { dst, .. }
                    if exact(*dst).is_some() =>
                {
                    work.push(*dst);
                }
                _ => hand_on(),
            }
        }
        for dst in merges.get(var).into_iter().flatten() {
            match exact(*dst) {
                Some(_) => work.push(*dst),
                None => hand_on(),
            }
        }
    }
    escaped
}

/// The temporary address arithmetic only inserted operations read, from their loads and `from`
/// (the addresses of rewritten reads). One pass counts reads; each operation is taken once.
pub(crate) fn inserted_addresses(
    func: &SSAFunction,
    inserted: &IdSet<OpId>,
    from: &[VarId],
) -> IdSet<OpId> {
    let values = func.values().len();
    let mut reads = IdMap::<VarId, usize>::new(values);
    let mut arithmetic = IdMap::<VarId, (OpId, Vec<VarId>)>::new(values);
    let mut work = from.to_vec();
    for block in (func.block_addrs().iter()).filter_map(|addr| func.get_block(*addr)) {
        for (_, phi) in block.sited_phis() {
            for (_, source) in &phi.sources {
                *reads.get_or_insert_with(*source, || 0) += 1;
            }
        }
        for (id, op) in block.sited() {
            match op {
                SSAOp::Load { addr, .. } if inserted.contains(id) => work.push(*addr),
                _ if inserted.contains(id) => {}
                _ => op.for_each_source(|source| *reads.get_or_insert_with(*source, || 0) += 1),
            }
            if let SSAOp::IntAdd { dst, .. } | SSAOp::IntSub { dst, .. } | SSAOp::Copy { dst, .. } =
                op
                && func.var(*dst).is_temp()
            {
                arithmetic.insert(*dst, (id, op.sources().into_iter().copied().collect()));
            }
        }
    }
    let mut taken = IdSet::new(func.id_limit());
    while let Some(var) = work.pop() {
        match arithmetic.get(var) {
            Some((id, sources))
                if reads.get(var).is_none_or(|n| *n == 0)
                    && !inserted.contains(*id)
                    && taken.insert(*id) =>
            {
                work.extend(sources.iter().copied());
            }
            _ => {}
        }
    }
    taken
}

/// Every store whose address is a root plus a constant, by root; written once, by the walk below.
pub(crate) struct SlotStores {
    by_root: IdMap<VarId, Vec<(i64, i64, OpId, VarId)>>,
}

impl SlotStores {
    pub(crate) fn of(func: &SSAFunction, defs: &Definitions) -> Self {
        let mut by_root = IdMap::<VarId, Vec<_>>::new(func.values().len());
        for block in func
            .block_addrs()
            .iter()
            .filter_map(|addr| func.get_block(*addr))
        {
            for (id, op) in block.sited() {
                if let SSAOp::Store { addr, val, .. } = op {
                    let (root, offset) = defs.affine(func, *addr);
                    let width = i64::from(func.var(*val).size);
                    by_root
                        .get_or_insert_with(root, Vec::new)
                        .push((offset, width, id, *val));
                }
            }
        }
        Self { by_root }
    }

    /// The one store that writes any byte of `[offset, offset + width)` from `root`, if exactly one does.
    pub(crate) fn sole_writer(&self, (root, offset): Affine, width: u32) -> Option<(OpId, VarId)> {
        let end = offset + i64::from(width);
        let mut writers = self
            .by_root
            .get(root)?
            .iter()
            .filter(|(start, size, ..)| *start < end && offset < start + size);
        let (start, size, id, val) = writers.next()?;
        (writers.next().is_none() && (*start, *size) == (offset, i64::from(width)))
            .then_some((*id, *val))
    }
}

/// One side of a check: the first read of the guard, the operations it took, and the rereads the
/// premise equates with the first read.
struct GuardRead {
    first: (OpId, VarId),
    ops: Vec<OpId>,
    rereads: Vec<(OpId, VarId)>,
}

fn guard_read(
    func: &SSAFunction,
    defs: &Definitions,
    slots: &SlotStores,
    guard: Guard<'_>,
    var: VarId,
) -> Option<GuardRead> {
    let (load, address, width) = defs.load(func, var)?;
    let loaded = defs.op(defs.copied(var))?.1.dst().copied()?;
    if guard.read(func, defs, address, width).is_some() {
        return Some(GuardRead {
            first: (load, loaded),
            ops: vec![load],
            rereads: Vec::new(),
        });
    }
    // A reload of a frame slot whose only writer, run before it, stored a direct read of the guard.
    let (store, stored) = slots.sole_writer(address, width)?;
    let (guard_load, stored_address, stored_width) = defs.load(func, stored)?;
    let direct = guard
        .read(func, defs, stored_address, stored_width)
        .is_some();
    if !direct || !defs.precedes(func, store, load) {
        return None;
    }
    let first = defs.op(defs.copied(stored))?.1.dst().copied()?;
    Some(GuardRead {
        first: (guard_load, first),
        ops: vec![load, store, guard_load],
        rereads: vec![(load, loaded)],
    })
}

/// The one guard a function's checks read: the platform's slot, or the global the container binds.
#[derive(Clone, Copy)]
enum Guard<'m> {
    Slot(&'m r2source::SourceStackGuard),
    Linked(&'m r2source::SourceLinkedGuard),
}

/// A read of the guard: direct, or through the load of a sealed word holding its address.
type Through = Option<OpId>;

impl<'m> Guard<'m> {
    fn of(machine: &'m SourceMachineContext) -> Option<Self> {
        if let Some(slot) =
            (machine.call_effect()).and_then(r2source::SourceCallEffect::stack_guard)
        {
            return Some(Self::Slot(slot));
        }
        let linked = machine.convention()?.forms.linked_guard.as_ref()?;
        Some(Self::Linked(linked))
    }

    /// Whether a read of `width` bytes at `address` reads the guard, and how. Every load of one
    /// sealed word holds one address, so two loads of it reach one guard.
    fn read(
        self,
        func: &SSAFunction,
        defs: &Definitions,
        (root, offset): Affine,
        width: u32,
    ) -> Option<Through> {
        match self {
            Self::Slot(guard) => (func.var(root).version == 0
                && func.storage_of(root) == Some(guard.base)
                && u64::try_from(offset).ok() == Some(guard.offset)
                && width == guard.width)
                .then_some(None),
            Self::Linked(guard) if width != guard.width => None,
            Self::Linked(guard) => {
                if guard.copy.is_some() && defs.absolute(func, (root, offset)) == guard.copy {
                    return Some(None);
                }
                let (word, slot, slot_width) = defs.load(func, root)?;
                let slot = defs.absolute(func, slot)?;
                (offset == 0
                    && slot_width == guard.slot_width
                    && guard.slots.binary_search(&slot).is_ok())
                .then_some(Some(word))
            }
        }
    }
}

/// The sealed-word loads the guard's inserted reads went through. O(ops).
fn guard_words(
    func: &SSAFunction,
    defs: &Definitions,
    guard: Guard<'_>,
    inserted: &IdSet<OpId>,
) -> Vec<OpId> {
    if matches!(guard, Guard::Slot(_)) {
        return Vec::new();
    }
    let mut words = (func.block_addrs().iter())
        .filter_map(|addr| func.get_block(*addr))
        .flat_map(|block| block.sited())
        .filter(|(id, _)| inserted.contains(*id))
        .filter_map(|(_, op)| match op {
            SSAOp::Load { dst, addr, .. } => {
                let address = defs.affine(func, *addr);
                guard.read(func, defs, address, func.var(*dst).size)?
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    words.sort_unstable();
    words.dedup();
    words
}

/// The word loads whose value only inserted operations read: the compiler's own address of the
/// guard. A word another reader sees stays. O(ops).
fn unread_words(func: &SSAFunction, inserted: &IdSet<OpId>, words: &[OpId]) -> Vec<OpId> {
    if words.is_empty() {
        return Vec::new();
    }
    let mut read = IdSet::new(func.values().len());
    let mut loaded = Vec::new();
    let blocks = || (func.block_addrs().iter()).filter_map(|addr| func.get_block(*addr));
    for (_, phi) in blocks().flat_map(|block| block.sited_phis()) {
        read.extend(phi.sources.iter().map(|(_, source)| *source));
    }
    for (id, op) in blocks().flat_map(|block| block.sited()) {
        if words.binary_search(&id).is_ok() {
            loaded.extend(op.dst().map(|dst| (id, *dst)));
        }
        if !inserted.contains(id) {
            op.for_each_source(|source| {
                read.insert(*source);
            });
        }
    }
    (loaded.into_iter())
        .filter(|(_, dst)| !read.contains(*dst))
        .map(|(id, _)| id)
        .collect()
}

/// The check that ends one block, when it compares two reads of one guard.
fn check(
    func: &SSAFunction,
    defs: &Definitions,
    slots: &SlotStores,
    guard: Guard<'_>,
    addr: u64,
) -> Option<Check> {
    let BlockTerminator::ConditionalBranch {
        true_target,
        false_target,
    } = func.cfg().get_block(addr)?.terminator
    else {
        return None;
    };
    let block = func.get_block(addr)?;
    let (branch, target, cond) = block.sited().rev().find_map(|(id, op)| match op {
        SSAOp::CBranch { target, cond } => Some((id, *target, *cond)),
        _ => None,
    })?;
    let (left, right, equal_when_true, difference) = equality(func, defs, cond)?;
    let left = guard_read(func, defs, slots, guard, left)?;
    let right = guard_read(func, defs, slots, guard, right)?;
    let (pass, fail) = if equal_when_true {
        (true_target, false_target)
    } else {
        (false_target, true_target)
    };
    if !fails_without_return(func, fail) {
        return None;
    }
    // The first read of the two runs before the other; the other and every reread equal it.
    let (first, second) = if defs.precedes(func, left.first.0, right.first.0) {
        (left.first, right.first)
    } else if defs.precedes(func, right.first.0, left.first.0) {
        (right.first, left.first)
    } else if left.first == right.first {
        (left.first, right.first)
    } else {
        return None;
    };
    let mut rereads = IdMap::default();
    rereads.extend(left.rereads.iter().chain(&right.rereads).copied());
    if second != first {
        rereads.insert(second.0, second.1);
    }
    // Every other read of the guard in the checking block is the check's: a compare may read it once per flag.
    rereads.extend(block.sited().filter_map(|(id, op)| {
        match op {
            SSAOp::Load { dst, addr, .. }
                if id != first.0
                    && (guard.read(func, defs, defs.affine(func, *addr), func.var(*dst).size))
                        .is_some() =>
            {
                Some((id, *dst))
            }
            _ => None,
        }
    }));
    if !rereads
        .iter()
        .all(|(op, _)| defs.precedes(func, first.0, op))
    {
        return None;
    }
    let mut inserted = left
        .ops
        .iter()
        .chain(&right.ops)
        .copied()
        .collect::<IdSet<_>>();
    inserted.extend(rereads.iter().map(|(op, _)| op));
    Some(Check {
        block: addr,
        branch,
        target,
        pass,
        pass_is_target: pass == true_target,
        fail,
        inserted,
        first: first.1,
        rereads,
        difference,
    })
}

/// A condition that is true exactly when two values are equal (or exactly when they differ), the
/// two values, and the difference the condition tests where it tests one.
pub(crate) fn equality(
    func: &SSAFunction,
    defs: &Definitions,
    cond: VarId,
) -> Option<(VarId, VarId, bool, Option<VarId>)> {
    let zero = |var: VarId| func.var(var).constant_bits() == Some(0);
    let (left, right, equal) = match &defs.op(defs.copied(cond))?.1 {
        SSAOp::IntEqual { a, b, .. } => (*a, *b, true),
        SSAOp::IntNotEqual { a, b, .. } => (*a, *b, false),
        SSAOp::BoolNot { src, .. } => {
            let (left, right, equal, difference) = equality(func, defs, *src)?;
            return Some((left, right, !equal, difference));
        }
        _ => return None,
    };
    // `a - b == 0` and `a ^ b == 0` hold exactly when `a == b`.
    let difference = if zero(right) {
        Some(left)
    } else if zero(left) {
        Some(right)
    } else {
        None
    };
    if let Some(difference) = difference
        && let Some((_, SSAOp::IntSub { dst, a, b } | SSAOp::IntXor { dst, a, b })) =
            defs.op(defs.copied(difference))
    {
        return Some((*a, *b, equal, Some(*dst)));
    }
    Some((left, right, equal, None))
}

/// Whether the block ends in a call that does not come back, by the CFG terminator.
fn fails_without_return(func: &SSAFunction, block: u64) -> bool {
    matches!(
        func.cfg().get_block(block).map(|block| &block.terminator),
        Some(
            BlockTerminator::Call {
                fallthrough: None,
                ..
            } | BlockTerminator::IndirectCall { fallthrough: None }
        )
    )
}
