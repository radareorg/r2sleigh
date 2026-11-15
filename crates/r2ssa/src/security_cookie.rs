//! The `/GS` check, decided under `Premise::UbFreeSource`: a UB-free source writes neither the
//! saved `[cookie] ^ sp` nor the cookie (doc/adr-call-boundary.md, "S17 as built").

use std::collections::BTreeSet;

use crate::arena::OpId;
use crate::cfg::BlockTerminator;
use crate::dense::{IdMap, IdSet};
use crate::frame_address::{Affine, Definitions};
use crate::function::SSAFunction;
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::stack_protector::{SlotStores, equality};
use crate::value_table::VarId;
use r2source::convention::SlotClass;

/// Whether `func` is a `/GS` check, as the ADR's "S17 as built" states the proof. O(blocks + ops),
/// and only a body loading the cookie's address builds its definitions.
pub(crate) fn proves_check(func: &SSAFunction, machine: &SourceMachineContext) -> bool {
    let Some((cookie, argument)) = cookie_and_argument(machine) else {
        return false;
    };
    // Only a body that loads the cookie's own address pays for the definitions below.
    let loads_cookie = (func.block_addrs().iter())
        .filter_map(|addr| func.get_block(*addr))
        .flat_map(|block| block.sited())
        .any(|(_, op)| {
            matches!(op, SSAOp::Load { addr, .. }
                if func.var(*addr).constant_bits() == Some(cookie.address))
        });
    if !loads_cookie {
        return false;
    }
    let defs = Definitions::of(func);
    let entry_argument = |var: VarId| {
        let var = defs.copied(var);
        func.var(var).version == 0 && func.storage_of(var) == Some(argument)
    };
    let reads_cookie = |var: VarId| {
        defs.load(func, var).is_some_and(|(_, address, width)| {
            defs.absolute(func, address) == Some(cookie.address) && width == cookie.width
        })
    };
    let checks = (func.block_addrs().iter().copied())
        .filter_map(|addr| comparison(func, &defs, addr))
        .filter(|(_, (left, right))| {
            (entry_argument(*left) && reads_cookie(*right))
                || (entry_argument(*right) && reads_cookie(*left))
        })
        .collect::<Vec<_>>();
    let [(check, _)] = checks.as_slice() else {
        return false;
    };
    let Check {
        block, pass, fail, ..
    } = *check;
    let failing = reachable(func, fail);
    if failing.contains(&pass) || !failing.iter().all(|addr| halts_or_continues(func, *addr)) {
        return false;
    }
    let returns = (func.block_addrs().iter().copied())
        .filter(|addr| leaves(func, *addr))
        .collect::<Vec<_>>();
    if returns.is_empty() || !returns.iter().all(|addr| func.dominates(block, *addr)) {
        return false;
    }
    // Whether it returns turns on the argument and the cookie alone: no other input decides it.
    let decided_by_argument = |var: VarId| {
        let leaf = |var: VarId| {
            entry_argument(var) || reads_cookie(var) || func.var(var).constant_bits().is_some()
        };
        derived_only_from(&defs, var, leaf)
    };
    returning_blocks(func, returns).iter().all(|addr| {
        let Some(found) = func.get_block(*addr) else {
            return false;
        };
        let condition = found.sited().find_map(|(_, op)| match op {
            SSAOp::CBranch { cond, .. } => Some(*cond),
            _ => None,
        });
        found.sited().all(|(_, op)| inert(op))
            && (*addr == block || condition.is_none_or(decided_by_argument))
    })
}

/// Whether `var` is computed by register operations from values `leaf` accepts, merging none.
/// Bounded: a computation of more than 64 operations is refused.
fn derived_only_from(defs: &Definitions, var: VarId, leaf: impl Fn(VarId) -> bool) -> bool {
    const BUDGET: usize = 64;
    let mut work = vec![var];
    let mut walked = 0;
    while let Some(var) = work.pop() {
        walked += 1;
        if walked > BUDGET || !defs.phi_sources(var).is_empty() {
            return false;
        }
        if leaf(var) {
            continue;
        }
        match defs.op(var) {
            Some((_, op)) if inert(op) && !matches!(op, SSAOp::Load { .. }) => {
                work.extend(op.sources().into_iter().copied());
            }
            _ => return false,
        }
    }
    true
}

/// The cookie the convention model's forms name, and the register its check takes (D230).
fn cookie_and_argument(
    machine: &SourceMachineContext,
) -> Option<(r2source::SourceSecurityCookie, r2source::CanonicalStorageId)> {
    let cookie = machine.convention()?.forms.security_cookie?;
    Some((cookie, cookie.argument))
}

/// The check one block ends in: the branch's two targets, by whether the values are equal.
#[derive(Clone, Copy)]
struct Check {
    block: u64,
    pass: u64,
    fail: u64,
}

/// The block's conditional branch and the two values it tests for equality.
fn comparison(
    func: &SSAFunction,
    defs: &Definitions,
    addr: u64,
) -> Option<(Check, (VarId, VarId))> {
    let BlockTerminator::ConditionalBranch {
        true_target,
        false_target,
    } = func.cfg().get_block(addr)?.terminator
    else {
        return None;
    };
    let cond = func
        .get_block(addr)?
        .sited()
        .rev()
        .find_map(|(_, op)| match op {
            SSAOp::CBranch { cond, .. } => Some(*cond),
            _ => None,
        })?;
    let (left, right, equal_when_true, _) = equality(func, defs, cond)?;
    let (pass, fail) = match equal_when_true {
        true => (true_target, false_target),
        false => (false_target, true_target),
    };
    Some((
        Check {
            block: addr,
            pass,
            fail,
        },
        (left, right),
    ))
}

/// Every block reached from `from`, itself included. O(blocks + edges).
fn reachable(func: &SSAFunction, from: u64) -> BTreeSet<u64> {
    let (mut seen, mut work) = (BTreeSet::new(), vec![from]);
    while let Some(addr) = work.pop() {
        if seen.insert(addr) {
            work.extend(func.successors(addr));
        }
    }
    seen
}

/// Every block a return is reached from. O(blocks + edges).
fn returning_blocks(func: &SSAFunction, mut work: Vec<u64>) -> BTreeSet<u64> {
    let mut seen = BTreeSet::new();
    while let Some(addr) = work.pop() {
        if seen.insert(addr) {
            work.extend(func.predecessors(addr));
        }
    }
    seen
}

/// Whether control can leave the function from this block back to a caller or somewhere unread.
fn leaves(func: &SSAFunction, addr: u64) -> bool {
    matches!(
        func.cfg().get_block(addr).map(|block| &block.terminator),
        Some(
            BlockTerminator::Return
                | BlockTerminator::ConditionalExit { .. }
                | BlockTerminator::IndirectBranch
                | BlockTerminator::None
        ) | None
    )
}

/// A failing block either goes on within the function or ends at a call that does not return.
fn halts_or_continues(func: &SSAFunction, addr: u64) -> bool {
    !leaves(func, addr) && (!func.successors(addr).is_empty() || ends_without_return(func, addr))
}

fn ends_without_return(func: &SSAFunction, addr: u64) -> bool {
    matches!(
        func.cfg().get_block(addr).map(|block| &block.terminator),
        Some(
            BlockTerminator::Call {
                fallthrough: None,
                ..
            } | BlockTerminator::IndirectCall { fallthrough: None }
        )
    )
}

/// An operation with no effect but on registers: no store, call, user operation or unknown.
fn inert(op: &SSAOp<VarId>) -> bool {
    !(op.is_call()
        || matches!(
            op,
            SSAOp::Store { .. }
                | SSAOp::StoreGuarded { .. }
                | SSAOp::StoreConditional { .. }
                | SSAOp::CallOther { .. }
                | SSAOp::Unimplemented
        )
        || op.transfer().is_some_and(|transfer| !transfer.direct))
}

/// Record compiler-inserted each call to a proven check handed the prologue's saved
/// `[cookie] ^ sp`, xored again with the same `sp`, and what computed it. O(ops).
pub(crate) fn decide(
    func: &mut SSAFunction,
    machine: &SourceMachineContext,
    checks: &BTreeSet<u64>,
) {
    if checks.is_empty() || !machine.accepts(r2source::Premise::UbFreeSource) {
        return;
    }
    let (Some((cookie, argument)), Some(stack_pointer), Some(model)) = (
        cookie_and_argument(machine),
        machine.stack_pointer_carrier(),
        machine.convention(),
    ) else {
        return;
    };
    let calls = check_calls(func, checks, argument);
    if calls.is_empty() {
        return;
    }
    let defs = Definitions::of(func);
    let slots = SlotStores::of(func, &defs);
    let readers = Readers::of(func);
    let context = Context {
        func,
        defs: &defs,
        slots: &slots,
        readers: &readers,
        loads: frame_loads(func, &defs),
        cookie,
        stack_pointer,
        results: (model.result_registers(SlotClass::Integer))
            .chain(model.result_registers(SlotClass::Float))
            .collect(),
    };
    let mut inserted = IdSet::default();
    for (call, handed) in calls {
        match context.elided(call, handed) {
            Ok(ops) => inserted.extend(ops),
            Err(why) => r2il::refusal_evidence!(
                "security-cookie",
                "{:#x}: the call {call:?} to a proven check stays: {why}",
                func.entry
            ),
        }
    }
    if inserted.is_empty() {
        return;
    }
    let addresses = crate::stack_protector::inserted_addresses(func, &inserted, &[]);
    inserted.extend(addresses.iter());
    func.record_compiler_inserted(inserted, Default::default(), Default::default());
    func.record_premise(r2source::Premise::UbFreeSource);
}

/// Each direct call to a proven check, and the value its cited register hands it: the boundary's
/// read, else the register's last whole definition in the block (i386's `ecx`, no cdecl argument).
fn check_calls(
    func: &SSAFunction,
    checks: &BTreeSet<u64>,
    argument: r2source::CanonicalStorageId,
) -> Vec<(OpId, VarId)> {
    let mut calls = Vec::new();
    for block in (func.block_addrs().iter()).filter_map(|addr| func.get_block(*addr)) {
        let mut handed = None;
        for (id, op) in block.sited() {
            if let SSAOp::CallUse { src, storage } = op
                && *storage == argument
            {
                handed = Some(*src);
                continue;
            }
            // A write of part of the register leaves no whole value handed.
            if let Some(written) = op.dst().and_then(|dst| func.storage_of(*dst))
                && overlaps(written, argument)
            {
                handed = (written == argument).then(|| op.dst().copied()).flatten();
            }
            let Some(call) = op.call() else {
                continue;
            };
            // A direct call names its callee as the RAM address it transfers to.
            let callee = (func.storage_of(*call.target))
                .filter(|storage| call.direct && storage.space == crate::CanonicalStorageSpace::Ram)
                .map(|storage| storage.offset);
            if let (Some(callee), Some(handed)) = (callee, handed.take())
                && checks.contains(&callee)
            {
                calls.push((id, handed));
            }
        }
    }
    calls
}

/// Every load by the root of its address, written once. O(ops).
fn frame_loads(func: &SSAFunction, defs: &Definitions) -> IdMap<VarId, Vec<(i64, i64, OpId)>> {
    let mut loads = IdMap::<VarId, Vec<_>>::new(func.values().len());
    let ops = (func.block_addrs().iter())
        .filter_map(|addr| func.get_block(*addr))
        .flat_map(|block| block.sited());
    for (id, op) in ops {
        if let SSAOp::Load { dst, addr, .. } = op {
            let (root, at) = defs.affine(func, *addr);
            let size = i64::from(func.var(*dst).size);
            loads
                .get_or_insert_with(root, Vec::new)
                .push((at, size, id));
        }
    }
    loads
}

/// What an operation does with a value it reads, for a walk asking whether nothing keeps it.
enum Read {
    /// `xor eax, eax`: it reads the lane and computes 0 whatever it holds.
    Cancels,
    /// A register operation: its result is read in turn.
    Into(Option<VarId>),
    /// An effect, a branch or a return keeps the value.
    Kept,
}

fn reads(op: &SSAOp<VarId>) -> Read {
    match op {
        SSAOp::IntXor { a, b, .. } | SSAOp::IntSub { a, b, .. } if a == b => Read::Cancels,
        SSAOp::CBranch { .. } | SSAOp::Return { .. } => Read::Kept,
        _ if inert(op) => Read::Into(op.dst().copied()),
        _ => Read::Kept,
    }
}

fn overlaps(a: r2source::CanonicalStorageId, b: r2source::CanonicalStorageId) -> bool {
    a.space == b.space
        && a.offset < b.offset + u64::from(b.size)
        && b.offset < a.offset + u64::from(a.size)
}

/// Each variable's readers and each operation by id, written once. O(ops).
struct Readers<'f> {
    readers: IdMap<VarId, Vec<OpId>>,
    /// The values a merge reads, which no elision follows.
    merged: IdSet<VarId>,
    ops: IdMap<OpId, &'f SSAOp<VarId>>,
}

impl<'f> Readers<'f> {
    fn of(func: &'f SSAFunction) -> Self {
        let mut readers = IdMap::<VarId, Vec<OpId>>::new(func.values().len());
        let mut merged = IdSet::new(func.values().len());
        let mut ops = IdMap::new(func.id_limit());
        let blocks = || (func.block_addrs().iter()).filter_map(|addr| func.get_block(*addr));
        let phis = blocks().flat_map(|block| block.sited_phis().map(|(_, phi)| phi));
        merged.extend(phis.flat_map(|phi| phi.sources.iter().map(|(_, source)| *source)));
        for (id, op) in blocks().flat_map(|block| block.sited()) {
            ops.insert(id, op);
            let sources = op.sources().into_iter().copied();
            sources.for_each(|source| readers.get_or_insert_with(source, Vec::new).push(id));
        }
        Self {
            readers,
            merged,
            ops,
        }
    }

    fn of_var(&self, var: VarId) -> &[OpId] {
        self.readers.get(var).map_or(&[], Vec::as_slice)
    }

    fn op(&self, id: OpId) -> Option<&'f SSAOp<VarId>> {
        self.ops.get(id).copied()
    }
}

struct Context<'f> {
    func: &'f SSAFunction,
    defs: &'f Definitions,
    slots: &'f SlotStores,
    readers: &'f Readers<'f>,
    /// Every load whose address is a root plus a constant, by root: `(offset, size, op)`.
    loads: IdMap<VarId, Vec<(i64, i64, OpId)>>,
    cookie: r2source::SourceSecurityCookie,
    stack_pointer: r2source::CanonicalStorageId,
    /// The convention's result carriers, which a return reads with no operation naming them.
    results: Vec<r2source::CanonicalStorageId>,
}

impl Context<'_> {
    /// The operations a check call and the save it reads inserted, or the step that is unproven.
    fn elided(&self, call: OpId, handed: VarId) -> Result<Vec<OpId>, &'static str> {
        let Context { func, defs, .. } = *self;
        // The handed value: `saved ^ sp`.
        let (reload_xor, saved, sp) = self
            .xor_with_stack_pointer(handed)
            .ok_or("the argument is no xor with the stack pointer")?;
        // `saved` is the prologue's `[cookie] ^ sp'` itself (a promoted slot) or a reload of a
        // slot whose one writer stored it.
        let (save_xor, value, sp_saved, reload) = match self.xor_with_stack_pointer(saved) {
            Some((xor, value, sp)) => (xor, value, sp, None),
            None => {
                let (load, address, width) = defs
                    .load(func, saved)
                    .ok_or("the saved word is no frame reload")?;
                let (store, stored) =
                    (self.slots.sole_writer(address, width)).ok_or("the slot has no one writer")?;
                if !defs.precedes(func, store, load) {
                    return Err("the save does not run before the reload");
                }
                if self.slot_read_elsewhere(address, width, load) {
                    return Err("another load reads the slot");
                }
                let (xor, value, sp) = (self.xor_with_stack_pointer(stored))
                    .ok_or("the stored word is no xor with the stack pointer")?;
                (xor, value, sp, Some((load, store)))
            }
        };
        let cookie_load = self.cookie_read(value).ok_or("the save reads no cookie")?;
        if defs.affine(func, sp) != defs.affine(func, sp_saved) || !self.entry_rooted(sp) {
            return Err("the save and the check xor different stack pointers");
        }
        let instruction = func
            .instruction_of(call)
            .ok_or("the call has no instruction")?;
        let mut ops = vec![reload_xor, save_xor, cookie_load];
        ops.extend(reload.into_iter().flat_map(|(load, store)| [load, store]));
        // The call instruction's own operations; what the boundary leaves standing renders as usual.
        let block = (defs.position(call))
            .and_then(|(addr, _)| func.get_block(addr))
            .ok_or("the call has no block")?;
        ops.extend(
            block
                .sited()
                .filter(|(id, op)| {
                    func.instruction_of(*id) == Some(instruction)
                        && !matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. })
                })
                .map(|(id, _)| id),
        );
        // A register the check clobbers that something reads would read nothing once the call goes.
        let clobber_read = block.sited().any(|(id, op)| {
            func.instruction_of(id) == Some(instruction)
                && matches!(op, SSAOp::CallDefine { dst }
                    if !self.readers.of_var(*dst).is_empty() || self.readers.merged.contains(*dst))
        });
        if clobber_read {
            return Err("a register the check clobbers is read after it");
        }
        let mut sinks = IdSet::new(func.id_limit());
        sinks.extend(ops.iter().copied());
        // What the inserted values reach: only each other, flags nothing reads, or lanes no one reads.
        let roots = ops
            .iter()
            .map(|op| self.readers.op(*op).map(|op| op.dst().copied()));
        let roots = roots
            .collect::<Option<Vec<_>>>()
            .ok_or("an operation is not indexed")?;
        let (dead, carried) = (self.computed_bytes(roots.into_iter().flatten(), &sinks))
            .ok_or("a value the check computes has another reader")?;
        ops.extend(dead);
        // A return reads its result carrier implicitly: a save left there is the function's result.
        if ops
            .iter()
            .chain(&carried)
            .any(|op| self.reaches_return(*op))
        {
            return Err("a value the check's save computes reaches a return in a result carrier");
        }
        Ok(ops)
    }

    /// Whether `op` writes a result carrier that a return reads before any other write to it.
    /// A restore puts back the same value, so it writes nothing. O(blocks + ops).
    fn reaches_return(&self, op: OpId) -> bool {
        let Context { func, defs, .. } = *self;
        let Some(storage) = (self.readers.op(op))
            .and_then(|op| op.dst())
            .and_then(|dst| func.storage_of(*dst))
            .filter(|storage| {
                self.results
                    .iter()
                    .any(|result| overlaps(*result, *storage))
            })
        else {
            return false;
        };
        let Some((block, index)) = defs.position(op) else {
            return true;
        };
        let kills = |op: &SSAOp<VarId>| {
            !matches!(op, SSAOp::CallRestore { .. })
                && (op.dst().and_then(|dst| func.storage_of(*dst)))
                    .is_some_and(|written| overlaps(written, storage))
        };
        let (mut seen, mut work) = (BTreeSet::new(), vec![(block, index + 1)]);
        while let Some((addr, from)) = work.pop() {
            let Some(ops) = func.get_block(addr) else {
                continue;
            };
            if ops.sited().skip(from).any(|(_, op)| kills(op)) {
                continue;
            }
            if leaves(func, addr) {
                return true;
            }
            let unseen = func
                .successors(addr)
                .into_iter()
                .filter(|next| seen.insert(*next));
            work.extend(unseen.map(|next| (next, 0)));
        }
        false
    }

    /// `var` as `value ^ sp`: the xor, the other operand, and the stack pointer operand.
    fn xor_with_stack_pointer(&self, var: VarId) -> Option<(OpId, VarId, VarId)> {
        let (id, op) = self.defs.op(self.defs.copied(var))?;
        let SSAOp::IntXor { a, b, .. } = op else {
            return None;
        };
        match (self.entry_rooted(*a), self.entry_rooted(*b)) {
            (true, false) => Some((*id, *b, *a)),
            (false, true) => Some((*id, *a, *b)),
            _ => None,
        }
    }

    /// Whether `var` is the entry stack pointer plus a constant.
    fn entry_rooted(&self, var: VarId) -> bool {
        let (root, _) = self.defs.affine(self.func, var);
        self.func.var(root).version == 0 && self.func.storage_of(root) == Some(self.stack_pointer)
    }

    /// The read of the cookie `var` is, through copies.
    fn cookie_read(&self, var: VarId) -> Option<OpId> {
        let (load, address, width) = self.defs.load(self.func, var)?;
        (self.defs.absolute(self.func, address) == Some(self.cookie.address)
            && width == self.cookie.width)
            .then_some(load)
    }

    /// Whether a load other than `reload` reads a byte of the slot.
    fn slot_read_elsewhere(&self, (root, offset): Affine, width: u32, reload: OpId) -> bool {
        let end = offset + i64::from(width);
        (self.loads.get(root).into_iter().flatten())
            .any(|(at, size, id)| *id != reload && *at < end && offset < at + size)
    }

    /// The operations `roots`' bytes reach whose results nothing else reads, and those still holding
    /// some; `None` where a byte reaches another reader (D230). Walked per byte gained, `BUDGET` ops.
    fn computed_bytes(
        &self,
        roots: impl IntoIterator<Item = VarId>,
        sinks: &IdSet<OpId>,
    ) -> Option<(Vec<OpId>, Vec<OpId>)> {
        const BUDGET: usize = 64;
        let func = self.func;
        let mut held = IdMap::<VarId, u64>::new(func.values().len());
        let mut work = Vec::new();
        for root in roots {
            let all = all_bytes(func.var(root).size);
            held.insert(root, all);
            work.push((root, all));
        }
        let mut walked = Vec::new();
        while let Some((var, bytes)) = work.pop() {
            if self.readers.merged.contains(var) {
                return None;
            }
            let readers =
                (self.readers.of_var(var).iter()).filter(|reader| !sinks.contains(**reader));
            for reader in readers {
                let into = self.byte_step(*reader, var, bytes, &mut walked)?;
                (walked.len() <= BUDGET).then_some(())?;
                let gained = into.filter(|(dst, kept)| {
                    let had = held.get(*dst).copied().unwrap_or(0);
                    held.insert(*dst, had | kept);
                    had | kept != had
                });
                work.extend(gained);
            }
        }
        // Dead: every reader of the result is a sink or dead; the rest still carry a byte. Each
        // round drops one operation or more, so at most `BUDGET` rounds.
        let live = |op: OpId, dead: &[OpId]| {
            let dst = self.readers.op(op).and_then(|op| op.dst().copied());
            dst.is_some_and(|dst| {
                self.readers.merged.contains(dst)
                    || (self.readers.of_var(dst).iter())
                        .any(|reader| !sinks.contains(*reader) && !dead.contains(reader))
            })
        };
        let mut dead = walked.clone();
        loop {
            let next = (dead.iter().copied())
                .filter(|op| !live(*op, &dead))
                .collect::<Vec<_>>();
            if next.len() == dead.len() {
                break;
            }
            dead = next;
        }
        let carried = (walked.into_iter())
            .filter(|op| !dead.contains(op))
            .collect();
        Some((dead, carried))
    }
}

impl Context<'_> {
    /// One reader of `bytes` of `var`, recorded in `walked`: `None` where it keeps them, else the
    /// result and the bytes it holds, where it has a result holding any.
    fn byte_step(
        &self,
        reader: OpId,
        var: VarId,
        bytes: u64,
        walked: &mut Vec<OpId>,
    ) -> Option<Option<(VarId, u64)>> {
        let op = self.readers.op(reader)?;
        let (dst, kept) = match lane_read(self.func, op, var, bytes) {
            LaneRead::Kept => return None,
            LaneRead::None => return Some(None),
            LaneRead::Into(dst, kept) => (dst, kept),
        };
        if !walked.contains(&reader) {
            walked.push(reader);
        }
        Some(dst.map(|dst| (dst, kept)))
    }
}

/// Every byte of a value `size` bytes wide, as a mask; a value past 64 bytes is 64 of them.
fn all_bytes(size: u32) -> u64 {
    1u64.checked_shl(size).map_or(u64::MAX, |past| past - 1)
}

/// What an operation does with `bytes` of `var` it reads.
enum LaneRead {
    /// An effect, a branch or a return keeps them.
    Kept,
    /// It reads none of them, or cancels them (`xor eax, eax`).
    None,
    /// Its result, where it has one, holds these bytes of them.
    Into(Option<VarId>, u64),
}

/// The bytes of `op`'s result `bytes` of `var` reach: an extract shifts them, an insert over a
/// constant position drops the ones it writes, any other register operation mixes them in whole.
fn lane_read(func: &SSAFunction, op: &SSAOp<VarId>, var: VarId, bytes: u64) -> LaneRead {
    match (op, reads(op)) {
        (_, Read::Kept) => LaneRead::Kept,
        (_, Read::Cancels) => LaneRead::None,
        (_, Read::Into(None)) => LaneRead::Into(None, bytes),
        (SSAOp::Copy { dst, .. }, _) => LaneRead::Into(Some(*dst), bytes),
        (SSAOp::Subpiece { dst, offset, .. }, _) => {
            let shifted = bytes.checked_shr(*offset).unwrap_or(0);
            match shifted & all_bytes(func.var(*dst).size) {
                0 => LaneRead::None,
                kept => LaneRead::Into(Some(*dst), kept),
            }
        }
        (SSAOp::Insert(insert), _) if insert.src == var && insert.value != var => {
            let written = (func.var(insert.position).constant_bits())
                .filter(|bits| bits % 8 == 0)
                .and_then(|bits| u32::try_from(bits / 8).ok())
                .and_then(|at| all_bytes(func.var(insert.value).size).checked_shl(at));
            match written.map(|written| bytes & !written) {
                Some(0) => LaneRead::None,
                Some(kept) => LaneRead::Into(Some(insert.dst), kept),
                None => LaneRead::Into(Some(insert.dst), all_bytes(func.var(insert.dst).size)),
            }
        }
        (_, Read::Into(Some(dst))) => LaneRead::Into(Some(dst), all_bytes(func.var(dst).size)),
    }
}
