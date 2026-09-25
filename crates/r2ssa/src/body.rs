//! The body of a function at a known address, lifted by recursive descent.
//!
//! This is what makes the engine callable without radare2. Until now the block
//! sequence an analysis request carries was walked out of radare2's own
//! function graph and lifted a block at a time; here the walk is the lift's,
//! from an entry address and a reader over the program's bytes.
//!
//! Only direct transfers are followed. An indirect branch is recorded and its
//! targets are not guessed, which is the same rule the rest of the engine
//! keeps: a body with an unresolved transfer is an honest partial body, and
//! resolving one needs a value domain that does not exist yet.
//!
//! A direct branch to another function's entry is a tail call and ends the
//! body. Without that question the walk has no boundary at all: `frame_dummy`
//! is two instructions ending in `jmp register_tm_clones`, and following that
//! edge swallowed the whole of the other function, so the body carried code
//! the function does not contain and refused on an obligation from it.

use std::collections::{BTreeMap, BTreeSet};

use r2il::R2ILBlock;
use r2sleigh_lift::{Continuation, Disassembler};
use r2source::AdvisorySuccessorKind;

use crate::cfg::{BasicBlock, BlockTerminator};

/// Longest instruction any supported architecture encodes, and the window
/// Sleigh wants for a decode wherever the address is mapped.
pub const WINDOW: usize = 16;

/// The program the walk reads, and the one question about it a walk cannot
/// answer for itself.
pub trait Program {
    /// As many bytes as are mapped at `vaddr`, up to `max`, or `None` where
    /// nothing is mapped.
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>>;

    /// Whether another function begins here.
    ///
    /// This is what bounds a body. The walk can see that control transfers; it
    /// cannot see that the target belongs to someone else, and a program that
    /// knows its own functions can.
    fn is_entry(&self, vaddr: u64) -> bool;

    /// Whether control comes back from a call to this address, which one body's walk cannot establish; unproven, it does.
    fn returns(&self, _callee: u64) -> bool {
        true
    }

    /// The register a call leaves the return address in, where the machine
    /// names one. The compiler specification states it; the walk reads the
    /// bytes and cannot know it, which is why it is asked for here.
    fn return_address_register(&self) -> Option<r2il::Varnode> {
        None
    }

    /// The register a call writes to say which instruction set its target is
    /// in, where the machine has more than one: Sleigh's `ISAModeSwitch`.
    fn mode_register(&self) -> Option<r2il::Varnode> {
        None
    }
}

/// A function body: its blocks, who it calls, and what it could not follow.
#[derive(Debug, Clone)]
pub struct Body {
    /// The address the walk started from.
    pub entry: u64,
    /// One entry per basic block, in address order.
    pub blocks: Vec<BodyBlock>,
    /// Direct call targets, in address order. The callee facts a request wants
    /// are collected from these.
    pub calls: Vec<u64>,
    /// Functions this body leaves for without returning, by branching straight
    /// to their entry. A tail call is a call whose result is this function's.
    pub tail_calls: Vec<u64>,
    /// The instruction set each call target is entered in, where the calling
    /// instruction wrote the mode register; a call that writes none keeps
    /// the caller's.
    pub entered_with: BTreeMap<u64, u64>,
    /// Every place the walk stopped without knowing where control went.
    pub unresolved: Vec<Unresolved>,
}

/// One basic block: what it lifts to, the bytes it is, and where it goes.
#[derive(Debug, Clone)]
pub struct BodyBlock {
    pub lifted: R2ILBlock,
    /// The block's own bytes, which a capture hands to the trusted lift.
    pub bytes: Vec<u8>,
    /// Where control continues from this block.
    pub successors: Vec<(AdvisorySuccessorKind, u64)>,
}

/// One place the walk could not continue, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unresolved {
    /// The instruction the walk stopped at.
    pub addr: u64,
    pub reason: UnresolvedReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// An indirect branch: a jump table or a computed target.
    IndirectBranch,
    /// Control reaches an address the image does not map.
    Unmapped,
    /// The bytes there do not decode.
    Undecodable,
    /// The instruction needs more bytes than the image maps at that address.
    Truncated,
}

/// Why a body could not be lifted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// Nothing is mapped at the entry address.
    EntryUnmapped(u64),
    /// The entry address does not decode, so there is no first instruction.
    EntryUndecodable(u64),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntryUnmapped(addr) => write!(f, "nothing mapped at {addr:#x}"),
            Self::EntryUndecodable(addr) => write!(f, "no instruction decodes at {addr:#x}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// Lift the body of the function at `entry`, past a call only where the program says control comes back from it.
pub fn lift_body(
    entry: u64,
    disasm: &Disassembler,
    program: &dyn Program,
    dispatched: &BTreeMap<u64, Vec<u64>>,
) -> Result<Body, BodyError> {
    let lifting = Walk::start(entry, disasm, program, dispatched.clone(), true);
    lifting.map(Walk::into_body)
}

/// One instruction the walk decoded, and where control goes after it.
#[derive(Debug, Clone)]
struct Instruction {
    lifted: R2ILBlock,
    bytes: Vec<u8>,
    terminator: BlockTerminator,
}

impl Instruction {
    /// The address after this instruction.
    fn end(&self) -> u64 {
        self.lifted.addr + self.lifted.size as u64
    }
}

/// Whether control leaves an instruction ending this way for somewhere other than the next one, which ends a basic block.
fn ends_block(terminator: &BlockTerminator) -> bool {
    !matches!(
        terminator,
        BlockTerminator::Fallthrough { .. }
            | BlockTerminator::Call { .. }
            | BlockTerminator::IndirectCall { .. }
    )
}

/// What a walk keeps of one decoded instruction unless it keeps the lift.
#[derive(Debug, Clone)]
struct Decoded {
    size: u32,
    /// Every constant it leaves in the link register.
    return_addresses: Vec<u64>,
}

/// What a walk reached that it had not reached before it was last asked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reached {
    /// Direct call targets, each the first time a call to it is seen.
    pub calls: Vec<u64>,
    /// Tail call targets, each the first time.
    pub tail_calls: Vec<u64>,
    /// Callees whose call now holds a fallthrough closed, each the first time.
    pub gated: Vec<u64>,
    /// Entries of other functions control runs on into, each the first time.
    pub falls_into: Vec<u64>,
    /// Whether control reached a return, a predicated exit or a stop the walk cannot see past.
    pub leaves: bool,
}

/// A walk that keeps where control goes and not what it lifted, continued past a call once its callee is known to return.
#[derive(Debug, Clone)]
pub struct Trace(Walk);

impl Trace {
    /// Walk the body at `entry`, past every call the program says returns.
    pub fn start(
        entry: u64,
        disasm: &Disassembler,
        program: &dyn Program,
    ) -> Result<Self, BodyError> {
        Walk::start(entry, disasm, program, BTreeMap::new(), false).map(Self)
    }

    /// Continue past every call to `callee`, visiting only what is not yet decoded.
    pub fn open(&mut self, callee: u64, disasm: &Disassembler, program: &dyn Program) {
        self.0.open(callee, disasm, program);
    }

    /// What the walk reached since it was last asked.
    pub fn reached(&mut self) -> Reached {
        std::mem::take(&mut self.0.reached)
    }

    /// The instruction set each call target is entered in, where the call wrote the mode register.
    pub const fn entered_with(&self) -> &BTreeMap<u64, u64> {
        &self.0.entered_with
    }

    /// Every direct call target.
    pub const fn calls(&self) -> &BTreeSet<u64> {
        &self.0.calls
    }

    /// Every function it leaves for by branching to its entry.
    pub const fn tail_calls(&self) -> &BTreeSet<u64> {
        &self.0.tail_calls
    }

    /// Every address a load reads that its lift states as a constant.
    pub const fn loads(&self) -> &BTreeSet<u64> {
        &self.0.loads
    }
}

/// One walk of a body, lifting it or only tracing it.
#[derive(Debug, Clone)]
struct Walk {
    entry: u64,
    /// Where a dispatch a previous pass resolved goes, by the address of the
    /// instruction that makes it.
    dispatched: BTreeMap<u64, Vec<u64>>,
    /// The register a call leaves its return address in, where there is one.
    link: Option<r2il::Varnode>,
    /// The register a call writes its target's instruction set to.
    mode: Option<r2il::Varnode>,
    decoded: BTreeMap<u64, Decoded>,
    /// The lift of each instruction, where the walk keeps it.
    lifted: Option<BTreeMap<u64, Instruction>>,
    leaders: BTreeSet<u64>,
    calls: BTreeSet<u64>,
    loads: BTreeSet<u64>,
    tail_calls: BTreeSet<u64>,
    falls_into: BTreeSet<u64>,
    entered_with: BTreeMap<u64, u64>,
    unresolved: Vec<Unresolved>,
    /// Calls not known to return, by callee: each call instruction and the address after it.
    gated: BTreeMap<u64, Vec<(u64, u64)>>,
    /// Where the last decode left the decoder's context, which the lifter keeps for the next one where it follows on.
    context: Option<Continuation>,
    reached: Reached,
}

impl Walk {
    /// Walk the body at `entry`, past every call the program says returns, keeping each lift where `lifting`.
    fn start(
        entry: u64,
        disasm: &Disassembler,
        program: &dyn Program,
        dispatched: BTreeMap<u64, Vec<u64>>,
        lifting: bool,
    ) -> Result<Self, BodyError> {
        let mut walk = Self {
            entry,
            dispatched,
            link: program.return_address_register(),
            mode: program.mode_register(),
            decoded: BTreeMap::new(),
            lifted: lifting.then(BTreeMap::new),
            leaders: BTreeSet::from([entry]),
            calls: BTreeSet::new(),
            loads: BTreeSet::new(),
            tail_calls: BTreeSet::new(),
            falls_into: BTreeSet::new(),
            entered_with: BTreeMap::new(),
            unresolved: Vec::new(),
            gated: BTreeMap::new(),
            context: None,
            reached: Reached::default(),
        };
        let Some(first) = walk.decode(entry, disasm, program) else {
            return Err(match walk.unresolved.last().map(|stop| stop.reason) {
                Some(UnresolvedReason::Unmapped) => BodyError::EntryUnmapped(entry),
                _ => BodyError::EntryUndecodable(entry),
            });
        };
        let pending = walk.record(first, program);
        walk.run(pending, disasm, program);
        Ok(walk)
    }

    fn open(&mut self, callee: u64, disasm: &Disassembler, program: &dyn Program) {
        let mut pending = Vec::new();
        for (_, next) in self.gated.remove(&callee).unwrap_or_default() {
            self.continues(Some(next), &mut pending, program);
        }
        self.run(pending, disasm, program);
    }

    fn run(&mut self, mut pending: Vec<u64>, disasm: &Disassembler, program: &dyn Program) {
        while let Some(addr) = pending.pop() {
            if self.decoded.contains_key(&addr) {
                continue;
            }
            if let Some(instruction) = self.decode(addr, disasm, program) {
                pending.extend(self.record(instruction, program));
            }
        }
    }

    /// Decode one instruction, or record why control stops here.
    fn decode(
        &mut self,
        addr: u64,
        disasm: &Disassembler,
        program: &dyn Program,
    ) -> Option<Instruction> {
        let Some(window) = program.read(addr, WINDOW) else {
            return self.stop(addr, UnresolvedReason::Unmapped);
        };
        let available = window.len();
        // Sleigh fetches a whole window whatever the instruction needs, so a
        // short one is padded and the decoded size checked against what is real.
        let mut fetch = window;
        fetch.resize(WINDOW, 0);

        // The decoder's context continues where this follows the last decode, exactly as a block lift of the same bytes would.
        let Ok((lifted, context)) = disasm.lift_after(&fetch, addr, self.context) else {
            return self.stop(addr, UnresolvedReason::Undecodable);
        };
        if lifted.size == 0 {
            return self.stop(addr, UnresolvedReason::Undecodable);
        }
        if lifted.size as usize > available {
            return self.stop(addr, UnresolvedReason::Truncated);
        }

        // Whether a call comes back is the callee's fact, decided where it is recorded.
        let terminator = BasicBlock::from_r2il_continuing(&lifted, true).terminator;
        let bytes = fetch[..lifted.size as usize].to_vec();
        self.context = Some(context);
        Some(Instruction {
            lifted,
            bytes,
            terminator,
        })
    }

    /// Whether the instructions leading to this transfer left `next` in the
    /// link register, which is what makes the transfer a call.
    ///
    /// Only the contiguous run before it is read, and only up to the start of
    /// the block: a return address written further back, across a join, is not
    /// this instruction's.
    fn returns_after(&self, addr: u64, next: u64) -> bool {
        let mut at = addr;
        while let Some((start, decoded)) = self.decoded.range(..at).next_back() {
            if start + u64::from(decoded.size) != at {
                return false;
            }
            if decoded.return_addresses.contains(&next) {
                return true;
            }
            if self.leaders.contains(start) {
                return false;
            }
            at = *start;
        }
        false
    }

    /// The constant an instruction writes to the mode register, if any.
    fn mode_written(&self, ops: &[r2il::R2ILOp]) -> Option<u64> {
        let mode = self.mode.as_ref()?;
        ops.iter().rev().find_map(|op| match op {
            r2il::R2ILOp::Copy { dst, src }
                if dst.space == mode.space && dst.offset == mode.offset =>
            {
                (src.space == r2il::SpaceId::Const).then_some(src.offset)
            }
            _ => None,
        })
    }

    fn stop(&mut self, addr: u64, reason: UnresolvedReason) -> Option<Instruction> {
        r2il::refusal_evidence!("body-walk", "stopping at {:#x}: {:?}", addr, reason);
        self.unresolved.push(Unresolved { addr, reason });
        self.reached.leaves = true;
        None
    }

    /// Follow a transfer, or end the body where it leaves for another function's entry; its own entry is a loop.
    fn transfer(&mut self, target: u64, successors: &mut Vec<u64>, program: &dyn Program) {
        if target != self.entry && program.is_entry(target) {
            if self.tail_calls.insert(target) {
                self.reached.tail_calls.push(target);
            }
            return;
        }
        self.leaders.insert(target);
        successors.push(target);
    }

    /// Continue to the address after an instruction, or run on into the function that begins there.
    fn continues(&mut self, next: Option<u64>, successors: &mut Vec<u64>, program: &dyn Program) {
        let Some(next) = next else {
            return;
        };
        if next != self.entry && program.is_entry(next) {
            if self.falls_into.insert(next) {
                self.reached.falls_into.push(next);
            }
            return;
        }
        successors.push(next);
    }

    /// Keep an instruction, and answer where the walk goes next.
    fn record(&mut self, instruction: Instruction, program: &dyn Program) -> Vec<u64> {
        let addr = instruction.lifted.addr;
        let next = instruction.end();
        let mut successors = Vec::new();
        self.loads.extend(constant_loads(&instruction.lifted.ops));

        match instruction.terminator {
            BlockTerminator::Fallthrough { next: after } => {
                self.continues(Some(after), &mut successors, program)
            }
            BlockTerminator::Branch { target } => self.transfer(target, &mut successors, program),
            // The arm that leaves is a return or an indirect transfer, either of which may hand control back.
            BlockTerminator::ConditionalExit { next: after } => {
                self.reached.leaves = true;
                self.continues(Some(after), &mut successors, program)
            }
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                self.transfer(true_target, &mut successors, program);
                self.transfer(false_target, &mut successors, program);
            }
            BlockTerminator::Call {
                target,
                fallthrough,
            } => {
                if self.calls.insert(target) {
                    self.reached.calls.push(target);
                }
                if let Some(mode) = self.mode_written(&instruction.lifted.ops) {
                    self.entered_with.entry(target).or_insert(mode);
                }
                // A predicated call reaches the next instruction when its predicate fails, whatever the callee does.
                let predicated = r2il::predicated_call(&instruction.lifted.ops, next);
                match (predicated || program.returns(target), fallthrough) {
                    (true, _) => self.continues(fallthrough, &mut successors, program),
                    // The bytes after a call not known to return may be the next function's.
                    (false, Some(after)) => self.gate(target, addr, after),
                    (false, None) => {}
                }
            }
            // A call through a register is opaque, so it is assumed to come back.
            BlockTerminator::IndirectCall { fallthrough } => {
                self.continues(fallthrough, &mut successors, program)
            }
            // A switch is an indirect branch through a table, so it is one
            // case rather than two: both go wherever a previous pass proved
            // the dispatch reads, and both stop where nothing did.
            BlockTerminator::IndirectBranch | BlockTerminator::Switch { .. } => {
                self.dispatch(addr, next, &mut successors, program)
            }
            BlockTerminator::Return => self.reached.leaves = true,
            // A trap has nowhere to go.
            BlockTerminator::None => {}
        }

        if ends_block(&instruction.terminator) {
            self.leaders.insert(next);
        }
        let return_addresses = match &self.link {
            Some(link) => r2il::return_addresses(&instruction.lifted.ops, link).collect(),
            None => Vec::new(),
        };
        let decoded = Decoded {
            size: instruction.lifted.size,
            return_addresses,
        };
        self.decoded.insert(addr, decoded);
        if let Some(lifted) = &mut self.lifted {
            lifted.insert(addr, instruction);
        }
        successors
    }

    /// Follow an indirect branch to the arms a previous pass read, or on past it where it is a call; stop where neither.
    fn dispatch(&mut self, addr: u64, next: u64, successors: &mut Vec<u64>, program: &dyn Program) {
        // A machine with no indirect call instruction leaves the return address in the link register and branches: an opaque call.
        if self.returns_after(addr, next) {
            return self.continues(Some(next), successors, program);
        }
        // No arm is no resolution: a dispatch read as going nowhere would be a
        // block with no successor, and that is a claim control stops there.
        let Some(arms) = self
            .dispatched
            .get(&addr)
            .filter(|arms| !arms.is_empty())
            .cloned()
        else {
            self.stop(addr, UnresolvedReason::IndirectBranch);
            return;
        };
        for target in arms.into_iter().collect::<BTreeSet<_>>() {
            self.transfer(target, successors, program);
        }
    }

    /// Hold the fallthrough of a call to `callee` closed until the callee is known to return.
    fn gate(&mut self, callee: u64, call: u64, after: u64) {
        let held = self.gated.entry(callee).or_default();
        if held.is_empty() {
            self.reached.gated.push(callee);
        }
        held.push((call, after));
    }

    /// Gather the decoded instructions into blocks, each ending where control leaves, a leader begins, a hole opens or a fallthrough is closed.
    fn into_body(self) -> Body {
        let closed = self
            .gated
            .values()
            .flatten()
            .map(|(call, _)| *call)
            .collect::<BTreeSet<_>>();
        let link = self.link.as_ref();
        let mut blocks: Vec<BodyBlock> = Vec::new();
        let mut parts: Vec<Instruction> = Vec::new();

        for (addr, instruction) in self.lifted.unwrap_or_default() {
            let broken = parts
                .last()
                .is_some_and(|last| last.end() != addr || self.leaders.contains(&addr));
            if broken {
                blocks.push(finish(&mut parts, link, &self.dispatched, false));
            }
            let ends = closed.contains(&addr);
            let ends_block = ends || ends_block(&instruction.terminator);
            parts.push(instruction);
            if ends_block {
                blocks.push(finish(&mut parts, link, &self.dispatched, ends));
            }
        }
        if !parts.is_empty() {
            blocks.push(finish(&mut parts, link, &self.dispatched, false));
        }

        Body {
            entry: self.entry,
            blocks,
            calls: self.calls.into_iter().collect(),
            tail_calls: self.tail_calls.into_iter().collect(),
            entered_with: self.entered_with,
            unresolved: self.unresolved,
        }
    }
}

/// Every address a load reads that the operations state as a constant.
fn constant_loads(ops: &[r2il::R2ILOp]) -> impl Iterator<Item = u64> + '_ {
    ops.iter().filter_map(|op| match op {
        r2il::R2ILOp::Load { space, addr, .. }
            if *space == r2il::SpaceId::Ram && addr.space == r2il::SpaceId::Const =>
        {
            Some(addr.offset)
        }
        _ => None,
    })
}

/// One block from the instructions collected for it, with its last instruction's successors, or none where that call is `closed`.
fn finish(
    parts: &mut Vec<Instruction>,
    link: Option<&r2il::Varnode>,
    dispatched: &BTreeMap<u64, Vec<u64>>,
    closed: bool,
) -> BodyBlock {
    let start = parts[0].lifted.addr;
    let last = parts
        .last()
        .expect("a block holds at least one instruction");
    let end = last.end();
    // A transfer the block returns from continues after it, whatever the
    // opcode was: the link register holding the address after the block is
    // what says so, and the walk followed it for the same reason.
    let returns = matches!(last.terminator, BlockTerminator::IndirectBranch)
        && link.is_some_and(|link| {
            parts
                .iter()
                .any(|part| r2il::returns_to(&part.lifted.ops, end, link))
        });
    let arms = dispatched
        .get(&last.lifted.addr)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let successors = match (closed, returns) {
        (true, _) => Vec::new(),
        (false, true) => vec![(AdvisorySuccessorKind::Fallthrough, end)],
        (false, false) => successors_of(&last.terminator, end, arms),
    };
    let size = u32::try_from(end - start).unwrap_or(u32::MAX);
    let mut bytes = Vec::with_capacity(size as usize);
    for part in parts.iter() {
        bytes.extend_from_slice(&part.bytes);
    }
    let lifted = R2ILBlock::join(start, size, parts.drain(..).map(|part| part.lifted));
    BodyBlock {
        lifted,
        bytes,
        successors,
    }
}

/// Where control goes after a block that ends this way.
///
/// A dispatch a previous pass read goes to the arms it read, which is the
/// only case where the terminator alone does not say.
fn successors_of(
    terminator: &BlockTerminator,
    end: u64,
    dispatched: &[u64],
) -> Vec<(AdvisorySuccessorKind, u64)> {
    match terminator {
        BlockTerminator::Fallthrough { next } => {
            vec![(AdvisorySuccessorKind::Fallthrough, *next)]
        }
        BlockTerminator::Branch { target } => vec![(AdvisorySuccessorKind::Direct, *target)],
        BlockTerminator::ConditionalExit { next } => {
            vec![(AdvisorySuccessorKind::Direct, *next)]
        }
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => vec![
            (AdvisorySuccessorKind::Direct, *true_target),
            (AdvisorySuccessorKind::Fallthrough, *false_target),
        ],
        // A call returns to the instruction after it, which is the next block
        // whenever the call is the last instruction of this one.
        BlockTerminator::Call { .. } | BlockTerminator::IndirectCall { .. } => {
            vec![(AdvisorySuccessorKind::Fallthrough, end)]
        }
        // Several cases reach one arm, and that is one edge; which cases
        // those were is the dispatch's own fact, carried by its table.
        BlockTerminator::Switch { .. } | BlockTerminator::IndirectBranch => dispatched
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|target| (AdvisorySuccessorKind::Direct, target))
            .collect(),
        BlockTerminator::Return | BlockTerminator::None => Vec::new(),
    }
}
