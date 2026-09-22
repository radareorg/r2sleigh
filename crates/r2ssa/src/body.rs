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
use r2sleigh_lift::Disassembler;
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

    /// The register a call leaves the return address in, where the machine
    /// names one. The compiler specification states it; the walk reads the
    /// bytes and cannot know it, which is why it is asked for here.
    fn return_address_register(&self) -> Option<r2il::Varnode> {
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

/// Lift the body of the function at `entry`.
///
/// `read` answers with as many bytes as the program maps at an address, up to
/// the length asked for, and `None` where nothing is mapped.
pub fn lift_body(
    entry: u64,
    disasm: &Disassembler,
    program: &dyn Program,
    dispatched: &BTreeMap<u64, Vec<u64>>,
) -> Result<Body, BodyError> {
    lift_body_where(entry, disasm, program, dispatched, &|_| false)
}

/// The same lift, told which call targets control never comes back from.
///
/// A call is otherwise assumed to return, and where it does not the walk runs
/// straight into whatever follows. On `/bin/ls` five adjacent `err(1, ...)`
/// stubs became one 260-byte function that claimed the four after it, and the
/// interprocedural summary then refused all six for overlapping ranges.
///
/// Whether a call returns is a fact about the callee, which the walk of one
/// body cannot establish -- but the caller can, from the declarations, and
/// that is what this takes.
pub fn lift_body_where(
    entry: u64,
    disasm: &Disassembler,
    program: &dyn Program,
    dispatched: &BTreeMap<u64, Vec<u64>>,
    never_returns: &dyn Fn(u64) -> bool,
) -> Result<Body, BodyError> {
    Walk::run(entry, disasm, program, dispatched, never_returns).map(Walk::into_body)
}

/// One instruction the walk decoded, and where control goes after it.
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

    /// Whether control leaves this instruction for somewhere other than the
    /// next one, which is what ends a basic block.
    fn ends_block(&self) -> bool {
        !matches!(
            self.terminator,
            BlockTerminator::Fallthrough { .. }
                | BlockTerminator::Call { .. }
                | BlockTerminator::IndirectCall { .. }
        )
    }
}

struct Walk<'a> {
    entry: u64,
    program: &'a dyn Program,
    /// Where a dispatch a previous pass resolved goes, by the address of the
    /// instruction that makes it.
    dispatched: &'a BTreeMap<u64, Vec<u64>>,
    decoded: BTreeMap<u64, Instruction>,
    leaders: BTreeSet<u64>,
    calls: BTreeSet<u64>,
    tail_calls: BTreeSet<u64>,
    unresolved: Vec<Unresolved>,
    /// The address the last decoded instruction ended at, so the next one can
    /// keep the decoder's context where it follows on.
    continuing_from: Option<u64>,
    /// Whether control comes back from a call to this address.
    never_returns: &'a dyn Fn(u64) -> bool,
}

impl<'a> Walk<'a> {
    fn run(
        entry: u64,
        disasm: &Disassembler,
        program: &'a dyn Program,
        dispatched: &'a BTreeMap<u64, Vec<u64>>,
        never_returns: &'a dyn Fn(u64) -> bool,
    ) -> Result<Self, BodyError> {
        let mut walk = Self {
            entry,
            program,
            dispatched,
            decoded: BTreeMap::new(),
            leaders: BTreeSet::from([entry]),
            calls: BTreeSet::new(),
            tail_calls: BTreeSet::new(),
            unresolved: Vec::new(),
            continuing_from: None,
            never_returns,
        };

        let mut pending = vec![entry];
        while let Some(addr) = pending.pop() {
            if walk.decoded.contains_key(&addr) {
                continue;
            }
            let instruction = match walk.decode(addr, disasm) {
                Some(instruction) => instruction,
                None if addr == entry => {
                    return Err(match walk.unresolved.last().map(|stop| stop.reason) {
                        Some(UnresolvedReason::Unmapped) => BodyError::EntryUnmapped(entry),
                        _ => BodyError::EntryUndecodable(entry),
                    });
                }
                None => continue,
            };
            pending.extend(walk.record(instruction));
        }

        Ok(walk)
    }

    /// Decode one instruction, or record why control stops here.
    fn decode(&mut self, addr: u64, disasm: &Disassembler) -> Option<Instruction> {
        let Some(window) = self.program.read(addr, WINDOW) else {
            return self.stop(addr, UnresolvedReason::Unmapped);
        };
        let available = window.len();
        // Sleigh fetches a whole window whatever the instruction needs, so a
        // short one is padded and the decoded size checked against what is real.
        let mut fetch = window;
        fetch.resize(WINDOW, 0);

        // Continue the decoder's context where this instruction follows the
        // last one decoded, exactly as a block lift of the same bytes would.
        let lifted = match self.continuing_from == Some(addr) {
            true => disasm.lift_continuing(&fetch, addr),
            false => disasm.lift(&fetch, addr),
        };
        let Ok(lifted) = lifted else {
            return self.stop(addr, UnresolvedReason::Undecodable);
        };
        if lifted.size == 0 {
            return self.stop(addr, UnresolvedReason::Undecodable);
        }
        if lifted.size as usize > available {
            return self.stop(addr, UnresolvedReason::Truncated);
        }

        // A call is assumed to come back. Whether it does is a fact about the
        // callee, and the walk of one body cannot hold it.
        let terminator = BasicBlock::from_r2il_continuing(&lifted, true).terminator;
        let bytes = fetch[..lifted.size as usize].to_vec();
        self.continuing_from = Some(lifted.addr + u64::from(lifted.size));
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
        let Some(link) = self.program.return_address_register() else {
            return false;
        };
        let mut at = addr;
        while let Some((start, instruction)) = self.decoded.range(..at).next_back() {
            if instruction.end() != at {
                return false;
            }
            if r2il::returns_to(&instruction.lifted.ops, next, &link) {
                return true;
            }
            if self.leaders.contains(start) {
                return false;
            }
            at = *start;
        }
        false
    }

    fn stop(&mut self, addr: u64, reason: UnresolvedReason) -> Option<Instruction> {
        r2il::refusal_evidence!("body-walk", "stopping at {:#x}: {:?}", addr, reason);
        self.unresolved.push(Unresolved { addr, reason });
        None
    }

    /// Follow a transfer, or end the body where it leaves for another
    /// function.
    ///
    /// Every way out of a block asks this: a conditional branch to another
    /// entry is a tail call on one arm, and a call to a function that never
    /// returns falls through into whatever the linker put next. Its own entry
    /// is not a boundary, because a function that jumps to its own start is a
    /// loop.
    fn transfer(&mut self, target: u64, successors: &mut Vec<u64>) {
        if target != self.entry && self.program.is_entry(target) {
            self.tail_calls.insert(target);
            return;
        }
        self.leaders.insert(target);
        successors.push(target);
    }

    /// Continue to the address after an instruction, where the next function
    /// does not begin there.
    fn continues(&mut self, next: Option<u64>, successors: &mut Vec<u64>) {
        let Some(next) = next else {
            return;
        };
        if next != self.entry && self.program.is_entry(next) {
            return;
        }
        successors.push(next);
    }

    /// Keep an instruction, and answer where the walk goes next.
    fn record(&mut self, instruction: Instruction) -> Vec<u64> {
        let addr = instruction.lifted.addr;
        let next = instruction.end();
        let mut successors = Vec::new();

        match instruction.terminator {
            BlockTerminator::Fallthrough { next: after } => {
                self.continues(Some(after), &mut successors)
            }
            BlockTerminator::Branch { target } => self.transfer(target, &mut successors),
            // The arm that leaves is this instruction's own transfer; only the
            // arm that stays has anywhere for the walk to go.
            BlockTerminator::ConditionalExit { next: after } => {
                self.continues(Some(after), &mut successors)
            }
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                self.transfer(true_target, &mut successors);
                self.transfer(false_target, &mut successors);
            }
            BlockTerminator::Call {
                target,
                fallthrough,
            } => {
                self.calls.insert(target);
                // A call the declarations say never returns ends the walk
                // here: the bytes after it are the next function's.
                if !(self.never_returns)(target) {
                    self.continues(fallthrough, &mut successors);
                }
            }
            BlockTerminator::IndirectCall { fallthrough } => {
                self.continues(fallthrough, &mut successors)
            }
            // A switch is an indirect branch through a table, so it is one
            // case rather than two: both go wherever a previous pass proved
            // the dispatch reads, and both stop where nothing did.
            BlockTerminator::IndirectBranch | BlockTerminator::Switch { .. } => {
                // A machine with no indirect call instruction spells one by
                // leaving the return address in the link register and then
                // branching. Control comes back, so the walk does too.
                match self.dispatched.get(&addr) {
                    _ if self.returns_after(addr, next) => {
                        self.continues(Some(next), &mut successors)
                    }
                    Some(targets) => {
                        for target in targets.iter().copied().collect::<BTreeSet<_>>() {
                            self.transfer(target, &mut successors);
                        }
                    }
                    None => {
                        self.stop(addr, UnresolvedReason::IndirectBranch);
                    }
                }
            }
            // A return and a terminal block have nowhere to go.
            BlockTerminator::Return | BlockTerminator::None => {}
        }

        if instruction.ends_block() {
            self.leaders.insert(next);
        }
        self.decoded.insert(addr, instruction);
        successors
    }

    /// Gather the decoded instructions into basic blocks.
    ///
    /// A block runs from a leader until control leaves it, until the next
    /// instruction is a leader, or until the instructions stop being
    /// contiguous, which is where an unresolved transfer left a hole.
    fn into_body(self) -> Body {
        let link = self.program.return_address_register();
        let mut blocks: Vec<BodyBlock> = Vec::new();
        let mut parts: Vec<Instruction> = Vec::new();

        for (addr, instruction) in self.decoded {
            let broken = parts
                .last()
                .is_some_and(|last| last.end() != addr || self.leaders.contains(&addr));
            if broken {
                blocks.push(finish(&mut parts, link.as_ref(), self.dispatched));
            }
            let ends = instruction.ends_block();
            parts.push(instruction);
            if ends {
                blocks.push(finish(&mut parts, link.as_ref(), self.dispatched));
            }
        }
        if !parts.is_empty() {
            blocks.push(finish(&mut parts, link.as_ref(), self.dispatched));
        }

        Body {
            entry: self.entry,
            blocks,
            calls: self.calls.into_iter().collect(),
            tail_calls: self.tail_calls.into_iter().collect(),
            unresolved: self.unresolved,
        }
    }
}

/// One block from the instructions collected for it.
///
/// The successors are the last instruction's, because that is the only
/// instruction in a basic block that control can leave by.
fn finish(
    parts: &mut Vec<Instruction>,
    link: Option<&r2il::Varnode>,
    dispatched: &BTreeMap<u64, Vec<u64>>,
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
    let successors = match returns {
        true => vec![(AdvisorySuccessorKind::Fallthrough, end)],
        false => successors_of(&last.terminator, end, arms),
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
