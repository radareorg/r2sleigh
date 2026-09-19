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

use std::collections::{BTreeMap, BTreeSet};

use r2il::R2ILBlock;
use r2sleigh_lift::Disassembler;

use crate::cfg::{BasicBlock, BlockTerminator};

/// Longest instruction any supported architecture encodes, and the window
/// Sleigh wants for a decode wherever the address is mapped.
const WINDOW: usize = 16;

/// A function body: its blocks, who it calls, and what it could not follow.
#[derive(Debug, Clone)]
pub struct Body {
    /// The address the walk started from.
    pub entry: u64,
    /// One block per basic block, in address order, ready for `CFG`.
    pub blocks: Vec<R2ILBlock>,
    /// Direct call targets, in address order. The callee facts a request wants
    /// are collected from these.
    pub calls: Vec<u64>,
    /// Every place the walk stopped without knowing where control went.
    pub unresolved: Vec<Unresolved>,
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
pub fn lift_body<R>(entry: u64, disasm: &Disassembler, read: R) -> Result<Body, BodyError>
where
    R: Fn(u64, usize) -> Option<Vec<u8>>,
{
    let walk = Walk::run(entry, disasm, read)?;
    Ok(walk.into_body())
}

/// One instruction the walk decoded, and where control goes after it.
struct Instruction {
    lifted: R2ILBlock,
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

struct Walk {
    entry: u64,
    decoded: BTreeMap<u64, Instruction>,
    leaders: BTreeSet<u64>,
    calls: BTreeSet<u64>,
    unresolved: Vec<Unresolved>,
}

impl Walk {
    fn run<R>(entry: u64, disasm: &Disassembler, read: R) -> Result<Self, BodyError>
    where
        R: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let mut walk = Self {
            entry,
            decoded: BTreeMap::new(),
            leaders: BTreeSet::from([entry]),
            calls: BTreeSet::new(),
            unresolved: Vec::new(),
        };

        let mut pending = vec![entry];
        while let Some(addr) = pending.pop() {
            if walk.decoded.contains_key(&addr) {
                continue;
            }
            let instruction = match walk.decode(addr, disasm, &read) {
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
    fn decode<R>(&mut self, addr: u64, disasm: &Disassembler, read: &R) -> Option<Instruction>
    where
        R: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let Some(window) = read(addr, WINDOW) else {
            return self.stop(addr, UnresolvedReason::Unmapped);
        };
        let available = window.len();
        // Sleigh fetches a whole window whatever the instruction needs, so a
        // short one is padded and the decoded size checked against what is real.
        let mut fetch = window;
        fetch.resize(WINDOW, 0);

        let Ok(lifted) = disasm.lift(&fetch, addr) else {
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
        Some(Instruction { lifted, terminator })
    }

    fn stop(&mut self, addr: u64, reason: UnresolvedReason) -> Option<Instruction> {
        r2il::refusal_evidence!("body-walk", "stopping at {:#x}: {:?}", addr, reason);
        self.unresolved.push(Unresolved { addr, reason });
        None
    }

    /// Keep an instruction, and answer where the walk goes next.
    fn record(&mut self, instruction: Instruction) -> Vec<u64> {
        let addr = instruction.lifted.addr;
        let next = instruction.end();
        let mut successors = Vec::new();

        match instruction.terminator {
            BlockTerminator::Fallthrough { next: after } => successors.push(after),
            BlockTerminator::Branch { target } => {
                self.leaders.insert(target);
                successors.push(target);
            }
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                self.leaders.insert(true_target);
                self.leaders.insert(false_target);
                successors.push(true_target);
                successors.push(false_target);
            }
            BlockTerminator::Call {
                target,
                fallthrough,
            } => {
                self.calls.insert(target);
                successors.extend(fallthrough);
            }
            BlockTerminator::IndirectCall { fallthrough } => successors.extend(fallthrough),
            BlockTerminator::IndirectBranch => {
                self.stop(addr, UnresolvedReason::IndirectBranch);
            }
            // A switch needs a value domain to resolve, which is why the walk
            // never produces one; a return and a terminal block have nowhere
            // to go.
            BlockTerminator::Switch { .. } | BlockTerminator::Return | BlockTerminator::None => {}
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
        let mut blocks = Vec::new();
        let mut parts: Vec<R2ILBlock> = Vec::new();
        let mut start = 0u64;
        let mut end = 0u64;

        for (addr, instruction) in &self.decoded {
            let breaks = parts.is_empty() || *addr != end || self.leaders.contains(addr);
            if breaks && !parts.is_empty() {
                blocks.push(finish(start, end, &mut parts));
            }
            if parts.is_empty() {
                start = *addr;
            }
            end = instruction.end();
            parts.push(instruction.lifted.clone());
            if instruction.ends_block() {
                blocks.push(finish(start, end, &mut parts));
            }
        }
        if !parts.is_empty() {
            blocks.push(finish(start, end, &mut parts));
        }

        Body {
            entry: self.entry,
            blocks,
            calls: self.calls.into_iter().collect(),
            unresolved: self.unresolved,
        }
    }
}

/// One block from the instructions collected for it.
fn finish(start: u64, end: u64, parts: &mut Vec<R2ILBlock>) -> R2ILBlock {
    let size = u32::try_from(end - start).unwrap_or(u32::MAX);
    R2ILBlock::join(start, size, parts.drain(..))
}
