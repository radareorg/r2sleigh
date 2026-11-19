//! The body of a function at a known address, lifted by recursive descent.
//!
//! This is what makes the engine callable without radare2. Until now the block
//! sequence an analysis request carries was walked out of radare2's own
//! function graph and lifted a block at a time; here the walk is the lift's,
//! from an entry address and a reader over the program's bytes.
//!
//! Direct transfers are followed, and an indirect branch only to the arms a
//! previous pass proved it reads (`dispatched`). Otherwise it is recorded and
//! its targets are not guessed, which is the same rule the rest of the engine
//! keeps: a body with an unresolved transfer is an honest partial body.
//!
//! No instruction is lifted where the program maps no execute permission.
//! Data decodes as readily as code on most machines, so the bytes cannot
//! say which one an address holds; the mapping can.
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

use crate::discovery::Never;

use r2ssa::cfg::{BasicBlock, BlockTerminator};

/// Longest instruction any supported architecture encodes, and the window
/// Sleigh wants for a decode wherever the address is mapped.
pub const WINDOW: usize = 16;

/// The program the walk reads, and the one question about it a walk cannot
/// answer for itself.
pub trait Program {
    /// As many bytes as are mapped at `vaddr`, up to `max`, or `None` where
    /// nothing is mapped.
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>>;

    /// The one run of addresses the program maps with one set of permissions
    /// that holds `vaddr`, or `None` where nothing is mapped.
    ///
    /// Whether an instruction can run at an address is the program's
    /// statement and not the bytes': data decodes as well as code does on
    /// most machines, and only the mapping says which one control can reach.
    fn region(&self, vaddr: u64) -> Option<Region>;

    /// Whether a patch holds the byte at `vaddr`: it backs zero fill as the file does.
    fn patched(&self, _vaddr: u64) -> bool {
        false
    }

    /// What the loader writes before the program runs, sorted by place and
    /// disjoint, with the value the container states for each: the file's
    /// bytes there are not what the program reads or runs. Nothing, where
    /// nothing is loaded. Read through [`crate::stated`], never directly.
    fn loader_writes(&self) -> &[crate::program::LoaderWrite] {
        &[]
    }

    /// How long `range` keeps what the loader leaves there; where the program states no seal,
    /// the region's own permission answers.
    fn permanence(&self, range: &std::ops::Range<u64>) -> crate::program::Permanence {
        let read_only = self
            .region(range.start)
            .is_some_and(|region| !region.write && range.end <= region.end);
        match read_only {
            true => crate::program::Permanence::ReadOnly,
            false => crate::program::Permanence::Writable,
        }
    }

    /// Whether another function begins here.
    ///
    /// This is what bounds a body. The walk can see that control transfers; it
    /// cannot see that the target belongs to someone else, and a program that
    /// knows its own functions can.
    fn is_entry(&self, vaddr: u64) -> bool;

    /// Whether control comes back from a call to this address, entered in the walk's instruction set
    /// unless `foreign`, which one body's walk cannot establish; unproven, it does.
    fn returns(&self, _callee: u64, _foreign: bool) -> bool {
        true
    }

    /// Why `returns` says a call to `callee` never comes back; `None` where nothing says so.
    fn exit(&self, _callee: u64, _foreign: bool) -> Option<crate::discovery::Never> {
        None
    }

    /// Why `call [slot]` never comes back: the program binds a never-returning import in `slot`.
    /// `None` where nothing says so, and the call comes back.
    fn exit_through(&self, _slot: u64) -> Option<crate::discovery::Never> {
        None
    }

    /// The document stating interrupt `vector` on `arch` never comes back (D229); `None` where
    /// none does, and it comes back.
    fn interrupt_halts(&self, _arch: &str, _vector: u64) -> Option<r2source::Citation> {
        None
    }

    /// The kernel source stating the supervisor call at `instruction` never comes back in the body
    /// at `entry`: its seal folds the number to a cited row's (D505). `None`: it comes back.
    fn supervisor_halts(&self, _entry: u64, _instruction: u64) -> Option<r2source::Citation> {
        None
    }

    /// The argument register that, holding the `Halt`, makes a transfer through `slot` not return,
    /// where the cited row of the import the loader binds there states one.
    fn halts_on_through(&self, _slot: u64) -> Option<Halting> {
        None
    }

    /// The same for a direct call to `callee`, where the program states it is an import's stub.
    fn halts_on(&self, _callee: u64) -> Option<Halting> {
        None
    }

    /// Whether an import row of this program may yield a handle: only a PE's KERNEL32 rows do.
    fn binds_handles(&self) -> bool {
        false
    }

    /// Whether a walk holds register values at all: a row yields a handle or halts on a value.
    fn holds_values(&self) -> bool {
        false
    }

    /// The register a call through `slot` leaves holding a handle the import states.
    fn yields_through(&self, _slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Handle)> {
        None
    }

    /// The register a call leaves the return address in, where the machine
    /// names one. The compiler specification states it; the walk reads the
    /// bytes and cannot know it, which is why it is asked for here.
    fn return_address_register(&self) -> Option<r2il::Varnode> {
        None
    }

    /// The landing pad a call whose last byte is `last` unwinds to, where a cited personality's
    /// table states one (D570); `None` where nothing does.
    fn landing_pad(&self, _last: u64) -> Option<u64> {
        None
    }
}

/// One run of addresses a program maps, and what it permits there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// The first address of the run.
    pub start: u64,
    /// The address after the last one.
    pub end: u64,
    /// The address after the last byte the file holds, at most `end`: from
    /// here to `end` the loader fills zeros, so no byte there is one the file
    /// states. A container may say a run is far longer than the file, and
    /// only this bounds what reading it can cost.
    pub file_end: u64,
    /// Whether an instruction there can run.
    pub execute: bool,
    /// Whether the program may write there once it runs.
    pub write: bool,
}

impl Region {
    /// Whether every address of `start..end` lies in this run.
    pub const fn holds(&self, start: u64, end: u64) -> bool {
        self.start <= start && start <= end && end <= self.end
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
    /// The calls the walk ended a block at on a model's word that the callee never returns.
    pub exits: r2ssa::AssumedExits,
    /// The exceptional flow, held apart from `blocks`: no flow reader joins it until D598.
    pub pads: Pads,
}

/// What a body's calls unwind to (D570): the blocks reached only through a landing pad. A call made
/// only there is in no `Body::calls`; `axt` reads it from the pads' lines.
#[derive(Debug, Clone, Default)]
pub struct Pads {
    /// Each block no normal edge reaches, in address order; a block both flows reach is in `blocks`.
    pub blocks: Vec<BodyBlock>,
    /// Each call instruction of either flow and the pad it unwinds to, sorted.
    pub unwinds: Vec<(u64, u64)>,
}

/// One basic block: what it lifts to, the bytes it is, and where it goes.
#[derive(Debug, Clone)]
pub struct BodyBlock {
    pub lifted: R2ILBlock,
    /// The block's own bytes, which a capture hands to the trusted lift.
    pub bytes: Vec<u8>,
    /// Where control continues from this block.
    pub successors: Vec<(AdvisorySuccessorKind, u64)>,
    /// Each transfer to another function the walk read in this block, in operation order.
    pub transfers: Vec<Transfer>,
}

impl r2ssa::site_boundary::Lifted for BodyBlock {
    fn lifted(&self) -> &R2ILBlock {
        &self.lifted
    }
}

/// One operation that leaves for another function, as the walk read it: a call it folded to its
/// target stays the call it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    /// The operation's index in its block.
    pub op: usize,
    /// The function's entry, or the slot a tail transfer loads it from.
    pub target: u64,
    pub kind: r2source::AdvisoryCallTransfer,
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
    /// Control reaches an address the program maps where no instruction can
    /// run: data decodes as readily as code, and the mapping is what says
    /// which one it is.
    NotExecutable,
    /// Control reaches an executable address the file holds no byte for: the loader's zero fill,
    /// which no file states as code (a debug companion's `.text`, a packer's empty segment).
    Unbacked,
    /// The bytes there do not decode.
    Undecodable,
    /// The instruction needs more bytes than the image maps at that address.
    Truncated,
    /// The loader writes a field of the instruction with a value the container does not state
    /// (audit W5): what its bytes decode to is not what runs.
    Relocated,
    /// The body reached [`BODY_INSTRUCTIONS`] before it closed (D18): no analysis reads it whole.
    Budget,
    /// A dispatch arm starts inside the instruction decoded at `with`, or spans its start (audit W6): the walk
    /// keeps the instruction it decoded first. A branch past a `lock` prefix is no arm and keeps both.
    Overlaps { with: u64 },
}

/// How many instructions one body may hold: 8x the largest function the corpora hold (pumasim's
/// Gui constructor, 8,250), so only hostile code (a chain of overlapping jumps) reaches it.
pub const BODY_INSTRUCTIONS: usize = 1 << 16;

/// Why a body could not be lifted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// Nothing is mapped at the entry address.
    EntryUnmapped(u64),
    /// The entry is mapped where no instruction can run, so it begins no function.
    EntryNotExecutable(u64),
    /// The file holds no byte at the entry: the loader fills zeros there, which state no code.
    EntryUnbacked(u64),
    /// The entry address does not decode, so there is no first instruction.
    EntryUndecodable(u64),
    /// The loader writes a field of the first instruction with a value the container does not state.
    EntryRelocated(u64),
    /// The body at this entry holds more instructions than [`BODY_INSTRUCTIONS`].
    Oversized(u64),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntryUnmapped(addr) => write!(f, "nothing mapped at {addr:#x}"),
            Self::EntryNotExecutable(addr) => write!(
                f,
                "no instruction can run at {addr:#x}: the program maps it without execute permission"
            ),
            Self::EntryUnbacked(addr) => write!(
                f,
                "the file holds no bytes at {addr:#x}: the loader fills zeros there"
            ),
            Self::EntryUndecodable(addr) => write!(f, "no instruction decodes at {addr:#x}"),
            Self::EntryRelocated(addr) => write!(
                f,
                "the instruction at {addr:#x} holds a field the loader writes with no value the container states"
            ),
            Self::Oversized(addr) => write!(
                f,
                "the body at {addr:#x} holds more than {BODY_INSTRUCTIONS} instructions, the budget no function reaches"
            ),
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
    let lifting = Walk::start(
        entry,
        Reader { disasm, program },
        dispatched.clone(),
        Keep::Lifts,
        Unwinds::Record,
    );
    lifting.map(|walk| walk.into_body().0)
}

/// The same body with each instruction's own lift, as the reference index lists it (ROADMAP D162).
pub fn listed_body(
    entry: u64,
    disasm: &Disassembler,
    program: &dyn Program,
    dispatched: &BTreeMap<u64, Vec<u64>>,
) -> Result<(Body, Vec<Decoded>), BodyError> {
    let walk = Walk::start(
        entry,
        Reader { disasm, program },
        dispatched.clone(),
        Keep::Decodes,
        Unwinds::Walk,
    );
    walk.map(Walk::into_body)
}

/// One instruction a walk decoded: its lift, its decode window and the context it left.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub lift: R2ILBlock,
    pub window: Vec<u8>,
    pub continuation: Continuation,
}

/// The pads' bytes a survey's trace holds once their walk is dropped: joined ranges, blocks, bytes.
#[derive(Debug, Clone)]
struct PadExtent {
    spans: Vec<std::ops::Range<u64>>,
    blocks: usize,
    bytes: u64,
}

/// What a walk does with a call's landing pad (D570, D599): nothing, record the unwind, or walk the pad too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unwinds {
    Ignore,
    Record,
    Walk,
}

/// The decoder and the program a walk reads its instructions through, passed as one.
#[derive(Clone, Copy)]
struct Reader<'a> {
    disasm: &'a Disassembler,
    program: &'a dyn Program,
}

/// What a walk keeps of each instruction it decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keep {
    Nothing,
    Lifts,
    Decodes,
}

/// One instruction the walk decoded, and where control goes after it.
#[derive(Debug, Clone)]
struct Instruction {
    lifted: R2ILBlock,
    bytes: Vec<u8>,
    terminator: BlockTerminator,
    /// The decode window and context, where the walk keeps its decodes.
    decode: Option<Box<(Vec<u8>, Continuation)>>,
    /// The document stating this `int n`'s vector (D229) or this supervisor call's number (D505)
    /// never comes back.
    halts: Option<r2source::Citation>,
    /// Whether it enters the supervisor, read once from its operations.
    supervisor: bool,
}

impl Instruction {
    /// The address after this instruction.
    fn end(&self) -> u64 {
        self.lifted.addr + self.lifted.size as u64
    }

    /// A copy of the lift, no decode window: what a block of a cut holds.
    fn copied(&self) -> Self {
        Self {
            lifted: self.lifted.clone(),
            bytes: self.bytes.clone(),
            terminator: self.terminator.clone(),
            decode: None,
            halts: self.halts,
            supervisor: self.supervisor,
        }
    }
}

/// Whether control leaves an instruction ending this way for somewhere other than the next one, which ends a basic block.
/// A register holding a handle an import yielded or a constant, and the instruction that put it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    storage: r2source::CanonicalStorageId,
    value: Holding,
    from: u64,
}

/// What a held register is known to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holding {
    Handle(r2abi::Handle),
    Constant(u64),
}

impl Holding {
    /// Whether a call's argument holding this meets a row's `Halt`.
    fn halts(self, halt: r2abi::Halt) -> bool {
        match (self, halt) {
            (Self::Handle(held), r2abi::Halt::Handle(handle)) => held == handle,
            // A nonzero low byte is a nonzero integer at any width the row's parameter has.
            (Self::Constant(value), r2abi::Halt::NonZero) => value & 0xff != 0,
            _ => false,
        }
    }
}

/// The handles and constants one straight run holds, read forward: a copy or a zero extension hands
/// one on, any other write or a call ends it. `O(ops * held)`.
#[derive(Debug, Clone, Default)]
struct Handles {
    at: Option<u64>,
    held: Vec<Held>,
}

impl Handles {
    fn step(&mut self, lifted: &R2ILBlock, program: &dyn Program) {
        let overlaps = |a: r2source::CanonicalStorageId, b: r2source::CanonicalStorageId| {
            a.space == b.space
                && a.offset < b.offset + u64::from(b.size)
                && b.offset < a.offset + u64::from(a.size)
        };
        let mut conditional = false;
        for (index, op) in lifted.ops.iter().enumerate() {
            // An unstated operation stands for writes the lift dropped.
            if matches!(op, r2il::R2ILOp::Unimplemented) {
                self.held.clear();
                continue;
            }
            // A value written past a branch inside the instruction is conditional (`moveq r0, #1`).
            if op.is_control_flow() && !op.is_call() {
                self.held.clear();
                conditional = true;
                continue;
            }
            if op.is_call() {
                self.held.clear();
                let slot = r2ssa::loaded_target_slot(lifted, index).map(|slot| slot.offset);
                let slot = slot.filter(|_| program.binds_handles());
                let yielded = slot
                    .filter(|slot| crate::stated::sealed_import(program, *slot).is_some())
                    .and_then(|slot| program.yields_through(slot));
                self.held.extend(yielded.map(|(storage, handle)| Held {
                    storage,
                    value: Holding::Handle(handle),
                    from: lifted.addr,
                }));
                continue;
            }
            let Some(output) = op.output() else {
                continue;
            };
            let written = r2source::CanonicalStorageId::from_varnode(output);
            let copied = match op {
                r2il::R2ILOp::Copy { src, .. } | r2il::R2ILOp::IntZExt { src, .. }
                    if src.is_const() =>
                {
                    Some(Held {
                        storage: written,
                        value: Holding::Constant(src.offset),
                        from: lifted.addr,
                    })
                }
                r2il::R2ILOp::Copy { src, .. } => {
                    let src = r2source::CanonicalStorageId::from_varnode(src);
                    self.held.iter().find(|held| held.storage == src).copied()
                }
                r2il::R2ILOp::IntZExt { src, .. } => {
                    let src = r2source::CanonicalStorageId::from_varnode(src);
                    let constant = |held: &&Held| matches!(held.value, Holding::Constant(_));
                    let held = self.held.iter().filter(constant);
                    held.into_iter().find(|held| held.storage == src).copied()
                }
                _ => None,
            };
            self.held.retain(|held| !overlaps(held.storage, written));
            self.held
                .extend(copied.filter(|_| !conditional).map(|held| Held {
                    storage: written,
                    ..held
                }));
        }
    }
}

/// Whose "never" closes a transfer: the callee's own, only this call's (a halting argument or an
/// interrupt), or a tail branch's, which closes no call (D384).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closer {
    Callee,
    Site,
    Branch,
}

/// The argument register whose value makes a call not return, the value, and the cited row that
/// states it (D211, D410).
pub(crate) type Halting = (
    r2source::CanonicalStorageId,
    r2abi::Halt,
    r2source::Citation,
);

/// The instruction that put the value a row halts on in its argument register, where one did, and
/// the "never" the row's citation states.
fn holding(held: &[Held], (argument, halt, citation): Halting) -> Option<(u64, Never)> {
    (held.iter())
        .find(|held| held.storage == argument && held.value.halts(halt))
        .map(|held| (held.from, Never::cited(citation)))
}

fn ends_block(terminator: &BlockTerminator) -> bool {
    !matches!(
        terminator,
        BlockTerminator::Fallthrough { .. }
            | BlockTerminator::Call { .. }
            | BlockTerminator::IndirectCall { .. }
    )
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

/// A lifting walk continued through each round's dispatch tables: a round lifts only what its arms
/// newly reach, and its body is the one [`lift_body`] returns told every table followed (D367).
#[derive(Debug, Clone)]
pub struct Lifting(Walk);

impl Lifting {
    /// Lift the body at `entry`, past every call the program says returns, no table told.
    pub fn start(
        entry: u64,
        disasm: &Disassembler,
        program: &dyn Program,
    ) -> Result<Self, BodyError> {
        Walk::start(
            entry,
            Reader { disasm, program },
            BTreeMap::new(),
            Keep::Lifts,
            Unwinds::Ignore,
        )
        .map(Self)
    }

    /// The instructions at which the walk stopped for want of a dispatch's arms.
    pub fn dispatches(&self) -> impl Iterator<Item = u64> + '_ {
        let stops = self.0.unresolved.iter();
        let stops = stops.filter(|stop| stop.reason == UnresolvedReason::IndirectBranch);
        stops.map(|stop| stop.addr)
    }

    /// Continue through the arms of dispatches, lifting only what is not yet decoded.
    pub fn dispatch(
        &mut self,
        arms: &BTreeMap<u64, Vec<u64>>,
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        self.0.follow(arms, disasm, program);
    }

    /// The blocks walked so far by place, no lift copied. O(instructions).
    pub fn shape(&self) -> Shape {
        self.0.shape()
    }

    /// The blocks of `shape`, this walk's as it stands, that `keep` holds, entered at `entry`, and
    /// how many lifts were copied: only theirs. O(instructions + kept operations).
    pub fn cut(&self, shape: &Shape, entry: u64, keep: &[bool]) -> (Body, usize) {
        self.0.cut(shape, entry, keep)
    }

    /// The instructions the walk reached that enter the supervisor.
    pub fn supervisor_calls(&self) -> &BTreeSet<u64> {
        &self.0.supervisor
    }

    /// The body walked, the walk ended.
    pub fn into_body(self) -> Body {
        self.0.into_body().0
    }
}

/// A walk that keeps where control goes and not what it lifted, continued past a call once its callee is known to return.
#[derive(Debug, Clone)]
pub struct Trace(Walk);

impl Trace {
    /// Walk the body at `entry`, past every call the program says returns, recording each call's
    /// unwind where `records` says, for `walk_pads` (D599).
    pub fn start(
        entry: u64,
        disasm: &Disassembler,
        program: &dyn Program,
        records: bool,
    ) -> Result<Self, BodyError> {
        Walk::start(
            entry,
            Reader { disasm, program },
            BTreeMap::new(),
            Keep::Nothing,
            if records {
                Unwinds::Record
            } else {
                Unwinds::Ignore
            },
        )
        .map(Self)
    }

    /// Walk the pads of the calls walked, once the walk is done and `program` says which callees
    /// return (D570, D599): their bytes join `spans` and `extent`.
    pub fn walk_pads(&mut self, disasm: &Disassembler, program: &dyn Program) {
        self.0.unwinding = Unwinds::Walk;
        self.0.walk_pads(disasm, program);
        // Only the pads' extent is read from here on: the walk of them is dropped (D570).
        let Some(pads) = self.0.pads.take() else {
            return;
        };
        let normal = &self.0.decoded;
        let own = |at: &&u64| !normal.contains_key(*at);
        let instructions = (pads.decoded.iter()).filter(|(at, _)| own(at));
        self.0.pad_extent = Some(Box::new(PadExtent {
            spans: joined(instructions.clone().map(|(at, size)| (*at, *size))),
            blocks: (pads.leaders.iter())
                .filter(|leader| pads.decoded.contains_key(leader))
                .filter(own)
                .count(),
            bytes: instructions.map(|(_, size)| u64::from(*size)).sum(),
        }));
        self.0.unwinds = Vec::new();
    }

    /// Continue past every call to `callee`, visiting only what is not yet decoded.
    pub fn open(&mut self, callee: u64, disasm: &Disassembler, program: &dyn Program) {
        self.0.open(callee, disasm, program);
    }

    /// The instructions at which the walk stopped for want of a dispatch's arms.
    pub fn dispatches(&self) -> impl Iterator<Item = u64> + '_ {
        let stops = self.0.unresolved.iter();
        let stops = stops.filter(|stop| stop.reason == UnresolvedReason::IndirectBranch);
        stops.map(|stop| stop.addr)
    }

    /// Continue through the arms of dispatches, by the instruction making each, visiting only what is not yet decoded.
    pub fn dispatch(
        &mut self,
        arms: &BTreeMap<u64, Vec<u64>>,
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        self.0.follow(arms, disasm, program);
    }

    /// What the walk reached since it was last asked.
    pub fn reached(&mut self) -> Reached {
        let walk = &mut self.0;
        let mut reached = std::mem::take(&mut walk.reached);
        reached.leaves = std::mem::take(&mut walk.leaving) || walk.unresolved.len() > walk.asked;
        walk.asked = walk.unresolved.len();
        reached
    }

    /// Whether each address an instruction states context for decodes in another context than the walk's.
    pub const fn target_contexts(&self) -> &BTreeMap<u64, bool> {
        &self.0.target_contexts
    }

    /// Every direct call target.
    pub const fn calls(&self) -> &BTreeSet<u64> {
        &self.0.calls
    }

    /// Every function it leaves for by branching to its entry.
    pub const fn tail_calls(&self) -> &BTreeSet<u64> {
        &self.0.tail_calls
    }

    /// Each direct call as (target, instruction), in walk order.
    pub fn call_sites(&self) -> &[(u64, u64)] {
        &self.0.call_sites
    }

    /// Each branch to another function's entry as (target, instruction), in walk order.
    pub fn tail_sites(&self) -> &[(u64, u64)] {
        &self.0.tail_sites
    }

    /// Every address a load reads that its lift states as a constant.
    pub const fn loads(&self) -> &BTreeSet<u64> {
        &self.0.loads
    }

    /// The "never" of each of the walk's ends a statement proves halts (a halting transfer), and
    /// how many none does (a trap, or a call through a slot whose "never" is a bound, D395).
    pub fn ends(&self) -> (Vec<&Never>, usize) {
        let walk = &self.0;
        let never = |at| (walk.nevers.get(at)).map(|(never, _)| never);
        let (proven, bound): (Vec<_>, Vec<_>) = (walk.halting.iter())
            .map(never)
            .partition(|never| never.is_some_and(|never| never.proves().is_some()));
        (
            proven.into_iter().flatten().collect(),
            walk.ends_unproven + bound.len(),
        )
    }

    /// The address after each call the walk ended a block at because its callee never comes back.
    pub fn exits_after(&self) -> impl Iterator<Item = u64> + '_ {
        let walk = &self.0;
        let through = (walk.halting.iter())
            .filter_map(|call| Some(call.saturating_add(u64::from(*walk.decoded.get(call)?))));
        (walk.gated.values().flatten().map(|(_, after)| *after)).chain(through)
    }

    /// Whether a call of the body, or of its pads, unwinds to a landing pad (D570).
    pub fn unwinds(&self) -> bool {
        !self.0.unwinds.is_empty() || self.0.pad_extent.is_some()
    }

    /// Whether the walk decoded an instruction that begins at `address`. `O(log n)`.
    pub fn begins(&self, address: u64) -> bool {
        self.0.decoded.contains_key(&address)
    }

    /// The instructions the walk reached that enter the supervisor.
    pub fn supervisor_calls(&self) -> &BTreeSet<u64> {
        &self.0.supervisor
    }

    /// The bytes the walk decoded as instructions, as ranges in address
    /// order with abutting instructions joined. Padding between blocks is no
    /// instruction of the body and lies in no range. O(instructions).
    pub fn spans(&self) -> Vec<std::ops::Range<u64>> {
        let spans = joined(self.0.decoded.iter().map(|(at, size)| (*at, *size)));
        let Some(pads) = &self.0.pad_extent else {
            return spans;
        };
        let mut all = spans;
        all.extend(pads.spans.iter().cloned());
        all.sort_unstable_by_key(|span| span.start);
        let mut merged: Vec<std::ops::Range<u64>> = Vec::with_capacity(all.len());
        for span in all {
            match merged.last_mut() {
                Some(last) if last.end >= span.start => last.end = last.end.max(span.end),
                _ => merged.push(span),
            }
        }
        merged
    }

    /// A block begins at each leader the walk decoded; padding between
    /// blocks is no instruction of the body and is not counted. A dispatch
    /// the walk could not follow reaches nothing, so its arms are not
    /// counted either. O(instructions).
    pub fn extent(&self) -> TraceExtent {
        let walk = &self.0;
        let leaders = (walk.leaders.iter())
            .filter(|leader| walk.decoded.contains_key(leader))
            .count();
        let bytes = walk
            .decoded
            .values()
            .map(|size| u64::from(*size))
            .sum::<u64>();
        let (pad_blocks, pad_bytes) =
            (walk.pad_extent.as_ref()).map_or((0, 0), |pads| (pads.blocks, pads.bytes));
        TraceExtent {
            blocks: leaders + pad_blocks,
            bytes: bytes + pad_bytes,
        }
    }
}

/// Instructions in address order as ranges, abutting ones joined. O(instructions).
fn joined(instructions: impl Iterator<Item = (u64, u32)>) -> Vec<std::ops::Range<u64>> {
    let mut spans: Vec<std::ops::Range<u64>> = Vec::new();
    for (at, size) in instructions {
        let end = at.saturating_add(u64::from(size));
        match spans.last_mut() {
            Some(last) if last.end >= at => last.end = last.end.max(end),
            _ => spans.push(at..end),
        }
    }
    spans
}

/// Whether an instruction enters the supervisor (`ArchSpec::supervisor_calls`), and the vector an
/// x86 `int n`'s `swi` reads; one pass over its operations.
fn supervisor_entry(ops: &[r2il::R2ILOp], arch: &r2il::ArchSpec) -> (bool, Option<u64>) {
    let mut entry = (false, None);
    for op in ops {
        let r2il::R2ILOp::CallOther { userop, inputs, .. } = op else {
            continue;
        };
        entry.0 |= arch.supervisor_calls.contains(userop);
        let swi = (arch.user_ops.get(*userop as usize)).is_some_and(|name| name == "swi");
        if let ([vector], true, None) = (inputs.as_slice(), swi, entry.1) {
            entry.1 = (vector.space == r2il::SpaceId::Const).then_some(vector.offset);
        }
    }
    entry
}

/// The shape of one traced body: its basic blocks and the bytes of its
/// instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceExtent {
    pub blocks: usize,
    pub bytes: u64,
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
    /// The size of each instruction decoded, by address: a whole program's survey holds one per
    /// instruction, so nothing else rides in it.
    decoded: BTreeMap<u64, u32>,
    /// Every constant an instruction leaves in the link register, where it leaves one.
    return_addresses: BTreeMap<u64, Box<[u64]>>,
    /// The lift of each instruction, where the walk keeps it.
    lifted: Option<BTreeMap<u64, Instruction>>,
    /// Whether each instruction keeps its decode window and context.
    decodes: bool,
    /// The address of the instruction recorded last in this run.
    last: Option<u64>,
    leaders: BTreeSet<u64>,
    /// The targets a dispatch's table names, whose starts are only as proven as the table's bound.
    arms: BTreeSet<u64>,
    /// The targets a branch names: a start the instruction itself states.
    direct: BTreeSet<u64>,
    calls: BTreeSet<u64>,
    loads: BTreeSet<u64>,
    tail_calls: BTreeSet<u64>,
    /// Each direct call as (target, instruction), and each tail branch, in walk order (D566).
    call_sites: Vec<(u64, u64)>,
    tail_sites: Vec<(u64, u64)>,
    /// Each call through a slot the loader binds to an import and seals, by instruction: the slot.
    slot_calls: BTreeMap<u64, u64>,
    /// The calls through a slot the program states never returns, by instruction.
    halting: BTreeSet<u64>,
    /// The registers holding a handle an import yielded, valid at the run's next address.
    handles: Handles,
    /// Each transfer proven not to return from a held value: the instruction that put it there,
    /// the transfer, and where a direct call goes on where that proof fails.
    proven: Vec<(u64, u64, Option<u64>)>,
    /// Ends no statement proves: a trap, or a call with no next instruction.
    ends_unproven: usize,
    /// Whether the program's rows read a held register value (`Program::holds_values`).
    holds_values: bool,
    falls_into: BTreeSet<u64>,
    /// Whether each address the lift states context for decodes in another context than this walk's.
    target_contexts: BTreeMap<u64, bool>,
    unresolved: Vec<Unresolved>,
    /// Calls not known to return, by callee: each call instruction and the address after it.
    gated: BTreeMap<u64, Vec<(u64, u64)>>,
    /// Each closed transfer, by instruction: what says it never comes back, and whose "never" it is.
    nevers: BTreeMap<u64, (Never, Closer)>,
    /// The instructions that enter the supervisor, as the language's own
    /// user-operation table says.
    supervisor: BTreeSet<u64>,
    /// Where the last decode left the decoder's context, which the lifter keeps for the next one where it follows on.
    context: Option<Continuation>,
    reached: Reached,
    /// Whether an operation since the last ask leaves; stops are counted from `unresolved` past `asked`.
    leaving: bool,
    /// How many of `unresolved` the last ask reported.
    asked: usize,
    /// Each call and the landing pad it unwinds to, in the order recorded: each instruction once.
    unwinds: Vec<(u64, u64)>,
    /// The walk of the pads, which never writes this walk's state; `None` until a call unwinds.
    pads: Option<Box<Walk>>,
    /// The pads this walk, as a pads' walk, was started from: each once.
    seeded: BTreeSet<u64>,
    /// What this walk does with its calls' pads (D599).
    unwinding: Unwinds,
    /// The extent of the pads a trace walked, its walk of them dropped.
    pad_extent: Option<Box<PadExtent>>,
}

impl Walk {
    /// Walk the body at `entry`, past every call the program says returns, keeping what `keep` says.
    fn start(
        entry: u64,
        reader: Reader,
        dispatched: BTreeMap<u64, Vec<u64>>,
        keep: Keep,
        unwinding: Unwinds,
    ) -> Result<Self, BodyError> {
        let Reader { disasm, program } = reader;
        let mut walk = Self {
            entry,
            dispatched,
            link: program.return_address_register(),
            decoded: BTreeMap::new(),
            return_addresses: BTreeMap::new(),
            lifted: (keep != Keep::Nothing).then(BTreeMap::new),
            decodes: keep == Keep::Decodes,
            last: None,
            leaders: BTreeSet::from([entry]),
            arms: BTreeSet::new(),
            direct: BTreeSet::new(),
            calls: BTreeSet::new(),
            loads: BTreeSet::new(),
            tail_calls: BTreeSet::new(),
            call_sites: Vec::new(),
            tail_sites: Vec::new(),
            slot_calls: BTreeMap::new(),
            halting: BTreeSet::new(),
            handles: Handles::default(),
            proven: Vec::new(),
            ends_unproven: 0,
            holds_values: program.holds_values(),
            falls_into: BTreeSet::new(),
            target_contexts: BTreeMap::new(),
            unresolved: Vec::new(),
            gated: BTreeMap::new(),
            nevers: BTreeMap::new(),
            supervisor: BTreeSet::new(),
            context: None,
            reached: Reached::default(),
            leaving: false,
            asked: 0,
            unwinds: Vec::new(),
            pads: None,
            seeded: BTreeSet::new(),
            unwinding,
            pad_extent: None,
        };
        let Some(first) = walk.decode(entry, disasm, program) else {
            return Err(match walk.unresolved.last().map(|stop| stop.reason) {
                Some(UnresolvedReason::Unmapped) => BodyError::EntryUnmapped(entry),
                Some(UnresolvedReason::NotExecutable) => BodyError::EntryNotExecutable(entry),
                Some(UnresolvedReason::Unbacked) => BodyError::EntryUnbacked(entry),
                Some(UnresolvedReason::Relocated) => BodyError::EntryRelocated(entry),
                _ => BodyError::EntryUndecodable(entry),
            });
        };
        let (pending, previous) = walk.record(first, None, program);
        walk.run(pending, previous, disasm, program);
        walk.walk_pads(disasm, program);
        Ok(walk)
    }

    fn open(&mut self, callee: u64, disasm: &Disassembler, program: &dyn Program) {
        let mut pending = Vec::new();
        for (_, next) in self.gated.remove(&callee).unwrap_or_default() {
            self.continues(Some(next), &mut pending, program);
        }
        self.run(pending, None, disasm, program);
    }

    /// Walk every landing pad not yet decoded, where this walk walks pads at all (D599).
    fn walk_pads(&mut self, disasm: &Disassembler, program: &dyn Program) {
        // A pads' walk is made only for a call that unwinds.
        if self.unwinding != Unwinds::Walk || self.unwinds.is_empty() {
            return;
        }
        let keep = match (&self.lifted, self.decodes) {
            (None, _) => Keep::Nothing,
            (Some(_), false) => Keep::Lifts,
            (Some(_), true) => Keep::Decodes,
        };
        let walk = self.pads.get_or_insert_with(|| {
            Box::new(Walk::beside(
                self.entry,
                &self.dispatched,
                self.link.clone(),
                keep,
                program,
            ))
        });
        walk.grow(&self.decoded, &self.unwinds, disasm, program);
    }

    /// As the pads' walk, walk every pad `unwinds` or its own calls name that neither it nor the normal
    /// flow decoded, stopping where `normal` decoded. A worklist: each pad is seeded once.
    fn grow(
        &mut self,
        normal: &BTreeMap<u64, u32>,
        unwinds: &[(u64, u64)],
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        loop {
            let mut fresh = (unwinds.iter().chain(&self.unwinds))
                .map(|(_, pad)| pad)
                .filter(|pad| !normal.contains_key(pad) && !self.seeded.contains(pad))
                .copied()
                .collect::<Vec<_>>();
            if fresh.is_empty() {
                return;
            }
            fresh.sort_unstable();
            fresh.dedup();
            self.leaders.extend(fresh.iter().copied());
            self.seeded.extend(fresh.iter().copied());
            self.run_beside(fresh, normal, disasm, program);
        }
    }

    /// An empty walk of the pads of the body at `entry`, with that body's tables.
    fn beside(
        entry: u64,
        dispatched: &BTreeMap<u64, Vec<u64>>,
        link: Option<r2il::Varnode>,
        keep: Keep,
        program: &dyn Program,
    ) -> Self {
        Self {
            entry,
            dispatched: dispatched.clone(),
            link,
            decoded: BTreeMap::new(),
            return_addresses: BTreeMap::new(),
            lifted: (keep != Keep::Nothing).then(BTreeMap::new),
            decodes: keep == Keep::Decodes,
            last: None,
            leaders: BTreeSet::new(),
            arms: BTreeSet::new(),
            direct: BTreeSet::new(),
            calls: BTreeSet::new(),
            loads: BTreeSet::new(),
            tail_calls: BTreeSet::new(),
            call_sites: Vec::new(),
            tail_sites: Vec::new(),
            slot_calls: BTreeMap::new(),
            halting: BTreeSet::new(),
            handles: Handles::default(),
            proven: Vec::new(),
            ends_unproven: 0,
            holds_values: program.holds_values(),
            falls_into: BTreeSet::new(),
            target_contexts: BTreeMap::new(),
            unresolved: Vec::new(),
            gated: BTreeMap::new(),
            nevers: BTreeMap::new(),
            supervisor: BTreeSet::new(),
            context: None,
            reached: Reached::default(),
            leaving: false,
            asked: 0,
            unwinds: Vec::new(),
            pads: None,
            seeded: BTreeSet::new(),
            unwinding: Unwinds::Record,
            pad_extent: None,
        }
    }

    /// Go on through the arms of dispatches the walk stopped at, as a walk told them from the start would.
    fn follow(
        &mut self,
        arms: &BTreeMap<u64, Vec<u64>>,
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        let pending = self.told(arms, program);
        self.run(pending, None, disasm, program);
    }

    /// Take the arms of `arms`, and answer where the walk goes on: the arms of each dispatch it stopped at.
    fn told(&mut self, arms: &BTreeMap<u64, Vec<u64>>, program: &dyn Program) -> Vec<u64> {
        let arms = arms.iter().filter(|(_, targets)| !targets.is_empty());
        // Every arm is told first, so a dispatch first reached through an arm is followed too.
        (self.dispatched).extend(arms.clone().map(|(addr, targets)| (*addr, targets.clone())));
        let mut pending = Vec::new();
        for (&addr, targets) in arms {
            let stopped = |stop: &Unresolved| {
                (stop.addr, stop.reason) == (addr, UnresolvedReason::IndirectBranch)
            };
            if !self.unresolved.iter().any(stopped) {
                continue;
            }
            self.retract(stopped);
            for target in targets.iter().collect::<BTreeSet<_>>() {
                self.arms.insert(*target);
                self.transfer(addr, *target, &mut pending, program);
            }
        }
        pending
    }

    /// Walk on from `pending` as the pads' walk, stopping where `normal` decoded.
    fn run_beside(
        &mut self,
        pending: Vec<u64>,
        normal: &BTreeMap<u64, u32>,
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        self.run_outside(pending, None, Some(normal), Reader { disasm, program });
    }

    /// Walk on from `pending`; `previous` is the lift recorded last where `lifted` keeps none.
    fn run(
        &mut self,
        pending: Vec<u64>,
        previous: Option<Instruction>,
        disasm: &Disassembler,
        program: &dyn Program,
    ) {
        self.run_outside(pending, previous, None, Reader { disasm, program });
    }

    /// Walk on from `pending`, never into an instruction `outside` holds.
    fn run_outside(
        &mut self,
        mut pending: Vec<u64>,
        mut previous: Option<Instruction>,
        outside: Option<&BTreeMap<u64, u32>>,
        reader: Reader,
    ) {
        let Reader { disasm, program } = reader;
        // Arms wait for every start the instructions state, lowest first: an arm inside an instruction loses to it.
        let mut held = BTreeSet::new();
        loop {
            let (addr, released) = match pending.pop() {
                Some(addr) => (addr, false),
                None => match held.pop_first() {
                    Some(addr) => (addr, true),
                    None => break,
                },
            };
            if self.decoded.contains_key(&addr) || outside.is_some_and(|o| o.contains_key(&addr)) {
                continue;
            }
            let arm = self.arms.contains(&addr) && !self.direct.contains(&addr);
            if arm && !released {
                held.insert(addr);
                continue;
            }
            if arm && let Some(with) = self.inside(addr, 1) {
                self.overlap(addr, with);
                continue;
            }
            if self.decoded.len() >= BODY_INSTRUCTIONS {
                self.stop(addr, UnresolvedReason::Budget);
                break;
            }
            let Some(instruction) = self.decode(addr, disasm, program) else {
                continue;
            };
            let end = u64::from(instruction.lifted.size) - 1;
            if arm && let Some(with) = self.inside(addr + 1, end) {
                self.overlap(addr, with);
                continue;
            }
            self.supervisor
                .extend(instruction.supervisor.then_some(addr));
            let (successors, kept) = self.record(instruction, previous.as_ref(), program);
            pending.extend(successors);
            previous = kept;
        }
        // A resumed walk starts after a call, not after the lift this run recorded last.
        self.last = None;
    }

    /// The start of a decoded instruction sharing a byte with `[at, at + len)` that does not begin at `at`'s
    /// instruction. `O(log n)`.
    fn inside(&self, at: u64, len: u64) -> Option<u64> {
        let before = (self.decoded.range(..at).next_back())
            .filter(|(start, size)| *start + u64::from(**size) > at)
            .map(|(start, _)| *start);
        before.or_else(|| {
            self.decoded
                .range(at..at + len)
                .next()
                .map(|(start, _)| *start)
        })
    }

    /// Refuse an instruction that overlaps one decoded, once per pair.
    fn overlap(&mut self, addr: u64, with: u64) {
        let reason = UnresolvedReason::Overlaps { with };
        if !self
            .unresolved
            .iter()
            .any(|stop| (stop.addr, stop.reason) == (addr, reason))
        {
            self.stop(addr, reason);
        }
    }

    /// Decode one instruction, or record why control stops here.
    fn decode(
        &mut self,
        addr: u64,
        disasm: &Disassembler,
        program: &dyn Program,
    ) -> Option<Instruction> {
        let Some(mut window) = program.read(addr, WINDOW) else {
            return self.stop(addr, UnresolvedReason::Unmapped);
        };
        let Some(region) = program.region(addr).filter(|region| region.execute) else {
            return self.stop(addr, UnresolvedReason::NotExecutable);
        };
        // An instruction reaching into the zero fill reads only bytes the file or a patch holds.
        let backed = |at: u64| at < region.file_end || program.patched(at);
        let held = (0..window.len() as u64)
            .take_while(|offset| backed(addr + offset))
            .count();
        if held == 0 {
            return self.stop(addr, UnresolvedReason::Unbacked);
        }
        window.truncate(held);
        let available = window.len();
        // What runs is what the loader leaves, so a field it writes decodes as the value it writes.
        let endian = disasm.arch_spec().memory_endianness;
        let code = crate::stated::code(program.loader_writes(), addr, window, endian);
        // Sleigh fetches a whole window whatever the instruction needs, so a
        // short one is padded and the decoded size checked against what is real.
        let mut fetch = code.bytes.clone();
        fetch.resize(WINDOW, 0);

        // The decoder's context continues where this follows the last decode, exactly as a block lift of the same bytes would.
        let Ok(one) = disasm.lift_after(&fetch, addr, self.context) else {
            return self.stop(addr, UnresolvedReason::Undecodable);
        };
        let lifted = one.block;
        if lifted.size == 0 {
            return self.stop(addr, UnresolvedReason::Undecodable);
        }
        if lifted.size as usize > available {
            return self.stop(addr, UnresolvedReason::Truncated);
        }
        if code.unstated(&(addr..addr + u64::from(lifted.size))) {
            return self.stop(addr, UnresolvedReason::Relocated);
        }

        // Whether a call comes back is the callee's fact, decided where it is recorded.
        let terminator = BasicBlock::from_r2il_continuing(&lifted, true).terminator;
        let bytes = fetch[..lifted.size as usize].to_vec();
        self.context = Some(one.continuation);
        for target in one.targets {
            self.target_contexts
                .entry(target.address)
                .or_insert(target.foreign);
        }
        let decode = self.decodes.then(|| Box::new((fetch, one.continuation)));
        let arch = disasm.arch_spec();
        let (supervisor, vector) = supervisor_entry(&lifted.ops, arch);
        let halts = (vector.and_then(|vector| program.interrupt_halts(&arch.name, vector)))
            .or_else(|| {
                supervisor
                    .then(|| program.supervisor_halts(self.entry, addr))
                    .flatten()
            });
        Some(Instruction {
            lifted,
            bytes,
            terminator,
            decode,
            halts,
            supervisor,
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
        while let Some((start, size)) = self.decoded.range(..at).next_back() {
            if start + u64::from(*size) != at {
                return false;
            }
            if self
                .return_addresses
                .get(start)
                .is_some_and(|addresses| addresses.contains(&next))
            {
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

    /// Follow a transfer, or end the body where it leaves for another function's entry; its own entry is a loop.
    fn transfer(
        &mut self,
        site: u64,
        target: u64,
        successors: &mut Vec<u64>,
        program: &dyn Program,
    ) {
        if target != self.entry && program.is_entry(target) {
            if self.tail_calls.insert(target) {
                self.reached.tail_calls.push(target);
            }
            self.tail_sites.push((target, site));
            return;
        }
        self.leaders.insert(target);
        successors.push(target);
        // A branch into a proven run reaches the transfer with a value nothing proved.
        let (entered, kept) = std::mem::take(&mut self.proven)
            .into_iter()
            .partition::<Vec<_>, _>(|(from, at, _)| *from < target && target <= *at);
        self.proven = kept;
        for (_, at, after) in entered {
            self.halting.remove(&at);
            self.nevers.remove(&at);
            match after {
                Some(after) => self.continues(Some(after), successors, program),
                None => _ = self.stop(at, UnresolvedReason::IndirectBranch),
            }
        }
    }

    /// Drop the overlap stops at `addr`: an instruction states a start there, so it is no arm's guess.
    fn retract_overlaps(&mut self, addr: u64) {
        self.retract(|stop| {
            stop.addr == addr && matches!(stop.reason, UnresolvedReason::Overlaps { .. })
        });
    }

    /// Drop the stops `gone` names, keeping `asked` the count of reported stops still held.
    fn retract(&mut self, gone: impl Fn(&Unresolved) -> bool) {
        let (mut index, asked) = (0, self.asked);
        self.unresolved.retain(|stop| {
            index += 1;
            let drop = gone(stop);
            self.asked -= usize::from(drop && index <= asked);
            !drop
        });
    }

    /// Follow a branch's target, a start the instruction states.
    fn branch(&mut self, site: u64, target: u64, successors: &mut Vec<u64>, program: &dyn Program) {
        if self.direct.insert(target) {
            self.retract_overlaps(target);
        }
        self.transfer(site, target, successors, program);
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

    /// Keep an instruction, and answer where the walk goes next and the lift where `lifted` keeps none.
    fn record(
        &mut self,
        mut instruction: Instruction,
        previous: Option<&Instruction>,
        program: &dyn Program,
    ) -> (Vec<u64>, Option<Instruction>) {
        let addr = instruction.lifted.addr;
        let next = instruction.end();
        let mut successors = Vec::new();
        self.loads.extend(constant_loads(&instruction.lifted.ops));
        if self.handles.at != Some(addr) || self.leaders.contains(&addr) {
            self.handles = Handles::default();
        }
        let handles_before = self.handles.held.clone();
        if self.holds_values {
            self.handles.step(&instruction.lifted, program);
            self.handles.at = Some(next);
        }
        if let BlockTerminator::IndirectCall { fallthrough } = instruction.terminator
            && let Some(target) = self.folded_call(&instruction, previous)
        {
            instruction.terminator = BlockTerminator::Call {
                target,
                fallthrough,
            };
        }

        // The unwinder looks a call up by its return address less one (D570), whether or not it returns.
        if let BlockTerminator::Call { .. } | BlockTerminator::IndirectCall { .. } =
            instruction.terminator
            && self.unwinding != Unwinds::Ignore
            && let Some(pad) = program.landing_pad(next - 1)
        {
            self.unwinds.push((addr, pad));
        }
        match instruction.terminator {
            // A supervisor call or an interrupt a kernel document says never comes back (D229, D505).
            BlockTerminator::IndirectCall { .. } | BlockTerminator::Fallthrough { .. }
                if let Some(citation) = instruction.halts =>
            {
                self.halting.insert(addr);
                self.nevers
                    .insert(addr, (Never::cited(citation), Closer::Site));
            }
            BlockTerminator::Fallthrough { next: after } => {
                self.continues(Some(after), &mut successors, program)
            }
            BlockTerminator::Branch { target } => {
                self.branch(addr, target, &mut successors, program)
            }
            // The arm that leaves is a return or an indirect transfer, either of which may hand control back.
            BlockTerminator::ConditionalExit { next: after } => {
                self.leaving = true;
                self.continues(Some(after), &mut successors, program)
            }
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                self.branch(addr, true_target, &mut successors, program);
                self.branch(addr, false_target, &mut successors, program);
            }
            BlockTerminator::Call {
                target,
                fallthrough,
            } => {
                if self.calls.insert(target) {
                    self.reached.calls.push(target);
                }
                self.call_sites.push((target, addr));
                // A predicated call reaches the next instruction when its predicate fails, whatever the callee does.
                let predicated = r2il::predicated_call(&instruction.lifted.ops, next);
                let foreign = self.target_contexts.get(&target).copied().unwrap_or(false);
                // A call to an import stub whose row halts on the argument it is handed (D211).
                let halts = (!predicated)
                    .then(|| program.halts_on(target))
                    .flatten()
                    .and_then(|halt| holding(&handles_before, halt));
                match (predicated || program.returns(target, foreign), fallthrough) {
                    _ if let Some((from, never)) = halts => {
                        self.halting.insert(addr);
                        self.proven.push((from, addr, fallthrough));
                        self.nevers.insert(addr, (never, Closer::Site));
                    }
                    (true, _) => self.continues(fallthrough, &mut successors, program),
                    // The bytes after a call not known to return may be the next function's.
                    (false, Some(after)) => {
                        if let Some(never) = program.exit(target, foreign) {
                            self.nevers.insert(addr, (never, Closer::Callee));
                        }
                        self.gate(target, addr, after);
                    }
                    (false, None) => self.ends_unproven += 1,
                }
            }
            // A call through a register is opaque, so it is assumed to come
            // back -- unless it calls through a slot whose pointer the
            // program states, and what it states there never returns.
            BlockTerminator::IndirectCall { fallthrough } => {
                let ops = &instruction.lifted.ops;
                let at = ops
                    .iter()
                    .rposition(|op| matches!(op, r2il::R2ILOp::CallInd { .. }));
                let through = at.and_then(|at| r2ssa::loaded_target_slot(&instruction.lifted, at));
                let through = through.map(|slot| slot.offset);
                if let Some(slot) = through
                    && crate::stated::sealed_import(program, slot).is_some()
                {
                    self.slot_calls.insert(addr, slot);
                }
                let halts = self.halts_through(&instruction, &handles_before, program);
                let exit = through.and_then(|slot| program.exit_through(slot));
                if let Some((from, never)) = halts {
                    // A call that terminates the current process (D229), as S17's tail jump.
                    self.halting.insert(addr);
                    self.proven.extend(from.map(|from| (from, addr, None)));
                    // Through a slot whose import never returns, the "never" is the callee's.
                    let closer = from.map_or(Closer::Callee, |_| Closer::Site);
                    self.nevers.insert(addr, (never, closer));
                } else if let Some(never) = exit {
                    self.halting.insert(addr);
                    self.nevers.insert(addr, (never, Closer::Callee));
                } else {
                    self.continues(fallthrough, &mut successors, program)
                }
            }
            // A switch is an indirect branch through a table, so it is one
            // case rather than two: both go wherever a previous pass proved
            // the dispatch reads, and both stop where nothing did.
            BlockTerminator::IndirectBranch | BlockTerminator::Switch { .. } => {
                match self.halts_through(&instruction, &handles_before, program) {
                    Some((from, never)) => {
                        self.halting.insert(addr);
                        self.proven.extend(from.map(|from| (from, addr, None)));
                        self.nevers.insert(addr, (never, Closer::Branch));
                    }
                    None => self.dispatch(addr, next, &mut successors, program),
                }
            }
            BlockTerminator::Return => self.leaving = true,
            // A trap has nowhere to go, and no statement says the process ends there.
            BlockTerminator::None => self.ends_unproven += 1,
        }

        if ends_block(&instruction.terminator) {
            self.leaders.insert(next);
        }
        if let Some(link) = &self.link {
            let addresses =
                r2il::return_addresses(&instruction.lifted.ops, link).collect::<Box<[_]>>();
            if !addresses.is_empty() {
                self.return_addresses.insert(addr, addresses);
            }
        }
        self.decoded.insert(addr, instruction.lifted.size);
        self.last = Some(addr);
        match &mut self.lifted {
            Some(lifted) => {
                lifted.insert(addr, instruction);
                (successors, None)
            }
            None => (successors, Some(instruction)),
        }
    }

    /// The constant an indirect call's target folds to over this instruction and the one the walk
    /// recorded just before it, where control reaches it only from that one and neither branches.
    fn folded_call(
        &self,
        instruction: &Instruction,
        previous: Option<&Instruction>,
    ) -> Option<u64> {
        let ops = &instruction.lifted.ops;
        let at = ops.iter().position(r2il::R2ILOp::is_control_flow)?;
        let r2il::R2ILOp::CallInd { target } = &ops[at] else {
            return None;
        };
        let previous = match &self.lifted {
            Some(lifted) => lifted.get(&self.last?),
            None => previous.filter(|_| self.last.is_some()),
        }
        .filter(|previous| {
            previous.end() == instruction.lifted.addr
                && !self.leaders.contains(&instruction.lifted.addr)
                && !previous
                    .lifted
                    .ops
                    .iter()
                    .any(r2il::R2ILOp::is_control_flow)
        });
        let mut origins = r2ssa::origin::BlockOrigins::default();
        for op in previous
            .into_iter()
            .flat_map(|previous| &previous.lifted.ops)
        {
            origins.step(op);
        }
        for op in &ops[..at] {
            origins.step(op);
        }
        origins.of(target)?.constant()
    }

    /// Whether a tail jump through an import slot never returns: `None` where the import never
    /// does, `Some(from)` where a handle the call at `from` yielded makes it not.
    fn halts_through(
        &self,
        instruction: &Instruction,
        held: &[Held],
        program: &dyn Program,
    ) -> Option<(Option<u64>, Never)> {
        let ops = &instruction.lifted.ops;
        // An indirect branch or call: r2il's transfer names no direct target.
        let transfer = |op: &r2il::R2ILOp| op.transfer().is_some_and(|transfer| !transfer.direct);
        let at = ops.iter().rposition(transfer)?;
        let slot = r2ssa::loaded_target_slot(&instruction.lifted, at)?.offset;
        crate::stated::sealed_import(program, slot)?;
        // Only a proven "never" halts a transfer; a bound's call stays closed, and its tail goes on.
        if let Some(never) = (program.exit_through(slot)).filter(|never| never.proves().is_some()) {
            return Some((None, never));
        }
        holding(held, program.halts_on_through(slot)?).map(|(from, never)| (Some(from), never))
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
            self.arms.insert(target);
            self.transfer(addr, target, successors, program);
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
    fn into_body(mut self) -> (Body, Vec<Decoded>) {
        let pads = self.pads.take();
        let unwinds = std::mem::take(&mut self.unwinds);
        let (mut body, mut decodes) = self.normal_body();
        let (held, pad_decodes) = finish_pads(pads, &self.decoded, unwinds);
        decodes.extend(pad_decodes);
        decodes.sort_by_key(|decoded| decoded.lift.addr);
        body.pads = held;
        (body, decodes)
    }

    /// The body of this walk's own blocks, its pads aside.
    fn normal_body(&mut self) -> (Body, Vec<Decoded>) {
        let closed = self.closed();
        let lifted = self.lifted.take().unwrap_or_default();
        let spans = self.spans(lifted.iter().map(|(addr, lift)| (*addr, lift)), &closed);
        let ending = self.ending();
        let (mut lifted, mut decodes) = (lifted.into_values(), Vec::new());
        let mut blocks = Vec::with_capacity(spans.len());
        for span in &spans {
            let mut parts = lifted.by_ref().take(span.len).collect::<Vec<_>>();
            decodes.extend(parts.iter_mut().filter_map(|instruction| {
                let (window, continuation) = *instruction.decode.take()?;
                let lift = instruction.lifted.clone();
                Some(Decoded {
                    lift,
                    window,
                    continuation,
                })
            }));
            blocks.push(finish(&mut parts, &ending, span.closed));
        }
        (self.body_of(self.entry, blocks, &spans, &closed), decodes)
    }

    /// The blocks walked so far by place, no lift copied. O(instructions).
    fn shape(&self) -> Shape {
        let closed = self.closed();
        let lifts = (self.lifted.iter().flatten()).collect::<Vec<_>>();
        let spans = self.spans(lifts.iter().map(|(addr, lift)| (**addr, *lift)), &closed);
        let ending = self.ending();
        let blocks = spans.iter().map(|span| {
            let parts = lifts[span.first..span.first + span.len]
                .iter()
                .map(|(_, lift)| *lift);
            let parts = parts.collect::<Vec<_>>();
            let successors = successors_after(&parts, &ending, span.closed);
            (
                span.start,
                successors.into_iter().map(|(_, to)| to).collect(),
            )
        });
        Shape {
            blocks: blocks.collect(),
            spans,
        }
    }

    /// The blocks of `shape` that `keep` holds, entered at `entry`: only their lifts are copied, and
    /// the body's calls, stops and exits are the whole walk's. O(instructions + kept operations).
    fn cut(&self, shape: &Shape, entry: u64, keep: &[bool]) -> (Body, usize) {
        let closed = self.closed();
        let lifts = (self.lifted.iter().flatten()).collect::<Vec<_>>();
        let ending = self.ending();
        let (mut blocks, mut copied) = (Vec::new(), 0);
        for (span, _) in (shape.spans.iter().zip(keep)).filter(|(_, kept)| **kept) {
            let parts = lifts[span.first..span.first + span.len].iter();
            let mut parts = parts.map(|(_, lift)| lift.copied()).collect::<Vec<_>>();
            copied += parts.len();
            blocks.push(finish(&mut parts, &ending, span.closed));
        }
        (self.body_of(entry, blocks, &shape.spans, &closed), copied)
    }

    /// The calls that end their block closed: gated on a callee not known to return, or halting.
    fn closed(&self) -> BTreeSet<u64> {
        (self.gated.values().flatten())
            .map(|(call, _)| *call)
            .chain(self.halting.iter().copied())
            .collect()
    }

    fn ending(&self) -> Ending<'_> {
        Ending {
            link: self.link.as_ref(),
            dispatched: &self.dispatched,
            tail_calls: &self.tail_calls,
            slot_calls: &self.slot_calls,
        }
    }

    /// Where each block of `lifted` (in address order) starts and how many instructions it holds:
    /// a block ends where control leaves, a leader begins, a hole opens or a call is `closed`. O(instructions).
    fn spans<'a>(
        &self,
        lifted: impl Iterator<Item = (u64, &'a Instruction)>,
        closed: &BTreeSet<u64>,
    ) -> Vec<Span> {
        let (mut spans, mut open) = (Vec::new(), None::<(Span, u64)>);
        for (index, (addr, instruction)) in lifted.enumerate() {
            let broken = open.is_some_and(|(_, end)| end != addr || self.leaders.contains(&addr));
            if broken {
                spans.extend(open.take().map(|(span, _)| span));
            }
            let (mut span, _) = open.unwrap_or((
                Span {
                    first: index,
                    len: 0,
                    start: addr,
                    closed: false,
                },
                addr,
            ));
            span.len += 1;
            let ends = closed.contains(&addr);
            open = Some((span, instruction.end()));
            if ends || ends_block(&instruction.terminator) {
                span.closed = ends;
                spans.push(span);
                open = None;
            }
        }
        spans.extend(open.map(|(span, _)| span));
        spans
    }

    /// The body of `blocks`, each call still closed ending its block with what says it never comes
    /// back (D384), placed among `spans` by binary search: `O(c log b)`.
    fn body_of(
        &self,
        entry: u64,
        blocks: Vec<BodyBlock>,
        spans: &[Span],
        closed: &BTreeSet<u64>,
    ) -> Body {
        let block_of = |call: u64| {
            let after = spans.partition_point(|span| span.start <= call);
            Some(spans.get(after.checked_sub(1)?)?.start)
        };
        let mut exits = r2ssa::AssumedExits::default();
        for (call, (never, closer)) in &self.nevers {
            let callee = match closer {
                Closer::Callee => true,
                Closer::Site => false,
                Closer::Branch => continue,
            };
            if let Some(block) = block_of(*call).filter(|_| closed.contains(call)) {
                exits.sites.push(r2ssa::ExitSite {
                    block,
                    never: never.clone(),
                    callee,
                });
            }
        }
        exits.sites.sort_unstable_by_key(|site| site.block);
        exits.sites.dedup_by_key(|site| site.block);
        Body {
            entry,
            blocks,
            calls: self.calls.iter().copied().collect(),
            tail_calls: self.tail_calls.iter().copied().collect(),
            unresolved: self.unresolved.clone(),
            exits,
            pads: Pads::default(),
        }
    }
}

/// The pads `pads` walked beside a normal flow that decoded `normal`, its calls unwinding as
/// `unwinds` says: an instruction both decoded is the normal flow's. O(pad instructions).
fn finish_pads(
    pads: Option<Box<Walk>>,
    normal: &BTreeMap<u64, u32>,
    mut unwinds: Vec<(u64, u64)>,
) -> (Pads, Vec<Decoded>) {
    let Some(mut pads) = pads else {
        unwinds.sort_unstable();
        let held = Pads {
            unwinds,
            ..Pads::default()
        };
        return (held, Vec::new());
    };
    (pads.lifted.iter_mut()).for_each(|lifted| lifted.retain(|addr, _| !normal.contains_key(addr)));
    pads.decoded.retain(|addr, _| !normal.contains_key(addr));
    unwinds.extend(std::mem::take(&mut pads.unwinds));
    unwinds.sort_unstable();
    unwinds.dedup();
    let (walked, decodes) = pads.normal_body();
    let held = Pads {
        blocks: walked.blocks,
        unwinds,
    };
    (held, decodes)
}

/// The pads of `body`, a walk that recorded its calls' unwinds and walked none (D599): what a
/// listing reads beside the blocks. O(body instructions + pad instructions).
pub fn pads_beside(
    body: &Body,
    dispatched: &BTreeMap<u64, Vec<u64>>,
    disasm: &Disassembler,
    program: &dyn Program,
) -> Pads {
    let normal = (body.blocks.iter())
        .flat_map(|block| block.lifted.instructions.iter().map(|run| (run.addr, 0)))
        .collect::<BTreeMap<_, _>>();
    let unwinds = body.pads.unwinds.clone();
    let link = program.return_address_register();
    let mut walk = Walk::beside(body.entry, dispatched, link, Keep::Lifts, program);
    walk.grow(&normal, &unwinds, disasm, program);
    finish_pads(Some(Box::new(walk)), &normal, unwinds).0
}

/// One block among a walk's lifts in address order: `len` instructions from the `first`th, the
/// first at `start`, and whether a closed call ends it.
#[derive(Debug, Clone, Copy)]
struct Span {
    first: usize,
    len: usize,
    start: u64,
    closed: bool,
}

/// A walk's blocks by place, no lift copied (D367): what a round indexes its regions over.
#[derive(Debug)]
pub struct Shape {
    spans: Vec<Span>,
    /// Each block's start and the addresses control goes to from it, in address order.
    pub blocks: Vec<(u64, Vec<u64>)>,
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

/// The call through a sealed import slot an instruction makes, which the walk recorded.
fn slot_call(
    instruction: &Instruction,
    base: usize,
    slot_calls: &BTreeMap<u64, u64>,
) -> Option<Transfer> {
    let slot = *slot_calls.get(&instruction.lifted.addr)?;
    let ops = &instruction.lifted.ops;
    let at = ops
        .iter()
        .rposition(|op| matches!(op, r2il::R2ILOp::CallInd { .. }))?;
    Some(Transfer {
        op: base + at,
        target: slot,
        kind: r2source::AdvisoryCallTransfer::CallSlot,
    })
}

/// What ending a block reads of the walk.
struct Ending<'a> {
    link: Option<&'a r2il::Varnode>,
    dispatched: &'a BTreeMap<u64, Vec<u64>>,
    tail_calls: &'a BTreeSet<u64>,
    slot_calls: &'a BTreeMap<u64, u64>,
}

/// The transfer to another function an instruction ends in, at `base`, its first operation's
/// index in the block: a call (folded or not) or a branch to an entry.
fn transfer_of(
    instruction: &Instruction,
    base: usize,
    tail_calls: &BTreeSet<u64>,
) -> Option<Transfer> {
    let (target, kind) = match instruction.terminator {
        BlockTerminator::Call { target, .. } => (target, r2source::AdvisoryCallTransfer::Call),
        BlockTerminator::Branch { target } if tail_calls.contains(&target) => {
            (target, r2source::AdvisoryCallTransfer::TailJump)
        }
        // A conditional branch whose arm is another function's entry: a predicated tail call.
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => match (
            tail_calls.contains(&true_target),
            tail_calls.contains(&false_target),
        ) {
            (true, false) => (true_target, r2source::AdvisoryCallTransfer::TailJump),
            (false, true) => (false_target, r2source::AdvisoryCallTransfer::TailJump),
            _ => return None,
        },
        _ => return None,
    };
    // The operation that transfers there: a guarded branch is the one naming the arm, not the guard.
    let at = match kind {
        r2source::AdvisoryCallTransfer::TailJump => {
            instruction.lifted.ops.iter().position(|op| {
                op.transfer()
                    .is_some_and(|transfer| transfer.direct && transfer.target.offset == target)
            })?
        }
        _ => instruction
            .lifted
            .ops
            .iter()
            .position(r2il::R2ILOp::is_control_flow)?,
    };
    Some(Transfer {
        op: base + at,
        target,
        kind,
    })
}

/// One block from the instructions collected for it, with its last instruction's successors, or none where that call is `closed`.
/// Where control goes after the block of `parts`, `closed` where a call ends it closed.
fn successors_after<P: std::borrow::Borrow<Instruction>>(
    parts: &[P],
    ending: &Ending<'_>,
    closed: bool,
) -> Vec<(AdvisorySuccessorKind, u64)> {
    let (link, dispatched) = (ending.link, ending.dispatched);
    let last = parts
        .last()
        .expect("a block holds at least one instruction")
        .borrow();
    let end = last.end();
    // A transfer the block returns from continues after it, whatever the
    // opcode was: the link register holding the address after the block is
    // what says so, and the walk followed it for the same reason.
    let returns = matches!(last.terminator, BlockTerminator::IndirectBranch)
        && link.is_some_and(|link| {
            (parts.iter()).any(|part| r2il::returns_to(&part.borrow().lifted.ops, end, link))
        });
    let arms = dispatched
        .get(&last.lifted.addr)
        .map(Vec::as_slice)
        .unwrap_or_default();
    match (closed, returns) {
        (true, _) => Vec::new(),
        (false, true) => vec![(AdvisorySuccessorKind::Fallthrough, end)],
        (false, false) => successors_of(&last.terminator, end, arms),
    }
}

fn finish(parts: &mut Vec<Instruction>, ending: &Ending<'_>, closed: bool) -> BodyBlock {
    let start = parts[0].lifted.addr;
    let end = parts
        .last()
        .expect("a block holds at least one instruction")
        .end();
    let successors = successors_after(parts, ending, closed);
    let size = u32::try_from(end - start).unwrap_or(u32::MAX);
    let mut bytes = Vec::with_capacity(size as usize);
    for part in parts.iter() {
        bytes.extend_from_slice(&part.bytes);
    }
    let mut transfers = Vec::new();
    let mut base = 0;
    for part in parts.iter() {
        transfers.extend(transfer_of(part, base, ending.tail_calls));
        transfers.extend(slot_call(part, base, ending.slot_calls));
        base += part.lifted.ops.len();
    }
    let lifted = R2ILBlock::join(start, size, parts.drain(..).map(|part| part.lifted));
    // A tail transfer through a loaded slot leaves by what the slot holds: the slot is its target.
    if let Some(last) = lifted.ops.len().checked_sub(1)
        && let Some(slot) = r2ssa::terminal_indirect_loaded_slot(&lifted, last)
    {
        transfers.push(Transfer {
            op: last,
            target: slot.offset,
            kind: r2source::AdvisoryCallTransfer::TailSlot,
        });
    }
    BodyBlock {
        lifted,
        bytes,
        successors,
        transfers,
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

#[cfg(test)]
mod transfer_tests {
    use super::*;

    struct Nothing;

    impl Program for Nothing {
        fn read(&self, _vaddr: u64, _max: usize) -> Option<Vec<u8>> {
            None
        }
        fn region(&self, _vaddr: u64) -> Option<Region> {
            None
        }
        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    /// `mov edi, 2` holds a constant a halting row reads; ARM's `moveq r0, #1` writes it only past
    /// the instruction's own branch, so it holds nothing (D211).
    #[test]
    fn a_constant_written_past_a_branch_inside_the_instruction_is_not_held() {
        let rdi = r2il::Varnode::register(0x38, 8);
        let plain = |lifted: &mut R2ILBlock| {
            lifted.push(r2il::R2ILOp::Copy {
                dst: rdi.clone(),
                src: r2il::Varnode::constant(2, 8),
            });
        };
        let mut unconditional = R2ILBlock::new(0x1000, 5);
        plain(&mut unconditional);
        let mut handles = Handles::default();
        handles.step(&unconditional, &Nothing);
        assert_eq!(handles.held.len(), 1);
        let mut predicated = R2ILBlock::new(0x1000, 4);
        predicated.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x1004, 8),
            cond: r2il::Varnode::unique(0x10, 1),
        });
        plain(&mut predicated);
        let mut handles = Handles::default();
        handles.step(&predicated, &Nothing);
        assert!(handles.held.is_empty(), "{:?}", handles.held);
    }

    /// A conditional branch whose arm is another function's entry (`jne g`, ARM's `bne g`) is a
    /// tail jump at the operation naming that arm.
    #[test]
    fn a_conditional_branch_to_an_entry_is_a_tail_jump() {
        let cond = r2il::Varnode::unique(0x10, 1);
        let mut lifted = R2ILBlock::new(0x1000, 6);
        lifted.push(r2il::R2ILOp::IntEqual {
            dst: cond.clone(),
            a: r2il::Varnode::register(0, 4),
            b: r2il::Varnode::constant(0, 4),
        });
        lifted.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x2000, 8),
            cond,
        });
        let instruction = Instruction {
            lifted,
            bytes: Vec::new(),
            decode: None,
            halts: None,
            supervisor: false,
            terminator: BlockTerminator::ConditionalBranch {
                true_target: 0x2000,
                false_target: 0x1006,
            },
        };
        let tail_calls = BTreeSet::from([0x2000]);
        let transfer = transfer_of(&instruction, 7, &tail_calls).expect("a transfer");
        assert_eq!((transfer.op, transfer.target), (8, 0x2000));
        assert!(matches!(
            transfer.kind,
            r2source::AdvisoryCallTransfer::TailJump
        ));
        assert!(transfer_of(&instruction, 7, &BTreeSet::new()).is_none());
    }
}
