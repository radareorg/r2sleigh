//! Decompiling a function with no radare2 anywhere.
//!
//! This is the whole native route in one place: walk the body out of the
//! program's bytes, state the machine from the convention data and the
//! compiler specification, mint a capture, and hand it to the same trusted
//! lift and the same request the plugin uses. Nothing downstream of the
//! capture is new, and nothing here formats anything.
//!
//! The callees a function calls directly are walked too, one level deep, and
//! their bodies are what say what each call takes and returns.
//! Whether a call comes back at all is the program's whole-program fixpoint.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::body::{BodyError, WINDOW};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2sleigh_lift::profile::{LanguageProfile, ParamEntry, SlotClass, SpecStorage};
use r2source::convention::{
    BoundaryForms, ConventionParts, LaneEntry, LaneSet, LaneSource, Location, OwnedRange,
    ResultLane, Section, SectionClass,
};
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, ConventionModel, SourceDataObject, SourceEndianness,
    SourceMachineRoles, SourceRoleRegisterNames, SourceStackAllocationContract, SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::{ArgumentReach, CalleePreservedCarriers, TrustedSsaArtifact};

use crate::declared::{Declared, Placement, Restatement};
use crate::{
    CalleeFacts, EngineDecompileResponse, EngineFunctionDecompileRequestInput, EngineFunctionInput,
    EngineFunctionInputQuality, EngineSession,
};

/// The program being analysed, as the engine needs to see it.
///
/// Two questions and no cursor: what byte lives at an address, and what the
/// program calls one. Whoever opened the binary answers them.
pub trait Program: crate::body::Program {
    /// What the program calls this address, where it names it at all.
    fn name_at(&self, vaddr: u64) -> Option<String>;

    /// The import this address stands for, where the binary says it is one.
    ///
    /// Asked of the binary rather than guessed from a name: a program that
    /// defines its own `strlen` carries a body there, and rendering that
    /// against the library's declaration would be a claim it never made.
    fn import_at(&self, vaddr: u64) -> Option<String>;

    /// The control for the request in hand: its cancellation, its deadline and
    /// the work it has spent.
    ///
    /// Asked of the program because that is what a request is made of here.
    /// Three sites used to mint one inline and drop the owner, so a native
    /// request carried tokens nothing could ever set and no request could be
    /// stopped once it started. The token and the meter are shared, so the
    /// control returned here is the caller's own and not a copy of it.
    fn control(&self) -> crate::EngineExecutionControl {
        crate::EngineExecutionControl::default()
    }

    /// Whether static data can live here: a section the program declares
    /// holds this address and answers
    /// [`holds_static_data`](crate::program::Section::holds_static_data).
    fn holds_static_data(&self, vaddr: u64) -> bool;

    /// Whether the container states the code at this address is instructions:
    /// a section it says holds code, or, where it states no sections, a region
    /// it maps executable.
    fn holds_code(&self, vaddr: u64) -> bool {
        self.region(vaddr).is_some_and(|region| region.execute)
    }

    /// Whether a function can begin here: code the file holds bytes for (audit W29).
    fn places_function(&self, vaddr: u64) -> bool {
        self.holds_code(vaddr)
            && self
                .region(vaddr)
                .is_some_and(|region| vaddr < region.file_end)
    }

    /// Where the program's loaded sections lie, code or data.
    ///
    /// A number nothing proves to move with the program names one of its
    /// objects only here, however low the program is linked.
    fn extents(&self) -> &r2types::ProgramExtents;

    /// The language the function at this address is written in, as the container states it.
    fn language_at(&self, _vaddr: u64) -> r2abi::statement::SourceLanguage {
        r2abi::statement::SourceLanguage::C
    }

    /// The machine the function at this address is written in, where the
    /// program has more than one; `None` keeps the caller's.
    fn target_at(&self, _vaddr: u64) -> Option<NativeTarget<'_>> {
        None
    }

    /// The register saves the container's call-frame information states for
    /// the function starting at `entry`. Empty where it states none.
    fn frame_saves(&self, _entry: u64) -> Vec<r2source::SourceFrameSave> {
        Vec::new()
    }

    /// What the closed world's `CallBoundary` decided of the result of the function at `entry`, from
    /// its open read's supply; none outside `aa` (doc/adr-result-side.md, section 3; D317).
    fn closed_result(&self, _entry: u64) -> Option<r2source::SourceClosedResult> {
        None
    }

    /// What one callee's body proves, as `read` derives it.
    ///
    /// A callee is prepared against the program and its imports alone, never
    /// against a body of whichever root calls it, so what it proves is a fact
    /// about the callee and the state of the program, and a program that holds
    /// one per state need derive it only once. Under `aa` (`callers`) a program
    /// may resolve it against its owners first.
    fn read_callee(
        &self,
        _address: u64,
        _callers: crate::program::World,
        read: &mut dyn FnMut() -> CalleeRead,
    ) -> Arc<CalleeRead> {
        Arc::new(read())
    }
}

/// What reading one callee's body gave a caller.
#[derive(Debug)]
pub struct CalleeRead {
    /// What the body proves about its boundary, which a callee whose
    /// preparation cannot be certified still proved.
    pub interface: Option<r2ssa::SourceFunctionInterface>,
    pub facts: Result<CalleeFacts, Unreadable>,
}

/// Everything about the machine that does not change between functions.
pub struct NativeTarget<'a> {
    pub arch: &'a r2ssa::Arch,
    pub disasm: &'a Disassembler,
    /// The processor context the decoder runs in, as the snapshot's machine
    /// tuple spells it. `arm` and `thumb` share an architecture, and this is
    /// the one fact the trusted lift has to tell them apart.
    pub cpu: &'a str,
    /// The function's convention: the specification's prototype joined with the ABI's row, held
    /// once per convention ([`convention_model`]).
    pub convention: Arc<ConventionModel>,
    /// The machine facts of the specification the convention reads: stack pointer, return address.
    pub compiler: &'a LanguageProfile,
    /// What a call here may run under: `convention`, joined with each other convention a function
    /// of the program states (doc/adr-call-boundary.md, "S20 as built").
    pub call: Arc<ConventionModel>,
    /// The program's own convention where this function's debug information states another.
    pub program: Option<Assembly<'a>>,
    /// The language's DWARF register numbering.
    pub dwarf: &'a r2sleigh_lift::profile::DwarfRegisters,
    /// The library rows this program's imports bind. An import has no body to read an
    /// interface off, so without its row a call to one renders with no arguments at all.
    pub imports: &'a crate::imports::Imports,
    /// What the binary's own debug information declares, by the address each
    /// body begins and each object sits at.
    pub declarations: &'a r2abi::Declarations,
    /// The target's cited C data model; `None` where no row states one.
    pub data_model: Option<&'static r2abi::CDataModel>,
}

/// One convention's held model and the specification it reads.
#[derive(Clone)]
pub struct Assembly<'a> {
    pub convention: Arc<ConventionModel>,
    pub compiler: &'a LanguageProfile,
}

impl<'a> NativeTarget<'a> {
    /// The target an import is placed in: the program's own convention, which its libraries run
    /// under; `None` where it is this function's too.
    pub fn importing(&self) -> Option<Self> {
        let program = self.program.as_ref()?;
        Some(Self {
            convention: Arc::clone(&program.convention),
            call: Arc::clone(&self.call),
            compiler: program.compiler,
            program: None,
            ..*self
        })
    }
}

/// Why a native decompile could not be attempted: the record `pdd`, `pddj`, `afi` and the listing
/// carry, never an error (ROADMAP D29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRefusal {
    Body(BodyError),
    /// The compiler specification named no stack pointer, so nothing can say
    /// where the frame is.
    NoStackPointer,
    /// A register the machine data names is not one this architecture has.
    UnknownRegister(String),
    /// The carriers or the convention slots are not a machine this engine can
    /// describe.
    Machine(&'static str),
    /// The machine or the function's convention could not be assembled for this program.
    Unassembled(Unassembled),
    /// No equivalence target grades this architecture's C, so none is rendered (ROADMAP D32).
    Unadmitted {
        architecture: String,
        bits: u32,
        big_endian: bool,
    },
    /// The function's convention passes what no call boundary states (doc/adr-language-profile.md).
    Convention {
        name: &'static str,
        reason: &'static str,
    },
    Capture(r2source::SnapshotValidationError),
    Lift(String),
    Prepare(String),
    /// The request's control stopped preparation: a fact about the request, never held as the program's.
    Stopped(r2ssa::SsaPrepareError),
    /// The analysis panicked: a defect, kept to this function and reported
    /// with where it was raised rather than taking the session with it.
    Panicked {
        location: Option<crate::isolation::PanicLocation>,
        message: String,
    },
}

impl NativeRefusal {
    /// Why preparation refused, a stop of the request's own kept apart.
    fn of_preparation(error: r2ssa::SsaPrepareError) -> Self {
        match error {
            r2ssa::SsaPrepareError::Cancelled | r2ssa::SsaPrepareError::DeadlineExceeded => {
                Self::Stopped(error)
            }
            error => Self::Prepare(error.to_string()),
        }
    }

    /// Whether this refusal is the request's stop rather than the program's answer.
    pub const fn stopped(&self) -> bool {
        matches!(self, Self::Stopped(_))
    }

    /// Whether the request named an address nothing maps: no function, so the request's error,
    /// never a record (ROADMAP D29).
    pub const fn names_no_function(&self) -> bool {
        matches!(self, Self::Body(BodyError::EntryUnmapped(_)))
    }

    /// The refusal's kind, as `pddj` tags it.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Body(BodyError::Oversized(_)) => "oversized",
            Self::Body(_) => "walk",
            Self::NoStackPointer
            | Self::UnknownRegister(_)
            | Self::Machine(_)
            | Self::Unassembled(_) => "machine",
            Self::Unadmitted { .. } => "architecture",
            Self::Convention { .. } => "convention",
            Self::Capture(_) => "capture",
            Self::Lift(_) => "lift",
            Self::Prepare(_) => "preparation",
            Self::Stopped(_) => "stopped",
            Self::Panicked { .. } => "panicked",
        }
    }
}

/// Why the machine a function runs on, or its convention, could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unassembled {
    /// No Sleigh specification decodes this architecture, as the lifter said.
    NoSpecification(String),
    /// No calling convention is stated for this architecture and width; `go` for Go's own.
    NoConvention {
        architecture: String,
        bits: u32,
        go: bool,
    },
    /// The convention runs under a compiler the language names none of.
    NoCompiler(&'static str),
    /// The compiler specification does not parse, as its parser said.
    UnparsedCompiler(String),
    /// The compiler specification states no prototype of the convention's name.
    NoPrototype(&'static str),
    /// The function's debug information states a convention no model here has.
    StatedConvention(r2abi::StatedConvention),
}

impl std::fmt::Display for Unassembled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSpecification(error) => write!(f, "no Sleigh specification: {error}"),
            Self::NoConvention {
                architecture,
                bits,
                go,
            } => {
                let go = if *go { "Go " } else { "" };
                write!(f, "no {go}calling convention for {architecture} {bits}")
            }
            Self::NoCompiler(compiler) => write!(f, "the language names no {compiler} compiler"),
            Self::UnparsedCompiler(error) => {
                write!(f, "the compiler specification does not parse: {error}")
            }
            Self::NoPrototype(prototype) => {
                write!(f, "the compiler specification states no {prototype}")
            }
            Self::StatedConvention(stated) => {
                write!(
                    f,
                    "the debug information states a convention no model has: {stated:?}"
                )
            }
        }
    }
}

impl From<crate::isolation::Panicked> for NativeRefusal {
    fn from(panicked: crate::isolation::Panicked) -> Self {
        Self::Panicked {
            location: panicked.location,
            message: panicked.message,
        }
    }
}

impl std::fmt::Display for NativeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(error) => write!(f, "{error}"),
            Self::NoStackPointer => write!(f, "the compiler specification names no stack pointer"),
            Self::UnknownRegister(name) => write!(f, "this architecture has no register {name}"),
            Self::Machine(what) => write!(f, "the machine cannot be described: {what}"),
            Self::Unassembled(why) => write!(f, "the machine is not assembled: {why}"),
            Self::Unadmitted {
                architecture,
                bits,
                big_endian,
            } => {
                let order = if *big_endian { " big-endian" } else { "" };
                write!(
                    f,
                    "no equivalence target grades {architecture} {bits}-bit{order} C, so none is rendered"
                )
            }
            Self::Convention { name, reason } => write!(f, "under the {name} convention: {reason}"),
            Self::Capture(error) => write!(f, "{error}"),
            Self::Lift(error) | Self::Prepare(error) => write!(f, "{error}"),
            Self::Stopped(stop) => write!(f, "{stop}"),
            Self::Panicked { location, message } => {
                let panicked = crate::isolation::Panicked {
                    location: location.clone(),
                    message: message.clone(),
                };
                write!(f, "the analysis {panicked}")
            }
        }
    }
}

impl std::error::Error for NativeRefusal {}

/// Decompile the function at `entry`.
/// The low tier for one function: the operations Sleigh lifted, per block.
///
/// Before SSA, before any analysis: what the specification says the bytes
/// mean. A defect the medium tier shows is either already here or belongs to
/// the construction between them.
pub fn lifted(target: &NativeTarget<'_>, walk: &Walk) -> String {
    let body = walk.body();
    let names = register_spellings(target.arch);
    let mut out = format!("Entry: {:#x}\nBlocks: {}\n", body.entry, body.blocks.len());
    for block in &body.blocks {
        out.push_str(&format!(
            "\nBlock {:#x} ({} bytes, {} ops)\n",
            block.lifted.addr,
            block.lifted.size,
            block.lifted.ops.len()
        ));
        for (index, op) in block.lifted.ops.iter().enumerate() {
            out.push_str(&format!(
                "  {index:3}: {}\n",
                spell_registers(&op.to_string(), &names)
            ));
        }
        for (kind, target) in &block.successors {
            out.push_str(&format!("  -> {target:#x} ({kind:?})\n"));
        }
    }
    for stop in &body.unresolved {
        out.push_str(&format!(
            "\nstopped at {:#x}: {:?}\n",
            stop.addr, stop.reason
        ));
    }
    out
}

/// Operations as the low tier prints them: each register by its name, each user operation by its own.
pub(crate) fn spelled_operations(arch: &r2il::ArchSpec, ops: &[r2il::R2ILOp]) -> Vec<String> {
    let names = register_spellings(arch);
    ops.iter()
        .map(|op| spell_registers(&op.to_string(), &names))
        .collect()
}

/// How this architecture's registers are spelled by `Varnode`'s own Display,
/// and what to call each instead.
///
/// The decoration below rewrites that spelling rather than the operations: a
/// register name is wanted only by a reader, and giving every varnode one
/// would cost an allocation per operand for something no analysis reads.
/// What the machine data calls the numbers a tier prints.
///
/// A register offset and a user operation's index are both indices into the
/// specification, and a reader who has to look them up is reading a worse
/// tier than the one that exists.
fn register_spellings(arch: &r2il::ArchSpec) -> Vec<(String, String)> {
    let mut spellings: Vec<(String, String)> =
        arch.registers
            .iter()
            .map(|register| {
                (
                    format!("reg:{:#x}[{}]", register.offset, register.size),
                    register.name.clone(),
                )
            })
            .chain(
                arch.user_ops.iter().enumerate().map(|(index, name)| {
                    (format!("CALLOTHER({index})"), format!("CALLOTHER({name})"))
                }),
            )
            .collect();
    // Longest first, so a wider register's spelling is never rewritten by the
    // prefix of a narrower one that starts at the same offset.
    spellings.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    spellings.dedup_by(|a, b| a.0 == b.0);
    spellings
}

fn spell_registers(line: &str, names: &[(String, String)]) -> String {
    let mut line = line.to_owned();
    for (spelling, name) in names {
        if line.contains(spelling.as_str()) {
            line = line.replace(spelling.as_str(), name);
        }
    }
    line
}

/// The medium tier for one function: SSA, prepared against its callees.
///
/// The same work `decompile` does, stopping before the rendering, so a reader
/// can ask what the analysis tier holds without asking for C.
pub fn prepared(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<std::sync::Arc<TrustedSsaArtifact>, NativeRefusal> {
    analysed(target, program, entry).map(|prepared| prepared.artifact)
}

/// Walk and prepare one function, without rendering anything from it.
pub fn analysed(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<Prepared, NativeRefusal> {
    let walk = walk(target, program, entry)?;
    analyse(target, program, entry, &walk, crate::program::World::Closed)
}

/// Prepare one function from its walk, reading its callers where `callers` says; the query
/// `Analysed` reads the walk from `Walked`.
pub(crate) fn analysed_from(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    (entry, walk): (u64, &Walk),
    callers: crate::program::World,
) -> Result<Prepared, NativeRefusal> {
    analyse(target, program, entry, walk, callers)
}

/// What a prepared function keeps of its walk once the lift is read: block extents and successors,
/// stops and callees reached (doc/adr-memory-model.md, decision 1).
pub struct Outline {
    pub name: String,
    pub blocks: Vec<OutlineBlock>,
    pub unresolved: Vec<crate::body::Unresolved>,
}

/// One walked block's extent and where control continues from it.
pub struct OutlineBlock {
    pub addr: u64,
    pub size: u32,
    pub successors: Vec<(r2source::AdvisorySuccessorKind, u64)>,
}

impl Outline {
    fn of(walked: &Walked) -> Self {
        let blocks = (walked.body.blocks.iter())
            .map(|block| OutlineBlock {
                addr: block.lifted.addr,
                size: block.lifted.size,
                successors: block.successors.clone(),
            })
            .collect();
        Self {
            name: walked.name.clone(),
            blocks,
            unresolved: walked.body.unresolved.clone(),
        }
    }
}

/// One function's walk, through the dispatch tables it reads (doc/adr-resolved-bodies.md, P6a).
#[derive(Clone)]
pub struct Walk {
    /// Shared with each analysis of the body; the tables stay the walk's.
    root: std::sync::Arc<Walked>,
    tables: Vec<NativePointerTable>,
    /// The tables the body's indirect calls read, fetched after its first preparation (P5).
    calls: Vec<NativePointerTable>,
    /// Why the tables of a body that has dispatches were not read: the body is then the walk that follows none.
    refusal: Option<NativeRefusal>,
}

impl Walk {
    /// A walked body with the tables read for it; a refused read leaves it following none.
    fn of(root: Walked, tables: Tables) -> Self {
        Self {
            root: std::sync::Arc::new(root),
            tables: tables.read,
            calls: Vec::new(),
            refusal: tables.refusal,
        }
    }

    /// Why this body's dispatch tables were not read, where they were not.
    pub const fn refusal(&self) -> Option<&NativeRefusal> {
        self.refusal.as_ref()
    }

    /// The walked body, dispatches followed.
    pub fn body(&self) -> &crate::body::Body {
        &self.root.body
    }

    /// The lift of each block of the body, dispatches followed: a dispatch's block carries the cases
    /// its table read, so the graph built over the blocks reaches every arm.
    pub fn lifted(&self) -> Vec<r2il::R2ILBlock> {
        let blocks = (self.root.body.blocks.iter())
            .map(|block| block.lifted.clone())
            .collect::<Vec<_>>();
        switched(blocks, &self.tables)
    }
}

/// Blocks with the cases each dispatch's table read set on the block that makes it.
fn switched(
    mut blocks: Vec<r2il::R2ILBlock>,
    tables: &[NativePointerTable],
) -> Vec<r2il::R2ILBlock> {
    // The body's blocks are in address order, so each table finds its block by search.
    for table in tables {
        let after = blocks.partition_point(|block| block.addr <= table.instruction);
        let Some(block) = after.checked_sub(1).map(|at| &mut blocks[at]) else {
            continue;
        };
        if table.instruction - block.addr < u64::from(block.size) {
            let cases = (table.cases.iter())
                .map(|&(value, target)| r2il::SwitchCase { value, target })
                .collect();
            block.switch_info = Some(r2il::SwitchInfo {
                switch_addr: table.instruction,
                default_target: None,
                cases,
            });
        }
    }
    blocks
}

/// Walk one function, and where a dispatch stops the walk, read its tables and walk again through them.
pub fn walk(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<Walk, NativeRefusal> {
    walk_reading(target, program, entry, &|| {
        dispatch_tables(target, program, entry)
    })
}

/// The same walk, asking `read` for the tables only where the body stops at a dispatch.
pub(crate) fn walk_reading(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
    read: &dyn Fn() -> Tables,
) -> Result<Walk, NativeRefusal> {
    let native = Native::over(target, program)?;
    let root = native.walk(entry)?;
    if !(root.body.unresolved.iter()).any(Tables::stops) {
        return Ok(Walk::of(root, Tables::default()));
    }
    let tables = read();
    if tables.read.is_empty() {
        return Ok(Walk::of(root, tables));
    }
    let through = native.walk_dispatched(entry, &tables.dispatched())?;
    Ok(Walk::of(through, tables))
}

/// One body as the reference index lists it: walked once, through the tables `read` gives.
pub(crate) struct ListedWalk {
    pub(crate) body: crate::body::Body,
    /// The lift of each block, dispatches' cases set; `body.blocks` is left empty.
    pub(crate) lifted: Vec<r2il::R2ILBlock>,
    /// Each instruction's own decode, in address order.
    pub(crate) decodes: Vec<crate::body::Decoded>,
}

/// The walk `walk_reading` makes, keeping each instruction's own decode.
pub(crate) fn listed_walk(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
    held: Option<Tables>,
    read: &dyn Fn() -> Tables,
) -> Result<ListedWalk, NativeRefusal> {
    Native::over(target, program)?;
    let walk = |dispatched: &BTreeMap<u64, Vec<u64>>| {
        crate::body::listed_body(entry, target.disasm, program, dispatched)
            .map_err(NativeRefusal::Body)
    };
    // Tables already read were read because the body stops at a dispatch: one walk through them.
    let (walked, tables) = match held {
        Some(tables) => (walk(&tables.dispatched())?, tables.read),
        None => {
            let root = walk(&BTreeMap::new())?;
            let tables = match (root.0.unresolved.iter()).any(Tables::stops) {
                true => read().read,
                false => Vec::new(),
            };
            match tables.is_empty() {
                true => (root, tables),
                false => (walk(&dispatched(&tables))?, tables),
            }
        }
    };
    let (mut body, decodes) = walked;
    let blocks = std::mem::take(&mut body.blocks).into_iter();
    let lifted = switched(blocks.map(|block| block.lifted).collect(), &tables);
    Ok(ListedWalk {
        body,
        lifted,
        decodes,
    })
}

/// The tables the dispatches of the body at `entry` read, off a preparation against the imports' declarations alone.
/// A refused read leaves the walk no table and says why.
pub(crate) fn dispatch_tables(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Tables {
    let native = match Native::over(target, program) {
        Ok(native) => native,
        Err(refusal) => return Tables::refused(refusal),
    };
    match native.walk(entry) {
        Ok(root) if root.body.unresolved.iter().any(Tables::stops) => native.read_tables(&root),
        _ => Tables::default(),
    }
}

/// Where each dispatch goes, by the instruction making it.
fn dispatched(tables: &[NativePointerTable]) -> BTreeMap<u64, Vec<u64>> {
    (tables.iter())
        .map(|table| (table.instruction, table.targets.clone()))
        .collect()
}

/// What reading a body's dispatch tables left: the tables, or the refusal that left the body following none.
#[derive(Clone, Default)]
pub(crate) struct Tables {
    read: Vec<NativePointerTable>,
    refusal: Option<NativeRefusal>,
}

impl std::fmt::Debug for Tables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tables({} read)", self.read.len())
    }
}

impl Tables {
    pub(crate) fn refused(refusal: NativeRefusal) -> Self {
        Self {
            read: Vec::new(),
            refusal: Some(refusal),
        }
    }

    fn stops(stop: &crate::body::Unresolved) -> bool {
        stop.reason == crate::body::UnresolvedReason::IndirectBranch
    }

    /// Where each dispatch goes, by the instruction making it.
    pub(crate) fn dispatched(&self) -> BTreeMap<u64, Vec<u64>> {
        dispatched(&self.read)
    }

    /// Why the read was refused, where it was.
    pub(crate) const fn refusal(&self) -> Option<&NativeRefusal> {
        self.refusal.as_ref()
    }
}

/// One function's analysis, before anything is rendered from it.
///
/// Every tier is a rendering of this, so it is handed out rather than redone:
/// asking for the prepared function and then for what the renderer decided
/// about its values used to walk, lift and prepare the same body twice.
pub struct Prepared {
    artifact: std::sync::Arc<TrustedSsaArtifact>,
    /// The walk's outline; its lift, which preparation has read, goes with the walk.
    outline: Outline,
    facts: Vec<crate::CalleeFacts>,
    declared: Vec<r2types::SourceOwnedCalleeSignature>,
    ptr_bits: u32,
    unread: Vec<Unread>,
    extents: r2types::ProgramExtents,
    /// The table each dispatch reads, as the walk fetched it, by the dispatching instruction.
    tables: BTreeMap<u64, DispatchTable>,
}

/// Where one dispatch's table lies in the program, as the fetch that followed it read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchTable {
    pub address: u64,
    pub entry_size: u32,
    pub entries: usize,
    /// What the container states about whether the bytes the fetch read are the ones the dispatch reads when it runs.
    pub stated: TableBytes,
}

impl DispatchTable {
    /// Where the fetch read this table, keyed by the dispatching instruction.
    fn of(fetched: &NativePointerTable) -> (u64, Self) {
        let table = Self {
            address: fetched.table.address(),
            entry_size: fetched.table.entry_size(),
            entries: fetched.targets.len(),
            stated: fetched.stated,
        };
        (fetched.instruction, table)
    }
}

impl Prepared {
    /// The table the dispatch at this instruction reads, where the walk fetched one.
    pub fn table_at(&self, instruction: u64) -> Option<&DispatchTable> {
        self.tables.get(&instruction)
    }

    /// Every instruction whose dispatch the walk read a table for, in address order.
    pub fn dispatches(&self) -> impl Iterator<Item = u64> + '_ {
        self.tables.keys().copied()
    }

    /// The walked body's blocks, dispatches followed, and where the walk could not follow.
    pub const fn outline(&self) -> &Outline {
        &self.outline
    }

    pub fn artifact(&self) -> &std::sync::Arc<TrustedSsaArtifact> {
        &self.artifact
    }

    /// What the program calls the function this analysis is of.
    pub fn name(&self) -> &str {
        &self.outline.name
    }

    /// What the program declares about each callee this body calls, where it declares one.
    pub fn declared(&self) -> &[r2types::SourceOwnedCalleeSignature] {
        &self.declared
    }

    /// The callees this analysis could not read, and how far each got.
    ///
    /// A call to one of these renders from whatever the call site itself
    /// shows, which for a result register is nothing. Until now they were
    /// skipped in silence, so a degraded answer and a clean one looked the
    /// same from outside.
    pub fn unread(&self) -> &[Unread] {
        &self.unread
    }
}

/// A callee whose contribution to this analysis is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub address: u64,
    pub reason: Unreadable,
}

/// How far reading a callee got before it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreadable {
    /// The body could not be walked, so nothing about its boundary is known.
    NotWalked,
    /// The body was walked and could not be prepared.
    NotPrepared,
    /// The request's control stopped its preparation.
    Stopped,
    /// It was prepared and proved nothing about its boundary that a caller
    /// could use.
    NothingProved,
    /// Reading it panicked: a defect in the analysis, kept to this callee.
    Panicked(crate::isolation::Panicked),
}

impl Unread {
    /// Whether reading this callee panicked: a defect in the engine, not a
    /// fact about the program, which a reader has to be shown.
    pub const fn panicked(&self) -> bool {
        matches!(self.reason, Unreadable::Panicked(_))
    }
}

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match &self.reason {
            Unreadable::NotWalked => "its body could not be walked",
            Unreadable::NotPrepared => "its body could not be prepared",
            Unreadable::Stopped => "the request stopped before its body was prepared",
            Unreadable::NothingProved => "it proved nothing about its boundary",
            Unreadable::Panicked(panicked) => {
                return write!(f, "{:#x}: its analysis {panicked}", self.address);
            }
        };
        write!(f, "{:#x}: {reason}", self.address)
    }
}

/// The C of one function, rendered from its sealed facts.
pub fn decompile(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    render(target, program, entry)
}

/// Whether a body that transfers to these callees and reads these import slots calls anything declared to take a function.
pub(crate) fn hands_a_function(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    callees: impl IntoIterator<Item = u64>,
    loads: &BTreeSet<u64>,
) -> bool {
    // A row applies to an import only: a body of the same name is typed by its own evidence.
    let direct = callees
        .into_iter()
        .filter_map(|callee| program.import_at(callee));
    let sealed = |slot: &u64| crate::stated::sealed_import(program, *slot).map(str::to_owned);
    let through_a_slot = loads.iter().filter_map(sealed);
    direct.chain(through_a_slot).any(|name| {
        let declared = Declared::import(target, &name);
        declared.is_some_and(|declared| {
            (declared.prototype.parameters.iter()).any(r2abi::Parameter::is_function)
        })
    })
}

/// The functions a walked body hands to a parameter a declaration calls a function.
pub(crate) fn handed(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    body: crate::body::Body,
) -> Vec<u64> {
    let entry = body.entry;
    let native = match machine(target) {
        Ok(machine) => Native {
            target,
            program,
            machine,
            control: program.control().ssa_execution_control(),
        },
        Err(error) => {
            r2il::refusal_evidence!("handed-function", "{entry:#x}: {error}");
            return Vec::new();
        }
    };
    let walked = native.walked(body);
    // What reaches a call's argument is the body's: read off the convention's seal, as a table.
    match native.convention_seal(&walked, &Callees::default(), Restatement::default()) {
        Ok(seal) => native.handed_functions(&seal, &walked),
        Err(error) => {
            r2il::refusal_evidence!(
                "handed-function",
                "{entry:#x}: preparing to read its arguments failed: {error:?}"
            );
            Vec::new()
        }
    }
}

/// Whether control comes back from the import at `address`, as its own declaration says; `None` where it is no import.
pub(crate) fn declared_return(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    address: u64,
) -> Option<crate::discovery::Return> {
    use crate::discovery::Return;
    let Some(name) = program.import_at(address) else {
        // A Go function the runtime model says never returns, under the runtime's contract.
        let go = program.language_at(address) == r2abi::statement::SourceLanguage::Go;
        let premise = r2source::Premise::GoRuntime;
        return (go && accepted_premises().contains(&premise))
            .then(|| program.name_at(address))
            .flatten()
            .filter(|name| r2abi::runtime::exits(name))
            .map(|_| Return::Never(std::collections::BTreeSet::from([premise])));
    };
    let row = target.imports.row(&name);
    Some(match row.is_some_and(|row| row.noreturn) {
        true => Return::Never(std::collections::BTreeSet::new()),
        false => Return::Comes,
    })
}

fn render(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    let control = program.control();
    let prepared = analysed(target, program, entry)?;
    Ok(match sealed(target, program, entry, &prepared, &control) {
        Ok(sealed) => EngineSession::new().render_sealed(&sealed, &control),
        Err(refused) => *refused,
    })
}

/// The type analysis of one prepared function under this request's control; a refusal is the response a rendering returns.
pub fn sealed(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
    prepared: &Prepared,
    control: &crate::EngineExecutionControl,
) -> Result<crate::SealedFunctionAnalysis, Box<EngineDecompileResponse>> {
    let sealed =
        EngineSession::new().seal_function_from_input(request(target, entry, prepared, control))?;
    Ok(sealed.stub_of(program))
}

/// The request one prepared function is analysed under.
fn request(
    target: &NativeTarget<'_>,
    entry: u64,
    prepared: &Prepared,
    control: &crate::EngineExecutionControl,
) -> EngineFunctionDecompileRequestInput {
    let Prepared {
        artifact,
        outline,
        facts,
        declared,
        ptr_bits,
        unread: _,
        extents,
        tables: _,
    } = prepared;
    let block_count = artifact.source_block_count();
    EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: outline.name.clone(),
            function_addr: entry,
            // The artifact owns the lift and the request reads it from there.
            blocks: Vec::new(),
            arch: Some(target.arch.clone()),
            semantic_metadata_enabled: true,
            source_snapshot: None,
        },
        Some(*ptr_bits),
        r2types::ParsedExternalContext {
            program_extents: extents.clone(),
            ..r2types::ParsedExternalContext::default()
        },
    )
    .with_input_quality(EngineFunctionInputQuality::complete(block_count))
    .with_trusted_ssa(std::sync::Arc::clone(artifact))
    .with_callee_facts(facts.clone())
    .with_declared_signatures(declared.clone())
    .with_execution_control(control.clone())
}

/// What the functions this one calls contribute to preparing it.
struct Read {
    callees: Callees,
    facts: Vec<crate::CalleeFacts>,
    declared: Vec<r2types::SourceOwnedCalleeSignature>,
    unread: Vec<Unread>,
}

/// Read every function this one reaches, by declaration or by body.
///
/// What a call takes and returns is a fact about the callee, so this runs
/// before the root is prepared and the root is prepared against it.
/// Place what the binary declares about each import it calls.
///
/// An import has no body here to read an interface off, so its declared
/// prototype goes in the convention's own slots and stands in for one, and the
/// same declaration states the C signature the call renders with.
fn declare_imports(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    targets: &[u64],
    ptr_bits: u32,
    callees: &mut Callees,
) -> Vec<r2types::SourceOwnedCalleeSignature> {
    let mut signatures = Vec::new();
    for address in targets {
        let Some(name) = native.program.import_at(*address) else {
            continue;
        };
        let Some(declared) = Declared::import(target, &name) else {
            callees
                .unstated
                .insert(*address, r2ssa::UnstatedImport::Undeclared);
            continue;
        };
        // An import has no body here, so nothing it declares about its own
        // frame is about anything this program can see.
        let placed = placing_imports(target, Some(&native.machine), |placement| {
            let interface = placement.restatement(declared, false).interface?;
            Some((interface, placement.function_type(declared)))
        });
        let Some((interface, signature)) = placed.flatten() else {
            callees
                .unstated
                .insert(*address, r2ssa::UnstatedImport::Unplaced);
            continue;
        };
        if let Some(signature) = signature
            && let Some(declaration) = r2types::SourceOwnedCalleeSignature::declared(
                *address,
                interface.clone(),
                signature,
                ptr_bits,
            )
        {
            signatures.push(declaration);
        }
        callees.interfaces.insert(*address, interface);
    }
    signatures
}

/// One callee's body, prepared against what the binary declares about it and its imports, and against no callee body of its own.
///
/// This is what a caller learns about a callee -- its interface, and what its
/// own body does through each parameter -- so every caller learns it the same way.
///
/// An isolation boundary: a panic preparing the callee is this callee's
/// `Unreadable::Panicked`, and its caller goes on without it.
fn prepared_callee(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
) -> Result<Resolution, Unreadable> {
    crate::isolation::isolated(|| prepare_callee(native, target, address, ptr_bits))
        .unwrap_or_else(|panicked| Err(Unreadable::Panicked(panicked)))
}

fn prepare_callee(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
) -> Result<Resolution, Unreadable> {
    // A callee in the other instruction set is walked and captured in it.
    let own = native
        .program
        .target_at(address)
        .filter(|own| own.cpu != target.cpu);
    let switched = own.as_ref().and_then(|own| native.in_target(own));
    let (native, target) = match (&switched, &own) {
        (Some(switched), Some(own)) => (switched, own),
        _ => (native, target),
    };
    let walked = walk(target, native.program, address).map_err(|_| Unreadable::NotWalked)?;
    resolved_alone(
        native,
        target,
        address,
        ptr_bits,
        &walked,
        Stated::default(),
    )
}

/// A resolved body, and the callees whose statement could prove what it leaves open.
type Resolution = Arc<TrustedSsaArtifact>;

/// What a body is resolved against beside its imports: its owners resolved, and the arities a
/// cycle's least fixpoint assumes of its members (doc/adr-resolved-bodies.md, "Arity").
#[derive(Clone, Copy, Default)]
pub(crate) struct Stated<'a> {
    pub(crate) owners: &'a [(u64, Arc<CalleeRead>)],
    pub(crate) assumed: &'a [(u64, r2source::SourceFunctionInterface)],
    /// Under `aa` a callee's result is its closed-world `CallBoundary`'s, as the root's is.
    pub(crate) world: crate::program::World,
}

/// A callee resolved as a root is, against its imports' declarations alone (doc/adr-resolved-bodies.md).
fn resolved_alone(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
    walked: &Walk,
    stated: Stated<'_>,
) -> Result<Resolution, Unreadable> {
    let mut imports = Callees::default();
    let targets = reached(&walked.root.body, native.program);
    declare_imports(native, target, &targets, ptr_bits, &mut imports);
    // Each resolved owner of its result or arity, read as any callee's statement.
    imports.state(stated.owners);
    // An assumed member states its interface alone: nothing it preserves or reaches.
    for (member, interface) in stated.assumed {
        imports.interfaces.insert(*member, interface.clone());
    }
    let resolved = native.resolve(address, walked, &imports, stated.world);
    resolved.map_err(|refusal| match refusal.stopped() {
        true => Unreadable::Stopped,
        false => Unreadable::NotPrepared,
    })
}

/// What a callee's own body proves about its parameters, prepared as every caller prepares it.
pub(crate) fn callee_summary(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    address: u64,
    walked: &Walk,
) -> Result<r2ssa::PreparedCalleeSummary, Unreadable> {
    let native = Native {
        target,
        program,
        machine: machine(target).map_err(|_| Unreadable::NotPrepared)?,
        control: program.control().ssa_execution_control(),
    };
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);
    let resolved = crate::isolation::isolated(|| {
        resolved_alone(
            &native,
            target,
            address,
            ptr_bits,
            walked,
            Stated::default(),
        )
    });
    let artifact = resolved.unwrap_or_else(|panicked| Err(Unreadable::Panicked(panicked)))?;
    let shared = artifact.shared_artifact();
    let summary =
        r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(address), &shared);
    summary.map_err(|_| Unreadable::NothingProved)
}

/// What one callee's body proves, read with this decoder; the query `CalleeReads` holds it.
pub(crate) fn callee_read(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    address: u64,
    walked: &Walk,
    stated: Stated<'_>,
) -> CalleeRead {
    let native = match machine(target) {
        Ok(machine) => Native {
            target,
            program,
            machine,
            control: program.control().ssa_execution_control(),
        },
        Err(_) => {
            return CalleeRead {
                interface: None,
                facts: Err(Unreadable::NotPrepared),
            };
        }
    };
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);
    let resolved = crate::isolation::isolated(|| {
        resolved_alone(&native, target, address, ptr_bits, walked, stated)
    });
    read_of(
        &native,
        resolved.unwrap_or_else(|panicked| Err(Unreadable::Panicked(panicked))),
    )
}

/// A callee built against its imports alone, before its seal, with those imports: its interface
/// names the owners of its result (doc/adr-callee-builds.md).
pub(crate) struct Built {
    address: u64,
    construction: r2ssa::TrustedConstruction,
    imports: Callees,
    declared_root: Restatement,
}

/// A body's first seal, by its entry, and the declaration it was captured under.
struct First {
    entry: u64,
    declared_root: Restatement,
    seal: r2ssa::TrustedSeal,
}

impl Built {
    /// The interface the build recovered or was stated.
    pub(crate) fn interface(&self) -> Option<&r2ssa::SourceFunctionInterface> {
        self.construction.machine_context().function_interface()
    }

    /// Whether its owners' statements can update this build instead of building it again.
    pub(crate) const fn restatable(&self) -> bool {
        self.construction.restatable()
    }
}

/// One callee built against its imports alone, or why it has no build: the first step of
/// `callee_read`.
pub(crate) fn callee_built(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    address: u64,
    walked: &Walk,
) -> Result<Built, Unreadable> {
    let native = Native::over(target, program).map_err(|_| Unreadable::NotPrepared)?;
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);
    let built = crate::isolation::isolated(|| {
        let mut imports = Callees::default();
        let targets = reached(&walked.root.body, native.program);
        declare_imports(&native, target, &targets, ptr_bits, &mut imports);
        let declared_root = native.declaration(address);
        let construction = native.construct_first(walked, &imports, &declared_root)?;
        Ok(Built {
            address,
            construction,
            imports,
            declared_root,
        })
    });
    match built {
        Ok(built) => built.map_err(|refusal: NativeRefusal| unreadable(&refusal)),
        Err(panicked) => Err(Unreadable::Panicked(panicked)),
    }
}

/// Why a refused resolution is unread.
fn unreadable(refusal: &NativeRefusal) -> Unreadable {
    match refusal.stopped() {
        true => Unreadable::Stopped,
        false => Unreadable::NotPrepared,
    }
}

/// `callee_read` against `owners` from a build their statements update, and whether its answer
/// is another seal than that build's (doc/adr-callee-builds.md).
pub(crate) fn built_read(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    walked: &Walk,
    built: Built,
    owners: &[(u64, Arc<CalleeRead>)],
) -> (CalleeRead, bool) {
    let Ok(native) = Native::over(target, program) else {
        let unread = CalleeRead {
            interface: None,
            facts: Err(Unreadable::NotPrepared),
        };
        return (unread, false);
    };
    let resolved = crate::isolation::isolated(|| native.resolve_built(walked, built, owners));
    let resolved = resolved.map(|resolved| resolved.map_err(|refusal| unreadable(&refusal)));
    let resolved = resolved.unwrap_or_else(|panicked| Err(Unreadable::Panicked(panicked)));
    let again = resolved.as_ref().is_ok_and(|(_, again)| *again);
    (
        read_of(&native, resolved.map(|(artifact, _)| artifact)),
        again,
    )
}

/// The declarations of the imports a resolved body calls directly. O(call sites x log rows).
fn declared_callees(
    native: &Native<'_>,
    artifact: &Resolution,
) -> Vec<r2types::SourceOwnedCalleeSignature> {
    let shared = artifact.shared_artifact();
    let sites = shared.facts().call_sites.by_id.values();
    let targets =
        (sites.filter_map(|site| site.direct_target)).collect::<std::collections::BTreeSet<_>>();
    let targets = targets.into_iter().collect::<Vec<_>>();
    let ptr_bits = crate::engine_effective_ptr_bits(native.target.arch);
    declare_imports(
        native,
        native.target,
        &targets,
        ptr_bits,
        &mut Callees::default(),
    )
}

/// What one callee's body proves, read under the same isolation boundary as its preparation.
fn read_callee(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
) -> CalleeRead {
    read_of(native, prepared_callee(native, target, address, ptr_bits))
}

/// What a resolved callee proves, derived under isolation against the imports it calls.
fn read_of(native: &Native<'_>, resolved: Result<Resolution, Unreadable>) -> CalleeRead {
    let artifact = match resolved {
        Ok(resolved) => resolved,
        Err(reason) => {
            return CalleeRead {
                interface: None,
                facts: Err(reason),
            };
        }
    };
    // The interface is what the callee's body proves about its boundary,
    // and a callee whose whole preparation cannot be certified still
    // proved that much.
    let interface = artifact
        .shared_artifact()
        .machine_context()
        .function_interface()
        .cloned();
    let declared = declared_callees(native, &artifact);
    let facts = match crate::isolation::isolated(|| CalleeFacts::derive(&artifact, declared)) {
        Ok(Some(derived)) => Ok(derived),
        Ok(None) => Err(Unreadable::NothingProved),
        Err(panicked) => Err(Unreadable::Panicked(panicked)),
    };
    CalleeRead { interface, facts }
}

fn read_callees(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    (root, entry): (&Walked, u64),
    ptr_bits: u32,
    callers: crate::program::World,
) -> Read {
    // What a call takes and returns is a fact about the callee's body, so the
    // bodies it calls are walked first and the root is prepared against them.
    // A callee that cannot be walked leaves its call unproven rather than
    // failing the root.
    let mut callees = Callees::default();
    let targets = reached(&root.body, native.program);
    let declared = declare_imports(native, target, &targets, ptr_bits, &mut callees);
    let mut facts = Vec::new();
    // Under `aa` a recursive root reads itself resolved, as its callers do ("Arity").
    let own = callers == crate::program::World::Closed;
    // An import has no body here, declared or not: its stub's arity is the loader's (P7). A
    // sealed import slot is a word of data.
    let bodies: Vec<u64> = targets
        .iter()
        .copied()
        .filter(|address| (own || *address != entry) && !callees.interfaces.contains_key(address))
        .filter(|address| native.program.import_at(*address).is_none())
        .filter(|address| crate::stated::sealed_import(native.program, *address).is_none())
        .collect();
    let mut unread = Vec::new();
    for address in &bodies {
        let read = native.program.read_callee(*address, callers, &mut || {
            read_callee(native, target, *address, ptr_bits)
        });
        // Taking the interface keeps the call rendered as a call.
        if let Some(interface) = &read.interface {
            callees.interfaces.insert(*address, interface.clone());
        }
        match &read.facts {
            Ok(derived) => {
                callees.record(*address, derived);
                facts.push(derived.clone());
            }
            Err(reason) => unread.push(Unread {
                address: *address,
                reason: reason.clone(),
            }),
        }
    }

    Read {
        callees,
        facts,
        declared,
        unread,
    }
}

fn analyse(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
    walk: &Walk,
    callers: crate::program::World,
) -> Result<Prepared, NativeRefusal> {
    // A convention whose boundaries carry what none states refuses before anything is read.
    if let Some(reason) = target.convention.refused {
        let name = target.convention.id.radare2_name();
        return Err(NativeRefusal::Convention { name, reason });
    }
    let native = Native {
        target,
        program,
        machine: machine(target)?,
        control: program.control().ssa_execution_control(),
    };
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);

    let Read {
        callees,
        facts,
        declared,
        unread,
    } = read_callees(&native, target, (&walk.root, entry), ptr_bits, callers);

    let artifact = native.resolve(entry, walk, &callees, callers)?;
    let artifact = native.with_call_tables(walk, &callees, callers, artifact)?;
    let tables = walk.tables.iter().map(DispatchTable::of).collect();
    Ok(Prepared {
        artifact,
        outline: Outline::of(&walk.root),
        facts,
        declared,
        ptr_bits,
        unread,
        extents: program.extents().clone(),
        tables,
    })
}

/// What to call each parameter the interface declares.
///
/// Exactly as long as that list, because the presentation is read positionally
/// against it. A declaration that named no parameter, or none at all, leaves
/// the position as the name.
fn declared_parameter_names(
    signature: Option<&r2source::SourceSignaturePresentation>,
    count: usize,
) -> Vec<String> {
    (0..count)
        .map(|index| {
            signature
                .and_then(|signature| signature.named_parameters().get(index))
                .and_then(r2source::SourceSignatureParameter::name)
                .map(str::to_owned)
                .unwrap_or_else(|| r2source::positional_parameter_name(index))
        })
        .collect()
}

/// Where each integer argument arrives under this machine's convention, by index.
pub(crate) fn argument_slots(target: &NativeTarget<'_>) -> Vec<CanonicalStorageId> {
    (target.convention.argument_registers(SlotClass::Integer)).collect()
}

/// Where an import's declaration says it takes a pointer.
pub(crate) fn declared_pointers(target: &NativeTarget<'_>, name: &str) -> Vec<CanonicalStorageId> {
    let Some(declared) = Declared::import(target, name) else {
        return Vec::new();
    };
    placing_imports(target, None, |placement| placement.pointers(declared)).unwrap_or_default()
}

/// The registers a call to the import `name` may read, where it binds a row (S7 reads it).
pub fn import_reads(target: &NativeTarget<'_>, name: &str) -> Option<r2ssa::call_reads::CallReads> {
    let declared = Declared::import(target, name)?;
    placing_imports(target, None, |placement| placement.reads(declared))
}

/// `f` over the placement an import's row takes: under the program's own convention, which its
/// libraries run under (S20). `None` where the machine does not build.
fn placing_imports<R>(
    target: &NativeTarget<'_>,
    built: Option<&NativeMachine>,
    f: impl FnOnce(&Placement<'_>) -> R,
) -> Option<R> {
    let library = target.importing();
    let target = library.as_ref().unwrap_or(target);
    let owned;
    let machine = match (built, &library) {
        (Some(machine), None) => machine,
        _ => {
            owned = machine(target).ok()?;
            &owned
        }
    };
    Some(f(&Placement::new(target, machine)))
}

/// One interface again, with stack slots it did not have, stated against
/// `revision`; every other fact it states is kept
/// (`SourceFunctionInterface::restated`).
pub(crate) fn restate(
    interface: &r2source::SourceFunctionInterface,
    slots: Vec<r2source::SourceStackSlotSpec>,
    revision: Vec<u8>,
) -> Option<r2source::SourceFunctionInterface> {
    interface
        .restated(slots, revision)
        .inspect_err(|error| {
            r2il::refusal_evidence!("restate-interface", "the slots do not restate: {error:?}");
        })
        .ok()
}

/// What the bodies a function calls say about their own boundaries.
#[derive(Default)]
struct Callees {
    interfaces: BTreeMap<u64, r2source::SourceFunctionInterface>,
    preserved: CalleePreservedCarriers,
    /// What each callee reaches through each pointer it is handed, which is
    /// what makes the bytes one callee covers one object in the caller.
    reach: BTreeMap<u64, BTreeMap<usize, ArgumentReach>>,
    /// The imports whose declaration states no interface: they have no body to read one off.
    unstated: BTreeMap<u64, r2ssa::UnstatedImport>,
}

impl Callees {
    /// These facts and the body's own library models, as preparation takes them.
    fn evidence(
        &self,
        library: BTreeMap<u64, r2ssa::interproc::FunctionSemanticSummary>,
        reentering: BTreeSet<u64>,
        exits: r2ssa::AssumedExits,
    ) -> r2ssa::CalleeEvidence {
        r2ssa::CalleeEvidence {
            interfaces: self.interfaces.clone(),
            preserved: self.preserved.clone(),
            reach: self.reach.clone(),
            library,
            reentering,
            exits,
            unstated_imports: self.unstated.clone(),
        }
    }

    /// Each resolved owner that proved facts, read as any callee's statement.
    fn state(&mut self, owners: &[(u64, Arc<CalleeRead>)]) {
        for (owner, read) in owners {
            if let Ok(facts) = &read.facts {
                self.record(*owner, facts);
            }
        }
    }

    fn record(&mut self, address: u64, facts: &CalleeFacts) {
        self.interfaces.insert(address, facts.interface().clone());
        self.preserved
            .insert(address, facts.preserved_carriers().clone());
        // Recorded even when empty: a body that touches nothing through its
        // arguments is described, and a callee with no entry is one nothing
        // describes.
        self.reach.insert(address, facts.argument_touch_reach());
    }
}

/// What the container states about whether a table's bytes, as the file holds them, are what
/// the dispatch reads when it runs; carried on `DispatchTable` and the listing's `Switch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableBytes {
    /// Mapped without write permission, and the loader leaves them alone: the bytes are the
    /// program's for its whole run.
    ReadOnly,
    /// The program may write them once it runs, and nothing the container states seals them
    /// after load: what the file holds is not what a dispatch reads, so the table is refused.
    Unsealed,
    /// Read-only once mapped, but the loader writes some (a rebase, a chained fixup): each entry
    /// is the word the container states it writes there, else the file's.
    LoaderWritten,
    /// Writable until start-up seals them (RELRO, `SG_READ_ONLY`): each entry is a word the
    /// container states the loader writes, or the table is refused (ROADMAP P5).
    Sealed,
}

impl TableBytes {
    /// O(log n): one search in the loader's writes and one in what it seals.
    fn of(program: &dyn Program, range: std::ops::Range<u64>) -> Self {
        use crate::program::Permanence;
        match program.permanence(&range) {
            Permanence::Writable => Self::Unsealed,
            Permanence::Sealed => Self::Sealed,
            // The interpreter seals it before this image runs: the file's word, else the loader's.
            Permanence::ReadOnly | Permanence::SealedByInterpreter
                if crate::stated::written(program, &range) =>
            {
                Self::LoaderWritten
            }
            Permanence::ReadOnly | Permanence::SealedByInterpreter => Self::ReadOnly,
        }
    }

    /// Whether the word `stated` is what the run reads, for a table of these bytes.
    fn holds(self, stated: crate::stated::StatedWord) -> bool {
        self != Self::Sealed || matches!(stated, crate::stated::StatedWord::Loaded(_))
    }

    /// Whether the table at `at` may be read as the run's, saying why
    /// wherever the answer is not a plain yes.
    fn read_as_run(self, at: u64) -> bool {
        match self {
            Self::LoaderWritten | Self::Sealed => {
                r2il::refusal_evidence!(
                    "dispatch-table",
                    "{at:#x}: {self:?}: read as the values the container states the loader writes"
                );
                true
            }
            Self::Unsealed => {
                r2il::refusal_evidence!(
                    "dispatch-table",
                    "{at:#x}: {self:?}: in memory the program may write, which \
                     nothing the container states seals after load"
                );
                false
            }
            Self::ReadOnly => true,
        }
    }
}

/// One function walked out of the program.
#[derive(Clone)]
struct Walked {
    name: String,
    body: crate::body::Body,
}

impl Walked {
    /// The same walk cut to the blocks an unresolved indirect branch is reachable from: a value there is built
    /// from the paths that arrive at it, and a kept block's edge to a cut one leaves the function. O(blocks + edges).
    fn reaching_unresolved(&self) -> Self {
        let blocks = &self.body.blocks;
        let block_at = |address: u64| {
            blocks
                .binary_search_by_key(&address, |block| block.lifted.addr)
                .ok()
        };
        let held = |address: u64| {
            let after = blocks.partition_point(|block| block.lifted.addr <= address);
            after.checked_sub(1)
        };
        let edges = (blocks.iter().enumerate()).flat_map(|(from, block)| {
            (block.successors.iter()).map(move |(_, target)| (from, *target))
        });
        let mut preceding = vec![Vec::new(); blocks.len()];
        for (from, target) in edges {
            if let Some(to) = block_at(target) {
                preceding[to].push(from);
            }
        }
        let indirect = self.body.unresolved.iter();
        let indirect =
            indirect.filter(|stop| stop.reason == crate::body::UnresolvedReason::IndirectBranch);
        let mut keep = vec![false; blocks.len()];
        let mut pending = indirect
            .filter_map(|stop| held(stop.addr))
            .collect::<Vec<_>>();
        while let Some(at) = pending.pop() {
            if !std::mem::replace(&mut keep[at], true) {
                pending.extend(preceding[at].iter().copied());
            }
        }
        if !keep.contains(&true) {
            return self.clone();
        }
        let kept = (blocks.iter().zip(&keep))
            .filter(|(_, kept)| **kept)
            .map(|(block, _)| block.clone())
            .collect();
        Self {
            name: self.name.clone(),
            body: crate::body::Body {
                entry: self.body.entry,
                blocks: kept,
                calls: self.body.calls.clone(),
                tail_calls: self.body.tail_calls.clone(),
                unresolved: self.body.unresolved.clone(),
                exits: self.body.exits.clone(),
            },
        }
    }
}

/// One program, one machine, and the walk over it.
/// One dispatch's table, read, and where the dispatch that reads it stands.
#[derive(Clone)]
struct NativePointerTable {
    instruction: u64,
    /// What the container states about whether the bytes read are the run's.
    stated: TableBytes,
    targets: Vec<u64>,
    /// What the selector is on each arm, and where that arm goes.
    cases: Vec<(u64, u64)>,
    table: r2source::SourceCodePointerTable,
}

struct Native<'a> {
    target: &'a NativeTarget<'a>,
    program: &'a dyn Program,
    machine: NativeMachine,
    /// Cancellation and the work meter, shared by the root and its callees.
    control: r2ssa::SsaExecutionControl,
}

impl<'a> Native<'a> {
    /// One body sealed against `callees`, and prepared again where it restates its declared frame
    /// or text it points at; in the closed world, sealed once more where its `CallBoundary` decides
    /// the result. Its first seal's facts are collected only where something reads them.
    fn resolve(
        &self,
        entry: u64,
        walk: &Walk,
        callees: &Callees,
        world: crate::program::World,
    ) -> Result<Resolution, NativeRefusal> {
        let declared_root = self.declaration(entry);
        let seal = self.seal_first(walk, callees, &declared_root, None)?;
        let first = First {
            entry,
            declared_root,
            seal,
        };
        Ok(self.finish(walk, callees, world, first)?.0)
    }

    /// A built body resolved against `owners` in the open world: its build sealed as it stands
    /// with none, else updated by their statements.
    fn resolve_built(
        &self,
        walk: &Walk,
        built: Built,
        owners: &[(u64, Arc<CalleeRead>)],
    ) -> Result<(Resolution, bool), NativeRefusal> {
        let Built {
            address,
            mut construction,
            mut imports,
            declared_root,
        } = built;
        if !owners.is_empty() {
            imports.state(owners);
            let evidence = self.evidence(&walk.root, &imports);
            let arch = Some(self.target.arch);
            let restated =
                construction.restated(arch, &self.control, &evidence, &premises_reading(false));
            let (restated, kept) = restated.map_err(NativeRefusal::of_preparation)?;
            r2il::refusal_evidence!(
                "restated",
                "{address:#x}: build {} against {} owners",
                if kept { "kept" } else { "rebuilt" },
                owners.len()
            );
            construction = restated;
        }
        let seal = construction.seal(&self.control);
        let first = First {
            entry: address,
            declared_root,
            seal: seal.map_err(NativeRefusal::of_preparation)?,
        };
        self.finish(walk, &imports, crate::program::World::Open, first)
    }

    /// What a body's first build captures: its declaration where it states an interface or the
    /// body reads tables.
    fn first_capture<'t>(
        walk: &'t Walk,
        declared_root: &Restatement,
        closed_result: Option<r2source::SourceClosedResult>,
    ) -> Capture<'t> {
        let (tables, calls) = (&walk.tables[..], &walk.calls[..]);
        let (restatement, tables) = match (declared_root.interface.is_some(), tables.is_empty()) {
            (false, true) => (Restatement::default(), &[][..]),
            _ => (declared_root.clone(), tables),
        };
        Capture {
            extra_literals: Vec::new(),
            restatement,
            tables,
            calls,
            closed_result,
        }
    }

    /// A body's first build, sealed.
    fn seal_first(
        &self,
        walk: &Walk,
        callees: &Callees,
        declared_root: &Restatement,
        reads: Option<r2source::SourceClosedResult>,
    ) -> Result<r2ssa::TrustedSeal, NativeRefusal> {
        let capture = Self::first_capture(walk, declared_root, reads);
        self.seal_captured(&walk.root, callees, capture)
    }

    /// A body's first build in the open world, before its seal: its interface names the owners
    /// of its result, and their statements update it (doc/adr-callee-builds.md).
    fn construct_first(
        &self,
        walk: &Walk,
        callees: &Callees,
        declared_root: &Restatement,
    ) -> Result<r2ssa::TrustedConstruction, NativeRefusal> {
        let capture = Self::first_capture(walk, declared_root, None);
        let (lifted, evidence) = self.lifted(&walk.root, callees, capture)?;
        TrustedSsaArtifact::construct_with_callee_interfaces(
            lifted,
            Some(self.target.arch),
            &self.control,
            &evidence,
            &premises_reading(false),
        )
        .map_err(NativeRefusal::of_preparation)
    }

    /// The callees' evidence as a capture of this body states it.
    fn evidence(&self, walked: &Walked, callees: &Callees) -> r2ssa::CalleeEvidence {
        let calls = call_sites(&walked.body, self.program);
        let library = library_evidence(self.program, &calls);
        callees.evidence(library, reentering_calls(&calls), walked.body.exits.clone())
    }

    /// A body resolved from its first seal, and whether another seal is the answer: one restating
    /// its declared frame or folded text, or the closed world's.
    fn finish(
        &self,
        walk: &Walk,
        callees: &Callees,
        world: crate::program::World,
        first: First,
    ) -> Result<(Resolution, bool), NativeRefusal> {
        let First {
            entry,
            declared_root,
            seal: mut first,
        } = first;
        let (root, tables, calls) = (&walk.root, &walk.tables[..], &walk.calls[..]);
        // The binary's debug information declares the body as a library declares an import.
        let declared_prototype =
            Declared::body(self.target, entry).map(|declared| declared.prototype);
        // The closed world's held decision, from the open read's supply (doc/adr-result-side.md, D317).
        let open = first.machine_context().function_interface().is_some();
        let reads = (world == crate::program::World::Closed && open)
            .then(|| self.program.closed_result(entry))
            .flatten();
        if reads.is_some() {
            drop(first);
            first = self.seal_first(walk, callees, &declared_root, reads)?;
        }
        // aarch64 forms an address from a page and an offset: its text is captured once folded.
        let folded = self.folded_literals(&first, root);
        // Only a declared frame's restatement reads the first's facts, or the first is the answer.
        let first = match declared_root.interface.is_some() || folded.is_empty() {
            true => Some(self.collected(first)?),
            false => None,
        };
        // The declared frame, measured from the pointer the function was entered with.
        let declared_root = match &first {
            Some(first) => crate::declared::rebased(declared_root, first, declared_prototype),
            None => declared_root,
        };
        let declared_slots = declared_root
            .interface
            .as_ref()
            .map(|interface| interface.stack_slots().to_vec())
            .unwrap_or_default();
        let restated = (first.as_ref()).and_then(|first| self.restated(first, &declared_slots));
        // A member's type is a declaration's (D166), so only a declared body mints from it.
        let declared = declared_root.interface.is_some();
        let members = (first.as_ref().filter(|_| declared))
            .map_or_else(Vec::new, |first| self.member_calls(first));
        let alone = restated.is_none() && folded.is_empty();
        let artifact = match first {
            Some(first) if alone && members.is_empty() => (first, reads.is_some()),
            first => {
                let rows = (first.as_ref()).map(|first| first.artifact().member_calls().clone());
                drop(first);
                let minted = !members.is_empty();
                if minted {
                    r2il::refusal_evidence!(
                        "member-calls",
                        "{entry:#x}: sealed again for {} member calls",
                        members.len()
                    );
                }
                // A body that proved no frame slot restates nothing, and the declaration stands.
                let restatement = Restatement {
                    interface: restated.or(declared_root.interface),
                    signature: declared_root.signature,
                    slot_names: declared_root.slot_names,
                    member_calls: members,
                };
                let retry = minted.then(|| (restatement.clone(), folded.clone()));
                let seal = self.seal(root, callees, folded, restatement, (tables, calls), reads)?;
                let second = self.collected(seal)?;
                // A contract adds no provenance, so the second seal proves the rows it was minted
                // from; where it does not, the contracts are a defect and the body seals without.
                let agrees = (rows.as_ref())
                    .is_some_and(|rows| rows.agrees(second.artifact().member_calls()));
                match retry.filter(|_| !agrees) {
                    None => (second, true),
                    Some((mut restatement, folded)) => {
                        r2il::refusal_evidence!(
                            "member-calls-defect",
                            "{entry:#x}: a member contract moved the member calls it was minted from"
                        );
                        drop(second);
                        restatement.member_calls.clear();
                        let seal =
                            self.seal(root, callees, folded, restatement, (tables, calls), reads)?;
                        (self.collected(seal)?, true)
                    }
                }
            }
        };
        Ok(artifact)
    }

    /// The contract of each call the first seal proves goes through a typed member (S32).
    fn member_calls(&self, first: &TrustedSsaArtifact) -> Vec<r2source::SourceCallSiteInterface> {
        let artifact = first.artifact();
        let Some(interface) = artifact.machine_context().function_interface() else {
            return Vec::new();
        };
        let Some(graph) = interface.type_graph() else {
            return Vec::new();
        };
        let placement = Placement::new(self.target, &self.machine);
        (artifact.member_calls().proven())
            .filter_map(|(_, call)| {
                placement.member_call(graph, &call, interface.revision_identity())
            })
            .collect()
    }

    fn over(target: &'a NativeTarget<'a>, program: &'a dyn Program) -> Result<Self, NativeRefusal> {
        Ok(Self {
            target,
            program,
            machine: machine(target)?,
            control: program.control().ssa_execution_control(),
        })
    }

    /// The tables a walked body's dispatches read; a refused read says why and leaves the body following none.
    fn read_tables(&self, root: &Walked) -> Tables {
        let ptr_bits = crate::engine_effective_ptr_bits(self.target.arch);
        let mut imports = Callees::default();
        declare_imports(
            self,
            self.target,
            &reached(&root.body, self.program),
            ptr_bits,
            &mut imports,
        );
        let declared = self.declaration(root.body.entry);
        let restatement = match declared.interface.is_some() {
            false => Restatement::default(),
            true => declared,
        };
        let read = crate::isolation::isolated(|| self.dispatch_reads(root, &imports, restatement));
        match read {
            Ok(Ok(reads)) => Tables {
                read: self.pointer_tables(reads.iter().filter(|read| !read.call)),
                refusal: None,
            },
            Ok(Err(refusal)) => Tables::refused(refusal),
            Err(panicked) => Tables::refused(panicked.into()),
        }
    }

    /// The same request over another machine of this program.
    fn in_target<'b>(&'b self, target: &'b NativeTarget<'b>) -> Option<Native<'b>> {
        Some(Native {
            target,
            program: self.program,
            machine: machine(target).ok()?,
            control: self.control.clone(),
        })
    }

    fn walk(&self, entry: u64) -> Result<Walked, NativeRefusal> {
        self.walk_dispatched(entry, &BTreeMap::new())
    }

    /// The same walk, told where the dispatches a previous pass read go.
    fn walk_dispatched(
        &self,
        entry: u64,
        dispatched: &BTreeMap<u64, Vec<u64>>,
    ) -> Result<Walked, NativeRefusal> {
        let body = crate::body::lift_body(entry, self.target.disasm, self.program, dispatched)
            .map_err(NativeRefusal::Body)?;
        Ok(self.walked(body))
    }

    /// One walked body, with what the program calls it.
    fn walked(&self, body: crate::body::Body) -> Walked {
        Walked {
            name: self
                .program
                .name_at(body.entry)
                .unwrap_or_else(|| r2source::unnamed_function(body.entry)),
            body,
        }
    }

    /// The tables the dispatches in a prepared body read, fetched.
    ///
    /// The engine captures a function's own bytes and nothing else, so a jump
    /// table in another section is memory nobody has looked at. The value
    /// analysis says where each dispatch reads and how far; this goes and
    /// reads it.
    ///
    /// Every entry must decode, or none of them are taken. A table is one
    /// object: an address in the middle of it that is not an instruction says
    /// the read was not a table walk, and half a table would be a guess about
    /// control flow, which is the one thing worse than an unresolved branch.
    fn pointer_tables<'r>(
        &self,
        reads: impl Iterator<Item = &'r r2ssa::indirect::DispatchTableRead>,
    ) -> Vec<NativePointerTable> {
        let (mut asked, mut tables) = (0, Vec::new());
        for read in reads {
            asked += 1;
            tables.extend(self.pointer_table(read));
        }
        r2il::refusal_evidence!(
            "dispatch-table",
            "{} of {asked} dispatch reads fetched",
            tables.len()
        );
        tables
    }

    /// The artifact prepared again with the tables its indirect calls read, if any (P5): one graph
    /// scan, and a second preparation only for a body with a fetched table.
    fn with_call_tables(
        &self,
        walk: &Walk,
        callees: &Callees,
        world: crate::program::World,
        artifact: Resolution,
    ) -> Result<Resolution, NativeRefusal> {
        let reads = r2ssa::indirect::dispatch_table_reads(artifact.shared_artifact().as_ref());
        let calls = self.pointer_tables(reads.iter().filter(|read| read.call));
        if calls.is_empty() {
            return Ok(artifact);
        }
        drop(artifact);
        let walk = Walk {
            calls,
            ..walk.clone()
        };
        self.resolve(walk.root.body.entry, &walk, callees, world)
    }

    /// Where each of a table's `count` entries sends the dispatch: the value
    /// the container states for its word when the dispatch runs, read through
    /// the one reader of stated memory, turned into a target as the read
    /// says. Every entry lies inside the table's span, which the caller has
    /// placed inside what the file holds of one region. The first entry
    /// nothing states the value of is the error, by index and place.
    fn stated_targets(
        &self,
        read: &r2ssa::indirect::DispatchTableRead,
        count: usize,
        stated: TableBytes,
    ) -> Result<Vec<u64>, (usize, u64)> {
        let endian = match self.machine.endianness {
            SourceEndianness::Little => r2il::Endianness::Little,
            SourceEndianness::Big => r2il::Endianness::Big,
        };
        (0..count)
            .map(|k| {
                let place = read.address + k as u64 * read.stride;
                crate::stated::stated_word(self.program, place, read.size, endian)
                    .filter(|word| stated.holds(*word))
                    .map(|word| read.transform.target(word.value(), read.size))
                    .ok_or((k, place))
            })
            .collect()
    }

    /// One dispatch's table, read and validated, or why it is not one.
    ///
    /// **Nothing is read until the program is known to have the bytes.** The
    /// value analysis proves how many entries the selector reaches, soundly
    /// and however many; what it cannot prove is that a table that long
    /// exists. The span is computed with checked arithmetic and must lie
    /// inside the one region holding its first entry, which is an O(1)
    /// question of the container's statement: a spilled 32-bit index reaching
    /// 16 GiB of table is refused here with no byte read, never allocated.
    /// It must lie in what the file holds of that region, too: past it the
    /// loader fills zeros, and a container can state a region as long as it
    /// likes. So every allocation below is bounded by the file's own size.
    ///
    /// A resolved dispatch has at least one target and every entry decodes
    /// where an instruction can run: a table of no entries would resolve the
    /// branch to nowhere, which the walk would read as a block with no
    /// successor rather than as a stop. Each distinct target is decoded once,
    /// since a table repeats its default arm for every hole in the case values.
    fn pointer_table(
        &self,
        read: &r2ssa::indirect::DispatchTableRead,
    ) -> Option<NativePointerTable> {
        let at = read.address;
        let refused = |why: std::fmt::Arguments<'_>| {
            r2il::refusal_evidence!("dispatch-table", "{at:#x}: {why}");
        };
        if read.count == 0 {
            refused(format_args!("a table of no entries sends control nowhere"));
            return None;
        }
        let (Some(span), Ok(count)) = (
            read.span().and_then(|span| usize::try_from(span).ok()),
            usize::try_from(read.count),
        ) else {
            refused(format_args!(
                "{} entries of {} bytes by {} span more than this machine addresses",
                read.count, read.size, read.stride
            ));
            return None;
        };
        let Some(region) = self.program.region(at) else {
            refused(format_args!("nothing is mapped there"));
            return None;
        };
        let end = at
            .checked_add(span as u64)
            .filter(|end| region.holds(at, *end));
        let Some(end) = end else {
            refused(format_args!(
                "{} entries by {} span {span} bytes, past the region ending at {:#x}",
                read.count, read.stride, region.end
            ));
            return None;
        };
        // Past what the file holds the loader fills zeros, and a container can
        // state a region as long as it likes: bounding the span by the file
        // is what bounds every allocation below by the file's own size.
        if end > region.file_end {
            refused(format_args!(
                "{} entries by {} span past what the file holds, which ends at {:#x}",
                read.count, read.stride, region.file_end
            ));
            return None;
        }
        let stated = TableBytes::of(self.program, at..end);
        if !stated.read_as_run(at) {
            return None;
        }
        let targets = match self.stated_targets(read, count, stated) {
            Ok(targets) => targets,
            Err((k, place)) => {
                refused(format_args!(
                    "entry {k} at {place:#x}: nothing the container states is what it holds when the dispatch runs"
                ));
                return None;
            }
        };
        let distinct = targets.iter().copied().collect::<BTreeSet<_>>();
        // An arm is code the container states is instructions, and decodes there.
        let arm = |target: u64| self.program.holds_code(target) && self.decodes(target);
        if let Some(target) = distinct.iter().find(|target| !arm(**target)) {
            refused(format_args!(
                "{} entries of {} bytes: entry target {target:#x} is not an instruction",
                read.count, read.size
            ));
            return None;
        }
        let cases = (0..read.count)
            .zip(&targets)
            .map(|(k, target)| Some((read.case(k)?, *target)))
            .collect::<Option<Vec<_>>>()?;
        Some(NativePointerTable {
            instruction: read.instruction?,
            stated,
            cases,
            table: self.captured(read, &targets)?,
            targets,
        })
    }

    /// The table as the snapshot carries it: where it lies, the dispatch that reads it, each target and its name.
    fn captured(
        &self,
        read: &r2ssa::indirect::DispatchTableRead,
        targets: &[u64],
    ) -> Option<r2source::SourceCodePointerTable> {
        let name = |target: &u64| self.program.name_at(*target).map(Into::into);
        Some(r2source::SourceCodePointerTable::new(
            read.address,
            read.size,
            read.instruction?,
            targets,
            targets.iter().map(name).collect::<Vec<_>>(),
        ))
    }

    /// Whether an instruction lives at an address, which is what makes a table
    /// entry a place control can go.
    fn decodes(&self, target: u64) -> bool {
        decodes(self.target.disasm, self.program, target)
    }

    /// The text a prepared body points at.
    ///
    /// A machine does not always write an address down: aarch64 forms one from
    /// a page and an offset, so the constant a string lives at exists only
    /// once the two are folded. Preparation folds them, and this asks it
    /// rather than re-scanning the operations that could not know.
    ///
    /// A residual: a folded value is read whatever uses it, so one that only
    /// an indirect call or jump uses is still looked up. Only code lying in a
    /// section the container states is data can be read as text that way,
    /// and ruling it out needs the def-use to say how each value is used.
    fn folded_literals(&self, seal: &r2ssa::TrustedSeal, walked: &Walked) -> Vec<(u64, String)> {
        let already = self
            .literals(&walked.body)
            .into_iter()
            .map(|(address, _)| address)
            .collect::<BTreeSet<_>>();
        let mut found = BTreeMap::new();
        for address in seal.folded_values() {
            if address == 0 || already.contains(&address) {
                continue;
            }
            if let Some(text) = text_at(self.program, address) {
                found.insert(address, text);
            }
        }
        found.into_iter().collect()
    }

    /// The interface the first pass recovered, restated with the frame slots the debug
    /// information declares; `None` where it declares none. A slot the body proves is the frame
    /// model's own (`SsaArtifact::stack_slot_role`), never restated as a declaration.
    fn restated(
        &self,
        artifact: &TrustedSsaArtifact,
        declared: &[r2source::SourceStackSlotSpec],
    ) -> Option<r2source::SourceFunctionInterface> {
        if declared.is_empty() {
            return None;
        }
        let prepared = artifact.shared_artifact();
        let interface = prepared.as_ref().machine_context().function_interface()?;
        restate(
            interface,
            declared.to_vec(),
            interface.revision_identity().to_vec(),
        )
    }

    /// What the binary's debug information declares about the body at this
    /// address, placed in this machine's carriers with the frame it states.
    fn declaration(&self, address: u64) -> Restatement {
        Declared::body(self.target, address)
            .map(|declared| Placement::new(self.target, &self.machine).restatement(declared, true))
            .unwrap_or_default()
    }

    /// One body captured, built and sealed, its facts not yet collected.
    fn seal(
        &self,
        walked: &Walked,
        callees: &Callees,
        extra_literals: Vec<(u64, String)>,
        restatement: Restatement,
        (tables, calls): (&[NativePointerTable], &[NativePointerTable]),
        closed_result: Option<r2source::SourceClosedResult>,
    ) -> Result<r2ssa::TrustedSeal, NativeRefusal> {
        let capture = Capture {
            extra_literals,
            restatement,
            tables,
            calls,
            closed_result,
        };
        self.seal_captured(walked, callees, capture)
    }

    /// One capture of a body built and sealed, its facts not yet collected.
    fn seal_captured(
        &self,
        walked: &Walked,
        callees: &Callees,
        capture: Capture<'_>,
    ) -> Result<r2ssa::TrustedSeal, NativeRefusal> {
        let closed = capture.closed_result.is_some();
        let (lifted, evidence) = self.lifted(walked, callees, capture)?;
        TrustedSsaArtifact::seal_with_callee_interfaces(
            lifted,
            Some(self.target.arch),
            &self.control,
            &evidence,
            &premises_reading(closed),
        )
        .map_err(NativeRefusal::of_preparation)
    }

    /// A seal's facts collected into the artifact.
    fn collected(
        &self,
        seal: r2ssa::TrustedSeal,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        let artifact = seal.collect(&self.control);
        artifact
            .map(Arc::new)
            .map_err(NativeRefusal::of_preparation)
    }

    /// Where each dispatch of a body walked without its tables reads them, off its seal alone.
    fn dispatch_reads(
        &self,
        walked: &Walked,
        callees: &Callees,
        restatement: Restatement,
    ) -> Result<Vec<r2ssa::indirect::DispatchTableRead>, NativeRefusal> {
        let seal = self.convention_seal(&walked.reaching_unresolved(), callees, restatement)?;
        Ok(seal.dispatch_table_reads())
    }

    /// One body captured, built against the convention alone and sealed: what values inside it
    /// read, which no interface decides.
    fn convention_seal(
        &self,
        walked: &Walked,
        callees: &Callees,
        restatement: Restatement,
    ) -> Result<r2ssa::TrustedSeal, NativeRefusal> {
        let capture = Capture {
            extra_literals: Vec::new(),
            restatement,
            tables: &[],
            calls: &[],
            closed_result: None,
        };
        let (lifted, evidence) = self.lifted(walked, callees, capture)?;
        TrustedSsaArtifact::seal_against_convention(
            lifted,
            Some(self.target.arch),
            &self.control,
            &evidence,
            &accepted_premises(),
        )
        .map_err(NativeRefusal::of_preparation)
    }

    /// One walked body captured and lifted against what is stated about it, and its callees' evidence.
    fn lifted(
        &self,
        walked: &Walked,
        callees: &Callees,
        capture: Capture<'_>,
    ) -> Result<(r2sleigh_lift::TrustedLiftedFunction, r2ssa::CalleeEvidence), NativeRefusal> {
        // A body the walk cut at its budget is no function's whole body: analysis refuses it, named.
        let cut = (walked.body.unresolved.iter())
            .any(|stop| stop.reason == crate::body::UnresolvedReason::Budget);
        if cut {
            return Err(NativeRefusal::Body(crate::body::BodyError::Oversized(
                walked.body.entry,
            )));
        }
        let Capture {
            extra_literals,
            restatement,
            tables,
            calls: call_tables,
            closed_result,
        } = capture;
        let Restatement {
            interface,
            signature,
            slot_names,
            member_calls,
        } = restatement;
        let arity = interface.as_ref().map_or(0, |i| i.parameters().len());
        let blocks = walked
            .body
            .blocks
            .iter()
            .map(|block| NativeBlock {
                address: block.lifted.addr,
                bytes: block.bytes.clone(),
                successors: block.successors.clone(),
                switch: tables
                    .iter()
                    .find(|table| {
                        (block.lifted.addr..block.lifted.addr + u64::from(block.lifted.size))
                            .contains(&table.instruction)
                    })
                    .map(|table| r2source::native::NativeSwitch {
                        instruction: table.instruction,
                        cases: table.cases.clone(),
                    }),
                unresolved: walked.body.unresolved.iter().any(|stop| {
                    stop.reason == crate::body::UnresolvedReason::IndirectBranch
                        && (block.lifted.addr..block.lifted.addr + u64::from(block.lifted.size))
                            .contains(&stop.addr)
                }),
            })
            .collect::<Vec<_>>();
        // The capture keeps an interface only where it is about the revision
        // being captured, which is what stops a restatement of other bytes
        // reaching this body. A declaration is about this body too, so it is
        // stated against this revision rather than against the name it was
        // read under -- without which a declared prototype was silently
        // dropped and every parameter went back to the width of its register.
        let identity = r2source::native::revision_identity(walked.body.entry, &blocks);
        let interface = interface.and_then(|interface| {
            let slots = interface.stack_slots().to_vec();
            restate(&interface, slots, identity.to_vec())
        });
        let calls = call_sites(&walked.body, self.program);
        let library = library_evidence(self.program, &calls);
        let reentering = reentering_calls(&calls);
        let exits = walked.body.exits.clone();
        let (data_symbols, data_types) = self.data_symbols(&walked.body);
        let function = NativeFunction {
            address: walked.body.entry,
            name: walked.name.clone(),
            blocks,
            calls,
            string_literals: {
                let mut literals = self.literals(&walked.body);
                literals.extend(extra_literals);
                literals.sort_by_key(|(address, _)| *address);
                literals.dedup_by_key(|(address, _)| *address);
                literals
            },
            read_only: self.read_only(&walked.body),
            data_symbols,
            data_types,
            code_pointer_tables: (tables.iter().chain(call_tables))
                .map(|table| table.table.clone())
                .collect(),
            parameter_names: declared_parameter_names(signature.as_ref(), arity),
            // A name has to land on a slot the interface carries, and which
            // slots survive is decided by what the body proved, so the names
            // are cut to fit here rather than where they were read.
            stack_slot_names: slot_names
                .into_iter()
                .filter(|name| {
                    interface.as_ref().is_some_and(|interface| {
                        interface.stack_slots().iter().any(|slot| {
                            slot.base() == name.base() && slot.offset() == name.offset()
                        })
                    })
                })
                .collect(),
            signature,
            interface,
            closed_result,
            frame_saves: self.program.frame_saves(walked.body.entry),
            member_calls,
        };

        let snapshot =
            r2source::native::capture(&self.machine, function).map_err(NativeRefusal::Capture)?;
        let lifted = Disassembler::lift_owned_function(snapshot)
            .map_err(|error| NativeRefusal::Lift(error.to_string()))?;
        Ok((lifted, callees.evidence(library, reentering, exits)))
    }
}

/// What a capture states beyond the walked body: literals folded since, a restatement, the tables
/// its dispatches and its indirect calls read, and what callers read of its result.
struct Capture<'t> {
    extra_literals: Vec<(u64, String)>,
    restatement: Restatement,
    tables: &'t [NativePointerTable],
    calls: &'t [NativePointerTable],
    closed_result: Option<r2source::SourceClosedResult>,
}

/// Every function this body reaches by a call, tail jump, loaded slot or folded target, each once
/// in address order: one callee declared twice is a duplicate address the type analysis rejects.
fn reached(body: &crate::body::Body, program: &dyn Program) -> Vec<u64> {
    body.calls
        .iter()
        .chain(body.tail_calls.iter())
        .copied()
        .chain(
            call_sites(body, program)
                .into_iter()
                .map(|site| site.target),
        )
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Where each transfer to another function is made and what it reaches, as the walk read it.
fn call_sites(body: &crate::body::Body, program: &dyn Program) -> Vec<NativeCall> {
    let mut sites = Vec::new();
    for block in &body.blocks {
        for transfer in &block.transfers {
            let Some(instruction) = block.lifted.instruction_of(transfer.op) else {
                continue;
            };
            sites.push(NativeCall {
                instruction,
                target: transfer.target,
                name: program.name_at(transfer.target),
                transfer: transfer.kind,
                linkage: match program.import_at(transfer.target) {
                    Some(_) => r2source::AdvisoryCalleeLinkage::Imported,
                    None => r2source::AdvisoryCalleeLinkage::Internal,
                },
            });
        }
    }
    sites
}

/// The library model of each import a body calls, by the name the container
/// binds it with; a local function is described by its body, not its name.
fn library_evidence(
    program: &dyn Program,
    calls: &[NativeCall],
) -> BTreeMap<u64, r2ssa::interproc::FunctionSemanticSummary> {
    calls
        .iter()
        .filter(|call| call.linkage == r2source::AdvisoryCalleeLinkage::Imported)
        .filter_map(|call| {
            let name = program.import_at(call.target)?;
            Some((
                call.target,
                crate::library::import_summary(call.target, &name)?,
            ))
        })
        .collect()
}

/// The call targets r2abi's runtime model says re-enter their caller at its entry, by the name the
/// program gives them: a model keyed by name, which the stack check weighs beside its shape.
fn reentering_calls(calls: &[NativeCall]) -> BTreeSet<u64> {
    calls
        .iter()
        .filter(|call| call.transfer == r2source::AdvisoryCallTransfer::Call)
        .filter(|call| {
            call.name
                .as_deref()
                .is_some_and(r2abi::runtime::reenters_caller)
        })
        .map(|call| call.target)
        .collect()
}

impl Native<'_> {
    /// The text this body points at.
    ///
    /// A constant the code computes with is not a pointer, and nothing here
    /// claims it is: the address has to hold a run of printable bytes ending
    /// in a terminator for it to be read as text at all.
    fn literals(&self, body: &crate::body::Body) -> Vec<(u64, String)> {
        referenced(body)
            .into_iter()
            .filter_map(|address| Some((address, text_at(self.program, address)?)))
            .collect()
    }

    /// The bytes at each literal address the body loads from, where the program never writes
    /// them and the loader does not (`TableBytes::ReadOnly`): what every such load reads (P5).
    fn read_only(&self, body: &crate::body::Body) -> Vec<(u64, Vec<u8>)> {
        let (loads, stores) = literal_accesses(body);
        loads
            .into_iter()
            .filter_map(|(address, size)| {
                let bytes = self.program.read(address, size)?;
                let range = address..address.checked_add(bytes.len() as u64)?;
                // A body that stores there says the container's statement is not this run's.
                let stored = stores
                    .iter()
                    .any(|written| written.start < range.end && range.start < written.end);
                (bytes.len() == size
                    && !stored
                    && TableBytes::of(self.program, range) == TableBytes::ReadOnly)
                    .then_some((address, bytes))
            })
            .collect()
    }

    /// The named program data this body points at, each with the type the
    /// binary's debug information declares at its address, and their graph.
    fn data_symbols(
        &self,
        body: &crate::body::Body,
    ) -> (Vec<SourceDataObject>, Option<r2source::SourceTypeGraph>) {
        let declarations = self.target.declarations;
        let named = referenced(body)
            .into_iter()
            .filter(|address| !body.calls.contains(address))
            // An import's slot is a word the loader fills, not an object the source names: its
            // relocation's name is the function's, and `&memcpy` is not where the slot is.
            .filter(|address| {
                self.program.import_at(*address).is_none()
                    || r2abi::statement::write_at(self.program.loader_writes(), *address)
                        .is_none_or(|write| write.place != *address)
            })
            .filter_map(|address| Some((address, self.program.name_at(address)?)))
            .collect::<Vec<_>>();
        let types = (named.iter())
            .map(|(address, _)| declarations.object_at(*address).map(|object| object.ty))
            .collect::<Vec<_>>();
        let (nodes, graph) = crate::declared::object_types(self.target, &types);
        let objects = (named.into_iter().zip(nodes))
            .map(|((address, name), node)| SourceDataObject::new(address, name, node))
            .collect();
        (objects, graph)
    }

    /// What one call operation calls, as the walk's transfer names it: a direct call its
    /// target, a call through a sealed import slot that import (`CallSlot`, audit W8).
    fn called_name(
        &self,
        sites: &[NativeCall],
        op: &r2ssa::SSAOp<r2ssa::ValueId>,
    ) -> Option<(u64, String)> {
        let instruction = op.call()?.instruction?;
        let site = sites.iter().find(|site| site.instruction == instruction)?;
        // A row applies to an import only, never to a body by its name.
        Some((instruction, self.program.import_at(site.target)?))
    }

    /// Addresses this body hands to a parameter a declaration calls a function.
    ///
    /// `entry0` never calls `main`. It puts `main` in an argument register and
    /// calls `__libc_start_main`, whose prototype spells that parameter
    /// `func`, so the address is a function on the declaration's authority.
    /// Nothing here guesses: a constant is believed only where a declared type
    /// says that slot holds a function, and the caller checks it decodes in
    /// the instruction set the pointer names.
    fn handed_functions(&self, seal: &r2ssa::TrustedSeal, walked: &Walked) -> Vec<u64> {
        let sites = call_sites(&walked.body, self.program);
        let mut found = Vec::new();
        let graph = seal.graph();
        for block in &graph.blocks {
            for &inst in graph.op_insts(block.id) {
                let (Some(op), Some(id)) = (graph.op(inst), graph.op_for_inst(inst)) else {
                    continue;
                };
                let Some((instruction, callee)) = self.called_name(&sites, op) else {
                    continue;
                };
                let Some(declared) = Declared::import(self.target, &callee) else {
                    continue;
                };
                let prototype = declared.prototype;
                // The convention places each parameter: by class, or by position where shared.
                let registers = |placement: &Placement<'_>| placement.registers(declared);
                let placed = placing_imports(self.target, Some(&self.machine), registers);
                let placed = placed.unwrap_or_default();
                for (index, (parameter, storage)) in
                    prototype.parameters.iter().zip(&placed).enumerate()
                {
                    let (true, Some(storage)) = (parameter.is_function(), storage) else {
                        continue;
                    };
                    let Some(address) = (seal.value_reaching(id, *storage))
                        .and_then(|value| seal.folded_value(value))
                    else {
                        continue;
                    };
                    if address != 0 {
                        r2il::refusal_evidence!(
                            "handed-function",
                            "{instruction:#x}: {} argument {index} is {address:#x}",
                            prototype.name
                        );
                        found.push(address);
                    }
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }
}

/// The text a section of static data holds at an address, where the loader leaves every byte of it and its terminator alone; the one reader a rendering and a listing share.
pub(crate) fn text_at(program: &dyn Program, address: u64) -> Option<String> {
    if !program.holds_static_data(address) {
        return None;
    }
    let bytes = program.read(address, crate::names::LITERAL_LIMIT)?;
    let text = crate::names::text_in(&bytes)?;
    let end = address.saturating_add(text.len() as u64 + 1);
    (!crate::stated::written(program, &(address..end))).then(|| text.to_owned())
}

/// [`text_at`] where no write reaches its bytes for the whole run: mapped read-only and untouched
/// by the loader (`TableBytes::ReadOnly`), so a call reads the text the file holds.
pub(crate) fn immutable_text_at(program: &dyn Program, address: u64) -> Option<String> {
    let text = text_at(program, address)?;
    let end = address.checked_add(text.len() as u64 + 1)?;
    (TableBytes::of(program, address..end) == TableBytes::ReadOnly).then_some(text)
}

/// Whether an instruction decodes at an address, in a region where one can run.
///
/// Data decodes as well as code on most machines, so the bytes alone cannot
/// say an address is a place control goes; the region the program maps it in
/// can.
pub(crate) fn decodes(disasm: &Disassembler, program: &dyn Program, at: u64) -> bool {
    if !program.region(at).is_some_and(|region| region.execute) {
        return false;
    }
    let Some(window) = program.read(at, WINDOW) else {
        return false;
    };
    let available = window.len();
    let endian = disasm.arch_spec().memory_endianness;
    let mut fetch = crate::stated::code(program.loader_writes(), at, window, endian).bytes;
    fetch.resize(WINDOW, 0);
    disasm
        .lift(&fetch, at)
        .is_ok_and(|lifted| lifted.size != 0 && lifted.size as usize <= available)
}

/// Every address this body names as a constant it reads as data.
///
/// Where a branch or a call sends control is executed, not read, so its
/// target is no constant of the body's: no string or object is looked for
/// there.
fn referenced(body: &crate::body::Body) -> BTreeSet<u64> {
    let mut addresses = BTreeSet::new();
    for block in &body.blocks {
        for op in &block.lifted.ops {
            for varnode in op.data_inputs() {
                // Whether a constant is an address is decided by what is
                // there, not by how large it is: a binary linked low puts its
                // strings at four-digit addresses.
                if matches!(varnode.space, r2il::SpaceId::Ram | r2il::SpaceId::Const)
                    && varnode.offset != 0
                {
                    addresses.insert(varnode.offset);
                }
            }
        }
    }
    addresses
}

/// Each literal address the body loads from with the widest load there, and the ranges it stores to.
fn literal_accesses(body: &crate::body::Body) -> (BTreeMap<u64, usize>, Vec<std::ops::Range<u64>>) {
    let literal = |addr: &r2il::Varnode| {
        matches!(addr.space, r2il::SpaceId::Ram | r2il::SpaceId::Const) && addr.offset != 0
    };
    let mut loads = BTreeMap::new();
    let mut stores = Vec::new();
    let accesses = (body.blocks.iter())
        .flat_map(|block| &block.lifted.ops)
        .flat_map(r2il::R2ILOp::memory_accesses);
    for access in accesses {
        let (addr, size) = (access.addr, access.size);
        match access.kind {
            r2il::eval::AccessKind::Read if literal(addr) && !access.repeated => {
                let size = usize::try_from(size).unwrap_or(usize::MAX);
                let widest = loads.entry(addr.offset).or_insert(size);
                *widest = (*widest).max(size);
            }
            r2il::eval::AccessKind::Write if literal(addr) => stores.push(match access.repeated {
                // A repeated write's extent turns on a count and a direction, so it may reach any byte.
                true => 0..u64::MAX,
                false => addr.offset..addr.offset.saturating_add(u64::from(size)),
            }),
            r2il::eval::AccessKind::Read | r2il::eval::AccessKind::Write => {}
        }
    }
    (loads, stores)
}

/// State the machine from the compiler specification and the function's convention model.
fn machine(target: &NativeTarget<'_>) -> Result<NativeMachine, NativeRefusal> {
    let (family, bits, endianness) = profile(target.arch)?;
    // A machine that leaves the return address in a register says so; one that
    // pushes it names a stack location, and then the carrier the return reads
    // is the program counter.
    let return_address_name = target
        .compiler
        .return_address
        .as_deref()
        .unwrap_or_else(|| target.disasm.program_counter());
    let return_address = storage(target.arch, return_address_name)?;
    let stack_pointer_name = target
        .compiler
        .stack_pointer
        .as_deref()
        .ok_or(NativeRefusal::NoStackPointer)?;
    let stack_pointer = storage(target.arch, stack_pointer_name)?;

    // Which way the stack grows is a fact about the machine, so it comes from
    // the compiler specification; how far past the stack pointer a leaf may
    // write is a fact about the ABI, so the red zone comes from the convention.
    let growth = match target.compiler.stack_growth {
        r2sleigh_lift::profile::StackGrowth::Lower => SourceStackGrowth::LowerAddresses,
        r2sleigh_lift::profile::StackGrowth::Higher => SourceStackGrowth::HigherAddresses,
    };
    let model = &*target.convention;
    let frame_pointer = model.forms.frame_pointer;
    let roles = SourceMachineRoles::new(Some(return_address), Some(stack_pointer))
        .and_then(|roles| {
            roles.with_stack_allocation_contract(
                SourceStackAllocationContract::with_implicit_active_sp_bytes(
                    growth,
                    model.forms.red_zone,
                ),
            )
        })
        .map_err(|_| NativeRefusal::Machine("the carriers are not register storages"))?
        .with_call_pushes_return_address(target.compiler.return_address_slot.is_some())
        // The names, not only the storages: the trusted lift restates every
        // carrier in its own architecture's numbering, and it looks the
        // carriers up by name to do it.
        .with_role_register_names(SourceRoleRegisterNames::new(
            Some(return_address_name),
            Some(stack_pointer_name),
            frame_pointer.and_then(|storage| register_named(target.arch, storage)),
        ));
    let roles = match frame_pointer {
        Some(frame_pointer) => roles
            .with_frame_pointer(frame_pointer)
            .map_err(|_| NativeRefusal::Machine("the frame pointer is not a register storage"))?,
        None => roles,
    };
    let slots = model
        .convention_slots()
        .map_err(|_| NativeRefusal::Machine("the convention names one register twice"))?;
    let call_effect = target.call.call_effect().inspect_err(|error| {
        r2il::refusal_evidence!("call-effect", "{:?}: {error:?}", model.id);
    });
    Ok(NativeMachine {
        arch_id: family.to_owned(),
        cpu_id: target.cpu.to_owned(),
        bits,
        endianness,
        roles,
        slots,
        // Asked in the first pass, before an interface exists; without it a caller loses its frame facts.
        call_effect: call_effect.ok(),
        convention: Some(Arc::clone(&target.convention)),
    })
}

/// The name the architecture gives a register storage.
fn register_named(arch: &ArchSpec, storage: CanonicalStorageId) -> Option<&str> {
    let named = arch.registers.iter().find(|register| {
        storage.space == CanonicalStorageSpace::Register
            && register.offset == storage.offset
            && register.size == storage.size
    });
    named.map(|register| register.name.as_str())
}

/// Where the container places the guard words a C library's row names; the row says which applies.
#[derive(Debug, Clone, Default)]
pub struct ContainerGuards {
    /// The PE load configuration's `/GS` cookie.
    pub cookie: Option<u64>,
    /// The `GuardRow::LinkedGlobal` word, where the container binds it (`stated::linked_guard`).
    pub linked: Option<r2source::SourceLinkedGuard>,
}

/// One convention's model on this machine: the specification's default prototype joined with
/// the ABI's row, every register resolved once (doc/adr-call-boundary.md, "The joined model").
///
/// A location or result register the architecture lacks refuses the model; a preserved,
/// killed or reserved one it lacks costs precision, never soundness, and is left out.
pub fn convention_model(
    arch: &ArchSpec,
    bits: u32,
    (kernel, library, guards): (r2abi::Kernel, r2abi::CLibrary, ContainerGuards),
    profile: &LanguageProfile,
    row: &r2abi::ConventionRow,
) -> Result<ConventionModel, NativeRefusal> {
    let prototype = profile.default_prototype().ok_or(NativeRefusal::Machine(
        "the compiler specification states no prototype",
    ))?;
    let at = Resolver { arch, id: row.id };
    let (sections, hidden_return) = sections(&at, prototype, row)?;
    let link = profile.return_address.as_deref().and_then(|n| at.placed(n));
    let (preserved, reserved) = duties(&at, prototype, link, bits, kernel);
    let owned = owned(prototype, row.home, &sections, profile.return_address_slot);
    let results = results(&at, prototype, row, &sections)?;
    let parts = ConventionParts {
        id: row.id,
        sections,
        hidden_return,
        results_complete: complete(&results, row),
        results,
        owned,
        preserved,
        killed: at.lanes(&prototype.killed_by_call),
        likely_trash: at.lanes(&prototype.likely_trash),
        reserved,
        link,
        forms: forms(&at, prototype, row, bits, (library, guards)),
        refused: row.refused,
    };
    ConventionModel::new(parts).map_err(|why| NativeRefusal::Machine(why.why()))
}

/// Where a convention's register names are placed on one architecture.
struct Resolver<'a> {
    arch: &'a ArchSpec,
    id: r2abi::ConventionId,
}

impl Resolver<'_> {
    fn resolve(&self, name: &str) -> Option<CanonicalStorageId> {
        r2sleigh_lift::lifted_register_storage(self.arch, name).filter(|storage| storage.size != 0)
    }

    /// Placed, or left out with the evidence of why.
    fn placed(&self, name: &str) -> Option<CanonicalStorageId> {
        let placed = self.resolve(name);
        if placed.is_none() {
            r2il::refusal_evidence!(
                "call-effect",
                "{:?}: {} names no single register of {}",
                self.id,
                name,
                self.arch.name
            );
        }
        placed
    }

    fn required(&self, name: &str) -> Result<CanonicalStorageId, NativeRefusal> {
        (self.resolve(name)).ok_or_else(|| NativeRefusal::UnknownRegister(name.to_owned()))
    }

    /// Every register of a list as the lanes it is of its root; addresses are no lanes.
    fn lanes(&self, list: &[SpecStorage]) -> Box<[LaneSet]> {
        (list.iter())
            .filter_map(|storage| match storage {
                SpecStorage::Register(name) => self.placed(name).map(|lane| self.in_root(lane)),
                SpecStorage::Address { .. } => None,
            })
            .collect()
    }

    /// A register as bytes of the widest register holding it: AAPCS64 6.1.2's `d8` is `z8` 0..8.
    fn in_root(&self, lane: CanonicalStorageId) -> LaneSet {
        let end = |offset: u64, size: u32| offset + u64::from(size);
        let root = (self.arch.registers.iter())
            .filter(|root| !root.hidden && root.offset <= lane.offset)
            .filter(|root| end(lane.offset, lane.size) <= end(root.offset, root.size))
            .max_by_key(|root| (root.size, std::cmp::Reverse(root.offset)))
            .map(|root| CanonicalStorageId {
                space: lane.space,
                offset: root.offset,
                size: root.size,
            });
        let bytes = |root: CanonicalStorageId| {
            let start = u8::try_from(lane.offset - root.offset).ok()?;
            Some(start..start.checked_add(u8::try_from(lane.size).ok()?)?)
        };
        match root.and_then(|root| Some((root, bytes(root)?))) {
            Some((storage, bytes)) if storage.size <= u32::from(u8::MAX) => {
                LaneSet { storage, bytes }
            }
            _ => LaneSet::whole(lane),
        }
    }
}

/// How a narrower value fills an entry: the ABI's override where it states one, else the cspec's.
fn extension(
    row: &r2abi::ConventionRow,
    side: r2abi::Side,
    entry: &ParamEntry,
) -> r2abi::Extension {
    let stated = row.overrides.iter().find_map(|item| match *item {
        r2abi::SpecOverride::Extension {
            side: on,
            class,
            extension,
            ..
        } if on == side && class == entry.class => Some(extension),
        _ => None,
    });
    stated.unwrap_or(entry.extension)
}

/// Integer, float and stack apart, or Microsoft x64's shared positions; and the hidden result pointer.
fn sections(
    at: &Resolver<'_>,
    prototype: &r2sleigh_lift::profile::ProtoModel,
    row: &r2abi::ConventionRow,
) -> Result<(Box<[Section]>, Option<CanonicalStorageId>), NativeRefusal> {
    let mut locations = Vec::new();
    let mut hidden_return = None;
    for entry in &prototype.input {
        let SpecStorage::Register(name) = &entry.at else {
            continue;
        };
        match entry.class {
            SlotClass::Integer | SlotClass::Float => locations.push(Location::Register {
                storage: at.required(name)?,
                bytes: u8::try_from(*entry.size.end()).unwrap_or(u8::MAX),
                class: entry.class,
                position: entry.group,
                extension: extension(row, r2abi::Side::Input, entry),
            }),
            SlotClass::HiddenReturn => hidden_return = at.placed(name),
            SlotClass::Stack => {}
        }
    }
    let section = |class, of: SlotClass| Section {
        class,
        locations: (locations.iter())
            .filter(|location| matches!(location, Location::Register { class, .. } if *class == of))
            .copied()
            .collect(),
    };
    let mut sections = match prototype.shares_positions() {
        true => vec![Section {
            class: SectionClass::Shared,
            locations: locations.clone().into(),
        }],
        false => vec![
            section(SectionClass::Integer, SlotClass::Integer),
            section(SectionClass::Float, SlotClass::Float),
        ],
    };
    if let Some((first, step)) = prototype.stack_arguments() {
        sections.push(Section {
            class: SectionClass::Stack { first, step },
            locations: Box::default(),
        });
    }
    Ok((sections.into(), hidden_return))
}

/// The specification's `<output>` registers, then the lanes a cited override adds, each with what
/// it holds at entry and the lane it follows (doc/adr-result-side.md, "The lane set").
fn results(
    at: &Resolver<'_>,
    prototype: &r2sleigh_lift::profile::ProtoModel,
    row: &r2abi::ConventionRow,
    sections: &[Section],
) -> Result<Box<[ResultLane]>, NativeRefusal> {
    let mut results = Vec::new();
    let lane = |storage, class, extension, stated_by| ResultLane {
        storage,
        class,
        extension,
        stated_by,
        entry: LaneEntry::Scratch,
        follows: None,
    };
    for entry in &prototype.output {
        if let SpecStorage::Register(name) = &entry.at {
            results.push(lane(
                at.required(name)?,
                entry.class,
                extension(row, r2abi::Side::Output, entry),
                LaneSource::Specification,
            ));
        }
    }
    for item in row.overrides {
        let r2abi::SpecOverride::Results { class, lanes, .. } = *item else {
            continue;
        };
        for storage in lanes.iter().filter_map(|name| at.placed(name.0)) {
            if !results.iter().any(|stated| stated.storage == storage) {
                results.push(lane(
                    storage,
                    class,
                    r2abi::Extension::Unspecified,
                    LaneSource::Override,
                ));
            }
        }
    }
    let arguments = (sections.iter())
        .flat_map(|section| section.locations.iter())
        .filter_map(|location| match location {
            Location::Register { storage, .. } => Some(*storage),
            _ => None,
        })
        .collect::<Vec<_>>();
    let set = row.results;
    let named = |names: &[r2abi::RegName]| {
        names
            .iter()
            .filter_map(|name| at.placed(name.0))
            .collect::<Vec<_>>()
    };
    let empty = set.map(|set| named(set.empty)).unwrap_or_default();
    let pairs = (set.iter().flat_map(|set| set.follows.iter()))
        .filter_map(|(lane, first)| Some((at.placed(lane.0)?, at.placed(first.0)?)))
        .collect::<Vec<_>>();
    let storages = results.iter().map(|lane| lane.storage).collect::<Vec<_>>();
    for lane in &mut results {
        lane.entry = if empty.iter().any(|held| overlap(*held, lane.storage)) {
            LaneEntry::Empty
        } else if arguments.iter().any(|held| overlap(*held, lane.storage)) {
            LaneEntry::Input
        } else {
            LaneEntry::Scratch
        };
        lane.follows = (pairs.iter())
            .find(|(follower, _)| overlap(*follower, lane.storage))
            .and_then(|(_, first)| storages.iter().position(|held| overlap(*held, *first)));
    }
    Ok(results.into())
}

/// The cited completeness of a lane set, where the row states it and the set fits a site's boundary.
fn complete(results: &[ResultLane], row: &r2abi::ConventionRow) -> Option<&'static str> {
    // Overlapping lanes (`XMM0_Qa` beside `xmm0`) are one lane.
    let distinct = (0..results.len())
        .filter(|at| {
            !results[..*at]
                .iter()
                .any(|earlier| overlap(earlier.storage, results[*at].storage))
        })
        .count();
    if distinct > r2source::convention::RESULT_LANES {
        r2il::refusal_evidence!(
            "result-lanes",
            "{:?} returns in {distinct} lanes, past the {} a boundary tracks",
            row.id,
            r2source::convention::RESULT_LANES
        );
        return None;
    }
    row.results.map(|set| set.citation)
}

/// Whether two storages share a byte.
fn overlap(one: CanonicalStorageId, other: CanonicalStorageId) -> bool {
    one.space == other.space
        && one.offset < other.offset + u64::from(other.size)
        && other.offset < one.offset + u64::from(one.size)
}

/// Who owns each entry-relative stack range the specification states. A `localrange` from the
/// return address's end, one ABI home per shared position, is those homes; any other the callee's.
fn owned(
    prototype: &r2sleigh_lift::profile::ProtoModel,
    home: Option<r2abi::HomeArea>,
    sections: &[Section],
    return_address: Option<(i64, u32)>,
) -> Box<[OwnedRange]> {
    let range = |r: &r2sleigh_lift::profile::StackRange| Some(r.first..r.last.checked_add(1)?);
    let slot = return_address.and_then(|(offset, size)| {
        Some(OwnedRange::ReturnAddress(
            offset..offset.checked_add(i64::from(size))?,
        ))
    });
    let positions = (sections.iter())
        .filter(|section| section.class == SectionClass::Shared)
        .flat_map(|section| section.locations.iter())
        .filter_map(|location| match *location {
            Location::Register { position, .. } => u8::try_from(position).ok(),
            Location::Stack { .. } => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let above = return_address.and_then(|(offset, size)| offset.checked_add(i64::from(size)));
    let homes = |at: &std::ops::Range<i64>| -> Option<Vec<OwnedRange>> {
        let step = i64::from(home?.step);
        let end = at.start + step * i64::try_from(positions.len()).ok()?;
        (Some(at.start) == above && at.end == end && !positions.is_empty()).then(|| {
            (positions.iter().zip(0..))
                .map(|(&position, nth)| OwnedRange::Home {
                    position,
                    at: at.start + nth * step..at.start + (nth + 1) * step,
                })
                .collect()
        })
    };
    (prototype.local_range.iter())
        .filter_map(range)
        .flat_map(|at| homes(&at).unwrap_or_else(|| vec![OwnedRange::Callee(at)]))
        .chain((prototype.param_range.iter()).filter_map(|r| range(r).map(OwnedRange::Arguments)))
        .chain(slot)
        .collect()
}

/// What a call preserves (`unaffected` less the return address, and the ABI's callee-saved
/// rows) and what the platform reserves.
fn duties(
    at: &Resolver<'_>,
    prototype: &r2sleigh_lift::profile::ProtoModel,
    link: Option<CanonicalStorageId>,
    bits: u32,
    kernel: r2abi::Kernel,
) -> (Box<[LaneSet]>, Box<[LaneSet]>) {
    let mut preserved = at.lanes(&prototype.unaffected).into_vec();
    preserved.retain(|lanes| Some(lanes.storage) != link);
    let mut reserved = Vec::new();
    let rows = r2abi::architecture_registers(&at.arch.name)
        .iter()
        .chain(r2abi::platform_registers(&at.arch.name, bits, kernel));
    for duty in rows {
        let Some(storage) = at.placed(duty.register) else {
            continue;
        };
        let into = match duty.duty {
            r2abi::RegisterDuty::SystemReserved => &mut reserved,
            r2abi::RegisterDuty::CalleeSaved => &mut preserved,
        };
        into.extend(covered_runs(storage, duty));
    }
    preserved.sort_unstable();
    preserved.dedup();
    (preserved.into(), reserved.into())
}

/// What the row states beyond locations, its registers placed.
fn forms(
    at: &Resolver<'_>,
    prototype: &r2sleigh_lift::profile::ProtoModel,
    row: &r2abi::ConventionRow,
    bits: u32,
    (library, guards): (r2abi::CLibrary, ContainerGuards),
) -> BoundaryForms {
    let guard = |guard: Option<&r2abi::StackGuard>| {
        let guard = guard?;
        Some(r2source::SourceStackGuard {
            base: at.placed(guard.register.0)?,
            offset: guard.offset,
            width: guard.width,
        })
    };
    let guard_row = r2abi::guard_row(&at.arch.name, bits, library);
    BoundaryForms {
        frame_pointer: row.frame_pointer.and_then(|name| at.resolve(name.0)),
        red_zone: row.red_zone,
        save_area: row.save_area.map(|area| r2source::SourceRegisterSaveArea {
            anchor: match area.anchor {
                r2abi::SaveAreaAnchor::Base => r2source::SourceSaveAreaAnchor::Base,
                r2abi::SaveAreaAnchor::End => r2source::SourceSaveAreaAnchor::End,
            },
            offset_field: area.offset_field,
            offset_width: area.offset_width,
            stack_field: area.stack_field,
        }),
        count_register: row.count_register.and_then(|name| at.resolve(name.0)),
        entry_stack: row.entry_stack.map(|stack| r2source::SourceEntryStack {
            alignment: stack.alignment,
            residue: stack.residue,
        }),
        variadic_on_stack: prototype.variadic_on_stack,
        guard: guard(match guard_row {
            Some(r2abi::GuardRow::ThreadSlot(slot)) => Some(slot),
            _ => None,
        }),
        stack_bound: guard(row.stack_bound.as_ref()),
        // The row says the C library checks a load-config cookie; the container says where.
        security_cookie: matches!(guard_row, Some(r2abi::GuardRow::LoadConfigCookie))
            .then_some(guards.cookie)
            .flatten()
            .map(|address| r2source::SourceSecurityCookie {
                address,
                width: bits / 8,
            }),
        // The row names the library's global; only the container's binding places it.
        linked_guard: matches!(guard_row, Some(r2abi::GuardRow::LinkedGlobal(_)))
            .then_some(guards.linked)
            .flatten(),
    }
}

/// The runs of whole bytes of `storage` a platform row's duty covers.
///
/// A row that speaks for the whole register is the register; one that speaks
/// for some of its bits claims only the bytes those bits fill, each run of
/// adjacent ones as one lane set.
fn covered_runs(storage: CanonicalStorageId, row: &r2abi::PlatformRegister) -> Vec<LaneSet> {
    let mut runs = Vec::<LaneSet>::new();
    for byte in row.covered_bytes(storage.size) {
        let Ok(byte) = u8::try_from(byte) else {
            continue;
        };
        match runs.last_mut() {
            Some(run) if run.bytes.end == byte => run.bytes.end += 1,
            _ => runs.push(LaneSet {
                storage,
                bytes: byte..byte + 1,
            }),
        }
    }
    runs
}

/// The machine tuple the trusted lift selects a Sleigh profile by.
fn profile(arch: &ArchSpec) -> Result<(&'static str, u32, SourceEndianness), NativeRefusal> {
    let bits = crate::engine_effective_ptr_bits(arch);
    let family = r2abi::family(&arch.name).ok_or(NativeRefusal::Machine(
        "no trusted profile for this machine",
    ))?;
    let endianness = match arch.memory_endianness {
        r2il::Endianness::Little => SourceEndianness::Little,
        r2il::Endianness::Big => SourceEndianness::Big,
        // A capture states one endianness, and a machine that switches or
        // spells its own is not one the trusted profiles cover.
        _ => {
            return Err(NativeRefusal::Machine(
                "this machine's byte order is not one a capture can state",
            ));
        }
    };
    Ok((family, bits, endianness))
}

/// The canonical storage one register name stands for.
///
/// The convention data spells registers in lower case and Sleigh spells them
/// in upper, so the match ignores case rather than either side converting.
pub(crate) fn storage(arch: &ArchSpec, name: &str) -> Result<CanonicalStorageId, NativeRefusal> {
    arch.registers
        .iter()
        .find(|register| register.name.eq_ignore_ascii_case(name))
        .map(|register| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: register.offset,
            size: register.size,
        })
        .ok_or_else(|| NativeRefusal::UnknownRegister(name.to_owned()))
}

/// The premises the engine grants every derivation: a UB-free source, so a stack-protector check
/// passes (doc/adr-frame-model.md, P4.4). A consumer that refuses it is item A's.
pub(crate) fn accepted_premises() -> std::collections::BTreeSet<r2source::Premise> {
    std::collections::BTreeSet::from([
        r2source::Premise::UbFreeSource,
        r2source::Premise::GoRuntime,
    ])
}

/// Those premises, and a closed world where the request read the program's callers (`aa`): what
/// every call the image shows does is what the program does (doc/adr-resolved-bodies.md).
fn premises_reading(callers_read: bool) -> std::collections::BTreeSet<r2source::Premise> {
    let mut premises = accepted_premises();
    if callers_read {
        premises.insert(r2source::Premise::ClosedWorld);
    }
    premises
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;
    /// `lea rdi, [0x1020]; xorps xmm0, xmm0; call on_double; ret`, the stub at 0x1018.
    const HANDS_AFTER_A_DOUBLE: &[u8] = &[
        0x48, 0x8d, 0x3d, 0x19, 0x00, 0x00, 0x00, // 0x1000 lea rdi, [rip + 0x19]
        0x0f, 0x57, 0xc0, // 0x1007 xorps xmm0, xmm0
        0xe8, 0x09, 0x00, 0x00, 0x00, // 0x100a call 0x1018
        0xc3, // 0x100f ret
        0, 0, 0, 0, 0, 0, 0, 0,    // to 0x1018
        0xc3, // 0x1018 the stub
        0, 0, 0, 0, 0, 0, 0,    // to 0x1020
        0xc3, // 0x1020 the handed function
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    struct HandsAfterADouble;

    impl crate::body::Program for HandsAfterADouble {
        fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
            let slice = HANDS_AFTER_A_DOUBLE.get(offset..)?;
            (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
        }

        fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
            let end = BASE + HANDS_AFTER_A_DOUBLE.len() as u64;
            (BASE..end).contains(&vaddr).then_some(crate::body::Region {
                start: BASE,
                end,
                file_end: end,
                execute: true,
                write: false,
            })
        }

        fn is_entry(&self, vaddr: u64) -> bool {
            matches!(vaddr, BASE | 0x1018 | 0x1020)
        }
    }

    impl Program for HandsAfterADouble {
        fn holds_static_data(&self, _vaddr: u64) -> bool {
            false
        }

        fn extents(&self) -> &r2types::ProgramExtents {
            const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
            NONE
        }

        fn name_at(&self, vaddr: u64) -> Option<String> {
            self.import_at(vaddr)
        }

        fn import_at(&self, vaddr: u64) -> Option<String> {
            (vaddr == 0x1018).then(|| "on_double".to_owned())
        }
    }

    /// System V passes `on_double(double, void (*)())`'s callback in RDI, the first integer
    /// register, however many floats come before it.
    #[test]
    fn a_function_handed_after_a_double_is_read_from_the_first_integer_slot() {
        let embedded = crate::machine::Machine::new(
            r2sleigh_lift::embedded_machine("x86-64").expect("embedded machine"),
        );
        let compiler = LanguageProfile::parse(embedded.compiler_spec).expect("parses");
        let convention = convention_model(
            &embedded.arch,
            64,
            (
                r2abi::Kernel::Unknown,
                r2abi::CLibrary::Unknown,
                Default::default(),
            ),
            &compiler,
            r2abi::ConventionId::SysVAmd64.row(),
        )
        .expect("System V");
        let rows = r2abi::LibraryRows::parse(
            r2abi::LibraryId::Portable,
            "on_double=func\nfunc.on_double.args=2\nfunc.on_double.arg.0=double,x\n\
             func.on_double.arg.1=func,callback\nfunc.on_double.ret=void\n",
        );
        let imports = crate::imports::Imports::new(
            rows,
            r2abi::CLibrary::Unknown,
            crate::imports::Linkage::one_c_library(),
        );
        let declarations = r2abi::Declarations::default();
        let target = NativeTarget {
            arch: embedded.tables(),
            disasm: &embedded.disasm,
            cpu: embedded.cpu,
            call: Arc::new(convention.clone()),
            convention: Arc::new(convention),
            compiler: &compiler,
            program: None,
            dwarf: &embedded.dwarf,
            imports: &imports,
            declarations: &declarations,
            data_model: None,
        };
        let walked = walk(&target, &HandsAfterADouble, BASE).expect("walks");
        let handed = handed(&target, &HandsAfterADouble, walked.root.body.clone());
        assert_eq!(handed, [0x1020]);
    }
}
