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

use r2abi::{CompilerSpec, Convention, Prototypes};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SourceCallEffect, SourceConventionSlots,
    SourceDataObject, SourceEndianness, SourceMachineRoles, SourceRoleRegisterNames,
    SourceStackAllocationContract, SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::body::{BodyError, WINDOW};
use r2ssa::{CalleePreservedCarriers, SummaryArgumentReach, TrustedSsaArtifact};

use crate::declared::{Declared, Placement, Restatement};
use crate::{
    CalleeFacts, EngineDecompileResponse, EngineFunctionDecompileRequestInput, EngineFunctionInput,
    EngineFunctionInputQuality, EngineSession,
};

/// The program being analysed, as the engine needs to see it.
///
/// Two questions and no cursor: what byte lives at an address, and what the
/// program calls one. Whoever opened the binary answers them.
pub trait Program: r2ssa::body::Program {
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

    /// Whether the loader writes any byte of this range before the program runs, so the file's bytes there are not what it reads.
    fn loader_writes(&self, range: &std::ops::Range<u64>) -> bool;

    /// Where the program's loaded sections lie, code or data.
    ///
    /// A number nothing proves to move with the program names one of its
    /// objects only here, however low the program is linked.
    fn extents(&self) -> &r2types::ProgramExtents;

    /// The machine the function at this address is written in, where the
    /// program has more than one; `None` keeps the caller's.
    fn target_at(&self, _vaddr: u64) -> Option<NativeTarget<'_>> {
        None
    }
}

/// Everything about the machine that does not change between functions.
pub struct NativeTarget<'a> {
    pub arch: &'a ArchSpec,
    pub disasm: &'a Disassembler,
    /// The processor context the decoder runs in, as the snapshot's machine
    /// tuple spells it. `arm` and `thumb` share an architecture, and this is
    /// the one fact the trusted lift has to tell them apart.
    pub cpu: &'a str,
    /// The convention every function is assumed to use, which is the one the
    /// data declares as the default until something says otherwise.
    pub convention: &'a Convention,
    /// What that convention says a call does here, resolved once by [`call_effect`].
    pub call_effect: Option<&'a SourceCallEffect>,
    pub compiler: &'a CompilerSpec,
    /// What the library functions this program calls take and return. An
    /// import has no body to read an interface off, so without this a call to
    /// one renders with no arguments at all.
    pub prototypes: &'a Prototypes,
    /// What the binary's own debug information declares, by the address each
    /// body begins and each object sits at.
    pub declarations: &'a r2abi::Declarations,
}

/// Why a native decompile could not be attempted.
///
/// These are all refusals to start. Once the request is built, a function the
/// engine cannot prove comes back as a rendered refusal rather than as an
/// error here.
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
    Capture(r2source::SnapshotValidationError),
    Lift(String),
    Prepare(String),
    /// The analysis panicked: a defect, kept to this function and reported
    /// with where it was raised rather than taking the session with it.
    Panicked {
        location: Option<crate::isolation::PanicLocation>,
        message: String,
    },
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
            Self::Capture(error) => write!(f, "{error}"),
            Self::Lift(error) | Self::Prepare(error) => write!(f, "{error}"),
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
pub fn lifted(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<String, NativeRefusal> {
    let body = r2ssa::body::lift_body(entry, target.disasm, program, &BTreeMap::new())
        .map_err(NativeRefusal::Body)?;
    let names = register_spellings(target.arch);
    let mut out = format!("Entry: {entry:#x}\nBlocks: {}\n", body.blocks.len());
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
    Ok(out)
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
    analyse(target, program, entry).map(|prepared| prepared.artifact)
}

/// Walk and prepare one function, without rendering anything from it.
pub fn analysed(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<Prepared, NativeRefusal> {
    analyse(target, program, entry)
}

/// One function's analysis, before anything is rendered from it.
///
/// Every tier is a rendering of this, so it is handed out rather than redone:
/// asking for the prepared function and then for what the renderer decided
/// about its values used to walk, lift and prepare the same body twice.
pub struct Prepared {
    artifact: std::sync::Arc<TrustedSsaArtifact>,
    root: Walked,
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

    /// The walked body's blocks, dispatches followed, and where the walk could not follow.
    pub fn body(&self) -> &r2ssa::body::Body {
        &self.root.body
    }

    pub fn artifact(&self) -> &std::sync::Arc<TrustedSsaArtifact> {
        &self.artifact
    }

    /// What the program calls the function this analysis is of.
    pub fn name(&self) -> &str {
        &self.root.name
    }

    /// The lift of each block of the body this analysis read, dispatches followed.
    pub fn lifted(&self) -> Vec<r2il::R2ILBlock> {
        self.root
            .body
            .blocks
            .iter()
            .map(|block| block.lifted.clone())
            .collect()
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
            Unreadable::NothingProved => "it proved nothing about its boundary",
            Unreadable::Panicked(panicked) => {
                return write!(f, "{:#x}: its analysis {panicked}", self.address);
            }
        };
        write!(f, "{:#x}: {reason}", self.address)
    }
}

/// The structured tier for one function: the tree the C is generated from.
///
/// The same analysis and the same request as `decompile`, rendered one step
/// earlier, so the two can be read against each other.
pub fn structured(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    render(target, program, entry, crate::RenderTier::Structured)
}

pub fn decompile(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    render(target, program, entry, crate::RenderTier::C)
}

/// Whether a body that transfers to these callees and reads these import slots calls anything declared to take a function.
pub(crate) fn hands_a_function(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    callees: impl IntoIterator<Item = u64>,
    loads: &BTreeSet<u64>,
) -> bool {
    let direct = callees
        .into_iter()
        .filter_map(|callee| program.name_at(callee));
    let through_a_slot = loads.iter().filter_map(|slot| program.import_at(*slot));
    direct.chain(through_a_slot).any(|name| {
        let prototype = target.prototypes.get(&name);
        prototype.is_some_and(|prototype| {
            prototype
                .parameters
                .iter()
                .any(r2abi::Parameter::is_function)
        })
    })
}

/// The functions a walked body hands to a parameter a declaration calls a function.
pub(crate) fn handed(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    body: r2ssa::body::Body,
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
    match native.prepare(&walked, &Callees::default()) {
        Ok(artifact) => native.handed_functions(&artifact, &walked),
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
) -> Option<bool> {
    let name = program.import_at(address)?;
    let prototype = target.prototypes.get(&name);
    Some(!prototype.is_some_and(|prototype| prototype.noreturn))
}

/// What the binding plan decided about each value.
pub fn values(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    render(target, program, entry, crate::RenderTier::Values)
}

fn render(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
    tier: crate::RenderTier,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    let control = program.control();
    let prepared = analyse(target, program, entry)?;
    Ok(match sealed(target, entry, &prepared, &control) {
        Ok(sealed) => EngineSession::new().render_sealed(&sealed, tier, &control),
        Err(refused) => *refused,
    })
}

/// The type analysis of one prepared function under this request's control; a refusal is the response a rendering returns.
pub fn sealed(
    target: &NativeTarget<'_>,
    entry: u64,
    prepared: &Prepared,
    control: &crate::EngineExecutionControl,
) -> Result<crate::SealedFunctionAnalysis, Box<EngineDecompileResponse>> {
    EngineSession::new().seal_function_from_input(request(target, entry, prepared, control))
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
        root,
        facts,
        declared,
        ptr_bits,
        unread: _,
        extents,
        tables: _,
    } = prepared;
    let block_count = artifact.source_block_count();
    let signatures = declared_signatures(target, root, extents);
    EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: root.name.clone(),
            function_addr: entry,
            // The artifact owns the lift and the request reads it from there.
            blocks: Vec::new(),
            arch: Some(target.arch.clone()),
            semantic_metadata_enabled: true,
            source_snapshot: None,
        },
        Some(*ptr_bits),
        signatures,
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
    let placement = Placement::new(target, &native.machine);
    let mut signatures = Vec::new();
    for address in targets {
        let Some(name) = native.program.import_at(*address) else {
            continue;
        };
        let Some(declared) = Declared::import(target, &name) else {
            continue;
        };
        // An import has no body here, so nothing it declares about its own
        // frame is about anything this program can see.
        let Some(interface) = placement.restatement(declared, false).interface else {
            continue;
        };
        if let Some(signature) = placement.function_type(declared)
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
) -> Result<Arc<TrustedSsaArtifact>, Unreadable> {
    crate::isolation::isolated(|| prepare_callee(native, target, address, ptr_bits))
        .unwrap_or_else(|panicked| Err(Unreadable::Panicked(panicked)))
}

fn prepare_callee(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
) -> Result<Arc<TrustedSsaArtifact>, Unreadable> {
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
    let walked = native.walk(address).map_err(|_| Unreadable::NotWalked)?;
    // Against what the binary declares about it, exactly as the root is
    // prepared: a callee prepared without its declaration proves only what
    // its instructions show, which for a result register is nothing, and
    // then the call site renders it as returning nothing.
    let declared = native.declaration(address);
    // An import's prototype is a declaration, not a body, so what the callee returns through one is known.
    let targets = walked
        .body
        .calls
        .iter()
        .chain(walked.body.tail_calls.iter())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut imports = Callees::default();
    declare_imports(native, target, &targets, ptr_bits, &mut imports);
    native
        .prepare_restated(&walked, &imports, Vec::new(), declared, &[])
        .map_err(|_| Unreadable::NotPrepared)
}

/// What a callee's own body proves about its parameters, prepared as every caller prepares it.
pub(crate) fn callee_summary(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    address: u64,
) -> Option<r2ssa::PreparedCalleeSummary> {
    let native = Native {
        target,
        program,
        machine: machine(target).ok()?,
        control: program.control().ssa_execution_control(),
    };
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);
    let artifact = prepared_callee(&native, target, address, ptr_bits).ok()?;
    let shared = artifact.shared_artifact();
    r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(address), &shared).ok()
}

fn read_callees(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    root: &Walked,
    entry: u64,
    ptr_bits: u32,
) -> Read {
    // What a call takes and returns is a fact about the callee's body, so the
    // bodies it calls are walked first and the root is prepared against them.
    // A callee that cannot be walked leaves its call unproven rather than
    // failing the root.
    let mut callees = Callees::default();
    // A tail jump reaches another function exactly as a call does; the only
    // difference is that its result is this function's own. One callee reached
    // both ways is still one callee: declaring it twice makes the type
    // analysis reject the whole capture as holding a duplicate address.
    let targets: Vec<u64> = root
        .body
        .calls
        .iter()
        .chain(root.body.tail_calls.iter())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let declared = declare_imports(native, target, &targets, ptr_bits, &mut callees);
    let mut facts = Vec::new();
    // A stub is not a body: walking one recovers an interface with no
    // parameters, which would displace the declaration that has them.
    let bodies: Vec<u64> = targets
        .iter()
        .copied()
        .filter(|address| *address != entry && !callees.interfaces.contains_key(address))
        .collect();
    let mut unread = Vec::new();
    for address in &bodies {
        let artifact = match prepared_callee(native, target, *address, ptr_bits) {
            Ok(artifact) => artifact,
            Err(reason) => {
                unread.push(Unread {
                    address: *address,
                    reason,
                });
                continue;
            }
        };
        // The interface is what the callee's body proves about its boundary,
        // and a callee whose whole preparation cannot be certified still
        // proved that much. Taking it keeps the call rendered as a call.
        if let Some(interface) = artifact
            .shared_artifact()
            .machine_context()
            .function_interface()
        {
            callees.interfaces.insert(*address, interface.clone());
        }
        // What the callee proves is read under the same boundary as its preparation.
        let derived = crate::isolation::isolated(|| CalleeFacts::derive(&artifact, ptr_bits));
        let derived = match derived {
            Ok(Some(derived)) => derived,
            Ok(None) => {
                unread.push(Unread {
                    address: *address,
                    reason: Unreadable::NothingProved,
                });
                continue;
            }
            Err(panicked) => {
                unread.push(Unread {
                    address: *address,
                    reason: Unreadable::Panicked(panicked),
                });
                continue;
            }
        };
        callees.record(*address, &derived);
        facts.push(derived);
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
) -> Result<Prepared, NativeRefusal> {
    let native = Native {
        target,
        program,
        machine: machine(target)?,
        control: program.control().ssa_execution_control(),
    };
    let root = native.walk(entry)?;
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);

    let Read {
        callees,
        facts,
        declared,
        unread,
    } = read_callees(&native, target, &root, entry, ptr_bits);

    // What the binary's own debug information says this function takes is a
    // declaration, exactly as an import's is, so it is placed in the
    // convention's slots the same way and the body is prepared against it.
    // Without this the engine reads every parameter as the width of the
    // register it arrived in, whatever the source said.
    let declared_prototype = Declared::body(target, entry).map(|declared| declared.prototype);
    let declared_root = native.declaration(entry);
    let first = match declared_root.interface.is_some() {
        false => native.prepare(&root, &callees)?,
        true => native.prepare_restated(&root, &callees, Vec::new(), declared_root.clone(), &[])?,
    };
    // A dispatch through a table is where the first walk stopped: it could see
    // the branch and not where it goes. The analysis it has just been through
    // says where the table is and how far it runs, so the table is read and
    // the body walked again through it. The blocks this adds are the switch
    // arms, which nothing has seen until now.
    let tables = native.pointer_tables(&first);
    let (root, first) = match tables.is_empty() {
        true => (root, first),
        false => {
            let root = native.walk_dispatched(
                entry,
                &tables
                    .iter()
                    .map(|table| (table.instruction, table.targets.clone()))
                    .collect(),
            )?;
            // The first walk stopped at the dispatch, so its interface and slots are read again off the whole body.
            let first = native.prepare_restated(
                &root,
                &callees,
                Vec::new(),
                declared_root.clone(),
                &tables,
            )?;
            (root, first)
        }
    };
    // A second capture states what the first proved. Preparation recovers the
    // interface off the instructions and proves which frame slots home which
    // parameter; declaring those turns the spill into the parameter again,
    // which is the whole difference between reading a frame and reading a
    // program. Text the body points at is harvested the same way, because
    // aarch64 forms an address from a page and an offset and the constant the
    // literal lives at appears only once those are folded.
    // The debug information may measure the frame from the frame pointer, and
    // objects are identified by where they sit relative to the pointer the
    // function was entered with. The distance between the two is what the
    // prologue moved, which the first pass proved for every object it placed,
    // so the declaration is restated into those coordinates rather than
    // dropped for being in the other ones.
    let declared_root = crate::declared::rebased(declared_root, &first, declared_prototype);
    let declared_slots = declared_root
        .interface
        .as_ref()
        .map(|interface| interface.stack_slots().to_vec())
        .unwrap_or_default();
    let restated = native.restated(&first, &declared_slots);
    let folded = native.folded_literals(&first, &root);
    let artifact = match restated.is_none() && folded.is_empty() {
        true => first,
        false => {
            // A body that proved no frame slot restates nothing, and the
            // declaration it was prepared against is still the declaration.
            let restatement = Restatement {
                interface: restated.or(declared_root.interface),
                signature: declared_root.signature,
                slot_names: declared_root.slot_names,
            };
            native.prepare_restated(&root, &callees, folded, restatement, &tables)?
        }
    };
    let tables = tables.iter().map(DispatchTable::of).collect();
    Ok(Prepared {
        artifact,
        root,
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
                .unwrap_or_else(|| format!("arg{index}"))
        })
        .collect()
}

/// Where each integer argument arrives under this machine's convention, by index.
pub(crate) fn argument_slots(target: &NativeTarget<'_>) -> Vec<CanonicalStorageId> {
    machine(target)
        .map(|machine| machine.slots.argument_slots().to_vec())
        .unwrap_or_default()
}

/// Where an import's declaration says it takes a pointer.
pub(crate) fn declared_pointers(target: &NativeTarget<'_>, name: &str) -> Vec<CanonicalStorageId> {
    let (Some(declared), Ok(machine)) = (Declared::import(target, name), machine(target)) else {
        return Vec::new();
    };
    Placement::new(target, &machine).pointers(declared)
}

/// The declared interfaces of the functions this body calls.
///
/// A function whose body the program carries is declared by the binary's
/// debug information at the address the call reaches; an import, by the
/// library table under its name. Either reaches the type layer under the
/// name the call renders with.
fn declared_signatures(
    target: &NativeTarget<'_>,
    root: &Walked,
    extents: &r2types::ProgramExtents,
) -> r2types::ParsedExternalContext {
    let mut context = r2types::ParsedExternalContext {
        program_extents: extents.clone(),
        ..r2types::ParsedExternalContext::default()
    };
    let Ok(machine) = machine(target) else {
        return context;
    };
    let placement = Placement::new(target, &machine);
    for callee in &root.callees {
        let declared = Declared::body(target, callee.address).or_else(|| {
            callee
                .import
                .as_deref()
                .and_then(|import| Declared::import(target, import))
        });
        let Some(signature) = declared.and_then(|declared| placement.function_type(declared))
        else {
            continue;
        };
        context
            .known_function_signatures
            .insert(callee.name.clone(), signature);
    }
    context
}

/// One interface again, with stack slots it did not have.
///
/// There is no builder that adds them, so the interface is rebuilt from what
/// it says about itself. The order matters: a return mechanism validates
/// against the carriers, and a carrier refuses to move once a mechanism is
/// bound, so the carriers go on first.
pub(crate) fn restate(
    interface: &r2source::SourceFunctionInterface,
    slots: Vec<r2source::SourceStackSlotSpec>,
    revision: Vec<u8>,
) -> Option<r2source::SourceFunctionInterface> {
    let mut restated = r2source::SourceFunctionInterface::new_exact_with_logical_types(
        revision,
        interface.calling_convention(),
        interface.parameters().to_vec(),
        interface.return_kind(),
        slots,
        interface.parameter_logical_values().to_vec(),
        interface.return_logical_value(),
        interface.type_graph().cloned(),
    )
    .inspect_err(|error| {
        r2il::refusal_evidence!("restate-interface", "the slots do not restate: {error:?}");
    })
    .ok()?
    .with_role_register_names(interface.role_register_names());
    let carried = |what: &str, placed: Result<_, _>| {
        placed
            .inspect_err(|error| {
                r2il::refusal_evidence!(
                    "restate-interface",
                    "the restated slots do not carry the {what}: {error:?}"
                );
            })
            .ok()
    };
    if let Some(storage) = interface.return_address_storage() {
        restated = carried(
            "return address",
            restated.with_return_address_storage(storage),
        )?;
    }
    if let Some(storage) = interface.stack_pointer_storage() {
        restated = carried(
            "stack pointer",
            restated.with_stack_pointer_storage(storage),
        )?;
    }
    if let Some(storage) = interface.frame_pointer_storage() {
        restated = carried(
            "frame pointer",
            restated.with_frame_pointer_storage(storage),
        )?;
    }
    if let Some(mechanism) = interface.return_mechanism() {
        restated = carried(
            "return mechanism",
            restated.with_exact_stacked_return(
                mechanism.stack_offset(),
                mechanism.slot_size_bytes(),
                mechanism.stack_pointer_delta_bytes(),
                mechanism.address_size_bytes(),
            ),
        )?;
    }
    if interface.prototype_from_source_types() {
        restated = restated.with_prototype_from_source_types();
    }
    Some(restated)
}

/// What the bodies a function calls say about their own boundaries.
#[derive(Default)]
struct Callees {
    interfaces: BTreeMap<u64, r2source::SourceFunctionInterface>,
    preserved: CalleePreservedCarriers,
    /// What each callee reaches through each pointer it is handed, which is
    /// what makes the bytes one callee covers one object in the caller.
    reach: BTreeMap<u64, BTreeMap<usize, SummaryArgumentReach>>,
}

impl Callees {
    fn record(&mut self, address: u64, facts: &CalleeFacts) {
        self.interfaces.insert(address, facts.interface().clone());
        self.preserved
            .insert(address, facts.preserved_carriers().clone());
        let reach = facts.argument_touch_reach();
        if !reach.is_empty() {
            self.reach.insert(address, reach);
        }
    }
}

/// What the container states about whether a table's bytes, as the file holds
/// them, are what the dispatch reads when it runs.
///
/// The seam immutability arrives through. A writable region is `Unsealed`:
/// the container has not yet been asked whether anything seals it after load
/// (a RELRO range, a read-only Mach-O segment), and that statement is what
/// turns it into one the program cannot change or refuses it. Until then the
/// table is read as before, the refusal evidence says it was read unsealed,
/// and every table carries this statement -- on `DispatchTable` and so on the
/// listing's `Switch` -- for that check to consume rather than recompute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableBytes {
    /// No write permission: the bytes are the program's for its whole run.
    ReadOnly,
    /// Writable, and nothing the container states seals it after load.
    Unsealed,
    /// The loader writes some of them -- a relocation, an import's slot, or
    /// the zeros it fills past what the file holds -- so the file's bytes are
    /// not what runs.
    LoaderWritten,
}

impl TableBytes {
    /// O(log n) in the loader's writes: one search, and one comparison against the file's extent.
    fn of(
        program: &dyn Program,
        region: &r2ssa::body::Region,
        range: std::ops::Range<u64>,
    ) -> Self {
        let written = range.end > region.file_end || program.loader_writes(&range);
        match (written, region.write) {
            (true, _) => Self::LoaderWritten,
            (false, false) => Self::ReadOnly,
            (false, true) => Self::Unsealed,
        }
    }

    /// Whether the file's bytes of the table at `at` may be read as the
    /// run's, saying why wherever the answer is not a plain yes.
    ///
    /// Unsealed is not a refusal yet: the statement that would seal it is not
    /// asked for until the immutability check lands, so it is said here and
    /// carried on the table.
    fn read_as_run(self, at: u64) -> bool {
        match self {
            Self::LoaderWritten => {
                r2il::refusal_evidence!(
                    "dispatch-table",
                    "{at:#x}: {self:?}: the file's bytes are not what the dispatch reads"
                );
                false
            }
            Self::Unsealed => {
                r2il::refusal_evidence!(
                    "dispatch-table",
                    "{at:#x}: {self:?}: read from memory the program may write, which \
                     nothing the container states seals after load"
                );
                true
            }
            Self::ReadOnly => true,
        }
    }
}

/// One function walked out of the program.
struct Walked {
    name: String,
    body: r2ssa::body::Body,
    /// Each function this one calls, and what it is called.
    callees: Vec<Callee>,
}

/// One function a body calls.
struct Callee {
    address: u64,
    /// What the program calls it.
    name: String,
    /// The import it stands for, where the binary says it is one.
    import: Option<String>,
}

/// One program, one machine, and the walk over it.
/// One dispatch's table, read, and where the dispatch that reads it stands.
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

impl Native<'_> {
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
        let body = r2ssa::body::lift_body(entry, self.target.disasm, self.program, dispatched)
            .map_err(NativeRefusal::Body)?;
        Ok(self.walked(body))
    }

    /// One walked body, with what the program calls it and each function it calls.
    fn walked(&self, body: r2ssa::body::Body) -> Walked {
        let callees = body
            .calls
            .iter()
            .filter_map(|address| {
                Some(Callee {
                    address: *address,
                    name: self.program.name_at(*address)?,
                    import: self.program.import_at(*address),
                })
            })
            .collect();
        Walked {
            name: self
                .program
                .name_at(body.entry)
                .unwrap_or_else(|| r2source::unnamed_function(body.entry)),
            body,
            callees,
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
    fn pointer_tables(&self, artifact: &TrustedSsaArtifact) -> Vec<NativePointerTable> {
        let reads = r2ssa::indirect::dispatch_table_reads(artifact.shared_artifact().as_ref());
        let tables = reads
            .iter()
            .filter_map(|read| self.pointer_table(read))
            .collect::<Vec<_>>();
        r2il::refusal_evidence!(
            "dispatch-table",
            "{} of {} dispatch reads fetched",
            tables.len(),
            reads.len()
        );
        tables
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
        let (Some(span), Ok(count), Ok(stride), Ok(size)) = (
            read.span().and_then(|span| usize::try_from(span).ok()),
            usize::try_from(read.count),
            usize::try_from(read.stride),
            usize::try_from(read.size),
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
        let stated = TableBytes::of(self.program, &region, at..end);
        if !stated.read_as_run(at) {
            return None;
        }
        let bytes = self.program.read(at, span).unwrap_or_default();
        if bytes.len() < span {
            refused(format_args!("{} of {span} bytes are mapped", bytes.len()));
            return None;
        }
        let word = |slot: &[u8]| match self.machine.endianness {
            SourceEndianness::Little => slot.iter().rev().fold(0u64, |v, b| (v << 8) | *b as u64),
            SourceEndianness::Big => slot.iter().fold(0u64, |v, b| (v << 8) | *b as u64),
        };
        // Every entry lies inside `bytes`: the last ends at `(count - 1) * stride + size`, which is `span`.
        let targets = (0..count)
            .map(|k| word(&bytes[k * stride..k * stride + size]))
            .map(|entry| read.transform.target(entry, read.size))
            .collect::<Vec<_>>();
        let distinct = targets.iter().copied().collect::<BTreeSet<_>>();
        if let Some(target) = distinct.iter().find(|target| !self.decodes(**target)) {
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
            table: r2source::SourceCodePointerTable::new(
                at,
                read.size,
                targets.clone(),
                targets
                    .iter()
                    .map(|target| self.program.name_at(*target).map(Into::into))
                    .collect::<Vec<_>>(),
            ),
            targets,
        })
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
    fn folded_literals(
        &self,
        artifact: &TrustedSsaArtifact,
        walked: &Walked,
    ) -> Vec<(u64, String)> {
        let prepared = artifact.shared_artifact();
        let already = self
            .literals(&walked.body)
            .into_iter()
            .map(|(address, _)| address)
            .collect::<BTreeSet<_>>();
        let mut found = BTreeMap::new();
        for value in prepared.value_ids() {
            let Some(address) = prepared.folded_value(value) else {
                continue;
            };
            if address == 0 || already.contains(&address) {
                continue;
            }
            if let Some(text) = text_at(self.program, address) {
                found.insert(address, text);
            }
        }
        found.into_iter().collect()
    }

    /// Capture what was walked and prepare it for the engine.
    fn prepare(
        &self,
        walked: &Walked,
        callees: &Callees,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        self.prepare_with_literals(walked, callees, Vec::new())
    }

    /// The interface the first pass recovered, restated with the frame slots
    /// it proved.
    ///
    /// `None` where the body proves no slot, which is every function that
    /// keeps its arguments in registers.
    fn restated(
        &self,
        artifact: &TrustedSsaArtifact,
        declared: &[r2source::SourceStackSlotSpec],
    ) -> Option<r2source::SourceFunctionInterface> {
        let prepared = artifact.shared_artifact();
        let prepared = prepared.as_ref();
        let interface = prepared.machine_context().function_interface()?;
        let base_storage = prepared.machine_context().stack_pointer_carrier()?;
        let proved = r2ssa::recover_interface::recovered_stack_slots(prepared);
        if proved.is_empty() && declared.is_empty() {
            return None;
        }

        let slots = proved
            .iter()
            .filter_map(|slot| {
                let parameter = match slot.parameter {
                    None => {
                        return Some(r2source::SourceStackSlotSpec::new_local(
                            r2source::StackAddressBase::StackPointer,
                            base_storage,
                            slot.offset,
                            slot.size_bytes,
                        ));
                    }
                    Some(index) => index,
                };
                // A home names the register its parameter arrived in, and the
                // constructor refuses any other.
                let home = interface
                    .parameters()
                    .get(parameter as usize)?
                    .register_storage()?;
                Some(r2source::SourceStackSlotSpec::new_parameter_home(
                    r2source::StackAddressBase::StackPointer,
                    base_storage,
                    slot.offset,
                    slot.size_bytes,
                    parameter,
                    home,
                ))
            })
            .collect::<Vec<_>>();

        // What the declaration states about the frame stays stated, extent and
        // type: the body proves where its own accesses land, and one inside a
        // declared object is a member of it, not an object of its own.
        let slots = crate::declared::restated_slots(declared, slots, interface);
        restate(interface, slots, interface.revision_identity().to_vec())
    }

    /// What the binary's debug information declares about the body at this
    /// address, placed in this machine's carriers with the frame it states.
    fn declaration(&self, address: u64) -> Restatement {
        Declared::body(self.target, address)
            .map(|declared| Placement::new(self.target, &self.machine).restatement(declared, true))
            .unwrap_or_default()
    }

    fn prepare_with_literals(
        &self,
        walked: &Walked,
        callees: &Callees,
        extra_literals: Vec<(u64, String)>,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        self.prepare_restated(walked, callees, extra_literals, Restatement::default(), &[])
    }

    fn prepare_restated(
        &self,
        walked: &Walked,
        callees: &Callees,
        extra_literals: Vec<(u64, String)>,
        restatement: Restatement,
        tables: &[NativePointerTable],
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        let Restatement {
            interface,
            signature,
            slot_names,
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
                    stop.reason == r2ssa::body::UnresolvedReason::IndirectBranch
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
        let function = NativeFunction {
            address: walked.body.entry,
            name: walked.name.clone(),
            blocks,
            calls: call_sites(&walked.body, self.program),
            string_literals: {
                let mut literals = self.literals(&walked.body);
                literals.extend(extra_literals);
                literals.sort_by_key(|(address, _)| *address);
                literals.dedup_by_key(|(address, _)| *address);
                literals
            },
            data_symbols: self.data_symbols(&walked.body),
            code_pointer_tables: tables.iter().map(|table| table.table.clone()).collect(),
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
            loader_role: None,
        };

        let snapshot =
            r2source::native::capture(&self.machine, function).map_err(NativeRefusal::Capture)?;
        let lifted = Disassembler::lift_owned_function(snapshot)
            .map_err(|error| NativeRefusal::Lift(error.to_string()))?;
        let artifact = TrustedSsaArtifact::prepare_with_callee_interfaces(
            lifted,
            &self.control,
            &callees.interfaces,
            &callees.preserved,
            &callees.reach,
        )
        .map_err(|error| NativeRefusal::Prepare(format!("{error:?}")))?;
        Ok(Arc::new(artifact))
    }
}

/// Where each direct call is made and what it reaches.
///
/// The walk collects call targets without saying which instruction made each
/// one, so the instruction is found by looking for the call operation in the
/// block that carries it.
fn call_sites(body: &r2ssa::body::Body, program: &dyn Program) -> Vec<NativeCall> {
    let mut sites = Vec::new();
    for block in &body.blocks {
        for index in 0..block.lifted.ops.len() {
            let Some((target, transfer)) = transfer(&block.lifted, index, body) else {
                continue;
            };
            let Some(instruction) = block
                .lifted
                .op_metadata(index)
                .and_then(|metadata| metadata.instruction_addr)
            else {
                continue;
            };
            sites.push(NativeCall {
                instruction,
                target,
                name: program.name_at(target),
                transfer,
                linkage: match program.import_at(target) {
                    Some(_) => r2source::AdvisoryCalleeLinkage::Imported,
                    None => r2source::AdvisoryCalleeLinkage::Internal,
                },
            });
        }
    }
    sites
}

/// How one operation reaches another function, where it reaches one at all.
///
/// A call comes back and a tail jump does not, and which this is a fact about
/// the body rather than about the callee: the walk decided it when it stopped
/// at the target's entry. A jump through a loaded value names no code address
/// at all, so its target is the slot the jump reads, which is what the
/// relocation on that slot licenses. The slot is read by the same pass that
/// reads it again when the site is correlated, so the two cannot disagree.
fn transfer(
    block: &r2il::R2ILBlock,
    index: usize,
    body: &r2ssa::body::Body,
) -> Option<(u64, r2source::AdvisoryCallTransfer)> {
    match block.ops.get(index)? {
        r2il::R2ILOp::Call { target } => {
            Some((target.offset, r2source::AdvisoryCallTransfer::Call))
        }
        r2il::R2ILOp::Branch { target } if body.tail_calls.contains(&target.offset) => {
            Some((target.offset, r2source::AdvisoryCallTransfer::TailJump))
        }
        r2il::R2ILOp::BranchInd { .. } => Some((
            r2ssa::terminal_indirect_loaded_slot(block, index)?.offset,
            r2source::AdvisoryCallTransfer::TailSlot,
        )),
        _ => None,
    }
}

impl Native<'_> {
    /// The text this body points at.
    ///
    /// A constant the code computes with is not a pointer, and nothing here
    /// claims it is: the address has to hold a run of printable bytes ending
    /// in a terminator for it to be read as text at all.
    fn literals(&self, body: &r2ssa::body::Body) -> Vec<(u64, String)> {
        referenced(body)
            .into_iter()
            .filter_map(|address| Some((address, text_at(self.program, address)?)))
            .collect()
    }

    /// The named program data this body points at.
    fn data_symbols(&self, body: &r2ssa::body::Body) -> Vec<SourceDataObject> {
        referenced(body)
            .into_iter()
            .filter(|address| !body.calls.contains(address))
            .filter_map(|address| {
                let name = self.program.name_at(address)?;
                Some(SourceDataObject::new(address, name, None::<String>))
            })
            .collect()
    }

    /// What one call operation calls, where the program names it.
    ///
    /// A direct call names its target outright. An import is usually reached
    /// indirectly, through a slot the loader fills, and what that slot stands
    /// for is a relocation the program declares -- so the callee is named
    /// there rather than guessed from the address the load lands on.
    fn called_name(
        &self,
        prepared: &r2ssa::SsaArtifact,
        sites: &[NativeCall],
        op: &r2ssa::SSAOp,
    ) -> Option<(u64, String)> {
        match op {
            r2ssa::SSAOp::Call {
                instruction: Some(instruction),
                ..
            } => {
                let site = sites.iter().find(|site| site.instruction == *instruction)?;
                Some((*instruction, self.program.name_at(site.target)?))
            }
            r2ssa::SSAOp::CallInd {
                target,
                instruction: Some(instruction),
            } => {
                let graph = prepared.graph();
                let value = graph.value_id_for_var(target)?;
                let defined = graph.inst(graph.def_inst(value)?)?;
                let r2ssa::InstPayload::Op(r2ssa::SSAOp::Load { addr, .. }) = &defined.payload
                else {
                    return None;
                };
                let slot = prepared.folded_value(graph.value_id_for_var(addr)?)?;
                Some((*instruction, self.program.import_at(slot)?))
            }
            _ => None,
        }
    }

    /// Addresses this body hands to a parameter a declaration calls a function.
    ///
    /// `entry0` never calls `main`. It puts `main` in an argument register and
    /// calls `__libc_start_main`, whose prototype spells that parameter
    /// `func`, so the address is a function on the declaration's authority.
    /// Nothing here guesses: a constant is believed only where a declared type
    /// says that slot holds a function, and the caller checks it decodes in
    /// the instruction set the pointer names.
    fn handed_functions(&self, artifact: &TrustedSsaArtifact, walked: &Walked) -> Vec<u64> {
        let prepared = artifact.shared_artifact();
        let sites = call_sites(&walked.body, self.program);
        let mut found = Vec::new();
        for block in prepared.function().blocks() {
            for (op_index, op) in block.ops.iter().enumerate() {
                let Some((instruction, callee)) = self.called_name(prepared.as_ref(), &sites, op)
                else {
                    continue;
                };
                let Some(prototype) = self.target.prototypes.get(&callee) else {
                    continue;
                };
                for (index, parameter) in prototype.parameters.iter().enumerate() {
                    if !parameter.is_function() {
                        continue;
                    }
                    let Some(storage) = self.machine.slots.argument_slots().get(index) else {
                        continue;
                    };
                    let Some(address) =
                        r2ssa::value_reaching(prepared.as_ref(), block.addr, op_index, *storage)
                            .and_then(|value| prepared.folded_value(value))
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

/// The text a section of static data holds at an address; the one reader a rendering and a listing share.
pub(crate) fn text_at(program: &dyn Program, address: u64) -> Option<String> {
    if !program.holds_static_data(address) {
        return None;
    }
    let bytes = program.read(address, crate::names::LITERAL_LIMIT)?;
    crate::names::text_in(&bytes).map(str::to_owned)
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
    let Some(mut fetch) = program.read(at, WINDOW) else {
        return false;
    };
    let available = fetch.len();
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
fn referenced(body: &r2ssa::body::Body) -> BTreeSet<u64> {
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

/// State the machine from the convention data and the compiler specification.
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
        r2abi::StackAllocation::Lower => SourceStackGrowth::LowerAddresses,
        r2abi::StackAllocation::Higher => SourceStackGrowth::HigherAddresses,
    };
    let redzone = u32::try_from(target.convention.redzone_bytes).unwrap_or(0);
    let roles = SourceMachineRoles::new(Some(return_address), Some(stack_pointer))
        .and_then(|roles| {
            roles.with_stack_allocation_contract(
                SourceStackAllocationContract::with_implicit_active_sp_bytes(growth, redzone),
            )
        })
        .map_err(|_| NativeRefusal::Machine("the carriers are not register storages"))?
        // The names, not only the storages: the trusted lift restates every
        // carrier in its own architecture's numbering, and it looks the
        // carriers up by name to do it.
        .with_role_register_names(SourceRoleRegisterNames::new(
            Some(return_address_name),
            Some(stack_pointer_name),
            None,
        ));

    let mut argument_slots = Vec::with_capacity(target.convention.args.len());
    for slot in &target.convention.args {
        argument_slots.push(storage(target.arch, slot.name())?);
    }
    let result_slot = match target.convention.return_register() {
        Some(slot) => Some(storage(target.arch, slot.name())?),
        None => None,
    };
    // Where an argument past the registers goes is the compiler specification's
    // own statement: its stack parameter entry carries the first offset and the
    // step between entries.
    let stack_arguments = target
        .compiler
        .stack_arguments
        .and_then(|(offset, align)| r2source::SourceStackArgumentPlacement::new(offset, align));
    let slots = SourceConventionSlots::new(&target.convention.name, argument_slots, result_slot)
        .map_err(|_| NativeRefusal::Machine("the convention names one register twice"))?
        .with_stack_arguments(stack_arguments);

    Ok(NativeMachine {
        arch_id: family.to_owned(),
        cpu_id: target.cpu.to_owned(),
        bits,
        endianness,
        roles,
        slots,
        // Asked in the first pass, before an interface exists; without it a caller loses its frame facts.
        call_effect: target.call_effect.cloned(),
    })
}

/// What a convention says a call does here; a name the arch lacks costs precision, never soundness.
pub fn call_effect(arch: &ArchSpec, convention: &Convention) -> Option<SourceCallEffect> {
    if convention.clobbered.is_empty() && convention.preserved.is_empty() {
        return None;
    }
    // One sorted index, so each name is placed in `O(log R)`.
    let mut named = BTreeMap::<String, Option<CanonicalStorageId>>::new();
    for register in arch.registers.iter().filter(|register| {
        register.size != 0
            && register
                .offset
                .checked_add(u64::from(register.size))
                .is_some()
    }) {
        let storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: register.offset,
            size: register.size,
        };
        named
            .entry(register.name.trim().to_ascii_lowercase())
            .and_modify(|placed| *placed = None)
            .or_insert(Some(storage));
    }
    let place = |names: &[String]| {
        names
            .iter()
            .filter_map(|name| {
                let placed = named.get(&name.to_ascii_lowercase()).copied().flatten();
                if placed.is_none() {
                    r2il::refusal_evidence!(
                        "call-effect",
                        "{}: {} names no single register of {}",
                        convention.name,
                        name,
                        arch.name
                    );
                }
                placed
            })
            .collect::<Vec<_>>()
    };
    SourceCallEffect::new(place(&convention.clobbered), place(&convention.preserved))
        .inspect_err(|error| {
            r2il::refusal_evidence!("call-effect", "{}: {error:?}", convention.name);
        })
        .ok()
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
