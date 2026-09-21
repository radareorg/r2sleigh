//! Decompiling a function with no radare2 anywhere.
//!
//! This is the whole native route in one place: walk the body out of the
//! program's bytes, state the machine from the convention data and the
//! compiler specification, mint a capture, and hand it to the same trusted
//! lift and the same request the plugin uses. Nothing downstream of the
//! capture is new, and nothing here formats anything.
//!
//! The callees a function calls directly are walked too, one level deep, and
//! their bodies are what say what each call takes and returns. Deeper than one
//! level is what an interprocedural fixpoint is for, and this is not one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2abi::{CompilerSpec, Convention, Prototypes};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SourceConventionSlots, SourceDataObject,
    SourceEndianness, SourceMachineRoles, SourceRoleRegisterNames, SourceStackAllocationContract,
    SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::body::{BodyError, WINDOW, lift_body};
use r2ssa::{CalleePreservedCarriers, SummaryArgumentReach, TrustedSsaArtifact};

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

    /// Whether static data can live here: a section the program declares that
    /// is not code.
    ///
    /// What makes a constant the address of a string is where it points, and
    /// "the bytes there read as text" is far too weak a test -- almost any
    /// pair of bytes does. A structure offset of eighty was rendered as the
    /// string at address eighty, which is two bytes of the ELF header and in
    /// no section at all.
    fn holds_static_data(&self, vaddr: u64) -> bool;
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
    pub compiler: &'a CompilerSpec,
    /// What the library functions this program calls take and return. An
    /// import has no body to read an interface off, so without this a call to
    /// one renders with no arguments at all.
    pub prototypes: &'a Prototypes,
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

/// One function's analysis, before anything is rendered from it.
struct Prepared {
    artifact: std::sync::Arc<TrustedSsaArtifact>,
    root: Walked,
    facts: Vec<crate::CalleeFacts>,
    declared: Vec<r2types::SourceOwnedCalleeSignature>,
    ptr_bits: u32,
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

/// Where one body transfers, without preparing or rendering it.
///
/// Discovery asks this of every address it believes, and it asks only for the
/// transfers -- walking is the cheap half and a body that refuses to prepare
/// still says who it calls.
pub fn transfers(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Option<crate::discovery::Transfers> {
    let native = Native {
        target,
        program,
        machine: machine(target).ok()?,
        control: crate::EngineExecutionControl::default().ssa_execution_control(),
    };
    let walked = native.walk(entry).ok()?;
    let mut transfers = crate::discovery::Transfers::from(&walked.body);
    // Preparing a body costs far more than walking one, so it is done only
    // where the typed rule could fire at all: this function has to call
    // something whose declaration hands it a function. On an ordinary binary
    // that is `entry0` and whoever registers a handler, and nothing else.
    if native.hands_a_function(&walked) {
        match native.prepare(&walked, &Callees::default()) {
            Ok(artifact) => transfers.handed = native.handed_functions(&artifact, &walked),
            Err(error) => r2il::refusal_evidence!(
                "handed-function",
                "{entry:#x}: preparing to read its arguments failed: {error:?}"
            ),
        }
    }
    Some(transfers)
}

/// Every reference one function makes, from its own lift.
///
/// The sibling of `transfers`: where that says which addresses a body treats as
/// code, this says every address it names at all, so a reverse index can be
/// built by asking each discovered function once.
pub fn data_refs(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Vec<r2ssa::DataRefFact> {
    let Ok(machine) = machine(target) else {
        return Vec::new();
    };
    let native = Native {
        target,
        program,
        machine,
        control: crate::EngineExecutionControl::default().ssa_execution_control(),
    };
    let Ok(walked) = native.walk(entry) else {
        return Vec::new();
    };
    let blocks = walked
        .body
        .blocks
        .iter()
        .map(|block| block.lifted.clone())
        .collect::<Vec<_>>();
    r2ssa::data_refs_from_blocks(&blocks, Some(target.arch)).unwrap_or_default()
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
    let Prepared {
        artifact,
        root,
        facts,
        declared,
        ptr_bits,
    } = analyse(target, program, entry)?;
    let block_count = artifact.source_block_count();
    let signatures = declared_signatures(target, &root, ptr_bits);
    let input = EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: root.name,
            function_addr: entry,
            // The artifact owns the lift and the request reads it from there.
            blocks: Vec::new(),
            arch: Some(target.arch.clone()),
            semantic_metadata_enabled: true,
            source_snapshot: None,
        },
        Some(ptr_bits),
        signatures,
    )
    .with_input_quality(EngineFunctionInputQuality::complete(block_count))
    .with_trusted_ssa(artifact)
    .with_callee_facts(facts)
    .with_declared_signatures(declared)
    .rendering(tier);

    Ok(EngineSession::new().decompile_function_from_input(input))
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
        control: crate::EngineExecutionControl::default().ssa_execution_control(),
    };
    let root = native.walk(entry)?;
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);

    // What a call takes and returns is a fact about the callee's body, so the
    // bodies it calls are walked first and the root is prepared against them.
    // A callee that cannot be walked leaves its call unproven rather than
    // failing the root.
    let mut callees = Callees::default();
    // An import has no body here to read an interface off, so its declared
    // prototype is placed in the convention's own slots and stands in for one,
    // and the same declaration states the C signature the call renders with.
    let mut declared = Vec::new();
    // A tail jump reaches another function exactly as a call does; the only
    // difference is that its result is this function's own.
    let targets: Vec<u64> = root
        .body
        .calls
        .iter()
        .chain(root.body.tail_calls.iter())
        .copied()
        .collect();
    for address in &targets {
        let Some(name) = native.program.import_at(*address) else {
            continue;
        };
        let Some(prototype) = target.prototypes.get(&name) else {
            continue;
        };
        // An import has no body here, so nothing it declares about its own
        // frame is about anything this program can see.
        let Some(interface) = declared_interface(
            prototype,
            target,
            &native.machine,
            ptr_bits,
            &DeclaredFrame::default(),
        ) else {
            continue;
        };
        if let Some(signature) = function_type(prototype, ptr_bits)
            && let Some(declaration) = r2types::SourceOwnedCalleeSignature::declared(
                *address,
                interface.clone(),
                signature,
                ptr_bits,
            )
        {
            declared.push(declaration);
        }
        callees.interfaces.insert(*address, interface);
    }
    let mut facts = Vec::new();
    // A stub is not a body: walking one recovers an interface with no
    // parameters, which would displace the declaration that has them.
    let bodies: Vec<u64> = targets
        .iter()
        .copied()
        .filter(|address| *address != entry && !callees.interfaces.contains_key(address))
        .collect();
    for address in &bodies {
        let Ok(walked) = native.walk(*address) else {
            continue;
        };
        // Against what the binary declares about it, exactly as the root is
        // prepared: a callee prepared without its declaration proves only what
        // its instructions show, which for a result register is nothing, and
        // then the call site renders it as returning nothing.
        let declared = declaration_for(&native, target, *address, ptr_bits);
        let Ok(artifact) =
            native.prepare_restated(&walked, &Callees::default(), Vec::new(), declared, &[])
        else {
            continue;
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
        let Some(derived) = CalleeFacts::derive(&artifact, ptr_bits) else {
            continue;
        };
        callees.record(*address, &derived);
        facts.push(derived);
    }

    // What the binary's own debug information says this function takes is a
    // declaration, exactly as an import's is, so it is placed in the
    // convention's slots the same way and the body is prepared against it.
    // Without this the engine reads every parameter as the width of the
    // register it arrived in, whatever the source said.
    let declared_prototype = native
        .program
        .name_at(entry)
        .and_then(|name| target.prototypes.get(&name).cloned());
    let declared_root = declaration_for(&native, target, entry, ptr_bits);
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
    let root = match tables.is_empty() {
        true => root,
        false => native.walk_dispatched(
            entry,
            &tables
                .iter()
                .map(|table| (table.instruction, table.targets.clone()))
                .collect(),
        )?,
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
    let declared_root = rebased(declared_root, &first, &declared_prototype);
    let declared_slots = declared_root
        .interface
        .as_ref()
        .map(|interface| interface.stack_slots().to_vec())
        .unwrap_or_default();
    let restated = native.restated(&first, &declared_slots);
    let folded = native.folded_literals(&first, &root);
    let artifact = match restated.is_none() && folded.is_empty() && tables.is_empty() {
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
    Ok(Prepared {
        artifact,
        root,
        facts,
        declared,
        ptr_bits,
    })
}

/// What a capture states about the boundary beyond what the bytes say.
///
/// Both halves describe the same declaration -- where each parameter arrives
/// and what it is called -- so they travel together and a capture that has one
/// without the other would render a signature its body was not prepared for.
#[derive(Debug, Clone, Default)]
struct Restatement {
    interface: Option<r2source::SourceFunctionInterface>,
    signature: Option<r2source::SourceSignaturePresentation>,
    slot_names: Vec<r2source::SourceStackSlotName>,
}

/// How a declaration spells a function, for rendering rather than for reading.
///
/// The interface carries the widths; without this the renderer has only those,
/// so a `size_t` arrives as a 64-bit register and is spelled as one.
fn declared_signature(prototype: &r2abi::Prototype) -> r2source::SourceSignaturePresentation {
    let parameters = prototype.parameters.iter().map(|parameter| {
        r2source::SourceSignatureParameter::new(
            parameter.name.clone(),
            Some(parameter.spelling.as_written().to_owned()),
        )
    });
    let ellipsis = prototype
        .variadic
        .then(|| r2source::SourceSignatureParameter::new(Some("..."), None::<String>));
    r2source::SourceSignaturePresentation::new(
        Some(prototype.returns.as_written().to_owned()),
        None::<String>,
        false,
        parameters.chain(ellipsis),
    )
}

/// One declaration, with anything it measured from the frame pointer measured
/// from the entry stack pointer instead.
///
/// Unchanged where the declaration used no frame pointer, and unchanged where
/// the body placed no object against one -- there is then nothing to restate
/// it by, and a guessed distance would put every local at the wrong address.
fn rebased(
    declared: Restatement,
    artifact: &TrustedSsaArtifact,
    prototype: &Option<r2abi::Prototype>,
) -> Restatement {
    let frame_based = |base| base == r2source::StackAddressBase::FramePointer;
    if !declared
        .slot_names
        .iter()
        .any(|name| frame_based(name.base()))
    {
        return declared;
    }
    let Some(from_entry) = prototype
        .as_ref()
        .and_then(|prototype| frame_pointer_from_entry(artifact, prototype))
    else {
        r2il::refusal_evidence!(
            "declared-stack-slot",
            "nothing states one slot in both coordinate systems, so the \
             declaration's frame-relative slots cannot be restated"
        );
        return declared;
    };
    let interface = declared.interface.and_then(|interface| {
        // A slot measured from the entry pointer names the stack pointer as
        // its base, whatever register the declaration measured it from.
        let stack_pointer = interface.stack_pointer_storage()?;
        let slots = interface
            .stack_slots()
            .iter()
            .map(|slot| match frame_based(slot.base()) {
                false => *slot,
                true => {
                    let rebased = r2source::SourceStackSlotSpec::new_local(
                        r2source::StackAddressBase::StackPointer,
                        stack_pointer,
                        slot.offset().saturating_add(from_entry),
                        slot.size_bytes(),
                    );
                    match slot.logical_type() {
                        None => rebased,
                        Some(id) => rebased.with_logical_type(id),
                    }
                }
            })
            .collect::<Vec<_>>();
        let revision = interface.revision_identity().to_vec();
        restate(&interface, slots, revision)
    });
    Restatement {
        interface,
        signature: declared.signature,
        slot_names: declared
            .slot_names
            .into_iter()
            .map(|name| match frame_based(name.base()) {
                false => name,
                true => r2source::SourceStackSlotName::new(
                    r2source::StackAddressBase::StackPointer,
                    name.offset().saturating_add(from_entry),
                    name.name(),
                )
                .with_type_spelling(name.type_spelling()),
            })
            .collect(),
    }
}

/// How far the frame pointer sits from the pointer the function was entered
/// with.
///
/// A parameter the prologue spills is the one place the same slot is stated
/// twice: the declaration says where it sits in the frame, and the body proves
/// where it sits relative to the pointer the function was entered with. The
/// difference is the distance, and every such parameter has to agree on it --
/// a frame pointer that moved during the body is not one distance.
fn frame_pointer_from_entry(
    artifact: &TrustedSsaArtifact,
    prototype: &r2abi::Prototype,
) -> Option<i64> {
    let prepared = artifact.shared_artifact();
    let mut proved: Option<i64> = None;
    for slot in r2ssa::recover_interface::recovered_stack_slots(prepared.as_ref()) {
        let Some(declared) = slot
            .parameter
            .and_then(|index| prototype.parameters.get(index as usize))
            .and_then(|parameter| parameter.frame_offset)
        else {
            continue;
        };
        let distance = slot.offset.checked_sub(declared)?;
        match proved {
            None => proved = Some(distance),
            Some(proved) if proved == distance => {}
            Some(_) => return None,
        }
    }
    proved
}

/// The frame the declaration states, in this machine's coordinates.
///
/// A slot and its name are built together because the snapshot requires every
/// name to land on a slot the interface carries: a name for a place the
/// function does not have would be rendered against whatever the engine
/// happened to recover there.
#[derive(Default)]
struct DeclaredFrame {
    names: Vec<r2source::SourceStackSlotName>,
    slots: Vec<r2source::SourceStackSlotSpec>,
    /// The register the declaration says the frame is measured from, where it
    /// names one. A slot measured from it is a false statement about the
    /// machine unless the interface says which register that is.
    frame_pointer: Option<CanonicalStorageId>,
}

/// What the declaration calls each frame slot, in this machine's coordinates.
///
/// The debug information measures a frame offset from an origin it names, and
/// the engine measures one from the stack pointer this function was entered
/// with or from the frame pointer. Both origins are exact, so the distance
/// between them is derived rather than assumed: the canonical frame address is
/// the caller's stack pointer before the call, which is this function's entry
/// pointer plus whatever the call itself pushed.
fn declared_frame(
    prototype: &r2abi::Prototype,
    target: &NativeTarget<'_>,
    machine: &NativeMachine,
    ptr_bits: u32,
) -> DeclaredFrame {
    let (Some(stated), Some(stack_pointer)) =
        (prototype.frame_base, machine.roles.stack_pointer_storage())
    else {
        return DeclaredFrame::default();
    };
    let mut frame = DeclaredFrame::default();
    let (base, base_storage, from_entry) = match stated {
        r2abi::FrameBase::CallFrameCfa => {
            // The canonical frame address is the caller's stack pointer before
            // the call, so it is the entry pointer plus whatever the call left
            // on the stack. The specification states that slot, and a machine
            // that leaves the return address in a register states none.
            let pushed = target
                .compiler
                .return_address_slot
                .map_or(0, |(_, size)| i64::from(size));
            (
                r2source::StackAddressBase::StackPointer,
                stack_pointer,
                pushed,
            )
        }
        r2abi::FrameBase::Register(number) => {
            match r2abi::dwarf_frame_register(target.arch.name.as_str(), ptr_bits, number) {
                Some((r2abi::FrameRole::FramePointer, name)) => {
                    let Ok(storage) = storage(target.arch, name) else {
                        return DeclaredFrame::default();
                    };
                    frame.frame_pointer = Some(storage);
                    (r2source::StackAddressBase::FramePointer, storage, 0)
                }
                // A base that is the stack pointer inside the body is a
                // distance from a value the body moves, which names no origin
                // the engine can place a slot against.
                _ => return DeclaredFrame::default(),
            }
        }
    };
    // Two locals declared over one place are two names for it: the compiler
    // gave them the same storage because their scopes do not overlap, and
    // `mbsstr_trimmed_wordbounded` has three at one offset. Nothing here knows
    // which name the storage holds at a given point, so neither is stated --
    // and stating both made the whole declaration unstatable, which cost the
    // function its parameter types as well as its locals.
    let places = prototype
        .locals
        .iter()
        .filter_map(|local| Some((local.frame_offset, local.size_bytes?)))
        .collect::<Vec<_>>();
    let overlaps = |local: &r2abi::Local, size: u32| {
        places
            .iter()
            .filter(|(offset, other)| {
                local.frame_offset < offset.saturating_add(i64::from(*other))
                    && *offset < local.frame_offset.saturating_add(i64::from(size))
            })
            .count()
            > 1
    };
    for local in &prototype.locals {
        // A slot with no stated extent is not a slot, and a name for it would
        // have nothing to attach to.
        let Some(size_bytes) = local.size_bytes else {
            continue;
        };
        if overlaps(local, size_bytes) {
            r2il::refusal_evidence!(
                "declared-stack-slot",
                "{}: `{}` shares its place with another declaration",
                prototype.name,
                local.name
            );
            continue;
        }
        let offset = local.frame_offset.saturating_add(from_entry);
        frame.names.push(
            r2source::SourceStackSlotName::new(base, offset, local.name.clone())
                .with_type_spelling(
                    local
                        .spelling
                        .as_ref()
                        .map(|spelled| spelled.as_written().to_owned()),
                ),
        );
        frame.slots.push(r2source::SourceStackSlotSpec::new_local(
            base,
            base_storage,
            offset,
            size_bytes,
        ));
    }
    frame
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

/// What the binary declares about the function at this address, placed in this
/// machine's carriers.
fn declaration_for(
    native: &Native<'_>,
    target: &NativeTarget<'_>,
    address: u64,
    ptr_bits: u32,
) -> Restatement {
    let Some(prototype) = native
        .program
        .name_at(address)
        .and_then(|name| target.prototypes.get(&name).cloned())
    else {
        return Restatement::default();
    };
    // The spelling and the interface are one declaration: a signature whose
    // arity the convention could not place would render a parameter list the
    // body was never prepared against.
    let frame = declared_frame(&prototype, target, &native.machine, ptr_bits);
    let Some(interface) = declared_interface(&prototype, target, &native.machine, ptr_bits, &frame)
    else {
        return Restatement::default();
    };
    Restatement {
        interface: Some(interface),
        signature: Some(declared_signature(&prototype)),
        slot_names: frame.names,
    }
}

/// The declared interfaces of the library functions this body calls.
///
/// Keyed by name, because that is what an import is: the body is elsewhere and
/// only the name reaches the program.
fn declared_signatures(
    target: &NativeTarget<'_>,
    root: &Walked,
    ptr_bits: u32,
) -> r2types::ParsedExternalContext {
    let mut context = r2types::ParsedExternalContext::default();
    for name in &root.callee_names {
        let Some(prototype) = target.prototypes.get(name) else {
            continue;
        };
        let Some(signature) = function_type(prototype, ptr_bits) else {
            continue;
        };
        context
            .known_function_signatures
            .insert(name.clone(), signature);
    }
    context
}

/// A declared prototype, placed in the convention's slots and typed.
///
/// The prototype says how many arguments there are and what they are; the
/// convention says where they arrive. Neither alone describes the call, and
/// nothing here proves anything about the callee's body, which is why this is
/// only reached for a function whose body the program does not carry.
fn declared_interface(
    prototype: &r2abi::Prototype,
    target: &NativeTarget<'_>,
    machine: &NativeMachine,
    ptr_bits: u32,
    frame: &DeclaredFrame,
) -> Option<r2source::SourceFunctionInterface> {
    let placed = placed_parameters(prototype, target, machine, ptr_bits)?;
    let parameters = placed
        .iter()
        .enumerate()
        .map(|(index, storage)| r2source::SourceAbiParameterSpec::new(index as u32, *storage))
        .collect::<Vec<_>>();
    // A result arrives where its own class arrives: a machine with separate
    // floating-point registers returns a `double` in one of those, and calling
    // it the integer result register would have the renderer read the bits of
    // whatever the integer register happened to hold.
    let result = match float_spelling(prototype.returns.as_type(), ptr_bits) {
        true => target
            .convention
            .float_return
            .as_ref()
            .and_then(|slot| storage(target.arch, slot.name()).ok()),
        false => machine.slots.result_slot(),
    };
    let returns = match (prototype.returns.as_type(), result) {
        ("void" | "", _) | (_, None) => r2source::SourceFunctionReturn::Void,
        (_, Some(storage)) => r2source::SourceFunctionReturn::Register { storage },
    };

    // The declared types, as the graph the interface carries. A spelling this
    // build cannot place leaves the prototype untyped rather than half-typed.
    let mut graph = DeclaredTypes::default();
    // A slot's own declared type joins the same graph, so a local declared
    // `double` is rendered as one rather than as the bits its carrier holds.
    // A spelling with no place in the graph leaves its slot untyped, which the
    // interface allows: the slot is still a slot of that size.
    let slots_declared = frame
        .names
        .iter()
        .zip(&frame.slots)
        .map(|(name, slot)| {
            match name
                .type_spelling()
                .and_then(|spelling| graph.type_id(spelling, ptr_bits))
            {
                None => *slot,
                Some(id) => slot.with_logical_type(id),
            }
        })
        .collect::<Vec<_>>();
    let parameter_values = prototype
        .parameters
        .iter()
        .zip(&placed)
        .map(|(parameter, storage)| {
            graph.value(parameter.spelling.as_type(), ptr_bits, storage.size)
        })
        .collect::<Vec<_>>();
    let return_value = match (returns, result) {
        (r2source::SourceFunctionReturn::Void, _) | (_, None) => None,
        (_, Some(storage)) => graph.value(prototype.returns.as_type(), ptr_bits, storage.size),
    };
    let typed = parameter_values.iter().all(Option::is_some)
        && matches!(returns, r2source::SourceFunctionReturn::Void) == return_value.is_none();
    let type_graph = typed
        .then(|| r2source::SourceTypeGraph::new(graph.types.clone(), []).ok())
        .flatten();

    let revision = format!("declared:{}", prototype.name);
    let interface = match &type_graph {
        Some(_) => r2source::SourceFunctionInterface::new_exact_with_logical_types(
            revision.into_bytes(),
            machine.slots.calling_convention(),
            parameters,
            returns,
            slots_declared.clone(),
            parameter_values,
            return_value,
            type_graph,
        ),
        None => r2source::SourceFunctionInterface::new_exact(
            revision.into_bytes(),
            machine.slots.calling_convention(),
            parameters,
            returns,
            // With no graph to name them in, a slot carries no type.
            frame.slots.clone(),
        ),
    };

    let interface = match interface {
        Ok(interface) => interface,
        Err(error) => {
            r2il::refusal_evidence!(
                "declared-interface",
                "{} does not state an interface: {error:?}",
                prototype.name
            );
            return None;
        }
    };
    let roles = machine.roles;
    let Some(return_address) = roles.return_address_storage() else {
        r2il::refusal_evidence!(
            "declared-interface",
            "{}: this machine names no return address carrier",
            prototype.name
        );
        return None;
    };
    let Some(stack_pointer) = roles.stack_pointer_storage() else {
        r2il::refusal_evidence!(
            "declared-interface",
            "{}: this machine names no stack pointer carrier",
            prototype.name
        );
        return None;
    };
    let placed = interface
        .with_return_address_storage(return_address)
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .and_then(|interface| match frame.frame_pointer {
            None => Ok(interface),
            Some(storage) => interface.with_frame_pointer_storage(storage),
        });
    match placed {
        // The types are radare2's declarations, which is exactly what this flag
        // says: the prototype was read rather than recovered.
        Ok(interface) => Some(interface.with_prototype_from_source_types()),
        Err(error) => {
            r2il::refusal_evidence!(
                "declared-interface",
                "{} does not fit this machine's carriers: {error:?}",
                prototype.name
            );
            None
        }
    }
}

/// One interface again, with stack slots it did not have.
///
/// There is no builder that adds them, so the interface is rebuilt from what
/// it says about itself. The order matters: a return mechanism validates
/// against the carriers, and a carrier refuses to move once a mechanism is
/// bound, so the carriers go on first.
fn restate(
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
    .with_role_register_names(interface.role_register_names())
    .with_preserved_call_carriers(
        interface.stack_pointer_preserved_across_calls(),
        interface.frame_pointer_preserved_across_calls(),
    );
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

/// The types one declared prototype needs, interned as it is read.
#[derive(Default)]
struct DeclaredTypes {
    types: Vec<r2source::SourceType>,
}

impl DeclaredTypes {
    /// The graph node one C spelling stands for.
    fn type_id(&mut self, spelling: &str, ptr_bits: u32) -> Option<u32> {
        let parsed = r2types::parse_c_type_like(spelling, ptr_bits)?;
        self.intern(&parsed, ptr_bits)
    }

    /// The logical value one C spelling stands for, in the carrier it arrives
    /// in.
    ///
    /// A declared type narrower than its carrier occupies the carrier's low
    /// bits and says so, which is what `int` in a 64-bit register is. Calling
    /// that the whole carrier is what made every prototype with an `int` in it
    /// refuse, and with it every `main`.
    fn value(
        &mut self,
        spelling: &str,
        ptr_bits: u32,
        carrier_size_bytes: u32,
    ) -> Option<r2source::SourceLogicalValue> {
        let parsed = r2types::parse_c_type_like(spelling, ptr_bits)?;
        let id = self.intern(&parsed, ptr_bits)?;
        let bits = self.types[id as usize].size_bits();
        let kind = match bits == u64::from(carrier_size_bytes) * 8 {
            true => r2source::SourceCarrierKind::Full,
            false => r2source::SourceCarrierKind::LowBits,
        };
        Some(r2source::SourceLogicalValue::new(
            id,
            r2source::SourceCarrierProjection::new(kind, 0, bits),
        ))
    }

    fn intern(&mut self, parsed: &r2types::CTypeLike, ptr_bits: u32) -> Option<u32> {
        use r2source::SourceTypeKind as Kind;
        use r2types::{CTypeLike, Signedness};

        let (kind, bits) = match parsed {
            CTypeLike::Void => (Kind::Void, 0),
            CTypeLike::Bool => (Kind::UnsignedInteger, 8),
            CTypeLike::Int { bits, signedness } => match signedness {
                Signedness::Signed => (Kind::SignedInteger, *bits),
                _ => (Kind::UnsignedInteger, *bits),
            },
            CTypeLike::Float(bits) => (Kind::Float, *bits),
            CTypeLike::Pointer(target) => {
                let target_type_id = self.intern(target, ptr_bits)?;
                (Kind::Pointer { target_type_id }, ptr_bits)
            }
            // A name for a type is that type. The graph carries no names, and
            // the spelling that keeps `size_t` readable travels beside it, so
            // interning the target is the whole of what this has to do --
            // without which one `size_t` in a prototype left the function with
            // no exact type and no source name at all.
            // A qualifier changes no layout and no register class, so the
            // graph node is the type it qualifies. Without this a single
            // `const char *` parameter left the whole prototype untyped, which
            // is most of the library functions there are.
            CTypeLike::Typedef { ty, .. } | CTypeLike::Const(ty) => {
                return self.intern(ty, ptr_bits);
            }
            // An aggregate needs a layout this declaration does not carry.
            _ => return None,
        };
        // One node per distinct type. Interning the same spelling twice used
        // to make two nodes, and the graph must have nothing in it that its
        // roots cannot reach -- so a node whose only reference was a slot the
        // body later proved for itself left the whole interface unstatable.
        let size_bits = u64::from(bits);
        // An object the graph does not describe has no extent and no
        // alignment, and the graph says so: giving `void` a byte's alignment
        // made every prototype through a `void *` unstatable, which is most of
        // the allocating ones.
        let align_bits = match kind {
            Kind::Void | Kind::Code => 0,
            _ => u64::from(bits.max(8)),
        };
        if let Some(found) = self.types.iter().find(|type_| {
            type_.kind() == kind
                && type_.size_bits() == size_bits
                && type_.align_bits() == align_bits
        }) {
            return Some(found.id());
        }
        let id = u32::try_from(self.types.len()).ok()?;
        self.types
            .push(r2source::SourceType::new(id, kind, size_bits, align_bits));
        Some(id)
    }
}

/// What a spelling stands for, with any name it was given taken off.
///
/// A register class is decided by what a type is, and a `typedef` is a name
/// for something else: `size_t` arrives where an unsigned long does.
fn unnamed(parsed: &r2types::CTypeLike) -> &r2types::CTypeLike {
    match parsed {
        r2types::CTypeLike::Typedef { ty, .. } | r2types::CTypeLike::Const(ty) => unnamed(ty),
        other => other,
    }
}

/// Whether a spelling names a floating-point type.
fn float_spelling(spelling: &str, ptr_bits: u32) -> bool {
    r2types::parse_c_type_like(spelling, ptr_bits)
        .is_some_and(|parsed| matches!(unnamed(&parsed), r2types::CTypeLike::Float(_)))
}

/// Where each declared parameter arrives.
///
/// A parameter arrives in the registers its own class uses, and the two
/// classes are counted separately: the third integer argument takes the third
/// integer register however many floating-point arguments came before it. A
/// class this does not place -- an aggregate, which the ABI may split across
/// registers or put in memory depending on its members -- refuses the whole
/// declaration rather than putting it in the next integer register and being
/// wrong about every argument after it.
fn placed_parameters(
    prototype: &r2abi::Prototype,
    target: &NativeTarget<'_>,
    machine: &NativeMachine,
    ptr_bits: u32,
) -> Option<Vec<CanonicalStorageId>> {
    let integer_slots = machine.slots.argument_slots();
    let mut integers = 0usize;
    let mut floats = 0usize;
    let mut placed = Vec::with_capacity(prototype.parameters.len());
    for parameter in &prototype.parameters {
        let Some(parsed) = r2types::parse_c_type_like(parameter.spelling.as_type(), ptr_bits)
        else {
            r2il::refusal_evidence!(
                "declared-interface",
                "{}: no register class for `{}`",
                prototype.name,
                parameter.spelling.as_written()
            );
            return None;
        };
        let storage = match unnamed(&parsed) {
            r2types::CTypeLike::Float(_) => {
                let slot = target.convention.float_args.get(floats)?;
                floats += 1;
                storage(target.arch, slot.name()).ok()?
            }
            // How an aggregate travels depends on its size and on what its
            // members are: one register, two, or memory. Nothing here knows
            // its members, so it refuses rather than taking the next integer
            // register and being wrong about every argument after it too.
            r2types::CTypeLike::Struct(_)
            | r2types::CTypeLike::Union(_)
            | r2types::CTypeLike::Array(..) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{}: `{}` is an aggregate and its register class depends on its members",
                    prototype.name,
                    parameter.spelling.as_written()
                );
                return None;
            }
            _ => {
                let storage = *integer_slots.get(integers)?;
                integers += 1;
                storage
            }
        };
        placed.push(storage);
    }
    Some(placed)
}

/// One declared prototype as the type layer states it.
///
/// A spelling this build cannot parse leaves the whole prototype out rather
/// than contributing a parameter list with a hole in it.
fn function_type(prototype: &r2abi::Prototype, ptr_bits: u32) -> Option<r2types::FunctionType> {
    let mut params = Vec::with_capacity(prototype.parameters.len());
    for parameter in &prototype.parameters {
        params.push(r2types::parse_c_type_like(
            parameter.spelling.as_type(),
            ptr_bits,
        )?);
    }
    Some(r2types::FunctionType {
        return_type: r2types::parse_c_type_like(prototype.returns.as_type(), ptr_bits)?,
        params,
        variadic: prototype.variadic,
    })
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

/// One function walked out of the program.
struct Walked {
    name: String,
    body: r2ssa::body::Body,
    /// What each function this one calls is called.
    callee_names: Vec<String>,
}

/// One program, one machine, and the walk over it.
/// One dispatch's table, read, and where the dispatch that reads it stands.
struct NativePointerTable {
    instruction: u64,
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
    fn walk(&self, entry: u64) -> Result<Walked, NativeRefusal> {
        self.walk_dispatched(entry, &BTreeMap::new())
    }

    /// The same walk, told where the dispatches a previous pass read go.
    fn walk_dispatched(
        &self,
        entry: u64,
        dispatched: &BTreeMap<u64, Vec<u64>>,
    ) -> Result<Walked, NativeRefusal> {
        let body = lift_body(entry, self.target.disasm, self.program, dispatched)
            .map_err(NativeRefusal::Body)?;
        let callee_names = body
            .calls
            .iter()
            .filter_map(|address| self.program.name_at(*address))
            .collect();
        Ok(Walked {
            name: self
                .program
                .name_at(entry)
                .unwrap_or_else(|| r2source::unnamed_function(entry)),
            body,
            callee_names,
        })
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

    fn pointer_table(
        &self,
        read: &r2ssa::indirect::DispatchTableRead,
    ) -> Option<NativePointerTable> {
        let entry = usize::try_from(read.entry_size).ok()?;
        let span = read.entries.checked_mul(entry)?;
        let bytes = self.program.read(read.address, span).unwrap_or_default();
        if bytes.len() < span {
            r2il::refusal_evidence!(
                "dispatch-table",
                "{:#x}: {} of {span} bytes are mapped",
                read.address,
                bytes.len()
            );
            return None;
        }
        let targets = bytes
            .chunks_exact(entry)
            .map(|slot| match self.machine.endianness {
                SourceEndianness::Little => {
                    slot.iter().rev().fold(0u64, |v, b| (v << 8) | *b as u64)
                }
                SourceEndianness::Big => slot.iter().fold(0u64, |v, b| (v << 8) | *b as u64),
            })
            .map(|slot| read.transform.target(slot, read.entry_size))
            .collect::<Vec<_>>();
        if !targets.iter().all(|target| self.decodes(*target)) {
            r2il::refusal_evidence!(
                "dispatch-table",
                "{:#x} x{} of {} bytes: an entry is not an instruction",
                read.address,
                read.entries,
                read.entry_size
            );
            return None;
        }
        Some(NativePointerTable {
            instruction: read.instruction?,
            cases: read
                .cases
                .iter()
                .copied()
                .zip(targets.iter().copied())
                .collect(),
            table: r2source::SourceCodePointerTable::new(
                read.address,
                read.entry_size,
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
        let Some(bytes) = self.program.read(target, WINDOW) else {
            return false;
        };
        let mut fetch = bytes;
        let available = fetch.len();
        fetch.resize(WINDOW, 0);
        self.target
            .disasm
            .lift(&fetch, target)
            .is_ok_and(|lifted| lifted.size != 0 && lifted.size as usize <= available)
    }

    /// The text a prepared body points at.
    ///
    /// A machine does not always write an address down: aarch64 forms one from
    /// a page and an offset, so the constant a string lives at exists only
    /// once the two are folded. Preparation folds them, and this asks it
    /// rather than re-scanning the operations that could not know.
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
            if address == 0
                || already.contains(&address)
                || !self.program.holds_static_data(address)
            {
                continue;
            }
            if let Some(text) = self.text_at(address) {
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

        // What the declaration stated about the frame stays stated: the body
        // proves where its own slots are, and it proves nothing about a slot
        // it never touched. A slot both describe keeps the recovered one,
        // which is the proven statement.
        let covers = |slot: &r2source::SourceStackSlotSpec,
                      other: &r2source::SourceStackSlotSpec| {
            slot.base() == other.base()
                && slot.offset() < other.offset() + i64::from(other.size_bytes())
                && other.offset() < slot.offset() + i64::from(slot.size_bytes())
        };
        let kept = declared
            .iter()
            .filter(|declared| !slots.iter().any(|slot| covers(slot, declared)))
            .cloned()
            .collect::<Vec<_>>();
        // A slot both describe is one slot: the body's extent stands, and the
        // declaration still says what type sits there.
        let mut slots = slots
            .into_iter()
            .map(|slot| {
                match declared.iter().find(|other| {
                    covers(&slot, other)
                        && other.offset() == slot.offset()
                        && other.size_bytes() == slot.size_bytes()
                }) {
                    Some(other) => match other.logical_type() {
                        None => slot,
                        Some(id) => slot.with_logical_type(id),
                    },
                    None => slot,
                }
            })
            .collect::<Vec<_>>();
        slots.extend(kept);

        restate(interface, slots, interface.revision_identity().to_vec())
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
            .filter(|address| self.program.holds_static_data(*address))
            .filter_map(|address| Some((address, self.text_at(address)?)))
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

    /// Whether any call this body makes is declared to take a function.
    ///
    /// The cheap half of the question, asked off the walk alone so that a body
    /// which cannot hand a function anywhere is never prepared to find out.
    fn hands_a_function(&self, walked: &Walked) -> bool {
        let direct = call_sites(&walked.body, self.program)
            .into_iter()
            .filter_map(|site| self.program.name_at(site.target));
        // An import is reached through a slot the loader fills, and the walk
        // sees the load rather than the call's target, so every slot this body
        // reads counts as a callee it might be handing something to.
        let through_a_slot = walked
            .body
            .blocks
            .iter()
            .flat_map(|block| block.lifted.ops.iter())
            .filter_map(|op| match op {
                // The address is a constant operand; the space is where the
                // load reads from, which is memory.
                r2il::R2ILOp::Load { space, addr, .. }
                    if *space == r2il::SpaceId::Ram && addr.space == r2il::SpaceId::Const =>
                {
                    self.program.import_at(addr.offset)
                }
                _ => None,
            });
        direct.chain(through_a_slot).any(|name| {
            self.target.prototypes.get(&name).is_some_and(|prototype| {
                prototype
                    .parameters
                    .iter()
                    .any(r2abi::Parameter::is_function)
            })
        })
    }

    /// Addresses this body hands to a parameter a declaration calls a function.
    ///
    /// `entry0` never calls `main`. It puts `main` in an argument register and
    /// calls `__libc_start_main`, whose prototype spells that parameter
    /// `func`, so the address is a function on the declaration's authority.
    /// Nothing here guesses: a constant is believed only where a declared type
    /// says that slot holds a function and the constant decodes.
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
                    if address != 0 && self.decodes(address) {
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

    /// The text at an address, where there is text there.
    fn text_at(&self, address: u64) -> Option<String> {
        let bytes = self.program.read(address, crate::names::LITERAL_LIMIT)?;
        crate::names::text_in(&bytes).map(str::to_owned)
    }
}

/// Every address this body names as a constant.
fn referenced(body: &r2ssa::body::Body) -> BTreeSet<u64> {
    let mut addresses = BTreeSet::new();
    for block in &body.blocks {
        for op in &block.lifted.ops {
            for varnode in op.inputs() {
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
        // What a call leaves standing is the specification's statement, and it
        // is asked in the first pass, before an interface exists to hold it.
        // Without it every function that calls loses the facts about its own
        // frame: no entry-relative roots, so no certificate that a slot is its
        // own, so the prologue's save renders as a variable assigned from a
        // value nothing wrote.
        .map(|roles| {
            roles.with_call_preserved_carriers(r2source::SourceCallPreservedCarriers::new(
                target.compiler.preserves(stack_pointer_name),
                // No frame pointer is declared, so a call has none of that kind
                // to disturb. This is the rule the interface fallback states.
                true,
            ))
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
    })
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
fn storage(arch: &ArchSpec, name: &str) -> Result<CanonicalStorageId, NativeRefusal> {
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
