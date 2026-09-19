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

use std::collections::BTreeMap;
use std::sync::Arc;

use r2abi::{CompilerSpec, Convention};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SourceConventionSlots, SourceEndianness,
    SourceMachineRoles, SourceRoleRegisterNames, SourceStackAllocationContract, SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::body::{BodyError, lift_body};
use r2ssa::{CalleePreservedCarriers, SummaryArgumentReach, TrustedSsaArtifact};

use crate::{
    CalleeFacts, EngineDecompileResponse, EngineFunctionDecompileRequestInput, EngineFunctionInput,
    EngineFunctionInputQuality, EngineSession,
};

/// The program being analysed, as the engine needs to see it.
///
/// Two questions and no cursor: what byte lives at an address, and what the
/// program calls one. Whoever opened the binary answers them.
pub trait Program {
    /// As many bytes as are mapped at `vaddr`, up to `max`, or `None` where
    /// nothing is mapped.
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>>;

    /// What the program calls this address, where it names it at all.
    fn name_at(&self, vaddr: u64) -> Option<String>;
}

/// Everything about the machine that does not change between functions.
pub struct NativeTarget<'a> {
    pub arch: &'a ArchSpec,
    pub disasm: &'a Disassembler,
    /// The convention every function is assumed to use, which is the one the
    /// data declares as the default until something says otherwise.
    pub convention: &'a Convention,
    pub compiler: &'a CompilerSpec,
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
pub fn decompile(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
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
    let mut facts = Vec::new();
    for address in root.body.calls.iter().filter(|address| **address != entry) {
        let Ok(walked) = native.walk(*address) else {
            continue;
        };
        let Ok(artifact) = native.prepare(&walked, &Callees::default()) else {
            continue;
        };
        let Some(derived) = CalleeFacts::derive(&artifact, ptr_bits) else {
            continue;
        };
        callees.record(*address, &derived);
        facts.push(derived);
    }

    let artifact = native.prepare(&root, &callees)?;
    let block_count = artifact.source_block_count();
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
        r2types::ParsedExternalContext::default(),
    )
    .with_input_quality(EngineFunctionInputQuality::complete(block_count))
    .with_trusted_ssa(artifact)
    .with_callee_facts(facts);

    Ok(EngineSession::new().decompile_function_from_input(input))
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
}

/// One program, one machine, and the walk over it.
struct Native<'a> {
    target: &'a NativeTarget<'a>,
    program: &'a dyn Program,
    machine: NativeMachine,
    /// Cancellation and the work meter, shared by the root and its callees.
    control: r2ssa::SsaExecutionControl,
}

impl Native<'_> {
    fn walk(&self, entry: u64) -> Result<Walked, NativeRefusal> {
        let body = lift_body(entry, self.target.disasm, |vaddr, max| {
            self.program.read(vaddr, max)
        })
        .map_err(NativeRefusal::Body)?;
        Ok(Walked {
            name: self
                .program
                .name_at(entry)
                .unwrap_or_else(|| format!("fcn.{entry:x}")),
            body,
        })
    }

    /// Capture what was walked and prepare it for the engine.
    fn prepare(
        &self,
        walked: &Walked,
        callees: &Callees,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        let function = NativeFunction {
            address: walked.body.entry,
            name: walked.name.clone(),
            blocks: walked
                .body
                .blocks
                .iter()
                .map(|block| NativeBlock {
                    address: block.lifted.addr,
                    bytes: block.bytes.clone(),
                    successors: block.successors.clone(),
                })
                .collect(),
            calls: call_sites(&walked.body, self.program),
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
    let mut calls = Vec::new();
    for block in &body.blocks {
        for (index, op) in block.lifted.ops.iter().enumerate() {
            let r2il::R2ILOp::Call { target } = op else {
                continue;
            };
            let Some(instruction) = block
                .lifted
                .op_metadata(index)
                .and_then(|metadata| metadata.instruction_addr)
            else {
                continue;
            };
            calls.push(NativeCall {
                instruction,
                target: target.offset,
                name: program.name_at(target.offset),
            });
        }
    }
    calls
}

/// State the machine from the convention data and the compiler specification.
fn machine(target: &NativeTarget<'_>) -> Result<NativeMachine, NativeRefusal> {
    let (family, bits, endianness) = profile(target.arch)?;
    let program_counter_name = target.disasm.program_counter();
    let program_counter = storage(target.arch, program_counter_name)?;
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
    let roles = SourceMachineRoles::new(Some(program_counter), Some(stack_pointer))
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
            Some(program_counter_name),
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
    // Where a seventh argument goes is stated by neither file directly: it is
    // arithmetic over the shadow space and the return-address slot. Until that
    // is derived, a function with more arguments than registers refuses rather
    // than being given a placement nothing proved.
    let slots = SourceConventionSlots::new(&target.convention.name, argument_slots, result_slot)
        .map_err(|_| NativeRefusal::Machine("the convention names one register twice"))?;

    Ok(NativeMachine {
        arch_id: family.to_owned(),
        cpu_id: family.to_owned(),
        bits,
        endianness,
        roles,
        slots,
    })
}

/// The machine tuple the trusted lift selects a Sleigh profile by.
fn profile(arch: &ArchSpec) -> Result<(&'static str, u32, SourceEndianness), NativeRefusal> {
    let bits = crate::engine_effective_ptr_bits(arch);
    let family = match arch.name.to_ascii_lowercase().as_str() {
        "x86" | "x86-32" | "x86-64" | "x86_64" | "x64" | "amd64" | "i386" | "i686" => "x86",
        "arm" | "arm32" | "arm64" | "arm64e" | "aarch64" => "arm",
        _ => {
            return Err(NativeRefusal::Machine(
                "no trusted profile for this machine",
            ));
        }
    };
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
