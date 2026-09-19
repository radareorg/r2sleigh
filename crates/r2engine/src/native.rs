//! Decompiling a function with no radare2 anywhere.
//!
//! This is the whole native route in one place: walk the body out of the
//! program's bytes, state the machine from the convention data and the
//! compiler specification, mint a capture, and hand it to the same trusted
//! lift and the same request the plugin uses. Nothing downstream of the
//! capture is new, and nothing here formats anything.
//!
//! What it does not do yet is read the callees. A capture with no callee
//! bodies renders calls it cannot prove as refusals, which is honest and is
//! the next thing to close.

use std::sync::Arc;

use r2abi::{CompilerSpec, Convention};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SourceConventionSlots, SourceEndianness,
    SourceMachineRoles, SourceRoleRegisterNames, SourceStackAllocationContract, SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::TrustedSsaArtifact;
use r2ssa::body::{BodyError, lift_body};

use crate::{
    EngineDecompileResponse, EngineFunctionDecompileRequestInput, EngineFunctionInput,
    EngineFunctionInputQuality, EngineSession,
};

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

/// Decompile the function at `entry`, reading the program through `read`.
pub fn decompile<R>(
    target: &NativeTarget<'_>,
    entry: u64,
    name: &str,
    read: R,
) -> Result<EngineDecompileResponse, NativeRefusal>
where
    R: Fn(u64, usize) -> Option<Vec<u8>>,
{
    let body = lift_body(entry, target.disasm, read).map_err(NativeRefusal::Body)?;
    let machine = machine(target)?;
    let function = NativeFunction {
        address: entry,
        name: name.to_owned(),
        blocks: body
            .blocks
            .iter()
            .map(|block| NativeBlock {
                address: block.lifted.addr,
                bytes: block.bytes.clone(),
                successors: block.successors.clone(),
            })
            .collect(),
        calls: call_sites(&body),
        loader_role: None,
    };

    let snapshot = r2source::native::capture(&machine, function).map_err(NativeRefusal::Capture)?;
    let lifted = Disassembler::lift_owned_function(snapshot)
        .map_err(|error| NativeRefusal::Lift(error.to_string()))?;
    let trusted = TrustedSsaArtifact::prepare(lifted)
        .map_err(|error| NativeRefusal::Prepare(format!("{error:?}")))?;

    let block_count = trusted.source_block_count();
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);
    let input = EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: name.to_owned(),
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
    .with_trusted_ssa(Arc::new(trusted));

    Ok(EngineSession::new().decompile_function_from_input(input))
}

/// Where each direct call is made and what it reaches.
///
/// The walk collects call targets without saying which instruction made each
/// one, so the instruction is found by looking for the call operation in the
/// block that carries it.
fn call_sites(body: &r2ssa::body::Body) -> Vec<NativeCall> {
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
