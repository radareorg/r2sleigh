//! Immutable machine context captured with an SSA artifact.
//!
//! Legacy `SSAOp` memory-space strings are presentation data and cannot serve
//! as proof. This snapshot retains the typed r2il address space at each source
//! operation site together with the architecture memory model used to lift it.

use std::collections::{BTreeMap, BTreeSet};

use r2il::{
    ArchSpec, Endianness, R2ILBlock, R2ILOp, RegisterProjection, RegisterStorage, SpaceId,
    effective_arch_address_size,
};
use serde::Serialize;

use crate::arch::Arch;
use crate::origin::BlockOrigins;
pub use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SOURCE_CALL_SITE_INTERFACE_SCHEMA_VERSION,
    SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION, SOURCE_TYPE_GRAPH_SCHEMA_VERSION,
    SourceAbiParameterSpec, SourceAggregateLayout, SourceAggregateMember, SourceArity,
    SourceArityFloor, SourceCallArgumentSpec, SourceCallPreservedCarriers, SourceCallResult,
    SourceCallSiteIdentity, SourceCallSiteInterface, SourceCallSiteInterfaceError,
    SourceCarrierKind, SourceCarrierProjection, SourceCodeSignature, SourceFloorCause,
    SourceFormatParameterRule, SourceFunctionInterface, SourceFunctionInterfaceError,
    SourceFunctionReturn, SourceLogicalValue, SourceMachineRoles, SourceMachineRolesError,
    SourceOpaqueTag, SourceParameterLocation, SourceResultCause, SourceResultSeed,
    SourceResultWidth, SourceSlot, SourceStackAllocationContract, SourceStackGrowth,
    SourceStackSlotRole, SourceStackSlotSpec, SourceTagKeyword, SourceType, SourceTypeAlias,
    SourceTypeClosure, SourceTypeGraph, SourceTypeGraphError, SourceTypeGraphParts, SourceTypeKind,
    SourceUnprovenCall, SourceUnprovenResult, SourceUnstatedCall, StackAddressBase,
};

pub const MACHINE_CONTEXT_SCHEMA_VERSION: u32 = 28;

/// Typed calling-convention carrier snapshot injected with the function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineAbiModel {
    schema_version: u32,
    available: bool,
    /// Whether the return carrier is a real register no other role aliases.
    return_boundary_coherent: bool,
    /// Whether every declared parameter register is real and unaliased.
    argument_placement_coherent: bool,
    /// Whether the frame slots are attributed and their bases resolved.
    frame_geometry_coherent: bool,
    /// Whether the return-address, stack- and frame-pointer carriers hold.
    machine_carriers_coherent: bool,
    frame_pointer_storage: Option<CanonicalStorageId>,
}

impl MachineAbiModel {
    fn unavailable() -> Self {
        Self {
            schema_version: MACHINE_CONTEXT_SCHEMA_VERSION,
            available: false,
            return_boundary_coherent: false,
            argument_placement_coherent: false,
            frame_geometry_coherent: false,
            machine_carriers_coherent: false,
            frame_pointer_storage: None,
        }
    }

    fn from_interface(
        interface: Option<&SourceFunctionInterface>,
        frame_pointer_storage: Option<CanonicalStorageId>,
    ) -> Self {
        if interface.is_none() {
            return Self::unavailable();
        }
        Self {
            schema_version: MACHINE_CONTEXT_SCHEMA_VERSION,
            available: true,
            return_boundary_coherent: true,
            argument_placement_coherent: true,
            frame_geometry_coherent: true,
            machine_carriers_coherent: true,
            frame_pointer_storage,
        }
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn is_available(&self) -> bool {
        self.available
    }

    /// Whether the values a `Return` carries can be read off this model.
    ///
    /// Asks only about the return register: that the architecture has it and
    /// that no machine carrier aliases it. Frame attribution is a different
    /// question and cannot invalidate this one.
    pub const fn return_boundary_is_coherent(&self) -> bool {
        self.return_boundary_coherent
    }

    /// Whether a declared parameter's register placement can be trusted.
    pub const fn argument_placement_is_coherent(&self) -> bool {
        self.argument_placement_coherent
    }

    /// Whether every frame slot is attributed and its base register resolved.
    pub const fn frame_geometry_is_coherent(&self) -> bool {
        self.frame_geometry_coherent
    }

    /// Whether the return-address, stack- and frame-pointer carriers hold.
    pub const fn machine_carriers_are_coherent(&self) -> bool {
        self.machine_carriers_coherent
    }

    pub const fn frame_pointer_storage(&self) -> Option<CanonicalStorageId> {
        self.frame_pointer_storage
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineMemoryEndianness {
    Little,
    Big,
    Mixed,
    Custom,
    Unknown,
}

impl From<Endianness> for MachineMemoryEndianness {
    fn from(endianness: Endianness) -> Self {
        match endianness {
            Endianness::Little => Self::Little,
            Endianness::Big => Self::Big,
            Endianness::Mixed => Self::Mixed,
            Endianness::Custom => Self::Custom,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineMemorySpace {
    space: SpaceId,
    address_bits: u32,
    word_size_bytes: u32,
    endianness: MachineMemoryEndianness,
}

impl MachineMemorySpace {
    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn address_bits(&self) -> u32 {
        self.address_bits
    }

    pub const fn word_size_bytes(&self) -> u32 {
        self.word_size_bytes
    }

    pub const fn endianness(&self) -> MachineMemoryEndianness {
        self.endianness
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineMemoryModel {
    schema_version: u32,
    available: bool,
    coherent: bool,
    default_address_bits: u32,
    alignment_bytes: u32,
    default_endianness: MachineMemoryEndianness,
    spaces: Box<[MachineMemorySpace]>,
}

impl MachineMemoryModel {
    fn unavailable() -> Self {
        Self {
            schema_version: MACHINE_CONTEXT_SCHEMA_VERSION,
            available: false,
            coherent: false,
            default_address_bits: 0,
            alignment_bytes: 0,
            default_endianness: MachineMemoryEndianness::Unknown,
            spaces: Box::new([]),
        }
    }

    pub(crate) fn from_arch(arch: Option<&ArchSpec>) -> Self {
        let Some(arch) = arch else {
            return Self::unavailable();
        };
        let effective_address_size = effective_arch_address_size(arch);
        let default_address_bits = effective_address_size.checked_mul(8).unwrap_or(0);
        let mut coherent = default_address_bits > 0 && arch.alignment > 0;
        let default_endianness = MachineMemoryEndianness::from(arch.memory_endianness);
        let mut spaces = Vec::with_capacity(arch.spaces.len() + 1);

        for source in &arch.spaces {
            if spaces
                .iter()
                .any(|space: &MachineMemorySpace| space.space == source.id)
            {
                coherent = false;
                continue;
            }
            let address_size = if source.addr_size > 1 {
                source.addr_size
            } else {
                effective_address_size
            };
            let address_bits = address_size.checked_mul(8).unwrap_or(0);
            if address_bits == 0 || source.word_size == 0 {
                coherent = false;
            }
            spaces.push(MachineMemorySpace {
                space: source.id,
                address_bits,
                word_size_bytes: source.word_size,
                endianness: source
                    .endianness
                    .map(MachineMemoryEndianness::from)
                    .unwrap_or(default_endianness),
            });
        }
        if !spaces.iter().any(|space| space.space == SpaceId::Ram) {
            spaces.push(MachineMemorySpace {
                space: SpaceId::Ram,
                address_bits: default_address_bits,
                word_size_bytes: 1,
                endianness: default_endianness,
            });
        }
        spaces.sort_by_key(|space| crate::semantic::memory_space_order(space.space));

        Self {
            schema_version: MACHINE_CONTEXT_SCHEMA_VERSION,
            available: true,
            coherent,
            default_address_bits,
            alignment_bytes: arch.alignment,
            default_endianness,
            spaces: spaces.into_boxed_slice(),
        }
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn is_available(&self) -> bool {
        self.available
    }

    pub const fn is_coherent(&self) -> bool {
        self.coherent
    }

    pub const fn default_address_bits(&self) -> u32 {
        self.default_address_bits
    }

    pub const fn default_endianness(&self) -> MachineMemoryEndianness {
        self.default_endianness
    }

    pub const fn spaces(&self) -> &[MachineMemorySpace] {
        &self.spaces
    }

    pub fn space(&self, space: SpaceId) -> Option<&MachineMemorySpace> {
        self.spaces
            .iter()
            .find(|candidate| candidate.space == space)
    }
}

fn is_exact_top_level_address_register(
    arch: &crate::Arch,
    storage: CanonicalStorageId,
    address_size: u32,
) -> bool {
    storage.space == CanonicalStorageSpace::Register
        && storage.size == address_size
        && arch.registers.iter().any(|register| {
            register.parent.is_none()
                && register.offset == storage.offset
                && register.size == storage.size
        })
        && !arch.registers.iter().any(|register| {
            register.size > storage.size
                && register.offset <= storage.offset
                && register
                    .offset
                    .checked_add(u64::from(register.size))
                    .zip(storage.offset.checked_add(u64::from(storage.size)))
                    .is_some_and(|(register_end, storage_end)| register_end >= storage_end)
        })
}

fn register_storages_are_disjoint(first: CanonicalStorageId, second: CanonicalStorageId) -> bool {
    if first.space != second.space {
        return true;
    }
    first
        .offset
        .checked_add(u64::from(first.size))
        .zip(second.offset.checked_add(u64::from(second.size)))
        .is_some_and(|(first_end, second_end)| {
            first_end <= second.offset || second_end <= first.offset
        })
}

fn frame_pointer_storage_matches_machine(
    interface: &SourceFunctionInterface,
    frame_pointer_storage: Option<CanonicalStorageId>,
    arch: Option<&Arch>,
) -> bool {
    let Some(frame_pointer) = frame_pointer_storage else {
        return true;
    };
    let Some(arch) = arch else {
        return false;
    };
    let Some(return_address) = interface.return_address_storage() else {
        return false;
    };
    let Some(stack_pointer) = interface.stack_pointer_storage() else {
        return false;
    };
    let address_size = effective_arch_address_size(arch);
    interface.frame_pointer_storage_is_valid(frame_pointer)
        && interface.return_address_storage_is_valid(return_address)
        && interface.stack_pointer_storage_is_valid(stack_pointer)
        && is_exact_top_level_address_register(arch, frame_pointer, address_size)
        && is_exact_top_level_address_register(arch, return_address, address_size)
        && is_exact_top_level_address_register(arch, stack_pointer, address_size)
        && register_storages_are_disjoint(frame_pointer, return_address)
        && register_storages_are_disjoint(frame_pointer, stack_pointer)
        && register_storages_are_disjoint(return_address, stack_pointer)
}

fn return_mechanism_matches_machine(
    interface: &SourceFunctionInterface,
    arch: Option<&Arch>,
    memory_model: &MachineMemoryModel,
) -> bool {
    let Some(mechanism) = interface.return_mechanism() else {
        return true;
    };
    let Some(arch) = arch else {
        return false;
    };
    let address_size = mechanism.address_size_bytes();
    let Some(address_bits) = address_size.checked_mul(8) else {
        return false;
    };
    if address_size <= 1
        || arch.addr_size != address_size
        || mechanism.stack_offset() != 0
        || mechanism.slot_size_bytes() != address_size
        || mechanism.stack_pointer_delta_bytes() != address_size
        || memory_model.default_address_bits() != address_bits
    {
        return false;
    }
    let Some(ram) = memory_model.space(SpaceId::Ram) else {
        return false;
    };
    if ram.word_size_bytes() != 1 || ram.address_bits() != address_bits {
        return false;
    }
    let mut explicit_ram_spaces = arch.spaces.iter().filter(|space| space.id == SpaceId::Ram);
    let Some(explicit_ram) = explicit_ram_spaces.next() else {
        return false;
    };
    if explicit_ram_spaces.next().is_some()
        || explicit_ram.word_size != 1
        || explicit_ram.addr_size != address_size
    {
        return false;
    }
    let Some(return_address) = interface.return_address_storage() else {
        return false;
    };
    let Some(stack_pointer) = interface.stack_pointer_storage() else {
        return false;
    };
    is_exact_top_level_address_register(arch, return_address, address_size)
        && is_exact_top_level_address_register(arch, stack_pointer, address_size)
}

/// Ingress disposition of the source-owned register geometry contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineRegisterGeometryState {
    Unavailable,
    Available,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMachineContext {
    schema_version: u32,
    /// The architecture the lift was made under, with its tables.
    arch: Option<Arch>,
    memory_model: MachineMemoryModel,
    function_interface: Option<SourceFunctionInterface>,
    machine_roles: SourceMachineRoles,
    /// The function's convention and its calls'; none only off the native path, where a call
    /// reads and clobbers every outermost register (RULING 2.1).
    conventions: Option<r2source::Conventions>,
    abi_model: MachineAbiModel,
    /// What a call in this body may leave changed: the set construction defines after every call.
    call_clobbered_carriers: Box<[CanonicalStorageId]>,
    /// What each direct callee's own body proves it leaves alone, by entry.
    callee_preserved: crate::function::CalleePreservedCarriers,
    /// How many arguments each callee whose result is unproven reads at least.
    callee_statements: BTreeMap<u64, CalleeStatement>,
    /// The projections of what this body writes that the register file does not declare, sorted.
    observed_projections: Box<[RegisterProjection]>,
    /// Every call site the raw lifted input has, by the instruction it was
    /// lifted from.
    raw_call_sites: BTreeMap<u64, SourceCallSiteIdentity>,
    tail_call_sites: BTreeSet<SourceCallSiteIdentity>,
    /// Who each raw call site calls, where the source knew.
    callee_linkages: BTreeMap<SourceCallSiteIdentity, r2source::AdvisoryCalleeLinkage>,
    /// The sealed import slot each `CallSlot` site calls through (audit W8).
    slot_targets: BTreeMap<SourceCallSiteIdentity, u64>,
    /// The sites whose contract an earlier seal minted from a member's type (S32).
    member_call_sites: BTreeSet<SourceCallSiteIdentity>,
    /// The name the source gave each raw call site's callee.
    callee_names: BTreeMap<SourceCallSiteIdentity, String>,
    /// How far each callee is proven to touch through each pointer argument,
    /// by the callee's own entry address. What a callee reaches through one
    /// address is one object in this frame, and the object model is built
    /// before the interprocedural solve exists, so the fact arrives with the
    /// bodies the capture took rather than from that solve.
    callee_argument_reach: BTreeMap<u64, BTreeMap<usize, crate::interproc::ArgumentReach>>,
    /// What each stated callee may write of its caller's stack, by entry (D377).
    callee_writes: BTreeMap<u64, crate::call_reads::StackWrites>,
    /// The low bytes each walked callee may read of each result register, by entry (D372).
    callee_lane_reads: crate::function::CalleeLaneReads,
    /// The convention each call runs under (D390); any other call runs under `calls`.
    sites: std::sync::Arc<crate::function::SiteModels>,
    /// The library models of the imports this body calls, by entry.
    callee_library: BTreeMap<u64, crate::interproc::FunctionSemanticSummary>,
    /// The callees a runtime model says re-enter their caller at its entry.
    reentering_callees: BTreeSet<u64>,
    /// The imports this body calls whose declaration states no interface, and why.
    unstated_imports: BTreeMap<u64, crate::UnstatedImport>,
    /// The register saves the container's call-frame information states.
    frame_saves: Vec<r2source::SourceFrameSave>,
    /// The premises the engine grants its derivations (`r2engine::premises`).
    accepted_premises: BTreeSet<r2source::Premise>,
    /// The function each captured code pointer table entry names, by the
    /// address of the entry. A slot a relocation fills holds no address the
    /// file states, so what it becomes is a fact about the program rather
    /// than bytes a reader could fetch.
    code_pointer_entries: BTreeMap<u64, u64>,
    /// The tables the capture fetched, by the indirect transfer that reads each: what a dispatch
    /// states is what its own table gave it, however another table covers the same slots.
    code_pointer_tables: BTreeMap<u64, r2source::SourceCodePointerTable>,
    call_site_interfaces: BTreeMap<SourceCallSiteIdentity, SourceCallSiteInterface>,
    /// Literal bytes captured by the same immutable source transaction as the
    /// callsite interfaces. Unlike display strings, these are semantic
    /// evidence, because a variadic format literal is count evidence.
    source_string_literals: BTreeMap<u64, String>,
    /// Bytes the program never writes, by the address a body loads from: what a load there reads.
    read_only: BTreeMap<u64, Box<[u8]>>,
    /// What the read-only format each printf call's own block passes consumes, by the call's
    /// instruction (D409).
    format_tails: BTreeMap<u64, r2abi::format::PrintfConsumedArguments>,
    /// The image's data objects whose type is a laid-out struct, with that graph (D348).
    data_structs: Option<std::sync::Arc<DataStructs>>,
}

/// Data objects the image graph types as a struct of known size, by address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStructs {
    pub graph: r2source::SourceTypeGraph,
    /// Start address to `(type id, size in bytes)`.
    by_address: BTreeMap<u64, (u32, u64)>,
}

impl DataStructs {
    /// The struct object holding `address`, as its start, type id and the offset into it. O(log n).
    pub fn containing(&self, address: u64) -> Option<(u64, u32, u64)> {
        let (&start, &(type_id, size)) = self.by_address.range(..=address).next_back()?;
        let offset = address - start;
        (offset < size).then_some((start, type_id, offset))
    }
}

/// Unique register-space ranges the lifted body actually reads or writes.
///
/// The architecture query owns projection policy. This pass only supplies the
/// exact observed ranges once so the immutable function context can retain a
/// sorted `O(log n)` lookup table for every later consumer.
fn observed_register_storages(blocks: &[R2ILBlock]) -> BTreeSet<RegisterStorage> {
    blocks
        .iter()
        .flat_map(|block| &block.ops)
        .flat_map(|op| op.inputs().into_iter().chain(op.output()))
        .filter(|varnode| varnode.space == SpaceId::Register)
        .map(|varnode| RegisterStorage {
            offset: varnode.offset,
            size: varnode.size,
        })
        .collect()
}

/// What a call in this body may leave changed: what the model names clobbered and every register
/// the body touches that the call neither keeps nor finds reserved; under no model, every one.
fn clobbered_by_a_call(
    calls: Option<&r2source::ConventionModel>,
    arch: Option<&Arch>,
    observed: &BTreeSet<RegisterStorage>,
) -> Box<[CanonicalStorageId]> {
    let named = match arch {
        Some(arch) => arch.call_clobbered(calls),
        None => calls
            .and_then(r2source::ConventionModel::clobbered)
            .unwrap_or(&[]),
    };
    let touched = (observed.iter())
        .map(|storage| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: storage.offset,
            size: storage.size,
        })
        .filter(|storage| calls.is_none_or(|model| model.clobbers(*storage)));
    (named.iter().copied().chain(touched))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// What a typed indirect call writes: its argument area.
static ARGUMENT_AREA: crate::call_reads::StackWrites = crate::call_reads::StackWrites::arguments();

impl SourceMachineContext {
    pub(crate) fn from_blocks(blocks: &[R2ILBlock], arch: Option<&Arch>) -> Self {
        Self::from_blocks_with_interfaces(
            blocks,
            arch,
            None,
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        )
    }

    pub(crate) fn from_blocks_with_interfaces(
        blocks: &[R2ILBlock],
        arch: Option<&Arch>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        conventions: Option<r2source::Conventions>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
    ) -> Self {
        Self::from_blocks_with_interfaces_and_tail_calls(
            blocks,
            arch,
            function_interface,
            machine_roles,
            conventions,
            call_site_interfaces,
            Vec::new(),
        )
    }

    pub(crate) fn from_blocks_with_interfaces_and_tail_calls(
        blocks: &[R2ILBlock],
        arch: Option<&Arch>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        conventions: Option<r2source::Conventions>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        tail_call_identities: Vec<SourceCallSiteIdentity>,
    ) -> Self {
        Self::from_blocks_with_interfaces_tail_calls_and_terminals(
            blocks,
            arch,
            function_interface,
            machine_roles,
            conventions,
            call_site_interfaces,
            tail_call_identities,
            &BTreeSet::new(),
        )
    }

    /// `terminal_blocks` are the blocks the source's own block graph declares
    /// to have no successor. A transfer at the end of one of them leaves the
    /// function whatever it transfers through, which is what makes an
    /// indirect jump there a tail call rather than an unresolved dispatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_blocks_with_interfaces_tail_calls_and_terminals(
        blocks: &[R2ILBlock],
        arch: Option<&Arch>,
        function_interface: Option<SourceFunctionInterface>,
        machine_roles: SourceMachineRoles,
        conventions: Option<r2source::Conventions>,
        call_site_interfaces: Vec<SourceCallSiteInterface>,
        tail_call_identities: Vec<SourceCallSiteIdentity>,
        terminal_blocks: &BTreeSet<u64>,
    ) -> Self {
        // One walk over the body names every register it touches, for the projections and the clobbers alike.
        let observed = observed_register_storages(blocks);
        let calls = conventions.as_ref().map(|it| &*it.calls);
        let observed_projections = arch
            .filter(|machine| machine.geometry() == MachineRegisterGeometryState::Available)
            .map(|machine| {
                observed
                    .iter()
                    .filter(|storage| machine.declared_projection(**storage).is_none())
                    .filter_map(|storage| machine.project(*storage))
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            })
            .unwrap_or_default();
        let storage_exists = |storage: CanonicalStorageId| {
            arch.is_some_and(|machine| machine.names_register(storage))
        };
        let memory_model = arch.map_or_else(MachineMemoryModel::unavailable, |machine| {
            machine.memory_model().clone()
        });
        let frame_pointer_storage = function_interface
            .as_ref()
            .and_then(SourceFunctionInterface::exact_frame_pointer_storage);
        let mut abi_model =
            MachineAbiModel::from_interface(function_interface.as_ref(), frame_pointer_storage);
        if let Some(interface) = function_interface.as_ref() {
            let has_frame_pointer_slots = interface
                .stack_slots()
                .iter()
                .any(|slot| slot.base() == StackAddressBase::FramePointer);
            let machine_carrier_roles_exist = interface.return_address_storage().is_some()
                && interface.stack_pointer_storage().is_some();
            // Where the frame's slots are, not what they hold. A slot whose
            // role the analysis could not attribute still has a base register
            // and an offset, and one such slot used to switch off the stack
            // address analysis for every other slot in the frame.
            let frame_roles_exist = !has_frame_pointer_slots || frame_pointer_storage.is_some();
            // Every machine carrier, the frame pointer included: a frame
            // pointer that aliases a parameter makes that parameter's
            // placement wrong, not just the frame's geometry.
            let carrier_storages_are_disjoint = interface
                .return_address_storage()
                .is_none_or(|storage| interface.return_address_storage_is_valid(storage))
                && interface
                    .stack_pointer_storage()
                    .is_none_or(|storage| interface.stack_pointer_storage_is_valid(storage))
                && frame_pointer_storage
                    .is_none_or(|storage| interface.frame_pointer_storage_is_valid(storage));
            // Asked per role rather than over the whole chain: a slot base the
            // architecture does not have says nothing about the return register.
            let parameter_storages_exist = interface
                .parameters()
                .iter()
                .filter_map(SourceAbiParameterSpec::register_storage)
                .all(storage_exists);
            let return_storage_exists = interface.return_kind().storages().all(storage_exists);
            let slot_base_storages_exist = interface
                .stack_slots()
                .iter()
                .map(SourceStackSlotSpec::base_storage)
                .all(storage_exists);
            let machine_carrier_storages_exist = interface
                .return_address_storage()
                .into_iter()
                .chain(interface.stack_pointer_storage())
                .chain(frame_pointer_storage)
                .all(storage_exists);
            let is_exact_address_register = |storage: CanonicalStorageId| {
                arch.is_some_and(|arch| {
                    is_exact_top_level_address_register(
                        arch,
                        storage,
                        effective_arch_address_size(arch),
                    )
                })
            };
            let machine_carriers_are_exact_address_registers = interface
                .return_address_storage()
                .is_none_or(is_exact_address_register)
                && interface
                    .stack_pointer_storage()
                    .is_none_or(is_exact_address_register)
                && frame_pointer_storage.is_none_or(is_exact_address_register);
            let frame_pointer_matches =
                frame_pointer_storage_matches_machine(interface, frame_pointer_storage, arch);
            let return_mechanism_matches =
                return_mechanism_matches_machine(interface, arch, &memory_model);
            // Four questions, each conjoining only the terms that bear on it.
            // Whole-model coherence made a frame-attribution gap silence the
            // return boundary, which asks nothing about frames.
            let return_boundary_coherent = return_storage_exists && carrier_storages_are_disjoint;
            let argument_placement_coherent =
                parameter_storages_exist && carrier_storages_are_disjoint;
            let frame_geometry_coherent =
                frame_roles_exist && slot_base_storages_exist && frame_pointer_matches;
            let machine_carriers_coherent = machine_carrier_roles_exist
                && machine_carrier_storages_exist
                && carrier_storages_are_disjoint
                && machine_carriers_are_exact_address_registers
                && return_mechanism_matches;
            if !(return_boundary_coherent
                && argument_placement_coherent
                && frame_geometry_coherent
                && machine_carriers_coherent)
            {
                // Which question failed, and on which term. An interface that
                // carries the frame-pointer homes DWARF declared but no
                // frame-pointer storage fails frame geometry alone, which is a
                // different repair from a carrier that is not an address
                // register -- and neither touches the return boundary.
                r2il::refusal_evidence!(
                    "abi-model-incoherent",
                    "return_boundary={return_boundary_coherent} \
                     argument_placement={argument_placement_coherent} \
                     frame_geometry={frame_geometry_coherent} \
                     machine_carriers={machine_carriers_coherent} \
                     slot_roles_complete={} return_address={} stack_pointer={} \
                     frame_pointer_slots={has_frame_pointer_slots} \
                     frame_pointer_storage={} carriers_disjoint={carrier_storages_are_disjoint} \
                     parameter_storages={parameter_storages_exist} \
                     return_storage={return_storage_exists} \
                     slot_base_storages={slot_base_storages_exist} \
                     carrier_storages={machine_carrier_storages_exist} \
                     carriers_are_addresses={machine_carriers_are_exact_address_registers} \
                     frame_pointer_matches={frame_pointer_matches} \
                     return_mechanism_matches={return_mechanism_matches} \
                     stack_slots={} unclassified_slots={} parameters={}",
                    interface.stack_slot_roles_complete(),
                    interface.return_address_storage().is_some(),
                    interface.stack_pointer_storage().is_some(),
                    frame_pointer_storage.is_some(),
                    interface.stack_slots().len(),
                    interface
                        .stack_slots()
                        .iter()
                        .filter(|slot| {
                            slot.role() == r2source::SourceStackSlotRole::UnclassifiedResource
                        })
                        .count(),
                    interface.parameters().len()
                );
            }
            abi_model.return_boundary_coherent &= return_boundary_coherent;
            abi_model.argument_placement_coherent &= argument_placement_coherent;
            abi_model.frame_geometry_coherent &= frame_geometry_coherent;
            abi_model.machine_carriers_coherent &= machine_carriers_coherent;
        }
        let (raw_call_sites, tail_call_sites) =
            collect_raw_call_site_identities(blocks, &tail_call_identities, terminal_blocks);
        let expected_call_site_revision = function_interface
            .as_ref()
            .map(|interface| interface.revision_identity().to_vec().into_boxed_slice())
            .or_else(|| {
                call_site_interfaces
                    .first()
                    .map(|interface| interface.revision_identity().to_vec().into_boxed_slice())
            });
        let mut call_site_interfaces_by_identity = BTreeMap::new();
        let mut claimed_sites = BTreeSet::new();
        for interface in call_site_interfaces {
            let identity = interface.identity();
            let site = identity.instruction();
            let carriers_exist = interface
                .arguments()
                .iter()
                .filter_map(|argument| argument.register_storage())
                .chain(interface.result().storages())
                .all(storage_exists);
            // A call site the source described badly says nothing about the
            // other call sites in this function. Drop the one that does not
            // hold up and keep the rest, rather than withholding every
            // interface because one of them was wrong: interfaces are already
            // stored per identity, so there is nothing shared to protect.
            let schema_ok = interface.schema_version() == SOURCE_CALL_SITE_INTERFACE_SCHEMA_VERSION;
            let revision_ok =
                expected_call_site_revision.as_deref() == Some(interface.revision_identity());
            let site_known = raw_call_sites.get(&identity.instruction()) == Some(&identity);
            let site_unclaimed = claimed_sites.insert(site);
            if !schema_ok || !revision_ok || !site_known || !site_unclaimed || !carriers_exist {
                r2il::refusal_evidence!(
                    "call-site-interface-dropped",
                    "site {:#x} target {:?}: schema={schema_ok} revision={revision_ok} known={site_known} unclaimed={site_unclaimed} carriers={carriers_exist} arguments={:?}",
                    identity.instruction(),
                    identity.target(),
                    interface
                        .arguments()
                        .iter()
                        .map(|argument| argument.location())
                        .collect::<Vec<_>>()
                );
                call_site_interfaces_by_identity.remove(&identity);
                continue;
            }
            if call_site_interfaces_by_identity
                .insert(identity, interface)
                .is_some()
            {
                // Two interfaces claiming one identity leave no way to tell
                // which describes the call, so neither is kept.
                call_site_interfaces_by_identity.remove(&identity);
            }
        }
        Self {
            schema_version: MACHINE_CONTEXT_SCHEMA_VERSION,
            arch: arch.cloned(),
            memory_model,
            function_interface,
            machine_roles,
            call_clobbered_carriers: clobbered_by_a_call(calls, arch, &observed),
            conventions,
            abi_model,
            callee_preserved: BTreeMap::new(),
            callee_statements: BTreeMap::new(),
            observed_projections,
            raw_call_sites,
            tail_call_sites,
            callee_linkages: BTreeMap::new(),
            slot_targets: BTreeMap::new(),
            member_call_sites: BTreeSet::new(),
            callee_names: BTreeMap::new(),
            callee_argument_reach: BTreeMap::new(),
            callee_writes: BTreeMap::new(),
            callee_lane_reads: BTreeMap::new(),
            sites: std::sync::Arc::default(),
            callee_library: BTreeMap::new(),
            reentering_callees: BTreeSet::new(),
            unstated_imports: BTreeMap::new(),
            frame_saves: Vec::new(),
            accepted_premises: BTreeSet::new(),
            code_pointer_entries: BTreeMap::new(),
            code_pointer_tables: BTreeMap::new(),
            call_site_interfaces: call_site_interfaces_by_identity,
            source_string_literals: BTreeMap::new(),
            read_only: BTreeMap::new(),
            format_tails: BTreeMap::new(),
            data_structs: None,
        }
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The lifted machine's identity; empty when no architecture was given.
    pub fn architecture(&self) -> &str {
        self.arch
            .as_ref()
            .map_or("", |machine| machine.name.as_str())
    }

    /// The architecture the lift was made under, with its tables.
    pub const fn arch(&self) -> Option<&Arch> {
        self.arch.as_ref()
    }

    pub const fn memory_model(&self) -> &MachineMemoryModel {
        &self.memory_model
    }

    pub const fn abi_model(&self) -> &MachineAbiModel {
        &self.abi_model
    }

    pub const fn function_interface(&self) -> Option<&SourceFunctionInterface> {
        self.function_interface.as_ref()
    }

    /// Replace the function interface with the one the body has been read
    /// into. Identity is computed on demand, so it follows the replacement.
    pub(crate) fn seal_function_interface(&mut self, interface: SourceFunctionInterface) {
        self.function_interface = Some(interface);
    }

    /// Borrow the machine carriers the source resolved from its register
    /// profile. These are available whether or not an ABI was recovered.
    pub const fn machine_roles(&self) -> &SourceMachineRoles {
        &self.machine_roles
    }

    /// The integer result register of the function's convention; none without a model.
    pub fn result_slot(&self) -> Option<CanonicalStorageId> {
        self.convention()
            .and_then(r2source::ConventionModel::result)
    }

    /// The location this function returns a value in, and whether it returns
    /// one at all.
    ///
    /// The interface states both, so a function declared to return nothing
    /// answers `None` rather than the location a result would have gone in.
    /// The convention answers only where a caller *would* leave a value, which
    /// is not the same claim, so it is the fallback for a function whose
    /// interface was never recovered.
    pub fn return_value_carrier(&self) -> Option<CanonicalStorageId> {
        match self.function_interface.as_ref().map(|i| i.return_kind()) {
            Some(r2source::SourceFunctionReturn::Void) => None,
            Some(r2source::SourceFunctionReturn::Register { storage }) => Some(storage),
            // Two registers are no one carrier.
            Some(r2source::SourceFunctionReturn::Pair { .. }) => None,
            // An unproven result claims nothing, so the convention answers.
            Some(r2source::SourceFunctionReturn::Unproven) | None => self.result_slot(),
        }
    }

    /// The carrier holding the return address, preferring the ABI's own
    /// declaration and falling back to the machine's.
    ///
    /// Both name the same register when both exist, which the source enforces
    /// when it captures them; the fallback is what keeps this answerable for a
    /// function whose ABI was never recovered.
    pub fn return_address_carrier(&self) -> Option<CanonicalStorageId> {
        self.function_interface
            .as_ref()
            .and_then(|interface| interface.return_address_storage())
            .or_else(|| self.machine_roles.return_address_storage())
    }

    /// The carrier holding the stack pointer, resolved like
    /// [`Self::return_address_carrier`].
    pub fn stack_pointer_carrier(&self) -> Option<CanonicalStorageId> {
        self.function_interface
            .as_ref()
            .and_then(|interface| interface.stack_pointer_storage())
            .or_else(|| self.machine_roles.stack_pointer_storage())
    }

    /// Whether a call pushes its return address, moving the stack pointer;
    /// unstated, the cautious answer is yes.
    pub fn call_moves_stack_pointer(&self) -> bool {
        match self.return_mechanism() {
            Some(r2source::SourceReturnMechanism::Stacked { .. }) => true,
            None => self
                .machine_roles
                .call_pushes_return_address()
                .unwrap_or(true),
        }
    }

    pub const fn return_mechanism(&self) -> Option<r2source::SourceReturnMechanism> {
        match self.function_interface.as_ref() {
            Some(interface) => interface.return_mechanism(),
            None => None,
        }
    }

    pub fn register_storage(&self, name: &str) -> Option<CanonicalStorageId> {
        self.register_storages_by_name()
            .get(&name.trim().to_ascii_lowercase())
            .copied()
    }

    /// The name the architecture gives this storage, when it names it exactly.
    pub fn register_name(&self, storage: CanonicalStorageId) -> Option<String> {
        self.arch
            .as_ref()?
            .register_name(storage)
            .map(str::to_owned)
    }

    /// The registers a call in this body may leave changed; every one without a model.
    pub const fn call_clobbered_carriers(&self) -> &[CanonicalStorageId] {
        &self.call_clobbered_carriers
    }

    /// What the direct callee at `target` proves it leaves alone, where its
    /// body was read.
    pub(crate) fn callee_preserved(&self, target: u64) -> Option<&BTreeSet<CanonicalStorageId>> {
        self.callee_preserved.get(&target)
    }

    pub(crate) fn set_callee_preserved(
        &mut self,
        preserved: crate::function::CalleePreservedCarriers,
    ) {
        self.callee_preserved = preserved;
    }

    /// What the callee at `target` states, where its unproven result mints no call contract.
    pub(crate) fn callee_statement(&self, target: u64) -> Option<&CalleeStatement> {
        self.callee_statements.get(&target)
    }

    pub(crate) fn set_callee_statements(&mut self, statements: &BTreeMap<u64, CalleeStatement>) {
        self.callee_statements.clone_from(statements);
    }

    /// What a call does to `storage` under the calls' model; clobbered under none.
    pub fn call_effect_on(&self, storage: CanonicalStorageId) -> r2source::CallRegisterEffect {
        match self.calls() {
            Some(model) => model.effect_on(storage),
            None => r2source::CallRegisterEffect::Clobbered,
        }
    }

    pub fn call_preserves(&self, storage: CanonicalStorageId) -> bool {
        self.call_effect_on(storage) == r2source::CallRegisterEffect::Preserved
    }

    pub fn call_reserves(&self, storage: CanonicalStorageId) -> bool {
        self.call_effect_on(storage) == r2source::CallRegisterEffect::SystemReserved
    }

    pub fn call_clobbers(&self, storage: CanonicalStorageId) -> bool {
        self.call_effect_on(storage) == r2source::CallRegisterEffect::Clobbered
    }

    /// Whether a call leaves the frame carriers where they were, per the calls' model.
    pub fn call_preserved_carriers(&self) -> Option<SourceCallPreservedCarriers> {
        let effect = self.calls()?;
        let frame_pointer = self
            .function_interface
            .as_ref()
            .and_then(SourceFunctionInterface::frame_pointer_storage);
        Some(SourceCallPreservedCarriers::new(
            self.stack_pointer_carrier()
                .is_some_and(|storage| effect.preserves(storage)),
            frame_pointer.is_none_or(|storage| effect.preserves(storage)),
        ))
    }

    pub fn register_storages_by_name(&self) -> &BTreeMap<String, CanonicalStorageId> {
        static NONE: BTreeMap<String, CanonicalStorageId> = BTreeMap::new();
        self.arch
            .as_ref()
            .map_or(&NONE, |machine| machine.registers_by_name())
    }

    /// The registers the processor specification says hold a value on entry, with that value.
    pub fn tracked_entry_values(&self) -> &[(CanonicalStorageId, u64)] {
        self.arch
            .as_ref()
            .map_or(&[], |machine| machine.tracked_entry_values())
    }

    pub fn register_geometry_state(&self) -> MachineRegisterGeometryState {
        self.arch
            .as_ref()
            .map_or(MachineRegisterGeometryState::Unavailable, Arch::geometry)
    }

    /// Resolve one exact written storage without consulting register spellings.
    pub fn register_projection(
        &self,
        written_storage: CanonicalStorageId,
    ) -> Option<&RegisterProjection> {
        if written_storage.space != CanonicalStorageSpace::Register {
            return None;
        }
        let written = RegisterStorage {
            offset: written_storage.offset,
            size: written_storage.size,
        };
        let machine = self.arch.as_ref()?;
        machine.declared_projection(written).or_else(|| {
            self.observed_projections
                .binary_search_by_key(&written, |projection| projection.written)
                .ok()
                .map(|index| &self.observed_projections[index])
        })
    }

    /// Whether `lane` is the least significant bytes of `root` by the register
    /// geometry, so a slot naming the lane is a slot of the root's low bytes.
    pub(crate) fn is_low_lane_of(
        &self,
        lane: CanonicalStorageId,
        root: CanonicalStorageId,
    ) -> bool {
        let bound = |storage| match self.register_projection(storage)?.disposition {
            r2il::RegisterProjectionDisposition::Bound { carrier, slice } => Some((carrier, slice)),
            r2il::RegisterProjectionDisposition::Refused { .. } => None,
        };
        lane.size <= root.size
            && matches!(
                (bound(lane), bound(root)),
                (Some((a, lane)), Some((b, root))) if a == b && lane.lsb_bit_offset == root.lsb_bit_offset
            )
    }

    /// Every call site of the raw lifted input, by instruction.
    pub const fn raw_call_sites(&self) -> &BTreeMap<u64, SourceCallSiteIdentity> {
        &self.raw_call_sites
    }

    /// The call site lifted from `instruction`, if that instruction is one.
    pub fn raw_call_site_at(&self, instruction: u64) -> Option<SourceCallSiteIdentity> {
        self.raw_call_sites.get(&instruction).copied()
    }

    pub fn is_tail_call_site(&self, identity: SourceCallSiteIdentity) -> bool {
        self.tail_call_sites.contains(&identity)
    }

    pub(crate) fn set_callee_linkages(
        &mut self,
        callee_linkages: BTreeMap<SourceCallSiteIdentity, r2source::AdvisoryCalleeLinkage>,
    ) {
        self.callee_linkages = callee_linkages;
    }

    pub(crate) fn set_callee_names(
        &mut self,
        callee_names: BTreeMap<SourceCallSiteIdentity, String>,
    ) {
        self.callee_names = callee_names;
    }

    pub(crate) fn set_callee_library(
        &mut self,
        library: BTreeMap<u64, crate::interproc::FunctionSemanticSummary>,
    ) {
        self.callee_library = library;
    }

    pub(crate) fn set_reentering_callees(&mut self, reentering: BTreeSet<u64>) {
        self.reentering_callees = reentering;
    }

    /// Whether a call to `target` re-enters its caller at the caller's entry, by a runtime model.
    pub(crate) fn reenters_caller(&self, target: u64) -> bool {
        self.reentering_callees.contains(&target)
    }

    pub(crate) fn set_unstated_imports(&mut self, imports: BTreeMap<u64, crate::UnstatedImport>) {
        self.unstated_imports = imports;
    }

    /// Why the import at `target` states no interface, where it is one that states none.
    pub(crate) fn unstated_import(&self, target: u64) -> Option<crate::UnstatedImport> {
        self.unstated_imports.get(&target).copied()
    }

    /// The library model of the import at `target`, where the engine named one.
    pub(crate) fn callee_library(
        &self,
        target: u64,
    ) -> Option<&crate::interproc::FunctionSemanticSummary> {
        self.callee_library.get(&target)
    }

    /// Every import this body calls that has a library model, by entry.
    pub(crate) const fn callee_libraries(
        &self,
    ) -> &BTreeMap<u64, crate::interproc::FunctionSemanticSummary> {
        &self.callee_library
    }

    pub(crate) fn set_callee_argument_reach(
        &mut self,
        callee_argument_reach: BTreeMap<u64, BTreeMap<usize, crate::interproc::ArgumentReach>>,
    ) {
        self.callee_argument_reach = callee_argument_reach;
    }

    pub(crate) fn set_callee_writes(
        &mut self,
        writes: BTreeMap<u64, crate::call_reads::StackWrites>,
    ) {
        self.callee_writes = writes;
    }

    pub(crate) fn set_callee_lane_reads(&mut self, reads: crate::function::CalleeLaneReads) {
        self.callee_lane_reads = reads;
    }

    pub(crate) fn set_site_models(&mut self, sites: std::sync::Arc<crate::function::SiteModels>) {
        self.sites = sites;
    }

    /// What the call at `instruction` to `direct` runs under: its stated model, else `calls`.
    pub fn site_model(
        &self,
        instruction: Option<u64>,
        direct: Option<u64>,
    ) -> Option<&r2source::ConventionModel> {
        (self.sites.stated(instruction, direct)).or_else(|| self.calls())
    }

    /// The integer argument registers the call at `instruction` to `direct` hands, in the order
    /// the callee's own summary numbers its reach (D365); none where no model states them.
    pub fn site_integer_arguments(
        &self,
        instruction: Option<u64>,
        direct: Option<u64>,
    ) -> &[CanonicalStorageId] {
        self.site_model(instruction, direct)
            .map(|model| model.arguments(r2source::convention::SlotClass::Integer))
            .unwrap_or_default()
    }

    /// How far `target` reaches through what it is handed at `position`.
    pub fn callee_reach_at(
        &self,
        target: u64,
        position: usize,
    ) -> Option<&crate::interproc::ArgumentReach> {
        self.callee_argument_reach.get(&target)?.get(&position)
    }

    pub(crate) fn set_frame_saves(&mut self, saves: &[r2source::SourceFrameSave]) {
        self.frame_saves = saves.to_vec();
    }

    pub(crate) fn set_accepted_premises(&mut self, premises: BTreeSet<r2source::Premise>) {
        self.accepted_premises = premises;
    }

    /// The function's convention and its calls', where the capture holds them.
    pub const fn conventions(&self) -> Option<&r2source::Conventions> {
        self.conventions.as_ref()
    }

    /// The function's own convention: where its arguments and result lie.
    pub fn convention(&self) -> Option<&r2source::ConventionModel> {
        self.conventions.as_ref().map(|it| &*it.own)
    }

    /// What a call this function makes runs under, where no site states its callee's.
    pub fn calls(&self) -> Option<&r2source::ConventionModel> {
        self.conventions.as_ref().map(|it| &*it.calls)
    }

    /// Who owns the stack byte at an entry-relative offset: the model's rule, else growing down.
    pub fn stack_owner(&self, offset: i64) -> r2source::convention::StackOwner {
        self.convention().map_or(
            r2source::convention::StackOwner::growing_down(offset),
            |model| model.owner(offset),
        )
    }

    /// Whether the engine grants this premise to what it derives here.
    pub fn accepts(&self, premise: r2source::Premise) -> bool {
        self.accepted_premises.contains(&premise)
    }

    /// Where the call-frame information says the function saves each register
    /// it preserves, from the stack pointer on entry; sorted by offset.
    pub fn frame_saves(&self) -> &[r2source::SourceFrameSave] {
        &self.frame_saves
    }

    pub(crate) fn set_code_pointer_entries(&mut self, entries: BTreeMap<u64, u64>) {
        self.code_pointer_entries = entries;
    }

    pub(crate) fn set_code_pointer_tables(
        &mut self,
        tables: BTreeMap<u64, r2source::SourceCodePointerTable>,
    ) {
        self.code_pointer_tables = tables;
    }

    /// The table the capture fetched for the indirect transfer at this instruction.
    pub fn code_pointer_table_at(
        &self,
        instruction: u64,
    ) -> Option<&r2source::SourceCodePointerTable> {
        self.code_pointer_tables.get(&instruction)
    }

    /// The function the code pointer slot at this address names.
    pub fn code_pointer_entry(&self, address: u64) -> Option<u64> {
        self.code_pointer_entries.get(&address).copied()
    }

    /// Every captured code pointer slot and the function it names.
    pub fn code_pointer_entries(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.code_pointer_entries
            .iter()
            .map(|(address, target)| (*address, *target))
    }

    /// How far the callee at this address is proven to touch through each of
    /// its pointer arguments.
    pub fn callee_argument_reach(
        &self,
        address: u64,
    ) -> Option<&BTreeMap<usize, crate::interproc::ArgumentReach>> {
        self.callee_argument_reach.get(&address)
    }

    /// The name the source gave the site's callee, where it gave one.
    pub fn callee_name(&self, identity: SourceCallSiteIdentity) -> Option<&str> {
        self.callee_names.get(&identity).map(String::as_str)
    }

    pub(crate) fn set_slot_targets(&mut self, slots: BTreeMap<SourceCallSiteIdentity, u64>) {
        self.slot_targets = slots;
    }

    pub(crate) fn set_member_call_sites(&mut self, sites: BTreeSet<SourceCallSiteIdentity>) {
        self.member_call_sites = sites;
    }

    /// Whether the site's contract is a member's, minted from an earlier seal's `MemberCalls`.
    pub fn is_member_call_site(&self, identity: SourceCallSiteIdentity) -> bool {
        self.member_call_sites.contains(&identity)
    }

    /// The sealed import slot a call through memory reaches, where the source states one.
    pub(crate) fn slot_target(&self, identity: SourceCallSiteIdentity) -> Option<u64> {
        self.slot_targets.get(&identity).copied()
    }

    /// Who the site calls, as the source's symbol or relocation said; unknown where it said nothing.
    pub fn callee_linkage(
        &self,
        identity: SourceCallSiteIdentity,
    ) -> r2source::AdvisoryCalleeLinkage {
        self.callee_linkages
            .get(&identity)
            .copied()
            .unwrap_or(r2source::AdvisoryCalleeLinkage::Unknown)
    }

    pub const fn call_site_interfaces(
        &self,
    ) -> &BTreeMap<SourceCallSiteIdentity, SourceCallSiteInterface> {
        &self.call_site_interfaces
    }

    /// What the call at `instruction` may read (`CallReads`): the locations of its complete, fixed
    /// interface, else every location; none where the machine names no convention.
    pub fn call_reads(&self, instruction: Option<u64>) -> Option<crate::call_reads::CallReads> {
        let identity = instruction.and_then(|instruction| self.raw_call_site_at(instruction));
        let target = identity
            .map(SourceCallSiteIdentity::target)
            .filter(|target| target.space == CanonicalStorageSpace::Ram);
        // A direct callee writes the stack its entry states; a typed indirect call, its arguments.
        let writes = match target {
            Some(target) => self.callee_writes.get(&target.offset),
            None => Some(&ARGUMENT_AREA),
        };
        let interface = (identity.and_then(|identity| self.call_site_interface(identity)))
            .filter(|interface| interface.is_complete());
        // The site's own model, by the one lookup rename and the frame walk ask (D390).
        let model = self.site_model(instruction, target.map(|target| target.offset));
        if let Some(interface) = interface.filter(|interface| !interface.is_variadic()) {
            let reads = crate::call_reads::CallReads::exact(interface, model);
            return Some(reads.writing(writes));
        }
        // A printf's stack is its fixed parameters and the operands its own format counts (D409).
        let counted = (interface.zip(model))
            .zip(instruction.and_then(|at| self.format_tails.get(&at)))
            .and_then(|((interface, model), tail)| counted_stack(interface, model, tail));
        if let (Some(stack), Some(model)) = (counted, model) {
            let reads = crate::call_reads::CallReads::every_location(model).on_stack(stack);
            return Some(reads.writing(writes));
        }
        // A walked callee that mints no contract still states its reads where its arity is exact.
        let stated = target
            .and_then(|target| self.callee_statement(target.offset))
            .and_then(|statement| statement.reads.as_deref());
        // A walked callee's register effect bounds its result registers; any other reads them whole.
        let lanes = target.and_then(|target| self.callee_lane_reads.get(&target.offset));
        let reads = match stated {
            Some(read) => Some(crate::call_reads::CallReads::of_locations(
                read.iter().copied(),
                model,
            )),
            None => model
                .map(crate::call_reads::CallReads::every_location)
                .map(|reads| reads.reading_lanes(lanes)),
        };
        reads.map(|reads| reads.writing(writes))
    }

    pub fn call_site_interface(
        &self,
        identity: SourceCallSiteIdentity,
    ) -> Option<&SourceCallSiteInterface> {
        self.call_site_interfaces.get(&identity)
    }

    /// Retain literal contents from the exact source snapshot before semantic
    /// preparation. Duplicate addresses with different contents are omitted;
    /// ambiguity is not literal evidence.
    /// Bind the image's struct-typed data objects (D348). Two objects at one address bind neither.
    pub(crate) fn bind_data_structs(&mut self, image: &r2source::OwnedFunctionImage) {
        use r2source::SourceTypeKind;
        let Some(graph) = image.data_types() else {
            return;
        };
        let mut by_address = BTreeMap::new();
        let mut doubled = std::collections::BTreeSet::new();
        for object in image.data_symbols() {
            let Some(node) =
                (object.type_id()).and_then(|id| graph.types().get(usize::try_from(id).ok()?))
            else {
                continue;
            };
            let SourceTypeKind::Struct { .. } = node.kind() else {
                continue;
            };
            let size = node.size_bits() / 8;
            if size == 0 || !node.size_bits().is_multiple_of(8) {
                continue;
            }
            if by_address
                .insert(object.address(), (node.id(), size))
                .is_some()
            {
                doubled.insert(object.address());
            }
        }
        by_address.retain(|address, _| !doubled.contains(address));
        if !by_address.is_empty() {
            self.data_structs = Some(std::sync::Arc::new(DataStructs {
                graph: graph.clone(),
                by_address,
            }));
        }
    }

    pub fn data_structs(&self) -> Option<&DataStructs> {
        self.data_structs.as_deref()
    }

    /// Bind the read-only bytes the capture took at each address the body loads from.
    pub(crate) fn bind_read_only(&mut self, windows: &[(u64, Vec<u8>)]) {
        self.read_only = windows
            .iter()
            .map(|(address, bytes)| (*address, bytes.clone().into_boxed_slice()))
            .collect();
    }

    /// What a `size`-byte load at `address` reads, where the capture holds those bytes read-only
    /// and they fit a constant: one search, in the memory's byte order.
    pub fn read_only_bits(&self, address: u64, size: u32) -> Option<u64> {
        let (start, bytes) = self.read_only.range(..=address).next_back()?;
        let from = usize::try_from(address - start).ok()?;
        let window = bytes.get(from..from.checked_add(usize::try_from(size).ok()?)?)?;
        if window.len() > 8 {
            return None;
        }
        let ordered = window.iter().copied();
        let bits = match self.memory_model.default_endianness() {
            MachineMemoryEndianness::Little => ordered
                .rev()
                .fold(0u64, |bits, byte| (bits << 8) | u64::from(byte)),
            MachineMemoryEndianness::Big => {
                ordered.fold(0u64, |bits, byte| (bits << 8) | u64::from(byte))
            }
            _ => return None,
        };
        Some(bits)
    }

    pub(crate) fn bind_source_string_literals(&mut self, literals: &[(u64, String)]) {
        let mut ambiguous = BTreeSet::new();
        for (address, text) in literals {
            if self
                .source_string_literals
                .insert(*address, text.clone())
                .is_some_and(|previous| previous != *text)
            {
                ambiguous.insert(*address);
            }
        }
        for address in ambiguous {
            self.source_string_literals.remove(&address);
        }
    }

    /// Fold the format each call to a cited printf `...` passes in its own block, one forward pass
    /// per block, and keep what a read-only format consumes (D409). O(operations + calls log calls).
    pub(crate) fn bind_format_tails(&mut self, blocks: &[R2ILBlock], immutable: &[u64]) {
        let mut tails = BTreeMap::new();
        for block in blocks {
            let mut origins = BlockOrigins::default();
            for (at, op) in block.ops.iter().enumerate() {
                let tail = (op.is_call())
                    .then(|| block.instruction_of(at))
                    .flatten()
                    .and_then(|instruction| Some((instruction, self.format_register(instruction)?)))
                    .and_then(|(instruction, register)| {
                        let varnode = r2il::Varnode::register(register.offset, register.size);
                        let at = origins.of(&varnode)?.constant()?;
                        immutable.binary_search(&at).ok()?;
                        let text = self.source_string_literal(at)?;
                        let consumed = r2abi::format::printf_consumed_arguments(text).ok()?;
                        Some((instruction, consumed))
                    });
                tails.extend(tail);
                origins.step(op);
            }
        }
        self.format_tails = tails;
    }

    /// What the read-only format the call at `instruction` passes consumes, where its block folds it.
    pub(crate) fn format_tail(
        &self,
        instruction: u64,
    ) -> Option<&r2abi::format::PrintfConsumedArguments> {
        self.format_tails.get(&instruction)
    }

    /// The register a call at `instruction` passes a cited printf `...`'s format in: the
    /// declaration's format of a variadic site (a body-proven one is no citation). O(log sites).
    fn format_register(&self, instruction: u64) -> Option<CanonicalStorageId> {
        let interface = self.call_site_interface(self.raw_call_site_at(instruction)?)?;
        let index = match interface.format_parameter_rule()? {
            r2source::SourceFormatParameterRule::Radare2FormatString { parameter_index } => {
                parameter_index
            }
            r2source::SourceFormatParameterRule::BodyProvenFormatString { .. } => return None,
        };
        let argument = interface.arguments().get(usize::try_from(index).ok()?)?;
        match (interface.is_variadic(), argument.location()) {
            (true, SourceParameterLocation::Register(storage)) => Some(storage),
            _ => None,
        }
    }

    pub fn source_string_literal(&self, address: u64) -> Option<&str> {
        self.source_string_literals
            .get(&address)
            .map(String::as_str)
    }

    /// How many string literals the capture delivered. A refusal to read one
    /// means something different when the table is empty than when it is full.
    pub fn source_string_literal_count(&self) -> usize {
        self.source_string_literals.len()
    }
}

/// Every transfer in the raw lifted input that can be a call site, keyed by
/// the instruction it was lifted from, with the subset the source proved to be
/// a tail transfer.
///
/// A call or indirect call is a site by itself. A branch is one only where
/// the source correlated it with a tail transfer, and then only when the
/// lifted operation at that instruction is the terminal branch the identity
/// names. Two transfers lifted from one instruction leave that instruction
/// with no identity at all: nothing downstream could tell which one a fact
/// was recorded against.
fn collect_raw_call_site_identities(
    blocks: &[R2ILBlock],
    tail_call_identities: &[SourceCallSiteIdentity],
    terminal_blocks: &BTreeSet<u64>,
) -> (
    BTreeMap<u64, SourceCallSiteIdentity>,
    BTreeSet<SourceCallSiteIdentity>,
) {
    let authorized_tail_calls = tail_call_identities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut by_instruction: BTreeMap<u64, Option<SourceCallSiteIdentity>> = BTreeMap::new();
    let mut tails = BTreeSet::new();
    for block in blocks {
        for (op_index, op) in block.ops.iter().enumerate() {
            let Some(instruction) = block.instruction_of(op_index) else {
                continue;
            };
            let identity = match op {
                R2ILOp::Call { target } | R2ILOp::CallInd { target } => {
                    SourceCallSiteIdentity::new(
                        instruction,
                        CanonicalStorageId::from_varnode(target),
                    )
                }
                R2ILOp::Branch { target } if op_index + 1 == block.ops.len() => {
                    let identity = SourceCallSiteIdentity::new(
                        instruction,
                        CanonicalStorageId::from_varnode(target),
                    );
                    if !authorized_tail_calls.contains(&identity) {
                        continue;
                    }
                    tails.insert(identity);
                    identity
                }
                R2ILOp::BranchInd { target } if op_index + 1 == block.ops.len() => {
                    match terminal_indirect_loaded_slot(block, op_index) {
                        Some(slot) => {
                            let identity = SourceCallSiteIdentity::new(instruction, slot);
                            if !authorized_tail_calls.contains(&identity) {
                                continue;
                            }
                            tails.insert(identity);
                            identity
                        }
                        // The jump goes through a register and the source says
                        // this block has no successor, so control leaves the
                        // function here: it is a tail call through whatever the
                        // register holds. This rests wholly on the source's
                        // statement. A block whose transfer the source could
                        // not follow is not terminal (`transfer_unresolved`
                        // keeps it out of `terminal_blocks`), and the native
                        // capture marks every register jump its walk did not
                        // resolve, so no native capture reaches this arm: it
                        // serves only a source that states it followed the
                        // transfer out of the function. The arity of such a
                        // call is still unproven until tail transfers are
                        // proved from machine state.
                        None if terminal_blocks.contains(&block.addr) => {
                            let identity = SourceCallSiteIdentity::new(
                                instruction,
                                CanonicalStorageId::from_varnode(target),
                            );
                            r2il::refusal_evidence!(
                                "call-site-identity",
                                "terminal indirect transfer at {instruction:#x} in block \
                                 {:#x}, which the source declares has no successor, is a tail \
                                 call through {:?}",
                                block.addr,
                                identity.target()
                            );
                            tails.insert(identity);
                            identity
                        }
                        None => {
                            r2il::refusal_evidence!(
                                "call-site-identity",
                                "terminal indirect transfer at {instruction:#x} in block {:#x} \
                                 loads no slot and the source does not declare the block \
                                 terminal, so it names no call site",
                                block.addr
                            );
                            continue;
                        }
                    }
                }
                _ => continue,
            };
            match by_instruction.entry(instruction) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(identity));
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    r2il::refusal_evidence!(
                        "call-site-identity",
                        "instruction {instruction:#x} lifts to more than one transfer; none of them is a call site"
                    );
                    slot.insert(None);
                }
            }
        }
    }
    let by_instruction = by_instruction
        .into_iter()
        .filter_map(|(instruction, identity)| identity.map(|identity| (instruction, identity)))
        .collect::<BTreeMap<_, _>>();
    tails.retain(|identity| by_instruction.get(&identity.instruction()) == Some(identity));
    (by_instruction, tails)
}

/// The canonical RAM slot whose loaded value a terminal indirect branch reads.
///
/// This is one fact with two lifted representations. x86-64 may put the RAM
/// varnode directly on `BranchInd`, leaving it undefined in SSA. AArch64 loads
/// the slot through an exactly folded address and copies the result through a
/// register into the program counter. Reading the block's own origins forward
/// recognizes both without depending on a variable name or architecture.
pub fn terminal_indirect_loaded_slot(
    block: &R2ILBlock,
    branch_op_index: usize,
) -> Option<CanonicalStorageId> {
    if branch_op_index + 1 != block.ops.len() {
        return None;
    }
    let R2ILOp::BranchInd { .. } = block.ops.get(branch_op_index)? else {
        return None;
    };
    loaded_target_slot(block, branch_op_index)
}

/// The canonical RAM slot an indirect call or branch at `op_index` loads its target from, as the
/// block's own origins show it: the one reader of `call [slot]` and `jmp [slot]` (audit W8, D3).
pub fn loaded_target_slot(block: &R2ILBlock, op_index: usize) -> Option<CanonicalStorageId> {
    let (R2ILOp::CallInd { target } | R2ILOp::BranchInd { target }) = block.ops.get(op_index)?
    else {
        return None;
    };
    BlockOrigins::upto(block, op_index)
        .of(target)?
        .loaded_slot()
}

/// The stack a variadic call reads from its stack pointer: the fixed parameters and one promoted
/// pointer-wide slot per `tail` operand (C17 6.5.2.2p7); refusals in adr-call-boundary "D409 as built".
fn counted_stack(
    interface: &SourceCallSiteInterface,
    model: &r2source::ConventionModel,
    tail: &r2abi::format::PrintfConsumedArguments,
) -> Option<Vec<(i64, i64)>> {
    use r2source::convention::SlotClass;
    let callee = interface.exact_callee_interface()?;
    let integers = model.arguments(SlotClass::Integer);
    let wide = integers.first().is_some_and(|first| first.size == 8);
    let unclassed = tail.long_double || tail.gapped || tail.count > 64;
    if !wide || model.forms.variadic_on_stack || unclassed {
        return None;
    }
    let floats = model.arguments(SlotClass::Float);
    let fixed = (callee.parameters().iter()).map(|parameter| match parameter.location() {
        SourceParameterLocation::Register(storage)
            if floats
                .iter()
                .any(|float| crate::semantic::register_storages_overlap(*float, storage)) =>
        {
            Some(crate::place::ParamClass::Float(
                u8::try_from(storage.size).ok()?,
            ))
        }
        SourceParameterLocation::Register(storage) => Some(crate::place::ParamClass::Integer(
            u8::try_from(storage.size).ok()?,
        )),
        SourceParameterLocation::Stack { size_bytes, .. } => Some(
            crate::place::ParamClass::Integer(u8::try_from(size_bytes).ok()?),
        ),
    });
    let operands = (0..tail.count).map(|at| match (tail.floating >> at) & 1 {
        1 => Some(crate::place::ParamClass::Float(8)),
        _ => Some(crate::place::ParamClass::Integer(8)),
    });
    let classes = fixed.chain(operands).collect::<Option<Vec<_>>>()?;
    let placement = crate::place::place(model, &classes);
    let declared = callee
        .parameters()
        .iter()
        .map(|parameter| parameter.location());
    let placed_as_declared = placement
        .locations
        .iter()
        .copied()
        .take(callee.parameters().len());
    if !placement.is_whole() || !placed_as_declared.eq(declared) {
        return None;
    }
    let at_call = (placement.locations.into_iter()).map(|location| callee.at_call_site(location));
    let at_call = at_call.collect::<Option<Vec<_>>>()?;
    crate::call_reads::CallReads::of_locations(at_call.into_iter(), Some(model)).stack
}

#[cfg(test)]
mod tests {

    /// Every ABI question answered, for the cases that used to assert the
    /// single whole-model boolean.
    fn all_abi_questions_coherent(abi: &MachineAbiModel) -> bool {
        abi.return_boundary_is_coherent()
            && abi.argument_placement_is_coherent()
            && abi.frame_geometry_is_coherent()
            && abi.machine_carriers_are_coherent()
    }
    use super::*;
    use r2il::{
        AddressSpace, RegisterDef, RegisterProjectionDisposition, RegisterProjectionRefusal,
        Varnode,
    };

    fn register_storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    /// The context of an empty body under `arch`.
    fn context_of(arch: &ArchSpec) -> SourceMachineContext {
        SourceMachineContext::from_blocks(&[], Some(&crate::Arch::from(arch.clone())))
    }

    #[test]
    fn source_register_geometry_is_copied_without_downstream_reconstruction() {
        let eax = RegisterStorage { offset: 0, size: 4 };
        let rax = RegisterStorage { offset: 0, size: 8 };
        let mut arch = ArchSpec::new("x86-64");
        arch.add_register(RegisterDef::sub(" EAX ", 0, 4, "RAX"));
        arch.add_register(RegisterDef::new("RAX", 0, 8));

        let absent = context_of(&arch);
        assert!(absent.register_projection(register_storage(0, 4)).is_none());
        assert_eq!(
            absent.register_geometry_state(),
            MachineRegisterGeometryState::Unavailable
        );
        assert_eq!(
            absent.register_storage(" eax "),
            Some(register_storage(0, 4))
        );

        let mut invalid_empty = ArchSpec::new("invalid-empty-geometry");
        invalid_empty.add_register(RegisterDef::new("broken", 0, 0));
        let invalid_empty = context_of(&invalid_empty);
        assert_eq!(
            invalid_empty.register_geometry_state(),
            MachineRegisterGeometryState::Malformed
        );

        arch.register_projections = vec![
            RegisterProjection {
                written: eax,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: rax,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 32,
                    },
                },
            },
            RegisterProjection {
                written: rax,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: rax,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 64,
                    },
                },
            },
        ];
        let bound = context_of(&arch);
        assert_eq!(
            bound.register_geometry_state(),
            MachineRegisterGeometryState::Available
        );
        for projection in &arch.register_projections {
            let written = register_storage(projection.written.offset, projection.written.size);
            assert_eq!(bound.register_projection(written), Some(projection));
        }

        for projection in &mut arch.register_projections {
            projection.disposition = RegisterProjectionDisposition::Refused {
                reason: RegisterProjectionRefusal::MissingRegisterEndianness,
            };
        }
        let refused = context_of(&arch);
        assert_eq!(
            refused.register_geometry_state(),
            MachineRegisterGeometryState::Available
        );

        arch.register_projections[1].disposition = RegisterProjectionDisposition::Bound {
            carrier: rax,
            slice: r2il::RegisterBitSlice {
                lsb_bit_offset: 0,
                size_bits: 64,
            },
        };
        let malformed = context_of(&arch);
        assert_eq!(
            malformed.register_geometry_state(),
            MachineRegisterGeometryState::Malformed
        );
        assert_eq!(malformed.register_projection(register_storage(0, 4)), None);
    }

    #[test]
    fn source_register_geometry_caches_canonical_observed_lane_projections() {
        let q0 = RegisterStorage {
            offset: 0x5000,
            size: 16,
        };
        let s0 = RegisterStorage {
            offset: 0x5000,
            size: 4,
        };
        let q4 = RegisterStorage {
            offset: 0x5040,
            size: 16,
        };
        let b4 = RegisterStorage {
            offset: 0x5040,
            size: 1,
        };
        let mut arch = ArchSpec::new("aarch64-vector-lanes");
        for (name, storage) in [("q0", q0), ("s0", s0), ("q4", q4), ("b4", b4)] {
            arch.add_register(RegisterDef::new(name, storage.offset, storage.size));
        }
        arch.register_projections = vec![
            RegisterProjection {
                written: s0,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: q0,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 32,
                    },
                },
            },
            RegisterProjection {
                written: q0,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: q0,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 128,
                    },
                },
            },
            RegisterProjection {
                written: b4,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: q4,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 8,
                    },
                },
            },
            RegisterProjection {
                written: q4,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: q4,
                    slice: r2il::RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: 128,
                    },
                },
            },
        ];
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0x5004, 4),
            src: Varnode::constant(1, 4),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0x5041, 1),
            src: Varnode::constant(1, 1),
        });

        let context =
            SourceMachineContext::from_blocks(&[block], Some(&crate::Arch::from(arch.clone())));
        assert_eq!(
            context
                .register_projection(register_storage(0x5004, 4))
                .map(|projection| projection.disposition),
            Some(RegisterProjectionDisposition::Bound {
                carrier: q0,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 32,
                    size_bits: 32,
                },
            })
        );
        assert_eq!(
            context
                .register_projection(register_storage(0x5041, 1))
                .map(|projection| projection.disposition),
            Some(RegisterProjectionDisposition::Bound {
                carrier: q4,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 8,
                    size_bits: 8,
                },
            })
        );
    }

    /// The architecture's return registers name no result: under no model the result is
    /// unproven, never carried (S34).
    #[test]
    fn no_model_names_no_result_carrier() {
        let mut arch = ArchSpec::new("x");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("r0", 0, 8));
        arch.return_registers = vec![RegisterDef::new("r0", 0, 8)];
        let context = SourceMachineContext::from_blocks(&[], Some(&crate::Arch::from(arch)));
        assert_eq!(context.result_slot(), None);
        assert_eq!(context.return_value_carrier(), None);
        assert!(
            context
                .call_clobbered_carriers()
                .contains(&register_storage(0, 8))
        );
    }

    #[test]
    fn a_register_is_named_by_its_storage() {
        let mut arch = ArchSpec::new("AARCH64:LE:64:v8A");
        arch.addr_size = 8;
        arch.add_space(AddressSpace::ram(8));
        for (index, name) in ["x0", "x1", "x2"].into_iter().enumerate() {
            arch.add_register(RegisterDef::new(name, index as u64 * 8, 8));
        }
        let slots = r2source::convention::testing::model(r2source::ConventionId::Aapcs64)
            .arguments(
                r2source::convention::SlotClass::Integer,
                [
                    register_storage(0, 8),
                    register_storage(8, 8),
                    register_storage(16, 8),
                ],
            )
            .result(
                r2source::convention::SlotClass::Integer,
                register_storage(0, 8),
            )
            .conventions();

        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            None,
            SourceMachineRoles::default(),
            Some(slots),
            Vec::new(),
        );

        assert_eq!(
            context.register_name(register_storage(8, 8)).as_deref(),
            Some("x1")
        );
    }

    #[test]
    fn function_interface_rejects_overlapping_parameter_aliases() {
        assert_eq!(
            SourceFunctionInterface::new(
                b"overlapping-register-interface".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [
                    SourceAbiParameterSpec::new(
                        0,
                        register_storage(0, 8),
                        r2source::SourceSlot::integer(0)
                    ),
                    SourceAbiParameterSpec::new(
                        1,
                        register_storage(4, 4),
                        r2source::SourceSlot::integer(1)
                    ),
                ],
                SourceFunctionReturn::Void,
                [],
            ),
            Err(SourceFunctionInterfaceError::OverlappingRegisterStorages)
        );
    }

    #[test]
    fn exact_function_interface_retains_local_and_parameter_home_roles() {
        let parameter_storage = register_storage(0, 8);
        let base_storage = register_storage(64, 8);
        let interface = SourceFunctionInterface::new_exact(
            b"exact-stack-slot-roles".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [SourceAbiParameterSpec::new(
                0,
                parameter_storage,
                r2source::SourceSlot::integer(0),
            )],
            SourceFunctionReturn::Void,
            [
                SourceStackSlotSpec::new_local(
                    StackAddressBase::FramePointer,
                    base_storage,
                    -16,
                    8,
                ),
                SourceStackSlotSpec::new_parameter_home(
                    StackAddressBase::FramePointer,
                    base_storage,
                    -8,
                    8,
                    0,
                    parameter_storage,
                ),
            ],
        )
        .expect("classified stack-slot roles are exact");

        assert!(interface.stack_slot_roles_complete());
        assert_eq!(
            interface.stack_slots()[0].role(),
            SourceStackSlotRole::Local
        );
        assert_eq!(
            interface.stack_slots()[1].role(),
            SourceStackSlotRole::ParameterHome {
                parameter_index: 0,
                home_storage: parameter_storage,
            }
        );
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let artifact =
            crate::SsaArtifact::for_decompile_with_interface(&[block], None, interface.clone())
                .expect("SSA artifact retains the exact source interface");
        assert_eq!(
            artifact.machine_context().function_interface(),
            Some(&interface)
        );

        let compatibility = SourceFunctionInterface::new(
            b"compatibility-stack-slot".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [SourceAbiParameterSpec::new(
                0,
                parameter_storage,
                r2source::SourceSlot::integer(0),
            )],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new(
                StackAddressBase::FramePointer,
                base_storage,
                -8,
                8,
            )],
        )
        .expect("unclassified compatibility resource remains representable");
        assert!(!compatibility.stack_slot_roles_complete());
        assert_eq!(
            compatibility.stack_slots()[0].role(),
            SourceStackSlotRole::UnclassifiedResource
        );
    }

    #[test]
    fn stack_pointer_binding_is_explicit_disjoint_and_matches_stack_resources() {
        let parameter = register_storage(0, 8);
        let result = register_storage(8, 8);
        let stack_pointer = register_storage(64, 8);
        let frame_pointer = register_storage(72, 8);
        let return_address = register_storage(80, 8);
        let unbound = |slots| {
            SourceFunctionInterface::new_exact(
                b"typed-stack-pointer".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [SourceAbiParameterSpec::new(
                    0,
                    parameter,
                    r2source::SourceSlot::integer(0),
                )],
                SourceFunctionReturn::Register { storage: result },
                slots,
            )
        };
        let build = |slots| {
            unbound(slots)
                .and_then(|interface| interface.with_return_address_storage(return_address))
        };

        assert_eq!(
            unbound(Vec::new())
                .and_then(|interface| interface.with_return_address_storage(parameter)),
            Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage)
        );
        assert_eq!(
            unbound(Vec::new()).and_then(|interface| interface.with_return_address_storage(result)),
            Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage)
        );
        assert_eq!(
            unbound(vec![SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )])
            .and_then(|interface| interface.with_return_address_storage(frame_pointer)),
            Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage)
        );
        assert_eq!(
            unbound(vec![SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                stack_pointer,
                0,
                8,
            )])
            .and_then(|interface| interface.with_return_address_storage(stack_pointer)),
            Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage)
        );

        let slotless = build(Vec::new())
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .expect("slotless interfaces still carry exit machine state");
        assert_eq!(slotless.stack_pointer_storage(), Some(stack_pointer));

        let frame_only = build(vec![SourceStackSlotSpec::new_local(
            StackAddressBase::FramePointer,
            frame_pointer,
            -8,
            8,
        )])
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("frame-pointer resources are disjoint from the stack pointer");
        assert_eq!(frame_only.stack_pointer_storage(), Some(stack_pointer));

        let mixed = build(vec![
            SourceStackSlotSpec::new_local(StackAddressBase::FramePointer, frame_pointer, -8, 8),
            SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, stack_pointer, 0, 8),
        ])
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("mixed bases retain the exact stack-pointer carrier");
        assert_eq!(mixed.stack_pointer_storage(), Some(stack_pointer));

        assert_eq!(
            build(vec![SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                stack_pointer,
                0,
                8,
            )])
            .and_then(|interface| {
                interface.with_stack_pointer_storage(register_storage(88, 8))
            }),
            Err(SourceFunctionInterfaceError::InvalidStackPointerStorage)
        );
        assert_eq!(
            build(Vec::new()).and_then(|interface| interface.with_stack_pointer_storage(parameter)),
            Err(SourceFunctionInterfaceError::InvalidStackPointerStorage)
        );
        assert_eq!(
            build(vec![SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )])
            .and_then(|interface| interface.with_stack_pointer_storage(frame_pointer)),
            Err(SourceFunctionInterfaceError::InvalidStackPointerStorage)
        );
    }

    #[test]
    fn exact_machine_interface_requires_declared_full_width_ra_and_sp() {
        let stack_pointer = register_storage(64, 8);
        let return_address = register_storage(80, 8);
        let make = || {
            SourceFunctionInterface::new_exact(
                b"exact-machine-roles".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [],
                SourceFunctionReturn::Void,
                [],
            )
            .expect("exact interface")
        };
        let mut arch = ArchSpec::new("exact-machine-roles");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("sp", stack_pointer.offset, 8));
        arch.add_register(RegisterDef::new("lr", return_address.offset, 8));

        let without_roles = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(make()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!without_roles.abi_model().machine_carriers_are_coherent());

        let return_only = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                make()
                    .with_return_address_storage(return_address)
                    .expect("return-address role"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!return_only.abi_model().machine_carriers_are_coherent());

        let complete = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                make()
                    .with_return_address_storage(return_address)
                    .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
                    .expect("exact machine roles"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(complete.abi_model()));

        let compatibility = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                SourceFunctionInterface::new(
                    b"compatibility-machine-roles".to_vec(),
                    r2source::ConventionId::SysVAmd64,
                    [],
                    SourceFunctionReturn::Void,
                    [],
                )
                .and_then(|interface| interface.with_return_address_storage(return_address))
                .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
                .expect("compatibility interface remains representable for refusal diagnostics"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        // A plain interface names its return-address and stack-pointer
        // carriers truthfully, and it declares no stack slots at all, so there
        // is no frame geometry for it to be wrong about either.
        assert!(all_abi_questions_coherent(compatibility.abi_model()));

        let narrow_stack_pointer = register_storage(96, 4);
        arch.add_register(RegisterDef::new("narrow_sp", 96, 4));
        let narrow = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                make()
                    .with_return_address_storage(return_address)
                    .and_then(|interface| {
                        interface.with_stack_pointer_storage(narrow_stack_pointer)
                    })
                    .expect("standalone binding is architecture-independent"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!narrow.abi_model().machine_carriers_are_coherent());

        let subregister_stack_pointer = register_storage(104, 8);
        arch.add_register(RegisterDef::sub("sp_alias", 104, 8, "missing_sp_parent"));
        let subregister_sp = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                make()
                    .with_return_address_storage(return_address)
                    .and_then(|interface| {
                        interface.with_stack_pointer_storage(subregister_stack_pointer)
                    })
                    .expect("standalone binding cannot inspect ArchSpec parentage"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!subregister_sp.abi_model().machine_carriers_are_coherent());

        let subregister_return_address = register_storage(112, 8);
        arch.add_register(RegisterDef::sub("lr_alias", 112, 8, "missing_lr_parent"));
        let subregister_ra = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(
                make()
                    .with_return_address_storage(subregister_return_address)
                    .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
                    .expect("standalone binding cannot inspect ArchSpec parentage"),
            ),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!subregister_ra.abi_model().machine_carriers_are_coherent());
    }

    #[test]
    fn exact_stacked_return_requires_matching_registers_and_byte_ram() {
        let stack_pointer = register_storage(64, 8);
        let return_address = register_storage(80, 8);
        let make = || {
            SourceFunctionInterface::new_exact(
                b"exact-stacked-return".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [],
                SourceFunctionReturn::Void,
                [],
            )
            .and_then(|interface| interface.with_return_address_storage(return_address))
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .expect("exact machine roles")
        };
        let exact = make()
            .with_exact_stacked_return(0, 8, 8, 8)
            .expect("canonical stacked return");
        let mut arch = ArchSpec::new("exact-stacked-return");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("source-ra", return_address.offset, 8));
        arch.add_register(RegisterDef::new("source-sp", stack_pointer.offset, 8));
        arch.add_space(AddressSpace::ram(8));

        let coherent = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(exact.clone()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(coherent.abi_model()));
        assert_eq!(coherent.return_mechanism(), exact.return_mechanism());

        let absent = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(make()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(absent.abi_model()));
        assert_eq!(absent.return_mechanism(), None);

        let mut subregister = arch.clone();
        subregister.registers.clear();
        subregister.add_register(RegisterDef::sub(
            "source-ra-alias",
            return_address.offset,
            8,
            "untrusted-parent",
        ));
        subregister.add_register(RegisterDef::new("source-sp", stack_pointer.offset, 8));
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(subregister.clone())),
            Some(exact.clone()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!context.abi_model().machine_carriers_are_coherent());

        let mut wrong_machine_width = arch.clone();
        wrong_machine_width.addr_size = 4;
        wrong_machine_width.spaces.clear();
        wrong_machine_width.add_space(AddressSpace::ram(4));
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(wrong_machine_width.clone())),
            Some(exact.clone()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!context.abi_model().machine_carriers_are_coherent());

        let mut word_addressed = arch.clone();
        word_addressed.spaces[0].word_size = 2;
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(word_addressed.clone())),
            Some(exact.clone()),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!context.abi_model().machine_carriers_are_coherent());

        let mut wrong_ram_width = arch;
        wrong_ram_width.spaces[0].addr_size = 4;
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(wrong_ram_width.clone())),
            Some(exact),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!context.abi_model().machine_carriers_are_coherent());
    }

    #[test]
    fn exact_machine_interface_requires_top_level_address_width_frame_pointer() {
        let stack_pointer = register_storage(64, 8);
        let frame_pointer = register_storage(72, 8);
        let return_address = register_storage(80, 8);
        let make_explicit = |frame_pointer| {
            SourceFunctionInterface::new_exact(
                b"exact-machine-frame-pointer".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [],
                SourceFunctionReturn::Void,
                [],
            )
            .and_then(|interface| interface.with_return_address_storage(return_address))
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .and_then(|interface| interface.with_frame_pointer_storage(frame_pointer))
            .expect("exact disjoint frame carriers")
        };
        let make_slot_derived = |frame_pointer, stack_pointer, return_address| {
            SourceFunctionInterface::new_exact(
                b"slot-derived-machine-frame-pointer".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [],
                SourceFunctionReturn::Void,
                [SourceStackSlotSpec::new_local(
                    StackAddressBase::FramePointer,
                    frame_pointer,
                    -8,
                    8,
                )],
            )
            .and_then(|interface| interface.with_return_address_storage(return_address))
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .expect("exact slot-derived frame carriers")
        };
        let mut arch = ArchSpec::new("exact-machine-frame-pointer");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("sp", stack_pointer.offset, 8));
        arch.add_register(RegisterDef::new("fp", frame_pointer.offset, 8));
        arch.add_register(RegisterDef::new("lr", return_address.offset, 8));

        let coherent = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(make_explicit(frame_pointer)),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(coherent.abi_model()));
        assert_eq!(
            coherent.abi_model().frame_pointer_storage(),
            Some(frame_pointer)
        );

        let slot_derived = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(make_slot_derived(
                frame_pointer,
                stack_pointer,
                return_address,
            )),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(slot_derived.abi_model()));
        assert_eq!(
            slot_derived.abi_model().frame_pointer_storage(),
            Some(frame_pointer)
        );

        let absent = SourceFunctionInterface::new_exact(
            b"absent-machine-frame-pointer".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("frame-pointer absence remains representable");
        let absent = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(absent),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(all_abi_questions_coherent(absent.abi_model()));
        assert_eq!(absent.abi_model().frame_pointer_storage(), None);

        let narrow_stack_pointer = register_storage(88, 4);
        let narrow_frame_pointer = register_storage(92, 4);
        let narrow_return_address = register_storage(96, 4);
        arch.add_register(RegisterDef::new(
            "narrow_fp",
            narrow_frame_pointer.offset,
            narrow_frame_pointer.size,
        ));
        arch.add_register(RegisterDef::new(
            "narrow_sp",
            narrow_stack_pointer.offset,
            narrow_stack_pointer.size,
        ));
        arch.add_register(RegisterDef::new(
            "narrow_lr",
            narrow_return_address.offset,
            narrow_return_address.size,
        ));
        let narrow_interface = SourceFunctionInterface::new_exact(
            b"narrow-machine-frame-pointer".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                narrow_frame_pointer,
                -8,
                4,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(narrow_return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(narrow_stack_pointer))
        .expect("source-width-coherent narrow carriers remain representable");
        let narrow = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(narrow_interface),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!narrow.abi_model().machine_carriers_are_coherent());
        assert!(!narrow.abi_model().frame_geometry_is_coherent());

        let subregister_frame_pointer = register_storage(104, 8);
        arch.add_register(RegisterDef::sub(
            "fp_alias",
            subregister_frame_pointer.offset,
            subregister_frame_pointer.size,
            "missing_fp_parent",
        ));
        let subregister = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(make_slot_derived(
                subregister_frame_pointer,
                stack_pointer,
                return_address,
            )),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(!subregister.abi_model().machine_carriers_are_coherent());
        assert!(!subregister.abi_model().frame_geometry_is_coherent());

        assert!(!is_exact_top_level_address_register(
            &crate::Arch::from(arch.clone()),
            CanonicalStorageId {
                space: CanonicalStorageSpace::Ram,
                offset: frame_pointer.offset,
                size: frame_pointer.size,
            },
            8,
        ));

        let overlapping = SourceFunctionInterface::new_exact(
            b"overlapping-machine-frame-pointer".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [SourceAbiParameterSpec::new(
                0,
                frame_pointer,
                r2source::SourceSlot::integer(0),
            )],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("representable overlapping source carrier");
        let overlapping = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(overlapping),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        // The frame-pointer slots name a base the interface cannot resolve to
        // a carrier, so the frame's geometry is unknown. Parameter 0 still
        // arrives in a real register, which is a different question.
        assert!(!overlapping.abi_model().frame_geometry_is_coherent());
    }

    #[test]
    fn exact_function_interface_rejects_malformed_parameter_homes() {
        let parameter_storage = register_storage(0, 8);
        let base_storage = register_storage(64, 8);
        let build = |slots| {
            SourceFunctionInterface::new_exact(
                b"malformed-stack-slot-role".to_vec(),
                r2source::ConventionId::SysVAmd64,
                [SourceAbiParameterSpec::new(
                    0,
                    parameter_storage,
                    r2source::SourceSlot::integer(0),
                )],
                SourceFunctionReturn::Void,
                slots,
            )
        };

        assert_eq!(
            build(vec![SourceStackSlotSpec::new(
                StackAddressBase::FramePointer,
                base_storage,
                -8,
                8,
            )]),
            Err(SourceFunctionInterfaceError::InvalidStackSlotRole)
        );
        assert_eq!(
            build(vec![SourceStackSlotSpec::new_parameter_home(
                StackAddressBase::FramePointer,
                base_storage,
                -8,
                8,
                1,
                parameter_storage,
            )]),
            Err(SourceFunctionInterfaceError::InvalidStackSlotRole)
        );
        assert_eq!(
            build(vec![SourceStackSlotSpec::new_parameter_home(
                StackAddressBase::FramePointer,
                base_storage,
                -8,
                8,
                0,
                register_storage(8, 8),
            )]),
            Err(SourceFunctionInterfaceError::InvalidStackSlotRole)
        );
        assert_eq!(
            build(vec![
                SourceStackSlotSpec::new_parameter_home(
                    StackAddressBase::FramePointer,
                    base_storage,
                    -8,
                    8,
                    0,
                    parameter_storage,
                ),
                SourceStackSlotSpec::new_parameter_home(
                    StackAddressBase::StackPointer,
                    register_storage(72, 8),
                    -8,
                    8,
                    0,
                    parameter_storage,
                ),
            ]),
            Err(SourceFunctionInterfaceError::InvalidStackSlotRole)
        );
    }

    fn demo_struct_type_graph() -> SourceTypeGraph {
        let members = (0..14).map(|index| {
            SourceAggregateMember::new(
                index,
                1,
                u64::from(index) * 32,
                32,
                format!("member_{index}"),
            )
        });
        SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::Struct { aggregate_id: 0 }, 56 * 8, 32),
                SourceType::new(1, SourceTypeKind::SignedInteger, 32, 32),
                SourceType::new(
                    2,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
            ],
            [SourceAggregateLayout::new(
                0,
                0,
                56 * 8,
                32,
                "DemoStruct",
                members,
            )],
        )
        .expect("valid exact DemoStruct graph")
    }

    #[test]
    fn function_interface_retains_exact_logical_type_graph() {
        // An `int` aligned to two bytes is m68k's; one aligned to eight, in
        // four bytes, is no C object anywhere.
        assert!(
            SourceTypeGraph::new(
                [SourceType::new(0, SourceTypeKind::SignedInteger, 32, 16)],
                [],
            )
            .is_ok()
        );
        assert_eq!(
            SourceTypeGraph::new(
                [SourceType::new(0, SourceTypeKind::SignedInteger, 32, 64)],
                [],
            ),
            Err(SourceTypeGraphError::InvalidType)
        );
        let pointer32 = SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::Struct { aggregate_id: 0 }, 32, 32),
                SourceType::new(1, SourceTypeKind::SignedInteger, 32, 32),
                SourceType::new(
                    2,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    32,
                    32,
                ),
            ],
            [SourceAggregateLayout::new(
                0,
                0,
                32,
                32,
                "OneField",
                [SourceAggregateMember::new(0, 1, 0, 32, "value")],
            )],
        )
        .expect("valid 32-bit pointer graph");
        assert!(pointer32.validates_pointer_width(32));
        assert!(!pointer32.validates_pointer_width(64));
        let parameters = [
            SourceAbiParameterSpec::new(
                0,
                register_storage(0, 8),
                r2source::SourceSlot::integer(0),
            ),
            SourceAbiParameterSpec::new(
                1,
                register_storage(8, 8),
                r2source::SourceSlot::integer(1),
            ),
            SourceAbiParameterSpec::new(
                2,
                register_storage(16, 8),
                r2source::SourceSlot::integer(2),
            ),
        ];
        let low_i32 = SourceCarrierProjection::new(SourceCarrierKind::LowBits, 0, 32);
        let interface = SourceFunctionInterface::new_with_logical_types(
            b"exact-type-layout".to_vec(),
            r2source::ConventionId::SysVAmd64,
            parameters,
            SourceFunctionReturn::Register {
                storage: register_storage(24, 8),
            },
            [],
            [
                Some(SourceLogicalValue::new(
                    2,
                    SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 64),
                )),
                Some(SourceLogicalValue::new(1, low_i32)),
                Some(SourceLogicalValue::new(1, low_i32)),
            ],
            Some(SourceLogicalValue::new(1, low_i32)),
            Some(demo_struct_type_graph()),
        )
        .expect("valid exact logical interface");

        assert_eq!(
            interface.schema_version(),
            SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION
        );
        assert_eq!(
            interface
                .parameter_logical_value(0)
                .expect("placed")
                .type_id(),
            2
        );
        assert_eq!(
            interface
                .parameter_logical_value(1)
                .expect("placed")
                .carrier()
                .kind(),
            SourceCarrierKind::LowBits
        );
        let graph = interface.type_graph().expect("retained exact graph");
        assert_eq!(graph.schema_version(), SOURCE_TYPE_GRAPH_SCHEMA_VERSION);
        assert_eq!(graph.types().len(), 3);
        assert_eq!(graph.aggregates()[0].name(), "DemoStruct");
        assert_eq!(graph.aggregates()[0].members()[2].offset_bits(), 8 * 8);
        assert_eq!(graph.aggregates()[0].members()[13].offset_bits(), 52 * 8);

        let invalid = SourceFunctionInterface::new_with_logical_types(
            b"exact-type-layout".to_vec(),
            r2source::ConventionId::SysVAmd64,
            parameters,
            SourceFunctionReturn::Register {
                storage: register_storage(24, 8),
            },
            [],
            [
                Some(SourceLogicalValue::new(
                    2,
                    SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 64),
                )),
                Some(SourceLogicalValue::new(
                    1,
                    SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 32),
                )),
                Some(SourceLogicalValue::new(1, low_i32)),
            ],
            Some(SourceLogicalValue::new(1, low_i32)),
            Some(demo_struct_type_graph()),
        );
        assert!(matches!(
            invalid,
            Err(SourceFunctionInterfaceError::InvalidLogicalTypes { .. })
        ));
    }

    #[test]
    fn function_interface_accepts_exact_unsigned_byte_pointee() {
        let graph = SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::UnsignedInteger, 8, 8),
                SourceType::new(
                    1,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
                SourceType::new(2, SourceTypeKind::UnsignedInteger, 64, 64),
            ],
            [],
        )
        .expect("unsigned-byte pointer graph");
        let full64 = SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 64);
        let interface = SourceFunctionInterface::new_exact_with_logical_types(
            b"fnv-u8-pointer-revision".to_vec(),
            r2source::ConventionId::Aapcs64,
            [
                SourceAbiParameterSpec::new(
                    0,
                    register_storage(0, 8),
                    r2source::SourceSlot::integer(0),
                ),
                SourceAbiParameterSpec::new(
                    1,
                    register_storage(8, 8),
                    r2source::SourceSlot::integer(1),
                ),
            ],
            SourceFunctionReturn::Register {
                storage: register_storage(0, 8),
            },
            [],
            [
                Some(SourceLogicalValue::new(1, full64)),
                Some(SourceLogicalValue::new(2, full64)),
            ],
            Some(SourceLogicalValue::new(2, full64)),
            Some(graph),
        )
        .expect("exact FNV logical interface");

        let graph = interface.type_graph().expect("logical graph");
        assert_eq!(
            graph.types()[1].kind(),
            SourceTypeKind::Pointer {
                target_type_id: 0,
                const_target: false
            }
        );
        assert_eq!(graph.types()[0].kind(), SourceTypeKind::UnsignedInteger);
    }

    #[test]
    fn source_type_graph_accepts_pointer_to_pointer() {
        let graph = SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::SignedInteger, 8, 8),
                SourceType::new(
                    1,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
                SourceType::new(
                    2,
                    SourceTypeKind::Pointer {
                        target_type_id: 1,
                        const_target: false,
                    },
                    64,
                    64,
                ),
            ],
            [],
        )
        .expect("char ** is a well formed source type");
        assert_eq!(
            graph.types()[2].kind(),
            SourceTypeKind::Pointer {
                target_type_id: 1,
                const_target: false
            }
        );
        assert!(graph.validates_pointer_width(64));
    }

    #[test]
    fn source_type_graph_rejects_pointer_to_absent_target() {
        assert_eq!(
            SourceTypeGraph::new(
                [SourceType::new(
                    0,
                    SourceTypeKind::Pointer {
                        target_type_id: 1,
                        const_target: false
                    },
                    64,
                    64,
                )],
                [],
            ),
            Err(SourceTypeGraphError::InvalidType)
        );
    }

    #[test]
    fn callsite_interface_rejects_bad_order_and_overlap() {
        let identity = SourceCallSiteIdentity::new(
            0x1000,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Ram,
                offset: 0x2000,
                size: 8,
            },
        );
        assert_eq!(
            SourceCallSiteInterface::new(
                b"call-revision".to_vec(),
                identity,
                true,
                r2source::ConventionId::SysVAmd64,
                [SourceCallArgumentSpec::new(1, register_storage(0, 8))],
                false,
                SourceCallResult::Void,
            ),
            Err(SourceCallSiteInterfaceError::InvalidArgumentOrder)
        );
        assert_eq!(
            SourceCallSiteInterface::new(
                b"call-revision".to_vec(),
                identity,
                true,
                r2source::ConventionId::SysVAmd64,
                [
                    SourceCallArgumentSpec::new(0, register_storage(0, 8)),
                    SourceCallArgumentSpec::new(1, register_storage(4, 8)),
                ],
                false,
                SourceCallResult::Void,
            ),
            Err(SourceCallSiteInterfaceError::OverlappingRegisterStorages)
        );
    }

    #[test]
    fn raw_call_sites_are_keyed_by_the_instruction_they_were_lifted_from() {
        let low_target = Varnode::ram(0x3000, 8);
        let high_target = Varnode::ram(0x4000, 8);
        let indirect_target = Varnode::register(0x18, 8);
        let mut high = R2ILBlock::new(0x2000, 4);
        high.push(R2ILOp::Call {
            target: high_target.clone(),
        });
        high.stamp_instruction(0, 0x2000);
        high.push(R2ILOp::CallInd {
            target: indirect_target.clone(),
        });
        high.stamp_instruction(1, 0x2002);
        let mut low = R2ILBlock::new(0x1000, 4);
        low.push(R2ILOp::Call {
            target: low_target.clone(),
        });
        low.stamp_instruction(0, 0x1000);
        // A transfer nothing lifted from an instruction is nobody's call site.
        low.push(R2ILOp::Call {
            target: low_target.clone(),
        });

        let context = SourceMachineContext::from_blocks(&[high, low], None);
        assert_eq!(
            context.raw_call_site_at(0x1000),
            Some(SourceCallSiteIdentity::new(
                0x1000,
                CanonicalStorageId::from_varnode(&low_target),
            ))
        );
        assert_eq!(
            context.raw_call_site_at(0x2000),
            Some(SourceCallSiteIdentity::new(
                0x2000,
                CanonicalStorageId::from_varnode(&high_target),
            ))
        );
        assert_eq!(
            context.raw_call_site_at(0x2002),
            Some(SourceCallSiteIdentity::new(
                0x2002,
                CanonicalStorageId::from_varnode(&indirect_target),
            ))
        );
        assert_eq!(context.raw_call_sites().len(), 3);
    }

    #[test]
    fn an_instruction_lifting_to_two_transfers_is_no_call_site() {
        let target = Varnode::ram(0x3000, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Call {
            target: target.clone(),
        });
        block.stamp_instruction(0, 0x1000);
        block.push(R2ILOp::Call { target });
        block.stamp_instruction(1, 0x1000);
        let context = SourceMachineContext::from_blocks(&[block], None);
        assert_eq!(context.raw_call_site_at(0x1000), None);
    }

    #[test]
    fn only_an_exact_source_correlated_branch_is_a_tail_call_site() {
        let target = Varnode::constant(0x5000, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Branch {
            target: target.clone(),
        });
        block.stamp_instruction(0, 0x1000);
        let identity =
            SourceCallSiteIdentity::new(0x1000, CanonicalStorageId::from_varnode(&target));
        let context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            &[block.clone()],
            None,
            None,
            SourceMachineRoles::default(),
            None,
            Vec::new(),
            vec![identity],
        );
        assert_eq!(context.raw_call_site_at(0x1000), Some(identity));
        assert!(context.is_tail_call_site(identity));

        let wrong_target = SourceCallSiteIdentity::new(
            0x1000,
            CanonicalStorageId {
                offset: 0x5004,
                ..identity.target()
            },
        );
        let unproved = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            &[block],
            None,
            None,
            SourceMachineRoles::default(),
            None,
            Vec::new(),
            vec![wrong_target],
        );
        assert!(unproved.raw_call_sites().is_empty());
        assert!(!unproved.is_tail_call_site(wrong_target));
    }

    #[test]
    fn interface_registers_missing_from_architecture_are_incoherent() {
        let interface = SourceFunctionInterface::new(
            b"missing-register-interface".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [SourceAbiParameterSpec::new(
                0,
                register_storage(0, 8),
                r2source::SourceSlot::integer(0),
            )],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("valid standalone interface");
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            None,
            Some(interface),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );
        assert!(context.abi_model().is_available());
        assert!(!all_abi_questions_coherent(context.abi_model()));
    }

    #[test]
    fn stack_base_storage_missing_from_architecture_is_incoherent() {
        let interface = SourceFunctionInterface::new(
            b"missing-stack-base-interface".to_vec(),
            r2source::ConventionId::SysVAmd64,
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new(
                StackAddressBase::StackPointer,
                register_storage(52, 4),
                -16,
                4,
            )],
        )
        .expect("valid standalone stack interface");
        let mut arch = ArchSpec::new("stack-base-mismatch-test");
        arch.addr_size = 4;
        arch.add_register(RegisterDef::new("r0", 0, 4));
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(interface),
            SourceMachineRoles::default(),
            None,
            Vec::new(),
        );

        assert!(context.abi_model().is_available());
        assert!(!context.abi_model().frame_geometry_is_coherent());
    }

    #[test]
    fn missing_architecture_keeps_typed_sites_but_marks_model_unavailable() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x10, 4),
            space: SpaceId::Custom(7),
            addr: Varnode::register(0, 8),
        });
        let context = SourceMachineContext::from_blocks(&[block], None);

        assert!(!context.memory_model().is_available());
        assert!(!context.memory_model().is_coherent());
    }

    #[test]
    fn architecture_snapshot_applies_per_space_endianness() {
        let mut arch = ArchSpec::new("test-be");
        arch.addr_size = 8;
        arch.alignment = 4;
        arch.set_memory_endianness(Endianness::Big);
        let mut custom = AddressSpace::new(SpaceId::Custom(3), "little-data", 4);
        custom.word_size = 2;
        custom.endianness = Some(Endianness::Little);
        arch.add_space(custom);
        let context = context_of(&arch);
        let model = context.memory_model();

        assert!(model.is_available());
        assert!(model.is_coherent());
        assert_eq!(model.default_address_bits(), 64);
        assert_eq!(model.default_endianness(), MachineMemoryEndianness::Big);
        assert_eq!(
            model
                .space(SpaceId::Ram)
                .map(MachineMemorySpace::endianness),
            Some(MachineMemoryEndianness::Big)
        );
        let custom = model.space(SpaceId::Custom(3)).expect("custom space");
        assert_eq!(custom.address_bits(), 32);
        assert_eq!(custom.word_size_bytes(), 2);
        assert_eq!(custom.endianness(), MachineMemoryEndianness::Little);
    }

    #[test]
    fn architecture_snapshot_takes_its_width_from_the_default_space() {
        let mut arch = ArchSpec::new("fallback-address-size");
        arch.addr_size = 1;
        arch.add_register(RegisterDef::new("pc", 0, 8));
        arch.add_space(AddressSpace::new(SpaceId::Custom(9), "fallback", 1));
        arch.add_space(AddressSpace::ram(8));
        let context = context_of(&arch);
        let model = context.memory_model();

        assert_eq!(model.default_address_bits(), 64);
        assert_eq!(
            model
                .space(SpaceId::Custom(9))
                .map(MachineMemorySpace::address_bits),
            Some(64)
        );
        assert_eq!(
            model
                .space(SpaceId::Ram)
                .map(MachineMemorySpace::address_bits),
            Some(64)
        );
    }
}

/// What a callee's body states when it mints no call contract (doc/adr-resolved-bodies.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CalleeStatement {
    /// The arguments its body proves it takes, a floor where a slot past them may be read.
    pub(crate) arity: crate::SourceArity,
    /// Its result, where the body proves it: an unproven result leaves an exact arity exact.
    pub(crate) result: Option<crate::SourceCallResult>,
    /// The carrier its header spells an unproven result in.
    pub(crate) seed: Option<r2source::SourceResultSeed>,
    /// The typed lanes its body writes a result byte in, where its result is unproven.
    pub(crate) carriers: Option<r2source::SourceResultCarriers>,
    /// What a call reads where the arity is exact and fixed: its parameters' locations (D283).
    pub(crate) reads: Option<Vec<crate::SourceParameterLocation>>,
}

impl CalleeStatement {
    /// Each callee interface that mints no call contract (an unproven result, or parameters that are
    /// a floor), as a statement.
    pub(crate) fn of(
        interfaces: &BTreeMap<u64, crate::SourceFunctionInterface>,
    ) -> BTreeMap<u64, Self> {
        let unproven = interfaces.iter().filter(|(_, interface)| {
            interface.return_kind() == crate::SourceFunctionReturn::Unproven
                || !interface.arity().is_exact()
        });
        let statements = unproven.map(|(address, interface)| {
            // A statement counts no call's variadic tail, so its parameters are only a floor.
            let arity = match interface.is_variadic() {
                true => crate::SourceArity::AtLeast(interface.parameters().len()),
                false
                    if !interface
                        .arity_floor()
                        .is_some_and(|floor| floor.reads_past()) =>
                {
                    crate::SourceArity::Exact(interface.parameters().len())
                }
                false => interface.arity(),
            };
            (
                *address,
                Self {
                    reads: (matches!(arity, crate::SourceArity::Exact(_))
                        && !interface.is_variadic()
                        && interface.unbounded_reads().is_none())
                    .then(|| crate::call_reads::CallReads::callee_locations(interface))
                    .flatten(),
                    arity,
                    result: match interface.return_kind() {
                        crate::SourceFunctionReturn::Void => Some(crate::SourceCallResult::Void),
                        crate::SourceFunctionReturn::Register { storage } => {
                            Some(crate::SourceCallResult::Register {
                                storage,
                                width: (interface.result_width())
                                    .unwrap_or(crate::SourceResultWidth::whole(storage)),
                            })
                        }
                        crate::SourceFunctionReturn::Pair { low, high } => {
                            Some(crate::SourceCallResult::Pair { low, high })
                        }
                        crate::SourceFunctionReturn::Unproven => None,
                    },
                    seed: interface
                        .unproven_result()
                        .and_then(r2source::SourceUnprovenResult::seed),
                    carriers: interface.result_carriers(),
                },
            )
        });
        statements.collect()
    }
}
