//! Disassembly and P-code lifting using libsla.
//!
//! This module provides runtime disassembly of instruction bytes to P-code
//! and translation to r2il using Ghidra's libsla library.

pub mod syntax;
pub(crate) mod user_operation;

#[cfg(test)]
mod tests;

use libsla::{
    Address, AddressSpace, AddressSpaceId, BoolOp, FloatOp, GhidraSleigh, InstructionLoader, IntOp,
    IntSign, OpCode, PcodeDisassembly, PcodeInstruction, PseudoOp, Sleigh, VarnodeData,
};
use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode, select_register_name};
use r2source::SourceEndianness;
use r2source::{
    AdvisorySuccessorKind, CanonicalStorageId, CanonicalStorageSpace, MachineProfile,
    OwnedFunctionSnapshot, SourceFunctionInterface,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::translate::{self, PcodeSource};
use crate::{LiftError, Result};
use user_operation::{Extension, ModelledUserOperation, PackedExtension};

/// One parsed Sleigh specification: everything derived from the `.sla` and the
/// processor spec, and nothing derived from who asked for it.
///
/// Parsing one is the single most expensive thing this crate does -- 58 to 91
/// milliseconds for x86-64, against 21 to 83 *micro*seconds to lift a block --
/// and it was being done three times over. `Disassembler::from_trusted_profile`
/// did it on the lift path, and `create_disassembler_for_arch` in the plugin
/// did it twice more for one `R2ILContext`: once through `build_arch_spec` for
/// the architecture and once through `from_sla` for the disassembler. Splitting
/// the parse from the caller's identity is what lets all three share one, and
/// putting the split here rather than a cache at each call site is what stops
/// there being a fourth.
///
/// The lift authority is minted with the specification rather than per
/// disassembler because minting copies the whole `.sla` into an `Arc` and
/// hashes it. Its documented meaning is unchanged: equality is the identity of
/// a load event, and there is now one load event per specification instead of
/// one per caller. It is handed out only to a caller holding a trusted profile.
struct LoadedSpecification {
    /// The thread-confined Sleigh instance. Public lift boundaries invalidate
    /// its address-keyed decode state before admitting another byte source.
    sleigh: RefCell<GhidraSleigh>,
    /// Canonical register names by (offset, size)
    reg_name_map: HashMap<(u64, u32), String>,
    /// Exact mapping extracted with the architecture metadata for this session.
    space_map: HashMap<AddressSpaceId, SpaceId>,
    /// Register the processor spec names as the program counter.
    program_counter: String,
    /// Architecture exactly as `extract_architecture` derived it, before any
    /// processor-spec overlay a particular consumer wants.
    arch: Arc<r2il::ArchSpec>,
    /// The operation each `CallOther` index names, where this lift models it,
    /// resolved once from `arch.user_ops` so no lift compares a name.
    modelled_user_ops: Vec<Option<ModelledUserOperation>>,
    /// Present only for a specification loaded from embedded bytes, which are
    /// the only ones that can certify.
    authority: Option<GenuineLiftAuthority>,
    /// The stamp of the last change to the Sleigh instance's decode state.
    decode_state: Cell<u64>,
}

/// Stamps every change to any specification's decode state, so no two changes share one.
static DECODE_STATES: AtomicU64 = AtomicU64::new(1);

impl LoadedSpecification {
    /// Stamp a change to the decode state: a cleared cache, a parse, or committed context.
    fn change_decode_state(&self) {
        self.decode_state
            .set(DECODE_STATES.fetch_add(1, Ordering::Relaxed));
    }
}

/// Where one decode left its specification's context; only the lifter judges whether the next decode keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation {
    decode_state: u64,
    end: u64,
}

/// A disassembler that uses libsla to lift instructions to r2il.
pub struct Disassembler {
    /// The parsed specification, shared with every other holder of it.
    spec: Rc<LoadedSpecification>,
    /// Architecture name
    arch_name: String,
    /// Opaque authority present only for an embedded trusted Sleigh profile.
    genuine_authority: Option<GenuineLiftAuthority>,
    trusted_profile: Option<TrustedSleighProfile>,
}

/// One instruction as a listing spells it and as its P-code says it runs, read from one parse.
#[derive(Debug)]
pub struct Decoded {
    pub syntax: syntax::Syntax,
    /// Refused where Sleigh leaves the constructor `unimpl` or the lifter cannot translate its P-code.
    pub lifted: Result<R2ILBlock>,
    /// Present only where Sleigh built the P-code, which is what commits the context.
    pub continuation: Option<Continuation>,
}

/// Embedded Sleigh profiles allowed to mint certifying lift authority.
///
/// Arbitrary caller-supplied SLA/pspec bytes remain useful for analysis, but
/// cannot enter the certification pipeline. Keeping the trust root here makes
/// the exact specification bundle—not a caller-provided name—the authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustedSleighProfile {
    #[cfg(feature = "x86")]
    X86,
    #[cfg(feature = "x86")]
    X86_64,
    #[cfg(feature = "arm")]
    ArmCortexLe,
    #[cfg(feature = "arm")]
    ArmThumbLe,
    #[cfg(feature = "arm")]
    Aarch64Le,
    #[cfg(feature = "arm")]
    Aarch64AppleSilicon,
    #[cfg(feature = "mips")]
    Mips32Be,
    #[cfg(feature = "mips")]
    Mips32Le,
    #[cfg(feature = "mips")]
    Mips64Be,
    #[cfg(feature = "mips")]
    Mips64Le,
    #[cfg(feature = "riscv")]
    RiscV32Gc,
    #[cfg(feature = "riscv")]
    RiscV64Gc,
}

impl TrustedSleighProfile {
    pub fn specification(self) -> (&'static [u8], &'static str, &'static str) {
        match self {
            #[cfg(feature = "x86")]
            Self::X86 => (
                sleigh_config::processor_x86::SLA_X86,
                sleigh_config::processor_x86::PSPEC_X86,
                "x86",
            ),
            #[cfg(feature = "x86")]
            Self::X86_64 => (
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64",
            ),
            #[cfg(feature = "arm")]
            // Ghidra's own ARM.ldefs pairs ARM8_le with ARMt, which leaves
            // TMode clear. A Cortex pspec sets TMode, and Cortex-M is
            // Thumb-only, so pairing it here would lift every A32 instruction
            // as Thumb: wrong instruction, wrong length, wrong control flow.
            Self::ArmCortexLe => (
                sleigh_config::processor_arm::SLA_ARM8_LE,
                sleigh_config::processor_arm::PSPEC_ARMT,
                "ARM",
            ),
            // The same language with TMode set: Ghidra's own Thumb decoder.
            #[cfg(feature = "arm")]
            Self::ArmThumbLe => (
                sleigh_config::processor_arm::SLA_ARM8_LE,
                sleigh_config::processor_arm::PSPEC_ARMTTHUMB,
                "ARM",
            ),
            #[cfg(feature = "arm")]
            Self::Aarch64Le => (
                sleigh_config::processor_aarch64::SLA_AARCH64,
                sleigh_config::processor_aarch64::PSPEC_AARCH64,
                "aarch64",
            ),
            #[cfg(feature = "arm")]
            Self::Aarch64AppleSilicon => (
                sleigh_config::processor_aarch64::SLA_AARCH64_APPLESILICON,
                sleigh_config::processor_aarch64::PSPEC_AARCH64,
                "aarch64",
            ),
            #[cfg(feature = "mips")]
            Self::Mips32Be => (
                sleigh_config::processor_mips::SLA_MIPS32BE,
                sleigh_config::processor_mips::PSPEC_MIPS32,
                "mips32be",
            ),
            #[cfg(feature = "mips")]
            Self::Mips32Le => (
                sleigh_config::processor_mips::SLA_MIPS32LE,
                sleigh_config::processor_mips::PSPEC_MIPS32,
                "mips32le",
            ),
            #[cfg(feature = "mips")]
            Self::Mips64Be => (
                sleigh_config::processor_mips::SLA_MIPS64BE,
                sleigh_config::processor_mips::PSPEC_MIPS64,
                "mips64be",
            ),
            #[cfg(feature = "mips")]
            Self::Mips64Le => (
                sleigh_config::processor_mips::SLA_MIPS64LE,
                sleigh_config::processor_mips::PSPEC_MIPS64,
                "mips64le",
            ),
            #[cfg(feature = "riscv")]
            Self::RiscV32Gc => (
                sleigh_config::processor_riscv::SLA_RISCV_ILP32D,
                sleigh_config::processor_riscv::PSPEC_RV32GC,
                "riscv32",
            ),
            #[cfg(feature = "riscv")]
            Self::RiscV64Gc => (
                sleigh_config::processor_riscv::SLA_RISCV_LP64D,
                sleigh_config::processor_riscv::PSPEC_RV64GC,
                "riscv64",
            ),
        }
    }

    /// Select an embedded specification from one exact source-owned machine
    /// tuple. Only tuples manually verified against the active radare analyzer
    /// are admitted; aliases, empty CPU defaults, and inferred host values are
    /// deliberately unsupported.
    fn from_machine(machine: &MachineProfile) -> Result<Self> {
        Self::from_tuple(
            machine.arch_id(),
            machine.cpu_id(),
            machine.bits(),
            machine.endianness(),
        )
    }

    fn from_tuple(
        arch_id: &str,
        cpu_id: &str,
        bits: u32,
        endianness: SourceEndianness,
    ) -> Result<Self> {
        match (arch_id, cpu_id, bits, endianness) {
            #[cfg(feature = "x86")]
            ("x86", "x86", 32, SourceEndianness::Little) => Ok(Self::X86),
            #[cfg(feature = "x86")]
            ("x86", "x86", 64, SourceEndianness::Little) => Ok(Self::X86_64),
            #[cfg(feature = "arm")]
            ("arm", "arm", 64, SourceEndianness::Little) => Ok(Self::Aarch64Le),
            #[cfg(feature = "arm")]
            ("arm", "arm", 32, SourceEndianness::Little) => Ok(Self::ArmCortexLe),
            #[cfg(feature = "arm")]
            ("arm", "thumb", 32, SourceEndianness::Little) => Ok(Self::ArmThumbLe),
            _ => Err(LiftError::Unsupported(format!(
                "no manually verified trusted Sleigh profile for source tuple {}/{}/{}/{:?}",
                arch_id, cpu_id, bits, endianness
            ))),
        }
    }
}

fn is_exact_top_level_address_register(
    arch: &r2il::ArchSpec,
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

/// Where the lifted architecture puts the register the source named.
///
/// Spelling differs between the two: radare2 writes x86 register names in lower
/// case where the Sleigh specification writes them in upper case, and that is a
/// difference in spelling, not in register. Case is therefore folded, and
/// nothing else is: a name the architecture does not define resolves to
/// nothing, because placing an unrecognised carrier by guesswork is how a
/// carrier ends up at another register's offset.
fn arch_register_storage(arch: &r2il::ArchSpec, name: &str) -> Option<CanonicalStorageId> {
    let register = arch
        .get_register(name)
        .or_else(|| arch.get_register(&name.to_ascii_uppercase()))
        .or_else(|| arch.get_register(&name.to_ascii_lowercase()))?;
    Some(CanonicalStorageId {
        space: r2source::CanonicalStorageSpace::Register,
        offset: register.offset,
        size: register.size,
    })
}

/// Restate a capture's role carriers in the lifted architecture's numbering.
///
/// The capture states each carrier as a name plus an offset into its own
/// register arena. Only the name crosses over, so each carrier is looked up
/// again here and a carrier the architecture cannot place is dropped. Dropping
/// costs the certificates that need that carrier; keeping the capture's offset
/// would instead assert that some unrelated register is the return address,
/// which every consumer downstream would then believe.
fn arch_resolved_source(
    source: OwnedFunctionSnapshot,
    arch: &r2il::ArchSpec,
) -> Result<OwnedFunctionSnapshot> {
    let resolve = |name: Option<&str>| name.and_then(|name| arch_register_storage(arch, name));
    let interface = match source.function_interface() {
        Some(interface) => {
            let names = interface.role_register_names();
            Some(
                interface
                    .clone()
                    .with_arch_resolved_role_carriers(
                        resolve(names.return_address()),
                        resolve(names.stack_pointer()),
                        resolve(names.frame_pointer()),
                    )
                    .map_err(|error| {
                        LiftError::Unsupported(format!(
                            "captured interface carriers do not resolve against the lifted \
                             architecture: {error:?}"
                        ))
                    })?,
            )
        }
        None => None,
    };
    let role_names = source.machine_roles().role_register_names();
    let roles = source
        .machine_roles()
        .with_direction_flag_storage(resolve(role_names.direction_flag()))
        .with_arch_resolved_carriers(
            resolve(role_names.return_address()),
            resolve(role_names.stack_pointer()),
        )
        .map_err(|error| {
            LiftError::Unsupported(format!(
                "captured machine carriers do not resolve against the lifted architecture: \
                 {error:?}"
            ))
        })?;
    Ok(source.with_arch_resolved_role_carriers(interface, roles))
}

fn captured_frame_pointer_storage_matches_arch(
    interface: &SourceFunctionInterface,
    arch: &r2il::ArchSpec,
) -> bool {
    let Some(frame_pointer) = interface.frame_pointer_storage() else {
        return true;
    };
    let Some(return_address) = interface.return_address_storage() else {
        return false;
    };
    let Some(stack_pointer) = interface.stack_pointer_storage() else {
        return false;
    };
    let address_size = r2il::effective_arch_address_size(arch);
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

fn captured_return_mechanism_matches_arch(
    interface: &SourceFunctionInterface,
    arch: &r2il::ArchSpec,
) -> bool {
    let Some(mechanism) = interface.return_mechanism() else {
        return true;
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
    {
        return false;
    }
    let mut ram_spaces = arch.spaces.iter().filter(|space| space.id == SpaceId::Ram);
    let Some(ram) = ram_spaces.next() else {
        return false;
    };
    if ram_spaces.next().is_some()
        || ram.word_size != 1
        || ram.addr_size.checked_mul(8) != Some(address_bits)
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

/// Schema of the exact lift-origin manifest retained by genuine blocks.
pub const GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug)]
struct GenuineLiftAuthorityState {
    arch_name: Arc<str>,
    arch: Arc<r2il::ArchSpec>,
    manifest_hash: u64,
}

/// Opaque run-local authority for one exact Sleigh configuration.
///
/// Equality is session identity, not manifest equality. Independently loading
/// identical specifications therefore cannot replay proof authority, while the
/// stable manifest hash remains available for diagnostics and cache partitioning.
#[derive(Clone)]
pub struct GenuineLiftAuthority(Arc<GenuineLiftAuthorityState>);

impl GenuineLiftAuthority {
    fn new(
        sla_bytes: Arc<[u8]>,
        pspec: Arc<str>,
        arch_name: Arc<str>,
        arch: Arc<r2il::ArchSpec>,
    ) -> Self {
        let manifest_hash = stable_lift_manifest_hash(&sla_bytes, &pspec, &arch_name);
        Self(Arc::new(GenuineLiftAuthorityState {
            arch_name,
            arch,
            manifest_hash,
        }))
    }

    /// Exact architecture derived from the retained Sleigh specification.
    pub fn arch_spec(&self) -> &r2il::ArchSpec {
        &self.0.arch
    }

    pub fn arch_name(&self) -> &str {
        &self.0.arch_name
    }

    pub const fn schema_version(&self) -> u32 {
        GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION
    }

    /// Stable diagnostic identity. This is never proof authority.
    pub fn manifest_hash(&self) -> u64 {
        self.0.manifest_hash
    }

    pub fn same_session(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for GenuineLiftAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenuineLiftAuthority")
            .field("schema_version", &self.schema_version())
            .field("arch_name", &self.arch_name())
            .field("manifest_hash", &self.manifest_hash())
            .finish_non_exhaustive()
    }
}

impl PartialEq for GenuineLiftAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.same_session(other)
    }
}

impl Eq for GenuineLiftAuthority {}

impl Hash for GenuineLiftAuthority {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// One immutable block produced directly by a genuine Disassembler session.
#[derive(Debug, Clone)]
pub struct GenuineLiftedBlock {
    authority: GenuineLiftAuthority,
    block: R2ILBlock,
    source_bytes: Arc<[u8]>,
    instruction_spans: Arc<[GenuineInstructionSpan]>,
}

/// Exact native instruction coverage retained even for zero-op instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenuineInstructionSpan {
    addr: u64,
    size: u32,
    first_canonical_op: u64,
    canonical_op_count: u64,
}

impl GenuineInstructionSpan {
    pub const fn addr(self) -> u64 {
        self.addr
    }

    pub const fn size(self) -> u32 {
        self.size
    }

    /// First operation in the exact canonical P-code stream for this native
    /// instruction. Zero-op spans point at the next canonical operation.
    pub const fn first_canonical_op(self) -> u64 {
        self.first_canonical_op
    }

    /// Number of exact canonical P-code operations emitted for this native
    /// instruction. Zero means the trusted translator supplied no semantics;
    /// it does not by itself prove that the instruction is effect-free.
    pub const fn canonical_op_count(self) -> u64 {
        self.canonical_op_count
    }
}

impl GenuineLiftedBlock {
    pub fn block(&self) -> &R2ILBlock {
        &self.block
    }

    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    pub fn instruction_spans(&self) -> &[GenuineInstructionSpan] {
        &self.instruction_spans
    }

    pub fn authority(&self) -> &GenuineLiftAuthority {
        &self.authority
    }
}

/// One exact source-owned basic-block extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenuineFunctionBlockRange {
    addr: u64,
    size: u32,
}

impl GenuineFunctionBlockRange {
    pub(crate) const fn new(addr: u64, size: u32) -> Self {
        Self { addr, size }
    }

    pub const fn addr(self) -> u64 {
        self.addr
    }

    pub const fn size(self) -> u32 {
        self.size
    }
}

/// Immutable source declaration of the complete function block layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenuineFunctionLayout {
    revision_identity: Arc<[u8]>,
    entry_addr: u64,
    blocks: Arc<[GenuineFunctionBlockRange]>,
    external_exits: Arc<[u64]>,
}

impl GenuineFunctionLayout {
    pub(crate) fn new(
        revision_identity: impl Into<Vec<u8>>,
        entry_addr: u64,
        blocks: impl IntoIterator<Item = GenuineFunctionBlockRange>,
        external_exits: impl IntoIterator<Item = u64>,
    ) -> Result<Self> {
        let revision_identity = revision_identity.into();
        let blocks = blocks.into_iter().collect::<Vec<_>>();
        if revision_identity.is_empty() || blocks.is_empty() {
            return Err(LiftError::Parse(
                "genuine function layout requires revision identity and blocks".to_string(),
            ));
        }
        let mut previous_end = None;
        let mut entry_found = false;
        for block in &blocks {
            if block.size == 0 {
                return Err(LiftError::Parse(
                    "genuine function layout contains an empty block".to_string(),
                ));
            }
            let end = block
                .addr
                .checked_add(u64::from(block.size))
                .ok_or_else(|| {
                    LiftError::Parse("genuine function block range overflows".to_string())
                })?;
            if previous_end.is_some_and(|previous| block.addr < previous) {
                return Err(LiftError::Parse(
                    "genuine function layout must be ordered and non-overlapping".to_string(),
                ));
            }
            entry_found |= block.addr == entry_addr;
            previous_end = Some(end);
        }
        if !entry_found {
            return Err(LiftError::Parse(
                "genuine function entry is not a declared block".to_string(),
            ));
        }
        let mut external_exits = external_exits.into_iter().collect::<Vec<_>>();
        external_exits.sort_unstable();
        if external_exits.windows(2).any(|pair| pair[0] == pair[1])
            || external_exits.iter().any(|target| {
                blocks.iter().any(|block| {
                    block
                        .addr
                        .checked_add(u64::from(block.size))
                        .is_some_and(|end| block.addr <= *target && *target < end)
                })
            })
        {
            return Err(LiftError::Parse(
                "genuine function external exits must be unique and outside the layout".to_string(),
            ));
        }
        Ok(Self {
            revision_identity: revision_identity.into(),
            entry_addr,
            blocks: blocks.into(),
            external_exits: external_exits.into(),
        })
    }

    pub fn revision_identity(&self) -> &[u8] {
        &self.revision_identity
    }

    pub const fn entry_addr(&self) -> u64 {
        self.entry_addr
    }

    pub fn blocks(&self) -> &[GenuineFunctionBlockRange] {
        &self.blocks
    }

    pub fn external_exits(&self) -> &[u64] {
        &self.external_exits
    }
}

/// Opaque identity of one complete exact-layout genuine lift.
#[derive(Debug)]
struct GenuineLiftedFunctionAuthorityState {
    lift: GenuineLiftAuthority,
    layout: GenuineFunctionLayout,
    source_manifest_hash: u64,
}

/// Opaque run-local identity of one complete exact-layout genuine lift.
#[derive(Clone)]
pub struct GenuineLiftedFunctionAuthority(Arc<GenuineLiftedFunctionAuthorityState>);

impl GenuineLiftedFunctionAuthority {
    pub fn lift_authority(&self) -> &GenuineLiftAuthority {
        &self.0.lift
    }

    pub fn layout(&self) -> &GenuineFunctionLayout {
        &self.0.layout
    }

    /// Stable diagnostic identity of configuration, layout, and source bytes.
    pub fn source_manifest_hash(&self) -> u64 {
        self.0.source_manifest_hash
    }

    /// Whether both values name the same exact function-lift event.
    pub fn same_lift(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for GenuineLiftedFunctionAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenuineLiftedFunctionAuthority")
            .field("lift", self.lift_authority())
            .field("layout", self.layout())
            .field("source_manifest_hash", &self.source_manifest_hash())
            .finish_non_exhaustive()
    }
}

impl PartialEq for GenuineLiftedFunctionAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.same_lift(other)
    }
}

impl Eq for GenuineLiftedFunctionAuthority {}

impl Hash for GenuineLiftedFunctionAuthority {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// Exact-layout immutable blocks from one exact lift session and policy.
#[derive(Debug, Clone)]
pub struct GenuineLiftedFunction {
    authority: GenuineLiftedFunctionAuthority,
    blocks: Arc<[GenuineLiftedBlock]>,
}

/// Canonical lift retaining the exact opaque source capture that supplied its
/// bytes and typed function interface. Detached genuine blocks/layouts remain
/// analysis-only and cannot construct this type.
#[derive(Debug, Clone)]
pub struct TrustedLiftedFunction {
    source: OwnedFunctionSnapshot,
    lifted: GenuineLiftedFunction,
}

impl TrustedLiftedFunction {
    pub fn source(&self) -> &OwnedFunctionSnapshot {
        &self.source
    }

    pub fn lifted(&self) -> &GenuineLiftedFunction {
        &self.lifted
    }
}

impl GenuineLiftedFunction {
    pub(crate) fn try_from_layout(
        layout: GenuineFunctionLayout,
        blocks: Vec<GenuineLiftedBlock>,
    ) -> Result<Self> {
        let Some(first) = blocks.first() else {
            return Err(LiftError::Parse(
                "genuine lifted function requires at least one block".to_string(),
            ));
        };
        if blocks.len() != layout.blocks.len() {
            return Err(LiftError::Parse(
                "genuine lift does not cover the exact declared block layout".to_string(),
            ));
        }
        let lift = first.authority.clone();
        for (declared, block) in layout.blocks.iter().zip(&blocks) {
            if !lift.same_session(&block.authority) {
                return Err(LiftError::Parse(
                    "genuine lifted function cannot mix disassembler sessions".to_string(),
                ));
            }
            if block.block.addr != declared.addr
                || block.block.size != declared.size
                || usize::try_from(declared.size) != Ok(block.source_bytes.len())
                || !genuine_instruction_spans_cover_block(block)
            {
                return Err(LiftError::Parse(
                    "genuine lifted block does not match its declared extent".to_string(),
                ));
            }
        }
        let successor_manifest = validate_genuine_function_cfg(&layout, &blocks)?;
        let source_manifest_hash =
            stable_genuine_function_manifest_hash(&lift, &layout, &blocks, &successor_manifest);
        Ok(Self {
            authority: GenuineLiftedFunctionAuthority(Arc::new(
                GenuineLiftedFunctionAuthorityState {
                    lift,
                    layout,
                    source_manifest_hash,
                },
            )),
            blocks: blocks.into(),
        })
    }

    pub fn authority(&self) -> &GenuineLiftedFunctionAuthority {
        &self.authority
    }

    pub fn arch_spec(&self) -> &r2il::ArchSpec {
        self.authority.lift_authority().arch_spec()
    }

    pub fn blocks(&self) -> &[GenuineLiftedBlock] {
        &self.blocks
    }
}

fn genuine_instruction_spans_cover_block(block: &GenuineLiftedBlock) -> bool {
    let mut expected = block.block.addr;
    let mut expected_op = 0usize;
    if block.instruction_spans.is_empty() {
        return false;
    }
    for span in block.instruction_spans.iter() {
        if span.addr != expected
            || span.size == 0
            || usize::try_from(span.first_canonical_op) != Ok(expected_op)
        {
            return false;
        }
        let Some(next) = expected.checked_add(u64::from(span.size)) else {
            return false;
        };
        let Ok(op_count) = usize::try_from(span.canonical_op_count) else {
            return false;
        };
        let Some(next_op) = expected_op.checked_add(op_count) else {
            return false;
        };
        if next_op > block.block.ops.len()
            || (expected_op..next_op).any(|op_index| {
                block
                    .block
                    .op_metadata(op_index)
                    .and_then(|metadata| metadata.instruction_addr)
                    != Some(span.addr)
            })
        {
            return false;
        }
        expected = next;
        expected_op = next_op;
    }
    block.block.addr.checked_add(u64::from(block.block.size)) == Some(expected)
        && expected_op == block.block.ops.len()
}

fn constant_control_target(target: &Varnode) -> Option<u64> {
    (matches!(target.space, SpaceId::Const | SpaceId::Ram) && target.size > 0)
        .then_some(target.offset)
}

/// True when this operation is p-code control flow internal to one machine
/// instruction rather than the block's terminator.
///
/// Sleigh emits these routinely: a conditional move becomes a conditional
/// branch over the move, and a conditional compare branches over the rest of
/// its own operations. Both target the following instruction, which is exactly
/// what an ordinary branch to the next block targets, so the target alone
/// cannot tell them apart. What distinguishes them is that further operations
/// of the same instruction still follow: a terminator is the last thing its
/// instruction does.
fn control_op_is_intra_instruction(block: &GenuineLiftedBlock, op_index: usize) -> bool {
    let Some(instruction) = block
        .block
        .op_metadata(op_index)
        .and_then(|metadata| metadata.instruction_addr)
    else {
        return false;
    };
    if (op_index + 1..block.block.ops.len()).any(|later| {
        block
            .block
            .op_metadata(later)
            .and_then(|metadata| metadata.instruction_addr)
            == Some(instruction)
    }) {
        return true;
    }
    let target = match &block.block.ops[op_index] {
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => {
            constant_control_target(target)
        }
        _ => None,
    };
    let Some(target) = target else {
        return false;
    };
    // A branch to a later instruction of this same block leaves nothing: the
    // block goes where it was going. `-O0` arm64 emits `b` to the very next
    // instruction before a `__stack_chk_fail` call, and radare2 keeps the two
    // in one block, which read as an instruction after the terminator.
    block
        .instruction_spans
        .iter()
        .any(|span| span.addr == target && target > instruction)
}

/// The operation that decides where this block goes, if any.
fn block_terminator(block: &GenuineLiftedBlock) -> Option<&R2ILOp> {
    block
        .block
        .ops
        .iter()
        .enumerate()
        .rev()
        .find(|(index, op)| op.is_control_flow() && !control_op_is_intra_instruction(block, *index))
        .map(|(_, op)| op)
}

fn genuine_block_successors(block: &GenuineLiftedBlock) -> Result<Vec<u64>> {
    let fallthrough = block
        .block
        .addr
        .checked_add(u64::from(block.block.size))
        .ok_or_else(|| LiftError::Parse("genuine block fallthrough overflows".to_string()))?;
    let last_instruction = block
        .instruction_spans
        .last()
        .ok_or_else(|| LiftError::Parse("genuine block has no native instruction".to_string()))?
        .addr;
    for (op_index, op) in block.block.ops.iter().enumerate() {
        // Only an operation that decides where this block goes has to be its
        // last instruction. An indirect branch the lift could not resolve
        // decides nothing, and traps are modelled that way: Ghidra lifts a
        // guard instruction such as `brk` into a user operation writing pc
        // followed by a branch through it, which routinely sits mid-block.
        //
        // Exempting it cannot let a wrong successor set through. If such a
        // branch were really this block's terminator, the block would name no
        // successors while the advisory graph names its edges, and comparing
        // the two refuses the function.
        // P-code has control flow inside a single instruction. Sleigh lifts
        // AArch64 `ccmp`, for example, into a conditional branch that skips the
        // rest of that instruction's own operations by targeting the next
        // instruction. Such a branch never leaves the block, so it decides no
        // successor and may sit anywhere in it.
        let decides_successors = match op {
            R2ILOp::Branch { .. } | R2ILOp::CBranch { .. } => {
                !control_op_is_intra_instruction(block, op_index)
            }
            R2ILOp::Return { .. } | R2ILOp::Breakpoint => true,
            R2ILOp::BranchInd { .. } => block.block.switch_info.is_some(),
            _ => false,
        };
        if decides_successors
            && block
                .block
                .op_metadata(op_index)
                .and_then(|metadata| metadata.instruction_addr)
                != Some(last_instruction)
        {
            return Err(LiftError::Parse(format!(
                "genuine basic block contains instructions after a control terminator:                  op {op_index} {} at {:x?} is not the block's last instruction {last_instruction:#x}",
                match op {
                    R2ILOp::Branch { .. } => "branch",
                    R2ILOp::CBranch { .. } => "cbranch",
                    R2ILOp::Return { .. } => "return",
                    R2ILOp::Breakpoint => "breakpoint",
                    R2ILOp::BranchInd { .. } => "branch-ind",
                    _ => "other",
                },
                block
                    .block
                    .op_metadata(op_index)
                    .and_then(|metadata| metadata.instruction_addr),
            )));
        }
    }
    // Same fact, same owner: a predicated instruction transfers on one arm and
    // continues to the next instruction on the other.
    if let Some(successors) = predicated_successors(block, fallthrough) {
        return Ok(successors);
    }
    match block_terminator(block) {
        Some(R2ILOp::Return { .. } | R2ILOp::Breakpoint) => Ok(Vec::new()),
        Some(R2ILOp::Branch { target }) => constant_control_target(target)
            .map(|target| vec![target])
            .ok_or_else(|| {
                LiftError::Parse("genuine direct branch target is not constant".to_string())
            }),
        Some(R2ILOp::CBranch { target, .. }) => constant_control_target(target)
            .map(|target| vec![target, fallthrough])
            .ok_or_else(|| {
                LiftError::Parse("genuine conditional branch target is not constant".to_string())
            }),
        // An indirect branch whose target the lift did not resolve leaves this
        // function through an address the machine does not know, so it
        // contributes no edge back into the function's own blocks. It is not
        // treated as a proof that control stops here: the operation that
        // produced the target is still in the block and still carries its own
        // obligation.
        //
        // A resolved jump table is a different case. Its targets are the
        // function's own blocks, so the advisory graph names edges the machine
        // does not, and the comparison against that graph refuses the function
        // rather than silently dropping them.
        Some(R2ILOp::BranchInd { .. }) => match block.block.switch_info.as_ref() {
            Some(switch) => {
                let mut successors = switch
                    .cases
                    .iter()
                    .map(|case| case.target)
                    .collect::<Vec<_>>();
                successors.extend(switch.default_target);
                successors.sort_unstable();
                successors.dedup();
                Ok(successors)
            }
            None => Ok(Vec::new()),
        },
        Some(R2ILOp::Call { .. } | R2ILOp::CallInd { .. }) | None => Ok(vec![fallthrough]),
        Some(_) => unreachable!("control-flow filter returned a non-control operation"),
    }
}

fn validate_genuine_function_cfg(
    layout: &GenuineFunctionLayout,
    blocks: &[GenuineLiftedBlock],
) -> Result<Vec<Vec<u64>>> {
    let starts = layout
        .blocks
        .iter()
        .map(|block| block.addr)
        .collect::<HashSet<_>>();
    // A successor that is not one of this function's block starts leaves the
    // function. What must never happen is a target landing part-way into a
    // block, because that would mean the lift decoded an instruction boundary
    // the block layout does not have. Requiring instead that every exit appear
    // in the source's declared exit list would refuse ordinary tail calls: the
    // source builds that list from the function it analysed, which records no
    // successor for a branch leaving the function at all.
    let lands_offcut = |target: u64| {
        !starts.contains(&target)
            && layout.blocks.iter().any(|block| {
                target > block.addr()
                    && target < block.addr().saturating_add(u64::from(block.size()))
            })
    };
    let mut internal_successors = HashMap::<u64, Vec<u64>>::new();
    let mut successor_manifest = Vec::with_capacity(blocks.len());
    for block in blocks {
        let successors = genuine_block_successors(block)?;
        if successors.iter().copied().any(lands_offcut) {
            return Err(LiftError::Parse(
                "genuine function branches into the middle of one of its blocks".to_string(),
            ));
        }
        // An indirect branch the lift could not resolve may land on any of this
        // function's blocks. Recording no edge would let the reachability check
        // below conclude that the blocks only it reaches were invented, which
        // is the machine's ignorance stated as a finding about the program.
        let internal = if matches!(block_terminator(block), Some(R2ILOp::BranchInd { .. }))
            && block.block.switch_info.is_none()
        {
            starts.iter().copied().collect()
        } else {
            successors
                .iter()
                .copied()
                .filter(|successor| starts.contains(successor))
                .collect()
        };
        internal_successors.insert(block.block.addr, internal);
        successor_manifest.push(successors);
    }
    let mut reached = HashSet::new();
    let mut queue = VecDeque::from([layout.entry_addr]);
    while let Some(block) = queue.pop_front() {
        if !reached.insert(block) {
            continue;
        }
        let successors = internal_successors.get(&block).ok_or_else(|| {
            LiftError::Parse("genuine function entry is missing from lifted blocks".to_string())
        })?;
        queue.extend(successors.iter().copied());
    }
    if reached.len() != blocks.len() {
        return Err(LiftError::Parse(
            "genuine function contains blocks unreachable from its exact entry".to_string(),
        ));
    }
    Ok(successor_manifest)
}

/// Whether this block leaves the function on one arm of a predicated
/// instruction and continues to `fallthrough` on the other.
///
/// The guard Sleigh writes for a predicated instruction skips that
/// instruction's own operations by naming the next instruction. Where those
/// operations transfer, the block goes both ways: on to `fallthrough`, and
/// wherever the transfer says. This is the same fact
/// `BasicBlock::analyze_terminator` reads, asked in one place so the two
/// graphs cannot disagree about it.
fn predicated_successors(block: &GenuineLiftedBlock, fallthrough: u64) -> Option<Vec<u64>> {
    match r2il::predicated_transfer(&block.block.ops, fallthrough)? {
        R2ILOp::Branch { target } => Some(vec![fallthrough, constant_control_target(target)?]),
        _ => Some(vec![fallthrough]),
    }
}

fn typed_genuine_block_successors(
    block: &GenuineLiftedBlock,
) -> Result<Vec<(AdvisorySuccessorKind, u64, Option<u64>)>> {
    let fallthrough = block
        .block
        .addr
        .checked_add(u64::from(block.block.size))
        .ok_or_else(|| LiftError::Parse("trusted block fallthrough overflows".to_string()))?;
    // A predicated instruction is the one shape that both transfers and goes
    // on: the guard skipping its transfer names the next instruction, and the
    // transfer stays the block's last.
    if let Some(successors) = predicated_successors(block, fallthrough) {
        return Ok(successors
            .into_iter()
            .map(|target| (AdvisorySuccessorKind::Direct, target, None))
            .collect());
    }
    match block_terminator(block) {
        Some(R2ILOp::Return { .. } | R2ILOp::Breakpoint) => Ok(Vec::new()),
        Some(R2ILOp::Branch { target }) => constant_control_target(target)
            .map(|target| vec![(AdvisorySuccessorKind::Direct, target, None)])
            .ok_or_else(|| {
                LiftError::Parse("trusted direct branch target is not constant".to_string())
            }),
        Some(R2ILOp::CBranch { target, .. }) => constant_control_target(target)
            .map(|target| {
                vec![
                    (AdvisorySuccessorKind::Direct, target, None),
                    (AdvisorySuccessorKind::Fallthrough, fallthrough, None),
                ]
            })
            .ok_or_else(|| {
                LiftError::Parse("trusted conditional branch target is not constant".to_string())
            }),
        // An unresolved indirect branch names no edge back into this function:
        // the machine does not know where it goes.
        //
        // A jump table is different only in that radare2 resolved it and put
        // the result on the block. That resolution is not machine evidence and
        // grants no authority, but it is still the flow this function has, and
        // reporting no successors here would say the switch block goes nowhere
        // -- leaving every block it reaches unreachable and the function
        // refused. The edges are reported so the graphs describe the same
        // function; what may be claimed about them is settled downstream,
        // where an unproven construct is marked rather than rejected.
        Some(R2ILOp::BranchInd { .. }) => Ok(match block.block.switch_info.as_ref() {
            Some(switch) => {
                let mut successors = switch
                    .cases
                    .iter()
                    .map(|case| {
                        (
                            AdvisorySuccessorKind::SwitchCase,
                            case.target,
                            Some(case.value),
                        )
                    })
                    .collect::<Vec<_>>();
                successors.extend(
                    switch
                        .default_target
                        .map(|target| (AdvisorySuccessorKind::SwitchDefault, target, None)),
                );
                successors
            }
            None => Vec::new(),
        }),
        // A call leaves the block by falling through to the next instruction.
        // Where it goes in between is a property of the callee, not of this
        // function's control flow, so it contributes no successor of its own.
        // This matches the machine-side closure check, which has always treated
        // a call terminator as a fallthrough.
        Some(R2ILOp::Call { .. } | R2ILOp::CallInd { .. }) => Ok(vec![(
            AdvisorySuccessorKind::Fallthrough,
            fallthrough,
            None,
        )]),
        None => Ok(vec![(
            AdvisorySuccessorKind::Fallthrough,
            fallthrough,
            None,
        )]),
        Some(_) => unreachable!("control-flow filter returned a non-control operation"),
    }
}

fn validate_owned_snapshot_cfg(
    source: &OwnedFunctionSnapshot,
    blocks: &[GenuineLiftedBlock],
) -> Result<()> {
    // Advisory call sites are diagnostic only: they never granted authority to
    // anything, and no consumer reads them. Refusing a function because radare2
    // reported the calls it found rejected more information rather than less,
    // and it suppressed every function that calls anything. Call boundaries are
    // certified from machine evidence, and residualize when that evidence is
    // absent.
    if source.image().blocks().len() != blocks.len() {
        return Err(LiftError::Parse(
            "trusted lift does not cover every owned source block".to_string(),
        ));
    }
    for (source_block, lifted_block) in source.image().blocks().iter().zip(blocks) {
        if source_block.address() != lifted_block.block().addr {
            return Err(LiftError::Parse(
                "trusted lift block order differs from owned source".to_string(),
            ));
        }
        let mut machine = typed_genuine_block_successors(lifted_block)?;
        machine.sort_unstable();
        if machine.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LiftError::Parse(
                "trusted machine CFG contains a duplicate successor".to_string(),
            ));
        }
        let mut advisory = source_block
            .successors()
            .iter()
            .map(|successor| (successor.kind(), successor.target(), successor.case_value()))
            .collect::<Vec<_>>();
        advisory.sort_unstable();
        // The two graphs are scoped differently and cannot be compared for
        // equality. The advisory graph is the function radare2 analysed, so it
        // stops at the function's edge: a tail call records no successor at
        // all, because its target is another function. The machine graph
        // describes the instructions, so it sees that branch.
        //
        // What must hold is that the lift did not lose or invent flow *inside*
        // the function: every edge landing on one of this function's own blocks
        // must appear in both. An edge leaving them is the function exiting,
        // which the machine may know about and radare2 may not.
        let block_starts = source
            .image()
            .blocks()
            .iter()
            .map(|block| block.address())
            .collect::<BTreeSet<_>>();
        let internal = |successors: &[(AdvisorySuccessorKind, u64, Option<u64>)]| {
            successors
                .iter()
                .copied()
                .filter(|(_, target, _)| block_starts.contains(target))
                .collect::<Vec<_>>()
        };
        // The two graphs answer the same question from different evidence, and
        // each knows something the other cannot. Where they disagree, the
        // question is whether one of them is ignorant or the two contradict
        // each other; only a contradiction refuses the function.
        //
        // The machine cannot resolve a jump table, so it names no edge out of
        // an indirect branch while radare2, having analysed the table, names
        // every case. The machine also assumes a call returns, because whether
        // it does is a property of the callee; radare2 knows `exit` does not
        // and ends the block there. Neither difference is a disagreement about
        // this function's instructions, and refusing on either rejects most
        // real programs -- the first takes out every entry point that switches,
        // the second every one that can fail.
        //
        // What certifies nothing still describes the flow, and is marked
        // unproven where that matters rather than discarded here.
        let terminator = block_terminator(lifted_block);
        let machine_internal = internal(&machine);
        let advisory_internal = internal(&advisory);
        let machine_only = machine_internal
            .iter()
            .filter(|edge| !advisory_internal.contains(edge))
            .copied()
            .collect::<Vec<_>>();
        let advisory_only = advisory_internal
            .iter()
            .filter(|edge| !machine_internal.contains(edge))
            .copied()
            .collect::<Vec<_>>();

        let call_may_not_return = matches!(
            terminator,
            Some(R2ILOp::Call { .. } | R2ILOp::CallInd { .. })
        ) && machine_only
            .iter()
            .all(|(kind, _, _)| *kind == AdvisorySuccessorKind::Fallthrough);
        let table_unresolved = matches!(terminator, Some(R2ILOp::BranchInd { .. }))
            && lifted_block.block().switch_info.is_none();

        if (!machine_only.is_empty() && !call_may_not_return)
            || (!advisory_only.is_empty() && !table_unresolved)
        {
            r2il::refusal_evidence!(
                "cfg-contradiction",
                "{:#x} terminator {:?} over {} ops",
                lifted_block.block().addr,
                terminator,
                lifted_block.block().ops.len()
            );
            return Err(LiftError::Parse(format!(
                "machine-derived CFG contradicts the owned advisory source CFG at {:#x}: \
                 machine names {machine_only:?}, source names {advisory_only:?}",
                lifted_block.block().addr,
            )));
        }
    }
    Ok(())
}

fn stable_genuine_function_manifest_hash(
    lift: &GenuineLiftAuthority,
    layout: &GenuineFunctionLayout,
    blocks: &[GenuineLiftedBlock],
    successor_manifest: &[Vec<u64>],
) -> u64 {
    fn update(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(0x100000001b3);
        }
        *hash ^= 0xff;
        *hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut hash = 0xcbf29ce484222325;
    update(
        &mut hash,
        &GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION.to_le_bytes(),
    );
    update(&mut hash, &lift.manifest_hash().to_le_bytes());
    update(&mut hash, layout.revision_identity());
    update(&mut hash, &layout.entry_addr().to_le_bytes());
    for (block, successors) in blocks.iter().zip(successor_manifest) {
        update(&mut hash, &block.block.addr.to_le_bytes());
        update(&mut hash, &block.block.size.to_le_bytes());
        update(&mut hash, block.source_bytes());
        for span in block.instruction_spans() {
            update(&mut hash, &span.addr().to_le_bytes());
            update(&mut hash, &span.size().to_le_bytes());
            update(&mut hash, &span.first_canonical_op().to_le_bytes());
            update(&mut hash, &span.canonical_op_count().to_le_bytes());
        }
        for successor in successors {
            update(&mut hash, &successor.to_le_bytes());
        }
    }
    for target in layout.external_exits() {
        update(&mut hash, &target.to_le_bytes());
    }
    hash
}

fn stable_lift_manifest_hash(sla_bytes: &[u8], pspec: &str, arch_name: &str) -> u64 {
    fn update(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(0x100000001b3);
        }
        *hash ^= 0xff;
        *hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut hash = 0xcbf29ce484222325;
    update(
        &mut hash,
        &GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION.to_le_bytes(),
    );
    update(&mut hash, sla_bytes);
    update(&mut hash, pspec.as_bytes());
    update(&mut hash, arch_name.as_bytes());
    hash
}

/// What a block lift does at an instruction Sleigh cannot decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Undecodable {
    /// The block ends before it.
    EndsBlock,
    /// The whole lift refuses.
    Refuses,
}

/// Wrapper for libsla PcodeInstruction that implements PcodeSource.
struct DisasmInstructionWrapper<'a> {
    instr: &'a PcodeInstruction,
    disasm: &'a Disassembler,
}

impl<'a> PcodeSource for DisasmInstructionWrapper<'a> {
    fn output(&self) -> Option<Varnode> {
        // translate_pcode_op validates every operand before creating this view.
        self.instr
            .output
            .as_ref()
            .and_then(|v| self.disasm.translate_varnode(v).ok())
    }

    fn input(&self, idx: usize) -> Option<Varnode> {
        // translate_pcode_op validates every operand before creating this view.
        self.instr
            .inputs
            .get(idx)
            .and_then(|v| self.disasm.translate_varnode(v).ok())
    }

    fn input_raw_offset(&self, idx: usize) -> Option<u64> {
        self.instr.inputs.get(idx).map(|v| v.address.offset)
    }

    fn input_count(&self) -> usize {
        self.instr.inputs.len()
    }

    fn space_from_index(&self, idx: u64) -> Option<SpaceId> {
        usize::try_from(idx)
            .ok()
            .and_then(|idx| self.disasm.spec.space_map.get(&AddressSpaceId::new(idx)))
            .copied()
    }
}

fn translate_err(e: translate::TranslateError) -> LiftError {
    match e {
        translate::TranslateError::MissingOutput(op) => {
            LiftError::Parse(format!("{} requires output", op))
        }
        translate::TranslateError::MissingInput(op, idx) => {
            LiftError::Parse(format!("{} requires input at index {}", op, idx))
        }
        translate::TranslateError::InvalidSpace(idx) => {
            LiftError::Parse(format!("Invalid space index: {}", idx))
        }
    }
}

fn build_register_name_map(sleigh: &GhidraSleigh) -> HashMap<(u64, u32), String> {
    let mut candidates: HashMap<(u64, u32), Vec<String>> = HashMap::new();

    for (varnode, name) in sleigh.register_name_map() {
        let key = (varnode.address.offset, varnode.size as u32);
        candidates.entry(key).or_default().push(name);
    }

    let mut map = HashMap::new();
    for (key, names) in candidates {
        if let Some(name) = select_register_name(names.iter().map(String::as_str)) {
            map.insert(key, name);
        }
    }

    map
}

impl LoadedSpecification {
    /// Parse one specification. `certifying` says whether the bytes are
    /// embedded, which is the only case that may mint authority.
    fn load(sla_bytes: &[u8], pspec: &str, arch_name: &str, certifying: bool) -> Result<Self> {
        let sleigh = GhidraSleigh::builder()
            .processor_spec(pspec)
            .map_err(|e| LiftError::Parse(format!("Invalid processor spec: {}", e)))?
            .build(sla_bytes)
            .map_err(|e| LiftError::Parse(format!("Failed to load .sla: {}", e)))?;

        let reg_name_map = build_register_name_map(&sleigh);
        let mut extracted = crate::sleigh::extract_architecture(&sleigh, arch_name)?;
        extracted.arch.tracked_entry_values = crate::sleigh::processor_spec_tracked_values(pspec);
        let arch = Arc::new(extracted.arch);
        let modelled_user_ops = user_operation::resolve_modelled_user_operations(&arch.user_ops);
        let authority = certifying.then(|| {
            GenuineLiftAuthority::new(
                Arc::from(sla_bytes),
                Arc::from(pspec),
                Arc::from(arch_name),
                Arc::clone(&arch),
            )
        });

        Ok(Self {
            program_counter: program_counter_from_pspec(pspec),
            sleigh: RefCell::new(sleigh),
            reg_name_map,
            space_map: extracted.space_map,
            arch,
            modelled_user_ops,
            authority,
            // No stamp is zero, so a fresh specification continues nothing.
            decode_state: Cell::new(0),
        })
    }
}

/// Load an embedded specification.
///
/// This is the cold embedded path. Session work uses the thread-local owner in
/// `Disassembler::shared_loaded_profile`; keeping this constructor separate
/// provides an intentionally independent instance for controls and callers
/// that need a distinct authority.
fn load_embedded_specification(
    sla_bytes: &'static [u8],
    pspec: &'static str,
    arch_name: &'static str,
) -> Result<Rc<LoadedSpecification>> {
    Ok(Rc::new(LoadedSpecification::load(
        sla_bytes, pspec, arch_name, true,
    )?))
}

/// One load, giving both the architecture the plugin wants and the
/// disassembler beside it.
///
/// These were two hand-written parses of the same bytes -- `build_arch_spec`
/// for the architecture and `from_sla` for the disassembler -- inside one
/// `create_disassembler_for_arch`. Sharing them is safe where sharing an
/// instance across callers is not: this is one load handed to one caller, so
/// there is no second consumer to see a decode cached by the first.
///
/// The architecture carries the processor spec's program counter, which
/// `extract_architecture` alone does not set and the disassembler tracks
/// separately.
pub fn embedded_arch_and_disassembler(
    sla_bytes: &'static [u8],
    pspec: &'static str,
    arch_name: &'static str,
) -> Result<(r2il::ArchSpec, Disassembler)> {
    let spec = load_embedded_specification(sla_bytes, pspec, arch_name)?;
    let mut arch = (*spec.arch).clone();
    arch.program_counter = crate::sleigh::processor_spec_program_counter(pspec);
    Ok((arch, Disassembler::wrap(spec, arch_name, None)))
}

/// One architecture's embedded Sleigh data, chosen by name.
///
/// The selection was written out three times -- in the plugin, in the command
/// line tool and in the shell -- and each copy knew a different subset. It is
/// one table here, and it is also the only place that knows which compiler
/// specification goes with which processor.
pub struct EmbeddedMachine {
    pub arch: r2il::ArchSpec,
    pub disasm: Disassembler,
    /// Ghidra's compiler specification, which names the stack pointer.
    pub compiler_spec: &'static str,
    /// The processor context this machine decodes in, as the snapshot's
    /// machine tuple spells it: `arm` and `thumb` share one instruction set
    /// and one architecture name, and only this tells the trusted lift apart.
    pub cpu: &'static str,
}

/// Load the embedded machine an architecture name selects.
///
/// The compiler specification is the one for the platform's usual toolchain.
/// Today only the stack pointer is read from it, and every specification for
/// one processor agrees about that; the prototype models, which do differ, are
/// not read here.
pub fn embedded_machine(arch_name: &str) -> Result<EmbeddedMachine> {
    let (sla, pspec, cspec, name, cpu) = embedded_specification(&arch_name.to_ascii_lowercase())
        .ok_or_else(|| {
            LiftError::Unsupported(format!("no embedded Sleigh specification for {arch_name}"))
        })?;
    let (arch, disasm) = embedded_arch_and_disassembler(sla, pspec, name)?;
    Ok(EmbeddedMachine {
        arch,
        disasm,
        compiler_spec: cspec,
        cpu,
    })
}

/// The Thumb decoder of an architecture that has one: ARM's second processor
/// context, which Ghidra ships as the same language with TMode set.
pub fn embedded_thumb_machine(arch_name: &str) -> Option<Result<EmbeddedMachine>> {
    match arch_name.to_ascii_lowercase().as_str() {
        "arm" | "arm32" => Some(embedded_machine("arm-thumb")),
        _ => None,
    }
}

/// The embedded data one lower-cased architecture name selects, if any is
/// compiled in for it.
type EmbeddedSpecification = (
    &'static [u8],
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

fn embedded_specification(arch_name: &str) -> Option<EmbeddedSpecification> {
    match arch_name {
        #[cfg(feature = "x86")]
        "x86-64" | "x86_64" | "x64" | "amd64" => Some((
            sleigh_config::processor_x86::SLA_X86_64,
            sleigh_config::processor_x86::PSPEC_X86_64,
            sleigh_config::processor_x86::CSPEC_X86_64_GCC,
            "x86-64",
            "x86",
        )),
        #[cfg(feature = "x86")]
        "x86" | "x86-32" | "i386" | "i686" => Some((
            sleigh_config::processor_x86::SLA_X86,
            sleigh_config::processor_x86::PSPEC_X86,
            sleigh_config::processor_x86::CSPEC_X86GCC,
            "x86",
            "x86",
        )),
        #[cfg(feature = "arm")]
        "aarch64" | "arm64" | "arm64e" => Some((
            sleigh_config::processor_aarch64::SLA_AARCH64_APPLESILICON,
            sleigh_config::processor_aarch64::PSPEC_AARCH64,
            sleigh_config::processor_aarch64::CSPEC_AARCH64,
            "aarch64",
            "arm",
        )),
        #[cfg(feature = "arm")]
        "arm" | "arm32" => Some((
            sleigh_config::processor_arm::SLA_ARM8_LE,
            sleigh_config::processor_arm::PSPEC_ARMT,
            sleigh_config::processor_arm::CSPEC_ARM,
            "ARM",
            "arm",
        )),
        // The same instruction set with TMode set, which is how Ghidra itself
        // ships a Thumb decoder: one language, two processor contexts.
        #[cfg(feature = "arm")]
        "arm-thumb" | "thumb" => Some((
            sleigh_config::processor_arm::SLA_ARM8_LE,
            sleigh_config::processor_arm::PSPEC_ARMTTHUMB,
            sleigh_config::processor_arm::CSPEC_ARM,
            "ARM",
            "thumb",
        )),
        _ => None,
    }
}

impl Disassembler {
    fn from_sla_parts(
        sla_bytes: &[u8],
        pspec: &str,
        arch_name: &str,
        trusted_profile: Option<TrustedSleighProfile>,
    ) -> Result<Self> {
        // Caller-supplied bytes: loaded on their own and never cached, because
        // nothing here can promise they outlive the cache.
        let spec = Rc::new(LoadedSpecification::load(
            sla_bytes,
            pspec,
            arch_name,
            trusted_profile.is_some(),
        )?);
        Ok(Self::wrap(spec, arch_name, trusted_profile))
    }

    /// Wrap a specification with one caller's identity. Everything expensive
    /// already happened; this is an `Rc` clone and a name.
    fn wrap(
        spec: Rc<LoadedSpecification>,
        arch_name: &str,
        trusted_profile: Option<TrustedSleighProfile>,
    ) -> Self {
        let genuine_authority = trusted_profile.and_then(|_| spec.authority.clone());
        Self {
            spec,
            arch_name: arch_name.to_string(),
            genuine_authority,
            trusted_profile,
        }
    }

    /// Construct from a pinned, embedded processor specification.
    ///
    /// This cold path mints an independent genuine lift authority. Prefer
    /// [`Self::shared_trusted_profile`] for session work.
    pub fn from_trusted_profile(profile: TrustedSleighProfile) -> Result<Self> {
        let (sla_bytes, pspec, arch_name) = profile.specification();
        let spec = load_embedded_specification(sla_bytes, pspec, arch_name)?;
        Ok(Self::wrap(spec, arch_name, Some(profile)))
    }

    /// The sole owner of a loaded embedded profile on this thread.
    ///
    /// Parsing the compiled specification dominates lifting cost. The C++
    /// instance cannot cross threads, so each lifting thread retains at most
    /// one parse per trusted embedded profile. Its address-keyed decode state
    /// is cleared once at every public byte-source boundary before reuse.
    fn shared_loaded_profile(profile: TrustedSleighProfile) -> Result<Rc<LoadedSpecification>> {
        thread_local! {
            static LOADED: RefCell<HashMap<TrustedSleighProfile, Rc<LoadedSpecification>>> =
                RefCell::new(HashMap::new());
        }

        if let Some(spec) = LOADED.with(|loaded| loaded.borrow().get(&profile).map(Rc::clone)) {
            return Ok(spec);
        }

        // Load outside the map borrow: construction is fallible and must not
        // leave the thread-local cache mutably borrowed while it runs.
        let (sla_bytes, pspec, arch_name) = profile.specification();
        let spec = load_embedded_specification(sla_bytes, pspec, arch_name)?;
        LOADED.with(|loaded| {
            loaded.borrow_mut().insert(profile, Rc::clone(&spec));
        });
        Ok(spec)
    }

    /// A certifying view of the thread-owned embedded profile.
    pub fn shared_trusted_profile(profile: TrustedSleighProfile) -> Result<Self> {
        let (_, _, arch_name) = profile.specification();
        Ok(Self::wrap(
            Self::shared_loaded_profile(profile)?,
            arch_name,
            Some(profile),
        ))
    }

    /// A non-certifying view of the thread-owned embedded profile.
    ///
    /// This is for consumers such as the radare2 architecture context: their
    /// input bytes are not the source-owned snapshot required for authority.
    pub fn shared_profile_for_analysis(profile: TrustedSleighProfile) -> Result<Self> {
        let (_, _, arch_name) = profile.specification();
        Ok(Self::wrap(
            Self::shared_loaded_profile(profile)?,
            arch_name,
            None,
        ))
    }

    /// One shared load, giving the plugin its processor-qualified architecture
    /// and a non-certifying disassembler view beside it.
    pub fn shared_arch_and_disassembler(
        profile: TrustedSleighProfile,
    ) -> Result<(r2il::ArchSpec, Self)> {
        let (_, pspec, _) = profile.specification();
        let disassembler = Self::shared_profile_for_analysis(profile)?;
        let mut arch = disassembler.arch_spec().clone();
        arch.program_counter = crate::sleigh::processor_spec_program_counter(pspec);
        Ok((arch, disassembler))
    }

    /// Whether two views use the exact same parsed C++ Sleigh instance.
    pub fn shares_loaded_specification(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.spec, &other.spec)
    }

    /// Architecture metadata extracted from this loaded specification.
    pub fn arch_spec(&self) -> &r2il::ArchSpec {
        &self.spec.arch
    }

    /// Lift every byte of one opaque source capture with the one exact embedded
    /// profile selected by its owned machine tuple.
    pub fn lift_owned_function(source: OwnedFunctionSnapshot) -> Result<TrustedLiftedFunction> {
        let profile = TrustedSleighProfile::from_machine(source.machine())?;
        let disassembler = Self::shared_trusted_profile(profile)?;
        if disassembler.trusted_profile != Some(profile) {
            return Err(LiftError::Unsupported(
                "trusted profile identity was lost while loading Sleigh".to_string(),
            ));
        }
        let trusted_arch = disassembler
            .genuine_authority
            .as_ref()
            .map(GenuineLiftAuthority::arch_spec)
            .ok_or_else(|| {
                LiftError::Unsupported(
                    "trusted lift lost its exact architecture authority".to_string(),
                )
            })?;
        // The capture's carriers are restated in this architecture's numbering
        // before anything reads them, including the agreement check below.
        let source = arch_resolved_source(source, trusted_arch)?;
        // Lifting is a function of the machine tuple and the image bytes; the
        // function interface is evidence about the ABI and is never read below.
        // An absent interface is therefore a fact about the source, not a lift
        // failure, and the obligations that depend on it residualize downstream
        // instead of suppressing the whole function.
        //
        // A present interface must still agree with the machine that was
        // actually lifted, because an interface contradicting the machine is
        // wrong rather than merely missing. Agreement between the interface and
        // the captured field flags is already an invariant established when the
        // snapshot is constructed, so it is not re-checked here.
        if let Some(interface) = source.function_interface()
            && (!captured_frame_pointer_storage_matches_arch(interface, trusted_arch)
                || !captured_return_mechanism_matches_arch(interface, trusted_arch))
        {
            return Err(LiftError::Unsupported(
                "captured frame/return mechanism conflicts with the exact lifted machine"
                    .to_string(),
            ));
        }
        let mut ranges = Vec::with_capacity(source.image().blocks().len());
        let mut blocks = Vec::with_capacity(source.image().blocks().len());
        // The register a call returns through, in the coordinates the lift
        // spells. Absent on a machine that pushes the return address instead.
        let link = source
            .machine_roles()
            .return_address_storage()
            .filter(|storage| storage.space == r2source::CanonicalStorageSpace::Register)
            .map(|storage| r2il::Varnode {
                space: r2il::SpaceId::Register,
                offset: storage.offset,
                size: storage.size,
                meta: None,
            });
        for block in source.image().blocks() {
            let size = u32::try_from(block.bytes().len()).map_err(|_| {
                LiftError::Parse("owned source block exceeds r2il size range".to_string())
            })?;
            ranges.push(GenuineFunctionBlockRange::new(block.address(), size));
            let mut lifted_block = disassembler.lift_genuine_block(
                block.bytes(),
                block.address(),
                block.bytes().len(),
            )?;
            // radare2 resolves jump tables, and the snapshot carries what it
            // found as switch-case successors. Lifting reads only the bytes, so
            // without this the dispatch arrives as an indirect branch with no
            // targets and the renderer says so and drops the rest of the
            // function: `murmur3_32` rendered four statements of thirty-five and
            // no return at all, because its tail switch on `len & 3` was thrown
            // away between the snapshot and the lift.
            if let Some(switch_addr) = block.switch_instruction() {
                let cases: Vec<r2il::SwitchCase> = block
                    .successors()
                    .iter()
                    .filter(|successor| {
                        successor.kind() == r2source::AdvisorySuccessorKind::SwitchCase
                    })
                    .filter_map(|successor| {
                        successor.case_value().map(|value| r2il::SwitchCase {
                            value,
                            target: successor.target(),
                        })
                    })
                    .collect();
                if !cases.is_empty() {
                    let default_target = block
                        .successors()
                        .iter()
                        .find(|successor| {
                            successor.kind() == r2source::AdvisorySuccessorKind::SwitchDefault
                        })
                        .map(|successor| successor.target());
                    lifted_block.block.switch_info = Some(r2il::SwitchInfo {
                        switch_addr,
                        default_target,
                        cases,
                    });
                }
            }
            // Sleigh lifts `sub pc, r3, 0x3f` as a branch, because that is
            // the opcode. What makes it a call is the return address the
            // block left in the link register: control comes back, and every
            // derivation below reads the operation to know that.
            if let Some(link) = link.as_ref() {
                let next = lifted_block
                    .block
                    .addr
                    .wrapping_add(u64::from(lifted_block.block.size));
                if r2il::returns_to(&lifted_block.block.ops, next, link)
                    && let Some(last) = lifted_block
                        .block
                        .ops
                        .iter()
                        .rposition(|op| matches!(op, r2il::R2ILOp::BranchInd { .. }))
                    && let r2il::R2ILOp::BranchInd { target } = lifted_block.block.ops[last].clone()
                {
                    lifted_block.block.ops[last] = r2il::R2ILOp::CallInd { target };
                }
            }
            blocks.push(lifted_block);
        }
        validate_owned_snapshot_cfg(&source, &blocks)?;
        let layout = GenuineFunctionLayout::new(
            source.source_revision_identity(),
            source.image().entry_address(),
            ranges,
            source.image().external_exits().iter().copied(),
        )?;
        let lifted = GenuineLiftedFunction::try_from_layout(layout, blocks)?;
        Ok(TrustedLiftedFunction { source, lifted })
    }

    /// Create an analysis-only disassembler from caller-provided specification bytes.
    ///
    /// This constructor never mints certification authority, even when the
    /// bytes happen to equal an embedded trusted profile. Use
    /// [`Self::from_trusted_profile`] for the certifying path.
    ///
    /// # Arguments
    ///
    /// * `sla_bytes` - The compiled .sla file contents
    /// * `pspec` - The processor specification XML string
    /// * `arch_name` - Name of the architecture
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use r2sleigh_lift::disasm::Disassembler;
    ///
    /// // Using sleigh-config precompiled data
    /// let disasm = Disassembler::from_sla(
    ///     include_bytes!("x86-64.sla"),
    ///     include_str!("x86-64.pspec"),
    ///     "x86-64"
    /// )?;
    /// ```
    pub fn from_sla(sla_bytes: &[u8], pspec: &str, arch_name: &str) -> Result<Self> {
        Self::from_sla_parts(sla_bytes, pspec, arch_name, None)
    }

    /// Get the architecture name.
    pub fn arch_name(&self) -> &str {
        &self.arch_name
    }

    /// The register this processor uses as its program counter.
    ///
    /// Taken from the processor spec rather than assumed, because it is `RIP`
    /// on x86-64, `EIP` on x86 and 16-bit, and `pc` on ARM, MIPS and RISC-V.
    /// Writing a branch target to the wrong name leaves the branch with no
    /// effect at all.
    pub fn program_counter(&self) -> &str {
        &self.spec.program_counter
    }

    /// Get the default code address space.
    pub fn default_code_space(&self) -> AddressSpace {
        self.spec.sleigh.borrow().default_code_space()
    }

    /// List all address spaces.
    pub fn address_spaces(&self) -> Vec<AddressSpace> {
        self.spec.sleigh.borrow().address_spaces()
    }

    /// Get a register's varnode data by name.
    pub fn register(&self, name: &str) -> Result<VarnodeData> {
        self.spec
            .sleigh
            .borrow()
            .register_from_name(name)
            .map_err(|e| LiftError::Parse(format!("Unknown register '{}': {}", name, e)))
    }

    /// Get the register name for a varnode in the register space.
    ///
    /// Returns `None` if the varnode is not in the register space or if
    /// no register name is found for the given offset and size.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let vn = Varnode::register(0x20, 8); // RSP on x86-64
    /// let name = disasm.register_name(&vn);
    /// assert_eq!(name, Some("RSP".to_string()));
    /// ```
    pub fn register_name(&self, vn: &Varnode) -> Option<String> {
        self.register_spelling(vn).map(std::borrow::Cow::into_owned)
    }

    /// The register's name, borrowed when the architecture already holds it.
    ///
    /// Every varnode the lifter reads asks this, and copying the stored name
    /// for each was one allocation per operand of every instruction.
    pub fn register_spelling(&self, vn: &Varnode) -> Option<std::borrow::Cow<'_, str>> {
        if vn.space != SpaceId::Register {
            return None;
        }

        if let Some(name) = self.spec.reg_name_map.get(&(vn.offset, vn.size)) {
            return Some(std::borrow::Cow::Borrowed(name.as_str()));
        }

        // Get the register address space
        let sleigh = self.spec.sleigh.borrow();
        let reg_space = sleigh.address_space_by_name("register")?;

        // Create a VarnodeData to query libsla
        let varnode_data = VarnodeData::new(Address::new(reg_space, vn.offset), vn.size as usize);

        sleigh
            .register_name(&varnode_data)
            .map(std::borrow::Cow::Owned)
    }

    /// Format a varnode as a human-readable string, resolving register names.
    ///
    /// This is useful for pretty-printing P-code operations.
    pub fn format_varnode(&self, vn: &Varnode) -> String {
        match vn.space {
            SpaceId::Const => format!("0x{:x}", vn.offset),
            SpaceId::Register => {
                // Try to resolve the register name
                if let Some(name) = self.register_name(vn) {
                    name
                } else {
                    format!("reg:0x{:x}:{}", vn.offset, vn.size)
                }
            }
            SpaceId::Unique => format!("tmp:0x{:x}", vn.offset),
            SpaceId::Ram => format!("[0x{:x}]:{}", vn.offset, vn.size),
            SpaceId::Custom(n) => format!("space{}:0x{:x}", n, vn.offset),
        }
    }

    /// Disassemble instruction bytes at a given address and return r2il.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Instruction bytes to disassemble
    /// * `addr` - Address where the instruction is located
    ///
    /// # Returns
    ///
    /// An `R2ILBlock` containing the translated operations, or an error.
    ///
    /// Note: This lifts a **single instruction**. Use `lift_block` to lift
    /// multiple instructions within a basic block.
    pub fn lift(&self, bytes: &[u8], addr: u64) -> Result<R2ILBlock> {
        self.clear_decode_cache()?;
        self.lift_canonical(bytes, addr)
    }

    /// Lift one instruction, keeping the context `after` left where it still holds.
    ///
    /// Some of that context is the meaning of what comes next: Thumb's `it`
    /// sets the condition the following instructions run under, and a decoder
    /// that starts afresh reads them as unconditional. A walk that lifts one
    /// instruction at a time therefore saw a different program from the block
    /// lift that reads the same bytes in a run -- unconditional where the
    /// machine is predicated -- and the two disagreed about where control
    /// goes.
    pub fn lift_after(
        &self,
        bytes: &[u8],
        addr: u64,
        after: Option<Continuation>,
    ) -> Result<(R2ILBlock, Continuation)> {
        self.resume(addr, after)?;
        let lifted = self.lift_canonical(bytes, addr)?;
        let end = addr + u64::from(lifted.size);
        Ok((lifted, self.continuation(end)))
    }

    /// Keep the context `after` left if it is this specification's last decode and ended at `addr`, else start afresh.
    fn resume(&self, addr: u64, after: Option<Continuation>) -> Result<()> {
        let holds = after.is_some_and(|after| {
            after.end == addr && after.decode_state == self.spec.decode_state.get()
        });
        match holds {
            true => Ok(()),
            false => self.clear_decode_cache(),
        }
    }

    /// The context the decode just made leaves, for an instruction ending at `end`.
    fn continuation(&self, end: u64) -> Continuation {
        Continuation {
            decode_state: self.spec.decode_state.get(),
            end,
        }
    }

    /// Begin one opaque lift against a caller-provided byte source.
    ///
    /// Sleigh may reuse parser contexts within this lift for delay slots and
    /// cross-builds because every read still belongs to the same source. The
    /// cache is invalidated once here, before another source can observe an
    /// address retained by an earlier caller.
    fn clear_decode_cache(&self) -> Result<()> {
        self.spec.change_decode_state();
        self.spec
            .sleigh
            .borrow_mut()
            .clear_cache()
            .map_err(|e| LiftError::Parse(format!("Failed to clear decode cache: {e}")))
    }

    /// Translate exactly the Sleigh-produced P-code plus the local label
    /// normalization required to preserve the instruction's control graph.
    /// No mnemonic, user-op name, or inferred metadata participates.
    fn lift_canonical(&self, bytes: &[u8], addr: u64) -> Result<R2ILBlock> {
        self.translated(self.pcode(bytes, addr)?, addr)
    }

    /// Sleigh's P-code for the instruction at `addr`; building it commits the parse's context.
    fn pcode(&self, bytes: &[u8], addr: u64) -> Result<PcodeDisassembly> {
        self.spec.change_decode_state();
        let sleigh = self.spec.sleigh.borrow();
        let address = Address::new(sleigh.default_code_space(), addr);
        let loader = ByteLoader::new(bytes, addr);
        sleigh
            .disassemble_pcode(&loader, address)
            .map_err(|e| LiftError::Parse(format!("Disassembly failed: {e}")))
    }

    /// One instruction's P-code as r2il, with its local labels normalized.
    fn translated(&self, pcode: PcodeDisassembly, addr: u64) -> Result<R2ILBlock> {
        let mut block = self.translate_pcode(pcode, addr)?;
        crate::internal_control::normalize_instruction_local_control(&mut block, &|userop| {
            self.user_op_name(userop).map(str::to_owned)
        });
        Ok(block)
    }

    /// Minimum bytes required by libsla for disassembly.
    const MIN_BYTES: usize = 16;

    /// Lift an entire basic block (multiple instructions) to r2il.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Instruction bytes for the entire block (should be at least 16 bytes for libsla)
    /// * `addr` - Starting address of the block
    /// * `block_size` - Size of the block in bytes
    ///
    /// # Returns
    ///
    /// An `R2ILBlock` containing operations from all instructions in the block.
    pub fn lift_block(&self, bytes: &[u8], addr: u64, block_size: usize) -> Result<R2ILBlock> {
        self.lift_block_with_policy_and_spans(bytes, addr, block_size, Undecodable::EndsBlock)
            .map(|(block, _)| block)
    }

    fn lift_block_with_policy_and_spans(
        &self,
        bytes: &[u8],
        addr: u64,
        block_size: usize,
        undecodable: Undecodable,
    ) -> Result<(R2ILBlock, Vec<GenuineInstructionSpan>)> {
        self.clear_decode_cache()?;
        u32::try_from(block_size)
            .map_err(|_| LiftError::Parse("block size exceeds r2il range".to_string()))?;
        let mut parts: Vec<R2ILBlock> = Vec::new();
        let mut op_count = 0usize;
        let mut instruction_spans = Vec::new();
        let mut offset = 0usize;

        while offset < block_size {
            let remaining = &bytes[offset..];
            if remaining.is_empty() {
                break;
            }

            let offset_u64 = u64::try_from(offset)
                .map_err(|_| LiftError::Parse("instruction offset exceeds u64".to_string()))?;
            let instr_addr = addr
                .checked_add(offset_u64)
                .ok_or_else(|| LiftError::Parse("instruction address overflows".to_string()))?;

            // libsla requires at least 16 bytes; pad if necessary
            let lift_bytes: Vec<u8> = if remaining.len() < Self::MIN_BYTES {
                let mut padded = remaining.to_vec();
                padded.resize(Self::MIN_BYTES, 0);
                padded
            } else {
                remaining.to_vec()
            };

            match self.lift_canonical(&lift_bytes, instr_addr) {
                Ok(instr_block) => {
                    let instr_size = instr_block.size as usize;
                    if instr_size == 0 {
                        // Prevent infinite loop on zero-size instruction
                        break;
                    }
                    let first_canonical_op = u64::try_from(op_count).map_err(|_| {
                        LiftError::Parse("canonical P-code index exceeds u64".to_string())
                    })?;
                    let canonical_op_count =
                        u64::try_from(instr_block.ops.len()).map_err(|_| {
                            LiftError::Parse("canonical P-code count exceeds u64".to_string())
                        })?;
                    instruction_spans.push(GenuineInstructionSpan {
                        addr: instr_addr,
                        size: instr_block.size,
                        first_canonical_op,
                        canonical_op_count,
                    });

                    op_count += instr_block.ops.len();
                    parts.push(instr_block);
                    offset += instr_size;
                }
                Err(error) if undecodable == Undecodable::Refuses => return Err(error),
                Err(_) => {
                    // Stop on disassembly error (e.g., invalid instruction)
                    break;
                }
            }
        }

        // The size is what the instructions consumed, not what was asked for.
        let consumed = u32::try_from(offset)
            .map_err(|_| LiftError::Parse("lifted block size exceeds r2il range".to_string()))?;

        Ok((R2ILBlock::join(addr, consumed, parts), instruction_spans))
    }

    /// Lift one complete block and retain unforgeable, immutable origin.
    pub fn lift_genuine_block(
        &self,
        bytes: &[u8],
        addr: u64,
        block_size: usize,
    ) -> Result<GenuineLiftedBlock> {
        if block_size == 0 || block_size > bytes.len() {
            return Err(LiftError::Parse(
                "genuine lift requires a nonempty in-bounds block".to_string(),
            ));
        }
        let authority = self.genuine_authority.clone().ok_or_else(|| {
            LiftError::Unsupported(
                "genuine lift requires an embedded trusted Sleigh profile".to_string(),
            )
        })?;
        let (block, instruction_spans) =
            self.lift_block_with_policy_and_spans(bytes, addr, block_size, Undecodable::Refuses)?;
        if usize::try_from(block.size) != Ok(block_size) {
            return Err(LiftError::Parse(format!(
                "genuine lift consumed {} of {block_size} requested bytes",
                block.size
            )));
        }
        Ok(GenuineLiftedBlock {
            authority,
            block,
            source_bytes: Arc::from(&bytes[..block_size]),
            instruction_spans: instruction_spans.into(),
        })
    }

    /// Disassemble and get native assembly mnemonic.
    pub fn disasm_native(&self, bytes: &[u8], addr: u64) -> Result<(String, usize)> {
        let (mnemonic, body, size) = self.disasm_parts(bytes, addr)?;
        Ok((format!("{mnemonic} {body}").trim().to_string(), size))
    }

    /// Spell and lift one instruction from one Sleigh parse, keeping the context `after` left where it still holds.
    ///
    /// The decoder knows which architecture it decodes and where each number
    /// in the operands is written, so it says both rather than handing out a
    /// line for someone else to parse back apart.
    pub fn decode(&self, bytes: &[u8], addr: u64, after: Option<Continuation>) -> Result<Decoded> {
        self.resume(addr, after)?;
        let (mnemonic, body, size) = self.native_parts(bytes, addr)?;
        let syntax = syntax::radare2(&mnemonic, &body, size, &self.arch_name);
        // The P-code is built from the parse just printed, and a finished build is what is known to commit its context.
        let pcode = self.pcode(bytes, addr);
        let end = addr + size as u64;
        let continuation = pcode.is_ok().then(|| self.continuation(end));
        Ok(Decoded {
            syntax,
            lifted: pcode.and_then(|pcode| self.translated(pcode, addr)),
            continuation,
        })
    }

    /// One instruction's operation and operands, as Sleigh itself spells them.
    fn disasm_parts(&self, bytes: &[u8], addr: u64) -> Result<(String, String, usize)> {
        self.clear_decode_cache()?;
        self.native_parts(bytes, addr)
    }

    /// Sleigh's own spelling of the instruction at `addr`, in whatever context the decoder holds.
    fn native_parts(&self, bytes: &[u8], addr: u64) -> Result<(String, String, usize)> {
        self.spec.change_decode_state();
        let sleigh = self.spec.sleigh.borrow();
        let code_space = sleigh.default_code_space();
        let address = Address::new(code_space, addr);
        let loader = ByteLoader::new(bytes, addr);

        let native = sleigh
            .disassemble_native(&loader, address)
            .map_err(|e| LiftError::Parse(format!("Disassembly failed: {}", e)))?;

        Ok((
            native.instruction.mnemonic,
            native.instruction.body,
            native.origin.size,
        ))
    }

    /// Translate a P-code disassembly to an r2il block.
    fn translate_pcode(&self, pcode: PcodeDisassembly, addr: u64) -> Result<R2ILBlock> {
        let instr_size = pcode.origin.size as u32;
        let mut block = R2ILBlock::new(addr, instr_size);

        let mut ops = Vec::with_capacity(pcode.instructions.len());
        for pcode_instr in pcode.instructions {
            if let Some(op) = self.translate_pcode_op(&pcode_instr)? {
                ops.push(op);
            }
        }

        // Where an expansion's own temporaries may live: above every temporary
        // this instruction already uses. Sleigh scopes the unique space to the
        // instruction, so that is the whole extent an expansion has to stay
        // clear of, and taking it from the instruction itself means there is no
        // offset to guess and nothing to collide with.
        let mut temp_base = ops
            .iter()
            .flat_map(|op| op.output().into_iter().chain(op.inputs()))
            .filter(|varnode| varnode.space == SpaceId::Unique)
            .filter_map(|varnode| varnode.offset.checked_add(u64::from(varnode.size)))
            .max()
            .unwrap_or(0);
        let address_size = u32::try_from(self.default_code_space().address_size)
            .map_err(|_| LiftError::Parse("default code space address size".into()))?;
        let ops = translate::canonicalize_memory_operands(ops, address_size, &mut temp_base);

        // A trap ends the instruction. Sleigh writes `brk` as a user operation
        // that produces `pc` followed by a branch through it, so the branch's
        // only definition of its target is the trap itself; expanding the trap
        // into `Breakpoint`, which produces nothing, would leave that branch
        // reading a `pc` nothing defines. Control does not reach it either way
        // -- the exception is taken at the trap and does not come back -- so
        // the operations Sleigh writes after it in the same instruction are not
        // executed, and dropping them is what the machine does.
        for op in ops {
            for expanded in self.expand_user_operation(op, temp_base) {
                let traps = matches!(expanded, R2ILOp::Breakpoint);
                block.push(expanded);
                if traps {
                    return Ok(block);
                }
            }
        }

        Ok(block)
    }

    /// The name the architecture gives the user-defined operation at `index`.
    /// Read from the specification rather than from the trust profile: what
    /// an operation is called is data the specification carries. Which of
    /// them this lift models is resolved from the same table once, when the
    /// specification is loaded, into `LoadedSpecification::modelled_user_ops`.
    fn user_op_name(&self, index: u32) -> Option<&str> {
        self.spec
            .arch
            .user_ops
            .get(index as usize)
            .map(String::as_str)
    }

    /// Give a user-defined operation its semantics, where the architecture
    /// names one this lift models.
    ///
    /// A `CallOther` carries no semantics at all, so everything downstream can
    /// only refuse the instruction and, with it, the function. Where the
    /// operation's meaning is exactly expressible in the ordinary vocabulary,
    /// expanding it here is what keeps the rest of the pipeline free of any
    /// vector-specific machinery. An operation this does not model, or one
    /// whose operands are not the shape its model states, is returned
    /// untouched and still refuses, which is the honest answer.
    ///
    /// Which operation an index names was resolved once, when the
    /// specification was loaded; this is one lookup.
    fn expand_user_operation(&self, op: R2ILOp, temp_base: u64) -> Vec<R2ILOp> {
        let R2ILOp::CallOther {
            userop,
            output,
            inputs,
        } = &op
        else {
            return vec![op];
        };
        let modelled = usize::try_from(*userop)
            .ok()
            .and_then(|index| self.spec.modelled_user_ops.get(index))
            .copied()
            .flatten();
        let output = output.as_ref();
        let expanded = match modelled {
            Some(ModelledUserOperation::NeonExt) => {
                Self::expand_neon_ext(output, inputs, temp_base)
            }
            Some(ModelledUserOperation::NeonUshl) => {
                Self::expand_neon_ushl(output, inputs, temp_base)
            }
            Some(ModelledUserOperation::NeonRev64) => {
                Self::expand_neon_rev64(output, inputs, temp_base)
            }
            Some(ModelledUserOperation::NeonMinMax { max }) => {
                Self::expand_neon_minmax(output, inputs, temp_base, max)
            }
            Some(ModelledUserOperation::NeonMinMaxAcross { max }) => {
                Self::expand_neon_minmax_across(output, inputs, temp_base, max)
            }
            Some(ModelledUserOperation::A64Tbl) => Self::expand_neon_tbl(output, inputs, temp_base),
            // A trap, and the pipeline already has one. `R2ILOp::Breakpoint` is
            // seeded as `Kind::Trap` by the obligation ledger, which is exactly
            // what these are: control leaves for an exception handler and does
            // not come back. Sleigh models that as a user-operation writing
            // `pc`, which nothing downstream could project, so the whole
            // function refused.
            //
            // The trap code -- `brk 0xc471`'s immediate, say -- is dropped,
            // because `R2ILOp::Breakpoint` carries no operands. It identifies
            // which check failed and is still in the disassembly; what matters
            // for rendering is that control stops here, and that is preserved
            // exactly.
            Some(ModelledUserOperation::Trap) => Some(vec![R2ILOp::Breakpoint]),
            // ARM `bx` switches instruction set by the target's low bit. The
            // p-code has already written the mode bit and masked the target
            // by the time this fires, so the operation itself spells nothing
            // more; which set a body decodes in is the function's own fact.
            Some(ModelledUserOperation::SetIsaMode) => Some(Vec::new()),
            Some(ModelledUserOperation::PackedExtension(extension)) => {
                Self::expand_packed_extension(output, inputs, temp_base, extension)
            }
            None => None,
        };
        expanded.unwrap_or_else(|| vec![op])
    }

    /// x86 `PMOVSX*` / `PMOVZX*`, in each encoding the specification names.
    ///
    /// Intel SDM, PMOVSX and PMOVZX, Operation: element `i` of the
    /// destination is element `i` of the source's low part, sign- or
    /// zero-extended -- `DEST[31:0] <- SignExtend(SRC[7:0])` up to
    /// `DEST[127:96] <- SignExtend(SRC[31:24])` for `PMOVSXBD`. So, with `L`
    /// elements of `d` bytes from elements of `s` bytes,
    ///
    /// `output = PIECE(i = L-1..0) EXT(SUBPIECE(source, i*s, s))`.
    ///
    /// The shape is the encoding's own, exactly:
    ///
    /// * legacy SSE4.1 is written `XmmReg = pmovsxbd(XmmReg, src)`. The first
    ///   operand is the old destination, and it is dropped only because it *is*
    ///   the destination -- the same varnode as the output -- and the
    ///   instruction defines every bit of that register from the source;
    /// * the VEX and EVEX forms pass the source alone, and produce the width
    ///   their encoding states.
    ///
    /// `L` is a power of two of at least two, and the source holds at least
    /// `L*s` bytes. Anything else is not the operation this models and is left
    /// to refuse.
    fn expand_packed_extension(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
        extension: PackedExtension,
    ) -> Option<Vec<R2ILOp>> {
        let output = output?;
        let source = match inputs {
            [old_destination, source]
                if extension.form.passes_old_destination() && old_destination == output =>
            {
                source
            }
            [source] if !extension.form.passes_old_destination() => source,
            _ => return None,
        };
        let PackedExtension {
            from_bytes,
            to_bytes,
            extension: widening,
            form,
        } = extension;
        if !form.produces(output.size) || to_bytes == 0 || output.size % to_bytes != 0 {
            return None;
        }
        let lanes = output.size / to_bytes;
        if lanes < 2 || !lanes.is_power_of_two() || source.size < lanes.checked_mul(from_bytes)? {
            return None;
        }
        let mut ops = Vec::with_capacity(lanes as usize * 3);
        let mut next = temp_base;
        let mut widened = Vec::with_capacity(lanes as usize);
        for lane in 0..lanes {
            let element = Self::lane_temp(&mut next, from_bytes);
            ops.push(R2ILOp::Subpiece {
                dst: element.clone(),
                src: source.clone(),
                offset: lane * from_bytes,
            });
            let wide = Self::lane_temp(&mut next, to_bytes);
            ops.push(match widening {
                Extension::Sign => R2ILOp::IntSExt {
                    dst: wide.clone(),
                    src: element,
                },
                Extension::Zero => R2ILOp::IntZExt {
                    dst: wide.clone(),
                    src: element,
                },
            });
            widened.push(wide);
        }
        let composed = Self::join_lanes(&mut ops, &mut next, widened, to_bytes)?;
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: composed,
        });
        Some(ops)
    }

    /// `NEON_ext(rn, rm, index, element_size)` -- AArch64 `EXT`.
    ///
    /// The result is the vector's width of bytes taken from the concatenation
    /// of `rm` above `rn`, starting at byte `index`. As a whole-register value
    /// that is `rn` shifted down by `index` bytes with `rm` shifted up into the
    /// space it vacated.
    ///
    /// Only the byte-granular form is expanded, which is the only form the
    /// specification uses; anything else is left to refuse.
    fn expand_neon_ext(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
    ) -> Option<Vec<R2ILOp>> {
        let [rn, rm, index, element_size] = inputs else {
            return None;
        };
        let output = output?;
        if index.space != SpaceId::Const
            || element_size.space != SpaceId::Const
            || element_size.offset != 1
        {
            return None;
        }
        let width_bytes = u64::from(output.size);
        if output.size != rn.size || output.size != rm.size || width_bytes == 0 {
            return None;
        }
        let taken = index.offset;
        if taken == 0 {
            return Some(vec![R2ILOp::Copy {
                dst: output.clone(),
                src: rn.clone(),
            }]);
        }
        if taken >= width_bytes {
            return None;
        }
        let low = Varnode::unique(temp_base, output.size);
        let high = Varnode::unique(temp_base.checked_add(width_bytes)?, output.size);
        let down = Varnode::constant(taken * 8, output.size);
        let up = Varnode::constant((width_bytes - taken) * 8, output.size);
        Some(vec![
            R2ILOp::IntRight {
                dst: low.clone(),
                a: rn.clone(),
                b: down,
            },
            R2ILOp::IntLeft {
                dst: high.clone(),
                a: rm.clone(),
                b: up,
            },
            R2ILOp::IntOr {
                dst: output.clone(),
                a: low,
                b: high,
            },
        ])
    }

    /// A fresh temporary allocator over `temp_base`.
    fn lane_temp(next: &mut u64, size: u32) -> Varnode {
        let node = Varnode::unique(*next, size);
        *next += u64::from(size).max(1);
        node
    }

    /// The elements of a vector, low lane first.
    fn split_lanes(
        ops: &mut Vec<R2ILOp>,
        next: &mut u64,
        vector: &Varnode,
        lane_bytes: u32,
    ) -> Vec<Varnode> {
        (0..vector.size / lane_bytes)
            .map(|lane| {
                let value = Self::lane_temp(next, lane_bytes);
                ops.push(R2ILOp::Subpiece {
                    dst: value.clone(),
                    src: vector.clone(),
                    offset: lane * lane_bytes,
                });
                value
            })
            .collect()
    }

    /// The vector the elements make, recomposed pairwise until one is left.
    fn join_lanes(
        ops: &mut Vec<R2ILOp>,
        next: &mut u64,
        mut lanes: Vec<Varnode>,
        lane_bytes: u32,
    ) -> Option<Varnode> {
        let mut width = lane_bytes;
        while lanes.len() > 1 {
            let mut joined = Vec::with_capacity(lanes.len() / 2);
            for pair in lanes.chunks(2) {
                let [low, high] = pair else {
                    return None;
                };
                let wider = Self::lane_temp(next, width * 2);
                ops.push(R2ILOp::Piece {
                    dst: wider.clone(),
                    hi: high.clone(),
                    lo: low.clone(),
                });
                joined.push(wider);
            }
            lanes = joined;
            width *= 2;
        }
        lanes.pop()
    }

    /// The larger or smaller of two unsigned elements.
    fn lane_minmax(
        ops: &mut Vec<R2ILOp>,
        next: &mut u64,
        a: &Varnode,
        b: &Varnode,
        max: bool,
    ) -> Varnode {
        let less = Self::lane_temp(next, 1);
        ops.push(R2ILOp::IntLess {
            dst: less.clone(),
            a: a.clone(),
            b: b.clone(),
        });
        let chosen = Self::lane_temp(next, a.size);
        let (if_true, if_false) = if max { (b, a) } else { (a, b) };
        ops.push(R2ILOp::Select {
            dst: chosen.clone(),
            cond: less,
            if_true: if_true.clone(),
            if_false: if_false.clone(),
        });
        chosen
    }

    /// `NEON_umax(rn, rm, element_size)` / `NEON_umin` -- AArch64 `UMAX`, `UMIN`.
    fn expand_neon_minmax(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
        max: bool,
    ) -> Option<Vec<R2ILOp>> {
        let [rn, rm, element_size] = inputs else {
            return None;
        };
        let output = output?;
        if element_size.space != SpaceId::Const {
            return None;
        }
        let lane_bytes = u32::try_from(element_size.offset).ok()?;
        if lane_bytes == 0
            || output.size != rn.size
            || output.size != rm.size
            || output.size % lane_bytes != 0
        {
            return None;
        }
        let mut ops = Vec::new();
        let mut next = temp_base;
        let a = Self::split_lanes(&mut ops, &mut next, rn, lane_bytes);
        let b = Self::split_lanes(&mut ops, &mut next, rm, lane_bytes);
        let lanes = a
            .iter()
            .zip(&b)
            .map(|(a, b)| Self::lane_minmax(&mut ops, &mut next, a, b, max))
            .collect();
        let composed = Self::join_lanes(&mut ops, &mut next, lanes, lane_bytes)?;
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: composed,
        });
        Some(ops)
    }

    /// `NEON_umaxv(rn, element_size)` / `NEON_uminv` -- AArch64 `UMAXV`, `UMINV`.
    ///
    /// The result is one element: the largest or smallest across the vector.
    fn expand_neon_minmax_across(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
        max: bool,
    ) -> Option<Vec<R2ILOp>> {
        let [rn, element_size] = inputs else {
            return None;
        };
        let output = output?;
        if element_size.space != SpaceId::Const {
            return None;
        }
        let lane_bytes = u32::try_from(element_size.offset).ok()?;
        if lane_bytes == 0 || output.size != lane_bytes || rn.size % lane_bytes != 0 {
            return None;
        }
        let mut ops = Vec::new();
        let mut next = temp_base;
        let lanes = Self::split_lanes(&mut ops, &mut next, rn, lane_bytes);
        let mut lanes = lanes.into_iter();
        let mut best = lanes.next()?;
        for lane in lanes {
            best = Self::lane_minmax(&mut ops, &mut next, &best, &lane, max);
        }
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: best,
        });
        Some(ops)
    }

    /// `a64_TBL(fill, table, indices)` -- AArch64 `TBL` and `TBX` with one
    /// table register.
    ///
    /// Each result byte is the table byte its index names, or the fill byte
    /// when the index reaches past the table: zero for `TBL`, the old value
    /// for `TBX`. The forms that concatenate several table registers are not
    /// expanded.
    fn expand_neon_tbl(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
    ) -> Option<Vec<R2ILOp>> {
        let [fill, table, indices] = inputs else {
            return None;
        };
        let output = output?;
        if output.size != indices.size || output.size > fill.size || table.size != 16 {
            return None;
        }
        let table_bytes = u64::from(table.size);
        let mut ops = Vec::new();
        let mut next = temp_base;
        let index_lanes = Self::split_lanes(&mut ops, &mut next, indices, 1);
        let fill_lanes = Self::split_lanes(&mut ops, &mut next, fill, 1);
        let mut lanes = Vec::with_capacity(index_lanes.len());
        for (index, fill) in index_lanes.iter().zip(&fill_lanes) {
            let wide = Self::lane_temp(&mut next, table.size);
            ops.push(R2ILOp::IntZExt {
                dst: wide.clone(),
                src: index.clone(),
            });
            let distance = Self::lane_temp(&mut next, table.size);
            ops.push(R2ILOp::IntLeft {
                dst: distance.clone(),
                a: wide,
                b: Varnode::constant(3, table.size),
            });
            let shifted = Self::lane_temp(&mut next, table.size);
            ops.push(R2ILOp::IntRight {
                dst: shifted.clone(),
                a: table.clone(),
                b: distance,
            });
            let byte = Self::lane_temp(&mut next, 1);
            ops.push(R2ILOp::Subpiece {
                dst: byte.clone(),
                src: shifted,
                offset: 0,
            });
            let in_range = Self::lane_temp(&mut next, 1);
            ops.push(R2ILOp::IntLess {
                dst: in_range.clone(),
                a: index.clone(),
                b: Varnode::constant(table_bytes, 1),
            });
            let chosen = Self::lane_temp(&mut next, 1);
            ops.push(R2ILOp::Select {
                dst: chosen.clone(),
                cond: in_range,
                if_true: byte,
                if_false: fill.clone(),
            });
            lanes.push(chosen);
        }
        let composed = Self::join_lanes(&mut ops, &mut next, lanes, 1)?;
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: composed,
        });
        Some(ops)
    }

    /// `NEON_rev64(rn, element_size)` -- AArch64 `REV64`.
    ///
    /// Each 64-bit half of the vector has its elements reversed in place. The
    /// elements are extracted one by one and recomposed in the reversed order,
    /// the same way `USHL` recomposes its lanes.
    fn expand_neon_rev64(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
    ) -> Option<Vec<R2ILOp>> {
        let [rn, element_size] = inputs else {
            return None;
        };
        let output = output?;
        if element_size.space != SpaceId::Const {
            return None;
        }
        let lane_bytes = u32::try_from(element_size.offset).ok()?;
        if lane_bytes == 0
            || lane_bytes >= 8
            || 8 % lane_bytes != 0
            || output.size != rn.size
            || output.size % 8 != 0
        {
            return None;
        }
        let per_half = 8 / lane_bytes;
        let lanes = output.size / lane_bytes;

        let mut ops = Vec::new();
        let mut next = temp_base;
        let temp = |size: u32, next: &mut u64| {
            let node = Varnode::unique(*next, size);
            *next += u64::from(size).max(1);
            node
        };
        let mut lane_values = Vec::with_capacity(lanes as usize);
        for lane in 0..lanes {
            let half = lane / per_half;
            let within = lane % per_half;
            let source_lane = half * per_half + (per_half - 1 - within);
            let value = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Subpiece {
                dst: value.clone(),
                src: rn.clone(),
                offset: source_lane * lane_bytes,
            });
            lane_values.push(value);
        }
        let mut width = lane_bytes;
        while lane_values.len() > 1 {
            let mut joined = Vec::with_capacity(lane_values.len() / 2);
            for pair in lane_values.chunks(2) {
                let [low, high] = pair else {
                    return None;
                };
                let wider = temp(width * 2, &mut next);
                ops.push(R2ILOp::Piece {
                    dst: wider.clone(),
                    hi: high.clone(),
                    lo: low.clone(),
                });
                joined.push(wider);
            }
            lane_values = joined;
            width *= 2;
        }
        let composed = lane_values.pop()?;
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: composed,
        });
        Some(ops)
    }

    /// `NEON_ushl(rn, rm, element_size)` -- AArch64 `USHL`.
    ///
    /// Each element of the result is the corresponding element of `rn` shifted
    /// by the signed low byte of the corresponding element of `rm`: left when
    /// that byte is positive, right when it is negative, and zero when the
    /// distance reaches the element's width, which is what the architecture
    /// says and not what a C shift would do.
    ///
    /// Written out per element and recomposed, because the element is where the
    /// operation is defined; nothing downstream needs to know it came from a
    /// vector.
    fn expand_neon_ushl(
        output: Option<&Varnode>,
        inputs: &[Varnode],
        temp_base: u64,
    ) -> Option<Vec<R2ILOp>> {
        let [rn, rm, element_size] = inputs else {
            return None;
        };
        let output = output?;
        if element_size.space != SpaceId::Const {
            return None;
        }
        let lane_bytes = u32::try_from(element_size.offset).ok()?;
        if lane_bytes == 0
            || output.size != rn.size
            || output.size != rm.size
            || output.size % lane_bytes != 0
        {
            return None;
        }
        let lanes = output.size / lane_bytes;
        if lanes < 2 || !lanes.is_power_of_two() {
            return None;
        }
        let lane_bits = u64::from(lane_bytes).checked_mul(8)?;

        let mut ops = Vec::new();
        let mut next = temp_base;
        let temp = |size: u32, next: &mut u64| {
            let node = Varnode::unique(*next, size);
            *next += u64::from(size).max(1);
            node
        };

        let mut lane_values = Vec::with_capacity(lanes as usize);
        for lane in 0..lanes {
            let byte_offset = lane * lane_bytes;
            let value = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Subpiece {
                dst: value.clone(),
                src: rn.clone(),
                offset: byte_offset,
            });
            let distance_lane = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Subpiece {
                dst: distance_lane.clone(),
                src: rm.clone(),
                offset: byte_offset,
            });
            // The distance is the element's low byte, read as signed.
            let distance_byte = temp(1, &mut next);
            ops.push(R2ILOp::Subpiece {
                dst: distance_byte.clone(),
                src: distance_lane,
                offset: 0,
            });
            let distance = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::IntSExt {
                dst: distance.clone(),
                src: distance_byte,
            });

            let zero = Varnode::constant(0, lane_bytes);
            let negative = temp(1, &mut next);
            ops.push(R2ILOp::IntSLess {
                dst: negative.clone(),
                a: distance.clone(),
                b: zero.clone(),
            });
            let magnitude = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::IntSub {
                dst: magnitude.clone(),
                a: zero.clone(),
                b: distance.clone(),
            });

            let left = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::IntLeft {
                dst: left.clone(),
                a: value.clone(),
                b: distance.clone(),
            });
            let right = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::IntRight {
                dst: right.clone(),
                a: value,
                b: magnitude.clone(),
            });
            let shifted = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Select {
                dst: shifted.clone(),
                cond: negative.clone(),
                if_true: right,
                if_false: left,
            });

            // A distance at or beyond the element's width leaves zero, in both
            // directions. A C shift would be undefined there, so it is decided
            // here rather than left to the rendering.
            let distance_magnitude = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Select {
                dst: distance_magnitude.clone(),
                cond: negative,
                if_true: magnitude,
                if_false: distance,
            });
            let within = temp(1, &mut next);
            ops.push(R2ILOp::IntLess {
                dst: within.clone(),
                a: distance_magnitude,
                b: Varnode::constant(lane_bits, lane_bytes),
            });
            let result = temp(lane_bytes, &mut next);
            ops.push(R2ILOp::Select {
                dst: result.clone(),
                cond: within,
                if_true: shifted,
                if_false: zero,
            });
            lane_values.push(result);
        }

        // Recompose, halving the count each round until one value is left.
        let mut width = lane_bytes;
        while lane_values.len() > 1 {
            let mut joined = Vec::with_capacity(lane_values.len() / 2);
            for pair in lane_values.chunks(2) {
                let [low, high] = pair else {
                    return None;
                };
                let wider = temp(width * 2, &mut next);
                ops.push(R2ILOp::Piece {
                    dst: wider.clone(),
                    hi: high.clone(),
                    lo: low.clone(),
                });
                joined.push(wider);
            }
            lane_values = joined;
            width *= 2;
        }
        let composed = lane_values.pop()?;
        ops.push(R2ILOp::Copy {
            dst: output.clone(),
            src: composed,
        });
        Some(ops)
    }

    fn translate_pcode_op(&self, instr: &PcodeInstruction) -> Result<Option<R2ILOp>> {
        self.validate_pcode_spaces(instr)?;
        let source = DisasmInstructionWrapper {
            instr,
            disasm: self,
        };

        // Helpers for common patterns
        let unary = |name, f: fn(Varnode, Varnode) -> R2ILOp| {
            translate::translate_unary(&source, name, f)
                .map(Some)
                .map_err(translate_err)
        };

        let binary = |name, f: fn(Varnode, Varnode, Varnode) -> R2ILOp| {
            translate::translate_binary(&source, name, f)
                .map(Some)
                .map_err(translate_err)
        };

        match &instr.op_code {
            // Data movement
            OpCode::Copy => {
                let dst = translate::require_output(&source, "COPY").map_err(translate_err)?;
                let src = translate::require_input(&source, 0, "COPY").map_err(translate_err)?;
                Ok(Some(R2ILOp::Copy { dst, src }))
            }

            OpCode::Load => translate::translate_load(&source)
                .map(Some)
                .map_err(translate_err),

            OpCode::Store => translate::translate_store(&source)
                .map(Some)
                .map_err(translate_err),

            // Control flow
            OpCode::Branch => {
                let target =
                    translate::require_input(&source, 0, "BRANCH").map_err(translate_err)?;
                Ok(Some(R2ILOp::Branch { target }))
            }

            OpCode::BranchConditional => translate::translate_cbranch(&source)
                .map(Some)
                .map_err(translate_err),

            OpCode::BranchIndirect => {
                let target =
                    translate::require_input(&source, 0, "BRANCHIND").map_err(translate_err)?;
                Ok(Some(R2ILOp::BranchInd { target }))
            }

            OpCode::Call => {
                let target = translate::require_input(&source, 0, "CALL").map_err(translate_err)?;
                Ok(Some(R2ILOp::Call { target }))
            }

            OpCode::CallIndirect => {
                let target =
                    translate::require_input(&source, 0, "CALLIND").map_err(translate_err)?;
                Ok(Some(R2ILOp::CallInd { target }))
            }

            OpCode::Return => {
                let target =
                    translate::require_input(&source, 0, "RETURN").map_err(translate_err)?;
                Ok(Some(R2ILOp::Return { target }))
            }

            // Integer arithmetic
            // Integer arithmetic
            OpCode::Int(IntOp::Add) => binary("INT_ADD", |dst, a, b| R2ILOp::IntAdd { dst, a, b }),
            OpCode::Int(IntOp::Subtract) => {
                binary("INT_SUB", |dst, a, b| R2ILOp::IntSub { dst, a, b })
            }
            OpCode::Int(IntOp::Multiply) => {
                binary("INT_MULT", |dst, a, b| R2ILOp::IntMult { dst, a, b })
            }
            OpCode::Int(IntOp::Divide(IntSign::Unsigned)) => {
                binary("INT_DIV", |dst, a, b| R2ILOp::IntDiv { dst, a, b })
            }
            OpCode::Int(IntOp::Divide(IntSign::Signed)) => {
                binary("INT_SDIV", |dst, a, b| R2ILOp::IntSDiv { dst, a, b })
            }
            OpCode::Int(IntOp::Remainder(IntSign::Unsigned)) => {
                binary("INT_REM", |dst, a, b| R2ILOp::IntRem { dst, a, b })
            }
            OpCode::Int(IntOp::Remainder(IntSign::Signed)) => {
                binary("INT_SREM", |dst, a, b| R2ILOp::IntSRem { dst, a, b })
            }
            OpCode::Int(IntOp::Negate) => {
                unary("INT_2COMP", |dst, src| R2ILOp::IntNegate { dst, src })
            }

            // Bitwise operations
            OpCode::Int(IntOp::Bitwise(BoolOp::And)) => {
                binary("INT_AND", |dst, a, b| R2ILOp::IntAnd { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Or)) => {
                binary("INT_OR", |dst, a, b| R2ILOp::IntOr { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Xor)) => {
                binary("INT_XOR", |dst, a, b| R2ILOp::IntXor { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Negate)) => {
                unary("INT_NEGATE", |dst, src| R2ILOp::IntNot { dst, src })
            }

            // Shift operations
            OpCode::Int(IntOp::ShiftLeft) => {
                binary("INT_LEFT", |dst, a, b| R2ILOp::IntLeft { dst, a, b })
            }
            OpCode::Int(IntOp::ShiftRight(IntSign::Unsigned)) => {
                binary("INT_RIGHT", |dst, a, b| R2ILOp::IntRight { dst, a, b })
            }
            OpCode::Int(IntOp::ShiftRight(IntSign::Signed)) => {
                binary("INT_SRIGHT", |dst, a, b| R2ILOp::IntSRight { dst, a, b })
            }

            // Comparison operations
            OpCode::Int(IntOp::Equal) => {
                binary("INT_EQUAL", |dst, a, b| R2ILOp::IntEqual { dst, a, b })
            }
            OpCode::Int(IntOp::NotEqual) => binary("INT_NOTEQUAL", |dst, a, b| {
                R2ILOp::IntNotEqual { dst, a, b }
            }),
            OpCode::Int(IntOp::LessThan(IntSign::Unsigned)) => {
                binary("INT_LESS", |dst, a, b| R2ILOp::IntLess { dst, a, b })
            }
            OpCode::Int(IntOp::LessThan(IntSign::Signed)) => {
                binary("INT_SLESS", |dst, a, b| R2ILOp::IntSLess { dst, a, b })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Unsigned)) => {
                binary("INT_LESSEQUAL", |dst, a, b| R2ILOp::IntLessEqual {
                    dst,
                    a,
                    b,
                })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Signed)) => {
                binary("INT_SLESSEQUAL", |dst, a, b| R2ILOp::IntSLessEqual {
                    dst,
                    a,
                    b,
                })
            }

            // Extension operations
            OpCode::Int(IntOp::Extension(IntSign::Unsigned)) => {
                unary("INT_ZEXT", |dst, src| R2ILOp::IntZExt { dst, src })
            }

            OpCode::Int(IntOp::Extension(IntSign::Signed)) => {
                unary("INT_SEXT", |dst, src| R2ILOp::IntSExt { dst, src })
            }

            // Carry/Borrow
            OpCode::Int(IntOp::Carry(IntSign::Unsigned)) => {
                binary("INT_CARRY", |dst, a, b| R2ILOp::IntCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Carry(IntSign::Signed)) => {
                binary("INT_SCARRY", |dst, a, b| R2ILOp::IntSCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Borrow) => {
                binary("INT_SBORROW", |dst, a, b| R2ILOp::IntSBorrow { dst, a, b })
            }

            // Boolean operations
            OpCode::Bool(BoolOp::And) => {
                binary("BOOL_AND", |dst, a, b| R2ILOp::BoolAnd { dst, a, b })
            }

            OpCode::Bool(BoolOp::Or) => binary("BOOL_OR", |dst, a, b| R2ILOp::BoolOr { dst, a, b }),

            OpCode::Bool(BoolOp::Xor) => {
                binary("BOOL_XOR", |dst, a, b| R2ILOp::BoolXor { dst, a, b })
            }

            OpCode::Bool(BoolOp::Negate) => {
                unary("BOOL_NEGATE", |dst, src| R2ILOp::BoolNot { dst, src })
            }

            // Piece/Subpiece
            // Piece/Subpiece
            OpCode::Piece => binary("PIECE", |dst, hi, lo| R2ILOp::Piece { dst, hi, lo }),

            OpCode::Subpiece => translate::translate_subpiece(&source)
                .map(Some)
                .map_err(translate_err),

            // Popcount/LzCount
            OpCode::Popcount => unary("POPCOUNT", |dst, src| R2ILOp::PopCount { dst, src }),

            OpCode::LzCount => unary("LZCOUNT", |dst, src| R2ILOp::Lzcount { dst, src }),

            // Floating point operations
            OpCode::Float(FloatOp::Add) => {
                binary("FLOAT_ADD", |dst, a, b| R2ILOp::FloatAdd { dst, a, b })
            }

            OpCode::Float(FloatOp::Subtract) => {
                binary("FLOAT_SUB", |dst, a, b| R2ILOp::FloatSub { dst, a, b })
            }

            OpCode::Float(FloatOp::Multiply) => {
                binary("FLOAT_MULT", |dst, a, b| R2ILOp::FloatMult { dst, a, b })
            }

            OpCode::Float(FloatOp::Divide) => {
                binary("FLOAT_DIV", |dst, a, b| R2ILOp::FloatDiv { dst, a, b })
            }

            OpCode::Float(FloatOp::Negate) => {
                unary("FLOAT_NEG", |dst, src| R2ILOp::FloatNeg { dst, src })
            }

            OpCode::Float(FloatOp::AbsoluteValue) => {
                unary("FLOAT_ABS", |dst, src| R2ILOp::FloatAbs { dst, src })
            }

            OpCode::Float(FloatOp::SquareRoot) => {
                unary("FLOAT_SQRT", |dst, src| R2ILOp::FloatSqrt { dst, src })
            }

            OpCode::Float(FloatOp::Equal) => {
                binary("FLOAT_EQUAL", |dst, a, b| R2ILOp::FloatEqual { dst, a, b })
            }

            OpCode::Float(FloatOp::NotEqual) => binary("FLOAT_NOTEQUAL", |dst, a, b| {
                R2ILOp::FloatNotEqual { dst, a, b }
            }),

            OpCode::Float(FloatOp::LessThan) => {
                binary("FLOAT_LESS", |dst, a, b| R2ILOp::FloatLess { dst, a, b })
            }

            OpCode::Float(FloatOp::LessThanOrEqual) => binary("FLOAT_LESSEQUAL", |dst, a, b| {
                R2ILOp::FloatLessEqual { dst, a, b }
            }),

            OpCode::Float(FloatOp::IsNaN) => {
                unary("FLOAT_NAN", |dst, src| R2ILOp::FloatNaN { dst, src })
            }

            OpCode::Float(FloatOp::IntToFloat) => {
                unary("INT2FLOAT", |dst, src| R2ILOp::Int2Float { dst, src })
            }

            OpCode::Float(FloatOp::FloatToFloat) => {
                unary("FLOAT_FLOAT", |dst, src| R2ILOp::FloatFloat { dst, src })
            }

            OpCode::Float(FloatOp::Truncate) => {
                unary("TRUNC", |dst, src| R2ILOp::Trunc { dst, src })
            }

            OpCode::Float(FloatOp::Ceiling) => {
                unary("FLOAT_CEIL", |dst, src| R2ILOp::FloatCeil { dst, src })
            }

            OpCode::Float(FloatOp::Floor) => {
                unary("FLOAT_FLOOR", |dst, src| R2ILOp::FloatFloor { dst, src })
            }

            OpCode::Float(FloatOp::Round) => {
                unary("FLOAT_ROUND", |dst, src| R2ILOp::FloatRound { dst, src })
            }

            // Pseudo operations
            OpCode::Pseudo(PseudoOp::CallOther) => {
                // CALLOTHER: first input is userop index, rest are arguments
                let userop_vn =
                    translate::require_input(&source, 0, "CALLOTHER").map_err(translate_err)?;
                let userop = u32::try_from(userop_vn.offset).map_err(|_| {
                    LiftError::Unsupported(format!(
                        "Sleigh CALLOTHER id does not fit r2il: {}",
                        userop_vn.offset
                    ))
                })?;
                let output = source.output();

                // Collect remaining inputs (args)
                let mut inputs = Vec::new();
                for i in 1..source.input_count() {
                    if let Some(input) = source.input(i) {
                        inputs.push(input);
                    }
                }

                Ok(Some(R2ILOp::CallOther {
                    userop,
                    output,
                    inputs,
                }))
            }

            OpCode::Pseudo(op) => Err(LiftError::Unsupported(format!(
                "Sleigh pseudo operation {op:?} has no exact r2il semantics"
            ))),
            OpCode::Analysis(op) => Err(LiftError::Unsupported(format!(
                "analysis P-code operation {op:?} is invalid in a machine-code lift"
            ))),
            OpCode::Unknown(raw) => Err(LiftError::Unsupported(format!(
                "unknown Sleigh P-code operation {raw}"
            ))),
        }
    }

    /// Convert a libsla VarnodeData to our Varnode type.
    fn translate_varnode(&self, vn: &VarnodeData) -> Result<Varnode> {
        let space = self.translate_space(&vn.address.address_space)?;
        let size = u32::try_from(vn.size).map_err(|_| {
            LiftError::Unsupported(format!(
                "Sleigh varnode size does not fit r2il: {}",
                vn.size
            ))
        })?;
        Ok(Varnode {
            space,
            offset: vn.address.offset,
            size,
            meta: None,
        })
    }

    fn validate_pcode_spaces(&self, instr: &PcodeInstruction) -> Result<()> {
        self.translate_space(&instr.address.address_space)?;
        for input in &instr.inputs {
            self.translate_varnode(input)?;
        }
        if let Some(output) = &instr.output {
            self.translate_varnode(output)?;
        }
        Ok(())
    }

    /// Convert a libsla AddressSpace using the exact metadata-extraction map.
    fn translate_space(&self, space: &AddressSpace) -> Result<SpaceId> {
        self.spec.space_map.get(&space.id).copied().ok_or_else(|| {
            LiftError::Unsupported(format!(
                "Sleigh emitted unmapped address space '{}' ({})",
                space.name, space.id
            ))
        })
    }
}

/// Simple byte loader for instruction bytes.
struct ByteLoader<'a> {
    bytes: &'a [u8],
    base_addr: u64,
}

impl<'a> ByteLoader<'a> {
    fn new(bytes: &'a [u8], base_addr: u64) -> Self {
        Self { bytes, base_addr }
    }
}

impl<'a> InstructionLoader for ByteLoader<'a> {
    fn load_instruction_bytes(
        &self,
        varnode: &VarnodeData,
    ) -> std::result::Result<Vec<u8>, String> {
        let offset = varnode
            .address
            .offset
            .checked_sub(self.base_addr)
            .ok_or_else(|| "Address underflow".to_string())?;
        let start = offset as usize;
        let end = start
            .checked_add(varnode.size)
            .ok_or_else(|| "Size overflow".to_string())?;

        if end <= self.bytes.len() {
            Ok(self.bytes[start..end].to_vec())
        } else {
            Err(format!(
                "Out of bounds: requested {}..{}, have {}",
                start,
                end,
                self.bytes.len()
            ))
        }
    }
}

/// Read `<programcounter register="..."/>` out of a Ghidra processor spec.
fn program_counter_from_pspec(pspec: &str) -> String {
    const KEY: &str = "programcounter";
    let Some(rest) = pspec.split_once(KEY).map(|(_, rest)| rest) else {
        return "pc".to_string();
    };
    let Some(rest) = rest.split_once("register=").map(|(_, rest)| rest) else {
        return "pc".to_string();
    };
    let rest = rest.trim_start();
    let quote = match rest.chars().next() {
        Some(c @ ('"' | '\'')) => c,
        _ => return "pc".to_string(),
    };
    rest[1..]
        .split(quote)
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("pc")
        .to_string()
}

#[cfg(all(test, feature = "x86"))]
mod sleigh_specification_load_cost {
    use super::*;

    /// What parsing a specification costs against what lifting costs, which is
    /// the measurement that moved the parse out of the per-caller path.
    ///
    /// Not a gate: it prints rather than asserts, because a wall-clock bound
    /// checked in CI is a flake and the ratio is the finding. Run it with
    /// `cargo test --release -p r2sleigh-lift --features x86
    /// sleigh_specification_load_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a gate"]
    fn parsing_a_specification_costs_a_thousand_lifts() {
        let (sla, pspec, name) = TrustedSleighProfile::X86_64.specification();
        for round in 0..3 {
            let started = std::time::Instant::now();
            let cold = LoadedSpecification::load(sla, pspec, name, true).expect("cold load");
            eprintln!(
                "round {round}: cold parse = {}us",
                started.elapsed().as_micros()
            );
            let wrapped = Disassembler::wrap(
                std::rc::Rc::new(cold),
                name,
                Some(TrustedSleighProfile::X86_64),
            );
            let started = std::time::Instant::now();
            let _ = wrapped.lift_genuine_block(&[0x48, 0x89, 0xe5], 0x1000, 3);
            eprintln!(
                "round {round}: one three-byte block = {}us",
                started.elapsed().as_micros()
            );
            let started = std::time::Instant::now();
            let _ = Disassembler::shared_trusted_profile(TrustedSleighProfile::X86_64)
                .expect("shared profile");
            eprintln!(
                "round {round}: shared build = {}us",
                started.elapsed().as_micros()
            );
        }
    }

    #[test]
    fn one_specification_serves_both_consumers_without_sharing_a_decode_cache() {
        // The architecture and analysis view still come from one load.
        let (sla, pspec, name) = TrustedSleighProfile::X86_64.specification();
        let (arch, plugin_side) =
            embedded_arch_and_disassembler(sla, pspec, name).expect("arch and disassembler");
        assert!(Rc::ptr_eq(&plugin_side.spec, &plugin_side.spec));
        assert_eq!(plugin_side.spec.arch.name, arch.name);
        assert!(plugin_side.genuine_authority.is_none());
        assert!(arch.program_counter.is_some());

        // Session consumers share the same loaded profile, but every public
        // lift boundary discards decode entries left by the previous source.
        let lifter = Disassembler::shared_trusted_profile(TrustedSleighProfile::X86_64)
            .expect("trusted disassembler");
        let (shared_arch, shared_plugin_side) =
            Disassembler::shared_arch_and_disassembler(TrustedSleighProfile::X86_64)
                .expect("shared architecture and analysis view");
        assert!(lifter.shares_loaded_specification(&shared_plugin_side));
        assert_eq!(shared_arch.name, arch.name);
        assert_eq!(shared_arch.program_counter, arch.program_counter);
        assert_eq!(lifter.trusted_profile, Some(TrustedSleighProfile::X86_64));
        assert!(lifter.genuine_authority.is_some());
        assert!(shared_plugin_side.genuine_authority.is_none());
    }

    #[test]
    fn caller_supplied_bytes_never_certify() {
        // Only embedded bytes may mint authority, whatever else is shared.
        let (sla, pspec, name) = TrustedSleighProfile::X86_64.specification();
        let owned = sla.to_vec();
        let ad_hoc = Disassembler::from_sla(&owned, pspec, name).expect("ad hoc disassembler");
        assert!(ad_hoc.genuine_authority.is_none());
        assert!(ad_hoc.trusted_profile.is_none());
    }
}

#[cfg(all(test, feature = "x86"))]
mod shared_instance_address_reuse {
    use super::*;

    fn lift_ops(disassembler: &Disassembler, bytes: &[u8], address: u64) -> Vec<R2ILOp> {
        disassembler
            .lift_genuine_block(bytes, address, 2)
            .expect("x86 byte-register move")
            .block()
            .ops
            .clone()
    }

    /// Breaks the load cost into parser, register-table, and architecture work.
    #[test]
    #[ignore = "measurement, not a gate"]
    fn where_the_load_time_goes() {
        let (sla, pspec, name) = TrustedSleighProfile::X86_64.specification();
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let sleigh = GhidraSleigh::builder()
                .processor_spec(pspec)
                .expect("pspec")
                .build(sla)
                .expect("sla");
            let parse = t.elapsed();
            let t = std::time::Instant::now();
            let _regs = build_register_name_map(&sleigh);
            let regs = t.elapsed();
            let t = std::time::Instant::now();
            let _arch = crate::sleigh::extract_architecture(&sleigh, name).expect("arch");
            let extract = t.elapsed();
            eprintln!(
                "parse={}us regs={}us extract={}us",
                parse.as_micros(),
                regs.as_micros(),
                extract.as_micros()
            );
        }
    }

    #[test]
    fn shared_instance_observes_new_bytes_at_a_reused_address() {
        // Independently loaded instances establish that these encodings really
        // differ without depending on the shared instance under test.
        let al_control = lift_ops(
            &Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
                .expect("fresh AL control"),
            &[0x88, 0xd8, 0x90, 0x90],
            0x2000,
        );
        let ah_control = lift_ops(
            &Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
                .expect("fresh AH control"),
            &[0x88, 0xdc, 0x90, 0x90],
            0x2000,
        );
        assert_ne!(
            al_control, ah_control,
            "the control instructions must differ"
        );

        let shared =
            Disassembler::shared_trusted_profile(TrustedSleighProfile::X86_64).expect("shared");
        let second_view =
            Disassembler::shared_trusted_profile(TrustedSleighProfile::X86_64).expect("shared");
        assert!(shared.shares_loaded_specification(&second_view));

        let al_first = lift_ops(&shared, &[0x88, 0xd8, 0x90, 0x90], 0x1000);
        let ah_second = lift_ops(&second_view, &[0x88, 0xdc, 0x90, 0x90], 0x1000);
        assert_eq!(al_first, al_control);
        assert_eq!(
            ah_second, ah_control,
            "a second decode at one address must observe its own bytes; equality with the first decode means the shared parser cache was not cleared"
        );

        let ah_first = lift_ops(&shared, &[0x88, 0xdc, 0x90, 0x90], 0x3000);
        let al_second = lift_ops(&second_view, &[0x88, 0xd8, 0x90, 0x90], 0x3000);
        assert_eq!(ah_first, ah_control);
        assert_eq!(
            al_second, al_control,
            "cache invalidation must be independent of which instruction occupied the address first"
        );
    }

    /// Measures invalidation in isolation and together with a public two-byte
    /// lift. Wall-clock timing is evidence, not a CI bound.
    #[test]
    #[ignore = "measurement, not a gate"]
    fn decode_cache_clear_cost() {
        const ROUNDS: u32 = 1_000;
        let disassembler =
            Disassembler::shared_trusted_profile(TrustedSleighProfile::X86_64).expect("shared");

        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            disassembler
                .clear_decode_cache()
                .expect("clear decode cache");
        }
        eprintln!(
            "decode cache clear average = {}ns",
            started.elapsed().as_nanos() / u128::from(ROUNDS)
        );

        let mut bytes = vec![0x88, 0xd8];
        bytes.resize(Disassembler::MIN_BYTES, 0x90);
        let mut lift_elapsed = std::time::Duration::ZERO;
        for _ in 0..ROUNDS {
            disassembler
                .clear_decode_cache()
                .expect("prepare uncached lift");
            let started = std::time::Instant::now();
            let block = disassembler
                .lift_canonical(std::hint::black_box(&bytes), 0x1000)
                .expect("uncached canonical lift");
            lift_elapsed += started.elapsed();
            std::hint::black_box(block);
        }
        eprintln!(
            "uncached two-byte canonical lift average = {}ns",
            lift_elapsed.as_nanos() / u128::from(ROUNDS)
        );

        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            let block = disassembler
                .lift_genuine_block(&[0x88, 0xd8, 0x90, 0x90], 0x1000, 2)
                .expect("lift after cache clear");
            std::hint::black_box(block);
        }
        eprintln!(
            "cache clear plus two-byte lift average = {}ns",
            started.elapsed().as_nanos() / u128::from(ROUNDS)
        );
    }
}
