//! Source-owned storage, type, ABI, stack, and call-site contracts.
//!
//! These values are validated data, not certification authority. Only an
//! [`OwnedFunctionSnapshot`] created by the audited snapshot-ingress module
//! binds them to one immutable source capture.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::type_graph::{SourceLogicalValue, SourceTypeGraph};

/// Name-independent storage identity retained from a lifted varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CanonicalStorageSpace {
    Ram,
    Register,
    Unique,
    Constant,
    Custom(u32),
    /// Programmatically synthesized SSA with no lifted storage provenance.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalStorageId {
    pub space: CanonicalStorageSpace,
    pub offset: u64,
    pub size: u32,
}

/// Where a storage lives, without saying how much of it a write touched.
///
/// A `CanonicalStorageId` records a slice: `EAX` and `RAX` differ in it because
/// they differ in size, which makes two writes to one register look like writes
/// to two places. A location is the register, and the slice is what a
/// particular access took of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalLocation {
    pub space: CanonicalStorageSpace,
    pub offset: u64,
}

impl CanonicalStorageId {
    /// The place this slice is a slice of.
    pub const fn location(self) -> CanonicalLocation {
        CanonicalLocation {
            space: self.space,
            offset: self.offset,
        }
    }

    pub const fn from_varnode(varnode: &r2il::Varnode) -> Self {
        let space = match varnode.space {
            r2il::SpaceId::Ram => CanonicalStorageSpace::Ram,
            r2il::SpaceId::Register => CanonicalStorageSpace::Register,
            r2il::SpaceId::Unique => CanonicalStorageSpace::Unique,
            r2il::SpaceId::Const => CanonicalStorageSpace::Constant,
            r2il::SpaceId::Custom(id) => CanonicalStorageSpace::Custom(id),
        };
        Self {
            space,
            offset: varnode.offset,
            size: varnode.size,
        }
    }

    pub const fn unknown(ordinal: u64, size: u32) -> Self {
        Self {
            space: CanonicalStorageSpace::Unknown,
            offset: ordinal,
            size,
        }
    }

    pub const fn is_unknown(self) -> bool {
        matches!(self.space, CanonicalStorageSpace::Unknown)
    }
}

/// Canonical base used to form a proven stack address.
///
/// `Realigned` is the stack pointer after a mask has aligned it. Its distance
/// from the entry pointer is what the mask threw away, so it is an origin of
/// its own rather than a position in the entry frame. No source declares one:
/// it is recovered from the body and never written back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StackAddressBase {
    FramePointer,
    StackPointer,
    Realigned,
}

pub const SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION: u32 = 12;
pub const SOURCE_CALL_SITE_INTERFACE_SCHEMA_VERSION: u32 = 3;

/// Typed classification of one source-owned calling-convention spelling.
///
/// The source spelling remains available for presentation, but semantic
/// consumers use this closed value. Classification happens once when a source
/// contract is constructed; consumers must not parse the spelling again.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum SourceAbiClass {
    /// The source supplied no convention, or explicitly marked it unknown.
    #[default]
    Unknown,
    /// The source supplied a convention outside the closed vocabulary below.
    Other,
    Microsoft,
    MicrosoftX64,
    SystemV,
    SystemVAMD64,
    Aapcs,
    Aapcs64,
    RiscV32,
    RiscV64,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
}

impl SourceAbiClass {
    /// Whether this convention requires the direction flag clear on entry and
    /// on return from every call.
    ///
    /// Both x86 ABIs state it -- System V's psABI in its register usage, and
    /// Microsoft's x64 convention alongside it -- and the 32-bit conventions
    /// inherit it from the same platforms. It is what makes a repeated string
    /// instruction's direction knowable at all: no compiled function in the
    /// corpus executes `cld` or `std`, so the flag's value where the
    /// instruction reads it is whatever the caller or the last callee left,
    /// and this is what each was required to leave.
    ///
    /// A convention outside the vocabulary states nothing, and a machine
    /// without a direction flag never asks.
    pub const fn clears_direction_flag(self) -> bool {
        matches!(
            self,
            Self::SystemVAMD64
                | Self::MicrosoftX64
                | Self::SystemV
                | Self::Microsoft
                | Self::Cdecl
                | Self::Stdcall
                | Self::Fastcall
                | Self::Thiscall
                | Self::Vectorcall
        )
    }

    /// Classify an exact source spelling without architecture or symbol hints.
    pub fn from_source_spelling(spelling: &str) -> Self {
        let mut normalized = String::with_capacity(spelling.len());
        for ch in spelling.trim().chars() {
            if ch.is_ascii_alphanumeric() {
                normalized.push(ch.to_ascii_lowercase());
            } else if ch.is_ascii_whitespace() || matches!(ch, '-' | '_' | ':' | '.' | '/') {
                continue;
            } else {
                return Self::Other;
            }
        }
        match normalized.as_str() {
            "" | "unknown" | "unspecified" | "default" | "none" => Self::Unknown,
            "ms" | "msvc" | "microsoft" => Self::Microsoft,
            "ms64" | "msx64" | "win64" | "windowsx64" | "microsoftx64" | "x64windows"
            | "amd64windows" => Self::MicrosoftX64,
            "sysv" | "systemv" => Self::SystemV,
            "amd64" | "sysv64" | "sysvamd64" | "systemvamd64" | "amd64sysv" | "x8664sysv" => {
                Self::SystemVAMD64
            }
            "aapcs" => Self::Aapcs,
            "aapcs64" => Self::Aapcs64,
            "riscv32" | "rv32" => Self::RiscV32,
            "riscv64" | "rv64" => Self::RiscV64,
            "cdecl" => Self::Cdecl,
            "stdcall" => Self::Stdcall,
            "fastcall" => Self::Fastcall,
            "thiscall" => Self::Thiscall,
            "vectorcall" => Self::Vectorcall,
            _ => Self::Other,
        }
    }
}

/// Where one parameter or argument lives at a call boundary.
///
/// A convention places its first arguments in registers and the rest in the
/// caller-owned argument area on the stack. Both are the same kind of fact --
/// the caller wrote the value there and the callee reads it from there -- so
/// both are one location and neither is an incomplete version of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceParameterLocation {
    Register(CanonicalStorageId),
    /// A slot in the argument area. For a function's own parameter the offset
    /// is from the stack pointer as the function was entered, so the first
    /// slot on x86-64 sits at +8 above the return address; for a call-site
    /// argument it is from the stack pointer at the call instruction, before
    /// the transfer spends anything, so the first slot sits at +0.
    Stack {
        offset: i64,
        size_bytes: u32,
        /// The same slot named from the stack pointer the callee finds. A
        /// transfer that pushes no return address leaves the callee the
        /// pointer the jump had, so a tail call's arguments sit here.
        callee_offset: i64,
    },
}

impl SourceParameterLocation {
    pub const fn register(self) -> Option<CanonicalStorageId> {
        match self {
            Self::Register(storage) => Some(storage),
            Self::Stack { .. } => None,
        }
    }

    pub const fn stack(self) -> Option<(i64, u32)> {
        match self {
            Self::Register(_) => None,
            Self::Stack {
                offset, size_bytes, ..
            } => Some((offset, size_bytes)),
        }
    }

    /// The width of the carrier in bytes.
    pub const fn size_bytes(self) -> u32 {
        match self {
            Self::Register(storage) => storage.size,
            Self::Stack { size_bytes, .. } => size_bytes,
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::Register(storage) => valid_register_storage(storage),
            Self::Stack {
                offset, size_bytes, ..
            } => size_bytes > 0 && offset.checked_add(i64::from(size_bytes)).is_some(),
        }
    }

    fn overlaps(self, other: Self) -> bool {
        match (self, other) {
            (Self::Register(a), Self::Register(b)) => register_storages_overlap(a, b),
            (
                Self::Stack {
                    offset: a,
                    size_bytes: a_size,
                    ..
                },
                Self::Stack {
                    offset: b,
                    size_bytes: b_size,
                    ..
                },
            ) => a < b.saturating_add(i64::from(b_size)) && b < a.saturating_add(i64::from(a_size)),
            _ => false,
        }
    }
}

/// One explicit parameter in a function snapshot, at the location the
/// convention gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceAbiParameterSpec {
    index: u32,
    location: SourceParameterLocation,
}

impl SourceAbiParameterSpec {
    /// A parameter passed in a register.
    pub const fn new(index: u32, storage: CanonicalStorageId) -> Self {
        Self {
            index,
            location: SourceParameterLocation::Register(storage),
        }
    }

    /// A parameter passed in the argument area, `offset` bytes above the
    /// stack pointer at entry.
    ///
    /// Entry is already the callee's own view, so the two coordinates agree.
    pub const fn on_stack(index: u32, offset: i64, size_bytes: u32) -> Self {
        Self {
            index,
            location: SourceParameterLocation::Stack {
                offset,
                size_bytes,
                callee_offset: offset,
            },
        }
    }

    pub const fn with_location(index: u32, location: SourceParameterLocation) -> Self {
        Self { index, location }
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn location(&self) -> SourceParameterLocation {
        self.location
    }

    /// The register this parameter arrives in, when it arrives in one.
    pub const fn register_storage(&self) -> Option<CanonicalStorageId> {
        self.location.register()
    }
}

/// Explicit source return contract. Absence of an interface remains unknown;
/// `Void` is therefore materially different from no return information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceFunctionReturn {
    Void,
    Register {
        storage: CanonicalStorageId,
    },
    /// The body proves no result, which is not a claim that it returns nothing.
    ///
    /// A function whose result boundary is owned by a body nobody read -- a
    /// tail transfer to a target without a prototype -- knows everything about
    /// its parameters and nothing about its result. `Void` would be an active
    /// claim that displaces the caller's convention, so the caller must read
    /// this as unknown and fall back to what its convention says instead.
    Unproven,
}

/// Exact source-owned mechanism used to recover the return address and final
/// stack-pointer delta. Absence remains unknown and grants no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceReturnMechanism {
    Stacked {
        stack_offset: i64,
        slot_size_bytes: u32,
        stack_pointer_delta_bytes: u32,
        address_size_bytes: u32,
    },
}

/// Exact source-owned direction in which a callee acquires private stack
/// storage by moving the architectural stack pointer away from its entry
/// value. This is an ownership contract, not an inference from an architecture
/// name, calling-convention string, or observed instruction spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum SourceStackGrowth {
    LowerAddresses,
    HigherAddresses,
}

/// Revision-bound stack-allocation authority supplied by the immutable source
/// snapshot. While an exact SP move in `growth` remains live and unrestored,
/// the half-open interval between the entry SP and that moved SP belongs to the
/// callee. `implicit_active_sp_bytes` describes exactly that many bytes beyond
/// the active SP in the growth direction, including when the active SP still
/// equals its entry value. This is geometric authority only: a consumer must
/// independently prove that no intervening call or other source-declared
/// invalidation can overwrite the implicit area while any certified value is
/// live. Absence grants no allocation or implicit-stack authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SourceStackAllocationContract {
    growth: SourceStackGrowth,
    implicit_active_sp_bytes: u32,
}

impl SourceStackAllocationContract {
    /// Construct the exact legacy envelope with no implicit bytes beyond the
    /// active SP. Wire producers for the current schema must still transport
    /// the explicit zero field.
    pub const fn new(growth: SourceStackGrowth) -> Self {
        Self::with_implicit_active_sp_bytes(growth, 0)
    }

    pub const fn with_implicit_active_sp_bytes(
        growth: SourceStackGrowth,
        implicit_active_sp_bytes: u32,
    ) -> Self {
        Self {
            growth,
            implicit_active_sp_bytes,
        }
    }

    pub const fn growth(self) -> SourceStackGrowth {
        self.growth
    }

    pub const fn implicit_active_sp_bytes(self) -> u32 {
        self.implicit_active_sp_bytes
    }

    /// Return the exact half-open entry-SP-relative geometric envelope for
    /// `active_sp_offset`. The active offset must move in the source-owned
    /// growth direction (or remain zero), and all endpoint arithmetic is
    /// checked. This does not prove the implicit portion survives a call.
    pub fn owned_entry_relative_envelope(
        self,
        active_sp_offset: i64,
    ) -> Option<std::ops::Range<i64>> {
        let implicit_bytes = i64::from(self.implicit_active_sp_bytes);
        match self.growth {
            SourceStackGrowth::LowerAddresses if active_sp_offset <= 0 => {
                Some(active_sp_offset.checked_sub(implicit_bytes)?..0)
            }
            SourceStackGrowth::HigherAddresses if active_sp_offset >= 0 => {
                Some(0..active_sp_offset.checked_add(implicit_bytes)?)
            }
            SourceStackGrowth::LowerAddresses | SourceStackGrowth::HigherAddresses => None,
        }
    }

    /// Check that one non-empty byte range is wholly inside the exact owned
    /// envelope for the supplied active SP. This rejects endpoint overflow,
    /// opposite-direction SP movement, and ranges crossing either boundary.
    pub fn owns_entry_relative_range(
        self,
        active_sp_offset: i64,
        offset: i64,
        size_bytes: u32,
    ) -> bool {
        if size_bytes == 0 {
            return false;
        }
        let Some(end) = offset.checked_add(i64::from(size_bytes)) else {
            return false;
        };
        self.owned_entry_relative_envelope(active_sp_offset)
            .is_some_and(|envelope| offset >= envelope.start && end <= envelope.end)
    }

    pub fn owns_entry_relative_reservation(self, offset: i64, size_bytes: u32) -> bool {
        if size_bytes == 0 {
            return false;
        }
        match self.growth {
            SourceStackGrowth::LowerAddresses => {
                offset < 0 && offset.checked_add(i64::from(size_bytes)) == Some(0)
            }
            SourceStackGrowth::HigherAddresses => offset == 0,
        }
    }
}

impl SourceReturnMechanism {
    pub const fn stack_offset(self) -> i64 {
        match self {
            Self::Stacked { stack_offset, .. } => stack_offset,
        }
    }

    pub const fn slot_size_bytes(self) -> u32 {
        match self {
            Self::Stacked {
                slot_size_bytes, ..
            } => slot_size_bytes,
        }
    }

    pub const fn stack_pointer_delta_bytes(self) -> u32 {
        match self {
            Self::Stacked {
                stack_pointer_delta_bytes,
                ..
            } => stack_pointer_delta_bytes,
        }
    }

    pub const fn address_size_bytes(self) -> u32 {
        match self {
            Self::Stacked {
                address_size_bytes, ..
            } => address_size_bytes,
        }
    }
}

/// One exactly sized stack resource supplied by the immutable source snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceStackSlotRole {
    /// Compatibility-only resource with no local or parameter-home authority.
    UnclassifiedResource,
    Local,
    ParameterHome {
        parameter_index: u32,
        home_storage: CanonicalStorageId,
    },
    /// The slot is the parameter itself: the caller wrote the value into the
    /// argument area and this function reads it from there. Unlike a home,
    /// nothing in this body ever assigns it, and a read of it is a read of
    /// the parameter.
    Parameter {
        parameter_index: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceStackSlotSpec {
    base: StackAddressBase,
    base_storage: CanonicalStorageId,
    offset: i64,
    size_bytes: u32,
    role: SourceStackSlotRole,
    /// The slot's declared type as a node of the interface's type graph.
    /// Absent when the interface carries no graph or the graph could not
    /// place the declaration; never a guess.
    logical_type: Option<u32>,
    /// Whether the source's debug information declares this slot, as opposed
    /// to radare2 inferring it from the body's stack accesses.
    declared_by_debug_info: bool,
}

impl SourceStackSlotSpec {
    /// Compatibility constructor. The result cannot prove a Local or parameter Home role.
    pub const fn new(
        base: StackAddressBase,
        base_storage: CanonicalStorageId,
        offset: i64,
        size_bytes: u32,
    ) -> Self {
        Self {
            base,
            base_storage,
            offset,
            size_bytes,
            role: SourceStackSlotRole::UnclassifiedResource,
            logical_type: None,
            declared_by_debug_info: false,
        }
    }

    pub const fn new_local(
        base: StackAddressBase,
        base_storage: CanonicalStorageId,
        offset: i64,
        size_bytes: u32,
    ) -> Self {
        Self {
            base,
            base_storage,
            offset,
            size_bytes,
            role: SourceStackSlotRole::Local,
            logical_type: None,
            declared_by_debug_info: false,
        }
    }

    pub const fn new_parameter_home(
        base: StackAddressBase,
        base_storage: CanonicalStorageId,
        offset: i64,
        size_bytes: u32,
        parameter_index: u32,
        home_storage: CanonicalStorageId,
    ) -> Self {
        Self {
            base,
            base_storage,
            offset,
            size_bytes,
            role: SourceStackSlotRole::ParameterHome {
                parameter_index,
                home_storage,
            },
            logical_type: None,
            declared_by_debug_info: false,
        }
    }

    /// A slot that is a stack-passed parameter's own storage.
    pub const fn new_parameter(
        base: StackAddressBase,
        base_storage: CanonicalStorageId,
        offset: i64,
        size_bytes: u32,
        parameter_index: u32,
    ) -> Self {
        Self {
            base,
            base_storage,
            offset,
            size_bytes,
            role: SourceStackSlotRole::Parameter { parameter_index },
            logical_type: None,
            declared_by_debug_info: false,
        }
    }

    /// The same slot with its declared type named as a graph node.
    pub const fn with_logical_type(self, type_id: u32) -> Self {
        Self {
            logical_type: Some(type_id),
            ..self
        }
    }

    pub const fn logical_type(&self) -> Option<u32> {
        self.logical_type
    }

    /// The same slot measured from another origin: its role, its type and
    /// who declared it are unchanged.
    pub const fn measured_from(
        self,
        base: StackAddressBase,
        base_storage: CanonicalStorageId,
        offset: i64,
    ) -> Self {
        Self {
            base,
            base_storage,
            offset,
            ..self
        }
    }

    /// The same slot, stated by the source's debug information.
    pub const fn with_debug_declaration(self) -> Self {
        Self {
            declared_by_debug_info: true,
            ..self
        }
    }

    pub const fn declared_by_debug_info(&self) -> bool {
        self.declared_by_debug_info
    }

    pub const fn base(&self) -> StackAddressBase {
        self.base
    }

    pub const fn base_storage(&self) -> CanonicalStorageId {
        self.base_storage
    }

    pub const fn offset(&self) -> i64 {
        self.offset
    }

    pub const fn size_bytes(&self) -> u32 {
        self.size_bytes
    }

    pub const fn role(&self) -> SourceStackSlotRole {
        self.role
    }
}

/// The register names a source spells for the machine role carriers.
///
/// A name is the only part of a source-reported carrier that means the same
/// thing to the architecture that gets lifted. Everything else about the
/// carrier -- its offset above all -- is stated in the source's own register
/// numbering and has to be re-derived from the name before it can be compared
/// with anything the lift produced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoleRegisterNames {
    return_address: Option<SourceRegisterName>,
    stack_pointer: Option<SourceRegisterName>,
    frame_pointer: Option<SourceRegisterName>,
    /// The flag that decides which way a repeated string instruction walks.
    /// A role register like the three above: the machine names it, and what
    /// its value is on entry is the convention's to say.
    direction_flag: Option<SourceRegisterName>,
}

/// One register spelling, stored inline.
///
/// Register names are short by construction, and holding one inline keeps the
/// carriers a machine states about itself copyable, which is what every
/// consumer of them already assumes. A name too long for the buffer is refused
/// rather than truncated: a truncated spelling would resolve to a different
/// register, which is the exact failure this type exists to prevent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SourceRegisterName {
    bytes: [u8; SOURCE_REGISTER_NAME_MAX],
    len: u8,
}

/// Longest register spelling a source may state.
pub const SOURCE_REGISTER_NAME_MAX: usize = 32;

impl SourceRegisterName {
    /// Take a spelling, refusing one that is empty, over-long, or not plain
    /// ASCII -- a register name outside that set is not one this transport can
    /// compare, and guessing at it would place the wrong register.
    pub fn new(name: &str) -> Option<Self> {
        if name.is_empty() || name.len() > SOURCE_REGISTER_NAME_MAX || !name.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; SOURCE_REGISTER_NAME_MAX];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            bytes,
            len: name.len() as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        // The only constructor accepts ASCII, so the prefix is always UTF-8.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

impl PartialEq for SourceRegisterName {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SourceRegisterName {}

impl SourceRoleRegisterNames {
    /// A capture that spelled no carrier at all.
    pub const fn none() -> Self {
        Self {
            return_address: None,
            stack_pointer: None,
            frame_pointer: None,
            direction_flag: None,
        }
    }

    /// Record what the source called each carrier. An empty spelling is no
    /// name: a carrier the source could not name is one the consumer must do
    /// without, never one it may place by its offset.
    pub fn new(
        return_address: Option<&str>,
        stack_pointer: Option<&str>,
        frame_pointer: Option<&str>,
    ) -> Self {
        let spelled = |name: Option<&str>| name.and_then(SourceRegisterName::new);
        Self {
            return_address: spelled(return_address),
            stack_pointer: spelled(stack_pointer),
            frame_pointer: spelled(frame_pointer),
            direction_flag: None,
        }
    }

    /// Record what the source called the direction flag.
    #[must_use]
    pub fn with_direction_flag(mut self, name: Option<&str>) -> Self {
        self.direction_flag = name.and_then(SourceRegisterName::new);
        self
    }

    pub fn return_address(&self) -> Option<&str> {
        self.return_address.as_ref().map(SourceRegisterName::as_str)
    }

    pub fn stack_pointer(&self) -> Option<&str> {
        self.stack_pointer.as_ref().map(SourceRegisterName::as_str)
    }

    pub fn frame_pointer(&self) -> Option<&str> {
        self.frame_pointer.as_ref().map(SourceRegisterName::as_str)
    }

    pub fn direction_flag(&self) -> Option<&str> {
        self.direction_flag.as_ref().map(SourceRegisterName::as_str)
    }
}

/// Coherent, revision-bound function interface injected by the source owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceFunctionInterface {
    schema_version: u32,
    revision_identity: Box<[u8]>,
    calling_convention: String,
    abi_class: SourceAbiClass,
    parameters: Box<[SourceAbiParameterSpec]>,
    return_kind: SourceFunctionReturn,
    return_address_storage: Option<CanonicalStorageId>,
    stack_pointer_storage: Option<CanonicalStorageId>,
    frame_pointer_storage: Option<CanonicalStorageId>,
    /// How the source spells each role carrier's register.
    ///
    /// The source numbers registers in its own arena, which says nothing about
    /// where the lifted architecture puts the same register: on arm64 the
    /// source calls the link register offset zero and the architecture calls it
    /// 16624. A storage taken from the source therefore names a different
    /// register, or none, until it is resolved through the architecture's own
    /// table -- and a comparison against a value's storage silently never
    /// matched. The name is what survives that translation, so it is what the
    /// capture carries.
    role_register_names: SourceRoleRegisterNames,
    return_mechanism: Option<SourceReturnMechanism>,
    stack_slots: Box<[SourceStackSlotSpec]>,
    /// One entry per parameter, absent where the capture could not place that
    /// parameter's type.
    ///
    /// Dense and non-optional until a root that would not place cost the
    /// function its *whole* graph -- every exact type, every layout and every
    /// source name, because one `double` in a signature had nowhere to go.
    /// A local already survived its own failure; a parameter does now too.
    parameter_logical_values: Box<[Option<SourceLogicalValue>]>,
    return_logical_value: Option<SourceLogicalValue>,
    type_graph: Option<SourceTypeGraph>,
    stack_slot_roles_complete: bool,
    /// Which of this function's own parameters its body proves is a format
    /// string, for callers whose prototype for it names none. A property of
    /// the function, unlike the per-callsite count rule a literal decides.
    body_proven_format_parameter: Option<u32>,
    /// Whether the body proves its result is the return address it was called
    /// with, which is what a position-independent code thunk returns.
    body_proven_return_address: bool,
    /// The prototype is radare2's, found by an import's name rather than
    /// linked to the address or stated by debug information.
    prototype_from_source_types: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFunctionInterfaceError {
    InvalidFormatParameterIndex,
    EmptyRevisionIdentity,
    EmptyCallingConvention,
    InvalidParameterOrder,
    InvalidRegisterStorage,
    InvalidReturnAddressStorage,
    InvalidStackPointerStorage,
    InvalidFramePointerStorage,
    InvalidReturnMechanism,
    OverlappingRegisterStorages,
    InvalidStackSlot,
    InvalidStackSlotRole,
    OverlappingStackSlots,
    /// The logical types do not describe the physical interface. The reason
    /// names which of the five conditions failed: a consumer that only ever
    /// saw the verdict had no way to tell a lane that overran its carrier
    /// from a type nothing could reach.
    InvalidLogicalTypes {
        reason: &'static str,
    },
}

impl std::fmt::Display for SourceFunctionInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid source function interface: {self:?}")
    }
}

impl std::error::Error for SourceFunctionInterfaceError {}

/// The logical half of an interface: what type each value has, and the
/// graph those types are nodes of.
struct LogicalTypes {
    parameters: Vec<Option<SourceLogicalValue>>,
    returns: Option<SourceLogicalValue>,
    graph: Option<SourceTypeGraph>,
    slots: Vec<SourceStackSlotSpec>,
}

impl LogicalTypes {
    /// These types, checked against the physical interface, with the graph
    /// closed over exactly what they name.
    ///
    /// The graph holds every type the interface names and nothing else. That
    /// is made true here rather than demanded of the caller: a declaration
    /// interned item by item leaves a node nothing names once one item is
    /// dropped, and refusing the interface for it lost every other type.
    ///
    /// An exact interface states a logical value for every parameter and for
    /// a register result. Absence there meant only that a capture could not
    /// type something, and the consumer read it as "the whole carrier", which
    /// is a width nothing stated.
    fn validated(
        self,
        parameters: &[SourceAbiParameterSpec],
        return_kind: SourceFunctionReturn,
        exact: bool,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        let refused = |reason| Err(SourceFunctionInterfaceError::InvalidLogicalTypes { reason });
        let Some(graph) = self.graph.as_ref() else {
            if self.parameters.iter().any(Option::is_some) || self.returns.is_some() {
                return refused("logical values without a type graph");
            }
            if self.slots.iter().any(|slot| slot.logical_type.is_some()) {
                return refused("a slot names a type without a type graph");
            }
            return Ok(self);
        };
        if self.parameters.len() != parameters.len() {
            return refused("one logical value per parameter");
        }
        let unstated_result =
            matches!(return_kind, SourceFunctionReturn::Register { .. }) && self.returns.is_none();
        if exact && (self.parameters.iter().any(Option::is_none) || unstated_result) {
            return refused("an exact interface states every logical value");
        }
        let fits = |value: &Option<SourceLogicalValue>, parameter: &SourceAbiParameterSpec| {
            value.is_none_or(|value| {
                graph.validates_logical_value(value, parameter.location.size_bytes())
            })
        };
        if !self
            .parameters
            .iter()
            .zip(parameters)
            .all(|(v, p)| fits(v, p))
        {
            return refused("a parameter's logical value does not fit its carrier");
        }
        match (return_kind, self.returns) {
            (SourceFunctionReturn::Register { storage }, Some(value))
                if !graph.validates_logical_value(value, storage.size) =>
            {
                return refused("the return's logical value does not fit its carrier");
            }
            (SourceFunctionReturn::Void | SourceFunctionReturn::Unproven, Some(_)) => {
                return refused("a return that names no carrier has no logical value");
            }
            _ => {}
        }
        if self
            .slots
            .iter()
            .filter_map(|slot| slot.logical_type)
            .any(|id| !graph.names_object(id))
        {
            return refused("a slot's type is not an object of the graph");
        }
        Ok(self.closed())
    }

    /// The same values, over the graph of only what they name.
    fn closed(self) -> Self {
        let Some(graph) = self.graph.as_ref() else {
            return self;
        };
        let roots = self
            .parameters
            .iter()
            .flatten()
            .chain(&self.returns)
            .map(|value| value.type_id())
            .chain(self.slots.iter().filter_map(|slot| slot.logical_type));
        let closure = graph.closure(roots);
        let renumber = |value: SourceLogicalValue| {
            SourceLogicalValue::new(
                closure.id(value.type_id()).unwrap_or(value.type_id()),
                value.carrier(),
            )
        };
        Self {
            parameters: self
                .parameters
                .iter()
                .map(|value| value.map(renumber))
                .collect(),
            returns: self.returns.map(renumber),
            slots: self
                .slots
                .iter()
                .map(|slot| SourceStackSlotSpec {
                    logical_type: slot.logical_type.and_then(|id| closure.id(id)),
                    ..*slot
                })
                .collect(),
            graph: Some(closure.into_graph()),
        }
    }
}

impl SourceFunctionInterface {
    pub fn new(
        revision_identity: impl Into<Vec<u8>>,
        calling_convention: impl Into<String>,
        parameters: impl IntoIterator<Item = SourceAbiParameterSpec>,
        return_kind: SourceFunctionReturn,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        Self::new_with_logical_types_internal(
            revision_identity,
            calling_convention,
            parameters,
            return_kind,
            stack_slots,
            Vec::new(),
            None,
            None,
            false,
        )
    }

    pub fn new_exact(
        revision_identity: impl Into<Vec<u8>>,
        calling_convention: impl Into<String>,
        parameters: impl IntoIterator<Item = SourceAbiParameterSpec>,
        return_kind: SourceFunctionReturn,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        Self::new_with_logical_types_internal(
            revision_identity,
            calling_convention,
            parameters,
            return_kind,
            stack_slots,
            Vec::new(),
            None,
            None,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_logical_types(
        revision_identity: impl Into<Vec<u8>>,
        calling_convention: impl Into<String>,
        parameters: impl IntoIterator<Item = SourceAbiParameterSpec>,
        return_kind: SourceFunctionReturn,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
        parameter_logical_values: impl IntoIterator<Item = Option<SourceLogicalValue>>,
        return_logical_value: Option<SourceLogicalValue>,
        type_graph: Option<SourceTypeGraph>,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        Self::new_with_logical_types_internal(
            revision_identity,
            calling_convention,
            parameters,
            return_kind,
            stack_slots,
            parameter_logical_values,
            return_logical_value,
            type_graph,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_exact_with_logical_types(
        revision_identity: impl Into<Vec<u8>>,
        calling_convention: impl Into<String>,
        parameters: impl IntoIterator<Item = SourceAbiParameterSpec>,
        return_kind: SourceFunctionReturn,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
        parameter_logical_values: impl IntoIterator<Item = Option<SourceLogicalValue>>,
        return_logical_value: Option<SourceLogicalValue>,
        type_graph: Option<SourceTypeGraph>,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        Self::new_with_logical_types_internal(
            revision_identity,
            calling_convention,
            parameters,
            return_kind,
            stack_slots,
            parameter_logical_values,
            return_logical_value,
            type_graph,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_logical_types_internal(
        revision_identity: impl Into<Vec<u8>>,
        calling_convention: impl Into<String>,
        parameters: impl IntoIterator<Item = SourceAbiParameterSpec>,
        return_kind: SourceFunctionReturn,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
        parameter_logical_values: impl IntoIterator<Item = Option<SourceLogicalValue>>,
        return_logical_value: Option<SourceLogicalValue>,
        type_graph: Option<SourceTypeGraph>,
        require_exact_stack_slot_roles: bool,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        let revision_identity = revision_identity.into();
        if revision_identity.is_empty() {
            return Err(SourceFunctionInterfaceError::EmptyRevisionIdentity);
        }
        let calling_convention = calling_convention.into();
        if calling_convention.trim().is_empty() {
            return Err(SourceFunctionInterfaceError::EmptyCallingConvention);
        }
        let abi_class = SourceAbiClass::from_source_spelling(&calling_convention);
        let parameters = parameters.into_iter().collect::<Vec<_>>();
        if parameters
            .iter()
            .enumerate()
            .any(|(index, parameter)| u32::try_from(index) != Ok(parameter.index))
        {
            return Err(SourceFunctionInterfaceError::InvalidParameterOrder);
        }
        if parameters
            .iter()
            .any(|parameter| !parameter.location.is_valid())
            || matches!(
                return_kind,
                SourceFunctionReturn::Register { storage }
                    if !valid_register_storage(storage)
            )
        {
            return Err(SourceFunctionInterfaceError::InvalidRegisterStorage);
        }
        if parameters.iter().enumerate().any(|(index, parameter)| {
            parameters[index.saturating_add(1)..]
                .iter()
                .any(|other| parameter.location.overlaps(other.location))
        }) {
            return Err(SourceFunctionInterfaceError::OverlappingRegisterStorages);
        }
        let mut stack_slots = stack_slots.into_iter().collect::<Vec<_>>();
        // size zero means the extent was never established, which only an exact role claim may refuse
        if stack_slots.iter().any(|slot| {
            !valid_register_storage(slot.base_storage)
                || (require_exact_stack_slot_roles && slot.size_bytes == 0)
                || slot
                    .offset
                    .checked_add(i64::from(slot.size_bytes))
                    .is_none()
        }) {
            return Err(SourceFunctionInterfaceError::InvalidStackSlot);
        }
        stack_slots.sort_by_key(|slot| (slot.base, slot.offset, slot.size_bytes));
        if stack_slots.iter().enumerate().any(|(index, slot)| {
            stack_slots[index.saturating_add(1)..]
                .iter()
                .any(|other| slot.base == other.base && slot.base_storage != other.base_storage)
        }) {
            return Err(SourceFunctionInterfaceError::InvalidStackSlot);
        }
        if let Some(pair) = stack_slots.windows(2).find(|pair| {
            pair[0].base == pair[1].base
                && pair[0]
                    .offset
                    .checked_add(i64::from(pair[0].size_bytes))
                    .is_none_or(|end| end > pair[1].offset)
        }) {
            r2il::refusal_evidence!(
                "stack-slot-overlap",
                "slot at {:?}{:+} ({} bytes, {:?}) overlaps slot at {:?}{:+} ({} bytes, {:?})",
                pair[0].base,
                pair[0].offset,
                pair[0].size_bytes,
                pair[0].role,
                pair[1].base,
                pair[1].offset,
                pair[1].size_bytes,
                pair[1].role
            );
            return Err(SourceFunctionInterfaceError::OverlappingStackSlots);
        }
        let mut parameter_homes = BTreeSet::new();
        for slot in &stack_slots {
            match slot.role {
                SourceStackSlotRole::UnclassifiedResource => {
                    if require_exact_stack_slot_roles {
                        r2il::refusal_evidence!(
                            "stack-slot-role",
                            "slot at {:?}{:+} ({} bytes) is unclassified in an interface whose roles are stated exact",
                            slot.base,
                            slot.offset,
                            slot.size_bytes
                        );
                        return Err(SourceFunctionInterfaceError::InvalidStackSlotRole);
                    }
                }
                SourceStackSlotRole::Local => {}
                SourceStackSlotRole::Parameter { parameter_index } => {
                    // The slot is a parameter the convention passes on the
                    // stack, and the parameter must say it lives there with
                    // a carrier the slot fits in. More than one slot may
                    // name the same parameter: a debugger's location list
                    // gives the variable a second frame slot over a later
                    // range, and which slot is the parameter's own is decided
                    // by position once the frame is known, not here.
                    let Ok(parameter_index_usize) = usize::try_from(parameter_index) else {
                        return Err(SourceFunctionInterfaceError::InvalidStackSlotRole);
                    };
                    if parameters
                        .get(parameter_index_usize)
                        .is_none_or(|parameter| {
                            parameter.index != parameter_index
                                || parameter.location.stack().is_none_or(|(_, size_bytes)| {
                                    slot.size_bytes == 0 || slot.size_bytes > size_bytes
                                })
                        })
                    {
                        r2il::refusal_evidence!(
                            "stack-slot-role",
                            "slot at {:?}{:+} ({} bytes) names parameter {} which is {:?}",
                            slot.base,
                            slot.offset,
                            slot.size_bytes,
                            parameter_index,
                            parameters
                                .get(parameter_index_usize)
                                .map(|parameter| parameter.location)
                        );
                        return Err(SourceFunctionInterfaceError::InvalidStackSlotRole);
                    }
                }
                SourceStackSlotRole::ParameterHome {
                    parameter_index,
                    home_storage,
                } => {
                    let Ok(parameter_index_usize) = usize::try_from(parameter_index) else {
                        return Err(SourceFunctionInterfaceError::InvalidStackSlotRole);
                    };
                    if !valid_register_storage(home_storage)
                        || parameters
                            .get(parameter_index_usize)
                            .is_none_or(|parameter| {
                                parameter.index != parameter_index
                                    || parameter.register_storage() != Some(home_storage)
                            })
                        || !parameter_homes.insert(parameter_index)
                    {
                        r2il::refusal_evidence!(
                            "stack-slot-role",
                            "home at {:?}{:+} ({} bytes) for parameter {} in {:?} names {:?}; already claimed: {}",
                            slot.base,
                            slot.offset,
                            slot.size_bytes,
                            parameter_index,
                            home_storage,
                            parameters
                                .get(parameter_index_usize)
                                .map(|parameter| parameter.location),
                            parameter_homes.contains(&parameter_index)
                        );
                        return Err(SourceFunctionInterfaceError::InvalidStackSlotRole);
                    }
                }
            }
        }
        let LogicalTypes {
            parameters: parameter_logical_values,
            returns: return_logical_value,
            graph: type_graph,
            slots: stack_slots,
        } = LogicalTypes {
            parameters: parameter_logical_values.into_iter().collect(),
            returns: return_logical_value,
            graph: type_graph,
            slots: stack_slots,
        }
        .validated(&parameters, return_kind, require_exact_stack_slot_roles)?;
        Ok(Self {
            schema_version: SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION,
            revision_identity: revision_identity.into_boxed_slice(),
            calling_convention,
            abi_class,
            parameters: parameters.into_boxed_slice(),
            return_kind,
            return_address_storage: None,
            stack_pointer_storage: None,
            frame_pointer_storage: None,
            role_register_names: SourceRoleRegisterNames::none(),
            return_mechanism: None,
            stack_slots: stack_slots.into_boxed_slice(),
            parameter_logical_values: parameter_logical_values.into_boxed_slice(),
            return_logical_value,
            type_graph,
            stack_slot_roles_complete: require_exact_stack_slot_roles,
            body_proven_format_parameter: None,
            body_proven_return_address: false,
            prototype_from_source_types: false,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn revision_identity(&self) -> &[u8] {
        &self.revision_identity
    }

    pub fn calling_convention(&self) -> &str {
        &self.calling_convention
    }

    pub const fn abi_class(&self) -> SourceAbiClass {
        self.abi_class
    }

    /// Whether a call site's argument location names the same carrier as one
    /// of this function's parameters.
    ///
    /// A register is the same register on both sides. A stack slot is named
    /// from the caller's stack pointer at the call and from this function's
    /// stack pointer at entry, and the two differ by exactly what the
    /// transfer spends -- the return-address slot the return mechanism
    /// states, or nothing where the address travels in a register.
    pub fn argument_location_matches_parameter(
        &self,
        argument: SourceParameterLocation,
        parameter: SourceParameterLocation,
    ) -> bool {
        match (argument, parameter) {
            (SourceParameterLocation::Register(a), SourceParameterLocation::Register(b)) => a == b,
            (
                SourceParameterLocation::Stack {
                    offset: call_offset,
                    size_bytes: call_size,
                    ..
                },
                SourceParameterLocation::Stack {
                    offset: entry_offset,
                    size_bytes: entry_size,
                    ..
                },
            ) => {
                let spent = self.return_mechanism.map_or(0, |mechanism| {
                    i64::from(mechanism.stack_pointer_delta_bytes())
                });
                call_size == entry_size && call_offset.checked_add(spent) == Some(entry_offset)
            }
            _ => false,
        }
    }

    pub const fn parameters(&self) -> &[SourceAbiParameterSpec] {
        &self.parameters
    }

    pub const fn return_kind(&self) -> SourceFunctionReturn {
        self.return_kind
    }

    /// The same interface with a return register the callee's body proved.
    ///
    /// Only a return that claims no carrier is replaced: an absent prototype
    /// defaults to void and an unproven boundary claims nothing, while a body
    /// that fills the return register on every return path outranks both. A
    /// stated return is never overridden.
    pub fn with_body_proven_return(
        mut self,
        storage: CanonicalStorageId,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if matches!(self.return_kind, SourceFunctionReturn::Register { .. }) {
            return Ok(self);
        }
        if !valid_register_storage(storage) {
            return Err(SourceFunctionInterfaceError::InvalidRegisterStorage);
        }
        if self.parameters.iter().any(|parameter| {
            parameter
                .location
                .overlaps(SourceParameterLocation::Register(storage))
        }) {
            return Err(SourceFunctionInterfaceError::OverlappingRegisterStorages);
        }
        self.return_kind = SourceFunctionReturn::Register { storage };
        Ok(self)
    }

    /// Record which parameter this function's body forwards as a format
    /// string. Checked against the parameters the interface actually has, so a
    /// body-derived index cannot name one that does not exist.
    pub fn with_body_proven_format_parameter(
        mut self,
        parameter_index: u32,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if usize::try_from(parameter_index)
            .ok()
            .is_none_or(|index| index >= self.parameters.len())
        {
            return Err(SourceFunctionInterfaceError::InvalidFormatParameterIndex);
        }
        self.body_proven_format_parameter = Some(parameter_index);
        Ok(self)
    }

    pub const fn body_proven_format_parameter(&self) -> Option<u32> {
        self.body_proven_format_parameter
    }

    /// Record that the body hands its caller back the return address it was
    /// called with. Only a register return can carry one, so a return naming
    /// no carrier is refused rather than silently marked.
    pub fn with_body_proven_return_address(mut self) -> Result<Self, SourceFunctionInterfaceError> {
        if !matches!(self.return_kind, SourceFunctionReturn::Register { .. }) {
            return Err(SourceFunctionInterfaceError::InvalidRegisterStorage);
        }
        self.body_proven_return_address = true;
        Ok(self)
    }

    /// Whether the result is the return address the caller pushed.
    pub const fn body_proven_return_address(&self) -> bool {
        self.body_proven_return_address
    }

    /// The same interface, with its prototype marked as radare2's by-name lookup.
    pub const fn with_prototype_from_source_types(mut self) -> Self {
        self.prototype_from_source_types = true;
        self
    }

    pub const fn prototype_from_source_types(&self) -> bool {
        self.prototype_from_source_types
    }

    pub fn return_address_storage_is_valid(&self, storage: CanonicalStorageId) -> bool {
        valid_register_storage(storage)
            && !self
                .parameters
                .iter()
                .filter_map(SourceAbiParameterSpec::register_storage)
                .chain(match self.return_kind {
                    SourceFunctionReturn::Void | SourceFunctionReturn::Unproven => None,
                    SourceFunctionReturn::Register { storage } => Some(storage),
                })
                .chain(self.stack_pointer_storage)
                .chain(self.frame_pointer_storage)
                .chain(
                    self.stack_slots
                        .iter()
                        .map(SourceStackSlotSpec::base_storage),
                )
                .chain(self.stack_slots.iter().filter_map(|slot| match slot.role {
                    SourceStackSlotRole::ParameterHome { home_storage, .. } => Some(home_storage),
                    SourceStackSlotRole::UnclassifiedResource
                    | SourceStackSlotRole::Local
                    | SourceStackSlotRole::Parameter { .. } => None,
                }))
                .any(|other| register_storages_overlap(storage, other))
    }

    pub fn stack_pointer_storage_is_valid(&self, storage: CanonicalStorageId) -> bool {
        let overlaps_non_stack_role = self
            .parameters
            .iter()
            .filter_map(SourceAbiParameterSpec::register_storage)
            .chain(match self.return_kind {
                SourceFunctionReturn::Void | SourceFunctionReturn::Unproven => None,
                SourceFunctionReturn::Register { storage } => Some(storage),
            })
            .chain(self.return_address_storage)
            .chain(self.frame_pointer_storage)
            .chain(self.stack_slots.iter().filter_map(|slot| match slot.role {
                SourceStackSlotRole::ParameterHome { home_storage, .. } => Some(home_storage),
                SourceStackSlotRole::UnclassifiedResource
                | SourceStackSlotRole::Local
                | SourceStackSlotRole::Parameter { .. } => None,
            }))
            .chain(
                self.stack_slots
                    .iter()
                    .filter(|slot| slot.base == StackAddressBase::FramePointer)
                    .map(SourceStackSlotSpec::base_storage),
            )
            .any(|other| register_storages_overlap(storage, other));
        let mismatched_stack_base = self
            .stack_slots
            .iter()
            .filter(|slot| slot.base == StackAddressBase::StackPointer)
            .any(|slot| slot.base_storage != storage);
        let mismatched_frame_width = self
            .frame_pointer_storage
            .is_some_and(|frame_pointer| frame_pointer.size != storage.size);
        valid_register_storage(storage)
            && !overlaps_non_stack_role
            && !mismatched_stack_base
            && !mismatched_frame_width
    }

    pub fn frame_pointer_storage_is_valid(&self, storage: CanonicalStorageId) -> bool {
        let overlaps_non_frame_role = self
            .parameters
            .iter()
            .filter_map(SourceAbiParameterSpec::register_storage)
            .chain(match self.return_kind {
                SourceFunctionReturn::Void | SourceFunctionReturn::Unproven => None,
                SourceFunctionReturn::Register { storage } => Some(storage),
            })
            .chain(self.return_address_storage)
            .chain(self.stack_pointer_storage)
            .chain(self.stack_slots.iter().filter_map(|slot| match slot.role {
                SourceStackSlotRole::ParameterHome { home_storage, .. } => Some(home_storage),
                SourceStackSlotRole::UnclassifiedResource
                | SourceStackSlotRole::Local
                | SourceStackSlotRole::Parameter { .. } => None,
            }))
            .chain(
                self.stack_slots
                    .iter()
                    .filter(|slot| slot.base == StackAddressBase::StackPointer)
                    .map(SourceStackSlotSpec::base_storage),
            )
            .any(|other| register_storages_overlap(storage, other));
        let mismatched_frame_base = self
            .stack_slots
            .iter()
            .filter(|slot| slot.base == StackAddressBase::FramePointer)
            .any(|slot| slot.base_storage != storage);
        let Some(stack_pointer) = self.stack_pointer_storage else {
            return false;
        };
        let mismatched_stack_width = stack_pointer.size != storage.size;
        valid_register_storage(storage)
            && !overlaps_non_frame_role
            && !mismatched_frame_base
            && !mismatched_stack_width
    }

    /// Bind the machine return-address carrier supplied by the immutable
    /// source snapshot. Exact frame/return certificates require this role;
    /// they never infer it from a register name.
    pub fn with_return_address_storage(
        mut self,
        storage: CanonicalStorageId,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if self
            .return_mechanism
            .is_some_and(|_| self.return_address_storage != Some(storage))
        {
            return Err(SourceFunctionInterfaceError::InvalidReturnMechanism);
        }
        if !self.return_address_storage_is_valid(storage) {
            return Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage);
        }
        self.return_address_storage = Some(storage);
        Ok(self)
    }

    pub const fn return_address_storage(&self) -> Option<CanonicalStorageId> {
        self.return_address_storage
    }

    /// Record how the source spelled each role carrier.
    pub const fn with_role_register_names(mut self, names: SourceRoleRegisterNames) -> Self {
        self.role_register_names = names;
        self
    }

    pub const fn role_register_names(&self) -> SourceRoleRegisterNames {
        self.role_register_names
    }

    /// Replace the role carriers with the storages the lifted architecture
    /// gives for the names the source spelled.
    ///
    /// This is the one place a source-numbered carrier becomes an
    /// architecture-numbered one, and it runs before anything compares a
    /// carrier with a value. A carrier the architecture cannot place is
    /// dropped rather than kept at its source offset: an absent carrier costs
    /// the certificates that need it, while a carrier at an offset belonging
    /// to some other register is a false statement about the machine.
    pub fn with_arch_resolved_role_carriers(
        mut self,
        return_address: Option<CanonicalStorageId>,
        stack_pointer: Option<CanonicalStorageId>,
        frame_pointer: Option<CanonicalStorageId>,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if return_address.is_some_and(|storage| !self.return_address_storage_is_valid(storage)) {
            return Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage);
        }
        if stack_pointer.is_some_and(|storage| !self.stack_pointer_storage_is_valid(storage)) {
            return Err(SourceFunctionInterfaceError::InvalidStackPointerStorage);
        }
        self.return_address_storage = return_address;
        self.stack_pointer_storage = stack_pointer;
        // The frame pointer is validated against the carriers just installed,
        // since its rule is that it overlaps neither of them.
        if frame_pointer.is_some_and(|storage| !self.frame_pointer_storage_is_valid(storage)) {
            return Err(SourceFunctionInterfaceError::InvalidFramePointerStorage);
        }
        self.frame_pointer_storage = frame_pointer;
        Ok(self)
    }

    /// Bind the source-owned full-width stack-pointer carrier. This identity
    /// is never inferred from stack resources or register names.
    pub fn with_stack_pointer_storage(
        mut self,
        storage: CanonicalStorageId,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if self
            .return_mechanism
            .is_some_and(|_| self.stack_pointer_storage != Some(storage))
        {
            return Err(SourceFunctionInterfaceError::InvalidReturnMechanism);
        }
        if !self.stack_pointer_storage_is_valid(storage) {
            return Err(SourceFunctionInterfaceError::InvalidStackPointerStorage);
        }
        self.stack_pointer_storage = Some(storage);
        Ok(self)
    }

    pub const fn stack_pointer_storage(&self) -> Option<CanonicalStorageId> {
        self.stack_pointer_storage
    }

    /// Bind the source-owned full-width frame-pointer carrier. This explicit
    /// fact remains available when the source has no frame-based stack slots.
    pub fn with_frame_pointer_storage(
        mut self,
        storage: CanonicalStorageId,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        if self
            .frame_pointer_storage
            .is_some_and(|bound| bound != storage)
            || !self.frame_pointer_storage_is_valid(storage)
        {
            return Err(SourceFunctionInterfaceError::InvalidFramePointerStorage);
        }
        self.frame_pointer_storage = Some(storage);
        Ok(self)
    }

    pub const fn frame_pointer_storage(&self) -> Option<CanonicalStorageId> {
        self.frame_pointer_storage
    }

    /// Bind an exact stacked return-address contract. The return address is at
    /// entry SP + 0, occupies one complete address-sized slot, and the return
    /// advances SP by exactly that slot width.
    pub fn with_exact_stacked_return(
        mut self,
        stack_offset: i64,
        slot_size_bytes: u32,
        stack_pointer_delta_bytes: u32,
        address_size_bytes: u32,
    ) -> Result<Self, SourceFunctionInterfaceError> {
        let Some(return_address) = self.return_address_storage else {
            return Err(SourceFunctionInterfaceError::InvalidReturnMechanism);
        };
        let Some(stack_pointer) = self.stack_pointer_storage else {
            return Err(SourceFunctionInterfaceError::InvalidReturnMechanism);
        };
        let return_slot_end = i64::from(slot_size_bytes);
        let overlaps_stack_slot = self.stack_slots.iter().any(|slot| {
            if slot.base != StackAddressBase::StackPointer || slot.base_storage != stack_pointer {
                return false;
            }
            let Some(slot_end) = slot.offset.checked_add(i64::from(slot.size_bytes)) else {
                return true;
            };
            slot.offset < return_slot_end && 0 < slot_end
        });
        if stack_offset != 0
            || slot_size_bytes == 0
            || slot_size_bytes != stack_pointer_delta_bytes
            || slot_size_bytes != address_size_bytes
            || return_address.size != address_size_bytes
            || stack_pointer.size != address_size_bytes
            || !self.return_address_storage_is_valid(return_address)
            || !self.stack_pointer_storage_is_valid(stack_pointer)
            || register_storages_overlap(return_address, stack_pointer)
            || overlaps_stack_slot
        {
            return Err(SourceFunctionInterfaceError::InvalidReturnMechanism);
        }
        self.return_mechanism = Some(SourceReturnMechanism::Stacked {
            stack_offset,
            slot_size_bytes,
            stack_pointer_delta_bytes,
            address_size_bytes,
        });
        Ok(self)
    }

    pub const fn return_mechanism(&self) -> Option<SourceReturnMechanism> {
        self.return_mechanism
    }

    /// Return the unique full frame-pointer carrier from an exact stack-slot
    /// contract. This derives a storage identity only; it grants no frame
    /// certification authority.
    pub fn exact_frame_pointer_storage(&self) -> Option<CanonicalStorageId> {
        if let Some(storage) = self.frame_pointer_storage {
            return self
                .frame_pointer_storage_is_valid(storage)
                .then_some(storage);
        }
        // Derived from the bases, not from the roles. Every frame-pointer
        // slot names the same carrier or this refuses, and a slot whose role
        // the analysis could not attribute still names its base -- so one
        // unclassified local used to hide the frame pointer, and with it every
        // stack root, every frame object a call takes the address of, and
        // every escape those addresses stand for.
        let mut frame_slots = self
            .stack_slots
            .iter()
            .filter(|slot| slot.base == StackAddressBase::FramePointer);
        let storage = frame_slots.next()?.base_storage;
        if !valid_register_storage(storage) || frame_slots.any(|slot| slot.base_storage != storage)
        {
            return None;
        }
        let stack_pointer = self.stack_pointer_storage?;
        let return_address = self.return_address_storage?;
        if storage.size != stack_pointer.size
            || !self.stack_pointer_storage_is_valid(stack_pointer)
            || !self.return_address_storage_is_valid(return_address)
        {
            return None;
        }
        let overlaps_source_carrier = self
            .parameters
            .iter()
            .filter_map(SourceAbiParameterSpec::register_storage)
            .chain(match self.return_kind {
                SourceFunctionReturn::Void | SourceFunctionReturn::Unproven => None,
                SourceFunctionReturn::Register { storage } => Some(storage),
            })
            .chain(Some(return_address))
            .chain(Some(stack_pointer))
            .chain(
                self.stack_slots
                    .iter()
                    .filter(|slot| slot.base == StackAddressBase::StackPointer)
                    .map(SourceStackSlotSpec::base_storage),
            )
            .chain(self.stack_slots.iter().filter_map(|slot| match slot.role {
                SourceStackSlotRole::ParameterHome { home_storage, .. } => Some(home_storage),
                SourceStackSlotRole::UnclassifiedResource
                | SourceStackSlotRole::Local
                | SourceStackSlotRole::Parameter { .. } => None,
            }))
            .any(|other| register_storages_overlap(storage, other));
        (!overlaps_source_carrier).then_some(storage)
    }

    pub const fn stack_slots(&self) -> &[SourceStackSlotSpec] {
        &self.stack_slots
    }

    pub const fn parameter_logical_values(&self) -> &[Option<SourceLogicalValue>] {
        &self.parameter_logical_values
    }

    /// The exact type of one parameter, when the capture placed it.
    pub fn parameter_logical_value(&self, index: usize) -> Option<SourceLogicalValue> {
        self.parameter_logical_values.get(index).copied().flatten()
    }

    pub const fn return_logical_value(&self) -> Option<SourceLogicalValue> {
        self.return_logical_value
    }

    pub const fn type_graph(&self) -> Option<&SourceTypeGraph> {
        self.type_graph.as_ref()
    }

    pub const fn stack_slot_roles_complete(&self) -> bool {
        self.stack_slot_roles_complete
    }
}

fn valid_register_storage(storage: CanonicalStorageId) -> bool {
    storage.space == CanonicalStorageSpace::Register
        && storage.size > 0
        && storage
            .offset
            .checked_add(u64::from(storage.size))
            .is_some()
}

fn register_storages_overlap(left: CanonicalStorageId, right: CanonicalStorageId) -> bool {
    let Some(left_end) = left.offset.checked_add(u64::from(left.size)) else {
        return true;
    };
    let Some(right_end) = right.offset.checked_add(u64::from(right.size)) else {
        return true;
    };
    left.offset < right_end && right.offset < left_end
}

/// Stable identity of one call in the lifted input: the native instruction
/// the transfer was lifted from, and the storage it transfers to.
///
/// An instruction address survives everything SSA construction does to the
/// operation stream -- block splitting, the synthetic call-boundary
/// definitions, every rewrite that drops or reorders operations -- which is
/// what lets a fact recorded against the raw input find its operation in the
/// prepared function. A position in a block does not survive any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SourceCallSiteIdentity {
    instruction: u64,
    target: CanonicalStorageId,
}

impl SourceCallSiteIdentity {
    pub const fn new(instruction: u64, target: CanonicalStorageId) -> Self {
        Self {
            instruction,
            target,
        }
    }

    /// Address of the native instruction the transfer was lifted from.
    pub const fn instruction(self) -> u64 {
        self.instruction
    }

    pub const fn target(self) -> CanonicalStorageId {
        self.target
    }
}

/// One ordered, full-width register argument at an explicit call boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceCallArgumentSpec {
    index: u32,
    location: SourceParameterLocation,
}

impl SourceCallArgumentSpec {
    /// An argument passed in a register.
    pub const fn new(index: u32, storage: CanonicalStorageId) -> Self {
        Self {
            index,
            location: SourceParameterLocation::Register(storage),
        }
    }

    /// An argument passed in the argument area, `offset` bytes above the
    /// stack pointer at the call instruction.
    pub const fn on_stack(index: u32, offset: i64, size_bytes: u32) -> Self {
        Self::on_stack_with_callee_view(index, offset, size_bytes, offset)
    }

    /// The same argument, with the coordinate the callee will read it at.
    pub const fn on_stack_with_callee_view(
        index: u32,
        offset: i64,
        size_bytes: u32,
        callee_offset: i64,
    ) -> Self {
        Self {
            index,
            location: SourceParameterLocation::Stack {
                offset,
                size_bytes,
                callee_offset,
            },
        }
    }

    pub const fn with_location(index: u32, location: SourceParameterLocation) -> Self {
        Self { index, location }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn location(self) -> SourceParameterLocation {
        self.location
    }

    /// The register this argument is passed in, when it is passed in one.
    pub const fn register_storage(self) -> Option<CanonicalStorageId> {
        self.location.register()
    }
}

/// Explicit result contract for one call. Absence of a callsite interface is
/// unknown and is deliberately distinct from `Void`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceCallResult {
    Void,
    Register { storage: CanonicalStorageId },
}

/// A callee that hands back one of its own arguments as a format string.
///
/// `printf(_("%s: %d"), ...)` is `printf(gettext("..."), ...)`, so the format
/// the callee receives is a translation chosen at run time and no literal
/// reaches the call. The msgid is in the binary, and gettext's contract is
/// that a translation carries the same conversion specifiers in the same
/// order -- `msgfmt -c` enforces it and a mismatch is a bug in the catalogue.
/// So the msgid settles how many arguments the call passed, which is the only
/// claim made here; it is not a claim that the program prints the msgid.
///
/// radare2 has no prototype for the gettext family at all, and could not
/// express this one if it did: the format is what the callee returns, not a
/// parameter it takes, and a type database has no key for that. The family is
/// therefore named where the source names are known, and travels as a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceFormatForwardingRule {
    msgid_argument_index: u32,
}

impl SourceFormatForwardingRule {
    /// The gettext family, by the argument each one takes its msgid in.
    ///
    /// A closed list of one standardised API, not a guess: every entry returns
    /// a translation of the named argument, and nothing else in libc does.
    pub const FAMILY: &'static [(&'static str, u32)] = &[
        ("gettext", 0),
        ("dgettext", 1),
        ("dcgettext", 1),
        ("ngettext", 0),
        ("dngettext", 1),
        ("dcngettext", 1),
    ];

    /// The rule for a call target, by the name the call renders with.
    ///
    /// radare2 spells a target with a prefix it chose -- `sym.imp.gettext` for
    /// an ELF import, `sym._gettext` for Mach-O, where the linker's own
    /// leading underscore survives -- so the last path component is matched
    /// with leading underscores removed.
    pub fn for_target_name(name: &str) -> Option<Self> {
        let bare = name.rsplit(['.', ':']).next().unwrap_or(name);
        let bare = bare.trim_start_matches('_');
        Self::FAMILY
            .iter()
            .find(|(known, _)| *known == bare)
            .map(|(_, index)| Self {
                msgid_argument_index: *index,
            })
    }

    pub const fn msgid_argument_index(self) -> u32 {
        self.msgid_argument_index
    }
}

/// Which fixed parameter the callee consumes as a printf format, and what
/// proved it.
///
/// A variadic callsite counts its tail from the literal that reaches this
/// parameter. A callsite with a fixed prototype -- `vfprintf` and the
/// `va_list` half of every wrapper -- has nothing to count, and carries the
/// rule so that a caller's body can be seen to forward its own parameter as
/// a format through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceFormatParameterRule {
    /// radare2's recovered prototype named this fixed parameter `format`.
    Radare2FormatString { parameter_index: u32 },
    /// The callee's own body forwards this fixed parameter as the format
    /// argument of a function whose prototype names one. radare2 has a
    /// prototype for the whole `v*printf` family and rarely for the wrapper,
    /// so the body is what identifies the wrapper's format parameter.
    BodyProvenFormatString { parameter_index: u32 },
}

impl SourceFormatParameterRule {
    /// The fixed parameter the rule names, whichever proved it.
    pub const fn parameter_index(self) -> u32 {
        match self {
            Self::Radare2FormatString { parameter_index }
            | Self::BodyProvenFormatString { parameter_index } => parameter_index,
        }
    }
}

/// Source-owned prototype and observed carrier contract for one exact raw
/// callsite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCallSiteInterface {
    schema_version: u32,
    revision_identity: Box<[u8]>,
    identity: SourceCallSiteIdentity,
    complete: bool,
    calling_convention: String,
    abi_class: SourceAbiClass,
    arguments: Box<[SourceCallArgumentSpec]>,
    variadic: bool,
    format_parameter_rule: Option<SourceFormatParameterRule>,
    /// Set when this call's target hands back one of its own arguments as a
    /// format string, so a caller can count from the msgid it passed.
    format_forwarding: Option<SourceFormatForwardingRule>,
    noreturn: bool,
    result: SourceCallResult,
    /// Exact callee-owned interface recovered from a body in the same capture.
    ///
    /// This is a runtime projection rather than snapshot input, so it is
    /// excluded from the source wire representation. The call-site carrier
    /// contract above remains the admission gate; [`Self::with_exact_callee_interface`]
    /// accepts this projection only when every carrier agrees.
    #[serde(skip)]
    exact_callee_interface: Option<Box<SourceFunctionInterface>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCallSiteInterfaceError {
    EmptyRevisionIdentity,
    InvalidTargetStorage,
    EmptyCallingConvention,
    InvalidArgumentOrder,
    InvalidRegisterStorage,
    OverlappingRegisterStorages,
    InvalidFormatParameterIndex,
    NoreturnWithResult,
    IncompatibleCalleeInterface,
}

impl std::fmt::Display for SourceCallSiteInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid source callsite interface: {self:?}")
    }
}

impl std::error::Error for SourceCallSiteInterfaceError {}

impl SourceCallSiteInterface {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision_identity: impl Into<Vec<u8>>,
        identity: SourceCallSiteIdentity,
        complete: bool,
        calling_convention: impl Into<String>,
        arguments: impl IntoIterator<Item = SourceCallArgumentSpec>,
        variadic: bool,
        noreturn: bool,
        result: SourceCallResult,
    ) -> Result<Self, SourceCallSiteInterfaceError> {
        let revision_identity = revision_identity.into();
        if revision_identity.is_empty() {
            return Err(SourceCallSiteInterfaceError::EmptyRevisionIdentity);
        }
        if !valid_call_target_storage(identity.target) {
            return Err(SourceCallSiteInterfaceError::InvalidTargetStorage);
        }
        let calling_convention = calling_convention.into();
        if calling_convention.trim().is_empty() {
            return Err(SourceCallSiteInterfaceError::EmptyCallingConvention);
        }
        let abi_class = SourceAbiClass::from_source_spelling(&calling_convention);
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments
            .iter()
            .enumerate()
            .any(|(index, argument)| u32::try_from(index) != Ok(argument.index))
        {
            return Err(SourceCallSiteInterfaceError::InvalidArgumentOrder);
        }
        if arguments
            .iter()
            .any(|argument| !argument.location.is_valid())
            || matches!(
                result,
                SourceCallResult::Register { storage } if !valid_register_storage(storage)
            )
        {
            return Err(SourceCallSiteInterfaceError::InvalidRegisterStorage);
        }
        if arguments.iter().enumerate().any(|(index, argument)| {
            arguments[index.saturating_add(1)..]
                .iter()
                .any(|other| argument.location.overlaps(other.location))
        }) {
            return Err(SourceCallSiteInterfaceError::OverlappingRegisterStorages);
        }
        if noreturn && !matches!(result, SourceCallResult::Void) {
            return Err(SourceCallSiteInterfaceError::NoreturnWithResult);
        }
        Ok(Self {
            schema_version: SOURCE_CALL_SITE_INTERFACE_SCHEMA_VERSION,
            revision_identity: revision_identity.into_boxed_slice(),
            identity,
            complete,
            calling_convention,
            abi_class,
            arguments: arguments.into_boxed_slice(),
            variadic,
            format_parameter_rule: None,
            format_forwarding: None,
            noreturn,
            result,
            exact_callee_interface: None,
        })
    }

    /// Attach a callee-owned logical interface when its physical call
    /// contract is exactly this call site's contract.
    ///
    /// The two are not required to share a revision: a capture set is
    /// consistent by construction, every body in it current by the analysis
    /// epochs when the root was read, and a body kept across roots carries
    /// the revision of its own capture. A variadic call matches on its fixed
    /// prefix: the callee's interface names only that, and the tail is the
    /// call site's own.
    pub fn with_exact_callee_interface(
        mut self,
        callee: SourceFunctionInterface,
    ) -> Result<Self, SourceCallSiteInterfaceError> {
        let expected_result = match callee.return_kind() {
            SourceFunctionReturn::Void => SourceCallResult::Void,
            SourceFunctionReturn::Register { storage } => SourceCallResult::Register { storage },
            // An unproven result is no claim, so no exact contract holds it.
            SourceFunctionReturn::Unproven => {
                return Err(SourceCallSiteInterfaceError::IncompatibleCalleeInterface);
            }
        };
        let carriers_match = self.complete
            && !self.noreturn
            && self.abi_class == callee.abi_class()
            && self.result == expected_result
            && self.arguments.len() == callee.parameters().len()
            && self
                .arguments
                .iter()
                .zip(callee.parameters())
                .all(|(argument, parameter)| {
                    argument.index() == parameter.index()
                        && callee.argument_location_matches_parameter(
                            argument.location(),
                            parameter.location(),
                        )
                });
        if !carriers_match {
            return Err(SourceCallSiteInterfaceError::IncompatibleCalleeInterface);
        }
        self.exact_callee_interface = Some(Box::new(callee));
        Ok(self)
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn revision_identity(&self) -> &[u8] {
        &self.revision_identity
    }

    pub const fn identity(&self) -> SourceCallSiteIdentity {
        self.identity
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn calling_convention(&self) -> &str {
        &self.calling_convention
    }

    pub const fn abi_class(&self) -> SourceAbiClass {
        self.abi_class
    }

    pub const fn arguments(&self) -> &[SourceCallArgumentSpec] {
        &self.arguments
    }

    pub const fn is_variadic(&self) -> bool {
        self.variadic
    }

    /// Bind the format parameter identified by the source owner's recovered
    /// prototype. The checked builder keeps an untrusted presentation name
    /// from manufacturing an out-of-range semantic role.
    pub fn with_radare2_format_parameter(
        mut self,
        parameter_index: u32,
    ) -> Result<Self, SourceCallSiteInterfaceError> {
        self.check_format_parameter(parameter_index)?;
        self.format_parameter_rule =
            Some(SourceFormatParameterRule::Radare2FormatString { parameter_index });
        Ok(self)
    }

    /// Bind the format parameter the callee's own body proves.
    ///
    /// radare2's prototype is not overridden where it has one: a rule already
    /// bound stands, so the two never disagree silently.
    pub fn with_body_proven_format_parameter(
        mut self,
        parameter_index: u32,
    ) -> Result<Self, SourceCallSiteInterfaceError> {
        self.check_format_parameter(parameter_index)?;
        if self.format_parameter_rule.is_none() {
            self.format_parameter_rule =
                Some(SourceFormatParameterRule::BodyProvenFormatString { parameter_index });
        }
        Ok(self)
    }

    fn check_format_parameter(
        &self,
        parameter_index: u32,
    ) -> Result<(), SourceCallSiteInterfaceError> {
        if usize::try_from(parameter_index)
            .ok()
            .is_none_or(|index| index >= self.arguments.len())
        {
            return Err(SourceCallSiteInterfaceError::InvalidFormatParameterIndex);
        }
        Ok(())
    }

    /// Record that this call's target returns a translation of one of its own
    /// arguments. Checked against the arguments the call actually carries, so
    /// a name match cannot name an argument that is not there.
    pub fn with_format_forwarding(
        mut self,
        rule: SourceFormatForwardingRule,
    ) -> Result<Self, SourceCallSiteInterfaceError> {
        if usize::try_from(rule.msgid_argument_index())
            .ok()
            .is_none_or(|index| index >= self.arguments.len())
        {
            return Err(SourceCallSiteInterfaceError::InvalidFormatParameterIndex);
        }
        self.format_forwarding = Some(rule);
        Ok(self)
    }

    pub const fn format_forwarding(&self) -> Option<SourceFormatForwardingRule> {
        self.format_forwarding
    }

    pub const fn format_parameter_rule(&self) -> Option<SourceFormatParameterRule> {
        self.format_parameter_rule
    }

    pub const fn is_noreturn(&self) -> bool {
        self.noreturn
    }

    pub const fn result(&self) -> SourceCallResult {
        self.result
    }

    pub fn exact_callee_interface(&self) -> Option<&SourceFunctionInterface> {
        self.exact_callee_interface.as_deref()
    }
}

fn valid_call_target_storage(storage: CanonicalStorageId) -> bool {
    !storage.is_unknown()
        && storage.size > 0
        && storage
            .offset
            .checked_add(u64::from(storage.size))
            .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register_storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn exact_return_interface(
        revision: &[u8],
        calling_convention: &str,
        stack_slots: impl IntoIterator<Item = SourceStackSlotSpec>,
    ) -> SourceFunctionInterface {
        SourceFunctionInterface::new_exact(
            revision.to_vec(),
            calling_convention,
            [],
            SourceFunctionReturn::Void,
            stack_slots,
        )
        .and_then(|interface| interface.with_return_address_storage(register_storage(80, 8)))
        .and_then(|interface| interface.with_stack_pointer_storage(register_storage(72, 8)))
        .expect("exact return carriers")
    }

    fn test_call_site(calling_convention: &str) -> SourceCallSiteInterface {
        SourceCallSiteInterface::new(
            b"abi-class-callsite".to_vec(),
            SourceCallSiteIdentity::new(
                0x1000,
                CanonicalStorageId {
                    space: CanonicalStorageSpace::Constant,
                    offset: 0x2000,
                    size: 8,
                },
            ),
            true,
            calling_convention,
            [],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("test callsite")
    }

    #[test]
    fn abi_class_synonyms_are_classified_once_on_each_source_contract() {
        let slots = SourceConventionSlots::new("windows_x64", [], None).expect("slots");
        assert_eq!(slots.abi_class(), SourceAbiClass::MicrosoftX64);
        assert_eq!(slots.calling_convention(), "windows_x64");

        let function = SourceFunctionInterface::new_exact(
            b"abi-class-function".to_vec(),
            "sysv-amd64",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("function interface");
        assert_eq!(function.abi_class(), SourceAbiClass::SystemVAMD64);
        assert_eq!(function.calling_convention(), "sysv-amd64");

        let callsite = test_call_site("microsoft-x64");
        assert_eq!(callsite.abi_class(), SourceAbiClass::MicrosoftX64);
        assert_eq!(callsite.calling_convention(), "microsoft-x64");

        assert_eq!(
            SourceAbiClass::from_source_spelling("ms"),
            SourceAbiClass::Microsoft
        );

        for spelling in ["win64", "windows-x64", "MS_X64"] {
            assert_eq!(
                SourceAbiClass::from_source_spelling(spelling),
                SourceAbiClass::MicrosoftX64
            );
        }
        for spelling in ["sysv64", "system-v-amd64", "x86_64_sysv"] {
            assert_eq!(
                SourceAbiClass::from_source_spelling(spelling),
                SourceAbiClass::SystemVAMD64
            );
        }
    }

    #[test]
    fn abi_class_preserves_renamed_other_spellings_as_presentation_only() {
        let first = SourceConventionSlots::new("vendor-abi-a", [], None).expect("first slots");
        let renamed =
            SourceConventionSlots::new("renamed-vendor-abi", [], None).expect("renamed slots");

        assert_eq!(first.abi_class(), SourceAbiClass::Other);
        assert_eq!(renamed.abi_class(), SourceAbiClass::Other);
        assert_ne!(first.calling_convention(), renamed.calling_convention());
    }

    #[test]
    fn a_format_count_rule_is_checked_against_the_variadic_fixed_prefix() {
        let identity = SourceCallSiteIdentity::new(
            0x1000,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        );
        let arguments = [
            SourceCallArgumentSpec::new(0, register_storage(0, 8)),
            SourceCallArgumentSpec::new(1, register_storage(8, 8)),
        ];
        let variadic = SourceCallSiteInterface::new(
            b"format-rule".to_vec(),
            identity,
            true,
            "sysv-amd64",
            arguments,
            true,
            false,
            SourceCallResult::Void,
        )
        .expect("variadic interface")
        .with_radare2_format_parameter(1)
        .expect("second fixed parameter is the format");
        assert_eq!(
            variadic.format_parameter_rule(),
            Some(SourceFormatParameterRule::Radare2FormatString { parameter_index: 1 })
        );
        assert_eq!(
            variadic.with_radare2_format_parameter(2),
            Err(SourceCallSiteInterfaceError::InvalidFormatParameterIndex)
        );

        let fixed = SourceCallSiteInterface::new(
            b"fixed-format-rule".to_vec(),
            identity,
            true,
            "sysv-amd64",
            arguments,
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("fixed interface")
        .with_radare2_format_parameter(1)
        .expect("a va_list callee names its format without a tail to count");
        assert!(!fixed.is_variadic());
        assert_eq!(
            fixed.format_parameter_rule(),
            Some(SourceFormatParameterRule::Radare2FormatString { parameter_index: 1 })
        );
    }

    #[test]
    fn a_body_proven_format_parameter_is_checked_and_never_overrides_radare2() {
        let identity = SourceCallSiteIdentity::new(
            0x1000,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        );
        let arguments = [
            SourceCallArgumentSpec::new(0, register_storage(0, 8)),
            SourceCallArgumentSpec::new(1, register_storage(8, 8)),
        ];
        let bare = || {
            SourceCallSiteInterface::new(
                b"body-format-rule".to_vec(),
                identity,
                true,
                "sysv-amd64",
                arguments,
                true,
                false,
                SourceCallResult::Void,
            )
            .expect("variadic interface")
        };

        let proven = bare()
            .with_body_proven_format_parameter(0)
            .expect("first fixed parameter is the format");
        assert_eq!(
            proven.format_parameter_rule(),
            Some(SourceFormatParameterRule::BodyProvenFormatString { parameter_index: 0 })
        );
        assert_eq!(
            proven
                .format_parameter_rule()
                .map(|rule| rule.parameter_index()),
            Some(0)
        );

        // The same bound is applied whichever proved it.
        assert_eq!(
            bare().with_body_proven_format_parameter(2),
            Err(SourceCallSiteInterfaceError::InvalidFormatParameterIndex)
        );

        // radare2's prototype is the exact recovered contract; a body proof
        // fills a gap rather than contradicting one.
        let both = bare()
            .with_radare2_format_parameter(1)
            .expect("radare2 named the second")
            .with_body_proven_format_parameter(0)
            .expect("body proof is accepted and ignored");
        assert_eq!(
            both.format_parameter_rule(),
            Some(SourceFormatParameterRule::Radare2FormatString { parameter_index: 1 })
        );
    }

    #[test]
    fn a_body_proven_format_parameter_must_name_a_parameter_the_function_has() {
        let interface = SourceFunctionInterface::new_exact(
            b"body-format-function".to_vec(),
            "sysv-amd64",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("bare function interface");
        assert_eq!(interface.body_proven_format_parameter(), None);
        assert_eq!(
            interface.with_body_proven_format_parameter(0),
            Err(SourceFunctionInterfaceError::InvalidFormatParameterIndex)
        );
    }

    #[test]
    fn abi_class_keeps_unknown_and_source_specific_spellings_honest() {
        let absent = SourceConventionSlots::new("", [], None).expect("absent convention slots");
        assert_eq!(absent.abi_class(), SourceAbiClass::Unknown);
        assert_eq!(
            SourceFunctionInterface::new_exact(
                b"unknown-function-abi".to_vec(),
                "unknown",
                [],
                SourceFunctionReturn::Void,
                [],
            )
            .expect("unknown function convention")
            .abi_class(),
            SourceAbiClass::Unknown
        );
        assert_eq!(
            test_call_site("default").abi_class(),
            SourceAbiClass::Unknown
        );
        assert_eq!(
            SourceAbiClass::from_source_spelling("amd64"),
            SourceAbiClass::SystemVAMD64,
            "radare2's exact callconv field uses amd64 for System V AMD64"
        );
        assert_eq!(
            SourceAbiClass::from_source_spelling("aapcs64"),
            SourceAbiClass::Aapcs64
        );
        assert_eq!(
            SourceAbiClass::from_source_spelling("riscv64"),
            SourceAbiClass::RiscV64
        );
    }

    #[test]
    fn slot_of_unestablished_extent_is_kept_without_an_exact_role_claim() {
        let stack_pointer = register_storage(72, 8);
        let slots = [
            SourceStackSlotSpec::new(StackAddressBase::StackPointer, stack_pointer, -40, 0),
            SourceStackSlotSpec::new(StackAddressBase::StackPointer, stack_pointer, -16, 8),
        ];
        let interface = SourceFunctionInterface::new(
            b"revision".to_vec(),
            "amd64",
            [],
            SourceFunctionReturn::Void,
            slots,
        )
        .expect("a located slot of unknown extent is still a fact");
        assert_eq!(interface.stack_slots().len(), 2);
        assert!(!interface.stack_slot_roles_complete());
    }

    #[test]
    fn exact_role_claim_refuses_a_slot_of_unestablished_extent() {
        let stack_pointer = register_storage(72, 8);
        assert_eq!(
            SourceFunctionInterface::new_exact(
                b"revision".to_vec(),
                "amd64",
                [],
                SourceFunctionReturn::Void,
                [SourceStackSlotSpec::new_local(
                    StackAddressBase::StackPointer,
                    stack_pointer,
                    -40,
                    0,
                )],
            ),
            Err(SourceFunctionInterfaceError::InvalidStackSlot)
        );
    }

    #[test]
    fn exact_stacked_return_is_revision_bound_and_name_independent() {
        let stack_pointer = register_storage(72, 8);
        let slots = [
            SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, stack_pointer, -8, 8),
            SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, stack_pointer, 8, 8),
        ];
        let exact = exact_return_interface(b"stacked-revision-a", "abi-display-a", slots)
            .with_exact_stacked_return(0, 8, 8, 8)
            .expect("exact stacked return");
        assert_eq!(
            exact.schema_version(),
            SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION
        );
        assert_eq!(exact.revision_identity(), b"stacked-revision-a");
        assert_eq!(
            exact.return_mechanism(),
            Some(SourceReturnMechanism::Stacked {
                stack_offset: 0,
                slot_size_bytes: 8,
                stack_pointer_delta_bytes: 8,
                address_size_bytes: 8,
            })
        );
        let mechanism = exact.return_mechanism().expect("stacked mechanism");
        assert_eq!(mechanism.stack_offset(), 0);
        assert_eq!(mechanism.slot_size_bytes(), 8);
        assert_eq!(mechanism.stack_pointer_delta_bytes(), 8);
        assert_eq!(mechanism.address_size_bytes(), 8);

        let renamed = exact_return_interface(b"stacked-revision-b", "abi-display-b", slots)
            .with_exact_stacked_return(0, 8, 8, 8)
            .expect("renamed exact stacked return");
        assert_eq!(renamed.return_mechanism(), exact.return_mechanism());
        assert_ne!(renamed.revision_identity(), exact.revision_identity());
        assert_ne!(renamed.calling_convention(), exact.calling_convention());
    }

    #[test]
    fn exact_stacked_return_rejects_missing_or_incoherent_carriers() {
        let unbound = SourceFunctionInterface::new_exact(
            b"stacked-unbound".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("unbound exact interface");
        assert_eq!(
            unbound.clone().with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );
        assert_eq!(
            unbound
                .clone()
                .with_return_address_storage(register_storage(80, 8))
                .expect("return-address-only interface")
                .with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );
        assert_eq!(
            unbound
                .with_stack_pointer_storage(register_storage(72, 8))
                .expect("stack-pointer-only interface")
                .with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );

        let exact = exact_return_interface(b"stacked-carriers", "test-abi", []);
        let mut invalid_return_address = exact.clone();
        invalid_return_address.return_address_storage = Some(CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            offset: 80,
            size: 8,
        });
        assert_eq!(
            invalid_return_address.with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );
        let mut overlapping = exact.clone();
        overlapping.return_address_storage = overlapping.stack_pointer_storage;
        assert_eq!(
            overlapping.with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );
        let mut narrow_stack_pointer = exact;
        narrow_stack_pointer.stack_pointer_storage = Some(register_storage(72, 4));
        assert_eq!(
            narrow_stack_pointer.with_exact_stacked_return(0, 8, 8, 8),
            Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
        );
    }

    #[test]
    fn exact_stacked_return_rejects_inexact_geometry_and_stack_overlap() {
        let exact = exact_return_interface(b"stacked-geometry", "test-abi", []);
        for geometry in [(1, 8, 8, 8), (0, 0, 0, 0), (0, 8, 4, 8), (0, 8, 8, 4)] {
            assert_eq!(
                exact
                    .clone()
                    .with_exact_stacked_return(geometry.0, geometry.1, geometry.2, geometry.3,),
                Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
            );
        }

        let stack_pointer = register_storage(72, 8);
        for (offset, size) in [(0, 8), (-4, 8), (4, 8)] {
            let overlapping = exact_return_interface(
                b"stacked-overlap",
                "test-abi",
                [SourceStackSlotSpec::new_local(
                    StackAddressBase::StackPointer,
                    stack_pointer,
                    offset,
                    size,
                )],
            );
            assert_eq!(
                overlapping.with_exact_stacked_return(0, 8, 8, 8),
                Err(SourceFunctionInterfaceError::InvalidReturnMechanism)
            );
        }
    }

    #[test]
    fn exact_stacked_return_cannot_be_invalidated_by_carrier_rebinding() {
        let exact = exact_return_interface(b"stacked-sealed", "test-abi", [])
            .with_exact_stacked_return(0, 8, 8, 8)
            .expect("exact stacked return");
        assert!(
            exact
                .clone()
                .with_return_address_storage(register_storage(88, 8))
                .is_err()
        );
        assert!(
            exact
                .clone()
                .with_stack_pointer_storage(register_storage(96, 8))
                .is_err()
        );
        assert_eq!(
            exact
                .clone()
                .with_return_address_storage(register_storage(80, 8))
                .expect("idempotent return-address binding")
                .return_mechanism(),
            exact.return_mechanism()
        );
        assert_eq!(
            exact
                .clone()
                .with_stack_pointer_storage(register_storage(72, 8))
                .expect("idempotent stack-pointer binding")
                .return_mechanism(),
            exact.return_mechanism()
        );
    }

    #[test]
    fn exact_frame_pointer_storage_requires_one_disjoint_exact_base() {
        let parameter = register_storage(0, 8);
        let result = register_storage(8, 8);
        let frame_pointer = register_storage(64, 8);
        let stack_pointer = register_storage(72, 8);
        let return_address = register_storage(80, 8);
        let exact = SourceFunctionInterface::new_exact(
            b"exact-frame-pointer".to_vec(),
            "test-abi",
            [SourceAbiParameterSpec::new(0, parameter)],
            SourceFunctionReturn::Register { storage: result },
            [
                SourceStackSlotSpec::new_local(
                    StackAddressBase::FramePointer,
                    frame_pointer,
                    -16,
                    8,
                ),
                SourceStackSlotSpec::new_parameter_home(
                    StackAddressBase::FramePointer,
                    frame_pointer,
                    -8,
                    8,
                    0,
                    parameter,
                ),
                SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, stack_pointer, 0, 8),
            ],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("coherent exact frame carriers");
        assert_eq!(exact.exact_frame_pointer_storage(), Some(frame_pointer));

        let unbound = SourceFunctionInterface::new_exact(
            b"unbound-frame-pointer".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )],
        )
        .expect("unbound exact stack roles");
        assert_eq!(unbound.exact_frame_pointer_storage(), None);
        assert_eq!(
            unbound
                .clone()
                .with_return_address_storage(return_address)
                .expect("return-address-only binding")
                .exact_frame_pointer_storage(),
            None
        );
        assert_eq!(
            unbound
                .with_stack_pointer_storage(stack_pointer)
                .expect("stack-pointer-only binding")
                .exact_frame_pointer_storage(),
            None
        );

        let inexact = SourceFunctionInterface::new(
            b"advisory-frame-pointer".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )],
        )
        .expect("advisory frame resource");
        assert_eq!(inexact.exact_frame_pointer_storage(), None);

        let stack_only = SourceFunctionInterface::new_exact(
            b"stack-only".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                stack_pointer,
                0,
                8,
            )],
        )
        .expect("exact stack-only resource");
        assert_eq!(stack_only.exact_frame_pointer_storage(), None);

        let parameter_overlap = SourceFunctionInterface::new_exact(
            b"frame-parameter-overlap".to_vec(),
            "test-abi",
            [SourceAbiParameterSpec::new(0, frame_pointer)],
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
        .expect("representable overlapping source carriers");
        assert_eq!(parameter_overlap.exact_frame_pointer_storage(), None);

        let result_overlap = SourceFunctionInterface::new_exact(
            b"frame-result-overlap".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Register {
                storage: frame_pointer,
            },
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("representable overlapping result carrier");
        assert_eq!(result_overlap.exact_frame_pointer_storage(), None);

        let narrow_frame_pointer = register_storage(88, 4);
        let width_mismatch = SourceFunctionInterface::new_exact(
            b"frame-stack-width-mismatch".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                narrow_frame_pointer,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("representable frame/SP width mismatch");
        assert_eq!(width_mismatch.exact_frame_pointer_storage(), None);

        let stack_overlap = SourceFunctionInterface::new_exact(
            b"frame-stack-overlap".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [
                SourceStackSlotSpec::new_local(
                    StackAddressBase::FramePointer,
                    frame_pointer,
                    -8,
                    8,
                ),
                SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, frame_pointer, 0, 8),
            ],
        )
        .expect("representable overlapping stack bases");
        assert_eq!(stack_overlap.exact_frame_pointer_storage(), None);
    }

    #[test]
    fn explicit_frame_pointer_storage_is_exact_without_stack_slots_and_name_independent() {
        let frame_pointer = register_storage(64, 8);
        let stack_pointer = register_storage(72, 8);
        let return_address = register_storage(80, 8);
        let build = |revision: &[u8], calling_convention: &str| {
            SourceFunctionInterface::new_exact(
                revision.to_vec(),
                calling_convention,
                [],
                SourceFunctionReturn::Void,
                [],
            )
            .and_then(|interface| interface.with_return_address_storage(return_address))
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .and_then(|interface| interface.with_frame_pointer_storage(frame_pointer))
        };
        let explicit = build(b"explicit-frame-a", "abi-display-a").expect("explicit frame fact");
        assert_eq!(explicit.frame_pointer_storage(), Some(frame_pointer));
        assert_eq!(explicit.exact_frame_pointer_storage(), Some(frame_pointer));

        let renamed = build(b"explicit-frame-b", "abi-display-b").expect("renamed frame fact");
        assert_eq!(
            renamed.frame_pointer_storage(),
            explicit.frame_pointer_storage()
        );
        assert_eq!(
            renamed.exact_frame_pointer_storage(),
            explicit.exact_frame_pointer_storage()
        );
        assert_ne!(renamed.revision_identity(), explicit.revision_identity());
        assert_ne!(renamed.calling_convention(), explicit.calling_convention());
    }

    #[test]
    fn explicit_frame_pointer_storage_rejects_incoherent_carriers() {
        let parameter = register_storage(0, 8);
        let result = register_storage(8, 8);
        let frame_pointer = register_storage(64, 8);
        let stack_pointer = register_storage(72, 8);
        let return_address = register_storage(80, 8);
        let no_stack_pointer = SourceFunctionInterface::new_exact(
            b"explicit-frame-no-sp".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("slotless interface");
        assert_eq!(
            no_stack_pointer.with_frame_pointer_storage(frame_pointer),
            Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
        );
        let base = SourceFunctionInterface::new_exact(
            b"explicit-frame-validation".to_vec(),
            "test-abi",
            [SourceAbiParameterSpec::new(0, parameter)],
            SourceFunctionReturn::Register { storage: result },
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
        .expect("bound source carriers");

        for overlapping in [parameter, result, stack_pointer, return_address] {
            assert_eq!(
                base.clone().with_frame_pointer_storage(overlapping),
                Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
            );
        }
        assert_eq!(
            base.clone()
                .with_frame_pointer_storage(register_storage(64, 4)),
            Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
        );
        assert_eq!(
            base.clone().with_frame_pointer_storage(CanonicalStorageId {
                space: CanonicalStorageSpace::Ram,
                offset: 64,
                size: 8,
            }),
            Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
        );

        let explicit = base
            .with_frame_pointer_storage(frame_pointer)
            .expect("valid frame pointer");
        assert_eq!(
            explicit
                .clone()
                .with_frame_pointer_storage(register_storage(88, 8)),
            Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
        );
        assert_eq!(
            explicit.clone().with_return_address_storage(frame_pointer),
            Err(SourceFunctionInterfaceError::InvalidReturnAddressStorage)
        );
        assert_eq!(
            explicit.with_stack_pointer_storage(register_storage(96, 4)),
            Err(SourceFunctionInterfaceError::InvalidStackPointerStorage)
        );
    }

    #[test]
    fn explicit_frame_pointer_storage_must_match_every_frame_slot_base() {
        let frame_pointer = register_storage(64, 8);
        let other_frame_pointer = register_storage(88, 8);
        let interface = SourceFunctionInterface::new_exact(
            b"explicit-frame-slots".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::FramePointer,
                frame_pointer,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register_storage(72, 8)))
        .expect("exact frame slot with stack pointer");
        assert_eq!(
            interface
                .clone()
                .with_frame_pointer_storage(other_frame_pointer),
            Err(SourceFunctionInterfaceError::InvalidFramePointerStorage)
        );
        assert_eq!(
            interface
                .with_frame_pointer_storage(frame_pointer)
                .expect("matching explicit frame base")
                .exact_frame_pointer_storage(),
            Some(frame_pointer)
        );
    }

    #[test]
    fn stack_allocation_contract_requires_exact_sp_and_owns_only_its_growth_interval() {
        let lower = SourceStackAllocationContract::new(SourceStackGrowth::LowerAddresses);
        let higher = SourceStackAllocationContract::new(SourceStackGrowth::HigherAddresses);
        let base = SourceMachineRoles::default();
        assert_eq!(
            base.with_stack_allocation_contract(lower),
            Err(SourceMachineRolesError::InvalidStackAllocationContract)
        );

        let exact = SourceMachineRoles::new(None, Some(register_storage(72, 8)))
            .and_then(|roles| roles.with_stack_allocation_contract(lower))
            .expect("exact downward stack allocation contract");
        assert_eq!(exact.stack_allocation_contract(), Some(lower));
        assert!(lower.owns_entry_relative_reservation(-16, 16));
        assert!(!lower.owns_entry_relative_reservation(0, 16));
        assert!(higher.owns_entry_relative_reservation(0, 16));
        assert!(!higher.owns_entry_relative_reservation(-16, 16));
        assert_eq!(
            exact.with_stack_allocation_contract(higher),
            Err(SourceMachineRolesError::InvalidStackAllocationContract)
        );
    }

    #[test]
    fn stack_allocation_contract_checks_implicit_active_sp_envelopes() {
        let lower = SourceStackAllocationContract::with_implicit_active_sp_bytes(
            SourceStackGrowth::LowerAddresses,
            128,
        );
        assert_eq!(lower.implicit_active_sp_bytes(), 128);
        assert_eq!(lower.owned_entry_relative_envelope(0), Some(-128..0));
        assert_eq!(lower.owned_entry_relative_envelope(-32), Some(-160..0));
        assert_eq!(lower.owned_entry_relative_envelope(1), None);
        assert_eq!(lower.owned_entry_relative_envelope(i64::MIN), None);
        assert!(lower.owns_entry_relative_range(0, -128, 128));
        assert!(lower.owns_entry_relative_range(-32, -160, 128));
        assert!(lower.owns_entry_relative_range(-32, -32, 32));
        assert!(!lower.owns_entry_relative_range(0, -129, 128));
        assert!(!lower.owns_entry_relative_range(0, -128, 0));
        assert!(!lower.owns_entry_relative_range(0, -1, 2));

        let higher = SourceStackAllocationContract::with_implicit_active_sp_bytes(
            SourceStackGrowth::HigherAddresses,
            128,
        );
        assert_eq!(higher.owned_entry_relative_envelope(0), Some(0..128));
        assert_eq!(higher.owned_entry_relative_envelope(32), Some(0..160));
        assert_eq!(higher.owned_entry_relative_envelope(-1), None);
        assert_eq!(higher.owned_entry_relative_envelope(i64::MAX), None);
        assert!(higher.owns_entry_relative_range(0, 0, 128));
        assert!(higher.owns_entry_relative_range(32, 32, 128));
        assert!(higher.owns_entry_relative_range(32, 0, 32));
        assert!(!higher.owns_entry_relative_range(0, 1, 128));
        assert!(!higher.owns_entry_relative_range(i64::MAX, i64::MAX, 1));

        let no_implicit = SourceStackAllocationContract::new(SourceStackGrowth::LowerAddresses);
        assert_eq!(no_implicit.owned_entry_relative_envelope(0), Some(0..0));
        assert!(!no_implicit.owns_entry_relative_range(0, 0, 1));
        assert!(no_implicit.owns_entry_relative_range(-16, -16, 16));
    }

    /// A storage survives a call only where preserved registers cover every byte of it.
    #[test]
    fn a_call_preserves_exactly_the_bytes_its_preserved_registers_cover() {
        // Two adjacent halves, a split pair with a gap, and a register nested in a wider preserved one.
        let effect = SourceCallEffect::new(
            [register_storage(0x40, 8)],
            [
                register_storage(0x10, 8),
                register_storage(0x18, 8),
                register_storage(0x80, 4),
                register_storage(0x88, 4),
                register_storage(0xa0, 16),
                register_storage(0xa4, 4),
            ],
        )
        .expect("a call effect");
        assert!(effect.preserves(register_storage(0x10, 16)));
        assert!(effect.preserves(register_storage(0x14, 8)));
        assert!(!effect.preserves(register_storage(0x80, 16)));
        assert!(effect.preserves(register_storage(0x88, 4)));
        assert!(effect.preserves(register_storage(0xa4, 4)));
        assert!(effect.preserves(register_storage(0xa0, 16)));
        // A partial overlap is not preserved, nor is anything past the covered prefix.
        assert!(!effect.preserves(register_storage(0x0c, 8)));
        assert!(!effect.preserves(register_storage(0x18, 16)));
        assert!(!effect.preserves(register_storage(0xa8, 16)));
        assert!(effect.clobbers(register_storage(0x40, 8)));
        assert!(effect.clobbers(register_storage(0x30, 8)));
        assert!(!effect.preserves(CanonicalStorageId {
            space: CanonicalStorageSpace::Unique,
            offset: 0x10,
            size: 8,
        }));
    }

    /// One register named both clobbered and preserved, even through an alias, is a contradiction.
    #[test]
    fn a_call_effect_naming_one_register_both_ways_refuses() {
        assert_eq!(
            SourceCallEffect::new([register_storage(0x10, 8)], [register_storage(0x14, 4)]),
            Err(SourceMachineRolesError::ContradictoryCallEffect)
        );
        assert_eq!(
            SourceCallEffect::new([register_storage(0x10, 8)], [register_storage(0x18, 8)])
                .map(|effect| (effect.clobbered().len(), effect.preserved().len())),
            Ok((1, 1))
        );
    }
}

/// Machine carriers radare2 knows from its register profile.
///
/// These are deliberately separate from [`SourceFunctionInterface`]. Which
/// register holds a return address, and which one is the stack pointer, are
/// properties of the machine: radare2 resolves them from register aliases and
/// they are available whether or not any ABI was recovered. The interface, by
/// contrast, describes an ABI — parameters, calling convention, return type —
/// and exists only when debug information supplied one.
///
/// Carrying both in one structure is what previously made the machine carriers
/// unreachable without debug information, because the whole structure was
/// captured all-or-nothing. Keeping them apart lets a function be reasoned
/// about on its machine facts while its ABI facts stay honestly absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceMachineRoles {
    return_address_storage: Option<CanonicalStorageId>,
    stack_pointer_storage: Option<CanonicalStorageId>,
    /// How the source spells these two carriers, for the same reason the
    /// interface records it: the offsets beside them are in the source's
    /// register numbering and mean nothing to the lifted architecture.
    role_register_names: SourceRoleRegisterNames,
    stack_allocation_contract: Option<SourceStackAllocationContract>,
    /// The flag that decides which way a repeated string instruction walks,
    /// placed against the lifted architecture.
    direction_flag_storage: Option<CanonicalStorageId>,
}

/// Whether a call leaves the frame carriers where they were, as the convention's call effect says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCallPreservedCarriers {
    stack_pointer: bool,
    frame_pointer: bool,
}

impl SourceCallPreservedCarriers {
    pub const fn new(stack_pointer: bool, frame_pointer: bool) -> Self {
        Self {
            stack_pointer,
            frame_pointer,
        }
    }

    pub const fn stack_pointer(self) -> bool {
        self.stack_pointer
    }

    pub const fn frame_pointer(self) -> bool {
        self.frame_pointer
    }

    /// Whether both carriers that can address a frame survive a call.
    pub const fn frame_survives_a_call(self) -> bool {
        self.stack_pointer && self.frame_pointer
    }
}

/// What a call does to the registers: one the convention preserves survives it, and no other does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCallEffect {
    /// Also what a callee's body is asked to prove it leaves alone.
    clobbered: Box<[CanonicalStorageId]>,
    preserved: Box<[CanonicalStorageId]>,
}

impl SourceCallEffect {
    /// Refuses a storage that is not a register, and a register named both ways.
    pub fn new(
        clobbered: impl IntoIterator<Item = CanonicalStorageId>,
        preserved: impl IntoIterator<Item = CanonicalStorageId>,
    ) -> Result<Self, SourceMachineRolesError> {
        let sorted = |storages: Vec<CanonicalStorageId>| {
            let mut storages = storages;
            storages.sort_unstable();
            storages.dedup();
            storages.into_boxed_slice()
        };
        let clobbered = sorted(clobbered.into_iter().collect());
        let preserved = sorted(preserved.into_iter().collect());
        if clobbered
            .iter()
            .chain(preserved.iter())
            .any(|storage| !valid_register_storage(*storage))
        {
            return Err(SourceMachineRolesError::InvalidRegisterStorage);
        }
        if clobbered.iter().any(|clobbered| {
            preserved
                .iter()
                .any(|preserved| register_storages_overlap(*clobbered, *preserved))
        }) {
            return Err(SourceMachineRolesError::ContradictoryCallEffect);
        }
        Ok(Self {
            clobbered,
            preserved,
        })
    }

    /// The registers the convention names as destroyed, sorted.
    pub const fn clobbered(&self) -> &[CanonicalStorageId] {
        &self.clobbered
    }

    /// The registers the convention names as restored, sorted.
    pub const fn preserved(&self) -> &[CanonicalStorageId] {
        &self.preserved
    }

    /// Whether every byte of a storage lies in registers the convention preserves.
    pub fn preserves(&self, storage: CanonicalStorageId) -> bool {
        let Some(end) = storage.offset.checked_add(u64::from(storage.size)) else {
            return false;
        };
        if storage.space != CanonicalStorageSpace::Register || storage.size == 0 {
            return false;
        }
        // One sweep over the preserved ranges in offset order, extending the covered prefix.
        let mut covered = storage.offset;
        for preserved in &self.preserved {
            if preserved.offset > covered {
                return false;
            }
            covered = covered.max(preserved.offset + u64::from(preserved.size));
            if covered >= end {
                return true;
            }
        }
        false
    }

    /// Whether a call may leave this storage changed.
    pub fn clobbers(&self, storage: CanonicalStorageId) -> bool {
        !self.preserves(storage)
    }
}

/// Where the calling convention would place arguments and the result.
///
/// This describes the convention, not the function. The slots are known even
/// when no prototype was recovered, and they say where a caller *would* leave a
/// value, never that this function takes one. A consumer recovering parameters
/// from machine code intersects this candidate list against what the function
/// reads before writing; without it there is nothing to intersect against, and
/// importing a guessed prototype instead would defeat the purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceConventionSlots {
    calling_convention: String,
    abi_class: SourceAbiClass,
    argument_slots: Box<[CanonicalStorageId]>,
    result_slot: Option<CanonicalStorageId>,
    stack_arguments: Option<SourceStackArgumentPlacement>,
    /// Every variadic argument travels on the stack from the first slot,
    /// whatever registers the fixed prefix leaves free: Apple's arm64 ABI.
    variadic_tail_on_stack: bool,
}

/// Where the convention puts an argument its registers cannot carry.
///
/// A call with more arguments than the convention has argument registers puts
/// the rest in the outgoing argument area, and the offsets are the
/// convention's to state: the first one, from the stack pointer at the call,
/// and the distance from each to the next. Two numbers rather than a list,
/// because how many there are is a fact about a call site and not about the
/// convention, and a list would have to guess how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStackArgumentPlacement {
    first_offset: i64,
    stride_bytes: u32,
}

impl SourceStackArgumentPlacement {
    pub const fn new(first_offset: i64, stride_bytes: u32) -> Option<Self> {
        if stride_bytes == 0 {
            return None;
        }
        Some(Self {
            first_offset,
            stride_bytes,
        })
    }

    /// The offset of the argument at `position` past the register slots, from
    /// the stack pointer entering the call.
    pub fn offset_of(self, position_past_registers: usize) -> Option<i64> {
        let steps = i64::try_from(position_past_registers).ok()?;
        let stride = i64::from(self.stride_bytes);
        self.first_offset.checked_add(steps.checked_mul(stride)?)
    }

    pub const fn first_offset(self) -> i64 {
        self.first_offset
    }

    pub const fn stride_bytes(self) -> u32 {
        self.stride_bytes
    }
}

impl SourceConventionSlots {
    /// Where the convention puts arguments past its register slots, when the
    /// source stated it.
    pub const fn stack_arguments(&self) -> Option<SourceStackArgumentPlacement> {
        self.stack_arguments
    }

    /// Record that placement. Separate from `new` because every existing caller
    /// states only the register slots, and because a convention that never
    /// spills to the stack legitimately has none.
    #[must_use]
    pub fn with_stack_arguments(mut self, placement: Option<SourceStackArgumentPlacement>) -> Self {
        self.stack_arguments = placement;
        self
    }

    /// Whether the variadic tail starts on the stack whatever registers are
    /// free, as Apple's arm64 ABI has it.
    pub const fn variadic_tail_on_stack(&self) -> bool {
        self.variadic_tail_on_stack
    }

    #[must_use]
    pub fn with_variadic_tail_on_stack(mut self, on_stack: bool) -> Self {
        self.variadic_tail_on_stack = on_stack;
        self
    }

    /// Build the candidate slots, rejecting anything that is not a well-formed
    /// register location or that names the same register twice.
    pub fn new(
        calling_convention: impl Into<String>,
        argument_slots: impl IntoIterator<Item = CanonicalStorageId>,
        result_slot: Option<CanonicalStorageId>,
    ) -> Result<Self, SourceMachineRolesError> {
        let calling_convention = calling_convention.into();
        let abi_class = SourceAbiClass::from_source_spelling(&calling_convention);
        let argument_slots = argument_slots.into_iter().collect::<Vec<_>>();
        if argument_slots
            .iter()
            .any(|storage| !valid_register_storage(*storage))
            || result_slot.is_some_and(|storage| !valid_register_storage(storage))
        {
            return Err(SourceMachineRolesError::InvalidRegisterStorage);
        }
        // A convention that named one register twice would make the candidate
        // order meaningless, so it is refused rather than deduplicated.
        for (index, storage) in argument_slots.iter().enumerate() {
            if argument_slots[..index].contains(storage) {
                return Err(SourceMachineRolesError::InvalidRegisterStorage);
            }
        }
        Ok(Self {
            calling_convention,
            abi_class,
            argument_slots: argument_slots.into_boxed_slice(),
            result_slot,
            stack_arguments: None,
            variadic_tail_on_stack: false,
        })
    }

    /// Convention these candidates belong to, named even when no prototype was
    /// recovered.
    pub fn calling_convention(&self) -> &str {
        &self.calling_convention
    }

    pub const fn abi_class(&self) -> SourceAbiClass {
        self.abi_class
    }

    pub const fn argument_slots(&self) -> &[CanonicalStorageId] {
        &self.argument_slots
    }

    pub const fn result_slot(&self) -> Option<CanonicalStorageId> {
        self.result_slot
    }

    pub const fn is_empty(&self) -> bool {
        self.argument_slots.is_empty() && self.result_slot.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMachineRolesError {
    InvalidRegisterStorage,
    InvalidStackAllocationContract,
    /// One register named both clobbered and preserved by a call.
    ContradictoryCallEffect,
}

impl SourceMachineRoles {
    /// Build the machine carriers, rejecting any storage that is not a
    /// well-formed register location.
    pub fn new(
        return_address_storage: Option<CanonicalStorageId>,
        stack_pointer_storage: Option<CanonicalStorageId>,
    ) -> Result<Self, SourceMachineRolesError> {
        if return_address_storage.is_some_and(|storage| !valid_register_storage(storage))
            || stack_pointer_storage.is_some_and(|storage| !valid_register_storage(storage))
        {
            return Err(SourceMachineRolesError::InvalidRegisterStorage);
        }
        Ok(Self {
            return_address_storage,
            stack_pointer_storage,
            role_register_names: SourceRoleRegisterNames::none(),
            stack_allocation_contract: None,
            direction_flag_storage: None,
        })
    }

    /// Record how the source spelled these carriers.
    #[must_use]
    pub const fn with_role_register_names(mut self, names: SourceRoleRegisterNames) -> Self {
        self.role_register_names = names;
        self
    }

    pub const fn role_register_names(&self) -> SourceRoleRegisterNames {
        self.role_register_names
    }

    /// Replace the carriers with the storages the lifted architecture gives
    /// for the names the source spelled, dropping one the architecture cannot
    /// place. This mirrors the interface's resolution and exists for the same
    /// reason: these offsets arrive in the source's numbering.
    pub fn with_arch_resolved_carriers(
        mut self,
        return_address: Option<CanonicalStorageId>,
        stack_pointer: Option<CanonicalStorageId>,
    ) -> Result<Self, SourceMachineRolesError> {
        if return_address.is_some_and(|storage| !valid_register_storage(storage))
            || stack_pointer.is_some_and(|storage| !valid_register_storage(storage))
        {
            return Err(SourceMachineRolesError::InvalidRegisterStorage);
        }
        // The allocation contract is a statement about the stack pointer, so
        // it cannot outlive a stack pointer the architecture would not place.
        if stack_pointer.is_none() {
            self.stack_allocation_contract = None;
        }
        self.return_address_storage = return_address;
        self.stack_pointer_storage = stack_pointer;
        Ok(self)
    }

    /// The direction flag, placed against the lifted architecture.
    pub const fn direction_flag_storage(&self) -> Option<CanonicalStorageId> {
        self.direction_flag_storage
    }

    /// Bind the direction flag's storage, dropping one that is not a
    /// well-formed register location.
    #[must_use]
    pub fn with_direction_flag_storage(mut self, storage: Option<CanonicalStorageId>) -> Self {
        self.direction_flag_storage = storage.filter(|storage| valid_register_storage(*storage));
        self
    }

    /// Bind exact geometric ownership around the architectural stack pointer.
    /// This is a machine/convention fact and remains available when no exact
    /// function prototype was recovered.
    pub fn with_stack_allocation_contract(
        mut self,
        contract: SourceStackAllocationContract,
    ) -> Result<Self, SourceMachineRolesError> {
        if self.stack_pointer_storage.is_none()
            || self
                .stack_allocation_contract
                .is_some_and(|bound| bound != contract)
        {
            return Err(SourceMachineRolesError::InvalidStackAllocationContract);
        }
        self.stack_allocation_contract = Some(contract);
        Ok(self)
    }

    pub const fn return_address_storage(&self) -> Option<CanonicalStorageId> {
        self.return_address_storage
    }

    pub const fn stack_pointer_storage(&self) -> Option<CanonicalStorageId> {
        self.stack_pointer_storage
    }

    pub const fn stack_allocation_contract(&self) -> Option<SourceStackAllocationContract> {
        self.stack_allocation_contract
    }

    /// True when neither carrier is known, which is the state of a source that
    /// could not resolve its register aliases at all.
    pub const fn is_empty(&self) -> bool {
        self.return_address_storage.is_none()
            && self.stack_pointer_storage.is_none()
            && self.stack_allocation_contract.is_none()
    }
}
