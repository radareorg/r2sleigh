//! SSA variable representation.

use serde::{Deserialize, Serialize};

pub use r2source::{CanonicalStorageId, CanonicalStorageSpace};

use crate::name::{InternedName, intern};

/// The prefix a spelling carries, for display only: no fold or class reads it (D459); the
/// lifted storage and the `CONSTANT` flag are the typed facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum SSAVarNameKind {
    RegisterAlias,
    Temporary,
    Constant,
    Memory,
    AddressSpace,
    /// A frame slot promoted out of memory into a variable of the function.
    Frame,
    Symbol,
    Object,
    Data,
    Got,
    Ordinary,
}

fn starts_with_ignore_ascii_case(name: &str, prefix: &str) -> bool {
    name.len() >= prefix.len()
        && name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

impl SSAVarNameKind {
    /// Which kind of location a spelling names.
    ///
    /// Compared prefix by prefix rather than by lowercasing the name first:
    /// this is asked of every variable on every operation, and the copy the
    /// lowercase made was an allocation for a question about five characters.
    pub(crate) fn classify(name: &str) -> Self {
        if starts_with_ignore_ascii_case(name, "reg:") {
            Self::RegisterAlias
        } else if starts_with_ignore_ascii_case(name, "tmp:")
            || starts_with_ignore_ascii_case(name, "unique:")
        {
            Self::Temporary
        } else if starts_with_ignore_ascii_case(name, "const:") {
            Self::Constant
        } else if starts_with_ignore_ascii_case(name, "ram:") {
            Self::Memory
        } else if starts_with_ignore_ascii_case(name, "stack:") {
            Self::Frame
        } else if starts_with_ignore_ascii_case(name, "space") {
            Self::AddressSpace
        } else if starts_with_ignore_ascii_case(name, "sym.") {
            Self::Symbol
        } else if starts_with_ignore_ascii_case(name, "obj.") {
            Self::Object
        } else if starts_with_ignore_ascii_case(name, "data.") {
            Self::Data
        } else if starts_with_ignore_ascii_case(name, "got.") {
            Self::Got
        } else {
            Self::Ordinary
        }
    }

    fn is_prefixed_display_name(self) -> bool {
        matches!(
            self,
            Self::RegisterAlias
                | Self::Temporary
                | Self::Constant
                | Self::Memory
                | Self::AddressSpace
                | Self::Frame
        )
    }
}

/// Whether `var` is a lifted temporary: its storage is the unique space, or it is a lane (D459).
pub(crate) fn is_lifted_temporary(var: &SSAVar, storage: Option<CanonicalStorageId>) -> bool {
    var.is_lane() || storage.is_some_and(|storage| storage.space == CanonicalStorageSpace::Unique)
}

/// An SSA variable: a named location with a version number.
///
/// In SSA form, each assignment creates a new version of the variable.
/// For example, if `RAX` is written twice, we get `RAX_0` and `RAX_1`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "SSAVarFields", into = "SSAVarFields")]
pub struct SSAVar {
    /// The base name of the variable (e.g., "RAX", "tmp:401334:8", "const:0x42").
    ///
    /// Interned rather than owned: the same few hundred spellings are repeated
    /// across every operation of every function, so a variable points at the
    /// one copy (see [`crate::name`]) and cloning one copies a pointer.
    name: &'static InternedName,
    /// Exact source bitvector for constants, zero where `flags` holds no
    /// `CONSTANT` so that two non-constants compare equal.
    ///
    /// This is semantic data. The `name` field is presentation-only and must
    /// not be parsed by proof-bearing consumers to recover a constant value.
    /// Held beside a flag rather than inside an `Option`, which has no spare
    /// bit pattern for a sixty-four bit value and so costs sixteen bytes.
    constant_bits: u64,
    /// The version number (0 for initial/input, incremented on each write).
    pub version: u32,
    /// Size in bytes.
    pub size: u32,
    /// Deterministic construction-time discriminator for two exact source
    /// storages that project to the same display name and width.
    ///
    /// This is identity only, not storage authority. Canonical storage remains
    /// in the source-retained graph facts.
    rename_disambiguator: u32,
    /// `CONSTANT`: `constant_bits` is a carried constant; `LANE`: a lane temporary, a register
    /// root's projection with no storage of its own (D477).
    flags: u8,
}

/// `SSAVar::flags`: the variable carries a constant.
const CONSTANT: u8 = 1;
/// `SSAVar::flags`: the variable is a lane temporary (`SSAVar::lane_temp`).
const LANE: u8 = 2;

/// A variable as it is written down.
///
/// The ordering the identity fields give is the one this shape gives, read in
/// this order: a variable that carries no constant sorts below one that does,
/// exactly as `None` sorts below `Some`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SSAVarFields {
    name: String,
    version: u32,
    size: u32,
    #[serde(default)]
    constant_bits: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    rename_disambiguator: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    lane: bool,
}

impl From<SSAVarFields> for SSAVar {
    fn from(fields: SSAVarFields) -> Self {
        Self {
            name: intern(&fields.name),
            constant_bits: fields.constant_bits.unwrap_or(0),
            version: fields.version,
            size: fields.size,
            rename_disambiguator: fields.rename_disambiguator,
            flags: (u8::from(fields.constant_bits.is_some()) * CONSTANT)
                | (u8::from(fields.lane) * LANE),
        }
    }
}

impl From<SSAVar> for SSAVarFields {
    fn from(var: SSAVar) -> Self {
        Self {
            name: var.name.text().to_owned(),
            version: var.version,
            size: var.size,
            constant_bits: var.constant_bits(),
            rename_disambiguator: var.rename_disambiguator,
            lane: var.is_lane(),
        }
    }
}

/// The derived spelling of the two fields `flags` replaced; `lane` only where set.
impl std::fmt::Debug for SSAVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = f.debug_struct("SSAVar");
        fields
            .field("name", &self.name)
            .field("constant_bits", &self.constant_bits)
            .field("version", &self.version)
            .field("size", &self.size)
            .field("rename_disambiguator", &self.rename_disambiguator)
            .field("is_constant", &(self.flags & CONSTANT != 0));
        if self.is_lane() {
            fields.field("lane", &true);
        }
        fields.finish()
    }
}

impl PartialEq for SSAVar {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.size == other.size
            && self.flags == other.flags
            && self.constant_bits == other.constant_bits
            && self.rename_disambiguator == other.rename_disambiguator
            && std::ptr::eq(self.name, other.name)
    }
}

impl Eq for SSAVar {}

impl Ord for SSAVar {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Two variables that share a spelling share its entry, so the common
        // case answers without looking at the text at all.
        let names = if std::ptr::eq(self.name, other.name) {
            std::cmp::Ordering::Equal
        } else {
            self.name.text().cmp(other.name.text())
        };
        names
            .then_with(|| self.version.cmp(&other.version))
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| self.flags.cmp(&other.flags))
            .then_with(|| self.constant_bits.cmp(&other.constant_bits))
            .then_with(|| self.rename_disambiguator.cmp(&other.rename_disambiguator))
    }
}

impl PartialOrd for SSAVar {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for SSAVar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.id().hash(state);
        self.version.hash(state);
        self.size.hash(state);
        self.flags.hash(state);
        self.constant_bits.hash(state);
        self.rename_disambiguator.hash(state);
    }
}

const fn is_zero(value: &u32) -> bool {
    *value == 0
}

const fn is_false(value: &bool) -> bool {
    !*value
}

impl SSAVar {
    /// Create a new SSA variable.
    pub fn new(name: impl AsRef<str>, version: u32, size: u32) -> Self {
        Self {
            name: intern(name.as_ref()),
            constant_bits: 0,
            version,
            size,
            rename_disambiguator: 0,
            flags: 0,
        }
    }

    /// A variable on a spelling the table already holds.
    pub(crate) const fn from_interned(
        name: &'static InternedName,
        version: u32,
        size: u32,
    ) -> Self {
        Self {
            name,
            constant_bits: 0,
            version,
            size,
            rename_disambiguator: 0,
            flags: 0,
        }
    }

    /// The lane temporary `serial` of the operation at `op_idx` of `instruction`: version 1, and a
    /// lane by the typed bit, never by its `tmp:lane:` spelling.
    pub(crate) fn lane_temp(instruction: u64, op_idx: usize, serial: u32, size: u32) -> Self {
        Self {
            flags: LANE,
            ..Self::new(
                format!("tmp:lane:{instruction:x}:{op_idx:x}:{serial:x}"),
                1,
                size,
            )
        }
    }

    /// Whether this is a lane temporary (`lane_temp`).
    pub(crate) const fn is_lane(&self) -> bool {
        self.flags & LANE != 0
    }

    /// Attach the deterministic source-identity projection selected by SSA
    /// construction while leaving the user-facing name unchanged.
    pub(crate) fn with_rename_disambiguator(mut self, disambiguator: u32) -> Self {
        self.rename_disambiguator = disambiguator;
        self
    }

    /// The variable's base name.
    ///
    /// Read-only: the name decides the comparison prefix the struct carries,
    /// so a variable's name is set when it is made and never after.
    pub fn name(&self) -> &'static str {
        self.name.text()
    }

    /// The same variable under a different display name.
    ///
    /// The name is presentation, so respelling one is an ordinary operation
    /// and this is how it is done: the identity fields travel unchanged. A
    /// fixture that needs a variable whose spelling disagrees with the bits it
    /// carries -- the case the name-versus-identity rule exists for -- builds
    /// it this way.
    pub fn renamed(&self, name: impl AsRef<str>) -> Self {
        Self {
            name: intern(name.as_ref()),
            ..self.clone()
        }
    }

    /// A hash of the whole identity, for indexing a variable's value.
    ///
    /// Not a substitute for equality and not stable across processes: the
    /// spelling contributes its interned identifier, which is assigned in the
    /// order spellings are first seen.
    pub fn index_hash(&self) -> u64 {
        const ODD: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut mixed = u64::from(self.name.id());
        for word in [
            u64::from(self.version),
            u64::from(self.size),
            u64::from(self.flags),
            self.constant_bits,
            u64::from(self.rename_disambiguator),
        ] {
            mixed = (mixed ^ word).wrapping_mul(ODD);
            mixed ^= mixed >> 29;
        }
        mixed
    }

    /// The construction-time discriminator that separates two exact storages
    /// which project to the same display name and width.
    ///
    /// Public because anything building an identity key for a variable has to
    /// include it, or the key collides on precisely the case this field exists
    /// to keep apart.
    pub const fn rename_disambiguator(&self) -> u32 {
        self.rename_disambiguator
    }

    /// Create the initial (version 0) variable.
    pub fn initial(name: impl AsRef<str>, size: u32) -> Self {
        Self::new(name, 0, size)
    }

    /// Create a constant SSA variable.
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            name: intern(&format!("const:{value:x}")),
            constant_bits: value,
            version: 0,
            size,
            rename_disambiguator: 0,
            flags: CONSTANT,
        }
    }

    /// Create the next version of this variable.
    ///
    /// Returns `None` when the version counter is exhausted instead of
    /// silently wrapping and aliasing a different SSA definition.
    pub fn next_version(&self) -> Option<Self> {
        Some(Self {
            version: self.version.checked_add(1)?,
            ..self.clone()
        })
    }

    /// Return the source bitvector carried by a constant SSA value.
    ///
    /// Unlike legacy helpers that parse `name`, this accessor is safe to use
    /// as semantic evidence.
    pub const fn constant_bits(&self) -> Option<u64> {
        if self.flags & CONSTANT != 0 {
            Some(self.constant_bits)
        } else {
            None
        }
    }

    /// Get a display name like "RAX_0" or "RAX_1".
    ///
    /// For named registers (without prefix), outputs "RAX_0".
    /// For unknown registers (with "reg:" prefix), outputs "reg:10_0".
    /// For constants, outputs "const:42_0".
    /// For temporaries, outputs "tmp:401334:8_1".
    pub fn display_name(&self) -> String {
        // Handle special prefixes (hex fallbacks and other spaces)
        if self.name_kind().is_prefixed_display_name() {
            return format!("{}_{}", self.name(), self.version);
        }
        // Named register - uppercase it
        format!("{}_{}", self.name().to_uppercase(), self.version)
    }

    fn name_kind(&self) -> SSAVarNameKind {
        self.name.kind()
    }

    /// Whether this value carries a constant: the `CONSTANT` flag, never the spelling (D459).
    pub const fn is_const(&self) -> bool {
        self.constant_bits().is_some()
    }
}

impl std::fmt::Display for SSAVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssa_var_creation() {
        let var = SSAVar::new("RAX", 0, 8);
        assert_eq!(var.name(), "RAX");
        assert_eq!(var.version, 0);
        assert_eq!(var.size, 8);
        assert_eq!(var.display_name(), "RAX_0");
    }

    #[test]
    fn constants_carry_bits_independently_of_display_names() {
        let constant = SSAVar::constant(0x100000001b3, 8);
        assert_eq!(constant.constant_bits(), Some(0x100000001b3));

        let spoofed_name = SSAVar::new("const:100000001b3", 0, 8);
        assert_eq!(spoofed_name.constant_bits(), None);
    }

    /// A constant is the `CONSTANT` flag (D459): a `const:` spelling proves nothing.
    #[test]
    fn a_constant_spelling_is_no_constant() {
        assert!(!SSAVar::new("const:2a", 0, 4).is_const());
        assert!(SSAVar::constant(0x2a, 4).is_const());
    }

    /// A lane is a typed fact on the value (D477): its spelling proves nothing.
    #[test]
    fn a_lane_spelling_is_no_lane_temporary() {
        let spelled = SSAVar::new("tmp:lane:1:2:3", 1, 4);
        assert!(!crate::rename::is_lane_temp(&spelled));
    }

    #[test]
    fn only_the_lane_constructor_makes_a_lane_temporary() {
        let spelled = SSAVar::new("tmp:lane:1:2:3", 1, 4);
        let lane = SSAVar::lane_temp(1, 2, 3, 4);
        assert_eq!(lane.name(), spelled.name());
        assert!(crate::rename::is_lane_temp(&lane));
        assert_ne!(lane, spelled);
        assert_ne!(lane.cmp(&spelled), std::cmp::Ordering::Equal);
        assert!(lane.next_version().is_some_and(|next| next.is_lane()));
        let json = serde_json::to_string(&lane).expect("serialize");
        assert_eq!(serde_json::from_str::<SSAVar>(&json).expect("parse"), lane);
        let plain = serde_json::to_string(&spelled).expect("serialize");
        assert!(!plain.contains("\"lane\":"));
        // The bit shares the constant flag's byte.
        assert_eq!(std::mem::size_of::<SSAVar>(), 32);
    }

    #[test]
    fn test_display_name_preserves_special_prefixes() {
        let cases = [
            ("reg:10", "reg:10_3"),
            ("tmp:0x1000", "tmp:0x1000_3"),
            ("const:0x42", "const:0x42_3"),
            ("ram:0x401000", "ram:0x401000_3"),
            ("space1:0x20", "space1:0x20_3"),
        ];

        for (name, expected) in cases {
            assert_eq!(SSAVar::new(name, 3, 8).display_name(), expected);
        }
    }

    #[test]
    fn test_name_kind_classification() {
        let cases = [
            ("reg:10", SSAVarNameKind::RegisterAlias),
            ("tmp:0x1000", SSAVarNameKind::Temporary),
            ("unique:0x1000", SSAVarNameKind::Temporary),
            ("const:0x42", SSAVarNameKind::Constant),
            ("ram:0x401000", SSAVarNameKind::Memory),
            ("space1:0x20", SSAVarNameKind::AddressSpace),
            ("sym.main", SSAVarNameKind::Symbol),
            ("obj.global", SSAVarNameKind::Object),
            ("data.rel.ro", SSAVarNameKind::Data),
            ("got.printf", SSAVarNameKind::Got),
            ("rax", SSAVarNameKind::Ordinary),
        ];

        for (name, expected) in cases {
            assert_eq!(SSAVarNameKind::classify(name), expected);
            assert_eq!(SSAVar::new(name, 0, 8).name_kind(), expected);
        }
        assert_eq!(
            SSAVarNameKind::classify("CONST:0x42"),
            SSAVarNameKind::Constant
        );
    }

    #[test]
    fn test_next_version() {
        let v0 = SSAVar::initial("RSP", 8);
        let v1 = v0.next_version().expect("version 0 has a successor");
        let v2 = v1.next_version().expect("version 1 has a successor");

        assert_eq!(v0.version, 0);
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
        assert_eq!(v0.name(), v1.name());
    }

    #[test]
    fn test_next_version_refuses_wraparound() {
        let max = SSAVar::new("RSP", u32::MAX, 8);
        assert_eq!(max.next_version(), None);
    }

    /// A spelling's prefix is a display kind; only the constant flag makes a constant (D459).
    #[test]
    fn test_var_classification() {
        assert!(!SSAVar::new("RAX", 0, 8).is_const());
        assert!(!SSAVar::new("tmp:0x1000", 0, 4).is_const());
        assert!(!SSAVar::new("const:0x42", 0, 4).is_const());
        assert!(SSAVar::constant(0x42, 4).is_const());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn next_version_is_checked_and_monotonic() {
        let version: u32 = kani::any();
        let size: u32 = kani::any();
        static RAX: InternedName = InternedName::unregistered("rax");
        let var = SSAVar::from_interned(&RAX, version, size);
        let next = var.next_version();

        if version == u32::MAX {
            assert!(next.is_none());
        } else {
            let next = next.expect("non-maximum version has a successor");
            assert_eq!(next.size, var.size);
            assert_eq!(next.version, version + 1);
            assert!(next.version > var.version);
        }
    }
}
