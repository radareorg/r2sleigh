//! Address space definitions for r2il.
//!
//! Address spaces define where data lives: RAM, registers, temporaries, or constants.

use serde::{Deserialize, Serialize};

use crate::Endianness;

/// Identifier for an address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SpaceId {
    /// Main memory (RAM)
    #[default]
    Ram,
    /// Processor registers
    Register,
    /// Temporary/unique storage for intermediate values
    Unique,
    /// Constant/immediate values
    Const,
    /// Architecture-specific custom space
    Custom(u32),
}

impl SpaceId {
    /// Returns true if this is the constant space.
    pub fn is_const(&self) -> bool {
        matches!(self, SpaceId::Const)
    }

    /// Returns true if this is a memory space (RAM).
    pub fn is_ram(&self) -> bool {
        matches!(self, SpaceId::Ram)
    }

    /// Returns true if this is the register space.
    pub fn is_register(&self) -> bool {
        matches!(self, SpaceId::Register)
    }

    /// Returns true if this is the unique/temporary space.
    pub fn is_unique(&self) -> bool {
        matches!(self, SpaceId::Unique)
    }
}

impl std::fmt::Display for SpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaceId::Ram => write!(f, "ram"),
            SpaceId::Register => write!(f, "reg"),
            SpaceId::Unique => write!(f, "uniq"),
            SpaceId::Const => write!(f, "const"),
            SpaceId::Custom(id) => write!(f, "space{}", id),
        }
    }
}

/// Full address space definition with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpace {
    /// Space identifier
    pub id: SpaceId,
    /// Human-readable name
    pub name: String,
    /// Size of addresses in this space (in bytes)
    pub addr_size: u32,
    /// Word size for this space (usually 1 for byte-addressable)
    pub word_size: u32,
    /// Whether this is the default code space
    pub is_default: bool,
    /// Optional endianness override for this space.
    #[serde(default)]
    pub endianness: Option<Endianness>,
}

impl AddressSpace {
    /// Create a new address space.
    pub fn new(id: SpaceId, name: impl Into<String>, addr_size: u32) -> Self {
        Self {
            id,
            name: name.into(),
            addr_size,
            word_size: 1,
            is_default: false,
            endianness: None,
        }
    }

    /// Create the standard RAM space.
    pub fn ram(addr_size: u32) -> Self {
        Self {
            id: SpaceId::Ram,
            name: "ram".into(),
            addr_size,
            word_size: 1,
            is_default: true,
            endianness: None,
        }
    }

    /// Create the standard register space.
    pub fn register() -> Self {
        Self {
            id: SpaceId::Register,
            name: "register".into(),
            addr_size: 4,
            word_size: 1,
            is_default: false,
            endianness: None,
        }
    }

    /// Create the standard unique/temporary space.
    pub fn unique() -> Self {
        Self {
            id: SpaceId::Unique,
            name: "unique".into(),
            addr_size: 4,
            word_size: 1,
            is_default: false,
            endianness: None,
        }
    }

    /// Create the constant space.
    pub fn constant() -> Self {
        Self {
            id: SpaceId::Const,
            name: "const".into(),
            addr_size: 8,
            word_size: 1,
            is_default: false,
            endianness: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressSpace, SpaceId};
    use crate::Endianness;

    #[test]
    fn address_space_optional_endianness_serde() {
        let space = AddressSpace::new(SpaceId::Ram, "ram", 8);
        let json = serde_json::to_string(&space).expect("serialize");
        assert!(json.contains("\"endianness\":null"));

        let mut be_space = AddressSpace::new(SpaceId::Ram, "ram_be", 8);
        be_space.endianness = Some(Endianness::Big);
        let json_be = serde_json::to_string(&be_space).expect("serialize");
        assert!(json_be.contains("endianness"));
        let roundtrip: AddressSpace = serde_json::from_str(&json_be).expect("deserialize");
        assert_eq!(roundtrip.endianness, Some(Endianness::Big));
    }
}
