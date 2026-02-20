//! Varnode definitions for r2il.
//!
//! A Varnode represents a location and size of data, similar to Ghidra's VarnodeData.

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::metadata::VarnodeMetadata;
use crate::space::SpaceId;

/// A varnode represents a sized piece of data at a specific location.
///
/// This is the fundamental unit of data in r2il, representing:
/// - A register (space=Register, offset=register_offset, size=register_size)
/// - A memory location (space=Ram, offset=address, size=access_size)
/// - A constant value (space=Const, offset=value, size=value_size)
/// - A temporary (space=Unique, offset=temp_id, size=temp_size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Varnode {
    /// The address space this varnode belongs to
    pub space: SpaceId,
    /// Offset within the address space
    pub offset: u64,
    /// Size in bytes
    pub size: u32,
    /// Optional semantic metadata hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<VarnodeMetadata>,
}

impl Varnode {
    /// Create a new varnode.
    pub fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
            meta: None,
        }
    }

    /// Create a constant varnode.
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Const,
            offset: value,
            size,
            meta: None,
        }
    }

    /// Create a register varnode.
    pub fn register(offset: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    /// Create a RAM varnode.
    pub fn ram(address: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Ram,
            offset: address,
            size,
            meta: None,
        }
    }

    /// Create a unique/temporary varnode.
    pub fn unique(id: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Unique,
            offset: id,
            size,
            meta: None,
        }
    }

    /// Return a copy of this varnode with metadata attached.
    pub fn with_meta(mut self, meta: VarnodeMetadata) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Set metadata on this varnode.
    pub fn set_meta(&mut self, meta: VarnodeMetadata) {
        self.meta = Some(meta);
    }

    /// Clear metadata on this varnode.
    pub fn clear_meta(&mut self) {
        self.meta = None;
    }

    /// Returns true if this is a constant.
    pub fn is_const(&self) -> bool {
        self.space.is_const()
    }

    /// Returns true if this is a register.
    pub fn is_register(&self) -> bool {
        self.space.is_register()
    }

    /// Returns true if this is a RAM location.
    pub fn is_ram(&self) -> bool {
        self.space.is_ram()
    }

    /// Returns true if this is a temporary.
    pub fn is_unique(&self) -> bool {
        self.space.is_unique()
    }

    /// Get the constant value if this is a constant varnode.
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.offset)
        } else {
            None
        }
    }
}

impl Default for Varnode {
    fn default() -> Self {
        Self::constant(0, 1)
    }
}

impl std::fmt::Display for Varnode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.space {
            crate::space::SpaceId::Const => {
                // For constants, show the value directly
                write!(f, "0x{:x}:{}", self.offset, self.size)
            }
            _ => {
                // For other spaces, show space:offset[size]
                write!(f, "{}:0x{:x}[{}]", self.space, self.offset, self.size)
            }
        }
    }
}

impl PartialEq for Varnode {
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space && self.offset == other.offset && self.size == other.size
    }
}

impl Eq for Varnode {}

impl Hash for Varnode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
        self.size.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PointerHint, ScalarKind};
    use std::collections::HashSet;

    #[test]
    fn test_constant_varnode() {
        let v = Varnode::constant(42, 4);
        assert!(v.is_const());
        assert_eq!(v.const_value(), Some(42));
        assert_eq!(v.size, 4);
    }

    #[test]
    fn test_register_varnode() {
        let v = Varnode::register(0x10, 8);
        assert!(v.is_register());
        assert!(!v.is_const());
        assert_eq!(v.offset, 0x10);
        assert_eq!(v.size, 8);
        assert!(v.meta.is_none());
    }

    #[test]
    fn varnode_default_meta_none() {
        let v = Varnode::default();
        assert!(v.meta.is_none());
    }

    #[test]
    fn varnode_with_meta_roundtrip_json() {
        let meta = VarnodeMetadata {
            scalar_kind: Some(ScalarKind::UnsignedInt),
            pointer_hint: Some(PointerHint::PointerLike),
            ..Default::default()
        };

        let v = Varnode::register(0x20, 8).with_meta(meta.clone());
        let json = serde_json::to_string(&v).expect("serialize");
        let de: Varnode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(de, v);
        assert_eq!(de.meta, Some(meta));
    }

    #[test]
    fn varnode_eq_hash_ignores_meta() {
        let meta = VarnodeMetadata {
            scalar_kind: Some(ScalarKind::SignedInt),
            ..Default::default()
        };

        let a = Varnode::register(0x30, 8);
        let b = Varnode::register(0x30, 8).with_meta(meta);
        assert_eq!(a, b);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
