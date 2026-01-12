//! Varnode definitions for r2il.
//!
//! A Varnode represents a location and size of data, similar to Ghidra's VarnodeData.

use serde::{Deserialize, Serialize};

use crate::space::SpaceId;

/// A varnode represents a sized piece of data at a specific location.
///
/// This is the fundamental unit of data in r2il, representing:
/// - A register (space=Register, offset=register_offset, size=register_size)
/// - A memory location (space=Ram, offset=address, size=access_size)
/// - A constant value (space=Const, offset=value, size=value_size)
/// - A temporary (space=Unique, offset=temp_id, size=temp_size)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    /// The address space this varnode belongs to
    pub space: SpaceId,
    /// Offset within the address space
    pub offset: u64,
    /// Size in bytes
    pub size: u32,
}

impl Varnode {
    /// Create a new varnode.
    pub fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }

    /// Create a constant varnode.
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Const,
            offset: value,
            size,
        }
    }

    /// Create a register varnode.
    pub fn register(offset: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Register,
            offset,
            size,
        }
    }

    /// Create a RAM varnode.
    pub fn ram(address: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Ram,
            offset: address,
            size,
        }
    }

    /// Create a unique/temporary varnode.
    pub fn unique(id: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Unique,
            offset: id,
            size,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
