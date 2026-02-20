//! Serialization support for r2il types.
//!
//! This module provides binary serialization using bincode for efficient
//! storage and loading of architecture specifications.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use thiserror::Error;

use crate::opcode::R2ILOp;
use crate::space::AddressSpace;
use crate::{FORMAT_VERSION, MAGIC};

/// Errors that can occur during serialization/deserialization.
#[derive(Debug, Error)]
pub enum SerializeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("Invalid magic bytes: expected R2IL")]
    InvalidMagic,

    #[error("Unsupported format version: {0} (expected {FORMAT_VERSION})")]
    UnsupportedVersion(u32),
}

/// Result type for serialization operations.
pub type Result<T> = std::result::Result<T, SerializeError>;

/// Definition of a processor register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDef {
    /// Register name (e.g., "RAX", "EAX", "AX", "AL")
    pub name: String,
    /// Offset in register space
    pub offset: u64,
    /// Size in bytes
    pub size: u32,
    /// Parent register name (if this is a sub-register)
    pub parent: Option<String>,
}

impl RegisterDef {
    /// Create a new register definition.
    pub fn new(name: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            parent: None,
        }
    }

    /// Create a sub-register definition.
    pub fn sub(name: impl Into<String>, offset: u64, size: u32, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            parent: Some(parent.into()),
        }
    }
}

/// User-defined operation (CALLOTHER) definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpDef {
    /// Operation index
    pub index: u32,
    /// Operation name
    pub name: String,
}

/// Instruction pattern and its semantic definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionDef {
    /// Instruction mnemonic
    pub mnemonic: String,
    /// P-code operations for this instruction pattern
    pub ops: Vec<R2ILOp>,
}

/// Complete architecture specification.
///
/// This is the top-level structure serialized to `.r2il` files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchSpec {
    /// Architecture name (e.g., "x86", "x86-64", "ARM")
    pub name: String,

    /// Processor variant (e.g., "default", "thumb")
    pub variant: String,

    /// Endianness: true for big-endian, false for little-endian
    pub big_endian: bool,

    /// Address size in bytes (4 for 32-bit, 8 for 64-bit)
    pub addr_size: u32,

    /// Alignment requirement
    pub alignment: u32,

    /// Address spaces
    pub spaces: Vec<AddressSpace>,

    /// Register definitions
    pub registers: Vec<RegisterDef>,

    /// Register name to offset mapping for quick lookup
    pub register_map: HashMap<String, u64>,

    /// User-defined operations (CALLOTHER)
    pub userops: Vec<UserOpDef>,

    /// Sleigh source file paths (for debugging)
    pub source_files: Vec<String>,
}

impl ArchSpec {
    /// Create a new architecture specification.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variant: "default".into(),
            big_endian: false,
            addr_size: 8,
            alignment: 1,
            spaces: Vec::new(),
            registers: Vec::new(),
            register_map: HashMap::new(),
            userops: Vec::new(),
            source_files: Vec::new(),
        }
    }

    /// Add a register definition.
    pub fn add_register(&mut self, reg: RegisterDef) {
        self.register_map.insert(reg.name.clone(), reg.offset);
        self.registers.push(reg);
    }

    /// Add an address space.
    pub fn add_space(&mut self, space: AddressSpace) {
        self.spaces.push(space);
    }

    /// Look up a register by name.
    pub fn get_register(&self, name: &str) -> Option<&RegisterDef> {
        self.registers.iter().find(|r| r.name == name)
    }

    /// Look up a register offset by name.
    pub fn get_register_offset(&self, name: &str) -> Option<u64> {
        self.register_map.get(name).copied()
    }
}

/// Header for r2il binary files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileHeader {
    /// Format version
    version: u32,
    /// Architecture name
    arch_name: String,
}

/// Save an architecture specification to a file.
pub fn save(arch: &ArchSpec, path: &Path) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Write magic bytes
    writer.write_all(MAGIC)?;

    // Create and serialize header
    let header = FileHeader {
        version: FORMAT_VERSION,
        arch_name: arch.name.clone(),
    };
    let header_bytes = bincode::serialize(&header)?;
    let header_len = header_bytes.len() as u32;
    writer.write_all(&header_len.to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    // Serialize the architecture spec
    let arch_bytes = bincode::serialize(arch)?;
    writer.write_all(&arch_bytes)?;

    writer.flush()?;
    Ok(())
}

/// Load an architecture specification from a file.
pub fn load(path: &Path) -> Result<ArchSpec> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Read and verify magic bytes
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(SerializeError::InvalidMagic);
    }

    // Read header
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header: FileHeader = bincode::deserialize(&header_bytes)?;

    // Check version
    if header.version != FORMAT_VERSION {
        return Err(SerializeError::UnsupportedVersion(header.version));
    }

    // Read the rest as architecture spec
    let mut arch_bytes = Vec::new();
    reader.read_to_end(&mut arch_bytes)?;
    let arch: ArchSpec = bincode::deserialize(&arch_bytes)?;

    Ok(arch)
}

/// Save to bytes (for testing or embedding).
pub fn to_bytes(arch: &ArchSpec) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();

    // Write magic bytes
    bytes.extend_from_slice(MAGIC);

    // Create and serialize header
    let header = FileHeader {
        version: FORMAT_VERSION,
        arch_name: arch.name.clone(),
    };
    let header_bytes = bincode::serialize(&header)?;
    let header_len = header_bytes.len() as u32;
    bytes.extend_from_slice(&header_len.to_le_bytes());
    bytes.extend_from_slice(&header_bytes);

    // Serialize the architecture spec
    let arch_bytes = bincode::serialize(arch)?;
    bytes.extend_from_slice(&arch_bytes);

    Ok(bytes)
}

/// Load from bytes (for testing or embedded resources).
pub fn from_bytes(bytes: &[u8]) -> Result<ArchSpec> {
    if bytes.len() < 8 {
        return Err(SerializeError::InvalidMagic);
    }

    // Verify magic bytes
    if &bytes[0..4] != MAGIC {
        return Err(SerializeError::InvalidMagic);
    }

    // Read header length
    let header_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;

    if bytes.len() < 8 + header_len {
        return Err(SerializeError::InvalidMagic);
    }

    // Deserialize header
    let header: FileHeader = bincode::deserialize(&bytes[8..8 + header_len])?;

    // Check version
    if header.version != FORMAT_VERSION {
        return Err(SerializeError::UnsupportedVersion(header.version));
    }

    // Deserialize architecture spec
    let arch: ArchSpec = bincode::deserialize(&bytes[8 + header_len..])?;

    Ok(arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let mut arch = ArchSpec::new("test-arch");
        arch.big_endian = false;
        arch.addr_size = 8;

        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::sub("EAX", 0, 4, "RAX"));

        arch.add_space(AddressSpace::ram(8));
        arch.add_space(AddressSpace::register());

        // Serialize and deserialize
        let bytes = to_bytes(&arch).unwrap();
        let loaded = from_bytes(&bytes).unwrap();

        assert_eq!(loaded.name, "test-arch");
        assert!(!loaded.big_endian);
        assert_eq!(loaded.addr_size, 8);
        assert_eq!(loaded.registers.len(), 2);
        assert_eq!(loaded.spaces.len(), 2);
    }

    #[test]
    fn test_invalid_magic() {
        let bytes = b"XXXX0000";
        let result = from_bytes(bytes);
        assert!(matches!(result, Err(SerializeError::InvalidMagic)));
    }
}
