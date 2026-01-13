//! Radare2 integration for binary loading and analysis.
//!
//! This module provides an interface to radare2 for:
//! - Loading binary files
//! - Reading memory segments
//! - Analyzing functions
//! - Disassembling code

#[cfg(feature = "r2")]
use r2pipe::R2Pipe;
use serde::Deserialize;
#[cfg(feature = "r2")]
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during r2 operations.
#[derive(Error, Debug)]
pub enum R2Error {
    #[error("Failed to open binary: {0}")]
    OpenFailed(String),

    #[error("R2 command failed: {0}")]
    CommandFailed(String),

    #[error("JSON parsing failed: {0}")]
    ParseFailed(String),

    #[error("R2 feature not enabled")]
    FeatureNotEnabled,
}

/// A memory segment from the binary.
#[derive(Debug, Clone, Deserialize)]
pub struct Segment {
    pub name: String,
    pub size: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub perm: String,
}

impl Segment {
    /// Check if segment is readable.
    pub fn is_readable(&self) -> bool {
        self.perm.contains('r')
    }

    /// Check if segment is writable.
    pub fn is_writable(&self) -> bool {
        self.perm.contains('w')
    }

    /// Check if segment is executable.
    pub fn is_executable(&self) -> bool {
        self.perm.contains('x')
    }
}

/// A function from the binary.
#[derive(Debug, Clone, Deserialize)]
pub struct Function {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    #[serde(default)]
    pub nargs: u64,
    #[serde(default)]
    pub nlocals: u64,
}

/// Binary information.
#[derive(Debug, Clone, Deserialize)]
pub struct BinaryInfo {
    pub arch: String,
    pub bits: u64,
    pub os: String,
    pub endian: String,
    #[serde(rename = "bintype")]
    pub bin_type: String,
}

/// R2 API wrapper for binary analysis.
#[cfg(feature = "r2")]
pub struct R2Api {
    pipe: R2Pipe,
    segments: Vec<Segment>,
    functions: HashMap<String, Function>,
    info: Option<BinaryInfo>,
}

#[cfg(feature = "r2")]
impl R2Api {
    /// Open a binary file with radare2.
    pub fn open(path: &str) -> Result<Self, R2Error> {
        let pipe = R2Pipe::spawn(path, None).map_err(|e| R2Error::OpenFailed(e.to_string()))?;

        let mut api = Self {
            pipe,
            segments: Vec::new(),
            functions: HashMap::new(),
            info: None,
        };

        // Analyze the binary
        api.cmd("aaa")?;

        // Load segments and info
        api.load_segments()?;
        api.load_info()?;

        Ok(api)
    }

    /// Execute an r2 command.
    pub fn cmd(&mut self, command: &str) -> Result<String, R2Error> {
        self.pipe
            .cmd(command)
            .map_err(|e| R2Error::CommandFailed(e.to_string()))
    }

    /// Execute an r2 command and parse JSON output.
    pub fn cmdj<T: for<'de> Deserialize<'de>>(&mut self, command: &str) -> Result<T, R2Error> {
        let output = self.cmd(command)?;
        serde_json::from_str(&output)
            .map_err(|e| R2Error::ParseFailed(format!("{}: {}", e, output)))
    }

    /// Load segment information.
    fn load_segments(&mut self) -> Result<(), R2Error> {
        self.segments = self.cmdj("iSj")?;
        Ok(())
    }

    /// Load binary info.
    fn load_info(&mut self) -> Result<(), R2Error> {
        #[derive(Deserialize)]
        struct InfoWrapper {
            bin: BinaryInfo,
        }
        let wrapper: InfoWrapper = self.cmdj("ij")?;
        self.info = Some(wrapper.bin);
        Ok(())
    }

    /// Get binary info.
    pub fn info(&self) -> Option<&BinaryInfo> {
        self.info.as_ref()
    }

    /// Get all segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Get architecture bits (32 or 64).
    pub fn bits(&self) -> u64 {
        self.info.as_ref().map(|i| i.bits).unwrap_or(64)
    }

    /// Read bytes from a virtual address.
    pub fn read_bytes(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, R2Error> {
        let hex = self.cmd(&format!("p8 {} @ 0x{:x}", size, addr))?;
        let hex = hex.trim();

        let mut bytes = Vec::with_capacity(size);
        for i in (0..hex.len()).step_by(2) {
            if i + 2 <= hex.len() {
                if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
                    bytes.push(byte);
                }
            }
        }
        Ok(bytes)
    }

    /// Get a function by name.
    pub fn get_function(&mut self, name: &str) -> Result<Option<Function>, R2Error> {
        if self.functions.is_empty() {
            let funcs: Vec<Function> = self.cmdj("aflj")?;
            for f in funcs {
                self.functions.insert(f.name.clone(), f);
            }
        }
        Ok(self.functions.get(name).cloned())
    }

    /// Get a function by address.
    pub fn get_function_at(&mut self, addr: u64) -> Result<Option<Function>, R2Error> {
        if self.functions.is_empty() {
            let funcs: Vec<Function> = self.cmdj("aflj")?;
            for f in funcs {
                self.functions.insert(f.name.clone(), f);
            }
        }
        Ok(self.functions.values().find(|f| f.offset == addr).cloned())
    }

    /// Seek to an address.
    pub fn seek(&mut self, addr: u64) -> Result<(), R2Error> {
        self.cmd(&format!("s 0x{:x}", addr))?;
        Ok(())
    }

    /// Get the entry point address.
    pub fn entry_point(&mut self) -> Result<u64, R2Error> {
        #[derive(Deserialize)]
        struct Entry {
            vaddr: u64,
        }
        let entries: Vec<Entry> = self.cmdj("iej")?;
        Ok(entries.first().map(|e| e.vaddr).unwrap_or(0))
    }

    /// Get the main function address if it exists.
    pub fn main_address(&mut self) -> Result<Option<u64>, R2Error> {
        if let Some(func) = self.get_function("main")? {
            return Ok(Some(func.offset));
        }
        if let Some(func) = self.get_function("sym.main")? {
            return Ok(Some(func.offset));
        }
        Ok(None)
    }
}

/// Stub implementation when r2 feature is not enabled.
#[cfg(not(feature = "r2"))]
pub struct R2Api;

#[cfg(not(feature = "r2"))]
impl R2Api {
    /// Stub: returns error when r2 feature is not enabled.
    pub fn open(_path: &str) -> Result<Self, R2Error> {
        Err(R2Error::FeatureNotEnabled)
    }
}
