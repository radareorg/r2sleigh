//! Sleigh specification parsing and metadata extraction.
//!
//! This module uses `sleigh-rs` to parse Ghidra Sleigh specification files
//! and extract architecture metadata including registers, address spaces,
//! and user-defined operations.

use std::path::Path;

use r2il::ArchSpec;
use sleigh_rs::space::SpaceType;

use crate::context::LiftContext;
use crate::LiftError;

/// Parse a Sleigh specification file and extract architecture metadata.
///
/// This function parses a `.slaspec` file using `sleigh-rs` and extracts:
/// - Endianness and alignment
/// - Address spaces (RAM, ROM, Register)
/// - Register definitions (varnodes)
/// - User-defined operations (CALLOTHER)
///
/// # Arguments
///
/// * `path` - Path to the `.slaspec` file
///
/// # Returns
///
/// An `ArchSpec` containing the extracted metadata, or an error if parsing fails.
///
/// # Example
///
/// ```rust,ignore
/// use r2sleigh_lift::sleigh::parse_sleigh_spec;
///
/// let spec = parse_sleigh_spec("path/to/x86-64.slaspec")?;
/// println!("Architecture: {}", spec.name);
/// println!("Registers: {}", spec.registers.len());
/// ```
pub fn parse_sleigh_spec(path: impl AsRef<Path>) -> Result<ArchSpec, LiftError> {
    let path = path.as_ref();

    // Extract architecture name from filename
    let arch_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // Parse the Sleigh specification
    let sleigh = sleigh_rs::file_to_sleigh(path)
        .map_err(|e| LiftError::Parse(format!("Failed to parse Sleigh spec: {}", e)))?;

    // Create lift context
    let mut ctx = LiftContext::new(arch_name);

    // Set endianness
    ctx.set_big_endian(sleigh.endian.is_big());

    // Set alignment
    ctx.set_alignment(sleigh.alignment as u32);

    // Add source file
    ctx.add_source_file(&path.display().to_string());

    // Extract address spaces
    for (idx, space) in sleigh.spaces().iter().enumerate() {
        let is_default = sleigh_rs::SpaceId(idx) == sleigh.default_space;
        let addr_size = space.addr_bytes.get() as u32;

        // Map sleigh-rs SpaceType to our space naming
        let space_name = match space.space_type {
            SpaceType::Ram => "ram",
            SpaceType::Rom => "rom",
            SpaceType::Register => "register",
        };

        ctx.add_space(space_name, addr_size, is_default);

        // If this is the default space, set the architecture's address size
        if is_default {
            ctx.set_addr_size(addr_size);
        }
    }

    // Add unique space (for temporaries) if not already present
    if ctx.get_space("unique").is_none() {
        ctx.add_space("unique", 4, false);
    }

    // Extract register definitions (varnodes in register space)
    for varnode in sleigh.varnodes() {
        let space = sleigh.space(varnode.space);

        // Only add varnodes from the register space as registers
        if space.space_type == SpaceType::Register {
            ctx.add_register(
                varnode.name(),
                varnode.address,
                varnode.len_bytes.get() as u32,
            );
        }
    }

    // Extract user-defined operations (for CALLOTHER)
    // Note: sleigh-rs UserFunction doesn't expose the name directly,
    // so we use the index as the operation ID
    for (idx, _user_fn) in sleigh.user_functions().iter().enumerate() {
        // We don't have access to the name in sleigh-rs 0.1.5
        // Use a placeholder name based on index
        ctx.add_userop(idx as u32, &format!("userop_{}", idx));
    }

    Ok(ctx.finish())
}

/// Parse a Sleigh specification and return detailed parsing information.
///
/// This is a more detailed version of `parse_sleigh_spec` that also returns
/// information useful for debugging and diagnostics.
pub struct SleighParseResult {
    /// The architecture specification
    pub spec: ArchSpec,
    /// Number of tables in the specification
    pub table_count: usize,
    /// Number of tokens defined
    pub token_count: usize,
    /// Number of P-code macros defined
    pub macro_count: usize,
    /// Whether the specification was fully parsed
    pub complete: bool,
}

/// Parse a Sleigh specification with detailed results.
pub fn parse_sleigh_spec_detailed(path: impl AsRef<Path>) -> Result<SleighParseResult, LiftError> {
    let path = path.as_ref();

    let sleigh = sleigh_rs::file_to_sleigh(path)
        .map_err(|e| LiftError::Parse(format!("Failed to parse Sleigh spec: {}", e)))?;

    let spec = parse_sleigh_spec(path)?;

    Ok(SleighParseResult {
        spec,
        table_count: sleigh.tables().len(),
        token_count: sleigh.tokens().len(),
        macro_count: sleigh.pcode_macros().len(),
        complete: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Note: These tests require actual Sleigh spec files to be present
    // They are marked as ignored by default

    #[test]
    #[ignore = "Requires Ghidra Sleigh spec files"]
    fn test_parse_x86_64() {
        let path = PathBuf::from("../ghidra-native/src/Processors/x86/data/languages/x86-64.slaspec");
        if path.exists() {
            let spec = parse_sleigh_spec(&path).expect("Failed to parse x86-64.slaspec");
            assert_eq!(spec.name, "x86-64");
            assert!(!spec.big_endian);
            assert!(spec.registers.len() > 0);
            assert!(spec.spaces.len() > 0);
        }
    }

    #[test]
    #[ignore = "Requires Ghidra Sleigh spec files"]
    fn test_parse_arm() {
        let path = PathBuf::from("../ghidra-native/src/Processors/ARM/data/languages/ARM8_le.slaspec");
        if path.exists() {
            let spec = parse_sleigh_spec(&path).expect("Failed to parse ARM8_le.slaspec");
            assert!(spec.name.contains("ARM"));
            assert!(!spec.big_endian);
        }
    }
}
