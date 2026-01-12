//! Integration tests for r2ssa with real disassembly.

#[cfg(feature = "sleigh-config")]
mod tests {
    use r2sleigh_lift::Disassembler;
    use r2ssa::block::to_ssa;
    use r2ssa::{def_use, SSAOp, SSAVar};

    fn create_x86_64_disasm() -> Disassembler {
        // Use sleigh-config precompiled data
        Disassembler::from_sla(
            sleigh_config::processor_x86::SLA_X86_64,
            sleigh_config::processor_x86::PSPEC_X86_64,
            "x86-64",
        )
        .expect("Failed to create x86-64 disassembler")
    }

    /// Pad hex bytes to at least 16 bytes (libsla requirement).
    fn pad_hex(hex: &str) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        while bytes.len() < 16 {
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn test_ssa_conversion_push_rbp() {
        let disasm = create_x86_64_disasm();
        let bytes = pad_hex("55"); // push rbp

        let block = disasm.lift(&bytes, 0x1000).expect("Failed to lift");
        let ssa_block = to_ssa(&block, &disasm);

        // Verify we got some operations
        assert!(!ssa_block.is_empty(), "SSA block should not be empty");
        assert_eq!(ssa_block.addr, 0x1000);

        // Check that we have versioned variables
        let mut found_write = false;
        for op in &ssa_block.ops {
            if let Some(dst) = op.dst() {
                // All writes should have version > 0
                assert!(dst.version > 0, "Written var should have version > 0");
                found_write = true;
            }
        }
        assert!(found_write, "Should have at least one write");
    }

    #[test]
    fn test_ssa_conversion_mov_rax_rbx() {
        let disasm = create_x86_64_disasm();
        let bytes = pad_hex("4889d8"); // mov rax, rbx

        let block = disasm.lift(&bytes, 0x1000).expect("Failed to lift");
        let ssa_block = to_ssa(&block, &disasm);

        // Verify we got operations
        assert!(!ssa_block.is_empty(), "SSA block should not be empty");

        // Find the copy operation
        for op in &ssa_block.ops {
            if let SSAOp::Copy { dst, src } = op {
                // RAX should be written (version > 0)
                if dst.name.to_lowercase().contains("rax") {
                    assert!(dst.version > 0, "RAX should be written");
                }
                // RBX should be read (version 0 initially)
                if src.name.to_lowercase().contains("rbx") {
                    assert_eq!(src.version, 0, "RBX should be read at version 0");
                }
            }
        }
    }

    #[test]
    fn test_ssa_conversion_add_rax_rbx() {
        let disasm = create_x86_64_disasm();
        let bytes = pad_hex("4801d8"); // add rax, rbx

        let block = disasm.lift(&bytes, 0x1000).expect("Failed to lift");
        let ssa_block = to_ssa(&block, &disasm);

        // Verify we got operations
        assert!(!ssa_block.is_empty(), "SSA block should not be empty");

        // The add should produce an IntAdd operation
        let has_add = ssa_block
            .ops
            .iter()
            .any(|op| matches!(op, SSAOp::IntAdd { .. }));
        assert!(has_add, "Should have an IntAdd operation");
    }

    #[test]
    fn test_def_use_analysis() {
        let disasm = create_x86_64_disasm();
        let bytes = pad_hex("4801d8"); // add rax, rbx

        let block = disasm.lift(&bytes, 0x1000).expect("Failed to lift");
        let ssa_block = to_ssa(&block, &disasm);

        let info = def_use(&ssa_block);

        // Should have some inputs (registers read)
        assert!(!info.inputs.is_empty(), "Should have input variables");

        // Should have some outputs (registers written)
        // Note: Some outputs may also be inputs to later ops
        let total_defined = info.definitions.values().filter(|v| v.is_some()).count();
        assert!(total_defined > 0, "Should have defined variables");
    }

    #[test]
    fn test_ssa_multiple_writes() {
        let disasm = create_x86_64_disasm();
        // inc rax (48 ff c0)
        let bytes = pad_hex("48ffc0");

        let block = disasm.lift(&bytes, 0x1000).expect("Failed to lift");
        let ssa_block = to_ssa(&block, &disasm);

        // Each inc should produce a new version
        // The exact behavior depends on P-code semantics
        assert!(!ssa_block.is_empty());
    }

    #[test]
    fn test_ssa_var_display() {
        let var = SSAVar::new("RAX", 3, 8);
        assert_eq!(var.display_name(), "RAX_3");
        assert_eq!(format!("{}", var), "RAX_3");
    }
}
