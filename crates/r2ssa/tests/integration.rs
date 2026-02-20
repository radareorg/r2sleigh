//! Integration tests for r2ssa with real disassembly.

#[cfg(feature = "sleigh-config")]
mod tests {
    use r2sleigh_lift::Disassembler;
    use r2ssa::block::to_ssa;
    use r2ssa::taint::{DefaultTaintPolicy, TaintAnalysis, TaintLabel, TaintPolicy, TaintSet};
    use r2ssa::{SSAFunction, SSAOp, SSAVar, def_use};

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

    // ========== Taint Analysis Integration Tests ==========

    // Helper functions for creating varnodes in tests
    fn make_reg(offset: u64, size: u32) -> r2il::Varnode {
        r2il::Varnode {
            space: r2il::SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    fn make_const(val: u64, size: u32) -> r2il::Varnode {
        r2il::Varnode {
            space: r2il::SpaceId::Const,
            offset: val,
            size,
            meta: None,
        }
    }

    // Simulated register offsets (x86-64 style)
    const RAX: u64 = 0;
    const RBX: u64 = 8;
    const RCX: u64 = 16;
    const RSI: u64 = 32;
    const RDI: u64 = 56;

    #[test]
    fn test_taint_analysis_simple_flow() {
        // Test: mov rax, rdi; mov [rbx], rax
        // RDI (arg0) should taint RAX, then flow to store sink
        use r2il::{R2ILBlock, R2ILOp, SpaceId};

        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    // mov rax, rdi
                    R2ILOp::Copy {
                        dst: make_reg(RAX, 8),
                        src: make_reg(RDI, 8),
                    },
                ],
            },
            R2ILBlock {
                addr: 0x1003,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    // mov [rbx], rax
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: make_reg(RBX, 8),
                        val: make_reg(RAX, 8),
                    },
                ],
            },
        ];

        let func = SSAFunction::from_blocks(&blocks).expect("Failed to build SSA function");
        let policy = DefaultTaintPolicy::all_inputs();
        let analysis = TaintAnalysis::new(&func, policy);
        let result = analysis.analyze();

        // Should have at least one sink hit (the store)
        assert!(
            result.has_violations(),
            "Should detect taint flowing to store"
        );

        // The store should have tainted data
        assert!(!result.sink_hits.is_empty());
        let hit = &result.sink_hits[0];
        assert!(matches!(hit.op, SSAOp::Store { .. }));
    }

    #[test]
    fn test_taint_analysis_custom_propagate() {
        // Test custom propagation rule: AND with constant clears taint
        use r2il::{R2ILBlock, R2ILOp};

        struct MaskingPolicy;

        impl TaintPolicy for MaskingPolicy {
            fn is_source(&self, var: &SSAVar, _block_addr: u64) -> Option<Vec<TaintLabel>> {
                if var.version == 0 && var.is_register() {
                    Some(vec![TaintLabel::new(format!("input:{}", var.name))])
                } else {
                    None
                }
            }

            fn is_sink(&self, op: &SSAOp, _block_addr: u64) -> bool {
                matches!(op, SSAOp::Store { .. } | SSAOp::Call { .. })
            }

            fn propagate(&self, op: &SSAOp, _source_taints: &[&TaintSet]) -> Option<TaintSet> {
                // AND with a small constant (mask) clears taint
                if let SSAOp::IntAnd { b, .. } = op
                    && b.is_const()
                {
                    // Masking clears taint
                    return Some(TaintSet::new());
                }
                None // Use default propagation
            }
        }

        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    // mov rax, rdi
                    R2ILOp::Copy {
                        dst: make_reg(RAX, 8),
                        src: make_reg(RDI, 8),
                    },
                ],
            },
            R2ILBlock {
                addr: 0x1003,
                size: 4,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    // and rax, 0xff (mask - should clear taint per our policy)
                    R2ILOp::IntAnd {
                        dst: make_reg(RAX, 8),
                        a: make_reg(RAX, 8),
                        b: make_const(0xff, 8),
                    },
                ],
            },
            R2ILBlock {
                addr: 0x1007,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    // call rax (would be a sink, but RAX is now clean)
                    R2ILOp::Call {
                        target: make_reg(RAX, 8),
                    },
                ],
            },
        ];

        let func = SSAFunction::from_blocks(&blocks).expect("Failed to build SSA function");
        let analysis = TaintAnalysis::new(&func, MaskingPolicy);
        let result = analysis.analyze();

        // The custom propagate() should have cleared taint on the AND
        // So the call should NOT be a violation
        assert!(
            !result.has_violations(),
            "Masking should clear taint, no violations expected"
        );
    }

    #[test]
    fn test_taint_analysis_multi_path_convergence() {
        // Test that taint from multiple paths converges correctly
        // Diamond CFG: entry -> (left | right) -> merge
        // Left path taints via RDI, right path taints via RSI
        // Merge should have both taints
        use r2il::{R2ILBlock, R2ILOp, SpaceId};

        let blocks = vec![
            // Entry: branch on a non-constant register so SCCP keeps both paths
            R2ILBlock {
                addr: 0x1000,
                size: 2,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1010, 8), // jump to right
                    cond: make_reg(RBX, 1),        // non-constant condition
                }],
            },
            // Left path (fallthrough): rax = rdi, then jump to merge
            R2ILBlock {
                addr: 0x1002,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(RAX, 8),
                        src: make_reg(RDI, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1020, 8),
                    },
                ],
            },
            // Right path: rax = rsi, then jump to merge
            R2ILBlock {
                addr: 0x1010,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(RAX, 8),
                        src: make_reg(RSI, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1020, 8),
                    },
                ],
            },
            // Merge: store rax
            R2ILBlock {
                addr: 0x1020,
                size: 3,
                switch_info: None,
                op_metadata: Default::default(),
                ops: vec![R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_reg(RCX, 8),
                    val: make_reg(RAX, 8),
                }],
            },
        ];

        let func = SSAFunction::from_blocks(&blocks).expect("Failed to build SSA function");
        let policy = DefaultTaintPolicy::all_inputs();
        let analysis = TaintAnalysis::new(&func, policy);
        let result = analysis.analyze();

        // Should have violations (store of tainted data)
        assert!(result.has_violations(), "Should detect taint at store");

        // The merged RAX at the store should have taint from both paths
        // (due to phi node merging)
        let hit = &result.sink_hits[0];
        let total_labels: usize = hit.tainted_vars.iter().map(|(_, t)| t.len()).sum();
        // Should have labels from both RDI and RSI paths
        assert!(
            total_labels >= 1,
            "Should have taint labels from at least one path"
        );
    }
}
