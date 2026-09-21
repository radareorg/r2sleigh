//! What the analysis proves about arrays and their elements.

use super::super::*;

#[test]
fn phi_scalar_array_addr_expr_preserves_max_confidence() {
    let block_addr = 0x401000;
    let left = SSAVar::new("left_expr", 1, 8);
    let right = SSAVar::new("right_expr", 1, 8);
    let mut array_addr_exprs = HashMap::new();
    let array_addr_expr_names = HashMap::new();
    let pointer = ScalarPointerValue {
        slot: 0,
        base: ArrayIndexBase::Param { index: 0 },
        element_stride: 8,
        confidence: 80,
    };
    let low = ScalarArrayAddrExpr {
        pointer,
        field_offset: 0x10,
        confidence: 30,
    };
    let high = ScalarArrayAddrExpr {
        confidence: 91,
        ..low.clone()
    };
    array_addr_exprs.insert(ssa_var_block_key(block_addr, &left), low);
    array_addr_exprs.insert(ssa_var_block_key(block_addr, &right), high);

    let selected = phi_scalar_array_addr_expr(
        block_addr,
        &[left, right],
        &array_addr_exprs,
        &array_addr_expr_names,
    )
    .expect("same-base phi should preserve array address expression");

    assert_eq!(selected.confidence, 91);
}

#[test]
fn prepared_parameter_indexed_accesses_keep_semantic_index_identity() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("RAX", 0x00, 8));
    arch.add_register(r2il::RegisterDef::sub("EAX", 0x00, 4, "RAX"));
    arch.add_register(r2il::RegisterDef::new("RDI", 0x10, 8));
    arch.add_register(r2il::RegisterDef::new("RSI", 0x18, 8));
    arch.add_register(r2il::RegisterDef::sub("ESI", 0x18, 4, "RSI"));
    let mut block = r2il::R2ILBlock::new(0x401000, 4);
    block.push(r2il::R2ILOp::IntZExt {
        dst: r2il::Varnode::unique(1, 8),
        src: r2il::Varnode::register(0x18, 4),
    });
    block.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(2, 8),
        a: r2il::Varnode::register(0x10, 8),
        b: r2il::Varnode::unique(1, 8),
    });
    block.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::register(0x00, 1),
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(2, 8),
    });
    block.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(3, 1),
        space: r2il::SpaceId::Custom(7),
        addr: r2il::Varnode::unique(2, 8),
    });
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"prepared-indexed-access-fixture".to_vec(),
        "sysv64",
        [
            r2ssa::SourceAbiParameterSpec::new(0, register_storage(0x10)),
            r2ssa::SourceAbiParameterSpec::new(1, register_storage(0x18)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
    )
    .expect("exact indexed-access interface");
    let prepared =
        r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("prepared indexed load");
    let load_index = prepared
        .function()
        .get_block(0x401000)
        .expect("block")
        .ops
        .iter()
        .position(|op| matches!(op, r2ssa::SSAOp::Load { .. }))
        .expect("indexed load");
    let address = prepared
        .memory_certificate_for_op_site(0x401000, load_index, false)
        .expect("memory certificate");
    let parameter_address = prepared
        .addresses()
        .parameter_expression(address.address)
        .expect("parameter-relative address");
    let index_value = parameter_address.terms[0].value;
    let custom_index = prepared
        .function()
        .get_block(0x401000)
        .expect("block")
        .ops
        .iter()
        .position(|op| matches!(op, r2ssa::SSAOp::Load { space, .. } if *space == r2il::SpaceId::Custom(7)))
        .expect("custom-space load");
    assert!(
        prepared
            .memory_certificate_for_op_site(0x401000, custom_index, false)
            .is_some(),
        "the Custom-space access must exist before type filtering"
    );

    let candidates = prepared_parameter_indexed_accesses(&prepared);

    assert_eq!(
        candidates,
        vec![ScalarArrayRenderCandidate {
            slot: 0,
            block_addr: 0x401000,
            op_index: load_index,
            is_write: false,
            field_offset: 0,
            element_stride: 1,
            access_width: 1,
            index_value: Some(index_value),
        }]
    );
}

#[test]
fn typed_stack_pointer_index_access_certifies_scalar_array_index() {
    let mut parsed_context = ParsedExternalContext::default();
    let buf_slot = StackSlotKey {
        base: ExternalStackBase::FramePointer,
        offset: -8,
    };
    parsed_context.stack_slots.insert(
        buf_slot,
        crate::ExternalStackSlotSpec {
            name: "buf".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Signed,
            }))),
            role: ExternalStackSlotRole::Local,
            param_index: None,
            param_name: None,
            source_reg: None,
        },
    );
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: -0x20,
        },
        crate::ExternalStackSlotSpec {
            name: "len_home".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned,
            }),
            role: ExternalStackSlotRole::ParamHome,
            param_index: Some(1),
            param_name: Some("len".to_string()),
            source_reg: Some("rsi".to_string()),
        },
    );
    let ssa_blocks = [SSABlock {
        addr: 0x4013b1,
        size: 32,
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("buf_slot_addr", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff8, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("buf", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("buf_slot_addr", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("len_slot_addr", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_ffe0, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("len", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("len_slot_addr", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("nul_addr", 1, 8),
                a: SSAVar::new("buf", 1, 8),
                b: SSAVar::new("len", 1, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("nul_addr", 1, 8),
                val: SSAVar::constant(0, 1),
            },
        ],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.alloc_and_copy",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_and_copy".to_string(),
            signature: "int8_t * sym.alloc_and_copy (int8_t * src, size_t len)".to_string(),
            ret_type: "int8_t *".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "src".to_string(),
                    param_type: "int8_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "len".to_string(),
                    param_type: "size_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| {
                cert.element_stride == 1
                    && cert.field_offset == 0
                    && matches!(
                        cert.base,
                        Some(ArrayIndexBase::StackSlot { ref slot }) if *slot == buf_slot
                    )
            }),
        "expected scalar typed stack pointer index certificate, got {:?}",
        analysis.type_facts.array_index_certificates
    );
    assert_eq!(
        analysis.type_facts.scalar_array_render_candidates,
        vec![ScalarArrayRenderCandidate {
            slot: legacy_array_slot_for_stack_slot(&buf_slot),
            block_addr: 0x4013b1,
            op_index: 5,
            is_write: true,
            field_offset: 0,
            element_stride: 1,
            access_width: 1,
            index_value: None,
        }],
        "render candidates must preserve the concrete scalar store op identity"
    );
}

#[test]
fn typed_pointer_induction_access_certifies_scalar_array_index() {
    let parsed_context = ParsedExternalContext {
        register_params: vec![
            crate::context::ExternalRegisterParamSpec {
                name: "buf".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unsigned,
                }))),
                reg: "RDI".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "n".to_string(),
                ty: Some(CTypeLike::typedef("size_t")),
                reg: "RSI".to_string(),
            },
        ],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "buf".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                        bits: 8,
                        signedness: Signedness::Unsigned,
                    }))),
                },
                FunctionParamSpec {
                    name: "n".to_string(),
                    ty: Some(CTypeLike::typedef("size_t")),
                },
            ],
        }),
        ..ParsedExternalContext::default()
    };
    let ssa_blocks = [SSABlock {
        addr: 0x401500,
        size: 32,
        ops: vec![
            SSAOp::Phi {
                dst: SSAVar::new("RDI", 2, 8),
                sources: vec![SSAVar::new("RDI", 0, 8), SSAVar::new("RDI", 1, 8)],
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("RDI", 1, 8),
                a: SSAVar::new("RDI", 2, 8),
                b: SSAVar::constant(1, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("byte", 1, 1),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("RDI", 2, 8),
            },
        ],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.pointer_induction",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.pointer_induction".to_string(),
            signature: "uint64_t sym.pointer_induction(uint8_t *buf, size_t n)".to_string(),
            ret_type: "uint64_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "buf".to_string(),
                    param_type: "uint8_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "n".to_string(),
                    param_type: "size_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| {
                cert.element_stride == 1
                    && cert.field_offset == 0
                    && matches!(cert.base, Some(ArrayIndexBase::Param { index: 0 }))
            }),
        "expected typed pointer induction array certificate, got {:?}",
        analysis.type_facts.array_index_certificates
    );
}

#[test]
fn typed_argument_phi_livein_access_certifies_scalar_array_index() {
    let parsed_context = ParsedExternalContext {
        register_params: vec![crate::context::ExternalRegisterParamSpec {
            name: "buf".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Unsigned,
            }))),
            reg: "RDI".to_string(),
        }],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned,
            }),
            params: vec![FunctionParamSpec {
                name: "buf".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unsigned,
                }))),
            }],
        }),
        ..ParsedExternalContext::default()
    };
    let ssa_blocks = [SSABlock {
        addr: 0x401500,
        size: 8,
        ops: vec![SSAOp::Load {
            dst: SSAVar::new("byte", 1, 1),
            space: r2il::SpaceId::Ram,
            addr: SSAVar::new("RDI", 1, 8),
        }],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.pointer_livein",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.pointer_livein".to_string(),
            signature: "uint64_t sym.pointer_livein(uint8_t *buf)".to_string(),
            ret_type: "uint64_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "buf".to_string(),
                param_type: "uint8_t *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| {
                cert.element_stride == 1
                    && cert.field_offset == 0
                    && matches!(cert.base, Some(ArrayIndexBase::Param { index: 0 }))
            }),
        "expected typed argument phi/live-in array certificate, got {:?}",
        analysis.type_facts.array_index_certificates
    );
}
