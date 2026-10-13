//! What the analysis proves about the frame and its slots.

use super::super::*;
use super::*;

#[test]
fn stack_width_evidence_requires_exact_ram_space() {
    let ram_addr = SSAVar::new("ram_addr", 1, 8);
    let custom_addr = SSAVar::new("custom_addr", 1, 8);
    let blocks = [SSABlock::from_parts(
        0x1000,
        8,
        vec![
            SSAOp::Load {
                dst: SSAVar::new("ram_value", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: ram_addr.clone(),
            },
            SSAOp::Load {
                dst: SSAVar::new("custom_value", 1, 8),
                space: r2il::SpaceId::Custom(7),
                addr: custom_addr.clone(),
            },
        ],
        Vec::new(),
    )];
    let ram_slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -8,
    };
    let custom_slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -16,
    };
    let prep_facts = [
        (
            ram_addr,
            r2ssa::StackAddressRoot {
                base: r2ssa::StackAddressBase::StackPointer,
                offset: ram_slot.offset,
            },
        ),
        (
            custom_addr,
            r2ssa::StackAddressRoot {
                base: r2ssa::StackAddressBase::StackPointer,
                offset: custom_slot.offset,
            },
        ),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<SSAVar, r2ssa::StackAddressRoot>>();

    let widths =
        canonical_stack_access_widths(&blocks, Some(&|var: &SSAVar| prep_facts.get(var).copied()));
    assert_eq!(widths.get(&ram_slot), Some(&BTreeSet::from([4])));
    assert!(!widths.contains_key(&custom_slot));
}

#[test]
fn canonical_stack_access_width_overrides_generic_host_integer_width() {
    let addr = SSAVar::new("tmp:sum", 1, 8);
    let blocks = [SSABlock::from_parts(
        0x1000,
        4,
        vec![SSAOp::Store {
            space: r2il::SpaceId::Ram,
            addr: addr.clone(),
            val: SSAVar::new("w8", 1, 4),
        }],
        Vec::new(),
    )];
    let prep_facts = [(
        addr,
        r2ssa::StackAddressRoot {
            base: r2ssa::StackAddressBase::StackPointer,
            offset: -16,
        },
    )]
    .into_iter()
    .collect::<std::collections::BTreeMap<SSAVar, r2ssa::StackAddressRoot>>();
    let vars = [RecoveredVariable {
        name: "var_10h".to_string(),
        kind: "s".to_string(),
        delta: -16,
        var_type: "int32_t".to_string(),
        isarg: false,
        reg: None,
    }];

    let analysis = build_type_analysis_with_prep_facts(
        TypeAnalysisInput {
            function_name: "sym._sum_array",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym._sum_array".to_string(),
                signature: "void sym._sum_array ()".to_string(),
                ret_type: "void".to_string(),
                params: Vec::new(),
                callconv: String::new(),
                arch: "aarch64".to_string(),
            },
            recovered_vars: &vars,
            ssa_blocks: &blocks,
            conventional_extension: &|_| false,
            parsed_context: ParsedExternalContext::default(),
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    let int32 = Some(CTypeLike::Int {
        bits: 32,
        signedness: Signedness::Signed,
    });
    assert!(analysis.type_facts.visible_bindings.iter().any(|binding| {
        binding.name == "var_10h"
            && binding.ty == int32
            && binding.stack_slot.as_ref()
                == Some(&StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: -16,
                })
    }));
}

#[test]
fn canonical_stack_zero_extension_recovers_unsigned_local() {
    let addr = SSAVar::new("tmp:byte", 1, 8);
    let loaded = SSAVar::new("tmp:loaded", 1, 1);
    let blocks = [SSABlock::from_parts(
        0x1000,
        4,
        vec![
            SSAOp::Load {
                dst: loaded.clone(),
                space: r2il::SpaceId::Ram,
                addr: addr.clone(),
            },
            SSAOp::IntZExt {
                dst: SSAVar::new("w8", 1, 4),
                src: loaded,
            },
        ],
        Vec::new(),
    )];
    let prep_facts = [(
        addr,
        r2ssa::StackAddressRoot {
            base: r2ssa::StackAddressBase::StackPointer,
            offset: -15,
        },
    )]
    .into_iter()
    .collect::<std::collections::BTreeMap<SSAVar, r2ssa::StackAddressRoot>>();
    let vars = [RecoveredVariable {
        name: "var_fh".to_string(),
        kind: "s".to_string(),
        delta: -15,
        var_type: "int8_t".to_string(),
        isarg: false,
        reg: None,
    }];

    let analysis = build_type_analysis_with_prep_facts(
        TypeAnalysisInput {
            function_name: "sym._fnv_fold",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym._fnv_fold".to_string(),
                signature: "void sym._fnv_fold ()".to_string(),
                ret_type: "void".to_string(),
                params: Vec::new(),
                callconv: String::new(),
                arch: "aarch64".to_string(),
            },
            recovered_vars: &vars,
            ssa_blocks: &blocks,
            conventional_extension: &|_| false,
            parsed_context: ParsedExternalContext::default(),
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    // A byte loaded only to be zero-extended is unsigned, whatever radare2 named its type.
    let uint8 = Some(CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Unsigned,
    });
    let binding = (analysis.type_facts.visible_bindings.iter())
        .find(|binding| binding.name == "var_fh")
        .expect("var_fh is bound");
    assert_eq!(binding.ty, uint8, "{binding:?}");
}

#[test]
fn interproc_summary_name_does_not_prune_generated_surplus_slots() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "dbg.or",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.or".to_string(),
            signature: "bool dbg.or(void *arg1, struct sla_struct_deadbeef *arg2)".to_string(),
            ret_type: "bool".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arg1".to_string(),
                    param_type: "void *".to_string(),
                },
                InferredSignatureParam {
                    name: "arg2".to_string(),
                    param_type: "struct sla_struct_deadbeef *".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        conventional_extension: &|_| false,
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts {
            slot_type_overrides: HashMap::from([(
                5usize,
                "struct sla_struct_0e18b2bc34030602 *".to_string(),
            )]),
            ..Default::default()
        },
        interproc_summary_set: Some(semantic_role_summary_set("dbg.or", Some(2))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(spelled_signature(&analysis).ret_type, "bool");
    assert_eq!(spelled_signature(&analysis).params.len(), 2);
}

#[test]
fn legacy_same_block_spill_reload_requires_memory_ssa() {
    let argv_ty = CTypeLike::Pointer(Box::new(CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Signed,
    }))));
    let parsed_context = ParsedExternalContext {
        register_params: vec![
            crate::context::ExternalRegisterParamSpec {
                name: "arg1".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "x0".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "arg2".to_string(),
                ty: Some(argv_ty.clone()),
                reg: "x1".to_string(),
            },
        ],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "arg1".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
                FunctionParamSpec {
                    name: "arg2".to_string(),
                    ty: Some(argv_ty),
                },
            ],
        }),
        ..ParsedExternalContext::default()
    };
    let ssa_blocks = [SSABlock::from_parts(
        0x100001000,
        40,
        vec![
            SSAOp::IntSub {
                dst: SSAVar::new("sp", 1, 8),
                a: SSAVar::new("sp", 0, 8),
                b: SSAVar::constant(0x200, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("slot", 1, 8),
                a: SSAVar::new("sp", 1, 8),
                b: SSAVar::constant(0x178, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("slot", 1, 8),
                val: SSAVar::new("x1", 0, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("slot", 2, 8),
                a: SSAVar::new("sp", 1, 8),
                b: SSAVar::constant(0x178, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("x8", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("slot", 2, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("arg_addr", 1, 8),
                a: SSAVar::new("x8", 1, 8),
                b: SSAVar::constant(8, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("x0", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("arg_addr", 1, 8),
            },
        ],
        Vec::new(),
    )];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym._main",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym._main".to_string(),
            signature: "int64_t sym._main(int32_t arg1, int8_t **arg2)".to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arg1".to_string(),
                    param_type: "int32_t".to_string(),
                },
                InferredSignatureParam {
                    name: "arg2".to_string(),
                    param_type: "int8_t **".to_string(),
                },
            ],
            callconv: "aarch64".to_string(),
            arch: "aarch64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        conventional_extension: &|_| false,
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        !analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| matches!(cert.base, Some(ArrayIndexBase::Param { index: 1 }))),
        "fixed-point block scans cannot prove store-before-load memory order: {:?}",
        analysis.type_facts.array_index_certificates
    );
}

#[test]
fn legacy_cross_block_spill_reload_requires_memory_ssa() {
    let arr_ty = CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 32,
        signedness: Signedness::Signed,
    }));
    let parsed_context = ParsedExternalContext {
        register_params: vec![
            crate::context::ExternalRegisterParamSpec {
                name: "arg1".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Signed,
                }),
                reg: "RDI".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "idx".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "RSI".to_string(),
            },
        ],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "arr".to_string(),
                    ty: Some(arr_ty),
                },
                FunctionParamSpec {
                    name: "idx".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
            ],
        }),
        ..ParsedExternalContext::default()
    };
    let ssa_blocks = [
        SSABlock::from_parts(
            0x401000,
            16,
            vec![
                SSAOp::IntAdd {
                    dst: SSAVar::new("slot", 1, 8),
                    a: SSAVar::new("RBP", 0, 8),
                    b: SSAVar::constant(0xffff_ffff_ffff_ffe8, 8),
                },
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("slot", 1, 8),
                    val: SSAVar::new("RDI", 0, 8),
                },
            ],
            Vec::new(),
        ),
        SSABlock::from_parts(
            0x401020,
            24,
            vec![
                SSAOp::IntAdd {
                    dst: SSAVar::new("slot", 2, 8),
                    a: SSAVar::new("RBP", 0, 8),
                    b: SSAVar::constant(0xffff_ffff_ffff_ffe8, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("ptr", 1, 8),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("slot", 2, 8),
                },
                SSAOp::IntLeft {
                    dst: SSAVar::new("idx_scaled", 1, 8),
                    a: SSAVar::new("RSI", 0, 8),
                    b: SSAVar::constant(2, 8),
                },
                SSAOp::IntAdd {
                    dst: SSAVar::new("elem", 1, 8),
                    a: SSAVar::new("ptr", 1, 8),
                    b: SSAVar::new("idx_scaled", 1, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("EAX", 1, 4),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("elem", 1, 8),
                },
            ],
            Vec::new(),
        ),
    ];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.sum_array",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.sum_array".to_string(),
            signature: "int32_t sym.sum_array(int32_t *arr, int32_t idx)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arr".to_string(),
                    param_type: "int32_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "idx".to_string(),
                    param_type: "int32_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        conventional_extension: &|_| false,
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        !analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| matches!(cert.base, Some(ArrayIndexBase::Param { index: 0 }))),
        "raw block coordinates cannot prove that a reload observes a store in another block: {:?}",
        analysis.type_facts.array_index_certificates
    );
    assert!(
        !analysis
            .type_facts
            .scalar_array_render_candidates
            .iter()
            .any(|candidate| candidate.slot == 0),
        "legacy inference must not mint parameter render evidence across blocks without memory SSA: {:?}",
        analysis.type_facts.scalar_array_render_candidates
    );
}
