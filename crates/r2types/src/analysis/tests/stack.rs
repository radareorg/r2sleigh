//! What the analysis proves about the frame and its slots.

use super::super::*;
use super::*;

#[test]
fn stack_width_evidence_requires_exact_ram_space() {
    let ram_addr = SSAVar::new("ram_addr", 1, 8);
    let custom_addr = SSAVar::new("custom_addr", 1, 8);
    let blocks = [SSABlock {
        addr: 0x1000,
        size: 8,
        ops: vec![
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
        phis: Vec::new(),
    }];
    let ram_slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -8,
    };
    let custom_slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -16,
    };
    let prep_facts = r2ssa::DecompilePrepFacts {
        stack_address_roots: [
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
        .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    };

    let widths = canonical_stack_access_widths(&blocks, Some(&prep_facts));
    assert_eq!(widths.get(&ram_slot), Some(&BTreeSet::from([4])));
    assert!(!widths.contains_key(&custom_slot));
}

#[test]
fn canonical_stack_access_width_overrides_generic_host_integer_width() {
    let addr = SSAVar::new("tmp:sum", 1, 8);
    let blocks = [SSABlock {
        addr: 0x1000,
        size: 4,
        ops: vec![SSAOp::Store {
            space: r2il::SpaceId::Ram,
            addr: addr.clone(),
            val: SSAVar::new("w8", 1, 4),
        }],
        phis: Vec::new(),
    }];
    let prep_facts = r2ssa::DecompilePrepFacts {
        stack_address_roots: [(
            addr,
            r2ssa::StackAddressRoot {
                base: r2ssa::StackAddressBase::StackPointer,
                offset: -16,
            },
        )]
        .into_iter()
        .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    };
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -16,
        },
        ExternalStackVarSpec {
            name: "var_10h".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            }),
            role: ExternalStackSlotRole::Local,
            param_index: None,
            param_name: None,
            source_reg: None,
        },
    );
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
            parsed_context,
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    let candidate = &analysis.plan.var_type_candidates[0];
    assert_eq!(candidate.var_type, parse_test_type("int32_t", 64));
    assert_eq!(candidate.source, TypeFactSource::DataflowRanked);
    assert!(
        candidate
            .evidence
            .contains(&TypeEvidence::CanonicalStackAccessWidth)
    );
    let slot = analysis
        .type_facts
        .stack_slots
        .get(&StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -16,
        })
        .expect("canonical stack slot");
    assert_eq!(
        slot.ty,
        Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        })
    );
    assert!(analysis.type_facts.visible_bindings.iter().any(|binding| {
        binding.name == "var_10h"
            && binding.ty == slot.ty
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
    let blocks = [SSABlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
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
        phis: Vec::new(),
    }];
    let prep_facts = r2ssa::DecompilePrepFacts {
        stack_address_roots: [(
            addr,
            r2ssa::StackAddressRoot {
                base: r2ssa::StackAddressBase::StackPointer,
                offset: -15,
            },
        )]
        .into_iter()
        .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    };
    let slot_key = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -15,
    };
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.stack_slots.insert(
        slot_key,
        ExternalStackVarSpec {
            name: "var_fh".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Signed,
            }),
            role: ExternalStackSlotRole::Local,
            param_index: None,
            param_name: None,
            source_reg: None,
        },
    );
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
            parsed_context,
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    let candidate = &analysis.plan.var_type_candidates[0];
    assert_eq!(candidate.var_type, parse_test_type("uint8_t", 64));
    assert!(
        candidate
            .evidence
            .contains(&TypeEvidence::CanonicalStackSignedness)
    );
    assert_eq!(
        analysis
            .type_facts
            .stack_slots
            .get(&slot_key)
            .and_then(|slot| slot.ty.clone()),
        Some(CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Unsigned,
        })
    );
}

#[test]
fn prepared_direct_stack_base_store_is_a_parameter_home() {
    let stack_addr = SSAVar::new("sp", 1, 8);
    let custom_stack_addr = SSAVar::new("custom_spill", 1, 8);
    let blocks = [SSABlock {
        addr: 0x1000,
        size: 8,
        ops: vec![
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: stack_addr.clone(),
                val: SSAVar::new("w2", 0, 4),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Custom(7),
                addr: custom_stack_addr.clone(),
                val: SSAVar::new("w1", 0, 4),
            },
        ],
        phis: Vec::new(),
    }];
    let prep_facts = r2ssa::DecompilePrepFacts {
        stack_address_roots: [
            (
                stack_addr,
                r2ssa::StackAddressRoot {
                    base: r2ssa::StackAddressBase::StackPointer,
                    offset: -16,
                },
            ),
            (
                custom_stack_addr,
                r2ssa::StackAddressRoot {
                    base: r2ssa::StackAddressBase::StackPointer,
                    offset: -24,
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    };
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: (0..3)
            .map(|index| FunctionParamSpec {
                name: format!("arg{index}"),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
            })
            .collect(),
    };
    let register_params = (0..3)
        .map(|index| ExternalRegisterParamSpec {
            name: format!("arg{index}"),
            ty: signature.params[index].ty.clone(),
            reg: format!("x{index}"),
        })
        .collect::<Vec<_>>();
    let mut stack_slots = BTreeMap::new();

    canonicalize_param_home_stack_slots(
        Some(&signature),
        &register_params,
        &mut stack_slots,
        &blocks,
        Some(&prep_facts),
        &aarch64_register_identity(),
    );

    let home = stack_slots
        .get(&StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -16,
        })
        .expect("direct stack-base parameter home");
    assert_eq!(home.role, ExternalStackSlotRole::ParamHome);
    assert_eq!(home.param_index, Some(2));
    assert_eq!(home.param_name.as_deref(), Some("arg2"));
    assert_eq!(home.source_reg.as_deref(), Some("x2"));
    assert!(!stack_slots.contains_key(&StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -24,
    }));
}

#[test]
fn stack_var_preference_renames_and_types_generic_stack_slots() {
    let mut parsed_context = ParsedExternalContext::default();
    let spec = ExternalStackVarSpec {
        name: "count".to_string(),
        ty: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        role: ExternalStackSlotRole::Local,
        param_index: None,
        param_name: None,
        source_reg: None,
    };
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: -0x10,
        },
        spec,
    );
    let vars = [RecoveredVariable {
        name: "var_10h".to_string(),
        kind: "b".to_string(),
        delta: -0x10,
        var_type: "byte[4]".to_string(),
        isarg: false,
        reg: None,
    }];
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.f".to_string().as_str(),
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.f".to_string(),
            signature: "void sym.f ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: String::new(),
            arch: String::new(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });
    assert_eq!(
        analysis.plan.var_type_candidates[0].var_type,
        parse_test_type("int32_t", 64)
    );
    assert_eq!(analysis.plan.var_rename_candidates[0].target_name, "count");
    assert!(
        analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(|binding| matches!(binding.kind, VisibleBindingKind::Local)
                && binding.stack_slot.as_ref().is_some_and(|slot| slot.base
                    == ExternalStackBase::FramePointer
                    && slot.offset == -0x10)
                && binding.name == "count"),
        "expected visible local binding for count, got {:?}",
        analysis.type_facts.visible_bindings
    );
    let count_binding = analysis
        .type_facts
        .visible_bindings
        .iter()
        .find(|binding| binding.name == "count")
        .expect("count visible binding");
    assert_eq!(
        count_binding.ty,
        Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        "renamed visible locals must keep the strongest canonical type"
    );
}

#[test]
fn param_home_slots_do_not_surface_as_visible_local_candidates() {
    let mut parsed_context = ParsedExternalContext::default();
    let spec = ExternalStackVarSpec {
        name: "arr_home".to_string(),
        ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
        role: ExternalStackSlotRole::ParamHome,
        param_index: Some(0),
        param_name: Some("arr".to_string()),
        source_reg: Some("rdi".to_string()),
    };
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: 0x10,
        },
        spec,
    );

    let vars = [RecoveredVariable {
        name: "var_10h".to_string(),
        kind: "b".to_string(),
        delta: 0x10,
        var_type: "void *".to_string(),
        isarg: false,
        reg: None,
    }];
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.f",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.f".to_string(),
            signature: "void sym.f ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        analysis.plan.var_type_candidates.is_empty(),
        "param-home slots should not emit visible local type candidates: {:?}",
        analysis.plan.var_type_candidates
    );
    assert!(
        analysis.plan.var_rename_candidates.is_empty(),
        "param-home slots should not emit visible local rename candidates: {:?}",
        analysis.plan.var_rename_candidates
    );
    assert!(
        analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(
                |binding| matches!(binding.kind, VisibleBindingKind::HiddenHome)
                    && binding.name == "arr_home"
            ),
        "expected hidden param-home binding, got {:?}",
        analysis.type_facts.visible_bindings
    );
}

#[test]
fn unproven_stack_pointer_zero_slot_is_hidden_saved_frame_state() {
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: 0,
        },
        ExternalStackVarSpec {
            name: "var_8h".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
            role: ExternalStackSlotRole::Unknown,
            param_index: None,
            param_name: None,
            source_reg: None,
        },
    );
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: -8,
        },
        ExternalStackVarSpec {
            name: "arr".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
            role: ExternalStackSlotRole::ParamHome,
            param_index: Some(0),
            param_name: Some("arr".to_string()),
            source_reg: Some("rdi".to_string()),
        },
    );

    let vars = [RecoveredVariable {
        name: "var_8h".to_string(),
        kind: "s".to_string(),
        delta: 0,
        var_type: "void *".to_string(),
        isarg: false,
        reg: None,
    }];
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_struct_array_index",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_struct_array_index".to_string(),
            signature: "int32_t sym.test_struct_array_index(void * arr, int32_t idx, int32_t v)"
                .to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arr".to_string(),
                    param_type: "void *".to_string(),
                },
                InferredSignatureParam {
                    name: "idx".to_string(),
                    param_type: "int32_t".to_string(),
                },
                InferredSignatureParam {
                    name: "v".to_string(),
                    param_type: "int32_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let slot = analysis
        .type_facts
        .stack_slots
        .get(&StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: 0,
        })
        .expect("canonicalized stack slot");
    assert_eq!(slot.role, ExternalStackSlotRole::SavedFp);
    assert_eq!(slot.name, "saved_fp");
    assert!(
        analysis.plan.var_type_candidates.is_empty(),
        "hidden saved frame state must not emit visible type candidates: {:?}",
        analysis.plan.var_type_candidates
    );
    assert!(
        analysis.plan.var_rename_candidates.is_empty(),
        "hidden saved frame state must not emit visible rename candidates: {:?}",
        analysis.plan.var_rename_candidates
    );
    assert!(
        analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(
                |binding| matches!(binding.kind, VisibleBindingKind::HiddenSaved)
                    && binding.name == "saved_fp"
            ),
        "expected hidden saved-frame binding, got {:?}",
        analysis.type_facts.visible_bindings
    );
    assert!(
        !analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(|binding| binding.name == "var_8h"),
        "raw stack artifact name must not remain visible: {:?}",
        analysis.type_facts.visible_bindings
    );
}

#[test]
fn frame_slots_do_not_cross_apply_to_stack_pointer_temps() {
    let mut parsed_context = ParsedExternalContext::default();
    let spec = ExternalStackVarSpec {
        name: "len".to_string(),
        ty: Some(CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        }),
        role: ExternalStackSlotRole::Local,
        param_index: None,
        param_name: None,
        source_reg: None,
    };
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: -8,
        },
        spec,
    );

    let vars = [RecoveredVariable {
        name: "var_8h".to_string(),
        kind: "s".to_string(),
        delta: -8,
        var_type: "void *".to_string(),
        isarg: false,
        reg: None,
    }];
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.f",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.f".to_string(),
            signature: "void sym.f ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.plan.var_type_candidates.len(), 1);
    assert_eq!(
        analysis.plan.var_type_candidates[0].var_type,
        parse_test_type("void *", 64)
    );
    assert_eq!(
        analysis.plan.var_type_candidates[0].source,
        TypeFactSource::LocalInferred
    );
    assert!(
        analysis.plan.var_rename_candidates.is_empty(),
        "stack-pointer temps must not inherit frame-slot names: {:?}",
        analysis.plan.var_rename_candidates
    );
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

    assert_eq!(analysis.signature.ret_type, "bool");
    assert_eq!(analysis.signature.params.len(), 2);
}

#[test]
fn prepared_local_inference_certifies_cross_block_spill_reload() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("RAX", 0x00, 8));
    arch.add_register(r2il::RegisterDef::sub("EAX", 0x00, 4, "RAX"));
    arch.add_register(r2il::RegisterDef::new("RDI", 0x10, 8));
    arch.add_register(r2il::RegisterDef::new("RSI", 0x18, 8));
    arch.add_register(r2il::RegisterDef::new("RBP", 0x20, 8));
    arch.add_register(r2il::RegisterDef::new("RSP", 0x28, 8));
    arch.add_register(r2il::RegisterDef::new("RIP", 0x30, 8));
    let mut entry = r2il::R2ILBlock::new(0x401000, 0x20);
    entry.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(1, 8),
        a: r2il::Varnode::register(0x20, 8),
        b: r2il::Varnode::constant(0xffff_ffff_ffff_ffe8, 8),
    });
    entry.push(r2il::R2ILOp::Store {
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(1, 8),
        val: r2il::Varnode::register(0x10, 8),
    });
    entry.push(r2il::R2ILOp::Branch {
        target: r2il::Varnode::constant(0x401020, 8),
    });
    let mut successor = r2il::R2ILBlock::new(0x401020, 0x20);
    successor.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(2, 8),
        a: r2il::Varnode::register(0x20, 8),
        b: r2il::Varnode::constant(0xffff_ffff_ffff_ffe8, 8),
    });
    successor.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(3, 8),
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(2, 8),
    });
    successor.push(r2il::R2ILOp::IntLeft {
        dst: r2il::Varnode::unique(4, 8),
        a: r2il::Varnode::register(0x18, 8),
        b: r2il::Varnode::constant(2, 8),
    });
    successor.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(5, 8),
        a: r2il::Varnode::unique(3, 8),
        b: r2il::Varnode::unique(4, 8),
    });
    successor.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::register(0x00, 4),
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(5, 8),
    });
    successor.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::register(0x00, 4),
    });
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let frame_pointer = register_storage(0x20);
    let parameter = register_storage(0x10);
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"cross-block-spill-reload".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, parameter)],
        r2ssa::SourceFunctionReturn::Void,
        [r2ssa::SourceStackSlotSpec::new_parameter_home(
            r2ssa::StackAddressBase::FramePointer,
            frame_pointer,
            -24,
            8,
            0,
            parameter,
        )],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(0x28)))
    .and_then(|interface| interface.with_frame_pointer_storage(frame_pointer))
    .expect("exact SysV64 stack-home interface");
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[entry, successor],
        Some(&arch),
        interface,
    )
    .expect("prepared SSA");
    let mut diagnostics = TypeAnalysisDiagnostics::default();

    let artifacts = infer_local_struct_artifacts_from_prepared_ssa(
        &prepared,
        Some("x86-64"),
        64,
        &mut diagnostics,
    );

    assert!(
        artifacts.indexed_accesses.iter().any(|candidate| {
            candidate.slot == 0
                && candidate.block_addr == 0x401020
                && !candidate.is_write
                && candidate.field_offset == 0
                && candidate.element_stride == 4
                && candidate.access_width == 4
                && candidate.index_value.is_some()
        }),
        "memory SSA must own cross-block spill recovery: {artifacts:?}; diagnostics={diagnostics:?}"
    );
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: vec![
            FunctionParamSpec {
                name: "arr".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }))),
            },
            FunctionParamSpec {
                name: "index".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Signed,
                }),
            },
        ],
    };
    let certificates = exact_indexed_access_certificates_from_local_artifacts(
        &artifacts,
        &[],
        Some(&signature),
        &ExternalTypeDb::default(),
        64,
    );
    assert!(certificates.array_index.iter().any(|certificate| {
        certificate.slot == 0
            && certificate.field_offset == 0
            && certificate.element_stride == 4
            && matches!(certificate.base, Some(ArrayIndexBase::Param { index: 0 }))
    }));
    assert_eq!(certificates.render_candidates, artifacts.indexed_accesses);
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
    let ssa_blocks = [SSABlock {
        addr: 0x100001000,
        size: 40,
        ops: vec![
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
        phis: Vec::new(),
    }];

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
        SSABlock {
            addr: 0x401000,
            size: 16,
            ops: vec![
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
            phis: Vec::new(),
        },
        SSABlock {
            addr: 0x401020,
            size: 24,
            ops: vec![
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
            phis: Vec::new(),
        },
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
