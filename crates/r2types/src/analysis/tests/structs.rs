//! What the analysis proves about aggregates.

use super::super::*;
use super::*;

#[test]
fn global_field_profiles_refuse_spoofed_constant_names() {
    let load_from = |addr| SSABlock {
        addr: 0x401000,
        size: 4,
        ops: vec![SSAOp::Load {
            dst: SSAVar::new("value", 1, 4),
            space: r2il::SpaceId::Ram,
            addr,
        }],
        phis: Vec::new(),
    };

    let loaded = crate::ProgramExtents::new([(0x10000, 0x11000)]);
    let spoofed =
        infer_global_field_profiles(&[load_from(SSAVar::new("const:10000", 0, 8))], 64, &loaded);
    let exact =
        infer_global_field_profiles(&[load_from(SSAVar::constant(0x10000, 8))], 64, &loaded);
    // The same access, where no section the program loads holds the base, names no global.
    let outside = infer_global_field_profiles(
        &[load_from(SSAVar::constant(0x10000, 8))],
        64,
        &crate::ProgramExtents::none(),
    );

    assert!(spoofed.is_empty());
    assert!(outside.is_empty());
    assert_eq!(
        exact
            .get(&0x10000)
            .and_then(|fields| fields.get(&0))
            .map(|field| field.reads),
        Some(1)
    );
}

#[test]
fn signature_type_parser_preserves_source_width_typedefs() {
    assert_eq!(
        parse_signature_type_preserving_c_typedefs("long", 64),
        Some(typedef_type("long"))
    );
    assert_eq!(
        parse_signature_type_preserving_c_typedefs("unsigned long int", 64),
        Some(typedef_type("unsigned long"))
    );
    assert_eq!(
        parse_signature_type_preserving_c_typedefs("short", 64),
        Some(typedef_type("short"))
    );
    assert_eq!(
        parse_signature_type_preserving_c_typedefs("size_t", 64),
        Some(typedef_type("size_t"))
    );
    assert_eq!(
        parse_signature_type_preserving_c_typedefs("ptrdiff_t", 64),
        Some(typedef_type("ptrdiff_t"))
    );
}

#[test]
fn local_struct_decl_preserves_sparse_offsets_with_padding() {
    let decl = build_struct_decl(
        "sla_struct_sparse",
        &[
            StructFieldCandidate {
                name: "f_8".to_string(),
                offset: 8,
                field_type: parse_test_type("int32_t", 64),
                confidence: 95,
            },
            StructFieldCandidate {
                name: "f_34".to_string(),
                offset: 0x34,
                field_type: parse_test_type("int32_t", 64),
                confidence: 95,
            },
        ],
        64,
    )
    .expect("struct decl");

    assert!(decl.contains("uint8_t _pad_0[8];"), "{decl}");
    assert!(decl.contains("int32_t f_8;"), "{decl}");
    assert!(decl.contains("uint8_t _pad_c[40];"), "{decl}");
    assert!(decl.contains("int32_t f_34;"), "{decl}");
}

#[test]
fn imported_size_t_type_hint_matches_preserved_source_typedef() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("rsi-size".to_string()),
            subject: r2ssa::AssumptionSubject::Register {
                name: "rsi".to_string(),
            },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "size_t".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::ImportedContext,
        }]),
        register_params: vec![crate::context::ExternalRegisterParamSpec {
            name: "n".to_string(),
            ty: Some(CTypeLike::typedef("size_t")),
            reg: "rsi".to_string(),
        }],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::typedef("size_t")),
            params: vec![FunctionParamSpec {
                name: "n".to_string(),
                ty: Some(CTypeLike::typedef("size_t")),
            }],
        }),
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.scan_example".to_string(),
        signature: "size_t sym.scan_example(size_t n)".to_string(),
        ret_type: "size_t".to_string(),
        params: vec![InferredSignatureParam {
            name: "n".to_string(),
            param_type: "size_t".to_string(),
        }],
        callconv: "amd64".to_string(),
        arch: "x86-64".to_string(),
    };

    let usage = apply_type_hint_assumptions_to_context(
        &mut parsed_context,
        &mut inferred_signature,
        64,
        Some(&SemanticTypeProjection::default()),
        &x86_64_register_identity(),
    );

    assert_eq!(usage.applied.len(), 1);
    assert!(usage.ignored.is_empty());
    assert!(usage.conflicts.is_empty());
    assert_eq!(
        parsed_context.register_params[0]
            .ty
            .as_ref()
            .map(|ty| render_signature_type(ty, 64))
            .as_deref(),
        Some("size_t")
    );
}

#[test]
fn structural_slots_do_not_apply_to_unrooted_variables() {
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
        kind: "x".to_string(),
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
        "unrooted recovered vars must not inherit names from structural slots: {:?}",
        analysis.plan.var_rename_candidates
    );
}

#[test]
fn external_stack_identity_refuses_without_a_structural_root() {
    let vars = [RecoveredVariable {
        name: "var_10h".to_string(),
        kind: "b".to_string(),
        delta: -0x10,
        var_type: "int32_t".to_string(),
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
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(analysis.type_facts.stack_slots.is_empty());
    assert!(analysis.plan.var_rename_candidates.is_empty());
    assert_eq!(
        analysis.plan.var_type_candidates[0].source,
        TypeFactSource::LocalInferred
    );
}

#[test]
fn local_external_struct_reconciliation_prefers_external_names() {
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.external_type_db.structs.insert(
        "node".to_string(),
        ExternalStruct {
            name: "node".to_string(),
            fields: BTreeMap::from([
                (
                    0,
                    ExternalField {
                        name: "value".to_string(),
                        offset: 0,
                        ty: Some("int32_t".to_string()),
                    },
                ),
                (
                    8,
                    ExternalField {
                        name: "next".to_string(),
                        offset: 8,
                        ty: Some("struct node *".to_string()),
                    },
                ),
            ]),
        },
    );
    let local_structs = LocalStructArtifacts {
        struct_decls: vec![StructDeclCandidate {
            name: "sla_struct_deadbeef".to_string(),
            decl: "struct sla_struct_deadbeef { int32_t f_0; struct node *f_8; };".to_string(),
            confidence: 90,
            source: StructDeclSource::LocalInferred,
            fields: vec![
                StructFieldCandidate {
                    name: "f_0".to_string(),
                    offset: 0,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 90,
                },
                StructFieldCandidate {
                    name: "f_8".to_string(),
                    offset: 8,
                    field_type: parse_test_type("struct node *", 64),
                    confidence: 90,
                },
            ],
        }],
        slot_type_overrides: HashMap::from([(0usize, "struct sla_struct_deadbeef *".to_string())]),
        slot_field_profiles: HashMap::from([(
            0usize,
            BTreeMap::from([
                (0u64, "int32_t".to_string()),
                (8u64, "struct node *".to_string()),
            ]),
        )]),
        slot_element_strides: HashMap::new(),
        indexed_accesses: Vec::new(),
    };
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.f",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.f".to_string(),
            signature: "void sym.f ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: String::new(),
            arch: String::new(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });
    assert_eq!(
        analysis
            .type_facts
            .slot_type_overrides
            .get(&0)
            .map(String::as_str),
        Some("struct node *")
    );
}

#[test]
fn local_generated_struct_replaces_stale_generated_external_layout() {
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.external_type_db.structs.insert(
        "sla_struct_420703e08f70f00e".to_string(),
        ExternalStruct {
            name: "sla_struct_420703e08f70f00e".to_string(),
            fields: BTreeMap::from([
                (
                    0,
                    ExternalField {
                        name: "_pad_0".to_string(),
                        offset: 0,
                        ty: Some("uint8_t".to_string()),
                    },
                ),
                (
                    4,
                    ExternalField {
                        name: "f_8".to_string(),
                        offset: 4,
                        ty: Some("int32_t".to_string()),
                    },
                ),
                (
                    8,
                    ExternalField {
                        name: "_pad_c".to_string(),
                        offset: 8,
                        ty: Some("uint8_t".to_string()),
                    },
                ),
                (
                    12,
                    ExternalField {
                        name: "f_34".to_string(),
                        offset: 12,
                        ty: Some("int32_t".to_string()),
                    },
                ),
            ]),
        },
    );
    parsed_context.current_signature = Some(FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: "arr".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
        }],
    });

    let local_structs = LocalStructArtifacts {
        struct_decls: vec![StructDeclCandidate {
            name: "sla_struct_420703e08f70f00e".to_string(),
            decl: "struct sla_struct_420703e08f70f00e { int32_t f_8; int32_t f_34; };".to_string(),
            confidence: 95,
            source: StructDeclSource::LocalInferred,
            fields: vec![
                StructFieldCandidate {
                    name: "f_8".to_string(),
                    offset: 8,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
                StructFieldCandidate {
                    name: "f_34".to_string(),
                    offset: 0x34,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
            ],
        }],
        slot_type_overrides: HashMap::from([(
            0usize,
            "struct sla_struct_420703e08f70f00e *".to_string(),
        )]),
        slot_field_profiles: HashMap::from([(
            0usize,
            BTreeMap::from([
                (8u64, "int32_t".to_string()),
                (0x34u64, "int32_t".to_string()),
            ]),
        )]),
        slot_element_strides: HashMap::new(),
        indexed_accesses: Vec::new(),
    };
    let ssa_blocks = [SSABlock {
        addr: 0x401000,
        size: 4,
        ops: vec![
            SSAOp::IntMult {
                dst: SSAVar::new("scaled", 1, 8),
                a: SSAVar::new("RSI", 0, 8),
                b: SSAVar::constant(0x38, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("elem", 1, 8),
                a: SSAVar::new("RDI", 0, 8),
                b: SSAVar::new("scaled", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("field", 1, 8),
                a: SSAVar::new("elem", 1, 8),
                b: SSAVar::constant(8, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("value", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("field", 1, 8),
            },
        ],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_struct_array_index",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_struct_array_index".to_string(),
            signature: "int32_t sym.test_struct_array_index (void * arr)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arr".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &ssa_blocks,
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let struct_entry = analysis
        .type_facts
        .external_type_db
        .structs
        .get("sla_struct_420703e08f70f00e")
        .expect("expected merged local struct entry");
    assert_eq!(
        struct_entry.fields.get(&8).map(|field| field.name.as_str()),
        Some("f_8")
    );
    assert_eq!(
        struct_entry
            .fields
            .get(&0x34)
            .map(|field| field.name.as_str()),
        Some("f_34")
    );
    assert!(
        !struct_entry.fields.contains_key(&4) && !struct_entry.fields.contains_key(&12),
        "stale generated external layout should be replaced, got {:?}",
        struct_entry.fields
    );
    assert!(
        analysis
            .plan
            .struct_decls
            .iter()
            .find(|decl| decl.name == "sla_struct_420703e08f70f00e")
            .is_some_and(|decl| decl.source == StructDeclSource::LocalInferred),
        "expected plan to keep the current local synthetic struct"
    );
    assert_eq!(
        analysis.type_facts.scalar_array_render_candidates,
        vec![ScalarArrayRenderCandidate {
            slot: 0,
            block_addr: 0x401000,
            op_index: 3,
            is_write: false,
            field_offset: 8,
            element_stride: 56,
            access_width: 4,
            index_value: None,
        }],
        "scalar array proof must use the reconciled local layout, not stale parsed context"
    );
}

/// A context whose stated signature is `int32_t (DemoStruct *param)`.
fn demo_struct_pointer_context(param: &str) -> crate::ParsedExternalContext {
    let signature = crate::FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: crate::Signedness::Signed,
        }),
        params: vec![crate::FunctionParamSpec {
            name: param.to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::typedef(
                "DemoStruct",
            )))),
        }],
    };
    crate::ParsedExternalContext {
        current_signature: Some(signature.clone()),
        merged_signature: Some(signature),
        ..crate::ParsedExternalContext::default()
    }
}

#[test]
fn debug_typedef_alias_beats_generated_local_struct_override() {
    // The debug information states `typedef struct type_0x261 DemoStruct`,
    // with `int third` at 8 and `int fourteenth` at 52.
    let mut parsed_context = demo_struct_pointer_context("arr");
    let field = |name: &str, offset| crate::ExternalField {
        name: name.to_string(),
        offset,
        ty: Some("int".to_string()),
    };
    let layout = |name: &str| ExternalStruct {
        name: name.to_string(),
        fields: BTreeMap::from([(8, field("third", 8)), (52, field("fourteenth", 52))]),
    };
    let db = &mut parsed_context.external_type_db;
    db.structs
        .insert("type_0x261".to_string(), layout("type_0x261"));
    db.structs
        .insert("demostruct".to_string(), layout("DemoStruct"));
    db.typedefs.insert(
        "demostruct".to_string(),
        crate::external::ExternalTypedef {
            name: "DemoStruct".to_string(),
            target: "type_0x261".to_string(),
        },
    );
    let local_structs = LocalStructArtifacts {
        struct_decls: vec![StructDeclCandidate {
            name: "sla_struct_420703e08f70f00e".to_string(),
            decl: "struct sla_struct_420703e08f70f00e { int32_t f_8; int32_t f_34; };".to_string(),
            confidence: 95,
            source: StructDeclSource::LocalInferred,
            fields: vec![
                StructFieldCandidate {
                    name: "f_8".to_string(),
                    offset: 8,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
                StructFieldCandidate {
                    name: "f_34".to_string(),
                    offset: 0x34,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
            ],
        }],
        slot_type_overrides: HashMap::from([(
            0usize,
            "struct sla_struct_420703e08f70f00e *".to_string(),
        )]),
        slot_field_profiles: HashMap::from([(
            0usize,
            BTreeMap::from([
                (8u64, "int32_t".to_string()),
                (0x34u64, "int32_t".to_string()),
            ]),
        )]),
        slot_element_strides: HashMap::new(),
        indexed_accesses: Vec::new(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_struct_array_index",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_struct_array_index".to_string(),
            signature: "int32_t sym.test_struct_array_index (void * arr)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arr".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.params[0].param_type, "DemoStruct*");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|signature| signature.params[0].ty.as_ref()),
        Some(&CTypeLike::Pointer(Box::new(CTypeLike::typedef(
            "DemoStruct"
        ))))
    );
    let external = analysis
        .type_facts
        .external_type_db
        .structs
        .get("demostruct")
        .expect("typedef-backed struct alias");
    assert_eq!(
        external.fields.get(&8).map(|field| field.name.as_str()),
        Some("third")
    );
    assert_eq!(
        external.fields.get(&0x34).map(|field| field.name.as_str()),
        Some("fourteenth")
    );
    assert!(
        !analysis
            .type_facts
            .slot_type_overrides
            .values()
            .any(|ty| ty.contains("sla_struct_")),
        "source typedef layout should prevent selected synthetic struct overrides"
    );
    assert_eq!(
        analysis.type_facts.array_index_certificates,
        vec![
            ArrayIndexCertificate {
                slot: 0,
                base: Some(ArrayIndexBase::Param { index: 0 }),
                field_offset: 8,
                element_stride: 56,
            },
            ArrayIndexCertificate {
                slot: 0,
                base: Some(ArrayIndexBase::Param { index: 0 }),
                field_offset: 0x34,
                element_stride: 56,
            },
        ],
        "source typedef layout plus local indexed field evidence should certify struct-array indexing"
    );
    let signature_certificate = analysis
        .type_facts
        .signature_certificate
        .as_ref()
        .expect("strong typed external signature should produce SignatureCertificate");
    assert!(
        signature_certificate
            .sources
            .contains(&SignatureCertificateSource::ExternalContext),
        "strong typed external signature certificate should record its source"
    );
}

#[test]
fn unresolved_named_pointer_materializes_local_struct_layout() {
    let mut parsed_context = demo_struct_pointer_context("obj");
    parsed_context.external_type_db.structs.insert(
        "demostruct".to_string(),
        ExternalStruct {
            name: "DemoStruct".to_string(),
            fields: BTreeMap::new(),
        },
    );

    let local_structs = LocalStructArtifacts {
        struct_decls: vec![StructDeclCandidate {
            name: "sla_struct_420703e08f70f00e".to_string(),
            decl: "struct sla_struct_420703e08f70f00e { int32_t f_0; int32_t f_c; };".to_string(),
            confidence: 95,
            source: StructDeclSource::LocalInferred,
            fields: vec![
                StructFieldCandidate {
                    name: "f_0".to_string(),
                    offset: 0,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
                StructFieldCandidate {
                    name: "f_c".to_string(),
                    offset: 12,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
            ],
        }],
        slot_type_overrides: HashMap::from([(
            0usize,
            "struct sla_struct_420703e08f70f00e *".to_string(),
        )]),
        slot_field_profiles: HashMap::from([(
            0usize,
            BTreeMap::from([
                (0u64, "int32_t".to_string()),
                (12u64, "int32_t".to_string()),
            ]),
        )]),
        slot_element_strides: HashMap::new(),
        indexed_accesses: Vec::new(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_demo_struct",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_demo_struct".to_string(),
            signature: "int32_t sym.test_demo_struct (void * obj)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "obj".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.params[0].param_type, "DemoStruct*");
    let layout = analysis
        .type_facts
        .external_type_db
        .structs
        .get("demostruct")
        .expect("unresolved signature type should receive inferred layout");
    assert_eq!(
        layout.fields.get(&0).map(|field| field.name.as_str()),
        Some("f_0")
    );
    assert_eq!(
        layout.fields.get(&12).map(|field| field.name.as_str()),
        Some("f_c")
    );
    assert_eq!(
        analysis
            .type_facts
            .slot_type_overrides
            .get(&0)
            .map(String::as_str),
        Some("struct DemoStruct *")
    );
    assert!(
        !analysis
            .type_facts
            .slot_type_overrides
            .values()
            .any(|ty| ty.contains("sla_struct_")),
        "unresolved named signature type should own the materialized layout"
    );
    assert_eq!(
        analysis.type_facts.array_index_certificates,
        vec![
            ArrayIndexCertificate {
                slot: 0,
                base: Some(ArrayIndexBase::Param { index: 0 }),
                field_offset: 0,
                element_stride: 16,
            },
            ArrayIndexCertificate {
                slot: 0,
                base: Some(ArrayIndexBase::Param { index: 0 }),
                field_offset: 12,
                element_stride: 16,
            },
        ],
        "materialized layout should keep struct-array indexing evidence"
    );
}

#[test]
fn local_struct_override_replaces_weak_generic_ptr_sized_integer_param() {
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: "arg1".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            }),
        }],
    };
    let parsed_context = ParsedExternalContext {
        current_signature: Some(current_signature.clone()),
        merged_signature: Some(current_signature),
        ..ParsedExternalContext::default()
    };

    let local_structs = LocalStructArtifacts {
        struct_decls: vec![StructDeclCandidate {
            name: "sla_struct_deadbeef".to_string(),
            decl: "struct sla_struct_deadbeef { int32_t f_8; int32_t f_34; };".to_string(),
            confidence: 95,
            source: StructDeclSource::LocalInferred,
            fields: vec![
                StructFieldCandidate {
                    name: "f_8".to_string(),
                    offset: 8,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
                StructFieldCandidate {
                    name: "f_34".to_string(),
                    offset: 52,
                    field_type: parse_test_type("int32_t", 64),
                    confidence: 95,
                },
            ],
        }],
        slot_type_overrides: HashMap::from([(0usize, "struct sla_struct_deadbeef *".to_string())]),
        slot_field_profiles: HashMap::from([(
            0usize,
            BTreeMap::from([
                (8u64, "int32_t".to_string()),
                (52u64, "int32_t".to_string()),
            ]),
        )]),
        slot_element_strides: HashMap::new(),
        indexed_accesses: Vec::new(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_struct_array_index",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_struct_array_index".to_string(),
            signature: "int32_t sym.test_struct_array_index (int64_t arg1)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                param_type: "int64_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        analysis
            .type_facts
            .slot_type_overrides
            .get(&0)
            .map(String::as_str),
        Some("struct sla_struct_deadbeef *")
    );
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.params.first())
            .and_then(|param| param.ty.as_ref()),
        Some(&CTypeLike::Pointer(Box::new(CTypeLike::Struct(
            "sla_struct_deadbeef".to_string(),
        ))))
    );
}

#[test]
fn indexed_local_struct_refinement_respects_signature_provenance() {
    let local_structs = LocalStructArtifacts {
        slot_type_overrides: HashMap::from([(0, "struct sla_struct_deadbeef *".to_string())]),
        slot_element_strides: HashMap::from([(0, 40)]),
        ..LocalStructArtifacts::default()
    };
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            }))),
        }],
    };
    let local_slots = indexed_local_struct_refinement_slots(
        &local_structs,
        &[SignatureCertificateSource::LocalInference],
        &HashSet::new(),
    );
    let external_slots = indexed_local_struct_refinement_slots(
        &local_structs,
        &[SignatureCertificateSource::ExternalContext],
        &HashSet::new(),
    );
    let assumption_protected_slots = indexed_local_struct_refinement_slots(
        &local_structs,
        &[
            SignatureCertificateSource::LocalInference,
            SignatureCertificateSource::TypeAssumption,
        ],
        &HashSet::from([0]),
    );

    let locally_refined = merge_slot_type_overrides_into_signature(
        Some(signature.clone()),
        &local_structs.slot_type_overrides,
        &local_slots,
        &ExternalTypeDb::default(),
        64,
        false,
    )
    .expect("local signature");
    let externally_protected = merge_slot_type_overrides_into_signature(
        Some(signature.clone()),
        &local_structs.slot_type_overrides,
        &external_slots,
        &ExternalTypeDb::default(),
        64,
        false,
    )
    .expect("external signature");

    assert_eq!(
        locally_refined.params[0].ty,
        Some(CTypeLike::Pointer(Box::new(CTypeLike::Struct(
            "sla_struct_deadbeef".to_string(),
        ))))
    );
    assert_eq!(externally_protected, signature);
    assert!(assumption_protected_slots.is_empty());
}

#[test]
fn local_field_access_certificates_derive_from_type_artifacts() {
    let mut local_structs = LocalStructArtifacts::default();
    local_structs
        .slot_field_profiles
        .insert(0, BTreeMap::from([(8, "int32_t".to_string())]));

    let accesses = local_field_accesses_from_struct_artifacts(&local_structs);
    assert_eq!(
        accesses,
        vec![LocalFieldAccessFact {
            slot: 0,
            field_offset: 8,
            field_name: "f_8".to_string(),
            field_type: Some("int32_t".to_string()),
        }]
    );

    let certificates = field_access_certificates_from_struct_artifacts(&local_structs);
    assert_eq!(
        certificates,
        vec![crate::FieldAccessCertificate {
            slot: 0,
            field_offset: 8,
            field_name: "f_8".to_string(),
            field_type: Some("int32_t".to_string()),
        }]
    );
}

#[test]
fn prepared_phi_preserves_recursive_struct_parameter_type() {
    let current = SSAVar::new("X0", 1, 8);
    let next = SSAVar::new("X0", 2, 8);
    let name = SSAVar::new("name", 1, 8);
    let len = SSAVar::new("len", 1, 2);
    let field_addr = |name: &str, version: u32, offset: u64| SSAOp::IntAdd {
        dst: SSAVar::new(name, version, 8),
        a: current.clone(),
        b: SSAVar::constant(offset, 8),
    };
    let blocks = [SSABlock {
        addr: 0x1000,
        phis: vec![PhiNode {
            dst: current.clone(),
            sources: vec![(0xff0, SSAVar::new("X0", 0, 8)), (0x1010, next.clone())],
            canonical_storage: None,
        }],
        ops: vec![
            field_addr("len_addr", 1, 6),
            SSAOp::Load {
                dst: len.clone(),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("len_addr", 1, 8),
            },
            SSAOp::IntZExt {
                dst: SSAVar::new("wide_len", 1, 8),
                src: len,
            },
            field_addr("name_addr", 1, 0x18),
            SSAOp::Load {
                dst: name.clone(),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("name_addr", 1, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("first_byte", 1, 1),
                space: r2il::SpaceId::Ram,
                addr: name,
            },
            field_addr("next_addr", 1, 0x20),
            SSAOp::Load {
                dst: next,
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("next_addr", 1, 8),
            },
        ],
        size: 0,
    }];
    let mut diagnostics = TypeAnalysisDiagnostics::default();

    let artifacts = infer_local_struct_artifacts_from_blocks(
        &blocks,
        None,
        Some("aarch64"),
        r2ssa::MachineArchitectureFamily::AArch64,
        &collect_pointer_arg_slot_map(r2ssa::MachineArchitectureFamily::AArch64, 64),
        64,
        &mut diagnostics,
    );

    let profile = artifacts
        .slot_field_profiles
        .get(&0)
        .expect("slot 0 profile");
    let struct_pointer = artifacts
        .slot_type_overrides
        .get(&0)
        .expect("slot 0 recursive struct pointer");
    assert_eq!(profile.get(&6).map(String::as_str), Some("uint16_t"));
    assert_eq!(profile.get(&0x18).map(String::as_str), Some("int8_t *"));
    assert_eq!(profile.get(&0x20), Some(struct_pointer));
    assert!(
        artifacts.struct_decls.iter().any(|decl| {
            decl.fields.iter().any(|field| {
                field.offset == 0x20 && field.field_type == parse_test_type(struct_pointer, 64)
            })
        }),
        "diagnostics={diagnostics:?}; artifacts={artifacts:?}"
    );
}

#[test]
fn local_struct_inference_uses_memory_ssa_for_spilled_element_pointer() {
    let entry = 0x100000548;
    let successor = 0x100000594;
    let stack_pointer = SSAVar::new("SP", 1, 8);
    let element = SSAVar::new("element", 1, 8);
    let blocks = [
        SSABlock {
            addr: entry,
            phis: Vec::new(),
            ops: vec![
                SSAOp::IntSub {
                    dst: stack_pointer.clone(),
                    a: SSAVar::new("SP", 0, 8),
                    b: SSAVar::constant(0x20, 8),
                },
                SSAOp::IntSExt {
                    dst: SSAVar::new("idx64", 1, 8),
                    src: SSAVar::new("W1", 0, 4),
                },
                SSAOp::IntMult {
                    dst: SSAVar::new("scaled", 1, 8),
                    a: SSAVar::new("idx64", 1, 8),
                    b: SSAVar::constant(0x28, 8),
                },
                SSAOp::IntAdd {
                    dst: element.clone(),
                    a: SSAVar::new("X0", 0, 8),
                    b: SSAVar::new("scaled", 1, 8),
                },
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr: stack_pointer.clone(),
                    val: element,
                },
                SSAOp::Load {
                    dst: SSAVar::new("element_reload", 1, 8),
                    space: r2il::SpaceId::Ram,
                    addr: stack_pointer.clone(),
                },
                SSAOp::IntAdd {
                    dst: SSAVar::new("score_addr", 1, 8),
                    a: SSAVar::new("element_reload", 1, 8),
                    b: SSAVar::constant(0x10, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("score", 1, 4),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("score_addr", 1, 8),
                },
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("score_addr", 1, 8),
                    val: SSAVar::new("W2", 0, 4),
                },
                SSAOp::IntAdd {
                    dst: SSAVar::new("flags_addr", 1, 8),
                    a: SSAVar::new("element_reload", 1, 8),
                    b: SSAVar::constant(4, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("flags", 1, 2),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("flags_addr", 1, 8),
                },
            ],
            size: 0,
        },
        SSABlock {
            addr: successor,
            phis: Vec::new(),
            ops: vec![
                SSAOp::Load {
                    dst: SSAVar::new("element_reload", 2, 8),
                    space: r2il::SpaceId::Ram,
                    addr: stack_pointer.clone(),
                },
                SSAOp::IntAdd {
                    dst: SSAVar::new("scores0_addr", 1, 8),
                    a: SSAVar::new("element_reload", 2, 8),
                    b: SSAVar::constant(8, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("scores0", 1, 4),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("scores0_addr", 1, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("element_reload", 3, 8),
                    space: r2il::SpaceId::Ram,
                    addr: stack_pointer.clone(),
                },
                SSAOp::IntAdd {
                    dst: SSAVar::new("len_addr", 1, 8),
                    a: SSAVar::new("element_reload", 3, 8),
                    b: SSAVar::constant(6, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("len", 1, 2),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("len_addr", 1, 8),
                },
                SSAOp::Load {
                    dst: SSAVar::new("element_reload", 4, 8),
                    space: r2il::SpaceId::Ram,
                    addr: stack_pointer,
                },
                SSAOp::Load {
                    dst: SSAVar::new("id", 1, 4),
                    space: r2il::SpaceId::Ram,
                    addr: SSAVar::new("element_reload", 4, 8),
                },
            ],
            size: 0,
        },
    ];
    let stack_version = MemoryVersion {
        object: r2ssa::ObjectId(1),
        version: 1,
    };
    let memory_versions = LocalMemoryVersionFacts {
        stores_by_site: HashMap::from([((entry, 4), vec![stack_version])]),
        loads_by_site: HashMap::from([
            ((entry, 5), vec![stack_version]),
            ((successor, 0), vec![stack_version]),
            ((successor, 3), vec![stack_version]),
            ((successor, 6), vec![stack_version]),
        ]),
        phi_inputs: HashMap::new(),
        value_ids: HashMap::from([(SSAVar::new("W1", 0, 4), r2ssa::ValueId(1))]),
    };
    let mut diagnostics = TypeAnalysisDiagnostics::default();

    let artifacts = infer_local_struct_artifacts_from_blocks(
        &blocks,
        Some(&memory_versions),
        Some("aarch64"),
        r2ssa::MachineArchitectureFamily::AArch64,
        &collect_pointer_arg_slot_map(r2ssa::MachineArchitectureFamily::AArch64, 64),
        64,
        &mut diagnostics,
    );

    assert_eq!(
        artifacts
            .slot_field_profiles
            .get(&0)
            .expect("spilled Item profile")
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 4, 6, 8, 0x10]),
        "diagnostics={diagnostics:?}"
    );
    assert_eq!(artifacts.slot_element_strides.get(&0), Some(&40));
    assert_eq!(artifacts.indexed_accesses.len(), 6);
    assert!(
        artifacts
            .indexed_accesses
            .iter()
            .all(|candidate| candidate.index_value == Some(r2ssa::ValueId(1)))
    );
}

#[test]
fn external_struct_pointer_strength_reduced_index_certifies_nested_array_fields() {
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.external_type_db.structs.insert(
        "item".to_string(),
        ExternalStruct {
            name: "Item".to_string(),
            fields: BTreeMap::from([
                (
                    0,
                    ExternalField {
                        name: "id".to_string(),
                        offset: 0,
                        ty: Some("int32_t".to_string()),
                    },
                ),
                (
                    4,
                    ExternalField {
                        name: "flags".to_string(),
                        offset: 4,
                        ty: Some("uint16_t".to_string()),
                    },
                ),
                (
                    6,
                    ExternalField {
                        name: "len".to_string(),
                        offset: 6,
                        ty: Some("uint16_t".to_string()),
                    },
                ),
                (
                    8,
                    ExternalField {
                        name: "scores".to_string(),
                        offset: 8,
                        ty: Some("int32_t[4]".to_string()),
                    },
                ),
                (
                    24,
                    ExternalField {
                        name: "name".to_string(),
                        offset: 24,
                        ty: Some("char *".to_string()),
                    },
                ),
                (
                    32,
                    ExternalField {
                        name: "next".to_string(),
                        offset: 32,
                        ty: Some("Item *".to_string()),
                    },
                ),
            ]),
        },
    );

    let ssa_blocks = [SSABlock {
        addr: 0x4012d0,
        size: 64,
        ops: vec![
            SSAOp::IntSExt {
                dst: SSAVar::new("RSI", 1, 8),
                src: SSAVar::new("ESI", 0, 4),
            },
            SSAOp::IntMult {
                dst: SSAVar::new("tmp:4900", 1, 8),
                a: SSAVar::new("RSI", 1, 8),
                b: SSAVar::constant(4, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:4a00", 1, 8),
                a: SSAVar::new("RSI", 1, 8),
                b: SSAVar::new("tmp:4900", 1, 8),
            },
            SSAOp::IntMult {
                dst: SSAVar::new("tmp:4900", 2, 8),
                a: SSAVar::new("tmp:4a00", 1, 8),
                b: SSAVar::constant(8, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("elem", 1, 8),
                a: SSAVar::new("RDI", 0, 8),
                b: SSAVar::new("tmp:4900", 2, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("scores2", 1, 8),
                a: SSAVar::new("elem", 1, 8),
                b: SSAVar::constant(0x10, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("score", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("scores2", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("flags", 1, 8),
                a: SSAVar::new("elem", 1, 8),
                b: SSAVar::constant(4, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("flagv", 1, 2),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("flags", 1, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("idv", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("elem", 1, 8),
            },
        ],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.struct_nested_array",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.struct_nested_array".to_string(),
            signature: "int32_t sym.struct_nested_array (Item * items, int32_t idx, int32_t add)"
                .to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "items".to_string(),
                    param_type: "Item *".to_string(),
                },
                InferredSignatureParam {
                    name: "idx".to_string(),
                    param_type: "int32_t".to_string(),
                },
                InferredSignatureParam {
                    name: "add".to_string(),
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
        analysis
            .type_facts
            .array_index_certificates
            .iter()
            .any(|cert| cert.element_stride == 40 && cert.field_offset == 0x10),
        "expected idx * sizeof(Item) proof for scores[2], got {:?}",
        analysis.type_facts.array_index_certificates
    );
    let certified_names = analysis
        .type_facts
        .field_access_certificates
        .iter()
        .map(|cert| cert.field_name.as_str())
        .collect::<BTreeSet<_>>();
    assert!(certified_names.contains("scores[2]"), "{certified_names:?}");
    assert!(certified_names.contains("flags"), "{certified_names:?}");
    assert!(certified_names.contains("id"), "{certified_names:?}");
    assert_eq!(
        analysis.type_facts.scalar_array_render_candidates,
        vec![
            ScalarArrayRenderCandidate {
                slot: 0,
                block_addr: 0x4012d0,
                op_index: 6,
                is_write: false,
                field_offset: 0x10,
                element_stride: 40,
                access_width: 4,
                index_value: None,
            },
            ScalarArrayRenderCandidate {
                slot: 0,
                block_addr: 0x4012d0,
                op_index: 8,
                is_write: false,
                field_offset: 4,
                element_stride: 40,
                access_width: 2,
                index_value: None,
            },
            ScalarArrayRenderCandidate {
                slot: 0,
                block_addr: 0x4012d0,
                op_index: 9,
                is_write: false,
                field_offset: 0,
                element_stride: 40,
                access_width: 4,
                index_value: None,
            },
        ],
        "render candidates must stay in deterministic op-site order"
    );
}

#[test]
fn stack_home_strength_reduced_index_certifies_struct_array_field_access() {
    let mut parsed_context = ParsedExternalContext::default();
    parsed_context.external_type_db.structs.insert(
        "demostruct".to_string(),
        ExternalStruct {
            name: "DemoStruct".to_string(),
            fields: BTreeMap::from([
                (
                    8,
                    ExternalField {
                        name: "third".to_string(),
                        offset: 8,
                        ty: Some("int32_t".to_string()),
                    },
                ),
                (
                    0x34,
                    ExternalField {
                        name: "fourteenth".to_string(),
                        offset: 0x34,
                        ty: Some("int32_t".to_string()),
                    },
                ),
            ]),
        },
    );
    let ssa_blocks = [SSABlock {
        addr: 0x401000,
        size: 64,
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("idx_addr", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff4, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("idx", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("idx_addr", 1, 8),
            },
            SSAOp::IntSExt {
                dst: SSAVar::new("idx64", 1, 8),
                src: SSAVar::new("idx", 1, 4),
            },
            SSAOp::IntLeft {
                dst: SSAVar::new("idx_x8", 1, 8),
                a: SSAVar::new("idx64", 1, 8),
                b: SSAVar::constant(3, 8),
            },
            SSAOp::IntSub {
                dst: SSAVar::new("idx_x7", 1, 8),
                a: SSAVar::new("idx_x8", 1, 8),
                b: SSAVar::new("idx64", 1, 8),
            },
            SSAOp::IntLeft {
                dst: SSAVar::new("idx_x56", 1, 8),
                a: SSAVar::new("idx_x7", 1, 8),
                b: SSAVar::constant(3, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("elem", 1, 8),
                a: SSAVar::new("RDI", 0, 8),
                b: SSAVar::new("idx_x56", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("field", 1, 8),
                a: SSAVar::new("elem", 1, 8),
                b: SSAVar::constant(0x34, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("value", 1, 4),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("field", 1, 8),
            },
        ],
        phis: Vec::new(),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.test_struct_array_index",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.test_struct_array_index".to_string(),
            signature:
                "int32_t sym.test_struct_array_index (DemoStruct * arr, int32_t idx, int32_t v)"
                    .to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arr".to_string(),
                    param_type: "DemoStruct *".to_string(),
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
                cert.slot == 0
                    && cert.element_stride == 56
                    && cert.field_offset == 0x34
                    && matches!(cert.base, Some(ArrayIndexBase::Param { index: 0 }))
            }),
        "expected stack-home strength-reduced idx * sizeof(DemoStruct) proof, got {:?}",
        analysis.type_facts.array_index_certificates
    );
    assert!(
        analysis
            .type_facts
            .field_access_certificates
            .iter()
            .any(|cert| cert.field_offset == 0x34 && cert.field_name == "fourteenth"),
        "expected external field certificate, got {:?}",
        analysis.type_facts.field_access_certificates
    );
    assert_eq!(
        analysis.type_facts.scalar_array_render_candidates,
        vec![ScalarArrayRenderCandidate {
            slot: 0,
            block_addr: 0x401000,
            op_index: 8,
            is_write: false,
            field_offset: 0x34,
            element_stride: 56,
            access_width: 4,
            index_value: None,
        }],
        "render candidate must preserve the concrete field load op identity"
    );
}

/// Parameter 0 points at a declared `Buffer { data, len }`; parameter 1 points at nothing declared.
fn buffer_then_undeclared_pointer() -> (r2il::ArchSpec, r2ssa::SourceFunctionInterface) {
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let mut arch = r2il::ArchSpec::new("aarch64");
    arch.addr_size = 8;
    arch.add_register(r2il::RegisterDef::new("x0", 0, 8));
    arch.add_register(r2il::RegisterDef::new("x1", 8, 8));
    arch.add_register(r2il::RegisterDef::new("sp", 16, 8));
    arch.add_register(r2il::RegisterDef::new("lr", 24, 8));
    let graph = r2ssa::SourceTypeGraph::new(
        [
            r2ssa::SourceType::new(
                0,
                r2ssa::SourceTypeKind::Struct { aggregate_id: 0 },
                16 * 8,
                64,
            ),
            r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::UnsignedInteger, 64, 64),
            r2ssa::SourceType::new(
                2,
                r2ssa::SourceTypeKind::Pointer { target_type_id: 0 },
                64,
                64,
            ),
        ],
        [r2ssa::SourceAggregateLayout::new(
            0,
            0,
            16 * 8,
            64,
            "Buffer",
            [
                r2ssa::SourceAggregateMember::new(0, 1, 0, 64, "data"),
                r2ssa::SourceAggregateMember::new(1, 1, 64, 64, "len"),
            ],
        )],
    )
    .expect("Buffer graph");
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"member-names-by-parameter".to_vec(),
        "aarch64",
        [
            r2ssa::SourceAbiParameterSpec::new(0, storage(0)),
            r2ssa::SourceAbiParameterSpec::new(1, storage(8)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
        [
            Some(r2ssa::SourceLogicalValue::new(
                2,
                r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
            )),
            None,
        ],
        None,
        Some(graph),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(24)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(16)))
    .expect("two-parameter interface");
    (arch, interface)
}

#[test]
fn a_source_member_name_reaches_only_its_own_parameter_s_fields() {
    // `len` is a member of what parameter 0 points at; parameter 1 points at an undeclared aggregate read at the same offset.
    let (arch, interface) = buffer_then_undeclared_pointer();
    let load = |dst, addr| r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(dst, 8),
        space: r2il::SpaceId::Ram,
        addr,
    };
    let add = |dst, base, offset| r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(dst, 8),
        a: r2il::Varnode::register(base, 8),
        b: r2il::Varnode::constant(offset, 8),
    };
    let block = r2il::R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            add(0x10, 0, 8),
            load(0x20, r2il::Varnode::unique(0x10, 8)),
            load(0x30, r2il::Varnode::register(8, 8)),
            add(0x40, 8, 8),
            load(0x50, r2il::Varnode::unique(0x40, 8)),
        ],
        switch_info: None,
        op_metadata: Default::default(),
    };
    let prepared =
        r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("prepared two-parameter function");
    let analysis = build_source_owned_type_analysis(
        TypeAnalysisRequest::new(Arc::new(prepared), ParsedExternalContext::default())
            .expect("coherent request"),
    )
    .expect("type analysis");
    let named = |slot, offset| {
        analysis
            .type_facts()
            .field_access_certificates
            .iter()
            .find(|certificate| certificate.slot == slot && certificate.field_offset == offset)
            .map(|certificate| certificate.field_name.clone())
    };
    assert_eq!(named(0, 8).as_deref(), Some("len"));
    assert_eq!(
        named(1, 8).as_deref(),
        Some("f_8"),
        "parameter 1's field took the name of parameter 0's member"
    );
}
