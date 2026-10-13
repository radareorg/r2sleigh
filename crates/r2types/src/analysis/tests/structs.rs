//! What the analysis proves about aggregates.

use super::super::*;
use super::*;

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
            },
            StructFieldCandidate {
                name: "f_34".to_string(),
                offset: 0x34,
                field_type: parse_test_type("int32_t", 64),
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
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    // No external stack identity applies: `var_10h` keeps radare2's name and its own type.
    let binding = &analysis.type_facts.visible_bindings[0];
    let int32 = parse_test_type("int32_t", 64);
    assert_eq!(
        (binding.name.as_str(), binding.ty.as_ref()),
        ("var_10h", Some(&int32))
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
                },
                StructFieldCandidate {
                    name: "f_8".to_string(),
                    offset: 8,
                    field_type: parse_test_type("struct node *", 64),
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
                },
                StructFieldCandidate {
                    name: "f_34".to_string(),
                    offset: 0x34,
                    field_type: parse_test_type("int32_t", 64),
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
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_signature(&analysis).params[0].param_type,
        "DemoStruct*"
    );
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
                },
                StructFieldCandidate {
                    name: "f_c".to_string(),
                    offset: 12,
                    field_type: parse_test_type("int32_t", 64),
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
        parsed_context,
        local_structs,
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_signature(&analysis).params[0].param_type,
        "DemoStruct*"
    );
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
                },
                StructFieldCandidate {
                    name: "f_34".to_string(),
                    offset: 52,
                    field_type: parse_test_type("int32_t", 64),
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

/// Parameter 0 points at a declared `Buffer { data, len }`; parameter 1 is a
/// `void *`, which says it is a pointer and nothing about what it points at.
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
            r2ssa::SourceType::new(3, r2ssa::SourceTypeKind::Void, 0, 0),
            r2ssa::SourceType::new(
                4,
                r2ssa::SourceTypeKind::Pointer { target_type_id: 3 },
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
            Some(r2ssa::SourceLogicalValue::new(
                4,
                r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
            )),
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
        ..Default::default()
    };
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&r2ssa::Arch::from(arch)),
        interface,
    )
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
    assert_ne!(
        named(1, 8).as_deref(),
        Some("len"),
        "parameter 1's field took the name of parameter 0's member"
    );
}
