//! What the analysis proves about a function's signature.

use super::super::*;
use super::*;

#[test]
fn source_owned_enrichment_without_interface_claims_no_parameters() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("rax", 0, 8));
    let source = Arc::new(
        SsaArtifact::for_decompile(
            &[r2il::R2ILBlock::new(0x401800, 1)],
            Some(&r2ssa::Arch::from(arch.clone())),
        )
        .expect("prepared source without interface"),
    );
    let request = TypeAnalysisRequest::new(source, ParsedExternalContext::default())
        .expect("matching assumptions");
    // A source without an exact interface still yields an analysis: the
    // absence of an ABI is a fact about the source, not a failure. What it
    // must never do is invent the parameters it could not resolve.
    let analysis = build_source_owned_type_analysis(request)
        .expect("a source without an exact interface still yields an analysis");
    assert!(
        analysis
            .type_facts()
            .merged_signature
            .as_ref()
            .is_none_or(|signature| signature.params.is_empty()),
        "no interface must not produce parameters"
    );
}

#[test]
fn main_name_without_signature_evidence_does_not_fabricate_signature_output() {
    let parsed_context = ParsedExternalContext::default();
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary = r2ssa::FunctionSemanticSummary::unknown(root, Some("dbg.main".to_string()));
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            read: true,
            ..Default::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };
    let input = TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.main".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: Vec::new(),
        },
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    };
    let analysis = build_type_analysis(input);
    assert_eq!(spelled_ret(&spelled_signature(&analysis).ret_type), "void");
    assert!(
        spelled_signature(&analysis).params.is_empty(),
        "main name alone must not fabricate argc/argv/envp parameters"
    );
    assert!(
        analysis
            .type_facts
            .signature_certificate
            .as_ref()
            .is_none_or(|certificate| !certificate
                .sources
                .contains(&SignatureCertificateSource::ExternalContext)),
        "name-only main canonicalization must not create external-context authority"
    );
}

/// A function named `main` keeps the signature its source states: the name rewrites no parameter
/// type and adds no `envp` (D396, AGENTS 6).
#[test]
fn main_name_keeps_its_stated_signature() {
    let char_ptr = CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Signed,
    }));
    let stated = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::typedef("int")),
        params: vec![
            FunctionParamSpec {
                name: "argc".to_string(),
                ty: Some(char_ptr.clone()),
            },
            FunctionParamSpec {
                name: "argv".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(char_ptr.clone()))),
            },
        ],
    };
    let parsed_context = ParsedExternalContext {
        current_signature: Some(stated.clone()),
        merged_signature: Some(stated.clone()),
        ..ParsedExternalContext::default()
    };
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.main".to_string(),
            ret_type: None,
            params: Vec::new(),
        },
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });
    let merged = analysis
        .type_facts
        .merged_signature
        .as_ref()
        .expect("the stated signature");
    assert_eq!(merged.params.len(), 2, "no envp from the name");
    assert_eq!(
        merged.params[0].ty,
        Some(char_ptr),
        "argc keeps its stated type"
    );
}

/// A summary is no type basis: its `HeapAlloc` return leaves the body's own return type (D382).
#[test]
fn a_heap_alloc_summary_does_not_retype_a_scalar_return() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let summary_set = InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(
            root,
            FunctionSemanticSummary {
                schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
                id: root,
                name: Some("sym.alloc_wrapper".to_string()),
                linkage: r2ssa::FunctionSemanticLinkage::Unknown,
                arg_count_hint: Some(1),
                direct_callees: BTreeSet::from([0x5000]),
                callsite_count: 1,
                has_unknown_calls: false,
                arg_effects: BTreeMap::new(),
                memory_effects: Vec::new(),
                transfer_effects: Vec::new(),
                allocation_effects: Vec::new(),
                lifetime_effects: Vec::new(),
                sync_effects: Vec::new(),
                atomic_effects: Vec::new(),
                return_relation: SummaryReturnRelation::HeapAlloc,
                reads_global_memory: false,
                writes_global_memory: false,
                touches_unknown_memory: false,
            },
        )]),
        diagnostics: Default::default(),
    };
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_wrapper".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: Vec::new(),
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
}

/// A returned-argument summary retypes no return; the callee's facts still carry its effects.
#[test]
fn a_returned_arg_summary_does_not_retype_the_return() {
    let root = r2ssa::InterprocFunctionId(0x401100);
    let helper = r2ssa::InterprocFunctionId(0x401200);
    let summary_set = InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([
            (
                root,
                FunctionSemanticSummary {
                    schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
                    id: root,
                    name: Some("sym.identity".to_string()),
                    linkage: r2ssa::FunctionSemanticLinkage::Unknown,
                    arg_count_hint: Some(1),
                    direct_callees: BTreeSet::from([helper.0]),
                    callsite_count: 1,
                    has_unknown_calls: false,
                    arg_effects: BTreeMap::new(),
                    memory_effects: Vec::new(),
                    transfer_effects: Vec::new(),
                    allocation_effects: Vec::new(),
                    lifetime_effects: Vec::new(),
                    sync_effects: Vec::new(),
                    atomic_effects: Vec::new(),
                    return_relation: SummaryReturnRelation::Arg(0),
                    reads_global_memory: false,
                    writes_global_memory: false,
                    touches_unknown_memory: false,
                },
            ),
            (
                helper,
                FunctionSemanticSummary {
                    schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
                    id: helper,
                    name: Some("sym.helper".to_string()),
                    linkage: r2ssa::FunctionSemanticLinkage::Unknown,
                    arg_count_hint: Some(1),
                    direct_callees: BTreeSet::new(),
                    callsite_count: 0,
                    has_unknown_calls: false,
                    arg_effects: BTreeMap::from([(
                        0,
                        SummaryArgEffect {
                            read: true,
                            write: false,
                            escape: false,
                            free: false,
                            assumed: false,
                        },
                    )]),
                    memory_effects: Vec::new(),
                    transfer_effects: Vec::new(),
                    allocation_effects: Vec::new(),
                    lifetime_effects: Vec::new(),
                    sync_effects: Vec::new(),
                    atomic_effects: Vec::new(),
                    return_relation: SummaryReturnRelation::Arg(0),
                    reads_global_memory: false,
                    writes_global_memory: false,
                    touches_unknown_memory: false,
                },
            ),
        ]),
        diagnostics: Default::default(),
    };
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.identity".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: vec![InferredSignatureParam {
                name: "src".to_string(),
                ty: parse_test_type("char *", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
    let callee = analysis
        .type_facts
        .callee_facts
        .get(&helper.0)
        .expect("helper callee fact");
    assert_eq!(callee.name.as_deref(), Some("sym.helper"));
    assert!(callee.arg_effects.get(&0).is_some_and(|effect| effect.read));
    assert_eq!(callee.return_relation, CalleeReturnRelation::Arg(0));
}

#[test]
fn local_inferred_scalar_param_narrows_external_wide_signature() {
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: "arg1".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned,
            }),
        }],
    };
    let parsed_context = ParsedExternalContext {
        current_signature: Some(current_signature.clone()),
        merged_signature: Some(current_signature),
        ..ParsedExternalContext::default()
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym._check_secret".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                ty: parse_test_type("int32_t", 64),
            }],
        },
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled(&spelled_signature(&analysis).params[0].ty),
        "int32_t"
    );
    let merged = analysis
        .type_facts
        .merged_signature
        .as_ref()
        .expect("merged signature");
    assert_eq!(
        merged.params[0].ty,
        Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        })
    );
}

#[test]
fn exact_named_external_size_signature_blocks_local_byte_narrowing() {
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(typedef_type("size_t")),
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
                ty: Some(typedef_type("size_t")),
            },
            FunctionParamSpec {
                name: "a".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unsigned,
                }),
            },
            FunctionParamSpec {
                name: "b".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unsigned,
                }),
            },
        ],
    };
    let parsed_context = ParsedExternalContext {
        current_signature: Some(current_signature.clone()),
        merged_signature: Some(current_signature),
        ..ParsedExternalContext::default()
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.scan_example".to_string(),
            ret_type: Some(parse_test_type("uint8_t", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "buf".to_string(),
                    ty: parse_test_type("uint8_t*", 64),
                },
                InferredSignatureParam {
                    name: "n".to_string(),
                    ty: parse_test_type("uint8_t", 64),
                },
                InferredSignatureParam {
                    name: "a".to_string(),
                    ty: parse_test_type("uint8_t", 64),
                },
                InferredSignatureParam {
                    name: "b".to_string(),
                    ty: parse_test_type("uint8_t", 64),
                },
            ],
        },
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "size_t"
    );
    assert_eq!(spelled_signature(&analysis).params[1].name, "n");
    assert_eq!(
        spelled(&spelled_signature(&analysis).params[1].ty),
        "size_t"
    );
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.params.get(1))
            .and_then(|param| param.ty.clone()),
        Some(typedef_type("size_t"))
    );
}

#[test]
fn authoritative_external_signature_keeps_param_count_over_longer_local_signature() {
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Signed,
        }))),
        params: vec![
            FunctionParamSpec {
                name: "src".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Signed,
                }))),
            },
            FunctionParamSpec {
                name: "len".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Unsigned,
                }),
            },
        ],
    };
    let parsed_context = ParsedExternalContext {
        current_signature: Some(current_signature.clone()),
        merged_signature: Some(current_signature),
        ..ParsedExternalContext::default()
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_and_copy".to_string(),
            ret_type: Some(parse_test_type("int8_t *", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "src".to_string(),
                    ty: parse_test_type("int8_t *", 64),
                },
                InferredSignatureParam {
                    name: "len".to_string(),
                    ty: parse_test_type("uint8_t", 64),
                },
                InferredSignatureParam {
                    name: "arg3".to_string(),
                    ty: parse_test_type("int64_t", 64),
                },
                InferredSignatureParam {
                    name: "arg4".to_string(),
                    ty: parse_test_type("int64_t", 64),
                },
            ],
        },
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(spelled_signature(&analysis).params.len(), 2);
    assert_eq!(spelled_signature(&analysis).params[0].name, "src");
    assert_eq!(spelled_signature(&analysis).params[1].name, "len");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .expect("merged signature")
            .params
            .len(),
        2
    );
}

#[test]
fn generated_external_signature_allows_proven_local_param_extension() {
    let external = FunctionSignatureSpec {
        ret_type: Some(signed_int_type(64)),
        params: vec![FunctionParamSpec {
            name: "arg1".to_string(),
            ty: Some(signed_int_type(64)),
        }],
    };
    let local = FunctionSignatureSpec {
        ret_type: Some(signed_int_type(32)),
        params: vec![
            FunctionParamSpec {
                name: "arg0".to_string(),
                ty: Some(signed_int_type(64)),
            },
            FunctionParamSpec {
                name: "arg1".to_string(),
                ty: Some(signed_int_type(32)),
            },
        ],
    };

    let merged = merge_local_signature_into_merged_signature(Some(external), Some(local))
        .expect("merged signature");

    assert_eq!(merged.params.len(), 2);
    assert_eq!(merged.ret_type, Some(signed_int_type(32)));
}

#[test]
fn generated_external_carrier_param_yields_to_local_pointer_evidence() {
    let external = FunctionSignatureSpec {
        ret_type: Some(signed_int_type(64)),
        params: vec![FunctionParamSpec {
            name: "arg1".to_string(),
            ty: Some(signed_int_type(64)),
        }],
    };
    let pointer = CTypeLike::Pointer(Box::new(CTypeLike::Void));
    let local = FunctionSignatureSpec {
        ret_type: Some(signed_int_type(64)),
        params: vec![FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(pointer.clone()),
        }],
    };

    let merged = merge_local_signature_into_merged_signature(Some(external), Some(local))
        .expect("merged signature");

    assert_eq!(merged.params[0].ty, Some(pointer));
}

#[test]
fn generated_signed_defaults_yield_to_certified_unsigned_signature() {
    let unsigned = CTypeLike::Int {
        bits: 64,
        signedness: Signedness::Unsigned,
    };
    let external = FunctionSignatureSpec {
        ret_type: Some(signed_int_type(64)),
        params: vec![FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(signed_int_type(64)),
        }],
    };
    let local = FunctionSignatureSpec {
        ret_type: Some(unsigned.clone()),
        params: vec![FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(unsigned.clone()),
        }],
    };

    let merged = merge_local_signature_into_merged_signature(Some(external), Some(local))
        .expect("merged signature");

    assert_eq!(merged.ret_type, Some(unsigned.clone()));
    assert_eq!(merged.params[0].ty, Some(unsigned));
}

#[test]
fn inferred_signature_certificate_records_local_source() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.local_exact".to_string(),
            ret_type: Some(parse_test_type("int32_t", 64)),
            params: vec![InferredSignatureParam {
                name: "value".to_string(),
                ty: parse_test_type("int32_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let signature_certificate = analysis
        .type_facts
        .signature_certificate
        .as_ref()
        .expect("exact local inferred signature should carry a certificate");
    assert_eq!(
        signature_certificate.sources,
        vec![SignatureCertificateSource::LocalInference]
    );
}

#[test]
fn a_heap_alloc_summary_does_not_type_an_unknown_return() {
    let mut summary_set = r2ssa::InterprocSummarySet::default();
    let root = r2ssa::InterprocFunctionId(0x401000);
    summary_set.root = Some(root);
    summary_set.summaries.insert(
        root,
        r2ssa::FunctionSemanticSummary {
            schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
            id: root,
            name: Some("sym.alloc_wrapper".to_string()),
            linkage: r2ssa::FunctionSemanticLinkage::Unknown,
            arg_count_hint: Some(1),
            direct_callees: BTreeSet::new(),
            callsite_count: 1,
            has_unknown_calls: false,
            arg_effects: BTreeMap::new(),
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: r2ssa::SummaryReturnRelation::HeapAlloc,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        },
    );
    summary_set.diagnostics = r2ssa::InterprocSummaryDiagnostics {
        iterations: 2,
        max_iterations: 8,
        converged: true,
        scope_size: 1,
        scc_count: 1,
        max_scc_size: 1,
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_wrapper".to_string(),
            ret_type: Some(parse_test_type("unknown_t", 64)),
            params: vec![InferredSignatureParam {
                name: "n".to_string(),
                ty: parse_test_type("int64_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let returns =
        (analysis.type_facts.merged_signature.as_ref()).and_then(|sig| sig.ret_type.as_ref());
    assert_ne!(returns, Some(&CTypeLike::typedef("allocation_ptr")));
    assert_eq!(analysis.type_facts.interproc_diagnostics.scope_size, 1);
}

#[test]
fn a_void_return_summary_does_not_replace_the_inferred_return() {
    let mut summary_set = r2ssa::InterprocSummarySet::default();
    let root = r2ssa::InterprocFunctionId(0x401500);
    summary_set.root = Some(root);
    summary_set.summaries.insert(
        root,
        r2ssa::FunctionSemanticSummary {
            schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
            id: root,
            name: Some("sym.side_effect_worker".to_string()),
            linkage: r2ssa::FunctionSemanticLinkage::Unknown,
            arg_count_hint: Some(1),
            direct_callees: BTreeSet::new(),
            callsite_count: 0,
            has_unknown_calls: false,
            arg_effects: BTreeMap::new(),
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: r2ssa::SummaryReturnRelation::Void,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        },
    );

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.side_effect_worker".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                ty: parse_test_type("int64_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
}

#[test]
fn interproc_summary_name_does_not_project_role_out_param_type() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(root, Some("dbg.open_input_files".to_string()));
    summary.arg_count_hint = Some(3);
    summary.arg_effects.insert(
        2,
        r2ssa::SummaryArgEffect {
            read: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary.clone())]),
        diagnostics: Default::default(),
    };
    let projection = SemanticTypeProjection::from_inputs(
        &InterprocSummaryView::new(Some(summary_set)).expect("current interproc report schema"),
    );
    assert!(!projection.out_param_indices.contains(&2));

    summary.arg_effects.insert(
        2,
        r2ssa::SummaryArgEffect {
            write: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };
    let projection = SemanticTypeProjection::from_inputs(
        &InterprocSummaryView::new(Some(summary_set)).expect("current interproc report schema"),
    );

    assert!(projection.out_param_indices.contains(&2));
}

/// An argument only handed to a call nothing describes is assumed, not proven, read and written:
/// it is no pointer and no out parameter (D382).
#[test]
fn an_assumed_effect_is_no_pointer_or_out_param_evidence() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary = r2ssa::FunctionSemanticSummary::unknown(root, None);
    summary.arg_count_hint = Some(1);
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            assumed: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };
    let projection = SemanticTypeProjection::from_inputs(
        &InterprocSummaryView::new(Some(summary_set)).expect("current interproc report schema"),
    );
    assert!(!projection.out_param_indices.contains(&0));
}

#[test]
fn interproc_escape_only_does_not_certify_out_param() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(root, Some("sym.escape_user".to_string()));
    summary.arg_count_hint = Some(1);
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            escape: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };
    let projection = SemanticTypeProjection::from_inputs(
        &InterprocSummaryView::new(Some(summary_set.clone()))
            .expect("current interproc report schema"),
    );
    assert!(!projection.out_param_indices.contains(&0));
    assert!(!projection.out_param_evidence.contains_key(&0));

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.escape_user".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: vec![InferredSignatureParam {
                name: "p".to_string(),
                ty: parse_test_type("int64_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert!(
        analysis.type_facts.out_param_certificates.is_empty(),
        "escape proves pointer flow, not a type fact"
    );
}

#[test]
fn interproc_arg_write_out_param_certificate_records_write_evidence() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(root, Some("sym.write_user".to_string()));
    summary.arg_count_hint = Some(1);
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            write: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.write_user".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: vec![InferredSignatureParam {
                name: "out".to_string(),
                ty: parse_test_type("void *", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.type_facts.out_param_certificates.len(), 1);
    let cert = &analysis.type_facts.out_param_certificates[0];
    assert_eq!(cert.param_index, 0);
    assert_eq!(cert.param_name, "out");
    assert_eq!(cert.pointee_type.as_deref(), Some("void"));
    assert_eq!(
        cert.evidence,
        vec![OutParamCertificateEvidence::InterprocArgWrite]
    );
    assert_eq!(
        cert.sources,
        vec![OutParamCertificateSource::InterprocSummaryEffect {
            function_id: root.0,
            evidence: OutParamCertificateEvidence::InterprocArgWrite,
            param_index: 0,
            effect_index: 0,
        }]
    );
}

#[test]
fn interproc_memory_write_out_param_certificate_records_memory_write_evidence() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(root, Some("sym.write_user".to_string()));
    summary.arg_count_hint = Some(1);
    summary.memory_effects.push(r2ssa::SummaryMemoryEffect {
        kind: r2ssa::SummaryMemoryEffectKind::Write,
        location: r2ssa::SummaryMemoryLocation {
            region: r2ssa::SummaryMemoryRegion::Arg { index: 0 },
            range: Some(r2ssa::SummaryMemoryRange {
                offset_lo: 0,
                offset_hi: 3,
                width: Some(4),
                scaled_by: None,
            }),
        },
    });
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.write_user".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: vec![InferredSignatureParam {
                name: "out".to_string(),
                ty: parse_test_type("void *", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.type_facts.out_param_certificates.len(), 1);
    let cert = &analysis.type_facts.out_param_certificates[0];
    assert_eq!(cert.param_index, 0);
    assert_eq!(cert.param_name, "out");
    assert_eq!(
        cert.evidence,
        vec![OutParamCertificateEvidence::InterprocMemoryWrite]
    );
    assert_eq!(
        cert.sources,
        vec![OutParamCertificateSource::InterprocSummaryEffect {
            function_id: root.0,
            evidence: OutParamCertificateEvidence::InterprocMemoryWrite,
            param_index: 0,
            effect_index: 0,
        }]
    );
}

#[test]
fn interproc_summary_name_does_not_project_role_signature() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.limfield.isra.0".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: (0..3)
                .map(|idx| InferredSignatureParam {
                    name: format!("arg{}", idx + 1),
                    ty: parse_test_type("int64_t", 64),
                })
                .collect(),
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("limfield", Some(3))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
    // The merged signature names parameters from zero, as the rendering declares them.
    let names = spelled_signature(&analysis)
        .params
        .into_iter()
        .map(|param| param.name);
    assert_eq!(names.collect::<Vec<_>>(), ["arg0", "arg1", "arg2"]);
}

#[test]
fn semantic_role_signature_hint_does_not_truncate_named_authoritative_signature() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.printf_fetchargs".to_string(),
            ret_type: Some(parse_test_type("int32_t", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "parser".to_string(),
                    ty: parse_test_type("struct parser *", 64),
                },
                InferredSignatureParam {
                    name: "slot".to_string(),
                    ty: parse_test_type("struct slot *", 64),
                },
                InferredSignatureParam {
                    name: "flags".to_string(),
                    ty: parse_test_type("uint32_t", 64),
                },
            ],
        },
        parsed_context: ParsedExternalContext {
            merged_signature: Some(FunctionSignatureSpec {
                ret_type: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                params: vec![
                    FunctionParamSpec {
                        name: "parser".to_string(),
                        ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Struct(
                            "parser".to_string(),
                        )))),
                    },
                    FunctionParamSpec {
                        name: "slot".to_string(),
                        ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Struct(
                            "slot".to_string(),
                        )))),
                    },
                    FunctionParamSpec {
                        name: "flags".to_string(),
                        ty: Some(CTypeLike::Int {
                            bits: 32,
                            signedness: Signedness::Unsigned,
                        }),
                    },
                ],
            }),
            ..Default::default()
        },
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("sym.printf_fetchargs", None)),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(spelled_signature(&analysis).params.len(), 3);
    assert_eq!(spelled_signature(&analysis).params[0].name, "parser");
    assert_eq!(spelled_signature(&analysis).params[1].name, "slot");
    assert_eq!(spelled_signature(&analysis).params[2].name, "flags");
}

#[test]
fn interproc_summary_name_does_not_truncate_weak_entry_signature() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "entry.init0".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                ty: parse_test_type("void *", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("entry.init0", Some(1))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
    assert_eq!(spelled_signature(&analysis).params.len(), 1);
    assert_eq!(spelled_signature(&analysis).params[0].name, "arg0");
    assert_eq!(spelled(&spelled_signature(&analysis).params[0].ty), "void*");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|signature| signature.ret_type.as_ref()),
        Some(&CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        })
    );
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .map(|signature| signature.params.len()),
        Some(1)
    );
}

#[test]
fn interproc_summary_name_does_not_replace_weak_scalar_return() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.verror_at_line".to_string(),
            ret_type: Some(parse_test_type("int64_t", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "status".to_string(),
                    ty: parse_test_type("int", 64),
                },
                InferredSignatureParam {
                    name: "errnum".to_string(),
                    ty: parse_test_type("int", 64),
                },
                InferredSignatureParam {
                    name: "file_name".to_string(),
                    ty: parse_test_type("int8_t *", 64),
                },
                InferredSignatureParam {
                    name: "line_number".to_string(),
                    ty: parse_test_type("unsigned int", 64),
                },
                InferredSignatureParam {
                    name: "message".to_string(),
                    ty: parse_test_type("int8_t *", 64),
                },
                InferredSignatureParam {
                    name: "args".to_string(),
                    ty: parse_test_type("struct __va_list_tag *", 64),
                },
            ],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("dbg.verror_at_line", Some(6))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled_ret(&spelled_signature(&analysis).ret_type),
        "int64_t"
    );
    assert_eq!(spelled_signature(&analysis).params.len(), 6);
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|signature| signature.ret_type.as_ref()),
        Some(&CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        })
    );
}

#[test]
fn summary_to_callee_fact_does_not_infer_import_linkage_from_summary_name() {
    let summary = r2ssa::FunctionSemanticSummary {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        id: r2ssa::InterprocFunctionId(0x401080),
        name: Some("sym.imp.memcpy".to_string()),
        linkage: r2ssa::FunctionSemanticLinkage::Unknown,
        arg_count_hint: Some(3),
        direct_callees: BTreeSet::new(),
        callsite_count: 1,
        has_unknown_calls: false,
        arg_effects: BTreeMap::new(),
        memory_effects: Vec::new(),
        transfer_effects: Vec::new(),
        allocation_effects: Vec::new(),
        lifetime_effects: Vec::new(),
        sync_effects: Vec::new(),
        atomic_effects: Vec::new(),
        return_relation: r2ssa::SummaryReturnRelation::Unknown,
        reads_global_memory: false,
        writes_global_memory: false,
        touches_unknown_memory: false,
    };

    let fact = summary_to_callee_fact(&summary);

    assert_eq!(fact.name.as_deref(), Some("sym.imp.memcpy"));
    assert_eq!(fact.linkage, crate::CalleeLinkage::Unknown);
    assert!(
        !fact.linkage.authorizes_import_policy(),
        "summary names are not typed import-linkage evidence",
    );
    assert!(
        fact.authorizes_model_policy(),
        "interproc summaries are explicit model-policy evidence"
    );
}

#[test]
fn summary_to_callee_fact_exports_explicit_import_linkage() {
    let mut summary = r2ssa::FunctionSemanticSummary::unknown(
        r2ssa::InterprocFunctionId(0x401088),
        Some("memcpy".to_string()),
    );
    summary.linkage = r2ssa::FunctionSemanticLinkage::Imported;

    let fact = summary_to_callee_fact(&summary);

    assert_eq!(fact.name.as_deref(), Some("memcpy"));
    assert_eq!(fact.linkage, crate::CalleeLinkage::Imported);
    assert!(
        fact.linkage.authorizes_import_policy(),
        "only explicit summary linkage should certify imported-call policy",
    );
    assert!(
        fact.authorizes_model_policy(),
        "summary-derived callee facts should retain explicit model evidence"
    );
}

#[test]
fn interproc_returned_arg_summary_exports_callee_facts() {
    let mut summary_set = r2ssa::InterprocSummarySet::default();
    let root = r2ssa::InterprocFunctionId(0x401000);
    let helper = r2ssa::InterprocFunctionId(0x401080);
    summary_set.root = Some(root);
    summary_set.summaries.insert(
        root,
        r2ssa::FunctionSemanticSummary {
            schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
            id: root,
            name: Some("sym.wrapper_user".to_string()),
            linkage: r2ssa::FunctionSemanticLinkage::Unknown,
            arg_count_hint: Some(2),
            direct_callees: BTreeSet::from([helper.0]),
            callsite_count: 1,
            has_unknown_calls: false,
            arg_effects: BTreeMap::new(),
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: r2ssa::SummaryReturnRelation::Unknown,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        },
    );
    summary_set.summaries.insert(
        helper,
        r2ssa::FunctionSemanticSummary {
            schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
            id: helper,
            name: Some("sym.memcpy_like".to_string()),
            linkage: r2ssa::FunctionSemanticLinkage::Unknown,
            arg_count_hint: Some(2),
            direct_callees: BTreeSet::new(),
            callsite_count: 1,
            has_unknown_calls: false,
            arg_effects: BTreeMap::from([
                (
                    0,
                    r2ssa::SummaryArgEffect {
                        read: false,
                        write: true,
                        escape: true,
                        free: false,
                        assumed: false,
                    },
                ),
                (
                    1,
                    r2ssa::SummaryArgEffect {
                        read: true,
                        write: false,
                        escape: false,
                        free: false,
                        assumed: false,
                    },
                ),
            ]),
            memory_effects: vec![
                r2ssa::SummaryMemoryEffect {
                    kind: r2ssa::SummaryMemoryEffectKind::Write,
                    location: r2ssa::SummaryMemoryLocation {
                        region: r2ssa::SummaryMemoryRegion::Arg { index: 0 },
                        range: None,
                    },
                },
                r2ssa::SummaryMemoryEffect {
                    kind: r2ssa::SummaryMemoryEffectKind::Read,
                    location: r2ssa::SummaryMemoryLocation {
                        region: r2ssa::SummaryMemoryRegion::Arg { index: 1 },
                        range: None,
                    },
                },
            ],
            transfer_effects: vec![r2ssa::SummaryTransferEffect {
                dst: r2ssa::SummaryMemoryLocation {
                    region: r2ssa::SummaryMemoryRegion::Arg { index: 0 },
                    range: None,
                },
                src: r2ssa::SummaryMemoryLocation {
                    region: r2ssa::SummaryMemoryRegion::Arg { index: 1 },
                    range: None,
                },
                len: r2ssa::SummaryTransferLength::Arg(2),
            }],
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: r2ssa::SummaryReturnRelation::Arg(0),
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        },
    );

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.wrapper_user".to_string(),
            ret_type: Some(parse_test_type("void *", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "dst".to_string(),
                    ty: parse_test_type("void *", 64),
                },
                InferredSignatureParam {
                    name: "src".to_string(),
                    ty: parse_test_type("void *", 64),
                },
            ],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let helper_fact = analysis
        .type_facts
        .callee_facts
        .get(&helper.0)
        .expect("helper callee fact");
    assert_eq!(helper_fact.return_relation, CalleeReturnRelation::Arg(0));
    assert!(
        helper_fact
            .arg_effects
            .get(&0)
            .is_some_and(|effect| effect.write && effect.escape)
    );
    assert!(
        helper_fact
            .arg_effects
            .get(&1)
            .is_some_and(|effect| effect.read && !effect.write)
    );
    assert!(helper_fact.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            crate::facts::CalleeMemoryEffect {
                kind: crate::facts::CalleeMemoryEffectKind::Write,
                location: crate::facts::CalleeMemoryLocation {
                    region: crate::facts::CalleeMemoryRegion::Arg { index: 0 },
                    ..
                },
            }
        )
    }));
    assert!(helper_fact.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            crate::facts::CalleeMemoryEffect {
                kind: crate::facts::CalleeMemoryEffectKind::Read,
                location: crate::facts::CalleeMemoryLocation {
                    region: crate::facts::CalleeMemoryRegion::Arg { index: 1 },
                    ..
                },
            }
        )
    }));
    assert_eq!(
        helper_fact.transfer_effects,
        vec![crate::facts::CalleeTransferEffect {
            dst: crate::facts::CalleeMemoryLocation {
                region: crate::facts::CalleeMemoryRegion::Arg { index: 0 },
                range: None,
            },
            src: crate::facts::CalleeMemoryLocation {
                region: crate::facts::CalleeMemoryRegion::Arg { index: 1 },
                range: None,
            },
            len: crate::facts::CalleeTransferLength::Arg(2),
        }]
    );
}

#[test]
fn interproc_summary_name_does_not_export_role_callee_type_facts() {
    let root = r2ssa::InterprocFunctionId(0x402000);
    let helper = r2ssa::InterprocFunctionId(0x402080);
    let mut root_summary =
        r2ssa::FunctionSemanticSummary::unknown(root, Some("sym.sort_driver".to_string()));
    root_summary.direct_callees.insert(helper.0);
    let mut helper_summary =
        r2ssa::FunctionSemanticSummary::unknown(helper, Some("dbg.open_input_files".to_string()));
    helper_summary.arg_count_hint = Some(3);
    helper_summary.arg_effects.insert(
        2,
        SummaryArgEffect {
            write: true,
            ..SummaryArgEffect::default()
        },
    );
    let summary_set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, root_summary), (helper, helper_summary)]),
        diagnostics: Default::default(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.sort_driver".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: Vec::new(),
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let helper_fact = analysis
        .type_facts
        .callee_facts
        .get(&helper.0)
        .expect("helper callee fact");
    assert_eq!(helper_fact.return_type_hint, None);
    assert_eq!(helper_fact.param_type_hints.get(&0), None);
    assert_eq!(
        helper_fact.param_type_hints.get(&2),
        Some(&void_pointer_type())
    );
    assert!(
        helper_fact
            .arg_effects
            .get(&2)
            .is_some_and(|effect| effect.write && !effect.free)
    );
}

#[test]
fn interproc_summary_name_does_not_fabricate_callee_out_param_writes() {
    let helper = r2ssa::InterprocFunctionId(0x402080);
    let mut helper_summary =
        r2ssa::FunctionSemanticSummary::unknown(helper, Some("dbg.open_input_files".to_string()));
    helper_summary.arg_count_hint = Some(3);
    helper_summary.arg_effects.insert(
        2,
        r2ssa::SummaryArgEffect {
            read: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );

    let helper_fact = summary_to_callee_fact(&helper_summary);

    assert_eq!(
        helper_fact.param_type_hints.get(&2),
        Some(&void_pointer_type())
    );
    assert!(
        !helper_fact
            .arg_effects
            .get(&2)
            .is_some_and(|effect| effect.write)
    );
}

/// A summary's memory effect through a parameter retypes no parameter: the body's evidence types
/// a dereferenced one, and the summary is a second owner of that fact (D382).
#[test]
fn a_memory_effect_summary_does_not_retype_a_parameter() {
    let root = r2ssa::InterprocFunctionId(0x401300);
    let summary_set = InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(
            root,
            FunctionSemanticSummary {
                schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
                id: root,
                name: Some("sym.ptr_user".to_string()),
                linkage: r2ssa::FunctionSemanticLinkage::Unknown,
                arg_count_hint: Some(1),
                direct_callees: BTreeSet::new(),
                callsite_count: 0,
                has_unknown_calls: false,
                arg_effects: BTreeMap::from([(
                    0,
                    SummaryArgEffect {
                        read: true,
                        write: true,
                        escape: false,
                        free: false,
                        assumed: false,
                    },
                )]),
                memory_effects: vec![r2ssa::SummaryMemoryEffect {
                    kind: r2ssa::SummaryMemoryEffectKind::Write,
                    location: r2ssa::SummaryMemoryLocation {
                        region: r2ssa::SummaryMemoryRegion::Arg { index: 0 },
                        range: Some(r2ssa::SummaryMemoryRange {
                            offset_lo: 0,
                            offset_hi: 7,
                            width: Some(8),
                            scaled_by: None,
                        }),
                    },
                }],
                transfer_effects: Vec::new(),
                allocation_effects: Vec::new(),
                lifetime_effects: Vec::new(),
                sync_effects: Vec::new(),
                atomic_effects: Vec::new(),
                return_relation: SummaryReturnRelation::Void,
                reads_global_memory: false,
                writes_global_memory: false,
                touches_unknown_memory: false,
            },
        )]),
        diagnostics: Default::default(),
    };

    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.ptr_user".to_string(),
            ret_type: Some(parse_test_type("void", 64)),
            params: vec![InferredSignatureParam {
                name: "p".to_string(),
                ty: parse_test_type("int64_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        spelled(&spelled_signature(&analysis).params[0].ty),
        "int64_t"
    );
}
