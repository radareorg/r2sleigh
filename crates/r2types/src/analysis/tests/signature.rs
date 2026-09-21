//! What the analysis proves about a function's signature.

use super::super::*;
use super::*;

#[test]
fn abi_register_params_cover_aarch64_as_well_as_sysv64() {
    // radare2 reports `arch="aarch64"` with the calling-convention field
    // left empty. Requiring a named convention meant arm64 functions got no
    // register parameters at all, which switched off the whole parameter
    // home machinery: no ParamHome slots, so no hidden-home bindings, so an
    // empty stack alias map, so frame accesses rendered as raw pointer
    // arithmetic instead of named locals.
    let signature = |arch: &str, callconv: &str| super::InferredSignature {
        function_name: "f".to_string(),
        signature: "int f(long a, long b, long c)".to_string(),
        ret_type: "int".to_string(),
        params: vec![
            super::InferredSignatureParam {
                name: "a".to_string(),
                param_type: "int64_t".to_string(),
            },
            super::InferredSignatureParam {
                name: "b".to_string(),
                param_type: "int64_t".to_string(),
            },
            super::InferredSignatureParam {
                name: "c".to_string(),
                param_type: "int64_t".to_string(),
            },
        ],
        callconv: callconv.to_string(),
        arch: arch.to_string(),
    };
    let regs = |arch: &str, callconv: &str| {
        super::inferred_signature_abi_register_params(&signature(arch, callconv), 64)
            .into_iter()
            .map(|param| param.reg)
            .collect::<Vec<_>>()
    };

    assert_eq!(regs("aarch64", ""), vec!["x0", "x1", "x2"]);
    assert_eq!(regs("arm64", "aapcs"), vec!["x0", "x1", "x2"]);
    assert_eq!(regs("x86-64", "amd64"), vec!["rdi", "rsi", "rdx"]);
    assert!(
        regs("mips", "").is_empty(),
        "an architecture with no table here still yields nothing"
    );
}

#[test]
fn source_owned_enrichment_without_interface_claims_no_parameters() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("rax", 0, 8));
    let source = Arc::new(
        SsaArtifact::for_decompile(&[r2il::R2ILBlock::new(0x401800, 1)], Some(&arch))
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
fn same_parameter_storage_follows_the_machine_not_the_spelling() {
    let x86 = x86_64_register_identity();

    // A low alias is the same parameter, at every width.
    assert!(x86.same_parameter_storage("rdi", "edi"));
    assert!(x86.same_parameter_storage("rdi", "dil"));
    assert!(x86.same_parameter_storage("rdi", "RDI"));

    // `dh` is a byte of `rdx` and is not the byte `rdx` is passed in. The
    // name table this replaced gave both the key "dx" and said yes, so an
    // externally supplied type assumption for `dh` was applied to the
    // `rdx` parameter and a stack slot was named after it.
    assert!(!x86.same_parameter_storage("rdx", "dh"));
    assert!(x86.same_parameter_storage("rdx", "dl"));
    assert!(!x86.same_parameter_storage("rax", "ah"));
    assert!(x86.same_parameter_storage("rax", "al"));

    // Different registers stay different however they are spelled.
    assert!(!x86.same_parameter_storage("rdi", "rdx"));
    assert!(!x86.same_parameter_storage("al", "dl"));
}

#[test]
fn same_parameter_storage_needs_no_per_architecture_table() {
    // The same predicate, with no arm64 case written anywhere: `w0` is the
    // low half of `x0`, and `s7` the low quarter of `v7`, because that is
    // where the machine puts them.
    let arm64 = register_identity_from(&[
        ("x0", 0x00, 8),
        ("w0", 0x00, 4),
        ("x8", 0x40, 8),
        ("w8", 0x40, 4),
        ("x29", 0xe8, 8),
        ("v7", 0x100, 16),
        ("d7", 0x100, 8),
        ("s7", 0x100, 4),
    ]);
    assert!(arm64.same_parameter_storage("x0", "w0"));
    assert!(arm64.same_parameter_storage("v7", "s7"));
    assert!(arm64.same_parameter_storage("v7", "d7"));
    assert!(!arm64.same_parameter_storage("x0", "w8"));

    // A name the machine does not declare is only ever itself.
    assert!(!arm64.same_parameter_storage("foo", "bar"));
    assert!(arm64.same_parameter_storage("foo", "FOO"));
    assert!(!arm64.same_parameter_storage("x0", "foo"));
}

#[test]
fn prepared_stack_roots_separate_arm64_param_homes_from_return_locals() {
    let home_addr = SSAVar::new("tmp:home", 1, 8);
    let return_addr = SSAVar::new("tmp:return", 1, 8);
    let ssa_blocks = [SSABlock {
        addr: 0x1000,
        size: 16,
        ops: vec![
            SSAOp::IntAdd {
                dst: home_addr.clone(),
                a: SSAVar::new("sp", 1, 8),
                b: SSAVar::constant(8, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: home_addr.clone(),
                val: SSAVar::new("w0", 0, 4),
            },
            SSAOp::IntAdd {
                dst: return_addr.clone(),
                a: SSAVar::new("sp", 1, 8),
                b: SSAVar::constant(12, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: return_addr.clone(),
                val: SSAVar::new("w8", 0, 4),
            },
        ],
        phis: Vec::new(),
    }];
    let prep_facts = r2ssa::DecompilePrepFacts {
        stack_address_roots: [
            (
                home_addr,
                r2ssa::StackAddressRoot {
                    base: r2ssa::StackAddressBase::StackPointer,
                    offset: -8,
                },
            ),
            (
                return_addr,
                r2ssa::StackAddressRoot {
                    base: r2ssa::StackAddressBase::StackPointer,
                    offset: -4,
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    };
    let mut stack_slots = [(-8, "var_8h"), (-4, "var_ch")]
        .into_iter()
        .map(|(offset, name)| {
            (
                StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset,
                },
                ExternalStackVarSpec {
                    name: name.to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                    role: ExternalStackSlotRole::Local,
                    param_index: None,
                    param_name: None,
                    source_reg: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let signature = test_signature_spec("arg0", 32);
    let register_params = [ExternalRegisterParamSpec {
        name: "arg0".to_string(),
        ty: signature.params[0].ty.clone(),
        reg: "x0".to_string(),
    }];

    canonicalize_param_home_stack_slots(
        Some(&signature),
        &register_params,
        &mut stack_slots,
        &ssa_blocks,
        Some(&prep_facts),
        &aarch64_register_identity(),
    );

    let home = stack_slots
        .get(&StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -8,
        })
        .expect("canonical parameter home");
    let return_local = stack_slots
        .get(&StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -4,
        })
        .expect("canonical return local");
    assert_eq!(home.role, ExternalStackSlotRole::ParamHome);
    assert_eq!(home.param_name.as_deref(), Some("arg0"));
    assert_eq!(return_local.role, ExternalStackSlotRole::Local);
    assert!(return_local.param_index.is_none());
    assert!(!stack_slots.keys().any(|slot| slot.offset > 0));
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
        function_name: "sym.main",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.main".to_string(),
            signature: "void sym.main ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    };
    let analysis = build_type_analysis(input);
    assert_eq!(analysis.signature.ret_type, "void");
    assert!(
        analysis.signature.params.is_empty(),
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

#[test]
fn user_type_hint_replaces_weak_pointer_sized_generic_arg() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("rdi-int32".to_string()),
            subject: r2ssa::AssumptionSubject::Register {
                name: "rdi".to_string(),
            },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "int32_t".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::User,
        }]),
        register_params: vec![crate::context::ExternalRegisterParamSpec {
            name: "arg1".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            }),
            reg: "EDI".to_string(),
        }],
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.demo".to_string(),
        signature: "int64_t sym.demo(int64_t)".to_string(),
        ret_type: "int64_t".to_string(),
        params: vec![InferredSignatureParam {
            name: "arg1".to_string(),
            param_type: "int64_t".to_string(),
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
    assert_eq!(inferred_signature.params[0].param_type, "int32_t");
    assert_eq!(
        render_signature_type(
            parsed_context.register_params[0]
                .ty
                .as_ref()
                .expect("register type"),
            64
        ),
        "int32_t"
    );
}

#[test]
fn interproc_heap_alloc_summary_upgrades_pointer_sized_scalar_return() {
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
        function_name: "sym.alloc_wrapper",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_wrapper".to_string(),
            signature: "int64_t sym.alloc_wrapper ()".to_string(),
            ret_type: "int64_t".to_string(),
            params: Vec::new(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "allocation_ptr");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.ret_type.clone()),
        Some(CTypeLike::typedef("allocation_ptr"))
    );
}

#[test]
fn interproc_returned_arg_summary_propagates_param_type_and_callee_facts() {
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
        function_name: "sym.identity",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.identity".to_string(),
            signature: "int64_t sym.identity (char * src)".to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "src".to_string(),
                param_type: "char *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "int8_t*");
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

    let vars = [RecoveredVariable {
        name: "arg0".to_string(),
        kind: "r".to_string(),
        delta: 0,
        var_type: "int32_t".to_string(),
        isarg: true,
        reg: Some("x0".to_string()),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym._check_secret",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym._check_secret".to_string(),
            signature: "int64_t sym._check_secret (int32_t arg1)".to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                param_type: "int32_t".to_string(),
            }],
            callconv: String::new(),
            arch: "aarch64".to_string(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.params[0].param_type, "int32_t");
    assert_eq!(
        analysis.plan.var_type_candidates[0].var_type,
        parse_test_type("int32_t", 64)
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
fn recovered_stack_arg_binds_to_canonical_signature_slot() {
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 64,
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

    let vars = [
        RecoveredVariable {
            name: "arg0".to_string(),
            kind: "r".to_string(),
            delta: 0,
            var_type: "int64_t".to_string(),
            isarg: true,
            reg: Some("rdi".to_string()),
        },
        RecoveredVariable {
            name: "arg6".to_string(),
            kind: "s".to_string(),
            delta: 8,
            var_type: "int64_t".to_string(),
            isarg: true,
            reg: None,
        },
    ];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.stack_arg",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.stack_arg".to_string(),
            signature: "int64_t sym.stack_arg (int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6)".to_string(),
            ret_type: "int64_t".to_string(),
            params: (0..7)
                .map(|slot| InferredSignatureParam {
                    name: format!("arg{slot}"),
                    param_type: "int64_t".to_string(),
                })
                .collect(),
            callconv: String::new(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let merged = analysis
        .type_facts
        .merged_signature
        .as_ref()
        .expect("merged signature");
    assert_eq!(merged.params.len(), 7);
    for idx in 1..6 {
        assert_eq!(
            merged.params[idx].ty,
            Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            })
        );
    }
    assert_eq!(merged.params[6].name, "arg6");
    assert_eq!(
        merged.params[6].ty,
        Some(CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        })
    );
    assert!(
        analysis.type_facts.visible_bindings.iter().any(|binding| {
            binding.name == "arg6"
                && binding.param_index == Some(6)
                && binding.stack_slot
                    == Some(StackSlotKey {
                        base: ExternalStackBase::StackPointer,
                        offset: 8,
                    })
        }),
        "recovered stack-arg binding should use the canonical C parameter name"
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

    let vars = [RecoveredVariable {
        name: "arg1".to_string(),
        kind: "r".to_string(),
        delta: 0,
        var_type: "uint8_t".to_string(),
        isarg: true,
        reg: Some("rsi".to_string()),
    }];

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "dbg.scan_example",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.scan_example".to_string(),
            signature: "uint8_t dbg.scan_example (uint8_t* buf, uint8_t n, uint8_t a, uint8_t b)"
                .to_string(),
            ret_type: "uint8_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "buf".to_string(),
                    param_type: "uint8_t*".to_string(),
                },
                InferredSignatureParam {
                    name: "n".to_string(),
                    param_type: "uint8_t".to_string(),
                },
                InferredSignatureParam {
                    name: "a".to_string(),
                    param_type: "uint8_t".to_string(),
                },
                InferredSignatureParam {
                    name: "b".to_string(),
                    param_type: "uint8_t".to_string(),
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

    assert_eq!(analysis.signature.ret_type, "size_t");
    assert_eq!(analysis.signature.params[1].name, "n");
    assert_eq!(analysis.signature.params[1].param_type, "size_t");
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
        function_name: "sym.alloc_and_copy",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_and_copy".to_string(),
            signature: "int8_t * sym.alloc_and_copy (int8_t * src, uint8_t len, int64_t arg3, int64_t arg4)".to_string(),
            ret_type: "int8_t *".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "src".to_string(),
                    param_type: "int8_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "len".to_string(),
                    param_type: "uint8_t".to_string(),
                },
                InferredSignatureParam {
                    name: "arg3".to_string(),
                    param_type: "int64_t".to_string(),
                },
                InferredSignatureParam {
                    name: "arg4".to_string(),
                    param_type: "int64_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.params.len(), 2);
    assert_eq!(analysis.signature.params[0].name, "src");
    assert_eq!(analysis.signature.params[1].name, "len");
    assert!(
        analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(|binding| matches!(binding.kind, VisibleBindingKind::Param)
                && binding.param_index == Some(0)
                && binding.name == "src"),
        "expected visible param binding for src, got {:?}",
        analysis.type_facts.visible_bindings
    );
    assert!(
        analysis
            .type_facts
            .visible_bindings
            .iter()
            .any(|binding| matches!(binding.kind, VisibleBindingKind::Param)
                && binding.param_index == Some(1)
                && binding.name == "len"),
        "expected visible param binding for len, got {:?}",
        analysis.type_facts.visible_bindings
    );
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
fn prepared_entry_store_roots_classify_unknown_param_homes() {
    let mut parsed_context = ParsedExternalContext {
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "arr".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
                },
                FunctionParamSpec {
                    name: "idx".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
                FunctionParamSpec {
                    name: "v".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
            ],
        }),
        register_params: vec![
            crate::context::ExternalRegisterParamSpec {
                name: "arg1".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
                reg: "rdi".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "arg2".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "rsi".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "arg3".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "rdx".to_string(),
            },
        ],
        ..Default::default()
    };
    for (offset, name) in [(-8, "arr"), (-12, "var_ch"), (-16, "var_10h")] {
        parsed_context.stack_slots.insert(
            StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            },
            ExternalStackVarSpec {
                name: name.to_string(),
                ty: None,
                role: ExternalStackSlotRole::Unknown,
                param_index: None,
                param_name: None,
                source_reg: None,
            },
        );
    }

    let ssa_blocks = [SSABlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff8, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 1, 8),
                val: SSAVar::new("RDI", 0, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 2, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff4, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 2, 8),
                val: SSAVar::new("ESI", 0, 4),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 3, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff0, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 3, 8),
                val: SSAVar::new("EDX", 0, 4),
            },
        ],
        phis: Vec::new(),
    }];

    let prep_facts = three_prepared_frame_slot_roots();
    let analysis = build_type_analysis_with_prep_facts(
        TypeAnalysisInput {
            function_name: "sym.test_struct_array_index",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym.test_struct_array_index".to_string(),
                signature:
                    "int32_t sym.test_struct_array_index(void * arr, int32_t idx, int32_t v)"
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
            recovered_vars: &[],
            ssa_blocks: &ssa_blocks,
            parsed_context,
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    for (offset, expected_name, expected_idx) in
        [(-8, "arr", 0usize), (-12, "idx", 1), (-16, "v", 2)]
    {
        let slot = analysis
            .type_facts
            .stack_slots
            .get(&StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            })
            .expect("canonicalized slot");
        assert_eq!(slot.role, ExternalStackSlotRole::ParamHome);
        assert_eq!(slot.param_index, Some(expected_idx));
        assert_eq!(slot.param_name.as_deref(), Some(expected_name));
    }
}

#[test]
fn prepared_roots_complete_partial_register_param_homes() {
    let mut parsed_context = ParsedExternalContext {
        register_params: vec![ExternalRegisterParamSpec {
            name: "arg0".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
            reg: "rdi".to_string(),
        }],
        stack_slots: BTreeMap::new(),
        ..Default::default()
    };
    for (offset, name, ty) in [
        (
            -8,
            "var_8h",
            CTypeLike::Pointer(Box::new(CTypeLike::Unknown)),
        ),
        (
            -12,
            "var_ch",
            CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            },
        ),
        (
            -16,
            "var_10h",
            CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            },
        ),
    ] {
        parsed_context.stack_slots.insert(
            StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            },
            ExternalStackVarSpec {
                name: name.to_string(),
                ty: Some(ty),
                role: ExternalStackSlotRole::Local,
                param_index: None,
                param_name: None,
                source_reg: None,
            },
        );
    }

    let ssa_blocks = [SSABlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff8, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 1, 8),
                val: SSAVar::new("RDI", 0, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 2, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff4, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 2, 8),
                val: SSAVar::new("ESI", 0, 4),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 3, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff0, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 3, 8),
                val: SSAVar::new("EDX", 0, 4),
            },
        ],
        phis: Vec::new(),
    }];
    let recovered_vars = [
        RecoveredVariable {
            name: "var_8h".to_string(),
            kind: "b".to_string(),
            delta: -8,
            var_type: "void *".to_string(),
            isarg: false,
            reg: None,
        },
        RecoveredVariable {
            name: "var_ch".to_string(),
            kind: "b".to_string(),
            delta: -12,
            var_type: "int32_t".to_string(),
            isarg: false,
            reg: None,
        },
        RecoveredVariable {
            name: "var_10h".to_string(),
            kind: "b".to_string(),
            delta: -16,
            var_type: "int32_t".to_string(),
            isarg: false,
            reg: None,
        },
    ];

    let prep_facts = three_prepared_frame_slot_roots();
    let analysis = build_type_analysis_with_prep_facts(
        TypeAnalysisInput {
            function_name: "sym.test_struct_array_index",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym.test_struct_array_index".to_string(),
                signature:
                    "int32_t sym.test_struct_array_index(DemoStruct * arr, int32_t idx, int32_t v)"
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
            recovered_vars: &recovered_vars,
            ssa_blocks: &ssa_blocks,
            parsed_context,
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    for (offset, expected_name, expected_idx) in
        [(-8, "arr", 0usize), (-12, "idx", 1), (-16, "v", 2)]
    {
        let slot = analysis
            .type_facts
            .stack_slots
            .get(&StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            })
            .expect("ABI-derived param-home slot");
        assert_eq!(slot.role, ExternalStackSlotRole::ParamHome);
        assert_eq!(slot.param_index, Some(expected_idx));
        assert_eq!(slot.param_name.as_deref(), Some(expected_name));
    }
    assert!(
        analysis.plan.var_type_candidates.is_empty(),
        "ABI-derived parameter homes must not surface as visible local type writes: {:?}",
        analysis.plan.var_type_candidates
    );
    assert!(
        analysis.plan.var_rename_candidates.is_empty(),
        "ABI-derived parameter homes must not surface as visible local renames: {:?}",
        analysis.plan.var_rename_candidates
    );
}

#[test]
fn prepared_entry_store_copy_roots_classify_unknown_param_homes() {
    let mut parsed_context = ParsedExternalContext {
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "arr".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
                },
                FunctionParamSpec {
                    name: "idx".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
                FunctionParamSpec {
                    name: "v".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: Signedness::Signed,
                    }),
                },
            ],
        }),
        register_params: vec![
            crate::context::ExternalRegisterParamSpec {
                name: "arg1".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
                reg: "rdi".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "arg2".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "rsi".to_string(),
            },
            crate::context::ExternalRegisterParamSpec {
                name: "arg3".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                }),
                reg: "rdx".to_string(),
            },
        ],
        ..Default::default()
    };
    for (offset, name) in [(-8, "arr"), (-12, "var_ch"), (-16, "var_10h")] {
        parsed_context.stack_slots.insert(
            StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            },
            ExternalStackVarSpec {
                name: name.to_string(),
                ty: None,
                role: ExternalStackSlotRole::Unknown,
                param_index: None,
                param_name: None,
                source_reg: None,
            },
        );
    }

    let ssa_blocks = [SSABlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 1, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff8, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("tmp:spill_arr", 1, 8),
                src: SSAVar::new("RDI", 0, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 1, 8),
                val: SSAVar::new("tmp:spill_arr", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 2, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff4, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("tmp:spill_idx", 1, 4),
                src: SSAVar::new("ESI", 0, 4),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 2, 8),
                val: SSAVar::new("tmp:spill_idx", 1, 4),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("tmp:slot", 3, 8),
                a: SSAVar::new("RBP", 1, 8),
                b: SSAVar::constant(0xffff_ffff_ffff_fff0, 8),
            },
            SSAOp::Copy {
                dst: SSAVar::new("tmp:spill_v", 1, 4),
                src: SSAVar::new("EDX", 0, 4),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("tmp:slot", 3, 8),
                val: SSAVar::new("tmp:spill_v", 1, 4),
            },
        ],
        phis: Vec::new(),
    }];

    let prep_facts = three_prepared_frame_slot_roots();
    let analysis = build_type_analysis_with_prep_facts(
        TypeAnalysisInput {
            function_name: "sym.test_struct_array_index",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym.test_struct_array_index".to_string(),
                signature:
                    "int32_t sym.test_struct_array_index(void * arr, int32_t idx, int32_t v)"
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
            recovered_vars: &[],
            ssa_blocks: &ssa_blocks,
            parsed_context,
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &prep_facts,
    );

    for (offset, expected_name, expected_idx) in
        [(-8, "arr", 0usize), (-12, "idx", 1), (-16, "v", 2)]
    {
        let slot = analysis
            .type_facts
            .stack_slots
            .get(&StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset,
            })
            .expect("canonicalized slot");
        assert_eq!(slot.role, ExternalStackSlotRole::ParamHome);
        assert_eq!(slot.param_index, Some(expected_idx));
        assert_eq!(slot.param_name.as_deref(), Some(expected_name));
    }
}

#[test]
fn inferred_signature_certificate_records_local_source() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.local_exact",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.local_exact".to_string(),
            signature: "int32_t sym.local_exact (int32_t value)".to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "value".to_string(),
                param_type: "int32_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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
fn stack_local_type_assumption_does_not_claim_signature_authority() {
    let stack_assumption = r2ssa::AnalysisAssumption {
        id: None,
        subject: r2ssa::AssumptionSubject::StackSlot {
            base: r2ssa::StackAddressBase::StackPointer,
            offset: -8,
        },
        value: r2ssa::AssumptionValue::TypeHint {
            ty: "int64_t".to_string(),
        },
        scope: r2ssa::AssumptionScope::Function,
        provenance: r2ssa::AssumptionProvenance::ImportedContext,
    };
    let mut usage = r2ssa::AssumptionUsageReport {
        applied: vec![stack_assumption],
        ..Default::default()
    };
    let context = ParsedExternalContext::default();

    assert!(
        applied_type_assumption_parameter_slots(&usage, &context, &x86_64_register_identity())
            .is_empty()
    );

    usage.applied.push(r2ssa::AnalysisAssumption {
        id: None,
        subject: r2ssa::AssumptionSubject::Parameter { index: 1 },
        value: r2ssa::AssumptionValue::TypeHint {
            ty: "uint64_t".to_string(),
        },
        scope: r2ssa::AssumptionScope::Function,
        provenance: r2ssa::AssumptionProvenance::ImportedContext,
    });
    assert_eq!(
        applied_type_assumption_parameter_slots(&usage, &context, &x86_64_register_identity()),
        HashSet::from([1])
    );
}

#[test]
fn interproc_heap_alloc_summary_upgrades_generic_return_type() {
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
        function_name: "sym.alloc_wrapper",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.alloc_wrapper".to_string(),
            signature: "void * sym.alloc_wrapper (int64_t n)".to_string(),
            ret_type: "unknown_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "n".to_string(),
                param_type: "int64_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.ret_type.as_ref()),
        Some(&CTypeLike::typedef("allocation_ptr"))
    );
    assert_eq!(analysis.type_facts.interproc_diagnostics.scope_size, 1);
}

#[test]
fn interproc_void_return_summary_replaces_weak_scalar_return_type() {
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
        function_name: "sym.side_effect_worker",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.side_effect_worker".to_string(),
            signature: "int64_t sym.side_effect_worker (int64_t arg1)".to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                param_type: "int64_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "void");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.ret_type.as_ref()),
        Some(&CTypeLike::Void)
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

    assert!(!projection.param_type_hints.contains_key(&2));
    assert!(projection.pointer_param_indices.contains(&2));
    assert!(!projection.out_param_indices.contains(&2));
    assert!(projection.refusal_warnings().is_empty());

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
    assert!(!projection.param_type_hints.contains_key(&2));
    assert!(projection.refusal_warnings().is_empty());
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

    assert!(projection.pointer_param_indices.contains(&0));
    assert!(!projection.out_param_indices.contains(&0));
    assert!(!projection.out_param_evidence.contains_key(&0));

    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.escape_user",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.escape_user".to_string(),
            signature: "void sym.escape_user (int64_t p)".to_string(),
            ret_type: "void".to_string(),
            params: vec![InferredSignatureParam {
                name: "p".to_string(),
                param_type: "int64_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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
        function_name: "sym.write_user",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.write_user".to_string(),
            signature: "void sym.write_user (void *out)".to_string(),
            ret_type: "void".to_string(),
            params: vec![InferredSignatureParam {
                name: "out".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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
        function_name: "sym.write_user",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.write_user".to_string(),
            signature: "void sym.write_user (void *out)".to_string(),
            ret_type: "void".to_string(),
            params: vec![InferredSignatureParam {
                name: "out".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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
        function_name: "sym.limfield.isra.0",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.limfield.isra.0".to_string(),
            signature: "int64_t sym.limfield.isra.0(int64_t arg1, int64_t arg2, int64_t arg3)"
                .to_string(),
            ret_type: "int64_t".to_string(),
            params: (0..3)
                .map(|idx| InferredSignatureParam {
                    name: format!("arg{}", idx + 1),
                    param_type: "int64_t".to_string(),
                })
                .collect(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("limfield", Some(3))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "int64_t");
    assert_eq!(analysis.signature.params.len(), 3);
    assert_eq!(analysis.signature.params[0].name, "arg1");
    assert_eq!(analysis.signature.params[1].name, "arg2");
    assert_eq!(analysis.signature.params[2].name, "arg3");
}

#[test]
fn semantic_role_signature_hint_does_not_truncate_named_authoritative_signature() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.printf_fetchargs",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.printf_fetchargs".to_string(),
            signature: "int32_t sym.printf_fetchargs (struct parser *parser, struct slot *slot, uint32_t flags)"
                .to_string(),
            ret_type: "int32_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "parser".to_string(),
                    param_type: "struct parser *".to_string(),
                },
                InferredSignatureParam {
                    name: "slot".to_string(),
                    param_type: "struct slot *".to_string(),
                },
                InferredSignatureParam {
                    name: "flags".to_string(),
                    param_type: "uint32_t".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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

    assert_eq!(analysis.signature.params.len(), 3);
    assert_eq!(analysis.signature.params[0].name, "parser");
    assert_eq!(analysis.signature.params[1].name, "slot");
    assert_eq!(analysis.signature.params[2].name, "flags");
}

#[test]
fn interproc_summary_name_does_not_truncate_weak_entry_signature() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "entry.init0",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "entry.init0".to_string(),
            signature: "int64_t entry.init0(void *arg1)".to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                param_type: "void *".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("entry.init0", Some(1))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "int64_t");
    assert_eq!(analysis.signature.params.len(), 1);
    assert_eq!(analysis.signature.params[0].name, "arg1");
    assert_eq!(analysis.signature.params[0].param_type, "void *");
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
        function_name: "dbg.verror_at_line",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.verror_at_line".to_string(),
            signature:
                "int64_t dbg.verror_at_line(int status, int errnum, int8_t *file_name, unsigned int line_number, int8_t *message, struct __va_list_tag *args)"
                    .to_string(),
            ret_type: "int64_t".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "status".to_string(),
                    param_type: "int".to_string(),
                },
                InferredSignatureParam {
                    name: "errnum".to_string(),
                    param_type: "int".to_string(),
                },
                InferredSignatureParam {
                    name: "file_name".to_string(),
                    param_type: "int8_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "line_number".to_string(),
                    param_type: "unsigned int".to_string(),
                },
                InferredSignatureParam {
                    name: "message".to_string(),
                    param_type: "int8_t *".to_string(),
                },
                InferredSignatureParam {
                    name: "args".to_string(),
                    param_type: "struct __va_list_tag *".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(semantic_role_summary_set("dbg.verror_at_line", Some(6))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.ret_type, "int64_t");
    assert_eq!(analysis.signature.params.len(), 6);
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
fn weak_summary_kind_projection_does_not_widen_authoritative_anonymous_signature() {
    let mut facts = FunctionTypeFacts {
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Void),
            params: vec![
                FunctionParamSpec {
                    name: "dst".to_string(),
                    ty: Some(void_pointer_type()),
                },
                FunctionParamSpec {
                    name: "src".to_string(),
                    ty: Some(void_pointer_type()),
                },
            ],
        }),
        ..FunctionTypeFacts::default()
    };
    let projected = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Void),
        params: vec![
            FunctionParamSpec {
                name: "dst".to_string(),
                ty: Some(void_pointer_type()),
            },
            FunctionParamSpec {
                name: "src".to_string(),
                ty: Some(void_pointer_type()),
            },
            FunctionParamSpec {
                name: "len".to_string(),
                ty: Some(typedef_type("size_t")),
            },
        ],
    };

    let result = facts.apply_signature_projection(
        "fcn.0000a200",
        FunctionSignatureProjection::weak_summary_kind(projected),
        64,
    );

    assert!(result.rejected.is_some());
    assert_eq!(
        facts
            .merged_signature
            .as_ref()
            .map(|signature| signature.params.len()),
        Some(2)
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
                    },
                ),
                (
                    1,
                    r2ssa::SummaryArgEffect {
                        read: true,
                        write: false,
                        escape: false,
                        free: false,
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
        function_name: "sym.wrapper_user",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.wrapper_user".to_string(),
            signature: "void * sym.wrapper_user (void * dst, void * src)".to_string(),
            ret_type: "void *".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "dst".to_string(),
                    param_type: "void *".to_string(),
                },
                InferredSignatureParam {
                    name: "src".to_string(),
                    param_type: "void *".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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
        function_name: "sym.sort_driver",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.sort_driver".to_string(),
            signature: "void sym.sort_driver(void)".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
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

#[test]
fn interproc_memory_effect_summary_upgrades_generic_pointer_like_params() {
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
        function_name: "sym.ptr_user",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.ptr_user".to_string(),
            signature: "void sym.ptr_user (int64_t p)".to_string(),
            ret_type: "void".to_string(),
            params: vec![InferredSignatureParam {
                name: "p".to_string(),
                param_type: "int64_t".to_string(),
            }],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        ssa_blocks: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: Some(summary_set),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(analysis.signature.params[0].param_type, "void*");
    assert_eq!(
        analysis
            .type_facts
            .merged_signature
            .as_ref()
            .and_then(|sig| sig.params.first())
            .and_then(|param| param.ty.as_ref()),
        Some(&CTypeLike::Pointer(Box::new(CTypeLike::Void)))
    );
}

#[test]
fn prepared_phi_refuses_conflicting_parameter_type_classes() {
    let merged = SSAVar::new("X0", 1, 8);
    let blocks = [SSABlock {
        addr: 0x1000,
        phis: vec![PhiNode {
            dst: merged.clone(),
            sources: vec![
                (0xff0, SSAVar::new("X0", 0, 8)),
                (0xff4, SSAVar::new("X1", 0, 8)),
            ],
            canonical_storage: None,
        }],
        ops: vec![
            SSAOp::IntAdd {
                dst: SSAVar::new("field0", 1, 8),
                a: merged.clone(),
                b: SSAVar::constant(0, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("value0", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("field0", 1, 8),
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("field8", 1, 8),
                a: merged,
                b: SSAVar::constant(8, 8),
            },
            SSAOp::Load {
                dst: SSAVar::new("value8", 1, 8),
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("field8", 1, 8),
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

    assert!(artifacts.slot_field_profiles.is_empty());
    assert!(artifacts.slot_type_overrides.is_empty());
}
