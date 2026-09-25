use super::*;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};

fn register_assumption(id: &str, name: &str, value: u64) -> r2ssa::AnalysisAssumption {
    r2ssa::AnalysisAssumption {
        id: Some(id.to_string()),
        subject: r2ssa::AssumptionSubject::Register {
            name: name.to_string(),
        },
        value: r2ssa::AssumptionValue::Constant { value },
        scope: r2ssa::AssumptionScope::Query,
        provenance: r2ssa::AssumptionProvenance::User,
    }
}

fn test_decompile_route(
    kind: r2types::DecompileRouteKind,
    reason: Option<&str>,
    fallback_comment: Option<&str>,
) -> r2types::DecompileRouteFacts {
    r2types::DecompileRouteFacts {
        kind,
        reason: reason.map(str::to_string),
        fallback_comment: fallback_comment.map(str::to_string),
        use_prepared_semantic_view: kind == r2types::DecompileRouteKind::Standard,
    }
}

fn const_return_blocks(addr: u64, value: u64) -> Vec<R2ILBlock> {
    let mut block = R2ILBlock::new(addr, 4);
    block.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::constant(value, 8),
    });
    vec![block]
}

fn test_source_snapshot(revision: &str) -> Arc<EngineSourceSnapshot> {
    Arc::new(
        EngineSourceSnapshot::new(revision.as_bytes().to_vec(), None, Vec::new())
            .expect("test source snapshot"),
    )
}

fn exact_empty_test_source_snapshot(revision: &str) -> Arc<EngineSourceSnapshot> {
    let revision_identity = revision.as_bytes().to_vec();
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        revision_identity.clone(),
        "sysv64",
        std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
        r2ssa::SourceFunctionReturn::Void,
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|interface| {
        interface.with_stack_pointer_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x28,
            size: 8,
        })
    })
    .and_then(|interface| {
        interface.with_return_address_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x30,
            size: 8,
        })
    })
    .expect("exact empty test interface");
    Arc::new(
        EngineSourceSnapshot::new(revision_identity, Some(interface), Vec::new())
            .expect("exact empty test source snapshot"),
    )
}

fn exact_rdi_test_source_snapshot(revision: &str) -> Arc<EngineSourceSnapshot> {
    let revision_identity = revision.as_bytes().to_vec();
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        revision_identity.clone(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(
            0,
            r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0x10,
                size: 8,
            },
        )],
        r2ssa::SourceFunctionReturn::Void,
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|interface| {
        interface.with_stack_pointer_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x28,
            size: 8,
        })
    })
    .and_then(|interface| {
        interface.with_return_address_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x30,
            size: 8,
        })
    })
    .expect("exact RDI test interface");
    Arc::new(
        EngineSourceSnapshot::new(revision_identity, Some(interface), Vec::new())
            .expect("exact RDI test source snapshot"),
    )
}

fn direct_call_return_blocks(addr: u64, target: u64) -> Vec<R2ILBlock> {
    let mut block = R2ILBlock::new(addr, 4);
    block.push(r2il::R2ILOp::Call {
        target: r2il::Varnode::constant(target, 8),
    });
    block.stamp_instruction(0, addr);
    block.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::constant(0, 8),
    });
    vec![block]
}

fn source_snapshot_call_interface(
    revision_identity: &[u8],
    block_addr: u64,
    op_index: usize,
    target: u64,
) -> r2ssa::SourceCallSiteInterface {
    // Test transfers are lifted from instruction `block_addr + op_index`.
    r2ssa::SourceCallSiteInterface::new(
        revision_identity.to_vec(),
        r2ssa::SourceCallSiteIdentity::new(
            block_addr + op_index as u64,
            r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Constant,
                offset: target,
                size: 8,
            },
        ),
        true,
        "sysv",
        Vec::<r2ssa::SourceCallArgumentSpec>::new(),
        false,
        false,
        r2ssa::SourceCallResult::Void,
    )
    .expect("source callsite interface")
}

fn source_snapshot_function_interface(revision_identity: &[u8]) -> r2ssa::SourceFunctionInterface {
    r2ssa::SourceFunctionInterface::new(
        revision_identity.to_vec(),
        "sysv",
        Vec::<r2ssa::SourceAbiParameterSpec>::new(),
        r2ssa::SourceFunctionReturn::Register {
            storage: r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        },
        Vec::<r2ssa::SourceStackSlotSpec>::new(),
    )
    .expect("source function interface")
}

#[test]
fn engine_source_snapshot_preserves_exact_ordered_interfaces() {
    let revision = b"source-revision-1";
    let function_interface = source_snapshot_function_interface(revision);
    let first = source_snapshot_call_interface(revision, 0x401000, 1, 0x5000);
    let second = source_snapshot_call_interface(revision, 0x401000, 3, 0x6000);

    let snapshot = EngineSourceSnapshot::new(
        revision.to_vec(),
        Some(function_interface.clone()),
        vec![second.clone(), first.clone()],
    )
    .expect("coherent source snapshot");

    assert_eq!(snapshot.revision_identity(), revision);
    assert_eq!(snapshot.function_interface(), Some(&function_interface));
    assert_eq!(snapshot.call_site_interfaces(), &[second, first]);
}

#[test]
fn engine_source_snapshot_rejects_empty_mismatched_and_duplicate_authority() {
    assert_eq!(
        EngineSourceSnapshot::new(Vec::new(), None, Vec::new()),
        Err(EngineSourceSnapshotError::EmptyRevisionIdentity)
    );
    assert_eq!(
        EngineSourceSnapshot::new(
            b"source-revision-1".to_vec(),
            Some(source_snapshot_function_interface(b"source-revision-2")),
            Vec::new(),
        ),
        Err(EngineSourceSnapshotError::FunctionRevisionMismatch)
    );

    let first = source_snapshot_call_interface(b"source-revision-1", 0x401000, 1, 0x5000);
    assert_eq!(
        EngineSourceSnapshot::new(b"source-revision-2".to_vec(), None, vec![first.clone()],),
        Err(EngineSourceSnapshotError::CallSiteRevisionMismatch)
    );
    assert_eq!(
        EngineSourceSnapshot::new(
            b"source-revision-1".to_vec(),
            None,
            vec![first.clone(), first],
        ),
        Err(EngineSourceSnapshotError::DuplicateCallSiteIdentity)
    );

    let same_location_other_target =
        source_snapshot_call_interface(b"source-revision-1", 0x401000, 1, 0x6000);
    let first = source_snapshot_call_interface(b"source-revision-1", 0x401000, 1, 0x5000);
    assert_eq!(
        EngineSourceSnapshot::new(
            b"source-revision-1".to_vec(),
            None,
            vec![first, same_location_other_target],
        ),
        Err(EngineSourceSnapshotError::DuplicateCallSiteLocation)
    );
}

#[test]
fn authoritative_source_interface_reaches_prepared_ssa_through_request() {
    let revision = b"source-revision-1";
    let register = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let function_interface = r2ssa::SourceFunctionInterface::new_exact(
        revision.to_vec(),
        "sysv",
        Vec::<r2ssa::SourceAbiParameterSpec>::new(),
        r2ssa::SourceFunctionReturn::Register {
            storage: register(0),
        },
        Vec::<r2ssa::SourceStackSlotSpec>::new(),
    )
    .expect("exact source interface")
    .with_return_address_storage(register(0x30))
    .and_then(|interface| interface.with_stack_pointer_storage(register(0x28)))
    .expect("exact source machine carriers");
    let snapshot = Arc::new(
        EngineSourceSnapshot::new(
            revision.to_vec(),
            Some(function_interface),
            vec![source_snapshot_call_interface(
                revision, 0x401000, 0, 0x5000,
            )],
        )
        .expect("source snapshot")
        .with_call_effect(x86_64_result_call_effect()),
    );
    let mut blocks = direct_call_return_blocks(0x401000, 0x5000);
    blocks[0].ops[1] = r2il::R2ILOp::Return {
        target: r2il::Varnode::register(0x30, 8),
    };
    let arch = x86_64_result_arch();
    let request =
        EngineAnalyzeRequest::full_semantics_for_function(EngineAnalyzeFunctionRequestInput {
            function: EngineFunctionInput {
                function_name: "sym.snapshot".to_string(),
                function_addr: 0x401000,
                blocks,
                arch: Some(arch),
                source_snapshot: Some(snapshot.clone()),
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(64),
            reg_type_hints: HashMap::new(),
            parsed_context: r2types::ParsedExternalContext::default(),
            include_interproc_summary_set: false,
        });
    assert!(Arc::ptr_eq(
        request.source_snapshot.as_ref().expect("request snapshot"),
        &snapshot
    ));

    let response = EngineSession::new()
        .analyze(request)
        .expect("snapshot-backed analysis");
    let context = response.artifact.ssa_func().machine_context();
    assert_eq!(
        context
            .function_interface()
            .expect("authoritative function interface")
            .revision_identity(),
        revision
    );
    let abi = context.abi_model();
    assert!(
        abi.return_boundary_is_coherent()
            && abi.argument_placement_is_coherent()
            && abi.frame_geometry_is_coherent()
            && abi.machine_carriers_are_coherent(),
        "authoritative source context must remain coherent: {context:#?}"
    );
    assert_eq!(context.call_site_interfaces().len(), 1);
    assert!(
        response
            .artifact
            .ssa_func()
            .facts()
            .boundaries
            .calls
            .values()
            .next()
            .expect("authoritative call boundary")
            .complete
    );
}

#[test]
fn absent_source_snapshot_refuses_before_ssa_construction() {
    let blocks = const_return_blocks(0x401000, 0);
    let arch = x86_64_result_arch();
    let session = EngineSession::new();
    let request =
        EngineAnalyzeRequest::full_semantics_for_function(EngineAnalyzeFunctionRequestInput {
            function: EngineFunctionInput {
                function_name: "sym.no_snapshot".to_string(),
                function_addr: 0x401000,
                blocks,
                arch: Some(arch),
                source_snapshot: None,
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(64),
            reg_type_hints: HashMap::new(),
            parsed_context: r2types::ParsedExternalContext::default(),
            include_interproc_summary_set: false,
        });

    let refusal = session
        .analyze_checked(request)
        .expect_err("missing source snapshot must refuse");
    assert_eq!(refusal.reason, MISSING_SOURCE_SNAPSHOT_REFUSAL);
    assert_eq!(refusal.phase, EnginePhase::SnapshotContext);
}

#[test]
fn request_assumptions_produce_one_shared_semantic_artifact() {
    let arch = x86_64_exact_rdi_arch();
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(r2il::R2ILOp::Copy {
        dst: r2il::Varnode::unique(0, 8),
        src: r2il::Varnode::register(0x10, 8),
    });
    block.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::unique(0, 8),
    });
    let parsed_context = r2types::ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![register_assumption("rdi-seven", "RDI", 7)]),
        ..r2types::ParsedExternalContext::default()
    };
    let response = EngineSession::new()
        .analyze_checked(EngineAnalyzeRequest {
            function_name: "sym.assumed".to_string(),
            function_addr: 0x401000,
            blocks: vec![block],
            arch: Some(arch),
            source_snapshot: Some(exact_rdi_test_source_snapshot("sym.assumed/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Optional,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        })
        .expect("assumption-conditioned analysis");

    assert!(response.artifact.trusted_ssa.is_none());
    let usage = &response.artifact.ssa_func().facts().assumption_usage;
    assert_eq!(usage.applied.len(), 1);
    assert!(usage.conflicts.is_empty());
}

/// What a call does on the result arch: rax clobbered, rsp and rip preserved.
fn x86_64_result_call_effect() -> r2ssa::SourceCallEffect {
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    r2ssa::SourceCallEffect::new([storage(0)], [storage(0x28), storage(0x30)])
        .expect("a call effect")
}

fn x86_64_result_arch() -> r2il::ArchSpec {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.set_memory_endianness(r2il::Endianness::Little);
    for (name, offset) in [("rax", 0), ("rsp", 0x28), ("rip", 0x30)] {
        let storage = r2il::RegisterStorage { offset, size: 8 };
        arch.add_register(r2il::RegisterDef::new(name, offset, 8));
        arch.register_projections.push(r2il::RegisterProjection {
            written: storage,
            disposition: r2il::RegisterProjectionDisposition::Bound {
                carrier: storage,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 64,
                },
            },
        });
    }
    arch
}

fn x86_64_exact_rdi_arch() -> r2il::ArchSpec {
    let mut arch = x86_64_result_arch();
    arch.add_register(r2il::RegisterDef::new("rdi", 0x10, 8));
    arch
}

#[test]
fn engine_render_target_canonicalizes_arch_without_renderer_config_type() {
    let mut arch = r2il::ArchSpec::new("amd64");
    arch.addr_size = 8;
    let (arch_name, ptr_bits, target) = EngineRenderTarget::for_arch(Some(&arch));

    assert_eq!(arch_name, "x86-64");
    assert_eq!(ptr_bits, 64);
    assert_eq!(
        target,
        EngineRenderTarget {
            arch_name: "x86-64".to_string(),
            ptr_bits: 64,
        }
    );

    let x86 = EngineRenderTarget::for_arch_name("i386", 32);
    assert_eq!(x86.arch_name, "x86");
    assert_eq!(x86.ptr_bits, 32);

    let (unknown_arch_name, unknown_target) = EngineRenderTarget::for_arch_with_ptr_bits(None, 32);
    assert_eq!(unknown_arch_name, "unknown");
    assert_eq!(
        unknown_target,
        EngineRenderTarget {
            arch_name: "unknown".to_string(),
            ptr_bits: 32,
        }
    );

    let riscv = EngineRenderTarget::for_arch_name("riscv32", 32).to_decompiler_config();
    assert_eq!(riscv.ptr_size, 32);
    assert_eq!(riscv.fp_name, "s0");
    assert_eq!(riscv.arg_regs.first().map(String::as_str), Some("a0"));

    let mut arm64 = r2il::ArchSpec::new("arm64");
    arm64.addr_size = 8;
    assert_eq!(
        engine_normalized_arch_name(Some(&arm64)).as_deref(),
        Some("aarch64")
    );
    let mut rv64 = r2il::ArchSpec::new("riscv:LE:64:default");
    rv64.addr_size = 8;
    assert_eq!(
        engine_normalized_arch_name(Some(&rv64)).as_deref(),
        Some("riscv64")
    );

    let mut contradictory = r2il::ArchSpec::new("x86-64");
    contradictory.addr_size = 4;
    let prepared =
        r2ssa::SsaArtifact::for_decompile(&const_return_blocks(0x401000, 0), Some(&contradictory))
            .expect("mismatched family/width remains analyzable");
    assert!(EngineRenderTarget::for_prepared(&prepared).is_none());
}

#[test]
fn engine_interproc_summary_json_preserves_supplied_scope_report() {
    let existing_scope = serde_json::json!({
        "payloads": [{ "function_addr": 0x403000u64, "function_name": "seeded" }],
        "seeds": [{ "id": 0x403000u64, "name": "seeded" }],
    });

    let interproc = interproc_summary_json(EngineInterprocSummaryJsonInput {
        callsite_count: 2,
        iterations: 0,
        max_iterations: 0,
        converged: true,
        summary: None,
        scope_report: Some(&existing_scope),
    });

    assert_eq!(interproc.iterations, 1);
    assert_eq!(interproc.max_iterations, 1);
    assert_eq!(interproc.scope, Some(existing_scope));
}

#[test]
fn type_analysis_interproc_budget_policy_is_engine_owned() {
    assert!(type_analysis_interproc_prefers_bounded_plan(0, false));
    assert!(type_analysis_interproc_prefers_bounded_plan(1, false));
    assert!(!type_analysis_interproc_prefers_bounded_plan(1, true));
    assert!(!type_analysis_interproc_prefers_bounded_plan(2, false));
}

#[test]
fn analyze_request_builders_own_semantic_mode_selection() {
    let parts = EngineAnalyzeRequestParts {
        function_name: "sym.builder".to_string(),
        function_addr: 0x401000,
        blocks: const_return_blocks(0x401000, 0),
        arch: None,
        source_snapshot: Some(test_source_snapshot("sym.builder/rev1")),
        ptr_bits: 64,
        semantic_metadata_enabled: false,
        reg_type_hints: HashMap::new(),
        parsed_context: r2types::ParsedExternalContext::default(),
        include_interproc_summary_set: true,
    };

    let full = EngineAnalyzeRequest::full_semantics(parts.clone());
    assert!(matches!(full.semantic_mode, EngineSemanticMode::Full));

    let compile_missing = EngineAnalyzeRequest::from_compile_missing_semantics(parts.clone(), true);
    assert!(matches!(
        compile_missing.semantic_mode,
        EngineSemanticMode::Full
    ));

    let optional = EngineAnalyzeRequest::from_compile_missing_semantics(parts, false);
    assert!(matches!(
        optional.semantic_mode,
        EngineSemanticMode::Optional
    ));
}

#[test]
fn analyze_request_input_builder_owns_parts_and_pointer_width() {
    let mut arch = r2il::ArchSpec::new("x86");
    arch.addr_size = 4;
    let input = EngineAnalyzeRequestInput {
        function_name: "sym.input_builder".to_string(),
        function_addr: 0x402000,
        blocks: const_return_blocks(0x402000, 0),
        arch: Some(arch),
        source_snapshot: Some(test_source_snapshot("sym.input_builder/rev1")),
        ptr_bits: None,
        semantic_metadata_enabled: true,
        reg_type_hints: HashMap::new(),
        parsed_context: r2types::ParsedExternalContext::default(),
        include_interproc_summary_set: true,
    };

    let full = EngineAnalyzeRequest::full_semantics_from_input(input.clone());
    assert_eq!(full.ptr_bits, 32);
    assert!(matches!(full.semantic_mode, EngineSemanticMode::Full));
    assert_eq!(full.function_name, "sym.input_builder");

    let explicit = EngineAnalyzeRequest::from_input_with_compile_missing_semantics(
        EngineAnalyzeRequestInput {
            ptr_bits: Some(64),
            ..input
        },
        false,
    );
    assert_eq!(explicit.ptr_bits, 64);
    assert!(matches!(
        explicit.semantic_mode,
        EngineSemanticMode::Optional
    ));

    let grouped =
        EngineAnalyzeRequest::full_semantics_for_function(EngineAnalyzeFunctionRequestInput {
            function: EngineFunctionInput {
                function_name: "sym.grouped".to_string(),
                function_addr: 0x403000,
                blocks: const_return_blocks(0x403000, 0),
                arch: explicit.arch,
                source_snapshot: Some(test_source_snapshot("sym.grouped/rev1")),
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(32),
            reg_type_hints: HashMap::new(),
            parsed_context: r2types::ParsedExternalContext::default(),
            include_interproc_summary_set: false,
        });
    assert_eq!(grouped.function_name, "sym.grouped");
    assert_eq!(grouped.ptr_bits, 32);
    assert!(matches!(grouped.semantic_mode, EngineSemanticMode::Full));
}

#[test]
fn register_type_hint_collection_is_engine_owned() {
    let ptr_reg = r2il::Varnode::register(0, 8).with_meta(r2il::VarnodeMetadata {
        scalar_kind: Some(r2il::ScalarKind::UnsignedInt),
        pointer_hint: Some(r2il::PointerHint::PointerLike),
        ..Default::default()
    });
    let int_reg = r2il::Varnode::register(4, 4).with_meta(r2il::VarnodeMetadata {
        scalar_kind: Some(r2il::ScalarKind::SignedInt),
        ..Default::default()
    });
    let mut block = r2il::R2ILBlock::new(0x401000, 4);
    block.push(r2il::R2ILOp::Copy {
        dst: int_reg,
        src: r2il::Varnode::constant(1, 4),
    });
    block.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(0, 8),
        a: ptr_reg,
        b: r2il::Varnode::constant(8, 8),
    });

    let hints = collect_register_type_hints_with_names(&[block], |vn| match vn.offset {
        0 => Some("RDI".to_string()),
        4 => Some("ESI".to_string()),
        _ => None,
    });

    assert_eq!(
        hints.get("rdi").map(|hint| hint.ty.as_str()),
        Some("void *")
    );
    assert_eq!(
        hints.get("esi").map(|hint| hint.ty.as_str()),
        Some("int32_t")
    );
    assert!(!hints.contains_key("RDI"));
}

#[test]
fn analyze_function_request_collects_register_hints_inside_engine() {
    let ptr_reg = r2il::Varnode::register(0, 8).with_meta(r2il::VarnodeMetadata {
        scalar_kind: Some(r2il::ScalarKind::UnsignedInt),
        pointer_hint: Some(r2il::PointerHint::PointerLike),
        ..Default::default()
    });
    let mut block = r2il::R2ILBlock::new(0x401000, 4);
    block.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(0, 8),
        a: ptr_reg,
        b: r2il::Varnode::constant(8, 8),
    });
    let input = EngineAnalyzeFunctionRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.hints".to_string(),
            function_addr: 0x401000,
            blocks: vec![block],
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.hints/rev1")),
            semantic_metadata_enabled: true,
        },
        ptr_bits: Some(64),
        reg_type_hints: HashMap::new(),
        parsed_context: r2types::ParsedExternalContext::default(),
        include_interproc_summary_set: false,
    };

    let request = EngineAnalyzeRequest::full_semantics_for_function_with_register_names(
        input.clone(),
        |vn| (vn.offset == 0).then(|| "RDI".to_string()),
    );
    assert_eq!(
        request
            .reg_type_hints
            .get("rdi")
            .map(|hint| hint.ty.as_str()),
        Some("void *")
    );

    let disabled = EngineAnalyzeRequest::full_semantics_for_function_with_register_names(
        EngineAnalyzeFunctionRequestInput {
            function: EngineFunctionInput {
                semantic_metadata_enabled: false,
                ..input.function
            },
            ..input
        },
        |vn| (vn.offset == 0).then(|| "RDI".to_string()),
    );
    assert!(disabled.reg_type_hints.is_empty());
}

#[test]
fn interproc_summary_build_uses_only_trusted_callee_bodies() {
    let root_addr = 0x401000;
    let helper_addr = 0x402000;
    let root_blocks = const_return_blocks(root_addr, 0);
    let helper_blocks = const_return_blocks(helper_addr, 1);
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("rax", 0, 8));
    arch.add_register(r2il::RegisterDef::new("rdi", 8, 8));
    arch.add_register(r2il::RegisterDef::new("rip", 16, 8));
    arch.add_register(r2il::RegisterDef::new("rsp", 24, 8));
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"interproc-owner/rev1".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, storage(8))],
        r2ssa::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
    .expect("exact interproc interface");
    let root_prepared = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(
            &root_blocks,
            Some(&arch),
            interface.clone(),
        )
        .expect("root prepared"),
    );
    let helper_prepared = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(&helper_blocks, Some(&arch), interface)
            .expect("helper prepared"),
    );
    let analysis = EngineAnalysis::from_prepared_ssa(Arc::clone(&root_prepared));
    // A body that is not source-owned is refused when its contribution is
    // derived, which is before a caller can consult it at all.
    let solve = |callees: &[Arc<r2ssa::SsaArtifact>]| {
        let summaries = callees
            .iter()
            .map(|callee| {
                r2ssa::PreparedCalleeSummary::derive(
                    r2ssa::InterprocFunctionId(callee.function().entry),
                    callee,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        build_prepared_interproc_summary_set(InterprocSummaryBuildInput {
            analysis: &analysis,
            callee_summaries: &summaries,
        })
    };

    assert_eq!(
        solve(&[helper_prepared]).expect_err("manual helper must not become source evidence"),
        r2ssa::PreparedInterprocSummaryError::ManualFunction
    );

    let root_only = solve(&[]).expect("root-only prepared summary set");
    assert_eq!(root_only.report().diagnostics.scope_size, 1);
    assert!(
        !root_only
            .report()
            .summaries
            .contains_key(&r2ssa::InterprocFunctionId(helper_addr))
    );
}

#[test]
fn cfg_risk_summary_counts_a_switch_case_back_edge_alongside_a_self_loop() {
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(r2il::R2ILOp::CBranch {
        target: r2il::Varnode::constant(0x1000, 8),
        cond: r2il::Varnode::constant(1, 1),
    });
    let mut switch = R2ILBlock::new(0x1004, 4);
    switch.switch_info = Some(r2il::SwitchInfo {
        switch_addr: 0x1004,
        default_target: Some(0x1008),
        cases: vec![r2il::SwitchCase {
            value: 0,
            target: 0x1000,
        }],
    });

    let blocks = [entry, switch];
    let summary = r2ssa::CFG::from_blocks(&blocks)
        .expect("cfg should build")
        .risk_summary();

    assert_eq!(summary.block_count, 2);
    assert_eq!(summary.loop_count, 1);
    // Two edges re-enter the entry: the block's own conditional branch and
    // the switch case. A summary that folded them into one would under-count
    // exactly the shape the guard's back-edge threshold exists to catch.
    assert_eq!(summary.back_edge_count, 2);
    assert_eq!(summary.switch_block_count, 1);
    assert_eq!(summary.max_switch_cases, 2);
}

fn self_looping_blocks(base: u64, loop_count: usize) -> Vec<R2ILBlock> {
    let mut blocks = Vec::with_capacity(loop_count + 1);
    for index in 0..loop_count {
        let addr = base + (index as u64) * 4;
        let mut block = R2ILBlock::new(addr, 4);
        block.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(addr, 8),
            cond: r2il::Varnode::constant(1, 1),
        });
        blocks.push(block);
    }
    let mut exit = R2ILBlock::new(base + (loop_count as u64) * 4, 4);
    exit.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::constant(0, 8),
    });
    blocks.push(exit);
    blocks
}

#[test]
fn cfg_guard_reason_reads_the_same_counters_the_ssa_summary_reports() {
    let blocks = self_looping_blocks(0x3000, 9);
    let prepared =
        r2ssa::SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let from_cfg = r2ssa::CFG::from_blocks(&blocks)
        .expect("cfg should build")
        .risk_summary();

    assert_eq!(
        from_cfg,
        prepared.cfg_risk_summary(),
        "the guard's cheap derivation must report what renamed SSA reports"
    );
    assert_eq!(
        cfg_guard_reason_from_summary(&from_cfg),
        cfg_guard_reason_from_summary(&prepared.cfg_risk_summary()),
    );
    assert!(cfg_guard_reason_from_summary(&from_cfg).is_some());
}

#[test]
fn cfg_risk_summary_answers_for_input_whose_raw_ssa_will_not_form() {
    // An unreachable block that jumps into the entry leaves a predecessor
    // outside the domain SSA retains, so preparation refuses the input.
    let mut blocks = self_looping_blocks(0x4000, 9);
    let mut orphan = R2ILBlock::new(0x4100, 4);
    orphan.push(r2il::R2ILOp::Branch {
        target: r2il::Varnode::constant(0x4000, 8),
    });
    blocks.push(orphan);

    assert!(r2ssa::SSAFunction::from_blocks_raw_no_arch(&blocks).is_none());
    // The two derivations do not accept the same inputs. Anything that
    // reintroduces a block-level guard has to decide what this input is,
    // because the CFG will happily call it complex while the SSA phase is
    // going to refuse it as malformed under its own reason.
    assert!(
        cfg_guard_reason_from_summary(
            &r2ssa::CFG::from_blocks(&blocks)
                .expect("cfg should build")
                .risk_summary()
        )
        .is_some(),
        "the CFG alone is complex enough to trip the guard"
    );
}

#[test]
fn analyze_reports_planning_time() {
    let session = EngineSession::new();
    let request = EngineAnalyzeRequest {
        function_name: "sym.zero".to_string(),
        function_addr: 0x401000,
        blocks: const_return_blocks(0x401000, 0),
        arch: Some(x86_64_result_arch()),
        source_snapshot: Some(exact_empty_test_source_snapshot("sym.zero/analyze/rev1")),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        ptr_bits: 64,
        semantic_metadata_enabled: false,
        reg_type_hints: HashMap::new(),
        parsed_context: r2types::ParsedExternalContext::default(),
        semantic_mode: EngineSemanticMode::Full,
        include_interproc_summary_set: true,
        execution: EngineExecutionControl::default(),
    };
    let response = session
        .analyze_checked(request)
        .unwrap_or_else(|error| panic!("analysis should succeed: {error:?}"));

    assert!(response.metrics.planning_time > Duration::default());
    assert_eq!(response.metrics.phase_timings.len(), EnginePhase::ALL.len());
    assert_eq!(
        response
            .metrics
            .phase_timings
            .iter()
            .map(|timing| timing.phase)
            .collect::<Vec<_>>(),
        EnginePhase::ALL
    );
    assert_eq!(
        response.metrics.phase_timings[2].status,
        EnginePhaseStatus::Executed
    );

    let decompiled = session.decompile_function_from_input(
        EngineFunctionDecompileRequestInput::single_function(
            EngineFunctionInput {
                function_name: "sym.zero".to_string(),
                function_addr: 0x401000,
                blocks: const_return_blocks(0x401000, 0),
                arch: Some(x86_64_result_arch()),
                source_snapshot: Some(exact_empty_test_source_snapshot("sym.zero/decompile/rev1")),
                semantic_metadata_enabled: false,
            },
            Some(64),
            r2types::ParsedExternalContext::default(),
        ),
    );
    assert_eq!(
        decompiled.metrics.phase_timings.len(),
        EnginePhase::ALL.len()
    );
    assert_eq!(
        decompiled.metrics.phase_timings[10].status,
        EnginePhaseStatus::NotExecuted,
        "FFI conversion is outside the engine measurement boundary"
    );
}

impl EngineSession {
    /// Seal one request and render its C, as `pdd` does.
    fn decompile_function(
        &self,
        request: EngineFunctionDecompileRequest,
    ) -> EngineDecompileResponse {
        let execution = request.analysis.execution.clone();
        match self.seal_function(request) {
            Ok(sealed) => self.render_sealed(&sealed, RenderTier::C, &execution),
            Err(refused) => *refused,
        }
    }
}

fn controlled_ssa_test_request(
    function_name: &str,
    blocks: Vec<R2ILBlock>,
) -> EngineAnalyzeRequest {
    EngineAnalyzeRequest::full_semantics_for_function(EngineAnalyzeFunctionRequestInput {
        function: EngineFunctionInput {
            function_name: function_name.to_string(),
            function_addr: blocks.first().map(|block| block.addr).unwrap_or(0),
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot(&format!(
                "{function_name}/controlled/rev1"
            ))),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        reg_type_hints: HashMap::new(),
        parsed_context: r2types::ParsedExternalContext::default(),
        include_interproc_summary_set: false,
    })
}

fn controlled_r2dec_sealed() -> SealedFunctionAnalysis {
    let mut block = R2ILBlock::new(0x614000, 4);
    block.push(r2il::R2ILOp::Copy {
        dst: r2il::Varnode::register(0, 8),
        src: r2il::Varnode::constant(7, 8),
    });
    block.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::register(0x30, 8),
    });
    let blocks = vec![block];
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"controlled-r2dec-source".to_vec(),
        "sysv64",
        std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
        r2ssa::SourceFunctionReturn::Register {
            storage: r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        },
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|interface| {
        interface.with_stack_pointer_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x28,
            size: 8,
        })
    })
    .and_then(|interface| {
        interface.with_return_address_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x30,
            size: 8,
        })
    })
    .expect("exact controlled r2dec interface");
    let prepared = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(
            &blocks,
            Some(&x86_64_result_arch()),
            interface,
        )
        .expect("prepared render SSA")
        .with_name("sym.r2dec_controlled"),
    );
    let type_analysis = r2types::build_source_owned_type_analysis(
        r2types::TypeAnalysisRequest::new(prepared, r2types::ParsedExternalContext::default())
            .expect("coherent test owner request"),
    )
    .expect("source-owned test facts");
    let source_owned_facts = type_analysis
        .finalize_for_decompile(r2types::DecompileFinalization {
            kind: r2types::DecompileRouteKind::Standard,
            reason: "controlled r2dec residual test".to_string(),
            fallback_comment: None,
        })
        .expect("compatible controlled r2dec route");
    SealedFunctionAnalysis {
        function_name: "sym.r2dec_controlled".to_string(),
        source_owned_facts,
        trusted_ssa: None,
        input_quality: None,
        render_target: EngineRenderTarget::default(),
        metrics: EngineMetrics::default(),
    }
}

/// Its C, asked under a fresh control.
fn render_request(sealed: &SealedFunctionAnalysis) -> EngineDecompileRequest<'_> {
    EngineDecompileRequest {
        tier: RenderTier::C,
        sealed,
        execution: EngineExecutionControl::default(),
    }
}

#[derive(Default)]
struct CountingRenderControl {
    polls: Cell<usize>,
}

impl r2ssa::SsaWorkControl for CountingRenderControl {
    fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
        self.polls.set(self.polls.get().saturating_add(1));
        Ok(())
    }
}

struct StopRenderAtPoll {
    polls: Cell<usize>,
    stop_at: usize,
    reason: r2ssa::SsaExecutionStopReason,
}

impl StopRenderAtPoll {
    fn new(stop_at: usize, reason: r2ssa::SsaExecutionStopReason) -> Self {
        Self {
            polls: Cell::new(0),
            stop_at,
            reason,
        }
    }
}

impl r2ssa::SsaWorkControl for StopRenderAtPoll {
    fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
        let polls = self.polls.get().saturating_add(1);
        self.polls.set(polls);
        if polls >= self.stop_at {
            Err(self.reason)
        } else {
            Ok(())
        }
    }
}

#[test]
fn engine_decompiler_input_retains_exact_source_owned_facts() {
    let sealed = controlled_r2dec_sealed();
    let request = render_request(&sealed);
    let source = request.sealed.source_owned_facts.shared_source();
    let input = decompiler_input_for_engine_request(&request);

    assert!(input.source_owned_facts().shares_source(&source));
    assert_eq!(
        input.function_facts().decompile_route(),
        request.function_facts().decompile_route()
    );
}

#[test]
fn r2dec_inner_stops_map_to_engine_refusals_and_keep_exact_audits() {
    let session = EngineSession::new();
    let sealed = controlled_r2dec_sealed();
    let request = render_request(&sealed);
    let decompiler_input = decompiler_input_for_engine_request(&request);
    let legacy_output = r2dec::Decompiler::new(request.sealed.render_target.to_decompiler_config())
        .decompile_input(&decompiler_input);
    let counting = CountingRenderControl::default();
    let controlled = session.decompile_with_r2dec_control(request.clone(), &counting);
    assert!(
        legacy_output.contains("return"),
        "the exact control fixture must reach native rendering: {legacy_output}"
    );
    assert!(
        controlled.output.text().contains("return"),
        "the engine path must render the same exact fixture: {}",
        controlled.output
    );
    assert_ne!(
        controlled.binding_audit,
        BindingShadowAuditOutcome::NotRun,
        "the completed native render must retain its exact r2dec audit: {}",
        controlled.output
    );
    assert_ne!(
        controlled.effect_obligations(),
        EffectObligationAudit::NOT_RUN,
        "the completed native render must retain its exact effect audit"
    );
    assert_eq!(
        controlled.render_refusal, None,
        "the exact fixture must not cross a renderer refusal boundary"
    );
    let completed_binding_audit = controlled.binding_audit;
    let completed_effect_obligations = controlled.effect_obligations();
    let total_polls = counting.polls.get();
    assert!(total_polls > 3, "r2dec pipeline must expose inner polls");

    let mut observed = HashMap::new();
    for stop_at in 1..=total_polls {
        let stop = StopRenderAtPoll::new(stop_at, r2ssa::SsaExecutionStopReason::Cancelled);
        let response = session.decompile_with_r2dec_control(request.clone(), &stop);
        let phase = [EnginePhase::Normalization, EnginePhase::Rendering]
            .into_iter()
            .find(|phase| {
                response.metrics.phase_timings.iter().any(|timing| {
                    timing.phase == *phase && timing.status == EnginePhaseStatus::Refused
                })
            })
            .expect("stopped render must mark one render phase refused");
        observed.entry(phase).or_insert(stop_at);
        if observed.len() == 2 {
            break;
        }
    }
    observed.insert(EnginePhase::Rendering, total_polls);

    for phase in [EnginePhase::Normalization, EnginePhase::Rendering] {
        let stop_at = *observed.get(&phase).unwrap_or_else(|| {
            panic!(
                "missing deterministic {phase:?} stop (polls={total_polls}, output={legacy_output})"
            )
        });
        let reason = if phase == EnginePhase::Rendering {
            r2ssa::SsaExecutionStopReason::DeadlineExceeded
        } else {
            r2ssa::SsaExecutionStopReason::Cancelled
        };
        let stop = StopRenderAtPoll::new(stop_at, reason);
        let response = session.decompile_with_r2dec_control(request.clone(), &stop);
        let expected_reason = match reason {
            r2ssa::SsaExecutionStopReason::Cancelled => {
                format!("engine request cancelled during {} phase", phase.as_str())
            }
            r2ssa::SsaExecutionStopReason::DeadlineExceeded => format!(
                "engine request deadline exceeded during {} phase",
                phase.as_str()
            ),
        };
        assert_eq!(response.metrics.phase_timings.len(), EnginePhase::ALL.len());
        assert!(response.metrics.phase_timings.iter().any(|timing| {
            timing.phase == phase && timing.status == EnginePhaseStatus::Refused
        }));
        assert_eq!(
            response
                .metrics
                .phase_timings
                .iter()
                .filter(|timing| timing.status == EnginePhaseStatus::Refused)
                .count(),
            1,
            "only the interrupted phase is refused"
        );
        let normalization_status = if phase == EnginePhase::Rendering {
            EnginePhaseStatus::Folded
        } else {
            EnginePhaseStatus::Refused
        };
        let structuring_status = if phase == EnginePhase::Rendering {
            EnginePhaseStatus::Folded
        } else {
            EnginePhaseStatus::NotExecuted
        };
        assert_eq!(
            response.metrics.phase_timings[EnginePhase::Normalization as usize].status,
            normalization_status
        );
        assert_eq!(
            response.metrics.phase_timings[EnginePhase::Structuring as usize].status,
            structuring_status
        );
        assert_eq!(
            response.metrics.phase_timings[EnginePhase::FfiConversion as usize].status,
            EnginePhaseStatus::NotExecuted
        );
        assert_eq!(
            response.diagnostics.route_reason.as_deref(),
            Some(expected_reason.as_str()),
            "an execution stop remains primary over audits retained from the partial render"
        );
        if phase == EnginePhase::Rendering {
            assert_eq!(response.binding_audit, completed_binding_audit);
            assert_eq!(response.effect_obligations(), completed_effect_obligations);
            assert!(
                !response.output.text().trim().is_empty(),
                "the stopped render retains the partial output it reached"
            );
            assert!(
                response
                    .diagnostics
                    .refusal
                    .as_deref()
                    .is_some_and(|value| value.contains(&expected_reason)),
                "the execution stop must remain the response refusal: {}",
                response.output
            );
        } else {
            assert_eq!(response.binding_audit, BindingShadowAuditOutcome::NotRun);
            assert_eq!(
                response.effect_obligations(),
                EffectObligationAudit::NOT_RUN
            );
            assert!(
                response
                    .diagnostics
                    .refusal
                    .as_deref()
                    .is_some_and(|refusal| refusal.contains(&expected_reason))
            );
            assert_eq!(
                response
                    .function_facts
                    .decompile_route()
                    .map(|route| route.kind),
                Some(r2types::DecompileRouteKind::FallbackComment)
            );
            assert!(response.output.text().starts_with("/* r2sleigh refused"));
            assert!(!response.output.text().contains("() {"));
        }
    }
}

#[test]
fn r2dec_stop_mapping_preserves_all_decompiler_phases_and_reasons() {
    // Production r2dec deliberately refuses executable Standard rendering before its
    // structurer, while every non-Standard route exits at a summary boundary. The r2dec
    // assignment-consensus test therefore exercises the actual inner Structuring stop;
    // this engine test covers its exact cross-crate phase/reason mapping without weakening
    // that fail-closed authorization boundary.
    for (decompile_phase, engine_phase) in [
        (
            r2dec::DecompileWorkPhase::Normalization,
            EnginePhase::Normalization,
        ),
        (
            r2dec::DecompileWorkPhase::Structuring,
            EnginePhase::Structuring,
        ),
        (r2dec::DecompileWorkPhase::Rendering, EnginePhase::Rendering),
    ] {
        for reason in [
            r2ssa::SsaExecutionStopReason::Cancelled,
            r2ssa::SsaExecutionStopReason::DeadlineExceeded,
        ] {
            let mapped = engine_render_stop_from_decompiler(
                r2dec::DecompileExecutionStop::new(decompile_phase, reason),
                BindingShadowAuditOutcome::NotRun,
                Some(stop_test_ledger()),
                PlacementAudit::NotRun,
                Some(DecompileRenderRefusal::UnrepresentableOperation),
            );
            let counted = effect_obligations_of((*mapped.obligation_ledger).as_ref());
            assert_eq!(mapped.phase, engine_phase);
            assert_eq!(*mapped.binding_audit, BindingShadowAuditOutcome::NotRun);
            assert_eq!(counted.total, 11);
            assert_eq!(counted.rendered, 6);
            assert_eq!(counted.justified_elision, 2);
            assert_eq!(counted.refused, 1);
            assert_eq!(counted.unaccounted, 2);
            assert_eq!(counted.conflicts, 1);
            // The columns account for every obligation, which a hand-written
            // audit could get wrong and a ledger cannot.
            assert_eq!(
                counted.total,
                counted.rendered
                    + counted.justified_elision
                    + counted.refused
                    + counted.gapped
                    + counted.unaccounted
            );
            assert_eq!(mapped.placement_audit, PlacementAudit::NotRun);
            assert_eq!(
                mapped.render_refusal.as_deref(),
                Some(&DecompileRenderRefusal::UnrepresentableOperation)
            );
            assert_eq!(
                mapped.normalization_completed,
                !matches!(decompile_phase, r2dec::DecompileWorkPhase::Normalization)
            );
            assert_eq!(
                mapped.structuring_completed,
                matches!(decompile_phase, r2dec::DecompileWorkPhase::Rendering)
            );
            match reason {
                r2ssa::SsaExecutionStopReason::Cancelled => {
                    assert_eq!(
                        mapped.reason,
                        format!(
                            "engine request cancelled during {} phase",
                            engine_phase.as_str()
                        )
                    );
                }
                r2ssa::SsaExecutionStopReason::DeadlineExceeded => {
                    assert_eq!(
                        mapped.reason,
                        format!(
                            "engine request deadline exceeded during {} phase",
                            engine_phase.as_str()
                        )
                    );
                }
            }
        }
    }
}

/// Eleven obligations: six rendered, two elided, one refused, one of the
/// rendered with a conflicting second answer, and two nothing spoke about.
fn stop_test_ledger() -> r2dec::ledger::ObligationLedger {
    let at = |op: u64| r2ssa::SemanticObligationId {
        instruction: r2ssa::CanonicalInstructionId {
            block_addr: 0x401000,
            site: r2ssa::CanonicalInstructionSite::Op(op),
        },
        kind: r2ssa::SemanticObligationKind::ObservableMemoryWrite,
        component: r2ssa::SemanticObligationComponent::Whole,
    };
    let ids = (0..11).map(at).collect::<Vec<_>>();
    let mut ledger = r2dec::ledger::ObligationLedger::over(ids.iter().copied());
    let rendered = r2dec::ledger::Outcome::Rendered {
        block_addr: 0x401000,
        op_idx: 0,
    };
    for id in &ids[..5] {
        ledger.record(*id, rendered);
    }
    for id in &ids[5..7] {
        ledger.record(
            *id,
            r2dec::ledger::Outcome::Elided(r2dec::ledger::ElisionReason::StackFrame),
        );
    }
    ledger.record(ids[7], r2dec::ledger::Outcome::Refused);
    ledger.record(ids[8], rendered);
    ledger.record_conflict(ids[8]);
    ledger
}

#[test]
fn refused_effect_obligations_produce_a_typed_engine_refusal() {
    let obligation = r2ssa::SemanticObligationId {
        instruction: r2ssa::CanonicalInstructionId {
            block_addr: 0x401000,
            site: r2ssa::CanonicalInstructionSite::Op(7),
        },
        kind: r2ssa::SemanticObligationKind::ObservableMemoryWrite,
        component: r2ssa::SemanticObligationComponent::Whole,
    };
    // The ledger is the fact the refusal is read from, so the test builds
    // one that closes to two refusals, one unaccounted and one conflict.
    let sibling = |op: u64| r2ssa::SemanticObligationId {
        instruction: r2ssa::CanonicalInstructionId {
            block_addr: 0x401000,
            site: r2ssa::CanonicalInstructionSite::Op(op),
        },
        ..obligation
    };
    let ids = (7..16).map(sibling).collect::<Vec<_>>();
    let mut ledger = r2dec::ledger::ObligationLedger::over(ids.iter().copied());
    ledger.record(ids[0], r2dec::ledger::Outcome::Refused);
    ledger.record(ids[1], r2dec::ledger::Outcome::Refused);
    ledger.record(
        ids[2],
        r2dec::ledger::Outcome::Elided(r2dec::ledger::ElisionReason::StackFrame),
    );
    for id in &ids[3..7] {
        ledger.record(
            *id,
            r2dec::ledger::Outcome::Rendered {
                block_addr: 0x401000,
                op_idx: 0,
            },
        );
    }
    ledger.record(
        ids[7],
        r2dec::ledger::Outcome::Rendered {
            block_addr: 0x401000,
            op_idx: 1,
        },
    );
    ledger.record_conflict(ids[7]);
    let obligation_ledger = Some(ledger);
    let effect_obligations = effect_obligations_of(obligation_ledger.as_ref());
    let reason = effect_obligation_refusal_reason(effect_obligations)
        .expect("refused effects must refuse the native engine outcome");
    assert_eq!(
        reason,
        "native effect obligations refused: 2 refused (memory-write at 0x401000:op:7), 1 unaccounted (memory-write at 0x401000:op:15), 1 conflicts (memory-write at 0x401000:op:14)"
    );
    let render_time = Duration::from_micros(17);
    let mut metrics = EngineMetrics::default();
    metrics.record_phase(
        EnginePhase::Rendering,
        EnginePhaseStatus::Refused,
        render_time,
    );
    let sentinel_quality = r2types::FunctionInputQualityFacts {
        expected_blocks: 7,
        lifted_blocks: 7,
        actual_lifted_blocks: 7,
        read_failures: 0,
        invalid_blocks: 0,
        null_lift_failures: 0,
        truncated_blocks: 0,
        refusal_reason: None,
    };
    let response = refused_decompile_response_with_metrics_and_audits(
        "sym.effect_refusal",
        &reason,
        None,
        metrics,
        EngineDiagnostics::default(),
        Some(FunctionFacts::default().with_input_quality(sentinel_quality.clone())),
        BindingShadowAuditOutcome::NotRun,
        obligation_ledger,
        PlacementAudit::NotRun,
        None,
    );

    assert_eq!(response.effect_obligations(), effect_obligations);
    assert_eq!(
        response.metrics.phase_timings[EnginePhase::Rendering as usize].status,
        EnginePhaseStatus::Refused
    );
    assert_eq!(
        response.diagnostics.route_reason.as_deref(),
        Some(reason.as_str())
    );
    assert!(
        response
            .diagnostics
            .refusal
            .as_deref()
            .is_some_and(|value| value.contains(reason.as_str()))
    );
    assert!(response.output.text().starts_with("/* r2sleigh refused"));
    assert!(effect_obligation_refusal_reason(EffectObligationAudit::NOT_RUN).is_none());
    assert_eq!(
        response.function_facts.input_quality(),
        Some(&sentinel_quality),
        "late effect refusal replaces only the route and retains existing function facts"
    );
    assert!(
        effect_obligation_refusal_reason(EffectObligationAudit {
            disposition: EffectObligationDisposition::Admitted,
            total: 1,
            rendered: 0,
            justified_elision: 0,
            refused: 1,
            gapped: 0,
            unaccounted: 0,
            conflicts: 0,
            refused_obligation: None,
            unaccounted_obligation: None,
            conflicting_obligation: None,
        })
        .is_some(),
        "nonzero refusal counts fail closed independently of disposition"
    );
}

#[test]
fn refused_placement_produces_a_typed_engine_refusal() {
    let placement_audit = PlacementAudit::Refused(PlacementAuditRefusal::ReadBeforeAssignment {
        binding_index: 3,
        instruction_id: 11,
        input_index: 2,
    });
    let reason = placement_refusal_reason(placement_audit)
        .expect("refused placement must refuse the native engine outcome");
    let mut metrics = EngineMetrics::default();
    metrics.record_phase(
        EnginePhase::Rendering,
        EnginePhaseStatus::Refused,
        Duration::from_micros(18),
    );
    let response = refused_decompile_response_with_metrics_and_audits(
        "sym.placement_refusal",
        &reason,
        None,
        metrics,
        EngineDiagnostics::default(),
        None,
        BindingShadowAuditOutcome::NotRun,
        None,
        placement_audit,
        None,
    );

    assert_eq!(response.placement_audit, placement_audit);
    assert_eq!(
        response.metrics.phase_timings[EnginePhase::Rendering as usize].status,
        EnginePhaseStatus::Refused,
    );
    assert_eq!(
        response.diagnostics.route_reason.as_deref(),
        Some(reason.as_str())
    );
    assert!(
        response
            .diagnostics
            .refusal
            .as_deref()
            .is_some_and(|value| value.contains(&reason))
    );
    assert!(response.output.text().starts_with("/* r2sleigh refused"));
    assert!(placement_refusal_reason(PlacementAudit::Applied).is_none());
    assert!(placement_refusal_reason(PlacementAudit::NotRun).is_none());
}

#[test]
fn renderer_boundary_refusal_produces_a_typed_engine_refusal() {
    let render_refusal = DecompileRenderRefusal::MissingMachineProjectionAuthorization(
        r2dec::MachineProjectionRefusalOrigin::op_lowering(),
    );
    let reason = render_refusal_reason(render_refusal, &FunctionFacts::default());
    let render_time = Duration::from_micros(19);
    let mut metrics = EngineMetrics::default();
    metrics.record_phase(
        EnginePhase::Rendering,
        EnginePhaseStatus::Refused,
        render_time,
    );
    let response = refused_decompile_response_with_metrics_and_audits(
        "sym.render_refusal",
        &reason,
        None,
        metrics,
        EngineDiagnostics::default(),
        None,
        BindingShadowAuditOutcome::NotRun,
        None,
        PlacementAudit::NotRun,
        Some(render_refusal),
    );

    assert_eq!(response.render_refusal, Some(render_refusal));
    assert_eq!(
        response.effect_obligations(),
        EffectObligationAudit::NOT_RUN
    );
    assert_eq!(
        response.metrics.phase_timings[EnginePhase::Rendering as usize].status,
        EnginePhaseStatus::Refused
    );
    assert_eq!(
        response.diagnostics.route_reason.as_deref(),
        Some(reason.as_str())
    );
    assert!(
        response
            .diagnostics
            .refusal
            .as_deref()
            .is_some_and(|value| value.contains(reason.as_str()))
    );
    assert!(response.output.text().starts_with("/* r2sleigh refused"));
    assert!(!response.output.text().contains("() {"));
}

#[test]
fn variadic_count_refusal_names_the_missing_callsite_evidence() {
    let reason = render_refusal_reason(
        DecompileRenderRefusal::VariadicCallsiteArgumentCount(
            r2ssa::VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral,
        ),
        &FunctionFacts::default(),
    );
    assert_eq!(
        reason,
        "native rendering refused: variadic callsite argument count: format_argument_not_literal"
    );
}

fn analyze_with_injected_ssa_control<C: r2ssa::SsaWorkControl + ?Sized>(
    session: &EngineSession,
    request: EngineAnalyzeRequest,
    control: &C,
) -> Result<EngineAnalyzeResponse, EngineExecutionRefusal> {
    let started = Instant::now();
    let mut metrics = EngineMetrics::default();
    poll_engine_execution(&request.execution, EnginePhase::SnapshotContext, &metrics)?;
    let phase_started = Instant::now();
    metrics.record_phase(
        EnginePhase::SnapshotContext,
        EnginePhaseStatus::Executed,
        phase_started.elapsed(),
    );
    session.analyze_with_ssa_control(request, started, metrics, control)
}

enum SsaPollTrigger {
    Cancel(EngineCancellationToken),
    Stop(r2ssa::SsaExecutionStopReason),
}

struct DeterministicSsaControl {
    polls: Cell<usize>,
    stop_at: usize,
    trigger: SsaPollTrigger,
    downstream: Option<r2ssa::SsaExecutionControl>,
}

impl r2ssa::SsaWorkControl for DeterministicSsaControl {
    fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
        let polls = self.polls.get() + 1;
        self.polls.set(polls);
        if polls == self.stop_at {
            match &self.trigger {
                SsaPollTrigger::Cancel(cancellation) => cancellation.cancel(),
                SsaPollTrigger::Stop(reason) => return Err(*reason),
            }
        }
        self.downstream
            .as_ref()
            .map_or(Ok(()), r2ssa::SsaWorkControl::poll)
    }
}

#[test]
fn analyze_checked_maps_mid_ssa_cancellation() {
    let session = EngineSession::new();
    let cancellation = EngineCancellationToken::default();
    let request =
        controlled_ssa_test_request("sym.ssa_cancelled", const_return_blocks(0x611000, 7))
            .with_cancellation(cancellation.clone());
    let control = DeterministicSsaControl {
        polls: Cell::new(0),
        stop_at: 10,
        trigger: SsaPollTrigger::Cancel(cancellation),
        downstream: Some(request.execution.ssa_execution_control()),
    };

    let refusal = analyze_with_injected_ssa_control(&session, request, &control)
        .expect_err("mid-SSA cancellation must fail closed");

    assert_eq!(control.polls.get(), 10);
    assert_eq!(refusal.phase, EnginePhase::Ssa);
    assert_eq!(refusal.reason, "engine request cancelled during ssa phase");
    assert_eq!(
        refusal.metrics.phase_timings[EnginePhase::Ssa as usize].status,
        EnginePhaseStatus::Refused
    );
}

#[test]
fn analyze_checked_maps_mid_ssa_deadline() {
    let session = EngineSession::new();
    let request = controlled_ssa_test_request("sym.ssa_deadline", const_return_blocks(0x612000, 9));
    let control = DeterministicSsaControl {
        polls: Cell::new(0),
        stop_at: 10,
        trigger: SsaPollTrigger::Stop(r2ssa::SsaExecutionStopReason::DeadlineExceeded),
        downstream: None,
    };

    let refusal = analyze_with_injected_ssa_control(&session, request, &control)
        .expect_err("mid-SSA deadline must fail closed");

    assert_eq!(control.polls.get(), 10);
    assert_eq!(refusal.phase, EnginePhase::Ssa);
    assert_eq!(
        refusal.reason,
        "engine request deadline exceeded during ssa phase"
    );
    assert_eq!(
        refusal.metrics.phase_timings[EnginePhase::Ssa as usize].status,
        EnginePhaseStatus::Refused
    );
}

#[test]
fn analyze_checked_keeps_malformed_ssa_distinct_from_execution_stops() {
    let session = EngineSession::new();
    let request = controlled_ssa_test_request("sym.ssa_malformed", Vec::new());
    let refusal = session
        .analyze_checked(request)
        .expect_err("malformed SSA input must fail closed");

    assert_eq!(refusal.phase, EnginePhase::Ssa);
    assert_eq!(
        refusal.reason,
        "malformed SSA source input during ssa phase"
    );
    assert!(!refusal.reason.contains("cancelled"));
    assert!(!refusal.reason.contains("deadline"));
    assert_eq!(
        refusal.metrics.phase_timings[EnginePhase::Ssa as usize].status,
        EnginePhaseStatus::Refused
    );
}

#[test]
fn controlled_ssa_build_is_unchanged() {
    let blocks = const_return_blocks(0x613000, 11);
    let snapshot = test_source_snapshot("sym.ssa_same/rev1");
    let prepared = build_engine_analysis_from_parts("sym.ssa_same", &blocks, None, &snapshot)
        .expect("snapshot-backed analysis");
    let controlled = build_engine_analysis_from_parts_with_control(
        "sym.ssa_same",
        &blocks,
        None,
        &snapshot,
        &r2ssa::SsaExecutionControl::default(),
    )
    .expect("controlled analysis");
    assert_eq!(prepared.ssa_func.graph(), controlled.ssa_func.graph());
    assert_eq!(prepared.ssa_func.facts(), controlled.ssa_func.facts());
}

#[test]
fn engine_execution_control_translates_combined_ssa_control() {
    let cancellation = EngineCancellationToken::default();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("future deadline");
    let execution =
        EngineExecutionControl::with_cancellation_and_deadline(cancellation.clone(), deadline);
    let ssa = execution.ssa_execution_control();
    assert_eq!(ssa.deadline(), Some(deadline));

    cancellation.cancel();
    assert_eq!(
        r2ssa::SsaWorkControl::poll(&ssa),
        Err(r2ssa::SsaExecutionStopReason::Cancelled)
    );
}

#[test]
fn analyze_checked_refuses_pre_cancelled_request_with_full_phase_report() {
    let cancellation = EngineCancellationToken::default();
    cancellation.cancel();
    let request =
        EngineAnalyzeRequest::full_semantics_for_function(EngineAnalyzeFunctionRequestInput {
            function: EngineFunctionInput {
                function_name: "sym.cancelled".to_string(),
                function_addr: 0x401000,
                blocks: const_return_blocks(0x401000, 0),
                arch: None,
                source_snapshot: Some(test_source_snapshot("sym.cancelled/rev1")),
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(64),
            reg_type_hints: HashMap::new(),
            parsed_context: r2types::ParsedExternalContext::default(),
            include_interproc_summary_set: false,
        })
        .with_cancellation(cancellation);

    let refusal = EngineSession::new()
        .analyze_checked(request)
        .expect_err("pre-cancelled analysis must fail closed");
    assert_eq!(refusal.phase, EnginePhase::SnapshotContext);
    assert!(refusal.reason.contains("cancelled before snapshot_context"));
    assert_eq!(refusal.metrics.phase_timings.len(), EnginePhase::ALL.len());
    assert!(
        refusal
            .metrics
            .phase_timings
            .iter()
            .all(|timing| timing.status == EnginePhaseStatus::Refused)
    );
    assert_eq!(
        refusal.diagnostics.refusal.as_deref(),
        Some(refusal.reason.as_str())
    );
}

#[test]
fn decompile_expired_deadline_returns_actionable_refusal_without_c() {
    let deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("deadline before now");
    let input = EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: "sym.expired".to_string(),
            function_addr: 0x401000,
            blocks: const_return_blocks(0x401000, 0),
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.expired/rev1")),
            semantic_metadata_enabled: false,
        },
        Some(64),
        r2types::ParsedExternalContext::default(),
    )
    .with_deadline(deadline);

    let response = EngineSession::new().decompile_function_from_input(input);
    assert!(
        response
            .output
            .text()
            .contains("deadline exceeded before snapshot_context")
    );
    assert!(!response.output.text().contains("uint64_t sym_expired"));
    assert!(
        response
            .diagnostics
            .refusal
            .as_deref()
            .is_some_and(|reason| reason.contains("deadline exceeded"))
    );
    assert_eq!(response.metrics.phase_timings.len(), EnginePhase::ALL.len());
    assert!(
        response
            .metrics
            .phase_timings
            .iter()
            .all(|timing| timing.status == EnginePhaseStatus::Refused)
    );
}

#[test]
fn cancellation_and_deadline_coexist_and_refuse_without_partial_c() {
    let cancellation = EngineCancellationToken::default();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("future deadline");
    let input = EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: "sym.combined".to_string(),
            function_addr: 0x401000,
            blocks: const_return_blocks(0x401000, 7),
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.combined/rev1")),
            semantic_metadata_enabled: false,
        },
        Some(64),
        r2types::ParsedExternalContext::default(),
    )
    .with_deadline(deadline)
    .with_cancellation(cancellation.clone());
    assert_eq!(input.execution.deadline(), Some(deadline));
    cancellation.cancel();

    let response = EngineSession::new().decompile_function_from_input(input);

    assert!(
        response
            .output
            .text()
            .contains("cancelled before snapshot_context")
    );
    assert!(!response.output.text().contains("uint64_t sym_combined"));
}

#[test]
fn engine_owns_public_guard_fallback_comments() {
    let block_comment = block_guard_fallback_comment("sym.big", 201, 200);
    assert!(block_comment.contains("r2dec budget"));
    assert!(block_comment.contains("sym.big"));
    assert!(block_comment.contains("201"));
    assert!(block_comment.contains("200"));

    let cfg_comment = cfg_guard_fallback_comment(
        "sym.loopy",
        &CFGRiskSummary {
            block_count: 107,
            loop_count: 9,
            back_edge_count: 17,
            switch_block_count: 0,
            max_switch_cases: 0,
        },
    )
    .expect("complex CFG should produce a guard fallback");
    assert!(cfg_comment.contains("r2sleigh refused"));
    assert!(cfg_comment.contains("sym.loopy"));
    assert!(cfg_comment.contains("complex loop graph"));

    let hostile_name = "sym.*/\r\nint forged(void)";
    let hostile_reason = "budget */\nreturn 7";
    let hostile_comments = [
        block_guard_fallback_comment(hostile_name, 201, 200),
        artifact_guard_fallback_comment(hostile_name, hostile_reason),
    ];
    for comment in &hostile_comments {
        let body = comment
            .strip_suffix("*/")
            .expect("engine fallback must remain one closed comment");
        assert!(!body.contains("*/"), "comment closed early: {comment}");
        assert!(!comment.contains(['\r', '\n']));
        assert!(comment.contains("sym.* /  int forged(void)"));
    }
    assert!(hostile_comments[1].contains("budget * / return 7"));
}

#[test]
fn function_identity_keeps_ordered_aliases_for_summary_and_type_routes() {
    let identity = EngineFunctionIdentity::with_aliases(
        0x7000,
        "fcn.00007000",
        "sym.limfield.isra.0",
        ["dbg.limfield", "sym.limfield.isra.0"],
    );
    let candidates = identity.name_candidates().collect::<Vec<_>>();

    assert_eq!(
        candidates,
        vec![
            "fcn.00007000",
            "00007000",
            "sym.limfield.isra.0",
            "limfield",
            "dbg.limfield"
        ]
    );
}

#[test]
fn type_route_decision_allows_moderate_dense_semantic_plan() {
    let cfg_summary = r2ssa::CFGRiskSummary {
        block_count: 55,
        loop_count: 1,
        back_edge_count: 1,
        switch_block_count: 1,
        max_switch_cases: 48,
    };
    let function_facts = FunctionFacts::default();

    assert!(type_cfg_forces_bounded_plan(&cfg_summary));
    assert!(type_cfg_allows_semantic_plan(&cfg_summary));
    assert_eq!(
        type_route_decision(&function_facts, &cfg_summary, false).kind,
        EngineTypeRouteKind::FullTypeEvidence
    );
}

#[test]
fn type_route_decision_bounds_large_loop_cfg() {
    let cfg_summary = r2ssa::CFGRiskSummary {
        block_count: 1977,
        loop_count: 9,
        back_edge_count: 17,
        switch_block_count: 0,
        max_switch_cases: 0,
    };
    let function_facts = FunctionFacts::default();
    let decision = type_route_decision(&function_facts, &cfg_summary, false);

    assert_eq!(decision.kind, EngineTypeRouteKind::BoundedCfg);
    assert_eq!(decision.plan, EnginePlan::BoundedType);
    assert!(decision.prefer_bounded_type_plan);
    assert!(
        decision
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("complex loop graph"))
    );
}

#[test]
fn type_route_decision_does_not_treat_name_only_workers_as_type_input() {
    let cfg_summary = r2ssa::CFGRiskSummary {
        block_count: 200,
        loop_count: 8,
        back_edge_count: 12,
        switch_block_count: 0,
        max_switch_cases: 0,
    };
    let function_facts = FunctionFacts::default();

    assert_eq!(
        type_route_decision(&function_facts, &cfg_summary, false).kind,
        EngineTypeRouteKind::FullTypeEvidence
    );
}

#[test]
fn external_layout_names_rewrite_placeholder_field_certificates() {
    let signature = r2types::FunctionSignatureSpec {
        ret_type: None,
        params: vec![r2types::FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(r2types::CTypeLike::Pointer(Box::new(
                r2types::CTypeLike::Struct("DemoStruct".to_string()),
            ))),
        }],
    };
    let type_facts = FunctionTypeFacts {
        merged_signature: Some(signature),
        external_type_db: r2types::ExternalTypeDb {
            structs: HashMap::from([(
                "demostruct".to_string(),
                r2types::ExternalStruct {
                    name: "DemoStruct".to_string(),
                    fields: BTreeMap::from([(
                        48,
                        r2types::ExternalField {
                            name: "thirteenth".to_string(),
                            offset: 48,
                            ty: Some("int32_t".to_string()),
                        },
                    )]),
                },
            )]),
            ..r2types::ExternalTypeDb::default()
        },
        field_access_certificates: vec![r2types::FieldAccessCertificate {
            slot: 0,
            field_offset: 48,
            field_name: "f_30".to_string(),
            field_type: None,
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.normalize_field_certificates_from_external_layout();

    assert_eq!(
        facts.type_facts().field_access_certificates[0].field_name,
        "thirteenth"
    );
    assert_eq!(
        facts.type_facts().field_access_certificates[0]
            .field_type
            .as_deref(),
        Some("int32_t")
    );
}

#[test]
fn type_function_refuses_large_name_only_summary_preprobe() {
    let mut blocks = const_return_blocks(0x55a0, 0);
    for idx in 0..210 {
        blocks.push(R2ILBlock::new(0x5600 + idx, 1));
    }
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.type_function(EngineTypeAnalysisRequest {
        analysis: EngineAnalyzeRequest {
            function_name: "dbg.main".to_string(),
            function_addr: 0x55a0,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("dbg.main/type/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
        caller_prefers_bounded_type_plan: false,
    });

    assert!(
        response.is_none(),
        "a large name-only fixture has no prepared semantic owner to authorize a summary route"
    );
}

#[test]
fn function_analysis_artifact_request_builder_owns_analysis_policy() {
    let request = EngineFunctionAnalysisArtifactRequest::full_semantics_for_function(
        EngineFunctionAnalysisArtifactRequestInput {
            function: EngineFunctionInput {
                function_name: "dbg.artifact".to_string(),
                function_addr: 0x6600,
                blocks: Vec::new(),
                arch: None,
                source_snapshot: Some(test_source_snapshot("dbg.artifact/rev1")),
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(64),
            parsed_context: r2types::ParsedExternalContext::default(),
        },
    );

    assert_eq!(request.analysis.function_name, "dbg.artifact");
    assert_eq!(request.analysis.function_addr, 0x6600);
    assert_eq!(request.analysis.ptr_bits, 64);
    assert_eq!(request.analysis.semantic_mode, EngineSemanticMode::Full);
    assert!(request.analysis.include_interproc_summary_set);
    assert!(
        request.analysis.reg_type_hints.is_empty(),
        "request builder owns default register-hint policy"
    );
}

#[test]
fn decompile_function_uses_engine_summary_preprobe_without_plugin_policy() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function(EngineFunctionDecompileRequest {
        input_quality: None,
        analysis: EngineAnalyzeRequest {
            function_name: "dbg.init_node".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("dbg.init_node/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
    });

    assert!(response.output.text().contains("init_node"));
    let route = response
        .function_facts
        .decompile_route()
        .expect("decompile response should carry FunctionFacts route");
    assert_ne!(route.kind, r2types::DecompileRouteKind::SummaryIslands);
}

#[test]
fn decompile_function_from_input_refuses_incomplete_lifted_function() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function_from_input(EngineFunctionDecompileRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.partial".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.partial/rev1")),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        parsed_context,
        input_quality: EngineFunctionInputQuality {
            expected_blocks: 2,
            lifted_blocks: 1,
            read_failures: 1,
            invalid_blocks: 0,
            null_lift_failures: 0,
            truncated_blocks: 0,
        },
        execution: EngineExecutionControl::default(),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        tier: RenderTier::C,
    });

    assert!(
        response
            .output
            .text()
            .contains("incomplete lifted function input"),
        "{}",
        response.output
    );
    let route = response
        .function_facts
        .decompile_route()
        .expect("refusal route must travel through FunctionFacts");
    assert_eq!(route.kind, r2types::DecompileRouteKind::FallbackComment);
    assert!(
        route
            .fallback_comment
            .as_deref()
            .is_some_and(|comment| comment.contains("read_failures=1")),
        "{route:?}"
    );
    assert_eq!(
        response.diagnostics.refusal,
        route.fallback_comment.clone(),
        "engine diagnostics must derive refusal from FunctionFacts route"
    );
    let quality = response
        .input_quality
        .as_ref()
        .expect("input quality must remain response-local");
    assert_eq!(quality.expected_blocks, 2);
    assert_eq!(quality.lifted_blocks, 1);
    assert_eq!(quality.actual_lifted_blocks, 1);
    assert_eq!(quality.read_failures, 1);
    assert_eq!(
        quality.refusal_reason.as_deref(),
        Some(
            "incomplete lifted function input: expected_blocks=2 lifted_blocks=1 read_failures=1 invalid_blocks=0 null_lift_failures=0 truncated_blocks=0"
        )
    );
}

#[test]
fn decompile_function_from_input_refuses_inconsistent_lift_quality() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function_from_input(EngineFunctionDecompileRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.inconsistent".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.inconsistent/rev1")),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        parsed_context,
        input_quality: EngineFunctionInputQuality::complete(2),
        execution: EngineExecutionControl::default(),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        tier: RenderTier::C,
    });

    assert!(
        response
            .output
            .text()
            .contains("inconsistent lifted function input"),
        "{}",
        response.output
    );
    assert!(response.output.text().contains("actual_lifted_blocks=1"));
    let route = response
        .function_facts
        .decompile_route()
        .expect("refusal route must travel through FunctionFacts");
    assert_eq!(route.kind, r2types::DecompileRouteKind::FallbackComment);
    assert_eq!(response.diagnostics.refusal, route.fallback_comment.clone());
    let quality = response
        .input_quality
        .as_ref()
        .expect("input quality must remain response-local");
    assert_eq!(quality.expected_blocks, 2);
    assert_eq!(quality.lifted_blocks, 2);
    assert_eq!(quality.actual_lifted_blocks, 1);
    assert!(
        quality
            .refusal_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("actual_lifted_blocks=1")),
        "{quality:?}"
    );
}

#[test]
fn decompile_function_from_input_refuses_zero_lifted_function() {
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function_from_input(EngineFunctionDecompileRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.all_failed".to_string(),
            function_addr: 0x401000,
            blocks: Vec::new(),
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.all_failed/rev1")),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        parsed_context,
        input_quality: EngineFunctionInputQuality {
            expected_blocks: 1,
            lifted_blocks: 0,
            read_failures: 0,
            invalid_blocks: 0,
            null_lift_failures: 1,
            truncated_blocks: 0,
        },
        execution: EngineExecutionControl::default(),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        tier: RenderTier::C,
    });

    assert!(
        response
            .output
            .text()
            .contains("empty lifted function input"),
        "{}",
        response.output
    );
    assert!(response.output.text().contains("null_lift_failures=1"));
    let route = response
        .function_facts
        .decompile_route()
        .expect("refusal route must travel through FunctionFacts");
    assert_eq!(route.kind, r2types::DecompileRouteKind::FallbackComment);
    assert_eq!(response.diagnostics.refusal, route.fallback_comment.clone());
    let quality = response
        .input_quality
        .as_ref()
        .expect("input quality must remain response-local");
    assert_eq!(quality.expected_blocks, 1);
    assert_eq!(quality.lifted_blocks, 0);
    assert_eq!(quality.actual_lifted_blocks, 0);
    assert_eq!(quality.null_lift_failures, 1);
    assert!(
        quality
            .refusal_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("empty lifted function input")),
        "{quality:?}"
    );
}

#[test]
fn decompile_function_from_input_refuses_zero_expected_blocks() {
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function_from_input(EngineFunctionDecompileRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.empty".to_string(),
            function_addr: 0x401000,
            blocks: Vec::new(),
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.empty/rev1")),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        parsed_context,
        input_quality: EngineFunctionInputQuality::complete(0),
        execution: EngineExecutionControl::default(),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        tier: RenderTier::C,
    });

    assert!(
        response
            .output
            .text()
            .contains("empty lifted function input"),
        "{}",
        response.output
    );
    assert!(response.output.text().contains("expected_blocks=0"));
    let route = response
        .function_facts
        .decompile_route()
        .expect("refusal route must travel through FunctionFacts");
    assert_eq!(route.kind, r2types::DecompileRouteKind::FallbackComment);
    assert_eq!(response.diagnostics.refusal, route.fallback_comment.clone());
    let quality = response
        .input_quality
        .as_ref()
        .expect("input quality must remain response-local");
    assert_eq!(quality.expected_blocks, 0);
    assert_eq!(quality.lifted_blocks, 0);
    assert_eq!(quality.actual_lifted_blocks, 0);
    assert!(
        quality
            .refusal_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("expected_blocks=0")),
        "{quality:?}"
    );
}

#[test]
fn decompile_function_from_input_attaches_complete_input_quality() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function_from_input(EngineFunctionDecompileRequestInput {
        function: EngineFunctionInput {
            function_name: "sym.complete".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.complete/rev1")),
            semantic_metadata_enabled: false,
        },
        ptr_bits: Some(64),
        parsed_context,
        input_quality: EngineFunctionInputQuality::complete(1),
        execution: EngineExecutionControl::default(),
        trusted_ssa: None,
        callee_facts: Vec::new(),
        declared_signatures: Vec::new(),
        tier: RenderTier::C,
    });

    let quality = response
        .input_quality
        .as_ref()
        .expect("complete input quality must remain response-local");
    assert!(quality.is_complete(), "{quality:?}");
    assert_eq!(quality.expected_blocks, 1);
    assert_eq!(quality.lifted_blocks, 1);
    assert_eq!(quality.actual_lifted_blocks, 1);
    assert_eq!(quality.refusal_reason, None);
}

#[test]
fn decompile_function_refuses_incomplete_optional_input_quality() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function(EngineFunctionDecompileRequest {
        input_quality: Some(EngineFunctionInputQuality {
            expected_blocks: 2,
            lifted_blocks: 1,
            read_failures: 1,
            invalid_blocks: 0,
            null_lift_failures: 0,
            truncated_blocks: 0,
        }),
        analysis: EngineAnalyzeRequest {
            function_name: "sym.direct_partial".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.direct_partial/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
    });

    assert!(
        response
            .output
            .text()
            .contains("incomplete lifted function input"),
        "{}",
        response.output
    );
    let route = response
        .function_facts
        .decompile_route()
        .expect("refusal route must travel through FunctionFacts");
    assert_eq!(route.kind, r2types::DecompileRouteKind::FallbackComment);
    let quality = response
        .input_quality
        .as_ref()
        .expect("direct decompile refusal must retain input quality");
    assert_eq!(quality.expected_blocks, 2);
    assert_eq!(quality.lifted_blocks, 1);
    assert_eq!(quality.actual_lifted_blocks, 1);
    assert_eq!(quality.read_failures, 1);
    assert!(quality.refusal_reason.is_some());
}

#[test]
fn decompile_function_uses_canonical_display_identity_without_raw_payloads() {
    let blocks = const_return_blocks(0x401000, 0);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function(EngineFunctionDecompileRequest {
        input_quality: None,
        analysis: EngineAnalyzeRequest {
            function_name: "dbg.raw_name".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("dbg.raw_name/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
    });

    assert!(
        !response.output.text().contains("rendered_name"),
        "decompile display identity must come from canonical analysis input: {}",
        response.output
    );
    assert!(
        response.output.text().contains("raw_name"),
        "canonical analysis name must remain the r2engine display identity: {}",
        response.output
    );
    let route = response
        .function_facts
        .decompile_route()
        .expect("decompile response should carry FunctionFacts route");
    assert_ne!(route.kind, r2types::DecompileRouteKind::SummaryIslands);
}

#[test]
fn decompile_function_does_not_invent_raw_payload_callee_names() {
    let blocks = direct_call_return_blocks(0x401000, 0x5000);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function(EngineFunctionDecompileRequest {
        input_quality: None,
        analysis: EngineAnalyzeRequest {
            function_name: "sym.caller".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.caller/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
    });

    assert!(
        !response.output.text().contains("printf"),
        "uncertified raw callee names must not appear in rendered calls: {}",
        response.output
    );
    assert!(
        !response
            .function_facts
            .type_facts()
            .known_function_signatures
            .contains_key("printf"),
        "uncertified raw callee names must not seed FunctionFacts signatures"
    );
}

#[test]
fn decompile_function_does_not_invent_raw_payload_strings() {
    let blocks = const_return_blocks(0x401000, 0x6000);
    let parsed_context = r2types::ParsedExternalContext::default();
    let session = EngineSession::new();

    let response = session.decompile_function(EngineFunctionDecompileRequest {
        input_quality: None,
        analysis: EngineAnalyzeRequest {
            function_name: "sym.string_const".to_string(),
            function_addr: 0x401000,
            blocks,
            arch: None,
            source_snapshot: Some(test_source_snapshot("sym.string_const/rev1")),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
            ptr_bits: 64,
            semantic_metadata_enabled: false,
            reg_type_hints: HashMap::new(),
            parsed_context,
            semantic_mode: EngineSemanticMode::Full,
            include_interproc_summary_set: true,
            execution: EngineExecutionControl::default(),
        },
    });

    assert!(
        !response.output.text().contains("raw string payload"),
        "uncertified raw strings must not render as string literals: {}",
        response.output
    );
}

#[test]
fn decompile_request_builder_owns_analysis_policy() {
    let request = EngineFunctionDecompileRequest::full_semantics_for_function(
        EngineFunctionDecompileRequestInput {
            tier: RenderTier::C,
            function: EngineFunctionInput {
                function_name: "sym.demo".to_string(),
                function_addr: 0x401000,
                blocks: Vec::new(),
                arch: None,
                source_snapshot: Some(test_source_snapshot("sym.demo/rev1")),
                semantic_metadata_enabled: false,
            },
            ptr_bits: Some(64),
            parsed_context: r2types::ParsedExternalContext::default(),
            input_quality: EngineFunctionInputQuality::complete(0),
            execution: EngineExecutionControl::default(),
            trusted_ssa: None,
            callee_facts: Vec::new(),
            declared_signatures: Vec::new(),
        },
    );

    assert_eq!(request.analysis.function_name, "sym.demo");
    assert_eq!(request.analysis.function_addr, 0x401000);
    assert_eq!(request.analysis.ptr_bits, 64);
    assert_eq!(request.analysis.semantic_mode, EngineSemanticMode::Full);
    assert!(request.analysis.include_interproc_summary_set);
}

#[test]
fn engine_plan_maps_routes_to_work_levels() {
    let route = test_decompile_route(
        r2types::DecompileRouteKind::SummaryIslands,
        Some("summary"),
        None,
    );
    assert_eq!(
        select_engine_plan(EngineRequestKind::Decompile, Some(&route), None),
        EnginePlan::SemanticSummary
    );
    assert_eq!(
        select_engine_plan(EngineRequestKind::Decompile, None, None),
        EnginePlan::FastLocal
    );
}

#[test]
fn semantic_route_reason_preserves_exact_engine_route_reason() {
    for (route, expected) in [
        (
            test_decompile_route(
                r2types::DecompileRouteKind::StructuredWorker,
                Some("structured proof"),
                None,
            ),
            Some("structured proof".to_string()),
        ),
        (
            test_decompile_route(
                r2types::DecompileRouteKind::SummaryIslands,
                Some("summary islands"),
                None,
            ),
            Some("summary islands".to_string()),
        ),
        (
            test_decompile_route(
                r2types::DecompileRouteKind::LinearWorker,
                Some("linear worker"),
                None,
            ),
            Some("linear worker".to_string()),
        ),
        (
            test_decompile_route(
                r2types::DecompileRouteKind::VmSummary,
                Some("vm summary"),
                None,
            ),
            Some("vm summary".to_string()),
        ),
        (
            test_decompile_route(
                r2types::DecompileRouteKind::FallbackComment,
                Some("fallback comment"),
                Some("fallback comment"),
            ),
            Some("fallback comment".to_string()),
        ),
        (
            test_decompile_route(r2types::DecompileRouteKind::Standard, None, None),
            None,
        ),
    ] {
        assert_eq!(semantic_route_reason(&route), expected);
    }
}

#[test]
fn request_plans_cover_decompile_and_types() {
    let blocks = const_return_blocks(0x3010, 0);
    let prepared = r2ssa::SsaArtifact::for_decompile(&blocks, None).expect("prepared");
    let cfg_summary = prepared.function().cfg_risk_summary();
    let function_facts = FunctionFacts::default();

    let decompile =
        plan_decompile_request("sym.simple", &function_facts, Some(&prepared), &cfg_summary);
    assert_eq!(decompile.request(), EngineRequestKind::Decompile);
    assert_eq!(decompile.engine_plan(), EnginePlan::FastLocal);
    assert_eq!(decompile.diagnostics().plan, Some(EnginePlan::FastLocal));

    let types = plan_type_request(&function_facts, &cfg_summary, false);
    assert_eq!(types.request(), EngineRequestKind::Types);
    assert_eq!(types.engine_plan(), EnginePlan::PreparedOnly);
}

#[test]
fn request_plan_preserves_refusal_diagnostics() {
    let comment = "/* r2sleigh refused: semantic evidence unavailable */".to_string();
    let route = test_decompile_route(
        r2types::DecompileRouteKind::FallbackComment,
        Some(&comment),
        Some(&comment),
    );
    let decision = EngineRouteDecision {
        request: EngineRequestKind::Decompile,
        plan: select_engine_plan(EngineRequestKind::Decompile, Some(&route), None),
        route,
    };

    let request_plan = EngineRequestPlan::decompile(decision);
    let diagnostics = request_plan.diagnostics();

    assert_eq!(request_plan.engine_plan(), EnginePlan::RefuseWithEvidence);
    assert_eq!(diagnostics.refusal, Some(comment.clone()));
    assert_eq!(diagnostics.route_reason, Some(comment));
}

#[test]
fn phase_timing_reports_executed_phases_and_omits_the_rest() {
    let mut metrics = EngineMetrics::default();
    metrics.record_phase(
        EnginePhase::Ssa,
        EnginePhaseStatus::Executed,
        Duration::from_micros(4_000),
    );
    metrics.record_phase(
        EnginePhase::Rendering,
        EnginePhaseStatus::Executed,
        Duration::from_micros(11_500),
    );
    metrics.record_phase(
        EnginePhase::Types,
        EnginePhaseStatus::Folded,
        Duration::default(),
    );
    let comment = format_phase_timing(&metrics);
    assert_eq!(
        comment,
        "/* r2dec timing: measured=15500us work=0 ssa=4000us types=folded rendering=11500us */"
    );
    // A phase this boundary never ran says nothing, rather than claiming
    // it cost nothing.
    assert!(!comment.contains("symbolic"));
}

#[test]
fn phase_timing_survives_a_refusal_so_refusing_can_be_compared_with_rendering() {
    let mut metrics = EngineMetrics::default();
    metrics.record_phase(
        EnginePhase::SnapshotContext,
        EnginePhaseStatus::Executed,
        Duration::from_micros(120),
    );
    metrics.refuse_from(EnginePhase::LiftNormalize);
    let comment = format_phase_timing(&metrics);
    assert!(
        comment.starts_with("/* r2dec timing: measured=120us"),
        "{comment}"
    );
    assert!(comment.contains("lift_normalize=refused"), "{comment}");
}

#[test]
fn a_panic_caught_at_rendering_refuses_from_its_own_phase_and_claims_none_before() {
    // The response used to say every phase from the snapshot on was refused,
    // which named the snapshot as where a rendering defect stopped the work.
    let panicked = isolation::Panicked {
        location: None,
        message: "a defect in the renderer".to_owned(),
    };
    let response = panicked_decompile_response("f", &panicked, EnginePhase::Structuring);
    let status = |phase| {
        let mut timings = response.metrics.phase_timings.iter();
        timings
            .find(|timing| timing.phase == phase)
            .map(|timing| timing.status)
    };
    for phase in [EnginePhase::SnapshotContext, EnginePhase::Types] {
        let status = status(phase);
        assert_eq!(status, Some(EnginePhaseStatus::NotExecuted), "{phase:?}");
    }
    for phase in [EnginePhase::Structuring, EnginePhase::Rendering] {
        assert_eq!(status(phase), Some(EnginePhaseStatus::Refused), "{phase:?}");
    }
    let text = response.output.text();
    assert!(text.contains("a defect in the renderer"), "{text}");
}
