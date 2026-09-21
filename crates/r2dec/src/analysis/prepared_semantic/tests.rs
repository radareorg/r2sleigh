use super::*;
use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};
use r2ssa::InterprocSummarySet;

/// The names a fixture in this module declares.
fn test_table() -> std::cell::RefCell<crate::symbol::SymbolTable> {
    std::cell::RefCell::new(crate::symbol::SymbolTable::new())
}

/// Two variables cannot share one value, and a claim that they do poisons
/// both rather than picking one.
///
/// The graph is now the only oracle for which value a variable names, and
/// it is injective, so this contradiction cannot arrive through it. The
/// guard stays because the identity table is what enforces the rule, and
/// the test states it where the rule lives.
#[test]
fn prepared_copy_binding_rejects_shared_value_id_before_fact_seeding() {
    let dst = SSAVar::new("dst", 1, 8);
    let src = SSAVar::new("src", 1, 8);

    let mut info = UseInfo::default();
    assert_eq!(info.bind_value_id(&dst, ValueId(1)), Some(ValueId(1)));
    assert_eq!(info.bind_value_id(&src, ValueId(1)), None);
    info.forwarded_values_by_value.retain(|_, _| false);

    assert!(info.forwarded_values_by_value.is_empty());
    assert_eq!(info.value_id_for_var(&dst), None);
    assert_eq!(info.value_id_for_var(&src), None);
}

#[test]
fn prepared_copy_provenance_ignores_colliding_display_fact() {
    let dst = SSAVar::new("dst", 1, 8);
    let src = SSAVar::constant(1, 8).renamed("same");
    let spoof = SSAVar::constant(2, 8).renamed("same");
    assert_eq!(src.display_name(), spoof.display_name());
    assert_ne!(src, spoof);

    let mut info = UseInfo::default();
    assert_eq!(info.bind_value_id(&spoof, ValueId(3)), Some(ValueId(3)));
    // The spoof's forwarding fact is filed under the spoof's identity. There
    // is no name-keyed half for it to be filed under any more, which is what
    // makes the collision this test was written for impossible rather than
    // merely avoided: `src` and `spoof` share a display name and differ as
    // values, and a store keyed by value cannot confuse them.
    info.forwarded_values_by_value.insert(
        ValueId(3),
        ValueProvenance {
            source: spoof.display_name(),
            source_value_id: Some(ValueId(3)),
            source_var: Some(spoof),
            stack_slot: Some(-8),
        },
    );

    assert_eq!(info.bind_value_id(&dst, ValueId(1)), Some(ValueId(1)));
    assert_eq!(info.bind_value_id(&src, ValueId(2)), Some(ValueId(2)));
    let (dst_id, src_id) = (
        info.exact_value_id_for_var(&dst)
            .expect("exact copy target"),
        info.exact_value_id_for_var(&src)
            .expect("exact copy source"),
    );
    assert_eq!((dst_id, src_id), (ValueId(1), ValueId(2)));
    assert_eq!(info.forwarded_value_for_var(&src), None);

    let provenance = exact_prepared_copy_provenance(&src, src_id, Some(-8));
    assert_eq!(provenance.source_value_id, Some(ValueId(2)));
    assert_eq!(provenance.source_var, Some(src));
}

#[test]
fn canonical_frame_pointer_slot_uses_runtime_offset() {
    let slot = StackSlotKey {
        base: ExternalStackBase::FramePointer,
        offset: 8,
    };
    assert_eq!(prepared_stack_slot_offset(&slot), -8);

    let legacy_slot = StackSlotKey {
        base: ExternalStackBase::FramePointer,
        offset: -8,
    };
    assert_eq!(prepared_stack_slot_offset(&legacy_slot), -8);
}

fn test_var(name: &str, version: u32, size: u32) -> SSAVar {
    SSAVar::new(name, version, size)
}

fn test_prepared_constant(value: u64) -> (SsaArtifact, SSAVar) {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x100, 8),
        src: Varnode::constant(value, 8),
    });
    let prepared = SsaArtifact::from_blocks(&[block], None).expect("prepared constant SSA");
    let constant = prepared
        .graph()
        .values
        .iter()
        .find(|candidate| candidate.var.constant_bits() == Some(value))
        .expect("exact graph constant")
        .var
        .clone();
    (prepared, constant)
}

#[test]
fn prepared_constants_require_exact_graph_constant_storage() {
    let (prepared, constant) = test_prepared_constant(0x40);
    assert_eq!(
        compare_style_operand_expr(&prepared, &constant, 8),
        Some(CExpr::IntLit(0x40))
    );

    for spoof in ["0d64", "0x40", "40", "deadbeef", "const:40"] {
        assert_eq!(
            compare_style_operand_expr(&prepared, &test_var(spoof, 0, 8), 8),
            None,
            "presentation spelling {spoof:?} is not constant evidence"
        );
    }

    let foreign = constant.renamed("0x40");
    assert_eq!(foreign.constant_bits(), Some(0x40));
    assert_eq!(
        compare_style_operand_expr(&prepared, &foreign, 8),
        None,
        "typed bits without exact graph identity and Constant storage must fail closed"
    );
}

#[test]
fn signed_dividend_shift_requires_exact_constant_identity() {
    let (prepared, shift) = test_prepared_constant(64);
    let limb = test_var("limb", 1, 8);
    assert!(prepared_shift_matches_signed_concat_width(
        &prepared, &shift, &limb, &limb, &limb
    ));
    assert!(!prepared_shift_matches_signed_concat_width(
        &prepared,
        &test_var("const:40", 0, 8),
        &limb,
        &limb,
        &limb
    ));
}

fn test_prepared_call_artifact() -> SsaArtifact {
    let mut block = R2ILBlock::new(0x1000, 5);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x401000, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    SsaArtifact::from_blocks(&[block], None).expect("prepared call SSA artifact")
}

fn test_prepared_recursive_call_artifact() -> SsaArtifact {
    let mut block = R2ILBlock::new(0x1500, 8);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x1500, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    SsaArtifact::raw(&[block], None)
        .expect("prepared recursive call SSA artifact")
        .with_name("sym.self")
}

fn test_x86_64_arg_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("RDI", 0x10, 8));
    arch.add_register(RegisterDef::new("RSI", 0x18, 8));
    arch.add_register(RegisterDef::new("RSP", 0x28, 8));
    arch.add_register(RegisterDef::new("RIP", 0x30, 8));
    arch
}

fn test_x86_64_result_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rsp", 16, 8));
    arch.add_register(RegisterDef::new("rbp", 24, 8));
    arch
}

fn test_prepared_two_arg_call_artifact() -> SsaArtifact {
    let arch = test_x86_64_arg_arch();
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0x10, 8),
        src: Varnode::constant(7, 8),
    });
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0x18, 8),
        src: Varnode::constant(9, 8),
    });
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x401000, 8),
    });
    block.stamp_instruction(2, 0x1002);
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let revision = b"prepared-semantic-two-arg-call";
    let function_interface = r2ssa::SourceFunctionInterface::new_exact(
        revision.to_vec(),
        "sysv64",
        [
            r2ssa::SourceAbiParameterSpec::new(0, storage(0x10)),
            r2ssa::SourceAbiParameterSpec::new(1, storage(0x18)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
    .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
    .expect("exact two-arg function interface");
    let call_target = Varnode::constant(0x401000, 8);
    let call_interface = r2ssa::SourceCallSiteInterface::new(
        revision.to_vec(),
        r2ssa::SourceCallSiteIdentity::new(
            0x1002,
            r2ssa::CanonicalStorageId::from_varnode(&call_target),
        ),
        true,
        "sysv64",
        [
            r2ssa::SourceCallArgumentSpec::new(0, storage(0x10)),
            r2ssa::SourceCallArgumentSpec::new(1, storage(0x18)),
        ],
        false,
        false,
        r2ssa::SourceCallResult::Void,
    )
    .expect("exact two-arg callsite interface");
    SsaArtifact::for_decompile_with_interfaces(
        &[block],
        Some(&arch),
        Some(function_interface),
        vec![call_interface],
    )
    .expect("prepared two-arg call SSA artifact")
}

fn test_prepared_stack_owned_call_result_artifact() -> SsaArtifact {
    let arch = test_x86_64_result_arch();
    let slot = Varnode::unique(0x1780, 8);
    let stored = Varnode::unique(0x1788, 8);
    let loaded = Varnode::unique(0x1790, 8);
    let alias = Varnode::unique(0x1798, 8);
    let mut block = R2ILBlock::new(0x1780, 6);
    block.push(R2ILOp::IntAdd {
        dst: slot.clone(),
        a: Varnode::register(16, 8),
        b: Varnode::constant(u64::MAX - 7, 8),
    });
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x401000, 8),
    });
    block.push(R2ILOp::Copy {
        dst: stored.clone(),
        src: Varnode::register(0, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: slot.clone(),
        val: stored,
    });
    block.push(R2ILOp::Load {
        dst: loaded.clone(),
        space: SpaceId::Ram,
        addr: slot,
    });
    block.push(R2ILOp::Copy {
        dst: alias,
        src: loaded,
    });
    SsaArtifact::for_decompile(&[block], Some(&arch))
        .expect("prepared stack-owned call result SSA artifact")
}

/// The one call the fixture makes, found rather than indexed: construction
/// emits a boundary read before every call, so the call's operation index
/// is not a property of the fixture's own operations.
fn sole_callsite_key(prepared: &SsaArtifact) -> CallsiteKey {
    let mut sites = prepared
        .certificates()
        .callsites
        .values()
        .filter_map(|cert| {
            prepared
                .inst_op_site(cert.at)
                .map(|(block_addr, op_index)| CallsiteKey {
                    block_addr,
                    op_index,
                })
        });
    let site = sites.next().expect("fixture makes one call");
    assert!(sites.next().is_none(), "fixture makes one call");
    site
}

fn test_callsite_facts(prepared: &SsaArtifact) -> r2types::FunctionCallsiteFacts {
    let by_callsite = prepared
        .certificates()
        .callsites
        .values()
        .filter_map(|cert| {
            let (block_addr, op_index) = prepared.inst_op_site(cert.at)?;
            let callsite = CallsiteKey {
                block_addr,
                op_index,
            };
            let register_argument_locations = cert
                .argument_certificates
                .iter()
                .filter_map(|argument| {
                    let r2ssa::CallArgumentLocation::Register { storage } = argument.location
                    else {
                        return None;
                    };
                    Some(r2types::RegisterCallArgumentLocationFact {
                        index: argument.index,
                        value: argument.value,
                        storage,
                        source_inst: argument.source_inst,
                    })
                })
                .collect();
            let stack_argument_locations = cert
                .argument_certificates
                .iter()
                .filter_map(|argument| {
                    let r2ssa::CallArgumentLocation::Stack {
                        object,
                        offset,
                        memory_access,
                    } = argument.location
                    else {
                        return None;
                    };
                    Some(r2types::StackCallArgumentLocationFact {
                        index: argument.index,
                        value: argument.value,
                        object,
                        offset,
                        memory_access,
                        source_inst: argument.source_inst,
                    })
                })
                .collect();
            Some((
                callsite,
                r2types::CallsiteArgumentFacts {
                    callsite,
                    call_site_id: cert.call_site,
                    at: cert.at,
                    target: cert.target,
                    direct_target: cert.direct_target,
                    argument_values: cert
                        .argument_values
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(index, value)| r2types::CallArgumentValueFact { index, value })
                        .collect(),
                    variadic: cert.variadic,
                    fixed_argument_count: cert.fixed_argument_count,
                    callee_signature: None,
                    callee_signature_from_source_types: false,
                    variadic_argument_count_evidence: cert.variadic_argument_count_evidence,
                    variadic_argument_count_refusal: cert.variadic_argument_count_refusal,
                    register_argument_locations,
                    stack_argument_locations,
                    arguments_complete: true,
                    results_complete: true,
                },
            ))
        })
        .collect();
    r2types::FunctionCallsiteFacts { by_callsite }
}

fn leak_function_facts(facts: FunctionFacts) -> &'static FunctionFacts {
    Box::leak(Box::new(facts))
}

#[test]
fn prepared_call_expr_requires_argument_value_bijection() {
    let symbols = test_table();
    let unproved = PreparedCallView {
        callee_identity: Some(CalleeIdentity::from_name("sym.helper")),
        authoritative_args: vec![CExpr::IntLit(7)],
        authoritative_arg_values: Vec::new(),
        ..PreparedCallView::default()
    };
    assert!(
        prepared_call_expr_from_view(&symbols, &unproved).is_none(),
        "prepared call expressions must not carry rendered args without ValueId proof"
    );

    let missing_render_fact = PreparedCallView {
        callee_identity: Some(CalleeIdentity::from_name("sym.helper")),
        authoritative_args: vec![CExpr::IntLit(7)],
        authoritative_arg_values: vec![ValueId(7)],
        ..PreparedCallView::default()
    };
    assert!(
        prepared_call_expr_from_view(&symbols, &missing_render_fact).is_none(),
        "prepared call expressions require FunctionFacts call-render authorization"
    );

    let proved = PreparedCallView {
        callee_identity: Some(CalleeIdentity::from_name("sym.helper")),
        authoritative_args: vec![CExpr::IntLit(7)],
        authoritative_arg_values: vec![ValueId(7)],
        render_fact: Some(r2types::CallsiteRenderFact {
            callsite: CallsiteKey {
                block_addr: 0x1000,
                op_index: 0,
            },
            target: None,
            disposition: r2types::CallsiteRenderDisposition::Statement,
            proof_values: vec![ValueId(7)],
            residual_reason: None,
        }),
        ..PreparedCallView::default()
    };
    assert_eq!(
        prepared_call_expr_from_view(&symbols, &proved),
        Some(CExpr::Call {
            func: Box::new(CExpr::External {
                name: "sym.helper".to_string(),
                kind: crate::symbol::ExternalKind::Function,
            }),
            args: vec![CExpr::IntLit(7)],
            site: None,
        })
    );
}

#[test]
fn prepared_view_prefers_typed_callee_resolution_over_raw_name_maps() {
    let symbols = test_table();
    let prepared = test_prepared_call_artifact();
    let resolution_function_names = HashMap::from([(0x401000, "sym.imp.printf".to_string())]);
    let binary_symbols = HashMap::new();
    let callee_facts = BTreeMap::new();
    let known_function_signatures = HashMap::new();
    let resolution_ctx = r2types::CalleeIdentityContext {
        function_names: &resolution_function_names,
        symbols: &binary_symbols,
        callee_facts: &callee_facts,
        known_function_signatures: &known_function_signatures,
    };
    let callee_resolution = CalleeResolutionFacts::from_direct_call_targets(
        [(
            CallsiteKey {
                block_addr: 0x1000,
                op_index: 0,
            },
            0x401000,
        )],
        &resolution_ctx,
    );
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let function_facts = FunctionFacts::default().with_callee_resolution(callee_resolution.clone());

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site((0x1000, 0))
        .expect("direct callsite should have prepared call view");
    let identity = call_view
        .callee_identity
        .as_ref()
        .expect("direct callsite should have typed callee identity");
    assert_eq!(identity.display_name.as_deref(), Some("sym.imp.printf"));
    assert_eq!(identity.primary_key(), "printf");
    assert!(identity.is_imported_name_hint());
    let resolved =
        CalleeResolutionFacts::resolve_target_policy(r2types::CalleeTargetResolutionRequest {
            identity: CalleeTargetIdentityRequest {
                resolution: Some(&callee_resolution),
                callsite: None,
                prepared_identity: Some(identity),
                prepared_direct_target: None,
                direct_target_context: None,
            },
            callee_facts: &callee_facts,
        })
        .expect("typed callee identity should resolve policy");
    assert!(
        !resolved.policy.imported,
        "typed function names alone must not authorize imported-call policy"
    );
}

#[test]
fn prepared_view_uses_typed_direct_addr_identity_through_callsite_facts() {
    let symbols = test_table();
    let prepared = test_prepared_call_artifact();
    let key = r2types::CalleeIdentityKey::DirectAddress(0x401000);
    let mut callee_resolution = CalleeResolutionFacts::default();
    callee_resolution
        .by_direct_addr
        .insert(0x401000, key.clone());
    callee_resolution
        .by_key
        .insert(key, CalleeIdentity::from_name("sym.imp.printf"));
    let callee_facts = BTreeMap::new();
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let callsite_facts = test_callsite_facts(&prepared);
    let function_facts = FunctionFacts::default()
        .with_callee_resolution(callee_resolution.clone())
        .with_callsites(callsite_facts);

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site((0x1000, 0))
        .expect("direct callsite should have prepared call view");
    assert_eq!(call_view.direct_target, Some(0x401000));
    let identity = call_view
        .callee_identity
        .as_ref()
        .expect("direct-address identity should be certified through callsite facts");
    assert_eq!(identity.display_name.as_deref(), Some("sym.imp.printf"));
    assert!(identity.is_imported_name_hint());
    let resolved =
        CalleeResolutionFacts::resolve_target_policy(r2types::CalleeTargetResolutionRequest {
            identity: CalleeTargetIdentityRequest {
                resolution: Some(&callee_resolution),
                callsite: None,
                prepared_identity: Some(identity),
                prepared_direct_target: None,
                direct_target_context: None,
            },
            callee_facts: &callee_facts,
        })
        .expect("direct-address callee identity should resolve policy");
    assert!(
        !resolved.policy.imported,
        "direct-address identities built from raw names remain import hints only"
    );
}

#[test]
fn prepared_view_requires_callsite_facts_for_direct_addr_identity() {
    let symbols = test_table();
    let prepared = test_prepared_call_artifact();
    let key = r2types::CalleeIdentityKey::DirectAddress(0x401000);
    let mut callee_resolution = CalleeResolutionFacts::default();
    callee_resolution
        .by_direct_addr
        .insert(0x401000, key.clone());
    callee_resolution
        .by_key
        .insert(key, CalleeIdentity::from_name("sym.imp.printf"));
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let function_facts = FunctionFacts::default().with_callee_resolution(callee_resolution.clone());

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site((0x1000, 0))
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view.direct_target, None,
        "prepared semantic view must not reparse direct targets from SSA names"
    );
    assert!(
        call_view.callee_identity.is_none(),
        "direct-address callee identity requires FunctionFacts direct-target evidence"
    );
}

#[test]
fn prepared_view_refuses_raw_callee_identity_without_typed_resolution() {
    let symbols = test_table();
    let prepared = test_prepared_call_artifact();
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: leak_function_facts(FunctionFacts::default()),
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site((0x1000, 0))
        .expect("direct callsite should have prepared call view");
    assert!(
        call_view.callee_identity.is_none(),
        "prepared semantic view must not certify raw callee names without typed resolution"
    );
    assert!(
        prepared_call_expr_from_view(&symbols, call_view).is_none(),
        "prepared calls must not fall back to fabricated sub_<addr> expressions"
    );
}

#[test]
fn prepared_view_refuses_recursive_name_identity_without_typed_resolution() {
    let symbols = test_table();
    let prepared = test_prepared_recursive_call_artifact();
    assert_eq!(
        prepared.structured().recursive_calls.len(),
        1,
        "fixture should expose a structural recursive call"
    );
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: leak_function_facts(FunctionFacts::default()),
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site((0x1500, 0))
        .expect("recursive direct callsite should have prepared call view");
    assert!(
        call_view.callee_identity.is_none(),
        "recursive function names are not callee identity evidence"
    );
}

/// The callee's recovered signature names one parameter and the call site
/// certificate carries two arguments. Two is the answer: how many
/// arguments a call passes is a fact about the call, and cutting the list
/// down to what the callee is declared to take is how every call to a
/// variadic callee came out with the same arity.
#[test]
fn prepared_call_arity_comes_from_the_call_site_not_the_callee_signature() {
    let symbols = test_table();
    let prepared = test_prepared_two_arg_call_artifact();
    let typed_function_names = HashMap::from([(0x401000, "sym.imp.one_arg".to_string())]);
    let binary_symbols = HashMap::new();
    let callee_facts = BTreeMap::new();
    let known_function_signatures = HashMap::from([(
        "sym.imp.one_arg".to_string(),
        r2types::FunctionType {
            return_type: r2types::CTypeLike::Void,
            params: vec![r2types::CTypeLike::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            }],
            variadic: false,
        },
    )]);
    let resolution_ctx = r2types::CalleeIdentityContext {
        function_names: &typed_function_names,
        symbols: &binary_symbols,
        callee_facts: &callee_facts,
        known_function_signatures: &known_function_signatures,
    };
    let callee_resolution = CalleeResolutionFacts::from_direct_call_targets(
        [(sole_callsite_key(&prepared), 0x401000)],
        &resolution_ctx,
    );
    let mut summaries = InterprocSummarySet::default();
    let summary_id = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(summary_id, Some("sym.local_two_arg".into()));
    summary.arg_count_hint = Some(2);
    summaries.summaries.insert(summary_id, summary);
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let callsite_facts = test_callsite_facts(&prepared);
    let function_facts = FunctionFacts::default()
        .with_callee_resolution(callee_resolution)
        .with_callsites(callsite_facts);

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site({
            let site = sole_callsite_key(&prepared);
            (site.block_addr, site.op_index)
        })
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view
            .callee_identity
            .as_ref()
            .and_then(CalleeIdentity::non_variadic_known_arity),
        Some(1)
    );
    assert_eq!(
        call_view.authoritative_args,
        vec![CExpr::IntLit(7), CExpr::IntLit(9)]
    );
}

#[test]
fn prepared_call_args_require_function_facts_callsite_contract() {
    let symbols = test_table();
    let prepared = test_prepared_two_arg_call_artifact();
    let mut summaries = InterprocSummarySet::default();
    let summary_id = r2ssa::InterprocFunctionId(0x401000);
    let mut summary =
        r2ssa::FunctionSemanticSummary::unknown(summary_id, Some("sym.local_two_arg".into()));
    summary.arg_count_hint = Some(1);
    summaries.summaries.insert(summary_id, summary);
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: leak_function_facts(FunctionFacts::default()),
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site({
            let site = sole_callsite_key(&prepared);
            (site.block_addr, site.op_index)
        })
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view.authoritative_args,
        Vec::<CExpr>::new(),
        "prepared call rendering must not infer authoritative args without FunctionFacts callsite facts"
    );
}

#[test]
fn prepared_call_args_require_function_facts_location_contract() {
    let symbols = test_table();
    let prepared = test_prepared_two_arg_call_artifact();
    let mut callsite_facts = test_callsite_facts(&prepared);
    let call_facts = callsite_facts
        .by_callsite
        .get_mut(&sole_callsite_key(&prepared))
        .expect("fixture callsite facts");
    call_facts.register_argument_locations.clear();
    call_facts.stack_argument_locations.clear();
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let function_facts = FunctionFacts::default().with_callsites(callsite_facts.clone());

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site({
            let site = sole_callsite_key(&prepared);
            (site.block_addr, site.op_index)
        })
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view.authoritative_args,
        Vec::<CExpr>::new(),
        "ordered values alone must not authorize executable call args without location proof"
    );
}

#[test]
fn prepared_call_args_use_function_facts_callsite_contract() {
    let symbols = test_table();
    let prepared = test_prepared_two_arg_call_artifact();
    let callsite_facts = test_callsite_facts(&prepared);
    let stack_slots = BTreeMap::new();
    let visible_bindings = Vec::new();
    let function_facts = FunctionFacts::default().with_callsites(callsite_facts);

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: &function_facts,
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site({
            let site = sole_callsite_key(&prepared);
            (site.block_addr, site.op_index)
        })
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view.authoritative_args,
        vec![CExpr::IntLit(7), CExpr::IntLit(9)]
    );
}

#[test]
fn prepared_call_result_owner_requires_function_facts_contract() {
    let symbols = test_table();
    let prepared = test_prepared_stack_owned_call_result_artifact();
    let stack_slots = BTreeMap::from([(
        StackSlotKey {
            base: r2types::ExternalStackBase::StackPointer,
            offset: -8,
        },
        ExternalStackSlotSpec {
            name: "call_result".to_string(),
            role: ExternalStackSlotRole::Local,
            ..ExternalStackSlotSpec::default()
        },
    )]);
    let visible_bindings = Vec::new();

    let view = PreparedSemanticView::build(
        &symbols,
        PreparedSemanticViewInputs {
            prepared: &prepared,
            stack_slots: &stack_slots,
            visible_bindings: &visible_bindings,
            function_facts: leak_function_facts(FunctionFacts::default()),
            certified_rendering_required: false,
        },
    );

    let call_view = view
        .call_view_for_site({
            let site = sole_callsite_key(&prepared);
            (site.block_addr, site.op_index)
        })
        .expect("direct callsite should have prepared call view");
    assert_eq!(
        call_view.result_owner, None,
        "prepared SSA call-result certificates must not bypass FunctionFacts"
    );
    assert!(
        view.call_result_source_by_value.is_empty(),
        "call-result source indexes must be populated from FunctionFacts, not local prepared SSA reads"
    );
}

/// Without a binding plan, nothing is spelled at all.
///
/// This used to assert an ordering: that a storage spelling must not
/// preempt the value projection. The ordering existed because an alias
/// ladder could answer the same question, and every table it consulted had
/// no writer, so it decided nothing while still being a second answerer.
/// With the ladder gone the ordering question does not arise, and what is
/// worth pinning is that the projection is the only source of a name.
#[test]
fn no_binding_plan_spells_nothing() {
    let symbols = test_table();
    let (prepared, _) = test_prepared_constant(1);
    let view = PreparedSemanticView::default();
    for var in [
        SSAVar::constant(1, 8),
        test_var("tmp:1", 0, 8),
        test_var("ram:401000", 0, 8),
        test_var("unique:1", 0, 8),
        test_var("const:40", 0, 8),
    ] {
        assert_eq!(
            prepared_fallback_visible_expr(&symbols, &prepared, &view, &var),
            None,
            "an empty binding plan cannot name {var:?}"
        );
    }
}
