use super::*;
use crate::{ExternalStackBase, FunctionParamSpec};
use r2il::{
    ArchSpec, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
    RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[test]
fn constant_looking_spelling_is_not_constant_evidence() {
    assert_eq!(
        const_var_i64(&r2ssa::SSAVar::new("const:ffffffffffffffb8", 0, 8)),
        None
    );
    assert_eq!(
        const_var_i64(&r2ssa::SSAVar::constant(0xffff_ffff_ffff_ffb8, 8)),
        Some(-72)
    );
}

#[test]
fn parameter_coalescing_values_are_exact_entry_membership() {
    let entry_values = BTreeSet::from([r2ssa::ValueId(7), r2ssa::ValueId(2), r2ssa::ValueId(11)]);
    let entity = CertifiedEntity::Parameter {
        id: r2ssa::SemanticId::Parameter(0),
        slot: 0,
        entry_values: entry_values.clone(),
        home_reload_values: BTreeSet::from([r2ssa::ValueId(20)]),
        carrier_width: 8,
        ty: None,
    };

    // The home slot's reloads are the parameter too: the slot is its
    // storage, so a register the body fills from it is not a copy.
    let mut expected = entry_values;
    expected.insert(r2ssa::ValueId(20));
    assert_eq!(entity.coalescing_values(), Some(expected));
}

#[test]
fn loop_carrier_coalescing_values_cover_every_program_point_role() {
    let entity = CertifiedEntity::LoopCarrier {
        id: r2ssa::SemanticId::LoopCarrier(r2ssa::ValueId(1)),
        loop_id: r2ssa::LoopId(0),
        header: 0x401000,
        phi: r2ssa::ValueId(1),
        width: 4,
        identity_values: BTreeSet::from([r2ssa::ValueId(4), r2ssa::ValueId(1)]),
        entries: vec![
            r2ssa::LoopCarrierEdgeValue {
                predecessor: 0x400ff0,
                value: r2ssa::ValueId(7),
                site: r2ssa::UseSite {
                    inst: r2ssa::InstId(20),
                    input_idx: 0,
                },
            },
            r2ssa::LoopCarrierEdgeValue {
                predecessor: 0x400fe0,
                value: r2ssa::ValueId(3),
                site: r2ssa::UseSite {
                    inst: r2ssa::InstId(20),
                    input_idx: 1,
                },
            },
        ],
        updates: vec![r2ssa::LoopCarrierUpdateFact {
            predecessor: 0x401010,
            value: r2ssa::ValueId(9),
            site: r2ssa::UseSite {
                inst: r2ssa::InstId(20),
                input_idx: 2,
            },
            identity_values: BTreeSet::from([r2ssa::ValueId(8), r2ssa::ValueId(2)]),
        }],
        dominating_initializers: vec![
            r2ssa::LoopCarrierEdgeValue {
                predecessor: 0x400fd0,
                value: r2ssa::ValueId(6),
                site: r2ssa::UseSite {
                    inst: r2ssa::InstId(30),
                    input_idx: 0,
                },
            },
            r2ssa::LoopCarrierEdgeValue {
                predecessor: 0x400fc0,
                value: r2ssa::ValueId(3),
                site: r2ssa::UseSite {
                    inst: r2ssa::InstId(30),
                    input_idx: 1,
                },
            },
        ],
        // Every member shares a run with the carrier; all but one also
        // hold a role the carrier proved, and that one is the span's to
        // offer rather than the carrier's to claim.
        members: [1, 2, 3, 4, 6, 7, 8, 9]
            .into_iter()
            .map(|value| r2ssa::LoopCarrierMemberFact {
                value: r2ssa::ValueId(value),
                roles: if value == 4 {
                    BTreeSet::from([r2ssa::LoopCarrierMemberRole::StorageContinuation])
                } else {
                    BTreeSet::from([
                        r2ssa::LoopCarrierMemberRole::StorageContinuation,
                        r2ssa::LoopCarrierMemberRole::Entry,
                    ])
                },
            })
            .collect(),
        ty: None,
    };

    assert_eq!(
        entity.coalescing_values(),
        Some(BTreeSet::from([
            r2ssa::ValueId(1),
            r2ssa::ValueId(2),
            r2ssa::ValueId(3),
            r2ssa::ValueId(6),
            r2ssa::ValueId(7),
            r2ssa::ValueId(8),
            r2ssa::ValueId(9),
        ]))
    );
}

#[test]
fn coalescing_membership_is_order_independent_and_stack_slots_refuse_it() {
    let edge = |predecessor, value| r2ssa::LoopCarrierEdgeValue {
        predecessor,
        value: r2ssa::ValueId(value),
        site: r2ssa::UseSite {
            inst: r2ssa::InstId(value),
            input_idx: 0,
        },
    };
    let update = |predecessor, value, identities| r2ssa::LoopCarrierUpdateFact {
        predecessor,
        value: r2ssa::ValueId(value),
        site: r2ssa::UseSite {
            inst: r2ssa::InstId(value),
            input_idx: 0,
        },
        identity_values: identities,
    };
    let make_carrier =
        |entries, updates, dominating_initializers, members| CertifiedEntity::LoopCarrier {
            id: r2ssa::SemanticId::LoopCarrier(r2ssa::ValueId(1)),
            loop_id: r2ssa::LoopId(0),
            header: 0x401000,
            phi: r2ssa::ValueId(1),
            width: 8,
            identity_values: BTreeSet::from([r2ssa::ValueId(5), r2ssa::ValueId(1)]),
            entries,
            updates,
            dominating_initializers,
            members,
            ty: None,
        };
    let members = |values: Vec<u32>| {
        values
            .into_iter()
            .map(|value| r2ssa::LoopCarrierMemberFact {
                value: r2ssa::ValueId(value),
                roles: BTreeSet::from([r2ssa::LoopCarrierMemberRole::StorageContinuation]),
            })
            .collect::<Vec<_>>()
    };
    let forward = make_carrier(
        vec![edge(10, 2), edge(20, 3)],
        vec![
            update(30, 4, BTreeSet::from([r2ssa::ValueId(6)])),
            update(40, 7, BTreeSet::from([r2ssa::ValueId(8)])),
        ],
        vec![edge(50, 9), edge(60, 10)],
        members(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    );
    let reversed = make_carrier(
        vec![edge(20, 3), edge(10, 2)],
        vec![
            update(40, 7, BTreeSet::from([r2ssa::ValueId(8)])),
            update(30, 4, BTreeSet::from([r2ssa::ValueId(6)])),
        ],
        vec![edge(60, 10), edge(50, 9)],
        members(vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
    );
    let object = r2ssa::ObjectId(3);
    let stack_slot = CertifiedEntity::StackSlot {
        id: r2ssa::SemanticId::stack_slot(object),
        object,
        base: r2ssa::StackAddressBase::FramePointer,
        offset: -8,
        size: Some(8),
        array_layout: r2ssa::StackArrayLayoutDisposition::NotIndexed,
        source_slot: None,
        reload_values: BTreeSet::new(),
        stored_values: BTreeSet::new(),
        callee_allocation: None,
        ty: None,
    };

    assert_eq!(forward.coalescing_values(), reversed.coalescing_values());
    // No source slot, so no declared local to be the contents of.
    assert_eq!(stack_slot.coalescing_values(), None);
}

#[test]
fn exact_source_param_slots_ignore_misleading_register_names() {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("rax", 0x20, 8));
    arch.add_register(RegisterDef::new("not_an_argument", 0x20, 4));
    arch.add_register(RegisterDef::new("rdi", 0x30, 8));
    arch.add_register(RegisterDef::new("rip", 0x40, 8));
    let storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset: 0x20,
        size: 8,
    };
    let logical = r2ssa::SourceLogicalValue::new(
        0,
        r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
    );
    let type_graph = r2ssa::SourceTypeGraph::new(
        [r2ssa::SourceType::new(
            0,
            r2ssa::SourceTypeKind::UnsignedInteger,
            64,
            64,
        )],
        [],
    )
    .expect("exact parameter type graph");
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"exact-param-alias".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, storage)],
        r2ssa::SourceFunctionReturn::Void,
        [],
        [Some(logical)],
        None,
        Some(type_graph),
    )
    .and_then(|interface| {
        interface.with_stack_pointer_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x30,
            size: 8,
        })
    })
    .and_then(|interface| {
        interface.with_return_address_storage(r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 0x40,
            size: 8,
        })
    })
    .expect("exact interface");
    let mut block = R2ILBlock::new(0x1000, 1);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x100, 8),
        src: Varnode::register(0x20, 8),
    });
    let source = r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("prepared source");

    let resolver = exact_source_param_slot_resolver(&source).expect("exact resolver");
    let parameter = source
        .facts()
        .boundaries
        .parameters
        .get(&0)
        .expect("exact boundary parameter");
    assert_eq!(resolver.slot_for_value(parameter.value), Some(0));
    let parameter_var = &source
        .graph()
        .value(parameter.value)
        .expect("parameter graph value")
        .var;
    assert_eq!(
        source
            .decompile_prep_facts()
            .and_then(|facts| facts.formal_parameter_of(parameter_var)),
        Some(0),
        "SSA preparation must consume the same exact boundary slot"
    );
    assert_eq!(
        Some(parameter_var.name()),
        Some("rax"),
        "the deliberately ABI-misleading display name must not change the slot"
    );
}

#[test]
fn exact_source_param_slots_refuse_missing_interface() {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("rdi", 0x20, 8));
    let source = r2ssa::SsaArtifact::for_decompile(&[R2ILBlock::new(0x1000, 1)], Some(&arch))
        .expect("prepared source without interface");

    assert!(exact_source_param_slot_resolver(&source).is_none());
}

fn exact_signed_i32_return_source(has_return: bool) -> r2ssa::SsaArtifact {
    signed_i32_return_source(has_return, true)
}

/// `eax + 7` returned through `rax`, under an interface whose graph a declaration states when `read`.
fn signed_i32_return_source(has_return: bool, read: bool) -> r2ssa::SsaArtifact {
    let mut arch = ArchSpec::new("x86-64");
    for (name, offset, size) in [
        ("rax", 0x00, 8),
        ("eax", 0x00, 4),
        ("rsp", 0x28, 8),
        ("rip", 0x30, 8),
    ] {
        arch.add_register(RegisterDef::new(name, offset, size));
    }
    let projection =
        |written: RegisterStorage, carrier: RegisterStorage, size_bits: u64| RegisterProjection {
            written,
            disposition: RegisterProjectionDisposition::Bound {
                carrier,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits,
                },
            },
        };
    arch.register_projections = vec![
        projection(
            RegisterStorage { offset: 0, size: 8 },
            RegisterStorage { offset: 0, size: 8 },
            64,
        ),
        projection(
            RegisterStorage { offset: 0, size: 4 },
            RegisterStorage { offset: 0, size: 8 },
            32,
        ),
        projection(
            RegisterStorage {
                offset: 0x28,
                size: 8,
            },
            RegisterStorage {
                offset: 0x28,
                size: 8,
            },
            64,
        ),
        projection(
            RegisterStorage {
                offset: 0x30,
                size: 8,
            },
            RegisterStorage {
                offset: 0x30,
                size: 8,
            },
            64,
        ),
    ];
    let mut block = R2ILBlock::new(0x401000, 2);
    // An arithmetic write followed by the carrier clear the lift states
    // for it. Arithmetic rather than a copy so the narrow result survives
    // as its own definition instead of being folded into its uses, and the
    // extension has an `eax` to name.
    block.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 4),
        a: Varnode::register(0, 4),
        b: Varnode::constant(7, 4),
    });
    block.push(R2ILOp::IntZExt {
        dst: Varnode::register(0, 8),
        src: Varnode::register(0, 4),
    });
    if has_return {
        block.push(R2ILOp::Return {
            target: Varnode::register(0x30, 8),
        });
    }
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let logical = r2ssa::SourceLogicalValue::new(
        0,
        r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::LowBits, 0, 32),
    );
    let graph = r2ssa::SourceTypeGraph::new(
        [r2ssa::SourceType::new(
            0,
            r2ssa::SourceTypeKind::SignedInteger,
            32,
            32,
        )],
        [],
    )
    .expect("exact signed return graph");
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"exact-signed-return".to_vec(),
        "sysv64",
        [],
        r2ssa::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
        [],
        Some(logical),
        Some(graph),
    )
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
    .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
    .map(|interface| {
        if read {
            interface.with_prototype_from_source_types()
        } else {
            interface
        }
    })
    .expect("exact signed return interface");
    r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("prepared signed return source")
}

#[test]
fn exact_source_return_type_preserves_signed_i32_with_matching_certificate() {
    let source = exact_signed_i32_return_source(true);

    assert_eq!(
        exact_source_return_type(&source),
        Some(CTypeLike::Int {
            bits: 32,
            signedness: crate::Signedness::Signed,
        })
    );

    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: crate::Signedness::Signed,
        }),
        params: Vec::new(),
    };
    let mut facts = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &signature,
            [crate::SignatureCertificateSource::ExternalContext],
        ),
        ..FunctionTypeFacts::default()
    });
    facts.apply_return_type_fact(&source, &crate::EvidenceTypes::default());
    assert_eq!(
        facts.return_type(),
        Some(&ReturnTypeFact::Decided {
            ty: signature.ret_type.expect("declared"),
            by: ReturnTypeEvidence::ExactSource,
        })
    );
    assert!(
        facts
            .type_facts()
            .signature_certificate
            .as_ref()
            .is_some_and(|certificate| certificate
                .sources
                .contains(&crate::SignatureCertificateSource::SourceReturnType))
    );
}

#[test]
fn exact_source_return_type_refuses_missing_or_mismatched_certificate() {
    let missing = exact_signed_i32_return_source(false);
    assert!(missing.certificates().returns.is_empty());
    assert_eq!(exact_source_return_type(&missing), None);

    let matching = exact_signed_i32_return_source(true);
    let mut mismatched = matching.certificates().returns[0].clone();
    mismatched.width = 8;
    let logical = matching
        .machine_context()
        .function_interface()
        .and_then(r2ssa::SourceFunctionInterface::return_logical_value)
        .expect("exact logical return");
    assert!(!exact_return_certificate_matches(
        &mismatched,
        logical,
        4,
        &r2ssa::ReturnCarrier::Register {
            storage: r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        },
    ));
    let mut forged_logical = matching.certificates().returns[0].clone();
    forged_logical.source_logical_value = None;
    assert!(!exact_return_certificate_matches(
        &forged_logical,
        logical,
        4,
        &r2ssa::ReturnCarrier::Register {
            storage: r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        },
    ));
}

#[test]
fn exact_tail_return_requires_a_complete_matching_source_boundary() {
    let storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let target_storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Ram,
        offset: 0x402000,
        size: 8,
    };
    let call_site_id = r2ssa::CallSiteId(0);
    let at = r2ssa::InstId(3);
    let target = r2ssa::ValueId(7);
    let call_site = r2ssa::CallSiteFact {
        id: call_site_id,
        at,
        raw_identity: Some(r2ssa::SourceCallSiteIdentity::new(0x401002, target_storage)),
        target,
        direct_target: Some(0x402000),
        fallthrough: None,
        transfer: r2ssa::CallSiteTransfer::TailCall,
        callee_linkage: r2source::AdvisoryCalleeLinkage::Unknown,
        memory_effect: r2ssa::CallMemoryEffect::Unknown,
    };
    let certificate = r2ssa::CallsiteCertificate {
        call_site: call_site_id,
        at,
        block_addr: 0x401000,
        op_index: 2,
        target,
        direct_target: Some(0x402000),
        fallthrough: None,
        transfer: r2ssa::CallSiteTransfer::TailCall,
        callee_linkage: r2source::AdvisoryCalleeLinkage::Unknown,
        argument_values: Vec::new(),
        variadic: false,
        fixed_argument_count: Some(0),
        variadic_argument_count_evidence: None,
        variadic_argument_count_refusal: None,
        stack_argument_values: Vec::new(),
        return_address_store: None,
        argument_certificates: Vec::new(),
        arguments_complete: true,
        results_complete: true,
        described: true,
    };
    let mut boundary = r2ssa::SourceCallBoundaryFact {
        call_site: call_site_id,
        at,
        calling_convention: Some("sysv64".to_string()),
        variadic: Some(false),
        noreturn: Some(false),
        result_kind: Some(r2ssa::SourceCallResult::Register { storage }),
        arguments: Vec::new(),
        fixed_argument_count: Some(0),
        variadic_argument_count_evidence: None,
        variadic_argument_count_refusal: None,
        results: Vec::new(),
        complete: true,
        arguments_complete: true,
        results_complete: true,
        described: true,
    };

    assert!(exact_tail_return_certificate_matches(
        &call_site,
        &certificate,
        &boundary,
        storage,
    ));

    boundary.complete = false;
    boundary.results_complete = false;
    assert!(!exact_tail_return_certificate_matches(
        &call_site,
        &certificate,
        &boundary,
        storage,
    ));
    boundary.complete = true;
    boundary.result_kind = Some(r2ssa::SourceCallResult::Void);
    assert!(!exact_tail_return_certificate_matches(
        &call_site,
        &certificate,
        &boundary,
        storage,
    ));
}

#[test]
fn exact_source_param_slots_accept_exact_empty_interface() {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("rsp", 0x30, 8));
    arch.add_register(RegisterDef::new("rip", 0x40, 8));
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"exact-empty-interface".to_vec(),
        "sysv64",
        [],
        r2ssa::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(0x30)))
    .and_then(|interface| interface.with_return_address_storage(register_storage(0x40)))
    .expect("exact empty interface");
    let source = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[R2ILBlock::new(0x1000, 1)],
        Some(&arch),
        interface,
    )
    .expect("prepared source");

    assert!(
        exact_source_param_slot_resolver(&source)
            .expect("empty resolver")
            .is_empty()
    );
}

fn test_control_domain() -> r2ssa::ControlDomain {
    r2ssa::ControlDomain {
        id: r2ssa::ControlDomainId(0),
        guards: Vec::new(),
        loops: Vec::new(),
        complete: true,
    }
}

fn test_render_with_stack_slots<const N: usize>(
    slots: [(r2ssa::ObjectId, r2ssa::StackAddressBase, i64); N],
) -> FunctionRenderFacts {
    FunctionRenderFacts {
        certified_entities: slots
            .into_iter()
            .map(|(object, base, offset)| {
                let id = r2ssa::SemanticId::stack_slot(object);
                (
                    id,
                    CertifiedEntity::StackSlot {
                        id,
                        object,
                        base,
                        offset,
                        size: None,
                        array_layout: r2ssa::StackArrayLayoutDisposition::NotIndexed,
                        source_slot: None,
                        reload_values: BTreeSet::new(),
                        stored_values: BTreeSet::new(),
                        callee_allocation: None,
                        ty: None,
                    },
                )
            })
            .collect(),
        ..FunctionRenderFacts::default()
    }
}

#[test]
fn function_facts_owns_input_quality_evidence() {
    let complete = FunctionInputQualityFacts {
        expected_blocks: 2,
        lifted_blocks: 2,
        actual_lifted_blocks: 2,
        read_failures: 0,
        invalid_blocks: 0,
        null_lift_failures: 0,
        truncated_blocks: 0,
        refusal_reason: None,
    };
    assert!(complete.is_complete());

    let refused = FunctionInputQualityFacts {
        expected_blocks: 2,
        lifted_blocks: 1,
        actual_lifted_blocks: 1,
        read_failures: 1,
        invalid_blocks: 0,
        null_lift_failures: 0,
        truncated_blocks: 0,
        refusal_reason: Some("incomplete lifted function input".to_string()),
    };
    assert!(!refused.is_complete());

    let mismatch = FunctionInputQualityFacts {
        expected_blocks: 2,
        lifted_blocks: 2,
        actual_lifted_blocks: 1,
        read_failures: 0,
        invalid_blocks: 0,
        null_lift_failures: 0,
        truncated_blocks: 0,
        refusal_reason: Some("inconsistent lifted function input".to_string()),
    };
    assert!(!mismatch.is_complete());

    let mut facts = FunctionFacts::default().with_input_quality(refused.clone());
    assert_eq!(facts.input_quality(), Some(&refused));
    assert!(
        !facts.input_quality().expect("quality fact").is_complete(),
        "incomplete lift quality must travel as refusal evidence"
    );

    facts.set_input_quality(Some(complete.clone()));
    assert_eq!(facts.input_quality(), Some(&complete));
    assert!(facts.input_quality().expect("quality fact").is_complete());

    facts.set_input_quality(Some(mismatch.clone()));
    assert_eq!(facts.input_quality(), Some(&mismatch));
    assert!(!facts.input_quality().expect("quality fact").is_complete());

    facts.set_input_quality(None);
    assert_eq!(facts.input_quality(), None);
}

#[test]
fn function_facts_owns_canonical_callee_resolution() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 3,
    };
    let function_names = HashMap::from([(0x402000, "sym.helper".to_string())]);
    let symbols = HashMap::new();
    let known_function_signatures = HashMap::new();
    let callee_facts = BTreeMap::new();
    let ctx = crate::CalleeIdentityContext {
        function_names: &function_names,
        symbols: &symbols,
        callee_facts: &callee_facts,
        known_function_signatures: &known_function_signatures,
    };
    let resolution = CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x402000)], &ctx);

    let facts = FunctionFacts::default().with_callee_resolution(resolution);

    assert!(
        facts
            .callee_resolution()
            .and_then(|resolution| resolution.identity_for_callsite(callsite))
            .is_some(),
        "callsite identity must travel through FunctionFacts, not a render side channel"
    );
}

#[test]
fn prepared_display_name_does_not_create_a_known_signature() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x402000, 8),
    });
    let prepared = x86_stack_home_under(&[block], None, Vec::new()).expect("prepared direct call");
    let callsite = CallsiteKey {
        block_addr: 0x401000,
        op_index: 0,
    };
    let mut names = crate::DisplayNames::default();
    names.insert_function(0x402000, "sym.imp.__memcpy_chk");
    let mut facts = FunctionFacts::default();
    facts.set_display_names(names);

    facts.attach_prepared_decompile_evidence(&prepared);

    let identity = facts
        .callee_resolution()
        .and_then(|resolution| resolution.identity_for_callsite(callsite))
        .expect("direct target identity");
    assert_eq!(identity.raw_name(), "sym.imp.__memcpy_chk");
    assert!(identity.known_signature().is_none());
    assert_eq!(identity.non_variadic_known_arity(), None);
}

#[test]
fn function_facts_owns_canonical_callsite_arguments() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let value = r2ssa::ValueId(11);
    let callsites = FunctionCallsiteFacts {
        by_callsite: BTreeMap::from([(
            callsite,
            CallsiteArgumentFacts {
                callsite,
                call_site_id: r2ssa::CallSiteId(2),
                at: r2ssa::InstId(5),
                target: r2ssa::ValueId(10),
                direct_target: Some(0x402000),
                argument_values: vec![CallArgumentValueFact { index: 0, value }],
                variadic: false,
                fixed_argument_count: None,
                callee_signature: None,
                callee_signature_from_source_types: false,
                variadic_argument_count_evidence: None,
                variadic_argument_count_refusal: None,
                register_argument_locations: vec![RegisterCallArgumentLocationFact {
                    index: 0,
                    value,
                    storage: r2ssa::CanonicalStorageId {
                        space: r2ssa::CanonicalStorageSpace::Register,
                        offset: 0,
                        size: 8,
                    },
                    source_inst: Some(r2ssa::InstId(4)),
                }],
                stack_argument_locations: Vec::new(),
                arguments_complete: true,
                results_complete: true,
            },
        )]),
    };

    let facts = FunctionFacts::default().with_callsites(callsites);

    assert_eq!(
        facts
            .callsites()
            .and_then(|callsites| callsites.arguments_for_site(callsite))
            .and_then(|args| args.argument_value(0)),
        Some(value),
        "callsite argument proof must travel through FunctionFacts, not r2dec local inference"
    );
    assert_eq!(
        facts
            .callsites()
            .and_then(|callsites| callsites.arguments_for_site(callsite))
            .and_then(|args| args.register_argument_locations.first())
            .map(|location| (location.index, location.value, location.storage)),
        Some((
            0,
            value,
            r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        )),
        "register argument location proof must travel through FunctionFacts"
    );
}

#[test]
fn a_recovered_pointer_replaces_a_storage_width_scalar() {
    let existing = CTypeLike::Int {
        bits: 32,
        signedness: crate::Signedness::Signed,
    };
    let recovered = CTypeLike::Pointer(Box::new(CTypeLike::Void));
    assert!(recovered_type_outranks(
        &existing,
        &recovered,
        64,
        &crate::ExternalTypeDb::default()
    ));
}

/// A name carries what it stands for, so a width can be measured through
/// it. Before the target travelled with the name every consumer re-parsed
/// the text, which only worked for standard spellings, and any other named
/// type was replaced here by the machine word.
#[test]
fn a_named_type_is_as_wide_as_what_it_names() {
    let named = CTypeLike::named(
        "UInt16",
        CTypeLike::Int {
            bits: 16,
            signedness: crate::Signedness::Unsigned,
        },
    );
    assert_eq!(declaration_type_width_bits(&named, 64), Some(16));
    assert_eq!(admit_declaration_type(named.clone(), 16, 64), named);
    // A name with nothing behind it still has no width, so the storage
    // stands instead -- which is what this rule did for every name before.
    let opaque = CTypeLike::typedef("Opaque");
    assert_eq!(declaration_type_width_bits(&opaque, 64), None);
    assert_eq!(
        admit_declaration_type(opaque, 32, 64),
        CTypeLike::machine_bits(32)
    );
}

#[test]
fn a_named_aggregate_is_still_an_aggregate() {
    let named = CTypeLike::named("bz_stream", CTypeLike::Struct("type_0x5e55".to_string()));
    assert!(matches!(named.unaliased(), CTypeLike::Struct(tag) if tag == "type_0x5e55"));
    assert_eq!(crate::convert::render_c_type_like(&named), "bz_stream");
}

#[test]
fn declaration_admission_canonicalizes_only_builtin_scalar_spellings() {
    assert_eq!(
        admit_declaration_type(CTypeLike::typedef("int64_t"), 64, 64),
        CTypeLike::Int {
            bits: 64,
            signedness: crate::Signedness::Signed,
        }
    );
    assert_eq!(
        admit_declaration_type(CTypeLike::typedef("size_t"), 64, 64),
        CTypeLike::typedef("size_t"),
        "a semantic alias keeps its source-owned identity"
    );
}

#[test]
fn a_recovered_type_never_demotes_a_structured_one() {
    let existing = CTypeLike::Pointer(Box::new(CTypeLike::Struct("Node".to_string())));
    for recovered in [
        CTypeLike::Int {
            bits: 64,
            signedness: crate::Signedness::Signed,
        },
        CTypeLike::Pointer(Box::new(CTypeLike::Void)),
        CTypeLike::typedef("int64_t"),
    ] {
        assert!(
            !recovered_type_outranks(&existing, &recovered, 64, &crate::ExternalTypeDb::default()),
            "{recovered:?} must not replace a struct pointer"
        );
    }
}

#[test]
fn a_recovered_type_that_renders_the_same_is_not_a_replacement() {
    let existing = CTypeLike::typedef("int32_t");
    let recovered = CTypeLike::Int {
        bits: 32,
        signedness: crate::Signedness::Signed,
    };
    assert!(!recovered_type_outranks(
        &existing,
        &recovered,
        64,
        &crate::ExternalTypeDb::default()
    ));
}

#[test]
fn a_storage_width_scalar_is_not_evidence_for_replacing_another_one() {
    let existing = CTypeLike::Int {
        bits: 64,
        signedness: crate::Signedness::Signed,
    };
    let recovered = CTypeLike::Int {
        bits: 32,
        signedness: crate::Signedness::Unsigned,
    };
    assert!(!recovered_type_outranks(
        &existing,
        &recovered,
        64,
        &crate::ExternalTypeDb::default()
    ));
}

#[test]
fn certified_call_argument_projects_callee_pointer_type_to_caller_parameter() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let value = r2ssa::ValueId(11);
    let signed_byte = CTypeLike::Int {
        bits: 8,
        signedness: crate::Signedness::Signed,
    };
    let pointer = CTypeLike::Pointer(Box::new(signed_byte));
    let function_names = HashMap::from([(0x402000, "strlen".to_string())]);
    let symbols = HashMap::new();
    let known_function_signatures = HashMap::from([(
        "strlen".to_string(),
        crate::FunctionType {
            return_type: CTypeLike::typedef("size_t"),
            params: vec![pointer.clone()],
            variadic: false,
        },
    )]);
    let callee_facts = BTreeMap::new();
    let identity_ctx = crate::CalleeIdentityContext {
        function_names: &function_names,
        symbols: &symbols,
        callee_facts: &callee_facts,
        known_function_signatures: &known_function_signatures,
    };
    let resolution =
        CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x402000)], &identity_ctx);
    let callsites = FunctionCallsiteFacts {
        by_callsite: BTreeMap::from([(
            callsite,
            CallsiteArgumentFacts {
                callsite,
                call_site_id: r2ssa::CallSiteId(2),
                at: r2ssa::InstId(5),
                target: r2ssa::ValueId(10),
                direct_target: Some(0x402000),
                argument_values: vec![CallArgumentValueFact { index: 0, value }],
                variadic: false,
                fixed_argument_count: None,
                callee_signature: None,
                callee_signature_from_source_types: false,
                variadic_argument_count_evidence: None,
                variadic_argument_count_refusal: None,
                register_argument_locations: Vec::new(),
                stack_argument_locations: Vec::new(),
                arguments_complete: true,
                results_complete: true,
            },
        )]),
    };
    let mut render = FunctionRenderFacts::default();
    render.certified_exprs.insert(
        r2ssa::SemanticId::expression(value),
        CertifiedExpr {
            id: r2ssa::SemanticId::expression(value),
            fact: ExpressionRenderFact {
                value,
                defining_inst: Some(r2ssa::InstId(4)),
                width: 8,
                renderable: true,
            },
            inputs: Vec::new(),
            bindings: BTreeSet::from([r2ssa::SemanticId::Parameter(0)]),
            guarded_phi: None,
        },
    );
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 64,
            signedness: crate::Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: "arg0".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: crate::Signedness::Signed,
            }),
        }],
    };
    let mut facts = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &signature,
            [crate::SignatureCertificateSource::LocalInference],
        ),
        ..FunctionTypeFacts::default()
    })
    .with_callee_resolution(resolution)
    .with_callsites(callsites)
    .with_render(render);

    assert_eq!(facts.apply_certified_call_argument_type_constraints(64), 1);
    let typed = facts
        .type_facts()
        .render_authorized_signature()
        .and_then(|signature| signature.params[0].ty.as_ref());
    assert_eq!(typed, Some(&pointer));
    assert!(
        facts
            .type_facts()
            .signature_certificate
            .as_ref()
            .is_some_and(|certificate| certificate
                .sources
                .contains(&crate::SignatureCertificateSource::CalleeSignature))
    );
}

#[test]
fn function_facts_owns_canonical_call_render_disposition() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let target = r2ssa::ValueId(10);
    let arg = r2ssa::ValueId(11);
    let render = FunctionCallRenderFacts {
        by_callsite: BTreeMap::from([(
            callsite,
            CallsiteRenderFact {
                callsite,
                target: Some(target),
                disposition: CallsiteRenderDisposition::Statement,
                proof_values: vec![arg],
                residual_reason: None,
            },
        )]),
    };

    let facts = FunctionFacts::default().with_call_render(render);

    let fact = facts
        .call_render()
        .and_then(|render| render.fact_for_site(callsite))
        .expect("call render fact must travel through FunctionFacts");
    assert_eq!(fact.target, Some(target));
    assert_eq!(fact.disposition, CallsiteRenderDisposition::Statement);
    assert_eq!(fact.proof_values, vec![arg]);
}

#[test]
fn callsite_facts_own_canonical_argument_vector() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let register_value = r2ssa::ValueId(11);
    let stack_value = r2ssa::ValueId(12);
    let duplicate_stack_value = r2ssa::ValueId(99);
    let args = CallsiteArgumentFacts {
        callsite,
        call_site_id: r2ssa::CallSiteId(2),
        at: r2ssa::InstId(5),
        target: r2ssa::ValueId(10),
        direct_target: Some(0x402000),
        argument_values: vec![CallArgumentValueFact {
            index: 0,
            value: register_value,
        }],
        variadic: false,
        fixed_argument_count: None,
        callee_signature: None,
        callee_signature_from_source_types: false,
        variadic_argument_count_evidence: None,
        variadic_argument_count_refusal: None,
        register_argument_locations: vec![RegisterCallArgumentLocationFact {
            index: 0,
            value: register_value,
            storage: r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
            source_inst: Some(r2ssa::InstId(4)),
        }],
        stack_argument_locations: vec![
            StackCallArgumentLocationFact {
                index: 0,
                value: duplicate_stack_value,
                object: r2ssa::ObjectId(1),
                offset: 0x20,
                memory_access: r2ssa::StructuredAccessId {
                    inst: r2ssa::InstId(3),
                    ordinal: 0,
                },
                source_inst: Some(r2ssa::InstId(3)),
            },
            StackCallArgumentLocationFact {
                index: 1,
                value: stack_value,
                object: r2ssa::ObjectId(2),
                offset: 0x28,
                memory_access: r2ssa::StructuredAccessId {
                    inst: r2ssa::InstId(4),
                    ordinal: 0,
                },
                source_inst: Some(r2ssa::InstId(4)),
            },
        ],
        arguments_complete: true,
        results_complete: true,
    };

    assert_eq!(
        args.canonical_argument_values(),
        vec![register_value, stack_value],
        "canonical callsite argument ordering and stack fallback must be owned by r2types"
    );
}

#[test]
fn function_facts_owns_canonical_call_results() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let value = r2ssa::ValueId(21);
    let derived_value = r2ssa::ValueId(22);
    let owner = r2ssa::ValueOwner::StackSlot {
        object: r2ssa::ObjectId(3),
        offset: -8,
    };
    let call_results = FunctionCallResultFacts {
        by_value: BTreeMap::from([
            (
                value,
                CallResultFact {
                    callsite,
                    call_site_id: r2ssa::CallSiteId(2),
                    at: r2ssa::InstId(8),
                    value,
                    width: 8,
                    relation: r2ssa::CallResultValueRelation::Identity,
                    carrier: r2ssa::ReturnCarrier::Register {
                        storage: r2ssa::CanonicalStorageId {
                            space: r2ssa::CanonicalStorageSpace::Register,
                            offset: 0x10,
                            size: 8,
                        },
                    },
                    owner: Some(owner.clone()),
                },
            ),
            (
                derived_value,
                CallResultFact {
                    callsite,
                    call_site_id: r2ssa::CallSiteId(2),
                    at: r2ssa::InstId(9),
                    value: derived_value,
                    width: 4,
                    relation: r2ssa::CallResultValueRelation::Derived,
                    carrier: r2ssa::ReturnCarrier::Register {
                        storage: r2ssa::CanonicalStorageId {
                            space: r2ssa::CanonicalStorageSpace::Register,
                            offset: 0x10,
                            size: 4,
                        },
                    },
                    owner: Some(r2ssa::ValueOwner::StackSlot {
                        object: r2ssa::ObjectId(4),
                        offset: -4,
                    }),
                },
            ),
        ]),
        by_callsite: BTreeMap::from([(callsite, vec![value, derived_value])]),
    };

    let facts = FunctionFacts::default().with_call_results(call_results);

    assert_eq!(
        facts
            .call_results()
            .and_then(|results| results.result_for_value(value))
            .and_then(|result| result.owner.as_ref()),
        Some(&owner),
        "call-result ownership proof must travel through FunctionFacts, not r2dec local inference"
    );
    assert_eq!(
        facts
            .call_results()
            .and_then(|results| results.owner_for_site(callsite)),
        Some(&owner),
        "derived values must not replace the identity result's stable owner"
    );
    assert_eq!(
        facts
            .call_results()
            .map(|results| results.results_for_site(callsite).count()),
        Some(2),
        "call-result site index must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .call_results()
            .and_then(|results| results.owner_for_site(callsite)),
        Some(&owner),
        "call-result owner lookup must be available by callsite"
    );
}

#[test]
fn call_result_definition_is_not_replaced_by_a_later_stack_owner() {
    let callsite = crate::CallsiteKey {
        block_addr: 0x401000,
        op_index: 7,
    };
    let defined = r2ssa::ValueId(20);
    let stored = r2ssa::ValueId(21);
    let storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset: 0x10,
        size: 8,
    };
    let stack_owner = r2ssa::ValueOwner::StackSlot {
        object: r2ssa::ObjectId(3),
        offset: -8,
    };
    let call_results = FunctionCallResultFacts {
        by_value: BTreeMap::from([
            (
                defined,
                CallResultFact {
                    callsite,
                    call_site_id: r2ssa::CallSiteId(2),
                    at: r2ssa::InstId(8),
                    value: defined,
                    width: 8,
                    relation: r2ssa::CallResultValueRelation::Identity,
                    carrier: r2ssa::ReturnCarrier::Register { storage },
                    owner: Some(r2ssa::ValueOwner::Value(defined)),
                },
            ),
            (
                stored,
                CallResultFact {
                    callsite,
                    call_site_id: r2ssa::CallSiteId(2),
                    at: r2ssa::InstId(9),
                    value: stored,
                    width: 8,
                    relation: r2ssa::CallResultValueRelation::Identity,
                    carrier: r2ssa::ReturnCarrier::Register { storage },
                    owner: Some(stack_owner.clone()),
                },
            ),
        ]),
        by_callsite: BTreeMap::from([(callsite, vec![defined, stored])]),
    };

    assert_eq!(
        call_results
            .definition_for_site(callsite)
            .map(|result| result.value),
        Some(defined),
        "the call statement must keep the boundary definition the binding plan can spell"
    );
    assert_eq!(
        call_results.owner_for_site(callsite),
        Some(&stack_owner),
        "the later stable owner remains available for subsequent result flow"
    );
}

#[test]
fn prepared_call_results_bind_certified_exprs_to_stable_call_ids() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.stamp_instruction(0, 0x401000);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x402000, 8),
    });
    block.push(R2ILOp::IntSub {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x20, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
        val: Varnode::register(0x00, 8),
    });
    let result_storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let target_storage = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Constant,
        offset: 0x402000,
        size: 8,
    };
    let call_interface = r2ssa::SourceCallSiteInterface::new(
        b"certified-call-result-fixture".to_vec(),
        r2ssa::SourceCallSiteIdentity::new(0x401000, target_storage),
        true,
        "sysv64",
        [],
        false,
        false,
        r2ssa::SourceCallResult::Register {
            storage: result_storage,
        },
    )
    .expect("exact call-result interface");
    let prepared = x86_stack_home_under(&[block], None, vec![call_interface])
        .expect("prepared exact call-result fixture");
    let mut facts = FunctionFacts::default();
    facts.attach_prepared_decompile_evidence(&prepared);

    let store_value = prepared
        .function()
        .get_block(0x401000)
        .expect("entry block")
        .ops
        .iter()
        .find_map(|op| match op {
            r2ssa::SSAOp::Store { val, .. } => prepared.graph().value_id_for_var(val),
            _ => None,
        })
        .expect("stored call result");
    let result = facts
        .call_results()
        .and_then(|results| results.result_for_value(store_value))
        .expect("canonical call-result fact");
    let binding = r2ssa::SemanticId::call(result.call_site_id);
    let certified = facts
        .render()
        .and_then(|render| render.certified_expr_for_value(store_value))
        .expect("certified call-result expression");

    assert!(certified.fact.renderable);
    assert!(certified.bindings.contains(&binding));
}

#[test]
fn an_implicit_call_read_keeps_its_entry_value_as_a_certified_parameter() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.stamp_instruction(0, 0x401000);
    let target = Varnode::constant(0x402000, 8);
    block.push(R2ILOp::Call {
        target: target.clone(),
    });
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let revision = b"implicit-call-parameter".to_vec();
    let parameter_storage = register_storage(0x10);
    let function_interface = r2ssa::SourceFunctionInterface::new_exact(
        revision.clone(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, parameter_storage)],
        r2ssa::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(0x28)))
    .expect("exact caller interface");
    let logical_parameter = r2ssa::SourceLogicalValue::new(
        0,
        r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::LowBits, 0, 32),
    );
    let callee_interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        revision.clone(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, parameter_storage)],
        r2ssa::SourceFunctionReturn::Void,
        [],
        [Some(logical_parameter)],
        None,
        Some(
            r2ssa::SourceTypeGraph::new(
                [r2ssa::SourceType::new(
                    0,
                    r2ssa::SourceTypeKind::UnsignedInteger,
                    32,
                    32,
                )],
                [],
            )
            .expect("callee type graph"),
        ),
    )
    .expect("logical callee interface");
    let call_interface = r2ssa::SourceCallSiteInterface::new(
        revision,
        r2ssa::SourceCallSiteIdentity::new(
            0x401000,
            r2ssa::CanonicalStorageId::from_varnode(&target),
        ),
        true,
        "sysv64",
        [r2ssa::SourceCallArgumentSpec::new(0, parameter_storage)],
        false,
        false,
        r2ssa::SourceCallResult::Void,
    )
    .and_then(|interface| interface.with_exact_callee_interface(callee_interface.clone()))
    .expect("exact callee interface");
    let prepared = x86_stack_home_under(&[block], Some(function_interface), vec![call_interface])
        .expect("prepared implicit-call fixture");
    let parameter = prepared
        .facts()
        .boundaries
        .parameters
        .get(&0)
        .expect("entry parameter boundary");
    assert!(prepared.graph().use_sites(parameter.value).is_empty());
    assert_eq!(
        prepared
            .callsite_certificate_for_op(0x401000, 0)
            .expect("callsite certificate")
            .argument_values,
        [parameter.value]
    );

    let mut facts = FunctionFacts::default();
    facts.attach_prepared_decompile_evidence(&prepared);
    let callsite = CallsiteKey {
        block_addr: 0x401000,
        op_index: 0,
    };
    assert_eq!(
        facts
            .callsites()
            .and_then(|facts| facts.arguments_for_site(callsite))
            .and_then(|facts| facts.callee_signature.as_ref()),
        None,
        "an exact carrier interface does not prove the callee's C signedness"
    );

    let callee_source = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(
            &[R2ILBlock::new(0x402000, 4)],
            Some(&x86_stack_home_arch()),
            callee_interface,
        )
        .expect("prepared callee owner"),
    );
    let signed_signature = crate::FunctionType {
        return_type: CTypeLike::Void,
        params: vec![CTypeLike::Int {
            bits: 32,
            signedness: crate::Signedness::Signed,
        }],
        variadic: false,
    };
    let source_owned_signature =
        SourceOwnedCalleeSignature::new(&callee_source, signed_signature.clone())
            .expect("logical type fits the exact low-bit carrier");
    facts.apply_source_owned_callee_signatures(
        &prepared,
        &BTreeMap::from([(0x402000, source_owned_signature)]),
    );
    assert_eq!(
        facts
            .callsites()
            .and_then(|facts| facts.arguments_for_site(callsite))
            .and_then(|facts| facts.callee_signature.as_ref()),
        Some(&signed_signature),
        "only the retained callee body may add logical signedness"
    );
    facts.populate_certified_parameter_exprs(&prepared, &x86_stack_home_param_slots(&prepared));

    assert_eq!(
        facts
            .render()
            .expect("render facts")
            .parameter_values(0)
            .collect::<Vec<_>>(),
        [parameter.value]
    );
}

#[test]
fn prepared_decompile_evidence_replaces_detached_source_dependent_rows() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x402000, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let callsite = CallsiteKey {
        block_addr: 0x401000,
        op_index: 0,
    };
    let sentinel_value = r2ssa::ValueId(0xfeed);
    let sentinel_callsite = CallsiteArgumentFacts {
        callsite,
        call_site_id: r2ssa::CallSiteId(0xbeef),
        at: r2ssa::InstId(0xbeef),
        target: sentinel_value,
        direct_target: Some(0x5555),
        argument_values: vec![CallArgumentValueFact {
            index: 0,
            value: sentinel_value,
        }],
        variadic: false,
        fixed_argument_count: None,
        callee_signature: None,
        callee_signature_from_source_types: false,
        variadic_argument_count_evidence: None,
        variadic_argument_count_refusal: None,
        register_argument_locations: Vec::new(),
        stack_argument_locations: Vec::new(),
        arguments_complete: true,
        results_complete: true,
    };
    let sentinel_render = CallsiteRenderFact {
        callsite,
        target: Some(sentinel_value),
        disposition: CallsiteRenderDisposition::Residualized,
        proof_values: vec![sentinel_value],
        residual_reason: Some("upstream refusal".to_string()),
    };
    let string_value = r2ssa::ValueId(0xcafe);
    let member_op = (0x501000, 3, false);
    let member_access = MemberAccessRenderFact {
        access: r2ssa::StructuredAccessId {
            inst: r2ssa::InstId(7),
            ordinal: 0,
        },
        block_addr: member_op.0,
        op_index: member_op.1,
        object: r2ssa::ObjectId(9),
        is_write: false,
        field_offset: 8,
        field_name: "len".to_string(),
        field_type: None,
        access_width: 32,
        base: None,
        source: MemberAccessSource::ExternalLayout,
    };
    let existing_render = FunctionRenderFacts {
        string_literals_by_value: BTreeMap::from([(
            string_value,
            StringLiteralRenderFact {
                value: string_value,
                address: 0x600000,
                text: "existing".to_string(),
                source: StringLiteralRenderSource::TypedFunctionFacts,
            },
        )]),
        member_accesses_by_op: BTreeMap::from([(member_op, vec![member_access])]),
        ..FunctionRenderFacts::default()
    };
    let mut facts = FunctionFacts::default()
        .with_callsites(FunctionCallsiteFacts {
            by_callsite: BTreeMap::from([(callsite, sentinel_callsite.clone())]),
        })
        .with_call_render(FunctionCallRenderFacts {
            by_callsite: BTreeMap::from([(callsite, sentinel_render.clone())]),
        })
        .with_render(existing_render);

    facts.attach_prepared_decompile_evidence(&prepared);

    assert_ne!(
        facts
            .callsites()
            .and_then(|callsites| callsites.arguments_for_site(callsite)),
        Some(&sentinel_callsite),
        "a detached callsite row must not outrank the retained prepared artifact"
    );
    assert_ne!(
        facts
            .call_render()
            .and_then(|render| render.fact_for_site(callsite)),
        Some(&sentinel_render),
        "a detached call-render disposition must not outrank the retained prepared artifact"
    );
    assert!(
        facts
            .render()
            .and_then(|render| render.string_literal_for_value(string_value))
            .is_none(),
        "an unvalidated detached string annotation must be removed during source rebuild"
    );
    assert!(
        facts
            .render()
            .and_then(|render| render.member_accesses_by_op.get(&member_op))
            .is_none(),
        "an unvalidated detached member projection must be removed during source rebuild"
    );
    assert!(
        facts
            .callee_resolution()
            .and_then(|resolution| resolution.identity_for_callsite(callsite))
            .is_some(),
        "prepared evidence should still fill missing FunctionFacts groups"
    );
}

#[test]
fn source_owned_seal_rederives_render_call_and_control_facts() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x402000, 8),
    });
    let source = Arc::new(
        x86_stack_home_under(&[block], None, Vec::new())
            .expect("prepared source-owned seal fixture"),
    );
    let canonical_report = || {
        let mut report =
            FunctionFacts::default().with_assumptions(source.facts().assumptions.clone());
        SourceOwnedFunctionFacts::enrich_report_from_source_for_decompile(
            source.as_ref(),
            &mut report,
        );
        report
    };

    assert!(
        SourceOwnedFunctionFacts::seal(Arc::clone(&source), canonical_report()).is_some(),
        "the independently rederived canonical report must seal"
    );

    let mut forged_render = canonical_report();
    forged_render
        .render
        .certified_exprs
        .values_mut()
        .next()
        .expect("fixture certified expression")
        .fact
        .width = 1;
    assert!(
        SourceOwnedFunctionFacts::seal(Arc::clone(&source), forged_render).is_none(),
        "a detached render-core mutation must not validate against itself"
    );

    let mut forged_call = canonical_report();
    assert!(!forged_call.call_render.by_callsite.is_empty());
    forged_call.call_render.by_callsite.clear();
    assert!(
        SourceOwnedFunctionFacts::seal(Arc::clone(&source), forged_call).is_none(),
        "a detached call-render mutation must not validate against itself"
    );

    let mut forged_control = canonical_report();
    assert!(!forged_control.control.control_domains.by_block.is_empty());
    forged_control.control = FunctionControlFacts::default();
    assert!(
        SourceOwnedFunctionFacts::seal(source, forged_control).is_none(),
        "a detached control projection must not validate against itself"
    );
}

#[test]
fn field_certificates_populate_direct_member_render_facts() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 8,
            field_name: "hash".to_string(),
            field_type: Some("uint64_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    let render = facts.render().expect("prepared render facts");
    let member = render
        .member_access_for_op(0x401000, 1, false, "hash", 8, Some(8))
        .expect("typed member render fact");
    let expected = CTypeLike::Int {
        bits: 64,
        signedness: crate::model::Signedness::Unsigned,
    };
    assert_eq!(member.field_type.as_ref(), Some(&expected));
    assert_eq!(render.memory_value_type(member.access), Some(&expected));
}

/// A pointer a loop carries -- `p = phi(arg0, p->next)` -- is parameter 0
/// only on the loop's first iteration. Naming its accesses from parameter 0's
/// field certificates rested on reading the merge as parameter 0 by skipping
/// the input nothing could place, which is the identity claim the value view
/// refuses: a merge is based where every input is. What types the carrier is
/// its declared pointee, which a certificate keyed by parameter does not
/// state, so the accesses through it get no parameter member name and the
/// carrier no type borrowed from one.
#[test]
fn field_certificates_do_not_follow_a_loop_carried_pointer_as_the_parameter() {
    let mut entry = R2ILBlock::new(0x400ff0, 0x10);
    entry.push(R2ILOp::Branch {
        target: Varnode::constant(0x401000, 8),
    });
    let mut header = R2ILBlock::new(0x401000, 0x10);
    header.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(8, 8),
    });
    header.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::constant(0x401020, 8),
        cond: Varnode::register(0x80, 1),
    });
    let mut latch = R2ILBlock::new(0x401010, 0x10);
    latch.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x200, 8),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(0x10, 8),
    });
    latch.push(R2ILOp::Load {
        dst: Varnode::register(0x10, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x200, 8),
    });
    latch.push(R2ILOp::Branch {
        target: Varnode::constant(0x401000, 8),
    });
    let mut exit = R2ILBlock::new(0x401020, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(0x08, 8),
    });
    let prepared = x86_stack_home_prepared(&[entry, header, latch, exit]);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![
            crate::facts::FieldAccessCertificate {
                slot: 0,
                field_offset: 8,
                field_name: "value".to_string(),
                field_type: Some("uint64_t".to_string()),
            },
            crate::facts::FieldAccessCertificate {
                slot: 0,
                field_offset: 0x10,
                field_name: "next".to_string(),
                field_type: Some("struct Node *".to_string()),
            },
        ],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    let upstream_carrier = prepared
        .structured()
        .loops
        .values()
        .flat_map(|loop_fact| loop_fact.carriers.iter())
        .next()
        .expect("prepared loop carrier");
    let projected_carrier = facts
        .render()
        .and_then(|render| render.certified_entities.get(&upstream_carrier.id))
        .expect("projected loop carrier");
    assert!(matches!(
        projected_carrier,
        CertifiedEntity::LoopCarrier {
            entries,
            updates,
            dominating_initializers,
            members,
            ..
        } if entries == &upstream_carrier.entries
            && updates == &upstream_carrier.updates
            && dominating_initializers == &upstream_carrier.dominating_initializers
            && members == &upstream_carrier.members
    ));
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );
    facts.populate_certified_loop_carrier_types();

    let render = facts.render().expect("prepared render facts");
    assert!(
        render
            .member_access_for_op(0x401000, 1, false, "value", 8, Some(8))
            .is_none()
    );
    assert!(
        render
            .member_access_for_op(0x401010, 1, false, "next", 0x10, Some(8))
            .is_none()
    );
    let borrowed = CTypeLike::Pointer(Box::new(CTypeLike::Struct("Node".to_string())));
    assert!(!render.loop_carriers().any(|carrier| {
        matches!(
            carrier,
            CertifiedEntity::LoopCarrier { ty: Some(ty), .. } if *ty == borrowed
        )
    }));
}

#[test]
fn field_certificates_do_not_populate_member_render_facts_for_wrong_width() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 8,
            field_name: "small".to_string(),
            field_type: Some("uint32_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    assert!(
        facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 1, false, "small", 8, Some(8))
            .is_none()),
        "wrong-width field certificate must not authorize member rendering"
    );
}

#[test]
fn field_certificates_do_not_populate_member_render_facts_for_wrong_param_slot() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x18, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 8,
            field_name: "hash".to_string(),
            field_type: Some("uint64_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    assert!(
        facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 1, false, "hash", 8, Some(8))
            .is_none()),
        "a field certificate for one parameter slot must not authorize the same offset on another parameter"
    );

    let matching_type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 1,
            field_offset: 8,
            field_name: "hash".to_string(),
            field_type: Some("uint64_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut matching_facts = FunctionFacts::new(matching_type_facts);

    matching_facts.attach_prepared_decompile_evidence(&prepared);
    matching_facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    assert!(
        matching_facts.render().is_some_and(|render| render
            .member_access_for_op(0x401000, 1, false, "hash", 8, Some(8))
            .is_some()),
        "the same memory proof should authorize the certificate for the matching parameter slot"
    );
}

fn x86_stack_home_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("rax", 0x00, 8));
    arch.add_register(RegisterDef::sub("eax", 0x00, 4, "rax"));
    arch.add_register(RegisterDef::new("rdi", 0x10, 8));
    arch.add_register(RegisterDef::new("rsi", 0x18, 8));
    arch.add_register(RegisterDef::sub("esi", 0x18, 4, "rsi"));
    arch.add_register(RegisterDef::new("rbp", 0x20, 8));
    arch.add_register(RegisterDef::new("rsp", 0x28, 8));
    arch.add_register(RegisterDef::new("rip", 0x30, 8));
    arch
}

/// The stack-home arch prepared where a call clobbers rax, rdi and rsi and preserves rbp, rsp and rip.
fn x86_stack_home_under(
    blocks: &[R2ILBlock],
    function_interface: Option<r2ssa::SourceFunctionInterface>,
    call_site_interfaces: Vec<r2ssa::SourceCallSiteInterface>,
) -> Option<r2ssa::SsaArtifact> {
    let storages = |offsets: [u64; 3]| {
        offsets.map(|offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        })
    };
    let call_effect =
        r2ssa::SourceCallEffect::new(storages([0x00, 0x10, 0x18]), storages([0x20, 0x28, 0x30]))
            .expect("a call effect");
    r2ssa::SsaArtifact::for_decompile_with(
        blocks,
        r2ssa::DecompileInputs {
            arch: Some(&x86_stack_home_arch()),
            function_interface,
            call_effect: Some(call_effect),
            call_site_interfaces,
            ..Default::default()
        },
    )
}

fn x86_stack_home_prepared(blocks: &[R2ILBlock]) -> r2ssa::SsaArtifact {
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let frame_pointer = register_storage(0x20);
    let parameter = register_storage(0x10);
    let second_parameter = register_storage(0x18);
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"x86-stack-home-fixture".to_vec(),
        "sysv64",
        [
            r2ssa::SourceAbiParameterSpec::new(0, parameter),
            r2ssa::SourceAbiParameterSpec::new(1, second_parameter),
        ],
        r2ssa::SourceFunctionReturn::Register {
            storage: register_storage(0x00),
        },
        [r2ssa::SourceStackSlotSpec::new_parameter_home(
            r2ssa::StackAddressBase::FramePointer,
            frame_pointer,
            -8,
            8,
            0,
            parameter,
        )],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(0x28)))
    .and_then(|interface| interface.with_frame_pointer_storage(frame_pointer))
    .expect("exact x86 stack-home interface");
    x86_stack_home_under(blocks, Some(interface), Vec::new())
        .expect("prepared exact stack-home fixture")
}

fn x86_stack_home_param_slots(prepared: &r2ssa::SsaArtifact) -> ParamSlotResolver {
    exact_source_param_slot_resolver(prepared).expect("exact source parameter slots")
}

#[test]
fn prepared_render_facts_certify_params_stack_memory_and_returns_by_semantic_id() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x20, 8),
        b: Varnode::constant(0xffff_ffff_ffff_fff8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
        val: Varnode::register(0x10, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::register(0x00, 8),
        a: Varnode::register(0x00, 8),
        b: Varnode::register(0x00, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 64,
            signedness: crate::Signedness::Unsigned,
        }),
        params: vec![FunctionParamSpec {
            name: "buffer".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: crate::Signedness::Unsigned,
            }),
        }],
    };
    let mut facts = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &signature,
            [crate::SignatureCertificateSource::ExternalContext],
        ),
        ..FunctionTypeFacts::default()
    });
    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_certified_parameter_exprs(&prepared, &x86_stack_home_param_slots(&prepared));
    let render = facts.render().expect("certified render facts");

    let rdi = prepared
        .graph()
        .values
        .iter()
        .find(|value| value.var.name().eq_ignore_ascii_case("rdi") && value.var.version == 0)
        .expect("entry rdi value");
    let param_id = r2ssa::SemanticId::parameter(0).expect("parameter ID");
    assert!(
        render
            .certified_expr_for_value(rdi.id)
            .is_some_and(|expr| expr.bindings.contains(&param_id)),
        "entry parameter binding must use ABI slot identity"
    );
    assert!(render.parameter_values(0).any(|value| value == rdi.id));
    assert_eq!(
        render
            .certified_entities
            .values()
            .filter(|entity| matches!(entity, CertifiedEntity::Parameter { .. }))
            .count(),
        1
    );
    let reloaded = prepared
        .certificates()
        .stack_reloads
        .values()
        .find(|reload| reload.canonical_source == rdi.id)
        .expect("certified parameter-home reload");
    assert!(
        render
            .certified_expr_for_value(reloaded.value)
            .is_some_and(|expr| expr.bindings.contains(&param_id)),
        "parameter identity must cross its certified stack-home reload"
    );
    assert!(
        render
            .certified_effects
            .values()
            .filter_map(CertifiedEffect::memory_fact)
            .find(|fact| fact.access == reloaded.load_access)
            .is_some_and(|fact| !fact.materialize_result),
        "a certified stack-home reload must render through its stable identity even when the raw value has multiple expression uses"
    );
    assert!(
        render
            .certified_exprs
            .values()
            .all(|expr| !expr.bindings.contains(&r2ssa::SemanticId::Parameter(1))),
        "unused ABI entry registers beyond signature arity must not become parameters"
    );

    let certified_entities = render.certified_entities.len();
    let memory_effects = render
        .certified_effects
        .values()
        .filter(|effect| {
            matches!(
                effect.kind(),
                CertifiedEffectKind::MemoryRead | CertifiedEffectKind::MemoryWrite
            )
        })
        .count();
    let return_effects = render
        .certified_effects
        .values()
        .filter(|effect| effect.kind() == CertifiedEffectKind::Return)
        .count();
    assert_eq!(certified_entities, 3);
    assert!(
        render
            .certified_entities
            .values()
            .any(|entity| matches!(entity, CertifiedEntity::Parameter { slot: 0, .. }))
    );
    assert!(
        render
            .certified_entities
            .values()
            .any(|entity| matches!(entity, CertifiedEntity::StackSlot { offset: -8, .. }))
    );
    assert_eq!(memory_effects, 2);
    assert!(return_effects >= 1);
    assert!(render.return_effect_id_for_op(0x401000, 4).is_some());
    assert!(render.return_for_op(0x401000, 4).is_some());
}

#[test]
fn prepared_render_facts_certify_branch_guarded_phi() {
    let mut entry = R2ILBlock::new(0x401000, 4);
    entry.push(R2ILOp::IntEqual {
        dst: Varnode::unique(0x300, 1),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::constant(0x401008, 8),
        cond: Varnode::unique(0x300, 1),
    });
    let mut when_false = R2ILBlock::new(0x401004, 4);
    when_false.push(R2ILOp::Copy {
        dst: Varnode::register(0x10, 8),
        src: Varnode::constant(1, 8),
    });
    when_false.push(R2ILOp::Branch {
        target: Varnode::constant(0x40100c, 8),
    });
    let mut when_true = R2ILBlock::new(0x401008, 4);
    when_true.push(R2ILOp::Branch {
        target: Varnode::constant(0x40100c, 8),
    });
    let mut exit = R2ILBlock::new(0x40100c, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(0x10, 8),
    });
    let prepared = r2ssa::SsaArtifact::for_decompile(
        &[entry, when_false, when_true, exit],
        Some(&x86_stack_home_arch()),
    )
    .expect("prepared");
    let phi = prepared
        .function()
        .get_block(0x40100c)
        .and_then(|block| block.phis.iter().find(|phi| phi.dst.name() == "rdi"))
        .and_then(|phi| prepared.graph().value_id_for_var(&phi.dst))
        .expect("return phi");
    let render = FunctionRenderFacts::from_prepared(&prepared);
    let guarded = render.guarded_phi_for_value(phi).expect("guarded phi");

    assert_eq!(
        guarded.predicate,
        r2ssa::SemanticId::predicate(r2ssa::PredicateId(0))
    );
    let r2ssa::SemanticId::Expression(true_value) = guarded.when_true.rendered else {
        panic!("guarded phi arm must render an expression identity");
    };
    assert_eq!(
        prepared.value_var(true_value),
        Some(&r2ssa::SSAVar::constant(0, 8)),
        "the true equality edge should substitute the proven constant"
    );
    assert_eq!(guarded.when_false.sources.len(), 1);
    assert_eq!(guarded.when_false.rendered, guarded.when_false.sources[0]);
}

#[test]
fn prepared_render_facts_materialize_load_for_distinct_consumers() {
    let mut block = R2ILBlock::new(0x402000, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::register(0x10, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::register(0x18, 8),
        val: Varnode::register(0x00, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::register(0x18, 8),
        val: Varnode::register(0x00, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let render = FunctionRenderFacts::from_prepared(&prepared);
    let read = render
        .memory_accesses()
        .find(|fact| !fact.is_write)
        .expect("certified load");

    assert!(
        read.materialize_result,
        "one certified load consumed by two rendered stores must be evaluated once"
    );
}

#[test]
fn prepared_render_facts_keep_single_consumer_load_inline() {
    let mut block = R2ILBlock::new(0x402000, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::register(0x10, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::register(0x18, 8),
        val: Varnode::register(0x00, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let render = FunctionRenderFacts::from_prepared(&prepared);
    let read = render
        .memory_accesses()
        .find(|fact| !fact.is_write)
        .expect("certified load");

    assert!(
        !read.materialize_result,
        "a single rendered consumer should keep the load inline"
    );
}

#[test]
fn parameter_identity_is_distinct_from_single_parameter_dependency() {
    let mut block = R2ILBlock::new(0x402000, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x100, 8),
        src: Varnode::register(0x10, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x108, 8),
        a: Varnode::unique(0x100, 8),
        b: Varnode::constant(1, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::unique(0x108, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let mut facts = FunctionFacts::default();
    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_certified_parameter_exprs(&prepared, &x86_stack_home_param_slots(&prepared));
    let render = facts.render().expect("render facts");
    let copied = prepared
        .graph()
        .values
        .iter()
        .find(|value| value.var.name() == "tmp:100")
        .expect("same-width parameter copy");
    let derived = prepared
        .graph()
        .values
        .iter()
        .find(|value| value.var.name() == "tmp:108")
        .expect("derived expression");

    assert_eq!(render.exact_parameter_slot_for_value(copied.id), Some(0));
    assert_eq!(render.exact_parameter_slot_for_value(derived.id), None);
    assert_eq!(
        render.unique_parameter_dependency_slot_for_value(derived.id),
        Some(0)
    );
}

fn member_load_prepared_for_register(arch: &ArchSpec, register_offset: u64) -> r2ssa::SsaArtifact {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(register_offset, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x100, 8),
    });
    r2ssa::SsaArtifact::for_decompile(&[block], Some(arch)).expect("prepared")
}

fn field_certificate_type_facts(slot: usize, offset: u64) -> FunctionTypeFacts {
    FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot,
            field_offset: offset,
            field_name: "hash".to_string(),
            field_type: Some("uint64_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    }
}

#[test]
fn field_certificates_fail_closed_without_param_slot_resolver() {
    let prepared = member_load_prepared_for_register(&x86_stack_home_arch(), 0x10);
    let mut facts = FunctionFacts::new(field_certificate_type_facts(0, 8));

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &ParamSlotResolver::default(),
    );

    assert!(
        facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 1, false, "hash", 8, Some(8))
            .is_none()),
        "missing ABI slot evidence must not guess rdi as parameter slot 0"
    );
}

fn stack_home_field_load_prepared(with_store: bool) -> r2ssa::SsaArtifact {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x100, 8),
        a: Varnode::register(0x20, 8),
        b: Varnode::constant(0xffff_ffff_ffff_fff8, 8),
    });
    if with_store {
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x104, 8),
            src: Varnode::register(0x10, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x100, 8),
            val: Varnode::unique(0x104, 8),
        });
    }
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x108, 8),
        a: Varnode::register(0x20, 8),
        b: Varnode::constant(0xffff_ffff_ffff_fff8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x110, 8),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x108, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x118, 8),
        a: Varnode::unique(0x110, 8),
        b: Varnode::constant(4, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 4),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x118, 8),
    });
    x86_stack_home_prepared(&[block])
}

#[test]
fn field_certificates_populate_stack_home_member_render_facts() {
    let prepared = stack_home_field_load_prepared(true);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 4,
            field_name: "hash".to_string(),
            field_type: Some("uint32_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    assert!(
        facts.render().is_some_and(|render| render
            .member_access_for_op(0x401000, 6, false, "hash", 4, Some(4))
            .is_some()),
        "field certificate plus prepared stack-reload proof must authorize O0 stack-home member rendering"
    );
}

#[test]
fn field_certificates_do_not_populate_stack_home_member_without_reload_proof() {
    let prepared = stack_home_field_load_prepared(false);
    let type_facts = FunctionTypeFacts {
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 4,
            field_name: "hash".to_string(),
            field_type: Some("uint32_t".to_string()),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    assert!(
        facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 4, false, "hash", 4, Some(4))
            .is_none()),
        "field certificate must not authorize a member render through an unproven stack load"
    );
}

#[test]
fn scalar_array_candidates_populate_indexed_member_render_facts() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::IntZExt {
        dst: Varnode::unique(0x100, 8),
        src: Varnode::register(0x18, 4),
    });
    block.push(R2ILOp::IntMult {
        dst: Varnode::unique(0x108, 8),
        a: Varnode::unique(0x100, 8),
        b: Varnode::constant(16, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x110, 8),
        a: Varnode::register(0x10, 8),
        b: Varnode::unique(0x108, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x118, 8),
        a: Varnode::unique(0x110, 8),
        b: Varnode::constant(4, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 4),
        space: SpaceId::Ram,
        addr: Varnode::unique(0x118, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let load_index = prepared
        .function()
        .get_block(0x401000)
        .expect("block")
        .ops
        .iter()
        .position(|op| matches!(op, r2ssa::SSAOp::Load { .. }))
        .expect("array load");
    let index_value = prepared
        .memory_certificate_for_op_site(0x401000, load_index, false)
        .expect("array load certificate")
        .address;
    let index_value = prepared
        .addresses()
        .parameter_expression(index_value)
        .and_then(|address| address.terms.first())
        .map(|term| term.value)
        .expect("semantic array index");
    let type_facts = FunctionTypeFacts {
        array_index_certificates: vec![crate::facts::ArrayIndexCertificate {
            slot: 0,
            base: Some(crate::facts::ArrayIndexBase::Param { index: 0 }),
            field_offset: 4,
            element_stride: 16,
        }],
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot: 0,
            field_offset: 4,
            field_name: "score".to_string(),
            field_type: Some("int32_t".to_string()),
        }],
        scalar_array_render_candidates: vec![crate::facts::ScalarArrayRenderCandidate {
            slot: 0,
            block_addr: 0x401000,
            op_index: load_index,
            is_write: false,
            field_offset: 4,
            element_stride: 16,
            access_width: 4,
            index_value: Some(index_value),
        }],
        ..FunctionTypeFacts::default()
    };
    let mut facts = FunctionFacts::new(type_facts);

    facts.attach_prepared_decompile_evidence(&prepared);
    facts.populate_certified_parameter_exprs(&prepared, &x86_stack_home_param_slots(&prepared));
    facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );
    facts.populate_array_access_render_facts_from_scalar_candidates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );

    let render = facts.render().expect("render facts");
    assert!(
        render
            .member_access_for_op(0x401000, load_index, false, "score", 4, Some(4))
            .is_some(),
        "scalar array candidate plus field certificate must authorize indexed member rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, load_index, false, 4, 16, Some(4))
            .is_some(),
        "scalar array candidate must still authorize array rendering"
    );
    let array = render
        .array_access_for_op(0x401000, load_index, false, 4, 16, Some(4))
        .expect("stable array render fact");
    assert_eq!(array.base, Some(r2ssa::SemanticId::Parameter(0)));
    assert_eq!(
        array.index,
        Some(r2ssa::SemanticId::expression(index_value))
    );
}

#[test]
fn scalar_array_member_candidate_requires_semantic_index_identity() {
    let mut block = R2ILBlock::new(0x401000, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::register(0x00, 4),
        space: SpaceId::Ram,
        addr: Varnode::register(0x18, 8),
    });
    let prepared = x86_stack_home_prepared(&[block]);
    let type_facts_for_slot = |slot| FunctionTypeFacts {
        array_index_certificates: vec![crate::facts::ArrayIndexCertificate {
            slot,
            base: Some(crate::facts::ArrayIndexBase::Param { index: slot }),
            field_offset: 4,
            element_stride: 16,
        }],
        field_access_certificates: vec![crate::facts::FieldAccessCertificate {
            slot,
            field_offset: 4,
            field_name: "score".to_string(),
            field_type: Some("int32_t".to_string()),
        }],
        scalar_array_render_candidates: vec![crate::facts::ScalarArrayRenderCandidate {
            slot,
            block_addr: 0x401000,
            op_index: 0,
            is_write: false,
            field_offset: 4,
            element_stride: 16,
            access_width: 4,
            index_value: None,
        }],
        ..FunctionTypeFacts::default()
    };

    let mut wrong_slot_facts = FunctionFacts::new(type_facts_for_slot(0));
    wrong_slot_facts.attach_prepared_decompile_evidence(&prepared);
    wrong_slot_facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );
    assert!(
        wrong_slot_facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 0, false, "score", 4, Some(4))
            .is_none()),
        "scalar-array member candidate from rsi must not render with a slot 0 certificate"
    );

    let mut matching_slot_facts = FunctionFacts::new(type_facts_for_slot(1));
    matching_slot_facts.attach_prepared_decompile_evidence(&prepared);
    matching_slot_facts.populate_member_access_render_facts_from_field_certificates(
        &prepared,
        &x86_stack_home_param_slots(&prepared),
    );
    assert!(
        matching_slot_facts.render().is_none_or(|render| render
            .member_access_for_op(0x401000, 0, false, "score", 4, Some(4))
            .is_none()),
        "coordinate-only array candidates must not authorize member rendering"
    );
}

#[test]
fn function_facts_owns_canonical_control_facts() {
    let branch = BranchPredicateFact {
        id: r2ssa::PredicateId(0),
        block_addr: 0x401000,
        condition: r2ssa::ValueId(31),
        comparison: Some(PredicateComparisonFact {
            kind: r2ssa::CompareKind::Equal,
            lhs: r2ssa::ValueId(32),
            rhs: r2ssa::ValueId(33),
        }),
        evaluated_comparison: None,
        render_comparison: Some(PredicateComparisonFact {
            kind: r2ssa::CompareKind::Equal,
            lhs: r2ssa::ValueId(32),
            rhs: r2ssa::ValueId(33),
        }),
        true_target: 0x401010,
        false_target: 0x401004,
    };
    let switch = SwitchSelectorFact {
        proof_node: r2ssa::ProofNodeId::switch_certificate(0x402000).to_string(),
        block_addr: 0x402000,
        selector: Some(r2ssa::ValueId(41)),
        cases: vec![(0, 0x402010), (1, 0x402020)],
        default: Some(0x402030),
    };
    let loop_fact = LoopStructureFact {
        loop_id: r2ssa::LoopId(2),
        proof_node: r2ssa::ProofNodeId::loop_certificate(0x403000, r2ssa::LoopId(2)).to_string(),
        header: 0x403000,
        condition: Some(branch.id),
        condition_value: Some(branch.condition),
        body: vec![0x403000, 0x403010],
        latches: vec![0x403010],
        exits: vec![0x403020],
        for_loop: None,
    };
    let control = FunctionControlFacts {
        branch_predicates: BTreeMap::from([(branch.block_addr, branch.clone())]),
        block_assumptions: BTreeMap::from([(
            branch.true_target,
            vec![ControlBlockAssumptionFact {
                predecessor: branch.block_addr,
                predicate: branch.id,
                truth: true,
            }],
        )]),
        loops: BTreeMap::from([(loop_fact.loop_id, loop_fact)]),
        switches: BTreeMap::from([(switch.block_addr, switch.clone())]),
        control_domains: r2ssa::ControlDomainFacts::default(),
    };

    let facts = FunctionFacts::default().with_control(control);

    assert_eq!(
        facts
            .control()
            .and_then(|control| control.branch_for_block(0x401000)),
        Some(&branch),
        "branch predicate proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .control()
            .map(|control| control.assumptions_for_block(0x401010).count()),
        Some(1),
        "block assumption proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .control()
            .map(|control| control.loops_for_header(0x403000).count()),
        Some(1),
        "loop structure proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .control()
            .and_then(|control| control.switch_for_block(0x402000)),
        Some(&switch),
        "switch selector proof must travel through FunctionFacts"
    );
}

#[test]
fn function_facts_owns_canonical_render_facts() {
    let value = r2ssa::ValueId(51);
    let access = r2ssa::StructuredAccessId {
        inst: r2ssa::InstId(7),
        ordinal: 0,
    };
    let object = r2ssa::ObjectId(3);
    let expression_id = r2ssa::SemanticId::expression(value);
    let memory_id = r2ssa::SemanticId::memory_access(access);
    let return_at = r2ssa::InstId(9);
    let return_id = r2ssa::SemanticId::return_value(return_at);
    let render = FunctionRenderFacts {
        certified_exprs: BTreeMap::from([(
            expression_id,
            CertifiedExpr {
                id: expression_id,
                fact: ExpressionRenderFact {
                    value,
                    defining_inst: Some(r2ssa::InstId(8)),
                    width: 8,
                    renderable: true,
                },
                inputs: Vec::new(),
                bindings: BTreeSet::new(),
                guarded_phi: None,
            },
        )]),
        certified_entities: BTreeMap::from([(
            r2ssa::SemanticId::stack_slot(object),
            CertifiedEntity::StackSlot {
                id: r2ssa::SemanticId::stack_slot(object),
                object,
                base: r2ssa::StackAddressBase::FramePointer,
                offset: -8,
                size: None,
                array_layout: r2ssa::StackArrayLayoutDisposition::NotIndexed,
                source_slot: None,
                reload_values: BTreeSet::new(),
                stored_values: BTreeSet::new(),
                callee_allocation: None,
                ty: None,
            },
        )]),
        certified_effects: BTreeMap::from([
            (
                memory_id,
                CertifiedEffect::Memory {
                    id: memory_id,
                    fact: MemoryAccessRenderFact {
                        access,
                        block_addr: 0x401000,
                        op_index: 4,
                        space: r2il::SpaceId::Ram,
                        object,
                        address: r2ssa::ValueId(52),
                        value: Some(value),
                        is_write: true,
                        width: 8,
                        object_offset: None,
                        materialize_result: false,
                        control_domain: test_control_domain(),
                    },
                },
            ),
            (
                return_id,
                CertifiedEffect::Return {
                    id: return_id,
                    at: return_at,
                    fact: ReturnValueRenderFact {
                        block_addr: 0x401010,
                        op_index: 2,
                        value,
                        width: 8,
                        control_domain: test_control_domain(),
                    },
                },
            ),
        ]),
        return_effects_by_op: BTreeMap::from([((0x401010, 2), return_id)]),
        memory_effects_by_op: BTreeMap::from([((0x401000, 4, true), vec![memory_id])]),
        string_literals_by_value: BTreeMap::from([(
            value,
            StringLiteralRenderFact {
                value,
                address: 0x402000,
                text: "value".to_string(),
                source: StringLiteralRenderSource::TypedFunctionFacts,
            },
        )]),
        member_accesses_by_op: BTreeMap::from([(
            (0x401000, 4, true),
            vec![MemberAccessRenderFact {
                access,
                block_addr: 0x401000,
                op_index: 4,
                object,
                is_write: true,
                field_offset: 0,
                field_name: "value".to_string(),
                field_type: None,
                access_width: 8,
                base: None,
                source: MemberAccessSource::ExternalLayout,
            }],
        )]),
        array_accesses_by_op: BTreeMap::from([(
            (0x401000, 4, true),
            vec![ArrayAccessRenderFact {
                access,
                block_addr: 0x401000,
                op_index: 4,
                object,
                is_write: true,
                field_offset: 0,
                element_stride: 8,
                access_width: 8,
                base: None,
                index: None,
            }],
        )]),
    };

    let facts = FunctionFacts::default().with_render(render);

    assert!(
        facts
            .render()
            .is_some_and(|render| render.expression_is_renderable(value)),
        "expression renderability proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .render()
            .and_then(|render| render.string_literal_for_value(value))
            .map(|literal| (literal.address, literal.text.as_str())),
        Some((0x402000, "value")),
        "string literal render proof must travel through FunctionFacts"
    );
    assert!(
        facts.render().is_some_and(|render| render
            .member_access_for_op(0x401000, 4, true, "value", 0, Some(8))
            .is_some()),
        "member access render proof must travel through FunctionFacts"
    );
    assert!(
        facts.render().is_some_and(|render| render
            .array_access_for_op(0x401000, 4, true, 0, 8, Some(8))
            .is_some()),
        "array access render proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .render()
            .and_then(|render| {
                render.memory_access_for_op(0x401000, 4, true, r2il::SpaceId::Ram)
            })
            .map(|memory| (memory.access, memory.space, memory.value, memory.width)),
        Some((access, r2il::SpaceId::Ram, Some(value), 8)),
        "memory access proof must travel through FunctionFacts"
    );
    assert_eq!(
        facts
            .render()
            .and_then(|render| render.return_for_op(0x401010, 2))
            .map(|ret| (ret.value, ret.width)),
        Some((value, 8)),
        "return value proof must travel through FunctionFacts"
    );
    assert!(
        facts
            .render()
            .is_some_and(|render| render.has_stack_slot_offset(-8)),
        "stack-slot offset proof must travel through FunctionFacts"
    );
}

#[test]
fn function_facts_authorizes_stack_owner_render_by_object_type_and_name() {
    let object = r2ssa::ObjectId(11);
    let facts = FunctionFacts::new(FunctionTypeFacts {
        visible_bindings: vec![crate::VisibleBinding {
            name: "local_buf".to_string(),
            ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                bits: 8,
                signedness: crate::Signedness::Unsigned,
            }))),
            kind: VisibleBindingKind::Local,
            stack_slot: Some(StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset: -8,
            }),
            param_index: None,
            source_reg: None,
        }],
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::FramePointer,
        -8,
    )]));

    let authorization = facts
        .authorized_stack_slot_owner_render(object, -8, "LOCAL_BUF")
        .expect("typed visible binding plus exact render object should authorize owner");
    assert_eq!(authorization.object, object);
    assert_eq!(authorization.offset, -8);
    assert_eq!(authorization.name, "LOCAL_BUF");
    assert!(
        facts
            .authorized_stack_slot_owner_render(r2ssa::ObjectId(12), -8, "local_buf")
            .is_none(),
        "a matching offset must not authorize the wrong SSA object"
    );
}

#[test]
fn function_render_facts_require_exact_array_access_identity() {
    let access = r2ssa::StructuredAccessId {
        inst: r2ssa::InstId(7),
        ordinal: 0,
    };
    let other_access = r2ssa::StructuredAccessId {
        inst: r2ssa::InstId(8),
        ordinal: 0,
    };
    let object = r2ssa::ObjectId(3);
    let value = r2ssa::ValueId(51);
    let memory_id = r2ssa::SemanticId::memory_access(access);
    let render = FunctionRenderFacts {
        certified_effects: BTreeMap::from([(
            memory_id,
            CertifiedEffect::Memory {
                id: memory_id,
                fact: MemoryAccessRenderFact {
                    access,
                    block_addr: 0x401000,
                    op_index: 4,
                    space: r2il::SpaceId::Ram,
                    object,
                    address: r2ssa::ValueId(52),
                    value: Some(value),
                    is_write: false,
                    width: 4,
                    object_offset: None,
                    materialize_result: false,
                    control_domain: test_control_domain(),
                },
            },
        )]),
        memory_effects_by_op: BTreeMap::from([((0x401000, 4, false), vec![memory_id])]),
        array_accesses_by_op: BTreeMap::from([(
            (0x401000, 4, false),
            vec![ArrayAccessRenderFact {
                access,
                block_addr: 0x401000,
                op_index: 4,
                object,
                is_write: false,
                field_offset: 0,
                element_stride: 4,
                access_width: 4,
                base: None,
                index: None,
            }],
        )]),
        ..FunctionRenderFacts::default()
    };

    assert!(
        render
            .array_access_for_op(0x401000, 4, false, 0, 4, Some(4))
            .is_some(),
        "exact op/access/object/direction/width/stride identity should authorize array rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, 5, false, 0, 4, Some(4))
            .is_none(),
        "wrong op site must not authorize array rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, 4, true, 0, 4, Some(4))
            .is_none(),
        "wrong direction must not authorize array rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, 4, false, 4, 4, Some(4))
            .is_none(),
        "wrong field offset must not authorize array rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, 4, false, 0, 8, Some(4))
            .is_none(),
        "wrong stride must not authorize array rendering"
    );
    assert!(
        render
            .array_access_for_op(0x401000, 4, false, 0, 4, Some(8))
            .is_none(),
        "wrong access width must not authorize array rendering"
    );

    let mut wrong_object = render.clone();
    wrong_object
        .array_accesses_by_op
        .get_mut(&(0x401000, 4, false))
        .expect("array fact")
        .first_mut()
        .expect("array fact")
        .object = r2ssa::ObjectId(9);
    assert!(
        wrong_object
            .array_access_for_op(0x401000, 4, false, 0, 4, Some(4))
            .is_none(),
        "wrong object identity must not authorize array rendering"
    );

    let mut wrong_access = render;
    wrong_access
        .array_accesses_by_op
        .get_mut(&(0x401000, 4, false))
        .expect("array fact")
        .first_mut()
        .expect("array fact")
        .access = other_access;
    assert!(
        wrong_access
            .array_access_for_op(0x401000, 4, false, 0, 4, Some(4))
            .is_none(),
        "wrong memory-access identity must not authorize array rendering"
    );
}

#[test]
fn memory_access_lookup_requires_exact_address_space() {
    let ram_access = r2ssa::StructuredAccessId {
        inst: r2ssa::InstId(7),
        ordinal: 0,
    };
    let custom_access = r2ssa::StructuredAccessId {
        inst: r2ssa::InstId(7),
        ordinal: 1,
    };
    let effect = |access, space| {
        let id = r2ssa::SemanticId::memory_access(access);
        (
            id,
            CertifiedEffect::Memory {
                id,
                fact: MemoryAccessRenderFact {
                    access,
                    block_addr: 0x401000,
                    op_index: 4,
                    space,
                    object: r2ssa::ObjectId(3),
                    address: r2ssa::ValueId(52),
                    value: Some(r2ssa::ValueId(51)),
                    is_write: false,
                    width: 4,
                    object_offset: None,
                    materialize_result: false,
                    control_domain: test_control_domain(),
                },
            },
        )
    };
    let ram_id = r2ssa::SemanticId::memory_access(ram_access);
    let custom_id = r2ssa::SemanticId::memory_access(custom_access);
    let render = FunctionRenderFacts {
        certified_effects: BTreeMap::from([
            effect(ram_access, r2il::SpaceId::Ram),
            effect(custom_access, r2il::SpaceId::Custom(7)),
        ]),
        memory_effects_by_op: BTreeMap::from([((0x401000, 4, false), vec![ram_id, custom_id])]),
        ..FunctionRenderFacts::default()
    };

    assert_eq!(
        render
            .memory_access_for_op(0x401000, 4, false, r2il::SpaceId::Ram)
            .map(|fact| fact.access),
        Some(ram_access)
    );
    assert_eq!(
        render
            .memory_access_for_op(0x401000, 4, false, r2il::SpaceId::Custom(7))
            .map(|fact| fact.access),
        Some(custom_access)
    );
    assert!(
        render
            .memory_access_for_op(0x401000, 4, false, r2il::SpaceId::Custom(8))
            .is_none()
    );
}

#[test]
fn function_facts_authorizes_recovered_stack_owner_only_by_exact_object_offset_and_name() {
    let object = r2ssa::ObjectId(21);
    let facts = FunctionFacts::default().with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::FramePointer,
        -4,
    )]));

    let authorization = facts
        .authorized_recovered_stack_slot_owner_render(object, -4, "i")
        .expect("a recovered loop scalar with exact object and offset should authorize");
    assert_eq!(authorization.object, object);
    assert_eq!(authorization.offset, -4);
    assert_eq!(authorization.name, "i");
    assert!(
        facts
            .authorized_recovered_stack_slot_owner_render(r2ssa::ObjectId(22), -4, "i")
            .is_none(),
        "wrong object must not authorize recovered stack owner rendering"
    );
    assert!(
        facts
            .authorized_recovered_stack_slot_owner_render(object, 4, "i")
            .is_none(),
        "wrong offset must not authorize recovered stack owner rendering"
    );
    for placeholder in ["fake_stack_slot", "local_4", "var_4h", "stack_8"] {
        assert!(
            facts
                .authorized_recovered_stack_slot_owner_render(object, -4, placeholder)
                .is_none(),
            "placeholder name {placeholder} must not authorize recovered stack owner rendering"
        );
    }
}

#[test]
fn function_facts_authorizes_stack_param_owner_render_only_for_params() {
    let object = r2ssa::ObjectId(13);
    let facts = FunctionFacts::new(FunctionTypeFacts {
        visible_bindings: vec![
            crate::VisibleBinding {
                name: "stack_arg".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: crate::Signedness::Signed,
                }),
                kind: VisibleBindingKind::Param,
                stack_slot: Some(StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: 8,
                }),
                param_index: Some(6),
                source_reg: None,
            },
            crate::VisibleBinding {
                name: "local_alias".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: crate::Signedness::Signed,
                }),
                kind: VisibleBindingKind::Local,
                stack_slot: Some(StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: 8,
                }),
                param_index: None,
                source_reg: None,
            },
        ],
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::StackPointer,
        8,
    )]));

    let authorization = facts
        .authorized_stack_param_owner_render(object, 8)
        .expect("typed parameter binding plus exact render object should authorize owner");
    assert_eq!(authorization.object, object);
    assert_eq!(authorization.offset, 8);
    assert_eq!(authorization.name, "stack_arg");
    assert!(
        facts
            .authorized_stack_param_owner_render(r2ssa::ObjectId(14), 8)
            .is_none(),
        "the stack parameter path still requires the exact render object"
    );
    assert!(
        facts
            .authorized_stack_param_owner_render(object, -8)
            .is_none(),
        "the stack parameter path still requires the exact offset"
    );

    let ambiguous = FunctionFacts::new(FunctionTypeFacts {
        visible_bindings: vec![
            crate::VisibleBinding {
                name: "left".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: crate::Signedness::Signed,
                }),
                kind: VisibleBindingKind::Param,
                stack_slot: Some(StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: 8,
                }),
                param_index: Some(6),
                source_reg: None,
            },
            crate::VisibleBinding {
                name: "right".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: crate::Signedness::Signed,
                }),
                kind: VisibleBindingKind::Param,
                stack_slot: Some(StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: 8,
                }),
                param_index: Some(6),
                source_reg: None,
            },
        ],
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::StackPointer,
        8,
    )]));
    assert!(
        ambiguous
            .authorized_stack_param_owner_render(object, 8)
            .is_none(),
        "ambiguous typed parameter names at one stack offset must not be rendered"
    );

    let canonical_slot = FunctionFacts::new(FunctionTypeFacts {
        visible_bindings: vec![crate::VisibleBinding {
            name: "arg6".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: crate::Signedness::Signed,
            }),
            kind: VisibleBindingKind::Param,
            stack_slot: Some(StackSlotKey {
                base: ExternalStackBase::StackPointer,
                offset: 8,
            }),
            param_index: Some(6),
            source_reg: None,
        }],
        stack_slots: BTreeMap::from([(
            StackSlotKey {
                base: ExternalStackBase::StackPointer,
                offset: 8,
            },
            crate::ExternalStackSlotSpec {
                name: "arg_8h".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 64,
                    signedness: crate::Signedness::Signed,
                }),
                role: ExternalStackSlotRole::StackArg,
                param_index: Some(6),
                param_name: Some("arg7".to_string()),
                source_reg: None,
            },
        )]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::StackPointer,
        8,
    )]));
    let authorization = canonical_slot
        .authorized_stack_param_owner_render(object, 8)
        .expect("canonical stack slot name should authorize");
    assert_eq!(authorization.name, "arg7");

    let param_home = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 32,
                signedness: crate::Signedness::Signed,
            }),
            params: vec![FunctionParamSpec {
                name: "node".to_string(),
                ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Struct(
                    "Node".to_string(),
                )))),
            }],
        }),
        stack_slots: BTreeMap::from([(
            StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset: -8,
            },
            crate::ExternalStackSlotSpec {
                name: "node_home".to_string(),
                ty: None,
                role: ExternalStackSlotRole::ParamHome,
                param_index: Some(0),
                param_name: Some("node".to_string()),
                source_reg: Some("rdi".to_string()),
            },
        )]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::FramePointer,
        -8,
    )]));
    let authorization = param_home
        .authorized_stack_param_owner_render(object, -8)
        .expect("typed parameter home should authorize original parameter owner");
    assert_eq!(authorization.name, "node");

    let stale_named_param_home = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Int {
                bits: 32,
                signedness: crate::Signedness::Signed,
            }),
            params: vec![
                FunctionParamSpec {
                    name: "arg0".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                        bits: 32,
                        signedness: crate::Signedness::Signed,
                    }))),
                },
                FunctionParamSpec {
                    name: "arg1".to_string(),
                    ty: Some(CTypeLike::Int {
                        bits: 32,
                        signedness: crate::Signedness::Signed,
                    }),
                },
            ],
        }),
        stack_slots: BTreeMap::from([(
            StackSlotKey {
                base: ExternalStackBase::FramePointer,
                offset: -8,
            },
            crate::ExternalStackSlotSpec {
                name: "arg1_home".to_string(),
                ty: None,
                role: ExternalStackSlotRole::ParamHome,
                param_index: Some(0),
                param_name: Some("arg1".to_string()),
                source_reg: Some("rdi".to_string()),
            },
        )]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        object,
        r2ssa::StackAddressBase::FramePointer,
        -8,
    )]));
    let authorization = stale_named_param_home
        .authorized_stack_param_owner_render(object, -8)
        .expect("parameter index should override a stale host-generated name");
    assert_eq!(authorization.name, "arg0");
    let raw_offset_param_home = param_home
        .clone()
        .with_render(test_render_with_stack_slots([(
            object,
            r2ssa::StackAddressBase::FramePointer,
            8,
        )]));
    assert!(
        raw_offset_param_home
            .authorized_stack_param_owner_render(object, 8)
            .is_none(),
        "frame-pointer parameter homes must match the canonical rendered offset, not the raw slot sign"
    );
    assert!(
        param_home
            .authorized_stack_slot_owner_render(object, -8, "node_home")
            .is_none(),
        "hidden parameter-home storage name must not become a rendered owner"
    );
}

#[test]
fn stack_owner_render_by_offset_rejects_ambiguous_or_untyped_slots() {
    let typed_slot = (
        StackSlotKey {
            base: ExternalStackBase::StackPointer,
            offset: -8,
        },
        crate::ExternalStackSlotSpec {
            name: "local_buf".to_string(),
            ty: Some(CTypeLike::Int {
                bits: 64,
                signedness: crate::Signedness::Signed,
            }),
            role: ExternalStackSlotRole::Local,
            ..crate::ExternalStackSlotSpec::default()
        },
    );
    let ambiguous = FunctionFacts::new(FunctionTypeFacts {
        stack_slots: BTreeMap::from([typed_slot.clone()]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([
        (
            r2ssa::ObjectId(1),
            r2ssa::StackAddressBase::StackPointer,
            -8,
        ),
        (
            r2ssa::ObjectId(2),
            r2ssa::StackAddressBase::StackPointer,
            -8,
        ),
    ]));
    assert!(
        ambiguous
            .authorized_stack_slot_owner_render_by_offset(-8, "local_buf")
            .is_none(),
        "offset-only bridge must refuse duplicate render objects"
    );

    let unknown_role = FunctionFacts::new(FunctionTypeFacts {
        stack_slots: BTreeMap::from([(
            typed_slot.0,
            crate::ExternalStackSlotSpec {
                role: ExternalStackSlotRole::Unknown,
                ..typed_slot.1.clone()
            },
        )]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        r2ssa::ObjectId(3),
        r2ssa::StackAddressBase::StackPointer,
        -8,
    )]));
    assert!(
        unknown_role
            .authorized_stack_slot_owner_render_by_offset(-8, "local_buf")
            .is_none(),
        "unknown stack-slot roles are not enough for certified owner rendering"
    );

    let untyped = FunctionFacts::new(FunctionTypeFacts {
        stack_slots: BTreeMap::from([(
            typed_slot.0,
            crate::ExternalStackSlotSpec {
                ty: Some(CTypeLike::Unknown),
                ..typed_slot.1
            },
        )]),
        ..FunctionTypeFacts::default()
    })
    .with_render(test_render_with_stack_slots([(
        r2ssa::ObjectId(4),
        r2ssa::StackAddressBase::StackPointer,
        -8,
    )]));
    assert!(
        untyped
            .authorized_stack_slot_owner_render_by_offset(-8, "local_buf")
            .is_none(),
        "unknown types are not enough for certified owner rendering"
    );
}

#[test]
fn decompile_type_override_requires_render_authorized_signature() {
    let base_signature = crate::FunctionSignatureSpec {
        ret_type: Some(crate::CTypeLike::Void),
        params: Vec::new(),
    };
    let override_signature = crate::FunctionSignatureSpec {
        ret_type: Some(crate::CTypeLike::Int {
            bits: 64,
            signedness: crate::Signedness::Unsigned,
        }),
        params: vec![crate::FunctionParamSpec {
            name: "buf".to_string(),
            ty: Some(crate::CTypeLike::Pointer(Box::new(crate::CTypeLike::Int {
                bits: 8,
                signedness: crate::Signedness::Unsigned,
            }))),
        }],
    };
    let mut facts = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(base_signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &base_signature,
            [crate::SignatureCertificateSource::ExternalContext],
        ),
        ..FunctionTypeFacts::default()
    });

    assert!(!facts.apply_decompile_type_override(FunctionTypeFacts {
        merged_signature: Some(override_signature.clone()),
        signature_certificate: None,
        ..FunctionTypeFacts::default()
    }));
    assert_eq!(
        facts.types.render_authorized_signature(),
        Some(&base_signature)
    );

    assert!(facts.apply_decompile_type_override(FunctionTypeFacts {
        merged_signature: Some(override_signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &override_signature,
            [crate::SignatureCertificateSource::ExternalContext],
        ),
        ..FunctionTypeFacts::default()
    }));
    assert_eq!(
        facts.types.render_authorized_signature(),
        Some(&override_signature)
    );
}

#[test]
fn decompile_fallback_comment_requires_fallback_route() {
    let fallback = DecompileRouteFacts {
        kind: DecompileRouteKind::FallbackComment,
        reason: Some("typed refusal".to_string()),
        fallback_comment: Some("/* typed fallback */".to_string()),
        use_prepared_semantic_view: false,
    };
    let standard_with_comment = DecompileRouteFacts {
        kind: DecompileRouteKind::Standard,
        reason: Some("must not render".to_string()),
        fallback_comment: Some("/* wrong route */".to_string()),
        use_prepared_semantic_view: false,
    };

    assert_eq!(
        FunctionFacts::default()
            .with_decompile_route(fallback)
            .decompile_fallback_comment(),
        Some("/* typed fallback */")
    );
    assert_eq!(
        FunctionFacts::default()
            .with_decompile_route(standard_with_comment)
            .decompile_fallback_comment(),
        None,
        "fallback comments are refusal payloads, not a side channel on executable routes"
    );
}

fn summary_with_effects(id: r2ssa::InterprocFunctionId) -> r2ssa::FunctionSemanticSummary {
    let mut summary = r2ssa::FunctionSemanticSummary::unknown(id, Some("sym.effect".into()));
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            escape: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    summary.arg_effects.insert(
        1,
        r2ssa::SummaryArgEffect {
            write: true,
            ..r2ssa::SummaryArgEffect::default()
        },
    );
    summary.memory_effects.push(r2ssa::SummaryMemoryEffect {
        kind: r2ssa::SummaryMemoryEffectKind::Write,
        location: r2ssa::SummaryMemoryLocation {
            region: r2ssa::SummaryMemoryRegion::Arg { index: 2 },
            range: None,
        },
    });
    summary.memory_effects.push(r2ssa::SummaryMemoryEffect {
        kind: r2ssa::SummaryMemoryEffectKind::Escape,
        location: r2ssa::SummaryMemoryLocation {
            region: r2ssa::SummaryMemoryRegion::Arg { index: 5 },
            range: None,
        },
    });
    summary.transfer_effects.push(r2ssa::SummaryTransferEffect {
        dst: r2ssa::SummaryMemoryLocation {
            region: r2ssa::SummaryMemoryRegion::Arg { index: 3 },
            range: None,
        },
        src: r2ssa::SummaryMemoryLocation {
            region: r2ssa::SummaryMemoryRegion::Arg { index: 4 },
            range: None,
        },
        len: r2ssa::SummaryTransferLength::Unknown,
    });
    summary
}

#[test]
fn summary_rollup_out_params_require_evidence() {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let helper = r2ssa::InterprocFunctionId(0x402000);
    let set = r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([
            (root, summary_with_effects(root)),
            (helper, summary_with_effects(helper)),
        ]),
        diagnostics: Default::default(),
    };

    let view = InterprocSummaryView::new(Some(set)).expect("current interproc report schema");

    assert_eq!(view.out_param_indices(), vec![1, 2, 3]);
    assert_eq!(
        view.rollup
            .as_ref()
            .expect("rollup")
            .out_param_facts
            .iter()
            .map(|fact| (&fact.evidence, &fact.source))
            .collect::<Vec<_>>(),
        vec![
            (
                &OutParamCertificateEvidence::InterprocArgWrite,
                &OutParamCertificateSource::InterprocSummaryEffect {
                    function_id: root.0,
                    evidence: OutParamCertificateEvidence::InterprocArgWrite,
                    param_index: 1,
                    effect_index: 1,
                },
            ),
            (
                &OutParamCertificateEvidence::InterprocMemoryWrite,
                &OutParamCertificateSource::InterprocSummaryEffect {
                    function_id: root.0,
                    evidence: OutParamCertificateEvidence::InterprocMemoryWrite,
                    param_index: 2,
                    effect_index: 0,
                },
            ),
            (
                &OutParamCertificateEvidence::InterprocTransferDst,
                &OutParamCertificateSource::InterprocSummaryEffect {
                    function_id: root.0,
                    evidence: OutParamCertificateEvidence::InterprocTransferDst,
                    param_index: 3,
                    effect_index: 0,
                },
            ),
        ]
    );
    assert_eq!(view.pointer_param_indices(), &[0, 1, 2, 3, 4, 5]);
    let helper_view = view
        .helper_view_for_name("sym.effect")
        .expect("helper view");
    assert_eq!(
        out_param_indices_from_facts(&helper_view.out_param_facts),
        vec![1, 2, 3]
    );
    assert_eq!(helper_view.pointer_param_indices, vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn interproc_summary_view_rejects_stale_or_mislabeled_reports() {
    let id = r2ssa::InterprocFunctionId(0x401000);
    let stale = r2ssa::InterprocSummarySet {
        schema_version: 1,
        ..r2ssa::InterprocSummarySet::default()
    };
    assert_eq!(
        InterprocSummaryView::new(Some(stale)),
        Err(r2ssa::interproc::InterprocSummarySchemaError::ReportSchemaVersion { found: 1 })
    );

    let summary_id = r2ssa::InterprocFunctionId(0x402000);
    let mut mislabeled = r2ssa::InterprocSummarySet::default();
    mislabeled.summaries.insert(
        id,
        r2ssa::FunctionSemanticSummary::unknown(summary_id, None),
    );
    assert_eq!(
        InterprocSummaryView::new(Some(mislabeled)),
        Err(
            r2ssa::interproc::InterprocSummarySchemaError::FunctionIdentityMismatch {
                key: id,
                summary_id,
            }
        )
    );
}

/// `rax = zext(t)` returned through an interface that states the carrier and no type for it.
fn untyped_return_source() -> r2ssa::SsaArtifact {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("RAX", 0, 8));
    arch.add_register(r2il::RegisterDef::new("RIP", 8, 8));
    arch.add_register(r2il::RegisterDef::new("RSP", 16, 8));
    let register = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"untyped-return".to_vec(),
        "sysv64",
        [],
        r2ssa::SourceFunctionReturn::Register {
            storage: register(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(register(8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
    .expect("carrier-only interface");
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::IntZExt {
        dst: Varnode::register(0, 8),
        src: Varnode::unique(0x20, 4),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(8, 8),
    });
    r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("prepared untyped return")
}

#[test]
fn a_recovered_graph_decides_a_carrier_and_a_read_one_the_exact_type() {
    let int32 = CTypeLike::Int {
        bits: 32,
        signedness: crate::Signedness::Signed,
    };
    let decide = |source: &r2ssa::SsaArtifact| {
        ReturnTypeFact::decide(source, &BTreeMap::new(), &crate::EvidenceTypes::default())
    };
    assert_eq!(
        decide(&signed_i32_return_source(true, true)),
        ReturnTypeFact::Decided {
            ty: int32.clone(),
            by: ReturnTypeEvidence::ExactSource,
        }
    );
    assert_eq!(
        decide(&signed_i32_return_source(true, false)),
        ReturnTypeFact::Decided {
            ty: int32,
            by: ReturnTypeEvidence::Carrier,
        }
    );
}

#[test]
fn no_value_is_void_only_where_the_boundary_proves_it() {
    let arch = {
        let mut arch = ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("RIP", 8, 8));
        arch
    };
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Return {
        target: Varnode::register(8, 8),
    });
    let unstated = r2ssa::SsaArtifact::for_patterns(&[block], Some(&arch)).expect("prepared");
    assert_eq!(
        ReturnTypeFact::decide(
            &unstated,
            &BTreeMap::new(),
            &crate::EvidenceTypes::default()
        ),
        ReturnTypeFact::Unproven { carrier: None }
    );
}

#[test]
fn a_locally_inferred_signature_does_not_decide_the_return() {
    // Local inference once spelled every untyped return as a scalar and let the signature win.
    let source = untyped_return_source();
    let signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::uint(32)),
        params: vec![FunctionParamSpec {
            name: "arg1".to_string(),
            ty: Some(CTypeLike::uint(64)),
        }],
    };
    let mut facts = FunctionFacts::new(FunctionTypeFacts {
        merged_signature: Some(signature.clone()),
        signature_certificate: crate::SignatureCertificate::from_signature(
            &signature,
            [crate::SignatureCertificateSource::LocalInference],
        ),
        ..FunctionTypeFacts::default()
    });
    facts.apply_return_type_fact(&source, &crate::EvidenceTypes::default());
    assert_eq!(
        facts.return_type(),
        Some(&ReturnTypeFact::Refused(ReturnTypeRefusal::UntypedReturn))
    );
    let merged = facts
        .type_facts()
        .merged_signature
        .as_ref()
        .expect("signature");
    assert_eq!(
        merged.ret_type, None,
        "the signature claims a return r2types refused"
    );
}
