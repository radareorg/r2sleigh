//! What the collector proves each value can be.

use super::super::*;
use super::*;

#[test]
fn return_certificate_requires_one_complete_source_boundary_value() {
    let storage = register_storage(0, 8);
    let artifact = complete_return_artifact(SourceFunctionReturn::Register { storage });
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(boundary.complete);
    let [boundary_value] = boundary.values.as_slice() else {
        panic!("complete register return must expose one value")
    };
    let (block_addr, op_index) = artifact
        .graph()
        .op_site_for_inst(boundary.at)
        .expect("return op site");
    let certificate = artifact
        .return_certificate_for_op(block_addr, op_index)
        .expect("complete boundary value certificate");
    assert_eq!(certificate.at, boundary.at);
    assert_eq!(certificate.value, boundary_value.value);
    assert_eq!(certificate.width, 8);
    assert_eq!(certificate.source_logical_value, None);
    assert_eq!(
        certificate.carrier,
        Some(ReturnCarrier::Register { storage })
    );

    let mut ambiguous = artifact.facts().boundaries.clone();
    ambiguous
        .returns
        .get_mut(&boundary.at)
        .expect("return boundary")
        .values
        .push(*boundary_value);
    let (certificates, by_inst) = super::super::collect_return_value_certificates(
        &ambiguous,
        artifact.graph(),
        Some(artifact.machine_context()),
        &artifact.certificates().stack_reloads,
    );
    assert!(certificates.is_empty());
    assert!(by_inst.is_empty());
}

#[test]
fn low_bit_return_certificate_owns_the_exact_logical_extension_input() {
    let artifact = exact_signed_low_return_artifact(true);
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    let [boundary_value] = boundary.values.as_slice() else {
        panic!("exact physical return boundary")
    };
    let physical = boundary_value.value;
    let (block_addr, op_index) = artifact
        .graph()
        .op_site_for_inst(boundary.at)
        .expect("return op site");
    let certificate = artifact
        .return_certificate_for_op(block_addr, op_index)
        .expect("exact logical return certificate");
    assert_ne!(certificate.value, physical);
    assert_eq!(certificate.width, 4);
    assert_eq!(
        certificate.source_logical_value,
        artifact
            .machine_context()
            .function_interface()
            .and_then(SourceFunctionInterface::return_logical_value)
    );
    assert_eq!(
        certificate.carrier,
        Some(ReturnCarrier::Register {
            storage: register_storage(0, 8),
        })
    );
    // The logical value is the narrow value the extension widened: the
    // lane temporary the addition defined.
    assert!(
        artifact.graph().value(certificate.value).is_some_and(
            |value| value.var.size == 4 && artifact.graph().def_inst(value.id).is_some()
        )
    );
    let return_value_obligations = artifact
        .obligations()
        .obligations_for_inst(boundary.at)
        .filter(|obligation| obligation.id.kind == crate::SemanticObligationKind::ReturnValue)
        .collect::<Vec<_>>();
    assert_eq!(return_value_obligations.len(), 1);
    assert_eq!(return_value_obligations[0].inputs, [certificate.value]);
}

#[test]
fn low_bit_return_certificate_owns_a_constant_that_is_its_own_zero_extension() {
    for constant in [1u64, 0xffff_fffe, 0xffff_ffff] {
        let artifact = constant_low_return_artifact(constant);
        let boundary = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("return boundary");
        assert!(boundary.complete, "constant {constant:#x}");
        let (block_addr, op_index) = artifact
            .graph()
            .op_site_for_inst(boundary.at)
            .expect("return op site");
        let certificate = artifact
            .return_certificate_for_op(block_addr, op_index)
            .unwrap_or_else(|| panic!("certificate for constant {constant:#x}"));
        assert_eq!(certificate.width, 4, "constant {constant:#x}");
        assert_eq!(
            certificate.carrier,
            Some(ReturnCarrier::Register {
                storage: register_storage(0, 8),
            }),
            "constant {constant:#x}"
        );
        assert_eq!(
            certificate.source_logical_value,
            artifact
                .machine_context()
                .function_interface()
                .and_then(SourceFunctionInterface::return_logical_value),
            "constant {constant:#x}"
        );
    }
}

/// The same shape with a constant that does not fit the logical width:
/// its upper bits are not zero, so the carrier is not the zero-extension
/// of the declared return and nothing proves what the return holds.
#[test]
fn low_bit_return_certificate_narrows_a_constant_wider_than_the_logical_width() {
    // `mov rax, 0x100000007` before an `int` return: the caller reads the
    // low lane, 7, and the certificate names the carrier at that width.
    let artifact = constant_low_return_artifact(0x1_0000_0007);
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(boundary.complete);
    let [physical] = boundary.values.as_slice() else {
        panic!("one boundary value");
    };
    let certificate = artifact
        .certificates()
        .returns
        .first()
        .expect("carrier return certificate");
    assert_eq!(certificate.value, physical.value);
    assert_eq!(certificate.width, 4);
}

#[test]
fn low_bit_return_certificate_narrows_a_full_write_to_the_carrier() {
    // A full write of the carrier that was never an extension of the
    // logical width still returns its low lane: the certificate names
    // the carrier, and the render narrows it to the declared type.
    let artifact = exact_signed_low_return_artifact(false);
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(boundary.complete);
    let [physical] = boundary.values.as_slice() else {
        panic!("one boundary value");
    };
    let certificate = artifact
        .certificates()
        .returns
        .first()
        .expect("carrier return certificate");
    assert_eq!(certificate.value, physical.value);
    assert_eq!(certificate.width, 4);
}

#[test]
fn complete_void_boundary_owns_no_return_value_certificate() {
    let artifact = complete_return_artifact(SourceFunctionReturn::Void);
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(boundary.complete);
    assert!(boundary.values.is_empty());
    assert!(artifact.certificates().returns.is_empty());
}

#[test]
fn stack_return_carrier_requires_stack_reload_certificate() {
    let storage = register_storage(0, 8);
    let artifact = complete_return_artifact(SourceFunctionReturn::Register { storage });
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    let mut value = boundary.values[0];
    value.slot = CallBoundarySlot::Stack(-8);
    assert_eq!(
        super::super::return_carrier_for_boundary_value(&value, &BTreeMap::new()),
        None
    );

    let access = StructuredAccessId {
        inst: boundary.at,
        ordinal: 0,
    };
    let object = ObjectId(7);
    let reload = StackReloadSourceCertificate {
        value: value.value,
        relation: crate::view::ViewRelation::Identity,
        reload: value.value,
        source: value.value,
        canonical_source: value.value,
        object,
        base: StackAddressBase::StackPointer,
        offset: -8,
        value_width: 8,
        memory_width: 8,
        store_access: access,
        load_access: access,
        store_inst: boundary.at,
        load_inst: boundary.at,
    };
    assert_eq!(
        super::super::return_carrier_for_boundary_value(
            &value,
            &BTreeMap::from([(value.value, reload)]),
        ),
        Some(ReturnCarrier::StackSlot {
            object,
            offset: -8,
            memory_access: Some(access),
        })
    );
}

#[test]
fn exit_stack_pointer_requires_preserved_entry_or_identical_path_value() {
    let mut direct = R2ILBlock::new(0x6000, 4);
    direct.push(R2ILOp::Copy {
        dst: Varnode::unique(0x100, 8),
        src: Varnode::register(32, 8),
    });
    direct.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let direct = SsaArtifact::raw_with_interface(
        &[direct],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("entry-live-in stack artifact");
    let direct_boundary = direct
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("direct return boundary");
    let entry_stack = direct_boundary
        .exit_stack_pointer
        .expect("entry stack pointer reaches return");
    assert_eq!(entry_stack.storage(), register_storage(32, 8));
    assert!(
        direct
            .graph()
            .def_inst(entry_stack.value().expect("explicit entry SP value"))
            .is_none()
    );
    assert!(direct_boundary.complete);

    let mut frameless = R2ILBlock::new(0x6050, 4);
    frameless.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let frameless = SsaArtifact::raw_with_interface(
        &[frameless],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("frameless stack artifact");
    let frameless_boundary = frameless
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("frameless return boundary");
    assert_eq!(
        frameless_boundary.exit_stack_pointer,
        Some(super::super::SourceReturnStackPointerFact::PreservedEntry {
            storage: register_storage(32, 8),
        })
    );
    assert!(frameless_boundary.complete);

    let mut loop_entry = R2ILBlock::new(0x6060, 4);
    loop_entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x6070, 8),
    });
    let mut loop_header = R2ILBlock::new(0x6070, 4);
    loop_header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6070, 8),
        cond: Varnode::register(24, 1),
    });
    let mut loop_exit = R2ILBlock::new(0x6074, 4);
    loop_exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let loop_preserved = SsaArtifact::raw_with_interface(
        &[loop_entry, loop_header, loop_exit],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("loop-preserved stack artifact");
    let loop_boundary = loop_preserved
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("loop return boundary");
    assert_eq!(
        loop_boundary.exit_stack_pointer,
        Some(super::super::SourceReturnStackPointerFact::PreservedEntry {
            storage: register_storage(32, 8),
        })
    );
    assert!(loop_boundary.complete);

    let mut entry = R2ILBlock::new(0x6100, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::unique(0x110, 8),
        src: Varnode::register(32, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6120, 8),
        cond: Varnode::register(24, 1),
    });
    let mut right = R2ILBlock::new(0x6104, 4);
    right.push(R2ILOp::Branch {
        target: Varnode::ram(0x6130, 8),
    });
    let mut left = R2ILBlock::new(0x6120, 4);
    left.push(R2ILOp::Branch {
        target: Varnode::ram(0x6130, 8),
    });
    let mut joined = R2ILBlock::new(0x6130, 4);
    joined.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let convergent = SsaArtifact::raw_with_interface(
        &[entry, right, left, joined],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("convergent stack artifact");
    let convergent_boundary = convergent
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("convergent return boundary");
    let converged_stack = convergent_boundary
        .exit_stack_pointer
        .expect("identical paths retain the entry stack pointer");
    assert_eq!(converged_stack.storage(), register_storage(32, 8));
    assert!(
        convergent
            .graph()
            .def_inst(converged_stack.value().expect("converged entry SP value"))
            .is_none()
    );
    assert!(convergent_boundary.complete);
}

#[test]
fn exit_stack_pointer_survives_an_early_return_that_skips_the_frame() {
    // `if (!x) return;` before the prologue and the epilogue that
    // unwinds the frame meet at one `ret`: the stack pointer merges two
    // values that are both the entry pointer.
    let sp = Varnode::register(32, 8);
    let mut entry = R2ILBlock::new(0x6200, 4);
    entry.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6230, 8),
        cond: Varnode::register(24, 1),
    });
    let mut body = R2ILBlock::new(0x6204, 4);
    body.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(0x40, 8),
    });
    body.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(7, 8),
    });
    body.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(0x40, 8),
    });
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x6230, 8),
    });
    let mut exit = R2ILBlock::new(0x6230, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let artifact = SsaArtifact::for_decompile_with_interface(
        &[entry, body, exit],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("early-return stack artifact");
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert_eq!(
        boundary.exit_stack_pointer,
        Some(super::super::SourceReturnStackPointerFact::PreservedEntry {
            storage: register_storage(32, 8),
        })
    );
    assert!(boundary.complete);
}

#[test]
fn a_step_this_cannot_state_exactly_is_absent_rather_than_approximated() {
    // Exclusive-or has no affine reading. The old recogniser answered
    // `XorConst` here; this refuses, because a consumer reading a step is
    // entitled to assume it describes the whole motion.
    let counter = Varnode::register(40, 8);
    let artifact = induction_loop_artifact(&[R2ILOp::IntXor {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(0x9e3779b9, 8),
    }]);
    // The loop and its carrier exist; it is the step that is refused. A
    // `None` from a fixture with no carrier would prove nothing.
    let carriers: usize = artifact
        .facts()
        .structured
        .loops
        .values()
        .map(|loop_fact| loop_fact.carriers.len())
        .sum();
    assert_eq!(carriers, 1, "the fixture carries a value round the latch");
    assert_eq!(recovered_induction_step(&artifact), None);
}

#[test]
fn counted_for_certificate_joins_condition_phi_initializer_and_latch_by_identity() {
    let artifact = counted_loop_artifact(true);
    let graph = artifact.graph();
    let certificate = artifact
        .facts()
        .certificates
        .loops
        .values()
        .find_map(|loop_fact| loop_fact.for_loop.as_ref())
        .unwrap_or_else(|| {
            panic!(
                "counted loop certificate: structured={:#?} prepared={:#?} predicates={:#?}",
                artifact.facts().structured.loops,
                artifact.facts().certificates.loops,
                artifact.facts().predicates,
            )
        });
    let induction = artifact
        .facts()
        .structured
        .inductions
        .get(&certificate.induction_phi)
        .expect("certificate induction fact");

    assert_eq!(certificate.induction_init, induction.init);
    assert_eq!(certificate.induction_update, induction.update);
    assert_eq!(certificate.latch, induction.latch);
    assert_eq!(certificate.initializer.value, induction.init);
    assert!(certificate.initializer.validate(graph));
    assert!(induction.validate(graph));

    let unrelated = counted_loop_artifact(false);
    assert!(
        unrelated
            .facts()
            .certificates
            .loops
            .values()
            .all(|loop_fact| loop_fact.for_loop.is_none()),
        "an induction step does not license `for` when the condition reads another value"
    );
}

#[test]
fn unrelated_condition_value_has_no_for_certificate() {
    let artifact = counted_loop_artifact(false);
    assert!(
        !artifact.facts().structured.inductions.is_empty(),
        "the refusal fixture must still contain an induction"
    );
    assert!(for_certificate(&artifact).is_none());
}

#[test]
fn distinct_value_identities_never_merge_for_certificate_by_name() {
    let artifact = counted_loop_artifact(false);
    let structured = &artifact.facts().structured;
    let induction = structured
        .inductions
        .values()
        .next()
        .expect("loop induction");
    let loop_fact = structured.loops.get(&induction.loop_id).expect("its loop");
    let comparison = artifact
        .facts()
        .predicates
        .predicates
        .get(&loop_fact.condition.expect("loop condition"))
        .and_then(|predicate| predicate.comparison.as_ref())
        .expect("loop comparison");
    assert!(!super::super::value_depends_on(
        artifact.graph(),
        comparison.lhs,
        induction.phi
    ));
    assert!(!super::super::value_depends_on(
        artifact.graph(),
        comparison.rhs,
        induction.phi
    ));
    assert!(for_certificate(&artifact).is_none());
}

#[test]
fn return_boundary_requires_declared_return_address_and_roots_it() {
    let mut exact = R2ILBlock::new(0x6150, 4);
    exact.push(R2ILOp::Copy {
        dst: Varnode::register(16, 8),
        src: Varnode::constant(0xfeed_face, 8),
    });
    exact.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let exact = SsaArtifact::raw_with_interface(
        &[exact],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("exact return-address artifact");
    let boundary = exact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("exact return boundary");
    let return_address = boundary.return_address.expect("declared return address");
    assert_eq!(return_address.storage, register_storage(16, 8));
    let producer = exact
        .graph()
        .def_inst(return_address.value)
        .expect("return-address producer");
    assert!(
        exact
            .obligations()
            .obligations_for_inst(producer)
            .any(|obligation| { obligation.id.kind == SemanticObligationKind::LiveValueProducer })
    );
    assert!(boundary.complete);

    let mut transported = R2ILBlock::new(0x6154, 4);
    transported.push(R2ILOp::Copy {
        dst: Varnode::register(40, 8),
        src: Varnode::register(16, 8),
    });
    transported.push(R2ILOp::Return {
        target: Varnode::register(40, 8),
    });
    let transported = SsaArtifact::raw_with_interface(
        &[transported],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("transported return-address artifact");
    let transported_boundary = transported
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("transported return boundary");
    let transported_address = transported_boundary
        .return_address
        .expect("declared return address transported to control target");
    assert_eq!(transported_address.storage, register_storage(16, 8));
    // The copy into the control register is forwarded: the return reads
    // the declared return address itself, and the copy is read by nothing.
    assert_eq!(
        transported
            .graph()
            .value(transported_address.value)
            .and_then(|value| value.canonical_storage),
        Some(register_storage(16, 8))
    );
    assert!(
        transported
            .graph()
            .def_inst(transported_address.value)
            .is_none(),
        "the return address is the value the function was entered with"
    );
    assert!(transported_boundary.complete);

    let mut wrong_source = R2ILBlock::new(0x6158, 4);
    wrong_source.push(R2ILOp::Copy {
        dst: Varnode::register(40, 8),
        src: Varnode::register(0, 8),
    });
    wrong_source.push(R2ILOp::Return {
        target: Varnode::register(40, 8),
    });

    let mut non_copy = R2ILBlock::new(0x615c, 4);
    non_copy.push(R2ILOp::IntAdd {
        dst: Varnode::register(40, 8),
        a: Varnode::register(16, 8),
        b: Varnode::constant(0, 8),
    });
    non_copy.push(R2ILOp::Return {
        target: Varnode::register(40, 8),
    });

    let mut non_terminal = R2ILBlock::new(0x6160, 4);
    non_terminal.push(R2ILOp::Copy {
        dst: Varnode::register(40, 8),
        src: Varnode::register(16, 8),
    });
    non_terminal.push(R2ILOp::Nop);
    non_terminal.push(R2ILOp::Return {
        target: Varnode::register(40, 8),
    });

    let mut copy_chain = R2ILBlock::new(0x6164, 4);
    copy_chain.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::register(16, 8),
    });
    copy_chain.push(R2ILOp::Copy {
        dst: Varnode::register(40, 8),
        src: Varnode::register(0, 8),
    });
    copy_chain.push(R2ILOp::Return {
        target: Varnode::register(40, 8),
    });

    // However the address is moved, the return reads the declared value
    // itself once the copies are forwarded, so the spelling of the
    // transport no longer decides anything.
    for transported in [non_terminal, copy_chain] {
        let artifact = SsaArtifact::raw_with_interface(
            &[transported],
            Some(&return_boundary_arch()),
            preserved_stack_interface(),
        )
        .expect("transported return-address artifact");
        let boundary = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("transported return boundary");
        assert_eq!(
            boundary.return_address.map(|address| address.storage),
            Some(register_storage(16, 8))
        );
        assert!(boundary.complete);
    }

    for corrupt in [wrong_source, non_copy] {
        let artifact = SsaArtifact::raw_with_interface(
            &[corrupt],
            Some(&return_boundary_arch()),
            preserved_stack_interface(),
        )
        .expect("invalid transported return-address artifact");
        let boundary = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("invalid transported return boundary");
        assert!(boundary.return_address.is_none());
        assert!(!boundary.complete);
    }

    for target in [Varnode::register(0, 8), Varnode::constant(0, 8)] {
        let mut corrupt = R2ILBlock::new(0x6168, 4);
        corrupt.push(R2ILOp::Return { target });
        let artifact = SsaArtifact::raw_with_interface(
            &[corrupt],
            Some(&return_boundary_arch()),
            preserved_stack_interface(),
        )
        .expect("corrupt return-address artifact");
        let boundary = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("corrupt return boundary");
        assert!(boundary.return_address.is_none());
        assert!(!boundary.complete);
    }
}

#[test]
fn exit_stack_pointer_refuses_divergence_calls_and_partial_writes() {
    let divergent_blocks = || {
        let mut entry = R2ILBlock::new(0x6200, 4);
        entry.push(R2ILOp::Copy {
            dst: Varnode::unique(0x120, 8),
            src: Varnode::register(32, 8),
        });
        entry.push(R2ILOp::CBranch {
            target: Varnode::ram(0x6220, 8),
            cond: Varnode::register(24, 1),
        });
        let mut right = R2ILBlock::new(0x6204, 4);
        right.push(R2ILOp::Copy {
            dst: Varnode::register(32, 8),
            src: Varnode::constant(0x1000, 8),
        });
        right.push(R2ILOp::Branch {
            target: Varnode::ram(0x6230, 8),
        });
        let mut left = R2ILBlock::new(0x6220, 4);
        left.push(R2ILOp::Copy {
            dst: Varnode::register(32, 8),
            src: Varnode::constant(0x2000, 8),
        });
        left.push(R2ILOp::Branch {
            target: Varnode::ram(0x6230, 8),
        });
        let mut joined = R2ILBlock::new(0x6230, 4);
        joined.push(R2ILOp::Return {
            target: Varnode::register(16, 8),
        });
        vec![entry, right, left, joined]
    };
    let divergent = SsaArtifact::raw_with_interface(
        &divergent_blocks(),
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("divergent stack artifact");
    let divergent_boundary = divergent
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("divergent return boundary");
    assert!(divergent_boundary.exit_stack_pointer.is_none());
    assert!(!divergent_boundary.complete);

    // A call is destructive; a user operation with no output writes nothing, so SP survives it.
    for (case_index, (op, destroys)) in [
        (
            R2ILOp::Call {
                target: Varnode::ram(0x9000, 8),
            },
            true,
        ),
        (
            R2ILOp::CallOther {
                output: None,
                userop: 7,
                inputs: Vec::new(),
            },
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut block = R2ILBlock::new(0x6300, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x130, 8),
            src: Varnode::register(32, 8),
        });
        block.push(op);
        block.push(R2ILOp::Return {
            target: Varnode::register(16, 8),
        });
        let artifact = SsaArtifact::raw_with_interface(
            &[block],
            Some(&return_boundary_arch()),
            preserved_stack_interface(),
        )
        .expect("closed stack artifact");
        let boundary = artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("closed return boundary");
        assert_eq!(
            boundary.exit_stack_pointer.is_none(),
            destroys,
            "SP case {case_index}: {boundary:?}"
        );
        assert_eq!(!boundary.complete, destroys, "SP case {case_index}");
    }

    // A write to a lane of the stack pointer defines the whole register:
    // the exit value is that definition, which is not the entry value.
    let mut block = R2ILBlock::new(0x6300, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x130, 8),
        src: Varnode::register(32, 8),
    });
    block.push(R2ILOp::Copy {
        dst: Varnode::register(32, 4),
        src: Varnode::constant(0, 4),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let artifact = SsaArtifact::raw_with_interface(
        &[block],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("lane-written stack artifact");
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    let exit = boundary
        .exit_stack_pointer
        .expect("the inserted lane defines the exit stack pointer");
    let value = exit.value().expect("a defined value, not the entry");
    assert!(artifact.graph().def_inst(value).is_some());
}

#[test]
fn exit_stack_pointer_prunes_disconnected_returns_and_handles_reachable_cycles() {
    let mut entry = R2ILBlock::new(0x6350, 4);
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x6354, 8),
    });
    let mut dead = R2ILBlock::new(0x6354, 4);
    dead.push(R2ILOp::Branch {
        target: Varnode::ram(0x6354, 8),
    });
    let mut disconnected_return = R2ILBlock::new(0x6360, 4);
    disconnected_return.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let disconnected = SsaArtifact::raw_with_interface(
        &[entry, dead, disconnected_return],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("disconnected return artifact");
    assert!(disconnected.facts().boundaries.returns.is_empty());

    let mut entry = R2ILBlock::new(0x6370, 4);
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x6374, 8),
    });
    let mut cycle = R2ILBlock::new(0x6374, 4);
    cycle.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6374, 8),
        cond: Varnode::register(24, 1),
    });
    let mut cycle_return = R2ILBlock::new(0x6378, 4);
    cycle_return.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let cycle_only = SsaArtifact::raw_with_interface(
        &[entry, cycle, cycle_return],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("reachable cycle return artifact");
    let boundary = cycle_only
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("reachable cycle return boundary");
    assert!(boundary.exit_stack_pointer.is_some());
    assert!(boundary.complete);
}

#[test]
fn exit_stack_pointer_is_collected_for_every_return() {
    let mut entry = R2ILBlock::new(0x6400, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::unique(0x140, 8),
        src: Varnode::register(32, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6420, 8),
        cond: Varnode::register(24, 1),
    });
    let mut right = R2ILBlock::new(0x6404, 4);
    right.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let mut left = R2ILBlock::new(0x6420, 4);
    left.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let artifact = SsaArtifact::raw_with_interface(
        &[entry, right, left],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("multi-return stack artifact");
    assert_eq!(artifact.facts().boundaries.returns.len(), 2);
    let values = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .map(|boundary| {
            assert!(boundary.complete);
            boundary
                .exit_stack_pointer
                .expect("typed stack pointer at every return")
                .value()
                .expect("multi-return graph carries entry SP")
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(values.len(), 1);
}

#[test]
fn return_boundary_without_typed_machine_roles_carries_values_but_no_exit_state() {
    // The lane writes define the root, so the return's value is found and
    // reported. The exit machine state the interface never named stays
    // absent: the values a return carries and the state it leaves behind
    // are separate questions, and the second cannot suppress the first.
    let artifact = composed_return_artifact(0x5000, "whole", "slice", "pc");
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(boundary.complete);
    assert!(boundary.exit_stack_pointer.is_none());
    assert!(!boundary.machine_state_complete);
    assert_eq!(
        boundary.values.len(),
        1,
        "the declared return register names one value"
    );
    let walked = super::super::reaching_abi_value_in_block(
        artifact.function(),
        artifact.graph(),
        artifact.machine_context(),
        0x5000,
        5,
        register_storage(0, 4),
    )
    .expect("the root the lane writes define");
    assert!(artifact.graph().def_inst(walked).is_some());
}

#[test]
fn return_boundary_refuses_unrepresented_partial_overlap() {
    let mut arch = composed_return_arch("whole", "slice", "pc");
    arch.add_register(RegisterDef::new("partial", 3, 2));
    let mut block = R2ILBlock::new(0x5180, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 4),
        src: Varnode::constant(0, 4),
    });
    block.push(R2ILOp::Copy {
        dst: Varnode::register(3, 2),
        src: Varnode::constant(1, 2),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let artifact = SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&arch),
        composed_return_interface(),
    )
    .expect("partial-overlap artifact");
    let boundary = artifact
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("return boundary");
    assert!(!boundary.complete);
    assert!(boundary.values.is_empty());
}

#[test]
fn return_boundary_refusal_is_deterministic_name_and_address_independent() {
    let first = composed_return_artifact(0x5200, "whole_a", "slice_a", "pc_a");
    let repeated = composed_return_artifact(0x5200, "whole_a", "slice_a", "pc_a");
    let renamed = composed_return_artifact(0x5200, "whole_b", "slice_b", "pc_b");
    let relocated = composed_return_artifact(0x9200, "whole_a", "slice_a", "pc_a");
    let boundary = |artifact: &SsaArtifact| {
        artifact
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .cloned()
            .expect("return boundary")
    };
    let first = boundary(&first);
    for refused in [
        boundary(&repeated),
        boundary(&renamed),
        boundary(&relocated),
    ] {
        assert_eq!(refused, first);
        assert!(!refused.machine_state_complete);
        assert!(refused.exit_stack_pointer.is_none());
    }
}
