//! What the artifact keeps of the lift it was built from.

use super::super::*;
use super::*;

/// An artifact built without an architecture names no user-operation.
///
/// `SSAOp::CallOther` carries an index alone, and an index means nothing
/// without the table it was assigned from. Returning `None` is what lets a
/// consumer refuse; inventing a name, or matching the index against a
/// hardcoded one, would make the answer depend on which architecture the
/// caller happened to be holding.
#[test]
fn an_artifact_without_an_architecture_names_no_user_operation() {
    let blocks = controlled_prep_blocks();
    let artifact = SsaArtifact::for_decompile(&blocks, None).expect("artifact");
    // The table is what travels; the lookup is the fact layer's, and an
    // empty table is what lets it refuse rather than guess at an index.
    assert!(artifact.user_operations().is_empty());
}

#[test]
fn decompile_ssa_models_post_call_arm64_return_register_clobber() {
    let arch = make_arm64_alias_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1400,
        size: 16,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0x00, 8),
                src: make_const(0, 8),
            },
            R2ILOp::Call {
                target: make_ram(0x401000, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(0x80, 8),
                src: make_reg(0x00, 8),
            },
            R2ILOp::IntEqual {
                dst: Varnode {
                    space: SpaceId::Unique,
                    offset: 0x20,
                    size: 1,
                    meta: None,
                },
                a: make_reg(0x80, 8),
                b: make_const(0, 8),
            },
            R2ILOp::CBranch {
                target: make_const(0x1410, 8),
                cond: Varnode {
                    space: SpaceId::Unique,
                    offset: 0x20,
                    size: 1,
                    meta: None,
                },
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared = prepared_preserving(&blocks, &arch, &[]).expect("prepared SSA should build");
    let ops = &prepared.get_block(0x1400).expect("entry block").ops;
    let post_call_x0 = ops
        .iter()
        .find_map(|op| match op {
            SSAOp::CallDefine { dst } if dst.name() == "x0" => Some(dst.clone()),
            _ => None,
        })
        .expect("decompile SSA should define a fresh x0 after calls");

    let copied_x8_source = ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Copy { dst, src } if dst.name() == "x8" => Some(src.clone()),
            _ => None,
        })
        .expect("expected x8 copy from call return register");

    assert_eq!(
        copied_x8_source, post_call_x0,
        "post-call x8 copy must use the fresh call result owner, not the pre-call x0"
    );
    assert_ne!(
        copied_x8_source,
        SSAVar::constant(0, 8),
        "call result must not fold back to the pre-call literal"
    );

    let x0_value = prepared
        .graph()
        .value_id_for_var(&post_call_x0)
        .expect("post-call x0 value");
    assert!(
        prepared
            .call_result_certificate_for_value(x0_value)
            .is_none()
    );

    let copied_x8_dst = ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Copy { dst, src } if dst.name() == "x8" && src == &post_call_x0 => {
                Some(dst.clone())
            }
            _ => None,
        })
        .expect("expected x8 alias of the certified call result");
    let copied_x8_value = prepared
        .graph()
        .value_id_for_var(&copied_x8_dst)
        .expect("copied x8 value");
    assert!(
        prepared
            .call_result_certificate_for_value(copied_x8_value)
            .is_none()
    );

    for op in ops {
        if let SSAOp::CallDefine { dst } = op
            && dst.name() == "x8"
        {
            let x8_call_define_value = prepared
                .graph()
                .value_id_for_var(dst)
                .expect("x8 call-define value");
            assert!(
                prepared
                    .call_result_certificate_for_value(x8_call_define_value)
                    .is_none(),
                "caller-saved x8 clobber must not be certified as a return value"
            );
        }
    }
}

#[test]
fn a_variadic_call_uses_its_literal_format_not_written_scratch_registers() {
    let no_tail = variadic_format_call(4, true, Some(1), Some("complete: 100%%"));
    assert_eq!(no_tail.argument_values.len(), 2);
    assert_eq!(no_tail.fixed_argument_count, Some(2));
    assert_eq!(
        no_tail
            .variadic_argument_count_evidence
            .expect("literal count evidence")
            .format_consumed_argument_count,
        0
    );

    let width_and_value = variadic_format_call(4, true, Some(1), Some("%*d"));
    assert_eq!(width_and_value.argument_values.len(), 4);
    assert_eq!(
        width_and_value
            .variadic_argument_count_evidence
            .expect("literal count evidence")
            .format_consumed_argument_count,
        2
    );

    let first_parameter_is_format = variadic_format_call(3, true, Some(0), Some("%u"));
    assert_eq!(first_parameter_is_format.argument_values.len(), 3);
    assert_eq!(
        first_parameter_is_format
            .variadic_argument_count_evidence
            .expect("literal count evidence")
            .format_argument_index,
        0
    );
}

#[test]
fn call_result_certificates_require_a_complete_machine_boundary() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1680,
        size: 4,
        ops: vec![
            R2ILOp::Call {
                target: make_const(0x401000, 8),
            },
            R2ILOp::Copy {
                dst: make_unique(0x20, 8),
                src: make_reg(0, 8),
            },
            R2ILOp::Call {
                target: make_const(0x402000, 8),
            },
            R2ILOp::Copy {
                dst: make_unique(0x30, 8),
                src: make_reg(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let callee_saved = ["rbx", "rsp", "rbp"];
    let first = prepared_preserving(&blocks, &arch, &callee_saved)
        .expect("first prepared SSA should build");
    let second = prepared_preserving(&blocks, &arch, &callee_saved)
        .expect("second prepared SSA should build");
    assert_eq!(
        first.certificates().call_results,
        second.certificates().call_results,
        "call-result certificates must be deterministic"
    );

    assert!(first.certificates().call_results.is_empty());
    assert!(first.certificates().call_results_by_callsite.is_empty());

    // With a convention boundary, a read of a contained return-register
    // lane is exact evidence for the result width even when the full
    // convention carrier itself has no reader. This is how an unknown
    // prototype returning in EAX is observed under an RAX result slot.
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::sub("eax", 0, 4, "rax"));
    let widened = make_unique(0x40, 8);
    let blocks = [R2ILBlock {
        addr: 0x16c0,
        size: 4,
        ops: vec![
            R2ILOp::Call {
                target: make_const(0x403000, 8),
            },
            R2ILOp::IntZExt {
                dst: widened.clone(),
                src: make_reg(0, 4),
            },
            R2ILOp::Copy {
                dst: make_unique(0x48, 8),
                src: widened,
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let full_result = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let callee_saved = [8, 16, 24].map(|offset| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    });
    let convention =
        SourceConventionSlots::new("amd64", [], Some(full_result)).expect("result convention");
    let prepared = SsaArtifact::for_decompile_with(
        &blocks,
        DecompileInputs {
            arch: Some(&arch),
            convention_slots: Some(convention),
            call_effect: clobbering([full_result], callee_saved),
            ..Default::default()
        },
    )
    .expect("prepared SSA with convention boundary");
    let call = prepared
        .sole_callsite_certificate_in_block(0x16c0)
        .expect("convention-certified call");
    // The call defines the root once; the lane the program reads is a
    // `Subpiece` of it, certified as that result sliced.
    let eax = prepared
        .function()
        .get_block(0x16c0)
        .into_iter()
        .flat_map(|block| &block.ops)
        .find_map(|op| match op {
            SSAOp::Subpiece {
                dst,
                src,
                offset: 0,
            } if dst.size == 4 && src.name().eq_ignore_ascii_case("rax") => {
                prepared.graph().value_id_for_var(dst)
            }
            _ => None,
        })
        .expect("post-call EAX lane read");
    let result = prepared
        .call_result_certificate_for_value(eax)
        .expect("observed return lane certificate");
    assert_eq!(result.call_site, call.call_site);
    assert_eq!(
        result.relation,
        crate::semantic::CallResultValueRelation::Derived
    );
    assert_eq!(result.width, 4);
    assert_eq!(
        result.carrier,
        crate::semantic::ReturnCarrier::Register {
            storage: full_result
        }
    );
}

#[test]
fn prepared_return_register_subpiece_zext_chain_is_renderable() {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0x00, 8));
    arch.add_register(RegisterDef::new("eax", 0x00, 4));
    arch.add_register(RegisterDef::new("rsi", 0x10, 8));
    arch.add_register(RegisterDef::new("esi", 0x10, 4));
    arch.add_register(RegisterDef::new("rdx", 0x18, 8));
    arch.add_register(RegisterDef::new("edx", 0x18, 4));
    arch.add_register(RegisterDef::new("rip", 0x20, 8));

    let blocks = vec![R2ILBlock {
        addr: 0x1740,
        size: 4,
        ops: vec![
            R2ILOp::IntAdd {
                dst: make_unique(0x4000, 8),
                a: make_reg(0x18, 8),
                b: make_reg(0x10, 8),
            },
            R2ILOp::Subpiece {
                dst: make_reg(0x00, 4),
                src: make_unique(0x4000, 8),
                offset: 0,
            },
            R2ILOp::IntZExt {
                dst: make_reg(0x00, 8),
                src: make_reg(0x00, 4),
            },
            R2ILOp::Return {
                target: make_reg(0x20, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA");
    let return_value = prepared
        .graph()
        .inst_id_for_op_site(0x1740, 2)
        .and_then(|inst| prepared.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("zero-extended return-register value");

    let expr_cert = prepared
        .certificates()
        .expressions
        .get(&return_value)
        .expect("return value expression certificate");
    let input_debug = expr_cert
        .inputs
        .iter()
        .map(|value| {
            let name = prepared
                .value_var(*value)
                .map(|var| var.display_name())
                .unwrap_or_else(|| "<unknown>".to_string());
            let renderable = prepared
                .certificates()
                .expressions
                .get(value)
                .is_some_and(|cert| cert.renderable);
            format!("{name}:{renderable}")
        })
        .collect::<Vec<_>>();
    let mut tmp_debug = Vec::new();
    for value in &expr_cert.inputs {
        if let Some(cert) = prepared.certificates().expressions.get(value) {
            let value_name = prepared
                .value_var(*value)
                .map(|var| var.display_name())
                .unwrap_or_else(|| "<unknown>".to_string());
            for input in &cert.inputs {
                let input_name = prepared
                    .value_var(*input)
                    .map(|var| var.display_name())
                    .unwrap_or_else(|| "<unknown>".to_string());
                let renderable = prepared
                    .certificates()
                    .expressions
                    .get(input)
                    .is_some_and(|cert| cert.renderable);
                tmp_debug.push(format!("{value_name}->{input_name}:{renderable}"));
            }
        }
    }
    assert!(
        expr_cert.renderable,
        "return-register subpiece/zext chain should be renderable; ret={:?} inputs={:?} tmp_inputs={:?}",
        prepared.value_var(return_value),
        input_debug,
        tmp_debug
    );
}

#[test]
fn a_callee_proven_to_preserve_a_register_leaves_it_undefined_by_the_call() {
    let arch = call_preservation_arch();
    // call 0x2000; *rsi = rdi; return -- the compiler kept rdi live across
    // the call because it knows the callee never writes it.
    let block = call_preservation_block(vec![
        R2ILOp::Call {
            target: make_ram(0x2000, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_reg(16, 8),
            val: make_reg(8, 8),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let rdi = call_preservation_storage(8, 8);
    let preserved = CalleePreservedCarriers::from([(0x2000u64, BTreeSet::from([rdi]))]);
    let with = SsaArtifact::for_decompile_with(
        std::slice::from_ref(&block),
        DecompileInputs {
            arch: Some(&arch),
            call_effect: call_preservation_effect(),
            callee_preserved_carriers: preserved,
            ..Default::default()
        },
    )
    .expect("artifact with a preserving callee");
    let without = call_preservation_artifact(std::slice::from_ref(&block), &arch)
        .expect("artifact without callee facts");
    let call_defines = |artifact: &SsaArtifact, name: &str| {
        artifact
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops
            .iter()
            .filter(|op| {
                matches!(op, SSAOp::CallDefine { dst } if dst.name().eq_ignore_ascii_case(name))
            })
            .count()
    };
    assert_eq!(call_defines(&without, "rdi"), 1);
    assert_eq!(call_defines(&with, "rdi"), 0);
    // What the callee may touch is still defined by the call.
    assert_eq!(call_defines(&with, "rsi"), 1);
    assert_eq!(call_defines(&with, "rax"), 1);
    // The store reads the value rdi held on entry, not a clobber.
    let stored = with
        .function()
        .get_block(0x1000)
        .expect("entry block")
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Store { val, .. } => Some(val.clone()),
            _ => None,
        })
        .expect("the store survives");
    assert_eq!(
        stored.version, 0,
        "{stored:?} must be the entry value of rdi"
    );
}

#[test]
fn a_callee_that_returns_an_unaffected_register_defines_it_at_the_call() {
    let mut arch = call_preservation_arch();
    // Preserved by the convention, so only the callee's own interface can say it is written.
    arch.add_register(RegisterDef::new("rbx", 32, 8));
    // call 0x2000; *rsi = rbx; return -- rbx holds what the call returned.
    let block = call_preservation_block(vec![
        R2ILOp::Call {
            target: make_ram(0x2000, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_reg(16, 8),
            val: make_reg(32, 8),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let returns_rbx = SourceFunctionInterface::new(
        b"rev".to_vec(),
        "cdecl",
        [],
        crate::SourceFunctionReturn::Register {
            storage: call_preservation_storage(32, 8),
        },
        [],
    )
    .expect("an interface returning rbx");
    let with = SsaArtifact::for_decompile_with(
        std::slice::from_ref(&block),
        DecompileInputs {
            arch: Some(&arch),
            call_effect: call_preservation_effect(),
            callee_interfaces: BTreeMap::from([(0x2000u64, returns_rbx)]),
            ..Default::default()
        },
    )
    .expect("artifact with a callee that returns rbx");
    let without = call_preservation_artifact(std::slice::from_ref(&block), &arch)
        .expect("artifact without callee facts");
    let call_defines = |artifact: &SsaArtifact| {
        artifact
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops
            .iter()
            .filter(|op| {
                matches!(op, SSAOp::CallDefine { dst } if dst.name().eq_ignore_ascii_case("rbx"))
            })
            .count()
    };
    assert_eq!(call_defines(&without), 0);
    assert_eq!(call_defines(&with), 1);
    let stored = |artifact: &SsaArtifact| {
        artifact
            .function()
            .get_block(0x1000)
            .expect("entry block")
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Store { val, .. } => Some(val.clone()),
                _ => None,
            })
            .expect("the store survives")
    };
    assert_eq!(stored(&without).version, 0, "the entry value of rbx");
    assert_ne!(
        stored(&with).version,
        0,
        "the store must read what the call returned, not the entry value"
    );
}

#[test]
fn a_leaf_body_preserves_every_clobbered_register_it_never_writes() {
    let arch = call_preservation_arch();
    let block = call_preservation_block(vec![
        R2ILOp::Copy {
            dst: make_reg(0, 4),
            src: make_const(1, 4),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let artifact = call_preservation_artifact(&[block], &arch).expect("leaf artifact");
    let preserved = &artifact.facts().boundaries.preserved_call_carriers;
    for offset in [8, 16, 24] {
        assert!(
            preserved.contains(&call_preservation_storage(offset, 8)),
            "register at {offset} is never written and must be preserved: {preserved:?}"
        );
    }
    assert!(!preserved.contains(&call_preservation_storage(0, 8)));
    assert!(!preserved.contains(&call_preservation_storage(0, 4)));
}

#[test]
fn a_body_that_leaves_by_a_jump_claims_no_preserved_register() {
    let arch = call_preservation_arch();
    let block = call_preservation_block(vec![
        R2ILOp::Copy {
            dst: make_reg(0, 4),
            src: make_const(1, 4),
        },
        R2ILOp::Branch {
            target: make_ram(0x3000, 8),
        },
    ]);
    let artifact = call_preservation_artifact(&[block], &arch).expect("jumping artifact");
    assert!(
        artifact
            .facts()
            .boundaries
            .preserved_call_carriers
            .is_empty(),
        "{:?}",
        artifact.facts().boundaries.preserved_call_carriers
    );
}

/// A call clobbers the direction flag, and what reads it after reads the zero the convention returns.
#[test]
fn a_call_returns_the_direction_flag_clear() {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("DF", 0x20a, 1));
    let direction = call_preservation_storage(0x20a, 1);
    // call 0x2000; rax = zext(DF); return
    let block = call_preservation_block(vec![
        R2ILOp::Call {
            target: make_ram(0x2000, 8),
        },
        R2ILOp::IntZExt {
            dst: make_reg(0, 8),
            src: make_reg(0x20a, 1),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let artifact = SsaArtifact::for_decompile_with(
        &[block],
        DecompileInputs {
            arch: Some(&arch),
            machine_roles: SourceMachineRoles::default()
                .with_direction_flag_storage(Some(direction)),
            convention_slots: Some(
                SourceConventionSlots::new("amd64", [], None).expect("convention slots"),
            ),
            call_effect: clobbering([call_preservation_storage(0, 8)], []),
            ..Default::default()
        },
    )
    .expect("artifact");
    let graph = artifact.graph();
    let clobbers = graph
        .insts
        .iter()
        .filter(|inst| {
            matches!(
                inst.payload,
                crate::graph::InstPayload::Op(SSAOp::CallDefine { .. })
            )
        })
        .filter(|inst| inst.canonical_storage == Some(direction))
        .filter_map(|inst| inst.output)
        .collect::<Vec<_>>();
    assert_eq!(clobbers.len(), 1, "the call clobbers the direction flag");
    assert!(
        clobbers
            .iter()
            .all(|value| graph.use_sites(*value).is_empty()),
        "what follows the call reads the convention's zero, not the clobber"
    );
}
