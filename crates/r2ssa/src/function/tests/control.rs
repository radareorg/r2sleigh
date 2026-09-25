//! What the artifact proves about control flow and merges.

use super::super::*;
use super::*;

#[test]
fn tail_jump_identity_requires_matching_terminal_branch() {
    let mut branch = R2ILBlock::new(0x1000, 4);
    branch.push_with_metadata(
        R2ILOp::Branch {
            target: make_const(0x5000, 8),
        },
        Some(r2il::OpMetadata {
            instruction_addr: Some(0x1000),
            ..r2il::OpMetadata::default()
        }),
    );
    let tail = advisory_call_site(0x1000, 0x5000, r2source::AdvisoryCallTransfer::TailJump);
    let identity = unique_call_site_identity(&[branch.clone()], &tail)
        .expect("exact terminal branch is the source-proven callsite");
    assert_eq!(identity.instruction(), 0x1000);
    assert_eq!(identity.target().offset, 0x5000);

    let ordinary_call = advisory_call_site(0x1000, 0x5000, r2source::AdvisoryCallTransfer::Call);
    assert!(unique_call_site_identity(&[branch.clone()], &ordinary_call).is_none());

    branch.ops.push(R2ILOp::Nop);
    assert!(unique_call_site_identity(&[branch], &tail).is_none());

    let mut call = R2ILBlock::new(0x2000, 4);
    call.push_with_metadata(
        R2ILOp::Call {
            target: make_const(0x6000, 8),
        },
        Some(r2il::OpMetadata {
            instruction_addr: Some(0x2000),
            ..r2il::OpMetadata::default()
        }),
    );
    call.push(R2ILOp::Nop);
    let ordinary_call = advisory_call_site(0x2000, 0x6000, r2source::AdvisoryCallTransfer::Call);
    assert!(
        unique_call_site_identity(&[call], &ordinary_call).is_some(),
        "ordinary calls keep their original nonterminal correlation rule"
    );
}

#[test]
fn unchecked_and_controlled_decompile_builders_produce_identical_artifacts() {
    let blocks = controlled_prep_blocks();
    let unchecked = SsaArtifact::for_decompile(&blocks, None).expect("unchecked artifact");
    let controlled = SsaArtifact::for_decompile_with_control(
        blocks.as_slice(),
        None,
        &crate::SsaExecutionControl::default(),
    )
    .expect("controlled artifact");

    assert_eq!(
        unchecked.function().block_addrs(),
        controlled.function().block_addrs()
    );
    for (lhs, rhs) in unchecked
        .function()
        .blocks()
        .iter()
        .zip(controlled.function().blocks())
    {
        assert_eq!(lhs.addr, rhs.addr);
        assert_eq!(lhs.size, rhs.size);
        assert_eq!(lhs.ops, rhs.ops);
        assert_eq!(lhs.phis.len(), rhs.phis.len());
        for (lhs_phi, rhs_phi) in lhs.phis.iter().zip(&rhs.phis) {
            assert_eq!(lhs_phi.dst, rhs_phi.dst);
            assert_eq!(lhs_phi.sources, rhs_phi.sources);
            assert_eq!(lhs_phi.canonical_storage, rhs_phi.canonical_storage);
        }
    }
    assert_eq!(
        unchecked.function().decompile_prep_facts(),
        controlled.function().decompile_prep_facts()
    );
    assert_eq!(unchecked.graph(), controlled.graph());
    assert_eq!(unchecked.facts(), controlled.facts());
    assert_eq!(unchecked.machine_context(), controlled.machine_context());
}

#[test]
fn prepared_function_ssa_tracks_mode_and_keeps_named_blocks() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(1, 8),
            },
            R2ILOp::Return {
                target: make_reg(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch))
        .expect("prepared SSA should build")
        .with_name("prepared_demo");

    assert_eq!(prepared.name.as_deref(), Some("prepared_demo"));
    assert!(
        prepared.decompile_prep_facts().is_some(),
        "decompile preparation should retain prep facts"
    );

    let local_blocks = prepared.local_ssa_blocks();
    assert_eq!(local_blocks.len(), 1);
    assert_eq!(local_blocks[0].addr, 0x1000);
    assert_eq!(
        local_blocks[0].ops,
        prepared.blocks().iter().next().expect("entry block").ops
    );

    let symbolic = SsaArtifact::for_symbolic(&blocks, Some(&arch))
        .expect("symbolic prepared SSA should build");
    assert!(
        symbolic.decompile_prep_facts().is_some(),
        "symbolic preparation should retain canonical prep facts for shared consumers"
    );
}

#[test]
fn prepared_function_does_not_infer_return_phi_without_source_boundary_authority() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![
        R2ILBlock {
            addr: 0x1100,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1110, 8),
                cond: make_reg(8, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1104,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(7, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1114, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1110,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(7, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1114, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1114,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
    assert!(prepared.certificates().returns.is_empty());
    assert!(prepared.return_certificate_for_op(0x1114, 0).is_none());
}

#[test]
fn prepared_expression_certificates_render_only_identity_phis() {
    fn prepared_with_phi_values(left: u64, right: u64) -> SsaArtifact {
        let arch = make_x86_64_prep_arch();
        let blocks = vec![
            R2ILBlock {
                addr: 0x1710,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1724, 8),
                    cond: make_reg(8, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1714,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(left, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1730, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1724,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(right, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x1730, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1730,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_reg(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build")
    }

    let identity_phi = prepared_with_phi_values(7, 7);
    let identity_value = identity_phi
        .graph()
        .inst_id_for_op_site(0x1730, 0)
        .and_then(|inst| identity_phi.graph().inst(inst))
        .and_then(|inst| inst.inputs.first().copied())
        .expect("identity phi return input");
    assert!(
        identity_phi
            .certificates()
            .expressions
            .get(&identity_value)
            .is_some_and(|cert| cert.renderable),
        "identity phi over one renderable ValueId should be renderable"
    );

    let mixed_phi = prepared_with_phi_values(7, 9);
    let mixed_value = mixed_phi
        .graph()
        .inst_id_for_op_site(0x1730, 0)
        .and_then(|inst| mixed_phi.graph().inst(inst))
        .and_then(|inst| inst.inputs.first().copied())
        .expect("mixed phi return input");
    assert!(
        mixed_phi
            .certificates()
            .expressions
            .get(&mixed_value)
            .is_some_and(|cert| cert.renderable),
        "non-memory phi with sibling values should be renderable; divergence handled by structurer"
    );
}

#[test]
fn prepared_expression_certificates_render_loop_carried_recurrence_phi() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1800,
            size: 0x10,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1810, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1810,
            size: 0x4,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1820, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1814,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1820,
            size: 0x4,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1810, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let mut function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let init = SSAVar::new("RAX", 0, 8);
    let phi = SSAVar::new("RAX", 2, 8);
    let update_source = SSAVar::new("tmp:update", 1, 8);
    let update = SSAVar::new("RAX", 3, 8);
    function.get_block_mut(0x1810).expect("loop header").phis = vec![PhiNode {
        dst: phi.clone(),
        sources: vec![(0x1800, init), (0x1820, update.clone())],
        canonical_storage: None,
    }];
    function.get_block_mut(0x1820).expect("loop latch").ops = vec![
        SSAOp::IntAdd {
            dst: update_source.clone(),
            a: phi.clone(),
            b: SSAVar::constant(1, 8),
        },
        SSAOp::Copy {
            dst: update,
            src: update_source.clone(),
        },
        SSAOp::Branch {
            target: SSAVar::new("ram:1810", 0, 8),
            instruction: None,
        },
    ];
    function.get_block_mut(0x1814).expect("loop exit").ops = vec![SSAOp::Return {
        target: phi.clone(),
    }];

    let prepared = SsaArtifact::new(function);
    let carrier = prepared
        .structured()
        .loops
        .values()
        .flat_map(|loop_fact| loop_fact.carriers.iter())
        .find(|carrier| carrier.phi == prepared.graph().value_id_for_var(&phi).unwrap())
        .expect("loop-carried phi fact");
    assert_eq!(carrier.id, SemanticId::loop_carrier(carrier.phi));
    assert_eq!(carrier.entries.len(), 1);
    assert_eq!(carrier.updates.len(), 1);
    assert!(
        carrier.updates[0]
            .identity_values
            .contains(&prepared.graph().value_id_for_var(&update_source).unwrap()),
        "same-width copy sources retain exact update identity at the latch program point"
    );
    assert!(carrier.identity_values.contains(&carrier.phi));
    assert!(
        prepared
            .certificates()
            .expressions
            .get(&carrier.phi)
            .is_some_and(|cert| cert.renderable),
        "loop-header phi is renderable when the loop certificate proves the backedge and the update is pure modulo that phi"
    );
}

#[test]
fn prepared_predicates_preserve_machine_point_comparison_before_normalization() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1900,
            size: 0x4,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1910, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1904,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1910,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let mut function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let before = SSAVar::new("RAX", 0, 8);
    let one = SSAVar::constant(1, 8);
    let updated = SSAVar::new("tmp:updated", 1, 8);
    let zero = SSAVar::constant(0, 8);
    let condition = SSAVar::new("tmp:condition", 1, 1);
    function.get_block_mut(0x1900).expect("branch block").ops = vec![
        SSAOp::IntSub {
            dst: updated.clone(),
            a: before.clone(),
            b: one.clone(),
        },
        SSAOp::IntNotEqual {
            dst: condition.clone(),
            a: updated.clone(),
            b: zero.clone(),
        },
        SSAOp::CBranch {
            target: SSAVar::new("ram:1910", 0, 8),
            cond: condition,
        },
    ];

    let prepared = SsaArtifact::new(function);
    let predicate = prepared
        .predicates()
        .predicates
        .values()
        .find(|predicate| predicate.block_addr == 0x1900)
        .expect("branch predicate");
    let normalized = predicate
        .comparison
        .as_ref()
        .expect("normalized comparison");
    assert_eq!(normalized.kind, crate::CompareKind::NotEqual);
    assert_eq!(
        normalized.lhs,
        prepared.graph().value_id_for_var(&before).unwrap()
    );
    assert_eq!(
        normalized.rhs,
        prepared.graph().value_id_for_var(&one).unwrap()
    );
    let evaluated = predicate
        .evaluated_comparison
        .as_ref()
        .expect("machine-point comparison");
    assert_eq!(evaluated.kind, crate::CompareKind::NotEqual);
    assert_eq!(
        evaluated.lhs,
        prepared.graph().value_id_for_var(&updated).unwrap()
    );
    assert_eq!(
        evaluated.rhs,
        prepared.graph().value_id_for_var(&zero).unwrap()
    );
}

#[test]
fn prepared_predicates_recover_signed_greater_equal_from_x86_flags() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1920,
            size: 0x4,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1930, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1924,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1930,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let mut function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let lhs = SSAVar::new("EAX", 0, 4);
    let rhs = SSAVar::new("ECX", 0, 4);
    let difference = SSAVar::new("tmp:difference", 1, 4);
    let overflow = SSAVar::new("OF", 1, 1);
    let sign = SSAVar::new("SF", 1, 1);
    let condition = SSAVar::new("tmp:condition", 1, 1);
    function.get_block_mut(0x1920).expect("branch block").ops = vec![
        SSAOp::IntSBorrow {
            dst: overflow.clone(),
            a: lhs.clone(),
            b: rhs.clone(),
        },
        SSAOp::IntSub {
            dst: difference.clone(),
            a: lhs.clone(),
            b: rhs.clone(),
        },
        SSAOp::IntSLess {
            dst: sign.clone(),
            a: difference,
            b: SSAVar::constant(0, 4),
        },
        SSAOp::IntEqual {
            dst: condition.clone(),
            a: overflow,
            b: sign,
        },
        SSAOp::CBranch {
            target: SSAVar::new("ram:1930", 0, 8),
            cond: condition,
        },
    ];

    let prepared = SsaArtifact::new(function);
    let comparison = prepared
        .predicates()
        .predicates
        .values()
        .find(|predicate| predicate.block_addr == 0x1920)
        .and_then(|predicate| predicate.comparison.as_ref())
        .expect("signed flag comparison");

    assert_eq!(comparison.kind, crate::CompareKind::SignedLessEqual);
    assert_eq!(
        comparison.lhs,
        prepared.graph().value_id_for_var(&rhs).unwrap(),
        "OF == SF means rhs <= lhs"
    );
    assert_eq!(
        comparison.rhs,
        prepared.graph().value_id_for_var(&lhs).unwrap()
    );
}

#[test]
fn loop_carrier_certifies_dominating_initializer_for_zero_iteration_exit() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1a00,
            size: 0x10,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1a30, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1a10,
            size: 0x10,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1a20, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1a20,
            size: 0x10,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1a20, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1a30,
            size: 0x10,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1a50, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1a40,
            size: 0x10,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1a50, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1a50,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let mut function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let init = SSAVar::new("RAX", 0, 8);
    let phi = SSAVar::new("RAX", 2, 8);
    let update_source = SSAVar::new("tmp:update", 1, 8);
    let update = SSAVar::new("RAX", 3, 8);
    let result = SSAVar::new("RAX", 4, 8);
    let chained_result = SSAVar::new("RAX", 5, 8);
    function.get_block_mut(0x1a20).expect("loop header").phis = vec![PhiNode {
        dst: phi.clone(),
        sources: vec![(0x1a10, init.clone()), (0x1a20, update.clone())],
        canonical_storage: None,
    }];
    function.get_block_mut(0x1a20).expect("loop header").ops = vec![
        SSAOp::IntAdd {
            dst: update_source.clone(),
            a: phi.clone(),
            b: SSAVar::constant(1, 8),
        },
        SSAOp::Copy {
            dst: update.clone(),
            src: update_source.clone(),
        },
        SSAOp::CBranch {
            target: SSAVar::new("ram:1a20", 0, 8),
            cond: SSAVar::constant(1, 1),
        },
    ];
    function.get_block_mut(0x1a30).expect("loop exit").phis = vec![PhiNode {
        dst: result.clone(),
        sources: vec![(0x1a00, init.clone()), (0x1a20, update.clone())],
        canonical_storage: None,
    }];
    function.get_block_mut(0x1a30).expect("loop exit").ops = vec![SSAOp::CBranch {
        target: SSAVar::new("ram:1a50", 0, 8),
        cond: SSAVar::constant(1, 1),
    }];
    function.get_block_mut(0x1a40).expect("exit bypass").ops = vec![SSAOp::Branch {
        target: SSAVar::new("ram:1a50", 0, 8),
        instruction: None,
    }];
    function.get_block_mut(0x1a50).expect("final exit").phis = vec![PhiNode {
        dst: chained_result.clone(),
        sources: vec![(0x1a30, result.clone()), (0x1a40, init.clone())],
        canonical_storage: None,
    }];
    function.get_block_mut(0x1a50).expect("final exit").ops = vec![SSAOp::Return {
        target: chained_result.clone(),
    }];

    let prepared = SsaArtifact::new(function);
    let phi_value = prepared.graph().value_id_for_var(&phi).unwrap();
    let init_value = prepared.graph().value_id_for_var(&init).unwrap();
    // The copy into RAX feeds the merge, so it is the merge's edge write
    // and stays; the merge reads it rather than the sum.
    let update_value = prepared.graph().value_id_for_var(&update).unwrap();
    let _ = &update_source;
    let result_value = prepared.graph().value_id_for_var(&result).unwrap();
    let chained_result_value = prepared.graph().value_id_for_var(&chained_result).unwrap();
    let phi_inst = prepared.graph().def_inst(phi_value).unwrap();
    let result_inst = prepared.graph().def_inst(result_value).unwrap();
    let loop_fact = prepared
        .structured()
        .loops
        .values()
        .find(|loop_fact| {
            loop_fact
                .carriers
                .iter()
                .any(|carrier| carrier.phi == phi_value)
        })
        .expect("structured loop fact");
    let carrier = loop_fact
        .carriers
        .iter()
        .find(|carrier| carrier.phi == phi_value)
        .expect("loop carrier");
    assert!(carrier.validate(prepared.graph()));
    assert!(carrier.identity_values.contains(&result_value));
    assert!(carrier.identity_values.contains(&chained_result_value));
    assert!(loop_fact.validate_carrier_members(
        prepared.graph(),
        prepared.storage_spans(),
        Some(prepared.machine_context()),
    ));
    for result in [result_value, chained_result_value] {
        assert!(carrier.members.iter().any(|member| {
            member.value == result
                && member
                    .roles
                    .contains(&crate::LoopCarrierMemberRole::PostLoopMerge)
        }));
    }
    assert_eq!(
        carrier.entries,
        vec![crate::LoopCarrierEdgeValue {
            predecessor: 0x1a10,
            value: init_value,
            site: crate::UseSite {
                inst: phi_inst,
                input_idx: 0,
            },
        }]
    );
    assert_eq!(carrier.updates.len(), 1);
    assert_eq!(carrier.updates[0].predecessor, 0x1a20);
    assert_eq!(carrier.updates[0].value, update_value);
    assert_eq!(
        carrier.updates[0].site,
        crate::UseSite {
            inst: phi_inst,
            input_idx: 1,
        }
    );
    assert_eq!(
        carrier.dominating_initializers,
        vec![crate::LoopCarrierEdgeValue {
            predecessor: 0x1a00,
            value: init_value,
            site: crate::UseSite {
                inst: result_inst,
                input_idx: 0,
            },
        }]
    );

    let mut forged = carrier.clone();
    forged.entries[0].site.input_idx = 1;
    assert!(
        !forged.validate(prepared.graph()),
        "a carrier must reject a site that names a different phi input"
    );
    let mut forged_loop = loop_fact.clone();
    forged_loop.carriers[0].members[0]
        .roles
        .insert(crate::LoopCarrierMemberRole::ProjectedPeer);
    assert!(
        !forged_loop.validate_carrier_members(
            prepared.graph(),
            prepared.storage_spans(),
            Some(prepared.machine_context()),
        ),
        "stored membership must not validate against its own tampered rows"
    );
}

#[test]
fn projected_loop_peers_form_one_order_and_name_independent_component() {
    let forward = projected_peer_loop_artifact(&[0, 1, 2], "named", true);
    let shuffled = projected_peer_loop_artifact(&[2, 0, 1], "renamed", true);

    assert_eq!(
        projected_peer_role_signature(&forward),
        projected_peer_role_signature(&shuffled),
        "role membership is keyed by source storage and SSA evidence, not names or phi order"
    );
    for prepared in [&forward, &shuffled] {
        let loop_fact = prepared
            .structured()
            .loops
            .values()
            .next()
            .expect("projected peer loop");
        assert!(loop_fact.validate_carrier_members(
            prepared.graph(),
            prepared.storage_spans(),
            Some(prepared.machine_context()),
        ));
        assert_eq!(loop_fact.carriers.len(), 3);
        let component = projected_peer_certificate_component(loop_fact);
        assert!(
            loop_fact
                .carriers
                .iter()
                .all(|carrier| component.contains(&carrier.phi))
        );
        let leader = loop_fact
            .carriers
            .iter()
            .max_by_key(|carrier| carrier.width)
            .expect("wide carrier");
        assert_eq!(
            leader
                .members
                .iter()
                .filter(|member| {
                    member
                        .roles
                        .contains(&crate::LoopCarrierMemberRole::ProjectedPeer)
                        && loop_fact
                            .carriers
                            .iter()
                            .any(|carrier| carrier.phi == member.value)
                })
                .count(),
            2,
        );
    }
}

#[test]
fn projected_loop_peers_require_one_coherent_storage_run() {
    let prepared = projected_peer_loop_artifact(&[0, 1, 2], "separate", false);
    let loop_fact = prepared
        .structured()
        .loops
        .values()
        .next()
        .expect("separate peer loop");
    assert!(loop_fact.validate_carrier_members(
        prepared.graph(),
        prepared.storage_spans(),
        Some(prepared.machine_context()),
    ));
    assert!(
        loop_fact
            .carriers
            .iter()
            .all(|carrier| carrier.members.iter().all(|member| !member
                .roles
                .contains(&crate::LoopCarrierMemberRole::ProjectedPeer)))
    );
}

#[test]
fn prepared_predicates_recover_signed_less_from_of_sf_flags() {
    let lhs = make_reg(0, 4);
    let rhs = make_reg(4, 4);
    let of = Varnode {
        space: SpaceId::Unique,
        offset: 0x2000,
        size: 1,
        meta: None,
    };
    let sf = Varnode {
        space: SpaceId::Unique,
        offset: 0x2001,
        size: 1,
        meta: None,
    };
    let sub = Varnode {
        space: SpaceId::Unique,
        offset: 0x2002,
        size: 4,
        meta: None,
    };
    let cond = Varnode {
        space: SpaceId::Unique,
        offset: 0x2003,
        size: 1,
        meta: None,
    };
    let blocks = vec![
        R2ILBlock {
            addr: 0x1600,
            size: 4,
            ops: vec![
                R2ILOp::IntSBorrow {
                    dst: of.clone(),
                    a: lhs.clone(),
                    b: rhs.clone(),
                },
                R2ILOp::IntSub {
                    dst: sub.clone(),
                    a: lhs,
                    b: rhs,
                },
                R2ILOp::IntSLess {
                    dst: sf.clone(),
                    a: sub,
                    b: make_const(0, 4),
                },
                R2ILOp::IntNotEqual {
                    dst: cond.clone(),
                    a: of,
                    b: sf,
                },
                R2ILOp::CBranch {
                    target: make_const(0x1608, 8),
                    cond,
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1604,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1608,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(1, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
    let predicate = prepared
        .predicates()
        .predicates
        .values()
        .next()
        .expect("predicate fact");
    let compare = predicate
        .comparison
        .as_ref()
        .expect("signed compare provenance");
    assert_eq!(compare.kind, crate::semantic::CompareKind::SignedLess);
    assert_ne!(compare.lhs, compare.rhs);
}

#[test]
fn cfg_risk_summary_reports_loops_and_switch_density() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1010, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![R2ILOp::Branch {
                target: make_const(0x1020, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1010,
            size: 4,
            ops: vec![R2ILOp::Branch {
                target: make_const(0x1000, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1020,
            size: 4,
            ops: vec![],
            switch_info: Some(R2ILSwitchInfo {
                switch_addr: 0x1020,
                default_target: Some(0x1040),
                cases: vec![
                    SwitchCase {
                        value: 0,
                        target: 0x1030,
                    },
                    SwitchCase {
                        value: 1,
                        target: 0x1040,
                    },
                ],
            }),
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1030,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1040,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("ssa function");
    let summary = func.cfg_risk_summary();

    assert_eq!(summary.block_count, 6);
    assert_eq!(
        summary.loop_count, 1,
        "expected one natural loop, got {summary:?}"
    );
    assert_eq!(
        summary.back_edge_count, 1,
        "expected one back edge from loop latch, got {summary:?}"
    );
    assert_eq!(summary.switch_block_count, 1);
    assert_eq!(summary.max_switch_cases, 3);

    assert_eq!(
        CFG::from_blocks(&blocks)
            .expect("cfg should build")
            .risk_summary(),
        summary,
        "a caller that has only the graph must read the same risk as a caller holding SSA"
    );
}

#[test]
fn producerless_switch_selector_is_retained_as_a_leaf() {
    let mut selector = R2ILBlock::new(0x1080, 4);
    selector.push(R2ILOp::BranchInd {
        target: make_reg(8, 8),
    });
    selector.set_switch_info(R2ILSwitchInfo {
        switch_addr: 0x1080,
        default_target: Some(0x10b0),
        cases: vec![
            SwitchCase {
                value: 1,
                target: 0x1090,
            },
            SwitchCase {
                value: 2,
                target: 0x10a0,
            },
        ],
    });
    let arms = [0x1090, 0x10a0, 0x10b0].map(|addr| {
        let mut block = R2ILBlock::new(addr, 4);
        block.push(R2ILOp::Return {
            target: make_reg(16, 8),
        });
        block
    });
    let artifact = SsaArtifact::raw(
        &[selector, arms[0].clone(), arms[1].clone(), arms[2].clone()],
        None,
    )
    .expect("switch artifact");
    let certificate = artifact
        .certificates()
        .switches
        .get(&0x1080)
        .expect("switch certificate");
    let selector = certificate.selector.expect("producerless selector leaf");
    let value = artifact
        .graph()
        .value(selector)
        .expect("selector graph value");
    assert_eq!(value.var.size, 8);
    let branch = artifact
        .graph()
        .insts
        .iter()
        .find(|instruction| {
            matches!(
                instruction.payload,
                crate::graph::InstPayload::Op(SSAOp::BranchInd { .. })
            )
        })
        .expect("branch instruction");
    assert_eq!(branch.inputs, vec![selector]);
}

#[test]
fn public_ssa_path_handles_a_deep_cycle_and_reports_its_back_edge() {
    const BLOCK_COUNT: usize = 8_192;
    const BASE: u64 = 0x10_0000;

    let blocks = (0..BLOCK_COUNT)
        .map(|index| R2ILBlock {
            addr: BASE + index as u64 * 4,
            size: 4,
            ops: if index + 1 == BLOCK_COUNT {
                vec![R2ILOp::Branch {
                    target: make_const(BASE, 8),
                }]
            } else {
                vec![R2ILOp::Nop]
            },
            switch_info: None,
            op_metadata: Default::default(),
        })
        .collect::<Vec<_>>();
    // The latch branches back to the first block, so control enters by the
    // entry edge in front of it.
    let expected_order = std::iter::once(crate::cfg::ENTRY_EDGE)
        .chain(blocks.iter().map(|block| block.addr))
        .collect::<Vec<_>>();
    let latch = BASE + (BLOCK_COUNT as u64 - 1) * 4;

    let function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("SSA for deep cyclic CFG");
    let risk = function.cfg_risk_summary();

    assert_eq!(function.entry, BASE);
    assert_eq!(function.root(), crate::cfg::ENTRY_EDGE);
    assert_eq!(function.block_addrs(), expected_order);
    assert_eq!(risk.block_count, BLOCK_COUNT);
    assert_eq!(risk.loop_count, 1);
    assert_eq!(risk.back_edge_count, 1);
    assert_eq!(
        function.cfg().collect_back_edges().get(&BASE),
        Some(&vec![latch])
    );
}

#[test]
fn noncarrier_use_follows_copy_and_phi_chains() {
    let blocks = [R2ILBlock::new(0x1000, 4), R2ILBlock::new(0x1004, 4)];
    let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function");
    let source = SSAVar::new("flag", 1, 1);
    let copied = SSAVar::new("flag", 2, 1);
    let merged = SSAVar::new("flag", 3, 1);
    let forwarded = SSAVar::new("flag", 4, 1);
    func.get_block_mut(0x1000).expect("copy block").ops = vec![SSAOp::Copy {
        dst: copied.clone(),
        src: source.clone(),
    }];
    let merge = func.get_block_mut(0x1004).expect("merge block");
    merge.phis = vec![PhiNode {
        dst: merged.clone(),
        sources: vec![(0x1000, copied)],
        canonical_storage: None,
    }];
    merge.ops = vec![SSAOp::Copy {
        dst: forwarded.clone(),
        src: merged,
    }];

    assert!(!func.has_noncarrier_use(&source));

    func.get_block_mut(0x1004)
        .expect("consumer block")
        .ops
        .push(SSAOp::Return { target: forwarded });

    assert!(func.has_noncarrier_use(&source));
}

#[test]
fn test_from_blocks_default_runs_optimization() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1008, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1008,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let func = SSAFunction::from_blocks(&blocks).expect("optimized SSA should build");
    assert!(
        func.num_blocks() < blocks.len(),
        "optimized constructor should prune dead branch blocks via SCCP"
    );
}

#[test]
fn test_refresh_after_cfg_mutation_recomputes_order_and_domtree() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1008, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![R2ILOp::Branch {
                target: make_const(0x100c, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1008,
            size: 4,
            ops: vec![R2ILOp::Branch {
                target: make_const(0x100c, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x100c,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_ram(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    func.remove_block(0x1004);
    func.refresh_after_cfg_mutation();

    assert!(!func.block_addrs().contains(&0x1004));
    assert!(func.get_block(0x1004).is_none());
    assert_eq!(func.idom(0x1008), Some(0x1000));
}

#[test]
fn test_for_each_source_reports_phi_and_op_sites() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1008, 8),
                cond: make_const(1, 1),
            }],
            op_metadata: std::collections::BTreeMap::new(),
            switch_info: None,
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                },
            ],
            op_metadata: std::collections::BTreeMap::new(),
            switch_info: None,
        },
        R2ILBlock {
            addr: 0x1008,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                },
            ],
            op_metadata: std::collections::BTreeMap::new(),
            switch_info: None,
        },
        R2ILBlock {
            addr: 0x100c,
            size: 4,
            ops: vec![R2ILOp::IntAdd {
                dst: make_reg(8, 8),
                a: make_reg(0, 8),
                b: make_const(3, 8),
            }],
            op_metadata: std::collections::BTreeMap::new(),
            switch_info: None,
        },
    ];

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    let merge = func.get_block(0x100c).expect("merge block");
    assert!(merge.has_phis(), "fixture should produce a merge phi");

    let mut seen = Vec::new();
    merge.for_each_source(|src| {
        seen.push(match src.site {
            SourceSite::Phi {
                phi_idx,
                src_idx,
                pred_addr,
            } => format!(
                "phi:{}:{}:0x{:x}:{}",
                phi_idx,
                src_idx,
                pred_addr,
                src.var.display_name()
            ),
            SourceSite::Op { op_idx, src_idx } => {
                format!("op:{}:{}:{}", op_idx, src_idx, src.var.display_name())
            }
        });
    });

    assert_eq!(seen.len(), 4, "2 phi sources + 2 IntAdd sources expected");
    assert!(
        seen[0].starts_with("phi:0:0:"),
        "first source should be first phi input"
    );
    assert!(
        seen[1].starts_with("phi:0:1:"),
        "second source should be second phi input"
    );
    assert!(
        seen[2].starts_with("op:0:0:"),
        "third source should be first op input"
    );
    assert!(
        seen[3].starts_with("op:0:1:"),
        "fourth source should be second op input"
    );
}

#[test]
fn test_for_each_def_reports_phi_and_op_defs() {
    let block = SSABlock {
        addr: 0x2000,
        size: 4,
        phis: vec![PhiNode {
            dst: SSAVar::new("reg:0", 2, 8),
            sources: vec![(0x1000, SSAVar::new("reg:0", 0, 8))],
            canonical_storage: None,
        }],
        ops: vec![
            SSAOp::Copy {
                dst: SSAVar::new("reg:8", 1, 8),
                src: SSAVar::new("reg:0", 2, 8),
            },
            SSAOp::Return {
                target: SSAVar::new("reg:8", 1, 8),
            },
        ],
    };

    let mut seen = Vec::new();
    block.for_each_def(|def| {
        seen.push(match def.site {
            DefSite::Phi { phi_idx } => format!("phi:{}:{}", phi_idx, def.var.display_name()),
            DefSite::Op { op_idx } => format!("op:{}:{}", op_idx, def.var.display_name()),
        });
    });

    assert_eq!(
        seen,
        vec!["phi:0:reg:0_2".to_string(), "op:0:reg:8_1".to_string()]
    );
}

#[test]
fn vector_alias_loop_edges_keep_exact_lane_producers_across_names_and_relocation() {
    assert_vector_loop_alias_provenance(0x1000, "first_names");
    assert_vector_loop_alias_provenance(0x7fff_4000, "renamed_registers");
}

#[test]
fn test_decompile_prep_facts_collapse_copy_chain_and_trivial_phi_roots() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1008, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(0x42, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1008,
            size: 4,
            ops: vec![R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(0x42, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x100c,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let arch = make_x86_64_prep_arch();
    let func = SSAFunction::from_blocks_for_decompile(&blocks, Some(&arch))
        .expect("prepared SSA should build");
    let facts = func.decompile_prep_facts().expect("prep facts");
    let merge = func.get_block(0x100c).expect("merge block");
    assert_eq!(merge.phis.len(), 1, "expected trivial merge phi");

    let const_root = SSAVar::constant(0x42, 8);
    let phi_dst = &merge.phis[0].dst;
    assert_eq!(
        facts.canonical_root_of(phi_dst),
        Some(&const_root),
        "merge phi should collapse to the shared constant root"
    );

    let left_dst = func
        .get_block(0x1004)
        .expect("left block")
        .ops
        .first()
        .and_then(|op| op.dst())
        .expect("left copy dst");
    let right_dst = func
        .get_block(0x1008)
        .expect("right block")
        .ops
        .first()
        .and_then(|op| op.dst())
        .expect("right copy dst");

    assert_eq!(facts.canonical_root_of(left_dst), Some(&const_root));
    assert_eq!(facts.canonical_root_of(right_dst), Some(&const_root));
    assert_eq!(facts.canonical_root_of(&const_root), Some(&const_root));
}
