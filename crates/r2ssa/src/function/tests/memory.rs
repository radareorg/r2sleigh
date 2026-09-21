//! What the artifact proves about memory and objects.

use super::super::*;
use super::*;

#[test]
fn a_halfword_offset_table_indexed_by_a_loaded_byte_selects_the_byte() {
    // `ldrb w8, [x0, x22]; ldrh w10, [x28, x8, lsl 1]; add x9, x9, x10, lsl 2;
    // br x9`: the selector is the byte, not the pointer it was read through
    // and not the table entry.
    let p = Varnode::register(0x10, 8);
    let i = Varnode::register(0x18, 8);
    let byte_address = Varnode::unique(0x100, 8);
    let byte = Varnode::register(0x20, 1);
    let index = Varnode::register(0x28, 8);
    let scaled = Varnode::unique(0x200, 8);
    let table = Varnode::register(0x38, 8);
    let entry_address = Varnode::unique(0x300, 8);
    let entry = Varnode::register(0x40, 2);
    let wide = Varnode::register(0x48, 8);
    let offset = Varnode::unique(0x400, 8);
    let base = Varnode::register(0x50, 8);
    let target = Varnode::register(0x58, 8);
    let pc = Varnode::register(0, 8);
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::IntAdd {
        dst: byte_address.clone(),
        a: p,
        b: i,
    });
    block.push(R2ILOp::Load {
        dst: byte.clone(),
        space: r2il::SpaceId::Ram,
        addr: byte_address,
    });
    block.push(R2ILOp::IntZExt {
        dst: index.clone(),
        src: byte,
    });
    block.push(R2ILOp::IntLeft {
        dst: scaled.clone(),
        a: index,
        b: Varnode::constant(1, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: entry_address.clone(),
        a: table,
        b: scaled,
    });
    block.push(R2ILOp::Load {
        dst: entry.clone(),
        space: r2il::SpaceId::Ram,
        addr: entry_address,
    });
    block.push(R2ILOp::IntZExt {
        dst: wide.clone(),
        src: entry,
    });
    block.push(R2ILOp::IntLeft {
        dst: offset.clone(),
        a: wide,
        b: Varnode::constant(2, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: target.clone(),
        a: base,
        b: offset,
    });
    block.push(R2ILOp::Copy {
        dst: pc.clone(),
        src: target,
    });
    block.push(R2ILOp::BranchInd { target: pc });
    let function = SSAFunction::from_blocks_raw_no_arch(&[block]).expect("raw SSA should build");
    let selector = test_switch_selector(&function, 0x1000);
    assert!(
        selector.starts_with("reg:20"),
        "the selector is the loaded byte, got {selector}"
    );
}

#[test]
fn a_switch_on_a_field_selects_the_loaded_value_not_the_pointer() {
    // `switch (s->state)` is a load at `s + 4` feeding a jump table. The
    // address walk used to follow `s` as if it were the table's index, so
    // the selector came out as the pointer and the rendering wrote
    // `switch (s)` for a `DState *`.
    let pointer = Varnode::register(0x10, 8);
    let field_address = Varnode::unique(0x100, 8);
    let state = Varnode::register(0x20, 8);
    let scaled = Varnode::unique(0x200, 8);
    let entry_address = Varnode::unique(0x300, 8);
    let entry = Varnode::register(0x30, 8);
    let pc = Varnode::register(0, 8);
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::IntAdd {
        dst: field_address.clone(),
        a: pointer,
        b: Varnode::constant(4, 8),
    });
    block.push(R2ILOp::Load {
        dst: state.clone(),
        space: r2il::SpaceId::Ram,
        addr: field_address,
    });
    block.push(R2ILOp::IntMult {
        dst: scaled.clone(),
        a: state.clone(),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: entry_address.clone(),
        a: Varnode::constant(0x40_0000, 8),
        b: scaled,
    });
    block.push(R2ILOp::Load {
        dst: entry.clone(),
        space: r2il::SpaceId::Ram,
        addr: entry_address,
    });
    block.push(R2ILOp::Copy {
        dst: pc.clone(),
        src: entry,
    });
    block.push(R2ILOp::BranchInd { target: pc });
    let function = SSAFunction::from_blocks_raw_no_arch(&[block]).expect("raw SSA should build");
    let selector = test_switch_selector(&function, 0x1000);
    let read_state = function
        .get_block(0x1000)
        .expect("the fixture block")
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Load { dst, .. } if dst.size == state.size => Some(dst.name().to_string()),
            _ => None,
        })
        .expect("the field load");
    assert_eq!(
        selector, read_state,
        "the selector is the loaded state, not the pointer it was read through"
    );
}

#[test]
fn prepared_function_does_not_infer_memory_backed_return_phi() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![
        R2ILBlock {
            addr: 0x1200,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1210, 8),
                cond: make_reg(8, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1204,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(0, 4),
                    space: r2il::SpaceId::Ram,
                    addr: make_reg(8, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1214, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1210,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(0, 4),
                    space: r2il::SpaceId::Ram,
                    addr: make_reg(8, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1214, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1214,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0, 4),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
    assert!(prepared.certificates().returns.is_empty());
    assert!(prepared.return_certificate_for_op(0x1214, 0).is_none());
}

#[test]
fn prepared_function_ssa_collects_call_sites_and_memory_effects() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1200,
            size: 4,
            ops: vec![R2ILOp::Call {
                target: make_const(0x401000, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1204,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
    let call = prepared
        .call_sites()
        .by_id
        .values()
        .next()
        .expect("call site fact");
    assert_eq!(call.direct_target, Some(0x401000));
    assert_eq!(call.fallthrough, Some(0x1204));
    assert_eq!(
        call.memory_effect,
        crate::semantic::CallMemoryEffect::Unknown
    );

    let call_ref = call.at;
    let uses = prepared
        .memory()
        .uses_by_inst
        .get(&call_ref)
        .expect("call memory use fact");
    let defs = prepared
        .memory()
        .defs_by_inst
        .get(&call_ref)
        .expect("call memory def fact");
    assert_eq!(uses.len(), 1);
    assert_eq!(defs.len(), 1);
    assert_eq!(uses[0].location.object, defs[0].location.object);
    assert_eq!(
        prepared
            .objects()
            .object(uses[0].location.object)
            .map(|fact| &fact.kind),
        Some(&crate::semantic::ObjectKind::EscapedUnknown {
            space: r2il::SpaceId::Ram,
        })
    );
}

#[test]
fn prepared_function_ssa_builds_memory_phis_per_object() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1300,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1308, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1304,
            size: 4,
            ops: vec![
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                    val: make_const(1, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x130c, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1308,
            size: 4,
            ops: vec![R2ILOp::Store {
                space: SpaceId::Ram,
                addr: make_const(0x5000, 8),
                val: make_const(2, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x130c,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(0, 8),
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared = SsaArtifact::raw(&blocks, None).expect("prepared SSA should build");
    let phis = prepared
        .memory()
        .phis_by_block
        .get(&0x130c)
        .expect("merge-block memory phi");
    assert_eq!(phis.len(), 1);
    assert_eq!(phis[0].inputs.len(), 2);

    let load_ref = SliceOpRef::Op {
        block_addr: 0x130c,
        op_idx: 0,
    };
    let load_inst = prepared
        .graph()
        .inst_id_for_op_site(load_ref.block_addr(), 0)
        .expect("load inst");
    let load_use = prepared
        .memory()
        .uses_by_inst
        .get(&load_inst)
        .and_then(|facts| facts.first())
        .expect("load use");
    assert_eq!(load_use.version, phis[0].output_version);
}

#[test]
fn prepared_call_result_refuses_display_named_stack_store_reload_owner() {
    let arch = make_x86_64_prep_arch();
    let slot = make_unique(0x1780, 8);
    let stored = make_unique(0x1788, 8);
    let loaded = make_unique(0x1790, 8);
    let alias = make_unique(0x1798, 8);
    let truncated = make_unique(0x17a0, 4);
    let blocks = vec![R2ILBlock {
        addr: 0x1780,
        size: 4,
        ops: vec![
            R2ILOp::IntAdd {
                dst: slot.clone(),
                a: make_reg(24, 8),
                b: make_const(u64::MAX - 7, 8),
            },
            R2ILOp::Call {
                target: make_const(0x401000, 8),
            },
            R2ILOp::Copy {
                dst: stored.clone(),
                src: make_reg(0, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: slot.clone(),
                val: stored,
            },
            R2ILOp::Load {
                dst: loaded.clone(),
                space: SpaceId::Ram,
                addr: slot,
            },
            R2ILOp::Copy {
                dst: alias,
                src: loaded.clone(),
            },
            R2ILOp::Subpiece {
                dst: truncated,
                src: loaded,
                offset: 0,
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
    let alias_var = prepared
        .function()
        .get_block(0x1780)
        .and_then(|block| {
            block.ops.iter().find_map(|op| match op {
                SSAOp::Copy { dst, .. } if dst.name() == "tmp:1798" => Some(dst.clone()),
                _ => None,
            })
        })
        .expect("reloaded alias");
    let alias_value = prepared
        .graph()
        .value_id_for_var(&alias_var)
        .expect("alias value");
    assert!(
        prepared
            .call_result_certificate_for_value(alias_value)
            .is_none()
    );
    let truncated_var = prepared
        .function()
        .get_block(0x1780)
        .and_then(|block| {
            block.ops.iter().find_map(|op| match op {
                SSAOp::Subpiece { dst, .. } if dst.name() == "tmp:17a0" => Some(dst),
                _ => None,
            })
        })
        .expect("truncated call-result value");
    assert!(
        prepared
            .graph()
            .value_id_for_var(truncated_var)
            .and_then(|value| prepared.call_result_certificate_for_value(value))
            .is_none()
    );
}

#[test]
fn an_escaped_frame_address_keeps_the_places_above_it_in_memory() {
    // sp -= 32; r1 = sp + 16 (through a temporary, as add-immediate lifts);
    // [sp] = r2; load [sp + 20]. The address in r1 may reach 16 and above.
    let sp = make_reg(0, 8);
    let sites = promotion_fixture(vec![
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(32, 8),
        },
        R2ILOp::Copy {
            dst: make_unique(0x100, 8),
            src: make_const(16, 8),
        },
        R2ILOp::IntAdd {
            dst: make_unique(0x108, 8),
            a: sp.clone(),
            b: make_unique(0x100, 8),
        },
        R2ILOp::Copy {
            dst: make_reg(16, 8),
            src: make_unique(0x108, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp.clone(),
            val: make_reg(24, 8),
        },
        R2ILOp::IntAdd {
            dst: make_unique(0x110, 8),
            a: sp,
            b: make_const(20, 8),
        },
        R2ILOp::Load {
            dst: make_unique(0x118, 4),
            space: SpaceId::Ram,
            addr: make_unique(0x110, 8),
        },
        R2ILOp::Return {
            target: make_reg(8, 8),
        },
    ]);
    assert_eq!(
        sites,
        BTreeSet::from([(0x4000, 4)]),
        "only the slot below the escape"
    );
}

#[test]
fn a_calls_return_address_push_is_refunded_by_the_callee() {
    // sp -= 16; r2 = 7; [sp] = r2; sp -= 8; [sp] = return address; call; load [sp].
    let sp = make_reg(0, 8);
    let mut arch = ArchSpec::new("promotion-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("sp", 0, 8));
    arch.add_register(RegisterDef::new("ra", 8, 8));
    arch.add_register(RegisterDef::new("r1", 16, 8));
    arch.add_register(RegisterDef::new("r2", 24, 8));
    arch.add_space(r2il::AddressSpace::ram(8));
    let storage = |offset| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"promotion-test".to_vec(),
        "test-abi",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0)))
    .expect("interface")
    .with_preserved_call_carriers(true, false);
    let mut block = R2ILBlock::new(0x4000, 4);
    for op in [
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(16, 8),
        },
        R2ILOp::Copy {
            dst: make_reg(24, 8),
            src: make_const(7, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp.clone(),
            val: make_reg(24, 8),
        },
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(8, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp.clone(),
            val: make_const(0x4010, 8),
        },
        R2ILOp::Call {
            target: make_ram(0x5000, 8),
        },
        R2ILOp::Load {
            dst: make_reg(16, 8),
            space: SpaceId::Ram,
            addr: sp,
        },
        R2ILOp::Return {
            target: make_reg(8, 8),
        },
    ] {
        block.push(op);
    }
    let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("artifact");
    assert_eq!(
        artifact.function().promoted_slot_sites().clone(),
        BTreeSet::from([(0x4000, 2), (0x4000, 6)]),
        "the slot is written before the call and read after it"
    );
}

#[test]
fn a_declared_stack_argument_is_the_store_the_call_finds_above_its_stack_pointer() {
    // sp -= 8; [sp] = rdi        -- the caller materialises an argument
    // sp -= 8; [sp] = ret; call  -- the call instruction spends its slot
    // The prototype says argument 0 sits at +0 from the stack pointer as
    // the call finds it, which is the slot the first store filled.
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rip", 16, 8));
    arch.add_register(RegisterDef::new("rsp", 32, 8));
    let storage = |offset, size| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    };
    let sp = make_reg(32, 8);
    let target = make_ram(0x2000, 8);
    let ops = vec![
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(8, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp.clone(),
            val: make_reg(8, 8),
        },
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(8, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp,
            val: make_const(0x100d, 8),
        },
        R2ILOp::Call {
            target: target.clone(),
        },
        R2ILOp::Return {
            target: make_reg(16, 8),
        },
    ];
    let mut op_metadata = std::collections::BTreeMap::new();
    for (index, instruction_addr) in [0x1000u64, 0x1000, 0x1008, 0x1008, 0x1008, 0x100d]
        .into_iter()
        .enumerate()
    {
        op_metadata.insert(
            index,
            r2il::OpMetadata {
                instruction_addr: Some(instruction_addr),
                ..Default::default()
            },
        );
    }
    let block = R2ILBlock {
        addr: 0x1000,
        size: 16,
        ops,
        switch_info: None,
        op_metadata,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"stack-argument".to_vec(),
        "test-stack-abi",
        [SourceAbiParameterSpec::new(0, storage(8, 8))],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(32, 8)))
    .expect("caller interface");
    let roles = SourceMachineRoles::new(Some(storage(16, 8)), Some(storage(32, 8)))
        .expect("machine roles")
        .with_call_preserved_carriers(SourceCallPreservedCarriers::new(true, true));
    let identity = SourceCallSiteIdentity::new(0x1008, CanonicalStorageId::from_varnode(&target));
    let call_interface = SourceCallSiteInterface::new(
        b"stack-argument".to_vec(),
        identity,
        true,
        "test-stack-abi",
        [SourceCallArgumentSpec::on_stack(0, 0, 8)],
        false,
        false,
        SourceCallResult::Void,
    )
    .expect("callsite interface");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[block],
        Some(&arch),
        Some(interface),
        roles,
        vec![call_interface],
    )
    .expect("artifact");
    let facts = artifact.facts();
    let call = facts
        .call_sites
        .by_id
        .values()
        .find(|call| call.direct_target == Some(0x2000))
        .expect("call site");
    let boundary = facts.boundaries.calls.get(&call.id).expect("boundary");
    assert!(boundary.complete, "{boundary:?}");
    let [argument] = boundary.arguments.as_slice() else {
        panic!("one stack argument: {boundary:?}");
    };
    assert_eq!(
        argument.slot,
        crate::semantic::CallBoundarySlot::Stack(-8),
        "{boundary:?}"
    );
    let crate::semantic::SourceCallArgumentValue::Value(value) = argument.value else {
        panic!("{boundary:?}");
    };
    assert_eq!(
        artifact.graph().value(value).map(|value| value.var.name()),
        Some("rdi"),
        "the argument is what the first store put in the slot"
    );
    let certificate = artifact
        .sole_callsite_certificate_in_block(0x1000)
        .expect("callsite certificate");
    assert!(
        matches!(
            certificate.argument_certificates.as_slice(),
            [crate::semantic::CallArgumentCertificate {
                index: 0,
                location: crate::semantic::CallArgumentLocation::Variable { offset: -8 },
                ..
            }]
        ),
        "{:?}",
        certificate.argument_certificates
    );
}
