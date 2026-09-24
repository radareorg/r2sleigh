//! What the artifact proves about the frame.

use super::super::*;
use super::*;

#[test]
fn tail_slot_is_a_terminal_callsite_through_either_ssa_shape() {
    let slot = 0x401008;
    let target_storage = CanonicalStorageId {
        space: CanonicalStorageSpace::Ram,
        offset: slot,
        size: 8,
    };

    let mut direct_ram = R2ILBlock::new(0x1600, 4);
    direct_ram.push(R2ILOp::BranchInd {
        target: Varnode::ram(slot, 8),
    });
    direct_ram.stamp_instruction(0, 0x1600);

    let address = Varnode::unique(0x6500, 8);
    let loaded = Varnode::register(0x4080, 8);
    let pc = Varnode::register(0, 8);
    let mut through_register = R2ILBlock::new(0x2600, 16);
    through_register.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: Varnode::constant(0x401000, 8),
        b: Varnode::constant(8, 8),
    });
    through_register.push(R2ILOp::Load {
        dst: loaded.clone(),
        space: r2il::SpaceId::Ram,
        addr: address,
    });
    through_register.push(R2ILOp::Copy {
        dst: pc.clone(),
        src: loaded,
    });
    through_register.push(R2ILOp::BranchInd { target: pc });
    through_register.stamp_instruction(3, 0x260c);

    for (block, op_index, instruction) in [(direct_ram, 0, 0x1600), (through_register, 3, 0x260c)] {
        let identity = SourceCallSiteIdentity::new(instruction, target_storage);
        let interface = SourceCallSiteInterface::new(
            b"tail-slot".to_vec(),
            identity,
            true,
            "sysv64",
            [],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("tail slot interface");
        let context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            std::slice::from_ref(&block),
            None,
            None,
            SourceMachineRoles::default(),
            None,
            None,
            vec![interface],
            vec![identity],
        );
        let function = SSAFunction::from_blocks_for_decompile(std::slice::from_ref(&block), None)
            .expect("tail slot SSA");
        let artifact = SsaArtifact::new_with_context(function, context);
        let certificate = artifact
            .callsite_certificate_for_op(block.addr, op_index)
            .expect("tail slot callsite certificate");
        assert_eq!(
            certificate.transfer,
            crate::semantic::CallSiteTransfer::TailCall
        );
        assert_eq!(certificate.direct_target, Some(slot));
        assert_eq!(certificate.fallthrough, None);
    }
}

#[test]
fn stack_root_follows_a_displacement_materialised_into_a_temp() {
    // AArch64 Sleigh writes `add x29, sp, 0x60` as
    // `tmp:A = 0x60; x29 = sp + tmp:A`, so the displacement operand is a
    // temp and the constant is one copy away. Reading only the operand left
    // the frame pointer with no stack root, and with it every address
    // derived from the frame pointer, which is most of a non-leaf
    // function's locals.
    use super::{StackAddressBase, StackAddressRoot, stack_address_root_from_add};
    use std::collections::BTreeMap;

    let sp = SSAVar::new("sp", 1, 8);
    let displacement = SSAVar::new("tmp:11e80", 1, 8);
    let literal = SSAVar::constant(0x60, 8);

    let mut stack_roots = BTreeMap::new();
    stack_roots.insert(
        sp.clone(),
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x70,
        },
    );
    let mut roots = HashMap::new();
    assert_eq!(
        stack_address_root_from_add(
            &sp,
            canonical_root_in(&roots, &sp),
            &displacement,
            canonical_root_in(&roots, &displacement),
            &stack_roots,
        ),
        None,
        "with nothing linking the temp to the constant there is no delta to add"
    );

    roots.insert(displacement.clone(), literal);
    assert_eq!(
        stack_address_root_from_add(
            &sp,
            canonical_root_in(&roots, &sp),
            &displacement,
            canonical_root_in(&roots, &displacement),
            &stack_roots,
        ),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x10,
        }),
        "the frame pointer sits 0x60 above a 0x70 frame, so 0x10 below entry"
    );
}

#[test]
fn decompile_artifact_two_address_stack_updates_read_incoming_versions() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::new("rip", 32, 8));
    let rsp = make_reg(16, 8);
    let rbp = make_reg(24, 8);
    let rip = make_reg(32, 8);
    let saved_fp = make_unique(0x10, 8);
    let restored_fp = make_unique(0x18, 8);
    let return_target = make_unique(0x20, 8);
    let blocks = [R2ILBlock {
        addr: 0x1000,
        size: 9,
        ops: vec![
            R2ILOp::Copy {
                dst: saved_fp.clone(),
                src: rbp.clone(),
            },
            R2ILOp::IntSub {
                dst: rsp.clone(),
                a: rsp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: rsp.clone(),
                val: saved_fp,
            },
            R2ILOp::Load {
                dst: restored_fp.clone(),
                space: SpaceId::Ram,
                addr: rsp.clone(),
            },
            R2ILOp::IntAdd {
                dst: rsp.clone(),
                a: rsp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::Copy {
                dst: rbp,
                src: restored_fp,
            },
            R2ILOp::Load {
                dst: return_target.clone(),
                space: SpaceId::Ram,
                addr: rsp.clone(),
            },
            R2ILOp::IntAdd {
                dst: rsp.clone(),
                a: rsp,
                b: make_const(8, 8),
            },
            R2ILOp::Copy {
                dst: rip,
                src: return_target,
            },
            R2ILOp::Return {
                target: make_reg(32, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let interface = SourceFunctionInterface::new_exact(
        b"two-address-stack-updates".to_vec(),
        "sysv",
        [],
        crate::SourceFunctionReturn::Void,
        [],
    )
    .expect("exact source interface");
    let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
        .expect("decompile SSA artifact");
    let updates = artifact
        .function()
        .get_block(0x1000)
        .expect("entry block")
        .ops
        .iter()
        .filter_map(|op| match op {
            SSAOp::IntSub { dst, a, .. } | SSAOp::IntAdd { dst, a, .. } if dst.name() == "rsp" => {
                Some((dst.version, a.name(), a.version))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        updates,
        vec![(1, "rsp", 0), (2, "rsp", 1), (3, "rsp", 2)],
        "PUSH-, POP-, and RET-like SP updates must read the incoming SSA version"
    );
}

#[test]
fn prepared_function_ssa_refuses_display_named_stack_object_facts() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![
        R2ILBlock {
            addr: 0x1100,
            size: 4,
            ops: vec![
                R2ILOp::IntSub {
                    dst: Varnode {
                        space: SpaceId::Unique,
                        offset: 0x10,
                        size: 8,
                        meta: None,
                    },
                    a: make_reg(24, 8),
                    b: make_const(0x20, 8),
                },
                R2ILOp::Load {
                    dst: make_reg(0, 8),
                    space: SpaceId::Ram,
                    addr: Varnode {
                        space: SpaceId::Unique,
                        offset: 0x10,
                        size: 8,
                        meta: None,
                    },
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x4040, 8),
                    val: make_reg(0, 8),
                },
                R2ILOp::IntEqual {
                    dst: make_reg(8, 1),
                    a: make_reg(0, 8),
                    b: make_const(0, 8),
                },
                R2ILOp::CBranch {
                    target: make_const(0x1108, 8),
                    cond: make_reg(8, 1),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1104,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1108,
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

    assert!(prepared.objects().stack_objects.is_empty());
    assert!(
        prepared
            .objects()
            .global_objects
            .iter()
            .any(|(key, _)| key.address == 0x4040),
        "constant RAM address should seed a global object"
    );

    let entry = prepared.get_block(0x1100).expect("entry block");
    let load_ref = SliceOpRef::Op {
        block_addr: 0x1100,
        op_idx: 1,
    };
    let store_ref = SliceOpRef::Op {
        block_addr: 0x1100,
        op_idx: 2,
    };
    let load_inst = prepared
        .graph()
        .inst_id_for_op_site(load_ref.block_addr(), 1)
        .expect("load inst");
    let store_inst = prepared
        .graph()
        .inst_id_for_op_site(store_ref.block_addr(), 2)
        .expect("store inst");
    assert!(
        prepared.memory().uses_by_inst.contains_key(&load_inst),
        "load should read through MemorySSA facts"
    );
    assert!(
        prepared.memory().defs_by_inst.contains_key(&store_inst),
        "store should define a new memory version"
    );
    // The flag is a lane of `rbx`: its write inserts into the root and
    // the branch's read is a subpiece of it.
    assert_eq!(entry.ops.len(), 7);

    assert_eq!(prepared.predicates().predicates.len(), 1);
    let predicate = prepared
        .predicates()
        .predicates
        .values()
        .next()
        .expect("branch predicate");
    assert_eq!(predicate.block_addr, 0x1100);
    assert_eq!(predicate.true_target, 0x1108);
    assert_eq!(predicate.false_target, 0x1104);
    assert_eq!(
        predicate.comparison.as_ref().map(|cmp| cmp.kind),
        Some(crate::semantic::CompareKind::Equal)
    );
    assert!(
        prepared
            .predicates()
            .block_assumptions
            .contains_key(&0x1104)
    );
    assert!(
        prepared
            .predicates()
            .block_assumptions
            .contains_key(&0x1108)
    );
}

#[test]
fn prepared_function_refuses_display_named_stack_reload_at_control_return() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::new("rip", 0x30, 8));
    let slot = make_unique(0x1880, 8);
    let stored = make_unique(0x1888, 8);
    let blocks = vec![
        R2ILBlock {
            addr: 0x1880,
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
                    dst: make_reg(0, 8),
                    space: SpaceId::Ram,
                    addr: slot,
                },
                R2ILOp::Branch {
                    target: make_const(0x1890, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1890,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0x30, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared = prepared_preserving(&blocks, &arch, &["rbx", "rsp", "rbp"])
        .expect("prepared SSA should build");
    let return_op_idx = prepared
        .function()
        .get_block(0x1890)
        .and_then(|block| {
            block
                .ops
                .iter()
                .position(|op| matches!(op, SSAOp::Return { target } if target.name().eq_ignore_ascii_case("rip")))
        })
        .expect("control return op");
    assert!(
        prepared
            .return_certificate_for_op(0x1890, return_op_idx)
            .is_none()
    );
}

#[test]
fn prepared_function_refuses_display_named_stack_merge_at_control_return() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::new("rip", 0x30, 8));
    let slot = make_unique(0x1900, 8);
    let cmp_load = make_unique(0x1908, 8);
    let cond = make_unique(0x1910, 1);
    let blocks = vec![
        R2ILBlock {
            addr: 0x1900,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: slot.clone(),
                    a: make_reg(24, 8),
                    b: make_const(u64::MAX - 7, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: slot.clone(),
                    val: make_reg(8, 8),
                },
                R2ILOp::Load {
                    dst: cmp_load.clone(),
                    space: SpaceId::Ram,
                    addr: slot.clone(),
                },
                R2ILOp::IntEqual {
                    dst: cond.clone(),
                    a: cmp_load,
                    b: make_const(0, 8),
                },
                R2ILOp::CBranch {
                    target: make_const(0x1908, 8),
                    cond,
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1904,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(0, 8),
                    space: SpaceId::Ram,
                    addr: slot,
                },
                R2ILOp::Branch {
                    target: make_const(0x190c, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1908,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(0, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x190c, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x190c,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0x30, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
    let return_op_idx = prepared
        .function()
        .get_block(0x190c)
        .and_then(|block| {
            block
                .ops
                .iter()
                .position(|op| matches!(op, SSAOp::Return { target } if target.name().eq_ignore_ascii_case("rip")))
        })
        .expect("control return op");
    assert!(
        prepared
            .return_certificate_for_op(0x190c, return_op_idx)
            .is_none()
    );
}

/// Apple's arm64 ABI puts the variadic tail on the stack from its first
/// slot whatever registers are free, and a `bl` there moves no stack
/// pointer: the store before the call is the argument.
#[test]
fn an_apple_arm64_variadic_tail_is_read_from_the_stack() {
    let mut arch = ArchSpec::new("arm64");
    arch.addr_size = 8;
    for (index, name) in ["x0", "x1", "x2", "x3"].iter().enumerate() {
        arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
    }
    arch.add_register(RegisterDef::new("sp", 64, 8));
    arch.add_register(RegisterDef::new("x30", 72, 8));
    let slot = |index: usize| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: (index as u64) * 8,
        size: 8,
    };
    let register = |offset: u64| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let ops = vec![
        R2ILOp::IntSub {
            dst: make_reg(64, 8),
            a: make_reg(64, 8),
            b: make_const(0x20, 8),
        },
        R2ILOp::Copy {
            dst: make_reg(0, 8),
            src: make_const(0x3000, 8),
        },
        R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: make_reg(64, 8),
            val: make_const(0x11, 8),
        },
        R2ILOp::Call {
            target: make_const(0x2000, 8),
        },
        R2ILOp::IntAdd {
            dst: make_reg(64, 8),
            a: make_reg(64, 8),
            b: make_const(0x20, 8),
        },
        R2ILOp::Return {
            target: make_reg(72, 8),
        },
    ];
    let mut block = R2ILBlock {
        addr: 0x1600,
        size: 4,
        ops,
        switch_info: None,
        op_metadata: Default::default(),
    };
    block.stamp_instruction(3, 0x1603);
    let blocks = vec![block];
    let interface = SourceCallSiteInterface::new(
        b"apple-variadic-tail".to_vec(),
        SourceCallSiteIdentity::new(
            0x1603,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        ),
        true,
        "arm64",
        [SourceCallArgumentSpec::new(0, slot(0))],
        true,
        false,
        SourceCallResult::Void,
    )
    .expect("exact callsite interface")
    .with_radare2_format_parameter(0)
    .expect("format parameter belongs to the fixed prefix");
    let convention =
        SourceConventionSlots::new("arm64", (0..4).map(slot).collect::<Vec<_>>(), None)
            .expect("convention slots")
            .with_stack_arguments(r2source::SourceStackArgumentPlacement::new(0, 8))
            .with_variadic_tail_on_stack(true);
    let roles =
        SourceMachineRoles::new(Some(register(72)), Some(register(64))).expect("machine roles");
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        roles,
        Some(convention),
        preserving([register(64)]),
        vec![interface],
    );
    machine_context.bind_source_string_literals(&[(0x3000, "%d".to_string())]);
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        &blocks,
        Some(&arch),
        InterfaceQuestions::new(&machine_context),
        &machine_context,
        &CalleeBoundaries::default(),
        None,
        &UncheckedSsaWorkControl,
    )
    .expect("decompile SSA");
    let artifact = SsaArtifact::new_with_context(function, machine_context);
    let call = artifact
        .sole_callsite_certificate_in_block(0x1600)
        .expect("callsite certificate")
        .clone();
    assert_eq!(call.argument_values.len(), 2, "{call:?}");
    let passed = artifact
        .graph()
        .value(call.argument_values[1])
        .expect("the stack argument's value");
    assert_eq!(passed.var.constant_bits(), Some(0x11));
}

#[test]
fn prepared_stack_reload_refuses_display_named_param_home() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::new("rsi", 32, 8));
    arch.add_register(RegisterDef::new("esi", 32, 4));

    let slot = make_unique(0x1820, 8);
    let loaded = make_unique(0x1828, 4);
    let extended = make_unique(0x1830, 8);
    let blocks = vec![R2ILBlock {
        addr: 0x1820,
        size: 4,
        ops: vec![
            R2ILOp::IntAdd {
                dst: slot.clone(),
                a: make_reg(24, 8),
                b: make_const(0xffffffffffffffe0, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: slot.clone(),
                val: make_reg(32, 4),
            },
            R2ILOp::Load {
                dst: loaded.clone(),
                space: SpaceId::Ram,
                addr: slot,
            },
            R2ILOp::IntSExt {
                dst: extended,
                src: loaded,
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
    assert!(
        prepared
            .stack_reload_certificate_for_op(0x1820, 2)
            .is_none()
    );

    let extended_value = prepared
        .graph()
        .value_id_for_var(&SSAVar::new("tmp:1830", 1, 8))
        .expect("extended index value");
    assert!(
        prepared
            .stack_reload_certificate_for_value(extended_value)
            .is_none()
    );
}

#[test]
fn prepared_callsite_refuses_display_named_stack_home_arguments() {
    let arch = make_x86_64_prep_arch();
    let stack_home = Varnode {
        space: SpaceId::Unique,
        offset: 0x1740,
        size: 8,
        meta: None,
    };
    let blocks = vec![R2ILBlock {
        addr: 0x1740,
        size: 4,
        ops: vec![
            R2ILOp::IntAdd {
                dst: stack_home.clone(),
                a: make_reg(16, 8),
                b: make_const(0x20, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: stack_home,
                val: make_const(7, 8),
            },
            R2ILOp::Call {
                target: make_const(0x401000, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared = prepared_preserving(&blocks, &arch, &["rbx", "rsp", "rbp"])
        .expect("prepared SSA should build");
    let call = prepared
        .sole_callsite_certificate_in_block(0x1740)
        .expect("callsite certificate");

    assert!(call.stack_argument_values.is_empty());
    assert!(
        call.argument_certificates
            .iter()
            .all(|argument| !matches!(argument.location, CallArgumentLocation::Stack { .. }))
    );
}

/// The widest slot is the family's canonical identity, and every alias
/// reaches the same one whatever width it names.
#[test]
fn widest_slot_is_one_canonical_identity_per_register() {
    let families = RegisterFamilyInfo::from_register_storages([
        ("RDI", 0x38u64, 8u32),
        ("EDI", 0x38, 4),
        ("DI", 0x38, 2),
        ("DIL", 0x38, 1),
    ]);

    let widest = families.widest_slot_for_name("rdi").expect("rdi is named");
    assert_eq!(widest.width, 8);
    for alias in ["edi", "di", "dil", "RDI"] {
        assert_eq!(
            families.widest_slot_for_name(alias).expect(alias),
            widest,
            "{alias}"
        );
    }
    assert!(families.widest_slot_for_name("rsi").is_none());
}

#[test]
fn test_decompile_prep_facts_refuse_display_named_stack_roots() {
    let blocks = vec![R2ILBlock {
        addr: 0x2000,
        size: 4,
        ops: vec![R2ILOp::Return {
            target: make_const(0, 8),
        }],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    func.get_block_mut(0x2000).expect("entry block").ops = vec![
        SSAOp::IntAdd {
            dst: SSAVar::new("tmp:1", 1, 8),
            a: SSAVar::new("rsp", 0, 8),
            b: SSAVar::constant(0xfffffffffffffff0, 8),
        },
        SSAOp::Copy {
            dst: SSAVar::new("tmp:2", 1, 8),
            src: SSAVar::new("tmp:1", 1, 8),
        },
        SSAOp::IntSub {
            dst: SSAVar::new("tmp:3", 1, 8),
            a: SSAVar::new("rbp", 0, 8),
            b: SSAVar::constant(0x20, 8),
        },
        SSAOp::Copy {
            dst: SSAVar::new("tmp:4", 1, 8),
            src: SSAVar::new("tmp:3", 1, 8),
        },
        SSAOp::IntAdd {
            dst: SSAVar::new("tmp:5", 1, 8),
            a: SSAVar::new("rsp", 0, 8),
            b: SSAVar::constant(0xffff_fff0, 4),
        },
        SSAOp::IntAdd {
            dst: SSAVar::new("tmp:max", 1, 8),
            a: SSAVar::new("rsp", 0, 8),
            b: SSAVar::constant(i64::MAX as u64, 8),
        },
        SSAOp::IntAdd {
            dst: SSAVar::new("tmp:overflow", 1, 8),
            a: SSAVar::new("tmp:max", 1, 8),
            b: SSAVar::constant(1, 8),
        },
    ];
    func.refresh_decompile_prep_facts();

    let facts = func.decompile_prep_facts().expect("prep facts");
    assert!(
        facts.stack_address_roots.is_empty(),
        "display names cannot establish stack roots without typed carrier evidence"
    );
    assert_eq!(
        facts.canonical_root_of(&SSAVar::new("tmp:2", 1, 8)),
        Some(&SSAVar::new("tmp:1", 1, 8))
    );
    assert_eq!(
        facts.canonical_root_of(&SSAVar::new("tmp:4", 1, 8)),
        Some(&SSAVar::new("tmp:3", 1, 8))
    );
}

#[test]
fn test_decompile_prep_facts_use_only_exact_typed_stack_carriers() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::new("rip", 32, 8));
    let rsp = make_reg(16, 8);
    let rbp = make_reg(24, 8);
    let blocks = vec![R2ILBlock {
        addr: 0x3000,
        size: 5,
        ops: vec![
            R2ILOp::Copy {
                dst: rbp.clone(),
                src: rsp.clone(),
            },
            R2ILOp::IntSub {
                dst: rsp.clone(),
                a: rsp.clone(),
                b: make_const(0x20, 8),
            },
            R2ILOp::IntAdd {
                dst: make_unique(0x10, 8),
                a: rsp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::IntSub {
                dst: make_unique(0x18, 8),
                a: rbp,
                b: make_const(0x10, 8),
            },
            R2ILOp::Subpiece {
                dst: make_unique(0x20, 4),
                src: rsp.clone(),
                offset: 0,
            },
            R2ILOp::Cast {
                dst: make_unique(0x24, 4),
                src: rsp.clone(),
            },
            R2ILOp::IntAdd {
                dst: make_unique(0x28, 4),
                a: rsp.clone(),
                b: make_const(1, 8),
            },
            R2ILOp::IntSub {
                dst: make_unique(0x2c, 4),
                a: rsp,
                b: make_const(1, 8),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 16,
        size: 8,
    };
    let fp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 24,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 32,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"typed-stack-roots".to_vec(),
        "sysv",
        [],
        SourceFunctionReturn::Void,
        [
            SourceStackSlotSpec::new_local(StackAddressBase::FramePointer, fp_storage, -0x10, 8),
            SourceStackSlotSpec::new_local(StackAddressBase::StackPointer, sp_storage, -0x18, 8),
        ],
    )
    .expect("exact typed interface")
    .with_return_address_storage(ra_storage)
    .expect("return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("stack-pointer carrier");

    let typed = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
        .expect("typed decompile artifact");
    let typed_function = typed.function();
    let typed_facts = typed_function.decompile_prep_facts().expect("typed facts");
    let op_roots = typed_function
        .get_block(0x3000)
        .expect("entry")
        .ops
        .iter()
        .filter_map(|op| op.dst())
        .filter_map(|dst| {
            typed_facts
                .stack_address_root_of(dst)
                .copied()
                .map(|root| (typed_function.canonical_storage_for_var(dst), root))
        })
        .collect::<Vec<_>>();
    let entry_op_roots = typed_function
        .get_block(0x3000)
        .expect("entry")
        .ops
        .iter()
        .filter_map(|op| op.dst())
        .filter_map(|dst| {
            typed_facts
                .entry_stack_address_root_of(dst)
                .copied()
                .map(|root| (typed_function.canonical_storage_for_var(dst), root))
        })
        .collect::<Vec<_>>();
    // The frame pointer has a position now, not a base of its own. Here it
    // is the entry stack pointer itself, which is what a frame pointer
    // established before any allocation is.
    assert!(
        op_roots.contains(&(
            Some(fp_storage),
            StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: 0,
            },
        )),
        "op roots were {op_roots:?}"
    );
    assert!(op_roots.contains(&(
        Some(sp_storage),
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x20,
        },
    )));
    assert!(op_roots.iter().any(|(_, root)| {
        *root
            == StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x18,
            }
    }));
    assert!(entry_op_roots.contains(&(
        Some(fp_storage),
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: 0,
        },
    )));
    assert!(entry_op_roots.contains(&(
        Some(sp_storage),
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x20,
        },
    )));
    assert!(entry_op_roots.iter().any(|(_, root)| {
        *root
            == StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x18,
            }
    }));
    assert!(
        typed_function
            .get_block(0x3000)
            .expect("entry")
            .ops
            .iter()
            .filter_map(SSAOp::dst)
            .filter(|dst| dst.size == 4)
            .all(|dst| typed_facts.entry_stack_address_root_of(dst).is_none()),
        "narrow copy/cast/add/sub values cannot carry entry-SP authority"
    );
    assert!(entry_op_roots.iter().any(|(_, root)| {
        *root
            == StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x10,
            }
    }));
    // The same position, and now the same name for it. This used to assert
    // that the general map called the location frame-relative while the
    // entry map called it stack-relative -- one place under two
    // coordinates, which is what the two maps existed to keep apart.
    assert!(op_roots.iter().any(|(_, root)| {
        *root
            == StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: -0x10,
            }
    }));

    let source_free =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("source-free decompile artifact");
    assert!(
        source_free
            .function()
            .decompile_prep_facts()
            .expect("source-free facts")
            .stack_address_roots
            .is_empty(),
        "register names and architecture storage alone cannot grant stack roots"
    );
}

#[test]
fn artifact_projects_typed_stack_roots_by_value_id_without_register_aliases() {
    let mut arch = ArchSpec::new("opaque-stack-registers");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("machine_base_alpha", 16, 8));
    arch.add_register(RegisterDef::new("machine_base_beta", 24, 8));
    arch.add_register(RegisterDef::new("machine_return_gamma", 32, 8));

    let stack_pointer = make_reg(16, 8);
    let frame_pointer = make_reg(24, 8);
    let blocks = vec![R2ILBlock {
        addr: 0x3400,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: frame_pointer.clone(),
                src: stack_pointer,
            },
            R2ILOp::IntSub {
                dst: make_unique(0x48, 8),
                a: frame_pointer,
                b: make_const(0x18, 8),
            },
            R2ILOp::Return {
                target: make_ram(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 16,
        size: 8,
    };
    let fp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 24,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 32,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"opaque-stack-registers".to_vec(),
        "opaque",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::FramePointer,
            fp_storage,
            -0x18,
            8,
        )],
    )
    .expect("typed interface")
    .with_return_address_storage(ra_storage)
    .expect("return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("stack-pointer carrier")
    .with_frame_pointer_storage(fp_storage)
    .expect("frame-pointer carrier");

    let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
        .expect("typed decompile artifact");
    let frame_setup = artifact
        .graph()
        .inst_id_for_op_site(0x3400, 0)
        .and_then(|inst| artifact.graph().inst(inst))
        .expect("frame setup graph instruction");
    let entry_sp = frame_setup.inputs[0];
    let local_address = artifact
        .graph()
        .inst_id_for_op_site(0x3400, 1)
        .and_then(|inst| artifact.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("local-address graph value");

    assert_eq!(
        artifact.stack_address_root_for_value(entry_sp),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: 0,
        })
    );
    // Same place, named in the one coordinate objects use. The frame
    // pointer here is the entry stack pointer, so a local twenty-four
    // below it is twenty-four below entry.
    assert_eq!(
        artifact.stack_address_root_for_value(local_address),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x18,
        })
    );
    assert_eq!(
        artifact.entry_stack_address_root_for_value(local_address),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -0x18,
        })
    );
    assert!(
        [entry_sp, local_address].iter().all(|value| {
            let name = &artifact
                .graph()
                .value(*value)
                .expect("graph value")
                .var
                .name();
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "sp" | "rsp" | "fp" | "rbp"
            )
        }),
        "the typed ValueId projection must not depend on conventional raw aliases"
    );
}

#[test]
fn a_mask_that_aligns_the_stack_pointer_opens_a_frame_of_its_own() {
    let mut arch = ArchSpec::new("custom-realign");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("custom_sp", 0x10, 8));
    arch.add_register(RegisterDef::new("custom_ra", 0x20, 8));
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 0x10,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 0x20,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"custom-realign-roots".to_vec(),
        "custom-unknown",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .expect("exact custom interface")
    .with_return_address_storage(ra_storage)
    .expect("custom return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("custom stack-pointer carrier");
    let blocks = vec![R2ILBlock {
        addr: 0x3400,
        size: 4,
        ops: vec![
            R2ILOp::IntAnd {
                dst: make_reg(0x10, 8),
                a: make_reg(0x10, 8),
                b: make_const(0xffff_ffff_ffff_fff0, 8),
            },
            R2ILOp::IntSub {
                dst: make_reg(0x10, 8),
                a: make_reg(0x10, 8),
                b: make_const(8, 8),
            },
            R2ILOp::IntAdd {
                dst: make_unique(0x40, 8),
                a: make_reg(0x10, 8),
                b: make_const(0x10, 8),
            },
            R2ILOp::Return {
                target: make_reg(0x20, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
        .expect("realigned artifact must build");
    let facts = artifact
        .function()
        .decompile_prep_facts()
        .expect("custom prep facts");
    let realigned = facts
        .stack_address_roots
        .values()
        .filter(|root| root.base == StackAddressBase::Realigned)
        .map(|root| root.offset)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        realigned,
        BTreeSet::from([0, -8, 8]),
        "the masked pointer, the push below it and the address above it share one origin"
    );
    assert!(
        facts
            .entry_stack_address_roots
            .values()
            .all(|root| root.base != StackAddressBase::StackPointer || root.offset == 0),
        "nothing past the mask keeps an entry-relative position"
    );
}

#[test]
fn entry_stack_roots_use_call_preservation_but_refuse_unknown_effects() {
    let mut arch = ArchSpec::new("custom-stack-call");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("custom_sp", 0x10, 8));
    arch.add_register(RegisterDef::new("custom_ra", 0x20, 8));
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 0x10,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 0x20,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"custom-stack-call-roots".to_vec(),
        "custom-unknown",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            sp_storage,
            -8,
            8,
        )],
    )
    .expect("exact custom interface")
    .with_return_address_storage(ra_storage)
    .expect("custom return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("custom stack-pointer carrier");

    for (name, boundary) in [
        (
            "call",
            R2ILOp::Call {
                target: make_const(0x5000, 8),
            },
        ),
        (
            "user operation",
            R2ILOp::CallOther {
                output: None,
                userop: 7,
                inputs: Vec::new(),
            },
        ),
        (
            "user operation into the stack pointer",
            R2ILOp::CallOther {
                output: Some(make_reg(0x10, 8)),
                userop: 7,
                inputs: Vec::new(),
            },
        ),
        (
            "cpu identity effect",
            R2ILOp::CpuId {
                dst: make_unique(0x80, 8),
            },
        ),
        (
            "allocation effect",
            R2ILOp::New {
                dst: make_unique(0x88, 8),
                src: make_const(8, 8),
            },
        ),
    ] {
        let blocks = vec![R2ILBlock {
            addr: 0x3400,
            size: 4,
            ops: vec![
                R2ILOp::IntSub {
                    dst: make_reg(0x10, 8),
                    a: make_reg(0x10, 8),
                    b: make_const(0x10, 8),
                },
                boundary,
                R2ILOp::IntAdd {
                    dst: make_unique(0x40, 8),
                    a: make_reg(0x10, 8),
                    b: make_const(8, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0x20, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let artifact = crate::testing::prepared(
            &blocks,
            &arch,
            Some(interface.clone()),
            Vec::new(),
            [sp_storage],
        )
        .unwrap_or_else(|| panic!("{name} artifact must build"));
        let facts = artifact
            .function()
            .decompile_prep_facts()
            .expect("custom prep facts");
        assert!(
            !facts.stack_address_roots.is_empty(),
            "{name} must preserve source-declared stack roots"
        );
        // A call preserves SP by convention; a user operation writes only its named output.
        if name == "call" || name == "user operation" {
            assert!(
                !facts.entry_stack_address_roots.is_empty(),
                "{name} leaves SP as it was, so entry-relative roots stand"
            );
        } else {
            assert!(
                facts.entry_stack_address_roots.is_empty(),
                "{name} must invalidate entry-SP-relative roots"
            );
        }
    }
}

#[test]
fn new_subregister_result_cannot_inherit_stack_address_authority() {
    let mut arch = make_x86_64_prep_arch();
    arch.add_register(RegisterDef::sub("esp", 16, 4, "rsp"));
    arch.add_register(RegisterDef::new("rip", 32, 8));
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 16,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 32,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"new-subregister-stack-roots".to_vec(),
        "sysv",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            sp_storage,
            -8,
            8,
        )],
    )
    .expect("exact stack interface")
    .with_return_address_storage(ra_storage)
    .expect("return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("stack-pointer carrier");
    let blocks = [R2ILBlock {
        addr: 0x3480,
        size: 4,
        ops: vec![
            R2ILOp::New {
                dst: make_reg(16, 4),
                src: make_reg(16, 8),
            },
            R2ILOp::Cast {
                dst: make_unique(0x90, 8),
                src: make_reg(16, 4),
            },
            R2ILOp::Load {
                dst: make_unique(0x98, 4),
                space: SpaceId::Ram,
                addr: make_unique(0x90, 8),
            },
            R2ILOp::Return {
                target: make_reg(32, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let artifact = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
        .expect("subregister New artifact");
    let block = artifact.function().get_block(0x3480).expect("entry block");
    let new_dst = block
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::New { dst, .. } => Some(dst),
            _ => None,
        })
        .expect("New output");
    let load_addr = block
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Load { addr, .. } => Some(addr),
            _ => None,
        })
        .expect("load address");
    let facts = artifact
        .function()
        .decompile_prep_facts()
        .expect("decompile prep facts");

    assert!(facts.stack_address_root_of(new_dst).is_none());
    assert!(facts.stack_address_root_of(load_addr).is_none());
    assert!(facts.entry_stack_address_roots.is_empty());
    let object = artifact
        .object_for_var(load_addr, SpaceId::Ram)
        .expect("load address object");
    assert!(
        !artifact
            .objects()
            .stack_objects
            .values()
            .any(|candidate| *candidate == object)
    );
    assert!(!artifact.objects().entry_stack_roots.contains_key(&object));
}

#[test]
fn test_decompile_prep_facts_refuse_renamed_stack_carriers() {
    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![R2ILOp::Return {
            target: make_ram(0, 8),
        }],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
    func.get_block_mut(0x1000).expect("entry").ops = vec![
        SSAOp::IntSub {
            dst: SSAVar::new("runtime.materialized.rsp", 1, 8),
            a: SSAVar::new("runtime.materialized.rsp", 0, 8),
            b: SSAVar::constant(8, 8),
        },
        SSAOp::Copy {
            dst: SSAVar::new("runtime.materialized.rbp", 1, 8),
            src: SSAVar::new("runtime.materialized.rsp", 1, 8),
        },
        SSAOp::IntAdd {
            dst: SSAVar::new("tmp:fp_slot", 1, 8),
            a: SSAVar::new("runtime.materialized.rbp", 1, 8),
            b: SSAVar::constant(0xffffffffffffffe8, 8),
        },
    ];
    func.refresh_decompile_prep_facts();

    let facts = func.decompile_prep_facts().expect("prep facts");
    assert_eq!(
        facts.stack_address_root_of(&SSAVar::new("runtime.materialized.rsp", 1, 8)),
        None
    );
    assert_eq!(
        facts.stack_address_root_of(&SSAVar::new("runtime.materialized.rbp", 1, 8)),
        None
    );
    assert_eq!(
        facts.stack_address_root_of(&SSAVar::new("tmp:fp_slot", 1, 8)),
        None
    );
}

#[test]
fn a_code_pointer_entry_names_the_function_its_slot_holds() {
    // Each entry of a captured table is one slot, an entry apart, and the
    // name travels with the target so a rendering can spell it.
    let mut block = R2ILBlock::new(0x1000, 1);
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let mut artifact =
        SsaArtifact::for_decompile(&[block], None).expect("a returning block prepares");
    artifact.record_code_pointer_entries([
        (0x2000, 0x1200, Some("sym.op_add".to_string())),
        (0x2008, 0x1220, None),
    ]);
    assert_eq!(
        artifact.machine_context().code_pointer_entry(0x2000),
        Some(0x1200)
    );
    assert_eq!(
        artifact.machine_context().code_pointer_entry(0x2008),
        Some(0x1220)
    );
    assert_eq!(artifact.machine_context().code_pointer_entry(0x2010), None);
    assert_eq!(
        artifact
            .display_names()
            .functions()
            .get(&0x1200)
            .map(String::as_str),
        Some("sym.op_add")
    );
    assert!(!artifact.display_names().functions().contains_key(&0x1220));
}

#[test]
fn a_constant_spilled_into_a_slot_is_not_a_parameter_home() {
    // sp -= 32; [sp + 8] = 16; load [sp + 8]. The stored constant has the
    // argument carrier's offset and is still a constant, not the parameter.
    let sp = make_reg(0, 8);
    let argument = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 16,
        size: 8,
    };
    let sites = promotion_fixture_with_argument(
        vec![
            R2ILOp::IntSub {
                dst: sp.clone(),
                a: sp.clone(),
                b: make_const(32, 8),
            },
            R2ILOp::IntAdd {
                dst: make_unique(0x100, 8),
                a: sp.clone(),
                b: make_const(8, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: make_unique(0x100, 8),
                val: make_const(16, 8),
            },
            R2ILOp::IntAdd {
                dst: make_unique(0x108, 8),
                a: sp,
                b: make_const(8, 8),
            },
            R2ILOp::Load {
                dst: make_unique(0x110, 8),
                space: SpaceId::Ram,
                addr: make_unique(0x108, 8),
            },
            R2ILOp::Return {
                target: make_reg(8, 8),
            },
        ],
        argument,
    );
    assert_eq!(
        sites,
        BTreeSet::from([(0x4000, 2), (0x4000, 4)]),
        "the slot holding a constant promotes"
    );
}

#[test]
fn a_redefined_temporary_stops_holding_the_frame_address() {
    // t = sp; ...; t = r1; load [t]: the second load is not a frame access.
    let sp = make_reg(0, 8);
    let temp = make_unique(0x100, 8);
    let sites = promotion_fixture(vec![
        R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: make_const(16, 8),
        },
        R2ILOp::Copy {
            dst: temp.clone(),
            src: sp,
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: temp.clone(),
            val: make_reg(24, 8),
        },
        R2ILOp::Copy {
            dst: temp.clone(),
            src: make_reg(16, 8),
        },
        R2ILOp::Load {
            dst: make_unique(0x118, 8),
            space: SpaceId::Ram,
            addr: temp,
        },
        R2ILOp::Return {
            target: make_reg(8, 8),
        },
    ]);
    assert_eq!(sites, BTreeSet::from([(0x4000, 2)]));
}
