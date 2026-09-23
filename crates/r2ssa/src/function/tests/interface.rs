//! What the artifact proves about the function interface.

use super::super::*;
use super::*;

#[test]
fn tail_slot_identity_unifies_direct_ram_and_loaded_register_targets() {
    let slot = 0x1000_4010;
    let tail = advisory_call_site(0x2010, slot, r2source::AdvisoryCallTransfer::TailSlot);

    let mut direct_ram = R2ILBlock::new(0x2000, 0x14);
    direct_ram.push_with_metadata(
        R2ILOp::BranchInd {
            target: Varnode::ram(slot, 8),
        },
        Some(r2il::OpMetadata {
            instruction_addr: Some(0x2010),
            ..r2il::OpMetadata::default()
        }),
    );
    let direct_identity = unique_call_site_identity(&[direct_ram], &tail)
        .expect("the terminal branch reads the relocated RAM slot directly");

    let base = Varnode::constant(0x1000_4000, 8);
    let displacement = Varnode::constant(0x10, 8);
    let address = Varnode::unique(0x6500, 8);
    let loaded = Varnode::register(0x4080, 8);
    let pc = Varnode::register(0, 8);
    let mut through_register = R2ILBlock::new(0x2000, 0x14);
    through_register.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: base,
        b: displacement,
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
    through_register.push_with_metadata(
        R2ILOp::BranchInd { target: pc },
        Some(r2il::OpMetadata {
            instruction_addr: Some(0x2010),
            ..r2il::OpMetadata::default()
        }),
    );
    let loaded_identity = unique_call_site_identity(&[through_register], &tail)
        .expect("the terminal branch reads a value loaded from the relocated slot");

    assert_eq!(direct_identity.target(), loaded_identity.target());
    assert_eq!(direct_identity.target().space, CanonicalStorageSpace::Ram);
    assert_eq!(direct_identity.target().offset, slot);
    assert!(unique_call_site_identity(&[R2ILBlock::new(0x2000, 0x14)], &tail,).is_none());
}

#[test]
fn a_format_parameter_is_named_and_is_a_char_pointer() {
    use r2source::SourceSignatureParameter as Parameter;
    // radare2 spells the role `format` for the printf family and `fmt` for
    // err/warn, and both count conversion specifiers the same way.
    for name in ["format", "fmt", "__format", "format_string", "fmtstr"] {
        assert!(parameter_names_a_format_string(&Parameter::new(
            Some(name),
            Some("const char *")
        )));
    }
    // `execl(const char *path, const char *arg, ...)` is the reason the
    // name is required: nothing counts specifiers from its last parameter.
    assert!(!parameter_names_a_format_string(&Parameter::new(
        Some("arg"),
        Some("const char *")
    )));
    // And the type is the guard on the name: `ioctl`'s request is not one.
    assert!(!parameter_names_a_format_string(&Parameter::new(
        Some("fmt"),
        Some("unsigned long")
    )));
}

/// One call, two calls, three: the stack pointer is where it started.
///
/// Sleigh lifts an x86-64 `call` as `RSP = RSP - 8` and the store of the
/// return address. The callee's `ret` puts the eight back, and the callee
/// is not in this function, so before the convention said so nothing did:
/// a function with one call grew a phantom slot at entry - 16, with two at
/// entry - 24, with three at entry - 32. Offsets taken after a call then
/// named a slot that does not exist, or worse, one that does and holds
/// something else.
#[test]
fn a_call_leaves_the_stack_pointer_where_the_convention_says_it_found_it() {
    let arch = make_x86_64_prep_arch();
    let sp_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 16,
        size: 8,
    };
    let ra_storage = CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset: 24,
        size: 8,
    };
    let rsp = make_reg(16, 8);

    // Three calls, each lifted the way Sleigh lifts one: the return
    // address pushed, then the transfer. Every operation carries the
    // instruction it came from, because that is what says where one call
    // instruction's stack traffic ends.
    let mut ops = Vec::new();
    let mut op_metadata = std::collections::BTreeMap::new();
    for index in 0..3u64 {
        let instr_addr = 0x4000 + index * 5;
        let first = ops.len();
        ops.push(R2ILOp::IntSub {
            dst: rsp.clone(),
            a: rsp.clone(),
            b: make_const(8, 8),
        });
        ops.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: rsp.clone(),
            val: make_const(instr_addr + 5, 8),
        });
        ops.push(R2ILOp::Call {
            target: make_ram(0x401000, 8),
        });
        for op_index in first..ops.len() {
            op_metadata.insert(
                op_index,
                r2il::OpMetadata {
                    instruction_addr: Some(instr_addr),
                    ..Default::default()
                },
            );
        }
    }
    let last = ops.len();
    ops.push(R2ILOp::Return {
        target: make_const(0, 8),
    });
    op_metadata.insert(
        last,
        r2il::OpMetadata {
            instruction_addr: Some(0x400f),
            ..Default::default()
        },
    );

    let blocks = vec![R2ILBlock {
        addr: 0x4000,
        size: 16,
        ops,
        switch_info: None,
        op_metadata,
    }];

    let interface = SourceFunctionInterface::new_exact(
        b"call-chain-stack-pointer".to_vec(),
        "sysv",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .expect("exact interface")
    .with_return_address_storage(ra_storage)
    .expect("return-address carrier")
    .with_stack_pointer_storage(sp_storage)
    .expect("stack-pointer carrier");

    let prepared =
        crate::testing::prepared(&blocks, &arch, Some(interface), Vec::new(), [sp_storage])
            .expect("prepared SSA should build");
    let function = prepared.function();
    let facts = function.decompile_prep_facts().expect("prep facts");
    let block = function.get_block(0x4000).expect("entry block");

    // The projection is the layer a new operation is most easily missed
    // in: three separate tables key on the operation kind, and all three
    // are needed before an entity exists for the restore's output. Two of
    // them refuse loudly and one -- the type table -- refuses as an entity
    // that was never built, which reads as a mismatch a long way from its
    // cause. Asserting it here costs nothing and is what the corpus took a
    // locked run to say.
    crate::machine::MachineFunction::from_artifact(&prepared)
        .expect("a restore is an ordinary machine expression");

    // Every restore the boundary states, in order. Three calls, three of
    // them, and the last one is what the return sees.
    let restored = block
        .ops
        .iter()
        .filter_map(|op| match op {
            SSAOp::CallRestore { dst, .. } => Some(dst.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        restored.len(),
        3,
        "each call restores the carrier once: {:?}",
        block.ops
    );

    for (index, dst) in restored.iter().enumerate() {
        assert_eq!(
            facts.entry_stack_address_root_of(dst).copied(),
            Some(StackAddressRoot {
                base: StackAddressBase::StackPointer,
                offset: 0,
            }),
            "after call {index} the stack pointer is the entry stack pointer"
        );
    }

    // And nothing in the function ever offers a slot at the drifted
    // addresses the un-refunded pushes used to leave behind.
    let drifted = block
        .ops
        .iter()
        .filter_map(|op| op.dst())
        .filter_map(|dst| facts.entry_stack_address_root_of(dst).copied())
        .filter(|root| {
            root.base == StackAddressBase::StackPointer && matches!(root.offset, -16 | -24 | -32)
        })
        .collect::<Vec<_>>();
    assert!(
        drifted.is_empty(),
        "no value addresses a slot the drift invented: {drifted:?}"
    );
}

#[test]
fn prepared_function_ssa_recovers_direct_call_target_from_ram_literal() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1300,
            size: 4,
            ops: vec![R2ILOp::Call {
                target: make_ram(0x401239, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1304,
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
    assert_eq!(call.direct_target, Some(0x401239));
    assert_eq!(call.fallthrough, Some(0x1304));
}

#[test]
fn symbolic_function_ssa_recovers_indirect_call_target_from_copied_ram_literal() {
    let tmp = Varnode {
        space: SpaceId::Unique,
        offset: 0x10,
        size: 8,
        meta: None,
    };
    let blocks = vec![
        R2ILBlock {
            addr: 0x1310,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: tmp.clone(),
                    src: make_ram(0x1400a6010, 8),
                },
                R2ILOp::CallInd { target: tmp },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1314,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared =
        SsaArtifact::for_symbolic(&blocks, None).expect("symbolic prepared SSA should build");
    let call = prepared
        .call_sites()
        .by_id
        .values()
        .next()
        .expect("call site fact");
    assert_eq!(call.direct_target, Some(0x1400a6010));
    assert_eq!(call.fallthrough, Some(0x1314));
}

#[test]
fn resolved_call_target_uses_canonical_copied_const_root_when_fact_is_unresolved() {
    let tmp = Varnode {
        space: SpaceId::Unique,
        offset: 0x10,
        size: 8,
        meta: None,
    };
    let blocks = vec![R2ILBlock {
        addr: 0x1310,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: tmp.clone(),
                src: make_const(0x401050, 8),
            },
            R2ILOp::CallInd { target: tmp },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let prepared =
        SsaArtifact::for_symbolic(&blocks, None).expect("symbolic prepared SSA should build");
    let call = prepared
        .call_sites()
        .by_id
        .values()
        .next()
        .expect("call site fact");
    assert_eq!(call.direct_target, Some(0x401050));
    assert_eq!(prepared.resolved_call_target(call), Some(0x401050));

    let mut unresolved_fact = call.clone();
    unresolved_fact.direct_target = None;
    assert_eq!(
        prepared.resolved_call_target(&unresolved_fact),
        Some(0x401050),
        "resolved call target must use the prepared canonical copied const root"
    );
}

/// The shared call passes the carriers of the format that consumes most;
/// on the other path the surplus operand is what the machine passed too.
#[test]
fn merged_formats_that_disagree_pass_the_larger_count() {
    let call = merged_format_call("opened %d", "closed %d as %s");
    let evidence = call
        .variadic_argument_count_evidence
        .expect("merged literal count");
    assert!(evidence.merged_literals);
    assert_eq!(evidence.format_consumed_argument_count, 2);
    assert_eq!(evidence.total_argument_count, 4);
    assert!(call.variadic_argument_count_refusal.is_none());
}

/// A callee that is not variadic takes what its prototype says, however
/// many argument registers the caller happens to have written. Extending
/// past the prototype there would be a claim about the callee, not an
/// observation about the call.
#[test]
fn a_fixed_callee_takes_only_the_arguments_its_prototype_names() {
    let call = variadic_format_call(4, false, None, None);
    assert_eq!(call.argument_values.len(), 2);
    assert!(!call.variadic);
    assert_eq!(call.fixed_argument_count, Some(2));
}

#[test]
fn source_declared_entry_parameter_flows_into_an_implicit_call_read() {
    let mut arch = ArchSpec::new("aarch64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("x0", 0x4000, 8));
    arch.add_register(RegisterDef::new("x30", 0x4100, 8));
    arch.add_register(RegisterDef::new("sp", 0x4200, 8));
    let argument_storage = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x4000,
        size: 8,
    };
    let return_address_storage = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x4100,
        size: 8,
    };
    let stack_pointer_storage = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0x4200,
        size: 8,
    };
    let revision = b"preserved-entry-call-argument";
    let target = make_const(0x401000, 8);
    let mut blocks = [R2ILBlock {
        addr: 0x1600,
        size: 4,
        ops: vec![R2ILOp::Call {
            target: target.clone(),
        }],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    blocks[0].stamp_instruction(0, 0x1600);
    let function_interface = SourceFunctionInterface::new_exact(
        revision.to_vec(),
        "aapcs64",
        [SourceAbiParameterSpec::new(0, argument_storage)],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(return_address_storage))
    .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer_storage))
    .expect("exact function interface");
    let call_interface = SourceCallSiteInterface::new(
        revision.to_vec(),
        SourceCallSiteIdentity::new(0x1600, CanonicalStorageId::from_varnode(&target)),
        true,
        "aapcs64",
        [SourceCallArgumentSpec::new(0, argument_storage)],
        false,
        false,
        SourceCallResult::Register {
            storage: argument_storage,
        },
    )
    .expect("exact callsite interface");

    let prepared = crate::testing::prepared(
        &blocks,
        &arch,
        Some(function_interface),
        vec![call_interface],
        [stack_pointer_storage],
    )
    .expect("prepared SSA");
    let abi = prepared.machine_context().abi_model();
    assert!(abi.return_boundary_is_coherent());
    assert!(abi.argument_placement_is_coherent());
    assert!(abi.frame_geometry_is_coherent());
    assert!(abi.machine_carriers_are_coherent());
    let parameter = prepared
        .facts()
        .boundaries
        .parameters
        .get(&0)
        .expect("source formal parameter fact");
    assert_eq!(parameter.graph_storage, argument_storage);
    assert_eq!(prepared.graph().def_inst(parameter.value), None);
    assert_eq!(
        prepared
            .function()
            .decompile_prep_facts()
            .and_then(|facts| {
                prepared
                    .graph()
                    .value(parameter.value)
                    .and_then(|value| facts.formal_parameter_of(&value.var))
            }),
        Some(0),
    );

    let boundary = prepared
        .facts()
        .boundaries
        .calls
        .get(&CallSiteId(0))
        .expect("source call boundary");
    assert!(boundary.complete);
    assert_eq!(
        boundary.arguments.as_slice(),
        [SourceCallArgumentFact {
            slot: CallBoundarySlot::Register {
                index: 0,
                storage: argument_storage,
            },
            value: SourceCallArgumentValue::Value(parameter.value),
        }]
    );
    let certificate = prepared
        .sole_callsite_certificate_in_block(0x1600)
        .expect("prepared callsite certificate");
    assert_eq!(certificate.argument_values, [parameter.value]);
    assert_eq!(certificate.argument_certificates.len(), 1);
    assert_eq!(certificate.argument_certificates[0].value, parameter.value);
    assert_eq!(certificate.argument_certificates[0].source_inst, None);
    let obligation = prepared
        .obligations()
        .obligations_for_inst(certificate.at)
        .find(|obligation| obligation.id.kind == crate::SemanticObligationKind::CallArgument)
        .expect("call argument obligation");
    assert_eq!(obligation.inputs, [parameter.value]);
}

#[test]
fn prepared_certificates_index_call_args_memory_and_returns() {
    let mut arch = make_arm64_alias_arch();
    for register in &mut arch.registers {
        if register.offset == 0 {
            register.name = if register.size == 8 { "rdx" } else { "edx" }.to_string();
        }
    }
    let mut blocks = vec![R2ILBlock {
        addr: 0x1600,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(7, 8),
            },
            R2ILOp::Load {
                dst: make_reg(0x80, 8),
                space: SpaceId::Ram,
                addr: make_const(0x5000, 8),
            },
            R2ILOp::Call {
                target: make_const(0x2000, 8),
            },
            R2ILOp::Return {
                target: make_reg(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    blocks[0].stamp_instruction(2, 0x1602);

    let argument_storage = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let call_interface = SourceCallSiteInterface::new(
        b"renamed-register-call-args".to_vec(),
        SourceCallSiteIdentity::new(
            0x1602,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        ),
        true,
        "aapcs64",
        [SourceCallArgumentSpec::new(0, argument_storage)],
        false,
        false,
        SourceCallResult::Void,
    )
    .expect("exact callsite interface");
    let prepared = crate::testing::prepared(&blocks, &arch, None, vec![call_interface], [])
        .expect("prepared SSA");
    let call = prepared
        .sole_callsite_certificate_in_block(0x1600)
        .expect("callsite certificate");
    assert_eq!(call.block_addr, 0x1600);
    assert_eq!(call.argument_values.len(), 1);
    let arg_value = call.argument_values[0];
    let arg = prepared.graph().value(arg_value).expect("arg value");
    assert_eq!(arg.canonical_storage, Some(argument_storage));
    let arg_source = prepared
        .graph()
        .def_inst(arg_value)
        .expect("register argument producer");
    let producer = prepared
        .graph()
        .inst(arg_source)
        .expect("argument producer");
    assert!(matches!(
        producer.payload,
        crate::graph::InstPayload::Op(SSAOp::Copy { .. })
    ));
    let [input] = producer.inputs.as_slice() else {
        panic!("register argument copy must have one exact input");
    };
    assert!(
        prepared
            .graph()
            .value(*input)
            .is_some_and(|value| value.var.constant_bits() == Some(7))
    );
    assert_eq!(call.argument_certificates.len(), 1);
    let typed_arg = &call.argument_certificates[0];
    assert_eq!(typed_arg.index, 0);
    assert_eq!(typed_arg.value, arg_value);
    assert_eq!(typed_arg.source_inst, Some(arg_source));
    match &typed_arg.location {
        CallArgumentLocation::Register { storage } => {
            assert_eq!(*storage, argument_storage)
        }
        CallArgumentLocation::Stack { .. } | CallArgumentLocation::Variable { .. } => {
            panic!("register argument should not be certified as stack")
        }
    }

    let memory = prepared
        .memory_certificate_for_op_site(0x1600, 1, false)
        .expect("memory certificate");
    assert_eq!(memory.block_addr, 0x1600);
    assert_eq!(memory.op_index, 1);
    assert!(!memory.is_write);

    let return_idx = prepared
        .function()
        .get_block(0x1600)
        .and_then(|block| {
            block
                .ops
                .iter()
                .position(|op| matches!(op, SSAOp::Return { .. }))
        })
        .expect("return op index");
    assert!(
        prepared
            .return_certificate_for_op(0x1600, return_idx)
            .is_none()
    );

    let result = prepared
        .function()
        .get_block(0x1600)
        .and_then(|block| {
            block
                .ops
                .iter()
                .enumerate()
                .find_map(|(op_idx, op)| match op {
                    SSAOp::CallDefine { dst } => Some((op_idx, dst)),
                    _ => None,
                })
        })
        .expect("post-call result op");
    assert!(
        prepared
            .call_result_certificate_for_op(0x1600, result.0)
            .is_none()
    );
    assert!(
        prepared
            .call_result_certificates_for_callsite(call.call_site)
            .is_empty()
    );
}

#[test]
fn a_register_an_earlier_call_clobbered_is_not_an_argument_of_the_next_call() {
    let arch = call_preservation_arch();
    let slot = |offset| call_preservation_storage(offset, 8);
    // call A; rdi = 1; call B. B has no prototype, so its arguments are
    // what the machine set for it: rdi, and not the rsi and rdx that A's
    // clobbers left behind.
    let block = call_preservation_block(vec![
        R2ILOp::Call {
            target: make_ram(0x2000, 8),
        },
        R2ILOp::Copy {
            dst: make_reg(8, 8),
            src: make_const(1, 8),
        },
        R2ILOp::Call {
            target: make_ram(0x3000, 8),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let convention =
        SourceConventionSlots::new("amd64", vec![slot(8), slot(16), slot(24)], Some(slot(0)))
            .expect("convention slots");
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        std::slice::from_ref(&block),
        Some(&arch),
        None,
        SourceMachineRoles::default(),
        Some(convention),
        Vec::new(),
    );
    machine_context.bind_call_effect(call_preservation_effect(), std::slice::from_ref(&block));
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        std::slice::from_ref(&block),
        Some(&arch),
        InterfaceQuestions::none(),
        &machine_context,
        &CalleeBoundaries::default(),
        None,
        &UncheckedSsaWorkControl,
    )
    .expect("decompile SSA");
    let artifact = SsaArtifact::new_with_context(function, machine_context);
    let facts = artifact.facts();
    let boundary_of = |target: u64| {
        let call = facts
            .call_sites
            .by_id
            .values()
            .find(|call| call.direct_target == Some(target))
            .expect("call site");
        facts.boundaries.calls.get(&call.id).expect("call boundary")
    };
    assert!(boundary_of(0x2000).arguments.is_empty());
    let second = boundary_of(0x3000);
    assert!(second.complete, "{second:?}");
    assert_eq!(
        second
            .arguments
            .iter()
            .map(|argument| argument.slot)
            .collect::<Vec<_>>(),
        vec![crate::semantic::CallBoundarySlot::Register {
            index: 0,
            storage: slot(8),
        }],
        "{second:?}"
    );
}

#[test]
fn a_convention_with_no_argument_registers_reads_the_area_it_passes_on() {
    // sp -= 8; [sp] = rdi        -- the caller materialises an argument
    // sp -= 8; [sp] = ret; call  -- the call instruction spends its slot
    // Nothing declares the callee. The convention says every argument is
    // on the stack, and the store above the call's pointer is the one it
    // passes; the slot above that has none, which ends the count.
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
            target: make_ram(0x2000, 8),
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
        b"convention-stack-argument".to_vec(),
        "test-stack-abi",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(32, 8)))
    .expect("caller interface");
    let convention = SourceConventionSlots::new("test-stack-abi", [], Some(storage(0, 8)))
        .expect("stack-only convention")
        .with_stack_arguments(r2source::SourceStackArgumentPlacement::new(0, 8));
    let artifact = SsaArtifact::for_decompile_with(
        &[block],
        DecompileInputs {
            arch: Some(&arch),
            function_interface: Some(interface),
            machine_roles: SourceMachineRoles::new(Some(storage(16, 8)), Some(storage(32, 8)))
                .expect("machine roles"),
            convention_slots: Some(convention),
            call_effect: preserving([storage(32, 8)]),
            ..Default::default()
        },
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
}
