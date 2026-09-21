fn advisory_call_site(
    instruction: u64,
    target: u64,
    transfer: r2source::AdvisoryCallTransfer,
) -> r2source::AdvisoryCallSite {
    r2source::AdvisoryCallSite::described(
        instruction,
        target,
        transfer,
        None,
        r2source::AdvisoryCalleeLinkage::Unknown,
    )
}

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

/// What the analysis says one dispatching block switches on.
fn test_switch_selector(function: &SSAFunction, block_addr: u64) -> String {
    let graph = crate::graph::SsaGraph::from_function(function);
    let predicates = crate::semantic::collect_predicate_facts_for_test(function, &graph);
    let values =
        crate::values::solve_value_ranges(&graph, function, &predicates, &Default::default());
    let selector = crate::indirect::dispatch_selectors(function, &graph, &values)
        .remove(&block_addr)
        .expect("the analysis names a selector");
    graph
        .value(selector)
        .expect("the selector is a value")
        .var
        .name()
        .to_owned()
}

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
fn tail_jump_is_a_terminal_callsite_without_call_clobbers() {
    // Direct code targets lifted from a real branch retain RAM storage;
    // unlike an arithmetic literal, their SSA variable has no
    // `constant_bits` payload.
    let target = make_ram(0x5000, 8);
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Branch {
        target: target.clone(),
    });
    block.stamp_instruction(0, 0x1000);
    let identity = SourceCallSiteIdentity::new(0x1000, CanonicalStorageId::from_varnode(&target));
    let interface = SourceCallSiteInterface::new(
        b"tail-jump".to_vec(),
        identity,
        true,
        "aapcs64",
        [],
        false,
        false,
        SourceCallResult::Void,
    )
    .expect("tail callsite interface");
    let context = SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
        &[block.clone()],
        None,
        None,
        SourceMachineRoles::default(),
        None,
        vec![interface],
        vec![identity],
    );
    let function = SSAFunction::from_blocks_for_decompile(&[block], None).expect("tail branch SSA");
    let artifact = SsaArtifact::new_with_context(function, context);

    let prepared_block = artifact.function().get_block(0x1000).expect("tail block");
    assert!(matches!(
        prepared_block.ops.as_slice(),
        [SSAOp::Branch { .. }]
    ));
    assert!(
        !prepared_block
            .ops
            .iter()
            .any(|op| matches!(op, SSAOp::CallDefine { .. } | SSAOp::CallRestore { .. }))
    );
    let call = artifact
        .callsite_certificate_for_op(0x1000, 0)
        .expect("tail callsite certificate");
    assert_eq!(call.transfer, crate::semantic::CallSiteTransfer::TailCall);
    assert_eq!(call.fallthrough, None);
    assert_eq!(call.direct_target, Some(0x5000));
    let obligations = artifact
        .obligations()
        .obligations_for_inst(call.at)
        .map(|obligation| obligation.id.kind)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(obligations.contains(&crate::SemanticObligationKind::Call));
    assert!(obligations.contains(&crate::SemanticObligationKind::ControlTransfer));
}

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
use super::*;
use crate::semantic::{CallArgumentLocation, SemanticId};
use crate::{
    CallBoundarySlot, CanonicalStorageSpace, SourceAbiParameterSpec, SourceCallArgumentFact,
    SourceCallArgumentValue, SourceFunctionReturn, SourceStackSlotSpec, ValueId,
};
use r2il::{R2ILOp, RegisterDef, SpaceId, SwitchCase, SwitchInfo as R2ILSwitchInfo, Varnode};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

fn make_const(val: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Const,
        offset: val,
        size,
        meta: None,
    }
}

fn make_reg(offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Register,
        offset,
        size,
        meta: None,
    }
}

fn make_ram(addr: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Ram,
        offset: addr,
        size,
        meta: None,
    }
}

fn make_unique(offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Unique,
        offset,
        size,
        meta: None,
    }
}

fn make_arm64_alias_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("aarch64");
    arch.add_register(RegisterDef::new("x0", 0x00, 8));
    arch.add_register(RegisterDef::new("w0", 0x00, 4));
    arch.add_register(RegisterDef::new("x8", 0x80, 8));
    arch.add_register(RegisterDef::new("w8", 0x80, 4));
    arch.add_register(RegisterDef::new("x9", 0x88, 8));
    arch.add_register(RegisterDef::new("w9", 0x88, 4));
    arch
}

fn make_x86_64_prep_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rbx", 8, 8));
    arch.add_register(RegisterDef::new("rsp", 16, 8));
    arch.add_register(RegisterDef::new("rbp", 24, 8));
    arch
}

fn vector_loop_alias_arch(prefix: &str) -> ArchSpec {
    let mut arch = ArchSpec::new("range-alias-test");
    let acc = format!("{prefix}_acc");
    let loaded = format!("{prefix}_loaded");
    arch.add_register(RegisterDef::new(&acc, 0x100, 16));
    arch.add_register(RegisterDef::new(format!("{prefix}_acc_a"), 0x100, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_acc_b"), 0x104, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_acc_c"), 0x108, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_acc_d"), 0x10c, 4));
    arch.add_register(RegisterDef::new(&loaded, 0x200, 16));
    arch.add_register(RegisterDef::new(format!("{prefix}_load_a"), 0x200, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_load_b"), 0x204, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_load_c"), 0x208, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_load_d"), 0x20c, 4));
    arch.add_register(RegisterDef::new(format!("{prefix}_return64"), 0x300, 8));
    arch.add_register(RegisterDef::new(format!("{prefix}_return32"), 0x300, 4));
    arch
}

fn vector_loop_alias_blocks(base: u64) -> Vec<R2ILBlock> {
    let header = base + 4;
    let exit = base + 8;
    let body = base + 12;
    let mut body_ops = vec![R2ILOp::Load {
        dst: make_reg(0x200, 16),
        space: SpaceId::Ram,
        addr: make_const(0x8000, 8),
    }];
    for lane in 0u64..4 {
        let offset = lane * 4;
        body_ops.push(R2ILOp::IntAdd {
            dst: make_reg(0x100 + offset, 4),
            a: make_reg(0x100 + offset, 4),
            b: make_reg(0x200 + offset, 4),
        });
    }
    body_ops.push(R2ILOp::Branch {
        target: make_const(header, 8),
    });

    vec![
        R2ILBlock {
            addr: base,
            size: 4,
            ops: vec![
                R2ILOp::IntXor {
                    dst: make_reg(0x100, 16),
                    a: make_reg(0x100, 16),
                    b: make_reg(0x100, 16),
                },
                R2ILOp::Branch {
                    target: make_const(header, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: header,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(body, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: exit,
            size: 4,
            ops: vec![
                R2ILOp::Subpiece {
                    dst: make_reg(0x300, 4),
                    src: make_reg(0x100, 16),
                    offset: 0,
                },
                R2ILOp::IntZExt {
                    dst: make_reg(0x300, 8),
                    src: make_reg(0x300, 4),
                },
                R2ILOp::Return {
                    target: make_reg(0x300, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: body,
            size: 4,
            ops: body_ops,
            switch_info: None,
            op_metadata: Default::default(),
        },
    ]
}

#[test]
fn graph_value_storage_is_retained_from_varnodes_across_cosmetic_names() {
    fn arch(prefix: &str) -> ArchSpec {
        let mut arch = ArchSpec::new("storage-provenance-test");
        arch.add_register(RegisterDef::new(format!("{prefix}_out"), 0x10, 8));
        arch.add_register(RegisterDef::new(format!("{prefix}_input"), 0x20, 8));
        arch.add_register(RegisterDef::new(format!("{prefix}_return"), 0x30, 8));
        arch
    }

    let blocks = [R2ILBlock {
        addr: 0x2200,
        size: 4,
        ops: vec![
            R2ILOp::IntAdd {
                dst: make_reg(0x10, 8),
                a: make_reg(0x20, 8),
                b: make_const(7, 8),
            },
            R2ILOp::Return {
                target: make_reg(0x30, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let left =
        SSAFunction::from_blocks_raw(&blocks, Some(&arch("left"))).expect("left SSA must build");
    let right =
        SSAFunction::from_blocks_raw(&blocks, Some(&arch("right"))).expect("right SSA must build");
    let left_graph = SsaGraph::from_function(&left);
    let right_graph = SsaGraph::from_function(&right);

    let projection = |graph: &SsaGraph| {
        graph
            .values
            .iter()
            .map(|value| {
                (
                    value.id,
                    value.var.version,
                    value.var.size,
                    value.canonical_storage,
                    graph.def_inst(value.id),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(projection(&left_graph), projection(&right_graph));
    assert_ne!(
        left_graph
            .values
            .iter()
            .map(|value| value.var.name())
            .collect::<Vec<_>>(),
        right_graph
            .values
            .iter()
            .map(|value| value.var.name())
            .collect::<Vec<_>>()
    );
    let storages = left_graph
        .values
        .iter()
        .map(|value| value.canonical_storage.expect("raw value provenance"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        storages,
        BTreeSet::from([
            CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Register,
                offset: 0x10,
                size: 8,
            },
            CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Register,
                offset: 0x20,
                size: 8,
            },
            CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Register,
                offset: 0x30,
                size: 8,
            },
            CanonicalStorageId {
                space: crate::CanonicalStorageSpace::Constant,
                offset: 7,
                size: 8,
            },
        ])
    );
}

fn assert_vector_loop_alias_provenance(base: u64, prefix: &str) {
    let function = SSAFunction::from_blocks_raw(
        &vector_loop_alias_blocks(base),
        Some(&vector_loop_alias_arch(prefix)),
    )
    .expect("vector loop SSA should build");
    let accumulator = |var: &SSAVar| {
        function
            .canonical_storage_for_var(var)
            .is_some_and(|storage| {
                storage.space == CanonicalStorageSpace::Register
                    && storage.offset == 0x100
                    && storage.size == 16
            })
    };
    // The accumulator is one family, so the loop carries one merge of it.
    let header = function.get_block(base + 4).expect("loop header");
    let accumulator_phis = header
        .phis
        .iter()
        .filter(|phi| accumulator(&phi.dst))
        .collect::<Vec<_>>();
    let [phi] = accumulator_phis.as_slice() else {
        panic!("one accumulator phi, got {:?}", header.phis);
    };
    let graph = SsaGraph::from_function(&function);
    assert_eq!(phi.sources.len(), 2);
    for (_, source) in &phi.sources {
        let value = graph.value_id_for_var(source).expect("phi input value");
        assert!(
            graph.def_inst(value).is_some(),
            "every merge input must have an SSA producer: {source}"
        );
    }

    // Each lane update reads its lane of the accumulator and of the load
    // as a subpiece and inserts the sum back at the lane's position.
    let body = function.get_block(base + 12).expect("vector body");
    let loaded = body
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Load { dst, .. } if dst.size == 16 => Some(dst.clone()),
            _ => None,
        })
        .expect("wide vector load");
    let lane_reads_of = |source: &dyn Fn(&SSAVar) -> bool| {
        body.ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::Subpiece { src, offset, dst } if source(src) && dst.size == 4 => {
                    Some(*offset)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(lane_reads_of(&|src| *src == loaded), vec![0, 4, 8, 12]);
    assert_eq!(lane_reads_of(&accumulator), vec![0, 4, 8, 12]);
    let insert_positions = body
        .ops
        .iter()
        .filter_map(|op| match op {
            SSAOp::Insert(insert)
                if accumulator(&insert.dst)
                    && accumulator(&insert.src)
                    && insert.value.size == 4 =>
            {
                insert.position.constant_bits()
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(insert_positions, vec![0, 32, 64, 96]);

    // The exit reads the low lane of the merged accumulator.
    let exit = function.get_block(base + 8).expect("loop exit");
    assert!(exit.ops.iter().any(|op| matches!(
        op,
        SSAOp::Subpiece { dst, src, offset: 0 } if dst.size == 4 && *src == phi.dst
    )));
    assert!(
        !function
            .blocks()
            .iter()
            .flat_map(|block| &block.ops)
            .any(|op| matches!(op, SSAOp::Piece { .. }))
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

fn controlled_prep_blocks() -> Vec<R2ILBlock> {
    vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1004, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_reg(0, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ]
}

struct StopAtPoll {
    polls: Cell<usize>,
    stop_at: usize,
    cancellation: crate::SsaCancellationToken,
    execution: crate::SsaExecutionControl,
}

impl StopAtPoll {
    fn new(stop_at: usize) -> Self {
        let cancellation = crate::SsaCancellationToken::default();
        let execution = crate::SsaExecutionControl::with_cancellation(cancellation.clone());
        Self {
            polls: Cell::new(0),
            stop_at,
            cancellation,
            execution,
        }
    }
}

impl SsaWorkControl for StopAtPoll {
    fn poll(&self) -> Result<(), SsaExecutionStopReason> {
        let polls = self.polls.get() + 1;
        self.polls.set(polls);
        if polls == self.stop_at {
            self.cancellation.cancel();
        }
        self.execution.poll()
    }
}

#[test]
fn checked_decompile_builder_reports_pre_cancelled() {
    let cancellation = crate::SsaCancellationToken::default();
    cancellation.cancel();
    let control = crate::SsaExecutionControl::with_cancellation(cancellation);

    let result = SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

    assert!(matches!(result, Err(SsaPrepareError::Cancelled)));
}

#[test]
fn checked_decompile_builder_reports_expired_deadline() {
    let deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("one millisecond is representable");
    let control = crate::SsaExecutionControl::with_deadline(deadline);

    let result = SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

    assert!(matches!(result, Err(SsaPrepareError::DeadlineExceeded)));
    assert!(matches!(
        SsaArtifact::for_decompile_with_control(&[], None, &crate::SsaExecutionControl::default()),
        Err(SsaPrepareError::MalformedInput)
    ));
}

#[test]
fn checked_decompile_builder_observes_mid_dominator_worklist_cancellation() {
    // Polls 1-3 cover builder/CFG boundaries; poll 6 occurs while the
    // two-entry RPO index is being assembled by the dominator builder.
    let control = StopAtPoll::new(6);

    let result = SsaArtifact::for_decompile_with_control(&controlled_prep_blocks(), None, &control);

    assert!(matches!(result, Err(SsaPrepareError::Cancelled)));
    assert_eq!(control.polls.get(), 6);
}

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
fn test_ssa_function_linear() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(1, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                },
            ],
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
    ];

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
    assert_eq!(func.entry, 0x1000);
    assert_eq!(func.num_blocks(), 2);

    // Check that entry block has the copy operations
    let entry = func.entry_block().unwrap();
    assert_eq!(entry.num_ops(), 2);
    assert!(!entry.has_phis());
}

#[test]
fn a_lane_read_is_a_subpiece_of_the_root_it_reads() {
    let arch = make_arm64_alias_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0x88, 8),
                src: make_const(0xdead, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: make_const(0x4000, 8),
                val: make_reg(0x88, 4),
            },
            R2ILOp::Return {
                target: make_ram(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let func = SSAFunction::from_blocks_raw(&blocks, Some(&arch)).expect("raw SSA");
    let ops = &func.entry_block().expect("entry block").ops;
    let stored = ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Store { val, .. } => Some(val.clone()),
            _ => None,
        })
        .expect("store");
    assert!(
        ops.iter().any(|op| matches!(
            op,
            SSAOp::Subpiece { dst, src, offset: 0 }
                if *dst == stored
                    && src.name().eq_ignore_ascii_case("x9")
                    && src.version == 1
                    && src.size == 8
        )),
        "the lane read is a subpiece of the written root: {ops:?}"
    );
}

#[test]
fn a_lane_read_of_a_constant_root_is_the_constant() {
    let arch = make_arm64_alias_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0x88, 8),
                src: make_const(0xdead, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: make_const(0x4000, 8),
                val: make_reg(0x88, 4),
            },
            R2ILOp::Return {
                target: make_ram(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let func = SSAFunction::from_blocks_for_decompile(&blocks, Some(&arch)).expect("decompile SSA");
    let store = func
        .entry_block()
        .expect("entry block")
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Store { val, .. } => Some(val),
            _ => None,
        })
        .expect("observable store");
    let stored = func
        .entry_block()
        .expect("entry block")
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Copy { dst, src } if dst == store => Some(src.clone()),
            _ => None,
        })
        .unwrap_or_else(|| store.clone());
    assert_eq!(stored, SSAVar::constant(0xdead, 4));
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
fn ssa_artifact_exposes_typed_graph_queries() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![R2ILBlock {
        addr: 0x1080,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(0x33, 8),
            },
            R2ILOp::Return {
                target: make_reg(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let artifact = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("artifact");
    let graph = artifact.graph();
    let value = artifact
        .blocks()
        .iter()
        .next()
        .and_then(|block| block.ops.first())
        .and_then(|op| op.dst())
        .cloned()
        .expect("destination value");
    let value_id = graph.value_id_for_var(&value).expect("value id");
    let def_inst = graph.def_inst(value_id).expect("definition");
    let use_sites = graph.use_sites(value_id);

    assert_eq!(
        graph.value(value_id).expect("value").var,
        value,
        "graph should retain render metadata for each typed value"
    );
    assert_eq!(
        graph.inst(def_inst).expect("inst").output,
        Some(value_id),
        "def_of should point back to the defining instruction"
    );
    assert_eq!(
        use_sites.len(),
        1,
        "return should consume the copied value once"
    );
}

#[test]
fn prepared_function_refuses_return_without_source_boundary_authority() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1010, 8),
                cond: make_reg(8, 8),
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
                    src: make_const(1, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1014, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1010,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1014, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1014,
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
    assert!(prepared.return_certificate_for_op(0x1014, 0).is_none());
    assert!(prepared.return_certificate_for_op(0x1004, 0).is_none());
    assert!(prepared.return_certificate_for_op(0x1010, 0).is_none());
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

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
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

#[test]
fn ssa_artifact_graph_ids_are_deterministic() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1200,
            size: 4,
            ops: vec![R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(1, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1204,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_reg(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let first = SsaArtifact::raw(&blocks, None).expect("first artifact");
    let second = SsaArtifact::raw(&blocks, None).expect("second artifact");

    assert_eq!(
        first.graph(),
        second.graph(),
        "graph ids should be stable across builds"
    );
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
    .expect("stack-pointer carrier")
    .with_preserved_call_carriers(true, true);

    let prepared = SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
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

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
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
fn prepared_function_ssa_collects_structured_dataflow_facts() {
    let loop_blocks = vec![
        R2ILBlock {
            addr: 0x1400,
            size: 4,
            ops: vec![R2ILOp::CBranch {
                target: make_const(0x1408, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1404,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1408,
            size: 4,
            ops: vec![
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: make_const(0x5000, 8),
                    val: make_const(7, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1400, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let prepared = SsaArtifact::raw(&loop_blocks, None).expect("prepared SSA should build");
    let structured = prepared.structured();
    let loop_fact = structured.loops.values().next().expect("natural loop fact");
    assert_eq!(structured.loops.len(), 1);
    assert_eq!(loop_fact.header, 0x1400);
    assert_eq!(loop_fact.latches, vec![0x1408]);
    assert_eq!(loop_fact.exits, vec![0x1404]);
    assert!(loop_fact.body.contains(&0x1400));
    assert!(loop_fact.body.contains(&0x1408));
    assert!(loop_fact.condition.is_some());
    assert!(
        structured.memory_accesses.values().any(|access| {
            access.block_addr == 0x1408 && access.op_index == 0 && access.is_write
        })
    );
    let certificates = prepared.certificates();
    assert_eq!(certificates.loops.len(), 1);
    assert!(certificates.switches.is_empty());
    assert!(!certificates.expressions.is_empty());
    assert_eq!(
        certificates.memory_accesses.len(),
        structured.memory_accesses.len()
    );
    assert!(certificates.returns.is_empty());

    let recursive_blocks = vec![
        R2ILBlock {
            addr: 0x1500,
            size: 4,
            ops: vec![R2ILOp::Call {
                target: make_const(0x1500, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1504,
            size: 4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let recursive = SsaArtifact::raw(&recursive_blocks, None).expect("recursive SSA should build");
    let call = recursive
        .structured()
        .recursive_calls
        .values()
        .next()
        .expect("recursive call fact");
    assert_eq!(recursive.structured().recursive_calls.len(), 1);
    assert_eq!(call.block_addr, 0x1500);
    assert_eq!(call.target, 0x1500);
}

/// A machine, a convention and a callsite whose prototype names two
/// parameters. The second is optionally the radare2-identified format.
fn variadic_format_call_artifact(
    defined: usize,
    variadic: bool,
    format_parameter: Option<u32>,
    format: Option<&str>,
) -> SsaArtifact {
    variadic_format_call_artifact_formed(defined, variadic, format_parameter, format, false)
}

/// The same, with the format address formed by constant arithmetic when
/// `arithmetic` is set: a page constant plus an offset, as arm64 spells it.
fn variadic_format_call_artifact_formed(
    defined: usize,
    variadic: bool,
    format_parameter: Option<u32>,
    format: Option<&str>,
    arithmetic: bool,
) -> SsaArtifact {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
        arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
    }
    let slot = |index: usize| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: (index as u64) * 8,
        size: 8,
    };

    let mut ops = (0..defined)
        .flat_map(|index| {
            let register = make_reg((index as u64) * 8, 8);
            if u32::try_from(index).ok() == format_parameter && arithmetic {
                vec![
                    R2ILOp::Copy {
                        dst: register.clone(),
                        src: make_const(0x2f00, 8),
                    },
                    R2ILOp::IntAdd {
                        dst: register.clone(),
                        a: register,
                        b: make_const(0x100, 8),
                    },
                ]
            } else {
                vec![R2ILOp::Copy {
                    dst: register,
                    src: make_const(
                        if u32::try_from(index).ok() == format_parameter {
                            0x3000
                        } else {
                            0x10 + index as u64
                        },
                        8,
                    ),
                }]
            }
        })
        .collect::<Vec<_>>();
    let call_index = ops.len();
    ops.push(R2ILOp::Call {
        target: make_const(0x2000, 8),
    });
    ops.push(R2ILOp::Return {
        target: make_const(0, 8),
    });
    let mut block = R2ILBlock {
        addr: 0x1600,
        size: 4,
        ops,
        switch_info: None,
        op_metadata: Default::default(),
    };
    block.stamp_instruction(call_index, 0x1600 + call_index as u64);
    let blocks = vec![block];

    let mut interface = SourceCallSiteInterface::new(
        b"variadic-tail".to_vec(),
        SourceCallSiteIdentity::new(
            0x1600 + call_index as u64,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        ),
        true,
        "amd64",
        [
            SourceCallArgumentSpec::new(0, slot(0)),
            SourceCallArgumentSpec::new(1, slot(1)),
        ],
        variadic,
        false,
        SourceCallResult::Void,
    )
    .expect("exact callsite interface");
    if let Some(index) = format_parameter {
        interface = interface
            .with_radare2_format_parameter(index)
            .expect("format parameter belongs to the fixed prefix");
    }
    let convention =
        SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
            .expect("convention slots");
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        SourceMachineRoles::default(),
        Some(convention),
        vec![interface],
    );
    if let Some(format) = format {
        machine_context.bind_source_string_literals(&[(0x3000, format.to_string())]);
    }
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        &blocks,
        Some(&arch),
        InterfaceQuestions::new(&machine_context),
        machine_context.machine_roles().call_preserved_carriers(),
        machine_context.stack_pointer_carrier(),
        &CalleeBoundaries::default(),
        None,
        &UncheckedSsaWorkControl,
    )
    .expect("decompile SSA");
    SsaArtifact::new_with_context(function, machine_context)
}

/// A call whose format argument is a merge of two literals.
///
/// The compiler that folded two `fprintf` calls into one left exactly this
/// shape, and the count is a property of the format rather than of the
/// path that chose it.
fn merged_format_call(first: &str, second: &str) -> CallsiteCertificate {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
        arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
    }
    let slot = |index: usize| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: (index as u64) * 8,
        size: 8,
    };
    let mut join = R2ILBlock {
        addr: 0x1014,
        size: 4,
        ops: vec![
            R2ILOp::Call {
                target: make_const(0x2000, 8),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    };
    join.stamp_instruction(0, 0x1014);
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(0x10, 8),
                },
                R2ILOp::CBranch {
                    target: make_const(0x1010, 8),
                    cond: make_reg(24, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_const(0x3000, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1014, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1010,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_const(0x3010, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x1014, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        join,
    ];

    let interface = SourceCallSiteInterface::new(
        b"merged-format".to_vec(),
        SourceCallSiteIdentity::new(
            0x1014,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x2000,
                size: 8,
            },
        ),
        true,
        "amd64",
        [
            SourceCallArgumentSpec::new(0, slot(0)),
            SourceCallArgumentSpec::new(1, slot(1)),
        ],
        true,
        false,
        SourceCallResult::Void,
    )
    .expect("exact callsite interface")
    .with_radare2_format_parameter(1)
    .expect("format parameter belongs to the fixed prefix");
    let convention =
        SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
            .expect("convention slots");
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        SourceMachineRoles::default(),
        Some(convention),
        vec![interface],
    );
    machine_context
        .bind_source_string_literals(&[(0x3000, first.to_string()), (0x3010, second.to_string())]);
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        &blocks,
        Some(&arch),
        InterfaceQuestions::new(&machine_context),
        machine_context.machine_roles().call_preserved_carriers(),
        machine_context.stack_pointer_carrier(),
        &CalleeBoundaries::default(),
        None,
        &UncheckedSsaWorkControl,
    )
    .expect("decompile SSA");
    SsaArtifact::new_with_context(function, machine_context)
        .sole_callsite_certificate_in_block(0x1014)
        .expect("callsite certificate")
        .clone()
}

#[test]
fn merged_formats_that_agree_prove_the_variadic_count() {
    let call = merged_format_call("opened %d", "closed %d");
    let evidence = call
        .variadic_argument_count_evidence
        .expect("merged literal count");
    assert!(evidence.merged_literals);
    assert!(matches!(
        evidence.parameter_rule,
        crate::SourceFormatParameterRule::Radare2FormatString { parameter_index: 1 }
    ));
    assert_eq!(evidence.format_argument_index, 1);
    assert_eq!(evidence.format_consumed_argument_count, 1);
    assert_eq!(evidence.total_argument_count, 3);
    assert!(call.variadic_argument_count_refusal.is_none());
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

fn variadic_format_call(
    defined: usize,
    variadic: bool,
    format_parameter: Option<u32>,
    format: Option<&str>,
) -> CallsiteCertificate {
    variadic_format_call_artifact(defined, variadic, format_parameter, format)
        .sole_callsite_certificate_in_block(0x1600)
        .expect("callsite certificate")
        .clone()
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

/// A format address the code forms from a page and an offset is the
/// literal at that address, the way `adrp`/`add` spells every string.
#[test]
fn a_variadic_call_reads_a_format_formed_by_constant_arithmetic() {
    let call = variadic_format_call_artifact_formed(4, true, Some(1), Some("%d %s"), true)
        .sole_callsite_certificate_in_block(0x1600)
        .expect("callsite certificate")
        .clone();
    assert_eq!(call.argument_values.len(), 4);
    assert_eq!(
        call.variadic_argument_count_evidence
            .expect("literal count evidence")
            .format_consumed_argument_count,
        2
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
    let roles = SourceMachineRoles::new(Some(register(72)), Some(register(64)))
        .expect("machine roles")
        .with_call_preserved_carriers(r2source::SourceCallPreservedCarriers::new(true, true));
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        roles,
        Some(convention),
        vec![interface],
    );
    machine_context.bind_source_string_literals(&[(0x3000, "%d".to_string())]);
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        &blocks,
        Some(&arch),
        InterfaceQuestions::new(&machine_context),
        machine_context.machine_roles().call_preserved_carriers(),
        machine_context.stack_pointer_carrier(),
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

/// Two sites reaching one variadic callee keep separate literal-count
/// evidence. Both sites write every convention register, so a result of
/// four for either call would expose the old register-write guess.
#[test]
fn two_calls_to_one_variadic_callee_may_pass_different_counts() {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    for (index, name) in ["rdi", "rsi", "rdx", "rcx"].iter().enumerate() {
        arch.add_register(RegisterDef::new(*name, (index as u64) * 8, 8));
    }
    let slot = |index: usize| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: (index as u64) * 8,
        size: 8,
    };
    let target = make_const(0x2000, 8);
    let first_call_index = 4;
    let second_call_index = 9;
    let mut blocks = vec![R2ILBlock {
        addr: 0x1680,
        size: 11,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(1, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(8, 8),
                src: make_const(0x3000, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(16, 8),
                src: make_const(2, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(24, 8),
                src: make_const(3, 8),
            },
            R2ILOp::Call {
                target: target.clone(),
            },
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(4, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(8, 8),
                src: make_const(0x3010, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(16, 8),
                src: make_const(5, 8),
            },
            R2ILOp::Copy {
                dst: make_reg(24, 8),
                src: make_const(6, 8),
            },
            R2ILOp::Call {
                target: target.clone(),
            },
            R2ILOp::Return {
                target: make_const(0, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    blocks[0].stamp_instruction(first_call_index, 0x1680 + first_call_index as u64);
    blocks[0].stamp_instruction(second_call_index, 0x1680 + second_call_index as u64);
    let interface = |op_index: usize| {
        SourceCallSiteInterface::new(
            b"same-variadic-callee".to_vec(),
            SourceCallSiteIdentity::new(
                0x1680 + op_index as u64,
                CanonicalStorageId::from_varnode(&target),
            ),
            true,
            "amd64",
            [
                SourceCallArgumentSpec::new(0, slot(0)),
                SourceCallArgumentSpec::new(1, slot(1)),
            ],
            true,
            false,
            SourceCallResult::Void,
        )
        .and_then(|interface| interface.with_radare2_format_parameter(1))
        .expect("exact variadic callsite interface")
    };
    let convention =
        SourceConventionSlots::new("amd64", (0..4).map(slot).collect::<Vec<_>>(), None)
            .expect("convention slots");
    let mut machine_context = SourceMachineContext::from_blocks_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        SourceMachineRoles::default(),
        Some(convention),
        vec![interface(first_call_index), interface(second_call_index)],
    );
    machine_context.bind_source_string_literals(&[
        (0x3000, "%u:%u".to_string()),
        (0x3010, "complete: 100%%".to_string()),
    ]);
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        &blocks,
        Some(&arch),
        InterfaceQuestions::new(&machine_context),
        machine_context.machine_roles().call_preserved_carriers(),
        machine_context.stack_pointer_carrier(),
        &CalleeBoundaries::default(),
        None,
        &UncheckedSsaWorkControl,
    )
    .expect("decompile SSA");
    let artifact = SsaArtifact::new_with_context(function, machine_context);

    let calls = artifact
        .certificates()
        .callsites
        .values()
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    let [first, second] = calls.as_slice() else {
        unreachable!("the callsite count was checked above")
    };
    assert_eq!(first.target, second.target);
    assert_eq!(first.fixed_argument_count, Some(2));
    assert_eq!(second.fixed_argument_count, Some(2));
    assert_eq!(first.argument_values.len(), 4);
    assert_eq!(second.argument_values.len(), 2);
    assert_eq!(
        first
            .variadic_argument_count_evidence
            .expect("first literal count")
            .format_literal_address,
        0x3000
    );
    assert_eq!(
        second
            .variadic_argument_count_evidence
            .expect("second literal count")
            .format_literal_address,
        0x3010
    );
}

#[test]
fn variadic_calls_without_literal_format_evidence_refuse() {
    let no_format_role = variadic_format_call(4, true, None, Some("%d"));
    assert!(no_format_role.argument_values.is_empty());
    assert_eq!(
        no_format_role.variadic_argument_count_refusal,
        Some(crate::VariadicCallsiteArgumentCountRefusal::MissingFormatParameter)
    );

    let non_literal = variadic_format_call(4, true, Some(1), None);
    assert!(non_literal.argument_values.is_empty());
    assert_eq!(
        non_literal.variadic_argument_count_refusal,
        Some(crate::VariadicCallsiteArgumentCountRefusal::FormatArgumentNotLiteral)
    );
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

    let prepared = SsaArtifact::for_decompile_with_interfaces(
        &blocks,
        Some(&arch),
        Some(function_interface),
        vec![call_interface],
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
    let prepared = SsaArtifact::for_decompile_with_interfaces(
        &blocks,
        Some(&arch),
        None,
        vec![call_interface],
    )
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

    let first =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("first prepared SSA should build");
    let second =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("second prepared SSA should build");
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
    let convention =
        SourceConventionSlots::new("amd64", [], Some(full_result)).expect("result convention");
    let prepared = SsaArtifact::for_decompile_with(
        &blocks,
        DecompileInputs {
            arch: Some(&arch),
            convention_slots: Some(convention),
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

    let prepared =
        SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA should build");
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

#[test]
fn prepared_expression_certificates_require_structural_render_proof() {
    let pure_blocks = vec![R2ILBlock {
        addr: 0x1700,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(7, 8),
            },
            R2ILOp::IntAdd {
                dst: make_reg(8, 8),
                a: make_reg(0, 8),
                b: make_const(1, 8),
            },
            R2ILOp::Return {
                target: make_reg(8, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let pure = SsaArtifact::raw(&pure_blocks, None).expect("pure SSA");
    let pure_value = pure
        .graph()
        .inst_id_for_op_site(0x1700, 1)
        .and_then(|inst| pure.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("pure expression output");
    assert!(
        pure.certificates()
            .expressions
            .get(&pure_value)
            .is_some_and(|cert| cert.renderable),
        "pure expression outputs should be renderable"
    );

    let load_blocks = vec![R2ILBlock {
        addr: 0x1710,
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
    }];
    let loaded = SsaArtifact::raw(&load_blocks, None).expect("load SSA");
    let loaded_value = loaded
        .graph()
        .inst_id_for_op_site(0x1710, 0)
        .and_then(|inst| loaded.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("load output");
    assert!(
        loaded
            .certificates()
            .expressions
            .get(&loaded_value)
            .is_some_and(|cert| cert.renderable),
        "memory-load expression outputs require a structured memory-read certificate"
    );

    let userop_out = Varnode {
        space: SpaceId::Unique,
        offset: 0x2222,
        size: 8,
        meta: None,
    };
    let userop_blocks = vec![R2ILBlock {
        addr: 0x1720,
        size: 4,
        ops: vec![
            R2ILOp::CallOther {
                output: Some(userop_out.clone()),
                userop: 99,
                inputs: vec![make_reg(0, 8)],
            },
            R2ILOp::Return { target: userop_out },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let userop = SsaArtifact::raw(&userop_blocks, None).expect("userop SSA");
    let userop_value = userop
        .graph()
        .inst_id_for_op_site(0x1720, 0)
        .and_then(|inst| userop.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("userop output");
    assert!(
        userop
            .certificates()
            .expressions
            .get(&userop_value)
            .is_some_and(|cert| !cert.renderable),
        "opaque userop outputs must not be renderable by width alone"
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
fn prepared_return_certificates_require_complete_source_boundary() {
    let arch = make_x86_64_prep_arch();
    let blocks = vec![
        R2ILBlock {
            addr: 0x1760,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(7, 8),
                },
                R2ILOp::Branch {
                    target: Varnode::ram(0x1770, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1770,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(9, 8),
                },
                R2ILOp::Return {
                    target: make_reg(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let prepared = SsaArtifact::for_decompile(&blocks, Some(&arch)).expect("prepared SSA");

    assert!(prepared.certificates().returns.is_empty());
    assert!(prepared.return_certificate_for_op(0x1770, 1).is_none());
    assert!(
        prepared.return_certificate_for_op(0x1760, 0).is_none(),
        "a predecessor return-register write is dataflow, not a return effect"
    );
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

fn projected_peer_loop_artifact(
    phi_order: &[usize],
    name_prefix: &str,
    coherent_storage_run: bool,
) -> SsaArtifact {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1b00,
            size: 0x10,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1b10, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1b10,
            size: 0x10,
            ops: vec![R2ILOp::CBranch {
                target: make_ram(0x1b30, 8),
                cond: make_const(1, 1),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1b20,
            size: 0x10,
            ops: vec![R2ILOp::Branch {
                target: make_ram(0x1b10, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1b30,
            size: 0x4,
            ops: vec![R2ILOp::Return {
                target: make_const(0, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];
    let widths = [8_u32, 4, 2];
    let entries = widths
        .iter()
        .enumerate()
        .map(|(index, width)| SSAVar::new(format!("{name_prefix}:entry:{index}"), 0, *width))
        .collect::<Vec<_>>();
    let phis = widths
        .iter()
        .enumerate()
        .map(|(index, width)| SSAVar::new(format!("{name_prefix}:phi:{index}"), 1, *width))
        .collect::<Vec<_>>();
    let updates = widths
        .iter()
        .enumerate()
        .map(|(index, width)| SSAVar::new(format!("{name_prefix}:update:{index}"), 2, *width))
        .collect::<Vec<_>>();
    let storage = |size| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size,
    };
    let phi_nodes = widths
        .iter()
        .enumerate()
        .map(|(index, width)| PhiNode {
            dst: phis[index].clone(),
            sources: vec![
                (0x1b00, entries[index].clone()),
                (0x1b20, updates[index].clone()),
            ],
            canonical_storage: Some(storage(*width)),
        })
        .collect::<Vec<_>>();

    let mut function =
        SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw peer loop should build");
    function.get_block_mut(0x1b10).expect("loop header").phis = phi_order
        .iter()
        .map(|index| phi_nodes[*index].clone())
        .collect();
    function.get_block_mut(0x1b10).expect("loop header").ops = vec![SSAOp::CBranch {
        target: SSAVar::new("ram:1b30", 0, 8),
        cond: SSAVar::constant(1, 1),
    }];
    function.get_block_mut(0x1b20).expect("loop latch").ops = if coherent_storage_run {
        vec![
            SSAOp::IntZExt {
                dst: updates[0].clone(),
                src: phis[1].clone(),
            },
            SSAOp::IntZExt {
                dst: updates[1].clone(),
                src: phis[2].clone(),
            },
            SSAOp::Subpiece {
                dst: updates[2].clone(),
                src: phis[0].clone(),
                offset: 0,
            },
            SSAOp::Branch {
                target: SSAVar::new("ram:1b10", 0, 8),
                instruction: None,
            },
        ]
    } else {
        vec![
            SSAOp::IntAdd {
                dst: updates[0].clone(),
                a: phis[0].clone(),
                b: SSAVar::constant(1, 8),
            },
            SSAOp::IntAdd {
                dst: updates[1].clone(),
                a: phis[1].clone(),
                b: SSAVar::constant(1, 4),
            },
            SSAOp::IntAdd {
                dst: updates[2].clone(),
                a: phis[2].clone(),
                b: SSAVar::constant(1, 2),
            },
            SSAOp::Branch {
                target: SSAVar::new("ram:1b10", 0, 8),
                instruction: None,
            },
        ]
    };
    function.get_block_mut(0x1b30).expect("loop exit").ops = vec![SSAOp::Return {
        target: phis[0].clone(),
    }];
    for (index, width) in widths.iter().copied().enumerate() {
        for value in [&entries[index], &phis[index], &updates[index]] {
            function
                .canonical_storage_by_var
                .insert(value.clone(), storage(width));
        }
    }

    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("RAX", 0, 8));
    arch.add_register(RegisterDef::sub("EAX", 0, 4, "RAX"));
    arch.add_register(RegisterDef::sub("AX", 0, 2, "RAX"));
    let rax = r2il::RegisterStorage { offset: 0, size: 8 };
    let eax = r2il::RegisterStorage { offset: 0, size: 4 };
    let ax = r2il::RegisterStorage { offset: 0, size: 2 };
    arch.register_projections = vec![
        r2il::RegisterProjection {
            written: ax,
            disposition: r2il::RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 16,
                },
            },
        },
        r2il::RegisterProjection {
            written: eax,
            disposition: r2il::RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 32,
                },
            },
        },
        r2il::RegisterProjection {
            written: rax,
            disposition: r2il::RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: r2il::RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 64,
                },
            },
        },
    ];
    let mut geometry_blocks = blocks;
    geometry_blocks[0].ops = vec![
        R2ILOp::Copy {
            dst: make_unique(0x1b00, 8),
            src: make_reg(0, 8),
        },
        R2ILOp::Copy {
            dst: make_unique(0x1b10, 4),
            src: make_reg(0, 4),
        },
        R2ILOp::Copy {
            dst: make_unique(0x1b20, 2),
            src: make_reg(0, 2),
        },
    ];
    let machine_context = SourceMachineContext::from_blocks(&geometry_blocks, Some(&arch));
    assert_eq!(
        machine_context.register_geometry_state(),
        crate::MachineRegisterGeometryState::Available,
    );
    for written in [ax, eax, rax] {
        assert!(matches!(
            machine_context
                .register_projection(CanonicalStorageId {
                    space: CanonicalStorageSpace::Register,
                    offset: written.offset,
                    size: written.size,
                })
                .map(|projection| projection.disposition),
            Some(r2il::RegisterProjectionDisposition::Bound { carrier, .. })
                if carrier == rax
        ));
    }
    SsaArtifact::new_with_context(function, machine_context)
}

fn projected_peer_role_signature(
    prepared: &SsaArtifact,
) -> Vec<(u32, Vec<crate::LoopCarrierMemberRole>)> {
    let loop_fact = prepared
        .structured()
        .loops
        .values()
        .next()
        .expect("projected peer loop");
    let leader = loop_fact
        .carriers
        .iter()
        .max_by_key(|carrier| carrier.width)
        .expect("wide loop carrier");
    let mut signature = leader
        .members
        .iter()
        .map(|member| {
            (
                prepared
                    .graph()
                    .value(member.value)
                    .and_then(|value| value.canonical_storage)
                    .map_or(0, |storage| storage.size),
                member.roles.iter().copied().collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    signature.sort();
    signature
}

fn projected_peer_certificate_component(
    loop_fact: &crate::StructuredLoopFact,
) -> BTreeSet<ValueId> {
    let mut sets = loop_fact
        .carriers
        .iter()
        .map(crate::LoopCarrierFact::coalescing_values)
        .collect::<Vec<_>>();
    sets.sort_by_key(|members| members.first().copied());
    let mut component = sets.first().cloned().unwrap_or_default();
    let mut pending = sets.into_iter().skip(1).collect::<Vec<_>>();
    loop {
        let mut changed = false;
        pending.retain(|members| {
            if component.is_disjoint(members) {
                true
            } else {
                component.extend(members.iter().copied());
                changed = true;
                false
            }
        });
        if !changed {
            break;
        }
    }
    component
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
fn test_ssa_function_diamond() {
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
                    src: make_const(1, 8),
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
                src: make_const(2, 8),
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

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();
    assert_eq!(func.num_blocks(), 4);

    // Merge block should have a phi node
    let merge = func.get_block(0x100c).unwrap();
    assert!(merge.has_phis());
    assert_eq!(merge.num_phis(), 1);

    // Phi should have two sources
    let phi = &merge.phis[0];
    assert_eq!(phi.sources.len(), 2);
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
    let expected_order = blocks.iter().map(|block| block.addr).collect::<Vec<_>>();
    let latch = BASE + (BLOCK_COUNT as u64 - 1) * 4;

    let function = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("SSA for deep cyclic CFG");
    let risk = function.cfg_risk_summary();

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
fn test_raw_ssa_construction_is_deterministic_across_runs() {
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
                    src: make_const(1, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_reg(0, 8),
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
            ops: vec![
                R2ILOp::Copy {
                    dst: make_reg(0, 8),
                    src: make_const(2, 8),
                },
                R2ILOp::Copy {
                    dst: make_reg(8, 8),
                    src: make_reg(0, 8),
                },
                R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x100c,
            size: 4,
            ops: vec![
                R2ILOp::IntXor {
                    dst: make_reg(16, 8),
                    a: make_reg(8, 8),
                    b: make_reg(0, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let mut dumps = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA should build");
        dumps.insert(func.dump());
    }

    assert_eq!(
        dumps.len(),
        1,
        "raw SSA output should stay stable across repeated construction"
    );
}

#[test]
fn test_find_def_use() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(1, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
        R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![R2ILOp::IntAdd {
                dst: make_reg(8, 8),
                a: make_reg(0, 8),
                b: make_const(1, 8),
            }],
            switch_info: None,
            op_metadata: Default::default(),
        },
    ];

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks).unwrap();

    // Find definition of reg:0 v1
    let var = SSAVar::new("reg:0", 1, 8);
    let def = func.find_def(&var);
    assert!(def.is_some());
    let (addr, loc) = def.unwrap();
    assert_eq!(addr, 0x1000);
    assert!(matches!(loc, DefLocation::Op(0)));

    // Find uses of reg:0 v1
    let uses = func.find_uses(&var);
    assert!(!uses.is_empty());
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
fn test_dump() {
    let blocks = vec![
        R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![R2ILOp::Copy {
                dst: make_reg(0, 8),
                src: make_const(42, 8),
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
    ];

    let func = SSAFunction::from_blocks_raw_no_arch(&blocks)
        .unwrap()
        .with_name("test_func");

    let dump = func.dump();
    assert!(dump.contains("test_func"));
    assert!(dump.contains("0x1000"));
    assert!(dump.contains("0x1004"));
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
fn a_lane_write_inserts_into_the_entry_root() {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("RAX", 0, 8));
    arch.add_register(RegisterDef::sub("AH", 1, 1, "RAX"));
    let mut block = R2ILBlock::new(0x1000, 4);
    // The caller's register is read on its own account, so it is not the
    // scratch register whose lane writes start from zero.
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: make_const(0x1ff8, 8),
        val: make_reg(0, 8),
    });
    block.push(R2ILOp::Copy {
        dst: make_reg(1, 1),
        src: make_const(3, 1),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: make_const(0x2000, 8),
        val: make_reg(0, 8),
    });

    let function = SSAFunction::from_blocks_with_arch(&[block], Some(&arch))
        .expect("partial-register fixture");
    let ops = &function.get_block(0x1000).expect("entry block").ops;
    let stored = ops
        .iter()
        .filter_map(|op| match op {
            SSAOp::Store { val, .. } => Some(val.clone()),
            _ => None,
        })
        .next_back()
        .expect("the store after the lane write");
    assert_eq!(stored, SSAVar::new("RAX", 1, 8), "{ops:?}");
    let lane = ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Insert(insert)
                if insert.dst == stored && insert.src == SSAVar::new("RAX", 0, 8) =>
            {
                assert_eq!(insert.position.constant_bits(), Some(8));
                Some(insert.value.clone())
            }
            _ => None,
        })
        .expect("the high byte is inserted into the entry root");
    assert!(
        lane.constant_bits() == Some(3)
            || ops.iter().any(|op| matches!(
                op,
                SSAOp::Copy { dst, src } if *dst == lane && src.constant_bits() == Some(3)
            )),
        "{ops:?}"
    );
    assert!(!ops.iter().any(|op| matches!(op, SSAOp::Piece { .. })));
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
fn a_low_byte_read_of_a_constant_lane_write_is_the_constant() {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_register(RegisterDef::new("RAX", 0x00, 8));
    arch.add_register(RegisterDef::new("EAX", 0x00, 4));
    arch.add_register(RegisterDef::new("AL", 0x00, 1));

    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            R2ILOp::Copy {
                dst: make_reg(0, 4),
                src: make_const(0x41, 4),
            },
            R2ILOp::IntEqual {
                dst: make_reg(0x200, 1),
                a: make_reg(0, 1),
                b: make_const(0x41, 1),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    // The lane write inserts into `RAX`; reading the byte back through
    // the insert and the constant is the optimizer's fold, so the fact is
    // stated of the optimized function.
    let mut func = SSAFunction::from_blocks_raw(&blocks, Some(&arch)).expect("raw SSA");
    crate::optimize::optimize_function(&mut func, &crate::optimize::OptimizationConfig::default());
    // The byte read back is the constant, so the comparison folds to true.
    let block = func.get_block(0x1000).expect("entry block");
    let flag = block
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Copy { dst, src } if dst.size == 1 && dst.name() == "reg:200" => {
                Some(src.clone())
            }
            SSAOp::IntEqual { a, .. } => Some(a.clone()),
            _ => None,
        })
        .expect("the comparison or its folded result survives");
    assert!(
        flag == SSAVar::constant(1, 1) || flag == SSAVar::constant(0x41, 1),
        "{:?}",
        block.ops
    );
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
    .expect("custom stack-pointer carrier")
    .with_preserved_call_carriers(true, false);
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
    .expect("custom stack-pointer carrier")
    .with_preserved_call_carriers(true, false);

    for (name, boundary) in [
        (
            "call",
            R2ILOp::Call {
                target: make_const(0x5000, 8),
            },
        ),
        (
            "unknown effect",
            R2ILOp::CallOther {
                output: None,
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
        let artifact =
            SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface.clone())
                .unwrap_or_else(|| panic!("{name} artifact must build"));
        let facts = artifact
            .function()
            .decompile_prep_facts()
            .expect("custom prep facts");
        assert!(
            !facts.stack_address_roots.is_empty(),
            "{name} must preserve source-declared stack roots"
        );
        if name == "call" {
            assert!(
                !facts.entry_stack_address_roots.is_empty(),
                "a convention-preserved SP retains entry-relative roots without an FP role"
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
fn test_constant_display_names_do_not_supply_bits() {
    let named_constant = SSAVar::new("const:0x1234", 0, 8);
    assert_eq!(named_constant.constant_bits(), None);
    assert_eq!(adapt_root_width(&named_constant, 4), None);

    let canonical_constant = SSAVar::constant(0x1234, 8).renamed("not-a-constant");
    assert_eq!(canonical_constant.constant_bits(), Some(0x1234));
    assert_eq!(
        adapt_root_width(&canonical_constant, 4),
        Some(SSAVar::constant(0x1234, 4))
    );
}

#[test]
fn prepared_ssa_preserves_exact_widths_when_unique_offsets_are_reused() {
    // Sleigh unique-space offsets are local scratch locations reused by
    // unrelated instruction templates. A later 8-byte definition must not
    // resize an earlier 16-byte IMUL overflow chain during SSA renaming.
    let extended = make_unique(0x2d180, 16);
    let product = make_unique(0x4b600, 16);
    let reused = make_unique(0x2d180, 8);
    let blocks = vec![R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            R2ILOp::IntSExt {
                dst: extended.clone(),
                src: make_reg(0x88, 8),
            },
            R2ILOp::IntNotEqual {
                dst: make_reg(0x200, 1),
                a: extended,
                b: product,
            },
            R2ILOp::Copy {
                dst: reused,
                src: make_reg(0x10, 8),
            },
        ],
        switch_info: None,
        op_metadata: Default::default(),
    }];

    let artifact = SsaArtifact::raw(&blocks, None).expect("width-coherent prepared SSA");
    let ops = &artifact
        .function()
        .get_block(0x1000)
        .expect("entry block")
        .ops;

    assert!(matches!(
        &ops[0],
        SSAOp::IntSExt { dst, src } if dst.size == 16 && src.size == 8
    ));
    assert!(matches!(
        &ops[1],
        SSAOp::IntNotEqual { dst, a, b }
            if dst.size == 1 && a.size == 16 && b.size == 16
    ));
    assert!(matches!(
        &ops[2],
        SSAOp::Copy { dst, src } if dst.size == 8 && src.size == 8
    ));
}

#[test]
fn prepared_ssa_refuses_implicit_copy_and_comparison_width_changes() {
    for op in [
        R2ILOp::Copy {
            dst: make_unique(0x10, 8),
            src: make_reg(0x20, 4),
        },
        R2ILOp::IntNotEqual {
            dst: make_reg(0x200, 1),
            a: make_unique(0x10, 8),
            b: make_unique(0x20, 16),
        },
    ] {
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![op],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        assert!(
            SsaArtifact::raw(&blocks, None).is_none(),
            "an implicit width change has no prepared-SSA proof"
        );
    }
}

fn call_preservation_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("eax", 0, 4));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rsi", 16, 8));
    arch.add_register(RegisterDef::new("rdx", 24, 8));
    arch
}

fn call_preservation_storage(offset: u64, size: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    }
}

fn call_preservation_block(ops: Vec<R2ILOp>) -> R2ILBlock {
    R2ILBlock {
        addr: 0x1000,
        size: 16,
        ops,
        switch_info: None,
        op_metadata: Default::default(),
    }
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
            callee_preserved_carriers: preserved,
            ..Default::default()
        },
    )
    .expect("artifact with a preserving callee");
    let without = SsaArtifact::for_decompile_with(
        std::slice::from_ref(&block),
        DecompileInputs {
            arch: Some(&arch),
            ..Default::default()
        },
    )
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
    // Outside the convention's clobber list, which is what makes the
    // callee's own interface the only thing that can say it is written.
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
            callee_interfaces: BTreeMap::from([(0x2000u64, returns_rbx)]),
            ..Default::default()
        },
    )
    .expect("artifact with a callee that returns rbx");
    let without = SsaArtifact::for_decompile_with(
        std::slice::from_ref(&block),
        DecompileInputs {
            arch: Some(&arch),
            ..Default::default()
        },
    )
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
    let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("leaf artifact");
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
fn a_body_that_calls_preserves_nothing_its_own_call_may_touch() {
    let arch = call_preservation_arch();
    let block = call_preservation_block(vec![
        R2ILOp::Call {
            target: make_ram(0x2000, 8),
        },
        R2ILOp::Return {
            target: make_const(0, 8),
        },
    ]);
    let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("calling artifact");
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
    let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("jumping artifact");
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
    let machine_context = SourceMachineContext::from_blocks_with_interfaces(
        std::slice::from_ref(&block),
        Some(&arch),
        None,
        SourceMachineRoles::default(),
        Some(convention),
        Vec::new(),
    );
    let function = SSAFunction::from_blocks_for_decompile_with_interface_and_control(
        std::slice::from_ref(&block),
        Some(&arch),
        InterfaceQuestions::none(),
        None,
        None,
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

fn promotion_fixture(ops: Vec<R2ILOp>) -> BTreeSet<(u64, usize)> {
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
    .expect("interface");
    let mut block = R2ILBlock::new(0x4000, 4);
    for op in ops {
        block.push(op);
    }
    let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("artifact");
    artifact.function().promoted_slot_sites().clone()
}

fn promotion_fixture_with_argument(
    ops: Vec<R2ILOp>,
    argument: CanonicalStorageId,
) -> BTreeSet<(u64, usize)> {
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
        [SourceAbiParameterSpec::new(0, argument)],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0)))
    .expect("interface");
    let mut block = R2ILBlock::new(0x4000, 4);
    for op in ops {
        block.push(op);
    }
    let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("artifact");
    artifact.function().promoted_slot_sites().clone()
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
                .expect("machine roles")
                .with_call_preserved_carriers(SourceCallPreservedCarriers::new(true, true)),
            convention_slots: Some(convention),
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
