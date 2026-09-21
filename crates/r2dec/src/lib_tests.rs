use super::*;
use r2il::{
    ArchSpec, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
    RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
};
use r2types::{FunctionParamSpec, FunctionSignatureSpec};
use std::collections::BTreeMap;

fn prepared_from_ops(ops: Vec<R2ILOp>, arch: &ArchSpec) -> r2ssa::SsaArtifact {
    let mut block = R2ILBlock::new(0x1000, 4);
    for op in ops {
        block.push(op);
    }
    prepared_from_blocks(&[block], arch)
}

fn prepared_from_blocks(blocks: &[R2ILBlock], arch: &ArchSpec) -> r2ssa::SsaArtifact {
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"r2dec-source-owned-fixture".to_vec(),
        "sysv64",
        std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
        r2ssa::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
    .expect("exact test source interface");
    r2ssa::SsaArtifact::for_decompile_with_interface(blocks, Some(arch), interface)
        .expect("prepared SSA should build")
        .with_name("stable_demo")
}

fn source_owned_type_analysis(
    prepared: impl Into<Arc<r2ssa::SsaArtifact>>,
) -> r2types::TypeAnalysis {
    let prepared = prepared.into();
    let request = r2types::TypeAnalysisRequest::new(
        Arc::clone(&prepared),
        r2types::ParsedExternalContext::default(),
    )
    .expect("test source assumptions");
    r2types::build_source_owned_type_analysis(request).expect("source-owned test analysis")
}

fn source_owned_decompiler_input(
    prepared: impl Into<Arc<r2ssa::SsaArtifact>>,
    route: (r2types::DecompileRouteKind, &'static str, Option<String>),
) -> DecompilerInput {
    let (kind, reason, fallback_comment) = route;
    let source_owned_facts = source_owned_type_analysis(prepared)
        .finalize_for_decompile(r2types::DecompileFinalization {
            kind,
            reason: reason.to_string(),
            fallback_comment,
        })
        .expect("compatible source-owned decompile finalization");
    DecompilerInput::new(source_owned_facts)
}

/// A comparison written directly into the logical low byte of the ABI
/// result carrier, rendered through the complete source-owned pipeline.
#[test]
fn a_constant_that_names_a_string_or_an_object_is_that_name() {
    let strings = BTreeMap::from([(0x2000, "usage: %s\n".to_string())]);
    let symbols = BTreeMap::from([(0x7000, "obj.progName".to_string())]);
    let object_types = r2types::ProgramDataObjectTypeFacts::default();
    let mut named = std::collections::BTreeMap::new();

    let (text, ty) = name_of_constant_address(
        &CExpr::UIntLit(0x2000),
        &strings,
        &symbols,
        &object_types,
        &mut named,
        true,
    )
    .expect("the string table answers for the address");
    assert_eq!(text, CExpr::StringLit("usage: %s\n".to_string()));
    assert_eq!(ty, CType::ptr(plain_char_type()));
    assert!(named.is_empty(), "a string literal declares nothing");

    // Through the conversions above it: the value is what the literal
    // denotes, whatever was spelled around it while it was a number.
    let (object, ty) = name_of_constant_address(
        &CExpr::cast(CType::u64(), CExpr::UIntLit(0x7000)),
        &strings,
        &symbols,
        &object_types,
        &mut named,
        true,
    )
    .expect("the symbol table answers for the address");
    assert_eq!(
        object,
        CExpr::addr_of(CExpr::DataObject {
            address: 0x7000,
            name: "progName".to_string(),
        })
    );
    // An object with no recovered type is a run of bytes, so its address
    // is a pointer to an array of `char` rather than a `char *`.
    assert_eq!(
        ty,
        CType::ptr(CType::Array(Box::new(plain_char_type()), None))
    );
    assert_eq!(named.len(), 1, "spelling the name declares the object");

    // A number nothing names stays a number.
    assert!(
        name_of_constant_address(
            &CExpr::UIntLit(0x20),
            &strings,
            &symbols,
            &object_types,
            &mut named,
            true,
        )
        .is_none()
    );
}

#[test]
fn a_logical_low_byte_return_renders() {
    let mut arch = test_arch_for_decompile();
    arch.add_register(RegisterDef::sub("AL", 0, 1, "RAX"));
    arch.register_projections.push(RegisterProjection {
        written: RegisterStorage { offset: 0, size: 1 },
        disposition: RegisterProjectionDisposition::Bound {
            carrier: RegisterStorage { offset: 0, size: 8 },
            slice: RegisterBitSlice {
                lsb_bit_offset: 0,
                size_bits: 8,
            },
        },
    });
    arch.register_projections
        .sort_by_key(|projection| projection.written);

    let storage = |offset, size| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size,
    };
    let logical_u64 = r2ssa::SourceLogicalValue::new(
        0,
        r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
    );
    let logical_u8 = r2ssa::SourceLogicalValue::new(
        1,
        r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::LowBits, 0, 8),
    );
    let type_graph = r2ssa::SourceTypeGraph::new(
        [
            r2ssa::SourceType::new(0, r2ssa::SourceTypeKind::UnsignedInteger, 64, 64),
            r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::UnsignedInteger, 8, 8),
        ],
        [],
    )
    .expect("exact boolean-return type graph");
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"logical-low-byte-return".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10, 8))],
        r2ssa::SourceFunctionReturn::Register {
            storage: storage(0, 8),
        },
        [],
        [Some(logical_u64)],
        Some(logical_u8),
        Some(type_graph),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x30, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28, 8)))
    .expect("exact boolean-return interface");

    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::IntLess {
        dst: Varnode::register(0, 1),
        a: Varnode::constant(7, 8),
        b: Varnode::register(0x10, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let prepared =
        r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("prepared boolean return")
            .with_name("shape_bool_probe");
    let boundary = prepared
        .facts()
        .boundaries
        .returns
        .values()
        .next()
        .expect("boolean return boundary");
    assert!(boundary.complete);
    let [boundary_value] = boundary.values.as_slice() else {
        panic!("logical low-byte return must carry one value")
    };
    // The byte is inserted into `RAX`; the boundary carries that root and
    // the certificate names the inserted lane at the declared width.
    assert!(
        prepared
            .graph()
            .value(boundary_value.value)
            .is_some_and(|value| {
                value.var.size == 8 && value.canonical_storage == Some(storage(0, 8))
            })
    );
    let (block_addr, op_index) = prepared
        .graph()
        .op_site_for_inst(boundary.at)
        .expect("return op site");
    let certificate = prepared
        .return_certificate_for_op(block_addr, op_index)
        .expect("logical low-byte certificate");
    assert_eq!(certificate.width, 1);
    assert!(
        prepared
            .graph()
            .value(certificate.value)
            .is_some_and(|value| value.var.size == 1),
        "the certificate names the inserted byte"
    );

    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "logical low-byte return route",
            None,
        ),
    );
    let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
    assert!(
        !output.contains("fallback") && !output.contains("native rendering refused"),
        "an exact logical low-byte result must render: {output}"
    );
    assert!(output.contains("uint8_t shape_bool_probe("), "{output}");
    assert!(
        output.contains("return ") && output.contains(" < "),
        "{output}"
    );
}

/// A call whose stack pointer the convention restores, rendered end to end.
#[test]
fn a_restored_stack_pointer_renders() {
    let arch = test_arch_for_decompile();
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let rsp = Varnode::register(0x28, 8);
    let rip = Varnode::register(0x30, 8);

    // One arm calls and one does not, so their restored stack pointers
    // meet in a phi that is also the same machine object.
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(R2ILOp::IntNotEqual {
        dst: Varnode::unique(0x80, 1),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::constant(0x1008, 8),
        cond: Varnode::unique(0x80, 1),
    });
    let mut no_call = R2ILBlock::new(0x1004, 4);
    no_call.push(R2ILOp::Branch {
        target: Varnode::constant(0x1010, 8),
    });

    let mut call_ops = vec![R2ILOp::IntSub {
        dst: rsp.clone(),
        a: rsp.clone(),
        b: Varnode::constant(8, 8),
    }];
    call_ops.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: rsp.clone(),
        val: Varnode::constant(0x100d, 8),
    });
    call_ops.push(R2ILOp::Call {
        target: Varnode::constant(0x2000, 8),
    });
    let mut call_meta = std::collections::BTreeMap::new();
    for i in 0..call_ops.len() {
        call_meta.insert(
            i,
            r2il::OpMetadata {
                instruction_addr: Some(0x1008),
                ..Default::default()
            },
        );
    }
    call_ops.push(R2ILOp::Branch {
        target: Varnode::constant(0x1010, 8),
    });
    let called = R2ILBlock {
        addr: 0x1008,
        size: 8,
        ops: call_ops,
        switch_info: None,
        op_metadata: call_meta,
    };

    let mut exit_ops = vec![R2ILOp::Load {
        dst: rip.clone(),
        space: SpaceId::Ram,
        addr: rsp.clone(),
    }];
    exit_ops.push(R2ILOp::IntAdd {
        dst: rsp.clone(),
        a: rsp,
        b: Varnode::constant(8, 8),
    });
    exit_ops.push(R2ILOp::Return { target: rip });
    let mut exit_meta = std::collections::BTreeMap::new();
    for i in 0..exit_ops.len() {
        exit_meta.insert(
            i,
            r2il::OpMetadata {
                instruction_addr: Some(0x1010),
                ..Default::default()
            },
        );
    }
    let exit = R2ILBlock {
        addr: 0x1010,
        size: 4,
        ops: exit_ops,
        switch_info: None,
        op_metadata: exit_meta,
    };
    let blocks = [entry, no_call, called, exit];

    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"restore-fixture".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
        r2ssa::SourceFunctionReturn::Void,
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|i| i.with_return_address_storage(storage(0x30)))
    .and_then(|i| i.with_stack_pointer_storage(storage(0x28)))
    .expect("interface")
    .with_preserved_call_carriers(true, true);
    let prepared =
        r2ssa::SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
            .expect("prepared")
            .with_name("restore_demo");
    let restores = prepared
        .function()
        .get_block(0x1008)
        .expect("call arm")
        .ops
        .iter()
        .filter(|op| matches!(op, r2ssa::SSAOp::CallRestore { .. }))
        .count();
    assert_eq!(restores, 1, "the call moved the carrier, so it is restored");
    assert!(
        prepared
            .function()
            .get_block(0x1010)
            .expect("join")
            .phis
            .iter()
            .any(|phi| phi.canonical_storage == Some(storage(0x28))),
        "the called and uncalled paths must merge their stack carriers"
    );
    let input = source_owned_decompiler_input(
        prepared,
        (r2types::DecompileRouteKind::Standard, "restore route", None),
    );
    let decompiler = Decompiler::new(DecompilerConfig::x86_64());
    let output = decompiler.decompile_input(&input);
    // The restore performs nothing and says so: its two sides are one
    // object, licensed by the convention, so both its read and its write
    // are accounted as a coalesced copy rather than left for the seal to
    // find. Before that licence existed this refused outright, first for
    // an unaccounted read of the entry carrier and then for a write with
    // no rendered occurrence.
    assert!(
        !output.contains("native render refusal"),
        "a restored carrier must not refuse the function: {output}"
    );
    // The count is written only when it is not zero, so its absence is
    // the assertion. It used to be read off a residual line that existed
    // only because the incomplete call boundary refused everything
    // reaching it; now the call is a gap and nothing else is in doubt.
    assert!(
        !output.contains("unaccounted"),
        "the restore accounts for both of its sides: {output}"
    );
}

/// A restore whose certified output is dead still has no C occurrence.
#[test]
fn an_unused_restored_stack_pointer_renders() {
    let arch = test_arch_for_decompile();
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let rsp = Varnode::register(0x28, 8);
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(R2ILOp::IntNotEqual {
        dst: Varnode::unique(0x80, 1),
        a: Varnode::register(0x10, 8),
        b: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::constant(0x1008, 8),
        cond: Varnode::unique(0x80, 1),
    });
    let mut no_call = R2ILBlock::new(0x1004, 4);
    no_call.push(R2ILOp::Branch {
        target: Varnode::constant(0x1010, 8),
    });
    let mut called = R2ILBlock::new(0x1008, 8);
    called.push(R2ILOp::IntSub {
        dst: rsp.clone(),
        a: rsp.clone(),
        b: Varnode::constant(8, 8),
    });
    called.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: rsp,
        val: Varnode::constant(0x100d, 8),
    });
    called.push(R2ILOp::Call {
        target: Varnode::constant(0x2000, 8),
    });
    for i in 0..called.ops.len() {
        called.op_metadata.insert(
            i,
            r2il::OpMetadata {
                instruction_addr: Some(0x1008),
                ..Default::default()
            },
        );
    }
    called.push(R2ILOp::Branch {
        target: Varnode::constant(0x1010, 8),
    });
    let mut exit = R2ILBlock::new(0x1010, 4);
    exit.push(R2ILOp::Breakpoint);
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"unused-restore-fixture".to_vec(),
        "sysv64",
        std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
        r2ssa::SourceFunctionReturn::Void,
        std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
    )
    .and_then(|i| i.with_return_address_storage(storage(0x30)))
    .and_then(|i| i.with_stack_pointer_storage(storage(0x28)))
    .expect("interface")
    .with_preserved_call_carriers(true, true);
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[entry, no_call, called, exit],
        Some(&arch),
        interface,
    )
    .expect("prepared")
    .with_name("unused_restore_demo");
    let restore_outputs = prepared
        .graph()
        .insts
        .iter()
        .filter(|inst| {
            matches!(
                inst.payload,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::CallRestore { .. })
            )
        })
        .filter_map(|inst| inst.output)
        .collect::<Vec<_>>();
    assert_eq!(restore_outputs.len(), 1, "one stack carrier is restored");
    let structural_unused = prepared
        .obligations()
        .structural_unused_values(
            prepared.graph(),
            prepared.unobserved_merges().unobserved_uses(),
        )
        .expect("complete structural-value inventory");
    assert!(
        restore_outputs
            .iter()
            .all(|value| structural_unused.contains(value)),
        "the regression requires an unused restore output"
    );

    let input = source_owned_decompiler_input(
        prepared,
        (r2types::DecompileRouteKind::Standard, "restore route", None),
    );
    let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
    assert!(
        !output.contains("native render refusal"),
        "an unused restored carrier must not refuse the function: {output}"
    );
    assert!(
        !output.contains("unaccounted"),
        "the structural elision accounts for the restore operand: {output}"
    );
}

fn test_arch_for_decompile() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    let registers = [
        (
            "RAX",
            RegisterStorage {
                offset: 0x00,
                size: 8,
            },
        ),
        (
            "RDI",
            RegisterStorage {
                offset: 0x10,
                size: 8,
            },
        ),
        (
            "RSI",
            RegisterStorage {
                offset: 0x18,
                size: 8,
            },
        ),
        (
            "RBP",
            RegisterStorage {
                offset: 0x20,
                size: 8,
            },
        ),
        (
            "RSP",
            RegisterStorage {
                offset: 0x28,
                size: 8,
            },
        ),
        (
            "RIP",
            RegisterStorage {
                offset: 0x30,
                size: 8,
            },
        ),
    ];
    for (name, storage) in registers {
        arch.add_register(RegisterDef::new(name, storage.offset, storage.size));
        arch.register_projections.push(RegisterProjection {
            written: storage,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: storage,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: u64::from(storage.size) * 8,
                },
            },
        });
    }
    arch
}

fn signature_spec(
    ret_type: Option<CType>,
    params: Vec<(&str, Option<CType>)>,
) -> FunctionSignatureSpec {
    FunctionSignatureSpec {
        ret_type: ret_type.as_ref().cloned(),
        params: params
            .into_iter()
            .map(|(name, ty)| FunctionParamSpec {
                name: name.to_string(),
                ty: ty.as_ref().cloned(),
            })
            .collect(),
    }
}

#[test]
fn test_decompiler_config_default() {
    let config = DecompilerConfig::default();
    assert_eq!(config.ptr_size, 64);
    assert_eq!(config.sp_name, "rsp");
    assert_eq!(config.fp_name, "rbp");
}

#[test]
fn test_decompiler_config_x86() {
    let config = DecompilerConfig::x86();
    assert_eq!(config.ptr_size, 32);
    assert_eq!(config.sp_name, "esp");
    assert_eq!(config.fp_name, "ebp");
}

#[test]
fn test_decompiler_config_arm() {
    let config = DecompilerConfig::arm();
    assert_eq!(config.ptr_size, 32);
    assert_eq!(config.sp_name, "sp");
    assert_eq!(config.fp_name, "fp");
}

#[test]
fn test_decompiler_config_aarch64() {
    let config = DecompilerConfig::aarch64();
    assert_eq!(config.ptr_size, 64);
    assert_eq!(config.sp_name, "sp");
    assert_eq!(config.fp_name, "x29");
    assert_eq!(config.arg_regs[0], "x0");
    assert_eq!(config.ret_regs[0], "x0");
    assert!(config.caller_saved_regs.contains("x17"));
}

#[test]
fn test_decompiler_config_riscv32() {
    let config = DecompilerConfig::riscv32();
    assert_eq!(config.ptr_size, 32);
    assert_eq!(config.sp_name, "sp");
    assert_eq!(config.fp_name, "s0");
}

#[test]
fn test_decompiler_config_riscv64() {
    let config = DecompilerConfig::riscv64();
    assert_eq!(config.ptr_size, 64);
    assert_eq!(config.sp_name, "sp");
    assert_eq!(config.fp_name, "s0");
}

#[test]
fn a_named_constant_keeps_every_observation_it_collapsed() {
    let mut observations = crate::ast::RenderObservationOwner::new();
    let (leaf_id, leaf) = observations
        .observe_expr(CExpr::UIntLit(0x1004))
        .expect("literal observation");
    let (inner_id, inner) = observations
        .observe_expr(CExpr::cast(CType::u32(), leaf))
        .expect("inner cast observation");
    let (root_id, mut expr) = observations
        .observe_expr(CExpr::cast(CType::u64(), inner))
        .expect("root observation");
    let strings = BTreeMap::from([(0x1004, "text".to_string())]);

    let no_symbols = BTreeMap::new();
    let no_object_types = r2types::ProgramDataObjectTypeFacts::default();
    let mut unused_objects = std::collections::BTreeMap::new();
    let (named, _) = name_of_constant_address(
        &expr,
        &strings,
        &no_symbols,
        &no_object_types,
        &mut unused_objects,
        true,
    )
    .expect("the string table answers for the address");
    expr = named;
    let mut function = CFunction::new(
        "folded",
        CType::Pointer(Box::new(CType::Int {
            bits: 8,
            signedness: r2types::Signedness::Signed,
        })),
    )
    .with_body(vec![CStmt::Return(Some(expr))]);
    let reachable =
        crate::ast::strip_render_observations(&mut function, observations.expected_count())
            .expect("constant folding preserves a valid marker domain");

    // The one rendered node stands for everything the substitution
    // collapsed, so it owns every occurrence those nodes owned. Keeping
    // only the root silently discarded the inner occurrences, and an
    // obligation whose only rendered occurrence sat on a collapsed cast
    // was then scored refused for an effect the program does render.
    assert!(reachable.contains(root_id));
    assert!(reachable.contains(inner_id));
    assert!(reachable.contains(leaf_id));
    // The conversions the address was wrapped in while it was a number
    // are gone with it: what the boundary requires of the string is the
    // conversion the caller then applies, and it is decided from the
    // typed boundaries rather than from what stood here.
    assert_eq!(
        function.body,
        vec![CStmt::Return(Some(CExpr::StringLit("text".to_string())))]
    );
}

#[test]
fn radare_typed_global_renders_as_its_type_and_direct_value() {
    let strings = BTreeMap::new();
    let symbols = BTreeMap::from([(0x7000, "obj.global_counter".to_string())]);
    let object_types = r2types::ProgramDataObjectTypeFacts::from_radare2(
        [(0x7000, Some("int32_t"))],
        64,
        &r2types::ExternalTypeDb::default(),
    );
    let mut used = std::collections::BTreeMap::new();
    // What the fold spells for `*(uint32_t *)0x7000`: the constant is the
    // object, and the load's own requirement converts it.
    let (address, address_type) = name_of_constant_address(
        &CExpr::UIntLit(0x7000),
        &strings,
        &symbols,
        &object_types,
        &mut used,
        true,
    )
    .expect("the symbol table answers for the address");
    let mut function = CFunction::new("read_counter", CType::i32()).with_body(vec![CStmt::Return(
        Some(CExpr::deref(crate::fold::op_lower::convert::convert(
            address,
            &r2rewrite::CValue::Typed(address_type),
            &CType::ptr(CType::u32()),
            64,
        ))),
    )]);
    let used = std::cell::RefCell::new(used);
    for stmt in &mut function.body {
        simplify_data_object_loads_in_stmt(stmt, 64, &used);
    }
    function.extern_objects = used.into_inner().into_values().collect();
    note_unproven_constructs(&mut function, None, 0, 0, 0, 0);
    let ready = crate::codegen::prepare_function_for_emission(function);
    let rendered = crate::codegen::CodeGenerator::new(Default::default()).generate_function(&ready);

    assert!(
        rendered.contains("extern int32_t global_counter;"),
        "{rendered}"
    );
    assert!(rendered.contains("return global_counter;"), "{rendered}");
    assert!(
        rendered.contains("1 data object type supplied by the source"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("extern char global_counter[]"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("*(uint32_t*)&global_counter"),
        "{rendered}"
    );
}

#[test]
fn unplaceable_global_type_keeps_the_honest_byte_declaration() {
    let symbols = BTreeMap::from([(0x7000, "obj.global_counter".to_string())]);
    let object_types = r2types::ProgramDataObjectTypeFacts::from_radare2(
        [(0x7000, Some("looks_specific_t"))],
        64,
        &r2types::ExternalTypeDb::default(),
    );
    let mut used = std::collections::BTreeMap::new();
    let (address, address_type) = name_of_constant_address(
        &CExpr::UIntLit(0x7000),
        &BTreeMap::new(),
        &symbols,
        &object_types,
        &mut used,
        true,
    )
    .expect("the symbol table answers for the address");
    let mut function = CFunction::new("read_counter", CType::u32()).with_body(vec![CStmt::Return(
        Some(crate::fold::op_lower::convert::convert(
            address,
            &r2rewrite::CValue::Typed(address_type),
            &CType::u32(),
            64,
        )),
    )]);
    let used = std::cell::RefCell::new(used);
    for stmt in &mut function.body {
        simplify_data_object_loads_in_stmt(stmt, 64, &used);
    }
    function.extern_objects = used.into_inner().into_values().collect();
    note_unproven_constructs(&mut function, None, 0, 0, 0, 0);
    let ready = crate::codegen::prepare_function_for_emission(function);
    let rendered = crate::codegen::CodeGenerator::new(Default::default()).generate_function(&ready);

    assert!(
        rendered.contains("extern char global_counter[];"),
        "{rendered}"
    );
    assert!(
        rendered.contains("1 data object type refused"),
        "{rendered}"
    );
    assert!(!rendered.contains("looks_specific_t"), "{rendered}");
}

#[test]
fn prepended_comment_keeps_only_the_exact_original_statement_observation() {
    let mut observations = crate::ast::RenderObservationOwner::new();
    let (stmt_id, stmt) = observations
        .observe_stmt(CStmt::Return(Some(CExpr::IntLit(7))))
        .expect("return observation");
    let commented = Decompiler::prepend_comment(stmt, "summary".to_string());
    assert_eq!(
        commented,
        CStmt::Block(vec![
            CStmt::comment("summary"),
            CStmt::observed(stmt_id, CStmt::Return(Some(CExpr::IntLit(7)))),
        ])
    );

    let mut function = CFunction::new(
        "commented",
        CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        },
    )
    .with_body(vec![commented]);
    let reachable =
        crate::ast::strip_render_observations(&mut function, observations.expected_count())
            .expect("comment insertion preserves a valid marker domain");
    assert!(reachable.contains(stmt_id));
}

#[test]
fn prepended_comment_does_not_move_a_split_block_observation() {
    let mut observations = crate::ast::RenderObservationOwner::new();
    let (child_id, child) = observations
        .observe_stmt(CStmt::Return(Some(CExpr::IntLit(1))))
        .expect("child observation");
    let (block_id, block) = observations
        .observe_stmt(CStmt::Block(vec![
            child,
            CStmt::Return(Some(CExpr::IntLit(2))),
        ]))
        .expect("block observation");
    let commented = Decompiler::prepend_comment(block, "summary".to_string());
    let mut function = CFunction::new(
        "commented_block",
        CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        },
    )
    .with_body(vec![commented]);

    let reachable =
        crate::ast::strip_render_observations(&mut function, observations.expected_count())
            .expect("comment insertion preserves a valid marker domain");
    assert!(reachable.contains(child_id));
    assert!(
        !reachable.contains(block_id),
        "a new comment sibling leaves no exact owner for the old block marker"
    );
    assert_eq!(
        function.body,
        vec![CStmt::Block(vec![
            CStmt::comment("summary"),
            CStmt::Return(Some(CExpr::IntLit(1))),
            CStmt::Return(Some(CExpr::IntLit(2))),
        ])]
    );
}

#[test]
fn split_block_observation_is_not_assigned_to_its_first_child() {
    let mut observations = crate::ast::RenderObservationOwner::new();
    let (first_id, first) = observations
        .observe_stmt(CStmt::Return(Some(CExpr::IntLit(1))))
        .expect("first statement observation");
    let (block_id, block) = observations
        .observe_stmt(CStmt::Block(vec![
            first,
            CStmt::Return(Some(CExpr::IntLit(2))),
        ]))
        .expect("block observation");
    let decompiler = Decompiler::new(DecompilerConfig::x86_64());
    let body = decompiler.stmt_to_vec(block);
    let mut function = CFunction::new(
        "split",
        CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        },
    )
    .with_body(body);

    let reachable =
        crate::ast::strip_render_observations(&mut function, observations.expected_count())
            .expect("block decomposition preserves a valid marker domain");
    assert!(reachable.contains(first_id));
    assert!(
        !reachable.contains(block_id),
        "a multi-statement block has no exact first-child projection"
    );
    assert_eq!(
        function.body,
        vec![
            CStmt::Return(Some(CExpr::IntLit(1))),
            CStmt::Return(Some(CExpr::IntLit(2))),
        ]
    );
}

/// A route the engine chose describes the function; it does not answer for
/// it. The rendering that used to stop here was two lines of prose counted
/// as a rendered function everywhere downstream.
#[test]
fn an_engine_chosen_fallback_route_does_not_pre_empt_native_lowering() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![
            R2ILOp::Load {
                dst: Varnode::unique(0x10, 4),
                space: SpaceId::Ram,
                addr: Varnode::register(0x10, 8),
            },
            R2ILOp::Return {
                target: Varnode::unique(0x10, 4),
            },
        ],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::FallbackComment,
            "engine refusal: tested route",
            Some("/* engine refusal: tested route */".to_string()),
        ),
    );

    let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);

    assert!(
        output.starts_with("/* unknown */ stable_demo()"),
        "native lowering owns the rendering: {output}"
    );
    assert!(
        !output.contains("skipped decompilation"),
        "the route must not skip the native attempt: {output}"
    );
    assert!(
        !output.contains("/* engine refusal: tested route */"),
        "stored fallback payload must not be replayed verbatim"
    );
}

/// The route stored on the facts is the same advice, and it is refused the
/// same authority: only the native certificates decide what renders.
#[test]
fn a_facts_owned_fallback_route_does_not_pre_empt_native_lowering() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::FallbackComment,
            "facts-owned route",
            Some("/* facts-owned refusal */".to_string()),
        ),
    );

    let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);

    assert!(
        output.starts_with("/* unknown */ stable_demo()"),
        "native lowering owns the rendering: {output}"
    );
    assert!(
        !output.contains("skipped decompilation"),
        "the route must not skip the native attempt: {output}"
    );
    assert!(
        !output.contains("/* facts-owned refusal */"),
        "stored fallback payload must not replace what the machine proves"
    );
}

#[test]
fn context_projection_preserves_the_exact_sealed_report() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "sealed projection",
            None,
        ),
    );

    let projected = input.context_projection();

    assert_eq!(projected.type_facts(), input.function_facts().type_facts());
    assert_eq!(
        projected.function_facts.decompile_route(),
        input.function_facts().decompile_route()
    );
}

#[test]
fn foreign_interproc_summary_never_reaches_decompiler_input() {
    let arch = test_arch_for_decompile();
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"rebuilt-identical-owner".to_vec(),
        "sysv64",
        [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
        r2ssa::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
    .expect("exact source interface");
    let requested = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(
            std::slice::from_ref(&block),
            Some(&arch),
            interface.clone(),
        )
        .expect("requested prepared SSA"),
    );
    let foreign = Arc::new(
        r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("foreign prepared SSA"),
    );
    let summary = r2ssa::solve_prepared_interproc_summary_set(
        Arc::clone(&foreign),
        &[r2ssa::PreparedInterprocFunctionInput {
            id: r2ssa::InterprocFunctionId(foreign.entry),
            name: None,
            prepared: &foreign,
        }],
    )
    .expect("foreign prepared summary");
    let request =
        r2types::TypeAnalysisRequest::new(requested, r2types::ParsedExternalContext::default())
            .expect("source-owned request");

    assert_eq!(
        request
            .with_interproc_summary(summary)
            .expect_err("foreign interprocedural evidence must be rejected before r2dec"),
        r2types::TypeAnalysisError::ForeignInterprocSummary
    );
}

/// A route kind is a label on advice, and advice does not have to be
/// backed by a symbolic artifact to be recorded. The pipeline that used to
/// require one is gone, so the finalization accepts every kind and the
/// native certificates decide what renders.
#[test]
fn decompile_finalization_accepts_every_route_kind() {
    let arch = test_arch_for_decompile();
    for route in [
        (
            r2types::DecompileRouteKind::StructuredWorker,
            "engine-selected structured summary route",
        ),
        (
            r2types::DecompileRouteKind::LinearWorker,
            "engine-selected linear summary route",
        ),
        (
            r2types::DecompileRouteKind::SummaryIslands,
            "engine-selected island summary route",
        ),
    ] {
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let finalized = source_owned_type_analysis(prepared)
            .finalize_for_decompile(r2types::DecompileFinalization {
                kind: route.0,
                reason: route.1.to_string(),
                fallback_comment: None,
            })
            .expect("a route kind is advice and is always recordable");

        assert_eq!(
            finalized.report().decompile_route().map(|facts| facts.kind),
            Some(route.0),
            "the route is recorded as given for {:?}",
            route.0,
        );
    }
}

#[test]
fn raw_fallback_comments_regenerate_and_sanitize_hostile_text() {
    let assert_one_safe_comment = |output: &str| {
        assert!(
            output.starts_with("/* "),
            "expected one C comment: {output:?}"
        );
        assert!(
            output.ends_with(" */"),
            "expected closed C comment: {output:?}"
        );
        assert_eq!(
            output.matches("*/").count(),
            1,
            "comment payload must not close the comment early: {output:?}"
        );
        assert!(
            !output.contains('\r') && !output.contains('\n'),
            "comment payload must stay on one line: {output:?}"
        );
    };

    // The refusal comment is the one fallback text that still reaches a
    // reader, and it carries both a function name and a reason, so both
    // are what must not be able to close the comment early.
    assert_one_safe_comment(&artifact_guard_fallback_comment(
        "bad */\nint injected",
        "reason */\nreturn 7;",
    ));

    // A hostile name reaches the rendered declaration, not only a comment,
    // so the identifier it spells is what has to be safe. Native lowering
    // now renders this function, which is exactly when that matters.
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    )
    .with_name("bad */\nint injected");
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::FallbackComment,
            "reason */\nreturn 7;",
            Some("*/ payload must be ignored\nint payload; /*".to_string()),
        ),
    );

    let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
    assert!(
        output.contains("bad____int_injected()"),
        "a hostile source name must render as one C identifier: {output}"
    );
    assert!(
        !output.contains("*/\nint injected"),
        "the name must not close the type comment it follows: {output}"
    );
    assert!(
        !output.contains("payload must be ignored"),
        "stored fallback payload must not be replayed as raw output: {output}"
    );
    assert!(
        !output.contains("return 7;"),
        "a route reason must not be replayed as a statement: {output}"
    );
}

#[test]
fn a_fallback_route_residualizes_the_tree_to_comments() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::FallbackComment,
            "engine-selected fallback route",
            Some("/* engine-selected fallback route */".to_string()),
        ),
    );

    let audit =
        Decompiler::new(DecompilerConfig::x86_64()).decompile_input_with_binding_audit(&input);
    let built = audit.rendered().function();

    assert!(
        built
            .body
            .iter()
            .all(|stmt| matches!(stmt, CStmt::Comment(_))),
        "fallback route AST must be comment-only, got {:?}",
        built.body
    );
    assert!(
        !built
            .body
            .iter()
            .any(|stmt| matches!(stmt, CStmt::Return(_))),
        "fallback route AST must not contain executable returns: {:?}",
        built.body
    );
}

/// A malformed source return boundary is refused before the effect ledger
/// can classify any native C as surviving.
#[test]
fn malformed_return_boundary_refuses_before_effect_audit() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "standard route request",
            None,
        ),
    );

    let decompiler = Decompiler::new(DecompilerConfig::x86_64());
    let audited = decompiler.decompile_input_with_binding_audit(&input);
    assert_eq!(
        audited.render_refusal(),
        Some(
            DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                crate::MachineProjectionRefusalOrigin::op_lowering(),
            )
        )
    );
    assert_eq!(audited.effect_obligations(), EffectObligationAudit::NOT_RUN);
    assert!(!audited.output().contains("return"), "{}", audited.output());
}

#[test]
fn native_standard_path_builds_a_sound_non_consuming_binding_shadow() {
    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![
            R2ILOp::Copy {
                dst: Varnode::register(0, 8),
                src: Varnode::constant(0, 8),
            },
            R2ILOp::Return {
                target: Varnode::register(0x30, 8),
            },
        ],
        &arch,
    );
    let block = prepared.function().get_block(0x1000).expect("entry block");
    let copy_source = block
        .ops
        .iter()
        .find_map(|op| match op {
            SSAOp::Copy { src, .. } => Some(src),
            _ => None,
        })
        .expect("copy source");
    let copy_source_value = prepared
        .graph()
        .value_id_for_var(copy_source)
        .expect("copy source must retain exact ValueId");
    let return_op = block
        .ops
        .iter()
        .position(|op| matches!(op, SSAOp::Return { .. }))
        .expect("return op");
    let return_certificate = prepared
        .return_certificate_for_op(0x1000, return_op)
        .expect("scalar audit fixture must retain an exact return certificate");
    assert_eq!(return_certificate.block_addr, 0x1000);
    assert_eq!(return_certificate.op_index, return_op);
    let return_value = return_certificate.value;
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "binding shadow production path",
            None,
        ),
    );
    let plan = crate::binding_plan::BindingPlan::build_shadow(input.source_owned_facts())
        .expect("scalar audit fixture binding plan");
    // The return is the only reader of either value here, and a value the
    // return alone reads is spelled by its expression rather than given an
    // object whose single use is `return t;`.
    assert!(matches!(
        plan.disposition(return_value),
        Some(crate::binding_plan::ValueDisposition::Inline { .. })
    ));
    assert!(matches!(
        plan.disposition(copy_source_value),
        Some(crate::binding_plan::ValueDisposition::Inline { .. })
    ));
    assert_eq!(
        input
            .function_facts()
            .render()
            .and_then(|render| render.return_for_op(0x1000, return_op))
            .map(|fact| fact.value),
        Some(return_value)
    );
    let config = DecompilerConfig::x86_64();
    let public_decompiler = Decompiler::new(config.clone());
    let internal_decompiler =
        Decompiler::new(config.clone()).with_context(input.context_projection());
    let execution = r2ssa::SsaExecutionControl::default();
    let work = DecompileWorkControl::new(&execution, DecompileWorkPhase::Normalization);
    let built = internal_decompiler
        .build_function_internal_with_control(&input, work, &Default::default())
        .expect("native production build");

    let internal_output = CodeGenerator::new(config.codegen).generate_function(built.emission());
    let public_output = public_decompiler.decompile_input(&input);
    assert_eq!(internal_output, public_output);
    let audited = public_decompiler.decompile_input_with_binding_audit(&input);
    assert_eq!(audited.output(), public_output);
    let BindingShadowAuditOutcome::Complete {
        ledger,
        observations,
    } = audited.binding_shadow()
    else {
        panic!(
            "public native path did not expose its complete shadow audit: {:?}",
            audited.binding_shadow()
        );
    };
    assert!(ledger.equations_hold());
    assert!(ledger.passes_quality());
    assert!(observations.equations_hold());
    assert!(observations.passes_quality());
    let mut corrupted_public_ledger = ledger;
    corrupted_public_ledger.values.observed =
        corrupted_public_ledger.values.observed.saturating_sub(1);
    assert!(!corrupted_public_ledger.equations_hold());
    assert!(!corrupted_public_ledger.passes_quality());
}

#[test]
fn shuffled_block_schedule_keeps_spans_bindings_placement_and_bytes_identical() {
    fn exact_diamond_input(blocks: &[R2ILBlock]) -> (r2ssa::span::StorageSpans, DecompilerInput) {
        let arch = test_arch_for_decompile();
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let logical_u64 = r2ssa::SourceLogicalValue::new(
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
        .expect("exact diamond type graph");
        let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
            b"r2dec-shuffled-diamond".to_vec(),
            "sysv64",
            [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
            r2ssa::SourceFunctionReturn::Register {
                storage: storage(0),
            },
            [],
            [Some(logical_u64)],
            Some(logical_u64),
            Some(type_graph),
        )
        .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
        .expect("exact diamond interface");
        let prepared = Arc::new(
            r2ssa::SsaArtifact::for_decompile_with_interface(blocks, Some(&arch), interface)
                .expect("prepared shuffled diamond")
                .with_name("stable_diamond"),
        );
        let spans = prepared.storage_spans().clone();
        let signature = signature_spec(
            Some(CType::Int {
                bits: 64,
                signedness: r2types::Signedness::Unsigned,
            }),
            vec![(
                "condition",
                Some(CType::Int {
                    bits: 64,
                    signedness: r2types::Signedness::Unsigned,
                }),
            )],
        );
        let parsed_context = r2types::ParsedExternalContext {
            current_signature: Some(signature.clone()),
            merged_signature: Some(signature),
            ..r2types::ParsedExternalContext::default()
        };
        let request = r2types::TypeAnalysisRequest::new(prepared, parsed_context)
            .expect("source-owned shuffled diamond request");
        let source_owned_facts = r2types::build_source_owned_type_analysis(request)
            .expect("source-owned shuffled diamond analysis")
            .finalize_for_decompile(r2types::DecompileFinalization {
                kind: r2types::DecompileRouteKind::Standard,
                reason: "shuffled determinism proof".to_string(),
                fallback_comment: None,
            })
            .expect("source-owned shuffled diamond finalization");
        let input = DecompilerInput::new(source_owned_facts);
        (spans, input)
    }

    fn binding_signature(input: &DecompilerInput) -> (Vec<String>, Vec<String>) {
        let plan = crate::binding_plan::BindingPlan::build_shadow(input.source_owned_facts())
            .expect("sealed deterministic plan");
        let bindings = plan
            .bindings()
            .map(|(id, binding)| {
                format!(
                    "{}:{:?}:{:?}:{:?}",
                    id.index(),
                    binding.declaration_type(),
                    binding.presentation_name_hint(),
                    plan.binding_role(id)
                )
            })
            .collect();
        let dispositions = (0..input.prepared_ssa().graph().values.len())
            .map(|index| {
                let value = r2ssa::ValueId(index as u32);
                match plan
                    .disposition(value)
                    .expect("one disposition per dense value")
                {
                    crate::binding_plan::ValueDisposition::Bound { binding } => {
                        format!("bound:{}", binding.index())
                    }
                    crate::binding_plan::ValueDisposition::Inline { term, .. } => {
                        format!("inline:{}", term.index())
                    }
                    crate::binding_plan::ValueDisposition::Elided { reason, .. } => {
                        format!("elided:{reason:?}")
                    }
                    crate::binding_plan::ValueDisposition::Refused { reason } => {
                        format!("refused:{reason:?}")
                    }
                }
            })
            .collect();
        (bindings, dispositions)
    }

    let mut entry = R2ILBlock::new(0x1000, 0x10);
    entry.push(R2ILOp::CBranch {
        target: Varnode::constant(0x1020, 8),
        cond: Varnode::register(0x10, 8),
    });
    let mut false_arm = R2ILBlock::new(0x1010, 0x10);
    false_arm.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(1, 8),
    });
    false_arm.push(R2ILOp::Branch {
        target: Varnode::constant(0x1030, 8),
    });
    let mut true_arm = R2ILBlock::new(0x1020, 0x10);
    true_arm.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(2, 8),
    });
    true_arm.push(R2ILOp::Branch {
        target: Varnode::constant(0x1030, 8),
    });
    let mut merge = R2ILBlock::new(0x1030, 4);
    merge.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });

    let peers = [false_arm, true_arm, merge];
    let baseline_blocks = vec![
        entry.clone(),
        peers[0].clone(),
        peers[1].clone(),
        peers[2].clone(),
    ];
    let (baseline_spans, baseline_input) = exact_diamond_input(&baseline_blocks);
    let decompiler = Decompiler::new(DecompilerConfig::x86_64());
    let baseline = decompiler.decompile_input_with_binding_audit(&baseline_input);
    let baseline_binding_signature = binding_signature(&baseline_input);
    let baseline_values = baseline_input
        .prepared_ssa()
        .graph()
        .values
        .iter()
        .map(|value| {
            format!(
                "{:?}:{}:{:?}",
                value.id,
                value.var.display_name(),
                value.canonical_storage
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        baseline.placement_audit(),
        PlacementAudit::Applied,
        "baseline must reach placement: output={} refusal={:?} binding={:?} effects={:?} signature={baseline_binding_signature:?} values={baseline_values:?} type_facts={:?}",
        baseline.output(),
        baseline.render_refusal(),
        baseline.binding_shadow(),
        baseline.effect_obligations(),
        baseline_input.function_facts().type_facts(),
    );

    // Exhaust the complete schedule domain of the non-entry blocks. Entry
    // identity is semantic input; node/edge insertion order is not.
    for schedule in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut shuffled_blocks = vec![entry.clone()];
        shuffled_blocks.extend(schedule.map(|index| peers[index].clone()));
        let (shuffled_spans, shuffled_input) = exact_diamond_input(&shuffled_blocks);
        let shuffled = decompiler.decompile_input_with_binding_audit(&shuffled_input);

        assert_eq!(baseline_spans, shuffled_spans, "schedule={schedule:?}");
        assert_eq!(
            baseline_binding_signature,
            binding_signature(&shuffled_input),
            "schedule={schedule:?}"
        );
        assert_eq!(
            baseline.placement_audit(),
            shuffled.placement_audit(),
            "schedule={schedule:?}"
        );
        assert_eq!(
            baseline.binding_shadow(),
            shuffled.binding_shadow(),
            "schedule={schedule:?}"
        );
        assert_eq!(
            baseline.effect_obligations(),
            shuffled.effect_obligations(),
            "schedule={schedule:?}"
        );
        assert_eq!(
            baseline.render_refusal(),
            shuffled.render_refusal(),
            "schedule={schedule:?}"
        );
        assert_eq!(
            baseline.output().as_bytes(),
            shuffled.output().as_bytes(),
            "schedule={schedule:?}"
        );
    }
}

#[test]
fn binding_shadow_adds_no_post_render_work_control_decision() {
    struct CountingControl {
        polls: std::cell::Cell<usize>,
        stop_at: Option<usize>,
    }

    impl r2ssa::SsaWorkControl for CountingControl {
        fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
            let poll = self.polls.get() + 1;
            self.polls.set(poll);
            if self.stop_at == Some(poll) {
                Err(r2ssa::SsaExecutionStopReason::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "binding shadow work-control path",
            None,
        ),
    );
    let decompiler = Decompiler::new(DecompilerConfig::x86_64());
    let baseline = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: None,
    };
    decompiler
        .decompile_input_with_binding_audit_and_control(&input, &baseline)
        .expect("unbounded audit");
    let final_production_poll = baseline.polls.get();

    let stop_at_final = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: Some(final_production_poll),
    };
    let stop = decompiler
        .decompile_input_with_binding_audit_and_control(&input, &stop_at_final)
        .expect_err("the final production poll must remain observable");
    assert_eq!(stop.phase(), DecompileWorkPhase::Rendering);
    assert_eq!(stop.reason(), r2ssa::SsaExecutionStopReason::Cancelled);

    let no_later_poll = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: Some(final_production_poll + 1),
    };
    decompiler
        .decompile_input_with_binding_audit_and_control(&input, &no_later_poll)
        .expect("shadow capture and classification must not poll work control");
    assert_eq!(no_later_poll.polls.get(), final_production_poll);
}

#[test]
fn audited_partial_retains_the_same_product_without_extra_polls() {
    struct CountingControl {
        polls: std::cell::Cell<usize>,
        stop_at: Option<usize>,
    }

    impl r2ssa::SsaWorkControl for CountingControl {
        fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
            let poll = self.polls.get() + 1;
            self.polls.set(poll);
            if self.stop_at == Some(poll) {
                Err(r2ssa::SsaExecutionStopReason::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    let arch = test_arch_for_decompile();
    let prepared = prepared_from_ops(
        vec![R2ILOp::Return {
            target: Varnode::constant(0, 8),
        }],
        &arch,
    );
    let input = source_owned_decompiler_input(
        prepared,
        (
            r2types::DecompileRouteKind::Standard,
            "same-run audited partial",
            None,
        ),
    );
    let decompiler = Decompiler::new(DecompilerConfig::x86_64());

    let baseline_control = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: None,
    };
    let baseline = decompiler
        .decompile_input_keeping_partial_with_binding_audit(&input, &baseline_control)
        .expect("unbounded audited rendering");
    let final_poll = baseline_control.polls.get();
    // Writing the C is counted too, so the two rendering-phase decisions are
    // no longer the last two polls of the run: the one before generation is
    // the first poll the Rendering phase makes, and it is found by asking.
    let first_render_poll = (1..=final_poll)
        .find(|stop_at| {
            let probe = CountingControl {
                polls: std::cell::Cell::new(0),
                stop_at: Some(*stop_at),
            };
            decompiler
                .decompile_input_keeping_partial_with_binding_audit(&input, &probe)
                .err()
                .is_some_and(|(stop, _)| stop.phase() == DecompileWorkPhase::Rendering)
        })
        .expect("a successful rendering makes at least one rendering poll");

    for stop_at in [first_render_poll, final_poll] {
        let stopped_control = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: Some(stop_at),
        };
        let (stop, partial) = decompiler
            .decompile_input_keeping_partial_with_binding_audit(&input, &stopped_control)
            .expect_err("selected rendering poll must stop");
        assert_eq!(stop.phase(), DecompileWorkPhase::Rendering);
        assert_eq!(stop.reason(), r2ssa::SsaExecutionStopReason::Cancelled);
        assert_eq!(
            stopped_control.polls.get(),
            stop_at,
            "retaining output and audit must neither rebuild nor poll again"
        );
        assert_eq!(
            partial.as_ref(),
            Some(&baseline),
            "the partial must classify the exact retained product"
        );
    }

    let pre_product_control = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: Some(1),
    };
    let (stop, partial) = decompiler
        .decompile_input_keeping_partial_with_binding_audit(&input, &pre_product_control)
        .expect_err("initial preparation poll must stop");
    assert_eq!(stop.phase(), DecompileWorkPhase::Normalization);
    assert_eq!(partial, None);
    assert_eq!(pre_product_control.polls.get(), 1);

    let compatibility_control = CountingControl {
        polls: std::cell::Cell::new(0),
        stop_at: None,
    };
    let compatibility_output = decompiler
        .decompile_input_keeping_partial(&input, &compatibility_control)
        .expect("compatibility rendering");
    assert_eq!(compatibility_output, baseline.output());
    assert_eq!(
        compatibility_control.polls.get(),
        final_poll,
        "the string compatibility mapper must add no work-control decision"
    );
}

/// The marks the structurer leaves are counted wherever they sit, including
/// inside a loop or a switch arm, and the function says how many it carries.
#[test]
fn unproven_constructs_are_counted_through_nested_bodies() {
    let mut func = CFunction::new("partly_proven".to_string(), CType::Unknown);
    func.body = vec![
        CStmt::comment("r2dec residual: unresolved branch condition at 0x1000"),
        CStmt::While {
            cond: CExpr::IntLit(1),
            body: Box::new(CStmt::Block(vec![CStmt::comment(
                "r2dec residual: uncertified loop structure at 0x1010",
            )])),
        },
        CStmt::Return(Some(CExpr::IntLit(0))),
    ];
    assert_eq!(count_residual_markers(&func.body), 2);

    note_unproven_constructs(&mut func, None, 0, 0, 0, 0);
    let note = match func.body.first() {
        Some(CStmt::Comment(text)) => text.clone(),
        other => panic!("expected a leading proof note, got {other:?}"),
    };
    assert!(note.contains("r2dec proof:"), "{note}");
    assert!(note.contains("2 constructs are marked below"), "{note}");
    assert!(
        func.body
            .iter()
            .any(|stmt| matches!(stmt, CStmt::Return(_))),
        "the proven return survives beside the marks: {:?}",
        func.body
    );
}

/// An uncertified route says so even when the structurer marked nothing,
/// because "nothing was marked" is not the same claim as "everything was
/// proven". Without this the near-miss aggregate fixture rendered a bare
/// `return` with no indication the kernel never claimed it.
#[test]
fn a_rendering_says_so_even_with_nothing_marked() {
    let mut func = CFunction::new("unclaimed".to_string(), CType::Unknown);
    func.body = vec![CStmt::Return(Some(CExpr::IntLit(0)))];
    note_unproven_constructs(&mut func, None, 0, 0, 0, 0);
    let note = match func.body.first() {
        Some(CStmt::Comment(text)) => text.clone(),
        other => panic!("expected a leading proof note, got {other:?}"),
    };
    assert!(note.contains("r2dec proof:"), "{note}");
    assert!(note.contains("no individual construct is marked"), "{note}");
}

#[test]
fn proof_line_attributes_variadic_format_counts_to_radare2() {
    let mut func = CFunction::new("formatted".to_string(), CType::Unknown);
    func.body = vec![CStmt::Return(None)];
    note_unproven_constructs(&mut func, None, 2, 0, 0, 0);
    let note = match func.body.first() {
        Some(CStmt::Comment(text)) => text,
        other => panic!("expected a leading proof note, got {other:?}"),
    };
    assert!(
        note.contains(
            "2 variadic callsite argument counts supplied by the source's format literals"
        ),
        "{note}"
    );
}

/// Rendering nothing is not the same as proving the function does nothing.
/// An empty body reads as "this function has no effects", so a render that
/// produced no statements says that instead of implying it.
#[test]
fn a_body_that_rendered_nothing_says_so_rather_than_reading_as_empty() {
    let mut func = CFunction::new("nothing_rendered".to_string(), CType::Unknown);
    func.body = Vec::new();
    note_unproven_constructs(&mut func, None, 0, 0, 0, 0);
    let text = format!("{:?}", func.body);
    assert!(
        text.contains("r2dec proof: rendering produced no statements"),
        "{text}"
    );
    assert_eq!(func.body.len(), 1, "one statement says it, not two: {text}");
}

#[test]
fn normal_residual_comments_hide_debug_ids_and_raw_storage_tokens() {
    let comment = sanitize_comment_text(
        "uncertified expression value ValueId(125) from ObjectId(9) via eax_1 var_8h var_ch fake_stack_slot t6a80 tmp:2c280_2",
    );

    for raw in [
        "ValueId",
        "ObjectId",
        "eax_1",
        "var_8h",
        "var_ch",
        "fake_stack_slot",
        "t6a80",
        "tmp:2c280_2",
    ] {
        assert!(
            !comment.contains(raw),
            "normal comments must hide {raw}, got {comment}"
        );
    }
    assert!(
        comment.contains("uncertified expression value value")
            && comment.contains("object")
            && comment.contains("register")
            && comment.contains("stack slot")
            && comment.contains("temporary"),
        "sanitized comment should preserve actionable categories, got {comment}"
    );
}

#[test]
fn autogenerated_name_detection_accepts_underscore_hex_labels() {
    assert!(is_autogenerated_function_name("_140010138"));
    assert!(is_autogenerated_function_name("_401000"));
    assert!(!is_autogenerated_function_name("_named_worker"));
}

#[test]
fn sealed_region_occurrence_mismatch_is_a_render_refusal() {
    assert_eq!(validate_sealed_region_occurrence_counts(3, 3), Ok(()));
    assert_eq!(
        validate_sealed_region_occurrence_counts(2, 3),
        Err(DecompileRenderRefusal::UnrepresentableControlFlow),
        "release builds must not admit a partially represented region domain"
    );
}

/// Every place that spells a C conversion, frozen.
///
/// A cast is a claim about what a value *is*, and the session that wrote
/// this found three copies of one conversion rule that had silently
/// diverged -- one filtered an unknown source type and two did not, so the
/// same value crossed into a pointer with a cast on one path and without
/// on another. The rule is stated once now, in `convert_optional`.
///
/// The guard is the file set, not a count: edits inside these files are
/// ordinary, a *new* file spelling a conversion is the drift. The list is
/// meant to shrink as the conversion sites move behind one elaborator; it
/// is not meant to grow.
#[test]
fn a_c_conversion_is_spelled_only_where_the_conversion_rules_live() {
    let sources: &[(&str, &str)] = &[
        (
            "fold/op_lower/convert.rs",
            include_str!("fold/op_lower/convert.rs"),
        ),
        (
            "fold/op_lower/implementation.rs",
            include_str!("fold/op_lower/implementation.rs"),
        ),
        (
            "fold/op_lower/subscript_renderer.rs",
            include_str!("fold/op_lower/subscript_renderer.rs"),
        ),
        (
            "fold/op_lower/projection.rs",
            include_str!("fold/op_lower/projection.rs"),
        ),
        (
            "fold/op_lower/memory_renderer.rs",
            include_str!("fold/op_lower/memory_renderer.rs"),
        ),
        (
            "fold/op_lower/lowering.rs",
            include_str!("fold/op_lower/lowering.rs"),
        ),
        ("lib.rs", include_str!("lib.rs")),
        (
            "analysis/prepared_semantic/mod.rs",
            include_str!("analysis/prepared_semantic/mod.rs"),
        ),
        ("placement/mod.rs", include_str!("placement/mod.rs")),
        (
            "observation_journal/mod.rs",
            include_str!("observation_journal/mod.rs"),
        ),
        (
            "observation_journal/recording.rs",
            include_str!("observation_journal/recording.rs"),
        ),
        (
            "observation_journal/sealing.rs",
            include_str!("observation_journal/sealing.rs"),
        ),
        // Not permitted: these are checked to be free of conversions.
        ("ast.rs", include_str!("ast.rs")),
        ("codegen.rs", include_str!("codegen.rs")),
        ("structure/rewrite.rs", include_str!("structure/rewrite.rs")),
        ("structure/shape.rs", include_str!("structure/shape.rs")),
        ("structure/place.rs", include_str!("structure/place.rs")),
        (
            "binding_plan/rules.rs",
            include_str!("binding_plan/rules.rs"),
        ),
        (
            "binding_plan/access_syntax.rs",
            include_str!("binding_plan/access_syntax.rs"),
        ),
        ("fold/stack.rs", include_str!("fold/stack.rs")),
        (
            "fold/op_lower/calls.rs",
            include_str!("fold/op_lower/calls.rs"),
        ),
        (
            "fold/op_lower/typing.rs",
            include_str!("fold/op_lower/typing.rs"),
        ),
    ];
    let permitted = [
        "fold/op_lower/convert.rs",
        "fold/op_lower/implementation.rs",
        "fold/op_lower/subscript_renderer.rs",
        "fold/op_lower/projection.rs",
        "fold/op_lower/memory_renderer.rs",
        "fold/op_lower/lowering.rs",
        "lib.rs",
        "analysis/prepared_semantic/mod.rs",
        "placement/mod.rs",
        "observation_journal/mod.rs",
    ];
    let spells_a_conversion = |source: &str| {
        source.contains(concat!("CExpr::", "cast("))
            || source.contains(concat!("CExpr::", "pointer_width_cast("))
    };
    let offenders: Vec<&str> = sources
        .iter()
        .filter(|(name, source)| spells_a_conversion(source) && !permitted.contains(name))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        offenders.is_empty(),
        "a C conversion is spelled outside the files that own the conversion rules: {offenders:?}"
    );
}
