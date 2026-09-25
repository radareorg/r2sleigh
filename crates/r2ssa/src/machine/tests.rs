use super::*;
use crate::SSAVar;
use r2il::{
    ArchSpec, Endianness, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
    RegisterProjectionDisposition, RegisterProjectionRefusal, RegisterStorage, SpaceId, Varnode,
};

#[test]
fn floating_arithmetic_lowers_in_the_operands_own_format() {
    let artifact = artifact_with_ops([R2ILOp::FloatMult {
        dst: Varnode::register(0, 8),
        a: Varnode::register(8, 8),
        b: Varnode::register(16, 8),
    }]);
    let machine = MachineFunction::from_artifact(&artifact).expect("float multiply");
    let root = machine
        .entities()
        .iter()
        .find_map(|entity| {
            matches!(
                machine.expr(entity.root()).map(MachineExpr::kind),
                Some(MachineExprKind::FloatArithmetic {
                    op: MachineFloatOp::Multiply,
                    ..
                })
            )
            .then_some(entity.root())
        })
        .expect("the multiply is projected");
    let expr = machine.expr(root).expect("root");
    assert_eq!(expr.ty(), &MachineType::Float { width_bits: 64 });
    for child in expr.kind().children() {
        assert_eq!(
            machine.expr(child).map(MachineExpr::ty),
            Some(&MachineType::Float { width_bits: 64 })
        );
    }
}

#[test]
fn a_floating_constant_is_a_floating_source() {
    let artifact = artifact_with_ops([R2ILOp::FloatSub {
        dst: Varnode::register(0, 8),
        a: Varnode::constant(0x3ff0_0000_0000_0000, 8),
        b: Varnode::register(8, 8),
    }]);
    let machine = MachineFunction::from_artifact(&artifact).expect("float subtract");
    assert!(machine.arena().iter().any(|(_, expr)| {
        matches!(expr.kind(), MachineExprKind::Constant { .. })
            && expr.ty() == &MachineType::Float { width_bits: 64 }
    }));
}

#[test]
fn trunc_is_the_floating_to_integer_conversion() {
    let artifact = artifact_with_ops([R2ILOp::Trunc {
        dst: Varnode::register(0, 4),
        src: Varnode::register(8, 8),
    }]);
    let machine = MachineFunction::from_artifact(&artifact).expect("trunc");
    let root = machine
        .entities()
        .iter()
        .find_map(|entity| {
            matches!(
                machine.expr(entity.root()).map(MachineExpr::kind),
                Some(MachineExprKind::Cast {
                    kind: MachineCastKind::FloatToInteger,
                    ..
                })
            )
            .then_some(entity.root())
        })
        .expect("trunc converts a floating value");
    assert_eq!(
        machine.expr(root).map(MachineExpr::ty),
        Some(&integer_type(32, MachineSignedness::Signed))
    );
}

#[test]
fn an_unspellable_floating_width_is_refused() {
    let artifact = artifact_with_ops([R2ILOp::FloatAdd {
        dst: Varnode::register(0, 10),
        a: Varnode::register(16, 10),
        b: Varnode::register(32, 10),
    }]);
    assert!(matches!(
        MachineFunction::from_artifact(&artifact),
        Err(MachineBuildError::UnsupportedOperation { op, .. })
            if matches!(*op, SSAOp::FloatAdd { .. })
    ));
}

#[test]
fn a_floating_comparison_is_a_boolean_producer() {
    let compared = Varnode::unique(0x10, 1);
    let artifact = artifact_with_ops([
        R2ILOp::FloatLess {
            dst: compared.clone(),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        },
        R2ILOp::BoolNot {
            dst: Varnode::unique(0x20, 1),
            src: compared,
        },
    ]);
    let machine = MachineFunction::from_artifact(&artifact).expect("float compare");
    assert!(machine.entities().iter().any(|entity| {
        matches!(
            machine.expr(entity.root()).map(MachineExpr::kind),
            Some(MachineExprKind::BooleanNot { .. })
        )
    }));
}

fn artifact_with_ops(ops: impl IntoIterator<Item = R2ILOp>) -> SsaArtifact {
    let mut block = R2ILBlock::new(0x1000, 4);
    for op in ops {
        block.push(op);
    }
    SsaArtifact::raw(&[block], None).expect("test SSA artifact")
}

fn artifact_with_arch(ops: impl IntoIterator<Item = R2ILOp>, arch: &ArchSpec) -> SsaArtifact {
    let mut block = R2ILBlock::new(0x1000, 4);
    for op in ops {
        block.push(op);
    }
    SsaArtifact::raw(&[block], Some(arch)).expect("test SSA artifact")
}

fn register_geometry_arch() -> ArchSpec {
    let eax = RegisterStorage { offset: 0, size: 4 };
    let rax = RegisterStorage { offset: 0, size: 8 };
    let ah = RegisterStorage { offset: 1, size: 1 };
    let mut arch = ArchSpec::new("geometry-test");
    arch.add_register(RegisterDef::new("eax", eax.offset, eax.size));
    arch.add_register(RegisterDef::new("rax", rax.offset, rax.size));
    arch.add_register(RegisterDef::new("ah", ah.offset, ah.size));
    arch.register_projections = vec![
        RegisterProjection {
            written: eax,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 32,
                },
            },
        },
        RegisterProjection {
            written: rax,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 64,
                },
            },
        },
        RegisterProjection {
            written: ah,
            disposition: RegisterProjectionDisposition::Bound {
                carrier: rax,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 8,
                    size_bits: 8,
                },
            },
        },
    ];
    arch
}

fn value_geometry_for_storage(
    projection: &MachineProjection,
    artifact: &SsaArtifact,
    storage: CanonicalStorageId,
) -> MachineValueGeometryDisposition {
    let dispositions = artifact
        .graph()
        .values
        .iter()
        .filter(|value| value.canonical_storage == Some(storage))
        .map(|value| {
            projection
                .value_geometry(value.id)
                .copied()
                .expect("dense value geometry")
        })
        .collect::<Vec<_>>();
    let first = *dispositions
        .first()
        .expect("fixture value with requested canonical storage");
    assert!(
        dispositions.iter().all(|disposition| *disposition == first),
        "versions of one exact storage must retain one geometry"
    );
    first
}

fn big_endian_register_geometry_arch() -> ArchSpec {
    let carrier = RegisterStorage { offset: 0, size: 8 };
    let high_byte = RegisterStorage { offset: 6, size: 1 };
    let mut arch = ArchSpec::new("geometry-test-be");
    arch.set_instruction_endianness(Endianness::Big);
    arch.set_memory_endianness(Endianness::Big);
    arch.add_register(RegisterDef::new("carrier", carrier.offset, carrier.size));
    arch.add_register(RegisterDef::new(
        "high_byte",
        high_byte.offset,
        high_byte.size,
    ));
    arch.register_projections = vec![
        RegisterProjection {
            written: carrier,
            disposition: RegisterProjectionDisposition::Bound {
                carrier,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 64,
                },
            },
        },
        RegisterProjection {
            written: high_byte,
            disposition: RegisterProjectionDisposition::Bound {
                carrier,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 8,
                    size_bits: 8,
                },
            },
        },
    ];
    arch
}

#[test]
fn zero_bitvector_is_checked_and_exact() {
    // 128 is included: a constant whose varnode is wider than a machine
    // word still carries its value in a `u64`, and 128 is the widest a C
    // integer literal can spell.
    for width_bits in [1, 8, 16, 32, 64, 65, 128] {
        let zero = MachineBitVector::zero(width_bits).expect("supported zero bitvector");
        assert_eq!(zero.width_bits(), width_bits);
        assert_eq!(zero.bits(), 0);
    }
    assert_eq!(MachineBitVector::zero(0), None);
    assert_eq!(MachineBitVector::zero(129), None);
    assert_eq!(MachineBitVector::zero(u32::MAX), None);
}

#[test]
fn unsigned_64_bit_multiply_retains_wrapping_arithmetic() {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let initial = Varnode::unique(0x10, 8);
    let folded = Varnode::unique(0x18, 8);
    let product = Varnode::unique(0x20, 8);
    let artifact = artifact_with_ops([
        R2ILOp::Copy {
            dst: initial.clone(),
            src: Varnode::constant(FNV_OFFSET, 8),
        },
        R2ILOp::IntXor {
            dst: folded.clone(),
            a: initial,
            b: Varnode::register(0, 8),
        },
        R2ILOp::IntMult {
            dst: product,
            a: folded,
            b: Varnode::constant(FNV_PRIME, 8),
        },
    ]);

    let machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let mult_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 2)
        .expect("multiply instruction");
    let output = artifact
        .graph()
        .inst(mult_inst)
        .and_then(|inst| inst.output)
        .expect("multiply output");
    let entity = machine.entity_for_output(output).expect("multiply entity");
    let root = machine.expr(entity.root()).expect("multiply expression");
    assert_eq!(
        root.ty(),
        &MachineType::Integer {
            width_bits: 64,
            signedness: MachineSignedness::Unsigned,
        }
    );
    let MachineExprKind::Arithmetic {
        op: MachineArithmeticOp::Multiply,
        mode: MachineArithmeticMode::Wrapping,
        right,
        ..
    } = root.kind()
    else {
        panic!("expected wrapping multiply, got {:?}", root.kind());
    };
    let MachineExprKind::Constant { value, .. } =
        machine.expr(*right).expect("prime expression").kind()
    else {
        panic!("FNV prime must remain a semantic constant");
    };
    assert_eq!(value.width_bits(), 64);
    assert_eq!(value.bits(), FNV_PRIME);
    let disposition = artifact
        .obligations()
        .instruction_for_inst(mult_inst)
        .expect("multiply disposition");
    assert_eq!(entity.producer(), disposition.id);
    assert_eq!(entity.source_obligations(), &disposition.obligations);
}

#[test]
fn narrow_bitwise_result_explicitly_extracts_low_operand_bits() {
    let artifact = artifact_with_ops([R2ILOp::IntAnd {
        dst: Varnode::unique(0x10, 4),
        a: Varnode::register(0, 8),
        b: Varnode::constant(0xff, 8),
    }]);

    let machine =
        MachineFunction::from_artifact(&artifact).expect("typed narrow bitwise expression");
    let entity = machine.entities().first().expect("bitwise entity");
    let root = machine.expr(entity.root()).expect("bitwise root");
    let MachineExprKind::Bitwise { left, right, .. } = root.kind() else {
        panic!("expected bitwise root, got {:?}", root.kind());
    };
    for input in [left, right] {
        let narrowed = machine.expr(*input).expect("narrowed operand");
        assert_eq!(
            narrowed.ty(),
            &integer_type(32, MachineSignedness::Unsigned)
        );
        let MachineExprKind::Extract { input, lsb_bits } = narrowed.kind() else {
            panic!(
                "expected explicit low-bit extract, got {:?}",
                narrowed.kind()
            );
        };
        assert_eq!(*lsb_bits, 0);
        assert_eq!(
            machine
                .expr(*input)
                .expect("wide source operand")
                .ty()
                .width_bits(),
            64
        );
    }
    machine
        .validate_against(&artifact)
        .expect("narrow bitwise expression remains source-bound");
}

#[test]
fn shifts_require_exact_value_width_and_keep_the_count_width() {
    let artifact = artifact_with_ops([
        R2ILOp::IntLeft {
            dst: Varnode::unique(0x10, 4),
            a: Varnode::unique(0x100, 4),
            b: Varnode::constant(1, 1),
        },
        R2ILOp::IntRight {
            dst: Varnode::unique(0x18, 4),
            a: Varnode::unique(0x108, 4),
            b: Varnode::constant(2, 1),
        },
        R2ILOp::IntSRight {
            dst: Varnode::unique(0x20, 4),
            a: Varnode::unique(0x110, 4),
            b: Varnode::constant(3, 1),
        },
    ]);

    let projection = MachineProjection::from_artifact(&artifact).expect("typed shift projection");
    assert!(
        projection.failures().is_empty(),
        "valid shifts must not become projection refusals: {:?}",
        projection.failures()
    );
    assert_eq!(
        projection,
        MachineProjection::from_artifact(&artifact).expect("repeated shift projection")
    );

    for (op_index, expected_kind) in [
        (0, MachineShiftKind::Left),
        (1, MachineShiftKind::LogicalRight),
        (2, MachineShiftKind::ArithmeticRight),
    ] {
        let inst = artifact
            .graph()
            .inst_id_for_op_site(0x1000, op_index)
            .expect("shift instruction");
        let output = artifact
            .graph()
            .inst(inst)
            .and_then(|inst| inst.output)
            .expect("shift output");
        let root = projection
            .entity_for_output(output)
            .and_then(|entity| projection.expr(entity.root()))
            .expect("shift expression");
        let MachineExprKind::Shift {
            kind, value, count, ..
        } = root.kind()
        else {
            panic!("expected shift root, got {:?}", root.kind());
        };
        assert_eq!(*kind, expected_kind);
        assert_eq!(root.ty().width_bits(), 32);

        let value = projection.expr(*value).expect("whole shift value");
        assert_eq!(value.ty().width_bits(), 32);
        let MachineExprKind::Source { binding, .. } = value.kind() else {
            panic!(
                "shift value must remain a whole source, got {:?}",
                value.kind()
            );
        };
        assert_eq!(
            *binding,
            MachineValueBinding {
                value: artifact
                    .graph()
                    .inst(inst)
                    .expect("shift instruction")
                    .inputs[0],
                width_bits: 32,
            }
        );
        assert_eq!(
            projection
                .expr(*count)
                .expect("shift count source")
                .ty()
                .width_bits(),
            8
        );
        assert_eq!(
            exact_use(&projection, &artifact, op_index, 0),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: 32,
                carrier_width_bits: 32,
                conversion: None,
            }
        );
        assert_eq!(
            exact_use(&projection, &artifact, op_index, 1),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: 8,
                carrier_width_bits: 8,
                conversion: None,
            }
        );
    }
    projection
        .validate_against(&artifact)
        .expect("shift projection remains source-bound");
}

#[test]
fn malformed_shift_graph_reports_instruction_width_mismatch() {
    let value = GraphValue {
        id: ValueId(0),
        var: SSAVar::initial("wide", 8),
        canonical_storage: None,
    };
    let count = GraphValue {
        id: ValueId(1),
        var: SSAVar::constant(1, 1),
        canonical_storage: None,
    };
    let inst = GraphInst {
        id: InstId(0),
        block: BlockId(0),
        ordinal: 0,
        inputs: vec![value.id, count.id],
        output: None,
        canonical_storage: None,
        payload: InstPayload::Op(SSAOp::IntRight {
            dst: SSAVar::new("result", 1, 4),
            a: value.var.clone(),
            b: count.var.clone(),
        }),
    };
    let values = vec![value, count];
    let graph = SsaGraph {
        entry: BlockId(0),
        block_order: vec![BlockId(0)],
        blocks: vec![crate::GraphBlock {
            id: BlockId(0),
            addr: 0x1000,
            size: 4,
            predecessors: Vec::new(),
            successors: Vec::new(),
            insts: vec![inst.id],
        }],
        insts: vec![inst],
        values: values.clone(),
        def_of: vec![None, None],
        use_offsets: vec![0, 1, 2],
        use_sites: vec![
            UseSite {
                inst: InstId(0),
                input_idx: 0,
            },
            UseSite {
                inst: InstId(0),
                input_idx: 1,
            },
        ],
        block_by_addr: [(0x1000, BlockId(0))].into(),
        value_index: crate::graph::value_index_of(&values),
        op_inst_by_site: [((0x1000, 0), InstId(0))].into(),
        op_site_by_inst: [(InstId(0), (0x1000, 0))].into(),
        instruction_by_inst: [(InstId(0), 0x1000)].into(),
        insts_by_instruction: [(0x1000, vec![InstId(0)])].into(),
        formal_projections: BTreeMap::new(),
        formal_roots: BTreeMap::new(),
    };
    let inst = graph.inst(InstId(0)).expect("shift instruction");
    let mut builder = MachineBuilder::for_graph(&graph);

    for expected_bits in [32, 128] {
        assert_eq!(
            builder
                .exact_width_operand_node(&graph, inst, 0, expected_bits)
                .expect_err("a shift value needs explicit upstream projection evidence"),
            MachineBuildError::WidthMismatch {
                inst: InstId(0),
                expected_bits,
                actual_bits: 64,
            }
        );
    }
    assert!(is_local_projection_failure(
        &MachineBuildError::WidthMismatch {
            inst: InstId(0),
            expected_bits: 32,
            actual_bits: 64,
        },
        InstId(0)
    ));
}

#[test]
fn spoofed_constant_name_is_not_semantic_constant_evidence() {
    let graph_value = GraphValue {
        id: ValueId(7),
        var: SSAVar::new("const:100000001b3", 0, 8),
        canonical_storage: None,
    };
    let mut builder = MachineBuilder::default();
    let id = builder
        .intern_value(&graph_value)
        .expect("source expression");
    assert!(matches!(
        builder.nodes[id.index()].kind,
        MachineExprKind::Source {
            binding: MachineValueBinding {
                value: ValueId(7),
                width_bits: 64,
            },
            ..
        }
    ));
}

#[test]
fn zero_and_sign_extension_remain_distinct() {
    let byte = Varnode::register(0, 1);
    let zext = Varnode::unique(0x10, 8);
    let sext = Varnode::unique(0x18, 8);
    let artifact = artifact_with_ops([
        R2ILOp::IntZExt {
            dst: zext,
            src: byte.clone(),
        },
        R2ILOp::IntSExt {
            dst: sext,
            src: byte,
        },
    ]);
    let machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let roots = machine
        .entities()
        .iter()
        .map(|entity| machine.expr(entity.root()).expect("entity root"))
        .collect::<Vec<_>>();
    assert!(matches!(
        roots[0].kind(),
        MachineExprKind::Cast {
            kind: MachineCastKind::ZeroExtend,
            ..
        }
    ));
    assert_eq!(
        roots[0].ty().signedness(),
        Some(MachineSignedness::Unsigned)
    );
    assert!(matches!(
        roots[1].kind(),
        MachineExprKind::Cast {
            kind: MachineCastKind::SignExtend,
            ..
        }
    ));
    assert_eq!(roots[1].ty().signedness(), Some(MachineSignedness::Signed));
}

#[test]
fn arithmetic_flags_remain_distinct_typed_boolean_operations() {
    let left = Varnode::register(0, 4);
    let right = Varnode::register(4, 4);
    let artifact = artifact_with_ops([
        R2ILOp::IntCarry {
            dst: Varnode::unique(0x10, 1),
            a: left.clone(),
            b: right.clone(),
        },
        R2ILOp::IntSCarry {
            dst: Varnode::unique(0x11, 1),
            a: left.clone(),
            b: right.clone(),
        },
        R2ILOp::IntSBorrow {
            dst: Varnode::unique(0x12, 1),
            a: left,
            b: right,
        },
    ]);

    let machine = MachineFunction::from_artifact(&artifact).expect("typed arithmetic flags");
    let flags = machine
        .entities()
        .iter()
        .map(|entity| machine.expr(entity.root()).expect("flag expression"))
        .collect::<Vec<_>>();
    assert_eq!(flags.len(), 3);
    assert!(
        flags
            .iter()
            .all(|flag| flag.ty() == &MachineType::Bool { storage_bits: 8 })
    );
    assert!(matches!(
        flags[0].kind(),
        MachineExprKind::ArithmeticFlag {
            op: MachineArithmeticFlagOp::UnsignedCarry,
            ..
        }
    ));
    assert!(matches!(
        flags[1].kind(),
        MachineExprKind::ArithmeticFlag {
            op: MachineArithmeticFlagOp::SignedCarry,
            ..
        }
    ));
    assert!(matches!(
        flags[2].kind(),
        MachineExprKind::ArithmeticFlag {
            op: MachineArithmeticFlagOp::SignedBorrow,
            ..
        }
    ));
}

/// A count of bits -- the set bits, or the zeros above the highest set bit --
/// reads the whole input and produces an unsigned count wide enough to hold
/// the input's width, which is the largest count either can be.
#[test]
fn bit_counts_are_exact_typed_machine_operations() {
    let ops = [
        R2ILOp::PopCount {
            dst: Varnode::unique(0x10, 1),
            src: Varnode::constant(0xf0f0, 8),
        },
        R2ILOp::Lzcount {
            dst: Varnode::unique(0x10, 1),
            src: Varnode::constant(0xf0f0, 8),
        },
    ];
    for op in ops {
        let lzcount = matches!(op, R2ILOp::Lzcount { .. });
        let artifact = artifact_with_ops([op]);

        let projection = MachineProjection::from_artifact(&artifact).expect("machine projection");
        projection
            .validate_against(&artifact)
            .expect("bit-count projection validation");
        assert!(projection.failures().is_empty());
        let entity = projection.entities().first().expect("bit-count entity");
        let root = projection.expr(entity.root()).expect("bit-count root");
        assert_eq!(
            root.ty(),
            &MachineType::Integer {
                width_bits: 8,
                signedness: MachineSignedness::Unsigned,
            }
        );
        if lzcount {
            assert!(matches!(
                root.kind(),
                MachineExprKind::LeadingZeroCount { .. }
            ));
        } else {
            assert!(matches!(
                root.kind(),
                MachineExprKind::PopulationCount { .. }
            ));
        }
        assert_eq!(
            exact_use(&projection, &artifact, 0, 0),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: 64,
                carrier_width_bits: 64,
                conversion: None,
            }
        );
    }
}

#[test]
fn boolean_not_and_select_require_a_proven_boolean_condition() {
    let compared = Varnode::unique(0x10, 1);
    let inverted = Varnode::unique(0x18, 1);
    let selected = Varnode::unique(0x20, 4);
    let true_value = Varnode::register(8, 4);
    let artifact = artifact_with_ops([
        R2ILOp::IntLess {
            dst: compared.clone(),
            a: Varnode::register(0, 4),
            b: Varnode::constant(26, 4),
        },
        R2ILOp::BoolNot {
            dst: inverted.clone(),
            src: compared,
        },
        R2ILOp::Copy {
            dst: selected.clone(),
            src: true_value.clone(),
        },
        R2ILOp::Select {
            dst: selected,
            cond: inverted,
            if_true: true_value,
            if_false: Varnode::register(12, 4),
        },
    ]);

    let machine = MachineFunction::from_artifact(&artifact).expect("typed select machine");
    let boolean = machine
        .entities()
        .iter()
        .find_map(|entity| {
            let expression = machine.expr(entity.root())?;
            matches!(expression.kind(), MachineExprKind::BooleanNot { .. }).then_some(expression)
        })
        .expect("boolean-not expression");
    assert_eq!(boolean.ty(), &MachineType::Bool { storage_bits: 8 });

    let selected = machine
        .entities()
        .iter()
        .find_map(|entity| {
            let expression = machine.expr(entity.root())?;
            matches!(expression.kind(), MachineExprKind::Select { .. }).then_some(expression)
        })
        .expect("select expression");
    let MachineExprKind::Select {
        condition,
        if_true,
        if_false,
    } = selected.kind()
    else {
        unreachable!();
    };
    assert!(matches!(
        machine.expr(*condition).map(MachineExpr::ty),
        Some(MachineType::Bool { storage_bits: 8 })
    ));
    assert_eq!(
        machine.expr(*if_true).map(MachineExpr::ty),
        Some(selected.ty())
    );
    assert_eq!(
        machine.expr(*if_false).map(MachineExpr::ty),
        Some(selected.ty())
    );
}

#[test]
fn select_rejects_unproven_integer_truthiness() {
    let artifact = artifact_with_ops([R2ILOp::Select {
        dst: Varnode::unique(0x20, 4),
        cond: Varnode::register(0, 1),
        if_true: Varnode::register(8, 4),
        if_false: Varnode::register(12, 4),
    }]);

    assert!(matches!(
        MachineFunction::from_artifact(&artifact),
        Err(MachineBuildError::UnsupportedOperation { op, .. })
            if matches!(*op, SSAOp::Select { .. })
    ));
}

#[test]
fn boolean_not_accepts_a_select_with_two_boolean_arms() {
    let first = Varnode::unique(0x10, 1);
    let second = Varnode::unique(0x18, 1);
    let condition = Varnode::unique(0x20, 1);
    let selected = Varnode::unique(0x28, 1);
    let inverted = Varnode::unique(0x30, 1);
    let artifact = artifact_with_ops([
        R2ILOp::IntEqual {
            dst: first.clone(),
            a: Varnode::register(0, 4),
            b: Varnode::constant(7, 4),
        },
        R2ILOp::IntEqual {
            dst: second.clone(),
            a: Varnode::register(4, 4),
            b: Varnode::constant(14, 4),
        },
        R2ILOp::IntEqual {
            dst: condition.clone(),
            a: Varnode::register(8, 4),
            b: Varnode::constant(21, 4),
        },
        R2ILOp::Select {
            dst: selected.clone(),
            cond: condition,
            if_true: first,
            if_false: second,
        },
        R2ILOp::BoolNot {
            dst: inverted,
            src: selected,
        },
    ]);

    let machine = MachineFunction::from_artifact(&artifact)
        .expect("a select of proven boolean arms remains boolean");
    assert!(machine.entities().iter().any(|entity| {
        matches!(
            machine.expr(entity.root()).map(MachineExpr::kind),
            Some(MachineExprKind::BooleanNot { .. })
        )
    }));
}

#[test]
fn corrupted_select_condition_type_is_rejected() {
    let compared = Varnode::unique(0x10, 1);
    let selected = Varnode::unique(0x20, 4);
    let true_value = Varnode::register(8, 4);
    let mut block = R2ILBlock::new(0x1010, 4);
    block.push(R2ILOp::IntLess {
        dst: compared.clone(),
        a: Varnode::register(0, 4),
        b: Varnode::constant(26, 4),
    });
    block.push(R2ILOp::Copy {
        dst: selected.clone(),
        src: true_value.clone(),
    });
    block.push(R2ILOp::Select {
        dst: selected,
        cond: compared,
        if_true: true_value,
        if_false: Varnode::register(12, 4),
    });
    let artifact = SsaArtifact::raw(&[block], None).expect("select artifact");
    let mut machine = MachineFunction::from_artifact(&artifact).expect("typed select machine");
    let root = machine
        .entities()
        .iter()
        .find_map(|entity| {
            matches!(
                &machine.arena.nodes[entity.root().index()].kind,
                MachineExprKind::Select { .. }
            )
            .then_some(entity.root())
        })
        .expect("select root");
    let MachineExprKind::Select { condition, .. } = &machine.arena.nodes[root.index()].kind else {
        unreachable!();
    };
    let condition = *condition;
    machine.arena.nodes[condition.index()].ty = integer_type(8, MachineSignedness::Unsigned);

    assert!(machine.validate_against(&artifact).is_err());
}

#[test]
fn divide_negate_and_piece_have_exact_machine_vocabulary() {
    let artifact = artifact_with_ops([
        R2ILOp::IntDiv {
            dst: Varnode::unique(0x10, 4),
            a: Varnode::unique(0x100, 4),
            b: Varnode::constant(0, 4),
        },
        R2ILOp::IntNegate {
            dst: Varnode::unique(0x18, 8),
            src: Varnode::unique(0x108, 8),
        },
        R2ILOp::Piece {
            dst: Varnode::unique(0x20, 8),
            hi: Varnode::unique(0x110, 4),
            lo: Varnode::unique(0x118, 4),
        },
    ]);
    let projection = MachineProjection::from_artifact(&artifact).expect("exact projection");
    assert!(projection.failures().is_empty());

    for (op_index, expected_width, expected_inputs) in [(0, 32, 2_usize), (1, 64, 1), (2, 64, 2)] {
        let inst = artifact
            .graph()
            .inst_id_for_op_site(0x1000, op_index)
            .expect("projected instruction");
        let output = artifact
            .graph()
            .inst(inst)
            .and_then(|inst| inst.output)
            .expect("projected output");
        let root = projection
            .entity_for_output(output)
            .and_then(|entity| projection.expr(entity.root()))
            .expect("projected root");
        assert_eq!(
            root.ty(),
            &integer_type(expected_width, MachineSignedness::Unsigned)
        );
        assert_eq!(root.kind().children().len(), expected_inputs);
        for input_idx in 0..expected_inputs {
            assert_eq!(
                exact_use(&projection, &artifact, op_index, input_idx),
                whole_machine_use(
                    binding_for_value(
                        artifact
                            .graph()
                            .value(artifact.graph().inst(inst).unwrap().inputs[input_idx])
                            .unwrap()
                    )
                    .unwrap()
                )
            );
        }
        assert_eq!(
            projection.write_disposition(inst),
            Some(&MachineWriteDisposition::Exact(
                MachineWriteProjection::Full
            ))
        );
    }

    let divide = projection
        .entity_for_output(artifact.graph().inst(InstId(0)).unwrap().output.unwrap())
        .and_then(|entity| projection.expr(entity.root()))
        .expect("divide root");
    assert!(matches!(
        divide.kind(),
        MachineExprKind::Divide {
            interpretation: MachineSignedness::Unsigned,
            zero_divisor: MachineZeroDivisorBehavior::Undefined,
            ..
        }
    ));
    let negate = projection
        .entity_for_output(artifact.graph().inst(InstId(1)).unwrap().output.unwrap())
        .and_then(|entity| projection.expr(entity.root()))
        .expect("negate root");
    assert!(matches!(
        negate.kind(),
        MachineExprKind::Negate {
            mode: MachineArithmeticMode::Wrapping,
            ..
        }
    ));
    let piece = projection
        .entity_for_output(artifact.graph().inst(InstId(2)).unwrap().output.unwrap())
        .and_then(|entity| projection.expr(entity.root()))
        .expect("piece root");
    assert!(matches!(piece.kind(), MachineExprKind::Concat { .. }));
    projection
        .validate_against(&artifact)
        .expect("new vocabulary remains source-bound");
}

#[test]
fn divide_negate_and_piece_reject_wrong_arity_and_width() {
    let artifact = artifact_with_ops([
        R2ILOp::IntDiv {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        },
        R2ILOp::IntNegate {
            dst: Varnode::unique(0x18, 8),
            src: Varnode::register(16, 8),
        },
        R2ILOp::Piece {
            dst: Varnode::unique(0x20, 8),
            hi: Varnode::register(24, 4),
            lo: Varnode::register(28, 4),
        },
    ]);
    for (op_index, expected_arity) in [(0, 2_usize), (1, 1), (2, 2)] {
        let inst = artifact
            .graph()
            .inst_id_for_op_site(0x1000, op_index)
            .and_then(|inst| artifact.graph().inst(inst))
            .expect("test instruction");
        let InstPayload::Op(op) = &inst.payload else {
            unreachable!();
        };
        let output = binding_for_value(
            artifact
                .graph()
                .value(inst.output.expect("test output"))
                .expect("test output value"),
        )
        .expect("test output binding");

        let mut wrong_arity = inst.clone();
        wrong_arity.inputs.pop();
        assert_eq!(
            MachineBuilder::for_graph(artifact.graph()).lower_op(
                &artifact,
                &wrong_arity,
                op,
                output,
            ),
            Err(MachineBuildError::WrongOperandCount {
                inst: inst.id,
                expected: expected_arity,
                actual: expected_arity - 1,
            })
        );

        let wrong_width = MachineValueBinding {
            width_bits: 32,
            ..output
        };
        assert!(matches!(
            MachineBuilder::for_graph(artifact.graph()).lower_op(
                &artifact,
                inst,
                op,
                wrong_width,
            ),
            Err(MachineBuildError::WidthMismatch {
                inst: actual,
                expected_bits: 32,
                actual_bits: 64,
            }) if actual == inst.id
        ));
    }
}

#[test]
fn unsigned_remainder_has_exact_machine_vocabulary() {
    let artifact = artifact_with_ops([R2ILOp::IntRem {
        dst: Varnode::unique(0x10, 8),
        a: Varnode::unique(0x100, 8),
        b: Varnode::constant(0, 8),
    }]);
    let projection = MachineProjection::from_artifact(&artifact).expect("exact remainder");
    assert!(projection.failures().is_empty());

    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("remainder instruction");
    let graph_inst = artifact.graph().inst(inst).expect("remainder graph node");
    let entity = projection
        .entity_for_output(graph_inst.output.expect("remainder output"))
        .expect("remainder entity");
    let root = projection.expr(entity.root()).expect("remainder root");
    assert_eq!(root.ty(), &integer_type(64, MachineSignedness::Unsigned));
    let MachineExprKind::Remainder {
        interpretation: MachineSignedness::Unsigned,
        zero_divisor,
        dividend,
        divisor,
    } = root.kind()
    else {
        panic!("unsigned remainder root expected");
    };
    assert_eq!(*zero_divisor, MachineZeroDivisorBehavior::Undefined);
    assert_eq!(
        operand_leaf_binding(projection.arena(), *dividend).map(|binding| binding.value()),
        Some(graph_inst.inputs[0])
    );
    assert_eq!(
        operand_leaf_binding(projection.arena(), *divisor).map(|binding| binding.value()),
        Some(graph_inst.inputs[1])
    );
    for input_idx in 0..2 {
        assert_eq!(
            exact_use(&projection, &artifact, 0, input_idx),
            whole_machine_use(
                binding_for_value(
                    artifact
                        .graph()
                        .value(graph_inst.inputs[input_idx])
                        .expect("remainder input"),
                )
                .expect("remainder input binding"),
            )
        );
    }
    assert_eq!(
        projection.write_disposition(inst),
        Some(&MachineWriteDisposition::Exact(
            MachineWriteProjection::Full
        ))
    );
    projection
        .validate_against(&artifact)
        .expect("remainder remains source-bound");
}

/// A signed division is a machine operation, not an unmodelled one.
///
/// It reads its operands signed and says so at the node, which is what the
/// rendered `/` on signed operands implements.
#[test]
fn signed_division_and_remainder_read_their_operands_signed() {
    for (op, signed_expr) in [
        (
            R2ILOp::IntSDiv {
                dst: Varnode::unique(0x10, 8),
                a: Varnode::unique(0x100, 8),
                b: Varnode::constant(32, 8),
            },
            true,
        ),
        (
            R2ILOp::IntSRem {
                dst: Varnode::unique(0x10, 8),
                a: Varnode::unique(0x100, 8),
                b: Varnode::constant(32, 8),
            },
            false,
        ),
    ] {
        let artifact = artifact_with_ops([op]);
        let projection = MachineProjection::from_artifact(&artifact).expect("exact signed op");
        assert!(projection.failures().is_empty());

        let inst = artifact
            .graph()
            .inst_id_for_op_site(0x1000, 0)
            .expect("signed instruction");
        let graph_inst = artifact.graph().inst(inst).expect("signed graph node");
        let entity = projection
            .entity_for_output(graph_inst.output.expect("signed output"))
            .expect("signed entity");
        let root = projection.expr(entity.root()).expect("signed root");
        assert_eq!(root.ty(), &integer_type(64, MachineSignedness::Signed));
        let (interpretation, zero_divisor, dividend, divisor) = match root.kind() {
            MachineExprKind::Divide {
                interpretation,
                zero_divisor,
                dividend,
                divisor,
            } if signed_expr => (interpretation, zero_divisor, dividend, divisor),
            MachineExprKind::Remainder {
                interpretation,
                zero_divisor,
                dividend,
                divisor,
            } if !signed_expr => (interpretation, zero_divisor, dividend, divisor),
            other => panic!("signed division root expected, got {other:?}"),
        };
        assert_eq!(*interpretation, MachineSignedness::Signed);
        assert_eq!(*zero_divisor, MachineZeroDivisorBehavior::Undefined);
        assert_eq!(
            operand_leaf_binding(projection.arena(), *dividend).map(|binding| binding.value()),
            Some(graph_inst.inputs[0])
        );
        assert_eq!(
            operand_leaf_binding(projection.arena(), *divisor).map(|binding| binding.value()),
            Some(graph_inst.inputs[1])
        );
        // The operands the renderer spells are the ones the projection
        // certified, which is what a refused use used to deny.
        for input_idx in 0..2 {
            assert_eq!(
                exact_use(&projection, &artifact, 0, input_idx),
                whole_machine_use(
                    binding_for_value(
                        artifact
                            .graph()
                            .value(graph_inst.inputs[input_idx])
                            .expect("signed input"),
                    )
                    .expect("signed input binding"),
                )
            );
        }
        assert_eq!(
            projection.write_disposition(inst),
            Some(&MachineWriteDisposition::Exact(
                MachineWriteProjection::Full
            ))
        );
        projection
            .validate_against(&artifact)
            .expect("signed division remains source-bound");
    }
}

#[test]
fn unsigned_remainder_rejects_wrong_arity_and_width() {
    let artifact = artifact_with_ops([R2ILOp::IntRem {
        dst: Varnode::unique(0x10, 8),
        a: Varnode::register(0, 8),
        b: Varnode::register(8, 8),
    }]);
    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .and_then(|inst| artifact.graph().inst(inst))
        .expect("remainder instruction");
    let InstPayload::Op(op) = &inst.payload else {
        unreachable!();
    };
    let output = binding_for_value(
        artifact
            .graph()
            .value(inst.output.expect("remainder output"))
            .expect("remainder output value"),
    )
    .expect("remainder output binding");

    let mut wrong_arity = inst.clone();
    wrong_arity.inputs.pop();
    assert_eq!(
        MachineBuilder::for_graph(artifact.graph()).lower_op(&artifact, &wrong_arity, op, output,),
        Err(MachineBuildError::WrongOperandCount {
            inst: inst.id,
            expected: 2,
            actual: 1,
        })
    );

    let wrong_width = MachineValueBinding {
        width_bits: 32,
        ..output
    };
    assert!(matches!(
        MachineBuilder::for_graph(artifact.graph()).lower_op(
            &artifact,
            inst,
            op,
            wrong_width,
        ),
        Err(MachineBuildError::WidthMismatch {
            inst: actual,
            expected_bits: 32,
            actual_bits: 64,
        }) if actual == inst.id
    ));
}

#[test]
fn plain_load_requires_and_retains_an_explicit_memory_model() {
    let loaded = Varnode::unique(0x10, 4);
    let mut block = R2ILBlock::new(0x1800, 4);
    block.push(R2ILOp::Load {
        dst: loaded,
        space: SpaceId::Ram,
        addr: Varnode::register(0, 8),
    });
    let mut arch = ArchSpec::new("big-endian-test");
    arch.addr_size = 8;
    arch.set_memory_endianness(Endianness::Big);
    let artifact = SsaArtifact::raw(&[block], Some(&arch)).expect("typed load artifact");
    let machine = MachineFunction::from_artifact(&artifact).expect("machine load");
    let entity = machine.entities().first().expect("load entity");
    let root = machine.expr(entity.root()).expect("load root");
    let MachineExprKind::MemoryRead {
        access,
        space,
        endianness,
        word_size_bytes,
        address,
        width_bits,
        ..
    } = root.kind()
    else {
        panic!("typed memory read expected, got {:?}", root.kind());
    };

    assert_eq!(access.ordinal, 0);
    assert_eq!(*space, MachineAddressSpace::Ram);
    assert_eq!(*endianness, MachineMemoryEndianness::Big);
    assert_eq!(*word_size_bytes, 1);
    assert_eq!(*width_bits, 32);
    assert!(matches!(
        machine.expr(*address).map(MachineExpr::ty),
        Some(MachineType::Address {
            width_bits: 64,
            space: MachineAddressSpace::Ram,
            ..
        })
    ));
    let load_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1800, 0)
        .expect("load instruction");
    let address_use = UseSite {
        inst: load_inst,
        input_idx: 0,
    };
    let projected = MachineValueUse::memory_address_for_use(&artifact, address_use)
        .expect("certified memory-address use")
        .expect("load input zero is the address use");
    assert_eq!(
        projected.binding().value(),
        artifact
            .graph()
            .inst(load_inst)
            .expect("load graph instruction")
            .inputs[0]
    );
    assert_eq!(projected.memory_access(), Some(*access));
    assert!(matches!(
        projected.ty(),
        MachineType::Address {
            width_bits: 64,
            space: MachineAddressSpace::Ram,
            ..
        }
    ));
    let projection =
        MachineProjection::from_artifact(&artifact).expect("source-owned machine projection");
    assert_eq!(
        projection.use_disposition(address_use),
        Some(MachineUseDisposition::MemoryAddress(projected)),
        "the contextual address certificate, not an integer slice, owns this UseSite"
    );
    machine
        .validate_against(&artifact)
        .expect("valid machine load");
}

#[test]
fn corrupted_plain_load_memory_policy_is_rejected() {
    let mut block = R2ILBlock::new(0x1810, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x10, 4),
        space: SpaceId::Ram,
        addr: Varnode::register(0, 8),
    });
    let arch = ArchSpec::new("little-endian-test");
    let artifact = SsaArtifact::raw(&[block], Some(&arch)).expect("typed load artifact");
    let mut machine = MachineFunction::from_artifact(&artifact).expect("machine load");
    let root = machine.entities()[0].root();
    let MachineExprKind::MemoryRead { endianness, .. } =
        &mut machine.arena.nodes[root.index()].kind
    else {
        panic!("memory read root expected");
    };
    *endianness = MachineMemoryEndianness::Big;

    assert!(matches!(
        machine.validate_against(&artifact),
        Err(MachineBuildError::EntityMismatch(_))
    ));
}

#[test]
fn memory_access_authority_rejects_each_exact_space_mismatch() {
    let artifact = artifact_with_ops([R2ILOp::Load {
        dst: Varnode::unique(0x10, 4),
        space: SpaceId::Ram,
        addr: Varnode::constant(0x4000, 8),
    }]);
    let fact = artifact
        .facts()
        .structured
        .memory_accesses
        .values()
        .next()
        .expect("load fact")
        .clone();
    let op = match &artifact
        .graph()
        .inst(fact.id.inst)
        .expect("load instruction")
        .payload
    {
        InstPayload::Op(op) => op.clone(),
        other => panic!("expected load operation, got {other:?}"),
    };
    assert!(memory_access_authorities_match(
        artifact.graph(),
        artifact.objects(),
        &op,
        &op,
        SpaceId::Ram,
        &fact,
        None,
    ));

    let mut mismatched_op = op.clone();
    let SSAOp::Load { space, .. } = &mut mismatched_op else {
        unreachable!();
    };
    *space = SpaceId::Custom(7);
    assert!(!memory_access_authorities_match(
        artifact.graph(),
        artifact.objects(),
        &mismatched_op,
        &op,
        SpaceId::Ram,
        &fact,
        None,
    ));
    assert!(!memory_access_authorities_match(
        artifact.graph(),
        artifact.objects(),
        &op,
        &mismatched_op,
        SpaceId::Ram,
        &fact,
        None,
    ));
    assert!(!memory_access_authorities_match(
        artifact.graph(),
        artifact.objects(),
        &op,
        &op,
        SpaceId::Custom(7),
        &fact,
        None,
    ));

    let mut mismatched_fact = fact.clone();
    mismatched_fact.space = SpaceId::Custom(7);
    assert!(!memory_access_authorities_match(
        artifact.graph(),
        artifact.objects(),
        &op,
        &op,
        SpaceId::Ram,
        &mismatched_fact,
        None,
    ));

    let mut mismatched_objects = artifact.objects().clone();
    mismatched_objects
        .objects
        .get_mut(&fact.object)
        .expect("load object")
        .kind = ObjectKind::EscapedUnknown {
        space: SpaceId::Custom(7),
    };
    assert!(!memory_access_authorities_match(
        artifact.graph(),
        &mismatched_objects,
        &op,
        &op,
        SpaceId::Ram,
        &fact,
        None,
    ));
}

#[test]
fn partial_projection_retains_unsupported_producer_and_supported_dependent() {
    let loaded = Varnode::unique(0x10, 8);
    let sum = Varnode::unique(0x18, 8);
    let artifact = artifact_with_ops([
        R2ILOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: Varnode::register(0, 8),
        },
        R2ILOp::IntAdd {
            dst: sum,
            a: loaded,
            b: Varnode::constant(1, 8),
        },
    ]);
    let projection = MachineProjection::from_artifact(&artifact).expect("partial projection");

    assert_eq!(projection.failures().len(), 1);
    assert!(matches!(
        projection.failures()[0].error(),
        MachineBuildError::UnsupportedOperation { op, .. }
            if matches!(op.as_ref(), SSAOp::Load { .. })
    ));
    assert!(projection.entities().iter().any(|entity| {
        artifact
            .graph()
            .def_inst(entity.output().value())
            .and_then(|inst| artifact.graph().inst(inst))
            .is_some_and(|inst| matches!(&inst.payload, InstPayload::Op(SSAOp::IntAdd { .. })))
    }));
    let failed_inst = artifact
        .graph()
        .def_inst(projection.failures()[0].output())
        .expect("failed producer instruction");
    assert_eq!(
        projection.write_disposition(failed_inst),
        Some(&MachineWriteDisposition::Refused(
            MachineWriteRefusal::UnsupportedOperation
        ))
    );
    projection
        .validate_against(&artifact)
        .expect("valid partial projection");
}

/// A value a user operation produces is refused as that operation: the use
/// and write cells say which one the specification declared, so the refusal a
/// reader sees can name it. An operation that writes nothing is projected, and
/// an unsupported operation of the ordinary vocabulary keeps its own class.
#[test]
fn an_unmodelled_user_operation_is_refused_by_its_index() {
    let produced = Varnode::unique(0x10, 16);
    let artifact = artifact_with_ops([
        R2ILOp::CallOther {
            userop: 204,
            output: Some(produced.clone()),
            inputs: vec![Varnode::register(0, 8), Varnode::register(8, 8)],
        },
        R2ILOp::CallOther {
            userop: 12,
            output: None,
            inputs: vec![Varnode::constant(3, 8)],
        },
        R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: Varnode::register(0x10, 8),
            val: produced,
        },
    ]);
    let projection = MachineProjection::from_artifact(&artifact).expect("partial projection");
    let graph = artifact.graph();
    let producer = graph
        .insts
        .iter()
        .find(|inst| {
            matches!(
                &inst.payload,
                InstPayload::Op(SSAOp::CallOther { userop: 204, .. })
            )
        })
        .expect("the value-producing user operation");
    let refused = MachineUseRefusal::UnmodelledUserOperation { userop: 204 };
    for input_idx in 0..producer.inputs.len() {
        assert_eq!(
            projection.use_disposition(UseSite {
                inst: producer.id,
                input_idx,
            }),
            Some(MachineUseDisposition::Refused(refused)),
        );
    }
    assert_eq!(
        projection.write_disposition(producer.id),
        Some(&MachineWriteDisposition::Refused(
            MachineWriteRefusal::UnmodelledUserOperation { userop: 204 }
        ))
    );
    let effect = graph
        .insts
        .iter()
        .find(|inst| {
            matches!(
                &inst.payload,
                InstPayload::Op(SSAOp::CallOther { userop: 12, .. })
            )
        })
        .expect("the user operation that writes nothing");
    assert!(matches!(
        projection.use_disposition(UseSite {
            inst: effect.id,
            input_idx: 0,
        }),
        Some(MachineUseDisposition::Exact(_))
    ));
    projection
        .validate_against(&artifact)
        .expect("valid partial projection");
}

#[test]
fn malformed_arena_backedge_is_rejected() {
    let artifact = artifact_with_ops([R2ILOp::Copy {
        dst: Varnode::unique(0x10, 8),
        src: Varnode::register(0, 8),
    }]);
    let mut machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let root = machine.entities()[0].root();
    machine.arena.nodes[root.index()].kind = MachineExprKind::Copy { input: root };

    assert_eq!(
        machine.validate_against(&artifact),
        Err(MachineBuildError::InvalidChild {
            expr: root,
            child: root,
        })
    );
}

#[test]
fn corrupted_source_leaf_type_is_rejected() {
    let artifact = artifact_with_ops([R2ILOp::Copy {
        dst: Varnode::unique(0x10, 8),
        src: Varnode::register(0, 8),
    }]);
    let mut machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let root = machine.entities()[0].root();
    let input = match &machine.arena.nodes[root.index()].kind {
        MachineExprKind::Copy { input } => *input,
        _ => panic!("expected copy root"),
    };
    machine.arena.nodes[input.index()].ty = MachineType::Address {
        width_bits: 64,
        space: MachineAddressSpace::Register,
        provenance: MachineAddressProvenance::Unknown,
    };

    assert_eq!(
        machine.validate_against(&artifact),
        Err(MachineBuildError::InvalidExpressionType { expr: input })
    );
}

#[test]
fn corrupted_sign_extension_result_type_is_rejected() {
    let artifact = artifact_with_ops([R2ILOp::IntSExt {
        dst: Varnode::unique(0x10, 8),
        src: Varnode::register(0, 1),
    }]);
    let mut machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let entity = machine.entities()[0].clone();
    machine.arena.nodes[entity.root().index()].ty =
        integer_type(entity.output().width_bits(), MachineSignedness::Unsigned);

    assert!(matches!(
        machine.validate_against(&artifact),
        Err(MachineBuildError::EntityMismatch(_))
    ));
}

#[test]
fn corrupted_subpiece_offset_is_rejected() {
    let artifact = artifact_with_ops([R2ILOp::Subpiece {
        dst: Varnode::unique(0x10, 4),
        src: Varnode::register(0, 8),
        offset: 4,
    }]);
    let mut machine = MachineFunction::from_artifact(&artifact).expect("machine function");
    let root = machine.entities()[0].root();
    let MachineExprKind::Extract { lsb_bits, .. } = &mut machine.arena.nodes[root.index()].kind
    else {
        panic!("expected extract root");
    };
    *lsb_bits = 0;

    assert!(matches!(
        machine.validate_against(&artifact),
        Err(MachineBuildError::EntityMismatch(_))
    ));
}

fn exact_use(
    projection: &MachineProjection,
    artifact: &SsaArtifact,
    op_index: usize,
    input_idx: usize,
) -> MachineUseSlice {
    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, op_index)
        .expect("operation instruction");
    match projection
        .use_disposition(UseSite { inst, input_idx })
        .expect("dense use disposition")
    {
        MachineUseDisposition::Exact(slice) => slice,
        MachineUseDisposition::MemoryAddress(address) => {
            panic!("expected bit-slice use projection, got contextual address {address:?}")
        }
        MachineUseDisposition::Refused(reason) => {
            panic!("expected exact use projection, got {reason:?}")
        }
    }
}

fn exact_write(
    projection: &MachineProjection,
    artifact: &SsaArtifact,
    op_index: usize,
) -> MachineWriteProjection {
    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, op_index)
        .expect("operation instruction");
    match projection
        .write_disposition(inst)
        .copied()
        .expect("dense write disposition")
    {
        MachineWriteDisposition::Exact(write) => write,
        MachineWriteDisposition::Refused(reason) => {
            panic!("expected exact write projection, got {reason:?}")
        }
    }
}

#[test]
fn outputless_constant_operand_has_exact_use_and_canonical_arena_leaf() {
    let artifact = artifact_with_ops([R2ILOp::Return {
        target: Varnode::constant(0xfeed, 8),
    }]);
    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("return instruction");
    let graph_inst = artifact
        .graph()
        .inst(inst)
        .expect("return graph instruction");
    assert_eq!(graph_inst.output, None);
    let [constant_value] = graph_inst.inputs.as_slice() else {
        panic!("return must retain its single constant operand");
    };
    let site = UseSite { inst, input_idx: 0 };

    let projection = MachineProjection::from_artifact(&artifact).expect("machine projection");
    assert_eq!(
        projection.use_disposition(site),
        Some(MachineUseDisposition::Exact(MachineUseSlice {
            bit_offset: 0,
            width_bits: 64,
            carrier_width_bits: 64,
            conversion: None,
        }))
    );
    assert_eq!(projection.arena().len(), 1);
    let (_, expression) = projection
        .arena()
        .iter()
        .next()
        .expect("constant arena leaf");
    let MachineExprKind::Constant { binding, value } = expression.kind() else {
        panic!("outputless literal must be a canonical constant node");
    };
    assert_eq!(binding.value(), *constant_value);
    assert_eq!(binding.width_bits(), 64);
    assert_eq!(value.width_bits(), 64);
    assert_eq!(value.bits(), 0xfeed);

    let mut missing_leaf = projection.clone();
    missing_leaf.machine.arena.nodes = Vec::new().into_boxed_slice();
    assert_eq!(
        missing_leaf.validate_against(&artifact),
        Err(MachineBuildError::UseDispositionMismatch(site))
    );
}

#[test]
fn register_use_slices_compose_nested_offsets_and_refuse_overflow() {
    let operation_relative = MachineUseSlice {
        bit_offset: 4,
        width_bits: 4,
        carrier_width_bits: 8,
        conversion: None,
    };
    assert_eq!(
        compose_machine_use_slice(operation_relative, 8, 64),
        Ok(MachineUseSlice {
            bit_offset: 12,
            width_bits: 4,
            carrier_width_bits: 64,
            conversion: None,
        })
    );
    assert_eq!(
        compose_machine_use_slice(operation_relative, u32::MAX, u32::MAX),
        Err(MachineUseRefusal::InvalidBitRange)
    );
}

#[test]
fn register_use_projection_refuses_unavailable_and_invalid_geometry() {
    let read = |arch: &ArchSpec, source: Varnode| {
        let artifact = artifact_with_arch(
            [R2ILOp::Copy {
                dst: Varnode::unique(0x10, source.size),
                src: source,
            }],
            arch,
        );
        let projection = MachineProjection::from_artifact(&artifact).expect("typed refusal");
        let inst = artifact
            .graph()
            .inst_id_for_op_site(0x1000, 0)
            .expect("copy instruction");
        projection
            .use_disposition(UseSite { inst, input_idx: 0 })
            .expect("dense use disposition")
    };

    let mut missing = register_geometry_arch();
    missing.register_projections.clear();
    assert_eq!(
        read(&missing, Varnode::register(1, 1)),
        MachineUseDisposition::Refused(MachineUseRefusal::MissingRegisterGeometry)
    );

    let mut refused = register_geometry_arch();
    for projection in &mut refused.register_projections {
        projection.disposition = RegisterProjectionDisposition::Refused {
            reason: RegisterProjectionRefusal::MissingRegisterEndianness,
        };
    }
    assert_eq!(
        read(&refused, Varnode::register(1, 1)),
        MachineUseDisposition::Refused(MachineUseRefusal::RegisterGeometry(
            RegisterProjectionRefusal::MissingRegisterEndianness
        ))
    );

    let mut malformed = refused;
    malformed.register_projections[0].disposition = RegisterProjectionDisposition::Bound {
        carrier: RegisterStorage { offset: 0, size: 8 },
        slice: RegisterBitSlice {
            lsb_bit_offset: 0,
            size_bits: 32,
        },
    };
    assert_eq!(
        read(&malformed, Varnode::register(1, 1)),
        MachineUseDisposition::Refused(MachineUseRefusal::MalformedRegisterGeometry)
    );

    let arch = register_geometry_arch();
    assert_eq!(
        read(&arch, Varnode::register(0x80, 1)),
        MachineUseDisposition::Refused(MachineUseRefusal::RegisterGeometry(
            RegisterProjectionRefusal::NoContainingCarrier
        ))
    );
}

#[test]
fn dense_use_slices_cover_whole_subpiece_narrow_bitwise_casts_and_effects() {
    let remainder = Varnode::unique(0x60, 8);
    let artifact = artifact_with_ops([
        R2ILOp::Copy {
            dst: Varnode::unique(0x10, 8),
            src: Varnode::unique(0x100, 8),
        },
        R2ILOp::Subpiece {
            dst: Varnode::unique(0x18, 4),
            src: Varnode::unique(0x108, 8),
            offset: 4,
        },
        R2ILOp::IntAnd {
            dst: Varnode::unique(0x20, 4),
            a: Varnode::unique(0x110, 8),
            b: Varnode::constant(0xff, 8),
        },
        R2ILOp::IntZExt {
            dst: Varnode::unique(0x28, 8),
            src: Varnode::unique(0x118, 1),
        },
        R2ILOp::IntSExt {
            dst: Varnode::unique(0x30, 8),
            src: Varnode::unique(0x119, 1),
        },
        R2ILOp::Subpiece {
            dst: Varnode::unique(0x38, 4),
            src: Varnode::unique(0x120, 8),
            offset: 0,
        },
        R2ILOp::Cast {
            dst: Varnode::unique(0x40, 4),
            src: Varnode::unique(0x128, 4),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x130, 8),
            val: Varnode::unique(0x138, 4),
        },
        R2ILOp::IntRem {
            dst: remainder.clone(),
            a: Varnode::unique(0x140, 8),
            b: Varnode::constant(3, 8),
        },
        R2ILOp::Copy {
            dst: Varnode::unique(0x68, 8),
            src: remainder,
        },
        R2ILOp::Return {
            target: Varnode::unique(0x148, 8),
        },
    ]);
    let projection = MachineProjection::from_artifact(&artifact).expect("use projection");

    assert_eq!(
        projection.uses().count(),
        artifact
            .graph()
            .insts
            .iter()
            .map(|inst| inst.inputs.len())
            .sum::<usize>()
    );
    for inst in &artifact.graph().insts {
        assert_eq!(projection.use_row_len(inst.id), Some(inst.inputs.len()));
    }

    assert_eq!(
        exact_use(&projection, &artifact, 0, 0),
        MachineUseSlice {
            bit_offset: 0,
            width_bits: 64,
            carrier_width_bits: 64,
            conversion: None,
        }
    );
    // Whole, as this test's name says: the subpiece operation renders the
    // extraction, so its operand is read entire.
    assert_eq!(
        exact_use(&projection, &artifact, 1, 0),
        MachineUseSlice {
            bit_offset: 0,
            width_bits: 64,
            carrier_width_bits: 64,
            conversion: None,
        }
    );
    for input_idx in 0..2 {
        assert_eq!(
            exact_use(&projection, &artifact, 2, input_idx),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: 32,
                carrier_width_bits: 64,
                conversion: None,
            }
        );
    }
    // A low subpiece reads its source whole; the narrowing is the node.
    assert_eq!(
        exact_use(&projection, &artifact, 5, 0),
        MachineUseSlice {
            bit_offset: 0,
            width_bits: 64,
            carrier_width_bits: 64,
            conversion: None,
        }
    );
    for (op_index, kind, source_bits, target_bits) in [
        (3, MachineCastKind::ZeroExtend, 8, 64),
        (4, MachineCastKind::SignExtend, 8, 64),
        (6, MachineCastKind::BitReinterpret, 32, 32),
    ] {
        assert_eq!(
            exact_use(&projection, &artifact, op_index, 0),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: source_bits,
                carrier_width_bits: source_bits,
                conversion: Some(MachineUseConversion {
                    kind,
                    to_width_bits: target_bits,
                }),
            }
        );
    }
    let store_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 7)
        .expect("store instruction");
    assert_eq!(
        projection.use_disposition(UseSite {
            inst: store_inst,
            input_idx: 0,
        }),
        Some(MachineUseDisposition::Refused(
            MachineUseRefusal::MissingMemoryContext
        )),
        "an address without an exact memory model must not masquerade as an integer slice"
    );
    assert_eq!(exact_use(&projection, &artifact, 7, 1).width_bits(), 32);

    let remainder_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 8)
        .expect("remainder instruction");
    for input_idx in 0..2 {
        assert_eq!(
            exact_use(&projection, &artifact, 8, input_idx),
            whole_machine_use(
                binding_for_value(
                    artifact
                        .graph()
                        .value(artifact.graph().inst(remainder_inst).unwrap().inputs[input_idx])
                        .unwrap()
                )
                .unwrap()
            )
        );
    }
    assert_eq!(
        projection.write_disposition(remainder_inst),
        Some(&MachineWriteDisposition::Exact(
            MachineWriteProjection::Full
        ))
    );
    assert_eq!(exact_use(&projection, &artifact, 9, 0).width_bits(), 64);
    assert_eq!(exact_use(&projection, &artifact, 10, 0).width_bits(), 64);
    projection
        .validate_against(&artifact)
        .expect("all dense uses remain source-bound");
}

#[test]
fn incoherent_slice_is_a_refusal_and_corrupted_exact_facts_are_rejected() {
    let incoherent = artifact_with_ops([R2ILOp::Subpiece {
        dst: Varnode::unique(0x10, 4),
        src: Varnode::register(0, 4),
        offset: 2,
    }]);
    let projection = MachineProjection::from_artifact(&incoherent)
        .expect("local incoherence remains a partial projection");
    let inst = incoherent
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("subpiece instruction");
    assert_eq!(
        projection.use_disposition(UseSite { inst, input_idx: 0 }),
        Some(MachineUseDisposition::Refused(
            MachineUseRefusal::IncoherentOperation
        ))
    );

    let artifact = artifact_with_ops([
        R2ILOp::Copy {
            dst: Varnode::unique(0x20, 8),
            src: Varnode::unique(0x100, 8),
        },
        R2ILOp::IntZExt {
            dst: Varnode::unique(0x28, 8),
            src: Varnode::unique(0x108, 1),
        },
    ]);
    let mut projection =
        MachineProjection::from_artifact(&artifact).expect("valid exact projection");
    let copy_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("copy instruction");
    let PackedUseDisposition::Exact(copy) =
        &mut projection.use_slots[projection.use_offsets[copy_inst.0 as usize] as usize]
    else {
        panic!("exact copy use expected");
    };
    copy.width_bits = 56;
    assert_eq!(
        projection.validate_against(&artifact),
        Err(MachineBuildError::UseDispositionMismatch(UseSite {
            inst: copy_inst,
            input_idx: 0,
        }))
    );

    let mut projection =
        MachineProjection::from_artifact(&artifact).expect("valid exact projection");
    let cast_inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 1)
        .expect("cast instruction");
    let PackedUseDisposition::Exact(cast) =
        &mut projection.use_slots[projection.use_offsets[cast_inst.0 as usize] as usize]
    else {
        panic!("exact cast use expected");
    };
    cast.conversion = Some(MachineUseConversion {
        kind: MachineCastKind::SignExtend,
        to_width_bits: 64,
    });
    assert_eq!(
        projection.validate_against(&artifact),
        Err(MachineBuildError::UseDispositionMismatch(UseSite {
            inst: cast_inst,
            input_idx: 0,
        }))
    );

    let mut projection =
        MachineProjection::from_artifact(&artifact).expect("valid exact projection");
    // One row short of the instruction's inputs, which is the topology
    // the validator is asked about.
    projection.use_offsets[copy_inst.0 as usize + 1] = projection.use_offsets[copy_inst.0 as usize];
    assert_eq!(
        projection.validate_against(&artifact),
        Err(MachineBuildError::TopologyMismatch)
    );
}

/// Every register value is its family's root, so its geometry is the
/// carrier itself (doc/adr-register-identity.md).
#[test]
fn value_geometry_is_dense_and_every_register_value_is_its_root() {
    let arch = register_geometry_arch();
    // The whole carrier is used, so it is this function's root.
    let artifact = artifact_with_arch(
        [
            R2ILOp::Copy {
                dst: Varnode::unique(0x8, 8),
                src: Varnode::register(0, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x10, 1),
                src: Varnode::register(1, 1),
            },
            R2ILOp::IntAdd {
                dst: Varnode::register(0, 4),
                a: Varnode::unique(0x20, 4),
                b: Varnode::constant(1, 4),
            },
        ],
        &arch,
    );
    let projection = MachineProjection::from_artifact(&artifact).expect("machine projection");

    assert_eq!(
        projection.value_geometries().len(),
        artifact.graph().values.len()
    );
    let rax = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let mut register_values = 0;
    for (index, value) in artifact.graph().values.iter().enumerate() {
        assert_eq!(value.id.0 as usize, index);
        assert_eq!(
            projection.value_geometry(value.id),
            projection.value_geometries().get(index)
        );
        match value.canonical_storage {
            Some(storage) if storage.space == CanonicalStorageSpace::Register => {
                assert_eq!(storage, rax, "the lane read and write both name the root");
                register_values += 1;
                assert_eq!(
                    projection.value_geometry(value.id),
                    Some(&MachineValueGeometryDisposition::ExactRegister(
                        MachineRegisterValueGeometry {
                            carrier: rax,
                            bit_offset: 0,
                            value_width_bits: 64,
                            carrier_width_bits: 64,
                        }
                    ))
                );
            }
            _ => assert!(matches!(
                projection.value_geometry(value.id),
                Some(MachineValueGeometryDisposition::Direct(_))
            )),
        }
    }
    assert!(register_values >= 2, "the entry root and the inserted root");
    assert_eq!(
        projection.value_geometry(ValueId(artifact.graph().values.len() as u32)),
        None
    );
    let MachineValueGeometryDisposition::ExactRegister(geometry) =
        value_geometry_for_storage(&projection, &artifact, rax)
    else {
        panic!("the root has exact register geometry");
    };
    assert_eq!(geometry.carrier_storage(), rax);
    assert_eq!(geometry.carrier_location(), rax.location());
    projection
        .validate_against(&artifact)
        .expect("every dense geometry remains source-bound");

    let mut corrupted = projection;
    corrupted.value_geometries[0] =
        MachineValueGeometryDisposition::Refused(MachineValueGeometryRefusal::InvalidBitRange);
    assert_eq!(
        corrupted.validate_against(&artifact),
        Err(MachineBuildError::TopologyMismatch)
    );
}

#[test]
fn value_geometry_ignores_register_names_and_definition_order() {
    let original = register_geometry_arch();
    let mut renamed = register_geometry_arch();
    for register in &mut renamed.registers {
        register.name = match (register.offset, register.size) {
            (0, 4) => "narrow_accumulator".to_string(),
            (0, 8) => "wide_accumulator".to_string(),
            (1, 1) => "upper_low_byte".to_string(),
            _ => unreachable!("geometry fixture has three registers"),
        };
    }
    renamed.registers.reverse();
    let root = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    for (offset, size) in [(1, 1), (0, 4)] {
        // The whole carrier is used, so it is this function's root.
        let ops = || {
            [
                R2ILOp::Copy {
                    dst: Varnode::unique(0x8, 8),
                    src: Varnode::register(0, 8),
                },
                R2ILOp::Copy {
                    dst: Varnode::unique(0x10, size),
                    src: Varnode::register(offset, size),
                },
            ]
        };
        let original_artifact = artifact_with_arch(ops(), &original);
        let renamed_artifact = artifact_with_arch(ops(), &renamed);
        let original_projection =
            MachineProjection::from_artifact(&original_artifact).expect("original projection");
        let renamed_projection =
            MachineProjection::from_artifact(&renamed_artifact).expect("renamed projection");
        assert_eq!(
            value_geometry_for_storage(&original_projection, &original_artifact, root),
            value_geometry_for_storage(&renamed_projection, &renamed_artifact, root)
        );
        let name_of = |artifact: &SsaArtifact| {
            artifact
                .graph()
                .values
                .iter()
                .find(|value| value.canonical_storage == Some(root))
                .expect("root register value")
                .var
                .name()
                .to_string()
        };
        assert_ne!(name_of(&original_artifact), name_of(&renamed_artifact));
    }
}

#[test]
fn value_geometry_preserves_register_geometry_refusals() {
    let root = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let read = |arch: &ArchSpec| {
        let artifact = artifact_with_arch(
            [
                R2ILOp::Copy {
                    dst: Varnode::unique(0x8, 8),
                    src: Varnode::register(0, 8),
                },
                R2ILOp::Copy {
                    dst: Varnode::unique(0x10, 1),
                    src: Varnode::register(1, 1),
                },
            ],
            arch,
        );
        let projection = MachineProjection::from_artifact(&artifact).expect("typed geometry");
        value_geometry_for_storage(&projection, &artifact, root)
    };

    let mut missing = register_geometry_arch();
    missing.register_projections.clear();
    assert_eq!(
        read(&missing),
        MachineValueGeometryDisposition::Refused(
            MachineValueGeometryRefusal::MissingRegisterGeometry
        )
    );

    let mut refused = register_geometry_arch();
    for projection in &mut refused.register_projections {
        projection.disposition = RegisterProjectionDisposition::Refused {
            reason: RegisterProjectionRefusal::MissingRegisterEndianness,
        };
    }
    assert_eq!(
        read(&refused),
        MachineValueGeometryDisposition::Refused(MachineValueGeometryRefusal::RegisterGeometry(
            RegisterProjectionRefusal::MissingRegisterEndianness
        ))
    );
}

/// A lane write defines its root whole, from the root it keeps and the
/// lane it inserts; only the lift's own extension of a lane into the root
/// is a zero-extending write.
#[test]
fn dense_write_projections_cover_full_and_zero_extension() {
    let arch = register_geometry_arch();
    let full = artifact_with_arch(
        [R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(7, 8),
        }],
        &arch,
    );
    let full_projection = MachineProjection::from_artifact(&full).expect("full projection");
    assert_eq!(
        exact_write(&full_projection, &full, 0),
        MachineWriteProjection::Full
    );

    // `Copy tmp = 7; RAX_1 = Insert(RAX_0, tmp, 0)`: the insert is the
    // root's definition. The trailing whole read is what makes the
    // carrier this function's root rather than the lane itself.
    let low = artifact_with_arch(
        [
            R2ILOp::Copy {
                dst: Varnode::register(0, 4),
                src: Varnode::constant(7, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x40, 8),
                src: Varnode::register(0, 8),
            },
        ],
        &arch,
    );
    let low_projection = MachineProjection::from_artifact(&low).expect("low projection");
    assert_eq!(
        exact_write(&low_projection, &low, 1),
        MachineWriteProjection::Full
    );
    let inserted = low
        .graph()
        .inst_id_for_op_site(0x1000, 1)
        .expect("insert instruction");
    assert!(matches!(
        low.graph().inst(inserted).map(|inst| &inst.payload),
        Some(InstPayload::Op(SSAOp::Insert { .. }))
    ));

    // `mov ah, 7`: a lane in the middle of the register is the same insert
    // at its own position.
    let high = artifact_with_arch(
        [
            R2ILOp::Copy {
                dst: Varnode::register(1, 1),
                src: Varnode::constant(7, 1),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x40, 8),
                src: Varnode::register(0, 8),
            },
        ],
        &arch,
    );
    let high_projection = MachineProjection::from_artifact(&high).expect("high projection");
    assert_eq!(
        exact_write(&high_projection, &high, 1),
        MachineWriteProjection::Full
    );
    let root = high
        .graph()
        .inst_id_for_op_site(0x1000, 1)
        .and_then(|inst| high.graph().inst(inst))
        .and_then(|inst| inst.output)
        .expect("inserted root");
    let entity = high_projection
        .entity_for_output(root)
        .expect("the root's machine entity");
    let Some(MachineExpr {
        kind:
            MachineExprKind::InsertLane {
                position,
                lsb_bits,
                width_bits,
                ..
            },
        ..
    }) = high_projection.expr(entity.root())
    else {
        panic!("the root is defined by a lane insert");
    };
    assert_eq!((*lsb_bits, *width_bits), (8, 8));
    assert!(high_projection.expr(*position).is_some());

    // `EAX = EAX + 7` and `RAX = zext(EAX)` as two instructions: the
    // first inserts its lane, the second redefines the root by extension.
    // Within one instruction the lift's own extension supersedes the
    // insert; the genuine-lift tests state that case.
    let clearing_low = artifact_with_arch(
        [
            R2ILOp::IntAdd {
                dst: Varnode::register(0, 4),
                a: Varnode::register(0, 4),
                b: Varnode::constant(7, 4),
            },
            R2ILOp::IntZExt {
                dst: Varnode::register(0, 8),
                src: Varnode::register(0, 4),
            },
        ],
        &arch,
    );
    let clearing_projection =
        MachineProjection::from_artifact(&clearing_low).expect("clearing projection");
    let ops = &clearing_low
        .function()
        .get_block(0x1000)
        .expect("block")
        .ops;
    let extension = ops
        .iter()
        .position(|op| matches!(op, SSAOp::IntZExt { .. }))
        .expect("the lift's extension");
    assert!(
        ops.iter().any(|op| matches!(op, SSAOp::Insert { .. })),
        "a lane written by one instruction is inserted into its root: {ops:?}"
    );
    assert_eq!(
        exact_write(&clearing_projection, &clearing_low, extension),
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
    assert_eq!(
        clearing_projection.write_dispositions().len(),
        clearing_low.graph().insts.len()
    );

    let external_zero_extend = artifact_with_arch(
        [R2ILOp::IntZExt {
            dst: Varnode::register(0, 8),
            src: Varnode::unique(0x80, 4),
        }],
        &arch,
    );
    let external_projection = MachineProjection::from_artifact(&external_zero_extend)
        .expect("external zero-extension projection");
    assert_eq!(
        exact_write(&external_projection, &external_zero_extend, 0),
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
}

/// A register is read whole: the lane a narrow read wants is the
/// `Subpiece` the read became, and its operand is the root.
#[test]
fn register_uses_read_the_root_whole() {
    let arch = register_geometry_arch();
    // The whole carrier is used too, so it is this function's root.
    let artifact = artifact_with_arch(
        [
            R2ILOp::Copy {
                dst: Varnode::unique(0x8, 8),
                src: Varnode::register(0, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x10, 4),
                src: Varnode::register(0, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x20, 1),
                src: Varnode::register(1, 1),
            },
        ],
        &arch,
    );
    let ops = &artifact.function().get_block(0x1000).expect("block").ops;
    let subpieces = ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| match op {
            SSAOp::Subpiece { offset, dst, .. } => Some((index, *offset, dst.size)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(subpieces.len(), 2, "{ops:?}");
    assert_eq!((subpieces[0].1, subpieces[0].2), (0, 4));
    assert_eq!((subpieces[1].1, subpieces[1].2), (1, 1));
    let projection = MachineProjection::from_artifact(&artifact).expect("use projection");
    for (index, _, _) in &subpieces {
        assert_eq!(
            exact_use(&projection, &artifact, *index, 0),
            MachineUseSlice {
                bit_offset: 0,
                width_bits: 64,
                carrier_width_bits: 64,
                conversion: None,
            }
        );
    }
    projection
        .validate_against(&artifact)
        .expect("whole reads remain source-bound");

    let read = artifact
        .graph()
        .inst_id_for_op_site(0x1000, subpieces[1].0)
        .expect("high-byte read");
    for corrupt in [
        |slice: &mut MachineUseSlice| slice.bit_offset = 8,
        |slice: &mut MachineUseSlice| slice.carrier_width_bits = 16,
    ] {
        let mut corrupted = MachineProjection::from_artifact(&artifact).expect("valid projection");
        let PackedUseDisposition::Exact(slice) =
            &mut corrupted.use_slots[corrupted.use_offsets[read.0 as usize] as usize]
        else {
            panic!("the root read must be exact");
        };
        corrupt(slice);
        assert_eq!(
            corrupted.validate_against(&artifact),
            Err(MachineBuildError::UseDispositionMismatch(UseSite {
                inst: read,
                input_idx: 0,
            }))
        );
    }
}

/// On a big-endian register file the lane at the highest address is the
/// least significant, so its `Subpiece` offset counts from that end.
#[test]
fn big_endian_lane_positions_count_from_the_least_significant_byte() {
    let arch = big_endian_register_geometry_arch();
    let artifact = artifact_with_arch(
        [
            R2ILOp::Copy {
                dst: Varnode::unique(0x8, 8),
                src: Varnode::register(0, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x10, 1),
                src: Varnode::register(6, 1),
            },
        ],
        &arch,
    );
    let ops = &artifact.function().get_block(0x1000).expect("block").ops;
    assert!(
        ops.iter().any(|op| matches!(
            op,
            SSAOp::Subpiece { offset: 1, dst, .. } if dst.size == 1
        )),
        "byte 6 of 8 is one byte above the least significant: {ops:?}"
    );
    let projection = MachineProjection::from_artifact(&artifact).expect("use projection");
    assert_eq!(
        exact_use(&projection, &artifact, 0, 0),
        MachineUseSlice {
            bit_offset: 0,
            width_bits: 64,
            carrier_width_bits: 64,
            conversion: None,
        }
    );
    projection
        .validate_against(&artifact)
        .expect("big-endian root read remains source-bound");
}

#[test]
fn write_projection_refuses_missing_and_upstream_refused_geometry() {
    let write = || {
        [R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(1, 8),
        }]
    };
    let mut missing = register_geometry_arch();
    missing.register_projections.clear();
    let missing_artifact = artifact_with_arch(write(), &missing);
    let missing_projection =
        MachineProjection::from_artifact(&missing_artifact).expect("typed refusal");
    let missing_inst = missing_artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("copy instruction");
    assert_eq!(
        missing_projection.write_disposition(missing_inst),
        Some(&MachineWriteDisposition::Refused(
            MachineWriteRefusal::MissingRegisterGeometry
        ))
    );

    let mut refused = register_geometry_arch();
    for projection in &mut refused.register_projections {
        projection.disposition = RegisterProjectionDisposition::Refused {
            reason: RegisterProjectionRefusal::MissingRegisterEndianness,
        };
    }
    let refused_artifact = artifact_with_arch(write(), &refused);
    let refused_projection =
        MachineProjection::from_artifact(&refused_artifact).expect("upstream refusal");
    let refused_inst = refused_artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("copy instruction");
    assert_eq!(
        refused_projection.write_disposition(refused_inst),
        Some(&MachineWriteDisposition::Refused(
            MachineWriteRefusal::RegisterGeometry(
                RegisterProjectionRefusal::MissingRegisterEndianness
            )
        ))
    );

    let mut malformed = refused;
    malformed.register_projections[0].disposition = RegisterProjectionDisposition::Bound {
        carrier: RegisterStorage { offset: 0, size: 8 },
        slice: RegisterBitSlice {
            lsb_bit_offset: 0,
            size_bits: 32,
        },
    };
    let malformed_artifact = artifact_with_arch(write(), &malformed);
    let malformed_projection =
        MachineProjection::from_artifact(&malformed_artifact).expect("malformed refusal");
    let malformed_inst = malformed_artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("copy instruction");
    assert_eq!(
        malformed_projection.write_disposition(malformed_inst),
        Some(&MachineWriteDisposition::Refused(
            MachineWriteRefusal::MalformedRegisterGeometry
        ))
    );
    assert_ne!(
        missing_artifact.machine_context().semantic_identity_bytes(),
        malformed_artifact
            .machine_context()
            .semantic_identity_bytes()
    );
}

/// A lane the architecture does not name still belongs to the register
/// containing it, so writing it inserts into that register's root.
#[test]
fn unnamed_vector_lanes_insert_into_their_root() {
    let q0 = RegisterStorage {
        offset: 0x5000,
        size: 16,
    };
    let s0 = RegisterStorage {
        offset: 0x5000,
        size: 4,
    };
    let q4 = RegisterStorage {
        offset: 0x5040,
        size: 16,
    };
    let b4 = RegisterStorage {
        offset: 0x5040,
        size: 1,
    };
    let mut arch = ArchSpec::new("aarch64-vector-lanes");
    for (name, storage) in [("q0", q0), ("s0", s0), ("q4", q4), ("b4", b4)] {
        arch.add_register(RegisterDef::new(name, storage.offset, storage.size));
    }
    let full = |storage: RegisterStorage| RegisterProjection {
        written: storage,
        disposition: RegisterProjectionDisposition::Bound {
            carrier: storage,
            slice: RegisterBitSlice {
                lsb_bit_offset: 0,
                size_bits: u64::from(storage.size) * 8,
            },
        },
    };
    arch.register_projections = vec![full(q0), full(q4)];
    arch.register_projections
        .sort_by_key(|projection| (projection.written.offset, projection.written.size));
    let artifact = artifact_with_arch(
        [
            R2ILOp::IntAdd {
                dst: Varnode::register(0x5004, 4),
                a: Varnode::unique(0x10, 4),
                b: Varnode::unique(0x14, 4),
            },
            R2ILOp::IntAnd {
                dst: Varnode::register(0x5041, 1),
                a: Varnode::unique(0x18, 1),
                b: Varnode::unique(0x19, 1),
            },
        ],
        &arch,
    );
    let projection = MachineProjection::from_artifact(&artifact).expect("machine projection");
    let ops = &artifact.function().get_block(0x1000).expect("block").ops;
    let inserts = ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| match op {
            SSAOp::Insert(insert) => {
                Some((index, insert.dst.size, insert.position.constant_bits()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(inserts.len(), 2, "{ops:?}");
    assert_eq!((inserts[0].1, inserts[0].2), (16, Some(32)));
    assert_eq!((inserts[1].1, inserts[1].2), (16, Some(8)));
    for (index, _, _) in &inserts {
        assert_eq!(
            exact_write(&projection, &artifact, *index),
            MachineWriteProjection::Full
        );
    }
    projection
        .validate_against(&artifact)
        .expect("unnamed lane inserts remain source-bound");
}

#[test]
fn corrupted_write_disposition_is_rejected() {
    let arch = register_geometry_arch();
    let artifact = artifact_with_arch(
        [R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(7, 8),
        }],
        &arch,
    );
    let mut projection = MachineProjection::from_artifact(&artifact).expect("projection");
    let inst = artifact
        .graph()
        .inst_id_for_op_site(0x1000, 0)
        .expect("copy instruction");
    projection.write_dispositions[inst.0 as usize] = Some(MachineWriteDisposition::Exact(
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        },
    ));
    assert_eq!(
        projection.validate_against(&artifact),
        Err(MachineBuildError::WriteDispositionMismatch(inst))
    );
}
