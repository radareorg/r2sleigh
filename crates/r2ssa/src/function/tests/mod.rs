mod control;
mod interface;
mod lift;
mod memory;
mod stack;

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

/// What the analysis says one dispatching block switches on.
fn test_switch_selector(function: &SSAFunction, block_addr: u64) -> String {
    let graph = crate::graph::SsaGraph::from_function(function);
    let predicates = crate::semantic::collect_predicate_facts_for_test(function, &graph);
    let values = crate::values::solve_value_ranges(&graph, function, &predicates);
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

use super::*;
use crate::semantic::{CallArgumentLocation, SemanticId};
use crate::{
    CallBoundarySlot, CanonicalStorageSpace, SourceAbiParameterSpec, SourceCallArgumentFact,
    SourceCallArgumentValue, SourceCallEffect, SourceFunctionReturn, SourceStackSlotSpec, ValueId,
};
use r2il::{R2ILOp, RegisterDef, SpaceId, SwitchCase, SwitchInfo as R2ILSwitchInfo, Varnode};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// A call effect naming these registers clobbered and these preserved.
fn clobbering(
    clobbered: impl IntoIterator<Item = CanonicalStorageId>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<SourceCallEffect> {
    crate::testing::call_effect(clobbered, preserved)
}

/// A call effect that preserves exactly these registers and clobbers every other.
fn preserving(preserved: impl IntoIterator<Item = CanonicalStorageId>) -> Option<SourceCallEffect> {
    clobbering([], preserved)
}

/// Decompile-prepared SSA under a call effect preserving the named registers.
fn prepared_preserving(
    blocks: &[R2ILBlock],
    arch: &ArchSpec,
    preserved: &[&str],
) -> Option<SsaArtifact> {
    let preserved = preserved.iter().map(|name| {
        let register = arch
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .expect("a named register");
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: register.offset,
            size: register.size,
        }
    });
    crate::testing::prepared(
        blocks,
        arch,
        None,
        Vec::new(),
        preserved.collect::<Vec<_>>(),
    )
}

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
        clobbering((0..4).map(slot), []),
        vec![interface],
    );
    if let Some(format) = format {
        machine_context.bind_source_string_literals(&[(0x3000, format.to_string())]);
    }
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
        clobbering((0..4).map(slot), []),
        vec![interface],
    );
    machine_context
        .bind_source_string_literals(&[(0x3000, first.to_string()), (0x3010, second.to_string())]);
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
        clobbering((0..4).map(slot), []),
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
        &machine_context,
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

/// The fixture's call effect: rax, rdi, rsi and rdx clobbered, the register at 32 preserved.
fn call_preservation_effect() -> Option<SourceCallEffect> {
    let clobbered = [0, 8, 16, 24].map(|offset| call_preservation_storage(offset, 8));
    clobbering(clobbered, [call_preservation_storage(32, 8)])
}

/// The fixture prepared for decompilation under its convention.
fn call_preservation_artifact(blocks: &[R2ILBlock], arch: &ArchSpec) -> Option<SsaArtifact> {
    SsaArtifact::for_decompile_with(
        blocks,
        DecompileInputs {
            arch: Some(arch),
            call_effect: call_preservation_effect(),
            ..Default::default()
        },
    )
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
    let artifact = call_preservation_artifact(&[block], &arch).expect("calling artifact");
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

/// Prepare blocks where a call clobbers the general registers and keeps `xmm8`, the low half of `ymm8`.
fn prepared_keeping_xmm8(
    blocks: Vec<(u64, Vec<R2ILOp>)>,
    callee_preserved_carriers: CalleePreservedCarriers,
) -> SsaArtifact {
    let mut arch = call_preservation_arch();
    arch.add_register(RegisterDef::new("ymm8", 0x100, 32));
    arch.add_register(RegisterDef::new("xmm8", 0x100, 16));
    let blocks = blocks
        .into_iter()
        .map(|(addr, ops)| R2ILBlock {
            addr,
            ..call_preservation_block(ops)
        })
        .collect::<Vec<_>>();
    let clobbered = [0, 8, 16, 24].map(|offset| call_preservation_storage(offset, 8));
    SsaArtifact::for_decompile_with(
        &blocks,
        DecompileInputs {
            arch: Some(&arch),
            call_effect: clobbering(clobbered, [call_preservation_storage(0x100, 16)]),
            callee_preserved_carriers,
            ..Default::default()
        },
    )
    .expect("artifact")
}

/// Write the upper half of `ymm8`, the half a call does not keep.
fn write_upper_ymm8() -> R2ILOp {
    R2ILOp::Copy {
        dst: make_reg(0x110, 16),
        src: make_const(0, 16),
    }
}

/// A call that never returns still ends its block when it writes part of a register it keeps the rest of.
#[test]
fn a_call_that_never_returns_ends_its_block_past_the_lanes_it_writes() {
    let general = [0, 8, 16, 24].map(|offset| call_preservation_storage(offset, 8));
    // The callee's body leaves every general register alone, so only the upper half of ymm8 changes.
    let callee = BTreeMap::from([(0x2000, general.into_iter().collect::<BTreeSet<_>>())]);
    let branch = R2ILOp::CBranch {
        target: make_ram(0x1020, 8),
        cond: make_reg(8, 1),
    };
    let ret = R2ILOp::Return {
        target: make_const(0, 8),
    };
    let call = R2ILOp::Call {
        target: make_ram(0x2000, 8),
    };
    let artifact = prepared_keeping_xmm8(
        vec![
            (0x1000, vec![write_upper_ymm8(), branch]),
            (0x1010, vec![ret]),
            (0x1020, vec![call]),
        ],
        callee,
    );
    let ends = artifact
        .function()
        .get_block(0x1020)
        .expect("calling block");
    assert!(
        matches!(ends.ops.last(), Some(SSAOp::Insert(_))),
        "{:?}",
        ends.ops
    );
    let preserved = &artifact.facts().boundaries.preserved_call_carriers;
    assert!(preserved.contains(&general[1]), "{preserved:?}");
}

/// The half of a register a call keeps is the value that reached the call, here a merge of two paths.
#[test]
fn a_call_keeps_the_merged_half_of_a_register_it_writes_part_of() {
    let set_xmm8 = |value| R2ILOp::Copy {
        dst: make_reg(0x100, 16),
        src: make_const(value, 16),
    };
    let to_join = R2ILOp::Branch {
        target: make_ram(0x1030, 8),
    };
    let call = R2ILOp::Call {
        target: make_ram(0x2000, 8),
    };
    let store = R2ILOp::Store {
        space: SpaceId::Ram,
        addr: make_const(0x5000, 8),
        val: make_reg(0x100, 16),
    };
    let ret = R2ILOp::Return {
        target: make_const(0, 8),
    };
    let fork = R2ILOp::CBranch {
        target: make_ram(0x1020, 8),
        cond: make_reg(8, 1),
    };
    let artifact = prepared_keeping_xmm8(
        vec![
            (0x1000, vec![fork]),
            (0x1010, vec![set_xmm8(1), to_join]),
            (0x1020, vec![set_xmm8(2)]),
            (0x1030, vec![write_upper_ymm8(), call, store, ret]),
        ],
        BTreeMap::new(),
    );
    let function = artifact.function();
    let ops = || function.blocks().iter().flat_map(|block| &block.ops);
    let merged = |value: &SSAVar| {
        let mut phis = function.blocks().iter().flat_map(|block| &block.phis);
        phis.any(|phi| phi.dst == *value)
    };
    let mut value = ops()
        .find_map(|op| match op {
            SSAOp::Store { val, .. } => Some(val.clone()),
            _ => None,
        })
        .expect("the store survives");
    while !merged(&value) {
        let def = ops().find(|op| op.dst() == Some(&value));
        value = match def.unwrap_or_else(|| panic!("{value} has no definition")) {
            SSAOp::Copy { src, .. } | SSAOp::Subpiece { src, .. } => src.clone(),
            SSAOp::Insert(insert) => insert.src.clone(),
            other => panic!("the stored value comes from {other:?}, not the merge"),
        };
    }
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
fn operations_inserted_ahead_of_a_block_leave_every_later_operation_on_its_instruction() {
    let rax = Varnode::register(0, 8);
    let rcx = Varnode::register(8, 8);
    let instructions = [
        (
            0x1000,
            R2ILOp::Copy {
                dst: rax.clone(),
                src: Varnode::constant(1, 8),
            },
        ),
        (0x1004, R2ILOp::Copy { dst: rcx, src: rax }),
        (
            0x1008,
            R2ILOp::Return {
                target: Varnode::constant(0, 8),
            },
        ),
    ];
    let mut block = R2ILBlock::new(0x1000, 12);
    for (addr, op) in instructions {
        let meta = r2il::OpMetadata {
            instruction_addr: Some(addr),
            ..Default::default()
        };
        block.push_with_metadata(op, Some(meta));
    }
    let mut function = SSAFunction::from_blocks(&[block]).expect("it builds");
    let entry = function.entry;
    let attributed = |function: &SSAFunction, from: usize| {
        (from..from + 3)
            .map(|index| function.instruction_at(entry, index))
            .collect::<Vec<_>>()
    };
    let before = attributed(&function, 0);
    assert_eq!(before, [Some(0x1000), Some(0x1004), Some(0x1008)]);
    function.insert_ops(entry, 0, vec![(SSAOp::Nop, None)]);
    // The minted operation belongs to no instruction, and each lifted one keeps its own.
    assert_eq!(function.instruction_at(entry, 0), None);
    assert_eq!(attributed(&function, 1), before);
}
