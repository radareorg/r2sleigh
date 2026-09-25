use super::*;
use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

fn reg(offset: u64, size: u32) -> Varnode {
    Varnode::new(SpaceId::Register, offset, size)
}

fn arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("RAX", 0, 8));
    arch.add_register(RegisterDef::new("RDI", 0x38, 8));
    arch.add_register(RegisterDef::new("RIP", 0x288, 8));
    arch.add_register(RegisterDef::new("XMM0", 0x1200, 16));
    for (lane, name) in ["XMM0_Da", "XMM0_Db", "XMM0_Dc", "XMM0_Dd"].iter().enumerate() {
        arch.add_register(RegisterDef::sub(*name, 0x1200 + 4 * lane as u64, 4, "XMM0"));
    }
    arch
}

fn block(ops: Vec<R2ILOp>) -> R2ILBlock {
    let mut block = R2ILBlock::new(0x1000, 4);
    for op in ops {
        block.push(op);
    }
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    block
}

/// Whether any operation still reads what the caller left in `name`.
fn reads_entry(func: &SSAFunction, name: &str) -> bool {
    func.blocks().iter().any(|block| {
        block.ops.iter().any(|op| {
            op.sources()
                .iter()
                .any(|source| source.version == 0 && source.name().eq_ignore_ascii_case(name))
        })
    })
}

/// Whether the value an effect reads is computed from what the caller left in
/// `name`: a read by an operation whose value nothing uses is not one.
fn effects_read_entry(func: &SSAFunction, name: &str) -> bool {
    let ops = func.blocks().iter().flat_map(|block| block.ops.iter());
    let defined = ops
        .clone()
        .filter_map(|op| Some((op.dst()?.clone(), op)))
        .collect::<BTreeMap<_, _>>();
    let mut pending = ops
        .filter(|op| op.dst().is_none())
        .flat_map(|op| op.sources().into_iter().cloned())
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    while let Some(var) = pending.pop() {
        if var.version == 0 && var.name().eq_ignore_ascii_case(name) {
            return true;
        }
        if seen.insert(var.clone())
            && let Some(op) = defined.get(&var)
        {
            pending.extend(op.sources().into_iter().cloned());
        }
    }
    false
}

/// `xorps xmm0, xmm0` is four lane writes of `lane ^ lane` over the caller's
/// `xmm0`; they cover every byte, so the stored vector reads nothing the
/// caller left, and the chain folds to the zero it computes.
#[test]
fn a_zeroing_idiom_over_every_lane_reads_nothing_of_the_callers_register() {
    let mut ops = Vec::new();
    for lane in 0..4u64 {
        let lane = reg(0x1200 + 4 * lane, 4);
        ops.push(R2ILOp::IntXor {
            dst: lane.clone(),
            a: lane.clone(),
            b: lane,
        });
    }
    ops.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x2000, 8),
        val: reg(0x1200, 16),
    });
    let mut func = SSAFunction::from_blocks_raw(&[block(ops)], Some(&arch())).expect("ssa");
    assert!(
        effects_read_entry(&func, "XMM0"),
        "each lane reads the caller's lane"
    );
    func.prepare_for_decompile(&crate::optimize::DecompilePrepConfig::default());
    // The slices the lanes were read through are dead once `x ^ x` folds;
    // only what the store reads matters.
    assert!(
        !effects_read_entry(&func, "XMM0"),
        "the zeroed vector still reads the caller's xmm0: {}",
        func.dump()
    );
}

/// `movsx ax, dil` returned at two bytes: the lane is the whole result, so
/// the caller's `rax` is not read. Returned at eight bytes it is: the upper
/// six bytes are the caller's, and nothing may drop them.
#[test]
fn a_lane_returned_at_its_own_width_stops_reading_its_root() {
    let body = || {
        vec![
            R2ILOp::IntSExt {
                dst: Varnode::unique(0x20, 2),
                src: reg(0x38, 1),
            },
            R2ILOp::Insert {
                dst: reg(0, 8),
                src: reg(0, 8),
                value: Varnode::unique(0x20, 2),
                position: Varnode::constant(0, 4),
            },
        ]
    };
    let rax = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    let narrowed = |returned: Returned| {
        let mut func = SSAFunction::from_blocks_raw(&[block(body())], Some(&arch())).expect("ssa");
        assert!(reads_entry(&func, "RAX"), "the lane write reads its root");
        drop_unobserved_operands(&mut func, returned);
        func
    };
    let two = narrowed(Returned::Result(ResultDemand::low(rax, 2)));
    assert!(!reads_entry(&two, "RAX"), "{}", two.dump());
    let returned = two
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .find(|op| op.dst().is_some_and(|dst| dst.name().eq_ignore_ascii_case("rax")))
        .expect("the result is still written");
    assert!(
        matches!(returned, SSAOp::IntZExt { .. }),
        "the lane over zero is the lane widened: {returned}"
    );
    let whole = narrowed(Returned::Result(ResultDemand::low(rax, 8)));
    assert!(reads_entry(&whole, "RAX"), "{}", whole.dump());
    assert!(reads_entry(&narrowed(Returned::Unstated), "RAX"));
}

/// A lane written before a call keeps its root: the callee could read the
/// whole register, whatever the convention says it takes.
#[test]
fn a_lane_written_before_a_call_keeps_its_root() {
    let mut func = SSAFunction::from_blocks_raw(
        &[block(vec![
            R2ILOp::Insert {
                dst: reg(0, 8),
                src: reg(0, 8),
                value: Varnode::constant(1, 1),
                position: Varnode::constant(0, 4),
            },
            R2ILOp::Call {
                target: Varnode::constant(0x4000, 8),
            },
            R2ILOp::Copy {
                dst: reg(0, 8),
                src: Varnode::constant(0, 8),
            },
        ])],
        Some(&arch()),
    )
    .expect("ssa");
    drop_unobserved_operands(&mut func, Returned::Unstated);
    assert!(reads_entry(&func, "RAX"), "{}", func.dump());
}
