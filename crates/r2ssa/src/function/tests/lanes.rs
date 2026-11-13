//! A call argument is the low lane of its carrier only where the lane's definition stands behind
//! the call (ROADMAP D68, doc/adr-decompiler-rewrite.md "D2's spelling order").

use super::*;
use crate::{
    CallSiteId, InstId, InstPayload, SourceCallArgumentSpec, SourceCallResult,
    SourceCallSiteIdentity, SourceCallSiteInterface, SourceFunctionInterface,
};
use r2il::ArchSpec;

const VECTOR: u64 = 0x100;
const MERGE: u64 = 0x100c;
const READER: u64 = 0x1010;
const CALLER: u64 = 0x1018;
const CALLEE: u64 = 0x4000;

fn storage(offset: u64, size: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    }
}

/// A block of `ops`, each stamped as its own instruction.
fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
    let mut block = R2ILBlock::new(addr, 4);
    for op in ops {
        block.push(op);
    }
    for index in 0..block.ops.len() {
        let returns = matches!(block.ops[index], R2ILOp::Return { .. });
        block.stamp_instruction(index, addr + if returns { 2 } else { 0 });
    }
    block
}

fn lane_read() -> Vec<R2ILOp> {
    vec![
        R2ILOp::Subpiece {
            dst: make_unique(0x200, 4),
            src: make_reg(VECTOR, 16),
            offset: 0,
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_const(0x3000, 8),
            val: make_unique(0x200, 4),
        },
    ]
}

/// Two arms load a vector register that merges at `MERGE`, which branches to `READER` (reads its low
/// lane) or `CALLER` (calls with it). `lane_in_the_merge` moves that read above the branch.
fn lane_call(lane_in_the_merge: bool) -> SsaArtifact {
    sealed_lane_call(lane_in_the_merge).expect("the lane call prepares")
}

/// The vector register `v`, its four lanes and the registers the call and returns use, with the
/// projections that bind each lane to `v`.
fn lane_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("lane-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("v", VECTOR, 16));
    let carrier = r2il::RegisterStorage {
        offset: VECTOR,
        size: 16,
    };
    let bound = |written, carrier, lsb_bit_offset, size_bits| r2il::RegisterProjection {
        written,
        disposition: r2il::RegisterProjectionDisposition::Bound {
            carrier,
            slice: r2il::RegisterBitSlice {
                lsb_bit_offset,
                size_bits,
            },
        },
    };
    let mut projections = vec![bound(carrier, carrier, 0, 128)];
    for lane in 0..4u32 {
        let offset = VECTOR + 4 * u64::from(lane);
        arch.add_register(RegisterDef::sub(format!("v{lane}"), offset, 4, "v"));
        let written = r2il::RegisterStorage { offset, size: 4 };
        projections.push(bound(written, carrier, 32 * u64::from(lane), 32));
    }
    for (name, offset, size) in [("cond", 0x40, 1), ("lr", 0x80, 8), ("sp", 0x88, 8)] {
        arch.add_register(RegisterDef::new(name, offset, size));
        let own = r2il::RegisterStorage { offset, size };
        projections.push(bound(own, own, 0, u64::from(size) * 8));
    }
    // The file lists its projections in the order of the storage they are for.
    projections.sort_by_key(|projection| projection.written);
    arch.register_projections = projections;
    arch
}

/// As x86 writes `xmm1` from memory: the low lane loaded, the three above it zeroed.
fn load_vector(addr: u64) -> Vec<R2ILOp> {
    let mut ops = vec![R2ILOp::Load {
        dst: make_reg(VECTOR, 4),
        space: SpaceId::Ram,
        addr: make_const(addr, 8),
    }];
    ops.extend((1..4).map(|lane| R2ILOp::Copy {
        dst: make_reg(VECTOR + 4 * lane, 4),
        src: make_const(0, 4),
    }));
    ops
}

fn lane_blocks(lane_in_the_merge: bool) -> Vec<R2ILBlock> {
    let branch = |target| R2ILOp::Branch {
        target: make_const(target, 8),
    };
    let conditional = |target| R2ILOp::CBranch {
        target: make_const(target, 8),
        cond: make_reg(0x40, 1),
    };
    let ret = || R2ILOp::Return {
        target: make_reg(0x80, 8),
    };
    let (mut merge, mut reader) = match lane_in_the_merge {
        true => (lane_read(), Vec::new()),
        false => (Vec::new(), lane_read()),
    };
    merge.push(conditional(CALLER));
    reader.push(ret());
    let call = R2ILOp::Call {
        target: make_ram(CALLEE, 8),
    };
    vec![
        block(0x1000, vec![conditional(0x1008)]),
        block(0x1004, [load_vector(0x2000), vec![branch(MERGE)]].concat()),
        block(0x1008, [load_vector(0x2010), vec![branch(MERGE)]].concat()),
        block(MERGE, merge),
        block(READER, reader),
        block(CALLER, vec![call, ret()]),
    ]
}

fn sealed_lane_call(lane_in_the_merge: bool) -> Result<SsaArtifact, crate::SsaPrepareError> {
    let revision = b"lane-call";
    let interface = SourceFunctionInterface::new_exact(
        revision.to_vec(),
        r2source::ConventionId::SysVAmd64,
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x80, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x88, 8)))
    .expect("a function interface");
    let callee = CanonicalStorageId::from_varnode(&make_ram(CALLEE, 8));
    let call = SourceCallSiteInterface::new(
        revision.to_vec(),
        SourceCallSiteIdentity::new(CALLER, callee),
        true,
        r2source::ConventionId::SysVAmd64,
        [SourceCallArgumentSpec::new(0, storage(VECTOR, 4))],
        false,
        false,
        SourceCallResult::Void,
    )
    .expect("a call interface");
    SsaArtifact::for_decompile_with_interfaces_and_control(
        &lane_blocks(lane_in_the_merge),
        Some(&crate::Arch::from(lane_arch())),
        Some(interface),
        crate::SourceMachineRoles::default(),
        vec![call],
        crate::testing::conventions([], [storage(0x88, 8)]),
        &crate::control::UncheckedSsaWorkControl,
    )
}

/// The call's one argument, and the instruction that defines a value, as `(block, is a phi)`.
fn the_argument(artifact: &SsaArtifact) -> SourceCallArgumentFact {
    let boundary =
        (artifact.facts().boundaries.calls.get(&CallSiteId(0))).expect("the call's boundary");
    let [argument] = boundary.arguments.as_slice() else {
        panic!("one argument: {boundary:?}");
    };
    *argument
}

fn defined_in(artifact: &SsaArtifact, value: ValueId) -> (u64, bool) {
    let graph = artifact.graph();
    let inst = graph
        .def_inst(value)
        .and_then(|inst| graph.inst(inst))
        .expect("a value the function defines");
    let block = graph.block(inst.block).expect("its block").addr;
    (block, matches!(inst.payload, InstPayload::Phi { .. }))
}

/// The value the low-lane read in `block` defines.
fn lane_defined_in(artifact: &SsaArtifact, block: u64) -> ValueId {
    let graph = artifact.graph();
    graph
        .insts
        .iter()
        .filter(|inst| {
            graph
                .block(inst.block)
                .is_some_and(|held| held.addr == block)
        })
        .find(|inst| matches!(&inst.payload, InstPayload::Op(SSAOp::Subpiece { .. })))
        .and_then(|inst| inst.output)
        .expect("a low lane read there")
}

#[test]
fn a_low_lane_read_on_the_other_arm_is_not_the_calls_argument() {
    // The lane is a view of the merge's vector, defined in `READER`, which does not dominate `CALLER`:
    // the argument is the merge itself, the carrier that does.
    let artifact = lane_call(false);
    let argument = the_argument(&artifact);
    let SourceCallArgumentValue::Value(value) = argument.value else {
        panic!("a value: {argument:?}");
    };
    assert_eq!(defined_in(&artifact, value), (MERGE, true));
    assert_eq!(artifact.graph().var(value).size, 16);
    assert_eq!(argument.lane_of, None);
    assert_ne!(value, lane_defined_in(&artifact, READER));
}

#[test]
fn a_low_lane_read_before_the_branch_is_the_calls_argument() {
    // The same lane read in the merge stands behind both arms: the argument narrows to it, as it did.
    let artifact = lane_call(true);
    let argument = the_argument(&artifact);
    let lane = lane_defined_in(&artifact, MERGE);
    assert_eq!(argument.value, SourceCallArgumentValue::Value(lane));
    let carrier = argument.lane_of.expect("the carrier the lane is of");
    assert_eq!(defined_in(&artifact, carrier), (MERGE, true));
    assert_eq!(artifact.graph().var(lane).size, 4);
}

/// The fact family `validate_boundary_values` names when `forge` puts `lane` (defined on the `READER`
/// arm, behind neither the call, the merge's branch nor either return of `CALLER`) in its place.
fn refused_for(
    artifact: &SsaArtifact,
    fact: &str,
    forge: impl FnOnce(&mut crate::PreparedFunctionFacts),
) -> &'static str {
    let mut forged = artifact.facts().clone();
    forge(&mut forged);
    let refused =
        crate::integrity::validate_boundary_values(artifact.function(), artifact.graph(), &forged)
            .expect_err(&format!("a value defined on the other arm is no {fact}"));
    assert_eq!(
        refused.rule(),
        crate::IntegrityRule::BoundaryValueNotDominated
    );
    let crate::SsaIntegrityError::BoundaryValueNotDominated { fact, .. } = refused else {
        panic!("{refused:?}");
    };
    fact
}

/// A change to the facts that puts a value out of its read's scope.
type Forge = Box<dyn Fn(&mut crate::PreparedFunctionFacts)>;

/// The forged facts that put `lane` in a call's place: its argument, the carrier it is of, its target.
fn call_forgeries(lane: ValueId, carrier: ValueId) -> Vec<(&'static str, Forge)> {
    vec![
        (
            "call argument",
            Box::new(move |f| {
                let call = f
                    .boundaries
                    .calls
                    .get_mut(&CallSiteId(0))
                    .expect("the call");
                call.arguments[0].value = SourceCallArgumentValue::Value(lane);
            }),
        ),
        (
            "call argument carrier",
            Box::new(move |f| {
                let call = f
                    .boundaries
                    .calls
                    .get_mut(&CallSiteId(0))
                    .expect("the call");
                call.arguments[0].value = SourceCallArgumentValue::Value(carrier);
                call.arguments[0].lane_of = Some(lane);
            }),
        ),
        (
            "call target",
            Box::new(move |f| {
                f.call_sites
                    .by_id
                    .values_mut()
                    .for_each(|site| site.target = lane)
            }),
        ),
    ]
}

/// The forged facts that put `lane` in the return at `at`: a value, the return address, the stack pointer.
fn return_forgeries(lane: ValueId, at: InstId) -> Vec<(&'static str, Forge)> {
    use crate::{CallBoundaryValueFact, SourceReturnAddressFact, SourceReturnStackPointerFact};
    let slot = CallBoundarySlot::Register {
        index: 0,
        storage: storage(0x80, 8),
    };
    vec![
        (
            "return value",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                ret.values.push(CallBoundaryValueFact { slot, value: lane });
            }),
        ),
        (
            "return address",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                let storage = storage(0x80, 8);
                ret.return_address = Some(SourceReturnAddressFact {
                    storage,
                    value: lane,
                });
            }),
        ),
        (
            "exit stack pointer",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                let storage = storage(0x88, 8);
                let sp = SourceReturnStackPointerFact::ReachingValue {
                    storage,
                    value: lane,
                };
                ret.exit_stack_pointer = Some(sp);
            }),
        ),
    ]
}

/// The forged facts that put `lane` in a branch's place: its condition, a switch's selector.
fn branch_forgeries(lane: ValueId) -> Vec<(&'static str, Forge)> {
    use crate::semantic::SwitchPredicateFact;
    vec![
        (
            "branch condition",
            Box::new(move |f| {
                f.predicates
                    .predicates
                    .values_mut()
                    .for_each(|p| p.condition = lane)
            }),
        ),
        (
            "switch selector",
            Box::new(move |f| {
                let switch = SwitchPredicateFact {
                    block_addr: MERGE,
                    selector: Some(lane),
                    cases: Vec::new(),
                    default: None,
                };
                f.predicates.switches.insert(MERGE, switch);
            }),
        ),
    ]
}

#[test]
fn a_boundary_fact_naming_a_value_its_read_does_not_stand_behind_is_refused() {
    let artifact = lane_call(false);
    crate::integrity::validate_boundary_values(
        artifact.function(),
        artifact.graph(),
        artifact.facts(),
    )
    .expect("the facts the collector states hold");
    let lane = lane_defined_in(&artifact, READER);
    let SourceCallArgumentValue::Value(carrier) = the_argument(&artifact).value else {
        panic!("the carrier is a value");
    };
    // The return in `CALLER`, which the `READER` arm does not lead to.
    let graph = artifact.graph();
    let at = (artifact.facts().boundaries.returns.iter())
        .map(|(at, _)| at)
        .find(|at| {
            graph
                .walk_start(*at)
                .is_some_and(|(block, _)| block == CALLER)
        })
        .expect("a return in the calling block");
    let cases = [
        call_forgeries(lane, carrier),
        return_forgeries(lane, at),
        branch_forgeries(lane),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    assert_eq!(cases.len(), 8);
    for (fact, forge) in cases {
        assert_eq!(refused_for(&artifact, fact, forge), fact);
    }
}

#[test]
fn a_value_is_defined_before_the_operations_after_its_definition_and_not_those_up_to_it() {
    let artifact = lane_call(true);
    let (function, graph) = (artifact.function(), artifact.graph());
    let before = |value, block, ordinal| {
        crate::integrity::defined_before(function, graph, value, block, ordinal)
    };
    // An operation's output is defined for the operations after it, not for itself or the ones before.
    let lane = lane_defined_in(&artifact, MERGE);
    let (block, ordinal) = graph
        .def_inst(lane)
        .and_then(|inst| graph.walk_start(inst))
        .expect("the lane is an operation's output");
    assert!(!before(lane, block, ordinal));
    assert!(before(lane, block, ordinal + 1));
    assert!(before(lane, block, usize::MAX));
    // A phi is defined at its block's entry, for every operation in it.
    let carrier = (the_argument(&artifact).lane_of).expect("the carrier the lane is of");
    assert_eq!(defined_in(&artifact, carrier), (MERGE, true));
    assert!(before(carrier, MERGE, 0));
    // The merge dominates both arms below it.
    assert!(before(carrier, CALLER, 0));
    assert!(before(lane, READER, 0));
    assert!(before(lane, CALLER, 0));
    // A value the function was entered with, and a constant, are defined before everything.
    let entry = artifact
        .graph()
        .values
        .iter()
        .find(|v| artifact.graph().def_inst(v.id).is_none());
    assert!(entry.is_some_and(|value| before(value.id, CALLER, 0)));
    // A definition on one arm reaches neither the other arm nor the merge above it.
    let other_arm = lane_call(false);
    let lane = lane_defined_in(&other_arm, READER);
    let (function, graph) = (other_arm.function(), other_arm.graph());
    let on_the_arm =
        |block, ordinal| crate::integrity::defined_before(function, graph, lane, block, ordinal);
    assert!(!on_the_arm(CALLER, 0) && !on_the_arm(MERGE, usize::MAX));
    assert!(on_the_arm(READER, usize::MAX));
}

#[cfg(feature = "fact_mutants")]
#[test]
fn an_unsound_lane_is_refused_by_the_check_of_the_sealed_facts() {
    use crate::fact_mutants::{Facts, with_facts};
    // The lane on the other arm is what the pick would state; sealing the function refuses it.
    let refused = with_facts(Facts::UnsoundLanes, || sealed_lane_call(false));
    assert!(matches!(
        refused,
        Err(crate::SsaPrepareError::Integrity(
            crate::IntegrityRule::BoundaryValueNotDominated
        ))
    ));
    // Unchecked, that fact is stated: the lane defined on the `READER` arm, of the merge's vector.
    let unchecked = with_facts(Facts::UnsoundLanesUnchecked, || sealed_lane_call(false))
        .expect("sealed without the check");
    let argument = the_argument(&unchecked);
    let SourceCallArgumentValue::Value(lane) = argument.value else {
        panic!("a value: {argument:?}");
    };
    assert_eq!(defined_in(&unchecked, lane), (READER, false));
    assert!(argument.lane_of.is_some());
    // A lane read above the branch stands behind the call: the same pick, nothing to refuse.
    assert!(with_facts(Facts::UnsoundLanes, || sealed_lane_call(true)).is_ok());
}

/// `v` entered and read by `reads`, then a return: the artifact whose entry `v` the index reads.
fn entry_read(reads: Vec<R2ILOp>) -> SsaArtifact {
    let revision = b"entry-read";
    let interface = SourceFunctionInterface::new_exact(
        revision.to_vec(),
        r2source::ConventionId::SysVAmd64,
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x80, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x88, 8)))
    .expect("a function interface");
    let ret = R2ILOp::Return {
        target: make_reg(0x80, 8),
    };
    SsaArtifact::for_decompile_with_interfaces_and_control(
        &[block(0x1000, [reads, vec![ret]].concat())],
        Some(&crate::Arch::from(lane_arch())),
        Some(interface),
        crate::SourceMachineRoles::default(),
        Vec::new(),
        crate::testing::conventions([], [storage(0x88, 8)]),
        &crate::control::UncheckedSsaWorkControl,
    )
    .expect("the entry read prepares")
}

/// Whether the index admits a held lane `bytes` wide of the entry `v` in `artifact`.
fn admits(artifact: &SsaArtifact, bytes: u32) -> bool {
    let graph = artifact.graph();
    let entry = (graph.values.iter())
        .find(|value| {
            value.canonical_storage == Some(storage(VECTOR, 16))
                && value.var.version == 0
                && graph.def_inst(value.id).is_none()
        })
        .expect("the entry v");
    let widths = crate::semantic::HeldLaneWidths::of(graph, artifact.machine_context());
    widths.admits(graph, None, entry.id, bytes)
}

/// One index per function answers every held lane (ROADMAP D105): a subpiece reads its end, and
/// a whole read reads past every lane.
#[test]
fn an_entry_carrier_s_widest_read_is_indexed_once_for_every_held_lane() {
    let low = entry_read(lane_read());
    assert!(admits(&low, 4));
    assert!(admits(&low, 8));
    assert!(!admits(&low, 2));
    let whole = entry_read(vec![R2ILOp::Store {
        space: SpaceId::Ram,
        addr: make_const(0x3000, 8),
        val: make_reg(VECTOR, 16),
    }]);
    assert!(!admits(&whole, 8));
    assert!(
        admits(&whole, 16),
        "a lane as wide as the register narrows nothing"
    );
}
