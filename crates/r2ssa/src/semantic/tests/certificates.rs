//! What the collector certifies about the body.

use super::super::*;
use super::*;

#[test]
fn callee_stack_allocation_reaches_unchanged_sp_through_loop_fixpoint() {
    let sp = Varnode::register(32, 8);
    let mut entry = R2ILBlock::new(0x6080, 4);
    entry.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    entry.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: Varnode::register(16, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x6090, 8),
    });

    let mut header = R2ILBlock::new(0x6090, 4);
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x6090, 8),
        cond: Varnode::register(24, 1),
    });

    let mut exit = R2ILBlock::new(0x6094, 4);
    exit.push(R2ILOp::Load {
        dst: Varnode::unique(0x6080, 8),
        space: SpaceId::Ram,
        addr: sp,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("exact downward stack allocation roles");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[entry, header, exit],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("loop stack allocation artifact");
    let [store] = artifact
        .inst_at(0x6080, 1)
        .and_then(|inst| artifact.memory_defs_for_inst(inst))
        .expect("saved stack definition")
    else {
        panic!("one saved stack definition")
    };
    let [load] = artifact
        .inst_at(0x6094, 0)
        .and_then(|inst| artifact.memory_uses_for_inst(inst))
        .expect("saved stack use after loop")
    else {
        panic!("one saved stack use")
    };
    assert_eq!(store.location.object, load.location.object);
    let certificate = artifact
        .certificates()
        .stack_slots
        .get(&store.location.object)
        .and_then(|slot| slot.callee_allocation.as_ref())
        .expect("loop-stable SP must certify the callee allocation");
    assert_eq!(certificate.entry_offset, -8);
    assert_eq!(certificate.size_bytes, 8);
    assert_eq!(certificate.active_sp_offsets.as_ref(), [-8]);
}

/// A pre-index store writes below the stack pointer and moves it there in one
/// instruction; the instruction's end owns the slot, so the callee allocates it.
#[test]
fn a_pre_index_store_is_allocated_by_its_own_instruction() {
    let sp = Varnode::register(32, 8);
    let below = Varnode::unique(0x6100, 8);
    let mut push = R2ILBlock::new(0x6100, 4);
    push.push(R2ILOp::IntSub {
        dst: below.clone(),
        a: sp.clone(),
        b: Varnode::constant(16, 8),
    });
    push.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: below.clone(),
        val: Varnode::register(40, 8),
    });
    push.push(R2ILOp::Copy {
        dst: sp.clone(),
        src: below,
    });
    for index in 0..push.ops.len() {
        push.stamp_instruction(index, 0x6100);
    }
    let mut pop = R2ILBlock::new(0x6104, 4);
    pop.push(R2ILOp::Load {
        dst: Varnode::register(40, 8),
        space: SpaceId::Ram,
        addr: sp.clone(),
    });
    pop.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(16, 8),
    });
    for index in 0..pop.ops.len() {
        pop.stamp_instruction(index, 0x6104);
    }
    let mut ret = R2ILBlock::new(0x6108, 4);
    ret.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("exact downward stack allocation roles");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[push, pop, ret],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("pre-index artifact");
    let [store] = artifact
        .inst_at(0x6100, 1)
        .and_then(|inst| artifact.memory_defs_for_inst(inst))
        .expect("the pre-index store")
    else {
        panic!("one saved definition")
    };
    let certificate = artifact
        .certificates()
        .stack_slots
        .get(&store.location.object)
        .and_then(|slot| slot.callee_allocation.as_ref())
        .expect("the instruction's own stack pointer write allocates the slot");
    assert_eq!(certificate.entry_offset, -16);
    assert_eq!(certificate.active_sp_offsets.as_ref(), [-16]);
}

#[test]
fn frame_pointer_round_trip_certificate_owns_exact_graph_cells() {
    let sp = Varnode::register(32, 8);
    let fp = Varnode::register(40, 8);
    let saved_fp = Varnode::unique(0x60a0, 8);
    let reloaded_fp = Varnode::unique(0x60a8, 8);
    let mut entry = R2ILBlock::new(0x60a0, 4);
    entry.push(R2ILOp::Copy {
        dst: saved_fp.clone(),
        src: fp.clone(),
    });
    entry.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    entry.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: saved_fp,
    });
    entry.push(R2ILOp::Copy {
        dst: fp.clone(),
        src: sp.clone(),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x60b0, 8),
    });

    let mut header = R2ILBlock::new(0x60b0, 4);
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x60b0, 8),
        cond: Varnode::register(24, 1),
    });

    let mut exit = R2ILBlock::new(0x60b4, 4);
    exit.push(R2ILOp::Load {
        dst: reloaded_fp.clone(),
        space: SpaceId::Ram,
        addr: sp.clone(),
    });
    exit.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(8, 8),
    });
    exit.push(R2ILOp::Copy {
        dst: fp,
        src: reloaded_fp,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    let frame_storage = register_storage(40, 8);
    let interface = preserved_stack_interface()
        .with_frame_pointer_storage(frame_storage)
        .expect("exact frame-pointer carrier");
    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("exact downward stack allocation roles");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[entry, header, exit],
        Some(&return_boundary_arch()),
        Some(interface),
        roles,
        Vec::new(),
    )
    .expect("frame round-trip artifact");
    let [store] = artifact
        .inst_at(0x60a0, 2)
        .and_then(|inst| artifact.memory_defs_for_inst(inst))
        .expect("frame save")
    else {
        panic!("one frame save")
    };
    let certificate = artifact
        .certificates()
        .stack_frame_round_trips
        .get(&store.location.object)
        .expect("exact frame save/reload certificate");
    let inst_sites = certificate
        .insts
        .iter()
        .filter_map(|inst| artifact.graph().walk_start(*inst))
        .collect::<BTreeSet<_>>();
    assert_eq!(certificate.storage, frame_storage);
    assert_eq!(
        artifact.graph().walk_start(certificate.store_access.inst),
        Some((0x60a0, 2))
    );
    assert_eq!(certificate.load_accesses.len(), 1);
    assert_eq!(
        inst_sites,
        // The save copy is forwarded into the store and read by nothing,
        // so the round trip is the store, the reload and the restore.
        BTreeSet::from([(0x60a0, 2), (0x60b4, 0), (0x60b4, 2)])
    );
    // Every read of a round-trip value is inside the round trip, or is
    // the forwarded save copy that nothing reads.
    assert!(certificate.values.iter().all(|value| {
        artifact.graph().use_sites(*value).iter().all(|site| {
            certificate.insts.contains(&site.inst)
                || artifact.graph().inst(site.inst).is_some_and(|inst| {
                    matches!(inst.payload, InstPayload::Op(SSAOp::Copy { .. }))
                        && inst
                            .output
                            .is_some_and(|out| artifact.graph().use_sites(out).is_empty())
                })
        })
    }));
    assert!(certificate.insts.iter().all(|inst| {
        artifact
            .certificates()
            .stack_frame_round_trip_by_inst
            .get(*inst)
            == Some(&store.location.object)
    }));
    let geometry_sites = artifact
        .certificates()
        .stack_geometry
        .insts
        .iter()
        .filter_map(|inst| artifact.graph().walk_start(inst))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        geometry_sites,
        BTreeSet::from([(0x60a0, 1), (0x60a0, 3), (0x60b4, 1)])
    );
    let stack_sub = artifact
        .graph()
        .inst_spelled_at(0x60a0, 1)
        .expect("stack subtraction instruction");
    assert!(
        artifact
            .certificates()
            .stack_geometry
            .uses
            .contains(&crate::UseSite {
                inst: stack_sub,
                input_idx: 0,
            })
    );
}

/// A save/restore pair still certifies when the only thing outside the
/// round trip that names the saved entry value is a merge nothing observes.
///
/// The lifted body merges every storage live across a join, so a register
/// the program overwrites at a loop head still collects a phi carrying its
/// entry value on the entry edge. Counting that phi as a read left the
/// prologue store rendered and its slot set but never used.
#[test]
fn frame_round_trip_certifies_through_a_merge_no_observation_depends_on() {
    let sp = Varnode::register(32, 8);
    let saved = Varnode::register(0, 8);
    let spilled = Varnode::unique(0x70a0, 8);
    let reloaded = Varnode::unique(0x70a8, 8);

    let mut entry = R2ILBlock::new(0x7000, 4);
    entry.push(R2ILOp::Copy {
        dst: spilled.clone(),
        src: saved.clone(),
    });
    entry.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    entry.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: spilled,
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7010, 8),
    });

    // The loop head overwrites the register before anything reads it, so
    // the merge its entry value reaches carries no observation.
    let mut header = R2ILBlock::new(0x7010, 4);
    header.push(R2ILOp::Copy {
        dst: saved.clone(),
        src: Varnode::constant(5, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7010, 8),
        cond: Varnode::register(24, 1),
    });

    let mut exit = R2ILBlock::new(0x7014, 4);
    exit.push(R2ILOp::Load {
        dst: reloaded.clone(),
        space: SpaceId::Ram,
        addr: sp.clone(),
    });
    exit.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(8, 8),
    });
    exit.push(R2ILOp::Copy {
        dst: saved,
        src: reloaded,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("exact downward stack allocation roles");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[entry, header, exit],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("callee-saved round-trip artifact");
    let [store] = artifact
        .inst_at(0x7000, 2)
        .and_then(|inst| artifact.memory_defs_for_inst(inst))
        .expect("callee-saved save")
    else {
        panic!("one callee-saved save")
    };
    let certificate = artifact
        .certificates()
        .stack_frame_round_trips
        .get(&store.location.object)
        .expect("an unobserved merge must not revoke the save/reload proof");
    assert_eq!(certificate.storage, register_storage(0, 8));

    let escaping = certificate
        .values
        .iter()
        .flat_map(|value| artifact.graph().use_sites(*value))
        .filter(|site| !certificate.insts.contains(&site.inst))
        .collect::<Vec<_>>();
    assert!(
        !escaping.is_empty(),
        "this function must reproduce the escaping merge the certificate has to discount"
    );
    assert!(
        escaping.iter().all(|site| artifact
            .unobserved_merges()
            .unobserved_uses()
            .contains(site)),
        "only uses no program observation depends on may be discounted"
    );
}

#[test]
fn stack_geometry_certificate_closes_equal_root_merge_phi() {
    let sp = Varnode::register(32, 8);
    let address = Varnode::unique(0x60c0, 8);
    let mut entry = R2ILBlock::new(0x60c0, 4);
    entry.push(R2ILOp::CBranch {
        target: Varnode::ram(0x60c8, 8),
        cond: Varnode::register(24, 1),
    });

    let mut right = R2ILBlock::new(0x60c4, 4);
    right.push(R2ILOp::IntSub {
        dst: address.clone(),
        a: sp.clone(),
        b: Varnode::constant(16, 8),
    });
    right.push(R2ILOp::Branch {
        target: Varnode::ram(0x60cc, 8),
    });

    let mut left = R2ILBlock::new(0x60c8, 4);
    left.push(R2ILOp::IntSub {
        dst: address.clone(),
        a: sp,
        b: Varnode::constant(16, 8),
    });
    left.push(R2ILOp::Branch {
        target: Varnode::ram(0x60cc, 8),
    });

    let mut joined = R2ILBlock::new(0x60cc, 4);
    joined.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address,
        val: Varnode::constant(7, 8),
    });
    joined.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    let artifact = SsaArtifact::for_decompile_with_interface(
        &[entry, right, left, joined],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("equal-root stack merge artifact");
    let phi = artifact
        .function()
        .named_block(0x60cc)
        .and_then(|block| block.phis().first().cloned())
        .expect("stack-address merge phi");
    let phi_value = artifact
        .graph()
        .value_id_for_var(&phi.dst)
        .expect("stack-address phi value");
    let phi_inst = artifact
        .graph()
        .def_inst(phi_value)
        .expect("stack-address phi instruction");
    let geometry = &artifact.certificates().stack_geometry;

    assert_eq!(
        artifact.entry_stack_address_root_for_value(phi_value),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -16,
        })
    );
    assert!(geometry.values.contains(phi_value));
    assert!(geometry.insts.contains(phi_inst));
    assert!(artifact.graph().inst(phi_inst).is_some_and(|inst| {
        matches!(inst.payload, InstPayload::Phi { .. })
            && inst
                .inputs
                .iter()
                .all(|input| geometry.values.contains(*input))
    }));
}

#[test]
fn stack_geometry_certificate_closes_the_call_restore() {
    let sp = Varnode::register(32, 8);
    let ra = Varnode::register(16, 8);
    let mut block = R2ILBlock::new(0x60c0, 16);
    // The frame, then one call instruction: push the return address, call.
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(16, 8),
    });
    block.stamp_instruction(0, 0x60c0);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: ra,
    });
    block.push(R2ILOp::Call {
        target: Varnode::ram(0x7000, 8),
    });
    for index in 1..=3 {
        block.stamp_instruction(index, 0x60c4);
    }
    let address = Varnode::unique(0x60c0, 8);
    block.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: sp,
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address,
        val: Varnode::constant(7, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    for index in 4..=6 {
        block.stamp_instruction(index, 0x60c9);
    }

    let artifact = crate::testing::prepared(
        &[block],
        &return_boundary_arch(),
        Some(preserved_stack_interface()),
        Vec::new(),
        [register_storage(16, 8), register_storage(32, 8)],
    )
    .expect("call restore artifact");
    let graph = artifact.graph();
    let restore = graph
        .insts
        .iter()
        .find(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::CallRestore { .. })))
        .expect("the call restores the carrier the convention preserves");
    let output = restore.output.expect("restore output");
    let geometry = &artifact.certificates().stack_geometry;

    assert_eq!(
        artifact.entry_stack_address_root_for_value(output),
        Some(StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -16,
        })
    );
    assert!(geometry.insts.contains(restore.id));
    assert!(geometry.values.contains(output));
    assert!(geometry.values.contains(restore.inputs[0]));
}

#[test]
fn machine_return_control_certificate_owns_exact_stack_reload() {
    let sp = Varnode::register(32, 8);
    let ra = Varnode::register(16, 8);
    let mut block = R2ILBlock::new(0x60c0, 4);
    block.push(R2ILOp::Load {
        dst: ra.clone(),
        space: SpaceId::Ram,
        addr: sp.clone(),
    });
    block.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Return { target: ra });
    let artifact = SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&return_boundary_arch()),
        preserved_stack_interface(),
    )
    .expect("stack return-control artifact");
    let return_inst = artifact
        .graph()
        .inst_spelled_at(0x60c0, 2)
        .expect("return instruction");
    let load_inst = artifact
        .graph()
        .inst_spelled_at(0x60c0, 0)
        .expect("return-address load");
    let certificate = artifact
        .certificates()
        .machine_return_controls
        .get(return_inst)
        .expect("machine return-control certificate");
    assert_eq!(certificate.storage, register_storage(16, 8));
    assert_eq!(certificate.insts, BTreeSet::from([load_inst]));
    assert_eq!(
        certificate.uses,
        BTreeSet::from([crate::UseSite {
            inst: load_inst,
            input_idx: 0,
        }])
    );
    assert_eq!(
        artifact
            .certificates()
            .machine_return_control_by_inst
            .get(load_inst),
        Some(&return_inst)
    );
    assert!(
        !artifact
            .certificates()
            .stack_geometry
            .uses
            .contains(&crate::UseSite {
                inst: load_inst,
                input_idx: 0,
            })
    );
}

/// A 32-byte frame around `body`, which addresses it through the stack pointer.
fn framed_artifact(body: impl FnOnce(&mut R2ILBlock, &Varnode)) -> SsaArtifact {
    framed_artifact_growing(SourceStackGrowth::LowerAddresses, body)
}

/// `framed_artifact`, under a stack the source states grows toward `growth`.
fn framed_artifact_growing(
    growth: SourceStackGrowth,
    body: impl FnOnce(&mut R2ILBlock, &Varnode),
) -> SsaArtifact {
    let sp = Varnode::register(32, 8);
    let mut block = R2ILBlock::new(0x7000, 16);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(32, 8),
    });
    body(&mut block, &sp);
    block.push(R2ILOp::IntAdd {
        dst: sp.clone(),
        a: sp,
        b: Varnode::constant(32, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    for index in 0..block.ops.len() {
        block.stamp_instruction(index, 0x7000 + index as u64);
    }
    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(growth))
            })
            .expect("exact stack allocation roles");
    let preserved = [register_storage(16, 8), register_storage(32, 8)];
    SsaArtifact::for_decompile_with(
        &[block],
        crate::DecompileInputs {
            arch: Some(&return_boundary_arch()),
            function_interface: Some(preserved_stack_interface()),
            machine_roles: roles,
            call_effect: crate::testing::call_effect([], preserved),
            ..Default::default()
        },
    )
    .expect("framed artifact")
}

/// `sp + offset + index`, the index masked to 0..16 when `bounded` and unbounded otherwise.
fn indexed_address(
    block: &mut R2ILBlock,
    sp: &Varnode,
    (offset, bounded): (u64, bool),
    unique: u64,
) -> Varnode {
    let index = Varnode::unique(unique, 8);
    block.push(R2ILOp::IntAnd {
        dst: index.clone(),
        a: Varnode::register(24, 8),
        b: Varnode::constant(if bounded { 0xf } else { u64::MAX }, 8),
    });
    let base = Varnode::unique(unique + 8, 8);
    block.push(R2ILOp::IntAdd {
        dst: base.clone(),
        a: sp.clone(),
        b: Varnode::constant(offset, 8),
    });
    let address = Varnode::unique(unique + 16, 8);
    block.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: base,
        b: index,
    });
    address
}

/// A byte store into the frame at `sp + 8 + index`.
fn indexed_byte_store(block: &mut R2ILBlock, sp: &Varnode, bounded: bool) {
    let address = indexed_address(block, sp, (8, bounded), 0x100);
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address,
        val: Varnode::register(40, 1),
    });
}

/// Whether the byte store is owned by the function, and whether it is certified dead.
fn store_ownership(artifact: &SsaArtifact) -> (bool, bool) {
    let store = (artifact.structured().memory_accesses.values())
        .find(|access| access.is_write && access.width == 1)
        .expect("the byte store")
        .id
        .inst;
    let certificates = artifact.certificates();
    let owned = certificates.stack_slots.values().any(|slot| {
        slot.callee_allocation.as_ref().is_some_and(|allocation| {
            allocation
                .accesses
                .iter()
                .any(|access| access.inst == store)
        })
    });
    (owned, certificates.dead_frame_stores.contains(store))
}

#[test]
fn a_write_only_owned_private_slot_is_a_dead_store() {
    let artifact = framed_artifact(|block, sp| indexed_byte_store(block, sp, true));
    assert_eq!(
        store_ownership(&artifact),
        (true, true),
        "{:?}",
        artifact.certificates().stack_slots
    );
}

#[test]
fn a_slot_whose_address_escapes_is_not_a_dead_store() {
    let artifact = framed_artifact(|block, sp| {
        indexed_byte_store(block, sp, true);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
            val: sp.clone(),
        });
    });
    assert_eq!(store_ownership(&artifact), (true, false));
}

#[test]
fn a_slot_a_call_may_reach_is_not_a_dead_store() {
    let artifact = framed_artifact(|block, sp| {
        indexed_byte_store(block, sp, true);
        block.push(R2ILOp::Call {
            target: Varnode::ram(0x8000, 8),
        });
    });
    assert_eq!(store_ownership(&artifact), (true, false));
}

#[test]
fn a_store_at_an_unbounded_index_is_not_a_dead_store() {
    let artifact = framed_artifact(|block, sp| indexed_byte_store(block, sp, false));
    assert_eq!(store_ownership(&artifact), (true, false));
}

#[test]
fn a_frame_read_at_an_unbounded_index_keeps_every_store() {
    let artifact = framed_artifact(|block, sp| {
        indexed_byte_store(block, sp, true);
        // Below the store's object: only the missing bound lets it reach the store.
        let address = indexed_address(block, sp, (0, false), 0x200);
        block.push(R2ILOp::Load {
            dst: Varnode::register(48, 1),
            space: SpaceId::Ram,
            addr: address,
        });
    });
    assert_eq!(store_ownership(&artifact), (true, false));
}

/// The frame with a stored slot at `sp + 8` and the address `sp + escaped` written to a global.
fn escaped_frame_address(escaped: u64) -> (SsaArtifact, InstId) {
    escaped_frame_address_growing(SourceStackGrowth::LowerAddresses, escaped)
}

fn escaped_frame_address_growing(growth: SourceStackGrowth, escaped: u64) -> (SsaArtifact, InstId) {
    let artifact = framed_artifact_growing(growth, |block, sp| {
        let slot = Varnode::unique(0x200, 8);
        block.push(R2ILOp::IntAdd {
            dst: slot.clone(),
            a: sp.clone(),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: slot,
            val: Varnode::constant(7, 8),
        });
        let address = Varnode::unique(0x208, 8);
        block.push(R2ILOp::IntAdd {
            dst: address.clone(),
            a: sp.clone(),
            b: Varnode::constant(escaped, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
            val: address,
        });
    });
    let adjust = artifact
        .graph()
        .inst_spelled_at(0x7000, 0)
        .expect("the frame allocation");
    (artifact, adjust)
}

#[test]
fn an_adjustment_read_only_to_name_a_frame_object_is_frame_setup() {
    let (artifact, adjust) = escaped_frame_address(8);
    let geometry = &artifact.certificates().stack_geometry;
    assert!(
        !geometry.insts.contains(adjust),
        "the address escapes the geometry"
    );
    assert!(geometry.frame_setup.contains(adjust), "{geometry:?}");
}

#[test]
fn an_adjustment_read_to_name_a_caller_slot_is_not_frame_setup() {
    let (artifact, adjust) = escaped_frame_address(40);
    assert!(
        !artifact
            .certificates()
            .stack_geometry
            .frame_setup
            .contains(adjust)
    );
}

/// On a stack that grows to higher addresses, the bytes below the entry stack pointer are the
/// caller's: an address there names no object of this frame, so reading `sp` for it is no setup.
#[test]
fn an_upward_stack_never_takes_the_downward_frame_rule() {
    let (artifact, adjust) = escaped_frame_address_growing(SourceStackGrowth::HigherAddresses, 8);
    let geometry = &artifact.certificates().stack_geometry;
    assert!(!geometry.frame_setup.contains(adjust), "{geometry:?}");
}

/// A frame slot written whole and read back narrower, so the read stays a memory access; `observe`
/// stores what was read to a global, else the register is overwritten unread.
fn narrow_reread(observe: bool) -> (SsaArtifact, InstId) {
    let artifact = framed_artifact(|block, sp| {
        let slot = Varnode::unique(0x300, 8);
        block.push(R2ILOp::IntAdd {
            dst: slot.clone(),
            a: sp.clone(),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: slot.clone(),
            val: Varnode::register(24, 8),
        });
        let read = Varnode::register(48, 4);
        block.push(R2ILOp::Load {
            dst: read.clone(),
            space: SpaceId::Ram,
            addr: slot,
        });
        let val = match observe {
            true => read,
            false => Varnode::constant(0, 4),
        };
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
            val,
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(48, 4),
            src: Varnode::constant(0, 4),
        });
    });
    let load = (artifact.structured().memory_accesses.values())
        .find(|access| !access.is_write)
        .unwrap_or_else(|| panic!("the read: {:?}", artifact.structured().memory_accesses))
        .id
        .inst;
    // The shape the renderer's pending-seeding exception asks about: a seeded private read.
    let seeded = (artifact.facts().obligations.obligations_for_inst(load))
        .any(|o| o.id.kind == crate::SemanticObligationKind::LiveValueProducer);
    assert!(seeded, "{load:?}");
    (artifact, load)
}

#[test]
fn a_private_read_nothing_observes_is_certified_unobserved() {
    let (artifact, load) = narrow_reread(false);
    assert!(
        artifact
            .certificates()
            .unobserved_private_reads
            .contains(load)
    );
}

/// Staged excuses only a certified read, so a dropped observed read stays unaccounted and refuses.
#[test]
fn a_private_read_whose_value_is_stored_is_not_certified_unobserved() {
    let (artifact, load) = narrow_reread(true);
    assert!(
        !artifact
            .certificates()
            .unobserved_private_reads
            .contains(load)
    );
}

/// The objects of the frame's indexed accesses, in access order.
fn indexed_objects(artifact: &SsaArtifact) -> Vec<crate::ObjectId> {
    (artifact.structured().memory_accesses.values())
        .filter(|access| artifact.objects().address_is_indexed(access.address))
        .map(|access| access.object)
        .collect()
}

#[test]
fn a_bounded_store_beside_an_unbounded_one_is_not_a_dead_store() {
    let artifact = framed_artifact(|block, sp| {
        for (bounded, unique) in [(true, 0x100), (false, 0x200)] {
            let address = indexed_address(block, sp, (8, bounded), unique);
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: address,
                val: Varnode::register(40, 1),
            });
        }
    });
    let objects = indexed_objects(&artifact);
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0], objects[1], "both stores reach one object");
    let certificates = artifact.certificates();
    assert!(
        certificates.stack_slots[&objects[0]]
            .callee_allocation
            .is_some()
    );
    assert!(certificates.dead_frame_stores.is_empty());
}

/// An unbounded byte read at `sp + index` beside a halfword read at `sp`: two widths, so the
/// object has no callee allocation; with `owned_store`, a bounded write-only store at `sp + 8`.
fn unowned_unbounded_read_artifact(owned_store: bool) -> SsaArtifact {
    framed_artifact(|block, sp| {
        if owned_store {
            indexed_byte_store(block, sp, true);
        }
        let address = indexed_address(block, sp, (0, false), 0x200);
        block.push(R2ILOp::Load {
            dst: Varnode::register(48, 1),
            space: SpaceId::Ram,
            addr: address,
        });
        block.push(R2ILOp::Load {
            dst: Varnode::register(56, 2),
            space: SpaceId::Ram,
            addr: sp.clone(),
        });
    })
}

#[test]
fn an_unbounded_index_into_an_unowned_object_leaves_its_extent_assumed() {
    let artifact = unowned_unbounded_read_artifact(false);
    let object = indexed_objects(&artifact)[0];
    let slot = &artifact.certificates().stack_slots[&object];
    assert!(slot.callee_allocation.is_none(), "{slot:?}");
    assert!(!matches!(
        slot.array_layout,
        crate::StackArrayLayoutDisposition::Proven(_)
    ));
    assert_eq!(
        artifact.extent_assumption(object),
        Some(crate::ExtentAssumption::UnboundedIndex)
    );
}

#[test]
fn an_unbounded_read_of_an_unowned_object_keeps_every_store() {
    let artifact = unowned_unbounded_read_artifact(true);
    assert_eq!(store_ownership(&artifact), (true, false));
}
