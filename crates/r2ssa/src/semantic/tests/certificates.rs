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
        .memory_defs_for_op_site(0x6080, 1)
        .expect("saved stack definition")
    else {
        panic!("one saved stack definition")
    };
    let [load] = artifact
        .memory_uses_for_op_site(0x6094, 0)
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
        .memory_defs_for_op_site(0x60a0, 2)
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
        .filter_map(|inst| artifact.graph().op_site_for_inst(*inst))
        .collect::<BTreeSet<_>>();
    assert_eq!(certificate.storage, frame_storage);
    assert_eq!(
        artifact
            .graph()
            .op_site_for_inst(certificate.store_access.inst),
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
            .get(inst)
            == Some(&store.location.object)
    }));
    let geometry_sites = artifact
        .certificates()
        .stack_geometry
        .insts
        .iter()
        .filter_map(|inst| artifact.graph().op_site_for_inst(*inst))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        geometry_sites,
        BTreeSet::from([(0x60a0, 1), (0x60a0, 3), (0x60b4, 1)])
    );
    let stack_sub = artifact
        .graph()
        .inst_id_for_op_site(0x60a0, 1)
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
        .memory_defs_for_op_site(0x7000, 2)
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
        .get_block(0x60cc)
        .and_then(|block| block.phis.first())
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
    assert!(geometry.values.contains(&phi_value));
    assert!(geometry.insts.contains(&phi_inst));
    assert!(artifact.graph().inst(phi_inst).is_some_and(|inst| {
        matches!(inst.payload, InstPayload::Phi { .. })
            && inst
                .inputs
                .iter()
                .all(|input| geometry.values.contains(input))
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

    let artifact = SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&return_boundary_arch()),
        preserved_stack_interface().with_preserved_call_carriers(true, false),
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
    assert!(geometry.insts.contains(&restore.id));
    assert!(geometry.values.contains(&output));
    assert!(geometry.values.contains(&restore.inputs[0]));
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
        .inst_id_for_op_site(0x60c0, 2)
        .expect("return instruction");
    let load_inst = artifact
        .graph()
        .inst_id_for_op_site(0x60c0, 0)
        .expect("return-address load");
    let certificate = artifact
        .certificates()
        .machine_return_controls
        .get(&return_inst)
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
            .get(&load_inst),
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
