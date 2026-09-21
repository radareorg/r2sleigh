//! What the collector proves about the frame's objects.

use super::super::*;
use super::*;

#[test]
fn same_value_id_is_space_keyed_for_global_stack_parameter_and_unknown_objects() {
    let global = dual_space_artifact(Vec::new(), Varnode::constant(0x4000, 8), None);
    assert_dual_space_objects_are_distinct(&global);
    let (ram_global, custom_global) = dual_space_locations(&global);
    assert!(matches!(
        global
            .objects()
            .object(ram_global.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::Global {
            space: SpaceId::Ram,
            address: 0x4000
        })
    ));
    assert!(matches!(
        global
            .objects()
            .object(custom_global.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::Global {
            space: SpaceId::Custom(7),
            address: 0x4000
        })
    ));

    let mut arch = ArchSpec::new("aarch64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("x0", 0, 8));
    arch.add_register(RegisterDef::new("sp", 16, 8));

    let parameter = dual_space_exact_parameter_artifact(&arch);
    assert_dual_space_objects_are_distinct(&parameter);
    let (ram_parameter, custom_parameter) = dual_space_locations(&parameter);
    assert!(matches!(
        parameter
            .objects()
            .object(ram_parameter.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::Parameter {
            space: SpaceId::Ram,
            index: 0
        })
    ));
    assert!(matches!(
        parameter
            .objects()
            .object(custom_parameter.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::EscapedUnknown {
            space: SpaceId::Custom(7)
        })
    ));
    assert_eq!(custom_parameter.address, RelativeMemoryAddress::Unknown);

    let stack = dual_space_artifact(Vec::new(), Varnode::unique(0x80, 8), Some(&arch));
    let stack_addr = stack
        .get_block(0x1000)
        .and_then(|block| {
            block.ops.iter().find_map(|op| match op {
                crate::SSAOp::Load { addr, .. } => Some(addr.clone()),
                _ => None,
            })
        })
        .expect("stack address");
    let mut stack_facts = DecompilePrepFacts::default();
    stack_facts.stack_address_roots.insert(
        stack_addr.clone(),
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -8,
        },
    );
    let stack_declared = super::super::DeclaredStackSlots::default();
    let stack_objects = super::super::ObjectModelBuilder::new(
        Some(&stack_facts),
        stack.addresses(),
        &stack_declared,
        Some(stack.machine_context()),
    )
    .build(
        stack.function(),
        stack.graph(),
        super::super::empty_value_ranges(),
    );
    let ram_stack = super::super::memory_location_for_addr(
        Some(&stack_facts),
        stack.addresses(),
        &stack_objects,
        stack.graph(),
        &stack_addr,
        SpaceId::Ram,
        8,
    );
    let custom_stack = super::super::memory_location_for_addr(
        Some(&stack_facts),
        stack.addresses(),
        &stack_objects,
        stack.graph(),
        &stack_addr,
        SpaceId::Custom(7),
        8,
    );
    assert_ne!(ram_stack.object, custom_stack.object);
    assert!(!memory_locations_may_alias(
        &stack_objects,
        &ram_stack,
        &custom_stack
    ));
    let ram_stack_kind = stack_objects
        .object(ram_stack.object)
        .map(|fact| &fact.kind);
    assert!(
        matches!(
            ram_stack_kind,
            Some(
                ObjectKind::StackSlot {
                    space: SpaceId::Ram,
                    ..
                } | ObjectKind::FrameObject {
                    space: SpaceId::Ram,
                    ..
                }
            )
        ),
        "unexpected RAM stack object: {ram_stack_kind:?}"
    );
    assert!(matches!(
        stack_objects
            .object(custom_stack.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::EscapedUnknown {
            space: SpaceId::Custom(7)
        })
    ));
    assert_eq!(custom_stack.address, RelativeMemoryAddress::Unknown);

    let unknown = dual_space_artifact(Vec::new(), Varnode::unique(0x90, 8), None);
    assert_dual_space_objects_are_distinct(&unknown);
    let (ram_unknown, custom_unknown) = dual_space_locations(&unknown);
    assert!(matches!(
        unknown
            .objects()
            .object(ram_unknown.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::EscapedUnknown {
            space: SpaceId::Ram
        })
    ));
    assert!(matches!(
        unknown
            .objects()
            .object(custom_unknown.object)
            .map(|fact| &fact.kind),
        Some(ObjectKind::EscapedUnknown {
            space: SpaceId::Custom(7)
        })
    ));
}

/// A declared aggregate's members are one object at two displacements, so
/// they neither alias each other nor lose their positions.
#[test]
fn a_member_of_a_declared_aggregate_is_the_aggregate_at_an_offset() {
    let sp = Varnode::register(0, 8);
    let fp = Varnode::register(8, 8);
    let ra = Varnode::register(16, 8);
    let first = Varnode::unique(0x100, 8);
    let second = Varnode::unique(0x108, 8);
    let mut block = R2ILBlock::new(0x3700, 4);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: fp.clone(),
    });
    block.push(R2ILOp::Copy {
        dst: fp.clone(),
        src: sp,
    });
    // The aggregate's base, then a member eight bytes into it.
    block.push(R2ILOp::IntSub {
        dst: first.clone(),
        a: fp.clone(),
        b: Varnode::constant(32, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: first.clone(),
        val: Varnode::constant(1, 8),
    });
    block.push(R2ILOp::IntSub {
        dst: second.clone(),
        a: fp,
        b: Varnode::constant(24, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: second,
        val: Varnode::constant(2, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x110, 8),
        space: SpaceId::Ram,
        addr: first,
    });
    block.push(R2ILOp::Return { target: ra });

    let mut arch = ArchSpec::new("aggregate-member-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("sp", 0, 8));
    arch.add_register(RegisterDef::new("fp", 8, 8));
    arch.add_register(RegisterDef::new("ra", 16, 8));
    arch.add_space(r2il::AddressSpace::ram(8));
    let storage = |offset| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"aggregate-member-revision-1".to_vec(),
        "test-abi",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            storage(0),
            -40,
            16,
        )],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0)))
    .expect("exact aggregate interface");
    let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("aggregate artifact");

    let [base_store] = artifact
        .memory_defs_for_op_site(0x3700, 4)
        .expect("aggregate base definition")
    else {
        panic!("one definition at the aggregate's base")
    };
    let [member_store] = artifact
        .memory_defs_for_op_site(0x3700, 6)
        .expect("member definition")
    else {
        panic!("one definition at the member")
    };
    assert_eq!(
        base_store.location.object, member_store.location.object,
        "a member belongs to the object its aggregate owns"
    );
    assert_eq!(base_store.location.address, RelativeMemoryAddress::Exact(0));
    assert_eq!(
        member_store.location.address,
        RelativeMemoryAddress::Exact(8),
        "the member sits at its displacement inside the object"
    );
    assert!(
        !memory_locations_may_alias(
            artifact.objects(),
            &base_store.location,
            &member_store.location
        ),
        "two members that do not overlap must not alias"
    );
    let [reload] = artifact
        .memory_uses_for_op_site(0x3700, 7)
        .expect("base reload")
    else {
        panic!("one use at the aggregate's base")
    };
    assert_eq!(
        reload.version, base_store.next_version,
        "the member's store must not shadow the base's value"
    );
}

#[test]
fn memory_ssa_separates_saved_sp_slot_from_frame_relative_local() {
    let sp = Varnode::register(0, 8);
    let fp = Varnode::register(8, 8);
    let ra = Varnode::register(16, 8);
    let local_addr = Varnode::unique(0x100, 8);
    let mut block = R2ILBlock::new(0x3600, 4);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: sp.clone(),
        val: fp.clone(),
    });
    block.push(R2ILOp::Copy {
        dst: fp.clone(),
        src: sp,
    });
    block.push(R2ILOp::IntSub {
        dst: local_addr.clone(),
        a: fp,
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: local_addr.clone(),
        val: Varnode::constant(1, 4),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x108, 4),
        space: SpaceId::Ram,
        addr: local_addr,
    });
    block.push(R2ILOp::Return { target: ra });

    let mut arch = ArchSpec::new("dual-stack-coordinate-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("sp", 0, 8));
    arch.add_register(RegisterDef::new("fp", 8, 8));
    arch.add_register(RegisterDef::new("ra", 16, 8));
    arch.add_space(r2il::AddressSpace::ram(8));
    let storage = |offset| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"dual-stack-coordinate-revision-1".to_vec(),
        "test-abi",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            storage(0),
            -16,
            4,
        )],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0)))
    .expect("exact dual-coordinate interface");
    let artifact =
        SsaArtifact::for_decompile_with_interface(&[block.clone()], Some(&arch), interface.clone())
            .expect("dual-coordinate artifact");

    let [save] = artifact
        .memory_defs_for_op_site(0x3600, 1)
        .expect("saved-frame definition")
    else {
        panic!("one saved-frame definition")
    };
    let [local_store] = artifact
        .memory_defs_for_op_site(0x3600, 4)
        .expect("local definition")
    else {
        panic!("one local definition")
    };
    let [local_load] = artifact
        .memory_uses_for_op_site(0x3600, 5)
        .expect("local use")
    else {
        panic!("one local use")
    };
    assert_ne!(save.location.object, local_store.location.object);
    assert_eq!(
        local_store.previous_version.object,
        local_store.location.object
    );
    assert_eq!(local_store.previous_version.version, 0);
    assert_eq!(local_load.location, local_store.location);
    assert_eq!(local_load.version, local_store.next_version);
    assert!(matches!(
        artifact
            .objects()
            .object(save.location.object)
            .map(|object| &object.kind),
        Some(ObjectKind::StackSlot {
            base: StackAddressBase::StackPointer,
            offset: -8,
            ..
        })
    ));
    // The two are still separate objects, and now they are separated by
    // where they actually are rather than by which register named them.
    // The frame pointer is established from the stack pointer here, so it
    // has a provable entry-relative position of minus eight, and a local
    // eight below it is at minus sixteen. Naming both minus eight and
    // distinguishing them by base was the coordinate split that made one
    // slot reachable under two incomparable names.
    assert!(matches!(
        artifact
            .objects()
            .object(local_store.location.object)
            .map(|object| &object.kind),
        Some(ObjectKind::StackSlot {
            base: StackAddressBase::StackPointer,
            offset: -16,
            ..
        })
    ));
    let local_certificate = artifact
        .certificates()
        .stack_slots
        .get(&local_store.location.object)
        .expect("the frame-relative local has one prepared certificate");
    assert_eq!(
        local_certificate.size,
        Some(4),
        "the prepared certificate must retain the exact source stack-slot width"
    );
    // The certificate carries the declared slot itself: the source states
    // it in the coordinate objects are identified in.
    let declared = interface.stack_slots()[0];
    assert_eq!(
        local_certificate.source_slot,
        Some(declared),
        "the prepared certificate must retain the declared slot's width and role at its entry position"
    );
    // Each has the width its own accesses give it, and they differ. The
    // concern this replaces was that a resource could borrow a width from
    // another coordinate naming the same offset; the two are at minus eight
    // and minus sixteen now, so there is no shared name to borrow through.
    // The saved slot is written once by an eight-byte store and says eight;
    // the local is four and stays four.
    assert_eq!(
        artifact
            .certificates()
            .stack_slots
            .get(&save.location.object)
            .and_then(|slot| slot.size),
        Some(8),
        "a resource takes the width its own accesses agree on"
    );
    assert_eq!(
        artifact
            .certificates()
            .stack_slots
            .get(&save.location.object)
            .and_then(|slot| slot.callee_allocation.as_ref()),
        None,
        "machine geometry without a source allocation contract grants no object authority"
    );
    assert_eq!(
        artifact
            .objects()
            .entry_stack_roots
            .get(&save.location.object),
        Some(&StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -8,
        })
    );
    assert_eq!(
        artifact
            .objects()
            .entry_stack_roots
            .get(&local_store.location.object),
        Some(&StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -16,
        })
    );

    let allocated_roles = SourceMachineRoles::new(Some(storage(16)), Some(storage(0)))
        .and_then(|roles| {
            roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                SourceStackGrowth::LowerAddresses,
            ))
        })
        .expect("exact downward allocation contract");
    let allocated = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[block.clone()],
        Some(&arch),
        Some(interface.clone()),
        allocated_roles,
        Vec::new(),
    )
    .expect("allocated dual-coordinate artifact");
    let [allocated_save] = allocated
        .memory_defs_for_op_site(0x3600, 1)
        .expect("allocated saved-frame definition")
    else {
        panic!("one allocated saved-frame definition")
    };
    let allocation = allocated
        .certificates()
        .stack_slots
        .get(&allocated_save.location.object)
        .and_then(|slot| slot.callee_allocation.as_ref())
        .expect("the exact allocation envelope certifies the source-less spill");
    assert_eq!(allocation.entry_offset, -8);
    assert_eq!(allocation.size_bytes, 8);
    assert_eq!(allocation.active_sp_offsets.as_ref(), [-8]);
    assert!(!allocation.uses_implicit_area);

    let mut incomplete_structured = allocated.facts().structured.clone();
    for access in incomplete_structured
        .memory_accesses
        .values_mut()
        .filter(|access| access.object == allocated_save.location.object)
    {
        access.provenance_complete = false;
    }
    let allocated_facts = allocated.facts();
    let incomplete = super::super::collect_prepared_function_certificates(
        super::super::Body {
            function: allocated.function(),
            graph: allocated.graph(),
            machine_context: Some(allocated.machine_context()),
        },
        super::super::Derived {
            values: &Default::default(),
            boundaries: &allocated_facts.boundaries,
            objects: allocated.objects(),
            memory: &allocated_facts.memory,
            predicates: &allocated_facts.predicates,
            call_sites: &allocated_facts.call_sites,
            structured: &incomplete_structured,
        },
        allocated.unobserved_merges(),
        allocated.live_out(),
        &BTreeSet::new(),
        &super::super::DeclaredStackSlots::default(),
        BTreeMap::new(),
    );
    assert!(
        incomplete
            .stack_slots
            .get(&allocated_save.location.object)
            .and_then(|slot| slot.callee_allocation.as_ref())
            .is_none(),
        "incomplete access provenance must revoke allocation authority"
    );

    let allocated_local = allocated
        .memory_defs_for_op_site(0x3600, 4)
        .and_then(|facts| facts.first())
        .expect("allocated local definition");
    let mut overlapping_objects = allocated.objects().clone();
    overlapping_objects.entry_stack_roots.insert(
        allocated_local.location.object,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -10,
        },
    );
    let overlapping = super::super::collect_prepared_function_certificates(
        super::super::Body {
            function: allocated.function(),
            graph: allocated.graph(),
            machine_context: Some(allocated.machine_context()),
        },
        super::super::Derived {
            values: &Default::default(),
            boundaries: &allocated_facts.boundaries,
            objects: &overlapping_objects,
            memory: &allocated_facts.memory,
            predicates: &allocated_facts.predicates,
            call_sites: &allocated_facts.call_sites,
            structured: &allocated_facts.structured,
        },
        allocated.unobserved_merges(),
        allocated.live_out(),
        &BTreeSet::new(),
        &super::super::DeclaredStackSlots::default(),
        BTreeMap::new(),
    );
    assert!(
        overlapping
            .stack_slots
            .get(&allocated_save.location.object)
            .and_then(|slot| slot.callee_allocation.as_ref())
            .is_none(),
        "an overlapping exact source object must revoke anonymous allocation authority"
    );

    let wrong_direction_roles = SourceMachineRoles::new(Some(storage(16)), Some(storage(0)))
        .and_then(|roles| {
            roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                SourceStackGrowth::HigherAddresses,
            ))
        })
        .expect("exact upward allocation contract");
    let wrong_direction = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[block],
        Some(&arch),
        Some(interface),
        wrong_direction_roles,
        Vec::new(),
    )
    .expect("opposite-direction artifact");
    let [wrong_direction_save] = wrong_direction
        .memory_defs_for_op_site(0x3600, 1)
        .expect("opposite-direction saved-frame definition")
    else {
        panic!("one opposite-direction saved-frame definition")
    };
    assert!(
        wrong_direction
            .certificates()
            .stack_slots
            .get(&wrong_direction_save.location.object)
            .and_then(|slot| slot.callee_allocation.as_ref())
            .is_none(),
        "opposite source stack growth must not certify the object"
    );
}

#[test]
fn a_stack_position_nothing_accesses_or_passes_on_has_no_extent() {
    // Two `sub sp` steps. The lower position is declared and stored to; the
    // upper one is a place the stack pointer passed through and nothing
    // ever reads, writes or hands on. The gap the frame leaves above such a
    // place is not a width it has, and a declaration needs a width.
    let artifact = |escapes: bool| {
        let sp = Varnode::register(0, 8);
        let ra = Varnode::register(16, 8);
        let held = Varnode::unique(0x100, 8);
        let mut block = R2ILBlock::new(0x4200, 4);
        block.push(R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Copy {
            dst: held.clone(),
            src: sp.clone(),
        });
        block.push(R2ILOp::IntSub {
            dst: sp.clone(),
            a: sp.clone(),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: sp,
            val: if escapes {
                held
            } else {
                Varnode::constant(1, 8)
            },
        });
        block.push(R2ILOp::Return { target: ra });

        let mut arch = ArchSpec::new("stack-position-test");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("sp", 0, 8));
        arch.add_register(RegisterDef::new("ra", 16, 8));
        arch.add_space(r2il::AddressSpace::ram(8));
        let storage = |offset| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"stack-position-revision-1".to_vec(),
            "test-abi",
            [],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                storage(0),
                -16,
                8,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(storage(16)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(0)))
        .expect("stack-position interface");
        SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("stack-position artifact")
    };
    let passed_through = |artifact: &SsaArtifact| {
        let object = artifact
            .objects()
            .objects
            .values()
            .find(|fact| {
                matches!(
                    fact.kind,
                    ObjectKind::StackSlot {
                        base: StackAddressBase::StackPointer,
                        offset: -8,
                        ..
                    }
                )
            })
            .map(|fact| fact.id)
            .expect("the position the stack pointer passed through");
        (
            artifact
                .certificates()
                .stack_slots
                .get(&object)
                .and_then(|slot| slot.size),
            artifact.declarable_stack_object(object),
        )
    };
    assert_eq!(
        passed_through(&artifact(false)),
        (None, false),
        "a position with no access and no escaping address is not an object to declare"
    );
    assert_eq!(
        passed_through(&artifact(true)),
        (Some(8), true),
        "the same position is a buffer once its address is handed on, and the frame's gap is its extent"
    );
}
