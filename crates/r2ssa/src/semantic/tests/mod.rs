mod boundaries;
mod certificates;
mod objects;
mod predicates;
mod values;

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ControlGuard, ForLoopCertificate, GlobalObjectKey, InductionStep, LoopCertificate,
    MemoryDefFact, MemoryLocation, MemorySSAFacts, MemoryUseFact, MemoryVersion, ObjectFact,
    ObjectId, ObjectKind, ObjectModel, ObjectModelBuilder, ObjectSpaceId, RelativeMemoryAddress,
    StructuredAccessId, StructuredLoopKind, memory_locations_may_alias,
};
use crate::{
    AddressProvenanceFacts, AnalysisAssumption, AssumptionProvenance, AssumptionScope,
    AssumptionSet, AssumptionSubject, AssumptionValue, CanonicalStorageId, CanonicalStorageSpace,
    InstId, InstPayload, SSAOp, SSAVar, SemanticObligationKind, SourceAbiParameterSpec,
    SourceCarrierKind, SourceCarrierProjection, SourceFunctionInterface, SourceFunctionReturn,
    SourceLogicalValue, SourceMachineRoles, SourceStackAllocationContract, SourceStackGrowth,
    SourceStackSlotSpec, SourceType, SourceTypeGraph, SourceTypeKind, SsaArtifact,
    StackAddressBase, StackAddressRoot, ValueId,
};
use r2il::{
    ArchSpec, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
    RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
};

fn test_reg(offset: u64) -> Varnode {
    Varnode::new(SpaceId::Register, offset, 8)
}

fn test_const(value: u64) -> Varnode {
    Varnode::constant(value, 8)
}

fn dual_space_artifact(
    mut prefix: Vec<R2ILOp>,
    addr: Varnode,
    arch: Option<&ArchSpec>,
) -> SsaArtifact {
    prefix.push(R2ILOp::Load {
        dst: Varnode::unique(0x100, 8),
        space: SpaceId::Ram,
        addr: addr.clone(),
    });
    prefix.push(R2ILOp::Load {
        dst: Varnode::unique(0x108, 8),
        space: SpaceId::Custom(7),
        addr,
    });
    SsaArtifact::for_symbolic(
        &[R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: prefix,
            switch_info: None,
            op_metadata: Default::default(),
        }],
        arch,
    )
    .expect("dual-space artifact")
}

fn dual_space_exact_parameter_artifact(arch: &ArchSpec) -> SsaArtifact {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x100, 8),
        space: SpaceId::Ram,
        addr: Varnode::register(0, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x108, 8),
        space: SpaceId::Custom(7),
        addr: Varnode::register(0, 8),
    });
    let interface = SourceFunctionInterface::new_exact(
        b"dual-space-exact-parameter".to_vec(),
        "aarch64-test",
        [SourceAbiParameterSpec::new(
            0,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Register,
                offset: 0,
                size: 8,
            },
        )],
        SourceFunctionReturn::Void,
        [],
    )
    .expect("valid exact parameter interface");
    SsaArtifact::for_decompile_with_interface(&[block], Some(arch), interface)
        .expect("dual-space exact parameter artifact")
}

fn dual_space_locations(artifact: &SsaArtifact) -> (MemoryLocation, MemoryLocation) {
    let block = artifact.get_block(0x1000).expect("dual-space block");
    let mut loads = block
        .ops
        .iter()
        .enumerate()
        .filter(|(_, op)| matches!(op, crate::SSAOp::Load { .. }));
    let ram_index = loads.next().expect("RAM load").0;
    let custom_index = loads.next().expect("Custom load").0;
    let ram = artifact
        .memory_uses_for_op_site(0x1000, ram_index)
        .and_then(|uses| uses.first())
        .expect("RAM location")
        .location
        .clone();
    let custom = artifact
        .memory_uses_for_op_site(0x1000, custom_index)
        .and_then(|uses| uses.first())
        .expect("Custom location")
        .location
        .clone();
    (ram, custom)
}

fn assert_dual_space_objects_are_distinct(artifact: &SsaArtifact) {
    let (ram, custom) = dual_space_locations(artifact);
    assert_eq!(ram.space, SpaceId::Ram);
    assert_eq!(custom.space, SpaceId::Custom(7));
    assert_ne!(ram.object, custom.object);
    assert_eq!(
        artifact
            .objects()
            .object(ram.object)
            .map(|fact| fact.kind.space()),
        Some(SpaceId::Ram)
    );
    assert_eq!(
        artifact
            .objects()
            .object(custom.object)
            .map(|fact| fact.kind.space()),
        Some(SpaceId::Custom(7))
    );
    assert!(!memory_locations_may_alias(
        artifact.objects(),
        &ram,
        &custom
    ));
}

#[test]
fn calls_clobber_every_present_typed_memory_space() {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x100, 8),
        space: SpaceId::Custom(7),
        addr: Varnode::constant(0x4000, 8),
    });
    block.push(R2ILOp::Call {
        target: Varnode::constant(0x2000, 8),
    });
    let artifact = SsaArtifact::for_symbolic(&[block], None).expect("call artifact");
    let call_index = artifact
        .get_block(0x1000)
        .expect("call block")
        .ops
        .iter()
        .position(|op| matches!(op, crate::SSAOp::Call { .. }))
        .expect("call op");
    let spaces = artifact
        .memory_defs_for_op_site(0x1000, call_index)
        .expect("call memory defs")
        .iter()
        .map(|fact| fact.location.space)
        .collect::<Vec<_>>();
    assert_eq!(spaces, vec![SpaceId::Ram, SpaceId::Custom(7)]);
}

#[test]
fn malformed_location_object_space_mismatch_never_proves_no_alias() {
    let object = ObjectId(1);
    let mut objects = ObjectModel::default();
    objects.objects.insert(
        object,
        ObjectFact {
            id: object,
            kind: ObjectKind::Global {
                space: SpaceId::Ram,
                address: 0x4000,
            },
        },
    );
    let malformed = MemoryLocation {
        space: SpaceId::Custom(7),
        object,
        address: RelativeMemoryAddress::Exact(0),
        size: 8,
    };
    let valid = MemoryLocation {
        space: SpaceId::Ram,
        object,
        address: RelativeMemoryAddress::Exact(0x1000),
        size: 8,
    };
    assert!(memory_locations_may_alias(&objects, &malformed, &valid));
}

#[test]
fn exact_entry_stack_coordinates_refine_cross_base_aliasing_fail_closed() {
    let saved = ObjectId(1);
    let local = ObjectId(2);
    let mut objects = ObjectModel::default();
    objects.objects.insert(
        saved,
        ObjectFact {
            id: saved,
            kind: ObjectKind::StackSlot {
                space: SpaceId::Ram,
                base: StackAddressBase::StackPointer,
                offset: -8,
            },
        },
    );
    objects.objects.insert(
        local,
        ObjectFact {
            id: local,
            kind: ObjectKind::StackSlot {
                space: SpaceId::Ram,
                base: StackAddressBase::FramePointer,
                offset: -8,
            },
        },
    );
    objects
        .address_bits_by_space
        .insert(ObjectSpaceId(SpaceId::Ram), 64);
    objects.entry_stack_roots.insert(
        saved,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -8,
        },
    );
    objects.entry_stack_roots.insert(
        local,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -16,
        },
    );
    let saved_location = MemoryLocation {
        space: SpaceId::Ram,
        object: saved,
        address: RelativeMemoryAddress::Exact(0),
        size: 8,
    };
    let local_location = MemoryLocation {
        space: SpaceId::Ram,
        object: local,
        address: RelativeMemoryAddress::Exact(0),
        size: 4,
    };
    assert!(!memory_locations_may_alias(
        &objects,
        &saved_location,
        &local_location
    ));

    objects.entry_stack_roots.remove(&local);
    assert!(memory_locations_may_alias(
        &objects,
        &saved_location,
        &local_location
    ));
    objects.entry_stack_roots.insert(
        local,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -8,
        },
    );
    assert!(memory_locations_may_alias(
        &objects,
        &saved_location,
        &local_location
    ));

    objects.entry_stack_roots.insert(
        saved,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: i64::MAX,
        },
    );
    objects.entry_stack_roots.insert(
        local,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: i64::MIN,
        },
    );
    let two_byte_saved = MemoryLocation {
        size: 2,
        ..saved_location.clone()
    };
    assert!(memory_locations_may_alias(
        &objects,
        &two_byte_saved,
        &local_location
    ));

    objects
        .address_bits_by_space
        .insert(ObjectSpaceId(SpaceId::Ram), 32);
    objects.entry_stack_roots.insert(
        saved,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: i64::from(i32::MAX),
        },
    );
    objects.entry_stack_roots.insert(
        local,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: i64::from(i32::MIN),
        },
    );
    assert!(memory_locations_may_alias(
        &objects,
        &two_byte_saved,
        &local_location
    ));

    objects.address_bits_by_space.clear();
    assert!(memory_locations_may_alias(
        &objects,
        &saved_location,
        &local_location
    ));
}

#[test]
fn conflicting_entry_stack_coordinates_permanently_drop_alias_refinement() {
    let addresses = AddressProvenanceFacts::default();
    let declared = super::DeclaredStackSlots::default();
    let mut builder = ObjectModelBuilder::new(None, &addresses, &declared, None);
    let object = ObjectId(7);
    let first = StackAddressRoot {
        base: StackAddressBase::StackPointer,
        offset: -16,
    };
    builder.record_entry_stack_root(object, first);
    builder.record_entry_stack_root(object, first);
    assert_eq!(builder.entry_stack_roots.get(&object), Some(&first));
    builder.record_entry_stack_root(
        object,
        StackAddressRoot {
            base: StackAddressBase::StackPointer,
            offset: -24,
        },
    );
    assert!(!builder.entry_stack_roots.contains_key(&object));
    builder.record_entry_stack_root(object, first);
    assert!(!builder.entry_stack_roots.contains_key(&object));
}

#[test]
fn global_object_key_order_binds_exact_typed_space() {
    let keys = [
        GlobalObjectKey {
            space: SpaceId::Ram,
            address: 0x4000,
        },
        GlobalObjectKey {
            space: SpaceId::Custom(1),
            address: 0x4000,
        },
        GlobalObjectKey {
            space: SpaceId::Custom(2),
            address: 0x4000,
        },
    ];
    let expected = keys.clone();
    let ordered = keys.into_iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ordered.len(), 3);
    assert_eq!(ordered.into_iter().collect::<Vec<_>>(), expected);
}

#[test]
fn global_aliasing_keeps_exact_typed_memory_spaces_disjoint() {
    let ram = ObjectId(1);
    let custom = ObjectId(2);
    let mut objects = ObjectModel::default();
    objects.objects.insert(
        ram,
        ObjectFact {
            id: ram,
            kind: ObjectKind::Global {
                space: SpaceId::Ram,
                address: 0x4000,
            },
        },
    );
    objects.objects.insert(
        custom,
        ObjectFact {
            id: custom,
            kind: ObjectKind::Global {
                space: SpaceId::Custom(7),
                address: 0x4000,
            },
        },
    );
    let location = |space, object| MemoryLocation {
        space,
        object,
        address: RelativeMemoryAddress::Exact(0),
        size: 8,
    };
    assert!(!memory_locations_may_alias(
        &objects,
        &location(SpaceId::Ram, ram),
        &location(SpaceId::Custom(7), custom)
    ));
}

fn raw_memory_access(
    locations: Vec<MemoryLocation>,
    is_write: bool,
    width: u32,
) -> super::StructuredMemoryAccessFact {
    let inst = InstId(0);
    let space = locations
        .first()
        .map_or(SpaceId::Ram, |location| location.space);
    let mut objects = ObjectModel::default();
    for location in &locations {
        objects
            .objects
            .entry(location.object)
            .or_insert(ObjectFact {
                id: location.object,
                kind: ObjectKind::Global {
                    space: location.space,
                    address: 0,
                },
            });
    }
    let mut memory = MemorySSAFacts::default();
    if is_write {
        memory.defs_by_inst.insert(
            inst,
            locations
                .into_iter()
                .enumerate()
                .map(|(index, location)| MemoryDefFact {
                    location,
                    previous_version: MemoryVersion {
                        object: ObjectId(index as u32 + 100),
                        version: 1,
                    },
                    next_version: MemoryVersion {
                        object: ObjectId(index as u32 + 100),
                        version: 2,
                    },
                })
                .collect(),
        );
    } else {
        memory.uses_by_inst.insert(
            inst,
            locations
                .into_iter()
                .enumerate()
                .map(|(index, location)| MemoryUseFact {
                    location,
                    version: MemoryVersion {
                        object: ObjectId(index as u32 + 100),
                        version: 1,
                    },
                })
                .collect(),
        );
    }
    let mut accesses = BTreeMap::new();
    let mut ordinal = 0;
    super::insert_raw_memory_subeffect(
        super::EffectSink {
            facts: &mut accesses,
            ordinal: &mut ordinal,
        },
        &memory,
        &objects,
        super::AccessSite {
            inst,
            block_addr: 0x1000,
            op_index: 0,
        },
        super::RawAccess {
            address: ValueId(0),
            space,
            value: Some(ValueId(1)),
            is_write,
            width,
        },
    );
    accesses
        .remove(&StructuredAccessId { inst, ordinal: 0 })
        .expect("raw memory access")
}

#[test]
fn memory_access_provenance_ignores_duplicate_reaching_versions() {
    let location = MemoryLocation {
        space: SpaceId::Ram,
        object: ObjectId(7),
        address: RelativeMemoryAddress::Exact(-8),
        size: 8,
    };
    for is_write in [false, true] {
        let access = raw_memory_access(vec![location.clone(), location.clone()], is_write, 8);
        assert!(access.provenance_complete);
        assert_eq!(access.object, location.object);
    }
}

#[test]
fn memory_access_provenance_rejects_distinct_location_ambiguity() {
    let location = MemoryLocation {
        space: SpaceId::Ram,
        object: ObjectId(7),
        address: RelativeMemoryAddress::Exact(-8),
        size: 8,
    };
    let mutations = [
        MemoryLocation {
            object: ObjectId(8),
            ..location.clone()
        },
        MemoryLocation {
            address: RelativeMemoryAddress::Exact(-16),
            ..location.clone()
        },
        MemoryLocation {
            size: 4,
            ..location.clone()
        },
    ];
    for mutation in mutations {
        for is_write in [false, true] {
            let access = raw_memory_access(vec![location.clone(), mutation.clone()], is_write, 8);
            assert!(!access.provenance_complete);
        }
    }
}

#[test]
fn display_names_do_not_resolve_constants_or_stack_roots() {
    let named_constant = SSAVar::new("ram:0x401000", 0, 8);
    assert_eq!(super::const_value(&named_constant), None);
    assert_eq!(super::resolve_const_value(None, &named_constant), None);

    let named_stack_pointer = SSAVar::new("rsp", 0, 8);
    assert_eq!(super::resolve_stack_root(None, &named_stack_pointer), None);

    let canonical_constant = SSAVar::constant(0x401000, 8).renamed("unrelated-display-name");
    assert_eq!(super::const_value(&canonical_constant), Some(0x401000));
}

fn conditional_block(addr: u64, selector: u64, target: u64) -> R2ILBlock {
    let mut block = R2ILBlock::new(addr, 4);
    let cond = Varnode::unique(addr, 1);
    block.push(R2ILOp::IntEqual {
        dst: cond.clone(),
        a: test_reg(selector),
        b: test_const(1),
    });
    block.push(R2ILOp::CBranch {
        target: test_const(target),
        cond,
    });
    block
}

fn branch_block(addr: u64, target: u64) -> R2ILBlock {
    let mut block = R2ILBlock::new(addr, 4);
    block.push(R2ILOp::Branch {
        target: test_const(target),
    });
    block
}

fn predicate_assumption_diamond() -> SsaArtifact {
    SsaArtifact::for_symbolic(
        &[
            conditional_block(0x9000, 0, 0x9040),
            branch_block(0x9004, 0x9080),
            branch_block(0x9040, 0x9080),
            R2ILBlock::new(0x9080, 4),
        ],
        None,
    )
    .expect("predicate-assumption diamond")
}

fn predicate_branch_assumption(
    predicate: &super::PredicateFact,
    block_addr: u64,
    predecessor: Option<u64>,
    truth: bool,
) -> AnalysisAssumption {
    AnalysisAssumption {
        id: Some("predicate-assumption-test".to_string()),
        subject: AssumptionSubject::Predicate {
            predicate: predicate.id,
            block_addr,
            predecessor,
        },
        value: AssumptionValue::Branch { truth },
        scope: AssumptionScope::Query,
        provenance: AssumptionProvenance::User,
    }
}

fn register_assumption(name: impl Into<String>) -> AnalysisAssumption {
    AnalysisAssumption {
        id: Some("register-assumption-test".to_string()),
        subject: AssumptionSubject::Register { name: name.into() },
        value: AssumptionValue::Constant { value: 7 },
        scope: AssumptionScope::Query,
        provenance: AssumptionProvenance::User,
    }
}

fn entry_register_artifact(arch: Option<&ArchSpec>) -> SsaArtifact {
    let mut block = R2ILBlock::new(0x8f00, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x80, 8),
        src: Varnode::register(0, 8),
    });
    SsaArtifact::for_symbolic(&[block], arch).expect("entry register artifact")
}

#[test]
fn register_assumption_does_not_treat_an_ssa_display_name_as_storage_proof() {
    let base = entry_register_artifact(None);
    let display_name = base
        .graph()
        .values
        .iter()
        .find(|value| value.var.version == 0 && value.var.is_register())
        .expect("entry register")
        .var
        .name();
    let assumption = register_assumption(display_name);
    let conditioned = base.with_assumptions(&AssumptionSet::new(vec![assumption.clone()]));

    assert!(conditioned.facts().applied_assumption_bindings.is_empty());
    assert!(conditioned.facts().assumption_usage.applied.is_empty());
    assert_eq!(conditioned.facts().assumption_usage.ignored, [assumption]);
    assert!(conditioned.facts().assumption_usage.conflicts.is_empty());
}

#[test]
fn register_assumption_certificate_is_bound_to_source_storage_and_value() {
    let mut arch = ArchSpec::new("assumption-storage-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("argument_carrier", 0, 8));
    let base = entry_register_artifact(Some(&arch));
    let assumption = register_assumption("ARGUMENT_CARRIER");
    let conditioned = base.with_assumptions(&AssumptionSet::new(vec![assumption.clone()]));

    assert_eq!(conditioned.facts().assumption_usage.applied, [assumption]);
    let [binding] = conditioned.facts().applied_assumption_bindings.as_slice() else {
        panic!("one exact register binding expected");
    };
    let super::PreparedAssumptionBindingKind::Register {
        storage,
        value,
        bits,
        ..
    } = &binding.binding
    else {
        panic!("register binding expected");
    };
    assert_eq!(*storage, register_storage(0, 8));
    assert_eq!(*bits, 64);
    assert_eq!(
        conditioned
            .graph()
            .value(*value)
            .and_then(|value| value.canonical_storage),
        Some(*storage)
    );
}

#[test]
fn stack_assumption_certificate_uses_the_typed_stack_base() {
    let mut arch = ArchSpec::new("assumption-stack-role-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("stack_carrier", 0, 8));
    arch.add_register(RegisterDef::new("return_link", 16, 8));
    arch.add_space(r2il::AddressSpace::ram(8));
    let stack_address = Varnode::unique(0x90, 8);
    let mut block = R2ILBlock::new(0x8f40, 4);
    block.push(R2ILOp::IntSub {
        dst: stack_address.clone(),
        a: Varnode::register(0, 8),
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x98, 8),
        space: SpaceId::Ram,
        addr: stack_address,
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let interface = SourceFunctionInterface::new_exact(
        b"assumption-stack-role-revision-1".to_vec(),
        "test-abi",
        [],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            register_storage(0, 8),
            -8,
            8,
        )],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(0, 8)))
    .expect("exact stack roles");
    let base = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("stack-role artifact");
    let assumption = AnalysisAssumption {
        id: Some("typed-stack-assumption-test".to_string()),
        subject: AssumptionSubject::StackSlot {
            base: StackAddressBase::StackPointer,
            offset: -8,
        },
        value: AssumptionValue::TypeHint {
            ty: "uint64_t".to_string(),
        },
        scope: AssumptionScope::Function,
        provenance: AssumptionProvenance::ImportedContext,
    };
    let conditioned = base.with_assumptions(&AssumptionSet::new(vec![assumption.clone()]));

    assert_eq!(conditioned.facts().assumption_usage.applied, [assumption]);
    assert!(matches!(
        conditioned.facts().applied_assumption_bindings.as_slice(),
        [super::PreparedAssumptionBinding {
            binding: super::PreparedAssumptionBindingKind::StackSlot {
                base: StackAddressBase::StackPointer,
                offset: -8,
                ..
            },
            ..
        }]
    ));
}

fn assert_conflicting_predicate_assumption_preserves_semantics(
    base: &SsaArtifact,
    assumption: AnalysisAssumption,
    expected_reason: &str,
) {
    let conditioned = base.with_assumptions(&AssumptionSet::new(vec![assumption.clone()]));

    assert_predicate_assumption_preserves_source_semantics(base, &conditioned);
    assert!(conditioned.facts().applied_assumption_bindings.is_empty());
    assert!(conditioned.facts().assumption_usage.applied.is_empty());
    assert!(conditioned.facts().assumption_usage.ignored.is_empty());
    assert_eq!(conditioned.facts().assumption_usage.conflicts.len(), 1);
    assert_eq!(
        conditioned.facts().assumption_usage.conflicts[0].assumption,
        assumption
    );
    assert_eq!(
        conditioned.facts().assumption_usage.conflicts[0].reason,
        expected_reason
    );
}

fn assert_predicate_assumption_preserves_source_semantics(
    base: &SsaArtifact,
    conditioned: &SsaArtifact,
) {
    assert_eq!(conditioned.predicates(), base.predicates());
    assert_eq!(conditioned.structured(), base.structured());
    assert_eq!(conditioned.control_domains(), base.control_domains());
    assert_eq!(conditioned.certificates(), base.certificates());
    assert_eq!(conditioned.obligations(), base.obligations());
}

fn return_boundary_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("return-boundary-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rip", 16, 8));
    arch.add_register(RegisterDef::new("cond", 24, 1));
    arch.add_register(RegisterDef::new("sp", 32, 8));
    arch.add_register(RegisterDef::sub("sp_low", 32, 4, "sp"));
    arch.add_register(RegisterDef::new("return_transport", 40, 8));
    arch
}

fn register_storage(offset: u64, size: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    }
}

fn return_boundary_interface() -> SourceFunctionInterface {
    SourceFunctionInterface::new(
        b"return-boundary-revision-1".to_vec(),
        "test-register-abi",
        [SourceAbiParameterSpec::new(0, register_storage(8, 8))],
        SourceFunctionReturn::Register {
            storage: register_storage(0, 8),
        },
        [],
    )
    .expect("return boundary interface")
}

fn preserved_stack_interface() -> SourceFunctionInterface {
    SourceFunctionInterface::new_exact(
        b"preserved-stack-revision-1".to_vec(),
        "test-register-abi",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(32, 8)))
    .expect("typed return-address and stack-pointer roles")
}

fn complete_return_interface(return_kind: SourceFunctionReturn) -> SourceFunctionInterface {
    SourceFunctionInterface::new_exact(
        b"complete-return-certificate-revision-1".to_vec(),
        "test-register-abi",
        [],
        return_kind,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(32, 8)))
    .expect("complete return interface")
}

fn complete_return_artifact(return_kind: SourceFunctionReturn) -> SsaArtifact {
    let mut block = R2ILBlock::new(0x2f00, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(7, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&return_boundary_arch()),
        complete_return_interface(return_kind),
    )
    .expect("complete return artifact")
}

fn exact_signed_low_return_artifact(write_logical_carrier: bool) -> SsaArtifact {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::sub("eax", 0, 4, "rax"));
    arch.add_register(RegisterDef::new("rip", 16, 8));
    arch.add_register(RegisterDef::new("sp", 32, 8));
    let projection =
        |written: RegisterStorage, carrier: RegisterStorage, size_bits: u64| RegisterProjection {
            written,
            disposition: RegisterProjectionDisposition::Bound {
                carrier,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits,
                },
            },
        };
    arch.register_projections = vec![
        projection(
            RegisterStorage { offset: 0, size: 8 },
            RegisterStorage { offset: 0, size: 8 },
            64,
        ),
        projection(
            RegisterStorage { offset: 0, size: 4 },
            RegisterStorage { offset: 0, size: 8 },
            32,
        ),
        projection(
            RegisterStorage {
                offset: 16,
                size: 8,
            },
            RegisterStorage {
                offset: 16,
                size: 8,
            },
            64,
        ),
        projection(
            RegisterStorage {
                offset: 32,
                size: 8,
            },
            RegisterStorage {
                offset: 32,
                size: 8,
            },
            64,
        ),
    ];
    let mut block = R2ILBlock::new(0x2f20, 4);
    if write_logical_carrier {
        // An arithmetic write rather than a copy, so that the narrow value
        // survives as its own definition: a copy of a constant is folded
        // into its uses, and then there is no `eax` for the extension to
        // name.
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(0, 4),
            a: Varnode::register(0, 4),
            b: Varnode::constant(7, 4),
        });
    } else {
        // Bits above the logical width, so the carrier is not the
        // zero-extension of its own low half and nothing proves what the
        // declared 32-bit return holds.
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(0x1_0000_0007, 8),
        });
    }
    if write_logical_carrier {
        // What the lift emits for a narrow x86-64 register write: Sleigh
        // states the carrier clear itself, on the op after the write, so
        // the full return register is defined here without anything in
        // this crate synthesizing a definition for it.
        block.push(R2ILOp::IntZExt {
            dst: Varnode::register(0, 8),
            src: Varnode::register(0, 4),
        });
    }
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let logical = SourceLogicalValue::new(
        0,
        SourceCarrierProjection::new(SourceCarrierKind::LowBits, 0, 32),
    );
    let type_graph = SourceTypeGraph::new(
        [SourceType::new(0, SourceTypeKind::SignedInteger, 32, 32)],
        [],
    )
    .expect("exact signed return type graph");
    let interface = SourceFunctionInterface::new_exact_with_logical_types(
        b"exact-signed-low-return".to_vec(),
        "test-register-abi",
        [],
        SourceFunctionReturn::Register {
            storage: register_storage(0, 8),
        },
        [],
        [],
        Some(logical),
        Some(type_graph),
    )
    .and_then(|interface| interface.with_return_address_storage(register_storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(32, 8)))
    .expect("exact signed low return interface");
    SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("exact signed low return artifact")
}

/// `return Z_STREAM_ERROR;` from an `int` function: the compiler emits
/// `mov eax, 0xfffffffe`, which the lift states as an eight-byte constant
/// copy into the carrier. No extension instruction exists, and none is
/// needed -- a constant whose bits above the logical width are zero is
/// the zero-extension of its own low half. Refusing it cost 132 of the
/// 140 low-bits return refusals in zlib's minigzip at -O2.
/// A function whose whole body is `mov eax, N; ret`, lifted as an
/// eight-byte constant copy into the return carrier.
fn constant_low_return_artifact(constant: u64) -> SsaArtifact {
    constant_return_artifact(constant, true)
}

/// The same body under an interface that types its values: exactly, with an
/// `int` result, or inexactly, stating no type for the register result.
fn constant_return_artifact(constant: u64, result_typed: bool) -> SsaArtifact {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::sub("eax", 0, 4, "rax"));
    arch.add_register(RegisterDef::new("rip", 16, 8));
    arch.add_register(RegisterDef::new("sp", 32, 8));
    let projection =
        |written: RegisterStorage, carrier: RegisterStorage, size_bits: u64| RegisterProjection {
            written,
            disposition: RegisterProjectionDisposition::Bound {
                carrier,
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits,
                },
            },
        };
    arch.register_projections = vec![
        projection(
            RegisterStorage { offset: 0, size: 8 },
            RegisterStorage { offset: 0, size: 8 },
            64,
        ),
        projection(
            RegisterStorage { offset: 0, size: 4 },
            RegisterStorage { offset: 0, size: 8 },
            32,
        ),
        projection(
            RegisterStorage {
                offset: 16,
                size: 8,
            },
            RegisterStorage {
                offset: 16,
                size: 8,
            },
            64,
        ),
        projection(
            RegisterStorage {
                offset: 32,
                size: 8,
            },
            RegisterStorage {
                offset: 32,
                size: 8,
            },
            64,
        ),
    ];
    let mut block = R2ILBlock::new(0x2f20, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(constant, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let logical = SourceLogicalValue::new(
        0,
        SourceCarrierProjection::new(SourceCarrierKind::LowBits, 0, 32),
    );
    let type_graph = SourceTypeGraph::new(
        [SourceType::new(0, SourceTypeKind::SignedInteger, 32, 32)],
        [],
    )
    .expect("constant low return type graph");
    let result = SourceFunctionReturn::Register {
        storage: register_storage(0, 8),
    };
    let interface = if result_typed {
        SourceFunctionInterface::new_exact_with_logical_types(
            b"constant-low-return".to_vec(),
            "test-register-abi",
            [],
            result,
            [],
            [],
            Some(logical),
            Some(type_graph),
        )
    } else {
        SourceFunctionInterface::new_with_logical_types(
            b"constant-untyped-return".to_vec(),
            "test-register-abi",
            [],
            result,
            [],
            [],
            None,
            Some(type_graph),
        )
    }
    .and_then(|interface| interface.with_return_address_storage(register_storage(16, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(32, 8)))
    .expect("constant low return interface");
    SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
        .expect("constant low return artifact")
}

fn composed_return_arch(whole_name: &str, slice_name: &str, pc_name: &str) -> ArchSpec {
    let mut arch = ArchSpec::new("return-composition-test");
    arch.add_register(RegisterDef::new(whole_name, 0, 4));
    arch.add_register(RegisterDef::sub(slice_name, 0, 1, whole_name));
    arch.add_register(RegisterDef::new(pc_name, 16, 8));
    arch
}

fn composed_return_interface() -> SourceFunctionInterface {
    SourceFunctionInterface::new(
        b"return-composition-revision-1".to_vec(),
        "test-register-abi",
        [],
        SourceFunctionReturn::Register {
            storage: register_storage(0, 4),
        },
        [],
    )
    .expect("composed return interface")
}

fn composed_return_block(addr: u64) -> R2ILBlock {
    let mut block = R2ILBlock::new(addr, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 4),
        src: Varnode::constant(0, 4),
    });
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 1),
        src: Varnode::constant(1, 1),
    });
    block.push(R2ILOp::Copy {
        dst: Varnode::register(0, 1),
        src: Varnode::constant(0, 1),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    block
}

fn composed_return_artifact(
    addr: u64,
    whole_name: &str,
    slice_name: &str,
    pc_name: &str,
) -> SsaArtifact {
    SsaArtifact::for_decompile_with_interface(
        &[composed_return_block(addr)],
        Some(&composed_return_arch(whole_name, slice_name, pc_name)),
        composed_return_interface(),
    )
    .expect("composed return artifact")
}

#[test]
fn return_boundary_recovery_accepts_identical_fanin_and_phi_free_cycles() {
    let mut entry = R2ILBlock::new(0x3000, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::unique(0x80, 8),
        src: Varnode::register(0, 8),
    });
    entry.push(R2ILOp::CBranch {
        target: Varnode::ram(0x3020, 8),
        cond: Varnode::register(24, 1),
    });
    let mut right = R2ILBlock::new(0x3004, 4);
    right.push(R2ILOp::Branch {
        target: Varnode::ram(0x3030, 8),
    });
    let mut left = R2ILBlock::new(0x3020, 4);
    left.push(R2ILOp::Branch {
        target: Varnode::ram(0x3030, 8),
    });
    let mut joined = R2ILBlock::new(0x3030, 4);
    joined.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let fanin = SsaArtifact::raw_with_interface(
        &[entry, right, left, joined],
        Some(&return_boundary_arch()),
        return_boundary_interface(),
    )
    .expect("fanin boundary artifact");
    let converged = super::reaching_abi_value_in_block(
        fanin.function(),
        fanin.graph(),
        fanin.machine_context(),
        0x3030,
        0,
        register_storage(0, 8),
    )
    .expect("both paths reach the same entry live-in");
    assert!(fanin.graph().def_inst(converged).is_none());

    let mut header = R2ILBlock::new(0x4000, 4);
    header.push(R2ILOp::Copy {
        dst: Varnode::unique(0x80, 8),
        src: Varnode::register(0, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x4000, 8),
        cond: Varnode::register(24, 1),
    });
    let mut exit = R2ILBlock::new(0x4004, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let cycle = SsaArtifact::raw_with_interface(
        &[header, exit],
        Some(&return_boundary_arch()),
        return_boundary_interface(),
    )
    .expect("cycle boundary artifact");
    // A loop nothing in it writes brings the entry live-in round
    // unchanged; the back edge adds no definition and no merge.
    let round_the_loop = super::reaching_abi_value_in_block(
        cycle.function(),
        cycle.graph(),
        cycle.machine_context(),
        0x4000,
        2,
        register_storage(0, 8),
    )
    .expect("the loop carries the entry live-in round");
    assert!(cycle.graph().def_inst(round_the_loop).is_none());
}

#[test]
fn reaching_abi_value_crosses_a_loop_that_defines_nothing_of_it() {
    // rdi is set before the loop; the loop body writes only rax; the
    // boundary after the loop asks for rdi.
    let mut entry = R2ILBlock::new(0x5000, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::register(8, 8),
        src: Varnode::constant(7, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x5004, 8),
    });
    let mut header = R2ILBlock::new(0x5004, 4);
    header.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 8),
        a: Varnode::register(0, 8),
        b: Varnode::constant(1, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x5004, 8),
        cond: Varnode::register(24, 1),
    });
    let mut exit = R2ILBlock::new(0x5008, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let artifact = SsaArtifact::raw_with_interface(
        &[entry, header, exit],
        Some(&return_boundary_arch()),
        return_boundary_interface(),
    )
    .expect("loop artifact");
    let reaching = super::reaching_abi_value_in_block(
        artifact.function(),
        artifact.graph(),
        artifact.machine_context(),
        0x5008,
        0,
        register_storage(8, 8),
    )
    .expect("the definition before the loop reaches the boundary after it");
    let definition = artifact
        .graph()
        .def_inst(reaching)
        .and_then(|inst| artifact.graph().inst(inst))
        .expect("rdi's definition");
    assert!(matches!(
        definition.payload,
        InstPayload::Op(SSAOp::Copy { .. })
    ));
    // rax is written in the loop, and the body's last write is what
    // reaches the exit.
    let written = super::reaching_abi_value_in_block(
        artifact.function(),
        artifact.graph(),
        artifact.machine_context(),
        0x5008,
        0,
        register_storage(0, 8),
    )
    .expect("the loop's own carrier reaches the boundary from its body");
    assert!(matches!(
        artifact
            .graph()
            .def_inst(written)
            .and_then(|inst| artifact.graph().inst(inst))
            .map(|inst| &inst.payload),
        Some(InstPayload::Op(SSAOp::IntAdd { .. }))
    ));
}

#[test]
fn reaching_abi_value_walks_a_diamond_chain_once() {
    // Twenty-four diamonds in a row have sixteen million paths; the walk
    // answers per block, so the value set before them reaches the end.
    let diamonds = 24u64;
    let mut blocks = Vec::new();
    let mut entry = R2ILBlock::new(0x8000, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::register(8, 8),
        src: Varnode::constant(7, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x8010, 8),
    });
    blocks.push(entry);
    for i in 0..diamonds {
        let base = 0x8010 + i * 0x40;
        let mut head = R2ILBlock::new(base, 4);
        head.push(R2ILOp::CBranch {
            target: Varnode::ram(base + 0x20, 8),
            cond: Varnode::register(24, 1),
        });
        let mut left = R2ILBlock::new(base + 4, 4);
        left.push(R2ILOp::Branch {
            target: Varnode::ram(base + 0x40, 8),
        });
        let mut right = R2ILBlock::new(base + 0x20, 4);
        right.push(R2ILOp::Branch {
            target: Varnode::ram(base + 0x40, 8),
        });
        blocks.extend([head, left, right]);
    }
    let mut exit = R2ILBlock::new(0x8010 + diamonds * 0x40, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    blocks.push(exit);
    let artifact = SsaArtifact::raw_with_interface(
        &blocks,
        Some(&return_boundary_arch()),
        return_boundary_interface(),
    )
    .expect("diamond chain artifact");
    let reaching = super::reaching_abi_value_in_block(
        artifact.function(),
        artifact.graph(),
        artifact.machine_context(),
        0x8010 + diamonds * 0x40,
        0,
        register_storage(8, 8),
    )
    .expect("the definition before the diamonds reaches the end");
    assert!(matches!(
        artifact
            .graph()
            .def_inst(reaching)
            .and_then(|inst| artifact.graph().inst(inst))
            .map(|inst| &inst.payload),
        Some(InstPayload::Op(SSAOp::Copy { .. }))
    ));
}

/// A counting loop: `x = 0` on entry, `x = x + step` round the latch.
///
/// `step_op` builds the latch update from the header phi's register, so a
/// test can say what motion the loop has without restating the fixture.
fn induction_loop_artifact(step_ops: &[R2ILOp]) -> SsaArtifact {
    let counter = Varnode::register(40, 8);
    let mut entry = R2ILBlock::new(0x7000, 4);
    entry.push(R2ILOp::Copy {
        dst: counter,
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7010, 8),
    });

    let mut header = R2ILBlock::new(0x7010, 4);
    for op in step_ops {
        header.push(op.clone());
    }
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7010, 8),
        cond: Varnode::register(24, 1),
    });

    let mut exit = R2ILBlock::new(0x7014, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    SsaArtifact::for_decompile(&[entry, header, exit], Some(&return_boundary_arch()))
        .expect("induction loop artifact")
}

/// A pre-test counted loop whose comparison and latch are in distinct
/// blocks, matching the region shape a renderer may turn into `for`.
fn counted_loop_artifact(condition_reads_counter: bool) -> SsaArtifact {
    let counter = Varnode::register(40, 8);
    let compared = if condition_reads_counter {
        counter.clone()
    } else {
        Varnode::register(48, 8)
    };
    let condition = Varnode::unique(0x7200, 1);

    let mut entry = R2ILBlock::new(0x7100, 4);
    entry.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7110, 8),
    });

    let mut header = R2ILBlock::new(0x7110, 4);
    header.push(R2ILOp::IntLess {
        dst: condition.clone(),
        a: compared,
        b: Varnode::constant(10, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7140, 8),
        cond: condition,
    });

    let mut body = R2ILBlock::new(0x7114, 4);
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x7120, 8),
    });

    let mut latch = R2ILBlock::new(0x7120, 4);
    latch.push(R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter.clone(),
        b: Varnode::constant(1, 8),
    });
    latch.push(R2ILOp::Branch {
        target: Varnode::ram(0x7110, 8),
    });

    let mut exit = R2ILBlock::new(0x7140, 4);
    exit.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x9000, 8),
        val: counter,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    SsaArtifact::for_decompile(
        &[entry, header, body, latch, exit],
        Some(&return_boundary_arch()),
    )
    .expect("counted loop artifact")
}

#[derive(Clone, Copy)]
enum CountedTestStep {
    Add(u64),
    Sub(u64),
    UnsupportedXor(u64),
}

/// The same pre-test loop with optional copy projections on the compared
/// phi and latch update. These are graph identities, not symbol aliases.
fn counted_loop_with_aliases(
    condition_aliases: usize,
    update_aliases: usize,
    step: CountedTestStep,
    trailing_latch_effect: bool,
) -> SsaArtifact {
    let counter = Varnode::register(40, 8);
    let condition = Varnode::unique(0x75f0, 1);

    let mut entry = R2ILBlock::new(0x7500, 4);
    entry.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7510, 8),
    });

    let mut header = R2ILBlock::new(0x7510, 4);
    let mut compared = counter.clone();
    for index in 0..condition_aliases {
        let alias = Varnode::unique(0x7600 + index as u64 * 8, 8);
        header.push(R2ILOp::Copy {
            dst: alias.clone(),
            src: compared,
        });
        compared = alias;
    }
    header.push(R2ILOp::IntLess {
        dst: condition.clone(),
        a: compared,
        b: Varnode::constant(10, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7540, 8),
        cond: condition,
    });

    let mut body = R2ILBlock::new(0x7514, 4);
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x7520, 8),
    });

    let mut latch = R2ILBlock::new(0x7520, 4);
    let mut update_input = counter.clone();
    for index in 0..update_aliases {
        let alias = Varnode::unique(0x7700 + index as u64 * 8, 8);
        latch.push(R2ILOp::Copy {
            dst: alias.clone(),
            src: update_input,
        });
        update_input = alias;
    }
    match step {
        CountedTestStep::Add(step) => latch.push(R2ILOp::IntAdd {
            dst: counter.clone(),
            a: update_input,
            b: Varnode::constant(step, 8),
        }),
        CountedTestStep::Sub(step) => latch.push(R2ILOp::IntSub {
            dst: counter.clone(),
            a: update_input,
            b: Varnode::constant(step, 8),
        }),
        CountedTestStep::UnsupportedXor(mask) => latch.push(R2ILOp::IntXor {
            dst: counter.clone(),
            a: update_input,
            b: Varnode::constant(mask, 8),
        }),
    }
    if trailing_latch_effect {
        latch.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9010, 8),
            val: counter.clone(),
        });
    }
    latch.push(R2ILOp::Branch {
        target: Varnode::ram(0x7510, 8),
    });

    let mut exit = R2ILBlock::new(0x7540, 4);
    exit.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x9000, 8),
        val: counter,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });

    SsaArtifact::for_decompile(
        &[entry, header, body, latch, exit],
        Some(&return_boundary_arch()),
    )
    .expect("counted loop with graph aliases")
}

/// A loop with two body paths converging either at the update itself or at
/// a common suffix immediately before it. Both shapes have one real latch.
fn counted_loop_with_shared_latch_artifact(common_suffix: bool) -> SsaArtifact {
    let counter = Varnode::register(40, 8);
    let loop_condition = Varnode::unique(0x7800, 1);
    let branch_condition = Varnode::register(56, 1);

    let mut entry = R2ILBlock::new(0x7100, 4);
    entry.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7110, 8),
    });

    let mut header = R2ILBlock::new(0x7110, 4);
    header.push(R2ILOp::IntLess {
        dst: loop_condition.clone(),
        a: counter.clone(),
        b: Varnode::constant(10, 8),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7140, 8),
        cond: loop_condition,
    });

    let mut branch = R2ILBlock::new(0x7114, 4);
    branch.push(R2ILOp::CBranch {
        target: Varnode::ram(if common_suffix { 0x711c } else { 0x7120 }, 8),
        cond: branch_condition,
    });

    let mut fallthrough = R2ILBlock::new(0x7118, 4);
    fallthrough.push(R2ILOp::Copy {
        dst: Varnode::unique(0x7810, 8),
        src: counter.clone(),
    });
    fallthrough.push(R2ILOp::Branch {
        target: Varnode::ram(0x7120, 8),
    });

    let mut blocks = vec![entry, header, branch, fallthrough];
    let latch_addr = if common_suffix {
        let mut alternate = R2ILBlock::new(0x711c, 4);
        alternate.push(R2ILOp::Copy {
            dst: Varnode::unique(0x7818, 8),
            src: counter.clone(),
        });
        alternate.push(R2ILOp::Branch {
            target: Varnode::ram(0x7120, 8),
        });
        let mut suffix = R2ILBlock::new(0x7120, 4);
        suffix.push(R2ILOp::Copy {
            dst: Varnode::unique(0x7820, 8),
            src: counter.clone(),
        });
        suffix.push(R2ILOp::Branch {
            target: Varnode::ram(0x7130, 8),
        });
        blocks.extend([alternate, suffix]);
        0x7130
    } else {
        0x7120
    };

    let mut latch = R2ILBlock::new(latch_addr, 4);
    latch.push(R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter.clone(),
        b: Varnode::constant(1, 8),
    });
    latch.push(R2ILOp::Branch {
        target: Varnode::ram(0x7110, 8),
    });
    blocks.push(latch);

    let mut exit = R2ILBlock::new(0x7140, 4);
    exit.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x9000, 8),
        val: counter,
    });
    exit.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    blocks.push(exit);

    SsaArtifact::for_decompile(&blocks, Some(&return_boundary_arch()))
        .expect("counted loop with shared latch")
}

fn for_certificate(artifact: &SsaArtifact) -> Option<(&LoopCertificate, &ForLoopCertificate)> {
    artifact
        .facts()
        .certificates
        .loops
        .values()
        .find_map(|loop_fact| {
            loop_fact
                .for_loop
                .as_ref()
                .map(|certificate| (loop_fact, certificate))
        })
}

fn recovered_induction_step(artifact: &SsaArtifact) -> Option<super::InductionStep> {
    artifact
        .facts()
        .structured
        .inductions
        .values()
        .find(|fact| fact.width_bits == 64)
        .map(|fact| fact.step)
}

#[test]
fn a_counter_stepped_by_a_constant_is_an_induction_variable() {
    let counter = Varnode::register(40, 8);
    let artifact = induction_loop_artifact(&[R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(1, 8),
    }]);
    assert_eq!(
        recovered_induction_step(&artifact),
        Some(super::InductionStep::AddConst(1))
    );
}

#[test]
fn a_decrementing_counter_says_it_subtracts_rather_than_adding_a_huge_number() {
    // `x - 1` and `x + 0xffff_ffff_ffff_ffff` are the same bits. Reporting
    // the second would make a consumer reading the step for a bound
    // conclude the value races away from zero rather than towards it.
    let counter = Varnode::register(40, 8);
    let artifact = induction_loop_artifact(&[R2ILOp::IntSub {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(1, 8),
    }]);
    assert_eq!(
        recovered_induction_step(&artifact),
        Some(super::InductionStep::SubConst(1))
    );
}

#[test]
fn a_multiply_and_add_is_recovered_as_one_affine_step() {
    let counter = Varnode::register(40, 8);
    let scaled = Varnode::unique(0x7100, 8);
    let artifact = induction_loop_artifact(&[
        R2ILOp::IntMult {
            dst: scaled.clone(),
            a: counter.clone(),
            b: Varnode::constant(31, 8),
        },
        R2ILOp::IntAdd {
            dst: counter,
            a: scaled,
            b: Varnode::constant(7, 8),
        },
    ]);
    assert_eq!(
        recovered_induction_step(&artifact),
        Some(super::InductionStep::Affine {
            multiplier: 31,
            addend: 7,
        })
    );
}

#[test]
fn a_value_that_does_not_move_is_not_an_induction_variable() {
    // Multiplier one and addend zero is the identity. A loop-invariant is
    // not motion, and calling it one would let a consumer index by
    // something that never advances.
    let counter = Varnode::register(40, 8);
    let artifact = induction_loop_artifact(&[R2ILOp::Copy {
        dst: counter.clone(),
        src: counter,
    }]);
    assert_eq!(recovered_induction_step(&artifact), None);
    assert!(
        artifact.facts().structured.inductions.is_empty(),
        "an invariant earns no induction fact at any width"
    );
}

#[test]
fn every_recovered_induction_proves_itself_against_its_graph() {
    let counter = Varnode::register(40, 8);
    let artifact = induction_loop_artifact(&[R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(4, 8),
    }]);
    let graph = artifact.graph();
    let inductions = &artifact.facts().structured.inductions;
    assert!(!inductions.is_empty(), "the fixture has an induction");
    for (phi, fact) in inductions {
        assert_eq!(*phi, fact.phi, "keyed by the merge it describes");
        assert!(fact.validate(graph), "{fact:?} must prove itself");
    }
}

// These seven names retain the behavior facts from the deleted
// presentation-level recognizer. Eligibility is now asserted at its one
// owner, before any C symbols or statement cleanup exist.
#[test]
fn rewrites_canonical_while_to_for() {
    let artifact = counted_loop_artifact(true);
    let (prepared_loop, certificate) =
        for_certificate(&artifact).expect("canonical counted certificate");
    let loop_fact = artifact
        .facts()
        .structured
        .loops
        .get(&prepared_loop.loop_id)
        .expect("certificate loop fact");

    assert_eq!(loop_fact.kind, StructuredLoopKind::Natural);
    assert_eq!(loop_fact.latches.as_slice(), [certificate.latch]);
    assert!(loop_fact.condition.is_some());
}

#[test]
fn rewrites_continue_tail_update_to_shared_for_latch() {
    let artifact = counted_loop_with_shared_latch_artifact(false);
    let (prepared_loop, certificate) =
        for_certificate(&artifact).expect("shared latch certificate");
    assert_eq!(certificate.latch, 0x7120);
    let loop_fact = artifact
        .facts()
        .structured
        .loops
        .get(&prepared_loop.loop_id)
        .expect("shared latch loop fact");
    assert!(loop_fact.body.contains(&0x7114));
    assert!(loop_fact.body.contains(&0x7118));
}

#[test]
fn rewrites_continue_tail_with_common_suffix_before_shared_latch() {
    let artifact = counted_loop_with_shared_latch_artifact(true);
    let (prepared_loop, certificate) =
        for_certificate(&artifact).expect("common-suffix latch certificate");
    assert_eq!(certificate.latch, 0x7130);
    let loop_fact = artifact
        .facts()
        .structured
        .loops
        .get(&prepared_loop.loop_id)
        .expect("common-suffix loop fact");
    for block in [0x7118, 0x711c, 0x7120, 0x7130] {
        assert!(
            loop_fact.body.contains(&block),
            "missing body block {block:#x}"
        );
    }
}

#[test]
fn rewrites_guard_break_while1_to_for() {
    let artifact = counted_loop_artifact(true);
    let (prepared_loop, _certificate) =
        for_certificate(&artifact).expect("guard-exit counted certificate");
    let loop_fact = artifact
        .facts()
        .structured
        .loops
        .get(&prepared_loop.loop_id)
        .expect("guard-exit loop fact");
    let predicate = artifact
        .facts()
        .predicates
        .predicates
        .get(&loop_fact.condition.expect("guard predicate"))
        .expect("guard predicate fact");
    assert!(predicate.comparison.is_some());
    assert_eq!(loop_fact.exits.as_slice(), [0x7140]);
}

#[test]
fn accepts_self_assign_update_forms() {
    let add = counted_loop_with_aliases(0, 0, CountedTestStep::Add(2), false);
    let sub = counted_loop_with_aliases(0, 0, CountedTestStep::Sub(1), false);
    assert!(for_certificate(&add).is_some());
    assert!(for_certificate(&sub).is_some());

    let unsupported = counted_loop_with_aliases(0, 0, CountedTestStep::UnsupportedXor(0x55), false);
    assert!(
        for_certificate(&unsupported).is_none(),
        "a self-assignment with no exact induction algebra must remain uncertified"
    );
}

#[test]
fn rewrites_while_to_for_when_condition_uses_addrof_induction_var() {
    let artifact = counted_loop_with_aliases(1, 0, CountedTestStep::Add(1), false);
    let (prepared_loop, certificate) = for_certificate(&artifact)
        .expect("an identity projection around the compared phi remains certified");
    let loop_fact = artifact
        .facts()
        .structured
        .loops
        .get(&prepared_loop.loop_id)
        .expect("projected-condition loop fact");
    let comparison = artifact
        .facts()
        .predicates
        .predicates
        .get(&loop_fact.condition.expect("condition"))
        .and_then(|predicate| predicate.comparison.as_ref())
        .expect("comparison");
    assert_eq!(
        comparison.lhs, certificate.induction_phi,
        "identity projections are normalized before certification, so an address-style presentation wrapper cannot become a second loop identity"
    );
}

#[test]
fn rewrites_while_to_for_with_two_step_alias_update_chain() {
    let artifact = counted_loop_with_aliases(0, 2, CountedTestStep::Add(1), false);
    let (_, certificate) =
        for_certificate(&artifact).expect("two exact update projections remain certified");
    let induction = artifact
        .facts()
        .structured
        .inductions
        .get(&certificate.induction_phi)
        .expect("aliased induction fact");
    assert_eq!(induction.step, InductionStep::AddConst(1));
    assert!(induction.validate(artifact.graph()));
}

#[test]
fn loop_without_exact_induction_update_has_no_for_certificate() {
    let artifact = counted_loop_with_aliases(0, 0, CountedTestStep::UnsupportedXor(0xaa), false);
    assert!(for_certificate(&artifact).is_none());
}

#[test]
fn update_followed_by_observable_effect_has_no_for_certificate() {
    let artifact = counted_loop_with_aliases(0, 0, CountedTestStep::Add(1), true);
    assert!(
        !artifact.facts().structured.inductions.is_empty(),
        "the loop still has an exact induction update"
    );
    assert!(
        for_certificate(&artifact).is_none(),
        "moving the update after a later store would reverse their order"
    );
}

#[test]
fn exact_update_projection_chain_is_not_bounded_by_presentation_lookback() {
    let artifact = counted_loop_with_aliases(0, 5, CountedTestStep::Add(1), false);
    assert!(
        for_certificate(&artifact).is_some(),
        "five exact graph identities are proof, not a symbol lookback heuristic"
    );
}

#[test]
fn a_step_applies_at_the_width_the_machine_used() {
    let step = super::InductionStep::AddConst(1);
    assert_eq!(step.apply(0xff, 8), 0, "an eight-bit counter wraps");
    assert_eq!(step.apply(0xff, 64), 0x100, "a sixty-four bit one does not");
    assert_eq!(super::InductionStep::SubConst(1).apply(0, 8), 0xff);
}

fn indexed_stack_artifact(mask: Option<u64>, conflicting_width: bool) -> SsaArtifact {
    let sp = Varnode::register(32, 8);
    let input = Varnode::register(8, 8);
    let index = Varnode::unique(0x7200, 8);
    let address = Varnode::unique(0x7208, 8);
    let mut block = R2ILBlock::new(0x7200, 4);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(16, 8),
    });
    if let Some(mask) = mask {
        block.push(R2ILOp::IntAnd {
            dst: index.clone(),
            a: input,
            b: Varnode::constant(mask, 8),
        });
    } else {
        block.push(R2ILOp::Copy {
            dst: index.clone(),
            src: input,
        });
    }
    block.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: sp,
        b: index,
    });
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address.clone(),
        val: Varnode::constant(7, 1),
    });
    if conflicting_width {
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x7210, 2),
            space: SpaceId::Ram,
            addr: address,
        });
    }
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("indexed stack machine roles");
    SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[block],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("indexed stack artifact")
}

fn indexed_stack_layout(artifact: &SsaArtifact) -> &super::StackArrayLayoutDisposition {
    let access = artifact
        .facts()
        .structured
        .memory_accesses
        .values()
        .find(|access| artifact.objects().address_is_indexed(access.address))
        .expect("indexed stack access");
    &artifact
        .certificates()
        .stack_slots
        .get(&access.object)
        .expect("indexed stack slot certificate")
        .array_layout
}

/// `for (i = 0; i < 8; i++) buffer[i] = 7;` with the exit test in the
/// header, spelled as the machine spells it: the limit on the left.
fn counted_loop_array_artifact(exit_test: bool) -> SsaArtifact {
    let sp = Varnode::register(32, 8);
    let counter = Varnode::register(40, 8);
    let guard = Varnode::register(24, 1);
    let scaled = Varnode::unique(0x7308, 8);
    let address = Varnode::unique(0x7310, 8);

    let mut entry = R2ILBlock::new(0x7300, 4);
    entry.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(64, 8),
    });
    entry.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7304, 8),
    });

    let mut header = R2ILBlock::new(0x7304, 4);
    if exit_test {
        // `i >= 8`, which has no spelling of its own: the machine compares
        // the limit against the counter and leaves when that holds.
        header.push(R2ILOp::IntLessEqual {
            dst: guard.clone(),
            a: Varnode::constant(8, 8),
            b: counter.clone(),
        });
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x7310, 8),
            cond: guard,
        });
    } else {
        // `i > 7`, the same exit spelled with a strict comparison.
        header.push(R2ILOp::IntLess {
            dst: guard.clone(),
            a: Varnode::constant(7, 8),
            b: counter.clone(),
        });
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x7310, 8),
            cond: guard,
        });
    }

    let mut body = R2ILBlock::new(0x7308, 4);
    body.push(R2ILOp::IntMult {
        dst: scaled.clone(),
        a: counter.clone(),
        b: Varnode::constant(4, 8),
    });
    body.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: sp,
        b: scaled,
    });
    body.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address,
        val: Varnode::constant(7, 4),
    });
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x730c, 8),
    });

    let mut latch = R2ILBlock::new(0x730c, 4);
    latch.push(R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(1, 8),
    });
    latch.push(R2ILOp::Branch {
        target: Varnode::ram(0x7304, 8),
    });

    let mut exit = R2ILBlock::new(0x7310, 4);
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
            .expect("counted loop machine roles");
    SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[entry, header, body, latch, exit],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("counted loop artifact")
}

/// The same loop filling both halves of an eight-byte element, the second
/// through an address displaced four bytes from the element's base.
fn counted_loop_pair_artifact(backwards: bool) -> SsaArtifact {
    let sp = Varnode::register(32, 8);
    let counter = Varnode::register(40, 8);
    let guard = Varnode::register(24, 1);
    let scaled = Varnode::unique(0x7408, 8);
    let low = Varnode::unique(0x7410, 8);
    let high = Varnode::unique(0x7418, 8);

    let mut entry = R2ILBlock::new(0x7400, 4);
    entry.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(128, 8),
    });
    entry.push(R2ILOp::Copy {
        dst: counter.clone(),
        src: Varnode::constant(0, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::ram(0x7404, 8),
    });

    let mut header = R2ILBlock::new(0x7404, 4);
    header.push(R2ILOp::IntLessEqual {
        dst: guard.clone(),
        a: Varnode::constant(8, 8),
        b: counter.clone(),
    });
    header.push(R2ILOp::CBranch {
        target: Varnode::ram(0x7410, 8),
        cond: guard,
    });

    let mut body = R2ILBlock::new(0x7408, 4);
    body.push(R2ILOp::IntMult {
        dst: scaled.clone(),
        a: counter.clone(),
        b: Varnode::constant(8, 8),
    });
    body.push(R2ILOp::IntAdd {
        dst: low.clone(),
        a: sp.clone(),
        b: scaled.clone(),
    });
    body.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: low,
        val: Varnode::constant(7, 4),
    });
    body.push(R2ILOp::IntAdd {
        dst: high.clone(),
        a: sp,
        b: scaled,
    });
    body.push(R2ILOp::IntAdd {
        dst: high.clone(),
        a: high.clone(),
        b: Varnode::constant(if backwards { u64::MAX - 3 } else { 4 }, 8),
    });
    body.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: high,
        val: Varnode::constant(9, 4),
    });
    body.push(R2ILOp::Branch {
        target: Varnode::ram(0x740c, 8),
    });

    let mut latch = R2ILBlock::new(0x740c, 4);
    latch.push(R2ILOp::IntAdd {
        dst: counter.clone(),
        a: counter,
        b: Varnode::constant(1, 8),
    });
    latch.push(R2ILOp::Branch {
        target: Varnode::ram(0x7404, 8),
    });

    let mut exit = R2ILBlock::new(0x7410, 4);
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
            .expect("counted loop machine roles");
    SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[entry, header, body, latch, exit],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("counted loop pair artifact")
}

#[test]
fn a_remainder_is_bounded_through_the_width_its_divisor_was_widened_to() {
    // `sp[(x % 3) * 8]`, with the three zero-extended the way a machine
    // that divides a wide dividend spells it. The table is three elements.
    let sp = Varnode::register(32, 8);
    let divisor = Varnode::unique(0x7500, 16);
    let remainder = Varnode::unique(0x7508, 16);
    let narrowed = Varnode::unique(0x7510, 8);
    let scaled = Varnode::unique(0x7518, 8);
    let address = Varnode::unique(0x7520, 8);
    let mut block = R2ILBlock::new(0x7500, 4);
    block.push(R2ILOp::IntSub {
        dst: sp.clone(),
        a: sp.clone(),
        b: Varnode::constant(64, 8),
    });
    block.push(R2ILOp::IntZExt {
        dst: divisor.clone(),
        src: Varnode::constant(3, 8),
    });
    block.push(R2ILOp::IntZExt {
        dst: remainder.clone(),
        src: Varnode::register(8, 8),
    });
    block.push(R2ILOp::IntRem {
        dst: remainder.clone(),
        a: remainder.clone(),
        b: divisor,
    });
    block.push(R2ILOp::Subpiece {
        dst: narrowed.clone(),
        src: remainder,
        offset: 0,
    });
    block.push(R2ILOp::IntMult {
        dst: scaled.clone(),
        a: narrowed,
        b: Varnode::constant(8, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: sp,
        b: scaled,
    });
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x7528, 8),
        space: SpaceId::Ram,
        addr: address,
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(16, 8),
    });
    let roles =
        SourceMachineRoles::new(Some(register_storage(16, 8)), Some(register_storage(32, 8)))
            .and_then(|roles| {
                roles.with_stack_allocation_contract(SourceStackAllocationContract::new(
                    SourceStackGrowth::LowerAddresses,
                ))
            })
            .expect("widened divisor machine roles");
    let artifact = SsaArtifact::for_decompile_with_interfaces_and_machine_roles(
        &[block],
        Some(&return_boundary_arch()),
        Some(preserved_stack_interface()),
        roles,
        Vec::new(),
    )
    .expect("widened divisor artifact");
    assert!(
        matches!(
            indexed_stack_layout(&artifact),
            super::StackArrayLayoutDisposition::Proven(layout)
                if layout.element_width == 8 && layout.extent == 24
        ),
        "{:?}",
        indexed_stack_layout(&artifact)
    );
}

#[test]
fn a_displaced_element_write_reaches_past_its_index() {
    // Eight elements of eight bytes: the write four bytes into the last
    // element reaches 64, not the 60 its index alone accounts for. The
    // same write four bytes back is a step backwards, not an index of
    // 2^64 - 4, and leaves the extent the other accesses prove.
    assert_eq!(counted_loop_pair_extent(false), Some(64));
    // Four bytes back from the element, the furthest write is the plain
    // one at 56, so the object is the 60 bytes its accesses reach.
    assert_eq!(counted_loop_pair_extent(true), Some(60));
}

fn counted_loop_pair_extent(backwards: bool) -> Option<u32> {
    let artifact = counted_loop_pair_artifact(backwards);
    let object = artifact
        .facts()
        .structured
        .memory_accesses
        .values()
        .find(|access| artifact.objects().address_is_indexed(access.address))
        .expect("indexed stack access")
        .object;
    artifact
        .certificates()
        .stack_slots
        .get(&object)
        .expect("indexed stack slot certificate")
        .size
}

#[test]
fn a_counted_loop_reaches_the_last_value_its_header_admits() {
    // Eight elements of four bytes: the counter the body sees stops at 7,
    // whichever way the machine spelled the test it leaves on.
    for exit_test in [false, true] {
        let artifact = counted_loop_array_artifact(exit_test);
        assert!(
            matches!(
                indexed_stack_layout(&artifact),
                super::StackArrayLayoutDisposition::Proven(layout)
                    if layout.element_width == 4 && layout.extent == 32
            ),
            "exit_test={exit_test}: {:?}",
            indexed_stack_layout(&artifact)
        );
    }
}

#[test]
fn indexed_stack_array_geometry_is_certified_or_refused_at_its_owner() {
    let proven = indexed_stack_artifact(Some(15), false);
    assert!(matches!(
        indexed_stack_layout(&proven),
        super::StackArrayLayoutDisposition::Proven(layout)
            if layout.element_width == 1
                && layout.stride == 1
                && layout.maximum_constant_offset == 15
                && layout.extent == 16
                && layout.indexed_elements.len() == 1
    ));

    let conflicting = indexed_stack_artifact(Some(15), true);
    assert_eq!(
        indexed_stack_layout(&conflicting),
        &super::StackArrayLayoutDisposition::Refused(
            super::StackArrayLayoutRefusal::ConflictingAccessWidths,
        )
    );

    let unbounded = indexed_stack_artifact(None, false);
    assert_eq!(
        indexed_stack_layout(&unbounded),
        &super::StackArrayLayoutDisposition::Refused(
            super::StackArrayLayoutRefusal::MissingConstantOffset,
        )
    );
}

#[test]
fn control_domains_intersect_shared_default_paths() {
    let blocks = vec![
        conditional_block(0x1000, 0, 0x1040),
        branch_block(0x1004, 0x1044),
        conditional_block(0x1040, 8, 0x1080),
        branch_block(0x1044, 0x10c0),
        branch_block(0x1080, 0x10c0),
        R2ILBlock::new(0x10c0, 4),
    ];
    let artifact = SsaArtifact::for_decompile(&blocks, None).expect("prepared SSA");
    let root_predicate = artifact
        .predicates()
        .predicates
        .values()
        .find(|predicate| predicate.block_addr == 0x1000)
        .expect("root predicate")
        .id;
    let nested_predicate = artifact
        .predicates()
        .predicates
        .values()
        .find(|predicate| predicate.block_addr == 0x1040)
        .expect("nested predicate")
        .id;

    let nested = artifact
        .control_domains()
        .for_block(0x1080)
        .expect("nested true domain");
    assert!(nested.complete);
    assert_eq!(
        nested.guards,
        vec![
            ControlGuard::Branch {
                predicate: root_predicate,
                truth: true,
            },
            ControlGuard::Branch {
                predicate: nested_predicate,
                truth: true,
            },
        ]
    );

    let shared_default = artifact
        .control_domains()
        .for_block(0x1044)
        .expect("shared default domain");
    assert!(shared_default.complete);
    assert!(shared_default.guards.is_empty());
    let merge = artifact
        .control_domains()
        .for_block(0x10c0)
        .expect("merge domain");
    assert!(merge.complete);
    assert!(merge.guards.is_empty());
}

#[test]
fn byte_sources_follow_zero_extension_insertion_and_copies() {
    use super::{ByteSource, MemberRunSource, member_run_source, value_byte_sources};
    let ops = vec![
        R2ILOp::Load {
            dst: Varnode::unique(0x100, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x18da8, 8),
        },
        R2ILOp::IntZExt {
            dst: Varnode::unique(0x200, 16),
            src: Varnode::unique(0x100, 8),
        },
        R2ILOp::Load {
            dst: Varnode::unique(0x108, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x18db8, 8),
        },
        R2ILOp::Insert {
            dst: Varnode::unique(0x210, 16),
            src: Varnode::unique(0x200, 16),
            value: Varnode::unique(0x108, 8),
            position: Varnode::constant(64, 4),
        },
        R2ILOp::Copy {
            dst: Varnode::unique(0x220, 16),
            src: Varnode::unique(0x210, 16),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0, 8),
            val: Varnode::unique(0x220, 16),
        },
    ];
    let artifact = SsaArtifact::for_symbolic(
        &[R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops,
            switch_info: None,
            op_metadata: Default::default(),
        }],
        None,
    )
    .expect("lane composite artifact");
    let graph = artifact.graph();
    let store = graph
        .insts
        .iter()
        .find(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::Store { .. })))
        .expect("the store");
    let bytes = value_byte_sources(graph, None, store.inputs[1]).expect("byte sources");
    assert_eq!(bytes.len(), 16);
    let first = graph
        .insts
        .iter()
        .find(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::Load { .. })))
        .and_then(|inst| inst.output)
        .expect("first lane");
    let second = graph
        .insts
        .iter()
        .filter(|inst| matches!(inst.payload, InstPayload::Op(SSAOp::Load { .. })))
        .nth(1)
        .and_then(|inst| inst.output)
        .expect("second lane");
    for (byte, source) in bytes.iter().enumerate() {
        let expected = if byte < 8 {
            ByteSource::Lane {
                value: first,
                byte: byte as u32,
            }
        } else {
            ByteSource::Lane {
                value: second,
                byte: byte as u32 - 8,
            }
        };
        assert_eq!(*source, expected, "byte {byte}");
    }
    assert_eq!(
        member_run_source(&bytes[..8]),
        Some(MemberRunSource::Lane(first))
    );
    assert_eq!(
        member_run_source(&bytes[8..]),
        Some(MemberRunSource::Lane(second))
    );
    // A slice that starts inside a value is nobody's whole value.
    assert_eq!(member_run_source(&bytes[4..12]), None);
    assert_eq!(
        member_run_source(&[ByteSource::Constant(0x34), ByteSource::Constant(0x12)]),
        Some(MemberRunSource::Constant(0x1234))
    );
}

/// The call result a body only returns is still the call's result.
#[test]
fn a_convention_result_read_only_by_the_return_is_the_call_result() {
    let mut arch = ArchSpec::new("x86");
    arch.addr_size = 4;
    arch.add_register(RegisterDef::new("eax", 0, 4));
    arch.add_register(RegisterDef::new("ecx", 4, 4));
    arch.add_register(RegisterDef::new("edx", 8, 4));
    arch.add_register(RegisterDef::new("eip", 12, 4));
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Call {
        target: Varnode::ram(0x2000, 4),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(12, 4),
    });
    // cdecl: the three scratch registers are clobbered, the return target is not.
    let effect = crate::testing::call_effect(
        [0, 4, 8].map(|offset| register_storage(offset, 4)),
        [register_storage(12, 4)],
    );
    let artifact = crate::testing::prepared_under(&[block], &arch, None, Vec::new(), effect)
        .expect("artifact");
    let eax = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 0,
        size: 4,
    };
    let (function, graph) = (artifact.function(), artifact.graph());
    let live_out = crate::liveout::FunctionLiveOut::compute(function, graph, &[eax]);
    let call_index = function
        .get_block(0x1000)
        .expect("entry block")
        .ops
        .iter()
        .position(|op| matches!(op, SSAOp::Call { .. }))
        .expect("the call survives");
    let found = super::observed_convention_call_result_after_call(
        function, graph, &live_out, 0x1000, call_index, eax,
    )
    .expect("the returned clobber is this call's result");
    // Nothing in the body reads it, which is what the use list alone gets wrong.
    assert!(graph.use_sites(found.value).is_empty());
}
