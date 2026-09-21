//! What the collector proves crosses a call or a return.

use super::super::*;
use super::*;

#[test]
fn stack_helpers_require_exact_ram_source_fact_object_and_memory_location() {
    let mut block = R2ILBlock::new(0x1100, 4);
    block.push(R2ILOp::Load {
        dst: Varnode::unique(0x100, 8),
        space: SpaceId::Ram,
        addr: Varnode::constant(0x4000, 8),
    });
    let artifact = SsaArtifact::for_symbolic(&[block], None).expect("RAM load artifact");
    let access = artifact
        .facts()
        .structured
        .memory_accesses
        .values()
        .next()
        .expect("RAM load access")
        .clone();
    let mut objects = artifact.objects().clone();
    objects
        .objects
        .get_mut(&access.object)
        .expect("RAM load object")
        .kind = ObjectKind::StackSlot {
        space: SpaceId::Ram,
        base: StackAddressBase::StackPointer,
        offset: -8,
    };
    let structured = artifact.facts().structured.clone();

    assert!(super::super::ram_memory_access_matches_source(
        artifact.function(),
        artifact.graph(),
        &objects,
        &access,
    ));
    assert_eq!(
        super::super::stack_memory_access_at(super::super::StackMemoryAccessInput {
            function: artifact.function(),
            graph: artifact.graph(),
            structured: &structured,
            objects: &objects,
            block_addr: access.block_addr,
            op_index: access.op_index,
            is_write: false,
            value: access.value,
        }),
        Some((access.object, -8, access.id))
    );
    let facts = artifact.facts();
    let certificates = super::super::collect_prepared_function_certificates(
        super::super::Body {
            function: artifact.function(),
            graph: artifact.graph(),
            machine_context: Some(artifact.machine_context()),
        },
        super::super::Derived {
            values: &Default::default(),
            boundaries: &facts.boundaries,
            objects: &objects,
            memory: &facts.memory,
            predicates: &facts.predicates,
            call_sites: &facts.call_sites,
            structured: &structured,
        },
        artifact.unobserved_merges(),
        artifact.live_out(),
        &BTreeSet::new(),
        &super::super::DeclaredStackSlots::default(),
        BTreeMap::new(),
    );
    assert_eq!(
        certificates
            .stack_slots
            .get(&access.object)
            .map(|slot| slot.space),
        Some(SpaceId::Ram)
    );

    let mut mismatched_fact = access.clone();
    mismatched_fact.space = SpaceId::Custom(7);
    assert!(!super::super::ram_memory_access_matches_source(
        artifact.function(),
        artifact.graph(),
        &objects,
        &mismatched_fact,
    ));

    let mut mismatched_objects = objects.clone();
    mismatched_objects
        .objects
        .get_mut(&access.object)
        .expect("RAM load object")
        .kind = ObjectKind::StackSlot {
        space: SpaceId::Custom(7),
        base: StackAddressBase::StackPointer,
        offset: -8,
    };
    assert!(!super::super::ram_memory_access_matches_source(
        artifact.function(),
        artifact.graph(),
        &mismatched_objects,
        &access,
    ));
    let certificates = super::super::collect_prepared_function_certificates(
        super::super::Body {
            function: artifact.function(),
            graph: artifact.graph(),
            machine_context: Some(artifact.machine_context()),
        },
        super::super::Derived {
            values: &Default::default(),
            boundaries: &facts.boundaries,
            objects: &mismatched_objects,
            memory: &facts.memory,
            predicates: &facts.predicates,
            call_sites: &facts.call_sites,
            structured: &structured,
        },
        artifact.unobserved_merges(),
        artifact.live_out(),
        &BTreeSet::new(),
        &super::super::DeclaredStackSlots::default(),
        BTreeMap::new(),
    );
    assert!(!certificates.stack_slots.contains_key(&access.object));

    let mut mismatched_memory = artifact.facts().memory.clone();
    for use_fact in mismatched_memory
        .uses_by_inst
        .get_mut(&access.id.inst)
        .expect("RAM memory use")
    {
        use_fact.location.space = SpaceId::Custom(7);
    }
    assert!(super::super::unique_memory_use_for_access(&mismatched_memory, &access).is_none());
}
