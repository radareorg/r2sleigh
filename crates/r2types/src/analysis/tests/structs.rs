//! What the analysis proves about aggregates.

use super::super::*;

fn buffer_then_undeclared_pointer() -> (r2il::ArchSpec, r2ssa::SourceFunctionInterface) {
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let mut arch = r2il::ArchSpec::new("aarch64");
    arch.addr_size = 8;
    arch.add_register(r2il::RegisterDef::new("x0", 0, 8));
    arch.add_register(r2il::RegisterDef::new("x1", 8, 8));
    arch.add_register(r2il::RegisterDef::new("sp", 16, 8));
    arch.add_register(r2il::RegisterDef::new("lr", 24, 8));
    let graph = r2ssa::SourceTypeGraph::new(
        [
            r2ssa::SourceType::new(
                0,
                r2ssa::SourceTypeKind::Struct { aggregate_id: 0 },
                16 * 8,
                64,
            ),
            r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::UnsignedInteger, 64, 64),
            r2ssa::SourceType::new(
                2,
                r2ssa::SourceTypeKind::Pointer {
                    target_type_id: 0,
                    const_target: false,
                },
                64,
                64,
            ),
            r2ssa::SourceType::new(3, r2ssa::SourceTypeKind::Void, 0, 0),
            r2ssa::SourceType::new(
                4,
                r2ssa::SourceTypeKind::Pointer {
                    target_type_id: 3,
                    const_target: false,
                },
                64,
                64,
            ),
        ],
        [r2ssa::SourceAggregateLayout::new(
            0,
            0,
            16 * 8,
            64,
            "Buffer",
            [
                r2ssa::SourceAggregateMember::new(0, 1, 0, 64, "data"),
                r2ssa::SourceAggregateMember::new(1, 1, 64, 64, "len"),
            ],
        )],
    )
    .expect("Buffer graph");
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"member-names-by-parameter".to_vec(),
        r2source::ConventionId::Aapcs64,
        [
            r2ssa::SourceAbiParameterSpec::new(0, storage(0)),
            r2ssa::SourceAbiParameterSpec::new(1, storage(8)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
        [
            Some(r2ssa::SourceLogicalValue::new(
                2,
                r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
            )),
            Some(r2ssa::SourceLogicalValue::new(
                4,
                r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
            )),
        ],
        None,
        Some(graph),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(24)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(16)))
    .expect("two-parameter interface");
    (arch, interface)
}

#[test]
fn a_source_member_name_reaches_only_its_own_parameter_s_fields() {
    // `len` is a member of what parameter 0 points at; parameter 1 points at an undeclared aggregate read at the same offset.
    let (arch, interface) = buffer_then_undeclared_pointer();
    let load = |dst, addr| r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(dst, 8),
        space: r2il::SpaceId::Ram,
        addr,
    };
    let add = |dst, base, offset| r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(dst, 8),
        a: r2il::Varnode::register(base, 8),
        b: r2il::Varnode::constant(offset, 8),
    };
    let block = r2il::R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops: vec![
            add(0x10, 0, 8),
            load(0x20, r2il::Varnode::unique(0x10, 8)),
            load(0x30, r2il::Varnode::register(8, 8)),
            add(0x40, 8, 8),
            load(0x50, r2il::Varnode::unique(0x40, 8)),
        ],
        ..Default::default()
    };
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&r2ssa::Arch::from(arch)),
        interface,
    )
    .expect("prepared two-parameter function");
    let analysis = build_source_owned_type_analysis(
        TypeAnalysisRequest::new(Arc::new(prepared), ParsedExternalContext::default())
            .expect("coherent request"),
    )
    .expect("type analysis");
    let named = |slot, offset| {
        analysis
            .type_facts()
            .field_access_certificates
            .iter()
            .find(|certificate| certificate.slot == slot && certificate.field_offset == offset)
            .map(|certificate| certificate.field_name.clone())
    };
    assert_eq!(named(0, 8).as_deref(), Some("len"));
    assert_ne!(
        named(1, 8).as_deref(),
        Some("len"),
        "parameter 1's field took the name of parameter 0's member"
    );
}

/// An aarch64 function of two pointer parameters typed `first` and `second` in `graph`.
fn two_pointers(
    graph: r2ssa::SourceTypeGraph,
    first: u32,
    second: u32,
) -> (r2il::ArchSpec, r2ssa::SourceFunctionInterface) {
    let (arch, template) = buffer_then_undeclared_pointer();
    let full = r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64);
    let storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
        b"layouts-by-type-id".to_vec(),
        template.convention(),
        [
            r2ssa::SourceAbiParameterSpec::new(0, storage(0)),
            r2ssa::SourceAbiParameterSpec::new(1, storage(8)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
        [
            Some(r2ssa::SourceLogicalValue::new(first, full)),
            Some(r2ssa::SourceLogicalValue::new(second, full)),
        ],
        None,
        Some(graph),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(24)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(16)))
    .expect("two-pointer interface");
    (arch, interface)
}

/// One load of `width` bytes at each `(register offset, displacement)`.
fn loads(width: u32, at: &[(u64, u64)]) -> r2il::R2ILBlock {
    let mut ops = Vec::new();
    for (index, (base, displacement)) in at.iter().enumerate() {
        let address = 0x100 + 0x20 * index as u64;
        ops.push(r2il::R2ILOp::IntAdd {
            dst: r2il::Varnode::unique(address, 8),
            a: r2il::Varnode::register(*base, 8),
            b: r2il::Varnode::constant(*displacement, 8),
        });
        ops.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(address + 8, width),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(address, 8),
        });
    }
    r2il::R2ILBlock {
        addr: 0x1000,
        size: 4,
        ops,
        ..Default::default()
    }
}

fn field_names(
    arch: r2il::ArchSpec,
    interface: r2ssa::SourceFunctionInterface,
    block: r2il::R2ILBlock,
) -> Vec<(usize, u64, String)> {
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&r2ssa::Arch::from(arch)),
        interface,
    )
    .expect("prepared function");
    let analysis = build_source_owned_type_analysis(
        TypeAnalysisRequest::new(Arc::new(prepared), ParsedExternalContext::default())
            .expect("coherent request"),
    )
    .expect("type analysis");
    (analysis.type_facts().field_access_certificates.iter())
        .map(|field| (field.slot, field.field_offset, field.field_name.clone()))
        .collect()
}

fn pointer_to(id: u32, target: u32) -> r2ssa::SourceType {
    let kind = r2ssa::SourceTypeKind::Pointer {
        target_type_id: target,
        const_target: false,
    };
    r2ssa::SourceType::new(id, kind, 64, 64)
}

/// D345 gate 1: `struct Node` and `struct node` are two layouts; a name collision merges none.
#[test]
fn two_tags_differing_in_case_keep_their_own_members() {
    use r2ssa::{SourceAggregateLayout as Layout, SourceAggregateMember as Member, SourceType};
    let int = r2ssa::SourceTypeKind::SignedInteger;
    let graph = r2ssa::SourceTypeGraph::new(
        [
            SourceType::new(0, r2ssa::SourceTypeKind::Struct { aggregate_id: 0 }, 64, 32),
            SourceType::new(1, int, 32, 32),
            pointer_to(2, 0),
            SourceType::new(3, r2ssa::SourceTypeKind::Struct { aggregate_id: 1 }, 64, 64),
            SourceType::new(4, int, 64, 64),
            pointer_to(5, 3),
        ],
        [
            Layout::new(
                0,
                0,
                64,
                32,
                "Node",
                [
                    Member::new(0, 1, 0, 32, "a"),
                    Member::new(1, 1, 32, 32, "b"),
                ],
            ),
            Layout::new(1, 3, 64, 64, "node", [Member::new(0, 4, 0, 64, "x")]),
        ],
    )
    .expect("two tags");
    let (arch, interface) = two_pointers(graph, 2, 5);
    let names = field_names(arch, interface, loads(4, &[(0, 4)]));
    assert_eq!(names, [(0, 4, "b".to_string())]);
}

/// D345 gate 2: `typedef struct other pool` strides by `struct other`, never by `struct pool`.
#[test]
fn a_typedef_strides_by_its_target_never_by_a_tag_sharing_its_name() {
    use r2ssa::{SourceAggregateLayout as Layout, SourceAggregateMember as Member, SourceType};
    let long = r2ssa::SourceTypeKind::SignedInteger;
    let graph = r2ssa::SourceTypeGraph::new_with_aliases(
        [
            SourceType::new(
                0,
                r2ssa::SourceTypeKind::Struct { aggregate_id: 0 },
                192,
                64,
            ),
            SourceType::new(1, long, 64, 64),
            SourceType::new(2, r2ssa::SourceTypeKind::Struct { aggregate_id: 1 }, 64, 64),
            pointer_to(3, 0),
            pointer_to(4, 2),
        ],
        [
            Layout::new(
                0,
                0,
                192,
                64,
                "other",
                (0..3).map(|i| Member::new(i, 1, u64::from(i) * 64, 64, format!("m{i}"))),
            ),
            Layout::new(1, 2, 64, 64, "pool", [Member::new(0, 1, 0, 64, "p")]),
        ],
        [r2ssa::SourceTypeAlias::new("pool".to_string(), 0)],
    )
    .expect("typedef and tag");
    let (arch, interface) = two_pointers(graph, 3, 4);
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[loads(8, &[(0, 16)])],
        Some(&r2ssa::Arch::from(arch)),
        interface,
    )
    .expect("prepared function");
    let local = infer_local_struct_artifacts_from_prepared_ssa(&prepared);
    assert_eq!(local.pointee_strides, [Some(24), Some(8)]);
}
