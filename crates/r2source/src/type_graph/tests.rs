use super::*;

fn ty(id: u32, kind: SourceTypeKind, size: u64, align: u64) -> SourceType {
    SourceType::new(id, kind, size, align)
}

fn int(id: u32, bits: u64, align: u64) -> SourceType {
    ty(id, SourceTypeKind::SignedInteger, bits, align)
}

/// `struct { int a; double d; }` as i386 lays it out: `d` at four bytes,
/// because the i386 ABI aligns a `double` in a struct to four. The natural
/// layout puts it at eight, and demanding that refused every such struct.
#[test]
fn an_i386_layout_is_a_stated_layout() {
    let graph = SourceTypeGraph::new(
        [
            int(0, 32, 32),
            ty(1, SourceTypeKind::Float, 64, 32),
            ty(2, SourceTypeKind::Struct { aggregate_id: 0 }, 96, 32),
        ],
        [SourceAggregateLayout::new(
            0,
            2,
            96,
            32,
            "mixed",
            [
                SourceAggregateMember::new(0, 0, 0, 32, "a"),
                SourceAggregateMember::new(1, 1, 32, 64, "d"),
            ],
        )],
    );
    assert!(graph.is_ok(), "{graph:?}");
}

/// `struct { char c; int x; } __attribute__((packed))`: `x` at one byte.
#[test]
fn a_packed_layout_is_a_stated_layout() {
    let graph = SourceTypeGraph::new(
        [
            int(0, 8, 8),
            int(1, 32, 32),
            ty(2, SourceTypeKind::Struct { aggregate_id: 0 }, 40, 8),
        ],
        [SourceAggregateLayout::new(
            0,
            2,
            40,
            8,
            "packed",
            [
                SourceAggregateMember::new(0, 0, 0, 8, "c"),
                SourceAggregateMember::new(1, 1, 8, 32, "x"),
            ],
        )],
    );
    assert!(graph.is_ok(), "{graph:?}");
}

/// What makes a layout a layout still holds: no member over another, none
/// outside its record.
#[test]
fn an_inconsistent_layout_is_refused() {
    let members = |second_offset: u64| {
        SourceTypeGraph::new(
            [
                int(0, 32, 32),
                ty(1, SourceTypeKind::Struct { aggregate_id: 0 }, 64, 32),
            ],
            [SourceAggregateLayout::new(
                0,
                1,
                64,
                32,
                "pair",
                [
                    SourceAggregateMember::new(0, 0, 0, 32, "a"),
                    SourceAggregateMember::new(1, 0, second_offset, 32, "b"),
                ],
            )],
        )
    };
    assert!(members(32).is_ok());
    assert_eq!(members(16), Err(SourceTypeGraphError::InvalidMember));
    assert_eq!(members(48), Err(SourceTypeGraphError::InvalidMember));
    // A size that is no multiple of its alignment is no C object.
    assert_eq!(
        SourceTypeGraph::new([int(0, 32, 64)], []),
        Err(SourceTypeGraphError::InvalidType)
    );
}

/// `FILE *`: a pointer to a tag the source never completes.
#[test]
fn a_pointer_to_an_incomplete_type_is_a_pointer() {
    let graph = SourceTypeGraph::from_parts(SourceTypeGraphParts {
        types: vec![
            ty(0, SourceTypeKind::Opaque { tag_id: 0 }, 0, 0),
            ty(1, SourceTypeKind::Pointer { target_type_id: 0 }, 64, 64),
        ],
        opaque_tags: vec![SourceOpaqueTag::new(0, SourceTagKeyword::Typedef, "FILE")],
        ..SourceTypeGraphParts::default()
    })
    .expect("a pointer to FILE");
    assert_eq!(graph.opaque_tags()[0].name(), "FILE");
    // An incomplete type holds nothing: it is no member and no value.
    let value = SourceLogicalValue::new(
        0,
        SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 0),
    );
    assert!(!graph.validates_logical_value(value, 8));
}

/// `struct flags { unsigned ready : 1; unsigned mode : 3; unsigned char tag;
/// int values[]; }`: two bit-fields and a flexible array member.
#[test]
fn bit_fields_and_a_flexible_array_member_are_a_layout() {
    let graph = SourceTypeGraph::new(
        [
            ty(0, SourceTypeKind::UnsignedInteger, 32, 32),
            ty(1, SourceTypeKind::UnsignedInteger, 8, 8),
            int(2, 32, 32),
            ty(
                3,
                SourceTypeKind::Array {
                    element_type_id: 2,
                    count: None,
                },
                0,
                32,
            ),
            ty(4, SourceTypeKind::Struct { aggregate_id: 0 }, 32, 32),
        ],
        [SourceAggregateLayout::new(
            0,
            4,
            32,
            32,
            "flags",
            [
                SourceAggregateMember::new_bit_field(0, 0, 0, 1, "ready"),
                SourceAggregateMember::new_bit_field(1, 0, 1, 3, "mode"),
                SourceAggregateMember::new(2, 1, 8, 8, "tag"),
                SourceAggregateMember::new(3, 3, 32, 0, "values"),
            ],
        )],
    );
    assert!(graph.is_ok(), "{graph:?}");
}

/// `int (*)(int, int)`: code with the signature the source states.
#[test]
fn code_carries_its_signature() {
    let graph = SourceTypeGraph::from_parts(SourceTypeGraphParts {
        types: vec![
            int(0, 32, 32),
            ty(1, SourceTypeKind::Code { signature_id: 0 }, 0, 0),
            ty(2, SourceTypeKind::Pointer { target_type_id: 1 }, 64, 64),
        ],
        signatures: vec![SourceCodeSignature::new(0, 0, [0, 0], false, true)],
        ..SourceTypeGraphParts::default()
    })
    .expect("a function pointer");
    assert_eq!(graph.signatures()[0].parameter_type_ids(), [0, 0]);
}

/// A slot dropped from an interface leaves its type named by nothing. The
/// closure keeps what the rest names and renumbers it; it never refuses.
#[test]
fn a_closure_keeps_what_its_roots_reach_and_nothing_else() {
    let graph = SourceTypeGraph::new(
        [
            int(0, 32, 32),
            ty(1, SourceTypeKind::Float, 64, 64),
            ty(2, SourceTypeKind::Pointer { target_type_id: 3 }, 64, 64),
            ty(3, SourceTypeKind::Struct { aggregate_id: 0 }, 128, 64),
        ],
        [SourceAggregateLayout::new(
            0,
            3,
            128,
            64,
            "node",
            [
                SourceAggregateMember::new(0, 0, 0, 32, "key"),
                SourceAggregateMember::new(1, 2, 64, 64, "next"),
            ],
        )],
    )
    .expect("a node graph");
    let closure = graph.closure([2]);
    assert_eq!(closure.id(1), None, "the double nothing names is gone");
    assert_eq!(closure.id(2), Some(1));
    let closed = closure.graph();
    assert_eq!(closed.types().len(), 3);
    // The cycle through `next` survives renumbering.
    assert_eq!(
        closed.types()[1].kind(),
        SourceTypeKind::Pointer { target_type_id: 2 }
    );
    assert_eq!(closed.aggregates()[0].members()[1].type_id(), 1);
    // And the closure is itself a valid graph.
    assert!(SourceTypeGraph::new(closed.types().to_vec(), closed.aggregates().to_vec()).is_ok());
    // A closed graph closes onto itself unchanged.
    assert_eq!(graph.closure([0, 1, 2]).graph(), &graph);
}
