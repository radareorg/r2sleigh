//! What the analysis proves about aggregates.

use super::super::*;
use super::*;

#[test]
fn signature_type_parser_preserves_source_width_typedefs() {
    assert_eq!(
        crate::convert::operator_type_hint("long", 64),
        Some(typedef_type("long"))
    );
    assert_eq!(
        crate::convert::operator_type_hint("unsigned long int", 64),
        Some(typedef_type("unsigned long"))
    );
    assert_eq!(
        crate::convert::operator_type_hint("short", 64),
        Some(typedef_type("short"))
    );
    assert_eq!(
        crate::convert::operator_type_hint("size_t", 64),
        Some(typedef_type("size_t"))
    );
    assert_eq!(
        crate::convert::operator_type_hint("ptrdiff_t", 64),
        Some(typedef_type("ptrdiff_t"))
    );
}

#[test]
fn local_struct_decl_preserves_sparse_offsets_with_padding() {
    let decl = build_struct_decl(
        "sla_struct_sparse",
        &[
            StructFieldCandidate {
                name: "f_8".to_string(),
                offset: 8,
                field_type: parse_test_type("int32_t", 64),
            },
            StructFieldCandidate {
                name: "f_34".to_string(),
                offset: 0x34,
                field_type: parse_test_type("int32_t", 64),
            },
        ],
        64,
    )
    .expect("struct decl");

    assert!(decl.contains("uint8_t _pad_0[8];"), "{decl}");
    assert!(decl.contains("int32_t f_8;"), "{decl}");
    assert!(decl.contains("uint8_t _pad_c[40];"), "{decl}");
    assert!(decl.contains("int32_t f_34;"), "{decl}");
}

#[test]
fn imported_size_t_type_hint_matches_preserved_source_typedef() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("rsi-size".to_string()),
            subject: r2ssa::AssumptionSubject::Register {
                name: "rsi".to_string(),
            },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "size_t".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::ImportedContext,
        }]),
        register_params: vec![crate::context::ExternalRegisterParamSpec {
            name: "n".to_string(),
            ty: Some(CTypeLike::typedef("size_t")),
            reg: "rsi".to_string(),
        }],
        merged_signature: Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::typedef("size_t")),
            params: vec![FunctionParamSpec {
                name: "n".to_string(),
                ty: Some(CTypeLike::typedef("size_t")),
            }],
        }),
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.scan_example".to_string(),
        signature: "size_t sym.scan_example(size_t n)".to_string(),
        ret_type: Some(parse_test_type("size_t", 64)),
        params: vec![InferredSignatureParam {
            name: "n".to_string(),
            ty: parse_test_type("size_t", 64),
        }],
        callconv: "amd64".to_string(),
        arch: "x86-64".to_string(),
    };

    let usage = apply_type_hint_assumptions_to_context(
        &mut parsed_context,
        &mut inferred_signature,
        64,
        Some(&SemanticTypeProjection::default()),
        &x86_64_register_identity(),
    );

    assert_eq!(usage.applied.len(), 1);
    assert!(usage.ignored.is_empty());
    assert!(usage.conflicts.is_empty());
    assert_eq!(
        parsed_context.register_params[0]
            .ty
            .as_ref()
            .map(|ty| render_signature_type(ty, 64))
            .as_deref(),
        Some("size_t")
    );
}

/// Parameter 0 points at a declared `Buffer { data, len }`; parameter 1 is a
/// `void *`, which says it is a pointer and nothing about what it points at.
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
