mod arrays;
mod assumptions;
mod bindings;
mod signature;
mod stack;
mod structs;

use r2ssa::PhiNode;

use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn parse_test_type(spelling: &str, ptr_bits: u32) -> CTypeLike {
    parse_c_type_like(spelling, ptr_bits).expect("test type spelling should parse")
}

#[test]
fn unplaceable_recovered_type_produces_no_candidate() {
    let vars = [RecoveredVariable {
        name: "var_8h".to_string(),
        kind: "b".to_string(),
        delta: -8,
        var_type: "not a type".to_string(),
        isarg: false,
        reg: None,
    }];
    let context_maps = SignatureContextMaps::default();
    let slot_type_overrides = HashMap::new();
    let stack_slots = BTreeMap::new();
    let existing_types = HashMap::new();
    let stack_access_widths = BTreeMap::new();
    let stack_access_signedness = BTreeMap::new();
    let context = VarTypeCandidateContext {
        current_context_maps: &context_maps,
        merged_signature: None,
        slot_type_overrides: &slot_type_overrides,
        stack_slots: &stack_slots,
        existing_types: &existing_types,
        stack_access_widths: &stack_access_widths,
        stack_access_signedness: &stack_access_signedness,
        ptr_bits: 64,
        is_main_signature: false,
    };
    let mut diagnostics = TypeAnalysisDiagnostics::default();

    let candidates = build_var_type_candidates(&vars, &context, &mut diagnostics);

    assert!(candidates.is_empty());
    assert_eq!(
        diagnostics.warnings,
        ["var `var_8h` type `not a type` was not a placeable C type"]
    );
}

#[test]
fn constant_offsets_require_exact_ssa_evidence() {
    let spoofed = SSAVar::new("const:20", 0, 8);
    let exact = SSAVar::constant(0x20, 8);

    assert_eq!(exact_ssa_const_offset(&spoofed, 64), None);
    assert_eq!(exact_ssa_const_offset(&exact, 64), Some(0x20));
}

#[test]
fn source_owned_function_facts_has_no_serde_contract() {
    trait AmbiguousIfSerialize<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<u8> for T {}

    trait AmbiguousIfDeserialize<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
    impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<u8> for T {}

    let _ = <SourceOwnedFunctionFacts as AmbiguousIfSerialize<_>>::marker;
    let _ = <SourceOwnedFunctionFacts as AmbiguousIfDeserialize<_>>::marker;
}

#[test]
fn source_owned_analysis_propagates_interproc_schema_error() {
    let stale = InterprocSummarySet {
        schema_version: 1,
        ..InterprocSummarySet::default()
    };

    assert_eq!(
        require_current_interproc_report_for_source_owned(Some(&stale)),
        Err(TypeAnalysisError::InterprocSummarySchema(
            r2ssa::interproc::InterprocSummarySchemaError::ReportSchemaVersion { found: 1 },
        ))
    );
}

#[test]
fn detached_advisory_analysis_drops_invalid_interproc_schema() {
    let stale = InterprocSummarySet {
        schema_version: 1,
        ..InterprocSummarySet::default()
    };

    let view = InterprocSummaryView::new(Some(stale)).unwrap_or_default();
    assert!(view.as_set().is_none());
    assert!(view.root_summary().is_none());
    assert!(view.pointer_param_indices().is_empty());
}

#[test]
fn local_pointee_type_evidence_requires_exact_ram_space() {
    let ram_addr = SSAVar::new("ram_addr", 1, 8);
    let custom_addr = SSAVar::new("custom_addr", 1, 8);
    let blocks = [SSABlock {
        addr: 0x1000,
        phis: Vec::new(),
        ops: vec![
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: ram_addr.clone(),
                val: SSAVar::new("ram_value", 1, 4),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Custom(7),
                addr: custom_addr.clone(),
                val: SSAVar::new("custom_value", 1, 8),
            },
        ],
        size: 0,
    }];

    let types = local_pointer_pointee_types(&blocks, 64, &HashMap::new());
    assert_eq!(
        types.get(&ram_addr),
        Some(&BTreeSet::from(["int32_t".to_string()]))
    );
    assert!(!types.contains_key(&custom_addr));
}

fn test_signature_spec(param_name: &str, param_bits: u32) -> FunctionSignatureSpec {
    FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        }),
        params: vec![FunctionParamSpec {
            name: param_name.to_string(),
            ty: Some(CTypeLike::Int {
                bits: param_bits,
                signedness: Signedness::Signed,
            }),
        }],
    }
}

fn three_prepared_frame_slot_roots() -> r2ssa::DecompilePrepFacts {
    r2ssa::DecompilePrepFacts {
        stack_address_roots: [(1, -8), (2, -12), (3, -16)]
            .into_iter()
            .map(|(version, offset)| {
                (
                    SSAVar::new("tmp:slot", version, 8),
                    r2ssa::StackAddressRoot {
                        base: r2ssa::StackAddressBase::FramePointer,
                        offset,
                    },
                )
            })
            .collect(),
        ..r2ssa::DecompilePrepFacts::default()
    }
}

/// Storage that an access states only the width of is a type C spells at
/// every width: an integer where C has one, the carrier past that, and no
/// type for no bytes. Both renderers spell it one way, and it reads back as
/// the type it was.
#[test]
fn storage_of_every_width_is_a_type_c_spells() {
    assert_eq!(storage_type(0, Signedness::Signed), None);
    for (bytes, signedness, spelling) in [
        (4, Signedness::Signed, "int32_t"),
        (8, Signedness::Unsigned, "uint64_t"),
        (10, Signedness::Signed, "struct r2sleigh_bits_80"),
        (16, Signedness::Signed, "__int128_t"),
        (16, Signedness::Unsigned, "__uint128_t"),
        (32, Signedness::Signed, "struct r2sleigh_bits_256"),
    ] {
        let ty = storage_type(bytes, signedness).expect("a width is storage");
        assert_eq!(ty, CTypeLike::machine_storage(bytes * 8, signedness));
        assert_eq!(render_c_type_like(&ty), spelling);
        assert_eq!(render_signature_type(&ty, 64), spelling);
        assert_eq!(parse_c_type_like(spelling, 64), Some(ty));
    }
    // A carrier states a width and nothing else, so any type outranks it. A
    // 128-bit integer is an integer, like the narrower ones.
    assert!(type_name_is_generic("struct r2sleigh_bits_256"));
    assert!(!type_name_is_generic("__int128_t"));
}

#[test]
fn type_name_policy_matches_planner_guard() {
    assert!(type_name_is_opaque_placeholder("struct type_0x1234 *"));
    assert!(type_name_is_opaque_placeholder("struct anon_field"));
    assert!(!type_name_is_opaque_placeholder("struct real_type *"));

    for generic in ["void *", "const char *", "unsigned char*", "unsigned long"] {
        assert!(
            type_name_is_generic(generic),
            "{generic:?} should stay a weak planner type"
        );
    }
    assert!(!type_name_is_generic("struct real_type *"));
}

#[test]
fn phi_scalar_pointer_value_preserves_max_confidence() {
    let block_addr = 0x401000;
    let dst = SSAVar::new("phi_ptr", 1, 8);
    let left = SSAVar::new("left_ptr", 1, 8);
    let right = SSAVar::new("right_ptr", 1, 8);
    let parsed_context = ParsedExternalContext::default();
    let pointer_arg_slot_map = HashMap::new();
    let local_element_strides = HashMap::new();
    let mut pointer_values = HashMap::new();
    let pointer_value_names = HashMap::new();
    let array_addr_exprs = HashMap::new();
    let array_addr_expr_names = HashMap::new();
    let stack_addr_offsets = HashMap::new();
    let stack_addr_offset_names = HashMap::new();
    let block_ops = HashMap::new();
    let value_ops = HashMap::new();

    let low = ScalarPointerValue {
        slot: 0,
        base: ArrayIndexBase::Param { index: 0 },
        element_stride: 8,
        confidence: 20,
    };
    let high = ScalarPointerValue {
        confidence: 88,
        ..low.clone()
    };
    pointer_values.insert(ssa_var_block_key(block_addr, &left), low);
    pointer_values.insert(ssa_var_block_key(block_addr, &right), high);
    let ctx = ScalarArrayInferenceCtx {
        parsed_context: &parsed_context,
        type_db: &parsed_context.external_type_db,
        merged_signature: None,
        ptr_bits: 64,
        pointer_arg_slot_map: &pointer_arg_slot_map,
        local_element_strides: &local_element_strides,
        pointer_values: &pointer_values,
        pointer_value_names: &pointer_value_names,
        array_addr_exprs: &array_addr_exprs,
        array_addr_expr_names: &array_addr_expr_names,
        stack_addr_offsets: &stack_addr_offsets,
        stack_addr_offset_names: &stack_addr_offset_names,
        block_ops: &block_ops,
        value_ops: &value_ops,
    };

    let selected = phi_scalar_pointer_value(block_addr, &dst, &[left, right], &ctx)
        .expect("same-base phi should preserve pointer value");

    assert_eq!(selected.confidence, 88);
}

#[test]
fn scalar_signedness_merge_only_refines_unknown_evidence() {
    let scalar = |signedness| CTypeLike::Int {
        bits: 64,
        signedness,
    };
    let signed = scalar(Signedness::Signed);
    let unsigned = scalar(Signedness::Unsigned);
    let unknown = scalar(Signedness::Unknown);

    assert!(local_scalar_override_should_apply(&signed, &unknown));
    assert!(local_scalar_override_should_apply(&unsigned, &unknown));
    assert!(!local_scalar_override_should_apply(&signed, &unsigned));
    assert!(!local_scalar_override_should_apply(&unsigned, &signed));
}

fn semantic_role_summary_set(
    name: &str,
    arg_count_hint: Option<usize>,
) -> r2ssa::InterprocSummarySet {
    let root = r2ssa::InterprocFunctionId(0x401000);
    let mut summary = r2ssa::FunctionSemanticSummary::unknown(root, Some(name.to_string()));
    summary.arg_count_hint = arg_count_hint;
    summary.reads_global_memory = true;
    r2ssa::InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(root, summary)]),
        diagnostics: Default::default(),
    }
}
