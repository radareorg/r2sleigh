mod arrays;
mod assumptions;
mod bindings;
mod signature;
mod stack;
mod structs;

use super::*;
use std::collections::BTreeMap;

/// The signature the facts carry, spelled: what a test reads where the plan's string copy once stood.
pub(super) fn spelled_signature(analysis: &DerivedTypeAnalysis) -> InferredSignature {
    let Some(signature) = analysis.type_facts.merged_signature.as_ref() else {
        return InferredSignature {
            function_name: String::new(),
            signature: String::new(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: String::new(),
            arch: String::new(),
        };
    };
    let spelled = |ty: &CTypeLike| crate::render_signature_type(ty, 64);
    InferredSignature {
        function_name: String::new(),
        signature: String::new(),
        ret_type: signature
            .ret_type
            .as_ref()
            .map_or_else(|| "void".to_string(), spelled),
        params: (signature.params.iter().enumerate())
            .map(|(index, param)| InferredSignatureParam {
                name: match param.name.trim().is_empty() {
                    true => format!("arg{}", index + 1),
                    false => param.name.clone(),
                },
                param_type: param
                    .ty
                    .as_ref()
                    .map_or_else(|| "void *".to_string(), spelled),
            })
            .collect(),
        callconv: String::new(),
        arch: String::new(),
    }
}

/// The operation a fixture names by its block and its place in the block.
/// System V's integer argument registers, in order, as a prepared machine spells them.
pub(super) fn system_v_argument_registers() -> Vec<String> {
    ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        .map(str::to_string)
        .to_vec()
}

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
    let stack_access_widths = BTreeMap::new();
    let stack_access_signedness = BTreeMap::new();
    let context = VarTypeCandidateContext {
        current_context_maps: &context_maps,
        merged_signature: None,
        slot_type_overrides: &slot_type_overrides,
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
