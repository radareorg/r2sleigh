mod arrays;
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
            ret_type: Some(parse_test_type("void", 64)),
            params: Vec::new(),
        };
    };
    InferredSignature {
        function_name: String::new(),
        ret_type: Some(signature.ret_type.clone().unwrap_or(CTypeLike::Void)),
        params: (signature.params.iter().enumerate())
            .map(|(index, param)| InferredSignatureParam {
                name: (param.name.clone())
                    .unwrap_or_else(|| r2source::positional_parameter_name(index)),
                ty: (param.ty.clone())
                    .unwrap_or_else(|| CTypeLike::Pointer(Box::new(CTypeLike::Void))),
            })
            .collect(),
    }
}

fn parse_test_type(spelling: &str, ptr_bits: u32) -> CTypeLike {
    crate::convert::parse_c_type_like(spelling, ptr_bits).expect("test type spelling should parse")
}

/// How an inferred signature's type spells.
fn spelled(ty: &CTypeLike) -> String {
    render_signature_type(ty, 64)
}

/// How an inferred signature's result spells: nothing where undecided.
fn spelled_ret(ty: &Option<CTypeLike>) -> String {
    ty.as_ref().map(spelled).unwrap_or_default()
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
    for (bytes, signedness, spelling) in [
        (4, Signedness::Signed, "int32_t"),
        (8, Signedness::Unsigned, "uint64_t"),
        (10, Signedness::Signed, "struct r2sleigh_bits_80"),
        (16, Signedness::Signed, "__int128_t"),
        (16, Signedness::Unsigned, "__uint128_t"),
        (32, Signedness::Signed, "struct r2sleigh_bits_256"),
    ] {
        let ty = CTypeLike::machine_storage(bytes * 8, signedness);
        assert_eq!(crate::convert::render_c_type_like(&ty), spelling);
        assert_eq!(render_signature_type(&ty, 64), spelling);
        assert_eq!(crate::convert::parse_c_type_like(spelling, 64), Some(ty));
    }
    // A carrier states a width and nothing else, so any type outranks it. A
    // 128-bit integer is an integer, like the narrower ones.
    assert!(inferred_type_is_generic(
        Some(&CTypeLike::BitVector(256)),
        64
    ));
    assert!(!inferred_type_is_generic(
        Some(&CTypeLike::machine_storage(128, Signedness::Signed)),
        64
    ));
}

#[test]
fn type_name_policy_matches_planner_guard() {
    let pointer = |ty: CTypeLike| CTypeLike::Pointer(Box::new(ty));
    for generic in [
        pointer(CTypeLike::Void),
        pointer(CTypeLike::Const(Box::new(CTypeLike::typedef("char")))),
        pointer(CTypeLike::typedef("unsigned char")),
        CTypeLike::typedef("unsigned long"),
    ] {
        assert!(
            inferred_type_is_generic(Some(&generic), 64),
            "{generic:?} should stay a weak planner type"
        );
    }
    assert!(!inferred_type_is_generic(
        Some(&parse_test_type("struct real_type *", 64)),
        64
    ));
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

/// A program may call its own structure `anon_cfg`: the spelling makes no placeholder (D482).
#[test]
fn a_declared_struct_spelled_like_a_placeholder_keeps_its_type() {
    let declared = CTypeLike::Pointer(Box::new(CTypeLike::Struct("anon_cfg".to_owned())));
    assert!(!inferred_type_is_generic(Some(&declared), 64));
    let current_signature = FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Void),
        params: vec![FunctionParamSpec {
            name: Some("cfg".to_string()),
            ty: Some(declared.clone()),
        }],
        basis: SignatureBasis::Declared,
    };
    let analysis = build_type_analysis(TypeAnalysisInput {
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "configure".to_string(),
            ret_type: Some(CTypeLike::Void),
            params: vec![InferredSignatureParam {
                name: "arg1".to_string(),
                ty: parse_test_type("int64_t", 64),
            }],
        },
        parsed_context: ParsedExternalContext {
            current_signature: Some(current_signature.clone()),
            merged_signature: Some(current_signature),
            ..ParsedExternalContext::default()
        },
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });
    assert_eq!(
        spelled(&spelled_signature(&analysis).params[0].ty),
        "struct anon_cfg*"
    );
}
