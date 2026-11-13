//! What the analysis proves about the frame and its slots.

use super::super::*;
use super::*;

#[test]
fn interproc_summary_name_does_not_prune_generated_surplus_slots() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "dbg.or",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.or".to_string(),
            ret_type: Some(parse_test_type("bool", 64)),
            params: vec![
                InferredSignatureParam {
                    name: "arg1".to_string(),
                    ty: parse_test_type("void *", 64),
                },
                InferredSignatureParam {
                    name: "arg2".to_string(),
                    ty: parse_test_type("struct sla_struct_deadbeef *", 64),
                },
            ],
        },
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts {
            ..Default::default()
        },
        interproc_summary_set: Some(semantic_role_summary_set("dbg.or", Some(2))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(spelled_ret(&spelled_signature(&analysis).ret_type), "bool");
    assert_eq!(spelled_signature(&analysis).params.len(), 2);
}
