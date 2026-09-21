//! What an operator's assumption does to the analysis.

use super::super::*;

#[test]
fn user_type_hint_assumptions_apply_without_semantic_corroboration() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("param0-char-ptr".to_string()),
            subject: r2ssa::AssumptionSubject::Parameter { index: 0 },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "char *".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::User,
        }]),
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.demo".to_string(),
        signature: "void sym.demo(void *)".to_string(),
        ret_type: "void".to_string(),
        params: vec![InferredSignatureParam {
            name: "arg1".to_string(),
            param_type: "void *".to_string(),
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
    assert_eq!(inferred_signature.params[0].param_type, "int8_t*");
    assert_eq!(
        render_signature_type(
            parsed_context
                .merged_signature
                .as_ref()
                .expect("merged signature")
                .params[0]
                .ty
                .as_ref()
                .expect("hinted param type"),
            64
        ),
        "int8_t*"
    );
}

#[test]
fn derived_type_hint_assumptions_still_require_corroboration() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("param0-char-ptr".to_string()),
            subject: r2ssa::AssumptionSubject::Parameter { index: 0 },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "char *".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::Derived,
        }]),
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.demo".to_string(),
        signature: "void sym.demo(void *)".to_string(),
        ret_type: "void".to_string(),
        params: vec![InferredSignatureParam {
            name: "arg1".to_string(),
            param_type: "void *".to_string(),
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

    assert!(usage.applied.is_empty());
    assert_eq!(usage.ignored.len(), 1);
    assert!(usage.conflicts.is_empty());
    assert_eq!(inferred_signature.params[0].param_type, "void *");
    assert!(parsed_context.merged_signature.is_none());
}

#[test]
fn corroborated_type_hint_assumptions_update_signature_and_usage() {
    let mut parsed_context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: Some("param0-char-ptr".to_string()),
            subject: r2ssa::AssumptionSubject::Parameter { index: 0 },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "char *".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::User,
        }]),
        ..ParsedExternalContext::default()
    };
    let mut inferred_signature = InferredSignature {
        function_name: "sym.demo".to_string(),
        signature: "void sym.demo(void *)".to_string(),
        ret_type: "void".to_string(),
        params: vec![InferredSignatureParam {
            name: "arg1".to_string(),
            param_type: "void *".to_string(),
        }],
        callconv: "amd64".to_string(),
        arch: "x86-64".to_string(),
    };
    let root = r2ssa::InterprocFunctionId(0x401000);
    let summary_set = InterprocSummarySet {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(root),
        summaries: BTreeMap::from([(
            root,
            FunctionSemanticSummary {
                schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
                id: root,
                name: Some("sym.demo".to_string()),
                linkage: r2ssa::FunctionSemanticLinkage::Unknown,
                arg_count_hint: Some(1),
                direct_callees: BTreeSet::new(),
                callsite_count: 0,
                has_unknown_calls: false,
                arg_effects: BTreeMap::from([(
                    0,
                    SummaryArgEffect {
                        read: true,
                        write: true,
                        escape: false,
                        free: false,
                    },
                )]),
                memory_effects: Vec::new(),
                transfer_effects: Vec::new(),
                allocation_effects: Vec::new(),
                lifetime_effects: Vec::new(),
                sync_effects: Vec::new(),
                atomic_effects: Vec::new(),
                return_relation: SummaryReturnRelation::Void,
                reads_global_memory: false,
                writes_global_memory: false,
                touches_unknown_memory: false,
            },
        )]),
        diagnostics: Default::default(),
    };
    let projection = SemanticTypeProjection::from_inputs(
        &InterprocSummaryView::new(Some(summary_set)).expect("current interproc report schema"),
    );

    let usage = apply_type_hint_assumptions_to_context(
        &mut parsed_context,
        &mut inferred_signature,
        64,
        Some(&projection),
        &x86_64_register_identity(),
    );

    assert_eq!(usage.applied.len(), 1);
    assert!(usage.ignored.is_empty());
    assert!(usage.conflicts.is_empty());
    assert_eq!(inferred_signature.params[0].param_type, "int8_t*");
    assert_eq!(
        render_signature_type(
            parsed_context
                .merged_signature
                .as_ref()
                .expect("merged signature")
                .params[0]
                .ty
                .as_ref()
                .expect("hinted param type"),
            64
        ),
        "int8_t*"
    );
}

#[test]
fn user_type_hint_can_replace_narrow_generic_scalar_inference() {
    let mut context = ParsedExternalContext {
        assumptions: r2ssa::AssumptionSet::new(vec![r2ssa::AnalysisAssumption {
            id: None,
            subject: r2ssa::AssumptionSubject::Register {
                name: "rdi".to_string(),
            },
            value: r2ssa::AssumptionValue::TypeHint {
                ty: "int32_t".to_string(),
            },
            scope: r2ssa::AssumptionScope::Function,
            provenance: r2ssa::AssumptionProvenance::User,
        }]),
        ..ParsedExternalContext::default()
    };
    let mut signature = InferredSignature {
        function_name: "sym.demo".to_string(),
        signature: "uint32_t sym.demo(uint32_t)".to_string(),
        ret_type: "uint32_t".to_string(),
        params: vec![InferredSignatureParam {
            name: "arg0".to_string(),
            param_type: "uint32_t".to_string(),
        }],
        callconv: "amd64".to_string(),
        arch: "x86-64".to_string(),
    };

    let usage = apply_type_hint_assumptions_to_context(
        &mut context,
        &mut signature,
        64,
        Some(&SemanticTypeProjection::default()),
        &x86_64_register_identity(),
    );

    assert_eq!(usage.applied.len(), 1);
    assert_eq!(signature.params[0].param_type, "int32_t");
    assert!(
        x86_64_register_identity().same_parameter_storage(&context.register_params[0].reg, "rdi")
    );
}

#[test]
fn explicit_role_type_hint_blocks_generic_pointer_upgrade() {
    let mut projection = SemanticTypeProjection::default();
    projection.pointer_param_indices.insert(0);
    projection.param_type_hints.insert(0, c_int_type());
    projection.param_name_hints.insert(0, "argc".to_string());

    let mut signature = InferredSignature {
        function_name: "dbg.main".to_string(),
        signature: "int dbg.main (int argc)".to_string(),
        ret_type: "int".to_string(),
        params: vec![InferredSignatureParam {
            name: "argc".to_string(),
            param_type: "int".to_string(),
        }],
        callconv: "amd64".to_string(),
        arch: "x86-64".to_string(),
    };
    let mut merged = inferred_signature_to_spec(&signature, 64);

    upgrade_param_indices_to_pointer(
        projection_pointer_upgrade_indices(&projection),
        &mut merged,
        &mut signature,
        64,
        &ExternalTypeDb::default(),
    );

    assert_eq!(signature.params[0].param_type, "int");
    assert_eq!(
        merged
            .as_ref()
            .and_then(|sig| sig.params[0].ty.as_ref())
            .map(|ty| render_signature_type(ty, 64)),
        Some("int".to_string())
    );

    let mut summary = r2ssa::FunctionSemanticSummary::unknown(
        r2ssa::InterprocFunctionId(0x401000),
        Some("dbg.main".to_string()),
    );
    summary.arg_effects.insert(
        0,
        r2ssa::SummaryArgEffect {
            read: true,
            ..Default::default()
        },
    );
    maybe_upgrade_param_to_pointer(
        &summary,
        &mut merged,
        &mut signature,
        64,
        &ExternalTypeDb::default(),
    );

    assert_eq!(signature.params[0].param_type, "int");
}
