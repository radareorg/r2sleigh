//! What each variable ends up called and typed.

use super::super::*;

#[test]
fn visible_binding_merge_prefers_typed_pointer_over_void_pointer() {
    let mut parsed_context = ParsedExternalContext::default();
    let spec = ExternalStackVarSpec {
        name: "buf".to_string(),
        ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
        role: ExternalStackSlotRole::Local,
        param_index: None,
        param_name: None,
        source_reg: None,
    };
    parsed_context.stack_slots.insert(
        StackSlotKey {
            base: ExternalStackBase::FramePointer,
            offset: -0x8,
        },
        spec,
    );
    let vars = [
        RecoveredVariable {
            name: "var_8h".to_string(),
            kind: "b".to_string(),
            delta: -0x8,
            var_type: "int8_t *".to_string(),
            isarg: false,
            reg: None,
        },
        RecoveredVariable {
            name: "var_8h".to_string(),
            kind: "s".to_string(),
            delta: 0x8,
            var_type: "int64_t".to_string(),
            isarg: false,
            reg: None,
        },
    ];
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "sym.f".to_string().as_str(),
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "sym.f".to_string(),
            signature: "void sym.f ()".to_string(),
            ret_type: "void".to_string(),
            params: Vec::new(),
            callconv: String::new(),
            arch: String::new(),
        },
        recovered_vars: &vars,
        ssa_blocks: &[],
        parsed_context,
        local_structs: LocalStructArtifacts::default(),
        interproc_summary_set: None,
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    let binding = analysis
        .type_facts
        .visible_bindings
        .iter()
        .find(|binding| binding.name == "buf")
        .expect("buf visible binding");
    assert_eq!(
        binding.ty,
        Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Signed,
        }))),
        "visible binding merge must keep the typed pointer, got {:?}",
        analysis.type_facts.visible_bindings
    );
}
