//! Ownership invariants that are stated over the workspace's source text.
//!
//! The lints in `src/lib.rs` check expressions as rustc sees them. What they
//! cannot see is the shape of a crate's surface: that a field stays private,
//! that a deleted repair stays deleted, that one owner stays the only one.
//! Those are checked here, by reading the source.
//!
//! These tests once read one file each and cut a function out of it between
//! two markers: its own name and the name of whatever followed it. Every
//! module split and every rename broke one; 34 of 41 had stopped checking
//! anything by the time they were revived, and a test that panics with
//! "missing marker" says nothing about the invariant it was written for. So
//! every reading here is by crate or by item (see `source`):
//!
//! - a retired seam is banned from the whole crate that owned it, so moving
//!   it to another file does not bring it back unnoticed;
//! - a live seam is named by the item that declares it; if that is renamed
//!   the test fails saying so, and the fix is to restate the invariant against
//!   the new name, not to delete the test.

mod source;

use source::{View, file, production};

/// Fails listing every retired pattern that has come back, where, and why it
/// was retired. A pattern is found in code and in string literals, never in
/// comments: a retired refusal text is as much a seam as a retired function.
fn assert_retired(crate_name: &str, production: View<'_>, retired: &[(&str, &str)]) {
    let returned = retired
        .iter()
        .flat_map(|(pattern, reason)| {
            production
                .lines_with_text(pattern)
                .into_iter()
                .map(move |line| format!("  {pattern:?} ({reason}):\n    {line}"))
        })
        .collect::<Vec<_>>();
    assert!(
        returned.is_empty(),
        "{crate_name} brought back seams that were retired:\n{}",
        returned.join("\n")
    );
}

/// Decompile route and refusal policy has one owner, `r2engine`, and one
/// carrier, `FunctionFacts::decompile_route`. The seams that let a route or a
/// refusal travel beside it, and the caches that let an old answer stand in
/// for a new analysis, were deleted; none may come back in any file.
#[test]
fn r2engine_retired_route_cache_and_mutation_seams_stay_deleted() {
    const ROUTE: &str = "a route beside FunctionFacts::decompile_route is a second owner of it";
    const SEAL: &str = "facts are sealed once, by finalize_for_decompile, and not edited after";
    const EVIDENCE: &str =
        "prepared evidence is derived by its r2types owner, not set by the engine";
    const CACHE: &str = "an analysis is request-local; no cache stands in for a new one";
    const DETACHED: &str = "no detached report or plan is promoted to authority";
    let engine = production("crates/r2engine/src");
    assert_retired(
        "r2engine",
        engine.view(),
        &[
            ("EngineSemanticRoutePlan", ROUTE),
            ("fn decompile_route_kind(", ROUTE),
            ("fn decompile_route_facts_from_decision(", ROUTE),
            ("fn to_decompiler_route(", ROUTE),
            ("r2dec::SemanticRoutePlan", ROUTE),
            (
                "summary-only decompile route lacks certified native FunctionFacts render proof",
                "refusal text is sealed into the route, never synthesized while rendering",
            ),
            (
                "(empty output)",
                "an empty rendering is reported, not papered over",
            ),
            (
                "decompile_empty_output_fallback_comment",
                "an empty rendering is reported",
            ),
            ("decompiler_input_from_prepared_facts", SEAL),
            (".stamp_decompile_route(", SEAL),
            (".into_source_owned_facts(", SEAL),
            ("response_function_facts.set_", SEAL),
            (".set_decompile_route(", SEAL),
            (".set_callee_resolution(", EVIDENCE),
            (".set_callsites(", EVIDENCE),
            (".set_call_results(", EVIDENCE),
            (".set_call_render(", EVIDENCE),
            (".set_control(", EVIDENCE),
            (".set_render(", EVIDENCE),
            (".set_semantics(", EVIDENCE),
            (".apply_decompile_type_override(", EVIDENCE),
            (".attach_prepared_decompile_evidence(", EVIDENCE),
            (".populate_certified_", EVIDENCE),
            ("mod cache;", CACHE),
            ("SessionCache", CACHE),
            ("struct AnalysisCache", CACHE),
            ("EngineSessionCacheMetrics", CACHE),
            ("AnalysisReuse", CACHE),
            ("fn cached_artifacts", CACHE),
            ("fn insert_artifacts", CACHE),
            ("fn cache_plan", CACHE),
            ("fn cache_profile", CACHE),
            ("RenderCacheKey", CACHE),
            ("fn cached_render", CACHE),
            ("fn insert_render", CACHE),
            ("precomputed_semantic_artifact", DETACHED),
            ("InterprocScopeFacts", DETACHED),
            ("build_interproc_summary_set_with_scope_facts", DETACHED),
            ("PreparedInterprocSummarySet::from_report", DETACHED),
            ("fn build_engine_analysis_from_parts(", DETACHED),
            ("EngineBoundedCfgTypePlan", DETACHED),
            ("semantic_fallback_type_plan", DETACHED),
            ("type_facts_with_summary_projection", DETACHED),
        ],
    );
}

/// A decompile consumes its type analysis once: `finalize_for_decompile`
/// takes the analysis by value and seals the facts every tier reads.
#[test]
fn r2engine_seals_source_owned_facts_exactly_once() {
    let engine = production("crates/r2engine/src");
    let seals = engine.view().lines_with(".finalize_for_decompile(");
    assert_eq!(
        seals.len(),
        1,
        "r2engine must seal source-owned facts at exactly one site; found {seals:#?}"
    );
    let types = production("crates/r2types/src");
    let finalize = types
        .view()
        .item("pub fn finalize_for_decompile(")
        .parameters();
    assert!(
        finalize.contains("mut self") && !finalize.contains("&mut self"),
        "finalize_for_decompile must consume its TypeAnalysis: {finalize}"
    );
}

/// The response hands back the sealed facts, and the route inside them is the
/// only route: no parallel decision rides beside it.
#[test]
fn r2engine_decompile_response_carries_function_facts_not_a_route_decision() {
    let engine = production("crates/r2engine/src");
    let response = engine.view().item("pub struct EngineDecompileResponse ");
    assert!(
        response.contains("pub function_facts: FunctionFacts"),
        "EngineDecompileResponse must carry the sealed FunctionFacts:\n{response}"
    );
    for forbidden in [
        "EngineRouteDecision",
        "EngineSemanticRoutePlan",
        "DecompileRouteFacts",
    ] {
        assert!(
            !response.contains(forbidden),
            "EngineDecompileResponse must not carry a route beside FunctionFacts ({forbidden}):\n{response}"
        );
    }
}

/// The request that drives a decompile is the engine's own. Outside callers
/// build it through the checked input's constructors, which run the
/// input-quality check, and cannot set its fields.
#[test]
fn r2engine_raw_decompile_requests_stay_private() {
    let engine = production("crates/r2engine/src");
    let engine = engine.view();
    for raw in [
        "pub struct EngineFunctionDecompileRequest ",
        "pub struct EngineFunctionDecompileRequest{",
        "pub struct EngineDecompileRequest<",
        "pub struct EngineDecompileRequest ",
    ] {
        let public = engine.lines_with(raw);
        assert!(
            public.is_empty(),
            "the raw request must not be public: {public:?}"
        );
    }
    let input = engine.item("pub struct EngineFunctionDecompileRequestInput ");
    assert!(
        input.public_fields().is_empty(),
        "EngineFunctionDecompileRequestInput fields must stay private: {:?}",
        input.public_fields()
    );
}

/// Route selection is engine policy. Its helpers stay crate-private: nothing
/// outside `r2engine` may choose a decompile route.
#[test]
fn r2engine_route_policy_helpers_stay_crate_private() {
    let engine = production("crates/r2engine/src");
    let engine = engine.view();
    let exported = engine
        .items("pub use ")
        .into_iter()
        .flat_map(|export| {
            export
                .text()
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<std::collections::BTreeSet<_>>();
    for helper in [
        "plan_decompile_request",
        "semantic_route_plan",
        "semantic_route_plan_from_context",
        "semantic_route_from_artifact_plan",
        "semantic_route_reason",
        "decompile_route_decision",
        "detached_semantic_route_plan",
        "detached_semantic_linearization_reason",
        "decompile_probe_decision",
        "decompile_probe_decision_for_identity",
        "should_skip_runtime_type_inference",
    ] {
        let public = engine.lines_with(&format!("pub fn {helper}("));
        assert!(
            public.is_empty(),
            "route helper {helper} must stay crate-private: {public:?}"
        );
        assert!(
            !exported.contains(helper),
            "route helper {helper} must not be re-exported"
        );
    }
}

/// The source-owned owners hold their state privately. A sealed report that
/// any caller can write into is not sealed, and a decompile input whose facts
/// can be swapped is not the input that was checked.
#[test]
fn sealed_owners_have_no_public_fields() {
    let types = production("crates/r2types/src");
    let engine = production("crates/r2engine/src");
    let dec = production("crates/r2dec/src");
    for (source, header) in [
        (types.view(), "pub struct FunctionFacts "),
        (types.view(), "pub struct SourceOwnedFunctionFacts "),
        (types.view(), "pub struct TypeAnalysis "),
        (engine.view(), "pub struct EngineAnalysisArtifact "),
        (engine.view(), "pub struct EngineTypeAnalysisResponse "),
        (dec.view(), "pub struct DecompilerInput "),
    ] {
        let owner = source.item(header);
        assert!(
            owner.public_fields().is_empty(),
            "{} must keep its state private; public fields: {:?}",
            header.trim(),
            owner.public_fields()
        );
    }
    let types = types.view();
    let sealed_at = types
        .find("pub struct SourceOwnedFunctionFacts ")
        .expect("the sealed owner is declared");
    let attributes = types.attributes_above(sealed_at);
    assert!(
        attributes.iter().any(|line| line.starts_with("#[derive("))
            && !attributes.iter().any(|line| line.contains("Serialize")),
        "SourceOwnedFunctionFacts is sealed from a body; it must not be (de)serialized: {attributes:?}"
    );
}

/// A sealed owner has no mutators, and the facts that are derived from an
/// exact prepared artifact are attached only by their `r2types` owner.
#[test]
fn sealed_owners_expose_no_mutators() {
    let types = production("crates/r2types/src");
    let types = types.view();
    let offending = |header: &str, forbidden: &[&str]| {
        types
            .items(header)
            .into_iter()
            .flat_map(|block| {
                forbidden
                    .iter()
                    .flat_map(move |pattern| block.lines_with(pattern))
            })
            .collect::<Vec<_>>()
    };
    let sealed = offending(
        "impl SourceOwnedFunctionFacts ",
        &[
            "pub fn seal(",
            "pub fn seal_with_callee_signatures(",
            "_mut(",
            "pub fn into_parts(",
            "pub fn set_",
            "pub fn replace_",
            "pub fn with_",
            "pub fn canonicalize",
        ],
    );
    assert!(
        sealed.is_empty(),
        "SourceOwnedFunctionFacts must stay immutable: {sealed:#?}"
    );
    for unsealing in [
        "DerefMut for SourceOwnedFunctionFacts",
        "AsMut<FunctionFacts> for SourceOwnedFunctionFacts",
    ] {
        assert!(
            !types.contains(unsealing),
            "impl {unsealing} would unseal the owner"
        );
    }
    let analysis = offending(
        "impl TypeAnalysis ",
        &[
            "pub fn function_facts_mut(",
            "pub fn plan_mut(",
            "pub fn set_",
            "pub fn apply_",
        ],
    );
    assert!(
        analysis.is_empty(),
        "TypeAnalysis must not expose post-analysis mutation: {analysis:#?}"
    );
    let report = offending(
        "impl FunctionFacts ",
        &[
            "pub fn from_prepared(",
            "pub fn attach_prepared_decompile_evidence(",
            "pub fn populate_certified_",
            "pub fn populate_member_access_render_facts_from_field_certificates(",
            "pub fn populate_array_access_render_facts_from_scalar_candidates(",
            "pub fn set_render(",
            "pub fn with_render(",
            "pub fn set_decompile_route(",
            "pub fn merge_proof_coverage",
        ],
    );
    assert!(
        report.is_empty(),
        "source-derived FunctionFacts evidence is attached by r2types alone: {report:#?}"
    );
    // One builder makes a TypeAnalysis. The detached builders it replaced are
    // gone from the surface; what survives of them is internal to r2types.
    let exported = types
        .items("pub use ")
        .into_iter()
        .map(|export| export.text().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    for detached in [
        "build_type_analysis",
        "build_type_analysis_with_semantics",
        "build_semantic_type_fallback_plan",
        "signature_projection_for_semantic_artifact",
        "field_access_certificates_from_struct_artifacts",
    ] {
        let public = types.lines_with(&format!("pub fn {detached}("));
        assert!(
            public.is_empty(),
            "{detached} must not be public: {public:?}"
        );
        let reexported = exported
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|word| word == detached);
        assert!(!reexported, "{detached} must not be exported");
    }
}

/// Every rendering r2dec produces starts from the sealed `DecompilerInput`:
/// no public entry takes raw SSA and renders it, and the context the renderer
/// projects from the sealed facts stays private to it.
#[test]
fn r2dec_renders_only_from_sealed_input() {
    let dec = production("crates/r2dec/src");
    let dec = dec.view();
    let entries = dec
        .items("impl Decompiler ")
        .into_iter()
        .flat_map(|block| block.items("pub fn "))
        .map(View::parameters)
        .filter(|entry| {
            let name = entry.text()["pub fn ".len()..]
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default();
            ["decompile", "structured_input", "values_input"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    assert!(
        !entries.is_empty(),
        "found no Decompiler rendering entry points"
    );
    for entry in entries {
        assert!(
            entry.contains("DecompilerInput"),
            "a Decompiler rendering entry must take the sealed DecompilerInput:\n{entry}"
        );
    }
    for raw in ["SSAFunction", "SsaArtifact", "TrustedSsaArtifact"] {
        let taking_raw = dec
            .items("pub fn ")
            .into_iter()
            .map(View::parameters)
            .filter(|entry| {
                entry.contains(&format!("&{raw}")) || entry.contains(&format!("::{raw}"))
            })
            .map(|entry| entry.text().to_string())
            .collect::<Vec<_>>();
        assert!(
            taking_raw.is_empty(),
            "no public r2dec entry may take raw SSA ({raw}): {taking_raw:#?}"
        );
    }
    for forbidden in [
        "pub struct DecompilerContext",
        "pub fn context_projection",
        "pub context: DecompilerContext",
    ] {
        assert!(
            !dec.contains(forbidden),
            "{forbidden}: the render context is private to r2dec"
        );
    }
}

/// The renderer's inputs carry `FunctionFacts` as their one authority. The
/// facts it reads (callee resolution, callsites, call results, control,
/// render) are read through it, not carried beside it, and no raw name map
/// (addresses to function, string or symbol spellings) reaches production
/// lowering: a name says how to print a thing, not what it is.
#[test]
fn r2dec_render_inputs_carry_function_facts_as_the_only_authority() {
    let dec = production("crates/r2dec/src");
    let dec = dec.view();
    for header in [
        "pub(crate) struct FoldInputs<",
        "pub(crate) struct PreparedSemanticViewInputs<",
    ] {
        let inputs = dec.item(header);
        assert!(
            inputs.contains("function_facts: &'a FunctionFacts"),
            "{header} must carry a non-optional FunctionFacts:\n{inputs}"
        );
        for side_channel in [
            "callee_facts:",
            "callee_resolution:",
            "callsite_facts:",
            "call_result_facts:",
            "call_render_facts:",
            "control_facts:",
            "render_facts:",
            "semantic_artifact:",
            "summary_view:",
            "function_names:",
            "symbols:",
            "strings:",
        ] {
            assert!(
                !inputs.contains(side_channel),
                "{header} must not carry {side_channel} beside FunctionFacts in production:\n{inputs}"
            );
        }
    }
    let context = dec.item("struct DecompilerContext ");
    for raw_map in ["function_names:", "symbols:", "strings:"] {
        assert!(
            !context.contains(raw_map),
            "the production render context must carry no raw name map ({raw_map}):\n{context}"
        );
    }
    for accessors in dec.items("impl<'a> PreparedSemanticViewInputs<'a>") {
        for fallback in [".or(self.", ".and_then(FunctionFacts::"] {
            assert!(
                !accessors.contains(fallback),
                "PreparedSemanticViewInputs must read FunctionFacts with no fallback ({fallback})"
            );
        }
    }
}

/// The certified render context reads its authority from the render facts
/// `FunctionFacts` carries, never from the prepared artifact's certificates
/// directly: a certificate is evidence, and what it licenses to render is
/// decided in `r2types`.
#[test]
fn r2dec_certified_render_context_reads_render_facts() {
    let dec = production("crates/r2dec/src");
    let dec = dec.view();
    let context = dec.item("pub(crate) struct CertifiedRenderContext<");
    assert!(
        context.contains("render_facts: &'a FunctionRenderFacts"),
        "CertifiedRenderContext must carry FunctionRenderFacts:\n{context}"
    );
    let methods = dec.item("impl<'a> CertifiedRenderContext<'a>");
    for forbidden in [
        ".certificates()",
        "return_certificate_for_op",
        "memory_certificate_for_op_site",
    ] {
        assert!(
            !methods.contains(forbidden),
            "CertifiedRenderContext must not read prepared certificates ({forbidden})"
        );
    }
}

/// C is generated from an AST only through the sealed pipeline. The code
/// generator, the folding context and the structurer are internal: a public
/// one is a way to print C that nothing proved.
#[test]
fn r2dec_raw_render_pipeline_is_not_public_api() {
    let lib = file("crates/r2dec/src/lib.rs");
    let lib = lib.view();
    let dec = production("crates/r2dec/src");
    for forbidden in [
        "pub mod codegen;",
        "pub mod fold;",
        "pub use structure::",
        "pub use fold::FoldingContext",
    ] {
        assert!(
            !lib.contains(forbidden),
            "r2dec must not expose {forbidden}"
        );
    }
    let codegen_exports = lib.lines_with("pub use codegen::");
    assert!(
        codegen_exports
            .iter()
            .all(|line| line == "pub use codegen::CodeGenConfig;"),
        "only the code generator's configuration is public: {codegen_exports:?}"
    );
    for forbidden in [
        "pub struct CodeGenerator",
        "pub struct FoldingContext",
        "pub use context::FoldingContext",
        "pub struct ControlFlowStructurer",
        "pub struct ControlRenderProof",
        "pub enum ControlRenderProofKind",
    ] {
        assert!(
            !dec.view().contains(forbidden),
            "{forbidden}: raw rendering state stays internal"
        );
    }
    // `structure` is a public module path, and must stay an empty one.
    let structure = production("crates/r2dec/src/structure");
    for public in [
        "pub fn ",
        "pub struct ",
        "pub enum ",
        "pub use ",
        "pub type ",
        "pub trait ",
        "pub mod ",
        "pub const ",
    ] {
        let found = structure.view().lines_with(public);
        assert!(
            found.is_empty(),
            "r2dec::structure must expose nothing: {found:?}"
        );
    }
}

/// The repairs a renderer once made to hide a missing fact were deleted when
/// the fact moved upstream. Each stays deleted from the whole crate: a name
/// that comes back in another module is the same repair.
#[test]
fn r2dec_retired_renderer_repairs_stay_deleted() {
    const RAW_NAMES: &str = "rendering reads no raw address-to-name map; names come from facts";
    const FINAL_AST: &str = "the final AST is not rewritten after its proofs are recorded";
    const CARRIERS: &str = "no C local is synthesized for a raw carrier";
    const OWNERS: &str = "a call result's owner is a canonical fact, not a renderer guess";
    const AGGREGATE: &str = "member and array syntax need per-access proof, not proof counters";
    const STANDARD: &str = "generic Standard rendering does not repair headers, calls or returns";
    const LOCAL: &str = "no local fallback stands in for a missing prepared fact";
    const SUMMARY: &str = "a summary route renders no executable C";
    let dec = production("crates/r2dec/src");
    assert_retired(
        "r2dec",
        dec.view(),
        &[
            ("lookup_function", RAW_NAMES),
            ("lookup_string", RAW_NAMES),
            ("lookup_symbol", RAW_NAMES),
            ("parse_address_from_var_name", RAW_NAMES),
            ("type_inference.set_function_names", RAW_NAMES),
            ("fn normalize_final_stmt_calls", FINAL_AST),
            ("fn normalize_final_stmt_expr", FINAL_AST),
            ("normalize_final_return_expr_candidate", FINAL_AST),
            ("certified_raw_carrier_definition", CARRIERS),
            ("materialize_certified_raw_carrier_locals", CARRIERS),
            ("fn collect_raw_carrier_assignment_names", CARRIERS),
            ("fn collect_raw_carrier_read_names", CARRIERS),
            ("fn rewrite_certified_raw_carrier_", CARRIERS),
            ("fn certified_raw_carrier_type", CARRIERS),
            ("fallback_owned_call_result_register_name_for_alias", OWNERS),
            ("fallback_owned_call_result_return_name_for_alias", OWNERS),
            ("fallback_owned_call_result_return_name_for_source", OWNERS),
            (
                "fallback_owned_call_result_stack_local_name_for_source",
                OWNERS,
            ),
            ("call_result_aliases_map", OWNERS),
            ("direct_call_result_aliases_set", OWNERS),
            ("source_call_allows_return_register_owner", OWNERS),
            ("call_result_candidate_names_have_observable_use", OWNERS),
            ("stable_owned_call_result_name_for_source", OWNERS),
            ("find_ssa_name_for_rendered_alias", OWNERS),
            ("rendered_visible_name_for_ssa_name", OWNERS),
            ("is_return_register_name", OWNERS),
            ("is_register_like_base_name", OWNERS),
            ("fn array_accesses_are_certified", AGGREGATE),
            ("fn field_accesses_are_certified", AGGREGATE),
            ("array_index_certificates", AGGREGATE),
            ("certified_array_indexes", AGGREGATE),
            ("certified_array_field_names", AGGREGATE),
            ("fn proved_member_access_counts", AGGREGATE),
            ("member_access_for_op_any_direction", AGGREGATE),
            ("array_access_for_op_any_direction", AGGREGATE),
            ("fallback_aggregate_field_name", AGGREGATE),
            ("fn params_from_authorized_signature", STANDARD),
            ("fn signature_has_complete_render_param_types", STANDARD),
            (
                "fn certified_standard_output_residual_reason_with_effect_proofs",
                STANDARD,
            ),
            ("fn prune_duplicate_tail_call_statements", STANDARD),
            ("fn certified_unique_scalar_stack_return_expr", STANDARD),
            ("fn duplicate_pruning_source_for_call_expr", STANDARD),
            ("fn merge_params_with_external_signature", STANDARD),
            ("fn infer_call_authoritative_arg", STANDARD),
            ("fn infer_stack_call_authoritative_args", STANDARD),
            ("lookup_definition", LOCAL),
            ("best_visible_definition", LOCAL),
            ("definition_for_name", LOCAL),
            ("resolve_stack_var", LOCAL),
            ("stack_var_for_addr_var", LOCAL),
            ("stable_stack_values", LOCAL),
            ("stack_slot_provenance_for_name", LOCAL),
            ("stack_offset_for_visible_storage_name", LOCAL),
            ("render_memory_access_from_visible_expr", LOCAL),
            ("render_semantic_value_by_name", LOCAL),
            ("render_exact_member_from_raw_subscript", LOCAL),
            ("semantic_deref_candidate_for_name", LOCAL),
            ("local_post_call_source_for_ssa_name", LOCAL),
            ("call_result_source_for_ssa_name", LOCAL),
            ("local_branch_condition_expr", LOCAL),
            ("symbolic_actionable_compiled_condition", LOCAL),
            ("symbolic_actionable_memory_condition_expr", LOCAL),
            ("symbolic_branch_condition_expr", LOCAL),
            ("resolve_predicate_operand", LOCAL),
            ("prepared_predicate_view", LOCAL),
            ("switch_selector_roots_map", LOCAL),
            ("refine_switch_selector_expr", LOCAL),
            ("infer_switch_selector_var", LOCAL),
            ("estimate_switch_case_bias", LOCAL),
            ("switch_case_display_bias", LOCAL),
            ("semanticize_visible_expr", LOCAL),
            ("prepared_call_args_for_site", LOCAL),
            ("render_authoritative_source_call_arg", LOCAL),
            ("fn render_semantic_worker_summary", SUMMARY),
            ("fn render_vm_semantic_summary", SUMMARY),
            ("fn render_semantic_worker_linearization", SUMMARY),
            ("structure_semantic_worker_islands", SUMMARY),
        ],
    );
}

/// The instruction-level `dec` export has no function, so no facts, so no C:
/// it may not depend on the renderer at all. What it prints instead is held by
/// `dec_c_like_residualizes_without_function_facts` in r2sleigh-export.
#[test]
fn r2sleigh_export_does_not_depend_on_the_renderer() {
    let manifest = file("crates/r2sleigh-export/Cargo.toml");
    let export = production("crates/r2sleigh-export/src");
    for forbidden in [
        "r2dec",
        "CodeGenerator",
        "CodeGenConfig",
        "lower_ssa_ops_to_stmts",
        "CStmt",
        "DecompilerInput",
        "DecompilerContext",
        "Decompiler::",
    ] {
        assert!(
            !manifest.view().text().contains(forbidden),
            "the r2sleigh-export manifest names {forbidden}"
        );
        assert!(
            !export.view().contains(forbidden),
            "r2sleigh-export source uses {forbidden}"
        );
    }
}
