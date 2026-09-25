#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_session;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint;
use rustc_ast::LitKind;
use rustc_hir::{Expr, ExprKind, ImplItem, Item, QPath};
use rustc_lint::{LateContext, LateLintPass, LintContext};

dylint_linting::dylint_library!();

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `DisplayNames` is read outside a rendering path.
    ///
    /// ### Why is this bad?
    ///
    /// `DisplayNames` holds the spellings radare2 resolved for addresses and
    /// parameters. A name says how to print something, not what it does, and a
    /// decompiler that classifies behaviour from the letters after `sym.imp.`
    /// invents semantics it cannot justify. The names are kept in a carrier of
    /// their own so that separation is checkable rather than conventional, and
    /// the check is this lint: only code that renders may read them.
    ///
    /// Semantic classification, route selection and type inference belong to
    /// `r2ssa`, `r2engine` and `r2types` respectively, and each has typed
    /// evidence for the job.
    ///
    /// The carrier's owners may touch it: `r2source` defines it, `r2ssa`'s
    /// function preparation fills it from the snapshot, `r2types`'
    /// `FunctionFacts` carries it, and the renderers read it -- `r2dec`, and
    /// `r2engine`'s `afi`/`afv` record, which spells an argument list.
    ///
    /// ### Example
    ///
    /// ```rust
    /// // in r2ssa, choosing a callee summary
    /// if facts.display_names().name_for(addr) == Some("sym.imp.malloc") {
    ///     // semantics from a spelling
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// if summary.evidence().allocates() {
    ///     // semantics from evidence
    /// }
    /// ```
    pub DISPLAY_NAMES_OUTSIDE_RENDERING,
    Warn,
    "display spellings may only be read where output is rendered"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when semantic storage/address classification is encoded as
    /// `starts_with` checks against string prefixes such as `tmp:`, `const:`,
    /// `ram:`, `sym.`, or `obj.`.
    ///
    /// ### Why is this bad?
    ///
    /// In r2sleigh those prefixes identify canonical IL/storage/address facts.
    /// Repeating prefix checks across crates creates parallel ownership and lets
    /// render and type code infer semantics that should arrive through typed
    /// contracts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// if name.starts_with("tmp:") {
    ///     // stringly semantic classification
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// match storage_kind {
    ///     StorageKind::Temporary => {}
    ///     _ => {}
    /// }
    /// ```
    pub STRING_PREFIX_SEMANTIC_CLASSIFICATION,
    Warn,
    "semantic classification should use typed contracts, not string prefixes"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` indexes `known_function_signatures` directly.
    ///
    /// ### Why is this bad?
    ///
    /// Signature lookup depends on the same alias, direct-address, import, and
    /// evidence rules as callee identity. Letting the renderer index the raw
    /// signature map recreates type policy downstream and can confuse type
    /// evidence with import evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// inputs.known_function_signatures.get(name);
    /// ```
    ///
    /// Use instead `r2types::CalleeIdentity` query methods, such as
    /// `known_signature()` or `non_variadic_known_arity()`.
    pub R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
    Warn,
    "r2dec should query signatures through typed callee identity, not the raw signature map"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` analysis code reconstructs imported-callee or
    /// imported-like call-argument policy instead of consuming typed
    /// `CalleeResolutionFacts` target resolution.
    ///
    /// ### Why is this bad?
    ///
    /// Import/model classification depends on the same callsite, direct-address,
    /// summary, callee-fact, and typed-signature evidence as callee identity.
    /// Rebuilding it in analysis from raw names or partial identity lookups
    /// creates a second owner and lets raw hints override typed facts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// r2types::callee_name_is_import_like(name);
    /// facts.identity_for_callsite(site).is_some_and(|id| id.is_import_policy_authorized());
    /// ```
    ///
    /// Use instead `CalleeResolutionFacts::resolve_target_identity(...)` or
    /// `CalleeResolutionFacts::resolve_target_policy(...)`.
    pub R2DEC_RAW_CALLEE_IMPORT_POLICY,
    Warn,
    "r2dec analysis should use typed callee resolution for import policy"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` op-lowering code parses call-target addresses through
    /// a local helper or direct `ram:` / `const:` prefix handling.
    ///
    /// ### Why is this bad?
    ///
    /// Call-target address interpretation is part of typed callee resolution and
    /// the shared decompiler address parser. Recreating it in lowering creates a
    /// second owner for call identity and lets rendering bypass
    /// `CalleeResolutionFacts`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// extract_call_address(name);
    /// self.prepared_constish_target_addr(target);
    /// name.strip_prefix("ram:");
    /// ```
    ///
    /// Use instead `crate::address::parse_address_from_var_name()` or a
    /// `CalleeResolutionFacts` lookup.
    pub R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
    Warn,
    "r2dec op-lowering should use typed callee resolution or the shared address parser"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` op-lowering code reconstructs call-target policy from
    /// imported-name authorization, raw callsite identity lookups,
    /// summary-helper lookups, or local modeled target helpers.
    ///
    /// ### Why is this bad?
    ///
    /// Imported/modeled call behavior is a typed callee-contract decision. If
    /// the renderer recomputes it from aliases, helper summaries, or callee
    /// facts, raw rendered names can override callsite evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// identity.is_import_policy_authorized();
    /// facts.identity_for_callsite(callsite);
    /// self.summary_helper_view_for_name(alias);
    /// self.is_modeled_callee_identity(identity);
    /// direct_target_context: Some(&ctx);
    /// ```
    ///
    /// Use instead `CalleeResolutionFacts::resolve_target_policy()` through the
    /// renderer's typed callee target resolver.
    pub R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
    Warn,
    "r2dec op-lowering should consume typed callee target policy instead of recomputing it"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` builds or reconstructs callee resolution
    /// internally from raw context.
    ///
    /// ### Why is this bad?
    ///
    /// Callee resolution is an engine/type-system contract. If the decompiler
    /// reconstructs it from prepared callsites, raw maps, or direct context
    /// identity helpers, rendering becomes a second owner for call identity and
    /// can silently turn missing engine facts into confident callee policy.
    ///
    /// ### Example
    ///
    /// ```rust
    /// CalleeResolutionFacts::from_direct_call_targets(targets, &ctx);
    /// CalleeResolutionFacts::identity_for_direct_target_in_context(None, addr, &ctx);
    /// CalleeResolutionFacts::identity_for_name_in_context(name, &ctx);
    /// ```
    ///
    /// Pass the engine-owned `CalleeResolutionFacts` through
    /// `FunctionFacts::with_callee_resolution()` instead.
    pub R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
    Warn,
    "r2dec must not synthesize CalleeResolutionFacts; r2engine owns callee resolution"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` call-argument render authorization treats
    /// `CallArgBinding::source_call` as standalone proof.
    ///
    /// ### Why is this bad?
    ///
    /// A source call proves where a value came from; it does not prove that the
    /// call argument is safe to emit as executable C. Argument rendering must
    /// be backed by a certified value ID or prepared semantic authority.
    ///
    /// ### Example
    ///
    /// ```rust
    /// binding.source_call.is_some()
    /// ```
    ///
    /// Use instead the certified callsite argument contract carried through
    /// `FunctionFacts`, or fail closed with a residual.
    pub R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
    Warn,
    "r2dec call-argument rendering must not treat source_call as standalone authority"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` builds a call expression whose argument list is
    /// written empty in the renderer: `CExpr::call(target, vec![])`.
    ///
    /// ### Why is this bad?
    ///
    /// What a call passes is a callsite fact: `FunctionFacts` carries each
    /// site's argument values, and a callee that takes nothing is a fact too.
    /// An argument list the renderer writes empty is neither; it prints `f()`
    /// for a call that may pass three arguments, which is C that compiles and
    /// is wrong. The review found exactly that class: `printf`'s variadic
    /// arguments dropped from the rendering.
    ///
    /// The lint names the expression rather than the function around it, so
    /// every such construction is one finding with its own line.
    ///
    /// ### Example
    ///
    /// ```rust
    /// SSAOp::Call { .. } => Some(CStmt::Expr(CExpr::call(func_expr, vec![])))
    /// ```
    ///
    /// Render the arguments the callsite facts name (`op_to_stmt_with_args`),
    /// or residualize the call when they are missing.
    pub R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
    Warn,
    "r2dec direct call lowering must residualize instead of emitting zero-arg fallback calls"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` code owns semantic route selection,
    /// fallback selection, CFG guard policy, or detached semantic route planning.
    ///
    /// ### Why is this bad?
    ///
    /// `r2dec` is a renderer. Route/refusal policy belongs in `r2engine`, where
    /// it can account for prepared facts, semantic evidence, budgets, and request
    /// kind consistently. If `r2dec` grows route helpers again, consumers can
    /// bypass engine refusal policy and make summary/fake C look like native
    /// reconstruction.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn semantic_route_plan(...) -> SemanticRoutePlan {
    ///     // renderer-owned routing policy
    /// }
    /// ```
    ///
    /// Use `r2types::DecompileRouteFacts` on `FunctionFacts` as the render
    /// boundary. `r2dec` must not define a local route enum or route adapter.
    pub R2DEC_ROUTE_POLICY_OWNERSHIP,
    Warn,
    "r2dec must consume engine route decisions, not own route/refusal policy"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` treats a missing `FunctionFacts::decompile_route` as
    /// any locally synthesized route.
    ///
    /// ### Why is this bad?
    ///
    /// Missing route facts mean the engine did not certify a render route.
    /// Defaulting that case to any renderer-minted route bypasses the typed
    /// spine and can turn missing engine policy into renderer policy.
    ///
    /// ### Example
    ///
    /// ```rust
    /// DecompileRouteFacts { kind: DecompileRouteKind::FallbackComment, ... }
    /// ```
    ///
    /// Residualize or refuse instead.
    pub R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
    Warn,
    "r2dec must residualize missing FunctionFacts::decompile_route without synthesizing a route"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2engine` applies decompile-route or
    /// callsite/callee evidence by filling request/context side-channel fields.
    ///
    /// ### Why is this bad?
    ///
    /// The decompile spine is one consuming `TypeAnalysis` finalization
    /// into immutable `SourceOwnedFunctionFacts`. Side-channel fields can diverge
    /// from the exact prepared SSA owner later retained by `DecompilerInput`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// context.with_semantic_route(Some(route));
    /// EngineDecompileRequest { callee_resolution: Some(facts), ..request }
    /// ```
    ///
    /// Derive evidence during source-owned analysis and consume
    /// `finalize_for_decompile(...)` once.
    pub R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    Warn,
    "r2engine must carry decompile policy through exact source-owned finalization"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2engine` directly mutates raw `FunctionFacts`
    /// call, control, semantic, or route evidence.
    ///
    /// ### Why is this bad?
    ///
    /// Decompile rendering needs one completed typed evidence contract. Letting
    /// separate call sites attach subsets of the contract creates divergent
    /// semantic identities, route decisions, and renderer permissions.
    ///
    /// ### Example
    ///
    /// ```rust
    /// function_facts.set_callsites(...);
    /// function_facts.set_control(...);
    /// ```
    ///
    /// Build `TypeAnalysis` from the exact source owner in `r2types`.
    pub R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
    Warn,
    "r2engine must not mutate detached FunctionFacts authority"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `crates/r2engine/src/lib.rs` exposes the
    /// lower-level `EngineDecompileRequest` API as public surface, either as a
    /// public request type or a public `decompile` method accepting that type.
    ///
    /// ### Why is this bad?
    ///
    /// Plugin and user-facing decompile paths must enter through
    /// `EngineFunctionDecompileRequest` so route policy, source identity,
    /// prepared SSA evidence, and `FunctionFacts` render contracts stay on the
    /// engine-owned function decompile spine. Public lower-level decompile
    /// entrypoints let callers bypass that policy.
    ///
    /// ### Example
    ///
    /// ```rust
    /// pub struct EngineDecompileRequest { ... }
    ///
    /// pub fn decompile(&self, request: EngineDecompileRequest) { ... }
    /// ```
    ///
    /// Keep `EngineDecompileRequest` internal and expose
    /// `EngineFunctionDecompileRequest` / `decompile_function(...)` instead.
    pub R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
    Warn,
    "r2engine must not expose lower-level EngineDecompileRequest decompile APIs publicly"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when the production `r2engine` decompile render request carries a
    /// fallback/refusal comment beside the finalized source-owned facts.
    ///
    /// ### Why is this bad?
    ///
    /// Decompile refusal and fallback output are route decisions. A request
    /// field such as `fallback_comment` can disagree with the route sealed by
    /// consuming `TypeAnalysis`, letting render output be controlled
    /// by a side channel that the exact source owner does not retain.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct EngineDecompileRequest {
    ///     fallback_comment: Option<String>,
    /// }
    /// request.fallback_comment.clone()
    /// ```
    ///
    /// Put the comment in `DecompileFinalization` before consuming
    /// `TypeAnalysis::finalize_for_decompile`.
    pub R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
    Warn,
    "r2engine fallback comments must be sealed by source-owned finalization"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when decompile route planning in `r2engine` accepts
    /// `FunctionTypeFacts` or a `type_facts` parameter beside
    /// `FunctionFacts`.
    ///
    /// ### Why is this bad?
    ///
    /// `FunctionFacts` is the decompile evidence spine. Passing type facts as a
    /// sibling argument lets a caller plan route/refusal decisions from type
    /// evidence that does not match the facts contract later handed to `r2dec`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn decompile_route_decision(..., function_facts: &FunctionFacts, type_facts: &FunctionTypeFacts, ...)
    /// ```
    ///
    /// Read type evidence through `function_facts.types`.
    pub R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
    Warn,
    "r2engine decompile route planning must read type evidence through FunctionFacts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2engine` directly assembles prepared decompile
    /// evidence maps or mutates individual `FunctionFacts` prepared-evidence
    /// fields.
    ///
    /// ### Why is this bad?
    ///
    /// Prepared SSA callsite, call-result, control, and render certificates are
    /// part of the single typed `FunctionFacts` contract. If `r2engine` builds
    /// or attaches those maps piecemeal, future callers can create partial
    /// evidence payloads whose route identity says "decompile" while the renderer
    /// sees missing proof.
    ///
    /// ### Example
    ///
    /// ```rust
    /// function_facts.set_callsites(decompile_callsite_argument_facts(prepared));
    /// function_facts.set_render(decompile_render_facts(prepared));
    /// ```
    ///
    /// Let `build_source_owned_type_analysis(...)` derive and retain
    /// prepared evidence from its exact `Arc<SsaArtifact>`.
    pub R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
    Warn,
    "r2engine must derive prepared decompile evidence through source-owned analysis"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec::DecompilerContext` defines decompile-route
    /// or render-policy side-channel fields/mutators outside the source-owned input.
    ///
    /// ### Why is this bad?
    ///
    /// `FunctionFacts::decompile_route` is the canonical render contract. A
    /// parallel context field lets direct callers bypass or contradict the
    /// engine-owned route/refusal decision, so executable C may be rendered under
    /// a different proof policy than the one carried by the typed facts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct DecompilerContext {
    ///     semantic_route: Option<SemanticRoutePlan>,
    /// }
    /// ```
    ///
    /// Project the immutable report only from `DecompilerInput`.
    pub R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    Warn,
    "r2dec must carry decompile routes through source-owned DecompilerInput"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec::DecompilerContext` defines a callee
    /// resolution side-channel field or mutator outside `FunctionFacts`.
    ///
    /// ### Why is this bad?
    ///
    /// Callee identity is canonical `FunctionFacts` evidence. A parallel
    /// renderer context field lets direct callers bypass the engine-owned
    /// callsite identity contract and can make raw target/name maps look
    /// authoritative.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct DecompilerContext {
    ///     callee_resolution: Option<CalleeResolutionFacts>,
    /// }
    /// ```
    ///
    /// Project callee evidence only from source-owned `DecompilerInput`.
    pub R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
    Warn,
    "r2dec must carry callee resolution through source-owned DecompilerInput"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` exposes APIs that mutate decompiler type
    /// evidence outside `FunctionFacts`.
    ///
    /// ### Why is this bad?
    ///
    /// Type/layout/signature facts are part of the `FunctionFacts` render
    /// contract. Public setters such as `set_type_facts`, `with_type_facts`, or
    /// mutable type-fact accessors let callers alter render evidence without
    /// carrying the matching route/refusal contract.
    ///
    /// ### Example
    ///
    /// ```rust
    /// decompiler.set_type_facts(type_facts);
    /// context.with_type_facts(type_facts);
    /// ```
    ///
    /// Seal the evidence as `SourceOwnedFunctionFacts` in `r2types`, then pass
    /// that single owner through `DecompilerInput::new(...)`.
    pub R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
    Warn,
    "r2dec production code must carry type evidence through SourceOwnedFunctionFacts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` reconstructs a prepared direct call target from
    /// prepared SSA variables, canonical value roots, or raw prepared callsite
    /// fields instead of consuming `FunctionFacts` callsite evidence.
    ///
    /// ### Why is this bad?
    ///
    /// Direct call targets are a canonical callsite fact produced upstream from
    /// SSA certificates and projected through `r2types::FunctionCallsiteFacts`.
    /// If `r2dec` reparses SSA variable names or reads prepared callsite target
    /// fields directly, missing FunctionFacts evidence becomes confident callee
    /// identity again.
    ///
    /// ### Example
    ///
    /// ```rust
    /// call_site.direct_target
    /// self.prepared_canonical_value_root(target)
    /// parse_address_from_var_name(&target.name)
    /// ```
    ///
    /// Use `FunctionCallsiteFacts::arguments_for_site(...).direct_target`.
    pub R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
    Warn,
    "r2dec must consume FunctionFacts direct-target evidence instead of reparsing prepared SSA"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` op-lowering reads prepared
    /// `CallsiteCertificate` data directly while synthesizing or recording
    /// executable calls.
    ///
    /// ### Why is this bad?
    ///
    /// Callsite target and argument evidence is already projected through
    /// `r2types::FunctionCallsiteFacts`. Reading prepared callsite
    /// certificates in the renderer creates a second call-proof owner and lets
    /// prepared SSA alone authorize executable calls without the `FunctionFacts`
    /// spine.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.prepared_call_site_for_op(block, op)
    /// self.prepared.callsite_certificate_for_op(block, op)
    /// fn certified_callsite_argument_values(cert: &r2types::CallsiteArgumentFacts)
    /// ```
    ///
    /// Use `FunctionCallsiteFacts::arguments_for_site(...)`.
    pub R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
    Warn,
    "certified r2dec call rendering must consume FunctionFacts callsite evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` stack owner authorization calls
    /// `FunctionRenderFacts::has_stack_slot_offset` and then locally
    /// recomposes proof from visible binding or type checks, or when certified
    /// call-result owner rendering reads stack alias/provenance helpers
    /// directly.
    ///
    /// ### Why is this bad?
    ///
    /// A render-fact stack offset or stack alias/provenance lookup only proves
    /// local renderer recovery. It does not authorize the renderer-local owner
    /// name or type. Certified stack owner helpers must call a
    /// `FunctionFacts`-owned predicate that checks the complete stack identity
    /// contract.
    pub R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
    Warn,
    "certified r2dec stack owner authorization must use a FunctionFacts-owned predicate"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` analysis reads prepared SSA call-result
    /// certificate maps directly.
    ///
    /// ### Why is this bad?
    ///
    /// Call-result ownership used by executable rendering must travel through
    /// `r2types::FunctionFacts`. Reading `prepared.certificates().call_results`
    /// in the renderer recreates a side channel and bypasses the engine-owned
    /// evidence projection.
    ///
    /// ### Example
    ///
    /// ```rust
    /// prepared.certificates().call_results.get(&value);
    /// prepared.certificates().call_results_by_callsite.get(&site);
    /// ```
    ///
    /// Use instead `FunctionCallResultFacts` from `FunctionFacts`.
    pub R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
    Warn,
    "r2dec analysis must consume FunctionFacts call-result facts instead of prepared certificate maps"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` reads prepared SSA predicate or switch
    /// maps directly, carries them through a side channel, or infers switch
    /// selectors from prepared SSA instead of the canonical control contract.
    ///
    /// ### Why is this bad?
    ///
    /// Branch predicate, loop structure, and switch selector rendering must be
    /// authorized by `r2types::FunctionFacts`. Reading
    /// `prepared.predicates().predicates`, `prepared.certificates().loops`,
    /// carrying `prepared_predicates`, or calling `infer_switch_selector_var`
    /// in the renderer recreates a side channel and bypasses the engine-owned
    /// control evidence projection.
    ///
    /// ### Example
    ///
    /// ```rust
    /// prepared.predicates().predicates.values();
    /// prepared.predicates().switches.get(&block);
    /// prepared.certificates().loops.values();
    /// inputs.prepared_predicates;
    /// prepared.function().infer_switch_selector_var(block);
    /// ```
    ///
    /// Use instead `FunctionControlFacts` from `FunctionFacts`.
    pub R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
    Warn,
    "r2dec analysis must consume FunctionFacts control facts instead of prepared predicate maps"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` falls back from a missing extracted branch condition
    /// to `CExpr::IntLit(1)`.
    ///
    /// ### Why is this bad?
    ///
    /// A missing branch predicate is not proof of a true condition. Rendering
    /// `if (1)` makes unresolved control flow look executable and confident.
    /// The renderer must emit an explicit residual/refusal comment unless the
    /// condition is backed by SSA/control evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fold_ctx.extract_condition_from_block(block).unwrap_or(CExpr::IntLit(1));
    /// ```
    ///
    /// Use instead an explicit unresolved-branch residual.
    pub R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
    Warn,
    "r2dec must not default missing branch predicates to true"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` memory lowering can construct member
    /// syntax from local type hints or type-oracle names without checking
    /// `FunctionTypeFacts::field_access_certificates`.
    ///
    /// ### Why is this bad?
    ///
    /// A type-looking base and external layout are not proof that a specific
    /// load/store is a real field access. Certified executable member syntax
    /// must be backed by explicit field-access evidence.
    pub R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
    Warn,
    "certified r2dec structured memory rendering must require direction-exact FunctionRenderFacts evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2engine` calls `r2dec` fallback-comment helpers.
    ///
    /// ### Why is this bad?
    ///
    /// Fallback/refusal text is route policy. `r2engine` owns the route and
    /// refusal decision, so it must construct engine-owned fallback comments
    /// from typed `FunctionFacts` instead of importing renderer helper policy.
    ///
    /// ### Example
    ///
    /// ```rust
    /// r2dec::semantic_fallback_comment(name, facts.semantics.as_ref())
    /// ```
    ///
    /// Use `r2engine::semantic_fallback_comment_for_facts(...)` or another
    /// engine-owned fallback helper.
    pub R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
    Warn,
    "r2engine must own refusal comments instead of calling r2dec helpers"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when a facts type answers a rendering decision rather than a fact.
    ///
    /// ### Why is this bad?
    ///
    /// A facts type says what is true about a function. A renderer decides what
    /// to do about it. A method named `should_inline`, `prefers_...` or
    /// `emit_...` moves that decision into the facts, and once it is there every
    /// consumer inherits one renderer's taste as though it were evidence, with
    /// no way to disagree and nothing to check the answer against.
    ///
    /// The names are the tell, so the names are what this checks. A fact is
    /// stated -- `is_`, `has_`, `for_`, `count_of_` -- and reads the same to
    /// every caller. A decision is imperative and reads as advice.
    ///
    /// ### Example
    ///
    /// ```rust
    /// impl FunctionRenderFacts {
    ///     pub fn should_inline_carrier(&self, value: ValueId) -> bool { .. }
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// impl FunctionRenderFacts {
    ///     pub fn reader_count_for_carrier(&self, value: ValueId) -> usize { .. }
    /// }
    /// ```
    pub FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
    Warn,
    "a facts type states what is true; deciding what to render belongs to a renderer"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when a `CStmt::Observed` or `CExpr::Observed` render-observation
    /// node is built as a struct literal anywhere but `r2dec::ast`.
    ///
    /// ### Why is this bad?
    ///
    /// An occurrence carries every observation id it has on one node, and an
    /// observed node never directly wraps another. The constructors in
    /// `r2dec::ast` keep that true by fusing: attaching ids to a node that
    /// already carries some adds them to its set. A literal skips the fusion,
    /// and wrapping an observed node in another rebuilds the old
    /// one-wrapper-per-id chain, whose depth grows with how many cells the
    /// occurrence accounts for. That chain is what overflowed the stack on a
    /// gap that claimed 38,726 cells: every recursive pass over the tree
    /// recursed once per id.
    ///
    /// The seal refuses a nested node with `nested_observation`, which is the
    /// runtime half of this check. The lint is the half that names the line.
    ///
    /// ### Example
    ///
    /// ```rust
    /// CStmt::Observed { ids, stmt: Box::new(rewrite(*stmt)) }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// CStmt::observe_all(ids, rewrite(*stmt))
    /// ```
    pub R2DEC_OBSERVED_LITERAL_CONSTRUCTION,
    Warn,
    "an observation node is built only by the fusing constructors in r2dec::ast"
);

rustc_session::declare_lint_pass!(R2sleighLintPass => [
    DISPLAY_NAMES_OUTSIDE_RENDERING,
    STRING_PREFIX_SEMANTIC_CLASSIFICATION,
    R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
    R2DEC_RAW_CALLEE_IMPORT_POLICY,
    R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
    R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
    R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
    R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
    R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
    R2DEC_ROUTE_POLICY_OWNERSHIP,
    R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
    R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
    R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
    R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
    R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
    R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
    R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
    R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
    R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
    R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
    R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
    R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
    R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
    R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
    R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
    R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
    FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
    R2DEC_OBSERVED_LITERAL_CONSTRUCTION,
]);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[
        DISPLAY_NAMES_OUTSIDE_RENDERING,
        STRING_PREFIX_SEMANTIC_CLASSIFICATION,
        R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
        R2DEC_RAW_CALLEE_IMPORT_POLICY,
        R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
        R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
        R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
        R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
        R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
        R2DEC_ROUTE_POLICY_OWNERSHIP,
        R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
        R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
        R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
        R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
        R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
        R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
        R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
        R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
        R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
        R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
        R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
        R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
        R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
        R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
        R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
        R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
        R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
        R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
        FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
        R2DEC_OBSERVED_LITERAL_CONSTRUCTION,
    ]);
    lint_store.register_late_pass(|_| Box::new(R2sleighLintPass));
}

impl<'tcx> LateLintPass<'tcx> for R2sleighLintPass {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if is_test_code(cx, item.hir_id()) {
            return;
        }
        if facts_impl_self_name(item).is_some() {
            for span in rendering_decision_method_names(cx, item) {
                span_lint(
                    cx,
                    FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
                    span,
                    "a facts type states what is true; name this for the fact it reports, not for what a renderer should do with it",
                );
            }
        }

        if is_r2dec_span(cx, item.span) && r2dec_route_policy_ownership_item(cx, item) {
            span_lint(
                cx,
                R2DEC_ROUTE_POLICY_OWNERSHIP,
                item.span,
                "r2dec must not define route/refusal policy helpers; r2engine owns route selection",
            );
        }

        if is_r2dec_span(cx, item.span) && r2dec_missing_route_defaults_to_standard_item(cx, item) {
            span_lint(
                cx,
                R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
                item.span,
                "r2dec must residualize missing FunctionFacts::decompile_route instead of defaulting to Standard",
            );
        }

        if is_r2engine_span(cx, item.span) && engine_decompiler_context_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2engine must carry decompile route/callee evidence through consuming source-owned finalization",
            );
        }

        if is_r2engine_span(cx, item.span) && engine_decompile_facts_spine_ownership_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
                item.span,
                "r2engine must not mutate raw FunctionFacts after source-owned analysis",
            );
        }

        if is_r2engine_span(cx, item.span)
            && raw_attach_prepared_decompile_evidence_signature_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
                item.span,
                "attach_prepared_decompile_evidence must not accept raw function_names/symbols side channels",
            );
        }

        if is_r2engine_span(cx, item.span) && engine_lower_level_decompile_api_bypass_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
                item.span,
                "r2engine must keep EngineDecompileRequest internal; callers decompile through EngineFunctionDecompileRequestInput",
            );
        }

        if is_r2engine_span(cx, item.span)
            && engine_decompile_fallback_comment_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
                item.span,
                "r2engine must carry fallback comments through DecompileFinalization",
            );
        }

        if is_r2engine_span(cx, item.span)
            && engine_decompile_route_type_facts_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
                item.span,
                "r2engine decompile route planning must not accept type facts outside FunctionFacts",
            );
        }

        if is_r2engine_span(cx, item.span)
            && engine_prepared_decompile_evidence_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
                item.span,
                "r2engine must derive prepared evidence inside source-owned analysis, not individual proof-map builders or setters",
            );
        }

        if is_r2dec_span(cx, item.span)
            && r2dec_decompiler_context_route_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not store route/render policy outside FunctionFacts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && r2dec_decompiler_context_callee_resolution_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not store callee resolution outside FunctionFacts",
            );
        }

        if is_r2dec_span(cx, item.span) && r2dec_direct_type_facts_mutator_item(cx, item) {
            span_lint(
                cx,
                R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
                item.span,
                "r2dec production APIs must not mutate type facts outside FunctionFacts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && r2dec_prepared_call_view_direct_target_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
                item.span,
                "r2dec prepared semantic view must read direct targets from FunctionFacts, not prepared callsite fields",
            );
        }

        if is_r2dec_op_lower_span(cx, item.span)
            && r2dec_direct_prepared_callsite_certificates_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
                item.span,
                "certified r2dec call rendering must read callsite proof from FunctionFacts, not prepared CallsiteCertificate",
            );
        }
    }

    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ImplItem<'tcx>) {
        if is_test_code(cx, item.hir_id()) {
            return;
        }
        if is_r2dec_span(cx, item.span) && r2dec_direct_type_facts_mutator_impl_item(cx, item) {
            span_lint(
                cx,
                R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
                item.span,
                "r2dec production methods must not mutate type facts outside FunctionFacts",
            );
        }

        if is_r2engine_span(cx, item.span)
            && engine_lower_level_decompile_api_bypass_impl_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
                item.span,
                "r2engine must not expose public decompile(&self, EngineDecompileRequest); use decompile_function with EngineFunctionDecompileRequest",
            );
        }

        if is_r2types_span(cx, item.span)
            && raw_attach_prepared_decompile_evidence_signature_impl_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
                item.span,
                "FunctionFacts::attach_prepared_decompile_evidence must not accept raw function_names/symbols side channels",
            );
        }

        if is_r2dec_span(cx, item.span) && r2dec_prepared_direct_target_reparse_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
                item.span,
                "r2dec direct call target lookup must not reparse prepared SSA names or roots",
            );
        }

        if is_r2dec_op_lower_span(cx, item.span)
            && r2dec_direct_prepared_callsite_certificates_impl_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
                item.span,
                "certified r2dec call rendering must not authorize calls from prepared callsite certificates",
            );
        }

        if is_r2dec_span(cx, item.span)
            && r2dec_certified_member_field_certificate_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
                item.span,
                "certified r2dec structured memory rendering must require direction-exact FunctionRenderFacts evidence",
            );
        }

        if is_r2dec_span(cx, item.span)
            && r2dec_decompiler_context_route_side_channel_method(item.ident.name.as_str())
        {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not expose route/render policy side-channel mutators",
            );
        }

        if is_r2dec_span(cx, item.span) && item.ident.name.as_str() == "with_callee_resolution" {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not expose callee-resolution side-channel mutators",
            );
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Struct(qpath, ..) = expr.kind
            && constructs_observation_node(cx, qpath, expr.hir_id)
            && !is_r2dec_ast_span(cx, expr.span)
        {
            span_lint(
                cx,
                R2DEC_OBSERVED_LITERAL_CONSTRUCTION,
                expr.span,
                "build an observation node with `observe_one` or `observe_all`, which fuse its ids into one set",
            );
        }

        if is_test_code(cx, expr.hir_id) {
            return;
        }

        if reads_display_names(expr) && !is_display_name_rendering_span(cx, expr.span) {
            span_lint(
                cx,
                DISPLAY_NAMES_OUTSIDE_RENDERING,
                expr.span,
                "display spellings are for rendering; classify behaviour from typed evidence instead",
            );
        }

        if let ExprKind::MethodCall(method, _receiver, [arg], _) = expr.kind
            && method.ident.as_str() == "starts_with"
            && semantic_prefix_literal(arg)
            && !is_canonical_ssa_var_classifier(cx, expr)
        {
            span_lint(
                cx,
                STRING_PREFIX_SEMANTIC_CLASSIFICATION,
                expr.span,
                "semantic storage/address classification by string prefix; use a typed classifier owned by the canonical fact producer",
            );
        }

        if let ExprKind::MethodCall(method, receiver, [_arg], _) = expr.kind
            && method.ident.as_str() == "get"
            && is_r2dec_path(cx, expr)
            && expr_references_known_function_signatures(receiver)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
                expr.span,
                "r2dec must resolve function signatures through r2types::CalleeIdentity, not direct raw-map lookup",
            );
        }

        if is_r2dec_analysis_path(cx, expr) && raw_callee_import_policy_expr(expr) {
            span_lint(
                cx,
                R2DEC_RAW_CALLEE_IMPORT_POLICY,
                expr.span,
                "r2dec analysis must consume CalleeResolutionFacts target resolution/policy, not reconstruct callee import/model policy",
            );
        }

        if is_r2dec_op_lower_path(cx, expr) && raw_call_target_address_parser_expr(expr) {
            span_lint(
                cx,
                R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
                expr.span,
                "r2dec op-lowering must use parse_address_from_var_name or CalleeResolutionFacts instead of local call-target address parsing",
            );
        }

        if is_r2dec_op_lower_path(cx, expr) && call_target_policy_ownership_expr(expr) {
            span_lint(
                cx,
                R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
                expr.span,
                "r2dec op-lowering must consume the typed callee target policy contract instead of recomputing imported/modeled policy",
            );
        }

        if is_r2dec_path(cx, expr) && callee_resolution_fallback_ownership_expr(expr) {
            span_lint(
                cx,
                R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
                expr.span,
                "r2dec must not synthesize CalleeResolutionFacts from raw call targets; pass the r2engine-owned resolution contract",
            );
        }

        if is_r2dec_op_lower_path(cx, expr) && call_arg_source_call_authority_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
                expr.span,
                "source_call proves provenance only; call-argument rendering needs certified argument evidence",
            );
        }

        if is_r2dec_path(cx, expr) && r2dec_route_policy_ownership_expr(expr) {
            span_lint(
                cx,
                R2DEC_ROUTE_POLICY_OWNERSHIP,
                expr.span,
                "r2dec must receive route/refusal decisions from r2engine instead of selecting them locally",
            );
        }

        if is_r2engine_path(cx, expr) && engine_decompiler_context_side_channel_expr(expr) {
            span_lint(
                cx,
                R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                expr.span,
                "r2engine must write decompile route/refusal decisions into FunctionFacts, not legacy DecompilerContext policy fields",
            );
        }

        if is_r2dec_analysis_path(cx, expr)
            && r2dec_direct_prepared_call_result_certificates_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
                expr.span,
                "r2dec analysis must read call-result proof from FunctionFacts, not prepared SSA certificate maps",
            );
        }

        if is_r2dec_path(cx, expr) && r2dec_direct_prepared_control_facts_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
                expr.span,
                "r2dec must read branch/switch proof from FunctionFacts, not prepared SSA predicate maps or local selector inference",
            );
        }

        if is_r2engine_path(cx, expr) && engine_r2dec_fallback_comment_ownership_expr(cx, expr) {
            span_lint(
                cx,
                R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
                expr.span,
                "r2engine must construct fallback/refusal comments from engine-owned route policy, not r2dec helper functions",
            );
        }

        if is_r2dec_path(cx, expr) && r2dec_empty_argument_call_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
                expr.span,
                "a call is built with an empty argument list no callsite fact supplied; render the facts' arguments or residualize",
            );
        }

        if is_r2dec_path(cx, expr) && r2dec_default_true_branch_condition_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
                expr.span,
                "r2dec must residualize unresolved branch predicates instead of rendering if (1)",
            );
        }

        if is_r2dec_path(cx, expr) && r2dec_certified_stack_owner_proof_recomposition_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
                expr.span,
                "certified r2dec stack owner helpers must call a FunctionFacts-owned predicate instead of recomposing proof from render facts or stack alias/provenance helpers",
            );
        }
    }
}

fn semantic_prefix_literal(expr: &Expr<'_>) -> bool {
    let ExprKind::Lit(lit) = expr.kind else {
        return false;
    };
    let LitKind::Str(symbol, _) = lit.node else {
        return false;
    };
    matches!(
        symbol.as_str(),
        "tmp:" | "const:" | "ram:" | "reg:" | "space" | "sym." | "obj." | "reloc."
    )
}

fn engine_r2dec_fallback_comment_ownership_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::Call(callee, _) = expr.kind else {
        return false;
    };
    if ![
        "block_guard_fallback_comment",
        "artifact_guard_fallback_comment",
        "semantic_fallback_comment",
    ]
    .iter()
    .any(|name| expr_path_last_segment_is(callee, name))
    {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(callee.span)
        .is_ok_and(|snippet| snippet.contains("r2dec::"))
}

fn r2dec_route_policy_ownership_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            [
                "fn semantic_route_plan(",
                "fn detached_semantic_route_plan(",
                "fn detached_semantic_linearization_reason(",
                "fn preferred_semantic_fallback_comment(",
                "fn preferred_semantic_linearization_reason(",
                "fn preferred_semantic_structuring_reason(",
                "fn preferred_semantic_summary_islands_reason(",
                "fn preferred_vm_summary_reason(",
                "fn cfg_guard_reason(",
                "fn cfg_guard_reason_from_summary(",
                "pub enum SemanticRoutePlan",
                "pub use planner::SemanticRoutePlan",
                "fn route_facts_to_plan(",
            ]
            .iter()
            .any(|needle| snippet.contains(needle))
        })
}

fn r2dec_missing_route_defaults_to_standard_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("decompile_route()")
                && (snippet.contains("SemanticRoutePlan::Standard")
                    || (snippet.contains("DecompileRouteFacts")
                        && snippet.contains("DecompileRouteKind::FallbackComment")))
        })
}

fn engine_prepared_decompile_evidence_side_channel_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            [
                "fn decompile_callsite_argument_facts(",
                "fn decompile_call_result_facts(",
                "fn decompile_render_facts(",
                "fn decompile_control_facts(",
            ]
            .iter()
            .any(|needle| snippet.contains(needle))
                || [
                    ".set_callsites(",
                    ".set_call_results(",
                    ".set_control(",
                    ".set_render(",
                ]
                .iter()
                .any(|needle| snippet.contains(needle))
        })
}

fn r2dec_route_policy_ownership_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => [
            "semantic_route_plan",
            "detached_semantic_route_plan",
            "detached_semantic_linearization_reason",
            "preferred_semantic_fallback_comment",
            "preferred_semantic_linearization_reason",
            "preferred_semantic_structuring_reason",
            "preferred_semantic_summary_islands_reason",
            "preferred_vm_summary_reason",
            "cfg_guard_reason",
            "cfg_guard_reason_from_summary",
        ]
        .iter()
        .any(|name| expr_path_last_segment_is(callee, name)),
        _ => false,
    }
}

fn r2dec_prepared_direct_target_reparse_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            snippet.contains("fn prepared_direct_call_target")
                && (snippet.contains("prepared_call_target_var")
                    || snippet.contains("parse_address_from_var_name")
                    || snippet.contains("prepared_canonical_value_root"))
        })
}

fn r2dec_prepared_call_view_direct_target_side_channel_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn populate_calls")
                && (snippet.contains(
                    "lookup_callee_identity_for_site(inputs, site, call_site.direct_target)",
                ) || snippet.contains("direct_target: call_site.direct_target"))
        })
}

fn r2dec_direct_prepared_callsite_certificates_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn certified_callsite_argument_values")
                && (snippet.contains("r2ssa::CallsiteCertificate")
                    || snippet.contains("r2types::CallsiteArgumentFacts"))
        })
}

fn r2dec_direct_prepared_callsite_certificates_impl_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            (snippet.contains("fn certified_callsite_for_op")
                && snippet.contains("callsite_certificate_for_op"))
                || (snippet.contains("fn certified_synthesized_call_expr_for_source_call")
                    && (snippet.contains("prepared_call_site_for_op")
                        || snippet.contains("resolved_call_target(call_site)")))
        })
}

fn r2dec_certified_member_field_certificate_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    (snippet.contains("fn render_access_expr_from_addr")
        && snippet.contains("member_access_expr")
        && !snippet.contains("certified_field_name_for_offset"))
        || snippet.contains("member_access_for_op_any_direction")
        || snippet.contains("array_access_for_op_any_direction")
}

/// Whether this builds `CExpr::call(target, vec![])` for a program call: a
/// call whose argument list is written empty in the renderer rather than taken
/// from the callsite facts.
///
/// A call to a `CExpr::External` is not one: that is a helper or intrinsic the
/// renderer itself defines (`__builtin_trap`, the residual helper), and its
/// arity is the renderer's own fact.
fn r2dec_empty_argument_call_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::Call(callee, [target, arguments]) = expr.kind else {
        return false;
    };
    if !expr_path_last_segment_is(callee, "call") {
        return false;
    }
    if let ExprKind::Struct(qpath, ..) = target.kind
        && qpath_last_segment_is(qpath, "External")
    {
        return false;
    }
    let source_map = cx.sess().source_map();
    source_map
        .span_to_snippet(callee.span)
        .is_ok_and(|snippet| snippet.ends_with("CExpr::call"))
        && source_map
            .span_to_snippet(arguments.span.source_callsite())
            .is_ok_and(|snippet| {
                let snippet: String = snippet.split_whitespace().collect();
                snippet == "vec![]" || snippet == "Vec::new()"
            })
}

fn r2dec_direct_prepared_call_result_certificates_expr(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
) -> bool {
    match expr.kind {
        ExprKind::Field(_, field) => {
            matches!(
                field.name.as_str(),
                "call_results" | "call_results_by_callsite"
            ) && cx
                .sess()
                .source_map()
                .span_to_snippet(expr.span)
                .is_ok_and(|snippet| snippet.contains("certificates()."))
        }
        ExprKind::MethodCall(method, _, _, _) => {
            method.ident.as_str() == "call_result_certificates_for_callsite"
        }
        _ => false,
    }
}

fn r2dec_direct_prepared_control_facts_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(_, field) => {
            field.name.as_str() == "prepared_predicates"
                || (matches!(field.name.as_str(), "predicates" | "switches")
                    && cx
                        .sess()
                        .source_map()
                        .span_to_snippet(expr.span)
                        .is_ok_and(|snippet| snippet.contains("predicates()")))
                || (matches!(field.name.as_str(), "loops" | "switches")
                    && cx
                        .sess()
                        .source_map()
                        .span_to_snippet(expr.span)
                        .is_ok_and(|snippet| snippet.contains("certificates()")))
        }
        ExprKind::MethodCall(method, _, _, _) => {
            method.ident.as_str() == "infer_switch_selector_var"
        }
        _ => false,
    }
}

fn engine_decompiler_context_side_channel_expr(expr: &Expr<'_>) -> bool {
    matches!(
        expr.kind,
        ExprKind::MethodCall(method, _, _, _)
            if matches!(
                method.ident.as_str(),
                "with_semantic_route"
                    | "with_render_permission"
                    | "with_runtime_type_inference_policy"
                    | "with_prepared_semantic_view_policy"
            )
    )
}

fn engine_decompiler_context_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    (snippet.contains("struct EngineDecompileRequest")
        || snippet.contains("struct DecompileRenderCacheKeyInput"))
        && snippet.contains("callee_resolution:")
}

fn engine_decompile_facts_spine_ownership_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    [
        ".set_callee_resolution(",
        ".set_callsites(",
        ".set_call_results(",
        ".set_call_render(",
        ".set_control(",
        ".set_render(",
        ".set_semantics(",
        ".set_decompile_route(",
        ".apply_decompile_type_override(",
        ".attach_prepared_decompile_evidence(",
        ".populate_certified_",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
}

fn raw_attach_prepared_decompile_evidence_signature(snippet: &str) -> bool {
    snippet.contains("fn attach_prepared_decompile_evidence(")
        && (snippet.contains("function_names:") || snippet.contains("symbols:"))
}

fn raw_attach_prepared_decompile_evidence_signature_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| raw_attach_prepared_decompile_evidence_signature(&snippet))
}

fn raw_attach_prepared_decompile_evidence_signature_impl_item(
    cx: &LateContext<'_>,
    item: &ImplItem<'_>,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| raw_attach_prepared_decompile_evidence_signature(&snippet))
}

fn engine_lower_level_decompile_api_bypass_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    let header = item_header(&snippet);
    header.contains("pub struct EngineDecompileRequest")
        || public_decompile_signature_accepts_engine_decompile_request(header)
}

fn engine_lower_level_decompile_api_bypass_impl_item(
    cx: &LateContext<'_>,
    item: &ImplItem<'_>,
) -> bool {
    if item.ident.name.as_str() != "decompile" {
        return false;
    }
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    public_decompile_signature_accepts_engine_decompile_request(item_header(&snippet))
}

fn public_decompile_signature_accepts_engine_decompile_request(header: &str) -> bool {
    header.contains("pub fn decompile(") && header.contains("EngineDecompileRequest")
}

fn item_header(snippet: &str) -> &str {
    snippet.split_once('{').map_or(snippet, |(head, _)| head)
}

fn engine_decompile_fallback_comment_side_channel_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    (snippet.contains("struct EngineDecompileRequest")
        && snippet.contains("fallback_comment: Option"))
        || (snippet.contains("fn render_engine_decompile_request")
            && snippet.contains("request.fallback_comment"))
}

fn engine_decompile_route_type_facts_side_channel_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    (snippet.contains("fn decompile_route_decision")
        || snippet.contains("fn plan_decompile_request")
        || snippet.contains("fn should_skip_runtime_type_inference"))
        && snippet.contains("type_facts:")
}

fn r2dec_decompiler_context_route_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    snippet.contains("struct DecompilerContext")
        && (snippet.contains("semantic_route:")
            || snippet.contains("render_permission:")
            || snippet.contains("skip_runtime_type_inference:")
            || snippet.contains("use_prepared_semantic_view:"))
}

fn r2dec_decompiler_context_callee_resolution_side_channel_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    snippet.contains("struct DecompilerContext") && snippet.contains("callee_resolution:")
}

fn r2dec_direct_type_facts_mutator_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    snippet.contains("fn from_analysis_inputs") && snippet.contains("FunctionTypeFacts")
}

fn r2dec_direct_type_facts_mutator_impl_item(cx: &LateContext<'_>, item: &ImplItem<'_>) -> bool {
    let name = item.ident.name.as_str();
    if !matches!(
        name,
        "type_facts_mut"
            | "with_type_facts"
            | "set_type_facts"
            | "set_known_function_signatures"
            | "set_external_type_db"
    ) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("FunctionTypeFacts")
                || snippet.contains("type_facts_mut")
                || snippet.contains(".function_facts.types")
        })
}

fn r2dec_decompiler_context_route_side_channel_method(name: &str) -> bool {
    matches!(
        name,
        "with_semantic_route"
            | "with_render_permission"
            | "with_runtime_type_inference_policy"
            | "with_prepared_semantic_view_policy"
    )
}

fn r2dec_default_true_branch_condition_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::MethodCall(method, _, _, _) = expr.kind else {
        return false;
    };
    if !matches!(method.ident.as_str(), "unwrap_or" | "unwrap_or_else") {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(expr.span)
        .is_ok_and(|snippet| {
            snippet.contains("extract_condition_from_block") && snippet.contains("CExpr::IntLit(1)")
        })
}

fn r2dec_certified_stack_owner_proof_recomposition_expr(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
) -> bool {
    let directly_reads_stack_owner_recovery = match expr.kind {
        ExprKind::MethodCall(method, _, _, _) => {
            matches!(
                method.ident.as_str(),
                "preferred_stack_alias_name" | "stack_slot_provenance_for_name"
            )
        }
        ExprKind::Call(callee, _) => [
            "preferred_stack_alias_name",
            "stack_slot_provenance_for_name",
        ]
        .iter()
        .any(|name| expr_path_last_segment_is(callee, name)),
        _ => false,
    };

    let recomposes_from_stack_offset = matches!(
        expr.kind,
        ExprKind::MethodCall(method, _, _, _) if method.ident.as_str() == "has_stack_slot_offset"
    );

    if !directly_reads_stack_owner_recovery && !recomposes_from_stack_offset {
        return false;
    }

    let Some((name, snippet)) = enclosing_item_name_and_snippet(cx, expr) else {
        return false;
    };
    if directly_reads_stack_owner_recovery && !certified_call_result_stack_owner_helper_name(&name)
    {
        return false;
    }
    if recomposes_from_stack_offset && !certified_stack_owner_helper_name(&name) {
        return false;
    }
    if snippet_calls_function_facts_stack_predicate(&snippet) {
        return false;
    }
    if directly_reads_stack_owner_recovery {
        return true;
    }
    snippet_recomposes_stack_owner_proof(&snippet)
}

fn certified_call_result_stack_owner_helper_name(name: &str) -> bool {
    name.contains("certified")
        && name.contains("call_result")
        && (name.contains("stack")
            || name.contains("owner")
            || name.contains("alias")
            || name.contains("source")
            || name.contains("expr")
            || name.contains("name"))
}

fn certified_stack_owner_helper_name(name: &str) -> bool {
    name.contains("certified")
        && name.contains("stack")
        && (name.contains("owner")
            || name.contains("local")
            || name.contains("visible_storage")
            || name.contains("storage_name"))
}

fn snippet_calls_function_facts_stack_predicate(snippet: &str) -> bool {
    [
        "FunctionFacts::",
        "function_facts.function_facts_stack",
        "function_facts.certified_stack",
        "function_facts.stack_owner",
        "function_facts.has_exact_stack",
        "stack_owner_authorizes",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
}

fn snippet_recomposes_stack_owner_proof(snippet: &str) -> bool {
    [
        "visible_bindings",
        "VisibleBinding",
        "binding.",
        "FunctionTypeFacts",
        "type_facts",
        "typed_stack",
        "stack_slots",
        "stack_type_is_renderable",
        "stack_owner_type_is_renderable",
        "local.ty",
        "slot.ty",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
}

/// Whether code is compiled only for tests: a `#[test]` function, or anything
/// carrying or inside `#[cfg(test)]`.
///
/// Read from the HIR's own attributes. The source text used to be searched
/// instead -- for "mod tests" or "#[test]" in every enclosing item's snippet,
/// on every expression -- which cost time quadratic in the size of an impl
/// block and exempted any item whose text merely mentioned a test.
fn is_test_code(cx: &LateContext<'_>, hir_id: rustc_hir::HirId) -> bool {
    clippy_utils::is_in_test(cx.tcx, hir_id) || clippy_utils::is_cfg_test(cx.tcx, hir_id)
}

fn expr_references_known_function_signatures(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "known_function_signatures"
                || expr_references_known_function_signatures(base)
        }
        ExprKind::MethodCall(_, receiver, args, _) => {
            expr_references_known_function_signatures(receiver)
                || args.iter().any(expr_references_known_function_signatures)
        }
        ExprKind::AddrOf(_, _, inner)
        | ExprKind::Unary(_, inner)
        | ExprKind::Cast(inner, _)
        | ExprKind::DropTemps(inner) => expr_references_known_function_signatures(inner),
        _ => false,
    }
}

fn expr_references_callee_facts(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "callee_facts" || expr_references_callee_facts(base)
        }
        ExprKind::MethodCall(_, receiver, args, _) => {
            expr_references_callee_facts(receiver) || args.iter().any(expr_references_callee_facts)
        }
        ExprKind::AddrOf(_, _, inner)
        | ExprKind::Unary(_, inner)
        | ExprKind::Cast(inner, _)
        | ExprKind::DropTemps(inner) => expr_references_callee_facts(inner),
        _ => false,
    }
}

fn raw_callee_import_policy_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => {
            expr_path_last_segment_is(callee, "callee_name_is_import_like")
                || expr_path_last_segment_is(callee, "from_direct_target")
        }
        ExprKind::MethodCall(method, _, _, _) => matches!(
            method.ident.as_str(),
            "identity_for_callsite"
                | "identity_for_direct_addr"
                | "is_import_policy_authorized"
                | "target_policy_for_callsite_or_identity"
        ),
        _ => false,
    }
}

fn raw_call_target_address_parser_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => expr_path_last_segment_is(callee, "extract_call_address"),
        ExprKind::MethodCall(method, _, _, _)
            if method.ident.as_str() == "prepared_constish_target_addr" =>
        {
            true
        }
        ExprKind::MethodCall(method, _, [arg], _) => {
            method.ident.as_str() == "strip_prefix" && call_target_address_prefix_literal(arg)
        }
        _ => false,
    }
}

fn call_target_address_prefix_literal(expr: &Expr<'_>) -> bool {
    let ExprKind::Lit(lit) = expr.kind else {
        return false;
    };
    let LitKind::Str(symbol, _) = lit.node else {
        return false;
    };
    matches!(symbol.as_str(), "ram:" | "const:")
}

fn call_target_policy_ownership_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => [
            "is_modeled_callee_identity",
            "modeled_callee_addr_for_identity",
        ]
        .iter()
        .any(|name| expr_path_last_segment_is(callee, name)),
        ExprKind::MethodCall(method, receiver, _, _)
            if method.ident.as_str() == "contains_key"
                && expr_references_callee_facts(receiver) =>
        {
            true
        }
        ExprKind::MethodCall(method, _, _, _) => matches!(
            method.ident.as_str(),
            "is_import_policy_authorized"
                | "identity_for_callsite"
                | "summary_helper_view_for_name"
                | "helper_view_for_name"
                | "is_modeled_callee_identity"
                | "modeled_callee_addr_for_identity"
                | "target_policy_for_callsite_or_identity"
        ),
        ExprKind::Struct(_, fields, _) => fields.iter().any(|field| {
            field.ident.name.as_str() == "direct_target_context" && expr_is_some_call(field.expr)
        }),
        _ => false,
    }
}

fn expr_is_some_call(expr: &Expr<'_>) -> bool {
    matches!(
        expr.kind,
        ExprKind::Call(callee, _) if expr_path_last_segment_is(callee, "Some")
    )
}

fn callee_resolution_fallback_ownership_expr(expr: &Expr<'_>) -> bool {
    matches!(
        expr.kind,
        ExprKind::Call(callee, _)
            if [
                "from_direct_call_targets",
                "identity_for_direct_target_in_context",
                "identity_for_name_in_context",
            ]
            .iter()
            .any(|name| expr_path_last_segment_is(callee, name))
    )
}

fn call_arg_source_call_authority_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if !enclosing_item_name(cx, expr)
        .as_deref()
        .is_some_and(is_call_arg_authority_boundary_name)
    {
        return false;
    }

    let ExprKind::MethodCall(method, receiver, _, _) = expr.kind else {
        return false;
    };
    if !matches!(method.ident.as_str(), "is_some" | "is_none" | "is_some_and") {
        return false;
    }
    expr_references_call_arg_source_call(receiver)
}

fn is_call_arg_authority_boundary_name(name: &str) -> bool {
    matches!(
        name,
        "certified_call_args_for_site"
            | "certified_call_args_for_site_with_direct_target"
            | "call_arg_binding_has_render_authority"
    )
}

fn expr_references_call_arg_source_call(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "source_call" || expr_references_call_arg_source_call(base)
        }
        ExprKind::MethodCall(_, receiver, args, _) => {
            expr_references_call_arg_source_call(receiver)
                || args.iter().any(expr_references_call_arg_source_call)
        }
        ExprKind::Call(callee, args) => {
            expr_references_call_arg_source_call(callee)
                || args.iter().any(expr_references_call_arg_source_call)
        }
        ExprKind::Block(block, _) => block.expr.is_some_and(expr_references_call_arg_source_call),
        ExprKind::AddrOf(_, _, inner)
        | ExprKind::Unary(_, inner)
        | ExprKind::Cast(inner, _)
        | ExprKind::DropTemps(inner) => expr_references_call_arg_source_call(inner),
        _ => false,
    }
}

fn enclosing_item_name(cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<String> {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        match node {
            rustc_hir::Node::ImplItem(item) => return Some(item.ident.name.as_str().to_string()),
            rustc_hir::Node::TraitItem(item) => return Some(item.ident.name.as_str().to_string()),
            _ => {}
        }
    }
    None
}

fn enclosing_item_name_and_snippet(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
) -> Option<(String, String)> {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        match node {
            rustc_hir::Node::Item(item) => {
                let snippet = cx.sess().source_map().span_to_snippet(item.span).ok()?;
                let name = function_name_from_snippet(&snippet)?;
                return Some((name, snippet));
            }
            rustc_hir::Node::ImplItem(item) => {
                let snippet = cx.sess().source_map().span_to_snippet(item.span).ok()?;
                return Some((item.ident.name.as_str().to_string(), snippet));
            }
            rustc_hir::Node::TraitItem(item) => {
                let snippet = cx.sess().source_map().span_to_snippet(item.span).ok()?;
                return Some((item.ident.name.as_str().to_string(), snippet));
            }
            _ => {}
        }
    }
    None
}

fn function_name_from_snippet(snippet: &str) -> Option<String> {
    let after_fn = snippet.split_once("fn ")?.1;
    let name = after_fn
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .next()?;
    (!name.is_empty()).then(|| name.to_string())
}

fn expr_path_last_segment_is(expr: &Expr<'_>, name: &str) -> bool {
    match expr.kind {
        ExprKind::Path(ref qpath) => qpath_last_segment_is(qpath, name),
        _ => false,
    }
}

fn qpath_last_segment_is(qpath: &QPath<'_>, name: &str) -> bool {
    match qpath {
        QPath::Resolved(_, path) => path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.name.as_str() == name),
        QPath::TypeRelative(_, segment) => segment.ident.name.as_str() == name,
    }
}

fn is_r2dec_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2dec/src/")
}

/// Whether this expression reads the display-name carrier.
fn reads_display_names(expr: &Expr<'_>) -> bool {
    match expr.kind {
        // Reaching the carrier at all is the thing being reported.
        ExprKind::MethodCall(method, _, _, _) if method.ident.as_str() == "display_names" => true,
        // Its accessors are only interesting when they are being applied to it.
        // `parameters` in particular is an ordinary name -- a typed function
        // interface has one too -- and matching it wherever it appeared
        // reported the interface accessor as if it were a display spelling.
        ExprKind::MethodCall(method, receiver, _, _) => {
            matches!(
                method.ident.as_str(),
                "name_for" | "parameter" | "parameters"
            ) && reads_display_names(receiver)
        }
        ExprKind::Field(_, field) => field.as_str() == "display_names",
        _ => false,
    }
}

/// The files allowed to read a display spelling.
///
/// `r2source` owns the carrier, and `r2dec` renders. `r2ssa`'s function
/// preparation fills it from the snapshot and `r2types`' `FunctionFacts`
/// carries it, which is a copy rather than a reading. `r2engine`'s program
/// info builds the `afi`/`afv` record, whose argument names are spelled for a
/// listing and decide nothing.
///
/// Directories, not files: `function.rs` and `function_facts.rs` became
/// module directories, and naming the old files turned the owners themselves
/// into findings.
fn is_display_name_rendering_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2source/src/display_names.rs")
        || filename.contains("crates/r2dec/src/")
        || filename.contains("crates/r2ssa/src/function/")
        || filename.contains("crates/r2types/src/function_facts/")
        || filename.contains("crates/r2engine/src/program/info.rs")
}

/// Whether a struct expression builds the `Observed` variant of `CStmt` or
/// `CExpr`, by what the path resolves to rather than how it is spelled, so
/// `Self::Observed { .. }` and a renamed import are caught too.
fn constructs_observation_node(
    cx: &LateContext<'_>,
    qpath: &QPath<'_>,
    hir_id: rustc_hir::HirId,
) -> bool {
    let rustc_hir::def::Res::Def(rustc_hir::def::DefKind::Variant, variant) =
        cx.qpath_res(qpath, hir_id)
    else {
        return false;
    };
    cx.tcx.item_name(variant).as_str() == "Observed"
        && matches!(
            cx.tcx.item_name(cx.tcx.parent(variant)).as_str(),
            "CStmt" | "CExpr"
        )
}

/// The one module that owns the observation node's canonical form.
fn is_r2dec_ast_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2dec/src/ast.rs")
}

fn is_r2dec_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2dec/src/")
}

fn is_r2dec_op_lower_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2dec/src/fold/op_lower/")
}

fn is_r2dec_analysis_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2dec/src/analysis/")
}

fn is_r2dec_op_lower_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2dec/src/fold/op_lower/")
}

fn is_r2engine_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2engine/src/")
}

fn is_r2engine_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2engine/src/")
}

/// Verb forms that ask what to do rather than state what is so.
const RENDERING_DECISION_PREFIXES: [&str; 8] = [
    "should_",
    "prefers_",
    "prefer_",
    "wants_",
    "emit_",
    "suppress_",
    "elide_",
    "inline_",
];

/// Whether this item declares methods on a type whose job is stating facts.
fn facts_impl_self_name(item: &Item<'_>) -> Option<String> {
    let rustc_hir::ItemKind::Impl(impl_item) = item.kind else {
        return None;
    };
    if impl_item.of_trait.is_some() {
        return None;
    }
    let rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(_, path)) = impl_item.self_ty.kind
    else {
        return None;
    };
    let name = path.segments.last()?.ident.name.to_string();
    name.ends_with("Facts").then_some(name)
}

/// Method names on a facts type that read as advice to a renderer.
fn rendering_decision_method_names(cx: &LateContext<'_>, item: &Item<'_>) -> Vec<rustc_span::Span> {
    let rustc_hir::ItemKind::Impl(impl_item) = item.kind else {
        return Vec::new();
    };
    impl_item
        .items
        .iter()
        .filter_map(|entry| {
            let def_id = entry.owner_id.to_def_id();
            let name = cx.tcx.item_name(def_id).to_string();
            RENDERING_DECISION_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
                .then(|| cx.tcx.def_span(def_id))
        })
        .collect()
}

fn is_r2types_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2types/src/")
}

fn is_canonical_ssa_var_classifier(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2ssa/src/var.rs")
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
