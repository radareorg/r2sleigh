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
    /// `r2sym`, `r2engine` and `r2types` respectively, and each has typed
    /// evidence for the job.
    ///
    /// ### Example
    ///
    /// ```rust
    /// // in r2sym, choosing a summary
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
    /// render/type/plugin code infer semantics that should arrive through typed
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
    /// Warns when internal Rust code embeds radare2 JSON command strings that
    /// are banned as plugin data sources, such as `afcfj`, `afvj`, or `tsj`.
    ///
    /// ### Why is this bad?
    ///
    /// The plugin may expose user-visible commands, but internal analysis must
    /// use typed collector APIs. Re-parsing radare2 command JSON creates a
    /// second source of truth and hides missing typed fields.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let facts = r2.cmd_str("afcfj");
    /// ```
    ///
    /// Use instead a typed collector payload owned by the radare2 seam.
    pub R2_JSON_COMMAND_INTERNAL_SEAM,
    Warn,
    "internal radare2 data seams should use typed collectors, not command JSON"
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
    /// Warns when `r2dec` call-argument rendering policy authorizes a nested
    /// call argument by asking whether its rendered callee is imported or
    /// modeled.
    ///
    /// ### Why is this bad?
    ///
    /// A rendered callee name is not proof that a nested call argument is safe
    /// to emit as executable C. Public call arguments may contain a call only
    /// when a certified render proof authorizes that callsite and argument
    /// value. Otherwise the renderer must emit an explicit unresolved argument
    /// or residual/refusal.
    ///
    /// ### Example
    ///
    /// ```rust
    /// if self.is_imported_call_target(func) {
    ///     return false; // source-less nested call accepted
    /// }
    /// ```
    ///
    /// Use instead the certified public call-argument gate, such as
    /// `proven_source_for_public_call_arg_call(...)`, and fail closed.
    pub R2DEC_UNCERTIFIED_CALL_ARG_CALL_POLICY,
    Warn,
    "r2dec call arguments must not authorize nested calls from rendered callee policy"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` call-argument render authorization treats
    /// `CallArgBinding::source_var_name` as standalone proof.
    ///
    /// ### Why is this bad?
    ///
    /// A source variable name is a rendered hint, not evidence that the call
    /// argument is safe to emit as executable C. Call arguments may render from
    /// exact value/call provenance, or from a source name only after it resolves
    /// through prepared semantic evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// binding.source_var_name.is_some()
    /// ```
    ///
    /// Use instead a helper that ties the name back to prepared SSA/semantic
    /// ownership before accepting it.
    pub R2DEC_CALL_ARG_SOURCE_NAME_AUTHORITY,
    Warn,
    "r2dec call-argument rendering must not treat source_var_name as standalone authority"
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
    /// Warns when certified `r2dec` call-argument rendering can fall through
    /// to local raw `CallArgBinding` inference without a prepared
    /// `FunctionFacts` callsite contract.
    ///
    /// ### Why is this bad?
    ///
    /// Matching a raw argument binding to an SSA value ID is still local
    /// renderer repair unless the argument list was projected through
    /// `FunctionFacts`. Certified executable calls must consume prepared
    /// callsite facts or residualize.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let args = self.render_call_args_for_site_with_direct_target(..., raw_args);
    /// self.call_arg_binding_has_render_authority(binding);
    /// ```
    ///
    /// Match raw argument source values against
    /// `CallsiteArgumentFacts::canonical_argument_values()` before rendering.
    pub R2DEC_CERTIFIED_RAW_CALL_ARG_FALLBACK,
    Warn,
    "certified r2dec call arguments must come from FunctionFacts, not local raw arg fallback"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified call proof validation compares rendered argument
    /// values against only a prefix of `FunctionCallsiteFacts.argument_values`.
    ///
    /// ### Why is this bad?
    ///
    /// A prefix match lets a renderer emit fewer call arguments than the
    /// canonical callsite contract proves. Certified executable calls must
    /// match the full typed callsite argument vector or residualize.
    ///
    /// ### Example
    ///
    /// ```rust
    /// cert.argument_values.iter().take(proof.values.len())
    /// ```
    ///
    /// Compare proof values against every `FunctionCallsiteFacts` argument
    /// value.
    pub R2DEC_CERTIFIED_CALL_ARG_PREFIX_PROOF,
    Warn,
    "certified r2dec call argument proofs must match the full FunctionFacts callsite vector"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when generic `r2dec` SSA-op statement lowering emits a direct
    /// zero-argument call fallback for `SSAOp::Call` or `SSAOp::CallInd`.
    ///
    /// ### Why is this bad?
    ///
    /// Certified executable calls require callsite target and argument evidence
    /// from `FunctionFacts`. The generic lowering path has no callsite frame,
    /// so rendering `foo()` locally fabricates an executable call when the
    /// typed callsite contract is missing or bypassed.
    ///
    /// ### Example
    ///
    /// ```rust
    /// SSAOp::Call { .. } => Some(CStmt::Expr(CExpr::call(func_expr, vec![])))
    /// ```
    ///
    /// Return a residual comment in certified rendering and use
    /// `op_to_stmt_with_args` for call-aware lowering.
    pub R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
    Warn,
    "r2dec direct call lowering must residualize instead of emitting zero-arg fallback calls"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` call-result replay can use cached
    /// `call_result_exprs` or alias definitions before trying the certified
    /// synthesized call expression.
    ///
    /// ### Why is this bad?
    ///
    /// Cached rendered calls and alias definitions are local renderer state.
    /// In certified mode, replaying a call result as executable C must use the
    /// certified callsite/argument proof carried through the prepared
    /// `FunctionFacts` path.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.call_result_exprs_map().get(&source_call)
    ///     .or_else(|| self.synthesized_call_expr_for_source_call(source_call))
    /// ```
    ///
    /// Use the synthesized certified call first in certified mode and only keep
    /// cached/alias fallback for legacy non-certified rendering.
    pub R2DEC_CERTIFIED_CALL_RESULT_REPLAY_FALLBACK,
    Warn,
    "certified r2dec call-result replay must use certified synthesized calls before cached fallback"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` accepts prepared rendered call-argument
    /// expressions as executable call arguments.
    ///
    /// ### Why is this bad?
    ///
    /// Prepared `CExpr` argument text is a renderer convenience view, not the
    /// decompile evidence contract. Certified calls must render arguments from
    /// `FunctionCallsiteFacts` argument values plus render evidence, otherwise
    /// prepared aliases, owner names, or cached definitions can become fake
    /// executable C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.prepared_call_args_for_site_with_direct_target(...)
    /// ```
    ///
    /// In certified mode, build call arguments from the FunctionFacts value
    /// vector; keep prepared argument rendering for non-certified display only.
pub R2DEC_CERTIFIED_PREPARED_CALL_ARG_EXPR_PROOF,
    Warn,
    "certified r2dec call arguments must not use prepared argument expression text as authority"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified executable lowering repairs post-call values from
    /// local renderer state.
    ///
    /// ### Why is this bad?
    ///
    /// Local post-call repair, cached call-result expressions, and raw
    /// definitions are compatibility paths. Certified executable C must flow
    /// from FunctionFacts render/call-result proof, otherwise the renderer can
    /// recover plausible call results without canonical evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.local_post_call_source_for_ssa_name(...)
    /// self.recovered_owned_call_result_definition_rhs(...)
    /// ```
    ///
    /// In certified mode, emit a residual unless FunctionFacts authorizes the
    /// value and rendered expression.
    pub R2DEC_CERTIFIED_EXECUTABLE_POST_CALL_REPAIR,
    Warn,
    "certified r2dec executable lowering must not repair post-call values from local renderer state"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified rendered-call proof collection discovers source
    /// calls by comparing local cached call expressions.
    ///
    /// ### Why is this bad?
    ///
    /// Equality against `call_result_exprs` or raw source-owner definitions is
    /// local renderer state, not a canonical callsite proof. Certified rendered
    /// calls must be tied to the current source call and FunctionFacts
    /// call-render disposition.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.source_matches_for_call_expr(call)
    /// self.call_result_exprs_map()
    /// ```
    ///
    /// Use current-source-call proof and FunctionCallRenderFacts instead.
    pub R2DEC_CERTIFIED_CALL_RENDER_PROOF_LOCAL_EQUALITY,
    Warn,
    "certified rendered-call proof must not be recovered from local cached call-expression equality"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` return rendering can choose local semantic
    /// or visible definitions before deriving the returned expression from a
    /// prepared `ReturnValueCertificate` / `ExpressionCertificate`.
    ///
    /// ### Why is this bad?
    ///
    /// A certified return proof identifies the returned SSA value, but local
    /// renderer definitions can still be poisoned or source-shaped. Executable
    /// return C must be rendered from prepared evidence or residualize.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.best_visible_definition(&target.display_name())
    /// ```
    ///
    /// Use `certified_return_expr_for_op` first in certified mode and keep local
    /// expression ranking only for legacy non-certified rendering.
    pub R2DEC_CERTIFIED_RETURN_LOCAL_EXPR_FALLBACK,
    Warn,
    "certified r2dec returns must render from prepared return evidence before local expression fallback"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` return-call rendering treats a prepared
    /// SSA call-result certificate as enough proof without requiring the
    /// canonical `FunctionCallResultFacts` result fact.
    ///
    /// ### Why is this bad?
    ///
    /// Prepared SSA certificates are construction evidence. The decompile
    /// render gate must consume the typed `FunctionFacts` contract; otherwise
    /// a return value can become executable `return callee(...)` without the
    /// canonical call-result fact carried through `r2engine`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// prepared.call_result_certificate_for_value(value)
    /// ```
    ///
    /// Use `certified_call_result_fact_for_value(value)` before synthesizing
    /// the returned call expression.
    pub R2DEC_CERTIFIED_RETURN_CALL_RESULT_FACT,
    Warn,
    "certified r2dec return-call rendering must require FunctionFacts call-result evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` local post-call source recovery can scan
    /// local SSA adjacency for a source call.
    ///
    /// ### Why is this bad?
    ///
    /// A nearby `CallDefine`, copy chain, or stack reload is useful discovery
    /// evidence, but it is not the typed decompile contract. Certified
    /// rendering must use FunctionFacts/prepared call-result provenance
    /// directly instead of rediscovering it in `r2dec`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// local_post_call_source_for_ssa_name_in_block(...)
    /// ```
    ///
    /// Return `None` immediately in certified mode and use the canonical
    /// call-result source lookup instead.
    pub R2DEC_CERTIFIED_LOCAL_POST_CALL_SOURCE_FACT,
    Warn,
    "certified r2dec local post-call source recovery must not scan local SSA adjacency"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` analysis defines helpers that infer
    /// authoritative call arguments locally.
    ///
    /// ### Why is this bad?
    ///
    /// Call arguments are executable C only after upstream SSA evidence has
    /// been carried through `r2types::FunctionFacts`. A decompiler-local
    /// `infer_call_authoritative_arg*` helper recreates callsite ownership
    /// downstream and can render plausible arguments without the canonical
    /// contract.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn infer_call_authoritative_args(...) { ... }
    /// ```
    ///
    /// Use instead `FunctionFacts` callsite argument facts populated by
    /// `r2engine` from `r2ssa` certificates.
    pub R2DEC_LOCAL_AUTHORITATIVE_CALL_ARG_INFERENCE,
    Warn,
    "r2dec must not infer authoritative call arguments outside FunctionFacts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when summary-only `r2dec` rendering paths emit executable-looking
    /// C constructs such as `switch`, `case`, `break`, or `return`.
    ///
    /// ### Why is this bad?
    ///
    /// Summary evidence is not native CFG/control/dataflow proof. Summary
    /// routes may render facts, comments, residuals, or refusals, but they must
    /// not present executable C as if control flow had been reconstructed.
    ///
    /// ### Example
    ///
    /// ```rust
    /// writeln!(out, "    switch ({selector}) {{");
    /// ```
    ///
    /// Use instead comment/fact rendering such as:
    ///
    /// ```rust
    /// writeln!(out, "    /* selector: {selector} */");
    /// ```
    pub R2DEC_SUMMARY_ROUTE_EXECUTABLE_C,
    Warn,
    "summary routes must render comments/facts, not executable C"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when summary-only `r2dec` renderer files construct executable
    /// `CStmt` nodes such as returns, branches, loops, switches, or expression
    /// statements.
    ///
    /// ### Why is this bad?
    ///
    /// Summary routes may emit comments/facts/residuals only. Building
    /// executable AST nodes in summary renderers creates a path where
    /// summary-only evidence can become native-looking C without going through
    /// the certified `FunctionFacts` render contract.
    ///
    /// ### Example
    ///
    /// ```rust
    /// vec![CStmt::Return(Some(expr))]
    /// ```
    ///
    /// Use `CStmt::comment(...)` or residualize. Executable output must be
    /// produced by an exact typed-output seal, outside summary renderers.
    pub R2DEC_SUMMARY_RENDER_EXECUTABLE_CSTMT,
    Warn,
    "summary/VM renderers must not construct executable CStmt bodies"
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
    /// Warns when `r2dec::Decompiler` exposes the removed raw
    /// `build_function(&SSAFunction)` API, or when the prepared AST builder can
    /// construct an executable `CFunction` without first checking
    /// `FunctionFacts::decompile_route`.
    ///
    /// ### Why is this bad?
    ///
    /// `SSAFunction` alone has no prepared SSA artifact or canonical
    /// `FunctionFacts` evidence. Keeping the raw AST builder as a compatibility
    /// entrypoint lets downstream callers bypass the engine-owned render
    /// contract.
    ///
    /// ### Example
    ///
    /// ```rust
    /// pub fn build_function(&self, func: &SSAFunction) -> CFunction {
    ///     ...
    /// }
    /// ```
    ///
    /// Use only `build_function_from_input(&DecompilerInput)` and require route
    /// facts before executable AST rendering.
    pub R2DEC_BUILD_FUNCTION_REQUIRES_ROUTE_FACTS,
    Warn,
    "r2dec must not expose raw SSAFunction build_function; prepared input must require FunctionFacts::decompile_route"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when public `r2dec` semantic-summary render entrypoints accept
    /// detached `FunctionFacts`, `FunctionTypeFacts`, `SemanticArtifactReport`,
    /// or a caller-supplied route instead of one exact `DecompilerInput`.
    ///
    /// ### Why is this bad?
    ///
    /// `DecompilerInput` retains immutable `SourceOwnedFunctionFacts`, which in
    /// turn retains the exact prepared SSA allocation. Detached reports and
    /// route arguments can otherwise be paired with a foreign source owner.
    ///
    /// ### Example
    ///
    /// ```rust
    /// pub fn render_semantic_worker_summary(..., facts: &FunctionFacts, ...)
    /// pub fn render_vm_semantic_summary(..., report: &SemanticArtifactReport, ...)
    /// ```
    ///
    /// Accept `&DecompilerInput`, derive its retained report, and require the
    /// matching summary render permission before emitting summary output.
    pub R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
    Warn,
    "r2dec summary rendering must require exact source-owned DecompilerInput"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` expands or repairs a certified external/header
    /// signature with locally recovered parameters or return types.
    ///
    /// ### Why is this bad?
    ///
    /// Function header arity is a typed contract owned by `FunctionFacts`.
    /// Letting local variable recovery append extra ABI-looking params or
    /// letting runtime type inference fill a return type makes the renderer a
    /// second signature owner.
    ///
    /// ### Example
    ///
    /// ```rust
    /// recovered_params.len().max(signature.params.len())
    /// ```
    ///
    /// Use the render-authorized signature for executable headers.
    pub R2DEC_LOCAL_HEADER_ARITY_REPAIR,
    Warn,
    "r2dec must not repair certified headers from local recovery or inference"
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
    /// Warns when `r2engine` passes, converts, or exposes renderer-local route
    /// plans beside the source-owned decompile input.
    ///
    /// ### Why is this bad?
    ///
    /// `r2engine` owns route selection, but the render boundary must carry that
    /// decision through the `SourceOwnedFunctionFacts` retained by
    /// `DecompilerInput`. Passing a route as a sibling argument recreates the
    /// removed r2engine/r2dec side channel.
    ///
    /// ### Example
    ///
    /// ```rust
    /// r2dec::render_semantic_worker_summary(name, facts, &route.to_decompiler_route(), config)
    /// ```
    ///
    /// Consume `TypeAnalysis::finalize_for_decompile`, construct one
    /// `DecompilerInput`, and pass only that exact owner to r2dec.
    pub R2ENGINE_R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
    Warn,
    "r2engine must not pass decompile routes beside source-owned DecompilerInput"
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
    /// Warns when summary decompile route/refusal state is carried in
    /// `EngineSummaryDecompileRequest` or render falls back to a request-local
    /// comment instead of the finalized source-owned input.
    ///
    /// ### Why is this bad?
    ///
    /// Summary decompile is still part of the decompile product path. If guard
    /// state or fallback comments live on a detached request, render decisions
    /// can diverge from the exact source-owned route contract.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct EngineSummaryDecompileRequest {
    ///     named_worker_guarded: bool,
    ///     fallback_comment: Option<String>,
    /// }
    /// ```
    ///
    /// Consume `TypeAnalysis::finalize_for_decompile`, then render only
    /// through the resulting `DecompilerInput`.
    pub R2ENGINE_SUMMARY_DECOMPILE_ROUTE_SIDE_CHANNEL,
    Warn,
    "r2engine summary decompile route/refusal state must come from source-owned finalization"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `crates/r2engine/src/lib.rs` exposes or calls the
    /// summary-only decompile API names `EngineSummaryDecompileRequest`,
    /// `decompile_summary`, or `decompile_summary_preprobe`.
    ///
    /// ### Why is this bad?
    ///
    /// Summary-only decompile must not be a decompile product path without the
    /// prepared SSA / `FunctionFacts` spine. Keeping a public request type or
    /// session method for summary decompile lets callers bypass prepared SSA,
    /// route authority, and certified render evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// session.decompile_summary(EngineSummaryDecompileRequest { ... });
    /// ```
    ///
    /// Use the prepared `EngineSession::decompile_function(...)` path and make
    /// summary evidence feed `FunctionFacts` before rendering or refusal.
    pub R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
    Warn,
    "r2engine must not expose/use summary-only decompile APIs as production decompile paths"
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
    /// Warns when `r2engine` mutates `FunctionFacts` semantics during render
    /// to hide an unrenderable summary artifact.
    ///
    /// ### Why is this bad?
    ///
    /// Render receives the canonical evidence contract. Clearing semantics
    /// while building `r2dec::DecompilerContext` makes the renderer see a
    /// different contract than route planning and downstream consumers saw. The
    /// route or refusal must be expressed in `FunctionFacts::decompile_route`
    /// before render starts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// function_facts.set_semantics(None);
    /// ```
    ///
    /// Choose a facts-owned fallback route for unrenderable summaries instead.
    pub R2ENGINE_RENDER_TIME_SEMANTICS_SUPPRESSION,
    Warn,
    "r2engine must not clear FunctionFacts semantics during decompile rendering"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when the production `r2engine` decompile path writes
    /// `FunctionFacts.types.merged_signature` or `signature_certificate`
    /// directly while applying a decompile type override.
    ///
    /// ### Why is this bad?
    ///
    /// The type override decision is engine orchestration, but the mutation
    /// that makes a signature render-authorized belongs to the typed
    /// `FunctionFacts` contract. Direct field writes create a second signature
    /// authority and let decompile rendering observe hand-patched facts that
    /// were not applied through the canonical type evidence API.
    ///
    /// ### Example
    ///
    /// ```rust
    /// artifact.function_facts.types.merged_signature = Some(signature);
    /// artifact.function_facts.types.signature_certificate = certificate;
    /// ```
    ///
    /// Put typed overrides in the parsed source context before building the
    /// source-owned type analysis.
    pub R2ENGINE_DECOMPILE_TYPE_OVERRIDE_SIDE_CHANNEL,
    Warn,
    "r2engine decompile type overrides must precede source-owned analysis"
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
    /// Warns when production code reintroduces whole-analysis cache mutation
    /// APIs outside request-local engine execution.
    ///
    /// ### Why is this bad?
    ///
    /// Whole-analysis caching was removed because realistic plugin sessions
    /// showed no reuse. Public cache or alias invalidation APIs would recreate
    /// an unmeasured authority-bearing side channel.
    ///
    /// ### Example
    ///
    /// ```rust
    /// session.clear_analysis_artifacts_for_function(&key, hash);
    /// ```
    ///
    /// Keep analysis request-local; retain only separately justified local
    /// memoization.
    pub R2ENGINE_CACHE_POLICY_OWNERSHIP,
    Warn,
    "whole-analysis cache mutation APIs are forbidden"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2engine::EngineArtifacts` carries decompile route or
    /// semantic-artifact fields beside `FunctionFacts`.
    ///
    /// ### Why is this bad?
    ///
    /// `FunctionFacts` is the canonical evidence spine. A generic artifact bag
    /// with `route` or `semantic_artifact` fields creates a second owner for
    /// render/refusal policy or semantic evidence and can drift from the facts
    /// handed to `r2dec`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct EngineArtifacts {
    ///     semantic_artifact: Option<SemanticArtifact>,
    ///     route: Option<DecompileRouteFacts>,
    /// }
    /// ```
    ///
    /// Store semantics and route/refusal decisions inside `FunctionFacts`.
    pub R2ENGINE_ARTIFACTS_FACTS_SIDE_CHANNEL,
    Warn,
    "r2engine EngineArtifacts must not duplicate FunctionFacts semantic or route evidence"
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
    /// Warns when `r2engine` reconstructs decompile authority from raw facts or
    /// legacy route-stamping helpers instead of consuming `TypeAnalysis`.
    ///
    /// ### Why is this bad?
    ///
    /// Only `TypeAnalysis::finalize_for_decompile(self, ...)` may seal
    /// immutable `SourceOwnedFunctionFacts`. A detached builder can pair a plan,
    /// report, or route with an unrelated prepared SSA allocation.
    ///
    /// ### Example
    ///
    /// ```rust
    /// analysis.stamp_decompile_route(route);
    /// let facts = analysis.into_source_owned_facts();
    /// ```
    ///
    /// Consume `analysis.finalize_for_decompile(finalization)` exactly once.
    pub R2ENGINE_DECOMPILER_INPUT_REQUIRES_SOURCE_OWNER,
    Warn,
    "r2engine decompiler input must consume exact source-owned type analysis"
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
    /// Warns when production `r2dec` enriches known function signatures from
    /// name/symbol maps while constructing render context.
    ///
    /// ### Why is this bad?
    ///
    /// Known callee signatures are typed evidence. If the renderer derives them
    /// from display names, `r2dec` becomes a second type-policy owner and can
    /// render calls with confidence that was not present in `FunctionFacts`.
    /// The engine/facts assembly path must attach this evidence before render.
    ///
    /// ### Example
    ///
    /// ```rust
    /// r2types::enrich_known_function_signatures_from_names(
    ///     &mut function_facts.types,
    ///     &function_names,
    ///     ptr_bits,
    /// );
    /// ```
    ///
    /// Build one `TypeAnalysis` with
    /// `build_source_owned_type_analysis(...)`, finalize it for the
    /// engine-selected decompile route, and pass the sealed
    /// `SourceOwnedFunctionFacts` through `DecompilerInput::new(...)`.
    pub R2DEC_LOCAL_SIGNATURE_ENRICHMENT,
    Warn,
    "r2dec must consume known callee signatures from FunctionFacts, not enrich them from names locally"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` code mutates switch case labels from
    /// nearby arithmetic or helper-derived display bias.
    ///
    /// ### Why is this bad?
    ///
    /// Switch case values are canonical CFG/SSA facts. If the renderer adjusts
    /// them from local `IntSub` patterns or dense-case guesses, unrelated
    /// arithmetic can turn authoritative switch metadata into plausible but
    /// fake source-shaped C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let label = case_value.saturating_add_signed(case_display_bias);
    /// ```
    ///
    /// Render the exact case value supplied by the canonical switch fact owner.
    pub R2DEC_SWITCH_CASE_VALUE_OWNERSHIP,
    Warn,
    "r2dec must render canonical switch case values without downstream display bias"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified switch selector rendering falls back to local
    /// `switch_selector_roots` instead of requiring `FunctionFacts` control
    /// evidence.
    ///
    /// ### Why is this bad?
    ///
    /// A local selector root is a renderer/use-info heuristic, not proof of a
    /// switch selector. Certified C must render switches only from canonical
    /// control facts; missing selector proof should become a residual.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let value = self.switch_selector_roots_map().get(&block_addr)?;
    /// ```
    ///
    /// In certified rendering, return `None` before using local selector roots.
    pub R2DEC_UNCERTIFIED_SWITCH_SELECTOR_ROOT_FALLBACK,
    Warn,
    "r2dec certified switch rendering must require FunctionFacts control evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified switch selector rendering accepts
    /// `PreparedSemanticView::switch_selector_expr_for_block` before requiring
    /// canonical `FunctionControlFacts`.
    ///
    /// ### Why is this bad?
    ///
    /// Prepared selector text is a renderer convenience view. It is not the
    /// typed control contract. Certified executable switch C must be authorized
    /// by `FunctionFacts::control`; otherwise summary/prepared text can
    /// materialize a switch selector without a block-scoped proof.
    ///
    /// ### Example
    ///
    /// ```rust
    /// view.switch_selector_expr_for_block(block_addr)
    /// ```
    ///
    /// In certified rendering, return `None` after the control-fact lookup and
    /// before reading prepared selector expressions.
    pub R2DEC_CERTIFIED_PREPARED_SWITCH_SELECTOR_PROOF,
    Warn,
    "certified r2dec switch selectors must require FunctionFacts control proof before prepared selector text"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` treats "there is exactly one switch selector fact"
    /// as proof for whatever block is currently being rendered.
    ///
    /// ### Why is this bad?
    ///
    /// Switch selector evidence is block-scoped. Reusing the only selector in
    /// the function for a different block fabricates control proof and can
    /// render executable switch C for the wrong CFG node.
    ///
    /// ### Example
    ///
    /// ```rust
    /// facts.switches.len() == 1
    /// view.switch_selector_expr_by_block.len() == 1
    /// ```
    ///
    /// Use exact `FunctionControlFacts::switch_for_block(block_addr)` style
    /// lookup and residualize when the block has no selector proof.
    pub R2DEC_SWITCH_SELECTOR_SINGLE_FACT_FALLBACK,
    Warn,
    "r2dec switch selector rendering must require a block-matching FunctionFacts control fact"
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
    /// Warns when certified `r2dec` output validation reads raw prepared
    /// expression, memory, return, or stack-slot certificates instead of the
    /// canonical `FunctionFacts` render evidence.
    ///
    /// ### Why is this bad?
    ///
    /// Renderability is an upstream fact. If `r2dec` validates executable C
    /// directly from prepared certificates, it creates a second render-proof
    /// owner and can bypass missing `FunctionFacts` evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let certificates = prepared.certificates();
    /// prepared.memory_certificate_for_op_site(block, op, is_write);
    /// prepared.return_certificate_for_op(block, op);
    /// certificates.expressions.get(&value);
    /// ```
    ///
    /// Use `FunctionRenderFacts` carried by `FunctionFacts`.
    pub R2DEC_DIRECT_PREPARED_RENDER_CERTIFICATES,
    Warn,
    "certified r2dec render validation must consume FunctionFacts render evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` call-result ownership logic derives a
    /// stable result owner from stack-local fallback helpers.
    ///
    /// ### Why is this bad?
    ///
    /// A post-call stack store is not by itself proof that the renderer may
    /// name the call result as that local. Stack-backed call-result ownership
    /// must arrive as prepared SSA/semantic ownership evidence; otherwise the
    /// renderer can turn missing provenance into confident source-shaped C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fallback_owned_call_result_stack_local_name_for_source(source);
    /// ```
    ///
    /// Use instead prepared semantic ownership, such as
    /// `PreparedCallView::result_owner`, or render the call result without
    /// inventing a stack-local owner.
    pub R2DEC_CALL_RESULT_STACK_OWNER_FALLBACK,
    Warn,
    "r2dec must not derive call-result owners from stack-local fallback logic"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` call-result ownership logic derives a
    /// stable owner from rendered call-expression matching.
    ///
    /// ### Why is this bad?
    ///
    /// Two rendered calls that look equivalent are not proof that one register
    /// owns the other callsite result. Call-result ownership must come from
    /// prepared SSA/semantic evidence, explicit aliases, or an exact
    /// unambiguous source proof; otherwise the decompiler can turn replayed or
    /// guessed call text into confident source-shaped C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fallback_owned_call_result_register_name_from_matching_definition(source);
    /// ```
    ///
    /// Use instead prepared semantic ownership, such as
    /// `PreparedCallView::result_owner`, or render a residual when ownership is
    /// not proven.
    pub R2DEC_CALL_RESULT_SOURCE_EXPR_OWNER_FALLBACK,
    Warn,
    "r2dec must not derive call-result owners from matching rendered call expressions"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` return-register call-result fallback can
    /// run before certified rendering has failed closed.
    ///
    /// ### Why is this bad?
    ///
    /// A direct return-register alias such as `rax` is ABI storage, not proof of
    /// stable result ownership. In certified rendering, call-result ownership
    /// must arrive through `FunctionFacts`; otherwise the renderer can turn
    /// missing ownership evidence into confident source-shaped C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fallback_owned_call_result_return_name_for_source(source_call);
    /// ```
    ///
    /// Use instead a certified guard before any return-register fallback logic,
    /// or consume an owner carried by `FunctionFacts`.
    pub R2DEC_CERTIFIED_CALL_RESULT_RETURN_REGISTER_FALLBACK,
    Warn,
    "certified r2dec rendering must not derive call-result owners from return-register fallback"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` call-result alias fallback can derive a
    /// stable owner before certified rendering has failed closed.
    ///
    /// ### Why is this bad?
    ///
    /// Alias maps and direct register aliases are local renderer observations,
    /// not proof that a call result has a stable source-level owner. Certified
    /// rendering must consume owners projected from `FunctionFacts`; otherwise
    /// a post-call register or temporary can become confident C without typed
    /// ownership evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// derive_stable_owned_call_result_name_for_source(aliases);
    /// ```
    ///
    /// Use instead a certified guard before local alias fallback, or consume
    /// `PreparedCallView::result_owner` projected from `FunctionFacts`.
    pub R2DEC_CERTIFIED_CALL_RESULT_ALIAS_OWNER_FALLBACK,
    Warn,
    "certified r2dec rendering must not derive call-result owners from local alias fallback"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` call-result ownership consults
    /// renderer-local `SemanticOwnershipFacts` before checking the prepared
    /// `FunctionFacts` owner path.
    ///
    /// ### Why is this bad?
    ///
    /// Local ownership maps are renderer recovery state. In certified
    /// rendering, stable call-result owners must come from prepared
    /// FunctionFacts/call-result evidence; otherwise a locally inferred owner
    /// can make an unproven call result look like source-level C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.ownership().ownership_for_source(...)
    /// self.ownership().source_for_visible_owner_name(...)
    /// ```
    ///
    /// Guard these paths out of certified rendering and use the prepared
    /// result-owner view instead.
    pub R2DEC_CERTIFIED_LOCAL_CALL_OWNERSHIP_FALLBACK,
    Warn,
    "certified r2dec call-result ownership must not trust renderer-local ownership maps"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` call-result preservation treats the
    /// renderer-local visible-owner cache as proof that a name should survive.
    ///
    /// ### Why is this bad?
    ///
    /// Preservation affects executable output even when it does not directly
    /// recover a call expression. In certified rendering, a visible call-result
    /// name must be preserved only if it can be traced back to stable
    /// FunctionFacts call-result ownership.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.ownership().has_visible_owner_name(name)
    /// ```
    ///
    /// In certified rendering, resolve the source call and require
    /// `stable_owned_call_result_name_for_source(source)` to match the visible
    /// name.
    pub R2DEC_CERTIFIED_CALL_RESULT_PRESERVATION_FALLBACK,
    Warn,
    "certified r2dec call-result preservation must not trust renderer-local ownership maps"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` duplicate-call pruning uses rendered-call
    /// source matching instead of certified FunctionFacts callsite proof.
    ///
    /// ### Why is this bad?
    ///
    /// Pruning is still a rendering decision: deleting a call because it looks
    /// like another rendered call can hide missing proof and change executable
    /// output. Certified rendering may prune duplicate calls only after the
    /// call source is proven through FunctionFacts callsite evidence.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.collect_rendered_call_sources_for_expr(expr, &mut sources);
    /// ```
    ///
    /// In certified rendering, use
    /// `collect_certified_rendered_call_sources_for_expr` and keep the
    /// statement when the proof is missing.
    pub R2DEC_CERTIFIED_DUPLICATE_CALL_PRUNING_FALLBACK,
    Warn,
    "certified r2dec duplicate-call pruning must require FunctionFacts callsite proof"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified visible-owner lookup returns a prepared source
    /// call without confirming the name is the stable FunctionFacts result
    /// owner for that call.
    ///
    /// ### Why is this bad?
    ///
    /// Prepared views may contain low-signal carriers such as return registers.
    /// A raw name match must not authorize executable call replay unless it
    /// also passes the same stable owner filter used by call-result ownership.
    ///
    /// ### Example
    ///
    /// ```rust
    /// return self.prepared_source_call_for_visible_owner_name(visible_name);
    /// ```
    ///
    /// Require `stable_owned_call_result_name_for_source(source)` to match the
    /// visible name before returning a source call.
    pub R2DEC_CERTIFIED_VISIBLE_OWNER_SOURCE_LOOKUP,
    Warn,
    "certified r2dec visible owner lookup must require stable FunctionFacts result ownership"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` call-result ownership accepts arbitrary
    /// prepared owner expressions instead of the stable FunctionFacts owner
    /// name path.
    ///
    /// ### Why is this bad?
    ///
    /// A call-result owner is identity evidence. If certified rendering treats
    /// `PreparedCallView::result_owner` as a general `CExpr`, a prepared side
    /// channel can smuggle executable expressions into output without proving
    /// a stable source-level owner name.
    ///
    /// ### Example
    ///
    /// ```rust
    /// view.result_owner.clone()
    /// ```
    ///
    /// Use `prepared_result_owner_name_for_source(...)` for certified
    /// rendering, then materialize `CExpr::Var(owner_name)`.
    pub R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_EXPR,
    Warn,
    "certified r2dec call-result ownership must accept only stable prepared owner names"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` accepts a prepared call-result owner name
    /// without also requiring canonical `FunctionCallResultFacts` owner
    /// evidence for the source call.
    ///
    /// ### Why is this bad?
    ///
    /// `PreparedSemanticView` is a render preparation view. Certified owner
    /// authority must come from `FunctionFacts::call_results`; otherwise a
    /// manually seeded prepared name can authorize executable call-result C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// prepared_result_owner_name_for_source(source_call).map(CExpr::Var)
    /// ```
    ///
    /// Require `has_certified_call_result_owner_fact_for_source(source_call)`
    /// before accepting the prepared owner name in certified mode.
    pub R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_FACT,
    Warn,
    "certified r2dec call-result owners must be backed by FunctionFacts call-result owner facts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` appended stack-return recovery reads
    /// renderer-local `return_stack_slots` without also requiring canonical
    /// render facts.
    ///
    /// ### Why is this bad?
    ///
    /// A locally detected stack return slot is not proof that executable C may
    /// return a friendly stack-local name. Certified rendering must require
    /// `FunctionFacts::render` return evidence and a structurally renderable
    /// return value before appending a return statement.
    pub R2DEC_CERTIFIED_STACK_RETURN_RENDER_FACTS,
    Warn,
    "certified r2dec stack-return recovery must require FunctionFacts render evidence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` local declaration validation or retention
    /// treats a stack offset certificate as enough proof for a rendered local
    /// name.
    ///
    /// ### Why is this bad?
    ///
    /// A certified stack offset only proves an object exists at that offset. It
    /// does not prove that a renderer-local friendly name or type is the
    /// canonical source-level local. Certified locals must require exact typed
    /// stack identity from `FunctionFacts`.
    pub R2DEC_CERTIFIED_STACK_LOCAL_IDENTITY,
    Warn,
    "certified r2dec local declarations must require exact typed stack identity"
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
    /// Warns when certified `r2dec` local declaration types can still come
    /// from renderer recovery, runtime inference, or runtime type hints.
    ///
    /// ### Why is this bad?
    ///
    /// Certified stack-local types must come from `FunctionTypeFacts`
    /// stack-slot/visible-binding evidence. Runtime type repair in `r2dec`
    /// creates a second type owner and can make unproven locals look typed.
    pub R2DEC_CERTIFIED_STACK_LOCAL_TYPE_OWNERSHIP,
    Warn,
    "certified r2dec stack local types must come from FunctionTypeFacts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` fold setup passes renderer-local type
    /// hints or a local type oracle into expression lowering.
    ///
    /// ### Why is this bad?
    ///
    /// CertifiedC output may use fold type hints to choose casts, pointer
    /// element types, and memory access shape. Those hints come from local
    /// runtime inference or variable recovery, not from the canonical
    /// `FunctionFacts` render contract.
    pub R2DEC_CERTIFIED_LOCAL_TYPE_HINTS,
    Warn,
    "certified r2dec fold inputs must not consume local type hints or local type oracle"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` reads local stable stack/local-store
    /// recovery directly on paths that can feed certified rendering.
    ///
    /// ### Why is this bad?
    ///
    /// `stable_stack_values` and `local_store_owner_expr_for_offset` are local
    /// recovery conveniences, not certified `FunctionFacts` evidence. Certified
    /// rendering must pass through a certified-aware accessor or an explicit
    /// non-certified/prepared-only guard before consuming them.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.use_info().stable_stack_values.get(&offset);
    /// local_store_owner_expr_for_offset(view, prepared, block, idx, offset);
    /// ```
    ///
    /// Use `stable_stack_value_for_offset(...)` or guard the prepared-only
    /// fallback out of certified rendering first.
    pub R2DEC_CERTIFIED_LOCAL_STACK_RECOVERY_BYPASS,
    Warn,
    "certified r2dec must not consume local stable stack/local-store recovery directly"
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
    /// Warns when `r2dec` tests assert source-shaped C snippets such as
    /// `return 1;` or `if (...)` from raw `Decompiler::decompile(&func)`
    /// output.
    ///
    /// ### Why is this bad?
    ///
    /// Raw `SSAFunction` decompile output does not prove that the rendered C is
    /// backed by canonical CFG/dataflow/type facts. Tests should assert the
    /// fold/AST/certificate invariant first, then use final text only for
    /// narrow stability or residual/refusal coverage.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let output = decompiler.decompile(&func);
    /// assert!(output.contains("return 1;"));
    /// ```
    ///
    /// Use instead a folded `CStmt::Return`, built AST, or render certificate
    /// invariant.
    pub R2DEC_SOURCE_SHAPED_DECOMPILE_ORACLE,
    Warn,
    "r2dec tests must not bless source-shaped C from raw SSAFunction decompile output"
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
    /// Warns when certified `r2dec` branch condition extraction can fall back
    /// to local/symbolic predicate recovery without first requiring
    /// `FunctionFacts` branch predicate evidence.
    ///
    /// ### Why is this bad?
    ///
    /// A rendered branch condition is executable control flow. Local flag,
    /// symbolic, or prepared-view recovery can be useful in legacy rendering,
    /// but certified rendering must only structure an `if`/loop condition when
    /// the condition expression is derived from canonical FunctionFacts control
    /// facts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.fold_ctx.extract_condition(op)
    /// self.local_branch_condition_expr(block, idx, cond, 0)
    /// ```
    ///
    /// In certified rendering, return `None` before those fallbacks unless
    /// `FunctionControlFacts::branch_for_block` supplies the predicate and
    /// comparison proof.
    pub R2DEC_CERTIFIED_BRANCH_CONDITION_FALLBACK,
    Warn,
    "certified r2dec branch conditions must come from FunctionFacts control facts"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` switch structuring emits `switch` syntax
    /// from selector/region shape without proving selector, case targets, and
    /// default target against `FunctionFacts` switch facts.
    ///
    /// ### Why is this bad?
    ///
    /// A switch is executable control flow. Selector proof alone does not prove
    /// case values or targets; rendering cases without the canonical
    /// `FunctionControlFacts::switches` payload can invent control structure.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.record_switch_render_proof(block, selector, cases, default);
    /// CStmt::Switch { ... }
    /// ```
    ///
    /// In certified rendering, require an exact `FunctionControlFacts::switches`
    /// match before emitting switch syntax; otherwise render a residual.
    pub R2DEC_CERTIFIED_SWITCH_STRUCTURE_FALLBACK,
    Warn,
    "certified r2dec switch rendering must require FunctionFacts switch structure proof"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when certified `r2dec` loop structuring emits `while`/`do while`
    /// from region shape without proving the loop against
    /// `FunctionFacts` loop structure facts.
    ///
    /// ### Why is this bad?
    ///
    /// A loop is executable control flow and includes more than a condition:
    /// body membership, latches, and exits must agree with the canonical loop
    /// certificate. Branch predicate proof alone is not enough to render a
    /// certified loop.
    ///
    /// ### Example
    ///
    /// ```rust
    /// self.record_loop_render_proof(header, predicate, value, body);
    /// CStmt::while_loop(cond, body_stmt)
    /// ```
    ///
    /// In certified rendering, require an exact `FunctionControlFacts::loops`
    /// match before emitting the loop; otherwise render an explicit residual.
    pub R2DEC_CERTIFIED_LOOP_STRUCTURE_FALLBACK,
    Warn,
    "certified r2dec loop rendering must require FunctionFacts loop structure proof"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when `r2dec` structures `Region::IfThenElse` into executable
    /// `CStmt::if_stmt` output without recording a branch render proof.
    ///
    /// ### Why is this bad?
    ///
    /// A rendered `if` is executable control flow. In certified mode it must
    /// be tied to the canonical `FunctionFacts` branch predicate for the
    /// condition block. Otherwise fake branch structure can survive validation
    /// as source-shaped C.
    ///
    /// ### Example
    ///
    /// ```rust
    /// Region::IfThenElse { .. } => CStmt::if_stmt(cond, then_stmt, else_stmt)
    /// ```
    ///
    /// Record `record_branch_render_proof(cond_block, predicate, value)` before
    /// emitting the `if` node, then validate it against `FunctionControlFacts`.
    pub R2DEC_CERTIFIED_BRANCH_RENDER_PROOF,
    Warn,
    "r2dec certified branch rendering must record FunctionFacts branch proof identity"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` uses broad local analysis presence, such
    /// as `has_definitions()` or `has_stack_slots()`, as proof that a synthetic
    /// stack local may be rendered.
    ///
    /// ### Why is this bad?
    ///
    /// Seeing a stack-shaped expression or any local definitions is not proof
    /// that an offset is a real local, stack argument, saved slot, or typed
    /// field. Executable stack locals must be backed by typed stack-slot facts
    /// in `FunctionFacts`; otherwise the renderer should leave a residual/raw
    /// expression.
    ///
    /// ### Example
    ///
    /// ```rust
    /// if offset < 0 && (self.has_stack_slots() || self.has_definitions()) {
    ///     return Some(Self::stack_synthetic_name(offset));
    /// }
    /// ```
    ///
    /// Use instead a typed stack-slot match from `FunctionFacts`.
    pub R2DEC_UNCERTIFIED_STACK_LOCAL_SYNTHESIS,
    Warn,
    "r2dec must not synthesize stack locals from broad local analysis presence"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2dec` defines fallback helpers that manufacture
    /// aggregate field names such as `f_<offset>` from a bare type name.
    ///
    /// ### Why is this bad?
    ///
    /// A `struct` or typedef-looking name is not proof that an offset is a real
    /// field. Member syntax must come from an explicit external layout,
    /// certified field access fact, or typed oracle evidence. Otherwise the
    /// renderer should keep pointer arithmetic/residual shape instead of
    /// inventing source-like fields.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn fallback_aggregate_field_name(type_name: &str, offset: u64) -> Option<String> {
    ///     Some(format!("f_{offset:x}"))
    /// }
    /// ```
    ///
    /// Use external layout facts carried through `FunctionFacts` instead.
    pub R2DEC_UNCERTIFIED_FIELD_PLACEHOLDER,
    Warn,
    "r2dec must not manufacture aggregate field placeholders without layout proof"
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
    /// Warns when `r2engine` constructs `r2dec::VariableRecovery` to infer
    /// signature parameters.
    ///
    /// ### Why is this bad?
    ///
    /// `r2engine` owns orchestration, while `r2types` owns type/signature
    /// inference and `r2dec` owns rendering. Pulling renderer variable recovery
    /// into the engine makes type inference depend on decompiler-local naming
    /// heuristics and reintroduces a second signature owner.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let mut vars = r2dec::VariableRecovery::new("rsp", "rbp", 64);
    /// vars.recover(&ssa);
    /// ```
    ///
    /// Use `r2types::recover_signature_params_from_ssa` instead.
    pub R2ENGINE_R2DEC_VARIABLE_RECOVERY_OWNERSHIP,
    Warn,
    "r2engine must not use r2dec VariableRecovery for signature inference"
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
    /// Warns when production `r2types` code outside `role_registry` calls the
    /// raw role-name signature lookup APIs directly.
    ///
    /// ### Why is this bad?
    ///
    /// Role names are weak hints. Signature/type projection must flow through
    /// `NativeWorkerRoleIdentity` and semantic evidence gates so name-only
    /// summaries cannot become authoritative type facts.
    ///
    /// ### Example
    ///
    /// ```rust
    /// role_registry::signature_hint_for_name_candidates([name], 0);
    /// ```
    ///
    /// Use instead `signature_hint_for_role_identity(...)` after r2sym has
    /// produced non-name semantic evidence.
    pub R2TYPES_ROLE_NAME_SIGNATURE_HINT_OWNERSHIP,
    Warn,
    "r2types consumers must not project signatures directly from role names"
);

rustc_session::declare_lint!(
    /// ### What it does
    ///
    /// Warns when production `r2engine` or `r2dec` assigns directly to canonical
    /// `FunctionFacts` report fields such as `types`, `summary_view`,
    /// `assumption_usage`, `render`, or `control`.
    ///
    /// ### Why is this bad?
    ///
    /// `FunctionFacts` is the typed combined contract. Direct field writes in
    /// consumers create silent side channels where type, semantic, or
    /// render evidence can be replaced without the canonical invariant methods
    /// that refresh plans and normalize certificates.
    ///
    /// ### Example
    ///
    /// ```rust
    /// function_facts.types = type_facts;
    /// ```
    ///
    /// Derive runtime evidence through the source-owned analysis builder and
    /// consuming finalization path.
    pub R2TYPES_FUNCTION_FACTS_FIELD_OWNERSHIP,
    Warn,
    "FunctionFacts owner fields must be mutated through r2types methods"
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
    R2_JSON_COMMAND_INTERNAL_SEAM,
    R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
    R2DEC_RAW_CALLEE_IMPORT_POLICY,
    R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
    R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
    R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
    R2DEC_UNCERTIFIED_CALL_ARG_CALL_POLICY,
    R2DEC_CALL_ARG_SOURCE_NAME_AUTHORITY,
    R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
    R2DEC_CERTIFIED_RAW_CALL_ARG_FALLBACK,
    R2DEC_CERTIFIED_CALL_ARG_PREFIX_PROOF,
    R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
    R2DEC_CERTIFIED_CALL_RESULT_REPLAY_FALLBACK,
    R2DEC_CERTIFIED_PREPARED_CALL_ARG_EXPR_PROOF,
    R2DEC_CERTIFIED_EXECUTABLE_POST_CALL_REPAIR,
    R2DEC_CERTIFIED_CALL_RENDER_PROOF_LOCAL_EQUALITY,
    R2DEC_CERTIFIED_RETURN_LOCAL_EXPR_FALLBACK,
    R2DEC_CERTIFIED_RETURN_CALL_RESULT_FACT,
    R2DEC_CERTIFIED_LOCAL_POST_CALL_SOURCE_FACT,
    R2DEC_LOCAL_AUTHORITATIVE_CALL_ARG_INFERENCE,
    R2DEC_SUMMARY_ROUTE_EXECUTABLE_C,
    R2DEC_SUMMARY_RENDER_EXECUTABLE_CSTMT,
    R2DEC_ROUTE_POLICY_OWNERSHIP,
    R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
    R2DEC_BUILD_FUNCTION_REQUIRES_ROUTE_FACTS,
    R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
    R2DEC_LOCAL_HEADER_ARITY_REPAIR,
    R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    R2ENGINE_R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
    R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
    R2ENGINE_SUMMARY_DECOMPILE_ROUTE_SIDE_CHANNEL,
    R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
    R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
    R2ENGINE_RENDER_TIME_SEMANTICS_SUPPRESSION,
    R2ENGINE_DECOMPILE_TYPE_OVERRIDE_SIDE_CHANNEL,
    R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
    R2ENGINE_ARTIFACTS_FACTS_SIDE_CHANNEL,
    R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
    R2ENGINE_DECOMPILER_INPUT_REQUIRES_SOURCE_OWNER,
    R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
    R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
    R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
    R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
    R2DEC_LOCAL_SIGNATURE_ENRICHMENT,
    R2DEC_SWITCH_CASE_VALUE_OWNERSHIP,
    R2DEC_UNCERTIFIED_SWITCH_SELECTOR_ROOT_FALLBACK,
    R2DEC_CERTIFIED_PREPARED_SWITCH_SELECTOR_PROOF,
    R2DEC_SWITCH_SELECTOR_SINGLE_FACT_FALLBACK,
    R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
    R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
    R2DEC_DIRECT_PREPARED_RENDER_CERTIFICATES,
    R2DEC_CALL_RESULT_STACK_OWNER_FALLBACK,
    R2DEC_CALL_RESULT_SOURCE_EXPR_OWNER_FALLBACK,
    R2DEC_CERTIFIED_CALL_RESULT_RETURN_REGISTER_FALLBACK,
    R2DEC_CERTIFIED_CALL_RESULT_ALIAS_OWNER_FALLBACK,
    R2DEC_CERTIFIED_LOCAL_CALL_OWNERSHIP_FALLBACK,
    R2DEC_CERTIFIED_CALL_RESULT_PRESERVATION_FALLBACK,
    R2DEC_CERTIFIED_DUPLICATE_CALL_PRUNING_FALLBACK,
    R2DEC_CERTIFIED_VISIBLE_OWNER_SOURCE_LOOKUP,
    R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_EXPR,
    R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_FACT,
    R2DEC_CERTIFIED_STACK_RETURN_RENDER_FACTS,
    R2DEC_CERTIFIED_STACK_LOCAL_IDENTITY,
    R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
    R2DEC_CERTIFIED_STACK_LOCAL_TYPE_OWNERSHIP,
    R2DEC_CERTIFIED_LOCAL_TYPE_HINTS,
    R2DEC_CERTIFIED_LOCAL_STACK_RECOVERY_BYPASS,
    R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
    R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
    R2DEC_SOURCE_SHAPED_DECOMPILE_ORACLE,
    R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
    R2DEC_CERTIFIED_BRANCH_CONDITION_FALLBACK,
    R2DEC_CERTIFIED_SWITCH_STRUCTURE_FALLBACK,
    R2DEC_CERTIFIED_LOOP_STRUCTURE_FALLBACK,
    R2DEC_CERTIFIED_BRANCH_RENDER_PROOF,
    R2DEC_UNCERTIFIED_STACK_LOCAL_SYNTHESIS,
    R2DEC_UNCERTIFIED_FIELD_PLACEHOLDER,
    R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
    R2ENGINE_R2DEC_VARIABLE_RECOVERY_OWNERSHIP,
    R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
    R2TYPES_ROLE_NAME_SIGNATURE_HINT_OWNERSHIP,
    R2TYPES_FUNCTION_FACTS_FIELD_OWNERSHIP,
    FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
    R2DEC_OBSERVED_LITERAL_CONSTRUCTION
]);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[
        DISPLAY_NAMES_OUTSIDE_RENDERING,
        STRING_PREFIX_SEMANTIC_CLASSIFICATION,
        R2_JSON_COMMAND_INTERNAL_SEAM,
        R2DEC_DIRECT_KNOWN_SIGNATURE_LOOKUP,
        R2DEC_RAW_CALLEE_IMPORT_POLICY,
        R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER,
        R2DEC_CALL_TARGET_POLICY_OWNERSHIP,
        R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
        R2DEC_UNCERTIFIED_CALL_ARG_CALL_POLICY,
        R2DEC_CALL_ARG_SOURCE_NAME_AUTHORITY,
        R2DEC_CALL_ARG_SOURCE_CALL_AUTHORITY,
        R2DEC_CERTIFIED_RAW_CALL_ARG_FALLBACK,
        R2DEC_CERTIFIED_CALL_ARG_PREFIX_PROOF,
        R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
        R2DEC_CERTIFIED_CALL_RESULT_REPLAY_FALLBACK,
        R2DEC_CERTIFIED_PREPARED_CALL_ARG_EXPR_PROOF,
        R2DEC_CERTIFIED_EXECUTABLE_POST_CALL_REPAIR,
        R2DEC_CERTIFIED_CALL_RENDER_PROOF_LOCAL_EQUALITY,
        R2DEC_CERTIFIED_RETURN_LOCAL_EXPR_FALLBACK,
        R2DEC_CERTIFIED_RETURN_CALL_RESULT_FACT,
        R2DEC_CERTIFIED_LOCAL_POST_CALL_SOURCE_FACT,
        R2DEC_LOCAL_AUTHORITATIVE_CALL_ARG_INFERENCE,
        R2DEC_SUMMARY_ROUTE_EXECUTABLE_C,
        R2DEC_SUMMARY_RENDER_EXECUTABLE_CSTMT,
        R2DEC_ROUTE_POLICY_OWNERSHIP,
        R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
        R2DEC_BUILD_FUNCTION_REQUIRES_ROUTE_FACTS,
        R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
        R2DEC_LOCAL_HEADER_ARITY_REPAIR,
        R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
        R2ENGINE_R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
        R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
        R2ENGINE_SUMMARY_DECOMPILE_ROUTE_SIDE_CHANNEL,
        R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
        R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
        R2ENGINE_RENDER_TIME_SEMANTICS_SUPPRESSION,
        R2ENGINE_DECOMPILE_TYPE_OVERRIDE_SIDE_CHANNEL,
        R2ENGINE_DECOMPILE_FALLBACK_COMMENT_SIDE_CHANNEL,
        R2ENGINE_CACHE_POLICY_OWNERSHIP,
        R2ENGINE_ARTIFACTS_FACTS_SIDE_CHANNEL,
        R2ENGINE_DECOMPILE_ROUTE_TYPE_FACTS_SIDE_CHANNEL,
        R2ENGINE_DECOMPILER_INPUT_REQUIRES_SOURCE_OWNER,
        R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
        R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
        R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
        R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
        R2DEC_LOCAL_SIGNATURE_ENRICHMENT,
        R2DEC_SWITCH_CASE_VALUE_OWNERSHIP,
        R2DEC_UNCERTIFIED_SWITCH_SELECTOR_ROOT_FALLBACK,
        R2DEC_CERTIFIED_PREPARED_SWITCH_SELECTOR_PROOF,
        R2DEC_SWITCH_SELECTOR_SINGLE_FACT_FALLBACK,
        R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
        R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
        R2DEC_DIRECT_PREPARED_RENDER_CERTIFICATES,
        R2DEC_CALL_RESULT_STACK_OWNER_FALLBACK,
        R2DEC_CALL_RESULT_SOURCE_EXPR_OWNER_FALLBACK,
        R2DEC_CERTIFIED_CALL_RESULT_RETURN_REGISTER_FALLBACK,
        R2DEC_CERTIFIED_CALL_RESULT_ALIAS_OWNER_FALLBACK,
        R2DEC_CERTIFIED_LOCAL_CALL_OWNERSHIP_FALLBACK,
        R2DEC_CERTIFIED_CALL_RESULT_PRESERVATION_FALLBACK,
        R2DEC_CERTIFIED_DUPLICATE_CALL_PRUNING_FALLBACK,
        R2DEC_CERTIFIED_VISIBLE_OWNER_SOURCE_LOOKUP,
        R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_EXPR,
        R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_FACT,
        R2DEC_CERTIFIED_STACK_RETURN_RENDER_FACTS,
        R2DEC_CERTIFIED_STACK_LOCAL_IDENTITY,
        R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
        R2DEC_CERTIFIED_STACK_LOCAL_TYPE_OWNERSHIP,
        R2DEC_CERTIFIED_LOCAL_TYPE_HINTS,
        R2DEC_CERTIFIED_LOCAL_STACK_RECOVERY_BYPASS,
        R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
        R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
        R2DEC_SOURCE_SHAPED_DECOMPILE_ORACLE,
        R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
        R2DEC_CERTIFIED_BRANCH_CONDITION_FALLBACK,
        R2DEC_CERTIFIED_SWITCH_STRUCTURE_FALLBACK,
        R2DEC_CERTIFIED_LOOP_STRUCTURE_FALLBACK,
        R2DEC_CERTIFIED_BRANCH_RENDER_PROOF,
        R2DEC_UNCERTIFIED_STACK_LOCAL_SYNTHESIS,
        R2DEC_UNCERTIFIED_FIELD_PLACEHOLDER,
        R2DEC_CERTIFIED_MEMBER_FIELD_CERTIFICATE,
        R2ENGINE_R2DEC_VARIABLE_RECOVERY_OWNERSHIP,
        R2ENGINE_R2DEC_FALLBACK_COMMENT_OWNERSHIP,
        R2TYPES_ROLE_NAME_SIGNATURE_HINT_OWNERSHIP,
        R2TYPES_FUNCTION_FACTS_FIELD_OWNERSHIP,
        FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
        R2DEC_OBSERVED_LITERAL_CONSTRUCTION,
    ]);
    lint_store.register_late_pass(|_| Box::new(R2sleighLintPass));
}

impl<'tcx> LateLintPass<'tcx> for R2sleighLintPass {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if facts_impl_self_name(item).is_some() && !item_is_test_only(cx, item) {
            for span in rendering_decision_method_names(cx, item) {
                span_lint(
                    cx,
                    FACTS_METHOD_SHAPED_LIKE_A_RENDERING_DECISION,
                    span,
                    "a facts type states what is true; name this for the fact it reports, not for what a renderer should do with it",
                );
            }
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_route_policy_ownership_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_ROUTE_POLICY_OWNERSHIP,
                item.span,
                "r2dec must not define route/refusal policy helpers; r2engine owns route selection",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_missing_route_defaults_to_standard_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_MISSING_DECOMPILE_ROUTE_DEFAULT_STANDARD,
                item.span,
                "r2dec must residualize missing FunctionFacts::decompile_route instead of defaulting to Standard",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_build_function_requires_route_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_BUILD_FUNCTION_REQUIRES_ROUTE_FACTS,
                item.span,
                "r2dec build_function must residualize before executable AST rendering when FunctionFacts::decompile_route is missing",
            );
        }

        if is_r2dec_lib_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_summary_render_route_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2dec summary render APIs must accept DecompilerInput and derive route permission from its exact source-owned facts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_local_header_arity_repair_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_LOCAL_HEADER_ARITY_REPAIR,
                item.span,
                "r2dec must not repair certified headers from local recovery or inference",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_local_signature_enrichment_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_LOCAL_SIGNATURE_ENRICHMENT,
                item.span,
                "r2dec must not enrich known signatures from names while constructing render context",
            );
        }

        if is_r2dec_analysis_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_local_authoritative_call_arg_inference_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_LOCAL_AUTHORITATIVE_CALL_ARG_INFERENCE,
                item.span,
                "r2dec must consume FunctionFacts callsite arguments instead of inferring authoritative call args locally",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_decompiler_context_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2engine must carry decompile route/callee evidence through consuming source-owned finalization",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_r2dec_route_conversion_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2engine must not define route conversion helpers or depend on r2dec route types",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_decompile_facts_spine_ownership_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILE_FACTS_SPINE_OWNERSHIP,
                item.span,
                "r2engine must not mutate raw FunctionFacts after source-owned analysis",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && raw_attach_prepared_decompile_evidence_signature_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
                item.span,
                "attach_prepared_decompile_evidence must not accept raw function_names/symbols side channels",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_summary_decompile_route_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_SUMMARY_DECOMPILE_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2engine summary decompile route/refusal must be carried by FunctionFacts, not request fields",
            );
        }

        if is_r2engine_lib_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_summary_only_decompile_api_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
                item.span,
                "r2engine production decompile must not expose summary-only request or decompile_summary entrypoints without prepared SSA",
            );
        }

        if is_r2engine_lib_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_lower_level_decompile_api_bypass_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_LOWER_LEVEL_DECOMPILE_API_BYPASS,
                item.span,
                "r2engine must keep EngineDecompileRequest internal; expose EngineFunctionDecompileRequest for plugin/user decompile paths",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_render_time_semantics_suppression_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_RENDER_TIME_SEMANTICS_SUPPRESSION,
                item.span,
                "r2engine must route/refuse unrenderable summaries before render instead of clearing FunctionFacts semantics",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_decompile_type_override_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILE_TYPE_OVERRIDE_SIDE_CHANNEL,
                item.span,
                "r2engine must apply type overrides before building source-owned analysis",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
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
            && !item_is_test_only(cx, item)
            && engine_whole_analysis_cache_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_CACHE_POLICY_OWNERSHIP,
                item.span,
                "r2engine must keep whole-analysis execution request-local and stateless",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && engine_artifacts_facts_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_ARTIFACTS_FACTS_SIDE_CHANNEL,
                item.span,
                "r2engine EngineArtifacts must not duplicate FunctionFacts semantic or route evidence",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
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
            && !item_is_test_only(cx, item)
            && engine_decompiler_input_requires_source_owner_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_DECOMPILER_INPUT_REQUIRES_SOURCE_OWNER,
                item.span,
                "r2engine must consume TypeAnalysis::finalize_for_decompile before constructing DecompilerInput",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !item_is_test_only(cx, item)
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
            && !item_is_test_only(cx, item)
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
            && !item_is_test_only(cx, item)
            && r2dec_decompiler_context_callee_resolution_side_channel_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_CALLEE_RESOLUTION_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not store callee resolution outside FunctionFacts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_direct_type_facts_mutator_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
                item.span,
                "r2dec production APIs must not mutate type facts outside FunctionFacts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_certified_call_arg_prefix_proof_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_ARG_PREFIX_PROOF,
                item.span,
                "certified call proof validation must compare the full FunctionFacts callsite argument vector",
            );
        }

        if is_r2dec_span(cx, item.span) && r2dec_source_shaped_decompile_oracle_item(cx, item) {
            span_lint(
                cx,
                R2DEC_SOURCE_SHAPED_DECOMPILE_ORACLE,
                item.span,
                "r2dec tests must prove fold/AST/certificate invariants instead of source-shaped raw decompile text",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_uncertified_switch_selector_root_fallback_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_UNCERTIFIED_SWITCH_SELECTOR_ROOT_FALLBACK,
                item.span,
                "certified switch rendering must residualize before local switch_selector_roots fallback",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
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
            && !item_is_test_only(cx, item)
            && r2dec_direct_prepared_callsite_certificates_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CALLSITE_CERTIFICATES,
                item.span,
                "certified r2dec call rendering must read callsite proof from FunctionFacts, not prepared CallsiteCertificate",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !item_is_test_only(cx, item)
            && r2dec_direct_prepared_render_certificates_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_RENDER_CERTIFICATES,
                item.span,
                "certified r2dec render validation must read render proof from FunctionFacts, not prepared certificates",
            );
        }
    }

    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ImplItem<'tcx>) {
        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_direct_type_facts_mutator_impl_item(cx, item)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_TYPE_FACTS_MUTATOR,
                item.span,
                "r2dec production methods must not mutate type facts outside FunctionFacts",
            );
        }

        if is_r2engine_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && matches!(
                item.ident.name.as_str(),
                "clear_analysis_artifacts_for_function"
                    | "cached_artifacts"
                    | "cached_artifacts_with_decision"
                    | "insert_artifacts"
                    | "cache_plan"
                    | "cache_profile"
            )
        {
            span_lint(
                cx,
                R2ENGINE_CACHE_POLICY_OWNERSHIP,
                item.span,
                "r2engine must not expose direct artifact-cache invalidation outside engine requests",
            );
        }

        if is_r2engine_lib_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && engine_summary_only_decompile_api_impl_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
                item.span,
                "r2engine production decompile must use prepared EngineFunctionDecompileRequest instead of summary-only decompile entrypoints",
            );
        }

        if is_r2engine_lib_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
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
            && !impl_item_is_test_only(cx, item)
            && raw_attach_prepared_decompile_evidence_signature_impl_item(cx, item)
        {
            span_lint(
                cx,
                R2ENGINE_PREPARED_DECOMPILE_EVIDENCE_SIDE_CHANNEL,
                item.span,
                "FunctionFacts::attach_prepared_decompile_evidence must not accept raw function_names/symbols side channels",
            );
        }

        if is_r2dec_span(cx, item.span) && r2dec_switch_case_value_ownership_item(cx, item.span) {
            span_lint(
                cx,
                R2DEC_SWITCH_CASE_VALUE_OWNERSHIP,
                item.span,
                "r2dec must not define switch case display-bias helpers; canonical switch facts own case values",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_switch_selector_single_fact_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_SWITCH_SELECTOR_SINGLE_FACT_FALLBACK,
                item.span,
                "r2dec must not reuse a single switch selector fact for a non-matching block",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_prepared_switch_selector_proof_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_PREPARED_SWITCH_SELECTOR_PROOF,
                item.span,
                "certified switch rendering must residualize before prepared selector text fallback",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_prepared_direct_target_reparse_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_PREPARED_DIRECT_TARGET_REPARSE,
                item.span,
                "r2dec direct call target lookup must not reparse prepared SSA names or roots",
            );
        }

        if is_r2dec_op_lower_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
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
            && r2dec_call_result_stack_owner_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CALL_RESULT_STACK_OWNER_FALLBACK,
                item.span,
                "r2dec must not derive call-result owners from stack-local fallback logic",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_call_result_source_expr_owner_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CALL_RESULT_SOURCE_EXPR_OWNER_FALLBACK,
                item.span,
                "r2dec must not derive call-result owners from matching rendered call expressions",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_call_result_return_register_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_RESULT_RETURN_REGISTER_FALLBACK,
                item.span,
                "certified r2dec rendering must reject return-register owner fallback before inference",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_call_result_alias_owner_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_RESULT_ALIAS_OWNER_FALLBACK,
                item.span,
                "certified r2dec rendering must reject local alias owner fallback before inference",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_local_call_ownership_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOCAL_CALL_OWNERSHIP_FALLBACK,
                item.span,
                "certified r2dec call-result ownership must not read local ownership maps before prepared FunctionFacts ownership",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_call_result_preservation_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_RESULT_PRESERVATION_FALLBACK,
                item.span,
                "certified call-result preservation must prove the visible name through FunctionFacts ownership before reading local owner caches",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_duplicate_call_pruning_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_DUPLICATE_CALL_PRUNING_FALLBACK,
                item.span,
                "certified duplicate-call pruning must use FunctionFacts callsite proof and keep calls when proof is missing",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_visible_owner_source_lookup_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_VISIBLE_OWNER_SOURCE_LOOKUP,
                item.span,
                "certified visible-owner lookup must cross-check the stable FunctionFacts result owner",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_prepared_result_owner_expr_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_EXPR,
                item.span,
                "certified call-result owner expressions must be reduced to stable prepared owner names",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_prepared_result_owner_fact_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_PREPARED_RESULT_OWNER_FACT,
                item.span,
                "certified call-result owner names must require FunctionFacts call-result owner facts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_stack_return_render_facts_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_STACK_RETURN_RENDER_FACTS,
                item.span,
                "certified r2dec stack-return recovery must require FunctionFacts render evidence",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_stack_local_identity_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_STACK_LOCAL_IDENTITY,
                item.span,
                "certified r2dec local declarations must require exact typed stack identity",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_stack_local_type_ownership_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_STACK_LOCAL_TYPE_OWNERSHIP,
                item.span,
                "certified r2dec stack local types must come from FunctionTypeFacts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_local_type_hints_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOCAL_TYPE_HINTS,
                item.span,
                "certified r2dec fold inputs must not consume local type hints or local type oracle",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_uncertified_field_placeholder_name(item.ident.name.as_str())
        {
            span_lint(
                cx,
                R2DEC_UNCERTIFIED_FIELD_PLACEHOLDER,
                item.span,
                "r2dec must not define fallback aggregate field-name helpers; use certified layout facts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
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
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_branch_condition_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_BRANCH_CONDITION_FALLBACK,
                item.span,
                "certified branch condition extraction must require FunctionFacts control proof before local predicate fallback",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_switch_structure_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_SWITCH_STRUCTURE_FALLBACK,
                item.span,
                "certified switch rendering must prove selector/cases/default through FunctionFacts before emitting switch syntax",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_loop_structure_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOOP_STRUCTURE_FALLBACK,
                item.span,
                "certified loop rendering must prove body/latch/exit structure through FunctionFacts before emitting loop syntax",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_branch_render_proof_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_BRANCH_RENDER_PROOF,
                item.span,
                "r2dec must record branch render proof before emitting certified if statements",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_raw_call_arg_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_RAW_CALL_ARG_FALLBACK,
                item.span,
                "certified r2dec call arguments must refuse local raw arg fallback without FunctionFacts callsite facts",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_prepared_call_arg_expr_proof_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_PREPARED_CALL_ARG_EXPR_PROOF,
                item.span,
                "certified prepared call arguments must prove rendered expressions match certified values",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_executable_post_call_repair_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_EXECUTABLE_POST_CALL_REPAIR,
                item.span,
                "certified executable lowering must not repair post-call values from local renderer state",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_call_render_proof_local_equality_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_RENDER_PROOF_LOCAL_EQUALITY,
                item.span,
                "certified rendered-call proof must not be recovered from local cached call-expression equality",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_direct_zero_arg_call_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_ZERO_ARG_CALL_FALLBACK,
                item.span,
                "r2dec direct SSA call lowering must not emit zero-arg executable fallback calls",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_call_result_replay_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_CALL_RESULT_REPLAY_FALLBACK,
                item.span,
                "certified r2dec call-result replay must try certified synthesized calls before cached fallback",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_return_local_expr_fallback_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_RETURN_LOCAL_EXPR_FALLBACK,
                item.span,
                "certified r2dec returns must derive expressions from prepared return proof before local expression fallback",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_return_call_result_fact_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_RETURN_CALL_RESULT_FACT,
                item.span,
                "certified return-call rendering must require FunctionFacts call-result evidence",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_certified_local_post_call_source_fact_item(cx, item.span)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOCAL_POST_CALL_SOURCE_FACT,
                item.span,
                "certified local post-call source recovery must require FunctionFacts call-result evidence",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && r2dec_decompiler_context_route_side_channel_method(item.ident.name.as_str())
        {
            span_lint(
                cx,
                R2DEC_DECOMPILER_CONTEXT_ROUTE_SIDE_CHANNEL,
                item.span,
                "r2dec DecompilerContext must not expose route/render policy side-channel mutators",
            );
        }

        if is_r2dec_span(cx, item.span)
            && !impl_item_is_test_only(cx, item)
            && item.ident.name.as_str() == "with_callee_resolution"
        {
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

        if is_canonical_ssa_var_classifier(cx, expr) {
            return;
        }

        if reads_display_names(expr)
            && !is_display_name_rendering_span(cx, expr.span)
            && !is_inside_test_item(cx, expr)
            && !is_inside_cfg_test_item_source(cx, expr)
        {
            span_lint(
                cx,
                DISPLAY_NAMES_OUTSIDE_RENDERING,
                expr.span,
                "display spellings are for rendering; classify behaviour from typed evidence instead",
            );
        }

        if (is_r2dec_span(cx, expr.span) || is_r2engine_span(cx, expr.span))
            && !is_inside_test_item(cx, expr)
            && !is_inside_cfg_test_item_source(cx, expr)
            && function_facts_owner_field_assignment_expr(expr)
        {
            span_lint(
                cx,
                R2TYPES_FUNCTION_FACTS_FIELD_OWNERSHIP,
                expr.span,
                "r2engine/r2dec must mutate FunctionFacts through r2types owner methods, not direct field assignment",
            );
        }

        if let ExprKind::MethodCall(method, _receiver, [arg], _) = expr.kind
            && method.ident.as_str() == "starts_with"
            && semantic_prefix_literal(arg)
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

        if is_r2dec_lib_path(cx, expr) && callee_resolution_fallback_ownership_expr(expr) {
            span_lint(
                cx,
                R2DEC_CALLEE_RESOLUTION_FALLBACK_OWNERSHIP,
                expr.span,
                "r2dec must not synthesize CalleeResolutionFacts from raw call targets; pass the r2engine-owned resolution contract",
            );
        }

        if is_r2dec_op_lower_path(cx, expr) && uncertified_call_arg_call_policy_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_UNCERTIFIED_CALL_ARG_CALL_POLICY,
                expr.span,
                "r2dec call arguments must require certified nested-call proof instead of rendered imported/modeled callee policy",
            );
        }

        if is_r2dec_op_lower_path(cx, expr) && call_arg_source_name_authority_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_CALL_ARG_SOURCE_NAME_AUTHORITY,
                expr.span,
                "source_var_name is only a hint; call-argument rendering needs source_value_id or prepared semantic authority",
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

        if is_r2dec_summary_render_path(cx, expr) && summary_route_executable_c_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_SUMMARY_ROUTE_EXECUTABLE_C,
                expr.span,
                "summary route rendering must stay comment/fact-only until native CFG/control/dataflow proof exists",
            );
        }

        if is_r2dec_summary_or_structured_consumer_path(cx, expr)
            && summary_render_executable_cstmt_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_SUMMARY_RENDER_EXECUTABLE_CSTMT,
                expr.span,
                "summary/VM renderers must not construct executable CStmt bodies without CertifiedC permission",
            );
        }

        if is_r2dec_route_render_path(cx, expr) && summary_route_structured_worker_expr(expr) {
            span_lint(
                cx,
                R2DEC_SUMMARY_ROUTE_EXECUTABLE_C,
                expr.span,
                "summary route rendering must not call semantic worker structuring without certified native render permission",
            );
        }

        if is_r2dec_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_route_policy_ownership_expr(expr)
        {
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

        if is_r2engine_path(cx, expr)
            && engine_r2dec_summary_render_route_side_channel_expr(cx, expr)
        {
            span_lint(
                cx,
                R2ENGINE_R2DEC_SUMMARY_RENDER_ROUTE_SIDE_CHANNEL,
                expr.span,
                "r2engine must not pass EngineSemanticRoutePlan/SemanticRoutePlan as a r2dec summary render side channel",
            );
        }

        if is_r2engine_lib_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && engine_summary_only_decompile_api_expr(cx, expr)
        {
            span_lint(
                cx,
                R2ENGINE_SUMMARY_ONLY_DECOMPILE_API,
                expr.span,
                "summary-only decompile APIs must not be used as a production r2engine decompile path without prepared SSA",
            );
        }

        if is_r2dec_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_switch_case_value_ownership_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_SWITCH_CASE_VALUE_OWNERSHIP,
                expr.span,
                "r2dec must not rewrite switch case values from display bias; render canonical case facts",
            );
        }

        if is_r2dec_op_lower_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_call_result_stack_owner_fallback_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CALL_RESULT_STACK_OWNER_FALLBACK,
                expr.span,
                "r2dec must consume prepared call-result ownership instead of deriving stack-local owners in op-lowering",
            );
        }

        if is_r2dec_op_lower_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_call_result_source_expr_owner_fallback_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CALL_RESULT_SOURCE_EXPR_OWNER_FALLBACK,
                expr.span,
                "r2dec must consume prepared call-result ownership instead of matching rendered call expressions",
            );
        }

        if is_r2dec_analysis_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_direct_prepared_call_result_certificates_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CALL_RESULT_CERTIFICATES,
                expr.span,
                "r2dec analysis must read call-result proof from FunctionFacts, not prepared SSA certificate maps",
            );
        }

        if is_r2dec_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_direct_prepared_control_facts_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_DIRECT_PREPARED_CONTROL_FACTS,
                expr.span,
                "r2dec must read branch/switch proof from FunctionFacts, not prepared SSA predicate maps or local selector inference",
            );
        }

        if is_r2engine_path(cx, expr) && engine_r2dec_variable_recovery_ownership_expr(cx, expr) {
            span_lint(
                cx,
                R2ENGINE_R2DEC_VARIABLE_RECOVERY_OWNERSHIP,
                expr.span,
                "r2engine must use r2types-owned signature parameter recovery instead of r2dec::VariableRecovery",
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

        if is_r2dec_path(cx, expr) && r2dec_default_true_branch_condition_expr(cx, expr) {
            span_lint(
                cx,
                R2DEC_DEFAULT_TRUE_BRANCH_CONDITION,
                expr.span,
                "r2dec must residualize unresolved branch predicates instead of rendering if (1)",
            );
        }

        if is_r2dec_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_uncertified_stack_local_synthesis_expr(expr)
        {
            span_lint(
                cx,
                R2DEC_UNCERTIFIED_STACK_LOCAL_SYNTHESIS,
                expr.span,
                "r2dec must require typed stack-slot proof before synthesizing stack locals",
            );
        }

        if is_r2dec_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_certified_stack_owner_proof_recomposition_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_STACK_OWNER_PROOF_RECOMPOSITION,
                expr.span,
                "certified r2dec stack owner helpers must call a FunctionFacts-owned predicate instead of recomposing proof from render facts or stack alias/provenance helpers",
            );
        }

        if is_r2dec_op_lower_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_direct_stable_stack_values_get_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOCAL_STACK_RECOVERY_BYPASS,
                expr.span,
                "r2dec op-lowering must read stable stack values through the certified-aware accessor",
            );
        }

        if is_r2dec_analysis_path(cx, expr)
            && !is_inside_test_item(cx, expr)
            && r2dec_unguarded_local_store_owner_expr(cx, expr)
        {
            span_lint(
                cx,
                R2DEC_CERTIFIED_LOCAL_STACK_RECOVERY_BYPASS,
                expr.span,
                "r2dec prepared local-store recovery must be guarded out of certified rendering",
            );
        }

        if is_r2types_non_role_registry_path(cx, expr)
            && r2types_role_name_signature_hint_expr(expr)
        {
            span_lint(
                cx,
                R2TYPES_ROLE_NAME_SIGNATURE_HINT_OWNERSHIP,
                expr.span,
                "r2types must project role signatures through evidence-backed role identity",
            );
        }

        if forbidden_r2_json_command_literal(expr) {
            span_lint(
                cx,
                R2_JSON_COMMAND_INTERNAL_SEAM,
                expr.span,
                "internal analysis must use typed radare2 collector APIs instead of JSON command strings",
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

fn forbidden_r2_json_command_literal(expr: &Expr<'_>) -> bool {
    let ExprKind::Lit(lit) = expr.kind else {
        return false;
    };
    let LitKind::Str(symbol, _) = lit.node else {
        return false;
    };
    let text = symbol.as_str();
    let command = text.split_whitespace().next().unwrap_or(text.as_ref());
    matches!(command, "afcfj" | "afvj" | "tsj")
}

fn function_facts_owner_field_assignment_expr(expr: &Expr<'_>) -> bool {
    let ExprKind::Assign(lhs, _, _) = expr.kind else {
        return false;
    };
    let ExprKind::Field(base, ident) = lhs.kind else {
        return false;
    };
    if !matches!(
        ident.name.as_str(),
        "types"
            | "summary_view"
            | "assumption_usage"
            | "proof"
            | "decompile_route"
            | "semantics"
            | "render"
            | "control"
    ) {
        return false;
    }
    field_base_mentions_function_facts(base)
}

fn field_base_mentions_function_facts(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Path(QPath::Resolved(_, path)) => path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.name.as_str() == "function_facts"),
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "function_facts" || field_base_mentions_function_facts(base)
        }
        _ => false,
    }
}

fn engine_r2dec_variable_recovery_ownership_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::Call(callee, _) = expr.kind else {
        return false;
    };
    if !expr_path_last_segment_is(callee, "new")
        && !expr_path_last_segment_is(callee, "new_with_abi")
    {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(callee.span)
        .is_ok_and(|snippet| snippet.contains("VariableRecovery::new"))
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

fn r2dec_build_function_requires_route_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            if snippet.contains("pub fn build_function(&self, func: &SSAFunction) -> CFunction") {
                return true;
            }
            snippet.contains(
                "pub fn build_function_from_input(&self, input: &DecompilerInput) -> CFunction",
            ) && (!snippet.contains("let Some(semantic_route)")
                || !snippet.contains("function_facts.decompile_route()")
                || !snippet.contains("route_is_summary_boundary"))
        })
}

fn r2dec_summary_render_route_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            let signature = snippet
                .split_once('{')
                .map_or(snippet.as_str(), |(sig, _)| sig);
            if snippet.contains("pub fn render_semantic_worker_summary(") {
                return signature.contains("SemanticRoutePlan")
                    || signature.contains("FunctionFacts")
                    || signature.contains("FunctionTypeFacts")
                    || signature.contains("SemanticArtifactReport")
                    || !signature.contains("DecompilerInput")
                    || !snippet.contains("input.function_facts()")
                    || !snippet.contains("decompile_route()")
                    || !snippet.contains("route_is_summary_boundary");
            }
            if snippet.contains("pub fn render_vm_semantic_summary(") {
                return signature.contains("FunctionFacts")
                    || signature.contains("FunctionTypeFacts")
                    || signature.contains("SemanticArtifactReport")
                    || !signature.contains("DecompilerInput")
                    || !snippet.contains("input.function_facts()")
                    || !snippet.contains("decompile_route()")
                    || !snippet.contains("DecompileRouteKind::VmSummary");
            }
            false
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

fn r2dec_local_header_arity_repair_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            (snippet.contains("fn merge_params_with_external_signature(")
                && snippet.contains("recovered_params.len().max(signature.params.len())"))
                || (snippet.contains("certified_standard_mode")
                    && snippet.contains("ret_type:")
                    && snippet.contains("inferred_ret_type.clone()"))
        })
}

fn r2dec_local_authoritative_call_arg_inference_item(
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
            snippet.contains("fn infer_call_authoritative_arg")
                || snippet.contains("fn infer_stack_call_authoritative_args")
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

fn r2dec_switch_case_value_ownership_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            [
                "fn estimate_switch_case_bias",
                "fn switch_case_display_bias",
                "fn guarded_dense_zero_based_switch_bias",
                "fn filter_switch_case_outliers",
            ]
            .iter()
            .any(|needle| snippet.contains(needle))
        })
}

fn r2dec_switch_case_value_ownership_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::MethodCall(method, _, _, _) => {
            let method = method.ident.as_str();
            matches!(
                method,
                "estimate_switch_case_bias"
                    | "switch_case_display_bias"
                    | "guarded_dense_zero_based_switch_bias"
                    | "filter_switch_case_outliers"
            ) || (method == "saturating_add_signed"
                && enclosing_item_snippet_contains(cx, expr, "switch"))
        }
        ExprKind::Call(callee, _) => [
            "estimate_switch_case_bias",
            "switch_case_display_bias",
            "guarded_dense_zero_based_switch_bias",
            "filter_switch_case_outliers",
        ]
        .iter()
        .any(|name| expr_path_last_segment_is(callee, name)),
        _ => false,
    }
}

fn r2dec_switch_selector_single_fact_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            snippet.contains("fn resolve_switch_expr_for_block_with_selector(")
                || snippet.contains("fn resolve_switch_expr_from_control_facts(")
        })
        && cx
            .sess()
            .source_map()
            .span_to_snippet(span)
            .is_ok_and(|snippet| {
                snippet.contains("switches.len() == 1")
                    || snippet.contains("switch_selector_expr_by_block.len() == 1")
            })
}

fn r2dec_certified_prepared_switch_selector_proof_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn resolve_switch_expr_for_block_with_selector(")
        || !snippet.contains("switch_selector_expr_for_block")
        || !snippet.contains("requires_certified_rendering")
    {
        return false;
    }
    let Some(prepared_selector_at) = snippet.find("switch_selector_expr_for_block") else {
        return false;
    };
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > prepared_selector_at)
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

fn r2dec_certified_call_arg_prefix_proof_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn certified_standard_output_residual_reason_with_effect_proofs")
                && snippet.contains("argument_values")
                && snippet.contains(".take(proof.values.len())")
        })
}

fn r2dec_direct_prepared_render_certificates_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn certified_standard_output_residual_reason_with_effect_proofs")
                && (snippet.contains("prepared.certificates()")
                    || snippet.contains("memory_certificate_for_op_site")
                    || snippet.contains("return_certificate_for_op")
                    || snippet.contains("callsite_certificate_for_op")
                    || snippet.contains("certificates.expressions")
                    || snippet.contains("certificates.stack_slots")
                    || snippet.contains("certificates.memory_accesses")
                    || snippet.contains("certificates.returns")
                    || snippet.contains("certificates.callsites"))
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

fn r2dec_call_result_stack_owner_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            snippet.contains("fn fallback_owned_call_result_stack_local_name_for_source")
                || snippet.contains("fallback_stack_local")
                || (snippet.contains("fn derive_stable_owned_call_result_name_for_alias")
                    && (snippet.contains("semantic_stack_owner_name_for_alias")
                        || snippet.contains("resolve_stack_var(")))
                || (snippet.contains("fn stable_owned_call_result_expr_for_name")
                    && (snippet.contains("semantic_stack_owner_name_for_alias")
                        || snippet.contains(".forwarded_value_for_name("))
                    && !snippet.contains("call_result_alias_has_stack_owner_provenance"))
        })
}

fn r2dec_uncertified_switch_selector_root_fallback_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    if !snippet.contains("fn resolve_switch_expr_for_block_with_selector(")
        || !snippet.contains("switch_selector_roots_map")
    {
        return false;
    }
    let Some(root_fallback_at) = snippet.find("switch_selector_roots_map") else {
        return false;
    };
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > root_fallback_at)
}

fn r2dec_call_result_stack_owner_fallback_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => expr_path_last_segment_is(
            callee,
            "fallback_owned_call_result_stack_local_name_for_source",
        ),
        ExprKind::MethodCall(method, _, _, _) => {
            let method = method.ident.as_str();
            method == "fallback_owned_call_result_stack_local_name_for_source"
                || (method == "semantic_stack_owner_name_for_alias"
                    && enclosing_item_snippet_contains(
                        cx,
                        expr,
                        "derive_stable_owned_call_result_name_for_alias",
                    ))
        }
        _ => false,
    }
}

fn r2dec_call_result_source_expr_owner_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(span)
        .is_ok_and(|snippet| {
            [
                "fn fallback_owned_call_result_register_name_from_matching_source_call",
                "fn fallback_owned_call_result_register_name_from_matching_definition",
            ]
            .iter()
            .any(|needle| snippet.contains(needle))
                || (snippet.contains("raw_call_exprs_match_for_source_owner_definition")
                    && [
                        "stable_owned_call_result_name_for_source",
                        "should_materialize_call_result_at_source",
                        "materializable_call_result_expr_for_call_expr",
                    ]
                    .iter()
                    .any(|needle| snippet.contains(needle)))
        })
}

fn r2dec_certified_call_result_return_register_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn fallback_owned_call_result_return_name_for_source")
        || !snippet.contains("fallback_owned_call_result_return_name_for_alias")
        || !snippet.contains("direct_call_result_aliases_set")
    {
        return false;
    }
    let fallback_at = snippet
        .find("source_call_allows_return_register_owner")
        .or_else(|| snippet.find("direct_call_result_aliases_set"))
        .unwrap_or(0);
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > fallback_at)
}

fn r2dec_certified_call_result_alias_owner_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn derive_stable_owned_call_result_name_for_source")
        || !snippet.contains("fallback_owned_call_result_register_name_for_alias")
        || !snippet.contains("direct_call_result_aliases_set")
    {
        return false;
    }
    let fallback_at = snippet
        .find("direct_call_result_aliases_set")
        .or_else(|| snippet.find("fallback_owned_call_result_register_name_for_alias"))
        .unwrap_or(0);
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > fallback_at)
}

fn r2dec_certified_local_call_ownership_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if snippet.contains("fn stable_owned_call_result_name_for_source") {
        let Some(local_owner_at) = snippet.find("ownership_for_source") else {
            return false;
        };
        return snippet
            .find("requires_certified_rendering")
            .is_none_or(|guard_at| guard_at > local_owner_at);
    }
    if snippet.contains("fn source_call_for_visible_owner_name") {
        let Some(local_owner_at) = snippet.find("source_for_visible_owner_name") else {
            return false;
        };
        return snippet
            .find("requires_certified_rendering")
            .is_none_or(|guard_at| guard_at > local_owner_at);
    }
    if snippet.contains("fn call_result_source_for_ssa_name")
        && (snippet.contains("source_for_alias")
            || snippet.contains("call_result_source_for_name")
            || snippet.contains("prepared_semantic_view"))
    {
        let local_at = snippet
            .find("source_for_alias")
            .or_else(|| snippet.find("call_result_source_for_name"))
            .or_else(|| snippet.find("prepared_semantic_view"))
            .unwrap_or(usize::MAX);
        let Some(certified_at) = snippet.find("if self.requires_certified_rendering()") else {
            return true;
        };
        return certified_at > local_at
            || !snippet[..local_at].contains("certified_call_result_source_for_ssa_name");
    }
    false
}

fn r2dec_certified_call_result_preservation_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn should_preserve_owned_call_result_visible_name")
        || !snippet.contains("has_visible_owner_name")
    {
        return false;
    }
    let Some(fallback_at) = snippet.find("has_visible_owner_name") else {
        return false;
    };
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > fallback_at)
}

fn r2dec_certified_duplicate_call_pruning_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if (snippet.contains("fn prune_duplicate_tail_call_statements")
        || snippet.contains("fn prune_duplicate_call_statements_by_source"))
        && snippet.contains("collect_rendered_call_sources_for_expr")
    {
        return true;
    }
    snippet.contains("fn collect_duplicate_pruning_call_sources_for_expr")
        && !snippet.contains("collect_certified_rendered_call_sources_for_expr")
}

fn r2dec_certified_visible_owner_source_lookup_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn source_call_for_visible_owner_name")
        && snippet.contains("prepared_source_call_for_visible_owner_name")
        && !snippet.contains("stable_owned_call_result_name_for_source")
}

fn r2dec_certified_prepared_result_owner_expr_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn stable_owned_call_result_expr_for_source")
        || !snippet.contains("result_owner.clone()")
    {
        return false;
    }
    let Some(prepared_expr_at) = snippet.find("result_owner.clone()") else {
        return false;
    };
    let certified_name_at = snippet
        .find("if self.requires_certified_rendering()")
        .filter(|guard_at| *guard_at < prepared_expr_at)
        .and_then(|guard_at| {
            snippet[guard_at..prepared_expr_at]
                .contains("prepared_result_owner_name_for_source")
                .then_some(guard_at)
        });
    certified_name_at.is_none()
}

fn r2dec_certified_prepared_result_owner_fact_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn stable_owned_call_result_name_for_source")
        && !snippet.contains("fn stable_owned_call_result_expr_for_source")
    {
        return false;
    }
    snippet.contains("prepared_result_owner_name_for_source")
        && !snippet.contains("has_certified_call_result_owner_fact_for_source")
}

fn r2dec_certified_stack_return_render_facts_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn certified_unique_scalar_stack_return_expr")
        && snippet.contains("return_stack_slots")
        && !snippet.contains("render_facts")
}

fn r2dec_certified_stack_local_identity_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    (snippet.contains("fn certified_standard_output_residual_reason_with_effect_proofs")
        && snippet.contains("has_stack_slot_offset(offset)")
        && !snippet.contains("certified_stack_local_identity_is_exact"))
        || (snippet.contains("fn build_function")
            && snippet.contains("body_visible_stack_offsets")
            && !snippet.contains("certified_recovered_stack_local_is_exact"))
        || (snippet.contains("fn stack_offset_for_visible_storage_name")
            && (snippet.contains("strip_prefix(\"local_\")")
                || snippet.contains("strip_prefix(\"arg_\")"))
            && !snippet.contains("certified_stack_offset_for_visible_storage_name"))
        || (snippet.contains("fn stack_offsets_for_visible_storage_name")
            && snippet.contains("canonical_stack_offset_for_visible_storage_name")
            && !snippet.contains("requires_certified_rendering()"))
        || (snippet.contains("fn stack_slot_provenance_for_name")
            && snippet.contains("render_stack_slot_for_name")
            && !snippet.contains("certified_stack_offset_for_visible_storage_name"))
        || (snippet.contains("fn stack_slot_provenance_for_var")
            && snippet.contains("render_stack_slot_for_name"))
}

fn r2dec_certified_stack_local_type_ownership_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    (snippet.contains("fn build_function")
        && snippet.contains("certified_standard_mode")
        && snippet.contains("choose_more_specific_runtime_type")
        && !snippet.contains("typed_stack_local_type_for_name_offset"))
        || (snippet.contains("fn certified_standard_output_residual_reason_with_effect_proofs")
            && snippet.contains("local.ty")
            && !snippet.contains("certified_stack_local_type_matches"))
}

fn r2dec_certified_local_type_hints_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("certified_standard_mode")
        && snippet.contains("FoldInputs")
        && (snippet.contains("type_hints: &type_hints") || snippet.contains("type_oracle,"))
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

fn r2dec_certified_branch_render_proof_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn structure_region")
        && snippet.contains("Region::IfThenElse")
        && snippet.contains("CStmt::if_stmt")
        && !snippet.contains("record_branch_render_proof")
}

fn r2dec_certified_branch_condition_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if snippet.contains("fn extract_condition_from_block") {
        let local_at = snippet
            .find("local_branch_condition_expr")
            .or_else(|| snippet.find("symbolic_actionable_compiled_condition_expr"))
            .or_else(|| snippet.find("symbolic_branch_condition_expr"));
        let Some(local_at) = local_at else {
            return false;
        };
        return snippet
            .find("requires_certified_rendering")
            .is_none_or(|guard_at| guard_at > local_at);
    }
    if snippet.contains("fn get_branch_condition_with_predicate")
        && snippet.contains("extract_condition(op)")
    {
        let Some(fallback_at) = snippet.find("extract_condition(op)") else {
            return false;
        };
        return snippet
            .find("requires_certified_rendering")
            .is_none_or(|guard_at| guard_at > fallback_at);
    }
    false
}

fn r2dec_certified_loop_structure_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn structure_region")
        && (snippet.contains("Region::WhileLoop") || snippet.contains("Region::DoWhileLoop"))
        && (snippet.contains("CStmt::while_loop") || snippet.contains("CStmt::DoWhile"))
        && !snippet.contains("certified_loop_render_proof")
}

fn r2dec_certified_switch_structure_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn structure_switch_region")
        && snippet.contains("CStmt::Switch")
        && !snippet.contains("certified_switch_render_proof")
}

fn r2dec_certified_raw_call_arg_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn certified_call_args_for_site_with_direct_target")
        || !snippet.contains("let args = self.render_call_args_for_site_with_direct_target")
    {
        return false;
    }
    if !snippet.contains("raw_call_args_match_function_facts")
        || !snippet.contains("canonical_argument_values")
    {
        return true;
    }
    false
}

fn r2dec_certified_prepared_call_arg_expr_proof_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn certified_call_args_for_site_with_direct_target")
        && snippet.contains("prepared_call_args_for_site_with_direct_target")
}

fn r2dec_certified_executable_post_call_repair_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn op_to_stmt_impl") || !snippet.contains("requires_certified_rendering")
    {
        return false;
    }
    [
        "local_post_call_source_for_ssa_name",
        "raw_local_post_call_source_for_ssa_name_in_block",
        "recovered_owned_call_result_definition_rhs",
        "recovered_owned_call_result_definition_rhs_for_visible_name",
        "call_result_exprs_map()",
        "call_result_aliases_map()",
        "lookup_definition_raw",
        "direct_definition_expr",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
}

fn r2dec_certified_call_render_proof_local_equality_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if ![
        "fn certified_source_for_rendered_call_expr",
        "fn source_proof_for_call_expr",
        "fn source_matches_for_call_expr",
        "fn collect_certified_rendered_call_sources_for_expr",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
    {
        return false;
    }
    [
        "source_proof_for_call_expr",
        "source_matches_for_call_expr",
        "call_result_exprs_map",
        "raw_call_exprs_match_for_source_owner_definition",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
}

fn r2dec_direct_zero_arg_call_fallback_item(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn op_to_stmt_impl")
        || !snippet.contains("SSAOp::Call")
        || !snippet.contains("CExpr::call(func_expr, vec![])")
    {
        return false;
    }
    let fallback_at = snippet.find("CExpr::call(func_expr, vec![])").unwrap_or(0);
    snippet
        .find("requires_certified_rendering")
        .is_none_or(|guard_at| guard_at > fallback_at)
}

fn r2dec_certified_call_result_replay_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if ![
        "fn recovered_owned_call_result_definition_rhs_for_visible_name",
        "fn recovered_owned_call_result_definition_rhs",
        "fn op_to_stmt_impl",
    ]
    .iter()
    .any(|needle| snippet.contains(needle))
        || !snippet.contains("call_result_exprs_map")
        || !snippet.contains("synthesized_call_expr_for_source_call(source_call)")
    {
        return false;
    }

    let mut search_from = 0;
    while let Some(relative_at) = snippet[search_from..].find("call_result_exprs_map") {
        let cached_at = search_from + relative_at;
        let window_start = cached_at.saturating_sub(900);
        let before_cached = &snippet[window_start..cached_at];
        if !before_cached.contains("if self.requires_certified_rendering()")
            || !before_cached.contains("synthesized_call_expr_for_source_call(source_call)")
        {
            return true;
        }
        search_from = cached_at + "call_result_exprs_map".len();
    }
    false
}

fn r2dec_certified_return_local_expr_fallback_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn fold_block")
        || !snippet.contains("certified_return_expr_for_op")
        || !snippet.contains("best_visible_definition(&target.display_name())")
    {
        return false;
    }

    let local_definition_at = snippet
        .find("best_visible_definition(&target.display_name())")
        .unwrap_or(usize::MAX);
    let local_semantic_at = snippet
        .find("render_semantic_value_by_name(\n                                &target.display_name()")
        .or_else(|| snippet.find("render_semantic_value_by_name(&target.display_name()"))
        .unwrap_or(usize::MAX);
    let local_at = local_definition_at.min(local_semantic_at);
    let Some(proof_at) = snippet.find("certified_return_expr_for_op(block.addr, return_op_idx)")
    else {
        return true;
    };

    proof_at > local_at
}

fn r2dec_certified_return_call_result_fact_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    snippet.contains("fn certified_return_expr_for_value")
        && snippet.contains("call_result_certificate_for_value")
        && !snippet.contains("certified_call_result_fact_for_value")
}

fn r2dec_certified_local_post_call_source_fact_item(
    cx: &LateContext<'_>,
    span: rustc_span::Span,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    if !snippet.contains("fn local_post_call_source_for_ssa_name_in_block")
        || !snippet.contains("raw_local_post_call_source_for_ssa_name_in_block")
    {
        return false;
    }
    let Some(certified_at) = snippet.find("if self.requires_certified_rendering()") else {
        return true;
    };
    let raw_at = snippet
        .find("raw_local_post_call_source_for_ssa_name_in_block")
        .unwrap_or(usize::MAX);
    if certified_at > raw_at {
        return true;
    }
    let certified_block = &snippet[certified_at..raw_at.min(snippet.len())];
    !certified_block.contains("return None;")
}

fn r2dec_call_result_source_expr_owner_fallback_expr(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
) -> bool {
    match expr.kind {
        ExprKind::Call(callee, _) => [
            "fallback_owned_call_result_register_name_from_matching_source_call",
            "fallback_owned_call_result_register_name_from_matching_definition",
        ]
        .iter()
        .any(|name| expr_path_last_segment_is(callee, name)),
        ExprKind::MethodCall(method, _, _, _) => {
            let method = method.ident.as_str();
            matches!(
                method,
                "fallback_owned_call_result_register_name_from_matching_source_call"
                    | "fallback_owned_call_result_register_name_from_matching_definition"
            ) || (method == "raw_call_exprs_match_for_source_owner_definition"
                && enclosing_item_name(cx, expr)
                    .as_deref()
                    .is_some_and(is_call_result_source_expr_owner_boundary_name))
        }
        _ => false,
    }
}

fn is_call_result_source_expr_owner_boundary_name(name: &str) -> bool {
    matches!(
        name,
        "stable_owned_call_result_name_for_source"
            | "should_materialize_call_result_at_source"
            | "materializable_call_result_expr_for_call_expr"
            | "fallback_owned_call_result_register_name_from_matching_source_call"
            | "fallback_owned_call_result_register_name_from_matching_definition"
    )
}

fn r2dec_uncertified_field_placeholder_name(name: &str) -> bool {
    matches!(
        name,
        "fallback_aggregate_field_name" | "typedef_name_looks_aggregate"
    )
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

fn engine_artifacts_facts_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("struct EngineArtifacts")
                && (snippet.contains("semantic_artifact") || snippet.contains("route:"))
        })
}

fn engine_whole_analysis_cache_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            [
                "mod cache;",
                "struct SessionCache",
                "struct AnalysisCache",
                "struct EngineSessionCacheMetrics",
                "enum CacheDecision",
                "enum AnalysisReuse",
                "fn cached_artifacts",
                "fn cached_artifacts_with_decision",
                "fn insert_artifacts",
                "fn cache_plan",
                "fn cache_profile",
            ]
            .iter()
            .any(|needle| snippet.contains(needle))
        })
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

fn engine_r2dec_summary_render_route_side_channel_expr(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
) -> bool {
    let ExprKind::Call(callee, args) = expr.kind else {
        return false;
    };
    let expected_arity = if expr_path_last_segment_is(callee, "render_semantic_worker_summary") {
        3
    } else if expr_path_last_segment_is(callee, "render_vm_semantic_summary") {
        2
    } else {
        return false;
    };
    args.len() > expected_arity
        || args.iter().any(|arg| {
            cx.sess()
                .source_map()
                .span_to_snippet(arg.span)
                .is_ok_and(|snippet| {
                    snippet.contains("EngineSemanticRoutePlan")
                        || snippet.contains("SemanticRoutePlan")
                        || snippet.contains("to_decompiler_route(")
                })
        })
}

fn engine_r2dec_route_conversion_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn to_decompiler_route(")
                || snippet.contains("pub enum EngineSemanticRoutePlan")
                || snippet.contains("struct EngineSemanticRoutePlan")
                || snippet.contains("fn decompile_route_facts_from_decision(")
                || snippet.contains("fn decompile_route_from_facts(")
                || snippet.contains("r2dec::SemanticRoutePlan")
        })
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

fn engine_summary_decompile_route_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    if snippet.contains("fn summary_decompile_function_facts_with_route(") {
        return false;
    }
    (snippet.contains("struct EngineSummaryDecompileRequest")
        && (snippet.contains("named_worker_guarded:")
            || snippet.contains("fallback_comment: Option")))
        || (snippet.contains("fn render_engine_summary_decompile_request")
            && snippet.contains("request.fallback_comment"))
        || (snippet.contains("fn decompile_summary")
            && snippet.contains("named_worker_summary_route(request.named_worker_guarded"))
}

fn engine_summary_only_decompile_api_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            let header = snippet
                .split_once('{')
                .map_or(snippet.as_str(), |(head, _)| head);
            header.contains("EngineSummaryDecompileRequest")
                || header.contains("fn decompile_summary(")
                || header.contains("fn decompile_summary_preprobe(")
        })
}

fn engine_summary_only_decompile_api_impl_item(cx: &LateContext<'_>, item: &ImplItem<'_>) -> bool {
    if engine_summary_only_decompile_api_name(item.ident.name.as_str()) {
        return true;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| snippet.contains("EngineSummaryDecompileRequest"))
}

fn engine_summary_only_decompile_api_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::MethodCall(method, ..) => {
            engine_summary_only_decompile_api_name(method.ident.as_str())
        }
        ExprKind::Call(callee, _) => {
            expr_path_last_segment_is(callee, "decompile_summary")
                || expr_path_last_segment_is(callee, "decompile_summary_preprobe")
                || cx
                    .sess()
                    .source_map()
                    .span_to_snippet(callee.span)
                    .is_ok_and(|snippet| snippet.contains("EngineSummaryDecompileRequest::"))
        }
        ExprKind::Struct(qpath, ..) => {
            qpath_last_segment_is(qpath, "EngineSummaryDecompileRequest")
        }
        ExprKind::Path(ref qpath) => qpath_last_segment_is(qpath, "EngineSummaryDecompileRequest"),
        _ => false,
    }
}

fn engine_summary_only_decompile_api_name(name: &str) -> bool {
    matches!(
        name,
        "EngineSummaryDecompileRequest" | "decompile_summary" | "decompile_summary_preprobe"
    )
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

fn engine_render_time_semantics_suppression_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    (snippet.contains("fn render_engine_decompile_request")
        && (snippet.contains("set_semantics(None)")
            || snippet.contains("suppress_unrenderable_summary")))
        || snippet.contains("fn should_suppress_unrenderable_standard_summary_artifact")
}

fn engine_decompile_type_override_side_channel_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    snippet.contains("fn decompile_function")
        && (snippet.contains(".function_facts.types.merged_signature")
            || snippet.contains(".function_facts.types.signature_certificate"))
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

fn engine_decompiler_input_requires_source_owner_item(
    cx: &LateContext<'_>,
    item: &Item<'_>,
) -> bool {
    let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
        return false;
    };
    snippet.contains("fn decompiler_input_from_prepared_facts")
        || snippet.contains(".stamp_decompile_route(")
        || snippet.contains(".into_source_owned_facts(")
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

fn r2dec_local_signature_enrichment_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains("fn from_function_facts")
                && snippet.contains("enrich_known_function_signatures_from_names")
        })
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

fn r2dec_source_shaped_decompile_oracle_item(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if !matches!(item.kind, rustc_hir::ItemKind::Fn { .. }) {
        return false;
    }
    if !item_is_inside_test_context(cx, item) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| {
            snippet.contains(".decompile(&func)")
                && source_shaped_positive_contains_oracle_snippet(&snippet)
        })
}

fn item_is_inside_test_context(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    if cx
        .sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| snippet.contains("#[test]") || snippet.contains("mod tests"))
    {
        return true;
    }

    for (_, node) in cx.tcx.hir_parent_iter(item.hir_id()) {
        if let rustc_hir::Node::Item(parent) = node
            && cx
                .sess()
                .source_map()
                .span_to_snippet(parent.span)
                .is_ok_and(|snippet| snippet.contains("mod tests"))
        {
            return true;
        }
    }
    false
}

fn source_shaped_positive_contains_oracle_snippet(snippet: &str) -> bool {
    const SHAPES: [&str; 6] = ["return ", "if (", "for (", "while (", "switch (", "case "];
    for line in snippet.lines() {
        if !line.contains(".contains(\"") || !SHAPES.iter().any(|shape| line.contains(shape)) {
            continue;
        }
        for (contains_idx, _) in line.match_indices(".contains(\"") {
            if !contains_call_is_negated_in_line(line, contains_idx) {
                return true;
            }
        }
    }
    false
}

fn contains_call_is_negated_in_line(line: &str, contains_idx: usize) -> bool {
    let prefix = &line[..contains_idx];
    prefix
        .rsplit(['&', '|', '('])
        .next()
        .is_some_and(|segment| segment.contains('!'))
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

fn r2dec_uncertified_stack_local_synthesis_expr(expr: &Expr<'_>) -> bool {
    matches!(
        expr.kind,
        ExprKind::MethodCall(method, _, _, _)
            if matches!(method.ident.as_str(), "has_definitions" | "has_stack_slots")
    )
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

fn r2dec_direct_stable_stack_values_get_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::MethodCall(method, receiver, _, _) = expr.kind else {
        return false;
    };
    method.ident.as_str() == "get"
        && expr_references_stable_stack_values(receiver)
        && !enclosing_item_name(cx, expr)
            .as_deref()
            .is_some_and(|name| name == "stable_stack_value_for_offset")
}

fn r2dec_unguarded_local_store_owner_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let ExprKind::Call(callee, _) = expr.kind else {
        return false;
    };
    if !expr_path_last_segment_is(callee, "local_store_owner_expr_for_offset") {
        return false;
    }
    !enclosing_item_snippet_contains(cx, expr, "certified_rendering_required")
        && !enclosing_item_snippet_contains(cx, expr, "requires_certified_rendering()")
        && !enclosing_item_snippet_contains(cx, expr, "prepared-only")
        && !enclosing_item_snippet_contains(cx, expr, "prepared only")
}

fn expr_references_stable_stack_values(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "stable_stack_values"
                || expr_references_stable_stack_values(base)
        }
        ExprKind::MethodCall(_, receiver, args, _) => {
            expr_references_stable_stack_values(receiver)
                || args.iter().any(expr_references_stable_stack_values)
        }
        ExprKind::Call(callee, args) => {
            expr_references_stable_stack_values(callee)
                || args.iter().any(expr_references_stable_stack_values)
        }
        ExprKind::AddrOf(_, _, inner)
        | ExprKind::Unary(_, inner)
        | ExprKind::Cast(inner, _)
        | ExprKind::DropTemps(inner) => expr_references_stable_stack_values(inner),
        _ => false,
    }
}

fn r2types_role_name_signature_hint_expr(expr: &Expr<'_>) -> bool {
    matches!(
        expr.kind,
        ExprKind::Call(callee, _)
            if expr_path_last_segment_is(callee, "signature_hint_for_name_candidates")
                || expr_path_last_segment_is(callee, "signature_hint_for_role_name")
                || expr_path_last_segment_is(callee, "type_projection_for_name_candidates")
    )
}

fn item_is_test_only(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| snippet.contains("#[cfg(test)]") || snippet.contains("#[test]"))
        || item_has_leading_test_attr(cx, item)
}

fn impl_item_is_test_only(cx: &LateContext<'_>, item: &ImplItem<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(item.span)
        .is_ok_and(|snippet| snippet.contains("#[cfg(test)]") || snippet.contains("#[test]"))
        || impl_item_has_leading_cfg_test(cx, item)
}

fn is_inside_test_item(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        if let rustc_hir::Node::Item(item) = node
            && cx
                .sess()
                .source_map()
                .span_to_snippet(item.span)
                .is_ok_and(|snippet| snippet.contains("mod tests") || snippet.contains("#[test]"))
        {
            return true;
        }
    }
    false
}

fn is_inside_cfg_test_item_source(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        if let rustc_hir::Node::Item(item) = node
            && item_has_leading_cfg_test(cx, item)
        {
            return true;
        }
    }
    false
}

fn item_has_leading_test_attr(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    let source_map = cx.sess().source_map();
    let loc = source_map.lookup_char_pos(item.span.lo());
    let path = loc
        .file
        .name
        .prefer_local_unconditionally()
        .to_string_lossy()
        .into_owned();
    let Ok(source) = std::fs::read_to_string(path) else {
        return false;
    };
    let line = loc.line;
    let start = line.saturating_sub(4).max(1);
    source
        .lines()
        .skip(start - 1)
        .take(line - start + 1)
        .any(|line| line.contains("#[cfg(test)]") || line.contains("#[test]"))
}

fn item_has_leading_cfg_test(cx: &LateContext<'_>, item: &Item<'_>) -> bool {
    item_has_leading_test_attr(cx, item)
}

fn impl_item_has_leading_cfg_test(cx: &LateContext<'_>, item: &ImplItem<'_>) -> bool {
    let source_map = cx.sess().source_map();
    let loc = source_map.lookup_char_pos(item.span.lo());
    let path = loc
        .file
        .name
        .prefer_local_unconditionally()
        .to_string_lossy()
        .into_owned();
    let Ok(source) = std::fs::read_to_string(path) else {
        return false;
    };
    let line = loc.line;
    let start = line.saturating_sub(4).max(1);
    source
        .lines()
        .skip(start - 1)
        .take(line - start + 1)
        .any(|line| line.contains("#[cfg(test)]"))
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

fn expr_is_none_path(expr: &Expr<'_>) -> bool {
    matches!(expr.kind, ExprKind::Path(ref qpath) if qpath_last_segment_is(qpath, "None"))
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

fn uncertified_call_arg_call_policy_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if !enclosing_item_name(cx, expr)
        .as_deref()
        .is_some_and(is_call_arg_render_boundary_name)
    {
        return false;
    }

    match expr.kind {
        ExprKind::MethodCall(method, _, args, _) => match method.ident.as_str() {
            "is_imported_call_target" | "is_modeled_call_target" => true,
            "imported_or_modeled_call_target_for_optional_site" => {
                args.is_empty() || args.iter().any(expr_is_none_path)
            }
            _ => false,
        },
        ExprKind::Call(callee, _) => ["is_imported_call_target", "is_modeled_call_target"]
            .iter()
            .any(|name| expr_path_last_segment_is(callee, name)),
        _ => false,
    }
}

fn is_call_arg_render_boundary_name(name: &str) -> bool {
    matches!(
        name,
        "call_arg_requires_result_rebuild"
            | "choose_preferred_imported_call_arg_expr"
            | "render_imported_call_arg"
            | "render_authoritative_source_call_arg"
            | "normalize_imported_call_arg_expr"
            | "finalize_authoritative_imported_call_arg_expr"
            | "normalize_call_arg_expr_with_import_policy"
    )
}

fn call_arg_source_name_authority_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
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
    if method.ident.as_str() == "is_some_and"
        && cx
            .sess()
            .source_map()
            .span_to_snippet(expr.span)
            .is_ok_and(|snippet| {
                snippet.contains("source_var_name_has_prepared_call_arg_authority")
            })
    {
        return false;
    }
    expr_references_call_arg_source_var_name(receiver)
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

fn expr_references_call_arg_source_var_name(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::Field(base, ident) => {
            ident.name.as_str() == "source_var_name"
                || expr_references_call_arg_source_var_name(base)
        }
        ExprKind::MethodCall(_, receiver, args, _) => {
            expr_references_call_arg_source_var_name(receiver)
                || args.iter().any(expr_references_call_arg_source_var_name)
        }
        ExprKind::Call(callee, args) => {
            expr_references_call_arg_source_var_name(callee)
                || args.iter().any(expr_references_call_arg_source_var_name)
        }
        ExprKind::Block(block, _) => block
            .expr
            .is_some_and(expr_references_call_arg_source_var_name),
        ExprKind::AddrOf(_, _, inner)
        | ExprKind::Unary(_, inner)
        | ExprKind::Cast(inner, _)
        | ExprKind::DropTemps(inner) => expr_references_call_arg_source_var_name(inner),
        _ => false,
    }
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

fn enclosing_item_snippet_contains(cx: &LateContext<'_>, expr: &Expr<'_>, needle: &str) -> bool {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        match node {
            rustc_hir::Node::Item(item) => {
                return cx
                    .sess()
                    .source_map()
                    .span_to_snippet(item.span)
                    .is_ok_and(|snippet| snippet.contains(needle));
            }
            rustc_hir::Node::ImplItem(item) => {
                return cx
                    .sess()
                    .source_map()
                    .span_to_snippet(item.span)
                    .is_ok_and(|snippet| snippet.contains(needle));
            }
            _ => {}
        }
    }
    false
}

fn summary_route_executable_c_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if matches!(expr.kind, ExprKind::Field(_, _))
        && enclosing_item_snippet_contains(cx, expr, "render_semantic_worker_linearization")
        && cx
            .sess()
            .source_map()
            .span_to_snippet(expr.span)
            .is_ok_and(|snippet| {
                snippet.contains("plan.signature.signature") || snippet.contains("decl.decl")
            })
    {
        return true;
    }

    if cx
        .sess()
        .source_map()
        .span_to_snippet(expr.span)
        .is_ok_and(|snippet| {
            snippet.lines().count() <= 2
                && ["switch (", "case 0x", "default:", "break;"]
                    .iter()
                    .any(|needle| snippet.contains(needle))
        })
    {
        return true;
    }

    match expr.kind {
        ExprKind::MethodCall(method, _, _, _)
            if method.ident.as_str() == "render_authorized_signature"
                && enclosing_item_snippet_contains(cx, expr, "CFunction") =>
        {
            true
        }
        ExprKind::Lit(lit) => {
            let LitKind::Str(symbol, _) = lit.node else {
                return false;
            };
            let text = symbol.as_str();
            let trimmed = text.trim();
            if trimmed.contains("switch (") {
                return true;
            }
            ["case ", "default:", "break;", "return "]
                .iter()
                .any(|prefix| trimmed.starts_with(prefix))
        }
        ExprKind::Call(callee, _) => {
            if cx
                .sess()
                .source_map()
                .span_to_snippet(expr.span)
                .is_ok_and(|snippet| snippet.contains("CStmt::"))
            {
                return false;
            }
            ["Return", "Expr", "merge_params_with_external_signature"]
                .iter()
                .any(|name| expr_path_last_segment_is(callee, name))
        }
        ExprKind::Field(_, ident) => {
            ident.name.as_str() == "register_params"
                && enclosing_item_snippet_contains(cx, expr, "CFunction")
        }
        _ => false,
    }
}

fn summary_render_executable_cstmt_expr(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if is_inside_test_item(cx, expr) {
        return false;
    }
    if !matches!(expr.kind, ExprKind::Call(_, _) | ExprKind::Struct(_, _, _)) {
        return false;
    }
    cx.sess()
        .source_map()
        .span_to_snippet(expr.span)
        .is_ok_and(|snippet| {
            let snippet = snippet.trim_start();
            [
                "CStmt::Return",
                "CStmt::Expr",
                "CStmt::If",
                "CStmt::While",
                "CStmt::DoWhile",
                "CStmt::For",
                "CStmt::Switch",
                "CStmt::if_stmt",
                "CStmt::while_loop",
            ]
            .iter()
            .any(|needle| snippet.starts_with(needle))
        })
}

fn summary_route_structured_worker_expr(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::MethodCall(method, _, _, _) => {
            method.ident.as_str() == "structure_semantic_worker_islands"
        }
        ExprKind::Call(callee, _) => {
            expr_path_last_segment_is(callee, "semantic_worker_structured_body")
                || expr_path_last_segment_is(callee, "structure_semantic_worker_islands")
        }
        _ => false,
    }
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
/// `r2source` owns the carrier, and `r2dec` renders. `r2ssa` fills it from the
/// snapshot, which is a copy rather than a reading, and is allowed for that.
fn is_display_name_rendering_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2source/src/display_names.rs")
        || filename.contains("crates/r2dec/src/")
        || filename.contains("crates/r2ssa/src/function.rs")
        || filename.contains("crates/r2types/src/function_facts.rs")
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

fn is_r2dec_analysis_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2dec/src/analysis/")
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

fn is_r2dec_lib_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2dec/src/lib.rs")
}

fn is_r2dec_lib_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2dec/src/lib.rs")
}

fn is_r2dec_summary_render_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2dec/src/consumer_summary.rs")
        || filename.contains("crates/r2dec/src/consumer_linear.rs")
        || filename.contains("crates/r2dec/src/consumer_vm.rs")
}

fn is_r2dec_summary_or_structured_consumer_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2dec/src/consumer_summary.rs")
        || filename.contains("crates/r2dec/src/consumer_linear.rs")
        || filename.contains("crates/r2dec/src/consumer_vm.rs")
        || filename.contains("crates/r2dec/src/consumer_structured.rs")
        || filename.contains("crates/r2dec/src/summary_render_executable_cstmt.rs")
}

fn is_r2dec_route_render_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2dec/src/consumer_structured.rs")
        || filename.contains("crates/r2dec/src/lib.rs")
}

fn is_r2engine_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2engine/src/")
}

fn is_r2engine_lib_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2engine/src/lib.rs")
}

fn is_r2engine_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2engine/src/")
}

fn is_r2engine_lib_span(cx: &LateContext<'_>, span: rustc_span::Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    format!("{filename:?}").contains("crates/r2engine/src/lib.rs")
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

fn is_r2types_non_role_registry_path(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    let filename = format!("{filename:?}");
    filename.contains("crates/r2types/src/")
        && !filename.contains("crates/r2types/src/role_registry.rs")
}

fn is_canonical_ssa_var_classifier(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let filename = cx.sess().source_map().span_to_filename(expr.span);
    format!("{filename:?}").contains("crates/r2ssa/src/var.rs")
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
