//! `convention_view_read`: no new production reader of the convention views and strings that
//! `ConventionModel` replaces (doc/adr-call-boundary.md, "The joined model"; D309).

use std::collections::BTreeSet;

use clippy_utils::diagnostics::span_lint;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_hir::{Expr, ExprKind, HirId, Pat, PatKind, QPath};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::Span;

rustc_lint::declare_lint!(
    /// A production item that reads a view or string of the call convention holds a fact
    /// `ConventionModel` owns; S34 deletes them, and only the items in `ALLOWLIST` may (D309).
    pub CONVENTION_VIEW_READ,
    Deny,
    "a convention fact is read from `ConventionModel`, never from a view S34 deletes"
);

/// Types every field of which `ConventionModel` builds (`convention_slots`, `call_effect`), and
/// the prototype no producer fills.
const VIEW_TYPES: &[&str] = &[
    "SourceConventionSlots",
    "SourceCallEffect",
    "SourceBoundaryReads",
    "AdvisoryCallPrototype",
];

/// `(owner, member)`: a field or method holding a convention as a string or a copy; `*` is any owner.
const VIEW_MEMBERS: &[(&str, &str)] = &[
    ("SourceSignaturePresentation", "calling_convention"),
    ("RegisterIdentity", "argument_registers"),
    ("RegisterIdentity", "with_argument_registers"),
    ("CalleeFact", "signature_callconv"),
    ("FunctionInfo", "convention"),
    ("*", "callconv"),
    ("*", "reg_type_hints"),
];

/// `(file, item)` of each production reader at D309; the list only falls, and an entry no
/// reader matches fails the lint.
const ALLOWLIST: &[(&str, &str)] = &[
    ("crates/r2dec/src/render/frame.rs", "Frame::of"),
    ("crates/r2dec/src/render/values.rs", "Values::entry_read"),
    ("crates/r2dec/src/render/values.rs", "located_class"),
    (
        "crates/r2engine/src/declared/mod.rs",
        "Placement::interface",
    ),
    ("crates/r2engine/src/declared/mod.rs", "Placement::reads"),
    ("crates/r2engine/src/declared/mod.rs", "Placement::result"),
    (
        "crates/r2engine/src/lib.rs",
        "EngineAnalyzeRequest::from_parts",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "EngineAnalyzeRequest::with_trusted_ssa",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "EngineFunctionAnalysisArtifactRequest::full_semantics_for_function",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "EngineFunctionDecompileRequest::full_semantics_for_function",
    ),
    ("crates/r2engine/src/lib.rs", "EngineSourceSnapshot"),
    (
        "crates/r2engine/src/lib.rs",
        "EngineSourceSnapshot::call_effect",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "EngineSourceSnapshot::new_with_machine_roles",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "EngineSourceSnapshot::with_call_effect",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "build_engine_analysis_from_parts_with_control",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "engine_analyze_request_input_from_function",
    ),
    (
        "crates/r2engine/src/lib.rs",
        "engine_analyze_request_parts_from_input",
    ),
    ("crates/r2engine/src/lib.rs", "trusted_parsed_context"),
    ("crates/r2engine/src/lib.rs", "trusted_source_signature"),
    ("crates/r2engine/src/native.rs", "machine"),
    ("crates/r2engine/src/program/fates.rs", "Reading"),
    (
        "crates/r2engine/src/program/fates.rs",
        "Reading::formatted_sites",
    ),
    (
        "crates/r2engine/src/program/fates.rs",
        "Reading::import_takes",
    ),
    ("crates/r2engine/src/program/fates.rs", "held_lanes"),
    ("crates/r2engine/src/program/fates.rs", "lanes_of"),
    ("crates/r2engine/src/program/fates.rs", "read_body"),
    ("crates/r2engine/src/program/info.rs", "FunctionInfo::read"),
    (
        "crates/r2engine/src/program/info.rs",
        "FunctionInfo::refused",
    ),
    (
        "crates/r2engine/src/program/requests.rs",
        "OpenProgram::answered",
    ),
    ("crates/r2engine/src/program/requests.rs", "claimed_by"),
    (
        "crates/r2engine/src/program/view.rs",
        "View::default_call_effect",
    ),
    ("crates/r2engine/src/query/annotate.rs", "After"),
    ("crates/r2engine/src/query/annotate.rs", "follow_copies"),
    ("crates/r2engine/src/query/annotate.rs", "handed_to_pointer"),
    ("crates/r2engine/src/query/annotate.rs", "named_by"),
    ("crates/r2engine/src/query/annotate.rs", "named_over"),
    ("crates/r2engine/src/query/annotate.rs", "over_run"),
    ("crates/r2engine/src/query/annotate.rs", "relative_over"),
    ("crates/r2engine/src/query/records.rs", "Answered"),
    ("crates/r2s/src/function.rs", "info"),
    (
        "crates/r2source/src/convention.rs",
        "ConventionModel::call_effect",
    ),
    (
        "crates/r2source/src/convention.rs",
        "ConventionModel::convention_slots",
    ),
    ("crates/r2source/src/lib.rs", "AdvisoryCallSite"),
    ("crates/r2source/src/lib.rs", "AdvisoryCallSite::described"),
    ("crates/r2source/src/lib.rs", "AdvisoryCallSite::prototype"),
    (
        "crates/r2source/src/lib.rs",
        "OwnedFunctionSnapshot::call_effect",
    ),
    (
        "crates/r2source/src/lib.rs",
        "OwnedFunctionSnapshot::convention_slots",
    ),
    (
        "crates/r2source/src/lib.rs",
        "OwnedFunctionSnapshot::from_captured_parts",
    ),
    (
        "crates/r2source/src/lib.rs",
        "OwnedFunctionSnapshot::with_convention",
    ),
    ("crates/r2source/src/lib.rs", "SnapshotState"),
    (
        "crates/r2source/src/lib.rs",
        "SourceSignaturePresentation::calling_convention",
    ),
    (
        "crates/r2source/src/lib.rs",
        "SourceSignaturePresentation::new",
    ),
    ("crates/r2source/src/native.rs", "NativeMachine"),
    ("crates/r2source/src/native.rs", "capture"),
    (
        "crates/r2ssa/src/function/caller_stack_slots.rs",
        "caller_stack_slots",
    ),
    ("crates/r2ssa/src/function/mod.rs", "DecompileInputs"),
    ("crates/r2ssa/src/function/mod.rs", "InterfaceQuestions"),
    (
        "crates/r2ssa/src/function/mod.rs",
        "InterfaceQuestions::before_recovery",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "InterfaceQuestions::construction_carriers",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "InterfaceQuestions::new",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "InterfaceQuestions::none",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "InterfaceQuestions::return_carriers",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "SsaArtifact::for_decompile_with",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "SsaArtifact::for_decompile_with_interfaces_and_control",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "SsaArtifact::for_symbolic_with_interfaces",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "SsaArtifact::raw_with_interfaces",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "TrustedSsaArtifact::construct",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "correlate_call_site_interfaces",
    ),
    (
        "crates/r2ssa/src/function/mod.rs",
        "decompile_call_boundary_config",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::call_effect",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::call_preserved_carriers",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::convention_slots",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::from_blocks",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::from_blocks_with_interfaces",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::from_blocks_with_interfaces_and_tail_calls",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::from_blocks_with_interfaces_tail_calls_and_terminals",
    ),
    (
        "crates/r2ssa/src/machine_context.rs",
        "SourceMachineContext::result_slot",
    ),
    ("crates/r2ssa/src/machine_context.rs", "call_universe"),
    ("crates/r2ssa/src/machine_context.rs", "clobbered_by_a_call"),
    ("crates/r2ssa/src/origin.rs", "BlockOrigins::step_under"),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "body_proven_result",
    ),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "direct_returns_beside_void_tails",
    ),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "entry_defines_nothing",
    ),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "float_result_written",
    ),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "recover_interface_inner",
    ),
    (
        "crates/r2ssa/src/recover_interface.rs",
        "recover_interface_with_context",
    ),
    ("crates/r2ssa/src/recover_interface.rs", "returned_result"),
    ("crates/r2ssa/src/recover_interface.rs", "seed_result"),
    ("crates/r2ssa/src/recover_interface.rs", "shared_position"),
    ("crates/r2ssa/src/save_area.rs", "home_va_list"),
    ("crates/r2ssa/src/save_area.rs", "register_save_area"),
    ("crates/r2ssa/src/saved_register.rs", "preserved"),
    ("crates/r2ssa/src/semantic/boundaries.rs", "carries_input"),
    (
        "crates/r2ssa/src/semantic/boundaries.rs",
        "convention_call_boundary",
    ),
    (
        "crates/r2ssa/src/semantic/boundaries.rs",
        "count_register_set",
    ),
    (
        "crates/r2ssa/src/semantic/boundaries.rs",
        "stated_call_arguments",
    ),
    (
        "crates/r2ssa/src/semantic/boundaries.rs",
        "variadic_callsite_arguments",
    ),
    (
        "crates/r2ssa/src/semantic/boundaries.rs",
        "variadic_tail_on_stack",
    ),
    (
        "crates/r2ssa/src/semantic/frame_reach.rs",
        "FrameReach::escape_spans",
    ),
    ("crates/r2ssa/src/semantic/frame_reach.rs", "compiler_slots"),
    (
        "crates/r2ssa/src/semantic/mod.rs",
        "ensure_source_formal_parameter_values",
    ),
    ("crates/r2ssa/src/semantic/shared.rs", "FrameBoundaries::of"),
    ("crates/r2ssa/src/semantic/shared.rs", "callee_write_spans"),
    ("crates/r2ssa/src/site_boundary.rs", "ResultLanes::of"),
    ("crates/r2ssa/src/site_boundary.rs", "argument_registers"),
    ("crates/r2ssa/src/slot_promotion.rs", "promote"),
    ("crates/r2ssa/src/slot_promotion.rs", "saves"),
    ("crates/r2ssa/src/stack_bound.rs", "decide"),
    ("crates/r2ssa/src/tail_count.rs", "Prover"),
    ("crates/r2ssa/src/tail_count.rs", "Prover::argument_slot"),
    ("crates/r2ssa/src/tail_count.rs", "Prover::saved"),
    ("crates/r2ssa/src/tail_count.rs", "tail_count"),
    ("crates/r2ssa/src/tail_cursors.rs", "Prover::aligned"),
    (
        "crates/r2types/src/analysis/mod.rs",
        "build_type_analysis_inner",
    ),
    (
        "crates/r2types/src/analysis/mod.rs",
        "summary_to_callee_fact",
    ),
    ("crates/r2types/src/facts.rs", "CalleeFact::named"),
    (
        "crates/r2types/src/facts.rs",
        "FunctionTypeFacts::canonicalized",
    ),
    ("crates/r2types/src/facts.rs", "FunctionTypeFacts::is_empty"),
    (
        "crates/r2types/src/facts.rs",
        "FunctionTypeFactsBuilder::build",
    ),
    (
        "crates/r2types/src/function_facts/mod.rs",
        "FunctionFacts::apply_callsite_callee_signatures",
    ),
];

#[derive(Default)]
pub struct ConventionViewPass {
    /// Allowlist entries a reader matched in this crate.
    matched: BTreeSet<(&'static str, &'static str)>,
    /// Readers reported once per item and view.
    reported: BTreeSet<(u32, String)>,
}

rustc_lint::impl_lint_pass!(ConventionViewPass => [CONVENTION_VIEW_READ]);

impl<'tcx> LateLintPass<'tcx> for ConventionViewPass {
    fn check_ty(
        &mut self,
        cx: &LateContext<'tcx>,
        ty: &'tcx rustc_hir::Ty<'tcx, rustc_hir::AmbigArg>,
    ) {
        let ty = ty.as_unambig_ty();
        if let rustc_hir::TyKind::Path(QPath::Resolved(_, path)) = ty.kind
            && let Res::Def(_, def_id) = path.res
            && let Some(view) = view_type(cx.tcx, def_id)
        {
            self.read(cx, ty.hir_id, ty.span, view.to_string());
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if let Some(view) = view_in_type(cx.tcx, cx.typeck_results().expr_ty(expr)) {
            self.read(cx, expr.hir_id, expr.span, view);
        }
        let member = match expr.kind {
            ExprKind::Field(base, field) => owner_name(cx.tcx, cx.typeck_results().expr_ty(base))
                .and_then(|owner| view_member(&owner, field.name.as_str())),
            ExprKind::Struct(_, fields, _) => owner_name(cx.tcx, cx.typeck_results().expr_ty(expr))
                .and_then(|owner| {
                    fields
                        .iter()
                        .find_map(|field| view_member(&owner, field.ident.name.as_str()))
                }),
            ExprKind::MethodCall(..) => cx
                .typeck_results()
                .type_dependent_def_id(expr.hir_id)
                .and_then(|method| associated_view_member(cx.tcx, method)),
            ExprKind::Path(ref qpath) => match cx.qpath_res(qpath, expr.hir_id) {
                Res::Def(DefKind::AssocFn, method) => associated_view_member(cx.tcx, method),
                _ => None,
            },
            _ => None,
        };
        if let Some(member) = member {
            self.read(cx, expr.hir_id, expr.span, member);
        }
    }

    fn check_pat(&mut self, cx: &LateContext<'tcx>, pat: &'tcx Pat<'tcx>) {
        if let PatKind::Struct(_, fields, _) = pat.kind
            && let Some(owner) = owner_name(cx.tcx, cx.typeck_results().node_type(pat.hir_id))
            && let Some(member) = fields
                .iter()
                .find_map(|field| view_member(&owner, field.ident.name.as_str()))
        {
            self.read(cx, pat.hir_id, pat.span, member);
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let local = cx
            .sess()
            .source_map()
            .files()
            .iter()
            .filter(|file| file.cnum == LOCAL_CRATE)
            .map(|file| file.name.prefer_local_unconditionally().to_string())
            .collect::<Vec<_>>();
        for (file, item) in stale_entries(ALLOWLIST, &local, &self.matched) {
            span_lint(
                cx,
                CONVENTION_VIEW_READ,
                cx.tcx.def_span(LOCAL_CRATE.as_def_id()),
                format!(
                    "(\"{file}\", \"{item}\") reads no view any more; remove it from the allowlist, which only falls"
                ),
            );
        }
    }
}

impl ConventionViewPass {
    fn read(&mut self, cx: &LateContext<'_>, at: HirId, span: Span, view: String) {
        if span.from_expansion() || clippy_utils::is_in_test(cx.tcx, at) {
            return;
        }
        let owner = cx.tcx.hir_get_parent_item(at).def_id;
        if inside_a_view(cx.tcx, owner) {
            return;
        }
        let file = cx
            .sess()
            .source_map()
            .span_to_filename(span)
            .prefer_local_unconditionally()
            .to_string();
        let item = item_label(cx.tcx, owner);
        if let Some(entry) = ALLOWLIST
            .iter()
            .find(|(allowed, name)| file == *allowed && *name == item)
        {
            self.matched.insert(*entry);
            return;
        }
        if self
            .reported
            .insert((owner.local_def_index.as_u32(), view.clone()))
        {
            span_lint(
                cx,
                CONVENTION_VIEW_READ,
                span,
                format!(
                    "(\"{file}\", \"{item}\") reads `{view}`, a view `ConventionModel` replaces; read the model (doc/adr-call-boundary.md, D309)"
                ),
            );
        }
    }
}

fn view_type(tcx: TyCtxt<'_>, def_id: DefId) -> Option<&'static str> {
    if !matches!(tcx.def_kind(def_id), DefKind::Struct | DefKind::Enum) {
        return None;
    }
    let name = tcx.item_name(def_id);
    VIEW_TYPES
        .iter()
        .copied()
        .find(|view| *view == name.as_str())
}

fn view_in_type<'tcx>(tcx: TyCtxt<'tcx>, ty: Ty<'tcx>) -> Option<String> {
    ty.walk().find_map(|arg| match arg.as_type()?.kind() {
        ty::Adt(adt, _) => view_type(tcx, adt.did()).map(str::to_string),
        _ => None,
    })
}

fn owner_name<'tcx>(tcx: TyCtxt<'tcx>, ty: Ty<'tcx>) -> Option<String> {
    match ty.peel_refs().kind() {
        ty::Adt(adt, _) => Some(tcx.item_name(adt.did()).to_string()),
        _ => None,
    }
}

fn view_member(owner: &str, member: &str) -> Option<String> {
    VIEW_MEMBERS
        .iter()
        .any(|(of, name)| *name == member && (*of == "*" || *of == owner))
        .then(|| format!("{owner}::{member}"))
}

/// A method or associated function of an inherent impl whose self type and name `VIEW_MEMBERS` lists.
fn associated_view_member(tcx: TyCtxt<'_>, method: DefId) -> Option<String> {
    let parent = tcx.parent(method);
    if !matches!(tcx.def_kind(parent), DefKind::Impl { of_trait: false }) {
        return None;
    }
    let owner = owner_name(
        tcx,
        tcx.type_of(parent)
            .instantiate_identity()
            .skip_normalization(),
    )?;
    view_member(&owner, tcx.item_name(method).as_str())
}

/// The view's own definition and impls are the view, not a reader of it; a derived impl
/// restates its type's fields, whose holder is the reader.
fn inside_a_view(tcx: TyCtxt<'_>, owner: LocalDefId) -> bool {
    let mut at = owner.to_def_id();
    loop {
        match tcx.def_kind(at) {
            DefKind::Struct | DefKind::Enum => return view_type(tcx, at).is_some(),
            DefKind::Impl { .. } => {
                return tcx.is_automatically_derived(at)
                    || view_in_type(
                        tcx,
                        tcx.type_of(at).instantiate_identity().skip_normalization(),
                    )
                    .is_some();
            }
            DefKind::AssocFn | DefKind::AssocConst | DefKind::AssocTy => at = tcx.parent(at),
            _ => return false,
        }
    }
}

/// `Type::method` for an associated item, `impl Type` for an impl, else the item's name.
fn item_label(tcx: TyCtxt<'_>, owner: LocalDefId) -> String {
    let def_id = owner.to_def_id();
    let self_name = |of: DefId| {
        let ty = tcx.type_of(of).instantiate_identity().skip_normalization();
        owner_name(tcx, ty).unwrap_or_else(|| ty.to_string())
    };
    match tcx.def_kind(def_id) {
        DefKind::Impl { .. } => format!("impl {}", self_name(def_id)),
        DefKind::AssocFn | DefKind::AssocConst | DefKind::AssocTy => {
            let parent = tcx.parent(def_id);
            let holder = match tcx.def_kind(parent) {
                DefKind::Impl { .. } => self_name(parent),
                _ => tcx.item_name(parent).to_string(),
            };
            format!("{holder}::{}", tcx.item_name(def_id))
        }
        _ => tcx
            .opt_item_name(def_id)
            .map_or_else(|| "_".to_string(), |name| name.to_string()),
    }
}

/// Entries whose file this crate compiled and no reader in it matched.
fn stale_entries(
    allowlist: &'static [(&'static str, &'static str)],
    local_files: &[String],
    matched: &BTreeSet<(&'static str, &'static str)>,
) -> Vec<(&'static str, &'static str)> {
    allowlist
        .iter()
        .filter(|entry| local_files.iter().any(|file| file == entry.0) && !matched.contains(*entry))
        .copied()
        .collect()
}

#[test]
fn an_entry_is_stale_only_where_its_file_was_compiled_and_nothing_matched() {
    const LIST: &[(&str, &str)] = &[
        ("fixture/a/x.rs", "f"),
        ("fixture/a/x.rs", "g"),
        ("fixture/b/y.rs", "h"),
    ];
    let local = vec!["fixture/a/x.rs".to_string()];
    let matched = BTreeSet::from([("fixture/a/x.rs", "f")]);
    assert_eq!(
        stale_entries(LIST, &local, &matched),
        vec![("fixture/a/x.rs", "g")]
    );
}
