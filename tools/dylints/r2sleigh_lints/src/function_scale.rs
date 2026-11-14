//! Per-item passes over function-scale sets (ROADMAP D416): `SCAN_IN_LOOP`, and the block-address
//! half of `ENTITY_KEYED_MAP`. Both read types and loop shape; neither sees a cross-crate callee.

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::{span_lint, span_lint_hir};
use clippy_utils::higher::{ForLoop, Range};
use rustc_hir::def::Res;
use rustc_hir::{Expr, ExprKind, HirId, Node, QPath};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty, TypeckResults};
use rustc_span::Span;
use rustc_span::def_id::LocalDefId;

rustc_lint::declare_lint!(
    /// ### What it does
    ///
    /// Flags a whole pass over a function-scale set inside a loop body or an iterator closure: an
    /// iteration, `clone` or `len()`-sized allocation of a dense table, a graph table, or a
    /// collection of a function's entities or registry rows, or a call to a function of the same
    /// crate that makes one over a function-owned table. A receiver that depends on the loop's own
    /// binding passes (`for b in blocks { for i in &b.insts }` is `O(I)`).
    ///
    /// ### Why is this bad?
    ///
    /// One pass per item over a set the size of the function is `O(|X| x |Y|)`. Five of the
    /// engine's quadratics had this shape (1cd65fdcc, c67924d1a, adee2bc73, 6e3250060, 8e9b6edc1).
    ///
    /// ### Known problems
    ///
    /// Blind to cross-crate callees, rebuilds per call and fixpoint height. A bounded scan states
    /// its bound in `allow(scan_in_loop, reason = ...)`; the scaling bench (D404, D417) proves it.
    pub SCAN_IN_LOOP,
    Warn,
    "a whole pass over a function-scale set inside a per-item loop"
);

/// Dense tables, each indexed by one function's ids.
const DENSE: &[&str] = &["Metered", "IdVec", "IdMap", "IdSet", "SparseMap", "Csr"];
const COLLECTIONS: &[&str] = &[
    "Vec", "VecDeque", "BTreeMap", "BTreeSet", "HashMap", "HashSet",
];
/// A function's entities and registry rows: a collection of them is the function's size.
const ROWS: &[&str] = &[
    "SSAVar",
    "VarId",
    "ValueId",
    "InstId",
    "BlockId",
    "OpId",
    "VarKey",
    "TermId",
    "GraphInst",
    "GraphBlock",
    "GraphValue",
    "StructuredAccessId",
    "StructuredMemoryAccessFact",
    "CallBase",
    "OpaqueAccess",
    "ObjectId",
    "CallSiteId",
    "UseSite",
    "SSABlock",
];
/// Types that hold a whole function: a table reached through one is the function's size.
const OWNERS: &[&str] = &[
    "SsaGraph",
    "SSAFunction",
    "SsaArtifact",
    "DecompilePrepFacts",
    "PreparedFunctionFacts",
];
const SCANS: &[&str] = &[
    "iter",
    "iter_mut",
    "into_iter",
    "values",
    "values_mut",
    "keys",
    "clone",
    "to_vec",
    "to_owned",
    "retain",
];
/// Linear only on a sequence; a tree or hash answers in `O(log n)` or `O(1)`.
const SEQUENCE_SCANS: &[&str] = &["contains", "position", "rposition"];
const ALLOCATORS: &[&str] = &["with_capacity", "filled", "from_fn", "from_elem", "new"];
const BLOCK_TYPES: &[&str] = &["GraphBlock", "SSABlock", "BasicBlock"];
const BLOCK_EDGES: &[&str] = &["successors", "predecessors", "block_addrs"];
/// A `u64` binding of one of these names holds a block's address.
const BLOCK_NAMES: &[&str] = &[
    "block",
    "successor",
    "predecessor",
    "dominator",
    "succ",
    "pred",
];
const KEY_METHODS: &[&str] = &[
    "insert",
    "entry",
    "get",
    "get_mut",
    "contains_key",
    "contains",
    "remove",
];

/// The hits standing when D416 landed, by item path, unaudited: each goes when its item is
/// rewritten or its bound is stated in `allow(scan_in_loop, reason = ...)` beside it. An entry
/// that no longer fires fails the build, so the list only shrinks.
const STANDING_SCANS: &[&str] = &[
    "r2dec::render::values::Values::<'a>::copies",
    "r2ssa::edge_fold::narrows",
    "r2ssa::function::body_proven_format_parameter",
    "r2ssa::function::caller_stack_slots::caller_stack_slots",
    "r2ssa::function::forward::resolve_chains",
    "r2ssa::function::forwarded_parameter_index",
    "r2ssa::function::rewrite::<impl function::SSAFunction>::mint_entry_lane_projections",
    "r2ssa::function::rewrite::<impl function::SSAFunction>::zero_scratch_insert_roots",
    "r2ssa::graph::SsaGraph::from_function_with_storage",
    "r2ssa::interproc::address_candidates",
    "r2ssa::interproc::dependence::FormalDependence::of",
    "r2ssa::interproc::dependence::FormalDependence::passed_to_call",
    "r2ssa::interproc::dependence::FrameTraffic::of",
    "r2ssa::interproc::solve_prepared_interproc_summary_set",
    "r2ssa::liveness::ValueLiveness::compute_with_relocations",
    "r2ssa::obligation::SemanticObligationInventory::collect",
    "r2ssa::obligation::ValueReaders::of",
    "r2ssa::recover_interface::body_proven_result",
    "r2ssa::recover_interface::homed_in_its_home",
    "r2ssa::recover_interface::left_by_calls",
    "r2ssa::recover_interface::observed_entry_read_storages",
    "r2ssa::recover_interface::passed_through_entry_storages",
    "r2ssa::recover_interface::recover_interface_inner",
    "r2ssa::recover_interface::recovered_result_over",
    "r2ssa::recover_interface::restored_from_its_save",
    "r2ssa::recover_interface::result_calls",
    "r2ssa::recover_interface::written_bytes",
    "r2ssa::save_area::homed_tail",
    "r2ssa::save_area::register_save_area",
    "r2ssa::security_cookie::Context::<'_>::computed_bytes",
    "r2ssa::semantic::assumptions::collect_prepared_assumption_usage",
    "r2ssa::semantic::boundaries::collect_source_boundary_facts",
    "r2ssa::semantic::boundaries::convention_call_boundary",
    "r2ssa::semantic::certificates::collect_prepared_function_certificates",
    "r2ssa::semantic::certificates::returns::collect_machine_return_control_certificates",
    "r2ssa::semantic::certificates::stack::accessed_object_storage",
    "r2ssa::semantic::certificates::stack::collect_callee_stack_allocation_certificates",
    "r2ssa::semantic::certificates::stack::collect_stack_frame_round_trip_certificates",
    "r2ssa::semantic::frame_reach::walk::Walker::<'a>::read",
    "r2ssa::semantic::loops::collect_structured_loop_facts",
    "r2ssa::tail_count::Prover::<'_>::bound",
    "r2types::evidence::EvidenceBuilder::<'a>::scalar_memory_cells",
    "r2types::function_facts::prepared::prepared_guarded_phi_render_fact",
    "r2types::prepare::recover_signature_params_from_prepared_ssa",
    "r2types::signature_infer::certified_parameter_home_aliases",
];
/// The block-address maps standing when D416 landed (owner: F2.1's dense block numbering).
const STANDING_BLOCK_KEYS: &[&str] = &[
    "r2dec::<structure::certify::CfgMachine<'_> as structure::condition::Machine>::entered_from_outside",
    "r2dec::structure::certify::certify",
    "r2dec::structure::certify::statement_violations",
    "r2dec::structure::place::closed_subtrees",
    "r2dec::structure::place::Placement::<'f>::compute",
    "r2dec::structure::place::Placement::labelled",
    "r2dec::structure::place::Placement::loops_of",
    "r2dec::structure::place::Placement::merge",
    "r2sleigh_lift::disasm::validate_genuine_function_cfg",
    "r2ssa::address::AddressCollector::<'a>::collect",
    "r2ssa::address::AddressCollector::stack_out",
    "r2ssa::cfg::CFG::addr_to_node",
    "r2ssa::cfg::CFG::dfs_back_edges",
    "r2ssa::cfg::DeclaredSuccessors::by_block",
    "r2ssa::cfg::DeclaredSuccessors::unresolved",
    "r2ssa::demand::exits_are_named_beside",
    "r2ssa::domtree::DomTree::frontier",
    "r2ssa::domtree::DomTree::iterated_frontier_with_control",
    "r2ssa::domtree::DomTree::number",
    "r2ssa::domtree::DomTree::of_graph",
    "r2ssa::domtree::frontiers",
    "r2ssa::fixpoint::forward_on_edges",
    "r2ssa::fixpoint::Solution::entry",
    "r2ssa::fixpoint::Solution::exit",
    "r2ssa::frame_address::Definitions::reach_of",
    "r2ssa::frame_address::Reach::above",
    "r2ssa::frame_address::Reach::last",
    "r2ssa::function::blocks::Blocks::<V>::reorder",
    "r2ssa::function::blocks::Blocks::apply",
    "r2ssa::function::edit::EditPlan::by_block",
    "r2ssa::integrity::validate_ssa_function",
    "r2ssa::natural_loops::NaturalLoop::body",
    "r2ssa::natural_loops::NaturalLoops::compute",
    "r2ssa::optimize::apply_sccp_results",
    "r2ssa::optimize::fuse_compare_chains_in_function",
    "r2ssa::phi::live_in_by_block",
    "r2ssa::phi::LiveIn::position",
    "r2ssa::phi::PhiPlacement::phis",
    "r2ssa::recover_interface::direct_return_result",
    "r2ssa::semantic::control_domains::collect_control_domain_facts",
    "r2ssa::semantic::facts::PredicateFacts::block_assumptions",
    "r2ssa::semantic::frame_reach::walk::reaching_writes",
    "r2ssa::semantic::frame_reach::walk::StackArguments::rewritten",
    "r2ssa::semantic::loops::header_carriers",
    "r2ssa::semantic::loops::LoopExits::of",
    "r2ssa::semantic::predicates::collect_predicate_facts",
    "r2ssa::semantic::reaching::ReachingStorage::<'a>::entry",
    "r2ssa::semantic::reaching::ReachingStorage::entries",
    "r2ssa::semantic::reaching::ReachingStorage::scanned",
    "r2ssa::semantic::shared::loop_carrier_peer_candidates",
    "r2ssa::semantic::structured::collect_unstructured_cycle_blocks",
    "r2ssa::semantic::trips::TripCounter::<'a>::defined_in",
    "r2ssa::slot_promotion::index_accesses",
    "r2ssa::slot_promotion::live_in",
    "r2ssa::slot_promotion::merge_blocks",
    "r2ssa::slot_promotion::walk_versions",
    "r2ssa::stack_bound::remove_failing_blocks",
    "r2ssa::stack_protector::decide",
    "r2ssa::values::narrow_where_defined",
];

#[derive(Default)]
pub struct FunctionScale {
    /// Whether each function of the crate makes a whole pass over a function-owned table.
    scanning: HashMap<LocalDefId, bool>,
    /// Block-address maps already reported, by declaration.
    keyed: HashSet<HirId>,
    /// Standing entries this crate hit.
    standing: HashSet<String>,
}

rustc_lint::impl_lint_pass!(FunctionScale => [SCAN_IN_LOOP]);

impl<'tcx> LateLintPass<'tcx> for FunctionScale {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let krate = cx.tcx.crate_name(rustc_span::def_id::LOCAL_CRATE);
        let prefix = format!("{krate}::");
        let span = cx.tcx.def_span(rustc_span::def_id::CRATE_DEF_ID);
        for (lint, list) in [
            (SCAN_IN_LOOP, STANDING_SCANS),
            (crate::ENTITY_KEYED_MAP, STANDING_BLOCK_KEYS),
        ] {
            for entry in list.iter().filter(|entry| entry.starts_with(&prefix)) {
                if !self.standing.contains(*entry) {
                    span_lint(
                        cx,
                        lint,
                        span,
                        format!("`{entry}` no longer fires; delete its standing entry"),
                    );
                }
            }
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let file = format!(
            "{:?}",
            cx.sess()
                .source_map()
                .span_to_filename(expr.span.source_callsite())
        );
        if !file.contains("crates/") || !file.contains("/src/") {
            return;
        }
        if clippy_utils::is_in_test(cx.tcx, expr.hir_id) {
            return;
        }
        self.block_keyed(cx, expr);
        let typeck = cx.typeck_results();
        let found = match scan_of(cx, typeck, expr) {
            Some((what, receiver)) => Some((what, Some(receiver))),
            None => self.scanning_call(cx, expr).map(|name| (name, None)),
        };
        if let Some((what, receiver)) = found
            && let Some(per) = enclosing_loop(cx, expr, receiver)
        {
            let item = item_path(
                cx,
                cx.tcx.hir_get_parent_item(expr.hir_id).def_id.to_def_id(),
            );
            if STANDING_SCANS.contains(&item.as_str()) {
                self.standing.insert(item);
                return;
            }
            span_lint(
                cx,
                SCAN_IN_LOOP,
                expr.span.source_callsite(),
                format!(
                    "{what} once per item of the loop at {per}, in `{item}`; index it once outside"
                ),
            );
        }
    }
}

/// The whole pass `expr` makes and its receiver, when it makes one over a function-scale set.
fn scan_of<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &TypeckResults<'tcx>,
    expr: &'tcx Expr<'tcx>,
) -> Option<(String, &'tcx Expr<'tcx>)> {
    if let Some(for_loop) = ForLoop::hir(expr)
        && !partial(cx, for_loop.arg)
        && function_scale(cx, typeck.expr_ty(for_loop.arg))
    {
        return Some(("a `for` over a function-scale set".to_owned(), for_loop.arg));
    }
    match expr.kind {
        ExprKind::MethodCall(segment, receiver, args, _) => {
            let name = segment.ident.name.as_str();
            let ty = typeck.expr_ty(receiver).peel_refs();
            let scans = SCANS.contains(&name) && function_scale(cx, ty)
                || SEQUENCE_SCANS.contains(&name) && sequence(cx, ty) && function_scale(cx, ty);
            let whole =
                args.is_empty() && named(cx, ty, OWNERS) && iterator(cx, typeck.expr_ty(expr));
            ((scans || whole) && !partial(cx, receiver))
                .then(|| (format!("`.{name}()` over a function-scale set"), receiver))
        }
        ExprKind::Call(callee, args) => {
            let name = callee_name(callee)?;
            if !ALLOCATORS.contains(&name.as_str()) {
                return None;
            }
            args.iter().find_map(|arg| match arg.kind {
                ExprKind::MethodCall(segment, receiver, [], _)
                    if segment.ident.name.as_str() == "len"
                        && function_scale(cx, typeck.expr_ty(receiver)) =>
                {
                    Some((
                        format!("`{name}` sized by a function-scale `len()`"),
                        receiver,
                    ))
                }
                _ => None,
            })
        }
        _ => None,
    }
}

fn callee_name(callee: &Expr<'_>) -> Option<String> {
    match callee.kind {
        ExprKind::Path(QPath::Resolved(_, path)) => {
            path.segments.last().map(|s| s.ident.to_string())
        }
        ExprKind::Path(QPath::TypeRelative(_, segment)) => Some(segment.ident.to_string()),
        _ => None,
    }
}

/// A slice of a range (`insts[..at]`) is not the whole set.
fn partial(cx: &LateContext<'_>, receiver: &Expr<'_>) -> bool {
    match receiver.kind {
        ExprKind::Index(_, index, _) => Range::hir(cx, index).is_some(),
        ExprKind::AddrOf(_, _, inner) => partial(cx, inner),
        _ => false,
    }
}

fn named(cx: &LateContext<'_>, ty: Ty<'_>, names: &[&str]) -> bool {
    match ty.peel_refs().kind() {
        ty::Adt(def, _) => names.contains(&cx.tcx.item_name(def.did()).as_str()),
        _ => false,
    }
}

fn sequence(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    matches!(ty.peel_refs().kind(), ty::Slice(_)) || named(cx, ty, &["Vec", "VecDeque", "Metered"])
}

fn iterator<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    cx.tcx
        .get_diagnostic_item(rustc_span::sym::Iterator)
        .is_some_and(|iterator| clippy_utils::ty::implements_trait(cx, ty, iterator, &[]))
}

/// A row of a function: an entity, a registry row, or a tuple or reference holding one.
fn row(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    match ty.peel_refs().kind() {
        ty::Adt(def, _) => ROWS.contains(&cx.tcx.item_name(def.did()).as_str()),
        ty::Tuple(items) => items.iter().any(|item| row(cx, item)),
        _ => false,
    }
}

/// A set the size of one function: a dense table, or a collection of the function's rows.
fn function_scale(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    match ty.peel_refs().kind() {
        ty::Adt(def, args) => {
            let name = cx.tcx.item_name(def.did());
            DENSE.contains(&name.as_str())
                || COLLECTIONS.contains(&name.as_str()) && args.types().any(|item| row(cx, item))
        }
        _ => false,
    }
}

/// The loop that runs `expr` once per item, when `receiver` does not depend on that item.
fn enclosing_loop<'tcx>(
    cx: &LateContext<'tcx>,
    expr: &Expr<'_>,
    receiver: Option<&'tcx Expr<'tcx>>,
) -> Option<String> {
    let mut below = vec![expr.hir_id];
    for (id, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        match node {
            Node::Item(_) | Node::ImplItem(_) | Node::TraitItem(_) => return None,
            Node::Expr(parent) => {
                let scope = if let Some(for_loop) = ForLoop::hir(parent)
                    && below.contains(&for_loop.body.hir_id)
                {
                    Some((for_loop.pat.span.to(for_loop.body.span), for_loop.span))
                } else if let ExprKind::Closure(closure) = parent.kind
                    && iterated_closure(cx, parent)
                {
                    let body = cx.tcx.hir_body(closure.body);
                    Some((parent.span, body.value.span))
                } else {
                    None
                };
                if let Some((bindings, at)) = scope
                    && receiver.is_none_or(|receiver| !bound_in(cx, receiver, bindings))
                {
                    let place = cx.sess().source_map().lookup_char_pos(at.lo());
                    return Some(format!("line {}", place.line));
                }
            }
            _ => {}
        }
        below.push(id);
    }
    None
}

/// A closure handed to an `Iterator` method: it runs once per item.
fn iterated_closure(cx: &LateContext<'_>, closure: &Expr<'_>) -> bool {
    let Some(parent) = clippy_utils::get_parent_expr(cx, closure) else {
        return false;
    };
    let ExprKind::MethodCall(_, _, args, _) = parent.kind else {
        return false;
    };
    let iterator = cx.tcx.get_diagnostic_item(rustc_span::sym::Iterator);
    let adapter = (cx.typeck_results().type_dependent_def_id(parent.hir_id))
        .is_some_and(|method| iterator.is_some() && cx.tcx.trait_of_assoc(method) == iterator);
    adapter && args.iter().any(|arg| arg.hir_id == closure.hir_id)
}

/// Whether `expr` reads a local bound inside `bindings`.
fn bound_in<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>, bindings: Span) -> bool {
    clippy_utils::visitors::for_each_expr(cx.tcx, expr, |inner| {
        if let ExprKind::Path(QPath::Resolved(None, path)) = inner.kind
            && let Res::Local(binding) = path.res
            && bindings.contains(cx.tcx.hir_span(binding))
        {
            return std::ops::ControlFlow::Break(());
        }
        std::ops::ControlFlow::Continue(())
    })
    .is_some()
}

impl FunctionScale {
    /// The callee's name when `expr` calls a function of this crate that scans a function-owned table.
    fn scanning_call(&mut self, cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<String> {
        let def_id = match expr.kind {
            ExprKind::MethodCall(..) => cx.typeck_results().type_dependent_def_id(expr.hir_id)?,
            ExprKind::Call(callee, _) => match callee.kind {
                ExprKind::Path(ref qpath) => cx.qpath_res(qpath, callee.hir_id).opt_def_id()?,
                _ => return None,
            },
            _ => return None,
        };
        let local = def_id.as_local()?;
        let scans = *self
            .scanning
            .entry(local)
            .or_insert_with(|| owned_scan(cx, local));
        scans.then(|| {
            format!(
                "`{}` scans a function-owned table",
                cx.tcx.item_name(def_id)
            )
        })
    }

    /// Reports a `u64`-keyed map or set whose keys are block addresses, once, at its declaration.
    fn block_keyed(&mut self, cx: &LateContext<'_>, expr: &Expr<'_>) {
        let ExprKind::MethodCall(segment, receiver, [key, ..], _) = expr.kind else {
            return;
        };
        let typeck = cx.typeck_results();
        let ty::Adt(collection, args) = typeck.expr_ty(receiver).peel_refs().kind() else {
            return;
        };
        let keyed_by_u64 = args.types().next().is_some_and(|key| is_u64(key));
        if !KEY_METHODS.contains(&segment.ident.name.as_str())
            || !keyed_by_u64
            || !["BTreeMap", "BTreeSet", "HashMap", "HashSet"]
                .contains(&cx.tcx.item_name(collection.did()).as_str())
            || !block_address(cx, key, 4)
        {
            return;
        }
        let Some((declared, span, item)) = declaration(cx, receiver) else {
            return;
        };
        if STANDING_BLOCK_KEYS.contains(&item.as_str()) {
            self.standing.insert(item);
            return;
        }
        if self.keyed.insert(declared) {
            span_lint_hir(
                cx,
                crate::ENTITY_KEYED_MAP,
                declared,
                span,
                format!(
                    "`{item}` is keyed by a block address; use an index over dense block ids (r2ssa::dense)"
                ),
            );
        }
    }
}

/// Whether `function`'s body makes a whole pass over a table reached through a function owner.
fn owned_scan(cx: &LateContext<'_>, function: LocalDefId) -> bool {
    if !matches!(
        cx.tcx.def_kind(function),
        rustc_hir::def::DefKind::Fn | rustc_hir::def::DefKind::AssocFn
    ) {
        return false;
    }
    let Some(body) = cx.tcx.hir_maybe_body_owned_by(function) else {
        return false;
    };
    let typeck = cx.tcx.typeck(function);
    clippy_utils::visitors::for_each_expr(cx.tcx, body.value, |expr| {
        match scan_of(cx, typeck, expr) {
            Some((_, receiver)) if owned(cx, typeck, receiver, 8) => {
                std::ops::ControlFlow::Break(())
            }
            _ => std::ops::ControlFlow::Continue(()),
        }
    })
    .is_some()
}

/// Whether `expr` is reached through a whole-function owner: a field, method or local chain.
fn owned<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &TypeckResults<'tcx>,
    expr: &'tcx Expr<'tcx>,
    depth: u8,
) -> bool {
    if depth == 0 {
        return false;
    }
    if named(cx, typeck.expr_ty(expr), OWNERS) {
        return true;
    }
    match expr.kind {
        ExprKind::Field(base, _)
        | ExprKind::MethodCall(_, base, _, _)
        | ExprKind::AddrOf(_, _, base)
        | ExprKind::Unary(_, base)
        | ExprKind::Index(base, _, _) => owned(cx, typeck, base, depth - 1),
        ExprKind::Path(QPath::Resolved(None, path)) => {
            let Res::Local(binding) = path.res else {
                return false;
            };
            let_init(cx, binding).is_some_and(|init| owned(cx, typeck, init, depth - 1))
        }
        _ => false,
    }
}

/// Whether `expr` is a block's address: a block's `addr`, a `u64` field or binding named as a
/// block, an edge of the CFG API, or a local bound to one. The names are the code's, not the binary's.
fn block_address(cx: &LateContext<'_>, expr: &Expr<'_>, depth: u8) -> bool {
    if depth == 0 {
        return false;
    }
    let typeck = cx.typeck_results();
    match expr.kind {
        ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(_, inner) => {
            block_address(cx, inner, depth - 1)
        }
        ExprKind::Field(base, field) => {
            let name = field.name.as_str();
            name == "addr" && named(cx, typeck.expr_ty(base), BLOCK_TYPES)
                || name == "block" && is_u64(typeck.expr_ty(expr))
        }
        ExprKind::Path(QPath::Resolved(None, path)) => {
            let Res::Local(binding) = path.res else {
                return false;
            };
            let name = cx.tcx.hir_name(binding);
            let named_block =
                BLOCK_NAMES.contains(&name.as_str()) || name.as_str().ends_with("_block");
            if named_block && typeck.node_type_opt(binding).is_some_and(is_u64) {
                return true;
            }
            match let_init(cx, binding) {
                Some(init) => block_address(cx, init, depth - 1),
                None => edge_binding(cx, binding),
            }
        }
        _ => false,
    }
}

/// Whether `binding` is a `for` pattern over a CFG edge list (`successors(block)`).
fn edge_binding(cx: &LateContext<'_>, binding: HirId) -> bool {
    cx.tcx.hir_parent_iter(binding).any(|(_, node)| {
        let Node::Expr(expr) = node else {
            return false;
        };
        let Some(for_loop) = ForLoop::hir(expr) else {
            return false;
        };
        for_loop.pat.span.contains(cx.tcx.hir_span(binding))
            && matches!(for_loop.arg.kind, ExprKind::MethodCall(segment, ..)
                if BLOCK_EDGES.contains(&segment.ident.name.as_str()))
    })
}

/// The crate-qualified path of `item` (`r2ssa::frame_address::Reach::last`).
fn item_path(cx: &LateContext<'_>, item: rustc_span::def_id::DefId) -> String {
    let krate = cx.tcx.crate_name(item.krate);
    format!("{krate}::{}", cx.tcx.def_path_str(item))
}

/// Where the map `receiver` names is declared, with the item that holds it: a local's binding
/// (its function) or a struct field.
fn declaration(cx: &LateContext<'_>, receiver: &Expr<'_>) -> Option<(HirId, Span, String)> {
    match receiver.kind {
        ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(_, inner) => declaration(cx, inner),
        ExprKind::Path(QPath::Resolved(None, path)) => match path.res {
            Res::Local(binding) => {
                let item = cx.tcx.hir_get_parent_item(binding).def_id.to_def_id();
                Some((binding, cx.tcx.hir_span(binding), item_path(cx, item)))
            }
            _ => None,
        },
        ExprKind::Field(base, field) => {
            let ty::Adt(owner, _) = cx.typeck_results().expr_ty(base).peel_refs().kind() else {
                return None;
            };
            if !owner.is_struct() {
                return None;
            }
            let field = owner
                .non_enum_variant()
                .fields
                .iter()
                .find(|f| f.name == field.name)?;
            let local = field.did.as_local()?;
            let hir_id = cx.tcx.local_def_id_to_hir_id(local);
            Some((hir_id, cx.tcx.hir_span(hir_id), item_path(cx, field.did)))
        }
        _ => None,
    }
}

fn is_u64(ty: Ty<'_>) -> bool {
    matches!(ty.peel_refs().kind(), ty::Uint(ty::UintTy::U64))
}

/// The initializer of the `let` (or `let ... else`) whose pattern binds `binding`.
fn let_init<'tcx>(cx: &LateContext<'tcx>, binding: HirId) -> Option<&'tcx Expr<'tcx>> {
    for (_, node) in cx.tcx.hir_parent_iter(binding) {
        match node {
            Node::Pat(_) | Node::PatField(_) => {}
            Node::LetStmt(local) => return local.init,
            _ => return None,
        }
    }
    None
}
