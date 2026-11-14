//! `UNPROVEN_NEGATIVE` (ROADMAP D411): a negative fact is a witness its owner mints, never a bool a
//! caller sets.

use std::collections::BTreeMap;

use clippy_utils::diagnostics::span_lint;
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

rustc_lint::declare_lint!(
    /// ### What it does
    ///
    /// Denies a `bool` field of a public struct whose name ends in `stated`, `assumed`, `cited`,
    /// `proven` or `kept`.
    ///
    /// ### Why is this bad?
    ///
    /// Such a field states that something does not happen (a call reads no more, a register is
    /// kept), and any code that builds the struct sets it with no evidence. Five built fixes had
    /// that cause (f6943caa5, D382, D393, D395, D379). The fact is a type whose owner mints it from
    /// its evidence: `ReadBound`, `Cancelled`, `StackWrites`, `Citation`.
    pub UNPROVEN_NEGATIVE,
    Deny,
    "a negative fact is a witness its owner mints, not a public bool"
);

const NAMES: &[&str] = &["stated", "assumed", "cited", "proven", "kept"];

/// The fields standing when D411 landed, by path: each goes when its owner mints a witness, and
/// the list only falls.
const STANDING: &[&str] = &[
    "r2ssa::semantic::certificates::CallsiteCertificate::arguments_proven",
    "r2ssa::semantic::facts::SourceCallBoundaryFact::arguments_proven",
];

#[derive(Default)]
pub struct UnprovenNegative {
    found: BTreeMap<String, Span>,
}

rustc_lint::impl_lint_pass!(UnprovenNegative => [UNPROVEN_NEGATIVE]);

impl<'tcx> LateLintPass<'tcx> for UnprovenNegative {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Struct(_, _, data) = item.kind else {
            return;
        };
        let def_id = item.owner_id.to_def_id();
        if !cx.tcx.visibility(def_id).is_public() || crate::item_is_test_only(cx, item) {
            return;
        }
        for field in data.fields() {
            let named = field.ident.as_str();
            let last = named.rsplit('_').next().unwrap_or(named);
            let ty = cx.tcx.type_of(field.def_id).instantiate_identity();
            let is_bool = ty.skip_normalization().is_bool();
            if !is_bool || !NAMES.contains(&last) {
                continue;
            }
            let krate = cx.tcx.crate_name(def_id.krate);
            let path = format!("{krate}::{}::{named}", cx.tcx.def_path_str(def_id));
            self.found.insert(path, field.span);
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let krate = cx.tcx.crate_name(rustc_span::def_id::LOCAL_CRATE);
        let prefix = format!("{krate}::");
        for (path, span) in &self.found {
            if !STANDING.contains(&path.as_str()) {
                span_lint(
                    cx,
                    UNPROVEN_NEGATIVE,
                    *span,
                    "a public bool states a negative fact any caller sets; carry a witness its owner mints",
                );
            }
        }
        let span = cx.tcx.def_span(rustc_span::def_id::CRATE_DEF_ID);
        for path in STANDING.iter().filter(|path| path.starts_with(&prefix)) {
            if !self.found.contains_key(*path) {
                span_lint(
                    cx,
                    UNPROVEN_NEGATIVE,
                    span,
                    format!("`{path}` is gone; delete its standing entry"),
                );
            }
        }
    }
}
