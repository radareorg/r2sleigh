use std::collections::HashSet;

use crate::ast::CExpr;
use crate::fold::FoldingContext;
use crate::normalize::{NormalizeMode, normalize_expr};

pub(crate) struct PredicateSimplifier<'a, 'o> {
    ctx: &'a FoldingContext<'o>,
}

impl<'a, 'o> PredicateSimplifier<'a, 'o> {
    pub(crate) fn new(ctx: &'a FoldingContext<'o>) -> Self {
        Self { ctx }
    }

    pub(crate) fn simplify_condition_expr(&self, expr: CExpr) -> CExpr {
        let mut visited = HashSet::new();
        let expanded = self.ctx.expand_predicate_vars(&expr, 0, &mut visited);
        let normalized = normalize_expr(self.ctx, expanded, NormalizeMode::Predicate);
        let reconstructed = self
            .ctx
            .try_reconstruct_condition(&normalized)
            .unwrap_or(normalized);
        normalize_expr(self.ctx, reconstructed, NormalizeMode::Predicate)
    }
}
