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
        const MAX_SIMPLIFY_PASSES: usize = 4;

        let mut current = expr;
        for _ in 0..MAX_SIMPLIFY_PASSES {
            let mut visited = HashSet::new();
            let expanded = self.ctx.expand_predicate_vars(&current, 0, &mut visited);
            let normalized = normalize_expr(self.ctx, expanded, NormalizeMode::Predicate);
            let reconstructed = self
                .ctx
                .try_reconstruct_condition(&normalized)
                .unwrap_or(normalized);
            let next = normalize_expr(self.ctx, reconstructed, NormalizeMode::Predicate);
            if next == current {
                return next;
            }
            current = next;
        }

        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, UnaryOp};

    #[test]
    fn simplify_condition_expr_reaches_stable_fixed_point() {
        let ctx = FoldingContext::new(64);
        let simplifier = PredicateSimplifier::new(&ctx);

        let expr = CExpr::unary(
            UnaryOp::Not,
            CExpr::binary(BinaryOp::Eq, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
        );

        let once = simplifier.simplify_condition_expr(expr);
        let twice = simplifier.simplify_condition_expr(once.clone());
        assert_eq!(
            once,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0))
        );
        assert_eq!(once, twice);
    }
}
