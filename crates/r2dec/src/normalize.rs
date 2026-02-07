use crate::ast::CExpr;
use crate::fold::FoldingContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NormalizeMode {
    General,
    Predicate,
}

pub(crate) fn normalize_expr(ctx: &FoldingContext, expr: CExpr, mode: NormalizeMode) -> CExpr {
    match mode {
        NormalizeMode::General | NormalizeMode::Predicate => ctx.simplify_predicate_expr(expr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, UnaryOp};

    #[test]
    fn normalization_is_idempotent_for_predicates() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::unary(
            UnaryOp::Not,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
                CExpr::IntLit(0),
            ),
        );

        let once = normalize_expr(&ctx, expr.clone(), NormalizeMode::Predicate);
        let twice = normalize_expr(&ctx, once.clone(), NormalizeMode::Predicate);
        assert_eq!(once, twice, "Predicate normalization must be idempotent");
    }
}
