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
            let reconstructed = self.reconstruct_condition_tree(normalized);
            let next = normalize_expr(self.ctx, reconstructed, NormalizeMode::Predicate);
            if next == current {
                return next;
            }
            current = next;
        }

        current
    }

    fn reconstruct_condition_tree(&self, expr: CExpr) -> CExpr {
        let rewritten = match expr {
            CExpr::Unary { op, operand } => CExpr::Unary {
                op,
                operand: Box::new(self.reconstruct_condition_tree(*operand)),
            },
            CExpr::Binary { op, left, right } => CExpr::Binary {
                op,
                left: Box::new(self.reconstruct_condition_tree(*left)),
                right: Box::new(self.reconstruct_condition_tree(*right)),
            },
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => CExpr::Ternary {
                cond: Box::new(self.reconstruct_condition_tree(*cond)),
                then_expr: Box::new(self.reconstruct_condition_tree(*then_expr)),
                else_expr: Box::new(self.reconstruct_condition_tree(*else_expr)),
            },
            CExpr::Cast { ty, expr } => CExpr::Cast {
                ty,
                expr: Box::new(self.reconstruct_condition_tree(*expr)),
            },
            CExpr::Call { func, args } => CExpr::Call {
                func: Box::new(self.reconstruct_condition_tree(*func)),
                args: args
                    .into_iter()
                    .map(|arg| self.reconstruct_condition_tree(arg))
                    .collect(),
            },
            CExpr::Subscript { base, index } => CExpr::Subscript {
                base: Box::new(self.reconstruct_condition_tree(*base)),
                index: Box::new(self.reconstruct_condition_tree(*index)),
            },
            CExpr::Member { base, member } => CExpr::Member {
                base: Box::new(self.reconstruct_condition_tree(*base)),
                member,
            },
            CExpr::PtrMember { base, member } => CExpr::PtrMember {
                base: Box::new(self.reconstruct_condition_tree(*base)),
                member,
            },
            CExpr::Sizeof(inner) => {
                CExpr::Sizeof(Box::new(self.reconstruct_condition_tree(*inner)))
            }
            CExpr::AddrOf(inner) => {
                CExpr::AddrOf(Box::new(self.reconstruct_condition_tree(*inner)))
            }
            CExpr::Deref(inner) => CExpr::Deref(Box::new(self.reconstruct_condition_tree(*inner))),
            CExpr::Comma(items) => CExpr::Comma(
                items
                    .into_iter()
                    .map(|item| self.reconstruct_condition_tree(item))
                    .collect(),
            ),
            CExpr::Paren(inner) => CExpr::Paren(Box::new(self.reconstruct_condition_tree(*inner))),
            other => other,
        };

        self.ctx
            .try_reconstruct_condition(&rewritten)
            .unwrap_or(rewritten)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, CExpr, CType, UnaryOp};

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

    #[test]
    fn simplify_condition_expr_reconstructs_nested_signed_predicate_scaffold() {
        let ctx = FoldingContext::new(64);
        let simplifier = PredicateSimplifier::new(&ctx);

        let expr = CExpr::binary(
            BinaryOp::BitXor,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::And,
                CExpr::binary(BinaryOp::Ne, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
                CExpr::binary(
                    BinaryOp::Eq,
                    CExpr::Var("of_1".to_string()),
                    CExpr::binary(BinaryOp::Lt, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
                ),
            ),
        );

        let simplified = simplifier.simplify_condition_expr(expr);
        let expected = CExpr::binary(
            BinaryOp::BitXor,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(BinaryOp::Gt, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
        );
        assert_eq!(simplified, expected);
    }

    #[test]
    fn simplify_condition_expr_reconstructs_nested_cast_paren_signed_predicate_scaffold() {
        let ctx = FoldingContext::new(64);
        let simplifier = PredicateSimplifier::new(&ctx);

        let expr = CExpr::binary(
            BinaryOp::BitXor,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::Paren(Box::new(CExpr::binary(
                BinaryOp::And,
                CExpr::binary(BinaryOp::Ne, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
                CExpr::binary(
                    BinaryOp::Eq,
                    CExpr::Var("of_1".to_string()),
                    CExpr::Paren(Box::new(CExpr::binary(
                        BinaryOp::Lt,
                        CExpr::cast(CType::Int(32), CExpr::Var("a".to_string())),
                        CExpr::cast(CType::Int(32), CExpr::IntLit(0)),
                    ))),
                ),
            ))),
        );

        let simplified = simplifier.simplify_condition_expr(expr);
        let expected = CExpr::binary(
            BinaryOp::BitXor,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::Paren(Box::new(CExpr::binary(
                BinaryOp::Gt,
                CExpr::Var("a".to_string()),
                CExpr::IntLit(0),
            ))),
        );
        assert_eq!(simplified, expected);
    }
}
