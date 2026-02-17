use super::*;
use std::collections::HashSet;

#[test]
fn collect_expr_reads_visits_nested_children() {
    let ctx = FoldingContext::new(64);
    let expr = CExpr::binary(
        BinaryOp::Add,
        CExpr::Var("a_1".to_string()),
        CExpr::call(
            CExpr::Var("callee_0".to_string()),
            vec![
                CExpr::Deref(Box::new(CExpr::Var("b_2".to_string()))),
                CExpr::Paren(Box::new(CExpr::cast(
                    CType::Int(32),
                    CExpr::Var("c_3".to_string()),
                ))),
            ],
        ),
    );

    let mut reads = HashSet::new();
    ctx.collect_expr_reads(&expr, &mut reads);

    assert!(reads.contains("a_1"));
    assert!(reads.contains("callee_0"));
    assert!(reads.contains("b_2"));
    assert!(reads.contains("c_3"));
}

#[test]
fn expr_is_pure_detects_side_effect_nodes() {
    let ctx = FoldingContext::new(64);
    let pure_expr = CExpr::binary(
        BinaryOp::Mul,
        CExpr::Var("x_1".to_string()),
        CExpr::IntLit(4),
    );
    assert!(ctx.expr_is_pure(&pure_expr));

    let call_expr = CExpr::call(
        CExpr::Var("foo".to_string()),
        vec![CExpr::Var("x_1".to_string())],
    );
    assert!(!ctx.expr_is_pure(&call_expr));

    let assign_expr = CExpr::assign(CExpr::Var("x_1".to_string()), CExpr::IntLit(7));
    assert!(!ctx.expr_is_pure(&assign_expr));
}
