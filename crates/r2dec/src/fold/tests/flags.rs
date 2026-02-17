use super::*;

#[test]
fn expr_contains_opaque_temp_uses_visit_over_nested_nodes() {
    let ctx = FoldingContext::new(64);

    let nested = CExpr::binary(
        BinaryOp::And,
        CExpr::Var("zf_1".to_string()),
        CExpr::Paren(Box::new(CExpr::Var("var_12".to_string()))),
    );
    assert!(ctx.expr_contains_opaque_temp(&nested));

    let clean = CExpr::binary(
        BinaryOp::Eq,
        CExpr::Var("eax_1".to_string()),
        CExpr::IntLit(0),
    );
    assert!(!ctx.expr_contains_opaque_temp(&clean));
}

#[test]
fn expr_contains_unresolved_memory_uses_visit_over_nested_nodes() {
    let ctx = FoldingContext::new(64);

    let deref_nested = CExpr::binary(
        BinaryOp::Or,
        CExpr::Var("zf_1".to_string()),
        CExpr::Paren(Box::new(CExpr::Deref(Box::new(CExpr::Var(
            "tmp:20_1".to_string(),
        ))))),
    );
    assert!(ctx.expr_contains_unresolved_memory(&deref_nested));

    let no_deref = CExpr::binary(
        BinaryOp::Ne,
        CExpr::Var("x_1".to_string()),
        CExpr::Var("y_1".to_string()),
    );
    assert!(!ctx.expr_contains_unresolved_memory(&no_deref));
}
