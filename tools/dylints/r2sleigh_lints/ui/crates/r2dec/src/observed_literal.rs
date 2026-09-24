#![allow(dead_code)]

// An observation node built by hand skips the fusion that keeps one
// occurrence's ids on one node, and wrapping an observed node rebuilds the
// one-wrapper-per-id chain whose depth grew with the ids it carried.

enum CExpr {
    Observed { ids: Vec<u32>, expr: Box<CExpr> },
    IntLit(i64),
}

enum CStmt {
    Observed { ids: Vec<u32>, stmt: Box<CStmt> },
    Expr(CExpr),
}

impl CStmt {
    fn rewrite(self) -> Self {
        match self {
            Self::Observed { ids, stmt } => Self::Observed { ids, stmt },
            other => other,
        }
    }
}

fn mark(ids: Vec<u32>, expr: CExpr) -> CStmt {
    CStmt::Expr(CExpr::Observed {
        ids,
        expr: Box::new(expr),
    })
}

fn main() {
    let stmt = mark(vec![1], CExpr::IntLit(0)).rewrite();
    // Reading one is not building one.
    if let CStmt::Observed { ids, .. } = &stmt {
        let _ = ids.len();
    }
}
