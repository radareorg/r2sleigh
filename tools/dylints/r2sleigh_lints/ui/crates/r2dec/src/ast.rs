#![allow(dead_code)]

// The module that owns the observation node's canonical form builds it.

enum CStmt {
    Observed { ids: Vec<u32>, stmt: Box<CStmt> },
    Empty,
}

impl CStmt {
    fn observe_all(ids: Vec<u32>, stmt: CStmt) -> Self {
        if ids.is_empty() {
            return stmt;
        }
        Self::Observed {
            ids,
            stmt: Box::new(stmt),
        }
    }
}

fn main() {
    let _ = CStmt::observe_all(vec![1], CStmt::Empty);
}
