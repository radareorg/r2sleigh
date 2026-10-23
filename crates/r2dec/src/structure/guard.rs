//! `if (c) { f(); } else { rest }` with `f` declared never to return is `if (c) { f(); } rest`:
//! `doc/adr-structure-dominator-tree.md`, "the noreturn guard".

use super::shape::Evidence;
use crate::ast::CStmt;

/// Rewrite every such `if` of `body` and say how many were rewritten. O(statements): each statement
/// is visited once, and a guard's else statements join the sequence it sits in without a second visit.
pub(crate) fn guard(body: &mut CStmt, ev: &Evidence<'_>) -> usize {
    let mut rewritten = 0;
    slot(body, ev, &mut rewritten);
    rewritten
}

/// A statement where one statement stands (an arm, a loop body): a guard there brings its rest.
fn slot(stmt: &mut CStmt, ev: &Evidence<'_>, rewritten: &mut usize) {
    if let CStmt::Block(stmts) = stmt {
        return sequence(stmts, ev, rewritten);
    }
    let mut stmts = vec![std::mem::replace(stmt, CStmt::Empty)];
    sequence(&mut stmts, ev, rewritten);
    *stmt = super::tails::one(stmts);
}

/// The statements of a body in order; a guard's rest is visited next, in the same body.
fn sequence(stmts: &mut Vec<CStmt>, ev: &Evidence<'_>, rewritten: &mut usize) {
    let mut pending = std::mem::take(stmts).into_iter().rev().collect::<Vec<_>>();
    while let Some(mut stmt) = pending.pop() {
        let rest = visit(&mut stmt, ev, rewritten);
        stmts.push(stmt);
        if let Some(rest) = rest {
            *rewritten += 1;
            pending.extend(rest.into_iter().rev());
        }
    }
}

/// `stmt`'s parts rewritten; for a guard, its else statements taken out for the body to continue with.
fn visit(stmt: &mut CStmt, ev: &Evidence<'_>, rewritten: &mut usize) -> Option<Vec<CStmt>> {
    match stmt {
        CStmt::Observed { stmt, .. } => visit(stmt, ev, rewritten),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            // The arm is rewritten first: a guard inside it can be what makes it end in the call.
            slot(then_body, ev, rewritten);
            if else_body.is_some() && ends_in_never_return(then_body, ev) {
                return match *else_body.take()? {
                    CStmt::Block(rest) => Some(rest),
                    CStmt::Empty => Some(Vec::new()),
                    other => Some(vec![other]),
                };
            }
            if let Some(else_body) = else_body {
                slot(else_body, ev, rewritten);
            }
            None
        }
        CStmt::Block(stmts) => {
            sequence(stmts, ev, rewritten);
            None
        }
        CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            slot(body, ev, rewritten);
            None
        }
        CStmt::Switch { cases, default, .. } => {
            for body in cases
                .iter_mut()
                .map(|case| &mut case.body)
                .chain(default.iter_mut())
            {
                sequence(body, ev, rewritten);
            }
            None
        }
        _ => None,
    }
}

/// Whether the last statement of `stmt` is a call to a callee declared never to return, so that
/// control cannot leave `stmt` by reaching its end.
fn ends_in_never_return(stmt: &CStmt, ev: &Evidence<'_>) -> bool {
    match stmt {
        CStmt::Observed { stmt, .. } => ends_in_never_return(stmt, ev),
        CStmt::Block(stmts) => stmts
            .iter()
            .rev()
            .find(|stmt| !matches!(stmt.unobserved(), CStmt::Empty | CStmt::Comment(_)))
            .is_some_and(|last| ends_in_never_return(last, ev)),
        CStmt::Expr(_) => (ev.never_returns)(stmt),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::CExpr;
    use crate::structure::certify::{Placed, StatementRole, certify};
    use crate::structure::support::{
        ByBlock, at, branch, cfg, cond, cond_branch, exit, expr, never_returns,
    };
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::domtree::DomTree;

    fn evidence<'a>(never_returns: &'a dyn Fn(&CStmt) -> bool) -> Evidence<'a> {
        Evidence {
            never_returns,
            distinct_return: &|_| false,
        }
    }

    fn ret() -> CStmt {
        CStmt::Return(Some(CExpr::IntLit(7)))
    }

    /// `if (c) { <then> } else { <rest> }` observed under the test block 0x10.
    fn branching(then_body: CStmt, rest: Vec<CStmt>) -> CStmt {
        at(
            0x10,
            CStmt::if_stmt(cond(), then_body, Some(CStmt::Block(rest))),
        )
    }

    /// 0x10 tests; 0x20 is the arm taken, 0x30 the one not; 0x40 follows 0x30.
    fn arms(taken: BlockTerminator) -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, taken),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    fn certified(body: &CStmt, cfg: &CFG) -> bool {
        struct Whole;
        impl Placed for Whole {
            fn block_of(&self, id: crate::ast::RenderObservationId) -> Option<u64> {
                ByBlock.block_of(id)
            }
            fn statement_of(
                &self,
                id: crate::ast::RenderObservationId,
            ) -> Option<crate::ast::RenderObservationId> {
                ByBlock.statement_of(id)
            }
            fn written(&self) -> usize {
                0
            }
            fn edge_copy(&self, _: crate::ast::RenderObservationId) -> bool {
                false
            }
        }
        certify(
            body,
            cfg,
            &DomTree::compute(cfg),
            0x10,
            &Whole,
            &|_| None,
            &|stmt| match never_returns(stmt) {
                true => StatementRole::Ends,
                false => StatementRole::Plain,
            },
        )
        .ok()
    }

    /// The tree's leaf statements in the order the text runs them, ignoring the `if`'s braces.
    fn trace(stmt: &CStmt, into: &mut Vec<&'static str>) {
        match stmt.unobserved() {
            CStmt::Block(stmts) => stmts.iter().for_each(|stmt| trace(stmt, into)),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                into.push("if");
                trace(then_body, into);
                if let Some(else_body) = else_body {
                    trace(else_body, into);
                }
            }
            CStmt::Return(_) => into.push("return"),
            other if never_returns(other) => into.push("exit"),
            _ => into.push("stmt"),
        }
    }

    #[test]
    fn a_then_arm_ending_in_a_call_that_never_returns_frees_the_else_and_still_certifies() {
        let cfg = arms(BlockTerminator::None);
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, expr()), at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x40, ret())],
        )]);
        assert_eq!(guard(&mut body, &evidence(&never_returns)), 1);
        let CStmt::Block(stmts) = &body else {
            panic!("a block");
        };
        let CStmt::Observed { stmt, .. } = &stmts[0] else {
            panic!("the observed if");
        };
        assert!(matches!(
            &**stmt,
            CStmt::If {
                else_body: None,
                ..
            }
        ));
        assert_eq!(stmts.len(), 3, "the else's two statements follow the if");
        assert!(certified(&body, &cfg));
    }

    #[test]
    fn the_statements_run_in_the_order_the_else_arm_had_them() {
        let nested = |rest: Vec<CStmt>| branching(CStmt::Block(vec![at(0x20, exit())]), rest);
        let mut body = CStmt::Block(vec![nested(vec![
            at(0x30, expr()),
            nested(vec![at(0x30, expr()), at(0x40, ret())]),
            at(0x30, expr()),
        ])]);
        let (mut before, mut after) = (Vec::new(), Vec::new());
        trace(&body, &mut before);
        assert_eq!(guard(&mut body, &evidence(&never_returns)), 2);
        trace(&body, &mut after);
        // The same leaves in the same order; no else arm holds anything now.
        assert_eq!(before, after);
        assert_eq!(count_elses(&body), 0);
    }

    fn count_elses(stmt: &CStmt) -> usize {
        match stmt.unobserved() {
            CStmt::Block(stmts) => stmts.iter().map(count_elses).sum(),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_elses(then_body)
                    + else_body.as_deref().map_or(0, |body| 1 + count_elses(body))
            }
            _ => 0,
        }
    }

    #[test]
    fn a_call_the_evidence_does_not_declare_never_to_return_keeps_its_else() {
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x40, ret())],
        )]);
        let kept = body.clone();
        assert_eq!(guard(&mut body, &evidence(&|_| false)), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn an_else_arm_that_never_returns_is_not_a_guard() {
        // The then arm returns; the polarity a guard of the other arm needs is not the test's.
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(0x20, ret())]),
                Some(CStmt::Block(vec![at(0x30, exit())])),
            ),
        )]);
        let kept = body.clone();
        assert_eq!(guard(&mut body, &evidence(&never_returns)), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn a_guard_the_machine_does_not_have_fails_the_certificate() {
        // 0x20 goes on to 0x40, as the diamond's text says. Evidence that claimed it never returns
        // would write 0x30 after it, an edge 0x20 does not have, and the stage is reverted whole.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let mut body = CStmt::Block(vec![
            branching(CStmt::Block(vec![at(0x20, expr())]), vec![at(0x30, expr())]),
            at(0x40, ret()),
        ]);
        assert!(certified(&body, &cfg));
        assert_eq!(guard(&mut body, &evidence(&|_| true)), 1);
        assert!(!certified(&body, &cfg));
    }
}
