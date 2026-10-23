//! `if (c) { f(); } else { rest }` with `f` declared never to return is `if (c) { f(); } rest`, and with
//! the arms the other way round `if (!c) { f(); } rest`: `doc/adr-structure-dominator-tree.md`, "the noreturn guard".

use super::condition::{Marks, as_atoms, negated};
use super::shape::Evidence;
use crate::ast::{CStmt, RenderObservationId};

/// What the rewrites may use: the evidence, the markers a negated test is written over, and a count.
struct Guard<'a, 'e> {
    ev: &'a Evidence<'e>,
    marks: &'a mut dyn Marks,
    rewritten: usize,
}

/// Rewrite every such `if` of `body` and say how many were rewritten. O(statements): each statement
/// is visited once, and the statements a guard frees join the sequence the `if` sits in.
pub(crate) fn guard(body: &mut CStmt, ev: &Evidence<'_>, marks: &mut dyn Marks) -> usize {
    let mut guard = Guard {
        ev,
        marks,
        rewritten: 0,
    };
    guard.slot(body);
    guard.rewritten
}

impl Guard<'_, '_> {
    /// A statement where one statement stands (an arm, a loop body): a guard there brings its rest.
    fn slot(&mut self, stmt: &mut CStmt) {
        if let CStmt::Block(stmts) = stmt {
            return self.sequence(stmts);
        }
        let mut stmts = vec![std::mem::replace(stmt, CStmt::Empty)];
        self.sequence(&mut stmts);
        *stmt = super::tails::one(stmts);
    }

    /// The statements of a body in order, each rewritten and followed by what it frees.
    fn sequence(&mut self, stmts: &mut Vec<CStmt>) {
        for mut stmt in std::mem::take(stmts) {
            let rest = self.visit(&mut stmt, &[]);
            stmts.push(stmt);
            stmts.extend(rest.into_iter().flatten());
        }
    }

    /// `stmt`'s parts rewritten; for a guard, the statements it frees. `ids` are the markers of the
    /// statement the `if` is observed under, which a negated test is written over.
    fn visit(&mut self, stmt: &mut CStmt, ids: &[RenderObservationId]) -> Option<Vec<CStmt>> {
        match stmt {
            CStmt::Observed { ids, stmt } => self.visit(stmt, ids.ids()),
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                // Both arms are rewritten first: a guard inside one can be what makes it end in the call.
                self.slot(then_body);
                let arm = else_body.as_mut()?;
                self.slot(arm);
                match (
                    ends_in_never_return(then_body, self.ev),
                    ends_in_never_return(arm, self.ev),
                ) {
                    (true, false) => {
                        self.rewritten += 1;
                        Some(statements(*else_body.take()?))
                    }
                    // The call is on the else arm: the guard tests the opposite, over the test's own atom.
                    (false, true) if !ids.is_empty() => {
                        let test = std::mem::replace(cond, crate::ast::CExpr::IntLit(0));
                        *cond = negated(as_atoms(test, ids.iter().copied(), self.marks));
                        self.rewritten += 1;
                        let rest = std::mem::replace(&mut **then_body, *else_body.take()?);
                        Some(statements(rest))
                    }
                    // Both arms end in such a call, or neither: nothing continues past one.
                    _ => None,
                }
            }
            CStmt::Block(stmts) => {
                self.sequence(stmts);
                None
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                self.slot(body);
                None
            }
            CStmt::Switch { cases, default, .. } => {
                for body in cases
                    .iter_mut()
                    .map(|case| &mut case.body)
                    .chain(default.iter_mut())
                {
                    self.sequence(body);
                }
                None
            }
            _ => None,
        }
    }
}

/// The statements of an arm, as the body they join.
fn statements(arm: CStmt) -> Vec<CStmt> {
    match arm {
        CStmt::Block(stmts) => stmts,
        CStmt::Empty => Vec::new(),
        other => vec![other],
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
    use crate::ast::{CExpr, UnaryOp};
    use crate::structure::certify::{StatementRole, Violation, certify};
    use crate::structure::support::{
        Fixture, at, branch, cfg, cond, cond_branch, exit, expr, never_returns,
    };
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::domtree::DomTree;

    fn evidence<'a>(never_returns: &'a dyn Fn(&CStmt) -> bool) -> Evidence<'a> {
        Evidence {
            never_returns,
            distinct_return: &|_| false,
        }
    }

    fn guarded(body: &mut CStmt, never_returns: &dyn Fn(&CStmt) -> bool) -> usize {
        guard(body, &evidence(never_returns), &mut Fixture)
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

    fn certificate(body: &CStmt, cfg: &CFG) -> crate::structure::certify::ControlCertificate {
        certify(
            body,
            cfg,
            &DomTree::compute(cfg),
            0x10,
            &Fixture,
            &|_| None,
            &|stmt| match never_returns(stmt) {
                true => StatementRole::Ends,
                false => StatementRole::Plain,
            },
        )
    }

    fn certified(body: &CStmt, cfg: &CFG) -> bool {
        certificate(body, cfg).ok()
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
    fn a_then_arm_ending_in_a_call_that_never_returns_frees_the_else_and_still_certifies() {
        let cfg = arms(BlockTerminator::None);
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, expr()), at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x40, ret())],
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 1);
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
        assert_eq!(guarded(&mut body, &never_returns), 2);
        trace(&body, &mut after);
        // The same leaves in the same order; no else arm holds anything now.
        assert_eq!(before, after);
        assert_eq!(count_elses(&body), 0);
    }

    #[test]
    fn a_call_the_evidence_does_not_declare_never_to_return_keeps_its_else() {
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x40, ret())],
        )]);
        let kept = body.clone();
        assert_eq!(guarded(&mut body, &|_| false), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn an_else_arm_that_never_returns_is_a_guard_on_the_negated_test_and_the_machine_s_edges_hold()
    {
        // 0x10 goes to 0x20 on true and to 0x30, which exits, on false: `if (!c) exit(); <0x20>`.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, BlockTerminator::None),
                (0x40, BlockTerminator::Return),
            ],
        );
        let mut body = CStmt::Block(vec![
            at(
                0x10,
                CStmt::if_stmt(
                    cond(),
                    CStmt::Block(vec![at(0x20, expr())]),
                    Some(CStmt::Block(vec![at(0x30, exit())])),
                ),
            ),
            at(0x40, ret()),
        ]);
        assert!(certified(&body, &cfg));
        assert_eq!(guarded(&mut body, &never_returns), 1);
        assert_eq!(count_elses(&body), 0);
        let certificate = certificate(&body, &cfg);
        assert!(certificate.ok(), "{certificate}");
        // The test is the opposite of the machine's true edge, over an atom of the test's own block.
        let CStmt::Block(stmts) = &mut body else {
            panic!("a block");
        };
        let CStmt::Observed { stmt, .. } = &mut stmts[0] else {
            panic!("the observed if");
        };
        let CStmt::If { cond, .. } = &mut **stmt else {
            panic!("an if");
        };
        let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = &*cond
        else {
            panic!("a negation: {cond:?}");
        };
        let CExpr::Observed { ids, .. } = &**operand else {
            panic!("a marked atom: {operand:?}");
        };
        assert_eq!(ids.iter().next().map(|id| id.index() % 1000), Some(0x10));
        // The same arms swapped under the unnegated test are the other branch, which the machine does not run.
        *cond = CExpr::int(1);
        let wrong = self::certificate(&CStmt::Block(stmts.clone()), &cfg);
        assert!(
            (wrong.violations.iter())
                .any(|violation| matches!(violation, Violation::EdgeMismatch { block: 0x10, .. })),
            "{wrong}"
        );
    }

    #[test]
    fn an_if_nothing_observed_has_no_atom_to_negate_and_keeps_its_else() {
        let mut body = CStmt::Block(vec![CStmt::if_stmt(
            cond(),
            CStmt::Block(vec![at(0x20, expr())]),
            Some(CStmt::Block(vec![at(0x30, exit())])),
        )]);
        let kept = body.clone();
        assert_eq!(guarded(&mut body, &never_returns), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn two_arms_that_never_return_leave_neither_as_the_guard() {
        // Control never reaches past either arm, so nothing continues and the `if` stays whole.
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x30, exit())],
        )]);
        let kept = body.clone();
        assert_eq!(guarded(&mut body, &never_returns), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn a_guard_the_machine_does_not_have_fails_the_certificate() {
        // 0x20 goes on to 0x40, as the diamond's text says. Evidence that claimed its call never returns
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
        let call = || CStmt::Expr(CExpr::IntLit(99));
        let mut body = CStmt::Block(vec![
            branching(CStmt::Block(vec![at(0x20, call())]), vec![at(0x30, expr())]),
            at(0x40, ret()),
        ]);
        assert!(certified(&body, &cfg));
        assert_eq!(guarded(&mut body, &|stmt| *stmt == call()), 1);
        assert!(!certified(&body, &cfg));
    }
}
