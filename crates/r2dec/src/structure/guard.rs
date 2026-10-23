//! `if (c) { f(); } else { rest }` with `f` declared never to return is `if (c) { f(); } rest`, and with
//! the arms the other way round `if (!c) { f(); } rest`: `doc/adr-structure-dominator-tree.md`, "the noreturn guard".

use super::condition::{Marks, as_atoms, negated};
use super::shape::Evidence;
use crate::ast::{CExpr, CStmt};

/// A place the pass has still to visit, borrowed from the tree.
enum Slot<'a> {
    /// Where one statement stands: an arm, a loop body.
    One(&'a mut CStmt),
    /// Statements in sequence: a block, a case.
    Many(&'a mut Vec<CStmt>),
}

/// What the rewrites may use: the evidence, the markers a negated test is written over, and a count.
struct Guard<'a, 'e> {
    ev: &'a Evidence<'e>,
    marks: &'a mut dyn Marks,
    rewritten: usize,
}

/// Rewrite every such `if` of `body` and say how many were rewritten. O(statements) with no recursion:
/// the places to visit are a stack, and a guard's freed statements join the sequence being rebuilt.
pub(crate) fn guard(body: &mut CStmt, ev: &Evidence<'_>, marks: &mut dyn Marks) -> usize {
    let mut guard = Guard {
        ev,
        marks,
        rewritten: 0,
    };
    // Each pop visits one place and pushes only places inside it, so the tree's finite height ends it.
    let mut pending = vec![Slot::One(body)];
    while let Some(slot) = pending.pop() {
        match slot {
            Slot::One(stmt) => guard.one(stmt, &mut pending),
            Slot::Many(stmts) => guard.many(stmts, &mut pending),
        }
    }
    guard.rewritten
}

impl Guard<'_, '_> {
    /// A statement where one statement stands: a guard there brings its rest, in a block of its own.
    fn one<'a>(&mut self, stmt: &'a mut CStmt, pending: &mut Vec<Slot<'a>>) {
        match stmt {
            CStmt::Block(stmts) => self.many(stmts, pending),
            stmt => {
                let mut stmts = vec![std::mem::replace(stmt, CStmt::Empty)];
                self.free(&mut stmts);
                *stmt = super::tails::one(stmts);
                match stmt {
                    CStmt::Block(stmts) => stmts.iter_mut().for_each(|stmt| enter(stmt, pending)),
                    stmt => enter(stmt, pending),
                }
            }
        }
    }

    /// The statements of a body in order, each followed by what it frees.
    fn many<'a>(&mut self, stmts: &'a mut Vec<CStmt>, pending: &mut Vec<Slot<'a>>) {
        self.free(stmts);
        stmts.iter_mut().for_each(|stmt| enter(stmt, pending));
    }

    /// `stmts` with the statements each guard frees after it. A freed statement is visited in its turn
    /// as one of the sequence, so a chain of guards is read in one pass and moved once.
    fn free(&mut self, stmts: &mut Vec<CStmt>) {
        let mut todo = std::mem::take(stmts);
        todo.reverse();
        stmts.reserve(todo.len());
        while let Some(mut stmt) = todo.pop() {
            let freed = self.freed(&mut stmt);
            stmts.push(stmt);
            todo.extend(freed.into_iter().flat_map(Vec::into_iter).rev());
        }
    }

    /// For a guard, `stmt` rewritten and the statements it frees.
    fn freed(&mut self, stmt: &mut CStmt) -> Option<Vec<CStmt>> {
        // The markers of the `if`'s own observation, which a negated test is written over.
        let (stmt, ids) = match stmt {
            CStmt::Observed { ids, stmt } => (&mut **stmt, ids.ids()),
            stmt => (stmt, &[][..]),
        };
        let CStmt::If {
            cond,
            then_body,
            else_body,
        } = stmt
        else {
            return None;
        };
        let ends = (
            ends_in_never_return(then_body, self.ev),
            ends_in_never_return(else_body.as_deref()?, self.ev),
        );
        match ends {
            (true, false) => {
                self.rewritten += 1;
                Some(statements(*else_body.take()?))
            }
            // The call is on the else arm: the guard tests the opposite, over the test's own atom.
            (false, true) if !ids.is_empty() => {
                let test = std::mem::replace(cond, CExpr::IntLit(0));
                *cond = negated(as_atoms(test, ids.iter().copied(), self.marks));
                self.rewritten += 1;
                let rest = std::mem::replace(&mut **then_body, *else_body.take()?);
                Some(statements(rest))
            }
            // Both arms end in such a call, or neither: nothing continues past one.
            _ => None,
        }
    }
}

/// The places inside `stmt` to visit: arms, loop bodies, blocks, cases.
fn enter<'a>(mut stmt: &'a mut CStmt, pending: &mut Vec<Slot<'a>>) {
    while let CStmt::Observed { stmt: inner, .. } = stmt {
        stmt = inner;
    }
    match stmt {
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            pending.push(Slot::One(then_body));
            pending.extend(else_body.as_deref_mut().map(Slot::One));
        }
        CStmt::Block(stmts) => pending.push(Slot::Many(stmts)),
        CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            pending.push(Slot::One(body));
        }
        CStmt::Switch { cases, default, .. } => pending.extend(
            (cases.iter_mut().map(|case| &mut case.body))
                .chain(default)
                .map(Slot::Many),
        ),
        _ => {}
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
/// control cannot leave `stmt` by reaching its end. Walks only the nested blocks at the arm's end.
fn ends_in_never_return(mut stmt: &CStmt, ev: &Evidence<'_>) -> bool {
    loop {
        match stmt {
            CStmt::Observed { stmt: inner, .. } => stmt = inner,
            CStmt::Block(stmts) => {
                let last = stmts
                    .iter()
                    .rev()
                    .find(|stmt| !matches!(stmt.unobserved(), CStmt::Empty | CStmt::Comment(_)));
                match last {
                    Some(last) => stmt = last,
                    None => return false,
                }
            }
            CStmt::Expr(_) => return (ev.never_returns)(stmt),
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, CExpr, UnaryOp, test_render_observation_id};
    use crate::structure::certify::{StatementRole, Violation, certify};
    use crate::structure::support::{
        Fixture, at, branch, cfg, cond, cond_branch, exit, expr, never_returns,
    };
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::domtree::DomTree;

    fn evidence<'a>(never_returns: &'a dyn Fn(&CStmt) -> bool) -> Evidence<'a> {
        Evidence {
            never_returns,
            declares_noreturn: true,
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
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                count_elses(body)
            }
            CStmt::Switch { cases, default, .. } => (cases.iter().map(|case| &case.body))
                .chain(default)
                .flatten()
                .map(count_elses)
                .sum(),
            _ => 0,
        }
    }

    /// The statements of a block.
    fn top(stmt: &CStmt) -> &[CStmt] {
        let CStmt::Block(stmts) = stmt.unobserved() else {
            panic!("a block: {stmt:?}");
        };
        stmts
    }

    /// The then and else arms of an `if`, looking through the observation around it.
    fn arms_of(stmt: &CStmt) -> (&CStmt, Option<&CStmt>) {
        let CStmt::If {
            then_body,
            else_body,
            ..
        } = stmt.unobserved()
        else {
            panic!("an if: {stmt:?}");
        };
        (then_body, else_body.as_deref())
    }

    /// `if (c) { exit } else { a; b }`, a guard that frees two statements.
    fn a_guard() -> CStmt {
        branching(
            CStmt::Block(vec![at(0x20, exit())]),
            vec![at(0x30, expr()), at(0x40, expr())],
        )
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
    fn a_chain_on_the_swapped_arm_is_negated_by_swapping_its_connective() {
        let atom = |block: u32| {
            CExpr::observe_one(
                test_render_observation_id(block),
                CExpr::int(i64::from(block)),
            )
        };
        let chain = CExpr::binary(BinaryOp::And, atom(0x10), atom(0x20));
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(
                chain,
                CStmt::Block(vec![at(0x30, expr())]),
                Some(CStmt::Block(vec![at(0x40, exit())])),
            ),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 1);
        let CStmt::Block(stmts) = &body else {
            panic!("a block");
        };
        let CStmt::Observed { stmt, .. } = &stmts[0] else {
            panic!("the observed if");
        };
        let CStmt::If { cond, .. } = &**stmt else {
            panic!("an if");
        };
        let not = |block| CExpr::unary(UnaryOp::Not, atom(block));
        assert_eq!(*cond, CExpr::binary(BinaryOp::Or, not(0x10), not(0x20)));
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

    #[test]
    fn a_guard_inside_an_arm_that_is_kept_is_rewritten_where_it_stands() {
        // Neither outer arm ends in the call, so the outer `if` keeps its else; the guards inside are rewritten.
        let inner = |block: u64| {
            at(
                block,
                CStmt::if_stmt(
                    cond(),
                    CStmt::Block(vec![at(block + 1, exit())]),
                    Some(CStmt::Block(vec![at(block + 2, expr())])),
                ),
            )
        };
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(0x20, expr()), inner(0x20)]),
                Some(CStmt::Block(vec![inner(0x30)])),
            ),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 2);
        assert_eq!(count_elses(&body), 1);
        let (then_body, else_body) = arms_of(&top(&body)[0]);
        // The rest each guard frees stands after it, inside the arm it was in.
        assert_eq!(top(then_body).len(), 3);
        assert_eq!(top(else_body.expect("the else")).len(), 2);
    }

    #[test]
    fn an_arm_with_nothing_in_it_does_not_end_in_a_call() {
        // `if (c) {} else { rest }` is not `if (c) {} rest`: an empty arm falls to the end, it does not leave.
        for empty in [
            CStmt::Block(Vec::new()),
            CStmt::Empty,
            CStmt::Block(vec![CStmt::Empty, CStmt::Comment("none".into())]),
        ] {
            let mut body = CStmt::Block(vec![at(
                0x10,
                CStmt::if_stmt(
                    cond(),
                    empty,
                    Some(CStmt::Block(vec![at(0x30, expr()), at(0x40, ret())])),
                ),
            )]);
            let kept = body.clone();
            assert_eq!(guarded(&mut body, &never_returns), 0);
            assert_eq!(body, kept);
        }
    }

    #[test]
    fn an_empty_then_arm_beside_an_else_that_exits_is_a_guard_on_the_opposite_test() {
        // 0x10 goes to 0x40 on true, which is the `if`'s empty arm, and to 0x30, which exits, on false.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x40, 0x30)),
                (0x30, BlockTerminator::None),
                (0x40, BlockTerminator::Return),
            ],
        );
        let mut body = CStmt::Block(vec![
            at(
                0x10,
                CStmt::if_stmt(
                    cond(),
                    CStmt::Block(Vec::new()),
                    Some(CStmt::Block(vec![at(0x30, expr()), at(0x30, exit())])),
                ),
            ),
            at(0x40, ret()),
        ]);
        assert!(certified(&body, &cfg));
        assert_eq!(guarded(&mut body, &never_returns), 1);
        let (then_body, else_body) = arms_of(&top(&body)[0]);
        assert_eq!((top(then_body).len(), else_body), (2, None));
        let certificate = certificate(&body, &cfg);
        assert!(certificate.ok(), "{certificate}");
    }

    #[test]
    fn a_comment_or_an_empty_statement_after_the_call_does_not_hide_it() {
        for after in [CStmt::Comment("noreturn".into()), CStmt::Empty] {
            let mut body = CStmt::Block(vec![branching(
                CStmt::Block(vec![at(0x20, exit()), after]),
                vec![at(0x30, expr())],
            )]);
            assert_eq!(guarded(&mut body, &never_returns), 1);
            assert_eq!(count_elses(&body), 0);
        }
    }

    #[test]
    fn a_label_after_the_call_is_a_way_into_the_end_of_the_arm_so_the_else_stays() {
        // A `goto` to the label reaches the arm's end without the call, so control does leave by it.
        let mut body = CStmt::Block(vec![branching(
            CStmt::Block(vec![at(0x20, exit()), CStmt::Label("L".into())]),
            vec![at(0x30, expr())],
        )]);
        let kept = body.clone();
        assert_eq!(guarded(&mut body, &never_returns), 0);
        assert_eq!(body, kept);
    }

    #[test]
    fn an_if_standing_alone_as_an_arm_keeps_the_statements_its_guard_frees() {
        // `if (c) { x } else if (d) { exit } else { r }`: the else arm is the bare `if`, with no block to free into.
        let inner = at(
            0x30,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(0x31, exit())]),
                Some(CStmt::Block(vec![at(0x32, expr())])),
            ),
        );
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(cond(), CStmt::Block(vec![at(0x20, expr())]), Some(inner)),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 1);
        let (_, else_body) = arms_of(&top(&body)[0]);
        let arm = top(else_body.expect("the else"));
        // `if (d) { exit }` and the statement it freed, in a block of their own.
        assert_eq!(arm.len(), 2);
        assert!(matches!(
            arm[0].unobserved(),
            CStmt::If {
                else_body: None,
                ..
            }
        ));
        assert!(matches!(arm[1].unobserved(), CStmt::Expr(_)));
    }

    /// `if (c) { exit } else { a }` with the test `block`'s, its two statements at `block + 1` and `block + 2`.
    fn guard_at(block: u64) -> CStmt {
        at(
            block,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(block + 1, exit())]),
                Some(CStmt::Block(vec![at(block + 2, expr())])),
            ),
        )
    }

    #[test]
    fn a_guard_under_an_if_standing_alone_as_an_arm_is_rewritten() {
        // `if (c) { x } else if (d) { guard } else { y }`: the bare `if` is no guard, and its arms are visited.
        let inner = at(
            0x30,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![guard_at(0x40)]),
                Some(CStmt::Block(vec![at(0x50, expr())])),
            ),
        );
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(cond(), CStmt::Block(vec![at(0x20, expr())]), Some(inner)),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 1);
        assert_eq!(count_elses(&body), 2);
    }

    #[test]
    fn what_an_if_standing_alone_as_an_arm_frees_is_visited_in_its_turn() {
        // `if (c) { x } else if (d) { exit } else { y; if (e) { guard } else { z } }`
        let rest = at(
            0x50,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![guard_at(0x60)]),
                Some(CStmt::Block(vec![at(0x70, expr())])),
            ),
        );
        let inner = at(
            0x30,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(0x31, exit())]),
                Some(CStmt::Block(vec![at(0x32, expr()), rest])),
            ),
        );
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(cond(), CStmt::Block(vec![at(0x20, expr())]), Some(inner)),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 2);
        assert_eq!(count_elses(&body), 2);
    }

    #[test]
    fn a_bare_if_as_the_then_arm_with_its_else_exiting_is_swapped_in_its_own_block() {
        // `if (c) if (d) { x } else { exit } else { y }`: the bare then arm is a guard on the opposite test.
        let inner = at(
            0x20,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![at(0x21, expr())]),
                Some(CStmt::Block(vec![at(0x22, exit())])),
            ),
        );
        let mut body = CStmt::Block(vec![at(
            0x10,
            CStmt::if_stmt(cond(), inner, Some(CStmt::Block(vec![at(0x30, expr())]))),
        )]);
        assert_eq!(guarded(&mut body, &never_returns), 1);
        let (then_body, _) = arms_of(&top(&body)[0]);
        assert_eq!(top(then_body).len(), 2);
        assert_eq!(count_elses(&body), 1);
    }

    #[test]
    fn a_guard_in_a_loop_body_is_rewritten() {
        let loops: [fn(CStmt) -> CStmt; 3] = [
            |body| CStmt::while_loop(cond(), body),
            |body| CStmt::DoWhile {
                body: Box::new(body),
                cond: cond(),
            },
            |body| CStmt::For {
                init: None,
                cond: None,
                update: None,
                body: Box::new(body),
            },
        ];
        for make in loops {
            // A body that is a block, and a body that is the bare `if`.
            for body in [CStmt::Block(vec![a_guard()]), a_guard()] {
                let mut tree = CStmt::Block(vec![make(body)]);
                assert_eq!(guarded(&mut tree, &never_returns), 1, "{tree:?}");
                assert_eq!(count_elses(&tree), 0, "{tree:?}");
            }
        }
    }

    #[test]
    fn a_guard_in_a_case_or_the_default_of_a_switch_is_rewritten() {
        let case = |body| crate::ast::SwitchCase {
            value: CExpr::int(1),
            body,
        };
        for (cases, default) in [
            (vec![case(vec![a_guard()])], None),
            (Vec::new(), Some(vec![a_guard()])),
            (vec![case(vec![a_guard()])], Some(vec![a_guard()])),
        ] {
            let guards = cases.len() + usize::from(default.is_some());
            let mut tree = CStmt::Block(vec![CStmt::Switch {
                expr: cond(),
                cases,
                default,
            }]);
            assert_eq!(guarded(&mut tree, &never_returns), guards, "{tree:?}");
            assert_eq!(count_elses(&tree), 0, "{tree:?}");
        }
    }

    #[test]
    fn a_guard_whose_else_is_empty_leaves_no_statement_after_it() {
        for empty in [CStmt::Block(Vec::new()), CStmt::Empty] {
            let mut body = CStmt::Block(vec![at(
                0x10,
                CStmt::if_stmt(cond(), CStmt::Block(vec![at(0x20, exit())]), Some(empty)),
            )]);
            assert_eq!(guarded(&mut body, &never_returns), 1);
            assert_eq!(top(&body).len(), 1);
            assert_eq!(count_elses(&body), 0);
        }
    }

    /// Runs `check` on a stack that holds a few hundred frames of a walk that recurses to the tree's depth.
    fn on_a_small_stack(check: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(check)
            .expect("a thread")
            .join()
            .expect("the pass finishes without recursing to the depth of the chain");
    }

    /// Deep enough that a recursion per level cannot fit the small stack, and that a pass moving the tail
    /// of the chain at each level takes seconds.
    const DEEP: usize = 10_000;

    /// A statement every level of a chain puts before the next level, and a `return` ends the chain.
    fn chain_end() -> CStmt {
        at(0x40, ret())
    }

    /// `DEEP` pairs of an `if` with no else and the statement it freed, then the `return` the chain ended in.
    fn flat_chain(stmts: &[CStmt]) -> bool {
        let (levels, rest) = stmts.as_chunks::<2>();
        let guard_and_rest = |[guard, freed]: &[CStmt; 2]| {
            matches!(
                guard.unobserved(),
                CStmt::If {
                    else_body: None,
                    ..
                }
            ) && matches!(freed.unobserved(), CStmt::Expr(_))
        };
        levels.len() == DEEP
            && levels.iter().all(guard_and_rest)
            && matches!(rest, [last] if matches!(last.unobserved(), CStmt::Return(_)))
    }

    #[test]
    fn a_chain_of_guards_nested_in_else_arms_is_freed_flat_without_a_frame_per_level() {
        on_a_small_stack(|| {
            let mut next = chain_end();
            for _ in 0..DEEP {
                next = branching(
                    CStmt::Block(vec![at(0x20, exit())]),
                    vec![at(0x30, expr()), next],
                );
            }
            let mut body = CStmt::Block(vec![next]);
            assert_eq!(guarded(&mut body, &never_returns), DEEP);
            // Each level's test, its exit, then the statement it freed, ending in the return.
            assert!(flat_chain(top(&body)));
        });
    }

    #[test]
    fn a_chain_of_guards_nested_in_then_arms_is_freed_flat_without_a_frame_per_level() {
        on_a_small_stack(|| {
            let mut next = chain_end();
            for _ in 0..DEEP {
                next = at(
                    0x10,
                    CStmt::if_stmt(
                        cond(),
                        CStmt::Block(vec![at(0x30, expr()), next]),
                        Some(CStmt::Block(vec![at(0x20, exit())])),
                    ),
                );
            }
            let mut body = CStmt::Block(vec![next]);
            assert_eq!(guarded(&mut body, &never_returns), DEEP);
            assert!(flat_chain(top(&body)));
        });
    }

    #[test]
    fn a_chain_of_else_ifs_nothing_frees_is_walked_without_a_frame_per_level() {
        on_a_small_stack(|| {
            let mut next = at(0x40, expr());
            for _ in 0..DEEP {
                next = at(
                    0x10,
                    CStmt::if_stmt(cond(), CStmt::Block(vec![at(0x20, expr())]), Some(next)),
                );
            }
            let mut body = CStmt::Block(vec![next]);
            assert_eq!(guarded(&mut body, &never_returns), 0);
            // Dropping the chain recurses to its depth, which is the tree's own and not this pass's.
            std::mem::forget(body);
        });
    }

    /// Random trees of `if`s, `exit`s and plain statements, for what the guard must keep.
    struct Gen {
        state: u64,
        ifs: i64,
        leaves: i64,
    }

    impl Gen {
        fn below(&mut self, n: u64) -> u64 {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            self.state % n
        }

        fn block(&mut self, depth: u32) -> CStmt {
            let len = self.below(4);
            CStmt::Block((0..len).map(|_| self.stmt(depth)).collect())
        }

        /// An arm: empty, a block, or a lone statement.
        fn arm(&mut self, depth: u32) -> CStmt {
            match self.below(10) {
                0 => CStmt::Empty,
                1 => self.stmt(depth),
                _ => self.block(depth),
            }
        }

        /// `stmt`, observed as a block's statement in seven of eight cases.
        fn observed(&mut self, stmt: CStmt) -> CStmt {
            match self.below(8) {
                0 => stmt,
                _ => at(0x100 + self.leaves as u64, stmt),
            }
        }

        fn nested(&mut self, depth: u32) -> CStmt {
            let block = self.block(depth - 1);
            self.observed(block)
        }

        fn conditional(&mut self, depth: u32) -> CStmt {
            self.ifs += 1;
            let test = self.ifs;
            let then_body = self.arm(depth - 1);
            let else_body = (self.below(4) != 0).then(|| self.arm(depth - 1));
            let stmt = CStmt::if_stmt(CExpr::IntLit(test), then_body, else_body);
            match self.below(8) {
                0 => stmt,
                _ => at(0x10 + test as u64, stmt),
            }
        }

        fn stmt(&mut self, depth: u32) -> CStmt {
            let kind = self.below(100);
            self.leaves += 1;
            let leaf = self.leaves;
            match kind {
                0..=29 => self.observed(CStmt::Expr(CExpr::IntLit(leaf))),
                30..=44 => self.observed(exit_with(leaf)),
                45..=47 => CStmt::Return(Some(CExpr::IntLit(leaf))),
                48..=52 => CStmt::Comment(format!("c{leaf}")),
                53..=54 => CStmt::Label(format!("L{leaf}")),
                55..=59 if depth > 0 => self.nested(depth),
                _ if depth == 0 => self.observed(CStmt::Expr(CExpr::IntLit(leaf))),
                _ => self.conditional(depth),
            }
        }
    }

    fn exit_with(code: i64) -> CStmt {
        let callee = CExpr::External {
            name: "exit".to_owned(),
            kind: crate::symbol::ExternalKind::Function,
        };
        CStmt::Expr(CExpr::call(callee, vec![CExpr::IntLit(code)]))
    }

    /// A test's value: its number's bit of the assignment, through the `!` and `||`/`&&` a guard writes.
    fn holds(test: &CExpr, assignment: u32) -> bool {
        match test.unobserved() {
            CExpr::IntLit(number) => (assignment >> (number - 1)) & 1 == 1,
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => !holds(operand, assignment),
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => holds(left, assignment) && holds(right, assignment),
            CExpr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => holds(left, assignment) || holds(right, assignment),
            other => panic!("a test: {other:?}"),
        }
    }

    /// What running `stmt` does, in order: a statement's number, a call's code negated, a return's
    /// plus 10,000. False once control has left.
    fn execute(stmt: &CStmt, assignment: u32, done: &mut Vec<i64>) -> bool {
        match stmt.unobserved() {
            CStmt::Block(stmts) => stmts.iter().all(|stmt| execute(stmt, assignment, done)),
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => match holds(cond, assignment) {
                true => execute(then_body, assignment, done),
                false => (else_body.iter()).all(|arm| execute(arm, assignment, done)),
            },
            CStmt::Expr(CExpr::IntLit(number)) => {
                done.push(*number);
                true
            }
            CStmt::Expr(CExpr::Call { args, .. }) => {
                let [CExpr::IntLit(code)] = args.as_slice() else {
                    panic!("a code: {args:?}");
                };
                done.push(-code);
                false
            }
            CStmt::Return(Some(CExpr::IntLit(number))) => {
                done.push(10_000 + number);
                false
            }
            CStmt::Empty | CStmt::Comment(_) | CStmt::Label(_) => true,
            other => panic!("a statement: {other:?}"),
        }
    }

    /// Whether `before` and `after` do the same, in the same order, under every assignment of `ifs` tests.
    fn run_alike(before: &CStmt, after: &CStmt, ifs: i64) -> Result<(), u32> {
        for assignment in 0..1u32 << ifs {
            let (mut then, mut now) = (Vec::new(), Vec::new());
            execute(before, assignment, &mut then);
            execute(after, assignment, &mut now);
            if then != now {
                return Err(assignment);
            }
        }
        Ok(())
    }

    #[test]
    fn the_guard_runs_every_path_as_before_and_a_second_pass_changes_nothing() {
        let (mut trees, mut rewrites) = (0, 0);
        for seed in 1..=1_500u64 {
            let mut rng = Gen {
                state: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
                ifs: 0,
                leaves: 0,
            };
            let mut body = CStmt::Block(vec![rng.block(4), rng.block(4)]);
            if rng.ifs == 0 || rng.ifs > 12 {
                continue;
            }
            let before = body.clone();
            rewrites += guarded(&mut body, &never_returns);
            trees += 1;
            let alike = run_alike(&before, &body, rng.ifs);
            assert_eq!(alike, Ok(()), "seed {seed}\n{before:#?}\n{body:#?}");
            let again = guarded(&mut body, &never_returns);
            assert_eq!(again, 0, "seed {seed}: {body:#?}");
        }
        assert!(
            trees > 800 && rewrites > 400,
            "{trees} trees, {rewrites} rewrites"
        );
    }
}
