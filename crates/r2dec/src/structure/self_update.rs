//! What a statement that updates a variable by itself looks like, and how it
//! is spelled.
//!
//! `x = x + 1`, `x += 1` and `x++` are one thing said three ways, and until
//! this module there were three answerers: the rewriter below had the ten-operator
//! table, a second recognizer beside it accepted a different set of shapes, and
//! the printer carried a third that knew only addition and subtraction and ran
//! after the tree was sealed. A rewrite in the printer cannot move the markers
//! of what it collapses, so a run of updates coalesced into one statement left
//! every marker it absorbed unaccounted -- which is the ledger reporting that
//! the program's effects went unrendered when they did not.
//!
//! So the recognizing and the rewriting live here, before sealing, and the
//! printer prints the node it is given.

use crate::ast::{BinaryOp, CExpr, CStmt, UnaryOp};
use crate::symbol::SymbolId;

/// The compound-assignment operator for a binary operator, where C has one.
pub(crate) fn compound_assignment_op(op: BinaryOp) -> Option<BinaryOp> {
    match op {
        BinaryOp::Add => Some(BinaryOp::AddAssign),
        BinaryOp::Sub => Some(BinaryOp::SubAssign),
        BinaryOp::Mul => Some(BinaryOp::MulAssign),
        BinaryOp::Div => Some(BinaryOp::DivAssign),
        BinaryOp::Mod => Some(BinaryOp::ModAssign),
        BinaryOp::BitAnd => Some(BinaryOp::BitAndAssign),
        BinaryOp::BitOr => Some(BinaryOp::BitOrAssign),
        BinaryOp::BitXor => Some(BinaryOp::BitXorAssign),
        BinaryOp::Shl => Some(BinaryOp::ShlAssign),
        BinaryOp::Shr => Some(BinaryOp::ShrAssign),
        _ => None,
    }
}

/// Whether this operator is one of those.
pub(crate) fn is_compound_assignment_op(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::AddAssign
            | BinaryOp::SubAssign
            | BinaryOp::MulAssign
            | BinaryOp::DivAssign
            | BinaryOp::ModAssign
            | BinaryOp::BitAndAssign
            | BinaryOp::BitOrAssign
            | BinaryOp::BitXorAssign
            | BinaryOp::ShlAssign
            | BinaryOp::ShrAssign
    )
}

/// How much this expression adds to a variable, where it adds a constant to
/// one and writes it back.
pub(crate) fn self_update_delta(expr: &CExpr) -> Option<(SymbolId, i64)> {
    let CExpr::Binary { op, left, right } = expr.unobserved() else {
        return None;
    };
    let CExpr::Var(name) = left.unobserved() else {
        return None;
    };
    match op {
        BinaryOp::Assign => delta_for_assigned_rhs(*name, right),
        BinaryOp::AddAssign => literal_i64(right).map(|delta| (*name, delta)),
        BinaryOp::SubAssign => {
            literal_i64(right).and_then(|delta| delta.checked_neg().map(|negated| (*name, negated)))
        }
        _ => None,
    }
}

/// The same, for a statement.
pub(crate) fn stmt_self_update_delta(stmt: &CStmt) -> Option<(SymbolId, i64)> {
    let CStmt::Expr(expr) = stmt.unobserved() else {
        return None;
    };
    self_update_delta(expr)
}

fn delta_for_assigned_rhs(name: SymbolId, rhs: &CExpr) -> Option<(SymbolId, i64)> {
    let CExpr::Binary { op, left, right } = rhs.unobserved() else {
        return None;
    };
    match op {
        BinaryOp::Add if expr_is_var(left, name) => literal_i64(right).map(|delta| (name, delta)),
        BinaryOp::Add if expr_is_var(right, name) => literal_i64(left).map(|delta| (name, delta)),
        BinaryOp::Sub if expr_is_var(left, name) => {
            literal_i64(right).and_then(|delta| delta.checked_neg().map(|negated| (name, negated)))
        }
        _ => None,
    }
}

fn expr_is_var(expr: &CExpr, name: SymbolId) -> bool {
    matches!(expr.unobserved(), CExpr::Var(candidate) if *candidate == name)
}

fn literal_i64(expr: &CExpr) -> Option<i64> {
    match expr.unobserved() {
        CExpr::IntLit(value) => Some(*value),
        CExpr::UIntLit(value) => i64::try_from(*value).ok(),
        _ => None,
    }
}

/// The shortest C for adding `delta` to `name`.
///
/// A delta of zero has no spelling: dropping the statement would drop the
/// definitions it stands for, so the caller keeps what it had.
pub(crate) fn update_expr(name: SymbolId, delta: i64) -> Option<CExpr> {
    match delta {
        0 => None,
        1 => Some(CExpr::Unary {
            op: UnaryOp::PostInc,
            operand: Box::new(CExpr::Var(name)),
        }),
        -1 => Some(CExpr::Unary {
            op: UnaryOp::PostDec,
            operand: Box::new(CExpr::Var(name)),
        }),
        _ => {
            let (op, amount) = if delta < 0 {
                (BinaryOp::SubAssign, delta.checked_abs()?)
            } else {
                (BinaryOp::AddAssign, delta)
            };
            Some(CExpr::binary(op, CExpr::Var(name), CExpr::IntLit(amount)))
        }
    }
}

/// Shorten an expression that adds one or subtracts one to `++` or `--`.
///
/// Every marker the expression owned moves onto the shorter spelling: it is
/// the same occurrence, said in fewer characters.
pub(crate) fn shorten_unit_update(expr: CExpr) -> CExpr {
    let Some((name, delta)) = self_update_delta(&expr) else {
        return expr;
    };
    if !matches!(delta, 1 | -1) {
        return expr;
    }
    let Some(shorter) = update_expr(name, delta) else {
        return expr;
    };
    crate::ast::carry_all_expr_observations(&expr, shorter)
}

/// Collapse the run of updates to one variable that starts at `stmts[0]`.
///
/// Returns how many statements it consumed and the one that replaces them,
/// carrying every marker they owned. A run of one is still rewritten, because
/// `x += 1` is `x++`.
pub(crate) fn coalesce_run(stmts: &[CStmt]) -> Option<(usize, CStmt)> {
    let (name, first) = stmt_self_update_delta(stmts.first()?)?;
    let mut total = first;
    // The longest prefix that still moves the variable. A run that cancels has
    // no spelling -- deleting it would delete the definitions it stands for,
    // and no elision proof says they are dead -- so the prefix before the
    // cancellation is taken and the rest is coalesced on the next pass.
    let mut best = (total != 0).then_some((1usize, total));
    let mut run_len = 1;
    for stmt in &stmts[1..] {
        let Some((next, delta)) = stmt_self_update_delta(stmt) else {
            break;
        };
        if next != name {
            break;
        }
        total = total.checked_add(delta)?;
        run_len += 1;
        if total != 0 {
            best = Some((run_len, total));
        }
    }
    let (run_len, total) = best?;
    let expr = update_expr(name, total)?;
    let absorbed = &stmts[..run_len];
    if run_len == 1 && stmts[0].unobserved() == &CStmt::Expr(expr.clone()) {
        return None;
    }
    Some((
        run_len,
        crate::ast::carry_all_stmt_observations(absorbed, CStmt::Expr(expr)),
    ))
}

/// Rewrite every run of updates in a statement sequence.
pub(crate) fn coalesce_sequence(stmts: Vec<CStmt>) -> Vec<CStmt> {
    let mut rewritten = Vec::with_capacity(stmts.len());
    let mut index = 0;
    while index < stmts.len() {
        match coalesce_run(&stmts[index..]) {
            Some((run_len, stmt)) => {
                rewritten.push(stmt);
                index += run_len;
            }
            None => {
                rewritten.push(stmts[index].clone());
                index += 1;
            }
        }
    }
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CFunction, CType};

    fn table() -> std::cell::RefCell<crate::symbol::SymbolTable> {
        std::cell::RefCell::new(crate::symbol::SymbolTable::new())
    }

    #[test]
    fn a_coalesced_run_owns_every_occurrence_it_absorbed() {
        let symbols = table();
        let value = crate::symbol::declare(&symbols, "value");
        let mut owner = crate::ast::RenderObservationOwner::new();
        let mut updates = Vec::new();
        let mut marked = Vec::new();
        for amount in [1, 2] {
            let (expr_id, expr) = owner
                .observe_expr(CExpr::assign(
                    CExpr::var(value),
                    CExpr::binary(BinaryOp::Add, CExpr::var(value), CExpr::int(amount)),
                ))
                .expect("allocate update observation");
            let (stmt_id, stmt) = owner
                .observe_stmt(CStmt::Expr(expr))
                .expect("allocate update statement observation");
            marked.extend([expr_id, stmt_id]);
            updates.push(stmt);
        }

        let (run_len, coalesced) = coalesce_run(&updates).expect("a run of two updates");
        assert_eq!(run_len, 2);

        let mut function = CFunction::new("updates", CType::Void).with_body(vec![coalesced]);
        let reachable =
            crate::ast::strip_render_observations(&mut function, owner.expected_count())
                .expect("coalescing preserves a valid observation domain");

        // The one surviving statement renders what both rendered, so it owns
        // what both owned. Leaving the markers behind is what the printer used
        // to do, and the ledger then reported four occurrences unaccounted for
        // effects the program does render.
        for id in marked {
            assert!(reachable.contains(id), "marker {id:?} was dropped");
        }
        assert_eq!(
            function.body,
            vec![CStmt::Expr(CExpr::binary(
                BinaryOp::AddAssign,
                CExpr::var(value),
                CExpr::IntLit(3),
            ))]
        );
    }

    #[test]
    fn a_single_step_is_an_increment() {
        let symbols = table();
        let value = crate::symbol::declare(&symbols, "value");
        let (run_len, stmt) = coalesce_run(&[CStmt::Expr(CExpr::assign(
            CExpr::var(value),
            CExpr::binary(BinaryOp::Add, CExpr::var(value), CExpr::int(1)),
        ))])
        .expect("one update");
        assert_eq!(run_len, 1);
        assert_eq!(
            stmt,
            CStmt::Expr(CExpr::Unary {
                op: UnaryOp::PostInc,
                operand: Box::new(CExpr::Var(value)),
            })
        );
    }

    #[test]
    fn a_run_that_cancels_keeps_the_steps_it_stands_for() {
        let symbols = table();
        let value = crate::symbol::declare(&symbols, "value");
        let step = |amount| {
            CStmt::Expr(CExpr::assign(
                CExpr::var(value),
                CExpr::binary(BinaryOp::Add, CExpr::var(value), CExpr::int(amount)),
            ))
        };
        // Collapsing to nothing would remove the definitions the run stands
        // for, and no proof says they are dead.
        let coalesced = coalesce_sequence(vec![step(1), step(-1)]);
        assert_eq!(
            coalesced,
            vec![
                CStmt::Expr(CExpr::Unary {
                    op: UnaryOp::PostInc,
                    operand: Box::new(CExpr::Var(value)),
                }),
                CStmt::Expr(CExpr::Unary {
                    op: UnaryOp::PostDec,
                    operand: Box::new(CExpr::Var(value)),
                }),
            ]
        );
    }

    #[test]
    fn a_run_stops_at_a_statement_that_is_not_an_update() {
        let symbols = table();
        let acc = crate::symbol::declare(&symbols, "acc");
        let observe = crate::symbol::declare(&symbols, "observe");
        let step = |amount| {
            CStmt::Expr(CExpr::assign(
                CExpr::var(acc),
                CExpr::binary(BinaryOp::Add, CExpr::var(acc), CExpr::int(amount)),
            ))
        };
        let call = CStmt::Expr(CExpr::call(CExpr::var(observe), vec![CExpr::var(acc)]));
        let coalesced = coalesce_sequence(vec![step(1), call.clone(), step(2), step(3)]);
        assert_eq!(
            coalesced,
            vec![
                CStmt::Expr(CExpr::Unary {
                    op: UnaryOp::PostInc,
                    operand: Box::new(CExpr::Var(acc)),
                }),
                call,
                CStmt::Expr(CExpr::binary(
                    BinaryOp::AddAssign,
                    CExpr::var(acc),
                    CExpr::IntLit(5),
                )),
            ]
        );
    }

    #[test]
    fn an_update_written_either_way_around_counts() {
        let symbols = table();
        let acc = crate::symbol::declare(&symbols, "acc");
        let coalesced = coalesce_sequence(vec![
            CStmt::Expr(CExpr::assign(
                CExpr::var(acc),
                CExpr::binary(BinaryOp::Add, CExpr::var(acc), CExpr::int(3)),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::var(acc),
                CExpr::binary(BinaryOp::Add, CExpr::int(4), CExpr::var(acc)),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::var(acc),
                CExpr::binary(BinaryOp::Sub, CExpr::var(acc), CExpr::int(2)),
            )),
        ]);
        assert_eq!(
            coalesced,
            vec![CStmt::Expr(CExpr::binary(
                BinaryOp::AddAssign,
                CExpr::var(acc),
                CExpr::IntLit(5),
            ))]
        );
    }
}
