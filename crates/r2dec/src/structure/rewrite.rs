//! The quality layer: rewrites on the placed tree, each preserving the
//! control certificate. What used to be the structurer's cleanup pass.

use std::collections::HashSet;

use crate::ast::{BinaryOp, CExpr, CStmt, StmtObservationChain, UnaryOp};
use crate::structured_region::StructuredRegionKind;
use crate::symbol::SymbolId;

use super::ControlFlowStructurer;

/// One arm's assignment, taken apart: the statement's own markers, the markers
/// around the assignment expression, the markers around the object written, and
/// the two sides.
type SoleAssignment = (
    StmtObservationChain,
    Vec<crate::observation_journal::RenderObservationId>,
    Vec<crate::observation_journal::RenderObservationId>,
    CExpr,
    CExpr,
);

impl ControlFlowStructurer<'_, '_> {
    pub(crate) fn cleanup(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        is_write: &dyn Fn(crate::observation_journal::RenderObservationId) -> bool,
        stmt: CStmt,
    ) -> CStmt {
        // Recurse first, then simplify
        let mut stmt = stmt;
        Self::cleanup_recurse(symbols, is_write, &mut stmt);
        Self::flatten(stmt)
    }

    /// Recursively clean up children first, then apply local simplifications.
    ///
    /// The walk edits the tree it is given. It used to take each node by value
    /// and hand back a new one, which unboxed and reboxed every child: one
    /// free and one allocation per node, and on a five-hundred-block function
    /// that was 1.46 million allocations, the largest single source of churn
    /// in a render and none of it retained. A node whose rewrite consumes it is
    /// still taken out and put back, which moves the node and allocates
    /// nothing.
    fn cleanup_recurse(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        is_write: &dyn Fn(crate::observation_journal::RenderObservationId) -> bool,
        stmt: &mut CStmt,
    ) {
        match stmt {
            CStmt::StructuredRegion {
                marker,
                stmt: inner,
            } => {
                Self::cleanup_recurse(symbols, is_write, inner);
                // An empty region renders nothing and its marker goes with
                // it -- except the function body's. That marker is what
                // sealing looks for at the root, so collapsing it turned a
                // function whose body rendered no statement, a forwarder
                // that is one jump out of the function, into a structurer
                // refusal reading "unrepresentable control flow", when the
                // control flow was fine and the honest report is the one the
                // proof line already makes: rendering produced no statements.
                if matches!(inner.unobserved(), CStmt::Empty)
                    && marker.kind() != StructuredRegionKind::FunctionBody
                {
                    *stmt = CStmt::Empty;
                }
            }
            CStmt::Observed { stmt: inner, .. } => Self::cleanup_recurse(symbols, is_write, inner),
            CStmt::Block(stmts) => {
                for child in stmts.iter_mut() {
                    Self::cleanup_recurse(symbols, is_write, child);
                }
                stmts.retain(|child| !matches!(child.unobserved(), CStmt::Empty));
                let cleaned = std::mem::take(stmts);
                let cleaned = Self::rewrite_block_tail_guard_clauses(cleaned);
                let cleaned = Self::rewrite_guarded_switch_if_else(cleaned);
                let cleaned = Self::rewrite_continue_tail_merges(symbols, cleaned);
                let cleaned = super::self_update::coalesce_sequence(cleaned);
                let mut cleaned = Self::truncate_dead_straight_line_tail(cleaned);
                *stmt = if cleaned.is_empty() {
                    CStmt::Empty
                } else if cleaned.len() == 1 {
                    cleaned.remove(0)
                } else {
                    CStmt::Block(cleaned)
                };
            }
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::cleanup_recurse(symbols, is_write, then_body);
                if let Some(body) = else_body {
                    Self::cleanup_recurse(symbols, is_write, body);
                }
                if else_body
                    .as_ref()
                    .is_some_and(|body| matches!(body.unobserved(), CStmt::Empty))
                {
                    *else_body = None;
                }
                let taken = std::mem::replace(stmt, CStmt::Empty);
                let taken = Self::rewrite_if_short_circuit(taken);
                let taken = Self::rewrite_two_way_assignment(is_write, taken);
                let taken = Self::rewrite_empty_if_bodies(taken);
                *stmt = Self::rewrite_guarded_switch_with_trailing_return(taken);
            }
            CStmt::While { body, .. } => {
                Self::cleanup_recurse(symbols, is_write, body);
                let taken = std::mem::replace(body.as_mut(), CStmt::Empty);
                **body = Self::strip_trailing_continue(taken);
            }
            CStmt::DoWhile { body, .. } => {
                Self::cleanup_recurse(symbols, is_write, body);
                let taken = std::mem::replace(body.as_mut(), CStmt::Empty);
                **body = Self::strip_trailing_continue(taken);
            }
            CStmt::For { update, body, .. } => {
                if let Some(update) = update.as_mut() {
                    let taken = std::mem::replace(update, CExpr::IntLit(0));
                    let compound = Self::rewrite_compound_assignment_expr(taken);
                    *update = super::self_update::shorten_unit_update(compound);
                }
                Self::cleanup_recurse(symbols, is_write, body);
                let taken = std::mem::replace(body.as_mut(), CStmt::Empty);
                let cleaned = Self::strip_trailing_continue(taken);
                // The strip consumes the body and hands one back either way, so
                // matching moves it. Written as `map(...).unwrap_or(body)` the
                // closure could not move it and every loop body in the function
                // was deep-copied to be passed, which nests: an outer loop
                // copied every inner loop that had just copied itself.
                **body = match update.as_ref() {
                    Some(update) => Self::strip_trailing_for_update(symbols, cleaned, update),
                    None => cleaned,
                };
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases.iter_mut() {
                    case.body = Self::cleanup_switch_body(
                        symbols,
                        is_write,
                        std::mem::take(&mut case.body),
                    );
                }
                if let Some(body) = default {
                    *body = Self::cleanup_switch_body(symbols, is_write, std::mem::take(body));
                }
            }
            CStmt::Expr(expr) => {
                let taken = std::mem::replace(expr, CExpr::IntLit(0));
                let compound = Self::rewrite_compound_assignment_expr(taken);
                *expr = super::self_update::shorten_unit_update(compound);
            }
            _ => {}
        }
    }

    fn cleanup_switch_body(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        is_write: &dyn Fn(crate::observation_journal::RenderObservationId) -> bool,
        stmts: Vec<CStmt>,
    ) -> Vec<CStmt> {
        let mut cleaned = stmts;
        for stmt in cleaned.iter_mut() {
            Self::cleanup_recurse(symbols, is_write, stmt);
        }
        cleaned.retain(|stmt| !matches!(stmt.unobserved(), CStmt::Empty));
        let cleaned = super::self_update::coalesce_sequence(cleaned);
        Self::truncate_dead_straight_line_tail(cleaned)
    }

    fn rewrite_compound_assignment_expr(expr: CExpr) -> CExpr {
        if let CExpr::Observed { id, expr } = expr {
            return CExpr::observed(id, Self::rewrite_compound_assignment_expr(*expr));
        }
        let CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        } = expr
        else {
            return expr;
        };

        let CExpr::Var(target_name) = left.as_ref() else {
            return CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                right,
            };
        };

        let Some((op, retained, eliminated)) =
            Self::compound_assignment_parts(*target_name, right.as_ref())
        else {
            return CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                right,
            };
        };

        let left = crate::ast::carry_outer_expr_observations(eliminated, *left);
        let rewritten = CExpr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(retained.clone()),
        };
        crate::ast::carry_outer_expr_observations(right.as_ref(), rewritten)
    }

    fn compound_assignment_parts(
        target: SymbolId,
        rhs: &CExpr,
    ) -> Option<(BinaryOp, &CExpr, &CExpr)> {
        let CExpr::Binary { op, left, right } = rhs.unobserved() else {
            return None;
        };
        let compound_op = super::self_update::compound_assignment_op(*op)?;

        if Self::expr_is_var(left, target) && crate::fold::op_lower::expr_is_side_effect_free(right)
        {
            return Some((compound_op, right, left));
        }

        if Self::binary_op_is_commutative_for_compound(*op)
            && Self::expr_is_var(right, target)
            && crate::fold::op_lower::expr_is_side_effect_free(left)
        {
            return Some((compound_op, left, right));
        }

        None
    }

    fn compound_assignment_rhs_of(target: SymbolId, rhs: &CExpr) -> Option<(BinaryOp, CExpr)> {
        let semantic = rhs.clone_without_render_observations();
        let (op, retained, _) = Self::compound_assignment_parts(target, &semantic)?;
        Some((op, retained.clone()))
    }

    fn binary_op_is_commutative_for_compound(op: BinaryOp) -> bool {
        matches!(
            op,
            BinaryOp::Add | BinaryOp::Mul | BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor
        )
    }

    fn expr_is_var(expr: &CExpr, target: SymbolId) -> bool {
        matches!(expr.unobserved(), CExpr::Var(name) if *name == target)
    }

    fn rewrite_if_short_circuit(stmt: CStmt) -> CStmt {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        let CStmt::If {
            cond,
            then_body,
            else_body,
        } = semantic
        else {
            return observations.reapply(semantic);
        };

        // if (a) { if (b) { T } } -> if (a && b) { T }
        if else_body.is_none()
            && let CStmt::If {
                cond: inner_cond,
                then_body: inner_then,
                else_body: None,
            } = then_body.unobserved()
        {
            let rewritten = CStmt::If {
                cond: CExpr::binary(BinaryOp::And, cond, inner_cond.clone()),
                then_body: inner_then.clone(),
                else_body: None,
            };
            return observations.reapply(rewritten);
        }

        // if (a) { T } else if (b) { T } -> if (a || b) { T }
        if let Some(else_stmt) = else_body.as_deref()
            && let CStmt::If {
                cond: right_cond,
                then_body: right_then,
                else_body: None,
            } = else_stmt.unobserved()
            && Self::stmt_transparently_eq(then_body.as_ref(), right_then)
        {
            let rewritten = CStmt::If {
                cond: CExpr::binary(BinaryOp::Or, cond, right_cond.clone()),
                then_body,
                else_body: None,
            };
            return observations.reapply(rewritten);
        }

        // if (a) { if (b) { T } } else { T } -> if (!a || b) { T }
        if let CStmt::If {
            cond: inner_cond,
            then_body: inner_then,
            else_body: None,
        } = then_body.unobserved()
            && let Some(outer_else) = else_body.as_deref()
            && Self::stmt_transparently_eq(outer_else, inner_then)
        {
            let rewritten = CStmt::If {
                cond: CExpr::binary(
                    BinaryOp::Or,
                    Self::negate_condition(cond),
                    inner_cond.clone(),
                ),
                then_body: inner_then.clone(),
                else_body: None,
            };
            return observations.reapply(rewritten);
        }

        // if (a) { if (b) { T } else { E } } else { E } -> if (a && b) { T } else { E }
        if let CStmt::If {
            cond: inner_cond,
            then_body: inner_then,
            else_body: Some(inner_else),
        } = then_body.unobserved()
            && let Some(outer_else) = else_body.as_deref()
            && Self::stmt_transparently_eq(outer_else, inner_else)
        {
            let rewritten = CStmt::If {
                cond: CExpr::binary(BinaryOp::And, cond, inner_cond.clone()),
                then_body: inner_then.clone(),
                else_body: Some(inner_else.clone()),
            };
            return observations.reapply(rewritten);
        }

        observations.reapply(CStmt::If {
            cond,
            then_body,
            else_body,
        })
    }

    fn append_stmt_body_flat(out: &mut Vec<CStmt>, stmt: CStmt) {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        match semantic {
            CStmt::Block(mut stmts) => {
                observations.reapply_to_unique(&mut stmts);
                out.extend(stmts);
            }
            CStmt::Empty => {}
            other => out.push(observations.reapply(other)),
        }
    }

    /// The one assignment a branch arm makes, with the markers around it.
    ///
    /// Through the region and observation wrappers, and through a block that
    /// holds nothing else: an arm that assigns once and does nothing more is
    /// the shape a selection has in the text.
    fn sole_assignment(stmt: &CStmt) -> Option<SoleAssignment> {
        let (semantic, observations) = stmt.clone().into_semantic_with_observations();
        match semantic {
            CStmt::StructuredRegion { stmt, .. } => {
                let (inner, carried, written, lhs, rhs) = Self::sole_assignment(&stmt)?;
                let mut chain = observations;
                chain.extend(inner);
                Some((chain, carried, written, lhs, rhs))
            }
            CStmt::Block(stmts) => {
                let mut live = stmts
                    .iter()
                    .filter(|stmt| !matches!(stmt.unobserved(), CStmt::Empty | CStmt::Comment(_)));
                let only = live.next()?;
                if live.next().is_some() {
                    return None;
                }
                let (inner, carried, written, lhs, rhs) = Self::sole_assignment(only)?;
                let mut chain = observations;
                // A statement that renders nothing can still carry markers, and
                // they are cells the survivor owes: dropping them loses an
                // occurrence the ledger is still counting.
                for stmt in &stmts {
                    if std::ptr::eq(stmt, only) {
                        continue;
                    }
                    let (_, marks) = stmt.clone().into_semantic_with_observations();
                    chain.extend(marks);
                }
                chain.extend(inner);
                Some((chain, carried, written, lhs, rhs))
            }
            CStmt::Expr(expr) => {
                // The assignment may carry expression markers of its own; they
                // belong to the whole statement's occurrence, so they go back
                // around whatever replaces it.
                let mut carried = Vec::new();
                let mut cursor = expr;
                while let CExpr::Observed { id, expr } = cursor {
                    carried.push(id);
                    cursor = *expr;
                }
                let CExpr::Binary {
                    op: BinaryOp::Assign,
                    left,
                    right,
                } = cursor
                else {
                    return None;
                };
                // The object written carries markers of its own, and only one
                // of the two arms' lvalues survives the conversion. They are
                // kept apart from the statement's own markers because they
                // belong on the lvalue: placement asks whether the marked
                // expression names the slot, and an assignment's plain-variable
                // lvalue is not a read of it.
                let mut written = Vec::new();
                let mut left = *left;
                while let CExpr::Observed { id, expr } = left {
                    written.push(id);
                    left = *expr;
                }
                Some((observations, carried, written, left, *right))
            }
            _ => None,
        }
    }

    /// `if (c) { x = A; } else { x = B; }` is one assignment of a conditional.
    ///
    /// A merge of two values under one condition is a selection, and this is
    /// where the text says so: the arms write one object, so the object is
    /// written once with the value the condition chooses. Both arms' markers
    /// stay on the result, so both writes are still accounted for where they
    /// were, and the condition keeps the one read it always had.
    fn rewrite_two_way_assignment(
        is_write: &dyn Fn(crate::observation_journal::RenderObservationId) -> bool,
        stmt: CStmt,
    ) -> CStmt {
        let CStmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } = stmt
        else {
            return stmt;
        };
        let restore = |cond, then_body, else_body| CStmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        };
        let (
            Some((then_marks, then_carried, then_written, then_lhs, then_rhs)),
            Some((else_marks, else_carried, else_written, else_lhs, else_rhs)),
        ) = (
            Self::sole_assignment(&then_body),
            Self::sole_assignment(&else_body),
        )
        else {
            r2il::refusal_evidence!("two-way-assignment", "an arm is not a sole assignment");
            return restore(cond, then_body, else_body);
        };
        if !then_lhs.transparently_eq(&else_lhs) {
            r2il::refusal_evidence!(
                "two-way-assignment",
                "the arms write different objects: {then_lhs:?} and {else_lhs:?}"
            );
            return restore(cond, then_body, else_body);
        }
        // Only one of the two lvalues survives, so neither may carry a marker
        // of its own: a store to a frame slot is marked on the expression that
        // names the slot, and two stores are two effects rather than one
        // assignment of a chosen value. A plain object written twice is the
        // shape this converts.
        if !matches!(then_lhs, CExpr::Var(_)) || !matches!(else_lhs, CExpr::Var(_)) {
            r2il::refusal_evidence!(
                "two-way-assignment",
                "an arm writes something other than a plain object: {then_lhs:?}"
            );
            return restore(cond, then_body, else_body);
        }
        // Both arms' write markers go on the one surviving lvalue. The text
        // writes the object once and that write is what both machine writes
        // became, so each cell keeps its own marker and both name the same
        // occurrence.
        let mut written_lhs = then_lhs;
        for id in then_written.into_iter().chain(else_written).rev() {
            written_lhs = CExpr::Observed {
                id,
                expr: Box::new(written_lhs),
            };
        }
        // Everything else an arm owned goes inside that arm. The arm's
        // statement became the arm's expression, so its markers travel with it
        // -- and staying inside the arm is what keeps two occurrences of one
        // obligation, one per arm, exclusive: the ledger reads exclusivity off
        // the emitted text, and outside the conditional there is no arm to
        // read.
        // Each arm keeps what it computed and gives up what it wrote. The
        // value an arm produced is still produced in that arm, so its markers
        // stay inside it -- and staying inside is what keeps two occurrences of
        // one obligation, one per arm, exclusive, since the ledger reads
        // exclusivity off the emitted text. The write is the single store the
        // merged assignment makes, so every arm's write marker rides on it:
        // a write marker left inside the right-hand side is an order placement
        // cannot resolve.
        let (then_writes, then_marks) = then_marks.split_out(is_write);
        let (else_writes, else_marks) = else_marks.split_out(is_write);
        let mut assignment = CExpr::assign(
            written_lhs,
            CExpr::Ternary {
                cond: Box::new(cond),
                then_expr: Box::new(then_marks.reapply_expr(then_rhs)),
                else_expr: Box::new(else_marks.reapply_expr(else_rhs)),
            },
        );
        for id in then_carried
            .into_iter()
            .chain(then_writes)
            .chain(else_carried)
            .chain(else_writes)
            .rev()
        {
            assignment = CExpr::Observed {
                id,
                expr: Box::new(assignment),
            };
        }
        CStmt::expr(assignment)
    }

    fn rewrite_empty_if_bodies(stmt: CStmt) -> CStmt {
        let CStmt::If {
            cond,
            then_body,
            else_body,
        } = stmt
        else {
            return stmt;
        };

        if matches!(then_body.unobserved(), CStmt::Empty) {
            return match else_body {
                Some(else_body) => CStmt::If {
                    cond: Self::negate_condition(cond),
                    then_body: else_body,
                    else_body: None,
                },
                None => CStmt::Empty,
            };
        }

        CStmt::If {
            cond,
            then_body,
            else_body,
        }
    }

    fn rewrite_guarded_switch_with_trailing_return(stmt: CStmt) -> CStmt {
        let CStmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } = stmt
        else {
            return stmt;
        };

        let then_branch = Self::extract_switch_with_trailing_stmt(then_body.as_ref());
        let else_branch = Self::extract_switch_with_trailing_stmt(else_body.as_ref());
        let (switch_stmt, default_stmt, trailing_stmt) = match (then_branch, else_branch) {
            (Some((switch_stmt, trailing_stmt)), None) => {
                (switch_stmt, (*else_body).clone(), trailing_stmt)
            }
            (None, Some((switch_stmt, trailing_stmt))) => {
                (switch_stmt, (*then_body).clone(), trailing_stmt)
            }
            _ => {
                return CStmt::If {
                    cond,
                    then_body,
                    else_body: Some(else_body),
                };
            }
        };

        if !matches!(switch_stmt, CStmt::Switch { default: None, .. })
            || !Self::stmt_guarantees_termination(&default_stmt)
            || trailing_stmt.as_ref().is_some_and(|stmt| {
                !matches!(
                    Self::single_terminator_stmt(stmt),
                    Some(CStmt::Return(Some(CExpr::IntLit(0) | CExpr::UIntLit(0))))
                )
            })
        {
            return CStmt::If {
                cond,
                then_body,
                else_body: Some(else_body),
            };
        }

        let CStmt::Switch { expr, cases, .. } = switch_stmt else {
            unreachable!();
        };
        let mut rewritten = vec![CStmt::Switch {
            expr,
            cases,
            default: Some(vec![default_stmt]),
        }];
        if let Some(trailing_stmt) = trailing_stmt {
            rewritten.push(trailing_stmt);
        }
        CStmt::Block(rewritten)
    }

    fn rewrite_block_tail_guard_clauses(stmts: Vec<CStmt>) -> Vec<CStmt> {
        // Statements pass through by moving out of the vector this owns.
        // Cloning them copied every subtree it did not rewrite, and three
        // passes over one block did it three times, which on a nested tree
        // was the largest source of churn in a whole render.
        let mut stmts = stmts;
        let mut rewritten = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            if i + 1 < stmts.len()
                && let CStmt::If {
                    cond,
                    then_body,
                    else_body: None,
                } = Self::semantic_stmt(&stmts[i])
                && let Some(terminator) = Self::single_terminator_stmt(&stmts[i + 1])
                && !matches!(Self::semantic_stmt(&terminator), CStmt::Return(_))
                && Self::single_terminator_stmt(then_body.as_ref()).is_none()
                && !matches!(Self::semantic_stmt(then_body), CStmt::Empty)
            {
                // The guard is the same branch, so it keeps the branch's
                // markers and the observations that own its transfer.
                let guard = Self::rewrap(
                    &stmts[i],
                    CStmt::If {
                        cond: Self::negate_condition(cond.clone()),
                        then_body: Box::new(terminator.clone_without_render_observations()),
                        else_body: None,
                    },
                );
                rewritten.push(guard);
                Self::append_stmt_body_flat(&mut rewritten, then_body.as_ref().clone());
                rewritten.push(std::mem::replace(&mut stmts[i + 1], CStmt::Empty));
                i += 2;
                continue;
            }

            rewritten.push(std::mem::replace(&mut stmts[i], CStmt::Empty));
            i += 1;
        }
        rewritten
    }

    fn rewrite_guarded_switch_if_else(stmts: Vec<CStmt>) -> Vec<CStmt> {
        // Statements pass through by moving out of the vector this owns.
        // Cloning them copied every subtree it did not rewrite, and three
        // passes over one block did it three times, which on a nested tree
        // was the largest source of churn in a whole render.
        let mut stmts = stmts;
        let mut rewritten = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            if i + 1 < stmts.len()
                && let CStmt::If {
                    then_body,
                    else_body: Some(else_body),
                    ..
                } = &stmts[i]
                && let Some(CStmt::Return(Some(CExpr::IntLit(0) | CExpr::UIntLit(0)))) =
                    Self::single_terminator_stmt(&stmts[i + 1])
            {
                let then_switch = Self::single_switch_stmt(then_body.as_ref())
                    .filter(|stmt| matches!(stmt, CStmt::Switch { default: None, .. }));
                let else_switch = Self::single_switch_stmt(else_body.as_ref())
                    .filter(|stmt| matches!(stmt, CStmt::Switch { default: None, .. }));
                let (switch_stmt, default_stmt) = match (then_switch, else_switch) {
                    (Some(switch_stmt), None) => (switch_stmt, else_body.as_ref().clone()),
                    (None, Some(switch_stmt)) => (switch_stmt, then_body.as_ref().clone()),
                    _ => {
                        rewritten.push(std::mem::replace(&mut stmts[i], CStmt::Empty));
                        i += 1;
                        continue;
                    }
                };
                if !Self::stmt_guarantees_termination(&default_stmt) {
                    rewritten.push(std::mem::replace(&mut stmts[i], CStmt::Empty));
                    i += 1;
                    continue;
                }

                if let CStmt::Switch { expr, cases, .. } = switch_stmt {
                    rewritten.push(CStmt::Switch {
                        expr,
                        cases,
                        default: Some(vec![default_stmt]),
                    });
                    rewritten.push(std::mem::replace(&mut stmts[i + 1], CStmt::Empty));
                    i += 2;
                    continue;
                }
            }

            rewritten.push(std::mem::replace(&mut stmts[i], CStmt::Empty));
            i += 1;
        }
        rewritten
    }

    fn rewrite_continue_tail_merges(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmts: Vec<CStmt>,
    ) -> Vec<CStmt> {
        // Statements pass through by moving out of the vector this owns.
        // Cloning them copied every subtree it did not rewrite, and three
        // passes over one block did it three times, which on a nested tree
        // was the largest source of churn in a whole render.
        let mut stmts = stmts;
        let mut rewritten = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            if i + 1 < stmts.len()
                && let CStmt::If {
                    cond,
                    then_body,
                    else_body: None,
                } = &stmts[i]
                && let Some((then_prefix, tail_stmt)) =
                    Self::split_trailing_update_continue(symbols, (**then_body).clone())
            {
                let else_stmts = stmts[i + 1..].to_vec();
                let else_body = Self::stmt_from_vec(else_stmts.clone());
                if !Self::stmt_guarantees_termination(&else_body) {
                    rewritten.extend(Self::factor_guarded_common_suffix(
                        cond.clone(),
                        then_prefix,
                        else_stmts,
                    ));
                    rewritten.push(tail_stmt);
                    break;
                }
            }

            rewritten.push(std::mem::replace(&mut stmts[i], CStmt::Empty));
            i += 1;
        }

        rewritten
    }

    fn factor_guarded_common_suffix(
        cond: CExpr,
        mut then_stmts: Vec<CStmt>,
        mut else_stmts: Vec<CStmt>,
    ) -> Vec<CStmt> {
        let mut common_suffix = Vec::new();
        while then_stmts.last().is_some()
            && then_stmts
                .last()
                .zip(else_stmts.last())
                .is_some_and(|(then_stmt, else_stmt)| {
                    Self::stmt_transparently_eq(then_stmt, else_stmt)
                })
            && !matches!(
                then_stmts.last().map(CStmt::unobserved),
                Some(CStmt::Return(_))
            )
            && !Self::stmt_list_contains_control_transfer(&then_stmts[..then_stmts.len() - 1])
            && !Self::stmt_list_contains_control_transfer(&else_stmts[..else_stmts.len() - 1])
        {
            let then_suffix = then_stmts.pop().expect("then suffix");
            let _else_suffix = else_stmts.pop().expect("else suffix");
            let semantic_suffix = then_suffix.clone_without_render_observations();
            common_suffix.push(semantic_suffix);
        }
        common_suffix.reverse();

        let mut out = Vec::new();
        if then_stmts.is_empty() && else_stmts.is_empty() {
            out.extend(common_suffix);
            return out;
        }

        let guarded = if then_stmts.is_empty() {
            CStmt::If {
                cond: Self::negate_condition(cond),
                then_body: Box::new(Self::stmt_from_vec(else_stmts)),
                else_body: None,
            }
        } else {
            CStmt::If {
                cond,
                then_body: Box::new(Self::stmt_from_vec(then_stmts)),
                else_body: (!else_stmts.is_empty())
                    .then(|| Box::new(Self::stmt_from_vec(else_stmts))),
            }
        };
        out.push(Self::rewrite_if_short_circuit(guarded));
        out.extend(common_suffix);
        out
    }

    fn stmt_transparently_eq(left: &CStmt, right: &CStmt) -> bool {
        let left = left.unobserved();
        let right = right.unobserved();
        match (left, right) {
            (CStmt::Empty, CStmt::Empty)
            | (CStmt::Break, CStmt::Break)
            | (CStmt::Continue, CStmt::Continue) => true,
            (CStmt::Expr(left), CStmt::Expr(right)) => left.transparently_eq(right),
            (
                CStmt::Decl {
                    ty: left_ty,
                    name: left_name,
                    init: left_init,
                },
                CStmt::Decl {
                    ty: right_ty,
                    name: right_name,
                    init: right_init,
                },
            ) => {
                left_ty == right_ty
                    && left_name == right_name
                    && match (left_init, right_init) {
                        (Some(left), Some(right)) => left.transparently_eq(right),
                        (None, None) => true,
                        _ => false,
                    }
            }
            (CStmt::Block(left), CStmt::Block(right)) => {
                Self::stmt_slices_transparently_eq(left, right)
            }
            (
                CStmt::If {
                    cond: left_cond,
                    then_body: left_then,
                    else_body: left_else,
                },
                CStmt::If {
                    cond: right_cond,
                    then_body: right_then,
                    else_body: right_else,
                },
            ) => {
                left_cond.transparently_eq(right_cond)
                    && Self::stmt_transparently_eq(left_then, right_then)
                    && match (left_else, right_else) {
                        (Some(left), Some(right)) => Self::stmt_transparently_eq(left, right),
                        (None, None) => true,
                        _ => false,
                    }
            }
            (
                CStmt::While {
                    cond: left_cond,
                    body: left_body,
                },
                CStmt::While {
                    cond: right_cond,
                    body: right_body,
                },
            )
            | (
                CStmt::DoWhile {
                    body: left_body,
                    cond: left_cond,
                },
                CStmt::DoWhile {
                    body: right_body,
                    cond: right_cond,
                },
            ) => {
                left_cond.transparently_eq(right_cond)
                    && Self::stmt_transparently_eq(left_body, right_body)
            }
            (
                CStmt::For {
                    init: left_init,
                    cond: left_cond,
                    update: left_update,
                    body: left_body,
                },
                CStmt::For {
                    init: right_init,
                    cond: right_cond,
                    update: right_update,
                    body: right_body,
                },
            ) => {
                let init_equal = match (left_init, right_init) {
                    (Some(left), Some(right)) => Self::stmt_transparently_eq(left, right),
                    (None, None) => true,
                    _ => false,
                };
                let cond_equal = match (left_cond, right_cond) {
                    (Some(left), Some(right)) => left.transparently_eq(right),
                    (None, None) => true,
                    _ => false,
                };
                let update_equal = match (left_update, right_update) {
                    (Some(left), Some(right)) => left.transparently_eq(right),
                    (None, None) => true,
                    _ => false,
                };
                init_equal
                    && cond_equal
                    && update_equal
                    && Self::stmt_transparently_eq(left_body, right_body)
            }
            (
                CStmt::Switch {
                    expr: left_expr,
                    cases: left_cases,
                    default: left_default,
                },
                CStmt::Switch {
                    expr: right_expr,
                    cases: right_cases,
                    default: right_default,
                },
            ) => {
                left_expr.transparently_eq(right_expr)
                    && left_cases.len() == right_cases.len()
                    && left_cases.iter().zip(right_cases).all(|(left, right)| {
                        left.value.transparently_eq(&right.value)
                            && Self::stmt_slices_transparently_eq(&left.body, &right.body)
                    })
                    && match (left_default, right_default) {
                        (Some(left), Some(right)) => {
                            Self::stmt_slices_transparently_eq(left, right)
                        }
                        (None, None) => true,
                        _ => false,
                    }
            }
            (CStmt::Return(left), CStmt::Return(right)) => match (left, right) {
                (Some(left), Some(right)) => left.transparently_eq(right),
                (None, None) => true,
                _ => false,
            },
            (CStmt::Goto(left), CStmt::Goto(right))
            | (CStmt::Label(left), CStmt::Label(right))
            | (CStmt::Comment(left), CStmt::Comment(right)) => left == right,
            _ => false,
        }
    }

    fn stmt_slices_transparently_eq(left: &[CStmt], right: &[CStmt]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| Self::stmt_transparently_eq(left, right))
    }

    fn stmt_list_contains_control_transfer(stmts: &[CStmt]) -> bool {
        stmts.iter().any(Self::stmt_contains_control_transfer)
    }

    fn stmt_contains_control_transfer(stmt: &CStmt) -> bool {
        if Self::stmt_is_unconditional_terminator(stmt) {
            return true;
        }
        match stmt.unobserved() {
            CStmt::Block(stmts) => Self::stmt_list_contains_control_transfer(stmts),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::stmt_contains_control_transfer(then_body)
                    || else_body
                        .as_ref()
                        .is_some_and(|stmt| Self::stmt_contains_control_transfer(stmt))
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } | CStmt::For { body, .. } => {
                Self::stmt_contains_control_transfer(body)
            }
            CStmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case| Self::stmt_list_contains_control_transfer(&case.body))
                    || default
                        .as_ref()
                        .is_some_and(|body| Self::stmt_list_contains_control_transfer(body))
            }
            _ => false,
        }
    }

    fn split_trailing_update_continue(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmt: CStmt,
    ) -> Option<(Vec<CStmt>, CStmt)> {
        let mut stmts = Self::stmt_into_vec(stmt);
        while stmts
            .last()
            .is_some_and(|stmt| matches!(stmt.unobserved(), CStmt::Empty))
        {
            stmts.pop();
        }
        if !stmts
            .last()
            .is_some_and(|stmt| matches!(stmt.unobserved(), CStmt::Continue))
        {
            return None;
        }
        stmts.pop();
        while stmts
            .last()
            .is_some_and(|stmt| matches!(stmt.unobserved(), CStmt::Empty))
        {
            stmts.pop();
        }
        let tail_stmt = stmts.pop()?;
        Self::stmt_is_self_update(symbols, &tail_stmt).then_some((stmts, tail_stmt))
    }

    /// Drop the explicit body occurrence of the exact update a certified
    /// `for` header now owns.
    fn strip_trailing_for_update(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        body: CStmt,
        update: &CExpr,
    ) -> CStmt {
        let mut stmts = Self::stmt_into_vec(body);
        while stmts
            .last()
            .is_some_and(|stmt| matches!(stmt.unobserved(), CStmt::Empty))
        {
            stmts.pop();
        }
        if stmts.last().is_some_and(|stmt| {
            matches!(stmt.unobserved(), CStmt::Expr(expr) if Self::expr_matches_for_update(symbols, expr, update))
        }) {
            stmts.pop();
        }
        Self::stmt_from_vec(stmts)
    }

    fn expr_matches_for_update(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        body_expr: &CExpr,
        for_update: &CExpr,
    ) -> bool {
        if body_expr.transparently_eq(for_update) {
            return true;
        }

        Self::normalized_self_update_signature(symbols, body_expr)
            .zip(Self::normalized_self_update_signature(symbols, for_update))
            .is_some_and(|(body, update)| body == update)
    }

    fn normalized_self_update_signature(
        _symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        expr: &CExpr,
    ) -> Option<(SymbolId, BinaryOp, CExpr)> {
        let semantic = expr.clone_without_render_observations();
        let CExpr::Binary { op, left, right } = &semantic else {
            return None;
        };
        let CExpr::Var(name) = left.unobserved() else {
            return None;
        };

        if super::self_update::is_compound_assignment_op(*op) {
            return Some((*name, *op, right.as_ref().clone()));
        }

        if *op == BinaryOp::Assign
            && let Some((compound_op, rhs)) = Self::compound_assignment_rhs_of(*name, right)
        {
            return Some((*name, compound_op, rhs));
        }

        None
    }

    fn stmt_is_self_update(
        _symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmt: &CStmt,
    ) -> bool {
        let CStmt::Expr(expr) = stmt.unobserved() else {
            return false;
        };
        match expr.unobserved() {
            CExpr::Unary { op, operand } => {
                matches!(
                    op,
                    UnaryOp::PreInc | UnaryOp::PostInc | UnaryOp::PreDec | UnaryOp::PostDec
                ) && matches!(operand.unobserved(), CExpr::Var(_))
            }
            CExpr::Binary { op, left, right } => {
                let CExpr::Var(name) = left.unobserved() else {
                    return false;
                };
                if super::self_update::is_compound_assignment_op(*op) {
                    return true;
                }
                if *op != BinaryOp::Assign {
                    return false;
                }
                let rhs_vars = Self::collect_expr_vars(right);
                rhs_vars.contains(name)
            }
            _ => false,
        }
    }

    fn truncate_dead_straight_line_tail(stmts: Vec<CStmt>) -> Vec<CStmt> {
        let mut rewritten = Vec::with_capacity(stmts.len());
        let mut terminated = false;
        for stmt in stmts {
            // Control does not only arrive here by falling in. A label is
            // somewhere a jump goes, so nothing before it can make it dead --
            // and a label carried inside a statement is still a label, which
            // dropping the statement around it would leave jumps pointing at
            // nothing.
            if Self::stmt_carries_label(&stmt) {
                terminated = false;
                rewritten.push(stmt);
                continue;
            }
            if terminated {
                continue;
            }
            terminated = Self::stmt_guarantees_termination(&stmt);
            rewritten.push(stmt);
        }
        rewritten
    }

    /// Whether anything can jump into this statement.
    fn stmt_carries_label(stmt: &CStmt) -> bool {
        match Self::semantic_stmt(stmt) {
            CStmt::Label(_) => true,
            CStmt::Block(stmts) => stmts.iter().any(Self::stmt_carries_label),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::stmt_carries_label(then_body)
                    || else_body
                        .as_ref()
                        .is_some_and(|body| Self::stmt_carries_label(body))
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } | CStmt::For { body, .. } => {
                Self::stmt_carries_label(body)
            }
            CStmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case| case.body.iter().any(Self::stmt_carries_label))
                    || default
                        .as_ref()
                        .is_some_and(|body| body.iter().any(Self::stmt_carries_label))
            }
            _ => false,
        }
    }

    fn stmt_guarantees_termination(stmt: &CStmt) -> bool {
        if Self::stmt_is_unconditional_terminator(stmt) {
            return true;
        }

        match Self::semantic_stmt(stmt) {
            CStmt::Block(stmts) => stmts
                .iter()
                .rev()
                .find(|stmt| !matches!(stmt.unobserved(), CStmt::Empty))
                .is_some_and(Self::stmt_guarantees_termination),
            CStmt::If {
                then_body,
                else_body: Some(else_body),
                ..
            } => {
                Self::stmt_guarantees_termination(then_body)
                    && Self::stmt_guarantees_termination(else_body)
            }
            _ => false,
        }
    }

    fn single_terminator_stmt(stmt: &CStmt) -> Option<CStmt> {
        if Self::stmt_is_unconditional_terminator(stmt) {
            return Some(stmt.clone());
        }

        if let CStmt::Block(stmts) = stmt.unobserved()
            && stmts.len() == 1
            && Self::stmt_is_unconditional_terminator(&stmts[0])
        {
            return Some(stmts[0].clone());
        }

        None
    }

    fn single_switch_stmt(stmt: &CStmt) -> Option<CStmt> {
        match stmt.unobserved() {
            CStmt::Switch { .. } => Some(stmt.clone()),
            CStmt::Block(stmts)
                if stmts.len() == 1 && matches!(stmts[0].unobserved(), CStmt::Switch { .. }) =>
            {
                Some(stmts[0].clone())
            }
            _ => None,
        }
    }

    fn extract_switch_with_trailing_stmt(stmt: &CStmt) -> Option<(CStmt, Option<CStmt>)> {
        match stmt.unobserved() {
            CStmt::Switch { .. } => Some((stmt.clone(), None)),
            CStmt::Block(stmts) => {
                let stmts = stmts
                    .iter()
                    .filter(|stmt| !matches!(stmt.unobserved(), CStmt::Empty))
                    .cloned()
                    .collect::<Vec<_>>();
                match stmts.as_slice() {
                    [switch @ CStmt::Switch { .. }] => Some((switch.clone(), None)),
                    [switch @ CStmt::Switch { .. }, trailing] => {
                        Some((switch.clone(), Some(trailing.clone())))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub(super) fn negate_condition(cond: CExpr) -> CExpr {
        match cond {
            CExpr::Observed { id, expr } => CExpr::observed(id, Self::negate_condition(*expr)),
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => *operand,
            CExpr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => {
                if let Some(rewritten) =
                    Self::negate_disjunctive_relation_pair(left.as_ref(), right.as_ref())
                {
                    return rewritten;
                }
                CExpr::unary(
                    UnaryOp::Not,
                    CExpr::Binary {
                        op: BinaryOp::Or,
                        left,
                        right,
                    },
                )
            }
            CExpr::Binary { op, left, right } => {
                let negated = match op {
                    BinaryOp::Eq => Some((BinaryOp::Ne, false)),
                    BinaryOp::Ne => Some((BinaryOp::Eq, false)),
                    BinaryOp::Lt => Some((BinaryOp::Ge, false)),
                    BinaryOp::Le => Some((BinaryOp::Lt, true)),
                    BinaryOp::Gt => Some((BinaryOp::Le, false)),
                    BinaryOp::Ge => Some((BinaryOp::Lt, false)),
                    _ => None,
                };

                if let Some((op, swap)) = negated {
                    if swap {
                        CExpr::Binary {
                            op,
                            left: right,
                            right: left,
                        }
                    } else {
                        CExpr::Binary { op, left, right }
                    }
                } else {
                    CExpr::unary(UnaryOp::Not, CExpr::Binary { op, left, right })
                }
            }
            other => CExpr::unary(UnaryOp::Not, other),
        }
    }

    fn negate_disjunctive_relation_pair(left: &CExpr, right: &CExpr) -> Option<CExpr> {
        let (lhs_a, rhs_a, op_a) = Self::relation_signature(left)?;
        let (lhs_b, rhs_b, op_b) = Self::relation_signature(right)?;
        if lhs_a != lhs_b || rhs_a != rhs_b {
            return None;
        }

        let negated_op = match (op_a, op_b) {
            (BinaryOp::Eq, BinaryOp::Lt) | (BinaryOp::Lt, BinaryOp::Eq) => BinaryOp::Gt,
            (BinaryOp::Eq, BinaryOp::Le) | (BinaryOp::Le, BinaryOp::Eq) => BinaryOp::Gt,
            (BinaryOp::Eq, BinaryOp::Gt) | (BinaryOp::Gt, BinaryOp::Eq) => BinaryOp::Lt,
            (BinaryOp::Eq, BinaryOp::Ge) | (BinaryOp::Ge, BinaryOp::Eq) => BinaryOp::Lt,
            _ => return None,
        };

        Some(CExpr::Binary {
            op: negated_op,
            left: Box::new(lhs_a.clone()),
            right: Box::new(rhs_a.clone()),
        })
    }

    fn relation_signature(expr: &CExpr) -> Option<(&CExpr, &CExpr, BinaryOp)> {
        match expr.unobserved() {
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                Self::relation_signature(inner)
            }
            CExpr::Binary { op, left, right }
                if matches!(
                    op,
                    BinaryOp::Eq | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
                ) =>
            {
                Some((left.as_ref(), right.as_ref(), *op))
            }
            _ => None,
        }
    }

    fn stmt_is_unconditional_terminator(stmt: &CStmt) -> bool {
        matches!(
            Self::semantic_stmt(stmt),
            CStmt::Break | CStmt::Continue | CStmt::Return(_) | CStmt::Goto(_)
        )
    }

    /// A new semantic statement inside the region markers and observation
    /// chain of an old one.
    fn rewrap(original: &CStmt, semantic: CStmt) -> CStmt {
        match original {
            CStmt::StructuredRegion { marker, stmt } => {
                CStmt::structured_region(marker.clone(), Self::rewrap(stmt, semantic))
            }
            CStmt::Observed { id, stmt } => CStmt::observed(*id, Self::rewrap(stmt, semantic)),
            _ => semantic,
        }
    }

    /// Borrow the semantic statement through all run-local metadata wrappers.
    fn semantic_stmt(mut stmt: &CStmt) -> &CStmt {
        loop {
            match stmt {
                CStmt::Observed { stmt: inner, .. }
                | CStmt::StructuredRegion { stmt: inner, .. } => stmt = inner,
                semantic => return semantic,
            }
        }
    }

    fn stmt_into_vec(stmt: CStmt) -> Vec<CStmt> {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        match semantic {
            CStmt::Block(mut stmts) => {
                observations.reapply_to_unique(&mut stmts);
                stmts
            }
            CStmt::Empty => Vec::new(),
            other => vec![observations.reapply(other)],
        }
    }

    fn stmt_from_vec(stmts: Vec<CStmt>) -> CStmt {
        match stmts.len() {
            0 => CStmt::Empty,
            1 => stmts.into_iter().next().unwrap(),
            _ => CStmt::Block(stmts),
        }
    }

    fn collect_expr_vars(expr: &CExpr) -> HashSet<SymbolId> {
        let mut vars = HashSet::new();
        Self::collect_expr_vars_into(expr, &mut vars);
        vars
    }

    fn normalize_loop_expr_refs(expr: &CExpr) -> &CExpr {
        match expr {
            CExpr::Observed { expr, .. } => Self::normalize_loop_expr_refs(expr),
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                Self::normalize_loop_expr_refs(inner)
            }
            CExpr::AddrOf(inner) => match inner.as_ref() {
                CExpr::Deref(inner2) => Self::normalize_loop_expr_refs(inner2),
                _ => expr,
            },
            CExpr::Deref(inner) => match inner.as_ref() {
                CExpr::AddrOf(inner2) => Self::normalize_loop_expr_refs(inner2),
                _ => expr,
            },
            _ => expr,
        }
    }

    fn collect_expr_vars_into(expr: &CExpr, out: &mut HashSet<SymbolId>) {
        match Self::normalize_loop_expr_refs(expr) {
            CExpr::Observed { expr, .. } => Self::collect_expr_vars_into(expr, out),
            CExpr::Var(name) => {
                out.insert(*name);
            }
            CExpr::External { .. } | CExpr::DataObject { .. } => {}
            CExpr::AddrOf(inner) | CExpr::Deref(inner) => {
                if let CExpr::Var(name) = Self::normalize_loop_expr_refs(inner) {
                    out.insert(*name);
                }
                Self::collect_expr_vars_into(inner, out);
            }
            CExpr::Unary { operand, .. } => Self::collect_expr_vars_into(operand, out),
            CExpr::Binary { left, right, .. } => {
                Self::collect_expr_vars_into(left, out);
                Self::collect_expr_vars_into(right, out);
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::collect_expr_vars_into(cond, out);
                Self::collect_expr_vars_into(then_expr, out);
                Self::collect_expr_vars_into(else_expr, out);
            }
            CExpr::Cast { expr, .. } | CExpr::Paren(expr) | CExpr::Sizeof(expr) => {
                Self::collect_expr_vars_into(expr, out)
            }
            CExpr::Call { func, args, .. } => {
                Self::collect_expr_vars_into(func, out);
                for arg in args {
                    Self::collect_expr_vars_into(arg, out);
                }
            }
            CExpr::Subscript { base, index } => {
                Self::collect_expr_vars_into(base, out);
                Self::collect_expr_vars_into(index, out);
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                Self::collect_expr_vars_into(base, out);
            }
            CExpr::Comma(values) => {
                for value in values {
                    Self::collect_expr_vars_into(value, out);
                }
            }
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::SizeofType(_) => {}
        }
    }

    /// Flatten single-element blocks.
    fn flatten(stmt: CStmt) -> CStmt {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        match semantic {
            CStmt::Block(mut stmts) if stmts.len() == 1 => {
                observations.reapply(Self::flatten(stmts.remove(0)))
            }
            CStmt::Block(stmts) if stmts.is_empty() => CStmt::Empty,
            other => observations.reapply(other),
        }
    }

    /// Fix B: Remove trailing `continue` from a loop body (it's implicit).
    /// Also remove trailing `break` inside an if-then at the end of a block
    /// if it's the only exit path.
    pub(super) fn strip_trailing_continue(stmt: CStmt) -> CStmt {
        match stmt {
            CStmt::Observed { id, stmt } => {
                let stripped = Self::strip_trailing_continue(*stmt);
                if matches!(stripped.unobserved(), CStmt::Empty) {
                    CStmt::Empty
                } else {
                    CStmt::observed(id, stripped)
                }
            }
            CStmt::Continue => CStmt::Empty,
            CStmt::Block(mut stmts) => {
                // Remove trailing Continue
                while stmts
                    .last()
                    .is_some_and(|stmt| matches!(stmt.unobserved(), CStmt::Continue))
                {
                    stmts.pop();
                }
                if stmts.is_empty() {
                    CStmt::Empty
                } else if stmts.len() == 1 {
                    stmts.remove(0)
                } else {
                    CStmt::Block(stmts)
                }
            }
            other => other,
        }
    }
}
