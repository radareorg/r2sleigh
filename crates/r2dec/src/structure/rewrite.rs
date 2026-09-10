//! The quality layer: rewrites on the placed tree, each preserving the
//! control certificate. What used to be the structurer's cleanup pass.

use std::collections::HashSet;

use crate::ast::{BinaryOp, CExpr, CStmt, UnaryOp};
use crate::structured_region::StructuredRegionKind;
use crate::symbol::SymbolId;

use super::ControlFlowStructurer;

impl ControlFlowStructurer<'_, '_> {
    pub(crate) fn cleanup(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmt: CStmt,
    ) -> CStmt {
        // Recurse first, then simplify
        let stmt = Self::cleanup_recurse(symbols, stmt);
        Self::flatten(stmt)
    }

    /// Recursively clean up children first, then apply local simplifications.
    fn cleanup_recurse(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmt: CStmt,
    ) -> CStmt {
        match stmt {
            CStmt::StructuredRegion { marker, stmt } => {
                let cleaned = Self::cleanup_recurse(symbols, *stmt);
                // An empty region renders nothing and its marker goes with
                // it -- except the function body's. That marker is what
                // sealing looks for at the root, so collapsing it turned a
                // function whose body rendered no statement, a forwarder
                // that is one jump out of the function, into a structurer
                // refusal reading "unrepresentable control flow", when the
                // control flow was fine and the honest report is the one the
                // proof line already makes: rendering produced no statements.
                if matches!(cleaned.unobserved(), CStmt::Empty)
                    && marker.kind() != StructuredRegionKind::FunctionBody
                {
                    CStmt::Empty
                } else {
                    CStmt::structured_region(marker, cleaned)
                }
            }
            CStmt::Observed { id, stmt } => {
                CStmt::observed(id, Self::cleanup_recurse(symbols, *stmt))
            }
            CStmt::Block(stmts) => {
                let cleaned = stmts
                    .into_iter()
                    .map(|x| Self::cleanup_recurse(symbols, x))
                    .filter(|s| !matches!(s.unobserved(), CStmt::Empty))
                    .collect();
                let cleaned = Self::rewrite_block_tail_guard_clauses(cleaned);
                let cleaned = Self::rewrite_guarded_switch_if_else(cleaned);
                let cleaned = Self::rewrite_continue_tail_merges(symbols, cleaned);
                let cleaned = Self::truncate_dead_straight_line_tail(cleaned);
                if cleaned.is_empty() {
                    CStmt::Empty
                } else if cleaned.len() == 1 {
                    cleaned.into_iter().next().unwrap()
                } else {
                    CStmt::Block(cleaned)
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let then_body = Box::new(Self::cleanup_recurse(symbols, *then_body));
                let else_body = else_body
                    .map(|e| Box::new(Self::cleanup_recurse(symbols, *e)))
                    .and_then(|e| (!matches!(e.unobserved(), CStmt::Empty)).then_some(e));
                let stmt = CStmt::If {
                    cond,
                    then_body,
                    else_body,
                };
                let stmt = Self::rewrite_if_short_circuit(stmt);
                let stmt = Self::rewrite_empty_if_bodies(stmt);
                Self::rewrite_guarded_switch_with_trailing_return(stmt)
            }
            CStmt::While { cond, body } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(symbols, *body));
                CStmt::While {
                    cond,
                    body: Box::new(body),
                }
            }
            CStmt::DoWhile { body, cond } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(symbols, *body));
                // Fix C: do { if (c) break; rest } while(1) -> while(!c) { rest }
                Self::try_convert_do_while_to_while(body, cond)
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(symbols, *body));
                let body = update
                    .as_ref()
                    .map(|update| Self::strip_trailing_for_update(symbols, body.clone(), update))
                    .unwrap_or(body);
                CStmt::For {
                    init,
                    cond,
                    update,
                    body: Box::new(body),
                }
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                let cases = cases
                    .into_iter()
                    .map(|c| crate::ast::SwitchCase {
                        value: c.value,
                        body: Self::cleanup_switch_body(symbols, c.body),
                    })
                    .collect();
                let default = default.map(|b| Self::cleanup_switch_body(symbols, b));
                CStmt::Switch {
                    expr,
                    cases,
                    default,
                }
            }
            CStmt::Expr(expr) => CStmt::Expr(Self::rewrite_compound_assignment_expr(expr)),
            other => other,
        }
    }

    fn cleanup_switch_body(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmts: Vec<CStmt>,
    ) -> Vec<CStmt> {
        let cleaned = stmts
            .into_iter()
            .map(|x| Self::cleanup_recurse(symbols, x))
            .filter(|stmt| !matches!(stmt.unobserved(), CStmt::Empty))
            .collect();
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
        let compound_op = Self::compound_assignment_op(*op)?;

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

    fn compound_assignment_op(op: BinaryOp) -> Option<BinaryOp> {
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
                then_body: then_body.clone(),
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
                rewritten.push(stmts[i + 1].clone());
                i += 2;
                continue;
            }

            rewritten.push(stmts[i].clone());
            i += 1;
        }
        rewritten
    }

    fn rewrite_guarded_switch_if_else(stmts: Vec<CStmt>) -> Vec<CStmt> {
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
                        rewritten.push(stmts[i].clone());
                        i += 1;
                        continue;
                    }
                };
                if !Self::stmt_guarantees_termination(&default_stmt) {
                    rewritten.push(stmts[i].clone());
                    i += 1;
                    continue;
                }

                if let CStmt::Switch { expr, cases, .. } = switch_stmt {
                    rewritten.push(CStmt::Switch {
                        expr,
                        cases,
                        default: Some(vec![default_stmt]),
                    });
                    rewritten.push(stmts[i + 1].clone());
                    i += 2;
                    continue;
                }
            }

            rewritten.push(stmts[i].clone());
            i += 1;
        }
        rewritten
    }

    fn rewrite_continue_tail_merges(
        symbols: &std::cell::RefCell<crate::symbol::SymbolTable>,
        stmts: Vec<CStmt>,
    ) -> Vec<CStmt> {
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

            rewritten.push(stmts[i].clone());
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

        if Self::is_compound_assign_op(*op) {
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
                if Self::is_compound_assign_op(*op) {
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

    fn is_compound_assign_op(op: BinaryOp) -> bool {
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

    fn stmt_is_unconditional_terminator(stmt: &CStmt) -> bool {
        matches!(
            Self::semantic_stmt(stmt),
            CStmt::Break | CStmt::Continue | CStmt::Return(_) | CStmt::Goto(_)
        )
    }

    fn stmt_is_unconditional_break(stmt: &CStmt) -> bool {
        matches!(Self::semantic_stmt(stmt), CStmt::Break)
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

    /// Remove the implicit terminal edge marker from a post-tested loop body.
    ///
    /// The latch condition owns both the backedge and the exit edge. Region
    /// analysis may classify that exit edge as a `break`, especially when the
    /// latch is also a singleton loop header. Emitting that marker inside the
    /// resulting do-while would force the loop to execute only once.
    fn try_convert_do_while_to_while(body: CStmt, cond: CExpr) -> CStmt {
        // Only applies when condition is always true (literal 1 or true)
        let is_infinite = match cond.unobserved() {
            CExpr::IntLit(v) => *v != 0,
            _ => false,
        };
        if !is_infinite {
            return CStmt::DoWhile {
                body: Box::new(body),
                cond,
            };
        }

        // Extract the body statements
        let stmts = match body.unobserved() {
            CStmt::Block(stmts) => stmts.clone(),
            CStmt::If { .. } => vec![body.unobserved().clone()],
            _ => {
                return CStmt::DoWhile {
                    body: Box::new(body),
                    cond,
                };
            }
        };

        if stmts.is_empty() {
            return CStmt::DoWhile {
                body: Box::new(body),
                cond,
            };
        }

        // Check if first statement is `if (c) { break; }` (no else)
        if let CStmt::If {
            cond: break_cond,
            then_body,
            else_body: None,
        } = stmts[0].unobserved()
        {
            let is_break = Self::stmt_is_unconditional_break(then_body)
                || matches!(then_body.unobserved(), CStmt::Block(v) if v.len() == 1 && Self::stmt_is_unconditional_break(&v[0]));
            if is_break {
                // Negate the condition
                let negated = CExpr::unary(crate::ast::UnaryOp::Not, break_cond.clone());
                // Remaining body after the break-guard
                let rest: Vec<CStmt> = stmts[1..].to_vec();
                let new_body = if rest.is_empty() {
                    CStmt::Empty
                } else if rest.len() == 1 {
                    rest.into_iter().next().unwrap()
                } else {
                    CStmt::Block(rest)
                };
                return CStmt::While {
                    cond: negated,
                    body: Box::new(new_body),
                };
            }
        }

        CStmt::DoWhile {
            body: Box::new(body),
            cond,
        }
    }
}
