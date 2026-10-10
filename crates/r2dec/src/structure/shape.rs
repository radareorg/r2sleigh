//! Structural rewrites on the placed tree, `doc/adr-structure-dominator-tree.md` §5.
//!
//! Each rewrite turns a jump the text already expresses into nothing, into
//! `break`, or into the shape of a loop, and none of them carries a proof of
//! its own: the certificate is taken on the result. What comes in is the
//! placement's tree -- every edge a transfer, every block once -- and what
//! goes out reads as C was written.

use std::collections::BTreeSet;

use crate::ast::{BinaryOp, CExpr, CStmt, RenderObservationId};
use crate::symbol::SymbolId;

/// What runs after a statement completes normally.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cont {
    /// The labelled position that follows in the text.
    Label(String),
    /// The top of the enclosing loop, with its header's label when it has one.
    Loop(Option<String>),
    /// Nothing this pass can name.
    Unknown,
}

impl Cont {
    fn is_label(&self, name: &str) -> bool {
        match self {
            Self::Label(label) | Self::Loop(Some(label)) => label == name,
            _ => false,
        }
    }
}

/// The enclosing constructs a `break` or `continue` can reach.
#[derive(Debug, Clone)]
struct Scope {
    /// What follows the innermost loop or switch.
    break_to: Cont,
}

/// The structural rewrites, in order: jumps to the next position and to
/// the end of a breakable go, unreferenced labels go, and a skipped block
/// is copied into the arms that fall to it.
/// `fresh` copies a statement as a new occurrence, with markers of its own for the same cells.
pub(crate) fn shape(fresh: &mut dyn FnMut(&CStmt) -> CStmt, stmt: CStmt) -> CStmt {
    let mut stmt = stmt;
    let scope = Scope {
        break_to: Cont::Unknown,
    };
    shape_stmt(&mut stmt, Cont::Unknown, &scope);
    drop_unreferenced_labels(&mut stmt);
    // A skipped block shows only once the jumps to it have gone.
    duplicate_skipped_tails(fresh, &mut stmt);
    shape_stmt(&mut stmt, Cont::Unknown, &scope);
    drop_unreferenced_labels(&mut stmt);
    stmt
}

/// `if (c) { x = a; } else { x = b; }` is `x = c ? a : b;`, the test's markers on the statement
/// and each arm's on its value (ADR §3); after `shape`, whose copies do not remint a value.
pub(crate) fn select(
    stmt: &mut CStmt,
    convert: &dyn Fn(SymbolId, CExpr) -> CExpr,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
    selections: &mut BTreeSet<RenderObservationId>,
) {
    if let CStmt::Observed { ids, stmt: inner } = stmt
        && let Some(selection) = selection(inner, convert, block_of)
    {
        selections.extend(ids.iter());
        **inner = selection;
        return;
    }
    let mut each = |stmt: &mut CStmt| select(stmt, convert, block_of, selections);
    match stmt {
        CStmt::Observed { stmt, .. } => each(stmt),
        CStmt::Block(stmts) => stmts.iter_mut().for_each(each),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            each(then_body);
            if let Some(else_body) = else_body {
                each(else_body);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                each(init);
            }
            each(body);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => each(body),
        CStmt::Switch { cases, default, .. } => (cases.iter_mut())
            .flat_map(|case| case.body.iter_mut())
            .chain(default.iter_mut().flatten())
            .for_each(each),
        _ => {}
    }
}

/// The selection an `if` with an else is, when each arm is one assignment to the same variable
/// of a value that writes nothing and whose markers name at most one block (the certificate
/// enters one block per arm); each value converted to the variable's type before they meet.
fn selection(
    stmt: &CStmt,
    convert: &dyn Fn(SymbolId, CExpr) -> CExpr,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> Option<CStmt> {
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = stmt
    else {
        return None;
    };
    let (then_ids, target, then_value) = sole_arm_assignment(then_body)?;
    let (else_ids, other, else_value) = sole_arm_assignment(else_body)?;
    let one_block = |ids: &[RenderObservationId]| {
        let mut named = ids.iter().filter_map(|id| block_of(*id));
        named.next().is_none_or(|first| named.all(|at| at == first))
    };
    if target != other || !one_block(&then_ids) || !one_block(&else_ids) {
        return None;
    }
    let arm = |ids, value| CExpr::observe_all(ids, convert(target, value));
    let selected = CExpr::Ternary {
        cond: Box::new(cond.clone()),
        then_expr: Box::new(arm(then_ids, then_value)),
        else_expr: Box::new(arm(else_ids, else_value)),
    };
    Some(CStmt::Expr(CExpr::assign(CExpr::var(target), selected)))
}

/// An arm that is one assignment to a plain variable, with nothing else but empty statements:
/// its markers, the variable and the value.
fn sole_arm_assignment(arm: &CStmt) -> Option<(Vec<RenderObservationId>, SymbolId, CExpr)> {
    let mut ids = arm.observation_ids().into_owned();
    let stmts = match arm.unobserved() {
        CStmt::Block(stmts) => stmts.as_slice(),
        single => std::slice::from_ref(single),
    };
    let mut live = stmts
        .iter()
        .filter(|stmt| !matches!(stmt.unobserved(), CStmt::Empty));
    let (Some(only), None) = (live.next(), live.next()) else {
        return None;
    };
    let CStmt::Expr(CExpr::Binary {
        op: BinaryOp::Assign,
        left,
        right,
    }) = only.unobserved()
    else {
        return None;
    };
    let CExpr::Var(target) = left.unobserved() else {
        return None;
    };
    if !left.observation_ids().is_empty() || super::certify::writes(right) {
        return None;
    }
    ids.extend(
        stmts
            .iter()
            .flat_map(|stmt| stmt.observation_ids().into_owned()),
    );
    Some((ids, *target, right.as_ref().clone()))
}

/// `if (c) { A; goto L; } T; L:` where `T` is one block's straight-line
/// text is the compiler's tail merge of `if (c) { A } else { T }`: the
/// paths that do not jump each get their own copy of `T`, and the jumps
/// then reach the next position and go. Only the text of one block is
/// duplicated, because that is the unit a compiler merged.
fn duplicate_skipped_tails(fresh: &mut dyn FnMut(&CStmt) -> CStmt, stmt: &mut CStmt) {
    match stmt {
        CStmt::Observed { stmt, .. } => duplicate_skipped_tails(fresh, stmt),
        CStmt::Block(stmts) => duplicate_in_body(fresh, stmts),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            duplicate_skipped_tails(fresh, then_body);
            if let Some(else_body) = else_body {
                duplicate_skipped_tails(fresh, else_body);
            }
        }
        CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            duplicate_skipped_tails(fresh, body)
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                duplicate_in_body(fresh, &mut case.body);
            }
            if let Some(default) = default {
                duplicate_in_body(fresh, default);
            }
        }
        _ => {}
    }
}

/// Each statement of a body, then the body's own sequence.
fn duplicate_in_body(fresh: &mut dyn FnMut(&CStmt) -> CStmt, body: &mut Vec<CStmt>) {
    for stmt in body.iter_mut() {
        duplicate_skipped_tails(fresh, stmt);
    }
    duplicate_in_sequence(fresh, body);
}

fn duplicate_in_sequence(fresh: &mut dyn FnMut(&CStmt) -> CStmt, stmts: &mut Vec<CStmt>) {
    let mut index = 0;
    while index + 2 < stmts.len() {
        // stmts[index] branches, stmts[index + 1] is the skipped block,
        // stmts[index + 2] starts with the label the branch's jumps name.
        let Some(label) = leading_label(&stmts[index + 2]) else {
            index += 1;
            continue;
        };
        let skipped_is_plain = is_plain_block(&stmts[index + 1]);
        let mut jumps = 0;
        let mut fall_through = 0;
        count_arm_ends(&stmts[index], &label, &mut jumps, &mut fall_through);
        if !skipped_is_plain || jumps == 0 || fall_through == 0 {
            index += 1;
            continue;
        }
        let tail = stmts.remove(index + 1);
        // The first copy keeps the tail's own observations; every further
        // copy is a fresh occurrence with targets of its own.
        let mut copies =
            std::iter::once(tail.clone()).chain(std::iter::repeat_with(|| fresh(&tail)));
        append_to_falling_arms(&mut stmts[index], &mut copies);
        index += 1;
    }
}

/// One block's text, straight-line: statements only, no label or jump.
fn is_plain_block(stmt: &CStmt) -> bool {
    match stmt {
        CStmt::Observed { stmt, .. } => is_plain_block(stmt),
        CStmt::Block(stmts) => stmts.iter().all(is_plain_block),
        CStmt::Expr(_) | CStmt::Empty | CStmt::Comment(_) => true,
        _ => false,
    }
}

/// How many arm ends of a conditional jump to `label`, and how many fall
/// out of it; a conditional that does anything else counts as neither.
fn count_arm_ends(stmt: &CStmt, label: &str, jumps: &mut usize, falls: &mut usize) {
    match stmt {
        CStmt::Observed { stmt, .. } => count_arm_ends(stmt, label, jumps, falls),
        CStmt::Block(stmts) => match stmts.last() {
            Some(last) => count_arm_ends(last, label, jumps, falls),
            None => *falls += 1,
        },
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            count_arm_ends(then_body, label, jumps, falls);
            match else_body {
                Some(else_body) => count_arm_ends(else_body, label, jumps, falls),
                None => *falls += 1,
            }
        }
        CStmt::Goto(name) if name == label => *jumps += 1,
        CStmt::Goto(_) | CStmt::Return(_) | CStmt::Break | CStmt::Continue => {}
        CStmt::Expr(_) | CStmt::Empty | CStmt::Comment(_) => *falls += 1,
        // A loop or switch ending an arm is not a shape this reads.
        _ => {
            *jumps = 0;
            *falls = 0;
        }
    }
}

/// Append the next copy of the tail to every arm end that falls out.
fn append_to_falling_arms(stmt: &mut CStmt, copies: &mut impl Iterator<Item = CStmt>) {
    match stmt {
        CStmt::Observed { stmt, .. } => append_to_falling_arms(stmt, copies),
        CStmt::Block(stmts) => match stmts.last_mut() {
            Some(last) if matches!(last.unobserved(), CStmt::If { .. } | CStmt::Block(_)) => {
                append_to_falling_arms(last, copies)
            }
            Some(last)
                if matches!(
                    last.unobserved(),
                    CStmt::Goto(_) | CStmt::Return(_) | CStmt::Break | CStmt::Continue
                ) => {}
            _ => {
                if let Some(copy) = copies.next() {
                    stmts.push(copy);
                }
            }
        },
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            append_to_falling_arms(then_body, copies);
            match else_body {
                Some(else_body) => append_to_falling_arms(else_body, copies),
                None => *else_body = copies.next().map(Box::new),
            }
        }
        CStmt::Goto(_) | CStmt::Return(_) | CStmt::Break | CStmt::Continue => {}
        other => {
            if let Some(copy) = copies.next() {
                *other = CStmt::Block(vec![other.clone(), copy]);
            }
        }
    }
}

/// The first label a statement's text starts with, through markers.
fn leading_label(stmt: &CStmt) -> Option<String> {
    match stmt {
        CStmt::Observed { stmt, .. } => leading_label(stmt),
        CStmt::Block(stmts) => stmts.first().and_then(leading_label),
        CStmt::Label(name) => Some(name.clone()),
        // Entering a body-first loop at its header is entering the loop.
        CStmt::For {
            init: None,
            cond: None,
            body,
            ..
        }
        | CStmt::DoWhile { body, .. } => leading_label(body),
        _ => None,
    }
}

fn shape_seq(stmts: &mut [CStmt], next: Cont, scope: &Scope) {
    let len = stmts.len();
    for index in 0..len {
        let following = stmts[index + 1..]
            .iter()
            .find(|stmt| !matches!(stmt.unobserved(), CStmt::Empty | CStmt::Comment(_)));
        let cont = match following {
            Some(stmt) => leading_label(stmt).map_or(Cont::Unknown, Cont::Label),
            None => next.clone(),
        };
        shape_stmt(&mut stmts[index], cont, scope);
    }
}

fn shape_stmt(stmt: &mut CStmt, next: Cont, scope: &Scope) {
    match stmt {
        CStmt::Observed { stmt, .. } => {
            shape_stmt(stmt, next, scope);
        }
        CStmt::Block(stmts) => shape_seq(stmts, next, scope),
        CStmt::Goto(name) => {
            // Reaching the next position needs no jump; reaching what
            // follows the enclosing loop or switch is a break; reaching the
            // enclosing loop's own top is a continue.
            if next.is_label(name) {
                *stmt = if matches!(next, Cont::Loop(_)) {
                    CStmt::Continue
                } else {
                    CStmt::Empty
                };
            } else if scope.break_to.is_label(name) {
                *stmt = CStmt::Break;
            }
        }
        CStmt::Continue => {
            if matches!(next, Cont::Loop(_)) {
                *stmt = CStmt::Empty;
            }
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            shape_stmt(then_body, next.clone(), scope);
            if let Some(else_body) = else_body {
                shape_stmt(else_body, next, scope);
            }
        }
        CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            let inner = Scope { break_to: next };
            let top = Cont::Loop(leading_label(body));
            shape_stmt(body, top, &inner);
        }
        CStmt::Switch { cases, default, .. } => {
            let inner = Scope {
                break_to: next.clone(),
            };
            // A case body runs into the next case's text; the last runs
            // into what follows the switch.
            let mut bodies: Vec<&mut Vec<CStmt>> = cases
                .iter_mut()
                .filter(|case| !case.body.is_empty())
                .map(|case| &mut case.body)
                .collect();
            if let Some(default) = default {
                bodies.push(default);
            }
            let count = bodies.len();
            let starts: Vec<Cont> = bodies
                .iter()
                .map(|body| {
                    body.first()
                        .and_then(leading_label)
                        .map_or(Cont::Unknown, Cont::Label)
                })
                .collect();
            for (index, body) in bodies.into_iter().enumerate() {
                let cont = if index + 1 < count {
                    starts[index + 1].clone()
                } else {
                    next.clone()
                };
                shape_seq(body, cont, &inner);
            }
        }
        _ => {}
    }
}

fn collect_gotos(stmt: &CStmt, into: &mut BTreeSet<String>) {
    match stmt {
        CStmt::Observed { stmt, .. } => collect_gotos(stmt, into),
        CStmt::Block(stmts) => stmts.iter().for_each(|stmt| collect_gotos(stmt, into)),
        CStmt::Goto(name) => {
            into.insert(name.clone());
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            collect_gotos(then_body, into);
            if let Some(else_body) = else_body {
                collect_gotos(else_body, into);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                collect_gotos(init, into);
            }
            collect_gotos(body, into);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => collect_gotos(body, into),
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                case.body.iter().for_each(|stmt| collect_gotos(stmt, into));
            }
            if let Some(default) = default {
                default.iter().for_each(|stmt| collect_gotos(stmt, into));
            }
        }
        _ => {}
    }
}

fn drop_labels(stmt: &mut CStmt, referenced: &BTreeSet<String>) {
    match stmt {
        CStmt::Observed { stmt, .. } => drop_labels(stmt, referenced),
        CStmt::Block(stmts) => stmts
            .iter_mut()
            .for_each(|stmt| drop_labels(stmt, referenced)),
        CStmt::Label(name) if !referenced.contains(name) => *stmt = CStmt::Empty,
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            drop_labels(then_body, referenced);
            if let Some(else_body) = else_body {
                drop_labels(else_body, referenced);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                drop_labels(init, referenced);
            }
            drop_labels(body, referenced);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => drop_labels(body, referenced),
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                case.body
                    .iter_mut()
                    .for_each(|stmt| drop_labels(stmt, referenced));
            }
            if let Some(default) = default {
                default
                    .iter_mut()
                    .for_each(|stmt| drop_labels(stmt, referenced));
            }
        }
        _ => {}
    }
}

fn drop_unreferenced_labels(stmt: &mut CStmt) {
    let mut referenced = BTreeSet::new();
    collect_gotos(stmt, &mut referenced);
    drop_labels(stmt, &referenced);
}
