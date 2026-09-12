//! Structural rewrites on the placed tree, `doc/adr-structure-dominator-tree.md` §5.
//!
//! Each rewrite turns a jump the text already expresses into nothing, into
//! `break`, or into the shape of a loop, and none of them carries a proof of
//! its own: the certificate is taken on the result. What comes in is the
//! placement's tree -- every edge a transfer, every block once -- and what
//! goes out reads as C was written.

use std::collections::BTreeSet;

use crate::ast::{CExpr, CStmt};
use crate::structured_region::StructuredRegionKind;

use super::ControlFlowStructurer;

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

impl ControlFlowStructurer<'_, '_> {
    /// The structural rewrites, in order: jumps to the next position and to
    /// the end of a breakable go, loops take their shape, unreferenced labels
    /// go.
    pub(crate) fn shape(fold_ctx: &crate::fold::FoldingContext<'_>, stmt: CStmt) -> CStmt {
        let mut stmt = stmt;
        let scope = Scope {
            break_to: Cont::Unknown,
        };
        Self::absorb_switch_tails(&mut stmt);
        Self::shape_stmt(&mut stmt, Cont::Unknown, &scope);
        Self::drop_unreferenced_labels(&mut stmt);
        // A skipped block shows only once the jumps to it have gone.
        Self::duplicate_skipped_tails(fold_ctx, &mut stmt);
        Self::shape_stmt(&mut stmt, Cont::Unknown, &scope);
        Self::rotate_loops(&mut stmt);
        Self::drop_unreferenced_labels(&mut stmt);
        stmt
    }

    /// A case arm that is one `goto` to a block placed after the switch takes
    /// that block as its body, when nothing else jumps there: the block was a
    /// merge only because the previous case falls into it, and C says that
    /// by writing the cases in order without `break`.
    fn absorb_switch_tails(stmt: &mut CStmt) {
        let mut references = std::collections::BTreeMap::<String, usize>::new();
        Self::count_gotos(stmt, &mut references);
        Self::absorb_in(stmt, &references);
    }

    fn absorb_in(stmt: &mut CStmt, references: &std::collections::BTreeMap<String, usize>) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::absorb_in(stmt, references)
            }
            CStmt::Block(stmts) => {
                let mut index = 0;
                while index < stmts.len() {
                    Self::absorb_in(&mut stmts[index], references);
                    if Self::switch_of(&mut stmts[index]).is_some() {
                        Self::absorb_following(stmts, index, references);
                    }
                    index += 1;
                }
            }
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::absorb_in(then_body, references);
                if let Some(else_body) = else_body {
                    Self::absorb_in(else_body, references);
                }
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::absorb_in(body, references)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body
                        .iter_mut()
                        .for_each(|stmt| Self::absorb_in(stmt, references));
                }
                if let Some(default) = default {
                    default
                        .iter_mut()
                        .for_each(|stmt| Self::absorb_in(stmt, references));
                }
            }
            _ => {}
        }
    }

    /// The switch statement inside a switch marker's wrappers.
    fn switch_of(stmt: &mut CStmt) -> Option<&mut CStmt> {
        let CStmt::StructuredRegion { marker, stmt } = stmt else {
            return None;
        };
        if marker.kind() != StructuredRegionKind::Switch {
            return None;
        }
        let mut inner: &mut CStmt = stmt;
        while let CStmt::Observed { stmt, .. } = inner {
            inner = stmt;
        }
        matches!(inner, CStmt::Switch { .. }).then_some(inner)
    }

    /// Move the labelled blocks following `stmts[index]` into the case arms
    /// that are a lone `goto` to them, one after another.
    fn absorb_following(
        stmts: &mut Vec<CStmt>,
        index: usize,
        references: &std::collections::BTreeMap<String, usize>,
    ) {
        loop {
            let Some(next) = stmts.get(index + 1) else {
                return;
            };
            let Some(label) = Self::leading_label(next) else {
                return;
            };
            let count = references.get(&label).copied().unwrap_or(0);
            let arm_index = {
                let Some(CStmt::Switch { cases, default, .. }) = Self::switch_of(&mut stmts[index])
                else {
                    return;
                };
                let bodies: Vec<&Vec<CStmt>> = cases
                    .iter()
                    .map(|case| &case.body)
                    .chain(default.iter())
                    .collect();
                let Some(arm_index) = bodies
                    .iter()
                    .position(|body| Self::lone_goto(body) == Some(label.as_str()))
                else {
                    return;
                };
                // The one other jump allowed is the previous arm falling into
                // this block, which C spells by writing the arms in order.
                let previous_falls_in = arm_index > 0
                    && bodies[arm_index - 1]
                        .last()
                        .and_then(Self::trailing_goto)
                        .is_some_and(|name| name == label);
                if count != 1 + usize::from(previous_falls_in) {
                    return;
                }
                arm_index
            };
            let block = stmts.remove(index + 1);
            let Some(CStmt::Switch { cases, default, .. }) = Self::switch_of(&mut stmts[index])
            else {
                return;
            };
            let Some(arm) = cases
                .iter_mut()
                .map(|case| &mut case.body)
                .chain(default.iter_mut())
                .nth(arm_index)
            else {
                return;
            };
            arm.pop();
            arm.push(block);
        }
    }

    /// The `goto` a statement's text ends with, through markers and blocks.
    fn trailing_goto(stmt: &CStmt) -> Option<String> {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::trailing_goto(stmt)
            }
            CStmt::Block(stmts) => stmts.last().and_then(Self::trailing_goto),
            CStmt::Goto(name) => Some(name.clone()),
            _ => None,
        }
    }

    /// The label a body jumps to when its last statement is a `goto` and the
    /// rest are plain statements.
    fn lone_goto(body: &[CStmt]) -> Option<&str> {
        let (last, rest) = body.split_last()?;
        if rest.iter().any(|stmt| {
            !matches!(
                stmt.unobserved(),
                CStmt::Expr(_) | CStmt::Empty | CStmt::Comment(_)
            )
        }) {
            return None;
        }
        match last.unobserved() {
            CStmt::Goto(name) => Some(name.as_str()),
            _ => None,
        }
    }

    fn count_gotos(stmt: &CStmt, into: &mut std::collections::BTreeMap<String, usize>) {
        let mut names = Vec::new();
        Self::collect_goto_names(stmt, &mut names);
        for name in names {
            *into.entry(name).or_default() += 1;
        }
    }

    fn collect_goto_names(stmt: &CStmt, into: &mut Vec<String>) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::collect_goto_names(stmt, into)
            }
            CStmt::Block(stmts) => stmts
                .iter()
                .for_each(|stmt| Self::collect_goto_names(stmt, into)),
            CStmt::Goto(name) => into.push(name.clone()),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::collect_goto_names(then_body, into);
                if let Some(else_body) = else_body {
                    Self::collect_goto_names(else_body, into);
                }
            }
            CStmt::For { init, body, .. } => {
                if let Some(init) = init {
                    Self::collect_goto_names(init, into);
                }
                Self::collect_goto_names(body, into);
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::collect_goto_names(body, into)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body
                        .iter()
                        .for_each(|stmt| Self::collect_goto_names(stmt, into));
                }
                if let Some(default) = default {
                    default
                        .iter()
                        .for_each(|stmt| Self::collect_goto_names(stmt, into));
                }
            }
            _ => {}
        }
    }

    /// `if (c) { A; goto L; } T; L:` where `T` is one block's straight-line
    /// text is the compiler's tail merge of `if (c) { A } else { T }`: the
    /// paths that do not jump each get their own copy of `T`, and the jumps
    /// then reach the next position and go. Only the text of one block is
    /// duplicated, because that is the unit a compiler merged.
    fn duplicate_skipped_tails(fold_ctx: &crate::fold::FoldingContext<'_>, stmt: &mut CStmt) {
        let recurse = |stmt: &mut CStmt| Self::duplicate_skipped_tails(fold_ctx, stmt);
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::duplicate_skipped_tails(fold_ctx, stmt)
            }
            CStmt::Block(stmts) => {
                stmts.iter_mut().for_each(recurse);
                Self::duplicate_in_sequence(fold_ctx, stmts);
            }
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::duplicate_skipped_tails(fold_ctx, then_body);
                if let Some(else_body) = else_body {
                    Self::duplicate_skipped_tails(fold_ctx, else_body);
                }
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::duplicate_skipped_tails(fold_ctx, body)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body.iter_mut().for_each(recurse);
                    Self::duplicate_in_sequence(fold_ctx, &mut case.body);
                }
                if let Some(default) = default {
                    default.iter_mut().for_each(recurse);
                    Self::duplicate_in_sequence(fold_ctx, default);
                }
            }
            _ => {}
        }
    }

    fn duplicate_in_sequence(fold_ctx: &crate::fold::FoldingContext<'_>, stmts: &mut Vec<CStmt>) {
        let mut index = 0;
        while index + 2 < stmts.len() {
            // stmts[index] branches, stmts[index + 1] is the skipped block,
            // stmts[index + 2] starts with the label the branch's jumps name.
            let Some(label) = Self::leading_label(&stmts[index + 2]) else {
                index += 1;
                continue;
            };
            let skipped_is_plain = Self::is_plain_block(&stmts[index + 1]);
            let mut jumps = 0;
            let mut fall_through = 0;
            Self::count_arm_ends(&stmts[index], &label, &mut jumps, &mut fall_through);
            if !skipped_is_plain || jumps == 0 || fall_through == 0 {
                index += 1;
                continue;
            }
            let tail = stmts.remove(index + 1);
            // The first copy keeps the tail's own observations; every further
            // copy is a fresh occurrence with targets of its own.
            let mut copies = std::iter::once(tail.clone()).chain(std::iter::repeat_with(|| {
                fold_ctx
                    .clone_cached_render_occurrence(std::slice::from_ref(&tail))
                    .into_iter()
                    .next()
                    .unwrap_or(CStmt::Empty)
            }));
            Self::append_to_falling_arms(&mut stmts[index], &mut copies);
            index += 1;
        }
    }

    /// One block's text, straight-line: statements only, no label or jump.
    fn is_plain_block(stmt: &CStmt) -> bool {
        match stmt {
            CStmt::StructuredRegion { marker, stmt } => {
                marker.kind() == StructuredRegionKind::Block && Self::is_plain_block(stmt)
            }
            CStmt::Observed { stmt, .. } => Self::is_plain_block(stmt),
            CStmt::Block(stmts) => stmts.iter().all(Self::is_plain_block),
            CStmt::Expr(_) | CStmt::Empty | CStmt::Comment(_) => true,
            _ => false,
        }
    }

    /// How many arm ends of a conditional jump to `label`, and how many fall
    /// out of it; a conditional that does anything else counts as neither.
    fn count_arm_ends(stmt: &CStmt, label: &str, jumps: &mut usize, falls: &mut usize) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::count_arm_ends(stmt, label, jumps, falls)
            }
            CStmt::Block(stmts) => match stmts.last() {
                Some(last) => Self::count_arm_ends(last, label, jumps, falls),
                None => *falls += 1,
            },
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::count_arm_ends(then_body, label, jumps, falls);
                match else_body {
                    Some(else_body) => Self::count_arm_ends(else_body, label, jumps, falls),
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
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::append_to_falling_arms(stmt, copies)
            }
            CStmt::Block(stmts) => match stmts.last_mut() {
                Some(last)
                    if matches!(
                        last.unobserved(),
                        CStmt::If { .. } | CStmt::Block(_) | CStmt::StructuredRegion { .. }
                    ) =>
                {
                    Self::append_to_falling_arms(last, copies)
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
                Self::append_to_falling_arms(then_body, copies);
                match else_body {
                    Some(else_body) => Self::append_to_falling_arms(else_body, copies),
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
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::leading_label(stmt)
            }
            CStmt::Block(stmts) => stmts.first().and_then(Self::leading_label),
            CStmt::Label(name) => Some(name.clone()),
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
                Some(stmt) => Self::leading_label(stmt).map_or(Cont::Unknown, Cont::Label),
                None => next.clone(),
            };
            Self::shape_stmt(&mut stmts[index], cont, scope);
        }
    }

    fn shape_stmt(stmt: &mut CStmt, next: Cont, scope: &Scope) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::shape_stmt(stmt, next, scope);
            }
            CStmt::Block(stmts) => Self::shape_seq(stmts, next, scope),
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
                Self::shape_stmt(then_body, next.clone(), scope);
                if let Some(else_body) = else_body {
                    Self::shape_stmt(else_body, next, scope);
                }
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                let inner = Scope { break_to: next };
                let top = Cont::Loop(Self::leading_label(body));
                Self::shape_stmt(body, top, &inner);
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
                            .and_then(Self::leading_label)
                            .map_or(Cont::Unknown, Cont::Label)
                    })
                    .collect();
                for (index, body) in bodies.into_iter().enumerate() {
                    let cont = if index + 1 < count {
                        starts[index + 1].clone()
                    } else {
                        next.clone()
                    };
                    Self::shape_seq(body, cont, &inner);
                }
            }
            _ => {}
        }
    }

    /// A body whose last act is `if (c) continue; else break;` is a
    /// `do { } while (c)`; `for (;;) { h: if (c) { A } else break; }` with
    /// nothing before the test is `while (c) { A }`. A header that computes
    /// before it tests stays a `for (;;)` with the test as a guard, since a
    /// comma-chained condition hides the computation rather than shaping it.
    fn rotate_loops(stmt: &mut CStmt) {
        match stmt {
            CStmt::StructuredRegion {
                marker,
                stmt: inner,
            } if marker.kind() == StructuredRegionKind::Loop => {
                Self::rotate_loops(inner);
                if let Some(rotated) = Self::rotate_post_test(inner) {
                    **inner = rotated;
                } else if let Some(rotated) = Self::rotate_pre_test(inner) {
                    **inner = rotated;
                }
            }
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::rotate_loops(stmt);
            }
            CStmt::Block(stmts) => stmts.iter_mut().for_each(Self::rotate_loops),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::rotate_loops(then_body);
                if let Some(else_body) = else_body {
                    Self::rotate_loops(else_body);
                }
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::rotate_loops(body);
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body.iter_mut().for_each(Self::rotate_loops);
                }
                if let Some(default) = default {
                    default.iter_mut().for_each(Self::rotate_loops);
                }
            }
            _ => {}
        }
    }

    /// The header block's text: its label, its statements, and the test that
    /// ends it, when the test is the last thing in it.
    fn header_parts(body: &CStmt) -> Option<(Option<String>, Vec<CStmt>, CStmt)> {
        let CStmt::StructuredRegion { marker, stmt } = body else {
            return None;
        };
        if marker.kind() != StructuredRegionKind::Block {
            return None;
        }
        let CStmt::Block(stmts) = stmt.as_ref() else {
            return None;
        };
        let mut stmts = stmts.clone();
        let last = stmts.pop()?;
        let label = match stmts.first() {
            Some(CStmt::Label(name)) => {
                let name = name.clone();
                stmts.remove(0);
                Some(name)
            }
            _ => None,
        };
        Some((label, stmts, last))
    }

    /// The `if` inside an `IfThenElse` marker, with the marker's and the
    /// observations' wrappers peeled: (cond, then, else, rewrap).
    fn peel_if(
        stmt: &CStmt,
    ) -> Option<(
        CExpr,
        CStmt,
        Option<CStmt>,
        crate::ast::StmtObservationChain,
    )> {
        let CStmt::StructuredRegion { marker, stmt } = stmt else {
            return None;
        };
        if marker.kind() != StructuredRegionKind::IfThenElse {
            return None;
        }
        let (semantic, observations) = stmt.as_ref().clone().into_semantic_with_observations();
        let CStmt::If {
            cond,
            then_body,
            else_body,
        } = semantic
        else {
            return None;
        };
        Some((cond, *then_body, else_body.map(|body| *body), observations))
    }

    fn is_break(stmt: &CStmt) -> bool {
        matches!(stmt.unobserved(), CStmt::Break)
    }

    fn is_continue(stmt: &CStmt) -> bool {
        matches!(stmt.unobserved(), CStmt::Continue)
    }

    fn rotate_pre_test(inner: &CStmt) -> Option<CStmt> {
        let CStmt::For {
            init,
            cond: None,
            update,
            body,
        } = inner
        else {
            return None;
        };
        let (label, prefix, last) = Self::header_parts(body)?;
        if !prefix
            .iter()
            .all(|stmt| matches!(stmt.unobserved(), CStmt::Empty | CStmt::Comment(_)))
        {
            return None;
        }
        let (cond, then_body, else_body, observations) = Self::peel_if(&last)?;
        let else_body = else_body?;
        let (cond, arm) = if Self::is_break(&else_body) {
            (cond, then_body)
        } else if Self::is_break(&then_body) {
            (Self::negate_condition(cond), else_body)
        } else {
            return None;
        };
        let arm = Self::strip_trailing_continue(arm);
        let rotated = if init.is_some() || update.is_some() {
            CStmt::For {
                init: init.clone(),
                cond: Some(cond),
                update: update.clone(),
                body: Box::new(arm),
            }
        } else {
            CStmt::While {
                cond,
                body: Box::new(arm),
            }
        };
        let rotated = observations.reapply(rotated);
        Some(match label {
            Some(label) => CStmt::Block(vec![CStmt::Label(label), rotated]),
            None => rotated,
        })
    }

    /// The last statement of a loop body's text, and the body without it.
    fn split_trailing(stmt: &CStmt) -> Option<(CStmt, CStmt)> {
        match stmt {
            CStmt::StructuredRegion {
                marker,
                stmt: inner,
            } => {
                let (rest, last) = Self::split_trailing(inner)?;
                Some((CStmt::structured_region(marker.clone(), rest), last))
            }
            CStmt::Block(stmts) => {
                let mut stmts = stmts.clone();
                let last = stmts.pop()?;
                if matches!(
                    last.unobserved(),
                    CStmt::Block(_) | CStmt::StructuredRegion { .. }
                ) {
                    let (rest, tail) = Self::split_trailing(&last)?;
                    stmts.push(rest);
                    return Some((CStmt::Block(stmts), tail));
                }
                Some((CStmt::Block(stmts), last))
            }
            _ => None,
        }
    }

    fn contains_continue(stmt: &CStmt) -> bool {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::contains_continue(stmt)
            }
            CStmt::Block(stmts) => stmts.iter().any(Self::contains_continue),
            CStmt::Continue => true,
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::contains_continue(then_body)
                    || else_body.as_deref().is_some_and(Self::contains_continue)
            }
            // A nested loop's `continue` is its own.
            CStmt::For { .. } | CStmt::While { .. } | CStmt::DoWhile { .. } => false,
            CStmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case| case.body.iter().any(Self::contains_continue))
                    || default
                        .as_ref()
                        .is_some_and(|body| body.iter().any(Self::contains_continue))
            }
            _ => false,
        }
    }

    fn rotate_post_test(inner: &CStmt) -> Option<CStmt> {
        let CStmt::For {
            init: None,
            cond: None,
            update: None,
            body,
        } = inner
        else {
            return None;
        };
        let (rest, last) = Self::split_trailing(body)?;
        let (cond, then_body, else_body, observations) = Self::peel_if(&last)?;
        let else_body = else_body?;
        let cond = if Self::is_continue(&then_body) && Self::is_break(&else_body) {
            cond
        } else if Self::is_break(&then_body) && Self::is_continue(&else_body) {
            Self::negate_condition(cond)
        } else {
            return None;
        };
        // Any other `continue` would reach the test instead of the top.
        if Self::contains_continue(&rest) {
            return None;
        }
        Some(observations.reapply(CStmt::DoWhile {
            body: Box::new(rest),
            cond,
        }))
    }

    fn collect_gotos(stmt: &CStmt, into: &mut BTreeSet<String>) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::collect_gotos(stmt, into)
            }
            CStmt::Block(stmts) => stmts
                .iter()
                .for_each(|stmt| Self::collect_gotos(stmt, into)),
            CStmt::Goto(name) => {
                into.insert(name.clone());
            }
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::collect_gotos(then_body, into);
                if let Some(else_body) = else_body {
                    Self::collect_gotos(else_body, into);
                }
            }
            CStmt::For { init, body, .. } => {
                if let Some(init) = init {
                    Self::collect_gotos(init, into);
                }
                Self::collect_gotos(body, into);
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::collect_gotos(body, into)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body
                        .iter()
                        .for_each(|stmt| Self::collect_gotos(stmt, into));
                }
                if let Some(default) = default {
                    default
                        .iter()
                        .for_each(|stmt| Self::collect_gotos(stmt, into));
                }
            }
            _ => {}
        }
    }

    fn drop_labels(stmt: &mut CStmt, referenced: &BTreeSet<String>) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                Self::drop_labels(stmt, referenced)
            }
            CStmt::Block(stmts) => stmts
                .iter_mut()
                .for_each(|stmt| Self::drop_labels(stmt, referenced)),
            CStmt::Label(name) if !referenced.contains(name) => *stmt = CStmt::Empty,
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::drop_labels(then_body, referenced);
                if let Some(else_body) = else_body {
                    Self::drop_labels(else_body, referenced);
                }
            }
            CStmt::For { init, body, .. } => {
                if let Some(init) = init {
                    Self::drop_labels(init, referenced);
                }
                Self::drop_labels(body, referenced);
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                Self::drop_labels(body, referenced)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body
                        .iter_mut()
                        .for_each(|stmt| Self::drop_labels(stmt, referenced));
                }
                if let Some(default) = default {
                    default
                        .iter_mut()
                        .for_each(|stmt| Self::drop_labels(stmt, referenced));
                }
            }
            _ => {}
        }
    }

    fn drop_unreferenced_labels(stmt: &mut CStmt) {
        let mut referenced = BTreeSet::new();
        Self::collect_gotos(stmt, &mut referenced);
        Self::drop_labels(stmt, &referenced);
    }
}
