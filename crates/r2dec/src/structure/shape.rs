//! Structural rewrites on the placed tree, `doc/adr-structure-dominator-tree.md` §5.
//!
//! Each rewrite turns a jump the text already expresses into nothing, into
//! `break`, or into the shape of a loop, and none of them carries a proof of
//! its own: the certificate is taken on the result. What comes in is the
//! placement's tree -- every edge a transfer, every block once -- and what
//! goes out reads as C was written.

use std::collections::BTreeSet;

use crate::ast::{BinaryOp, CExpr, CStmt, RenderObservationId, SwitchCase};
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

/// The block and instruction each marker stands for; the rewrites mint a marker for every copy of
/// a block's text they make.
pub(crate) struct Occurrences {
    blocks: Vec<u64>,
    addresses: Vec<Option<u64>>,
    /// By marker: the marker the placement wrote that this one stands for (itself, if it is one).
    origins: Vec<u32>,
    written: usize,
}

impl Occurrences {
    pub(crate) fn new(blocks: Vec<u64>, addresses: Vec<Option<u64>>) -> Self {
        let written = blocks.len();
        let origins = (0..written as u32).collect();
        Self {
            blocks,
            addresses,
            origins,
            written,
        }
    }

    /// The block a marker was written for.
    pub(crate) fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        self.blocks.get(id.index() as usize).copied()
    }

    /// The instruction each marker's line accounts for, by marker.
    pub(crate) fn into_addresses(self) -> Vec<Option<u64>> {
        self.addresses
    }

    /// `stmt` copied as a new occurrence: each marker in it replaced by one for the same block.
    pub(crate) fn fresh(&mut self, stmt: &CStmt) -> CStmt {
        remint(stmt, &mut |id| self.copy_of(id))
    }

    /// A marker of its own for the same block and instruction, for one more occurrence of it.
    pub(crate) fn copy_of(&mut self, id: RenderObservationId) -> RenderObservationId {
        let at = id.index() as usize;
        let copy = RenderObservationId::from_dense_index(self.blocks.len());
        self.blocks.push(self.blocks[at]);
        self.addresses.push(self.addresses[at]);
        self.origins.push(self.origins[at]);
        copy
    }

    /// How many markers exist, to hand back to `retract` when a stage's copies are refused.
    pub(crate) fn issued(&self) -> usize {
        self.blocks.len()
    }

    /// Forget the markers minted after `issued` markers existed.
    pub(crate) fn retract(&mut self, issued: usize) {
        self.blocks.truncate(issued);
        self.addresses.truncate(issued);
        self.origins.truncate(issued);
    }
}

impl super::certify::Placed for Occurrences {
    fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        Self::block_of(self, id)
    }

    fn statement_of(&self, id: RenderObservationId) -> Option<RenderObservationId> {
        let origin = *self.origins.get(id.index() as usize)?;
        Some(RenderObservationId::from_dense_index(origin as usize))
    }

    fn written(&self) -> usize {
        self.written
    }

    fn edge_copy(&self, id: RenderObservationId) -> bool {
        self.addresses.get(id.index() as usize) == Some(&None)
    }
}

impl super::condition::Marks for Occurrences {
    fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        Self::block_of(self, id)
    }

    fn copy_of(&mut self, id: RenderObservationId) -> RenderObservationId {
        Self::copy_of(self, id)
    }
}

/// What the rewrites may rely on that the tree does not say.
pub(crate) struct Evidence<'a> {
    /// Whether a statement is a call to a callee declared never to return.
    pub(crate) never_returns: &'a dyn Fn(&CStmt) -> bool,
    /// Whether any callee is declared never to return; when none is, `never_returns` is false everywhere.
    pub(crate) declares_noreturn: bool,
    /// Whether the return ending a block hands back a merge whose inputs are pairwise distinct
    /// values (the compiler merged returns of different values into this one).
    pub(crate) distinct_return: &'a dyn Fn(u64) -> bool,
}

/// The structural rewrites (ADR §5): jumps to the next position go, a skipped block is copied to the
/// arms that fall to it, a terminal block to the sites that reach it; labels nothing names go.
pub(crate) fn shape(occ: &mut Occurrences, ev: &Evidence<'_>, stmt: CStmt) -> CStmt {
    let mut stmt = stmt;
    let scope = Scope {
        break_to: Cont::Unknown,
    };
    shape_stmt(&mut stmt, Cont::Unknown, &scope);
    drop_unreferenced_labels(&mut stmt);
    // A skipped block is copied while the jumps over it stand, which a terminal block's copies replace.
    duplicate_skipped_tails(occ, &mut stmt);
    shape_stmt(&mut stmt, Cont::Unknown, &scope);
    drop_unreferenced_labels(&mut stmt);
    super::tails::inline_tails(occ, ev, &mut stmt);
    shape_stmt(&mut stmt, Cont::Unknown, &scope);
    drop_unreferenced_labels(&mut stmt);
    stmt
}

/// `stmt` copied as a new occurrence: each marker in it replaced by the one `mint` gives for it.
fn remint(stmt: &CStmt, mint: &mut dyn FnMut(RenderObservationId) -> RenderObservationId) -> CStmt {
    let copy = |stmts: &[CStmt],
                mint: &mut dyn FnMut(RenderObservationId) -> RenderObservationId| {
        stmts
            .iter()
            .map(|stmt| remint(stmt, mint))
            .collect::<Vec<_>>()
    };
    match stmt {
        CStmt::Observed { .. } => {
            let ids = stmt
                .observation_ids()
                .iter()
                .map(|id| mint(*id))
                .collect::<Vec<_>>();
            CStmt::observe_all(ids, remint(stmt.unobserved(), mint))
        }
        CStmt::Block(stmts) => CStmt::Block(copy(stmts, mint)),
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => CStmt::If {
            cond: cond.clone(),
            then_body: Box::new(remint(then_body, mint)),
            else_body: else_body.as_ref().map(|body| Box::new(remint(body, mint))),
        },
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => CStmt::For {
            init: init.as_ref().map(|init| Box::new(remint(init, mint))),
            cond: cond.clone(),
            update: update.clone(),
            body: Box::new(remint(body, mint)),
        },
        CStmt::While { cond, body } => CStmt::While {
            cond: cond.clone(),
            body: Box::new(remint(body, mint)),
        },
        CStmt::DoWhile { body, cond } => CStmt::DoWhile {
            body: Box::new(remint(body, mint)),
            cond: cond.clone(),
        },
        CStmt::Switch {
            expr,
            cases,
            default,
        } => CStmt::Switch {
            expr: expr.clone(),
            cases: cases
                .iter()
                .map(|case| SwitchCase {
                    value: case.value.clone(),
                    body: copy(&case.body, mint),
                })
                .collect(),
            default: default.as_ref().map(|body| copy(body, mint)),
        },
        other => other.clone(),
    }
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
fn duplicate_skipped_tails(occ: &mut Occurrences, stmt: &mut CStmt) {
    match stmt {
        CStmt::Observed { stmt, .. } => duplicate_skipped_tails(occ, stmt),
        CStmt::Block(stmts) => duplicate_in_body(occ, stmts),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            duplicate_skipped_tails(occ, then_body);
            if let Some(else_body) = else_body {
                duplicate_skipped_tails(occ, else_body);
            }
        }
        CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            duplicate_skipped_tails(occ, body)
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                duplicate_in_body(occ, &mut case.body);
            }
            if let Some(default) = default {
                duplicate_in_body(occ, default);
            }
        }
        _ => {}
    }
}

/// Each statement of a body, then the body's own sequence.
fn duplicate_in_body(occ: &mut Occurrences, body: &mut Vec<CStmt>) {
    for stmt in body.iter_mut() {
        duplicate_skipped_tails(occ, stmt);
    }
    duplicate_in_sequence(occ, body);
}

fn duplicate_in_sequence(occ: &mut Occurrences, stmts: &mut Vec<CStmt>) {
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
            std::iter::once(tail.clone()).chain(std::iter::repeat_with(|| occ.fresh(&tail)));
        append_to_falling_arms(&mut stmts[index], &mut copies);
        index += 1;
    }
}

/// One block's text, straight-line: statements only, no label or jump, and nothing unproven.
fn is_plain_block(stmt: &CStmt) -> bool {
    match stmt {
        CStmt::Observed { stmt, .. } => is_plain_block(stmt),
        CStmt::Block(stmts) => stmts.iter().all(is_plain_block),
        CStmt::Expr(_) | CStmt::Empty | CStmt::Comment(_) => super::tails::copyable(stmt),
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

pub(super) fn collect_gotos(stmt: &CStmt, into: &mut BTreeSet<String>) {
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

pub(super) fn drop_unreferenced_labels(stmt: &mut CStmt) {
    let mut referenced = BTreeSet::new();
    collect_gotos(stmt, &mut referenced);
    drop_labels(stmt, &referenced);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(index: usize) -> RenderObservationId {
        RenderObservationId::from_dense_index(index)
    }

    /// Markers 0 and 1, for blocks 0x10 and 0x20 and their instructions 0x11 and 0x21.
    fn marks() -> Occurrences {
        Occurrences::new(vec![0x10, 0x20], vec![Some(0x11), Some(0x21)])
    }

    #[test]
    fn a_copy_is_a_marker_of_its_own_for_the_same_block_and_instruction() {
        let mut marks = marks();
        let copy = marks.copy_of(id(1));
        assert_ne!(copy, id(1));
        assert_eq!((marks.block_of(copy), marks.issued()), (Some(0x20), 3));
        assert_eq!(marks.into_addresses(), [Some(0x11), Some(0x21), Some(0x21)]);
    }

    #[test]
    fn fresh_text_replaces_each_marker_it_carries_with_a_copy() {
        let mut marks = marks();
        let text = CStmt::Block(vec![
            CStmt::observe_all([id(0)], CStmt::Break),
            CStmt::observe_all([id(1)], CStmt::Break),
        ]);
        let CStmt::Block(copies) = marks.fresh(&text) else {
            panic!("a block stays a block");
        };
        let ids: Vec<_> = copies
            .iter()
            .flat_map(|c| c.observation_ids().into_owned())
            .collect();
        assert_eq!(ids, [id(2), id(3)]);
        let blocks: Vec<_> = ids.iter().map(|id| marks.block_of(*id)).collect();
        assert_eq!(blocks, [Some(0x10), Some(0x20)]);
        assert_eq!(marks.issued(), 4);
    }

    #[test]
    fn a_retraction_forgets_the_markers_minted_after_it_and_their_instructions() {
        let mut marks = marks();
        let before = marks.issued();
        let copy = marks.copy_of(id(0));
        marks.copy_of(id(1));
        marks.retract(before);
        assert_eq!((marks.issued(), marks.block_of(copy)), (before, None));
        assert_eq!(marks.block_of(id(1)), Some(0x20));
        assert_eq!(marks.into_addresses(), [Some(0x11), Some(0x21)]);
    }
}
