//! D470: a class's members spelled as one local where the finished text satisfies Chaitin's
//! condition (doc/adr-one-ir.md, "D470 as built: renaming under a text certificate").

use std::collections::BTreeMap;

use super::condition::Marks;
use crate::ast::{BinaryOp, CExpr, CStmt, RenderObservationId, UnaryOp};
use crate::symbol::SymbolId;

/// A candidate symbol, the r2ssa class its value is in, and the value, which orders the joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Member {
    pub(crate) class: u32,
    pub(crate) value: u32,
    pub(crate) symbol: SymbolId,
}

/// Why a member kept its own symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kept {
    /// The text reads the tree as no statement graph it models.
    Unmodelled,
    /// An address-of, a compound or nested assignment, `++` or a declaration names it.
    Occurrence,
    /// It is live where the function begins.
    LiveAtEntry,
    /// Its C type is not its group's.
    Type,
    /// A write of it, or of a group member, leaves the other live without copying it.
    Interferes,
}

/// What the renaming did: members considered, members joined, and each kept one's cause.
#[derive(Debug, Default)]
pub(crate) struct Renamed {
    pub(crate) members: usize,
    pub(crate) joined: usize,
    pub(crate) kept: BTreeMap<Kept, usize>,
    /// The markers of each deleted `L = L;`, which now stand on an empty statement.
    pub(crate) deleted: Vec<RenderObservationId>,
    /// Each joined member's symbol and its group's, in member order.
    pub(crate) spelled: Vec<(SymbolId, SymbolId)>,
}

const NONE: u32 = u32::MAX;

/// Rename each class's joinable members to one member's symbol and delete `L = L;`.
/// `members` is sorted; `same_type` compares two symbols' C types. O(statements + live ranges).
pub(crate) fn rename(
    body: &mut CStmt,
    members: &[Member],
    symbols: usize,
    same_type: &dyn Fn(SymbolId, SymbolId) -> bool,
) -> Renamed {
    let mut renamed = Renamed {
        members: members.len(),
        ..Renamed::default()
    };
    let mut slot = vec![NONE; symbols];
    for (index, member) in members.iter().enumerate() {
        debug_assert_eq!(slot[member.symbol.index()], NONE, "one value per symbol");
        slot[member.symbol.index()] = index as u32;
    }
    let Some(graph) = Graph::read(body, &slot, members.len()) else {
        *renamed.kept.entry(Kept::Unmodelled).or_default() += members.len();
        return renamed;
    };
    let group = groups(&graph, members, same_type, &mut renamed);
    if renamed.joined == 0 {
        return renamed;
    }
    // The group's symbol is the member the text declares first, so no new name is declared.
    let mut first = vec![None::<SymbolId>; members.len()];
    for (index, leader) in group
        .iter()
        .enumerate()
        .filter(|(_, leader)| **leader != NONE)
    {
        let symbol = members[index].symbol;
        let held = &mut first[*leader as usize];
        *held = Some(held.map_or(symbol, |held| held.min(symbol)));
    }
    let mut to = vec![None; symbols];
    for (index, leader) in group
        .iter()
        .enumerate()
        .filter(|(_, leader)| **leader != NONE)
    {
        let target = first[*leader as usize].filter(|target| *target != members[index].symbol);
        to[members[index].symbol.index()] = target;
        renamed
            .spelled
            .extend(target.map(|target| (members[index].symbol, target)));
    }
    body.visit_exprs_mut(&mut |expr| {
        expr.visit_mut(&mut |node| {
            if let CExpr::Var(symbol) = node
                && let Some(Some(leader)) = to.get(symbol.index())
            {
                *symbol = *leader;
            }
        })
    });
    let mut spelled = vec![false; symbols];
    renamed
        .spelled
        .iter()
        .for_each(|(_, to)| spelled[to.index()] = true);
    delete_self_copies(body, &spelled, &mut renamed.deleted);
    renamed.deleted.sort();
    renamed
}

/// Per-candidate stamps of the backward liveness walk: a node is entered once per candidate.
struct Spread {
    live_in: Vec<u32>,
    out: Vec<u32>,
    pending: Vec<u32>,
}

impl Spread {
    /// Enters each node that reads candidate `k`.
    fn seed(&mut self, k: u32, reads: &[u32]) {
        for node in reads {
            if std::mem::replace(&mut self.live_in[*node as usize], k) != k {
                self.pending.push(*node);
            }
        }
    }

    /// Drains `pending` backward for candidate `k`, stopping at `k`'s writes.
    fn back(&mut self, k: u32, preds: &[Vec<u32>], def: &[u32], live: &mut Live) {
        while let Some(node) = self.pending.pop() {
            for pred in &preds[node as usize] {
                self.enter(*pred as usize, k, def, live);
            }
        }
    }

    /// `k` is live out of `pred`; it is live into `pred` too unless `pred` writes `k`.
    fn enter(&mut self, pred: usize, k: u32, def: &[u32], live: &mut Live) {
        if std::mem::replace(&mut self.out[pred], k) == k {
            return;
        }
        live.out[pred].push(k);
        live.after[k as usize].push(pred as u32);
        if def[pred] != k && std::mem::replace(&mut self.live_in[pred], k) != k {
            self.pending.push(pred as u32);
        }
    }
}

/// Each candidate's group leader, or `NONE` where it kept its symbol (the cause counted).
fn groups(
    graph: &Graph,
    members: &[Member],
    same_type: &dyn Fn(SymbolId, SymbolId) -> bool,
    renamed: &mut Renamed,
) -> Vec<u32> {
    let live = graph.live_out();
    let mut group = vec![NONE; members.len()];
    let mut leaders = Vec::<u32>::new();
    for (index, member) in members.iter().enumerate() {
        let index = index as u32;
        // A member the text never spells has nothing to rename.
        if !graph.occurs[index as usize] {
            renamed.members -= 1;
            continue;
        }
        let kept = match (graph.refused[index as usize], live.at_entry[index as usize]) {
            (true, _) => Some(Kept::Occurrence),
            (false, true) => Some(Kept::LiveAtEntry),
            _ => None,
        };
        if let Some(kept) = kept {
            *renamed.kept.entry(kept).or_default() += 1;
            continue;
        }
        let open = (leaders.last().copied())
            .filter(|leader| members[*leader as usize].class == member.class);
        let Some(leader) = open else {
            group[index as usize] = index;
            leaders.push(index);
            continue;
        };
        let kept = match same_type(members[leader as usize].symbol, member.symbol) {
            false => Some(Kept::Type),
            true => (!graph.joins(&live, &group, leader, index)).then_some(Kept::Interferes),
        };
        match kept {
            Some(kept) => *renamed.kept.entry(kept).or_default() += 1,
            None => {
                group[index as usize] = leader;
                renamed.joined += 1;
            }
        }
    }
    group
}

/// Each `L = L;` of a group's symbol becomes an empty statement under the markers it carried.
fn delete_self_copies(stmt: &mut CStmt, groups: &[bool], deleted: &mut Vec<RenderObservationId>) {
    if self_copy(stmt.unobserved()).is_some_and(|symbol| groups[symbol.index()]) {
        let ids = stmt.observation_ids().into_owned();
        deleted.extend(ids.iter().copied());
        *stmt = CStmt::observe_all(ids, CStmt::Empty);
        return;
    }
    each_child(stmt, &mut |child| {
        delete_self_copies(child, groups, deleted)
    });
}

/// The symbol of `x = x;` with no marker on either side.
fn self_copy(stmt: &CStmt) -> Option<SymbolId> {
    let CStmt::Expr(CExpr::Binary {
        op: BinaryOp::Assign,
        left,
        right,
    }) = stmt
    else {
        return None;
    };
    match (left.as_ref(), right.as_ref()) {
        (CExpr::Var(a), CExpr::Var(b)) if a == b => Some(*a),
        _ => None,
    }
}

/// The statements directly inside `stmt`.
fn each_child(stmt: &mut CStmt, f: &mut impl FnMut(&mut CStmt)) {
    match stmt {
        CStmt::Observed { stmt, .. } => f(stmt),
        CStmt::Block(stmts) => stmts.iter_mut().for_each(f),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            f(then_body);
            if let Some(arm) = else_body {
                f(arm);
            }
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => f(body),
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                f(init);
            }
            f(body);
        }
        CStmt::Switch { cases, default, .. } => {
            (cases.iter_mut()).for_each(|case| case.body.iter_mut().for_each(&mut *f));
            default.iter_mut().flatten().for_each(f);
        }
        _ => {}
    }
}

/// The finished tree as C runs it: a node per simple statement and per control test.
struct Graph {
    succ: Vec<Vec<u32>>,
    reads: Vec<Vec<u32>>,
    def: Vec<u32>,
    /// Where the node is exactly `x = y;` of two candidates, `(x, y)`.
    exact: Vec<Option<(u32, u32)>>,
    refused: Vec<bool>,
    /// Whether the text spells each candidate at all.
    occurs: Vec<bool>,
    writes: Vec<Vec<u32>>,
}

/// Each candidate's liveness: the nodes after which it is live, and whether it is live at entry.
struct Live {
    out: Vec<Vec<u32>>,
    /// The same pairs by candidate: the nodes after which it is live.
    after: Vec<Vec<u32>>,
    at_entry: Vec<bool>,
}

/// An enclosing loop or switch: where a `break` goes, and a loop's `continue` target.
struct Frame {
    breaks: Vec<u32>,
    next: Option<u32>,
}

struct Reader<'a> {
    graph: Graph,
    slot: &'a [u32],
    frames: Vec<Frame>,
    labels: BTreeMap<String, u32>,
    gotos: Vec<(u32, String)>,
    unmodelled: bool,
}

impl Graph {
    /// Read `body` from a node of its own; `None` where a construct is not modelled. O(statements).
    fn read(body: &CStmt, slot: &[u32], members: usize) -> Option<Self> {
        let mut reader = Reader {
            graph: Self {
                succ: Vec::new(),
                reads: Vec::new(),
                def: Vec::new(),
                exact: Vec::new(),
                refused: vec![false; members],
                occurs: vec![false; members],
                writes: vec![Vec::new(); members],
            },
            slot,
            frames: Vec::new(),
            labels: BTreeMap::new(),
            gotos: Vec::new(),
            unmodelled: false,
        };
        let entry = reader.node(Vec::new(), Vec::new());
        reader.walk(body, vec![entry]);
        for (from, label) in std::mem::take(&mut reader.gotos) {
            match reader.labels.get(&label) {
                Some(to) => reader.graph.succ[from as usize].push(*to),
                None => reader.unmodelled = true,
            }
        }
        (!reader.unmodelled).then_some(reader.graph)
    }

    /// Text liveness per candidate: backward from each read, each node entered once per candidate.
    /// Terminates: the per-candidate stamps only grow and the graph is finite.
    fn live_out(&self) -> Live {
        let nodes = self.succ.len();
        let mut preds = vec![Vec::new(); nodes];
        for (from, succ) in self.succ.iter().enumerate() {
            succ.iter()
                .for_each(|to| preds[*to as usize].push(from as u32));
        }
        let mut readers = vec![Vec::new(); self.writes.len()];
        for (node, reads) in self.reads.iter().enumerate() {
            reads
                .iter()
                .for_each(|k| readers[*k as usize].push(node as u32));
        }
        let mut live = Live {
            out: vec![Vec::new(); nodes],
            after: vec![Vec::new(); self.writes.len()],
            at_entry: vec![false; self.writes.len()],
        };
        let mut spread = Spread {
            live_in: vec![NONE; nodes],
            out: vec![NONE; nodes],
            pending: Vec::new(),
        };
        for (k, reads) in readers.iter().enumerate() {
            let k = k as u32;
            spread.seed(k, reads);
            spread.back(k, &preds, &self.def, &mut live);
            live.at_entry[k as usize] = spread.live_in[0] == k;
        }
        live
    }

    /// Whether `next` may join `leader`'s group: Chaitin's condition both ways against every
    /// member, over `next`'s writes' live-out sets and `next`'s own live range.
    fn joins(&self, live: &Live, group: &[u32], leader: u32, next: u32) -> bool {
        let in_group = |k: u32| k != next && group[k as usize] == leader;
        let copies = |node: u32, x: u32, y: u32| self.exact[node as usize] == Some((x, y));
        let own = self.writes[next as usize].iter().all(|node| {
            (live.out[*node as usize].iter()).all(|y| !in_group(*y) || copies(*node, next, *y))
        });
        own && live.after[next as usize].iter().all(|node| {
            let g = self.def[*node as usize];
            g == NONE || !in_group(g) || copies(*node, g, next)
        })
    }
}

impl Reader<'_> {
    /// The candidate a plain copy `x = y;` reads, where its right side is one.
    fn copied(&self, right: &CExpr) -> Option<u32> {
        match right {
            CExpr::Var(y) => self.slot_of(*y),
            _ => None,
        }
    }

    fn slot_of(&self, symbol: SymbolId) -> Option<u32> {
        (self.slot.get(symbol.index()).copied()).filter(|slot| *slot != NONE)
    }

    /// A new node entered from each of `open`.
    fn node(&mut self, open: Vec<u32>, reads: Vec<u32>) -> u32 {
        let node = self.graph.succ.len() as u32;
        self.graph.succ.push(Vec::new());
        self.graph.reads.push(reads);
        self.graph.def.push(NONE);
        self.graph.exact.push(None);
        for from in open {
            self.graph.succ[from as usize].push(node);
        }
        node
    }

    fn edge(&mut self, from: impl IntoIterator<Item = u32>, to: u32) {
        from.into_iter()
            .for_each(|from| self.graph.succ[from as usize].push(to));
    }

    /// The candidates `expr` reads; one it writes or takes the address of is refused.
    fn scan(&mut self, expr: &CExpr, target: bool, reads: &mut Vec<u32>) {
        match expr.unobserved() {
            CExpr::Var(symbol) => {
                if let Some(k) = self.slot_of(*symbol) {
                    self.graph.occurs[k as usize] = true;
                    match target {
                        true => self.graph.refused[k as usize] = true,
                        false => reads.push(k),
                    }
                }
            }
            CExpr::AddrOf(inner) => self.scan(inner, true, reads),
            CExpr::Binary { op, left, right } if op.writes_left_operand() => {
                self.scan(left, true, reads);
                self.scan(right, target, reads);
            }
            CExpr::Unary {
                op: UnaryOp::PreInc | UnaryOp::PreDec | UnaryOp::PostInc | UnaryOp::PostDec,
                operand,
            } => self.scan(operand, true, reads),
            other => (other.children())
                .into_iter()
                .for_each(|child| self.scan(child, target, reads)),
        }
    }

    fn reads(&mut self, exprs: &[&CExpr]) -> Vec<u32> {
        let mut reads = Vec::new();
        exprs
            .iter()
            .for_each(|expr| self.scan(expr, false, &mut reads));
        reads
    }

    /// A statement-level expression: `x = e;` writes `x`, every other occurrence is scanned.
    fn statement(&mut self, expr: &CExpr, open: Vec<u32>) -> u32 {
        let mut reads = Vec::new();
        let (mut def, mut exact) = (NONE, None);
        match expr.unobserved() {
            CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                right,
            } if matches!(left.as_ref(), CExpr::Var(_)) => {
                self.scan(right, false, &mut reads);
                let CExpr::Var(x) = left.as_ref() else {
                    unreachable!("matched a variable")
                };
                if let Some(x) = self.slot_of(*x) {
                    self.graph.occurs[x as usize] = true;
                    def = x;
                    exact = self.copied(right).map(|y| (x, y));
                }
            }
            _ => self.scan(expr, false, &mut reads),
        }
        let node = self.node(open, reads);
        if def != NONE {
            self.graph.def[node as usize] = def;
            self.graph.exact[node as usize] = exact;
            self.graph.writes[def as usize].push(node);
        }
        node
    }

    fn walk_seq(&mut self, stmts: &[CStmt], mut open: Vec<u32>) -> Vec<u32> {
        for stmt in stmts {
            open = self.walk(stmt, open);
        }
        open
    }

    /// Walk `stmt` entered from `open`; the nodes control leaves it from by falling through.
    fn walk(&mut self, stmt: &CStmt, open: Vec<u32>) -> Vec<u32> {
        match stmt {
            CStmt::Observed { stmt, .. } => self.walk(stmt, open),
            CStmt::Block(stmts) => self.walk_seq(stmts, open),
            CStmt::Expr(expr) => vec![self.statement(expr, open)],
            CStmt::Decl { name, init, .. } => {
                if let Some(k) = self.slot_of(*name) {
                    self.graph.occurs[k as usize] = true;
                    self.graph.refused[k as usize] = true;
                }
                let reads = self.reads(&init.iter().collect::<Vec<_>>());
                vec![self.node(open, reads)]
            }
            // A trap's fallthrough is one edge more than C runs: liveness only grows.
            CStmt::Empty | CStmt::Comment(_) | CStmt::Gap(_) => open,
            CStmt::Return(value) => {
                let reads = self.reads(&value.iter().collect::<Vec<_>>());
                self.node(open, reads);
                Vec::new()
            }
            CStmt::Label(name) => {
                let node = self.node(open, Vec::new());
                if self.labels.insert(name.clone(), node).is_some() {
                    self.unmodelled = true;
                }
                vec![node]
            }
            CStmt::Goto(name) => {
                (open.into_iter()).for_each(|from| self.gotos.push((from, name.clone())));
                Vec::new()
            }
            CStmt::Break => {
                match self.frames.last_mut() {
                    Some(frame) => frame.breaks.extend(open),
                    None => self.unmodelled = true,
                }
                Vec::new()
            }
            CStmt::Continue => {
                match self.frames.iter().rev().find_map(|frame| frame.next) {
                    Some(next) => self.edge(open, next),
                    None => self.unmodelled = true,
                }
                Vec::new()
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let reads = self.reads(&[cond]);
                let test = self.node(open, reads);
                let mut ends = self.walk(then_body, vec![test]);
                match else_body {
                    Some(arm) => ends.extend(self.walk(arm, vec![test])),
                    None => ends.push(test),
                }
                ends
            }
            CStmt::While { .. } | CStmt::DoWhile { .. } | CStmt::For { .. } => {
                self.walk_loop(stmt, open)
            }
            CStmt::Switch { .. } => self.walk_switch(stmt, open),
        }
    }

    /// A `while`, `do` or `for` entered from `open`; the nodes control leaves it from.
    fn walk_loop(&mut self, stmt: &CStmt, open: Vec<u32>) -> Vec<u32> {
        match stmt {
            CStmt::While { cond, body } => {
                let reads = self.reads(&[cond]);
                let test = self.node(open, reads);
                let ends = self.looped(body, vec![test], test);
                self.edge(ends.0, test);
                [vec![test], ends.1].concat()
            }
            CStmt::DoWhile { body, cond } => {
                let top = self.node(open, Vec::new());
                let reads = self.reads(&[cond]);
                let test = self.node(Vec::new(), reads);
                let (ends, breaks) = self.looped(body, vec![top], test);
                self.edge(ends, test);
                self.edge([test], top);
                [vec![test], breaks].concat()
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let open = match init {
                    Some(init) => self.walk(init, open),
                    None => open,
                };
                let reads = self.reads(&cond.iter().collect::<Vec<_>>());
                let test = self.node(open, reads);
                let reads = self.reads(&update.iter().collect::<Vec<_>>());
                // An assignment in the update is no statement: `scan` refused what it writes.
                let step = self.node(Vec::new(), reads);
                let (ends, breaks) = self.looped(body, vec![test], step);
                self.edge(ends, step);
                self.edge([step], test);
                match cond {
                    Some(_) => [vec![test], breaks].concat(),
                    None => breaks,
                }
            }
            _ => unreachable!("`walk` passes only a loop"),
        }
    }

    /// A `switch` entered from `open`: each case falls into the next; breaks leave it.
    fn walk_switch(&mut self, stmt: &CStmt, open: Vec<u32>) -> Vec<u32> {
        let CStmt::Switch {
            expr,
            cases,
            default,
        } = stmt
        else {
            unreachable!("`walk` passes only a switch")
        };
        let mut exprs = vec![expr];
        exprs.extend(cases.iter().map(|case| &case.value));
        exprs.extend(cases.iter().filter_map(|case| case.test.as_ref()));
        let reads = self.reads(&exprs);
        let select = self.node(open, reads);
        self.frames.push(Frame {
            breaks: Vec::new(),
            next: None,
        });
        let mut falls = Vec::new();
        for case in cases {
            falls = self.walk_seq(&case.body, [vec![select], falls].concat());
        }
        let mut ends = match default {
            Some(arm) => self.walk_seq(arm, [vec![select], falls].concat()),
            None => [vec![select], falls].concat(),
        };
        ends.extend(
            self.frames
                .pop()
                .map(|frame| frame.breaks)
                .unwrap_or_default(),
        );
        ends
    }

    /// A loop body entered from `open` whose `continue` goes to `next`: its ends and its breaks.
    fn looped(&mut self, body: &CStmt, open: Vec<u32>, next: u32) -> (Vec<u32>, Vec<u32>) {
        self.frames.push(Frame {
            breaks: Vec::new(),
            next: Some(next),
        });
        let ends = self.walk(body, open);
        let frame = self.frames.pop().expect("pushed above");
        (ends, frame.breaks)
    }
}

/// Rotate each `for (;;)` whose last test's arms hold only markers of deleted copies, a `break` or
/// a `continue`: those markers move before the test, then `rotate` reads the loop. The number rotated.
pub(crate) fn rotate_emptied(
    stmt: &mut CStmt,
    deleted: &[RenderObservationId],
    marks: &mut dyn Marks,
) -> usize {
    let mut inner = 0;
    each_child(stmt, &mut |child| {
        inner += rotate_emptied(child, deleted, marks)
    });
    let CStmt::For {
        init: None,
        cond: None,
        update: None,
        ..
    } = stmt
    else {
        return inner;
    };
    let CStmt::For { body, .. } = stmt else {
        unreachable!("matched above")
    };
    if !last_test(body).is_some_and(|arms| arms.iter().any(|arm| markers_of(arm, deleted) > 0)) {
        return inner;
    }
    let kept = stmt.clone();
    let CStmt::For { body, .. } = stmt else {
        unreachable!("matched above")
    };
    hoist_markers(body, deleted);
    // The markers move only for a loop that then rotates.
    match super::rotate::rotate(stmt, marks) {
        0 => {
            *stmt = kept;
            inner
        }
        rotated => inner + rotated,
    }
}

/// Move the deleted copies' markers out of the arms of the body's last `if`, before it.
fn hoist_markers(body: &mut CStmt, deleted: &[RenderObservationId]) -> bool {
    let CStmt::Block(stmts) = body else {
        return false;
    };
    let Some(at) = stmts.iter().rposition(|stmt| !matches!(stmt, CStmt::Empty)) else {
        return false;
    };
    if matches!(stmts[at], CStmt::Block(_)) {
        return hoist_markers(&mut stmts[at], deleted);
    }
    let CStmt::Observed { stmt, .. } = &mut stmts[at] else {
        return false;
    };
    let CStmt::If {
        then_body,
        else_body: Some(else_body),
        ..
    } = stmt.as_mut()
    else {
        return false;
    };
    let mut moved = Vec::new();
    for arm in [then_body, else_body] {
        if let Some(markers) = marker_only(arm, deleted) {
            moved.extend(markers);
        }
    }
    let hoisted = !moved.is_empty();
    stmts.splice(at..at, moved);
    hoisted
}

/// The arms of a body's last `if`, read only.
fn last_test(body: &CStmt) -> Option<[&CStmt; 2]> {
    let CStmt::Block(stmts) = body else {
        return None;
    };
    let last = stmts.iter().rfind(|stmt| !matches!(stmt, CStmt::Empty))?;
    if matches!(last, CStmt::Block(_)) {
        return last_test(last);
    }
    let CStmt::Observed { stmt, .. } = last else {
        return None;
    };
    match stmt.as_ref() {
        CStmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => Some([then_body, else_body]),
        _ => None,
    }
}

/// How many deleted copies' markers lead an arm that holds nothing else but a `break` or a
/// `continue`; 0 for any other arm.
fn markers_of(arm: &CStmt, deleted: &[RenderObservationId]) -> usize {
    let marker = |stmt: &CStmt| {
        let ids = stmt.observation_ids();
        matches!(stmt.unobserved(), CStmt::Empty)
            && !ids.is_empty()
            && ids.iter().all(|id| deleted.binary_search(id).is_ok())
    };
    let live = super::rotate::live(arm);
    let markers = live.iter().take_while(|stmt| marker(stmt)).count();
    match live[markers..] {
        [] | [CStmt::Break] | [CStmt::Continue] => markers,
        _ => 0,
    }
}

/// An arm [`markers_of`] counts: the markers, taken out of it. Any other arm is left as it is.
fn marker_only(arm: &mut CStmt, deleted: &[RenderObservationId]) -> Option<Vec<CStmt>> {
    let markers = markers_of(arm, deleted);
    if markers == 0 {
        return None;
    }
    let mut flat = Vec::new();
    super::rotate::flatten(std::mem::replace(arm, CStmt::Empty), &mut flat);
    let rest = flat.split_off(markers);
    *arm = CStmt::Block(rest);
    Some(flat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CType, test_render_observation_id};
    use crate::structure::support::Fixture;
    use crate::symbol::{ExternalKind, SymbolRole, SymbolTable};

    /// Symbols `p`, `q`, `r`, `t` of one type; each a member of class 0 in that order.
    fn table() -> (SymbolTable, [SymbolId; 4]) {
        let mut table = SymbolTable::new();
        let ty = CType::Int {
            bits: 64,
            signedness: r2types::Signedness::Unsigned,
        };
        let mut declare = |name: &str| table.declare(name, ty.clone(), SymbolRole::Carrier);
        let symbols = [declare("p"), declare("q"), declare("r"), declare("t")];
        (table, symbols)
    }

    fn members(symbols: &[SymbolId]) -> Vec<Member> {
        (symbols.iter().enumerate())
            .map(|(value, symbol)| Member {
                class: 0,
                value: value as u32,
                symbol: *symbol,
            })
            .collect()
    }

    fn renamed(body: &mut CStmt, table: &SymbolTable, symbols: &[SymbolId]) -> Renamed {
        rename(body, &members(symbols), table.len(), &|_, _| true)
    }

    fn set(x: SymbolId, value: CExpr) -> CStmt {
        CStmt::Expr(CExpr::assign(CExpr::var(x), value))
    }

    fn copy(x: SymbolId, y: SymbolId) -> CStmt {
        set(x, CExpr::var(y))
    }

    fn call(name: &str, args: Vec<CExpr>) -> CExpr {
        let func = CExpr::External {
            name: name.to_owned(),
            kind: ExternalKind::Function,
        };
        CExpr::call(func, args)
    }

    fn read(x: SymbolId) -> CStmt {
        CStmt::Expr(call("use", vec![CExpr::var(x)]))
    }

    fn plus(x: SymbolId, n: i64) -> CExpr {
        CExpr::binary(BinaryOp::Add, CExpr::var(x), CExpr::int(n))
    }

    fn marked(id: u32, stmt: CStmt) -> CStmt {
        CStmt::observe_one(test_render_observation_id(id), stmt)
    }

    fn cond() -> CExpr {
        call("c", Vec::new())
    }

    #[test]
    fn a_gapped_merge_s_residual_copy_is_renamed_and_kept() {
        // Round 2's witness: the J -> K copy is `q = <residual>;`, which renaming leaves `p = ...`.
        let (table, [p, q, ..]) = table();
        let residual = || call("r2sleigh_residual_u64", vec![CExpr::int(1)]);
        let mut body = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            CStmt::if_stmt(cond(), set(q, residual()), Some(marked(7, copy(q, p)))),
            read(q),
        ]);
        let done = renamed(&mut body, &table, &[p, q]);
        assert_eq!(done.joined, 1);
        let expected = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            CStmt::if_stmt(cond(), set(p, residual()), Some(marked(7, CStmt::Empty))),
            read(p),
        ]);
        assert_eq!(body, expected);
        assert_eq!(done.deleted, [test_render_observation_id(7)]);
    }

    #[test]
    fn a_read_forwarded_past_a_redefinition_keeps_its_symbol() {
        // `r = p + 1` while `p` is still read after it: one location would hold two values.
        let (table, [p, _, r, _]) = table();
        let mut body = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            set(r, plus(p, 1)),
            read(p),
            read(r),
        ]);
        let before = body.clone();
        let done = renamed(&mut body, &table, &[p, r]);
        assert_eq!(
            (done.joined, done.kept.get(&Kept::Interferes)),
            (0, Some(&1))
        );
        assert_eq!(body, before);
    }

    #[test]
    fn a_latch_copy_whose_source_is_read_after_it_is_no_self_copy() {
        // Round 1's latch witness: `r = p;` then `p = r + 1;` with `r` read after: `r` stays.
        let (table, [p, _, r, _]) = table();
        let mut body = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            CStmt::while_loop(
                cond(),
                CStmt::Block(vec![copy(r, p), set(p, plus(r, 1)), read(r)]),
            ),
            read(p),
        ]);
        let before = body.clone();
        let done = renamed(&mut body, &table, &[p, r]);
        assert_eq!(done.joined, 0);
        assert_eq!(body, before);
    }

    #[test]
    fn a_swap_keeps_both_symbols() {
        let (table, [p, q, _, t]) = table();
        let mut body = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            set(q, CExpr::int(2)),
            copy(t, p),
            copy(p, q),
            copy(q, t),
            read(p),
            read(q),
        ]);
        let done = renamed(&mut body, &table, &[p, q, t]);
        assert_eq!(done.joined, 0, "{body:?}");
    }

    #[test]
    fn a_goto_into_a_loop_carries_liveness_to_the_label() {
        // `p = 3; goto L;` reaches `L: use(q)` inside the loop: `q` is live after `p = 3`.
        let (table, [p, q, ..]) = table();
        let mut body = CStmt::Block(vec![
            set(q, CExpr::int(1)),
            CStmt::while_loop(
                cond(),
                CStmt::Block(vec![CStmt::Label("L".to_owned()), read(q)]),
            ),
            set(p, CExpr::int(3)),
            CStmt::Goto("L".to_owned()),
        ]);
        let done = renamed(&mut body, &table, &[p, q]);
        assert_eq!(
            (done.joined, done.kept.get(&Kept::Interferes)),
            (0, Some(&1))
        );
        // A label nothing defines is no statement graph the reader models.
        let mut body = CStmt::Block(vec![set(p, CExpr::int(1)), CStmt::Goto("M".to_owned())]);
        let done = renamed(&mut body, &table, &[p, q]);
        assert_eq!(done.kept.get(&Kept::Unmodelled), Some(&2));
    }

    #[test]
    fn a_member_whose_address_is_taken_keeps_its_symbol() {
        let (table, [p, q, ..]) = table();
        let mut body = CStmt::Block(vec![
            set(p, CExpr::int(1)),
            CStmt::Expr(call("f", vec![CExpr::addr_of(CExpr::var(q))])),
            copy(q, p),
            read(q),
        ]);
        let done = renamed(&mut body, &table, &[p, q]);
        assert_eq!(
            (done.joined, done.kept.get(&Kept::Occurrence)),
            (0, Some(&1))
        );
    }

    #[test]
    fn a_carrier_copied_back_on_the_latch_is_one_symbol_and_the_loop_rotates() {
        // fnv1a64's shape: `for (;;) { q = p + 1; if (c) { p = q; } else { r = q; break; } } use(r)`.
        let (table, [p, q, r, _]) = table();
        let test = marked(
            0x10,
            CStmt::if_stmt(
                cond(),
                CStmt::Block(vec![marked(0x20, copy(p, q))]),
                Some(CStmt::Block(vec![marked(0x21, copy(r, q)), CStmt::Break])),
            ),
        );
        let looped = CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(CStmt::Block(vec![set(q, plus(p, 1)), test])),
        };
        let mut body = CStmt::Block(vec![set(p, CExpr::int(0)), looped, read(r)]);
        let done = renamed(&mut body, &table, &[p, q, r]);
        assert_eq!(done.joined, 2, "{body:?}");
        assert_eq!(rotate_emptied(&mut body, &done.deleted, &mut Fixture), 1);
        let CStmt::Block(stmts) = &body else {
            panic!("a block");
        };
        let CStmt::DoWhile { body: inner, .. } = stmts[1].unobserved() else {
            panic!("a do-while: {body:?}");
        };
        let CStmt::Block(inner) = inner.as_ref() else {
            panic!("a block");
        };
        assert_eq!(inner[0], set(p, plus(p, 1)));
        assert_eq!(
            inner.len(),
            3,
            "the update and the two kept markers: {inner:?}"
        );
        assert_eq!(stmts[2], read(p));
    }
}
