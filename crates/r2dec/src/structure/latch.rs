//! Latch copies written before the latch's test, so a rotated loop is a `do-while`
//! (`doc/adr-structure-dominator-tree.md` §5, 2026-10-22).

use std::collections::{BTreeMap, BTreeSet};

use super::certify::Placed;
use super::rotate::{continues, flatten, is_break, live, parts};
use crate::ast::{BinaryOp, CExpr, CStmt};
use crate::symbol::SymbolId;

/// Write the copies of each latch before its test where the C text allows; the number of loops.
/// O(statements): the reads are counted in one pass, a loop's from the counts at its entry and exit.
pub(crate) fn hoist(root: &mut CStmt, placed: &dyn Placed) -> usize {
    let mut scan = Scan::new(placed);
    scan.stmt(root);
    let verdicts = scan.verdicts();
    if !verdicts.iter().any(Option::is_some) {
        return 0;
    }
    let mut verdicts = verdicts.into_iter();
    let written = walk(root, &mut verdicts);
    debug_assert!(
        verdicts.next().is_none(),
        "the walk met each loop the scan did"
    );
    written
}

/// The reads of the function and, for each `for (;;)` in pre-order, the latch it has and how often
/// each of the latch's copies is read inside the loop.
struct Scan<'p> {
    placed: &'p dyn Placed,
    /// Reads of each variable so far.
    reads: BTreeMap<SymbolId, usize>,
    loops: Vec<Option<Latch>>,
}

/// The latch of a loop: whether the arm that stays is the test's true arm, and each variable that
/// arm copies with its reads before the loop, then inside it.
struct Latch {
    stay_is_true: bool,
    copies: Vec<(SymbolId, usize)>,
}

impl<'p> Scan<'p> {
    fn new(placed: &'p dyn Placed) -> Self {
        Self {
            placed,
            reads: BTreeMap::new(),
            loops: Vec::new(),
        }
    }

    fn stmt(&mut self, stmt: &CStmt) {
        match stmt {
            CStmt::Observed { stmt, .. } => self.stmt(stmt),
            CStmt::Block(stmts) => stmts.iter().for_each(|stmt| self.stmt(stmt)),
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.read(cond);
                self.stmt(then_body);
                if let Some(else_body) = else_body {
                    self.stmt(else_body);
                }
            }
            CStmt::While { cond, body } | CStmt::DoWhile { body, cond } => {
                self.read(cond);
                self.stmt(body);
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                self.read(expr);
                for case in cases {
                    self.read(&case.value);
                    case.body.iter().for_each(|stmt| self.stmt(stmt));
                }
                default.iter().flatten().for_each(|stmt| self.stmt(stmt));
            }
            CStmt::For {
                init: None,
                cond: None,
                update: None,
                body,
            } => self.forever(body),
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                // A statement in the header holds no loop for `walk` to find.
                if let Some(init) = init {
                    init.visit_exprs(&mut |root| self.read(root));
                }
                cond.iter().chain(update).for_each(|expr| self.read(expr));
                self.stmt(body);
            }
            other => other.visit_exprs(&mut |root| self.read(root)),
        }
    }

    fn forever(&mut self, body: &CStmt) {
        let at = self.loops.len();
        let latch = latch_of(body, self.placed);
        self.loops.push(latch.map(|(stay_is_true, targets)| {
            Latch {
                stay_is_true,
                copies: (targets.into_iter())
                    .map(|target| (target, self.count(target)))
                    .collect(),
            }
        }));
        self.stmt(body);
        let reads = &self.reads;
        if let Some(latch) = &mut self.loops[at] {
            for (target, before) in &mut latch.copies {
                *before = reads.get(target).copied().unwrap_or(0) - *before;
            }
        }
    }

    fn read(&mut self, expr: &CExpr) {
        let reads = &mut self.reads;
        reads_of(expr, &mut |symbol| *reads.entry(symbol).or_default() += 1);
    }

    fn count(&self, symbol: SymbolId) -> usize {
        self.reads.get(&symbol).copied().unwrap_or(0)
    }

    /// For each loop, `Some(stay_is_true)` when its copies may be written before its test: nothing
    /// outside the loop reads them, so every read of each is inside.
    fn verdicts(&self) -> Vec<Option<bool>> {
        (self.loops.iter())
            .map(|latch| {
                let latch = latch.as_ref()?;
                let beyond = |(target, inside): &(SymbolId, usize)| self.count(*target) != *inside;
                (!latch.copies.iter().any(beyond)).then_some(latch.stay_is_true)
            })
            .collect()
    }
}

/// Write the loops `verdicts` allow, taken in the order `Scan::stmt` met them.
fn walk(stmt: &mut CStmt, verdicts: &mut impl Iterator<Item = Option<bool>>) -> usize {
    match stmt {
        CStmt::Observed { stmt, .. } => walk(stmt, verdicts),
        CStmt::Block(stmts) => stmts.iter_mut().map(|stmt| walk(stmt, verdicts)).sum(),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => walk(then_body, verdicts) + else_body.as_deref_mut().map_or(0, |e| walk(e, verdicts)),
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => walk(body, verdicts),
        CStmt::Switch { cases, default, .. } => {
            let in_cases: usize = (cases.iter_mut())
                .flat_map(|case| case.body.iter_mut())
                .map(|stmt| walk(stmt, verdicts))
                .sum();
            in_cases
                + default
                    .iter_mut()
                    .flatten()
                    .map(|stmt| walk(stmt, verdicts))
                    .sum::<usize>()
        }
        CStmt::For {
            init: None,
            cond: None,
            update: None,
            body,
        } => {
            let verdict = verdicts.next().expect("the scan met this loop");
            let inner = walk(body, verdicts);
            let Some(stay_is_true) = verdict else {
                return inner;
            };
            let taken = std::mem::replace(&mut **body, CStmt::Empty);
            **body = moved(taken, stay_is_true);
            inner + 1
        }
        CStmt::For { body, .. } => walk(body, verdicts),
        _ => 0,
    }
}

/// Whether a loop's body ends in a latch whose copies could be written before its test, and if so
/// whether the arm that stays is the test's true arm, and the variables it copies.
fn latch_of(body: &CStmt, placed: &dyn Placed) -> Option<(bool, Vec<SymbolId>)> {
    let stmts = live(body);
    let (last, before) = stmts.split_last()?;
    let (test, on_true, on_false) = parts(last)?;
    // The loop leaves on one arm and goes back on the other, which does nothing but copy.
    let (stay, stay_is_true) = match (is_break(on_true), is_break(on_false)) {
        (false, true) => (on_true, true),
        (true, false) => (on_false, false),
        _ => return None,
    };
    // Nothing else goes back to the top, or the loop is not a `do-while` once the copies are out.
    if before.is_empty() || before.iter().any(|stmt| continues(stmt)) || !pure(test) {
        return None;
    }
    let targets: BTreeSet<SymbolId> = copies_of(stay, placed)?.into_iter().collect();
    // The test reads none of what is written.
    let mut read_by_test = false;
    reads_of(test, &mut |symbol| {
        read_by_test |= targets.contains(&symbol)
    });
    (!read_by_test).then(|| (stay_is_true, targets.into_iter().collect()))
}

/// The variables an arm assigns, when it is the copies its edge carries (assignments to variables
/// under markers that say so) and nothing else but a closing `continue`.
fn copies_of(arm: &CStmt, placed: &dyn Placed) -> Option<Vec<SymbolId>> {
    let mut statements = live(arm);
    if matches!(statements.last(), Some(CStmt::Continue)) {
        statements.pop();
    }
    let copy_target = |stmt: &CStmt| {
        let ids = stmt.observation_ids();
        if ids.is_empty() || !ids.iter().all(|id| placed.edge_copy(*id)) {
            return None;
        }
        match stmt.unobserved() {
            CStmt::Expr(CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                ..
            }) => match &**left {
                CExpr::Var(target) => Some(*target),
                _ => None,
            },
            _ => None,
        }
    };
    let targets: Option<Vec<SymbolId>> = statements.into_iter().map(copy_target).collect();
    targets.filter(|targets| !targets.is_empty())
}

/// The body with the stay arm's statements ahead of the test and the arm itself empty.
fn moved(body: CStmt, stay_is_true: bool) -> CStmt {
    let mut stmts = Vec::new();
    flatten(body, &mut stmts);
    let Some(CStmt::Observed { ids, stmt }) = stmts.pop() else {
        unreachable!("the test was found last");
    };
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = *stmt
    else {
        unreachable!("the test was an if with both arms");
    };
    let (stay, leave) = match stay_is_true {
        true => (*then_body, *else_body),
        false => (*else_body, *then_body),
    };
    let mut copies = Vec::new();
    flatten(stay, &mut copies);
    copies.retain(|stmt| !matches!(stmt, CStmt::Continue));
    stmts.extend(copies);
    let (on_true, on_false) = match stay_is_true {
        true => (CStmt::Empty, leave),
        false => (leave, CStmt::Empty),
    };
    stmts.push(CStmt::observe_all(
        ids.iter(),
        CStmt::if_stmt(cond, on_true, Some(on_false)),
    ));
    CStmt::Block(stmts)
}

/// Whether evaluating a test only reads: no call, no assignment, no increment.
fn pure(expr: &CExpr) -> bool {
    let mut calls = false;
    let mut pending = vec![expr];
    while let Some(node) = pending.pop() {
        calls |= matches!(node.unobserved(), CExpr::Call { .. });
        pending.extend(node.children());
    }
    !calls && !super::certify::writes(expr)
}

/// Each read of a variable in `expr`: a plain assignment's target is written, not read.
fn reads_of(expr: &CExpr, read: &mut impl FnMut(SymbolId)) {
    #[cfg(test)]
    COUNTED.with(|counted| counted.set(counted.get() + 1));
    match expr.unobserved() {
        CExpr::Var(symbol) => read(*symbol),
        CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        } if matches!(left.unobserved(), CExpr::Var(_)) => reads_of(right, read),
        other => {
            for child in other.children() {
                reads_of(child, read);
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The expressions read for the variables they name, in this thread.
    static COUNTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{RenderObservationId, SwitchCase, UnaryOp, test_render_observation_id};
    use crate::symbol::SymbolTable;

    struct Fixture {
        symbols: SymbolTable,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                symbols: SymbolTable::new(),
            }
        }

        fn var(&mut self, name: &str) -> CExpr {
            CExpr::var(self.symbols.declare_or_reuse(name))
        }
    }

    fn marker(block: u32, stmt: CStmt) -> CStmt {
        CStmt::observe_one(test_render_observation_id(block), stmt)
    }

    /// Markers from this one on are copies an edge carries.
    const COPY: u32 = 0x1000;

    struct Edges;

    impl Placed for Edges {
        fn block_of(&self, id: RenderObservationId) -> Option<u64> {
            Some(u64::from(id.index() % COPY))
        }

        fn statement_of(&self, id: RenderObservationId) -> Option<RenderObservationId> {
            Some(id)
        }

        fn written(&self) -> usize {
            0
        }

        fn edge_copy(&self, id: RenderObservationId) -> bool {
            id.index() >= COPY
        }
    }

    fn write(target: &CExpr, value: CExpr) -> CStmt {
        CStmt::Expr(CExpr::assign(target.clone(), value))
    }

    /// An assignment the latch's edge carries.
    fn assign(target: &CExpr, value: CExpr) -> CStmt {
        marker(COPY, write(target, value))
    }

    fn latch(test: CExpr, stay: Vec<CStmt>) -> CStmt {
        marker(
            0x30,
            CStmt::if_stmt(
                test,
                CStmt::Block(stay),
                Some(CStmt::Block(vec![CStmt::Break])),
            ),
        )
    }

    fn forever(stmts: Vec<CStmt>) -> CStmt {
        CStmt::Block(vec![CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(CStmt::Block(stmts)),
        }])
    }

    fn work(block: u32) -> CStmt {
        marker(block, CStmt::Expr(CExpr::int(i64::from(block))))
    }

    /// The loop of `forever`, after `hoist`: its body's statements.
    fn body_after(root: CStmt) -> (Vec<CStmt>, usize) {
        body_after_at(root, 0)
    }

    /// The same, for the loop that is statement `at` of the outer block.
    fn body_after_at(mut root: CStmt, at: usize) -> (Vec<CStmt>, usize) {
        let count = hoist(&mut root, &Edges);
        let CStmt::Block(outer) = root else {
            panic!("a block");
        };
        let CStmt::For { body, .. } = &outer[at] else {
            panic!("a for");
        };
        let CStmt::Block(stmts) = &**body else {
            panic!("a block body");
        };
        (stmts.clone(), count)
    }

    /// `depth` loops inside one another, each with a copy that nothing outside it reads.
    fn nested(f: &mut Fixture, depth: usize) -> CStmt {
        let (a, n) = (f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let mut inner = None;
        for level in (0..depth).rev() {
            let x = f.var(&format!("x{level}"));
            let mut body = vec![work(0x20)];
            body.extend(inner.take());
            body.push(latch(
                test.clone(),
                vec![assign(&x, a.clone()), CStmt::Continue],
            ));
            inner = Some(CStmt::For {
                init: None,
                cond: None,
                update: None,
                body: Box::new(CStmt::Block(body)),
            });
        }
        CStmt::Block(inner.into_iter().collect())
    }

    /// The loops written and the expressions read for `hoist` of `depth` nested loops.
    fn read_for(depth: usize) -> (usize, usize) {
        let mut root = nested(&mut Fixture::new(), depth);
        let before = COUNTED.with(std::cell::Cell::get);
        let written = hoist(&mut root, &Edges);
        (written, COUNTED.with(std::cell::Cell::get) - before)
    }

    #[test]
    fn nested_loops_are_read_once_however_deep_they_go() {
        // Doubling the depth at most doubles the expressions read; reading each loop's whole body,
        // inner loops included, would quadruple them.
        let (few, many) = (read_for(50), read_for(100));
        assert_eq!(
            (few.0, many.0),
            (50, 100),
            "every level writes its copy first"
        );
        assert!(
            many.1 <= 2 * few.1,
            "{} read for 50 loops, {} for 100",
            few.1,
            many.1
        );
    }

    fn looped(body: Vec<CStmt>) -> CStmt {
        CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(CStmt::Block(body)),
        }
    }

    /// The statements of the body of a `for`.
    fn body_of(stmt: &CStmt) -> &[CStmt] {
        let CStmt::For { body, .. } = stmt else {
            panic!("a for: {stmt:?}");
        };
        let CStmt::Block(stmts) = &**body else {
            panic!("a block body");
        };
        stmts
    }

    /// Whether the latch ending `body` still copies on its staying arm.
    fn copies_on_arm(body: &[CStmt]) -> bool {
        let Some(CStmt::Observed { stmt, .. }) = body.last() else {
            panic!("a marked latch");
        };
        let CStmt::If { then_body, .. } = &**stmt else {
            panic!("an if");
        };
        !matches!(&**then_body, CStmt::Empty)
    }

    #[test]
    fn a_copy_read_in_the_enclosing_loop_outside_the_inner_one_stays_on_its_arm() {
        let mut f = Fixture::new();
        let (x, y, a, n) = (f.var("x"), f.var("y"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let inner = || {
            looped(vec![
                work(0x20),
                latch(test.clone(), vec![assign(&x, a.clone()), CStmt::Continue]),
            ])
        };
        let outer_latch = || latch(test.clone(), vec![assign(&y, a.clone()), CStmt::Continue]);
        let read_x = || CStmt::Expr(x.clone());
        // Read after the inner loop, and before it: only the outer loop's copy is written first.
        for body in [
            vec![inner(), read_x(), outer_latch()],
            vec![read_x(), inner(), outer_latch()],
        ] {
            let mut root = CStmt::Block(vec![looped(body)]);
            assert_eq!(hoist(&mut root, &Edges), 1);
            let CStmt::Block(top) = &root else {
                panic!("a block");
            };
            let outer = body_of(&top[0]);
            let inner = outer.iter().find(|stmt| matches!(stmt, CStmt::For { .. }));
            assert!(copies_on_arm(body_of(inner.expect("the inner loop"))));
            assert!(!copies_on_arm(outer), "{outer:?}");
        }
        // Read nowhere else: both write their copies first.
        let mut root = CStmt::Block(vec![looped(vec![inner(), outer_latch()])]);
        assert_eq!(hoist(&mut root, &Edges), 2);
    }

    #[test]
    fn the_scan_counts_every_read_the_whole_tree_holds() {
        // Each container reads a variable of its own in its header, so one the scan skips shows.
        let mut f = Fixture::new();
        let names = [
            "i", "w", "d", "fi", "fc", "fu", "s", "c", "b", "r", "x", "o",
        ];
        let v: Vec<CExpr> = names.iter().map(|name| f.var(name)).collect();
        let stmt = |expr: &CExpr| Box::new(CStmt::Expr(expr.clone()));
        let tree = CStmt::Block(vec![
            CStmt::if_stmt(
                v[0].clone(),
                CStmt::Expr(v[10].clone()),
                Some(CStmt::Expr(v[11].clone())),
            ),
            CStmt::While {
                cond: v[1].clone(),
                body: stmt(&v[10]),
            },
            CStmt::DoWhile {
                body: stmt(&v[10]),
                cond: v[2].clone(),
            },
            CStmt::For {
                init: Some(stmt(&v[3])),
                cond: Some(v[4].clone()),
                update: Some(v[5].clone()),
                body: stmt(&v[10]),
            },
            CStmt::Switch {
                expr: v[6].clone(),
                cases: vec![SwitchCase {
                    value: v[7].clone(),
                    body: vec![CStmt::Expr(v[10].clone())],
                    test: None,
                }],
                default: Some(vec![CStmt::Return(Some(v[9].clone()))]),
            },
            CStmt::Expr(CExpr::assign(v[8].clone(), v[10].clone())),
        ]);
        let mut whole = BTreeMap::new();
        tree.visit_exprs(&mut |root| reads_of(root, &mut |s| *whole.entry(s).or_insert(0) += 1));
        let mut scan = Scan::new(&Edges);
        scan.stmt(&tree);
        assert_eq!(scan.reads, whole);
        assert_eq!(whole.len(), 11, "every name but the assigned one is read");
    }

    #[test]
    fn copies_a_test_does_not_read_are_written_before_it() {
        // for (;;) { work; if (a != n) { x = a; } else { break; } } with `x` read nowhere else.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let root = forever(vec![
            work(0x20),
            latch(test, vec![assign(&x, a), CStmt::Continue]),
        ]);
        let (stmts, count) = body_after(root);
        assert_eq!(count, 1);
        // work; x = a; if (...) {} else { break; }
        assert_eq!(stmts.len(), 3, "{stmts:?}");
        assert!(matches!(stmts[1].unobserved(), CStmt::Expr(_)));
        let CStmt::Observed { stmt, .. } = &stmts[2] else {
            panic!("the test stays marked");
        };
        let CStmt::If { then_body, .. } = &**stmt else {
            panic!("an if");
        };
        assert!(matches!(&**then_body, CStmt::Empty));
    }

    #[test]
    fn a_copy_that_carries_its_blocks_marker_moves_with_it() {
        // An edge's copy is a statement of its block: the marker the certificate counts goes with it.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let copy = assign(&x, a);
        let stay = vec![copy.clone(), CStmt::Continue];
        let (stmts, count) = body_after(forever(vec![work(0x20), latch(test, stay)]));
        assert_eq!(count, 1);
        assert_eq!(stmts[1], copy);
    }

    #[test]
    fn an_assignment_a_block_writes_is_no_copy_an_edge_carries() {
        // The arm is the text of another block that assigns; hoisted, that block would run before the test.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let own = marker(0x30, write(&x, a));
        let root = forever(vec![work(0x20), latch(test, vec![own, CStmt::Continue])]);
        assert_eq!(body_after(root).1, 0);
    }

    #[test]
    fn the_stay_arm_on_the_false_side_is_emptied_too() {
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let test = CExpr::binary(BinaryOp::Eq, a.clone(), CExpr::int(0));
        let latch = marker(
            0x30,
            CStmt::if_stmt(
                test,
                CStmt::Block(vec![CStmt::Break]),
                Some(CStmt::Block(vec![assign(&x, a)])),
            ),
        );
        let (stmts, count) = body_after(forever(vec![work(0x20), latch]));
        assert_eq!(count, 1);
        let CStmt::Observed { stmt, .. } = &stmts[2] else {
            panic!("marked");
        };
        let CStmt::If { else_body, .. } = &**stmt else {
            panic!("an if");
        };
        assert!(matches!(else_body.as_deref(), Some(CStmt::Empty)));
    }

    #[test]
    fn a_copy_the_test_reads_stays_on_the_arm() {
        // The test reads `x`, which the copy writes: after the move it would see the new value.
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let test = CExpr::binary(BinaryOp::Ne, x.clone(), CExpr::int(0));
        let root = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])]);
        let (_, count) = body_after(root);
        assert_eq!(count, 0);
    }

    #[test]
    fn a_copy_something_after_the_loop_reads_stays_on_the_arm() {
        // `x` is read after the loop; the exit would see the copy it never made.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let mut root = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])]);
        let CStmt::Block(outer) = &mut root else {
            panic!("a block");
        };
        outer.push(CStmt::Return(Some(x)));
        let (_, count) = body_after(root);
        assert_eq!(count, 0);
    }

    #[test]
    fn a_write_before_the_loop_is_no_read_after_it() {
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let CStmt::Block(mut outer) = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])])
        else {
            panic!("a block");
        };
        outer.insert(0, write(&x, CExpr::int(0)));
        outer.push(CStmt::Return(Some(CExpr::int(1))));
        let (_, count) = body_after_at(CStmt::Block(outer), 1);
        assert_eq!(count, 1);
    }

    #[test]
    fn a_test_that_calls_or_writes_keeps_its_copies_where_they_are() {
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let call = CExpr::call(
            CExpr::var(f.symbols.declare_or_reuse("probe")),
            vec![a.clone()],
        );
        let root = forever(vec![work(0x20), latch(call, vec![assign(&x, a.clone())])]);
        assert_eq!(body_after(root).1, 0);
        let bump = CExpr::unary(UnaryOp::PostInc, a.clone());
        let root = forever(vec![work(0x20), latch(bump, vec![assign(&x, a)])]);
        assert_eq!(body_after(root).1, 0);
    }

    #[test]
    fn a_latch_that_does_more_than_copy_or_a_continue_before_it_is_left_alone() {
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        // The arm also stores through a pointer.
        let store = CStmt::Expr(CExpr::assign(
            CExpr::Deref(Box::new(a.clone())),
            CExpr::int(1),
        ));
        let root = forever(vec![
            work(0x20),
            latch(test.clone(), vec![assign(&x, a.clone()), store]),
        ]);
        assert_eq!(body_after(root).1, 0);
        // A `continue` before the latch reaches the top, which the copies would skip.
        let early = CStmt::If {
            cond: CExpr::int(1),
            then_body: Box::new(CStmt::Continue),
            else_body: None,
        };
        let root = forever(vec![work(0x20), early, latch(test, vec![assign(&x, a)])]);
        assert_eq!(body_after(root).1, 0);
    }
}
