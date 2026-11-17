//! D474: an `if` chain testing one value against distinct proven constants is the `switch` it
//! tests (doc/adr-structure-dominator-tree.md, "Chained switch").

use crate::ast::{BinaryOp, CExpr, CStmt, CType, RenderObservationId, SwitchCase};

/// What one test block's branch states (r2types `BranchPredicateFact`): the value it compares for
/// equality and the constant the artifact proves the other operand is.
pub(crate) type Tested<'a> = dyn Fn(u64) -> Option<(r2ssa::ValueId, u64)> + 'a;

/// One `if` of a chain, read against its block's fact.
struct Link<'a> {
    /// The `if` statement's markers, which name its test block.
    ids: Vec<RenderObservationId>,
    cond: &'a CExpr,
    value: r2ssa::ValueId,
    /// The compared operand as written, markers stripped.
    scrutinee: CExpr,
    /// The literal under its cast, and its bits at the comparison's width.
    literal: CExpr,
    bits: u64,
    /// The arm taken when the two are equal, and the other one.
    equal: Option<&'a CStmt>,
    other: Option<&'a CStmt>,
}

/// Rewrite every chain of three or more tests in `stmt`; the number rewritten. O(statements): a
/// chain too short at its head is too short at its later tests, which `skip` reading again.
pub(crate) fn switch(
    stmt: &mut CStmt,
    tested: &Tested<'_>,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
    skip: usize,
) -> usize {
    let (mut rewritten, mut later) = (0, skip.saturating_sub(1));
    if skip == 0 {
        match chain(stmt, tested, block_of) {
            Ok(chained) => {
                *stmt = chained;
                rewritten = 1;
            }
            Err(links) if links < 3 => later = links.saturating_sub(1),
            Err(_) => {}
        }
    }
    let continues = continuation(stmt);
    each_child(stmt, &mut |child, index| {
        let skip = if Some(index) == continues { later } else { 0 };
        rewritten += switch(child, tested, block_of, skip)
    });
    rewritten
}

/// Which child of an `if` the chain continues through: the arm taken when the test is false.
fn continuation(stmt: &CStmt) -> Option<usize> {
    let CStmt::If { cond, .. } = stmt.unobserved() else {
        return None;
    };
    let compared = match cond.unobserved() {
        CExpr::Cast { expr, .. } => expr.unobserved(),
        other => other,
    };
    match compared {
        CExpr::Binary {
            op: BinaryOp::Ne, ..
        } => Some(0),
        _ => Some(1),
    }
}

/// The statements nested directly inside `stmt`, each with its index; a one-statement unmarked
/// block hands its statement the block's own index, as a chain reads through it.
fn each_child(stmt: &mut CStmt, f: &mut dyn FnMut(&mut CStmt, usize)) {
    match stmt {
        CStmt::Observed { stmt, .. } => each_child(stmt, f),
        CStmt::Block(stmts) => stmts.iter_mut().for_each(|stmt| f(stmt, 0)),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            through(then_body, 0, f);
            if let Some(body) = else_body {
                through(body, 1, f);
            }
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } | CStmt::For { body, .. } => {
            f(body, 0)
        }
        CStmt::Switch { cases, default, .. } => {
            (cases.iter_mut()).for_each(|case| case.body.iter_mut().for_each(|stmt| f(stmt, 0)));
            default.iter_mut().flatten().for_each(|stmt| f(stmt, 0));
        }
        _ => {}
    }
}

/// `f` on an arm, through the unmarked one-statement blocks `only` reads through.
fn through(stmt: &mut CStmt, index: usize, f: &mut dyn FnMut(&mut CStmt, usize)) {
    match stmt {
        CStmt::Block(stmts) if stmts.len() == 1 => through(&mut stmts[0], index, f),
        other => f(other, index),
    }
}

/// The switch `stmt` heads, where all five conditions hold; else how many tests the chain read.
fn chain(
    stmt: &CStmt,
    tested: &Tested<'_>,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> Result<CStmt, usize> {
    let mut links = vec![link(stmt, tested, block_of).ok_or(0usize)?];
    let default = loop {
        let last = links.last().expect("a chain has a head");
        let next = last.other.map(only);
        match next.and_then(|next| link(next, tested, block_of)) {
            Some(next) if next.value == last.value && next.scrutinee == last.scrutinee => {
                links.push(next)
            }
            _ => break last.other,
        }
    };
    let mut seen = std::collections::BTreeSet::new();
    let distinct = links.iter().all(|link| seen.insert(link.bits));
    let arms = (links.iter().filter_map(|link| link.equal)).chain(default);
    let unbound = arms.clone().all(|arm| !breaks_out(arm));
    if links.len() < 3 {
        return Err(links.len());
    }
    if !distinct || !unbound {
        return Err(usize::MAX);
    }
    let expr = links[0].scrutinee.clone();
    let cases = (links.into_iter())
        .map(|link| {
            let mut body = link.equal.cloned().map(statements).unwrap_or_default();
            if !ends_in_jump(&body) {
                body.push(CStmt::Break);
            }
            SwitchCase {
                value: link.literal,
                body,
                test: Some(CExpr::observe_all(link.ids, link.cond.clone())),
            }
        })
        .collect();
    Ok(CStmt::Switch {
        expr,
        cases,
        default: (default.cloned().map(statements)).filter(|body| !body.iter().all(empty)),
    })
}

/// One `if` read as an equality of a variable against a proven constant, or `None`.
fn link<'a>(
    stmt: &'a CStmt,
    tested: &Tested<'_>,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> Option<Link<'a>> {
    let CStmt::If {
        cond,
        then_body,
        else_body,
    } = stmt.unobserved()
    else {
        return None;
    };
    // A test written as a chain of atoms is a condition, not one comparison.
    if !cond.observation_ids().is_empty() {
        return None;
    }
    let compared = match cond.unobserved() {
        CExpr::Cast { expr, .. } => expr.unobserved(),
        other => other,
    };
    let CExpr::Binary { op, left, right } = compared else {
        return None;
    };
    let (equal, other) = match op {
        BinaryOp::Eq => (Some(&**then_body), else_body.as_deref()),
        BinaryOp::Ne => (else_body.as_deref(), Some(&**then_body)),
        _ => return None,
    };
    let (literal, bits, width) = case_literal(left, right)?;
    let mask = |v: u64| v & (u64::MAX >> (64 - width));
    let ids = stmt.observation_ids().into_owned();
    let mut blocks = ids.iter().filter_map(|id| block_of(*id));
    let block = blocks.next()?;
    if blocks.any(|other| other != block) {
        return None;
    }
    let (value, constant) = tested(block)?;
    (mask(bits) == mask(constant)).then(|| Link {
        ids,
        cond,
        value,
        scrutinee: left.clone_without_render_observations(),
        literal,
        bits,
        equal,
        other,
    })
}

/// An integer cast: its type, width and signedness, and what it converts.
fn integer(expr: &CExpr) -> Option<(CType, u32, r2types::Signedness, &CExpr)> {
    match expr.unobserved() {
        CExpr::Cast {
            ty: ty @ CType::Int { bits, signedness },
            expr,
            ..
        } if (1..=64).contains(bits) => Some((ty.clone(), *bits, *signedness, expr.unobserved())),
        _ => None,
    }
}

/// `(T)x == (T)k` read as a case: the literal `k`, its bits at T's width, and the width, where `x`
/// is a variable and T an integer type `k` fits when narrower than `int`, since `switch` promotes.
pub(crate) fn case_literal(left: &CExpr, right: &CExpr) -> Option<(CExpr, u64, u32)> {
    let (ty, width, signedness, scrutinee) = integer(left)?;
    let (written, _, _, inner) = integer(right)?;
    let value = match inner {
        CExpr::IntLit(v) => i128::from(*v),
        CExpr::UIntLit(v) => i128::from(*v),
        _ => return None,
    };
    let (low, high) = match signedness {
        r2types::Signedness::Signed => (-(1i128 << (width - 1)), 1i128 << (width - 1)),
        _ => (0, 1i128 << width),
    };
    let fits = width >= 32 || (low..high).contains(&value);
    let bits = (value as u64) & (u64::MAX >> (64 - width));
    (written == ty && matches!(scrutinee, CExpr::Var(_)) && fits)
        .then(|| (inner.clone(), bits, width))
}

/// The one statement a body of one unmarked block holds, or the body itself.
fn only(stmt: &CStmt) -> &CStmt {
    match stmt {
        CStmt::Block(stmts) if stmts.len() == 1 => only(&stmts[0]),
        other => other,
    }
}

/// An arm as a case's statements: an unmarked block is its statements.
fn statements(stmt: CStmt) -> Vec<CStmt> {
    match stmt {
        CStmt::Block(stmts) => stmts,
        other => vec![other],
    }
}

/// Whether `stmt` is unmarked and writes nothing, so a `default` of it says nothing.
fn empty(stmt: &CStmt) -> bool {
    match stmt {
        CStmt::Empty => true,
        CStmt::Block(stmts) => stmts.iter().all(empty),
        _ => false,
    }
}

/// Whether control cannot fall off the end of `stmts`.
fn ends_in_jump(stmts: &[CStmt]) -> bool {
    stmts.last().is_some_and(jumps)
}

fn jumps(stmt: &CStmt) -> bool {
    match stmt.unobserved() {
        CStmt::Return(_) | CStmt::Goto(_) | CStmt::Continue | CStmt::Break => true,
        CStmt::Block(inner) => ends_in_jump(inner),
        CStmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => jumps(then_body) && jumps(else_body),
        _ => false,
    }
}

/// Whether `stmt` holds a `break` that binds outside it: inside the new switch it would bind there.
fn breaks_out(stmt: &CStmt) -> bool {
    match stmt.unobserved() {
        CStmt::Break => true,
        CStmt::Block(stmts) => stmts.iter().any(breaks_out),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => breaks_out(then_body) || else_body.as_deref().is_some_and(breaks_out),
        // A loop or switch binds every `break` inside it.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::case_literal;
    use crate::ast::{CExpr, CType};

    /// Below `int`'s width a `switch` promotes its value, so a literal the cast wraps is no case:
    /// `(uint8_t)x == (uint8_t)-1` holds where `case -1` never would.
    #[test]
    fn a_case_literal_fits_a_type_narrower_than_int() {
        let x = crate::symbol::SymbolTable::new().declare_or_reuse("x");
        let at = |ty: CType, literal: CExpr| {
            let side = |expr| CExpr::cast(ty.clone(), expr);
            case_literal(&side(CExpr::Var(x)), &side(literal)).map(|(_, bits, _)| bits)
        };
        assert_eq!(at(CType::uint(8), CExpr::UIntLit(0xff)), Some(0xff));
        assert_eq!(at(CType::uint(8), CExpr::IntLit(-1)), None);
        assert_eq!(at(CType::uint(8), CExpr::UIntLit(0x100)), None);
        assert_eq!(at(CType::int(8), CExpr::UIntLit(200)), None);
        assert_eq!(at(CType::int(8), CExpr::IntLit(-128)), Some(0x80));
        assert_eq!(at(CType::uint(16), CExpr::UIntLit(0xfffe)), Some(0xfffe));
        assert_eq!(at(CType::uint(32), CExpr::IntLit(-4)), Some(0xffff_fffc));
        // Two different casts are two comparisons.
        let wide = CExpr::cast(CType::uint(64), CExpr::UIntLit(1));
        assert_eq!(
            case_literal(&CExpr::cast(CType::uint(32), CExpr::Var(x)), &wide),
            None
        );
    }
}
