//! Fixtures for the structure tests: a CFG from terminators, and statements observed as a block's.

use r2ssa::cfg::{BasicBlock, BlockTerminator, CFG};

use super::certify::Placed;
use crate::ast::{CExpr, CStmt, RenderObservationId, test_render_observation_id};
use crate::symbol::ExternalKind;

/// Markers numbered by the block they were written for, none of them a statement the placement wrote.
pub(crate) struct ByBlock;

impl Placed for ByBlock {
    fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        Some(u64::from(id.index()))
    }

    fn statement_of(&self, id: RenderObservationId) -> Option<RenderObservationId> {
        Some(id)
    }

    fn written(&self) -> usize {
        0
    }

    fn edge_copy(&self, _id: RenderObservationId) -> bool {
        false
    }
}

pub(crate) fn cfg(entry: u64, blocks: &[(u64, BlockTerminator)]) -> CFG {
    let mut cfg = CFG::new(entry);
    for (addr, _) in blocks {
        cfg.add_block(BasicBlock::new(*addr));
    }
    for (addr, terminator) in blocks {
        cfg.set_terminator(*addr, terminator.clone());
    }
    cfg
}

/// A statement observed as belonging to `block`.
pub(crate) fn at(block: u64, stmt: CStmt) -> CStmt {
    CStmt::observe_one(
        test_render_observation_id(u32::try_from(block).expect("small address")),
        stmt,
    )
}

pub(crate) fn expr() -> CStmt {
    CStmt::Expr(CExpr::IntLit(0))
}

pub(crate) fn cond() -> CExpr {
    CExpr::IntLit(1)
}

pub(crate) fn branch(target: u64) -> BlockTerminator {
    BlockTerminator::Branch { target }
}

pub(crate) fn cond_branch(true_target: u64, false_target: u64) -> BlockTerminator {
    BlockTerminator::ConditionalBranch {
        true_target,
        false_target,
    }
}

/// The callee every test declares never returns.
pub(crate) const EXIT: &str = "exit";

/// A call to the function `name`.
pub(crate) fn call_to(name: &str) -> CStmt {
    let callee = CExpr::External {
        name: name.to_owned(),
        kind: ExternalKind::Function,
    };
    CStmt::Expr(CExpr::call(callee, Vec::new()))
}

/// A call to `exit`.
pub(crate) fn exit() -> CStmt {
    call_to(EXIT)
}

/// One argument of every `CExpr` form; the match has no wildcard, so a new form must join the list.
fn arguments() -> Vec<CExpr> {
    let x = CExpr::var(crate::symbol::SymbolTable::new().declare_or_reuse("x"));
    let boxed = || Box::new(x.clone());
    let int = crate::ast::CType::Int {
        bits: 32,
        signedness: r2types::Signedness::Signed,
    };
    let forms = vec![
        CExpr::observe_one(test_render_observation_id(7), x.clone()),
        CExpr::IntLit(1),
        CExpr::UIntLit(1),
        CExpr::FloatLit(1.0, 64),
        CExpr::StringLit("s".to_owned()),
        CExpr::CharLit('c'),
        x.clone(),
        CExpr::External {
            name: "g".to_owned(),
            kind: ExternalKind::Global,
        },
        CExpr::DataObject {
            address: 0x40,
            name: "d".to_owned(),
        },
        CExpr::Unary {
            op: crate::ast::UnaryOp::Neg,
            operand: boxed(),
        },
        CExpr::binary(crate::ast::BinaryOp::Add, x.clone(), CExpr::IntLit(1)),
        CExpr::Ternary {
            cond: boxed(),
            then_expr: boxed(),
            else_expr: boxed(),
        },
        CExpr::cast(int.clone(), x.clone()),
        CExpr::cast(int.clone(), CExpr::IntLit(1)),
        CExpr::call(
            CExpr::External {
                name: "f".to_owned(),
                kind: ExternalKind::Import,
            },
            vec![x.clone()],
        ),
        CExpr::Subscript {
            base: boxed(),
            index: boxed(),
        },
        CExpr::Member {
            base: boxed(),
            member: "m".to_owned(),
        },
        CExpr::PtrMember {
            base: boxed(),
            member: "m".to_owned(),
        },
        CExpr::Sizeof(boxed()),
        CExpr::SizeofType(int),
        CExpr::AddrOf(boxed()),
        CExpr::Deref(boxed()),
        CExpr::Comma(vec![x.clone(), x.clone()]),
        CExpr::Paren(boxed()),
    ];
    for form in &forms {
        match form {
            CExpr::Observed { .. }
            | CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(..)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::Var(_)
            | CExpr::External { .. }
            | CExpr::DataObject { .. }
            | CExpr::Unary { .. }
            | CExpr::Binary { .. }
            | CExpr::Ternary { .. }
            | CExpr::Cast { .. }
            | CExpr::Call { .. }
            | CExpr::Subscript { .. }
            | CExpr::Member { .. }
            | CExpr::PtrMember { .. }
            | CExpr::Sizeof(_)
            | CExpr::SizeofType(_)
            | CExpr::AddrOf(_)
            | CExpr::Deref(_)
            | CExpr::Comma(_)
            | CExpr::Paren(_) => {}
        }
    }
    forms
}

/// Calls to `exit`: none to sixteen arguments with each form at each position, and every ordered pair of forms.
/// A reader that reads them, by count, form or order, fails its test.
pub(crate) fn exit_calls() -> impl Iterator<Item = CStmt> {
    let forms = arguments();
    let call = |args: Vec<CExpr>| {
        let callee = CExpr::External {
            name: EXIT.to_owned(),
            kind: ExternalKind::Function,
        };
        CStmt::Expr(CExpr::call(callee, args))
    };
    let len = forms.len();
    let rotated = (0..len).flat_map(move |start| {
        (0..=16).map(move |count| (0..count).map(|at| (start + at) % len).collect())
    });
    let pairs = (0..len).flat_map(move |left| (0..len).map(move |right| vec![left, right]));
    rotated
        .chain(pairs)
        .map(|picked: Vec<usize>| call(picked.into_iter().map(|at| forms[at].clone()).collect()))
        .collect::<Vec<_>>()
        .into_iter()
}

/// The callees the tests' evidence declares never to return: `exit`.
pub(crate) fn declared() -> std::collections::BTreeSet<String> {
    std::collections::BTreeSet::from([EXIT.to_owned()])
}

/// Whether a statement is a call to `exit`, which is what [`declared`] says.
pub(crate) fn never_returns(stmt: &CStmt) -> bool {
    matches!(stmt, CStmt::Expr(CExpr::Call { func, .. })
        if matches!(&**func, CExpr::External { name, .. } if name == EXIT))
}

/// Markers whose block is their index; the copy of marker `n` is marker `1000 + n`.
pub(crate) struct Fixture;

impl Placed for Fixture {
    fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        Some(u64::from(id.index() % 1000))
    }

    fn statement_of(&self, id: RenderObservationId) -> Option<RenderObservationId> {
        Some(id)
    }

    fn written(&self) -> usize {
        0
    }

    fn edge_copy(&self, _id: RenderObservationId) -> bool {
        false
    }
}

impl super::condition::Marks for Fixture {
    fn block_of(&self, id: RenderObservationId) -> Option<u64> {
        Some(u64::from(id.index() % 1000))
    }

    fn copy_of(&mut self, id: RenderObservationId) -> RenderObservationId {
        test_render_observation_id(1000 + id.index())
    }
}
