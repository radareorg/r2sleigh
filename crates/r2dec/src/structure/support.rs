#![cfg(test)]
//! Fixtures for the structure tests: a CFG from terminators, and statements observed as a block's.

use std::collections::BTreeSet;

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
    let forms = [leaves(&x), composites(&x)].concat();
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

/// The forms with no operand: literals, the variable `x` bare and observed, and names the function does not own.
fn leaves(x: &CExpr) -> Vec<CExpr> {
    vec![
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
    ]
}

/// The forms over operands, each over `x`, and a cast of a literal beside the cast of `x`.
fn composites(x: &CExpr) -> Vec<CExpr> {
    let boxed = || Box::new(x.clone());
    let int = crate::ast::CType::Int {
        bits: 32,
        signedness: r2types::Signedness::Signed,
    };
    let callee = CExpr::External {
        name: "f".to_owned(),
        kind: ExternalKind::Import,
    };
    vec![
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
        CExpr::call(callee, vec![x.clone()]),
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
    ]
}

/// Calls to `exit`: each top-level form at each position of none to sixteen arguments, every ordered pair of forms,
/// and [`Draw`]'s calls, which vary values, symbols, sites, the callee's kind and nesting to depth eight.
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
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    let drawn = (0..2048).map(|_| draw.call()).collect::<Vec<_>>();
    rotated
        .chain(pairs)
        .map(|picked: Vec<usize>| call(picked.into_iter().map(|at| forms[at].clone()).collect()))
        .chain(drawn)
        .collect::<Vec<_>>()
        .into_iter()
}

/// A fixed xorshift stream of calls to `exit` with none to twenty arguments, each a tree of every form.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("below n")
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())].clone()
    }

    fn site(&mut self) -> Option<r2ssa::InstId> {
        let id = r2ssa::InstId(u32::try_from(self.below(64)).expect("small"));
        self.pick(&[None, Some(id)])
    }

    fn call(&mut self) -> CStmt {
        let kind = self.pick(&[ExternalKind::Function, ExternalKind::Import]);
        let callee = CExpr::External {
            name: EXIT.to_owned(),
            kind,
        };
        let args = (0..self.below(21)).map(|_| self.tree(8)).collect();
        let site = self.site();
        CStmt::Expr(CExpr::Call {
            func: Box::new(callee),
            args,
            site,
        })
    }

    fn ty(&mut self) -> crate::ast::CType {
        use crate::ast::CType;
        let signedness = self.pick(&[r2types::Signedness::Signed, r2types::Signedness::Unsigned]);
        let bits = self.pick(&[8, 16, 32, 64]);
        let int = CType::Int { bits, signedness };
        self.pick(&[int.clone(), CType::ptr(int), CType::void_ptr(), CType::Bool])
    }

    /// An argument: a leaf at depth 0 and one time in three, else a form over arguments one level shallower.
    fn tree(&mut self, depth: u32) -> CExpr {
        match depth {
            0 => self.leaf(),
            _ if self.below(3) == 0 => self.leaf(),
            _ => self.node(depth - 1),
        }
    }

    fn sub(&mut self, depth: u32) -> Box<CExpr> {
        Box::new(self.tree(depth))
    }

    fn leaf(&mut self) -> CExpr {
        let raw = self.next();
        match self.below(9) {
            0 => {
                CExpr::IntLit(self.pick(&[0, 1, -1, 2, 127, i64::MIN, i64::MAX, raw.cast_signed()]))
            }
            1 => CExpr::UIntLit(self.pick(&[0, 1, 2, 4096, u64::MAX, raw])),
            2 => CExpr::FloatLit(self.pick(&[0.0, 1.5, -0.0]), self.pick(&[32, 64])),
            3 => CExpr::StringLit(self.pick(&["", "s", "bad %d at %s\n"]).to_owned()),
            4 => CExpr::CharLit(self.pick(&['\0', 'c', 'x'])),
            5 => CExpr::External {
                name: self.pick(&["g", "f", EXIT]).to_owned(),
                kind: self.pick(&[
                    ExternalKind::Function,
                    ExternalKind::Import,
                    ExternalKind::Global,
                    ExternalKind::Intrinsic,
                ]),
            },
            6 => CExpr::DataObject {
                address: self.pick(&[0, 0x40, 0x4010, raw]),
                name: "d".to_owned(),
            },
            _ => {
                let mut table = crate::symbol::SymbolTable::new();
                let names = ["x", "arg0", "rax_2", "tmp_14ad_0_1", "rdi", "local_10"];
                let ids = names.map(|name| table.declare_or_reuse(name));
                CExpr::var(self.pick(&ids))
            }
        }
    }

    /// A form over operands of `depth`, with its operator, type, role, size or site drawn.
    fn node(&mut self, depth: u32) -> CExpr {
        use crate::ast::{BinaryOp as B, CastRole, UnaryOp as U};
        let many = |draw: &mut Self, least: usize| {
            let n = least + draw.below(4);
            (0..n).map(|_| draw.tree(depth)).collect::<Vec<_>>()
        };
        match self.below(15) {
            0 => {
                let op = self.pick(&[U::Not, U::BitNot, U::Neg, U::PreInc, U::PostDec]);
                CExpr::Unary {
                    op,
                    operand: self.sub(depth),
                }
            }
            1 => {
                let op = self.pick(&[
                    B::Add,
                    B::Sub,
                    B::BitAnd,
                    B::Shr,
                    B::Mul,
                    B::Eq,
                    B::Lt,
                    B::And,
                ]);
                CExpr::binary(op, self.tree(depth), self.tree(depth))
            }
            2 => CExpr::Ternary {
                cond: self.sub(depth),
                then_expr: self.sub(depth),
                else_expr: self.sub(depth),
            },
            3 => CExpr::Cast {
                ty: self.ty(),
                expr: self.sub(depth),
                role: self.pick(&[CastRole::Conversion, CastRole::PointerWidthStep]),
            },
            4 => {
                let callee = CExpr::External {
                    name: self.pick(&["f", EXIT]).to_owned(),
                    kind: ExternalKind::Import,
                };
                CExpr::Call {
                    func: Box::new(callee),
                    args: many(self, 0),
                    site: self.site(),
                }
            }
            5 => CExpr::Subscript {
                base: self.sub(depth),
                index: self.sub(depth),
            },
            6 => CExpr::Member {
                base: self.sub(depth),
                member: "m".to_owned(),
            },
            7 => CExpr::PtrMember {
                base: self.sub(depth),
                member: "code".to_owned(),
            },
            8 => CExpr::Sizeof(self.sub(depth)),
            9 => CExpr::SizeofType(self.ty()),
            10 => CExpr::AddrOf(self.sub(depth)),
            11 => CExpr::Deref(self.sub(depth)),
            12 => CExpr::Comma(many(self, 1)),
            13 => CExpr::Paren(self.sub(depth)),
            _ => {
                let id = test_render_observation_id(u32::try_from(self.below(32)).expect("small"));
                CExpr::observe_one(id, self.tree(depth))
            }
        }
    }
}

/// The callees the tests' evidence declares never to return: `exit`.
pub(crate) fn declared() -> std::collections::BTreeSet<String> {
    std::collections::BTreeSet::from([EXIT.to_owned()])
}

/// Whether a statement is a call to `exit`, which is what [`declared`] says.
pub(crate) fn never_returns(stmt: &CStmt) -> bool {
    super::shape::callee_of(stmt) == Some(EXIT)
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

/// How deep `expr` nests, a leaf being 0.
fn depth(expr: &CExpr) -> usize {
    let operands: Vec<&CExpr> = match expr {
        CExpr::Observed { expr, .. }
        | CExpr::Cast { expr, .. }
        | CExpr::Sizeof(expr)
        | CExpr::AddrOf(expr)
        | CExpr::Deref(expr)
        | CExpr::Paren(expr)
        | CExpr::Unary { operand: expr, .. }
        | CExpr::Member { base: expr, .. }
        | CExpr::PtrMember { base: expr, .. } => vec![expr],
        CExpr::Binary { left, right, .. }
        | CExpr::Subscript {
            base: left,
            index: right,
        } => vec![left, right],
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => vec![cond, then_expr, else_expr],
        CExpr::Call { args, .. } | CExpr::Comma(args) => args.iter().collect(),
        _ => Vec::new(),
    };
    operands
        .into_iter()
        .map(|e| 1 + depth(e))
        .max()
        .unwrap_or(0)
}

#[test]
fn the_drawn_calls_reach_twenty_arguments_depth_eight_and_both_sites() {
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    let calls = (0..2048).map(|_| draw.call()).collect::<Vec<_>>();
    let (mut most, mut deepest, mut sites) = (0, 0, BTreeSet::new());
    for call in &calls {
        let CStmt::Expr(CExpr::Call { args, site, .. }) = call else {
            panic!("{call:?}")
        };
        most = most.max(args.len());
        deepest = deepest.max(args.iter().map(depth).max().unwrap_or(0));
        sites.insert(site.is_some());
    }
    assert_eq!((most, deepest, sites.len()), (20, 8, 2));
}
