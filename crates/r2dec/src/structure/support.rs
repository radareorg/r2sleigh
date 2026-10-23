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

/// A call to `exit`.
pub(crate) fn exit() -> CStmt {
    let callee = CExpr::External {
        name: EXIT.to_owned(),
        kind: ExternalKind::Function,
    };
    CStmt::Expr(CExpr::call(callee, Vec::new()))
}

/// Whether a statement is a call to `exit`, which is what the tests' evidence says.
pub(crate) fn never_returns(stmt: &CStmt) -> bool {
    matches!(stmt, CStmt::Expr(CExpr::Call { func, .. })
        if matches!(&**func, CExpr::External { name, .. } if name == EXIT))
}
