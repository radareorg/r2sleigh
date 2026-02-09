use crate::ast::CExpr;
use crate::fold::FoldingContext;
use r2ssa::{SSAFunction, SSAOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NormalizeMode {
    General,
    Predicate,
}

pub(crate) fn normalize_expr(ctx: &FoldingContext, expr: CExpr, mode: NormalizeMode) -> CExpr {
    match mode {
        NormalizeMode::General | NormalizeMode::Predicate => ctx.simplify_predicate_expr(expr),
    }
}

fn is_block_terminator(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::Branch { .. } | SSAOp::CBranch { .. } | SSAOp::Return { .. }
    )
}

/// Materialize phi moves on single-successor predecessor edges.
///
/// For `phi(dst <- src@pred)`, insert `dst = src` at the end of `pred` when
/// `pred` has only one successor. This keeps semantics without CFG rewriting
/// and reduces emitted phi artifacts in structured output.
pub(crate) fn materialize_phis(func: &SSAFunction) -> SSAFunction {
    let mut normalized = func.clone();
    let mut copies_by_pred: std::collections::HashMap<u64, Vec<SSAOp>> =
        std::collections::HashMap::new();
    let mut kept_phis_by_block: std::collections::HashMap<u64, Vec<r2ssa::PhiNode>> =
        std::collections::HashMap::new();

    for block in func.blocks() {
        let mut kept = Vec::new();

        for phi in &block.phis {
            let mut all_materialized = true;
            for (pred, src) in &phi.sources {
                if func.successors(*pred).len() == 1 {
                    copies_by_pred.entry(*pred).or_default().push(SSAOp::Copy {
                        dst: phi.dst.clone(),
                        src: src.clone(),
                    });
                } else {
                    all_materialized = false;
                }
            }
            if !all_materialized {
                kept.push(phi.clone());
            }
        }

        if kept.len() != block.phis.len() {
            kept_phis_by_block.insert(block.addr, kept);
        }
    }

    for (addr, kept) in kept_phis_by_block {
        if let Some(block) = normalized.get_block_mut(addr) {
            block.phis = kept;
        }
    }

    for (pred, copies) in copies_by_pred {
        if copies.is_empty() {
            continue;
        }
        if let Some(block) = normalized.get_block_mut(pred) {
            let insert_at = block
                .ops
                .iter()
                .rposition(is_block_terminator)
                .unwrap_or(block.ops.len());
            block.ops.splice(insert_at..insert_at, copies);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, UnaryOp};
    use r2il::{R2ILBlock, R2ILOp, Varnode};
    use r2ssa::SSAFunction;

    #[test]
    fn normalization_is_idempotent_for_predicates() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::unary(
            UnaryOp::Not,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
                CExpr::IntLit(0),
            ),
        );

        let once = normalize_expr(&ctx, expr.clone(), NormalizeMode::Predicate);
        let twice = normalize_expr(&ctx, once.clone(), NormalizeMode::Predicate);
        assert_eq!(once, twice, "Predicate normalization must be idempotent");
    }

    #[test]
    fn materialize_phis_on_single_successor_pred() {
        // 0x1000: cbranch to 0x1008 else 0x1004
        // 0x1004: define reg0 = 1, branch 0x100c
        // 0x1008: define reg0 = 2, branch 0x100c
        // 0x100c: return reg0 (forces phi at join)
        let mut b0 = R2ILBlock::new(0x1000, 4);
        b0.push(R2ILOp::CBranch {
            cond: Varnode::constant(1, 1),
            target: Varnode::constant(0x1008, 8),
        });

        let mut b1 = R2ILBlock::new(0x1004, 4);
        b1.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(1, 8),
        });
        b1.push(R2ILOp::Branch {
            target: Varnode::constant(0x100c, 8),
        });

        let mut b2 = R2ILBlock::new(0x1008, 4);
        b2.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(2, 8),
        });
        b2.push(R2ILOp::Branch {
            target: Varnode::constant(0x100c, 8),
        });

        let mut b3 = R2ILBlock::new(0x100c, 4);
        b3.push(R2ILOp::Return {
            target: Varnode::register(0, 8),
        });

        let func = SSAFunction::from_blocks(&[b0, b1, b2, b3]).expect("ssa function");
        let with_phis = func.blocks().any(|b| !b.phis.is_empty());
        assert!(with_phis, "fixture should include phi nodes");

        let normalized = materialize_phis(&func);
        let any_phi = normalized.blocks().any(|b| !b.phis.is_empty());
        assert!(
            !any_phi,
            "phis should be removed when all edges materialize"
        );
    }
}
