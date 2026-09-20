use r2ssa::{FunctionSSABlock, SSAVar};

use super::context::FoldingContext;
use crate::ast::CExpr;
impl<'a> FoldingContext<'a> {
    fn exact_branch_input_expr(&self, block_addr: u64, branch_idx: usize) -> Option<CExpr> {
        match self.planned_input_expr_at(block_addr, branch_idx, 1) {
            Ok(expr) => Some(expr),
            Err(refusal) => {
                self.retain_first_lowering_refusal(refusal);
                None
            }
        }
    }

    pub fn extract_condition_from_block(&self, block: &FunctionSSABlock) -> Option<CExpr> {
        self.certified_branch_condition_from_block(block)
            .map(|(expr, _, _)| expr)
    }

    pub(super) fn certified_branch_condition_from_block(
        &self,
        block: &FunctionSSABlock,
    ) -> Option<(CExpr, r2ssa::PredicateId, r2ssa::ValueId)> {
        // The structurer asks after the fold, when no block is current; the
        // condition's reads are the block's own and are journaled there.
        self.with_current_block(block.addr, || self.branch_condition_in_block(block))
    }

    fn branch_condition_in_block(
        &self,
        block: &FunctionSSABlock,
    ) -> Option<(CExpr, r2ssa::PredicateId, r2ssa::ValueId)> {
        let declined = |gate: &str| {
            r2il::refusal_evidence!("branch-condition", "block {:#x}: {gate}", block.addr);
            None::<(CExpr, r2ssa::PredicateId, r2ssa::ValueId)>
        };
        let Some((branch_idx, cond)) = r2ssa::branch_condition(block) else {
            return declined("no single conditional branch ends the block");
        };
        let Some(predicate) = self
            .control_facts()
            .and_then(|facts| facts.branch_for_block(block.addr))
        else {
            return declined("no control fact names a branch predicate here");
        };
        if self.prepared_value_id_for_var(cond) != Some(predicate.condition) {
            return declined("the branch operand is not the value the predicate names");
        }
        let Some(expr) = self.exact_branch_input_expr(block.addr, branch_idx) else {
            return declined("the predicate has no planned expression at this branch");
        };
        Some((expr, predicate.id, predicate.condition))
    }

    /// The condition guarding this block's tail, and where that tail starts.
    ///
    /// A predicated instruction runs only when its condition fails: the branch
    /// is the skip over it. The operations after the skip are the guarded
    /// ones, so the caller renders them under the negated condition.
    pub fn guarded_tail_condition(&self, block: &FunctionSSABlock) -> Option<(CExpr, usize)> {
        let (branch_idx, _) = r2ssa::branch_condition(block)?;
        if branch_idx + 1 >= block.ops.len() {
            return None;
        }
        // The branch's own operand, read the way every operand is read. No
        // predicate fact names this branch: a fact carries the two blocks a
        // test reaches, and one arm of this one leaves the function.
        let expr = self.exact_branch_input_expr(block.addr, branch_idx)?;
        Some((expr, branch_idx + 1))
    }

    pub(super) fn resolve_predicate_rhs_for_var(&self, _src: &SSAVar, fallback: CExpr) -> CExpr {
        // `fallback` was assembled from the current normalized operation's
        // exact planned inputs. Preserve those source UseSites verbatim.
        fallback
    }

    #[cfg(test)]
    fn prepared_predicate_candidate_for_branch_block(
        &self,
        block_addr: u64,
        var: &SSAVar,
    ) -> Option<CExpr> {
        let facts = self.control_facts()?;
        let predicate = facts
            .branch_for_block(block_addr)
            .filter(|predicate| Some(predicate.condition) == self.prepared_value_id_for_var(var))
            .or_else(|| {
                facts
                    .block_assumptions
                    .values()
                    .flat_map(|assumptions| assumptions.iter())
                    .find(|assumption| assumption.predecessor == block_addr)
                    .and_then(|assumption| {
                        facts
                            .branch_predicates
                            .values()
                            .find(|predicate| predicate.id == assumption.predicate)
                    })
            })?;
        let block = self.inputs.prepared_ssa?.function().get_block(block_addr)?;
        self.certified_branch_condition_from_block(block)
            .filter(|(_, predicate_id, _)| *predicate_id == predicate.id)
            .map(|(expr, _, _)| expr)
    }

    #[cfg(test)]
    pub(super) fn prepared_predicate_candidate_for_branch_block_for_test(
        &self,
        block_addr: u64,
        var: &SSAVar,
    ) -> Option<CExpr> {
        self.prepared_predicate_candidate_for_branch_block(block_addr, var)
    }
    // ========== Helper functions for flag pattern detection ==========
}
