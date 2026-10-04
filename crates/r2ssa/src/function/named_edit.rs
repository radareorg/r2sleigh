//! A block edited in the spelling a fixture writes: variables by name.
//!
//! A function holds its operands as [`VarId`]s into its [`ValueTable`]. A
//! test that builds or corrupts a function writes a program by name, so the
//! edit it is handed interns every variable it writes and names every one it
//! reads. Passes never edit through this: they hold ids and change a block
//! through [`BlockMut`] directly.

use crate::arena::{OpId, Pass};
use crate::block::BlockMut;
use crate::op::SSAOp;
use crate::value_table::{ValueTable, VarId};
use crate::var::SSAVar;

use super::PhiNode;

/// One block, open for change in variables by name, beside the table that
/// numbers them.
pub struct NamedBlockMut<'a> {
    block: BlockMut<'a, VarId>,
    values: &'a mut ValueTable,
}

impl<'a> NamedBlockMut<'a> {
    pub(super) fn new(block: BlockMut<'a, VarId>, values: &'a mut ValueTable) -> Self {
        Self { block, values }
    }

    fn intern_op(&mut self, op: &SSAOp) -> SSAOp<VarId> {
        op.map(&mut |var| self.values.intern(var))
    }

    fn intern_phi(&mut self, phi: &PhiNode) -> PhiNode<VarId> {
        phi.map(&mut |var| self.values.intern(var))
    }

    /// The operations, named.
    pub fn ops(&self) -> Vec<SSAOp> {
        self.block
            .ops()
            .iter()
            .map(|op| op.map(&mut |id| self.values.var(*id).clone()))
            .collect()
    }

    /// The phis, named.
    pub fn phis(&self) -> Vec<PhiNode> {
        self.block
            .phis()
            .iter()
            .map(|phi| phi.map(&mut |id| self.values.var(*id).clone()))
            .collect()
    }

    /// Rewrite the operation at `at` by name; it keeps its id.
    pub fn edit_op(&mut self, at: usize, edit: impl FnOnce(&mut SSAOp)) {
        let mut op = self.ops().swap_remove(at);
        edit(&mut op);
        let op = self.intern_op(&op);
        self.block.ops_mut()[at] = op;
    }

    /// Rewrite the phi at `at` by name; it keeps its id.
    pub fn edit_phi(&mut self, at: usize, edit: impl FnOnce(&mut PhiNode)) {
        let mut phi = self.phis().swap_remove(at);
        edit(&mut phi);
        let phi = self.intern_phi(&phi);
        self.block.phis_mut()[at] = phi;
    }

    /// Append one operation, derived by `pass` from `from`.
    pub fn push_op(&mut self, op: SSAOp, from: Option<OpId>, pass: Pass) {
        let op = self.intern_op(&op);
        self.block.push_op(op, from, pass);
    }

    /// Replace every operation: the old ids die, the new ones are minted.
    pub fn replace_ops(&mut self, pass: Pass, ops: Vec<SSAOp>) {
        let ops = ops.iter().map(|op| self.intern_op(op)).collect();
        self.block.replace_ops(pass, ops);
    }

    /// Replace every phi: the old ids die, the new ones are minted.
    pub fn replace_phis(&mut self, pass: Pass, phis: Vec<PhiNode>) {
        let phis = phis.iter().map(|phi| self.intern_phi(phi)).collect();
        self.block.replace_phis(pass, phis);
    }

    /// Keep the phis `keep` accepts by name, tombstoning the rest.
    pub fn retain_phis(&mut self, pass: Pass, mut keep: impl FnMut(&PhiNode) -> bool) {
        let values = &*self.values;
        self.block.retain_phis(pass, |phi| {
            keep(&phi.map(&mut |id| values.var(*id).clone()))
        });
    }

    /// The variable an id names, for a fixture that compares against one.
    pub fn var(&self, id: VarId) -> &SSAVar {
        self.values.var(id)
    }
}
