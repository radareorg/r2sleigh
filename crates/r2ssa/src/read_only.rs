//! A load at a literal address of bytes the capture holds read-only reads them on every run, so it
//! becomes a copy of the constant (ROADMAP P5): one pass over the operations, one search per load.

use crate::function::{EditPlan, SSAFunction};
use crate::machine_context::SourceMachineContext;
use crate::op::SSAOp;
use crate::value_table::Minting;
use r2il::SpaceId;

/// Rewrite each load of read-only bytes at a literal address into a copy of the constant; the count.
pub(crate) fn fold_loads(func: &mut SSAFunction, context: &SourceMachineContext) -> usize {
    let mut plan = EditPlan::new();
    let mut minting = Minting::new(func.values());
    let mut folded = 0;
    for block in func.blocks() {
        for (index, op) in block.ops().iter().enumerate() {
            let SSAOp::Load {
                dst,
                space: SpaceId::Ram,
                addr,
            } = op
            else {
                continue;
            };
            let address = func.var(*addr);
            let Some(at) = address.constant_bits().filter(|_| address.is_const()) else {
                continue;
            };
            let size = func.var(*dst).size;
            let (Some(bits), Some(id)) = (context.read_only_bits(at, size), block.op_id(index))
            else {
                continue;
            };
            r2il::refusal_evidence!(
                "read-only-load",
                "{:#x}: the {size}-byte load at {at:#x} reads {bits:#x}",
                func.entry
            );
            let src = minting.constant(bits, size);
            plan.replace(id, SSAOp::Copy { dst: *dst, src });
            folded += 1;
        }
    }
    if folded > 0 {
        plan.adopt(minting.finish());
        func.apply_edits(plan);
    }
    folded
}
