//! Where a value may be computed, as opposed to where the graph computed it.
//!
//! The graph records one site per value: the instruction that produced it. That
//! site is an accident of how the machine was lifted, not a fact about the
//! program. A value may legally be computed anywhere its inputs are already
//! available and from which every reader is still reached, provided nothing in
//! between changes what it would answer.
//!
//! Three things the renderer cannot do without this. A loop test cannot be
//! lifted into its header while the staging copy that feeds it is pinned to the
//! block below. A flag definition cannot be dropped while a merge that nothing
//! renders still counts as a read. And a frame-slot read cannot be spelled at
//! the place that uses it, which is why a rendering names one local for the slot
//! and a second for the register that ferried it -- twice the instruction mass
//! of the source, at `-O0`, and the largest single defect in the output.
//!
//! This module answers the third, for the shape that produces it. A load moved
//! forward to its reader is safe exactly when nothing between the two can have
//! changed the cell: no store, and no call, since a call may write anywhere.
//! Loads are pure, so arriving on fewer paths costs nothing.

use crate::graph::ValueId;
use crate::op::SSAOp;
use crate::semantic::{StructuredDataflowFacts, StructuredMemoryAccessFact};

/// One point in the rendered program: an operation within a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramPoint {
    pub block_addr: u64,
    pub op_index: usize,
}

/// Why a value could not move to the point it was asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobilityRefusal {
    /// The two points are in different blocks. Answering needs the paths
    /// between them, which this does not yet walk.
    DifferentBlocks,
    /// The reader runs before the definition, so moving the definition forward
    /// would put it after its own use.
    ReaderPrecedesDefinition,
    /// The block does not exist in the function being rendered.
    NoSuchBlock,
    /// A store between the two points may have changed the cell.
    StoreBetween { op_index: usize },
    /// A call between the two points may write anywhere.
    CallBetween { op_index: usize },
}

/// Whether the cell `access` reads still holds the same value at `reader`, so
/// that the read may be spelled there instead of being given a name here.
///
/// Conservative in one direction only: a refusal means this could not prove the
/// move safe, never that the move is unsafe.
pub fn load_may_move_to<F>(
    function: &F,
    access: &StructuredMemoryAccessFact,
    reader: ProgramPoint,
) -> Result<(), MobilityRefusal>
where
    F: BlockOps,
{
    if access.is_write {
        return Err(MobilityRefusal::StoreBetween {
            op_index: access.op_index,
        });
    }
    if access.block_addr != reader.block_addr {
        return Err(MobilityRefusal::DifferentBlocks);
    }
    if reader.op_index <= access.op_index {
        return Err(MobilityRefusal::ReaderPrecedesDefinition);
    }
    let ops = function
        .block_ops(access.block_addr)
        .ok_or(MobilityRefusal::NoSuchBlock)?;
    for (offset, op) in ops
        .iter()
        .enumerate()
        .take(reader.op_index)
        .skip(access.op_index + 1)
    {
        // A call may write any cell, so it ends the answer as surely as a
        // store to this one does.
        if matches!(
            op,
            SSAOp::Call { .. } | SSAOp::CallInd { .. } | SSAOp::CallDefine { .. }
        ) {
            return Err(MobilityRefusal::CallBetween { op_index: offset });
        }
        if op.is_memory_write() {
            return Err(MobilityRefusal::StoreBetween { op_index: offset });
        }
    }
    Ok(())
}

/// The operations of one block, which is all this needs of a function.
pub trait BlockOps {
    fn block_ops(&self, block_addr: u64) -> Option<&[SSAOp]>;
}

/// Every load in the function whose cell is unchanged at the single operation
/// that reads its value, keyed by the value the load produced.
///
/// The renderer uses this to spell a slot read at its reader rather than
/// declaring a name for it.
pub fn loads_movable_to_their_reader<F>(
    function: &F,
    structured: &StructuredDataflowFacts,
    reader_of: impl Fn(ValueId) -> Option<ProgramPoint>,
) -> std::collections::BTreeSet<ValueId>
where
    F: BlockOps,
{
    let mut movable = std::collections::BTreeSet::new();
    for access in structured.memory_accesses.values() {
        if access.is_write || !access.provenance_complete {
            continue;
        }
        let Some(value) = access.value else { continue };
        let Some(reader) = reader_of(value) else {
            continue;
        };
        if load_may_move_to(function, access, reader).is_ok() {
            movable.insert(value);
        }
    }
    movable
}

impl BlockOps for crate::function::SSAFunction {
    fn block_ops(&self, block_addr: u64) -> Option<&[SSAOp]> {
        self.get_block(block_addr).map(|block| block.ops.as_slice())
    }
}

/// The instructions whose rendering something depends on.
///
/// A read is only a read if what it feeds reaches the page. At `-O0` a
/// sub-register write reads the whole register to rebuild it, and the rebuilt
/// value is usually dead, so a value can carry nine graph readers and one
/// rendered one. Counting the graph's readers is what keeps such a value named.
///
/// The roots are the instructions that owe a semantic obligation: the ledger is
/// the authority on what must be accounted for, so anything it does not ask for
/// and nothing needed reads is not rendered. Needing is then transitive through
/// operands, and the closure is taken to a fixpoint -- which is what the two
/// single-instruction predicates tried before this could not express.
pub fn instructions_that_render(
    graph: &crate::graph::SsaGraph,
    owes_obligation: impl Fn(crate::graph::InstId) -> bool,
) -> std::collections::BTreeSet<crate::graph::InstId> {
    let mut needed = std::collections::BTreeSet::new();
    let mut frontier = Vec::new();
    for (index, _) in graph.insts.iter().enumerate() {
        let inst = crate::graph::InstId(index as u32);
        if owes_obligation(inst) && needed.insert(inst) {
            frontier.push(inst);
        }
    }
    while let Some(inst) = frontier.pop() {
        let Some(node) = graph.inst(inst) else {
            continue;
        };
        for input in &node.inputs {
            let Some(definition) = graph.def_inst(*input) else {
                continue;
            };
            if needed.insert(definition) {
                frontier.push(definition);
            }
        }
    }
    needed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::StructuredMemoryAccessFact;

    struct Ops(Vec<SSAOp>);

    impl BlockOps for Ops {
        fn block_ops(&self, _block_addr: u64) -> Option<&[SSAOp]> {
            Some(self.0.as_slice())
        }
    }

    fn var(name: &str) -> crate::var::SSAVar {
        crate::var::SSAVar::new(name, 1, 8)
    }

    fn nop() -> SSAOp {
        SSAOp::Copy {
            dst: var("a"),
            src: var("b"),
        }
    }

    fn store() -> SSAOp {
        SSAOp::Store {
            space: r2il::SpaceId::Ram,
            addr: var("p"),
            val: var("v"),
        }
    }

    fn read_at(op_index: usize) -> StructuredMemoryAccessFact {
        StructuredMemoryAccessFact {
            id: crate::semantic::StructuredAccessId {
                inst: crate::graph::InstId(0),
                ordinal: 0,
            },
            block_addr: 0x1000,
            op_index,
            space: r2il::SpaceId::Ram,
            object: crate::semantic::ObjectId(0),
            address: ValueId(0),
            value: Some(ValueId(1)),
            is_write: false,
            width: 8,
            provenance_complete: true,
            object_offset: None,
        }
    }

    fn point(op_index: usize) -> ProgramPoint {
        ProgramPoint {
            block_addr: 0x1000,
            op_index,
        }
    }

    /// The shape `-O0` emits: load a slot, use it two operations later, with
    /// nothing in between that can have changed the cell.
    #[test]
    fn a_slot_read_moves_to_its_reader_when_nothing_intervenes() {
        let ops = Ops(vec![nop(), nop(), nop(), nop()]);
        assert_eq!(load_may_move_to(&ops, &read_at(0), point(3)), Ok(()));
    }

    #[test]
    fn a_store_between_pins_the_read_where_it_is() {
        let ops = Ops(vec![nop(), store(), nop(), nop()]);
        assert_eq!(
            load_may_move_to(&ops, &read_at(0), point(3)),
            Err(MobilityRefusal::StoreBetween { op_index: 1 })
        );
    }

    /// A call may write any cell, so it ends the answer as surely as a store
    /// to this one does.
    #[test]
    fn a_call_between_pins_the_read_where_it_is() {
        let ops = Ops(vec![
            nop(),
            SSAOp::Call {
                target: var("f"),
                instruction: None,
            },
            nop(),
        ]);
        assert!(matches!(
            load_may_move_to(&ops, &read_at(0), point(2)),
            Err(MobilityRefusal::CallBetween { .. })
        ));
    }

    #[test]
    fn a_reader_before_the_read_is_not_a_move_forward() {
        let ops = Ops(vec![nop(), nop(), nop()]);
        assert_eq!(
            load_may_move_to(&ops, &read_at(2), point(1)),
            Err(MobilityRefusal::ReaderPrecedesDefinition)
        );
    }
}
