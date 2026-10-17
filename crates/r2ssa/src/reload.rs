//! Loads that reread an exact frame slot no write has touched since an earlier load, so are its bits.
//! Along single-predecessor chains, `O(ops)` (doc/adr-frame-model.md, "Reloads").

use std::collections::BTreeMap;

use crate::SSAOp;
use crate::dense::IdMap;
use crate::function::{DecompilePrepFacts, StackAddressRoot};
use crate::graph::{BlockId, SsaGraph, ValueId};
use crate::semantic::resolve_entry_stack_root;

/// Widest access the held slots are searched for overlap at.
const WIDEST: u32 = 64;

type Held = BTreeMap<(StackAddressRoot, u32), ValueId>;

/// The graph walked, and the rereads found so far.
struct Rereads<'a> {
    graph: &'a SsaGraph,
    prep: Option<&'a DecompilePrepFacts>,
    found: IdMap<ValueId, ValueId>,
}

/// For each load that rereads a slot unchanged, the value of the load it rereads.
pub(crate) fn reloads(
    graph: &SsaGraph,
    prep: Option<&DecompilePrepFacts>,
) -> IdMap<ValueId, ValueId> {
    let mut rereads = Rereads {
        graph,
        prep,
        found: IdMap::new(graph.values.len()),
    };
    if prep.is_none() {
        return rereads.found;
    }
    let sole_predecessor = |block: BlockId| match graph.blocks[block.0 as usize].predecessors[..] {
        [only] if only != block => Some(only),
        _ => None,
    };
    // A sole-predecessor block continues its parent's slots, the rest start empty: each block is visited once.
    let mut pending: Vec<(BlockId, Held)> = (graph.blocks.iter())
        .filter(|block| sole_predecessor(block.id).is_none())
        .map(|block| (block.id, Held::new()))
        .collect();
    while let Some((block, mut held)) = pending.pop() {
        for &inst in graph.op_insts(block) {
            let (Some(op), Some(node)) = (graph.op(inst), graph.inst(inst)) else {
                continue;
            };
            rereads.step(op, node.output, &mut held);
        }
        let mut children = (graph.blocks[block.0 as usize].successors.iter())
            .copied()
            .filter(|child| sole_predecessor(*child) == Some(block))
            .collect::<Vec<_>>();
        children.sort_unstable();
        children.dedup();
        let last = children.len();
        for (index, child) in children.into_iter().enumerate() {
            let state = if index + 1 == last {
                std::mem::take(&mut held)
            } else {
                held.clone()
            };
            pending.push((child, state));
        }
    }
    rereads.found
}

impl Rereads<'_> {
    fn step(&mut self, op: &SSAOp<ValueId>, output: Option<ValueId>, held: &mut Held) {
        let (graph, prep) = (self.graph, self.prep);
        let slot = |addr: ValueId, space: r2il::SpaceId| {
            (space == r2il::SpaceId::Ram)
                .then(|| resolve_entry_stack_root(prep, addr))
                .flatten()
        };
        match op {
            SSAOp::Load { space, addr, .. } => {
                let (Some(root), Some(out)) = (slot(*addr, *space), output) else {
                    return;
                };
                let size = graph.value(out).map_or(0, |value| value.var.size);
                if size == 0 || size > WIDEST {
                    return;
                }
                match held.get(&(root, size)) {
                    Some(first) => {
                        self.found.insert(out, *first);
                    }
                    None => {
                        held.insert((root, size), out);
                    }
                }
            }
            SSAOp::Store { space, addr, val } => {
                let size = graph.value(*val).map_or(0, |value| value.var.size);
                let wide = size > 0 && size <= WIDEST;
                after_store(
                    held,
                    slot(*addr, *space)
                        .filter(|_| wide)
                        .map(|root| (root, size)),
                );
            }
            op if clobbers(op) => held.clear(),
            _ => {}
        }
    }
}

/// What a store leaves held: an exact frame slot keeps the slots it misses, any other store keeps none.
fn after_store(held: &mut Held, stored: Option<(StackAddressRoot, u32)>) {
    match stored {
        Some(stored) => held.retain(|(root, size), _| disjoint((*root, *size), stored)),
        None => held.clear(),
    }
}

/// Whether two accesses are of different bytes of one frame.
fn disjoint((a, a_size): (StackAddressRoot, u32), (b, b_size): (StackAddressRoot, u32)) -> bool {
    let end = |root: StackAddressRoot, size: u32| root.offset.saturating_add(i64::from(size));
    a.base == b.base && (end(a, a_size) <= b.offset || end(b, b_size) <= a.offset)
}

/// Whether the operation may write memory the frame holds, or leave what a load reads unstated.
fn clobbers(op: &SSAOp<ValueId>) -> bool {
    op.is_memory_write()
        || op.is_call()
        || matches!(
            op,
            SSAOp::CallOther { .. }
                | SSAOp::Fence { .. }
                | SSAOp::ClearExclusive
                | SSAOp::IndivisibleAccess
                | SSAOp::BlockTransfer(_)
                | SSAOp::Unimplemented
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
        )
}
