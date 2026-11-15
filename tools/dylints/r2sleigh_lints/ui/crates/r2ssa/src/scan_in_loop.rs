use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InstId(u32);

struct GraphInst {
    id: InstId,
}

struct GraphBlock {
    addr: u64,
    insts: Vec<InstId>,
}

struct SsaGraph {
    blocks: Vec<GraphBlock>,
    insts: Vec<GraphInst>,
}

/// One whole pass over the graph per call: a caller in a loop pays `O(calls x insts)`.
fn position_of(graph: &SsaGraph, at: InstId) -> usize {
    graph.insts.iter().position(|inst| inst.id == at).unwrap_or(0)
}

/// A pass over one block's own list: per block, `O(I)` in all.
fn block_len(block: &GraphBlock) -> usize {
    block.insts.iter().count()
}

fn per_call(graph: &SsaGraph, calls: &[InstId]) -> usize {
    let mut total = 0;
    for call in calls.iter() {
        total += graph.insts.iter().filter(|inst| inst.id == *call).count();
        let seen = vec![false; graph.insts.len()];
        total += seen.len();
    }
    total + calls.iter().map(|call| position_of(graph, *call)).sum::<usize>()
}

fn per_block(graph: &SsaGraph) -> usize {
    let mut total = 0;
    for block in graph.blocks.iter() {
        for inst in block.insts.iter() {
            total += inst.0 as usize;
        }
        total += block_len(block) + block.insts[..1].iter().count();
    }
    total
}

/// The shape of D381's parent (8e9b6edc1^): a list of tails searched per value.
fn handed_to_tails(graph: &SsaGraph, calls: &[GraphInst]) -> usize {
    let tails = (calls.iter()).map(|call| call.id).collect::<Vec<_>>();
    (graph.insts.iter())
        .filter(|inst| (tails.iter()).any(|tail| *tail == inst.id))
        .count()
}

fn ids(graph: &SsaGraph) -> impl Iterator<Item = InstId> + '_ {
    graph.insts.iter().map(|inst| inst.id)
}

/// The same through an opaque iterator.
fn handed_through_opaque(graph: &SsaGraph, calls: &[GraphInst]) -> usize {
    let tails = (calls.iter()).map(|call| call.id).collect::<Vec<_>>();
    ids(graph).filter(|id| (tails.iter()).any(|tail| tail == id)).count()
}

fn keyed(graph: &SsaGraph, entry: u64) -> usize {
    let mut last = BTreeMap::<u64, usize>::new();
    for block in graph.blocks.iter() {
        last.insert(block.addr, block.insts.len());
    }
    let mut by_function = BTreeMap::<u64, usize>::new();
    by_function.insert(entry, 1);
    last.len() + by_function.len()
}

fn main() {
    let graph = SsaGraph {
        blocks: vec![GraphBlock {
            addr: 0x1000,
            insts: vec![InstId(0)],
        }],
        insts: vec![GraphInst { id: InstId(0) }],
    };
    let _ = per_call(&graph, &[InstId(0)]) + per_block(&graph) + keyed(&graph, 0x1000)
        + handed_to_tails(&graph, &[])
        + handed_through_opaque(&graph, &[]);
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_scan_per_item() {
        let graph = super::SsaGraph { blocks: Vec::new(), insts: Vec::new() };
        for _ in 0..2 {
            let _ = graph.insts.iter().count();
        }
    }
}
