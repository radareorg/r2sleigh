//! The natural loops of a function's control graph, computed once.
//!
//! An edge `latch -> header` is a back edge when `header` dominates `latch`.
//! A header's loop is the header with every block that reaches one of its
//! latches without passing through the header; every such block the entry
//! reaches is dominated by the header (a path around the header to it and on
//! to the latch would reach the latch around the header). Loops are merged by
//! header, so two loops are disjoint or one holds the other.
//!
//! Cost: one pass over the edges for the back edges, then one backward walk
//! per header, so `O(E + sum of loop sizes)`.

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::CFG;
use crate::domtree::DomTree;

/// One natural loop, merged over every back edge into its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaturalLoop {
    pub header: u64,
    /// The blocks that branch back to the header.
    pub latches: BTreeSet<u64>,
    /// The header and every block of the loop.
    pub body: BTreeSet<u64>,
}

/// Every natural loop of one control graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NaturalLoops {
    by_header: BTreeMap<u64, NaturalLoop>,
}

impl NaturalLoops {
    pub fn compute(cfg: &CFG, domtree: &DomTree) -> Self {
        let reached = |block: u64| block == domtree.entry || domtree.idom(block).is_some();
        let mut by_header = BTreeMap::<u64, NaturalLoop>::new();
        for latch in cfg.block_addrs().filter(|block| reached(*block)) {
            for header in cfg.successors(latch) {
                if domtree.dominates(header, latch) {
                    by_header
                        .entry(header)
                        .or_insert_with(|| NaturalLoop {
                            header,
                            latches: BTreeSet::new(),
                            body: BTreeSet::from([header]),
                        })
                        .latches
                        .insert(latch);
                }
            }
        }
        for natural in by_header.values_mut() {
            let mut pending = natural.latches.iter().copied().collect::<Vec<_>>();
            while let Some(block) = pending.pop() {
                if !natural.body.insert(block) {
                    continue;
                }
                pending.extend(
                    cfg.predecessors(block)
                        .into_iter()
                        .filter(|pred| reached(*pred) && !natural.body.contains(pred)),
                );
            }
        }
        Self { by_header }
    }

    /// The loop headed by `header`.
    pub fn get(&self, header: u64) -> Option<&NaturalLoop> {
        self.by_header.get(&header)
    }

    /// Every loop, by header address.
    pub fn iter(&self) -> impl Iterator<Item = &NaturalLoop> {
        self.by_header.values()
    }

    /// Every loop, outermost first: two loops are disjoint or nested, so a
    /// loop is larger than every loop it holds; ties by header address.
    pub fn outermost_first(&self) -> Vec<&NaturalLoop> {
        let mut loops = self.iter().collect::<Vec<_>>();
        loops.sort_by(|a, b| {
            b.body
                .len()
                .cmp(&a.body.len())
                .then(a.header.cmp(&b.header))
        });
        loops
    }

    pub fn len(&self) -> usize {
        self.by_header.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_header.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn varnode(space: SpaceId, offset: u64, size: u32) -> Varnode {
        Varnode {
            space,
            offset,
            size,
        }
    }

    fn block(addr: u64, op: R2ILOp) -> R2ILBlock {
        R2ILBlock {
            addr,
            size: 4,
            ops: vec![op],
            switch_info: None,
            op_metadata: Default::default(),
        }
    }

    fn branch_if(target: u64) -> R2ILOp {
        R2ILOp::CBranch {
            target: varnode(SpaceId::Const, target, 8),
            cond: varnode(SpaceId::Const, 1, 1),
        }
    }

    fn loops_of(blocks: &[R2ILBlock]) -> NaturalLoops {
        let cfg = CFG::from_blocks(blocks).unwrap();
        NaturalLoops::compute(&cfg, &DomTree::compute(&cfg))
    }

    #[test]
    fn nested_loops_are_merged_by_header_and_ordered_outermost_first() {
        let loops = loops_of(&[
            block(0x1000, R2ILOp::Nop),
            block(0x1004, R2ILOp::Nop),
            block(0x1008, R2ILOp::Nop),
            block(0x100c, branch_if(0x1008)),
            block(0x1010, branch_if(0x1004)),
            block(
                0x1014,
                R2ILOp::Return {
                    target: varnode(SpaceId::Ram, 0, 8),
                },
            ),
        ]);
        let order = loops.outermost_first();
        assert_eq!(
            order.iter().map(|l| l.header).collect::<Vec<_>>(),
            [0x1004, 0x1008]
        );
        assert_eq!(order[0].latches, BTreeSet::from([0x1010]));
        assert_eq!(
            order[0].body,
            BTreeSet::from([0x1004, 0x1008, 0x100c, 0x1010])
        );
        assert_eq!(order[1].latches, BTreeSet::from([0x100c]));
        assert_eq!(order[1].body, BTreeSet::from([0x1008, 0x100c]));
    }

    #[test]
    fn a_cycle_entered_at_two_blocks_is_no_natural_loop() {
        // 0x2004 and 0x2008 branch to each other, and the entry reaches both.
        let loops = loops_of(&[
            block(0x2000, branch_if(0x2008)),
            block(0x2004, branch_if(0x200c)),
            block(
                0x2008,
                R2ILOp::Branch {
                    target: varnode(SpaceId::Const, 0x2004, 8),
                },
            ),
            block(
                0x200c,
                R2ILOp::Return {
                    target: varnode(SpaceId::Ram, 0, 8),
                },
            ),
        ]);
        assert!(loops.is_empty());
    }
}
