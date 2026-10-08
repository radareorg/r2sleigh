//! Dominator trees of control flow graphs.
//!
//! The tree is Cooper, Harvey and Kennedy's ("A Simple, Fast Dominance
//! Algorithm", 2001): the blocks the entry reaches are numbered in reverse
//! postorder, each block's immediate dominator is the intersection of its
//! predecessors' in the tree built so far, and rounds repeat until one changes
//! nothing. Dominance is then answered in `O(1)` from the tree's preorder
//! intervals, and the dominance frontiers are Cytron et al.'s, found by the
//! same paper's walk from each predecessor of a merge up to the merge's
//! immediate dominator.

use std::collections::{HashMap, HashSet};

use crate::cfg::CFG;
use crate::control::{SsaExecutionStopReason, SsaWorkControl, UncheckedSsaWorkControl};
use crate::dense::{Csr, DenseId};

/// A block the entry reaches, by its place in reverse postorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rpo(u32);

impl DenseId for Rpo {
    fn index(self) -> usize {
        self.0 as usize
    }

    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 blocks"))
    }
}

const ENTRY: Rpo = Rpo(0);

/// Dominator tree for a CFG.
///
/// The dominator tree captures the dominance relationship between blocks:
/// block A dominates block B if every path from the entry to B goes through A.
/// A block the entry does not reach has no dominator, dominates only itself,
/// and is dominated only by itself.
#[derive(Debug, Clone)]
pub struct DomTree {
    /// The entry block address.
    pub entry: u64,
    /// Each reachable block's number.
    number: HashMap<u64, Rpo>,
    /// The reachable blocks, in reverse postorder.
    blocks: Vec<u64>,
    /// Each reachable block's immediate dominator; the entry's is itself.
    idom: Vec<Rpo>,
    /// Each reachable block's children in the tree, in address order.
    children: Vec<Vec<u64>>,
    /// Each reachable block's depth in the tree; the entry's is zero.
    depth: Vec<u32>,
    /// Each reachable block's place in a preorder walk of the tree, and the
    /// last place in its subtree: `a` dominates `b` exactly when `b`'s place
    /// lies in `a`'s interval.
    pre: Vec<u32>,
    last: Vec<u32>,
    /// Each block's dominance frontier, in address order. A block the entry
    /// does not reach has the merges it feeds directly: what it defines
    /// arrives there along that edge.
    frontier: HashMap<u64, Vec<u64>>,
}

impl DomTree {
    /// Compute the dominator tree for a CFG.
    pub fn compute(cfg: &CFG) -> Self {
        Self::compute_with_control(cfg, &UncheckedSsaWorkControl)
            .expect("unchecked dominator construction cannot stop")
    }

    /// Compute a dominator tree while polling iterative worklists.
    pub fn compute_with_control<C: SsaWorkControl + ?Sized>(
        cfg: &CFG,
        control: &C,
    ) -> Result<Self, SsaExecutionStopReason> {
        control.poll()?;
        Self::of_graph(
            cfg.entry,
            cfg.reverse_postorder(),
            cfg.block_addrs().collect(),
            |block| cfg.predecessors(block),
            control,
        )
    }

    /// The tree of a graph given as its entry, the reverse postorder of the
    /// blocks the entry reaches, every block, and each block's predecessors
    /// in address order.
    fn of_graph<C: SsaWorkControl + ?Sized>(
        entry: u64,
        blocks: Vec<u64>,
        every_block: Vec<u64>,
        predecessors: impl Fn(u64) -> Vec<u64>,
        control: &C,
    ) -> Result<Self, SsaExecutionStopReason> {
        let n = blocks.len();
        let number = blocks
            .iter()
            .enumerate()
            .map(|(index, &block)| (block, Rpo::from_index(index)))
            .collect::<HashMap<_, _>>();
        // Read once: the rounds below revisit every edge.
        let mut preds_of = Vec::with_capacity(every_block.len());
        for block in every_block {
            control.poll()?;
            preds_of.push((block, predecessors(block)));
        }
        let reached_preds = Csr::from_pairs(
            n,
            preds_of.iter().flat_map(|(block, preds)| {
                let number = &number;
                let to = number.get(block).copied();
                preds
                    .iter()
                    .filter_map(move |pred| Some((to?, *number.get(pred)?)))
            }),
        );

        // Each round sets a block's dominator to the intersection of its
        // processed predecessors'. Read as dominator sets (a block's path to
        // the entry), this is the iterative data-flow solution, whose sets
        // only shrink (Cooper et al., section 3); n sets of at most n blocks
        // shrink at most n^2 times, so the rounds end. Every reached block but
        // the entry has a predecessor numbered before it, its parent in the
        // walk that numbered them, so the first round sets every block.
        let mut idom = vec![None; n];
        if n > 0 {
            idom[0] = Some(ENTRY);
        }
        loop {
            control.poll()?;
            let mut changed = false;
            for index in 1..n {
                let block = Rpo::from_index(index);
                let mut meet = None;
                for &pred in reached_preds.get(block) {
                    if idom[pred.index()].is_none() {
                        continue;
                    }
                    meet = Some(match meet {
                        None => pred,
                        Some(meet) => intersect(&idom, pred, meet),
                    });
                }
                if meet.is_some() && idom[index] != meet {
                    idom[index] = meet;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let idom = idom
            .into_iter()
            .map(|idom| idom.expect("every reached block has a dominator after the first round"))
            .collect::<Vec<_>>();

        let mut children = vec![Vec::new(); n];
        for (index, parent) in idom.iter().enumerate().skip(1) {
            children[parent.index()].push(index);
        }
        for children in &mut children {
            children.sort_unstable_by_key(|child| blocks[*child]);
        }

        let (pre, last, depth) = number_the_tree(&idom, &children, control)?;
        let frontier = frontiers(&number, &blocks, &idom, &preds_of, control)?;

        Ok(Self {
            entry,
            number,
            children: children
                .into_iter()
                .map(|children| children.into_iter().map(|child| blocks[child]).collect())
                .collect(),
            blocks,
            idom,
            depth,
            pre,
            last,
            frontier,
        })
    }

    /// Get the immediate dominator of a block.
    pub fn idom(&self, block: u64) -> Option<u64> {
        let node = self.number.get(&block)?.index();
        let idom = self.blocks[self.idom[node].index()];
        (idom != block).then_some(idom)
    }

    /// Get the children of a block in the dominator tree.
    pub fn children(&self, block: u64) -> &[u64] {
        self.number
            .get(&block)
            .map_or(&[], |node| self.children[node.index()].as_slice())
    }

    /// Get the dominance frontier of a block, in address order.
    pub fn frontier(&self, block: u64) -> impl Iterator<Item = u64> + '_ {
        self.frontier.get(&block).into_iter().flatten().copied()
    }

    /// Get the depth of a block in the dominator tree.
    pub fn depth(&self, block: u64) -> usize {
        self.number
            .get(&block)
            .map_or(0, |node| self.depth[node.index()] as usize)
    }

    /// Check if block A dominates block B, in `O(1)`.
    pub fn dominates(&self, a: u64, b: u64) -> bool {
        if a == b {
            return true;
        }
        let (Some(a), Some(b)) = (self.number.get(&a), self.number.get(&b)) else {
            return false;
        };
        let (a, b) = (a.index(), b.index());
        self.pre[a] <= self.pre[b] && self.pre[b] <= self.last[a]
    }

    /// Check if block A strictly dominates block B (A dominates B and A != B).
    pub fn strictly_dominates(&self, a: u64, b: u64) -> bool {
        a != b && self.dominates(a, b)
    }

    /// Iterate over the dominator tree in preorder.
    pub fn preorder(&self) -> Vec<u64> {
        let mut result = Vec::new();
        let mut stack = vec![self.entry];

        while let Some(current) = stack.pop() {
            result.push(current);
            // Push children in reverse order for correct preorder
            let children = self.children(current);
            for &child in children.iter().rev() {
                stack.push(child);
            }
        }

        result
    }

    /// Compute the iterated dominance frontier for a set of blocks.
    ///
    /// This is used for phi-node placement: we need to place phi nodes
    /// at all blocks in the iterated dominance frontier of the definition sites.
    pub fn iterated_frontier(&self, blocks: &[u64]) -> HashSet<u64> {
        self.iterated_frontier_with_control(blocks, &UncheckedSsaWorkControl)
            .expect("unchecked dominance-frontier construction cannot stop")
    }

    /// Compute an iterated dominance frontier while polling its worklist.
    pub fn iterated_frontier_with_control<C: SsaWorkControl + ?Sized>(
        &self,
        blocks: &[u64],
        control: &C,
    ) -> Result<HashSet<u64>, SsaExecutionStopReason> {
        let mut result = HashSet::new();
        let mut worklist: Vec<u64> = blocks.to_vec();
        worklist.sort_unstable_by(|a, b| b.cmp(a));
        let mut processed = HashSet::new();

        while let Some(block) = worklist.pop() {
            control.poll()?;
            if !processed.insert(block) {
                continue;
            }

            let mut frontier_blocks: Vec<u64> = self.frontier(block).collect();
            frontier_blocks.sort_unstable_by(|a, b| b.cmp(a));
            for frontier_block in frontier_blocks {
                control.poll()?;
                if result.insert(frontier_block) {
                    worklist.push(frontier_block);
                }
            }
        }

        Ok(result)
    }
}

/// Each node's preorder place in the tree, children in address order, the
/// last place in its subtree, and its depth.
type TreeNumbers = (Vec<u32>, Vec<u32>, Vec<u32>);

fn number_the_tree<C: SsaWorkControl + ?Sized>(
    idom: &[Rpo],
    children: &[Vec<usize>],
    control: &C,
) -> Result<TreeNumbers, SsaExecutionStopReason> {
    let n = idom.len();
    // Preorder, children in address order, with each subtree's size.
    let mut pre = vec![0u32; n];
    let mut depth = vec![0u32; n];
    let mut order = Vec::with_capacity(n);
    let mut stack = if n > 0 { vec![0usize] } else { Vec::new() };
    while let Some(node) = stack.pop() {
        control.poll()?;
        pre[node] = order.len() as u32;
        order.push(node);
        for &child in children[node].iter().rev() {
            depth[child] = depth[node] + 1;
            stack.push(child);
        }
    }
    let mut size = vec![1u32; n];
    for &node in order.iter().rev().take(n.saturating_sub(1)) {
        let parent = idom[node].index();
        size[parent] += size[node];
    }
    let last = (0..n).map(|node| pre[node] + size[node] - 1).collect();

    Ok((pre, last, depth))
}

/// Cytron et al.'s frontiers, by the walk from each predecessor of a merge
/// up to the merge's immediate dominator, each in address order.
fn frontiers<C: SsaWorkControl + ?Sized>(
    number: &HashMap<u64, Rpo>,
    blocks: &[u64],
    idom: &[Rpo],
    preds_of: &[(u64, Vec<u64>)],
    control: &C,
) -> Result<HashMap<u64, Vec<u64>>, SsaExecutionStopReason> {
    let mut frontier = HashMap::<u64, Vec<u64>>::new();
    for (merge, preds) in preds_of {
        if preds.len() < 2 {
            continue;
        }
        for &pred in preds {
            control.poll()?;
            match (number.get(&pred), number.get(merge)) {
                (Some(&runner), Some(&stop)) => {
                    let stop = idom[stop.index()];
                    let mut runner = runner;
                    while runner != stop {
                        frontier
                            .entry(blocks[runner.index()])
                            .or_default()
                            .push(*merge);
                        if runner == ENTRY {
                            break;
                        }
                        runner = idom[runner.index()];
                    }
                }
                (None, _) if pred != *merge => {
                    frontier.entry(pred).or_default().push(*merge);
                }
                // A reached block's successors are reached, and an
                // unreached block's edge to itself enters nothing new.
                _ => {}
            }
        }
    }
    for merges in frontier.values_mut() {
        merges.sort_unstable();
        merges.dedup();
    }

    Ok(frontier)
}

/// The nearest common dominator of two processed blocks: walk the one
/// numbered later up the tree until the two meet. A block's dominator is
/// numbered before it, so each step lowers a number and the walk ends at the
/// entry at the latest.
fn intersect(idom: &[Option<Rpo>], mut a: Rpo, mut b: Rpo) -> Rpo {
    let up = |node: Rpo| idom[node.index()].expect("a processed block's dominators are processed");
    while a != b {
        while a > b {
            a = up(a);
        }
        while b > a {
            b = up(b);
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn make_const(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
        }
    }

    fn make_ram(addr: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Ram,
            offset: addr,
            size,
        }
    }

    #[test]
    fn test_domtree_linear() {
        // Linear CFG: A -> B -> C
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let cfg = CFG::from_blocks(&blocks).unwrap();
        let domtree = DomTree::compute(&cfg);

        // Entry dominates all
        assert!(domtree.dominates(0x1000, 0x1000));
        assert!(domtree.dominates(0x1000, 0x1004));
        assert!(domtree.dominates(0x1000, 0x1008));

        // B dominates C
        assert!(domtree.dominates(0x1004, 0x1008));

        // C doesn't dominate A or B
        assert!(!domtree.dominates(0x1008, 0x1000));
        assert!(!domtree.dominates(0x1008, 0x1004));

        // Immediate dominators
        assert_eq!(domtree.idom(0x1004), Some(0x1000));
        assert_eq!(domtree.idom(0x1008), Some(0x1004));
    }

    #[test]
    fn test_domtree_diamond() {
        // Diamond CFG:
        //     A (0x1000)
        //    / \
        //   B   C
        //    \ /
        //     D (0x100c)
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let cfg = CFG::from_blocks(&blocks).unwrap();
        let domtree = DomTree::compute(&cfg);

        // A dominates all
        assert!(domtree.dominates(0x1000, 0x1004));
        assert!(domtree.dominates(0x1000, 0x1008));
        assert!(domtree.dominates(0x1000, 0x100c));

        // B and C don't dominate D (both paths lead to D)
        assert!(!domtree.strictly_dominates(0x1004, 0x100c));
        assert!(!domtree.strictly_dominates(0x1008, 0x100c));

        // D's immediate dominator is A
        assert_eq!(domtree.idom(0x100c), Some(0x1000));

        // Dominance frontier of B and C should include D
        assert!(domtree.frontier(0x1004).any(|x| x == 0x100c));
        assert!(domtree.frontier(0x1008).any(|x| x == 0x100c));
    }

    #[test]
    fn test_iterated_frontier() {
        // Diamond CFG
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: make_const(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let cfg = CFG::from_blocks(&blocks).unwrap();
        let domtree = DomTree::compute(&cfg);

        // If we define a variable in B and C, we need a phi at D
        let def_sites = vec![0x1004, 0x1008];
        let idf = domtree.iterated_frontier(&def_sites);
        assert!(idf.contains(&0x100c));
    }

    #[test]
    fn test_preorder() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Nop],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let cfg = CFG::from_blocks(&blocks).unwrap();
        let domtree = DomTree::compute(&cfg);

        let preorder = domtree.preorder();
        // Entry should be first
        assert_eq!(preorder[0], 0x1000);
        // All blocks should be present
        assert_eq!(preorder.len(), 3);
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// A graph over blocks `0..n` (at addresses `0x100 * i`), entered at 0,
    /// with no edge into the entry, as every CFG rooted at its entry edge is.
    fn graphs() -> impl Strategy<Value = (usize, BTreeSet<(usize, usize)>)> {
        (1usize..10).prop_flat_map(|n| {
            let edges = proptest::collection::btree_set((0..n, 1..n.max(2)), 0..(3 * n));
            (Just(n), edges).prop_map(|(n, edges)| {
                let edges = edges.into_iter().filter(|(_, to)| *to < n).collect();
                (n, edges)
            })
        })
    }

    fn addr(block: usize) -> u64 {
        0x100 * block as u64
    }

    #[derive(Debug)]
    struct Naive {
        reached: BTreeSet<usize>,
        /// Every block's dominators, by the data-flow definition.
        dom: Vec<BTreeSet<usize>>,
        preds: Vec<Vec<usize>>,
    }

    fn naive(n: usize, edges: &BTreeSet<(usize, usize)>) -> Naive {
        let succs = |b: usize| edges.iter().filter(move |(f, _)| *f == b).map(|(_, t)| *t);
        let preds = (0..n)
            .map(|b| {
                edges
                    .iter()
                    .filter(|(_, t)| *t == b)
                    .map(|(f, _)| *f)
                    .collect()
            })
            .collect::<Vec<Vec<usize>>>();
        let mut reached = BTreeSet::from([0]);
        let mut stack = vec![0];
        while let Some(b) = stack.pop() {
            for s in succs(b) {
                if reached.insert(s) {
                    stack.push(s);
                }
            }
        }
        let all = reached.clone();
        let mut dom = (0..n)
            .map(|b| {
                if b == 0 {
                    BTreeSet::from([0])
                } else {
                    all.clone()
                }
            })
            .collect::<Vec<_>>();
        loop {
            let mut changed = false;
            for b in reached.iter().copied().filter(|b| *b != 0) {
                let mut meet = all.clone();
                for p in preds[b].iter().filter(|p| reached.contains(p)) {
                    meet = meet.intersection(&dom[*p]).copied().collect();
                }
                meet.insert(b);
                if meet != dom[b] {
                    dom[b] = meet;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Naive {
            reached,
            dom,
            preds,
        }
    }

    fn tree(n: usize, edges: &BTreeSet<(usize, usize)>) -> DomTree {
        let succs = |b: usize| {
            edges
                .iter()
                .filter(move |(f, _)| *f == b)
                .map(|(_, t)| *t)
                .collect::<Vec<_>>()
        };
        // A depth-first postorder from the entry, reversed.
        let mut seen = BTreeSet::new();
        let mut post = Vec::new();
        let mut stack = vec![(0usize, false)];
        while let Some((b, done)) = stack.pop() {
            if done {
                post.push(addr(b));
                continue;
            }
            if !seen.insert(b) {
                continue;
            }
            stack.push((b, true));
            for s in succs(b).into_iter().rev() {
                stack.push((s, false));
            }
        }
        post.reverse();
        DomTree::of_graph(
            0,
            post,
            (0..n).map(addr).collect(),
            |block| {
                let b = (block / 0x100) as usize;
                edges
                    .iter()
                    .filter(|(_, t)| *t == b)
                    .map(|(f, _)| addr(*f))
                    .collect()
            },
            &UncheckedSsaWorkControl,
        )
        .unwrap()
    }

    proptest! {
        #[test]
        fn the_tree_is_the_data_flow_dominance((n, edges) in graphs()) {
            let truth = naive(n, &edges);
            let tree = tree(n, &edges);
            for a in 0..n {
                for b in 0..n {
                    let dominates = a == b
                        || (truth.reached.contains(&b) && truth.dom[b].contains(&a));
                    prop_assert_eq!(tree.dominates(addr(a), addr(b)), dominates, "{} dom {}", a, b);
                }
                // The immediate dominator: the strict dominator every other dominates.
                let idom = truth.reached.contains(&a).then(|| {
                    truth.dom[a]
                        .iter()
                        .copied()
                        .filter(|d| *d != a)
                        .find(|d| truth.dom[a].iter().all(|o| *o == a || truth.dom[*d].contains(o)))
                });
                prop_assert_eq!(tree.idom(addr(a)), idom.flatten().map(addr));
                let children = (0..n)
                    .filter(|c| tree.idom(addr(*c)) == Some(addr(a)))
                    .map(addr)
                    .collect::<Vec<_>>();
                prop_assert_eq!(tree.children(addr(a)), children.as_slice());
                let depth = if truth.reached.contains(&a) { truth.dom[a].len() - 1 } else { 0 };
                prop_assert_eq!(tree.depth(addr(a)), depth);
                // Cytron et al.'s frontier: where a's dominance ends. An
                // unreached block's is the merges it feeds.
                let frontier = (0..n)
                    .filter(|b| truth.preds[*b].len() >= 2)
                    .filter(|b| {
                        if truth.reached.contains(&a) {
                            truth.preds[*b].iter().any(|p| {
                                truth.reached.contains(p) && truth.dom[*p].contains(&a)
                            }) && !(a != *b && truth.dom[*b].contains(&a))
                        } else {
                            *b != a && truth.preds[*b].contains(&a)
                        }
                    })
                    .map(addr)
                    .collect::<Vec<_>>();
                prop_assert_eq!(tree.frontier(addr(a)).collect::<Vec<_>>(), frontier);
            }
        }
    }
}
