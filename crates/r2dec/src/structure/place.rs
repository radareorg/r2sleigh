//! Dominator-tree placement, `doc/adr-structure-dominator-tree.md` §4.
//!
//! Every block is written once, in the region of its immediate dominator or
//! in the exit list of the outermost loop it leaves; every edge is written
//! once, as adjacency, an `if` or `switch` arm, `continue`, or `goto`. The
//! shape is total for any CFG, and the certificate in `certify.rs` is what
//! says the text it produced is the machine's graph.

use std::collections::{BTreeSet, HashMap};

use r2ssa::domtree::DomTree;
use r2ssa::natural_loops::NaturalLoop;

/// Where every block and every edge of a function goes, decided before any
/// text is written.
pub(crate) struct Placement<'f> {
    entry: u64,
    /// The function's own dominator tree; placement computes none.
    dom: &'f DomTree,
    rpo: HashMap<u64, usize>,
    /// The function's natural loops, outermost first.
    loops: Vec<&'f NaturalLoop>,
    /// The loops containing each block, outermost first.
    loops_of: HashMap<u64, Vec<usize>>,
    header_of: HashMap<u64, usize>,
    /// Blocks with two or more forward in-edges.
    merge: BTreeSet<u64>,
    /// Merge blocks written in each block's region, in reverse postorder.
    merge_children: HashMap<u64, Vec<u64>>,
    /// Blocks written after each loop, in reverse postorder.
    exits: HashMap<usize, Vec<u64>>,
    /// Blocks some edge reaches by `goto`.
    labelled: BTreeSet<u64>,
}

impl<'f> Placement<'f> {
    /// The placement of a function's blocks, from its CFG, dominator tree and loops alone.
    pub(crate) fn compute(
        cfg: &'f r2ssa::cfg::CFG,
        dom: &'f DomTree,
        natural_loops: &'f r2ssa::natural_loops::NaturalLoops,
        entry: u64,
    ) -> Self {
        let rpo: HashMap<u64, usize> = cfg
            .reverse_postorder()
            .into_iter()
            .enumerate()
            .map(|(index, addr)| (addr, index))
            .collect();
        // Blocks the entry reaches; an unreachable block has no dominator and
        // no place.
        let placed_set: BTreeSet<u64> = cfg
            .block_addrs()
            .filter(|addr| *addr == entry || dom.idom(*addr).is_some())
            .collect();
        let placed = |addr: u64| placed_set.contains(&addr);
        let is_back_edge = |from: u64, to: u64| dom.dominates(to, from);

        let loops = natural_loops.outermost_first();
        let header_of: HashMap<u64, usize> = loops
            .iter()
            .enumerate()
            .map(|(index, l)| (l.header, index))
            .collect();
        let mut loops_of = HashMap::<u64, Vec<usize>>::new();
        for (index, natural) in loops.iter().enumerate() {
            for block in &natural.body {
                loops_of.entry(*block).or_default().push(index);
            }
        }

        let mut merge = BTreeSet::new();
        for addr in cfg.block_addrs() {
            if !placed(addr) {
                continue;
            }
            let forward = cfg
                .predecessors(addr)
                .into_iter()
                .filter(|pred| placed(*pred) && !is_back_edge(*pred, addr))
                .count();
            if forward >= 2 {
                merge.insert(addr);
            }
        }

        let mut placement = Self {
            entry,
            dom,
            rpo,
            loops,
            loops_of,
            header_of,
            merge,
            merge_children: HashMap::new(),
            exits: HashMap::new(),
            labelled: BTreeSet::new(),
        };
        // Anchors: a block leaving a loop its dominator is in goes after the
        // outermost such loop; a merge goes in its dominator's region.
        for addr in cfg.block_addrs() {
            if addr == entry || !placed(addr) {
                continue;
            }
            let Some(idom) = placement.dom.idom(addr) else {
                continue;
            };
            match placement.exit_of(idom, addr) {
                Some(index) => placement.exits.entry(index).or_default().push(addr),
                None if placement.merge.contains(&addr) => {
                    placement.merge_children.entry(idom).or_default().push(addr);
                }
                None => {}
            }
        }
        let rpo = placement.rpo.clone();
        let by_rpo = |list: &mut Vec<u64>| list.sort_by_key(|addr| rpo.get(addr).copied());
        for list in placement.merge_children.values_mut() {
            by_rpo(list);
        }
        for list in placement.exits.values_mut() {
            by_rpo(list);
        }
        for from in cfg.block_addrs() {
            if !placed(from) {
                continue;
            }
            for to in cfg.successors(from) {
                if placed(to) && matches!(placement.edge(from, to), EdgeShape::Goto) {
                    placement.labelled.insert(to);
                }
            }
        }
        placement
    }

    pub(crate) const fn entry(&self) -> u64 {
        self.entry
    }

    /// Blocks some edge reaches by `goto`, in address order.
    pub(crate) fn labelled(&self) -> &BTreeSet<u64> {
        &self.labelled
    }

    /// The loop `addr` heads, by its index in [`Self::loops`].
    pub(crate) fn loop_headed_by(&self, addr: u64) -> Option<usize> {
        self.header_of.get(&addr).copied()
    }

    /// The blocks written after one loop, in reverse postorder.
    pub(crate) fn exits_of(&self, index: usize) -> &[u64] {
        self.exits.get(&index).map_or(&[], Vec::as_slice)
    }

    /// The merges written in one block's region, in reverse postorder.
    pub(crate) fn merges_in(&self, addr: u64) -> &[u64] {
        self.merge_children.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// The block's position in reverse postorder.
    pub(crate) fn rpo_of(&self, addr: u64) -> Option<usize> {
        self.rpo.get(&addr).copied()
    }

    /// The outermost loop containing `from` and not `to`, if any.
    fn exit_of(&self, from: u64, to: u64) -> Option<usize> {
        self.loops_of
            .get(&from)?
            .iter()
            .copied()
            .find(|index| !self.loops[*index].body.contains(&to))
    }

    fn innermost_loop(&self, block: u64) -> Option<usize> {
        self.loops_of
            .get(&block)
            .and_then(|list| list.last().copied())
    }

    /// How the edge `from -> to` is written.
    pub(crate) fn edge(&self, from: u64, to: u64) -> EdgeShape {
        if self.dom.dominates(to, from) {
            return if self.innermost_loop(from) == self.header_of.get(&to).copied() {
                EdgeShape::Continue
            } else {
                EdgeShape::Goto
            };
        }
        if self.dom.idom(to) == Some(from)
            && !self.merge.contains(&to)
            && self.exit_of(from, to).is_none()
        {
            EdgeShape::Inline
        } else {
            EdgeShape::Goto
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeShape {
    /// The target's text follows here.
    Inline,
    Continue,
    Goto,
}
