//! Dominator-tree placement, `doc/adr-structure-dominator-tree.md` §4: every block is written once,
//! and every edge once; the certificate in `certify.rs` says the text is the machine's graph.

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;

use r2ssa::domtree::DomTree;
use r2ssa::natural_loops::NaturalLoop;

use super::order::WriteOrder;

/// Where every block and every edge of a function goes, decided before any
/// text is written.
pub(crate) struct Placement<'f> {
    entry: u64,
    /// The function's own dominator tree; placement computes none.
    dom: &'f DomTree,
    rpo: FxHashMap<u64, usize>,
    /// The function's natural loops, outermost first.
    loops: Vec<&'f NaturalLoop>,
    /// The loops containing each block, outermost first.
    loops_of: FxHashMap<u64, Vec<usize>>,
    header_of: FxHashMap<u64, usize>,
    /// Blocks with two or more forward in-edges.
    merge: BTreeSet<u64>,
    /// Merge blocks written in each block's region, in reverse postorder.
    merge_children: FxHashMap<u64, Vec<u64>>,
    /// Blocks written after each loop, in reverse postorder.
    exits: FxHashMap<usize, Vec<u64>>,
    /// Exit blocks written where their one edge leaves the loop, not after it.
    inlined: BTreeSet<u64>,
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
        let rpo: FxHashMap<u64, usize> = cfg
            .reverse_postorder()
            .into_iter()
            .enumerate()
            .map(|(index, addr)| (addr, index))
            .collect();
        // Blocks the entry reaches; an unreachable block has no dominator and
        // no place.
        let placed_set: BTreeSet<u64> = cfg
            .block_addrs()
            .filter(|addr| is_placed(dom, entry, *addr))
            .collect();
        let placed = |addr: u64| placed_set.contains(&addr);

        let loops = natural_loops.outermost_first();
        let header_of: FxHashMap<u64, usize> = loops
            .iter()
            .enumerate()
            .map(|(index, l)| (l.header, index))
            .collect();
        let mut loops_of = FxHashMap::<u64, Vec<usize>>::default();
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
                .filter(|pred| placed(*pred) && !dom.is_back_edge(*pred, addr))
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
            merge_children: FxHashMap::default(),
            exits: FxHashMap::default(),
            inlined: BTreeSet::new(),
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
        let order = WriteOrder::current();
        for list in placement.merge_children.values_mut() {
            by_rpo(list);
            order.merges(list);
        }
        for list in placement.exits.values_mut() {
            by_rpo(list);
            order.exits(list);
        }
        if order.inlines_exits() {
            placement.inline_exits(&closed_subtrees(cfg, dom, &placed_set));
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
        if self.dom.is_back_edge(from, to) {
            return if self.innermost_loop(from) == self.header_of.get(&to).copied() {
                EdgeShape::Continue
            } else {
                EdgeShape::Goto
            };
        }
        if self.inlines(from, to) {
            EdgeShape::Inline
        } else {
            EdgeShape::Goto
        }
    }

    /// Whether `to` is written where the edge from `from` reaches it: its only forward way in,
    /// and no loop left, or a loop left by a block that [`Self::inline_exits`] kept in.
    fn inlines(&self, from: u64, to: u64) -> bool {
        self.dom.idom(to) == Some(from)
            && !self.merge.contains(&to)
            && (self.exit_of(from, to).is_none() || self.inlined.contains(&to))
    }

    /// An exit with one way in and a closed subtree goes where its edge leaves, unless `break`
    /// reaches it as the first exit of one loop (ADR §4). `O(exits)`.
    fn inline_exits(&mut self, closed: &FxHashSet<u64>) {
        let loops = self.exits.keys().copied().collect::<Vec<_>>();
        for index in loops {
            let mut broken_to = false;
            let listed = std::mem::take(self.exits.entry(index).or_default());
            let (kept, inlined): (Vec<u64>, Vec<u64>) = (listed.into_iter())
                .partition(|exit| self.stays_after(index, *exit, closed, &mut broken_to));
            self.inlined.extend(inlined);
            self.exits.insert(index, kept);
        }
    }

    /// Whether `exit` stays after loop `index`: it has a second way in, or a subtree an edge
    /// leaves, or `break` reaches it as the first such exit of the one loop its edge leaves.
    fn stays_after(
        &self,
        index: usize,
        exit: u64,
        closed: &FxHashSet<u64>,
        broken: &mut bool,
    ) -> bool {
        let sole = !self.merge.contains(&exit) && closed.contains(&exit);
        let one_level =
            (self.dom.idom(exit)).is_some_and(|from| self.innermost_loop(from) == Some(index));
        let stays = !sole || (one_level && !*broken);
        *broken |= stays;
        stays
    }
}

/// Whether the entry reaches `addr`: only a reached block has a place.
pub(crate) fn is_placed(dom: &DomTree, entry: u64, addr: u64) -> bool {
    addr == entry || dom.idom(addr).is_some()
}

/// The placed blocks in the CFG's reverse postorder, which is the order every verdict is spelled in
/// (`render::spelled`): a block comes after the blocks that dominate it. `O(B)`.
pub(crate) fn placed_in_order(function: &r2ssa::SSAFunction) -> Vec<u64> {
    let (dom, root) = (function.domtree(), function.root());
    let order = (function.block_addrs().iter().copied())
        .filter(|addr| is_placed(dom, root, *addr))
        .collect::<Vec<_>>();
    debug_assert!(
        order.iter().copied().eq(function
            .cfg()
            .reverse_postorder()
            .into_iter()
            .filter(|addr| is_placed(dom, root, *addr))),
        "the SSA function's blocks are the CFG's reverse postorder"
    );
    order
}

/// The blocks whose dominator subtree no edge leaves: the extremes of the successors' preorder
/// positions over the subtree lie in its interval. `O(B + E)`.
fn closed_subtrees(cfg: &r2ssa::cfg::CFG, dom: &DomTree, placed: &BTreeSet<u64>) -> FxHashSet<u64> {
    let order = dom.preorder();
    let position: FxHashMap<u64, usize> =
        order.iter().enumerate().map(|(at, b)| (*b, at)).collect();
    let mut last = (0..order.len()).collect::<Vec<_>>();
    let mut lowest = last.clone();
    let mut highest = last.clone();
    for (at, block) in order.iter().enumerate() {
        for to in cfg.successors(*block) {
            if let Some(to) = placed.contains(&to).then(|| position[&to]) {
                lowest[at] = lowest[at].min(to);
                highest[at] = highest[at].max(to);
            }
        }
    }
    for (at, block) in order.iter().enumerate().rev() {
        let Some(parent) = dom.idom(*block).map(|parent| position[&parent]) else {
            continue;
        };
        last[parent] = last[parent].max(last[at]);
        lowest[parent] = lowest[parent].min(lowest[at]);
        highest[parent] = highest[parent].max(highest[at]);
    }
    (order.iter().enumerate())
        .filter(|(at, _)| lowest[*at] >= *at && highest[*at] <= last[*at])
        .map(|(_, block)| *block)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeShape {
    /// The target's text follows here.
    Inline,
    Continue,
    Goto,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::support::{branch, cfg, cond_branch};
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::natural_loops::NaturalLoops;

    const RETURN: BlockTerminator = BlockTerminator::Return;

    /// Run `check` on the placement of `cfg`.
    fn placed(cfg: &CFG, check: impl FnOnce(&Placement<'_>)) {
        let dom = DomTree::compute(cfg);
        let loops = NaturalLoops::compute(cfg, &dom);
        check(&Placement::compute(cfg, &dom, &loops, cfg.entry));
    }

    /// A loop 0x20/0x30 that leaves for the returns 0x40 (from its header) and 0x50 (from 0x30).
    fn two_exits() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, RETURN),
                (0x50, RETURN),
            ],
        )
    }

    /// The two exits of [`two_exits`] by reverse postorder: the one after the loop, then the other.
    fn by_rpo(placement: &Placement<'_>) -> (u64, u64) {
        let first = [0x40, 0x50]
            .into_iter()
            .min_by_key(|exit| placement.rpo_of(*exit))
            .expect("two exits");
        (first, 0x40 + 0x50 - first)
    }

    #[test]
    fn the_exit_after_the_loop_stays_there_and_the_other_is_written_where_its_edge_leaves() {
        placed(&two_exits(), |placement| {
            let (after, inside) = by_rpo(placement);
            let from = |exit| if exit == 0x40 { 0x20 } else { 0x30 };
            assert_eq!(placement.edge(from(after), after), EdgeShape::Goto);
            assert_eq!(placement.edge(from(inside), inside), EdgeShape::Inline);
            assert_eq!(placement.exits_of(0), [after]);
            assert!(!placement.labelled().contains(&inside));
        });
    }

    #[test]
    fn a_loop_with_one_exit_keeps_it_after_the_loop() {
        let one = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x20, 0x40)),
                (0x40, RETURN),
            ],
        );
        placed(&one, |placement| {
            assert_eq!(placement.edge(0x20, 0x40), EdgeShape::Goto);
            assert_eq!(placement.exits_of(0), [0x40]);
        });
    }

    #[test]
    fn an_exit_with_a_second_way_in_stays_after_the_loop() {
        // 0x40 and 0x50 both go on to the return 0x60: 0x50 has one way in, but its subtree is
        // not closed, and 0x60 has two ways in.
        let merging = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, branch(0x60)),
                (0x50, branch(0x60)),
                (0x60, RETURN),
            ],
        );
        placed(&merging, |placement| {
            assert_eq!(placement.exits_of(0), [0x40, 0x50, 0x60]);
            assert_eq!(placement.edge(0x30, 0x50), EdgeShape::Goto);
            assert!(placement.labelled().contains(&0x50));
        });
    }

    #[test]
    fn a_subtree_is_closed_when_no_edge_leaves_it() {
        // 0x50 branches to the return 0x80 or to the exit 0x40, which is not below it; 0x30's back
        // edge to the header leaves its subtree; the root and the header's subtree hold every edge.
        let leaving = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, RETURN),
                (0x50, cond_branch(0x80, 0x40)),
                (0x80, RETURN),
            ],
        );
        let dom = DomTree::compute(&leaving);
        let placed = leaving.block_addrs().collect::<BTreeSet<_>>();
        let closed = closed_subtrees(&leaving, &dom, &placed);
        assert_eq!(
            closed.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([0x10, 0x20, 0x40, 0x80])
        );
    }

    #[test]
    fn a_closed_subtree_is_written_whole_where_the_edge_leaves() {
        // The second exit branches to two returns of its own.
        let whole = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, RETURN),
                (0x50, cond_branch(0x80, 0x90)),
                (0x80, RETURN),
                (0x90, RETURN),
            ],
        );
        placed(&whole, |placement| {
            let leaving = [(0x30, 0x50), (0x50, 0x80), (0x50, 0x90)];
            for (from, to) in leaving {
                assert_eq!(
                    placement.edge(from, to),
                    EdgeShape::Inline,
                    "{from:#x} {to:#x}"
                );
            }
            assert_eq!(placement.exits_of(0), [0x40]);
        });
    }

    #[test]
    fn an_exit_leaving_two_loops_is_written_where_it_leaves_even_when_it_is_the_first() {
        // 0x30 heads the inner loop {0x30, 0x35} inside the outer loop {0x20, 0x30, 0x35, 0x38};
        // 0x60 leaves the outer loop from its header, 0x70 leaves both from the inner header.
        let nested = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x60)),
                (0x30, cond_branch(0x35, 0x70)),
                (0x35, cond_branch(0x30, 0x38)),
                (0x38, branch(0x20)),
                (0x60, RETURN),
                (0x70, RETURN),
            ],
        );
        placed(&nested, |placement| {
            assert_eq!(placement.edge(0x30, 0x70), EdgeShape::Inline);
            assert_eq!(placement.edge(0x20, 0x60), EdgeShape::Goto);
            assert!(!placement.labelled().contains(&0x70));
        });
    }
}

#[cfg(all(test, feature = "placement_mutants"))]
mod orders {
    use super::*;
    use crate::placement_mutants::{WriteOrder, with_write_order};
    use crate::structure::support::{branch, cfg, cond_branch};
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::natural_loops::NaturalLoops;

    const RETURN: BlockTerminator = BlockTerminator::Return;

    /// Run `check` on the placement of `cfg` written in `order`.
    fn under(order: WriteOrder, cfg: &CFG, check: impl FnOnce(&Placement<'_>)) {
        let dom = DomTree::compute(cfg);
        let loops = NaturalLoops::compute(cfg, &dom);
        with_write_order(order, || {
            check(&Placement::compute(cfg, &dom, &loops, cfg.entry));
        });
    }

    /// A loop 0x20/0x30 leaving for the returns 0x40 (from its header) and 0x50 (from 0x30), which both
    /// go on to the return 0x60: the loop's exits are 0x40, 0x50 and 0x60.
    fn three_exits() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, branch(0x60)),
                (0x50, branch(0x60)),
                (0x60, RETURN),
            ],
        )
    }

    /// An entry that branches two ways to two blocks that both go to 0x40 and 0x50, which both go to 0x60:
    /// the entry's region holds the merges 0x40, 0x50 and 0x60.
    fn three_merges() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, cond_branch(0x40, 0x50)),
                (0x30, cond_branch(0x40, 0x50)),
                (0x40, branch(0x60)),
                (0x50, branch(0x60)),
                (0x60, RETURN),
            ],
        )
    }

    #[test]
    fn keeping_the_exits_inlines_none() {
        let loop_exits = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x40, RETURN),
                (0x50, RETURN),
            ],
        );
        under(WriteOrder::Natural, &loop_exits, |placement| {
            assert_eq!(placement.exits_of(0).len(), 1);
            assert!(placement.inlined.len() == 1 && placement.labelled().len() == 1);
        });
        under(WriteOrder::KeepExits, &loop_exits, |placement| {
            assert_eq!(placement.exits_of(0), [0x40, 0x50]);
            assert!(placement.inlined.is_empty());
            assert_eq!(placement.labelled(), &BTreeSet::from([0x40, 0x50]));
        });
    }

    #[test]
    fn reversing_the_exits_reverses_the_exits_of_each_loop() {
        under(WriteOrder::Natural, &three_exits(), |placement| {
            assert_eq!(placement.exits_of(0), [0x40, 0x50, 0x60]);
        });
        under(WriteOrder::ExitsReversed, &three_exits(), |placement| {
            assert_eq!(placement.exits_of(0), [0x60, 0x50, 0x40]);
        });
    }

    #[test]
    fn reversing_the_merges_reverses_the_merges_of_each_region() {
        let natural = {
            let mut found = Vec::new();
            under(WriteOrder::Natural, &three_merges(), |placement| {
                found = placement.merges_in(0x10).to_vec();
                assert_eq!(found.len(), 3);
                assert!(
                    found
                        .windows(2)
                        .all(|pair| placement.rpo_of(pair[0]) < placement.rpo_of(pair[1]))
                );
            });
            found
        };
        let reversed = natural.iter().rev().copied().collect::<Vec<_>>();
        under(WriteOrder::MergesReversed, &three_merges(), |placement| {
            assert_eq!(placement.merges_in(0x10), reversed);
        });
    }

    /// The exits of the first loop and the merges of the entry's region, written in `order`.
    fn lists(order: WriteOrder, cfg: &CFG) -> [Vec<u64>; 2] {
        let mut found = [Vec::new(), Vec::new()];
        under(order, cfg, |p| {
            found = [p.exits_of(0).to_vec(), p.merges_in(0x10).to_vec()];
        });
        found
    }

    #[test]
    fn only_the_order_asked_for_moves_a_placement() {
        // Each order moves the one list it names and leaves the other as it was.
        for graph in [three_exits(), three_merges()] {
            let natural = lists(WriteOrder::Natural, &graph);
            assert_eq!(lists(WriteOrder::MergesReversed, &graph)[0], natural[0]);
            assert_eq!(lists(WriteOrder::ExitsReversed, &graph)[1], natural[1]);
            assert_eq!(lists(WriteOrder::KeepExits, &graph)[1], natural[1]);
        }
    }

    #[test]
    fn a_write_order_holds_only_inside_its_scope() {
        with_write_order(WriteOrder::ExitsReversed, || {
            with_write_order(WriteOrder::KeepExits, || {
                assert_eq!(WriteOrder::current(), WriteOrder::KeepExits);
            });
            assert_eq!(WriteOrder::current(), WriteOrder::ExitsReversed);
        });
        assert_eq!(WriteOrder::current(), WriteOrder::Natural);
    }
}
