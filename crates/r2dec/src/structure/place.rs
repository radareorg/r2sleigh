//! Dominator-tree placement, `doc/adr-structure-dominator-tree.md` §4.
//!
//! Every block is written once, in the region of its immediate dominator or
//! in the exit list of the outermost loop it leaves; every edge is written
//! once, as adjacency, an `if` or `switch` arm, `continue`, or `goto`. The
//! shape is total for any CFG, and the certificate in `certify.rs` is what
//! says the text it produced is the machine's graph.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use r2ssa::cfg::BlockTerminator;
use r2ssa::domtree::DomTree;
use r2ssa::{SSAFunction, SSAOp};

use crate::ast::{CExpr, CStmt, SwitchCase};
use crate::structured_region::{StructuredRegionKind, StructuredRegionMarker};

use super::{ControlFlowStructureResult, ControlFlowStructurer};

/// One natural loop: the target of a back edge and everything that reaches a
/// latch without passing through it.
pub(crate) struct NaturalLoop {
    pub(crate) header: u64,
    pub(crate) body: BTreeSet<u64>,
    pub(crate) latches: BTreeSet<u64>,
}

/// Where every block and every edge of a function goes, decided before any
/// text is written.
pub(crate) struct Placement {
    entry: u64,
    dom: DomTree,
    rpo: HashMap<u64, usize>,
    loops: Vec<NaturalLoop>,
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

impl Placement {
    pub(crate) fn compute(func: &SSAFunction) -> Self {
        let cfg = func.cfg();
        let entry = func.entry;
        let dom = DomTree::compute(cfg);
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

        // Natural loops, one per header, from the back edges.
        let mut by_header = BTreeMap::<u64, NaturalLoop>::new();
        for from in cfg.block_addrs() {
            if !placed(from) {
                continue;
            }
            for to in cfg.successors(from) {
                if !is_back_edge(from, to) {
                    continue;
                }
                let entry = by_header.entry(to).or_insert_with(|| NaturalLoop {
                    header: to,
                    body: BTreeSet::from([to]),
                    latches: BTreeSet::new(),
                });
                entry.latches.insert(from);
                let mut pending = vec![from];
                while let Some(block) = pending.pop() {
                    if !entry.body.insert(block) {
                        continue;
                    }
                    pending.extend(
                        cfg.predecessors(block)
                            .into_iter()
                            .filter(|pred| placed(*pred)),
                    );
                }
            }
        }
        let mut loops: Vec<NaturalLoop> = by_header.into_values().collect();
        // Outermost first: two natural loops are disjoint or nested, so size
        // orders nesting.
        loops.sort_by(|a, b| {
            b.body
                .len()
                .cmp(&a.body.len())
                .then(a.header.cmp(&b.header))
        });
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

    pub(crate) fn loops(&self) -> &[NaturalLoop] {
        &self.loops
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

impl ControlFlowStructurer<'_, '_> {
    /// Write the whole function: the entry's region, then everything it
    /// dominates, by the placement.
    pub(crate) fn place_function(
        &mut self,
        placement: &Placement,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        for addr in placement.labelled.iter().copied().collect::<Vec<_>>() {
            self.ensure_label(addr);
        }
        self.place(placement, placement.entry)
    }

    /// One block at its position: its loop around it when it heads one, and
    /// what that loop leaves through after it.
    fn place(
        &mut self,
        placement: &Placement,
        addr: u64,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        if !self.poll() {
            return Ok(Vec::new());
        }
        let Some(index) = placement.header_of.get(&addr).copied() else {
            return Ok(vec![self.block_region(placement, addr)?]);
        };
        let body = self.block_region(placement, addr)?;
        let counted = self.certified_for_regions.remove(&addr);
        let (init, update) = match counted {
            Some(counted) => (Some(Box::new(counted.init)), Some(counted.update)),
            None => (None, None),
        };
        let mut out = vec![CStmt::structured_region(
            StructuredRegionMarker::unsealed(addr, StructuredRegionKind::Loop),
            CStmt::For {
                init,
                cond: None,
                update,
                body: Box::new(body),
            },
        )];
        for exit in placement.exits.get(&index).cloned().unwrap_or_default() {
            out.extend(self.place(placement, exit)?);
        }
        Ok(out)
    }

    /// A block's own text: its label, its statements, its arms, and the
    /// merges it dominates.
    fn block_region(
        &mut self,
        placement: &Placement,
        addr: u64,
    ) -> ControlFlowStructureResult<CStmt> {
        let mut stmts = Vec::new();
        if placement.labelled.contains(&addr) {
            stmts.push(CStmt::Label(self.ensure_label(addr)));
        }
        if let Some(block) = self.func.get_block(addr) {
            // One fold per block: a second fold of a cached block mints fresh
            // observation targets for statements nobody emits.
            let entries = self.folded_block_entries(block, addr)?;
            self.mark_terminal_callee(block, addr, &entries);
            stmts.extend(
                entries
                    .into_iter()
                    .filter(|entry| !self.certified_for_header_sites.contains(&entry.site))
                    .map(|entry| entry.stmt),
            );
        }
        stmts.extend(self.arms(placement, addr)?);
        for merge in placement
            .merge_children
            .get(&addr)
            .cloned()
            .unwrap_or_default()
        {
            stmts.extend(self.place(placement, merge)?);
        }
        Ok(CStmt::structured_region(
            StructuredRegionMarker::unsealed(addr, StructuredRegionKind::Block),
            CStmt::Block(stmts),
        ))
    }

    /// A block the source declared terminal ends in a call that never
    /// returns: the callee of its terminating operation is declared so, and
    /// only that callee, because the prototype makes the compiler believe it.
    fn mark_terminal_callee(
        &mut self,
        block: &r2ssa::FunctionSSABlock,
        addr: u64,
        entries: &[crate::fold::op_lower::FoldedOpStmt],
    ) {
        let terminal = self.func.cfg().get_block(addr).is_some_and(|cfg_block| {
            matches!(
                cfg_block.terminator,
                BlockTerminator::None
                    | BlockTerminator::Call {
                        fallthrough: None,
                        ..
                    }
            )
        });
        // Materialised merge copies can follow the call, so the terminating
        // operation is the last call, not the last operation.
        let last_call = block
            .ops
            .iter()
            .rposition(|op| matches!(op, SSAOp::Call { .. }));
        let Some(last) = last_call else {
            return;
        };
        if !terminal {
            return;
        }
        let name = entries
            .iter()
            .find(|entry| entry.site.op_idx == last)
            .and_then(|entry| super::certify::stmt_callee_name(&entry.stmt).map(str::to_string));
        if let Some(name) = name {
            self.fold_ctx.mark_callee_noreturn(&name);
        }
    }

    /// The block's terminator, one transfer per edge.
    fn arms(&mut self, placement: &Placement, addr: u64) -> ControlFlowStructureResult<Vec<CStmt>> {
        let Some(cfg_block) = self.func.cfg().get_block(addr) else {
            return Ok(Vec::new());
        };
        let terminator = cfg_block.terminator.clone();
        match terminator {
            BlockTerminator::Fallthrough { next: target }
            | BlockTerminator::Branch { target }
            | BlockTerminator::Call {
                fallthrough: Some(target),
                ..
            }
            | BlockTerminator::IndirectCall {
                fallthrough: Some(target),
            } => self.edge(placement, addr, target),
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => self.conditional_arms(placement, addr, true_target, false_target),
            BlockTerminator::Switch { cases, default } => {
                self.switch_arms(placement, addr, &cases, default)
            }
            BlockTerminator::IndirectBranch => {
                let targets = self.func.successors(addr);
                if targets.is_empty() {
                    if self.is_unresolved_indirect_dispatch_block(addr) {
                        return Ok(vec![CStmt::comment(
                            "indirect branch target unresolved".to_string(),
                        )]);
                    }
                    return Ok(Vec::new());
                }
                let cases: Vec<(u64, u64)> =
                    targets.iter().map(|target| (*target, *target)).collect();
                self.switch_arms(placement, addr, &cases, None)
            }
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::Return
            | BlockTerminator::None => Ok(Vec::new()),
        }
    }

    /// The text of one edge: the merge it carries, then the transfer.
    fn edge(
        &mut self,
        placement: &Placement,
        from: u64,
        to: u64,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        if self.func.cfg().get_block(to).is_none() {
            // A transfer out of the function is the folded statement's own:
            // a certified tail call already rendered its return.
            return Ok(Vec::new());
        }
        let mut stmts = self.edge_merge_writes(to, from)?;
        match placement.edge(from, to) {
            EdgeShape::Inline => stmts.extend(self.place(placement, to)?),
            EdgeShape::Continue => stmts.push(CStmt::Continue),
            EdgeShape::Goto => stmts.push(CStmt::Goto(self.ensure_label(to))),
        }
        Ok(stmts)
    }

    fn conditional_arms(
        &mut self,
        placement: &Placement,
        addr: u64,
        true_target: u64,
        false_target: u64,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        let (cond, _, _) = self.get_branch_condition_with_predicate(addr);
        let then_body = self.edge(placement, addr, true_target)?;
        let else_body = self.edge(placement, addr, false_target)?;
        let Some(cond) = cond else {
            // The test has no rendering, so the arms are written where they
            // would go and the certificate says the block's edges are unowned.
            let mut stmts = vec![CStmt::comment(format!(
                "r2dec residual: unresolved branch condition at 0x{addr:x}"
            ))];
            stmts.extend(else_body);
            stmts.extend(then_body);
            return Ok(stmts);
        };
        let stmt = self.observe_control_ownership(
            addr,
            CStmt::if_stmt(
                cond,
                Self::arm_stmt(then_body),
                Some(Self::arm_stmt(else_body)),
            ),
        );
        Ok(vec![CStmt::structured_region(
            StructuredRegionMarker::unsealed(addr, StructuredRegionKind::IfThenElse),
            stmt,
        )])
    }

    fn switch_arms(
        &mut self,
        placement: &Placement,
        addr: u64,
        cases: &[(u64, u64)],
        default: Option<u64>,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        let selector = match self.get_switch_expression(addr)? {
            Some((expr, _)) => Some(expr),
            None => self.dispatch_operand_expr(addr),
        };
        // One arm per target; values whose target is the default's are the
        // default's, which is what `default:` means.
        let mut by_target = BTreeMap::<u64, Vec<u64>>::new();
        let mut order = Vec::new();
        for (value, target) in cases {
            if Some(*target) == default {
                continue;
            }
            if !by_target.contains_key(target) {
                order.push(*target);
            }
            by_target.entry(*target).or_default().push(*value);
        }
        order.sort_by_key(|target| placement.rpo.get(target).copied());
        let Some(selector) = selector else {
            let mut stmts = vec![CStmt::comment(format!(
                "r2dec residual: unresolved switch selector at 0x{addr:x}"
            ))];
            for target in order {
                stmts.extend(self.edge(placement, addr, target)?);
            }
            if let Some(default) = default {
                stmts.extend(self.edge(placement, addr, default)?);
            }
            return Ok(stmts);
        };
        // A table with no default covers every value the machine can reach
        // it with, so C's `default:` says nothing new; putting it on the last
        // arm lets the compiler see that the switch does not fall out.
        let default_on_last = default.is_none();
        let mut switch_cases = Vec::new();
        let mut default_body = match default {
            Some(target) => Some(self.edge(placement, addr, target)?),
            None => None,
        };
        let count = order.len();
        for (index, target) in order.into_iter().enumerate() {
            let values = &by_target[&target];
            let body = self.edge(placement, addr, target)?;
            let last_is_default = default_on_last && index + 1 == count;
            let (leading, last) = if last_is_default {
                (&values[..], None)
            } else {
                (&values[..values.len() - 1], Some(values[values.len() - 1]))
            };
            for value in leading {
                switch_cases.push(SwitchCase {
                    value: CExpr::IntLit(*value as i64),
                    body: Vec::new(),
                });
            }
            match last {
                Some(value) => switch_cases.push(SwitchCase {
                    value: CExpr::IntLit(value as i64),
                    body,
                }),
                None => default_body = Some(body),
            }
        }
        let stmt = self.observe_control_ownership(
            addr,
            CStmt::Switch {
                expr: selector,
                cases: switch_cases,
                default: default_body,
            },
        );
        Ok(vec![CStmt::structured_region(
            StructuredRegionMarker::unsealed(addr, StructuredRegionKind::Switch),
            stmt,
        )])
    }

    /// The value an indirect branch dispatches through, when it renders: a
    /// `switch` on the target address is exact where no selector is certified.
    fn dispatch_operand_expr(&mut self, addr: u64) -> Option<CExpr> {
        let block = self.func.get_block(addr)?;
        let target = block.ops.iter().find_map(|op| match op {
            SSAOp::BranchInd { target, .. } => Some(target.clone()),
            _ => None,
        })?;
        let value = self.fold_ctx.prepared_value_id_for_var(&target)?;
        self.fold_ctx.planned_value_expr(value).ok()
    }

    fn arm_stmt(mut stmts: Vec<CStmt>) -> CStmt {
        match stmts.len() {
            0 => CStmt::Empty,
            1 => stmts.remove(0),
            _ => CStmt::Block(stmts),
        }
    }
}
