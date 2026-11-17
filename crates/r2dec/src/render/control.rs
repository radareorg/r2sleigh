//! D1: the function's control, placed by the dominator tree (doc/adr-structure-dominator-tree.md
//! §4), around the text D2 spelled for every block (`spelled`); control decides layout, never a value.

use std::collections::BTreeMap;

use r2ssa::cfg::BlockTerminator;

use super::RenderInput;
use super::spelled::{BlockText, EdgeText, Edges, End, Spelled, values_not_rendered};
use crate::ast::RenderObservationId;
use crate::ast::{CExpr, CStmt, SwitchCase};
use crate::structure::place::{EdgeShape, Placement};

/// The written body, its labels, and the block and instruction each marked statement stands for.
pub(super) struct Written {
    pub(super) body: Vec<CStmt>,
    pub(super) labels: BTreeMap<u64, String>,
    /// By observation index: the block a marked statement was written for, which the certificate reads.
    pub(super) blocks: Vec<u64>,
    /// By observation index: the instruction, which each emitted line names; none for an edge's copy.
    pub(super) addresses: Vec<Option<u64>>,
    /// Where the work control stopped the writing, if it did.
    pub(super) stopped: Option<crate::control::DecompileExecutionStop>,
}

/// Write every block once, in the region of its immediate dominator or after the loop it leaves.
pub(super) fn write(
    input: &RenderInput<'_>,
    spelled: Spelled,
    placement: &Placement<'_>,
    work: &crate::control::DecompileWorkControl<'_>,
) -> Written {
    let mut writer = Writer {
        input,
        spelled,
        work,
        stopped: None,
        placement,
        labels: BTreeMap::new(),
        blocks: Vec::new(),
        addresses: Vec::new(),
    };
    for addr in placement.labelled().iter().copied() {
        writer.label(addr);
    }
    let body = writer.place(placement.entry());
    debug_assert!(
        writer.stopped.is_some() || writer.spelled.is_empty(),
        "every block spelled was written"
    );
    Written {
        body,
        labels: writer.labels,
        blocks: writer.blocks,
        addresses: writer.addresses,
        stopped: writer.stopped,
    }
}

struct Writer<'w, 'i> {
    input: &'w RenderInput<'i>,
    spelled: Spelled,
    work: &'w crate::control::DecompileWorkControl<'w>,
    stopped: Option<crate::control::DecompileExecutionStop>,
    placement: &'w Placement<'i>,
    labels: BTreeMap<u64, String>,
    blocks: Vec<u64>,
    addresses: Vec<Option<u64>>,
}

impl Writer<'_, '_> {
    fn label(&mut self, addr: u64) -> String {
        let next = self.labels.len();
        self.labels
            .entry(addr)
            .or_insert_with(|| format!("L{next}"))
            .clone()
    }

    /// Mark a statement as the one written for block `addr`, which is what the certificate reads.
    fn observe(&mut self, addr: u64, stmt: CStmt) -> CStmt {
        self.observe_at(addr, addr, stmt)
    }

    /// The same, naming the instruction at `at` as the one the statement's line accounts for.
    fn observe_at(&mut self, addr: u64, at: u64, stmt: CStmt) -> CStmt {
        self.mark(addr, Some(at), stmt)
    }

    /// A copy an edge of block `addr` carries: the block's statement, which no instruction writes.
    fn observe_copy(&mut self, addr: u64, stmt: CStmt) -> CStmt {
        self.mark(addr, None, stmt)
    }

    fn mark(&mut self, addr: u64, at: Option<u64>, stmt: CStmt) -> CStmt {
        let id = RenderObservationId::from_dense_index(self.blocks.len());
        self.blocks.push(addr);
        self.addresses.push(at);
        CStmt::observe_all([id], stmt)
    }

    /// One block at its position: its loop around it when it heads one, then what that loop leaves through.
    fn place(&mut self, addr: u64) -> Vec<CStmt> {
        let region = self.block_region(addr);
        let Some(index) = self.placement.loop_headed_by(addr) else {
            return vec![region];
        };
        let mut out = vec![CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(region),
        }];
        for exit in self.placement.exits_of(index).to_vec() {
            out.extend(self.place(exit));
        }
        out
    }

    /// A block's label, its statements, its arms, and the merges it dominates.
    fn block_region(&mut self, addr: u64) -> CStmt {
        // One poll per block written, so a stop is heard within one block of the work.
        if self.stopped.is_some() {
            return CStmt::Block(Vec::new());
        }
        if let Err(stop) = self.work.poll() {
            self.stopped = Some(stop);
            return CStmt::Block(Vec::new());
        }
        let text = self.spelled.take(addr);
        debug_assert!(text.is_some(), "the block {addr:#x} was spelled");
        let mut text = text.unwrap_or_else(|| BlockText::gap(addr));
        let mut stmts = Vec::new();
        if self.placement.labelled().contains(&addr) {
            stmts.push(CStmt::Label(self.label(addr)));
        }
        let written = stmts.len();
        for (at, stmt) in std::mem::take(&mut text.statements) {
            stmts.push(self.observe_at(addr, at, stmt));
        }
        // A block that writes nothing and leaves by plain flow still occurs, which the certificate reads.
        if stmts.len() == written && matches!(text.end, End::Flow) {
            stmts.push(self.observe(addr, CStmt::Empty));
        }
        stmts.extend(self.arms(addr, text));
        for merge in self.placement.merges_in(addr).to_vec() {
            stmts.extend(self.place(merge));
        }
        CStmt::Block(stmts)
    }

    /// The block's terminator, one transfer per edge.
    fn arms(&mut self, addr: u64, mut text: BlockText) -> Vec<CStmt> {
        let Some(terminator) = self
            .input
            .function()
            .cfg()
            .get_block(addr)
            .map(|block| block.terminator.clone())
        else {
            return Vec::new();
        };
        match (terminator, text.end) {
            (
                BlockTerminator::Fallthrough { next: target }
                | BlockTerminator::Branch { target }
                | BlockTerminator::Call {
                    fallthrough: Some(target),
                    ..
                }
                | BlockTerminator::IndirectCall {
                    fallthrough: Some(target),
                }
                | BlockTerminator::ConditionalExit { next: target },
                End::Flow,
            ) => self.edge(&mut text.edges, addr, target),
            // Both arms to one block are one edge, which is how the CFG holds it.
            (
                BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                },
                End::Flow,
            ) if true_target == false_target => self.edge(&mut text.edges, addr, true_target),
            (
                BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                },
                End::Test(test),
            ) => {
                let then_body = arm(self.edge(&mut text.edges, addr, true_target));
                let else_body = arm(self.edge(&mut text.edges, addr, false_target));
                vec![self.observe(addr, CStmt::if_stmt(test, then_body, Some(else_body)))]
            }
            (BlockTerminator::Switch { cases, default }, End::Selector(selector)) => {
                self.switch(addr, selector, (&cases, default), &mut text.edges)
            }
            (BlockTerminator::IndirectBranch, End::Selector(selector)) => {
                let cases = (self.input.function().successors(addr).into_iter())
                    .map(|target| (target, target))
                    .collect::<Vec<_>>();
                self.switch(addr, selector, (&cases, None), &mut text.edges)
            }
            (BlockTerminator::Return, End::Return { stmt, at }) => {
                vec![self.observe_at(addr, at, stmt)]
            }
            (
                BlockTerminator::IndirectBranch
                | BlockTerminator::Call {
                    fallthrough: None, ..
                }
                | BlockTerminator::IndirectCall { fallthrough: None }
                | BlockTerminator::None,
                End::Trap(gap),
            ) => vec![self.observe(addr, gap)],
            (
                BlockTerminator::Call {
                    fallthrough: None, ..
                }
                | BlockTerminator::IndirectCall { fallthrough: None },
                End::NoReturn,
            ) => Vec::new(),
            _ => {
                debug_assert!(false, "the block {addr:#x} ends as it was spelled");
                vec![self.observe(addr, values_not_rendered(addr, 0))]
            }
        }
    }

    /// A switch on `selector`, one arm per target; values reaching the default are its own.
    fn switch(
        &mut self,
        addr: u64,
        selector: CExpr,
        (cases, default): (&[(u64, u64)], Option<u64>),
        edges: &mut Edges,
    ) -> Vec<CStmt> {
        let mut by_target = BTreeMap::<u64, Vec<u64>>::new();
        for (value, target) in cases {
            if Some(*target) != default {
                by_target.entry(*target).or_default().push(*value);
            }
        }
        let mut order = by_target.keys().copied().collect::<Vec<_>>();
        order.sort_by_key(|target| self.placement.rpo_of(*target));
        let default_body = default.map(|target| self.edge(edges, addr, target));
        let mut switch_cases = Vec::new();
        for target in order {
            let body = self.edge(edges, addr, target);
            let values = &by_target[&target];
            let (last, leading) = values.split_last().expect("a target has a value");
            switch_cases.extend(leading.iter().map(|value| SwitchCase {
                value: CExpr::IntLit(*value as i64),
                body: Vec::new(),
                test: None,
            }));
            switch_cases.push(SwitchCase {
                value: CExpr::IntLit(*last as i64),
                body,
                test: None,
            });
        }
        let stmt = CStmt::Switch {
            expr: selector,
            cases: switch_cases,
            default: default_body,
        };
        vec![self.observe(addr, stmt)]
    }

    /// One edge: its merge copies, then the target written here, a `continue`, a `goto`, or a
    /// return where it leaves the function.
    fn edge(&mut self, edges: &mut Edges, from: u64, to: u64) -> Vec<CStmt> {
        let mut out: Vec<CStmt> = match edges.take(from, to) {
            EdgeText::Leaves(stmts) => {
                return stmts
                    .into_iter()
                    .map(|stmt| self.observe(from, stmt))
                    .collect();
            }
            EdgeText::Copies(copies) => (copies.into_iter())
                .map(|copy| self.observe_copy(from, copy))
                .collect(),
        };
        match self.placement.edge(from, to) {
            EdgeShape::Inline => out.extend(self.place(to)),
            EdgeShape::Continue => out.push(CStmt::Continue),
            EdgeShape::Goto => out.push(CStmt::Goto(self.label(to))),
        }
        out
    }
}

fn arm(mut stmts: Vec<CStmt>) -> CStmt {
    match stmts.len() {
        0 => CStmt::Empty,
        1 => stmts.remove(0),
        _ => CStmt::Block(stmts),
    }
}
