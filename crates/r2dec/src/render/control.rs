//! D1: the function's control, placed by the dominator tree (doc/adr-structure-dominator-tree.md
//! §4); until D2 renders values, a block's operations are one gap and a test a residual.

use std::collections::BTreeMap;

use r2ssa::cfg::BlockTerminator;

use super::RenderInput;
use crate::ast::{CExpr, CStmt, CType, GapMarker, SwitchCase};
use crate::observation_journal::RenderObservationId;
use crate::prelude::ResidualCause;
use crate::structure::place::{EdgeShape, Placement};

/// The written body, its labels, and the block each marked statement stands for.
pub(super) struct Written {
    pub(super) body: Vec<CStmt>,
    pub(super) labels: BTreeMap<u64, String>,
    /// By observation index: the block a marked statement was written for.
    pub(super) blocks: Vec<u64>,
}

/// Write every block once, in the region of its immediate dominator or after the loop it leaves.
pub(super) fn write(input: &RenderInput<'_>) -> Written {
    let function = input.function();
    let placement = Placement::compute(
        function.cfg(),
        function.domtree(),
        function.natural_loops(),
        function.root(),
    );
    let mut writer = Writer {
        input,
        placement: &placement,
        labels: BTreeMap::new(),
        blocks: Vec::new(),
    };
    for addr in placement.labelled().iter().copied() {
        writer.label(addr);
    }
    let body = writer.place(placement.entry());
    Written {
        body,
        labels: writer.labels,
        blocks: writer.blocks,
    }
}

struct Writer<'w, 'i> {
    input: &'w RenderInput<'i>,
    placement: &'w Placement<'i>,
    labels: BTreeMap<u64, String>,
    blocks: Vec<u64>,
}

impl Writer<'_, '_> {
    fn label(&mut self, addr: u64) -> String {
        let next = self.labels.len();
        self.labels
            .entry(addr)
            .or_insert_with(|| format!("L{next}"))
            .clone()
    }

    /// Mark a statement as the one written for `addr`, which is what the certificate reads.
    fn observe(&mut self, addr: u64, stmt: CStmt) -> CStmt {
        let id = RenderObservationId::from_dense_index(self.blocks.len());
        self.blocks.push(addr);
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

    /// A block's label, its operations as one gap, its arms, and the merges it dominates.
    fn block_region(&mut self, addr: u64) -> CStmt {
        let mut stmts = Vec::new();
        if self.placement.labelled().contains(&addr) {
            stmts.push(CStmt::Label(self.label(addr)));
        }
        let ops = self
            .input
            .function()
            .get_block(addr)
            .map_or(0, |block| block.ops().len());
        if ops != 0 {
            let gap = CStmt::Gap(GapMarker {
                kind: "ValuesNotRendered".to_owned(),
                origin: "render::control".to_owned(),
                block_addr: addr,
                op_idx: 0,
                ops,
            });
            stmts.push(self.observe(addr, gap));
        }
        stmts.extend(self.arms(addr));
        for merge in self.placement.merges_in(addr).to_vec() {
            stmts.extend(self.place(merge));
        }
        CStmt::Block(stmts)
    }

    /// The block's terminator, one transfer per edge.
    fn arms(&mut self, addr: u64) -> Vec<CStmt> {
        let function = self.input.function();
        let Some(terminator) = function
            .cfg()
            .get_block(addr)
            .map(|block| block.terminator.clone())
        else {
            return Vec::new();
        };
        match terminator {
            BlockTerminator::Fallthrough { next: target }
            | BlockTerminator::Branch { target }
            | BlockTerminator::Call {
                fallthrough: Some(target),
                ..
            }
            | BlockTerminator::IndirectCall {
                fallthrough: Some(target),
            }
            | BlockTerminator::ConditionalExit { next: target } => self.edge(addr, target),
            // Both arms to one block are one edge, which is how the CFG holds it.
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } if true_target == false_target => self.edge(addr, true_target),
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                let then_body = arm(self.edge(addr, true_target));
                let else_body = arm(self.edge(addr, false_target));
                let test = self.residual(&CType::Bool);
                vec![self.observe(addr, CStmt::if_stmt(test, then_body, Some(else_body)))]
            }
            BlockTerminator::Switch { cases, default } => self.switch(addr, &cases, default),
            BlockTerminator::IndirectBranch => {
                let targets = function.successors(addr);
                let cases = targets
                    .iter()
                    .map(|target| (*target, *target))
                    .collect::<Vec<_>>();
                match cases.is_empty() {
                    // No stated target: control goes where the facts do not say, so the text traps.
                    true => {
                        let trap = CStmt::Expr(self.residual(&CType::Void));
                        vec![self.observe(addr, trap)]
                    }
                    false => self.switch(addr, &cases, None),
                }
            }
            BlockTerminator::Return => vec![self.observe(addr, self.return_stmt())],
            // Control never comes back: a void residual traps, so the text ends here as the machine does.
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::None => {
                let trap = CStmt::Expr(self.residual(&CType::Void));
                vec![self.observe(addr, trap)]
            }
        }
    }

    /// A return hands back a residual of the function's result type, or nothing where that is `void`.
    fn return_stmt(&self) -> CStmt {
        match super::result_type(self.input) {
            CType::Void => CStmt::Return(None),
            ty => CStmt::Return(Some(self.residual(&ty))),
        }
    }

    /// A residual of `ty`, or of the machine word where C has no residual of `ty`.
    fn residual(&self, ty: &CType) -> CExpr {
        crate::prelude::residual(ty, ResidualCause::Gap)
            .or_else(|| crate::prelude::residual(&super::word(self.input), ResidualCause::Gap))
            .expect("a machine word has a residual")
    }

    /// A switch on a residual selector, one arm per target; values reaching the default are its own.
    fn switch(&mut self, addr: u64, cases: &[(u64, u64)], default: Option<u64>) -> Vec<CStmt> {
        let mut by_target = BTreeMap::<u64, Vec<u64>>::new();
        for (value, target) in cases {
            if Some(*target) != default {
                by_target.entry(*target).or_default().push(*value);
            }
        }
        let mut order = by_target.keys().copied().collect::<Vec<_>>();
        order.sort_by_key(|target| self.placement.rpo_of(*target));
        let default_body = default.map(|target| self.edge(addr, target));
        let mut switch_cases = Vec::new();
        for target in order {
            let body = self.edge(addr, target);
            let values = &by_target[&target];
            let (last, leading) = values.split_last().expect("a target has a value");
            switch_cases.extend(leading.iter().map(|value| SwitchCase {
                value: CExpr::IntLit(*value as i64),
                body: Vec::new(),
            }));
            switch_cases.push(SwitchCase {
                value: CExpr::IntLit(*last as i64),
                body,
            });
        }
        let stmt = CStmt::Switch {
            expr: self.residual(&super::word(self.input)),
            cases: switch_cases,
            default: default_body,
        };
        vec![self.observe(addr, stmt)]
    }

    /// One edge: the target written here, a `continue`, a `goto`, or a return where it leaves the function.
    fn edge(&mut self, from: u64, to: u64) -> Vec<CStmt> {
        if self.input.function().cfg().get_block(to).is_none() {
            return vec![self.observe(from, self.return_stmt())];
        }
        match self.placement.edge(from, to) {
            EdgeShape::Inline => self.place(to),
            EdgeShape::Continue => vec![CStmt::Continue],
            EdgeShape::Goto => vec![CStmt::Goto(self.label(to))],
        }
    }
}

fn arm(mut stmts: Vec<CStmt>) -> CStmt {
    match stmts.len() {
        0 => CStmt::Empty,
        1 => stmts.remove(0),
        _ => CStmt::Block(stmts),
    }
}
