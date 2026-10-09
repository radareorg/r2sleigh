//! D1: the function's control, placed by the dominator tree (doc/adr-structure-dominator-tree.md
//! §4), around D2's statements; where D2 has none, a block's operations are one gap.

use std::collections::BTreeMap;

use r2ssa::cfg::BlockTerminator;

use super::RenderInput;
use super::values::Values;
use crate::ast::RenderObservationId;
use crate::ast::{CExpr, CStmt, CType, GapMarker, SwitchCase};
use crate::prelude::ResidualCause;
use crate::structure::place::{EdgeShape, Placement};

/// The transfers the text cannot make, each a gap that traps where control would leave.
const UNRESOLVED_INDIRECT_BRANCH: &str = "UnresolvedIndirectBranch";
const TRANSFER_NOT_FOLLOWED: &str = "TransferNotFollowed";
const TAIL_TRANSFER_NOT_RENDERED: &str = "TailTransferNotRendered";

/// Whether `marker` is one of those: control does not go on past it.
pub(super) fn ends_control(marker: &GapMarker) -> bool {
    [
        UNRESOLVED_INDIRECT_BRANCH,
        TRANSFER_NOT_FOLLOWED,
        TAIL_TRANSFER_NOT_RENDERED,
    ]
    .contains(&marker.kind.as_str())
}

/// The written body, its labels, and the block and instruction each marked statement stands for.
pub(super) struct Written {
    pub(super) body: Vec<CStmt>,
    pub(super) labels: BTreeMap<u64, String>,
    /// By observation index: the block a marked statement was written for, which the certificate reads.
    pub(super) blocks: Vec<u64>,
    /// By observation index: the instruction, which each emitted line names.
    pub(super) addresses: Vec<u64>,
    /// Where the work control stopped the writing, if it did.
    pub(super) stopped: Option<crate::control::DecompileExecutionStop>,
}

/// Write every block once, in the region of its immediate dominator or after the loop it leaves.
pub(super) fn write(
    input: &RenderInput<'_>,
    values: Option<&Values<'_>>,
    work: &crate::control::DecompileWorkControl<'_>,
) -> Written {
    let function = input.function();
    let placement = Placement::compute(
        function.cfg(),
        function.domtree(),
        function.natural_loops(),
        function.root(),
    );
    let mut writer = Writer {
        input,
        values,
        work,
        stopped: None,
        placement: &placement,
        labels: BTreeMap::new(),
        blocks: Vec::new(),
        addresses: Vec::new(),
    };
    for addr in placement.labelled().iter().copied() {
        writer.label(addr);
    }
    let body = writer.place(placement.entry());
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
    values: Option<&'w Values<'i>>,
    work: &'w crate::control::DecompileWorkControl<'w>,
    stopped: Option<crate::control::DecompileExecutionStop>,
    placement: &'w Placement<'i>,
    labels: BTreeMap<u64, String>,
    blocks: Vec<u64>,
    addresses: Vec<u64>,
}

impl<'i> Writer<'_, 'i> {
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
        let mut stmts = Vec::new();
        if self.placement.labelled().contains(&addr) {
            stmts.push(CStmt::Label(self.label(addr)));
        }
        let written = stmts.len();
        if let Some(values) = self.values {
            for (at, stmt) in values.statements(addr) {
                stmts.push(self.observe_at(addr, at, stmt));
            }
        } else {
            stmts.extend(self.gap(addr));
        }
        // A block that writes nothing and leaves by plain flow still occurs, which the certificate reads.
        if stmts.len() == written && !self.ends_observed(addr) {
            stmts.push(self.observe(addr, CStmt::Empty));
        }
        stmts.extend(self.arms(addr));
        for merge in self.placement.merges_in(addr).to_vec() {
            stmts.extend(self.place(merge));
        }
        CStmt::Block(stmts)
    }

    /// A block's operations as one gap, where D2 rendered no values.
    fn gap(&mut self, addr: u64) -> Option<CStmt> {
        let ops = self
            .input
            .function()
            .get_block(addr)
            .map_or(0, |block| block.ops().len());
        (ops != 0).then(|| {
            let gap = CStmt::Gap(GapMarker {
                kind: "ValuesNotRendered".to_owned(),
                origin: "render::control".to_owned(),
                block_addr: addr,
                op_idx: 0,
                ops,
            });
            self.observe(addr, gap)
        })
    }

    /// Whether the block's terminator is written as a statement marked for the block.
    fn ends_observed(&self, addr: u64) -> bool {
        match self
            .input
            .function()
            .cfg()
            .get_block(addr)
            .map(|b| &b.terminator)
        {
            Some(BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            }) => true_target != false_target,
            Some(
                BlockTerminator::Switch { .. }
                | BlockTerminator::IndirectBranch
                | BlockTerminator::Return
                | BlockTerminator::Call {
                    fallthrough: None, ..
                }
                | BlockTerminator::IndirectCall { fallthrough: None }
                | BlockTerminator::None,
            ) => true,
            _ => false,
        }
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
                let test = self.spelled(addr, Values::condition, &CType::Bool);
                vec![self.observe(addr, CStmt::if_stmt(test, then_body, Some(else_body)))]
            }
            BlockTerminator::Switch { cases, default } => {
                let selector = self.spelled(addr, Values::selector, &super::word(self.input));
                self.switch(addr, selector, &cases, default)
            }
            BlockTerminator::IndirectBranch => {
                let targets = function.successors(addr);
                let cases = targets
                    .iter()
                    .map(|target| (*target, *target))
                    .collect::<Vec<_>>();
                match cases.is_empty() {
                    // No stated target: control goes where the facts do not say, so the text traps.
                    true => vec![self.trap(addr, UNRESOLVED_INDIRECT_BRANCH)],
                    false => {
                        let selector = self.residual(&super::word(self.input));
                        self.switch(addr, selector, &cases, None)
                    }
                }
            }
            BlockTerminator::Return => {
                let stmt = self.return_stmt(Some(addr));
                // The line accounts for the return instruction, wherever in the block it sits.
                let at = (self.values)
                    .and_then(|values| values.terminator_address(addr))
                    .unwrap_or(addr);
                vec![self.observe_at(addr, at, stmt)]
            }
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
                if self
                    .values
                    .is_some_and(|values| values.ends_never_returning(addr)) =>
            {
                // The call written above is declared never to return, which C ends control at.
                Vec::new()
            }
            // Control never comes back: a void residual traps, so the text ends here as the machine does.
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::None => vec![self.trap(addr, TRANSFER_NOT_FOLLOWED)],
        }
    }

    /// A return hands back what D2 spelled, else a residual of the result type, or nothing for `void`.
    fn return_stmt(&self, addr: Option<u64>) -> CStmt {
        let ty = super::result_type(self.input);
        let decided = self
            .input
            .return_type()
            .and_then(r2types::ReturnTypeFact::decided);
        let spelled = self
            .values
            .zip(addr)
            .and_then(|(values, addr)| Some((values.returned(addr, decided)?, values, addr)));
        if let Some((value, values, addr)) = spelled {
            let stmt = CStmt::Return(value);
            values.spelled_terminator(addr, &stmt);
            return stmt;
        }
        // The interface proves no result: what this return hands back is unproven, not a gap.
        let unproven = self
            .input
            .return_type()
            .is_some_and(r2types::ReturnTypeFact::is_unproven);
        match ty {
            CType::Void => CStmt::Return(None),
            ty if unproven => CStmt::Return(Some(
                crate::prelude::residual(&ty, ResidualCause::UnprovenReturn)
                    .unwrap_or_else(|| self.residual(&ty)),
            )),
            ty => CStmt::Return(Some(self.residual(&ty))),
        }
    }

    /// The terminator's operand as D2 spelled it, else a residual of `ty`.
    fn spelled(&self, addr: u64, read: fn(&Values<'i>, u64) -> Option<CExpr>, ty: &CType) -> CExpr {
        match self
            .values
            .and_then(|values| Some((read(values, addr)?, values)))
        {
            Some((expr, values)) => {
                values.spelled_terminator(addr, &CStmt::Expr(expr.clone()));
                expr
            }
            None => self.residual(ty),
        }
    }

    /// A residual of `ty`, or of the machine word where C has no residual of `ty`.
    /// A transfer the text cannot make, as a gap whose marker names it: running it traps.
    fn trap(&mut self, addr: u64, kind: &'static str) -> CStmt {
        let gap = CStmt::Gap(GapMarker {
            kind: kind.to_owned(),
            origin: "render::control".to_owned(),
            block_addr: addr,
            op_idx: 0,
            ops: 0,
        });
        self.observe(addr, gap)
    }

    fn residual(&self, ty: &CType) -> CExpr {
        crate::prelude::residual(ty, ResidualCause::Gap)
            .or_else(|| crate::prelude::residual(&super::word(self.input), ResidualCause::Gap))
            .expect("a machine word has a residual")
    }

    /// A switch on `selector`, one arm per target; values reaching the default are its own.
    fn switch(
        &mut self,
        addr: u64,
        selector: CExpr,
        cases: &[(u64, u64)],
        default: Option<u64>,
    ) -> Vec<CStmt> {
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
            expr: selector,
            cases: switch_cases,
            default: default_body,
        };
        vec![self.observe(addr, stmt)]
    }

    /// One edge: its merge copies, then the target written here, a `continue`, a `goto`, or a
    /// return where it leaves the function.
    fn edge(&mut self, from: u64, to: u64) -> Vec<CStmt> {
        // An edge out of the function is a tail call D2 writes from its certificate; any other
        // transfer the text cannot make, so it traps rather than return.
        if self.input.function().cfg().get_block(to).is_none() {
            let ty = super::result_type(self.input);
            let decided = self
                .input
                .return_type()
                .and_then(r2types::ReturnTypeFact::decided);
            if let Some(stmts) = self
                .values
                .and_then(|values| values.tail_call(from, &ty, decided))
            {
                return stmts
                    .into_iter()
                    .map(|stmt| self.observe(from, stmt))
                    .collect();
            }
            return vec![self.trap(from, TAIL_TRANSFER_NOT_RENDERED)];
        }
        let mut out = self
            .values
            .map(|values| values.copies(from, to))
            .unwrap_or_default();
        if let Some(values) = self.values {
            values.transferred(from);
        }
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

/// `stmt` copied as a new occurrence: each marker in it replaced by the one `mint` gives for it.
pub(super) fn remint(
    stmt: &CStmt,
    mint: &mut dyn FnMut(RenderObservationId) -> RenderObservationId,
) -> CStmt {
    let copy = |stmts: &[CStmt],
                mint: &mut dyn FnMut(RenderObservationId) -> RenderObservationId| {
        stmts
            .iter()
            .map(|stmt| remint(stmt, mint))
            .collect::<Vec<_>>()
    };
    match stmt {
        CStmt::Observed { .. } => {
            let ids = stmt
                .observation_ids()
                .iter()
                .map(|id| mint(*id))
                .collect::<Vec<_>>();
            CStmt::observe_all(ids, remint(stmt.unobserved(), mint))
        }
        CStmt::Block(stmts) => CStmt::Block(copy(stmts, mint)),
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => CStmt::If {
            cond: cond.clone(),
            then_body: Box::new(remint(then_body, mint)),
            else_body: else_body.as_ref().map(|body| Box::new(remint(body, mint))),
        },
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => CStmt::For {
            init: init.as_ref().map(|init| Box::new(remint(init, mint))),
            cond: cond.clone(),
            update: update.clone(),
            body: Box::new(remint(body, mint)),
        },
        CStmt::While { cond, body } => CStmt::While {
            cond: cond.clone(),
            body: Box::new(remint(body, mint)),
        },
        CStmt::DoWhile { body, cond } => CStmt::DoWhile {
            body: Box::new(remint(body, mint)),
            cond: cond.clone(),
        },
        CStmt::Switch {
            expr,
            cases,
            default,
        } => CStmt::Switch {
            expr: expr.clone(),
            cases: cases
                .iter()
                .map(|case| SwitchCase {
                    value: case.value.clone(),
                    body: copy(&case.body, mint),
                })
                .collect(),
            default: default.as_ref().map(|body| copy(body, mint)),
        },
        other => other.clone(),
    }
}
