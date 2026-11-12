//! D2 to D1: what the values stage spells for every block, once, in the CFG's reverse postorder and
//! before any block is placed (ROADMAP D58), so no write order can reach a verdict.

use r2ssa::cfg::BlockTerminator;
use rustc_hash::FxHashMap;

use super::RenderInput;
use super::values::Values;
use crate::ast::{CExpr, CStmt, CType, GapKind, GapMarker};
use crate::control::{DecompileExecutionStop, DecompileWorkControl};
use crate::prelude::ResidualCause;

/// Every placed block's text, taken once by the control that writes it.
pub(super) struct Spelled {
    blocks: FxHashMap<u64, BlockText>,
}

/// What one block says: its statements, how it ends, and the text on each edge it leaves by.
pub(super) struct BlockText {
    /// Each statement with the address of the instruction it stands for.
    pub(super) statements: Vec<(u64, CStmt)>,
    pub(super) edges: Edges,
    pub(super) end: End,
}

/// The text on each distinct successor's edge, by target address, each taken once.
pub(super) struct Edges(Vec<(u64, Option<EdgeText>)>);

/// The text an edge carries before the target is written.
pub(super) enum EdgeText {
    /// The parallel copy of the target's merges.
    Copies(Vec<CStmt>),
    /// An edge out of the function: a tail call, or the gap that stands for it.
    Leaves(Vec<CStmt>),
}

/// How a block ends, with the operand or statement D2 spelled for it.
pub(super) enum End {
    /// Plain flow to the one successor, or none.
    Flow,
    Test(CExpr),
    Selector(CExpr),
    Return {
        stmt: CStmt,
        at: u64,
    },
    /// A call declared never to return: C ends control there.
    NoReturn,
    /// A transfer the text cannot make: a gap, which traps.
    Trap(CStmt),
}

impl Spelled {
    /// The block's text, once.
    pub(super) fn take(&mut self, addr: u64) -> Option<BlockText> {
        self.blocks.remove(&addr)
    }

    /// Whether every block's text was taken.
    pub(super) fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl Edges {
    /// The text on the edge `from -> to`, once; a missing edge is a gap, never a panic.
    pub(super) fn take(&mut self, from: u64, to: u64) -> EdgeText {
        let taken = (self.0.binary_search_by_key(&to, |(target, _)| *target))
            .ok()
            .and_then(|at| self.0[at].1.take());
        debug_assert!(
            taken.is_some(),
            "the edge {from:#x} -> {to:#x} was spelled once"
        );
        taken.unwrap_or_else(|| EdgeText::Copies(vec![values_not_rendered(from, 0)]))
    }
}

impl BlockText {
    /// A block nothing spelled, which is one gap.
    pub(super) fn gap(addr: u64) -> Self {
        Self {
            statements: vec![(addr, values_not_rendered(addr, 0))],
            edges: Edges(Vec::new()),
            end: End::Flow,
        }
    }
}

/// Spell every block of `order` (the placed blocks in reverse postorder) in one pass, `O(B + E +
/// statements + phi inputs)`: a block follows its dominators and forward predecessors.
pub(super) fn spell(
    input: &RenderInput<'_>,
    tags: &super::tags::Tags,
    values: Option<&Values<'_>>,
    order: &[u64],
    work: &DecompileWorkControl<'_>,
) -> Result<Spelled, DecompileExecutionStop> {
    let ty = super::result_type(input, tags);
    // A decided result is the declared one, spelled alike.
    let decided = (input.return_type())
        .and_then(r2types::ReturnTypeFact::decided)
        .map(|_| ty.clone());
    let spelling = Spelling {
        input,
        values,
        ty,
        decided,
        carried: super::unproven_carrier_bits(input),
    };
    let mut blocks = FxHashMap::with_capacity_and_hasher(order.len(), Default::default());
    for addr in order.iter().copied() {
        work.poll()?;
        blocks.insert(addr, spelling.block(addr));
    }
    Ok(Spelled { blocks })
}

struct Spelling<'s, 'i> {
    input: &'s RenderInput<'i>,
    values: Option<&'s Values<'i>>,
    /// The function's result type, and the one the analysis decided, if it did.
    ty: CType,
    decided: Option<CType>,
    /// An unproven result's carrier width: a spelled return hands its value through the identity.
    carried: Option<u32>,
}

impl<'i> Spelling<'_, 'i> {
    /// A block's statements, then each edge, then the operand it branches on: the order the Writer
    /// used. No verdict depends on it; a test reads no merge its own forward edges pay (ROADMAP D68).
    fn block(&self, addr: u64) -> BlockText {
        if let Some(values) = self.values {
            values.enter(addr);
        }
        let statements = self.statements(addr);
        let Some(terminator) = self
            .input
            .function()
            .cfg()
            .get_block(addr)
            .map(|block| block.terminator.clone())
        else {
            return BlockText {
                statements,
                edges: Edges(Vec::new()),
                end: End::Flow,
            };
        };
        let (edges, end) = self.ending(addr, &terminator);
        let mut edges = edges
            .into_iter()
            .map(|(to, text)| (to, Some(text)))
            .collect::<Vec<_>>();
        edges.sort_by_key(|(to, _)| *to);
        BlockText {
            statements,
            edges: Edges(edges),
            end,
        }
    }

    /// A block's operations as D2 spelled them, or as one gap where D2 rendered no values.
    fn statements(&self, addr: u64) -> Vec<(u64, CStmt)> {
        if let Some(values) = self.values {
            return values.statements(addr);
        }
        let graph = self.input.graph();
        let ops = (graph.block_id_for_addr(addr)).map_or(0, |block| graph.op_insts(block).len());
        match ops {
            0 => Vec::new(),
            ops => vec![(addr, values_not_rendered(addr, ops))],
        }
    }

    /// The edges of `addr` in the order they are spelled, and how the block ends.
    fn ending(&self, addr: u64, terminator: &BlockTerminator) -> (Vec<(u64, EdgeText)>, End) {
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
            | BlockTerminator::ConditionalExit { next: target } => {
                (vec![self.along(addr, *target)], End::Flow)
            }
            // Both arms to one block are one edge, which is how the CFG holds it.
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } if true_target == false_target => (vec![self.along(addr, *true_target)], End::Flow),
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => {
                let edges = vec![
                    self.along(addr, *true_target),
                    self.along(addr, *false_target),
                ];
                let test = self.operand(addr, Values::condition, &CType::Bool);
                (edges, End::Test(test))
            }
            BlockTerminator::Switch { cases, default } => {
                let selector = self.operand(addr, Values::selector, &super::word(self.input));
                let targets = cases.iter().map(|(_, target)| *target);
                let edges = self.edges(addr, *default, targets);
                (edges, End::Selector(selector))
            }
            BlockTerminator::IndirectBranch => {
                let targets = self.input.function().successors(addr);
                if targets.is_empty() {
                    // No stated target: control goes where the facts do not say, so the text traps.
                    let trap = self.trap(addr, GapKind::UnresolvedIndirectBranch);
                    return (Vec::new(), End::Trap(trap));
                }
                self.residual_terminator(addr);
                let selector = self.residual(&super::word(self.input));
                let edges = self.edges(addr, None, targets.into_iter());
                (edges, End::Selector(selector))
            }
            BlockTerminator::Return => {
                let stmt = self.return_stmt(addr);
                // The line accounts for the return instruction, wherever in the block it sits.
                let at = (self.values)
                    .and_then(|values| values.terminator_address(addr))
                    .unwrap_or(addr);
                (Vec::new(), End::Return { stmt, at })
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
                (Vec::new(), End::NoReturn)
            }
            // Control never comes back: a void residual traps, so the text ends here as the machine does.
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::None => {
                let trap = self.trap(addr, GapKind::TransferNotFollowed);
                (Vec::new(), End::Trap(trap))
            }
        }
    }

    /// The edges of a multiway block: the default first, then the other distinct targets in reverse
    /// postorder, which is the order the cases are written in.
    fn edges(
        &self,
        addr: u64,
        default: Option<u64>,
        targets: impl Iterator<Item = u64>,
    ) -> Vec<(u64, EdgeText)> {
        let mut others = targets
            .filter(|target| Some(*target) != default)
            .collect::<Vec<_>>();
        let graph = self.input.graph();
        others.sort_by_key(|target| (graph.block_id_for_addr(*target), *target));
        others.dedup();
        default
            .into_iter()
            .chain(others)
            .map(|target| self.along(addr, target))
            .collect()
    }

    /// One edge: its merge copies where it enters a block, a tail call or the gap that stands for it
    /// where it leaves the function.
    fn along(&self, from: u64, to: u64) -> (u64, EdgeText) {
        if self.input.function().cfg().get_block(to).is_some() {
            let copies = (self.values)
                .map(|values| values.copies(from, to))
                .unwrap_or_default();
            if let Some(values) = self.values {
                values.transferred(from);
            }
            return (to, EdgeText::Copies(copies));
        }
        // An edge out of the function is a tail call D2 writes from its certificate; any other
        // transfer the text cannot make, so it traps rather than return.
        let tail = (self.values)
            .and_then(|values| values.tail_call(from, &self.ty, self.decided.as_ref()));
        if let Some(stmts) = tail {
            let stmts = stmts.into_iter().map(|stmt| match stmt {
                CStmt::Return(value) => CStmt::Return(self.carry(value)),
                stmt => stmt,
            });
            return (to, EdgeText::Leaves(stmts.collect()));
        }
        let resolution = self.input.callee_resolution();
        let call = (self.values).and_then(|values| values.tail_gap(from, resolution));
        let trap = self.trap(from, GapKind::TailTransferNotRendered(call));
        (to, EdgeText::Leaves(vec![trap]))
    }

    /// A return hands back what D2 spelled, else a residual of the result type, or nothing for `void`.
    fn return_stmt(&self, addr: u64) -> CStmt {
        let carried = self.carried.map(|_| &self.ty);
        let spelled = self.values.and_then(|values| {
            Some((
                values.returned(addr, self.decided.as_ref().or(carried))?,
                values,
            ))
        });
        if let Some((value, values)) = spelled {
            let stmt = CStmt::Return(self.carry(value));
            values.spelled_terminator(addr, &stmt);
            return stmt;
        }
        // The interface proves no result: what this return hands back is unproven, not a gap.
        let unproven = self
            .input
            .return_type()
            .is_some_and(r2types::ReturnTypeFact::is_unproven);
        if self.ty != CType::Void {
            self.residual_terminator(addr);
        }
        match &self.ty {
            CType::Void => CStmt::Return(None),
            ty if unproven => CStmt::Return(Some(
                crate::prelude::residual(ty, ResidualCause::UnprovenReturn)
                    .unwrap_or_else(|| self.residual(ty)),
            )),
            ty => CStmt::Return(Some(self.residual(ty))),
        }
    }

    /// An unproven result's returned value through the carrier identity, which claims no type; a
    /// value spelled as a residual traps already and is no carried value.
    fn carry(&self, value: Option<CExpr>) -> Option<CExpr> {
        let helper = self.carried.and_then(crate::prelude::carrier);
        match (value, helper) {
            (Some(value), Some(helper)) if !crate::prelude::holds_residual(&value) => {
                Some(helper.call(vec![value]))
            }
            (value, _) => value,
        }
    }

    /// The terminator's operand as D2 spelled it, else a residual of `ty`.
    fn operand(&self, addr: u64, read: fn(&Values<'i>, u64) -> Option<CExpr>, ty: &CType) -> CExpr {
        match self
            .values
            .and_then(|values| Some((read(values, addr)?, values)))
        {
            Some((expr, values)) => {
                values.spelled_terminator(addr, &CStmt::Expr(expr.clone()));
                expr
            }
            None => {
                self.residual_terminator(addr);
                self.residual(ty)
            }
        }
    }

    /// The terminator of the block at `addr` is a residual the text spells, which the ledger reads.
    fn residual_terminator(&self, addr: u64) {
        if let Some(values) = self.values {
            values.residual_terminator(addr);
        }
    }

    /// A transfer the text cannot make, as a gap whose marker names it: running it traps.
    fn trap(&self, addr: u64, kind: GapKind) -> CStmt {
        self.residual_terminator(addr);
        CStmt::Gap(GapMarker {
            kind,
            origin: "render::control".to_owned(),
            block_addr: addr,
            op_idx: 0,
            ops: 0,
        })
    }

    /// A residual of `ty`, or of the machine word where C has no residual of `ty`.
    fn residual(&self, ty: &CType) -> CExpr {
        crate::prelude::residual(ty, ResidualCause::Gap)
            .or_else(|| crate::prelude::residual(&super::word(self.input), ResidualCause::Gap))
            .expect("a machine word has a residual")
    }
}

/// A block's operations, or an edge's copies, that D2 spelled no values for: one gap.
pub(super) fn values_not_rendered(addr: u64, ops: usize) -> CStmt {
    CStmt::Gap(GapMarker {
        kind: GapKind::ValuesNotRendered,
        origin: "render::control".to_owned(),
        block_addr: addr,
        op_idx: 0,
        ops,
    })
}
