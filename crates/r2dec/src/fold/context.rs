use std::cell::Cell;
#[cfg(test)]
use std::cell::OnceCell;
#[cfg(test)]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::OnceLock;

use crate::analysis;
use crate::ast::CExpr;
use crate::ast::CType;
use r2ssa::{BlockId, InstId, SemanticObligationId, SsaArtifact, UseSite, ValueId};
use r2types::{CalleeFact, CalleeResolutionFacts, FunctionFacts};
#[cfg(test)]
use r2types::{ExternalStackSlotSpec, StackSlotKey, VisibleBinding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EffectOccurrenceKind {
    Expression,
    MemoryRead,
    MemoryWrite,
    Return,
}

#[derive(Debug, Clone)]
pub(crate) struct FoldArchConfig {
    pub(crate) ptr_size: u32,
    pub(crate) arg_regs: Vec<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct FoldInputs<'a> {
    pub(crate) arch: &'a FoldArchConfig,
    #[cfg(test)]
    pub(crate) function_names: &'a HashMap<u64, String>,
    #[cfg(test)]
    /// What the binary calls the thing at an address, not a name this
    /// rendering declares.
    pub(crate) binary_symbols: &'a HashMap<u64, String>,
    pub(crate) function_facts: &'a FunctionFacts,
    #[cfg(test)]
    pub(crate) stack_slots: &'a BTreeMap<StackSlotKey, ExternalStackSlotSpec>,
    #[cfg(test)]
    pub(crate) visible_bindings: &'a [VisibleBinding],
    pub(crate) function_return_type: Option<&'a CType>,
    pub(crate) prepared_ssa: Option<&'a SsaArtifact>,
    /// Sole `BindingId -> SymbolId` projection for this native rendering.
    pub(crate) binding_names: Option<&'a std::rc::Rc<crate::binding_plan::BindingNameResolution>>,
    pub(crate) prepared_semantic_view: Option<&'a analysis::PreparedSemanticView>,
    /// Exact origin of every operation in the normalized function.
    pub(crate) normalization_origins: Option<&'a crate::normalize::NormalizationOrigins>,
    /// Sole authority-bound observation journal for this native rendering.
    /// Test and residual-only folds deliberately carry no journal.
    pub(crate) observation_journal:
        Option<&'a std::cell::RefCell<crate::observation_journal::LegacyObservationJournal>>,
}

impl<'a> FoldInputs<'a> {
    pub(crate) fn callee_facts(&self) -> &'a BTreeMap<u64, CalleeFact> {
        &self.function_facts.type_facts().callee_facts
    }

    pub(crate) fn callee_resolution(&self) -> Option<&'a CalleeResolutionFacts> {
        self.function_facts.callee_resolution()
    }

    pub(crate) fn callsite_facts(&self) -> Option<&'a r2types::FunctionCallsiteFacts> {
        self.function_facts.callsites()
    }

    pub(crate) fn call_result_facts(&self) -> Option<&'a r2types::FunctionCallResultFacts> {
        self.function_facts.call_results()
    }

    pub(crate) fn call_render_facts(&self) -> Option<&'a r2types::FunctionCallRenderFacts> {
        self.function_facts.call_render()
    }

    pub(crate) fn control_facts(&self) -> Option<&'a r2types::FunctionControlFacts> {
        self.function_facts.control()
    }

    pub(crate) fn render_facts(&self) -> Option<&'a r2types::FunctionRenderFacts> {
        self.function_facts.render()
    }
}

#[cfg(test)]
pub(crate) fn empty_function_facts() -> &'static FunctionFacts {
    static EMPTY_FUNCTION_FACTS: OnceLock<FunctionFacts> = OnceLock::new();
    EMPTY_FUNCTION_FACTS.get_or_init(FunctionFacts::default)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FoldState {
    pub(crate) analysis_ctx: analysis::DecompilerFacts,
}

/// Internal executable-folding state.
///
/// Public callers must enter through [`crate::DecompilerInput`], which retains
/// the exact source-owned facts for its prepared SSA. Raw SSA exports use the
/// residual-only [`crate::fold::lower_ssa_ops_to_stmts`] boundary instead.
///
/// ```compile_fail
/// let _ = r2dec::fold::FoldingContext::new(64);
/// ```
pub(crate) struct FoldingContext<'a> {
    pub(crate) inputs: FoldInputs<'a>,
    pub(crate) state: FoldState,
    pub(crate) current_block_addr: Cell<Option<u64>>,
    pub(crate) current_block_id: Cell<Option<BlockId>>,
    /// Where each name is defined in the block being walked.
    ///
    /// Finding a definition by scanning the block costs one pass per question,
    /// so a block with many definitions costs the square of its size. One pass
    /// answers every question about that block, and it is rebuilt when the walk
    /// moves on.
    pub(crate) current_op_idx: Cell<Option<usize>>,
    /// What the right-hand side of the assignment being lowered has.
    ///
    /// The operation's lowering states it when it spells the assignment,
    /// and the finaliser reads it when it applies the write projection and
    /// the conversion to the declared object, which happen after the
    /// statement has been built. One transaction sets and takes it.
    pub(crate) pending_assignment_type: Cell<Option<r2rewrite::CValue>>,
    /// Legacy cache retained only as a negative test fixture: production
    /// inlining is authorized exclusively by the sealed binding plan.
    ///
    /// Leaving a statement out is a promise that the reader will show the value
    /// instead. The promise used to be made by one rule and kept by another, and
    /// when they disagreed the reader printed the value's name and nothing
    /// defined it. The expression the skipped statement would have carried is
    /// recorded here as it is skipped, so the rule that decides and the rule that
    /// renders are reading the same answer.
    #[cfg(test)]
    pub(crate) inlined_renderings: std::cell::RefCell<HashMap<String, CExpr>>,
    #[cfg(test)]
    pub(crate) prepared_semantic_view_cache: OnceCell<analysis::PreparedSemanticView>,
    /// Blocks the fold walked, which is what expresses a merge standing at their head.
    pub(crate) folded_blocks: std::cell::RefCell<std::collections::BTreeSet<u64>>,
    /// A prototype for each function this rendering calls, keyed by the name
    /// the call spells, collected while the calls are lowered because that is
    /// where the callee's interface is in hand. Handed to the function when it
    /// is built.
    pub(crate) callee_declarations:
        std::cell::RefCell<std::collections::BTreeMap<String, crate::ast::CExternDecl>>,
    /// Names minted while folding, handed to the function when it is built.
    ///
    /// A cell because the builders take `&self`. Minting has to borrow, insert
    /// and drop inside one statement: a borrow held across a nested build would
    /// panic, and nested builds are the ordinary case here.
    /// The names this rendering declares, shared with whatever else renders
    /// the same function. An identifier only means something in the table that
    /// issued it, so the passes cannot each hold a copy.
    pub(crate) symbols: std::rc::Rc<std::cell::RefCell<crate::symbol::SymbolTable>>,
    /// First exact-observation failure. Lowering is largely `Option`-based, so
    /// marker issuance records the typed failure here and the native boundary
    /// retains it in the non-consuming audit while emitting the same marker-free
    /// native program.
    pub(crate) observation_error:
        std::cell::RefCell<Option<crate::observation_journal::LegacyObservationJournalError>>,
    /// Transaction-local lowering failure. Legacy helpers are still mostly
    /// expression-returning, so an exact projection failure records this flag
    /// and the operation boundary discards the whole candidate AST.
    pub(crate) pending_lowering_refusal: Cell<Option<crate::fold::op_lower::OpLoweringRefusal>>,
    /// Source instructions a marked gap already accounts for.
    ///
    /// A gap owns a closure that can reach into blocks this fold has not
    /// walked yet, so the set outlives the block it was opened in: an
    /// operation inside it must not also render, or one cell would have two
    /// answers.
    pub(crate) gapped_sites: std::cell::RefCell<std::collections::BTreeSet<InstId>>,
    /// Gaps a previous structuring attempt learned about, by the instruction
    /// each one is anchored at.
    ///
    /// A planned gap is opened when the fold reaches its anchor, not when the
    /// refusal is met: that is the whole point of planning it, since by the
    /// time the refusal was met a reader had already claimed its cells.
    pub(crate) gap_anchors: std::cell::RefCell<std::collections::BTreeMap<InstId, GapReason>>,
}

/// Why a gap was planned, in the terms the marker prints.
///
/// A lowering refusal carries its own kind and site. A proof failure found
/// after rendering names a cell rather than a lowering site, so it says what
/// failed and where the cell was named instead.
#[derive(Clone)]
pub(crate) struct GapReason {
    pub(crate) kind: String,
    pub(crate) origin: String,
    /// The lowering refusal to report if the gap cannot be opened after all.
    pub(crate) lowering: Option<crate::fold::op_lower::OpLoweringRefusal>,
}

impl GapReason {
    pub(crate) fn from_lowering(refusal: crate::fold::op_lower::OpLoweringRefusal) -> Self {
        Self {
            kind: refusal.kind().to_string(),
            origin: refusal.origin_site(),
            lowering: Some(refusal),
        }
    }

    /// A cell a later proof could not account for.
    pub(crate) fn from_proof(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            origin: "render proof".to_string(),
            lowering: None,
        }
    }

    pub(crate) fn refusal(&self) -> crate::fold::op_lower::OpLoweringRefusal {
        self.lowering
            .unwrap_or_else(crate::fold::op_lower::OpLoweringRefusal::missing_machine_projection)
    }
}

impl FoldArchConfig {
    #[cfg(test)]
    pub(crate) fn for_ptr_size(ptr_size: u32) -> Self {
        let arg_regs = if ptr_size == 64 {
            vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ]
        } else {
            vec![]
        };
        Self { ptr_size, arg_regs }
    }
}

/// What one marked gap covers: the source instructions it owns and the cells
/// those instructions still owe.
pub(crate) struct GapClosure {
    pub(crate) ops: usize,
    pub(crate) sites: BTreeSet<InstId>,
    pub(crate) cells: Vec<crate::observation_journal::GapCell>,
}

impl<'a> FoldingContext<'a> {
    pub(crate) fn from_inputs(inputs: FoldInputs<'a>) -> Self {
        Self {
            symbols: std::rc::Rc::new(std::cell::RefCell::new(crate::symbol::SymbolTable::new())),
            inputs,
            state: FoldState::default(),
            current_block_addr: Cell::new(None),
            current_block_id: Cell::new(None),
            current_op_idx: Cell::new(None),
            pending_assignment_type: Cell::new(None),
            #[cfg(test)]
            inlined_renderings: std::cell::RefCell::new(HashMap::new()),
            #[cfg(test)]
            prepared_semantic_view_cache: OnceCell::new(),
            folded_blocks: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            callee_declarations: std::cell::RefCell::new(std::collections::BTreeMap::new()),
            observation_error: std::cell::RefCell::new(None),
            pending_lowering_refusal: Cell::new(None),
            gapped_sites: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            gap_anchors: std::cell::RefCell::new(std::collections::BTreeMap::new()),
        }
    }

    pub(crate) fn normalized_site(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<crate::normalize::NormalizedOpSite> {
        let block = self
            .inputs
            .prepared_ssa?
            .graph()
            .block_id_for_addr(block_addr)?;
        Some(crate::normalize::NormalizedOpSite { block, op_idx })
    }

    fn observation_site(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Result<
        crate::normalize::NormalizedOpSite,
        crate::observation_journal::LegacyObservationJournalError,
    > {
        self.normalized_site(block_addr, op_idx).ok_or(
            crate::observation_journal::LegacyObservationJournalError::MissingNormalizedBlock(
                block_addr,
            ),
        )
    }

    /// Every source cell one marked gap accounts for, from the operation that
    /// could not be lowered.
    ///
    /// The closure is forced by what a gap means. The refused operation is
    /// unproven, so every value it defines is unproven, so every statement
    /// that reads one of those values is unproven too: rendering a reader of
    /// a value nothing produced would name a variable no statement assigns.
    /// That is the forward direction. Backwards, a producer the plan inlines
    /// exists only inside its readers; when all of them are inside the gap it
    /// has no other occurrence, and the gap owns it. Both are taken to a fixed
    /// point, and nothing else is owned: a value defined outside keeps its own
    /// occurrence and only its use here is gapped.
    pub(crate) fn gap_closure(&self, block_addr: u64, op_idx: usize) -> Option<GapClosure> {
        let Some(seed) = self.source_inst_for_normalized_op(block_addr, op_idx) else {
            r2il::refusal_evidence!(
                "gap",
                "the operation at {block_addr:#x}:{op_idx} has no source instruction to anchor \
                 a gap on"
            );
            return None;
        };
        self.gap_closure_from_seed(seed)
    }

    /// The gap a seed instruction opens, and everything that reads it.
    pub(crate) fn gap_closure_from_seed(&self, seed: InstId) -> Option<GapClosure> {
        let prepared = self.inputs.prepared_ssa?;
        let names = self.inputs.binding_names?;
        let graph = prepared.graph();
        let block_addr = graph
            .inst(seed)
            .and_then(|inst| graph.block(inst.block))
            .map(|block| block.addr)?;

        // A gap stands in for computation and for effects, never for where
        // the program goes next. A return whose value cannot be proven has no
        // honest marked form: C must return something, and leaving the
        // statement out would fall off the end of a value-returning function.
        // The same holds for a transfer. Those refusals stand.
        if let Some(r2ssa::graph::InstPayload::Op(op)) = graph.inst(seed).map(|inst| &inst.payload)
            && matches!(
                op,
                r2ssa::SSAOp::Return { .. }
                    | r2ssa::SSAOp::Branch { .. }
                    | r2ssa::SSAOp::CBranch { .. }
                    | r2ssa::SSAOp::BranchInd { .. }
            )
        {
            r2il::refusal_evidence!(
                "gap",
                "the operation at {block_addr:#x} is a control transfer, which a \
                 marker cannot stand in for"
            );
            return None;
        }

        // A call takes its arguments and a return its value through the
        // convention, so neither reader is an SSA use the walk below sees.
        let mut implicit_readers: std::collections::BTreeMap<ValueId, BTreeSet<InstId>> =
            std::collections::BTreeMap::new();
        for certificate in prepared.certificates().callsites.values() {
            for value in certificate.argument_values.iter().copied().chain(
                certificate
                    .stack_argument_values
                    .iter()
                    .map(|argument| argument.value),
            ) {
                implicit_readers
                    .entry(value)
                    .or_default()
                    .insert(certificate.at);
            }
        }
        for boundary in prepared.facts().boundaries.returns.values() {
            for value in boundary.values.iter().map(|fact| fact.value).chain(
                boundary
                    .register_compositions
                    .iter()
                    .flat_map(|composition| {
                        composition
                            .ordered_definitions()
                            .map(|definition| definition.value)
                    }),
            ) {
                implicit_readers
                    .entry(value)
                    .or_default()
                    .insert(boundary.at);
            }
        }

        // A call and the `CallDefine`s certified at its site are one statement:
        // the call supplies the effect and each define owns a result lane.
        let mut statement_mates: std::collections::BTreeMap<InstId, Vec<InstId>> =
            std::collections::BTreeMap::new();
        for result in prepared.certificates().call_results.values() {
            let Some(call) = prepared
                .certificates()
                .callsites
                .get(&result.call_site)
                .map(|site| site.at)
            else {
                continue;
            };
            statement_mates.entry(call).or_default().push(result.at);
            statement_mates.entry(result.at).or_default().push(call);
        }

        let mut owned: BTreeSet<InstId> = BTreeSet::new();
        owned.insert(seed);
        let mut worklist = vec![seed];
        while let Some(inst) = worklist.pop() {
            let Some(instruction) = graph.inst(inst) else {
                continue;
            };
            for mate in statement_mates.get(&inst).into_iter().flatten().copied() {
                if owned.insert(mate) {
                    worklist.push(mate);
                }
            }
            // Forward: a statement that reads an unproven value is unproven.
            if let Some(output) = instruction.output
                && matches!(
                    names.disposition_for_value(output),
                    Some(
                        crate::binding_plan::ValueDisposition::Bound { .. }
                            | crate::binding_plan::ValueDisposition::Inline { .. }
                    )
                )
            {
                let implicit = implicit_readers.get(&output).into_iter().flatten().copied();
                for reader in graph
                    .use_sites(output)
                    .iter()
                    .map(|site| site.inst)
                    .chain(implicit)
                {
                    if owned.insert(reader) {
                        worklist.push(reader);
                    }
                }
            }
            // Backward: an inline producer read only from inside the gap has
            // nowhere else to be rendered.
            for input in instruction.inputs.iter().copied() {
                let Some(definition) = graph.def_inst(input) else {
                    continue;
                };
                if owned.contains(&definition)
                    || !matches!(
                        names.disposition_for_value(input),
                        Some(crate::binding_plan::ValueDisposition::Inline { .. })
                    )
                    || !graph
                        .use_sites(input)
                        .iter()
                        .all(|site| owned.contains(&site.inst))
                {
                    continue;
                }
                owned.insert(definition);
                worklist.push(definition);
            }
        }

        let mut cells = Vec::new();
        let mut claimed_values: BTreeSet<ValueId> = BTreeSet::new();
        for inst in &owned {
            let Some(instruction) = graph.inst(*inst) else {
                continue;
            };
            if let Some(output) = instruction.output {
                cells.push(crate::observation_journal::GapCell::Write(*inst));
                if claimed_values.insert(output) {
                    cells.push(crate::observation_journal::GapCell::Value(output));
                }
            }
            for (input_idx, input) in instruction.inputs.iter().copied().enumerate() {
                cells.push(crate::observation_journal::GapCell::Use {
                    site: UseSite {
                        inst: *inst,
                        input_idx,
                    },
                    block: block_addr,
                });
                // A value the caller supplied has no defining statement to
                // answer for it; its cell is answered wherever it is read. If
                // every one of those reads is inside the gap, the gap is the
                // only place left that can account for it.
                if graph.def_inst(input).is_none()
                    && graph
                        .use_sites(input)
                        .iter()
                        .all(|site| owned.contains(&site.inst))
                    && claimed_values.insert(input)
                {
                    cells.push(crate::observation_journal::GapCell::Value(input));
                }
            }
        }
        // A marker stands in for computation and effects, never for where
        // control goes next, so a gap that reached one has no honest form.
        if let Some(transfer) = owned.iter().copied().find(|inst| {
            matches!(
                graph.inst(*inst).map(|inst| &inst.payload),
                Some(r2ssa::graph::InstPayload::Op(
                    r2ssa::SSAOp::Return { .. }
                        | r2ssa::SSAOp::Branch { .. }
                        | r2ssa::SSAOp::CBranch { .. }
                        | r2ssa::SSAOp::BranchInd { .. }
                ))
            )
        }) {
            r2il::refusal_evidence!(
                "gap",
                "the closure from {block_addr:#x} reaches {transfer:?}, a control transfer a \
                 marker cannot stand in for"
            );
            return None;
        }
        for (id, obligation) in prepared.obligations().obligations() {
            if obligation
                .source
                .graph_inst()
                .is_some_and(|inst| owned.contains(&inst))
            {
                cells.push(crate::observation_journal::GapCell::Effect(*id));
            }
        }
        Some(GapClosure {
            ops: owned.len(),
            sites: owned,
            cells,
        })
    }

    /// Add the operation whose refusal just escaped the fold to the gap plan.
    ///
    /// The fold marks its cells as it renders, so a gap opened at the moment
    /// of refusal can find a reader has already claimed one of them. Nothing
    /// is wrong with the gap; it was learned too late. Recording its closure
    /// here lets the next attempt skip the whole closure before any of it
    /// renders, which is the only ordering in which those cells are free.
    ///
    /// Returns whether the plan grew, so a caller that retries can stop when
    /// the refusal is one no gap can cover.
    pub(crate) fn plan_gap_for_escaped_refusal(
        &self,
        refusal: crate::fold::op_lower::OpLoweringRefusal,
    ) -> bool {
        let (Some(block_addr), Some(op_idx)) =
            (self.current_block_addr.get(), self.current_op_idx.get())
        else {
            return false;
        };
        let Some(anchor) = self.source_inst_for_normalized_op(block_addr, op_idx) else {
            return false;
        };
        let Some(closure) = self.gap_closure(block_addr, op_idx) else {
            return false;
        };
        if self.gap_anchors.borrow().contains_key(&anchor) {
            return false;
        }
        self.gap_anchors
            .borrow_mut()
            .insert(anchor, GapReason::from_lowering(refusal));
        self.gapped_sites.borrow_mut().extend(closure.sites);
        r2il::refusal_evidence!(
            "gap",
            "planning a gap at {block_addr:#x}:{op_idx} over {} ops before the next \
             structuring attempt",
            closure.ops
        );
        true
    }

    /// Plan a gap at an instruction a later proof failure named.
    ///
    /// The lowering path plans from where it is; a seal or placement refusal
    /// names a cell instead, and the instruction behind that cell is the same
    /// anchor arrived at from the other end.
    pub(crate) fn plan_gap_at_anchor(&self, anchor: InstId, kind: &str) -> bool {
        if self.gap_anchors.borrow().contains_key(&anchor) {
            return false;
        }
        let Some(closure) = self.gap_closure_from_seed(anchor) else {
            return false;
        };
        self.gap_anchors
            .borrow_mut()
            .insert(anchor, GapReason::from_proof(kind));
        self.gapped_sites.borrow_mut().extend(closure.sites);
        r2il::refusal_evidence!(
            "gap",
            "planning a gap at {anchor:?} over {} ops before the next render attempt",
            closure.ops
        );
        true
    }

    /// The gap a previous attempt planned at this operation, if any.
    pub(crate) fn planned_gap_at(&self, block_addr: u64, op_idx: usize) -> Option<GapReason> {
        let anchor = self.source_inst_for_normalized_op(block_addr, op_idx)?;
        self.gap_anchors.borrow().get(&anchor).cloned()
    }

    /// Whether a marked gap accounts for the operation at this normalized site.
    ///
    /// A copy normalization made for a merge has no source instruction of its
    /// own; it belongs to the merge, and is gapped exactly when the merge is.
    pub(crate) fn normalized_op_is_gapped(&self, block_addr: u64, op_idx: usize) -> bool {
        let Some(site) = self.normalized_site(block_addr, op_idx) else {
            return false;
        };
        let inst = match self
            .inputs
            .normalization_origins
            .and_then(|origins| origins.origin(site))
        {
            Some(crate::normalize::NormalizedOpOrigin::Original(inst)) => Some(*inst),
            Some(crate::normalize::NormalizedOpOrigin::PhiEdgeCopy(origin)) => {
                Some(origin.definition.inst)
            }
            Some(crate::normalize::NormalizedOpOrigin::RelocatedInitializer(origin)) => {
                Some(origin.definition.inst)
            }
            None => self.source_inst_for_normalized_site(site),
        };
        inst.is_some_and(|inst| self.gapped_sites.borrow().contains(&inst))
    }

    /// Whether a marked gap accounts for the definition of this value, which
    /// means no statement in the output assigns it.
    pub(crate) fn value_is_gapped(&self, value: ValueId) -> bool {
        let Some(prepared) = self.inputs.prepared_ssa else {
            return false;
        };
        prepared
            .graph()
            .def_inst(value)
            .is_some_and(|inst| self.gapped_sites.borrow().contains(&inst))
    }

    /// Open a marked gap for a refusal, or refuse as before when the journal
    /// cannot account for one of its cells.
    ///
    /// A gap that could not mark every cell it covers is worse than a refusal:
    /// the cells it missed would seal as unaccounted and the failure would be
    /// reported as a decompiler defect rather than as the unproven operation
    /// it is. So the marking is all or nothing.
    pub(crate) fn open_gap(
        &self,
        block_addr: u64,
        op_idx: usize,
        reason: &GapReason,
    ) -> Option<(crate::ast::CStmt, BTreeSet<InstId>)> {
        let Some(journal) = self.inputs.observation_journal else {
            r2il::refusal_evidence!(
                "gap",
                "no observation journal at {block_addr:#x}:{op_idx}, so nothing can account \
                 for the cells a gap would cover"
            );
            return None;
        };
        let Some(closure) = self.gap_closure(block_addr, op_idx) else {
            r2il::refusal_evidence!(
                "gap",
                "no closure for the refusal at {block_addr:#x}:{op_idx}"
            );
            return None;
        };
        let anchor = crate::shadow_report::GapAnchor {
            block_addr,
            op_idx: u32::try_from(op_idx).ok()?,
        };
        let marker = crate::ast::GapMarker {
            kind: reason.kind.clone(),
            origin: reason.origin.clone(),
            block_addr,
            op_idx,
            ops: closure.ops,
        };
        match journal
            .borrow_mut()
            .gap_stmt(anchor, marker, &closure.cells)
        {
            Ok(stmt) => {
                // A gap that opens is as load-bearing as one that refuses: it
                // claims cells, and a cell the rendering also answers is a
                // second reader nothing else reports.
                r2il::refusal_evidence!(
                    "gap",
                    "opened at {block_addr:#x}:{op_idx} for {} over {} ops, claiming {} cells: {:?}",
                    reason.kind,
                    closure.ops,
                    closure.cells.len(),
                    closure.sites
                );
                Some((stmt, closure.sites))
            }
            Err(error) => {
                r2il::refusal_evidence!(
                    "gap",
                    "the journal refused {} cells over {} ops at {block_addr:#x}:{op_idx}: {error:?}",
                    closure.cells.len(),
                    closure.ops
                );
                self.retain_first_observation_error(error);
                None
            }
        }
    }

    pub(super) fn retain_first_observation_error(
        &self,
        error: crate::observation_journal::LegacyObservationJournalError,
    ) {
        if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
            eprintln!("OBSERVATION_ERROR {error:?}");
        }
        let mut first = self.observation_error.borrow_mut();
        if first.is_none() {
            *first = Some(error);
        }
    }

    /// Store the first refusal this fold decided, and say where.
    ///
    /// A stored refusal is raised later by whoever finishes the transaction, so
    /// it does not pass through any of the propagation paths and instrumenting
    /// those never finds it. This is the only place it can be caught, which is
    /// why the location is captured here rather than left to be rediscovered.
    #[track_caller]
    pub(super) fn retain_first_lowering_refusal(
        &self,
        refusal: crate::fold::op_lower::OpLoweringRefusal,
    ) {
        if self.pending_lowering_refusal.get().is_none() {
            if std::env::var_os("R2DEC_TRACE_REFUSAL").is_some() {
                eprintln!(
                    "refusal {refusal:?} retained at {}",
                    std::panic::Location::caller()
                );
            }
            self.pending_lowering_refusal.set(Some(refusal));
        }
    }

    /// Materialize one cached fold as a distinct final-AST occurrence.
    ///
    /// Folding is stateful and must not be replayed merely to obtain fresh
    /// diagnostic identities. The journal duplicates its own authority-bound
    /// targets; on allocation failure the semantic clone survives marker-free
    /// and the typed audit failure is retained.
    pub(crate) fn clone_cached_render_occurrence(
        &self,
        stmts: &[crate::ast::CStmt],
    ) -> Vec<crate::ast::CStmt> {
        let Some(journal) = self.inputs.observation_journal else {
            return stmts.to_vec();
        };
        let fallback = stmts
            .iter()
            .map(crate::ast::CStmt::clone_without_render_observations)
            .collect();
        match journal.borrow_mut().clone_render_occurrence(stmts) {
            Ok(clone) => clone,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    pub(crate) fn observe_optional_normalized_input_uses_expr(
        &self,
        site: Option<crate::normalize::NormalizedOpSite>,
        input_idx: usize,
        expr: CExpr,
    ) -> CExpr {
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let Some(site) = site else {
            self.retain_first_observation_error(
                crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
            );
            return expr;
        };
        let fallback = expr.clone();
        match journal
            .borrow_mut()
            .observe_normalized_input_uses_expr(site, input_idx, expr)
        {
            Ok(marked) => marked,
            Err(error) => {
                r2il::refusal_evidence!("input-use-observation", "{error:?} at {site:?}");
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    /// The obligations a definition carries, asked of the source instruction
    /// rather than of a normalized site.
    ///
    /// A definition rendered where its value is read has no normalized site of
    /// its own to ask about, and its obligations are otherwise never requested
    /// at all, which the ledger scores as refused.
    pub(crate) fn exact_effect_obligations_for_source_inst(
        &self,
        kind: EffectOccurrenceKind,
        source_inst: r2ssa::InstId,
        value: Option<ValueId>,
    ) -> BTreeSet<SemanticObligationId> {
        self.exact_value_obligations(kind, source_inst, value.as_slice())
    }

    pub(crate) fn observe_certified_value_read_expr(
        &self,
        value: r2ssa::ValueId,
        at: r2ssa::InstId,
        expr: CExpr,
    ) -> CExpr {
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let fallback = expr.clone();
        let Some(symbol) = self
            .inputs
            .binding_names
            .and_then(|names| names.symbol_for_value(value))
        else {
            self.retain_first_observation_error(
                crate::observation_journal::LegacyObservationJournalError::rendered_value_required(
                    value,
                    crate::observation_journal::RenderedValueRequirementCause::CertifiedValueReadMissingSymbol,
                    self.inputs
                        .binding_names
                        .and_then(|names| names.disposition_for_value(value)),
                ),
            );
            return fallback;
        };
        match journal
            .borrow_mut()
            .observe_certified_value_read_expr(value, at, symbol, expr)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    pub(crate) fn observe_certified_address_read_expr(
        &self,
        value: r2ssa::ValueId,
        access: r2ssa::StructuredAccessId,
        expr: CExpr,
    ) -> CExpr {
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let fallback = expr.clone();
        let Some(symbol) = self
            .inputs
            .binding_names
            .and_then(|names| names.symbol_for_value(value))
        else {
            self.retain_first_observation_error(
                crate::observation_journal::LegacyObservationJournalError::rendered_value_required(
                    value,
                    crate::observation_journal::RenderedValueRequirementCause::CertifiedAddressReadMissingSymbol,
                    self.inputs
                        .binding_names
                        .and_then(|names| names.disposition_for_value(value)),
                ),
            );
            return fallback;
        };
        match journal
            .borrow_mut()
            .observe_certified_address_read_expr(value, access, symbol, expr)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    pub(crate) fn observe_certified_array_index_expr(
        &self,
        access: r2ssa::StructuredAccessId,
        value: r2ssa::ValueId,
        expr: CExpr,
    ) -> CExpr {
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let fallback = expr.clone();
        let Some(symbol) = self
            .inputs
            .binding_names
            .and_then(|names| names.symbol_for_value(value))
        else {
            self.retain_first_observation_error(
                crate::observation_journal::LegacyObservationJournalError::rendered_value_required(
                    value,
                    crate::observation_journal::RenderedValueRequirementCause::CertifiedAddressReadMissingSymbol,
                    self.inputs
                        .binding_names
                        .and_then(|names| names.disposition_for_value(value)),
                ),
            );
            return fallback;
        };
        match journal
            .borrow_mut()
            .observe_certified_array_index_expr(access, value, symbol, expr)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    /// Wrap one exact normalized definition that survives as a statement.
    pub(crate) fn observe_normalized_output_stmt(
        &self,
        block_addr: u64,
        op_idx: usize,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let Some(journal) = self.inputs.observation_journal else {
            return stmt;
        };
        let fallback = stmt.clone();
        let result = self.observation_site(block_addr, op_idx).and_then(|site| {
            journal
                .borrow_mut()
                .observe_normalized_output_stmt(site, stmt)
        });
        match result {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    /// Whether this instruction's statement is spoken for by the write whose
    /// projection absorbed it. The same question as
    /// [`Self::absorbed_extensions_discharged_by`], asked from the other side,
    /// so the two cannot disagree.
    pub(crate) fn write_is_discharged_by_absorbing_write(&self, inst: r2ssa::InstId) -> bool {
        let Some(head) = self.inputs.binding_names.and_then(|names| {
            names
                .plan()
                .machine_projection()
                .immediate_absorbing_write(inst)
        }) else {
            return false;
        };
        self.absorbed_extensions_discharged_by(head).contains(&inst)
    }

    /// The carrier extensions a definition's statement speaks for.
    ///
    /// The machine projection says which extensions certified a write as a
    /// zero-extension into its carrier -- `EAX = x` followed by
    /// `RAX = zext(EAX)` -- and that is a fact about the machine. Whether the
    /// extension then has anything left to say is the plan's question: where
    /// the write and the extension are one rendered object, the statement
    /// `x = (uint64_t)(uint32_t)...` has already performed the extension, and
    /// rendering it again spells `x = (uint64_t)(uint32_t)x`. Where they are
    /// two objects the extension is a real assignment from one to the other
    /// and keeps its statement. The chain is taken as a prefix: an extension
    /// that lands in another object ends what this statement can stand for.
    pub(crate) fn absorbed_extensions_discharged_by(
        &self,
        inst: r2ssa::InstId,
    ) -> Vec<r2ssa::InstId> {
        let (Some(names), Some(prepared)) = (self.inputs.binding_names, self.inputs.prepared_ssa)
        else {
            return Vec::new();
        };
        let graph = prepared.graph();
        let projection = names.plan().machine_projection();
        let Some(crate::binding_plan::ValueDisposition::Bound { binding }) = graph
            .inst(inst)
            .and_then(|inst| inst.output)
            .and_then(|output| names.disposition_for_value(output))
        else {
            return Vec::new();
        };
        let mut discharged = Vec::new();
        for member in projection.absorbed_extensions(inst) {
            let same_object = graph
                .inst(*member)
                .and_then(|inst| inst.output)
                .and_then(|output| names.disposition_for_value(output))
                .is_some_and(|disposition| {
                    matches!(disposition, crate::binding_plan::ValueDisposition::Bound { binding: other } if other == binding)
                });
            if !same_object {
                break;
            }
            discharged.push(*member);
        }
        discharged
    }

    /// Statement twin of [`Self::observe_discharged_expr`]: the cells and the
    /// effects of the instructions a rendered definition's projection stands
    /// for, on that definition's statement.
    /// `already` is the obligation set the caller will mark on this same
    /// statement for its own operation. A machine instruction lifts to several
    /// p-code operations, so a narrow write and the carrier clear that
    /// certifies it are frequently *one* `CanonicalInstructionId` carrying one
    /// obligation. Marking it here as well as there renders it twice, and the
    /// ledger scores an obligation with two occurrences as
    /// `DuplicateRenderedOccurrence` -- which is a refusal, and the right one:
    /// two occurrences of one effect is exactly what it is there to catch.
    pub(crate) fn observe_discharged_stmt(
        &self,
        discharged: &[r2ssa::InstId],
        already: &BTreeSet<SemanticObligationId>,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let Some(journal) = self.inputs.observation_journal else {
            return stmt;
        };
        let fallback = stmt.clone();
        let marked = match journal
            .borrow_mut()
            .observe_discharged_stmt(discharged, stmt)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                return fallback;
            }
        };
        self.observe_discharged_effects(discharged, already, marked)
    }

    /// The cells and effects a bound value's canonical-term assignment owes,
    /// on that assignment. See
    /// [`LegacyObservationJournal::observe_canonical_assignment_stmt`]: the
    /// producers the term absorbed and the operands it dropped are both
    /// answered here, because neither is answered by the statement's own
    /// markers.
    pub(crate) fn observe_canonical_assignment_stmt(
        &self,
        value: ValueId,
        definition: r2ssa::InstId,
        absorbed: &[r2ssa::InstId],
        already: &BTreeSet<SemanticObligationId>,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let Some(journal) = self.inputs.observation_journal else {
            return stmt;
        };
        let fallback = stmt.clone();
        let marked = match journal
            .borrow_mut()
            .observe_canonical_assignment_stmt(value, definition, absorbed, stmt)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                return fallback;
            }
        };
        self.observe_discharged_effects(absorbed, already, marked)
    }

    /// Mark the source effects the discharged instructions carry, less the
    /// ones the caller marks on this same statement for its own operation.
    fn observe_discharged_effects(
        &self,
        discharged: &[r2ssa::InstId],
        already: &BTreeSet<SemanticObligationId>,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let obligations = self
            .discharged_obligations(discharged)
            .difference(already)
            .copied()
            .collect();
        self.observe_effect_stmt(&obligations, stmt)
    }

    /// The source effects the instructions a statement discharges carry.
    pub(crate) fn discharged_obligations(
        &self,
        discharged: &[r2ssa::InstId],
    ) -> BTreeSet<SemanticObligationId> {
        let mut obligations = BTreeSet::new();
        for definition in discharged {
            let output = self
                .inputs
                .prepared_ssa
                .and_then(|prepared| prepared.graph().inst(*definition))
                .and_then(|inst| inst.output);
            obligations.extend(self.exact_effect_obligations_for_source_inst(
                EffectOccurrenceKind::Expression,
                *definition,
                output,
            ));
        }
        obligations
    }

    /// Attach exact source-effect cells to the statement occurrence that
    /// discharges them. No construction-time side table participates: if this
    /// statement is deleted, its markers are deleted with it.
    pub(crate) fn observe_effect_stmt(
        &self,
        obligation_ids: &BTreeSet<SemanticObligationId>,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let Some(journal) = self.inputs.observation_journal else {
            return stmt;
        };
        if obligation_ids.is_empty() {
            return stmt;
        }
        let fallback = stmt.clone();
        match journal
            .borrow_mut()
            .observe_effect_stmt(obligation_ids, stmt)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    /// Attach a composite statement's implicit effects without duplicating an
    /// exact effect marker already carried by one of its child statements.
    pub(crate) fn observe_composite_effect_stmt(
        &self,
        obligation_ids: &BTreeSet<SemanticObligationId>,
        stmt: crate::ast::CStmt,
    ) -> crate::ast::CStmt {
        let Some(journal) = self.inputs.observation_journal else {
            return stmt;
        };
        if obligation_ids.is_empty() {
            return stmt;
        }
        let fallback = stmt.clone();
        match journal
            .borrow_mut()
            .observe_composite_effect_stmt(obligation_ids, stmt)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    /// O(1) origin lookup once the caller holds the normalized block's dense id.
    pub(crate) fn source_inst_for_normalized_site(
        &self,
        site: crate::normalize::NormalizedOpSite,
    ) -> Option<InstId> {
        if let Some(origins) = self.inputs.normalization_origins {
            return match origins.origin(site)? {
                crate::normalize::NormalizedOpOrigin::Original(inst) => Some(*inst),
                crate::normalize::NormalizedOpOrigin::PhiEdgeCopy(_)
                | crate::normalize::NormalizedOpOrigin::RelocatedInitializer(_) => None,
            };
        }

        // A context without normalization origins is walking the unchanged
        // source function (principally focused unit tests). This is not a
        // fallback for a malformed normalized artifact: once an origins table
        // is supplied, only `Original` rows above can reach source facts.
        let graph = self.inputs.prepared_ssa?.graph();
        let block = graph.block(site.block)?;
        graph.inst_id_for_op_site(block.addr, site.op_idx)
    }

    pub(crate) fn source_inst_for_normalized_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<InstId> {
        self.source_inst_for_normalized_site(self.normalized_site(block_addr, op_idx)?)
    }

    pub(crate) fn source_op_site_for_normalized_op(
        &self,
        block_addr: u64,
        op_idx: usize,
    ) -> Option<(u64, usize)> {
        if self.inputs.normalization_origins.is_none() {
            return Some((block_addr, op_idx));
        }
        let inst = self.source_inst_for_normalized_op(block_addr, op_idx)?;
        self.inputs.prepared_ssa?.inst_op_site(inst)
    }

    pub(crate) fn current_source_op_site(&self) -> Option<(u64, usize)> {
        let block_addr = self.current_block_addr.get()?;
        let op_idx = self.current_op_idx.get()?;
        if let Some(block) = self.current_block_id.get() {
            let inst =
                self.source_inst_for_normalized_site(crate::normalize::NormalizedOpSite {
                    block,
                    op_idx,
                })?;
            return self.inputs.prepared_ssa?.inst_op_site(inst);
        }
        self.source_op_site_for_normalized_op(block_addr, op_idx)
    }

    pub(crate) fn is_unconditional_materialized_phi_edge_copy(
        &self,
        block_addr: u64,
        op_idx: usize,
        successor: u64,
    ) -> bool {
        let Some(site) = self.normalized_site(block_addr, op_idx) else {
            return false;
        };
        self.inputs
            .normalization_origins
            .is_some_and(|origins| origins.is_unconditional_phi_edge_copy(site, successor))
    }

    /// Takes every value the occurrence carries, because a return can carry
    /// more than one: a composed ABI register is a base with ordered overlays
    /// laid over it, and each of them is seeded as its own obligation.
    fn exact_value_obligations(
        &self,
        kind: EffectOccurrenceKind,
        source_inst: InstId,
        values: &[ValueId],
    ) -> BTreeSet<SemanticObligationId> {
        use r2ssa::SemanticObligationKind as ObligationKind;

        // Every occurrence but a composed return carries at most one value,
        // and the rules below are written about that one.
        let value: Option<ValueId> = match values {
            [single] => Some(*single),
            _ => None,
        };
        let Some(prepared) = self.inputs.prepared_ssa else {
            return BTreeSet::new();
        };
        let Some(inst) = prepared.graph().inst(source_inst) else {
            return BTreeSet::new();
        };
        let source_site = prepared.inst_op_site(source_inst);
        let call_fact = source_site.and_then(|(block_addr, op_idx)| {
            self.inputs
                .call_render_facts()?
                .fact_for_site(r2types::CallsiteKey {
                    block_addr,
                    op_index: op_idx,
                })
        });
        // A return is certified when the plan says which value it carries, and
        // also when the source says it carries none.
        //
        // Only the first was asked, so a function returning nothing could not
        // discharge its own `Return` obligation: no return-value fact exists for
        // a void boundary, and none ever will. The obligation was scored
        // unaccounted and the function refused for the one statement it had
        // certainly rendered. A complete boundary with no values and no
        // compositions is the source's own statement that the return carries
        // nothing, which is exactly what `return;` renders.
        let void_return = values.is_empty()
            && prepared
                .facts()
                .boundaries
                .returns
                .get(&source_inst)
                .is_some_and(|boundary| {
                    boundary.at == source_inst
                        && boundary.complete
                        && boundary.values.is_empty()
                        && boundary.register_compositions.is_empty()
                });
        let return_certified = void_return
            || source_site
                .and_then(|(block_addr, op_idx)| {
                    self.inputs
                        .render_facts()?
                        .return_for_op(block_addr, op_idx)
                })
                .is_some_and(|fact| fact.values().eq(values.iter().copied()));
        let rendered_call = call_fact.filter(|fact| {
            !matches!(
                fact.disposition,
                r2types::CallsiteRenderDisposition::Residualized
            )
        });
        // Every carried value owns exactly one return-value obligation. A
        // composed return discharges all of them at the one expression that
        // reassembles it, so a value whose obligation is ambiguous disqualifies
        // the whole occurrence rather than being silently dropped from it.
        // One return-value obligation carries the whole composition, with every
        // value it is assembled from as its ordered inputs -- not one
        // obligation per value, which is what this first assumed and what the
        // ledger disproved: `inputs=[ValueId(11), ValueId(32)]` on a single
        // obligation. A composed return discharges that one obligation at the
        // one expression that reassembles it.
        let unique_return_value = !values.is_empty()
            && prepared
                .obligations()
                .obligations_for_inst(source_inst)
                .filter(|obligation| {
                    obligation.id.kind == ObligationKind::ReturnValue
                        && obligation.inputs.as_slice() == values
                })
                .count()
                == 1;
        let unique_call_result = value.is_some_and(|value| {
            prepared
                .obligations()
                .obligations_for_inst(source_inst)
                .filter(|obligation| {
                    obligation.id.kind == ObligationKind::CallResult && obligation.inputs == [value]
                })
                .count()
                == 1
        });

        let mut obligation_ids = BTreeSet::new();
        for obligation in prepared.obligations().obligations_for_inst(source_inst) {
            let exact = match kind {
                EffectOccurrenceKind::Return => {
                    return_certified
                        && (obligation.id.kind == ObligationKind::Return
                            || (obligation.id.kind == ObligationKind::ReturnValue
                                && unique_return_value
                                && obligation.inputs.as_slice() == values))
                }
                EffectOccurrenceKind::Expression => match &inst.payload {
                    r2ssa::InstPayload::Op(
                        r2ssa::SSAOp::Branch { .. } | r2ssa::SSAOp::BranchInd { .. },
                    ) => {
                        obligation.id.kind == ObligationKind::ControlTransfer
                            || rendered_call.is_some_and(|fact| {
                                fact.disposition.is_terminal_return()
                                    && (obligation.id.kind == ObligationKind::Call
                                        || (obligation.id.kind == ObligationKind::CallArgument
                                            && !obligation.inputs.is_empty()
                                            && obligation
                                                .inputs
                                                .iter()
                                                .all(|input| fact.proof_values.contains(input))))
                            })
                    }
                    r2ssa::InstPayload::Op(r2ssa::SSAOp::CBranch { .. }) => matches!(
                        obligation.id.kind,
                        ObligationKind::ControlPredicate | ObligationKind::ControlTransfer
                    ),
                    r2ssa::InstPayload::Op(
                        r2ssa::SSAOp::Call { .. } | r2ssa::SSAOp::CallInd { .. },
                    ) => {
                        if obligation.id.kind == ObligationKind::CallArgument
                            && obligation.inputs.is_empty()
                        {
                            r2il::refusal_evidence!(
                                "call-argument-occurrence",
                                "component={:?} has no inputs, so no rendering can discharge it; \
                                 rendered_call={} proof_values={:?}",
                                obligation.id.component,
                                rendered_call.is_some(),
                                rendered_call.map(|fact| fact.proof_values.clone())
                            );
                        }
                        rendered_call.is_some()
                            && (obligation.id.kind == ObligationKind::Call
                                || (obligation.id.kind == ObligationKind::CallArgument
                                    && !obligation.inputs.is_empty()
                                    && obligation.inputs.iter().all(|input| {
                                        rendered_call
                                            .is_some_and(|fact| fact.proof_values.contains(input))
                                    }))
                                || (obligation.id.kind == ObligationKind::CallResult
                                    && unique_call_result
                                    && obligation.inputs.as_slice() == value.as_slice()))
                    }
                    r2ssa::InstPayload::Op(
                        r2ssa::SSAOp::IntDiv { .. }
                        | r2ssa::SSAOp::IntSDiv { .. }
                        | r2ssa::SSAOp::IntRem { .. }
                        | r2ssa::SSAOp::IntSRem { .. },
                    ) => {
                        inst.output == value
                            && matches!(
                                obligation.id.kind,
                                ObligationKind::LiveValueProducer | ObligationKind::Trap
                            )
                    }
                    // A trap renders as the statement that takes it --
                    // `__builtin_trap()` -- and that statement produces no
                    // value, so the occurrence carries none either. Without
                    // this arm the trap fell to the value-producer case below,
                    // which no valueless statement can satisfy, and every
                    // function containing a guard instruction was refused for
                    // an effect it had in fact rendered.
                    r2ssa::InstPayload::Op(r2ssa::SSAOp::Breakpoint) => {
                        obligation.id.kind == ObligationKind::Trap && inst.output == value
                    }
                    _ => {
                        obligation.id.kind == ObligationKind::LiveValueProducer
                            && inst.output == value
                    }
                },
                EffectOccurrenceKind::MemoryRead | EffectOccurrenceKind::MemoryWrite => false,
            };
            if exact {
                obligation_ids.insert(obligation.id);
            }
        }
        obligation_ids
    }

    fn exact_effect_obligations_for_phi_edges(
        &self,
        definition: InstId,
        sites: &[UseSite],
    ) -> BTreeSet<SemanticObligationId> {
        use r2ssa::{SemanticObligationComponent, SemanticObligationKind};

        let Some(prepared) = self.inputs.prepared_ssa else {
            return BTreeSet::new();
        };
        let graph = prepared.graph();
        let mut obligation_ids = BTreeSet::new();
        for site in sites {
            for obligation in prepared.obligations().obligations_for_inst(definition) {
                if obligation.id.kind == SemanticObligationKind::LiveStateTransition
                    && matches!(
                        obligation.id.component,
                        SemanticObligationComponent::LoopTransition { .. }
                    )
                    && obligation.edge_use == Some(*site)
                    && obligation.inputs
                        == graph
                            .inst(site.inst)
                            .and_then(|inst| inst.inputs.get(site.input_idx))
                            .copied()
                            .into_iter()
                            .collect::<Vec<_>>()
                {
                    obligation_ids.insert(obligation.id);
                }
            }
        }
        obligation_ids
    }

    /// Exact source obligations discharged by one normalized value
    /// occurrence. Synthetic phi copies project only their named original
    /// edge obligations; ordinary operations project only their source InstId.
    pub(crate) fn exact_effect_obligations_for_normalized_value(
        &self,
        kind: EffectOccurrenceKind,
        block_addr: u64,
        op_idx: usize,
        value: Option<ValueId>,
    ) -> BTreeSet<SemanticObligationId> {
        self.exact_effect_obligations_for_normalized_values(
            kind,
            block_addr,
            op_idx,
            value.as_slice(),
        )
    }

    /// The occurrence carries several values, which only a composed return
    /// does: its ABI register is a base with ordered overlays laid over it and
    /// every one of them owns an obligation the single expression discharges.
    pub(crate) fn exact_effect_obligations_for_normalized_values(
        &self,
        kind: EffectOccurrenceKind,
        block_addr: u64,
        op_idx: usize,
        values: &[ValueId],
    ) -> BTreeSet<SemanticObligationId> {
        let Some(site) = self.normalized_site(block_addr, op_idx) else {
            return BTreeSet::new();
        };
        let Some(origins) = self.inputs.normalization_origins else {
            return self
                .source_inst_for_normalized_site(site)
                .map(|inst| self.exact_value_obligations(kind, inst, values))
                .unwrap_or_default();
        };
        match origins.origin(site) {
            Some(crate::normalize::NormalizedOpOrigin::Original(inst)) => {
                self.exact_value_obligations(kind, *inst, values)
            }
            Some(crate::normalize::NormalizedOpOrigin::PhiEdgeCopy(origin)) => self
                .exact_effect_obligations_for_phi_edges(
                    origin.definition.inst,
                    std::slice::from_ref(&origin.incoming),
                ),
            Some(crate::normalize::NormalizedOpOrigin::RelocatedInitializer(origin)) => self
                .exact_effect_obligations_for_phi_edges(
                    origin.definition.inst,
                    &origin.replaced_sites,
                ),
            None => BTreeSet::new(),
        }
    }

    fn exact_effect_obligations_for_inst_memory(
        &self,
        kind: EffectOccurrenceKind,
        source_inst: InstId,
        space: r2il::SpaceId,
        address: Option<ValueId>,
        value: Option<ValueId>,
    ) -> BTreeSet<SemanticObligationId> {
        use r2ssa::{SemanticObligationComponent, SemanticObligationKind};

        let Some(prepared) = self.inputs.prepared_ssa else {
            return BTreeSet::new();
        };
        let Some((block_addr, op_idx)) = prepared.inst_op_site(source_inst) else {
            return BTreeSet::new();
        };
        let is_write = kind == EffectOccurrenceKind::MemoryWrite;
        let Some(fact) = self
            .inputs
            .render_facts()
            .and_then(|facts| facts.memory_access_for_op(block_addr, op_idx, is_write, space))
            .filter(|fact| {
                fact.access.inst == source_inst
                    && address == Some(fact.address)
                    && fact.value == value
                    && fact.is_write == is_write
            })
        else {
            return BTreeSet::new();
        };
        let expected_inputs = address
            .into_iter()
            .chain(is_write.then_some(value).flatten())
            .collect::<Vec<ValueId>>();
        prepared
            .obligations()
            .obligations_for_inst(source_inst)
            .filter(|obligation| {
                obligation.id.kind
                    == if is_write {
                        SemanticObligationKind::ObservableMemoryWrite
                    } else {
                        SemanticObligationKind::ObservableMemoryRead
                    }
                    && obligation.id.component
                        == SemanticObligationComponent::MemoryAccess(fact.access.ordinal)
                    && obligation.inputs == expected_inputs
            })
            .map(|obligation| obligation.id)
            .collect::<BTreeSet<_>>()
    }

    /// The write obligation one member of a decomposed wide store carries.
    pub(crate) fn exact_effect_obligations_for_member_access(
        &self,
        source_inst: InstId,
        access: r2ssa::StructuredAccessId,
        address: ValueId,
    ) -> BTreeSet<SemanticObligationId> {
        use r2ssa::{SemanticObligationComponent, SemanticObligationKind};

        let Some(prepared) = self.inputs.prepared_ssa else {
            return BTreeSet::new();
        };
        let Some((block_addr, op_idx)) = prepared.inst_op_site(source_inst) else {
            return BTreeSet::new();
        };
        let Some(fact) = self
            .inputs
            .render_facts()
            .and_then(|facts| facts.memory_access_for_access(block_addr, op_idx, true, access))
            .filter(|fact| {
                fact.access.inst == source_inst
                    && fact.address == address
                    && fact.value.is_none()
                    && fact.is_write
            })
        else {
            return BTreeSet::new();
        };
        prepared
            .obligations()
            .obligations_for_inst(source_inst)
            .filter(|obligation| {
                obligation.id.kind == SemanticObligationKind::ObservableMemoryWrite
                    && obligation.id.component
                        == SemanticObligationComponent::MemoryAccess(fact.access.ordinal)
                    && obligation.inputs == [address]
            })
            .map(|obligation| obligation.id)
            .collect::<BTreeSet<_>>()
    }

    pub(crate) fn exact_effect_obligations_for_normalized_memory(
        &self,
        kind: EffectOccurrenceKind,
        block_addr: u64,
        op_idx: usize,
        space: r2il::SpaceId,
        address: Option<ValueId>,
        value: Option<ValueId>,
    ) -> BTreeSet<SemanticObligationId> {
        self.source_inst_for_normalized_op(block_addr, op_idx)
            .map(|inst| {
                self.exact_effect_obligations_for_inst_memory(kind, inst, space, address, value)
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn exact_effect_obligations_for_source_memory(
        &self,
        kind: EffectOccurrenceKind,
        block_addr: u64,
        op_idx: usize,
        space: r2il::SpaceId,
        address: Option<ValueId>,
        value: Option<ValueId>,
    ) -> BTreeSet<SemanticObligationId> {
        self.inputs
            .prepared_ssa
            .and_then(|prepared| prepared.graph().inst_id_for_op_site(block_addr, op_idx))
            .map(|inst| {
                self.exact_effect_obligations_for_inst_memory(kind, inst, space, address, value)
            })
            .unwrap_or_default()
    }

    /// Internal/test convenience constructor. It deliberately has no
    /// source-owned authority and therefore cannot be a public render entry.
    #[cfg(test)]
    pub(crate) fn new(ptr_size: u32) -> Self {
        #[cfg(test)]
        static EMPTY_U64_STRING: OnceLock<HashMap<u64, String>> = OnceLock::new();
        #[cfg(test)]
        static EMPTY_STACK_SLOTS: OnceLock<BTreeMap<StackSlotKey, ExternalStackSlotSpec>> =
            OnceLock::new();
        #[cfg(test)]
        static EMPTY_VISIBLE_BINDINGS: OnceLock<Vec<VisibleBinding>> = OnceLock::new();
        static ARCH64: OnceLock<FoldArchConfig> = OnceLock::new();
        static ARCH32: OnceLock<FoldArchConfig> = OnceLock::new();

        let arch = match ptr_size {
            64 => ARCH64.get_or_init(|| FoldArchConfig::for_ptr_size(64)),
            32 => ARCH32.get_or_init(|| FoldArchConfig::for_ptr_size(32)),
            other => Box::leak(Box::new(FoldArchConfig::for_ptr_size(other))),
        };

        let inputs = FoldInputs {
            normalization_origins: None,
            observation_journal: None,
            binding_names: None,
            arch,
            #[cfg(test)]
            function_names: EMPTY_U64_STRING.get_or_init(HashMap::new),
            #[cfg(test)]
            binary_symbols: EMPTY_U64_STRING.get_or_init(HashMap::new),
            function_facts: empty_function_facts(),
            #[cfg(test)]
            stack_slots: EMPTY_STACK_SLOTS.get_or_init(BTreeMap::new),
            #[cfg(test)]
            visible_bindings: EMPTY_VISIBLE_BINDINGS.get_or_init(Vec::new),
            function_return_type: None,
            prepared_ssa: None,
            prepared_semantic_view: None,
        };

        Self::from_inputs(inputs)
    }
}
