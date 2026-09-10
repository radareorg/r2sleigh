//! Control structure: the dominator-tree placement of
//! `doc/adr-structure-dominator-tree.md`, the certificate that checks the
//! text against the CFG, and the rewrites that shape it afterwards.

pub(crate) mod certify;
mod place;
mod rewrite;
mod shape;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use r2ssa::{PredicateId, SSAFunction, SSAOp, ValueId};

use crate::ast::{CExpr, CStmt};
use crate::control::{DecompileExecutionStop, DecompileWorkControl};
use crate::fold::FoldingContext;
use crate::fold::op_lower::OpLoweringRefusal;
use crate::structured_region::{
    SealedStructuredBody, StructuredRegionBuildError, StructuredRegionKind, StructuredRegionMarker,
    seal_structured_body,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlFlowStructureError {
    Lowering(OpLoweringRefusal),
    StructuredRegion(StructuredRegionBuildError),
}

impl From<OpLoweringRefusal> for ControlFlowStructureError {
    #[track_caller]
    fn from(error: OpLoweringRefusal) -> Self {
        if std::env::var_os("R2DEC_TRACE_REFUSAL").is_some() {
            eprintln!(
                "refusal {error:?} left lowering at {}",
                std::panic::Location::caller()
            );
        }
        Self::Lowering(error)
    }
}

impl From<StructuredRegionBuildError> for ControlFlowStructureError {
    fn from(error: StructuredRegionBuildError) -> Self {
        Self::StructuredRegion(error)
    }
}

pub(crate) type ControlFlowStructureResult<T> = Result<T, ControlFlowStructureError>;

/// Writes a function's blocks as C control, by the placement.
pub(crate) struct ControlFlowStructurer<'a, 'o> {
    func: &'a SSAFunction,
    fold_ctx: &'o FoldingContext<'o>,
    /// Cached folded statements per basic block.
    folded_block_cache: HashMap<u64, FoldedBlock>,
    /// Labels for blocks some edge jumps to.
    labels: HashMap<u64, String>,
    label_counter: usize,
    control: Option<DecompileWorkControl<'a>>,
    stop_reason: Cell<Option<DecompileExecutionStop>>,
    /// Counted loops whose initializer and update move into the `for` header.
    certified_for_regions: BTreeMap<u64, CertifiedForRegion>,
    certified_for_header_sites: BTreeSet<crate::normalize::NormalizedOpSite>,
    /// What each rewrite stage did, for the census.
    rewrite_outcomes: Vec<String>,
}

#[derive(Debug, Clone)]
struct FoldedBlock {
    stmts: Vec<crate::fold::op_lower::FoldedOpStmt>,
}

#[derive(Debug, Clone)]
struct CertifiedForRegion {
    init: CStmt,
    update: CExpr,
}

impl<'a, 'o> ControlFlowStructurer<'a, 'o> {
    #[cfg(test)]
    pub(crate) fn new(func: &'a SSAFunction, fold_ctx: &'o FoldingContext<'o>) -> Self {
        Self {
            func,
            fold_ctx,
            folded_block_cache: HashMap::new(),
            labels: HashMap::new(),
            label_counter: 0,
            control: None,
            stop_reason: Cell::new(None),
            certified_for_regions: BTreeMap::new(),
            certified_for_header_sites: BTreeSet::new(),
            rewrite_outcomes: Vec::new(),
        }
    }

    /// A structurer that polls the engine's work control as it writes.
    pub(crate) fn new_with_control(
        func: &'a SSAFunction,
        fold_ctx: &'o FoldingContext<'o>,
        control: DecompileWorkControl<'a>,
    ) -> Result<Self, DecompileExecutionStop> {
        control.poll()?;
        Ok(Self {
            func,
            fold_ctx,
            folded_block_cache: HashMap::new(),
            labels: HashMap::new(),
            label_counter: 0,
            control: Some(control),
            stop_reason: Cell::new(None),
            certified_for_regions: BTreeMap::new(),
            certified_for_header_sites: BTreeSet::new(),
            rewrite_outcomes: Vec::new(),
        })
    }

    /// The label each block address was given, for a reader of the tree.
    pub(crate) fn labels(&self) -> &HashMap<u64, String> {
        &self.labels
    }

    /// One word per rewrite stage: applied, or why not.
    pub(crate) fn rewrite_report(&self) -> String {
        self.rewrite_outcomes.join(",")
    }

    pub(crate) fn execution_stop(&self) -> Option<DecompileExecutionStop> {
        self.stop_reason.get()
    }

    #[inline]
    fn poll(&self) -> bool {
        if self.stop_reason.get().is_some() {
            return false;
        }
        if let Some(control) = self.control
            && let Err(reason) = control.poll()
        {
            self.stop_reason.set(Some(reason));
            return false;
        }
        true
    }

    fn ensure_label(&mut self, addr: u64) -> String {
        if let Some(label) = self.labels.get(&addr) {
            return label.clone();
        }
        let label = format!("L{}", self.label_counter);
        self.label_counter += 1;
        self.labels.insert(addr, label.clone());
        label
    }

    /// Write the function and seal its lexical regions.
    ///
    /// Placement is total; the certificate is taken before and after the
    /// rewrites, and a rewrite that loses it is not applied.
    pub(crate) fn structure_with_regions(
        &mut self,
    ) -> ControlFlowStructureResult<SealedStructuredBody> {
        let source_authority = self
            .fold_ctx
            .inputs
            .prepared_ssa
            .map(r2ssa::SsaArtifact::authority)
            .ok_or(StructuredRegionBuildError::MissingSourceAuthority)?;
        let placement = place::Placement::compute(self.func);
        crate::stage_timing::mark("structure_analyze");
        self.prepare_certified_for_loops(&placement)?;
        crate::stage_timing::mark("structure_prepare");
        let body = self.place_function(&placement)?;
        let stmt = CStmt::structured_region(
            StructuredRegionMarker::unsealed(self.func.entry, StructuredRegionKind::FunctionBody),
            CStmt::Block(body),
        );
        crate::stage_timing::mark("structure_walk");
        // Each rewrite stage keeps the certificate it was given and every
        // observed occurrence, or it is not applied.
        let placed = self.certificate(&stmt);
        let fold_ctx = self.fold_ctx;
        let shaped =
            self.rewrite_stage("shape", &placed, &stmt, |tree| Self::shape(fold_ctx, tree));
        let symbols = std::rc::Rc::clone(&self.fold_ctx.symbols);
        let stmt = self.rewrite_stage("cleanup", &placed, &shaped, |tree| {
            Self::cleanup(&symbols, tree)
        });
        crate::stage_timing::mark("structure_cleanup");
        let sealed =
            seal_structured_body(stmt, source_authority).map_err(ControlFlowStructureError::from);
        crate::stage_timing::mark("structure_seal_body");
        sealed
    }

    /// One rewrite stage under the gate: the result must certify at least as
    /// well as the placed tree and keep every observed occurrence.
    fn rewrite_stage(
        &mut self,
        name: &str,
        placed: &certify::ControlCertificate,
        before: &CStmt,
        rewrite: impl FnOnce(CStmt) -> CStmt,
    ) -> CStmt {
        let after = rewrite(before.clone());
        let certificate = self.certificate(&after);
        let kept: BTreeSet<_> = crate::ast::stmt_render_observation_ids(&after)
            .into_iter()
            .collect();
        let lost: Vec<_> = crate::ast::stmt_render_observation_ids(before)
            .into_iter()
            .filter(|id| !kept.contains(id))
            .collect();
        let certified = certificate.ok() || !placed.ok();
        if r2il::refusal_evidence::tracing() {
            r2il::refusal_evidence!(
                "control-shape",
                "{name}: {certificate}; lost observations {}; before: {}; after: {}",
                lost.len(),
                Self::tree_digest(before),
                Self::tree_digest(&after)
            );
        }
        if certified && lost.is_empty() {
            self.rewrite_outcomes.push(format!("{name}:applied"));
            after
        } else {
            let why = if !certified {
                "certificate"
            } else {
                "observations"
            };
            self.rewrite_outcomes.push(format!("{name}:{why}"));
            r2il::refusal_evidence!(
                "control-rewrite",
                "{name} not applied: certificate {certificate}; {} observations lost",
                lost.len()
            );
            before.clone()
        }
    }

    /// A one-line sketch of a tree for the trace: control statements and
    /// block markers, nothing else.
    fn tree_digest(stmt: &CStmt) -> String {
        fn walk(stmt: &CStmt, out: &mut String) {
            match stmt {
                CStmt::StructuredRegion { marker, stmt } => {
                    out.push_str(&format!("{:?}@{:#x}[", marker.kind(), marker.entry()));
                    walk(stmt, out);
                    out.push(']');
                }
                CStmt::Observed { stmt, .. } => walk(stmt, out),
                CStmt::Block(stmts) => stmts.iter().for_each(|stmt| walk(stmt, out)),
                CStmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    out.push_str("if{");
                    walk(then_body, out);
                    out.push_str("}else{");
                    if let Some(else_body) = else_body {
                        walk(else_body, out);
                    }
                    out.push('}');
                }
                CStmt::While { body, .. } => {
                    out.push_str("while{");
                    walk(body, out);
                    out.push('}');
                }
                CStmt::DoWhile { body, .. } => {
                    out.push_str("do{");
                    walk(body, out);
                    out.push('}');
                }
                CStmt::For { body, cond, .. } => {
                    out.push_str(if cond.is_some() { "for{" } else { "loop{" });
                    walk(body, out);
                    out.push('}');
                }
                CStmt::Switch { cases, default, .. } => {
                    out.push_str("switch{");
                    for case in cases {
                        out.push_str("case:");
                        case.body.iter().for_each(|stmt| walk(stmt, out));
                    }
                    if let Some(default) = default {
                        out.push_str("default:");
                        default.iter().for_each(|stmt| walk(stmt, out));
                    }
                    out.push('}');
                }
                CStmt::Label(name) => out.push_str(&format!("{name}:")),
                CStmt::Goto(name) => out.push_str(&format!("goto {name};")),
                CStmt::Break => out.push_str("break;"),
                CStmt::Continue => out.push_str("continue;"),
                CStmt::Return(_) => out.push_str("return;"),
                CStmt::Empty | CStmt::Comment(_) => {}
                _ => out.push_str("s;"),
            }
        }
        let mut out = String::new();
        walk(stmt, &mut out);
        out.truncate(4000);
        out
    }

    /// The control certificate of a marked tree, read with this function's
    /// labels and the journal's block attribution.
    pub(crate) fn certificate(&self, stmt: &CStmt) -> certify::ControlCertificate {
        let journal = self
            .fold_ctx
            .inputs
            .observation_journal
            .map(|journal| journal.borrow());
        let by_name: HashMap<&str, u64> = self
            .labels
            .iter()
            .map(|(addr, name)| (name.as_str(), *addr))
            .collect();
        let declarations = self.fold_ctx.callee_declarations.borrow();
        certify::certify(
            stmt,
            self.func.cfg(),
            self.func.entry,
            &|id| {
                journal
                    .as_ref()
                    .and_then(|journal| journal.observation_block(id))
            },
            &|name| by_name.get(name).copied(),
            &|stmt| {
                certify::stmt_callee_name(stmt)
                    .is_some_and(|name| declarations.get(name).is_some_and(|d| d.noreturn))
            },
        )
    }

    fn is_unresolved_indirect_dispatch_block(&self, addr: u64) -> bool {
        let Some(cfg_block) = self.func.cfg().get_block(addr) else {
            return false;
        };
        // A source-proven tail call through a slot is an indirect branch with
        // no successor, and it is resolved: its callsite fact renders the
        // terminal return. Only a dispatch nothing certified is unresolved.
        let certified_terminal_call = self.func.get_block(addr).is_some_and(|block| {
            block.ops.iter().enumerate().any(|(op_idx, _)| {
                self.fold_ctx
                    .certified_call_render_fact_for_op(addr, op_idx)
                    .is_some_and(|fact| fact.disposition.is_terminal_return())
            })
        });

        matches!(
            cfg_block.terminator,
            r2ssa::cfg::BlockTerminator::IndirectBranch
        ) && !certified_terminal_call
            && self.func.successors(addr).is_empty()
            && self.func.switch_info(addr).is_none()
    }

    fn exact_control_obligations(
        &self,
        anchors: impl IntoIterator<Item = u64>,
    ) -> BTreeSet<r2ssa::SemanticObligationId> {
        let mut obligations = BTreeSet::new();
        for anchor in anchors {
            let Some(block) = self.func.blocks().find(|block| block.addr == anchor) else {
                continue;
            };
            let Some(op_idx) = block.ops.len().checked_sub(1) else {
                continue;
            };
            obligations.extend(self.fold_ctx.exact_effect_obligations_for_normalized_value(
                crate::fold::context::EffectOccurrenceKind::Expression,
                anchor,
                op_idx,
                None,
            ));
        }
        obligations
    }

    fn observe_control_ownership(&self, anchor: u64, stmt: CStmt) -> CStmt {
        let obligations = self.exact_control_obligations(std::iter::once(anchor));
        self.fold_ctx.observe_effect_stmt(&obligations, stmt)
    }

    /// Counted loops: a certified induction's initializer and update are
    /// moved into the `for` header before the blocks are written.
    fn prepare_certified_for_loops(
        &mut self,
        placement: &place::Placement,
    ) -> ControlFlowStructureResult<()> {
        self.certified_for_regions.clear();
        self.certified_for_header_sites.clear();
        let Some(prepared) = self.fold_ctx.inputs.prepared_ssa else {
            return Ok(());
        };
        let Some(origins) = self.fold_ctx.inputs.normalization_origins else {
            return Ok(());
        };
        let Some(control) = self.fold_ctx.control_facts() else {
            return Ok(());
        };
        let Some(names) = self.fold_ctx.inputs.binding_names else {
            return Ok(());
        };
        let region_loops: Vec<(u64, BTreeSet<u64>)> = placement
            .loops()
            .iter()
            .map(|natural| (natural.header, natural.body.clone()))
            .collect();
        for (header, body_blocks) in region_loops {
            let mut loops = control.loops_for_header(header).filter_map(|loop_fact| {
                loop_fact
                    .for_loop
                    .as_ref()
                    .map(|certificate| (loop_fact.loop_id, certificate))
            });
            let Some((_, certificate)) = loops.next() else {
                continue;
            };
            if loops.next().is_some() || !body_blocks.contains(&certificate.latch) {
                continue;
            }
            let same_binding = match (
                names.plan().disposition(certificate.induction_phi),
                names.plan().disposition(certificate.induction_update),
            ) {
                (
                    Some(crate::binding_plan::ValueDisposition::Bound { binding: left }),
                    Some(crate::binding_plan::ValueDisposition::Bound { binding: right }),
                ) => left == right,
                _ => false,
            };
            if !same_binding {
                continue;
            }
            let Some(sites) = origins.for_loop_sites(certificate, prepared) else {
                continue;
            };
            let initializer_block = certificate.initializer.predecessor;
            let Some(initializer_addr) = prepared
                .graph()
                .block(sites.initializer.block)
                .map(|b| b.addr)
            else {
                continue;
            };
            let Some(update_addr) = prepared.graph().block(sites.update.block).map(|b| b.addr)
            else {
                continue;
            };
            if initializer_addr != initializer_block || update_addr != certificate.latch {
                continue;
            }
            let Some(initializer_ssa) = self.func.get_block(initializer_addr) else {
                continue;
            };
            let Some(update_ssa) = self.func.get_block(update_addr) else {
                continue;
            };
            let mut initializer_entries =
                self.folded_block_entries(initializer_ssa, initializer_addr)?;
            let Some(initializer_index) = initializer_entries
                .iter()
                .position(|entry| entry.site == sites.initializer)
            else {
                continue;
            };
            if initializer_entries[initializer_index + 1..]
                .iter()
                .any(|entry| !matches!(entry.stmt.unobserved(), CStmt::Empty))
            {
                continue;
            }
            let initializer = initializer_entries.remove(initializer_index).stmt;
            let update = self
                .folded_block_entries(update_ssa, update_addr)?
                .into_iter()
                .find(|entry| entry.site == sites.update)
                .and_then(|entry| {
                    let (semantic, observations) = entry.stmt.into_semantic_with_observations();
                    match semantic {
                        CStmt::Expr(expr) => Some(observations.reapply_expr(expr)),
                        _ => None,
                    }
                });
            let Some(update) = update else {
                continue;
            };
            let prior = self.certified_for_regions.insert(
                header,
                CertifiedForRegion {
                    init: initializer,
                    update,
                },
            );
            debug_assert!(prior.is_none(), "one candidate per counted-loop header");
            self.certified_for_header_sites.insert(sites.initializer);
            self.certified_for_header_sites.insert(sites.update);
        }
        Ok(())
    }

    fn get_switch_expression(
        &mut self,
        switch_addr: u64,
    ) -> ControlFlowStructureResult<Option<(CExpr, ValueId)>> {
        let Some(block) = self.func.get_block(switch_addr) else {
            r2il::refusal_evidence!("switch-selector", "{switch_addr:#x} is not a block");
            return Ok(None);
        };
        // The dispatch is not always the block's last operation. Materializing
        // a merge's incoming edges appends copies after the terminator, and
        // taking the last op then found one of those and declined, which is one
        // of the two reasons no real jump table has ever structured.
        let mut dispatches = block.ops.iter().enumerate().filter_map(|(index, op)| {
            if let SSAOp::BranchInd { target, .. } = op {
                Some((index, target))
            } else {
                None
            }
        });
        let Some((op_idx, target)) = dispatches.next() else {
            r2il::refusal_evidence!("switch-selector", "{switch_addr:#x} has no indirect branch");
            return Ok(None);
        };
        if dispatches.next().is_some() {
            r2il::refusal_evidence!(
                "switch-selector",
                "{switch_addr:#x} has more than one indirect branch"
            );
            return Ok(None);
        }
        let Some(fact) = self
            .fold_ctx
            .control_facts()
            .and_then(|facts| facts.switch_for_block(switch_addr))
        else {
            r2il::refusal_evidence!("switch-selector", "{switch_addr:#x} has no control fact");
            return Ok(None);
        };
        if fact.block_addr != switch_addr {
            r2il::refusal_evidence!(
                "switch-selector",
                "{switch_addr:#x} control fact names block {:#x}",
                fact.block_addr
            );
            return Ok(None);
        }
        let Some(selector) = fact.selector else {
            r2il::refusal_evidence!(
                "switch-selector",
                "{switch_addr:#x} control fact carries no selector value"
            );
            return Ok(None);
        };
        // The dispatch operand is not the selector, and requiring it to be was
        // why no real jump table ever structured. `switch (len & 3)` computes
        // the index, loads an address out of a table, and dispatches through
        // that address, so the operand is the loaded target while the selector
        // is several instructions upstream. The two are different values, the
        // equality never held, and the only shape that satisfied it was the
        // unit fixture's undefined target.
        //
        // What the switch prints is the selector. The dispatch operand is
        // control, accounted beside the case topology that expresses it.
        let _ = target;
        // The heading names the selector object, and it has to be built through
        // the observation machinery: an expression assembled outside it carries
        // no marker, so declaration placement sees a symbol read that nothing
        // authorizes. `observe_certified_value_read_expr` is what records a read
        // of a value at an instruction, which is exactly what the dispatch does
        // with the selector.
        let Some(symbol) = self
            .fold_ctx
            .inputs
            .binding_names
            .and_then(|names| names.symbol_for_value(selector))
        else {
            return Ok(None);
        };
        let Some(at) = self
            .fold_ctx
            .inputs
            .prepared_ssa
            .and_then(|prepared| prepared.graph().inst_id_for_op_site(switch_addr, op_idx))
        else {
            return Ok(None);
        };
        let expr = self.fold_ctx.observe_certified_value_read_expr(
            selector,
            at,
            crate::ast::CExpr::Var(symbol),
        );
        Ok(Some((expr, selector)))
    }

    /// What the edge `source -> target` writes for the merges at `target`:
    /// one assignment per phi whose incoming value has a different name.
    ///
    /// A merge the plan elided as a dead stack base is the address of a slot
    /// the readers already name, so the edge writes nothing for it; that is
    /// hypothesis H6 of the ADR, checked by the corpus differential.
    fn edge_merge_writes(
        &self,
        target: u64,
        source: u64,
    ) -> ControlFlowStructureResult<Vec<CStmt>> {
        let Some(block) = self.func.get_block(target) else {
            return Ok(Vec::new());
        };
        let mut writes = Vec::new();
        for phi in &block.phis {
            let Some(value) = phi
                .sources
                .iter()
                .find_map(|(pred, value)| (*pred == source).then_some(value))
            else {
                r2il::refusal_evidence!(
                    "edge-merge",
                    "{source:#x} -> {target:#x}: phi {:?} has no input for this edge",
                    phi.dst
                );
                continue;
            };
            let Some(target_value) = self.fold_ctx.prepared_value_id_for_var(&phi.dst) else {
                continue;
            };
            let Some(source_value) = self.fold_ctx.prepared_value_id_for_var(value) else {
                continue;
            };
            // The plan decides whether the edge writes anything before any
            // expression is asked for, because asking observes a read: a merge
            // the plan elided has no reader, and a merge coalesced with its
            // input is already the same object.
            let Some(names) = self.fold_ctx.inputs.binding_names else {
                continue;
            };
            use crate::binding_plan::ValueDisposition;
            let target_binding = match names.plan().disposition(target_value) {
                Some(ValueDisposition::Bound { binding }) => *binding,
                _ => continue,
            };
            if let Some(ValueDisposition::Bound { binding }) =
                names.plan().disposition(source_value)
                && *binding == target_binding
            {
                continue;
            }
            let target_expr = match self.fold_ctx.planned_value_expr(target_value) {
                Ok(expr) => expr,
                Err(error) => {
                    r2il::refusal_evidence!(
                        "program-variable",
                        "shared exit {target:#x} from {source:#x}: merge target {target_value:?} of {:?} unplanned: {error:?}",
                        phi.dst
                    );
                    return Err(OpLoweringRefusal::missing_program_variable().into());
                }
            };
            let source_expr = self
                .fold_ctx
                .planned_value_expr(source_value)
                .map_err(|error| {
                    r2il::refusal_evidence!(
                        "program-variable",
                        "shared exit {target:#x} from {source:#x}: merge source {source_value:?} of {:?} unplanned: {error:?}",
                        phi.dst
                    );
                    OpLoweringRefusal::missing_program_variable()
                })?;
            if target_expr.transparently_eq(&source_expr) {
                continue;
            }
            writes.push(CStmt::Expr(CExpr::assign(target_expr, source_expr)));
        }
        Ok(writes)
    }

    fn folded_block_entries(
        &mut self,
        block: &r2ssa::FunctionSSABlock,
        addr: u64,
    ) -> ControlFlowStructureResult<Vec<crate::fold::op_lower::FoldedOpStmt>> {
        Ok(if let Some(folded) = self.folded_block_cache.get(&addr) {
            if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
                eprintln!("FOLDCACHE hit block={addr:#x} stmts={}", folded.stmts.len());
            }
            let semantic = folded
                .stmts
                .iter()
                .map(|entry| entry.stmt.clone())
                .collect::<Vec<_>>();
            self.fold_ctx
                .clone_cached_render_occurrence(&semantic)
                .into_iter()
                .zip(&folded.stmts)
                .map(|(stmt, original)| crate::fold::op_lower::FoldedOpStmt {
                    site: original.site,
                    stmt,
                })
                .collect()
        } else {
            let stmts = self.fold_ctx.fold_block_with_sites(block, addr)?;
            if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
                eprintln!("FOLDCACHE miss block={addr:#x} stmts={}", stmts.len());
            }
            self.folded_block_cache.insert(
                addr,
                FoldedBlock {
                    stmts: stmts.clone(),
                },
            );
            stmts
        })
    }

    fn get_branch_condition_with_predicate(
        &mut self,
        addr: u64,
    ) -> (Option<CExpr>, Option<PredicateId>, Option<ValueId>) {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return (None, None, None),
        };
        let predicate = self
            .fold_ctx
            .control_facts()
            .and_then(|facts| facts.branch_for_block(addr))
            .map(|predicate| (predicate.id, predicate.condition));
        let predicate_id = predicate.map(|(id, _)| id);
        let condition_value = predicate.map(|(_, value)| value);

        // A condition a marked gap covers has no rendered definition, so
        // spelling it here would put a name in an `if` that no statement
        // assigns. The branch is unresolved for the same reason the gap
        // exists, and the caller's existing residual path says so.
        if condition_value.is_some_and(|value| self.fold_ctx.value_is_gapped(value)) {
            return (None, predicate_id, condition_value);
        }

        if let Some(cond) = self.fold_ctx.extract_condition_from_block(block) {
            if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
                let table = self.fold_ctx.symbols.borrow();
                let mut ids = std::collections::HashSet::new();
                crate::collect_expr_var_names(&cond, &mut ids);
                let names = ids
                    .into_iter()
                    .map(|id| format!("{id:?}={}", table.name(id)))
                    .collect::<Vec<_>>();
                eprintln!("BRANCHCOND block={addr:#x} cond={cond:?} names={names:?}");
            }
            return (Some(cond), predicate_id, condition_value);
        }

        (None, predicate_id, condition_value)
    }
}
