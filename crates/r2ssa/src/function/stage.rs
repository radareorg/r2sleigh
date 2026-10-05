//! The three stages an SSA function passes through, each a type
//! (doc/adr-stable-identity.md, "Stages").
//!
//! - [`Lifted`]: built from the lift and open for change. Optimisation runs
//!   here, through the plans an `EditPlan` states.
//! - [`Prepared`]: the validator holds (`validate_ssa_function`, dominance
//!   included). Nothing is derived from it yet, and nothing changes it but
//!   [`Prepared::seal`].
//! - [`Sealed`]: the function as every fact describes it, with the facts.
//!   It has no `&mut` path to its blocks, so a fact can never answer for
//!   blocks that have since changed, and no revision has to say whether it
//!   still does.
//!
//! Sealing is one fixed sequence, private to this module: the boundary
//! constants, the entry lanes and the forwarded copies rewrite the blocks;
//! the demand pass plans its releases over a provisional graph; then the prep
//! facts are collected once, the graph is final, and the source's formals
//! are read off it. No step can be called on its own, so none can run twice.
//!
//! The validator is the precondition of both [`Prepared`] and [`Sealed`]: an
//! entry-lane formal is the caller's value, live at entry with no definition,
//! and the whole register it is a lane of is rebuilt at a fresh version from
//! the caller's own register (step 4 of the ADR).

use std::ops::Deref;

use crate::control::{SsaExecutionStopReason, SsaPrepareError, SsaWorkControl};
use crate::graph::SsaGraph;
use crate::integrity::{SsaIntegrityError, validate_ssa_function};
use crate::machine_context::SourceMachineContext;

use super::{DecompilePrepFacts, InterfaceQuestions, SSAFunction};

/// A function as the lift built it: the only stage whose blocks open for
/// change.
///
/// A pass changes it through an `EditPlan`; a test that writes a fixture
/// changes it a block at a time. Either way nothing has been derived from it
/// yet, so nothing can go stale.
#[derive(Debug, Clone)]
pub struct Lifted {
    ir: SSAFunction,
}

impl Lifted {
    /// A function to change before it is prepared.
    pub fn new(ir: SSAFunction) -> Self {
        Self { ir }
    }

    /// One block, open for any change in variables by name: what the block
    /// gains is minted an id and interned, and what it loses is tombstoned.
    pub fn edit_block(&mut self, addr: u64) -> Option<super::NamedBlockMut<'_>> {
        self.ir.named_block_for_change(addr)
    }

    /// Run the decompiler's optimisation over the function and validate what
    /// it leaves.
    ///
    /// The optimisation reads the interface for the return projection only.
    pub(crate) fn prepare<C: SsaWorkControl + ?Sized>(
        mut self,
        config: &crate::optimize::DecompilePrepConfig,
        return_carrier: Option<r2source::CanonicalStorageId>,
        control: &C,
    ) -> Result<Prepared, SsaPrepareError> {
        control.poll()?;
        // What each operation wrote, before an optimisation folds it away.
        self.ir.capture_written();
        let config: crate::optimize::OptimizationConfig = config.into();
        crate::optimize::optimize_function_with_return_and_control(
            &mut self.ir,
            &config,
            return_carrier,
            control,
        )?;
        self.validate().map_err(super::integrity_refusal)
    }

    /// Run a configured optimisation and validate what it leaves.
    pub(crate) fn optimize_and_validate<C: SsaWorkControl + ?Sized>(
        mut self,
        config: &crate::optimize::OptimizationConfig,
        control: &C,
    ) -> Result<Prepared, SsaPrepareError> {
        crate::optimize::optimize_function_with_control(&mut self.ir, config, control)?;
        self.validate().map_err(super::integrity_refusal)
    }

    /// The function, prepared as it stands: the validator is the whole of
    /// the precondition. Its typed error names the block and the edge it
    /// disagreed about.
    #[expect(
        clippy::result_large_err,
        reason = "the validator's typed failure is the refusal; it is mapped once, at the artifact boundary"
    )]
    pub fn validate(self) -> Result<Prepared, SsaIntegrityError> {
        validate_ssa_function(&self.ir)?;
        Ok(Prepared { ir: self.ir })
    }
}

impl Deref for Lifted {
    type Target = SSAFunction;

    fn deref(&self) -> &SSAFunction {
        &self.ir
    }
}

/// A validated function, not yet sealed.
///
/// `validate_ssa_function` holds: every value defined once, every use
/// dominated, the blocks and the graph agree. Its only way forward is
/// [`Self::seal`], which consumes it, so it is sealed at most once:
///
/// ```compile_fail,E0382
/// fn twice(prepared: r2ssa::Prepared, context: &r2ssa::SourceMachineContext) {
///     let _first = prepared.seal(context);
///     let _second = prepared.seal(context);
/// }
/// ```
///
/// where sealing it once is what every artifact does:
///
/// ```no_run
/// fn once(prepared: r2ssa::Prepared, context: &r2ssa::SourceMachineContext) {
///     let _sealed = prepared.seal(context);
/// }
/// ```
#[derive(Debug)]
pub struct Prepared {
    ir: SSAFunction,
}

impl Prepared {
    /// The function, given back as an IR with no stage: whatever is done to
    /// it next starts again from [`Lifted`].
    pub fn into_function(self) -> SSAFunction {
        self.ir
    }

    /// The same prepared function under the name the source gives it. A
    /// name is presentation, and no fact reads it.
    pub(crate) fn named(mut self, name: String) -> Self {
        self.ir.name = Some(name);
        self
    }

    /// The prep facts of a function that is analysed here and never sealed:
    /// interface recovery reads them off the provisional function it
    /// recovers from.
    pub(crate) fn provisional_prep_facts<C: SsaWorkControl + ?Sized>(
        &self,
        control: &C,
    ) -> Result<DecompilePrepFacts, SsaExecutionStopReason> {
        let graph = SsaGraph::from_function_with_storage(&self.ir);
        self.ir
            .collect_decompile_prep_facts_with_control(&graph, None, control)
    }

    /// Seal the function: the fixed sequence that rewrites the blocks for
    /// the last time, then derives the facts every later stage reads from
    /// them.
    ///
    /// 1. Boundary constants the machine context states.
    /// 2. Entry-lane projections for every formal lane.
    /// 3. Copy forwarding, so a copied value's readers are counted where they
    ///    are.
    /// 4. The demand pass: over a graph of the function as it now stands,
    ///    plan the INSERT bases nothing reads; apply the plan and build the
    ///    graph again only where it released one.
    /// 5. The prep facts, collected once, with the interface's frame
    ///    geometry where the context's ABI model holds it coherent.
    /// 6. The source's formals, materialised in the graph and installed in
    ///    the prep facts where they are exact.
    ///
    /// `O(n)` per rewrite and per collection; the graph is built once, twice
    /// for a function the demand pass changes.
    ///
    /// The sealed function validates as the prepared one did: the steps add
    /// no definition at version zero and no read its definition does not
    /// dominate. Where one does, the typed failure is the refusal.
    #[expect(
        clippy::result_large_err,
        reason = "the validator's typed failure is the refusal; it is mapped once, at the artifact boundary"
    )]
    pub fn seal(self, machine_context: &SourceMachineContext) -> Result<Sealed, SsaIntegrityError> {
        let mut ir = self.ir;
        ir.apply_boundary_constants(machine_context);
        ir.mint_entry_lane_projections(machine_context);
        // Before the graph, so every fact built from it counts readers of a
        // copied value where they are, not where the copy was. It rewrites
        // reads to variables the validated function already defines.
        ir.forward_copies();
        let mut graph = SsaGraph::from_function_with_storage(&ir);
        // A lane write whose untouched bytes nothing reads does not read the
        // value it was written into (`demand`); releasing those bases changes
        // an operand, so the graph is taken once more where it did.
        let released = super::release_undemanded_bytes(&ir, machine_context, &graph);
        if !released.is_empty() {
            ir.apply_edits(released);
            graph = SsaGraph::from_function_with_storage(&ir);
        }
        let mut prep = ir
            .collect_decompile_prep_facts_with_control(
                &graph,
                InterfaceQuestions::new(machine_context).for_frame_geometry(),
                &crate::control::UncheckedSsaWorkControl,
            )
            .expect("an unchecked control never stops");
        crate::semantic::ensure_source_formal_parameter_values(&mut graph, machine_context);
        let formal_parameters =
            crate::semantic::collect_source_formal_parameter_facts(&graph, machine_context);
        prep.install_exact_formal_parameters(&graph, &formal_parameters);
        validate_ssa_function(&ir)?;
        let folded = Folded {
            prepared: crate::constant::fold_all(&graph, Some(&prep)),
            bare: crate::constant::fold_all(&graph, None),
        };
        Ok(Sealed {
            ir,
            prep,
            graph,
            folded,
        })
    }
}

impl Deref for Prepared {
    type Target = SSAFunction;

    fn deref(&self) -> &SSAFunction {
        &self.ir
    }
}

/// A sealed function: the blocks, the prep facts collected from them, and
/// their graph.
///
/// Nothing reaches the blocks mutably. A sealed function, owned or not,
/// hands out only shared views of them:
///
/// ```compile_fail,E0596
/// fn edit(mut artifact: r2ssa::SsaArtifact) {
///     artifact.function().blocks()[0].ops_mut()[0] = r2ssa::SSAOp::Nop;
/// }
/// ```
///
/// ```compile_fail,E0596
/// fn edit(mut sealed: r2ssa::Sealed) {
///     sealed.function().blocks()[0].phis_mut().clear();
/// }
/// ```
///
/// while reading them is what every consumer does:
///
/// ```no_run
/// fn read(artifact: &r2ssa::SsaArtifact) -> usize {
///     artifact.function().blocks()[0].ops().len()
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Sealed {
    ir: SSAFunction,
    prep: DecompilePrepFacts,
    graph: SsaGraph,
    folded: Folded,
}

/// What each value of the sealed graph folds to, computed once at the seal
/// (`crate::constant::fold_all`): with what preparation proved admitted, and
/// from the graph alone.
#[derive(Debug, Clone)]
pub(crate) struct Folded {
    pub(crate) prepared: crate::dense::IdVec<crate::graph::ValueId, Option<u64>>,
    pub(crate) bare: crate::dense::IdVec<crate::graph::ValueId, Option<u64>>,
}

impl Sealed {
    /// The function every fact describes.
    pub fn function(&self) -> &SSAFunction {
        &self.ir
    }

    /// The decompiler-prep facts, collected once, from these blocks.
    pub fn decompile_prep_facts(&self) -> &DecompilePrepFacts {
        &self.prep
    }

    /// The graph, built once, from these blocks.
    pub fn graph(&self) -> &SsaGraph {
        &self.graph
    }

    /// The constant folds of every value, computed once at the seal.
    pub(crate) fn folded(&self) -> &Folded {
        &self.folded
    }

    /// The same sealed function under the name the source gives it. A name
    /// is presentation, and no fact reads it.
    pub(super) fn named(mut self, name: String) -> Self {
        self.ir.name = Some(name);
        self
    }

    /// The artifact over this sealed function: liveness and the semantic
    /// facts, collected from the prep facts as they were sealed. Neither is
    /// written into the other afterwards (`SsaArtifact::formal_parameter_of`
    /// asks both).
    pub(super) fn into_artifact<C: SsaWorkControl + ?Sized>(
        self,
        machine_context: SourceMachineContext,
        finish: super::Finish,
        control: &C,
        prepare_entry_bytes: usize,
    ) -> Result<super::SsaArtifact, SsaPrepareError> {
        let prepared_bytes = r2il::allocation::live_bytes();
        let (mut facts, liveness) =
            crate::semantic::PreparedFunctionFacts::collect_with_context_and_control(
                crate::semantic::CollectionOver {
                    function: &self.ir,
                    prep: Some(&self.prep),
                    graph: &self.graph,
                    assumptions: &crate::AssumptionSet::default(),
                    machine_context: Some(&machine_context),
                    site: "prepare",
                },
                control,
            )?;
        // What one prepared function holds is the space every later stage has
        // to work above, so it is reported beside the phases that built it.
        r2il::refusal_evidence!(
            "prepare-held",
            "{:#x}/{} holds {} bytes after preparation: function+graph {} facts {}",
            self.ir.entry,
            self.ir.num_blocks(),
            r2il::allocation::live_bytes().saturating_sub(prepare_entry_bytes),
            prepared_bytes.saturating_sub(prepare_entry_bytes),
            r2il::allocation::live_bytes().saturating_sub(prepared_bytes)
        );
        let crate::semantic::CollectedLiveness {
            live_out,
            values,
            storage_spans,
            ignored_reads,
        } = liveness;
        let unobserved_merges = crate::deadphi::DeadPhis::find(&self.graph, &live_out, &facts);
        let aggregate_accesses = crate::aggregate_access::collect_aggregate_access_projections(
            &self.graph,
            &facts.addresses,
            &facts.structured.memory_accesses,
            &machine_context,
        );
        // The obligations are about the native instructions of the lift the
        // function came from; a span the obligations cannot bind means the
        // lift and the function disagree.
        if let Some(spans) = finish.native_spans
            && !facts.obligations.bind_genuine_native_spans(spans)
        {
            return Err(super::malformed_ssa_input());
        }
        control.poll()?;
        Ok(super::SsaArtifact {
            authority: super::SsaArtifactAuthority::new(),
            provenance: finish.provenance,
            sealed: self,
            liveness: super::ArtifactLiveness {
                storage_spans,
                live_out,
                values,
                ignored_reads,
            },
            unobserved_merges,
            facts,
            machine_context,
            aggregate_accesses,
            spellings: finish.spellings,
        })
    }
}
