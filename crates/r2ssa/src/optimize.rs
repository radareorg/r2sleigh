//! SSA optimization pipeline.
//!
//! This module applies a sequence of lightweight, SSA-safe optimizations
//! intended to simplify analysis and decompilation output.

use std::collections::{BTreeSet, HashSet, VecDeque};

use crate::control::{SsaExecutionStopReason, SsaWorkControl};
use crate::dense::{Csr, IdMap, IdSet, IdVec};
use crate::function::{EditPlan, ShapeEdit};
use crate::value_table::{Minting, VarId};
use crate::{
    BlockTerminator, CanonicalStorageId, CanonicalStorageSpace, PhiNode, SSAFunction, SSAOp,
    SourceCarrierKind, SourceFunctionInterface, SourceFunctionReturn, SourceSite, SourceTypeKind,
};

/// Configuration for SSA optimization passes.
#[derive(Debug, Clone)]
pub struct OptimizationConfig {
    pub enable_sccp: bool,
    pub enable_inst_combine: bool,
    pub preserve_memory_reads: bool,
}

/// Configuration for preparing SSA for decompilation.
///
/// The decompiler needs provenance-preserving SSA more than aggressively
/// simplified SSA, so the default intentionally disables destructive
/// simplification passes and only allows explicitly opted-in transforms.
#[derive(Debug, Clone)]
pub struct DecompilePrepConfig {
    pub enable_inst_combine: bool,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            enable_sccp: true,
            enable_inst_combine: true,
            preserve_memory_reads: false,
        }
    }
}

impl Default for DecompilePrepConfig {
    fn default() -> Self {
        Self {
            enable_inst_combine: true,
        }
    }
}

impl From<&DecompilePrepConfig> for OptimizationConfig {
    fn from(value: &DecompilePrepConfig) -> Self {
        Self {
            enable_sccp: false,
            enable_inst_combine: value.enable_inst_combine,
            preserve_memory_reads: true,
        }
    }
}

/// Optimization statistics for a single run.
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    pub iterations: usize,
    pub sccp_constants_found: usize,
    pub sccp_edges_pruned: usize,
    pub sccp_blocks_removed: usize,
    pub constants_propagated: usize,
    pub ops_simplified: usize,
    pub chains_fused: usize,
}

/// Run the SSA optimization pipeline on a function.
#[cfg(test)]
pub(crate) fn optimize_function(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
) -> OptimizationStats {
    optimize_function_with_control(func, config, &crate::control::UncheckedSsaWorkControl)
        .expect("unchecked SSA optimization cannot stop")
}

pub(crate) fn optimize_function_with_control<C: SsaWorkControl + ?Sized>(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
    control: &C,
) -> Result<OptimizationStats, SsaExecutionStopReason> {
    optimize_function_with_return_and_control(func, config, None, control)
}

/// Optimise, keeping every source of a merge of `return_carrier` in a
/// returning block as it is: what the function hands back is read whole
/// there, so a constant folded into one source is no longer a value of
/// the carrier the caller reads.
pub(crate) fn optimize_function_with_return_and_control<C: SsaWorkControl + ?Sized>(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
    return_carrier: Option<CanonicalStorageId>,
    control: &C,
) -> Result<OptimizationStats, SsaExecutionStopReason> {
    control.poll()?;
    let mut stats = OptimizationStats::default();
    // Constants and folds feed each other: a fold through a definition can
    // turn a lane read into a constant copy, which is a constant the next
    // propagation round carries to its readers. The passes run in one stated
    // order until a round moves nothing (doc/adr-fixpoint.md, K3). A round
    // that moves rewrites at least one operation, so the rounds are budgeted
    // by the operations; every round preserves the function's meaning, so a
    // run that meets the budget leaves a correct function, less simplified,
    // and says so.
    let budget = func
        .blocks()
        .iter()
        .map(|block| block.ops().len())
        .sum::<usize>()
        .saturating_add(1);
    loop {
        if stats.iterations >= budget {
            r2il::refusal_evidence!(
                "optimize",
                "{:#x}: still moving after {budget} rounds",
                func.entry
            );
            break;
        }
        control.poll()?;
        let mut changed = false;

        if config.enable_sccp {
            let (consts, executable_edges) = sccp_with_control(func, control)?;
            control.poll()?;
            if apply_sccp_results(func, &consts, &executable_edges, return_carrier, &mut stats) {
                changed = true;
            }
        }

        // Before the shape passes and whatever they are configured to do: a
        // machine comparison is a comparison in the graph, not a flag algebra
        // for a later stage to undo.
        if fold_condition_codes_in_function(func, &mut stats) {
            changed = true;
        }

        if fuse_compare_chains_in_function(func, &mut stats) {
            changed = true;
        }

        if config.enable_inst_combine && inst_combine(func, &mut stats) {
            changed = true;
        }

        stats.iterations += 1;
        if !changed {
            break;
        }
    }

    control.poll()?;
    Ok(stats)
}

/// An operation as the function holds it: operands are the function's ids.
type Op = SSAOp<VarId>;

type SccpResult = (IdMap<VarId, u64>, HashSet<(u64, u64)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatticeValue {
    Top,
    Const(u64),
    Bottom,
}

impl LatticeValue {
    fn meet(self, other: Self) -> Self {
        match (self, other) {
            (LatticeValue::Top, x) | (x, LatticeValue::Top) => x,
            (LatticeValue::Bottom, _) | (_, LatticeValue::Bottom) => LatticeValue::Bottom,
            (LatticeValue::Const(a), LatticeValue::Const(b)) => {
                if a == b {
                    LatticeValue::Const(a)
                } else {
                    LatticeValue::Bottom
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum UseLocation {
    Phi { block_addr: u64, phi_idx: usize },
    Op { block_addr: u64, op_idx: usize },
}

/// The constant a variable is spelled as, where it is one.
fn const_value(values: &Minting<'_>, id: VarId) -> Option<u64> {
    values.var(id).constant_bits()
}

/// A variable's width in bytes.
fn width(values: &Minting<'_>, id: VarId) -> u32 {
    values.var(id).size
}

/// Every read of each variable, in block order: a compressed row per id.
fn build_use_map(func: &SSAFunction) -> Csr<VarId, UseLocation> {
    let mut uses = Vec::new();
    for block in func.blocks() {
        block.for_each_source(|src| {
            let use_loc = match src.site {
                SourceSite::Phi { phi_idx, .. } => UseLocation::Phi {
                    block_addr: block.addr,
                    phi_idx,
                },
                SourceSite::Op { op_idx, .. } => UseLocation::Op {
                    block_addr: block.addr,
                    op_idx,
                },
            };
            uses.push((*src.var, use_loc));
        });
    }
    Csr::from_pairs(func.values().len(), uses)
}

fn get_lattice_value(
    values: &Minting<'_>,
    id: VarId,
    lattice: &IdVec<VarId, LatticeValue>,
) -> LatticeValue {
    if let Some(val) = const_value(values, id) {
        return LatticeValue::Const(val);
    }
    lattice[id]
}

fn init_if_input(values: &Minting<'_>, id: VarId, lattice: &mut IdVec<VarId, LatticeValue>) {
    let var = values.var(id);
    if var.version == 0 && var.constant_bits().is_none() && lattice[id] == LatticeValue::Top {
        lattice[id] = LatticeValue::Bottom;
    }
}

fn update_lattice(
    lattice: &mut IdVec<VarId, LatticeValue>,
    id: VarId,
    new_val: LatticeValue,
) -> bool {
    let old_val = lattice[id];
    let merged = old_val.meet(new_val);
    if merged != old_val {
        lattice[id] = merged;
        return true;
    }
    false
}

fn evaluate_op_sccp(
    op: &Op,
    values: &Minting<'_>,
    lattice: &IdVec<VarId, LatticeValue>,
) -> LatticeValue {
    if matches!(
        op,
        SSAOp::Load { .. }
            | SSAOp::Store { .. }
            | SSAOp::Call { .. }
            | SSAOp::CallInd { .. }
            | SSAOp::CallOther { .. }
            | SSAOp::CpuId { .. }
            | SSAOp::New { .. }
    ) {
        return LatticeValue::Bottom;
    }

    let mut has_top = false;
    let mut has_bottom = false;
    for src in op.sources() {
        match get_lattice_value(values, *src, lattice) {
            LatticeValue::Bottom => has_bottom = true,
            LatticeValue::Top => has_top = true,
            LatticeValue::Const(_) => {}
        }
    }

    // An absorbing constant decides the result without the other operand,
    // so it is tried before an unknown operand is allowed to make the
    // result unknown; the evaluator answers only from the constants it has.
    let known = |id: VarId| match get_lattice_value(values, id, lattice) {
        LatticeValue::Const(c) => Some(c),
        LatticeValue::Top | LatticeValue::Bottom => None,
    };
    if let Some(c) = eval_const_op(op, values, known) {
        return LatticeValue::Const(c);
    }
    if has_bottom {
        LatticeValue::Bottom
    } else if has_top {
        LatticeValue::Top
    } else {
        LatticeValue::Bottom
    }
}

fn evaluate_phi_sccp(
    phi: &PhiNode<VarId>,
    executable: &HashSet<(u64, u64)>,
    values: &Minting<'_>,
    lattice: &IdVec<VarId, LatticeValue>,
    block_addr: u64,
) -> LatticeValue {
    let mut value = LatticeValue::Top;
    for (pred_addr, src) in &phi.sources {
        if !executable.contains(&(*pred_addr, block_addr)) {
            continue;
        }
        value = value.meet(get_lattice_value(values, *src, lattice));
    }
    value
}

fn find_cbranch_condition(
    func: &SSAFunction,
    values: &Minting<'_>,
    block_addr: u64,
    lattice: &IdVec<VarId, LatticeValue>,
) -> LatticeValue {
    let Some(block) = func.get_block(block_addr) else {
        return LatticeValue::Bottom;
    };
    for op in block.ops().iter().rev() {
        if let SSAOp::CBranch { cond, .. } = op {
            return get_lattice_value(values, *cond, lattice);
        }
    }
    LatticeValue::Bottom
}

fn evaluate_terminator_sccp(
    func: &SSAFunction,
    values: &Minting<'_>,
    block_addr: u64,
    lattice: &IdVec<VarId, LatticeValue>,
    cfg_worklist: &mut VecDeque<(u64, u64)>,
) {
    let Some(cfg_block) = func.cfg().get_block(block_addr) else {
        return;
    };

    match &cfg_block.terminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => match find_cbranch_condition(func, values, block_addr, lattice) {
            LatticeValue::Const(0) => cfg_worklist.push_back((block_addr, *false_target)),
            LatticeValue::Const(_) => cfg_worklist.push_back((block_addr, *true_target)),
            LatticeValue::Top | LatticeValue::Bottom => {
                cfg_worklist.push_back((block_addr, *true_target));
                cfg_worklist.push_back((block_addr, *false_target));
            }
        },
        _ => {
            for succ in func.successors(block_addr) {
                cfg_worklist.push_back((block_addr, succ));
            }
        }
    }
}

#[cfg(test)]
fn sccp(func: &SSAFunction) -> SccpResult {
    sccp_with_control(func, &crate::control::UncheckedSsaWorkControl)
        .expect("unchecked SCCP cannot stop")
}

/// The state of one SCCP run: the lattice, which edges and blocks are
/// executable, and the two worklists.
struct Sccp<'f> {
    func: &'f SSAFunction,
    values: Minting<'f>,
    lattice: IdVec<VarId, LatticeValue>,
    executable: HashSet<(u64, u64)>,
    block_visited: HashSet<u64>,
    cfg_worklist: VecDeque<(u64, u64)>,
    ssa_worklist: VecDeque<VarId>,
}

impl Sccp<'_> {
    /// Lower `var` to `value`, queueing its readers when it falls.
    fn lower(&mut self, var: VarId, value: LatticeValue) {
        if update_lattice(&mut self.lattice, var, value) {
            self.ssa_worklist.push_back(var);
        }
    }

    fn evaluate_phi(&mut self, phi: &PhiNode<VarId>, block_addr: u64) {
        let value = evaluate_phi_sccp(
            phi,
            &self.executable,
            &self.values,
            &self.lattice,
            block_addr,
        );
        self.lower(phi.dst, value);
    }

    fn evaluate_op(&mut self, op: &Op) {
        if let Some(dst) = op.dst() {
            let value = evaluate_op_sccp(op, &self.values, &self.lattice);
            self.lower(*dst, value);
        }
    }

    fn evaluate_terminator(&mut self, block_addr: u64) {
        evaluate_terminator_sccp(
            self.func,
            &self.values,
            block_addr,
            &self.lattice,
            &mut self.cfg_worklist,
        );
    }

    /// The edge `from -> to` is executable: its merges are re-evaluated, and
    /// the block's operations the first time any edge reaches it.
    fn enter<C: SsaWorkControl + ?Sized>(
        &mut self,
        from: u64,
        to: u64,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        if !self.executable.insert((from, to)) {
            return Ok(());
        }
        let func = self.func;
        let Some(block) = func.get_block(to) else {
            return Ok(());
        };
        for phi in block.phis() {
            control.poll()?;
            self.evaluate_phi(phi, to);
        }
        if self.block_visited.insert(to) {
            for op in block.ops() {
                control.poll()?;
                self.evaluate_op(op);
            }
            self.evaluate_terminator(to);
        }
        Ok(())
    }

    /// A value read at `use_loc` fell: re-evaluate the reader, where its
    /// block is executable.
    fn revisit(&mut self, use_loc: &UseLocation) {
        let func = self.func;
        match *use_loc {
            UseLocation::Phi {
                block_addr,
                phi_idx,
            } => {
                if !self.block_visited.contains(&block_addr) {
                    return;
                }
                if let Some(phi) = func
                    .get_block(block_addr)
                    .and_then(|block| block.phis().get(phi_idx))
                {
                    self.evaluate_phi(phi, block_addr);
                }
            }
            UseLocation::Op { block_addr, op_idx } => {
                if !self.block_visited.contains(&block_addr) {
                    return;
                }
                let Some(op) = func
                    .get_block(block_addr)
                    .and_then(|block| block.ops().get(op_idx))
                else {
                    return;
                };
                self.evaluate_op(op);
                if matches!(op, SSAOp::CBranch { .. }) {
                    self.evaluate_terminator(block_addr);
                }
            }
        }
    }
}

/// Wegman and Zadeck's sparse conditional constants over the function's
/// ids. The lattice is a dense vector, so a value's state is one index; each
/// value falls at most twice (Top, Const, Bottom), and each fall revisits its
/// readers, so the walk is `O(n + e)` in operations, uses and edges.
fn sccp_with_control<C: SsaWorkControl + ?Sized>(
    func: &SSAFunction,
    control: &C,
) -> Result<SccpResult, SsaExecutionStopReason> {
    control.poll()?;
    let mut sccp = Sccp {
        func,
        values: Minting::new(func.values()),
        lattice: IdVec::filled(func.values().len(), LatticeValue::Top),
        executable: HashSet::new(),
        block_visited: HashSet::new(),
        cfg_worklist: VecDeque::new(),
        ssa_worklist: VecDeque::new(),
    };
    let use_map = build_use_map(func);

    for block in func.blocks() {
        control.poll()?;
        let (values, lattice) = (&sccp.values, &mut sccp.lattice);
        block.for_each_def(|def| init_if_input(values, *def.var, lattice));
        block.for_each_source(|src| init_if_input(values, *src.var, lattice));
    }

    // The pseudo-edge into the root; nothing names it as a merge source.
    sccp.cfg_worklist.push_back((u64::MAX, func.root()));

    while !sccp.cfg_worklist.is_empty() || !sccp.ssa_worklist.is_empty() {
        control.poll()?;
        while let Some((from, to)) = sccp.cfg_worklist.pop_front() {
            control.poll()?;
            sccp.enter(from, to, control)?;
        }
        while let Some(var) = sccp.ssa_worklist.pop_front() {
            control.poll()?;
            for use_loc in use_map.get(var) {
                control.poll()?;
                sccp.revisit(use_loc);
            }
        }
    }

    let Sccp {
        lattice,
        executable,
        ..
    } = sccp;
    let mut consts = IdMap::new(func.values().len());
    for (id, value) in lattice.iter() {
        if let LatticeValue::Const(c) = value {
            consts.insert(id, *c);
        }
    }
    control.poll()?;
    Ok((consts, executable))
}

fn mask_for_bits(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else if bits == 0 {
        0
    } else {
        (1u64 << bits) - 1
    }
}

/// Whether the optimizer folds this operation over constants; a flag over literals is r2rewrite's `literal.flag` to fold.
fn folds_over_constants<V>(op: &SSAOp<V>) -> bool {
    op.operation().is_some()
        && !matches!(
            op,
            SSAOp::IntCarry { .. } | SSAOp::IntSCarry { .. } | SSAOp::IntSBorrow { .. }
        )
}

/// The value `op` computes from the operands `known` answers, literals
/// included.
fn eval_const_op(
    op: &Op,
    values: &Minting<'_>,
    known: impl Fn(VarId) -> Option<u64>,
) -> Option<u64> {
    use SSAOp::*;

    let dst = op.dst()?;
    let mask = mask_for_bits(width(values, *dst).saturating_mul(8));
    // Absorbing elements decide the value whatever the other operand holds: `or rax, -1` reads nothing.
    match op {
        IntMult { a, b, .. } | IntAnd { a, b, .. }
            if known(*a) == Some(0) || known(*b) == Some(0) =>
        {
            return Some(0);
        }
        IntOr { a, b, .. }
            if [known(*a), known(*b)]
                .into_iter()
                .flatten()
                .any(|value| value & mask == mask) =>
        {
            return Some(mask);
        }
        _ => {}
    }
    if !folds_over_constants(op) {
        return None;
    }
    let operands = op
        .sources()
        .into_iter()
        .map(|id| known(*id))
        .collect::<Option<Vec<_>>>()?;
    crate::constant::computed(
        op,
        |id: &VarId| crate::op::var_facts(values.var(*id)),
        &operands,
    )
}

/// The register a source interface states the result in, where its logical
/// value describes that register coherently: the whole of it, or the low
/// bits of an integer.
pub(crate) fn coherent_return_carrier(
    interface: &SourceFunctionInterface,
) -> Option<CanonicalStorageId> {
    let SourceFunctionReturn::Register { storage } = interface.return_kind() else {
        return None;
    };
    let logical = interface.return_logical_value()?;
    let graph = interface.type_graph()?;
    let source_type = graph
        .types()
        .get(usize::try_from(logical.type_id()).ok()?)?;
    let carrier = logical.carrier();
    let storage_bits = u64::from(storage.size).checked_mul(8)?;
    if storage.space != CanonicalStorageSpace::Register
        || storage.size == 0
        || carrier.offset_bits() != 0
        || carrier.size_bits() == 0
        || carrier.size_bits() != source_type.size_bits()
        || carrier.size_bits() % 8 != 0
        || carrier.size_bits() > storage_bits
    {
        return None;
    }
    match carrier.kind() {
        SourceCarrierKind::Full if carrier.size_bits() == storage_bits => Some(storage),
        SourceCarrierKind::LowBits
            if carrier.size_bits() < storage_bits
                && matches!(
                    source_type.kind(),
                    SourceTypeKind::SignedInteger
                        | SourceTypeKind::UnsignedInteger
                        | SourceTypeKind::Char { .. }
                ) =>
        {
            Some(storage)
        }
        _ => None,
    }
}

/// The plan that reads every constant SCCP proved where its value was read.
fn replace_sources_with_constants(
    func: &SSAFunction,
    consts: &IdMap<VarId, u64>,
    return_storage: Option<CanonicalStorageId>,
    stats: &mut OptimizationStats,
) -> EditPlan {
    let mut plan = EditPlan::new();
    let mut values = Minting::new(func.values());

    for &addr in func.block_addrs() {
        let is_return_block = func
            .cfg()
            .get_block(addr)
            .is_some_and(|cfg_block| cfg_block.is_return());
        let Some(block) = func.get_block(addr) else {
            continue;
        };

        for (id, phi) in block.sited_phis() {
            let preserve_phi_sources = is_return_block
                && return_storage.is_some_and(|storage| phi.canonical_storage == Some(storage));
            if preserve_phi_sources {
                continue;
            }
            let mut replaced = phi.clone();
            let mut changed = false;
            for (_, src) in &mut replaced.sources {
                if let Some(val) = consts.get(*src).copied() {
                    let new_var = values.constant(val, width(&values, *src));
                    if new_var != *src {
                        *src = new_var;
                        stats.constants_propagated += 1;
                        changed = true;
                    }
                }
            }
            if changed {
                plan.reshape(ShapeEdit::ReplacePhi {
                    block: addr,
                    id,
                    phi: replaced,
                });
            }
        }

        for (id, op) in block.sited() {
            let new_op = op.map_sources(|var: &VarId| match consts.get(*var).copied() {
                Some(val) => values.constant(val, width(&values, *var)),
                None => *var,
            });
            if &new_op != op {
                let delta = count_source_replacements(op, &new_op);
                if delta > 0 {
                    stats.constants_propagated += delta;
                }
                plan.replace(id, new_op);
            }
        }
    }

    plan.adopt(values.finish());
    plan
}

fn apply_sccp_results(
    func: &mut SSAFunction,
    consts: &IdMap<VarId, u64>,
    executable_edges: &HashSet<(u64, u64)>,
    return_carrier: Option<CanonicalStorageId>,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;
    let mut cfg_changed = false;

    let constants = replace_sources_with_constants(func, consts, return_carrier, stats);
    if !constants.is_empty() {
        changed = true;
    }
    func.apply_edits(constants);
    stats.sccp_constants_found = consts.len();

    #[derive(Debug, Clone, Copy)]
    struct BranchRewrite {
        block_addr: u64,
        op_id: crate::arena::OpId,
        keep_target: u64,
        dead_target: u64,
        replaced: Option<VarId>,
    }

    let mut rewrites = Vec::new();
    for &addr in func.block_addrs() {
        let Some(block) = func.get_block(addr) else {
            continue;
        };
        let Some(cfg_block) = func.cfg().get_block(addr) else {
            continue;
        };
        let BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } = &cfg_block.terminator
        else {
            continue;
        };

        for (op_id, op) in block.sited() {
            if let SSAOp::CBranch { cond, target } = op
                && let Some(value) = func.var(*cond).constant_bits()
            {
                let take_true = value != 0;
                let (keep_target, dead_target) = if take_true {
                    (*true_target, *false_target)
                } else {
                    (*false_target, *true_target)
                };
                rewrites.push(BranchRewrite {
                    block_addr: addr,
                    op_id,
                    keep_target,
                    dead_target,
                    replaced: take_true.then_some(*target),
                });
                break;
            }
        }
    }

    // A decided branch: the edge it no longer takes, and what each merge at
    // the far end read along it, go with it.
    let mut decided = EditPlan::new();
    for rw in rewrites {
        // The branch that remains was never a call site the source named, so
        // it keeps no instruction identity.
        let op = match rw.replaced {
            Some(target) => SSAOp::Branch {
                target,
                instruction: None,
            },
            None => SSAOp::Nop,
        };
        decided.replace(rw.op_id, op);
        decided.reshape(ShapeEdit::RemoveEdge {
            from: rw.block_addr,
            to: rw.dead_target,
        });
        decided.reshape(ShapeEdit::SetTerminator {
            block: rw.block_addr,
            terminator: BlockTerminator::Branch {
                target: rw.keep_target,
            },
        });
        decided.reshape(ShapeEdit::DropPhiSources {
            block: rw.dead_target,
            pred: rw.block_addr,
        });
        stats.sccp_edges_pruned += 1;
        changed = true;
        cfg_changed = true;
    }
    func.apply_edits(decided);

    // Every edge SCCP never found executable, read off the graph the
    // decided branches left.
    let mut unexecuted = EditPlan::new();
    for &addr in func.block_addrs() {
        for succ in func.successors(addr) {
            if !executable_edges.contains(&(addr, succ)) {
                unexecuted.reshape(ShapeEdit::RemoveEdge {
                    from: addr,
                    to: succ,
                });
                unexecuted.reshape(ShapeEdit::DropPhiSources {
                    block: succ,
                    pred: addr,
                });
                stats.sccp_edges_pruned += 1;
                changed = true;
                cfg_changed = true;
            }
        }
    }
    func.apply_edits(unexecuted);

    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(func.root());
    while let Some(addr) = queue.pop_front() {
        if !reachable.insert(addr) {
            continue;
        }
        for succ in func.successors(addr) {
            queue.push_back(succ);
        }
    }

    // A block no edge reaches any more goes, and the merges it fed stop
    // reading it; the reorder then drops its operations.
    let mut unreachable = EditPlan::new();
    for &addr in func.block_addrs() {
        if !reachable.contains(&addr) {
            for succ in func.successors(addr) {
                unreachable.reshape(ShapeEdit::DropPhiSources {
                    block: succ,
                    pred: addr,
                });
            }
            unreachable.reshape(ShapeEdit::RemoveBlock(addr));
            stats.sccp_blocks_removed += 1;
            changed = true;
            cfg_changed = true;
        }
    }
    if cfg_changed {
        unreachable.reorder();
    }
    func.apply_edits(unreachable);

    changed
}

fn count_source_replacements<V: PartialEq>(before: &SSAOp<V>, after: &SSAOp<V>) -> usize {
    let mut count = 0;
    let before_sources = before.sources();
    let after_sources = after.sources();
    for (a, b) in before_sources.iter().zip(after_sources.iter()) {
        if a != b {
            count += 1;
        }
    }
    count
}

/// Each variable's defining operation, by its id.
fn definitions(func: &SSAFunction) -> IdMap<VarId, Op> {
    let mut defs = IdMap::new(func.values().len());
    for op in func.all_ops() {
        if let Some(dst) = op.dst() {
            defs.insert(*dst, op.clone());
        }
    }
    defs
}

fn inst_combine(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();
    let mut defs = definitions(func);

    let depths = definition_depths(&defs, func.values().len());
    // Each operation is rewritten until a step moves nothing; every step lowers `combine_measure`
    // (doc/adr-renderer-printer.md, R1c), so the rewriting ends, and a step that did not is a defect.
    let mut combined = EditPlan::new();
    let mut values = Minting::new(func.values());
    for addr in &block_addrs {
        let Some(block) = func.get_block(*addr) else {
            continue;
        };
        for (id, original) in block.sited() {
            let mut op = original.clone();
            loop {
                let Some(new_op) = substitute_constant_temporaries(&op, &defs, &mut values)
                    .or_else(|| fold_through_definition(&op, &defs, &mut values))
                    .or_else(|| simplify_op(&op, &mut values))
                else {
                    break;
                };
                if new_op == op {
                    break;
                }
                let (before, after) = (
                    combine_measure(&op, &depths, &values),
                    combine_measure(&new_op, &depths, &values),
                );
                assert!(
                    after < before,
                    "inst_combine rewrote {op:?} to {new_op:?} without lowering its measure"
                );
                if let Some(dst) = new_op.dst() {
                    defs.insert(*dst, new_op.clone());
                }
                op = new_op;
                stats.ops_simplified += 1;
                changed = true;
            }
            if &op != original {
                combined.replace(id, op);
            }
        }
    }
    combined.adopt(values.finish());
    func.apply_edits(combined);

    // A lane temporary that a fold made a copy of another value is that
    // value: it is the construction's own scaffolding, not a move the
    // program made, so its readers take the value and the copy goes dead.
    let mut lane_copies = IdMap::new(func.values().len());
    for (key, op) in defs.iter() {
        if let SSAOp::Copy { dst, src } = op
            && crate::rename::is_lane_temp(func.var(*dst))
        {
            lane_copies.insert(key, *src);
        }
    }
    if !lane_copies.is_empty() {
        // A chain of lane copies ends where a value is no lane copy; the
        // hops are bounded by the copies there are, which a cycle -- which
        // SSA cannot hold -- would meet.
        let resolve = |var: &VarId| {
            let mut current = *var;
            let mut hops = 0;
            while let Some(next) = lane_copies.get(current) {
                current = *next;
                hops += 1;
                if hops > lane_copies.len() {
                    break;
                }
            }
            current
        };
        // A merge keeps its copy: its edge assignment is a statement of the
        // copied object, not an expression read.
        let mut forwarded = EditPlan::new();
        for addr in &block_addrs {
            let Some(block) = func.get_block(*addr) else {
                continue;
            };
            for (id, op) in block.sited() {
                let new_op = op.map_sources(resolve);
                if &new_op != op {
                    forwarded.replace(id, new_op);
                    changed = true;
                }
            }
        }
        func.apply_edits(forwarded);
    }

    changed
}

/// Read a `Subpiece` through the operation defining its source.
///
/// A lane read is a `Subpiece` of its root, and the root's definition says
/// what the lane holds: the constant copied there, the value an `Insert` put
/// at that position, the narrower value an extension widened, or a slice of
/// a wider slice (doc/adr-register-identity.md §5). Copies of non-constants
/// are left alone: a copy is a statement the prepared SSA keeps.
/// Replace every condition assembled from condition codes with the comparison
/// the source wrote. Always runs: the graph is what every later stage reads.
/// One equality test a block ends in: `selector == value` sends control to
/// `equal`, anything else to `other`.
struct EqualityTest {
    selector: VarId,
    value: u64,
    equal: u64,
    other: u64,
}

/// A comparison chain, fused into the multiway branch it lowers.
///
/// A `switch` too small for a jump table compiles to one equality test per
/// case, each falling to the next, and the case bodies fall into each other
/// exactly as the source's `case` labels did. Structured as tests, that shape
/// needs a `goto`: the default edge leaves from the innermost test and jumps
/// over every body. The tests are one branch on one value, so the graph says
/// so, and the structurer prints the `switch` it already prints for a table.
///
/// Only a chain whose bodies fall into each other is fused. Tests whose bodies
/// each rejoin the same successor structure as `else if`, and that is what the
/// source most likely wrote.
fn fuse_compare_chains_in_function(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let defs = definitions(func);
    let define = |var: VarId| defs.get(var);
    let constant = |var: VarId| func.var(var).constant_bits();
    // The value a copy chain carries: a promoted slot's reload is a copy of
    // the store, and the store a copy of the register. The value view's copy
    // root, which dominates the copy, so the fused switch may branch on it.
    let views = crate::view::ValueViews::compute(func);
    let root = |var: VarId| views.copy_root(var);
    // `x == c`, or the zero flag of `x - c` where the difference also lands in
    // a register and so was left as the flag fold found it.
    let against_constant = |a: VarId, b: VarId| {
        let (selector, value) = match (constant(a), constant(b)) {
            (None, Some(value)) => (a, value),
            (Some(value), None) => (b, value),
            _ => return None,
        };
        if value == 0
            && let Some(SSAOp::IntSub { a: x, b: c, .. }) = define(root(selector))
            && let Some(c) = constant(root(*c))
        {
            return Some((root(*x), c));
        }
        Some((root(selector), value))
    };
    // The test a condition is, through its copies and negations. Each step
    // reads an operand of the operation before it, and `define` names no
    // phi, so the walk runs down one acyclic definition chain; the visited
    // set states that bound instead of a count.
    let equality = |var: VarId| {
        let mut current = root(var);
        let mut negated = false;
        let mut visited = IdSet::new(func.values().len());
        loop {
            if !visited.insert(current) {
                return None;
            }
            match define(current)? {
                SSAOp::BoolNot { src, .. } => {
                    negated = !negated;
                    current = root(*src);
                }
                SSAOp::IntEqual { a, b, .. } => {
                    let (selector, value) = against_constant(*a, *b)?;
                    return Some((selector, value, negated));
                }
                SSAOp::IntNotEqual { a, b, .. } => {
                    let (selector, value) = against_constant(*a, *b)?;
                    return Some((selector, value, !negated));
                }
                _ => return None,
            }
        }
    };
    let test_of = |addr: u64| {
        let block = func.get_block(addr)?;
        let SSAOp::CBranch { cond, .. } = block.ops().last()? else {
            return None;
        };
        let BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } = func.cfg().get_block(addr)?.terminator
        else {
            return None;
        };
        if true_target == false_target {
            return None;
        }
        let (selector, value, negated) = equality(*cond)?;
        let (equal, other) = if negated {
            (false_target, true_target)
        } else {
            (true_target, false_target)
        };
        Some(EqualityTest {
            selector,
            value,
            equal,
            other,
        })
    };
    // A block that computes nothing the fused branch does not: values only,
    // no memory and no call, and it is entered from the chain alone.
    let pure_link = |addr: u64| {
        let block = func.get_block(addr)?;
        if !block.phis().is_empty() || func.predecessors(addr).len() != 1 {
            return None;
        }
        let (last, body) = block.ops().split_last()?;
        let pure = body.iter().all(|op| {
            op.dst().is_some()
                && !matches!(
                    op,
                    SSAOp::Load { .. }
                        | SSAOp::LoadLinked { .. }
                        | SSAOp::LoadGuarded { .. }
                        | SSAOp::AtomicCAS { .. }
                        | SSAOp::CallOther { .. }
                        | SSAOp::CallDefine { .. }
                        | SSAOp::CallRestore { .. }
                        | SSAOp::StoreConditional { .. }
                )
        }) || body.iter().all(|op| matches!(op, SSAOp::Nop));
        pure.then(|| last.clone())
    };

    struct Fusion {
        block: u64,
        selector: VarId,
        cases: Vec<(u64, u64)>,
        default: u64,
        links: Vec<u64>,
    }
    let mut fusions: Vec<Fusion> = Vec::new();
    let mut claimed = HashSet::new();
    for addr in func.block_addrs().to_vec() {
        if claimed.contains(&addr) {
            continue;
        }
        let Some(head) = test_of(addr) else {
            continue;
        };
        let mut cases = vec![(head.value, head.equal)];
        let mut links = Vec::new();
        let mut cur = head.other;
        loop {
            if cur == addr || links.contains(&cur) || claimed.contains(&cur) {
                r2il::refusal_evidence!("fuse-compare-chain", "{addr:#x}: {cur:#x} closes a cycle");
                break;
            }
            let Some(last) = pure_link(cur) else {
                r2il::refusal_evidence!(
                    "fuse-compare-chain",
                    "{addr:#x}: {cur:#x} is not a pure single-entry link"
                );
                break;
            };
            match last {
                SSAOp::Branch { .. } => {
                    let Some(BlockTerminator::Branch { target }) = func
                        .cfg()
                        .get_block(cur)
                        .map(|block| block.terminator.clone())
                    else {
                        break;
                    };
                    links.push(cur);
                    cur = target;
                }
                SSAOp::CBranch { .. } => {
                    let Some(test) = test_of(cur) else {
                        r2il::refusal_evidence!(
                            "fuse-compare-chain",
                            "{addr:#x}: {cur:#x} tests no equality against a constant"
                        );
                        break;
                    };
                    // One selector is one value's bits, whichever copy of
                    // them a test reads: the copies of an extension share
                    // its view, not a root any of them can be named by.
                    if !views.same_bits(test.selector, head.selector)
                        || cases.iter().any(|(value, _)| *value == test.value)
                    {
                        r2il::refusal_evidence!(
                            "fuse-compare-chain",
                            "{addr:#x}: {cur:#x} tests {} == {}, not {}",
                            func.var(test.selector).display_name(),
                            test.value,
                            func.var(head.selector).display_name()
                        );
                        break;
                    }
                    cases.push((test.value, test.equal));
                    links.push(cur);
                    cur = test.other;
                }
                _ => break,
            }
        }
        if cases.len() < 2 {
            continue;
        }
        let default = cur;
        let chain = std::iter::once(addr)
            .chain(links.iter().copied())
            .collect::<HashSet<_>>();
        let falls_through = cases.iter().any(|(_, target)| {
            !chain.contains(target)
                && func
                    .predecessors(*target)
                    .iter()
                    .any(|pred| !chain.contains(pred))
        });
        if !falls_through {
            r2il::refusal_evidence!(
                "fuse-compare-chain",
                "{addr:#x}: {} tests whose bodies rejoin, left as else-if",
                cases.len()
            );
            continue;
        }
        if cases.iter().any(|(_, target)| chain.contains(target)) || chain.contains(&default) {
            continue;
        }
        // A phi at a target reads what the chain passed it: one value from
        // every chain edge, or the fused edge cannot say which it carries.
        let targets = cases
            .iter()
            .map(|(_, target)| *target)
            .chain(std::iter::once(default))
            .collect::<BTreeSet<_>>();
        let phis_agree = targets.iter().all(|target| {
            func.get_block(*target).is_none_or(|block| {
                block.phis().iter().all(|phi| {
                    let mut carried = phi
                        .sources
                        .iter()
                        .filter(|(pred, _)| chain.contains(pred))
                        .map(|(_, var)| var);
                    let first = carried.next();
                    carried.all(|var| Some(var) == first)
                })
            })
        });
        if !phis_agree {
            r2il::refusal_evidence!(
                "fuse-compare-chain",
                "{addr:#x}: a target merges different values from the chain"
            );
            continue;
        }
        claimed.extend(chain.iter().copied());
        fusions.push(Fusion {
            block: addr,
            selector: head.selector,
            cases,
            default,
            links,
        });
    }
    if fusions.is_empty() {
        return false;
    }
    for fusion in fusions {
        r2il::refusal_evidence!(
            "fuse-compare-chain",
            "{:#x}: {} cases on {} through {} links, default {:#x}",
            fusion.block,
            fusion.cases.len(),
            func.var(fusion.selector).display_name(),
            fusion.links.len(),
            fusion.default
        );
        // The links' values stay defined: they are pure, the head dominates
        // every reader, and the merges at the targets still name them.
        // Each hoisted value is derived from the link operation it copies,
        // and so executes for that operation's instruction.
        let hoisted = fusion
            .links
            .iter()
            .filter_map(|link| func.get_block(*link))
            .flat_map(|block| {
                let body = block.len().saturating_sub(1);
                block
                    .sited()
                    .take(body)
                    .filter(|(_, op)| !matches!(op, SSAOp::Nop))
                    .map(|(id, op)| (op.clone(), Some(id)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut plan = EditPlan::new();
        if let Some((terminator, _)) = func
            .get_block(fusion.block)
            .and_then(|block| block.sited().next_back())
        {
            plan.insert(
                crate::function::Anchor::Before(terminator),
                crate::arena::Pass::FuseCompareChain,
                hoisted,
            );
            plan.replace(
                terminator,
                SSAOp::Switch {
                    selector: fusion.selector,
                },
            );
        }
        let targets = fusion
            .cases
            .iter()
            .map(|(_, target)| *target)
            .chain(std::iter::once(fusion.default))
            .collect::<BTreeSet<_>>();
        for target in &targets {
            let Some(block) = func.get_block(*target) else {
                continue;
            };
            for (id, phi) in block.sited_phis() {
                let mut merged = phi.clone();
                let carried = merged
                    .sources
                    .iter()
                    .find(|(pred, _)| *pred == fusion.block || fusion.links.contains(pred))
                    .map(|(_, var)| *var);
                merged
                    .sources
                    .retain(|(pred, _)| *pred != fusion.block && !fusion.links.contains(pred));
                if let Some(var) = carried {
                    merged.sources.push((fusion.block, var));
                }
                // A merge lists its sources in predecessor order.
                merged.sources.sort_by_key(|(pred, _)| *pred);
                plan.reshape(ShapeEdit::ReplacePhi {
                    block: *target,
                    id,
                    phi: merged,
                });
            }
        }
        for link in &fusion.links {
            plan.reshape(ShapeEdit::RemoveBlock(*link));
        }
        plan.reshape(ShapeEdit::SetTerminator {
            block: fusion.block,
            terminator: BlockTerminator::Switch {
                cases: fusion.cases.clone(),
                default: Some(fusion.default),
            },
        });
        func.apply_edits(plan);
        stats.chains_fused += 1;
    }
    let mut reorder = EditPlan::new();
    reorder.reorder();
    func.apply_edits(reorder);
    true
}

/// What a condition-code fold reads of the function: each value's
/// definition, its copy root, and which values the pass must keep readable.
struct FlagFacts<'f> {
    func: &'f SSAFunction,
    defs: IdMap<VarId, Op>,
    views: crate::view::ValueViews<VarId>,
    kept: IdSet<VarId>,
    combined: IdSet<VarId>,
}

fn fold_condition_codes_in_function(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let len = func.values().len();
    let defs = definitions(func);
    // Values a statement other than a flag test reads. A difference read only
    // by the flags of its own instruction does go unread once they fold; one a
    // register receives does not.
    let mut kept = IdSet::new(len);
    for op in func.all_ops().filter(|op| {
        !matches!(
            op,
            SSAOp::IntEqual { .. }
                | SSAOp::IntNotEqual { .. }
                | SSAOp::IntSLess { .. }
                | SSAOp::IntSLessEqual { .. }
                | SSAOp::IntLess { .. }
                | SSAOp::IntLessEqual { .. }
                | SSAOp::IntSBorrow { .. }
                | SSAOp::IntCarry { .. }
        )
    }) {
        for source in op.sources() {
            kept.insert(*source);
        }
    }
    // Flags a disjunction reads: those are halves of one combined condition.
    // The machine copies a flag out of its scratch register before testing it,
    // so the disjunction names the copy and the fold has to look through it.
    let mut combined = IdSet::new(len);
    let mut pending = Vec::new();
    for op in func
        .all_ops()
        .filter(|op| matches!(op, SSAOp::IntOr { .. } | SSAOp::BoolOr { .. }))
    {
        for source in op.sources() {
            if combined.insert(*source) {
                pending.push(*source);
            }
        }
    }
    // Back through the copies, once: each copy's source joins the set when
    // its destination is in it. Each value joins at most once, so the walk
    // is linear in the copies.
    while let Some(var) = pending.pop() {
        if let Some(SSAOp::Copy { src, .. }) = defs.get(var)
            && combined.insert(*src)
        {
            pending.push(*src);
        }
    }
    // Which values are copies of which, as the value view states it once for
    // the whole function. The folds below rewrite comparisons, never a copy,
    // so the view stays true while they run.
    let views = crate::view::ValueViews::compute(func);
    let facts = FlagFacts {
        func,
        views,
        defs,
        kept,
        combined,
    };
    let mut folds = EditPlan::new();
    for &addr in func.block_addrs() {
        let Some(block) = func.get_block(addr) else {
            continue;
        };
        for (id, op) in block.sited() {
            let Some(folded) = fold_condition_codes(op, &facts) else {
                continue;
            };
            if &folded == op {
                continue;
            }
            folds.replace(id, folded);
            stats.ops_simplified += 1;
        }
    }
    let changed = !folds.edits_no_operation();
    func.apply_edits(folds);
    changed
}

/// A branch condition assembled from condition codes, as the comparison it is.
///
/// A machine has no `a <= b`; it subtracts and then tests the flags the
/// subtraction set, so `cmp a, b; jle` lifts to a sign flag, an overflow flag,
/// a zero flag and two boolean operations over them. The source wrote one
/// comparison, and every stage after this one -- the binding plan's reader
/// counts, the observation journal, the placement audit -- reads the graph, so
/// the comparison has to be *in* the graph rather than reconstructed later by
/// the renderer's term rewriter. Folding it there instead leaves the flags with
/// graph readers the rewritten term no longer has, which is a disagreement no
/// amount of bookkeeping downstream can settle.
///
/// The flag definitions are left where they are. They become unread, and the
/// passes that remove unread values already know what to do with them.
fn fold_condition_codes(op: &Op, facts: &FlagFacts<'_>) -> Option<Op> {
    let define = |var: VarId| facts.defs.get(var);
    let is_zero = |var: VarId| facts.func.var(var).constant_bits() == Some(0);
    // `d = a - b`, whether the flag reads the difference by name or the
    // subtraction was folded into it.
    let subtraction = |var: VarId| match define(var)? {
        SSAOp::IntSub { a, b, .. } => Some((*a, *b)),
        _ => None,
    };
    // A flag read through the copies the machine makes of it: arm64 tests
    // `ZR`, which is a copy of the `tmpZR` the subtraction wrote. The value
    // view's copy root is the end of that chain, however long.
    let define_through_copies = |var: VarId| define(facts.views.copy_root(var));
    // The sign flag: `(a - b) <s 0`.
    let sign_flag = |var: VarId| match define_through_copies(var)? {
        SSAOp::IntSLess { a: d, b: zero, .. } if is_zero(*zero) => subtraction(*d),
        _ => None,
    };
    // The overflow flag: `sborrow(a, b)`.
    let overflow_flag = |var: VarId| match define_through_copies(var)? {
        SSAOp::IntSBorrow { a, b, .. } => Some((*a, *b)),
        _ => None,
    };
    // The zero flag: `(a - b) == 0`, or already the equality this pass made
    // of it, since the two halves of a disjunction fold in one walk.
    let zero_flag = |var: VarId| match define_through_copies(var)? {
        SSAOp::IntEqual { a: d, b: zero, .. } if is_zero(*zero) => subtraction(*d),
        SSAOp::IntEqual { a, b, .. } => Some((*a, *b)),
        _ => None,
    };
    // The unsigned ordering: the carry of `a - b` is `b <= a`, and the machine
    // tests its negation for `a < b`.
    let unsigned_order = |var: VarId| match define_through_copies(var)? {
        SSAOp::IntLess { a, b, .. } => Some((*a, *b)),
        SSAOp::BoolNot { src, .. } => match define_through_copies(*src)? {
            SSAOp::IntLessEqual { a: y, b: x, .. } => Some((*x, *y)),
            _ => None,
        },
        _ => None,
    };
    // `SF != OF` is `a <s b`, and `SF == OF` is `b <=s a`. Either order.
    let signed_order = |x: VarId, y: VarId| {
        sign_flag(x)
            .zip(overflow_flag(y))
            .or_else(|| sign_flag(y).zip(overflow_flag(x)))
            .filter(|(sign, overflow)| sign == overflow)
            .map(|(sign, _)| sign)
    };
    match *op {
        // `jl` / `jge`: the sign and overflow flags alone.
        SSAOp::IntNotEqual { dst, a, b } => {
            if let Some((left, right)) = signed_order(a, b) {
                return Some(SSAOp::IntSLess {
                    dst,
                    a: left,
                    b: right,
                });
            }
            if facts.kept.contains(a) && !facts.combined.contains(dst) {
                return None;
            }
            let (left, right) = is_zero(b).then(|| subtraction(a)).flatten()?;
            Some(SSAOp::IntNotEqual {
                dst,
                a: left,
                b: right,
            })
        }
        SSAOp::IntEqual { dst, a, b } => {
            if let Some((left, right)) = signed_order(a, b) {
                return Some(SSAOp::IntSLessEqual {
                    dst,
                    a: right,
                    b: left,
                });
            }
            // The zero flag of a subtraction is an equality between its
            // operands. True of two's complement at any width, and it is what
            // lets the difference itself go unread.
            // Only where the difference really does go unread. When a
            // register receives it, restating the test over the operands moves
            // the read to before the write, and the comparison can no longer be
            // spelled after it -- which is what leaves the flag in a local.
            // Unless the flag is half of a combined condition: `jle` and
            // `jbe` are an ordering beside this test, and that fold needs the
            // test in its operand form to recognise the pair.
            if facts.kept.contains(a) && !facts.combined.contains(dst) {
                return None;
            }
            let (left, right) = is_zero(b).then(|| subtraction(a)).flatten()?;
            Some(SSAOp::IntEqual {
                dst,
                a: left,
                b: right,
            })
        }
        // `jle` / `jg`: the ordering with the zero flag beside it. The lifter
        // spells the disjunction of two flags as either an integer or a
        // boolean or, depending on the instruction it came from.
        SSAOp::IntOr { dst, a, b } | SSAOp::BoolOr { dst, a, b } => {
            // The ordering half is either still the flag pair or already the
            // comparison this pass made of it, because the two are folded in
            // one walk and the operand may have been reached first.
            let ordered = |ordering: VarId, zero: VarId| {
                let (left, right, signed) = match define(ordering)? {
                    SSAOp::IntNotEqual { a: x, b: y, .. } => {
                        let (l, r) = signed_order(*x, *y)?;
                        (l, r, true)
                    }
                    SSAOp::IntSLess { a: x, b: y, .. } => (*x, *y, true),
                    _ => {
                        let (l, r) = unsigned_order(ordering)?;
                        (l, r, false)
                    }
                };
                let (zero_left, zero_right) = zero_flag(zero)?;
                let same = (zero_left == left && zero_right == right)
                    || (zero_left == right && zero_right == left);
                same.then_some((left, right, signed))
            };
            let (left, right, signed) = ordered(a, b).or_else(|| ordered(b, a))?;
            Some(if signed {
                SSAOp::IntSLessEqual {
                    dst,
                    a: left,
                    b: right,
                }
            } else {
                SSAOp::IntLessEqual {
                    dst,
                    a: left,
                    b: right,
                }
            })
        }
        // `jg` / `ja`: the non-strict ordering with the zero flag denied beside
        // it, which is the strict ordering.
        SSAOp::BoolAnd { dst, a, b } | SSAOp::IntAnd { dst, a, b } => {
            let denied_zero = |var: VarId| match define_through_copies(var)? {
                SSAOp::BoolNot { src, .. } => zero_flag(*src),
                _ => None,
            };
            // The ordering half: the signed pair, or the comparison this pass
            // already made of either pair.
            let ordered = |var: VarId| match define_through_copies(var)? {
                SSAOp::IntEqual { a: x, b: y, .. } => {
                    let (l, r) = signed_order(*x, *y)?;
                    Some((r, l, true))
                }
                SSAOp::IntSLessEqual { a: x, b: y, .. } => Some((*x, *y, true)),
                SSAOp::IntLessEqual { a: x, b: y, .. } => Some((*x, *y, false)),
                _ => None,
            };
            let strict = |ordering: VarId, zero: VarId| {
                let (left, right, signed) = ordered(ordering)?;
                let (zero_left, zero_right) = denied_zero(zero)?;
                let same = (zero_left == left && zero_right == right)
                    || (zero_left == right && zero_right == left);
                same.then_some((left, right, signed))
            };
            let (left, right, signed) = strict(a, b).or_else(|| strict(b, a))?;
            Some(if signed {
                SSAOp::IntSLess {
                    dst,
                    a: left,
                    b: right,
                }
            } else {
                SSAOp::IntLess {
                    dst,
                    a: left,
                    b: right,
                }
            })
        }
        _ => None,
    }
}

/// The constant a value is, computed through its definitions: the decompile
/// pipeline runs no constant propagation, so `x9 = 4; (x9 == 0)` is decided
/// here where the operation that reads the result is simplified.
fn constant_through_definitions(
    var: VarId,
    defs: &IdMap<VarId, Op>,
    values: &Minting<'_>,
    depth: u32,
) -> Option<u64> {
    if let Some(value) = const_value(values, var) {
        return Some(value);
    }
    if depth > 8 {
        return None;
    }
    let op = defs.get(var)?;
    let mut known = Vec::new();
    for source in op.sources() {
        known.push((
            *source,
            constant_through_definitions(*source, defs, values, depth + 1)?,
        ));
    }
    eval_const_op(op, values, |id| {
        known
            .iter()
            .find(|(source, _)| *source == id)
            .map(|(_, value)| *value)
    })
}

/// A mask over a boolean keeps it or kills it, and nothing in between.
fn fold_mask_over_boolean(
    op: &Op,
    defs: &IdMap<VarId, Op>,
    values: &mut Minting<'_>,
) -> Option<Op> {
    let SSAOp::IntAnd { dst, a, b } = *op else {
        return None;
    };
    let (mask, value) = match (const_value(values, a), const_value(values, b)) {
        (Some(mask), _) => (mask, b),
        (_, Some(mask)) => (mask, a),
        _ => return None,
    };
    if !is_boolean_valued(value, defs, values) {
        return None;
    }
    let src = if mask & 1 == 1 {
        value
    } else {
        values.constant(0, width(values, dst))
    };
    Some(SSAOp::Copy { dst, src })
}

/// Whether a value is known to be `0` or `1` rather than merely narrow.
fn is_boolean_valued(var: VarId, defs: &IdMap<VarId, Op>, values: &Minting<'_>) -> bool {
    if let Some(value) = const_value(values, var) {
        return value <= 1;
    }
    matches!(
        defs.get(var),
        Some(
            SSAOp::IntEqual { .. }
                | SSAOp::IntNotEqual { .. }
                | SSAOp::IntLess { .. }
                | SSAOp::IntSLess { .. }
                | SSAOp::IntLessEqual { .. }
                | SSAOp::IntSLessEqual { .. }
                | SSAOp::IntCarry { .. }
                | SSAOp::IntSCarry { .. }
                | SSAOp::IntSBorrow { .. }
                | SSAOp::BoolNot { .. }
                | SSAOp::BoolAnd { .. }
                | SSAOp::BoolOr { .. }
                | SSAOp::BoolXor { .. }
        )
    )
}

/// Read every temporary operand as the constant its definitions make it.
/// What every `inst_combine` step lowers, lexicographically: more than a copy, non-constant
/// operands, the depth a slice reads (doc/adr-renderer-printer.md, R1c).
fn combine_measure(
    op: &Op,
    depth: &IdMap<VarId, usize>,
    values: &Minting<'_>,
) -> (bool, usize, usize) {
    let unknown = op
        .sources()
        .into_iter()
        .filter(|var| const_value(values, **var).is_none());
    let through = match op {
        SSAOp::Subpiece { src, .. } => depth.get(*src).copied().unwrap_or(0),
        _ => 0,
    };
    (!matches!(op, SSAOp::Copy { .. }), unknown.count(), through)
}

/// The longest chain of non-merge definitions above each value, in O(definitions); a fold reads a
/// strictly shallower value, and rewrites name only values above, so the depths hold (R1c).
fn definition_depths(defs: &IdMap<VarId, Op>, limit: usize) -> IdMap<VarId, usize> {
    let mut depth = IdMap::new(limit);
    for (root, _) in defs.iter() {
        let mut stack = vec![(root, false)];
        while let Some((var, expanded)) = stack.pop() {
            if depth.get(var).is_some() {
                continue;
            }
            let sources: Vec<VarId> = match defs.get(var) {
                Some(op) if !matches!(op, SSAOp::Phi { .. }) => {
                    op.sources().into_iter().copied().collect()
                }
                _ => Vec::new(),
            };
            if expanded {
                let deepest = sources
                    .iter()
                    .filter_map(|source| depth.get(*source).copied())
                    .max();
                depth.insert(var, deepest.map_or(0, |deepest| deepest + 1));
                continue;
            }
            stack.push((var, true));
            let pending = sources
                .into_iter()
                .filter(|source| depth.get(*source).is_none());
            stack.extend(pending.map(|source| (source, false)));
        }
    }
    depth
}

fn substitute_constant_temporaries(
    op: &Op,
    defs: &IdMap<VarId, Op>,
    values: &mut Minting<'_>,
) -> Option<Op> {
    // A phi arm is an edge, not an operand.
    if matches!(op, SSAOp::Phi { .. }) {
        return None;
    }
    let mut substituted = false;
    let mapped = op.map_sources(|var: &VarId| {
        let (temporary, literal, size) = {
            let spelled = values.var(*var);
            (
                spelled.is_temp(),
                spelled.constant_bits().is_some(),
                spelled.size,
            )
        };
        if !temporary || literal {
            return *var;
        }
        match constant_through_definitions(*var, defs, values, 0) {
            Some(value) => {
                substituted = true;
                values.constant(value, size)
            }
            None => *var,
        }
    });
    substituted.then_some(mapped)
}

fn fold_through_definition(
    op: &Op,
    defs: &IdMap<VarId, Op>,
    values: &mut Minting<'_>,
) -> Option<Op> {
    // A selection on a condition its definitions decide is the arm decided.
    if let SSAOp::Select(select) = op {
        let chosen = match constant_through_definitions(select.cond, defs, values, 0)? {
            0 => select.if_false,
            _ => select.if_true,
        };
        return Some(SSAOp::Copy {
            dst: select.dst,
            src: chosen,
        });
    }
    if let Some(folded) = fold_mask_over_boolean(op, defs, values) {
        return Some(folded);
    }
    let SSAOp::Subpiece { dst, src, offset } = *op else {
        return None;
    };
    let values: &Minting<'_> = values;
    let producer = defs.get(src)?;
    let lane_start = u64::from(offset) * 8;
    let lane_bits = u64::from(width(values, dst)) * 8;
    let lane_end = lane_start + lane_bits;
    let subpiece = |src: VarId, offset: u64| {
        let offset = u32::try_from(offset).ok()?;
        Some(
            if u64::from(width(values, src)) * 8 == lane_bits && offset == 0 {
                SSAOp::Copy { dst, src }
            } else {
                SSAOp::Subpiece { dst, src, offset }
            },
        )
    };
    match producer {
        SSAOp::Copy { src: value, .. } if const_value(values, *value).is_some() => {
            subpiece(*value, u64::from(offset))
        }
        SSAOp::Insert(insert) => {
            let (root, value) = (insert.src, insert.value);
            let position = const_value(values, insert.position)?;
            let inserted_end = position.checked_add(u64::from(width(values, value)) * 8)?;
            if position <= lane_start && lane_end <= inserted_end {
                subpiece(value, (lane_start - position) / 8)
            } else if lane_end <= position || inserted_end <= lane_start {
                subpiece(root, u64::from(offset))
            } else {
                None
            }
        }
        SSAOp::IntZExt { src: narrow, .. } | SSAOp::IntSExt { src: narrow, .. }
            if lane_end <= u64::from(width(values, *narrow)) * 8 =>
        {
            subpiece(*narrow, u64::from(offset))
        }
        SSAOp::Subpiece {
            src: wider,
            offset: inner,
            ..
        } => subpiece(*wider, u64::from(offset) + u64::from(*inner)),
        _ => None,
    }
}

/// What an operation simplifies to before its constant is minted.
enum Simplified {
    Constant(u64),
    Copy(VarId),
}

fn simplify_op(op: &Op, values: &mut Minting<'_>) -> Option<Op> {
    use SSAOp::*;
    use Simplified::{Constant, Copy as CopyOf};

    let dst = *op.dst()?;
    let size = width(values, dst);
    let mask = mask_for_bits(size.saturating_mul(8));

    if matches!(op, Copy { .. }) {
        return None;
    }
    let simplified = {
        let values: &Minting<'_> = values;
        let const_of = |var: &VarId| const_value(values, *var);
        // Over constants the value is what `r2il::eval` says the operation computes, or nothing.
        if folds_over_constants(op)
            && let Some(operands) = op
                .sources()
                .into_iter()
                .map(const_of)
                .collect::<Option<Vec<_>>>()
        {
            Constant(crate::constant::computed(
                op,
                |id: &VarId| crate::op::var_facts(values.var(*id)),
                &operands,
            )?)
        } else {
            identity(op, values, mask)?
        }
    };

    Some(match simplified {
        Constant(value) => SSAOp::Copy {
            dst,
            src: values.constant(value & mask, size),
        },
        CopyOf(src) => SSAOp::Copy { dst, src },
    })
}

/// What remains once no operand is all constants: identities, which hold
/// whatever the unknown operand is.
fn identity(op: &Op, values: &Minting<'_>, mask: u64) -> Option<Simplified> {
    use SSAOp::*;
    use Simplified::{Constant, Copy as CopyOf};

    let const_of = |var: &VarId| const_value(values, *var);
    let size = width(values, *op.dst()?);
    Some(match op {
        // A selection on a decided condition is the arm it decided.
        Select(select) => match const_of(&select.cond) {
            Some(0) => CopyOf(select.if_false),
            Some(_) => CopyOf(select.if_true),
            None => return None,
        },
        IntAdd { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => CopyOf(*b),
            (_, Some(0)) => CopyOf(*a),
            _ => return None,
        },
        IntSub { a, b, .. } => match const_of(b) {
            Some(0) => CopyOf(*a),
            _ if a == b => Constant(0),
            _ => return None,
        },
        IntMult { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) | (_, Some(0)) => Constant(0),
            (Some(1), _) => CopyOf(*b),
            (_, Some(1)) => CopyOf(*a),
            _ => return None,
        },
        IntDiv { a, b, .. } | IntSDiv { a, b, .. } => match const_of(b) {
            Some(1) => CopyOf(*a),
            _ => return None,
        },
        IntAnd { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) | (_, Some(0)) => Constant(0),
            (Some(av), _) if av == mask => CopyOf(*b),
            (_, Some(bv)) if bv == mask => CopyOf(*a),
            _ => return None,
        },
        IntOr { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => CopyOf(*b),
            (_, Some(0)) => CopyOf(*a),
            // All ones absorbs: `or rax, -1` is the constant whatever `rax` held.
            (Some(av), _) if av == mask => Constant(mask),
            (_, Some(bv)) if bv == mask => Constant(mask),
            _ => return None,
        },
        IntXor { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => CopyOf(*b),
            (_, Some(0)) => CopyOf(*a),
            _ if a == b => Constant(0),
            _ => return None,
        },
        IntLeft { a, b, .. } | IntRight { a, b, .. } | IntSRight { a, b, .. } => {
            match const_of(b) {
                Some(0) => CopyOf(*a),
                _ => return None,
            }
        }
        IntEqual { a, b, .. }
        | IntNotEqual { a, b, .. }
        | IntLess { a, b, .. }
        | IntLessEqual { a, b, .. }
        | IntSLess { a, b, .. }
        | IntSLessEqual { a, b, .. }
            if a == b =>
        {
            let reflexive = matches!(
                op,
                IntEqual { .. } | IntLessEqual { .. } | IntSLessEqual { .. }
            );
            Constant(u64::from(reflexive))
        }
        BoolAnd { a, b, .. } | BoolOr { a, b, .. } => {
            // Nought decides a conjunction and one a disjunction, whatever the other operand is.
            let absorbing = u64::from(matches!(op, BoolOr { .. }));
            match (const_of(a), const_of(b)) {
                (Some(av), _) | (_, Some(av)) if av == absorbing => Constant(absorbing),
                _ => return None,
            }
        }
        IntZExt { src, .. } | IntSExt { src, .. } if width(values, *src) == size => CopyOf(*src),
        _ => return None,
    })
}

#[cfg(test)]
mod sccp_tests {
    use super::*;
    use crate::SSAVar;
    use crate::value_table::ValueTable;

    /// A rule over ids, run on an operation a test spells by name, with the
    /// definitions it may fold through, and its answer named back.
    fn through_ids(
        op: &SSAOp,
        definitions: &[SSAOp],
        rule: impl FnOnce(&Op, &IdMap<VarId, Op>, &mut Minting<'_>) -> Option<Op>,
    ) -> Option<SSAOp> {
        let mut table = ValueTable::default();
        let definitions = definitions
            .iter()
            .map(|op| op.map(&mut |var| table.intern(var)))
            .collect::<Vec<_>>();
        let op = op.map(&mut |var| table.intern(var));
        let mut defs = IdMap::new(table.len());
        for definition in definitions {
            if let Some(dst) = definition.dst() {
                defs.insert(*dst, definition.clone());
            }
        }
        let mut values = Minting::new(&table);
        let answer = rule(&op, &defs, &mut values)?;
        Some(answer.map(&mut |id| values.var(*id).clone()))
    }

    fn simplify(op: &SSAOp) -> Option<SSAOp> {
        through_ids(op, &[], |op, _, values| simplify_op(op, values))
    }

    fn fold(op: &SSAOp, definitions: &[SSAOp]) -> Option<SSAOp> {
        through_ids(op, definitions, fold_through_definition)
    }

    /// A binary operation, its machine operation, and whether it yields a boolean byte.
    type Binary = (
        fn(SSAVar, SSAVar, SSAVar) -> SSAOp,
        r2il::eval::Operation,
        bool,
    );

    fn binaries() -> Vec<Binary> {
        use r2il::eval::Operation as O;
        vec![
            (|dst, a, b| SSAOp::IntAdd { dst, a, b }, O::Add, false),
            (|dst, a, b| SSAOp::IntSub { dst, a, b }, O::Sub, false),
            (|dst, a, b| SSAOp::IntMult { dst, a, b }, O::Mult, false),
            (|dst, a, b| SSAOp::IntDiv { dst, a, b }, O::Div, false),
            (|dst, a, b| SSAOp::IntSDiv { dst, a, b }, O::SDiv, false),
            (|dst, a, b| SSAOp::IntAnd { dst, a, b }, O::And, false),
            (|dst, a, b| SSAOp::IntOr { dst, a, b }, O::Or, false),
            (|dst, a, b| SSAOp::IntXor { dst, a, b }, O::Xor, false),
            (|dst, a, b| SSAOp::IntLeft { dst, a, b }, O::Left, false),
            (|dst, a, b| SSAOp::IntRight { dst, a, b }, O::Right, false),
            (|dst, a, b| SSAOp::IntSRight { dst, a, b }, O::SRight, false),
            (|dst, a, b| SSAOp::IntEqual { dst, a, b }, O::Equal, true),
            (
                |dst, a, b| SSAOp::IntNotEqual { dst, a, b },
                O::NotEqual,
                true,
            ),
            (|dst, a, b| SSAOp::IntLess { dst, a, b }, O::Less, true),
            (
                |dst, a, b| SSAOp::IntLessEqual { dst, a, b },
                O::LessEqual,
                true,
            ),
            (|dst, a, b| SSAOp::IntSLess { dst, a, b }, O::SLess, true),
            (
                |dst, a, b| SSAOp::IntSLessEqual { dst, a, b },
                O::SLessEqual,
                true,
            ),
            (|dst, a, b| SSAOp::BoolAnd { dst, a, b }, O::BoolAnd, true),
            (|dst, a, b| SSAOp::BoolOr { dst, a, b }, O::BoolOr, true),
        ]
    }

    /// What `op` computes on the machine (`r2il::eval`), its operands read from `env`.
    fn machine(op: &SSAOp, env: &dyn Fn(&SSAVar) -> u128) -> Option<u128> {
        use r2il::eval::{Operation as O, Word, apply};
        let (operation, operands): (O, Vec<&SSAVar>) = match op {
            SSAOp::Copy { src, .. } => (O::Copy, vec![src]),
            SSAOp::Subpiece { src, offset, .. } => (O::Subpiece { offset: *offset }, vec![src]),
            SSAOp::IntZExt { src, .. } => (O::ZExt, vec![src]),
            SSAOp::IntSExt { src, .. } => (O::SExt, vec![src]),
            SSAOp::IntAnd { a, b, .. } => (O::And, vec![a, b]),
            SSAOp::IntLess { a, b, .. } => (O::Less, vec![a, b]),
            SSAOp::Insert(insert) => (
                O::Insert,
                vec![&insert.src, &insert.value, &insert.position],
            ),
            SSAOp::Select(select) => (
                O::Select,
                vec![&select.cond, &select.if_true, &select.if_false],
            ),
            _ => panic!("no machine operation for {op:?}"),
        };
        let value = |var: &SSAVar| var.constant_bits().map_or_else(|| env(var), u128::from);
        let words = operands
            .iter()
            .map(|var| Word::new(value(var), var.size).expect("a width"));
        apply(operation, &words.collect::<Vec<_>>(), op.dst()?.size).ok()
    }

    /// Every fold through a definition equals `r2il::eval` of the operation over its definition, for
    /// every byte x and z and every 257th half-word y (R1c).
    #[test]
    fn every_fold_through_a_definition_is_what_the_machine_computes() {
        let checked: usize = fold_cases()
            .iter()
            .map(|(defs, op)| check_fold(defs, op))
            .sum();
        assert!(checked > 0);
    }

    /// A free input of the fold cases, or a value one of them defines.
    fn fold_var(name: &str, size: u32) -> SSAVar {
        SSAVar::new(name, 1, size)
    }

    /// Each fold through a definition: its definitions over the free inputs x, z (bytes) and y (a half-word), and the operation.
    fn fold_cases() -> Vec<(Vec<SSAOp>, SSAOp)> {
        let (x, z, y) = (fold_var("x", 1), fold_var("z", 1), fold_var("y", 2));
        let (constant, byte) = (SSAVar::constant, |name: &str| fold_var(name, 1));
        let slice = |src: SSAVar, offset| SSAOp::Subpiece {
            dst: byte("d"),
            src,
            offset,
        };
        let less = SSAOp::IntLess {
            dst: byte("b"),
            a: x.clone(),
            b: z.clone(),
        };
        let masks = [0u64, 1, 0xfe, 0xff].into_iter().flat_map(|mask| {
            let (b, m) = (byte("b"), constant(mask, 1));
            [
                SSAOp::IntAnd {
                    dst: byte("d"),
                    a: b.clone(),
                    b: m.clone(),
                },
                SSAOp::IntAnd {
                    dst: byte("d"),
                    a: m,
                    b,
                },
            ]
        });
        let mut cases: Vec<_> = masks.map(|op| (vec![less.clone()], op)).collect();
        for (position, offset) in [(0u64, 0), (0, 1), (8, 0), (8, 1)] {
            let insert = SSAOp::Insert(Box::new(crate::op::InsertOp {
                dst: fold_var("r", 2),
                src: y.clone(),
                value: x.clone(),
                position: constant(position, 4),
            }));
            cases.push((vec![insert], slice(fold_var("r", 2), offset)));
        }
        let widened = fold_var("w", 2);
        let zext = SSAOp::IntZExt {
            dst: widened.clone(),
            src: x.clone(),
        };
        let sext = SSAOp::IntSExt {
            dst: widened.clone(),
            src: x.clone(),
        };
        cases.push((vec![zext], slice(widened.clone(), 0)));
        cases.push((vec![sext], slice(widened, 0)));
        let narrowed = SSAOp::Subpiece {
            dst: byte("m"),
            src: y,
            offset: 1,
        };
        cases.push((vec![narrowed], slice(byte("m"), 0)));
        let literal = SSAOp::Copy {
            dst: fold_var("c", 2),
            src: constant(0xabcd, 2),
        };
        cases.push((vec![literal], slice(fold_var("c", 2), 1)));
        for decided in [0u64, 1] {
            let condition = SSAOp::Copy {
                dst: byte("k"),
                src: constant(decided, 1),
            };
            let select = SSAOp::Select(Box::new(crate::op::SelectOp {
                dst: byte("d"),
                cond: byte("k"),
                if_true: x.clone(),
                if_false: z.clone(),
            }));
            cases.push((vec![condition], select));
        }
        cases
    }

    /// The fold of `op` over `definitions` against the machine, for every byte x and every 257th half-word y; the inputs compared.
    fn check_fold(definitions: &[SSAOp], op: &SSAOp) -> usize {
        let Some(replacement) = fold(op, definitions) else {
            panic!("the fold this case names does not fire: {op:?} over {definitions:?}");
        };
        let halves = (0u128..=0xffff)
            .step_by(257)
            .chain([0xffff, 0x8000, 0x7fff]);
        let inputs =
            (0u128..256).flat_map(|x| halves.clone().map(move |y| (x, (x * 37 + 11) & 0xff, y)));
        let mut checked = 0;
        for (xv, zv, yv) in inputs {
            let free = |v: &SSAVar| match v.name() {
                "x" => xv,
                "z" => zv,
                "y" => yv,
                _ => panic!("no input {v:?}"),
            };
            let defined = |v: &SSAVar| match definitions.iter().find(|d| d.dst() == Some(v)) {
                Some(definition) => machine(definition, &free).expect("the definition computes"),
                None => free(v),
            };
            let (Some(original), Some(folded)) =
                (machine(op, &defined), machine(&replacement, &defined))
            else {
                continue;
            };
            let at = format!("x={xv:#x} z={zv:#x} y={yv:#x}");
            assert_eq!(
                folded, original,
                "{op:?} over {definitions:?} at {at}: folded to {replacement:?}"
            );
            checked += 1;
        }
        checked
    }

    /// An operand of a checked operation: the free variable, or a literal.
    #[derive(Clone, Copy, Debug)]
    enum Operand {
        Free,
        Literal(u64),
    }

    /// What `simplify_op` replaced `op` with, as the value it computes for the free variable `x`.
    fn replaced_value(replacement: &SSAOp, free: &SSAVar, x: u128) -> u128 {
        let SSAOp::Copy { src, .. } = replacement else {
            panic!("an identity answers with a copy: {replacement:?}");
        };
        match src.constant_bits() {
            Some(bits) => u128::from(bits),
            None => {
                assert_eq!(src, free, "a copy of the free operand");
                x
            }
        }
    }

    /// Every identity `inst_combine` applies equals `r2il::eval` for every value of its free operand
    /// (0, 1, all ones or the same variable beside it), exhaustively at 8 and 16 bits (R1c).
    #[test]
    fn every_identity_inst_combine_applies_is_what_the_machine_computes() {
        let mut checked = 0usize;
        for bytes in [1u32, 2] {
            for (build, operation, boolean) in binaries() {
                checked += check_binary_identities(bytes, build, operation, boolean);
            }
            checked += check_unary_identities(bytes);
        }
        assert!(checked > 0);
    }

    /// What `simplify_op` or `eval_const_op` answers for `op`, which decides absorbing elements on its own.
    fn identity_answer(op: &SSAOp) -> Option<SSAOp> {
        let absorbed = through_ids(op, &[], |op, _, values| {
            let value = eval_const_op(op, values, |id| const_value(values, id))?;
            let dst = *op.dst()?;
            Some(SSAOp::Copy {
                dst,
                src: values.constant(value, width(values, dst)),
            })
        });
        absorbed.or_else(|| simplify(op))
    }

    /// One binary operation over each operand shape at `bytes`, against `r2il::eval`; the inputs compared.
    fn check_binary_identities(
        bytes: u32,
        build: fn(SSAVar, SSAVar, SSAVar) -> SSAOp,
        operation: r2il::eval::Operation,
        boolean: bool,
    ) -> usize {
        use r2il::eval::{Word, apply};
        let boolean_inputs = matches!(
            operation,
            r2il::eval::Operation::BoolAnd | r2il::eval::Operation::BoolOr
        );
        if boolean_inputs && bytes != 1 {
            return 0;
        }
        let mask = (1u64 << (bytes * 8)) - 1;
        let out_bytes = if boolean { 1 } else { bytes };
        let x = SSAVar::new("x", 1, bytes);
        let shapes = [0, 1, mask].into_iter().flat_map(|literal| {
            [
                (Operand::Free, Operand::Literal(literal)),
                (Operand::Literal(literal), Operand::Free),
            ]
        });
        let values: u128 = if boolean_inputs { 2 } else { 1 << (bytes * 8) };
        let mut checked = 0;
        for (left, right) in shapes.chain([(Operand::Free, Operand::Free)]) {
            let spell = |operand: Operand| match operand {
                Operand::Free => x.clone(),
                Operand::Literal(literal) => SSAVar::constant(literal & mask, bytes),
            };
            let op = build(SSAVar::new("dst", 1, out_bytes), spell(left), spell(right));
            let Some(replacement) = identity_answer(&op) else {
                continue;
            };
            let computed = (0..values).filter_map(|value| {
                let operand = |operand: Operand| match operand {
                    Operand::Free => value,
                    Operand::Literal(literal) => u128::from(literal & mask),
                };
                let words =
                    [operand(left), operand(right)].map(|v| Word::new(v, bytes).expect("a width"));
                apply(operation, &words, out_bytes)
                    .ok()
                    .map(|machine| (value, machine))
            });
            for (value, machine) in computed {
                let answered = replaced_value(&replacement, &x, value);
                assert_eq!(
                    answered, machine,
                    "{op:?} at x = {value:#x}: inst_combine answered {replacement:?}"
                );
                checked += 1;
            }
        }
        checked
    }

    /// A decided selection is its arm; an extension to its own width is its operand.
    fn check_unary_identities(bytes: u32) -> usize {
        let (x, z, dst) = (
            SSAVar::new("x", 1, bytes),
            SSAVar::new("z", 1, bytes),
            SSAVar::new("dst", 1, bytes),
        );
        let mut ops = vec![
            SSAOp::IntZExt {
                dst: dst.clone(),
                src: x.clone(),
            },
            SSAOp::IntSExt {
                dst: dst.clone(),
                src: x.clone(),
            },
        ];
        ops.extend([0u64, 1].map(|decided| {
            SSAOp::Select(Box::new(crate::op::SelectOp {
                dst: dst.clone(),
                cond: SSAVar::constant(decided, 1),
                if_true: x.clone(),
                if_false: z.clone(),
            }))
        }));
        let mut checked = 0;
        for op in &ops {
            let replacement = simplify(op).expect("the identity fires");
            for value in 0..(1u128 << (bytes * 8)) {
                let env = |v: &SSAVar| [0x5a, value][usize::from(v == &x)];
                let machine = machine(op, &env).expect("it computes");
                let answered = machine_value(&replacement, &env);
                assert_eq!(
                    answered, machine,
                    "{op:?} at x = {value:#x}: answered {replacement:?}"
                );
                checked += 1;
            }
        }
        checked
    }

    /// What a replacement copy computes, its operand read from `env`.
    fn machine_value(op: &SSAOp, env: &dyn Fn(&SSAVar) -> u128) -> u128 {
        let SSAOp::Copy { src, .. } = op else {
            panic!("an identity answers with a copy: {op:?}");
        };
        src.constant_bits().map_or_else(|| env(src), u128::from)
    }
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn make_const(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
        }
    }

    fn make_reg(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
        }
    }

    fn make_ram(addr: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Ram,
            offset: addr,
            size,
        }
    }

    fn raw_func(blocks: Vec<R2ILBlock>) -> SSAFunction {
        SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function should build")
    }

    #[test]
    fn meet_top_top() {
        assert_eq!(LatticeValue::Top.meet(LatticeValue::Top), LatticeValue::Top);
    }

    #[test]
    fn meet_top_const() {
        assert_eq!(
            LatticeValue::Top.meet(LatticeValue::Const(5)),
            LatticeValue::Const(5)
        );
    }

    #[test]
    fn meet_const_same() {
        assert_eq!(
            LatticeValue::Const(5).meet(LatticeValue::Const(5)),
            LatticeValue::Const(5)
        );
    }

    #[test]
    fn meet_const_diff() {
        assert_eq!(
            LatticeValue::Const(5).meet(LatticeValue::Const(7)),
            LatticeValue::Bottom
        );
    }

    #[test]
    fn meet_bottom_absorbs() {
        assert_eq!(
            LatticeValue::Bottom.meet(LatticeValue::Const(9)),
            LatticeValue::Bottom
        );
    }

    #[test]
    fn sccp_constant_identity_ignores_display_names() {
        let mut table = ValueTable::default();
        let spoofed = table.intern(&SSAVar::new("const:2a", 0, 8));
        let renamed = table.intern(&SSAVar::constant(0x2a, 8).renamed("renamed-value"));
        let values = Minting::new(&table);
        assert_eq!(const_value(&values, spoofed), None);
        let mut lattice = IdVec::filled(table.len(), LatticeValue::Top);
        init_if_input(&values, spoofed, &mut lattice);
        assert_eq!(lattice[spoofed], LatticeValue::Bottom);
        assert_eq!(const_value(&values, renamed), Some(0x2a));
    }

    #[test]
    fn sccp_absorbing_constant_folds_without_the_other_operand() {
        // `or rax, -1` on an entry value: the result is all ones whatever
        // `rax` held, so the entry carrier is not a reader of the return.
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntOr {
                    dst: make_reg(0, 8),
                    a: make_reg(0, 8),
                    b: make_const(u64::MAX, 8),
                },
                R2ILOp::IntAnd {
                    dst: make_reg(1, 4),
                    a: make_reg(1, 4),
                    b: make_const(0, 4),
                },
                R2ILOp::IntMult {
                    dst: make_reg(2, 4),
                    a: make_const(0, 4),
                    b: make_reg(2, 4),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);

        let (consts, _) = sccp(&func);
        assert!(
            consts
                .iter()
                .map(|(_, value)| value)
                .any(|v| *v == u64::MAX),
            "SCCP should fold `x | -1` to all ones: {consts:?}"
        );
        assert_eq!(
            consts
                .iter()
                .map(|(_, value)| value)
                .filter(|v| **v == 0)
                .count(),
            2,
            "SCCP should fold `x & 0` and `0 * x` to zero: {consts:?}"
        );
    }

    #[test]
    fn a_fold_computes_what_r2il_eval_says_the_operation_does() {
        // A four-byte 0x80 is positive at its own width, whatever width the boolean result has.
        let less = |dst| R2ILOp::IntSLess {
            dst,
            a: make_const(0x80, 4),
            b: make_const(0, 4),
        };
        // The most negative quotient's negation does not fit, so p-code gives it no value.
        let overflow = |dst| R2ILOp::IntSDiv {
            dst,
            a: make_const(1 << 63, 8),
            b: make_const(u64::MAX, 8),
        };
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                less(make_reg(0, 1)),
                overflow(make_reg(8, 8)),
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);
        let (consts, _) = sccp(&func);
        let sized = |size| {
            let found = consts.iter().filter(|(key, _)| func.var(*key).size == size);
            found.map(|(_, value)| *value).collect::<Vec<_>>()
        };
        assert_eq!(sized(1), [0], "{consts:?}");
        assert!(sized(8).is_empty(), "{consts:?}");
        // The combiner answers from the same statement once every operand is a constant.
        let flag = SSAVar::new("flag", 1, 1);
        let quotient = SSAVar::new("quotient", 1, 8);
        let constant = |value, size| SSAVar::constant(value, size);
        let signed_less = SSAOp::IntSLess {
            dst: flag.clone(),
            a: constant(0x80, 4),
            b: constant(0, 4),
        };
        let folded = SSAOp::Copy {
            dst: flag,
            src: constant(0, 1),
        };
        assert_eq!(simplify(&signed_less), Some(folded));
        let divided = SSAOp::IntSDiv {
            dst: quotient,
            a: constant(1 << 63, 8),
            b: constant(u64::MAX, 8),
        };
        assert_eq!(simplify(&divided), None);
    }

    #[test]
    fn sccp_simple_const() {
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: make_reg(0, 8),
                    a: make_const(5, 8),
                    b: make_const(3, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);

        let (consts, _) = sccp(&func);
        assert!(
            consts.iter().map(|(_, value)| value).any(|v| *v == 8),
            "SCCP should discover y = 8"
        );
    }

    #[test]
    fn sccp_phi_one_dead_edge() {
        let func = raw_func(vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![
                    R2ILOp::IntAdd {
                        dst: make_reg(8, 8),
                        a: make_reg(0, 8),
                        b: make_const(1, 8),
                    },
                    R2ILOp::Return {
                        target: make_ram(0, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ]);

        let (consts, executable) = sccp(&func);
        assert!(
            !executable.contains(&(0x1000, 0x1004)),
            "false edge should be non-executable"
        );
        assert!(
            consts
                .iter()
                .map(|(_, value)| value)
                .any(|v| *v == 2 || *v == 3),
            "phi should resolve to live input constant on the executable edge"
        );
    }

    #[test]
    fn sccp_params_stay_bottom() {
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_const(1, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);

        let (consts, _) = sccp(&func);
        assert!(
            !consts.keys().any(|k| func.var(k).name() == "reg:8"),
            "param-derived values should not be treated as constants"
        );
    }

    #[test]
    fn sccp_load_stays_bottom() {
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Load {
                    dst: make_reg(8, 8),
                    space: SpaceId::Ram,
                    addr: make_reg(0, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);

        let (consts, _) = sccp(&func);
        assert!(
            !consts.keys().any(|k| func.var(k).name() == "reg:8"),
            "loads are conservative Bottom in SCCP"
        );
    }

    #[test]
    fn sccp_noop_on_no_consts() {
        let func = raw_func(vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntAdd {
                    dst: make_reg(8, 8),
                    a: make_reg(0, 8),
                    b: make_reg(16, 8),
                },
                R2ILOp::Return {
                    target: make_ram(0, 8),
                },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }]);

        let (consts, _) = sccp(&func);
        assert!(consts.is_empty(), "no constants should be discovered");
    }

    #[test]
    fn sccp_apply_prunes_edges_and_blocks() {
        let mut func = raw_func(vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: make_const(0x1008, 8),
                    cond: make_const(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(1, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![
                    R2ILOp::Copy {
                        dst: make_reg(0, 8),
                        src: make_const(2, 8),
                    },
                    R2ILOp::Branch {
                        target: make_const(0x100c, 8),
                    },
                ],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: make_ram(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ]);

        let (consts, executable) = sccp(&func);
        let mut stats = OptimizationStats::default();
        let changed = apply_sccp_results(&mut func, &consts, &executable, None, &mut stats);
        assert!(changed);
        assert!(
            func.named_block(0x1004).is_none(),
            "dead branch block should be removed"
        );
        assert!(!func.cfg().has_edge(0x1000, 0x1004));
        assert!(stats.sccp_edges_pruned > 0);
        assert!(stats.sccp_blocks_removed > 0);
    }

    /// The definition-aware folds a lane read goes through
    /// (doc/adr-register-identity.md §5).
    #[test]
    fn subpiece_folds_through_the_definition_of_its_source() {
        let root = SSAVar::new("RAX", 1, 8);
        let older = SSAVar::new("RAX", 0, 8);
        let lane = SSAVar::new("tmp:lane:1000:1:0", 1, 4);
        let byte = SSAVar::new("tmp:lane:1000:2:0", 1, 1);
        let read = |offset: u32, size: u32| SSAOp::Subpiece {
            dst: SSAVar::new("tmp:lane:1000:3:0", 1, size),
            src: root.clone(),
            offset,
        };
        let defined_by = |op: SSAOp| vec![op];

        // A constant copied into the root: the lane is that constant's bytes.
        let constant = defined_by(SSAOp::Copy {
            dst: root.clone(),
            src: SSAVar::constant(0x1122_3344_5566_7788, 8),
        });
        assert_eq!(
            fold(&read(4, 4), &constant),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: SSAVar::constant(0x1122_3344_5566_7788, 8),
                offset: 4,
            })
        );

        // A lane inserted at bit 32: a read inside it is the inserted value,
        // a read outside it is the same read of the older root.
        let inserted = defined_by(SSAOp::Insert(Box::new(crate::op::InsertOp {
            dst: root.clone(),
            src: older.clone(),
            value: lane.clone(),
            position: SSAVar::constant(32, 4),
        })));
        assert_eq!(
            fold(&read(4, 4), &inserted),
            Some(SSAOp::Copy {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: lane.clone(),
            })
        );
        assert_eq!(
            fold(&read(5, 1), &inserted),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 1),
                src: lane.clone(),
                offset: 1,
            })
        );
        assert_eq!(
            fold(&read(0, 4), &inserted),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: older.clone(),
                offset: 0,
            })
        );
        assert_eq!(fold(&read(2, 4), &inserted), None);

        // A widened value: a read within the narrow width is the narrow value.
        let widened = defined_by(SSAOp::IntZExt {
            dst: root.clone(),
            src: lane.clone(),
        });
        assert_eq!(
            fold(&read(0, 4), &widened),
            Some(SSAOp::Copy {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: lane.clone(),
            })
        );
        assert_eq!(
            fold(&read(0, 1), &widened),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 1),
                src: lane,
                offset: 0,
            })
        );
        assert_eq!(fold(&read(0, 8), &widened), None);

        // A slice of a slice is one slice.
        let sliced = defined_by(SSAOp::Subpiece {
            dst: root.clone(),
            src: SSAVar::new("XMM0", 1, 16),
            offset: 8,
        });
        assert_eq!(
            fold(&read(2, 1), &sliced),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 1),
                src: SSAVar::new("XMM0", 1, 16),
                offset: 10,
            })
        );

        // A copy of a non-constant is a statement the prepared SSA keeps.
        let copied = defined_by(SSAOp::Copy {
            dst: root.clone(),
            src: older,
        });
        assert_eq!(fold(&read(0, 4), &copied), None);
        let _ = byte;
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn c(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
        }
    }

    fn r(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
        }
    }

    fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
        R2ILBlock {
            addr,
            size: 4,
            ops,
            switch_info: None,
            op_metadata: Default::default(),
        }
    }

    fn test(value: u64, target: u64, negated: bool) -> Vec<R2ILOp> {
        let mut ops = vec![R2ILOp::IntEqual {
            dst: r(9, 1),
            a: r(8, 8),
            b: c(value, 8),
        }];
        let cond = if negated {
            ops.push(R2ILOp::BoolNot {
                dst: r(10, 1),
                src: r(9, 1),
            });
            r(10, 1)
        } else {
            r(9, 1)
        };
        ops.push(R2ILOp::CBranch {
            target: c(target, 8),
            cond,
        });
        ops
    }

    fn body(addend: u64, next: u64) -> Vec<R2ILOp> {
        vec![
            R2ILOp::IntAdd {
                dst: r(16, 8),
                a: r(16, 8),
                b: c(addend, 8),
            },
            R2ILOp::Branch { target: c(next, 8) },
        ]
    }

    fn chain(case3_next: u64, case2_next: u64) -> SSAFunction {
        let mut head = vec![R2ILOp::IntAnd {
            dst: r(8, 8),
            a: r(0, 8),
            b: c(3, 8),
        }];
        head.extend(test(1, 0x1030, false));
        let blocks = vec![
            block(0x1000, head),
            block(0x1004, test(2, 0x1020, false)),
            block(0x1008, test(3, 0x1040, true)),
            block(0x100c, body(3, case3_next)),
            block(0x1020, body(2, case2_next)),
            block(0x1030, body(1, 0x1040)),
            block(0x1040, vec![R2ILOp::Return { target: r(0, 8) }]),
        ];
        let mut func =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function should build");
        optimize_function(&mut func, &OptimizationConfig::default());
        func
    }

    #[test]
    fn a_chain_whose_cases_fall_through_fuses_into_one_switch() {
        let func = chain(0x1020, 0x1030);
        let terminator = func
            .cfg()
            .get_block(0x1000)
            .expect("head")
            .terminator
            .clone();
        assert_eq!(
            terminator,
            BlockTerminator::Switch {
                cases: vec![(1, 0x1030), (2, 0x1020), (3, 0x100c)],
                default: Some(0x1040),
            }
        );
        assert!(matches!(
            func.named_block(0x1000).expect("head").ops().last(),
            Some(SSAOp::Switch { .. })
        ));
        assert!(func.named_block(0x1004).is_none());
        assert!(func.named_block(0x1008).is_none());
        let mut successors = func.successors(0x1000);
        successors.sort_unstable();
        successors.dedup();
        assert_eq!(successors, vec![0x100c, 0x1020, 0x1030, 0x1040]);
        let merge = func.named_block(0x1020).expect("case 2");
        assert!(
            merge.phis().iter().all(|phi| phi
                .sources
                .iter()
                .all(|(pred, _)| *pred == 0x1000 || *pred == 0x100c)),
            "phi sources: {:?}",
            merge.phis()
        );
    }

    #[test]
    fn a_chain_whose_cases_rejoin_stays_an_else_if_ladder() {
        let func = chain(0x1040, 0x1040);
        assert!(matches!(
            func.cfg().get_block(0x1000).expect("head").terminator,
            BlockTerminator::ConditionalBranch { .. }
        ));
        assert!(func.named_block(0x1004).is_some());
    }
}

#[cfg(test)]
mod signed_flag_tests {
    use super::*;
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn c(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
        }
    }

    fn r(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
        }
    }

    // `cmp x, #1` as arm64 lifts it, with the flags copied out of their
    // temporaries before the branch reads them.
    fn compare(strict: bool) -> SSAFunction {
        let x = r(0, 8);
        let mut ops = vec![
            R2ILOp::IntAnd {
                dst: x.clone(),
                a: r(8, 8),
                b: c(3, 8),
            },
            R2ILOp::IntSBorrow {
                dst: r(0x40, 1),
                a: x.clone(),
                b: c(1, 8),
            },
            R2ILOp::IntSub {
                dst: r(0x50, 8),
                a: x.clone(),
                b: c(1, 8),
            },
            R2ILOp::IntSLess {
                dst: r(0x41, 1),
                a: r(0x50, 8),
                b: c(0, 8),
            },
            R2ILOp::IntEqual {
                dst: r(0x42, 1),
                a: x,
                b: c(1, 8),
            },
            R2ILOp::Copy {
                dst: r(0x60, 1),
                src: r(0x41, 1),
            },
            R2ILOp::Copy {
                dst: r(0x61, 1),
                src: r(0x40, 1),
            },
            R2ILOp::Copy {
                dst: r(0x62, 1),
                src: r(0x42, 1),
            },
            R2ILOp::IntEqual {
                dst: r(0x70, 1),
                a: r(0x60, 1),
                b: r(0x61, 1),
            },
        ];
        let cond = if strict {
            ops.push(R2ILOp::BoolNot {
                dst: r(0x71, 1),
                src: r(0x62, 1),
            });
            ops.push(R2ILOp::BoolAnd {
                dst: r(0x72, 1),
                a: r(0x71, 1),
                b: r(0x70, 1),
            });
            r(0x72, 1)
        } else {
            r(0x70, 1)
        };
        ops.push(R2ILOp::CBranch {
            target: c(0x1010, 8),
            cond,
        });
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops,
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return { target: r(0x80, 8) }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1010,
                size: 4,
                ops: vec![R2ILOp::Return { target: r(0x80, 8) }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut func =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function should build");
        optimize_function(&mut func, &OptimizationConfig::default());
        func
    }

    fn condition_op(func: &SSAFunction) -> SSAOp {
        let block = func.named_block(0x1000).expect("head");
        let SSAOp::CBranch { cond, .. } = block.ops().last().expect("branch") else {
            panic!("no branch");
        };
        block
            .ops()
            .iter()
            .find(|op| op.dst() == Some(cond))
            .cloned()
            .expect("condition definition")
    }

    #[test]
    fn a_select_on_a_decided_condition_is_the_arm_it_decided() {
        // arm64's udiv guard: `x9 = 4; q = x8 / x9; x8 = (x9 == 0) ? 0 : q`.
        let blocks = vec![R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: r(0x10, 8),
                    src: c(4, 8),
                },
                R2ILOp::IntEqual {
                    dst: r(0x20, 1),
                    a: r(0x10, 8),
                    b: c(0, 8),
                },
                R2ILOp::IntDiv {
                    dst: r(0x30, 8),
                    a: r(0, 8),
                    b: r(0x10, 8),
                },
                R2ILOp::Select {
                    dst: r(0x40, 8),
                    cond: r(0x20, 1),
                    if_true: c(0, 8),
                    if_false: r(0x30, 8),
                },
                R2ILOp::Return { target: r(0x80, 8) },
            ],
            switch_info: None,
            op_metadata: Default::default(),
        }];
        let mut func =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function should build");
        // As the decompile pipeline runs it: no constant propagation.
        optimize_function(
            &mut func,
            &OptimizationConfig {
                enable_sccp: false,
                ..OptimizationConfig::default()
            },
        );
        let block = func.named_block(0x1000).expect("block");
        assert!(
            block.ops().iter().any(|op| matches!(op, SSAOp::Copy { dst, src } if dst.display_name().contains("40") && src.display_name().contains("30"))),
            "ops: {:?}",
            block.ops()
        );
    }

    #[test]
    fn sign_equals_overflow_through_copies_is_the_non_strict_ordering() {
        assert!(matches!(
            condition_op(&compare(false)),
            SSAOp::IntSLessEqual { a, b, .. } if a.constant_bits() == Some(1) && b.display_name().starts_with("reg")
        ));
    }

    /// A flag copied any number of times is still the flag: the fold reads
    /// the view's copy root, not a chain it gives up on after eight hops.
    #[test]
    fn a_flag_copied_many_times_folds_as_the_flag() {
        let x = r(0, 8);
        let mut ops = vec![
            R2ILOp::IntAnd {
                dst: x.clone(),
                a: r(8, 8),
                b: c(3, 8),
            },
            R2ILOp::IntSBorrow {
                dst: r(0x40, 1),
                a: x.clone(),
                b: c(1, 8),
            },
            R2ILOp::IntSub {
                dst: r(0x50, 8),
                a: x,
                b: c(1, 8),
            },
            R2ILOp::IntSLess {
                dst: r(0x41, 1),
                a: r(0x50, 8),
                b: c(0, 8),
            },
        ];
        // Twelve registers, each a copy of the one before.
        let mut sign = r(0x41, 1);
        for hop in 0..12 {
            let next = r(0x90 + hop, 1);
            ops.push(R2ILOp::Copy {
                dst: next.clone(),
                src: sign,
            });
            sign = next;
        }
        ops.push(R2ILOp::IntEqual {
            dst: r(0x70, 1),
            a: sign,
            b: r(0x40, 1),
        });
        ops.push(R2ILOp::CBranch {
            target: c(0x1010, 8),
            cond: r(0x70, 1),
        });
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops,
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return { target: r(0x80, 8) }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1010,
                size: 4,
                ops: vec![R2ILOp::Return { target: r(0x80, 8) }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut func =
            SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function should build");
        optimize_function(&mut func, &OptimizationConfig::default());
        let condition = condition_op(&func);
        assert!(
            matches!(
                &condition,
                SSAOp::IntSLessEqual { a, b, .. } if a.constant_bits() == Some(1) && b.display_name().starts_with("reg")
            ),
            "{condition:?}"
        );
    }

    #[test]
    fn not_zero_and_sign_equals_overflow_is_the_strict_ordering() {
        assert!(matches!(
            condition_op(&compare(true)),
            SSAOp::IntSLess { a, b, .. } if a.constant_bits() == Some(1) && b.display_name().starts_with("reg")
        ));
    }
}
