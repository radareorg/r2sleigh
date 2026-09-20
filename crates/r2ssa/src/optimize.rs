//! SSA optimization pipeline.
//!
//! This module applies a sequence of lightweight, SSA-safe optimizations
//! intended to simplify analysis and decompilation output.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::control::{SsaExecutionStopReason, SsaWorkControl, UncheckedSsaWorkControl};
use crate::{
    BlockTerminator, CanonicalStorageId, CanonicalStorageSpace, PhiNode, SSAFunction, SSAOp,
    SSAVar, SourceCarrierKind, SourceFunctionInterface, SourceFunctionReturn, SourceSite,
    SourceTypeKind,
};

/// Configuration for SSA optimization passes.
#[derive(Debug, Clone)]
pub struct OptimizationConfig {
    pub max_iterations: usize,
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
    pub max_iterations: usize,
    pub enable_inst_combine: bool,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            max_iterations: 4,
            enable_sccp: true,
            enable_inst_combine: true,
            preserve_memory_reads: false,
        }
    }
}

impl Default for DecompilePrepConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1,
            enable_inst_combine: true,
        }
    }
}

impl From<&DecompilePrepConfig> for OptimizationConfig {
    fn from(value: &DecompilePrepConfig) -> Self {
        Self {
            max_iterations: value.max_iterations.max(1),
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
pub fn optimize_function(func: &mut SSAFunction, config: &OptimizationConfig) -> OptimizationStats {
    optimize_function_with_control(func, config, &UncheckedSsaWorkControl)
        .expect("unchecked SSA optimization cannot stop")
}

pub(crate) fn optimize_function_with_control<C: SsaWorkControl + ?Sized>(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
    control: &C,
) -> Result<OptimizationStats, SsaExecutionStopReason> {
    optimize_function_with_interface_and_control(func, config, None, control)
}

pub(crate) fn optimize_function_with_interface_and_control<C: SsaWorkControl + ?Sized>(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
    function_interface: Option<&SourceFunctionInterface>,
    control: &C,
) -> Result<OptimizationStats, SsaExecutionStopReason> {
    control.poll()?;
    let mut stats = OptimizationStats::default();
    let max_iters = config.max_iterations.max(1);

    // Constants and folds feed each other: a fold through a definition can
    // turn a lane read into a constant copy, which is a constant the next
    // propagation round carries to its readers. Both run until neither moves.
    for _ in 0..max_iters {
        control.poll()?;
        let mut changed = false;

        if config.enable_sccp {
            let (consts, executable_edges) = sccp_with_control(func, control)?;
            control.poll()?;
            if apply_sccp_results(
                func,
                &consts,
                &executable_edges,
                function_interface,
                &mut stats,
            ) {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarKey {
    name: String,
    version: u32,
    size: u32,
    rename_disambiguator: u32,
}

type SccpResult = (HashMap<VarKey, u64>, HashSet<(u64, u64)>);

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

impl VarKey {
    fn from_var(var: &SSAVar) -> Self {
        Self {
            name: var.name().to_string(),
            version: var.version,
            size: var.size,
            rename_disambiguator: var.rename_disambiguator(),
        }
    }
}

impl Ord for VarKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.name.as_str(),
            self.version,
            self.size,
            self.rename_disambiguator,
        )
            .cmp(&(
                other.name.as_str(),
                other.version,
                other.size,
                other.rename_disambiguator,
            ))
    }
}

impl PartialOrd for VarKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn build_use_map(func: &SSAFunction) -> HashMap<VarKey, Vec<UseLocation>> {
    let mut uses = HashMap::new();
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
            uses.entry(VarKey::from_var(src.var))
                .or_insert_with(Vec::new)
                .push(use_loc);
        });
    }
    uses
}

fn get_lattice_value(var: &SSAVar, lattice: &HashMap<VarKey, LatticeValue>) -> LatticeValue {
    if let Some(val) = const_value(var) {
        return LatticeValue::Const(val);
    }
    lattice
        .get(&VarKey::from_var(var))
        .copied()
        .unwrap_or(LatticeValue::Top)
}

fn init_if_input(var: &SSAVar, lattice: &mut HashMap<VarKey, LatticeValue>) {
    if var.version == 0 && var.constant_bits().is_none() {
        lattice
            .entry(VarKey::from_var(var))
            .or_insert(LatticeValue::Bottom);
    }
}

fn update_lattice(
    lattice: &mut HashMap<VarKey, LatticeValue>,
    var: &SSAVar,
    new_val: LatticeValue,
) -> bool {
    let key = VarKey::from_var(var);
    let old_val = lattice.get(&key).copied().unwrap_or(LatticeValue::Top);
    let merged = old_val.meet(new_val);
    if merged != old_val {
        lattice.insert(key, merged);
        return true;
    }
    false
}

fn evaluate_op_sccp(op: &SSAOp, lattice: &HashMap<VarKey, LatticeValue>) -> LatticeValue {
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
    let mut temp_consts = HashMap::new();
    for src in op.sources() {
        match get_lattice_value(src, lattice) {
            LatticeValue::Bottom => has_bottom = true,
            LatticeValue::Top => has_top = true,
            LatticeValue::Const(c) => {
                temp_consts.insert(VarKey::from_var(src), c);
            }
        }
    }

    // An absorbing constant decides the result without the other operand,
    // so it is tried before an unknown operand is allowed to make the
    // result unknown; the evaluator answers only from the constants it has.
    if let Some(c) = eval_const_op(op, &temp_consts) {
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
    phi: &PhiNode,
    executable: &HashSet<(u64, u64)>,
    lattice: &HashMap<VarKey, LatticeValue>,
    block_addr: u64,
) -> LatticeValue {
    let mut value = LatticeValue::Top;
    for (pred_addr, src) in &phi.sources {
        if !executable.contains(&(*pred_addr, block_addr)) {
            continue;
        }
        value = value.meet(get_lattice_value(src, lattice));
    }
    value
}

fn find_cbranch_condition(
    func: &SSAFunction,
    block_addr: u64,
    lattice: &HashMap<VarKey, LatticeValue>,
) -> LatticeValue {
    let Some(block) = func.get_block(block_addr) else {
        return LatticeValue::Bottom;
    };
    for op in block.ops.iter().rev() {
        if let SSAOp::CBranch { cond, .. } = op {
            return get_lattice_value(cond, lattice);
        }
    }
    LatticeValue::Bottom
}

fn evaluate_terminator_sccp(
    func: &SSAFunction,
    block_addr: u64,
    lattice: &HashMap<VarKey, LatticeValue>,
    cfg_worklist: &mut VecDeque<(u64, u64)>,
) {
    let Some(cfg_block) = func.cfg().get_block(block_addr) else {
        return;
    };

    match &cfg_block.terminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => match find_cbranch_condition(func, block_addr, lattice) {
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
fn sccp(func: &SSAFunction) -> (HashMap<VarKey, u64>, HashSet<(u64, u64)>) {
    sccp_with_control(func, &UncheckedSsaWorkControl).expect("unchecked SCCP cannot stop")
}

fn sccp_with_control<C: SsaWorkControl + ?Sized>(
    func: &SSAFunction,
    control: &C,
) -> Result<SccpResult, SsaExecutionStopReason> {
    control.poll()?;
    let mut lattice = HashMap::new();
    let mut executable = HashSet::new();
    let mut block_visited = HashSet::new();
    let mut cfg_worklist = VecDeque::new();
    let mut ssa_worklist = VecDeque::new();
    let use_map = build_use_map(func);

    for block in func.blocks() {
        control.poll()?;
        block.for_each_def(|def| init_if_input(def.var, &mut lattice));
        block.for_each_source(|src| init_if_input(src.var, &mut lattice));
    }

    cfg_worklist.push_back((u64::MAX, func.entry));

    while !cfg_worklist.is_empty() || !ssa_worklist.is_empty() {
        control.poll()?;
        while let Some((from, to)) = cfg_worklist.pop_front() {
            control.poll()?;
            if !executable.insert((from, to)) {
                continue;
            }

            let Some(block) = func.get_block(to) else {
                continue;
            };

            for phi in &block.phis {
                control.poll()?;
                let new_val = evaluate_phi_sccp(phi, &executable, &lattice, to);
                if update_lattice(&mut lattice, &phi.dst, new_val) {
                    ssa_worklist.push_back(VarKey::from_var(&phi.dst));
                }
            }

            if block_visited.insert(to) {
                for op in &block.ops {
                    control.poll()?;
                    if let Some(dst) = op.dst() {
                        let new_val = evaluate_op_sccp(op, &lattice);
                        if update_lattice(&mut lattice, dst, new_val) {
                            ssa_worklist.push_back(VarKey::from_var(dst));
                        }
                    }
                }
                evaluate_terminator_sccp(func, to, &lattice, &mut cfg_worklist);
            }
        }

        while let Some(var_key) = ssa_worklist.pop_front() {
            control.poll()?;
            let Some(use_locs) = use_map.get(&var_key) else {
                continue;
            };
            for use_loc in use_locs {
                control.poll()?;
                match use_loc {
                    UseLocation::Phi {
                        block_addr,
                        phi_idx,
                    } => {
                        if !block_visited.contains(block_addr) {
                            continue;
                        }
                        let Some(block) = func.get_block(*block_addr) else {
                            continue;
                        };
                        let Some(phi) = block.phis.get(*phi_idx) else {
                            continue;
                        };
                        let new_val = evaluate_phi_sccp(phi, &executable, &lattice, *block_addr);
                        if update_lattice(&mut lattice, &phi.dst, new_val) {
                            ssa_worklist.push_back(VarKey::from_var(&phi.dst));
                        }
                    }
                    UseLocation::Op { block_addr, op_idx } => {
                        if !block_visited.contains(block_addr) {
                            continue;
                        }
                        let Some(block) = func.get_block(*block_addr) else {
                            continue;
                        };
                        let Some(op) = block.ops.get(*op_idx) else {
                            continue;
                        };

                        if let Some(dst) = op.dst() {
                            let new_val = evaluate_op_sccp(op, &lattice);
                            if update_lattice(&mut lattice, dst, new_val) {
                                ssa_worklist.push_back(VarKey::from_var(dst));
                            }
                        }

                        if matches!(op, SSAOp::CBranch { .. }) {
                            evaluate_terminator_sccp(
                                func,
                                *block_addr,
                                &lattice,
                                &mut cfg_worklist,
                            );
                        }
                    }
                }
            }
        }
    }

    let consts = lattice
        .iter()
        .filter_map(|(k, v)| match v {
            LatticeValue::Const(c) => Some((k.clone(), *c)),
            LatticeValue::Top | LatticeValue::Bottom => None,
        })
        .collect();
    control.poll()?;
    Ok((consts, executable))
}

fn const_value(var: &SSAVar) -> Option<u64> {
    var.constant_bits()
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

fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits == 0 {
        return 0;
    }
    if bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn const_for_var(var: &SSAVar, consts: &HashMap<VarKey, u64>) -> Option<u64> {
    if let Some(val) = const_value(var) {
        return Some(val);
    }
    consts.get(&VarKey::from_var(var)).copied()
}

fn eval_const_op(op: &SSAOp, consts: &HashMap<VarKey, u64>) -> Option<u64> {
    use SSAOp::*;

    let dst = op.dst()?;
    let bits = dst.size.saturating_mul(8);
    let mask = mask_for_bits(bits);

    let unary = |src: &SSAVar| const_for_var(src, consts);
    let binary =
        |a: &SSAVar, b: &SSAVar| Some((const_for_var(a, consts)?, const_for_var(b, consts)?));

    let val = match op {
        Copy { src, .. } => unary(src)?,
        IntNegate { src, .. } => (!unary(src)?).wrapping_add(1),
        IntNot { src, .. } => !unary(src)?,
        BoolNot { src, .. } => (unary(src)? == 0) as u64,
        IntZExt { src, .. } => unary(src)?,
        IntSExt { src, .. } => {
            let src_bits = src.size.saturating_mul(8);
            sign_extend(unary(src)?, src_bits) as u64
        }
        Trunc { src, .. } => unary(src)? & mask_for_bits(bits),
        IntAdd { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a.wrapping_add(b)
        }
        IntSub { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a.wrapping_sub(b)
        }
        IntMult { a, b, .. } => match (unary(a), unary(b)) {
            (Some(0), _) | (_, Some(0)) => 0,
            (Some(a), Some(b)) => a.wrapping_mul(b),
            _ => return None,
        },
        IntDiv { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b == 0 {
                return None;
            }
            a / b
        }
        IntSDiv { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b == 0 {
                return None;
            }
            let signed = sign_extend(a, bits) / sign_extend(b, bits);
            signed as u64
        }
        IntRem { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b == 0 {
                return None;
            }
            a % b
        }
        IntSRem { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b == 0 {
                return None;
            }
            let signed = sign_extend(a, bits) % sign_extend(b, bits);
            signed as u64
        }
        // Absorbing elements are constants whatever the other operand holds:
        // `and x, 0` is 0, `or x, -1` is all ones, `mul x, 0` is 0. Without
        // them a write like `or rax, -1` reads the entry carrier for nothing.
        IntAnd { a, b, .. } => match (unary(a), unary(b)) {
            (Some(0), _) | (_, Some(0)) => 0,
            (Some(a), Some(b)) => a & b,
            _ => return None,
        },
        IntOr { a, b, .. } => match (unary(a), unary(b)) {
            (Some(v), _) | (_, Some(v)) if v & mask == mask => mask,
            (Some(a), Some(b)) => a | b,
            _ => return None,
        },
        IntXor { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a ^ b
        }
        IntLeft { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b >= bits as u64 {
                return None;
            }
            a.wrapping_shl(b as u32)
        }
        IntRight { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b >= bits as u64 {
                return None;
            }
            a >> (b as u32)
        }
        IntSRight { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            if b >= bits as u64 {
                return None;
            }
            let signed = sign_extend(a, bits) >> (b as u32);
            signed as u64
        }
        IntEqual { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (a == b) as u64
        }
        IntNotEqual { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (a != b) as u64
        }
        IntLess { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (a < b) as u64
        }
        IntLessEqual { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (a <= b) as u64
        }
        IntSLess { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (sign_extend(a, bits) < sign_extend(b, bits)) as u64
        }
        IntSLessEqual { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            (sign_extend(a, bits) <= sign_extend(b, bits)) as u64
        }
        BoolAnd { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            ((a != 0) && (b != 0)) as u64
        }
        BoolOr { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            ((a != 0) || (b != 0)) as u64
        }
        BoolXor { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            ((a != 0) ^ (b != 0)) as u64
        }
        Piece { hi, lo, .. } => {
            let hi_val = const_for_var(hi, consts)?;
            let lo_val = const_for_var(lo, consts)?;
            let lo_bits = lo.size.saturating_mul(8);
            if lo_bits >= 64 {
                return None;
            }
            (hi_val << lo_bits) | (lo_val & mask_for_bits(lo_bits))
        }
        Subpiece { src, offset, .. } => {
            let val = unary(src)?;
            let shift = offset.saturating_mul(8);
            if shift >= 64 {
                return None;
            }
            val >> shift
        }
        PopCount { src, .. } => (unary(src)? & mask).count_ones() as u64,
        Lzcount { src, .. } => {
            let val = unary(src)? & mask;
            let width = bits.min(64);
            if width == 0 {
                0
            } else {
                let leading = val.leading_zeros();
                (leading.saturating_sub(64 - width)) as u64
            }
        }
        PtrAdd {
            base,
            index,
            element_size,
            ..
        } => {
            let (base, index) = binary(base, index)?;
            base.wrapping_add(index.wrapping_mul(*element_size as u64))
        }
        PtrSub {
            base,
            index,
            element_size,
            ..
        } => {
            let (base, index) = binary(base, index)?;
            base.wrapping_sub(index.wrapping_mul(*element_size as u64))
        }
        _ => return None,
    };

    Some(val & mask)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalStorageProjection {
    carrier: CanonicalStorageId,
    logical: CanonicalStorageId,
}

fn coherent_return_projection(
    function_interface: Option<&SourceFunctionInterface>,
) -> Option<TerminalStorageProjection> {
    let interface = function_interface?;
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
    let logical = match carrier.kind() {
        SourceCarrierKind::Full if carrier.size_bits() == storage_bits => storage,
        SourceCarrierKind::LowBits
            if carrier.size_bits() < storage_bits
                && matches!(
                    source_type.kind(),
                    SourceTypeKind::SignedInteger | SourceTypeKind::UnsignedInteger
                ) =>
        {
            CanonicalStorageId {
                space: storage.space,
                offset: storage.offset,
                size: u32::try_from(carrier.size_bits() / 8).ok()?,
            }
        }
        _ => return None,
    };
    Some(TerminalStorageProjection {
        carrier: storage,
        logical,
    })
}

fn replace_sources_with_constants(
    func: &mut SSAFunction,
    consts: &HashMap<VarKey, u64>,
    function_interface: Option<&SourceFunctionInterface>,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();
    let return_storage =
        coherent_return_projection(function_interface).map(|projection| projection.carrier);

    for addr in block_addrs {
        let is_return_block = func
            .cfg()
            .get_block(addr)
            .is_some_and(|cfg_block| cfg_block.is_return());
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };

        for phi in &mut block.phis {
            let preserve_phi_sources = is_return_block
                && return_storage.is_some_and(|storage| phi.canonical_storage == Some(storage));
            for (_, src) in &mut phi.sources {
                if preserve_phi_sources {
                    continue;
                }
                let key = VarKey::from_var(src);
                if let Some(val) = consts.get(&key).copied() {
                    let new_var = SSAVar::constant(val, src.size);
                    if &new_var != src {
                        *src = new_var;
                        stats.constants_propagated += 1;
                        changed = true;
                    }
                }
            }
        }

        for op in &mut block.ops {
            let new_op = map_sources_in_op(op, &|var| {
                let key = VarKey::from_var(var);
                if let Some(val) = consts.get(&key).copied() {
                    SSAVar::constant(val, var.size)
                } else {
                    var.clone()
                }
            });
            if &new_op != op {
                let delta = count_source_replacements(op, &new_op);
                if delta > 0 {
                    stats.constants_propagated += delta;
                }
                *op = new_op;
                changed = true;
            }
        }
    }

    changed
}

fn apply_sccp_results(
    func: &mut SSAFunction,
    consts: &HashMap<VarKey, u64>,
    executable_edges: &HashSet<(u64, u64)>,
    function_interface: Option<&SourceFunctionInterface>,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;
    let mut cfg_changed = false;

    if replace_sources_with_constants(func, consts, function_interface, stats) {
        changed = true;
    }
    stats.sccp_constants_found = consts.len();

    #[derive(Debug, Clone, Copy)]
    struct BranchRewrite {
        block_addr: u64,
        op_idx: usize,
        keep_target: u64,
        dead_target: u64,
        take_true: bool,
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

        for (op_idx, op) in block.ops.iter().enumerate() {
            if let SSAOp::CBranch { cond, .. } = op
                && let Some(value) = const_value(cond)
            {
                let take_true = value != 0;
                let (keep_target, dead_target) = if take_true {
                    (*true_target, *false_target)
                } else {
                    (*false_target, *true_target)
                };
                rewrites.push(BranchRewrite {
                    block_addr: addr,
                    op_idx,
                    keep_target,
                    dead_target,
                    take_true,
                });
                break;
            }
        }
    }

    for rw in rewrites {
        if let Some(block) = func.get_block_mut(rw.block_addr)
            && let Some(op) = block.ops.get_mut(rw.op_idx)
        {
            if rw.take_true {
                if let SSAOp::CBranch { target, .. } = op {
                    // The branch that remains was never a call site the source
                    // named, so it keeps no instruction identity.
                    *op = SSAOp::Branch {
                        target: target.clone(),
                        instruction: None,
                    };
                }
            } else {
                *op = SSAOp::Nop;
            }
        }

        func.cfg_mut().remove_edge(rw.block_addr, rw.dead_target);
        func.cfg_mut().set_terminator(
            rw.block_addr,
            BlockTerminator::Branch {
                target: rw.keep_target,
            },
        );
        func.remove_phi_source(rw.dead_target, rw.block_addr);
        stats.sccp_edges_pruned += 1;
        changed = true;
        cfg_changed = true;
    }

    let block_addrs = func.block_addrs().to_vec();
    for addr in block_addrs {
        let succs = func.successors(addr);
        for succ in succs {
            if !executable_edges.contains(&(addr, succ)) {
                func.cfg_mut().remove_edge(addr, succ);
                func.remove_phi_source(succ, addr);
                stats.sccp_edges_pruned += 1;
                changed = true;
                cfg_changed = true;
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(func.entry);
    while let Some(addr) = queue.pop_front() {
        if !reachable.insert(addr) {
            continue;
        }
        for succ in func.successors(addr) {
            queue.push_back(succ);
        }
    }

    let all_addrs = func.block_addrs().to_vec();
    for addr in all_addrs {
        if !reachable.contains(&addr) {
            let succs = func.successors(addr);
            for succ in succs {
                func.remove_phi_source(succ, addr);
            }
            func.remove_block(addr);
            stats.sccp_blocks_removed += 1;
            changed = true;
            cfg_changed = true;
        }
    }

    if cfg_changed {
        func.refresh_after_cfg_mutation();
    }

    changed
}

fn count_source_replacements(before: &SSAOp, after: &SSAOp) -> usize {
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

fn inst_combine(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();
    let mut defs = func
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter_map(|op| op.dst().map(|dst| (VarKey::from_var(dst), op.clone())))
        .collect::<HashMap<_, _>>();

    for addr in &block_addrs {
        let Some(block) = func.get_block_mut(*addr) else {
            continue;
        };
        for op in &mut block.ops {
            loop {
                let Some(new_op) = fold_through_definition(op, &defs).or_else(|| simplify_op(op))
                else {
                    break;
                };
                if &new_op == op {
                    break;
                }
                if let Some(dst) = new_op.dst() {
                    defs.insert(VarKey::from_var(dst), new_op.clone());
                }
                *op = new_op;
                stats.ops_simplified += 1;
                changed = true;
            }
        }
    }

    // A lane temporary that a fold made a copy of another value is that
    // value: it is the construction's own scaffolding, not a move the
    // program made, so its readers take the value and the copy goes dead.
    let mut lane_copies = HashMap::new();
    for (key, op) in &defs {
        if let SSAOp::Copy { dst, src } = op
            && crate::rename::is_lane_temp(dst)
        {
            lane_copies.insert(key.clone(), src.clone());
        }
    }
    if !lane_copies.is_empty() {
        let resolve = |var: &SSAVar| {
            let mut current = var.clone();
            let mut hops = 0;
            while let Some(next) = lane_copies.get(&VarKey::from_var(&current)) {
                current = next.clone();
                hops += 1;
                if hops > lane_copies.len() {
                    break;
                }
            }
            current
        };
        // A merge keeps its copy: its edge assignment is a statement of the
        // copied object, not an expression read.
        for addr in &block_addrs {
            let Some(block) = func.get_block_mut(*addr) else {
                continue;
            };
            for op in &mut block.ops {
                let new_op = map_sources_in_op(op, &resolve);
                if &new_op != op {
                    *op = new_op;
                    changed = true;
                }
            }
        }
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
    selector: SSAVar,
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
    let defs = func
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter_map(|op| op.dst().map(|dst| (VarKey::from_var(dst), op.clone())))
        .collect::<HashMap<_, _>>();
    let define = |var: &SSAVar| defs.get(&VarKey::from_var(var));
    // The value a copy chain carries: a promoted slot's reload is a copy of
    // the store, and the store a copy of the register.
    let root = |var: &SSAVar| {
        let mut var = var.clone();
        for _ in 0..16 {
            match define(&var) {
                Some(SSAOp::Copy { src, .. }) => var = src.clone(),
                _ => break,
            }
        }
        var
    };
    // `x == c`, or the zero flag of `x - c` where the difference also lands in
    // a register and so was left as the flag fold found it.
    let against_constant = |a: &SSAVar, b: &SSAVar| {
        let (selector, value) = match (const_value(a), const_value(b)) {
            (None, Some(value)) => (a, value),
            (Some(value), None) => (b, value),
            _ => return None,
        };
        if value == 0
            && let Some(SSAOp::IntSub { a: x, b: c, .. }) = define(&root(selector))
            && let Some(c) = const_value(&root(c))
        {
            return Some((root(x), c));
        }
        Some((root(selector), value))
    };
    let equality = |var: &SSAVar| {
        let mut op = define(var)?;
        let mut negated = false;
        for _ in 0..16 {
            match op {
                SSAOp::Copy { src, .. } => op = define(src)?,
                SSAOp::BoolNot { src, .. } => {
                    negated = !negated;
                    op = define(src)?;
                }
                SSAOp::IntEqual { a, b, .. } => {
                    let (selector, value) = against_constant(a, b)?;
                    return Some((selector, value, negated));
                }
                SSAOp::IntNotEqual { a, b, .. } => {
                    let (selector, value) = against_constant(a, b)?;
                    return Some((selector, value, !negated));
                }
                _ => return None,
            }
        }
        None
    };
    let test_of = |addr: u64| {
        let block = func.get_block(addr)?;
        let SSAOp::CBranch { cond, .. } = block.ops.last()? else {
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
        let (selector, value, negated) = equality(cond)?;
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
        if !block.phis.is_empty() || func.predecessors(addr).len() != 1 {
            return None;
        }
        let (last, body) = block.ops.split_last()?;
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
        pure.then_some(last)
    };

    struct Fusion {
        block: u64,
        selector: SSAVar,
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
                    if test.selector != head.selector
                        || cases.iter().any(|(value, _)| *value == test.value)
                    {
                        r2il::refusal_evidence!(
                            "fuse-compare-chain",
                            "{addr:#x}: {cur:#x} tests {} == {}, not {}",
                            test.selector.display_name(),
                            test.value,
                            head.selector.display_name()
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
                block.phis.iter().all(|phi| {
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
            fusion.selector.display_name(),
            fusion.links.len(),
            fusion.default
        );
        // The links' values stay defined: they are pure, the head dominates
        // every reader, and the merges at the targets still name them.
        let hoisted = fusion
            .links
            .iter()
            .filter_map(|link| func.get_block(*link))
            .flat_map(|block| {
                block.ops[..block.ops.len().saturating_sub(1)]
                    .iter()
                    .filter(|op| !matches!(op, SSAOp::Nop))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if let Some(block) = func.get_block_mut(fusion.block) {
            let terminator = block.ops.len() - 1;
            block.ops[terminator] = SSAOp::Switch {
                selector: fusion.selector.clone(),
            };
            block.ops.splice(terminator..terminator, hoisted);
        }
        let targets = fusion
            .cases
            .iter()
            .map(|(_, target)| *target)
            .chain(std::iter::once(fusion.default))
            .collect::<BTreeSet<_>>();
        for target in &targets {
            if let Some(block) = func.get_block_mut(*target) {
                for phi in &mut block.phis {
                    let carried = phi
                        .sources
                        .iter()
                        .find(|(pred, _)| *pred == fusion.block || fusion.links.contains(pred))
                        .map(|(_, var)| var.clone());
                    phi.sources
                        .retain(|(pred, _)| *pred != fusion.block && !fusion.links.contains(pred));
                    if let Some(var) = carried {
                        phi.sources.push((fusion.block, var));
                    }
                    // A merge lists its sources in predecessor order.
                    phi.sources.sort_by_key(|(pred, _)| *pred);
                }
            }
        }
        for link in &fusion.links {
            func.cfg_mut().remove_block(*link);
        }
        func.cfg_mut().set_terminator(
            fusion.block,
            BlockTerminator::Switch {
                cases: fusion.cases.clone(),
                default: Some(fusion.default),
            },
        );
        stats.chains_fused += 1;
    }
    func.refresh_after_cfg_mutation();
    true
}

fn fold_condition_codes_in_function(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let defs = func
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter_map(|op| op.dst().map(|dst| (VarKey::from_var(dst), op.clone())))
        .collect::<HashMap<_, _>>();
    // Values a statement other than a flag test reads. A difference read only
    // by the flags of its own instruction does go unread once they fold; one a
    // register receives does not.
    let kept = func
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter(|op| {
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
        })
        .flat_map(|op| op.sources())
        .map(VarKey::from_var)
        .collect::<HashSet<_>>();
    // Flags a disjunction reads: those are halves of one combined condition.
    // The machine copies a flag out of its scratch register before testing it,
    // so the disjunction names the copy and the fold has to look through it.
    let mut combined = func
        .blocks()
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter(|op| matches!(op, SSAOp::IntOr { .. } | SSAOp::BoolOr { .. }))
        .flat_map(|op| op.sources())
        .map(VarKey::from_var)
        .collect::<HashSet<_>>();
    loop {
        let grown = func
            .blocks()
            .iter()
            .flat_map(|block| block.ops.iter())
            .filter_map(|op| match op {
                SSAOp::Copy { dst, src } if combined.contains(&VarKey::from_var(dst)) => {
                    Some(VarKey::from_var(src))
                }
                _ => None,
            })
            .filter(|key| !combined.contains(key))
            .collect::<Vec<_>>();
        if grown.is_empty() {
            break;
        }
        combined.extend(grown);
    }
    let mut changed = false;
    for addr in func.block_addrs().to_vec() {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };
        for op in &mut block.ops {
            let Some(folded) = fold_condition_codes(op, &defs, &kept, &combined) else {
                continue;
            };
            if &folded == op {
                continue;
            }
            *op = folded;
            stats.ops_simplified += 1;
            changed = true;
        }
    }
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
fn fold_condition_codes(
    op: &SSAOp,
    defs: &HashMap<VarKey, SSAOp>,
    kept: &HashSet<VarKey>,
    combined: &HashSet<VarKey>,
) -> Option<SSAOp> {
    let define = |var: &SSAVar| defs.get(&VarKey::from_var(var));
    let is_zero = |var: &SSAVar| const_value(var) == Some(0);
    // `d = a - b`, whether the flag reads the difference by name or the
    // subtraction was folded into it.
    let subtraction = |var: &SSAVar| match define(var)? {
        SSAOp::IntSub { a, b, .. } => Some((a.clone(), b.clone())),
        _ => None,
    };
    // A flag read through the copies the machine makes of it: arm64 tests
    // `ZR`, which is a copy of the `tmpZR` the subtraction wrote.
    let define_through_copies = |var: &SSAVar| {
        let mut op = define(var)?;
        let mut hops = 0;
        while let SSAOp::Copy { src, .. } = op {
            hops += 1;
            if hops > 8 {
                return None;
            }
            op = define(src)?;
        }
        Some(op)
    };
    // The sign flag: `(a - b) <s 0`.
    let sign_flag = |var: &SSAVar| match define_through_copies(var)? {
        SSAOp::IntSLess { a: d, b: zero, .. } if is_zero(zero) => subtraction(d),
        _ => None,
    };
    // The overflow flag: `sborrow(a, b)`.
    let overflow_flag = |var: &SSAVar| match define_through_copies(var)? {
        SSAOp::IntSBorrow { a, b, .. } => Some((a.clone(), b.clone())),
        _ => None,
    };
    // The zero flag: `(a - b) == 0`, or already the equality this pass made
    // of it, since the two halves of a disjunction fold in one walk.
    let zero_flag = |var: &SSAVar| match define_through_copies(var)? {
        SSAOp::IntEqual { a: d, b: zero, .. } if is_zero(zero) => subtraction(d),
        SSAOp::IntEqual { a, b, .. } => Some((a.clone(), b.clone())),
        _ => None,
    };
    // The unsigned ordering: the carry of `a - b` is `b <= a`, and the machine
    // tests its negation for `a < b`.
    let unsigned_order = |var: &SSAVar| match define_through_copies(var)? {
        SSAOp::IntLess { a, b, .. } => Some((a.clone(), b.clone())),
        SSAOp::BoolNot { src, .. } => match define_through_copies(src)? {
            SSAOp::IntLessEqual { a: y, b: x, .. } => Some((x.clone(), y.clone())),
            _ => None,
        },
        _ => None,
    };
    // `SF != OF` is `a <s b`, and `SF == OF` is `b <=s a`. Either order.
    let signed_order = |x: &SSAVar, y: &SSAVar| {
        sign_flag(x)
            .zip(overflow_flag(y))
            .or_else(|| sign_flag(y).zip(overflow_flag(x)))
            .filter(|(sign, overflow)| sign == overflow)
            .map(|(sign, _)| sign)
    };
    match op {
        // `jl` / `jge`: the sign and overflow flags alone.
        SSAOp::IntNotEqual { dst, a, b } => {
            if let Some((left, right)) = signed_order(a, b) {
                return Some(SSAOp::IntSLess {
                    dst: dst.clone(),
                    a: left,
                    b: right,
                });
            }
            if kept.contains(&VarKey::from_var(a)) && !combined.contains(&VarKey::from_var(dst)) {
                return None;
            }
            let (left, right) = is_zero(b).then(|| subtraction(a)).flatten()?;
            Some(SSAOp::IntNotEqual {
                dst: dst.clone(),
                a: left,
                b: right,
            })
        }
        SSAOp::IntEqual { dst, a, b } => {
            if let Some((left, right)) = signed_order(a, b) {
                return Some(SSAOp::IntSLessEqual {
                    dst: dst.clone(),
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
            if kept.contains(&VarKey::from_var(a)) && !combined.contains(&VarKey::from_var(dst)) {
                return None;
            }
            let (left, right) = is_zero(b).then(|| subtraction(a)).flatten()?;
            Some(SSAOp::IntEqual {
                dst: dst.clone(),
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
            let ordered = |ordering: &SSAVar, zero: &SSAVar| {
                let (left, right, signed) = match define(ordering)? {
                    SSAOp::IntNotEqual { a: x, b: y, .. } => {
                        let (l, r) = signed_order(x, y)?;
                        (l, r, true)
                    }
                    SSAOp::IntSLess { a: x, b: y, .. } => (x.clone(), y.clone(), true),
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
                    dst: dst.clone(),
                    a: left,
                    b: right,
                }
            } else {
                SSAOp::IntLessEqual {
                    dst: dst.clone(),
                    a: left,
                    b: right,
                }
            })
        }
        // `jg` / `ja`: the non-strict ordering with the zero flag denied beside
        // it, which is the strict ordering.
        SSAOp::BoolAnd { dst, a, b } | SSAOp::IntAnd { dst, a, b } => {
            let denied_zero = |var: &SSAVar| match define_through_copies(var)? {
                SSAOp::BoolNot { src, .. } => zero_flag(src),
                _ => None,
            };
            // The ordering half: the signed pair, or the comparison this pass
            // already made of either pair.
            let ordered = |var: &SSAVar| match define_through_copies(var)? {
                SSAOp::IntEqual { a: x, b: y, .. } => {
                    let (l, r) = signed_order(x, y)?;
                    Some((r, l, true))
                }
                SSAOp::IntSLessEqual { a: x, b: y, .. } => Some((x.clone(), y.clone(), true)),
                SSAOp::IntLessEqual { a: x, b: y, .. } => Some((x.clone(), y.clone(), false)),
                _ => None,
            };
            let strict = |ordering: &SSAVar, zero: &SSAVar| {
                let (left, right, signed) = ordered(ordering)?;
                let (zero_left, zero_right) = denied_zero(zero)?;
                let same = (zero_left == left && zero_right == right)
                    || (zero_left == right && zero_right == left);
                same.then_some((left, right, signed))
            };
            let (left, right, signed) = strict(a, b).or_else(|| strict(b, a))?;
            Some(if signed {
                SSAOp::IntSLess {
                    dst: dst.clone(),
                    a: left,
                    b: right,
                }
            } else {
                SSAOp::IntLess {
                    dst: dst.clone(),
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
    var: &SSAVar,
    defs: &HashMap<VarKey, SSAOp>,
    depth: u32,
) -> Option<u64> {
    if let Some(value) = const_value(var) {
        return Some(value);
    }
    if depth > 8 {
        return None;
    }
    let op = defs.get(&VarKey::from_var(var))?;
    let mut consts = HashMap::new();
    for source in op.sources() {
        consts.insert(
            VarKey::from_var(source),
            constant_through_definitions(source, defs, depth + 1)?,
        );
    }
    eval_const_op(op, &consts)
}

fn fold_through_definition(op: &SSAOp, defs: &HashMap<VarKey, SSAOp>) -> Option<SSAOp> {
    // A selection on a condition its definitions decide is the arm decided.
    if let SSAOp::Select(select) = op {
        let chosen = match constant_through_definitions(&select.cond, defs, 0)? {
            0 => &select.if_false,
            _ => &select.if_true,
        };
        return Some(SSAOp::Copy {
            dst: select.dst.clone(),
            src: chosen.clone(),
        });
    }
    let SSAOp::Subpiece { dst, src, offset } = op else {
        return None;
    };
    let producer = defs.get(&VarKey::from_var(src))?;
    let lane_start = u64::from(*offset) * 8;
    let lane_bits = u64::from(dst.size) * 8;
    let lane_end = lane_start + lane_bits;
    let subpiece = |src: &SSAVar, offset: u64| {
        let offset = u32::try_from(offset).ok()?;
        Some(if u64::from(src.size) * 8 == lane_bits && offset == 0 {
            SSAOp::Copy {
                dst: dst.clone(),
                src: src.clone(),
            }
        } else {
            SSAOp::Subpiece {
                dst: dst.clone(),
                src: src.clone(),
                offset,
            }
        })
    };
    match producer {
        SSAOp::Copy { src: value, .. } if value.constant_bits().is_some() => {
            subpiece(value, u64::from(*offset))
        }
        SSAOp::Insert(insert) => {
            let (root, value) = (&insert.src, &insert.value);
            let position = insert.position.constant_bits()?;
            let inserted_end = position.checked_add(u64::from(value.size) * 8)?;
            if position <= lane_start && lane_end <= inserted_end {
                subpiece(value, (lane_start - position) / 8)
            } else if lane_end <= position || inserted_end <= lane_start {
                subpiece(root, u64::from(*offset))
            } else {
                None
            }
        }
        SSAOp::IntZExt { src: narrow, .. } | SSAOp::IntSExt { src: narrow, .. }
            if lane_end <= u64::from(narrow.size) * 8 =>
        {
            subpiece(narrow, u64::from(*offset))
        }
        SSAOp::Subpiece {
            src: wider,
            offset: inner,
            ..
        } => subpiece(wider, u64::from(*offset) + u64::from(*inner)),
        _ => None,
    }
}

fn simplify_op(op: &SSAOp) -> Option<SSAOp> {
    use SSAOp::*;

    let dst = op.dst()?.clone();
    let bits = dst.size.saturating_mul(8);
    let mask = mask_for_bits(bits);

    let const_of = |var: &SSAVar| const_value(var);

    let make_const = |val: u64| SSAOp::Copy {
        dst: dst.clone(),
        src: SSAVar::constant(val & mask, dst.size),
    };

    let make_copy = |src: &SSAVar| SSAOp::Copy {
        dst: dst.clone(),
        src: src.clone(),
    };

    let simplified = match op {
        Copy { .. } => return None,
        // A selection on a decided condition is the arm it decided.
        Select(select) => match const_of(&select.cond) {
            Some(0) => make_copy(&select.if_false),
            Some(_) => make_copy(&select.if_true),
            None => return None,
        },
        IntAdd { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => make_copy(b),
            (_, Some(0)) => make_copy(a),
            (Some(av), Some(bv)) => make_const(av.wrapping_add(bv)),
            _ => return None,
        },
        IntSub { a, b, .. } => match (const_of(a), const_of(b)) {
            (_, Some(0)) => make_copy(a),
            _ if a == b => make_const(0),
            (Some(av), Some(bv)) => make_const(av.wrapping_sub(bv)),
            _ => return None,
        },
        IntMult { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) | (_, Some(0)) => make_const(0),
            (Some(1), _) => make_copy(b),
            (_, Some(1)) => make_copy(a),
            (Some(av), Some(bv)) => make_const(av.wrapping_mul(bv)),
            _ => return None,
        },
        IntDiv { a, b, .. } => match (const_of(a), const_of(b)) {
            (_, Some(1)) => make_copy(a),
            (Some(_), Some(0)) => return None,
            (Some(av), Some(bv)) => make_const(av / bv),
            _ => return None,
        },
        IntSDiv { a, b, .. } => match (const_of(a), const_of(b)) {
            (_, Some(1)) => make_copy(a),
            (Some(_), Some(0)) => return None,
            (Some(av), Some(bv)) => {
                let res = sign_extend(av, bits) / sign_extend(bv, bits);
                make_const(res as u64)
            }
            _ => return None,
        },
        IntRem { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(_), Some(0)) => return None,
            (Some(av), Some(bv)) => make_const(av % bv),
            _ => return None,
        },
        IntSRem { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(_), Some(0)) => return None,
            (Some(av), Some(bv)) => {
                let res = sign_extend(av, bits) % sign_extend(bv, bits);
                make_const(res as u64)
            }
            _ => return None,
        },
        IntNegate { src, .. } => match const_of(src) {
            Some(val) => make_const((!val).wrapping_add(1)),
            _ => return None,
        },
        IntAnd { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) | (_, Some(0)) => make_const(0),
            (Some(av), Some(bv)) => make_const(av & bv),
            (Some(av), _) if av == mask => make_copy(b),
            (_, Some(bv)) if bv == mask => make_copy(a),
            _ => return None,
        },
        IntOr { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => make_copy(b),
            (_, Some(0)) => make_copy(a),
            // All ones absorbs: `or rax, -1` is the constant whatever `rax` held.
            (Some(av), _) if av == mask => make_const(mask),
            (_, Some(bv)) if bv == mask => make_const(mask),
            (Some(av), Some(bv)) => make_const(av | bv),
            _ => return None,
        },
        IntXor { a, b, .. } => match (const_of(a), const_of(b)) {
            (Some(0), _) => make_copy(b),
            (_, Some(0)) => make_copy(a),
            (Some(av), Some(bv)) => make_const(av ^ bv),
            _ if a == b => make_const(0),
            _ => return None,
        },
        IntNot { src, .. } => match const_of(src) {
            Some(val) => make_const(!val),
            _ => return None,
        },
        IntLeft { a, b, .. } | IntRight { a, b, .. } | IntSRight { a, b, .. } => {
            match (const_of(a), const_of(b)) {
                (Some(av), Some(bv)) => {
                    if bv >= bits as u64 {
                        return None;
                    }
                    let res = match op {
                        IntLeft { .. } => av.wrapping_shl(bv as u32),
                        IntRight { .. } => av >> (bv as u32),
                        IntSRight { .. } => (sign_extend(av, bits) >> (bv as u32)) as u64,
                        _ => av,
                    };
                    make_const(res)
                }
                (_, Some(0)) => make_copy(a),
                _ => return None,
            }
        }
        IntEqual { a, b, .. }
        | IntNotEqual { a, b, .. }
        | IntLess { a, b, .. }
        | IntLessEqual { a, b, .. }
        | IntSLess { a, b, .. }
        | IntSLessEqual { a, b, .. } => {
            if a == b {
                let val = matches!(
                    op,
                    IntEqual { .. } | IntLessEqual { .. } | IntSLessEqual { .. }
                ) as u64;
                return Some(make_const(val));
            }
            match (const_of(a), const_of(b)) {
                (Some(av), Some(bv)) => {
                    let result = match op {
                        IntEqual { .. } => av == bv,
                        IntNotEqual { .. } => av != bv,
                        IntLess { .. } => av < bv,
                        IntLessEqual { .. } => av <= bv,
                        IntSLess { .. } => sign_extend(av, bits) < sign_extend(bv, bits),
                        IntSLessEqual { .. } => sign_extend(av, bits) <= sign_extend(bv, bits),
                        _ => false,
                    };
                    make_const(result as u64)
                }
                _ => return None,
            }
        }
        BoolNot { src, .. } => match const_of(src) {
            Some(val) => make_const((val == 0) as u64),
            _ => return None,
        },
        BoolAnd { a, b, .. } | BoolOr { a, b, .. } | BoolXor { a, b, .. } => {
            match (const_of(a), const_of(b)) {
                (Some(av), Some(bv)) => {
                    let a = av != 0;
                    let b = bv != 0;
                    let res = match op {
                        BoolAnd { .. } => a && b,
                        BoolOr { .. } => a || b,
                        BoolXor { .. } => a ^ b,
                        _ => false,
                    };
                    make_const(res as u64)
                }
                (Some(0), _) if matches!(op, BoolAnd { .. }) => make_const(0),
                (_, Some(0)) if matches!(op, BoolAnd { .. }) => make_const(0),
                (Some(1), _) if matches!(op, BoolOr { .. }) => make_const(1),
                (_, Some(1)) if matches!(op, BoolOr { .. }) => make_const(1),
                _ => return None,
            }
        }
        IntZExt { src, .. } => match const_of(src) {
            Some(val) => make_const(val),
            _ if src.size == dst.size => make_copy(src),
            _ => return None,
        },
        IntSExt { src, .. } => match const_of(src) {
            Some(val) => {
                let src_bits = src.size.saturating_mul(8);
                make_const(sign_extend(val, src_bits) as u64)
            }
            _ if src.size == dst.size => make_copy(src),
            _ => return None,
        },
        Trunc { src, .. } => match const_of(src) {
            Some(val) => make_const(val & mask_for_bits(bits)),
            _ => return None,
        },
        Piece { hi, lo, .. } => match (const_of(hi), const_of(lo)) {
            (Some(h), Some(l)) => {
                let lo_bits = lo.size.saturating_mul(8);
                if lo_bits >= 64 {
                    return None;
                }
                make_const((h << lo_bits) | (l & mask_for_bits(lo_bits)))
            }
            _ => return None,
        },
        Subpiece { src, offset, .. } => match const_of(src) {
            Some(val) => {
                let shift = offset.saturating_mul(8);
                if shift >= 64 {
                    return None;
                }
                make_const(val >> shift)
            }
            _ => return None,
        },
        PtrAdd {
            base,
            index,
            element_size,
            ..
        } => match (const_of(base), const_of(index)) {
            (Some(b), Some(i)) => make_const(b.wrapping_add(i.wrapping_mul(*element_size as u64))),
            _ => return None,
        },
        PtrSub {
            base,
            index,
            element_size,
            ..
        } => match (const_of(base), const_of(index)) {
            (Some(b), Some(i)) => make_const(b.wrapping_sub(i.wrapping_mul(*element_size as u64))),
            _ => return None,
        },
        _ => return None,
    };

    Some(simplified)
}

pub(crate) fn map_sources_in_op<F>(op: &SSAOp, map: &F) -> SSAOp
where
    F: Fn(&SSAVar) -> SSAVar,
{
    use SSAOp::*;

    match op {
        Phi { dst, sources } => Phi {
            dst: dst.clone(),
            sources: sources.iter().map(map).collect(),
        },
        Copy { dst, src } => Copy {
            dst: dst.clone(),
            src: map(src),
        },
        Load { dst, space, addr } => Load {
            dst: dst.clone(),
            space: *space,
            addr: map(addr),
        },
        Store { space, addr, val } => Store {
            space: *space,
            addr: map(addr),
            val: map(val),
        },
        BlockTransfer(transfer) => BlockTransfer(Box::new(crate::op::BlockTransferOp {
            space: transfer.space,
            kind: transfer.kind,
            destination: map(&transfer.destination),
            source: map(&transfer.source),
            count: map(&transfer.count),
            direction: map(&transfer.direction),
            element_size: transfer.element_size,
        })),
        Fence { ordering } => Fence {
            ordering: *ordering,
        },
        LoadLinked {
            dst,
            space,
            addr,
            ordering,
        } => LoadLinked {
            dst: dst.clone(),
            space: *space,
            addr: map(addr),
            ordering: *ordering,
        },
        StoreConditional {
            result,
            space,
            addr,
            val,
            ordering,
        } => StoreConditional {
            result: result.clone(),
            space: *space,
            addr: map(addr),
            val: map(val),
            ordering: *ordering,
        },
        AtomicCAS(swap) => AtomicCAS(Box::new(crate::op::AtomicCasOp {
            dst: swap.dst.clone(),
            space: swap.space,
            addr: map(&swap.addr),
            expected: map(&swap.expected),
            replacement: map(&swap.replacement),
            ordering: swap.ordering,
        })),
        LoadGuarded {
            dst,
            space,
            addr,
            guard,
            ordering,
        } => LoadGuarded {
            dst: dst.clone(),
            space: *space,
            addr: map(addr),
            guard: map(guard),
            ordering: *ordering,
        },
        StoreGuarded {
            space,
            addr,
            val,
            guard,
            ordering,
        } => StoreGuarded {
            space: *space,
            addr: map(addr),
            val: map(val),
            guard: map(guard),
            ordering: *ordering,
        },
        IntAdd { dst, a, b } => IntAdd {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSub { dst, a, b } => IntSub {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntMult { dst, a, b } => IntMult {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntDiv { dst, a, b } => IntDiv {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSDiv { dst, a, b } => IntSDiv {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntRem { dst, a, b } => IntRem {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSRem { dst, a, b } => IntSRem {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntNegate { dst, src } => IntNegate {
            dst: dst.clone(),
            src: map(src),
        },
        IntCarry { dst, a, b } => IntCarry {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSCarry { dst, a, b } => IntSCarry {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSBorrow { dst, a, b } => IntSBorrow {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntAnd { dst, a, b } => IntAnd {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntOr { dst, a, b } => IntOr {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntXor { dst, a, b } => IntXor {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntNot { dst, src } => IntNot {
            dst: dst.clone(),
            src: map(src),
        },
        IntLeft { dst, a, b } => IntLeft {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntRight { dst, a, b } => IntRight {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSRight { dst, a, b } => IntSRight {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntEqual { dst, a, b } => IntEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntNotEqual { dst, a, b } => IntNotEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntLess { dst, a, b } => IntLess {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSLess { dst, a, b } => IntSLess {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntLessEqual { dst, a, b } => IntLessEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntSLessEqual { dst, a, b } => IntSLessEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        IntZExt { dst, src } => IntZExt {
            dst: dst.clone(),
            src: map(src),
        },
        IntSExt { dst, src } => IntSExt {
            dst: dst.clone(),
            src: map(src),
        },
        BoolNot { dst, src } => BoolNot {
            dst: dst.clone(),
            src: map(src),
        },
        BoolAnd { dst, a, b } => BoolAnd {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        BoolOr { dst, a, b } => BoolOr {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        BoolXor { dst, a, b } => BoolXor {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        Piece { dst, hi, lo } => Piece {
            dst: dst.clone(),
            hi: map(hi),
            lo: map(lo),
        },
        Subpiece { dst, src, offset } => Subpiece {
            dst: dst.clone(),
            src: map(src),
            offset: *offset,
        },
        PopCount { dst, src } => PopCount {
            dst: dst.clone(),
            src: map(src),
        },
        Lzcount { dst, src } => Lzcount {
            dst: dst.clone(),
            src: map(src),
        },
        Branch {
            target,
            instruction,
        } => Branch {
            target: map(target),
            instruction: *instruction,
        },
        CBranch { target, cond } => CBranch {
            target: map(target),
            cond: map(cond),
        },
        BranchInd {
            target,
            instruction,
        } => BranchInd {
            target: map(target),
            instruction: *instruction,
        },
        Switch { selector } => Switch {
            selector: map(selector),
        },
        Call {
            target,
            instruction,
        } => Call {
            target: map(target),
            instruction: *instruction,
        },
        CallInd {
            target,
            instruction,
        } => CallInd {
            target: map(target),
            instruction: *instruction,
        },
        CallDefine { dst } => CallDefine { dst: dst.clone() },
        CallUse { src } => CallUse { src: map(src) },
        CallRestore { dst, src } => CallRestore {
            dst: dst.clone(),
            src: map(src),
        },
        Return { target } => Return {
            target: map(target),
        },
        FloatAdd { dst, a, b } => FloatAdd {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatSub { dst, a, b } => FloatSub {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatMult { dst, a, b } => FloatMult {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatDiv { dst, a, b } => FloatDiv {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatNeg { dst, src } => FloatNeg {
            dst: dst.clone(),
            src: map(src),
        },
        FloatAbs { dst, src } => FloatAbs {
            dst: dst.clone(),
            src: map(src),
        },
        FloatSqrt { dst, src } => FloatSqrt {
            dst: dst.clone(),
            src: map(src),
        },
        FloatCeil { dst, src } => FloatCeil {
            dst: dst.clone(),
            src: map(src),
        },
        FloatFloor { dst, src } => FloatFloor {
            dst: dst.clone(),
            src: map(src),
        },
        FloatRound { dst, src } => FloatRound {
            dst: dst.clone(),
            src: map(src),
        },
        FloatNaN { dst, src } => FloatNaN {
            dst: dst.clone(),
            src: map(src),
        },
        FloatEqual { dst, a, b } => FloatEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatNotEqual { dst, a, b } => FloatNotEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatLess { dst, a, b } => FloatLess {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        FloatLessEqual { dst, a, b } => FloatLessEqual {
            dst: dst.clone(),
            a: map(a),
            b: map(b),
        },
        Int2Float { dst, src } => Int2Float {
            dst: dst.clone(),
            src: map(src),
        },
        Float2Int { dst, src } => Float2Int {
            dst: dst.clone(),
            src: map(src),
        },
        FloatFloat { dst, src } => FloatFloat {
            dst: dst.clone(),
            src: map(src),
        },
        Trunc { dst, src } => Trunc {
            dst: dst.clone(),
            src: map(src),
        },
        CallOther {
            output,
            userop,
            inputs,
        } => CallOther {
            output: output.clone(),
            userop: *userop,
            inputs: inputs.iter().map(map).collect(),
        },
        CpuId { dst } => CpuId { dst: dst.clone() },
        PtrAdd {
            dst,
            base,
            index,
            element_size,
        } => PtrAdd {
            dst: dst.clone(),
            base: map(base),
            index: map(index),
            element_size: *element_size,
        },
        PtrSub {
            dst,
            base,
            index,
            element_size,
        } => PtrSub {
            dst: dst.clone(),
            base: map(base),
            index: map(index),
            element_size: *element_size,
        },
        SegmentOp {
            dst,
            segment,
            offset,
        } => SegmentOp {
            dst: dst.clone(),
            segment: map(segment),
            offset: map(offset),
        },
        New { dst, src } => New {
            dst: dst.clone(),
            src: map(src),
        },
        Cast { dst, src } => Cast {
            dst: dst.clone(),
            src: map(src),
        },
        Extract { dst, src, position } => Extract {
            dst: dst.clone(),
            src: map(src),
            position: map(position),
        },
        Insert(insert) => Insert(Box::new(crate::op::InsertOp {
            dst: insert.dst.clone(),
            src: map(&insert.src),
            value: map(&insert.value),
            position: map(&insert.position),
        })),
        Select(select) => Select(Box::new(crate::op::SelectOp {
            dst: select.dst.clone(),
            cond: map(&select.cond),
            if_true: map(&select.if_true),
            if_false: map(&select.if_false),
        })),
        Nop => Nop,
        Unimplemented => Unimplemented,
        Breakpoint => Breakpoint,
    }
}

#[cfg(test)]
mod sccp_tests {
    use super::*;
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn make_const(val: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: val,
            size,
            meta: None,
        }
    }

    fn make_reg(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    fn make_ram(addr: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Ram,
            offset: addr,
            size,
            meta: None,
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
        let spoofed = SSAVar::new("const:2a", 0, 8);
        assert_eq!(const_value(&spoofed), None);
        let mut lattice = HashMap::new();
        init_if_input(&spoofed, &mut lattice);
        assert_eq!(
            lattice.get(&VarKey::from_var(&spoofed)),
            Some(&LatticeValue::Bottom)
        );

        let renamed = SSAVar::constant(0x2a, 8).renamed("renamed-value");
        assert_eq!(const_value(&renamed), Some(0x2a));
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
            consts.values().any(|v| *v == u64::MAX),
            "SCCP should fold `x | -1` to all ones: {consts:?}"
        );
        assert_eq!(
            consts.values().filter(|v| **v == 0).count(),
            2,
            "SCCP should fold `x & 0` and `0 * x` to zero: {consts:?}"
        );
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
            consts.values().any(|v| *v == 8),
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
            consts.values().any(|v| *v == 2 || *v == 3),
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
            !consts.keys().any(|k| k.name == "reg:8"),
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
            !consts.keys().any(|k| k.name == "reg:8"),
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
            func.get_block(0x1004).is_none(),
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
        let defined_by = |op: SSAOp| {
            let mut defs = HashMap::new();
            defs.insert(VarKey::from_var(&root), op);
            defs
        };

        // A constant copied into the root: the lane is that constant's bytes.
        let constant = defined_by(SSAOp::Copy {
            dst: root.clone(),
            src: SSAVar::constant(0x1122_3344_5566_7788, 8),
        });
        assert_eq!(
            fold_through_definition(&read(4, 4), &constant),
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
            fold_through_definition(&read(4, 4), &inserted),
            Some(SSAOp::Copy {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: lane.clone(),
            })
        );
        assert_eq!(
            fold_through_definition(&read(5, 1), &inserted),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 1),
                src: lane.clone(),
                offset: 1,
            })
        );
        assert_eq!(
            fold_through_definition(&read(0, 4), &inserted),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: older.clone(),
                offset: 0,
            })
        );
        assert_eq!(fold_through_definition(&read(2, 4), &inserted), None);

        // A widened value: a read within the narrow width is the narrow value.
        let widened = defined_by(SSAOp::IntZExt {
            dst: root.clone(),
            src: lane.clone(),
        });
        assert_eq!(
            fold_through_definition(&read(0, 4), &widened),
            Some(SSAOp::Copy {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 4),
                src: lane.clone(),
            })
        );
        assert_eq!(
            fold_through_definition(&read(0, 1), &widened),
            Some(SSAOp::Subpiece {
                dst: SSAVar::new("tmp:lane:1000:3:0", 1, 1),
                src: lane,
                offset: 0,
            })
        );
        assert_eq!(fold_through_definition(&read(0, 8), &widened), None);

        // A slice of a slice is one slice.
        let sliced = defined_by(SSAOp::Subpiece {
            dst: root.clone(),
            src: SSAVar::new("XMM0", 1, 16),
            offset: 8,
        });
        assert_eq!(
            fold_through_definition(&read(2, 1), &sliced),
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
        assert_eq!(fold_through_definition(&read(0, 4), &copied), None);
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
            meta: None,
        }
    }

    fn r(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
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
            func.get_block(0x1000).expect("head").ops.last(),
            Some(SSAOp::Switch { .. })
        ));
        assert!(func.get_block(0x1004).is_none());
        assert!(func.get_block(0x1008).is_none());
        let mut successors = func.successors(0x1000);
        successors.sort_unstable();
        successors.dedup();
        assert_eq!(successors, vec![0x100c, 0x1020, 0x1030, 0x1040]);
        let merge = func.get_block(0x1020).expect("case 2");
        assert!(
            merge.phis.iter().all(|phi| phi
                .sources
                .iter()
                .all(|(pred, _)| *pred == 0x1000 || *pred == 0x100c)),
            "phi sources: {:?}",
            merge.phis
        );
    }

    #[test]
    fn a_chain_whose_cases_rejoin_stays_an_else_if_ladder() {
        let func = chain(0x1040, 0x1040);
        assert!(matches!(
            func.cfg().get_block(0x1000).expect("head").terminator,
            BlockTerminator::ConditionalBranch { .. }
        ));
        assert!(func.get_block(0x1004).is_some());
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
            meta: None,
        }
    }

    fn r(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
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
        let block = func.get_block(0x1000).expect("head");
        let SSAOp::CBranch { cond, .. } = block.ops.last().expect("branch") else {
            panic!("no branch");
        };
        block
            .ops
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
        let block = func.get_block(0x1000).expect("block");
        assert!(
            block.ops.iter().any(|op| matches!(op, SSAOp::Copy { dst, src } if dst.display_name().contains("40") && src.display_name().contains("30"))),
            "ops: {:?}",
            block.ops
        );
    }

    #[test]
    fn sign_equals_overflow_through_copies_is_the_non_strict_ordering() {
        assert!(matches!(
            condition_op(&compare(false)),
            SSAOp::IntSLessEqual { a, b, .. } if const_value(&a) == Some(1) && b.display_name().starts_with("reg")
        ));
    }

    #[test]
    fn not_zero_and_sign_equals_overflow_is_the_strict_ordering() {
        assert!(matches!(
            condition_op(&compare(true)),
            SSAOp::IntSLess { a, b, .. } if const_value(&a) == Some(1) && b.display_name().starts_with("reg")
        ));
    }
}
