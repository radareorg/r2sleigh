//! SSA optimization pipeline.
//!
//! This module applies a sequence of lightweight, SSA-safe optimizations
//! intended to simplify analysis and decompilation output.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use crate::{SSAFunction, SSAOp, SSAVar};

/// Configuration for SSA optimization passes.
#[derive(Debug, Clone)]
pub struct OptimizationConfig {
    pub max_iterations: usize,
    pub enable_const_prop: bool,
    pub enable_inst_combine: bool,
    pub enable_copy_prop: bool,
    pub enable_cse: bool,
    pub enable_dce: bool,
    pub preserve_memory_reads: bool,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            max_iterations: 4,
            enable_const_prop: true,
            enable_inst_combine: true,
            enable_copy_prop: true,
            enable_cse: true,
            enable_dce: true,
            preserve_memory_reads: false,
        }
    }
}

/// Optimization statistics for a single run.
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    pub iterations: usize,
    pub constants_propagated: usize,
    pub ops_simplified: usize,
    pub copies_propagated: usize,
    pub phis_simplified: usize,
    pub cse_replacements: usize,
    pub dce_removed_ops: usize,
    pub dce_removed_phis: usize,
}

/// Run the SSA optimization pipeline on a function.
pub fn optimize_function(func: &mut SSAFunction, config: &OptimizationConfig) -> OptimizationStats {
    let mut stats = OptimizationStats::default();
    let max_iters = config.max_iterations.max(1);

    for _ in 0..max_iters {
        let mut changed = false;

        if config.enable_const_prop {
            let consts = compute_constants(func, max_iters);
            if replace_sources_with_constants(func, &consts, &mut stats) {
                changed = true;
            }
        }

        if config.enable_inst_combine {
            if inst_combine(func, &mut stats) {
                changed = true;
            }
        }

        if config.enable_cse {
            if common_subexpr_elim(func, &mut stats) {
                changed = true;
            }
        }

        if config.enable_copy_prop {
            if copy_propagation(func, &mut stats) {
                changed = true;
            }
        }

        if config.enable_dce {
            if dead_code_elim(func, config, &mut stats) {
                changed = true;
            }
        }

        stats.iterations += 1;
        if !changed {
            break;
        }
    }

    stats
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarKey {
    name: String,
    version: u32,
    size: u32,
}

impl VarKey {
    fn from_var(var: &SSAVar) -> Self {
        Self {
            name: var.name.clone(),
            version: var.version,
            size: var.size,
        }
    }
}

impl Ord for VarKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.name.as_str(), self.version, self.size).cmp(&(
            other.name.as_str(),
            other.version,
            other.size,
        ))
    }
}

impl PartialOrd for VarKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn const_value(var: &SSAVar) -> Option<u64> {
    if !var.is_const() {
        return None;
    }
    let val_str = var.name.strip_prefix("const:")?;
    if let Some(hex) = val_str
        .strip_prefix("0x")
        .or_else(|| val_str.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Ok(val) = u64::from_str_radix(val_str, 16) {
        return Some(val);
    }
    val_str.parse::<u64>().ok()
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

fn compute_constants(func: &SSAFunction, max_iters: usize) -> HashMap<VarKey, u64> {
    let mut consts = HashMap::new();

    for _ in 0..max_iters {
        let mut changed = false;

        for phi in func.all_phis() {
            let dst_key = VarKey::from_var(&phi.dst);
            if consts.contains_key(&dst_key) {
                continue;
            }
            let mut iter = phi.sources.iter();
            let Some((_, first)) = iter.next() else {
                continue;
            };
            let Some(first_val) = const_for_var(first, &consts) else {
                continue;
            };
            if iter.all(|(_, src)| const_for_var(src, &consts) == Some(first_val)) {
                consts.insert(dst_key, first_val);
                changed = true;
            }
        }

        for op in func.all_ops() {
            let Some(dst) = op.dst() else { continue };
            let dst_key = VarKey::from_var(dst);
            if consts.contains_key(&dst_key) {
                continue;
            }
            if let Some(val) = eval_const_op(op, &consts) {
                consts.insert(dst_key, val);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    consts
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
        IntMult { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a.wrapping_mul(b)
        }
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
        IntAnd { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a & b
        }
        IntOr { a, b, .. } => {
            let (a, b) = binary(a, b)?;
            a | b
        }
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

fn replace_sources_with_constants(
    func: &mut SSAFunction,
    consts: &HashMap<VarKey, u64>,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();

    for addr in block_addrs {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };

        for phi in &mut block.phis {
            for (_, src) in &mut phi.sources {
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

    for addr in block_addrs {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };
        for op in &mut block.ops {
            if let Some(new_op) = simplify_op(op) {
                if &new_op != op {
                    *op = new_op;
                    stats.ops_simplified += 1;
                    changed = true;
                }
            }
        }
    }

    changed
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

fn copy_propagation(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let (replacements, changed) = build_copy_replacements(func, stats);
    let applied = if replacements.is_empty() {
        false
    } else {
        apply_replacements(func, &replacements, stats)
    };
    changed || applied
}

fn build_copy_replacements(
    func: &mut SSAFunction,
    stats: &mut OptimizationStats,
) -> (HashMap<VarKey, SSAVar>, bool) {
    let mut replacements = HashMap::new();
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();

    for addr in block_addrs {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };

        block.phis.retain(|phi| {
            let mut iter = phi.sources.iter();
            let Some((_, first)) = iter.next() else {
                return true;
            };
            if iter.all(|(_, src)| src == first) {
                let dst_key = VarKey::from_var(&phi.dst);
                if phi.dst != *first {
                    replacements.insert(dst_key, first.clone());
                }
                stats.phis_simplified += 1;
                changed = true;
                false
            } else {
                true
            }
        });

        for op in &block.ops {
            if let SSAOp::Copy { dst, src } = op {
                if dst.size == src.size && dst != src {
                    replacements.insert(VarKey::from_var(dst), src.clone());
                }
            }
        }
    }

    (resolve_replacements(replacements), changed)
}

fn resolve_replacements(mut replacements: HashMap<VarKey, SSAVar>) -> HashMap<VarKey, SSAVar> {
    let keys: Vec<VarKey> = replacements.keys().cloned().collect();
    for key in keys {
        let mut visited = HashSet::new();
        let mut current_key = key.clone();
        let mut current_var = replacements.get(&current_key).cloned();
        while let Some(next) = current_var {
            let next_key = VarKey::from_var(&next);
            if !visited.insert(next_key.clone()) {
                break;
            }
            if let Some(follow) = replacements.get(&next_key).cloned() {
                current_var = Some(follow);
                current_key = next_key;
            } else {
                replacements.insert(key.clone(), next);
                break;
            }
        }
    }
    replacements
}

fn apply_replacements(
    func: &mut SSAFunction,
    replacements: &HashMap<VarKey, SSAVar>,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();

    let mapper = |var: &SSAVar| -> SSAVar {
        let mut visited = HashSet::new();
        let mut current = var.clone();
        let mut key = VarKey::from_var(&current);
        while let Some(next) = replacements.get(&key).cloned() {
            if !visited.insert(key) {
                return var.clone();
            }
            current = next;
            key = VarKey::from_var(&current);
        }
        current
    };

    for addr in block_addrs {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };

        for phi in &mut block.phis {
            for (_, src) in &mut phi.sources {
                let new_src = mapper(src);
                if new_src != *src {
                    *src = new_src;
                    stats.copies_propagated += 1;
                    changed = true;
                }
            }
        }

        for op in &mut block.ops {
            let new_op = map_sources_in_op(op, &mapper);
            if &new_op != op {
                let delta = count_source_replacements(op, &new_op);
                if delta > 0 {
                    stats.copies_propagated += delta;
                }
                *op = new_op;
                changed = true;
            }
        }
    }

    changed
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExprKind {
    Unary(&'static str),
    Binary(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExprKey {
    kind: ExprKind,
    dst_size: u32,
    args: Vec<VarKey>,
}

fn expr_key(op: &SSAOp) -> Option<ExprKey> {
    use SSAOp::*;
    let dst = op.dst()?;
    let key = match op {
        IntNegate { src, .. } => ExprKey {
            kind: ExprKind::Unary("IntNegate"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        IntNot { src, .. } => ExprKey {
            kind: ExprKind::Unary("IntNot"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        BoolNot { src, .. } => ExprKey {
            kind: ExprKind::Unary("BoolNot"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        IntZExt { src, .. } => ExprKey {
            kind: ExprKind::Unary("IntZExt"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        IntSExt { src, .. } => ExprKey {
            kind: ExprKind::Unary("IntSExt"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        Trunc { src, .. } => ExprKey {
            kind: ExprKind::Unary("Trunc"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        FloatNeg { src, .. } => ExprKey {
            kind: ExprKind::Unary("FloatNeg"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        FloatAbs { src, .. } => ExprKey {
            kind: ExprKind::Unary("FloatAbs"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        FloatSqrt { src, .. } => ExprKey {
            kind: ExprKind::Unary("FloatSqrt"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        Int2Float { src, .. } => ExprKey {
            kind: ExprKind::Unary("Int2Float"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        Float2Int { src, .. } => ExprKey {
            kind: ExprKind::Unary("Float2Int"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        FloatFloat { src, .. } => ExprKey {
            kind: ExprKind::Unary("FloatFloat"),
            dst_size: dst.size,
            args: vec![VarKey::from_var(src)],
        },
        IntAdd { a, b, .. }
        | IntMult { a, b, .. }
        | IntAnd { a, b, .. }
        | IntOr { a, b, .. }
        | IntXor { a, b, .. }
        | IntEqual { a, b, .. }
        | IntNotEqual { a, b, .. }
        | BoolAnd { a, b, .. }
        | BoolOr { a, b, .. }
        | BoolXor { a, b, .. }
        | FloatAdd { a, b, .. }
        | FloatMult { a, b, .. }
        | FloatEqual { a, b, .. }
        | FloatNotEqual { a, b, .. } => {
            let mut args = vec![VarKey::from_var(a), VarKey::from_var(b)];
            args.sort();
            let kind = match op {
                IntAdd { .. } => ExprKind::Binary("IntAdd"),
                IntMult { .. } => ExprKind::Binary("IntMult"),
                IntAnd { .. } => ExprKind::Binary("IntAnd"),
                IntOr { .. } => ExprKind::Binary("IntOr"),
                IntXor { .. } => ExprKind::Binary("IntXor"),
                IntEqual { .. } => ExprKind::Binary("IntEqual"),
                IntNotEqual { .. } => ExprKind::Binary("IntNotEqual"),
                BoolAnd { .. } => ExprKind::Binary("BoolAnd"),
                BoolOr { .. } => ExprKind::Binary("BoolOr"),
                BoolXor { .. } => ExprKind::Binary("BoolXor"),
                FloatAdd { .. } => ExprKind::Binary("FloatAdd"),
                FloatMult { .. } => ExprKind::Binary("FloatMult"),
                FloatEqual { .. } => ExprKind::Binary("FloatEqual"),
                FloatNotEqual { .. } => ExprKind::Binary("FloatNotEqual"),
                _ => return None,
            };
            ExprKey {
                kind,
                dst_size: dst.size,
                args,
            }
        }
        IntSub { a, b, .. }
        | IntDiv { a, b, .. }
        | IntSDiv { a, b, .. }
        | IntRem { a, b, .. }
        | IntSRem { a, b, .. }
        | IntLeft { a, b, .. }
        | IntRight { a, b, .. }
        | IntSRight { a, b, .. }
        | IntLess { a, b, .. }
        | IntLessEqual { a, b, .. }
        | IntSLess { a, b, .. }
        | IntSLessEqual { a, b, .. }
        | FloatSub { a, b, .. }
        | FloatDiv { a, b, .. }
        | FloatLess { a, b, .. }
        | FloatLessEqual { a, b, .. } => {
            let args = vec![VarKey::from_var(a), VarKey::from_var(b)];
            let kind = match op {
                IntSub { .. } => ExprKind::Binary("IntSub"),
                IntDiv { .. } => ExprKind::Binary("IntDiv"),
                IntSDiv { .. } => ExprKind::Binary("IntSDiv"),
                IntRem { .. } => ExprKind::Binary("IntRem"),
                IntSRem { .. } => ExprKind::Binary("IntSRem"),
                IntLeft { .. } => ExprKind::Binary("IntLeft"),
                IntRight { .. } => ExprKind::Binary("IntRight"),
                IntSRight { .. } => ExprKind::Binary("IntSRight"),
                IntLess { .. } => ExprKind::Binary("IntLess"),
                IntLessEqual { .. } => ExprKind::Binary("IntLessEqual"),
                IntSLess { .. } => ExprKind::Binary("IntSLess"),
                IntSLessEqual { .. } => ExprKind::Binary("IntSLessEqual"),
                FloatSub { .. } => ExprKind::Binary("FloatSub"),
                FloatDiv { .. } => ExprKind::Binary("FloatDiv"),
                FloatLess { .. } => ExprKind::Binary("FloatLess"),
                FloatLessEqual { .. } => ExprKind::Binary("FloatLessEqual"),
                _ => return None,
            };
            ExprKey {
                kind,
                dst_size: dst.size,
                args,
            }
        }
        _ => return None,
    };

    Some(key)
}

fn common_subexpr_elim(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
    let mut changed = false;
    let block_addrs = func.block_addrs().to_vec();

    for addr in block_addrs {
        let Some(block) = func.get_block_mut(addr) else {
            continue;
        };
        let mut available: HashMap<ExprKey, SSAVar> = HashMap::new();

        for op in &mut block.ops {
            let Some(dst) = op.dst().cloned() else {
                continue;
            };
            let Some(key) = expr_key(op) else { continue };

            if let Some(existing) = available.get(&key).cloned() {
                if existing.size == dst.size {
                    *op = SSAOp::Copy { dst, src: existing };
                    stats.cse_replacements += 1;
                    changed = true;
                }
            } else {
                available.insert(key, dst);
            }
        }
    }

    changed
}

fn op_has_side_effects(op: &SSAOp, preserve_memory_reads: bool) -> bool {
    if op.is_control_flow() || op.is_memory_write() {
        return true;
    }
    if preserve_memory_reads && op.is_memory_read() {
        return true;
    }
    matches!(
        op,
        SSAOp::CallOther { .. }
            | SSAOp::Breakpoint
            | SSAOp::Unimplemented
            | SSAOp::CpuId { .. }
            | SSAOp::New { .. }
    )
}

fn dead_code_elim(
    func: &mut SSAFunction,
    config: &OptimizationConfig,
    stats: &mut OptimizationStats,
) -> bool {
    let mut changed = false;

    loop {
        let use_set = collect_uses(func);
        let mut local_change = false;
        let block_addrs = func.block_addrs().to_vec();

        for addr in block_addrs {
            let Some(block) = func.get_block_mut(addr) else {
                continue;
            };

            let before_ops = block.ops.len();
            block.ops.retain(|op| {
                if let Some(dst) = op.dst() {
                    let key = VarKey::from_var(dst);
                    if !use_set.contains(&key)
                        && !op_has_side_effects(op, config.preserve_memory_reads)
                    {
                        stats.dce_removed_ops += 1;
                        return false;
                    }
                }
                true
            });

            let before_phis = block.phis.len();
            block.phis.retain(|phi| {
                let key = VarKey::from_var(&phi.dst);
                if !use_set.contains(&key) {
                    stats.dce_removed_phis += 1;
                    return false;
                }
                true
            });

            if block.ops.len() != before_ops || block.phis.len() != before_phis {
                local_change = true;
            }
        }

        if !local_change {
            break;
        }
        changed = true;
    }

    changed
}

fn collect_uses(func: &SSAFunction) -> HashSet<VarKey> {
    let mut uses = HashSet::new();

    for phi in func.all_phis() {
        for (_, src) in &phi.sources {
            uses.insert(VarKey::from_var(src));
        }
    }

    for op in func.all_ops() {
        for src in op.sources() {
            uses.insert(VarKey::from_var(src));
        }
    }

    uses
}

fn map_sources_in_op<F>(op: &SSAOp, map: &F) -> SSAOp
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
            space: space.clone(),
            addr: map(addr),
        },
        Store { space, addr, val } => Store {
            space: space.clone(),
            addr: map(addr),
            val: map(val),
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
        Branch { target } => Branch {
            target: map(target),
        },
        CBranch { target, cond } => CBranch {
            target: map(target),
            cond: map(cond),
        },
        BranchInd { target } => BranchInd {
            target: map(target),
        },
        Call { target } => Call {
            target: map(target),
        },
        CallInd { target } => CallInd {
            target: map(target),
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
        Insert {
            dst,
            src,
            value,
            position,
        } => Insert {
            dst: dst.clone(),
            src: map(src),
            value: map(value),
            position: map(position),
        },
        Nop => Nop,
        Unimplemented => Unimplemented,
        Breakpoint => Breakpoint,
    }
}
