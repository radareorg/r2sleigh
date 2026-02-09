use std::collections::{HashMap, HashSet};

use r2ssa::SSAOp;

use super::{utils, FlagInfo, PassEnv, UseInfo};
use crate::fold::SSABlock;

#[derive(Debug, Default)]
pub(crate) struct FlagScratch {
    pub(crate) info: FlagInfo,
}

pub(crate) fn analyze(blocks: &[SSABlock], use_info: &UseInfo, _env: &PassEnv) -> FlagInfo {
    let mut scratch = FlagScratch::default();

    for block in blocks {
        analyze_comparison_patterns(&mut scratch, block, use_info);
    }
    recompute_flag_only_values(&mut scratch, blocks);

    scratch.info
}

fn format_compare_operand(var_name: &str) -> String {
    if let Some(val) = utils::parse_const_value(var_name) {
        if val > 255 && val % 10 != 0 {
            format!("0x{:x}", val)
        } else if val > 0xffff {
            format!("0x{:x}", val)
        } else {
            format!("{}", val)
        }
    } else {
        var_name.to_string()
    }
}

fn analyze_comparison_patterns(scratch: &mut FlagScratch, block: &SSABlock, use_info: &UseInfo) {
    for op in &block.ops {
        if let SSAOp::IntSub { dst, a, b } = op {
            let dst_key = dst.display_name();
            let a_name =
                utils::trace_ssa_var_to_source(a, &use_info.copy_sources, &use_info.var_aliases);
            let b_name = if b.is_const() {
                format_compare_operand(&b.name)
            } else {
                utils::trace_ssa_var_to_source(b, &use_info.copy_sources, &use_info.var_aliases)
            };
            scratch.info.sub_results.insert(dst_key, (a_name, b_name));
        }

        if let SSAOp::IntEqual { dst, a, b } = op {
            let dst_name = dst.name.to_lowercase();
            if dst_name.contains("zf")
                && b.is_const()
                && utils::parse_const_value(&b.name) == Some(0)
            {
                let a_key = a.display_name();
                if let Some((orig_a, orig_b)) = scratch.info.sub_results.get(&a_key).cloned() {
                    scratch
                        .info
                        .flag_origins
                        .insert(dst.display_name(), (orig_a, orig_b));
                }
            }
        }

        if let SSAOp::IntSLess { dst, a, b } = op {
            let dst_name = dst.name.to_lowercase();
            if dst_name.contains("sf")
                && b.is_const()
                && utils::parse_const_value(&b.name) == Some(0)
            {
                let a_key = a.display_name();
                if let Some((orig_a, orig_b)) = scratch.info.sub_results.get(&a_key).cloned() {
                    scratch
                        .info
                        .flag_origins
                        .insert(dst.display_name(), (orig_a, orig_b));
                }
            }
        }

        if let SSAOp::IntSBorrow { dst, a, b } = op {
            let dst_name = dst.name.to_lowercase();
            if dst_name.contains("of") {
                let a_name = utils::trace_ssa_var_to_source(
                    a,
                    &use_info.copy_sources,
                    &use_info.var_aliases,
                );
                let b_name = if b.is_const() {
                    format_compare_operand(&b.name)
                } else {
                    utils::trace_ssa_var_to_source(b, &use_info.copy_sources, &use_info.var_aliases)
                };
                scratch
                    .info
                    .flag_origins
                    .insert(dst.display_name(), (a_name, b_name));
            }
        }

        if let SSAOp::IntLess { dst, a, b } = op {
            let dst_name = dst.name.to_lowercase();
            if dst_name.contains("cf") {
                let a_name = utils::trace_ssa_var_to_source(
                    a,
                    &use_info.copy_sources,
                    &use_info.var_aliases,
                );
                let b_name = if b.is_const() {
                    format_compare_operand(&b.name)
                } else {
                    utils::trace_ssa_var_to_source(b, &use_info.copy_sources, &use_info.var_aliases)
                };
                scratch
                    .info
                    .flag_origins
                    .insert(dst.display_name(), (a_name, b_name));
            }
        }
    }
}

fn op_can_be_flag_glue(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::Cast { .. }
    )
}

fn consumer_is_flag_context(op: &SSAOp, flag_context_dsts: &HashSet<String>) -> bool {
    if matches!(op, SSAOp::CBranch { .. }) {
        return true;
    }

    if let Some(dst) = op.dst() {
        let dst_key = dst.display_name();
        return utils::is_cpu_flag(&dst.name.to_lowercase())
            || flag_context_dsts.contains(&dst_key);
    }

    false
}

fn recompute_flag_only_values(scratch: &mut FlagScratch, blocks: &[SSABlock]) {
    scratch.info.flag_only_values.clear();

    let mut consumers: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut defs: HashMap<String, (usize, usize)> = HashMap::new();

    for (block_idx, block) in blocks.iter().enumerate() {
        for (op_idx, op) in block.ops.iter().enumerate() {
            for src in op.sources() {
                consumers
                    .entry(src.display_name())
                    .or_default()
                    .push((block_idx, op_idx));
            }
            if let Some(dst) = op.dst() {
                defs.insert(dst.display_name(), (block_idx, op_idx));
            }
        }
    }

    let mut flag_context_dsts: HashSet<String> = defs
        .keys()
        .filter(|name| utils::is_cpu_flag(&name.to_lowercase()))
        .cloned()
        .collect();

    loop {
        let mut changed = false;
        for (dst_key, (block_idx, op_idx)) in &defs {
            if flag_context_dsts.contains(dst_key) {
                continue;
            }

            let op = &blocks[*block_idx].ops[*op_idx];
            if !op_can_be_flag_glue(op) {
                continue;
            }

            let srcs = op.sources();
            if srcs.is_empty() {
                continue;
            }

            if !srcs.iter().all(|src| {
                src.is_const()
                    || utils::is_cpu_flag(&src.name.to_lowercase())
                    || flag_context_dsts.contains(&src.display_name())
            }) {
                continue;
            }

            let Some(op_consumers) = consumers.get(dst_key) else {
                continue;
            };
            if op_consumers.is_empty() {
                continue;
            }

            if op_consumers.iter().all(|(consumer_block, consumer_op)| {
                consumer_is_flag_context(
                    &blocks[*consumer_block].ops[*consumer_op],
                    &flag_context_dsts,
                )
            }) {
                flag_context_dsts.insert(dst_key.clone());
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    for (src_key, src_consumers) in consumers {
        if src_consumers.is_empty() || utils::is_cpu_flag(&src_key.to_lowercase()) {
            continue;
        }

        if src_consumers.iter().all(|(consumer_block, consumer_op)| {
            consumer_is_flag_context(
                &blocks[*consumer_block].ops[*consumer_op],
                &flag_context_dsts,
            )
        }) {
            scratch.info.flag_only_values.insert(src_key);
        }
    }
}
