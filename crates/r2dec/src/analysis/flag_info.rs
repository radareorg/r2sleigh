use std::collections::{HashMap, HashSet};

use r2ssa::SSAOp;

use super::{FlagInfo, PassEnv, UseInfo, utils};
use crate::ast::{BinaryOp, CExpr, UnaryOp};
use crate::fold::SSABlock;

#[derive(Debug, Default)]
pub(crate) struct FlagScratch {
    pub(crate) info: FlagInfo,
}

pub(crate) fn analyze(blocks: &[SSABlock], use_info: &UseInfo, _env: &PassEnv<'_>) -> FlagInfo {
    let mut scratch = FlagScratch::default();

    for block in blocks {
        analyze_comparison_patterns(&mut scratch, block, use_info);
    }
    recompute_flag_only_values(&mut scratch, blocks);

    scratch.info
}

fn format_compare_operand(var_name: &str) -> String {
    if let Some(val) = utils::parse_const_value(var_name) {
        if (val > 255 && val % 10 != 0) || val > 0xffff {
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

        let predicate_expr = match op {
            SSAOp::Copy { src, .. }
            | SSAOp::IntZExt { src, .. }
            | SSAOp::IntSExt { src, .. }
            | SSAOp::Trunc { src, .. }
            | SSAOp::Cast { src, .. } => predicate_passthrough_expr(src, scratch),
            SSAOp::BoolNot { src, .. } => Some(CExpr::unary(
                UnaryOp::Not,
                predicate_operand_expr(src, scratch),
            )),
            SSAOp::BoolAnd { a, b, .. } => Some(CExpr::binary(
                BinaryOp::And,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::BoolOr { a, b, .. } => Some(CExpr::binary(
                BinaryOp::Or,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::BoolXor { a, b, .. } => Some(CExpr::binary(
                BinaryOp::BitXor,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::IntEqual { a, b, .. } => Some(CExpr::binary(
                BinaryOp::Eq,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::IntNotEqual { a, b, .. } => Some(CExpr::binary(
                BinaryOp::Ne,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::IntLess { a, b, .. } | SSAOp::IntSLess { a, b, .. } => Some(CExpr::binary(
                BinaryOp::Lt,
                predicate_operand_expr(a, scratch),
                predicate_operand_expr(b, scratch),
            )),
            SSAOp::IntLessEqual { a, b, .. } | SSAOp::IntSLessEqual { a, b, .. } => {
                Some(CExpr::binary(
                    BinaryOp::Le,
                    predicate_operand_expr(a, scratch),
                    predicate_operand_expr(b, scratch),
                ))
            }
            _ => None,
        };

        if let (Some(dst), Some(expr)) = (op.dst(), predicate_expr) {
            record_predicate_expr(scratch, dst.display_name(), expr, use_info);
        }
    }
}

fn const_expr_from_name(name: &str) -> Option<CExpr> {
    let val = utils::parse_const_value(name)?;
    Some(if val > 0x7fffffff {
        CExpr::UIntLit(val)
    } else {
        CExpr::IntLit(val as i64)
    })
}

fn predicate_passthrough_expr(src: &r2ssa::SSAVar, scratch: &FlagScratch) -> Option<CExpr> {
    if let Some(expr) = scratch.info.predicate_exprs.get(&src.display_name()) {
        return Some(expr.clone());
    }
    if src.is_const() {
        return const_expr_from_name(&src.name);
    }
    if utils::is_cpu_flag(&src.name.to_lowercase()) {
        return Some(CExpr::Var(src.display_name()));
    }
    None
}

fn predicate_operand_expr(src: &r2ssa::SSAVar, scratch: &FlagScratch) -> CExpr {
    predicate_passthrough_expr(src, scratch).unwrap_or_else(|| {
        if src.is_const() {
            const_expr_from_name(&src.name).unwrap_or_else(|| CExpr::Var(src.display_name()))
        } else {
            CExpr::Var(src.display_name())
        }
    })
}

fn record_predicate_expr(
    scratch: &mut FlagScratch,
    dst_key: String,
    expr: CExpr,
    use_info: &UseInfo,
) {
    let formatted = utils::format_traced_name(&dst_key, &use_info.var_aliases);
    scratch.info.predicate_exprs.insert(dst_key, expr.clone());
    scratch.info.predicate_exprs.insert(formatted, expr);
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
