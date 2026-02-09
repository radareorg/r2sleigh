use std::collections::{HashMap, HashSet};

use r2ssa::SSAOp;

use super::{PassEnv, UseInfo, lower::LowerCtx, utils};
use crate::ast::CExpr;
use crate::fold::{PtrArith, SSABlock};

#[derive(Debug, Default)]
pub(crate) struct UseScratch {
    pub(crate) info: UseInfo,
}

pub(crate) fn analyze(blocks: &[SSABlock], env: &PassEnv<'_>) -> UseInfo {
    let mut scratch = UseScratch::default();
    scratch.info.type_hints = env.type_hints.clone();

    for block in blocks {
        count_uses_and_conditions(&mut scratch, block);
    }
    for block in blocks {
        collect_definitions(&mut scratch, block, env);
    }

    analyze_call_args(&mut scratch, blocks, env);
    coalesce_variables(&mut scratch, blocks, env);
    build_formatted_defs(&mut scratch);

    scratch.info
}

fn count_uses_and_conditions(scratch: &mut UseScratch, block: &SSABlock) {
    for op in &block.ops {
        for src in op.sources() {
            let key = src.display_name();
            *scratch.info.use_counts.entry(key).or_insert(0) += 1;
        }

        if let SSAOp::CBranch { cond, .. } = op {
            scratch.info.condition_vars.insert(cond.display_name());
        }
    }
}

fn collect_definitions(scratch: &mut UseScratch, block: &SSABlock, env: &PassEnv<'_>) {
    for op in &block.ops {
        if let SSAOp::Copy { dst, src } = op {
            scratch
                .info
                .copy_sources
                .insert(dst.display_name(), src.display_name());
        }

        if let SSAOp::Store { addr, val, .. } = op {
            let addr_key = utils::normalize_stack_address(
                addr,
                &scratch.info.definitions,
                &env.fp_name,
                &env.sp_name,
            );
            scratch
                .info
                .memory_stores
                .insert(addr_key, val.display_name());
        }

        if let SSAOp::Load { dst, addr, .. } = op {
            let addr_key = utils::normalize_stack_address(
                addr,
                &scratch.info.definitions,
                &env.fp_name,
                &env.sp_name,
            );
            if let Some(stored_val) = scratch.info.memory_stores.get(&addr_key).cloned() {
                scratch
                    .info
                    .copy_sources
                    .insert(dst.display_name(), stored_val);
            } else {
                scratch
                    .info
                    .copy_sources
                    .insert(dst.display_name(), format!("*{}", addr.display_name()));
            }
        }

        if let SSAOp::PtrAdd {
            dst,
            base,
            index,
            element_size,
        } = op
        {
            scratch.info.ptr_arith.insert(
                dst.display_name(),
                PtrArith {
                    base: base.clone(),
                    index: index.clone(),
                    element_size: *element_size,
                    is_sub: false,
                },
            );
        }

        if let SSAOp::PtrSub {
            dst,
            base,
            index,
            element_size,
        } = op
        {
            scratch.info.ptr_arith.insert(
                dst.display_name(),
                PtrArith {
                    base: base.clone(),
                    index: index.clone(),
                    element_size: *element_size,
                    is_sub: true,
                },
            );
        }

        match op {
            SSAOp::IntAdd { dst, a, b } => {
                if let Some(offset) = utils::parse_const_offset(a) {
                    scratch
                        .info
                        .ptr_members
                        .insert(dst.display_name(), (b.clone(), offset));
                } else if let Some(offset) = utils::parse_const_offset(b) {
                    scratch
                        .info
                        .ptr_members
                        .insert(dst.display_name(), (a.clone(), offset));
                }
            }
            SSAOp::IntSub { dst, a, b } => {
                if let Some(offset) = utils::parse_const_offset(b) {
                    scratch
                        .info
                        .ptr_members
                        .insert(dst.display_name(), (a.clone(), -offset));
                }
            }
            _ => {}
        }

        if let Some(dst) = op.dst() {
            let key = dst.display_name();
            let expr = {
                let lower = LowerCtx {
                    definitions: &scratch.info.definitions,
                    use_counts: &scratch.info.use_counts,
                    condition_vars: &scratch.info.condition_vars,
                    pinned: &scratch.info.pinned,
                    var_aliases: &scratch.info.var_aliases,
                    ptr_arith: &scratch.info.ptr_arith,
                    function_names: &env.function_names,
                    strings: &env.strings,
                    symbols: &env.symbols,
                    type_oracle: env.type_oracle,
                };
                lower.op_to_expr(op)
            };
            scratch.info.definitions.insert(key, expr);
        }
    }
}

fn build_formatted_defs(scratch: &mut UseScratch) {
    scratch.info.formatted_defs.clear();
    let defs = scratch.info.definitions.clone();
    for (ssa_key, expr) in defs {
        let formatted = utils::format_traced_name(&ssa_key, &scratch.info.var_aliases);
        scratch.info.formatted_defs.insert(formatted, expr);
    }
}

fn coalesce_variables(scratch: &mut UseScratch, blocks: &[SSABlock], env: &PassEnv<'_>) {
    let mut reg_versions: HashMap<String, Vec<(String, u32)>> = HashMap::new();

    for block in blocks {
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                if dst.name.starts_with("tmp:")
                    || dst.name.starts_with("const:")
                    || dst.name.starts_with("ram:")
                    || dst.name.starts_with("reg:")
                {
                    continue;
                }
                let base = dst.name.to_lowercase();
                reg_versions
                    .entry(base)
                    .or_default()
                    .push((dst.display_name(), dst.version));
            }
            for src in op.sources() {
                if src.name.starts_with("tmp:")
                    || src.name.starts_with("const:")
                    || src.name.starts_with("ram:")
                    || src.name.starts_with("reg:")
                {
                    continue;
                }
                let base = src.name.to_lowercase();
                reg_versions
                    .entry(base)
                    .or_default()
                    .push((src.display_name(), src.version));
            }
        }
        for phi in &block.phis {
            if !phi.dst.name.starts_with("tmp:")
                && !phi.dst.name.starts_with("const:")
                && !phi.dst.name.starts_with("ram:")
                && !phi.dst.name.starts_with("reg:")
            {
                let base = phi.dst.name.to_lowercase();
                reg_versions
                    .entry(base)
                    .or_default()
                    .push((phi.dst.display_name(), phi.dst.version));
            }
            for (_, src) in &phi.sources {
                if !src.name.starts_with("tmp:")
                    && !src.name.starts_with("const:")
                    && !src.name.starts_with("ram:")
                    && !src.name.starts_with("reg:")
                {
                    let base = src.name.to_lowercase();
                    reg_versions
                        .entry(base)
                        .or_default()
                        .push((src.display_name(), src.version));
                }
            }
        }
    }

    let mut uf_parent: HashMap<String, String> = HashMap::new();
    for versions in reg_versions.values() {
        for (name, _) in versions {
            uf_parent
                .entry(name.clone())
                .or_insert_with(|| name.clone());
        }
    }

    for block in blocks {
        for phi in &block.phis {
            if phi.dst.name.starts_with("tmp:")
                || phi.dst.name.starts_with("const:")
                || phi.dst.name.starts_with("ram:")
                || phi.dst.name.starts_with("reg:")
            {
                continue;
            }
            let dst_key = phi.dst.display_name();
            for (_, src) in &phi.sources {
                let src_key = src.display_name();
                let root_a = utils::uf_find(&mut uf_parent, &dst_key);
                let root_b = utils::uf_find(&mut uf_parent, &src_key);
                if root_a != root_b {
                    uf_parent.insert(root_a, root_b);
                }
            }
        }
    }

    let mut block_vars: HashMap<u64, HashSet<String>> = HashMap::new();
    for block in blocks {
        let vars = block_vars.entry(block.addr).or_default();
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                vars.insert(dst.display_name());
            }
            for src in op.sources() {
                vars.insert(src.display_name());
            }
        }
        for phi in &block.phis {
            vars.insert(phi.dst.display_name());
            for (_, src) in &phi.sources {
                vars.insert(src.display_name());
            }
        }
    }

    for (base, versions) in &reg_versions {
        if *base == env.sp_name || *base == env.fp_name {
            continue;
        }
        let mut unique: Vec<(String, u32)> = versions.clone();
        unique.sort_by_key(|(_, v)| *v);
        unique.dedup_by_key(|(k, _)| k.clone());
        if unique.len() <= 1 {
            continue;
        }

        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for (ssa_name, _) in &unique {
            let root = utils::uf_find(&mut uf_parent, ssa_name);
            groups.entry(root).or_default().push(ssa_name.clone());
        }

        let mut group_idx = 0usize;
        for members in groups.values() {
            let has_conflict = block_vars.values().any(|vars| {
                let mut count = 0;
                for m in members {
                    if vars.contains(m) {
                        count += 1;
                    }
                }
                count > 1
            });

            if !has_conflict {
                let alias = if group_idx == 0 {
                    base.clone()
                } else {
                    format!("{}_{}", base, group_idx + 1)
                };
                for m in members {
                    scratch.info.var_aliases.insert(m.clone(), alias.clone());
                }
                group_idx += 1;
            } else {
                let alias = if group_idx == 0 {
                    base.clone()
                } else {
                    format!("{}_{}", base, group_idx + 1)
                };
                for m in members {
                    if let Some((_, v)) = unique.iter().find(|(n, _)| n == m)
                        && *v == 0
                    {
                        scratch.info.var_aliases.insert(m.clone(), alias.clone());
                    }
                }
                group_idx += 1;
            }
        }

        let grouped: HashSet<&str> = groups
            .values()
            .flat_map(|v| v.iter().map(|s| s.as_str()))
            .collect();
        let ungrouped: Vec<&(String, u32)> = unique
            .iter()
            .filter(|(n, _)| {
                !grouped.contains(n.as_str()) && !scratch.info.var_aliases.contains_key(n)
            })
            .collect();
        if !ungrouped.is_empty() {
            let ug_names: Vec<&str> = ungrouped.iter().map(|(n, _)| n.as_str()).collect();
            let has_conflict = block_vars.values().any(|vars| {
                let mut count = 0;
                for n in &ug_names {
                    if vars.contains(*n) {
                        count += 1;
                    }
                }
                count > 1
            });
            if !has_conflict {
                let alias = if group_idx == 0 {
                    base.clone()
                } else {
                    format!("{}_{}", base, group_idx + 1)
                };
                for (n, _) in &ungrouped {
                    scratch.info.var_aliases.insert(n.clone(), alias.clone());
                }
            }
        }
    }
}

fn analyze_call_args(scratch: &mut UseScratch, blocks: &[SSABlock], env: &PassEnv<'_>) {
    if env.arg_regs.is_empty() {
        return;
    }

    for block in blocks {
        let ops = &block.ops;
        for (call_idx, op) in ops.iter().enumerate() {
            let is_call = matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. });
            if !is_call {
                continue;
            }

            let mut found_regs: HashMap<String, (CExpr, String)> = HashMap::new();
            let mut i = call_idx;
            while i > 0 {
                i -= 1;
                let prev_op = &ops[i];

                if matches!(prev_op, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                    break;
                }

                let src_expr = {
                    let lower = LowerCtx {
                        definitions: &scratch.info.definitions,
                        use_counts: &scratch.info.use_counts,
                        condition_vars: &scratch.info.condition_vars,
                        pinned: &scratch.info.pinned,
                        var_aliases: &scratch.info.var_aliases,
                        ptr_arith: &scratch.info.ptr_arith,
                        function_names: &env.function_names,
                        strings: &env.strings,
                        symbols: &env.symbols,
                        type_oracle: env.type_oracle,
                    };
                    match prev_op {
                        SSAOp::Copy { dst, src } => Some((dst, lower.get_expr(src))),
                        SSAOp::IntZExt { dst, src } => Some((dst, lower.get_expr(src))),
                        SSAOp::IntSExt { dst, src } => Some((dst, lower.get_expr(src))),
                        SSAOp::IntXor { dst, a, b } if a == b => Some((dst, CExpr::IntLit(0))),
                        _ => None,
                    }
                };

                let Some((dst_var, expr)) = src_expr else {
                    continue;
                };

                let dst_base = dst_var.name.to_lowercase();
                if env.arg_regs.iter().any(|r| *r == dst_base)
                    && !found_regs.contains_key(&dst_base)
                {
                    let dst_key = dst_var.display_name();
                    found_regs.insert(dst_base.clone(), (expr, dst_key));
                }
            }

            let mut args = Vec::new();
            let mut consumed_keys = Vec::new();
            for reg in &env.arg_regs {
                if let Some((expr, dst_key)) = found_regs.remove(reg) {
                    args.push(expr);
                    consumed_keys.push(dst_key);
                } else {
                    break;
                }
            }

            if !args.is_empty() {
                scratch.info.call_args.insert((block.addr, call_idx), args);
                for key in consumed_keys {
                    scratch.info.consumed_by_call.insert(key);
                }
            }

            let mut j = call_idx;
            while j > 0 {
                j -= 1;
                let prev = &ops[j];
                if matches!(prev, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                    break;
                }
                if let SSAOp::Store { addr, val, .. } = prev {
                    let addr_lower = addr.name.to_lowercase();
                    if addr_lower.contains(&env.sp_name) && val.is_const() {
                        scratch.info.consumed_by_call.insert(val.display_name());
                        scratch.info.consumed_by_call.insert(addr.display_name());
                        if j > 0 {
                            let prev2 = &ops[j - 1];
                            if let SSAOp::IntSub { dst, b, .. } = prev2 {
                                let dst_lower = dst.name.to_lowercase();
                                if dst_lower.contains(&env.sp_name) && b.is_const() {
                                    scratch.info.consumed_by_call.insert(dst.display_name());
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}
