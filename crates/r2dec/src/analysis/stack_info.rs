use std::collections::{HashMap, HashSet};

use r2ssa::SSAOp;

use super::{PassEnv, StackInfo, UseInfo, lower::LowerCtx, utils};
use crate::ast::CExpr;
use crate::fold::SSABlock;

#[derive(Debug, Default)]
pub(crate) struct StackScratch {
    pub(crate) info: StackInfo,
}

pub(crate) fn analyze(blocks: &[SSABlock], use_info: &UseInfo, env: &PassEnv) -> StackInfo {
    let mut scratch = StackScratch::default();

    analyze_stack_vars(&mut scratch, blocks, use_info, env);

    scratch.info
}

fn analyze_stack_vars(
    scratch: &mut StackScratch,
    blocks: &[SSABlock],
    use_info: &UseInfo,
    env: &PassEnv,
) {
    for block in blocks {
        for op in &block.ops {
            match op {
                SSAOp::Load { addr, .. } => {
                    if let Some(offset) = utils::extract_stack_offset_from_var(
                        addr,
                        &use_info.definitions,
                        &env.fp_name,
                        &env.sp_name,
                    ) {
                        get_or_create_stack_var(scratch, offset);
                    }
                }
                SSAOp::Store { addr, val, .. } => {
                    if let Some(offset) = utils::extract_stack_offset_from_var(
                        addr,
                        &use_info.definitions,
                        &env.fp_name,
                        &env.sp_name,
                    ) {
                        if let Some(arg_alias) = utils::arg_alias_for_store_source(
                            val,
                            &use_info.copy_sources,
                            &use_info.var_aliases,
                        ) {
                            set_stack_arg_alias(scratch, offset, arg_alias);
                        }
                        get_or_create_stack_var(scratch, offset);
                    }
                }
                SSAOp::IntAdd { a, b, .. } => {
                    let a_lower = a.name.to_lowercase();
                    if (a_lower.contains(&env.fp_name) || a_lower.contains(&env.sp_name))
                        && let Some(offset) = utils::parse_const_offset(b)
                    {
                        get_or_create_stack_var(scratch, offset);
                    }
                }
                _ => {}
            }
        }
    }

    let mut merged_defs = use_info.definitions.clone();

    for block in blocks {
        for op in &block.ops {
            match op {
                SSAOp::IntAdd { dst, a, b } => {
                    let a_lower = a.name.to_lowercase();
                    if !(a_lower.contains(&env.fp_name) || a_lower.contains(&env.sp_name)) {
                        continue;
                    }
                    if let Some(offset) = utils::parse_const_offset(b)
                        && let Some(stack_var_name) = scratch.info.stack_vars.get(&offset).cloned()
                    {
                        let expr = CExpr::Var(format!("&{}", stack_var_name));
                        scratch
                            .info
                            .definition_overrides
                            .insert(dst.display_name(), expr.clone());
                        merged_defs.insert(dst.display_name(), expr);
                    }
                }
                SSAOp::Load { dst, addr, .. } => {
                    if let Some(stack_var_name) = stack_var_for_addr_var(
                        addr,
                        &merged_defs,
                        &scratch.info.stack_vars,
                        &use_info.var_aliases,
                        env,
                    ) && stack_var_name.starts_with("arg")
                    {
                        let expr = CExpr::Var(stack_var_name);
                        scratch
                            .info
                            .definition_overrides
                            .insert(dst.display_name(), expr.clone());
                        merged_defs.insert(dst.display_name(), expr);
                    }
                }
                _ => {}
            }
        }
    }
}

fn set_stack_arg_alias(scratch: &mut StackScratch, offset: i64, alias: String) {
    scratch
        .info
        .stack_arg_aliases
        .entry(offset)
        .or_insert_with(|| alias.clone());

    let should_replace = match scratch.info.stack_vars.get(&offset) {
        None => true,
        Some(existing) => {
            existing.starts_with("local_")
                || existing.starts_with("stack_")
                || existing == "saved_fp"
        }
    };

    if should_replace {
        scratch.info.stack_vars.insert(offset, alias);
    }
}

fn get_or_create_stack_var(scratch: &mut StackScratch, offset: i64) -> String {
    if let Some(alias) = scratch.info.stack_arg_aliases.get(&offset) {
        return alias.clone();
    }
    if let Some(name) = scratch.info.stack_vars.get(&offset) {
        return name.clone();
    }

    let name = if offset < 0 {
        format!("local_{:x}", (-offset) as u64)
    } else if offset == 0 {
        "saved_fp".to_string()
    } else {
        format!("stack_{:x}", offset as u64)
    };

    scratch.info.stack_vars.insert(offset, name.clone());
    name
}

fn stack_var_for_addr_var(
    addr: &r2ssa::SSAVar,
    definitions: &HashMap<String, CExpr>,
    stack_vars: &HashMap<i64, String>,
    var_aliases: &HashMap<String, String>,
    env: &PassEnv,
) -> Option<String> {
    let addr_key = addr.display_name();
    if let Some(alias) = resolve_stack_alias_from_addr_expr(
        &CExpr::Var(addr_key.clone()),
        definitions,
        stack_vars,
        env,
        0,
        &mut HashSet::new(),
    ) {
        return Some(alias);
    }

    let empty_counts: HashMap<String, usize> = HashMap::new();
    let empty_names: HashSet<String> = HashSet::new();
    let empty_ptrs: HashMap<String, crate::fold::PtrArith> = HashMap::new();
    let lower = LowerCtx {
        definitions,
        use_counts: &empty_counts,
        condition_vars: &empty_names,
        pinned: &empty_names,
        var_aliases,
        ptr_arith: &empty_ptrs,
        function_names: &env.function_names,
        strings: &env.strings,
        symbols: &env.symbols,
    };
    let rendered = lower.var_name(addr);
    if let Some(alias) = resolve_stack_alias_from_addr_expr(
        &CExpr::Var(rendered),
        definitions,
        stack_vars,
        env,
        0,
        &mut HashSet::new(),
    ) {
        return Some(alias);
    }

    utils::extract_stack_offset_from_var(addr, definitions, &env.fp_name, &env.sp_name)
        .and_then(|offset| stack_vars.get(&offset).cloned())
}

fn resolve_stack_alias_from_addr_expr(
    expr: &CExpr,
    definitions: &HashMap<String, CExpr>,
    stack_vars: &HashMap<i64, String>,
    env: &PassEnv,
    depth: u32,
    visited: &mut HashSet<String>,
) -> Option<String> {
    if depth > 8 {
        return None;
    }

    if let Some(alias) = utils::simplify_stack_access(expr, stack_vars, &env.fp_name, &env.sp_name)
    {
        return Some(alias);
    }

    match expr {
        CExpr::Var(name) => {
            if let Some(stripped) = name.strip_prefix('&') {
                return Some(stripped.to_string());
            }
            if !visited.insert(name.clone()) {
                return None;
            }
            definitions.get(name).and_then(|inner| {
                resolve_stack_alias_from_addr_expr(
                    inner,
                    definitions,
                    stack_vars,
                    env,
                    depth + 1,
                    visited,
                )
            })
        }
        CExpr::Paren(inner) => resolve_stack_alias_from_addr_expr(
            inner,
            definitions,
            stack_vars,
            env,
            depth + 1,
            visited,
        ),
        CExpr::Cast { expr: inner, .. } => resolve_stack_alias_from_addr_expr(
            inner,
            definitions,
            stack_vars,
            env,
            depth + 1,
            visited,
        ),
        CExpr::Deref(inner) => resolve_stack_alias_from_addr_expr(
            inner,
            definitions,
            stack_vars,
            env,
            depth + 1,
            visited,
        ),
        _ => None,
    }
}
