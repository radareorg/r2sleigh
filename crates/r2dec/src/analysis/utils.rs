use std::collections::{HashMap, HashSet};

use r2ssa::SSAVar;

use crate::ast::{BinaryOp, CExpr};

/// Threshold for detecting 64-bit negative values stored as unsigned.
const LIKELY_NEGATIVE_THRESHOLD: u64 = 0xffffffffffff0000;

pub(crate) fn is_cpu_flag(name: &str) -> bool {
    if matches!(
        name,
        "cf" | "pf"
            | "af"
            | "zf"
            | "sf"
            | "of"
            | "df"
            | "tf"
            | "if"
            | "iopl"
            | "nt"
            | "rf"
            | "vm"
            | "ac"
            | "vif"
            | "vip"
            | "id"
    ) {
        return true;
    }

    name.starts_with("cf_")
        || name.starts_with("pf_")
        || name.starts_with("af_")
        || name.starts_with("zf_")
        || name.starts_with("sf_")
        || name.starts_with("of_")
}

pub(crate) fn parse_const_value(name: &str) -> Option<u64> {
    let val_str = name.strip_prefix("const:")?;
    let val_str = val_str.split('_').next().unwrap_or(val_str);

    if let Some(hex) = val_str
        .strip_prefix("0x")
        .or_else(|| val_str.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if val_str.chars().all(|c| c.is_ascii_hexdigit()) {
        if val_str.chars().any(|c| c.is_ascii_alphabetic()) {
            u64::from_str_radix(val_str, 16).ok()
        } else if val_str.len() > 4 {
            u64::from_str_radix(val_str, 16).ok()
        } else {
            val_str.parse().ok()
        }
    } else {
        val_str.parse().ok()
    }
}

pub(crate) fn parse_const_offset(var: &SSAVar) -> Option<i64> {
    if !var.is_const() {
        return None;
    }
    // Offsets in SSA const varnames are interpreted as hex by default to stay
    // consistent with type inference / field recovery paths.
    let val = {
        let val_str = var
            .name
            .strip_prefix("const:")?
            .split('_')
            .next()
            .unwrap_or_default();
        if let Some(hex) = val_str
            .strip_prefix("0x")
            .or_else(|| val_str.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()?
        } else if let Some(dec) = val_str
            .strip_prefix("0d")
            .or_else(|| val_str.strip_prefix("0D"))
        {
            dec.parse().ok()?
        } else {
            u64::from_str_radix(val_str, 16).ok()?
        }
    };
    if val > LIKELY_NEGATIVE_THRESHOLD {
        let neg = (!val).wrapping_add(1);
        Some(-(neg as i64))
    } else {
        Some(val as i64)
    }
}

pub(crate) fn uf_find(parent: &mut HashMap<String, String>, x: &str) -> String {
    let p = parent.get(x).cloned().unwrap_or_else(|| x.to_string());
    if p == x {
        return x.to_string();
    }
    let root = uf_find(parent, &p);
    parent.insert(x.to_string(), root.clone());
    root
}

pub(crate) fn format_traced_name(key: &str, var_aliases: &HashMap<String, String>) -> String {
    if let Some(alias) = var_aliases.get(key) {
        return alias.clone();
    }

    if !key.starts_with("tmp:") && !key.starts_with("const:") && !key.starts_with("ram:") {
        if let Some((base, version)) = key.rsplit_once('_') {
            if version == "0" {
                return base.to_lowercase();
            }
            return format!("{}_{}", base.to_lowercase(), version);
        }
        return key.to_lowercase();
    }

    if key.starts_with("tmp:")
        && let Some(version_str) = key.rsplit_once('_').map(|(_, v)| v)
    {
        if let Ok(ver) = version_str.parse::<u32>() {
            return if ver > 0 {
                format!("t{}_{}", ver, ver)
            } else {
                "t0".to_string()
            };
        }
        return format!("t{}", version_str);
    }

    key.to_string()
}

pub(crate) fn trace_ssa_var_to_source(
    var: &SSAVar,
    copy_sources: &HashMap<String, String>,
    var_aliases: &HashMap<String, String>,
) -> String {
    let mut current_key = var.display_name();
    let mut visited = HashSet::new();

    for _ in 0..20 {
        if !visited.insert(current_key.clone()) {
            break;
        }

        if let Some(src_key) = copy_sources.get(&current_key) {
            if src_key.starts_with('*') {
                return format!("var_{}", current_key.split('_').last().unwrap_or("0"));
            }
            current_key = src_key.clone();
            continue;
        }
        break;
    }

    format_traced_name(&current_key, var_aliases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2ssa::SSAVar;

    #[test]
    fn parse_const_value_keeps_existing_general_behavior() {
        assert_eq!(parse_const_value("const:100"), Some(100));
        assert_eq!(parse_const_value("const:0x100"), Some(0x100));
    }

    #[test]
    fn parse_const_offset_handles_negative_wrapped_values() {
        let wrapped = SSAVar::new("const:ffffffffffffffb8", 0, 8);
        assert_eq!(parse_const_offset(&wrapped), Some(-72));
    }

    #[test]
    fn parse_const_offset_prefers_hex_for_plain_offsets() {
        let plain = SSAVar::new("const:100", 0, 8);
        assert_eq!(parse_const_offset(&plain), Some(0x100));
        let explicit_dec = SSAVar::new("const:0d100", 0, 8);
        assert_eq!(parse_const_offset(&explicit_dec), Some(100));
    }
}

pub(crate) fn expr_to_offset(expr: &CExpr) -> Option<i64> {
    match expr {
        CExpr::IntLit(v) => Some(*v),
        CExpr::UIntLit(v) => {
            if *v > LIKELY_NEGATIVE_THRESHOLD {
                let neg = (!*v).wrapping_add(1);
                Some(-(neg as i64))
            } else {
                Some(*v as i64)
            }
        }
        _ => None,
    }
}

pub(crate) fn extract_offset_from_expr(expr: &CExpr, fp_name: &str, sp_name: &str) -> Option<i64> {
    match expr {
        CExpr::Paren(inner) => extract_offset_from_expr(inner, fp_name, sp_name),
        CExpr::Cast { expr: inner, .. } => extract_offset_from_expr(inner, fp_name, sp_name),
        CExpr::Binary {
            op: BinaryOp::Add,
            left,
            right,
        } => {
            if let CExpr::Var(name) = left.as_ref() {
                let name_lower = name.to_lowercase();
                if name_lower.contains(fp_name) || name_lower.contains(sp_name) {
                    return expr_to_offset(right);
                }
            }
            if let CExpr::Var(name) = right.as_ref() {
                let name_lower = name.to_lowercase();
                if name_lower.contains(fp_name) || name_lower.contains(sp_name) {
                    return expr_to_offset(left);
                }
            }
            None
        }
        CExpr::Binary {
            op: BinaryOp::Sub,
            left,
            right,
        } => {
            if let CExpr::Var(name) = left.as_ref() {
                let name_lower = name.to_lowercase();
                if name_lower.contains(fp_name) || name_lower.contains(sp_name) {
                    return expr_to_offset(right).map(|off| -off);
                }
            }
            None
        }
        CExpr::Var(name) => {
            let name_lower = name.to_lowercase();
            if name_lower.contains(fp_name) || name_lower.contains(sp_name) {
                return Some(0);
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn extract_stack_offset_from_var(
    var: &SSAVar,
    definitions: &HashMap<String, CExpr>,
    fp_name: &str,
    sp_name: &str,
) -> Option<i64> {
    let name_lower = var.name.to_lowercase();
    if name_lower.contains(fp_name) || name_lower.contains(sp_name) {
        return Some(0);
    }

    let key = var.display_name();
    let mut visited = HashSet::new();
    definitions.get(&key).and_then(|expr| {
        extract_offset_from_expr_with_defs(expr, definitions, fp_name, sp_name, 0, &mut visited)
    })
}

fn extract_offset_from_expr_with_defs(
    expr: &CExpr,
    definitions: &HashMap<String, CExpr>,
    fp_name: &str,
    sp_name: &str,
    depth: u32,
    visited: &mut HashSet<String>,
) -> Option<i64> {
    if depth > 10 {
        return None;
    }

    if let Some(offset) = extract_offset_from_expr(expr, fp_name, sp_name) {
        return Some(offset);
    }

    match expr {
        CExpr::Var(name) => {
            if !visited.insert(name.clone()) {
                return None;
            }
            definitions.get(name).and_then(|inner| {
                extract_offset_from_expr_with_defs(
                    inner,
                    definitions,
                    fp_name,
                    sp_name,
                    depth + 1,
                    visited,
                )
            })
        }
        CExpr::Paren(inner)
        | CExpr::Cast { expr: inner, .. }
        | CExpr::Deref(inner)
        | CExpr::Unary { operand: inner, .. } => extract_offset_from_expr_with_defs(
            inner,
            definitions,
            fp_name,
            sp_name,
            depth + 1,
            visited,
        ),
        _ => None,
    }
}

pub(crate) fn normalize_stack_address(
    addr: &SSAVar,
    definitions: &HashMap<String, CExpr>,
    fp_name: &str,
    sp_name: &str,
) -> String {
    let addr_key = addr.display_name();
    if let Some(expr) = definitions.get(&addr_key)
        && let Some(offset) = extract_offset_from_expr(expr, fp_name, sp_name)
    {
        return format!("stack:{}", offset);
    }
    addr_key
}

pub(crate) fn simplify_stack_access(
    addr_expr: &CExpr,
    stack_vars: &HashMap<i64, String>,
    fp_name: &str,
    sp_name: &str,
) -> Option<String> {
    match addr_expr {
        CExpr::Paren(inner) => return simplify_stack_access(inner, stack_vars, fp_name, sp_name),
        CExpr::Cast { expr: inner, .. } => {
            return simplify_stack_access(inner, stack_vars, fp_name, sp_name);
        }
        CExpr::AddrOf(inner) => return simplify_stack_access(inner, stack_vars, fp_name, sp_name),
        CExpr::Var(name) => {
            if let Some(stripped) = name.strip_prefix('&') {
                return Some(stripped.to_string());
            }
        }
        _ => {}
    }

    extract_offset_from_expr(addr_expr, fp_name, sp_name)
        .and_then(|offset| stack_vars.get(&offset).cloned())
}

pub(crate) fn arg_alias_for_register_name(reg_name: &str) -> Option<String> {
    let reg = reg_name.to_lowercase();
    if reg.contains("rdi") || reg.contains("edi") {
        return Some("arg1".to_string());
    }
    if reg.contains("rsi") || reg.contains("esi") {
        return Some("arg2".to_string());
    }
    if reg.contains("rdx") || reg.contains("edx") {
        return Some("arg3".to_string());
    }
    if reg.contains("rcx") || reg.contains("ecx") {
        return Some("arg4".to_string());
    }
    if reg.contains("r8") {
        return Some("arg5".to_string());
    }
    if reg.contains("r9") {
        return Some("arg6".to_string());
    }
    None
}

pub(crate) fn arg_alias_for_ssa_name(ssa_name: &str) -> Option<String> {
    let (base, version) = ssa_name.rsplit_once('_')?;
    if version != "0" {
        return None;
    }
    arg_alias_for_register_name(base)
}

pub(crate) fn arg_alias_for_store_source(
    src: &SSAVar,
    copy_sources: &HashMap<String, String>,
    var_aliases: &HashMap<String, String>,
) -> Option<String> {
    let mut key = src.display_name();
    let mut visited = HashSet::new();

    for _ in 0..8 {
        if !visited.insert(key.clone()) {
            break;
        }
        if let Some(alias) = arg_alias_for_ssa_name(&key) {
            return Some(alias);
        }
        let Some(next) = copy_sources.get(&key) else {
            break;
        };
        key = next.clone();
    }

    let traced = trace_ssa_var_to_source(src, copy_sources, var_aliases);
    arg_alias_for_register_name(&traced)
}
