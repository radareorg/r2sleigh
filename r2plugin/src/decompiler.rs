use crate::context::PluginCtxView;
use crate::{
    decompile_artifact_guard_fallback, decompile_block_guard_fallback, decompiler_cfg_guard_reason,
    decompiler_max_blocks, parse_addr_name_map, parse_external_reg_params,
    parse_external_stack_vars, run_decompile_on_large_stack,
};
use r2il::{ArchSpec, R2ILBlock};

pub(crate) struct DecompilerEnv {
    pub(crate) arch_name: String,
    pub(crate) ptr_bits: u32,
    pub(crate) cfg: r2dec::DecompilerConfig,
}

pub(crate) fn normalize_sig_arch_name(arch: Option<&ArchSpec>) -> Option<String> {
    let arch = arch?;
    let lower = arch.name.to_ascii_lowercase();
    if matches!(lower.as_str(), "x86-64" | "x86_64" | "x64" | "amd64") {
        return Some("x86-64".to_string());
    }
    if matches!(lower.as_str(), "x86" | "x86-32" | "i386" | "i686") {
        return Some("x86".to_string());
    }
    Some(arch.name.clone())
}

pub(crate) fn decompiler_config_for_arch_name(
    arch_name: &str,
    ptr_bits: u32,
) -> r2dec::DecompilerConfig {
    match (arch_name, ptr_bits) {
        ("x86", 32) | ("x86-32", _) => r2dec::DecompilerConfig::x86(),
        ("x86-64", _) | ("x86_64", _) | ("x64", _) | ("amd64", _) => {
            r2dec::DecompilerConfig::x86_64()
        }
        ("arm", _) | ("ARM", _) if ptr_bits == 32 => r2dec::DecompilerConfig::arm(),
        ("aarch64", _) | ("arm64", _) | ("ARM64", _) => r2dec::DecompilerConfig::aarch64(),
        ("riscv32", _) | ("rv32", _) | ("rv32gc", _) => r2dec::DecompilerConfig::riscv32(),
        ("riscv64", _) | ("rv64", _) | ("rv64gc", _) => r2dec::DecompilerConfig::riscv64(),
        ("riscv", _) if ptr_bits == 32 => r2dec::DecompilerConfig::riscv32(),
        ("riscv", _) => r2dec::DecompilerConfig::riscv64(),
        _ => r2dec::DecompilerConfig {
            ptr_size: ptr_bits,
            ..r2dec::DecompilerConfig::default()
        },
    }
}

pub(crate) fn build_decompiler_env(ctx: &PluginCtxView<'_>) -> DecompilerEnv {
    let arch_name = normalize_sig_arch_name(ctx.arch).unwrap_or_else(|| "unknown".to_string());
    let ptr_bits = ctx.arch.map(|arch| arch.addr_size * 8).unwrap_or(64);
    let cfg = decompiler_config_for_arch_name(&arch_name, ptr_bits);
    DecompilerEnv {
        arch_name,
        ptr_bits,
        cfg,
    }
}

pub(crate) fn decompile_blocks(
    blocks: &[R2ILBlock],
    function_name: &str,
    arch: Option<&ArchSpec>,
) -> Option<String> {
    let max_blocks = decompiler_max_blocks();
    if blocks.len() > max_blocks {
        return Some(decompile_block_guard_fallback(
            function_name,
            blocks.len(),
            max_blocks,
        ));
    }
    if let Some(reason) = decompiler_cfg_guard_reason(blocks) {
        return Some(decompile_artifact_guard_fallback(function_name, &reason));
    }

    let env = DecompilerEnv {
        arch_name: normalize_sig_arch_name(arch).unwrap_or_else(|| "unknown".to_string()),
        ptr_bits: arch.map(|spec| spec.addr_size * 8).unwrap_or(64),
        cfg: decompiler_config_for_arch_name(
            &normalize_sig_arch_name(arch).unwrap_or_else(|| "unknown".to_string()),
            arch.map(|spec| spec.addr_size * 8).unwrap_or(64),
        ),
    };

    let ssa_func =
        r2ssa::SSAFunction::from_blocks_for_decompile(blocks, arch)?.with_name(function_name);
    let decompiler = r2dec::Decompiler::new(env.cfg);
    Some(run_decompile_on_large_stack(decompiler, ssa_func))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_full_decompile_on_large_stack(
    r2il_blocks: Vec<R2ILBlock>,
    func_name_str: String,
    arch: Option<r2il::ArchSpec>,
    ptr_bits: u32,
    semantic_metadata_enabled: bool,
    reg_type_hints: std::collections::HashMap<String, crate::types::TypeHint>,
    func_names_str: String,
    strings_str: String,
    symbols_str: String,
    signature_str: String,
    stack_vars_str: String,
    types_str: String,
) -> String {
    const STACK_SIZE: usize = 512 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            if let Some(reason) = crate::decompiler_cfg_guard_reason(&r2il_blocks) {
                return decompile_artifact_guard_fallback(&func_name_str, &reason);
            }
            let arch_name =
                normalize_sig_arch_name(arch.as_ref()).unwrap_or_else(|| "unknown".to_string());
            let config = decompiler_config_for_arch_name(&arch_name, ptr_bits);
            let Some(artifact) = crate::types::build_detached_function_analysis_artifact(
                &r2il_blocks,
                &func_name_str,
                arch.as_ref(),
                ptr_bits,
                semantic_metadata_enabled,
                &reg_type_hints,
                &signature_str,
                &stack_vars_str,
                &types_str,
            ) else {
                return decompile_artifact_guard_fallback(
                    &func_name_str,
                    "failed to build detached analysis artifact",
                );
            };

            let mut decompiler = r2dec::Decompiler::new(config);
            decompiler.set_function_names(parse_addr_name_map(&func_names_str));
            decompiler.set_strings(parse_addr_name_map(&strings_str));
            decompiler.set_symbols(parse_addr_name_map(&symbols_str));

            let reg_params = parse_external_reg_params(&stack_vars_str, ptr_bits);
            decompiler.set_register_params(reg_params);
            let stack_vars = parse_external_stack_vars(&stack_vars_str, ptr_bits);
            if !stack_vars.is_empty() {
                decompiler.set_stack_vars(stack_vars);
            }

            decompiler.set_type_facts(artifact.type_facts);

            decompiler.decompile(&artifact.ssa_func)
        });

    match handle {
        Ok(h) => match h.join() {
            Ok(output) => output,
            Err(_) => "/* r2dec: decompilation panicked (internal error) */".to_string(),
        },
        Err(e) => format!("/* r2dec: failed to spawn decompiler thread: {} */", e),
    }
}
