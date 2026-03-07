use crate::blocks::BlockSlice;
use crate::{R2ILBlock, R2ILContext, SSAOpInfo, ssa_op_to_info};
use r2ssa::TaintPolicy;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct TaintConfig {
    sources: Vec<String>,
    sink_calls: bool,
    sink_stores: bool,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            sink_calls: true,
            sink_stores: true,
        }
    }
}

fn taint_config() -> &'static Mutex<TaintConfig> {
    static CONFIG: OnceLock<Mutex<TaintConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| Mutex::new(TaintConfig::default()))
}

#[derive(Serialize)]
struct TaintSourceJson {
    var: String,
    labels: Vec<String>,
    block: u64,
    block_hex: String,
}

#[derive(Serialize)]
struct TaintSinkJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
    op: SSAOpInfo,
}

#[derive(Serialize)]
struct TaintedVarJson {
    var: String,
    labels: Vec<String>,
}

#[derive(Serialize)]
struct SinkHitJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
    op: SSAOpInfo,
    tainted_vars: Vec<TaintedVarJson>,
}

#[derive(Serialize)]
struct TaintReportJson {
    sources: Vec<TaintSourceJson>,
    sinks: Vec<TaintSinkJson>,
    sink_hits: Vec<SinkHitJson>,
    tainted_vars: Vec<TaintedVarJson>,
}

#[derive(Serialize)]
struct TaintSummaryReportJson {
    sources: Vec<TaintSourceJson>,
    sink_hits: Vec<SinkHitJson>,
}

fn labels_to_strings(labels: &r2ssa::taint::TaintSet) -> Vec<String> {
    let mut out: Vec<String> = labels.iter().map(|l| l.id.clone()).collect();
    out.sort();
    out
}

fn current_taint_policy() -> Option<r2ssa::DefaultTaintPolicy> {
    let cfg = taint_config().lock().ok()?.clone();
    let mut policy = if cfg.sources.is_empty() {
        r2ssa::DefaultTaintPolicy::all_inputs()
    } else {
        r2ssa::DefaultTaintPolicy::new()
    }
    .with_sink_calls(cfg.sink_calls)
    .with_sink_stores(cfg.sink_stores);
    for src in cfg.sources {
        policy = policy.with_source(src);
    }
    Some(policy)
}

fn collect_taint_sources(
    ssa_func: &r2ssa::SSAFunction,
    policy: &r2ssa::DefaultTaintPolicy,
) -> Vec<TaintSourceJson> {
    let mut source_map = std::collections::HashMap::new();
    for block in ssa_func.blocks() {
        block.for_each_source(|src| {
            if let Some(labels) = policy.is_source(src.var, block.addr) {
                let entry = source_map
                    .entry(src.var.display_name())
                    .or_insert(TaintSourceJson {
                        var: src.var.display_name(),
                        labels: Vec::new(),
                        block: block.addr,
                        block_hex: format!("0x{:x}", block.addr),
                    });
                for label in labels {
                    entry.labels.push(label.id);
                }
            }
        });
    }

    for source in source_map.values_mut() {
        source.labels.sort();
        source.labels.dedup();
    }

    let mut sources: Vec<TaintSourceJson> = source_map.into_values().collect();
    sources.sort_by(|a, b| a.var.cmp(&b.var));
    sources
}

fn collect_taint_sink_hits(result: &r2ssa::TaintResult) -> Vec<SinkHitJson> {
    result
        .sink_hits
        .iter()
        .map(|hit| SinkHitJson {
            block: hit.block_addr,
            block_hex: format!("0x{:x}", hit.block_addr),
            op_idx: hit.op_idx,
            op: ssa_op_to_info(&hit.op),
            tainted_vars: hit
                .tainted_vars
                .iter()
                .map(|(var, labels)| TaintedVarJson {
                    var: var.display_name(),
                    labels: labels_to_strings(labels),
                })
                .collect(),
        })
        .collect()
}

/// Configure taint sources/sinks via JSON.
/// If `json` is NULL or empty, returns the current configuration.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_sources_sinks_json(json: *const c_char) -> *mut c_char {
    if !json.is_null() {
        let json_str = unsafe {
            match CStr::from_ptr(json).to_str() {
                Ok(s) => s.trim(),
                Err(_) => return ptr::null_mut(),
            }
        };
        if !json_str.is_empty() {
            match serde_json::from_str::<TaintConfig>(json_str) {
                Ok(new_cfg) => {
                    if let Ok(mut cfg) = taint_config().lock() {
                        *cfg = new_cfg;
                    }
                }
                Err(_) => return ptr::null_mut(),
            }
        }
    }

    let cfg = match taint_config().lock() {
        Ok(cfg) => cfg.clone(),
        Err(_) => return ptr::null_mut(),
    };

    match serde_json::to_string_pretty(&cfg) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Run taint analysis and return results as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_function_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let Some(blocks) = (unsafe { BlockSlice::from_ffi(blocks, num_blocks) }) else {
        return ptr::null_mut();
    };
    let ctx_ref = unsafe { &*ctx };

    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(blocks.as_slice(), ctx_ref.arch.as_ref()) {
            Some(f) => f,
            None => return ptr::null_mut(),
        };
    let policy = match current_taint_policy() {
        Some(policy) => policy,
        None => return ptr::null_mut(),
    };
    let sources = collect_taint_sources(&ssa_func, &policy);

    let mut sinks = Vec::new();
    for block in ssa_func.blocks() {
        for (op_idx, op) in block.ops.iter().enumerate() {
            if policy.is_sink(op, block.addr) {
                sinks.push(TaintSinkJson {
                    block: block.addr,
                    block_hex: format!("0x{:x}", block.addr),
                    op_idx,
                    op: ssa_op_to_info(op),
                });
            }
        }
    }

    let analysis = r2ssa::TaintAnalysis::with_arch(&ssa_func, policy, ctx_ref.arch.as_ref());
    let result = analysis.analyze();

    let mut tainted_vars = Vec::new();
    for (name, labels) in result.var_taints.iter() {
        if labels.is_empty() {
            continue;
        }
        tainted_vars.push(TaintedVarJson {
            var: name.clone(),
            labels: labels_to_strings(labels),
        });
    }
    tainted_vars.sort_by(|a, b| a.var.cmp(&b.var));

    let report = TaintReportJson {
        sources,
        sinks,
        sink_hits: collect_taint_sink_hits(&result),
        tainted_vars,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Run taint analysis and return post-analysis summary JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_function_summary_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let Some(blocks) = (unsafe { BlockSlice::from_ffi(blocks, num_blocks) }) else {
        return ptr::null_mut();
    };
    let ctx_ref = unsafe { &*ctx };

    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(blocks.as_slice(), ctx_ref.arch.as_ref()) {
            Some(f) => f,
            None => return ptr::null_mut(),
        };
    let policy = match current_taint_policy() {
        Some(policy) => policy,
        None => return ptr::null_mut(),
    };
    let sources = collect_taint_sources(&ssa_func, &policy);
    let analysis = r2ssa::TaintAnalysis::with_arch(&ssa_func, policy, ctx_ref.arch.as_ref());
    let result = analysis.analyze();
    let report = TaintSummaryReportJson {
        sources,
        sink_hits: collect_taint_sink_hits(&result),
    };

    match serde_json::to_string(&report) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}
