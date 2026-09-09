//! r2dec - Decompiler for r2sleigh.
//!
//! This crate provides decompilation capabilities for the r2sleigh project,
//! converting SSA form to readable C code.
//!
//! ## Overview
//!
//! The decompilation pipeline consists of:
//!
//! 1. **AST** (`ast`): C Abstract Syntax Tree representation
//! 2. **Expression Building** (`expr`): Convert SSA operations to C expressions
//! 3. **Region Identification** (`region`): Identify control flow regions
//! 4. **Control Flow Structuring** (`structure`): Convert CFG to structured code
//! 5. **Type Facts** (`r2types`): Consume inferred type/layout facts
//! 6. **Binding Planning** (`binding_plan`): Project exact SSA identities into C bindings
//! 7. **Code Generation** (`codegen`): Generate readable C source code
//!
//! ## Usage
//!
//! ```ignore
//! use r2dec::{Decompiler, DecompilerConfig, DecompilerInput};
//!
//! let input: DecompilerInput = /* built by r2engine from source-owned FunctionFacts */;
//! let config = DecompilerConfig::default();
//! let decompiler = Decompiler::new(config);
//! let c_code = decompiler.decompile_input(&input);
//! println!("{}", c_code);
//! ```

pub(crate) mod analysis;
pub mod ast;
mod binding_plan;
pub(crate) mod codegen;
pub(crate) mod consumer_structured;
pub mod control;
mod effect_ledger;
pub(crate) mod fold;
pub mod highlight;
pub(crate) mod normalize;
mod observation_journal;
mod placement;
pub(crate) mod planner;
pub mod region;
mod shadow_report;
pub(crate) mod single_evaluation;
pub(crate) mod stage_timing;
pub mod structure;
mod structured_region;
pub mod symbol;
pub(crate) mod unrendered;
mod variable;

use crate::codegen::{CodeGenerator, EmissionReadyFunction, prepare_function_for_emission};
use crate::fold::FoldingContext;
use crate::fold::context::{FoldArchConfig, FoldInputs};
use crate::observation_journal::{
    LegacyObservationCoverage, LegacyObservationJournal, MarkedNativeDraft, SealedNativeFunction,
};
pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::CodeGenConfig;
pub use control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
pub use fold::lower_ssa_ops_to_stmts;
pub use highlight::highlight_c_ansi;
use r2ssa::SSAFunction;
#[cfg(test)]
use r2ssa::SSAOp;
use r2ssa::cfg::BlockTerminator;
#[cfg(test)]
use r2types::{ExternalTypeDb, FunctionType};
use r2types::{FunctionFacts, FunctionTypeFacts};
pub use region::{Region, RegionAnalyzer};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::rc::Rc;
#[cfg(test)]
use std::sync::Arc;
pub(crate) use structure::ControlFlowStructurer;

#[cfg(test)]
pub(crate) fn certified_memory_result_name(access: r2ssa::StructuredAccessId) -> String {
    format!("memory_value_{}_{}", access.inst.0, access.ordinal)
}

pub(crate) fn sanitize_comment_text(text: &str) -> String {
    let flattened = text.replace("*/", "* /").replace(['\r', '\n'], " ");
    sanitize_comment_raw_tokens(&sanitize_comment_debug_ids(&flattened))
}

fn sanitize_comment_debug_ids(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        let rest = &text[index..];
        let replacement = if rest.starts_with("ValueId(") {
            Some("value")
        } else if rest.starts_with("ObjectId(") {
            Some("object")
        } else {
            None
        };
        if let Some(replacement) = replacement {
            out.push_str(replacement);
            if let Some(end) = rest.find(')') {
                index += end + 1;
            } else {
                break;
            }
            continue;
        }
        let ch = rest.chars().next().expect("valid char boundary");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn sanitize_comment_raw_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush_token = |out: &mut String, token: &mut String| {
        if token.is_empty() {
            return;
        }
        if let Some(replacement) = sanitized_comment_token(token) {
            out.push_str(replacement);
        } else {
            out.push_str(token);
        }
        token.clear();
    };

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            token.push(ch);
        } else {
            flush_token(&mut out, &mut token);
            out.push(ch);
        }
    }
    flush_token(&mut out, &mut token);
    out
}

fn sanitized_comment_token(token: &str) -> Option<&'static str> {
    let lower = token.to_ascii_lowercase();
    if matches!(lower.as_str(), "fake_stack_slot" | "saved_fp") {
        return Some("stack slot");
    }
    if is_ssa_versioned_register_label(token) {
        return Some("register");
    }
    if lower.starts_with("tmp:") || lower.starts_with("ram:") {
        return Some("temporary");
    }
    for prefix in ["stack_", "slot_", "local_", "arg_", "var_"] {
        if let Some(suffix) = lower.strip_prefix(prefix)
            && raw_stack_suffix_label(suffix)
        {
            return Some("stack slot");
        }
    }
    if let Some(rest) = lower.strip_prefix('t')
        && rest.len() >= 3
        && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Some("temporary");
    }
    None
}

fn raw_stack_suffix_label(suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    let suffix = suffix.strip_suffix('h').unwrap_or(suffix);
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_ssa_versioned_register_label(name: &str) -> bool {
    let Some((base, suffix)) = name.rsplit_once('_') else {
        return false;
    };
    let upper_ssa_label = !base.is_empty()
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
        && base.bytes().any(|byte| byte.is_ascii_alphabetic())
        && base
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    upper_ssa_label || is_known_lowercase_register_version_label(base, suffix)
}

fn is_known_lowercase_register_version_label(base: &str, suffix: &str) -> bool {
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let lower = base.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "rax"
            | "eax"
            | "ax"
            | "al"
            | "ah"
            | "rbx"
            | "ebx"
            | "bx"
            | "bl"
            | "bh"
            | "rcx"
            | "ecx"
            | "cx"
            | "cl"
            | "ch"
            | "rdx"
            | "edx"
            | "dx"
            | "dl"
            | "dh"
            | "rsi"
            | "esi"
            | "si"
            | "sil"
            | "rdi"
            | "edi"
            | "di"
            | "dil"
            | "rbp"
            | "ebp"
            | "bp"
            | "bpl"
            | "rsp"
            | "esp"
            | "sp"
            | "spl"
            | "rip"
            | "eip"
            | "pc"
            | "x0"
            | "w0"
            | "x1"
            | "w1"
            | "x2"
            | "w2"
            | "x3"
            | "w3"
            | "r0"
            | "r1"
            | "r2"
            | "r3"
            | "a0"
            | "a1"
            | "v0"
            | "v1"
    ) || x86_extended_register_label(&lower)
}

fn x86_extended_register_label(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix('r') else {
        return false;
    };
    let digit_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_len == 0 {
        return false;
    }
    let (digits, suffix) = rest.split_at(digit_len);
    digits
        .parse::<u8>()
        .ok()
        .is_some_and(|index| (8..=15).contains(&index))
        && matches!(suffix, "" | "b" | "w" | "d")
}

#[cfg(test)]
pub(crate) fn is_autogenerated_function_name(name: &str) -> bool {
    r2source::display_names::is_generated_function_name(name)
}

pub fn block_guard_fallback_comment(func_name: &str, blocks: usize, max_blocks: usize) -> String {
    planner::block_guard_fallback_comment(func_name, blocks, max_blocks)
}

pub fn artifact_guard_fallback_comment(func_name: &str, reason: &str) -> String {
    planner::artifact_guard_fallback_comment(func_name, reason)
}

/// Count the residual markers the structurer left in a rendered body.
///
/// The structurer already refuses per construct: an unresolved branch, loop,
/// switch selector or case value becomes a `r2dec residual:` comment where that
/// construct would have been. Counting them is a reading of the body, not a
/// second opinion about what was proven.
fn count_residual_markers(stmts: &[CStmt]) -> usize {
    fn walk(stmts: &[CStmt], found: &mut usize) {
        for stmt in stmts {
            walk_one(stmt, found);
        }
    }
    fn walk_one(stmt: &CStmt, found: &mut usize) {
        match stmt.unobserved() {
            CStmt::Comment(text) => {
                if text.contains("r2dec residual:") {
                    *found += 1;
                }
            }
            CStmt::Block(body) => walk(body, found),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                walk_one(then_body, found);
                if let Some(else_body) = else_body {
                    walk_one(else_body, found);
                }
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => walk_one(body, found),
            CStmt::For { init, body, .. } => {
                if let Some(init) = init {
                    walk_one(init, found);
                }
                walk_one(body, found);
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    walk(&case.body, found);
                }
                if let Some(default) = default {
                    walk(default, found);
                }
            }
            _ => {}
        }
    }
    let mut found = 0;
    walk(stmts, &mut found);
    found
}

/// State what the rendering did and did not show.
///
/// "Nothing was marked" and "everything was shown to be right" are different
/// claims, and only the second earns silence. Nothing here makes the second, so
/// the note is always emitted: it reports how many constructs carry a residual
/// marker, and then reports the ledger, which says what became of every effect
/// the source obliges.
///
/// The ledger's columns sum to its total, so an effect that went missing is a
/// number in the line rather than an absence from it. An unaccounted count is
/// never zero because nothing went wrong; it is zero only when every obligation
/// was reached by a rule that named its fate.
fn note_unproven_constructs(
    func: &mut CFunction,
    ledger: Option<&r2ssa::ledger::ObligationLedger>,
    radare2_variadic_format_counts: usize,
    radare2_local_names: usize,
) {
    let rendered_nothing = func.body.is_empty();
    let residuals = count_residual_markers(&func.body);
    let detail = if rendered_nothing {
        "rendering produced no statements".to_string()
    } else {
        match residuals {
            0 => "no individual construct is marked".to_string(),
            1 => "1 construct is marked below".to_string(),
            n => format!("{n} constructs are marked below"),
        }
    };
    let mut detail = match ledger.map(r2ssa::ledger::ObligationLedger::close) {
        Some(closure) if closure.total > 0 => {
            let mut line = format!(
                "{detail}; {} source obligations: {} rendered, {} elided, {} refused",
                closure.total, closure.rendered, closure.elided, closure.refused
            );
            // A gapped function is rendered, not proven. The count says how
            // many obligations a marked gap accounts for, so the proof line
            // never reads as clean when part of the body went unproven.
            if closure.gapped > 0 {
                let _ = write!(&mut line, ", {} gapped", closure.gapped);
            }
            // The column that used to have no name. Saying nothing here is what let a
            // gutted body report as clean, so it is spelled out whenever it is not zero.
            if closure.unattributed > 0 {
                let _ = write!(&mut line, ", {} unaccounted", closure.unattributed);
            }
            if closure.conflicts > 0 {
                let _ = write!(&mut line, ", {} conflicting", closure.conflicts);
            }
            let _ = write!(
                &mut line,
                "; {} statements rendered",
                count_body_statements(&func.body)
            );
            line
        }
        _ => detail,
    };
    let radare_typed_objects =
        func.extern_objects
            .iter()
            .filter(|object| {
                object.type_fact.as_ref().is_some_and(|fact| {
                    fact.provenance == r2types::DataObjectTypeProvenance::Radare2
                })
            })
            .count();
    let refused_object_types = func
        .extern_objects
        .iter()
        .filter(|object| object.type_fact.is_none() && object.type_refusal.is_some())
        .count();
    if radare_typed_objects > 0 {
        let noun = if radare_typed_objects == 1 {
            "data object type"
        } else {
            "data object types"
        };
        let _ = write!(
            &mut detail,
            "; {radare_typed_objects} {noun} supplied by radare2"
        );
    }
    if refused_object_types > 0 {
        let noun = if refused_object_types == 1 {
            "data object type"
        } else {
            "data object types"
        };
        let _ = write!(&mut detail, "; {refused_object_types} {noun} refused");
    }
    if radare2_variadic_format_counts > 0 {
        let noun = if radare2_variadic_format_counts == 1 {
            "variadic callsite argument count"
        } else {
            "variadic callsite argument counts"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_variadic_format_counts} {noun} supplied by radare2 format literals"
        );
    }
    if radare2_local_names > 0 {
        let noun = if radare2_local_names == 1 {
            "local name"
        } else {
            "local names"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_local_names} {noun} supplied by radare2"
        );
    }
    func.body.insert(
        0,
        CStmt::comment(sanitize_comment_text(&format!("r2dec proof: {detail}"))),
    );
}

/// Statements the body holds, counting the ones nested inside control flow.
fn count_body_statements(stmts: &[CStmt]) -> usize {
    fn visit(stmt: &CStmt) -> usize {
        match stmt.unobserved() {
            // A gap marks a cell that was not rendered; it is not one of
            // the statements the proof line counts as body.
            CStmt::Comment(_) | CStmt::Empty | CStmt::Gap(_) => 0,
            CStmt::Block(inner) => inner.iter().map(visit).sum(),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => 1 + visit(then_body) + else_body.as_deref().map(visit).unwrap_or(0),
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => 1 + visit(body),
            CStmt::For { init, body, .. } => {
                1 + init.as_deref().map(visit).unwrap_or(0) + visit(body)
            }
            CStmt::Switch { cases, default, .. } => {
                1 + cases
                    .iter()
                    .map(|case| case.body.iter().map(visit).sum::<usize>())
                    .sum::<usize>()
                    + default
                        .as_ref()
                        .map(|body| body.iter().map(visit).sum::<usize>())
                        .unwrap_or(0)
            }
            _ => 1,
        }
    }
    stmts.iter().map(visit).sum()
}

/// Whether a run was asked to report what the rendering left unaccounted for.
pub(crate) fn unowned_report_requested() -> bool {
    static REQUESTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *REQUESTED.get_or_init(|| std::env::var_os("R2SLEIGH_DEBUG_UNOWNED").is_some())
}

/// Write the whole ledger out on request, so a count has somewhere to look.
///
/// The rendered note says how many obligations landed in each column, which tells
/// a reader that a function is short without saying short of what. This names the
/// kinds left undecided, the reasons given for eliding, and the layer behind every
/// refusal, which is what turns those numbers into a place to start.
/// Print the backward slice of the seed `R2SLEIGH_SLICE` names, if it is set.
///
/// The question every trace ends at is where a value came from; this answers it
/// in one run instead of a rebuild per layer.
fn debug_log_slice(prepared: &r2ssa::SsaArtifact) {
    let Some(seed) = std::env::var_os("R2SLEIGH_SLICE") else {
        return;
    };
    let Some(seed) = seed.to_str() else {
        return;
    };
    match r2ssa::resolve_slice_seed(prepared, seed) {
        Ok(seed) => eprintln!("{}", r2ssa::backward_slice(prepared, seed)),
        Err(error) => eprintln!("r2sleigh: slice seed {seed:?}: {error}"),
    }
}

fn debug_log_ledger(prepared: &r2ssa::SsaArtifact, ledger: &r2ssa::ledger::ObligationLedger) {
    if !unowned_report_requested() {
        return;
    }
    let closure = ledger.close();
    // Largest first, and by name where two entries tie, so the report reads the
    // same way twice over the same binary.
    fn ranked<K: std::fmt::Display>(counts: std::collections::BTreeMap<K, usize>) -> String {
        let mut entries = counts.into_iter().collect::<Vec<_>>();
        entries.sort_by(|(left_key, left), (right_key, right)| {
            right
                .cmp(left)
                .then_with(|| left_key.to_string().cmp(&right_key.to_string()))
        });
        entries
            .into_iter()
            .map(|(key, count)| format!("{key}={count}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
    let refusals = ranked(
        ledger
            .refusals_by_layer()
            .into_iter()
            .map(|((layer, reason), count)| (format!("{layer}/{reason}"), count))
            .collect(),
    );
    let refused_ids = ledger
        .entries()
        .filter_map(|(id, outcome)| match outcome {
            r2ssa::ledger::Outcome::Refused { layer, reason } => {
                Some(format!("{id}={layer}/{reason}"))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    let message = format!(
        "LEDGER fn={:#x} total={} rendered={} elided={} refused={} unaccounted={} conflicts={} | unaccounted-kinds: {} | elided: {} | refused: {} | refused-ids: {}",
        prepared.function().entry,
        closure.total,
        closure.rendered,
        closure.elided,
        closure.refused,
        closure.unattributed,
        closure.conflicts,
        ranked(ledger.unattributed_by_kind()),
        ranked(ledger.elisions_by_reason()),
        refusals,
        refused_ids,
    );
    let path = std::env::var("R2SLEIGH_DEBUG_UNOWNED_LOG")
        .unwrap_or_else(|_| "/tmp/r2sleigh_unowned.log".to_string());
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{message}");
    }
}

fn debug_log_render_contract_error(
    prepared: &r2ssa::SsaArtifact,
    stage: &str,
    error: &impl std::fmt::Debug,
) {
    if !unowned_report_requested() {
        return;
    }
    let path = std::env::var("R2SLEIGH_DEBUG_UNOWNED_LOG")
        .unwrap_or_else(|_| "/tmp/r2sleigh_unowned.log".to_string());
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(
            file,
            "RENDER_CONTRACT fn={:#x} stage={stage} error={error:?}",
            prepared.function().entry
        );
    }
}

/// Why the source obligation inventory cannot account for this function, if it cannot.
fn incomplete_source_obligations_reason(prepared: &r2ssa::SsaArtifact) -> Option<String> {
    let obligations = prepared.obligations();
    if obligations.is_complete() {
        return None;
    }
    let failures = obligations.construction_failures().len();
    let cycles = obligations.unstructured_cycle_blocks().len();
    Some(format!(
        "r2dec refusal: the source obligation inventory did not close, so what this function owes was never enumerated ({failures} construction failures, {cycles} unstructured cycle blocks)"
    ))
}

/// The name this rendering gives the function.
///
/// A source name is arbitrary bytes: a radare2 flag, an ELF symbol, a DWARF
/// string. Spelling one straight into the output makes the whole rendering
/// invalid C when the name is not an identifier, and a name carrying `*/` or a
/// newline escapes whatever comment or declaration holds it. The name is
/// therefore sanitized once, here, and a name of which nothing survives falls
/// back to the address form -- the same answer an unnamed function gets.
pub(crate) fn rendered_function_name(func: &SSAFunction) -> String {
    func.name
        .as_deref()
        .and_then(r2types::sanitize_c_identifier)
        .unwrap_or_else(|| format!("sub_{:x}", func.entry))
}

fn residual_function_for_render_boundary(func_name: &str, reason: &str) -> CFunction {
    let mut func = CFunction::new(func_name.to_string(), CType::Unknown).with_unknown_params();
    func.body = vec![CStmt::comment(sanitize_comment_text(reason))];
    func
}

pub fn normalize_sig_arch_name(arch: Option<&r2il::ArchSpec>) -> Option<String> {
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

/// Decompiler configuration.
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// Code generation configuration.
    pub codegen: CodeGenConfig,
    /// Pointer size in bits.
    pub ptr_size: u32,
    /// Stack pointer register name.
    pub sp_name: String,
    /// Frame pointer register name.
    pub fp_name: String,
    /// Ordered argument registers for the active ABI.
    pub arg_regs: Vec<String>,
    /// Return-value registers for the active ABI.
    pub ret_regs: Vec<String>,
    /// Caller-saved registers for the active ABI.
    pub caller_saved_regs: HashSet<String>,
    /// Soft cap for function blocks before forcing fallback.
    pub max_blocks: usize,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            codegen: CodeGenConfig::default(),
            ptr_size: 64,
            sp_name: "rsp".to_string(),
            fp_name: "rbp".to_string(),
            arg_regs: vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ],
            ret_regs: vec![
                "rax".to_string(),
                "eax".to_string(),
                "xmm0".to_string(),
                "xmm0_qa".to_string(),
                "xmm0_qb".to_string(),
                "st0".to_string(),
            ],
            caller_saved_regs: ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            max_blocks: 200,
        }
    }
}

impl DecompilerConfig {
    pub fn for_arch_name(arch_name: &str, ptr_bits: u32) -> Self {
        match (arch_name, ptr_bits) {
            ("x86", 32) | ("x86-32", _) => Self::x86(),
            ("x86-64", _) | ("x86_64", _) | ("x64", _) | ("amd64", _) => Self::x86_64(),
            ("arm", _) | ("ARM", _) if ptr_bits == 32 => Self::arm(),
            ("aarch64", _) | ("arm64", _) | ("ARM64", _) => Self::aarch64(),
            ("riscv32", _) | ("rv32", _) | ("rv32gc", _) => Self::riscv32(),
            ("riscv64", _) | ("rv64", _) | ("rv64gc", _) => Self::riscv64(),
            ("riscv", _) if ptr_bits == 32 => Self::riscv32(),
            ("riscv", _) => Self::riscv64(),
            _ => Self::unrecognized(ptr_bits),
        }
    }

    /// A target whose registers this renderer does not know.
    ///
    /// Falling back to the defaults meant falling back to x86-64: an
    /// unrecognized target was rendered with rsp, rbp and the SysV argument
    /// registers, naming registers it does not have. Naming none of them is
    /// the honest answer, and it leaves the residual machinery to say so.
    fn unrecognized(ptr_bits: u32) -> Self {
        Self {
            ptr_size: ptr_bits,
            sp_name: String::new(),
            fp_name: String::new(),
            arg_regs: Vec::new(),
            ret_regs: Vec::new(),
            caller_saved_regs: Default::default(),
            ..Self::default()
        }
    }

    pub fn for_arch(arch: Option<&r2il::ArchSpec>) -> (String, u32, Self) {
        let arch_name = normalize_sig_arch_name(arch).unwrap_or_else(|| "unknown".to_string());
        let ptr_bits = arch.map(|spec| spec.addr_size * 8).unwrap_or(64);
        let config = Self::for_arch_name(&arch_name, ptr_bits);
        (arch_name, ptr_bits, config)
    }

    /// Create a configuration for 32-bit x86.
    pub fn x86() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "esp".to_string(),
            fp_name: "ebp".to_string(),
            arg_regs: vec![],
            ret_regs: vec!["eax".to_string(), "xmm0".to_string(), "st0".to_string()],
            caller_saved_regs: ["eax", "ecx", "edx"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for 64-bit x86.
    pub fn x86_64() -> Self {
        Self::default()
    }

    /// Create a configuration for ARM.
    pub fn arm() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "sp".to_string(),
            fp_name: "fp".to_string(),
            arg_regs: ["r0", "r1", "r2", "r3"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["r0".to_string()],
            caller_saved_regs: ["r0", "r1", "r2", "r3", "r12", "lr", "ip"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for AArch64.
    pub fn aarch64() -> Self {
        Self {
            ptr_size: 64,
            sp_name: "sp".to_string(),
            fp_name: "x29".to_string(),
            arg_regs: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["x0".to_string(), "w0".to_string()],
            caller_saved_regs: [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for RISC-V RV32.
    pub fn riscv32() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "sp".to_string(),
            fp_name: "s0".to_string(),
            arg_regs: ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["a0".to_string()],
            caller_saved_regs: [
                "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for RISC-V RV64.
    pub fn riscv64() -> Self {
        Self {
            ptr_size: 64,
            sp_name: "sp".to_string(),
            fp_name: "s0".to_string(),
            arg_regs: ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["a0".to_string()],
            caller_saved_regs: [
                "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DecompilerContext {
    #[cfg(test)]
    pub function_names: std::collections::HashMap<u64, String>,
    #[cfg(test)]
    pub symbols: std::collections::HashMap<u64, String>,
    /// Canonical combined type and semantic facts.
    function_facts: FunctionFacts,
}

impl DecompilerContext {
    fn type_facts(&self) -> &FunctionTypeFacts {
        self.function_facts.type_facts()
    }

    fn from_source_owned(
        function_facts: &r2types::function_facts::SourceOwnedFunctionFacts,
    ) -> Self {
        Self {
            #[cfg(test)]
            function_names: std::collections::HashMap::new(),
            #[cfg(test)]
            symbols: std::collections::HashMap::new(),
            function_facts: function_facts.report().clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecompilerInput {
    source_owned_facts: r2types::function_facts::SourceOwnedFunctionFacts,
}

impl DecompilerInput {
    pub fn new(source_owned_facts: r2types::function_facts::SourceOwnedFunctionFacts) -> Self {
        Self { source_owned_facts }
    }

    pub fn source_owned_facts(&self) -> &r2types::function_facts::SourceOwnedFunctionFacts {
        &self.source_owned_facts
    }

    pub fn prepared_ssa(&self) -> &r2ssa::SsaArtifact {
        self.source_owned_facts.source()
    }

    pub fn function_facts(&self) -> &FunctionFacts {
        self.source_owned_facts.report()
    }

    fn context_projection(&self) -> DecompilerContext {
        DecompilerContext::from_source_owned(&self.source_owned_facts)
    }
}

#[derive(Debug)]
enum BindingShadowFailure {
    Pairing,
    Report,
    IncompleteObservations {
        ledger: crate::shadow_report::ShadowLedger,
        coverage: LegacyObservationCoverage,
    },
    NonQuality {
        ledger: crate::shadow_report::ShadowLedger,
        coverage: LegacyObservationCoverage,
    },
}

#[derive(Debug)]
struct BindingShadow {
    ledger: crate::shadow_report::ShadowLedger,
    coverage: LegacyObservationCoverage,
}

#[derive(Debug)]
enum BindingShadowOutcome {
    Complete(BindingShadow),
    Failed(BindingShadowFailure),
}

impl BindingShadowOutcome {
    fn build(
        plan: &crate::binding_plan::BindingPlan,
        source: &r2types::function_facts::SourceOwnedFunctionFacts,
        legacy: &crate::shadow_report::LegacyAnalysisSnapshot,
        coverage: LegacyObservationCoverage,
    ) -> Self {
        if crate::fold::op_lower::PlannedLoweringInput::try_new(source, plan).is_err() {
            return Self::Failed(BindingShadowFailure::Pairing);
        }
        let report = match crate::shadow_report::ShadowReport::build(plan, source, legacy) {
            Ok(report) => report,
            Err(_) => return Self::Failed(BindingShadowFailure::Report),
        };
        if report.validate_against(plan, source, legacy).is_err() {
            return Self::Failed(BindingShadowFailure::Report);
        }
        let ledger = report.ledger(source);
        if !coverage.is_complete() {
            return Self::Failed(BindingShadowFailure::IncompleteObservations { ledger, coverage });
        }
        if !ledger.passes_quality() || !coverage.passes_quality() {
            return Self::Failed(BindingShadowFailure::NonQuality { ledger, coverage });
        }
        Self::Complete(BindingShadow { ledger, coverage })
    }
}

/// Public, renderer-independent counts for one binding-shadow domain.
///
/// These are audit results, not rendering inputs. Keeping the complete ledger
/// visible prevents a refusal or an unclassified cell from being counted as a
/// successful shadow run merely because no C was emitted for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingShadowDomainAudit {
    pub total: usize,
    pub observed: usize,
    pub agree_correct: usize,
    pub old_wrong: usize,
    pub shadow_wrong: usize,
    pub both_wrong_equal: usize,
    pub both_wrong_different: usize,
    pub unclassified: usize,
    pub refused: usize,
    /// Cells a marked gap accounts for: neither account claimed them, and the
    /// output says so where they stand.
    pub gapped: usize,
}

impl BindingShadowDomainAudit {
    pub const fn equations_hold(self) -> bool {
        let Some(both_wrong) = self.both_wrong_equal.checked_add(self.both_wrong_different) else {
            return false;
        };
        let Some(classified) = self.agree_correct.checked_add(self.old_wrong) else {
            return false;
        };
        let Some(classified) = classified.checked_add(self.shadow_wrong) else {
            return false;
        };
        let Some(classified) = classified.checked_add(both_wrong) else {
            return false;
        };
        let Some(classified) = classified.checked_add(self.gapped) else {
            return false;
        };
        let Some(accounted) = classified.checked_add(self.unclassified) else {
            return false;
        };
        self.total == self.observed && self.observed == accounted
    }

    /// Quality admits a marked gap and refuses everything else that is not
    /// proven. A gap is an accounted cell whose absence the output states; a
    /// caller that needs a fully proven body reads `is_fully_proven`.
    pub const fn passes_quality(self) -> bool {
        self.equations_hold()
            && self.shadow_wrong == 0
            && self.both_wrong_equal == 0
            && self.both_wrong_different == 0
            && self.unclassified == 0
            && self.refused == 0
    }

    pub const fn is_fully_proven(self) -> bool {
        self.passes_quality() && self.gapped == 0
    }
}

impl From<crate::shadow_report::DomainLedger> for BindingShadowDomainAudit {
    fn from(ledger: crate::shadow_report::DomainLedger) -> Self {
        Self {
            total: ledger.total,
            observed: ledger.observed,
            agree_correct: ledger.agree_correct,
            old_wrong: ledger.old_wrong,
            shadow_wrong: ledger.shadow_wrong,
            both_wrong_equal: ledger.both_wrong_equal,
            both_wrong_different: ledger.both_wrong_different,
            unclassified: ledger.unclassified,
            refused: ledger.refused,
            gapped: ledger.gapped,
        }
    }
}

/// Public count of exact legacy-render observations for one source domain.
///
/// This is deliberately separate from the shadow classification ledger. A
/// dense shadow report can classify `LegacyAbsent` as an old-renderer defect;
/// only this equation proves that the renderer actually accounted for every
/// source value, use, and write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingObservationDomainAudit {
    pub total: usize,
    pub rendered: usize,
    pub justified_elision: usize,
    pub refused: usize,
    /// Cells a marked gap accounts for, which are admitted and not proven.
    pub gapped: usize,
    pub unaccounted: usize,
}

impl BindingObservationDomainAudit {
    pub const fn equations_hold(self) -> bool {
        let Some(accounted) = self.rendered.checked_add(self.justified_elision) else {
            return false;
        };
        let Some(accounted) = accounted.checked_add(self.refused) else {
            return false;
        };
        let Some(accounted) = accounted.checked_add(self.gapped) else {
            return false;
        };
        let Some(accounted) = accounted.checked_add(self.unaccounted) else {
            return false;
        };
        accounted == self.total
    }

    pub const fn is_complete(self) -> bool {
        self.equations_hold() && self.unaccounted == 0
    }

    pub const fn passes_quality(self) -> bool {
        self.is_complete() && self.refused == 0
    }

    pub const fn is_fully_proven(self) -> bool {
        self.passes_quality() && self.gapped == 0
    }
}

impl From<crate::observation_journal::LegacyObservationDomainCoverage>
    for BindingObservationDomainAudit
{
    fn from(coverage: crate::observation_journal::LegacyObservationDomainCoverage) -> Self {
        Self {
            total: coverage.total,
            rendered: coverage.rendered,
            justified_elision: coverage.justified_elision,
            refused: coverage.refused,
            gapped: coverage.gapped,
            unaccounted: coverage.unaccounted,
        }
    }
}

/// Exact V/U/W observation coverage, independent of shadow correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingObservationAudit {
    pub values: BindingObservationDomainAudit,
    pub uses: BindingObservationDomainAudit,
    pub writes: BindingObservationDomainAudit,
}

impl BindingObservationAudit {
    pub const fn equations_hold(self) -> bool {
        self.values.equations_hold() && self.uses.equations_hold() && self.writes.equations_hold()
    }

    pub const fn is_complete(self) -> bool {
        self.values.is_complete() && self.uses.is_complete() && self.writes.is_complete()
    }

    pub const fn passes_quality(self) -> bool {
        self.values.passes_quality() && self.uses.passes_quality() && self.writes.passes_quality()
    }
}

impl From<LegacyObservationCoverage> for BindingObservationAudit {
    fn from(coverage: LegacyObservationCoverage) -> Self {
        Self {
            values: coverage.values.into(),
            uses: coverage.uses.into(),
            writes: coverage.writes.into(),
        }
    }
}

/// Observable Stage 4 ledger, kept separate from all renderer inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingShadowAuditLedger {
    pub values: BindingShadowDomainAudit,
    pub uses: BindingShadowDomainAudit,
    pub writes: BindingShadowDomainAudit,
}

impl BindingShadowAuditLedger {
    pub const fn equations_hold(self) -> bool {
        self.values.equations_hold() && self.uses.equations_hold() && self.writes.equations_hold()
    }

    pub const fn passes_quality(self) -> bool {
        self.values.passes_quality() && self.uses.passes_quality() && self.writes.passes_quality()
    }
}

impl From<crate::shadow_report::ShadowLedger> for BindingShadowAuditLedger {
    fn from(ledger: crate::shadow_report::ShadowLedger) -> Self {
        Self {
            values: ledger.values.into(),
            uses: ledger.uses.into(),
            writes: ledger.writes.into(),
        }
    }
}

/// Stable public cause retained when the observation journal cannot be built or sealed.
///
/// The journal's implementation error type remains private because it also
/// carries renderer-only contracts.  This projection preserves every error
/// category and the canonical IDs or counts that are safe to expose across the
/// `r2dec`/`r2engine` boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMachineProjectionFailure {
    UntrustedArtifactProvenance,
    IncompleteObligationInventory,
    MissingGraphValue {
        value: r2ssa::ValueId,
    },
    MissingGraphBlock {
        block: r2ssa::BlockId,
    },
    DuplicateBlockAddress {
        address: u64,
    },
    TopologyMismatch,
    MachineContextMismatch,
    MissingInstruction {
        inst: r2ssa::InstId,
    },
    MissingInstructionDisposition {
        inst: r2ssa::InstId,
    },
    MissingUseDisposition {
        site: r2ssa::UseSite,
    },
    MissingWriteDisposition {
        inst: r2ssa::InstId,
    },
    MissingOutput {
        inst: r2ssa::InstId,
    },
    InvalidValueWidth {
        value: r2ssa::ValueId,
        size_bytes: u32,
    },
    ConstantTooWide {
        value: r2ssa::ValueId,
        width_bits: u32,
    },
    WrongOperandCount {
        inst: r2ssa::InstId,
        expected: usize,
        actual: usize,
    },
    WidthMismatch {
        inst: r2ssa::InstId,
        expected_bits: u32,
        actual_bits: u32,
    },
    InvalidCastWidth {
        inst: r2ssa::InstId,
        kind: r2ssa::MachineCastKind,
        from_bits: u32,
        to_bits: u32,
    },
    InvalidSubpiece {
        inst: r2ssa::InstId,
        source_bits: u32,
        result_bits: u32,
        lsb_bits: u32,
    },
    InvalidChild {
        expr_index: usize,
        child_index: usize,
    },
    InvalidExpressionType {
        expr_index: usize,
    },
    DuplicateEntity {
        value: r2ssa::ValueId,
    },
    EntityMismatch {
        inst: r2ssa::InstId,
    },
    ObligationMismatch {
        inst: r2ssa::InstId,
    },
    UseDispositionMismatch {
        site: r2ssa::UseSite,
    },
    WriteDispositionMismatch {
        inst: r2ssa::InstId,
    },
    ObligationSourceMismatch {
        instruction: r2ssa::CanonicalInstructionId,
    },
    UnsupportedOperation {
        inst: r2ssa::InstId,
    },
}

impl BindingMachineProjectionFailure {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::UntrustedArtifactProvenance => {
                "binding_plan_machine_untrusted_artifact_provenance"
            }
            Self::IncompleteObligationInventory => {
                "binding_plan_machine_incomplete_obligation_inventory"
            }
            Self::MissingGraphValue { .. } => "binding_plan_machine_missing_graph_value",
            Self::MissingGraphBlock { .. } => "binding_plan_machine_missing_graph_block",
            Self::DuplicateBlockAddress { .. } => "binding_plan_machine_duplicate_block_address",
            Self::TopologyMismatch => "binding_plan_machine_topology_mismatch",
            Self::MachineContextMismatch => "binding_plan_machine_context_mismatch",
            Self::MissingInstruction { .. } => "binding_plan_machine_missing_instruction",
            Self::MissingInstructionDisposition { .. } => {
                "binding_plan_machine_missing_instruction_disposition"
            }
            Self::MissingUseDisposition { .. } => "binding_plan_machine_missing_use_disposition",
            Self::MissingWriteDisposition { .. } => {
                "binding_plan_machine_missing_write_disposition"
            }
            Self::MissingOutput { .. } => "binding_plan_machine_missing_output",
            Self::InvalidValueWidth { .. } => "binding_plan_machine_invalid_value_width",
            Self::ConstantTooWide { .. } => "binding_plan_machine_constant_too_wide",
            Self::WrongOperandCount { .. } => "binding_plan_machine_wrong_operand_count",
            Self::WidthMismatch { .. } => "binding_plan_machine_width_mismatch",
            Self::InvalidCastWidth { kind, .. } => match kind {
                r2ssa::MachineCastKind::ZeroExtend => {
                    "binding_plan_machine_invalid_zero_extend_width"
                }
                r2ssa::MachineCastKind::SignExtend => {
                    "binding_plan_machine_invalid_sign_extend_width"
                }
                r2ssa::MachineCastKind::Truncate => "binding_plan_machine_invalid_truncate_width",
                r2ssa::MachineCastKind::BitReinterpret => {
                    "binding_plan_machine_invalid_bit_reinterpret_width"
                }
                r2ssa::MachineCastKind::IntegerToAddress => {
                    "binding_plan_machine_invalid_integer_to_address_width"
                }
                r2ssa::MachineCastKind::AddressToInteger => {
                    "binding_plan_machine_invalid_address_to_integer_width"
                }
            },
            Self::InvalidSubpiece { .. } => "binding_plan_machine_invalid_subpiece",
            Self::InvalidChild { .. } => "binding_plan_machine_invalid_child",
            Self::InvalidExpressionType { .. } => "binding_plan_machine_invalid_expression_type",
            Self::DuplicateEntity { .. } => "binding_plan_machine_duplicate_entity",
            Self::EntityMismatch { .. } => "binding_plan_machine_entity_mismatch",
            Self::ObligationMismatch { .. } => "binding_plan_machine_obligation_mismatch",
            Self::UseDispositionMismatch { .. } => "binding_plan_machine_use_disposition_mismatch",
            Self::WriteDispositionMismatch { .. } => {
                "binding_plan_machine_write_disposition_mismatch"
            }
            Self::ObligationSourceMismatch { instruction } => match instruction.site {
                r2ssa::CanonicalInstructionSite::Phi(storage) => match storage.space {
                    r2ssa::CanonicalStorageSpace::Ram => {
                        "binding_plan_machine_obligation_source_mismatch_phi_ram"
                    }
                    r2ssa::CanonicalStorageSpace::Register => {
                        "binding_plan_machine_obligation_source_mismatch_phi_register"
                    }
                    r2ssa::CanonicalStorageSpace::Unique => {
                        "binding_plan_machine_obligation_source_mismatch_phi_unique"
                    }
                    r2ssa::CanonicalStorageSpace::Constant => {
                        "binding_plan_machine_obligation_source_mismatch_phi_constant"
                    }
                    r2ssa::CanonicalStorageSpace::Custom(_) => {
                        "binding_plan_machine_obligation_source_mismatch_phi_custom"
                    }
                    r2ssa::CanonicalStorageSpace::Unknown => {
                        "binding_plan_machine_obligation_source_mismatch_phi_unknown"
                    }
                },
                r2ssa::CanonicalInstructionSite::Op(_) => {
                    "binding_plan_machine_obligation_source_mismatch_op"
                }
                r2ssa::CanonicalInstructionSite::NativeSpan { .. } => {
                    "binding_plan_machine_obligation_source_mismatch_native_span"
                }
            },
            Self::UnsupportedOperation { .. } => "binding_plan_machine_unsupported_operation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingObservationJournalFailure {
    SourceAuthority,
    BindingPlanAuthority,
    BindingPlanMachineProjection(BindingMachineProjectionFailure),
    BindingPlanValueTopology {
        index: usize,
        value: r2ssa::ValueId,
    },
    BindingPlanDispositionCount {
        expected: usize,
        actual: usize,
    },
    BindingPlanBindingCount {
        expected: usize,
        actual: usize,
    },
    BindingPlanInvalidBindingReference {
        value: r2ssa::ValueId,
        binding_index: usize,
    },
    BindingPlanCertificateMembership {
        binding_index: usize,
    },
    BindingPlanDeclarationWidth {
        binding_index: usize,
    },
    BindingPlanInvalidLiteralInline {
        value: r2ssa::ValueId,
    },
    BindingPlanInvalidElisionProof {
        value: r2ssa::ValueId,
    },
    BindingPlanUnexpectedValueDisposition {
        value: r2ssa::ValueId,
    },
    BindingPlanStackObjectCount {
        expected: usize,
        actual: usize,
    },
    BindingPlanUnexpectedStackObjectDisposition {
        object: r2ssa::ObjectId,
    },
    BindingPlanStackObjectCertificate {
        object: r2ssa::ObjectId,
        binding_index: usize,
    },
    BindingPlanStackObjectDeclarationWidth {
        object: r2ssa::ObjectId,
        binding_index: usize,
    },
    BindingPlanParameterCount {
        expected: usize,
        actual: usize,
    },
    BindingPlanUnexpectedParameterDisposition {
        slot: u32,
    },
    BindingPlanParameterCertificate {
        slot: u32,
        binding_index: usize,
    },
    BindingPlanParameterDeclarationWidth {
        slot: u32,
        binding_index: usize,
    },
    NormalizationSourceAuthority,
    NormalizationBlockTopology,
    NormalizationRowCount {
        block_address: u64,
    },
    NormalizationOriginalInstruction {
        block_address: u64,
        op_idx: usize,
    },
    NormalizationOriginalCoverage,
    NormalizationPhiEdge {
        block_address: u64,
        op_idx: usize,
    },
    NormalizationRelocatedInitializer {
        block_address: u64,
        op_idx: usize,
    },
    NormalizationRemovedPhi,
    NormalizationRemovedPhiEdge,
    NormalizationInvalidCarrierCertificates,
    TooManyObservations,
    InvalidValue {
        value: r2ssa::ValueId,
    },
    InvalidCertifiedValueRead {
        value: r2ssa::ValueId,
        at: r2ssa::InstId,
    },
    InvalidUse {
        site: r2ssa::UseSite,
    },
    InvalidWrite {
        inst: r2ssa::InstId,
    },
    InvalidEffectObligation {
        obligation: r2ssa::SemanticObligationId,
    },
    OutputlessWrite {
        inst: r2ssa::InstId,
    },
    InvalidNormalizedSite {
        block: r2ssa::BlockId,
        op_idx: usize,
    },
    MissingNormalizedBlock {
        address: u64,
    },
    MissingNormalizedSiteContext,
    InvalidNormalizedInput {
        block: r2ssa::BlockId,
        op_idx: usize,
        input_idx: usize,
    },
    MissingNormalizedOutput {
        block: r2ssa::BlockId,
        op_idx: usize,
    },
    RefusedRenderedUse {
        site: r2ssa::UseSite,
    },
    RefusedRenderedWrite {
        inst: r2ssa::InstId,
    },
    RenderedValueRequired {
        value: r2ssa::ValueId,
    },
    PlannedElidedValueRendered {
        value: r2ssa::ValueId,
    },
    PlannedRefusedValueRendered {
        value: r2ssa::ValueId,
    },
    MissingPlannedValue {
        value: r2ssa::ValueId,
    },
    InvalidPlannedInline {
        value: r2ssa::ValueId,
        term_index: usize,
    },
    ExactUseRequiresRenderedOccurrence {
        site: r2ssa::UseSite,
    },
    ExactWriteRequiresRenderedOccurrence {
        inst: r2ssa::InstId,
    },
    SymbolTableMismatch,
    UnownedBindingSymbol {
        value: r2ssa::ValueId,
        symbol_index: usize,
    },
    ConflictingValue {
        value: r2ssa::ValueId,
    },
    ConflictingUse {
        site: r2ssa::UseSite,
    },
    ConflictingWrite {
        inst: r2ssa::InstId,
    },
    ObservationDomainTooLarge {
        expected_count: usize,
    },
    ObservationCapacityUnavailable {
        expected_count: usize,
    },
    ObservationOutOfRange {
        observation_id: u32,
        expected_count: usize,
    },
    DuplicateObservation {
        observation_id: u32,
    },
}

impl BindingObservationJournalFailure {
    /// Stable machine-readable category used by the plugin JSON boundary.
    pub const fn kind(self) -> &'static str {
        match self {
            Self::SourceAuthority => "source_authority",
            Self::BindingPlanAuthority => "binding_plan_authority",
            Self::BindingPlanMachineProjection(failure) => failure.kind(),
            Self::BindingPlanValueTopology { .. } => "binding_plan_value_topology",
            Self::BindingPlanDispositionCount { .. } => "binding_plan_disposition_count",
            Self::BindingPlanBindingCount { .. } => "binding_plan_binding_count",
            Self::BindingPlanInvalidBindingReference { .. } => {
                "binding_plan_invalid_binding_reference"
            }
            Self::BindingPlanCertificateMembership { .. } => "binding_plan_certificate_membership",
            Self::BindingPlanDeclarationWidth { .. } => "binding_plan_declaration_width",
            Self::BindingPlanInvalidLiteralInline { .. } => "binding_plan_invalid_literal_inline",
            Self::BindingPlanInvalidElisionProof { .. } => "binding_plan_invalid_elision_proof",
            Self::BindingPlanUnexpectedValueDisposition { .. } => {
                "binding_plan_unexpected_value_disposition"
            }
            Self::BindingPlanStackObjectCount { .. } => "binding_plan_stack_object_count",
            Self::BindingPlanUnexpectedStackObjectDisposition { .. } => {
                "binding_plan_unexpected_stack_object_disposition"
            }
            Self::BindingPlanStackObjectCertificate { .. } => {
                "binding_plan_stack_object_certificate"
            }
            Self::BindingPlanStackObjectDeclarationWidth { .. } => {
                "binding_plan_stack_object_declaration_width"
            }
            Self::BindingPlanParameterCount { .. } => "binding_plan_parameter_count",
            Self::BindingPlanUnexpectedParameterDisposition { .. } => {
                "binding_plan_unexpected_parameter_disposition"
            }
            Self::BindingPlanParameterCertificate { .. } => "binding_plan_parameter_certificate",
            Self::BindingPlanParameterDeclarationWidth { .. } => {
                "binding_plan_parameter_declaration_width"
            }
            Self::NormalizationSourceAuthority => "normalization_source_authority",
            Self::NormalizationBlockTopology => "normalization_block_topology",
            Self::NormalizationRowCount { .. } => "normalization_row_count",
            Self::NormalizationOriginalInstruction { .. } => "normalization_original_instruction",
            Self::NormalizationOriginalCoverage => "normalization_original_coverage",
            Self::NormalizationPhiEdge { .. } => "normalization_phi_edge",
            Self::NormalizationRelocatedInitializer { .. } => "normalization_relocated_initializer",
            Self::NormalizationRemovedPhi => "normalization_removed_phi",
            Self::NormalizationRemovedPhiEdge => "normalization_removed_phi_edge",
            Self::NormalizationInvalidCarrierCertificates => {
                "normalization_invalid_carrier_certificates"
            }
            Self::TooManyObservations => "too_many_observations",
            Self::InvalidValue { .. } => "invalid_value",
            Self::InvalidCertifiedValueRead { .. } => "invalid_certified_value_read",
            Self::InvalidUse { .. } => "invalid_use",
            Self::InvalidWrite { .. } => "invalid_write",
            Self::InvalidEffectObligation { .. } => "invalid_effect_obligation",
            Self::OutputlessWrite { .. } => "outputless_write",
            Self::InvalidNormalizedSite { .. } => "invalid_normalized_site",
            Self::MissingNormalizedBlock { .. } => "missing_normalized_block",
            Self::MissingNormalizedSiteContext => "missing_normalized_site_context",
            Self::InvalidNormalizedInput { .. } => "invalid_normalized_input",
            Self::MissingNormalizedOutput { .. } => "missing_normalized_output",
            Self::RefusedRenderedUse { .. } => "refused_rendered_use",
            Self::RefusedRenderedWrite { .. } => "refused_rendered_write",
            Self::RenderedValueRequired { .. } => "rendered_value_required",
            Self::PlannedElidedValueRendered { .. } => "planned_elided_value_rendered",
            Self::PlannedRefusedValueRendered { .. } => "planned_refused_value_rendered",
            Self::MissingPlannedValue { .. } => "missing_planned_value",
            Self::InvalidPlannedInline { .. } => "invalid_planned_inline",
            Self::ExactUseRequiresRenderedOccurrence { .. } => {
                "exact_use_requires_rendered_occurrence"
            }
            Self::ExactWriteRequiresRenderedOccurrence { .. } => {
                "exact_write_requires_rendered_occurrence"
            }
            Self::SymbolTableMismatch => "symbol_table_mismatch",
            Self::UnownedBindingSymbol { .. } => "unowned_binding_symbol",
            Self::ConflictingValue { .. } => "conflicting_value",
            Self::ConflictingUse { .. } => "conflicting_use",
            Self::ConflictingWrite { .. } => "conflicting_write",
            Self::ObservationDomainTooLarge { .. } => "observation_domain_too_large",
            Self::ObservationCapacityUnavailable { .. } => "observation_capacity_unavailable",
            Self::ObservationOutOfRange { .. } => "observation_out_of_range",
            Self::DuplicateObservation { .. } => "duplicate_observation",
        }
    }
}

/// Typed reason a production binding-shadow audit did not complete cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingShadowAuditFailure {
    PlanBuild,
    SourcePairing,
    JournalConstruction(BindingObservationJournalFailure),
    JournalRecording(BindingObservationJournalFailure),
    JournalSeal(BindingObservationJournalFailure),
    Placement(PlacementAuditRefusal),
    NonQualityObservations {
        observations: BindingObservationAudit,
    },
    Report,
    IncompleteObservations {
        ledger: BindingShadowAuditLedger,
        observations: BindingObservationAudit,
    },
    NonQuality {
        ledger: BindingShadowAuditLedger,
        observations: BindingObservationAudit,
    },
}

/// The instruction a native render failure names, when it names a cell.
///
/// A failure that reaches a value, a use or a write reaches the instruction
/// that defines or performs it, and that is what a marked gap anchors to.
fn gap_anchor_for_native_failure(
    failure: &BindingShadowAuditFailure,
    prepared: &r2ssa::SsaArtifact,
) -> Option<r2ssa::InstId> {
    use BindingObservationJournalFailure as Journal;
    let journal = match failure {
        BindingShadowAuditFailure::JournalConstruction(journal)
        | BindingShadowAuditFailure::JournalRecording(journal)
        | BindingShadowAuditFailure::JournalSeal(journal) => journal,
        _ => return None,
    };
    let graph = prepared.graph();
    match journal {
        Journal::RenderedValueRequired { value }
        | Journal::PlannedElidedValueRendered { value }
        | Journal::PlannedRefusedValueRendered { value }
        | Journal::MissingPlannedValue { value }
        | Journal::ConflictingValue { value }
        | Journal::InvalidPlannedInline { value, .. }
        | Journal::UnownedBindingSymbol { value, .. } => graph.def_inst(*value),
        Journal::InvalidCertifiedValueRead { at, .. } => Some(*at),
        Journal::InvalidUse { site }
        | Journal::RefusedRenderedUse { site }
        | Journal::ExactUseRequiresRenderedOccurrence { site }
        | Journal::ConflictingUse { site } => Some(site.inst),
        Journal::InvalidWrite { inst }
        | Journal::OutputlessWrite { inst }
        | Journal::RefusedRenderedWrite { inst }
        | Journal::ExactWriteRequiresRenderedOccurrence { inst }
        | Journal::ConflictingWrite { inst } => Some(*inst),
        _ => None,
    }
}

/// Non-consuming binding audit exposed to corpus and integration tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingShadowAuditOutcome {
    Complete {
        ledger: BindingShadowAuditLedger,
        observations: BindingObservationAudit,
    },
    Failed(BindingShadowAuditFailure),
    /// The selected route never entered the native Standard renderer.
    NotRun,
}

impl BindingShadowAuditOutcome {
    fn from_internal(outcome: &BindingShadowOutcome) -> Self {
        match outcome {
            BindingShadowOutcome::Complete(shadow) => Self::Complete {
                ledger: shadow.ledger.into(),
                observations: shadow.coverage.into(),
            },
            BindingShadowOutcome::Failed(BindingShadowFailure::Pairing) => {
                Self::Failed(BindingShadowAuditFailure::SourcePairing)
            }
            BindingShadowOutcome::Failed(BindingShadowFailure::Report) => {
                Self::Failed(BindingShadowAuditFailure::Report)
            }
            BindingShadowOutcome::Failed(BindingShadowFailure::IncompleteObservations {
                ledger,
                coverage,
            }) => Self::Failed(BindingShadowAuditFailure::IncompleteObservations {
                ledger: (*ledger).into(),
                observations: (*coverage).into(),
            }),
            BindingShadowOutcome::Failed(BindingShadowFailure::NonQuality { ledger, coverage }) => {
                Self::Failed(BindingShadowAuditFailure::NonQuality {
                    ledger: (*ledger).into(),
                    observations: (*coverage).into(),
                })
            }
        }
    }
}

/// Whether the final emission tree satisfied the source effect inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectObligationDisposition {
    Admitted,
    /// Admitted with marked gaps: every obligation is accounted, and the ones
    /// a gap covers were not discharged. The body is rendered, not proven.
    Gapped,
    Refused,
    /// The selected route never entered the native Standard renderer.
    NotRun,
}

/// Stable source-effect tuple exposed independently of binding quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectObligationAudit {
    pub disposition: EffectObligationDisposition,
    pub total: usize,
    pub rendered: usize,
    pub justified_elision: usize,
    pub refused: usize,
    /// Obligations a marked gap accounts for.
    pub gapped: usize,
    pub unaccounted: usize,
    pub conflicts: usize,
    /// First refused obligation in canonical source order, for diagnostics.
    pub refused_obligation: Option<r2ssa::SemanticObligationId>,
    /// First obligation with no occurrence or certificate, for diagnostics.
    pub unaccounted_obligation: Option<r2ssa::SemanticObligationId>,
    /// First obligation with incompatible occurrences, for diagnostics.
    pub conflicting_obligation: Option<r2ssa::SemanticObligationId>,
}

impl EffectObligationAudit {
    pub const NOT_RUN: Self = Self {
        disposition: EffectObligationDisposition::NotRun,
        total: 0,
        rendered: 0,
        justified_elision: 0,
        refused: 0,
        gapped: 0,
        unaccounted: 0,
        conflicts: 0,
        refused_obligation: None,
        unaccounted_obligation: None,
        conflicting_obligation: None,
    };

    fn from_ledger(ledger: &r2ssa::ledger::ObligationLedger) -> Self {
        let closure = ledger.close();
        let admitted = closure.refused == 0
            && closure.unattributed == 0
            && closure.conflicts == 0
            && closure.is_closed();
        Self {
            disposition: match (admitted, closure.gapped) {
                (true, 0) => EffectObligationDisposition::Admitted,
                (true, _) => EffectObligationDisposition::Gapped,
                (false, _) => EffectObligationDisposition::Refused,
            },
            total: closure.total,
            rendered: closure.rendered,
            justified_elision: closure.elided,
            refused: closure.refused,
            gapped: closure.gapped,
            unaccounted: closure.unattributed,
            conflicts: closure.conflicts,
            refused_obligation: ledger.entries().find_map(|(id, outcome)| {
                matches!(outcome, r2ssa::ledger::Outcome::Refused { .. }).then_some(*id)
            }),
            unaccounted_obligation: ledger.unattributed().next().copied(),
            conflicting_obligation: ledger.conflicts().next().map(|(id, _)| *id),
        }
    }

    /// Whether the body may be emitted: every obligation is accounted for,
    /// with the ones a gap covers marked in the output rather than dropped.
    pub const fn is_admitted(self) -> bool {
        matches!(
            self.disposition,
            EffectObligationDisposition::Admitted | EffectObligationDisposition::Gapped
        )
    }

    /// Whether every obligation was discharged or proven unnecessary.
    pub const fn is_fully_proven(self) -> bool {
        matches!(self.disposition, EffectObligationDisposition::Admitted)
    }
}

/// Stable reason the final native declaration-placement pass refused C.
///
/// Payloads contain only deterministic dense identities and counts. Private
/// renderer errors are projected into this type before crossing the r2dec API
/// boundary; their debug representations are never part of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementAuditRefusal {
    MissingStructuredRegionArtifact,
    ObservationJournalUnavailable,
    SourceAuthorityMismatch,
    BindingOutsidePlan {
        binding_index: usize,
    },
    RegionOutsideArtifact {
        region_index: usize,
    },
    BlockOutsideFunction {
        block_address: u64,
    },
    RegionDoesNotDominateOccurrence {
        region_index: usize,
        block_address: u64,
    },
    ExternalBindingOutsidePlan {
        binding_index: usize,
    },
    RegionMarkerUnsealed,
    RegionMarkerForeign {
        anchor_index: usize,
    },
    RegionMarkerDuplicate {
        region_index: usize,
    },
    RegionMarkerMissing {
        region_index: usize,
    },
    RegionMarkerParentMismatch {
        region_index: usize,
    },
    RegionMarkerOutOfOrder {
        region_index: usize,
        expected_region_index: usize,
    },
    ObservationDomainTooLarge {
        expected_count: usize,
    },
    ObservationCapacityUnavailable {
        expected_count: usize,
    },
    ObservationOutOfRange {
        observation_id: u32,
        expected_count: usize,
    },
    DuplicateObservation {
        observation_id: u32,
    },
    MissingObservationTarget {
        observation_id: u32,
    },
    InvalidUse {
        instruction_id: u32,
        input_index: usize,
    },
    InvalidWrite {
        instruction_id: u32,
    },
    InvalidCertifiedValueRead {
        value_id: u32,
        instruction_id: u32,
    },
    MissingPlannedValue {
        value_id: u32,
    },
    RefusedPlannedValue {
        value_id: u32,
    },
    UnscopedObservation {
        observation_id: u32,
    },
    UnauthorizedProgramVariable {
        symbol_index: usize,
    },
    UnobservedBindingRead {
        binding_index: usize,
    },
    UnobservedBindingWrite {
        binding_index: usize,
    },
    NoDominatingRegion {
        binding_index: usize,
    },
    MissingDefinition {
        binding_index: usize,
    },
    ReadBeforeAssignment {
        binding_index: usize,
        instruction_id: u32,
        input_index: usize,
    },
    CertifiedValueReadBeforeAssignment {
        binding_index: usize,
        value_id: u32,
        instruction_id: u32,
    },
    StackAccessReadBeforeAssignment {
        binding_index: usize,
        instruction_id: u32,
        access_ordinal: u32,
    },
    PreservedCarrierReadBeforeAssignment {
        binding_index: usize,
        instruction_id: u32,
    },
    UnprovableExecutionOrder {
        binding_index: usize,
    },
    AmbiguousObservationExecutionOrder {
        observation_id: u32,
    },
    MissingBinding {
        binding_index: usize,
    },
    MissingBindingSymbol {
        binding_index: usize,
    },
    ExternalBindingMissingParameter {
        binding_index: usize,
    },
    MissingRegion {
        region_index: usize,
    },
    DuplicateRegion {
        region_index: usize,
    },
    MissingInlineWrite {
        instruction_id: u32,
    },
    DuplicateInlineWrite {
        instruction_id: u32,
    },
    MissingBindingRole {
        binding_index: usize,
    },
    UndeclaredNames {
        count: usize,
    },
}

impl PlacementAuditRefusal {
    /// Stable machine-readable category used by engine and plugin boundaries.
    pub const fn kind(self) -> &'static str {
        match self {
            Self::MissingStructuredRegionArtifact => "missing_structured_region_artifact",
            Self::ObservationJournalUnavailable => "observation_journal_unavailable",
            Self::SourceAuthorityMismatch => "source_authority_mismatch",
            Self::BindingOutsidePlan { .. } => "binding_outside_plan",
            Self::RegionOutsideArtifact { .. } => "region_outside_artifact",
            Self::BlockOutsideFunction { .. } => "block_outside_function",
            Self::RegionDoesNotDominateOccurrence { .. } => "region_does_not_dominate_occurrence",
            Self::ExternalBindingOutsidePlan { .. } => "external_binding_outside_plan",
            Self::RegionMarkerUnsealed => "region_marker_unsealed",
            Self::RegionMarkerForeign { .. } => "region_marker_foreign",
            Self::RegionMarkerDuplicate { .. } => "region_marker_duplicate",
            Self::RegionMarkerMissing { .. } => "region_marker_missing",
            Self::RegionMarkerParentMismatch { .. } => "region_marker_parent_mismatch",
            Self::RegionMarkerOutOfOrder { .. } => "region_marker_out_of_order",
            Self::ObservationDomainTooLarge { .. } => "observation_domain_too_large",
            Self::ObservationCapacityUnavailable { .. } => "observation_capacity_unavailable",
            Self::ObservationOutOfRange { .. } => "observation_out_of_range",
            Self::DuplicateObservation { .. } => "duplicate_observation",
            Self::MissingObservationTarget { .. } => "missing_observation_target",
            Self::InvalidUse { .. } => "invalid_use",
            Self::InvalidWrite { .. } => "invalid_write",
            Self::InvalidCertifiedValueRead { .. } => "invalid_certified_value_read",
            Self::MissingPlannedValue { .. } => "missing_planned_value",
            Self::RefusedPlannedValue { .. } => "refused_planned_value",
            Self::UnscopedObservation { .. } => "unscoped_observation",
            Self::UnauthorizedProgramVariable { .. } => "unauthorized_program_variable",
            Self::UnobservedBindingRead { .. } => "unobserved_binding_read",
            Self::UnobservedBindingWrite { .. } => "unobserved_binding_write",
            Self::NoDominatingRegion { .. } => "no_dominating_region",
            Self::MissingDefinition { .. } => "missing_definition",
            Self::ReadBeforeAssignment { .. } => "read_before_assignment",
            Self::CertifiedValueReadBeforeAssignment { .. } => {
                "certified_value_read_before_assignment"
            }
            Self::StackAccessReadBeforeAssignment { .. } => "stack_access_read_before_assignment",
            Self::PreservedCarrierReadBeforeAssignment { .. } => {
                "preserved_carrier_read_before_assignment"
            }
            Self::UnprovableExecutionOrder { .. } => "unprovable_execution_order",
            Self::AmbiguousObservationExecutionOrder { .. } => {
                "ambiguous_observation_execution_order"
            }
            Self::MissingBinding { .. } => "missing_binding",
            Self::MissingBindingSymbol { .. } => "missing_binding_symbol",
            Self::ExternalBindingMissingParameter { .. } => "external_binding_missing_parameter",
            Self::MissingRegion { .. } => "missing_region",
            Self::DuplicateRegion { .. } => "duplicate_region",
            Self::MissingInlineWrite { .. } => "missing_inline_write",
            Self::DuplicateInlineWrite { .. } => "duplicate_inline_write",
            Self::MissingBindingRole { .. } => "missing_binding_role",
            Self::UndeclaredNames { .. } => "undeclared_names",
        }
    }
}

/// Independent final-tree declaration-placement audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementAudit {
    Applied,
    Refused(PlacementAuditRefusal),
    /// The selected route never entered native declaration placement.
    NotRun,
}

impl PlacementAudit {
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Which upstream authority failed when a machine projection was refused.
///
/// Every one of these used to become the same payload-free
/// `MissingMachineProjectionAuthorization`, so twelve refusing functions on
/// `/bin/ls` reported one cause between them and could not be told apart. The
/// upstream error already knows which authority it was; this carries that the
/// last step to the reader.
#[derive(Clone, Copy, Eq)]
pub enum MachineProjectionRefusalOrigin {
    ShadowAuditPlanBuild,
    ShadowAuditSourcePairing,
    ShadowAuditReport,
    ShadowAuditIncompleteObservations,
    ShadowAuditNonQuality,
    /// One of the lowering predicates declined, named by its site.
    ///
    /// Every lowering refusal in the pipeline arrived here as one word, and on
    /// `/bin/ls` that word covered two unrelated causes -- an incomplete return
    /// boundary and a call whose arguments could not be spelled -- reported as
    /// a single count of seven. The site the witness carries is free and says
    /// which.
    OpLowering(&'static std::panic::Location<'static>),
    RenderedIdentityMachineUse,
    RenderedIdentityMachineWrite,
    RenderedIdentityMissingUseDisposition,
    RenderedIdentityMissingWriteDisposition,
    RenderedIdentityMissingLiteralProjection,
    RenderedIdentityUnmodelledUserOperation,
    RenderedIdentityIncoherentUseProjection,
    RenderedIdentityIncoherentWriteProjection,
    BindingPlanBuild,
    PlannedLoweringInput,
}

impl MachineProjectionRefusalOrigin {
    /// An op-lowering refusal decided here.
    ///
    /// Production builds these from the lowering witness, which took the line
    /// from `#[track_caller]`. A caller that only means "the lowering authority
    /// declined" -- a test asserting the cause, say -- uses this and gets its
    /// own line, which equality ignores.
    #[track_caller]
    #[must_use]
    pub fn op_lowering() -> Self {
        Self::OpLowering(std::panic::Location::caller())
    }
}

/// The cause, and the site only where the cause alone does not identify it.
impl std::fmt::Debug for MachineProjectionRefusalOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShadowAuditPlanBuild => f.write_str("ShadowAuditPlanBuild"),
            Self::ShadowAuditSourcePairing => f.write_str("ShadowAuditSourcePairing"),
            Self::ShadowAuditReport => f.write_str("ShadowAuditReport"),
            Self::ShadowAuditIncompleteObservations => {
                f.write_str("ShadowAuditIncompleteObservations")
            }
            Self::ShadowAuditNonQuality => f.write_str("ShadowAuditNonQuality"),
            Self::OpLowering(site) => {
                let file = site.file();
                let base = file.rsplit('/').next().unwrap_or(file);
                write!(f, "OpLowering({base}:{})", site.line())
            }
            Self::RenderedIdentityMachineUse => f.write_str("RenderedIdentityMachineUse"),
            Self::RenderedIdentityMachineWrite => f.write_str("RenderedIdentityMachineWrite"),
            Self::RenderedIdentityMissingUseDisposition => {
                f.write_str("RenderedIdentityMissingUseDisposition")
            }
            Self::RenderedIdentityMissingWriteDisposition => {
                f.write_str("RenderedIdentityMissingWriteDisposition")
            }
            Self::RenderedIdentityMissingLiteralProjection => {
                f.write_str("RenderedIdentityMissingLiteralProjection")
            }
            Self::RenderedIdentityUnmodelledUserOperation => {
                f.write_str("RenderedIdentityUnmodelledUserOperation")
            }
            Self::RenderedIdentityIncoherentUseProjection => {
                f.write_str("RenderedIdentityIncoherentUseProjection")
            }
            Self::RenderedIdentityIncoherentWriteProjection => {
                f.write_str("RenderedIdentityIncoherentWriteProjection")
            }
            Self::BindingPlanBuild => f.write_str("BindingPlanBuild"),
            Self::PlannedLoweringInput => f.write_str("PlannedLoweringInput"),
        }
    }
}

/// Two refusals from the same authority are the same refusal.
///
/// `OpLowering` carries the line that decided it so a reader can open the
/// predicate, but a refusal's identity is the authority that failed, not which
/// of its predicates got there first. Comparing the line would make every
/// equality assertion in the tree brittle against moving one, and would split a
/// gate's baseline on a refactor that changed no behaviour.
impl PartialEq for MachineProjectionRefusalOrigin {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl std::hash::Hash for MachineProjectionRefusalOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

/// Rendered C paired with the non-consuming Stage 4 binding audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompileRenderRefusal {
    MissingMachineProjectionAuthorization(MachineProjectionRefusalOrigin),
    MissingProgramVariableAuthorization,
    VariadicCallsiteArgumentCount(r2ssa::VariadicCallsiteArgumentCountRefusal),
    /// The legacy observation journal could not be constructed.
    ///
    /// The journal already computes a precise typed cause. Reporting this as a
    /// missing machine-projection authorization named a different authority
    /// than the one that actually failed, so the corpus attributed every such
    /// cell to the projection seam and the real cause was never counted.
    ObservationJournal(BindingObservationJournalFailure),
    DeclarationPlacement(PlacementAuditRefusal),
    RefusedBindingDisposition {
        observations: BindingObservationAudit,
    },
    NormalizationOriginUnavailable,
    UnrepresentableControlFlow,
    IncompleteEffectInventory,
    UnrepresentableOperation,
}

impl DecompileRenderRefusal {
    /// Stable machine-readable category used by engine and corpus boundaries.
    pub const fn kind(self) -> &'static str {
        match self {
            Self::MissingMachineProjectionAuthorization(_) => {
                "missing_machine_projection_authorization"
            }
            Self::MissingProgramVariableAuthorization => "missing_program_variable_authorization",
            Self::VariadicCallsiteArgumentCount(_) => "variadic_callsite_argument_count",
            Self::ObservationJournal(failure) => failure.kind(),
            Self::DeclarationPlacement(refusal) => refusal.kind(),
            Self::RefusedBindingDisposition { .. } => "refused_binding_disposition",
            Self::NormalizationOriginUnavailable => "normalization_origin_unavailable",
            Self::UnrepresentableControlFlow => "unrepresentable_control_flow",
            Self::IncompleteEffectInventory => "incomplete_effect_inventory",
            Self::UnrepresentableOperation => "unrepresentable_operation",
        }
    }
}

// The refusal is `Copy` and callers compare it, so its observation audit is
// carried by value rather than boxed; the gap column pushed that audit just
// past the lint's threshold.
#[allow(clippy::result_large_err)]
fn validate_sealed_region_occurrence_counts(
    occurrences: usize,
    region_nodes: usize,
) -> Result<(), DecompileRenderRefusal> {
    if occurrences == region_nodes {
        Ok(())
    } else {
        Err(DecompileRenderRefusal::UnrepresentableControlFlow)
    }
}

#[allow(clippy::result_large_err)]
fn validate_sealed_region_occurrence_coverage(
    body: &crate::structured_region::SealedStructuredBody,
) -> Result<(), DecompileRenderRefusal> {
    let mut occurrences = 0usize;
    body.visit_occurrences(|_| occurrences += 1);
    validate_sealed_region_occurrence_counts(occurrences, body.regions().nodes().len())
}

impl From<BindingShadowAuditFailure> for DecompileRenderRefusal {
    fn from(failure: BindingShadowAuditFailure) -> Self {
        match failure {
            BindingShadowAuditFailure::Placement(refusal) => Self::DeclarationPlacement(refusal),
            BindingShadowAuditFailure::NonQualityObservations { observations } => {
                Self::RefusedBindingDisposition { observations }
            }
            // Each journal failure already carries the exact obligation that
            // could not be sealed. Collapsing them into a machine-projection
            // refusal named an authority that had not failed, so every such
            // cell was attributed to the projection seam and the real cause
            // was only visible in the separate shadow-audit record.
            BindingShadowAuditFailure::JournalConstruction(failure)
            | BindingShadowAuditFailure::JournalRecording(failure)
            | BindingShadowAuditFailure::JournalSeal(failure) => Self::ObservationJournal(failure),
            BindingShadowAuditFailure::PlanBuild => Self::MissingMachineProjectionAuthorization(
                MachineProjectionRefusalOrigin::ShadowAuditPlanBuild,
            ),
            BindingShadowAuditFailure::SourcePairing => {
                Self::MissingMachineProjectionAuthorization(
                    MachineProjectionRefusalOrigin::ShadowAuditSourcePairing,
                )
            }
            BindingShadowAuditFailure::Report => Self::MissingMachineProjectionAuthorization(
                MachineProjectionRefusalOrigin::ShadowAuditReport,
            ),
            BindingShadowAuditFailure::IncompleteObservations { .. } => {
                Self::MissingMachineProjectionAuthorization(
                    MachineProjectionRefusalOrigin::ShadowAuditIncompleteObservations,
                )
            }
            BindingShadowAuditFailure::NonQuality { .. } => {
                Self::MissingMachineProjectionAuthorization(
                    MachineProjectionRefusalOrigin::ShadowAuditNonQuality,
                )
            }
        }
    }
}

impl From<crate::fold::op_lower::OpLoweringRefusal> for DecompileRenderRefusal {
    fn from(refusal: crate::fold::op_lower::OpLoweringRefusal) -> Self {
        match refusal {
            crate::fold::op_lower::OpLoweringRefusal::MissingMachineProjectionAuthorization(
                origin,
            ) => Self::MissingMachineProjectionAuthorization(
                MachineProjectionRefusalOrigin::OpLowering(origin.site()),
            ),
            crate::fold::op_lower::OpLoweringRefusal::MissingProgramVariableAuthorization(..) => {
                Self::MissingProgramVariableAuthorization
            }
            crate::fold::op_lower::OpLoweringRefusal::UnrepresentableOperation(..) => {
                Self::UnrepresentableOperation
            }
            crate::fold::op_lower::OpLoweringRefusal::VariadicCallsiteArgumentCount(refusal) => {
                Self::VariadicCallsiteArgumentCount(refusal)
            }
        }
    }
}

fn rendered_identity_refusal_category(
    refusal: crate::binding_plan::RenderedIdentityRefusal,
) -> DecompileRenderRefusal {
    use crate::binding_plan::{RenderedIdentityRefusal, ValueRefusal};

    use MachineProjectionRefusalOrigin as Origin;

    match refusal {
        RenderedIdentityRefusal::MachineUse { .. } => {
            DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                Origin::RenderedIdentityMachineUse,
            )
        }
        RenderedIdentityRefusal::MachineWrite { .. } => {
            DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                Origin::RenderedIdentityMachineWrite,
            )
        }
        RenderedIdentityRefusal::MissingUseDisposition { .. } => {
            DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                Origin::RenderedIdentityMissingUseDisposition,
            )
        }
        RenderedIdentityRefusal::MissingWriteDisposition { .. } => {
            DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                Origin::RenderedIdentityMissingWriteDisposition,
            )
        }
        RenderedIdentityRefusal::Value {
            reason: ValueRefusal::MissingLiteralProjection { .. },
            ..
        } => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
            Origin::RenderedIdentityMissingLiteralProjection,
        ),
        RenderedIdentityRefusal::Value {
            reason: ValueRefusal::UnmodelledUserOperation { .. },
            ..
        } => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
            Origin::RenderedIdentityUnmodelledUserOperation,
        ),
        RenderedIdentityRefusal::Value {
            reason: ValueRefusal::IncoherentUseProjection { .. },
            ..
        } => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
            Origin::RenderedIdentityIncoherentUseProjection,
        ),
        RenderedIdentityRefusal::Value {
            reason: ValueRefusal::IncoherentWriteProjection { .. },
            ..
        } => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
            Origin::RenderedIdentityIncoherentWriteProjection,
        ),
        RenderedIdentityRefusal::Value {
            reason:
                ValueRefusal::MissingBindingCertificate { .. }
                | ValueRefusal::UnsupportedDeclarationWidth { .. },
            ..
        }
        | RenderedIdentityRefusal::Parameter { .. }
        | RenderedIdentityRefusal::StackObject { .. }
        | RenderedIdentityRefusal::StackObjectElided { .. }
        | RenderedIdentityRefusal::MissingBinding { .. }
        | RenderedIdentityRefusal::MissingValueDisposition { .. }
        | RenderedIdentityRefusal::MissingParameterDisposition { .. }
        | RenderedIdentityRefusal::MissingStackDisposition { .. } => {
            DecompileRenderRefusal::MissingProgramVariableAuthorization
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompileBindingAudit {
    output: String,
    binding_shadow: BindingShadowAuditOutcome,
    effect_obligations: EffectObligationAudit,
    placement_audit: PlacementAudit,
    render_refusal: Option<DecompileRenderRefusal>,
}

impl DecompileBindingAudit {
    fn not_run(output: String) -> Self {
        Self {
            output,
            binding_shadow: BindingShadowAuditOutcome::NotRun,
            effect_obligations: EffectObligationAudit::NOT_RUN,
            placement_audit: PlacementAudit::NotRun,
            render_refusal: None,
        }
    }

    pub fn output(&self) -> &str {
        &self.output
    }

    pub fn into_output(self) -> String {
        self.output
    }

    pub const fn binding_shadow(&self) -> BindingShadowAuditOutcome {
        self.binding_shadow
    }

    pub const fn effect_obligations(&self) -> EffectObligationAudit {
        self.effect_obligations
    }

    pub const fn placement_audit(&self) -> PlacementAudit {
        self.placement_audit
    }

    pub const fn render_refusal(&self) -> Option<DecompileRenderRefusal> {
        self.render_refusal
    }
}

/// Rendered C whose same-run binding classification is deliberately deferred.
///
/// The engine uses this boundary to make every production cancellation and
/// deadline decision before the diagnostic shadow comparison runs. Finalizing
/// consumes the exact rendered product; dropping it emits the same C without
/// paying for or consulting the audit.
pub struct PendingDecompileBindingAudit {
    output: String,
    product: Option<(
        InternalBuildProduct,
        r2types::function_facts::SourceOwnedFunctionFacts,
    )>,
    ready: BindingShadowAuditOutcome,
    ready_effects: EffectObligationAudit,
    ready_placement: PlacementAudit,
    ready_refusal: Option<DecompileRenderRefusal>,
}

impl PendingDecompileBindingAudit {
    fn from_audit(audit: DecompileBindingAudit) -> Self {
        Self {
            output: audit.output,
            product: None,
            ready: audit.binding_shadow,
            ready_effects: audit.effect_obligations,
            ready_placement: audit.placement_audit,
            ready_refusal: audit.render_refusal,
        }
    }

    fn from_product(
        output: String,
        product: InternalBuildProduct,
        source: r2types::function_facts::SourceOwnedFunctionFacts,
    ) -> Self {
        Self {
            output,
            product: Some((product, source)),
            ready: BindingShadowAuditOutcome::NotRun,
            ready_effects: EffectObligationAudit::NOT_RUN,
            ready_placement: PlacementAudit::NotRun,
            ready_refusal: None,
        }
    }

    pub fn output(&self) -> &str {
        &self.output
    }

    pub fn into_output(self) -> String {
        self.output
    }

    pub fn finalize(self) -> DecompileBindingAudit {
        let (binding_shadow, effect_obligations, placement_audit, render_refusal) =
            self.product.map_or(
                (
                    self.ready,
                    self.ready_effects,
                    self.ready_placement,
                    self.ready_refusal,
                ),
                |(product, source)| {
                    (
                        product.binding_shadow(&source),
                        product.effect_obligations(),
                        product.placement_audit(),
                        product.render_refusal(),
                    )
                },
            );
        DecompileBindingAudit {
            output: self.output,
            binding_shadow,
            effect_obligations,
            placement_audit,
            render_refusal,
        }
    }
}

/// Private result of one source-authority-bound native build.
///
/// Native output retains the exact binding plan and final-AST observations.
/// Residual output is marker-free and carries no pretend native audit.
#[expect(
    clippy::large_enum_variant,
    reason = "all variants are request-local products; boxing native output would add allocation only to hide its typed audit payload"
)]
enum InternalBuildProduct {
    Native(SealedNativeFunction),
    Residual(EmissionReadyFunction),
    Refused {
        emission: EmissionReadyFunction,
        refusal: DecompileRenderRefusal,
        binding_shadow: BindingShadowAuditOutcome,
        placement_audit: PlacementAudit,
    },
}

#[expect(
    clippy::large_enum_variant,
    reason = "both variants are request-local decompile products; boxing either would add allocation without shrinking the dominant audit payload"
)]
enum PreparedDecompile {
    Immediate(DecompileBindingAudit),
    NativeOrResidual(InternalBuildProduct),
}

impl InternalBuildProduct {
    fn residual(function: CFunction) -> Self {
        Self::Residual(prepare_function_for_emission(&function))
    }

    fn refused(function: CFunction, refusal: DecompileRenderRefusal) -> Self {
        Self::Refused {
            emission: prepare_function_for_emission(&function),
            refusal,
            binding_shadow: BindingShadowAuditOutcome::NotRun,
            placement_audit: PlacementAudit::NotRun,
        }
    }

    fn refused_after_native_admission(
        function: CFunction,
        failure: BindingShadowAuditFailure,
    ) -> Self {
        let refusal = DecompileRenderRefusal::from(failure);
        let placement_audit = match failure {
            BindingShadowAuditFailure::Placement(refusal) => PlacementAudit::Refused(refusal),
            BindingShadowAuditFailure::NonQualityObservations { .. } => PlacementAudit::Applied,
            _ => PlacementAudit::NotRun,
        };
        Self::Refused {
            emission: prepare_function_for_emission(&function),
            refusal,
            binding_shadow: BindingShadowAuditOutcome::Failed(failure),
            placement_audit,
        }
    }

    fn emission(&self) -> &EmissionReadyFunction {
        match self {
            Self::Native(native) => native.emission(),
            Self::Residual(ready) => ready,
            Self::Refused { emission, .. } => emission,
        }
    }

    fn into_function(self) -> CFunction {
        match self {
            Self::Native(native) => native.into_function(),
            Self::Residual(ready) => ready.into_function(),
            Self::Refused { emission, .. } => emission.into_function(),
        }
    }

    fn binding_shadow(
        &self,
        source: &r2types::SourceOwnedFunctionFacts,
    ) -> BindingShadowAuditOutcome {
        let native = match self {
            Self::Native(native) => native,
            Self::Refused { binding_shadow, .. } => return *binding_shadow,
            Self::Residual(_) => return BindingShadowAuditOutcome::NotRun,
        };
        let (observations, coverage) = match native.audit_observations() {
            Ok(observations) => observations,
            Err(failure) => return BindingShadowAuditOutcome::Failed(failure),
        };
        let outcome = BindingShadowOutcome::build(native.plan(), source, observations, coverage);
        BindingShadowAuditOutcome::from_internal(&outcome)
    }

    fn effect_obligations(&self) -> EffectObligationAudit {
        match self {
            Self::Native(native) => native.effect_obligation_audit(),
            Self::Residual(_) | Self::Refused { .. } => EffectObligationAudit::NOT_RUN,
        }
    }

    fn placement_audit(&self) -> PlacementAudit {
        match self {
            Self::Native(native) => native.placement_audit(),
            Self::Refused {
                placement_audit, ..
            } => *placement_audit,
            Self::Residual(_) => PlacementAudit::NotRun,
        }
    }

    fn render_refusal(&self) -> Option<DecompileRenderRefusal> {
        match self {
            Self::Refused { refusal, .. } => Some(*refusal),
            Self::Native(_) | Self::Residual(_) => None,
        }
    }
}

/// The main decompiler.
pub struct Decompiler {
    config: DecompilerConfig,
    context: DecompilerContext,
}

impl Decompiler {
    /// Create a new decompiler with the given configuration.
    pub fn new(config: DecompilerConfig) -> Self {
        Self {
            config,
            context: DecompilerContext::default(),
        }
    }

    fn with_context(mut self, context: DecompilerContext) -> Self {
        self.context = context;
        self
    }

    /// Set external context (function names, strings, symbols).
    /// Set externally recovered known function signatures keyed by name.
    #[cfg(test)]
    pub fn set_known_function_signatures<T>(
        &mut self,
        signatures: std::collections::HashMap<String, T>,
    ) where
        T: Into<FunctionType>,
    {
        let mut type_facts = self.context.type_facts().clone();
        type_facts.known_function_signatures = signatures
            .into_iter()
            .map(|(name, sig)| (name, sig.into()))
            .collect();
        self.context.function_facts.replace_type_facts(type_facts);
    }

    /// Set externally recovered host type database.
    #[cfg(test)]
    pub fn set_external_type_db(&mut self, external_type_db: ExternalTypeDb) {
        let mut type_facts = self.context.type_facts().clone();
        type_facts.external_type_db = external_type_db;
        self.context.function_facts.replace_type_facts(type_facts);
    }

    /// Set externally recovered type facts.
    #[cfg(test)]
    pub fn set_type_facts(&mut self, type_facts: FunctionTypeFacts) {
        self.context.function_facts.replace_type_facts(type_facts);
    }

    /// Decompile a prepared function with an explicit typed context payload.
    pub fn decompile_input(&self, input: &DecompilerInput) -> String {
        let control = r2ssa::SsaExecutionControl::default();
        self.decompile_input_with_control(input, &control)
            .expect("default decompiler control never stops")
    }

    /// Decompile with cooperative cancellation/deadline polling.
    pub fn decompile_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<String, DecompileExecutionStop> {
        self.decompile_input_with_binding_audit_and_control(input, control)
            .map(DecompileBindingAudit::into_output)
    }

    /// Decompile and expose the non-consuming binding-shadow audit.
    ///
    /// The audit is constructed only after the final production poll. Its
    /// outcome therefore cannot change the C output or a cancellation/deadline
    /// decision made by the rendering path.
    pub fn decompile_input_with_binding_audit(
        &self,
        input: &DecompilerInput,
    ) -> DecompileBindingAudit {
        let control = r2ssa::SsaExecutionControl::default();
        self.decompile_input_with_binding_audit_and_control(input, &control)
            .expect("default decompiler control never stops")
    }

    fn prepare_decompile_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<PreparedDecompile, DecompileExecutionStop> {
        let work = DecompileWorkControl::new(control, DecompileWorkPhase::Normalization);
        work.poll()?;
        let func = input.prepared_ssa().function();
        let func_name = rendered_function_name(func);
        let block_count = func.blocks().count();
        if block_count > self.config.max_blocks {
            return Ok(PreparedDecompile::Immediate(
                DecompileBindingAudit::not_run(block_guard_fallback_comment(
                    &func_name,
                    block_count,
                    self.config.max_blocks,
                )),
            ));
        }
        // The semantic route used to answer here, before the native pipeline
        // was asked anything, and its prose counted as a rendered function
        // everywhere downstream: functions were reported as covered while
        // their whole body was two lines of summary. The route is advisory,
        // so it may say what native lowering could not prove; it may not
        // stand in for asking.
        self.build_product_from_input_with_control(input, control)
            .map(PreparedDecompile::NativeOrResidual)
    }

    /// Controlled form of [`Self::decompile_input_with_binding_audit`].
    pub fn decompile_input_with_binding_audit_and_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<DecompileBindingAudit, DecompileExecutionStop> {
        let product = match self.prepare_decompile_with_control(input, control)? {
            PreparedDecompile::Immediate(audit) => return Ok(audit),
            PreparedDecompile::NativeOrResidual(product) => product,
        };
        let render_work = DecompileWorkControl::new(control, DecompileWorkPhase::Rendering);
        render_work.poll()?;
        let output =
            CodeGenerator::new(self.config.codegen.clone()).generate_function(product.emission());
        // This is deliberately the last production work-control decision.
        // Everything below classifies the already sealed observation journal.
        render_work.poll()?;
        let binding_shadow = product.binding_shadow(input.source_owned_facts());
        let effect_obligations = product.effect_obligations();
        let placement_audit = product.placement_audit();
        Ok(DecompileBindingAudit {
            output,
            binding_shadow,
            effect_obligations,
            placement_audit,
            render_refusal: product.render_refusal(),
        })
    }

    /// Render, keeping whatever was produced when a phase stopped.
    ///
    /// `decompile_input_with_control` returns only the stop, so a caller has to
    /// discard the rendering to report that a budget ran out. That is why
    /// `RefusalReason::BudgetExhausted` has never been constructed: the ledger
    /// that would record it lives in the rendering being thrown away, and a
    /// function that ran out of time reports as one that produced nothing.
    ///
    /// A stop while building the C function has no partial to keep. A stop
    /// during rendering does -- the function is built by then, and generating it
    /// is what the caller wanted.
    pub fn decompile_input_keeping_partial<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<String, (DecompileExecutionStop, Option<String>)> {
        self.decompile_input_keeping_partial_with_pending_binding_audit(input, control)
            .map(PendingDecompileBindingAudit::into_output)
            .map_err(|(stop, partial)| {
                (stop, partial.map(PendingDecompileBindingAudit::into_output))
            })
    }

    /// Render with a same-run binding audit, retaining both after a rendering stop.
    ///
    /// A product-bound partial is classified from the exact product that was
    /// rendered. The audit is never rebuilt, and its construction performs no
    /// work-control poll. Stops before a product exists therefore retain no
    /// partial; either rendering poll retains the already sealed product's C and
    /// audit together.
    #[expect(
        clippy::result_large_err,
        reason = "a stopped request retains its exact same-run binding audit rather than a lossy or reconstructed diagnostic"
    )]
    pub fn decompile_input_keeping_partial_with_binding_audit<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<DecompileBindingAudit, (DecompileExecutionStop, Option<DecompileBindingAudit>)>
    {
        self.decompile_input_keeping_partial_with_pending_binding_audit(input, control)
            .map(PendingDecompileBindingAudit::finalize)
            .map_err(|(stop, partial)| (stop, partial.map(PendingDecompileBindingAudit::finalize)))
    }

    /// Render while deferring non-consuming binding classification until the
    /// caller has made every production control decision.
    #[expect(
        clippy::result_large_err,
        reason = "a stopped request retains the sealed request-local product so classification cannot be rebuilt from different facts"
    )]
    pub fn decompile_input_keeping_partial_with_pending_binding_audit<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<
        PendingDecompileBindingAudit,
        (DecompileExecutionStop, Option<PendingDecompileBindingAudit>),
    > {
        let product = match self.prepare_decompile_with_control(input, control) {
            Ok(PreparedDecompile::Immediate(audit)) => {
                return Ok(PendingDecompileBindingAudit::from_audit(audit));
            }
            Ok(PreparedDecompile::NativeOrResidual(product)) => product,
            Err(stop) => return Err((stop, None)),
        };
        let render_work = DecompileWorkControl::new(control, DecompileWorkPhase::Rendering);
        if let Err(stop) = render_work.poll() {
            let output = CodeGenerator::new(self.config.codegen.clone())
                .generate_function(product.emission());
            return Err((
                stop,
                Some(PendingDecompileBindingAudit::from_product(
                    output,
                    product,
                    input.source_owned_facts().clone(),
                )),
            ));
        }
        let output =
            CodeGenerator::new(self.config.codegen.clone()).generate_function(product.emission());
        crate::stage_timing::mark("codegen");
        crate::stage_timing::report(&product.emission().function().name);
        if let Err(stop) = render_work.poll() {
            return Err((
                stop,
                Some(PendingDecompileBindingAudit::from_product(
                    output,
                    product,
                    input.source_owned_facts().clone(),
                )),
            ));
        }
        Ok(PendingDecompileBindingAudit::from_product(
            output,
            product,
            input.source_owned_facts().clone(),
        ))
    }

    /// Build a C function from a prepared function + typed context payload.
    pub fn build_function_from_input(&self, input: &DecompilerInput) -> CFunction {
        let control = r2ssa::SsaExecutionControl::default();
        self.build_function_from_input_with_control(input, &control)
            .expect("default decompiler control never stops")
    }

    /// Build a C AST with cooperative cancellation/deadline polling.
    pub fn build_function_from_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<CFunction, DecompileExecutionStop> {
        self.build_product_from_input_with_control(input, control)
            .map(InternalBuildProduct::into_function)
    }

    fn build_product_from_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<InternalBuildProduct, DecompileExecutionStop> {
        let work = DecompileWorkControl::new(control, DecompileWorkPhase::Normalization);
        work.poll()?;
        let func = input.prepared_ssa().function();
        let func_name = rendered_function_name(func);
        let block_count = func.blocks().count();
        if block_count > self.config.max_blocks {
            return Ok(InternalBuildProduct::residual(
                residual_function_for_render_boundary(
                    &func_name,
                    &block_guard_fallback_comment(&func_name, block_count, self.config.max_blocks),
                ),
            ));
        }
        // A proof failure that names a cell is planned as a gap and the whole
        // rendering is run again with that cell marked, exactly as a lowering
        // refusal is. The plan only grows and is a subset of the graph, so the
        // attempts are bounded by it.
        let mut seed_gaps = std::collections::BTreeMap::new();
        let gap_attempt_bound = input.prepared_ssa().graph().insts.len().saturating_add(1);
        loop {
            let decompiler =
                Self::new(self.config.clone()).with_context(input.context_projection());
            let product =
                decompiler.build_function_internal_with_control(input, work, &seed_gaps)?;
            if seed_gaps.len() < gap_attempt_bound
                && let BindingShadowAuditOutcome::Failed(failure) =
                    product.binding_shadow(input.source_owned_facts())
                && let Some(anchor) = gap_anchor_for_native_failure(&failure, input.prepared_ssa())
                && !seed_gaps.contains_key(&anchor)
            {
                let kind = DecompileRenderRefusal::from(failure).kind().to_string();
                r2il::refusal_evidence!(
                    "gap",
                    "the proof named {anchor:?} as {kind}; planning a gap and rendering again"
                );
                seed_gaps.insert(anchor, kind);
                continue;
            }
            return Ok(product);
        }
    }

    fn linearize_function_body(
        &self,
        func: &SSAFunction,
        fold_ctx: &FoldingContext<'_>,
    ) -> structure::ControlFlowStructureResult<Vec<CStmt>> {
        let blocks: Vec<_> = func.blocks().cloned().collect();
        // A multi-way dispatch cannot be linearized. The terminator arm below
        // described one -- `/* case 0: goto loc_...; */` -- and a comment is not
        // a transfer: the block fell through to whichever arm the linearizer
        // placed next, and the function compiled cleanly and computed the wrong
        // answer. Refusing is the honest answer, and it is what the structured
        // path already does when it cannot express the switch.
        if blocks.iter().any(|block| {
            func.cfg().get_block(block.addr).is_some_and(|cfg_block| {
                matches!(cfg_block.terminator, BlockTerminator::Switch { .. })
            })
        }) {
            return Err(
                crate::fold::op_lower::OpLoweringRefusal::unrepresentable_operation().into(),
            );
        }
        // An unclassified transfer whose target is not a block of this function
        // cannot be linearized. The terminator arm below spells it as
        // `goto loc_<addr>`, but an outside target has no block to carry that
        // label. A source-proven tail jump is different: its callsite fact
        // renders a terminal return in the folded body, so the absent target is
        // no longer a label the linear form owes. Every other outside branch
        // stays behind this refusal; a target that is not a function entry is
        // still a jump, and inventing a call for it would be a wrong answer.
        let own_blocks: std::collections::BTreeSet<u64> =
            blocks.iter().map(|block| block.addr).collect();
        if blocks.iter().any(|block| {
            let terminal_call = block.ops.iter().enumerate().any(|(op_idx, _)| {
                fold_ctx
                    .certified_call_render_fact_for_op(block.addr, op_idx)
                    .is_some_and(|fact| fact.disposition.is_terminal_return())
            });
            func.cfg().get_block(block.addr).is_some_and(|cfg_block| {
                !terminal_call
                    && Self::linearized_transfer_targets(&cfg_block.terminator)
                        .iter()
                        .any(|target| !own_blocks.contains(target))
            })
        }) {
            return Err(
                crate::fold::op_lower::OpLoweringRefusal::unrepresentable_operation().into(),
            );
        }
        let mut labelled = Vec::new();

        for block in &blocks {
            let mut body = Vec::new();
            for stmt in fold_ctx.fold_block(block, block.addr)? {
                if !matches!(stmt, CStmt::Empty) {
                    body.push(stmt);
                }
            }
            if let Some(terminator_stmt) = Self::linearized_terminator_stmt(func, fold_ctx, block) {
                body.push(terminator_stmt);
            }
            labelled.push((Self::linear_block_label(block.addr), body));
        }

        // A block gets a label only if something jumps to it. Labelling every
        // block is how the linear form used to be written, and it emits names
        // no `goto` mentions, which a strict compile rejects. The set has to be
        // collected across the whole body first, because a jump backwards is
        // the normal case here.
        let mut targets = std::collections::BTreeSet::new();
        for (_, body) in &labelled {
            for stmt in body {
                collect_goto_targets(stmt, &mut targets);
            }
        }

        let mut stmts = Vec::new();
        for (label, body) in labelled {
            if targets.contains(&label) {
                stmts.push(CStmt::Label(label));
            }
            stmts.extend(body);
        }

        Ok(stmts)
    }

    fn linear_block_label(addr: u64) -> String {
        format!("loc_{addr:x}")
    }

    /// Every address the linear form would spell as a `goto` for this
    /// terminator. Kept beside `linearized_terminator_stmt` so the two cannot
    /// drift: a target that arm turns into a label has to be listed here, or
    /// the containment check above stops seeing it.
    fn linearized_transfer_targets(terminator: &BlockTerminator) -> Vec<u64> {
        match terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => vec![*true_target, *false_target],
            BlockTerminator::Branch { target } | BlockTerminator::Fallthrough { next: target } => {
                vec![*target]
            }
            BlockTerminator::Call {
                fallthrough: Some(target),
                ..
            }
            | BlockTerminator::IndirectCall {
                fallthrough: Some(target),
            } => vec![*target],
            BlockTerminator::Switch { cases, default } => cases
                .iter()
                .map(|(_, target)| *target)
                .chain(default.iter().copied())
                .collect(),
            BlockTerminator::IndirectBranch
            | BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::Return
            | BlockTerminator::None => Vec::new(),
        }
    }

    fn linearized_terminator_stmt(
        func: &SSAFunction,
        fold_ctx: &FoldingContext<'_>,
        block: &r2ssa::FunctionSSABlock,
    ) -> Option<CStmt> {
        let terminator = &func.cfg().get_block(block.addr)?.terminator;
        if matches!(terminator, BlockTerminator::Branch { .. })
            && block.ops.iter().enumerate().any(|(op_idx, _)| {
                fold_ctx
                    .certified_call_render_fact_for_op(block.addr, op_idx)
                    .is_some_and(|fact| fact.disposition.is_terminal_return())
            })
        {
            return None;
        }
        match terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            } => fold_ctx
                .extract_condition_from_block(block)
                .map(|cond| {
                    let stmt = CStmt::if_stmt(
                        cond,
                        CStmt::Goto(Self::linear_block_label(*true_target)),
                        Some(CStmt::Goto(Self::linear_block_label(*false_target))),
                    );
                    Self::observe_linearized_control_terminator(fold_ctx, block, stmt)
                })
                .or_else(|| {
                    Some(CStmt::comment(format!(
                        "conditional branch condition unresolved; true_target={}, false_target={}",
                        Self::linear_block_label(*true_target),
                        Self::linear_block_label(*false_target)
                    )))
                }),
            BlockTerminator::Branch { target } | BlockTerminator::Fallthrough { next: target } => {
                Some(Self::observe_linearized_control_terminator(
                    fold_ctx,
                    block,
                    CStmt::Goto(Self::linear_block_label(*target)),
                ))
            }
            BlockTerminator::Call {
                fallthrough: Some(target),
                ..
            }
            | BlockTerminator::IndirectCall {
                fallthrough: Some(target),
            } => Some(CStmt::Goto(Self::linear_block_label(*target))),
            BlockTerminator::Switch { cases, default } => {
                let mut stmts = Vec::new();
                for (value, target) in cases {
                    stmts.push(CStmt::comment(format!(
                        "case {value}: goto {};",
                        Self::linear_block_label(*target)
                    )));
                }
                if let Some(target) = default {
                    stmts.push(CStmt::comment(format!(
                        "default: goto {};",
                        Self::linear_block_label(*target)
                    )));
                }
                (!stmts.is_empty()).then_some(CStmt::Block(stmts))
            }
            BlockTerminator::IndirectBranch => Some(CStmt::comment(
                "indirect branch target unresolved".to_string(),
            )),
            BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None }
            | BlockTerminator::Return
            | BlockTerminator::None => None,
        }
    }

    fn observe_linearized_control_terminator(
        fold_ctx: &FoldingContext<'_>,
        block: &r2ssa::FunctionSSABlock,
        stmt: CStmt,
    ) -> CStmt {
        let Some(op_idx) = block.ops.len().checked_sub(1) else {
            return stmt;
        };
        let obligations = fold_ctx.exact_effect_obligations_for_normalized_value(
            crate::fold::context::EffectOccurrenceKind::Expression,
            block.addr,
            op_idx,
            None,
        );
        fold_ctx.observe_effect_stmt(&obligations, stmt)
    }

    #[cfg(test)]
    pub(crate) fn prepend_comment(stmt: CStmt, text: String) -> CStmt {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        let comment = CStmt::comment(text);
        match semantic {
            CStmt::Empty => CStmt::Block(vec![comment]),
            CStmt::Block(mut stmts) => {
                // Inserting a new sibling splits the observed block position;
                // no existing child is an exact owner for its outer markers.
                // Nested child observations remain intact.
                stmts.insert(0, comment);
                CStmt::Block(stmts)
            }
            other => CStmt::Block(vec![comment, observations.reapply(other)]),
        }
    }

    fn build_function_internal_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        work: DecompileWorkControl<'a>,
        seed_gaps: &std::collections::BTreeMap<r2ssa::InstId, String>,
    ) -> Result<InternalBuildProduct, DecompileExecutionStop> {
        crate::stage_timing::begin();
        // The names this rendering declares, from the first pass that mints one.
        let symbol_table =
            std::rc::Rc::new(std::cell::RefCell::new(crate::symbol::SymbolTable::new()));
        let symbols = &*symbol_table;

        work.poll()?;
        let prepared = input.prepared_ssa();
        debug_log_slice(prepared);
        let func = prepared.function();
        if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
            let graph = prepared.graph();
            let live = prepared.live_out();
            let dead = prepared.unobserved_merges();
            let total: usize = func.blocks().map(|b| b.phis.len()).sum();
            eprintln!(
                "MERGES fn={:#x} phis={} unobserved={} live_out={} unresolved={}",
                func.entry,
                total,
                dead.len(),
                live.len(),
                live.unresolved_blocks().count()
            );
            // Which merges the carrier gate admits, and which it turns away. The
            // gate is one question asked per phi, so printing its answer beside the
            // merge names the value that is lost rather than the layer that lost it.
            let render_facts = self.context.function_facts.render();
            for block in func.blocks() {
                for phi in &block.phis {
                    let value = graph.value_id_for_var(&phi.dst);
                    let carrier = value.is_some_and(|value| {
                        render_facts
                            .is_some_and(|facts| facts.loop_carrier_for_value(value).is_some())
                    });
                    eprintln!(
                        "MERGEPHI block={:#x} dst={} size={} value={:?} carrier={}",
                        block.addr,
                        phi.dst.display_name(),
                        phi.dst.size,
                        value,
                        carrier
                    );
                }
            }
            // What each carrier member is spelled as, so a member that some other
            // table also answers for shows up as a name the body never uses.
            if let Some(facts) = render_facts {
                // A carrier the alias map drops is spelled by whatever else answers
                // for its name, so the two filters that drop one are printed by name.
                let mirrored = prepared.memory_mirrored_carriers();
                let reused = prepared.carriers_spanning_a_reuse();
                let spans = prepared.storage_spans();
                for carrier in facts.loop_carriers() {
                    if let r2types::CertifiedEntity::LoopCarrier {
                        id,
                        phi,
                        identity_values,
                        entries,
                        updates,
                        ..
                    } = carrier
                    {
                        eprintln!(
                            "CARRIERFILTER id={:?} phi={:?} var={} mirrored={} reused={}",
                            id,
                            phi,
                            graph
                                .value(*phi)
                                .map(|value| value.var.display_name())
                                .unwrap_or_default(),
                            mirrored.contains(id),
                            reused.contains(id)
                        );
                        // A member in a second span is what makes a carrier span a
                        // reuse, so each member prints with the span it landed in.
                        let members = identity_values
                            .iter()
                            .copied()
                            .chain(entries.iter().map(|edge| edge.value))
                            .chain(updates.iter().flat_map(|update| {
                                std::iter::once(update.value)
                                    .chain(update.identity_values.iter().copied())
                            }))
                            .collect::<std::collections::BTreeSet<_>>();
                        for member in members {
                            eprintln!(
                                "  MEMBER value={:?} var={} storage={:?} span={:?}",
                                member,
                                graph
                                    .value(member)
                                    .map(|value| value.var.display_name())
                                    .unwrap_or_default(),
                                graph
                                    .value(member)
                                    .and_then(|value| value.canonical_storage),
                                spans.span_of(member)
                            );
                        }
                    }
                }
            }
        }
        let normalization_refusal = |error: normalize::NormalizationOriginError| {
            let func_name = rendered_function_name(func);
            residual_function_for_render_boundary(
                &func_name,
                &format!("normalization origin refusal: {error}"),
            )
        };
        let (mut normalized_func, mut normalization_origins) =
            if let Some(render_facts) = self.context.function_facts.render() {
                match normalize::materialize_certified_loop_carriers_with_control(
                    func,
                    prepared,
                    render_facts,
                    work,
                ) {
                    Ok(result) => result,
                    Err(normalize::NormalizationFailure::Execution(error)) => return Err(error),
                    Err(normalize::NormalizationFailure::Origins(error)) => {
                        return Ok(InternalBuildProduct::refused(
                            normalization_refusal(error),
                            DecompileRenderRefusal::NormalizationOriginUnavailable,
                        ));
                    }
                }
            } else {
                (
                    func.clone(),
                    normalize::NormalizationOrigins::for_unchanged(func, prepared),
                )
            };
        if let Some(render_facts) = self.context.function_facts.render()
            && let Err(error) =
                normalize::materialize_certified_loop_carrier_initializers_with_control(
                    &mut normalized_func,
                    &mut normalization_origins,
                    prepared,
                    render_facts,
                    work,
                )
        {
            match error {
                normalize::NormalizationFailure::Execution(error) => return Err(error),
                normalize::NormalizationFailure::Origins(error) => {
                    return Ok(InternalBuildProduct::refused(
                        normalization_refusal(error),
                        DecompileRenderRefusal::NormalizationOriginUnavailable,
                    ));
                }
            }
        }
        // The graph and the normalized function, verbatim, so a rendered
        // statement can be read back to the instruction that produced it.
        // Every other probe answers one question; this one is for the
        // question nobody has asked yet.
        if std::env::var_os("R2SLEIGH_DUMP_SSA").is_some() {
            let graph = prepared.graph();
            eprintln!("SSADUMP prepared\n{}", func.dump());
            eprintln!("SSADUMP normalized\n{}", normalized_func.dump());
            for value in &graph.values {
                eprintln!(
                    "SSAVALUE {:?} {} storage={:?} def={:?} uses={:?}",
                    value.id,
                    value.var,
                    value.canonical_storage.map(|storage| (
                        storage.space,
                        storage.offset,
                        storage.size
                    )),
                    graph.def_inst(value.id),
                    graph.use_sites(value.id)
                );
            }
            for inst in &graph.insts {
                eprintln!(
                    "SSAINST {:?} block={:?} ordinal={} out={:?} in={:?} {}",
                    inst.id,
                    inst.block,
                    inst.ordinal,
                    inst.output,
                    inst.inputs,
                    format!("{:?}", inst.payload)
                        .chars()
                        .take(160)
                        .collect::<String>()
                );
            }
        }
        if let Err(error) = normalization_origins.validate(
            &normalized_func,
            prepared,
            self.context.function_facts.render(),
        ) {
            let func_name = rendered_function_name(func);
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(
                    &func_name,
                    &format!("normalization origin refusal: {error:?}"),
                ),
                DecompileRenderRefusal::NormalizationOriginUnavailable,
            ));
        }
        crate::stage_timing::mark("prepare");
        let binding_plan =
            match crate::binding_plan::BindingPlan::build_shadow(input.source_owned_facts()) {
                Ok(plan) => std::rc::Rc::new(plan),
                Err(error) => {
                    debug_log_render_contract_error(prepared, "binding-plan", &error);
                    // The plan's own error says which value or entity it could
                    // not place, and until now it reached only a debug log
                    // nobody turns on: the census recorded six functions as
                    // `BindingPlanBuild` with no way to tell what any of them
                    // met. It rides the same evidence channel as every other
                    // refusal now.
                    r2il::refusal_evidence!(
                        "binding-plan-build",
                        "{}: {error:?}",
                        rendered_function_name(func)
                    );
                    let refusal = match error {
                        crate::binding_plan::BindingPlanBuildError::MachineProjection(_)
                        | crate::binding_plan::BindingPlanBuildError::Seal(
                            crate::binding_plan::BindingPlanSourceMismatch::MachineProjection(_),
                        ) => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                            MachineProjectionRefusalOrigin::BindingPlanBuild,
                        ),
                        _ => DecompileRenderRefusal::MissingProgramVariableAuthorization,
                    };
                    return Ok(InternalBuildProduct::refused(
                        residual_function_for_render_boundary(
                            &rendered_function_name(func),
                            &format!("native render refusal: {}", refusal.kind()),
                        ),
                        refusal,
                    ));
                }
            };
        if let Err(error) = crate::fold::op_lower::PlannedLoweringInput::try_new(
            input.source_owned_facts(),
            &binding_plan,
        ) {
            debug_log_render_contract_error(prepared, "planned-lowering-input", &error);
            let refusal = match error {
                crate::binding_plan::BindingPlanSourceMismatch::MachineProjection(_) => {
                    DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                        MachineProjectionRefusalOrigin::PlannedLoweringInput,
                    )
                }
                _ => DecompileRenderRefusal::MissingProgramVariableAuthorization,
            };
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(
                    &rendered_function_name(func),
                    &format!("native render refusal: {}", refusal.kind()),
                ),
                refusal,
            ));
        }
        let binding_names = match crate::binding_plan::BindingNameResolution::build(
            input.source_owned_facts(),
            std::rc::Rc::clone(&binding_plan),
            std::rc::Rc::clone(&symbol_table),
        ) {
            Ok(names) => std::rc::Rc::new(names),
            Err(error) => {
                debug_log_render_contract_error(prepared, "binding-name-resolution", &error);
                let refusal = match error {
                    crate::binding_plan::BindingNameResolutionError::Source(
                        crate::binding_plan::BindingPlanSourceMismatch::MachineProjection(_),
                    ) => DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                        MachineProjectionRefusalOrigin::PlannedLoweringInput,
                    ),
                    crate::binding_plan::BindingNameResolutionError::Source(_)
                    | crate::binding_plan::BindingNameResolutionError::ConflictingCertifiedRoles(
                        _,
                    ) => DecompileRenderRefusal::MissingProgramVariableAuthorization,
                };
                return Ok(InternalBuildProduct::refused(
                    residual_function_for_render_boundary(
                        &rendered_function_name(func),
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    refusal,
                ));
            }
        };
        let func = &normalized_func;
        let func_name = rendered_function_name(func);
        let observation_journal = match LegacyObservationJournal::new(
            input.source_owned_facts(),
            &normalized_func,
            &normalization_origins,
            Rc::clone(&binding_names),
            Rc::clone(&symbol_table),
        ) {
            Ok(journal) => std::cell::RefCell::new(journal),
            Err(error) => {
                let refusal = DecompileRenderRefusal::ObservationJournal(
                    BindingObservationJournalFailure::from(&error),
                );
                return Ok(InternalBuildProduct::refused(
                    residual_function_for_render_boundary(
                        &func_name,
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    refusal,
                ));
            }
        };
        work.poll()?;
        if std::env::var_os("R2SLEIGH_DEBUG_MERGES").is_some() {
            eprintln!(
                "SOURCE_INTERFACE {:?}",
                prepared.machine_context().function_interface()
            );
            // What materialisation left behind, so a carrier update that renders
            // more than once shows which ops the fold was handed.
            for block in normalized_func.blocks() {
                for (index, op) in block.ops.iter().enumerate() {
                    let op: &r2ssa::SSAOp = op;
                    let kind = format!("{op:?}");
                    let kind = kind.split([' ', '{']).next().unwrap_or("?");
                    let origin = prepared
                        .graph()
                        .block_id_for_addr(block.addr)
                        .and_then(|block| {
                            normalization_origins.origin(crate::normalize::NormalizedOpSite {
                                block,
                                op_idx: index,
                            })
                        })
                        .map(|origin| match origin {
                            crate::normalize::NormalizedOpOrigin::Original(inst) => {
                                format!("original:{}", inst.0)
                            }
                            crate::normalize::NormalizedOpOrigin::PhiEdgeCopy(_) => {
                                "phi-edge-copy".to_string()
                            }
                            crate::normalize::NormalizedOpOrigin::RelocatedInitializer(_) => {
                                "relocated-initializer".to_string()
                            }
                        })
                        .unwrap_or_else(|| "missing".to_string());
                    eprintln!(
                        "NORMOP block={:#x} idx={index} origin={origin} kind={kind} dst={:?} srcs={:?}",
                        block.addr,
                        op.dst().map(|var| var.display_name()),
                        op.sources()
                            .iter()
                            .map(|var| var.display_name())
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        let render_signature = self.context.type_facts().render_authorized_signature();
        let params = match binding_names
            .parameters()
            .map(|resolved| {
                let resolved = resolved?;
                // The render-authorized signature is the canonical declaration
                // fact and is already the type authority used while lowering
                // this parameter's uses. Admit that same fact at the header
                // boundary only when it describes the certified carrier width;
                // otherwise this value alone keeps its sealed machine type.
                let ty = render_signature
                    .and_then(|signature| {
                        usize::try_from(resolved.slot)
                            .ok()
                            .and_then(|slot| signature.params.get(slot))
                    })
                    .and_then(|parameter| parameter.ty.clone())
                    .map(|ty| {
                        crate::binding_plan::admit_declaration(
                            ty,
                            resolved.width_bits,
                            self.config.ptr_size,
                        )
                    })
                    .unwrap_or(resolved.declaration_type);
                Ok(ast::CParam {
                    ty,
                    name: resolved.symbol,
                })
            })
            .collect::<Result<Vec<_>, crate::binding_plan::RenderedIdentityRefusal>>()
        {
            Ok(params) => params,
            Err(error) => {
                let refusal = rendered_identity_refusal_category(error);
                return Ok(InternalBuildProduct::refused(
                    residual_function_for_render_boundary(
                        &func_name,
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    refusal,
                ));
            }
        };
        let inferred_ret_type = r2types::exact_source_return_type(prepared).unwrap_or_else(|| {
            evidence_return_type(prepared, input.source_owned_facts().evidence_types())
        });
        let signature_ret_type = render_signature.and_then(|sig| sig.ret_type.clone());
        let fold_function_return_type = signature_ret_type.as_ref().or(Some(&inferred_ret_type));
        let fold_arch = FoldArchConfig {
            ptr_size: self.config.ptr_size,
            arg_regs: self.config.arg_regs.clone(),
        };
        let prepared_semantic_view = match analysis::PreparedSemanticView::build_with_bindings(
            symbols,
            analysis::PreparedSemanticViewInputs {
                prepared,
                #[cfg(test)]
                stack_slots: &self.context.type_facts().stack_slots,
                #[cfg(test)]
                visible_bindings: &self.context.type_facts().visible_bindings,
                function_facts: &self.context.function_facts,
                #[cfg(test)]
                certified_rendering_required: false,
            },
            Rc::clone(&binding_names),
        ) {
            Ok(view) => view,
            Err(error) => {
                debug_log_render_contract_error(prepared, "prepared-semantic-view", &error);
                let refusal = match error {
                    analysis::prepared_semantic::PreparedSemanticViewBuildError::RenderedIdentity(
                        refusal,
                    ) => {
                        rendered_identity_refusal_category(refusal)
                    }
                    analysis::prepared_semantic::PreparedSemanticViewBuildError::SourceAuthorityMismatch
                    | analysis::prepared_semantic::PreparedSemanticViewBuildError::SymbolTableMismatch => {
                        DecompileRenderRefusal::MissingProgramVariableAuthorization
                    }
                };
                return Ok(InternalBuildProduct::refused(
                    residual_function_for_render_boundary(
                        &rendered_function_name(func),
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    refusal,
                ));
            }
        };
        let fold_inputs = FoldInputs {
            normalization_origins: Some(&normalization_origins),
            observation_journal: Some(&observation_journal),
            arch: &fold_arch,
            #[cfg(test)]
            function_names: &self.context.function_names,
            #[cfg(test)]
            binary_symbols: &self.context.symbols,
            function_facts: &self.context.function_facts,
            #[cfg(test)]
            stack_slots: &self.context.type_facts().stack_slots,
            #[cfg(test)]
            visible_bindings: &self.context.type_facts().visible_bindings,
            function_return_type: fold_function_return_type,
            prepared_ssa: Some(prepared),
            binding_names: Some(&binding_names),
            prepared_semantic_view: Some(&prepared_semantic_view),
        };
        crate::stage_timing::mark("binding_plan");
        let mut fold_ctx = FoldingContext::from_inputs(fold_inputs);
        // One rendered function has one table, and this is the one the passes
        // before now declared into.
        fold_ctx.symbols = std::rc::Rc::clone(&symbol_table);
        // Cells a previous attempt's proof could not account for. Planning them
        // before the fold runs is the whole point: by the time the proof failed,
        // a statement reading the unproven value had already rendered.
        for (anchor, kind) in seed_gaps {
            fold_ctx.plan_gap_at_anchor(*anchor, kind);
        }
        let fold_blocks: Vec<_> = func.blocks().cloned().collect();
        let structuring_work = work.with_phase(DecompileWorkPhase::Structuring);
        if let Err(error) = fold_ctx.analyze_blocks_with_control(&fold_blocks, structuring_work) {
            debug_log_render_contract_error(prepared, "fold-analysis", &error);
            match error {
                analysis::PreparedRuntimeFactsError::ExecutionStop(stop) => return Err(stop),
                analysis::PreparedRuntimeFactsError::Lowering(refusal) => {
                    return Ok(InternalBuildProduct::refused(
                        residual_function_for_render_boundary(
                            &func_name,
                            &format!("operation lowering refusal: {refusal:?}"),
                        ),
                        refusal.into(),
                    ));
                }
            }
        }
        crate::stage_timing::mark("fold");
        structuring_work.poll()?;
        // Structure control flow (primary path: folded).
        //
        // A refusal that escapes here is one the fold could not turn into a
        // marked gap, and there is exactly one reason it cannot: a statement
        // that reads the unproven value had already rendered, so the gap's
        // cells were claimed. Nothing about the refusal has changed, only
        // when it was learned. So the site is added to the gap plan and the
        // whole structuring is run again from a rolled-back journal, with
        // that operation and its readers skipped before either can render.
        // The plan only grows and it is a subset of the graph's
        // instructions, so the retries are bounded by the graph.
        let structure_attempt_bound = prepared.graph().insts.len().saturating_add(1);
        let structure_checkpoint = observation_journal.borrow().checkpoint();
        let structure_observation_error = fold_ctx.observation_error.borrow().clone();
        let mut structure_attempt = 0usize;
        let routed_body = loop {
            structure_attempt += 1;
            let mut structurer =
                ControlFlowStructurer::new_with_control(func, &fold_ctx, structuring_work)?;
            let tentative_observation_checkpoint = observation_journal.borrow().checkpoint();
            let tentative_observation_error = fold_ctx.observation_error.borrow().clone();

            match consumer_structured::primary_native_body(
                &mut structurer,
                || self.linearize_function_body(func, &fold_ctx),
                || {
                    observation_journal
                        .borrow_mut()
                        .rollback(tentative_observation_checkpoint);
                    *fold_ctx.observation_error.borrow_mut() = tentative_observation_error.clone();
                },
            ) {
                Ok(body) => {
                    if let Some(stop) = structurer.execution_stop() {
                        return Err(stop);
                    }
                    break body;
                }
                Err(structure::ControlFlowStructureError::Lowering(refusal)) => {
                    if structure_attempt < structure_attempt_bound
                        && fold_ctx.plan_gap_for_escaped_refusal(refusal)
                    {
                        observation_journal
                            .borrow_mut()
                            .rollback(structure_checkpoint);
                        *fold_ctx.observation_error.borrow_mut() =
                            structure_observation_error.clone();
                        fold_ctx.folded_blocks.borrow_mut().clear();
                        continue;
                    }
                    debug_log_render_contract_error(
                        prepared,
                        "control-structure-lowering",
                        &refusal,
                    );
                    let function = residual_function_for_render_boundary(
                        &rendered_function_name(func),
                        &format!("operation lowering refusal: {refusal:?}"),
                    );
                    return Ok(InternalBuildProduct::refused(function, refusal.into()));
                }
                Err(structure::ControlFlowStructureError::StructuredRegion(error)) => {
                    debug_log_render_contract_error(prepared, "structured-region", &error);
                    return Ok(InternalBuildProduct::refused(
                        residual_function_for_render_boundary(
                            &rendered_function_name(func),
                            &format!("structured-region refusal: {error:?}"),
                        ),
                        DecompileRenderRefusal::UnrepresentableControlFlow,
                    ));
                }
            }
        };
        structuring_work.poll()?;
        crate::stage_timing::mark("structure_route");
        if let Some(structured_body) = routed_body.structured_body()
            && let Err(refusal) = validate_sealed_region_occurrence_coverage(structured_body)
        {
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(
                    &func_name,
                    "structured-region occurrence coverage mismatch",
                ),
                refusal,
            ));
        }
        crate::stage_timing::mark("structure_region_seal");
        let (body_stmt, structured_regions) = routed_body.into_marked_body();
        crate::stage_timing::mark("structure_marked_body");

        // Build the C function
        // Convert body to statements
        let body = self.stmt_to_vec(body_stmt);
        crate::stage_timing::mark("structure_flatten");
        let mut c_function = CFunction {
            symbols: std::rc::Rc::clone(&symbol_table),
            name: crate::ast::c_identifier(&func_name),
            extern_objects: Vec::new(),
            externs: fold_ctx
                .callee_declarations
                .borrow()
                .values()
                .cloned()
                .collect(),
            ret_type: render_signature
                .and_then(|sig| sig.ret_type.clone())
                .unwrap_or_else(|| inferred_ret_type.clone()),
            params,
            // Program locals are introduced only by the final placement pass
            // from surviving, observed BindingId occurrences.
            locals: Vec::new(),
            body,
            // Parameters here come from the render signature, so an empty list
            // is a recovered empty list rather than an unknown one.
            params_known: true,
        };
        let display = self.context.function_facts.display_names();
        let strings = display.strings();
        let data_symbols = display.symbols();
        let data_object_types = &self
            .context
            .function_facts
            .type_facts()
            .program_data_objects;
        let used_objects: std::cell::RefCell<
            std::collections::BTreeMap<u64, crate::ast::CExternObject>,
        > = std::cell::RefCell::new(std::collections::BTreeMap::new());
        crate::stage_timing::mark("structure");
        fold_constant_arithmetic_in_function(
            &mut c_function,
            strings,
            data_symbols,
            data_object_types,
            &used_objects,
            self.config.ptr_size,
        );
        c_function.extern_objects = used_objects.into_inner().into_values().collect();

        if let Err(error) = single_evaluation::bind_each_call_site_once(
            &mut c_function,
            &binding_names,
            structured_regions.as_ref(),
        ) {
            debug_log_render_contract_error(prepared, "single-evaluation", &error);
            let refusal = DecompileRenderRefusal::MissingProgramVariableAuthorization;
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(
                    &c_function.name,
                    &format!("native render refusal: {}", refusal.kind()),
                ),
                refusal,
            ));
        }
        crate::stage_timing::mark("normalize");
        unrendered::prune_unreferenced_labels(&mut c_function);
        if void_function_has_value_return(&c_function) {
            let refusal = DecompileRenderRefusal::UnrepresentableOperation;
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(
                    &c_function.name,
                    "native render refusal: value-bearing return in void function",
                ),
                refusal,
            ));
        }
        // The refusal gate above proves this is a no-op. Do not discard a
        // value-bearing return here: its expression may carry source effects.
        unrendered::drop_values_from_void_returns(&mut c_function);
        // Executable C is admitted only when the source obligation inventory is
        // complete. The inventory is what says which effects the source has, so a
        // function whose inventory did not close has no account of what the output
        // owes, and rendering it says the effects were all handled when nothing
        // ever enumerated them.
        if let Some(reason) = incomplete_source_obligations_reason(prepared) {
            return Ok(InternalBuildProduct::refused(
                residual_function_for_render_boundary(&c_function.name, &reason),
                DecompileRenderRefusal::IncompleteEffectInventory,
            ));
        }
        let observation_error = fold_ctx.observation_error.borrow().clone();
        drop(fold_ctx);
        let draft = MarkedNativeDraft::new_with_placement(
            c_function,
            observation_journal.into_inner(),
            structured_regions,
            Rc::clone(&binding_names),
        );
        let mut native = match draft.finish_enforcing(input.source_owned_facts(), observation_error)
        {
            Ok(native) => native,
            Err(failure) => {
                let refusal = DecompileRenderRefusal::from(failure);
                return Ok(InternalBuildProduct::refused_after_native_admission(
                    residual_function_for_render_boundary(
                        &func_name,
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    failure,
                ));
            }
        };
        crate::stage_timing::mark("seal");
        let ledger = effect_ledger::build_obligation_ledger(
            prepared,
            &normalization_origins,
            native.effect_observations(),
        );
        debug_log_ledger(prepared, &ledger);
        let radare2_variadic_format_counts = self
            .context
            .function_facts
            .callsites()
            .into_iter()
            .flat_map(|facts| facts.by_callsite.values())
            .filter(|fact| {
                fact.variadic_argument_count_evidence
                    .is_some_and(|evidence| {
                        evidence.source
                            == r2ssa::VariadicCallsiteArgumentCountSource::Radare2FormatString
                    })
            })
            .count();
        native.finalize_effect_ledger(
            &ledger,
            radare2_variadic_format_counts,
            binding_names.source_named_locals(),
        );
        Ok(InternalBuildProduct::Native(native))
    }

    /// Convert a CStmt to a Vec<CStmt>.
    fn stmt_to_vec(&self, stmt: CStmt) -> Vec<CStmt> {
        let (semantic, observations) = stmt.into_semantic_with_observations();
        match semantic {
            CStmt::Block(mut stmts) => {
                observations.reapply_to_unique(&mut stmts);
                stmts
            }
            CStmt::Empty => vec![],
            other => vec![observations.reapply(other)],
        }
    }
}

fn evidence_return_type(source: &r2ssa::SsaArtifact, evidence: &r2types::EvidenceTypes) -> CType {
    let mut candidate: Option<CType> = None;
    let mut saw_return = false;
    for certificate in &source.certificates().returns {
        saw_return = true;
        let Some(ty) = evidence.value_type(certificate.value) else {
            return CType::Unknown;
        };
        let ty = ty.clone();
        match &candidate {
            None => candidate = Some(ty),
            Some(existing) if existing == &ty => {}
            Some(_) => return CType::Unknown,
        }
    }
    if saw_return {
        r2il::refusal_evidence!(
            "return-evidence",
            "return certificates present; agreed={:?}",
            candidate
        );
        return candidate.unwrap_or(CType::Unknown);
    }
    // A function with no `Return` of its own may still return: a tail call
    // returns its callee's result on this function's behalf, and the exact
    // boundary at that site says what the callee returns. Reading only the
    // `Return` certificates scored every tail-only function `void`, and a
    // thunk's `return fileno(stream);` then had no type to be declared with.
    let mut tail_candidate: Option<CType> = None;
    let mut saw_tail = false;
    for certificate in source.certificates().callsites.values() {
        if certificate.transfer != r2ssa::CallSiteTransfer::TailCall {
            continue;
        }
        let Some(interface) = source.call_site_interface(certificate.call_site) else {
            return CType::Unknown;
        };
        saw_tail = true;
        let ty = match interface.result() {
            r2ssa::SourceCallResult::Void => CType::Void,
            r2ssa::SourceCallResult::Register { storage } => CType::uint(storage.size * 8),
        };
        match &tail_candidate {
            None => tail_candidate = Some(ty),
            Some(existing) if existing == &ty => {}
            Some(_) => return CType::Unknown,
        }
    }
    r2il::refusal_evidence!(
        "return-evidence",
        "no return certificate; tail boundaries={} agreed={:?}",
        saw_tail,
        tail_candidate
    );
    if saw_tail {
        return tail_candidate.unwrap_or(CType::Unknown);
    }
    CType::Void
}

fn void_function_has_value_return(func: &CFunction) -> bool {
    if !matches!(func.ret_type, CType::Void) {
        return false;
    }

    fn stmt_has_value_return(stmt: &CStmt) -> bool {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => {
                stmt_has_value_return(stmt)
            }
            CStmt::Return(Some(_)) => true,
            CStmt::Block(stmts) => stmts.iter().any(stmt_has_value_return),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                stmt_has_value_return(then_body)
                    || else_body.as_deref().is_some_and(stmt_has_value_return)
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => stmt_has_value_return(body),
            CStmt::For { init, body, .. } => {
                init.as_deref().is_some_and(stmt_has_value_return) || stmt_has_value_return(body)
            }
            CStmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case| case.body.iter().any(stmt_has_value_return))
                    || default
                        .as_ref()
                        .is_some_and(|stmts| stmts.iter().any(stmt_has_value_return))
            }
            CStmt::Empty
            | CStmt::Expr(_)
            | CStmt::Decl { .. }
            | CStmt::Break
            | CStmt::Continue
            | CStmt::Goto(_)
            | CStmt::Label(_)
            | CStmt::Return(None)
            | CStmt::Comment(_)
            | CStmt::Gap(_) => false,
        }
    }

    func.body.iter().any(stmt_has_value_return)
}

pub(crate) fn collect_expr_var_names(expr: &CExpr, out: &mut HashSet<crate::symbol::SymbolId>) {
    match expr {
        CExpr::Observed { expr, .. } => collect_expr_var_names(expr, out),
        CExpr::Var(name) => {
            out.insert(*name);
        }
        // Not a name this function declares, so not one it has to.
        CExpr::External { .. } | CExpr::DataObject { .. } => {}
        CExpr::Unary { operand, .. }
        | CExpr::Cast { expr: operand, .. }
        | CExpr::Paren(operand)
        | CExpr::AddrOf(operand)
        | CExpr::Deref(operand) => collect_expr_var_names(operand, out),
        CExpr::Comma(items) => {
            for item in items {
                collect_expr_var_names(item, out);
            }
        }
        CExpr::Binary { left, right, .. } => {
            collect_expr_var_names(left, out);
            collect_expr_var_names(right, out);
        }
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_var_names(cond, out);
            collect_expr_var_names(then_expr, out);
            collect_expr_var_names(else_expr, out);
        }
        CExpr::Call { func, args, .. } => {
            collect_expr_var_names(func, out);
            for arg in args {
                collect_expr_var_names(arg, out);
            }
        }
        CExpr::Subscript { base, index } => {
            collect_expr_var_names(base, out);
            collect_expr_var_names(index, out);
        }
        CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
            collect_expr_var_names(base, out);
        }
        CExpr::IntLit(_)
        | CExpr::UIntLit(_)
        | CExpr::FloatLit(_)
        | CExpr::CharLit(_)
        | CExpr::StringLit(_)
        | CExpr::Sizeof(_)
        | CExpr::SizeofType(_) => {}
    }
}

/// Names a statement introduces, wherever it sits in the body.
pub(crate) fn collect_stmt_var_names(stmts: &[CStmt]) -> HashSet<crate::symbol::SymbolId> {
    fn visit_stmt(stmt: &CStmt, out: &mut HashSet<crate::symbol::SymbolId>) {
        match stmt {
            CStmt::StructuredRegion { stmt, .. } => visit_stmt(stmt, out),
            CStmt::Observed { stmt, .. } => visit_stmt(stmt, out),
            CStmt::Empty
            | CStmt::Break
            | CStmt::Continue
            | CStmt::Comment(_)
            | CStmt::Gap(_)
            | CStmt::Goto(_)
            | CStmt::Label(_) => {}
            CStmt::Expr(expr) => collect_expr_var_names(expr, out),
            CStmt::Return(expr) => {
                if let Some(expr) = expr {
                    collect_expr_var_names(expr, out);
                }
            }
            CStmt::Decl { init, .. } => {
                if let Some(init) = init {
                    collect_expr_var_names(init, out);
                }
            }
            CStmt::Block(stmts) => {
                for stmt in stmts {
                    visit_stmt(stmt, out);
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_expr_var_names(cond, out);
                visit_stmt(then_body, out);
                if let Some(else_body) = else_body {
                    visit_stmt(else_body, out);
                }
            }
            CStmt::While { cond, body } => {
                collect_expr_var_names(cond, out);
                visit_stmt(body, out);
            }
            CStmt::DoWhile { body, cond } => {
                visit_stmt(body, out);
                collect_expr_var_names(cond, out);
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    visit_stmt(init, out);
                }
                if let Some(cond) = cond {
                    collect_expr_var_names(cond, out);
                }
                if let Some(update) = update {
                    collect_expr_var_names(update, out);
                }
                visit_stmt(body, out);
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                collect_expr_var_names(expr, out);
                for case in cases {
                    collect_expr_var_names(&case.value, out);
                    for stmt in &case.body {
                        visit_stmt(stmt, out);
                    }
                }
                if let Some(default) = default {
                    for stmt in default {
                        visit_stmt(stmt, out);
                    }
                }
            }
        }
    }

    let mut names = HashSet::new();
    for stmt in stmts {
        visit_stmt(stmt, &mut names);
    }
    names
}

/// Which locals the body still assigns, printed between passes.
///
/// A statement the fold built and the page does not show was removed by one of
/// the passes that run after structuring, and there are a dozen of them. Naming
/// Fold arithmetic between integer literals, and name the result when it names
/// a string.
///
/// A PIC address arrives as two constants: `adrp` puts a page in a register and
/// `add` puts the offset on top, so the renderer had `0x100002000U + 0xbbc`
/// where the program has one address. The sum is strictly more readable folded,
/// and folding it is also what lets the string table answer: the table is keyed
/// by address, and until the two halves are one number there is no address to
/// look up.
fn fold_constant_arithmetic_in_function(
    func: &mut CFunction,
    strings: &std::collections::BTreeMap<u64, String>,
    symbols: &std::collections::BTreeMap<u64, String>,
    object_types: &r2types::ProgramDataObjectTypeFacts,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
    pointer_bits: u32,
) {
    let symbol_table = std::rc::Rc::clone(&func.symbols);
    for stmt in &mut func.body {
        fold_constant_arithmetic_in_stmt(
            stmt,
            strings,
            symbols,
            object_types,
            used,
            pointer_bits,
            Some(&symbol_table),
        );
    }
}

/// Restate the conversions around a constant that turned out to be a string.
///
/// The conversions above a constant address are decided while it is an
/// integer, because that is what it is until the string table is consulted.
/// Substituting the string changes the expression's type -- a string literal
/// is a `char *`, not a number -- so every conversion that was spelled for
/// the integer is a statement about a type the expression no longer has, and
/// `(char *)(uint64_t)"a string"` is what survives.
///
/// The chain is therefore not patched but restated: the net conversion, from
/// what the string is to what the outermost conversion required, spelled by
/// the one emitter. Where the two are the same the chain disappears, which is
/// the common case -- a string reaches a `char *` parameter as itself.
/// The type of a `char` in C, which is its own type.
///
/// Not `int8_t`. C has three character types and `char` is distinct from both
/// `signed char` and `unsigned char`, so a `char *` and an `int8_t *` are
/// different pointers and converting between them is a cast the compiler
/// asks for. A string literal is an array of `char`, and saying so is what
/// lets it reach a `char *` with nothing spelled.
fn plain_char_type() -> CType {
    CType::Typedef("char".to_string())
}

/// The address a chain of conversions is wrapped around, and what it is.
///
/// Two substitutions put an address where a number was. A string literal is
/// an array of `char` that decays to a `char *` wherever a value is wanted.
/// The address of a named object is a pointer to the object, and the object
/// is declared `extern char name[]`, so `&name` is a pointer to an array of
/// `char` -- not a `char *`, which is why converting it to one is a cast
/// that C requires rather than noise.
fn substituted_address_under_conversions<'a>(
    expr: &'a CExpr,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
) -> Option<(&'a CExpr, CType)> {
    match expr {
        CExpr::StringLit(_) => Some((expr, CType::ptr(plain_char_type()))),
        CExpr::AddrOf(inner) => match inner.unobserved() {
            CExpr::DataObject { address, .. } => {
                let object_type = used
                    .borrow()
                    .get(address)
                    .and_then(|object| object.type_fact.as_ref())
                    .map(|fact| fact.ty.clone())
                    .unwrap_or_else(|| CType::Array(Box::new(plain_char_type()), None));
                Some((expr, CType::ptr(object_type)))
            }
            _ => None,
        },
        CExpr::Observed { expr, .. } | CExpr::Paren(expr) | CExpr::Cast { expr, .. } => {
            substituted_address_under_conversions(expr, used)
        }
        _ => None,
    }
}

/// Restate the conversions around a substituted address.
///
/// `required` is what the place this expression sits in asks of it, for the
/// places that ask without spelling a cast -- a declaration's initialiser
/// asks for the declared type, an assignment's right-hand side for the type
/// of what it is assigned to. Inside an expression the enclosing conversion
/// is the ask, and the outermost one is what the whole chain amounted to.
///
/// The distinction matters because the conversion around a constant address
/// is often *nothing*: a `uint64_t` constant initialising a `uint64_t` needs
/// no cast, so after `&progName` is substituted there is no chain to notice
/// and the rendering assigns a pointer to an integer. That is not noise but
/// a type error, and `-Wint-conversion` in the corpus's own compile is what
/// found it.
fn restate_string_conversions_in_expr(
    expr: &mut CExpr,
    pointer_bits: u32,
    required: Option<&CType>,
    symbols: Option<&std::rc::Rc<std::cell::RefCell<crate::symbol::SymbolTable>>>,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
) {
    if let Some((address, from)) = substituted_address_under_conversions(expr, used) {
        let required = match expr.unobserved() {
            CExpr::Cast { ty, .. } => Some(ty.clone()),
            _ => required.cloned(),
        };
        let Some(required) = required else {
            return;
        };
        let restated = crate::fold::op_lower::convert::convert(
            address.clone(),
            &r2rewrite::CValue::Typed(from),
            &required,
            pointer_bits,
        );
        let source = std::mem::replace(expr, CExpr::IntLit(0));
        *expr = crate::ast::carry_all_expr_observations(&source, restated);
        return;
    }
    // A literal that the fold above rewrote, or that the renderer will spell
    // as the negative it stands for, carries no type of its own. `-0x4` is an
    // `int` whatever value it denotes, so reading it as a `uint64_t` is a
    // signedness-changing conversion; the constant fold produces exactly that
    // when it collapses a mask, after every conversion has been decided.
    if let Some(required) = required
        && crate::fold::op_lower::convert::literal_renders_as_signed(expr)
        && crate::fold::op_lower::convert::is_unsigned_integer(required, pointer_bits)
    {
        // The cast is built around the literal as it stands, markers and
        // all, so every occurrence it records is still in the tree exactly
        // once. Carrying them again would put each one in twice.
        let source = std::mem::replace(expr, CExpr::IntLit(0));
        *expr = CExpr::cast(required.clone(), source);
        return;
    }
    // A render marker and a bracket are metadata: what the place asks of the
    // expression it asks of the expression under them. Falling through to the
    // generic descent instead dropped the requirement, and every statement
    // whose right-hand side carries an occurrence marker -- which is most of
    // them -- was walked as though nothing had been asked of it.
    if let CExpr::Observed { expr, .. } | CExpr::Paren(expr) = expr {
        restate_string_conversions_in_expr(expr, pointer_bits, required, symbols, used);
        return;
    }
    // An assignment tells its right-hand side what is wanted: the type of
    // the object being written. A compound assignment says the same thing:
    // `x &= m` converts `m` to x's type exactly as `x = x & m` would.
    if let CExpr::Binary {
        op:
            BinaryOp::Assign
            | BinaryOp::AddAssign
            | BinaryOp::SubAssign
            | BinaryOp::MulAssign
            | BinaryOp::DivAssign
            | BinaryOp::ModAssign
            | BinaryOp::BitAndAssign
            | BinaryOp::BitOrAssign
            | BinaryOp::BitXorAssign
            | BinaryOp::ShlAssign
            | BinaryOp::ShrAssign,
        left,
        right,
    } = expr
    {
        let target = match left.unobserved() {
            CExpr::Var(symbol) => symbols.map(|table| table.borrow().get(*symbol).ty.clone()),
            _ => None,
        };
        restate_string_conversions_in_expr(left, pointer_bits, None, symbols, used);
        restate_string_conversions_in_expr(right, pointer_bits, target.as_ref(), symbols, used);
        return;
    }
    // Arithmetic on an address is arithmetic on a number. C has one operator
    // that means anything by a pointer operand, and it counts elements rather
    // than bytes -- and `&name` is a pointer to an incomplete array, which C
    // will not do arithmetic on at all. So an address that reaches an
    // arithmetic operator crosses into the address integer first, and the
    // conversion back to a pointer is whatever the surrounding place asks
    // for.
    if let CExpr::Binary { op, left, right } = expr
        && matches!(
            op,
            BinaryOp::Add
                | BinaryOp::Sub
                | BinaryOp::Mul
                | BinaryOp::Shl
                | BinaryOp::Shr
                | BinaryOp::BitAnd
                | BinaryOp::BitOr
                | BinaryOp::BitXor
                | BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge
        )
    {
        // An address takes the address integer, because arithmetic on an
        // address is arithmetic on a number. The operator's own operand rule
        // is otherwise left alone: restating it from this pass, which knows
        // the address width and nothing else, would widen a narrow
        // computation and change what it computes.
        //
        // A literal is the exception, and only for the operators whose
        // operands C converts to the result's type. There the type the whole
        // expression is read at is the type the operand is read at, so a
        // literal the renderer spells as a negative -- an `int` to the
        // compiler whatever value it denotes -- can be given that type. A
        // shift's count is not such an operand: it keeps its own type, and
        // saying otherwise would be a claim about a different thing.
        let address = CType::uint(pointer_bits);
        let converted_together = !matches!(op, BinaryOp::Shl | BinaryOp::Shr);
        // A comparison's operands are converted to each other rather than to
        // the type the comparison is read at, which is a truth value. So the
        // type a literal takes there is the other operand's, and the only
        // other operand this pass can ask about is a name.
        let comparison = matches!(
            op,
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
        );
        let peer = |other: &CExpr| match other.unobserved() {
            CExpr::Var(symbol) => symbols.map(|table| table.borrow().get(*symbol).ty.clone()),
            _ => None,
        };
        let peers = comparison.then(|| (peer(right), peer(left)));
        for (index, operand) in [&mut *left, &mut *right].into_iter().enumerate() {
            let peer_type = peers.as_ref().and_then(|(for_left, for_right)| {
                if index == 0 { for_left } else { for_right }.clone()
            });
            let wanted = if substituted_address_under_conversions(operand, used).is_some() {
                Some(address.clone())
            } else if !crate::fold::op_lower::convert::literal_renders_as_signed(operand) {
                None
            } else if comparison {
                peer_type
            } else if index == 0 || converted_together {
                required.cloned()
            } else {
                None
            };
            restate_string_conversions_in_expr(
                operand,
                pointer_bits,
                wanted.as_ref(),
                symbols,
                used,
            );
        }
        return;
    }
    let taken = std::mem::replace(expr, CExpr::IntLit(0));
    *expr = taken.map_children(&mut |mut child| {
        restate_string_conversions_in_expr(&mut child, pointer_bits, None, symbols, used);
        child
    });
}

/// Replace a machine-width load through a substituted global address with the
/// source-typed object itself.
///
/// The rewrite is authorized only when radare2 supplied the object's type and
/// the machine load clears that type's storage width. The address and load are
/// already proven by the ordinary memory path; this removes the byte-pointer
/// cast that was needed only while the object had no type.
fn simplify_typed_data_object_loads(
    expr: &mut CExpr,
    pointer_bits: u32,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
) {
    let taken = std::mem::replace(expr, CExpr::IntLit(0));
    *expr = taken.map_children(&mut |mut child| {
        simplify_typed_data_object_loads(&mut child, pointer_bits, used);
        child
    });

    let CExpr::Deref(address) = expr.unobserved() else {
        return;
    };
    let Some((object_address, name)) = data_object_under_conversions(address) else {
        return;
    };
    let name = name.to_string();
    let Some(object_type) = used
        .borrow()
        .get(&object_address)
        .and_then(|object| object.type_fact.as_ref())
        .map(|fact| fact.ty.clone())
    else {
        return;
    };
    let access_type =
        pointer_target_under_conversions(address).unwrap_or_else(|| object_type.clone());
    if access_type != object_type {
        let Some(access_bits) = c_object_storage_bits(&access_type, pointer_bits) else {
            return;
        };
        let Some(object_bits) = c_object_storage_bits(&object_type, pointer_bits) else {
            return;
        };
        if access_bits != object_bits {
            return;
        }
    }
    let source = std::mem::replace(expr, CExpr::IntLit(0));
    *expr = crate::ast::carry_all_expr_observations(
        &source,
        CExpr::DataObject {
            address: object_address,
            name,
        },
    );
}

fn data_object_under_conversions(expr: &CExpr) -> Option<(u64, &str)> {
    match expr.unobserved() {
        CExpr::AddrOf(inner) => match inner.unobserved() {
            CExpr::DataObject { address, name } => Some((*address, name)),
            _ => None,
        },
        CExpr::Cast { expr, .. } | CExpr::Paren(expr) => data_object_under_conversions(expr),
        _ => None,
    }
}

fn pointer_target_under_conversions(expr: &CExpr) -> Option<CType> {
    match expr.unobserved() {
        CExpr::Cast {
            ty: CType::Pointer(inner),
            ..
        } => Some(inner.as_ref().clone()),
        CExpr::Cast { expr, .. } | CExpr::Paren(expr) => pointer_target_under_conversions(expr),
        _ => None,
    }
}

fn c_object_storage_bits(ty: &CType, pointer_bits: u32) -> Option<u32> {
    match ty {
        CType::Bool => Some(8),
        CType::Int { bits, .. } | CType::Float(bits) | CType::BitVector(bits) => Some(*bits),
        CType::Pointer(_) | CType::Function { .. } => Some(pointer_bits),
        CType::Array(element, Some(len)) => {
            c_object_storage_bits(element, pointer_bits)?.checked_mul(u32::try_from(*len).ok()?)
        }
        CType::Void
        | CType::Array(_, None)
        | CType::Struct(_)
        | CType::Union(_)
        | CType::Enum(_)
        | CType::Typedef(_)
        | CType::Unknown => None,
    }
}

fn fold_constant_arithmetic_in_stmt(
    stmt: &mut CStmt,
    strings: &std::collections::BTreeMap<u64, String>,
    symbols: &std::collections::BTreeMap<u64, String>,
    object_types: &r2types::ProgramDataObjectTypeFacts,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
    pointer_bits: u32,
    symbol_table: Option<&std::rc::Rc<std::cell::RefCell<crate::symbol::SymbolTable>>>,
) {
    // The substitution and the restatement of what it changed are one visit
    // of one expression: a conversion can only be restated once the string
    // it converts is there to be seen.
    let fold_expr = |expr: &mut CExpr| {
        fold_constant_arithmetic_in_expr(expr, strings, symbols, object_types, used);
        restate_string_conversions_in_expr(expr, pointer_bits, None, symbol_table, used);
        simplify_typed_data_object_loads(expr, pointer_bits, used);
    };
    match stmt {
        CStmt::StructuredRegion { stmt, .. } => fold_constant_arithmetic_in_stmt(
            stmt,
            strings,
            symbols,
            object_types,
            used,
            pointer_bits,
            symbol_table,
        ),
        CStmt::Observed { stmt, .. } => fold_constant_arithmetic_in_stmt(
            stmt,
            strings,
            symbols,
            object_types,
            used,
            pointer_bits,
            symbol_table,
        ),
        CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
        CStmt::Expr(expr) => fold_expr(expr),
        CStmt::Decl { ty, init, .. } => {
            if let Some(init) = init {
                fold_constant_arithmetic_in_expr(init, strings, symbols, object_types, used);
                restate_string_conversions_in_expr(
                    init,
                    pointer_bits,
                    Some(ty),
                    symbol_table,
                    used,
                );
                simplify_typed_data_object_loads(init, pointer_bits, used);
            }
        }
        CStmt::Return(expr) => {
            if let Some(expr) = expr {
                fold_expr(expr);
            }
        }
        CStmt::Block(stmts) => {
            for stmt in stmts {
                fold_constant_arithmetic_in_stmt(
                    stmt,
                    strings,
                    symbols,
                    object_types,
                    used,
                    pointer_bits,
                    symbol_table,
                );
            }
        }
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            fold_expr(cond);
            fold_constant_arithmetic_in_stmt(
                then_body,
                strings,
                symbols,
                object_types,
                used,
                pointer_bits,
                symbol_table,
            );
            if let Some(else_body) = else_body {
                fold_constant_arithmetic_in_stmt(
                    else_body,
                    strings,
                    symbols,
                    object_types,
                    used,
                    pointer_bits,
                    symbol_table,
                );
            }
        }
        CStmt::While { cond, body } | CStmt::DoWhile { body, cond } => {
            fold_expr(cond);
            fold_constant_arithmetic_in_stmt(
                body,
                strings,
                symbols,
                object_types,
                used,
                pointer_bits,
                symbol_table,
            );
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                fold_constant_arithmetic_in_stmt(
                    init,
                    strings,
                    symbols,
                    object_types,
                    used,
                    pointer_bits,
                    symbol_table,
                );
            }
            if let Some(cond) = cond {
                fold_expr(cond);
            }
            if let Some(update) = update {
                fold_expr(update);
            }
            fold_constant_arithmetic_in_stmt(
                body,
                strings,
                symbols,
                object_types,
                used,
                pointer_bits,
                symbol_table,
            );
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            fold_expr(expr);
            for case in cases {
                for stmt in &mut case.body {
                    fold_constant_arithmetic_in_stmt(
                        stmt,
                        strings,
                        symbols,
                        object_types,
                        used,
                        pointer_bits,
                        symbol_table,
                    );
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    fold_constant_arithmetic_in_stmt(
                        stmt,
                        strings,
                        symbols,
                        object_types,
                        used,
                        pointer_bits,
                        symbol_table,
                    );
                }
            }
        }
    }
}

/// The unsigned value of an integer literal, ignoring any cast around it.
fn literal_value(expr: &CExpr) -> Option<u64> {
    match expr {
        CExpr::Observed { expr, .. } => literal_value(expr),
        CExpr::UIntLit(value) => Some(*value),
        CExpr::IntLit(value) => u64::try_from(*value).ok(),
        CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => literal_value(inner),
        _ => None,
    }
}

fn fold_constant_arithmetic_in_expr(
    expr: &mut CExpr,
    strings: &std::collections::BTreeMap<u64, String>,
    symbols: &std::collections::BTreeMap<u64, String>,
    object_types: &r2types::ProgramDataObjectTypeFacts,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
) {
    if let CExpr::Observed { expr, .. } = expr {
        fold_constant_arithmetic_in_expr(expr, strings, symbols, object_types, used);
        return;
    }
    let mut replacement = None;
    match expr {
        CExpr::Unary { operand, .. }
        | CExpr::Cast { expr: operand, .. }
        | CExpr::Sizeof(operand)
        | CExpr::AddrOf(operand)
        | CExpr::Deref(operand)
        | CExpr::Paren(operand) => {
            fold_constant_arithmetic_in_expr(operand, strings, symbols, object_types, used)
        }
        CExpr::Binary { op, left, right } => {
            fold_constant_arithmetic_in_expr(left, strings, symbols, object_types, used);
            fold_constant_arithmetic_in_expr(right, strings, symbols, object_types, used);
            if let (Some(lhs), Some(rhs)) = (literal_value(left), literal_value(right)) {
                // Wrapping, because the program's arithmetic wraps; a fold that
                // disagreed with the machine would be worse than no fold.
                let folded = match op {
                    BinaryOp::Add => Some(lhs.wrapping_add(rhs)),
                    BinaryOp::Sub => Some(lhs.wrapping_sub(rhs)),
                    _ => None,
                };
                if let Some(folded) = folded {
                    replacement = Some(CExpr::UIntLit(folded));
                }
            }
        }
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            fold_constant_arithmetic_in_expr(cond, strings, symbols, object_types, used);
            fold_constant_arithmetic_in_expr(then_expr, strings, symbols, object_types, used);
            fold_constant_arithmetic_in_expr(else_expr, strings, symbols, object_types, used);
        }
        CExpr::Call { func, args, .. } => {
            fold_constant_arithmetic_in_expr(func, strings, symbols, object_types, used);
            for arg in args {
                fold_constant_arithmetic_in_expr(arg, strings, symbols, object_types, used);
            }
        }
        CExpr::Subscript { base, index } => {
            fold_constant_arithmetic_in_expr(base, strings, symbols, object_types, used);
            fold_constant_arithmetic_in_expr(index, strings, symbols, object_types, used);
        }
        CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
            fold_constant_arithmetic_in_expr(base, strings, symbols, object_types, used)
        }
        CExpr::Comma(items) => {
            for item in items {
                fold_constant_arithmetic_in_expr(item, strings, symbols, object_types, used);
            }
        }
        _ => {}
    }
    if let Some(replacement) = replacement {
        let source = std::mem::replace(expr, CExpr::IntLit(0));
        // Every marker in the collapsed subtree, not only the outermost:
        // folding a cast chain down to one literal deletes the nodes the inner
        // markers sat on, and the one literal is what renders them now.
        *expr = crate::ast::carry_all_expr_observations(&source, replacement);
    }
    // Once the address is one number the string table can answer for it.
    if let Some(value) = literal_value(expr)
        && let Some(text) = strings.get(&value)
    {
        let source = std::mem::replace(expr, CExpr::IntLit(0));
        *expr = crate::ast::carry_all_expr_observations(&source, CExpr::StringLit(text.clone()));
        return;
    }
    // And so can the object table, for an address radare2 has a name for.
    //
    // The address is taken rather than the object's value: `lea` puts the
    // address of the object in the register, so `&progName` is what the
    // constant is. Rendering the number instead loses a name the analysis
    // already had and that a reader cannot recover from it.
    if let Some(value) = literal_value(expr)
        && let Some(name) = symbols.get(&value)
    {
        let source = std::mem::replace(expr, CExpr::IntLit(0));
        let rendered = c_identifier_for_data_symbol(name);
        let type_fact = object_types.get(value).cloned();
        let type_refusal = object_types.refused().get(&value).cloned();
        used.borrow_mut().insert(
            value,
            crate::ast::CExternObject {
                name: rendered.clone(),
                address: value,
                type_fact,
                type_refusal,
            },
        );
        *expr = crate::ast::carry_all_expr_observations(
            &source,
            CExpr::addr_of(CExpr::DataObject {
                address: value,
                name: rendered,
            }),
        );
    }
}

/// The C name for a radare2 data flag.
///
/// The fact is kept as radare2 stated it -- `obj.progName`, `reloc.stderr` --
/// because that is what the analysis said and what the proof line answers for.
/// What C can take is the name without the flag space that qualifies it, and
/// with anything left that is not an identifier character replaced, so the
/// rendered program declares `progName` rather than a dotted spelling no
/// compiler accepts.
fn c_identifier_for_data_symbol(flag: &str) -> String {
    const SPACES: [&str; 6] = ["obj.", "reloc.", "segment.", "section.", "str.", "sym."];
    let mut name = flag;
    loop {
        let Some(stripped) = SPACES.iter().find_map(|space| name.strip_prefix(space)) else {
            break;
        };
        name = stripped;
    }
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.starts_with(|c: char| c.is_ascii_digit()) {
        format!("g_{cleaned}")
    } else {
        cleaned
    }
}

fn typed_integer_literal_expr(value: u64, is_signed: bool, bits: u32) -> CExpr {
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let truncated = value & mask;
    if is_signed {
        let sign_bit = 1u64 << (bits - 1);
        if truncated & sign_bit != 0 {
            return CExpr::IntLit((truncated | (!mask)) as i64);
        }
        return CExpr::IntLit(truncated as i64);
    }
    if bits == 64 || truncated > 0x7fff_ffff {
        CExpr::UIntLit(truncated)
    } else {
        CExpr::IntLit(truncated as i64)
    }
}

/// Every label a `goto` in this statement names.
fn collect_goto_targets(statement: &CStmt, into: &mut std::collections::BTreeSet<String>) {
    match statement {
        CStmt::Goto(label) => {
            into.insert(label.clone());
        }
        CStmt::Observed { stmt, .. } | CStmt::StructuredRegion { stmt, .. } => {
            collect_goto_targets(stmt, into);
        }
        CStmt::Block(statements) => {
            for statement in statements {
                collect_goto_targets(statement, into);
            }
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            collect_goto_targets(then_body, into);
            if let Some(else_body) = else_body {
                collect_goto_targets(else_body, into);
            }
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            collect_goto_targets(body, into);
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                collect_goto_targets(init, into);
            }
            collect_goto_targets(body, into);
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                for statement in &case.body {
                    collect_goto_targets(statement, into);
                }
            }
            if let Some(default) = default {
                for statement in default {
                    collect_goto_targets(statement, into);
                }
            }
        }
        CStmt::Empty
        | CStmt::Expr(_)
        | CStmt::Decl { .. }
        | CStmt::Return(_)
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_extern_objects()
    -> std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>> {
        std::cell::RefCell::new(std::collections::BTreeMap::new())
    }

    #[test]
    fn a_compared_mask_takes_the_type_of_what_it_is_compared_with() {
        // `tmp < -0x4` where `tmp` is a `uint64_t`. The comparison is read as
        // a truth value, so the type the mask needs is not the statement's --
        // it is the other operand's, and `-0x4` is an `int` until something
        // says otherwise.
        let mut symbols = crate::symbol::SymbolTable::new();
        let name = symbols.reserve_binding(
            "tmp_3ea80_2".to_string(),
            CType::u64(),
            crate::symbol::SymbolRole::Carrier,
        );
        let table = std::rc::Rc::new(std::cell::RefCell::new(symbols));
        let mut owner = crate::ast::RenderObservationOwner::new();
        let (_, marked) = owner
            .observe_expr(CExpr::binary(
                BinaryOp::Lt,
                CExpr::Var(name),
                CExpr::UIntLit(0xffff_ffff_ffff_fffc),
            ))
            .expect("the statement's own occurrence marker");
        let mut expr = marked;
        restate_string_conversions_in_expr(
            &mut expr,
            64,
            Some(&CType::u8()),
            Some(&table),
            &no_extern_objects(),
        );
        let CExpr::Observed { expr: inner, .. } = &expr else {
            panic!("the marker must survive: {expr:?}");
        };
        let CExpr::Binary { right, .. } = inner.as_ref() else {
            panic!("expected the comparison, got {inner:?}");
        };
        assert!(
            matches!(right.as_ref(), CExpr::Cast { ty, .. } if *ty == CType::u64()),
            "the mask takes the compared operand's type, not the flag's: {right:?}"
        );
    }

    #[test]
    fn a_mask_under_a_render_marker_still_takes_the_type_that_reads_it() {
        // The shape every statement has in production: the right-hand side
        // carries an occurrence marker. `X1_0 & -0x4` on a `uint64_t` is a
        // signedness-changing conversion, because `-0x4` is an `int`
        // whatever value it denotes, and the marker must not hide the ask.
        let mut symbols = crate::symbol::SymbolTable::new();
        let name = symbols.reserve_binding(
            "X1_0".to_string(),
            CType::u64(),
            crate::symbol::SymbolRole::Carrier,
        );
        let table = std::rc::Rc::new(std::cell::RefCell::new(symbols));
        let mask = CExpr::UIntLit(0xffff_ffff_ffff_fffc);
        let mut owner = crate::ast::RenderObservationOwner::new();
        let (_, marked) = owner
            .observe_expr(CExpr::binary(BinaryOp::BitAnd, CExpr::Var(name), mask))
            .expect("the statement's own occurrence marker");
        let mut expr = marked;
        restate_string_conversions_in_expr(
            &mut expr,
            64,
            Some(&CType::u64()),
            Some(&table),
            &no_extern_objects(),
        );
        let CExpr::Observed { expr: inner, .. } = &expr else {
            panic!("the marker must survive: {expr:?}");
        };
        let CExpr::Binary { right, .. } = inner.as_ref() else {
            panic!("expected the masking, got {inner:?}");
        };
        assert!(
            matches!(right.as_ref(), CExpr::Cast { ty, .. } if *ty == CType::u64()),
            "the mask must say it is a uint64_t, got {right:?}"
        );
    }

    #[test]
    fn a_string_address_drops_the_conversions_spelled_for_its_number() {
        // A string reaches a `char *` as itself: the conversions above the
        // constant were spelled while it was a number, and substituting the
        // string makes every one of them a statement about a type the
        // expression no longer has.
        let text = CExpr::StringLit("usage: %s\n".to_string());
        let char_ptr = CType::ptr(plain_char_type());
        let mut expr = CExpr::cast(
            char_ptr.clone(),
            CExpr::cast(
                CType::Int {
                    bits: 64,
                    signedness: r2types::Signedness::Unsigned,
                },
                text.clone(),
            ),
        );
        restate_string_conversions_in_expr(&mut expr, 64, None, None, &no_extern_objects());
        assert_eq!(expr, text, "got {expr:?}");

        // Converted to a number, the string is still an address, so the
        // conversion that is C's own is the one that survives -- and it is
        // recorded as the address-width step, so a round trip collapses.
        let mut as_number = CExpr::cast(
            CType::Int {
                bits: 64,
                signedness: r2types::Signedness::Unsigned,
            },
            text.clone(),
        );
        restate_string_conversions_in_expr(&mut as_number, 64, None, None, &no_extern_objects());
        assert!(
            matches!(
                &as_number,
                CExpr::Cast {
                    ty: CType::Int { bits: 64, .. },
                    role: crate::ast::CastRole::PointerWidthStep,
                    ..
                }
            ),
            "got {as_number:?}"
        );
        let _ = char_ptr;
    }

    /// What the two type models lose when a type crosses between them.
    ///
    /// `r2dec` and `r2types` each have a type enum and a renderer, and the two
    /// renderers already disagreed once -- about how to spell a 128-bit integer
    /// -- with nothing to catch it. Before the two are folded into one model,
    /// this records exactly which types do not survive the trip, so the fold is
    /// closing a measured gap rather than an assumed one.
    use r2il::{
        ArchSpec, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
        RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
    };
    use r2ssa::SSAFunction;
    use r2types::{FunctionParamSpec, FunctionSignatureSpec};
    use std::collections::{BTreeMap, HashMap};

    fn empty_fold_context_for_linearization<'a>() -> FoldingContext<'a> {
        let arch = Box::leak(Box::new(FoldArchConfig {
            ptr_size: 8,
            arg_regs: vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ],
        }));
        FoldingContext::from_inputs(FoldInputs {
            normalization_origins: None,
            observation_journal: None,
            arch,
            function_names: Box::leak(Box::new(HashMap::new())),
            binary_symbols: Box::leak(Box::new(HashMap::new())),
            function_facts: crate::fold::context::empty_function_facts(),
            stack_slots: Box::leak(Box::new(BTreeMap::new())),
            visible_bindings: Box::leak(Box::new(Vec::new())),
            function_return_type: None,
            prepared_ssa: None,
            binding_names: None,
            prepared_semantic_view: None,
        })
    }

    #[test]
    fn linearized_conditional_branch_without_predicate_is_residual_comment() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: Varnode::constant(0x2000, 8),
                    cond: Varnode::constant(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: Varnode::constant(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x2000,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: Varnode::constant(1, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];
        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("raw SSA function");
        func.get_block_mut(0x1000).expect("entry block").ops.clear();
        let block = func.get_block(0x1000).expect("entry block");
        let fold_ctx = empty_fold_context_for_linearization();

        let stmt = Decompiler::linearized_terminator_stmt(&func, &fold_ctx, block)
            .expect("linearized residual terminator");
        let CStmt::Comment(comment) = stmt else {
            panic!("unresolved conditional branch must not fabricate executable control: {stmt:?}");
        };
        assert!(comment.contains("conditional branch condition unresolved"));
        assert!(comment.contains("true_target=loc_2000"));
        assert!(comment.contains("false_target=loc_1004"));
    }

    fn prepared_from_ops(ops: Vec<R2ILOp>, arch: &ArchSpec) -> r2ssa::SsaArtifact {
        let mut block = R2ILBlock::new(0x1000, 4);
        for op in ops {
            block.push(op);
        }
        prepared_from_blocks(&[block], arch)
    }

    fn prepared_from_blocks(blocks: &[R2ILBlock], arch: &ArchSpec) -> r2ssa::SsaArtifact {
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"r2dec-source-owned-fixture".to_vec(),
            "sysv64",
            std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
            r2ssa::SourceFunctionReturn::Register {
                storage: storage(0),
            },
            std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
        )
        .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
        .expect("exact test source interface");
        r2ssa::SsaArtifact::for_decompile_with_interface(blocks, Some(arch), interface)
            .expect("prepared SSA should build")
            .with_name("stable_demo")
    }

    fn source_owned_type_analysis(
        prepared: impl Into<Arc<r2ssa::SsaArtifact>>,
    ) -> r2types::TypeWritebackAnalysis {
        let prepared = prepared.into();
        let request = r2types::TypeWritebackAnalysisRequest::new(
            Arc::clone(&prepared),
            r2types::ParsedExternalContext::default(),
        )
        .expect("test source assumptions");
        r2types::build_source_owned_type_writeback_analysis(request)
            .expect("source-owned test analysis")
    }

    fn source_owned_decompiler_input(
        prepared: impl Into<Arc<r2ssa::SsaArtifact>>,
        route: (r2types::DecompileRouteKind, &'static str, Option<String>),
    ) -> DecompilerInput {
        let (kind, reason, fallback_comment) = route;
        let source_owned_facts = source_owned_type_analysis(prepared)
            .finalize_for_decompile(r2types::DecompileFinalization {
                kind,
                reason: reason.to_string(),
                fallback_comment,
            })
            .expect("compatible source-owned decompile finalization");
        DecompilerInput::new(source_owned_facts)
    }

    /// A comparison written directly into the logical low byte of the ABI
    /// result carrier, rendered through the complete source-owned pipeline.
    #[test]
    fn a_logical_low_byte_return_renders() {
        let mut arch = test_arch_for_decompile();
        arch.add_register(RegisterDef::sub("AL", 0, 1, "RAX"));
        arch.register_projections.push(RegisterProjection {
            written: RegisterStorage { offset: 0, size: 1 },
            disposition: RegisterProjectionDisposition::Bound {
                carrier: RegisterStorage { offset: 0, size: 8 },
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: 8,
                },
            },
        });
        arch.register_projections
            .sort_by_key(|projection| projection.written);

        let storage = |offset, size| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size,
        };
        let logical_u64 = r2ssa::SourceLogicalValue::new(
            0,
            r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
        );
        let logical_u8 = r2ssa::SourceLogicalValue::new(
            1,
            r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::LowBits, 0, 8),
        );
        let type_graph = r2ssa::SourceTypeGraph::new(
            [
                r2ssa::SourceType::new(0, r2ssa::SourceTypeKind::UnsignedInteger, 64, 64),
                r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::UnsignedInteger, 8, 8),
            ],
            [],
        )
        .expect("exact boolean-return type graph");
        let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
            b"logical-low-byte-return".to_vec(),
            "sysv64",
            [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10, 8))],
            r2ssa::SourceFunctionReturn::Register {
                storage: storage(0, 8),
            },
            [],
            [logical_u64],
            Some(logical_u8),
            Some(type_graph),
        )
        .and_then(|interface| interface.with_return_address_storage(storage(0x30, 8)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28, 8)))
        .expect("exact boolean-return interface");

        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntLess {
            dst: Varnode::register(0, 1),
            a: Varnode::constant(7, 8),
            b: Varnode::register(0x10, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(0x30, 8),
        });
        let prepared =
            r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
                .expect("prepared boolean return")
                .with_name("shape_bool_probe");
        let boundary = prepared
            .facts()
            .boundaries
            .returns
            .values()
            .next()
            .expect("boolean return boundary");
        assert!(boundary.complete);
        let [boundary_value] = boundary.values.as_slice() else {
            panic!("logical low-byte return must carry one value")
        };
        assert!(
            prepared
                .graph()
                .value(boundary_value.value)
                .is_some_and(|value| {
                    value.var.size == 1 && value.canonical_storage == Some(storage(0, 1))
                })
        );

        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "logical low-byte return route",
                None,
            ),
        );
        let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
        assert!(
            !output.contains("fallback") && !output.contains("native rendering refused"),
            "an exact logical low-byte result must render: {output}"
        );
        assert!(output.contains("uint8_t shape_bool_probe("), "{output}");
        assert!(
            output.contains("return ") && output.contains(" < "),
            "{output}"
        );
    }

    /// A call whose stack pointer the convention restores, rendered end to end.
    #[test]
    fn a_restored_stack_pointer_renders() {
        let arch = test_arch_for_decompile();
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let rsp = Varnode::register(0x28, 8);
        let rip = Varnode::register(0x30, 8);

        // One arm calls and one does not, so their restored stack pointers
        // meet in a phi that is also the same machine object.
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::IntNotEqual {
            dst: Varnode::unique(0x80, 1),
            a: Varnode::register(0x10, 8),
            b: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1008, 8),
            cond: Varnode::unique(0x80, 1),
        });
        let mut no_call = R2ILBlock::new(0x1004, 4);
        no_call.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });

        let mut call_ops = vec![R2ILOp::IntSub {
            dst: rsp.clone(),
            a: rsp.clone(),
            b: Varnode::constant(8, 8),
        }];
        call_ops.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: rsp.clone(),
            val: Varnode::constant(0x100d, 8),
        });
        call_ops.push(R2ILOp::Call {
            target: Varnode::constant(0x2000, 8),
        });
        let mut call_meta = std::collections::BTreeMap::new();
        for i in 0..call_ops.len() {
            call_meta.insert(
                i,
                r2il::OpMetadata {
                    instruction_addr: Some(0x1008),
                    ..Default::default()
                },
            );
        }
        call_ops.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let called = R2ILBlock {
            addr: 0x1008,
            size: 8,
            ops: call_ops,
            switch_info: None,
            op_metadata: call_meta,
        };

        let mut exit_ops = vec![R2ILOp::Load {
            dst: rip.clone(),
            space: SpaceId::Ram,
            addr: rsp.clone(),
        }];
        exit_ops.push(R2ILOp::IntAdd {
            dst: rsp.clone(),
            a: rsp.clone(),
            b: Varnode::constant(8, 8),
        });
        exit_ops.push(R2ILOp::Return {
            target: rip.clone(),
        });
        let mut exit_meta = std::collections::BTreeMap::new();
        for i in 0..exit_ops.len() {
            exit_meta.insert(
                i,
                r2il::OpMetadata {
                    instruction_addr: Some(0x1010),
                    ..Default::default()
                },
            );
        }
        let exit = R2ILBlock {
            addr: 0x1010,
            size: 4,
            ops: exit_ops,
            switch_info: None,
            op_metadata: exit_meta,
        };
        let blocks = [entry, no_call, called, exit];

        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"restore-fixture".to_vec(),
            "sysv64",
            [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
            r2ssa::SourceFunctionReturn::Void,
            std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
        )
        .and_then(|i| i.with_return_address_storage(storage(0x30)))
        .and_then(|i| i.with_stack_pointer_storage(storage(0x28)))
        .expect("interface")
        .with_preserved_call_carriers(true, true);
        let prepared =
            r2ssa::SsaArtifact::for_decompile_with_interface(&blocks, Some(&arch), interface)
                .expect("prepared")
                .with_name("restore_demo");
        let restores = prepared
            .function()
            .get_block(0x1008)
            .expect("call arm")
            .ops
            .iter()
            .filter(|op| matches!(op, r2ssa::SSAOp::CallRestore { .. }))
            .count();
        assert_eq!(restores, 1, "the call moved the carrier, so it is restored");
        assert!(
            prepared
                .function()
                .get_block(0x1010)
                .expect("join")
                .phis
                .iter()
                .any(|phi| phi.canonical_storage == Some(storage(0x28))),
            "the called and uncalled paths must merge their stack carriers"
        );
        let input = source_owned_decompiler_input(
            prepared,
            (r2types::DecompileRouteKind::Standard, "restore route", None),
        );
        let decompiler = Decompiler::new(DecompilerConfig::x86_64());
        let output = decompiler.decompile_input(&input);
        // The restore performs nothing and says so: its two sides are one
        // object, licensed by the convention, so both its read and its write
        // are accounted as a coalesced copy rather than left for the seal to
        // find. Before that licence existed this refused outright, first for
        // an unaccounted read of the entry carrier and then for a write with
        // no rendered occurrence.
        assert!(
            !output.contains("native render refusal"),
            "a restored carrier must not refuse the function: {output}"
        );
        assert!(
            output.contains("0 unaccounted"),
            "the restore accounts for both of its sides: {output}"
        );
    }

    /// A restore whose certified output is dead still has no C occurrence.
    #[test]
    fn an_unused_restored_stack_pointer_renders() {
        let arch = test_arch_for_decompile();
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let rsp = Varnode::register(0x28, 8);
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::IntNotEqual {
            dst: Varnode::unique(0x80, 1),
            a: Varnode::register(0x10, 8),
            b: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1008, 8),
            cond: Varnode::unique(0x80, 1),
        });
        let mut no_call = R2ILBlock::new(0x1004, 4);
        no_call.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut called = R2ILBlock::new(0x1008, 8);
        called.push(R2ILOp::IntSub {
            dst: rsp.clone(),
            a: rsp.clone(),
            b: Varnode::constant(8, 8),
        });
        called.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: rsp,
            val: Varnode::constant(0x100d, 8),
        });
        called.push(R2ILOp::Call {
            target: Varnode::constant(0x2000, 8),
        });
        for i in 0..called.ops.len() {
            called.op_metadata.insert(
                i,
                r2il::OpMetadata {
                    instruction_addr: Some(0x1008),
                    ..Default::default()
                },
            );
        }
        called.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut exit = R2ILBlock::new(0x1010, 4);
        exit.push(R2ILOp::Breakpoint);
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"unused-restore-fixture".to_vec(),
            "sysv64",
            std::iter::empty::<r2ssa::SourceAbiParameterSpec>(),
            r2ssa::SourceFunctionReturn::Void,
            std::iter::empty::<r2ssa::SourceStackSlotSpec>(),
        )
        .and_then(|i| i.with_return_address_storage(storage(0x30)))
        .and_then(|i| i.with_stack_pointer_storage(storage(0x28)))
        .expect("interface")
        .with_preserved_call_carriers(true, true);
        let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
            &[entry, no_call, called, exit],
            Some(&arch),
            interface,
        )
        .expect("prepared")
        .with_name("unused_restore_demo");
        let restore_outputs = prepared
            .graph()
            .insts
            .iter()
            .filter(|inst| {
                matches!(
                    inst.payload,
                    r2ssa::InstPayload::Op(r2ssa::SSAOp::CallRestore { .. })
                )
            })
            .filter_map(|inst| inst.output)
            .collect::<Vec<_>>();
        assert_eq!(restore_outputs.len(), 1, "one stack carrier is restored");
        let structural_unused = prepared
            .obligations()
            .structural_unused_values(
                prepared.graph(),
                prepared.unobserved_merges().unobserved_uses(),
            )
            .expect("complete structural-value inventory");
        assert!(
            restore_outputs
                .iter()
                .all(|value| structural_unused.contains(value)),
            "the regression requires an unused restore output"
        );

        let input = source_owned_decompiler_input(
            prepared,
            (r2types::DecompileRouteKind::Standard, "restore route", None),
        );
        let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
        assert!(
            !output.contains("native render refusal"),
            "an unused restored carrier must not refuse the function: {output}"
        );
        assert!(
            output.contains("0 unaccounted"),
            "the structural elision accounts for the restore operand: {output}"
        );
    }

    fn test_arch_for_decompile() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        let registers = [
            (
                "RAX",
                RegisterStorage {
                    offset: 0x00,
                    size: 8,
                },
            ),
            (
                "RDI",
                RegisterStorage {
                    offset: 0x10,
                    size: 8,
                },
            ),
            (
                "RSI",
                RegisterStorage {
                    offset: 0x18,
                    size: 8,
                },
            ),
            (
                "RBP",
                RegisterStorage {
                    offset: 0x20,
                    size: 8,
                },
            ),
            (
                "RSP",
                RegisterStorage {
                    offset: 0x28,
                    size: 8,
                },
            ),
            (
                "RIP",
                RegisterStorage {
                    offset: 0x30,
                    size: 8,
                },
            ),
        ];
        for (name, storage) in registers {
            arch.add_register(RegisterDef::new(name, storage.offset, storage.size));
            arch.register_projections.push(RegisterProjection {
                written: storage,
                disposition: RegisterProjectionDisposition::Bound {
                    carrier: storage,
                    slice: RegisterBitSlice {
                        lsb_bit_offset: 0,
                        size_bits: u64::from(storage.size) * 8,
                    },
                },
            });
        }
        arch
    }

    fn signature_spec(
        ret_type: Option<CType>,
        params: Vec<(&str, Option<CType>)>,
    ) -> FunctionSignatureSpec {
        FunctionSignatureSpec {
            ret_type: ret_type.as_ref().cloned(),
            params: params
                .into_iter()
                .map(|(name, ty)| FunctionParamSpec {
                    name: name.to_string(),
                    ty: ty.as_ref().cloned(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_decompiler_config_default() {
        let config = DecompilerConfig::default();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "rsp");
        assert_eq!(config.fp_name, "rbp");
    }

    #[test]
    fn test_decompiler_config_x86() {
        let config = DecompilerConfig::x86();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "esp");
        assert_eq!(config.fp_name, "ebp");
    }

    #[test]
    fn test_decompiler_config_arm() {
        let config = DecompilerConfig::arm();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "fp");
    }

    #[test]
    fn test_decompiler_config_aarch64() {
        let config = DecompilerConfig::aarch64();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "x29");
        assert_eq!(config.arg_regs[0], "x0");
        assert_eq!(config.ret_regs[0], "x0");
        assert!(config.caller_saved_regs.contains("x17"));
    }

    #[test]
    fn test_decompiler_config_riscv32() {
        let config = DecompilerConfig::riscv32();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "s0");
    }

    #[test]
    fn test_decompiler_config_riscv64() {
        let config = DecompilerConfig::riscv64();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "s0");
    }

    #[test]
    fn folded_constant_keeps_every_observation_it_collapsed() {
        let mut observations = crate::ast::RenderObservationOwner::new();
        let (left_id, left) = observations
            .observe_expr(CExpr::UIntLit(0x1000))
            .expect("left operand observation");
        let (right_id, right) = observations
            .observe_expr(CExpr::UIntLit(4))
            .expect("right operand observation");
        let (root_id, mut expr) = observations
            .observe_expr(CExpr::binary(BinaryOp::Add, left, right))
            .expect("root observation");
        let strings = BTreeMap::from([(0x1004, "text".to_string())]);

        let no_symbols = BTreeMap::new();
        let no_object_types = r2types::ProgramDataObjectTypeFacts::default();
        let unused_objects = std::cell::RefCell::new(std::collections::BTreeMap::new());
        fold_constant_arithmetic_in_expr(
            &mut expr,
            &strings,
            &no_symbols,
            &no_object_types,
            &unused_objects,
        );
        let mut function = CFunction::new(
            "folded",
            CType::Pointer(Box::new(CType::Int {
                bits: 8,
                signedness: r2types::Signedness::Signed,
            })),
        )
        .with_body(vec![CStmt::Return(Some(expr))]);
        let reachable =
            crate::ast::strip_render_observations(&mut function, observations.expected_count())
                .expect("constant folding preserves a valid marker domain");

        // The one rendered node stands for everything the fold collapsed, so
        // it owns every occurrence those nodes owned. Keeping only the root
        // silently discarded the operands' occurrences, and an obligation
        // whose only rendered occurrence sat on a folded operand was then
        // scored refused for an effect the program does render.
        assert!(reachable.contains(root_id));
        assert!(reachable.contains(left_id));
        assert!(reachable.contains(right_id));
        assert_eq!(
            function.body,
            vec![CStmt::Return(Some(CExpr::StringLit("text".to_string())))]
        );
    }

    #[test]
    fn radare_typed_global_renders_as_its_type_and_direct_value() {
        let mut function =
            CFunction::new("read_counter", CType::i32()).with_body(vec![CStmt::Return(Some(
                CExpr::deref(CExpr::cast(
                    CType::ptr(CType::u32()),
                    CExpr::UIntLit(0x7000),
                )),
            ))]);
        let strings = BTreeMap::new();
        let symbols = BTreeMap::from([(0x7000, "obj.global_counter".to_string())]);
        let object_types = r2types::ProgramDataObjectTypeFacts::from_radare2(
            [(0x7000, Some("int32_t"))],
            64,
            &r2types::ExternalTypeDb::default(),
        );
        let used = std::cell::RefCell::new(std::collections::BTreeMap::new());

        fold_constant_arithmetic_in_function(
            &mut function,
            &strings,
            &symbols,
            &object_types,
            &used,
            64,
        );
        function.extern_objects = used.into_inner().into_values().collect();
        note_unproven_constructs(&mut function, None, 0, 0);
        let ready = crate::codegen::prepare_function_for_emission(&function);
        let rendered =
            crate::codegen::CodeGenerator::new(Default::default()).generate_function(&ready);

        assert!(
            rendered.contains("extern int32_t global_counter;"),
            "{rendered}"
        );
        assert!(rendered.contains("return global_counter;"), "{rendered}");
        assert!(
            rendered.contains("1 data object type supplied by radare2"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("extern char global_counter[]"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("*(uint32_t*)&global_counter"),
            "{rendered}"
        );
    }

    #[test]
    fn unplaceable_global_type_keeps_the_honest_byte_declaration() {
        let mut function = CFunction::new("read_counter", CType::u32())
            .with_body(vec![CStmt::Return(Some(CExpr::UIntLit(0x7000)))]);
        let symbols = BTreeMap::from([(0x7000, "obj.global_counter".to_string())]);
        let object_types = r2types::ProgramDataObjectTypeFacts::from_radare2(
            [(0x7000, Some("looks_specific_t"))],
            64,
            &r2types::ExternalTypeDb::default(),
        );
        let used = std::cell::RefCell::new(std::collections::BTreeMap::new());
        fold_constant_arithmetic_in_function(
            &mut function,
            &BTreeMap::new(),
            &symbols,
            &object_types,
            &used,
            64,
        );
        function.extern_objects = used.into_inner().into_values().collect();
        note_unproven_constructs(&mut function, None, 0, 0);
        let ready = crate::codegen::prepare_function_for_emission(&function);
        let rendered =
            crate::codegen::CodeGenerator::new(Default::default()).generate_function(&ready);

        assert!(
            rendered.contains("extern char global_counter[];"),
            "{rendered}"
        );
        assert!(
            rendered.contains("1 data object type refused"),
            "{rendered}"
        );
        assert!(!rendered.contains("looks_specific_t"), "{rendered}");
    }

    #[test]
    fn prepended_comment_keeps_only_the_exact_original_statement_observation() {
        let mut observations = crate::ast::RenderObservationOwner::new();
        let (stmt_id, stmt) = observations
            .observe_stmt(CStmt::Return(Some(CExpr::IntLit(7))))
            .expect("return observation");
        let commented = Decompiler::prepend_comment(stmt, "summary".to_string());
        assert_eq!(
            commented,
            CStmt::Block(vec![
                CStmt::comment("summary"),
                CStmt::observed(stmt_id, CStmt::Return(Some(CExpr::IntLit(7)))),
            ])
        );

        let mut function = CFunction::new(
            "commented",
            CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            },
        )
        .with_body(vec![commented]);
        let reachable =
            crate::ast::strip_render_observations(&mut function, observations.expected_count())
                .expect("comment insertion preserves a valid marker domain");
        assert!(reachable.contains(stmt_id));
    }

    #[test]
    fn prepended_comment_does_not_move_a_split_block_observation() {
        let mut observations = crate::ast::RenderObservationOwner::new();
        let (child_id, child) = observations
            .observe_stmt(CStmt::Return(Some(CExpr::IntLit(1))))
            .expect("child observation");
        let (block_id, block) = observations
            .observe_stmt(CStmt::Block(vec![
                child,
                CStmt::Return(Some(CExpr::IntLit(2))),
            ]))
            .expect("block observation");
        let commented = Decompiler::prepend_comment(block, "summary".to_string());
        let mut function = CFunction::new(
            "commented_block",
            CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            },
        )
        .with_body(vec![commented]);

        let reachable =
            crate::ast::strip_render_observations(&mut function, observations.expected_count())
                .expect("comment insertion preserves a valid marker domain");
        assert!(reachable.contains(child_id));
        assert!(
            !reachable.contains(block_id),
            "a new comment sibling leaves no exact owner for the old block marker"
        );
        assert_eq!(
            function.body,
            vec![CStmt::Block(vec![
                CStmt::comment("summary"),
                CStmt::Return(Some(CExpr::IntLit(1))),
                CStmt::Return(Some(CExpr::IntLit(2))),
            ])]
        );
    }

    #[test]
    fn split_block_observation_is_not_assigned_to_its_first_child() {
        let mut observations = crate::ast::RenderObservationOwner::new();
        let (first_id, first) = observations
            .observe_stmt(CStmt::Return(Some(CExpr::IntLit(1))))
            .expect("first statement observation");
        let (block_id, block) = observations
            .observe_stmt(CStmt::Block(vec![
                first,
                CStmt::Return(Some(CExpr::IntLit(2))),
            ]))
            .expect("block observation");
        let decompiler = Decompiler::new(DecompilerConfig::x86_64());
        let body = decompiler.stmt_to_vec(block);
        let mut function = CFunction::new(
            "split",
            CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            },
        )
        .with_body(body);

        let reachable =
            crate::ast::strip_render_observations(&mut function, observations.expected_count())
                .expect("block decomposition preserves a valid marker domain");
        assert!(reachable.contains(first_id));
        assert!(
            !reachable.contains(block_id),
            "a multi-statement block has no exact first-child projection"
        );
        assert_eq!(
            function.body,
            vec![
                CStmt::Return(Some(CExpr::IntLit(1))),
                CStmt::Return(Some(CExpr::IntLit(2))),
            ]
        );
    }

    #[test]
    fn decompile_input_enforces_configured_block_budget_before_route_work() {
        let arch = test_arch_for_decompile();
        let mut first = R2ILBlock::new(0x1000, 4);
        first.push(R2ILOp::Branch {
            target: Varnode::ram(0x2000, 8),
        });
        let mut second = R2ILBlock::new(0x2000, 4);
        second.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let prepared = prepared_from_blocks(&[first, second], &arch).with_name("budget_demo");
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "block budget route",
                None,
            ),
        );
        let mut config = DecompilerConfig::x86_64();
        config.max_blocks = 1;
        let decompiler = Decompiler::new(config);

        let output = decompiler.decompile_input(&input);
        let function = decompiler.build_function_from_input(&input);

        assert_eq!(
            output,
            "/* r2dec budget: skipped decompilation for budget_demo (2 blocks > limit 1). */"
        );
        assert!(
            function.body.iter().any(
                |stmt| matches!(stmt, CStmt::Comment(text) if text.contains("2 blocks > limit 1"))
            ),
            "direct AST construction must enforce the same block budget: {function:?}"
        );
    }

    /// A route the engine chose describes the function; it does not answer for
    /// it. The rendering that used to stop here was two lines of prose counted
    /// as a rendered function everywhere downstream.
    #[test]
    fn an_engine_chosen_fallback_route_does_not_pre_empt_native_lowering() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![
                R2ILOp::Load {
                    dst: Varnode::unique(0x10, 4),
                    space: SpaceId::Ram,
                    addr: Varnode::register(0x10, 8),
                },
                R2ILOp::Return {
                    target: Varnode::unique(0x10, 4),
                },
            ],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::FallbackComment,
                "engine refusal: tested route",
                Some("/* engine refusal: tested route */".to_string()),
            ),
        );

        let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);

        assert!(
            output.starts_with("/* unknown */ stable_demo()"),
            "native lowering owns the rendering: {output}"
        );
        assert!(
            !output.contains("skipped decompilation"),
            "the route must not skip the native attempt: {output}"
        );
        assert!(
            !output.contains("/* engine refusal: tested route */"),
            "stored fallback payload must not be replayed verbatim"
        );
    }

    /// The route stored on the facts is the same advice, and it is refused the
    /// same authority: only the native certificates decide what renders.
    #[test]
    fn a_facts_owned_fallback_route_does_not_pre_empt_native_lowering() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::FallbackComment,
                "facts-owned route",
                Some("/* facts-owned refusal */".to_string()),
            ),
        );

        let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);

        assert!(
            output.starts_with("/* unknown */ stable_demo()"),
            "native lowering owns the rendering: {output}"
        );
        assert!(
            !output.contains("skipped decompilation"),
            "the route must not skip the native attempt: {output}"
        );
        assert!(
            !output.contains("/* facts-owned refusal */"),
            "stored fallback payload must not replace what the machine proves"
        );
    }

    #[test]
    fn context_projection_preserves_the_exact_sealed_report() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "sealed projection",
                None,
            ),
        );

        let projected = input.context_projection();

        assert_eq!(projected.type_facts(), input.function_facts().type_facts());
        assert_eq!(
            projected.function_facts.decompile_route(),
            input.function_facts().decompile_route()
        );
    }

    #[test]
    fn foreign_interproc_summary_never_reaches_decompiler_input() {
        let arch = test_arch_for_decompile();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"rebuilt-identical-owner".to_vec(),
            "sysv64",
            [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
            r2ssa::SourceFunctionReturn::Register {
                storage: storage(0),
            },
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
        .expect("exact source interface");
        let requested = Arc::new(
            r2ssa::SsaArtifact::for_decompile_with_interface(
                std::slice::from_ref(&block),
                Some(&arch),
                interface.clone(),
            )
            .expect("requested prepared SSA"),
        );
        let foreign = Arc::new(
            r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
                .expect("foreign prepared SSA"),
        );
        let summary = r2ssa::solve_prepared_interproc_summary_set(
            Arc::clone(&foreign),
            &[r2ssa::PreparedInterprocFunctionInput {
                id: r2ssa::InterprocFunctionId(foreign.entry),
                name: None,
                prepared: &foreign,
            }],
            r2ssa::InterprocSolveConfig::default(),
        )
        .expect("foreign prepared summary");
        let request = r2types::TypeWritebackAnalysisRequest::new(
            requested,
            r2types::ParsedExternalContext::default(),
        )
        .expect("source-owned request");

        assert_eq!(
            request
                .with_interproc_summary(summary)
                .expect_err("foreign interprocedural evidence must be rejected before r2dec"),
            r2types::TypeWritebackAnalysisError::ForeignInterprocSummary
        );
    }

    /// A route kind is a label on advice, and advice does not have to be
    /// backed by a symbolic artifact to be recorded. The pipeline that used to
    /// require one is gone, so the finalization accepts every kind and the
    /// native certificates decide what renders.
    #[test]
    fn decompile_finalization_accepts_every_route_kind() {
        let arch = test_arch_for_decompile();
        for route in [
            (
                r2types::DecompileRouteKind::StructuredWorker,
                "engine-selected structured summary route",
            ),
            (
                r2types::DecompileRouteKind::LinearWorker,
                "engine-selected linear summary route",
            ),
            (
                r2types::DecompileRouteKind::SummaryIslands,
                "engine-selected island summary route",
            ),
        ] {
            let prepared = prepared_from_ops(
                vec![R2ILOp::Return {
                    target: Varnode::constant(0, 8),
                }],
                &arch,
            );
            let finalized = source_owned_type_analysis(prepared)
                .finalize_for_decompile(r2types::DecompileFinalization {
                    kind: route.0,
                    reason: route.1.to_string(),
                    fallback_comment: None,
                })
                .expect("a route kind is advice and is always recordable");

            assert_eq!(
                finalized.report().decompile_route().map(|facts| facts.kind),
                Some(route.0),
                "the route is recorded as given for {:?}",
                route.0,
            );
        }
    }

    #[test]
    fn raw_fallback_comments_regenerate_and_sanitize_hostile_text() {
        let assert_one_safe_comment = |output: &str| {
            assert!(
                output.starts_with("/* "),
                "expected one C comment: {output:?}"
            );
            assert!(
                output.ends_with(" */"),
                "expected closed C comment: {output:?}"
            );
            assert_eq!(
                output.matches("*/").count(),
                1,
                "comment payload must not close the comment early: {output:?}"
            );
            assert!(
                !output.contains('\r') && !output.contains('\n'),
                "comment payload must stay on one line: {output:?}"
            );
        };

        let block_comment = block_guard_fallback_comment("bad */\nint injected", 2, 1);
        assert_one_safe_comment(&block_comment);

        // A hostile name reaches the rendered declaration, not only a comment,
        // so the identifier it spells is what has to be safe. Native lowering
        // now renders this function, which is exactly when that matters.
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        )
        .with_name("bad */\nint injected");
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::FallbackComment,
                "reason */\nreturn 7;",
                Some("*/ payload must be ignored\nint payload; /*".to_string()),
            ),
        );

        let output = Decompiler::new(DecompilerConfig::x86_64()).decompile_input(&input);
        assert!(
            output.contains("bad____int_injected()"),
            "a hostile source name must render as one C identifier: {output}"
        );
        assert!(
            !output.contains("*/\nint injected"),
            "the name must not close the type comment it follows: {output}"
        );
        assert!(
            !output.contains("payload must be ignored"),
            "stored fallback payload must not be replayed as raw output: {output}"
        );
        assert!(
            !output.contains("return 7;"),
            "a route reason must not be replayed as a statement: {output}"
        );
    }

    #[test]
    fn build_function_from_input_fallback_route_residualizes_ast() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::FallbackComment,
                "engine-selected fallback route",
                Some("/* engine-selected fallback route */".to_string()),
            ),
        );

        let built = Decompiler::new(DecompilerConfig::x86_64()).build_function_from_input(&input);

        assert!(
            built
                .body
                .iter()
                .all(|stmt| matches!(stmt, CStmt::Comment(_))),
            "fallback route AST must be comment-only, got {:?}",
            built.body
        );
        assert!(
            !built
                .body
                .iter()
                .any(|stmt| matches!(stmt, CStmt::Return(_))),
            "fallback route AST must not contain executable returns: {:?}",
            built.body
        );
    }

    /// A malformed source return boundary is refused before the effect ledger
    /// can classify any native C as surviving.
    #[test]
    fn malformed_return_boundary_refuses_before_effect_audit() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "standard route request",
                None,
            ),
        );

        let decompiler = Decompiler::new(DecompilerConfig::x86_64());
        let audited = decompiler.decompile_input_with_binding_audit(&input);
        assert_eq!(
            audited.render_refusal(),
            Some(
                DecompileRenderRefusal::MissingMachineProjectionAuthorization(
                    crate::MachineProjectionRefusalOrigin::op_lowering(),
                )
            )
        );
        assert_eq!(audited.effect_obligations(), EffectObligationAudit::NOT_RUN);
        assert!(!audited.output().contains("return"), "{}", audited.output());
    }

    #[test]
    fn native_standard_path_builds_a_sound_non_consuming_binding_shadow() {
        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![
                R2ILOp::Copy {
                    dst: Varnode::register(0, 8),
                    src: Varnode::constant(0, 8),
                },
                R2ILOp::Return {
                    target: Varnode::register(0x30, 8),
                },
            ],
            &arch,
        );
        let block = prepared.function().get_block(0x1000).expect("entry block");
        let copy_source = block
            .ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Copy { src, .. } => Some(src),
                _ => None,
            })
            .expect("copy source");
        let copy_source_value = prepared
            .graph()
            .value_id_for_var(copy_source)
            .expect("copy source must retain exact ValueId");
        let return_op = block
            .ops
            .iter()
            .position(|op| matches!(op, SSAOp::Return { .. }))
            .expect("return op");
        let return_certificate = prepared
            .return_certificate_for_op(0x1000, return_op)
            .expect("scalar audit fixture must retain an exact return certificate");
        assert_eq!(return_certificate.block_addr, 0x1000);
        assert_eq!(return_certificate.op_index, return_op);
        let return_value = return_certificate.value;
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "binding shadow production path",
                None,
            ),
        );
        let plan = crate::binding_plan::BindingPlan::build_shadow(input.source_owned_facts())
            .expect("scalar audit fixture binding plan");
        assert!(matches!(
            plan.disposition(return_value),
            Some(crate::binding_plan::ValueDisposition::Bound { .. })
        ));
        assert!(matches!(
            plan.disposition(copy_source_value),
            Some(crate::binding_plan::ValueDisposition::Inline { .. })
        ));
        assert_eq!(
            input
                .function_facts()
                .render()
                .and_then(|render| render.return_for_op(0x1000, return_op))
                .map(|fact| fact.value),
            Some(return_value)
        );
        let config = DecompilerConfig::x86_64();
        let public_decompiler = Decompiler::new(config.clone());
        let internal_decompiler =
            Decompiler::new(config.clone()).with_context(input.context_projection());
        let execution = r2ssa::SsaExecutionControl::default();
        let work = DecompileWorkControl::new(&execution, DecompileWorkPhase::Normalization);
        let built = internal_decompiler
            .build_function_internal_with_control(&input, work, &Default::default())
            .expect("native production build");

        let internal_output =
            CodeGenerator::new(config.codegen).generate_function(built.emission());
        let public_output = public_decompiler.decompile_input(&input);
        assert_eq!(internal_output, public_output);
        let audited = public_decompiler.decompile_input_with_binding_audit(&input);
        assert_eq!(audited.output(), public_output);
        let BindingShadowAuditOutcome::Complete {
            ledger,
            observations,
        } = audited.binding_shadow()
        else {
            panic!("public native path did not expose its complete shadow audit");
        };
        assert!(ledger.equations_hold());
        assert!(ledger.passes_quality());
        assert!(observations.equations_hold());
        assert!(observations.passes_quality());
        let mut corrupted_public_ledger = ledger;
        corrupted_public_ledger.values.observed =
            corrupted_public_ledger.values.observed.saturating_sub(1);
        assert!(!corrupted_public_ledger.equations_hold());
        assert!(!corrupted_public_ledger.passes_quality());
    }

    #[test]
    fn shuffled_block_schedule_keeps_spans_bindings_placement_and_bytes_identical() {
        fn exact_diamond_input(
            blocks: &[R2ILBlock],
        ) -> (r2ssa::span::StorageSpans, DecompilerInput) {
            let arch = test_arch_for_decompile();
            let storage = |offset| r2ssa::CanonicalStorageId {
                space: r2ssa::CanonicalStorageSpace::Register,
                offset,
                size: 8,
            };
            let logical_u64 = r2ssa::SourceLogicalValue::new(
                0,
                r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
            );
            let type_graph = r2ssa::SourceTypeGraph::new(
                [r2ssa::SourceType::new(
                    0,
                    r2ssa::SourceTypeKind::UnsignedInteger,
                    64,
                    64,
                )],
                [],
            )
            .expect("exact diamond type graph");
            let interface = r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
                b"r2dec-shuffled-diamond".to_vec(),
                "sysv64",
                [r2ssa::SourceAbiParameterSpec::new(0, storage(0x10))],
                r2ssa::SourceFunctionReturn::Register {
                    storage: storage(0),
                },
                [],
                [logical_u64],
                Some(logical_u64),
                Some(type_graph),
            )
            .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
            .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
            .expect("exact diamond interface");
            let prepared = Arc::new(
                r2ssa::SsaArtifact::for_decompile_with_interface(blocks, Some(&arch), interface)
                    .expect("prepared shuffled diamond")
                    .with_name("stable_diamond"),
            );
            let spans = prepared.storage_spans().clone();
            let signature = signature_spec(
                Some(CType::Int {
                    bits: 64,
                    signedness: r2types::Signedness::Unsigned,
                }),
                vec![(
                    "condition",
                    Some(CType::Int {
                        bits: 64,
                        signedness: r2types::Signedness::Unsigned,
                    }),
                )],
            );
            let parsed_context = r2types::ParsedExternalContext {
                current_signature: Some(signature.clone()),
                merged_signature: Some(signature),
                ..r2types::ParsedExternalContext::default()
            };
            let request = r2types::TypeWritebackAnalysisRequest::new(prepared, parsed_context)
                .expect("source-owned shuffled diamond request");
            let source_owned_facts = r2types::build_source_owned_type_writeback_analysis(request)
                .expect("source-owned shuffled diamond analysis")
                .finalize_for_decompile(r2types::DecompileFinalization {
                    kind: r2types::DecompileRouteKind::Standard,
                    reason: "shuffled determinism proof".to_string(),
                    fallback_comment: None,
                })
                .expect("source-owned shuffled diamond finalization");
            let input = DecompilerInput::new(source_owned_facts);
            (spans, input)
        }

        fn binding_signature(input: &DecompilerInput) -> (Vec<String>, Vec<String>) {
            let plan = crate::binding_plan::BindingPlan::build_shadow(input.source_owned_facts())
                .expect("sealed deterministic plan");
            let bindings = plan
                .bindings()
                .map(|(id, binding)| {
                    format!(
                        "{}:{:?}:{:?}:{:?}",
                        id.index(),
                        binding.declaration_type(),
                        binding.presentation_name_hint(),
                        plan.binding_role(id)
                    )
                })
                .collect();
            let dispositions = (0..input.prepared_ssa().graph().values.len())
                .map(|index| {
                    let value = r2ssa::ValueId(index as u32);
                    match plan
                        .disposition(value)
                        .expect("one disposition per dense value")
                    {
                        crate::binding_plan::ValueDisposition::Bound { binding } => {
                            format!("bound:{}", binding.index())
                        }
                        crate::binding_plan::ValueDisposition::Inline { term, .. } => {
                            format!("inline:{}", term.index())
                        }
                        crate::binding_plan::ValueDisposition::Elided { reason, .. } => {
                            format!("elided:{reason:?}")
                        }
                        crate::binding_plan::ValueDisposition::Refused { reason } => {
                            format!("refused:{reason:?}")
                        }
                    }
                })
                .collect();
            (bindings, dispositions)
        }

        let mut entry = R2ILBlock::new(0x1000, 0x10);
        entry.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1020, 8),
            cond: Varnode::register(0x10, 8),
        });
        let mut false_arm = R2ILBlock::new(0x1010, 0x10);
        false_arm.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(1, 8),
        });
        false_arm.push(R2ILOp::Branch {
            target: Varnode::constant(0x1030, 8),
        });
        let mut true_arm = R2ILBlock::new(0x1020, 0x10);
        true_arm.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(2, 8),
        });
        true_arm.push(R2ILOp::Branch {
            target: Varnode::constant(0x1030, 8),
        });
        let mut merge = R2ILBlock::new(0x1030, 4);
        merge.push(R2ILOp::Return {
            target: Varnode::register(0x30, 8),
        });

        let peers = [false_arm, true_arm, merge];
        let baseline_blocks = vec![
            entry.clone(),
            peers[0].clone(),
            peers[1].clone(),
            peers[2].clone(),
        ];
        let (baseline_spans, baseline_input) = exact_diamond_input(&baseline_blocks);
        let decompiler = Decompiler::new(DecompilerConfig::x86_64());
        let baseline = decompiler.decompile_input_with_binding_audit(&baseline_input);
        let baseline_binding_signature = binding_signature(&baseline_input);
        let baseline_values = baseline_input
            .prepared_ssa()
            .graph()
            .values
            .iter()
            .map(|value| {
                format!(
                    "{:?}:{}:{:?}",
                    value.id,
                    value.var.display_name(),
                    value.canonical_storage
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            baseline.placement_audit(),
            PlacementAudit::Applied,
            "baseline must reach placement: output={} refusal={:?} binding={:?} effects={:?} signature={baseline_binding_signature:?} values={baseline_values:?} type_facts={:?}",
            baseline.output(),
            baseline.render_refusal(),
            baseline.binding_shadow(),
            baseline.effect_obligations(),
            baseline_input.function_facts().type_facts(),
        );

        // Exhaust the complete schedule domain of the non-entry blocks. Entry
        // identity is semantic input; node/edge insertion order is not.
        for schedule in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut shuffled_blocks = vec![entry.clone()];
            shuffled_blocks.extend(schedule.map(|index| peers[index].clone()));
            let (shuffled_spans, shuffled_input) = exact_diamond_input(&shuffled_blocks);
            let shuffled = decompiler.decompile_input_with_binding_audit(&shuffled_input);

            assert_eq!(baseline_spans, shuffled_spans, "schedule={schedule:?}");
            assert_eq!(
                baseline_binding_signature,
                binding_signature(&shuffled_input),
                "schedule={schedule:?}"
            );
            assert_eq!(
                baseline.placement_audit(),
                shuffled.placement_audit(),
                "schedule={schedule:?}"
            );
            assert_eq!(
                baseline.binding_shadow(),
                shuffled.binding_shadow(),
                "schedule={schedule:?}"
            );
            assert_eq!(
                baseline.effect_obligations(),
                shuffled.effect_obligations(),
                "schedule={schedule:?}"
            );
            assert_eq!(
                baseline.render_refusal(),
                shuffled.render_refusal(),
                "schedule={schedule:?}"
            );
            assert_eq!(
                baseline.output().as_bytes(),
                shuffled.output().as_bytes(),
                "schedule={schedule:?}"
            );
        }
    }

    #[test]
    fn binding_shadow_adds_no_post_render_work_control_decision() {
        struct CountingControl {
            polls: std::cell::Cell<usize>,
            stop_at: Option<usize>,
        }

        impl r2ssa::SsaWorkControl for CountingControl {
            fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
                let poll = self.polls.get() + 1;
                self.polls.set(poll);
                if self.stop_at == Some(poll) {
                    Err(r2ssa::SsaExecutionStopReason::Cancelled)
                } else {
                    Ok(())
                }
            }
        }

        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "binding shadow work-control path",
                None,
            ),
        );
        let decompiler = Decompiler::new(DecompilerConfig::x86_64());
        let baseline = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: None,
        };
        decompiler
            .decompile_input_with_binding_audit_and_control(&input, &baseline)
            .expect("unbounded audit");
        let final_production_poll = baseline.polls.get();

        let stop_at_final = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: Some(final_production_poll),
        };
        let stop = decompiler
            .decompile_input_with_binding_audit_and_control(&input, &stop_at_final)
            .expect_err("the final production poll must remain observable");
        assert_eq!(stop.phase(), DecompileWorkPhase::Rendering);
        assert_eq!(stop.reason(), r2ssa::SsaExecutionStopReason::Cancelled);

        let no_later_poll = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: Some(final_production_poll + 1),
        };
        decompiler
            .decompile_input_with_binding_audit_and_control(&input, &no_later_poll)
            .expect("shadow capture and classification must not poll work control");
        assert_eq!(no_later_poll.polls.get(), final_production_poll);
    }

    #[test]
    fn audited_partial_retains_the_same_product_without_extra_polls() {
        struct CountingControl {
            polls: std::cell::Cell<usize>,
            stop_at: Option<usize>,
        }

        impl r2ssa::SsaWorkControl for CountingControl {
            fn poll(&self) -> Result<(), r2ssa::SsaExecutionStopReason> {
                let poll = self.polls.get() + 1;
                self.polls.set(poll);
                if self.stop_at == Some(poll) {
                    Err(r2ssa::SsaExecutionStopReason::Cancelled)
                } else {
                    Ok(())
                }
            }
        }

        let arch = test_arch_for_decompile();
        let prepared = prepared_from_ops(
            vec![R2ILOp::Return {
                target: Varnode::constant(0, 8),
            }],
            &arch,
        );
        let input = source_owned_decompiler_input(
            prepared,
            (
                r2types::DecompileRouteKind::Standard,
                "same-run audited partial",
                None,
            ),
        );
        let decompiler = Decompiler::new(DecompilerConfig::x86_64());

        let baseline_control = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: None,
        };
        let baseline = decompiler
            .decompile_input_keeping_partial_with_binding_audit(&input, &baseline_control)
            .expect("unbounded audited rendering");
        let final_poll = baseline_control.polls.get();
        let first_render_poll = final_poll
            .checked_sub(1)
            .expect("successful product rendering has two rendering polls");

        for stop_at in [first_render_poll, final_poll] {
            let stopped_control = CountingControl {
                polls: std::cell::Cell::new(0),
                stop_at: Some(stop_at),
            };
            let (stop, partial) = decompiler
                .decompile_input_keeping_partial_with_binding_audit(&input, &stopped_control)
                .expect_err("selected rendering poll must stop");
            assert_eq!(stop.phase(), DecompileWorkPhase::Rendering);
            assert_eq!(stop.reason(), r2ssa::SsaExecutionStopReason::Cancelled);
            assert_eq!(
                stopped_control.polls.get(),
                stop_at,
                "retaining output and audit must neither rebuild nor poll again"
            );
            assert_eq!(
                partial.as_ref(),
                Some(&baseline),
                "the partial must classify the exact retained product"
            );
        }

        let pre_product_control = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: Some(1),
        };
        let (stop, partial) = decompiler
            .decompile_input_keeping_partial_with_binding_audit(&input, &pre_product_control)
            .expect_err("initial preparation poll must stop");
        assert_eq!(stop.phase(), DecompileWorkPhase::Normalization);
        assert_eq!(partial, None);
        assert_eq!(pre_product_control.polls.get(), 1);

        let compatibility_control = CountingControl {
            polls: std::cell::Cell::new(0),
            stop_at: None,
        };
        let compatibility_output = decompiler
            .decompile_input_keeping_partial(&input, &compatibility_control)
            .expect("compatibility rendering");
        assert_eq!(compatibility_output, baseline.output());
        assert_eq!(
            compatibility_control.polls.get(),
            final_poll,
            "the string compatibility mapper must add no work-control decision"
        );
    }

    /// The marks the structurer leaves are counted wherever they sit, including
    /// inside a loop or a switch arm, and the function says how many it carries.
    #[test]
    fn unproven_constructs_are_counted_through_nested_bodies() {
        let mut func = CFunction::new("partly_proven".to_string(), CType::Unknown);
        func.body = vec![
            CStmt::comment("r2dec residual: unresolved branch condition at 0x1000"),
            CStmt::While {
                cond: CExpr::IntLit(1),
                body: Box::new(CStmt::Block(vec![CStmt::comment(
                    "r2dec residual: uncertified loop structure at 0x1010",
                )])),
            },
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];
        assert_eq!(count_residual_markers(&func.body), 2);

        note_unproven_constructs(&mut func, None, 0, 0);
        let note = match func.body.first() {
            Some(CStmt::Comment(text)) => text.clone(),
            other => panic!("expected a leading proof note, got {other:?}"),
        };
        assert!(note.contains("r2dec proof:"), "{note}");
        assert!(note.contains("2 constructs are marked below"), "{note}");
        assert!(
            func.body
                .iter()
                .any(|stmt| matches!(stmt, CStmt::Return(_))),
            "the proven return survives beside the marks: {:?}",
            func.body
        );
    }

    /// An uncertified route says so even when the structurer marked nothing,
    /// because "nothing was marked" is not the same claim as "everything was
    /// proven". Without this the near-miss aggregate fixture rendered a bare
    /// `return` with no indication the kernel never claimed it.
    #[test]
    fn a_rendering_says_so_even_with_nothing_marked() {
        let mut func = CFunction::new("unclaimed".to_string(), CType::Unknown);
        func.body = vec![CStmt::Return(Some(CExpr::IntLit(0)))];
        note_unproven_constructs(&mut func, None, 0, 0);
        let note = match func.body.first() {
            Some(CStmt::Comment(text)) => text.clone(),
            other => panic!("expected a leading proof note, got {other:?}"),
        };
        assert!(note.contains("r2dec proof:"), "{note}");
        assert!(note.contains("no individual construct is marked"), "{note}");
    }

    #[test]
    fn proof_line_attributes_variadic_format_counts_to_radare2() {
        let mut func = CFunction::new("formatted".to_string(), CType::Unknown);
        func.body = vec![CStmt::Return(None)];
        note_unproven_constructs(&mut func, None, 2, 0);
        let note = match func.body.first() {
            Some(CStmt::Comment(text)) => text,
            other => panic!("expected a leading proof note, got {other:?}"),
        };
        assert!(
            note.contains(
                "2 variadic callsite argument counts supplied by radare2 format literals"
            ),
            "{note}"
        );
    }

    /// Rendering nothing is not the same as proving the function does nothing.
    /// An empty body reads as "this function has no effects", so a render that
    /// produced no statements says that instead of implying it.
    #[test]
    fn a_body_that_rendered_nothing_says_so_rather_than_reading_as_empty() {
        let mut func = CFunction::new("nothing_rendered".to_string(), CType::Unknown);
        func.body = Vec::new();
        note_unproven_constructs(&mut func, None, 0, 0);
        let text = format!("{:?}", func.body);
        assert!(
            text.contains("r2dec proof: rendering produced no statements"),
            "{text}"
        );
        assert_eq!(func.body.len(), 1, "one statement says it, not two: {text}");
    }

    #[test]
    fn normal_residual_comments_hide_debug_ids_and_raw_storage_tokens() {
        let comment = sanitize_comment_text(
            "uncertified expression value ValueId(125) from ObjectId(9) via eax_1 var_8h var_ch fake_stack_slot t6a80 tmp:2c280_2",
        );

        for raw in [
            "ValueId",
            "ObjectId",
            "eax_1",
            "var_8h",
            "var_ch",
            "fake_stack_slot",
            "t6a80",
            "tmp:2c280_2",
        ] {
            assert!(
                !comment.contains(raw),
                "normal comments must hide {raw}, got {comment}"
            );
        }
        assert!(
            comment.contains("uncertified expression value value")
                && comment.contains("object")
                && comment.contains("register")
                && comment.contains("stack slot")
                && comment.contains("temporary"),
            "sanitized comment should preserve actionable categories, got {comment}"
        );
    }

    #[test]
    fn autogenerated_name_detection_accepts_underscore_hex_labels() {
        assert!(is_autogenerated_function_name("_140010138"));
        assert!(is_autogenerated_function_name("_401000"));
        assert!(!is_autogenerated_function_name("_named_worker"));
    }

    #[test]
    fn sealed_region_occurrence_mismatch_is_a_render_refusal() {
        assert_eq!(validate_sealed_region_occurrence_counts(3, 3), Ok(()));
        assert_eq!(
            validate_sealed_region_occurrence_counts(2, 3),
            Err(DecompileRenderRefusal::UnrepresentableControlFlow),
            "release builds must not admit a partially represented region domain"
        );
    }
}
