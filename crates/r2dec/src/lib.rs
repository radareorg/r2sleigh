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
pub mod bitvector;
pub(crate) mod codegen;
pub(crate) mod consumer_structured;
pub mod control;
pub(crate) mod debug;
mod effect_ledger;
pub(crate) mod fold;
pub mod highlight;
pub mod ledger;
pub(crate) mod normalize;
mod observation_journal;
mod placement;
pub(crate) mod planner;
pub mod prelude;
pub mod report;
mod shadow_report;
pub(crate) mod single_evaluation;
pub(crate) mod stage_timing;
pub mod structure;
mod structured_region;
pub mod symbol;
pub(crate) mod unrendered;
mod variable;

use crate::codegen::{CodeGenerator, EmissionReadyFunction, prepare_function_for_emission};
pub use crate::codegen::{Emission, ResidualSite, SourceLine};
use crate::fold::FoldingContext;
use crate::fold::context::{FoldArchConfig, FoldInputs};
use crate::observation_journal::{
    LegacyObservationCoverage, LegacyObservationJournal, MarkedNativeDraft, SealedNativeFunction,
};
use crate::symbol::SymbolId;
pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::CodeGenConfig;
pub use control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
pub use fold::lower_ssa_ops_to_stmts;
pub use highlight::highlight_c_ansi;
use r2ssa::SSAFunction;
#[cfg(test)]
use r2ssa::SSAOp;
use r2types::FunctionFacts;
#[cfg(test)]
use r2types::FunctionTypeFacts;
#[cfg(test)]
use r2types::{ExternalTypeDb, FunctionType};
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    sanitize_comment_text_keeping(text, |_| false)
}

/// Sanitize a comment, keeping every token `declared` says the function
/// declares.
///
/// The sanitizer exists to keep machine labels a reader cannot find in the
/// body out of the prose around it. A name the function declares is one the
/// reader can find: the body spells it, and a comment that rewrote it to
/// "register" would disagree with the line below it.
pub(crate) fn sanitize_comment_text_keeping(text: &str, declared: impl Fn(&str) -> bool) -> String {
    let flattened = text.replace("*/", "* /").replace(['\r', '\n'], " ");
    sanitize_comment_raw_tokens(&sanitize_comment_debug_ids(&flattened), declared)
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

fn sanitize_comment_raw_tokens(text: &str, declared: impl Fn(&str) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush_token = |out: &mut String, token: &mut String| {
        if token.is_empty() {
            return;
        }
        if declared(token) {
            out.push_str(token);
        } else if let Some(replacement) = sanitized_comment_token(token) {
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

pub fn artifact_guard_fallback_comment(func_name: &str, reason: &str) -> String {
    planner::artifact_guard_fallback_comment(func_name, reason)
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
    ledger: Option<&crate::ledger::ObligationLedger>,
    radare2_variadic_format_counts: usize,
    radare2_prototypes: usize,
    radare2_local_names: usize,
    unassigned: &[UnassignedRead],
) {
    let rendered_nothing = func.body.is_empty();
    // Each residual is a construct the rendering says it did not prove, and
    // it traps where it stands: a residual call, or a marked gap.
    let residuals = crate::prelude::count_residuals(func);
    let detail = if rendered_nothing {
        "rendering produced no statements".to_string()
    } else {
        match residuals {
            0 => "no individual construct is marked".to_string(),
            1 => "1 construct is marked below".to_string(),
            n => format!("{n} constructs are marked below"),
        }
    };
    let mut detail = match ledger.map(crate::ledger::ObligationLedger::close) {
        Some(closure) if closure.total > 0 => {
            let mut line = format!(
                "{detail}; {} source obligations: {} rendered, {} elided, {} refused",
                closure.total, closure.rendered, closure.elided, closure.refused
            );
            // A function with a residual is rendered, not proven. The count
            // says how many obligations a residual stands in for, so the proof
            // line never reads as clean when part of the body went unproven.
            if closure.gapped > 0 {
                let _ = write!(&mut line, ", {} residual", closure.gapped);
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
    note_unassigned_reads(&mut detail, unassigned);
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
            "; {radare_typed_objects} {noun} supplied by the source"
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
            "; {radare2_variadic_format_counts} {noun} supplied by the source's format literals"
        );
    }
    if radare2_prototypes > 0 {
        let noun = if radare2_prototypes == 1 {
            "callee prototype"
        } else {
            "callee prototypes"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_prototypes} {noun} supplied by the source"
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
            "; {radare2_local_names} {noun} supplied by the source"
        );
    }
    // The names are identifiers the body declares, so the sanitizer keeps them.
    let text = {
        let symbols = func.symbols.borrow();
        sanitize_comment_text_keeping(&format!("r2dec proof: {detail}"), |token| {
            symbols.by_name(token).is_some()
        })
    };
    func.body.insert(0, CStmt::comment(text));
}

/// Why a read the rendering spells as a residual has no value C can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnassignedCause {
    /// Held from entry, in storage no convention argument slot delivers.
    Held,
    /// Delivered in an argument slot no recovered parameter admits.
    UnadmittedArgument,
    /// Declared and never assigned, with no value from entry behind it: a
    /// result a call left in a register nothing claimed, for one.
    Unassigned,
}

impl UnassignedCause {
    /// The cause each residual standing for such a read carries.
    const fn residual(self) -> crate::prelude::ResidualCause {
        match self {
            Self::Held => crate::prelude::ResidualCause::HeldFromEntry,
            Self::UnadmittedArgument => crate::prelude::ResidualCause::UnadmittedArgument,
            Self::Unassigned => crate::prelude::ResidualCause::NeverAssigned,
        }
    }
}

/// One object whose every read is now a residual, and why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnassignedRead {
    pub(crate) cause: UnassignedCause,
    pub(crate) name: String,
}

/// Name the objects whose reads became residuals, by why each had no value.
///
/// A count cannot say which reads it excuses, so each is named. An argument
/// slot no parameter admits is named apart: the signature says the function
/// was not given that value, so reading it is a gap in the interface, not a
/// value held from entry.
fn note_unassigned_reads(detail: &mut String, unassigned: &[UnassignedRead]) {
    for (cause, one, many) in [
        (UnassignedCause::Held, "held from entry", "held from entry"),
        (
            UnassignedCause::UnadmittedArgument,
            "argument slot read with no parameter",
            "argument slots read with no parameter",
        ),
        (
            UnassignedCause::Unassigned,
            "never assigned",
            "never assigned",
        ),
    ] {
        let names = unassigned
            .iter()
            .filter(|read| read.cause == cause)
            .map(|read| read.name.as_str())
            .collect::<Vec<_>>();
        if names.is_empty() {
            continue;
        }
        let noun = if names.len() == 1 { one } else { many };
        let _ = write!(
            detail,
            "; {} {noun}, read as residuals ({})",
            names.len(),
            names.join(", ")
        );
    }
}

/// Spell every read of an object nothing assigns as a residual.
///
/// An object declared without a value, that no statement writes and whose
/// address is never taken, is indeterminate at every read: C has no spelling
/// for a value the function entered holding, or for one a call left in a
/// register nothing claimed. A read of it is undefined behaviour that looks
/// like a value. Each read becomes a residual of the object's type instead,
/// which traps if it is reached, and the declaration nothing reads any more
/// goes. The binding plan says which of these hold a value from entry; the
/// rest were never given one.
///
/// Only a scalar: a callee may write an aggregate or an array through its
/// decayed name, so no statement writing it is not proof that nothing does.
/// And only an object written nowhere, which makes the answer exact without
/// dataflow; an object written on some paths and read before that on others
/// needs the reaching definitions the SSA versions give, and is left as it is.
///
/// The residual keeps the markers the read carried, so the line map still
/// names the instruction that read it, and an obligation whose occurrence
/// held the read is found under a residual when the ledger is closed.
///
/// Read off the final tree, because that is what is printed: one walk for the
/// declarations, one for the writes and the reads, one to rewrite -- linear in
/// the body.
pub(crate) fn residualize_unassigned_reads(
    func: &mut CFunction,
    entry_supplied: &BTreeMap<SymbolId, binding_plan::EntrySupply>,
) -> Vec<UnassignedRead> {
    let declared = unassigned_scalar_reads(func);
    if declared.is_empty() {
        return Vec::new();
    }
    let cause = |symbol: &SymbolId| match entry_supplied.get(symbol) {
        Some(binding_plan::EntrySupply::Held) => UnassignedCause::Held,
        Some(binding_plan::EntrySupply::UnadmittedArgument) => UnassignedCause::UnadmittedArgument,
        None => UnassignedCause::Unassigned,
    };
    let declared = declared
        .into_iter()
        .map(|(symbol, ty)| {
            let cause = cause(&symbol);
            (symbol, (ty, cause))
        })
        .collect::<BTreeMap<_, _>>();
    for stmt in &mut func.body {
        stmt.visit_exprs_mut(&mut |root| {
            let expr = std::mem::replace(root, CExpr::IntLit(0));
            *root = residualize_reads_in(expr, &declared);
        });
    }
    func.visit_body_stmts_mut(&mut |stmt| {
        if let CStmt::Decl {
            name, init: None, ..
        } = stmt
            && declared.contains_key(name)
        {
            *stmt = CStmt::Empty;
        }
    });
    func.locals
        .retain(|local| !declared.contains_key(&local.name));
    let symbols = func.symbols.borrow();
    let mut objects = declared
        .iter()
        .map(|(symbol, (_, cause))| UnassignedRead {
            cause: *cause,
            name: symbols.name(*symbol).to_string(),
        })
        .collect::<Vec<_>>();
    objects.sort();
    objects
}

/// One expression with each read of a `declared` object replaced by a
/// residual of its type, under the markers the read carried.
fn residualize_reads_in(
    expr: CExpr,
    declared: &BTreeMap<SymbolId, (CType, UnassignedCause)>,
) -> CExpr {
    if let CExpr::Var(symbol) = expr.unobserved()
        && let Some(residual) = declared
            .get(symbol)
            .and_then(|(ty, cause)| crate::prelude::residual(ty, cause.residual()))
    {
        let (_, ids) = expr.into_semantic_with_observations();
        return CExpr::observe_all(ids, residual);
    }
    expr.map_children(&mut |child| residualize_reads_in(child, declared))
}

/// The scalars the function declares without a value, never writes, and
/// reads, at the types they are declared.
fn unassigned_scalar_reads(func: &CFunction) -> BTreeMap<SymbolId, CType> {
    let mut declared = func
        .locals
        .iter()
        .map(|local| (local.name, local.ty.clone()))
        .collect::<BTreeMap<_, _>>();
    // A declaration with a value writes the object it declares, and one name
    // declared twice -- once with a value -- is written by that one.
    let mut written = BTreeSet::new();
    for stmt in &func.body {
        declarations(stmt, &mut declared, &mut written);
    }
    if declared.is_empty() {
        return declared;
    }
    let mut mentioned = BTreeSet::new();
    func.visit_body_exprs(&mut |node| match node {
        CExpr::Var(symbol) => {
            mentioned.insert(*symbol);
        }
        CExpr::Binary { op, left, .. } if op.writes_left_operand() => {
            written.extend(written_object(left));
        }
        CExpr::Unary {
            op: UnaryOp::PreInc | UnaryOp::PreDec | UnaryOp::PostInc | UnaryOp::PostDec,
            operand,
        }
        // Whoever holds the address may write through it.
        | CExpr::AddrOf(operand) => {
            written.extend(written_object(operand));
        }
        _ => {}
    });
    declared.retain(|symbol, ty| {
        mentioned.contains(symbol)
            && !written.contains(symbol)
            && !matches!(
                crate::prelude::ResidualType::of(ty),
                None | Some(crate::prelude::ResidualType::Void)
            )
    });
    declared
}

/// Every name a statement and the statements inside it declare: with no
/// value, at the type it is declared, into `uninitialized`, and with one into
/// `initialized`.
fn declarations(
    stmt: &CStmt,
    uninitialized: &mut BTreeMap<SymbolId, CType>,
    initialized: &mut BTreeSet<SymbolId>,
) {
    let mut each = |stmts: &[CStmt]| {
        for stmt in stmts {
            declarations(stmt, uninitialized, initialized);
        }
    };
    match stmt.unobserved() {
        CStmt::StructuredRegion { stmt, .. } => each(std::slice::from_ref(stmt)),
        CStmt::Decl {
            ty,
            name,
            init: None,
        } => {
            uninitialized.insert(*name, ty.clone());
        }
        CStmt::Decl {
            name,
            init: Some(_),
            ..
        } => {
            initialized.insert(*name);
        }
        CStmt::Block(body) => each(body),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            each(std::slice::from_ref(then_body));
            each(
                else_body
                    .as_deref()
                    .map(std::slice::from_ref)
                    .unwrap_or_default(),
            );
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            each(std::slice::from_ref(body));
        }
        CStmt::For { init, body, .. } => {
            each(
                init.as_deref()
                    .map(std::slice::from_ref)
                    .unwrap_or_default(),
            );
            each(std::slice::from_ref(body));
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                each(&case.body);
            }
            each(default.as_deref().unwrap_or_default());
        }
        _ => {}
    }
}

/// The object a write lands in. An element or a member of an object is part
/// of it; storage reached through a pointer is not the pointer.
fn written_object(expr: &CExpr) -> Option<SymbolId> {
    match expr.unobserved() {
        CExpr::Var(symbol) => Some(*symbol),
        CExpr::Subscript { base, .. }
        | CExpr::Member { base, .. }
        | CExpr::Paren(base)
        | CExpr::Cast { expr: base, .. } => written_object(base),
        _ => None,
    }
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
fn debug_log_ledger(prepared: &r2ssa::SsaArtifact, ledger: &crate::ledger::ObligationLedger) {
    if !unowned_report_requested() {
        return;
    }
    let message = format!(
        "LEDGER fn={:#x} {}",
        prepared.function().entry,
        ledger.report()
    );
    let path = crate::debug::unowned_log_path().unwrap_or("/tmp/r2sleigh_unowned.log");
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
    let path = crate::debug::unowned_log_path().unwrap_or("/tmp/r2sleigh_unowned.log");
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
    rendered_name_of(func.name.as_deref(), func.entry)
}

/// The C name a rendering gives a function, from what it is called and where
/// it starts.
pub fn rendered_name_of(name: Option<&str>, entry: u64) -> String {
    name.and_then(r2types::sanitize_c_identifier)
        .unwrap_or_else(|| r2source::unnamed_identifier(entry))
}

/// The same name, for operations that were rewritten over a function.
pub(crate) fn rewritten_function_name(func: &r2ssa::RewrittenFunction<'_>) -> String {
    rendered_name_of(func.name(), func.entry())
}

/// A function the renderer refused: the reason, and no definition.
///
/// A definition with nothing proven in it would still have to claim a return
/// type and a parameter list, and a comment in place of both is not C. What is
/// known is why nothing is defined, so that is what is written.
fn residual_function_for_render_boundary(func_name: &str, reason: &str) -> CFunction {
    CFunction::new(func_name.to_string(), CType::Unknown)
        .with_unknown_params()
        .as_declaration_only(format!(
            "r2dec refused {}: {}",
            crate::ast::c_identifier(func_name),
            sanitize_comment_text(reason)
        ))
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
    #[cfg(test)]
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
                r2ssa::MachineCastKind::BitReinterpret => {
                    "binding_plan_machine_invalid_bit_reinterpret_width"
                }
                r2ssa::MachineCastKind::IntegerToAddress => {
                    "binding_plan_machine_invalid_integer_to_address_width"
                }
                r2ssa::MachineCastKind::AddressToInteger => {
                    "binding_plan_machine_invalid_address_to_integer_width"
                }
                r2ssa::MachineCastKind::IntegerToFloat => {
                    "binding_plan_machine_invalid_integer_to_float_width"
                }
                r2ssa::MachineCastKind::FloatToInteger => {
                    "binding_plan_machine_invalid_float_to_integer_width"
                }
                r2ssa::MachineCastKind::FloatToFloat => {
                    "binding_plan_machine_invalid_float_to_float_width"
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
    /// A rendered use of a value the specification's user operation `userop`
    /// produces, which the lift left without semantics.
    UnmodelledUserOperation {
        site: r2ssa::UseSite,
        userop: u32,
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
    /// One occurrence's observations were split over two nested nodes.
    NestedObservation {
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
            Self::UnmodelledUserOperation { .. } => "unmodelled_user_operation",
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
            Self::NestedObservation { .. } => "nested_observation",
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
        | Journal::UnmodelledUserOperation { site, .. }
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

    pub fn from_ledger(ledger: &crate::ledger::ObligationLedger) -> Self {
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
                matches!(outcome, crate::ledger::Outcome::Refused).then_some(*id)
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
    /// One occurrence's observations were split over two nested nodes.
    NestedObservation {
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
    ObjectAddressReadBeforeAssignment {
        binding_index: usize,
        value_id: u32,
    },
    StackAccessReadBeforeAssignment {
        binding_index: usize,
        instruction_id: u32,
        access_ordinal: u32,
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
            Self::NestedObservation { .. } => "nested_observation",
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
            Self::ObjectAddressReadBeforeAssignment { .. } => {
                "object_address_read_before_assignment"
            }
            Self::StackAccessReadBeforeAssignment { .. } => "stack_access_read_before_assignment",
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
    /// A value the specification's user operation `userop` produces, which
    /// the lift gave no semantics. The operation is sited in the function's
    /// SSA form, as `pdim` prints it: `block` is the address of its block and
    /// `op` its index among that block's operations. The engine names the
    /// operation from the specification's own table.
    UnmodelledUserOperation {
        userop: u32,
        block: u64,
        op: usize,
    },
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
            Self::UnmodelledUserOperation { .. } => "unmodelled_user_operation",
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
            crate::fold::op_lower::OpLoweringRefusal::MissingProgramVariableAuthorization(..)
            | crate::fold::op_lower::OpLoweringRefusal::UnrepresentableOperation(..) => {
                // These two categories drop their origin here, and a whole-
                // function refusal has no gap marker to carry it instead, so
                // the site is reported before it is lost.
                r2il::refusal_evidence!(
                    "op-lowering",
                    "{} refused at {}",
                    refusal.kind(),
                    refusal.origin_site()
                );
                match refusal {
                    crate::fold::op_lower::OpLoweringRefusal::UnrepresentableOperation(..) => {
                        Self::UnrepresentableOperation
                    }
                    _ => Self::MissingProgramVariableAuthorization,
                }
            }
            crate::fold::op_lower::OpLoweringRefusal::VariadicCallsiteArgumentCount(refusal) => {
                Self::VariadicCallsiteArgumentCount(refusal)
            }
            crate::fold::op_lower::OpLoweringRefusal::UnmodelledUserOperation {
                userop,
                block,
                op,
            } => Self::UnmodelledUserOperation { userop, block, op },
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

/// A rendering and the tree it was rendered from.
///
/// The emitter accepts no raw `CFunction`, so the only way to hold both is to
/// take them from the one run that produced them. A consumer that wants to
/// walk the C and a consumer that wants to read it are then looking at the
/// same function, and the two cannot drift apart.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedFunction {
    emission: Emission,
    function: CFunction,
}

impl RenderedFunction {
    pub(crate) const fn new(emission: Emission, function: CFunction) -> Self {
        Self { emission, function }
    }

    /// The C, as the certified emitter wrote it.
    pub fn text(&self) -> &str {
        self.emission.definition()
    }

    pub fn into_text(self) -> String {
        self.emission.into_definition()
    }

    /// The same C as its own translation unit, with where each line came from.
    pub const fn emission(&self) -> &Emission {
        &self.emission
    }

    /// The tree that C was written from, for a consumer that walks rather than parses.
    pub const fn function(&self) -> &CFunction {
        &self.function
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecompileBindingAudit {
    rendered: RenderedFunction,
    binding_shadow: BindingShadowAuditOutcome,
    ledger: Option<crate::ledger::ObligationLedger>,
    placement_audit: PlacementAudit,
    render_refusal: Option<DecompileRenderRefusal>,
}

impl DecompileBindingAudit {
    pub fn output(&self) -> &str {
        self.rendered.text()
    }

    pub fn into_output(self) -> String {
        self.rendered.into_text()
    }

    /// The C and the tree it came from, for a consumer that walks the function.
    pub fn rendered(&self) -> &RenderedFunction {
        &self.rendered
    }

    pub fn into_rendered(self) -> RenderedFunction {
        self.rendered
    }

    pub const fn binding_shadow(&self) -> BindingShadowAuditOutcome {
        self.binding_shadow
    }

    pub fn effect_obligations(&self) -> EffectObligationAudit {
        self.ledger.as_ref().map_or(
            EffectObligationAudit::NOT_RUN,
            EffectObligationAudit::from_ledger,
        )
    }

    /// What became of every obligation, which is what the counts are counting.
    pub fn obligation_ledger(&self) -> Option<&crate::ledger::ObligationLedger> {
        self.ledger.as_ref()
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
    output: Emission,
    product: InternalBuildProduct,
    source: r2types::function_facts::SourceOwnedFunctionFacts,
}

impl PendingDecompileBindingAudit {
    fn from_product(
        output: Emission,
        product: InternalBuildProduct,
        source: r2types::function_facts::SourceOwnedFunctionFacts,
    ) -> Self {
        Self {
            output,
            product,
            source,
        }
    }

    pub fn output(&self) -> &str {
        self.output.definition()
    }

    pub fn into_output(self) -> String {
        self.output.into_definition()
    }

    pub fn finalize(self) -> DecompileBindingAudit {
        let Self {
            output,
            product,
            source,
        } = self;
        let binding_shadow = product.binding_shadow(&source);
        let ledger = product.obligation_ledger().cloned();
        let placement_audit = product.placement_audit();
        let render_refusal = product.render_refusal();
        DecompileBindingAudit {
            rendered: RenderedFunction::new(output, product.into_function()),
            binding_shadow,
            ledger,
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

impl InternalBuildProduct {
    fn refused(function: CFunction, refusal: DecompileRenderRefusal) -> Self {
        Self::Refused {
            emission: prepare_function_for_emission(function),
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
            emission: prepare_function_for_emission(function),
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

    /// Whether the shadow audit fails, without building the classification.
    ///
    /// The gap loop asks only this: a failure names the cell to mark. Building
    /// the whole comparison to answer it cost more than every other stage of
    /// the audit put together and was then dropped.
    fn binding_shadow_failure(&self) -> Option<BindingShadowAuditFailure> {
        match self {
            Self::Native(native) => native.audit_observations().err(),
            Self::Refused { binding_shadow, .. } => match binding_shadow {
                BindingShadowAuditOutcome::Failed(failure) => Some(*failure),
                BindingShadowAuditOutcome::Complete { .. } | BindingShadowAuditOutcome::NotRun => {
                    None
                }
            },
            Self::Residual(_) => None,
        }
    }

    fn obligation_ledger(&self) -> Option<&crate::ledger::ObligationLedger> {
        match self {
            Self::Native(native) => native.obligation_ledger(),
            Self::Residual(_) | Self::Refused { .. } => None,
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
    ) -> Result<InternalBuildProduct, DecompileExecutionStop> {
        let work = DecompileWorkControl::new(control, DecompileWorkPhase::Normalization);
        work.poll()?;
        // The semantic route used to answer here, before the native pipeline
        // was asked anything, and its prose counted as a rendered function
        // everywhere downstream: functions were reported as covered while
        // their whole body was two lines of summary. The route is advisory,
        // so it may say what native lowering could not prove; it may not
        // stand in for asking.
        self.build_product_from_input_with_control(input, control)
    }

    /// Controlled form of [`Self::decompile_input_with_binding_audit`].
    pub fn decompile_input_with_binding_audit_and_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<DecompileBindingAudit, DecompileExecutionStop> {
        let product = self.prepare_decompile_with_control(input, control)?;
        let render_work = DecompileWorkControl::new(control, DecompileWorkPhase::Rendering);
        render_work.poll()?;
        let output = CodeGenerator::new(self.config.codegen.clone())
            .with_work(control)
            .emit(product.emission(), self.config.ptr_size);
        // This is deliberately the last production work-control decision.
        // Everything below classifies the already sealed observation journal.
        render_work.poll()?;
        let binding_shadow = product.binding_shadow(input.source_owned_facts());
        let ledger = product.obligation_ledger().cloned();
        let placement_audit = product.placement_audit();
        let render_refusal = product.render_refusal();
        Ok(DecompileBindingAudit {
            rendered: RenderedFunction::new(output, product.into_function()),
            binding_shadow,
            ledger,
            placement_audit,
            render_refusal,
        })
    }

    /// The structured tier for this function, printed.
    ///
    /// The same pipeline `decompile_input_with_control` runs, stopping before
    /// the C is generated. It answers even when the rendering refuses, which
    /// is when a reader most wants to see the tree.
    pub fn structured_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<String, DecompileExecutionStop> {
        let product = self.prepare_decompile_with_control(input, control)?;
        Ok(crate::structure::print::render(
            product.emission().function_for_aggregate_definitions(),
            self.config.codegen.clone(),
        ))
    }

    /// The value tier's dispositions, printed.
    ///
    /// Read against `pdd`, this says which variable a value became, which
    /// expression it was folded into, or why nothing spells it -- the question
    /// that otherwise costs a rebuild with a print in it.
    pub fn values_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<String, DecompileExecutionStop> {
        let facts = input.source_owned_facts();
        // A plan that refuses is the answer, not an absence of one: the
        // refusal names the value or the object it could not decide, which is
        // exactly what the reader is here to see.
        Ok(
            match crate::binding_plan::BindingPlan::build_shadow_with_control(facts, control) {
                Ok(plan) => crate::binding_plan::dump(facts.source(), &plan),
                Err(error) => format!("the binding plan refused: {error:?}\n"),
            },
        )
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
            Ok(product) => product,
            Err(stop) => return Err((stop, None)),
        };
        let render_work = DecompileWorkControl::new(control, DecompileWorkPhase::Rendering);
        if let Err(stop) = render_work.poll() {
            // The run has already stopped; this writes the partial the caller
            // keeps, so it is not charged again against a spent budget.
            let output = CodeGenerator::new(self.config.codegen.clone())
                .emit(product.emission(), self.config.ptr_size);
            return Err((
                stop,
                Some(PendingDecompileBindingAudit::from_product(
                    output,
                    product,
                    input.source_owned_facts().clone(),
                )),
            ));
        }
        crate::stage_timing::mark("audit");
        let output = CodeGenerator::new(self.config.codegen.clone())
            .with_work(control)
            .emit(product.emission(), self.config.ptr_size);
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

    fn build_product_from_input_with_control<'a>(
        &self,
        input: &'a DecompilerInput,
        control: &'a dyn r2ssa::SsaWorkControl,
    ) -> Result<InternalBuildProduct, DecompileExecutionStop> {
        let work = DecompileWorkControl::new(control, DecompileWorkPhase::Normalization);
        work.poll()?;
        // A proof failure that names a cell is planned as a gap and the whole
        // rendering is run again with that cell marked, exactly as a lowering
        // refusal is. Each attempt plans an anchor that was not planned before
        // and the anchors are instructions, so the loop terminates on a finite
        // set without being counted.
        let mut seed_gaps = std::collections::BTreeMap::new();
        loop {
            let decompiler =
                Self::new(self.config.clone()).with_context(input.context_projection());
            let product =
                decompiler.build_function_internal_with_control(input, work, &seed_gaps)?;
            if let Some(failure) = product.binding_shadow_failure()
                && let Some(anchor) = gap_anchor_for_native_failure(&failure, input.prepared_ssa())
                && !seed_gaps.contains_key(&anchor)
            {
                let kind = DecompileRenderRefusal::from(failure).kind().to_string();
                r2il::refusal_evidence!(
                    "gap",
                    "the proof named {anchor:?} ({:?}) as {kind}; planning a gap and rendering again",
                    input
                        .prepared_ssa()
                        .graph()
                        .inst(anchor)
                        .map(|inst| &inst.payload)
                );
                seed_gaps.insert(anchor, kind);
                continue;
            }
            return Ok(product);
        }
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
        crate::stage_timing::begin(input.prepared_ssa().graph().insts.len());
        // The names this rendering declares, from the first pass that mints one.
        let symbol_table =
            std::rc::Rc::new(std::cell::RefCell::new(crate::symbol::SymbolTable::new()));
        let symbols = &*symbol_table;

        work.poll()?;
        let prepared = input.prepared_ssa();
        let func = prepared.function();
        if let Some(declaration) = self.import_stub_declaration(prepared) {
            return Ok(InternalBuildProduct::Residual(declaration));
        }
        if crate::debug::debug_merges() {
            let graph = prepared.graph();
            let live = prepared.live_out();
            let dead = prepared.unobserved_merges();
            let total: usize = func.blocks().iter().map(|b| b.phis.len()).sum();
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
                    r2ssa::RewrittenFunction::new(func, func.blocks().to_vec()),
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
        if crate::debug::dump_ssa() {
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
        let binding_plan = match crate::binding_plan::BindingPlan::build_shadow_with_control(
            input.source_owned_facts(),
            work.work(),
        ) {
            Ok(plan) => {
                // Every value's disposition, beside the SSA dump it indexes.
                if crate::debug::dump_ssa() {
                    let canonical = plan.canonical();
                    for value in &prepared.graph().values {
                        let term = canonical.value(value.id).map(|rewrite| {
                            r2rewrite::spell_term(canonical.arena(), rewrite.canonical)
                        });
                        eprintln!(
                            "PLANVALUE {:?} {} {:?} term={}",
                            value.id,
                            value.var,
                            plan.disposition(value.id),
                            term.unwrap_or_default()
                        );
                    }
                    for (id, access) in &prepared.structured().memory_accesses {
                        eprintln!(
                            "PLANACCESS {:?} object={:?} address={:?} width={} offset={:?} write={} complete={} indexed={} interior={:?}",
                            id,
                            access.object,
                            access.address,
                            access.width,
                            access.object_offset,
                            access.is_write,
                            access.provenance_complete,
                            prepared.objects().address_is_indexed(access.address),
                            prepared.objects().interior_offset(access.address)
                        );
                    }
                    for (object, fact) in &prepared.objects().objects {
                        eprintln!(
                            "PLANOBJECT {:?} {:?} {:?} slot={:?}",
                            object,
                            fact.kind,
                            plan.stack_object_disposition(*object),
                            prepared.certificates().stack_slots.get(object).map(|slot| (
                                slot.offset,
                                slot.size,
                                slot.byte_array
                            ))
                        );
                    }
                }
                std::rc::Rc::new(plan)
            }
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
                // A stopped run is not a function whose program variables
                // could not be authorized.
                if let crate::binding_plan::BindingPlanBuildError::Stopped(reason) = error {
                    return Err(DecompileExecutionStop::new(work.phase(), reason));
                }
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
        crate::stage_timing::mark("plan_names");
        let func = &normalized_func;
        let func_name = rewritten_function_name(func);
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
        crate::stage_timing::mark("plan_journal");
        work.poll()?;
        if crate::debug::debug_merges() {
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
        let params = match binding_names
            .parameters()
            .map(|resolved| {
                let resolved = resolved?;
                // r2types owns what a parameter is declared as; the binding's own type answers only where it declares nothing.
                let ty = usize::try_from(resolved.slot)
                    .ok()
                    .and_then(|slot| {
                        input
                            .source_owned_facts()
                            .parameter_declaration(slot, resolved.width_bits)
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
                // The parameter list is the first thing rendered, so a formal
                // without a symbol is the whole function's refusal; say which.
                r2il::refusal_evidence!("parameter-list", "{func_name}: {error:?}");
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
        // What the function returns is r2types' one decision: the decided
        // type, or where the boundary left the value unproven, the result
        // carrier a caller reads, which every return hands back a residual of.
        // A refused type is spelled as any unknown type is.
        let return_type = input
            .source_owned_facts()
            .return_type()
            .and_then(r2types::ReturnTypeFact::declared)
            .cloned()
            .unwrap_or(CType::Unknown);
        let fold_function_return_type = Some(&return_type);
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
                        &rewritten_function_name(func),
                        &format!("native render refusal: {}", refusal.kind()),
                    ),
                    refusal,
                ));
            }
        };
        crate::stage_timing::mark("plan_view");
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
        let structuring_work = work.with_phase(DecompileWorkPhase::Structuring);
        if let Err(error) = fold_ctx.analyze_blocks_with_control(func.blocks(), structuring_work) {
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
        //
        // The loop needs no attempt limit, because `plan_gap_for_escaped_refusal`
        // answers `true` only when it has inserted an anchor that was not
        // already planned, and the anchors are instructions. Every retry
        // therefore consumes one instruction from a finite set and the loop
        // stops as soon as none is left to plan. A counted bound here would be
        // a cap standing in for an argument that already holds, and on a
        // thirty-five-thousand-operation function it permitted that many
        // re-structurings.
        let structure_checkpoint = observation_journal.borrow().checkpoint();
        let structure_observation_error = fold_ctx.observation_error.borrow().clone();
        let structure_labels: std::collections::HashMap<u64, String>;
        let structure_rewrites: String;
        let mut declined_rewrites = std::collections::BTreeSet::new();
        let routed_body = loop {
            let mut structurer = ControlFlowStructurer::new_with_control(
                func,
                &fold_ctx,
                structuring_work,
                declined_rewrites.clone(),
            )?;
            match consumer_structured::primary_native_body(&mut structurer) {
                Ok(body) => {
                    if let Some(stop) = structurer.execution_stop() {
                        return Err(stop);
                    }
                    structure_labels = structurer.labels().clone();
                    structure_rewrites = structurer.rewrite_report();
                    break body;
                }
                // A rewrite stage that loses the certificate declines the
                // whole writing rather than returning a copy of the tree it
                // was handed. Two stages, each declinable once, so the loop
                // ends for the same reason the gap loop does: every retry
                // takes one name out of a finite set.
                Err(structure::ControlFlowStructureError::RewriteDeclined(stage)) => {
                    declined_rewrites.insert(stage);
                    observation_journal
                        .borrow_mut()
                        .rollback(structure_checkpoint);
                    *fold_ctx.observation_error.borrow_mut() = structure_observation_error.clone();
                    fold_ctx.folded_blocks.borrow_mut().clear();
                    continue;
                }
                Err(structure::ControlFlowStructureError::Lowering(refusal)) => {
                    if fold_ctx.plan_gap_for_escaped_refusal(refusal) {
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
                        &rewritten_function_name(func),
                        &format!("operation lowering refusal: {refusal:?}"),
                    );
                    return Ok(InternalBuildProduct::refused(function, refusal.into()));
                }
                Err(structure::ControlFlowStructureError::StructuredRegion(error)) => {
                    debug_log_render_contract_error(prepared, "structured-region", &error);
                    return Ok(InternalBuildProduct::refused(
                        residual_function_for_render_boundary(
                            &rewritten_function_name(func),
                            &format!("structured-region refusal: {error:?}"),
                        ),
                        DecompileRenderRefusal::UnrepresentableControlFlow,
                    ));
                }
            }
        };
        structuring_work.poll()?;
        crate::stage_timing::mark("structure_route");
        if let Some(structured_body) = routed_body.structured_body() {
            let journal = observation_journal.borrow();
            let labels_by_name: std::collections::HashMap<&str, u64> = structure_labels
                .iter()
                .map(|(addr, name)| (name.as_str(), *addr))
                .collect();
            // The linear form labels a block by its address.
            let label_block = |name: &str| {
                labels_by_name.get(name).copied().or_else(|| {
                    name.strip_prefix("loc_")
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                })
            };
            let declarations = fold_ctx.callee_declarations.borrow();
            let certificate = structure::certify::certify(
                structured_body.stmt(),
                func.cfg(),
                func.entry(),
                &|id| journal.observation_block(id),
                &label_block,
                &|stmt| {
                    structure::certify::stmt_callee_name(stmt).is_some_and(|name| {
                        declarations
                            .get(name)
                            .is_some_and(|recorded| recorded.declaration.noreturn)
                    })
                },
            );
            structure::certify::report(
                &func_name,
                &certificate,
                &structure_rewrites,
                prepared.register_identity_census(),
            );
            crate::stage_timing::mark("control_certificate");
        }
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
            declaration_only: None,
            typedefs: Vec::new(),
            aggregates: Vec::new(),
            bitvector_helpers: Vec::new(),
            extern_objects: Vec::new(),
            externs: fold_ctx
                .callee_declarations
                .borrow()
                .values()
                .map(|recorded| recorded.declaration.clone())
                .collect(),
            // A recovery that reached no return type still has to declare
            // one, and `/* unknown */` is a comment rather than C.
            ret_type: r2types::spellable_c_type_like(&return_type, self.config.ptr_size),
            params,
            // Program locals are introduced only by the final placement pass
            // from surviving, observed BindingId occurrences.
            locals: Vec::new(),
            body,
            // Parameters here come from the render signature, so an empty list
            // is a recovered empty list rather than an unknown one.
            params_known: true,
        };
        // The fold named every constant address it converted, and declaring
        // the objects is part of naming them.
        let used_objects: std::cell::RefCell<
            std::collections::BTreeMap<u64, crate::ast::CExternObject>,
        > = std::cell::RefCell::new(fold_ctx.named_data_objects.borrow().clone());
        crate::stage_timing::mark("structure");
        for stmt in &mut c_function.body {
            simplify_data_object_loads_in_stmt(stmt, self.config.ptr_size, &used_objects);
        }
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
        native.define_declared_aggregates(prepared);
        native.define_declared_typedefs(prepared);
        // Before the ledger closes, and after the last rewrite: an obligation
        // whose occurrence evaluates a residual traps there, and the ledger
        // counts it that way.
        let unassigned = native.residualize_unassigned_reads(binding_names.entry_supplied());
        let ledger = effect_ledger::build_obligation_ledger(
            prepared,
            &normalization_origins,
            native.effect_observations(),
            &native.obligations_under_residuals(),
        );
        debug_log_ledger(prepared, &ledger);
        let radare2_variadic_format_counts = self
            .context
            .function_facts
            .callsites()
            .into_iter()
            .flat_map(|facts| facts.by_callsite.values())
            .filter(|fact| {
                // Counts radare2's prototype proved, so the proof line keeps
                // attributing to radare2 only what radare2 named. A count the
                // callee's own body proved is ours and is not counted here.
                fact.variadic_argument_count_evidence
                    .is_some_and(|evidence| {
                        matches!(
                            evidence.parameter_rule,
                            r2ssa::SourceFormatParameterRule::Radare2FormatString { .. }
                        )
                    })
            })
            .count();
        // Call sites whose prototype is radare2's by-name lookup for an import.
        let radare2_prototypes = self
            .context
            .function_facts
            .callsites()
            .into_iter()
            .flat_map(|facts| facts.by_callsite.values())
            .filter(|fact| fact.callee_signature_from_source_types)
            .count();
        crate::stage_timing::mark("effect_ledger");
        native.finalize_effect_ledger(
            &ledger,
            radare2_variadic_format_counts,
            radare2_prototypes,
            binding_names.source_named_locals(),
            &unassigned,
        );
        Ok(InternalBuildProduct::Native(native))
    }

    /// The declaration an import stub renders as.
    ///
    /// A stub is one tail transfer to an import and nothing else: no store, no
    /// other call, no register written that the transfer does not carry. It has
    /// no body of its own, so it renders as the import's declaration and a
    /// comment naming the import, and it is counted as a declaration. A stub
    /// whose import has no prototype renders as the comment alone: nothing is
    /// invented for it.
    fn import_stub_declaration(
        &self,
        prepared: &r2ssa::SsaArtifact,
    ) -> Option<EmissionReadyFunction> {
        let certificates = prepared.certificates();
        let [callsite] = certificates.callsites.values().collect::<Vec<_>>()[..] else {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "{:#x}: {} call sites, not one",
                prepared.function().entry,
                certificates.callsites.len()
            );
            return None;
        };
        if callsite.transfer != r2ssa::CallSiteTransfer::TailCall
            || !certificates.returns.is_empty()
        {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "{:#x}: transfer {:?}, {} return certificates",
                prepared.function().entry,
                callsite.transfer,
                certificates.returns.len()
            );
            return None;
        }
        let graph = prepared.graph();
        let machine = prepared.machine_context();
        let clobbered = machine
            .call_clobbered_carriers()
            .iter()
            .map(|storage| storage.location())
            .collect::<std::collections::BTreeSet<_>>();
        let arguments = machine
            .abi_model()
            .argument_registers()
            .iter()
            .map(|slot| slot.storage().location())
            .collect::<std::collections::BTreeSet<_>>();
        let transfer_inputs = graph
            .inst_id_for_op_site(callsite.block_addr, callsite.op_index)
            .and_then(|inst| graph.inst(inst))
            .map(|inst| inst.inputs.to_vec())
            .unwrap_or_default();
        let observable = graph.insts.iter().find(|inst| {
            if matches!(
                inst.payload,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::Store { .. } | r2ssa::SSAOp::Call { .. })
            ) {
                return true;
            }
            let Some(output) = inst.output else {
                return false;
            };
            if transfer_inputs.contains(&output) {
                return false;
            }
            // A write nothing reads and nothing carries out is the transfer's
            // own bookkeeping, such as the program counter it sets.
            if graph.use_sites(output).is_empty() && !prepared.live_out().contains(output) {
                return false;
            }
            graph
                .value(output)
                .and_then(|value| value.canonical_storage)
                .is_some_and(|storage| match storage.space {
                    r2ssa::CanonicalStorageSpace::Ram => true,
                    r2ssa::CanonicalStorageSpace::Register => {
                        let location = storage.location();
                        arguments.contains(&location) || !clobbered.contains(&location)
                    }
                    _ => false,
                })
        });
        if let Some(inst) = observable {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "{:#x}: the body defines observable state beside the transfer: {:?} -> {:?} caller_supplied={}",
                prepared.function().entry,
                inst.payload,
                inst.output
                    .and_then(|output| graph.value(output))
                    .map(|value| (value.var.display_name(), value.canonical_storage)),
                inst.output
                    .is_some_and(|output| graph.caller_supplied(output))
            );
            return None;
        }
        let Some(identity) =
            self.context
                .function_facts
                .callee_resolution()
                .and_then(|resolution| {
                    resolution.identity_for_callsite(r2types::CallsiteKey {
                        block_addr: callsite.block_addr,
                        op_index: callsite.op_index,
                    })
                })
        else {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "{:#x}: the transfer resolves to no callee identity",
                prepared.function().entry
            );
            return None;
        };
        // An external symbol reached through a relocation slot is an import
        // by another name; an internal or unknown callee is not a stub's.
        if !matches!(
            identity.class,
            r2types::CalleeClass::Imported | r2types::CalleeClass::ExternalSymbol
        ) {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "{:#x}: the callee is {:?}, not an import: {:?}",
                prepared.function().entry,
                identity.class,
                identity
            );
            return None;
        }
        let name = identity
            .display_name
            .as_deref()
            .or(identity.normalized_name.as_deref())
            .or(identity.raw_name.as_deref())?;
        let name = crate::ast::c_identifier(name);
        let entry = prepared.function().entry;
        let Some(signature) = identity.signature.as_ref() else {
            r2il::refusal_evidence!(
                "import-stub-declaration",
                "tail transfer at {:#x}:{} resolves to {name}, which has no prototype",
                callsite.block_addr,
                callsite.op_index
            );
            let reason = format!(
                "r2sleigh: import stub at {entry:#x}; this symbol is the import `{name}`, \
                 whose prototype nothing states."
            );
            return Some(prepare_function_for_emission(
                crate::residual_function_for_render_boundary(&name, &reason),
            ));
        };
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "tail transfer at {:#x}:{} resolves to {name}, declared rather than defined",
            callsite.block_addr,
            callsite.op_index
        );
        let reason = format!(
            "r2sleigh: import stub at {entry:#x}; this symbol is the import `{name}` and \
             has no body of its own."
        );
        let mut function = CFunction::new(name.clone(), signature.return_type.clone())
            .as_declaration_only(sanitize_comment_text(&reason));
        function.externs = vec![crate::ast::CExternDecl {
            name,
            ret_type: signature.return_type.clone(),
            params: Some(signature.params.clone()),
            variadic: signature.variadic,
            noreturn: false,
            address: Some(entry),
        }];
        Some(prepare_function_for_emission(function))
    }

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
        | CExpr::FloatLit(..)
        | CExpr::CharLit(_)
        | CExpr::StringLit(_)
        | CExpr::Sizeof(_)
        | CExpr::SizeofType(_) => {}
    }
}

/// Which locals the body still assigns, printed between passes.
///
/// A statement the fold built and the page does not show was removed by one of
/// the passes that run after structuring, and there are a dozen of them. Naming
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
    CType::typedef("char")
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
    // A name occupies whatever it names.
    match ty.unaliased() {
        CType::Bool => Some(8),
        CType::Int { bits, .. } | CType::Float(bits) | CType::BitVector(bits) => Some(*bits),
        CType::Pointer(_) | CType::Function { .. } => Some(pointer_bits),
        CType::Array(element, Some(len)) => {
            c_object_storage_bits(element, pointer_bits)?.checked_mul(u32::try_from(*len).ok()?)
        }
        CType::Const(inner) => c_object_storage_bits(inner, pointer_bits),
        CType::Void
        | CType::Array(_, None)
        | CType::Struct(_)
        | CType::Union(_)
        | CType::Enum(_)
        | CType::Typedef { .. }
        | CType::Unknown => None,
    }
}
/// Walk every expression in `stmt` and simplify the loads through a named
/// object that radare2 gave a type.
fn simplify_data_object_loads_in_stmt(
    stmt: &mut CStmt,
    pointer_bits: u32,
    used: &std::cell::RefCell<std::collections::BTreeMap<u64, crate::ast::CExternObject>>,
) {
    let expr_of = |expr: &mut CExpr| simplify_typed_data_object_loads(expr, pointer_bits, used);
    let mut inner = |stmt: &mut CStmt| simplify_data_object_loads_in_stmt(stmt, pointer_bits, used);
    match stmt {
        CStmt::StructuredRegion { stmt, .. } | CStmt::Observed { stmt, .. } => inner(stmt),
        CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
        CStmt::Expr(expr) => expr_of(expr),
        CStmt::Decl { init, .. } => {
            if let Some(init) = init {
                expr_of(init);
            }
        }
        CStmt::Return(expr) => {
            if let Some(expr) = expr {
                expr_of(expr);
            }
        }
        CStmt::Block(stmts) => stmts.iter_mut().for_each(inner),
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_of(cond);
            inner(then_body);
            if let Some(else_body) = else_body {
                inner(else_body);
            }
        }
        CStmt::While { cond, body } | CStmt::DoWhile { body, cond } => {
            expr_of(cond);
            inner(body);
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                inner(init);
            }
            if let Some(cond) = cond {
                expr_of(cond);
            }
            if let Some(update) = update {
                expr_of(update);
            }
            inner(body);
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            expr_of(expr);
            for case in cases {
                case.body.iter_mut().for_each(&mut inner);
            }
            if let Some(default) = default {
                default.iter_mut().for_each(inner);
            }
        }
    }
}

/// The unsigned value of an integer literal, ignoring any cast around it.
pub(crate) fn literal_value(expr: &CExpr) -> Option<u64> {
    match expr {
        CExpr::Observed { expr, .. } => literal_value(expr),
        CExpr::UIntLit(value) => Some(*value),
        CExpr::IntLit(value) => u64::try_from(*value).ok(),
        CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => literal_value(inner),
        _ => None,
    }
}
/// Whether a string literal can stand where a value of `required` is wanted:
/// anywhere but behind a pointer to something wider than a character, since a
/// load of a word through a string's address reads an object, not text.
pub(crate) fn string_literal_serves(required: &CType, ptr_bits: u32) -> bool {
    match required {
        CType::Pointer(inner) => {
            matches!(**inner, CType::Void | CType::Unknown)
                || r2types::declaration_type_width_bits(inner, ptr_bits) == Some(8)
        }
        _ => true,
    }
}

/// The name this constant address is, the type that name has, and the object it declares.
pub(crate) fn name_of_constant_address(
    expr: &CExpr,
    strings: &std::collections::BTreeMap<u64, String>,
    symbols: &std::collections::BTreeMap<u64, String>,
    object_types: &r2types::ProgramDataObjectTypeFacts,
    named: &mut std::collections::BTreeMap<u64, crate::ast::CExternObject>,
    string_serves: bool,
) -> Option<(CExpr, CType)> {
    let value = literal_value(expr)?;
    if string_serves && let Some(text) = strings.get(&value) {
        return Some((
            crate::ast::carry_all_expr_observations(expr, CExpr::StringLit(text.clone())),
            CType::ptr(plain_char_type()),
        ));
    }
    let flag = symbols.get(&value);
    r2il::refusal_evidence!(
        "constant-address",
        "{value:#x}: {}",
        flag.map_or("no symbol", String::as_str)
    );
    let flag = flag?;
    let rendered = c_identifier_for_data_symbol(flag);
    let type_fact = object_types.get(value).cloned();
    // An object radare2 gave no type to is a run of bytes, which is what
    // `extern char name[]` says and is the honest declaration for it.
    let object_type = type_fact
        .as_ref()
        .map(|fact| fact.ty.clone())
        .unwrap_or_else(|| CType::Array(Box::new(plain_char_type()), None));
    named.insert(
        value,
        crate::ast::CExternObject {
            name: rendered.clone(),
            address: value,
            type_fact,
            type_refusal: object_types.refused().get(&value).cloned(),
        },
    );
    Some((
        crate::ast::carry_all_expr_observations(
            expr,
            CExpr::addr_of(CExpr::DataObject {
                address: value,
                name: rendered,
            }),
        ),
        CType::ptr(object_type),
    ))
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

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
