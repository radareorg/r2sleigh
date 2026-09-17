//! Debug switches, read once.
//!
//! Each of these is asked inside a loop -- per symbol, per merge, per
//! expression the renderer lowers -- and reading the environment there walks
//! the environment block and allocates a string for every question. They are
//! also the whole list of switches this crate answers to, which is worth
//! having in one place rather than as literals spread across seven modules.

use std::sync::OnceLock;

fn flag(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

fn value(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The one variable a run was asked to trace.
pub(crate) fn traced_variable_name() -> Option<&'static str> {
    static TRACED: OnceLock<Option<String>> = OnceLock::new();
    TRACED
        .get_or_init(|| value("R2SLEIGH_TRACE_NAME"))
        .as_deref()
}

/// Whether to report how merges were placed and named.
pub(crate) fn debug_merges() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| flag("R2SLEIGH_DEBUG_MERGES"))
}

/// Whether to report each merge materialisation.
pub(crate) fn trace_materialization() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| flag("R2SLEIGH_TRACE_MAT"))
}

/// The one value whose inlining decision a run was asked to trace.
pub(crate) fn traced_inline_name() -> Option<&'static str> {
    static TRACED: OnceLock<Option<String>> = OnceLock::new();
    TRACED
        .get_or_init(|| value("R2SLEIGH_TRACE_INLINE"))
        .as_deref()
}

/// Whether to dump the SSA the render was given.
pub(crate) fn dump_ssa() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| flag("R2SLEIGH_DUMP_SSA"))
}

/// Where to append the unowned-value log, when one was asked for.
pub(crate) fn unowned_log_path() -> Option<&'static str> {
    static PATH: OnceLock<Option<String>> = OnceLock::new();
    PATH.get_or_init(|| value("R2SLEIGH_DEBUG_UNOWNED_LOG"))
        .as_deref()
}

/// Where to write the marked tree as placement sees it, when asked for.
pub(crate) fn dump_ast_path() -> Option<&'static str> {
    static PATH: OnceLock<Option<String>> = OnceLock::new();
    PATH.get_or_init(|| value("R2SLEIGH_DUMP_AST")).as_deref()
}
