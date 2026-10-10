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
