//! Where one render's time goes, when asked.
//!
//! The engine times the whole render as one phase, and on a corpus cell that
//! phase is about ninety-five per cent of everything the engine does. That
//! number says the rewriting layer is in the right place and nothing about
//! which part of the render to change: the binding plan, the fold, the
//! structuring, the normalization passes, declaration placement, the seal and
//! code generation are one bucket.
//!
//! This is a diagnostic, not a contract. It writes to stderr under
//! `R2SLEIGH_TIMING`, the same switch the engine's phase comment uses, and it
//! is a thread-local so a stage can be marked from wherever it actually
//! happens rather than from wherever a timing struct could be threaded. It
//! costs one `Instant::now` per mark when the switch is off and nothing else.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("R2SLEIGH_TIMING").is_some())
}

thread_local! {
    static STAGES: RefCell<Vec<(&'static str, Duration)>> = const { RefCell::new(Vec::new()) };
    static LAST: RefCell<Option<Instant>> = const { RefCell::new(None) };
    /// What each stage reached at its high-water mark, and what it still held
    /// when it ended. A stage that allocates a scratch structure and frees it
    /// shows in the first and not the second, and only the second accumulates
    /// into the render's own peak, so reading one without the other says
    /// nothing about which stage to change.
    static PEAKS: RefCell<Vec<(&'static str, usize, usize, usize)>> = const { RefCell::new(Vec::new()) };
    /// The allocation count when the running stage began.
    static ALLOCS: RefCell<usize> = const { RefCell::new(0) };
    /// What was already held when this render began, so a stage's high-water
    /// mark can be read as what the render added rather than as what the
    /// process holds.
    static ENTRY: RefCell<usize> = const { RefCell::new(0) };
    /// How many graph instructions this render was asked about. Every stage
    /// scales in the body it is given, so a time without it cannot say whether
    /// a stage grew with the function or grew faster than it.
    static SIZE: RefCell<usize> = const { RefCell::new(0) };
}

/// Begin a render. Any marks left by an earlier render are discarded, because
/// a render that stopped early owes nothing to the next one.
pub(crate) fn begin(instructions: usize) {
    if !enabled() {
        return;
    }
    SIZE.with_borrow_mut(|size| *size = instructions);
    ENTRY.with_borrow_mut(|entry| *entry = r2il::allocation::live_bytes());
    STAGES.with_borrow_mut(Vec::clear);
    PEAKS.with_borrow_mut(Vec::clear);
    r2il::allocation::reset_peak();
    ALLOCS.with_borrow_mut(|allocs| *allocs = r2il::allocation::allocation_count());
    LAST.with_borrow_mut(|last| *last = Some(Instant::now()));
}

/// Close the stage that has been running and name it.
pub(crate) fn mark(stage: &'static str) {
    if !enabled() {
        return;
    }
    let now = Instant::now();
    let elapsed = LAST.with_borrow_mut(|last| {
        let elapsed = last.map(|start| now.duration_since(start));
        *last = Some(now);
        elapsed
    });
    let peak = r2il::allocation::peak_bytes();
    let live = r2il::allocation::live_bytes();
    let allocs = ALLOCS.with_borrow_mut(|allocs| {
        let now = r2il::allocation::allocation_count();
        let made = now.saturating_sub(*allocs);
        *allocs = now;
        made
    });
    r2il::allocation::reset_peak();
    PEAKS.with_borrow_mut(|peaks| {
        if let Some(row) = peaks.iter_mut().find(|(name, _, _, _)| *name == stage) {
            row.1 = row.1.max(peak);
            row.2 = row.2.max(live);
            row.3 += allocs;
        } else {
            peaks.push((stage, peak, live, allocs));
        }
    });
    if let Some(elapsed) = elapsed {
        STAGES.with_borrow_mut(|stages| {
            // A stage reached twice is one stage: structuring runs again when a
            // speculative rewrite declines, and two rows for one name would
            // read as two different stages.
            if let Some(row) = stages.iter_mut().find(|(name, _)| *name == stage) {
                row.1 += elapsed;
            } else {
                stages.push((stage, elapsed));
            }
        });
    }
}

/// Report the render just finished, once, to stderr.
pub(crate) fn report(function: &str) {
    if !enabled() {
        return;
    }
    let stages = STAGES.with_borrow_mut(std::mem::take);
    let peaks = PEAKS.with_borrow_mut(std::mem::take);
    LAST.with_borrow_mut(|last| *last = None);
    if stages.is_empty() {
        return;
    }
    let total: Duration = stages.iter().map(|(_, elapsed)| *elapsed).sum();
    let mut line = format!(
        "r2dec stage timing {function}: instructions={} total={}us",
        SIZE.with_borrow(|size| *size),
        total.as_micros()
    );
    for (stage, elapsed) in &stages {
        line.push_str(&format!(" {stage}={}us", elapsed.as_micros()));
    }
    // Bytes only when an allocator is actually counting: a zero here would
    // otherwise read as "this stage allocated nothing", which is a different
    // claim from "nobody measured".
    if r2il::allocation::is_counting() {
        let high = peaks.iter().map(|(_, peak, _, _)| *peak).max().unwrap_or(0);
        line.push_str(&format!(
            " entry_bytes={} peak_bytes={high}",
            ENTRY.with_borrow(|entry| *entry)
        ));
        let made: usize = peaks.iter().map(|(_, _, _, allocs)| *allocs).sum();
        line.push_str(&format!(" allocations={made}"));
        for (stage, peak, live, allocs) in &peaks {
            line.push_str(&format!(
                " {stage}_bytes={peak} {stage}_live={live} {stage}_allocs={allocs}"
            ));
        }
    }
    eprintln!("{line}");
}
