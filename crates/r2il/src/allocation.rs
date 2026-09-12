//! What one render costs in bytes, when something is counting.
//!
//! The engine has always reported where a decompile spends its time and never
//! where it spends its memory, and memory is what the complexity caps were
//! really guarding: a single function once reached several gigabytes and the
//! kernel killed radare2, which loses every function in the binary rather than
//! the one that was too big. Peak resident set measured from outside the
//! process is too coarse to attribute -- it is a high-water mark for the whole
//! run, and radare2's own analysis dominates it below a few hundred blocks.
//!
//! So the counters live here, at the bottom of the crate graph where every
//! stage can reach them, and the global allocator that feeds them lives in the
//! plugin behind a feature. With no allocator installed every function below is
//! a relaxed load of a zero, which is what an ordinary build pays.

use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Record an allocation. Called by the counting allocator, not by hand.
pub fn record_allocation(bytes: usize) {
    // Marking here rather than at plugin init means a report can never claim
    // zero bytes because nobody remembered to announce the allocator.
    COUNTING.store(1, Ordering::Relaxed);
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

/// Record a deallocation. Called by the counting allocator, not by hand.
pub fn record_deallocation(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::Relaxed);
}

/// Bytes allocated and not yet freed.
pub fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// The high-water mark since it was last reset.
pub fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// Start a new measurement from what is live now.
///
/// The peak is reset to the live total rather than to zero, because what is
/// already held is part of the next measurement's floor.
pub fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Whether anything is actually counting.
///
/// Set by the first allocation the counting allocator sees, so a report can say
/// "not measured" rather than "zero bytes", which are different claims.
static COUNTING: AtomicUsize = AtomicUsize::new(0);

pub fn is_counting() -> bool {
    COUNTING.load(Ordering::Relaxed) == 1
}
