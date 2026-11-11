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
//! stage can reach them, and the global allocator that feeds them is r2s's
//! `alloc-count` build. With no allocator installed every reading below is
//! `None`, never a zero that would claim nothing was allocated (audit W63).

use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// How many allocations have been made. Bytes alone cannot say whether a
/// stage asked the allocator once for a megabyte or thirty thousand times for
/// thirty bytes, and on this workload the difference shows up as resident
/// memory the allocator holds above what is live.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
/// Allocations by size, in powers of two from sixteen bytes.
///
/// A count alone says a stage asked thirty thousand times and not what for: a
/// tree of boxed nodes, a string per name and a vector per operand list all
/// read the same. The shape says which, and that decides whether an arena, an
/// interner or a flat vector is the answer.
const SIZE_CLASSES: usize = 10;
static BY_SIZE: [AtomicUsize; SIZE_CLASSES] = [const { AtomicUsize::new(0) }; SIZE_CLASSES];

/// How many allocations of each size class have been made.
pub fn allocations_by_size() -> [usize; SIZE_CLASSES] {
    std::array::from_fn(|index| BY_SIZE[index].load(Ordering::Relaxed))
}

thread_local! {
    /// Where the sampled allocations came from, by captured stack.
    static SAMPLED: std::cell::RefCell<rustc_hash::FxHashMap<String, usize>> =
        std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

static SAMPLING_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Begin attributing sampled allocations to their stacks.
pub fn enable_origin_sampling() {
    SAMPLING_ENABLED.store(true, Ordering::Relaxed);
}

/// The sampled stacks and how many allocations each accounted for, highest
/// first, clearing what was collected.
pub fn take_sampled_origins() -> Vec<(String, usize)> {
    let mut origins = SAMPLED.with_borrow_mut(|sampled| sampled.drain().collect::<Vec<_>>());
    origins.sort_by_key(|origin| std::cmp::Reverse(origin.1));
    origins
}

/// Start counting sizes again from zero, for one measured render.
pub fn reset_size_histogram() {
    for class in &BY_SIZE {
        class.store(0, Ordering::Relaxed);
    }
}

/// The inclusive upper bound of a size class, or `None` for the last.
pub const fn size_class_bound(class: usize) -> Option<usize> {
    if class + 1 == SIZE_CLASSES {
        None
    } else {
        Some(16 << class)
    }
}

/// Count one allocation of `size` bytes: the counting allocator's half of these counters.
pub fn allocated(size: usize) {
    COUNTING.store(true, Ordering::Relaxed);
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    BY_SIZE[size_class(size)].fetch_add(1, Ordering::Relaxed);
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

/// The class whose bound is the least at or above `size`.
fn size_class(size: usize) -> usize {
    (((size.max(16) - 1).ilog2() - 3) as usize).min(SIZE_CLASSES - 1)
}

/// Count `size` bytes freed.
pub fn freed(size: usize) {
    LIVE.fetch_sub(size, Ordering::Relaxed);
}

/// Bytes allocated and not yet freed, where something counts them.
pub fn live_bytes() -> Option<usize> {
    counted(&LIVE)
}

/// How many allocations have been made since the process started, where something counts them.
pub fn allocation_count() -> Option<usize> {
    counted(&ALLOCATIONS)
}

/// The high-water mark since it was last reset, where something counts it.
pub fn peak_bytes() -> Option<usize> {
    counted(&PEAK)
}

/// What grew from `before` to `after`, where both were measured.
pub fn grown(before: Option<usize>, after: Option<usize>) -> Option<usize> {
    Some(after?.saturating_sub(before?))
}

/// A count as evidence spells it: the number, or `unmeasured` where nothing counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence(pub Option<usize>);

impl std::fmt::Display for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(count) => write!(f, "{count}"),
            None => f.write_str("unmeasured"),
        }
    }
}

fn counted(counter: &AtomicUsize) -> Option<usize> {
    COUNTING
        .load(Ordering::Relaxed)
        .then(|| counter.load(Ordering::Relaxed))
}

/// Start a new measurement from what is live now.
///
/// The peak is reset to the live total rather than to zero, because what is
/// already held is part of the next measurement's floor.
pub fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Whether a counting allocator is installed: set by the first allocation it sees.
static COUNTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
mod tests {
    /// Each size falls in the first class whose bound holds it.
    #[test]
    fn a_size_counts_in_the_least_class_that_holds_it() {
        for size in [0, 1, 16, 17, 32, 33, 4096, 8192, 8193, usize::MAX >> 1] {
            let class = super::size_class(size);
            assert!(super::size_class_bound(class).is_none_or(|bound| size <= bound));
            assert!(
                class == 0 || super::size_class_bound(class - 1).is_some_and(|below| size > below)
            );
        }
    }

    /// No counting allocator in the test binary: a reading is unmeasured, never zero.
    #[test]
    fn an_uncounted_reading_is_no_zero() {
        assert_eq!(super::live_bytes(), None);
        assert_eq!(
            super::Evidence(super::live_bytes()).to_string(),
            "unmeasured"
        );
        assert_eq!(super::grown(Some(3), Some(10)), Some(7));
        assert_eq!(super::grown(None, Some(10)), None);
    }
}
