//! The process allocator, an allocation count for the timing gate (ROADMAP PF4), and a heap
//! profile (`dhat-heap`, which takes the allocator where both are asked for).

#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static ALLOCATOR: Purging = Purging;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// mimalloc, returning freed pages after every [`PURGE_EVERY`] bytes freed, and in the
/// `alloc-count` build counting each allocation and the live bytes in the engine's counters.
#[cfg(not(feature = "dhat-heap"))]
struct Purging;

/// Bytes freed between two forced collects: the most a free waits to be returned (D338,
/// doc/adr-memory-model.md "Deterministic memory").
#[cfg(not(feature = "dhat-heap"))]
const PURGE_EVERY: usize = 64 << 20;

/// Bytes freed since the last collect. A plain load and store: the engine frees on one thread.
#[cfg(not(feature = "dhat-heap"))]
static FREED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Count `size` bytes freed; collect once [`PURGE_EVERY`] have been, a function of the
/// allocation sequence alone.
#[cfg(not(feature = "dhat-heap"))]
fn freed(size: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let freed = FREED.load(Relaxed) + size;
    if freed < PURGE_EVERY {
        FREED.store(freed, Relaxed);
        return;
    }
    FREED.store(0, Relaxed);
    // SAFETY: mimalloc's collect takes no pointer and may run between any two calls.
    unsafe { libmimalloc_sys::mi_collect(true) }
}

// SAFETY: each method forwards its arguments unchanged to mimalloc's own.
#[cfg(not(feature = "dhat-heap"))]
unsafe impl std::alloc::GlobalAlloc for Purging {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        #[cfg(feature = "alloc-count")]
        r2engine::allocation::allocated(layout.size());
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        #[cfg(feature = "alloc-count")]
        r2engine::allocation::allocated(layout.size());
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        let moved = unsafe { mimalloc::MiMalloc.realloc(ptr, layout, size) };
        // A failed realloc leaves the old block allocated, so it counts nothing.
        if !moved.is_null() {
            #[cfg(feature = "alloc-count")]
            {
                r2engine::allocation::freed(layout.size());
                r2engine::allocation::allocated(size);
            }
            freed(layout.size());
        }
        moved
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        #[cfg(feature = "alloc-count")]
        r2engine::allocation::freed(layout.size());
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) };
        freed(layout.size());
    }
}

/// mimalloc v3's `mi_option_purge_delay` (`include/mimalloc.h`); libmimalloc-sys names none.
const PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

/// Purge on the freed-bytes count alone, never on mimalloc's clock (D338). Before any phase runs.
pub fn install() {
    // About eleven days: no run reaches it, so only a forced collect purges.
    const NEVER: std::ffi::c_long = 1_000_000_000;
    // SAFETY: mimalloc reads its options on every purge decision; nothing else runs yet.
    unsafe { libmimalloc_sys::mi_option_set(PURGE_DELAY, NEVER) };
}

/// The heap profile of one run, where the build takes one and `R2S_HEAP_PROFILE` asks; written to
/// `dhat-heap.json` when it drops.
pub struct Profile {
    #[cfg(feature = "dhat-heap")]
    _heap: Option<dhat::Profiler>,
}

/// Start profiling the heap where the build can and the run asks, so an `--all-features` test run
/// prints nothing extra.
pub fn profile() -> Profile {
    Profile {
        #[cfg(feature = "dhat-heap")]
        _heap: std::env::var_os("R2S_HEAP_PROFILE").map(|_| dhat::Profiler::new_heap()),
    }
}

/// The allocation count and heap peak on stderr where this build counts them and
/// `R2S_ALLOCATIONS` asks (`census.py time` reads them), and the heap profile written, before a
/// script exits.
pub fn report(_profile: Profile) {
    #[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
    if std::env::var_os("R2S_ALLOCATIONS").is_some() {
        use r2engine::allocation::{Evidence, allocation_count, peak_bytes};
        eprintln!("r2s: allocations: {}", Evidence(allocation_count()));
        eprintln!("r2s: heap peak: {}", Evidence(peak_bytes()));
    }
}
