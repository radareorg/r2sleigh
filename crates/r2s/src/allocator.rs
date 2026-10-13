//! The process allocator, an allocation count for the timing gate (ROADMAP PF4), and a heap
//! profile (`dhat-heap`, which takes the allocator where both are asked for).

#[cfg(not(any(feature = "alloc-count", feature = "dhat-heap")))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// mimalloc, counting each allocation and the bytes live in the engine's counters, which its phase
/// traces read.
#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
struct Counting;

// SAFETY: each method forwards its arguments unchanged to mimalloc's own.
#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        r2engine::allocation::allocated(layout.size());
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        r2engine::allocation::allocated(layout.size());
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        let moved = unsafe { mimalloc::MiMalloc.realloc(ptr, layout, size) };
        // A failed realloc leaves the old block allocated, so it counts nothing.
        if !moved.is_null() {
            r2engine::allocation::freed(layout.size());
            r2engine::allocation::allocated(size);
        }
        moved
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        r2engine::allocation::freed(layout.size());
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) }
    }
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
        eprintln!(
            "r2s: allocations: {}",
            r2engine::allocation::allocation_count()
        );
        eprintln!("r2s: heap peak: {}", r2engine::allocation::peak_bytes());
    }
}
