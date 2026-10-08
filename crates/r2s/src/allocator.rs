//! The process allocator, and an allocation count for the timing gate (ROADMAP PF4).

#[cfg(not(feature = "alloc-count"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "alloc-count")]
#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[cfg(feature = "alloc-count")]
static ALLOCATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// mimalloc, counting each allocation and reallocation.
#[cfg(feature = "alloc-count")]
struct Counting;

// SAFETY: each method forwards its arguments unchanged to mimalloc's own.
#[cfg(feature = "alloc-count")]
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) }
    }
}

/// The allocation count on stderr where this build counts them and `R2S_ALLOCATIONS` asks;
/// `census.py time` reads it.
pub fn report() {
    #[cfg(feature = "alloc-count")]
    if std::env::var_os("R2S_ALLOCATIONS").is_some() {
        eprintln!(
            "r2s: allocations: {}",
            ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed)
        );
    }
}
