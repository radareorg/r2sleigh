//! A global allocator that counts, so a render can say what it cost in bytes.
//!
//! Installed only under the `alloc-probe` feature. The counters it feeds live
//! in `r2il::allocation`, at the bottom of the crate graph, so every stage can
//! read them without depending on the plugin.
//!
//! The size is taken from the layout the caller passes, which the allocator
//! contract already requires to match between allocation and deallocation, so
//! no header is added and no allocation is made larger.

use std::alloc::{GlobalAlloc, Layout, System};

pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            r2il::allocation::record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        r2il::allocation::record_deallocation(layout.size());
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let grown = unsafe { System.realloc(pointer, layout, new_size) };
        if !grown.is_null() {
            r2il::allocation::record_deallocation(layout.size());
            r2il::allocation::record_allocation(new_size);
        }
        grown
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            r2il::allocation::record_allocation(layout.size());
        }
        pointer
    }
}
