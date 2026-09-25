//! What the engine is told about a program, by whoever opened it.
//!
//! The engine never opens anything. The shell parses the container and hands
//! over its bytes and what it states -- sections, symbols, relocations, entry
//! points, declared prototypes -- through this trait, and the engine derives
//! everything else from those. That keeps the whole derivation testable from
//! a program built out of byte literals, with no file anywhere.

use std::ops::Range;

/// A program's bytes and the facts its container states.
pub trait Source {
    /// As many bytes as are mapped at `vaddr`, up to `max`, or `None` where
    /// nothing is mapped.
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>>;

    /// What the container states. Fixed for the program's life: a write
    /// changes bytes, never which sections or symbols exist.
    fn container(&self) -> &Container;

    /// Which open program this is. Two opens of one file are two programs,
    /// because one may be patched and the other not.
    fn identity(&self) -> u64;

    /// How many times the program's bytes have been written.
    fn byte_revision(&self) -> u64;

    /// Whether anything in this range has been written since that revision.
    fn written_since(&self, revision: u64, range: &Range<u64>) -> bool;
}

/// What a container states, as the image loader states it.
///
/// One definition, in `r2abi::statement`: the loader produces these and the
/// engine reads them as they are, so a fact the container states reaches every
/// consumer without a copy between them that could narrow it.
pub use r2abi::statement::*;
