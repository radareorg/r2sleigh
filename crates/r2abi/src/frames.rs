//! What a container's call-frame information states about each function.
//!
//! The statement types: r2image reads them out of `.eh_frame` and
//! `.debug_frame`, and the engine reads them without copying them into a
//! shape of its own.

use std::collections::BTreeMap;

/// One function the call-frame information describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindFrame {
    /// The first address the entry covers.
    pub start: u64,
    /// One past the last address it covers.
    pub end: u64,
    /// Where each register the function preserves is saved, as a DWARF
    /// register number and an offset from the stack pointer on entry. Empty
    /// when the CFA on entry is not stated from the stack pointer.
    pub saves: BTreeMap<u16, i64>,
}

/// Every frame the call-frame information states, by start address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnwindFrames {
    by_start: BTreeMap<u64, UnwindFrame>,
}

impl UnwindFrames {
    pub fn frames(&self) -> impl Iterator<Item = &UnwindFrame> {
        self.by_start.values()
    }

    /// The frame that starts at this address.
    pub fn at(&self, start: u64) -> Option<&UnwindFrame> {
        self.by_start.get(&start)
    }

    /// The frame that covers this address. Frames do not overlap, so the
    /// nearest start at or below the address is the only candidate.
    pub fn covering(&self, address: u64) -> Option<&UnwindFrame> {
        self.by_start
            .range(..=address)
            .next_back()
            .map(|(_, frame)| frame)
            .filter(|frame| address < frame.end)
    }

    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }

    /// Record a frame, keeping the first one stated at its start.
    pub fn insert(&mut self, frame: UnwindFrame) {
        // `.eh_frame` and `.debug_frame` may both describe a function. They
        // describe one frame; the first read is kept.
        self.by_start.entry(frame.start).or_insert(frame);
    }
}
