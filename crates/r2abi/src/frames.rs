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
    /// How control enters the frame's first address, as its first row states it.
    pub entry: FrameEntry,
    /// Each call-site range of the frame's LSDA, absolute and sorted by start (doc/adr-radare2-function-walk.md, "Unwind edges as built").
    pub pads: Box<[CallSiteRange]>,
    /// Whether that table was read, and why not.
    pub lsda: LsdaRead,
}

/// One record of a call-site table: a call whose last byte lies in `start..end` unwinds to `pad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSiteRange {
    pub start: u64,
    pub end: u64,
    /// The landing pad; `None` where the record states 0, no cleanup and no handler.
    pub pad: Option<u64>,
}

/// What a frame's language-specific data area states, as read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LsdaRead {
    /// The frame names no LSDA, or its CIE states no personality.
    #[default]
    None,
    /// Read under the personality row named, a declaration of the import the CIE's pointer resolves to.
    Read(&'static crate::runtime::Personality),
    /// The personality has a row but the table does not read.
    Refused(LsdaRefusal),
    /// The CIE's personality resolves to no cited row: the table's format is unstated.
    PersonalityUnstated,
}

/// Why a table under a cited personality was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsdaRefusal {
    /// The LSDA pointer is not mapped, or names no byte the file holds.
    Unmapped,
    /// An encoding the personality's reader does not state, or a field past the table's end.
    Malformed,
    /// The records do not end at the call-site table's stated length.
    Length,
    /// A call-site range outside its frame.
    RangeOutsideFrame,
    /// A landing pad outside every frame of the image.
    PadOutsideFrames,
}

/// The state the call-frame information states at a frame's first address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FrameEntry {
    /// The state a call leaves: the CFA the return address alone sets, no other register saved.
    Called,
    /// Any other state: a part of a function that its own code jumps to, as GCC's `.cold` is.
    MidFunction,
    /// Not stated: no call state is known for the architecture, or the first row did not read.
    #[default]
    Unstated,
}

/// Every frame the call-frame information states, by start address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnwindFrames {
    by_start: BTreeMap<u64, UnwindFrame>,
    /// Every call-site range with a pad, sorted and disjoint, as `seal_pads` left them.
    landing: Vec<CallSiteRange>,
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

    /// The landing pad of a call whose last byte is `last`, as the unwinder looks it up from the
    /// return address less one (GCC `eh_personality.cc`: `--ip`). O(log R) over every pad's range.
    pub fn pad_for(&self, last: u64) -> Option<u64> {
        let at = self.landing.partition_point(|range| range.start <= last);
        let range = self.landing.get(at.checked_sub(1)?)?;
        (last < range.end).then_some(range.pad).flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }

    /// Refuse each frame's table where a landing pad lies outside every frame, then index every
    /// range with a pad for `pad_for`; call once every frame is inserted. O(R log F + R log R).
    pub fn seal_pads(&mut self) {
        let stray = (self.frames())
            .filter(|frame| {
                (frame.pads.iter().filter_map(|range| range.pad))
                    .any(|pad| self.covering(pad).is_none())
            })
            .map(|frame| frame.start)
            .collect::<Vec<_>>();
        for start in stray {
            if let Some(frame) = self.by_start.get_mut(&start) {
                frame.pads = Box::default();
                frame.lsda = LsdaRead::Refused(LsdaRefusal::PadOutsideFrames);
            }
        }
        let landing = (self.by_start.values()).flat_map(|frame| frame.pads.iter());
        self.landing = landing
            .filter(|range| range.pad.is_some())
            .copied()
            .collect();
        self.landing.sort_unstable_by_key(|range| range.start);
    }

    /// Record a frame, keeping the first one stated at its start.
    pub fn insert(&mut self, frame: UnwindFrame) {
        // `.eh_frame` and `.debug_frame` may both describe a function. They
        // describe one frame; the first read is kept.
        self.by_start.entry(frame.start).or_insert(frame);
    }
}
