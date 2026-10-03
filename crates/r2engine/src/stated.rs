//! What a word of the program holds when it starts running, as the container states it.
//!
//! The one reader of program memory as data. The file's bytes are what the
//! program reads only where the loader leaves them alone; where it writes, the
//! container states what it writes -- an address of this image, a definition
//! nothing can replace, an import, a resolver's result -- and that statement,
//! not the file's word, is what the program starts with. A listing's word, a
//! dispatch table's entries and a string's bytes all read through here, so a
//! rebased pointer is read as the address it is and a chained fixup is never
//! read as the link it encodes.

use std::ops::Range;

use crate::native::Program;

/// The value a word holds when the program starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatedWord {
    /// This revision's bytes, which the loader leaves alone.
    Held(u64),
    /// The loader writes it, and the container states the address it writes:
    /// one of this image's own, or a definition no other image can replace.
    Loaded(u64),
}

impl StatedWord {
    pub const fn value(self) -> u64 {
        match self {
            Self::Held(value) | Self::Loaded(value) => value,
        }
    }
}

/// Whether the loader writes any byte of `range`: one search.
pub fn written(program: &dyn Program, range: &Range<u64>) -> bool {
    r2abi::statement::writes_any(program.loader_writes(), range)
}

/// What the `width`-byte word at `place` holds when the program starts, where
/// the container states it; `None` where it does not.
///
/// A word the loader leaves alone is read from this revision's bytes, in the
/// container's byte order. A word the loader writes is its stated value where
/// one write covers exactly those bytes and states an address; a word part
/// written, or written with a value chosen when the program runs, states
/// nothing. `O(log W)` in the loader's writes.
pub fn stated_word(
    program: &dyn Program,
    place: u64,
    width: u32,
    endian: r2il::Endianness,
) -> Option<StatedWord> {
    let bytes = usize::try_from(width)
        .ok()
        .filter(|bytes| (1..=8).contains(bytes))?;
    let end = place.checked_add(u64::from(width))?;
    let writes = program.loader_writes();
    if r2abi::statement::writes_any(writes, &(place..end)) {
        let write = r2abi::statement::write_at(writes, place)?;
        let exact = write.place == place && write.width == u64::from(width);
        return exact
            .then(|| write.value())
            .flatten()
            .map(StatedWord::Loaded);
    }
    let read = program
        .read(place, bytes)
        .filter(|read| read.len() == bytes)?;
    let mut word = [0u8; 8];
    word[..bytes].copy_from_slice(&read);
    Some(StatedWord::Held(match endian {
        r2il::Endianness::Little => u64::from_le_bytes(word),
        r2il::Endianness::Big => u64::from_be_bytes(word) >> (8 * (8 - bytes)),
        // Nothing says which way a word reads here, so nothing is claimed.
        r2il::Endianness::Mixed | r2il::Endianness::Custom => return None,
    }))
}
