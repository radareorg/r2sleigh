//! The file's bytes as an image holds them: mapped from the file it was opened from, or owned
//! (doc/adr-memory-model.md, MM.4).

use std::ops::{Deref, Range};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) enum Held {
    Owned(Vec<u8>),
    Mapped {
        map: Arc<memmap2::Mmap>,
        range: Range<usize>,
    },
}

impl Held {
    /// The file at `file`, mapped read-only. An empty file is held as nothing, which no map is.
    pub(crate) fn map(file: &std::fs::File) -> std::io::Result<Self> {
        if file.metadata()?.len() == 0 {
            return Ok(Self::Owned(Vec::new()));
        }
        // SAFETY: the map is read-only. A file changed under it changes what a read sees and one
        // cut short faults the reader, as with radare2's own map of the file.
        let map = unsafe { memmap2::Mmap::map(file) }?;
        let range = 0..map.len();
        Ok(Self::Mapped {
            map: Arc::new(map),
            range,
        })
    }

    /// Only `range` of these bytes: one slice of a fat Mach-O.
    pub(crate) fn narrowed(self, within: Range<usize>) -> Self {
        match self {
            Self::Owned(bytes) => Self::Owned(bytes[within].to_vec()),
            Self::Mapped { map, range } => Self::Mapped {
                map,
                range: range.start + within.start..range.start + within.end,
            },
        }
    }
}

impl Deref for Held {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped { map, range } => &map[range.clone()],
        }
    }
}
