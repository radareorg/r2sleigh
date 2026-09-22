//! The shell's state: an open program and the seek cursor.
//!
//! The cursor lives here and nowhere else. Everything else about the open
//! binary -- its bytes, its decoders, the tables read out of both -- belongs to
//! the engine, so the shell is a client of one surface rather than a layer
//! that keeps its own copy of the answers.

use r2engine::program::OpenProgram;

pub struct Session {
    pub program: OpenProgram,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
}

impl Session {
    pub fn open(path: &str) -> Result<Self, String> {
        let program = OpenProgram::open(path)?;
        let addr = entry_of(&program);
        Ok(Self {
            program,
            path: path.to_owned(),
            addr,
        })
    }
}

/// Where a listing starts before anything has been sought.
///
/// The declared main entry, then any declared entry, then the first code
/// section -- an object file declares no entry at all -- then the first
/// executable segment.
fn entry_of(program: &OpenProgram) -> u64 {
    let image = &program.image;
    image
        .entry_points()
        .iter()
        .find(|entry| entry.kind == r2engine::program::EntryKind::Main)
        .or_else(|| image.entry_points().first())
        .map(|entry| entry.vaddr)
        .or_else(|| {
            image
                .sections()
                .iter()
                .find(|section| section.is_code && section.vsize > 0)
                .map(|section| section.vaddr)
        })
        .or_else(|| {
            image
                .segments()
                .iter()
                .find(|segment| segment.permissions.execute)
                .map(|segment| segment.vaddr)
        })
        .unwrap_or(0)
}
