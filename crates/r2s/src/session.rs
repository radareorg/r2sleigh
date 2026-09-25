//! The shell's state: the open binary and the seek cursor.
//!
//! The shell is what opens the file. It parses the container once, hands the
//! engine the bytes and what the container states through `Source`, and keeps
//! the cursor. Everything derived from those -- names, import stubs, what is
//! defined where -- is the engine's.

use r2engine::program::{Container, OpenProgram, Source};
use r2image::Image;

pub struct Session {
    pub program: OpenProgram<Opened>,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
}

impl Session {
    pub fn open(path: &str) -> Result<Self, String> {
        let image = Image::open(path).map_err(|error| error.to_string())?;
        let program = OpenProgram::of(Opened::of(image));
        Ok(Self {
            addr: program.start().unwrap_or(0),
            program,
            path: path.to_owned(),
        })
    }

    /// The binary as the container states it.
    pub fn image(&self) -> &Image {
        &self.program.source().image
    }

    /// The binary, to be written to.
    pub fn image_mut(&mut self) -> &mut Image {
        &mut self.program.source_mut().image
    }
}

/// An opened binary, as the engine reads it: the image is the source, and
/// what its container states is handed over as the loader read it.
pub struct Opened {
    pub image: Image,
}

impl Opened {
    const fn of(image: Image) -> Self {
        Self { image }
    }
}

impl Source for Opened {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.image
            .read_upto(vaddr, max)
            .map(std::borrow::Cow::into_owned)
    }

    fn container(&self) -> &Container {
        self.image.container()
    }

    fn identity(&self) -> u64 {
        self.image.identity()
    }

    fn byte_revision(&self) -> u64 {
        self.image.byte_revision()
    }

    fn written_since(&self, revision: u64, range: &std::ops::Range<u64>) -> bool {
        self.image.written_since(revision, range)
    }
}
