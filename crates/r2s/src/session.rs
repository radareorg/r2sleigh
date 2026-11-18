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
    /// How listings are painted, `scr.color`: 0 none, 1 sixteen colours, 2 256, 3 truecolor;
    /// 1 for a terminal unless `NO_COLOR` says otherwise.
    pub color: u8,
    /// Whether a grep reads the output of the statement running, which an
    /// escape would split. Set for one statement, never a setting.
    pub grepped: bool,
    /// Whether a listing shows each instruction's bytes: `asm.bytes`.
    pub bytes: bool,
    /// Whether each note names its basis and each setter its call: `asm.proof` (r2s only).
    pub proof: bool,
    /// Whether `pdf` draws flow lanes: `asm.lines`.
    pub lines: bool,
    /// The cells the lanes and arrows take, `asm.lines.width`; by the terminal's width where unset.
    pub lines_width: Option<usize>,
    /// The cell each line's first `;` stands at: `asm.cmt.col`.
    pub cmt_col: usize,
    /// Box glyphs, or radare2's ASCII: `scr.utf8`.
    pub utf8: bool,
    /// The terminal's width, where stdout is one: lines are cut to it. A pipe is never cut.
    pub columns: Option<usize>,
    /// Whether `pdd` draws a rail per nesting level: `asm.rails` (r2s only), on for a terminal.
    pub rails: bool,
    /// Whether `pdd` writes each line's lowest instruction before it: `asm.pdd.addr` (r2s only).
    pub pdd_addr: bool,
}

impl Session {
    pub fn open(path: &str) -> Result<Self, String> {
        let image = Image::open(path).map_err(|error| error.to_string())?;
        let program = OpenProgram::of(Opened::of(image));
        Ok(Self {
            color: 0,
            grepped: false,
            bytes: true,
            proof: false,
            lines: true,
            lines_width: None,
            cmt_col: 71,
            utf8: true,
            columns: None,
            rails: false,
            pdd_addr: false,
            addr: program.start().unwrap_or(0),
            program,
            path: path.to_owned(),
        })
    }

    /// The depth what the running statement prints is painted at, where it is painted.
    pub const fn paints(&self) -> Option<r2s_tui::theme::Depth> {
        match self.grepped {
            true => None,
            false => r2s_tui::theme::Depth::of(self.color),
        }
    }

    /// The width the running statement's lines are cut to: the terminal's, unless a grep reads
    /// them, which then reads the plain grid as a pipe would.
    pub const fn width(&self) -> Option<usize> {
        match self.grepped {
            true => None,
            false => self.columns,
        }
    }

    /// Whether `pdd` draws rails for the running statement: `asm.rails`, unless a grep reads it.
    pub const fn railed(&self) -> bool {
        self.rails && !self.grepped
    }

    /// How `pdf`'s gutter is drawn: 10 cells of lanes in plain mode and from 160 columns, 6 under.
    pub fn gutter(&self) -> crate::flow::Gutter {
        let narrow = self.width().is_some_and(|columns| columns < 160);
        crate::flow::Gutter {
            width: (self.lines_width).unwrap_or(if narrow { 6 } else { 10 }),
            utf8: self.utf8,
            lanes: self.lines,
        }
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

    fn patched(&self, vaddr: u64) -> bool {
        self.image.patched(vaddr)
    }
}

#[cfg(test)]
mod tests {
    use super::Session;

    /// A grep reads the plain grid on a terminal too: no cut, no rails, no colour (D565, D568).
    #[test]
    fn a_grepped_statement_is_laid_out_as_a_pipe_is() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/rv_O0g");
        let mut session = Session::open(path).expect("the fixture opens");
        (session.color, session.columns, session.rails) = (1, Some(80), true);
        assert_eq!(session.width(), Some(80));
        assert!(session.railed() && session.paints().is_some());
        assert_eq!(session.gutter().width, 6);
        session.grepped = true;
        assert_eq!(session.width(), None);
        assert!(!session.railed() && session.paints().is_none());
        assert_eq!(session.gutter().width, 10);
    }
}
