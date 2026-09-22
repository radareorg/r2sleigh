//! What a listing is made of, before anything formats it.
//!
//! One record per line, and one annotation per thing the engine can say about
//! it. The shell used to build each line by rewriting the decoder's prose
//! seven times and then substituting a name wherever a hexadecimal run
//! happened to equal an address it knew; these are the answers it needs
//! instead, and what is left for it is column layout.

use r2il::Endianness;
use r2sleigh_lift::{EmbeddedMachine, NumberSpan, Syntax};
use r2ssa::body::Program;

use super::Support;

/// Which decoder the code at an address is written in.
///
/// ARM states the instruction set per function, in the low bit of the symbol
/// that names it, so a program has no one decoder and a listing that crosses a
/// boundary decodes the rest of itself wrongly unless it asks again at every
/// line.
pub trait Decoders {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine>;
}

/// The program's own memory, and how it spells a word in it.
///
/// The endianness is the container's and not the decoder's. ARM BE8 is the
/// case that forces them apart: instructions are little-endian there while
/// data is big, so asking the Sleigh specification which way a pool word reads
/// gives the wrong answer on exactly the binaries that have pool words.
pub struct Memory<'a> {
    pub program: &'a dyn Program,
    pub endian: Endianness,
}

impl Memory<'_> {
    /// The value this revision holds at an address, where it holds one.
    pub(super) fn word(&self, address: u64, width: u32) -> Option<u64> {
        let width = usize::try_from(width)
            .ok()
            .filter(|width| (1..=8).contains(width))?;
        let read = self
            .program
            .read(address, width)
            .filter(|read| read.len() == width)?;
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(&read);
        Some(match self.endian {
            Endianness::Little => u64::from_le_bytes(bytes),
            Endianness::Big => u64::from_be_bytes(bytes) >> (8 * (8 - width as u32)),
            // Nothing says which way a word reads here, so nothing is claimed.
            Endianness::Mixed | Endianness::Custom => return None,
        })
    }
}

/// What a listing is answered from.
///
/// The decoder, the bytes, and -- where the request paid for it -- what the
/// engine proved about the function the run is inside. The three travel
/// together from the request down into every line.
pub struct Answered<'a> {
    pub decoders: &'a dyn Decoders,
    pub memory: Memory<'a>,
    /// Absent below `Work::Function`, which is what keeps a listing cheap.
    pub facts: Option<&'a r2ssa::SsaArtifact>,
}

/// A run of instructions, asked for by where it starts and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing {
    pub start: u64,
    pub count: usize,
}

/// One line of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub address: u64,
    /// The bytes this line accounts for: the whole instruction, or the single
    /// byte that did not begin one.
    pub bytes: Vec<u8>,
    /// How the decoder spells it. Absent where the bytes are not an instruction.
    pub syntax: Option<Syntax>,
    pub annotations: Vec<Annotation>,
}

impl Line {
    /// Whether the bytes decoded at all.
    pub fn decoded(&self) -> bool {
        self.syntax.is_some()
    }
}

/// Something the engine can say about one instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub kind: AnnotationKind,
    pub support: Support,
    /// Which number in the operand body this is about, where exactly one of
    /// them spells it. Two operands holding the same value leave this empty
    /// rather than guessing which was meant.
    pub operand: Option<NumberSpan>,
}

/// What one annotation claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationKind {
    /// The instruction encodes a transfer of control to this address.
    Target { address: u64, call: bool },
    /// The instruction reads this many bytes at this address.
    Reads { address: u64, width: u32 },
    /// The instruction writes this many bytes at this address.
    Writes { address: u64, width: u32 },
    /// The instruction produces this number, and nothing later in the run
    /// reads it back.
    ///
    /// `lea rdi, 0x4070` computes an address and that is its whole result;
    /// `adrp x17, 0x100008000` computes a page base the next instruction moves
    /// fifty bytes past. The difference is not in either instruction, which is
    /// why this is the rung above one.
    Computes { value: u64 },
    /// The value this instruction defines lies in this range wherever it is
    /// live.
    ///
    /// Not refined to this point. The range is narrowed where the value is
    /// defined, because every execution that defines it passes there, so
    /// reading it as what the storage holds *here* would claim more than was
    /// proved.
    Bounds {
        storage: r2ssa::CanonicalStorageId,
        low: u64,
        high: u64,
        stride: u64,
    },
    /// The revision this answer names holds this value at that address.
    ///
    /// Not "the load returns it". Nothing here says the bytes will still be
    /// these when the instruction runs, and saying so would be the one claim
    /// a listing cannot support.
    Holds {
        address: u64,
        width: u32,
        value: u64,
    },
}

impl AnnotationKind {
    /// The address this claim is about.
    pub fn address(self) -> u64 {
        match self {
            Self::Target { address, .. }
            | Self::Reads { address, .. }
            | Self::Writes { address, .. }
            | Self::Holds { address, .. } => address,
            Self::Computes { value } => value,
            // A range is about a storage, not about an address in the program.
            Self::Bounds { low, .. } => low,
        }
    }
}
