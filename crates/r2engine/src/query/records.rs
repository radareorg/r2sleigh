//! What a listing is made of, before anything formats it.
//!
//! One record per line, and one annotation per thing the engine can say about
//! it. The shell used to build each line by rewriting the decoder's prose
//! seven times and then substituting a name wherever a hexadecimal run
//! happened to equal an address it knew; these are the answers it needs
//! instead, and what is left for it is column layout.

use r2il::Endianness;
use r2sleigh_lift::{EmbeddedMachine, NumberSpan, Syntax};
use r2ssa::fate::{Fate, Fates};

use super::Support;
use super::references::ReferenceKind;
use crate::native::Program;

/// Which decoder the code at an address is written in.
///
/// ARM states the instruction set per function, in the low bit of the symbol
/// that names it, so a program has no one decoder and a listing that crosses a
/// boundary decodes the rest of itself wrongly unless it asks again at every
/// line.
pub trait Decoders {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine>;
}

/// A call's callee, as the call names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Callee {
    /// A direct call to this address.
    At(u64),
    /// A call through the word at this address, which names a callee only where the loader fills it with an import.
    ThroughSlot(u64),
}

/// Which parameters of a callee take an address, and what shows it.
///
/// One owner answers for every listing: a declaration for an import, the
/// callee's own prepared body otherwise, each read once per callee.
pub trait Parameters {
    /// How well a call is shown to hand an address in one of the `held` storages, where it is.
    ///
    /// The callee is read only when one of them is a register its convention passes an argument in.
    fn pointer_use(
        &self,
        callee: Callee,
        held: &dyn Fn(&r2ssa::CanonicalStorageId) -> bool,
    ) -> Option<Support>;
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
    /// Whether the program maps this address at all.
    pub(super) fn maps(&self, address: u64) -> bool {
        self.program.read(address, 1).is_some()
    }

    /// Whether a section the program loads holds this address.
    pub(super) fn declares(&self, address: u64) -> bool {
        self.program.extents().holds(address)
    }

    /// The text this revision holds at an address in a section of static data, where it holds text the loader leaves alone.
    pub(super) fn text(&self, address: u64) -> Option<String> {
        let text = crate::native::text_at(self.program, address)?;
        let end = address.saturating_add(text.len() as u64 + 1);
        (!self.program.loader_writes(&(address..end))).then_some(text)
    }

    /// The value this revision holds at an address, where it holds one the loader leaves alone.
    pub(super) fn word(&self, address: u64, width: u32) -> Option<u64> {
        let width = usize::try_from(width)
            .ok()
            .filter(|width| (1..=8).contains(width))?;
        // A rebased pointer or an import's slot reads as what the loader wrote there, which the file does not hold.
        if self
            .program
            .loader_writes(&(address..address.saturating_add(width as u64)))
        {
            return None;
        }
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
    /// What a call does, where the program's convention was read.
    pub call_effect: Option<&'a r2ssa::SourceCallEffect>,
    /// The function's analysis; absent below `Work::Function`, which is what keeps a listing cheap.
    pub prepared: Option<&'a crate::native::Prepared>,
    /// The def-use of the body the run is in, which says whether a number it computes is a step.
    pub fate: Option<&'a DefUse<'a>>,
    /// Whether each line is spelled; the reference index reads only what the lines claim.
    pub spelled: bool,
    /// Which parameters of each callee take an address, where the listing can ask.
    pub parameters: Option<&'a dyn Parameters>,
}

/// The def-use of one body and every value's fate on it, built the first time a line's fate needs them.
pub struct DefUse<'a> {
    built: std::cell::OnceCell<Option<(r2ssa::SsaGraph, Fates)>>,
    blocks: &'a [r2il::R2ILBlock],
    arch: &'a r2il::ArchSpec,
}

impl<'a> DefUse<'a> {
    pub fn new(blocks: &'a [r2il::R2ILBlock], arch: &'a r2il::ArchSpec) -> Self {
        Self {
            built: std::cell::OnceCell::new(),
            blocks,
            arch,
        }
    }

    /// What becomes of the value one instruction leaves in a storage, as the body's def-use settles it.
    pub fn fate_of(&self, instruction: u64, storage: r2ssa::CanonicalStorageId) -> Option<Fate> {
        let (graph, fates) = self.settled()?;
        let value = graph.left_by_instruction(instruction, storage)?;
        Some(fates.of_value(value))
    }

    /// What one instruction alone makes of the value it leaves in a storage, read off the lift's own operations.
    pub fn own_bound(
        &self,
        instruction: u64,
        storage: r2ssa::CanonicalStorageId,
    ) -> Option<r2ssa::InstructionBound> {
        let (graph, _) = self.settled()?;
        r2ssa::instruction_bound(graph, instruction, storage)
    }

    /// The graph and the fates, built now if nothing has asked for them yet.
    fn settled(&self) -> Option<&(r2ssa::SsaGraph, Fates)> {
        self.built
            .get_or_init(|| {
                let graph = r2ssa::def_use_graph(self.blocks, Some(self.arch))?;
                let fates = Fates::of(&graph);
                Some((graph, fates))
            })
            .as_ref()
    }

    /// Whether a line needed the graph and it did not build.
    pub fn failed(&self) -> bool {
        matches!(self.built.get(), Some(None))
    }
}

/// A run of instructions: where it starts, and where it stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing {
    pub start: u64,
    pub stop: Stop,
}

/// Where a listing stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// After this many lines, which is what `pd N` asks for.
    After(usize),
    /// At this address, which is what a block's extent says. Asking for a
    /// count and discarding what ran past the end decoded, lifted and read the
    /// bytes of whatever came next.
    At(u64),
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
    /// Whether the claim names an address of this program, and how; the reference index is these.
    pub reference: Option<ReferenceKind>,
}

/// What one annotation claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationKind {
    /// The instruction encodes a transfer of control to this address.
    Target { address: u64, call: bool },
    /// The instruction reads this many bytes at this address.
    Reads { address: u64, width: u32 },
    /// The instruction writes this many bytes at this address.
    Writes { address: u64, width: u32 },
    /// The instruction computes this address, and nothing later derives another number from it.
    ///
    /// Only a number proven to be an address: lifting the instruction a page
    /// further on moves it by that page, so it is where the program itself is.
    /// An absolute number is claimed only where it is used as one.
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
    /// The revision this answer names holds this value at that address, and the loader leaves it there.
    ///
    /// Not "the load returns it". Nothing here says the bytes will still be
    /// these when the instruction runs, and saying so would be the one claim
    /// a listing cannot support.
    Holds {
        address: u64,
        width: u32,
        value: u64,
    },
    /// The revision holds this text where a claim on the line uses the address; like `Holds`, never that the line reads it.
    Text { address: u64, text: String },
}

impl AnnotationKind {
    /// The address this claim is about.
    pub fn address(&self) -> u64 {
        match *self {
            Self::Target { address, .. }
            | Self::Reads { address, .. }
            | Self::Writes { address, .. }
            | Self::Holds { address, .. }
            | Self::Text { address, .. } => address,
            Self::Computes { value } => value,
            // A range is about a storage, not about an address in the program.
            Self::Bounds { low, .. } => low,
        }
    }
}
