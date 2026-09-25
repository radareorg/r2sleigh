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

/// What a container states, in the shape the engine reads it.
#[derive(Debug, Clone, Default)]
pub struct Container {
    pub format: Format,
    pub arch: Arch,
    /// Where the loader maps the program and what it permits there, sorted by address and disjoint.
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    /// The bytes the loader writes before the program runs, sorted and disjoint; what the file holds there is not what the program reads.
    pub loader_writes: Vec<Range<u64>>,
    pub entries: Vec<Entry>,
    /// Prototypes the program's own debug information declares.
    pub declared: Vec<r2abi::Prototype>,
}

impl Container {
    /// The segment holding `vaddr`: one search over the sorted, disjoint segments.
    pub fn segment_at(&self, vaddr: u64) -> Option<&Segment> {
        let after = self
            .segments
            .partition_point(|segment| segment.vaddr <= vaddr);
        let segment = self.segments.get(after.checked_sub(1)?)?;
        segment.contains(vaddr).then_some(segment)
    }

    /// Whether the loader writes any byte of this range: one search over the sorted, disjoint writes.
    pub fn loader_writes_any(&self, range: &Range<u64>) -> bool {
        let first = self
            .loader_writes
            .partition_point(|written| written.end <= range.start);
        self.loader_writes
            .get(first)
            .is_some_and(|written| written.start < range.end)
    }
}

/// The container format, where it decides something the engine does.
///
/// Mach-O decorates a C name with a leading underscore and names its stubs
/// rather than the slots they read; which platform's prototypes apply follows
/// from it too. Nothing else about the format reaches the engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    Elf,
    MachO,
    #[default]
    Other,
}

/// The machine the container says the code is for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arch {
    /// As the lifter spells it, such as `x86-64` or `ARM`.
    pub name: String,
    pub bits: u32,
    /// How a word in memory reads, which on ARM BE8 is not how an instruction
    /// does.
    pub endian: r2il::Endianness,
}

/// One run of addresses the loader maps, and what the program may do there.
///
/// The loader's statement, not the linker's: a section says what the bytes
/// were for, and a segment says whether an instruction there can run at all
/// and whether the program can write the bytes once it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub vsize: u64,
    pub permissions: Permissions,
}

impl Segment {
    pub const fn contains(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr - self.vaddr < self.vsize
    }

    /// The half-open range of addresses the segment occupies.
    pub const fn range(&self) -> (u64, u64) {
        (self.vaddr, self.vaddr.saturating_add(self.vsize))
    }
}

/// What a segment permits, as the container states it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    /// Whether the container states this section holds instructions, as its
    /// own flags or attributes say, never as its name suggests.
    pub is_code: bool,
    /// Whether the loader maps it at all. A section it does not map occupies
    /// no address.
    pub loaded: bool,
}

impl Section {
    /// Whether static data can live here: a section the loader maps that the
    /// container does not state holds instructions.
    ///
    /// The one answer to where static data can be, which the name table, a
    /// listing's text and the decompiler's literals all read. What makes a
    /// constant the address of a string is where it points, and "the bytes
    /// there read as text" is far too weak a test -- almost any pair of bytes
    /// does. A structure offset of eighty was rendered as the string at
    /// address eighty, which is two bytes of the ELF header and in no section
    /// at all; the stub a Mach-O call lands on read as the string `"1"` while
    /// the container stated it held instructions.
    pub const fn holds_static_data(&self) -> bool {
        self.loaded && !self.is_code && self.vsize > 0
    }

    /// The half-open range of addresses the section occupies.
    pub const fn range(&self) -> (u64, u64) {
        (self.vaddr, self.vaddr.saturating_add(self.vsize))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    Other,
    /// An ARM mapping symbol: where the bytes become code of one instruction
    /// set, or data.
    Mapping(Mapping),
}

/// What an ARM mapping symbol says the bytes from it are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    Arm,
    Thumb,
    Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub kind: SymbolKind,
    /// Whether the symbol names a place in this program rather than an import.
    pub defined: bool,
    /// Whether the function it names is Thumb, on a machine where that exists.
    pub thumb: bool,
}

/// A slot the loader fills, and the symbol it fills it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub vaddr: u64,
    pub symbol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The format's declared entry point.
    Main,
    /// Listed in an initialiser or finaliser array.
    Init,
    Fini,
    /// Named by a symbol typed as a function.
    Symbol,
    /// The C `main` the format names outright.
    CMain,
    /// Listed in the Mach-O function-starts table.
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub vaddr: u64,
    pub kind: EntryKind,
    pub thumb: bool,
}
