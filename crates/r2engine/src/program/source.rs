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
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub entries: Vec<Entry>,
    /// Prototypes the program's own debug information declares.
    pub declared: Vec<r2abi::Prototype>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub is_code: bool,
    /// Whether the loader maps it at all. A section it does not map occupies
    /// no address.
    pub loaded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    Other,
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
