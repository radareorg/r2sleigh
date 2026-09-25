//! What a container states about a program, in the one shape every reader shares.
//!
//! The image loader produces these and nothing else restates them: the engine
//! reads them through its `Source`, and the shell spells them. They were three
//! copies once -- the loader's, the engine's, and a field-by-field projection
//! between the two in the shell -- and every fact added to one had to be added
//! to all three, where the middle one narrowed whatever it did not know about.
//!
//! Nothing here is inferred. Each field is what the file says, in the file's
//! own terms, so a consumer that disagrees with one is disagreeing with the
//! container and not with a reading of it.

use std::ops::Range;

/// Everything the container states that the engine reads.
///
/// Fixed for the program's life: a write to the bytes changes what they hold,
/// never which sections, symbols or relocations exist.
#[derive(Debug, Clone, Default)]
pub struct Container {
    pub format: Format,
    pub arch: Arch,
    /// The address the image's first file byte is mapped at, which is how
    /// radare2 presents `baddr`. Presentation only: no value the engine
    /// computes is relative to it.
    pub base_address: u64,
    /// Where the loader maps the program and what it permits there, sorted by
    /// address and disjoint.
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    /// The bytes the loader writes before the program runs, sorted and
    /// disjoint; what the file holds there is not what the program reads.
    pub loader_writes: Vec<Range<u64>>,
    pub entries: Vec<Entry>,
    /// Prototypes the program's own debug information declares.
    pub declared: Vec<crate::Prototype>,
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

/// The container format the bytes were parsed as.
///
/// Mach-O decorates a C name with a leading underscore and names its stubs
/// rather than the slots they read; which platform's prototypes apply follows
/// from it too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    Elf,
    MachO,
    Pe,
    Coff,
    Wasm,
    Xcoff,
    #[default]
    Other,
}

/// How a word in memory reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// The machine the container says the code is for, in the terms a Sleigh
/// specification is selected by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arch {
    /// As the lifter spells it, such as `x86-64` or `AArch64`.
    pub name: String,
    pub bits: u32,
    /// How a word in memory reads, which on ARM BE8 is not how an instruction
    /// does.
    pub endian: Endian,
}

/// What a segment permits, as the container states it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// One run of addresses the loader maps, and what the program may do there.
///
/// The loader's statement, not the linker's: a section says what the bytes
/// were for, and a segment says whether an instruction there can run at all
/// and whether the program can write the bytes once it does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    /// Virtual size, which exceeds `file_size` wherever the range is zero-filled.
    pub vsize: u64,
    pub file_offset: u64,
    /// How many of its bytes, from its start, the file holds. The loader
    /// fills the rest of `vsize` with zeros.
    pub file_size: u64,
    pub permissions: Permissions,
    pub name: Option<String>,
}

impl Segment {
    pub const fn contains(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr - self.vaddr < self.vsize
    }

    /// The half-open range of addresses the segment occupies.
    pub const fn range(&self) -> (u64, u64) {
        (self.vaddr, self.vaddr.saturating_add(self.vsize))
    }

    /// The address after the last byte the file holds; never past the segment's end.
    pub const fn file_end(&self) -> u64 {
        let held = if self.file_size < self.vsize {
            self.file_size
        } else {
            self.vsize
        };
        self.vaddr.saturating_add(held)
    }
}

/// One named range the format declares, finer-grained than a segment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub file_offset: u64,
    pub file_size: u64,
    /// Whether the container states this section holds instructions.
    ///
    /// Stated, not inferred from a name: ELF says it with `SHF_EXECINSTR`,
    /// COFF with `IMAGE_SCN_CNT_CODE` or `IMAGE_SCN_MEM_EXECUTE`, and Mach-O
    /// with the `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`
    /// attribute. Mach-O's `__stubs` and `__auth_stubs` state it too, so the
    /// stub a call lands on is never data a string can be read out of.
    pub is_code: bool,
    /// Whether the loader maps this section, so `vaddr` is an address at all.
    ///
    /// A section the loader ignores -- `.shstrtab`, `.symtab`, the debug
    /// sections -- is reported at address zero, which makes it appear to cover
    /// the start of the image. A consumer asking what lives at an address got
    /// `.shstrtab` for everything below its size, which is how a structure
    /// offset of eighty came to be rendered as the string at address eighty.
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    #[default]
    Other,
    /// An ARM mapping symbol: where the bytes become code of one instruction
    /// set, or data.
    Mapping(Mapping),
}

/// What an ARM mapping symbol (`$a`, `$t`, `$d`) says the bytes from it are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    Arm,
    Thumb,
    Data,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub kind: SymbolKind,
    /// Whether the symbol names a place in this program rather than an import.
    pub defined: bool,
    /// Whether the function it names is Thumb, which ARM states in the low bit
    /// of the symbol's value. False on every other machine.
    pub thumb: bool,
}

/// A slot the loader fills, and the symbol it fills it with.
///
/// The slot is where the pointer goes, not where the code is: a call to an
/// import reaches a stub that reads this slot, so naming the stub means
/// following the stub's own read back to here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relocation {
    pub vaddr: u64,
    pub symbol: String,
}

/// Why an address is a place execution can begin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EntryKind {
    /// The format's declared entry point.
    #[default]
    Main,
    /// Listed in an initialiser or finaliser array.
    Init,
    Fini,
    /// Named by a symbol typed as a function.
    Symbol,
    /// The C `main` the format names outright.
    ///
    /// Mach-O's `LC_MAIN` carries the offset of `main` itself, not of the
    /// runtime's start routine, so the language's own declaration applies:
    /// `main` returns `int`. An ELF entry is `_start`, which is a different
    /// function and returns nothing, so this kind is never used for one.
    CMain,
    /// Listed in the Mach-O function-starts table.
    ///
    /// The linker writes one entry per function it laid out, so this is the
    /// binary's own statement of where its functions begin -- including the
    /// ones no symbol names and nothing calls directly.
    Declared,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Entry {
    pub vaddr: u64,
    pub kind: EntryKind,
    /// Whether the address selected Thumb, on a machine where bit 0 does.
    ///
    /// The bit is not part of the address and is masked out of `vaddr`; what
    /// it said about the instruction set is kept here, exactly as it is for a
    /// symbol. A static ARM binary whose `e_entry` is odd starts in Thumb, and
    /// decoding it as ARM produces plausible instructions that are not there.
    pub thumb: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(vaddr: u64, vsize: u64) -> Segment {
        Segment {
            vaddr,
            vsize,
            file_size: vsize,
            ..Segment::default()
        }
    }

    #[test]
    fn the_segment_holding_an_address_is_one_search_and_gaps_hold_nothing() {
        let container = Container {
            segments: vec![segment(0x1000, 0x10), segment(0x3000, 0x10)],
            ..Container::default()
        };
        let at = |vaddr| container.segment_at(vaddr).map(|segment| segment.vaddr);
        assert_eq!(at(0x1008), Some(0x1000));
        assert_eq!(at(0x2000), None);
        assert_eq!(at(0x300f), Some(0x3000));
        assert_eq!(at(0x3010), None);
    }

    #[test]
    fn a_range_touching_a_loader_write_is_written_and_one_beside_it_is_not() {
        let container = Container {
            loader_writes: vec![0x10..0x18, 0x40..0x48],
            ..Container::default()
        };
        assert!(container.loader_writes_any(&(0x14..0x15)));
        assert!(container.loader_writes_any(&(0x08..0x11)));
        assert!(!container.loader_writes_any(&(0x18..0x40)));
    }
}
