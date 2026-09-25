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
    /// Every relocation record the loader or the program's start-up applies,
    /// each once, in the order they are applied.
    pub relocations: Vec<Relocation>,
    /// The stubs the format declares stand for imports.
    pub import_stubs: Vec<ImportStub>,
    /// What the loader writes before the program runs, and what the container
    /// states it writes, sorted by place and disjoint: several records
    /// writing one place are composed in the order the loader applies them.
    /// What the file holds at any of these bytes is not what the program reads.
    pub loader_writes: Vec<LoaderWrite>,
    pub entries: Vec<Entry>,
    /// Ranges of writable segments the loader makes read-only once it is
    /// done, sorted and disjoint: ELF's `PT_GNU_RELRO`, and a Mach-O segment
    /// flagged `SG_READ_ONLY`, whose fixups dyld applies before sealing it.
    pub sealed: Vec<Range<u64>>,
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

    /// Each slot the loader fills with the address of an import, and the
    /// import's name as the record states it.
    ///
    /// A call to an import reaches a stub that reads one of these, or reads
    /// one itself; a word bound to a symbol this image defines, a copy, or a
    /// thread-local offset is no such slot.
    pub fn import_slots(&self) -> impl Iterator<Item = (u64, &str)> {
        self.loader_writes
            .iter()
            .filter_map(|write| match &write.kind {
                WriteKind::Import { symbol } if !symbol.is_empty() => {
                    Some((write.place, symbol.as_str()))
                }
                _ => None,
            })
    }

    /// Whether the loader writes any byte of this range: one search over the sorted, disjoint writes.
    pub fn loader_writes_any(&self, range: &Range<u64>) -> bool {
        writes_any(&self.loader_writes, range)
    }

    /// The loader's write covering `place`, where it makes one: one search.
    pub fn loader_write_at(&self, place: u64) -> Option<&LoaderWrite> {
        write_at(&self.loader_writes, place)
    }

    /// Whether nothing can write any byte of `range` once the program runs.
    ///
    /// A segment mapped without write permission is immutable for the whole
    /// run; a writable one is immutable after load only where the loader
    /// seals it. Either way what the loader wrote first is what stays, so a
    /// word here holds its stated value for the whole run. `O(log S)`.
    pub fn immutable(&self, range: &Range<u64>) -> bool {
        if range.start >= range.end {
            return true;
        }
        let read_only = self
            .segment_at(range.start)
            .is_some_and(|segment| !segment.permissions.write && range.end <= segment.range().1);
        let after = self
            .sealed
            .partition_point(|sealed| sealed.start <= range.start);
        let sealed = after
            .checked_sub(1)
            .and_then(|at| self.sealed.get(at))
            .is_some_and(|sealed| range.end <= sealed.end);
        read_only || sealed
    }

    /// The bytes the loader writes, as sorted, disjoint ranges with touching ones made one.
    pub fn written_ranges(&self) -> Vec<Range<u64>> {
        let mut ranges: Vec<Range<u64>> = Vec::with_capacity(self.loader_writes.len());
        for write in &self.loader_writes {
            match ranges.last_mut() {
                Some(last) if write.place <= last.end => last.end = last.end.max(write.end()),
                _ => ranges.push(write.place..write.end()),
            }
        }
        ranges
    }
}

/// Whether any of the sorted, disjoint `writes` touches `range`: one binary search.
pub fn writes_any(writes: &[LoaderWrite], range: &Range<u64>) -> bool {
    let first = writes.partition_point(|written| written.end() <= range.start);
    writes
        .get(first)
        .is_some_and(|written| written.place < range.end)
}

/// The one of the sorted, disjoint `writes` covering `place`: one binary search.
pub fn write_at(writes: &[LoaderWrite], place: u64) -> Option<&LoaderWrite> {
    let first = writes.partition_point(|written| written.end() <= place);
    writes.get(first).filter(|written| written.place <= place)
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
    /// What the container states the section holds.
    pub role: SectionRole,
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
    /// Whether the container states this section holds instructions.
    pub fn is_code(&self) -> bool {
        self.role == SectionRole::Code
    }

    /// Whether the program's static data can live here: a section the loader
    /// maps that the container states holds the program's own data.
    ///
    /// The one answer to where static data can be, which the name table, a
    /// listing's text and the decompiler's literals all read. What makes a
    /// constant the address of a string is where it points, and "the bytes
    /// there read as text" is far too weak a test -- almost any pair of bytes
    /// does. A structure offset of eighty was rendered as the string at
    /// address eighty, which is two bytes of the ELF header and in no section
    /// at all; the stub a Mach-O call lands on read as the string `"1"` while
    /// the container stated it held instructions; and the loader's own tables
    /// -- the interpreter's path, a build note, the dynamic string table, the
    /// unwind tables -- were listed as the program's strings.
    pub fn holds_static_data(&self) -> bool {
        self.loaded && self.vsize > 0 && self.role.is_program_data()
    }

    /// The half-open range of addresses the section occupies.
    pub const fn range(&self) -> (u64, u64) {
        (self.vaddr, self.vaddr.saturating_add(self.vsize))
    }
}

/// What a section holds, as the container states it: its type and flags,
/// and the program headers that name it, never its name.
///
/// ELF states it with `sh_type` and `sh_flags` -- `SHT_NOBITS`,
/// `SHF_MERGE|SHF_STRINGS`, the loader's own table types -- and with the
/// program headers that locate the interpreter's path (`PT_INTERP`) and the
/// unwind tables (`PT_GNU_EH_FRAME`, whose `eh_frame_ptr` names `.eh_frame`).
/// Mach-O states it with the section type (`S_ZEROFILL`,
/// `S_CSTRING_LITERALS`) and its attributes; its unwind sections are the ones
/// the runtime finds by their segment and section name, which is how the
/// format identifies them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SectionRole {
    /// Instructions: `SHF_EXECINSTR`, `IMAGE_SCN_CNT_CODE`, or a Mach-O
    /// instructions attribute. Mach-O's `__stubs` and `__auth_stubs` state it
    /// too, so the stub a call lands on is never data a string is read from.
    Code,
    /// The program's data, which it may write once it runs.
    Data,
    /// The program's data, which nothing writes once the loader is done.
    ReadOnlyData,
    /// C strings, as the container states: `SHF_STRINGS`, `S_CSTRING_LITERALS`.
    Strings,
    /// The program's data, which the loader fills with zeros.
    ZeroFill,
    /// The loader's own tables: symbols, strings, relocations, hashes,
    /// versions, notes, the dynamic table and the interpreter's path.
    LoaderMetadata,
    /// The unwinder's tables.
    Unwind,
    /// A kind the container states that no role here names.
    #[default]
    Other,
}

impl SectionRole {
    /// Whether this holds data of the program's own, where a string or an
    /// object can be.
    pub const fn is_program_data(self) -> bool {
        matches!(
            self,
            Self::Data | Self::ReadOnlyData | Self::Strings | Self::ZeroFill
        )
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

/// One relocation record the loader, or the program's own start-up, applies.
///
/// A record, not a place: two records writing one slot are two records, and
/// one record reached through two views of the same table -- the dynamic
/// table's and a section header's -- is one. Where it writes is `vaddr`; which
/// record it is, is `record`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relocation {
    /// Where it writes, in the coordinates the image is linked at.
    pub vaddr: u64,
    /// Which record this is.
    pub record: Record,
    /// The format's own number for what it computes: ELF's `r_type`, or the
    /// Mach-O rebase or bind type. Zero where the format numbers nothing.
    pub ntype: u32,
    /// How many bytes it writes.
    pub width: u64,
    /// The addend the record states, where it states one. `None` where the
    /// word the file holds at `vaddr` is the addend: ELF `REL` and `RELR`, and
    /// a Mach-O rebase.
    pub addend: Option<i64>,
    /// The symbol it is computed against, where it names one.
    pub symbol: Option<RelocationSymbol>,
    /// What the loader computes for it.
    pub applies: Applies,
}

/// Where a relocation record is stated in the file.
///
/// `table` is a file offset and `index` a position there: an ELF `REL` or
/// `RELA` entry is at its own offset with index zero, a `RELR` bitmap word
/// states one record per bit, and a record decoded out of a stream (Android's
/// packed tables, a Mach-O opcode stream or chain) is the stream's offset and
/// its position in it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Record {
    pub table: u64,
    pub index: u64,
}

/// The symbol a relocation is computed against, as the table it names states it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationSymbol {
    pub name: String,
    /// The address this image defines it at; `None` where it is an import.
    pub defined: Option<u64>,
    pub size: u64,
    pub binding: Binding,
    pub visibility: Visibility,
}

/// What the loader computes for one relocation, by its type.
///
/// The psABI of each machine says it per type number; this is the part of it
/// the value of the word depends on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Applies {
    /// The image's own address, moved with it: the addend, or the word the file holds.
    Relative,
    /// The symbol's address, whatever the record's addend (`GLOB_DAT`, `JUMP_SLOT`).
    Symbol,
    /// The symbol's address plus the addend (`R_X86_64_64`, `R_AARCH64_ABS64`).
    SymbolPlusAddend,
    /// The address a resolver function returns; the addend is the resolver.
    Resolver,
    /// A thread-local module number or offset, which is no address.
    ThreadLocal,
    /// The bytes of an object another image defines, copied in.
    Copy,
    /// A type whose computation this reader does not state.
    #[default]
    Unknown,
}

/// A symbol's binding, as the table states it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Binding {
    Local,
    #[default]
    Global,
    Weak,
    /// A binding the format numbers but this reader does not name.
    Other(u8),
}

/// A symbol's visibility, as ELF's `st_other` states it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Visibility {
    #[default]
    Default,
    Internal,
    Hidden,
    Protected,
}

/// Bytes the loader writes before the program runs, and what the container states it writes there.
///
/// Values are in the coordinates the image is linked at. The load bias moves
/// every address the image states by one amount, so an address of this image
/// is its link-time value here: a relative relocation's value is its addend,
/// never the addend plus wherever `baddr` puts the first file byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderWrite {
    pub place: u64,
    pub width: u64,
    pub kind: WriteKind,
}

impl LoaderWrite {
    /// The address after its last byte.
    pub const fn end(&self) -> u64 {
        self.place.saturating_add(self.width)
    }

    /// The address the word holds once the program runs, where the container
    /// states it outright: an address of this image, or a definition in it
    /// no other image can replace.
    pub const fn value(&self) -> Option<u64> {
        match self.kind {
            WriteKind::Relative(value) | WriteKind::Absolute(value) => Some(value),
            _ => None,
        }
    }

    /// The address of this image the container states the word holds when the
    /// program starts, which is a reference from the word whether or not
    /// another image may replace it later.
    pub const fn stated_address(&self) -> Option<u64> {
        match self.kind {
            WriteKind::Relative(value)
            | WriteKind::Absolute(value)
            | WriteKind::Preemptible { default: value, .. } => Some(value),
            _ => None,
        }
    }
}

/// What the loader writes into one place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WriteKind {
    /// An address of this image, moved with it.
    Relative(u64),
    /// The address of a definition in this image that no other image can
    /// replace: the executable's own, a hidden or protected one, or any under
    /// `DT_SYMBOLIC`.
    Absolute(u64),
    /// The address of an import, which another image defines.
    Import { symbol: String },
    /// This image's own definition, which an image loaded ahead of it may
    /// replace; `default` is what the word holds when none does.
    Preemptible { symbol: String, default: u64 },
    /// What a resolver function returns. The resolver is at the address this
    /// states; what it returns is chosen when the program runs.
    Resolver(u64),
    /// A thread-local module number or offset, which is no address.
    NotAnAddress,
    /// Written, with no value the container states: a copy of another image's
    /// object, a word its psABI reserves, a signed pointer, or a format this
    /// reader does not decode.
    #[default]
    Unknown,
}

/// One stub the format itself declares stands for an import.
///
/// Mach-O states it outright: a section of type `S_SYMBOL_STUBS` holds one
/// stub per entry, `reserved2` bytes each, and the indirect symbol table says
/// which import each stands for. The stub is code a call lands on, so it is
/// never a relocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStub {
    pub vaddr: u64,
    pub size: u64,
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
        let write = |place, width| LoaderWrite {
            place,
            width,
            kind: WriteKind::Unknown,
        };
        let container = Container {
            loader_writes: vec![write(0x10, 8), write(0x18, 8), write(0x40, 8)],
            ..Container::default()
        };
        assert!(container.loader_writes_any(&(0x14..0x15)));
        assert!(container.loader_writes_any(&(0x08..0x11)));
        assert!(!container.loader_writes_any(&(0x20..0x40)));
        assert_eq!(
            container.loader_write_at(0x1f).map(|write| write.place),
            Some(0x18)
        );
        assert_eq!(container.loader_write_at(0x20), None);
        assert_eq!(container.written_ranges(), [0x10..0x20, 0x40..0x48]);
    }
}
