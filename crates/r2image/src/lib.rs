//! Program image: what the engine needs from a binary before any analysis runs.
//!
//! An `Image` answers three questions without radare2: which architecture the
//! bytes are for, where execution can start, and what byte lives at a virtual
//! address. Everything is extracted into owned values at open time, so an
//! `Image` borrows nothing, is `Send + Sync`, and can be shared across analysis
//! threads behind an `Arc`.

use object::read::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::borrow::Cow;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unrecognised binary: {0}")]
    Parse(String),
    #[error("no architecture mapping for {0:?}")]
    UnsupportedArchitecture(object::Architecture),
}

/// Container format the bytes were parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    MachO,
    Pe,
    Coff,
    Wasm,
    Xcoff,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Architecture identity, in the terms a Sleigh specification is selected by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageArch {
    /// Name as the lifter spells it, such as `x86-64` or `AArch64`.
    pub name: &'static str,
    pub bits: u32,
    pub endian: Endian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// One loadable range, mapping a file extent onto a virtual address range.
#[derive(Debug, Clone)]
pub struct Segment {
    pub vaddr: u64,
    /// Virtual size, which exceeds `file_size` wherever the range is zero-filled.
    pub vsize: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: Permissions,
    pub name: Option<String>,
}

impl Segment {
    pub fn contains(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr - self.vaddr < self.vsize
    }
}

/// One named range the format declares, finer-grained than a segment.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub file_offset: u64,
    pub file_size: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    Other,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub kind: SymbolKind,
    /// False for an undefined symbol, which names an import rather than a body.
    pub defined: bool,
    /// Whether this function's code is Thumb, which ARM states in the low bit
    /// of the symbol's value. False on every other machine.
    pub thumb: bool,
}

/// Why an address is a place execution can begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The format's declared entry point.
    Main,
    /// Listed in an initialiser or finaliser array.
    Init,
    Fini,
    /// Named by a symbol typed as a function.
    Symbol,
}

#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub vaddr: u64,
    pub kind: EntryKind,
}

/// One slot the loader fills with the address of a symbol.
///
/// The slot is where the pointer goes, not where the code is: a call to an
/// import reaches a stub that reads this slot, so naming the stub means
/// following the stub's own read back to here.
#[derive(Debug, Clone)]
pub struct Relocation {
    pub vaddr: u64,
    pub symbol: String,
}

/// The address a code pointer names, with the mode bit taken off.
///
/// On 32-bit ARM the low bit of a function's address selects Thumb rather than
/// forming part of the address: the ELF ABI says so, and no instruction begins
/// at an odd address on a machine whose instructions are two- or four-byte
/// aligned. Keeping the bit made an entry point decode from one byte into
/// itself and every instruction after it read from the wrong place.
///
/// The mode the bit selected is kept beside the address, as `Symbol::thumb`.
fn code_address(arch: &ImageArch, value: u64) -> u64 {
    match is_arm32(arch) {
        true => value & !1,
        false => value,
    }
}

/// Whether the low bit of a function's address selects Thumb on this machine.
fn is_arm32(arch: &ImageArch) -> bool {
    arch.name == "ARM" && arch.bits == 32
}

/// Which symbol each stub and pointer slot stands for, in a Mach-O.
///
/// A section of stubs or of symbol pointers says where its entries begin in the
/// indirect symbol table (`reserved1`) and how wide one entry is
/// (`reserved2`), and the table says which symbol each entry stands for. That
/// is the whole mapping, and it needs no bind-opcode interpreter.
/// Whether the loader maps this section, asked of the format rather than
/// guessed from the address.
///
/// ELF says so outright with `SHF_ALLOC`. The other formats have no section a
/// loader ignores in the same way, so a section they declare is mapped.
fn section_is_loaded<'a>(section: &impl object::read::ObjectSection<'a>) -> bool {
    const SHF_ALLOC: u64 = 0x2;
    match section.flags() {
        object::SectionFlags::Elf { sh_flags } => sh_flags & SHF_ALLOC != 0,
        _ => true,
    }
}

fn macho_indirect_symbols(file: &object::File<'_>, data: &[u8]) -> Vec<Relocation> {
    match file {
        object::File::MachO64(macho) => indirect_symbols(macho, data),
        object::File::MachO32(macho) => indirect_symbols(macho, data),
        _ => Vec::new(),
    }
}

/// The two fields a Mach-O section uses to point into the indirect symbol
/// table. They are struct fields rather than trait methods in `object`, so a
/// generic walk over both widths needs this to reach them.
trait IndirectRange {
    fn first_indirect(&self, endian: object::Endianness) -> u32;
    fn entry_stride(&self, endian: object::Endianness) -> u32;
}

impl IndirectRange for object::macho::Section64<object::Endianness> {
    fn first_indirect(&self, endian: object::Endianness) -> u32 {
        self.reserved1.get(endian)
    }

    fn entry_stride(&self, endian: object::Endianness) -> u32 {
        self.reserved2.get(endian)
    }
}

impl IndirectRange for object::macho::Section32<object::Endianness> {
    fn first_indirect(&self, endian: object::Endianness) -> u32 {
        self.reserved1.get(endian)
    }

    fn entry_stride(&self, endian: object::Endianness) -> u32 {
        self.reserved2.get(endian)
    }
}

fn indirect_symbols<'data, Mach, R>(
    file: &object::read::macho::MachOFile<'data, Mach, R>,
    data: &'data [u8],
) -> Vec<Relocation>
where
    Mach: object::read::macho::MachHeader<Endian = object::Endianness>,
    Mach::Section: IndirectRange,
    R: object::ReadRef<'data>,
{
    use object::read::macho::{Nlist as _, Section as _};
    use object::{Object, ObjectSection, macho};

    let endian = match file.macho_header().endian() {
        Ok(endian) => endian,
        Err(_) => return Vec::new(),
    };
    let Ok(mut commands) = file.macho_header().load_commands(endian, data, 0) else {
        return Vec::new();
    };
    let mut table = None;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(dysymtab)) = command.dysymtab() {
            table = Some(dysymtab);
            break;
        }
    }
    let Some(dysymtab) = table else {
        return Vec::new();
    };
    let offset = dysymtab.indirectsymoff.get(endian) as usize;
    let count = dysymtab.nindirectsyms.get(endian) as usize;
    let Some(end) = count
        .checked_mul(4)
        .and_then(|size| offset.checked_add(size))
    else {
        return Vec::new();
    };
    let Some(bytes) = data.get(offset..end) else {
        return Vec::new();
    };
    let indirect: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|word| {
            let word = [word[0], word[1], word[2], word[3]];
            match endian {
                object::Endianness::Big => u32::from_be_bytes(word),
                object::Endianness::Little => u32::from_le_bytes(word),
            }
        })
        .collect();

    let symbols = file.macho_symbol_table();
    let mut named = Vec::new();
    for section in file.sections() {
        let raw = section.macho_section();
        let kind = raw.flags(endian) & macho::SECTION_TYPE;
        if !matches!(
            kind,
            macho::S_NON_LAZY_SYMBOL_POINTERS
                | macho::S_LAZY_SYMBOL_POINTERS
                | macho::S_SYMBOL_STUBS
        ) {
            continue;
        }
        let stride = match kind {
            macho::S_SYMBOL_STUBS => u64::from(raw.entry_stride(endian)),
            _ if file.is_64() => 8,
            _ => 4,
        };
        if stride == 0 {
            continue;
        }
        let first = raw.first_indirect(endian) as usize;
        let entries = section.size() / stride;
        for entry in 0..entries {
            let Some(index) = indirect.get(first + entry as usize).copied() else {
                break;
            };
            if index & (macho::INDIRECT_SYMBOL_LOCAL | macho::INDIRECT_SYMBOL_ABS) != 0 {
                continue;
            }
            let Ok(symbol) = symbols.symbol(object::SymbolIndex(index as usize)) else {
                continue;
            };
            let Ok(name) = symbol.name(endian, symbols.strings()) else {
                continue;
            };
            let Ok(name) = core::str::from_utf8(name) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            named.push(Relocation {
                vaddr: section.address() + entry * stride,
                symbol: name.to_owned(),
            });
        }
    }
    named
}

/// A parsed binary, with its bytes retained for address reads.
#[derive(Debug, Clone)]
pub struct Image {
    data: Vec<u8>,
    format: Format,
    arch: ImageArch,
    base_address: u64,
    segments: Vec<Segment>,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    entry_points: Vec<EntryPoint>,
    relocations: Vec<Relocation>,
}

impl Image {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageError> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|source| ImageError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, ImageError> {
        let data = match select_fat_slice(&data)? {
            Some(range) => data[range].to_vec(),
            None => data,
        };
        let file = object::File::parse(&*data).map_err(|e| ImageError::Parse(e.to_string()))?;

        let arch = map_architecture(file.architecture(), file.is_64(), file.endianness())?;
        let format = map_format(file.format());
        let base_address = file.relative_address_base();

        let mut segments: Vec<Segment> = file
            .segments()
            .map(|segment| {
                let (file_offset, file_size) = segment.file_range();
                Segment {
                    vaddr: segment.address(),
                    vsize: segment.size(),
                    file_offset,
                    file_size,
                    permissions: map_permissions(segment.flags()),
                    name: segment.name().ok().flatten().map(str::to_owned),
                }
            })
            .filter(|segment| segment.vsize > 0)
            .collect();
        segments.sort_by_key(|segment| segment.vaddr);

        // A format whose segments do not map (an object file) still has sections.
        if segments.is_empty() {
            segments = file
                .sections()
                .filter(|section| section.address() != 0 || section.size() != 0)
                .map(|section| {
                    let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
                    Segment {
                        vaddr: section.address(),
                        vsize: section.size(),
                        file_offset,
                        file_size,
                        permissions: Permissions::RX,
                        name: section.name().ok().map(str::to_owned),
                    }
                })
                .collect();
            segments.sort_by_key(|segment| segment.vaddr);
        }

        // Both tables, because a stripped shared library has no `.symtab` and
        // every name it still carries is in `.dynsym`. Reading only the first
        // is why such a library listed no functions at all.
        let read_symbol = |symbol: object::read::Symbol<'_, '_>| {
            let name = symbol.name().ok()?;
            if name.is_empty() {
                return None;
            }
            Some(Symbol {
                name: name.to_owned(),
                vaddr: match symbol.kind() {
                    object::SymbolKind::Text => code_address(&arch, symbol.address()),
                    _ => symbol.address(),
                },
                size: symbol.size(),
                kind: match symbol.kind() {
                    object::SymbolKind::Text => SymbolKind::Function,
                    object::SymbolKind::Data => SymbolKind::Data,
                    object::SymbolKind::Section => SymbolKind::Section,
                    _ => SymbolKind::Other,
                },
                defined: symbol.is_definition(),
                thumb: is_arm32(&arch)
                    && symbol.kind() == object::SymbolKind::Text
                    && symbol.address() & 1 == 1,
            })
        };
        let mut symbols: Vec<Symbol> = file
            .symbols()
            .filter_map(&read_symbol)
            .chain(file.dynamic_symbols().filter_map(&read_symbol))
            .collect();
        // One name at one address is one symbol, whichever table held it.
        symbols.sort_by(|left, right| {
            left.vaddr
                .cmp(&right.vaddr)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| right.defined.cmp(&left.defined))
        });
        symbols.dedup_by(|left, right| left.vaddr == right.vaddr && left.name == right.name);

        // What the loader will write into each slot it fills. `object` reports
        // the dynamic relocations for a linked image and the static ones for an
        // object file, and both name their symbol the same way.
        let mut relocations: Vec<Relocation> = file
            .dynamic_relocations()
            .into_iter()
            .flatten()
            .filter_map(|(vaddr, relocation)| {
                let object::RelocationTarget::Symbol(index) = relocation.target() else {
                    return None;
                };
                let table = file.dynamic_symbol_table()?;
                let symbol =
                    object::read::ObjectSymbolTable::symbol_by_index(&table, index).ok()?;
                let name = symbol.name().ok()?;
                (!name.is_empty()).then(|| Relocation {
                    vaddr,
                    symbol: name.to_owned(),
                })
            })
            .collect();
        // Mach-O states its imports through the indirect symbol table rather
        // than through relocations, and `object` reports none for it.
        relocations.extend(macho_indirect_symbols(&file, data.as_slice()));
        relocations.sort_by(|left, right| left.vaddr.cmp(&right.vaddr));
        relocations.dedup_by_key(|relocation| relocation.vaddr);

        let sections: Vec<Section> = file
            .sections()
            .map(|section| {
                let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
                Section {
                    name: section.name().unwrap_or_default().to_owned(),
                    vaddr: section.address(),
                    vsize: section.size(),
                    file_offset,
                    file_size,
                    is_code: section.kind() == object::SectionKind::Text,
                    loaded: section_is_loaded(&section),
                }
            })
            .collect();

        // Code lives in code sections, not merely in executable segments: Mach-O
        // puts __cstring and __const inside __TEXT, and the header itself starts it.
        let code_ranges: Vec<(u64, u64)> = sections
            .iter()
            .filter(|section| section.is_code && section.vsize > 0)
            .map(|section| (section.vaddr, section.vsize))
            .collect();
        let executable = |vaddr: u64| {
            if code_ranges.is_empty() {
                return segments
                    .iter()
                    .any(|segment| segment.contains(vaddr) && segment.permissions.execute);
            }
            code_ranges
                .iter()
                .any(|(address, size)| vaddr >= *address && vaddr - *address < *size)
        };

        let mut entry_points = Vec::new();
        let entry = code_address(&arch, file.entry());
        if entry != 0 {
            // Mach-O states the entry as a file offset, so translate when unmapped.
            let vaddr = if executable(entry) {
                Some(entry)
            } else {
                file_offset_to_vaddr(&segments, entry).filter(|vaddr| executable(*vaddr))
            };
            if let Some(vaddr) = vaddr {
                entry_points.push(EntryPoint {
                    vaddr,
                    kind: EntryKind::Main,
                });
            }
        }
        for symbol in &symbols {
            if symbol.kind == SymbolKind::Function && symbol.defined && executable(symbol.vaddr) {
                entry_points.push(EntryPoint {
                    vaddr: symbol.vaddr,
                    kind: EntryKind::Symbol,
                });
            }
        }
        let pointer_bytes = (arch.bits / 8) as usize;
        for (section, kind) in [
            (".init_array", EntryKind::Init),
            (".fini_array", EntryKind::Fini),
        ] {
            let Some(section) = file.section_by_name(section) else {
                continue;
            };
            let Ok(bytes) = section.data() else {
                continue;
            };
            for slot in bytes.chunks_exact(pointer_bytes) {
                let vaddr = code_address(&arch, read_pointer(slot, arch.endian));
                if vaddr != 0 {
                    entry_points.push(EntryPoint { vaddr, kind });
                }
            }
        }
        entry_points.sort_by_key(|entry| (entry.vaddr, entry.kind as u8));
        entry_points.dedup_by_key(|entry| (entry.vaddr, entry.kind as u8));

        Ok(Self {
            data,
            format,
            arch,
            base_address,
            segments,
            sections,
            symbols,
            entry_points,
            relocations,
        })
    }

    pub fn format(&self) -> Format {
        self.format
    }

    pub fn arch(&self) -> &ImageArch {
        &self.arch
    }

    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// The slots the loader fills, in address order.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    pub fn entry_points(&self) -> &[EntryPoint] {
        &self.entry_points
    }

    pub fn segment_at(&self, vaddr: u64) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.contains(vaddr))
    }

    /// Bytes at a virtual address, or `None` when the range is not all mapped.
    ///
    /// A range reaching past a segment's file extent reads as zero, which is how
    /// `.bss` and any other zero-filled tail answers. The borrowed case is the
    /// common one; only a read crossing into a zero-filled tail allocates.
    pub fn read(&self, vaddr: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        if len == 0 {
            return Some(Cow::Borrowed(&[]));
        }
        let segment = self.segment_at(vaddr)?;
        // An unreadable range is not zeroes; Mach-O __PAGEZERO is the whole low 4GiB.
        if !segment.permissions.read {
            return None;
        }
        let offset_in_segment = vaddr - segment.vaddr;
        if (len as u64) > segment.vsize - offset_in_segment {
            return None;
        }

        let backed = segment
            .file_size
            .saturating_sub(offset_in_segment)
            .min(len as u64) as usize;
        // A range starting past the file extent has no file offset to index.
        let backed_bytes: &[u8] = if backed == 0 {
            &[]
        } else {
            let start = (segment.file_offset + offset_in_segment) as usize;
            self.data.get(start..start.checked_add(backed)?)?
        };
        if backed == len {
            return Some(Cow::Borrowed(backed_bytes));
        }

        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(backed_bytes);
        bytes.resize(len, 0);
        Some(Cow::Owned(bytes))
    }

    /// As much of `max` bytes at `vaddr` as the containing segment holds.
    ///
    /// A decoder wants a window rather than an exact length, since it does not
    /// know an instruction's size until it has read it, and a window at the end
    /// of a segment is short rather than absent.
    pub fn read_upto(&self, vaddr: u64, max: usize) -> Option<Cow<'_, [u8]>> {
        let segment = self.segment_at(vaddr)?;
        let available = (segment.vsize - (vaddr - segment.vaddr)).min(max as u64) as usize;
        self.read(vaddr, available)
    }

    /// Whether the address is inside a segment marked executable.
    pub fn is_executable(&self, vaddr: u64) -> bool {
        self.segment_at(vaddr)
            .is_some_and(|segment| segment.permissions.execute)
    }
}

/// Byte range of the slice to analyse in a universal Mach-O, or `None` if thin.
///
/// The choice is by fixed preference rather than by host architecture, so the
/// same binary yields the same analysis on every machine.
fn select_fat_slice(data: &[u8]) -> Result<Option<std::ops::Range<usize>>, ImageError> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};

    let kind = object::FileKind::parse(data).map_err(|e| ImageError::Parse(e.to_string()))?;
    let arches: Vec<(object::Architecture, (u64, u64))> = match kind {
        object::FileKind::MachOFat32 => MachOFatFile32::parse(data)
            .map_err(|e| ImageError::Parse(e.to_string()))?
            .arches()
            .iter()
            .map(|arch| (arch.architecture(), arch.file_range()))
            .collect(),
        object::FileKind::MachOFat64 => MachOFatFile64::parse(data)
            .map_err(|e| ImageError::Parse(e.to_string()))?
            .arches()
            .iter()
            .map(|arch| (arch.architecture(), arch.file_range()))
            .collect(),
        _ => return Ok(None),
    };

    let preference = [object::Architecture::Aarch64, object::Architecture::X86_64];
    let chosen = preference
        .iter()
        .find_map(|wanted| arches.iter().find(|(arch, _)| arch == wanted))
        .or_else(|| {
            arches
                .iter()
                .find(|(arch, _)| map_architecture(*arch, true, object::Endianness::Little).is_ok())
        })
        .ok_or_else(|| {
            ImageError::Parse(format!(
                "universal binary carries no supported slice: {:?}",
                arches.iter().map(|(arch, _)| *arch).collect::<Vec<_>>()
            ))
        })?;

    let (offset, size) = chosen.1;
    let start = offset as usize;
    let end = start
        .checked_add(size as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| ImageError::Parse("universal slice runs past the file".to_owned()))?;
    Ok(Some(start..end))
}

/// Virtual address a file offset maps to, for a format that states one.
fn file_offset_to_vaddr(segments: &[Segment], offset: u64) -> Option<u64> {
    segments
        .iter()
        .filter(|segment| segment.file_size > 0)
        .find(|segment| {
            offset >= segment.file_offset && offset - segment.file_offset < segment.file_size
        })
        .map(|segment| segment.vaddr + (offset - segment.file_offset))
}

fn read_pointer(slot: &[u8], endian: Endian) -> u64 {
    let mut value: u64 = 0;
    match endian {
        Endian::Little => {
            for (index, byte) in slot.iter().enumerate() {
                value |= (*byte as u64) << (8 * index);
            }
        }
        Endian::Big => {
            for byte in slot {
                value = (value << 8) | *byte as u64;
            }
        }
    }
    value
}

fn map_format(format: object::BinaryFormat) -> Format {
    match format {
        object::BinaryFormat::Elf => Format::Elf,
        object::BinaryFormat::MachO => Format::MachO,
        object::BinaryFormat::Pe => Format::Pe,
        object::BinaryFormat::Coff => Format::Coff,
        object::BinaryFormat::Wasm => Format::Wasm,
        object::BinaryFormat::Xcoff => Format::Xcoff,
        _ => Format::Other,
    }
}

fn map_permissions(flags: object::SegmentFlags) -> Permissions {
    match flags {
        object::SegmentFlags::Elf { p_flags, .. } => Permissions {
            read: p_flags & 0x4 != 0,
            write: p_flags & 0x2 != 0,
            execute: p_flags & 0x1 != 0,
        },
        object::SegmentFlags::MachO { initprot, .. } => Permissions {
            read: initprot & 0x1 != 0,
            write: initprot & 0x2 != 0,
            execute: initprot & 0x4 != 0,
        },
        object::SegmentFlags::Coff {
            characteristics, ..
        } => Permissions {
            read: characteristics & 0x4000_0000 != 0,
            write: characteristics & 0x8000_0000 != 0,
            execute: characteristics & 0x2000_0000 != 0,
        },
        _ => Permissions::RX,
    }
}

fn map_architecture(
    arch: object::Architecture,
    is_64: bool,
    endianness: object::Endianness,
) -> Result<ImageArch, ImageError> {
    let endian = match endianness {
        object::Endianness::Little => Endian::Little,
        object::Endianness::Big => Endian::Big,
    };
    // Names are the lifter's spelling, not the object crate's.
    let name = match arch {
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => "x86-64",
        object::Architecture::I386 => "x86",
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => "AArch64",
        object::Architecture::Arm => "ARM",
        other => return Err(ImageError::UnsupportedArchitecture(other)),
    };
    Ok(ImageArch {
        name,
        bits: if is_64 { 64 } else { 32 },
        endian,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_with(segments: Vec<Segment>, data: Vec<u8>) -> Image {
        Image {
            data,
            format: Format::Elf,
            arch: ImageArch {
                name: "x86-64",
                bits: 64,
                endian: Endian::Little,
            },
            base_address: 0,
            segments,
            sections: Vec::new(),
            symbols: Vec::new(),
            entry_points: Vec::new(),
            relocations: Vec::new(),
        }
    }

    fn segment(vaddr: u64, vsize: u64, file_offset: u64, file_size: u64) -> Segment {
        Segment {
            vaddr,
            vsize,
            file_offset,
            file_size,
            permissions: Permissions::RX,
            name: None,
        }
    }

    #[test]
    fn reads_a_file_backed_range_without_copying() {
        let image = image_with(vec![segment(0x1000, 4, 0, 4)], vec![1, 2, 3, 4]);
        assert!(matches!(
            image.read(0x1000, 4),
            Some(Cow::Borrowed([1, 2, 3, 4]))
        ));
        assert!(matches!(image.read(0x1002, 2), Some(Cow::Borrowed([3, 4]))));
    }

    #[test]
    fn reads_a_zero_filled_tail_as_zero() {
        let image = image_with(vec![segment(0x1000, 8, 0, 2)], vec![0xaa, 0xbb]);
        assert_eq!(image.read(0x1000, 4).unwrap().as_ref(), &[0xaa, 0xbb, 0, 0]);
        assert_eq!(image.read(0x1004, 2).unwrap().as_ref(), &[0, 0]);
    }

    #[test]
    fn refuses_a_range_leaving_its_segment() {
        let image = image_with(vec![segment(0x1000, 4, 0, 4)], vec![1, 2, 3, 4]);
        assert!(image.read(0x1000, 5).is_none());
        assert!(image.read(0x0fff, 1).is_none());
        assert!(image.read(0x2000, 1).is_none());
    }

    #[test]
    fn does_not_read_across_a_gap_between_segments() {
        let image = image_with(
            vec![segment(0x1000, 4, 0, 4), segment(0x3000, 4, 4, 4)],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
        assert!(image.read(0x1002, 4).is_none());
        assert!(matches!(
            image.read(0x3000, 4),
            Some(Cow::Borrowed([5, 6, 7, 8]))
        ));
    }

    #[test]
    fn reads_a_pointer_in_both_orders() {
        assert_eq!(
            read_pointer(&[0x78, 0x56, 0x34, 0x12], Endian::Little),
            0x1234_5678
        );
        assert_eq!(
            read_pointer(&[0x12, 0x34, 0x56, 0x78], Endian::Big),
            0x1234_5678
        );
    }
}

#[cfg(test)]
mod dynamic_symbol_tests {
    use super::*;

    /// A shared object with a `.dynsym` and no `.symtab`, which is what a
    /// stripped library is.
    fn stripped_library() -> Vec<u8> {
        const TEXT: u64 = 0x1000;
        let names = b"\0pick\0";
        let sections = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0";
        let mut out = vec![0u8; TEXT as usize];
        out.extend_from_slice(&[0x31, 0xc0, 0xc3]); // xor eax, eax; ret
        let dynstr = out.len() as u64;
        out.extend_from_slice(names);
        let dynsym = out.len() as u64;
        out.extend_from_slice(&[0u8; 24]); // the null symbol
        out.extend_from_slice(&1u32.to_le_bytes()); // st_name -> "pick"
        out.push(0x12); // global function
        out.push(0); // st_other
        out.extend_from_slice(&1u16.to_le_bytes()); // st_shndx -> .text
        out.extend_from_slice(&TEXT.to_le_bytes());
        out.extend_from_slice(&3u64.to_le_bytes()); // st_size
        let shstrtab = out.len() as u64;
        out.extend_from_slice(sections);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff = out.len() as u64;

        // `sh_flags`: SHF_ALLOC marks what the loader maps, and only that.
        const ALLOC: u64 = 0x2;
        const EXEC: u64 = 0x4;
        let mut section =
            |name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64, link: u32| {
                out.extend_from_slice(&name.to_le_bytes());
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&addr.to_le_bytes());
                out.extend_from_slice(&offset.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&link.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes()); // sh_info
                out.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
                out.extend_from_slice(&if kind == 11 { 24u64 } else { 0 }.to_le_bytes());
            };
        section(0, 0, 0, 0, 0, 0, 0); // the null section
        section(1, 1, ALLOC | EXEC, TEXT, TEXT, 3, 0); // .text
        section(7, 3, ALLOC, 0, dynstr, names.len() as u64, 0); // .dynstr
        section(15, 11, ALLOC, 0, dynsym, 48, 2); // .dynsym, linked to .dynstr
        // The section-header string table is not mapped, and so has no address.
        section(23, 3, 0, 0, shstrtab, sections.len() as u64, 0); // .shstrtab

        let mut header = Vec::new();
        header.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        header.extend_from_slice(&[0u8; 8]);
        header.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
        header.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&TEXT.to_le_bytes()); // e_entry
        header.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        header.extend_from_slice(&shoff.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        header.extend_from_slice(&64u16.to_le_bytes());
        header.extend_from_slice(&56u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes()); // one program header
        header.extend_from_slice(&64u16.to_le_bytes());
        header.extend_from_slice(&5u16.to_le_bytes()); // five sections
        header.extend_from_slice(&4u16.to_le_bytes()); // .shstrtab

        let mut program = Vec::new();
        program.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        program.extend_from_slice(&5u32.to_le_bytes()); // read and execute
        program.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        program.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
        program.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
        program.extend_from_slice(&shoff.to_le_bytes()); // p_filesz
        program.extend_from_slice(&shoff.to_le_bytes()); // p_memsz
        program.extend_from_slice(&1u64.to_le_bytes()); // p_align

        out[..64].copy_from_slice(&header);
        out[64..120].copy_from_slice(&program);
        out
    }

    #[test]
    fn a_section_the_loader_ignores_is_not_a_place_data_lives() {
        // `.shstrtab` has no virtual address, so it is reported at zero and
        // appears to cover the start of the image. A consumer asking what
        // lives at an address got it for everything below its size, which is
        // how a structure offset of eighty came to be rendered as the string
        // at address eighty.
        let image = Image::parse(stripped_library()).expect("the fixture parses");
        let named = |name: &str| {
            image
                .sections()
                .iter()
                .find(|section| section.name == name)
                .unwrap_or_else(|| panic!("{name} is in the fixture"))
                .loaded
        };
        assert!(named(".text"));
        assert!(!named(".shstrtab"));
    }

    #[test]
    fn a_stripped_library_still_lists_the_functions_its_dynamic_table_names() {
        // Every name such a library carries is in `.dynsym`; reading only
        // `.symtab` left one listing no functions at all.
        let image = Image::parse(stripped_library()).expect("the fixture parses");
        let named = image
            .symbols()
            .iter()
            .find(|symbol| symbol.name == "pick")
            .expect("the dynamic table names it");
        assert_eq!(named.vaddr, 0x1000);
        assert_eq!(named.kind, SymbolKind::Function);
        assert!(named.defined);
    }
}
