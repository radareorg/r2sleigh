//! What dyld writes: the chained fixups, the rebase and bind opcode streams, and the relocations of an image older than both; and the stubs the format declares stand for imports.
//!
//! Each fixup is one record, stated where its bytes are: a chained fixup is
//! the word it rewrites, and an opcode stream's write is its position in the
//! stream. A stub is not a record: `S_SYMBOL_STUBS` holds code a call lands
//! on, and the indirect symbol table says which import each stands for.

use std::ops::Range;

use object::macho;
use object::read::macho::{LoadCommandVariant, MachHeader};

use r2abi::statement::{
    Applies, Binding, ImportStub, LoaderWrite, Record, Relocation, RelocationSymbol, Visibility,
    WriteKind,
};

use super::written;

/// What dyld writes into one Mach-O image, and the stubs its format declares.
pub(super) struct Read {
    pub relocations: Vec<Relocation>,
    /// What each record writes, in the order dyld applies them.
    pub writes: Vec<LoaderWrite>,
    /// Every range written, stated by a record or not.
    pub ranges: Vec<Range<u64>>,
    pub stubs: Vec<ImportStub>,
}

/// Every record dyld applies to one Mach-O image, every range it writes, and every stub the image declares.
pub(super) fn read(file: &object::File<'_>, data: &[u8]) -> Read {
    let macho = match file {
        object::File::MachO32(file) => Macho::of(file, data),
        object::File::MachO64(file) => Macho::of(file, data),
        _ => None,
    };
    macho.map_or_else(
        || Read {
            relocations: Vec::new(),
            writes: Vec::new(),
            ranges: Vec::new(),
            stubs: Vec::new(),
        },
        |macho| macho.read(),
    )
}

/// One segment as its load command places it.
struct Segment {
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    writable: bool,
}

/// One section as its load command states it: its type, and where it indexes the indirect symbol table.
struct Section {
    addr: u64,
    size: u64,
    flags: u32,
    /// `reserved1`: its first entry in the indirect symbol table.
    first_indirect: u32,
    /// `reserved2`: a stub's size, for a section of stubs.
    stride: u32,
}

/// The load commands of one Mach-O image that say what dyld writes.
struct Macho<'d> {
    data: &'d [u8],
    little: bool,
    pointer: u64,
    x86_64: bool,
    /// In load-command order, which is how the opcode streams number them.
    segments: Vec<Segment>,
    sections: Vec<Section>,
    /// `LC_DYLD_CHAINED_FIXUPS`, and its file offset.
    chained: Option<(&'d [u8], u64)>,
    /// `LC_DYLD_INFO`: the rebase stream, then the bind, weak bind and lazy bind streams, each with its file offset.
    opcodes: Vec<(&'d [u8], u64, Stream)>,
    /// `LC_DYSYMTAB`'s external and local relocations, each with its file offset.
    relocations: Vec<(&'d [u8], u64)>,
    /// `LC_DYSYMTAB`'s indirect symbol table: its file offset and entry count.
    indirect: Option<(u64, u64)>,
    /// `LC_SYMTAB`: the symbol table's offset and count, and the string table's offset and size.
    symtab: Option<(u64, u64, u64, u64)>,
}

/// Which opcode stream, since each spells its operations differently.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stream {
    Rebase,
    Bind,
    /// Binds a definition in another image may replace.
    WeakBind,
    Lazy,
}

/// The file bytes a load command's offset and size name.
fn span(data: &[u8], offset: u32, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    data.get(start..end)
}

/// A symbol a bind names, by the C identifier it binds.
fn imported(name: &str, weak: bool) -> RelocationSymbol {
    RelocationSymbol {
        name: crate::macho_identifier(name).to_owned(),
        defined: None,
        size: 0,
        binding: if weak { Binding::Weak } else { Binding::Global },
        visibility: Visibility::Default,
    }
}

/// What dyld writes, as it is found: the records and the ranges no record covers.
#[derive(Default)]
struct Found {
    records: Vec<Relocation>,
    ranges: Vec<Range<u64>>,
}

impl Found {
    fn push(&mut self, record: Relocation) {
        self.ranges.push(written(record.vaddr, record.width));
        self.records.push(record);
    }
}

impl<'d> Macho<'d> {
    fn of<Mach, R>(
        file: &object::read::macho::MachOFile<'d, Mach, R>,
        data: &'d [u8],
    ) -> Option<Self>
    where
        Mach: MachHeader<Endian = object::Endianness>,
        R: object::ReadRef<'d>,
    {
        let header = file.macho_header();
        let endian = header.endian().ok()?;
        let mut commands = header.load_commands(endian, data, 0).ok()?;
        let mut macho = Self {
            data,
            little: header.is_little_endian(),
            pointer: if header.is_type_64() { 8 } else { 4 },
            x86_64: header.cputype(endian) == macho::CPU_TYPE_X86_64,
            segments: Vec::new(),
            sections: Vec::new(),
            chained: None,
            opcodes: Vec::new(),
            relocations: Vec::new(),
            indirect: None,
            symtab: None,
        };
        while let Ok(Some(command)) = commands.next() {
            if let Ok(variant) = command.variant() {
                macho.read_command(variant, endian);
            }
        }
        Some(macho)
    }

    /// One segment, and each section it holds, as its load command states them.
    ///
    /// `reserved` reads a section's `reserved1` and `reserved2`, which the
    /// 32- and 64-bit section headers both carry and no trait names.
    fn take_segment<S>(
        &mut self,
        segment: &S,
        sections: &'d [u8],
        endian: object::Endianness,
        reserved: impl Fn(&S::Section) -> (u32, u32),
    ) where
        S: object::read::macho::Segment<Endian = object::Endianness>,
    {
        use object::read::macho::Section as _;
        self.segments.push(Segment {
            vmaddr: segment.vmaddr(endian).into(),
            fileoff: segment.fileoff(endian).into(),
            filesize: segment.filesize(endian).into(),
            writable: segment.initprot(endian) & macho::VM_PROT_WRITE != 0,
        });
        for section in segment.sections(endian, sections).unwrap_or_default() {
            let (first_indirect, stride) = reserved(section);
            self.sections.push(Section {
                addr: section.addr(endian).into(),
                size: section.size(endian).into(),
                flags: section.flags(endian),
                first_indirect,
                stride,
            });
        }
    }

    /// Take what one load command says.
    fn read_command(
        &mut self,
        variant: LoadCommandVariant<'d, object::Endianness>,
        endian: object::Endianness,
    ) {
        let data = self.data;
        match variant {
            LoadCommandVariant::Segment32(segment, sections) => {
                self.take_segment(segment, sections, endian, |section| {
                    (section.reserved1.get(endian), section.reserved2.get(endian))
                });
            }
            LoadCommandVariant::Segment64(segment, sections) => {
                self.take_segment(segment, sections, endian, |section| {
                    (section.reserved1.get(endian), section.reserved2.get(endian))
                });
            }
            LoadCommandVariant::LinkeditData(linkedit)
                if linkedit.cmd.get(endian) == macho::LC_DYLD_CHAINED_FIXUPS =>
            {
                let (offset, size) = (
                    linkedit.dataoff.get(endian),
                    u64::from(linkedit.datasize.get(endian)),
                );
                self.chained = span(data, offset, size).map(|bytes| (bytes, u64::from(offset)));
            }
            LoadCommandVariant::DyldInfo(info) => {
                let stream = |offset: &object::U32<_>, size: &object::U32<_>, kind| {
                    let at = offset.get(endian);
                    Some((
                        span(data, at, u64::from(size.get(endian)))?,
                        u64::from(at),
                        kind,
                    ))
                };
                self.opcodes = [
                    stream(&info.rebase_off, &info.rebase_size, Stream::Rebase),
                    stream(&info.bind_off, &info.bind_size, Stream::Bind),
                    stream(&info.weak_bind_off, &info.weak_bind_size, Stream::WeakBind),
                    stream(&info.lazy_bind_off, &info.lazy_bind_size, Stream::Lazy),
                ]
                .into_iter()
                .flatten()
                .collect();
            }
            LoadCommandVariant::Dysymtab(table) => {
                let entries = |offset: &object::U32<_>, count: &object::U32<_>| {
                    let at = offset.get(endian);
                    Some((
                        span(data, at, u64::from(count.get(endian)) * 8)?,
                        u64::from(at),
                    ))
                };
                let external = entries(&table.extreloff, &table.nextrel);
                let local = entries(&table.locreloff, &table.nlocrel);
                self.relocations = [external, local].into_iter().flatten().collect();
                self.indirect = Some((
                    u64::from(table.indirectsymoff.get(endian)),
                    u64::from(table.nindirectsyms.get(endian)),
                ));
            }
            LoadCommandVariant::Symtab(table) => {
                self.symtab = Some((
                    u64::from(table.symoff.get(endian)),
                    u64::from(table.nsyms.get(endian)),
                    u64::from(table.stroff.get(endian)),
                    u64::from(table.strsize.get(endian)),
                ));
            }
            _ => {}
        }
    }

    fn read(&self) -> Read {
        let mut found = Found::default();
        if let Some((fixups, offset)) = self.chained {
            self.chains(fixups, offset, &mut found);
        }
        for (stream, offset, kind) in &self.opcodes {
            self.stream(stream, *offset, *kind, &mut found);
        }
        for (entries, offset) in &self.relocations {
            self.relocated(entries, *offset, &mut found);
        }
        let (stubs, pointers) = self.indirect_entries();
        // The symbol pointers the indirect table names are the loader's
        // writes, and where no fixup stream states them -- an image older than
        // both -- the table is the only statement of them there is.
        let streamed = self.chained.is_some() || !self.opcodes.is_empty();
        for record in pointers {
            match streamed {
                true => found.ranges.push(written(record.vaddr, record.width)),
                false => found.push(record),
            }
        }
        found.ranges.extend(self.filled());
        let writes = found
            .records
            .iter()
            .map(|record| LoaderWrite {
                place: record.vaddr,
                width: record.width,
                kind: self.kind(record),
            })
            .collect();
        Read {
            relocations: found.records,
            writes,
            ranges: found.ranges,
            stubs,
        }
    }

    /// What one record writes, in the coordinates the image is linked at.
    ///
    /// A rebase from an opcode stream writes the word the file holds, which
    /// the linker laid out as the unslid address; a chained rebase states its
    /// target, decoded per pointer format. A bind writes the import's address,
    /// where nothing is added to it.
    fn kind(&self, record: &Relocation) -> WriteKind {
        match (record.applies, &record.symbol) {
            (Applies::Relative, _) => match record.addend {
                Some(target) => WriteKind::Relative(target as u64),
                None => self
                    .word(record.vaddr, record.width)
                    .map_or(WriteKind::Unknown, |(_, value)| WriteKind::Relative(value)),
            },
            (Applies::Symbol | Applies::SymbolPlusAddend, Some(symbol))
                if symbol.defined.is_none() && matches!(record.addend, None | Some(0)) =>
            {
                WriteKind::Import {
                    symbol: symbol.name.clone(),
                }
            }
            _ => WriteKind::Unknown,
        }
    }

    /// The sections dyld fills whole: every symbol pointer, and the stubs an old image has it rewrite in place.
    fn filled(&self) -> Vec<Range<u64>> {
        self.sections
            .iter()
            .filter(|section| {
                let kind = section.flags & macho::SECTION_TYPE;
                let pointers = matches!(
                    kind,
                    macho::S_NON_LAZY_SYMBOL_POINTERS
                        | macho::S_LAZY_SYMBOL_POINTERS
                        | macho::S_LAZY_DYLIB_SYMBOL_POINTERS
                        | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
                );
                let rewritten = kind == macho::S_SYMBOL_STUBS
                    && section.flags & macho::S_ATTR_SELF_MODIFYING_CODE != 0;
                pointers || rewritten
            })
            .map(|section| written(section.addr, section.size))
            .collect()
    }

    fn u16(&self, bytes: &[u8], at: usize) -> Option<u16> {
        let word = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(word)
        } else {
            u16::from_be_bytes(word)
        })
    }

    fn u32(&self, bytes: &[u8], at: usize) -> Option<u32> {
        let word = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        })
    }

    fn u64(&self, bytes: &[u8], at: usize) -> Option<u64> {
        let word = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(word)
        } else {
            u64::from_be_bytes(word)
        })
    }

    /// The file offset of a placed address, and the word the file holds there.
    fn word(&self, vaddr: u64, width: u64) -> Option<(u64, u64)> {
        let segment = self.segments.iter().find(|segment| {
            vaddr >= segment.vmaddr
                && (vaddr - segment.vmaddr)
                    .checked_add(width)
                    .is_some_and(|end| end <= segment.filesize)
        })?;
        let offset = segment.fileoff.checked_add(vaddr - segment.vmaddr)?;
        let at = usize::try_from(offset).ok()?;
        let value = match width {
            4 => self.u32(self.data, at).map(u64::from),
            _ => self.u64(self.data, at),
        }?;
        Some((offset, value))
    }

    /// Where the image's header is placed, which a chain's segment offsets count from.
    fn header(&self) -> Option<u64> {
        let text = self
            .segments
            .iter()
            .find(|segment| segment.fileoff == 0 && segment.filesize > 0);
        text.map(|segment| segment.vmaddr)
    }

    /// A C string in the file, from `at` to its terminator within `end`.
    fn text(&self, at: u64, end: u64) -> Option<String> {
        let bytes = self
            .data
            .get(usize::try_from(at).ok()?..usize::try_from(end).ok()?)?;
        let length = bytes.iter().position(|byte| *byte == 0)?;
        core::str::from_utf8(&bytes[..length])
            .ok()
            .map(str::to_owned)
    }

    /// The imports a chained fixups header lists, by ordinal: each one's name, whether it is weak, and its addend.
    fn chained_imports(&self, fixups: &[u8], base: u64) -> Vec<(String, bool, i64)> {
        let (Some(imports), Some(symbols), Some(count), Some(format)) = (
            self.u32(fixups, 8),
            self.u32(fixups, 12),
            self.u32(fixups, 16),
            self.u32(fixups, 20),
        ) else {
            return Vec::new();
        };
        let (imports, symbols) = (u64::from(imports), u64::from(symbols));
        let end = base.saturating_add(fixups.len() as u64);
        let name_at = |offset: u64| {
            self.text(base.saturating_add(symbols).saturating_add(offset), end)
                .unwrap_or_default()
        };
        let mut found = Vec::new();
        for index in 0..u64::from(count) {
            let entry = match format {
                // DYLD_CHAINED_IMPORT: lib_ordinal:8, weak_import:1, name_offset:23.
                1 => self
                    .u32(fixups, (imports + index * 4) as usize)
                    .map(|word| (u64::from(word >> 9), word >> 8 & 1 == 1, 0)),
                // DYLD_CHAINED_IMPORT_ADDEND: the same, then a signed 32-bit addend.
                2 => self
                    .u32(fixups, (imports + index * 8) as usize)
                    .and_then(|word| {
                        let addend = self.u32(fixups, (imports + index * 8 + 4) as usize)?;
                        Some((
                            u64::from(word >> 9),
                            word >> 8 & 1 == 1,
                            i64::from(addend as i32),
                        ))
                    }),
                // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16, weak_import:1, reserved:15, name_offset:32, then a 64-bit addend.
                3 => self
                    .u64(fixups, (imports + index * 16) as usize)
                    .and_then(|word| {
                        let addend = self.u64(fixups, (imports + index * 16 + 8) as usize)?;
                        Some((word >> 32, word >> 16 & 1 == 1, addend as i64))
                    }),
                _ => None,
            };
            let Some((name, weak, addend)) = entry else {
                break;
            };
            found.push((name_at(name), weak, addend));
        }
        found
    }

    /// Every fixup of every chain `dyld_chained_fixups_header` starts.
    fn chains(&self, fixups: &[u8], base: u64, found: &mut Found) {
        let (Some(starts), Some(header)) = (self.u32(fixups, 4), self.header()) else {
            return;
        };
        let imports = self.chained_imports(fixups, base);
        let Some(image) = usize::try_from(starts)
            .ok()
            .and_then(|starts| fixups.get(starts..))
        else {
            return;
        };
        let count = self.u32(image, 0).unwrap_or(0);
        for index in 0..count as usize {
            let offset = self.u32(image, 4 + 4 * index).unwrap_or(0) as usize;
            if let Some(segment) = image.get(offset..).filter(|_| offset != 0) {
                self.segment_chains(segment, header, &imports, found);
            }
        }
    }

    /// The chains of one `dyld_chained_starts_in_segment`, one per page it lists.
    fn segment_chains(
        &self,
        starts: &[u8],
        header: u64,
        imports: &[(String, bool, i64)],
        found: &mut Found,
    ) {
        let (Some(page_size), Some(format), Some(offset), Some(pages)) = (
            self.u16(starts, 4),
            self.u16(starts, 6),
            self.u64(starts, 8),
            self.u16(starts, 20),
        ) else {
            return;
        };
        let size = u64::from(page_size);
        for page in 0..usize::from(pages) {
            let Some(start) = self
                .u16(starts, 22 + 2 * page)
                .filter(|start| *start != 0xffff)
            else {
                continue;
            };
            let base = header.wrapping_add(offset).wrapping_add(page as u64 * size);
            let Some(chain) = Chain::of(format) else {
                // A pointer format this reader does not decode: every byte of the page may be written.
                found.ranges.push(written(base, size));
                continue;
            };
            let chained = Chained { header, imports };
            for first in self.page_starts(starts, usize::from(pages), start) {
                let at = base.saturating_add(u64::from(first));
                self.chain(chain, at..base.saturating_add(size), chained, found);
            }
        }
    }

    /// Where a page's chains begin: one offset, or a list the high bit points into.
    fn page_starts(&self, starts: &[u8], pages: usize, start: u16) -> Vec<u16> {
        const MULTI: u16 = 0x8000;
        if start & MULTI == 0 {
            return vec![start];
        }
        let mut found = Vec::new();
        let mut index = pages + usize::from(start & !MULTI);
        while let Some(entry) = self.u16(starts, 22 + 2 * index) {
            found.push(entry & !MULTI);
            if entry & MULTI != 0 {
                break;
            }
            index += 1;
        }
        found
    }

    /// One chain, from its first fixup to the one whose link is zero; a chain never leaves its page.
    fn chain(&self, chain: Chain, page: Range<u64>, chained: Chained<'_>, found: &mut Found) {
        let Range { start: mut at, end } = page;
        while at < end {
            let Some((offset, value)) = self.word(at, chain.width) else {
                found.ranges.push(written(at, chain.width));
                return;
            };
            found.push(chain.record(at, (offset, value), chained));
            let next = (value >> chain.shift) & chain.mask;
            if next == 0 {
                return;
            }
            at = at.saturating_add(next * chain.stride);
        }
    }

    /// One rebase or bind opcode stream, as dyld runs it.
    fn stream(&self, bytes: &[u8], offset: u64, kind: Stream, found: &mut Found) {
        let mut state = Opcodes {
            bytes,
            offset,
            at: 0,
            written: 0,
            address: None,
            width: self.pointer,
            ntype: 1,
            symbol: None,
            addend: 0,
            kind,
        };
        while let Some(byte) = state.byte() {
            let step = match kind {
                Stream::Rebase => self.rebase(&mut state, byte, found),
                Stream::Bind | Stream::WeakBind | Stream::Lazy => {
                    self.bind(&mut state, byte, found)
                }
            };
            // A lazy bind stream ends each symbol with a done and carries on with the next.
            if step.is_none() && !(kind == Stream::Lazy && byte == 0) {
                return;
            }
        }
    }

    /// Where a segment index and an offset in it place a write.
    fn placed(&self, segment: u8, offset: u64) -> Option<u64> {
        let segment = self.segments.get(usize::from(segment))?;
        Some(segment.vmaddr.wrapping_add(offset))
    }

    fn rebase(&self, state: &mut Opcodes<'_>, byte: u8, found: &mut Found) -> Option<()> {
        let (opcode, immediate) = (
            byte & macho::REBASE_OPCODE_MASK,
            byte & macho::REBASE_IMMEDIATE_MASK,
        );
        let pointer = self.pointer;
        match opcode {
            macho::REBASE_OPCODE_SET_TYPE_IMM => {
                state.width = typed_width(immediate, pointer);
                state.ntype = u32::from(immediate);
            }
            macho::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                state.address = self.placed(immediate, state.uleb()?);
            }
            macho::REBASE_OPCODE_ADD_ADDR_ULEB => {
                let by = state.uleb()?;
                state.advance(by)?;
            }
            macho::REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                state.advance(u64::from(immediate) * pointer)?
            }
            macho::REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                state.repeat(u64::from(immediate), 0, pointer, found)?
            }
            macho::REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let times = state.uleb()?;
                state.repeat(times, 0, pointer, found)?;
            }
            macho::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                let skip = state.uleb()?;
                state.repeat(1, skip, pointer, found)?;
            }
            macho::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (times, skip) = (state.uleb()?, state.uleb()?);
                state.repeat(times, skip, pointer, found)?;
            }
            _ => return None,
        }
        Some(())
    }

    fn bind(&self, state: &mut Opcodes<'_>, byte: u8, found: &mut Found) -> Option<()> {
        let (opcode, immediate) = (
            byte & macho::BIND_OPCODE_MASK,
            byte & macho::BIND_IMMEDIATE_MASK,
        );
        let pointer = self.pointer;
        match opcode {
            macho::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | macho::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
            }
            macho::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                state.uleb()?;
            }
            macho::BIND_OPCODE_SET_ADDEND_SLEB => state.addend = state.sleb()?,
            macho::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let weak = immediate & macho::BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0;
                state.symbol = Some((state.string()?, weak));
            }
            macho::BIND_OPCODE_SET_TYPE_IMM => {
                state.width = typed_width(immediate, pointer);
                state.ntype = u32::from(immediate);
            }
            macho::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                state.address = self.placed(immediate, state.uleb()?);
            }
            macho::BIND_OPCODE_ADD_ADDR_ULEB => {
                let by = state.uleb()?;
                state.advance(by)?;
            }
            macho::BIND_OPCODE_DO_BIND => state.repeat(1, 0, pointer, found)?,
            macho::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let skip = state.uleb()?;
                state.repeat(1, skip, pointer, found)?;
            }
            macho::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                state.repeat(1, u64::from(immediate) * pointer, pointer, found)?;
            }
            macho::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (times, skip) = (state.uleb()?, state.uleb()?);
                state.repeat(times, skip, pointer, found)?;
            }
            macho::BIND_OPCODE_THREADED => self.threaded(state, immediate, found)?,
            _ => return None,
        }
        Some(())
    }

    /// A threaded bind: a table size to skip, or an arm64e chain from the current address.
    fn threaded(&self, state: &mut Opcodes<'_>, immediate: u8, found: &mut Found) -> Option<()> {
        match immediate {
            macho::BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                state.uleb()?;
            }
            macho::BIND_SUBOPCODE_THREADED_APPLY => {
                let start = state.address?;
                let chain = Chain::of(1)?;
                // A threaded chain runs through its segment rather than one page.
                let segment = self.segments.iter().find(|segment| {
                    start >= segment.vmaddr && start - segment.vmaddr < segment.filesize
                })?;
                let end = segment.vmaddr.saturating_add(segment.filesize);
                // Its binds index a table the stream built, which this reader does not keep: the writes are stated, their values are not.
                let mut threaded = Found::default();
                let chained = Chained {
                    header: self.header()?,
                    imports: &[],
                };
                self.chain(chain, start..end, chained, &mut threaded);
                for mut record in threaded.records {
                    record.applies = Applies::Unknown;
                    found.push(record);
                }
                found.ranges.extend(threaded.ranges);
            }
            _ => return None,
        }
        Some(())
    }

    /// The external and local relocations of an image laid out before dyld had opcodes.
    fn relocated(&self, entries: &[u8], table: u64, found: &mut Found) {
        // x86-64 counts from its first writable segment, everything else from its first segment.
        let base = match self.x86_64 {
            true => self.segments.iter().find(|segment| segment.writable),
            false => self.segments.first(),
        };
        let Some(base) = base.map(|segment| segment.vmaddr) else {
            return;
        };
        for (index, entry) in entries.chunks_exact(8).enumerate() {
            let (Some(address), Some(info)) = (self.u32(entry, 0), self.u32(entry, 4)) else {
                continue;
            };
            const SCATTERED: u32 = 0x8000_0000;
            // A scattered entry packs its offset, length and type into the first word.
            let (offset, length, ntype) = match address & SCATTERED {
                0 => (u64::from(address), (info >> 25) & 3, info >> 28),
                _ => (
                    u64::from(address & 0x00ff_ffff),
                    (address >> 28) & 3,
                    (address >> 24) & 0xf,
                ),
            };
            found.push(Relocation {
                vaddr: base.wrapping_add(offset),
                record: Record {
                    table: table + index as u64 * 8,
                    index: 0,
                },
                ntype,
                width: 1u64 << length,
                addend: None,
                symbol: None,
                applies: Applies::Unknown,
            });
        }
    }

    /// The symbol table's name for one index.
    fn symbol_name(&self, index: u32) -> Option<String> {
        let (symoff, nsyms, stroff, strsize) = self.symtab?;
        if u64::from(index) >= nsyms {
            return None;
        }
        let entry = if self.pointer == 8 { 16 } else { 12 };
        let at = symoff.checked_add(u64::from(index) * entry)?;
        let strx = self.u32(self.data, usize::try_from(at).ok()?)?;
        let start = stroff.checked_add(u64::from(strx))?;
        self.text(start, stroff.saturating_add(strsize))
            .filter(|name| !name.is_empty())
    }

    /// Which import each stub and each symbol pointer stands for, by the indirect symbol table.
    ///
    /// A section of stubs or of symbol pointers says where its entries begin
    /// in the table (`reserved1`) and how wide one is (`reserved2` for a stub,
    /// a pointer otherwise); the table says which symbol each entry stands for.
    fn indirect_entries(&self) -> (Vec<ImportStub>, Vec<Relocation>) {
        let (mut stubs, mut pointers) = (Vec::new(), Vec::new());
        for section in &self.sections {
            let kind = section.flags & macho::SECTION_TYPE;
            let stride = match kind {
                macho::S_SYMBOL_STUBS => u64::from(section.stride),
                macho::S_NON_LAZY_SYMBOL_POINTERS | macho::S_LAZY_SYMBOL_POINTERS => self.pointer,
                _ => 0,
            };
            for (vaddr, at, index) in self.indirect_of(section, stride) {
                let local = index & (macho::INDIRECT_SYMBOL_LOCAL | macho::INDIRECT_SYMBOL_ABS);
                let name = (local == 0).then(|| self.symbol_name(index)).flatten();
                match kind {
                    macho::S_SYMBOL_STUBS => stubs.extend(name.map(|symbol| ImportStub {
                        vaddr,
                        size: stride,
                        symbol: crate::macho_identifier(&symbol).to_owned(),
                    })),
                    _ => pointers.push(pointer_entry(vaddr, (at, index), stride, name)),
                }
            }
        }
        (stubs, pointers)
    }

    /// Each entry the indirect symbol table states for one section of
    /// `stride`-byte entries: where the entry is, where its table word is,
    /// and the symbol index that word holds.
    fn indirect_of(&self, section: &Section, stride: u64) -> Vec<(u64, u64, u32)> {
        let Some((table, count)) = self.indirect.filter(|_| stride != 0) else {
            return Vec::new();
        };
        let first = u64::from(section.first_indirect);
        (0..section.size / stride)
            .take_while(|entry| first + entry < count)
            .map_while(|entry| {
                let at = table + (first + entry) * 4;
                let index = usize::try_from(at)
                    .ok()
                    .and_then(|at| self.u32(self.data, at))?;
                Some((section.addr + entry * stride, at, index))
            })
            .collect()
    }
}

/// The record of one symbol pointer the indirect symbol table names: `entry`
/// is where its table word is and the index that word holds.
fn pointer_entry(vaddr: u64, entry: (u64, u32), width: u64, name: Option<String>) -> Relocation {
    let (at, index) = entry;
    Relocation {
        vaddr,
        record: Record {
            table: at,
            index: 0,
        },
        ntype: 0,
        width,
        addend: None,
        applies: match name {
            Some(_) => Applies::Symbol,
            // A local entry is rebased where it is not absolute.
            None if index & macho::INDIRECT_SYMBOL_ABS != 0 => Applies::Unknown,
            None => Applies::Relative,
        },
        symbol: name.map(|name| imported(&name, false)),
    }
}

/// How many bytes a rebase or bind of this type writes.
fn typed_width(typ: u8, pointer: u64) -> u64 {
    match typ {
        macho::REBASE_TYPE_TEXT_ABSOLUTE32 | macho::REBASE_TYPE_TEXT_PCREL32 => 4,
        _ => pointer,
    }
}

/// A cursor over one opcode stream, and the state its operations set.
struct Opcodes<'b> {
    bytes: &'b [u8],
    /// The stream's file offset, which with `written` identifies each record.
    offset: u64,
    at: usize,
    /// How many writes the stream has made so far.
    written: u64,
    /// Where the next write goes, once a segment and offset are set.
    address: Option<u64>,
    width: u64,
    ntype: u32,
    /// The symbol a bind binds, and whether it is a weak import.
    symbol: Option<(String, bool)>,
    addend: i64,
    kind: Stream,
}

impl Opcodes<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0u32;
        let last = loop {
            let byte = self.byte()?;
            value |= i64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
            shift += 7;
            if byte & 0x80 == 0 {
                break byte;
            }
            if shift >= 70 {
                return None;
            }
        };
        // The last byte's sixth bit is the sign, extended over every bit above those read.
        if shift < 64 && last & 0x40 != 0 {
            value |= -1i64 << shift;
        }
        Some(value)
    }

    fn string(&mut self) -> Option<String> {
        let rest = self.bytes.get(self.at..)?;
        let length = rest.iter().position(|byte| *byte == 0)?;
        let text = core::str::from_utf8(&rest[..length]).ok()?.to_owned();
        self.at += length + 1;
        Some(text)
    }

    fn advance(&mut self, by: u64) -> Option<()> {
        self.address = Some(self.address?.wrapping_add(by));
        Some(())
    }

    /// The record one write of this stream makes at `vaddr`.
    fn record(&mut self, vaddr: u64) -> Relocation {
        let record = Record {
            table: self.offset,
            index: self.written,
        };
        self.written += 1;
        match self.kind {
            Stream::Rebase => Relocation {
                vaddr,
                record,
                ntype: self.ntype,
                width: self.width,
                addend: None,
                symbol: None,
                applies: Applies::Relative,
            },
            Stream::Bind | Stream::WeakBind | Stream::Lazy => {
                let weak = self.kind == Stream::WeakBind;
                let symbol = self
                    .symbol
                    .clone()
                    .map(|(name, weak_import)| imported(&name, weak || weak_import));
                Relocation {
                    vaddr,
                    record,
                    ntype: self.ntype,
                    width: self.width,
                    addend: Some(self.addend),
                    applies: Applies::SymbolPlusAddend,
                    symbol,
                }
            }
        }
    }

    /// Write `times` times, stepping a pointer and `skip` more after each; a threaded bind names its symbols before any address.
    fn repeat(&mut self, times: u64, skip: u64, pointer: u64, found: &mut Found) -> Option<()> {
        let Some(mut address) = self.address else {
            return Some(());
        };
        for _ in 0..times {
            let record = self.record(address);
            found.push(record);
            address = address.wrapping_add(skip).wrapping_add(pointer);
        }
        self.address = Some(address);
        Some(())
    }
}

/// What decoding a chained fixup needs besides its word: where the image's
/// header is, which the offset formats count from, and the imports a bind
/// names by ordinal.
#[derive(Clone, Copy)]
struct Chained<'a> {
    header: u64,
    imports: &'a [(String, bool, i64)],
}

/// What one chained fixup word says, whatever its format.
enum Fixup {
    /// A rebase to this target, in link coordinates.
    Rebase(u64),
    /// A bind to the import at this ordinal, plus an addend.
    Bind { ordinal: u64, addend: i64 },
    /// A bind arm64e signs: its bits are not its value until authenticated.
    SignedBind(u64),
    /// A write whose value this does not state: a signed rebase, or a format
    /// whose fields are not decoded.
    Unstated,
}

/// How one chained pointer format links a fixup to the next, and what a fixup says.
#[derive(Clone, Copy)]
struct Chain {
    format: u16,
    width: u64,
    stride: u64,
    shift: u32,
    mask: u64,
}

impl Chain {
    /// The link field of each `DYLD_CHAINED_PTR_*` format this reader decodes.
    fn of(format: u16) -> Option<Self> {
        let (width, stride, shift, mask) = match format {
            // ARM64E, ARM64E_USERLAND, ARM64E_USERLAND24
            1 | 9 | 12 => (8, 8, 51, 0x7ff),
            // ARM64E_KERNEL, ARM64E_FIRMWARE
            7 | 10 => (8, 4, 51, 0x7ff),
            // 64, 64_OFFSET, 64_KERNEL_CACHE, ARM64E_SEGMENTED
            2 | 6 | 8 | 14 => (8, 4, 51, 0xfff),
            // X86_64_KERNEL_CACHE
            11 => (8, 1, 51, 0xfff),
            // 32, 32_CACHE, 32_FIRMWARE
            3 => (4, 4, 26, 0x1f),
            4 => (4, 4, 30, 0x3),
            5 => (4, 4, 26, 0x3f),
            _ => return None,
        };
        Some(Self {
            format,
            width,
            stride,
            shift,
            mask,
        })
    }

    /// The record one fixup word states, as `dyld` decodes it.
    ///
    /// A rebase's target is what the pointer holds once applied, in the
    /// coordinates the image is linked at: already an address for the plain
    /// 64-bit and arm64e formats, an offset from the image's header for the
    /// `_OFFSET` and userland formats. A pointer arm64e signs, and every
    /// format this does not decode the fields of, is a write whose value is
    /// not stated.
    /// `fixup` is the word's file offset, which identifies the record, and the word itself.
    fn record(&self, vaddr: u64, fixup: (u64, u64), chained: Chained<'_>) -> Relocation {
        let (offset, word) = fixup;
        let unknown = Relocation {
            vaddr,
            record: Record {
                table: offset,
                index: 0,
            },
            // A chained fixup has no type number of its own; its pointer format is the chain's.
            ntype: 0,
            width: self.width,
            addend: None,
            symbol: None,
            applies: Applies::Unknown,
        };
        let import = |ordinal: u64| chained.imports.get(ordinal as usize);
        match self.fixup(word, chained.header) {
            Fixup::Rebase(target) => Relocation {
                addend: Some(target as i64),
                applies: Applies::Relative,
                ..unknown
            },
            Fixup::Bind { ordinal, addend } => Relocation {
                addend: Some(addend + import(ordinal).map_or(0, |(_, _, own)| *own)),
                applies: Applies::SymbolPlusAddend,
                symbol: import(ordinal).map(|(name, weak, _)| imported(name, *weak)),
                ..unknown
            },
            Fixup::SignedBind(ordinal) => Relocation {
                symbol: import(ordinal).map(|(name, weak, _)| imported(name, *weak)),
                ..unknown
            },
            Fixup::Unstated => unknown,
        }
    }

    /// What one fixup word says in this chain's `DYLD_CHAINED_PTR_*` format.
    fn fixup(&self, word: u64, header: u64) -> Fixup {
        let bits = |low: u32, count: u32| (word >> low) & ((1u64 << count) - 1);
        let arm64e_ordinal = match self.format {
            12 => bits(0, 24),
            _ => bits(0, 16),
        };
        match (self.format, bits(63, 1), bits(62, 1)) {
            // _64 and _64_OFFSET: bind:1 at 63; ordinal:24, addend:8; or target:36, high8:8.
            (2 | 6, 1, _) => Fixup::Bind {
                ordinal: bits(0, 24),
                addend: bits(24, 8) as i64,
            },
            (2 | 6, _, _) => {
                let base = if self.format == 6 { header } else { 0 };
                Fixup::Rebase(base.wrapping_add(bits(0, 36)) | bits(36, 8) << 56)
            }
            // ARM64E and the userland forms: auth:1 at 63, bind:1 at 62. A
            // signed pointer's bits are not its value until authenticated.
            (1 | 9 | 12, 1, 1) => Fixup::SignedBind(arm64e_ordinal),
            (1 | 9 | 12, 1, _) => Fixup::Unstated,
            // addend:19 at 32, sign-extended.
            (1 | 9 | 12, _, 1) => Fixup::Bind {
                ordinal: arm64e_ordinal,
                addend: ((bits(32, 19) << 45) as i64) >> 45,
            },
            (1 | 9 | 12, _, _) => {
                let base = if self.format == 1 { 0 } else { header };
                Fixup::Rebase(base.wrapping_add(bits(0, 43)) | bits(43, 8) << 56)
            }
            // _32: bind:1 at 31; ordinal:20, addend:6; or target:26.
            (3, _, _) if bits(31, 1) == 1 => Fixup::Bind {
                ordinal: bits(0, 20),
                addend: bits(20, 6) as i64,
            },
            (3, _, _) => Fixup::Rebase(bits(0, 26)),
            _ => Fixup::Unstated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macho(data: &[u8]) -> Macho<'_> {
        Macho {
            data,
            little: true,
            pointer: 8,
            x86_64: false,
            segments: vec![
                Segment {
                    vmaddr: 0,
                    fileoff: 0,
                    filesize: 0,
                    writable: false,
                },
                Segment {
                    vmaddr: 0x4000,
                    fileoff: 0x4000,
                    filesize: 0x100,
                    writable: true,
                },
            ],
            sections: Vec::new(),
            chained: None,
            opcodes: Vec::new(),
            relocations: Vec::new(),
            indirect: None,
            symtab: None,
        }
    }

    #[test]
    fn a_rebase_stream_writes_where_its_opcodes_step() {
        let macho = macho(&[]);
        // set type pointer; segment 1 offset 0x10; rebase 2 times; add 8; rebase with skip 8, 2 times; done
        let stream = [0x11, 0x21, 0x10, 0x52, 0x30, 0x08, 0x80, 0x02, 0x08, 0x00];
        let mut found = Found::default();
        macho.stream(&stream, 0x100, Stream::Rebase, &mut found);
        assert_eq!(
            super::super::merged(found.ranges),
            [0x4010..0x4020, 0x4028..0x4030, 0x4038..0x4040]
        );
        // One record per write, each its position in the stream.
        let records: Vec<(u64, Record)> = found
            .records
            .iter()
            .map(|record| (record.vaddr, record.record))
            .collect();
        assert_eq!(records.len(), 4);
        assert_eq!(
            records[3],
            (
                0x4038,
                Record {
                    table: 0x100,
                    index: 3
                }
            )
        );
    }

    #[test]
    fn a_chained_offset_rebase_is_its_target_above_the_header() {
        // DYLD_CHAINED_PTR_64_OFFSET: target 0x3c0, next 2 (eight bytes on), at a header placed at 0x1_0000_0000.
        let chain = Chain::of(6).expect("decoded");
        let chained = Chained {
            header: 0x1_0000_0000,
            imports: &[],
        };
        let record = chain.record(0x1_0000_4000, (0x4000, 0x0010_0000_0000_03c0), chained);
        assert_eq!(record.applies, Applies::Relative);
        assert_eq!(record.addend, Some(0x1_0000_03c0));
        assert_eq!((0x0010_0000_0000_03c0u64 >> chain.shift) & chain.mask, 2);
    }

    #[test]
    fn a_chained_bind_names_its_import_by_ordinal_and_by_its_c_identifier() {
        let chain = Chain::of(6).expect("decoded");
        // Mach-O links `__memcpy_chk` as `___memcpy_chk`: one underscore is
        // the format's, and the other two are the identifier's own.
        let imports = [("___memcpy_chk".to_owned(), false, 0)];
        let chained = Chained {
            header: 0x1_0000_0000,
            imports: &imports,
        };
        let record = chain.record(0x1_0000_4000, (0x4000, 1 << 63), chained);
        assert_eq!(record.applies, Applies::SymbolPlusAddend);
        assert_eq!(
            record.symbol.map(|symbol| symbol.name).as_deref(),
            Some("__memcpy_chk")
        );
    }
}
