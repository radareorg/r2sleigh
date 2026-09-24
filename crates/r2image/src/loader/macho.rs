//! What dyld writes: the chained fixups, the rebase and bind opcode streams, and the relocations of an image older than both.

use std::ops::Range;

use object::macho;
use object::read::macho::{LoadCommandVariant, MachHeader};

use super::written;

/// Every range dyld writes into one Mach-O image.
pub(super) fn writes(file: &object::File<'_>, data: &[u8]) -> Vec<Range<u64>> {
    let macho = match file {
        object::File::MachO32(file) => Macho::of(file, data),
        object::File::MachO64(file) => Macho::of(file, data),
        _ => None,
    };
    macho.map_or_else(Vec::new, |macho| macho.writes())
}

/// One segment as its load command places it.
struct Segment {
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    writable: bool,
}

/// The load commands of one Mach-O image that say what dyld writes.
struct Macho<'d> {
    data: &'d [u8],
    little: bool,
    pointer: u64,
    x86_64: bool,
    /// In load-command order, which is how the opcode streams number them.
    segments: Vec<Segment>,
    /// `LC_DYLD_CHAINED_FIXUPS`.
    chained: Option<&'d [u8]>,
    /// `LC_DYLD_INFO`: the rebase stream, then the bind, weak bind and lazy bind streams.
    opcodes: Vec<(&'d [u8], Stream)>,
    /// `LC_DYSYMTAB`'s external and local relocations.
    relocations: Vec<&'d [u8]>,
    /// The sections dyld fills whole: symbol pointers, and stubs it rewrites in place.
    filled: Vec<Range<u64>>,
}

/// Which opcode stream, since each spells its operations differently.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stream {
    Rebase,
    Bind,
    Lazy,
}

/// The sections dyld fills whole: every symbol pointer, and the stubs an old image has it rewrite in place.
fn filled<S>(sections: &[S], endian: object::Endianness) -> Vec<Range<u64>>
where
    S: object::read::macho::Section<Endian = object::Endianness>,
{
    let whole = |section: &S| {
        let flags = section.flags(endian);
        let pointers = matches!(
            flags & macho::SECTION_TYPE,
            macho::S_NON_LAZY_SYMBOL_POINTERS
                | macho::S_LAZY_SYMBOL_POINTERS
                | macho::S_LAZY_DYLIB_SYMBOL_POINTERS
                | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
        );
        let rewritten = flags & macho::SECTION_TYPE == macho::S_SYMBOL_STUBS
            && flags & macho::S_ATTR_SELF_MODIFYING_CODE != 0;
        pointers || rewritten
    };
    let range = |section: &S| {
        let start: u64 = section.addr(endian).into();
        written(start, section.size(endian).into())
    };
    sections
        .iter()
        .filter(|section| whole(section))
        .map(range)
        .collect()
}

/// The file bytes a load command's offset and size name.
fn span(data: &[u8], offset: u32, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    data.get(start..end)
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
            chained: None,
            opcodes: Vec::new(),
            relocations: Vec::new(),
            filled: Vec::new(),
        };
        while let Ok(Some(command)) = commands.next() {
            if let Ok(variant) = command.variant() {
                macho.read(variant, endian);
            }
        }
        Some(macho)
    }

    /// Take what one load command says.
    fn read(
        &mut self,
        variant: LoadCommandVariant<'d, object::Endianness>,
        endian: object::Endianness,
    ) {
        let data = self.data;
        match variant {
            LoadCommandVariant::Segment32(segment, sections) => {
                self.segments.push(Segment {
                    vmaddr: u64::from(segment.vmaddr.get(endian)),
                    fileoff: u64::from(segment.fileoff.get(endian)),
                    filesize: u64::from(segment.filesize.get(endian)),
                    writable: segment.initprot.get(endian) & macho::VM_PROT_WRITE != 0,
                });
                let sections = object::read::macho::Segment::sections(segment, endian, sections);
                self.filled
                    .extend(filled(sections.unwrap_or_default(), endian));
            }
            LoadCommandVariant::Segment64(segment, sections) => {
                self.segments.push(Segment {
                    vmaddr: segment.vmaddr.get(endian),
                    fileoff: segment.fileoff.get(endian),
                    filesize: segment.filesize.get(endian),
                    writable: segment.initprot.get(endian) & macho::VM_PROT_WRITE != 0,
                });
                let sections = object::read::macho::Segment::sections(segment, endian, sections);
                self.filled
                    .extend(filled(sections.unwrap_or_default(), endian));
            }
            LoadCommandVariant::LinkeditData(linkedit)
                if linkedit.cmd.get(endian) == macho::LC_DYLD_CHAINED_FIXUPS =>
            {
                let size = u64::from(linkedit.datasize.get(endian));
                self.chained = span(data, linkedit.dataoff.get(endian), size);
            }
            LoadCommandVariant::DyldInfo(info) => {
                let stream = |offset: &object::U32<_>, size: &object::U32<_>, kind| {
                    Some((
                        span(data, offset.get(endian), u64::from(size.get(endian)))?,
                        kind,
                    ))
                };
                self.opcodes = [
                    stream(&info.rebase_off, &info.rebase_size, Stream::Rebase),
                    stream(&info.bind_off, &info.bind_size, Stream::Bind),
                    stream(&info.weak_bind_off, &info.weak_bind_size, Stream::Bind),
                    stream(&info.lazy_bind_off, &info.lazy_bind_size, Stream::Lazy),
                ]
                .into_iter()
                .flatten()
                .collect();
            }
            LoadCommandVariant::Dysymtab(table) => {
                let entries = |offset: &object::U32<_>, count: &object::U32<_>| {
                    span(data, offset.get(endian), u64::from(count.get(endian)) * 8)
                };
                let external = entries(&table.extreloff, &table.nextrel);
                let local = entries(&table.locreloff, &table.nlocrel);
                self.relocations = [external, local].into_iter().flatten().collect();
            }
            _ => {}
        }
    }

    fn writes(&self) -> Vec<Range<u64>> {
        let mut ranges = self.filled.clone();
        if let Some(chained) = self.chained {
            self.chains(chained, &mut ranges);
        }
        for (stream, kind) in &self.opcodes {
            self.stream(stream, *kind, &mut ranges);
        }
        for entries in &self.relocations {
            self.relocated(entries, &mut ranges);
        }
        ranges
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

    /// The word the file holds at a placed address.
    fn word(&self, vaddr: u64, width: u64) -> Option<u64> {
        let segment = self.segments.iter().find(|segment| {
            vaddr >= segment.vmaddr
                && (vaddr - segment.vmaddr)
                    .checked_add(width)
                    .is_some_and(|end| end <= segment.filesize)
        })?;
        let at = usize::try_from(segment.fileoff.checked_add(vaddr - segment.vmaddr)?).ok()?;
        match width {
            4 => self.u32(self.data, at).map(u64::from),
            _ => self.u64(self.data, at),
        }
    }

    /// Where the image's header is placed, which a chain's segment offsets count from.
    fn header(&self) -> Option<u64> {
        let text = self
            .segments
            .iter()
            .find(|segment| segment.fileoff == 0 && segment.filesize > 0);
        text.map(|segment| segment.vmaddr)
    }

    /// Every fixup of every chain `dyld_chained_fixups_header` starts.
    fn chains(&self, fixups: &[u8], ranges: &mut Vec<Range<u64>>) {
        let (Some(starts), Some(header)) = (self.u32(fixups, 4), self.header()) else {
            return;
        };
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
                self.segment_chains(segment, header, ranges);
            }
        }
    }

    /// The chains of one `dyld_chained_starts_in_segment`, one per page it lists.
    fn segment_chains(&self, starts: &[u8], header: u64, ranges: &mut Vec<Range<u64>>) {
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
                ranges.push(written(base, size));
                continue;
            };
            for first in self.page_starts(starts, usize::from(pages), start) {
                let end = base.saturating_add(size);
                self.chain(chain, base.saturating_add(u64::from(first)), end, ranges);
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
    fn chain(&self, chain: Chain, mut at: u64, end: u64, ranges: &mut Vec<Range<u64>>) {
        while at < end {
            ranges.push(written(at, chain.width));
            let Some(value) = self.word(at, chain.width) else {
                return;
            };
            let next = (value >> chain.shift) & chain.mask;
            if next == 0 {
                return;
            }
            at = at.saturating_add(next * chain.stride);
        }
    }

    /// One rebase or bind opcode stream, as dyld runs it.
    fn stream(&self, bytes: &[u8], kind: Stream, ranges: &mut Vec<Range<u64>>) {
        let mut state = Opcodes {
            bytes,
            at: 0,
            address: None,
            width: self.pointer,
        };
        while let Some(byte) = state.byte() {
            let step = match kind {
                Stream::Rebase => self.rebase(&mut state, byte, ranges),
                Stream::Bind | Stream::Lazy => self.bind(&mut state, byte, ranges),
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

    fn rebase(
        &self,
        state: &mut Opcodes<'_>,
        byte: u8,
        ranges: &mut Vec<Range<u64>>,
    ) -> Option<()> {
        let (opcode, immediate) = (
            byte & macho::REBASE_OPCODE_MASK,
            byte & macho::REBASE_IMMEDIATE_MASK,
        );
        let pointer = self.pointer;
        match opcode {
            macho::REBASE_OPCODE_SET_TYPE_IMM => state.width = typed_width(immediate, pointer),
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
                state.repeat(u64::from(immediate), 0, pointer, ranges)?
            }
            macho::REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let times = state.uleb()?;
                state.repeat(times, 0, pointer, ranges)?;
            }
            macho::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                let skip = state.uleb()?;
                state.repeat(1, skip, pointer, ranges)?;
            }
            macho::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (times, skip) = (state.uleb()?, state.uleb()?);
                state.repeat(times, skip, pointer, ranges)?;
            }
            _ => return None,
        }
        Some(())
    }

    fn bind(&self, state: &mut Opcodes<'_>, byte: u8, ranges: &mut Vec<Range<u64>>) -> Option<()> {
        let (opcode, immediate) = (
            byte & macho::BIND_OPCODE_MASK,
            byte & macho::BIND_IMMEDIATE_MASK,
        );
        let pointer = self.pointer;
        match opcode {
            macho::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | macho::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
            }
            macho::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB | macho::BIND_OPCODE_SET_ADDEND_SLEB => {
                state.uleb()?;
            }
            macho::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => state.string()?,
            macho::BIND_OPCODE_SET_TYPE_IMM => state.width = typed_width(immediate, pointer),
            macho::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                state.address = self.placed(immediate, state.uleb()?);
            }
            macho::BIND_OPCODE_ADD_ADDR_ULEB => {
                let by = state.uleb()?;
                state.advance(by)?;
            }
            macho::BIND_OPCODE_DO_BIND => state.repeat(1, 0, pointer, ranges)?,
            macho::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let skip = state.uleb()?;
                state.repeat(1, skip, pointer, ranges)?;
            }
            macho::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                state.repeat(1, u64::from(immediate) * pointer, pointer, ranges)?;
            }
            macho::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (times, skip) = (state.uleb()?, state.uleb()?);
                state.repeat(times, skip, pointer, ranges)?;
            }
            macho::BIND_OPCODE_THREADED => self.threaded(state, immediate, ranges)?,
            _ => return None,
        }
        Some(())
    }

    /// A threaded bind: a table size to skip, or an arm64e chain from the current address.
    fn threaded(
        &self,
        state: &mut Opcodes<'_>,
        immediate: u8,
        ranges: &mut Vec<Range<u64>>,
    ) -> Option<()> {
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
                self.chain(chain, start, end, ranges);
            }
            _ => return None,
        }
        Some(())
    }

    /// The external and local relocations of an image laid out before dyld had opcodes.
    fn relocated(&self, entries: &[u8], ranges: &mut Vec<Range<u64>>) {
        // x86-64 counts from its first writable segment, everything else from its first segment.
        let base = match self.x86_64 {
            true => self.segments.iter().find(|segment| segment.writable),
            false => self.segments.first(),
        };
        let Some(base) = base.map(|segment| segment.vmaddr) else {
            return;
        };
        for entry in entries.chunks_exact(8) {
            let (Some(address), Some(info)) = (self.u32(entry, 0), self.u32(entry, 4)) else {
                continue;
            };
            const SCATTERED: u32 = 0x8000_0000;
            // A scattered entry packs its offset and length into the first word.
            let (offset, length) = match address & SCATTERED {
                0 => (u64::from(address), (info >> 25) & 3),
                _ => (u64::from(address & 0x00ff_ffff), (address >> 28) & 3),
            };
            ranges.push(written(base.wrapping_add(offset), 1u64 << length));
        }
    }
}

/// How many bytes a rebase or bind of this type writes.
fn typed_width(typ: u8, pointer: u64) -> u64 {
    match typ {
        macho::REBASE_TYPE_TEXT_ABSOLUTE32 | macho::REBASE_TYPE_TEXT_PCREL32 => 4,
        _ => pointer,
    }
}

/// A cursor over one opcode stream.
struct Opcodes<'b> {
    bytes: &'b [u8],
    at: usize,
    /// Where the next write goes, once a segment and offset are set.
    address: Option<u64>,
    width: u64,
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

    fn string(&mut self) -> Option<()> {
        let length = self
            .bytes
            .get(self.at..)?
            .iter()
            .position(|byte| *byte == 0)?;
        self.at += length + 1;
        Some(())
    }

    fn advance(&mut self, by: u64) -> Option<()> {
        self.address = Some(self.address?.wrapping_add(by));
        Some(())
    }

    /// Write `times` times, stepping a pointer and `skip` more after each; a threaded bind names its symbols before any address.
    fn repeat(
        &mut self,
        times: u64,
        skip: u64,
        pointer: u64,
        ranges: &mut Vec<Range<u64>>,
    ) -> Option<()> {
        let Some(mut address) = self.address else {
            return Some(());
        };
        for _ in 0..times {
            ranges.push(written(address, self.width));
            address = address.wrapping_add(skip).wrapping_add(pointer);
        }
        self.address = Some(address);
        Some(())
    }
}

/// How one chained pointer format links a fixup to the next.
#[derive(Clone, Copy)]
struct Chain {
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
            width,
            stride,
            shift,
            mask,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rebase_stream_writes_where_its_opcodes_step() {
        let macho = Macho {
            data: &[],
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
            chained: None,
            opcodes: Vec::new(),
            relocations: Vec::new(),
            filled: Vec::new(),
        };
        // set type pointer; segment 1 offset 0x10; rebase 2 times; add 8; rebase with skip 8, 2 times; done
        let stream = [0x11, 0x21, 0x10, 0x52, 0x30, 0x08, 0x80, 0x02, 0x08, 0x00];
        let mut ranges = Vec::new();
        macho.stream(&stream, Stream::Rebase, &mut ranges);
        assert_eq!(
            super::super::merged(ranges),
            [0x4010..0x4020, 0x4028..0x4030, 0x4038..0x4040]
        );
    }
}
