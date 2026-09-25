//! What the loader does before the program runs: the relocation records it applies, the bytes it writes, where the file's own bytes are not what the program reads, and the stubs a format declares stand for imports.

use std::ops::Range;

use object::read::pe::ImageNtHeaders;
use object::{Object, ObjectSection};

use r2abi::statement::{ImportStub, LoaderWrite, Relocation, WriteKind};

mod elf;
mod macho;

/// What the loader applies to one image.
pub(crate) struct Loaded {
    /// Every relocation record, each once, in the order it is applied.
    pub relocations: Vec<Relocation>,
    /// What the loader writes, sorted by place and disjoint.
    pub writes: Vec<LoaderWrite>,
    pub import_stubs: Vec<ImportStub>,
}

/// Every record the loader applies to the image, what it writes, and the stubs the format declares.
pub(crate) fn read(
    file: &object::File<'_>,
    data: &[u8],
    placed: &dyn Fn(&object::read::Section<'_, '_>) -> u64,
    pointer: u64,
) -> Loaded {
    let (relocations, writes, ranges, import_stubs) = match file {
        _ if file.kind() == object::ObjectKind::Relocatable => (
            Vec::new(),
            Vec::new(),
            linked(file, placed, pointer),
            Vec::new(),
        ),
        object::File::Elf32(_) | object::File::Elf64(_) => {
            let (relocations, writes, ranges) = elf::read(file, pointer);
            (relocations, writes, ranges, Vec::new())
        }
        object::File::MachO32(_) | object::File::MachO64(_) => {
            let read = macho::read(file, data);
            (read.relocations, read.writes, read.ranges, read.stubs)
        }
        object::File::Pe32(pe) => (Vec::new(), Vec::new(), pe_writes(pe), Vec::new()),
        object::File::Pe64(pe) => (Vec::new(), Vec::new(), pe_writes(pe), Vec::new()),
        _ => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
    };
    Loaded {
        relocations,
        writes: composed(writes, ranges),
        import_stubs,
    }
}

/// The ranges of writable segments the loader makes read-only once it is done, sorted and merged.
///
/// ELF states them as `PT_GNU_RELRO`, which the dynamic loader `mprotect`s
/// after relocating; Mach-O as a segment flagged `SG_READ_ONLY`, which dyld
/// seals after applying its fixups. A segment mapped without write
/// permission needs no statement: it is read-only from the start.
pub(crate) fn sealed(file: &object::File<'_>) -> Vec<Range<u64>> {
    use object::read::ObjectSegment as _;
    use object::read::elf::ProgramHeader as _;
    const SG_READ_ONLY: u32 = 0x10;
    let ranges = match file {
        object::File::Elf32(elf) => relro(elf),
        object::File::Elf64(elf) => relro(elf),
        object::File::MachO32(_) | object::File::MachO64(_) => file
            .segments()
            .filter(|segment| {
                matches!(segment.flags(), object::SegmentFlags::MachO { flags, .. } if flags & SG_READ_ONLY != 0)
            })
            .map(|segment| written(segment.address(), segment.size()))
            .collect(),
        _ => Vec::new(),
    };
    return merged(ranges);

    fn relro<'data, E: object::read::elf::FileHeader, R: object::ReadRef<'data>>(
        elf: &object::read::elf::ElfFile<'data, E, R>,
    ) -> Vec<Range<u64>> {
        let endian = elf.endian();
        elf.elf_program_headers()
            .iter()
            .filter(|header| header.p_type(endian) == object::elf::PT_GNU_RELRO)
            .map(|header| written(header.p_vaddr(endian).into(), header.p_memsz(endian).into()))
            .collect()
    }
}

/// The writes as the program sees them once the loader is done: sorted by place and disjoint.
///
/// Records writing one place are applied in order, so the last one's value
/// stands. Two that overlap without writing the same bytes leave a value no
/// record states, and so does every range the loader writes with no record
/// saying what: a word its psABI reserves, a section dyld fills whole, a page
/// of a chain format this reader does not decode. The union of the writes is
/// exactly the union of what was written. `O(W log W)` once.
fn composed(mut writes: Vec<LoaderWrite>, ranges: Vec<Range<u64>>) -> Vec<LoaderWrite> {
    writes.retain(|write| write.width > 0);
    // Stable, so the writes to one place stay in the order they are applied.
    writes.sort_by_key(|write| write.place);
    let mut stated: Vec<LoaderWrite> = Vec::with_capacity(writes.len());
    for write in writes {
        match stated.last_mut() {
            Some(last) if last.place == write.place && last.width == write.width => *last = write,
            Some(last) if write.place < last.end() => {
                last.width = last.end().max(write.end()) - last.place;
                last.kind = WriteKind::Unknown;
            }
            _ => stated.push(write),
        }
    }
    // What the ranges write beyond the records: each gap between stated writes.
    let mut out = Vec::with_capacity(stated.len());
    let mut next = 0;
    for range in merged(ranges) {
        let mut at = range.start;
        while next < stated.len() && stated[next].end() <= at {
            out.push(stated[next].clone());
            next += 1;
        }
        while at < range.end {
            match stated.get(next) {
                Some(write) if write.place <= at => {
                    at = at.max(write.end());
                    out.push(write.clone());
                    next += 1;
                }
                Some(write) if write.place < range.end => {
                    out.push(unknown(at, write.place));
                    at = write.place;
                }
                _ => {
                    out.push(unknown(at, range.end));
                    at = range.end;
                }
            }
        }
    }
    out.extend(stated.into_iter().skip(next));
    out
}

/// A write of these bytes whose value nothing states.
fn unknown(start: u64, end: u64) -> LoaderWrite {
    LoaderWrite {
        place: start,
        width: end - start,
        kind: WriteKind::Unknown,
    }
}

/// Sorted, with overlapping and touching ranges made one.
fn merged(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.retain(|range| range.start < range.end);
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut out: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match out.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => out.push(range),
        }
    }
    out
}

/// The bytes from `start` for `length`; a corrupt table cannot carry the range past the top of the address space.
fn written(start: u64, length: u64) -> Range<u64> {
    start..start.saturating_add(length)
}

/// A relocation's width in bytes, or a pointer where the format leaves it implicit.
fn width(bits: u8, pointer: u64) -> u64 {
    match bits {
        0 => pointer,
        bits => u64::from(bits).div_ceil(8),
    }
}

/// An object file's own relocations, each at the place its section was put.
fn linked(
    file: &object::File<'_>,
    placed: &dyn Fn(&object::read::Section<'_, '_>) -> u64,
    pointer: u64,
) -> Vec<Range<u64>> {
    let at = |section: object::read::Section<'_, '_>| {
        let base = placed(&section);
        let relocations = section.relocations().collect::<Vec<_>>();
        relocations.into_iter().map(move |(offset, relocation)| {
            written(base.wrapping_add(offset), width(relocation.size(), pointer))
        })
    };
    file.sections().flat_map(at).collect()
}

/// The base relocations, and each import address table the loader or the delay-load helper fills.
fn pe_writes<'data, Pe, R>(file: &object::read::pe::PeFile<'data, Pe, R>) -> Vec<Range<u64>>
where
    Pe: ImageNtHeaders,
    R: object::ReadRef<'data>,
{
    let base = file.relative_address_base();
    let sections = file.section_table();
    let directories = file.data_directories();
    let mut ranges = Vec::new();
    if let Ok(Some(blocks)) = directories.relocation_blocks(file.data(), &sections) {
        let relocations = blocks.flatten().flatten();
        let one = |relocation: object::read::pe::Relocation| {
            let start = base.wrapping_add(u64::from(relocation.virtual_address));
            written(start, based_width(relocation.typ))
        };
        ranges.extend(relocations.map(one));
    }
    let pointer = if file.is_64() { 8 } else { 4 };
    if let Ok(Some(imports)) = file.import_table() {
        let descriptors = imports.descriptors().into_iter().flatten().flatten();
        let firsts = descriptors.map(|descriptor| descriptor.first_thunk.get(object::LittleEndian));
        let thunks = |first| imports.thunks(first).ok();
        ranges.extend(tables::<Pe>(firsts.collect(), &thunks, base, pointer));
    }
    if let Ok(Some(delayed)) = directories.delay_load_import_table(file.data(), &sections) {
        let descriptors = delayed.descriptors().into_iter().flatten().flatten();
        let firsts = descriptors.map(|descriptor| {
            descriptor
                .import_address_table_rva
                .get(object::LittleEndian)
        });
        let thunks = |first| delayed.thunks(first).ok();
        ranges.extend(tables::<Pe>(firsts.collect(), &thunks, base, pointer));
    }
    ranges
}

/// Each import address table, walked once: in address order, a table starting inside one already walked, in step with it, ends at that one's null.
fn tables<'t, Pe: ImageNtHeaders>(
    firsts: std::collections::BTreeSet<u32>,
    thunks: &dyn Fn(u32) -> Option<object::read::pe::ImportThunkList<'t>>,
    base: u64,
    pointer: u64,
) -> Vec<Range<u64>> {
    // Where the last table walked in each alignment class ends.
    let mut walked = [0u64; 8];
    let mut ranges = Vec::new();
    for first in firsts {
        let (start, class) = (u64::from(first), usize::from(first as u8 % pointer as u8));
        if start < walked[class] {
            continue;
        }
        let bytes = thunks(first).map_or(0, thunk_count::<Pe>) * pointer;
        walked[class] = start + bytes;
        ranges.push(written(base.wrapping_add(start), bytes));
    }
    ranges
}

/// How many thunks an import address table holds before its null one.
fn thunk_count<Pe: ImageNtHeaders>(mut thunks: object::read::pe::ImportThunkList<'_>) -> u64 {
    let mut count = 0;
    while let Ok(Some(_)) = thunks.next::<Pe>() {
        count += 1;
    }
    count
}

/// How many bytes a PE base relocation of this type rewrites.
fn based_width(typ: u16) -> u64 {
    use object::pe;
    match typ {
        pe::IMAGE_REL_BASED_ABSOLUTE => 0,
        pe::IMAGE_REL_BASED_HIGH | pe::IMAGE_REL_BASED_LOW | pe::IMAGE_REL_BASED_HIGHADJ => 2,
        pe::IMAGE_REL_BASED_HIGHLOW => 4,
        // A pair of instructions, or a doubleword; unknown types are taken as wide as any.
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touching_and_overlapping_writes_are_one_range() {
        let ranges = merged(vec![8..16, 0..8, 32..40, 12..20, 5..5]);
        assert_eq!(ranges, [0..20, 32..40]);
    }

    #[test]
    fn a_later_record_at_one_place_stands_and_a_range_no_record_states_is_unknown() {
        let write = |place, width, kind| LoaderWrite { place, width, kind };
        let writes = vec![
            write(0x10, 8, WriteKind::Relative(0x100)),
            write(
                0x20,
                8,
                WriteKind::Import {
                    symbol: "f".to_owned(),
                },
            ),
            write(0x10, 8, WriteKind::Relative(0x200)),
            // Overlaps the import's slot without writing the same bytes.
            write(0x24, 8, WriteKind::Relative(0x300)),
        ];
        // Two touching ranges, which are one written run.
        let composed = composed(writes, vec![0x08..0x30, 0x30..0x40]);
        assert_eq!(
            composed,
            [
                write(0x08, 8, WriteKind::Unknown),
                write(0x10, 8, WriteKind::Relative(0x200)),
                write(0x18, 8, WriteKind::Unknown),
                write(0x20, 12, WriteKind::Unknown),
                write(0x2c, 0x14, WriteKind::Unknown),
            ]
        );
    }
}
