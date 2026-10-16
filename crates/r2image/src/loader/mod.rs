//! What the loader does before the program runs: the relocation records it applies, the bytes it writes, where the file's own bytes are not what the program reads, and the stubs a format declares stand for imports.

use std::ops::Range;

use object::{Object, ObjectSection};

use r2abi::statement::{Encoding, ImportStub, LoaderWrite, Relocation, WriteKind};

mod elf;
mod macho;

pub(crate) use elf::{binding, common, hooks, is_static_image};

/// What the loader applies to one image.
pub(crate) struct Loaded {
    /// Every relocation record, each once, in the order it is applied.
    pub relocations: Vec<Relocation>,
    /// What the loader writes, sorted by place and disjoint.
    pub writes: Vec<LoaderWrite>,
    pub import_stubs: Vec<ImportStub>,
    /// Where each record of a relocatable object resolves, by its place, sorted: what the call-frame reader relocates through.
    pub targets: Vec<(u64, u64)>,
}

/// Every record the loader applies to the image, what it writes, and the stubs the format declares.
pub(crate) fn read(
    file: &object::File<'_>,
    data: &[u8],
    placed: &dyn Fn(&object::read::Section<'_, '_>) -> u64,
    linkage: u64,
    common: &dyn Fn(u32) -> Option<u64>,
    pointer: u64,
    pe: Option<&crate::pe::Read>,
) -> Loaded {
    let relocatable = file.kind() == object::ObjectKind::Relocatable;
    let (relocations, writes, ranges, import_stubs) = match file {
        object::File::Elf32(_) | object::File::Elf64(_) if relocatable => {
            let at = |index| {
                file.section_by_index(index)
                    .ok()
                    .map(|section| placed(&section))
            };
            let placing = elf::Placing {
                section: &at,
                common,
            };
            let linked = elf::linked(file, &placing, linkage, pointer);
            return Loaded {
                relocations: linked.relocations,
                writes: composed(linked.writes, Vec::new()),
                import_stubs: linked.stubs,
                targets: linked.targets,
            };
        }
        _ if relocatable => (
            Vec::new(),
            linked(file, placed, pointer),
            Vec::new(),
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
        _ => match pe {
            Some(pe) => (
                Vec::new(),
                pe_imports(pe, pointer),
                pe.written.clone(),
                Vec::new(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        },
    };
    Loaded {
        relocations,
        writes: composed(writes, ranges),
        import_stubs,
        targets: Vec::new(),
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
    let ranges = match file {
        object::File::Elf32(elf) => relro(elf),
        object::File::Elf64(elf) => relro(elf),
        object::File::MachO32(_) | object::File::MachO64(_) => file
            .segments()
            .filter(|segment| {
                matches!(segment.flags(), object::SegmentFlags::MachO { flags, .. } if flags.contains(object::macho::SG_READ_ONLY))
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
                if last.encoding != write.encoding {
                    last.encoding = Encoding::Typed;
                }
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
        encoding: Encoding::Word,
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

/// A non-ELF object file's own relocations, each at the place its section was put, written as the type states and with no value read.
fn linked(
    file: &object::File<'_>,
    placed: &dyn Fn(&object::read::Section<'_, '_>) -> u64,
    pointer: u64,
) -> Vec<LoaderWrite> {
    let at = |section: object::read::Section<'_, '_>| {
        let base = placed(&section);
        let relocations = section.relocations().collect::<Vec<_>>();
        relocations
            .into_iter()
            .map(move |(offset, relocation)| LoaderWrite {
                place: base.wrapping_add(offset),
                width: width(relocation.size(), pointer),
                kind: WriteKind::Unknown,
                encoding: Encoding::Typed,
            })
    };
    file.sections().flat_map(at).collect()
}

/// Each import address table slot, which the loader (or the delay-load helper) fills with its import.
fn pe_imports(pe: &crate::pe::Read, pointer: u64) -> Vec<LoaderWrite> {
    (pe.imports.iter())
        .map(|import| LoaderWrite {
            place: import.slot,
            width: pointer,
            kind: WriteKind::Import {
                symbol: import.name.to_string(),
                library: Some(import.library.to_string()),
            },
            encoding: Encoding::Word,
        })
        .collect()
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
        let write = |place, width, kind| LoaderWrite {
            place,
            width,
            kind,
            encoding: Encoding::Word,
        };
        let writes = vec![
            write(0x10, 8, WriteKind::Relative(0x100)),
            write(
                0x20,
                8,
                WriteKind::Import {
                    symbol: "f".to_owned(),
                    library: None,
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
