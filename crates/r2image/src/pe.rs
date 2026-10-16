//! A PE image as the Windows loader maps it, and what its directories state through that mapping:
//! each import address table slot and the import written there, by library, each address the
//! export directory publishes, and each word a base relocation rewrites; and what a COFF symbol
//! record states that `object` does not give.

use std::ops::Range;
use std::sync::Arc;

use object::LittleEndian as LE;
use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{Object, ReadRef};
use r2abi::statement::{Permissions, Segment};

/// One import address table slot: the loader writes `name`, which `library` defines, there.
pub(crate) struct Imported {
    pub slot: u64,
    pub library: Arc<str>,
    /// The name it binds, or `Ordinal_N` (radare2's spelling) for an import by ordinal.
    pub name: Arc<str>,
    /// Its position in its library's table, from one.
    pub nth: usize,
}

/// One address the export directory publishes, by name or `Ordinal_N`.
pub(crate) struct Exported {
    pub vaddr: u64,
    pub name: Arc<str>,
    /// The module name the directory states for itself.
    pub library: Option<Arc<str>>,
    pub nth: usize,
}

/// One section header as the loader reads it, in table order.
pub(crate) struct Placed {
    pub vaddr: u64,
    /// `VirtualSize`, or `SizeOfRawData` where it is 0.
    pub vsize: u64,
    /// `PointerToRawData` rounded down to 0x200, as the loader rounds it.
    pub file_offset: u64,
    /// The raw data from there to where the header states it ends, as far as the file holds it.
    pub file_size: u64,
}

/// What one PE image states, read once through the loader's mapping.
pub(crate) struct Read {
    pub base: u64,
    /// Sorted and disjoint: the headers and each section, or the whole file where it is mapped flat.
    pub segments: Vec<Segment>,
    pub sections: Vec<Placed>,
    /// `AddressOfEntryPoint`, where it names one: a DLL's 0 names none.
    pub entry: Option<u64>,
    pub imports: Vec<Imported>,
    pub exports: Vec<Exported>,
    /// Each import address table and each word a base relocation rewrites.
    pub written: Vec<Range<u64>>,
}

pub(crate) fn read(file: &object::File<'_>, data: &[u8]) -> Option<Read> {
    match file {
        object::File::Pe32(pe) => Some(read_of(pe, data, u64::from(u32::MAX))),
        object::File::Pe64(pe) => Some(read_of(pe, data, u64::MAX)),
        _ => None,
    }
}

/// The page the loader maps in; a smaller `SectionAlignment` maps the file as it lies.
const PAGE: u64 = 0x1000;

/// The mapping (W35): `PointerToRawData` rounds down to 0x200 and the raw data read up to
/// `FileAlignment`, `VirtualSize` 0 means that raw size, a section spans its `SectionAlignment`
/// with zeros past `VirtualSize`, and the headers are mapped.
struct Layout {
    base: u64,
    /// Addresses wrap at the image's width: a PE32 RVA past 4 GiB less the base is low memory.
    mask: u64,
    segments: Vec<Segment>,
    sections: Vec<Placed>,
}

impl Layout {
    fn of<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
        file: &PeFile<'data, Pe, R>,
        length: u64,
        mask: u64,
    ) -> Self {
        let optional = file.nt_headers().optional_header();
        let base = optional.image_base() & mask;
        let alignment = u64::from(optional.section_alignment()).max(1);
        let span = |size: u64| size.checked_next_multiple_of(alignment).unwrap_or(size);
        let file_alignment = u64::from(optional.file_alignment()).max(1);
        let held = |offset: u64, size: u64| size.min(length.saturating_sub(offset));
        let flat = alignment < PAGE;
        let mut sections = Vec::new();
        let mut segments = Vec::new();
        for header in file.section_table().iter() {
            let raw = u64::from(header.size_of_raw_data.get(LE));
            let pointer = u64::from(header.pointer_to_raw_data.get(LE));
            let stated = u64::from(header.virtual_size.get(LE));
            // Mapped flat, the file is the image and no raw pointer is read, so none is rounded.
            let rounding = if flat { 0 } else { pointer & 0x1ff };
            let (file_offset, file_size) = match raw {
                0 => (0, 0),
                _ => (pointer - rounding, raw + rounding),
            };
            // The raw data the loader reads runs to a FileAlignment boundary, and stops at VirtualSize.
            let read = (file_size.checked_next_multiple_of(file_alignment)).unwrap_or(file_size);
            let mapped = match stated {
                0 => read,
                stated => stated,
            };
            let placed = Placed {
                vaddr: base.wrapping_add(u64::from(header.virtual_address.get(LE))) & mask,
                vsize: if stated == 0 { raw } else { stated },
                file_offset,
                file_size: held(file_offset, file_size),
            };
            if mapped > 0 {
                segments.push(Segment {
                    vaddr: placed.vaddr,
                    vsize: span(mapped),
                    file_offset,
                    file_size: held(file_offset, read.min(mapped)),
                    permissions: permissions(header.characteristics.get(LE)),
                    name: Some(String::from_utf8_lossy(header.raw_name()).into_owned()),
                });
            }
            sections.push(placed);
        }
        let headers = u64::from(optional.size_of_headers());
        if flat {
            let image = u64::from(optional.size_of_image());
            segments = vec![Segment {
                vaddr: base,
                vsize: span(image),
                file_offset: 0,
                file_size: held(0, image),
                permissions: Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
                name: None,
            }];
        } else {
            segments.push(Segment {
                vaddr: base,
                vsize: span(headers),
                file_offset: 0,
                file_size: held(0, headers),
                permissions: Permissions {
                    read: true,
                    ..Permissions::default()
                },
                name: None,
            });
        }
        segments.sort_by_key(|segment| segment.vaddr);
        Self {
            base,
            mask,
            segments: crate::disjoint(segments),
            sections,
        }
    }

    fn at(&self, rva: u64) -> u64 {
        self.base.wrapping_add(rva) & self.mask
    }

    /// The file bytes the loader puts at `rva`, to where its segment's file bytes end, and whether
    /// zeros follow them there: one search.
    fn held<'d>(&self, data: &'d [u8], rva: u64) -> Option<(&'d [u8], bool)> {
        let vaddr = self.at(rva);
        let after = self
            .segments
            .partition_point(|segment| segment.vaddr <= vaddr);
        let segment = self.segments.get(after.checked_sub(1)?)?;
        let into = vaddr - segment.vaddr;
        if into >= segment.file_size || !segment.permissions.mapped() {
            return None;
        }
        let start = usize::try_from(segment.file_offset + into).ok()?;
        let end = usize::try_from(segment.file_offset + segment.file_size).ok()?;
        Some((data.get(start..end)?, segment.vsize > segment.file_size))
    }

    fn bytes<'d>(&self, data: &'d [u8], rva: u64) -> Option<&'d [u8]> {
        self.held(data, rva).map(|(bytes, _)| bytes)
    }

    fn word(&self, data: &[u8], rva: u64, width: u64) -> Option<u64> {
        let bytes = self.bytes(data, rva)?.get(..width as usize)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0, |word, byte| word << 8 | u64::from(*byte)),
        )
    }

    /// A NUL-terminated name; the loader's zeros past the file's bytes terminate one too.
    fn text(&self, data: &[u8], rva: u64) -> Option<Arc<str>> {
        let (bytes, zeros) = self.held(data, rva)?;
        let end =
            (bytes.iter().position(|byte| *byte == 0)).or_else(|| zeros.then_some(bytes.len()))?;
        Some(String::from_utf8_lossy(&bytes[..end]).into())
    }
}

fn permissions(characteristics: pe::SectionFlags) -> Permissions {
    Permissions {
        read: characteristics.contains(pe::IMAGE_SCN_MEM_READ),
        write: characteristics.contains(pe::IMAGE_SCN_MEM_WRITE),
        execute: characteristics.contains(pe::IMAGE_SCN_MEM_EXECUTE),
    }
}

fn read_of<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
    file: &PeFile<'data, Pe, R>,
    data: &[u8],
    mask: u64,
) -> Read {
    let layout = Layout::of(file, data.len() as u64, mask);
    let directory = |index| {
        let directory = file.data_directories().get(index)?;
        let rva = directory.virtual_address.get(LE);
        (rva != 0).then(|| (u64::from(rva), u64::from(directory.size.get(LE))))
    };
    let pointer = if file.is_64() { 8 } else { 4 };
    let (imports, mut written) = imports_of(&layout, data, &directory, pointer);
    if let Some((rva, size)) = directory(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)
        && let Some(bytes) = layout.bytes(data, rva)
    {
        let bytes = &bytes[..bytes.len().min(size as usize)];
        let mut blocks = object::read::pe::RelocationBlockIterator::new(bytes);
        while let Ok(Some(block)) = blocks.next() {
            for relocation in block {
                let start = layout.at(u64::from(relocation.virtual_address));
                written.push(start..start.saturating_add(based_width(relocation.typ)));
            }
        }
    }
    let optional = file.nt_headers().optional_header();
    let dll =
        (file.nt_headers().file_header().characteristics.get(LE)).contains(pe::IMAGE_FILE_DLL);
    let entry = match optional.address_of_entry_point() {
        0 if dll => None,
        rva => Some(layout.at(u64::from(rva))),
    };
    Read {
        base: layout.base,
        exports: exports_of(&layout, data, &directory),
        segments: layout.segments,
        sections: layout.sections,
        entry,
        imports,
        written,
    }
}

/// One import table: where its slots begin, its DLL, where its names begin, and whether a delay
/// descriptor of the VC6 form states it, in addresses rather than RVAs.
struct Table {
    slots: u64,
    library: Arc<str>,
    names: u64,
    addressed: bool,
}

/// The ordinary and the delay-load tables, read through the mapping in slot order; a malformed
/// descriptor ends its table, not the image.
fn import_tables(
    layout: &Layout,
    data: &[u8],
    directory: &dyn Fn(usize) -> Option<(u64, u64)>,
) -> Vec<Table> {
    let mut tables = Vec::new();
    if let Some(bytes) =
        (directory(pe::IMAGE_DIRECTORY_ENTRY_IMPORT)).and_then(|(rva, _)| layout.bytes(data, rva))
    {
        for descriptor in bytes.as_chunks::<20>().0 {
            let descriptor = &descriptor[..];
            if descriptor.iter().all(|byte| *byte == 0) {
                break;
            }
            let (lookup, name, slots) = (
                dword(descriptor, 0),
                dword(descriptor, 12),
                dword(descriptor, 16),
            );
            // A bound image may keep no lookup table: the slots hold the names until bound.
            let names = if lookup != 0 { lookup } else { slots };
            if let Some(library) = layout.text(data, name) {
                tables.push(Table {
                    slots,
                    library,
                    names,
                    addressed: false,
                });
            }
        }
    }
    if let Some(bytes) = (directory(pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT))
        .and_then(|(rva, _)| layout.bytes(data, rva))
    {
        for descriptor in bytes.as_chunks::<32>().0 {
            let descriptor = &descriptor[..];
            if descriptor.iter().all(|byte| *byte == 0) {
                break;
            }
            // `dlattrRva` clear is the VC6 form, whose fields are addresses (delayimp.h).
            let addressed = dword(descriptor, 0) & 1 == 0;
            let relative = |value: u64| relative(layout, value, addressed);
            let (name, slots, names) = (
                dword(descriptor, 4),
                dword(descriptor, 12),
                dword(descriptor, 16),
            );
            if let Some(library) = layout.text(data, relative(name)) {
                tables.push(Table {
                    slots: relative(slots),
                    library,
                    names: relative(names),
                    addressed,
                });
            }
        }
    }
    // A descriptor naming no file names no DLL: Corkami's manyimports pads with thousands whose
    // "names" are the next descriptor's bytes.
    tables
        .retain(|table| !table.library.is_empty() && !table.library.chars().any(char::is_control));
    tables.sort_by_key(|table| table.slots);
    tables
}

/// One little-endian 32-bit field of a descriptor.
fn dword(descriptor: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        descriptor[at..at + 4].try_into().unwrap_or_default(),
    ))
}

/// Each import slot the tables state, and the ranges the loader writes.
///
/// Tables are walked in slot order and one stops at a slot already stated, so tables that overlap
/// (each starting inside the last, all ending at one null) cost their distinct slots once.
fn imports_of(
    layout: &Layout,
    data: &[u8],
    directory: &dyn Fn(usize) -> Option<(u64, u64)>,
    pointer: u64,
) -> (Vec<Imported>, Vec<Range<u64>>) {
    let tables = import_tables(layout, data, directory);
    let ordinal = 1u64 << (pointer * 8 - 1);
    let mut stated = std::collections::BTreeSet::new();
    let mut found = Vec::new();
    let mut written = Vec::new();
    for table in tables {
        let mut nth = 0;
        while let Some(thunk) = layout.word(data, table.names + nth * pointer, pointer)
            && thunk != 0
        {
            let slot = layout.at(table.slots + nth * pointer);
            let name = match thunk & ordinal {
                0 => {
                    let hint = relative(layout, thunk & 0x7fff_ffff, table.addressed);
                    layout.text(data, hint + 2)
                }
                _ => Some(format!("Ordinal_{}", thunk & 0xffff).into()),
            };
            // An unreadable name ends its table; a slot already stated, the tables it overlaps.
            let Some(name) = name.filter(|_| stated.insert(slot)) else {
                break;
            };
            nth += 1;
            // A name with no character a symbol holds binds nothing.
            if name.is_empty() || name.chars().any(char::is_control) {
                continue;
            }
            found.push(Imported {
                slot,
                library: Arc::clone(&table.library),
                name,
                nth: nth as usize,
            });
        }
        let start = layout.at(table.slots);
        written.push(start..start.saturating_add(nth * pointer));
    }
    (found, written)
}

/// An RVA from a VC6 delay descriptor's field, which states an address; one below the image base
/// names nothing as an address and is read image-relative, as radare2 reads the table.
fn relative(layout: &Layout, value: u64, addressed: bool) -> u64 {
    match addressed && value >= layout.base {
        true => value - layout.base,
        false => value,
    }
}

/// Each export at an address of this image; a forwarder's lies in the directory's stated extent.
/// Tables and names are read through the mapped image, never past the file's bytes (D18).
fn exports_of(
    layout: &Layout,
    data: &[u8],
    directory: &dyn Fn(usize) -> Option<(u64, u64)>,
) -> Vec<Exported> {
    let Some((rva, size)) = directory(pe::IMAGE_DIRECTORY_ENTRY_EXPORT) else {
        return Vec::new();
    };
    let field = |at: u64| layout.word(data, rva + at, 4);
    let (
        Some(library),
        Some(base),
        Some(functions),
        Some(names),
        Some(by_function),
        Some(by_name),
        Some(by_ordinal),
    ) = (
        field(12),
        field(16),
        field(20),
        field(24),
        field(28),
        field(32),
        field(36),
    )
    else {
        return Vec::new();
    };
    // A table is the bytes its pointer names, as many as it states; a pointer of 0 states none.
    let table = |at: u64, count: u64, width: u64| -> Option<&[u8]> {
        match at {
            0 => Some(&[]),
            _ => layout
                .bytes(data, at)?
                .get(..usize::try_from(count * width).ok()?),
        }
    };
    let (Some(addresses), Some(pointers), Some(ordinals)) = (
        table(by_function, functions, 4),
        table(by_name, names, 4),
        table(if by_name == 0 { 0 } else { by_ordinal }, names, 2),
    ) else {
        return Vec::new();
    };
    if by_name != 0 && by_ordinal == 0 {
        return Vec::new();
    }
    let (addresses, _) = addresses.as_chunks::<4>();
    let (pointers, _) = pointers.as_chunks::<4>();
    let (ordinals, _) = ordinals.as_chunks::<2>();
    let mut named = vec![None; addresses.len()];
    for (pointer, ordinal) in pointers.iter().zip(ordinals) {
        let pointer = u64::from(u32::from_le_bytes(*pointer));
        if let (Some(name), Some(slot)) = (
            layout.text(data, pointer),
            named.get_mut(usize::from(u16::from_le_bytes(*ordinal))),
        ) {
            *slot = Some(name);
        }
    }
    let library = layout.text(data, library);
    let forwarded = |address: u64| size != 0 && (rva..rva.saturating_add(size)).contains(&address);
    addresses
        .iter()
        .zip(named)
        .enumerate()
        .map(|(index, (address, name))| {
            let ordinal = base.wrapping_add(index as u64) & 0xffff_ffff;
            (ordinal, u64::from(u32::from_le_bytes(*address)), name)
        })
        // An unused ordinal's slot is 0, which states no export.
        .filter(|(_, address, _)| *address != 0 && !forwarded(*address))
        .enumerate()
        .map(|(index, (ordinal, address, name))| Exported {
            vaddr: layout.at(address),
            name: name.unwrap_or_else(|| format!("Ordinal_{ordinal}").into()),
            library: library.clone(),
            nth: index + 1,
        })
        .collect()
}

/// How many bytes a PE base relocation of this type rewrites.
fn based_width(typ: pe::BaseRelocationType) -> u64 {
    match typ {
        pe::IMAGE_REL_BASED_ABSOLUTE => 0,
        pe::IMAGE_REL_BASED_HIGH | pe::IMAGE_REL_BASED_LOW | pe::IMAGE_REL_BASED_HIGHADJ => 2,
        pe::IMAGE_REL_BASED_HIGHLOW => 4,
        // A pair of instructions, or a doubleword; unknown types are taken as wide as any.
        _ => 8,
    }
}

/// A COFF record's `Value`, which `object` gives as no address where the record names no section:
/// an absolute record's (`SectionNumber` -1) is a value, not an address. One record read, by index.
pub(crate) fn coff_value(file: &object::File<'_>, data: &[u8], index: usize) -> Option<u64> {
    use object::read::coff::Symbol as _;
    const RECORD: usize = 18;
    let at = object::SymbolIndex(index);
    let table = match file {
        object::File::Coff(coff) => {
            return coff
                .coff_symbol_table()
                .symbol(at)
                .ok()
                .map(|record| u64::from(record.value()));
        }
        object::File::CoffBig(coff) => {
            return coff
                .coff_symbol_table()
                .symbol(at)
                .ok()
                .map(|record| u64::from(record.value()));
        }
        object::File::Pe32(pe) => pe.nt_headers().file_header.pointer_to_symbol_table.get(LE),
        object::File::Pe64(pe) => pe.nt_headers().file_header.pointer_to_symbol_table.get(LE),
        _ => return None,
    };
    // `Value` follows the record's eight-byte name.
    let start = (table as usize)
        .checked_add(index.checked_mul(RECORD)?)?
        .checked_add(8)?;
    let bytes = data.get(start..start.checked_add(4)?)?;
    Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)))
}
