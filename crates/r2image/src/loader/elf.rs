//! What an ELF loader writes: every relocation its dynamic table or its sections name, and the table words its psABI reserves.

use std::ops::Range;

use object::read::elf::{
    Dyn as _, ElfFile, FileHeader, ProgramHeader as _, Rel as _, Rela as _, Sym as _,
};
use object::{Object, ObjectSymbol, ObjectSymbolTable, elf};

use super::{width, written};

/// Every range the dynamic loader, or a static binary's own start-up, writes.
pub(super) fn writes(file: &object::File<'_>, pointer: u64) -> Vec<Range<u64>> {
    let mut ranges = sectioned(file, pointer);
    let tabled = match file {
        object::File::Elf32(file) => tabled(file, pointer),
        object::File::Elf64(file) => tabled(file, pointer),
        _ => Vec::new(),
    };
    ranges.extend(tabled);
    ranges
}

/// The relocation sections: what a static binary's start-up applies, and what the dynamic table names where it has sections.
fn sectioned(file: &object::File<'_>, pointer: u64) -> Vec<Range<u64>> {
    let copy = copy_type(file.architecture());
    let one = |(vaddr, relocation): (u64, object::Relocation)| {
        let copied = matches!(relocation.flags(), object::RelocationFlags::Elf { r_type } if Some(r_type) == copy);
        let bytes = match copied {
            true => copied_size(file, &relocation).unwrap_or(pointer),
            false => width(relocation.size(), pointer),
        };
        written(vaddr, bytes)
    };
    let mut ranges = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .map(one)
        .collect::<Vec<_>>();
    let packed = match file {
        object::File::Elf32(file) => relr(file),
        object::File::Elf64(file) => relr(file),
        _ => Vec::new(),
    };
    ranges.extend(packed.into_iter().map(|vaddr| written(vaddr, pointer)));
    ranges
}

/// What the dynamic table names, read as the loader reads it: through the program headers, whatever sections remain.
fn tabled<'data, E, R>(file: &ElfFile<'data, E, R>, pointer: u64) -> Vec<Range<u64>>
where
    E: FileHeader,
    R: object::ReadRef<'data>,
{
    let Some(table) = Table::of(file) else {
        return Vec::new();
    };
    let copy = copy_type(file.architecture());
    let mut ranges = Vec::new();
    for (offset, typ, symbol) in table.relocations() {
        let bytes = match Some(typ) == copy {
            true => table.symbol_size(symbol).unwrap_or(pointer),
            false => pointer,
        };
        ranges.push(written(offset, bytes));
    }
    let packed = table.packed();
    ranges.extend(packed.into_iter().map(|vaddr| written(vaddr, pointer)));
    ranges.extend(table.reserved(pointer));
    ranges
}

/// Tags Android's linker reads beside the standard ones.
const DT_ANDROID_REL: u32 = 0x6000_000f;
const DT_ANDROID_RELSZ: u32 = 0x6000_0010;
const DT_ANDROID_RELA: u32 = 0x6000_0011;
const DT_ANDROID_RELASZ: u32 = 0x6000_0012;
const DT_ANDROID_RELR: u32 = 0x6fff_e000;
const DT_ANDROID_RELRSZ: u32 = 0x6fff_e001;
/// The generic packed relative table, which `object` does not name.
const DT_RELR: u32 = 36;
const DT_RELRSZ: u32 = 35;

/// One image's dynamic table, and the loaded bytes its addresses name.
struct Table<'f, 'data, E: FileHeader, R: object::ReadRef<'data>> {
    file: &'f ElfFile<'data, E, R>,
    entries: &'data [E::Dyn],
}

impl<'f, 'data, E: FileHeader, R: object::ReadRef<'data>> Table<'f, 'data, E, R> {
    fn of(file: &'f ElfFile<'data, E, R>) -> Option<Self> {
        let (endian, data) = (file.endian(), file.data());
        let mut headers = file.elf_program_headers().iter();
        let header = headers.find(|header| header.p_type(endian) == elf::PT_DYNAMIC)?;
        let offset: u64 = header.p_offset(endian).into();
        let length = data
            .len()
            .ok()?
            .saturating_sub(offset)
            .min(header.p_filesz(endian).into());
        let entries = whole::<E::Dyn>(data.read_bytes_at(offset, length).ok()?);
        // The loader reads to the terminating entry, whatever size the header claims.
        let end = entries
            .iter()
            .position(|entry| entry.d_tag(endian).into() == 0);
        let entries = &entries[..end.unwrap_or(entries.len())];
        Some(Self { file, entries })
    }

    fn tag(&self, wanted: u32) -> Option<u64> {
        let endian = self.file.endian();
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.tag32(endian) == Some(wanted))?;
        Some(entry.d_val(endian).into())
    }

    /// The file bytes a loaded range holds, found through the segment that loads it.
    fn bytes(&self, vaddr: u64, size: u64) -> Option<&'data [u8]> {
        let endian = self.file.endian();
        let header = self.file.elf_program_headers().iter().find(|header| {
            let (start, filesz): (u64, u64) = (
                header.p_vaddr(endian).into(),
                header.p_filesz(endian).into(),
            );
            header.p_type(endian) == elf::PT_LOAD
                && vaddr >= start
                && (vaddr - start)
                    .checked_add(size)
                    .is_some_and(|end| end <= filesz)
        })?;
        let into = vaddr - header.p_vaddr(endian).into();
        let offset = header.p_offset(endian).into().checked_add(into)?;
        self.file.data().read_bytes_at(offset, size).ok()
    }

    /// The bytes a pair of tags names: where a table is loaded, and how long it is.
    fn table(&self, address: u32, size: u32) -> Option<&'data [u8]> {
        self.bytes(self.tag(address)?, self.tag(size)?)
    }

    /// Each explicit relocation: its offset, its type and its symbol.
    fn relocations(&self) -> Vec<(u64, u32, u32)> {
        let mut found = Vec::new();
        let plt_rela = self.tag(elf::DT_PLTREL) == Some(u64::from(elf::DT_RELA));
        for (bytes, rela) in [
            (self.table(elf::DT_RELA, elf::DT_RELASZ), true),
            (self.table(elf::DT_REL, elf::DT_RELSZ), false),
            (self.table(elf::DT_JMPREL, elf::DT_PLTRELSZ), plt_rela),
        ] {
            found.extend(bytes.map_or_else(Vec::new, |bytes| self.entries_of(bytes, rela)));
        }
        found
    }

    /// The entries of one `Rel` or `Rela` table.
    fn entries_of(&self, bytes: &'data [u8], rela: bool) -> Vec<(u64, u32, u32)> {
        let (endian, mips64el) = (
            self.file.endian(),
            self.file.elf_header().is_mips64el(self.file.endian()),
        );
        match rela {
            true => whole::<E::Rela>(bytes)
                .iter()
                .map(|entry| {
                    (
                        entry.r_offset(endian).into(),
                        entry.r_type(endian, mips64el),
                        entry.r_sym(endian, mips64el),
                    )
                })
                .collect(),
            false => whole::<E::Rel>(bytes)
                .iter()
                .map(|entry| {
                    (
                        entry.r_offset(endian).into(),
                        entry.r_type(endian),
                        entry.r_sym(endian),
                    )
                })
                .collect(),
        }
    }

    /// Every address a packed table relocates: `DT_RELR` and Android's packed forms.
    fn packed(&self) -> Vec<u64> {
        let endian = self.file.endian();
        let mut found = Vec::new();
        for (address, size) in [(DT_RELR, DT_RELRSZ), (DT_ANDROID_RELR, DT_ANDROID_RELRSZ)] {
            let words = whole::<E::Relr>(self.table(address, size).unwrap_or_default());
            found.extend(object::read::elf::RelrIterator::<E>::new(endian, words).map(Into::into));
        }
        for (address, size, rela) in [
            (DT_ANDROID_REL, DT_ANDROID_RELSZ, false),
            (DT_ANDROID_RELA, DT_ANDROID_RELASZ, true),
        ] {
            found.extend(android_packed(
                self.table(address, size).unwrap_or_default(),
                rela,
            ));
        }
        found
    }

    /// The size of the object a dynamic symbol names, read from the table the loader reads it from.
    fn symbol_size(&self, index: u32) -> Option<u64> {
        let (symbols, entry) = (self.tag(elf::DT_SYMTAB)?, self.tag(elf::DT_SYMENT)?);
        let bytes = self.bytes(
            symbols.wrapping_add(u64::from(index).wrapping_mul(entry)),
            entry,
        )?;
        let (symbol, _) = object::pod::from_bytes::<E::Sym>(bytes).ok()?;
        Some(symbol.st_size(self.file.endian()).into()).filter(|size| *size > 0)
    }

    /// The words of the global offset table the loader fills with no relocation naming them, as each psABI reserves them.
    fn reserved(&self, pointer: u64) -> Option<Range<u64>> {
        use object::Architecture as A;
        let got = self.tag(elf::DT_PLTGOT)?;
        let (first, count) = match self.file.architecture() {
            // The link map and the lazy resolver, after the word that holds `_DYNAMIC`.
            A::X86_64 | A::X86_64_X32 | A::I386 | A::Arm | A::Aarch64 | A::Aarch64_Ilp32 => (1, 2),
            A::Riscv32 | A::Riscv64 | A::LoongArch64 => (0, 2),
            // The whole table: its local words are rebased and its global ones bound, all without relocations.
            A::Mips | A::Mips64 | A::Mips64_N32 => {
                let local = self.tag(elf::DT_MIPS_LOCAL_GOTNO)?;
                let symbols = self.tag(elf::DT_MIPS_SYMTABNO)?;
                let first_global = self.tag(elf::DT_MIPS_GOTSYM)?;
                (
                    0,
                    local.saturating_add(symbols.saturating_sub(first_global)),
                )
            }
            _ => return None,
        };
        let start = got.wrapping_add(first * pointer);
        Some(written(start, count.saturating_mul(pointer)))
    }
}

/// As many whole entries as the bytes hold.
fn whole<T: object::Pod>(bytes: &[u8]) -> &[T] {
    let count = bytes.len() / std::mem::size_of::<T>().max(1);
    object::pod::slice_from_bytes::<T>(bytes, count).map_or(&[], |(entries, _)| entries)
}

/// The relocation type that copies a whole object out of a library, which is as wide as that object.
fn copy_type(architecture: object::Architecture) -> Option<u32> {
    use object::Architecture as A;
    Some(match architecture {
        A::X86_64 | A::X86_64_X32 => elf::R_X86_64_COPY,
        A::I386 => elf::R_386_COPY,
        A::Aarch64 | A::Aarch64_Ilp32 => elf::R_AARCH64_COPY,
        A::Arm => elf::R_ARM_COPY,
        A::Riscv32 | A::Riscv64 => elf::R_RISCV_COPY,
        A::PowerPc | A::PowerPc64 => elf::R_PPC_COPY,
        A::Mips | A::Mips64 | A::Mips64_N32 => elf::R_MIPS_COPY,
        A::Sparc | A::Sparc32Plus | A::Sparc64 => elf::R_SPARC_COPY,
        A::S390x => elf::R_390_COPY,
        A::LoongArch64 => elf::R_LARCH_COPY,
        _ => return None,
    })
}

/// How many bytes a copy relocation writes: the size of the object it names.
fn copied_size(file: &object::File<'_>, relocation: &object::Relocation) -> Option<u64> {
    let object::RelocationTarget::Symbol(index) = relocation.target() else {
        return None;
    };
    let symbol = file.dynamic_symbol_table()?.symbol_by_index(index).ok()?;
    Some(symbol.size()).filter(|size| *size > 0)
}

/// Every address a packed section relocates: `SHT_RELR`, and Android's packed forms.
fn relr<'data, Elf, R>(file: &object::read::elf::ElfFile<'data, Elf, R>) -> Vec<u64>
where
    Elf: object::read::elf::FileHeader,
    R: object::ReadRef<'data>,
{
    use object::read::elf::{RelrIterator, SectionHeader as _};
    const ANDROID_REL: u32 = 0x6000_0001;
    const ANDROID_RELA: u32 = 0x6000_0002;
    const ANDROID_RELR: u32 = 0x6fff_ff00;
    let endian = file.endian();
    let mut found = Vec::new();
    for section in file.elf_section_table().iter() {
        let kind = section.sh_type(endian);
        match kind {
            object::elf::SHT_RELR | ANDROID_RELR => {
                let words = section.data_as_array::<Elf::Relr, _>(endian, file.data());
                let words = words.unwrap_or_default();
                found.extend(RelrIterator::<Elf>::new(endian, words).map(Into::into));
            }
            ANDROID_REL | ANDROID_RELA => {
                let data = section.data(endian, file.data()).unwrap_or_default();
                found.extend(android_packed(data, kind == ANDROID_RELA));
            }
            _ => {}
        }
    }
    found
}

/// The offsets an `APS2` packed relocation section names, as bionic's linker decodes it.
fn android_packed(data: &[u8], addend: bool) -> Vec<u64> {
    let Some(stream) = data.strip_prefix(b"APS2") else {
        return Vec::new();
    };
    let mut leb = Leb {
        bytes: stream,
        at: 0,
    };
    let (Some(count), Some(offset)) = (leb.sleb(), leb.sleb()) else {
        return Vec::new();
    };
    let mut packed = Packed {
        leb,
        addend,
        offset,
        found: Vec::new(),
    };
    let mut left = count;
    while left > 0 {
        let Some(size) = packed.group(left) else {
            break;
        };
        left -= size;
    }
    packed.found
}

/// An `APS2` stream being decoded: where it is, and the offset the last relocation left.
struct Packed<'b> {
    leb: Leb<'b>,
    addend: bool,
    offset: i64,
    found: Vec<u64>,
}

impl Packed<'_> {
    /// One group: a header saying which fields its relocations share, then each relocation's own.
    fn group(&mut self, left: i64) -> Option<i64> {
        let size = self.leb.sleb()?.min(left);
        let flags = self.leb.sleb()?;
        if size <= 0 {
            return None;
        }
        let (by_info, by_delta, by_addend) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
        let has_addend = self.addend && flags & 8 != 0;
        let delta = if by_delta { self.leb.sleb()? } else { 0 };
        let shared = usize::from(by_info) + usize::from(has_addend && by_addend);
        let own = usize::from(!by_info) + usize::from(has_addend && !by_addend);
        self.leb.skip(shared)?;
        for _ in 0..size {
            let step = if by_delta { delta } else { self.leb.sleb()? };
            self.offset = self.offset.wrapping_add(step);
            self.leb.skip(own)?;
            self.found.push(self.offset as u64);
        }
        Some(size)
    }
}

/// A cursor over a run of signed LEB128 numbers.
struct Leb<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl Leb<'_> {
    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0u32;
        let last = loop {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            value |= i64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
            shift += 7;
            if byte & 0x80 == 0 {
                break byte;
            }
        };
        let negative = shift < 64 && last & 0x40 != 0;
        Some(if negative {
            value | (-1i64 << shift)
        } else {
            value
        })
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        for _ in 0..count {
            self.sleb()?;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_aps2_stream_steps_by_its_group_delta_or_by_each_relocation_own() {
        // Three relocations from 0x1000: a group of two sharing info and an 8-byte delta, then one with its own delta of 0x100.
        let stream = [
            b'A', b'P', b'S', b'2', 0x03, 0x80, 0x20, // count, base offset
            0x02, 0x0b, 0x08, 0x83, 0x08, 0x10,
            0x10, // group: size, flags, delta, info; two addends
            0x01, 0x09, 0x83, 0x08, 0x80, 0x02,
            0x10, // group: size, flags, info; a delta and an addend
        ];
        assert_eq!(android_packed(&stream, true), [0x1008, 0x1010, 0x1110]);
    }
}
