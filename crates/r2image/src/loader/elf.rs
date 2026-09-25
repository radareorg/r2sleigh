//! What an ELF loader writes: every relocation record its dynamic table or its sections name, and the table words its psABI reserves.
//!
//! There is one reader of relocation records. A table is reached two ways --
//! through the dynamic table, as the loader reads it, and through a section
//! header, as a static binary's start-up reads `.rela.iplt` -- and a record is
//! identified by where its bytes are in the file, so a table both routes reach
//! states each of its records once. The dynamic table's route is the loader's
//! own, so its order is the order of application.

use std::collections::BTreeSet;
use std::ops::Range;

use object::read::elf::{
    Dyn as _, ElfFile, FileHeader, ProgramHeader as _, Rel as _, Rela as _, SectionHeader as _,
    Sym as _,
};
use object::{Object, elf};

use r2abi::statement::{
    Applies, Binding, LoaderWrite, Record, Relocation, RelocationSymbol, Visibility, WriteKind,
};

use super::written;

/// Every relocation record the dynamic loader, or a static binary's own start-up, applies, in the order it applies them; what each writes; and the words the psABI reserves, which it writes with no record.
pub(super) fn read(
    file: &object::File<'_>,
    pointer: u64,
) -> (Vec<Relocation>, Vec<LoaderWrite>, Vec<Range<u64>>) {
    match file {
        object::File::Elf32(file) => Elf::of(file, pointer).read(),
        object::File::Elf64(file) => Elf::of(file, pointer).read(),
        _ => (Vec::new(), Vec::new(), Vec::new()),
    }
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
/// Android's section types for the same tables.
const SHT_ANDROID_REL: u32 = 0x6000_0001;
const SHT_ANDROID_RELA: u32 = 0x6000_0002;
const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;

/// How a table spells its records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Rel,
    Rela,
    Relr,
    /// Android's `APS2` stream, with or without addends.
    Packed {
        addend: bool,
    },
}

/// Where a table's symbol indices point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Symbols {
    /// The dynamic table's own `DT_SYMTAB`, which is what the loader reads.
    Dynamic,
    /// The symbol table a section header links to.
    Section(object::SectionIndex),
    /// None: a record naming a symbol names nothing this image states.
    None,
}

/// One entry as its table encodes it: where its bytes are, where it writes,
/// its type, its symbol's index and its addend.
type Encoded = (Record, u64, u32, u32, Option<i64>);

/// One table of relocation records, located in the file.
#[derive(Debug, Clone, Copy)]
struct View {
    offset: u64,
    size: u64,
    form: Form,
    /// When the loader applies it: packed relative words first, then the
    /// explicit tables, then the procedure-linkage table, then what only a
    /// static start-up applies.
    phase: u8,
    symbols: Symbols,
}

/// One image's program headers, dynamic table and section headers, read the way its loader reads them.
struct Elf<'f, 'data, E: FileHeader, R: object::ReadRef<'data>> {
    file: &'f ElfFile<'data, E, R>,
    endian: E::Endian,
    pointer: u64,
    dynamic: &'data [E::Dyn],
}

impl<'f, 'data, E: FileHeader, R: object::ReadRef<'data>> Elf<'f, 'data, E, R> {
    fn of(file: &'f ElfFile<'data, E, R>, pointer: u64) -> Self {
        let endian = file.endian();
        Self {
            file,
            endian,
            pointer,
            dynamic: dynamic_entries(file).unwrap_or_default(),
        }
    }

    /// Every record once, in application order, and every range written.
    fn read(&self) -> (Vec<Relocation>, Vec<LoaderWrite>, Vec<Range<u64>>) {
        let mut views = self.tabled();
        views.extend(self.sectioned());
        // A record is where its bytes are; the first view to reach it -- the
        // loader's own, where it has one -- says when it is applied.
        let mut seen: BTreeSet<Record> = BTreeSet::new();
        let mut records: Vec<(u8, Relocation)> = views
            .iter()
            .flat_map(|view| {
                let phase = view.phase;
                self.records(view)
                    .into_iter()
                    .map(move |record| (phase, record))
            })
            .filter(|(_, record)| seen.insert(record.record))
            .collect();
        // Stable: within one phase, table order is application order.
        records.sort_by_key(|(phase, _)| *phase);
        let relocations: Vec<Relocation> = records.into_iter().map(|(_, record)| record).collect();
        let writes = relocations
            .iter()
            .map(|record| LoaderWrite {
                place: record.vaddr,
                width: extent(record, self.pointer),
                kind: self.kind(record),
            })
            .collect();
        (relocations, writes, self.reserved().into_iter().collect())
    }

    /// What one record writes, in the coordinates the image is linked at.
    ///
    /// A relative record's value is its addend, or the word the file holds
    /// where the table states none: the load bias is what moves it, and in
    /// link coordinates the bias is zero whatever address the first segment
    /// is linked at. A definition's address is the value only where no image
    /// loaded ahead of this one can replace it.
    fn kind(&self, record: &Relocation) -> WriteKind {
        let addend = || match record.addend {
            Some(addend) => Some(addend as u64),
            None => self.file_word(record.vaddr, record.width),
        };
        match record.applies {
            Applies::Relative => addend().map_or(WriteKind::Unknown, WriteKind::Relative),
            Applies::Resolver => addend().map_or(WriteKind::Unknown, WriteKind::Resolver),
            Applies::ThreadLocal => WriteKind::NotAnAddress,
            Applies::Copy | Applies::Unknown => WriteKind::Unknown,
            Applies::Symbol | Applies::SymbolPlusAddend => {
                let offset = match record.applies {
                    Applies::Symbol => Some(0),
                    _ => addend(),
                };
                let Some(offset) = offset else {
                    return WriteKind::Unknown;
                };
                let Some(symbol) = &record.symbol else {
                    // Symbol index zero is the value zero: the addend, not moved.
                    return WriteKind::Absolute(offset);
                };
                // An import's address is the value only where nothing is added to it.
                let Some(defined) = symbol.defined else {
                    return match offset {
                        0 => WriteKind::Import {
                            symbol: symbol.name.clone(),
                        },
                        _ => WriteKind::Unknown,
                    };
                };
                let value = defined.wrapping_add(offset);
                match self.binds_locally(symbol) {
                    true => WriteKind::Absolute(value),
                    false => WriteKind::Preemptible {
                        symbol: symbol.name.clone(),
                        default: value,
                    },
                }
            }
        }
    }

    /// Whether a definition this image makes is the one every reference in it binds to.
    ///
    /// The executable is first in every lookup scope, so nothing replaces its
    /// definitions; a hidden, internal or protected symbol, or a local one, is
    /// never exported to be replaced; and `DT_SYMBOLIC` binds a library's own
    /// references to its own definitions.
    fn binds_locally(&self, symbol: &RelocationSymbol) -> bool {
        const DF_SYMBOLIC: u64 = 0x2;
        const DF_1_PIE: u64 = 0x0800_0000;
        let endian = self.endian;
        let header = self.file.elf_header();
        let executable = header.e_type(endian) == elf::ET_EXEC
            || self
                .tag(elf::DT_FLAGS_1)
                .is_some_and(|flags| flags & DF_1_PIE != 0)
            || self
                .file
                .elf_program_headers()
                .iter()
                .any(|header| header.p_type(endian) == elf::PT_INTERP);
        let symbolic = self.tag(elf::DT_SYMBOLIC).is_some()
            || self
                .tag(elf::DT_FLAGS)
                .is_some_and(|flags| flags & DF_SYMBOLIC != 0);
        executable
            || symbolic
            || symbol.binding == Binding::Local
            || symbol.visibility != Visibility::Default
    }

    /// The word the file holds at a loaded address, in the image's byte order.
    fn file_word(&self, vaddr: u64, width: u64) -> Option<u64> {
        let bytes = self.bytes(self.offset_of(vaddr, width)?, width);
        if bytes.len() as u64 != width || width > 8 {
            return None;
        }
        let little = self.file.is_little_endian();
        Some(bytes.iter().enumerate().fold(0u64, |value, (at, byte)| {
            let shift = match little {
                true => 8 * at,
                false => 8 * (bytes.len() - 1 - at),
            };
            value | u64::from(*byte) << shift
        }))
    }

    fn tag(&self, wanted: u32) -> Option<u64> {
        let entry = self
            .dynamic
            .iter()
            .find(|entry| entry.tag32(self.endian) == Some(wanted))?;
        Some(entry.d_val(self.endian).into())
    }

    /// The file offset a loaded range starts at, found through the segment that loads it.
    fn offset_of(&self, vaddr: u64, size: u64) -> Option<u64> {
        let endian = self.endian;
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
        header.p_offset(endian).into().checked_add(into)
    }

    fn bytes(&self, offset: u64, size: u64) -> &'data [u8] {
        self.file
            .data()
            .read_bytes_at(offset, size)
            .unwrap_or_default()
    }

    /// The tables the dynamic table names, as the loader reads them: through the program headers, whatever sections remain.
    fn tabled(&self) -> Vec<View> {
        let plt_rela = self.tag(elf::DT_PLTREL) == Some(u64::from(elf::DT_RELA));
        let tables = [
            (DT_RELR, DT_RELRSZ, Form::Relr, 0),
            (DT_ANDROID_RELR, DT_ANDROID_RELRSZ, Form::Relr, 0),
            (elf::DT_RELA, elf::DT_RELASZ, Form::Rela, 1),
            (elf::DT_REL, elf::DT_RELSZ, Form::Rel, 1),
            (
                DT_ANDROID_RELA,
                DT_ANDROID_RELASZ,
                Form::Packed { addend: true },
                1,
            ),
            (
                DT_ANDROID_REL,
                DT_ANDROID_RELSZ,
                Form::Packed { addend: false },
                1,
            ),
            (
                elf::DT_JMPREL,
                elf::DT_PLTRELSZ,
                if plt_rela { Form::Rela } else { Form::Rel },
                2,
            ),
        ];
        tables
            .into_iter()
            .filter_map(|(address, size, form, phase)| {
                let (address, size) = (self.tag(address)?, self.tag(size)?);
                Some(View {
                    offset: self.offset_of(address, size)?,
                    size,
                    form,
                    phase,
                    symbols: Symbols::Dynamic,
                })
            })
            .collect()
    }

    /// Every loaded relocation section: what a static binary's start-up applies, and the same tables again where the dynamic table names them.
    fn sectioned(&self) -> Vec<View> {
        let endian = self.endian;
        let table = self.file.elf_section_table();
        let mut views = Vec::new();
        for header in table.iter() {
            let form = match header.sh_type(endian) {
                elf::SHT_REL => Form::Rel,
                elf::SHT_RELA => Form::Rela,
                elf::SHT_RELR | SHT_ANDROID_RELR => Form::Relr,
                SHT_ANDROID_REL => Form::Packed { addend: false },
                SHT_ANDROID_RELA => Form::Packed { addend: true },
                _ => continue,
            };
            let flags: u64 = header.sh_flags(endian).into();
            if flags & u64::from(elf::SHF_ALLOC) == 0 {
                continue;
            }
            let link = header.sh_link(endian);
            views.push(View {
                offset: header.sh_offset(endian).into(),
                size: header.sh_size(endian).into(),
                form,
                phase: 3,
                symbols: match link {
                    0 => Symbols::None,
                    link => Symbols::Section(object::SectionIndex(link as usize)),
                },
            });
        }
        views
    }

    /// The records of one table.
    fn records(&self, view: &View) -> Vec<Relocation> {
        let machine = self.file.elf_header().e_machine(self.endian);
        self.encoded(view)
            .into_iter()
            .filter_map(|(record, vaddr, ntype, symbol, addend)| {
                // A packed relative word is a relative relocation of a pointer, whatever the machine numbers it.
                let (applies, width) = match view.form {
                    Form::Relr => (Applies::Relative, self.pointer),
                    _ => applies(machine, ntype, self.pointer)?,
                };
                let symbol = (symbol != 0)
                    .then(|| self.symbol(view.symbols, symbol))
                    .flatten();
                Some(Relocation {
                    vaddr,
                    record,
                    ntype,
                    width,
                    addend,
                    symbol,
                    applies,
                })
            })
            .collect()
    }

    /// Each entry of one table as its form encodes it: where its bytes are,
    /// where it writes, its type, its symbol's index and its addend.
    fn encoded(&self, view: &View) -> Vec<Encoded> {
        let bytes = self.bytes(view.offset, view.size);
        let (endian, mips64el) = (self.endian, self.file.elf_header().is_mips64el(self.endian));
        let at = |index: usize, size: usize| Record {
            table: view.offset + (index * size) as u64,
            index: 0,
        };
        match view.form {
            Form::Rela => whole::<E::Rela>(bytes)
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    (
                        at(index, std::mem::size_of::<E::Rela>()),
                        entry.r_offset(endian).into(),
                        entry.r_type(endian, mips64el),
                        entry.r_sym(endian, mips64el),
                        Some(entry.r_addend(endian).into()),
                    )
                })
                .collect(),
            Form::Rel => whole::<E::Rel>(bytes)
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    (
                        at(index, std::mem::size_of::<E::Rel>()),
                        entry.r_offset(endian).into(),
                        entry.r_type(endian),
                        entry.r_sym(endian),
                        None,
                    )
                })
                .collect(),
            Form::Relr => {
                let relative = relative_type(self.file.elf_header().e_machine(endian));
                relr(bytes, self.pointer, self.file.is_little_endian())
                    .into_iter()
                    .map(|(offset, bit, vaddr)| {
                        let record = Record {
                            table: view.offset + offset,
                            index: bit,
                        };
                        (record, vaddr, relative.unwrap_or(0), 0, None)
                    })
                    .collect()
            }
            Form::Packed { addend } => {
                let is_64 = self.file.is_64();
                android_packed(bytes, addend)
                    .into_iter()
                    .enumerate()
                    .map(|(index, (vaddr, info, addend))| {
                        let (symbol, typ) = match is_64 {
                            true => ((info >> 32) as u32, info as u32),
                            false => ((info >> 8) as u32, (info & 0xff) as u32),
                        };
                        let record = Record {
                            table: view.offset,
                            index: index as u64,
                        };
                        (record, vaddr, typ, symbol, addend)
                    })
                    .collect()
            }
        }
    }

    /// The symbol one index names, in the table the view's records index.
    fn symbol(&self, symbols: Symbols, index: u32) -> Option<RelocationSymbol> {
        let endian = self.endian;
        let data = self.file.data();
        let (symbol, name): (&E::Sym, &[u8]) = match symbols {
            Symbols::None => return None,
            Symbols::Section(section) => {
                let table = self
                    .file
                    .elf_section_table()
                    .symbol_table_by_index(endian, data, section)
                    .ok()?;
                let symbol = table.symbol(object::SymbolIndex(index as usize)).ok()?;
                (symbol, table.symbol_name(endian, symbol).ok()?)
            }
            Symbols::Dynamic => {
                let entry = self.tag(elf::DT_SYMENT)?;
                let address = self
                    .tag(elf::DT_SYMTAB)?
                    .checked_add(u64::from(index).checked_mul(entry)?)?;
                let offset = self.offset_of(address, entry)?;
                let (symbol, _) =
                    object::pod::from_bytes::<E::Sym>(self.bytes(offset, entry)).ok()?;
                let strings = self.tag(elf::DT_STRTAB)?;
                let length = self.tag(elf::DT_STRSZ)?;
                let start = u64::from(symbol.st_name(endian));
                let table = self.offset_of(strings, length)?;
                let text = self.bytes(table, length).get(start as usize..)?;
                let end = text.iter().position(|byte| *byte == 0)?;
                (symbol, &text[..end])
            }
        };
        let name = core::str::from_utf8(name).ok()?.to_owned();
        let defined = symbol.st_shndx(endian) != elf::SHN_UNDEF;
        Some(RelocationSymbol {
            name,
            defined: defined.then(|| symbol.st_value(endian).into()),
            size: symbol.st_size(endian).into(),
            binding: binding(symbol.st_bind()),
            visibility: visibility(symbol.st_visibility()),
        })
    }

    /// The words of the global offset table the loader fills with no relocation naming them, as each psABI reserves them.
    fn reserved(&self) -> Option<Range<u64>> {
        use object::Architecture as A;
        let pointer = self.pointer;
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

/// The dynamic table's entries, read through `PT_DYNAMIC` to the terminating one.
fn dynamic_entries<'data, E: FileHeader, R: object::ReadRef<'data>>(
    file: &ElfFile<'data, E, R>,
) -> Option<&'data [E::Dyn]> {
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
    Some(&entries[..end.unwrap_or(entries.len())])
}

/// How many bytes one record writes: a copy writes the whole object it names.
fn extent(record: &Relocation, pointer: u64) -> u64 {
    match record.applies {
        Applies::Copy => record
            .symbol
            .as_ref()
            .map(|symbol| symbol.size)
            .filter(|size| *size > 0)
            .unwrap_or(pointer),
        _ => record.width,
    }
}

fn binding(bind: u8) -> Binding {
    match bind {
        elf::STB_LOCAL => Binding::Local,
        elf::STB_GLOBAL => Binding::Global,
        elf::STB_WEAK => Binding::Weak,
        other => Binding::Other(other),
    }
}

fn visibility(other: u8) -> Visibility {
    match other & 3 {
        elf::STV_INTERNAL => Visibility::Internal,
        elf::STV_HIDDEN => Visibility::Hidden,
        elf::STV_PROTECTED => Visibility::Protected,
        _ => Visibility::Default,
    }
}

/// The machine's type number for a relative relocation, which a `RELR` word applies.
fn relative_type(machine: u16) -> Option<u32> {
    Some(match machine {
        elf::EM_X86_64 => elf::R_X86_64_RELATIVE,
        elf::EM_386 => elf::R_386_RELATIVE,
        elf::EM_AARCH64 => elf::R_AARCH64_RELATIVE,
        elf::EM_ARM => elf::R_ARM_RELATIVE,
        elf::EM_RISCV => elf::R_RISCV_RELATIVE,
        elf::EM_LOONGARCH => elf::R_LARCH_RELATIVE,
        _ => return None,
    })
}

/// What a dynamic relocation type computes and how many bytes it writes, as the machine's psABI states it; `None` for the type that writes nothing.
///
/// A type this table does not name is still a write the loader makes, so it
/// is kept, at the width of a pointer, with its computation unknown.
fn applies(machine: u16, ntype: u32, pointer: u64) -> Option<(Applies, u64)> {
    use Applies as A;
    if ntype == 0 {
        return None;
    }
    let (applies, width) = match machine {
        elf::EM_X86_64 => match ntype {
            elf::R_X86_64_64 => (A::SymbolPlusAddend, 8),
            elf::R_X86_64_32 | elf::R_X86_64_32S => (A::SymbolPlusAddend, 4),
            elf::R_X86_64_COPY => (A::Copy, pointer),
            elf::R_X86_64_GLOB_DAT | elf::R_X86_64_JUMP_SLOT => (A::Symbol, pointer),
            elf::R_X86_64_RELATIVE | elf::R_X86_64_RELATIVE64 => (A::Relative, pointer),
            elf::R_X86_64_IRELATIVE => (A::Resolver, pointer),
            elf::R_X86_64_DTPMOD64 | elf::R_X86_64_DTPOFF64 | elf::R_X86_64_TPOFF64 => {
                (A::ThreadLocal, 8)
            }
            elf::R_X86_64_TLSDESC => (A::ThreadLocal, 16),
            _ => (A::Unknown, pointer),
        },
        elf::EM_386 => match ntype {
            elf::R_386_32 => (A::SymbolPlusAddend, 4),
            elf::R_386_COPY => (A::Copy, 4),
            elf::R_386_GLOB_DAT | elf::R_386_JMP_SLOT => (A::Symbol, 4),
            elf::R_386_RELATIVE => (A::Relative, 4),
            elf::R_386_IRELATIVE => (A::Resolver, 4),
            elf::R_386_TLS_TPOFF
            | elf::R_386_TLS_DTPMOD32
            | elf::R_386_TLS_DTPOFF32
            | elf::R_386_TLS_TPOFF32 => (A::ThreadLocal, 4),
            elf::R_386_TLS_DESC => (A::ThreadLocal, 8),
            _ => (A::Unknown, 4),
        },
        elf::EM_AARCH64 => match ntype {
            elf::R_AARCH64_ABS64 => (A::SymbolPlusAddend, 8),
            elf::R_AARCH64_ABS32 => (A::SymbolPlusAddend, 4),
            elf::R_AARCH64_COPY => (A::Copy, 8),
            // AArch64 adds the addend to both, which ELF gABI leaves to the psABI.
            elf::R_AARCH64_GLOB_DAT | elf::R_AARCH64_JUMP_SLOT => (A::SymbolPlusAddend, 8),
            elf::R_AARCH64_RELATIVE => (A::Relative, 8),
            elf::R_AARCH64_IRELATIVE => (A::Resolver, 8),
            elf::R_AARCH64_TLS_DTPMOD | elf::R_AARCH64_TLS_DTPREL | elf::R_AARCH64_TLS_TPREL => {
                (A::ThreadLocal, 8)
            }
            elf::R_AARCH64_TLSDESC => (A::ThreadLocal, 16),
            _ => (A::Unknown, pointer),
        },
        elf::EM_ARM => match ntype {
            elf::R_ARM_ABS32 => (A::SymbolPlusAddend, 4),
            elf::R_ARM_COPY => (A::Copy, 4),
            elf::R_ARM_GLOB_DAT | elf::R_ARM_JUMP_SLOT => (A::Symbol, 4),
            elf::R_ARM_RELATIVE => (A::Relative, 4),
            elf::R_ARM_IRELATIVE => (A::Resolver, 4),
            elf::R_ARM_TLS_DTPMOD32 | elf::R_ARM_TLS_DTPOFF32 | elf::R_ARM_TLS_TPOFF32 => {
                (A::ThreadLocal, 4)
            }
            elf::R_ARM_TLS_DESC => (A::ThreadLocal, 8),
            _ => (A::Unknown, 4),
        },
        elf::EM_RISCV => match ntype {
            elf::R_RISCV_32 => (A::SymbolPlusAddend, 4),
            elf::R_RISCV_64 => (A::SymbolPlusAddend, 8),
            elf::R_RISCV_COPY => (A::Copy, pointer),
            elf::R_RISCV_JUMP_SLOT => (A::Symbol, pointer),
            elf::R_RISCV_RELATIVE => (A::Relative, pointer),
            elf::R_RISCV_IRELATIVE => (A::Resolver, pointer),
            elf::R_RISCV_TLS_DTPMOD32 | elf::R_RISCV_TLS_DTPREL32 | elf::R_RISCV_TLS_TPREL32 => {
                (A::ThreadLocal, 4)
            }
            elf::R_RISCV_TLS_DTPMOD64 | elf::R_RISCV_TLS_DTPREL64 | elf::R_RISCV_TLS_TPREL64 => {
                (A::ThreadLocal, 8)
            }
            _ => (A::Unknown, pointer),
        },
        _ => (A::Unknown, pointer),
    };
    Some((applies, width))
}

/// As many whole entries as the bytes hold.
fn whole<T: object::Pod>(bytes: &[u8]) -> &[T] {
    let count = bytes.len() / std::mem::size_of::<T>().max(1);
    object::pod::slice_from_bytes::<T>(bytes, count).map_or(&[], |(entries, _)| entries)
}

/// Every address a packed relative table relocates, each with the offset of the word stating it and which bit of that word does.
///
/// An even word is an address, and states itself; an odd one is a bitmap over
/// the pointer-sized words after the last address, each set bit above bit
/// zero one relocation, and the next bitmap continues where it ends.
fn relr(bytes: &[u8], pointer: u64, little: bool) -> Vec<(u64, u64, u64)> {
    let mut found = Vec::new();
    let mut base = 0u64;
    let bits = pointer * 8;
    for (index, word) in bytes.chunks_exact(pointer as usize).enumerate() {
        let offset = index as u64 * pointer;
        let value = word.iter().enumerate().fold(0u64, |value, (at, byte)| {
            let shift = match little {
                true => 8 * at,
                false => 8 * (word.len() - 1 - at),
            };
            value | u64::from(*byte) << shift
        });
        if value & 1 == 0 {
            found.push((offset, 0, value));
            base = value.wrapping_add(pointer);
            continue;
        }
        for bit in 1..bits {
            if value >> bit & 1 == 1 {
                found.push((offset, bit, base.wrapping_add((bit - 1) * pointer)));
            }
        }
        base = base.wrapping_add((bits - 1) * pointer);
    }
    found
}

/// Each relocation an `APS2` packed stream states, as bionic's linker decodes it: its offset, its info word, and its addend where the stream carries them.
fn android_packed(data: &[u8], addend: bool) -> Vec<(u64, u64, Option<i64>)> {
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
        info: 0,
        value: 0,
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

/// An `APS2` stream being decoded: where it is, and the fields the last relocation left.
struct Packed<'b> {
    leb: Leb<'b>,
    addend: bool,
    offset: i64,
    info: i64,
    /// The addend, which the stream states as a running sum.
    value: i64,
    found: Vec<(u64, u64, Option<i64>)>,
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
        if by_info {
            self.info = self.leb.sleb()?;
        }
        if self.addend && by_addend {
            self.value = self.value.wrapping_add(self.leb.sleb()?);
        } else if !has_addend {
            self.value = 0;
        }
        for _ in 0..size {
            let step = if by_delta { delta } else { self.leb.sleb()? };
            self.offset = self.offset.wrapping_add(step);
            if !by_info {
                self.info = self.leb.sleb()?;
            }
            if has_addend && !by_addend {
                self.value = self.value.wrapping_add(self.leb.sleb()?);
            }
            let addend = self.addend.then_some(self.value);
            self.found
                .push((self.offset as u64, self.info as u64, addend));
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
        let offsets: Vec<u64> = android_packed(&stream, true)
            .into_iter()
            .map(|(offset, ..)| offset)
            .collect();
        assert_eq!(offsets, [0x1008, 0x1010, 0x1110]);
    }

    #[test]
    fn a_relr_bitmap_states_one_relocation_per_set_bit_after_the_address_it_follows() {
        // 0x1000, then a bitmap with bits 1 and 3 set: 0x1008 and 0x1018.
        let mut words = Vec::new();
        words.extend_from_slice(&0x1000u64.to_le_bytes());
        words.extend_from_slice(&0b1011u64.to_le_bytes());
        let found = relr(&words, 8, true);
        assert_eq!(
            found,
            [(0, 0, 0x1000), (8, 1, 0x1008), (8, 3, 0x1018)],
            "each record is the word stating it and the bit"
        );
    }
}
