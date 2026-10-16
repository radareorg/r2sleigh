//! What an ELF loader writes: every relocation record its dynamic table or its sections name, and the table words its psABI reserves.
//!
//! There is one reader of relocation records. A table is reached two ways --
//! through the dynamic table, as the loader reads it, and through a section
//! header, as a static binary's start-up reads `.rela.iplt` -- and a record is
//! identified by where its bytes are in the file, so a table both routes reach
//! states each of its records once. The dynamic table's route is the loader's
//! own, so its order is the order of application.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use object::read::elf::{
    Dyn as _, ElfFile, FileHeader, ProgramHeader as _, Rel as _, Rela as _, SectionHeader as _,
    Sym as _,
};
use object::{Object, ObjectSymbol as _, elf};

use r2abi::statement::{
    Applies, Binding, Encoding, EntryKind, ImportStub, LoaderWrite, Record, Relocation,
    RelocationSymbol, StatedAt, Visibility, WriteKind,
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
const DT_ANDROID_REL: elf::DynamicTag = elf::DynamicTag(0x6000_000f);
const DT_ANDROID_RELSZ: elf::DynamicTag = elf::DynamicTag(0x6000_0010);
const DT_ANDROID_RELA: elf::DynamicTag = elf::DynamicTag(0x6000_0011);
const DT_ANDROID_RELASZ: elf::DynamicTag = elf::DynamicTag(0x6000_0012);
const DT_ANDROID_RELR: elf::DynamicTag = elf::DynamicTag(0x6fff_e000);
const DT_ANDROID_RELRSZ: elf::DynamicTag = elf::DynamicTag(0x6fff_e001);
/// The generic packed relative table, which `object` does not name.
const DT_RELR: elf::DynamicTag = elf::DynamicTag(36);
const DT_RELRSZ: elf::DynamicTag = elf::DynamicTag(35);
/// Android's section types for the same tables.
const SHT_ANDROID_REL: elf::SectionType = elf::SectionType(0x6000_0001);
const SHT_ANDROID_RELA: elf::SectionType = elf::SectionType(0x6000_0002);
const SHT_ANDROID_RELR: elf::SectionType = elf::SectionType(0x6fff_ff00);

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
    /// An object's compact stream, `SHT_CREL`.
    Crel,
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
type Encoded = (Record, u64, elf::RelocationType, u32, Option<i64>);

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
                encoding: record.encoding,
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
            // A field of an instruction or a word less its place, which a dynamic table states only for text relocations.
            Applies::Copy
            | Applies::Unknown
            | Applies::PcRelative
            | Applies::PltRelative
            | Applies::GotRelative
            | Applies::Field => WriteKind::Unknown,
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
                            symbol: symbol.name.to_string(),
                            library: None,
                        },
                        _ => WriteKind::Unknown,
                    };
                };
                let value = defined.wrapping_add(offset);
                match self.binds_locally(symbol) {
                    true => WriteKind::Absolute(value),
                    false => WriteKind::Preemptible {
                        symbol: symbol.name.to_string(),
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
        let endian = self.endian;
        let header = self.file.elf_header();
        let executable = header.e_type(endian) == elf::ET_EXEC
            || self
                .tag(elf::DT_FLAGS_1)
                .is_some_and(|flags| elf::DynamicFlags1(flags).contains(elf::DF_1_PIE))
            || self
                .file
                .elf_program_headers()
                .iter()
                .any(|header| header.p_type(endian) == elf::PT_INTERP);
        let symbolic = self.tag(elf::DT_SYMBOLIC).is_some()
            || self
                .tag(elf::DT_FLAGS)
                .is_some_and(|flags| elf::DynamicFlags(flags).contains(elf::DF_SYMBOLIC));
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

    fn tag(&self, wanted: elf::DynamicTag) -> Option<u64> {
        let entry = self
            .dynamic
            .iter()
            .find(|entry| entry.tag(self.endian) == wanted)?;
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
        let plt_rela = self.tag(elf::DT_PLTREL) == u64::try_from(elf::DT_RELA.0).ok();
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
            if !header.sh_flags(endian).contains(elf::SHF_ALLOC) {
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
                let (applies, width, encoding) = match view.form {
                    Form::Relr => (Applies::Relative, self.pointer, Encoding::Word),
                    _ => applies(machine, ntype, self.pointer)?,
                };
                let symbol = (symbol != 0)
                    .then(|| self.symbol(view.symbols, symbol))
                    .flatten();
                Some(Relocation {
                    vaddr,
                    record,
                    ntype: ntype.0,
                    width,
                    addend,
                    symbol: symbol.map(Box::new),
                    applies,
                    encoding,
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
                        (record, vaddr, relative.unwrap_or_default(), 0, None)
                    })
                    .collect()
            }
            Form::Crel => crel(bytes, view.offset),
            Form::Packed { addend } => {
                let is_64 = self.file.is_64();
                android_packed(bytes, addend)
                    .into_iter()
                    .enumerate()
                    .map(|(index, (vaddr, info, addend))| {
                        let (symbol, typ) = match is_64 {
                            true => ((info >> 32) as u32, elf::RelocationType(info as u32)),
                            false => (
                                (info >> 8) as u32,
                                elf::RelocationType((info & 0xff) as u32),
                            ),
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
            name: name.into(),
            defined: defined.then(|| symbol.st_value(endian).into()),
            size: symbol.st_size(endian).into(),
            binding: binding(symbol.st_bind(), self.file.elf_header().e_ident().os_abi),
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

/// What a relocatable object's records state once its sections are placed.
pub(super) struct Linked {
    /// Every record of every relocation section, in section order.
    pub relocations: Vec<Relocation>,
    /// What the records into loaded sections write, and each slot of the linkage.
    pub writes: Vec<LoaderWrite>,
    pub stubs: Vec<ImportStub>,
    /// Where each record's symbol plus addend is, by its place, sorted.
    pub targets: Vec<(u64, u64)>,
}

/// A relocatable object's records, each at the place `at` gives its section, and what a static link puts at `linkage` for them.
pub(super) fn linked(
    file: &object::File<'_>,
    at: &Placing<'_>,
    linkage: u64,
    pointer: u64,
) -> Linked {
    match file {
        object::File::Elf32(file) => Elf::of(file, pointer).linked(at, linkage),
        object::File::Elf64(file) => Elf::of(file, pointer).linked(at, linkage),
        _ => Linked {
            relocations: Vec::new(),
            writes: Vec::new(),
            stubs: Vec::new(),
            targets: Vec::new(),
        },
    }
}

/// Where the reader puts an object's sections, and each common symbol of its symbol table by index.
pub(super) struct Placing<'a> {
    pub section: &'a dyn Fn(object::SectionIndex) -> Option<u64>,
    pub common: &'a dyn Fn(u32) -> Option<u64>,
}

/// What a relocatable object's symbol is once its sections are placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Bound {
    /// A definition, at its placed address; weak where another object's may replace it.
    At { address: u64, weak: bool },
    /// Undefined: another object or image defines it. Keyed by symbol table and index.
    Import(usize, u32),
    /// A common symbol, or one in a section with no place: the static linker gives it its address.
    Unplaced,
}

/// What a static link adds for an object's loaded records: a stub per import one branches or
/// points to, then a slot per symbol one reads through the global offset table, from `linkage` on.
struct Linkage {
    /// Each import's stub and the name of the first record naming it.
    stubs: BTreeMap<(usize, u32), (u64, String)>,
    /// Each symbol's slot and the name of the first record naming it.
    slots: BTreeMap<Bound, (u64, String)>,
}

impl Linkage {
    fn of(binds: &[Bind], linkage: u64, pointer: u64) -> Self {
        let mut stubs: BTreeMap<(usize, u32), (u64, String)> = BTreeMap::new();
        let mut slots: BTreeMap<Bound, (u64, String)> = BTreeMap::new();
        for bind in binds.iter().filter(|bind| bind.loaded) {
            match (bind.record.applies, bind.bound) {
                (Applies::GotRelative, bound) => {
                    slots.entry(bound).or_insert_with(|| (0, bind.name()));
                }
                (
                    Applies::PcRelative | Applies::PltRelative | Applies::Field,
                    Bound::Import(table, index),
                ) => {
                    stubs
                        .entry((table, index))
                        .or_insert_with(|| (0, bind.name()));
                }
                _ => {}
            }
        }
        let places = stubs.values_mut().chain(slots.values_mut());
        for (at, (place, _)) in places.enumerate() {
            *place = linkage + at as u64 * pointer;
        }
        Self { stubs, slots }
    }

    fn stated(&self, pointer: u64) -> Vec<ImportStub> {
        let stub = |(place, name): &(u64, String)| ImportStub {
            vaddr: *place,
            size: pointer,
            symbol: name.clone(),
        };
        self.stubs.values().map(stub).collect()
    }

    /// What the static linker writes into each slot: the symbol's address.
    fn slot_writes(&self, pointer: u64) -> Vec<LoaderWrite> {
        let slot = |(bound, (place, name)): (&Bound, &(u64, String))| {
            let kind = match *bound {
                Bound::At {
                    address,
                    weak: false,
                } => WriteKind::Absolute(address),
                Bound::At {
                    address,
                    weak: true,
                } => WriteKind::Preemptible {
                    symbol: name.clone(),
                    default: address,
                },
                Bound::Import(..) => WriteKind::Import {
                    symbol: name.clone(),
                    library: None,
                },
                Bound::Unplaced => WriteKind::Unknown,
            };
            LoaderWrite {
                place: *place,
                width: pointer,
                kind,
                encoding: Encoding::Word,
            }
        };
        self.slots.iter().map(slot).collect()
    }

    /// What one record into a loaded section writes: its symbol, stub or slot plus its addend.
    fn written(&self, bind: &Bind, mask: u64) -> LoaderWrite {
        let record = &bind.record;
        let plus = |address: u64| {
            bind.addend
                .map(|addend| address.wrapping_add(addend as u64) & mask)
        };
        let kind = match (record.applies, bind.bound) {
            (Applies::ThreadLocal, _) => WriteKind::NotAnAddress,
            (Applies::GotRelative, bound) => (self.slots.get(&bound))
                .and_then(|(slot, _)| plus(*slot))
                .map_or(WriteKind::Unknown, WriteKind::Absolute),
            (Applies::Symbol | Applies::SymbolPlusAddend, Bound::Import(..))
                if bind.addend == Some(0) =>
            {
                WriteKind::Import {
                    symbol: bind.name(),
                    library: None,
                }
            }
            (
                Applies::PcRelative | Applies::PltRelative | Applies::Field,
                Bound::Import(table, index),
            ) => (self.stubs.get(&(table, index)))
                .and_then(|(stub, _)| plus(*stub))
                .map_or(WriteKind::Unknown, WriteKind::Absolute),
            (
                Applies::Symbol
                | Applies::SymbolPlusAddend
                | Applies::PcRelative
                | Applies::PltRelative
                | Applies::Field,
                Bound::At { address, weak },
            ) => match (plus(address), weak) {
                (Some(value), false) => WriteKind::Absolute(value),
                (Some(value), true) => WriteKind::Preemptible {
                    symbol: bind.name(),
                    default: value,
                },
                (None, _) => WriteKind::Unknown,
            },
            _ => WriteKind::Unknown,
        };
        // An object's bytes hold no value a link has not written, so a write it states no value for is no word the file holds.
        let encoding = match kind {
            WriteKind::Unknown => Encoding::Typed,
            _ => record.encoding,
        };
        LoaderWrite {
            place: record.vaddr,
            width: record.width,
            kind,
            encoding,
        }
    }
}

/// One record of an object, with what its symbol is.
struct Bind {
    record: Relocation,
    bound: Bound,
    /// The addend the record states, or for `REL` the one its place holds.
    addend: Option<i64>,
    loaded: bool,
}

impl Bind {
    fn name(&self) -> String {
        let symbol = self.record.symbol.as_ref();
        symbol.map_or_else(String::new, |symbol| symbol.name.to_string())
    }
}

impl<'f, 'data, E: FileHeader, R: object::ReadRef<'data>> Elf<'f, 'data, E, R> {
    /// Every record of every relocation section, the stub and slot each import and table read needs, and what each writes.
    fn linked(&self, placing: &Placing<'_>, linkage: u64) -> Linked {
        let mut binds = Vec::new();
        for header in self.file.elf_section_table().iter() {
            let form = match header.sh_type(self.endian) {
                elf::SHT_REL => Form::Rel,
                elf::SHT_RELA => Form::Rela,
                elf::SHT_CREL => Form::Crel,
                _ => continue,
            };
            self.bind(header, form, placing, &mut binds);
        }
        let mask = match self.pointer {
            4 => u64::from(u32::MAX),
            _ => u64::MAX,
        };
        let linkage = Linkage::of(&binds, linkage, self.pointer);
        let mut writes = linkage.slot_writes(self.pointer);
        let mut targets = Vec::new();
        let mut relocations = Vec::with_capacity(binds.len());
        for bind in binds {
            if let (Bound::At { address, .. }, Some(addend)) = (bind.bound, bind.addend) {
                let target = address.wrapping_add(addend as u64) & mask;
                targets.push((bind.record.vaddr, target));
            }
            writes.extend(bind.loaded.then(|| linkage.written(&bind, mask)));
            relocations.push(bind.record);
        }
        targets.sort_unstable();
        Linked {
            relocations,
            writes,
            stubs: linkage.stated(self.pointer),
            targets,
        }
    }

    /// Each record of one relocation section, with what its symbol is.
    fn bind(
        &self,
        header: &E::SectionHeader,
        form: Form,
        placing: &Placing<'_>,
        binds: &mut Vec<Bind>,
    ) {
        let endian = self.endian;
        let table = self.file.elf_section_table();
        let machine = self.file.elf_header().e_machine(endian);
        let target = object::SectionIndex(header.sh_info(endian) as usize);
        let (Ok(into), Some(base)) = (table.section(target), (placing.section)(target)) else {
            return;
        };
        let symbols = object::SectionIndex(header.sh_link(endian) as usize);
        let view = View {
            offset: header.sh_offset(endian).into(),
            size: header.sh_size(endian).into(),
            form,
            phase: 0,
            symbols: Symbols::Section(symbols),
        };
        let loaded = into.sh_flags(endian).contains(elf::SHF_ALLOC);
        let held = (into.sh_type(endian) != elf::SHT_NOBITS).then(|| into.sh_offset(endian).into());
        // Parsed once per relocation section: parsing looks its extended indices up across the section table.
        let parsed = table
            .symbol_table_by_index(endian, self.file.data(), symbols)
            .ok();
        let symbols = (symbols.0, parsed.as_ref());
        for (record, offset, ntype, index, addend) in self.encoded(&view) {
            let Some((applies, width, encoding)) = applies(machine, ntype, self.pointer) else {
                continue;
            };
            // A type this reader does not decode holds no value its bytes state.
            let encoding = match applies {
                Applies::Unknown => Encoding::Typed,
                _ => encoding,
            };
            let (symbol, bound) = self.bound(symbols, index, placing);
            let implicit = || {
                let word = held?.checked_add(offset)?;
                (encoding != Encoding::Typed)
                    .then(|| self.implicit(word, width))
                    .flatten()
            };
            binds.push(Bind {
                record: Relocation {
                    vaddr: base.wrapping_add(offset),
                    record,
                    ntype: ntype.0,
                    width,
                    addend,
                    symbol: symbol.map(Box::new),
                    applies,
                    encoding,
                },
                bound,
                addend: addend.or_else(implicit),
                loaded,
            });
        }
    }

    /// What one symbol of an object is: its name as a record spells it, and where it is once placed.
    fn bound(
        &self,
        (symbols, table): (usize, Option<&object::read::elf::SymbolTable<'data, E, R>>),
        index: u32,
        placing: &Placing<'_>,
    ) -> (Option<RelocationSymbol>, Bound) {
        let endian = self.endian;
        let sections = self.file.elf_section_table();
        // Symbol index zero is the value zero: the addend alone.
        let absolute = Bound::At {
            address: 0,
            weak: false,
        };
        if index == 0 {
            return (None, absolute);
        }
        let Some(table) = table else {
            return (None, Bound::Unplaced);
        };
        let at_index = object::SymbolIndex(index as usize);
        let Ok(symbol) = table.symbol(at_index) else {
            return (None, Bound::Unplaced);
        };
        let section = table
            .symbol_section(endian, symbol, at_index)
            .ok()
            .flatten();
        let name = match (symbol.st_type(), section) {
            // A section's symbol is spelled by the section's name.
            (elf::STT_SECTION, Some(section)) => sections
                .section(section)
                .ok()
                .and_then(|header| sections.section_name(endian, header).ok()),
            _ => table.symbol_name(endian, symbol).ok(),
        };
        let name = name
            .and_then(|name| core::str::from_utf8(name).ok())
            .unwrap_or_default();
        let weak = symbol.st_bind() == elf::STB_WEAK;
        let value: u64 = symbol.st_value(endian).into();
        let bound = if symbol.is_undefined(endian) {
            Bound::Import(symbols, index)
        } else if let Some(address) = (placing.common)(index) {
            // A common symbol, allocated as the static linker would, at the size and alignment it states.
            Bound::At { address, weak }
        } else if symbol.is_common(endian) {
            Bound::Unplaced
        } else if symbol.is_absolute(endian) {
            Bound::At {
                address: value,
                weak,
            }
        } else {
            match section.and_then(placing.section) {
                Some(base) => Bound::At {
                    address: base.wrapping_add(value),
                    weak,
                },
                None => Bound::Unplaced,
            }
        };
        let defined = match bound {
            Bound::At { address, .. } => Some(address),
            _ => None,
        };
        let stated = RelocationSymbol {
            name: name.into(),
            defined,
            size: symbol.st_size(endian).into(),
            binding: binding(symbol.st_bind(), self.file.elf_header().e_ident().os_abi),
            visibility: visibility(symbol.st_visibility()),
        };
        (Some(stated), bound)
    }

    /// The addend a `REL` record leaves in the bytes it relocates: the word there, sign-extended from its width.
    fn implicit(&self, offset: u64, width: u64) -> Option<i64> {
        let bytes = self.bytes(offset, width);
        if bytes.len() as u64 != width || !(1..=8).contains(&width) {
            return None;
        }
        let little = self.file.is_little_endian();
        let word = bytes.iter().enumerate().fold(0u64, |value, (at, byte)| {
            let shift = match little {
                true => 8 * at,
                false => 8 * (bytes.len() - 1 - at),
            };
            value | u64::from(*byte) << shift
        });
        let unused = 64 - 8 * width as u32;
        Some(((word << unused) as i64) >> unused)
    }
}

/// An ELF image the static linker finished: linked, with no `PT_DYNAMIC` for a loader to bind it.
pub(crate) fn is_static_image(file: &object::File<'_>) -> bool {
    fn none<'data, E: FileHeader, R: object::ReadRef<'data>>(file: &ElfFile<'data, E, R>) -> bool {
        let endian = file.endian();
        let mut headers = file.elf_program_headers().iter();
        !headers.any(|header| header.p_type(endian) == elf::PT_DYNAMIC)
    }
    match file {
        _ if file.kind() == object::ObjectKind::Relocatable => false,
        object::File::Elf32(elf) => none(elf),
        object::File::Elf64(elf) => none(elf),
        _ => false,
    }
}

/// The dynamic table's entries, read through `PT_DYNAMIC` to the terminating one.
/// The functions the dynamic table names for the loader to call itself, `DT_INIT` and `DT_FINI`,
/// each with where the table states it: its entry's value field.
pub(crate) fn hooks(file: &object::File<'_>) -> Vec<(EntryKind, u64, StatedAt)> {
    match file {
        object::File::Elf32(elf) => hooks_of(elf),
        object::File::Elf64(elf) => hooks_of(elf),
        _ => Vec::new(),
    }
}

fn hooks_of<'data, E: FileHeader, R: object::ReadRef<'data>>(
    file: &ElfFile<'data, E, R>,
) -> Vec<(EntryKind, u64, StatedAt)> {
    let endian = file.endian();
    let mut headers = file.elf_program_headers().iter();
    let Some(header) = headers.find(|header| header.p_type(endian) == elf::PT_DYNAMIC) else {
        return Vec::new();
    };
    let (offset, vaddr): (u64, u64) = (
        header.p_offset(endian).into(),
        header.p_vaddr(endian).into(),
    );
    // `d_val` is the second of an entry's two words.
    let size = std::mem::size_of::<E::Dyn>() as u64;
    let entries = dynamic_entries(file).unwrap_or_default();
    let named = entries.iter().enumerate().filter_map(|(at, entry)| {
        let kind = match entry.tag(endian) {
            elf::DT_INIT => EntryKind::InitHook,
            elf::DT_FINI => EntryKind::FiniHook,
            _ => return None,
        };
        let place = at as u64 * size + size / 2;
        let stated = StatedAt {
            offset: offset + place,
            vaddr: Some(vaddr + place),
        };
        Some((kind, entry.d_val(endian).into(), stated))
    });
    named.collect()
}

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
        .position(|entry| entry.d_tag(endian) == elf::DT_NULL);
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

/// A symbol's binding; 10 is `STB_GNU_UNIQUE` only under the GNU ABI, as readelf reads it.
pub(crate) fn binding(bind: elf::SymbolBind, os_abi: elf::OsAbi) -> Binding {
    match bind {
        elf::STB_LOCAL => Binding::Local,
        elf::STB_GLOBAL => Binding::Global,
        elf::STB_WEAK => Binding::Weak,
        elf::STB_GNU_UNIQUE if matches!(os_abi, elf::ELFOSABI_NONE | elf::ELFOSABI_GNU) => {
            Binding::Unique
        }
        other => Binding::Other(other.0),
    }
}

fn visibility(visibility: elf::SymbolVisibility) -> Visibility {
    match visibility {
        elf::STV_INTERNAL => Visibility::Internal,
        elf::STV_HIDDEN => Visibility::Hidden,
        elf::STV_PROTECTED => Visibility::Protected,
        _ => Visibility::Default,
    }
}

/// The x86-64 psABI's large common symbol (`.largecomm`), which `object` reads as no section.
const SHN_X86_64_LCOMMON: elf::SymbolSection = elf::SymbolSection(0xff02);

/// Whether an object's symbol is common, its value an alignment: `SHN_COMMON`, or x86-64's large common.
pub(crate) fn common(file: &object::File<'_>, symbol: &object::read::Symbol<'_, '_>) -> bool {
    fn large<'data, E: FileHeader, R: object::ReadRef<'data>>(
        file: &ElfFile<'data, E, R>,
        index: object::SymbolIndex,
    ) -> bool {
        let endian = file.endian();
        file.elf_header().e_machine(endian) == elf::EM_X86_64
            && (file.elf_symbol_table().symbol(index))
                .is_ok_and(|symbol| symbol.st_shndx(endian) == SHN_X86_64_LCOMMON)
    }
    match (symbol.section(), file) {
        (object::SymbolSection::Common, _) => true,
        (object::SymbolSection::Unknown, object::File::Elf32(elf)) => large(elf, symbol.index()),
        (object::SymbolSection::Unknown, object::File::Elf64(elf)) => large(elf, symbol.index()),
        _ => false,
    }
}

/// The machine's type number for a relative relocation, which a `RELR` word applies.
fn relative_type(machine: elf::Machine) -> Option<elf::RelocationType> {
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

/// What a relocation type computes, how many bytes it writes and how they hold it, as the machine's psABI states it; `None` for a type that writes nothing.
///
/// A type this table does not name is still a write, so it is kept, at the
/// width of a pointer, with its computation unknown.
fn applies(
    machine: elf::Machine,
    ntype: elf::RelocationType,
    pointer: u64,
) -> Option<(Applies, u64, Encoding)> {
    if ntype.0 == 0 {
        return None;
    }
    match machine {
        elf::EM_X86_64 => x86_64(ntype, pointer),
        elf::EM_386 => i386(ntype),
        elf::EM_AARCH64 => aarch64(ntype, pointer),
        elf::EM_ARM => arm(ntype),
        elf::EM_RISCV => riscv(ntype, pointer),
        _ => Some((Applies::Unknown, pointer, Encoding::Word)),
    }
}

/// The x86-64 psABI's types.
fn x86_64(ntype: elf::RelocationType, pointer: u64) -> Option<(Applies, u64, Encoding)> {
    use Applies as A;
    use Encoding::{FromPlace, Typed, Word};
    Some(match ntype {
        elf::R_X86_64_64 => (A::SymbolPlusAddend, 8, Word),
        elf::R_X86_64_32 | elf::R_X86_64_32S => (A::SymbolPlusAddend, 4, Word),
        elf::R_X86_64_16 => (A::SymbolPlusAddend, 2, Word),
        elf::R_X86_64_8 => (A::SymbolPlusAddend, 1, Word),
        elf::R_X86_64_PC64 => (A::PcRelative, 8, FromPlace),
        elf::R_X86_64_PC32 => (A::PcRelative, 4, FromPlace),
        elf::R_X86_64_PC16 => (A::PcRelative, 2, FromPlace),
        elf::R_X86_64_PC8 => (A::PcRelative, 1, FromPlace),
        elf::R_X86_64_PLT32 => (A::PltRelative, 4, FromPlace),
        elf::R_X86_64_GOTPCREL
        | elf::R_X86_64_GOTPCRELX
        | elf::R_X86_64_REX_GOTPCRELX
        | elf::R_X86_64_CODE_4_GOTPCRELX
        | elf::R_X86_64_CODE_5_GOTPCRELX
        | elf::R_X86_64_CODE_6_GOTPCRELX => (A::GotRelative, 4, FromPlace),
        elf::R_X86_64_GOTPCREL64 => (A::GotRelative, 8, FromPlace),
        elf::R_X86_64_COPY => (A::Copy, pointer, Word),
        elf::R_X86_64_GLOB_DAT | elf::R_X86_64_JUMP_SLOT => (A::Symbol, pointer, Word),
        elf::R_X86_64_RELATIVE | elf::R_X86_64_RELATIVE64 => (A::Relative, pointer, Word),
        elf::R_X86_64_IRELATIVE => (A::Resolver, pointer, Word),
        elf::R_X86_64_DTPMOD64 | elf::R_X86_64_DTPOFF64 | elf::R_X86_64_TPOFF64 => {
            (A::ThreadLocal, 8, Word)
        }
        elf::R_X86_64_TLSDESC => (A::ThreadLocal, 16, Word),
        // Offsets from the thread pointer or into a module's block, in an instruction.
        elf::R_X86_64_TLSGD
        | elf::R_X86_64_TLSLD
        | elf::R_X86_64_DTPOFF32
        | elf::R_X86_64_GOTTPOFF
        | elf::R_X86_64_TPOFF32
        | elf::R_X86_64_GOTPC32_TLSDESC
        | elf::R_X86_64_CODE_4_GOTTPOFF
        | elf::R_X86_64_CODE_4_GOTPC32_TLSDESC => (A::ThreadLocal, 4, Typed),
        // A marker on the call through a descriptor: it writes nothing.
        elf::R_X86_64_TLSDESC_CALL => return None,
        _ => (A::Unknown, pointer, Word),
    })
}

/// The i386 psABI's types.
fn i386(ntype: elf::RelocationType) -> Option<(Applies, u64, Encoding)> {
    use Applies as A;
    use Encoding::{FromPlace, Typed, Word};
    Some(match ntype {
        elf::R_386_32 => (A::SymbolPlusAddend, 4, Word),
        elf::R_386_16 => (A::SymbolPlusAddend, 2, Word),
        elf::R_386_8 => (A::SymbolPlusAddend, 1, Word),
        elf::R_386_PC32 => (A::PcRelative, 4, FromPlace),
        elf::R_386_PC16 => (A::PcRelative, 2, FromPlace),
        elf::R_386_PC8 => (A::PcRelative, 1, FromPlace),
        elf::R_386_PLT32 => (A::PltRelative, 4, FromPlace),
        // Offsets from the global offset table, which no address states.
        elf::R_386_GOT32 | elf::R_386_GOT32X | elf::R_386_GOTOFF | elf::R_386_GOTPC => {
            (A::Unknown, 4, Typed)
        }
        elf::R_386_COPY => (A::Copy, 4, Word),
        elf::R_386_GLOB_DAT | elf::R_386_JMP_SLOT => (A::Symbol, 4, Word),
        elf::R_386_RELATIVE => (A::Relative, 4, Word),
        elf::R_386_IRELATIVE => (A::Resolver, 4, Word),
        elf::R_386_TLS_TPOFF
        | elf::R_386_TLS_DTPMOD32
        | elf::R_386_TLS_DTPOFF32
        | elf::R_386_TLS_TPOFF32 => (A::ThreadLocal, 4, Word),
        elf::R_386_TLS_DESC => (A::ThreadLocal, 8, Word),
        _ => (A::Unknown, 4, Word),
    })
}

/// The AArch64 ELF ABI's types.
fn aarch64(ntype: elf::RelocationType, pointer: u64) -> Option<(Applies, u64, Encoding)> {
    use Applies as A;
    use Encoding::{FromPlace, Typed, Word};
    Some(match ntype {
        elf::R_AARCH64_ABS64 => (A::SymbolPlusAddend, 8, Word),
        elf::R_AARCH64_ABS32 => (A::SymbolPlusAddend, 4, Word),
        elf::R_AARCH64_ABS16 => (A::SymbolPlusAddend, 2, Word),
        elf::R_AARCH64_PREL64 => (A::PcRelative, 8, FromPlace),
        elf::R_AARCH64_PREL32 => (A::PcRelative, 4, FromPlace),
        elf::R_AARCH64_PREL16 => (A::PcRelative, 2, FromPlace),
        elf::R_AARCH64_CALL26
        | elf::R_AARCH64_JUMP26
        | elf::R_AARCH64_CONDBR19
        | elf::R_AARCH64_TSTBR14
        | elf::R_AARCH64_LD_PREL_LO19
        | elf::R_AARCH64_ADR_PREL_LO21
        | elf::R_AARCH64_ADR_PREL_PG_HI21
        | elf::R_AARCH64_ADR_PREL_PG_HI21_NC
        | elf::R_AARCH64_ADD_ABS_LO12_NC
        | elf::R_AARCH64_LDST8_ABS_LO12_NC
        | elf::R_AARCH64_LDST16_ABS_LO12_NC
        | elf::R_AARCH64_LDST32_ABS_LO12_NC
        | elf::R_AARCH64_LDST64_ABS_LO12_NC
        | elf::R_AARCH64_LDST128_ABS_LO12_NC
        | elf::R_AARCH64_MOVW_UABS_G0
        | elf::R_AARCH64_MOVW_UABS_G0_NC
        | elf::R_AARCH64_MOVW_UABS_G1
        | elf::R_AARCH64_MOVW_UABS_G1_NC
        | elf::R_AARCH64_MOVW_UABS_G2
        | elf::R_AARCH64_MOVW_UABS_G2_NC
        | elf::R_AARCH64_MOVW_UABS_G3 => (A::Field, 4, Typed),
        elf::R_AARCH64_ADR_GOT_PAGE
        | elf::R_AARCH64_LD64_GOT_LO12_NC
        | elf::R_AARCH64_LD64_GOTPAGE_LO15 => (A::GotRelative, 4, Typed),
        elf::R_AARCH64_COPY => (A::Copy, 8, Word),
        // AArch64 adds the addend to both, which ELF gABI leaves to the psABI.
        elf::R_AARCH64_GLOB_DAT | elf::R_AARCH64_JUMP_SLOT => (A::SymbolPlusAddend, 8, Word),
        elf::R_AARCH64_RELATIVE => (A::Relative, 8, Word),
        elf::R_AARCH64_IRELATIVE => (A::Resolver, 8, Word),
        elf::R_AARCH64_TLS_DTPMOD | elf::R_AARCH64_TLS_DTPREL | elf::R_AARCH64_TLS_TPREL => {
            (A::ThreadLocal, 8, Word)
        }
        elf::R_AARCH64_TLSDESC => (A::ThreadLocal, 16, Word),
        _ => (A::Unknown, pointer, Word),
    })
}

/// The Arm ELF ABI's types.
fn arm(ntype: elf::RelocationType) -> Option<(Applies, u64, Encoding)> {
    use Applies as A;
    use Encoding::{FromPlace, Typed, Word};
    Some(match ntype {
        elf::R_ARM_ABS32 | elf::R_ARM_TARGET1 => (A::SymbolPlusAddend, 4, Word),
        elf::R_ARM_REL32 => (A::PcRelative, 4, FromPlace),
        elf::R_ARM_CALL
        | elf::R_ARM_JUMP24
        | elf::R_ARM_PC24
        | elf::R_ARM_THM_PC22
        | elf::R_ARM_THM_JUMP24
        | elf::R_ARM_THM_JUMP19
        | elf::R_ARM_PREL31
        | elf::R_ARM_MOVW_ABS_NC
        | elf::R_ARM_MOVT_ABS
        | elf::R_ARM_MOVW_PREL_NC
        | elf::R_ARM_MOVT_PREL
        | elf::R_ARM_THM_MOVW_ABS_NC
        | elf::R_ARM_THM_MOVT_ABS
        | elf::R_ARM_THM_MOVW_PREL_NC
        | elf::R_ARM_THM_MOVT_PREL => (A::Field, 4, Typed),
        elf::R_ARM_THM_PC11 | elf::R_ARM_THM_PC9 => (A::Field, 2, Typed),
        elf::R_ARM_GOT_PREL => (A::GotRelative, 4, FromPlace),
        // A marker that `bx` may be rewritten for ARMv4: it states no value.
        elf::R_ARM_V4BX => return None,
        elf::R_ARM_COPY => (A::Copy, 4, Word),
        elf::R_ARM_GLOB_DAT | elf::R_ARM_JUMP_SLOT => (A::Symbol, 4, Word),
        elf::R_ARM_RELATIVE => (A::Relative, 4, Word),
        elf::R_ARM_IRELATIVE => (A::Resolver, 4, Word),
        elf::R_ARM_TLS_DTPMOD32 | elf::R_ARM_TLS_DTPOFF32 | elf::R_ARM_TLS_TPOFF32 => {
            (A::ThreadLocal, 4, Word)
        }
        elf::R_ARM_TLS_DESC => (A::ThreadLocal, 8, Word),
        _ => (A::Unknown, 4, Word),
    })
}

/// The RISC-V psABI's types.
fn riscv(ntype: elf::RelocationType, pointer: u64) -> Option<(Applies, u64, Encoding)> {
    use Applies as A;
    use Encoding::Word;
    Some(match ntype {
        elf::R_RISCV_32 => (A::SymbolPlusAddend, 4, Word),
        elf::R_RISCV_64 => (A::SymbolPlusAddend, 8, Word),
        elf::R_RISCV_COPY => (A::Copy, pointer, Word),
        elf::R_RISCV_JUMP_SLOT => (A::Symbol, pointer, Word),
        elf::R_RISCV_RELATIVE => (A::Relative, pointer, Word),
        elf::R_RISCV_IRELATIVE => (A::Resolver, pointer, Word),
        elf::R_RISCV_TLS_DTPMOD32 | elf::R_RISCV_TLS_DTPREL32 | elf::R_RISCV_TLS_TPREL32 => {
            (A::ThreadLocal, 4, Word)
        }
        elf::R_RISCV_TLS_DTPMOD64 | elf::R_RISCV_TLS_DTPREL64 | elf::R_RISCV_TLS_TPREL64 => {
            (A::ThreadLocal, 8, Word)
        }
        _ => (A::Unknown, pointer, Word),
    })
}

/// Each entry of an object's compact stream, as `SHT_CREL` encodes it; the stream's own offset and each entry's position are its record.
fn crel(bytes: &[u8], table: u64) -> Vec<Encoded> {
    let Ok(entries) = object::read::elf::CrelIterator::new(bytes) else {
        return Vec::new();
    };
    let rela = entries.is_rela();
    let entry = |(index, entry): (usize, object::read::elf::Crel)| {
        let record = Record {
            table,
            index: index as u64,
        };
        let addend = rela.then_some(entry.r_addend);
        (record, entry.r_offset, entry.r_type, entry.r_sym, addend)
    };
    entries
        .map_while(Result::ok)
        .enumerate()
        .map(entry)
        .collect()
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
