//! What an ELF states about the versions it binds: `.gnu.version_r`'s needs, and the version
//! `.gnu.version` gives each dynamic symbol (doc/adr-call-boundary.md, "What only the ABI states").

use std::sync::Arc;

use object::read::elf::{ElfFile, FileHeader};

use crate::{SymbolVersion, VersionNeed};

/// The needs in file order, and each dynamic symbol's version by its `.dynsym` index.
#[derive(Debug, Default)]
pub(crate) struct Versions {
    pub(crate) needs: Vec<VersionNeed>,
    pub(crate) symbols: Vec<Option<SymbolVersion>>,
}

impl Versions {
    pub(crate) fn of_symbol(&self, dynamic: usize) -> Option<SymbolVersion> {
        self.symbols.get(dynamic).cloned().flatten()
    }
}

pub(crate) fn read(file: &object::File<'_>) -> Versions {
    match file {
        object::File::Elf32(elf) => of(elf).unwrap_or_default(),
        object::File::Elf64(elf) => of(elf).unwrap_or_default(),
        _ => Versions::default(),
    }
}

/// One pass over the needs and one over `.gnu.version`; a malformed table states nothing.
fn of<'data, E: FileHeader>(file: &ElfFile<'data, E>) -> Option<Versions> {
    let (endian, data) = (file.endian(), file.data());
    let sections = file.elf_section_table();
    let text = |bytes: &[u8]| Arc::<str>::from(String::from_utf8_lossy(bytes));
    let mut needs = Vec::new();
    if let Ok(Some((mut entries, link))) = sections.gnu_verneed(endian, data) {
        let strings = sections.strings(endian, data, link).ok()?;
        while let Ok(Some((need, mut versions))) = entries.next() {
            let library = text(need.file(endian, strings).ok()?);
            let mut names = Vec::new();
            while let Ok(Some(version)) = versions.next() {
                names.push(text(version.name(endian, strings).ok()?));
            }
            needs.push(VersionNeed {
                library,
                versions: names,
            });
        }
    }
    let table = sections.versions(endian, data).ok().flatten();
    let symbols = match (&table, file.elf_dynamic_symbol_table().is_empty()) {
        (Some(table), false) => (0..file.elf_dynamic_symbol_table().len())
            .map(|index| {
                let versym = table.version_index(endian, object::read::SymbolIndex(index));
                let version = table.version(versym.index()).ok().flatten()?;
                let name = text(version.name());
                Some(match version.file() {
                    Some(library) => SymbolVersion::Needed {
                        library: text(library),
                        version: name,
                    },
                    None => SymbolVersion::Defined { version: name },
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(Versions { needs, symbols })
}
