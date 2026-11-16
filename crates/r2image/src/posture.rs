//! How an image is linked and protected: one bounded pass over its headers and dynamic section (D18).

use object::elf;
use object::read::elf::{Dyn as _, ElfFile, FileHeader, ProgramHeader as _};

use crate::{LoadBase, Posture, Relro};

/// The posture the container states; an unstated one for every format but ELF.
pub(crate) fn read(file: &object::File<'_>) -> Posture {
    match file {
        object::File::Elf32(elf) => of(elf),
        object::File::Elf64(elf) => of(elf),
        _ => Posture::default(),
    }
}

fn of<'data, E: FileHeader, R: object::ReadRef<'data>>(file: &ElfFile<'data, E, R>) -> Posture {
    let (endian, data) = (file.endian(), file.data());
    let mut posture = Posture {
        statically_linked: true,
        ..Posture::default()
    };
    let (mut relro, mut dynamic, mut stated_dynamic) = (false, None, false);
    for header in file.elf_program_headers() {
        match header.p_type(endian) {
            elf::PT_GNU_STACK if posture.nx.is_none() => {
                posture.nx = Some(!header.p_flags(endian).contains(elf::PF_X));
            }
            elf::PT_GNU_RELRO => relro = true,
            elf::PT_INTERP if posture.interpreter.is_none() => {
                posture.statically_linked = false;
                let path = header.interpreter(endian, data).ok().flatten();
                let path = path.map(<[u8]>::to_vec).unwrap_or_default();
                posture.interpreter = Some(String::from_utf8_lossy(&path).into_owned());
            }
            elf::PT_DYNAMIC => {
                posture.statically_linked = false;
                stated_dynamic = true;
                if dynamic.is_none() {
                    dynamic = header.dynamic(endian, data).ok().flatten();
                }
            }
            _ => {}
        }
    }
    let value = |entry: &E::Dyn| -> u64 { entry.d_val(endian).into() };
    let stated = |entry: &&E::Dyn| entry.tag(endian) != elf::DT_NULL;
    let entries = || dynamic.into_iter().flatten().take_while(stated);
    // The loader binds everything at load for any of the three statements, reading to `DT_NULL`.
    let bind_now = entries().any(|entry| match entry.tag(endian) {
        elf::DT_BIND_NOW => true,
        elf::DT_FLAGS => elf::DynamicFlags(value(entry)).contains(elf::DF_BIND_NOW),
        elf::DT_FLAGS_1 => elf::DynamicFlags1(value(entry)).contains(elf::DF_1_NOW),
        _ => false,
    });
    // gABI `DT_TEXTREL`: "one or more relocation entries might request modifications to a
    // non-writable segment"; an unreadable dynamic section states nothing either way.
    let text_relocated = (stated_dynamic && dynamic.is_none())
        || entries().any(|entry| match entry.tag(endian) {
            elf::DT_TEXTREL => true,
            elf::DT_FLAGS => elf::DynamicFlags(value(entry)).contains(elf::DF_TEXTREL),
            _ => false,
        });
    posture.load = match file.elf_header().e_type(endian) {
        elf::ET_EXEC if !text_relocated => LoadBase::Linked,
        elf::ET_DYN => LoadBase::Slid,
        _ => LoadBase::Unstated,
    };
    posture.relro = Some(match (relro, bind_now) {
        (false, _) => Relro::No,
        (true, false) => Relro::Partial,
        (true, true) => Relro::Full,
    });
    posture
}
