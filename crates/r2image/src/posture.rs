//! How an image is linked and protected: one bounded pass over its headers and dynamic section (D18).

use object::elf;
use object::read::elf::{Dyn as _, ElfFile, FileHeader, ProgramHeader as _};

use crate::{Posture, Relro};

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
        pic: file.elf_header().e_type(endian) == elf::ET_DYN,
        statically_linked: true,
        ..Posture::default()
    };
    let (mut relro, mut dynamic) = (false, None);
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
                if dynamic.is_none() {
                    dynamic = header.dynamic(endian, data).ok().flatten();
                }
            }
            _ => {}
        }
    }
    // The loader binds everything at load for any of the three statements, reading to `DT_NULL`.
    let bind_now = dynamic.is_some_and(|entries| {
        let value = |entry: &E::Dyn| -> u64 { entry.d_val(endian).into() };
        entries
            .iter()
            .take_while(|entry| entry.tag(endian) != elf::DT_NULL)
            .any(|entry| match entry.tag(endian) {
                elf::DT_BIND_NOW => true,
                elf::DT_FLAGS => elf::DynamicFlags(value(entry)).contains(elf::DF_BIND_NOW),
                elf::DT_FLAGS_1 => elf::DynamicFlags1(value(entry)).contains(elf::DF_1_NOW),
                _ => false,
            })
    });
    posture.relro = Some(match (relro, bind_now) {
        (false, _) => Relro::No,
        (true, false) => Relro::Partial,
        (true, true) => Relro::Full,
    });
    posture
}
