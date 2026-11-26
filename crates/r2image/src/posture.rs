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
    let mut posture = Posture::default();
    let (mut relro, mut dynamic, mut stated_dynamic) = (false, None, false);
    for header in file.elf_program_headers() {
        match header.p_type(endian) {
            elf::PT_GNU_STACK if posture.nx.is_none() => {
                posture.nx = Some(!header.p_flags(endian).contains(elf::PF_X));
            }
            elf::PT_GNU_RELRO => relro = true,
            elf::PT_INTERP if posture.interpreter.is_none() => {
                let path = header.interpreter(endian, data).ok().flatten();
                let path = path.map(<[u8]>::to_vec).unwrap_or_default();
                posture.interpreter = Some(String::from_utf8_lossy(&path).into_owned());
            }
            elf::PT_DYNAMIC => {
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
    posture.statically_linked = linked_alone(
        posture.interpreter.is_some(),
        stated_dynamic.then(|| dynamic.is_some()),
        entries().map(|entry| (entry.tag(endian), value(entry))),
    );
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

/// Whether only the image's own start-up builds it (ROADMAP D663); `dynamic` is `None` with no
/// `PT_DYNAMIC`, `Some(false)` where its table is unreadable.
fn linked_alone(
    interpreter: bool,
    dynamic: Option<bool>,
    mut entries: impl Iterator<Item = (elf::DynamicTag, u64)>,
) -> Option<bool> {
    let (mut needs, mut pie) = (false, false);
    for (tag, value) in entries.by_ref() {
        match tag {
            elf::DT_NEEDED | elf::DT_SONAME => needs = true,
            elf::DT_FLAGS_1 => pie |= elf::DynamicFlags1(value).contains(elf::DF_1_PIE),
            _ => {}
        }
    }
    match dynamic {
        _ if interpreter || needs => Some(false),
        None => Some(true),
        Some(true) if pie => Some(true),
        _ => None,
    }
}
