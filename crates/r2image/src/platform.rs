//! What an ELF states about the C library its program runs against.
//!
//! Three statements, none of them a name the program chose: the dynamic
//! linker `PT_INTERP` asks for, the notes a C library's start files leave in
//! every program linked against it, and the header's OS ABI byte. Each is
//! stated as the evidence it is; which platform's declarations apply is the
//! engine's to decide from it. Mach-O states its platform by being Mach-O and
//! carries none of these.

use std::collections::BTreeSet;

use object::Endian as _;
use object::elf;
use object::read::elf::{ElfFile, FileHeader, ProgramHeader};

use crate::{Libc, PlatformEvidence};

/// Bionic's identification note: `Android`, type 1, the API level it targets.
const NT_ANDROID_TYPE_IDENT: u32 = 1;

/// Everything this file states about its C library.
pub(crate) fn evidence(file: &object::File<'_>) -> BTreeSet<PlatformEvidence> {
    match file {
        object::File::Elf32(elf) => of(elf),
        object::File::Elf64(elf) => of(elf),
        _ => BTreeSet::new(),
    }
}

/// One pass over the program headers, reading `PT_INTERP` and each `PT_NOTE`.
fn of<'data, E: FileHeader, R: object::ReadRef<'data>>(
    file: &ElfFile<'data, E, R>,
) -> BTreeSet<PlatformEvidence> {
    let (endian, data) = (file.endian(), file.data());
    let mut found = BTreeSet::new();
    let os_abi = file.elf_header().e_ident().os_abi;
    if os_abi != elf::ELFOSABI_NONE {
        found.insert(PlatformEvidence::OsAbi(os_abi));
    }
    for header in file.elf_program_headers() {
        if let Ok(Some(path)) = header.interpreter(endian, data)
            && let Some(libc) = interpreter(path)
        {
            found.insert(PlatformEvidence::Interpreter(libc));
        }
        let Ok(Some(mut notes)) = header.notes(endian, data) else {
            continue;
        };
        while let Ok(Some(note)) = notes.next() {
            let libc = match (note.name(), note.n_type(endian)) {
                (b"Android", NT_ANDROID_TYPE_IDENT) => Some(Libc::Bionic),
                // glibc's start files state the kernel ABI its build targets;
                // the first word is the OS, and zero is Linux.
                (elf::ELF_NOTE_GNU, elf::NT_GNU_ABI_TAG) => note
                    .desc()
                    .first_chunk::<4>()
                    .map(|os| endian.read_u32_bytes(*os))
                    .filter(|os| *os == elf::ELF_NOTE_OS_LINUX)
                    .map(|_| Libc::Glibc),
                _ => None,
            };
            if let Some(libc) = libc {
                found.insert(PlatformEvidence::Note(libc));
            }
        }
    }
    found
}

/// The C library whose dynamic linker `path` is, by the file it names.
///
/// Each library installs its linker under a name only it uses: glibc's is
/// `ld-linux*.so.*` (`ld64.so.*` on the 64-bit POWER and s390 ABIs), musl's
/// `ld-musl-<arch>.so.1`, bionic's `linker` or `linker64`. A path naming none
/// of them -- MIPS glibc's `ld.so.1` is also uClibc's -- is evidence of none.
fn interpreter(path: &[u8]) -> Option<Libc> {
    let file = path.rsplit(|byte| *byte == b'/').next()?;
    if file.starts_with(b"ld-linux") || file.starts_with(b"ld64.so.") {
        Some(Libc::Glibc)
    } else if file.starts_with(b"ld-musl-") {
        Some(Libc::Musl)
    } else if matches!(file, b"linker" | b"linker64") {
        Some(Libc::Bionic)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_librarys_dynamic_linker_is_known_by_the_file_it_names() {
        for (path, libc) in [
            (&b"/lib64/ld-linux-x86-64.so.2"[..], Some(Libc::Glibc)),
            (b"/lib/ld-linux-aarch64.so.1", Some(Libc::Glibc)),
            (b"/lib/ld-linux-riscv64-lp64d.so.1", Some(Libc::Glibc)),
            (b"/lib64/ld64.so.2", Some(Libc::Glibc)),
            (b"/lib/ld-musl-x86_64.so.1", Some(Libc::Musl)),
            (b"/system/bin/linker64", Some(Libc::Bionic)),
            (b"/system/bin/linker", Some(Libc::Bionic)),
            (b"/lib/ld.so.1", None),
            (b"/usr/libexec/ld-elf.so.1", None),
        ] {
            assert_eq!(interpreter(path), libc, "{}", path.escape_ascii());
        }
    }
}
