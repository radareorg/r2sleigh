//! What a container states about the C library its program runs against.
//!
//! `readelf -lnW` on each fixture: the dynamic linker `PT_INTERP` names, and
//! the notes the library's start files leave. Mach-O states its platform by
//! being Mach-O, so it carries none of this evidence.

use std::collections::BTreeSet;

use r2image::{Image, Libc, PlatformEvidence};

fn evidence(bytes: &[u8]) -> BTreeSet<PlatformEvidence> {
    Image::parse(bytes.to_vec())
        .expect("the fixture parses")
        .container()
        .platform
        .clone()
}

#[test]
fn an_elf_names_its_c_library_by_its_dynamic_linker_and_its_start_files_notes() {
    // `/lib64/ld-linux-x86-64.so.2`, and glibc's `.note.ABI-tag` naming Linux.
    assert_eq!(
        evidence(include_bytes!("data/fortified_glibc.elf")),
        BTreeSet::from([
            PlatformEvidence::Interpreter(Libc::Glibc),
            PlatformEvidence::Note(Libc::Glibc),
        ])
    );
    // `/system/bin/linker64`, and bionic's `.note.android.ident`.
    assert_eq!(
        evidence(include_bytes!("data/fortified_bionic.elf")),
        BTreeSet::from([
            PlatformEvidence::Interpreter(Libc::Bionic),
            PlatformEvidence::Note(Libc::Bionic),
        ])
    );
    assert_eq!(
        evidence(include_bytes!("../../../tests/fixtures/manual_limits_O0")),
        BTreeSet::new()
    );
}
