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

/// `readelf -VW`: the needs `.gnu.version_r` states, and the version `.gnu.version` gives each import.
#[test]
fn an_elf_states_the_versions_it_needs_and_each_import_binds() {
    use r2image::{SymbolVersion, VersionNeed};
    let image = Image::parse(include_bytes!("data/fortified_glibc.elf").to_vec()).expect("parses");
    let container = image.container();
    assert_eq!(
        container.version_needs,
        [VersionNeed {
            library: "libc.so.6".into(),
            versions: vec![
                "GLIBC_2.4".into(),
                "GLIBC_2.2.5".into(),
                "GLIBC_2.34".into()
            ],
        }]
    );
    let version = |name: &str| {
        let import = container
            .symbols
            .iter()
            .find(|symbol| symbol.import && &*symbol.name == name);
        import.and_then(|symbol| symbol.version.clone())
    };
    assert_eq!(
        version("__fgets_chk"),
        Some(SymbolVersion::Needed {
            library: "libc.so.6".into(),
            version: "GLIBC_2.4".into(),
        })
    );
    // A weak reference the linker left unversioned states none.
    assert_eq!(version("__gmon_start__"), None);
    // A shared object that needs no library states no need.
    let library = Image::parse(include_bytes!("data/loader_values.so").to_vec()).expect("parses");
    assert!(library.container().version_needs.is_empty());
}
