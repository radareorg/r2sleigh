//! Which C library's rows apply is the program's to say.
//!
//! `_Exit` is declared by each library rather than by the table every target shares, and a name
//! two libraries export can be two interfaces, so a call to one has the row of the library the
//! program runs against or none.

use r2abi::{CLibrary, LibraryRows};

/// Each parameter's type, as the row writes it.
fn parameters(library: CLibrary, name: &str) -> Option<Vec<String>> {
    let rows = LibraryRows::embedded(library);
    let row = rows.find(library.scope(), name)?;
    let parameters = rows.prototype(row).parameters.iter();
    Some(
        parameters
            .map(|parameter| parameter.spelling.as_written().to_owned())
            .collect(),
    )
}

fn declares(library: CLibrary, name: &str) -> bool {
    LibraryRows::embedded(library)
        .find(library.scope(), name)
        .is_some()
}

#[test]
fn the_portable_table_does_not_declare_a_library_function() {
    assert!(!declares(CLibrary::Unknown, "_Exit"));
    assert!(!declares(CLibrary::Musl, "_Exit"));
}

#[test]
fn glibc_declares_its_own() {
    assert_eq!(
        parameters(CLibrary::Glibc, "_Exit").map(|types| types.len()),
        Some(1)
    );
    assert!(
        declares(CLibrary::Glibc, "printf"),
        "the portable table still applies"
    );
    // error(3) is GNU's, and no other library's table states it.
    assert!(declares(CLibrary::Glibc, "error"));
    assert!(!declares(CLibrary::LibSystem, "error"));
    assert!(!declares(CLibrary::Bionic, "error"));
}

#[test]
fn libsystem_declares_its_own() {
    assert!(
        declares(CLibrary::LibSystem, "printf"),
        "the portable table still applies"
    );
    // libSystem's second name for `bzero`, which clang calls on x86-64.
    assert_eq!(
        parameters(CLibrary::LibSystem, "__bzero"),
        Some(vec!["void *".into(), "size_t".into()])
    );
    assert_eq!(parameters(CLibrary::Glibc, "__bzero"), None);
}

/// The libSystem imports `ls` calls that no declaration stated (ROADMAP B2), each as the SDK's
/// header declares it, and none of them on a program whose C library is another.
#[test]
fn libsystem_declares_the_imports_ls_calls() {
    let declared = |name: &str| parameters(CLibrary::LibSystem, name);
    assert_eq!(
        declared("__assert_rtn"),
        Some(vec![
            "const char *".into(),
            "const char *".into(),
            "int".into(),
            "const char *".into()
        ])
    );
    let rows = LibraryRows::embedded(CLibrary::LibSystem);
    let scope = CLibrary::LibSystem.scope();
    assert!(
        rows.find(scope, "__assert_rtn")
            .is_some_and(|row| row.noreturn)
    );
    assert_eq!(declared("__maskrune").map(|types| types.len()), Some(2));
    assert_eq!(declared("__error"), Some(vec![]));
    assert_eq!(
        declared("fts_open"),
        Some(vec!["char * const *".into(), "int".into(), "void *".into()])
    );
    assert_eq!(declared("fts_read"), Some(vec!["FTS *".into()]));
    assert_eq!(declared("fts_set").map(|types| types.len()), Some(3));
    assert_eq!(declared("acl_get_entry").map(|types| types.len()), Some(3));
    assert_eq!(declared("getxattr").map(|types| types.len()), Some(6));
    assert_eq!(declared("fflagstostr"), Some(vec!["unsigned long".into()]));
    for name in ["__assert_rtn", "fts_read", "acl_get_entry", "getxattr"] {
        assert_eq!(parameters(CLibrary::Glibc, name), None, "{name}");
    }
    assert_eq!(declared("assert_rtn"), None);
}

#[test]
fn each_c_library_declares_its_own_fgets_chk_and_no_other_library_does() {
    // glibc puts the buffer's size second and the stream last; bionic takes the stream third and
    // the size last. libSystem exports none, and with no library named there is no order to read.
    assert_eq!(
        parameters(CLibrary::Glibc, "__fgets_chk"),
        Some(vec![
            "char *".into(),
            "size_t".into(),
            "int".into(),
            "FILE *".into()
        ])
    );
    assert_eq!(
        parameters(CLibrary::Bionic, "__fgets_chk"),
        Some(vec![
            "char *".into(),
            "int".into(),
            "FILE *".into(),
            "size_t".into()
        ])
    );
    assert_eq!(parameters(CLibrary::LibSystem, "__fgets_chk"), None);
    assert_eq!(parameters(CLibrary::Unknown, "__fgets_chk"), None);
    assert_eq!(
        parameters(CLibrary::Bionic, "__fread_chk").map(|types| types[4].clone()),
        Some("size_t".to_owned())
    );
    assert_eq!(
        parameters(CLibrary::Glibc, "__fread_chk").map(|types| types[4].clone()),
        Some("FILE *".to_owned())
    );
}

#[test]
fn a_fortified_function_every_library_declares_alike_is_portable() {
    for library in [
        CLibrary::Glibc,
        CLibrary::Bionic,
        CLibrary::LibSystem,
        CLibrary::Unknown,
    ] {
        assert_eq!(
            parameters(library, "__memcpy_chk").map(|types| types.len()),
            Some(4),
            "{library:?}"
        );
    }
    // glibc's own fortified `printf` is glibc's alone.
    assert!(declares(CLibrary::Glibc, "__printf_chk"));
    assert!(!declares(CLibrary::Bionic, "__printf_chk"));
    assert!(!declares(CLibrary::LibSystem, "__printf_chk"));
}

/// Within one library's scope no name has two rows, so the scope's order decides nothing.
#[test]
fn a_scope_states_each_name_once() {
    for library in [CLibrary::Glibc, CLibrary::Bionic, CLibrary::LibSystem] {
        let rows = LibraryRows::embedded(library);
        let mut seen = std::collections::BTreeMap::new();
        for row in rows.rows() {
            if let Some(other) = seen.insert(row.linked_name.clone(), row.library) {
                panic!(
                    "{library:?}: `{}` in {other:?} and {:?}",
                    row.linked_name, row.library
                );
            }
        }
    }
}
