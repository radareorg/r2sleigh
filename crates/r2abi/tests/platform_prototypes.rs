//! Which C library's declarations apply is the platform's to say.
//!
//! `_Exit` is declared by each library rather than by the table every target
//! shares, and a name two libraries export can be two interfaces, so a call
//! to one has the prototype of the library the program runs against or none.

use r2abi::{Platform, Prototypes};

/// Each parameter's type, as the declaration writes it.
fn parameters(platform: Platform, name: &str) -> Option<Vec<String>> {
    let prototypes = Prototypes::embedded_for(platform);
    let prototype = prototypes.get(name)?;
    Some(
        prototype
            .parameters
            .iter()
            .map(|parameter| parameter.spelling.as_written().to_owned())
            .collect(),
    )
}

#[test]
fn the_portable_table_does_not_declare_a_platform_function() {
    let portable = Prototypes::embedded_for(Platform::Unknown);
    assert!(portable.get("_Exit").is_none());
}

#[test]
fn linux_declares_its_own() {
    let linux = Prototypes::embedded_for(Platform::Linux);
    let exit = linux.get("_Exit").expect("_Exit is declared on linux");
    assert_eq!(exit.parameters.len(), 1);
    assert!(
        linux.get("printf").is_some(),
        "the portable table still applies"
    );
}

#[test]
fn darwin_declares_its_own() {
    let darwin = Prototypes::embedded_for(Platform::Darwin);
    assert!(
        darwin.get("printf").is_some(),
        "the portable table still applies"
    );
    // libSystem's second name for `bzero`, which clang calls on x86-64.
    assert_eq!(
        parameters(Platform::Darwin, "__bzero"),
        Some(vec!["void *".into(), "size_t".into()])
    );
    assert_eq!(parameters(Platform::Linux, "__bzero"), None);
}

/// The libSystem imports `ls` calls that no declaration stated (ROADMAP B2), each as the SDK's
/// header declares it, and none of them on a platform whose C library is another.
#[test]
fn darwin_declares_the_libsystem_imports_ls_calls() {
    let declared = |name: &str| parameters(Platform::Darwin, name);
    assert_eq!(
        declared("__assert_rtn"),
        Some(vec![
            "const char *".into(),
            "const char *".into(),
            "int".into(),
            "const char *".into()
        ])
    );
    assert!(
        Prototypes::embedded_for(Platform::Darwin)
            .get("__assert_rtn")
            .is_some_and(|prototype| prototype.noreturn)
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
        assert_eq!(parameters(Platform::Linux, name), None, "{name}");
    }
    // radare2's undecorated key names no symbol a Mach-O binds.
    assert_eq!(declared("assert_rtn"), None);
}

#[test]
fn each_c_library_declares_its_own_fgets_chk_and_no_other_library_does() {
    // glibc puts the buffer's size second and the stream last; bionic takes
    // the stream third and the size last. Darwin exports none, and with no
    // library named there is no order to read a call in.
    assert_eq!(
        parameters(Platform::Linux, "__fgets_chk"),
        Some(vec![
            "char *".into(),
            "size_t".into(),
            "int".into(),
            "FILE *".into()
        ])
    );
    assert_eq!(
        parameters(Platform::Android, "__fgets_chk"),
        Some(vec![
            "char *".into(),
            "int".into(),
            "FILE *".into(),
            "size_t".into()
        ])
    );
    assert_eq!(parameters(Platform::Darwin, "__fgets_chk"), None);
    assert_eq!(parameters(Platform::Unknown, "__fgets_chk"), None);
    // `__fread_chk` likewise: glibc's buffer size is second, bionic's last.
    assert_eq!(
        parameters(Platform::Android, "__fread_chk").map(|types| types[4].clone()),
        Some("size_t".to_owned())
    );
    assert_eq!(
        parameters(Platform::Linux, "__fread_chk").map(|types| types[4].clone()),
        Some("FILE *".to_owned())
    );
}

#[test]
fn a_fortified_function_every_library_declares_alike_is_portable() {
    for platform in [
        Platform::Linux,
        Platform::Android,
        Platform::Darwin,
        Platform::Unknown,
    ] {
        assert_eq!(
            parameters(platform, "__memcpy_chk").map(|types| types.len()),
            Some(4),
            "{platform:?}"
        );
    }
    // glibc's own fortified `printf` is glibc's alone.
    assert!(parameters(Platform::Linux, "__printf_chk").is_some());
    assert!(parameters(Platform::Android, "__printf_chk").is_none());
    assert!(parameters(Platform::Darwin, "__printf_chk").is_none());
}
