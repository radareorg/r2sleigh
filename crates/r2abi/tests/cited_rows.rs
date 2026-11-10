//! Each cited row names its header on `.include=`, sits under a comment naming its standard, and
//! states its tail where it spells `...` (doc/adr-call-boundary.md, S8).

use r2abi::{CLibrary, LibraryId, LibraryRows, Tail};

const CITED: [&str; 2] = ["types-posix.sdb.txt", "types-glibc.sdb.txt"];
const UNCITED: [&str; 5] = [
    "types.sdb.txt",
    "types-cxx.sdb.txt",
    "types-linux.sdb.txt",
    "types-android.sdb.txt",
    "types-darwin.sdb.txt",
];

fn table(file: &str) -> String {
    let path = format!("{}/data/{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Each row's name with the comment block above it and the header it includes.
fn rows(text: &str) -> Vec<(String, String, Option<String>)> {
    let mut rows: Vec<(String, String, Option<String>)> = Vec::new();
    let mut comment = String::new();
    let mut after_comment = false;
    for line in text.lines().map(str::trim) {
        if let Some(words) = line.strip_prefix('#') {
            if !after_comment {
                comment.clear();
            }
            comment.push_str(words);
            comment.push(' ');
            after_comment = true;
            continue;
        }
        after_comment = false;
        if let Some(name) = line.strip_suffix("=func") {
            rows.push((name.to_owned(), comment.clone(), None));
        } else if let Some((key, header)) = line.split_once('=')
            && let Some(name) = key
                .strip_prefix("func.")
                .and_then(|rest| rest.strip_suffix(".include"))
            && let Some(row) = rows.iter_mut().find(|row| row.0 == name)
        {
            row.2 = Some(header.trim().to_owned());
        }
    }
    rows
}

#[test]
fn every_row_cites_its_header() {
    for file in CITED {
        let rows = rows(&table(file));
        assert!(rows.len() > 40, "{file}: {} rows", rows.len());
        for (name, comment, header) in rows {
            let header = header.unwrap_or_else(|| panic!("{file}: `{name}` names no header"));
            assert!(
                header.ends_with(".h"),
                "{file}: `{name}` includes `{header}`"
            );
            assert!(
                r2abi::library::SOURCES
                    .iter()
                    .any(|source| comment.contains(source)),
                "{file}: `{name}` sits under a comment that names no source: {comment}"
            );
        }
    }
}

/// An uncited table states no tail: its rows are radare2's, `Unstated` until cited.
#[test]
fn an_uncited_table_states_no_tail() {
    for file in UNCITED {
        for line in table(file).lines() {
            assert!(!line.contains(".tail="), "{file}: {line}");
        }
    }
}

/// A row moved to a cited table leaves its old declaration: one fact has one owner.
#[test]
fn a_cited_row_is_declared_in_no_other_table() {
    let names = |file: &str| {
        rows(&table(file))
            .into_iter()
            .map(|row| row.0)
            .collect::<std::collections::BTreeSet<_>>()
    };
    let posix = names("types-posix.sdb.txt");
    let glibc = names("types-glibc.sdb.txt");
    for other in ["types.sdb.txt", "types-cxx.sdb.txt", "types-linux.sdb.txt"] {
        let declared = names(other);
        for name in posix.iter().chain(&glibc) {
            assert!(
                !declared.contains(name),
                "`{name}` is also declared in {other}"
            );
        }
    }
    let both = posix.intersection(&glibc).collect::<Vec<_>>();
    assert!(both.is_empty(), "declared by both cited tables: {both:?}");
}

/// A pointer's own qualifier is no part of a prototype's type here, and a spelling that states one
/// would print as a `const` on the pointee: the rows leave it out.
#[test]
fn no_cited_row_spells_a_qualifier_on_a_pointer() {
    for file in CITED {
        for line in table(file).lines().filter(|line| line.contains(".arg.")) {
            let spelling = line.split_once('=').map_or("", |(_, spelling)| spelling);
            let spelling = spelling.split(',').next().unwrap_or_default();
            assert!(
                !spelling.contains("* const") && !spelling.contains("restrict"),
                "{file}: {line}"
            );
        }
    }
}

/// Every cited row reads whole on every C library, states a tail that fits its prototype, and
/// carries its citation; a format names a fixed `char` or `wchar_t` pointer.
#[test]
fn every_cited_row_states_a_tail_its_prototype_has() {
    for library in [
        CLibrary::Glibc,
        CLibrary::Bionic,
        CLibrary::LibSystem,
        CLibrary::Musl,
        CLibrary::Unknown,
    ] {
        let rows = LibraryRows::embedded(library);
        let graph = rows.graph();
        let cited = rows.rows().filter(|row| !row.citation.is_empty());
        let mut count = 0;
        for row in cited {
            count += 1;
            let prototype = rows.prototype(row);
            let name = &row.linked_name;
            let types = prototype.parameters.iter().map(|parameter| parameter.ty);
            for ty in types.chain([prototype.return_type]) {
                let refused = matches!(graph.get(ty), Some(r2abi::Type::Refused(_)));
                assert!(!refused, "{name} on {library:?}: {:?}", graph.get(ty));
            }
            let fixed = prototype.parameters.len();
            let spelling = |index: u8| {
                let parameter = prototype.parameters.get(usize::from(index));
                parameter.map(|parameter| parameter.spelling.as_written().to_owned())
            };
            match row.tail {
                Tail::None => assert!(!prototype.variadic, "{name}"),
                Tail::Unstated => panic!("{name}: a cited row states its tail"),
                Tail::Variadic => assert!(prototype.variadic, "{name}"),
                Tail::Format { index, .. } => {
                    assert!(prototype.variadic && usize::from(index) < fixed, "{name}");
                    let format = spelling(index).unwrap_or_default();
                    let narrow = format.ends_with(" char *");
                    assert!(narrow || format.ends_with("wchar_t *"), "{name}: {format}");
                }
                Tail::VaList { index, format } => {
                    assert!(!prototype.variadic, "{name}");
                    assert_eq!(spelling(index).as_deref(), Some("va_list"), "{name}");
                    let format = format.map(|(at, _)| spelling(at).unwrap_or_default());
                    let names =
                        |format: &str| format.ends_with(" char *") || format.ends_with("wchar_t *");
                    assert!(format.is_none_or(|format| names(&format)), "{name}");
                }
            }
        }
        assert!(count > 80, "{library:?}: {count} cited rows");
    }
}

/// radare2 keys a row by the name with its underscores dropped, which no program links: those
/// keys are gone, and the linked names glibc exports are cited rows.
#[test]
fn a_row_is_keyed_by_the_name_a_program_links() {
    let glibc = LibraryRows::embedded(CLibrary::Glibc);
    for key in [
        "assert_fail",
        "errno_location",
        "libc_start_main",
        "cxa_throw",
        "cxa_finalize",
        "libc_init",
        "libc_init_array",
        "uClibc_main",
    ] {
        assert!(glibc.rows().all(|row| &*row.linked_name != key), "{key}");
    }
    let assert_fail = glibc.row(LibraryId::Glibc, "__assert_fail").expect("cited");
    assert!(assert_fail.noreturn);
    assert_eq!(assert_fail.tail, Tail::None);
    assert!(glibc.row(LibraryId::Glibc, "__errno_location").is_some());
    let libsystem = LibraryRows::embedded(CLibrary::LibSystem);
    assert!(
        libsystem
            .rows()
            .all(|row| &*row.linked_name != "assert_fail")
    );
}
