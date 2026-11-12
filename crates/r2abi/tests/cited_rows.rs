//! Each cited row names its header on `.include=`, sits under a comment naming its standard, and
//! states its tail where it spells `...` (doc/adr-call-boundary.md, S8).

use r2abi::{CLibrary, Dll, Handle, LibraryId, LibraryRows, Tail};

/// Each cited table and the fewest rows it holds.
const CITED: [(&str, usize); 5] = [
    ("types-posix.sdb.txt", 515),
    ("types-glibc.sdb.txt", 85),
    ("types-bionic.sdb.txt", 100),
    ("types-kernel32.sdb.txt", 50),
    ("types-ucrt.sdb.txt", 1),
];
const UNCITED: [&str; 6] = [
    "types.sdb.txt",
    "types-cxx.sdb.txt",
    "types-linux.sdb.txt",
    "types-android.sdb.txt",
    "types-darwin.sdb.txt",
    "types-objc.sdb.txt",
];

fn table(file: &str) -> String {
    let path = format!("{}/data/{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Each row's name with the comment block above it and the header it includes, or for a
/// binary-only interface the section it cites.
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
        } else if let Some((key, page)) = line.split_once('=')
            && let Some(name) = key
                .strip_prefix("func.")
                .and_then(|rest| rest.strip_suffix(".cite"))
            && let Some(row) = rows.iter_mut().find(|row| row.0 == name && row.2.is_none())
            && row.1.contains("LSB 5.0")
            && row.1.contains("binary standard only")
        {
            row.2 = Some(format!("LSB: {}", page.trim()));
        }
    }
    rows
}

#[test]
fn every_row_cites_its_header() {
    for (file, fewest) in CITED {
        let rows = rows(&table(file));
        assert!(rows.len() >= fewest, "{file}: {} rows", rows.len());
        for (name, comment, header) in rows {
            let header = header.unwrap_or_else(|| panic!("{file}: `{name}` names no header"));
            assert!(
                header.ends_with(".h") || header.starts_with("LSB: LSB-Core-generic 5.0, "),
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

/// The rows glibc's headers could speak for that are still radare2's, each with its reason; the
/// list only falls (ROADMAP D242).
#[test]
fn every_uncited_glibc_facing_row_names_why() {
    let listed = table("uncited-rows.txt")
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, why) = line.split_once(" | ").expect("`name | why`");
            assert!(!why.trim().is_empty(), "`{name}` states no reason");
            name.trim().to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let uncited = ["types.sdb.txt", "types-linux.sdb.txt"]
        .iter()
        .flat_map(|file| rows(&table(file)))
        .map(|row| row.0)
        .collect::<std::collections::BTreeSet<_>>();
    let unnamed = uncited.difference(&listed).collect::<Vec<_>>();
    assert!(unnamed.is_empty(), "uncited with no reason: {unnamed:?}");
    let stale = listed.difference(&uncited).collect::<Vec<_>>();
    assert!(stale.is_empty(), "listed, but no uncited row: {stale:?}");
    assert!(listed.len() <= 119, "{} uncited rows", listed.len());
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
    let bionic = names("types-bionic.sdb.txt");
    let android = names("types-android.sdb.txt");
    for table in [&android, &posix] {
        let both = bionic.intersection(table).collect::<Vec<_>>();
        assert!(
            both.is_empty(),
            "bionic's cited rows also declared: {both:?}"
        );
    }
}

/// A Microsoft row cites the reference page it is read from and the minimum version it states.
#[test]
fn a_microsoft_row_cites_its_page() {
    let rows = LibraryRows::embedded(CLibrary::Ucrt);
    let kernel32 = rows
        .rows()
        .filter(|row| row.library == LibraryId::Dll(Dll::Kernel32));
    let mut count = 0;
    for row in kernel32 {
        count += 1;
        let cited = &row.citation;
        assert!(
            cited.starts_with("Microsoft, <"),
            "{}: {cited}",
            row.linked_name
        );
        assert!(cited.contains("https://learn.microsoft.com/"), "{cited}");
        assert!(
            cited.ends_with(')'),
            "{}: no minimum version: {cited}",
            row.linked_name
        );
    }
    assert!(count >= 50, "{count} KERNEL32 rows");
    let exit = rows.row(LibraryId::Dll(Dll::Kernel32), "ExitProcess");
    assert!(exit.is_some_and(|row| row.noreturn));
    // TerminateProcess returns unless its handle is the caller's own, which GetCurrentProcess yields.
    let kernel32 = |name| rows.row(LibraryId::Dll(Dll::Kernel32), name).expect(name);
    let terminate = kernel32("TerminateProcess");
    assert!(!terminate.noreturn);
    assert_eq!(terminate.halts_on, Some((0, Handle::CurrentProcess)));
    assert_eq!(
        kernel32("GetCurrentProcess").yields,
        Some(Handle::CurrentProcess)
    );
    assert_eq!(kernel32("GetCurrentProcessId").yields, None);
    let printf = rows.row(LibraryId::Dll(Dll::Ucrt), "__stdio_common_vfprintf");
    let printf = printf.expect("UCRT's printf");
    assert_eq!(printf.tail.printf_format(), Some(2));
    // A glibc program reads no Windows row.
    let glibc = LibraryRows::embedded(CLibrary::Glibc);
    assert!(
        glibc
            .rows()
            .all(|row| !matches!(row.library, LibraryId::Dll(_)))
    );
}

/// The Windows type names read as Microsoft defines them: `DWORD` is 32 bits on x64, where
/// `long` is, and a handle is a pointer.
#[test]
fn a_windows_type_name_has_its_defined_width() {
    let rows = LibraryRows::embedded(CLibrary::Ucrt);
    let model = r2abi::CDataModel::of("x86", 64, CLibrary::Ucrt).expect("Microsoft x64");
    let heap_alloc = rows.find(&[LibraryId::Dll(Dll::Kernel32)], "HeapAlloc");
    let prototype = rows.prototype(heap_alloc.expect("HeapAlloc"));
    let bits = |index: usize| {
        let ty = prototype.parameters[index].ty;
        rows.graph().size_bits(ty, model)
    };
    assert_eq!((bits(0), bits(1), bits(2)), (Some(64), Some(32), Some(64)));
}

/// A pointer's own qualifier is no part of a prototype's type here, and a spelling that states one
/// would print as a `const` on the pointee: the rows leave it out.
#[test]
fn no_cited_row_spells_a_qualifier_on_a_pointer() {
    for (file, _) in CITED {
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
        CLibrary::Ucrt,
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
                Tail::Flagged { index, then, .. } => {
                    assert!(prototype.variadic && usize::from(index) < fixed, "{name}");
                    assert_eq!(spelling(index).as_deref(), Some("int"), "{name}");
                    assert!(then > 0, "{name}");
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
    // D151's last two: libio's `__overflow` and glibc's `wcwidth` are cited, fixed prototypes.
    for (name, parameters) in [("__overflow", 2), ("wcwidth", 1)] {
        let row = glibc.row(LibraryId::Glibc, name).expect(name);
        assert_eq!(row.tail, Tail::None, "{name}");
        assert_eq!(glibc.prototype(row).parameters.len(), parameters, "{name}");
    }
    let libsystem = LibraryRows::embedded(CLibrary::LibSystem);
    assert!(
        libsystem
            .rows()
            .all(|row| &*row.linked_name != "assert_fail")
    );
}

/// glibc's `open` family reads its mode where `__OPEN_NEEDS_MODE` holds (glibc 2.39 `<fcntl.h>`),
/// whose `__O_TMPFILE` holds each architecture's `__O_DIRECTORY`; another library states only
/// `...`, and `prctl` is variadic everywhere (RULING 2.2, 2.3).
#[test]
fn only_glibc_counts_the_mode_open_reads() {
    use r2abi::{FlagBits, FlagTest};
    let glibc = LibraryRows::embedded(CLibrary::Glibc);
    for (name, index) in [("open", 1), ("open64", 1), ("openat", 2)] {
        let row = glibc.row(LibraryId::Glibc, name).expect(name);
        assert_eq!(
            row.tail,
            Tail::Flagged {
                index,
                test: FlagTest::OpenNeedsMode,
                then: 1
            },
            "{name}"
        );
    }
    let prctl = glibc.row(LibraryId::Glibc, "prctl").expect("prctl");
    assert_eq!(prctl.tail, Tail::Variadic);
    let bionic = LibraryRows::embedded(CLibrary::Bionic);
    let open = bionic
        .find(CLibrary::Bionic.scope(), "open")
        .expect("bionic open");
    assert_eq!(open.tail, Tail::Variadic);
    let musl = LibraryRows::embedded(CLibrary::Musl);
    assert!(musl.find(CLibrary::Musl.scope(), "open").is_none());
    let test = FlagTest::OpenNeedsMode;
    let bits = |library, arch, width| test.bits(library, arch, width);
    let x86 = FlagBits {
        any: 0o100,
        all: 0o20200000,
    };
    let arm = FlagBits {
        any: 0o100,
        all: 0o20040000,
    };
    assert_eq!(bits(CLibrary::Glibc, "x86", 64), Some(x86));
    assert_eq!(bits(CLibrary::Glibc, "arm", 64), Some(arm));
    assert_eq!(bits(CLibrary::Glibc, "x86", 32), None);
    assert_eq!(bits(CLibrary::Bionic, "arm", 64), None);
}
