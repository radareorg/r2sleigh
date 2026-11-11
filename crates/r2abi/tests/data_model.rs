//! Each `CDataModel` row agrees with its compiler's `-dM -E`: plain `char`'s sign,
//! `wchar_t`'s sign and width, `long` and pointers (doc/adr-call-boundary.md).

use std::process::Command;

use r2abi::{CDataModel, CLibrary, ScalarKind, Width};

/// A compiler triple and the row the engine looks up for a program built by it.
const TARGETS: &[(&str, &str, u32, CLibrary)] = &[
    ("x86_64-linux-gnu", "x86-64", 64, CLibrary::Glibc),
    ("x86_64-linux-android", "x86-64", 64, CLibrary::Bionic),
    ("x86_64-apple-darwin", "x86-64", 64, CLibrary::LibSystem),
    ("x86_64-pc-windows-msvc", "x86-64", 64, CLibrary::Ucrt),
    ("i386-linux-gnu", "x86", 32, CLibrary::Glibc),
    ("i686-linux-android", "x86", 32, CLibrary::Bionic),
    ("aarch64-linux-gnu", "aarch64", 64, CLibrary::Glibc),
    ("aarch64-linux-android", "aarch64", 64, CLibrary::Bionic),
    ("arm64-apple-darwin", "arm64", 64, CLibrary::LibSystem),
    ("arm-linux-gnueabihf", "arm", 32, CLibrary::Glibc),
    ("armv7a-linux-androideabi", "arm", 32, CLibrary::Bionic),
    ("riscv64-linux-gnu", "riscv64", 64, CLibrary::Glibc),
];

/// `clang -target T -dM -E -x c /dev/null` (Apple clang 21.0.0): `__CHAR_UNSIGNED__`, `__WCHAR_TYPE__`,
/// `__SIZEOF_WCHAR_T__`, `__SIZEOF_LONG__` and `__SIZEOF_POINTER__`.
const RECORDED: &[(&str, bool, &str, u32, u32, u32)] = &[
    ("x86_64-linux-gnu", false, "int", 4, 8, 8),
    ("x86_64-linux-android", false, "int", 4, 8, 8),
    ("x86_64-apple-darwin", false, "int", 4, 8, 8),
    ("x86_64-pc-windows-msvc", false, "unsigned short", 2, 4, 8),
    ("i386-linux-gnu", false, "int", 4, 4, 4),
    ("i686-linux-android", false, "int", 4, 4, 4),
    ("aarch64-linux-gnu", true, "unsigned int", 4, 8, 8),
    ("aarch64-linux-android", true, "unsigned int", 4, 8, 8),
    ("arm64-apple-darwin", false, "int", 4, 8, 8),
    ("arm-linux-gnueabihf", true, "unsigned int", 4, 4, 4),
    ("armv7a-linux-androideabi", true, "unsigned int", 4, 4, 4),
    ("riscv64-linux-gnu", true, "int", 4, 8, 8),
];

/// The compiler's model, read from its predefined macros.
#[derive(Debug, PartialEq, Eq)]
struct Defined {
    plain_char: ScalarKind,
    wide_char: (ScalarKind, u32),
    long_bits: u32,
    pointer_bits: u32,
}

impl Defined {
    fn of(char_unsigned: bool, wchar: &str, wchar_bytes: u32, long: u32, pointer: u32) -> Self {
        let sign = |unsigned| match unsigned {
            true => ScalarKind::Unsigned,
            false => ScalarKind::Signed,
        };
        Self {
            plain_char: sign(char_unsigned),
            wide_char: (sign(wchar.starts_with("unsigned")), wchar_bytes * 8),
            long_bits: long * 8,
            pointer_bits: pointer * 8,
        }
    }

    fn parse(macros: &str) -> Option<Self> {
        let value = |name: &str| {
            macros.lines().find_map(|line| {
                let rest = line.strip_prefix("#define ")?.strip_prefix(name)?;
                rest.strip_prefix(' ').map(str::trim)
            })
        };
        let bytes = |name: &str| value(name)?.parse::<u32>().ok();
        Some(Self::of(
            value("__CHAR_UNSIGNED__").is_some(),
            value("__WCHAR_TYPE__")?,
            bytes("__SIZEOF_WCHAR_T__")?,
            bytes("__SIZEOF_LONG__")?,
            bytes("__SIZEOF_POINTER__")?,
        ))
    }

    fn of_row(row: &CDataModel) -> Self {
        Self {
            plain_char: row.plain_char.expect("a row states char's sign"),
            wide_char: row.wide_char.expect("a row states wchar_t"),
            long_bits: row.long_bits,
            pointer_bits: row.pointer_bits,
        }
    }
}

fn row(triple: &str) -> &'static CDataModel {
    let (_, arch, bits, platform) = TARGETS
        .iter()
        .find(|(listed, ..)| *listed == triple)
        .expect("a listed target");
    CDataModel::of(arch, *bits, *platform).unwrap_or_else(|| panic!("{triple} has a row"))
}

#[test]
fn every_row_agrees_with_the_macros_its_compiler_defined() {
    assert_eq!(RECORDED.len(), TARGETS.len());
    for (triple, char_unsigned, wchar, wchar_bytes, long, pointer) in RECORDED {
        let row = row(triple);
        assert!(!row.citation.is_empty(), "{triple}: a row is cited");
        assert_eq!(
            Defined::of_row(row),
            Defined::of(*char_unsigned, wchar, *wchar_bytes, *long, *pointer),
            "{triple}"
        );
    }
}

/// The same comparison against the compiler on this machine, for each target
/// it supports; a missing compiler or target is printed, never passed silently.
#[test]
fn every_row_agrees_with_the_compiler_here() {
    let mut compared = 0;
    for (triple, ..) in TARGETS {
        let output = Command::new("clang")
            .args(["-target", triple, "-dM", "-E", "-x", "c", "/dev/null"])
            .output();
        let defined = match output {
            Ok(output) if output.status.success() => {
                Defined::parse(&String::from_utf8_lossy(&output.stdout))
            }
            Ok(output) => {
                eprintln!(
                    "note: clang -target {triple} refused: {}; not compared",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                continue;
            }
            Err(error) => {
                eprintln!("note: no clang here ({error}); {triple} not compared");
                continue;
            }
        };
        let defined = defined.unwrap_or_else(|| panic!("{triple}: clang defined no data model"));
        assert_eq!(Defined::of_row(row(triple)), defined, "{triple}");
        compared += 1;
    }
    eprintln!(
        "compared {compared} of {} targets with clang",
        TARGETS.len()
    );
}

#[test]
fn a_target_no_row_lists_states_no_sign() {
    assert_eq!(CDataModel::of("x86-64", 64, CLibrary::Unknown), None);
    assert_eq!(CDataModel::of("mips", 32, CLibrary::Glibc), None);
    let unlisted = CDataModel::unix(64);
    assert_eq!(unlisted.kind(ScalarKind::PlainChar), None);
    assert_eq!(unlisted.kind(ScalarKind::WideChar), None);
    assert_eq!(unlisted.bits(Width::WideChar), None);
    assert_eq!(
        unlisted.kind(ScalarKind::Unsigned),
        Some(ScalarKind::Unsigned)
    );
}

/// A row's `const char *` and `wchar_t` read once, and each target answers for
/// them: AAPCS64 makes both unsigned, SysV x86-64 both signed.
#[test]
fn a_rows_char_and_wchar_take_the_targets_sign() {
    let rows = r2abi::LibraryRows::embedded(CLibrary::Glibc);
    let graph = rows.graph();
    let scope = CLibrary::Glibc.scope();
    let wcschr = rows.prototype(rows.find(scope, "wcschr").expect("wcschr is declared"));
    let strlen = rows.prototype(rows.find(scope, "strlen").expect("strlen is declared"));
    let scalar_under = |ty| {
        let (mut at, _) = graph.peel(ty);
        while let Some(r2abi::Type::Pointer { target }) = graph.get(at) {
            at = graph.peel(*target).0;
        }
        match graph.get(at) {
            Some(r2abi::Type::Scalar(scalar)) => scalar.clone(),
            other => panic!("not a scalar: {other:?}"),
        }
    };
    let char_ = scalar_under(strlen.parameters[0].ty);
    let wide = scalar_under(wcschr.parameters[1].ty);
    assert_eq!(char_.kind, ScalarKind::PlainChar);
    assert_eq!(wide.kind, ScalarKind::WideChar);
    let aarch64 = row("aarch64-linux-gnu");
    let x86_64 = row("x86_64-linux-gnu");
    assert_eq!(aarch64.kind(char_.kind), Some(ScalarKind::Unsigned));
    assert_eq!(x86_64.kind(char_.kind), Some(ScalarKind::Signed));
    assert_eq!(aarch64.kind(wide.kind), Some(ScalarKind::Unsigned));
    assert_eq!(x86_64.kind(wide.kind), Some(ScalarKind::Signed));
    assert_eq!(aarch64.bits(wide.width), Some(32));
    assert_eq!(row("x86_64-pc-windows-msvc").bits(wide.width), Some(16));
    assert_eq!(
        graph.spelled(strlen.parameters[0].ty).map(|s| s.declared),
        Some("const char *".to_owned())
    );
}

/// Bionic's `mode_t` is the kernel's `__kernel_mode_t`: 16 bits on 32-bit Arm and x86, 32 on the
/// 64-bit targets; glibc's is 32 everywhere and libSystem's 16.
#[test]
fn mode_t_takes_the_targets_kernel_width() {
    let width = |library: CLibrary, triple: &str| {
        let rows = r2abi::LibraryRows::embedded(library);
        let mkdir = rows
            .find(library.scope(), "mkdir")
            .expect("mkdir is declared");
        let ty = rows.prototype(mkdir).parameters[1].ty;
        rows.graph().size_bits(ty, row(triple))
    };
    for (triple, bits) in [
        ("x86_64-linux-android", 32),
        ("i686-linux-android", 16),
        ("aarch64-linux-android", 32),
        ("armv7a-linux-androideabi", 16),
    ] {
        assert_eq!(width(CLibrary::Bionic, triple), Some(bits), "{triple}");
    }
    assert_eq!(width(CLibrary::Glibc, "i386-linux-gnu"), Some(32));
    assert_eq!(width(CLibrary::LibSystem, "arm64-apple-darwin"), Some(16));
    assert!(!r2abi::KERNEL_MODE_CITATION.is_empty());
}
