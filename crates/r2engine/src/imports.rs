//! Which library row an import binds: the library the container states for it, by its DLL, its
//! two-level namespace dylib or its version need; never by a bare name, and never to a body
//! (doc/adr-call-boundary.md, Refusals "A library row", "S20 as built").

use std::collections::BTreeMap;

use r2abi::statement::{Container, Format, Symbol, SymbolVersion};
use r2abi::{CLibrary, LibraryId, LibraryRow, LibraryRows};

/// The rows one program's C library states, and how its container says each import binds.
#[derive(Debug, Clone)]
pub struct Imports {
    rows: LibraryRows,
    library: CLibrary,
    linkage: Linkage,
}

/// What the container states about how its imports bind, read once per program.
#[derive(Debug, Clone)]
pub struct Linkage {
    /// Each import by linked name: what its identity binds, or why it binds nothing.
    bindings: BTreeMap<Box<str>, Binding>,
    /// What a name no import symbol states binds: an ELF slot's unversioned import, or nothing.
    unlisted: Binding,
}

/// The library one import's identity names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Binding {
    /// These tables' rows, the stated library's own first.
    Scope(&'static [LibraryId]),
    /// A C library's own version node: its rows where the program runs on it.
    Versioned(CLibrary),
    /// The program's C library, the one library `DT_NEEDED` names.
    CLibrary,
    /// Why the container states no library whose rows apply.
    Unstated(&'static str),
}

impl Linkage {
    /// What `container` states: O(imports × log imports + needed libraries).
    pub fn of(container: &Container) -> Self {
        let mut bindings: BTreeMap<Box<str>, Binding> = BTreeMap::new();
        // An ELF import the loader binds is a dynamic symbol; `.symtab` repeats it unversioned.
        let elf = container.format == Format::Elf;
        let imports = (container.symbols.iter())
            .filter(|symbol| symbol.import && (!elf || symbol.origin.dynamic.is_some()));
        for symbol in imports {
            let binding = binding(container, symbol);
            let held = bindings.entry(symbol.name.as_ref().into());
            let held = held.or_insert_with(|| binding.clone());
            if *held != binding {
                *held = Binding::Unstated("two imports of this name bind two libraries");
            }
        }
        let unlisted = match elf {
            true => unversioned(container),
            false => Binding::Unstated("the container states no import of this name"),
        };
        Self { bindings, unlisted }
    }

    /// Every import binds the program's C library at `Declared`: a test's linkage.
    pub fn one_c_library() -> Self {
        Self {
            bindings: BTreeMap::new(),
            unlisted: Binding::CLibrary,
        }
    }
}

/// What one import's identity binds.
fn binding(container: &Container, symbol: &Symbol) -> Binding {
    let library = symbol.library.as_deref();
    match container.format {
        Format::Elf => match &symbol.version {
            Some(SymbolVersion::Needed { library, version }) => {
                versioned(container, library, version)
            }
            Some(SymbolVersion::Defined { .. }) | None => unversioned(container),
        },
        // A PE import names its DLL (doc/adr-call-boundary.md, S13).
        Format::Pe => match library.and_then(r2abi::Dll::of) {
            Some(r2abi::Dll::Kernel32) => Binding::Scope(KERNEL32),
            Some(r2abi::Dll::Ucrt) => Binding::Scope(UCRT),
            None => Binding::Unstated("it names a DLL no cited table states"),
        },
        // A two-level namespace names the dylib; a flat one names none.
        Format::MachO => match library.map(dylib) {
            Some(Dylib::LibSystem) => Binding::Scope(CLibrary::LibSystem.scope()),
            Some(Dylib::CxxRuntime) => Binding::Scope(CXX_RUNTIME),
            Some(Dylib::Objc) => Binding::Scope(OBJC),
            Some(Dylib::Other) => Binding::Unstated("it names a dylib no table states"),
            None => Binding::Unstated("no two-level namespace names its dylib"),
        },
        _ => Binding::Unstated("the format states no import binding"),
    }
}

/// An ELF import bound to a version node of a library `DT_NEEDED` names.
fn versioned(container: &Container, library: &str, version: &str) -> Binding {
    if !container.libraries.iter().any(|needed| needed == library) {
        return Binding::Unstated("its version need names a file DT_NEEDED does not");
    }
    if versioned_runtime(version) {
        return Binding::Scope(CXX_RUNTIME);
    }
    match versioned_library(library, version) {
        Some(named) => Binding::Versioned(named),
        None => Binding::Unstated("its version names a library no table states"),
    }
}

/// An unversioned ELF import binds only where `DT_NEEDED` names one library, a C library: any
/// other library could define it.
fn unversioned(container: &Container) -> Binding {
    match container.libraries.as_slice() {
        [only] if is_c_library(only) => Binding::CLibrary,
        _ => Binding::Unstated("it is unversioned and DT_NEEDED names more than its C library"),
    }
}

/// The dylibs a table states, by install name.
enum Dylib {
    LibSystem,
    CxxRuntime,
    Objc,
    Other,
}

/// libSystem's umbrella, the C++ runtime's two dylibs and objc4's runtime, by the whole install
/// name dyld loads: a same-named file elsewhere is another library.
fn dylib(install: &str) -> Dylib {
    match install {
        "/usr/lib/libSystem.B.dylib" => Dylib::LibSystem,
        "/usr/lib/libc++.1.dylib" | "/usr/lib/libc++abi.dylib" => Dylib::CxxRuntime,
        "/usr/lib/libobjc.A.dylib" => Dylib::Objc,
        _ => Dylib::Other,
    }
}

/// A soname only a C library ships: glibc's `libc.so.6`, bionic's and musl's `libc.so`, Alpine's
/// `libc.musl-<arch>.so.1`.
fn is_c_library(soname: &str) -> bool {
    matches!(soname, "libc.so.6" | "libc.so")
        || soname.starts_with("libc.musl-") && soname.ends_with(".so.1")
}

/// The C library a version node names, by the node: glibc's are `GLIBC_*`, bionic's `LIBC` and
/// `LIBC_*` (bionic `libc.map.txt`) on its `libc.so`, `libm.so` or `libdl.so`.
fn versioned_library(library: &str, version: &str) -> Option<CLibrary> {
    let bionic_file = matches!(library, "libc.so" | "libm.so" | "libdl.so");
    if version.starts_with("GLIBC_") {
        Some(CLibrary::Glibc)
    } else if bionic_file && (version == "LIBC" || version.starts_with("LIBC_")) {
        Some(CLibrary::Bionic)
    } else {
        None
    }
}

/// The C++ runtime's version nodes: libstdc++'s `GLIBCXX_*` and `CXXABI_*`, libgcc_s's `GCC_*`.
fn versioned_runtime(version: &str) -> bool {
    ["GLIBCXX_", "CXXABI_", "GCC_"]
        .iter()
        .any(|prefix| version.starts_with(prefix))
}

const CXX_RUNTIME: &[LibraryId] = &[LibraryId::CxxRuntime];
/// objc4's own table: `objc_msgSend` and its kin.
const OBJC: &[LibraryId] = &[LibraryId::Objc];
const KERNEL32: &[LibraryId] = &[LibraryId::Dll(r2abi::Dll::Kernel32)];
/// UCRT's own rows first, then the rows a PE import read before S13.
const UCRT: &[LibraryId] = &[
    LibraryId::Dll(r2abi::Dll::Ucrt),
    LibraryId::CxxRuntime,
    LibraryId::Portable,
];

/// The argument registers a call to an import may read (doc/adr-call-boundary.md, "Lower bounds
/// and upper bounds"): an upper bound only where the row's citation states a fixed prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReads {
    /// Each register, the fixed parameters' first, then the convention's later ones in its order.
    pub registers: Vec<r2source::CanonicalStorageId>,
    /// SysV `al`, read with a tail and bounding the vector registers it counts.
    pub count_register: Option<r2source::CanonicalStorageId>,
    /// A printf-format `...` in registers with no count register (AAPCS64): what bounds its vector reads.
    pub format: Option<FormatTail>,
}

/// Where a printf-family call's format arrives, and the tail's vector registers, which only a
/// floating conversion reads (doc/adr-call-boundary.md, "S15 as built").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatTail {
    pub format: r2source::CanonicalStorageId,
    pub floats: Vec<r2source::CanonicalStorageId>,
}

impl Imports {
    pub fn new(rows: LibraryRows, library: CLibrary, linkage: Linkage) -> Self {
        Self {
            rows,
            library,
            linkage,
        }
    }

    /// The program's C library.
    pub fn library(&self) -> CLibrary {
        self.library
    }

    pub fn rows(&self) -> &LibraryRows {
        &self.rows
    }

    /// The row the import `name` binds, or why none: O(log imports + log rows). `name` is one
    /// the container states as an import (`Program::import_at`); a body's name binds nothing. A
    /// mangled name's own row applies whatever library defines it (S13).
    pub fn bind(&self, name: &str) -> Result<&LibraryRow, &'static str> {
        let mangled = || self.rows.row(LibraryId::Itanium, name);
        match self.scope(name) {
            Ok(scope) => (self.rows.find(scope, name).or_else(mangled))
                .ok_or("no row of the library it binds states this name"),
            Err(why) => mangled().ok_or(why),
        }
    }

    /// The row the import binds, with the refusal stated as evidence.
    pub fn row(&self, name: &str) -> Option<&LibraryRow> {
        self.bind(name)
            .inspect_err(|why| r2il::refusal_evidence!("library-row", "{name}: {why}"))
            .ok()
    }

    fn scope(&self, name: &str) -> Result<&'static [LibraryId], &'static str> {
        let linkage = &self.linkage;
        match linkage.bindings.get(name).unwrap_or(&linkage.unlisted) {
            Binding::Scope(scope) => Ok(scope),
            Binding::Versioned(named) if *named == self.library => Ok(named.scope()),
            Binding::Versioned(_) => {
                Err("its version names a C library the program does not run on")
            }
            Binding::CLibrary => Ok(self.library.scope()),
            Binding::Unstated(why) => Err(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2abi::statement::{Symbol, SymbolOrigin};

    fn import(name: &str, version: Option<(&str, &str)>) -> Symbol {
        Symbol {
            name: name.into(),
            import: true,
            origin: SymbolOrigin {
                dynamic: Some(1),
                ..SymbolOrigin::default()
            },
            version: version.map(|(library, version)| SymbolVersion::Needed {
                library: library.into(),
                version: version.into(),
            }),
            ..Symbol::default()
        }
    }

    fn elf(needed: &[&str], symbols: Vec<Symbol>) -> Container {
        Container {
            format: Format::Elf,
            libraries: needed.iter().map(|name| (*name).to_owned()).collect(),
            symbols,
            ..Container::default()
        }
    }

    fn imports(container: &Container, library: CLibrary) -> Imports {
        Imports::new(
            LibraryRows::embedded(library),
            library,
            Linkage::of(container),
        )
    }

    /// A versioned import binds to the library its version names, whatever else is linked.
    #[test]
    fn a_versioned_import_binds_to_the_library_its_version_names() {
        let container = elf(
            &["libz.so.1", "libc.so.6", "libstdc++.so.6"],
            vec![
                import("__assert_fail", Some(("libc.so.6", "GLIBC_2.2.5"))),
                import("printf", Some(("libc.so.6", "GLIBC_2.2.5"))),
                import("__cxa_throw", Some(("libstdc++.so.6", "CXXABI_1.3"))),
                import("deflate", Some(("libz.so.1", "ZLIB_1.2.0"))),
                import("compress", None),
            ],
        );
        let imports = imports(&container, CLibrary::Glibc);
        let library = |name| imports.bind(name).map(|row| row.library);
        assert_eq!(library("__assert_fail"), Ok(LibraryId::Glibc));
        assert_eq!(library("printf"), Ok(LibraryId::Portable));
        assert_eq!(library("__cxa_throw"), Ok(LibraryId::CxxRuntime));
        assert!(library("deflate").is_err());
        // Unversioned beside three libraries: any of them could define it, so no row applies.
        assert!(library("compress").is_err());
        assert!(library("puts").is_err());
        // A version need on a file DT_NEEDED does not name states no library the loader binds.
        let unneeded = elf(
            &["libc.so.6"],
            vec![import("printf", Some(("libc.so.7", "GLIBC_2.2.5")))],
        );
        assert!(
            super::tests::imports(&unneeded, CLibrary::Glibc)
                .bind("printf")
                .is_err()
        );
    }

    /// A PE import binds the table of the DLL it names; a DLL no cited table states binds nothing.
    #[test]
    fn a_pe_import_binds_the_dll_it_names() {
        let pe = |dll: &str, name: &str| Symbol {
            library: Some(dll.into()),
            ..import(name, None)
        };
        let container = Container {
            format: Format::Pe,
            symbols: vec![
                pe("KERNEL32.dll", "GetLastError"),
                pe("KERNEL32.dll", "puts"),
                pe("api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfprintf"),
                pe("api-ms-win-crt-stdio-l1-1-0.dll", "fputs"),
                pe("msvcrt.dll", "strlen"),
                pe("KERNEL32.dll", "Ordinal_123"),
                pe("KERNEL32.dll", "GetTickCount"),
                pe("msvcrt.dll", "GetTickCount"),
            ],
            ..Container::default()
        };
        let imports = imports(&container, CLibrary::Ucrt);
        let library = |name| imports.bind(name).map(|row| row.library);
        let dll = LibraryId::Dll;
        assert_eq!(library("GetLastError"), Ok(dll(r2abi::Dll::Kernel32)));
        assert!(library("puts").is_err(), "KERNEL32 exports no puts");
        let vfprintf = library("__stdio_common_vfprintf");
        assert_eq!(vfprintf, Ok(dll(r2abi::Dll::Ucrt)));
        assert_eq!(library("fputs"), Ok(LibraryId::Portable));
        // msvcrt.dll is no DLL a cited table states, whatever its exports are named.
        assert!(library("strlen").is_err());
        // By ordinal, the import states no name a row is keyed by.
        assert!(library("Ordinal_123").is_err());
        // One name from two DLLs: no one library is stated for it.
        assert!(library("GetTickCount").is_err());
    }

    /// A Mach-O import binds the dylib its two-level namespace ordinal names; a flat namespace
    /// names none, and a mangled name states its own parameters whatever defines it.
    #[test]
    fn a_mach_o_import_binds_the_dylib_its_ordinal_names() {
        let macho = |dylib: Option<&str>, name: &str| Symbol {
            library: dylib.map(Into::into),
            ..import(name, None)
        };
        let container = Container {
            format: Format::MachO,
            symbols: vec![
                macho(Some("/usr/lib/libSystem.B.dylib"), "puts"),
                macho(Some("/usr/lib/libz.1.dylib"), "strlen"),
                macho(None, "fputs"),
                macho(Some("/usr/lib/libc++.1.dylib"), "__cxa_throw"),
                macho(Some("/opt/lib/libfoo.dylib"), "_Z3bari"),
                macho(Some("/opt/lib/libSystem.B.dylib"), "fgets"),
                macho(Some("/usr/lib/libobjc.A.dylib"), "objc_msgSend"),
                macho(Some("/usr/lib/libobjc.A.dylib"), "strcpy"),
                macho(Some("/usr/lib/libSystem.B.dylib"), "objc_retain"),
            ],
            ..Container::default()
        };
        let mut rows = LibraryRows::embedded(CLibrary::LibSystem);
        rows.read_mangled(["_Z3bari"]);
        let imports = Imports::new(rows, CLibrary::LibSystem, Linkage::of(&container));
        let library = |name| imports.bind(name).map(|row| row.library);
        assert_eq!(library("puts"), Ok(LibraryId::Portable));
        assert!(library("strlen").is_err(), "libz is no table's");
        assert!(library("fputs").is_err(), "a flat namespace names no dylib");
        assert_eq!(library("__cxa_throw"), Ok(LibraryId::CxxRuntime));
        assert_eq!(library("_Z3bari"), Ok(LibraryId::Itanium));
        assert!(
            library("fgets").is_err(),
            "another file of libSystem's name"
        );
        assert_eq!(library("objc_msgSend"), Ok(LibraryId::Objc));
        assert!(library("strcpy").is_err(), "libobjc exports no strcpy");
        assert!(library("objc_retain").is_err(), "libSystem exports none");
    }

    /// With no C library named, or two, an unversioned import binds to nothing.
    #[test]
    fn an_unversioned_import_binds_only_where_one_c_library_is_named() {
        let none = elf(&["libfoo.so"], vec![import("puts", None)]);
        assert!(imports(&none, CLibrary::Glibc).bind("puts").is_err());
        let beside = elf(&["libz.so.1", "libc.so.6"], vec![import("puts", None)]);
        assert!(imports(&beside, CLibrary::Glibc).bind("puts").is_err());
        let only = elf(&["libc.so.6"], vec![import("puts", None)]);
        assert!(imports(&only, CLibrary::Glibc).bind("puts").is_ok());
        let two = elf(&["libc.so.6", "libc.so"], vec![import("puts", None)]);
        assert!(imports(&two, CLibrary::Glibc).bind("puts").is_err());
        let musl = elf(&["libc.musl-x86_64.so.1"], vec![import("puts", None)]);
        assert!(imports(&musl, CLibrary::Musl).bind("puts").is_ok());
        // A glibc version on a program another library's evidence names binds nothing.
        let crossed = elf(
            &["libc.so.6"],
            vec![import("printf", Some(("libc.so.6", "GLIBC_2.2.5")))],
        );
        assert!(imports(&crossed, CLibrary::Bionic).bind("printf").is_err());
    }
}
