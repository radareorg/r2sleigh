//! Which library row an import binds: by its version, else at `Declared` where the container names
//! one C library; never to a body by name (doc/adr-call-boundary.md, Refusals "A library row").

use std::collections::BTreeMap;

use r2abi::statement::{Container, Format, SymbolVersion};
use r2abi::{CLibrary, LibraryId, LibraryRow, LibraryRows};

/// The rows one program's C library states, and how its container says each import binds.
#[derive(Debug, Clone)]
pub struct Imports {
    rows: LibraryRows,
    library: CLibrary,
    linkage: Linkage,
}

/// What the container states about how its imports bind.
#[derive(Debug, Clone, Default)]
pub struct Linkage {
    /// Each versioned import by linked name; an import absent here states no version.
    versions: BTreeMap<Box<str>, Stated>,
    /// Each PE import by name, and the DLL a cited table states for it; `None` where two
    /// imports of the name name two DLLs.
    dlls: BTreeMap<Box<str>, Option<r2abi::Dll>>,
    /// Whether an unversioned import binds: `DT_NEEDED` names exactly one C library, or the
    /// format is one library's (Mach-O's libSystem, a PE's Microsoft runtime).
    one_c_library: bool,
}

/// The version the container states for one import name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stated {
    Versioned(SymbolVersion),
    /// Two symbols of the name state two versions.
    Conflicting,
}

impl Linkage {
    /// What `container` states, read once per program: O(symbols + needed libraries).
    pub fn of(container: &Container) -> Self {
        let mut versions: BTreeMap<Box<str>, Stated> = BTreeMap::new();
        let imports = container.symbols.iter().filter(|symbol| symbol.import);
        for (symbol, version) in imports.filter_map(|s| Some((s, s.version.clone()?))) {
            let stated = Stated::Versioned(version);
            let held = versions.entry(symbol.name.as_ref().into());
            let held = held.or_insert_with(|| stated.clone());
            if *held != stated {
                *held = Stated::Conflicting;
            }
        }
        let mut dlls: BTreeMap<Box<str>, Option<r2abi::Dll>> = BTreeMap::new();
        let pe = matches!(container.format, Format::Pe);
        for symbol in container
            .symbols
            .iter()
            .filter(|symbol| pe && symbol.import)
        {
            let dll = symbol.library.as_deref().and_then(r2abi::Dll::of);
            let held = dlls.entry(symbol.name.as_ref().into()).or_insert(dll);
            if *held != dll {
                *held = None;
            }
        }
        let one_c_library = match container.format {
            Format::MachO | Format::Pe => true,
            Format::Elf => {
                let named = container.libraries.iter();
                named.filter(|library| is_c_library(library)).count() == 1
            }
            _ => false,
        };
        Self {
            versions,
            dlls,
            one_c_library,
        }
    }

    /// No version stated and one C library named: every import binds at `Declared`.
    pub fn one_c_library() -> Self {
        Self {
            versions: BTreeMap::new(),
            dlls: BTreeMap::new(),
            one_c_library: true,
        }
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
    /// the container states as an import (`Program::import_at`); a body's name binds nothing.
    pub fn bind(&self, name: &str) -> Result<&LibraryRow, &'static str> {
        let scope = self.scope(name)?;
        (self.rows.find(scope, name)).ok_or("no row of the library it binds states this name")
    }

    /// The row the import binds, with the refusal stated as evidence.
    pub fn row(&self, name: &str) -> Option<&LibraryRow> {
        self.bind(name)
            .inspect_err(|why| r2il::refusal_evidence!("library-row", "{name}: {why}"))
            .ok()
    }

    fn scope(&self, name: &str) -> Result<&'static [LibraryId], &'static str> {
        // A PE import binds by the DLL it names (doc/adr-call-boundary.md, S13).
        match self.linkage.dlls.get(name) {
            Some(Some(r2abi::Dll::Kernel32)) => return Ok(KERNEL32),
            Some(Some(r2abi::Dll::Ucrt)) => return Ok(UCRT),
            Some(None) | None => {}
        }
        match self.linkage.versions.get(name) {
            Some(Stated::Versioned(SymbolVersion::Needed { library, version })) => {
                if versioned_runtime(version) {
                    return Ok(CXX_RUNTIME);
                }
                match versioned_library(library, version) {
                    Some(named) if named == self.library => Ok(named.scope()),
                    Some(_) => Err("its version names a C library the program does not run on"),
                    None => Err("its version names a library no table states"),
                }
            }
            Some(Stated::Conflicting) => Err("two symbols of this name state two versions"),
            Some(Stated::Versioned(SymbolVersion::Defined { .. })) | None => {
                match self.linkage.one_c_library {
                    true => Ok(self.library.scope()),
                    false => Err("it is unversioned and the container names no one C library"),
                }
            }
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
        // libc.so.6 is the one C library DT_NEEDED names, so an unversioned import binds.
        assert!(library("compress").is_err(), "no row states it");
        assert_eq!(library("puts"), Ok(LibraryId::Portable));
    }

    /// A PE import binds the table of the DLL it names; a DLL no table states binds as before.
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
        assert_eq!(library("strlen"), Ok(LibraryId::Portable));
    }

    /// With no C library named, or two, an unversioned import binds to nothing.
    #[test]
    fn an_unversioned_import_binds_only_where_one_c_library_is_named() {
        let none = elf(&["libfoo.so"], vec![import("puts", None)]);
        assert!(imports(&none, CLibrary::Glibc).bind("puts").is_err());
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
