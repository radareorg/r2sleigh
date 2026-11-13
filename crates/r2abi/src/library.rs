//! Library rows parsed once into [`LibraryRow`]s keyed by `(LibraryId, linked_name)`, each with the
//! [`Tail`] its citation states (doc/adr-call-boundary.md; tables kept per `data/README.md`).

use std::collections::BTreeMap;

use crate::prototypes::{Parameter, Prototype, Spelled};
use crate::types::TypeGraph;

/// The C library a program runs against: it picks the rows, the type names and the data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CLibrary {
    Glibc,
    Bionic,
    /// musl, whose cited table is small: it reads the portable rows besides.
    Musl,
    /// Apple's libSystem, which every Mach-O links.
    LibSystem,
    /// Microsoft's C runtime, which a PE reads.
    Ucrt,
    Unknown,
}

/// The kernel a program traps into: it picks the system calls, the reserved registers and the
/// default convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kernel {
    Linux,
    Darwin,
    Windows,
    Unknown,
}

/// Who declares a row: the scope one table states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LibraryId {
    /// Declared alike by glibc, bionic and libSystem; the citation names ISO C or POSIX.
    Portable,
    Glibc,
    Bionic,
    Musl,
    LibSystem,
    /// objc4's runtime, `libobjc.A.dylib`: bound only by an import that names that dylib.
    Objc,
    /// The Itanium C++ ABI runtime and libstdc++'s exports, read beside every C library.
    CxxRuntime,
    /// Rows read from an import's mangled name: the ABI's statement, whichever library defines it.
    Itanium,
    /// A Windows DLL's own rows, bound by the DLL a PE import names.
    Dll(Dll),
}

/// A DLL whose exports a cited table states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dll {
    Kernel32,
    /// The Universal C Runtime: `ucrtbase.dll`, its debug build `ucrtbased.dll` (Microsoft, "C
    /// runtime (CRT) and C++ standard library (STL) lib files") and the `api-ms-win-crt-*` sets.
    Ucrt,
}

impl Dll {
    /// The DLL a PE import names, matched as Windows matches a module name: ignoring case.
    pub fn of(module: &str) -> Option<Self> {
        let module = module.to_ascii_lowercase();
        match module.as_str() {
            "kernel32.dll" => Some(Self::Kernel32),
            "ucrtbase.dll" | "ucrtbased.dll" => Some(Self::Ucrt),
            _ if module.starts_with("api-ms-win-crt-") && module.ends_with(".dll") => {
                Some(Self::Ucrt)
            }
            _ => None,
        }
    }
}

/// How a format parameter's conversions consume the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Printf,
    Scanf,
    /// A `wchar_t` format (ISO C17 7.29.2), which no format reader here reads.
    WidePrintf,
    WideScanf,
}

/// What a row's citation states past its fixed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    /// The citation states a fixed prototype: the call reads its fixed locations only.
    None,
    /// No citation: the call may read every argument location of its convention.
    Unstated,
    /// `...` with nothing in the prototype that counts it.
    Variadic,
    /// `...` counted by the format at this fixed parameter.
    Format { index: u8, kind: FormatKind },
    /// A `va_list` at this fixed parameter carries the tail, counted by the format the citation
    /// names, where it names one (`vfprintf`'s GCC `format(printf, 2, 0)`).
    VaList {
        index: u8,
        format: Option<(u8, FormatKind)>,
    },
    /// `...` the library's body reads `then` arguments of where the flag at this fixed parameter
    /// passes `test`, and none where it does not (glibc `open`'s mode).
    Flagged { index: u8, test: FlagTest, then: u8 },
}

/// A test a library body makes of a flag argument before it reads its tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagTest {
    /// glibc's `__OPEN_NEEDS_MODE` (`<fcntl.h>`): `O_CREAT`, or every bit of `__O_TMPFILE`.
    OpenNeedsMode,
}

/// A flag passes where it holds any bit of `any` or every bit of `all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagBits {
    pub any: u64,
    pub all: u64,
}

impl FlagTest {
    /// The bits the test reads for this C library on this architecture, where a header read
    /// states them. O(1).
    pub fn bits(self, library: CLibrary, arch: &str, bits: u32) -> Option<FlagBits> {
        // glibc 2.39 `bits/fcntl-linux.h`: `O_CREAT` 0100, `__O_TMPFILE` (020000000 |
        // __O_DIRECTORY); `__O_DIRECTORY` 0200000 there and 040000 in aarch64's `bits/fcntl.h`.
        let directory = match (self, library, crate::family(arch), bits) {
            (Self::OpenNeedsMode, CLibrary::Glibc, Some("x86"), 64) => 0o200000,
            (Self::OpenNeedsMode, CLibrary::Glibc, Some("arm"), 64) => 0o40000,
            _ => return None,
        };
        Some(FlagBits {
            any: 0o100,
            all: 0o20000000 | directory,
        })
    }
}

impl Tail {
    /// Whether a call may read argument locations past the fixed ones: a lower bound unless the
    /// citation states a fixed prototype (doc/adr-call-boundary.md, "Lower bounds").
    pub const fn reads_past_fixed(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The format parameter the printf reader counts the tail from. A scanf format consumes
    /// arguments differently (`%*d`), so it states none until a scanf reader exists.
    pub const fn printf_format(self) -> Option<u8> {
        match self {
            Self::Format {
                index,
                kind: FormatKind::Printf,
            }
            | Self::VaList {
                format: Some((index, FormatKind::Printf)),
                ..
            } => Some(index),
            _ => None,
        }
    }
}

/// A prototype in a [`LibraryRows`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrototypeId(u32);

/// One library function as its table states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryRow {
    pub library: LibraryId,
    pub linked_name: Box<str>,
    pub prototype: PrototypeId,
    pub tail: Tail,
    /// Whether the parameters are all a call passes before its arguments: a row read from a
    /// mangled name may not know of a hidden result pointer or a VTT.
    pub passing: crate::mangled::Passing,
    /// Whether the row states what the function returns.
    pub result: RowResult,
    pub noreturn: bool,
    /// A parameter that, holding this handle, makes the call not return.
    pub halts_on: Option<(u8, Handle)>,
    /// The handle the result always is.
    pub yields: Option<Handle>,
    /// The standard and header the row is read from; empty for a row radare2's tables state.
    pub citation: Box<str>,
}

/// Whether a row states its function's result (doc/adr-result-side.md, "Imports with an unstated result").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowResult {
    /// The row's return type is the function's, `void` included.
    Stated,
    /// The row is read from a mangled name, which states parameters only.
    Unstated,
}

/// A handle a Microsoft row names by what it refers to, not by its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handle {
    /// The calling process's own handle, as `GetCurrentProcess` returns it.
    CurrentProcess,
}

impl Handle {
    fn read(text: &str) -> Option<Self> {
        (text == "current-process").then_some(Self::CurrentProcess)
    }
}

/// Every row one C library's program reads, and the graph their types are nodes of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryRows {
    library: CLibrary,
    graph: TypeGraph,
    prototypes: Vec<Prototype>,
    rows: BTreeMap<LibraryId, BTreeMap<Box<str>, LibraryRow>>,
}

const PORTABLE: &str = include_str!("../data/types.sdb.txt");
/// ISO C, POSIX and BSD rows, each citing its header (`data/README.md`, "Cited rows").
const PORTABLE_CITED: &str = include_str!("../data/types-posix.sdb.txt");
const CXX: &str = include_str!("../data/types-cxx.sdb.txt");
const CXX_CITED: &str = include_str!("../data/types-cxx-cited.sdb.txt");
const GLIBC: &str = include_str!("../data/types-linux.sdb.txt");
const GLIBC_CITED: &str = include_str!("../data/types-glibc.sdb.txt");
const BIONIC: &str = include_str!("../data/types-android.sdb.txt");
const BIONIC_CITED: &str = include_str!("../data/types-bionic.sdb.txt");
const MUSL_CITED: &str = include_str!("../data/types-musl.sdb.txt");
const LIBSYSTEM: &str = include_str!("../data/types-darwin.sdb.txt");
const OBJC: &str = include_str!("../data/types-objc.sdb.txt");
const KERNEL32: &str = include_str!("../data/types-kernel32.sdb.txt");
const UCRT: &str = include_str!("../data/types-ucrt.sdb.txt");
/// Whether a mangled member takes `this` where its name leaves it open, by the header declaring it.
const CXX_OBJECTS: &str = include_str!("../data/cxx-objects.txt");

/// One embedded table: whose rows, whether each row cites its source, and the text.
struct Embedded {
    library: LibraryId,
    cited: bool,
    text: &'static str,
}

const fn table(library: LibraryId, cited: bool, text: &'static str) -> Embedded {
    Embedded {
        library,
        cited,
        text,
    }
}

/// The sources a cited row's comment may name.
pub const SOURCES: [&str; 11] = [
    "ISO C17",
    "POSIX.1-2017",
    "POSIX.1-2024",
    "4.4BSD",
    "glibc",
    "LSB 5.0",
    "GCC",
    "bionic",
    "musl",
    "Microsoft",
    "Itanium C++ ABI",
];

/// What a row read from a mangled name cites.
const MANGLING: &str = "Itanium C++ ABI 5.1, the mangled name";

impl CLibrary {
    /// The libraries whose rows an import bound to this C library reads, the library's own first.
    pub const fn scope(self) -> &'static [LibraryId] {
        use LibraryId::{CxxRuntime, Portable};
        match self {
            Self::Glibc => &[LibraryId::Glibc, CxxRuntime, Portable],
            Self::Bionic => &[LibraryId::Bionic, CxxRuntime, Portable],
            Self::LibSystem => &[LibraryId::LibSystem, CxxRuntime, Portable],
            Self::Musl => &[LibraryId::Musl, CxxRuntime, Portable],
            Self::Ucrt | Self::Unknown => &[CxxRuntime, Portable],
        }
    }
}

impl Default for LibraryRows {
    fn default() -> Self {
        Self {
            library: CLibrary::Unknown,
            graph: TypeGraph::default(),
            prototypes: Vec::new(),
            rows: BTreeMap::new(),
        }
    }
}

impl LibraryRows {
    /// The rows a program on this C library can bind, each table read once.
    pub fn embedded(library: CLibrary) -> Self {
        use LibraryId::{Bionic, CxxRuntime, Glibc, LibSystem, Musl, Portable};
        let own: &[Embedded] = match library {
            CLibrary::Glibc => &[table(Glibc, false, GLIBC), table(Glibc, true, GLIBC_CITED)],
            CLibrary::Bionic => &[
                table(Bionic, false, BIONIC),
                table(Bionic, true, BIONIC_CITED),
            ],
            CLibrary::LibSystem => &[
                table(LibSystem, false, LIBSYSTEM),
                table(LibraryId::Objc, false, OBJC),
            ],
            CLibrary::Ucrt => &[
                table(LibraryId::Dll(Dll::Kernel32), true, KERNEL32),
                table(LibraryId::Dll(Dll::Ucrt), true, UCRT),
            ],
            CLibrary::Musl => &[table(Musl, true, MUSL_CITED)],
            CLibrary::Unknown => &[],
        };
        let shared = [
            table(Portable, false, PORTABLE),
            table(Portable, true, PORTABLE_CITED),
            table(CxxRuntime, false, CXX),
            table(CxxRuntime, true, CXX_CITED),
        ];
        let mut rows = Self {
            library,
            ..Self::default()
        };
        for embedded in shared.iter().chain(own) {
            rows.read(embedded, library);
        }
        rows
    }

    /// One uncited table's rows under `library`, for a test that states its own.
    pub fn parse(library: LibraryId, text: &str) -> Self {
        let mut rows = Self::default();
        let embedded = Embedded {
            library,
            cited: false,
            text: "",
        };
        rows.read_text(&embedded, text, CLibrary::Unknown);
        rows
    }

    /// A row for each mangled name, where the name states its parameters and, for a member,
    /// whether it takes `this`: O(names x name length).
    pub fn read_mangled<'a>(&mut self, names: impl IntoIterator<Item = &'a str>) {
        let objects = CxxObjects::read(CXX_OBJECTS);
        for name in names {
            if let Some(row) = self.mangled(name, &objects) {
                let rows = self.rows.entry(LibraryId::Itanium).or_default();
                rows.insert(name.into(), row);
            }
        }
    }

    /// The parameters only: a mangled name states no result, so the return type is refused.
    fn mangled(&mut self, name: &str, objects: &CxxObjects) -> Option<LibraryRow> {
        use crate::mangled::Object;
        let mangled = crate::mangled::parse(name)?;
        let (this, citation) = match mangled.object {
            Object::None => (None, MANGLING.to_owned()),
            Object::This(this) => (Some(this), MANGLING.to_owned()),
            Object::Unstated(this) => {
                let (takes, header) = objects.get(name)?;
                let takes = *takes;
                (takes.then_some(this), format!("{MANGLING}; {header}"))
            }
        };
        let library = self.library;
        let object = this.map(|this| (this, Some("this")));
        let explicit = mangled
            .parameters
            .into_iter()
            .map(|spelling| (spelling, None));
        let parameters = object.into_iter().chain(explicit);
        let parameters = parameters
            .map(|(spelling, called)| {
                let ty = crate::spelling::read(&spelling, &mut self.graph, library);
                Parameter::new(ty, spelling, called)
            })
            .collect();
        let return_type = self
            .graph
            .refused("a mangled name states no result".to_owned());
        let id = PrototypeId(u32::try_from(self.prototypes.len()).unwrap_or(u32::MAX));
        self.prototypes.push(Prototype {
            name: name.to_owned(),
            parameters,
            returns: Spelled::from(""),
            return_type,
            variadic: mangled.variadic,
            ..Prototype::default()
        });
        Some(LibraryRow {
            library: LibraryId::Itanium,
            linked_name: name.into(),
            prototype: id,
            tail: match mangled.variadic {
                true => Tail::Variadic,
                false => Tail::None,
            },
            passing: mangled.passing,
            result: RowResult::Unstated,
            noreturn: false,
            halts_on: None,
            yields: None,
            citation: citation.into(),
        })
    }

    fn read(&mut self, embedded: &Embedded, library: CLibrary) {
        self.read_text(embedded, embedded.text, library);
    }

    fn read_text(&mut self, embedded: &Embedded, text: &str, library: CLibrary) {
        for (name, declared) in Table::read(text).functions {
            let row = self.typed(&name, declared, embedded, library);
            (self.rows.entry(embedded.library).or_default()).insert(name.into(), row);
        }
    }

    /// One row's spellings, read into this table's graph.
    fn typed(
        &mut self,
        name: &str,
        declared: Declared,
        embedded: &Embedded,
        library: CLibrary,
    ) -> LibraryRow {
        let mut read = |spelling: &str| crate::spelling::read(spelling, &mut self.graph, library);
        let returns = declared.returns.unwrap_or_else(|| "void".to_owned());
        let return_type = read(&returns);
        let mut parameters = Vec::new();
        let mut variadic = false;
        for (spelling, called) in declared.parameters.into_values() {
            // An empty spelling is the ellipsis.
            if spelling.is_empty() {
                variadic = true;
                break;
            }
            let called = called.filter(|called| !called.is_empty());
            parameters.push(Parameter::new(read(&spelling), spelling, called));
        }
        let tail = match (embedded.cited, declared.tail.as_deref()) {
            (false, _) => Tail::Unstated,
            (true, None) if !variadic => Tail::None,
            (true, None) => Tail::Unstated,
            (true, Some(tail)) => parse_tail(tail).unwrap_or(Tail::Unstated),
        };
        let citation = match (embedded.cited, declared.include) {
            (true, Some(header)) => {
                let source = declared.source.unwrap_or("?");
                match declared.cite {
                    Some(page) => format!("{source}, <{header}>, {page}"),
                    None => format!("{source}, <{header}>"),
                }
            }
            // A binary-only interface (LSB's `__stack_chk_fail`) has no header: its section is cited.
            (true, None) => match (declared.source, declared.cite) {
                (Some(source), Some(page)) => format!("{source}, {page}"),
                _ => String::new(),
            },
            _ => String::new(),
        };
        let id = PrototypeId(u32::try_from(self.prototypes.len()).unwrap_or(u32::MAX));
        self.prototypes.push(Prototype {
            name: name.to_owned(),
            parameters,
            returns: Spelled::from(returns),
            return_type,
            variadic,
            ..Prototype::default()
        });
        LibraryRow {
            library: embedded.library,
            linked_name: name.into(),
            prototype: id,
            tail,
            passing: crate::mangled::Passing::Stated,
            result: RowResult::Stated,
            noreturn: declared.noreturn,
            halts_on: declared.halts_on,
            yields: declared.yields,
            citation: citation.into(),
        }
    }

    /// The row `library` states for exactly this linked name: nothing is stripped to match.
    pub fn row(&self, library: LibraryId, name: &str) -> Option<&LibraryRow> {
        self.rows.get(&library)?.get(name)
    }

    /// The first row a scope states for the name, in the scope's order.
    pub fn find(&self, scope: &[LibraryId], name: &str) -> Option<&LibraryRow> {
        scope.iter().find_map(|library| self.row(*library, name))
    }

    pub fn prototype(&self, row: &LibraryRow) -> &Prototype {
        &self.prototypes[row.prototype.0 as usize]
    }

    /// The graph every prototype here names its types in.
    pub fn graph(&self) -> &TypeGraph {
        &self.graph
    }

    /// Every row, by library and then name.
    pub fn rows(&self) -> impl Iterator<Item = &LibraryRow> {
        self.rows.values().flat_map(BTreeMap::values)
    }

    pub fn len(&self) -> usize {
        self.rows.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `none`, `variadic`, `format(printf,2)`, `va_list(2)`, `va_list(2,printf,1)` or
/// `flagged(1,open_needs_mode,1)`.
/// The last comma outside parentheses: where a row's parameter name begins.
fn outer_comma(value: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut last = None;
    for (at, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => last = Some(at),
            _ => {}
        }
    }
    last
}

fn parse_tail(text: &str) -> Option<Tail> {
    let text = text.trim();
    let call = |name: &str| {
        text.strip_prefix(name)?
            .strip_prefix('(')?
            .strip_suffix(')')
    };
    let format = |kind: &str, index: &str| {
        let kind = match kind.trim() {
            "printf" => FormatKind::Printf,
            "scanf" => FormatKind::Scanf,
            "wprintf" => FormatKind::WidePrintf,
            "wscanf" => FormatKind::WideScanf,
            _ => return None,
        };
        Some((index.trim().parse().ok()?, kind))
    };
    if let Some(arguments) = call("format") {
        let (kind, index) = arguments.split_once(',')?;
        let (index, kind) = format(kind, index)?;
        return Some(Tail::Format { index, kind });
    }
    if let Some(arguments) = call("flagged") {
        let mut parts = arguments.split(',').map(str::trim);
        let index = parts.next()?.parse().ok()?;
        let test = match parts.next()? {
            "open_needs_mode" => FlagTest::OpenNeedsMode,
            _ => return None,
        };
        let then = parts.next()?.parse().ok()?;
        return parts
            .next()
            .is_none()
            .then_some(Tail::Flagged { index, test, then });
    }
    if let Some(arguments) = call("va_list") {
        let mut parts = arguments.splitn(3, ',');
        let index = parts.next()?.trim().parse().ok()?;
        let format = match (parts.next(), parts.next()) {
            (Some(kind), Some(at)) => Some(format(kind, at)?),
            (None, None) => None,
            _ => return None,
        };
        return Some(Tail::VaList { index, format });
    }
    match text {
        "none" => Some(Tail::None),
        "variadic" => Some(Tail::Variadic),
        _ => None,
    }
}

/// One function as the table spells it, before its types are read.
#[derive(Debug, Default)]
struct Declared {
    parameters: BTreeMap<usize, (String, Option<String>)>,
    returns: Option<String>,
    noreturn: bool,
    halts_on: Option<(u8, Handle)>,
    yields: Option<Handle>,
    include: Option<String>,
    /// The reference page and minimum version a Microsoft row cites.
    cite: Option<String>,
    tail: Option<String>,
    /// The first source the comment above the row names.
    source: Option<&'static str>,
}

/// `cxx-objects.txt`: each mangled member whose name leaves `this` open, and the header that says.
struct CxxObjects(BTreeMap<&'static str, (bool, String)>);

impl CxxObjects {
    /// `name | this|none | header`, under a comment naming the library; O(lines).
    fn read(text: &'static str) -> Self {
        let mut objects = BTreeMap::new();
        let (mut library, mut in_comment) = ("", false);
        for line in text.lines().map(str::trim) {
            // A block's first line names the library before its colon.
            let comment = line.strip_prefix('#');
            if let (Some(comment), false) = (comment, in_comment) {
                library = comment.split(':').next().unwrap_or_default().trim();
            }
            in_comment = comment.is_some();
            if in_comment {
                continue;
            }
            let mut fields = line.split('|').map(str::trim);
            let (Some(name), Some(object), Some(header)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let takes = match object {
                "this" => true,
                "none" => false,
                _ => continue,
            };
            objects.insert(name, (takes, format!("{library} <{header}>")));
        }
        Self(objects)
    }

    fn get(&self, name: &str) -> Option<&(bool, String)> {
        self.0.get(name)
    }
}

/// The functions one `sdb` dump declares.
#[derive(Debug, Default)]
struct Table {
    functions: BTreeMap<String, Declared>,
}

impl Table {
    fn read(text: &str) -> Self {
        let mut table = Self::default();
        let mut comment = String::new();
        let mut in_comment = false;
        for line in text.lines().map(str::trim) {
            // A comment block names the source of the rows below it until the next block.
            let words = line.strip_prefix('#');
            if words.is_some() && !in_comment {
                comment.clear();
            }
            in_comment = words.is_some();
            if let Some(words) = words {
                comment.push_str(words);
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if value == "func" {
                let source = SOURCES.into_iter().find(|source| comment.contains(source));
                table.declare(key).source = source;
                continue;
            }
            let Some((name, what)) = key.strip_prefix("func.").and_then(|r| r.rsplit_once('.'))
            else {
                continue;
            };
            table.take(name, what, value.trim());
        }
        table
    }

    fn take(&mut self, name: &str, what: &str, value: &str) {
        // `func.<name>.arg.<index>=<type>,<parameter name>`.
        if let Some(name) = name.strip_suffix(".arg") {
            let Ok(index) = what.parse::<usize>() else {
                return;
            };
            // A code pointer's spelling holds commas inside its parentheses: the name follows the last outside them.
            let (spelling, called) = match outer_comma(value).map(|at| value.split_at(at)) {
                Some((spelling, called)) => (spelling.trim(), Some(called[1..].trim().to_owned())),
                None => (value, None),
            };
            (self.declare(name).parameters).insert(index, (spelling.to_owned(), called));
            return;
        }
        let declared = self.declare(name);
        match what {
            "ret" => declared.returns = Some(value.to_owned()),
            "noreturn" => declared.noreturn = value == "true",
            "yields" => declared.yields = Handle::read(value),
            "halts_on" => {
                declared.halts_on = value.split_once(',').and_then(|(index, handle)| {
                    Some((index.trim().parse().ok()?, Handle::read(handle.trim())?))
                });
            }
            "include" => declared.include = Some(value.to_owned()),
            "cite" => declared.cite = Some(value.to_owned()),
            "tail" => declared.tail = Some(value.to_owned()),
            _ => {}
        }
    }

    fn declare(&mut self, name: &str) -> &mut Declared {
        self.functions.entry(name.to_owned()).or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tail_reads_as_its_citation_spells_it() {
        assert_eq!(parse_tail("none"), Some(Tail::None));
        assert_eq!(parse_tail("variadic"), Some(Tail::Variadic));
        assert_eq!(
            parse_tail("format(printf, 2)"),
            Some(Tail::Format {
                index: 2,
                kind: FormatKind::Printf
            })
        );
        assert_eq!(
            parse_tail("va_list(1)"),
            Some(Tail::VaList {
                index: 1,
                format: None
            })
        );
        assert_eq!(
            parse_tail("flagged(1, open_needs_mode, 1)"),
            Some(Tail::Flagged {
                index: 1,
                test: FlagTest::OpenNeedsMode,
                then: 1
            })
        );
        assert_eq!(parse_tail("flagged(1,o_creat,1)"), None);
        let vfprintf = parse_tail("va_list(2,printf,1)").expect("vfprintf");
        assert_eq!(vfprintf.printf_format(), Some(1));
        assert_eq!(parse_tail("format(strftime,1)"), None);
        assert!(!Tail::None.reads_past_fixed());
        assert!(Tail::Unstated.reads_past_fixed());
        let wide = Tail::Format {
            index: 0,
            kind: FormatKind::WidePrintf,
        };
        assert_eq!(wide.printf_format(), None);
        let scanf = Tail::Format {
            index: 1,
            kind: FormatKind::Scanf,
        };
        assert_eq!(
            scanf.printf_format(),
            None,
            "`%*d %d` reads one argument, printf counts three"
        );
    }

    /// A row of an uncited table is `Unstated` whatever it spells; the cited one states its tail.
    #[test]
    fn only_a_cited_row_states_its_tail() {
        let glibc = LibraryRows::embedded(CLibrary::Glibc);
        let gettext = (glibc.row(LibraryId::Portable, "dcgettext")).expect("dcgettext");
        assert_eq!((gettext.tail, &*gettext.citation), (Tail::Unstated, ""));
        let puts = glibc.row(LibraryId::Portable, "puts").expect("puts");
        assert_eq!(puts.tail, Tail::None);
        assert!(puts.citation.contains("ISO C17"), "{}", puts.citation);
        let printf = glibc.row(LibraryId::Portable, "printf").expect("printf");
        assert_eq!(printf.tail.printf_format(), Some(0));
        assert!(printf.citation.contains("ISO C17"), "{}", printf.citation);
        let closedir = glibc
            .row(LibraryId::Portable, "closedir")
            .expect("closedir");
        assert_eq!(closedir.tail, Tail::None);
        assert!(glibc.prototype(printf).variadic);
    }

    fn spelled(rows: &LibraryRows, parameter: &Parameter) -> Option<String> {
        (rows.graph().spelled(parameter.ty)).map(|spelled| spelled.declared)
    }

    fn prototype<'a>(rows: &'a LibraryRows, library: CLibrary, name: &str) -> &'a Prototype {
        rows.prototype(rows.find(library.scope(), name).expect(name))
    }

    #[test]
    fn a_fixed_prototype_reads_whole() {
        let rows = LibraryRows::embedded(CLibrary::Unknown);
        let puts = prototype(&rows, CLibrary::Unknown, "puts");
        assert_eq!(puts.parameters.len(), 1);
        assert_eq!(puts.parameters[0].name.as_deref(), Some("s"));
        assert_eq!(
            spelled(&rows, &puts.parameters[0]).as_deref(),
            Some("const char *")
        );
        assert_eq!(puts.returns.as_written(), "int");
        assert!(!puts.variadic);
    }

    #[test]
    fn the_ellipsis_is_variadic_rather_than_a_parameter() {
        let rows = LibraryRows::embedded(CLibrary::Unknown);
        let printf = prototype(&rows, CLibrary::Unknown, "printf");
        assert_eq!(printf.parameters.len(), 1);
        assert_eq!(printf.parameters[0].name.as_deref(), Some("format"));
        assert!(printf.variadic);
    }

    /// objc4, Darwin's runtime: a message send passes whatever the method takes after `self` and
    /// `op`, and `objc_storeStrong` stores through a pointer (audit W10); only libobjc has it.
    #[test]
    fn the_objective_c_runtime_is_declared_as_objc4_declares_it() {
        let glibc = LibraryRows::embedded(CLibrary::Glibc);
        assert!(
            glibc
                .find(CLibrary::Glibc.scope(), "objc_storeStrong")
                .is_none()
        );
        let rows = LibraryRows::embedded(CLibrary::LibSystem);
        let libsystem = CLibrary::LibSystem.scope();
        assert!(rows.find(libsystem, "objc_msgSend").is_none());
        let objc = |name: &str| rows.prototype(rows.row(LibraryId::Objc, name).expect(name));
        let send = objc("objc_msgSend");
        assert_eq!(send.parameters.len(), 2);
        assert!(send.variadic);
        let store = objc("objc_storeStrong");
        let spellings: Vec<_> = (store.parameters.iter())
            .map(|parameter| spelled(&rows, parameter))
            .collect();
        assert_eq!(
            spellings,
            [Some("void **".to_owned()), Some("void *".to_owned())]
        );
        assert_eq!(store.returns.as_written(), "void");
        assert_eq!(objc("objc_retain").returns.as_written(), "void *");
    }

    /// The C++ runtime's rows (`types-cxx.sdb.txt`): operator new takes the width its mangling
    /// states, the ABI's throws never return, and a `z` in a mangling is the ellipsis.
    #[test]
    fn the_cxx_runtime_is_declared_as_its_mangling_and_the_abi_state() {
        let rows = LibraryRows::embedded(CLibrary::Unknown);
        let graph = rows.graph();
        let model = crate::CDataModel::unix(64);
        let row = |name: &str| rows.row(LibraryId::CxxRuntime, name).expect(name);
        let size = |name: &str| {
            let prototype = rows.prototype(row(name));
            let [size] = prototype.parameters.as_slice() else {
                panic!("{name}: {:?}", prototype.parameters);
            };
            let returns = prototype.returns.as_written().to_owned();
            (graph.size_bits(size.ty, &model), returns)
        };
        assert_eq!(size("_Znwm"), (Some(64), "void *".to_owned()));
        assert_eq!(size("_Znaj"), (Some(32), "void *".to_owned()));
        let sized = row("_ZdlPvm");
        assert_eq!(
            (rows.prototype(sized).parameters.len(), sized.noreturn),
            (2, false)
        );
        let atexit = rows.prototype(row("__cxa_atexit"));
        assert_eq!(atexit.parameters.len(), 3);
        assert_eq!(
            atexit.parameters[0].code_returns(graph),
            Some(crate::TypeId::VOID)
        );
        for name in [
            "__cxa_throw",
            "__cxa_rethrow",
            "_Unwind_Resume",
            "__cxa_pure_virtual",
            "_ZSt9terminatev",
            "_ZSt19__throw_logic_errorPKc",
        ] {
            assert!(row(name).noreturn, "{name}");
        }
        assert!(!row("__cxa_begin_catch").noreturn);
        let format = rows.prototype(row("_ZSt24__throw_out_of_range_fmtPKcz"));
        assert_eq!((format.parameters.len(), format.variadic), (1, true));
        let cxx = LibraryRows::parse(LibraryId::CxxRuntime, CXX);
        assert!(cxx.len() > 70, "{}", cxx.len());
        for row in cxx.rows() {
            for parameter in &cxx.prototype(row).parameters {
                let ty = cxx.graph().get(parameter.ty);
                assert!(
                    !matches!(ty, Some(crate::Type::Refused(_))),
                    "{}",
                    row.linked_name
                );
            }
        }
    }

    /// A mangled import's row states its parameters, `this` where the name or a cited header
    /// says, and no result; a member whose object nothing states gets no row.
    #[test]
    fn a_mangled_import_states_its_parameters_and_no_result() {
        let mut rows = LibraryRows::embedded(CLibrary::Glibc);
        let put = "_ZNSo3putEc";
        let now = "_ZNSt6chrono3_V212system_clock3nowEv";
        let open = "_ZN3Foo3barEi";
        rows.read_mangled([put, now, open, "_ZNSolsEi", "_Znwm", "main"]);
        let count = |name: &str| {
            let row = rows.row(LibraryId::Itanium, name)?;
            let prototype = rows.prototype(row);
            let refused = matches!(
                rows.graph().get(prototype.return_type),
                Some(crate::Type::Refused(_))
            );
            assert!(refused, "{name} states a result");
            assert_eq!(row.tail, Tail::None);
            Some(prototype.parameters.len())
        };
        assert_eq!(count(put), Some(2));
        assert!(
            rows.row(LibraryId::Itanium, put)
                .is_some_and(|row| row.citation.contains("<ostream>"))
        );
        assert_eq!(count(now), Some(0));
        assert_eq!(count("_ZNSolsEi"), Some(2));
        assert_eq!(count(open), None);
        // The table's own row stands beside the name's: operator new states its result there.
        let new = rows
            .row(LibraryId::CxxRuntime, "_Znwm")
            .expect("operator new");
        assert!(new.citation.is_empty());
        assert_eq!(count("_Znwm"), Some(1));
        assert!(rows.row(LibraryId::Itanium, "main").is_none());
    }

    /// Every `cxx-objects.txt` name parses, and its name leaves the object open.
    #[test]
    fn every_cited_object_is_one_the_name_leaves_open() {
        let objects = CxxObjects::read(CXX_OBJECTS);
        assert!(objects.0.len() >= 50, "{}", objects.0.len());
        for (name, (_, cited)) in &objects.0 {
            let parsed = crate::mangled::parse(name).unwrap_or_else(|| panic!("{name}"));
            assert!(
                matches!(parsed.object, crate::mangled::Object::Unstated(_)),
                "{name}: the name states its object"
            );
            assert!(cited.contains(" <"), "{name}: {cited}");
        }
    }

    #[test]
    fn a_name_is_looked_up_exactly_as_it_is_spelled() {
        let rows = LibraryRows::embedded(CLibrary::Unknown);
        let scope = CLibrary::Unknown.scope();
        let strcpy = rows
            .find(scope, "__strcpy_chk")
            .map(|row| rows.prototype(row));
        assert_eq!(strcpy.map(|p| p.parameters.len()), Some(3));
        // A name with one more underscore is another function.
        assert!(rows.find(scope, "_strlen").is_none());
        assert!(rows.find(scope, "___strcpy_chk").is_none());
        assert!(rows.len() > 500, "{}", rows.len());
    }

    /// The table's spellings are read once, into the same graph a binary's debug information is
    /// read into: `size_t` is an unsigned integer as wide as an address, and `FILE` is glibc's tag.
    #[test]
    fn every_spelling_is_a_node_of_one_graph() {
        use crate::Type;
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let graph = rows.graph();
        let fwrite = prototype(&rows, CLibrary::Glibc, "fwrite");
        let model = crate::CDataModel::unix(64);
        assert_eq!(graph.size_bits(fwrite.return_type, &model), Some(64));
        let stream = fwrite.parameters.last().expect("a stream");
        let Some(Type::Pointer { target }) = graph.resolved(stream.ty) else {
            panic!("{:?}", graph.get(stream.ty));
        };
        let Some(Type::Typedef { target, .. }) = graph.get(*target) else {
            panic!("{:?}", graph.get(*target));
        };
        assert!(matches!(graph.get(*target), Some(Type::Opaque { .. })));
    }
}
