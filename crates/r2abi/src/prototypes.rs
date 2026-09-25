//! What a library function takes and returns.
//!
//! An import has no body to read an interface off, so a call to one renders
//! with no arguments at all unless something states its prototype. radare2
//! ships that statement for two thousand library functions as `sdb` text, and
//! this reads it: the data is good, and only the lookup had any business being
//! on the other side of an FFI boundary.

use std::collections::BTreeMap;

use crate::types::{TypeGraph, TypeId};

/// What a declaration says about one function.
///
/// The shipped table declares interfaces only. A binary's own debug
/// information declares the same interface and, for a function it has the body
/// of, where that body keeps its named variables -- which reaches the engine
/// by this same shape so that a declaration read from DWARF and one read from
/// the table never become two models of the same thing.
///
/// Every type is a node of the graph the declaration was read into, which
/// travels beside it. The spellings are that node written as C, for
/// presentation; nothing reads a type back out of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototype {
    pub name: String,
    /// One fixed parameter per entry, in order.
    pub parameters: Vec<Parameter>,
    pub returns: Spelled,
    /// What the function returns, as a node; `void` where it returns nothing.
    pub return_type: TypeId,
    /// Whether arguments continue past the fixed ones.
    pub variadic: bool,
    /// Whether control never returns from this function.
    ///
    /// `err`, `abort`, `exit` and twenty-four others in the shipped tables say
    /// so, and a call to one ends the block: the bytes after it belong to
    /// whatever comes next, not to the caller. Reading it is what stops a body
    /// walk running through the function that follows.
    pub noreturn: bool,
    /// What the offsets in `locals` are measured from.
    pub frame_base: Option<FrameBase>,
    /// Each named variable the declaration places in the frame.
    pub locals: Vec<Local>,
}

/// One C type, as the declaration writes it and as the language reads it.
///
/// A name for a type is not the type: `idx_t` says nothing about width or
/// indirection to anything that only has the text, so a prototype holding one
/// was left untyped whole -- a hundred and four of the eight hundred and
/// thirty-five in the `diffutils` binaries. The debug information knows what
/// the name stands for, and this is where it says so. The name stays because
/// it is what the source called it and it is what a reader wants to see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spelled {
    /// What the declaration writes.
    pub declared: String,
    /// What that names, where it is a name for something else.
    pub resolved: Option<String>,
}

impl Spelled {
    pub fn new(declared: impl Into<String>, resolved: Option<impl Into<String>>) -> Self {
        let declared = declared.into();
        let resolved = resolved.map(Into::into).filter(|other| *other != declared);
        Self { declared, resolved }
    }

    /// The spelling with every name read through.
    pub fn as_type(&self) -> &str {
        self.resolved.as_deref().unwrap_or(&self.declared)
    }

    /// The spelling to render.
    pub fn as_written(&self) -> &str {
        &self.declared
    }
}

impl From<String> for Spelled {
    fn from(declared: String) -> Self {
        Self {
            declared,
            resolved: None,
        }
    }
}

impl From<&str> for Spelled {
    fn from(declared: &str) -> Self {
        Self::from(declared.to_owned())
    }
}

/// Where a function's frame offsets are measured from.
///
/// Only the two forms that hold for a whole function are carried. A base that
/// moves as the body runs states no single origin, so it states nothing here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBase {
    /// The caller's stack pointer before the call: DWARF's canonical frame
    /// address.
    CallFrameCfa,
    /// One register, by the number this machine's DWARF table gives it.
    Register(u16),
}

/// One variable the source named and the compiler put in the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub name: String,
    pub spelling: Option<Spelled>,
    /// Bytes from the frame base.
    pub frame_offset: i64,
    /// How many bytes it occupies: its type's size, where the type has one.
    pub size_bytes: Option<u32>,
    pub ty: TypeId,
    /// The code the name is in scope over, as the lexical blocks enclosing it
    /// state it; empty where that is the whole function.
    pub scopes: Vec<std::ops::Range<u64>>,
}

/// What role a machine gives one DWARF register number.
///
/// Only the two that a frame base can name are answered, and only for the
/// machines this engine lifts. The numbering is each platform's ABI document,
/// which is also where radare2's own copy of this comes from; a number no
/// document here assigns is evidence of nothing rather than a guess.
pub fn dwarf_frame_register(
    arch: &str,
    bits: u32,
    number: u16,
) -> Option<(FrameRole, &'static str)> {
    let (frame_pointer, stack_pointer) = match (crate::family(arch)?, bits) {
        ("x86", 64) => ((6, "rbp"), (7, "rsp")),
        ("x86", 32) => ((5, "ebp"), (4, "esp")),
        ("arm", 64) => ((29, "x29"), (31, "sp")),
        ("arm", 32) => ((11, "r11"), (13, "sp")),
        _ => return None,
    };
    match number {
        number if number == frame_pointer.0 => Some((FrameRole::FramePointer, frame_pointer.1)),
        number if number == stack_pointer.0 => Some((FrameRole::StackPointer, stack_pointer.1)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameRole {
    FramePointer,
    StackPointer,
}

/// The integer register one DWARF register number names, as radare2 spells
/// it.
///
/// The numbering is each platform's ABI document again. Only the integer
/// file is answered, which is where a declaration can say an integer or
/// pointer parameter arrives; a number past it is evidence of nothing here.
pub fn dwarf_register(arch: &str, bits: u32, number: u16) -> Option<&'static str> {
    const X86_64: [&str; 16] = [
        "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const X86: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    const AARCH64: [&str; 32] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30", "sp",
    ];
    const ARM: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc",
    ];
    let table: &[&'static str] = match (crate::family(arch)?, bits) {
        ("x86", 64) => &X86_64,
        ("x86", 32) => &X86,
        ("arm", 64) => &AARCH64,
        ("arm", 32) => &ARM,
        _ => return None,
    };
    table.get(usize::from(number)).copied()
}

/// One declared parameter: what it is, and what the declaration calls it.
///
/// The type decides how the call is read; the name decides only how it is
/// rendered, and a declaration that gives none renders the position instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameter {
    pub spelling: Spelled,
    pub name: Option<String>,
    /// Bytes from the frame base, where the declaration says it is kept in the
    /// frame. This is the one place a declaration states the same slot in two
    /// coordinate systems, which is what lets the two be lined up.
    pub frame_offset: Option<i64>,
    pub ty: TypeId,
    /// Where the declaration says the parameter is as the body begins, where
    /// it says anything about that instant.
    pub arrival: Option<Arrival>,
}

/// Where one parameter is at the first instruction of the body.
///
/// A compiler that specialises a function -- a `.constprop` clone with a
/// constant folded in, an `.isra` clone passing a member instead of the
/// pointer to it -- still describes the clone against the source's prototype.
/// That prototype is then not what the body takes, and the only statement
/// that says so is where each parameter is on entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// In the register this machine's DWARF table numbers so.
    Register(u16),
    /// Passed nowhere: the declaration gives the body a constant for it, or
    /// says nothing of it at all where it describes every other parameter.
    Unpassed,
}

impl Parameter {
    /// Whether the declaration says this parameter is a function.
    ///
    /// The type data spells it `func`, which is what `__libc_start_main` says
    /// of `main` and `atexit` says of the handler it is given. A constant in
    /// such a slot is a function address on the declaration's authority, which
    /// is the only ground on which this engine will believe one.
    pub fn is_function(&self) -> bool {
        self.spelling.as_type().trim() == "func"
    }

    pub fn new(ty: TypeId, spelling: impl Into<Spelled>, name: Option<impl Into<String>>) -> Self {
        Self {
            spelling: spelling.into(),
            name: name.map(Into::into),
            frame_offset: None,
            ty,
            arrival: None,
        }
    }

    pub fn at_frame_offset(mut self, frame_offset: Option<i64>) -> Self {
        self.frame_offset = frame_offset;
        self
    }
}

/// Every prototype the data declares, and the graph its types are nodes of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototypes {
    graph: TypeGraph,
    by_name: BTreeMap<String, Prototype>,
}

const EMBEDDED: &str = include_str!("../data/types.sdb.txt");
const EMBEDDED_LINUX: &str = include_str!("../data/types-linux.sdb.txt");
const EMBEDDED_DARWIN: &str = include_str!("../data/types-darwin.sdb.txt");

/// Which platform's own declarations apply on top of the portable ones.
///
/// `_Exit` and `__errno_location` are declared per platform, not in the table
/// every target shares, so a call to one has no prototype until the platform
/// says which set to read. The platform also says what its own names for
/// integers are: `mode_t` is sixteen bits on one and thirty-two on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Darwin,
    Unknown,
}

impl Prototypes {
    /// The prototypes radare2 ships for every target.
    pub fn embedded() -> Self {
        Self::embedded_for(Platform::Unknown)
    }

    /// Those, with the ones this platform declares itself layered over them.
    pub fn embedded_for(platform: Platform) -> Self {
        let own = match platform {
            Platform::Linux => Some(EMBEDDED_LINUX),
            Platform::Darwin => Some(EMBEDDED_DARWIN),
            Platform::Unknown => None,
        };
        Self::parse_all([EMBEDDED].into_iter().chain(own), platform)
    }

    pub fn parse(text: &str) -> Self {
        Self::parse_all([text], Platform::Unknown)
    }

    /// Several tables into one graph, a later declaration of a name replacing
    /// an earlier one.
    fn parse_all<'a>(texts: impl IntoIterator<Item = &'a str>, platform: Platform) -> Self {
        let mut prototypes = Self::default();
        for text in texts {
            let table = Table::read(text);
            for (name, declared) in table.functions {
                let prototype = prototypes.typed(name.clone(), declared, platform);
                prototypes.by_name.insert(name, prototype);
            }
        }
        prototypes
    }

    /// One declaration's spellings, read into this table's graph.
    fn typed(&mut self, name: String, declared: Declared, platform: Platform) -> Prototype {
        let mut read = |spelling: &str| crate::spelling::read(spelling, &mut self.graph, platform);
        let returns = declared.returns.unwrap_or_else(|| "void".to_owned());
        let return_type = read(&returns);
        let mut parameters = Vec::new();
        let mut variadic = false;
        for (spelling, called) in declared.parameters.into_values() {
            // An empty spelling is the ellipsis: everything after it is
            // whatever the caller passes.
            if spelling.is_empty() {
                variadic = true;
                break;
            }
            parameters.push(Parameter::new(
                read(&spelling),
                spelling,
                called.filter(|called| !called.is_empty()),
            ));
        }
        Prototype {
            name,
            parameters,
            returns: Spelled::from(returns),
            return_type,
            variadic,
            noreturn: declared.noreturn,
            ..Prototype::default()
        }
    }

    pub fn get(&self, name: &str) -> Option<&Prototype> {
        // A linked name carries at most the platform's own decoration, which
        // is one underscore where there is any: Mach-O spells `__strcpy_chk`
        // as `___strcpy_chk`, and the declaration keeps the other two. Only
        // that one is dropped. Dropping them until something matched turned
        // `__memcpy_chk` into `memcpy`, which takes one argument fewer.
        self.by_name
            .get(name)
            .or_else(|| self.by_name.get(name.strip_prefix('_')?))
    }

    /// The graph every prototype here names its types in.
    pub fn graph(&self) -> &TypeGraph {
        &self.graph
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// One function as the table spells it, before its types are read.
#[derive(Debug, Default)]
struct Declared {
    parameters: BTreeMap<usize, (String, Option<String>)>,
    returns: Option<String>,
    noreturn: bool,
}

/// The functions one `sdb` dump declares.
#[derive(Debug, Default)]
struct Table {
    functions: BTreeMap<String, Declared>,
}

impl Table {
    fn read(text: &str) -> Self {
        let mut table = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let Some(rest) = key.strip_prefix("func.") else {
                continue;
            };
            let Some((name, what)) = rest.rsplit_once('.') else {
                continue;
            };
            table.take(name, what, value.trim());
        }
        table
    }

    fn take(&mut self, name: &str, what: &str, value: &str) {
        // `func.<name>.arg.<index>=<type>,<parameter name>`, where the
        // parameter name is presentation and the type decides how the call is
        // read.
        if let Some(name) = name.strip_suffix(".arg") {
            let Ok(index) = what.parse::<usize>() else {
                return;
            };
            let (spelling, called) = match value.split_once(',') {
                Some((spelling, called)) => (spelling.trim(), Some(called.trim().to_owned())),
                None => (value, None),
            };
            self.declare(name)
                .parameters
                .insert(index, (spelling.to_owned(), called));
            return;
        }
        match what {
            "args" => {
                self.declare(name);
            }
            "ret" => self.declare(name).returns = Some(value.to_owned()),
            "noreturn" => self.declare(name).noreturn = value == "true",
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
    use crate::types::{DataModel, Type};

    fn spelled(prototypes: &Prototypes, parameter: &Parameter) -> Option<String> {
        prototypes
            .graph()
            .spelled(parameter.ty)
            .map(|spelled| spelled.declared)
    }

    #[test]
    fn a_fixed_prototype_reads_whole() {
        let prototypes = Prototypes::embedded();
        let puts = prototypes.get("puts").expect("puts");
        assert_eq!(puts.parameters.len(), 1);
        assert_eq!(puts.parameters[0].name.as_deref(), Some("s"));
        assert_eq!(
            spelled(&prototypes, &puts.parameters[0]).as_deref(),
            Some("const char *")
        );
        assert_eq!(puts.returns.as_written(), "int");
        assert!(!puts.variadic);
    }

    #[test]
    fn the_ellipsis_is_variadic_rather_than_a_parameter() {
        let prototypes = Prototypes::embedded();
        let printf = prototypes.get("printf").expect("printf");
        assert_eq!(printf.parameters.len(), 1);
        assert_eq!(printf.parameters[0].name.as_deref(), Some("format"));
        assert!(printf.variadic);
    }

    #[test]
    fn a_decorated_name_finds_its_undecorated_prototype() {
        let prototypes = Prototypes::embedded();
        assert_eq!(
            prototypes.get("_strlen").map(|p| p.returns.as_written()),
            Some("size_t")
        );
        // The declaration keeps two underscores and the linker adds a third.
        assert_eq!(
            prototypes.get("___strcpy_chk").map(|p| p.parameters.len()),
            Some(3)
        );
    }

    #[test]
    fn the_data_declares_a_few_thousand_functions() {
        let count = Prototypes::embedded().len();
        assert!(count > 500, "{count}");
    }

    /// The table's spellings are read once, into the same graph a binary's
    /// debug information is read into: `size_t` is an unsigned integer as
    /// wide as an address, and `FILE` is a tag the table never completes.
    #[test]
    fn every_spelling_is_a_node_of_one_graph() {
        let prototypes = Prototypes::embedded_for(Platform::Linux);
        let graph = prototypes.graph();
        let fwrite = prototypes.get("fwrite").expect("fwrite");
        let model = DataModel::unix(64);
        assert_eq!(graph.size_bits(fwrite.return_type, &model), Some(64));
        let stream = fwrite.parameters.last().expect("a stream");
        let Some(Type::Pointer { target }) = graph.resolved(stream.ty) else {
            panic!("{:?}", graph.get(stream.ty));
        };
        assert!(matches!(graph.get(*target), Some(Type::Opaque { .. })));
    }
}
