//! What a library function takes and returns.
//!
//! An import has no body to read an interface off, so a call to one renders
//! with no arguments at all unless something states its prototype. radare2
//! ships that statement for two thousand library functions as `sdb` text, and
//! this reads it: the data is good, and only the lookup had any business being
//! on the other side of an FFI boundary.

use std::collections::BTreeMap;

/// What a declaration says about one function, in C spellings.
///
/// The shipped table declares interfaces only. A binary's own debug
/// information declares the same interface and, for a function it has the body
/// of, where that body keeps its named variables -- which reaches the engine
/// by this same shape so that a declaration read from DWARF and one read from
/// the table never become two models of the same thing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototype {
    pub name: String,
    /// One fixed parameter per entry, in order.
    pub parameters: Vec<Parameter>,
    pub returns: Spelled,
    /// Whether arguments continue past the fixed ones.
    pub variadic: bool,
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

    /// The spelling to read the type from.
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
    /// How many bytes it occupies, where the declaration states an extent.
    pub size_bytes: Option<u32>,
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

/// One declared parameter: what it is, and what the declaration calls it.
///
/// The spelling decides how the call is read; the name decides only how it is
/// rendered, and a declaration that gives none renders the position instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameter {
    pub spelling: Spelled,
    pub name: Option<String>,
    /// Bytes from the frame base, where the declaration says it is kept in the
    /// frame. This is the one place a declaration states the same slot in two
    /// coordinate systems, which is what lets the two be lined up.
    pub frame_offset: Option<i64>,
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

    pub fn new(spelling: impl Into<Spelled>, name: Option<impl Into<String>>) -> Self {
        Self {
            spelling: spelling.into(),
            name: name.map(Into::into),
            frame_offset: None,
        }
    }

    pub fn at_frame_offset(mut self, frame_offset: Option<i64>) -> Self {
        self.frame_offset = frame_offset;
        self
    }
}

/// Every prototype the data declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototypes {
    by_name: BTreeMap<String, Prototype>,
}

const EMBEDDED: &str = include_str!("../data/types.sdb.txt");
const EMBEDDED_LINUX: &str = include_str!("../data/types-linux.sdb.txt");
const EMBEDDED_DARWIN: &str = include_str!("../data/types-darwin.sdb.txt");

/// Which platform's own declarations apply on top of the portable ones.
///
/// `_Exit` and `__errno_location` are declared per platform, not in the table
/// every target shares, so a call to one has no prototype until the platform
/// says which set to read.
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
        let mut prototypes = Self::parse(EMBEDDED);
        let platform = match platform {
            Platform::Linux => Some(EMBEDDED_LINUX),
            Platform::Darwin => Some(EMBEDDED_DARWIN),
            Platform::Unknown => None,
        };
        if let Some(text) = platform {
            prototypes.by_name.extend(Self::parse(text).by_name);
        }
        prototypes
    }

    pub fn parse(text: &str) -> Self {
        let mut by_name: BTreeMap<String, Prototype> = BTreeMap::new();
        let mut slots: BTreeMap<String, BTreeMap<usize, Parameter>> = BTreeMap::new();
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
            let value = value.trim();

            // `func.<name>.arg.<index>=<type>,<parameter name>`, where the
            // parameter name is presentation and the type decides how the call
            // is read.
            if let Some(name) = name.strip_suffix(".arg") {
                let Ok(index) = what.parse::<usize>() else {
                    continue;
                };
                declare(&mut by_name, name);
                let (spelling, called) = match value.split_once(',') {
                    Some((spelling, called)) => (spelling.trim(), Some(called.trim())),
                    None => (value, None),
                };
                slots.entry(name.to_owned()).or_default().insert(
                    index,
                    Parameter::new(spelling, called.filter(|called| !called.is_empty())),
                );
                continue;
            }

            match what {
                "args" => {
                    declare(&mut by_name, name);
                }
                "ret" => declare(&mut by_name, name).returns = Spelled::from(value),
                _ => {}
            }
        }

        for (name, positions) in slots {
            let Some(prototype) = by_name.get_mut(&name) else {
                continue;
            };
            for parameter in positions.into_values() {
                // An empty spelling is the ellipsis: everything after it is
                // whatever the caller passes.
                if parameter.spelling.declared.is_empty() {
                    prototype.variadic = true;
                    break;
                }
                prototype.parameters.push(parameter);
            }
        }
        Self { by_name }
    }

    /// Layer prototypes the binary itself declares over the shipped ones.
    ///
    /// What a binary's own debug information says beats what the shared table
    /// declares for the same name: the table is what a library is expected to
    /// look like, and the binary is what it is.
    pub fn declare(&mut self, prototypes: impl IntoIterator<Item = Prototype>) {
        for prototype in prototypes {
            self.by_name.insert(prototype.name.clone(), prototype);
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

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The prototype this name will be filled in for.
fn declare<'a>(by_name: &'a mut BTreeMap<String, Prototype>, name: &str) -> &'a mut Prototype {
    by_name.entry(name.to_owned()).or_insert_with(|| Prototype {
        name: name.to_owned(),
        ..Prototype::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_prototype_reads_whole() {
        let prototypes = Prototypes::embedded();
        let puts = prototypes.get("puts").expect("puts");
        assert_eq!(puts.parameters, [Parameter::new("const char *", Some("s"))]);
        assert_eq!(puts.returns.as_written(), "int");
        assert!(!puts.variadic);
    }

    #[test]
    fn the_ellipsis_is_variadic_rather_than_a_parameter() {
        let prototypes = Prototypes::embedded();
        let printf = prototypes.get("printf").expect("printf");
        assert_eq!(
            printf.parameters,
            [Parameter::new("const char *", Some("format"))]
        );
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
}

#[cfg(test)]
mod dwarf_tests {
    use super::*;

    #[test]
    fn each_machines_frame_and_stack_registers_are_answered_by_number() {
        assert_eq!(
            dwarf_frame_register("x86-64", 64, 6),
            Some((FrameRole::FramePointer, "rbp"))
        );
        assert_eq!(
            dwarf_frame_register("x86-64", 64, 7),
            Some((FrameRole::StackPointer, "rsp"))
        );
        assert_eq!(
            dwarf_frame_register("aarch64", 64, 29),
            Some((FrameRole::FramePointer, "x29"))
        );
        assert_eq!(
            dwarf_frame_register("arm", 32, 13),
            Some((FrameRole::StackPointer, "sp"))
        );
    }

    #[test]
    fn a_number_no_document_here_assigns_answers_nothing() {
        assert_eq!(dwarf_frame_register("x86-64", 64, 0), None);
        assert_eq!(dwarf_frame_register("riscv", 64, 8), None);
    }
}
