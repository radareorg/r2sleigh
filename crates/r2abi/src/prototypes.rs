//! What a declaration says a function takes and returns: a library row's (`crate::library`) or
//! the binary's own debug information's (`crate::declarations`), in one shape.

use crate::types::TypeId;

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
    /// DWARF's `DW_AT_noreturn`; a library row states its own on `LibraryRow::noreturn`.
    pub noreturn: bool,
    /// DWARF's `DW_AT_calling_convention`; the engine chooses the convention from it (S20).
    pub convention: StatedConvention,
    /// What the offsets in `locals` are measured from.
    pub frame_base: Option<FrameBase>,
    /// Each named variable the declaration places in the frame.
    pub locals: Vec<Local>,
}

/// A subprogram's `DW_AT_calling_convention` as its producer writes it (DWARF 5 3.3.1.1; LLVM's
/// vendor codes are `llvm/BinaryFormat/Dwarf.def`'s `HANDLE_DW_CC`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatedConvention {
    /// No attribute, or `DW_CC_normal`.
    #[default]
    Normal,
    /// `DW_CC_program`: a main program, not callable by the ordinary convention.
    Program,
    /// `DW_CC_nocall`: the compiler passes the arguments its own way.
    NoCall,
    /// `DW_CC_LLVM_Win64` (0xc1), clang's `ms_abi`.
    LlvmWin64,
    /// `DW_CC_LLVM_X86_64SysV` (0xc2), clang's `sysv_abi`.
    LlvmX8664SysV,
    /// Any other code.
    Other(u8),
}

impl StatedConvention {
    /// The attribute's constant.
    pub const fn of(code: u8) -> Self {
        match code {
            0x01 => Self::Normal,
            0x02 => Self::Program,
            0x03 => Self::NoCall,
            0xc1 => Self::LlvmWin64,
            0xc2 => Self::LlvmX8664SysV,
            code => Self::Other(code),
        }
    }
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
    /// The return type of the code this parameter points to; `None` for a data pointer or a
    /// refused return (`func`, S30). A constant in such a slot is a function address.
    pub fn code_returns(&self, graph: &crate::TypeGraph) -> Option<crate::TypeId> {
        let crate::types::Type::Pointer { target } = graph.resolved(self.ty)? else {
            return None;
        };
        match graph.resolved(*target)? {
            crate::types::Type::Code(signature) => Some(signature.returns),
            _ => None,
        }
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
