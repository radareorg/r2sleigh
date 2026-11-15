//! The negative facts the default-deny matrix crosses with every unknown input (ROADMAP D405,
//! D411): each is a type whose owner mints it from evidence, and each names its columns here.

/// One column of the default-deny matrix: a fact that something does not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NegativeFact {
    /// A read the text names that the call does not perform.
    IgnoredReads,
    /// A register the callee leaves as found.
    Kept,
    /// The low bytes of an argument register a call takes.
    CallReadBytes,
    /// A function that returns no value.
    Void,
    /// A call that never comes back.
    Never,
    /// An argument the body proves it dereferences.
    Pointer,
    /// The caller's stack a callee writes no more of.
    IncomingWrites,
}

impl NegativeFact {
    pub const ALL: [Self; 7] = [
        Self::IgnoredReads,
        Self::Kept,
        Self::CallReadBytes,
        Self::Void,
        Self::Never,
        Self::Pointer,
        Self::IncomingWrites,
    ];

    /// The column as the matrix prints it.
    pub const fn column(self) -> &'static str {
        match self {
            Self::IgnoredReads => "ignored_reads",
            Self::Kept => "kept",
            Self::CallReadBytes => "call_read_bytes",
            Self::Void => "void",
            Self::Never => "never",
            Self::Pointer => "pointer",
            Self::IncomingWrites => "incoming_writes",
        }
    }
}

/// A type that states negative facts: the matrix holds a column for each of its `FACTS`.
pub trait Negative {
    const FACTS: &'static [NegativeFact];
}

impl Negative for crate::Never {
    const FACTS: &'static [NegativeFact] = &[NegativeFact::Never];
}

impl Negative for crate::SourceFunctionReturn {
    const FACTS: &'static [NegativeFact] = &[NegativeFact::Void];
}

impl Negative for r2il::eval::independence::Cancelled {
    const FACTS: &'static [NegativeFact] = &[NegativeFact::IgnoredReads];
}
