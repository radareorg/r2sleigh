//! One typed surface every command answers from.
//!
//! The engine owns its facts, and until now the only consumer that read them
//! was the decompiler. A listing built its lines by rewriting the decoder's
//! prose and guessing which numbers were addresses, so it could neither say
//! what it had proved nor say what it had merely noticed. This module is the
//! request and the answer: a caller says what it wants and how much work it is
//! willing to pay for, and gets records rather than text.
//!
//! Two rules hold everything else up. Cost is a work-admission policy and
//! never a precision knob, so allowing more work can only decide whether a
//! fact could be established, never what the fact means. And every answer
//! names the state of the program it was computed against, so no two answers
//! in one view can describe different programs.

pub mod annotate;
pub mod decode;
pub mod memo;
mod proved;
pub mod records;
pub mod references;

pub use decode::listing;
pub use memo::{Memo, MemoStats};
pub use records::{
    Annotation, AnnotationKind, Answered, Callee, Decoders, DefUse, Line, Listing, Memory,
    Parameters, Stop,
};
pub use references::{Coverage, Reference, ReferenceKind, References, Unread};

/// How much work a request permits.
///
/// A ladder of scheduling, not of truth: allowing more work decides whether a
/// fact could be established, never what the fact means. Each rung admits
/// everything below it, and a rung is added when something asks for it rather
/// than because a plan named it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Work {
    /// Spell the instruction; its P-code is built only to commit the decoder context, and not returned.
    Decode,
    /// Lift one instruction and fold within it.
    InstructionLocal,
    /// Follow the run after each instruction, which says whether a number one
    /// instruction computes is an address or a step towards one. A run may be
    /// entered anywhere, so nothing is folded across its instructions.
    BlockLocal,
    /// List the function block by block: each block is entered only at its
    /// top, so an address built over several of its instructions folds, and
    /// the body's def-use settles what the run cannot; a prepared function
    /// adds what was proved about the values each line defines.
    Function,
}

/// The smallest evidence that establishes a claim, each rung reading more of the program; an unclaimed number has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Support {
    /// The instruction alone says it: where it transfers, what it accesses, or the bound its own operations put on what it writes.
    Decoded,
    /// Evaluated over the run of instructions around it in its block.
    Folded,
    /// Exact over the whole function: its def-use, or a certificate `r2ssa` issued.
    Certified,
    /// A bound an analysis over the whole function proved: true everywhere, exact nowhere.
    Solved,
    /// A callee's own body loads or stores through the parameter the number arrives in.
    Dereferenced,
    /// A library declaration types the parameter the number arrives in as a pointer.
    Declared,
}

/// Which state of a program an answer was computed against.
///
/// Four axes rather than one counter, so a patch does not invalidate what it
/// cannot have touched. `bytes` alone would be that counter: it moves on every
/// write, so comparing it threw away every answer about every other function.
/// What an answer read is compared by range instead, and the two derived
/// tables are compared whole, because a walk consults them about addresses it
/// never reads. There is no axis for which addresses exist, because that never
/// moves within one program: a write refuses a range the file does not map, so
/// a patch can neither create an address nor destroy one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Revision {
    /// Which open program this is. Two answers about different programs are
    /// never about the same thing, whatever their other numbers say.
    pub program: u64,
    /// How many times the program's bytes have been written.
    pub bytes: u64,
    /// Moves only when the name table rebuilt from those bytes differs from
    /// the one it replaced, so a patch that renames nothing invalidates
    /// nothing that depended on a name.
    pub names: u64,
    /// The same, for what the program defines at each address -- which is what
    /// bounds every body walk.
    pub entries: u64,
}

/// Why an answer stopped where it did.
///
/// Kept apart from the facts on purpose: a deadline is a fact about this
/// request, not about the program, and a consumer that cannot tell them apart
/// will eventually print one as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Everything asked for was answered.
    Complete,
    /// The program maps nothing at this address, so there was nothing to read.
    Unmapped { at: u64 },
}

/// One answer, with the state it describes and how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    pub value: T,
    pub revision: Revision,
    pub completion: Completion,
}

impl<T> Answer<T> {
    pub fn complete(value: T, revision: Revision) -> Self {
        Self {
            value,
            revision,
            completion: Completion::Complete,
        }
    }

    /// Whether everything asked for was answered.
    pub fn is_complete(&self) -> bool {
        self.completion == Completion::Complete
    }
}
