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
pub mod records;

pub use decode::listing;
pub use memo::{Memo, MemoStats};
pub use records::{Annotation, AnnotationKind, Decoders, Line, Listing, Memory};

/// How much work a request permits.
///
/// A ladder of scheduling, not of truth: allowing more work decides whether a
/// fact could be established, never what the fact means. Each rung admits
/// everything below it, and a rung is added when something asks for it rather
/// than because a plan named it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Work {
    /// Read the bytes and spell the instruction. No lifting.
    Decode,
    /// Lift one instruction and fold within it.
    InstructionLocal,
    /// Fold across a run of instructions, which is what an address built over
    /// three of them needs, and what says whether a number one instruction
    /// computes is an address or a step towards one.
    BlockLocal,
}

/// How well supported a claim about a number is, strongest first.
///
/// This is the axis that was missing. Substituting a name wherever a number
/// happened to equal an address is not wrong so much as unlabelled: it is a
/// coincidence until something says the number is used as an address, and a
/// reader told which is which can act on the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Support {
    /// An operand of one decoded instruction says the instruction transfers
    /// there or accesses it.
    Decoded,
    /// Constants folded, within one instruction or across a run of them.
    Folded,
    /// The number equals an address something names, and nothing in the
    /// instruction says it is used as one.
    Coincident,
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
    /// The permitted work ran out before the question did.
    Exhausted { after: usize },
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
