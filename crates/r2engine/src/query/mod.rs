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
pub mod db;
pub mod decode;
pub mod proved;
pub mod records;
pub mod references;

pub use decode::listing;

/// What the analysis queries have computed and served.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnalysisStats {
    pub analysed: db::QueryStats,
    pub sealed: db::QueryStats,
    pub callee_reads: db::QueryStats,
    /// Callees resolved against the owners of their result, which every caller asks.
    pub resolved: db::QueryStats,
    pub rendered: db::QueryStats,
}
pub use proved::Proved;
pub use r2ssa::InductionStep;
pub use records::{
    Annotation, AnnotationKind, Answered, ArgumentSlot, CallArgument, Callee, Decoders, Line,
    Listing, Memory, Operand, Parameters, Stop, Trips, WalkedBody,
};
pub use references::{Claimant, Coverage, Reference, References, Role, Unread};

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
    /// List inside the walked body: the fold starts afresh at each of its blocks, its def-use settles what the run cannot, and a prepared function adds what was proved.
    Function,
}

/// The smallest evidence that establishes a claim, each rung reading more of the program; an unclaimed number has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Support {
    /// The container states it: the loader writes this address into this word.
    Stated,
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

/// One answer, and how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    pub value: T,
    pub completion: Completion,
}

impl<T> Answer<T> {
    pub const fn complete(value: T) -> Self {
        Self {
            value,
            completion: Completion::Complete,
        }
    }

    /// Whether everything asked for was answered.
    pub fn is_complete(&self) -> bool {
        self.completion == Completion::Complete
    }
}
