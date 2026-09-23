//! The reverse-reference index, and the scope it was built over.
//!
//! An index built from the bodies discovery walked says nothing about code no
//! walk reached: what lies behind an indirect branch it could not follow, or a
//! body it could not walk at all. So the facts never travel without that
//! scope, and an address missing from them is absent within it, not absent.
//!
//! Each fact is a claim the listing makes about one instruction, so `ax` and `pdf` cannot disagree.

use std::collections::BTreeMap;

use r2ssa::body::{Unresolved, UnresolvedReason};

use crate::native::NativeRefusal;

/// Every reference the walked bodies make, and what the walks covered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct References {
    /// Sorted, without repeats.
    pub facts: Vec<Reference>,
    pub coverage: Coverage,
}

/// One instruction naming one address of this program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub kind: ReferenceKind,
}

/// Whether the instruction transfers control there or names it as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceKind {
    Code,
    Data,
}

/// Every reference the lines of a listing claim, by the line that claims it.
pub fn claimed_by(lines: &[super::Line]) -> Vec<Reference> {
    lines
        .iter()
        .flat_map(|line| {
            line.annotations.iter().filter_map(|annotation| {
                Some(Reference {
                    from: line.address,
                    to: annotation.kind.address(),
                    kind: annotation.reference?,
                })
            })
        })
        .collect()
}

impl ReferenceKind {
    /// As radare2 spells the kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "c",
            Self::Data => "d",
        }
    }
}

/// Which functions the index read, and where it could not read on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    /// Every function whose body was walked and read, by entry.
    pub read: Vec<u64>,
    /// Every function discovery believes whose references are unknown, and why.
    pub unread: BTreeMap<u64, Unread>,
    /// Per function, every place its walk stopped without knowing where
    /// control went; code past those is in no body.
    pub unresolved: BTreeMap<u64, Vec<Unresolved>>,
}

/// Why one function contributed nothing to the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// The body could not be walked.
    Refused(NativeRefusal),
    /// A number the body computes needed its def-use to say whether it is a step, and that did not build.
    NoSsa,
}

impl Coverage {
    /// How many transfers no walk could follow, across every function.
    pub fn unresolved_count(&self) -> usize {
        self.unresolved.values().map(Vec::len).sum()
    }

    /// How many of those are indirect branches rather than unreadable bytes.
    pub fn indirect_count(&self) -> usize {
        self.unresolved
            .values()
            .flatten()
            .filter(|stop| stop.reason == UnresolvedReason::IndirectBranch)
            .count()
    }

    /// Whether every believed body was read and walked to its end.
    pub fn is_closed(&self) -> bool {
        self.unread.is_empty() && self.unresolved.is_empty()
    }
}
