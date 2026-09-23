//! The reverse-reference index, and the scope it was built over.
//!
//! An index built from the bodies discovery walked says nothing about code no
//! walk reached: what lies behind an indirect branch it could not follow, or a
//! body it could not walk at all. So the facts never travel without that
//! scope, and an address missing from them is absent within it, not absent.

use std::collections::BTreeMap;

use r2ssa::DataRefFact;
use r2ssa::body::{Unresolved, UnresolvedReason};

use crate::native::NativeRefusal;

/// Every reference the walked bodies make, and what the walks covered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct References {
    /// Sorted, without repeats.
    pub facts: Vec<DataRefFact>,
    pub coverage: Coverage,
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
    /// The body walked but its SSA did not build, so what it names is unknown.
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
