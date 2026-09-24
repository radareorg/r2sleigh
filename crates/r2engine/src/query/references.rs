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

use super::{Line, Support};
use crate::native::NativeRefusal;

/// Every reference the walked bodies make, and what the walks covered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct References {
    /// By source, then target and role, each with the smallest support any listing of it gave.
    facts: Vec<Reference>,
    /// Positions in `facts` ordered by target, so the references to one address are one run.
    by_target: Vec<usize>,
    /// Each instruction a fact is from, by address, as the index first listed it, with every function whose listing of it claims one.
    sources: Vec<Claimant>,
    /// Where in `sources` each fact's instruction is.
    source_of: Vec<usize>,
    pub coverage: Coverage,
}

/// One instruction naming one address of this program, how it uses it, and the smallest evidence that shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub role: Role,
    pub support: Support,
}

/// What the instruction does with the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// It calls there.
    Call,
    /// It transfers control there without a call.
    Jump,
    /// It reads this many bytes there.
    Read { width: u32 },
    /// It writes this many bytes there.
    Write { width: u32 },
    /// It computes the address as a result it uses as it stands.
    Value,
}

impl Role {
    /// How many bytes the instruction accesses at the address where it uses it
    /// as data, or `None` where it transfers control there, so the bytes are
    /// executed rather than read.
    pub const fn data_access(self) -> Option<u32> {
        match self {
            Self::Read { width } | Self::Write { width } => Some(width),
            Self::Value => Some(0),
            Self::Call | Self::Jump => None,
        }
    }
}

/// An instruction the index read references from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimant {
    /// The line as the index listed it, whose claims are its references.
    pub line: Line,
    /// Every function whose listing of it claims a reference, by entry, ascending: a shared tail has more than one.
    pub owners: Vec<u64>,
}

/// Every reference the lines of a listing claim, by the line that claims it.
pub fn claimed_by(lines: &[Line]) -> Vec<Reference> {
    lines.iter().flat_map(claims_of).collect()
}

/// The references one line claims.
fn claims_of(line: &Line) -> impl Iterator<Item = Reference> + '_ {
    line.annotations.iter().filter_map(|annotation| {
        Some(Reference {
            from: line.address,
            to: annotation.kind.address()?,
            role: annotation.role()?,
            support: annotation.support,
        })
    })
}

impl References {
    /// Every reference, by source.
    pub fn facts(&self) -> &[Reference] {
        &self.facts
    }

    /// Every reference to one address, by source, with the instruction it is from: a binary search, then the run.
    pub fn to(&self, target: u64) -> impl Iterator<Item = (&Reference, &Claimant)> {
        let start = self
            .by_target
            .partition_point(|at| self.facts[*at].to < target);
        self.by_target[start..]
            .iter()
            .map(|at| (&self.facts[*at], &self.sources[self.source_of[*at]]))
            .take_while(move |(fact, _)| fact.to == target)
    }
}

/// An index being read body by body.
#[derive(Default)]
pub(crate) struct Indexing {
    facts: Vec<Reference>,
    sources: BTreeMap<u64, Claimant>,
}

impl Indexing {
    /// Take one walked body's listing, keeping only the lines that claim a reference.
    pub(crate) fn read(&mut self, entry: u64, lines: Vec<Line>) {
        for line in lines {
            let before = self.facts.len();
            self.facts.extend(claims_of(&line));
            if self.facts.len() == before {
                continue;
            }
            let claimant = self.sources.entry(line.address).or_insert(Claimant {
                line,
                owners: Vec::new(),
            });
            // A body lists an instruction once per block that holds it, and the bodies come by entry.
            if claimant.owners.last() != Some(&entry) {
                claimant.owners.push(entry);
            }
        }
    }

    /// The index, in `O(R log R)` once: sorted by source, one support per reference, and ordered by target beside it.
    pub(crate) fn finish(self, coverage: Coverage) -> References {
        let mut facts = self.facts;
        facts.sort_unstable();
        // Sorted with the support last, so the first of a run is the smallest.
        facts.dedup_by_key(|fact| (fact.from, fact.to, fact.role));
        let mut by_target = (0..facts.len()).collect::<Vec<_>>();
        by_target.sort_unstable_by_key(|at| (facts[*at].to, *at));
        let sources = self.sources.into_values().collect::<Vec<_>>();
        // Both are by address and every fact's instruction is a source, so one merge pairs them.
        let mut next = 0;
        let source_of = facts
            .iter()
            .map(|fact| {
                while sources[next].line.address < fact.from {
                    next += 1;
                }
                next
            })
            .collect();
        References {
            facts,
            by_target,
            sources,
            source_of,
            coverage,
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
