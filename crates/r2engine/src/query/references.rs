//! The reverse-reference index, and the scope it was built over.
//!
//! An index built from the bodies the walk resolved says nothing about code no
//! walk reached: what lies behind an indirect branch it could not follow, or a
//! body it could not walk at all. So the facts never travel without that
//! scope, and an address missing from them is absent within it, not absent.
//!
//! Each fact is a claim the listing makes about one instruction, so `ax` and `pdf` cannot disagree.

use std::collections::BTreeMap;

use crate::body::{Unresolved, UnresolvedReason};

use super::Line;
use crate::native::NativeRefusal;
use r2source::confidence::Basis;

/// Every reference the resolved bodies make (`Walked`, as `pdf` lists them), and what the walks covered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct References {
    /// By source, then target and role, each with the smallest support any listing of it gave.
    facts: Vec<Reference>,
    /// Positions in `facts` ordered by target, so the references to one address are one run.
    by_target: Vec<usize>,
    /// Each instruction a fact is from, as columns by address: no decoded line is held (D612).
    sources: Sources,
    /// Where in `sources` each fact's instruction is.
    source_of: Vec<usize>,
    pub coverage: Coverage,
}

/// The claiming instructions as columns, ascending by address; owners are one compressed row set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Sources {
    addresses: Vec<u64>,
    lengths: Vec<u8>,
    /// Bit `i` is set where source `i` is a word the loader writes, not an instruction.
    words: Vec<u64>,
    /// `owners[start[i]..start[i + 1]]` are source `i`'s.
    start: Vec<u32>,
    owners: Vec<u64>,
}

impl Sources {
    /// Source `at`: `O(1)`.
    fn claim(&self, at: usize) -> Claim<'_> {
        let owners = self.start[at] as usize..self.start[at + 1] as usize;
        Claim {
            address: self.addresses[at],
            length: self.lengths[at],
            word: self.words[at / 64] >> (at % 64) & 1 == 1,
            owners: &self.owners[owners],
        }
    }
}

/// One instruction naming one address of this program, how it uses it, and the smallest evidence that shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub role: Role,
    pub support: Basis,
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

/// Every reference to one address, as `axt` lists them, and the index they come from.
pub struct ReferencesTo {
    /// By source, as [`References::to`] gives them.
    pub referring: Vec<Referring>,
    pub index: std::sync::Arc<References>,
}

/// One reference with the instruction it is from.
pub struct Referring {
    pub fact: Reference,
    /// Every function holding the instruction, by entry; none for a loader word.
    pub owners: Vec<u64>,
    /// The line as the index's listing of the first owner gives it; `None` for a loader word.
    pub line: Option<Line>,
}

/// An instruction the index read references from, or a word the loader writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim<'a> {
    pub address: u64,
    /// The instruction's byte length as the index first listed it; 0 for a word.
    pub length: u8,
    /// A loader-written word in data, which no function owns.
    pub word: bool,
    /// Every function whose listing of it claims a reference, by entry, ascending: a shared tail has more than one.
    pub owners: &'a [u64],
}

/// Every reference the lines of a listing claim, by the line that claims it.
pub fn claimed_by(lines: &[Line]) -> Vec<Reference> {
    lines.iter().flat_map(claims_of).collect()
}

/// Whether a line claims any reference: the index keeps the first that does.
pub(crate) fn claims(line: &Line) -> bool {
    claims_of(line).next().is_some()
}

/// The references one line claims.
fn claims_of(line: &Line) -> impl Iterator<Item = Reference> + '_ {
    line.annotations.iter().filter_map(|annotation| {
        Some(Reference {
            from: line.address,
            to: annotation.kind.address()?,
            role: annotation.role()?,
            support: annotation.confidence.basis,
        })
    })
}

impl References {
    /// Every reference, by source.
    pub fn facts(&self) -> &[Reference] {
        &self.facts
    }

    /// Every reference, by source, with the instruction that claims it.
    pub fn claimed(&self) -> impl Iterator<Item = (&Reference, Claim<'_>)> {
        (self.facts.iter())
            .zip(&self.source_of)
            .map(|(fact, at)| (fact, self.sources.claim(*at)))
    }

    /// Every reference to one address, by source, with the instruction it is from: a binary search, then the run.
    pub fn to(&self, target: u64) -> impl Iterator<Item = (&Reference, Claim<'_>)> {
        let start = self
            .by_target
            .partition_point(|at| self.facts[*at].to < target);
        self.by_target[start..]
            .iter()
            .map(|at| (&self.facts[*at], self.sources.claim(self.source_of[*at])))
            .take_while(move |(fact, _)| fact.to == target)
    }
}

/// An index being read body by body.
#[derive(Default)]
pub(crate) struct Indexing {
    facts: Vec<Reference>,
    /// One `(address, length, owner)` per claiming line in reading order; `None` owns a word.
    rows: Vec<(u64, u8, Option<u64>)>,
}

impl Indexing {
    /// Take one walked body's listing, keeping only each claiming line's address and length.
    pub(crate) fn read(&mut self, entry: u64, lines: Vec<Line>) {
        for line in lines {
            let before = self.facts.len();
            self.facts.extend(claims_of(&line));
            if self.facts.len() > before {
                self.rows.push((line.address, length(&line), Some(entry)));
            }
        }
    }

    /// Take every word the loader writes an address of this program into, as the container states it.
    ///
    /// A pointer in data refers to what it points at as surely as an
    /// instruction does, and the relocation type says it is an address: a
    /// relative one, a definition's, or a definition another image may
    /// replace, which the word still names until one does. A word belongs to
    /// no function, so it has no owner.
    pub(crate) fn read_words(
        &mut self,
        writes: &[crate::program::LoaderWrite],
        holds_code: impl Fn(u64) -> bool,
        coverage: &mut Coverage,
    ) {
        use r2abi::statement::{Encoding, WriteKind};
        for write in writes {
            // The loader calls a resolver; a word whose value no record states may name any code.
            let value = match (write.encoding, &write.kind) {
                (_, WriteKind::Resolver(resolver)) => *resolver,
                (_, WriteKind::Unknown) => {
                    coverage.unstated.push(write.place);
                    continue;
                }
                (Encoding::Word, _) => match write.stated_address() {
                    Some(value) => value,
                    None => continue,
                },
                (Encoding::FromPlace | Encoding::Field(_) | Encoding::Typed, _) => {
                    let code = write.target().filter(|target| holds_code(*target));
                    coverage.unstated.extend(code.map(|_| write.place));
                    continue;
                }
            };
            let line = Line {
                address: write.place,
                bytes: Vec::new(),
                syntax: None,
                flow: None,
                annotations: vec![super::Annotation {
                    kind: super::AnnotationKind::Points { value },
                    confidence: Basis::Stated.into(),
                    operand: None,
                    reference: true,
                }],
            };
            self.facts.extend(claims_of(&line));
            self.rows.push((write.place, 0, None));
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
        let sources = sources(self.rows);
        // Both are by address and every fact's instruction is a source, so one merge pairs them.
        let mut next = 0;
        let source_of = facts
            .iter()
            .map(|fact| {
                while sources.addresses[next] < fact.from {
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

/// An instruction's byte length; every lifted instruction set's longest fits a byte.
fn length(line: &Line) -> u8 {
    u8::try_from(line.bytes.len()).expect("an instruction longer than 255 bytes")
}

/// The rows as columns, `O(R log R)`: a stable sort keeps reading order within one address, so a
/// source's length and kind are its first listing's, and its owners ascend as the bodies came.
fn sources(mut rows: Vec<(u64, u8, Option<u64>)>) -> Sources {
    rows.sort_by_key(|(address, _, _)| *address);
    let mut sources = Sources::default();
    let mut first = 0;
    for (address, length, owner) in rows {
        if sources.addresses.last() != Some(&address) {
            let at = sources.addresses.len();
            if at % 64 == 0 {
                sources.words.push(0);
            }
            sources.words[at / 64] |= u64::from(owner.is_none()) << (at % 64);
            sources.addresses.push(address);
            sources.lengths.push(length);
            first = sources.owners.len();
            sources.start.push(start(first));
        }
        // A body lists an instruction once per block that holds it, and the bodies come by entry.
        if let Some(owner) = owner.filter(|owner| sources.owners[first..].last() != Some(owner)) {
            sources.owners.push(owner);
        }
    }
    sources.start.push(start(sources.owners.len()));
    sources
}

/// A position in the owner column.
fn start(at: usize) -> u32 {
    u32::try_from(at).expect("more than 2^32 owner rows")
}

/// Bytes a function's listing leaves between two of its lines (D622).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub range: std::ops::Range<u64>,
    /// Whether a walked body holds any byte; else every byte is in no walked body.
    pub held: bool,
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
    /// Each place the loader writes a value the index cannot read: a word no record states, or a
    /// field forming an address of code (doc/adr-result-side.md, "The closed world").
    pub unstated: Vec<u64>,
    /// The survey's count of indirect transfers no walk followed, the header's own (D619); `None`
    /// where a body is unwalked.
    pub indirect: Option<usize>,
}

/// Why one function contributed nothing to the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// The body could not be walked.
    Refused(NativeRefusal),
    /// A number the body computes needed its def-use to say whether it is a step, and that did not build.
    NoSsa(r2ssa::SsaPrepareError),
}

impl Coverage {
    /// How many walk stops are unreadable bytes rather than indirect branches, across every function.
    pub fn unreadable_count(&self) -> usize {
        let stops = self.unresolved.values().flatten();
        stops
            .filter(|stop| stop.reason != UnresolvedReason::IndirectBranch)
            .count()
    }

    /// How many indirect transfers no walk followed: opaque calls and unresolved dispatches, as the
    /// survey counts them for every header (D619).
    pub fn indirect_count(&self) -> Option<usize> {
        self.indirect
    }

    /// Whether every believed body was read and walked to its end, every indirect transfer followed.
    pub fn is_closed(&self) -> bool {
        self.unread.is_empty() && self.unresolved.is_empty() && self.indirect == Some(0)
    }
}
