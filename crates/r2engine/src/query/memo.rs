//! What a request does not have to do again.
//!
//! Every tier of one function is a rendering of one analysis, and a session
//! asks for several of them: the C, then the obligation ledger behind it, then
//! the values the renderer bound. Each of those used to walk the body, lift
//! every block, walk and prepare every callee, and prepare the root again.
//! Measured on this tree, a repeat of the cheapest tier cost 18 ms of work
//! whose inputs had not changed.
//!
//! **The key states the identity rather than asserting it.** The program's
//! revision says which open program this is and how many times its bytes have
//! been written, so two requests carrying one revision are about one state of
//! one program -- not probably, by construction, because every write bumps the
//! counter and every open mints a fresh identity. That is the same standard
//! the byte-for-byte comparison this replaces was held to, at the cost of a
//! comparison of four integers rather than of a whole serialized capture, and
//! it is why there is no hash anywhere here: a hash small enough to store
//! claims both that it covers every input and that no two inputs collide, and
//! neither can be checked at the point of use. A miss costs time; a wrong hit
//! renders a body that is not the function's and nothing downstream would say
//! so.
//!
//! **What bounds it.** One analysis, the most recent. A session sweeping a
//! binary asks about each function exactly once, so every entry but the last
//! would be dead weight, and an interactive session asking about one function
//! again is served by the one entry. A prepared body is megabytes on a large
//! function, so the bound has to be the request in hand rather than a number
//! chosen to look large enough.

use std::sync::{Arc, Mutex};

use crate::native::NativeRefusal;
use crate::query::Revision;

/// What the memo has been asked and what it holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoStats {
    pub hits: u64,
    pub misses: u64,
    /// Lookups that found the function and refused it because the program had
    /// moved on. Worth separating from a first-ever miss: a session full of
    /// these means something is writing between requests.
    pub replacements: u64,
}

/// The one analysis a session holds, and what identifies it.
struct Held<T> {
    revision: Revision,
    entry: u64,
    /// Kept whether it succeeded or refused, because a refusal is as much a
    /// function of the program's state as an answer is, and re-deriving one
    /// costs exactly what deriving it did.
    analysis: Result<Arc<T>, NativeRefusal>,
}

/// The most recent analysis, and nothing older.
///
/// Generic in what it holds so the map's own behaviour can be tested without
/// preparing a real function, which needs an image and a Sleigh profile.
pub struct Memo<T> {
    held: Mutex<Option<Held<T>>>,
    stats: Mutex<MemoStats>,
}

impl<T> Default for Memo<T> {
    fn default() -> Self {
        Self {
            held: Mutex::new(None),
            stats: Mutex::new(MemoStats::default()),
        }
    }
}

impl<T> Memo<T> {
    /// The analysis of one function at one revision, derived if it is not held.
    pub fn analysed(
        &self,
        revision: Revision,
        entry: u64,
        derive: impl FnOnce() -> Result<T, NativeRefusal>,
    ) -> Result<Arc<T>, NativeRefusal> {
        if let Some(held) = self.lookup(revision, entry) {
            return held;
        }
        let analysis = derive().map(Arc::new);
        let mut held = self.held.lock().unwrap_or_else(|held| held.into_inner());
        *held = Some(Held {
            revision,
            entry,
            analysis: analysis.clone(),
        });
        analysis
    }

    fn lookup(&self, revision: Revision, entry: u64) -> Option<Result<Arc<T>, NativeRefusal>> {
        let held = self.held.lock().unwrap_or_else(|held| held.into_inner());
        let mut stats = self.stats.lock().unwrap_or_else(|stats| stats.into_inner());
        match held.as_ref() {
            Some(held) if held.entry == entry && held.revision == revision => {
                stats.hits += 1;
                Some(held.analysis.clone())
            }
            Some(held) if held.entry == entry => {
                stats.replacements += 1;
                stats.misses += 1;
                None
            }
            _ => {
                stats.misses += 1;
                None
            }
        }
    }

    pub fn stats(&self) -> MemoStats {
        *self.stats.lock().unwrap_or_else(|stats| stats.into_inner())
    }
}

impl<T> std::fmt::Debug for Memo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memo")
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(bytes: u64) -> Revision {
        Revision {
            program: 7,
            bytes,
            names: 0,
            entries: 0,
        }
    }

    fn memo() -> Memo<u32> {
        Memo::default()
    }

    #[test]
    fn one_function_at_one_revision_is_derived_once() {
        let memo = memo();
        assert_eq!(
            *memo.analysed(at(0), 0x1000, || Ok(99)).expect("derived"),
            99
        );
        let again = memo
            .analysed(at(0), 0x1000, || panic!("the held analysis answers"))
            .expect("held");
        assert_eq!(*again, 99);
        let stats = memo.stats();
        assert_eq!((stats.hits, stats.misses, stats.replacements), (1, 1, 0));
    }

    #[test]
    fn the_same_function_at_a_later_revision_is_a_replacement_not_a_hit() {
        let memo = memo();
        memo.analysed(at(0), 0x1000, || Ok(99)).expect("derived");
        assert_eq!(
            *memo.analysed(at(1), 0x1000, || Ok(100)).expect("derived"),
            100
        );
        let stats = memo.stats();
        assert_eq!((stats.hits, stats.replacements), (0, 1));
        // And the replacement is the one entry, not a second beside it.
        assert!(memo.lookup(at(0), 0x1000).is_none());
    }

    #[test]
    fn the_same_bytes_in_another_program_are_not_this_program() {
        // Two opens of one file are two programs: one may be patched and the
        // other not, and nothing in the counters alone would tell them apart.
        let memo = memo();
        memo.analysed(at(0), 0x1000, || Ok(99)).expect("derived");
        let elsewhere = Revision {
            program: 8,
            ..at(0)
        };
        assert_eq!(
            *memo
                .analysed(elsewhere, 0x1000, || Ok(100))
                .expect("derived"),
            100
        );
    }

    #[test]
    fn another_function_is_a_plain_miss() {
        let memo = memo();
        memo.analysed(at(0), 0x1000, || Ok(99)).expect("derived");
        memo.analysed(at(0), 0x2000, || Ok(100)).expect("derived");
        let stats = memo.stats();
        assert_eq!((stats.misses, stats.replacements), (2, 0));
    }

    #[test]
    fn a_refusal_is_held_the_way_an_answer_is() {
        let memo = memo();
        let refused = memo.analysed(at(0), 0x1000, || Err(NativeRefusal::NoStackPointer));
        assert_eq!(refused.unwrap_err(), NativeRefusal::NoStackPointer);
        let again = memo.analysed(at(0), 0x1000, || panic!("the held refusal answers"));
        assert_eq!(again.unwrap_err(), NativeRefusal::NoStackPointer);
        assert_eq!(memo.stats().hits, 1);
    }
}
