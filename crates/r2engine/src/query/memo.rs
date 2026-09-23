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
//! **Only answers are held.** Re-deriving a refusal costs exactly what
//! deriving it did, which is a real temptation to keep one. It is still wrong:
//! a request can be cancelled or run out of its deadline, and a refusal for
//! that reason is a fact about the request rather than about the program.
//! Holding one would serve somebody else's timeout as this program's answer.
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
    /// Type analyses run, a refused one included.
    pub sealed: u64,
}

/// The one analysis a session holds, and what identifies it.
struct Held<T, S> {
    revision: Revision,
    entry: u64,
    analysis: Arc<T>,
    /// Which bytes deriving it read. A write that missed every one of them --
    /// a patch to another function -- leaves this answer about this program.
    read: Vec<std::ops::Range<u64>>,
    /// The type analysis sealed from exactly this analysis, once a request sealed it.
    sealed: Option<S>,
}

/// The most recent analysis, and nothing older.
///
/// Generic in what it holds so the map's own behaviour can be tested without
/// preparing a real function, which needs an image and a Sleigh profile.
pub struct Memo<T, S> {
    held: Mutex<Option<Held<T, S>>>,
    stats: Mutex<MemoStats>,
}

impl<T, S> Default for Memo<T, S> {
    fn default() -> Self {
        Self {
            held: Mutex::new(None),
            stats: Mutex::new(MemoStats::default()),
        }
    }
}

impl<T, S> Memo<T, S> {
    /// The held answer, where the program has not moved under it.
    ///
    /// `written_since` says whether anything in a range has been written since
    /// a revision. A write that missed every byte the derivation read leaves
    /// the answer standing, which is what a patch to another function is; the
    /// name and entry tables are compared whole, because a walk consults them
    /// about addresses it never read.
    ///
    /// `derive` answers with the analysis and the bytes it read, together, so
    /// the read set held is always the one that derivation made. Recorded by a
    /// second call, a hit -- which reads nothing -- wrote an empty set over it,
    /// and the answer then stood against every later write.
    pub fn analysed_since(
        &self,
        revision: Revision,
        entry: u64,
        written_since: &dyn Fn(u64, &std::ops::Range<u64>) -> bool,
        derive: impl FnOnce() -> Result<(T, Vec<std::ops::Range<u64>>), NativeRefusal>,
    ) -> Result<Arc<T>, NativeRefusal> {
        if let Some(held) = self.lookup_against(revision, entry, written_since) {
            return Ok(held);
        }
        let (analysis, read) = derive()?;
        let analysis = Arc::new(analysis);
        let mut held = self.held.lock().unwrap_or_else(|held| held.into_inner());
        *held = Some(Held {
            revision,
            entry,
            analysis: Arc::clone(&analysis),
            read: coalesced(read),
            sealed: None,
        });
        Ok(analysis)
    }

    fn lookup_against(
        &self,
        revision: Revision,
        entry: u64,
        written_since: &dyn Fn(u64, &std::ops::Range<u64>) -> bool,
    ) -> Option<Arc<T>> {
        let held = self.held.lock().unwrap_or_else(|held| held.into_inner());
        let mut stats = self.stats.lock().unwrap_or_else(|stats| stats.into_inner());
        match held.as_ref() {
            Some(held)
                if held.entry == entry
                    && held.revision.program == revision.program
                    && held.revision.names == revision.names
                    && held.revision.entries == revision.entries
                    && !held
                        .read
                        .iter()
                        .any(|range| written_since(held.revision.bytes, range)) =>
            {
                stats.hits += 1;
                Some(Arc::clone(&held.analysis))
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

    /// Read the type analysis sealed from exactly this held analysis, sealing it first; a refusal is counted, not held.
    pub fn read_sealed<E, R>(
        &self,
        analysis: &Arc<T>,
        seal: impl FnOnce() -> Result<S, E>,
        read: impl FnOnce(&S) -> R,
    ) -> Result<R, E> {
        let beside = |held: &Held<T, S>| Arc::ptr_eq(&held.analysis, analysis);
        {
            let held = self.held.lock().unwrap_or_else(|held| held.into_inner());
            if let Some(sealed) = held
                .as_ref()
                .filter(|held| beside(held))
                .and_then(|held| held.sealed.as_ref())
            {
                return Ok(read(sealed));
            }
        }
        self.stats
            .lock()
            .unwrap_or_else(|stats| stats.into_inner())
            .sealed += 1;
        let sealed = seal()?;
        let mut held = self.held.lock().unwrap_or_else(|held| held.into_inner());
        Ok(match held.as_mut().filter(|held| beside(held)) {
            Some(held) => read(held.sealed.insert(sealed)),
            None => read(&sealed),
        })
    }

    pub fn stats(&self) -> MemoStats {
        *self.stats.lock().unwrap_or_else(|stats| stats.into_inner())
    }
}

impl<T, S> std::fmt::Debug for Memo<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memo")
            .field("stats", &self.stats())
            .finish()
    }
}

/// One range per run of addresses, so a walk's thousands of reads become the
/// handful of extents it actually covered.
fn coalesced(read: impl IntoIterator<Item = std::ops::Range<u64>>) -> Vec<std::ops::Range<u64>> {
    let mut ranges: Vec<std::ops::Range<u64>> = read
        .into_iter()
        .filter(|range| range.start < range.end)
        .collect();
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<std::ops::Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
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

    fn memo() -> Memo<u32, u64> {
        Memo::default()
    }

    /// Nothing has been written at all.
    fn untouched(_since: u64, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    /// Everything the answer read has been written over.
    fn overwritten(_since: u64, _range: &std::ops::Range<u64>) -> bool {
        true
    }

    /// An answer, and the bytes deriving it read.
    fn reading(value: u32) -> Result<(u32, Vec<std::ops::Range<u64>>), NativeRefusal> {
        Ok((value, std::iter::once(0x1000..0x1010).collect()))
    }

    fn derived(memo: &Memo<u32, u64>, revision: Revision, value: u32) -> Arc<u32> {
        memo.analysed_since(revision, 0x1000, &untouched, || reading(value))
            .expect("derived")
    }

    #[test]
    fn one_function_at_one_revision_is_derived_once() {
        let memo = memo();
        assert_eq!(*derived(&memo, at(0), 99), 99);
        let again = memo
            .analysed_since(at(0), 0x1000, &untouched, || {
                panic!("the held analysis answers")
            })
            .expect("held");
        assert_eq!(*again, 99);
        let stats = memo.stats();
        assert_eq!((stats.hits, stats.misses, stats.replacements), (1, 1, 0));
    }

    #[test]
    fn a_refused_sealing_is_not_held_and_a_sealed_one_is() {
        let memo = memo();
        let analysis = derived(&memo, at(0), 99);
        let read = |sealed: &u64| *sealed;
        assert_eq!(
            memo.read_sealed(&analysis, || Err("stopped"), read),
            Err("stopped")
        );
        assert_eq!(
            memo.read_sealed(&analysis, || Ok::<_, &str>(7), read),
            Ok(7)
        );
        let held = memo.read_sealed(
            &analysis,
            || -> Result<u64, &str> { panic!("the held sealing answers") },
            read,
        );
        assert_eq!(held, Ok(7));
        assert_eq!(memo.stats().sealed, 2);
    }

    #[test]
    fn a_write_over_what_it_read_is_a_replacement_not_a_hit() {
        let memo = memo();
        derived(&memo, at(0), 99);
        let value = memo
            .analysed_since(at(1), 0x1000, &overwritten, || reading(100))
            .expect("derived");
        assert_eq!(*value, 100);
        assert_eq!((memo.stats().hits, memo.stats().replacements), (0, 1));
    }

    #[test]
    fn a_write_that_missed_everything_it_read_leaves_it_standing() {
        // A patch to another function. The bytes moved and this answer is
        // still about this program, which is the whole point of recording
        // which bytes it read.
        let memo = memo();
        derived(&memo, at(0), 99);
        let held = memo
            .analysed_since(at(1), 0x1000, &untouched, || {
                panic!("the held analysis answers")
            })
            .expect("held");
        assert_eq!(*held, 99);
        assert_eq!(memo.stats().hits, 1);
    }

    #[test]
    fn a_renaming_or_a_moved_entry_is_a_replacement() {
        // A walk asks what the program defines at addresses it never reads, so
        // those tables are compared whole rather than by what was read.
        for moved in [
            Revision { names: 1, ..at(1) },
            Revision {
                entries: 1,
                ..at(1)
            },
        ] {
            let memo = memo();
            derived(&memo, at(0), 99);
            let value = memo
                .analysed_since(moved, 0x1000, &untouched, || reading(100))
                .expect("derived");
            assert_eq!(*value, 100);
        }
    }

    #[test]
    fn the_same_bytes_in_another_program_are_not_this_program() {
        // Two opens of one file are two programs: one may be patched and the
        // other not, and nothing in the counters alone would tell them apart.
        let memo = memo();
        derived(&memo, at(0), 99);
        let elsewhere = Revision {
            program: 8,
            ..at(0)
        };
        assert_eq!(*derived(&memo, elsewhere, 100), 100);
    }

    #[test]
    fn another_function_is_a_plain_miss() {
        let memo = memo();
        derived(&memo, at(0), 99);
        memo.analysed_since(at(0), 0x2000, &untouched, || reading(100))
            .expect("derived");
        let stats = memo.stats();
        assert_eq!((stats.misses, stats.replacements), (2, 0));
    }

    #[test]
    fn a_refusal_is_not_held() {
        // A request that was cancelled or ran out of its deadline refuses, and
        // that is a fact about the request. Holding one would serve somebody
        // else's timeout as this program's answer.
        let memo = memo();
        let refused = memo.analysed_since(at(0), 0x1000, &untouched, || {
            Err(NativeRefusal::NoStackPointer)
        });
        assert_eq!(refused.unwrap_err(), NativeRefusal::NoStackPointer);
        assert_eq!(*derived(&memo, at(0), 99), 99);
    }

    #[test]
    fn a_read_is_recorded_as_the_extents_it_covered() {
        assert_eq!(
            coalesced([
                0x1000..0x1004,
                0x1004..0x1008,
                0x2000..0x2004,
                0x1002..0x1003,
                // An empty read covers no byte, so no write can land in it.
                0x3000..0x3000
            ]),
            vec![0x1000..0x1008, 0x2000..0x2004]
        );
    }
}
