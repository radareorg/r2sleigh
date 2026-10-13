//! What the program's calls to a function read of its result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): each caller is lifted, never prepared, so no answer waits on its own function.

use std::collections::BTreeMap;
use std::sync::Arc;

use r2abi::statement::{Binding, EntryKind, Format, SourceLanguage, Symbol};
use r2source::SourceResultReads;

use super::requests::{ReferenceIndex, SurveyQuery};
use super::{ProgramInputs, Source, View};
use crate::query::db::{Db, Query, Retention};
use crate::query::references::Role;

/// The reads at every call to one function, by its entry: what each read or overwrote of the result
/// registers; `None` where the program makes no call to it the walk can read.
pub(super) struct ResultReads;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ResultReads {
    type Key = u64;
    type Value = Option<SourceResultReads>;
    const NAME: &'static str = "result-reads";
    const RETENTION: Retention = Retention::Held;

    /// Work: one lift per caller discovery found, each read from each call the walk found to `callee`
    /// to its block's end.
    fn compute(db: &Db<ProgramInputs<S>>, &callee: &u64) -> Self::Value {
        let survey = db.get::<SurveyQuery>(&()).ok()?;
        let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        let mut reads = SourceResultReads::default();
        // A caller that is not read may read the result: the calls read are then not every call.
        let mut unread = false;
        for &caller in survey.callers_of(callee) {
            let Some(Ok(thumb)) = survey.walked_in(caller) else {
                unread = true;
                continue;
            };
            let target = walker.target(thumb);
            let Ok(slots) = crate::native::convention_slots(target) else {
                unread = true;
                continue;
            };
            let Ok(body) = crate::body::lift_body(caller, target.disasm, &view, &BTreeMap::new())
            else {
                unread = true;
                continue;
            };
            let calls = body.blocks.iter().flat_map(|block| {
                (block.transfers.iter())
                    .filter(|transfer| {
                        transfer.target == callee
                            && transfer.kind == r2source::AdvisoryCallTransfer::Call
                    })
                    .map(move |transfer| (&block.lifted, transfer.op))
            });
            for (lifted, index) in calls {
                reads = reads.and(r2ssa::caller_reads::reads_after_call(
                    lifted,
                    index,
                    slots.result_slot(),
                    slots.float_result_slot(),
                    slots.second_result_slot(),
                ));
            }
        }
        // Only a result no call reads asks whether the calls are every way in: the reference index
        // that answers reads every body.
        reads.exhaustive =
            !unread && reads.all_overwrite(false) && only_called(db, callee, reads.calls);
        (reads.calls > 0).then_some(reads)
    }
}

/// Whether the program enters `callee` only by the `calls` read: no other way in it shows, and every
/// call the reference index claims is one of them (doc/adr-resolved-bodies.md, "Closed world").
fn only_called<S: Source + 'static>(db: &Db<ProgramInputs<S>>, callee: u64, calls: u32) -> bool {
    let language = db.inputs().source.container().languages.at(callee);
    // Swift, Objective-C, Go and .NET reach functions through tables of relative offsets no word holds.
    if !matches!(
        language,
        SourceLanguage::C | SourceLanguage::Cpp | SourceLanguage::Rust
    ) {
        return false;
    }
    let Ok(escapes) = db.get::<Escapes>(&()) else {
        return false;
    };
    let Some(escaped) = escapes.as_ref() else {
        return false;
    };
    if escaped.binary_search(&callee).is_ok() {
        r2il::refusal_evidence!("closed-world", "{callee:#x}: a way in other than a call");
        return false;
    }
    let Ok(index) = db.get::<ReferenceIndex>(&()) else {
        return false;
    };
    let Ok(index) = index.as_ref() else {
        return false;
    };
    let claimed = (index.0.to(callee))
        .filter(|(fact, _)| fact.role == Role::Call)
        .count();
    let all = usize::try_from(calls).is_ok_and(|calls| calls == claimed);
    if !all {
        r2il::refusal_evidence!(
            "closed-world",
            "{callee:#x}: {calls} calls read, {claimed} claimed by the index"
        );
    }
    all
}

/// The functions the program enters other than by a direct call, by entry, ascending; `None` where
/// it does not show every way in (doc/adr-resolved-bodies.md, "Closed world").
pub(super) struct Escapes;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Escapes {
    type Key = ();
    type Value = Option<Arc<[u64]>>;
    const NAME: &'static str = "escapes";
    const RETENTION: Retention = Retention::Held;

    /// Work: one pass over the references, symbols and entries, and one over every mapped file byte
    /// (a range check per word, a search per word in range): `O(R + S + B log F)`.
    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let source = &db.inputs().source;
        let container = source.container();
        // x86-64 and AArch64 build an address whole, in one instruction or word the index or a scan
        // reads; a machine that splits one across immediates (`movw`/`movt`, `lui`) hides it from both.
        let whole = container.arch.bits == 64
            && matches!(r2abi::family(&container.arch.name), Some("x86" | "arm"));
        if !whole || !matches!(container.format, Format::Elf | Format::MachO) {
            return None;
        }
        let survey = db.get::<SurveyQuery>(&()).ok()?;
        let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
        let index = db.get::<ReferenceIndex>(&()).ok()?;
        let index = Arc::clone(&index.as_ref().as_ref().ok()?.0);
        // A body not read, or code past a transfer no walk resolved, may hold any reference.
        if !index.coverage.unread.is_empty() || !index.coverage.unresolved.is_empty() {
            r2il::refusal_evidence!(
                "closed-world",
                "{} bodies unread, {} with unresolved transfers: not every way in is known",
                index.coverage.unread.len(),
                index.coverage.unresolved.len()
            );
            return None;
        }
        let mut escaped = Vec::new();
        for (fact, claimant) in index.claimed() {
            // A jump inside a function to its own entry is a loop, no way in.
            let looping = fact.role == Role::Jump && claimant.owners.contains(&fact.to);
            if fact.role != Role::Call && !looping {
                escaped.push(fact.to);
            }
        }
        escaped.extend(
            (container.entries.iter())
                .filter(|entry| !matches!(entry.kind, EntryKind::Symbol | EntryKind::Declared))
                .map(|entry| entry.vaddr),
        );
        escaped.extend(
            (container.symbols.iter())
                .filter(|symbol| exported(container.format, symbol))
                .map(|symbol| symbol.vaddr),
        );
        stored_words(source, &survey.entries(), &mut escaped);
        escaped.sort_unstable();
        escaped.dedup();
        Some(escaped.into())
    }
}

/// Whether another image may call the function `symbol` names: ELF's dynamic table, or any Mach-O
/// symbol not local to its file.
fn exported(format: Format, symbol: &Symbol) -> bool {
    symbol.defined
        && match format {
            Format::Elf => symbol.origin.dynamic.is_some(),
            _ => symbol.binding != Binding::Local,
        }
}

/// Each of `entries` some mapped file word names: pointer-wide at any offset, and on a 64-bit machine
/// 32 bits wide too (an `imm32` or `.long` of a non-PIE address), with bit 0 cleared as Thumb sets it.
fn stored_words<S: Source>(source: &S, entries: &[u64], escaped: &mut Vec<u64>) {
    let (Some(&low), Some(&high)) = (entries.first(), entries.last()) else {
        return;
    };
    let little = super::view::endian(source) == r2il::Endianness::Little;
    let widths: &[usize] = match source.container().arch.bits {
        64 => &[8, 4],
        _ => &[4],
    };
    for segment in &source.container().segments {
        let Some(bytes) = usize::try_from(segment.file_size)
            .ok()
            .filter(|size| *size > 0)
            .and_then(|size| source.read(segment.vaddr, size))
        else {
            continue;
        };
        for &width in widths {
            for window in bytes.windows(width) {
                let mut word = [0u8; 8];
                let word = if little {
                    word[..width].copy_from_slice(window);
                    u64::from_le_bytes(word)
                } else {
                    word[8 - width..].copy_from_slice(window);
                    u64::from_be_bytes(word)
                };
                for value in [word, word & !1] {
                    if (low..=high).contains(&value) && entries.binary_search(&value).is_ok() {
                        escaped.push(value);
                    }
                }
            }
        }
    }
}
