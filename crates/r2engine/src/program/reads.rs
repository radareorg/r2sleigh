//! What the program's calls to a function read of its result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): each caller is lifted, never prepared, so no answer waits on its own function.

use std::collections::BTreeMap;
use std::sync::Arc;

use r2abi::statement::{Binding, EntryKind, Format, SectionRole, SourceLanguage, Symbol};
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
        // A call two bodies hold (one walk enters the other's tail) is one call, read once.
        let mut read = std::collections::BTreeSet::new();
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
                if !read.insert(lifted.instruction_of(index)) {
                    continue;
                }
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
        // A body not read may hold any reference.
        if !index.coverage.unread.is_empty() {
            r2il::refusal_evidence!(
                "closed-world",
                "{} bodies unread: not every way in is known",
                index.coverage.unread.len()
            );
            return None;
        }
        // Code no walk decoded (past an unresolved transfer, or never reached) may call or name
        // anything; a code byte no body, stub section or padding accounts for refuses.
        if let Some(at) = unaccounted_code(db, &survey) {
            r2il::refusal_evidence!("closed-world", "{at:#x}: code no body holds");
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

/// The first code byte the file holds that no walked body, linkage section or padding accounts
/// for: the sections the container states as code, else its executable segments.
fn unaccounted_code<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    survey: &super::requests::Survey,
) -> Option<u64> {
    let view = View::new(db, true);
    let container = view.source().container();
    let sections = (container.sections.iter())
        .filter(|section| section.role == SectionRole::Code && section.loaded)
        .map(|section| section.vaddr..section.vaddr + section.file_size.min(section.vsize))
        .collect::<Vec<_>>();
    let code = match sections.is_empty() {
        true => (container.segments.iter())
            .filter(|segment| segment.permissions.execute)
            .map(|segment| segment.vaddr..segment.vaddr + segment.file_size.min(segment.vsize))
            .collect(),
        false => sections,
    };
    let mut covered = survey.held().collect::<Vec<_>>();
    covered.extend((view.linkage().sections.iter()).map(|(start, end)| *start..*end));
    covered.sort_by_key(|range| range.start);
    let entries = survey.entries();
    let known = |address: u64| {
        entries.binary_search(&address).is_ok()
            || covered.iter().any(|held| held.contains(&address))
    };
    let walker = super::returns::Walking::new(view.clone(), true).ok()?;
    let disasm = walker.target(false).disasm;
    for range in code.into_iter().filter(|range| range.start < range.end) {
        let mut at = range.start;
        for held in covered
            .iter()
            .filter(|held| held.end > range.start && held.start < range.end)
        {
            if held.start > at && !padding(&view, disasm, &known, at..held.start) {
                return Some(at);
            }
            at = at.max(held.end);
        }
        if at < range.end && !padding(&view, disasm, &known, at..range.end) {
            return Some(at);
        }
    }
    None
}

/// Whether these bytes hold no code that could reach or name a function discovery does not know:
/// zeros, instructions that lift to no operation, traps, or direct transfers to known code (a call
/// to `abort` after one that never returns). An indirect transfer is unknown code.
fn padding<S: Source + 'static>(
    view: &View<'_, S>,
    disasm: &r2sleigh_lift::Disassembler,
    known: &dyn Fn(u64) -> bool,
    bytes: std::ops::Range<u64>,
) -> bool {
    let Some(held) = usize::try_from(bytes.end - bytes.start)
        .ok()
        .and_then(|size| view.source().read(bytes.start, size))
    else {
        return false;
    };
    let mut at = 0;
    while at < held.len() {
        if held[at] == 0 {
            at += 1;
            continue;
        }
        let mut window = held[at..].to_vec();
        window.resize(crate::body::WINDOW.max(window.len()), 0);
        let address = bytes.start + at as u64;
        let inert = |lifted: &r2il::R2ILBlock| {
            let mut transfers = lifted
                .ops
                .iter()
                .filter(|op| op.is_control_flow())
                .peekable();
            lifted.ops.is_empty()
                || (transfers.peek().is_some()
                    && transfers.all(|op| {
                        matches!(op, r2il::R2ILOp::Breakpoint)
                            || (op.transfer()).is_some_and(|transfer| {
                                transfer.direct && known(transfer.target.offset)
                            })
                    }))
        };
        match disasm.lift_after(&window, address, None) {
            Ok((lifted, _)) if lifted.size > 0 && inert(&lifted) => {
                at += lifted.size as usize;
            }
            _ => return false,
        }
    }
    true
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
