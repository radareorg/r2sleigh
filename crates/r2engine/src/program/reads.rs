//! Whether the program's calls to a function are every way in (doc/adr-resolved-bodies.md, "Closed
//! world"), which a closed-world boundary needs before it reads every call dead.

use std::sync::Arc;

use r2abi::statement::{Applies, Binding, EntryKind, Format, SectionRole, SourceLanguage, Symbol};

use super::requests::{ReferenceIndex, SurveyQuery};
use super::{ProgramInputs, Source, View};
use crate::query::db::{Db, Query, Retention};
use crate::query::references::Role;

/// Whether the program enters `callee` only by the `calls` read: no other way in it shows, and every
/// call the reference index claims is one of them (doc/adr-resolved-bodies.md, "Closed world").
pub(super) fn only_called<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
    calls: u32,
) -> bool {
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
    let Some(ways) = escapes.as_ref() else {
        return false;
    };
    if ways.escapes(callee) {
        r2il::refusal_evidence!("closed-world", "{callee:#x}: a way in other than a call");
        return false;
    }
    calls_claimed(db, callee, calls)
}

/// Whether the `calls` read are every call the reference index claims to `callee`.
pub(super) fn calls_claimed<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    callee: u64,
    calls: u32,
) -> bool {
    let Ok(index) = db.get::<ReferenceIndex>(&()) else {
        return false;
    };
    let Ok(index) = index.as_ref() else {
        return false;
    };
    let claimed = (index.0.to(callee))
        .filter(|(fact, _)| fact.role == Role::Call)
        .count();
    let all = every_call_read(calls, claimed);
    if !all {
        r2il::refusal_evidence!(
            "closed-world",
            "{callee:#x}: {calls} calls read, {claimed} claimed by the index"
        );
    }
    all
}

/// Whether the calls a boundary read are every call the index claims: one short is a call unread.
fn every_call_read(calls: u32, claimed: usize) -> bool {
    usize::try_from(calls).is_ok_and(|calls| calls == claimed)
}

/// The ways the program enters functions other than by a direct call; `None` where it does not
/// show every way in (doc/adr-resolved-bodies.md, "Closed world").
pub(super) struct Escapes;

/// Every way in other than a call: what escapes, and each address a body's instruction takes.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct WaysIn {
    /// Entries reached other than by a call or a take, ascending.
    escaped: Box<[u64]>,
    /// Each instruction that forms a function's address in a body (`Role::Value`), by target.
    takes: Box<[Take]>,
    /// `takes` by owner, then instruction: indices into it.
    by_owner: Box<[u32]>,
}

/// One instruction of `owner` forming `target`'s address (S30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Take {
    pub(super) target: u64,
    pub(super) from: u64,
    pub(super) owner: u64,
    /// The end of the instruction's bytes: an immediate inside them is this take, no other way in.
    pub(super) end: u64,
}

impl WaysIn {
    /// Whether `entry` is reached other than by a call: a take is a way in. `O(log n)`.
    pub(super) fn escapes(&self, entry: u64) -> bool {
        self.escaped.binary_search(&entry).is_ok() || !self.takes_of(entry).is_empty()
    }

    /// Whether `entry` escapes other than by a take.
    pub(super) fn escaped(&self, entry: u64) -> bool {
        self.escaped.binary_search(&entry).is_ok()
    }

    /// The takes `owner`'s instructions make, by instruction. `O(log n)`.
    pub(super) fn takes_from(&self, owner: u64) -> impl Iterator<Item = &Take> {
        let owner_of = |at: &u32| self.takes[*at as usize].owner;
        let start = self.by_owner.partition_point(|at| owner_of(at) < owner);
        let end = self.by_owner.partition_point(|at| owner_of(at) <= owner);
        (self.by_owner[start..end].iter()).map(|at| &self.takes[*at as usize])
    }

    /// The takes of `entry`. `O(log n)`.
    pub(super) fn takes_of(&self, entry: u64) -> &[Take] {
        let start = self.takes.partition_point(|take| take.target < entry);
        let end = self.takes.partition_point(|take| take.target <= entry);
        &self.takes[start..end]
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Escapes {
    type Key = ();
    type Value = Option<Arc<WaysIn>>;
    const NAME: &'static str = "escapes";
    const RETENTION: Retention = Retention::Held;

    /// Work: one pass over the references, symbols, entries and relocation records, a search of the
    /// loader's slots per reference and record, and one over every mapped file byte: `O(R log L + S + B log F)`.
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
        // Code no walk decoded may call or name anything; a code byte no body, stub section or padding
        // accounts for refuses before the index is built (doc/adr-call-boundary.md, "S7 cost").
        let mut escaped = Vec::new();
        if let Some(at) = unaccounted_code(db, &survey, &mut escaped) {
            r2il::refusal_evidence!("closed-world", "{at:#x}: code no body holds");
            return None;
        }
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
        // A loader write the index cannot read may name any function.
        if let Some(at) = index.coverage.unstated.first() {
            r2il::refusal_evidence!("closed-world", "{at:#x}: a loader write no record states");
            return None;
        }
        // A loader call a cited row states is a call whose read the row states, which `DirectSites`
        // joins; the slot stating it, and the loader's word there, name no other way in (D237, D240).
        let library = super::c_library(container);
        let mut slots = Vec::new();
        for entry in &container.entries {
            match r2abi::loader_call(container.format, library, entry.kind) {
                Some(call) => {
                    r2il::refusal_evidence!(
                        "closed-world",
                        "{:#x}: the loader's {:?} call reads {:?} ({})",
                        entry.vaddr,
                        entry.kind,
                        call.reads_result,
                        call.citation
                    );
                    slots.extend(
                        (entry.stated_at.and_then(|at| at.vaddr)).map(|at| (at, entry.vaddr)),
                    );
                }
                None if matches!(entry.kind, EntryKind::Symbol | EntryKind::Declared) => {}
                None => escaped.push(entry.vaddr),
            }
        }
        slots.sort_unstable();
        let mut takes = Vec::new();
        for (fact, claimant) in index.claimed() {
            // An address a body's instruction forms is a take, which S30 follows (`DeclaredSlot`).
            if fact.role == Role::Value && !claimant.owners.is_empty() {
                let end = claimant.line.address + claimant.line.bytes.len() as u64;
                let take = |owner: &u64| Take {
                    target: fact.to,
                    from: fact.from,
                    owner: *owner,
                    end,
                };
                takes.extend(claimant.owners.iter().map(take));
                continue;
            }
            // A jump inside a function to its own entry is a loop, no way in.
            let looping = fact.role == Role::Jump && claimant.owners.contains(&fact.to);
            // A PIE's slot is a loader write: the reference is the slot's own word.
            let slot =
                claimant.owners.is_empty() && slots.binary_search(&(fact.from, fact.to)).is_ok();
            if fact.role != Role::Call && !looping && !slot {
                escaped.push(fact.to);
            }
        }
        let mut stated = slots.iter().map(|(at, _)| *at).collect::<Vec<_>>();
        // A relative `RELA` record writing such a slot states the entry in its own addend word (D239).
        let addends = (container.relocations.iter())
            .filter(|record| {
                let entry = (slots
                    .binary_search_by_key(&record.vaddr, |(at, _)| *at)
                    .ok())
                .map(|at| slots[at].1);
                record.applies == Applies::Relative
                    && entry.is_some_and(|entry| record.addend == i64::try_from(entry).ok())
            })
            .filter_map(|record| record.addend_at.and_then(|at| at.vaddr));
        stated.extend(addends);
        stated.sort_unstable();
        escaped.extend(
            (container.symbols.iter())
                .filter(|symbol| exported(container.format, symbol))
                .map(|symbol| symbol.vaddr),
        );
        takes.sort_unstable();
        takes.dedup();
        let words = Words {
            stated: &stated,
            takes: &takes,
        };
        stored_words(source, &survey.entries(), &words, &mut escaped);
        escaped.sort_unstable();
        escaped.dedup();
        let mut by_owner = (0..takes.len())
            .map(|at| u32::try_from(at).expect("fewer than 2^32 takes"))
            .collect::<Vec<_>>();
        by_owner.sort_unstable_by_key(|at| {
            let take = &takes[*at as usize];
            (take.owner, take.from, take.target)
        });
        Some(Arc::new(WaysIn {
            escaped: escaped.into(),
            takes: takes.into(),
            by_owner: by_owner.into(),
        }))
    }
}

/// The first code byte the file holds that no walked body, linkage section or padding accounts
/// for: the sections the container states as code, else its executable segments.
fn unaccounted_code<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    survey: &super::requests::Survey,
    targets: &mut Vec<u64>,
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
    // An x86 instruction states an address whole; AArch64 splits one across `adrp` and `add`, which
    // only a body's def-use joins, so its code after an exit stays unheld.
    let whole = r2abi::family(&container.arch.name) == Some("x86");
    let mut filler = |gap: std::ops::Range<u64>| {
        let gap = Gap {
            after_exit: whole && survey.after_exit(gap.start),
            bytes: gap,
        };
        padding(&view, disasm, &known, gap, targets)
    };
    for range in code.into_iter().filter(|range| range.start < range.end) {
        let mut at = range.start;
        for held in covered
            .iter()
            .filter(|held| held.end > range.start && held.start < range.end)
        {
            if held.start > at && !filler(at..held.start) {
                return Some(at);
            }
            at = at.max(held.end);
        }
        if at < range.end && !filler(at..range.end) {
            return Some(at);
        }
    }
    None
}

/// Bytes between two held ranges, and whether they follow a call a walk ended at because its
/// callee never comes back (doc/adr-result-side.md, "S18b as built").
struct Gap {
    bytes: std::ops::Range<u64>,
    after_exit: bool,
}

/// Whether these bytes hold no code that could reach or name a function discovery does not know. Its direct
/// transfers' targets, and after an exit every address it holds, join `targets` (doc/adr-result-side.md, "S18b as built"). `O(bytes)`.
fn padding<S: Source + 'static>(
    view: &View<'_, S>,
    disasm: &r2sleigh_lift::Disassembler,
    known: &dyn Fn(u64) -> bool,
    gap: Gap,
    targets: &mut Vec<u64>,
) -> bool {
    let Gap { bytes, after_exit } = gap;
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
        let end = (at + crate::body::WINDOW).min(held.len());
        let address = bytes.start + at as u64;
        let endian = disasm.arch_spec().memory_endianness;
        let writes = &view.source().container().loader_writes;
        let code = crate::stated::code(writes, address, held[at..end].to_vec(), endian);
        let mut window = [0u8; crate::body::WINDOW];
        window[..end - at].copy_from_slice(&code.bytes);
        let inert = |lifted: &r2il::R2ILBlock| {
            let mut transfers = lifted
                .ops
                .iter()
                .filter(|op| op.is_control_flow())
                .peekable();
            // A multi-byte `nop` forms an address into a temporary and drops it.
            let none = |op: &r2il::R2ILOp| !op.is_control_flow() && op.writes_only_temporaries();
            let leaves = transfers.peek().is_some();
            let stated = transfers.all(|op| {
                matches!(op, r2il::R2ILOp::Breakpoint)
                    || (op.transfer()).is_some_and(|transfer| {
                        // `hlt` lifts to a branch to itself, which reaches no other code.
                        transfer.direct
                            && (known(transfer.target.offset)
                                || (!transfer.call && transfer.target.offset == address))
                    })
            });
            lifted.ops.iter().all(none)
                || (leaves && stated)
                || (after_exit && !leaves && moves_only(&lifted.ops))
        };
        match disasm
            .lift_after(&window, address, None)
            .map(|one| one.block)
        {
            Ok(lifted)
                if lifted.size > 0
                    && inert(&lifted)
                    && !code.unstated(&(address..address + u64::from(lifted.size))) =>
            {
                targets.extend(
                    (lifted.ops.iter())
                        .filter_map(r2il::R2ILOp::transfer)
                        .filter(|transfer| transfer.direct && transfer.target.offset != address)
                        .map(|transfer| transfer.target.offset),
                );
                if after_exit {
                    targets.extend(lifted.ops.iter().flat_map(named));
                }
                at += lifted.size as usize;
            }
            _ => return false,
        }
    }
    true
}

/// Whether an instruction's operations only move values: what reaches a register or memory is an
/// input, a loaded word or a literal, so no address is computed here (doc/adr-result-side.md, "S18b as built").
fn moves_only(ops: &[r2il::R2ILOp]) -> bool {
    use r2il::ValueMovement as Movement;
    // The temporaries arithmetic produced: an address to load or store at, never a value to keep.
    let mut computed: Vec<&r2il::Varnode> = Vec::new();
    for op in ops {
        let moved = match op.value_movement() {
            Movement::Nothing | Movement::Loads | Movement::Literal => continue,
            Movement::Stores(value) if computed.contains(&value) => return false,
            Movement::Stores(_) => continue,
            Movement::Moves(source) => !computed.contains(&source),
            Movement::Computes => false,
            Movement::Transfers | Movement::Unstated => return false,
        };
        // Arithmetic may leave a temporary, or a flag, which is too narrow to hold an address.
        match (moved, op.output()) {
            (true, _) => {}
            (false, Some(dst)) if dst.space == r2il::SpaceId::Unique => computed.push(dst),
            (false, Some(flag)) if flag.size == 1 => {}
            (false, _) => return false,
        }
    }
    true
}

/// Every address one operation holds: a constant it computes with, or a place in memory it reads or writes.
fn named(op: &r2il::R2ILOp) -> impl Iterator<Item = u64> + '_ {
    let stated = |varnode: &&r2il::Varnode| {
        matches!(varnode.space, r2il::SpaceId::Const | r2il::SpaceId::Ram)
    };
    (op.inputs().into_iter().chain(op.output()))
        .filter(stated)
        .map(|varnode| varnode.offset)
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

/// The mapped words that name no other way in: the loader's slots at `stated` (D237), and each
/// take's own immediate inside its instruction's bytes (D227), both ascending.
struct Words<'a> {
    stated: &'a [u64],
    takes: &'a [Take],
}

impl Words<'_> {
    /// Whether the word of `width` bytes at `at` naming `value` is one of these. `O(log n)`.
    fn known(&self, at: u64, width: u64, value: u64, pointer: u64) -> bool {
        let first = self.takes.partition_point(|take| take.target < value);
        let mut takes = self.takes[first..]
            .iter()
            .take_while(|take| take.target == value);
        in_slot(self.stated, at, pointer)
            || takes.any(|take| take.from <= at && at + width <= take.end)
    }
}

/// Each of `entries` a mapped word names, pointer-wide or (64-bit) 32 bits, bit 0 cleared as Thumb
/// sets it, unless `words` accounts for it.
fn stored_words<S: Source>(source: &S, entries: &[u64], words: &Words<'_>, escaped: &mut Vec<u64>) {
    let (Some(&low), Some(&high)) = (entries.first(), entries.last()) else {
        return;
    };
    let little = super::view::endian(source) == r2il::Endianness::Little;
    let pointer = u64::from(source.container().arch.bits / 8);
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
            for (at, window) in bytes.windows(width).enumerate() {
                let mut word = [0u8; 8];
                let word = if little {
                    word[..width].copy_from_slice(window);
                    u64::from_le_bytes(word)
                } else {
                    word[8 - width..].copy_from_slice(window);
                    u64::from_be_bytes(word)
                };
                for value in [word, word & !1] {
                    if (low..=high).contains(&value)
                        && entries.binary_search(&value).is_ok()
                        && !words.known(segment.vaddr + at as u64, width as u64, value, pointer)
                    {
                        escaped.push(value);
                    }
                }
            }
        }
    }
}

/// Whether `at` lies in a `pointer`-byte slot starting at one of `slots` (ascending): `O(log slots)`.
fn in_slot(slots: &[u64], at: u64, pointer: u64) -> bool {
    let below = slots.partition_point(|slot| *slot <= at);
    below > 0 && at < slots[below - 1].saturating_add(pointer)
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Words, every_call_read, stored_words};
    use crate::program::{Arch, Container, Endian, Segment, Source};

    /// A 64-bit image of one segment at `vaddr` holding `bytes`.
    pub(in crate::program) struct Image {
        pub(in crate::program) vaddr: u64,
        pub(in crate::program) bytes: Vec<u8>,
        pub(in crate::program) container: Container,
    }

    impl Source for Image {
        fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
            let at = usize::try_from(vaddr.checked_sub(self.vaddr)?).ok()?;
            let rest = self.bytes.get(at..).filter(|rest| !rest.is_empty())?;
            Some(rest.iter().take(max).copied().collect())
        }
        fn container(&self) -> &Container {
            &self.container
        }
        fn identity(&self) -> u64 {
            0
        }
        fn byte_revision(&self) -> u64 {
            0
        }
        fn written_since(&self, _: u64, _: &std::ops::Range<u64>) -> bool {
            false
        }
    }

    /// An image above 4 GiB, as a Mach-O is linked: only a pointer-wide word names an entry there.
    #[test]
    fn a_pointer_wide_word_above_four_gib_names_its_function() {
        let vaddr: u64 = 0x1_0000_0000;
        let mut bytes = vec![0u8; 16];
        bytes[8..].copy_from_slice(&vaddr.to_le_bytes());
        let segment = Segment {
            vaddr,
            vsize: 16,
            file_size: 16,
            ..Segment::default()
        };
        let container = Container {
            arch: Arch {
                name: "x86-64".to_owned(),
                bits: 64,
                endian: Endian::Little,
                instructions: None,
            },
            segments: vec![segment],
            ..Container::default()
        };
        let image = Image {
            vaddr,
            bytes,
            container,
        };
        let mut escaped = Vec::new();
        let words = Words {
            stated: &[],
            takes: &[],
        };
        stored_words(&image, &[vaddr], &words, &mut escaped);
        assert!(escaped.contains(&vaddr), "{escaped:?}");
    }

    /// A call the index claims that no boundary read may read the result: one short refuses.
    #[test]
    fn a_call_count_one_short_of_the_index_is_not_every_call() {
        assert!(every_call_read(2, 2));
        assert!(!every_call_read(1, 2));
        assert!(!every_call_read(2, 1));
    }
}
