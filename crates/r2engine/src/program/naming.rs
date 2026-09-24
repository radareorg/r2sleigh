//! What this binary calls each address, filled from what the container states.
//!
//! The table itself is `crate::names::NameDb`: one name per address, stored
//! plain beside the namespace it belongs to, so the engine can key a prototype
//! by `printf` while a listing writes `sym.imp.printf`. This module is the
//! half that reads the container and decodes the linkage stubs, plus the
//! substitution that puts a name where a listing would otherwise print a
//! number.

use std::collections::BTreeMap;

use super::source::{EntryKind, Format, Section, Source, Symbol, SymbolKind};
use crate::names::{Name, NameDb, Namespace};
use r2il::R2ILOp;
use r2sleigh_lift::Disassembler;

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Every address this binary names, as the container states it.
pub fn of(source: &impl Source) -> NameDb {
    let image = source.container();
    let mut db = NameDb::new();
    for section in &image.sections {
        // A section the loader does not map occupies no address, and a
        // section at zero names nothing -- the same rule a symbol is held to.
        // Naming one made every literal `0x0` in a listing read
        // `section..comment`.
        if section.name.is_empty() || !section.loaded || section.vaddr == 0 {
            continue;
        }
        db.insert(
            section.vaddr,
            Name {
                text: section.name.clone(),
                namespace: Namespace::Section,
                size: section.vsize,
            },
        );
    }
    for symbol in &image.symbols {
        if !names_an_address(symbol) {
            continue;
        }
        db.insert(
            symbol.vaddr,
            Name {
                text: symbol.name.clone(),
                namespace: match symbol.kind {
                    SymbolKind::Section => Namespace::Section,
                    SymbolKind::Function => Namespace::Symbol,
                    SymbolKind::Data => Namespace::Object,
                    // An untyped symbol names a place, not an object, which is the difference `loc.` carries.
                    SymbolKind::Other | SymbolKind::Mapping(_) => Namespace::Label,
                },
                size: symbol.size,
            },
        );
    }
    // An entry the loader runs is named for the list it came from, and the
    // declared one is `entry0` whatever else names that address. A symbol
    // typed as a function is an entry too, but the symbol table already names
    // it, so it gets no second name here.
    let mut inits = 0;
    let mut finis = 0;
    // Where the format names `main` outright, that address is `main` and not
    // also `entry0`: `LC_MAIN` carries the C function, not a start routine.
    let c_main: std::collections::BTreeSet<u64> = image
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::CMain)
        .map(|entry| entry.vaddr)
        .collect();
    for entry in &image.entries {
        let text = match entry.kind {
            EntryKind::Main if c_main.contains(&entry.vaddr) => continue,
            EntryKind::Main => "entry0".to_owned(),
            // `LC_MAIN` names `main` itself, and the language declares what
            // `main` returns, so the name is what reaches that declaration.
            EntryKind::CMain => "main".to_owned(),
            EntryKind::Init => {
                inits += 1;
                format!("entry.init{}", inits - 1)
            }
            EntryKind::Fini => {
                finis += 1;
                format!("entry.fini{}", finis - 1)
            }
            // The symbol table names one of these already, and a stated
            // function start is a position rather than a name.
            EntryKind::Symbol | EntryKind::Declared => continue,
        };
        db.insert(
            entry.vaddr,
            Name {
                text,
                namespace: Namespace::Entry,
                size: 0,
            },
        );
    }
    db
}

/// Name every string the data sections hold.
///
/// radare2 names a run of printable bytes however it ends, which turns four
/// bytes of a hash table into `str._E7_`. A string this names is terminated,
/// because that is what makes it a string a program could pass to anything,
/// and it is long enough that finding one by chance is not expected.
pub fn name_strings(db: &mut NameDb, source: &impl Source) {
    let image = source.container();
    let scanned: u64 = image
        .sections
        .iter()
        .filter(|section| section.holds_static_data())
        .map(|section| section.vsize)
        .sum();
    // One bar for the whole listing, because that is what a reader reads: a
    // short section must not get a lower bar than the binary it is part of.
    let floor = chance_run_length(scanned);
    for section in &image.sections {
        // Section by section, so no string runs across the end of one.
        if !section.holds_static_data() {
            continue;
        }
        let Some(bytes) = source.read(section.vaddr, section.vsize as usize) else {
            continue;
        };
        let mut at = 0usize;
        while at < bytes.len() {
            let Some(text) = crate::names::text_in(&bytes[at..]) else {
                at += 1;
                continue;
            };
            let run = text.len();
            if run >= floor {
                db.insert(
                    section.vaddr + at as u64,
                    Name {
                        text: text.to_owned(),
                        namespace: Namespace::String,
                        // The terminator belongs to the string: it is what a
                        // reader has to step over to reach the next one.
                        size: run as u64 + 1,
                    },
                );
            }
            at += run + 1;
        }
    }
}

/// The shortest run this binary is not expected to contain by chance.
///
/// A printable byte is one of ninety-five values in two hundred and fifty-six,
/// so a run of `n` of them followed by a terminator has probability
/// `(95/256)^n / 256` at any offset. Over `size` offsets the expected number of
/// such runs is `size` times that, and this returns the smallest `n` that puts
/// it at or below one. The bound is derived from the bytes being scanned
/// rather than picked, so a larger binary asks for a longer run by itself.
fn chance_run_length(size: u64) -> usize {
    const PRINTABLE: f64 = 95.0 / 256.0;
    let expected = (size.max(1) as f64) / 256.0;
    if expected <= 1.0 {
        return 1;
    }
    (expected.ln() / -PRINTABLE.ln()).ceil() as usize
}

/// Give each import stub the name of the import it stands for.
///
/// Mach-O decorates a C name with one leading underscore, so the import the
/// relocation calls `_printf` is `printf` -- the same decoration the prototype
/// table already accounts for, and the spelling radare2 writes. ELF carries no
/// such decoration, so nothing is stripped there.
pub fn name_imports(db: &mut NameDb, format: Format, imports: &BTreeMap<u64, String>) {
    let decorated = format == Format::MachO;
    for (stub, symbol) in imports {
        let undecorated = match decorated {
            true => symbol.strip_prefix('_').unwrap_or(symbol),
            false => symbol.as_str(),
        };
        db.insert(
            *stub,
            Name {
                text: undecorated.to_owned(),
                namespace: Namespace::Import,
                size: 0,
            },
        );
    }
}

/// Name each slot the loader fills by the relocation that fills it.
///
/// A call through the global offset table reads a word rather than reaching a
/// stub, so the address in the instruction is the slot. Without this the
/// listing prints the bare number for the one operand whose meaning the
/// container states outright.
pub fn name_slots(
    db: &mut NameDb,
    format: Format,
    slots: &BTreeMap<u64, String>,
    stubs: &BTreeMap<u64, String>,
) {
    let decorated = format == Format::MachO;
    for (slot, symbol) in slots {
        // Mach-O records its relocations against the stub itself, so the same
        // address is in both tables. A stub is code the program transfers to
        // and `sym.imp.` is what says so; `reloc.` is for the word a stub
        // reads, and calling a stub one would state the wrong thing about it.
        if stubs.contains_key(slot) {
            continue;
        }
        let undecorated = match decorated {
            true => symbol.strip_prefix('_').unwrap_or(symbol),
            false => symbol.as_str(),
        };
        if undecorated.is_empty() {
            continue;
        }
        db.insert(
            *slot,
            Name {
                text: undecorated.to_owned(),
                namespace: Namespace::Reloc,
                size: 0,
            },
        );
    }
}

/// Which stub stands for which import, by its own name.
///
/// A call to an import reaches a stub, and the stub reads the slot the loader
/// fills. Following that read back to the relocation names the stub, which is
/// the address the call names. Reading the stubs rather than assuming an entry
/// size is what keeps this exact across formats and architectures.
pub fn imports(
    source: &impl Source,
    decoder: &Disassembler,
    alignment: u32,
) -> BTreeMap<u64, String> {
    let image = source.container();
    let slots: BTreeMap<u64, &str> = image
        .relocations
        .iter()
        .map(|relocation| (relocation.vaddr, relocation.symbol.as_str()))
        .collect();
    let mut named = BTreeMap::new();
    if slots.is_empty() {
        return named;
    }

    // Mach-O names the stub itself rather than a slot the stub reads, so a
    // relocation landing inside a stub section already is the answer.
    for section in image.sections.iter().filter(|section| stubs(&section.name)) {
        let end = section.vaddr + section.vsize;
        for (vaddr, symbol) in slots.range(section.vaddr..end) {
            named.insert(*vaddr, (*symbol).to_owned());
        }
    }

    for section in image.sections.iter().filter(|section| stubs(&section.name)) {
        for (start, symbol) in section_stubs(source, decoder, section, &slots, alignment) {
            named.entry(start).or_insert(symbol);
        }
    }

    named
}

/// Where each stub in one section begins, and which import it stands for.
///
/// A stub ends at the transfer it makes, and every stub in a section is the
/// same size, so the distance between two consecutive ends is the size the
/// linker gave them. Measuring it from the stubs themselves is what keeps a
/// landing pad at a stub's head inside the stub: nothing has to decide whether
/// an instruction that writes nothing is padding before a stub or the first
/// instruction of one.
fn section_stubs(
    source: &impl Source,
    decoder: &Disassembler,
    section: &Section,
    slots: &BTreeMap<u64, &str>,
    alignment: u32,
) -> Vec<(u64, String)> {
    // Where each stub reads the slot the loader fills. A stub is a run of
    // instructions ending in its transfer, and which slot that transfer reads
    // is one question with one answer: the reaching-origin pass the engine
    // asks when it correlates the site. x86 loads the slot directly and ARM
    // computes its address across three instructions; both answer here.
    // Each reader: where its transfer is, where its run began, and the import.
    let mut readers: Vec<(u64, u64, String)> = Vec::new();
    let mut run = fresh_run(section.vaddr);
    // Where each instruction of the run begins, and its first operation.
    let mut starts: Vec<(u64, usize)> = Vec::new();
    let step = u64::from(alignment.max(1));
    let mut pc = section.vaddr;
    let end = section.vaddr + section.vsize;
    while pc < end {
        let Some(window) = source.read(pc, DECODE_WINDOW) else {
            break;
        };
        let mut fetch = window;
        fetch.resize(DECODE_WINDOW, 0);
        // A word in a stub section that is not an instruction is the linker's
        // own data -- the offset an ARM stub adds, the padding before one --
        // and not the end of the section. It is stepped over at the width the
        // machine addresses instructions at, and the run starts again after
        // it. Giving up here instead ended the scan at the first such word.
        //
        // What the first byte is says nothing about that. Rejecting a word
        // whose first byte is zero is an x86 reading of a fixed-width machine:
        // `adr ip, 0x2c8` is `00 c6 8f e2`, which is how every ARM import stub
        // begins, so every one of them went unnamed.
        let lifted = match decoder.lift(&fetch, pc) {
            Ok(lifted) if lifted.size != 0 => lifted,
            _ => {
                pc += step;
                run = fresh_run(pc);
                starts.clear();
                continue;
            }
        };
        let leaves = lifted
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::Branch { .. } | R2ILOp::BranchInd { .. }));
        starts.push((pc, run.ops.len()));
        run.ops.extend(lifted.ops);
        run.size = (pc + u64::from(lifted.size) - run.addr) as u32;
        let leaving_at = pc;
        pc += u64::from(lifted.size);
        if !leaves {
            continue;
        }
        let terminal = run.ops.len().saturating_sub(1);
        if let Some(slot) = r2ssa::terminal_indirect_loaded_slot(&run, terminal)
            && let Some(found) = slots.get(&slot.offset)
        {
            readers.push((leaving_at, stub_start(&run, &starts), (*found).to_owned()));
        }
        run = fresh_run(pc);
        starts.clear();
    }

    // The stubs are uniform cells filling the section's tail: whatever header
    // the linker put first, the last cell ends where the section ends. That
    // anchors every cell without deciding what a landing pad or an alignment
    // nop belongs to, and it holds for x86's PLT0, its `.plt.sec`, and ARM's
    // twenty-byte header alike.
    let stride = match readers.as_slice() {
        [first, second, ..] => second.0.saturating_sub(first.0),
        // One stub has no neighbour to measure against, so its cell is what its transfer needs.
        [(_, start, symbol)] => return vec![(*start, symbol.clone())],
        [] => return Vec::new(),
    };
    if stride == 0 {
        return Vec::new();
    }
    let count = readers.len() as u64;
    readers
        .into_iter()
        .enumerate()
        .filter_map(|(index, (_, _, symbol))| {
            let from_end = count.checked_sub(index as u64)?.checked_mul(stride)?;
            Some((end.checked_sub(from_end)?, symbol))
        })
        .collect()
}

/// Where a stub begins: the longest tail of its run that only feeds the transfer or does nothing.
///
/// A stub's work before its transfer is computing where it goes. An instruction
/// that stores, or writes what the transfer never reads, is not part of that:
/// on x86 the zero pad after PLT0 decodes as `add byte [eax], al`. One that
/// writes nothing stays, so a landing pad at the stub's head is its own.
fn stub_start(run: &r2il::R2ILBlock, starts: &[(u64, usize)]) -> u64 {
    let register = |varnode: &&r2il::Varnode| {
        !matches!(varnode.space, r2il::SpaceId::Unique | r2il::SpaceId::Const)
    };
    let overlaps = |a: &r2il::Varnode, b: &r2il::Varnode| {
        a.space == b.space
            && a.offset < b.offset + u64::from(b.size)
            && b.offset < a.offset + u64::from(a.size)
    };
    let mut needed: Vec<r2il::Varnode> = Vec::new();
    let mut start = run.addr;
    let ends = starts
        .iter()
        .skip(1)
        .map(|(_, first)| *first)
        .chain([run.ops.len()]);
    let instructions: Vec<(u64, &[R2ILOp])> = starts
        .iter()
        .zip(ends)
        .map(|((pc, first), end)| (*pc, &run.ops[*first..end]))
        .collect();
    for (index, (pc, ops)) in instructions.iter().enumerate().rev() {
        let transfer = index + 1 == instructions.len();
        let stores = ops.iter().any(|op| matches!(op, R2ILOp::Store { .. }));
        let stray = ops
            .iter()
            .filter_map(R2ILOp::output)
            .filter(register)
            .any(|written| !needed.iter().any(|want| overlaps(want, written)));
        if !transfer && (stores || stray) {
            break;
        }
        needed.extend(
            ops.iter()
                .flat_map(R2ILOp::inputs)
                .filter(register)
                .cloned(),
        );
        start = *pc;
    }
    start
}

/// An empty run beginning here.
fn fresh_run(addr: u64) -> r2il::R2ILBlock {
    r2il::R2ILBlock {
        addr,
        size: 0,
        ops: Vec::new(),
        switch_info: None,
        op_metadata: BTreeMap::new(),
    }
}

/// The sections a format puts import stubs in.
fn stubs(name: &str) -> bool {
    // `__auth_stubs` is where arm64e puts them, and every Mach-O built for
    // Apple silicon has that section and no `__stubs`. Missing it left the
    // import table empty on those binaries, which is not a cosmetic gap: the
    // table decides which addresses are entries, and that is what bounds a
    // body walk.
    name.starts_with(".plt") || matches!(name, "__stubs" | "__auth_stubs" | "__symbol_stub")
}

/// Whether a symbol names a place in the program.
///
/// An undefined symbol names an import and lives at no address; a symbol at
/// zero names nothing; ARM's `$a`, `$d` and `$t` mark where code becomes data
/// and back; and a symbol carrying a path is the object file a section came
/// from. radare2 keeps none of them as a flag on an instruction operand.
fn names_an_address(symbol: &Symbol) -> bool {
    symbol.defined
        && symbol.vaddr != 0
        && !symbol.name.is_empty()
        && !symbol.name.starts_with('$')
        && !symbol.name.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> NameDb {
        let mut db = NameDb::new();
        db.insert(
            0x100000340,
            Name {
                text: "_add_two".to_owned(),
                namespace: Namespace::Symbol,
                size: 0x20,
            },
        );
        name_imports(
            &mut db,
            Format::Elf,
            &BTreeMap::from([(0x1030, "printf".to_owned())]),
        );
        db
    }

    #[test]
    fn the_engine_reads_a_name_without_its_namespace() {
        // A prototype table is keyed by what the import is called, not by how
        // a listing writes it, so both answers come from one entry.
        assert_eq!(db().text_at(0x1030), Some("printf"));
        assert_eq!(
            db().at(0x1030).map(Name::spelled).as_deref(),
            Some("sym.imp.printf")
        );
    }

    #[test]
    fn a_symbol_that_names_no_place_is_not_in_the_table() {
        // ARM's mapping symbols, an object file's own name, and anything at
        // address zero: radare2 puts none of them on an operand.
        for (name, vaddr) in [("$d", 0x1000), ("a/b.c", 0x1000), ("zero", 0)] {
            let symbol = Symbol {
                name: name.to_owned(),
                vaddr,
                size: 0,
                kind: SymbolKind::Function,
                defined: true,
                thumb: false,
            };
            assert!(!names_an_address(&symbol), "{name}");
        }
    }
}
