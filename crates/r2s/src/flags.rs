//! What the shell calls an address, spelled the way radare2 spells it.
//!
//! radare2 substitutes a flag name wherever an instruction names an address it
//! has a flag for, which is why eighteen of its twenty-four disassembly
//! disagreements with this shell were one cause. The flag vocabulary is
//! radare2's presentation, not an engine fact: the engine asks the image for a
//! symbol's own name, and this asks for the spelling a radare2 user expects.

use std::collections::BTreeMap;

use r2il::{R2ILOp, SpaceId};
use r2image::{EntryKind, Image, SymbolKind};
use r2sleigh_lift::Disassembler;

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Every address this binary has a name for.
#[derive(Debug, Default)]
pub struct Flags {
    by_address: BTreeMap<u64, String>,
}

impl Flags {
    pub fn of(image: &Image) -> Self {
        let mut by_address = BTreeMap::new();
        for symbol in image.symbols() {
            if !names_an_address(symbol) {
                continue;
            }
            // An import is named at its PLT stub, which takes reading the
            // relocations; until then an import has no flag rather than a
            // wrong one.
            let space = match symbol.kind {
                SymbolKind::Section => "section",
                _ => "sym",
            };
            // A later symbol at one address does not displace an earlier one,
            // which is what keeps the name stable across two runs.
            by_address
                .entry(symbol.vaddr)
                .or_insert_with(|| format!("{space}.{}", symbol.name));
        }
        // The declared entry point is `entry0` whatever else names it.
        if let Some(entry) = image
            .entry_points()
            .iter()
            .find(|entry| entry.kind == EntryKind::Main)
        {
            by_address.insert(entry.vaddr, "entry0".to_owned());
        }
        Self { by_address }
    }

    /// Give each import stub the name radare2 gives it.
    pub fn name_imports(&mut self, imports: &BTreeMap<u64, String>) {
        for (stub, symbol) in imports {
            self.by_address
                .entry(*stub)
                .or_insert_with(|| format!("sym.imp.{symbol}"));
        }
    }

    pub fn at(&self, vaddr: u64) -> Option<&str> {
        self.by_address.get(&vaddr).map(String::as_str)
    }

    /// Replace every literal that names something.
    ///
    /// radare2 substitutes on the value alone: an immediate equal to an
    /// address it has a flag for is spelled by the flag, whether the
    /// instruction branches there or merely computes it. What keeps that from
    /// renaming ordinary arithmetic is the flag table, not the operand: a
    /// symbol that names no place in the program never becomes a flag.
    pub fn spell(&self, text: &str) -> String {
        if self.by_address.is_empty() {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("0x") {
            out.push_str(&rest[..start]);
            let digits = rest[start + 2..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map_or(rest.len() - start - 2, |end| end);
            let literal = &rest[start..start + 2 + digits];
            match u64::from_str_radix(&literal[2..], 16)
                .ok()
                .and_then(|value| self.at(value))
            {
                Some(name) => out.push_str(name),
                None => out.push_str(literal),
            }
            rest = &rest[start + 2 + digits..];
        }
        out.push_str(rest);
        out
    }
}

/// Which stub stands for which import, by its own name.
///
/// A call to an import reaches a stub, and the stub reads the slot the loader
/// fills. Following that read back to the relocation names the stub, which is
/// the address the call names. Reading the stubs rather than assuming an entry
/// size is what keeps this exact across formats and architectures.
pub fn imports(image: &Image, decoder: &Disassembler) -> BTreeMap<u64, String> {
    let slots: BTreeMap<u64, &str> = image
        .relocations()
        .iter()
        .map(|relocation| (relocation.vaddr, relocation.symbol.as_str()))
        .collect();
    let mut named = BTreeMap::new();
    if slots.is_empty() {
        return named;
    }

    // Mach-O names the stub itself rather than a slot the stub reads, so a
    // relocation landing inside a stub section already is the answer.
    for section in image
        .sections()
        .iter()
        .filter(|section| stubs(&section.name))
    {
        let end = section.vaddr + section.vsize;
        for (vaddr, symbol) in slots.range(section.vaddr..end) {
            named.insert(*vaddr, (*symbol).to_owned());
        }
    }

    for section in image
        .sections()
        .iter()
        .filter(|section| stubs(&section.name))
    {
        for (start, symbol) in section_stubs(image, decoder, section, &slots) {
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
    image: &Image,
    decoder: &Disassembler,
    section: &r2image::Section,
    slots: &BTreeMap<u64, &str>,
) -> Vec<(u64, String)> {
    // Where each stub reads the slot the loader fills. A stub is a run of
    // instructions ending in its transfer, and which slot that transfer reads
    // is one question with one answer: the reaching-origin pass the engine
    // asks when it correlates the site. x86 loads the slot directly and ARM
    // computes its address across three instructions; both answer here.
    let mut readers: Vec<(u64, String)> = Vec::new();
    let mut run = r2il::R2ILBlock {
        addr: section.vaddr,
        size: 0,
        ops: Vec::new(),
        switch_info: None,
        op_metadata: BTreeMap::new(),
    };
    let mut pc = section.vaddr;
    let end = section.vaddr + section.vsize;
    while pc < end {
        let Some(window) = image.read_upto(pc, DECODE_WINDOW) else {
            break;
        };
        let mut fetch = window.into_owned();
        fetch.resize(DECODE_WINDOW, 0);
        // Zero bytes are not an instruction, so nothing reads a slot in them.
        if fetch[0] == 0 {
            pc += 1;
            continue;
        }
        let Ok(lifted) = decoder.lift(&fetch, pc) else {
            break;
        };
        if lifted.size == 0 {
            break;
        }
        let leaves = lifted
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::Branch { .. } | R2ILOp::BranchInd { .. }));
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
            readers.push((leaving_at, (*found).to_owned()));
        }
        run = r2il::R2ILBlock {
            addr: pc,
            size: 0,
            ops: Vec::new(),
            switch_info: None,
            op_metadata: BTreeMap::new(),
        };
    }

    // The stubs are uniform cells filling the section's tail: whatever header
    // the linker put first, the last cell ends where the section ends. That
    // anchors every cell without deciding what a landing pad or an alignment
    // nop belongs to, and it holds for x86's PLT0, its `.plt.sec`, and ARM's
    // twenty-byte header alike.
    let stride = match readers.as_slice() {
        [first, second, ..] => second.0.saturating_sub(first.0),
        [_] | [] => return readers,
    };
    if stride == 0 {
        return Vec::new();
    }
    let count = readers.len() as u64;
    readers
        .into_iter()
        .enumerate()
        .filter_map(|(index, (_, symbol))| {
            let from_end = count.checked_sub(index as u64)?.checked_mul(stride)?;
            Some((end.checked_sub(from_end)?, symbol))
        })
        .collect()
}

/// The sections a format puts import stubs in.
fn stubs(name: &str) -> bool {
    name.starts_with(".plt") || name == "__stubs" || name == "__symbol_stub"
}

/// Whether a symbol names a place in the program.
///
/// An undefined symbol names an import and lives at no address; a symbol at
/// zero names nothing; ARM's `$a`, `$d` and `$t` mark where code becomes data
/// and back; and a symbol carrying a path is the object file a section came
/// from. radare2 keeps none of them as a flag on an instruction operand.
fn names_an_address(symbol: &r2image::Symbol) -> bool {
    symbol.defined
        && symbol.vaddr != 0
        && !symbol.name.is_empty()
        && !symbol.name.starts_with('$')
        && !symbol.name.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> Flags {
        Flags {
            by_address: BTreeMap::from([
                (0x100000340, "sym._add_two".to_owned()),
                (0x1030, "sym.imp.printf".to_owned()),
            ]),
        }
    }

    #[test]
    fn a_named_address_is_spelled_by_its_name() {
        assert_eq!(flags().spell("call 0x100000340"), "call sym._add_two");
        assert_eq!(
            flags().spell("lea r8, [0x1030]"),
            "lea r8, [sym.imp.printf]"
        );
    }

    #[test]
    fn an_address_with_no_name_stays_a_number() {
        assert_eq!(flags().spell("call 0x100000341"), "call 0x100000341");
        assert_eq!(flags().spell("sub rsp, 0x10"), "sub rsp, 0x10");
    }

    #[test]
    fn an_import_stub_is_named_by_what_it_reaches() {
        let mut flags = Flags::default();
        flags.name_imports(&BTreeMap::from([(0x1030, "printf".to_owned())]));
        assert_eq!(flags.at(0x1030), Some("sym.imp.printf"));
    }

    #[test]
    fn a_symbol_that_names_no_place_is_not_a_flag() {
        // ARM's mapping symbols, an object file's own name, and anything at
        // address zero: radare2 puts none of them on an operand.
        for (name, vaddr) in [("$d", 0x1000), ("a/b.c", 0x1000), ("zero", 0)] {
            let symbol = r2image::Symbol {
                name: name.to_owned(),
                vaddr,
                size: 0,
                kind: SymbolKind::Function,
                defined: true,
            };
            assert!(!names_an_address(&symbol), "{name}");
        }
    }

    #[test]
    fn a_binary_with_no_names_changes_nothing() {
        assert_eq!(Flags::default().spell("call 0x1030"), "call 0x1030");
    }
}
