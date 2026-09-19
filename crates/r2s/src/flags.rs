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
        let mut stub = section.vaddr;
        let mut pc = section.vaddr;
        let end = section.vaddr + section.vsize;
        while pc < end {
            let Some(window) = image.read_upto(pc, DECODE_WINDOW) else {
                break;
            };
            let mut fetch = window.into_owned();
            fetch.resize(DECODE_WINDOW, 0);
            // Padding between stubs is zero bytes, and zero bytes are not an
            // instruction. Skipping them is what puts the name on the stub a
            // call reaches rather than on the padding before it.
            if fetch[0] == 0 {
                pc += 1;
                stub = pc;
                continue;
            }
            let Ok(lifted) = decoder.lift(&fetch, pc) else {
                break;
            };
            if lifted.size == 0 {
                break;
            }

            // Alignment padding between stubs is an instruction like
            // `nop dword [rax]` as often as it is zero bytes. It writes
            // nothing the program can read, and the stub begins after it.
            if is_padding(&lifted) {
                pc += u64::from(lifted.size);
                stub = pc;
                continue;
            }

            let mut leaves = false;
            for op in &lifted.ops {
                match op {
                    R2ILOp::Load { addr, .. } | R2ILOp::Store { addr, .. }
                        if matches!(addr.space, SpaceId::Ram | SpaceId::Const) =>
                    {
                        if let Some(symbol) = slots.get(&addr.offset) {
                            named.entry(stub).or_insert_with(|| (*symbol).to_owned());
                        }
                    }
                    // An unconditional transfer ends the stub, so whatever
                    // follows begins the next one.
                    R2ILOp::Branch { .. } | R2ILOp::BranchInd { .. } => leaves = true,
                    _ => {}
                }
            }

            pc += u64::from(lifted.size);
            if leaves {
                stub = pc;
            }
        }
    }
    named
}

/// Whether an instruction only occupies space.
///
/// Padding leaves nothing behind: it writes no memory, transfers nowhere, and
/// whatever it computes stays in the temporaries the lift invented for it.
fn is_padding(lifted: &r2il::R2ILBlock) -> bool {
    // An instruction that lifts to nothing at all did nothing at all.
    lifted.ops.iter().all(|op| match op {
        R2ILOp::Store { .. }
        | R2ILOp::Branch { .. }
        | R2ILOp::CBranch { .. }
        | R2ILOp::BranchInd { .. }
        | R2ILOp::Call { .. }
        | R2ILOp::CallInd { .. }
        | R2ILOp::Return { .. } => false,
        _ => op.output().is_none_or(|out| out.space == SpaceId::Unique),
    })
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
