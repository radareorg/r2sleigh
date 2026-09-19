//! What the shell calls an address, spelled the way radare2 spells it.
//!
//! radare2 substitutes a flag name wherever an instruction names an address it
//! has a flag for, which is why eighteen of its twenty-four disassembly
//! disagreements with this shell were one cause. The flag vocabulary is
//! radare2's presentation, not an engine fact: the engine asks the image for a
//! symbol's own name, and this asks for the spelling a radare2 user expects.

use std::collections::BTreeMap;

use r2image::{EntryKind, Image, SymbolKind};

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
