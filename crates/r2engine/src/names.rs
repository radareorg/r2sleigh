//! What each address in a program is called, and how sure the engine is.
//!
//! Before this there were four answers to that question and they disagreed:
//! the shell's flag table spelled `sym.imp.printf`, the engine's `name_at`
//! answered `printf`, and three more places invented `fcn.{x}`, `fcn_{x}` or
//! `sub_{x}` when nothing named an address at all. Two of those are genuinely
//! different questions -- what a thing is called, and how a user expects to
//! see it written -- and the defect was that each was derived separately from
//! the same source, so they could drift.
//!
//! One table answers both. A name is stored plain, beside the namespace it
//! belongs to, and spelling is a projection of the pair. Whoever opened the
//! binary fills it; the engine and the shell read it.

use std::collections::BTreeMap;

use crate::discovery::Confidence;

/// The longest text that will be read out of one address.
///
/// Long enough for any format string or message a program renders, and short
/// enough that a constant landing in a run of printable bytes cannot pull the
/// whole section in behind it.
pub const LITERAL_LIMIT: usize = 4096;

/// The text these bytes begin with, where they begin with text.
///
/// A run of printable bytes that never terminates is not text, and neither is
/// an empty one. One character is: a program that points at `"x"` points at a
/// string. This is the only answer to that question, so the constants a body
/// names and a scan of the data sections agree by construction.
pub fn text_in(bytes: &[u8]) -> Option<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .filter(|end| *end > 0)?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    text.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t')
        .then_some(text)
}

/// Which vocabulary a name belongs to, spelled the way radare2 spells it.
///
/// This is presentation and provenance at once: `sym.imp.` says the address is
/// a linkage stub as surely as it says how to print it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Namespace {
    /// The program's declared entry points, numbered as radare2 numbers them.
    Entry,
    /// A symbol the container declares.
    Symbol,
    /// A linkage stub standing for an import.
    Import,
    /// A function the engine found rather than the container declared.
    Function,
    /// A label inside a function.
    Label,
    /// Text the program points at.
    String,
    /// A data object the container declares.
    Object,
    Section,
    Segment,
}

impl Namespace {
    /// The prefix radare2 writes before a name of this kind.
    pub const fn prefix(self) -> &'static str {
        match self {
            // An entry carries its ordinal instead, so it has no prefix.
            Self::Entry => "",
            Self::Symbol => "sym.",
            Self::Object => "obj.",
            Self::Import => "sym.imp.",
            Self::Function => "fcn.",
            Self::Label => "loc.",
            Self::String => "str.",
            Self::Section => "section.",
            Self::Segment => "segment.",
        }
    }
}

/// One address's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// The name itself, with no namespace on it. This is what a prototype
    /// table is keyed by and what a rendering spells a call with.
    pub text: String,
    pub namespace: Namespace,
    /// How far this name reaches, where the container said. Zero means the
    /// name covers only its own address, which is what keeps a nearest-name
    /// lookup from claiming everything after the last symbol.
    pub size: u64,
    pub confidence: Confidence,
}

impl Name {
    /// The name as a user expects to read it.
    pub fn spelled(&self) -> String {
        format!("{}{}", self.namespace.prefix(), self.text)
    }
}

/// Every address this program has a name for.
///
/// An address can hold more than one name, because more than one thing can be
/// true of it at once: `.text` begins where the first linkage stub does, and
/// both statements are the container's. They are kept in one place per
/// namespace and ordered by strength, so a listing can show every one while a
/// spelling asks for the strongest.
#[derive(Debug, Default, Clone)]
pub struct NameDb {
    by_address: BTreeMap<u64, Vec<Name>>,
}

impl NameDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name, replacing only a weaker name of the same kind.
    ///
    /// Strength is the confidence first and the namespace second, so a symbol
    /// the container declares outranks a function the engine inferred, and the
    /// order a caller happens to insert in does not decide the answer.
    pub fn insert(&mut self, vaddr: u64, name: Name) {
        let held = self.by_address.entry(vaddr).or_default();
        match held.iter_mut().find(|at| at.namespace == name.namespace) {
            Some(at) if at.confidence <= name.confidence => {}
            Some(at) => *at = name,
            None => {
                held.push(name);
                held.sort_by(|a, b| (a.confidence, a.namespace).cmp(&(b.confidence, b.namespace)));
            }
        }
    }

    /// The strongest name at exactly this address.
    pub fn at(&self, vaddr: u64) -> Option<&Name> {
        self.by_address.get(&vaddr)?.first()
    }

    /// Every name at exactly this address, strongest first.
    pub fn all_at(&self, vaddr: u64) -> &[Name] {
        self.by_address.get(&vaddr).map_or(&[], Vec::as_slice)
    }

    /// The plain name at exactly this address, which is what the engine keys
    /// prototypes and callee facts by.
    ///
    /// A section or a segment names a region, not the thing at its start, so
    /// neither answers here: `.text` begins where the first function does, and
    /// calling that function `.text` would key its prototype and spell its
    /// rendering by the name of the place it lives in.
    pub fn text_at(&self, vaddr: u64) -> Option<&str> {
        self.by_address
            .get(&vaddr)?
            .iter()
            .find(|name| !matches!(name.namespace, Namespace::Section | Namespace::Segment))
            .map(|name| name.text.as_str())
    }

    /// The strongest name covering this address, and where it begins.
    ///
    /// A name with no size covers only its own address: a symbol table that
    /// gave no size must not make the last symbol own the rest of the binary.
    pub fn containing(&self, vaddr: u64) -> Option<(u64, &Name)> {
        let (start, names) = self.by_address.range(..=vaddr).next_back()?;
        let name = names
            .iter()
            .find(|name| vaddr == *start || vaddr - start < name.size)?;
        Some((*start, name))
    }

    /// How many names the table holds, counting every namespace.
    pub fn len(&self) -> usize {
        self.by_address.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Every name, in address order and strongest first within an address.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &Name)> {
        self.by_address
            .iter()
            .flat_map(|(vaddr, names)| names.iter().map(move |name| (*vaddr, name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(text: &str, namespace: Namespace, size: u64, confidence: Confidence) -> Name {
        Name {
            text: text.to_owned(),
            namespace,
            size,
            confidence,
        }
    }

    #[test]
    fn a_name_is_stored_plain_and_spelled_with_its_namespace() {
        let name = named("printf", Namespace::Import, 0, Confidence::Stated);
        assert_eq!(name.text, "printf");
        assert_eq!(name.spelled(), "sym.imp.printf");
    }

    #[test]
    fn a_stated_symbol_outranks_an_inferred_function() {
        let mut db = NameDb::new();
        db.insert(
            0x1000,
            named("work", Namespace::Symbol, 0x20, Confidence::Stated),
        );
        db.insert(
            0x1000,
            named("1000", Namespace::Function, 0, Confidence::Called),
        );
        assert_eq!(db.text_at(0x1000), Some("work"));
        // Both are true of the address, so both are kept.
        assert_eq!(db.all_at(0x1000).len(), 2);
    }

    #[test]
    fn the_order_of_insertion_does_not_decide_the_answer() {
        let weak = named("1000", Namespace::Function, 0, Confidence::Called);
        let strong = named("work", Namespace::Symbol, 0x20, Confidence::Stated);
        let mut forwards = NameDb::new();
        forwards.insert(0x1000, weak.clone());
        forwards.insert(0x1000, strong.clone());
        let mut backwards = NameDb::new();
        backwards.insert(0x1000, strong);
        backwards.insert(0x1000, weak);
        assert_eq!(forwards.at(0x1000), backwards.at(0x1000));
        assert_eq!(forwards.all_at(0x1000), backwards.all_at(0x1000));
    }

    #[test]
    fn a_region_does_not_name_what_begins_inside_it() {
        // `.text` begins where the first function does, and the engine keys a
        // prototype by what a thing is called rather than by where it lives.
        let mut db = NameDb::new();
        db.insert(
            0x1000,
            named(".text", Namespace::Section, 0x200, Confidence::Stated),
        );
        assert_eq!(db.text_at(0x1000), None);
        assert_eq!(db.at(0x1000).map(|name| name.text.as_str()), Some(".text"));
    }

    #[test]
    fn a_section_and_a_symbol_can_begin_at_one_address() {
        // The first linkage stub begins where `.text` does, and both
        // statements are the container's own.
        let mut db = NameDb::new();
        db.insert(
            0x1000,
            named(".text", Namespace::Section, 0x200, Confidence::Stated),
        );
        db.insert(
            0x1000,
            named("printf", Namespace::Import, 0, Confidence::Stated),
        );
        assert_eq!(db.all_at(0x1000).len(), 2);
        assert_eq!(db.text_at(0x1000), Some("printf"));
    }

    #[test]
    fn a_name_covers_its_own_extent_and_no_further() {
        let mut db = NameDb::new();
        db.insert(
            0x1000,
            named("work", Namespace::Symbol, 0x20, Confidence::Stated),
        );
        assert_eq!(db.containing(0x1000).map(|(at, _)| at), Some(0x1000));
        assert_eq!(db.containing(0x101f).map(|(at, _)| at), Some(0x1000));
        assert!(db.containing(0x1020).is_none());
    }

    #[test]
    fn a_sizeless_name_does_not_own_the_rest_of_the_binary() {
        // A symbol table that gave no size must not make the last symbol
        // answer for every address after it.
        let mut db = NameDb::new();
        db.insert(
            0x1000,
            named("work", Namespace::Symbol, 0, Confidence::Stated),
        );
        assert!(db.containing(0x1000).is_some());
        assert!(db.containing(0x1001).is_none());
    }
}
