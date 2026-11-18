//! What each address in a program is called.
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

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The longest text that will be read out of one address.
///
/// Long enough for any format string or message a program renders, and short
/// enough that a constant landing in a run of printable bytes cannot pull the
/// whole section in behind it.
pub const LITERAL_LIMIT: usize = 4096;

/// Whether a character is text: printable, a byte a C string literal names by a simple escape
/// (`\a \b \t \n \v \f \r`, ISO C 6.4.4.4), or ESC. Any other control character ends text.
fn is_text(c: char) -> bool {
    !c.is_control() || matches!(c, '\x07'..='\x0d' | '\x1b')
}

/// The text these bytes begin with, where they begin with text.
///
/// A run of text that never terminates is not text, and neither is an empty one. One character
/// is: a program that points at `"x"` points at a string. The only answer to that question, so
/// a listing's notes, `iz` and `izz` agree by construction.
pub fn text_in(bytes: &[u8]) -> Option<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .filter(|end| *end > 0)?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    text.chars().all(is_text).then_some(text)
}

/// [`text_in`] where rendered C holds it as a literal: no control character but `\n` and `\t`.
pub fn literal_in(bytes: &[u8]) -> Option<&str> {
    let literal = |c: char| !c.is_control() || c == '\n' || c == '\t';
    text_in(bytes).filter(|text| text.chars().all(literal))
}

/// The first start in `segment`, a run of bytes with no zero, whose suffix
/// is text as [`text_in`] reads it, and that text.
///
/// One forward pass. A suffix from any start at or before an invalid UTF-8
/// sequence decodes into it -- UTF-8 resynchronises, so no other start skips
/// it -- and so does one from any start at or before a character that is no
/// text: the next start worth asking is just past either. Validation stops at
/// the first error, so the jumps cost what they skip, and a suffix that
/// validates is scanned at most twice.
pub fn first_text_in(segment: &[u8]) -> Option<(usize, &str)> {
    let mut start = 0usize;
    while start < segment.len() {
        match std::str::from_utf8(&segment[start..]) {
            Err(error) => start += error.valid_up_to() + 1,
            Ok(text) => match text.char_indices().rev().find(|(_, c)| !is_text(*c)) {
                None => return Some((start, text)),
                Some((at, c)) => start += at + c.len_utf8(),
            },
        }
    }
    None
}

/// Text as radare2's `r_str_byte_escape` spells it (`\n`, `\\`, `\x1b`): the one speller of text for
/// notes, `iz`, `izz` and string flags. O(length).
pub fn escaped(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\x0c' => escaped.push_str("\\f"),
            '\x08' => escaped.push_str("\\b"),
            '\x0b' => escaped.push_str("\\v"),
            '\x07' => escaped.push_str("\\a"),
            '\\' => escaped.push_str("\\\\"),
            c if c.is_control() => escaped.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Which vocabulary a name belongs to, spelled the way radare2 spells it.
///
/// This is presentation and provenance at once: `sym.imp.` says the address is
/// a linkage stub as surely as it says how to print it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Namespace {
    /// A linkage stub standing for an import. The most specific thing the
    /// container states about an address that has one.
    Import,
    /// A slot the loader fills, named by the relocation that fills it.
    ///
    /// Below a stub because a stub is code the program transfers to while this
    /// is a word it reads, and above a symbol because a relocation naming an
    /// exact address is more specific than the object it sits inside.
    Reloc,
    /// A symbol the container declares.
    Symbol,
    /// A data object the container declares.
    Object,
    /// The program's declared entry points, numbered as radare2 numbers them.
    ///
    /// Below a symbol on purpose: `entry0` says what an address is *for*, and
    /// a symbol says what it *is*. A listing that has both should give the
    /// name, and a stripped binary still gets the role.
    Entry,
    /// A function the engine found rather than the container declared.
    Function,
    /// A label inside a function.
    Label,
    /// Text the program points at.
    String,
    Section,
    Segment,
}

impl Namespace {
    const ALL: [Self; 10] = [
        Self::Import,
        Self::Reloc,
        Self::Symbol,
        Self::Object,
        Self::Entry,
        Self::Function,
        Self::Label,
        Self::String,
        Self::Section,
        Self::Segment,
    ];

    /// The prefix radare2 writes before a name of this kind.
    pub const fn prefix(self) -> &'static str {
        match self {
            // An entry carries its ordinal instead, so it has no prefix.
            Self::Entry => "",
            Self::Symbol => "sym.",
            Self::Object => "obj.",
            Self::Import => "sym.imp.",
            Self::Reloc => "reloc.",
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
    pub text: Arc<str>,
    pub namespace: Namespace,
    /// How far this name reaches, where the container said. Zero means the
    /// name covers only its own address, which is what keeps a nearest-name
    /// lookup from claiming everything after the last symbol.
    pub size: u64,
}

impl Name {
    /// Every spelling that seeks to this name, as `NameDb::by_spelling` keys it: the listed one
    /// past its prefix, and a symbol's bare text, which radare2 also accepts (`s main`).
    fn seeks(&self) -> Vec<(usize, Arc<str>)> {
        let listed: Arc<str> = match self.flagged() {
            Cow::Borrowed(_) => Arc::clone(&self.text),
            Cow::Owned(text) => text.into(),
        };
        let mut seeks = vec![(self.namespace as usize, Arc::clone(&listed))];
        if self.namespace == Namespace::Symbol {
            seeks.push((BARE, listed));
        }
        seeks
    }

    /// What a C++ symbol or import is called, as the ABI's grammar spells it: the same
    /// symbol, so as Stated as its mangled text. None where the text does not parse whole.
    fn demangled(&self) -> Option<String> {
        let mangled = matches!(self.namespace, Namespace::Symbol | Namespace::Import);
        mangled
            .then(|| r2abi::mangled::parse(&self.text)?.spelled())
            .flatten()
    }

    /// The name as a listing shows it: the demangled spelling where `demangle` holds and
    /// there is one (`asm.demangle`), else [`Name::spelled`]. O(length).
    pub fn shown(&self, demangle: bool) -> Cow<'_, str> {
        match self.demangled().filter(|_| demangle) {
            Some(demangled) => Cow::Owned(demangled),
            None => Cow::Owned(self.spelled()),
        }
    }

    /// The text past the prefix, as radare2 names the flag.
    fn flagged(&self) -> Cow<'_, str> {
        match self.namespace {
            Namespace::String => identifier(&self.text).into(),
            _ => flag_filter(&self.text),
        }
    }

    pub fn spelled(&self) -> String {
        format!("{}{}", self.namespace.prefix(), self.flagged())
    }
}

/// A flag name as radare2 keeps it (`r_name_filter`): letters, digits, `.`, `:` and `_` stay,
/// dash-like characters and a backslash before an escape letter become `_`, the rest are dropped.
fn flag_filter(text: &str) -> Cow<'_, str> {
    let kept = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_');
    if text.chars().all(kept) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if kept(c) => out.push(c),
            '\\' if chars.peek().is_some_and(|next| "sbfnrtva".contains(*next)) => out.push('_'),
            '!' | '"' | '$' | '%' | '(' | ')' | ',' | '-' | '/' | ';' | '<' | '>' | '?' | '@'
            | '[' | ']' | '`' | '~' | ' ' => out.push('_'),
            _ => {}
        }
    }
    Cow::Owned(out)
}

/// The text as radare2 names a string's flag: the scanner's escaped form through the flag filter.
fn identifier(text: &str) -> String {
    flag_filter(&escaped(text)).into_owned()
}

/// Every address this program has a name for.
///
/// An address can hold more than one name, because more than one thing can be
/// true of it at once: `.text` begins where the first linkage stub does, and
/// both statements are the container's. They are kept in one place per
/// namespace and ordered by strength, so a listing can show every one while a
/// spelling asks for the strongest.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NameDb {
    by_address: BTreeMap<u64, Vec<Name>>,
    /// The lowest address each spelling names, by its namespace and the rest past the prefix,
    /// which is the name's own text, shared; `BARE` holds symbols' bare text. Only ever added to.
    by_spelling: [BTreeMap<Arc<str>, u64>; BARE + 1],
}

/// `NameDb::by_spelling`'s map of symbols' bare text, after one per namespace.
const BARE: usize = Namespace::ALL.len();

impl NameDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name unless the address has one of its kind: every name is the container's, so its first statement stands.
    pub fn insert(&mut self, vaddr: u64, name: Name) {
        let held = self.by_address.entry(vaddr).or_default();
        if held.iter().any(|at| at.namespace == name.namespace) {
            return;
        }
        for (seek, key) in name.seeks() {
            let lowest = self.by_spelling[seek].entry(key).or_insert(vaddr);
            *lowest = (*lowest).min(vaddr);
        }
        // An address nearly always has one name; a first push would reserve four.
        held.reserve_exact(1);
        held.push(name);
        held.sort_by_key(|name| name.namespace);
    }

    /// The lowest address a name is spelled as, the way a listing writes it.
    ///
    /// This is what `s sym.main` or `s entry0` reads: the name `f` lists for an
    /// address is the name that seeks there.
    pub fn address_of(&self, spelling: &str) -> Option<u64> {
        // Prefixes nest (`sym.`, `sym.imp.`, and an entry's none): each that fits is asked.
        let prefixed = Namespace::ALL.iter().filter_map(|namespace| {
            let rest = spelling.strip_prefix(namespace.prefix())?;
            self.by_spelling[*namespace as usize].get(rest)
        });
        let listed = prefixed
            .chain(self.by_spelling[BARE].get(spelling))
            .copied();
        // A demangled spelling holds its parameter list: asked of each C++ name on a miss, in
        // address order, so no key is kept for the rare seek (O(names x length)).
        listed.min().or_else(|| {
            let shown = |name: &Name| name.demangled().is_some_and(|text| text == spelling);
            spelling
                .contains('(')
                .then(|| self.iter().find(|(_, name)| shown(name)))?
                .map(|(vaddr, _)| vaddr)
        })
    }

    /// The strongest name at exactly this address.
    pub fn at(&self, vaddr: u64) -> Option<&Name> {
        self.by_address.get(&vaddr)?.first()
    }

    /// Every name at exactly this address, strongest first.
    pub fn all_at(&self, vaddr: u64) -> &[Name] {
        self.by_address.get(&vaddr).map_or(&[], Vec::as_slice)
    }

    /// The strongest name for the thing at this address.
    ///
    /// A section or a segment names a region, not the thing at its start, so
    /// neither answers here: `.text` begins where the first function does, and
    /// calling that function `.text` would name it after the place it lives
    /// in. `at` still returns them, because a listing of names lists them.
    pub fn of(&self, vaddr: u64) -> Option<&Name> {
        self.by_address
            .get(&vaddr)?
            .iter()
            .find(|name| !matches!(name.namespace, Namespace::Section | Namespace::Segment))
    }

    /// The function that begins at this address, shown as a listing shows it, else as an unnamed one.
    pub fn function(&self, entry: u64, demangle: bool) -> String {
        self.of(entry).map_or_else(
            || r2source::unnamed_function(entry),
            |name| name.shown(demangle).into_owned(),
        )
    }

    /// The plain name at exactly this address, which is what the engine keys
    /// prototypes and callee facts by.
    pub fn text_at(&self, vaddr: u64) -> Option<&str> {
        self.of(vaddr).map(|name| &*name.text)
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
    /// The text the scan finds in a segment is the text asking at every
    /// offset finds: the first offset whose suffix reads as text.
    fn first_by_every_offset(segment: &[u8]) -> Option<(usize, String)> {
        let mut terminated = segment.to_vec();
        terminated.push(0);
        (0..segment.len()).find_map(|offset| {
            super::text_in(&terminated[offset..]).map(|text| (offset, text.to_owned()))
        })
    }

    proptest::proptest! {
        #[test]
        fn the_first_text_in_a_segment_is_the_first_offset_that_reads_as_text(
            segment in proptest::collection::vec(
                proptest::prop_oneof![
                    1u8..0x20,
                    0x20u8..0x7f,
                    0x7fu8..=0xff,
                    proptest::strategy::Just(b'\n'),
                    proptest::sample::select(vec![0xc2u8, 0x80, 0x9f, 0xe2, 0x82, 0xac, 0xf0, 0x9f]),
                ],
                0..64,
            )
        ) {
            let found = super::first_text_in(&segment).map(|(offset, text)| (offset, text.to_owned()));
            proptest::prop_assert_eq!(found, first_by_every_offset(&segment));
        }
    }

    use super::*;

    fn named(text: &str, namespace: Namespace, size: u64) -> Name {
        Name {
            text: text.into(),
            namespace,
            size,
        }
    }

    /// A C simple escape and ESC are text and are escaped back as radare2 spells them; any
    /// other control byte ends text, and a suffix past it is the text a scan finds.
    #[test]
    fn a_simple_escape_and_esc_are_text_and_another_control_byte_is_not() {
        let run = b"wget -q\r\x1b[0m\x07\x08\x0b\x0c x\0";
        let text = text_in(run).expect("one text");
        assert_eq!(text.len(), run.len() - 1);
        assert_eq!(escaped(text), "wget -q\\r\\x1b[0m\\a\\b\\v\\f x");
        assert_eq!(literal_in(run), None);
        assert_eq!(text_in(b"ab\x01cd\0"), None);
        assert_eq!(first_text_in(b"ab\x01cd"), Some((3, "cd")));
        assert_eq!(escaped("a\\b"), "a\\\\b");
        assert_eq!(literal_in(b"a\tb\n\0"), Some("a\tb\n"));
    }

    #[test]
    fn a_string_is_stored_as_itself_and_spelled_as_an_identifier() {
        let name = named("hello %s\n", Namespace::String, 10);
        assert_eq!(&*name.text, "hello %s\n");
        assert_eq!(name.spelled(), "str.hello__s_n");
    }

    #[test]
    fn a_name_is_spelled_as_the_flag_radare2_makes_of_it() {
        // `r_name_filter`: dash-like characters become `_`, other invalid ones are dropped, `.:_` stay.
        let name = named("__OBJC_METACLASS_RO_$_Test", Namespace::Object, 0);
        assert_eq!(&*name.text, "__OBJC_METACLASS_RO_$_Test");
        assert_eq!(name.spelled(), "obj.__OBJC_METACLASS_RO___Test");
        assert_eq!(
            named("a-b'c::d.\u{e9}", Namespace::Symbol, 0).spelled(),
            "sym.a_bc::d."
        );
    }

    #[test]
    fn a_filtered_name_seeks_by_its_flag_and_not_by_the_text_the_filter_changed() {
        let mut db = NameDb::new();
        db.insert(0x1000, named("ro_$_Test", Namespace::Symbol, 0));
        for spelling in ["sym.ro___Test", "ro___Test"] {
            assert_eq!(db.address_of(spelling), Some(0x1000), "{spelling}");
        }
        assert_eq!(db.address_of("sym.ro_$_Test"), None);
    }

    #[test]
    fn a_name_is_stored_plain_and_spelled_with_its_namespace() {
        let name = named("printf", Namespace::Import, 0);
        assert_eq!(&*name.text, "printf");
        assert_eq!(name.spelled(), "sym.imp.printf");
    }

    #[test]
    fn a_symbol_outranks_a_function_name() {
        let mut db = NameDb::new();
        db.insert(0x1000, named("work", Namespace::Symbol, 0x20));
        db.insert(0x1000, named("1000", Namespace::Function, 0));
        assert_eq!(db.text_at(0x1000), Some("work"));
        // Both are true of the address, so both are kept.
        assert_eq!(db.all_at(0x1000).len(), 2);
    }

    #[test]
    fn the_order_of_insertion_does_not_decide_the_answer() {
        let weak = named("1000", Namespace::Function, 0);
        let strong = named("work", Namespace::Symbol, 0x20);
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
        db.insert(0x1000, named(".text", Namespace::Section, 0x200));
        assert_eq!(db.text_at(0x1000), None);
        assert_eq!(db.at(0x1000).map(|name| &*name.text), Some(".text"));
    }

    #[test]
    fn a_section_and_a_symbol_can_begin_at_one_address() {
        // The first linkage stub begins where `.text` does, and both
        // statements are the container's own.
        let mut db = NameDb::new();
        db.insert(0x1000, named(".text", Namespace::Section, 0x200));
        db.insert(0x1000, named("printf", Namespace::Import, 0));
        assert_eq!(db.all_at(0x1000).len(), 2);
        assert_eq!(db.text_at(0x1000), Some("printf"));
    }

    #[test]
    fn a_name_covers_its_own_extent_and_no_further() {
        let mut db = NameDb::new();
        db.insert(0x1000, named("work", Namespace::Symbol, 0x20));
        assert_eq!(db.containing(0x1000).map(|(at, _)| at), Some(0x1000));
        assert_eq!(db.containing(0x101f).map(|(at, _)| at), Some(0x1000));
        assert!(db.containing(0x1020).is_none());
    }

    #[test]
    fn a_spelling_resolves_to_the_address_it_names_and_a_second_of_its_kind_does_not() {
        let mut db = NameDb::new();
        db.insert(0x1000, named("1000", Namespace::Function, 0));
        db.insert(0x2000, named("entry0", Namespace::Entry, 0));
        db.insert(0x3000, named("work", Namespace::Function, 0));
        db.insert(0x3000, named("other", Namespace::Function, 0));
        assert_eq!(db.address_of("fcn.1000"), Some(0x1000));
        assert_eq!(db.address_of("entry0"), Some(0x2000));
        // The first statement of a kind at an address is the one kept, and the second seeks nowhere.
        assert_eq!(db.address_of("fcn.work"), Some(0x3000));
        assert_eq!(db.address_of("fcn.other"), None);
        assert_eq!(db.address_of("other"), None);
    }

    #[test]
    fn a_sizeless_name_does_not_own_the_rest_of_the_binary() {
        // A symbol table that gave no size must not make the last symbol
        // answer for every address after it.
        let mut db = NameDb::new();
        db.insert(0x1000, named("work", Namespace::Symbol, 0));
        assert!(db.containing(0x1000).is_some());
        assert!(db.containing(0x1001).is_none());
    }

    #[test]
    fn a_spelling_two_namespaces_reach_seeks_the_lower_of_their_addresses() {
        let mut db = NameDb::new();
        db.insert(0x2000, named("printf", Namespace::Import, 0));
        db.insert(0x1000, named("imp.printf", Namespace::Symbol, 0));
        db.insert(0x3000, named("entry0", Namespace::Entry, 0));
        db.insert(0x4000, named("entry0", Namespace::Symbol, 0));
        assert_eq!(db.address_of("sym.imp.printf"), Some(0x1000));
        assert_eq!(db.address_of("imp.printf"), Some(0x1000));
        assert_eq!(db.address_of("entry0"), Some(0x3000));
        assert_eq!(db.address_of("sym.entry0"), Some(0x4000));
        assert_eq!(db.address_of("sym.printf"), None);
        // A string seeks by its identifier, which is not its text.
        db.insert(0x5000, named("hello %s\n", Namespace::String, 9));
        assert_eq!(db.address_of("str.hello__s_n"), Some(0x5000));
        assert_eq!(db.address_of("str.hello %s\n"), None);
    }
}
