//! Which of several symbols at one address names it.

use crate::common;

use common::{Literal, ONE, TEXT};
use r2engine::program::{Binding, OpenProgram, Symbol, SymbolKind};

fn symbol(name: &str, binding: Binding) -> Symbol {
    Symbol {
        name: name.into(),
        vaddr: ONE,
        size: 6,
        kind: SymbolKind::Function,
        defined: true,
        binding,
        ..Symbol::default()
    }
}

/// The strongest binding names the address, whichever the table lists first.
#[test]
fn a_global_names_its_address_before_a_weak_alias_or_a_local_one() {
    let named = |symbols: [Symbol; 2]| {
        let program = symbols
            .into_iter()
            .fold(Literal::new().stripped_of("one"), Literal::declaring);
        let program = OpenProgram::of(program);
        program.names().of(ONE).map(|name| name.spelled())
    };
    let aliases = [
        symbol("_Exit", Binding::Weak),
        symbol("_exit", Binding::Global),
    ];
    assert_eq!(named(aliases).as_deref(), Some("sym._exit"));
    let internal = [
        symbol("__GI___libc_write", Binding::Local),
        symbol("write", Binding::Weak),
    ];
    assert_eq!(named(internal).as_deref(), Some("sym.write"));
}

/// A flag is radare2's filtered name; the table keeps the container's text, which a prototype is keyed by.
#[test]
fn a_symbol_radare2_filters_is_spelled_and_sought_as_its_flag() {
    let object = Symbol {
        name: "__OBJC_METACLASS_RO_$_Test".into(),
        vaddr: TEXT,
        size: 8,
        kind: SymbolKind::Data,
        defined: true,
        ..Symbol::default()
    };
    let program = OpenProgram::of(Literal::new().with_data().declaring(object));
    let names = program.names();
    let spelled = names.of(TEXT).map(|name| name.spelled());
    assert_eq!(spelled.as_deref(), Some("obj.__OBJC_METACLASS_RO___Test"));
    assert_eq!(
        names.address_of("obj.__OBJC_METACLASS_RO___Test"),
        Some(TEXT)
    );
    assert_eq!(names.address_of("obj.__OBJC_METACLASS_RO_$_Test"), None);
    assert_eq!(names.text_at(TEXT), Some("__OBJC_METACLASS_RO_$_Test"));
}

/// `caller: call f; ret`, then `f: dec edi; jne f; ret`, which no symbol names (as discovery's test).
const CALLS_AN_UNNAMED_FUNCTION: &[u8] = &[0xe8, 1, 0, 0, 0, 0xc3, 0xff, 0xcf, 0x75, 0xfc, 0xc3];

/// An unnamed function has radare2's one spelling, `fcn.%08x` (canal.c:158), and it seeks; a
/// spelling no listing prints seeks nowhere, and neither does one for an address no survey lists.
#[test]
fn an_unnamed_function_is_spelled_fcn_and_eight_digits_and_seeks() {
    let unnamed = common::BASE + 6;
    let functions = [("caller", common::BASE, 6)];
    let mut open = OpenProgram::of(Literal::of_code(CALLS_AN_UNNAMED_FUNCTION, &functions));
    let listed = open.functions().expect("surveyed");
    assert!(listed.iter().any(|found| found.address == unnamed));
    assert_eq!(open.names().function(unnamed, true), "fcn.00001006");
    assert_eq!(open.address_spelled("fcn.00001006"), Ok(Some(unnamed)));
    assert_eq!(open.address_spelled("fcn.1006"), Ok(None));
    assert_eq!(open.address_spelled("fcn.00001007"), Ok(None));
    assert_eq!(open.address_spelled("sym.caller"), Ok(Some(common::BASE)));
    // The C a function is defined as keeps its identifier form.
    let rendered = open.rendered(unnamed).expect("it renders");
    let text = rendered.response.output.into_text();
    assert!(text.contains("fcn_1006("), "{text}");
}

/// A C++ symbol is shown as `c++filt` prints it under `asm.demangle`, keeps its flag spelling
/// otherwise, and seeks by both: the same symbol, respelled by the ABI's grammar.
#[test]
fn a_mangled_symbol_is_shown_demangled_and_seeks_by_both_spellings() {
    let mangled = Symbol {
        name: "_ZN4LIEF9corruptedD1Ev".into(),
        vaddr: ONE,
        size: 6,
        kind: SymbolKind::Function,
        defined: true,
        binding: Binding::Global,
        ..Symbol::default()
    };
    let program = OpenProgram::of(Literal::new().stripped_of("one").declaring(mangled));
    let names = program.names();
    let name = names.of(ONE).expect("named");
    assert_eq!(name.shown(true), "LIEF::corrupted::~corrupted()");
    assert_eq!(name.shown(false), "sym._ZN4LIEF9corruptedD1Ev");
    assert_eq!(name.spelled(), "sym._ZN4LIEF9corruptedD1Ev");
    assert_eq!(names.function(ONE, true), "LIEF::corrupted::~corrupted()");
    for spelling in [
        "sym._ZN4LIEF9corruptedD1Ev",
        "_ZN4LIEF9corruptedD1Ev",
        "LIEF::corrupted::~corrupted()",
    ] {
        assert_eq!(names.address_of(spelling), Some(ONE), "{spelling}");
    }
}
