//! Which of several symbols at one address names it.

mod common;

use common::{Literal, ONE};
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
