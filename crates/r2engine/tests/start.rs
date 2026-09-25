//! Where a session starts, and what a flag spelling seeks to.

mod common;

use common::{BASE, CALLER, Literal, STUB, TEXT, TWO};
use r2engine::program::{EntryKind, OpenProgram, Section};

#[test]
fn a_session_starts_at_the_declared_entry_then_any_entry_then_the_code() {
    let start = |literal: Literal| OpenProgram::of(literal).start();
    let declared = Literal::new()
        .entering(TWO, EntryKind::Init)
        .entering(CALLER, EntryKind::Main);
    assert_eq!(start(declared), Some(CALLER));
    assert_eq!(
        start(Literal::new().entering(TWO, EntryKind::Init)),
        Some(TWO)
    );
    // An object file declares no entry at all, and a section before the
    // code that holds no code, or nothing, is not where it starts.
    assert_eq!(start(Literal::new()), Some(BASE));
    for (is_code, vsize) in [(false, 8), (true, 0)] {
        let first = Section {
            name: ".first".to_owned(),
            vaddr: TEXT,
            vsize,
            is_code,
            loaded: true,
            ..Section::default()
        };
        assert_eq!(start(Literal::new().preceded_by(first)), Some(BASE));
    }
}

#[test]
fn a_flag_spelling_seeks_to_what_the_program_names() {
    let mut program = OpenProgram::of(
        Literal::new()
            .entering(CALLER, EntryKind::Main)
            .importing("puts"),
    );
    assert_eq!(program.address_named("two"), Ok(Some(TWO)));
    assert_eq!(program.address_named("entry0"), Ok(Some(CALLER)));
    // A stub is named only once there is a decoder to read it with.
    assert_eq!(program.address_named("sym.imp.puts"), Ok(Some(STUB)));
    assert_eq!(program.address_named("nowhere"), Ok(None));
}

#[test]
fn entry0_is_the_declared_entry_even_where_the_format_names_it_main() {
    // Mach-O's `LC_MAIN` names the address `main`; radare2 answers both.
    let mut program = OpenProgram::of(
        Literal::new()
            .entering(TWO, EntryKind::Init)
            .entering(CALLER, EntryKind::Main)
            .entering(CALLER, EntryKind::CMain),
    );
    assert_eq!(program.address_named("main"), Ok(Some(CALLER)));
    assert_eq!(program.address_named("entry0"), Ok(Some(CALLER)));
}
