//! Where an import stub begins, as the call to it names it.

mod common;

use common::{BASE, Literal, MOVED_STUB, PLT_CALLER, PLT_STUB};
use r2engine::program::OpenProgram;
use r2engine::query::{Listing, Stop};

#[test]
fn a_lone_stub_begins_at_its_transfer_not_at_the_pad_before_it() {
    let mut program = OpenProgram::of(Literal::plt());
    let call = program
        .listing(Listing {
            start: PLT_CALLER,
            stop: Stop::After(1),
        })
        .expect("it lists");
    let imports: Vec<(u64, &str)> = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    let named = program.names().of(PLT_STUB).map(|name| name.spelled());
    assert_eq!(named.as_deref(), Some("sym.imp._Exit"), "{:?}", call.value);
    // A lone stub has no neighbour to measure a stride against; its cell runs
    // to the end of the section, which is where every cell is anchored.
    let size = program.names().of(PLT_STUB).map(|name| name.size);
    assert_eq!(size, Some(BASE + 0x20 - PLT_STUB));
}

#[test]
fn a_section_of_stubs_is_known_by_what_it_holds_not_by_its_name() {
    // The same `.plt` under another name still holds nothing but a resolver
    // jump and a jump through the import's slot, so its stub is named.
    let mut program = OpenProgram::of(Literal::plt().renamed(0, ".foo"));
    program.ensure_current().expect("it is current");
    let imports: Vec<(u64, &str)> = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    // The code that calls it makes a call, so it is the program's own and holds no stub.
    assert!(program.imports().range(PLT_CALLER..).next().is_none());
}

#[test]
fn a_stub_that_builds_its_slot_from_two_halves_is_named_for_the_import() {
    let literal = Literal::of_code(MOVED_STUB, &[]).in_arm();
    let mut program = OpenProgram::of(literal.in_plt(0x2000, "_Exit"));
    let listing = Listing {
        start: BASE,
        stop: Stop::After(3),
    };
    let stub = program.listing(listing).expect("it lists");
    // The fold carries `movw` into `movt`, so the load names the slot and the slot names the import.
    let imports = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()));
    assert_eq!(
        imports.collect::<Vec<_>>(),
        [(BASE, "_Exit")],
        "{:?}",
        stub.value
    );
}
