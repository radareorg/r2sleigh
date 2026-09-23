//! Where an import stub begins, as the call to it names it.

mod common;

use common::{Literal, PLT_CALLER, PLT_STUB};
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
        .map(|(at, name)| (*at, name.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    let named = program.names().of(PLT_STUB).map(|name| name.spelled());
    assert_eq!(named.as_deref(), Some("sym.imp._Exit"), "{:?}", call.value);
}
