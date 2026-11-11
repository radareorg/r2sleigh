//! A row that control never returns is part of the interface.
//!
//! Without it a body walk runs straight through the function that follows a call to `err` or
//! `abort`, because a call normally falls through and there is no `ret` to stop at.

use r2abi::{CLibrary, LibraryRows, Tail};

#[test]
fn the_table_declares_which_functions_never_return() {
    let rows = LibraryRows::embedded(CLibrary::Unknown);
    let scope = CLibrary::Unknown.scope();
    let err = rows.find(scope, "err").expect("err is declared");
    assert!(err.noreturn, "err calls exit and never comes back");
    assert!(rows.prototype(err).variadic);
    assert_eq!(err.tail.printf_format(), Some(1));
    let memcpy = rows.find(scope, "memcpy").expect("memcpy is declared");
    assert!(!memcpy.noreturn, "memcpy returns");
    // ISO C17 7.24.2.1 states its prototype: a call reads its three fixed parameters only.
    assert_eq!(memcpy.tail, Tail::None);
}
